use crate::apfs::{current_euid, fsgetpath, lstat_inode_mode, real_home_dir, statfs_info};
use crate::error::{AfuseError, ERR_EACCES, ERR_EEXIST, ERR_EINVAL, ERR_ENOENT, ERR_EPERM};
use crate::manifest::{
    compute_fast_fingerprint, compute_single_file_manifest, json_escape, read_verified_snap_meta,
    write_meta,
};
use crate::restore_tree::{find_single_snap_file, same_disk_entry};
use crate::snapshot::list_snapshots_unlocked;
use crate::trash::{allowed_trash_roots_for, record_live_target_inode_if_new};
use crate::trash_ledger::load_root_inodes;
use crate::unicode_norm::{path_eq_casefold_nfd, path_starts_with_casefold_nfd};
use crate::vault::{
    lock_vault, resolve_workspace_vault_recovery, validate_workspace_binding_with_vault, TargetKind,
};
pub use crate::vault_gc::{
    inspect_vault_orphans, prune_orphan_vaults_with, OrphanPruneReport,
};
pub(crate) use crate::vault_gc::atomic_retire_and_remove_vault;
use crate::vault_policy::enforce_vault_target_kind;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocateOutcome {
    MovedValid { new_path: PathBuf, ino: u64, kind: TargetKind },
    MovedBlocked { new_path: PathBuf, reason: String },
    Trashed { path: PathBuf },
    MissingOrTcc { errno: i32 },
}

impl LocateOutcome {
    pub fn to_json(&self) -> String {
        match self {
            LocateOutcome::MovedValid { new_path, ino, kind } => format!(
                "{{\"ok\":true,\"status\":\"moved_valid\",\"new_path\":\"{}\",\"ino\":{},\"kind\":\"{}\"}}",
                json_escape(&new_path.to_string_lossy()),
                ino,
                kind.as_str()
            ),
            LocateOutcome::MovedBlocked { new_path, reason } => format!(
                "{{\"ok\":true,\"status\":\"moved_blocked\",\"new_path\":\"{}\",\"reason\":\"{}\"}}",
                json_escape(&new_path.to_string_lossy()),
                json_escape(reason)
            ),
            LocateOutcome::Trashed { path } => format!(
                "{{\"ok\":true,\"status\":\"trashed\",\"path\":\"{}\"}}",
                json_escape(&path.to_string_lossy())
            ),
            LocateOutcome::MissingOrTcc { errno } => {
                format!("{{\"ok\":true,\"status\":\"missing_or_tcc\",\"errno\":{}}}", errno)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RelocateReport {
    pub from: PathBuf,
    pub to: PathBuf,
    pub kind: TargetKind,
    pub dev: u64,
    pub ino: u64,
    pub snapshots_updated: usize,
}

fn nearest_existing_dir(p: &Path) -> PathBuf {
    let mut cur = p.to_path_buf();
    while !cur.exists() && cur.pop() {}
    if cur.is_dir() { cur } else { cur.parent().unwrap_or(Path::new("/")).to_path_buf() }
}

pub fn locate_workspace_target_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    hint_ino: Option<u64>,
) -> Result<LocateOutcome, AfuseError> {
    let (ws, ws_vault) = resolve_workspace_vault_recovery(workspace, vault_override)?;
    let stat_dir = nearest_existing_dir(&ws);
    let fsi = statfs_info(&stat_dir)?;

    let mut seen = BTreeSet::new();
    let mut cands = Vec::new();
    if let Some(h) = hint_ino.filter(|&x| x > 0) {
        if seen.insert(h) { cands.push(h); }
    }
    for ino in load_root_inodes(&ws_vault) {
        if ino > 0 && seen.insert(ino) { cands.push(ino); }
    }
    let mut expected_kind: Option<TargetKind> = None;
    if let Ok(snaps) = list_snapshots_unlocked(&ws_vault) {
        if let Some(first) = snaps.first() {
            expected_kind = Some(first.target_kind);
        }
        for m in snaps {
            if m.root_inode > 0 && seen.insert(m.root_inode) {
                cands.push(m.root_inode);
            }
        }
    }

    let home = real_home_dir().ok();
    let custom = env::var("AFUSE_TRASH_DIR").ok();
    let trash_roots = allowed_trash_roots_for(home.as_deref(), custom.as_deref(), Some(&ws), current_euid());
    let mut last_errno = ERR_ENOENT;

    for cand_ino in cands {
        let raw_path = match fsgetpath(fsi.fsid, cand_ino) {
            Ok(p) => p,
            Err(e) => {
                if e.code == ERR_EPERM || e.code == ERR_EACCES {
                    last_errno = e.code;
                }
                continue;
            }
        };
        let norm_path = raw_path
            .parent()
            .and_then(|p| fs::canonicalize(p).ok())
            .and_then(|cp| raw_path.file_name().map(|n| cp.join(n)))
            .unwrap_or(raw_path);
        if trash_roots
            .iter()
            .any(|t| path_starts_with_casefold_nfd(&norm_path, t) && !path_eq_casefold_nfd(&norm_path, t))
        {
            return Ok(LocateOutcome::Trashed { path: norm_path });
        }
        if norm_path == ws {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&norm_path) else { continue };
        if meta.file_type().is_symlink() || meta.ino() != cand_ino {
            continue;
        }
        match validate_workspace_binding_with_vault(&norm_path, vault_override) {
            Ok(v) => {
                if let Some(exp) = expected_kind {
                    if v.kind != exp {
                        return Ok(LocateOutcome::MovedBlocked {
                            new_path: norm_path,
                            reason: format!("target kind mismatch: expected {}", exp.as_str()),
                        });
                    }
                }
                return Ok(LocateOutcome::MovedValid {
                    new_path: v.canonical_path,
                    ino: v.ino,
                    kind: v.kind,
                });
            }
            Err(e) => {
                return Ok(LocateOutcome::MovedBlocked {
                    new_path: norm_path,
                    reason: e.message,
                });
            }
        }
    }
    Ok(LocateOutcome::MissingOrTcc { errno: last_errno })
}

pub fn relocate_workspace_vault_with(
    from_ws: &Path,
    to_ws: &Path,
    vault_override: Option<&Path>,
    expected_ino: Option<u64>,
) -> Result<RelocateReport, AfuseError> {
    let (old_ws, vault_p1) = resolve_workspace_vault_recovery(from_ws, vault_override)?;
    let validated = validate_workspace_binding_with_vault(to_ws, vault_override)?;
    if let Some(exp_ino) = expected_ino.filter(|&x| x > 0) {
        if validated.ino != exp_ino {
            return Err(AfuseError::new(
                ERR_EINVAL,
                format!("relocate inode mismatch: expected {}, live={}", exp_ino, validated.ino),
            ));
        }
    }
    let (new_ws, vault_p2) = resolve_workspace_vault_recovery(&validated.canonical_path, vault_override)?;
    if old_ws == new_ws || vault_p1 == vault_p2 || same_disk_entry(&vault_p1, &vault_p2) {
        return Ok(RelocateReport {
            from: old_ws, to: new_ws, kind: validated.kind,
            dev: validated.dev, ino: validated.ino, snapshots_updated: 0,
        });
    }
    if fs::symlink_metadata(&old_ws).is_ok() {
        let same_ent = lstat_inode_mode(&old_ws).map(|(i, _)| i == validated.ino).unwrap_or(false);
        if !same_ent {
            return Err(AfuseError::new(ERR_EEXIST, "source path still exists on disk"));
        }
    }
    if vault_p2.exists() {
        return Err(AfuseError::new(ERR_EEXIST, "destination vault already exists"));
    }
    if !vault_p1.is_dir() {
        return Ok(RelocateReport {
            from: old_ws, to: new_ws, kind: validated.kind,
            dev: validated.dev, ino: validated.ino, snapshots_updated: 0,
        });
    }
    let _guard = lock_vault(&vault_p1)?;
    enforce_vault_target_kind(&vault_p1, validated.kind)?;
    fs::rename(&vault_p1, &vault_p2).map_err(|e| {
        AfuseError::new(e.raw_os_error().unwrap_or(1), format!("vault rename failed: {}", e))
    })?;

    let mut updated = 0usize;
    let new_ws_str = new_ws.to_string_lossy().into_owned();
    let new_leaf = new_ws.file_name().map(|n| n.to_os_string());
    let snaps_dir = vault_p2.join("snapshots");
    if let Ok(rd) = fs::read_dir(&snaps_dir) {
        for ent in rd.flatten() {
            let sdir = ent.path();
            let Ok(mut m) = read_verified_snap_meta(&sdir) else { continue };
            let meta_p = sdir.join("meta.kv");
            m.workspace = new_ws_str.clone();
            if validated.kind == TargetKind::SingleFile {
                if let Some(ref nl) = new_leaf {
                    let tree_dir = sdir.join("tree");
                    if let Some(old_f) = find_single_snap_file(&old_ws, &tree_dir) {
                        let dst_f = tree_dir.join(nl);
                        let active_f = if old_f != dst_f && fs::rename(&old_f, &dst_f).is_ok() {
                            dst_f
                        } else {
                            old_f
                        };
                        if m.tree_sha256.starts_with("fast:") {
                            if let Ok((fp, fc, lb)) = compute_fast_fingerprint(&active_f, TargetKind::SingleFile) {
                                m.tree_sha256 = fp;
                                m.file_count = fc;
                                m.logical_bytes = lb;
                            }
                        } else if m.tree_sha256 != "fast" {
                            if let Ok((h, fc, lb, _)) = compute_single_file_manifest(&active_f) {
                                m.tree_sha256 = h;
                                m.file_count = fc;
                                m.logical_bytes = lb;
                            }
                        }
                    }
                }
            }
            if write_meta(&meta_p, &m).is_ok() {
                updated += 1;
            }
        }
    }
    record_live_target_inode_if_new(&new_ws, validated.kind, &vault_p2);
    Ok(RelocateReport {
        from: old_ws, to: new_ws, kind: validated.kind,
        dev: validated.dev, ino: validated.ino, snapshots_updated: updated,
    })
}
