use crate::apfs::{
    can_write_path, current_euid, force_remove_all, fsgetpath, lstat_inode_mode, real_home_dir,
    statfs_info,
};
use crate::error::{AfuseError, ERR_EACCES, ERR_ENOENT, ERR_EPERM, ERR_ESTALE};
use crate::manifest::SnapshotMeta;
use crate::snapshot::list_snapshots_unlocked;
use crate::trash_ledger::{
    collect_all_candidates, collect_live_path_inodes, collect_selective_candidates,
    merge_live_entries_into_ledger, retire_and_gc_ledger,
};
use crate::unicode_norm::{canonical_rel_key, path_eq_casefold_nfd, path_starts_with_casefold_nfd};
use crate::vault::{lock_vault, resolve_workspace_vault_recovery, TargetKind};
use crate::vault_policy::VerifiedLiveTarget;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(crate) use crate::trash_ledger::{record_live_target_inode_if_new, record_snapshot_inodes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrashCleanupStatus {
    NotInTrash,
    Purged,
    TccDenied,
}

impl TrashCleanupStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TrashCleanupStatus::NotInTrash => "not_in_trash",
            TrashCleanupStatus::Purged => "purged",
            TrashCleanupStatus::TccDenied => "tcc_denied",
        }
    }
}

pub(crate) fn validate_custom_trash_dir(
    raw: &str,
    home: Option<&Path>,
    ws: Option<&Path>,
    euid: u32,
) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let p = PathBuf::from(trimmed);
    if !p.is_absolute() {
        return None;
    }
    let sym = fs::symlink_metadata(&p).ok()?;
    if sym.file_type().is_symlink() || !sym.file_type().is_dir() {
        return None;
    }
    let canon = fs::canonicalize(&p).ok()?;
    let mut forbidden_exact = vec![
        PathBuf::from("/"),
        PathBuf::from("/Users"),
        PathBuf::from("/tmp"),
        PathBuf::from("/private/tmp"),
        PathBuf::from("/var/folders"),
        PathBuf::from("/private/var/folders"),
    ];
    if let Some(h) = home {
        forbidden_exact.push(h.to_path_buf());
        if let Ok(ch) = fs::canonicalize(h) {
            forbidden_exact.push(ch);
        }
    }
    if forbidden_exact
        .iter()
        .any(|f| path_eq_casefold_nfd(&canon, f))
    {
        return None;
    }
    let forbidden_trees = [
        Path::new("/System"),
        Path::new("/Applications"),
        Path::new("/Library"),
        Path::new("/usr"),
        Path::new("/bin"),
        Path::new("/sbin"),
        Path::new("/etc"),
        Path::new("/private/etc"),
    ];
    if forbidden_trees
        .iter()
        .any(|f| path_starts_with_casefold_nfd(&canon, f))
    {
        return None;
    }
    if let Some(w) = ws {
        let w_canon = fs::canonicalize(w).unwrap_or_else(|_| w.to_path_buf());
        if path_eq_casefold_nfd(&canon, &w_canon)
            || path_starts_with_casefold_nfd(&w_canon, &canon)
            || path_starts_with_casefold_nfd(&canon, &w_canon)
        {
            return None;
        }
    }
    let in_tmp_sandbox = [
        Path::new("/tmp"),
        Path::new("/private/tmp"),
        Path::new("/var/folders"),
        Path::new("/private/var/folders"),
    ]
    .iter()
    .any(|root| path_starts_with_casefold_nfd(&canon, root) && !path_eq_casefold_nfd(&canon, root));
    let leaf_has_trash = canon
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_ascii_lowercase().contains("trash"))
        .unwrap_or(false);
    let owned_trash_leaf = leaf_has_trash && sym.uid() == euid;
    if !in_tmp_sandbox && !owned_trash_leaf {
        return None;
    }
    Some(canon)
}

pub(crate) fn allowed_trash_roots_for(
    home: Option<&Path>,
    custom_env: Option<&str>,
    ws: Option<&Path>,
    euid: u32,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push_if_ok = |p: PathBuf| {
        let resolved = fs::canonicalize(&p).ok().or_else(|| fs::symlink_metadata(&p).ok().map(|_| p));
        if let Some(r) = resolved {
            if !out.iter().any(|x| path_eq_casefold_nfd(x, &r)) {
                out.push(r);
            }
        }
    };
    if let Some(custom) = custom_env {
        if let Some(safe) = validate_custom_trash_dir(custom, home, ws, euid) {
            push_if_ok(safe);
        }
    }
    if let Some(h) = home {
        push_if_ok(h.join(".Trash"));
        push_if_ok(h.join("Library/Mobile Documents/com~apple~CloudDocs/.Trash"));
    }
    if let Some(w) = ws {
        let mut comps = w.components();
        if matches!(comps.next(), Some(std::path::Component::RootDir)) {
            if let (Some(c1), Some(c2)) = (comps.next(), comps.next()) {
                if c1.as_os_str() == "Volumes" {
                    push_if_ok(PathBuf::from("/Volumes").join(c2.as_os_str()).join(".Trashes").join(euid.to_string()));
                }
            }
        }
    }
    out
}

pub fn allowed_trash_roots() -> Vec<PathBuf> {
    let home = real_home_dir().ok();
    let custom = env::var("AFUSE_TRASH_DIR").ok();
    allowed_trash_roots_for(home.as_deref(), custom.as_deref(), None, current_euid())
}

fn normalize_parent_keep_leaf(raw: &Path) -> PathBuf {
    let Some(name) = raw.file_name() else { return raw.to_path_buf(); };
    match raw.parent().and_then(|p| fs::canonicalize(p).ok()) {
        Some(canon_parent) => canon_parent.join(name),
        None => raw.to_path_buf(),
    }
}

fn probe_trash_roots_tcc(
    canon_ws: &Path,
    home: Option<&Path>,
    trash_roots: &[PathBuf],
    stale_probe: &BTreeSet<u64>,
) -> bool {
    if stale_probe.is_empty() { return false; }
    let icloud_trash = home
        .map(|h| h.join("Library/Mobile Documents/com~apple~CloudDocs/.Trash"))
        .and_then(|p| fs::canonicalize(&p).ok());
    let is_icloud_desk_doc = home
        .map(|h| canon_ws.starts_with(h.join("Desktop")) || canon_ws.starts_with(h.join("Documents")))
        .unwrap_or(false)
        && icloud_trash.as_ref().map(|p| fs::read_dir(p).is_ok()).unwrap_or(false);
    let local_trash = home.and_then(|h| fs::canonicalize(h.join(".Trash")).ok());
    for tr in trash_roots {
        if is_icloud_desk_doc && local_trash.as_deref() == Some(tr.as_path()) {
            continue;
        }
        match fs::read_dir(tr) {
            Err(e) if matches!(e.raw_os_error(), Some(c) if c == ERR_EPERM || c == ERR_EACCES) => return true,
            Ok(rd) => {
                let has_match = rd.flatten().any(|ent| {
                    fs::symlink_metadata(ent.path()).map(|m| stale_probe.contains(&m.ino())).unwrap_or(false)
                });
                if has_match && matches!(can_write_path(tr), Err(e) if e.code == ERR_EPERM || e.code == ERR_EACCES) {
                    return true;
                }
            }
            Err(_) => {}
        }
    }
    false
}

fn purge_candidate_inodes(
    restored_ws: &Path,
    kind: TargetKind,
    ws_vault: &Path,
    cands: &[u64],
    probe_inos: &BTreeSet<u64>,
    fsid: (i32, i32),
) -> TrashCleanupStatus {
    let live_entries = collect_live_path_inodes(restored_ws, kind);
    let live_inodes: BTreeSet<u64> = live_entries.iter().map(|(ino, _)| *ino).collect();
    let home = real_home_dir().ok();
    let custom = env::var("AFUSE_TRASH_DIR").ok();
    let trash_roots = allowed_trash_roots_for(home.as_deref(), custom.as_deref(), Some(restored_ws), current_euid());
    if trash_roots.is_empty() {
        merge_live_entries_into_ledger(ws_vault, &live_entries);
        return TrashCleanupStatus::NotInTrash;
    }
    let canon_ws = fs::canonicalize(restored_ws).unwrap_or_else(|_| restored_ws.to_path_buf());
    let mut purged_any = false;
    let mut saw_tcc_denied = false;
    let mut purged_inos = BTreeSet::new();
    let mut gone_inos = BTreeSet::new();

    for &cand_ino in cands {
        if live_inodes.contains(&cand_ino) { continue; }
        let raw_path = match fsgetpath(fsid, cand_ino) {
            Ok(p) => p,
            Err(e) if e.code == ERR_EPERM || e.code == ERR_EACCES => {
                saw_tcc_denied = true;
                continue;
            }
            Err(e) if e.code == ERR_ENOENT || e.code == ERR_ESTALE => {
                gone_inos.insert(cand_ino);
                continue;
            }
            Err(_) => continue,
        };
        let cand_path = normalize_parent_keep_leaf(&raw_path);
        if path_eq_casefold_nfd(&cand_path, &canon_ws)
            || path_starts_with_casefold_nfd(&cand_path, &canon_ws)
            || path_starts_with_casefold_nfd(&canon_ws, &cand_path)
        {
            continue;
        }
        let Some(matched_trash) = trash_roots
            .iter()
            .find(|t| path_starts_with_casefold_nfd(&cand_path, t) && !path_eq_casefold_nfd(&cand_path, t))
        else {
            continue;
        };
        let actual_ino = match lstat_inode_mode(&cand_path) {
            Ok((ino, _)) => ino,
            Err(e) if e.code == ERR_EPERM || e.code == ERR_EACCES => {
                saw_tcc_denied = true;
                continue;
            }
            Err(_) => continue,
        };
        if actual_ino != cand_ino { continue; }
        let same_vol = statfs_info(cand_path.parent().unwrap_or(&cand_path)).map(|s| s.fsid == fsid).unwrap_or(false);
        if !same_vol { continue; }
        let parent = cand_path.parent().unwrap_or(&cand_path);
        if let Err(e) = can_write_path(matched_trash).and_then(|_| can_write_path(parent)) {
            if e.code == ERR_EPERM || e.code == ERR_EACCES { saw_tcc_denied = true; }
            continue;
        }
        match force_remove_all(&cand_path) {
            Ok(()) => {
                purged_any = true;
                purged_inos.insert(cand_ino);
            }
            Err(e) if e.code == ERR_EPERM || e.code == ERR_EACCES => saw_tcc_denied = true,
            Err(_) => {}
        }
    }

    if !saw_tcc_denied && !purged_any {
        let stale_probe: BTreeSet<u64> = probe_inos
            .iter()
            .copied()
            .filter(|ino| !live_inodes.contains(ino) && !purged_inos.contains(ino) && !gone_inos.contains(ino))
            .collect();
        if probe_trash_roots_tcc(&canon_ws, home.as_deref(), &trash_roots, &stale_probe) {
            saw_tcc_denied = true;
        }
    }

    let mut retired_inos = purged_inos;
    retired_inos.extend(gone_inos);
    retire_and_gc_ledger(ws_vault, &live_entries, &retired_inos, fsid);
    if saw_tcc_denied {
        TrashCleanupStatus::TccDenied
    } else if purged_any {
        TrashCleanupStatus::Purged
    } else {
        TrashCleanupStatus::NotInTrash
    }
}

pub(crate) fn purge_trashed_counterparts(
    restored_ws: &Path,
    kind: TargetKind,
    ws_vault: &Path,
    snap_dir: &Path,
    target_meta: &SnapshotMeta,
    fsid: (i32, i32),
) -> TrashCleanupStatus {
    let (cands, root_cands) = collect_all_candidates(ws_vault, snap_dir, target_meta);
    let mut probe_inos = root_cands;
    probe_inos.extend(cands.iter().copied());
    purge_candidate_inodes(restored_ws, kind, ws_vault, &cands, &probe_inos, fsid)
}

pub(crate) fn purge_trashed_selective_paths(
    restored_ws: &Path,
    ws_vault: &Path,
    snap_dir: &Path,
    clean_paths: &[PathBuf],
    fsid: (i32, i32),
) -> TrashCleanupStatus {
    let targets: Vec<String> = clean_paths
        .iter()
        .map(|p| canonical_rel_key(&p.to_string_lossy()).trim_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if targets.is_empty() {
        let live_entries = collect_live_path_inodes(restored_ws, TargetKind::Directory);
        merge_live_entries_into_ledger(ws_vault, &live_entries);
        return TrashCleanupStatus::NotInTrash;
    }
    let cands = collect_selective_candidates(ws_vault, snap_dir, &targets);
    let probe_inos: BTreeSet<u64> = cands.iter().copied().collect();
    purge_candidate_inodes(restored_ws, TargetKind::Directory, ws_vault, &cands, &probe_inos, fsid)
}

pub fn purge_workspace_trash_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
) -> Result<TrashCleanupStatus, AfuseError> {
    let (ws, ws_vault) = resolve_workspace_vault_recovery(workspace, vault_override)?;
    let _guard = lock_vault(&ws_vault)?;
    let snaps = list_snapshots_unlocked(&ws_vault)?;
    let Some(latest) = snaps.first() else { return Ok(TrashCleanupStatus::NotInTrash); };
    let live = VerifiedLiveTarget::open_matching(&ws, latest.target_kind)?;
    let snap_dir = ws_vault.join("snapshots").join(&latest.id);
    let stat_p = if live.kind() == TargetKind::SingleFile {
        live.path().parent().unwrap_or(live.path())
    } else {
        live.path()
    };
    let fsi = statfs_info(stat_p)?;
    Ok(purge_trashed_counterparts(live.path(), live.kind(), &ws_vault, &snap_dir, latest, fsi.fsid))
}
