use crate::apfs::{force_remove_all, lstat_inode_mode, TMP_SEQ};
use crate::error::{AfuseError, ERR_EINVAL, ERR_ENOENT};
pub use crate::diff::{diff_snapshot, diff_snapshot_with_vault, DiffReport};
use crate::diff::diff_fast_unlocked;
use crate::fs_guard::clonefile_readable;
use crate::manifest::{
    clone_filtered_tree, compute_fast_entries, compute_single_file_manifest,
    compute_snap_tree_manifest, compute_tree_manifest, count_non_git_entries, read_meta, write_meta,
    SnapshotMeta,
};
use crate::prune::{dedup_and_calibrate_history_unlocked, snap_tree_fast_fp};
use crate::rolling::{enforce_pre_delete_quota_unlocked, PRE_DELETE_LABEL};
use crate::sha256::Sha256;
pub use crate::restore::{
    restore_snapshot, restore_snapshot_paths, restore_snapshot_paths_with_vault,
    restore_snapshot_with_vault, RestoreReport,
};
use crate::trash::{record_live_target_inode_if_new, record_snapshot_inodes};
use crate::vault::{
    lock_vault, prepare_live_workspace_vault_with, resolve_workspace_vault_recovery, TargetKind,
    VaultLock,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub(crate) fn lock_vault_and_resolve(
    workspace: &Path,
    vault_override: Option<&Path>,
) -> Result<(PathBuf, PathBuf, VaultLock), AfuseError> {
    let (ws, ws_vault) = resolve_workspace_vault_recovery(workspace, vault_override)?;
    let guard = lock_vault(&ws_vault)?;
    Ok((ws, ws_vault, guard))
}

pub fn create_snapshot(workspace: &Path, label: &str) -> Result<SnapshotMeta, AfuseError> {
    create_snapshot_opts_with_vault(workspace, None, label, false)
}

pub fn create_snapshot_fast(workspace: &Path, label: &str) -> Result<SnapshotMeta, AfuseError> {
    create_snapshot_opts_with_vault(workspace, None, label, true)
}

pub fn create_snapshot_fast_dedup(
    workspace: &Path,
    label: &str,
) -> Result<(SnapshotMeta, bool), AfuseError> {
    create_snapshot_fast_dedup_with_vault(workspace, None, label)
}

pub fn create_snapshot_if_changed(
    workspace: &Path,
    label: &str,
) -> Result<(SnapshotMeta, bool), AfuseError> {
    create_snapshot_if_changed_with_vault(workspace, None, label)
}

pub fn create_snapshot_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    label: &str,
) -> Result<SnapshotMeta, AfuseError> {
    create_snapshot_opts_with_vault(workspace, vault_override, label, false)
}

pub fn create_snapshot_opts_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    label: &str,
    fast: bool,
) -> Result<SnapshotMeta, AfuseError> {
    if fast {
        return create_snapshot_fast_dedup_with_vault(workspace, vault_override, label).map(|x| x.0);
    }
    let (ws, ws_vault) = prepare_live_workspace_vault_with(workspace, vault_override)?;
    let _guard = lock_vault(&ws_vault)?;
    create_snapshot_unlocked_opts(&ws, &ws_vault, label, false)
}

pub(crate) fn create_snapshot_fast_dedup_unlocked(
    ws: &Path,
    ws_vault: &Path,
    label: &str,
) -> Result<(SnapshotMeta, bool), AfuseError> {
    let kind = if ws.is_file() { TargetKind::SingleFile } else { TargetKind::Directory };
    if label.starts_with("auto:") && label != "auto:pre-restore" {
        if let Ok((entries, _, _, _)) = compute_fast_entries(ws, kind) {
            let mut h = Sha256::new();
            for (rel, sig) in &entries {
                h.update(rel.as_bytes());
                h.update(b"\0");
                h.update(sig.as_bytes());
                h.update(b"\n");
            }
            let cur_fp = format!("fast:{}", h.finalize_hex());
            let existing = list_snapshots_unlocked(ws_vault)?;
            if let Some(latest) = existing.iter().find(|m| m.label != "auto:pre-restore") {
                let fp_same = snap_tree_fast_fp(ws_vault, latest).as_deref() == Some(cur_fp.as_str());
                let content_same = fp_same
                    || diff_fast_unlocked(ws, ws_vault, latest)
                        .map(|d| {
                            d.report.added.is_empty()
                                && d.report.modified.is_empty()
                                && d.report.deleted.is_empty()
                        })
                        .unwrap_or(false);
                if content_same {
                    if kind == TargetKind::SingleFile {
                        record_live_target_inode_if_new(ws, kind, ws_vault);
                    }
                    return Ok((latest.clone(), true));
                }
            }
        }
    }
    Ok((create_snapshot_unlocked_opts(ws, ws_vault, label, true)?, false))
}

pub fn create_snapshot_fast_dedup_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    label: &str,
) -> Result<(SnapshotMeta, bool), AfuseError> {
    let (ws, ws_vault) = prepare_live_workspace_vault_with(workspace, vault_override)?;
    let _guard = lock_vault(&ws_vault)?;
    create_snapshot_fast_dedup_unlocked(&ws, &ws_vault, label)
}

pub fn create_snapshot_if_changed_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    label: &str,
) -> Result<(SnapshotMeta, bool), AfuseError> {
    let (ws, ws_vault) = prepare_live_workspace_vault_with(workspace, vault_override)?;
    let _guard = lock_vault(&ws_vault)?;
    let existing = list_snapshots_unlocked(&ws_vault)?;
    if let Some(latest) = existing.iter().find(|m| m.label != "auto:pre-restore") {
        let (live_sha, _, _, _) = if ws.is_file() {
            compute_single_file_manifest(&ws)?
        } else {
            compute_tree_manifest(&ws)?
        };
        let latest_sha = if latest.tree_sha256 == "fast" || latest.tree_sha256.starts_with("fast:") {
            let latest_tree = ws_vault.join("snapshots").join(&latest.id).join("tree");
            compute_snap_tree_manifest(&latest_tree, &ws, latest.target_kind)
                .map(|t| t.0)
                .unwrap_or_default()
        } else {
            latest.tree_sha256.clone()
        };
        if !latest_sha.is_empty() && live_sha == latest_sha {
            return Ok((latest.clone(), true));
        }
    }
    let meta = create_snapshot_unlocked_opts(&ws, &ws_vault, label, false)?;
    Ok((meta, false))
}

pub(crate) fn create_snapshot_unlocked_opts(
    ws: &Path,
    ws_vault: &Path,
    label: &str,
    fast: bool,
) -> Result<SnapshotMeta, AfuseError> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let snap_id = format!(
        "snap-{}-{:04x}",
        now_ms,
        (((std::process::id() as u64) & 0xff) << 8) | (seq & 0xff)
    );
    let snap_dir = ws_vault.join("snapshots").join(&snap_id);
    let tree_dir = snap_dir.join("tree");

    let (root_inode, root_mode) = lstat_inode_mode(ws)?;
    let target_kind = if ws.is_file() {
        TargetKind::SingleFile
    } else {
        TargetKind::Directory
    };

    let t0 = Instant::now();
    let clone_res = if target_kind == TargetKind::SingleFile {
        fs::create_dir_all(&tree_dir)
            .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))
            .and_then(|_| {
                let fname = ws
                    .file_name()
                    .ok_or_else(|| AfuseError::new(ERR_EINVAL, "missing single-file name"))?;
                clonefile_readable(ws, &tree_dir.join(fname))
            })
    } else {
        clone_filtered_tree(ws, &tree_dir)
    };
    if let Err(e) = clone_res {
        let _ = force_remove_all(&snap_dir);
        return Err(e);
    }
    let clone_elapsed_us = t0.elapsed().as_micros();

    let (tree_sha256, file_count, logical_bytes, project_files) = if fast {
        let fp_target = if target_kind == TargetKind::SingleFile {
            tree_dir.join(ws.file_name().unwrap_or_default())
        } else {
            tree_dir.clone()
        };
        let (entries, fc, lb, pf) = compute_fast_entries(&fp_target, target_kind)?;
        let mut h = Sha256::new();
        for (rel, sig) in &entries {
            h.update(rel.as_bytes());
            h.update(b"\0");
            h.update(sig.as_bytes());
            h.update(b"\n");
        }
        (format!("fast:{}", h.finalize_hex()), fc, lb, pf)
    } else {
        let (sha, fc, lb, map) = compute_snap_tree_manifest(&tree_dir, ws, target_kind)?;
        let pf = if target_kind == TargetKind::SingleFile { 1 } else { count_non_git_entries(&map) };
        (sha, fc, lb, pf)
    };
    if label.starts_with("auto:") && label != "auto:pre-restore" && target_kind == TargetKind::Directory {
        let prior = list_snapshots_unlocked(ws_vault)?;
        let empty_tree = file_count == 0 && prior.iter().any(|m| m.file_count > 0 || m.project_files > 0);
        let empty_proj = project_files == 0 && prior.iter().any(|m| m.project_files > 0);
        if empty_tree || empty_proj {
            let _ = force_remove_all(&snap_dir);
            return Err(AfuseError::new(
                ERR_EINVAL,
                "refusing auto-snapshot of empty directory while non-empty history exists",
            ));
        }
    }

    record_snapshot_inodes(ws, target_kind, &snap_dir, ws_vault);

    let meta = SnapshotMeta {
        id: snap_id,
        created_ms: now_ms,
        label: if label.trim().is_empty() {
            "manual".to_string()
        } else {
            label.trim().to_string()
        },
        workspace: ws.to_string_lossy().into_owned(),
        root_inode,
        root_mode: root_mode & 0o7777,
        file_count,
        project_files,
        logical_bytes,
        tree_sha256,
        elapsed_us: clone_elapsed_us,
        target_kind,
    };
    write_meta(&snap_dir.join("meta.kv"), &meta)?;
    enforce_auto_snap_quota_unlocked(ws_vault, &meta.label)?;
    Ok(meta)
}

const MAX_PRE_RESTORE_SNAPS: usize = 10;

fn enforce_auto_snap_quota_unlocked(ws_vault: &Path, label: &str) -> Result<(), AfuseError> {
    if label == "auto:pre-restore" {
        for m in list_snapshots_unlocked(ws_vault)?
            .into_iter()
            .filter(|m| m.label == "auto:pre-restore")
            .skip(MAX_PRE_RESTORE_SNAPS)
        {
            force_remove_all(&ws_vault.join("snapshots").join(&m.id))?;
        }
        return Ok(());
    }
    if label == PRE_DELETE_LABEL {
        return enforce_pre_delete_quota_unlocked(ws_vault);
    }
    if !label.starts_with("auto:") {
        return Ok(());
    }
    let _ = dedup_and_calibrate_history_unlocked(ws_vault)?;
    let max_keep = std::env::var("AFUSE_MAX_AUTO_SNAPS").ok().and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(50);
    if max_keep == 0 {
        return Ok(());
    }
    for m in list_snapshots_unlocked(ws_vault)?
        .into_iter()
        .filter(|m| {
            m.label.starts_with("auto:")
                && m.label != "auto:pre-restore"
                && m.label != PRE_DELETE_LABEL
        })
        .skip(max_keep)
    {
        force_remove_all(&ws_vault.join("snapshots").join(&m.id))?;
    }
    Ok(())
}

pub fn list_snapshots_with_vault(workspace: &Path, vault_override: Option<&Path>) -> Result<Vec<SnapshotMeta>, AfuseError> {
    let (_ws, ws_vault) = resolve_workspace_vault_recovery(workspace, vault_override)?;
    if !ws_vault.join("snapshots").is_dir() {
        return Ok(Vec::new());
    }
    let _guard = lock_vault(&ws_vault)?;
    list_snapshots_unlocked(&ws_vault)
}

pub fn list_snapshots(workspace: &Path) -> Result<Vec<SnapshotMeta>, AfuseError> {
    list_snapshots_with_vault(workspace, None)
}

pub(crate) fn list_snapshots_unlocked(ws_vault: &Path) -> Result<Vec<SnapshotMeta>, AfuseError> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(ws_vault.join("snapshots")) {
        for entry in rd.flatten() {
            let snap_dir = entry.path();
            let meta_path = snap_dir.join("meta.kv");
            if meta_path.is_file() && snap_dir.join("tree").is_dir() {
                if let Ok(m) = read_meta(&meta_path) {
                    out.push(m);
                }
            }
        }
    }
    out.sort_by(|a, b| b.created_ms.cmp(&a.created_ms).then_with(|| b.id.cmp(&a.id)));
    Ok(out)
}

pub(crate) fn resolve_snapshot_id(
    ws_vault: &Path,
    target: &str,
) -> Result<SnapshotMeta, AfuseError> {
    let all = list_snapshots_unlocked(ws_vault)?;
    if all.is_empty() {
        return Err(AfuseError::new(
            ERR_ENOENT,
            "no snapshots exist for this workspace",
        ));
    }
    if target == "latest" || target.is_empty() {
        return Ok(all
            .iter()
            .find(|m| m.label != "auto:pre-restore")
            .unwrap_or(&all[0])
            .clone());
    }
    for m in &all {
        if m.id == target || m.id.starts_with(target) {
            return Ok(m.clone());
        }
    }
    if target != "latest"
        && !target.is_empty()
        && !target.contains('/')
        && !target.contains('\\')
        && !target.contains("..")
    {
        let snap_dir = ws_vault.join("snapshots").join(target);
        let direct_meta = snap_dir.join("meta.kv");
        if direct_meta.is_file() && snap_dir.join("tree").is_dir() {
            return read_meta(&direct_meta);
        }
    }
    Err(AfuseError::new(
        ERR_ENOENT,
        format!("snapshot '{}' not found", target),
    ))
}
