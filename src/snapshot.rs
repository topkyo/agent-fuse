use crate::apfs::{force_remove_all, lstat_inode_mode, TMP_SEQ};
use crate::error::{AfuseError, ERR_EINVAL, ERR_ENOENT};
use crate::manifest::{
    clone_filtered_tree, compute_tree_manifest, compute_tree_stats_fast, read_meta, write_meta,
    SnapshotMeta,
};
pub use crate::restore::{
    restore_snapshot, restore_snapshot_paths, restore_snapshot_paths_with_vault,
    restore_snapshot_with_vault, RestoreReport,
};
use crate::vault::{
    lock_vault, prepare_live_workspace_vault_with, resolve_workspace_vault_recovery, PROJECT_MARKERS,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct DiffReport {
    pub snapshot_id: String,
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
}

pub fn create_snapshot(workspace: &Path, label: &str) -> Result<SnapshotMeta, AfuseError> {
    create_snapshot_opts_with_vault(workspace, None, label, false)
}

pub fn create_snapshot_fast(workspace: &Path, label: &str) -> Result<SnapshotMeta, AfuseError> {
    create_snapshot_opts_with_vault(workspace, None, label, true)
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
    let (ws, ws_vault) = prepare_live_workspace_vault_with(workspace, vault_override)?;
    let _guard = lock_vault(&ws_vault)?;
    create_snapshot_unlocked_opts(&ws, &ws_vault, label, fast)
}

pub fn create_snapshot_if_changed_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    label: &str,
) -> Result<(SnapshotMeta, bool), AfuseError> {
    let (ws, ws_vault) = prepare_live_workspace_vault_with(workspace, vault_override)?;
    let _guard = lock_vault(&ws_vault)?;
    let existing = list_snapshots_unlocked(&ws_vault)?;
    if let Some(latest) = existing.first() {
        let (live_sha, _, _, _) = compute_tree_manifest(&ws)?;
        let latest_sha = if latest.tree_sha256 == "fast" {
            let latest_tree = ws_vault.join("snapshots").join(&latest.id).join("tree");
            compute_tree_manifest(&latest_tree)
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

    let t0 = Instant::now();
    if let Err(e) = clone_filtered_tree(ws, &tree_dir) {
        let _ = force_remove_all(&snap_dir);
        return Err(e);
    }
    let clone_elapsed_us = t0.elapsed().as_micros();

    let (tree_sha256, file_count, logical_bytes) = if fast {
        let (fc, lb) = compute_tree_stats_fast(&tree_dir)?;
        ("fast".to_string(), fc, lb)
    } else {
        let (sha, fc, lb, _) = compute_tree_manifest(&tree_dir)?;
        (sha, fc, lb)
    };
    if label.starts_with("auto:") && label != "auto:pre-restore" {
        let has_marker = PROJECT_MARKERS
            .iter()
            .any(|m| fs::symlink_metadata(ws.join(m)).is_ok());
        if (!has_marker || file_count == 0)
            && list_snapshots_unlocked(ws_vault)?.iter().any(|m| m.file_count > 0)
        {
            let _ = force_remove_all(&snap_dir);
            return Err(AfuseError::new(
                ERR_EINVAL,
                "refusing auto-snapshot of empty or markerless workspace while non-empty history exists",
            ));
        }
    }

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
        logical_bytes,
        tree_sha256,
        elapsed_us: clone_elapsed_us,
    };
    write_meta(&snap_dir.join("meta.kv"), &meta)?;
    enforce_auto_snap_quota_unlocked(ws_vault, &meta.label)?;
    Ok(meta)
}

fn enforce_auto_snap_quota_unlocked(ws_vault: &Path, label: &str) -> Result<(), AfuseError> {
    if !label.starts_with("auto:") || label == "auto:pre-restore" {
        return Ok(());
    }
    let max_keep = std::env::var("AFUSE_MAX_AUTO_SNAPS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(50);
    if max_keep == 0 {
        return Ok(());
    }
    let all = list_snapshots_unlocked(ws_vault)?;
    for m in all
        .into_iter()
        .filter(|m| m.label.starts_with("auto:") && m.label != "auto:pre-restore")
        .skip(max_keep)
    {
        let dir = ws_vault.join("snapshots").join(&m.id);
        force_remove_all(&dir)?;
    }
    Ok(())
}

pub fn list_snapshots_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
) -> Result<Vec<SnapshotMeta>, AfuseError> {
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
    let snaps_dir = ws_vault.join("snapshots");
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(&snaps_dir) {
        for entry in rd.flatten() {
            let meta_path = entry.path().join("meta.kv");
            if meta_path.is_file() {
                if let Ok(m) = read_meta(&meta_path) {
                    out.push(m);
                }
            }
        }
    }
    out.sort_by(|a, b| {
        b.created_ms
            .cmp(&a.created_ms)
            .then_with(|| b.id.cmp(&a.id))
    });
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
        let direct_meta = ws_vault.join("snapshots").join(target).join("meta.kv");
        if direct_meta.is_file() {
            return read_meta(&direct_meta);
        }
    }
    Err(AfuseError::new(
        ERR_ENOENT,
        format!("snapshot '{}' not found", target),
    ))
}

pub fn diff_snapshot(workspace: &Path, target_id: &str) -> Result<DiffReport, AfuseError> {
    diff_snapshot_with_vault(workspace, None, target_id)
}

pub fn diff_snapshot_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    target_id: &str,
) -> Result<DiffReport, AfuseError> {
    let (ws, ws_vault) = resolve_workspace_vault_recovery(workspace, vault_override)?;
    if !ws_vault.join("snapshots").is_dir() {
        return Err(AfuseError::new(ERR_ENOENT, "no snapshots exist for this workspace"));
    }
    let _guard = lock_vault(&ws_vault)?;
    let meta = resolve_snapshot_id(&ws_vault, target_id)?;
    let snap_tree = ws_vault.join("snapshots").join(&meta.id).join("tree");

    let (_, _, _, snap_map) = compute_tree_manifest(&snap_tree)?;
    let live_map = if ws.is_dir() {
        compute_tree_manifest(&ws)?.3
    } else {
        BTreeMap::new()
    };

    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();

    let all_keys: BTreeSet<&String> = snap_map.keys().chain(live_map.keys()).collect();
    for k in all_keys {
        match (snap_map.get(k), live_map.get(k)) {
            (None, Some(_)) => added.push(k.clone()),
            (Some(_), None) => deleted.push(k.clone()),
            (Some(a), Some(b)) if a != b => modified.push(k.clone()),
            _ => {}
        }
    }

    Ok(DiffReport {
        snapshot_id: meta.id,
        added,
        modified,
        deleted,
    })
}
