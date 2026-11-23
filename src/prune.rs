use crate::apfs::force_remove_all;
use crate::error::{AfuseError, ERR_EINVAL};
use crate::manifest::{
    compute_fast_fingerprint, count_project_files, read_meta, write_meta, SnapshotMeta,
    SnapshotOrigin,
};
use crate::meta::PIN_CONTAINS_DELETED;
use crate::rolling::{enforce_pre_delete_quota_unlocked, is_delete_pinned, PRE_DELETE_LABEL};
use crate::snapshot::list_snapshots_unlocked;
use crate::vault::{lock_vault, resolve_workspace_vault_recovery, TargetKind};
use std::fs;
use std::path::Path;
use std::time::SystemTime;

pub(crate) const ORPHAN_MAX_AGE_SECS: u64 = 60;
pub(crate) const MAX_PRE_RESTORE_SNAPS: usize = 10;

pub(crate) fn is_primary_snapshot(m: &SnapshotMeta) -> bool {
    m.origin != SnapshotOrigin::BeforeRestore && m.label != "auto:pre-restore"
}

pub(crate) fn enforce_auto_snap_quota_unlocked(
    ws_vault: &Path,
    label: &str,
    origin: SnapshotOrigin,
) -> Result<(), AfuseError> {
    if origin == SnapshotOrigin::BeforeRestore || label == "auto:pre-restore" {
        for m in list_snapshots_unlocked(ws_vault)?
            .into_iter()
            .filter(|m| !is_primary_snapshot(m))
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
    let max_keep = std::env::var("AFUSE_MAX_AUTO_SNAPS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(50);
    if max_keep == 0 {
        return Ok(());
    }
    for m in list_snapshots_unlocked(ws_vault)?
        .into_iter()
        .filter(|m| m.label.starts_with("auto:") && is_primary_snapshot(m) && !is_delete_pinned(m))
        .skip(max_keep)
    {
        force_remove_all(&ws_vault.join("snapshots").join(&m.id))?;
    }
    Ok(())
}

pub(crate) fn snap_tree_fast_fp(ws_vault: &Path, meta: &SnapshotMeta) -> Option<String> {
    if meta.tree_sha256.starts_with("fast:") {
        return Some(meta.tree_sha256.clone());
    }
    let tree_dir = ws_vault.join("snapshots").join(&meta.id).join("tree");
    if meta.target_kind == TargetKind::SingleFile {
        let f = fs::read_dir(&tree_dir)
            .ok()?
            .flatten()
            .map(|e| e.path())
            .find(|p| p.is_file())?;
        return compute_fast_fingerprint(&f, TargetKind::SingleFile)
            .ok()
            .map(|x| x.0);
    }
    compute_fast_fingerprint(&tree_dir, TargetKind::Directory)
        .ok()
        .map(|x| x.0)
}

pub(crate) fn calibrate_legacy_meta_if_needed(snap_dir: &Path, meta: &mut SnapshotMeta) {
    let meta_p = snap_dir.join("meta.kv");
    let has_pf = fs::read_to_string(&meta_p)
        .map(|raw| raw.lines().any(|l| l.starts_with("project_files=")))
        .unwrap_or(false);
    if has_pf && meta.tree_sha256 != "fast" {
        return;
    }
    let tree_dir = snap_dir.join("tree");
    if !tree_dir.is_dir() {
        return;
    }
    let fp_target = if meta.target_kind == TargetKind::SingleFile {
        fs::read_dir(&tree_dir)
            .ok()
            .and_then(|rd| rd.flatten().map(|e| e.path()).find(|p| p.is_file()))
            .unwrap_or_else(|| tree_dir.clone())
    } else {
        tree_dir.clone()
    };
    meta.project_files = count_project_files(&fp_target, meta.target_kind);
    if meta.tree_sha256 == "fast" {
        if let Ok((fp, fc, lb)) = compute_fast_fingerprint(&fp_target, meta.target_kind) {
            meta.tree_sha256 = fp;
            meta.file_count = fc;
            meta.logical_bytes = lb;
        }
    }
    let _ = write_meta(&meta_p, meta);
}

pub(crate) fn dedup_and_calibrate_history_unlocked(ws_vault: &Path) -> Result<usize, AfuseError> {
    let mut all = list_snapshots_unlocked(ws_vault)?;
    for m in &mut all {
        calibrate_legacy_meta_if_needed(&ws_vault.join("snapshots").join(&m.id), m);
    }
    let mut prev_fp: Option<String> = None;
    let mut removed = 0usize;
    for m in all {
        let protected = m.origin == SnapshotOrigin::BeforeRestore
            || m.origin == SnapshotOrigin::RestoredFrom
            || m.label == "auto:pre-restore"
            || m.label == "auto:pro:pre-delete"
            || m.retention_pin.as_deref() == Some(PIN_CONTAINS_DELETED);
        if protected {
            prev_fp = None;
            continue;
        }
        let cur_fp = snap_tree_fast_fp(ws_vault, &m);
        if m.label.starts_with("auto:") && prev_fp.is_some() && cur_fp == prev_fp {
            if force_remove_all(&ws_vault.join("snapshots").join(&m.id)).is_ok() {
                removed += 1;
            }
        } else if cur_fp.is_some() {
            prev_fp = cur_fp;
        }
    }
    Ok(removed)
}

pub(crate) fn cleanup_orphan_snapshots_unlocked(ws_vault: &Path, min_age_secs: u64) -> usize {
    let snaps_dir = ws_vault.join("snapshots");
    let Ok(rd) = fs::read_dir(&snaps_dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut cleaned = 0usize;
    for entry in rd.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let meta_p = p.join("meta.kv");
        let tree_ok = p.join("tree").is_dir();
        let meta_ok = meta_p.is_file() && read_meta(&meta_p).is_ok();
        if tree_ok && meta_ok {
            continue;
        }
        let corrupt_zombie = meta_p.is_file();
        let is_stale = corrupt_zombie
            || min_age_secs == 0
            || fs::symlink_metadata(&p)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|mt| now.duration_since(mt).ok())
                .map(|age| age.as_secs() >= min_age_secs)
                .unwrap_or(false);
        if is_stale && force_remove_all(&p).is_ok() {
            cleaned += 1;
        }
    }
    cleaned
}

pub(crate) fn is_prune_protected(m: &SnapshotMeta) -> bool {
    is_delete_pinned(m)
        || m.origin == SnapshotOrigin::BeforeRestore
        || m.origin == SnapshotOrigin::Initial
        || m.label == "auto:pre-restore"
        || m.label == "auto:pro:init"
}

pub(crate) fn prune_unlocked(
    ws_vault: &Path,
    keep_latest: usize,
    label_prefix: Option<&str>,
    orphan_min_age_secs: u64,
) -> Result<usize, AfuseError> {
    if let Some(pfx) = label_prefix {
        if pfx.trim().is_empty() {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "--label-prefix must not be empty",
            ));
        }
    }
    let mut removed = cleanup_orphan_snapshots_unlocked(ws_vault, orphan_min_age_secs);
    if !(keep_latest == 0 && label_prefix.is_none()) {
        removed += dedup_and_calibrate_history_unlocked(ws_vault)?;
    }
    let all = list_snapshots_unlocked(ws_vault)?;
    match label_prefix {
        Some(pfx) => {
            let protect_special = keep_latest > 0 && pfx == "auto:";
            for m in all
                .into_iter()
                .filter(|m| m.label.starts_with(pfx) && (!protect_special || !is_prune_protected(m)))
                .skip(keep_latest)
            {
                let dir = ws_vault.join("snapshots").join(&m.id);
                force_remove_all(&dir)?;
                removed += 1;
            }
        }
        None => {
            for m in all.into_iter().skip(keep_latest) {
                let dir = ws_vault.join("snapshots").join(&m.id);
                force_remove_all(&dir)?;
                removed += 1;
            }
        }
    }
    Ok(removed)
}

pub fn parse_prune_args(args: &[String]) -> Result<(usize, Option<String>, bool), AfuseError> {
    let mut keep: Option<usize> = None;
    let mut label_prefix: Option<String> = None;
    let mut json = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--keep" => {
                if i + 1 >= args.len() {
                    return Err(AfuseError::new(ERR_EINVAL, "--keep requires a non-negative integer"));
                }
                let parsed = args[i + 1].parse::<usize>().map_err(|_| {
                    AfuseError::new(
                        ERR_EINVAL,
                        format!("invalid --keep count '{}': expected non-negative integer", args[i + 1]),
                    )
                })?;
                keep = Some(parsed);
                i += 2;
            }
            "--label-prefix" => {
                if i + 1 >= args.len() {
                    return Err(AfuseError::new(ERR_EINVAL, "--label-prefix requires a non-empty string"));
                }
                let pfx = args[i + 1].clone();
                if pfx.trim().is_empty() {
                    return Err(AfuseError::new(ERR_EINVAL, "--label-prefix must not be empty"));
                }
                label_prefix = Some(pfx);
                i += 2;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            other => {
                return Err(AfuseError::new(
                    ERR_EINVAL,
                    format!("unknown prune option '{}': expected --keep <N> [--label-prefix <P>] [--json]", other),
                ));
            }
        }
    }
    let keep_val = keep.ok_or_else(|| {
        AfuseError::new(
            ERR_EINVAL,
            "prune requires explicit --keep <N> to prevent accidental snapshot deletion",
        )
    })?;
    Ok((keep_val, label_prefix, json))
}

pub fn prune_snapshots(workspace: &Path, keep_latest: usize) -> Result<usize, AfuseError> {
    prune_snapshots_filtered_with_vault(workspace, None, keep_latest, None)
}

pub fn prune_snapshots_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    keep_latest: usize,
) -> Result<usize, AfuseError> {
    prune_snapshots_filtered_with_vault(workspace, vault_override, keep_latest, None)
}

pub fn prune_snapshots_filtered(
    workspace: &Path,
    keep_latest: usize,
    label_prefix: Option<&str>,
) -> Result<usize, AfuseError> {
    prune_snapshots_filtered_with_vault(workspace, None, keep_latest, label_prefix)
}

pub fn prune_snapshots_filtered_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    keep_latest: usize,
    label_prefix: Option<&str>,
) -> Result<usize, AfuseError> {
    let (_ws, ws_vault) = resolve_workspace_vault_recovery(workspace, vault_override)?;
    if !ws_vault.exists() {
        return Ok(0);
    }
    let snaps_dir = ws_vault.join("snapshots");
    if !snaps_dir.is_dir() {
        if keep_latest == 0 {
            force_remove_all(&ws_vault)?;
        }
        return Ok(0);
    }
    let guard = lock_vault(&ws_vault)?;
    let removed = prune_unlocked(&ws_vault, keep_latest, label_prefix, ORPHAN_MAX_AGE_SECS)?;
    let has_remaining_dirs = fs::read_dir(&snaps_dir)
        .map(|rd| rd.flatten().any(|e| e.path().is_dir()))
        .unwrap_or(false);
    let can_drop_vault = keep_latest == 0
        && (label_prefix.map(|s| s.is_empty()).unwrap_or(true) || !has_remaining_dirs);
    if can_drop_vault {
        drop(guard);
        force_remove_all(&ws_vault)?;
    }
    Ok(removed)
}

// MARK: - Transparent Hook Snippets, Depth-Aware JSON Scanner & Fail-Open `--exec`
