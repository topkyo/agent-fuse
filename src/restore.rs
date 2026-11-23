use crate::apfs::{
    force_remove_all, force_unlock, lstat_inode_mode, statfs_info, swap_paths, TMP_SEQ,
};
use crate::error::{AfuseError, ERR_EACCES, ERR_EINVAL, ERR_ENOENT};
use crate::fs_guard::clonefile_readable;
use crate::manifest::{
    compute_fast_fingerprint, compute_single_file_manifest, compute_snap_tree_manifest,
    compute_tree_manifest, count_project_files, SnapshotMeta,
};
use crate::restore_fast::{
    compute_fast_receipt_hex, verify_selective_restored_paths, workspace_differs_fast_check,
};
use crate::restore_tree::{
    align_ancestor_case, clear_heterogeneous_path_if_needed, find_single_snap_file,
    force_unlock_tree_recursive, lock_guard_single_dir, prepare_ancestors_writable,
    resolve_disk_rel_path, same_disk_entry, selective_differs, top_level_nfd_key,
    validate_rel_restore_path, workspace_differs_full, workspace_has_visible_files,
    NestedIgnoredGuard, UnlockedDirsGuard,
};
use crate::snapshot::{
    create_snapshot_fast_dedup_unlocked, create_snapshot_unlocked_opts, resolve_snapshot_id,
};
use crate::trash::{purge_trashed_counterparts, TrashCleanupStatus};
use crate::trash_map::purge_trashed_selective_paths;
use crate::unicode_norm::components_equal_casefold_nfd;
use crate::vault::{is_ignored_name, lock_vault, resolve_workspace_vault_recovery, TargetKind};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct RestoreReport {
    pub snapshot_id: String,
    pub safety_snapshot_id: Option<String>,
    pub root_inode_before: u64,
    pub root_inode_after: u64,
    pub tree_sha256: String,
    pub restored_files: u64,
    pub project_files: u64,
    pub elapsed_us: u128,
    pub selective: bool,
    pub restored_paths: usize,
    pub trash_cleanup: TrashCleanupStatus,
}

fn verify_snapshot_tree(ws: &Path, ws_vault: &Path, target_id: &str) -> Result<(SnapshotMeta, PathBuf, Option<String>), AfuseError> {
    if !ws_vault.join("snapshots").is_dir() {
        return Err(AfuseError::new(ERR_ENOENT, "no snapshots exist for this workspace"));
    }
    let meta = resolve_snapshot_id(ws_vault, target_id)?;
    let snap_tree = ws_vault.join("snapshots").join(&meta.id).join("tree");
    if !snap_tree.is_dir() {
        return Err(AfuseError::new(ERR_ENOENT, format!("snapshot tree missing on disk: {}", snap_tree.display())));
    }
    let vault_hash = if meta.tree_sha256 == "fast" {
        None
    } else if meta.tree_sha256.starts_with("fast:") {
        let fp_target = if meta.target_kind == TargetKind::SingleFile {
            find_single_snap_file(ws, &snap_tree)
                .ok_or_else(|| AfuseError::new(ERR_ENOENT, "snapshot file missing in tree"))?
        } else {
            snap_tree.clone()
        };
        let (actual_fp, _, _) = compute_fast_fingerprint(&fp_target, meta.target_kind)?;
        if actual_fp != meta.tree_sha256 {
            return Err(AfuseError::new(
                ERR_EINVAL,
                format!("fast snapshot integrity mismatch: expected {}, found {}", meta.tree_sha256, actual_fp),
            ));
        }
        None
    } else {
        let (vh, _, _, _) = compute_snap_tree_manifest(&snap_tree, ws, meta.target_kind)?;
        if vh != meta.tree_sha256 {
            return Err(AfuseError::new(ERR_EINVAL, format!("snapshot integrity mismatch: expected {}, found {}", meta.tree_sha256, vh)));
        }
        Some(vh)
    };
    Ok((meta, snap_tree, vault_hash))
}

fn take_pre_restore_backup(ws: &Path, ws_vault: &Path, safety_backup: bool) -> Result<Option<String>, AfuseError> {
    if !safety_backup { return Ok(None); }
    match create_snapshot_fast_dedup_unlocked(ws, ws_vault, "auto:pre-restore") {
        Ok((m, _)) => Ok(Some(m.id)),
        Err(e) if e.code == ERR_EACCES => {
            force_unlock_tree_recursive(ws);
            Ok(create_snapshot_unlocked_opts(ws, ws_vault, "auto:pre-restore", true).ok().map(|m| m.id))
        }
        Err(e) => Err(e),
    }
}

fn prepare_restore_stage(ws: &Path, ws_vault: &Path, safety_backup: bool) -> Result<(u64, Option<String>), AfuseError> {
    let cleared = clear_heterogeneous_path_if_needed(ws, true)?;
    if cleared || fs::symlink_metadata(ws).is_err() {
        fs::create_dir_all(ws).map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), format!("cannot recreate workspace dir: {}", e)))?;
        return Ok((0, None));
    }
    let (ino_before, _) = lstat_inode_mode(ws)?;
    force_unlock(ws);
    let safety_id = if workspace_has_visible_files(ws) {
        take_pre_restore_backup(ws, ws_vault, safety_backup)?
    } else {
        None
    };
    Ok((ino_before, safety_id))
}

fn verify_root_inode(ws: &Path, ino_before: u64) -> Result<u64, AfuseError> {
    let (ino_after, _) = lstat_inode_mode(ws)?;
    if ino_before != 0 && ino_before != ino_after {
        return Err(AfuseError::new(ERR_EINVAL, format!("root Inode invariant violated: before={} after={}", ino_before, ino_after)));
    }
    Ok(ino_after)
}

fn commit_staged_entry(tmp_new: &Path, target: &Path, tmp_old: &Path) -> Result<(), AfuseError> {
    if fs::symlink_metadata(target).is_err() {
        return fs::rename(tmp_new, target).map_err(|e| {
            let _ = force_remove_all(tmp_new);
            AfuseError::new(e.raw_os_error().unwrap_or(1), format!("rename failed: {}", e))
        });
    }
    force_unlock(target);
    if swap_paths(tmp_new, target).is_ok() {
        return force_remove_all(tmp_new);
    }
    if fs::symlink_metadata(tmp_old).is_ok() {
        force_remove_all(tmp_old)?;
    }
    fs::rename(target, tmp_old).map_err(|e| {
        let _ = force_remove_all(tmp_new);
        AfuseError::new(e.raw_os_error().unwrap_or(1), format!("stage-1 rename failed: {}", e))
    })?;
    if let Err(e) = fs::rename(tmp_new, target) {
        let _ = fs::rename(tmp_old, target);
        let _ = force_remove_all(tmp_new);
        return Err(AfuseError::new(e.raw_os_error().unwrap_or(1), format!("stage-2 rename failed: {}", e)));
    }
    force_remove_all(tmp_old)
}

fn stage_and_replace(parent: &Path, tag: &str, snap_item: &Path, target: &Path) -> Result<(), AfuseError> {
    let pid = std::process::id();
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_new = parent.join(format!(".afuse.tmp.{}.{}.{}", tag, pid, seq));
    if fs::symlink_metadata(&tmp_new).is_ok() {
        force_remove_all(&tmp_new)?;
    }
    clonefile_readable(snap_item, &tmp_new)?;
    let tmp_old = parent.join(format!(".afuse.tmp.old.{}.{}", pid, seq));
    commit_staged_entry(&tmp_new, target, &tmp_old)
}

#[allow(clippy::too_many_arguments)]
fn finalize_restore_unlocked(
    ws: &Path, kind: TargetKind, ws_vault: &Path, meta: &SnapshotMeta,
    ino_before: u64, ino_after: u64, safety_id: Option<String>,
    selective: bool, restored_paths: usize, vault_hash: Option<&str>,
    fast_receipt: bool, selective_ctx: Option<(&Path, &[(Option<PathBuf>, Option<PathBuf>)], &[PathBuf])>,
    t0: Instant,
) -> Result<RestoreReport, AfuseError> {
    let elapsed_us = t0.elapsed().as_micros();
    let (live_hash, live_files) = if let Some((snap_tree, resolved, _)) = selective_ctx {
        verify_selective_restored_paths(ws, snap_tree, resolved)?
    } else if fast_receipt && vault_hash.is_none() {
        compute_fast_receipt_hex(ws, kind)?
    } else if kind == TargetKind::SingleFile {
        let (h, f, _, _) = compute_single_file_manifest(ws)?;
        (h, f)
    } else {
        let (h, f, _, _) = compute_tree_manifest(ws)?;
        (h, f)
    };
    if let Some(expected) = vault_hash {
        if live_hash != expected {
            return Err(AfuseError::new(ERR_EINVAL, format!("post-restore Merkle mismatch: expected {}, got {}", expected, live_hash)));
        }
    }
    let snap_dir = ws_vault.join("snapshots").join(&meta.id);
    let trash_cleanup = if selective {
        let clean_paths = selective_ctx.map(|x| x.2).unwrap_or(&[]);
        statfs_info(ws)
            .map(|fsi| purge_trashed_selective_paths(ws, ws_vault, &snap_dir, clean_paths, fsi.fsid))
            .unwrap_or(TrashCleanupStatus::NotInTrash)
    } else {
        let stat_p = if kind == TargetKind::SingleFile { ws.parent().unwrap_or(ws) } else { ws };
        statfs_info(stat_p)
            .map(|fsi| purge_trashed_counterparts(ws, kind, ws_vault, &snap_dir, meta, fsi.fsid))
            .unwrap_or(TrashCleanupStatus::NotInTrash)
    };
    Ok(RestoreReport {
        snapshot_id: meta.id.clone(), safety_snapshot_id: safety_id,
        root_inode_before: ino_before, root_inode_after: ino_after,
        tree_sha256: live_hash, restored_files: live_files,
        project_files: count_project_files(ws, kind), elapsed_us,
        selective, restored_paths, trash_cleanup,
    })
}

fn restore_single_file_unlocked(
    ws: &Path, ws_vault: &Path, meta: &SnapshotMeta, snap_tree: &Path,
    vault_hash: Option<&str>, safety_backup: bool, fast_receipt: bool, t0: Instant,
) -> Result<RestoreReport, AfuseError> {
    let parent = ws.parent().ok_or_else(|| AfuseError::new(ERR_EINVAL, "missing parent directory"))?;
    let ino_before = if parent.is_dir() {
        lstat_inode_mode(parent)?.0
    } else {
        fs::create_dir_all(parent).map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))?;
        0
    };
    let mut parent_guard = lock_guard_single_dir(parent)?;
    let cleared_hetero = clear_heterogeneous_path_if_needed(ws, false)?;
    let effective_backup = !cleared_hetero && safety_backup && workspace_differs_full(ws, TargetKind::SingleFile, snap_tree, vault_hash);
    let safety_id = if !cleared_hetero && fs::symlink_metadata(ws).is_ok() {
        let sid = take_pre_restore_backup(ws, ws_vault, effective_backup)?;
        force_unlock(ws);
        sid
    } else {
        None
    };
    let snap_file = find_single_snap_file(ws, snap_tree)
        .ok_or_else(|| AfuseError::new(ERR_ENOENT, "snapshot file missing in tree"))?;
    stage_and_replace(parent, "file", &snap_file, ws)?;
    let _ = fs::set_permissions(ws, fs::Permissions::from_mode(meta.root_mode & 0o7777));
    parent_guard.restore_all();
    let ino_after = verify_root_inode(parent, ino_before)?;
    finalize_restore_unlocked(ws, TargetKind::SingleFile, ws_vault, meta, ino_before, ino_after, safety_id, false, 0, vault_hash, fast_receipt, None, t0)
}

pub fn restore_snapshot(workspace: &Path, target_id: &str, safety_backup: bool) -> Result<RestoreReport, AfuseError> {
    restore_snapshot_opts_with_vault(workspace, None, target_id, safety_backup, false)
}

pub fn restore_snapshot_fast(workspace: &Path, target_id: &str, safety_backup: bool) -> Result<RestoreReport, AfuseError> {
    restore_snapshot_opts_with_vault(workspace, None, target_id, safety_backup, true)
}

pub fn restore_snapshot_with_vault(
    workspace: &Path, vault_override: Option<&Path>, target_id: &str, safety_backup: bool,
) -> Result<RestoreReport, AfuseError> {
    restore_snapshot_opts_with_vault(workspace, vault_override, target_id, safety_backup, false)
}

pub fn restore_snapshot_opts_with_vault(
    workspace: &Path, vault_override: Option<&Path>, target_id: &str, safety_backup: bool, fast: bool,
) -> Result<RestoreReport, AfuseError> {
    let (ws, ws_vault) = resolve_workspace_vault_recovery(workspace, vault_override)?;
    let _guard = lock_vault(&ws_vault)?;
    let t0 = Instant::now();
    let (meta, snap_tree, vault_hash) = verify_snapshot_tree(&ws, &ws_vault, target_id)?;
    if meta.target_kind == TargetKind::SingleFile {
        return restore_single_file_unlocked(&ws, &ws_vault, &meta, &snap_tree, vault_hash.as_deref(), safety_backup, fast, t0);
    }
    let effective_backup = safety_backup && if fast && vault_hash.is_none() {
        workspace_differs_fast_check(&ws, &ws_vault, &meta)
    } else {
        workspace_differs_full(&ws, TargetKind::Directory, &snap_tree, vault_hash.as_deref())
    };
    let (ino_before, safety_id) = prepare_restore_stage(&ws, &ws_vault, effective_backup)?;
    let mut nested_guard = NestedIgnoredGuard::preserve(&ws)?;
    let mut snap_children: BTreeMap<String, (OsString, PathBuf)> = BTreeMap::new();
    for entry in fs::read_dir(&snap_tree).map_err(|e| AfuseError::new(1, e.to_string()))? {
        let entry = entry.map_err(|e| AfuseError::new(1, e.to_string()))?;
        let name = entry.file_name();
        if !is_ignored_name(&name.to_string_lossy()) {
            snap_children.insert(top_level_nfd_key(&name), (name, entry.path()));
        }
    }
    let mut ws_children: Vec<(String, OsString)> = Vec::new();
    for entry in fs::read_dir(&ws).map_err(|e| AfuseError::new(1, e.to_string()))? {
        let entry = entry.map_err(|e| AfuseError::new(1, e.to_string()))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == nested_guard.stage_name { continue; }
        if name_str.starts_with(".afuse.tmp.") {
            let _ = force_remove_all(&entry.path());
        } else if !is_ignored_name(&name_str) {
            ws_children.push((top_level_nfd_key(&name), name));
        }
    }
    let mut handled_aliases: BTreeSet<OsString> = BTreeSet::new();
    for (nfd_k, (snap_name, snap_child)) in &snap_children {
        for (ws_k, ws_name) in &ws_children {
            let is_alias = ws_name != snap_name
                && (ws_k == nfd_k
                    || (components_equal_casefold_nfd(Path::new(ws_name), Path::new(snap_name))
                        && same_disk_entry(&ws.join(ws_name), &ws.join(snap_name))));
            if is_alias {
                handled_aliases.insert(ws_name.clone());
                let _ = force_remove_all(&ws.join(ws_name));
            }
        }
        stage_and_replace(&ws, "new", snap_child, &ws.join(snap_name))?;
    }
    for (nfd_k, ws_name) in ws_children {
        let points_to_restored = handled_aliases.contains(&ws_name)
            || snap_children.values().any(|(sn, _)| same_disk_entry(&ws.join(&ws_name), &ws.join(sn)));
        if !snap_children.contains_key(&nfd_k) && !points_to_restored {
            force_remove_all(&ws.join(ws_name))?;
        }
    }
    nested_guard.restore_back()?;
    let _ = fs::set_permissions(&ws, fs::Permissions::from_mode(meta.root_mode & 0o7777));
    let ino_after = verify_root_inode(&ws, ino_before)?;
    finalize_restore_unlocked(&ws, TargetKind::Directory, &ws_vault, &meta, ino_before, ino_after, safety_id, false, 0, vault_hash.as_deref(), fast, None, t0)
}

pub fn restore_snapshot_paths(
    workspace: &Path, target_id: &str, safety_backup: bool, rel_paths: &[String],
) -> Result<RestoreReport, AfuseError> {
    restore_snapshot_paths_with_vault(workspace, None, target_id, safety_backup, rel_paths)
}

pub fn restore_snapshot_paths_with_vault(
    workspace: &Path, vault_override: Option<&Path>, target_id: &str, safety_backup: bool, rel_paths: &[String],
) -> Result<RestoreReport, AfuseError> {
    if rel_paths.is_empty() {
        return restore_snapshot_with_vault(workspace, vault_override, target_id, safety_backup);
    }
    let mut clean_paths = Vec::new();
    let mut seen = BTreeSet::new();
    for raw in rel_paths {
        let c = validate_rel_restore_path(raw)?;
        if seen.insert(c.clone()) { clean_paths.push(c); }
    }
    let (ws, ws_vault) = resolve_workspace_vault_recovery(workspace, vault_override)?;
    let _guard = lock_vault(&ws_vault)?;
    let t0 = Instant::now();
    let (meta, snap_tree, vault_hash) = verify_snapshot_tree(&ws, &ws_vault, target_id)?;
    if meta.target_kind == TargetKind::SingleFile {
        if clean_paths.len() == 1
            && ws.file_name().map(|n| top_level_nfd_key(n) == top_level_nfd_key(clean_paths[0].as_os_str())).unwrap_or(false)
        {
            return restore_single_file_unlocked(&ws, &ws_vault, &meta, &snap_tree, vault_hash.as_deref(), safety_backup, true, t0);
        }
        return Err(AfuseError::new(ERR_EINVAL, "invalid selective path for single-file target"));
    }
    let ws_is_real_dir = fs::symlink_metadata(&ws)
        .map(|m| m.file_type().is_dir() && !m.file_type().is_symlink())
        .unwrap_or(false);
    let mut resolved = Vec::with_capacity(clean_paths.len());
    for rel in &clean_paths {
        let snap_rel = resolve_disk_rel_path(&snap_tree, rel)?;
        let live_rel = if ws_is_real_dir { resolve_disk_rel_path(&ws, rel)? } else { None };
        if snap_rel.is_none() && live_rel.is_none() {
            return Err(AfuseError::new(ERR_ENOENT, "requested path does not exist in snapshot or workspace"));
        }
        resolved.push((snap_rel, live_rel));
    }
    let effective_backup = safety_backup && selective_differs(&ws, &snap_tree, &resolved);
    let mut dir_guard = UnlockedDirsGuard::new();
    if ws_is_real_dir { dir_guard.unlock_if_needed(&ws)?; }
    let (ino_before, safety_id) = prepare_restore_stage(&ws, &ws_vault, effective_backup)?;
    let mut nested_guard = NestedIgnoredGuard::preserve(&ws)?;
    for (snap_rel_opt, live_rel_opt) in &resolved {
        if let Some(snap_rel) = snap_rel_opt {
            if let Some(live_rel) = live_rel_opt {
                if live_rel != snap_rel {
                    prepare_ancestors_writable(&ws, live_rel, false, &mut dir_guard)?;
                    let _ = force_remove_all(&ws.join(live_rel));
                }
            }
            align_ancestor_case(&ws, snap_rel, &mut dir_guard)?;
            prepare_ancestors_writable(&ws, snap_rel, true, &mut dir_guard)?;
            let dst_item = ws.join(snap_rel);
            stage_and_replace(dst_item.parent().unwrap_or(&ws), "sel", &snap_tree.join(snap_rel), &dst_item)?;
        } else if let Some(live_rel) = live_rel_opt {
            prepare_ancestors_writable(&ws, live_rel, false, &mut dir_guard)?;
            let dst_item = ws.join(live_rel);
            if fs::symlink_metadata(&dst_item).is_ok() { force_remove_all(&dst_item)?; }
        }
    }
    dir_guard.restore_all();
    nested_guard.restore_back()?;
    let ino_after = verify_root_inode(&ws, ino_before)?;
    finalize_restore_unlocked(&ws, TargetKind::Directory, &ws_vault, &meta, ino_before, ino_after, safety_id, true, clean_paths.len(), None, true, Some((&snap_tree, &resolved, &clean_paths)), t0)
}
