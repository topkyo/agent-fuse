use crate::apfs::{
    clonefile_nofollow, force_remove_all, force_unlock, lstat_inode_mode, swap_paths, TMP_SEQ,
};
use crate::error::{AfuseError, ERR_EACCES, ERR_EINVAL, ERR_ENOENT};
use crate::manifest::{compute_tree_manifest, SnapshotMeta};
use crate::snapshot::{create_snapshot_unlocked_opts, resolve_snapshot_id};
use crate::vault::{is_ignored_name, lock_vault, resolve_workspace_vault_recovery};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
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
    pub elapsed_us: u128,
    pub selective: bool,
    pub restored_paths: usize,
}

fn force_unlock_tree_recursive(p: &Path) {
    force_unlock(p);
    if let Ok(meta) = fs::symlink_metadata(p) {
        if meta.file_type().is_dir() {
            if let Ok(rd) = fs::read_dir(p) {
                for entry in rd.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if !is_ignored_name(&name) {
                        force_unlock_tree_recursive(&entry.path());
                    }
                }
            }
        }
    }
}

fn verify_snapshot_tree(
    ws_vault: &Path,
    target_id: &str,
) -> Result<(SnapshotMeta, PathBuf, Option<String>), AfuseError> {
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
    } else {
        let (vh, _, _, _) = compute_tree_manifest(&snap_tree)?;
        if vh != meta.tree_sha256 {
            return Err(AfuseError::new(
                ERR_EINVAL,
                format!("snapshot integrity check failed: expected {}, found {}", meta.tree_sha256, vh),
            ));
        }
        Some(vh)
    };
    Ok((meta, snap_tree, vault_hash))
}

fn take_pre_restore_backup(
    ws: &Path,
    ws_vault: &Path,
    safety_backup: bool,
) -> Result<Option<String>, AfuseError> {
    if !safety_backup {
        return Ok(None);
    }
    match create_snapshot_unlocked_opts(ws, ws_vault, "auto:pre-restore", true) {
        Ok(m) => Ok(Some(m.id)),
        Err(e) if e.code == ERR_EACCES => {
            force_unlock_tree_recursive(ws);
            Ok(create_snapshot_unlocked_opts(ws, ws_vault, "auto:pre-restore", true).ok().map(|m| m.id))
        }
        Err(e) => Err(e),
    }
}

fn workspace_has_visible_files(ws: &Path) -> bool {
    let mut stack = vec![ws.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            if is_ignored_name(&entry.file_name().to_string_lossy()) {
                continue;
            }
            let p = entry.path();
            match fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_dir() => stack.push(p),
                Ok(_) => return true,
                Err(_) => {}
            }
        }
    }
    false
}

fn prepare_restore_stage(
    ws: &Path,
    ws_vault: &Path,
    safety_backup: bool,
) -> Result<(u64, Option<String>), AfuseError> {
    if !ws.exists() {
        if fs::symlink_metadata(ws).is_ok() {
            return Err(AfuseError::new(ERR_EINVAL, "workspace is not a directory"));
        }
        fs::create_dir_all(ws).map_err(|e| {
            AfuseError::new(e.raw_os_error().unwrap_or(1), format!("cannot recreate workspace dir: {}", e))
        })?;
        return Ok((0, None));
    }
    if !ws.is_dir() {
        return Err(AfuseError::new(ERR_EINVAL, "workspace is not a directory"));
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
        fs::rename(tmp_new, target).map_err(|e| {
            let _ = force_remove_all(tmp_new);
            AfuseError::new(e.raw_os_error().unwrap_or(1), format!("rename failed: {}", e))
        })?;
        return Ok(());
    }
    force_unlock(target);
    if swap_paths(tmp_new, target).is_ok() {
        force_remove_all(tmp_new)?;
        return Ok(());
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
    force_remove_all(tmp_old)?;
    Ok(())
}

fn stage_and_replace(parent: &Path, tag: &str, snap_item: &Path, target: &Path) -> Result<(), AfuseError> {
    let pid = std::process::id();
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_new = parent.join(format!(".afuse.tmp.{}.{}.{}", tag, pid, seq));
    if fs::symlink_metadata(&tmp_new).is_ok() {
        force_remove_all(&tmp_new)?;
    }
    clonefile_nofollow(snap_item, &tmp_new)?;
    let tmp_old = parent.join(format!(".afuse.tmp.old.{}.{}", pid, seq));
    commit_staged_entry(&tmp_new, target, &tmp_old)
}

pub fn restore_snapshot(workspace: &Path, target_id: &str, safety_backup: bool) -> Result<RestoreReport, AfuseError> {
    restore_snapshot_with_vault(workspace, None, target_id, safety_backup)
}

pub fn restore_snapshot_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    target_id: &str,
    safety_backup: bool,
) -> Result<RestoreReport, AfuseError> {
    let (ws, ws_vault) = resolve_workspace_vault_recovery(workspace, vault_override)?;
    if !ws_vault.join("snapshots").is_dir() {
        return Err(AfuseError::new(ERR_ENOENT, "no snapshots exist for this workspace"));
    }
    let _guard = lock_vault(&ws_vault)?;
    let t0 = Instant::now();
    let (meta, snap_tree, vault_hash) = verify_snapshot_tree(&ws_vault, target_id)?;
    let (ino_before, safety_id) = prepare_restore_stage(&ws, &ws_vault, safety_backup)?;

    let mut snap_children: BTreeMap<OsString, PathBuf> = BTreeMap::new();
    for entry in fs::read_dir(&snap_tree).map_err(|e| AfuseError::new(1, e.to_string()))? {
        let entry = entry.map_err(|e| AfuseError::new(1, e.to_string()))?;
        let name = entry.file_name();
        if !is_ignored_name(&name.to_string_lossy()) {
            snap_children.insert(name, entry.path());
        }
    }
    let mut ws_children: Vec<OsString> = Vec::new();
    for entry in fs::read_dir(&ws).map_err(|e| AfuseError::new(1, e.to_string()))? {
        let entry = entry.map_err(|e| AfuseError::new(1, e.to_string()))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(".afuse.tmp.") {
            let _ = force_remove_all(&entry.path());
            continue;
        }
        if !is_ignored_name(&name_str) {
            ws_children.push(name);
        }
    }

    for (name, snap_child) in &snap_children {
        stage_and_replace(&ws, "new", snap_child, &ws.join(name))?;
    }
    for name in ws_children {
        if !snap_children.contains_key(&name) {
            force_remove_all(&ws.join(name))?;
        }
    }

    let _ = fs::set_permissions(&ws, fs::Permissions::from_mode(meta.root_mode & 0o7777));
    let elapsed_us = t0.elapsed().as_micros();
    let ino_after = verify_root_inode(&ws, ino_before)?;
    let (live_hash, live_files, _, _) = compute_tree_manifest(&ws)?;
    if let Some(expected_hash) = vault_hash {
        if live_hash != expected_hash {
            return Err(AfuseError::new(ERR_EINVAL, format!("post-restore Merkle mismatch: expected {}, got {}", expected_hash, live_hash)));
        }
    }

    Ok(RestoreReport {
        snapshot_id: meta.id,
        safety_snapshot_id: safety_id,
        root_inode_before: ino_before,
        root_inode_after: ino_after,
        tree_sha256: live_hash,
        restored_files: live_files,
        elapsed_us,
        selective: false,
        restored_paths: 0,
    })
}

fn validate_rel_restore_path(raw: &str) -> Result<PathBuf, AfuseError> {
    if raw.contains('\\') {
        return Err(AfuseError::new(ERR_EINVAL, "selective restore path must not contain backslashes ('\\')"));
    }
    if raw.is_empty() || raw.trim().is_empty() || raw.contains('\0') {
        return Err(AfuseError::new(ERR_EINVAL, "selective restore path must be relative"));
    }
    let p = Path::new(raw);
    if p.is_absolute() {
        return Err(AfuseError::new(ERR_EINVAL, "selective restore rejects absolute paths"));
    }
    let mut clean = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s.starts_with(".afuse.tmp.") || is_ignored_name(&s) {
                    return Err(AfuseError::new(ERR_EINVAL, "rejected internal or ignored segment"));
                }
                clean.push(seg);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AfuseError::new(ERR_EINVAL, "rejected '..' or root traversal"));
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(AfuseError::new(ERR_EINVAL, "restore path resolves to workspace root"));
    }
    Ok(clean)
}

fn verify_no_symlink_ancestors(ws: &Path, rel: &Path, create_missing: bool) -> Result<(), AfuseError> {
    let mut cur = ws.to_path_buf();
    let comps: Vec<_> = rel.components().collect();
    if comps.len() <= 1 {
        return Ok(());
    }
    for comp in &comps[..comps.len() - 1] {
        cur.push(comp.as_os_str());
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.file_type().is_dir() => {
                return Err(AfuseError::new(ERR_EINVAL, "unsafe symlink or file ancestor"));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if create_missing {
                    fs::create_dir(&cur).map_err(|ce| AfuseError::new(ce.raw_os_error().unwrap_or(1), ce.to_string()))?;
                } else {
                    return Ok(());
                }
            }
            Err(e) => return Err(AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string())),
        }
    }
    Ok(())
}

pub fn restore_snapshot_paths(
    workspace: &Path,
    target_id: &str,
    safety_backup: bool,
    rel_paths: &[String],
) -> Result<RestoreReport, AfuseError> {
    restore_snapshot_paths_with_vault(workspace, None, target_id, safety_backup, rel_paths)
}

pub fn restore_snapshot_paths_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    target_id: &str,
    safety_backup: bool,
    rel_paths: &[String],
) -> Result<RestoreReport, AfuseError> {
    if rel_paths.is_empty() {
        return restore_snapshot_with_vault(workspace, vault_override, target_id, safety_backup);
    }
    let mut clean_paths = Vec::new();
    let mut seen = BTreeSet::new();
    for raw in rel_paths {
        let c = validate_rel_restore_path(raw)?;
        if seen.insert(c.clone()) {
            clean_paths.push(c);
        }
    }
    let (ws, ws_vault) = resolve_workspace_vault_recovery(workspace, vault_override)?;
    if !ws_vault.join("snapshots").is_dir() {
        return Err(AfuseError::new(ERR_ENOENT, "no snapshots exist for this workspace"));
    }
    let _guard = lock_vault(&ws_vault)?;
    let t0 = Instant::now();
    let (meta, snap_tree, _) = verify_snapshot_tree(&ws_vault, target_id)?;
    for rel in &clean_paths {
        if fs::symlink_metadata(snap_tree.join(rel)).is_err() && fs::symlink_metadata(ws.join(rel)).is_err() {
            return Err(AfuseError::new(ERR_ENOENT, "requested path does not exist in snapshot or workspace"));
        }
    }
    let (ino_before, safety_id) = prepare_restore_stage(&ws, &ws_vault, safety_backup)?;

    for rel in &clean_paths {
        let snap_item = snap_tree.join(rel);
        let dst_item = ws.join(rel);
        if fs::symlink_metadata(&snap_item).is_ok() {
            verify_no_symlink_ancestors(&ws, rel, true)?;
            stage_and_replace(dst_item.parent().unwrap_or(&ws), "sel", &snap_item, &dst_item)?;
        } else {
            verify_no_symlink_ancestors(&ws, rel, false)?;
            if fs::symlink_metadata(&dst_item).is_ok() {
                force_remove_all(&dst_item)?;
            }
        }
    }

    let elapsed_us = t0.elapsed().as_micros();
    let ino_after = verify_root_inode(&ws, ino_before)?;
    let (live_hash, live_files, _, _) = compute_tree_manifest(&ws)?;
    Ok(RestoreReport {
        snapshot_id: meta.id,
        safety_snapshot_id: safety_id,
        root_inode_before: ino_before,
        root_inode_after: ino_after,
        tree_sha256: live_hash,
        restored_files: live_files,
        elapsed_us,
        selective: true,
        restored_paths: clean_paths.len(),
    })
}
