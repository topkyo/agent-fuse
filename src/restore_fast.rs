use crate::apfs::{force_remove_all, force_unlock, lstat_inode_mode, swap_paths, TMP_SEQ};
use crate::diff::diff_fast_unlocked;
use crate::error::{AfuseError, ERR_EACCES, ERR_EINVAL, ERR_ENOENT};
use crate::fs_guard::clonefile_readable;
use crate::manifest::{
    compute_fast_fingerprint, compute_snap_tree_manifest, compute_tree_manifest,
    hash_file_streaming, SnapshotMeta, SnapshotOrigin,
};
use crate::restore_tree::{
    find_single_snap_file, force_unlock_tree_recursive, workspace_differs_full,
    workspace_has_visible_files, HeteroStashGuard, UnlockedDirsGuard,
};
use crate::sha256::{sha256_hex, Sha256};
use crate::snapshot::{
    create_snapshot_unlocked_full, list_snapshots_unlocked, resolve_snapshot_id,
};
use crate::vault::TargetKind;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

pub(crate) fn find_latest_primary(ws_vault: &Path) -> Option<SnapshotMeta> {
    list_snapshots_unlocked(ws_vault)
        .ok()?
        .into_iter()
        .find(|m| m.origin != SnapshotOrigin::BeforeRestore && m.label != "auto:pre-restore")
}

pub(crate) fn verify_snapshot_tree(
    ws: &Path,
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
        return Err(AfuseError::new(
            ERR_EINVAL,
            "snapshot metadata missing integrity digest (legacy unhashed 'fast' rejected)",
        ));
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

pub(crate) fn workspace_differs_fast_check(
    ws: &Path,
    ws_vault: &Path,
    meta: &SnapshotMeta,
) -> bool {
    match diff_fast_unlocked(ws, ws_vault, meta) {
        Ok(d) => !(d.report.added.is_empty()
            && d.report.modified.is_empty()
            && d.report.deleted.is_empty()
            && d.report.renamed.is_empty()),
        Err(_) => true,
    }
}

pub(crate) fn live_matches_snapshot_unlocked(
    ws: &Path,
    ws_vault: &Path,
    meta: &SnapshotMeta,
) -> bool {
    if meta.target_kind == TargetKind::SingleFile {
        let snap_tree = ws_vault.join("snapshots").join(&meta.id).join("tree");
        return !workspace_differs_full(ws, TargetKind::SingleFile, &snap_tree, None);
    }
    !workspace_differs_fast_check(ws, ws_vault, meta)
}

pub(crate) fn take_pre_restore_unconditional(
    ws: &Path,
    ws_vault: &Path,
) -> Result<Option<String>, AfuseError> {
    match create_snapshot_unlocked_full(
        ws,
        ws_vault,
        "auto:pre-restore",
        true,
        Some(SnapshotOrigin::BeforeRestore),
        None,
        None,
    ) {
        Ok(m) => Ok(Some(m.id)),
        Err(e) if e.code == ERR_EACCES => {
            force_unlock_tree_recursive(ws);
            create_snapshot_unlocked_full(
                ws,
                ws_vault,
                "auto:pre-restore",
                true,
                Some(SnapshotOrigin::BeforeRestore),
                None,
                None,
            )
            .map(|m| Some(m.id))
        }
        Err(e) => Err(e),
    }
}

pub(crate) fn append_post_restore_head(
    ws: &Path,
    ws_vault: &Path,
    source_snap_id: &str,
) -> Result<String, AfuseError> {
    let m = create_snapshot_unlocked_full(
        ws,
        ws_vault,
        "auto:pro:restored",
        true,
        Some(SnapshotOrigin::RestoredFrom),
        Some(source_snap_id.to_string()),
        None,
    )?;
    Ok(m.id)
}

pub(crate) fn compute_fast_receipt_hex(ws: &Path, kind: TargetKind) -> Result<(String, u64), AfuseError> {
    let (fp, files, _) = compute_fast_fingerprint(ws, kind)?;
    let hex = fp.strip_prefix("fast:").unwrap_or(&fp).to_string();
    Ok((hex, files))
}

pub(crate) fn verify_selective_restored_paths(
    ws: &Path,
    snap_tree: &Path,
    resolved: &[(Option<PathBuf>, Option<PathBuf>)],
) -> Result<(String, u64), AfuseError> {
    let mut receipt = Sha256::new();
    let mut verified_files = 0u64;
    for (snap_opt, live_opt) in resolved {
        if let Some(sr) = snap_opt {
            let sp = snap_tree.join(sr);
            let lp = ws.join(sr);
            let sm = fs::symlink_metadata(&sp)
                .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))?;
            let lm = fs::symlink_metadata(&lp)
                .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))?;
            let (sft, lft) = (sm.file_type(), lm.file_type());
            receipt.update(sr.to_string_lossy().as_bytes());
            receipt.update(b"\0");
            if sft.is_symlink() {
                if !lft.is_symlink() {
                    return Err(AfuseError::new(ERR_EINVAL, "post-restore symlink type mismatch"));
                }
                let st = fs::read_link(&sp).map_err(|e| AfuseError::new(1, e.to_string()))?;
                let lt = fs::read_link(&lp).map_err(|e| AfuseError::new(1, e.to_string()))?;
                if st != lt {
                    return Err(AfuseError::new(ERR_EINVAL, "post-restore symlink target mismatch"));
                }
                let h = sha256_hex(lt.as_os_str().as_bytes());
                receipt.update(b"L:");
                receipt.update(h.as_bytes());
                verified_files += 1;
            } else if sft.is_file() {
                if !lft.is_file() || lft.is_symlink() {
                    return Err(AfuseError::new(ERR_EINVAL, "post-restore file type mismatch"));
                }
                let sh = hash_file_streaming(&sp)?;
                let lh = hash_file_streaming(&lp)?;
                if sh != lh {
                    return Err(AfuseError::new(ERR_EINVAL, "post-restore selective checksum mismatch"));
                }
                receipt.update(b"F:");
                receipt.update(lh.as_bytes());
                verified_files += 1;
            } else if sft.is_dir() {
                if !lft.is_dir() || lft.is_symlink() {
                    return Err(AfuseError::new(ERR_EINVAL, "post-restore dir type mismatch"));
                }
                let (sh, _, _, _) = compute_tree_manifest(&sp)?;
                let (lh, fc, _, _) = compute_tree_manifest(&lp)?;
                if sh != lh {
                    return Err(AfuseError::new(ERR_EINVAL, "post-restore selective dir checksum mismatch"));
                }
                receipt.update(b"D:");
                receipt.update(lh.as_bytes());
                verified_files += fc;
            }
            receipt.update(b"\n");
        } else if let Some(lr) = live_opt {
            if fs::symlink_metadata(ws.join(lr)).is_ok() {
                return Err(AfuseError::new(ERR_EINVAL, "post-restore added path still exists"));
            }
            receipt.update(b"X:");
            receipt.update(lr.to_string_lossy().as_bytes());
            receipt.update(b"\n");
        }
    }
    Ok((receipt.finalize_hex(), verified_files))
}

pub(crate) fn prepare_restore_stage(
    ws: &Path,
    ws_vault: &Path,
    need_backup: bool,
    safety_backup: bool,
) -> Result<(u64, Option<String>, HeteroStashGuard), AfuseError> {
    let mut hetero = HeteroStashGuard::stash_if_needed(ws, ws_vault, true, safety_backup)?;
    if hetero.cleared || fs::symlink_metadata(ws).is_err() {
        let mut p_guard = UnlockedDirsGuard::new();
        if let Some(parent) = ws.parent() {
            if fs::symlink_metadata(parent).is_ok() {
                let _ = p_guard.unlock_if_needed(parent);
            }
        }
        let mk_res = fs::create_dir_all(ws).map_err(|e| {
            AfuseError::new(
                e.raw_os_error().unwrap_or(1),
                format!("cannot recreate workspace dir: {}", e),
            )
        });
        p_guard.restore_all();
        mk_res?;
        hetero.mark_placeholder_created();
        return Ok((0, None, hetero));
    }
    let (ino_before, _) = lstat_inode_mode(ws)?;
    force_unlock(ws);
    let safety_id = if need_backup && workspace_has_visible_files(ws) {
        take_pre_restore_unconditional(ws, ws_vault)?
    } else {
        None
    };
    Ok((ino_before, safety_id, hetero))
}

pub(crate) fn verify_root_inode(ws: &Path, ino_before: u64) -> Result<u64, AfuseError> {
    let (ino_after, _) = lstat_inode_mode(ws)?;
    if ino_before != 0 && ino_before != ino_after {
        return Err(AfuseError::new(
            ERR_EINVAL,
            format!("root Inode invariant violated: before={} after={}", ino_before, ino_after),
        ));
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
        return Err(AfuseError::new(
            e.raw_os_error().unwrap_or(1),
            format!("stage-2 rename failed: {}", e),
        ));
    }
    force_remove_all(tmp_old)
}

pub(crate) fn stage_and_replace(
    parent: &Path,
    tag: &str,
    snap_item: &Path,
    target: &Path,
) -> Result<(), AfuseError> {
    let pid = std::process::id();
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_new = parent.join(format!(".afuse.tmp.{}.{}.{}", tag, pid, seq));
    if fs::symlink_metadata(&tmp_new).is_ok() {
        force_remove_all(&tmp_new)?;
    }
    if let Err(e) = clonefile_readable(snap_item, &tmp_new) {
        let _ = force_remove_all(&tmp_new);
        return Err(e);
    }
    let tmp_old = parent.join(format!(".afuse.tmp.old.{}.{}", pid, seq));
    commit_staged_entry(&tmp_new, target, &tmp_old)
}
