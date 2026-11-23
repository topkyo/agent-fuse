use crate::diff::diff_fast_unlocked;
use crate::error::{AfuseError, ERR_EINVAL};
use crate::manifest::{compute_fast_fingerprint, compute_tree_manifest, hash_file_streaming, SnapshotMeta};
use crate::sha256::{sha256_hex, Sha256};
use crate::vault::TargetKind;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub(crate) fn workspace_differs_fast_check(
    ws: &Path,
    ws_vault: &Path,
    meta: &SnapshotMeta,
) -> bool {
    match diff_fast_unlocked(ws, ws_vault, meta) {
        Ok(d) => !(d.report.added.is_empty() && d.report.modified.is_empty() && d.report.deleted.is_empty()),
        Err(_) => true,
    }
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
