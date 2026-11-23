use crate::apfs::force_remove_all;
use crate::diff::{diff_fast_unlocked, parse_fast_file_sig, FAST_REHASH_MAX_BYTES};
use crate::error::{AfuseError, ERR_EINVAL};
use crate::manifest::{hash_file_streaming, write_meta, SnapshotMeta};
use crate::snapshot::{
    create_snapshot_fast_dedup_unlocked, create_snapshot_unlocked_opts, list_snapshots_unlocked,
};
use crate::vault::{lock_vault, prepare_live_workspace_vault_with};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

pub const PRE_DELETE_LABEL: &str = "auto:pro:pre-delete";
pub(crate) const MAX_PRE_DELETE_SNAPS: usize = 10;

#[derive(Debug, Clone)]
pub struct RollingSnapReport {
    pub meta: SnapshotMeta,
    pub deduplicated: bool,
    pub skipped: bool,
    pub reason: Option<&'static str>,
    pub promoted_pre_delete_id: Option<String>,
}

fn is_project_path(rel: &str) -> bool {
    rel != ".git" && !rel.starts_with(".git/")
}

pub(crate) fn enforce_pre_delete_quota_unlocked(ws_vault: &Path) -> Result<(), AfuseError> {
    for m in list_snapshots_unlocked(ws_vault)?
        .into_iter()
        .filter(|m| m.label == PRE_DELETE_LABEL)
        .skip(MAX_PRE_DELETE_SNAPS)
    {
        force_remove_all(&ws_vault.join("snapshots").join(&m.id))?;
    }
    Ok(())
}

fn promote_latest_to_pre_delete_unlocked(
    ws_vault: &Path,
    latest: &SnapshotMeta,
) -> Result<Option<String>, AfuseError> {
    if !latest.label.starts_with("auto:")
        || latest.label == "auto:pre-restore"
        || latest.label == PRE_DELETE_LABEL
    {
        return Ok(None);
    }
    let mut promoted = latest.clone();
    promoted.label = PRE_DELETE_LABEL.to_string();
    let meta_path = ws_vault
        .join("snapshots")
        .join(&promoted.id)
        .join("meta.kv");
    write_meta(&meta_path, &promoted)?;
    enforce_pre_delete_quota_unlocked(ws_vault)?;
    Ok(Some(promoted.id))
}

fn is_pure_rename_all(
    snap_tree: &Path,
    ws: &Path,
    snap_entries: &BTreeMap<String, String>,
    live_entries: &BTreeMap<String, String>,
    proj_deleted: &[String],
    proj_added: &[String],
) -> bool {
    if proj_deleted.is_empty() || proj_added.len() < proj_deleted.len() {
        return false;
    }
    let mut added_by_len: HashMap<u64, Vec<usize>> = HashMap::new();
    for (idx, rel) in proj_added.iter().enumerate() {
        let Some(sig) = live_entries.get(rel) else {
            continue;
        };
        let Some((_, len)) = parse_fast_file_sig(sig) else {
            continue;
        };
        if len <= FAST_REHASH_MAX_BYTES {
            added_by_len.entry(len).or_default().push(idx);
        }
    }
    let mut used_added = vec![false; proj_added.len()];
    let mut added_hashes: HashMap<usize, Option<String>> = HashMap::new();

    for d_rel in proj_deleted {
        let Some(d_sig) = snap_entries.get(d_rel) else {
            return false;
        };
        let Some((_, d_len)) = parse_fast_file_sig(d_sig) else {
            return false;
        };
        if d_len > FAST_REHASH_MAX_BYTES {
            return false;
        }
        let Some(candidates) = added_by_len.get(&d_len) else {
            return false;
        };
        let Ok(d_hash) = hash_file_streaming(&snap_tree.join(d_rel)) else {
            return false;
        };
        let mut matched = false;
        for &cand_idx in candidates {
            if used_added[cand_idx] {
                continue;
            }
            let cand_hash = added_hashes
                .entry(cand_idx)
                .or_insert_with(|| hash_file_streaming(&ws.join(&proj_added[cand_idx])).ok());
            if cand_hash.as_deref() == Some(d_hash.as_str()) {
                used_added[cand_idx] = true;
                matched = true;
                break;
            }
        }
        if !matched {
            return false;
        }
    }
    true
}

pub fn create_snapshot_rolling(
    workspace: &Path,
    label: &str,
) -> Result<RollingSnapReport, AfuseError> {
    create_snapshot_rolling_with_vault(workspace, None, label)
}

pub fn create_snapshot_rolling_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    label: &str,
) -> Result<RollingSnapReport, AfuseError> {
    let (ws, ws_vault) = prepare_live_workspace_vault_with(workspace, vault_override)?;
    let _guard = lock_vault(&ws_vault)?;
    if ws.is_file() {
        let (meta, deduplicated) = create_snapshot_fast_dedup_unlocked(&ws, &ws_vault, label)?;
        return Ok(RollingSnapReport {
            meta,
            deduplicated,
            skipped: false,
            reason: None,
            promoted_pre_delete_id: None,
        });
    }

    let existing = list_snapshots_unlocked(&ws_vault)?;
    let Some(latest) = existing.iter().find(|m| m.label != "auto:pre-restore") else {
        let meta = create_snapshot_unlocked_opts(&ws, &ws_vault, label, true)?;
        return Ok(RollingSnapReport {
            meta,
            deduplicated: false,
            skipped: false,
            reason: None,
            promoted_pre_delete_id: None,
        });
    };

    let detail = diff_fast_unlocked(&ws, &ws_vault, latest)?;
    if label.starts_with("auto:") && label != "auto:pre-restore" {
        let empty_tree = detail.live_file_count == 0
            && existing
                .iter()
                .any(|m| m.file_count > 0 || m.project_files > 0);
        let empty_proj =
            detail.live_project_files == 0 && existing.iter().any(|m| m.project_files > 0);
        if empty_tree || empty_proj {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "refusing auto-snapshot of empty directory while non-empty history exists",
            ));
        }
    }

    if detail.report.added.is_empty()
        && detail.report.modified.is_empty()
        && detail.report.deleted.is_empty()
    {
        return Ok(RollingSnapReport {
            meta: latest.clone(),
            deduplicated: true,
            skipped: false,
            reason: None,
            promoted_pre_delete_id: None,
        });
    }

    let proj_added: Vec<String> = detail
        .report
        .added
        .iter()
        .filter(|p| is_project_path(p))
        .cloned()
        .collect();
    let proj_modified: Vec<String> = detail
        .report
        .modified
        .iter()
        .filter(|p| is_project_path(p))
        .cloned()
        .collect();
    let proj_deleted: Vec<String> = detail
        .report
        .deleted
        .iter()
        .filter(|p| is_project_path(p))
        .cloned()
        .collect();

    if !proj_deleted.is_empty() && proj_added.is_empty() && proj_modified.is_empty() {
        return Ok(RollingSnapReport {
            meta: latest.clone(),
            deduplicated: true,
            skipped: true,
            reason: Some("pure_delete_hold"),
            promoted_pre_delete_id: None,
        });
    }

    let mut promoted_id = None;
    if !proj_deleted.is_empty() {
        let snap_tree = ws_vault.join("snapshots").join(&latest.id).join("tree");
        let pure_rename = is_pure_rename_all(
            &snap_tree,
            &ws,
            &detail.snap_entries,
            &detail.live_entries,
            &proj_deleted,
            &proj_added,
        );
        if !pure_rename {
            promoted_id = promote_latest_to_pre_delete_unlocked(&ws_vault, latest)?;
        }
    }

    let meta = create_snapshot_unlocked_opts(&ws, &ws_vault, label, true)?;
    Ok(RollingSnapReport {
        meta,
        deduplicated: false,
        skipped: false,
        reason: None,
        promoted_pre_delete_id: promoted_id,
    })
}
