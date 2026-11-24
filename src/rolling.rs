use crate::apfs::force_remove_all;
use crate::diff::diff_fast_unlocked;
use crate::diff_rename::RenamePair;
use crate::error::{AfuseError, ERR_EINVAL};
use crate::manifest::{write_meta, SnapshotMeta, SnapshotOrigin};
use crate::meta::{summarize_project_diff, PIN_CONTAINS_DELETED};
use crate::snapshot::{
    create_snapshot_fast_dedup_unlocked, create_snapshot_unlocked_opts, list_snapshots_unlocked,
};
use crate::trash::record_live_target_inode_if_new;
use crate::vault::{lock_vault, prepare_live_workspace_vault_with, TargetKind};
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

fn is_git_ref_change(rel: &str) -> bool {
    rel == ".git/HEAD" || (rel.starts_with(".git/refs/") && !rel.ends_with(".lock"))
}

pub(crate) fn is_high_risk_delete(del_n: usize, add_n: usize, base_n: u64, live_n: u64) -> bool {
    if del_n == 0 {
        return false;
    }
    if live_n > 0 && add_n >= 10 && del_n.saturating_sub(add_n) < 5.max(del_n / 3) {
        return false;
    }
    if del_n >= 20 {
        return true;
    }
    if base_n >= 5 && del_n >= 5 && (del_n as u64).saturating_mul(2) >= base_n {
        return true;
    }
    base_n >= 2 && live_n == 0 && del_n >= 2
}

pub(crate) fn is_delete_pinned(m: &SnapshotMeta) -> bool {
    m.retention_pin.as_deref() == Some(PIN_CONTAINS_DELETED) || m.label == PRE_DELETE_LABEL
}

pub(crate) fn enforce_pre_delete_quota_unlocked(ws_vault: &Path) -> Result<(), AfuseError> {
    for m in list_snapshots_unlocked(ws_vault)?
        .into_iter()
        .filter(|m| m.label.starts_with("auto:") && is_delete_pinned(m))
        .skip(MAX_PRE_DELETE_SNAPS)
    {
        force_remove_all(&ws_vault.join("snapshots").join(&m.id))?;
    }
    Ok(())
}

fn pin_latest_contains_deleted_unlocked(
    ws_vault: &Path,
    latest: &SnapshotMeta,
) -> Result<Option<String>, AfuseError> {
    if !latest.label.starts_with("auto:")
        || latest.origin == SnapshotOrigin::BeforeRestore
        || latest.label == "auto:pre-restore"
        || is_delete_pinned(latest)
    {
        return Ok(None);
    }
    let mut pinned = latest.clone();
    pinned.retention_pin = Some(PIN_CONTAINS_DELETED.to_string());
    let meta_path = ws_vault
        .join("snapshots")
        .join(&pinned.id)
        .join("meta.kv");
    write_meta(&meta_path, &pinned)?;
    enforce_pre_delete_quota_unlocked(ws_vault)?;
    Ok(Some(pinned.id))
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
    let Some(latest) = existing
        .iter()
        .find(|m| m.origin != SnapshotOrigin::BeforeRestore && m.label != "auto:pre-restore")
    else {
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
        && detail.report.renamed.is_empty()
    {
        record_live_target_inode_if_new(&ws, TargetKind::Directory, &ws_vault);
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
    let proj_renamed: Vec<RenamePair> = detail
        .report
        .renamed
        .iter()
        .filter(|r| is_project_path(&r.from) && is_project_path(&r.to))
        .cloned()
        .collect();

    if proj_added.is_empty()
        && proj_modified.is_empty()
        && proj_deleted.is_empty()
        && proj_renamed.is_empty()
    {
        let has_git_ref = detail
            .report
            .added
            .iter()
            .chain(detail.report.modified.iter())
            .chain(detail.report.deleted.iter())
            .any(|p| is_git_ref_change(p))
            || detail
                .report
                .renamed
                .iter()
                .any(|r| is_git_ref_change(&r.from) || is_git_ref_change(&r.to));
        if !has_git_ref {
            record_live_target_inode_if_new(&ws, TargetKind::Directory, &ws_vault);
            return Ok(RollingSnapReport {
                meta: latest.clone(),
                deduplicated: true,
                skipped: true,
                reason: Some("no_project_changes"),
                promoted_pre_delete_id: None,
            });
        }
    }

    if !proj_deleted.is_empty()
        && proj_added.is_empty()
        && proj_modified.is_empty()
        && proj_renamed.is_empty()
    {
        record_live_target_inode_if_new(&ws, TargetKind::Directory, &ws_vault);
        return Ok(RollingSnapReport {
            meta: latest.clone(),
            deduplicated: true,
            skipped: true,
            reason: Some("pure_delete_hold"),
            promoted_pre_delete_id: None,
        });
    }

    let base_n = detail.report.snapshot_project_files.unwrap_or(latest.project_files);
    if label.starts_with("auto:")
        && label != "auto:pre-restore"
        && is_high_risk_delete(proj_deleted.len(), proj_added.len(), base_n, detail.live_project_files)
    {
        let promoted_id = pin_latest_contains_deleted_unlocked(&ws_vault, latest)?;
        record_live_target_inode_if_new(&ws, TargetKind::Directory, &ws_vault);
        return Ok(RollingSnapReport {
            meta: latest.clone(),
            deduplicated: true,
            skipped: true,
            reason: Some("high_risk_delete_hold"),
            promoted_pre_delete_id: promoted_id,
        });
    }

    let promoted_id = if !proj_deleted.is_empty() {
        pin_latest_contains_deleted_unlocked(&ws_vault, latest)?
    } else {
        None
    };

    let mut meta = create_snapshot_unlocked_opts(&ws, &ws_vault, label, true)?;
    if let Some(sum) = summarize_project_diff(&proj_added, &proj_modified, &proj_deleted, &proj_renamed) {
        meta.summary = Some(sum);
        let _ = write_meta(&ws_vault.join("snapshots").join(&meta.id).join("meta.kv"), &meta);
    }
    Ok(RollingSnapReport {
        meta,
        deduplicated: false,
        skipped: false,
        reason: None,
        promoted_pre_delete_id: promoted_id,
    })
}
