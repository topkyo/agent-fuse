use crate::error::{AfuseError, ERR_ENOENT};
use crate::manifest::{compute_single_file_manifest, compute_snap_tree_manifest, compute_tree_manifest};
use crate::snapshot::{lock_vault_and_resolve, resolve_snapshot_id};
use crate::unicode_norm::canonical_rel_key;
use crate::vault::TargetKind;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct DiffReport {
    pub snapshot_id: String,
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
}

pub fn diff_snapshot(workspace: &Path, target_id: &str) -> Result<DiffReport, AfuseError> {
    diff_snapshot_with_vault(workspace, None, target_id)
}

pub fn diff_snapshot_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    target_id: &str,
) -> Result<DiffReport, AfuseError> {
    let (ws, ws_vault, _guard) = lock_vault_and_resolve(workspace, vault_override)?;
    if !ws_vault.join("snapshots").is_dir() {
        return Err(AfuseError::new(ERR_ENOENT, "no snapshots exist for this workspace"));
    }
    let meta = resolve_snapshot_id(&ws_vault, target_id)?;
    let snap_tree = ws_vault.join("snapshots").join(&meta.id).join("tree");

    let (_, _, _, snap_map) = compute_snap_tree_manifest(&snap_tree, &ws, meta.target_kind)?;
    let live_map = match fs::symlink_metadata(&ws) {
        Ok(m) if meta.target_kind == TargetKind::SingleFile => {
            if !m.file_type().is_symlink() && m.file_type().is_file() {
                compute_single_file_manifest(&ws)?.3
            } else {
                BTreeMap::new()
            }
        }
        Ok(m) if !m.file_type().is_symlink() && m.file_type().is_dir() => {
            compute_tree_manifest(&ws)?.3
        }
        _ => BTreeMap::new(),
    };

    let mut snap_norm = BTreeMap::new();
    for (k, v) in snap_map {
        snap_norm.insert(canonical_rel_key(&k), (k, v));
    }
    let mut live_norm = BTreeMap::new();
    for (k, v) in live_map {
        live_norm.insert(canonical_rel_key(&k), (k, v));
    }

    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();

    let all_keys: BTreeSet<&String> = snap_norm.keys().chain(live_norm.keys()).collect();
    for k in all_keys {
        match (snap_norm.get(k), live_norm.get(k)) {
            (None, Some((live_k, _))) => added.push(live_k.clone()),
            (Some((snap_k, _)), None) => deleted.push(snap_k.clone()),
            (Some((snap_k, sv)), Some((_, lv))) if sv != lv => modified.push(snap_k.clone()),
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
