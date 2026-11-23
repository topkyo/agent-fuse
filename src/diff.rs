use crate::error::{AfuseError, ERR_ENOENT};
use crate::manifest::{
    compute_fast_entries, compute_single_file_manifest, compute_snap_tree_manifest,
    compute_tree_manifest, hash_file_streaming, SnapshotMeta,
};
use crate::restore_tree::find_single_snap_file;
use crate::snapshot::{lock_vault_and_resolve, resolve_snapshot_id};
use crate::unicode_norm::canonical_rel_key;
use crate::vault::TargetKind;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const FAST_REHASH_MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct DiffReport {
    pub snapshot_id: String,
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
}

pub(crate) struct FastDiffDetail {
    pub report: DiffReport,
    pub snap_entries: BTreeMap<String, String>,
    pub live_entries: BTreeMap<String, String>,
    pub live_file_count: u64,
    pub live_project_files: u64,
}

pub(crate) fn parse_fast_file_sig(sig: &str) -> Option<(&str, u64)> {
    let rest = sig.strip_prefix("F:")?;
    let mut parts = rest.splitn(4, ':');
    let mode = parts.next()?;
    let len = parts.next()?.parse::<u64>().ok()?;
    let _mtime = parts.next()?;
    let _nsec = parts.next()?;
    Some((mode, len))
}

fn fast_entry_content_equal(
    snap_root: &Path,
    live_root: &Path,
    kind: TargetKind,
    snap_k: &str,
    live_k: &str,
    sv: &str,
    lv: &str,
) -> bool {
    let Some((sm, sl)) = parse_fast_file_sig(sv) else {
        return false;
    };
    let Some((lm, ll)) = parse_fast_file_sig(lv) else {
        return false;
    };
    if sm != lm || sl != ll || sl > FAST_REHASH_MAX_BYTES {
        return false;
    }
    let (snap_p, live_p) = if kind == TargetKind::SingleFile {
        (snap_root.to_path_buf(), live_root.to_path_buf())
    } else {
        (snap_root.join(snap_k), live_root.join(live_k))
    };
    match (hash_file_streaming(&snap_p), hash_file_streaming(&live_p)) {
        (Ok(sh), Ok(lh)) => sh == lh,
        _ => false,
    }
}

pub(crate) fn diff_fast_unlocked(
    ws: &Path,
    ws_vault: &Path,
    meta: &SnapshotMeta,
) -> Result<FastDiffDetail, AfuseError> {
    let snap_tree = ws_vault.join("snapshots").join(&meta.id).join("tree");
    let (snap_root, snap_entries): (PathBuf, BTreeMap<String, String>) =
        if meta.target_kind == TargetKind::SingleFile {
            let sf = find_single_snap_file(ws, &snap_tree)
                .ok_or_else(|| AfuseError::new(ERR_ENOENT, "snapshot file missing in tree"))?;
            let entries = compute_fast_entries(&sf, TargetKind::SingleFile)?.0;
            (sf, entries)
        } else {
            let entries = compute_fast_entries(&snap_tree, TargetKind::Directory)?.0;
            (snap_tree, entries)
        };
    let (live_entries, live_file_count, live_project_files) = match fs::symlink_metadata(ws) {
        Ok(m) if meta.target_kind == TargetKind::SingleFile => {
            if !m.file_type().is_symlink() && m.file_type().is_file() {
                let (e, fc, _, pf) = compute_fast_entries(ws, TargetKind::SingleFile)?;
                (e, fc, pf)
            } else {
                (BTreeMap::new(), 0, 0)
            }
        }
        Ok(m) if !m.file_type().is_symlink() && m.file_type().is_dir() => {
            let (e, fc, _, pf) = compute_fast_entries(ws, TargetKind::Directory)?;
            (e, fc, pf)
        }
        _ => (BTreeMap::new(), 0, 0),
    };

    let mut snap_norm = BTreeMap::new();
    for (k, v) in &snap_entries {
        snap_norm.insert(canonical_rel_key(k), (k.clone(), v.clone()));
    }
    let mut live_norm = BTreeMap::new();
    for (k, v) in &live_entries {
        live_norm.insert(canonical_rel_key(k), (k.clone(), v.clone()));
    }

    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();

    let all_keys: BTreeSet<&String> = snap_norm.keys().chain(live_norm.keys()).collect();
    for k in all_keys {
        match (snap_norm.get(k), live_norm.get(k)) {
            (None, Some((live_k, lv))) if !lv.starts_with("D:") => added.push(live_k.clone()),
            (Some((snap_k, sv)), None) if !sv.starts_with("D:") => deleted.push(snap_k.clone()),
            (Some((snap_k, sv)), Some((live_k, lv)))
                if sv != lv && !(sv.starts_with("D:") && lv.starts_with("D:")) =>
            {
                if !fast_entry_content_equal(
                    &snap_root,
                    ws,
                    meta.target_kind,
                    snap_k,
                    live_k,
                    sv,
                    lv,
                ) {
                    modified.push(snap_k.clone());
                }
            }
            _ => {}
        }
    }

    Ok(FastDiffDetail {
        report: DiffReport {
            snapshot_id: meta.id.clone(),
            added,
            modified,
            deleted,
        },
        snap_entries,
        live_entries,
        live_file_count,
        live_project_files,
    })
}

pub fn diff_snapshot(workspace: &Path, target_id: &str) -> Result<DiffReport, AfuseError> {
    diff_snapshot_with_vault(workspace, None, target_id)
}

pub fn diff_snapshot_fast(workspace: &Path, target_id: &str) -> Result<DiffReport, AfuseError> {
    diff_snapshot_opts_with_vault(workspace, None, target_id, true)
}

pub fn diff_snapshot_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    target_id: &str,
) -> Result<DiffReport, AfuseError> {
    diff_snapshot_opts_with_vault(workspace, vault_override, target_id, false)
}

pub fn diff_snapshot_opts_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    target_id: &str,
    fast: bool,
) -> Result<DiffReport, AfuseError> {
    let (ws, ws_vault, _guard) = lock_vault_and_resolve(workspace, vault_override)?;
    if !ws_vault.join("snapshots").is_dir() {
        return Err(AfuseError::new(
            ERR_ENOENT,
            "no snapshots exist for this workspace",
        ));
    }
    let meta = resolve_snapshot_id(&ws_vault, target_id)?;
    if fast {
        return diff_fast_unlocked(&ws, &ws_vault, &meta).map(|d| d.report);
    }

    let snap_tree = ws_vault.join("snapshots").join(&meta.id).join("tree");
    let snap_map = compute_snap_tree_manifest(&snap_tree, &ws, meta.target_kind)?.3;
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
            (None, Some((live_k, lv))) if !lv.starts_with("D:") => added.push(live_k.clone()),
            (Some((snap_k, sv)), None) if !sv.starts_with("D:") => deleted.push(snap_k.clone()),
            (Some((snap_k, sv)), Some((_, lv)))
                if sv != lv && !(sv.starts_with("D:") && lv.starts_with("D:")) =>
            {
                modified.push(snap_k.clone());
            }
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
