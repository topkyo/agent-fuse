use crate::apfs::force_remove_all;
use crate::error::{AfuseError, ERR_EINVAL};
use crate::snapshot::list_snapshots_unlocked;
use crate::vault::{lock_vault, resolve_workspace_vault_recovery};
use std::fs;
use std::path::Path;
use std::time::SystemTime;

pub(crate) const ORPHAN_MAX_AGE_SECS: u64 = 60;

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
        if p.join("meta.kv").is_file() {
            continue;
        }
        let is_stale = fs::symlink_metadata(&p)
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
    let all = list_snapshots_unlocked(ws_vault)?;
    match label_prefix {
        Some(pfx) => {
            for m in all
                .into_iter()
                .filter(|m| m.label.starts_with(pfx))
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
    if !ws_vault.join("snapshots").is_dir() {
        return Ok(0);
    }
    let guard = lock_vault(&ws_vault)?;
    let removed = prune_unlocked(&ws_vault, keep_latest, label_prefix, ORPHAN_MAX_AGE_SECS)?;
    if keep_latest == 0 && label_prefix.map(|s| s.is_empty()).unwrap_or(true) {
        drop(guard);
        force_remove_all(&ws_vault)?;
    }
    Ok(removed)
}

// MARK: - Transparent Hook Snippets, Depth-Aware JSON Scanner & Fail-Open `--exec`
