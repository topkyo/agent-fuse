use crate::apfs::{force_remove_all, random_hex_suffix};
use crate::error::AfuseError;
use crate::snapshot::list_snapshots_unlocked;
use crate::vault::{resolve_vault_base, try_lock_vault, VAULT_ROOT_MARKER};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct OrphanPruneReport {
    pub scanned: usize,
    pub candidates: Vec<String>,
    pub removed: usize,
    pub dry_run: bool,
}

fn is_vault_subdir_candidate(name: &str, dir: &Path) -> bool {
    let Some((prefix, hex)) = name.rsplit_once('-') else {
        return false;
    };
    if prefix.is_empty()
        || hex.len() != 16
        || !hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return false;
    }
    let has_snaps = fs::symlink_metadata(dir.join("snapshots"))
        .map(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
        .unwrap_or(false);
    let has_lock = fs::symlink_metadata(dir.join("vault.lock"))
        .map(|m| !m.file_type().is_symlink() && m.file_type().is_file())
        .unwrap_or(false);
    has_snaps || has_lock
}

fn is_dir_orphan_now(dir: &Path) -> bool {
    let snaps = list_snapshots_unlocked(dir).unwrap_or_default();
    match snaps.first() {
        None => true,
        Some(m) => !m.workspace.is_empty() && fs::symlink_metadata(&m.workspace).is_err(),
    }
}

pub(crate) fn atomic_retire_and_remove_vault(dir: &Path) -> Result<(), AfuseError> {
    let Some(parent) = dir.parent() else {
        return force_remove_all(dir);
    };
    let hidden = parent.join(format!(
        ".afuse.retire.{}.{}",
        std::process::id(),
        random_hex_suffix()
    ));
    if fs::rename(dir, &hidden).is_ok() {
        force_remove_all(&hidden)
    } else {
        force_remove_all(dir)
    }
}

pub fn inspect_vault_orphans(
    vault_override: Option<&Path>,
    min_age_secs: u64,
) -> (usize, Vec<PathBuf>) {
    let base = match vault_override {
        Some(v) => v.to_path_buf(),
        None => match resolve_vault_base() {
            Ok(b) => b,
            Err(_) => return (0, Vec::new()),
        },
    };
    let _has_root_marker = fs::symlink_metadata(base.join(VAULT_ROOT_MARKER))
        .map(|m| !m.file_type().is_symlink() && m.file_type().is_file())
        .unwrap_or(false);
    let Ok(rd) = fs::read_dir(&base) else {
        return (0, Vec::new());
    };
    let now = SystemTime::now();
    let mut total = 0usize;
    let mut orphans = Vec::new();
    for ent in rd.flatten() {
        let p = ent.path();
        let name = ent.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            continue;
        }
        if !is_vault_subdir_candidate(&name, &p) {
            continue;
        }
        total += 1;
        let age_ok = min_age_secs == 0
            || meta
                .modified()
                .ok()
                .and_then(|mt| now.duration_since(mt).ok())
                .map(|d| d >= Duration::from_secs(min_age_secs))
                .unwrap_or(false);
        if !age_ok {
            continue;
        }
        if is_dir_orphan_now(&p) {
            orphans.push(p);
        }
    }
    orphans.sort();
    (total, orphans)
}

fn sweep_stale_retired_vaults(vault_override: Option<&Path>, min_age_secs: u64) {
    let base = match vault_override {
        Some(v) => v.to_path_buf(),
        None => match resolve_vault_base() {
            Ok(b) => b,
            Err(_) => return,
        },
    };
    let Ok(rd) = fs::read_dir(&base) else { return };
    let now = SystemTime::now();
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if !name.starts_with(".afuse.retire.") {
            continue;
        }
        let p = ent.path();
        let Ok(meta) = fs::symlink_metadata(&p) else { continue };
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            continue;
        }
        let age_ok = min_age_secs == 0
            || meta
                .modified()
                .ok()
                .and_then(|mt| now.duration_since(mt).ok())
                .map(|d| d >= Duration::from_secs(min_age_secs))
                .unwrap_or(false);
        if age_ok {
            let _ = force_remove_all(&p);
        }
    }
}

pub fn prune_orphan_vaults_with(
    vault_override: Option<&Path>,
    min_age_days: u64,
    dry_run: bool,
) -> Result<OrphanPruneReport, AfuseError> {
    let min_age_secs = min_age_days.saturating_mul(86_400);
    if !dry_run {
        sweep_stale_retired_vaults(vault_override, min_age_secs.max(60));
    }
    let (scanned, orphans) = inspect_vault_orphans(vault_override, min_age_secs);
    let mut candidates = Vec::new();
    let mut removed = 0usize;
    for dir in orphans {
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if dry_run {
            candidates.push(name);
            continue;
        }
        let Ok(guard) = try_lock_vault(&dir) else { continue };
        if !is_dir_orphan_now(&dir) {
            drop(guard);
            continue;
        }
        candidates.push(name);
        let res = atomic_retire_and_remove_vault(&dir);
        drop(guard);
        if res.is_ok() {
            removed += 1;
        }
    }
    Ok(OrphanPruneReport {
        scanned,
        candidates,
        removed,
        dry_run,
    })
}
