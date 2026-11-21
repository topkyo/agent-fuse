use crate::apfs::{clonefile_nofollow, real_home_dir, statfs_info, TMP_SEQ};
use crate::error::{AfuseError, ERR_EINVAL, ERR_ENOENT};
use crate::manifest::json_escape;
use crate::relocate::inspect_vault_orphans;
use crate::snapshot::list_snapshots_unlocked;
use crate::trash::allowed_trash_roots;
use crate::vault::{
    check_workspace_path_rules, resolve_vault_base, resolve_workspace_vault_recovery,
};
use std::env;
use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq)]
pub struct DoctorReport {
    pub ok: bool,
    pub version: String,
    pub os: String,
    pub arch: String,
    pub apfs_verified: bool,
    pub clonefile_probe_us: u64,
    pub free_gib: f64,
    pub vault_writable: bool,
    pub workspace_valid: bool,
    pub snapshot_count: usize,
    pub trash_roots_readable: bool,
    pub icloud_trash_detected: bool,
    pub vault_dir_count: usize,
    pub orphan_vault_count: usize,
}

impl DoctorReport {
    pub fn to_json(&self) -> String {
        format_doctor_json(self)
    }
}

pub fn format_doctor_json(rep: &DoctorReport) -> String {
    format!(
        "{{\"ok\":{},\"version\":\"{}\",\"os\":\"{}\",\"arch\":\"{}\",\"apfs_verified\":{},\"clonefile_probe_us\":{},\"free_gib\":{:.2},\"vault_writable\":{},\"workspace_valid\":{},\"snapshot_count\":{},\"trash_roots_readable\":{},\"icloud_trash_detected\":{},\"vault_dir_count\":{},\"orphan_vault_count\":{}}}",
        rep.ok,
        json_escape(&rep.version),
        json_escape(&rep.os),
        json_escape(&rep.arch),
        rep.apfs_verified,
        rep.clonefile_probe_us,
        rep.free_gib,
        rep.vault_writable,
        rep.workspace_valid,
        rep.snapshot_count,
        rep.trash_roots_readable,
        rep.icloud_trash_detected,
        rep.vault_dir_count,
        rep.orphan_vault_count
    )
}

pub fn run_doctor(workspace: &Path) -> Result<DoctorReport, AfuseError> {
    run_doctor_with_opts(workspace, None, false)
}

pub fn run_doctor_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
) -> Result<DoctorReport, AfuseError> {
    run_doctor_with_opts(workspace, vault_override, false)
}

pub(crate) fn compute_doctor_ok(
    apfs_verified: bool,
    vault_writable: bool,
    clonefile_probe_us: u64,
    workspace_valid: bool,
    free_gib: f64,
) -> bool {
    apfs_verified && vault_writable && clonefile_probe_us > 0 && workspace_valid && free_gib >= 2.0
}

pub fn run_doctor_with_opts(
    workspace: &Path,
    vault_override: Option<&Path>,
    skip_workspace_check: bool,
) -> Result<DoctorReport, AfuseError> {
    let mut target_ws = workspace.to_path_buf();
    let workspace_valid;
    let stat_dir: std::path::PathBuf;
    if skip_workspace_check {
        workspace_valid = true;
        let vault_hint = vault_override
            .map(|v| v.to_path_buf())
            .or_else(|| resolve_vault_base().ok())
            .unwrap_or_else(|| std::path::PathBuf::from("/"));
        let mut probe_p = vault_hint.clone();
        while !probe_p.exists() && probe_p.pop() {}
        stat_dir = if probe_p.exists() { probe_p } else { workspace.to_path_buf() };
    } else {
        if !workspace.exists() {
            return Err(AfuseError::new(
                ERR_ENOENT,
                "target path does not exist",
            ));
        }
        let sym = fs::symlink_metadata(workspace).map_err(|e| {
            AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), e.to_string())
        })?;
        if sym.file_type().is_symlink() || (!sym.file_type().is_dir() && !sym.file_type().is_file()) {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "target path must be a regular directory or regular file",
            ));
        }
        target_ws = fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
        workspace_valid = check_workspace_path_rules(&target_ws).is_ok();
        stat_dir = if target_ws.is_dir() {
            target_ws.clone()
        } else {
            target_ws.parent().unwrap_or(Path::new("/")).to_path_buf()
        };
    }
    let fs_info = statfs_info(&stat_dir)
        .map_err(|e| AfuseError::new(e.code, "statfs probe failed on target workspace"))?;
    let apfs_verified = fs_info.fstype.eq_ignore_ascii_case("apfs");
    let free_gib = (fs_info.avail_bytes as f64) / (1024.0 * 1024.0 * 1024.0);

    let resolved_vault = match vault_override {
        Some(v) => Ok(v.to_path_buf()),
        None => resolve_vault_base(),
    };
    let mut vault_writable = false;
    let mut clonefile_probe_us = 0u64;
    let mut snapshot_count = 0usize;

    if let Ok(probe_root) = resolved_vault {
        if fs::create_dir_all(&probe_root).is_ok() {
            let probe_dir = probe_root.join(format!(
                ".doctor-probe-{}-{}",
                std::process::id(),
                TMP_SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            if fs::create_dir_all(&probe_dir).is_ok() {
                let src = probe_dir.join("probe.src");
                let dst = probe_dir.join("probe.dst");
                if fs::write(&src, b"afuse-doctor-probe").is_ok() {
                    vault_writable = true;
                    let t0 = Instant::now();
                    if clonefile_nofollow(&src, &dst).is_ok() {
                        clonefile_probe_us = (t0.elapsed().as_micros() as u64).max(1);
                    }
                }
                let _ = fs::remove_dir_all(&probe_dir);
            }
        }

        if !skip_workspace_check && vault_writable && workspace_valid {
            snapshot_count = resolve_workspace_vault_recovery(&target_ws, Some(&probe_root))
                .and_then(|(_, ws_vault)| {
                    if ws_vault.join("snapshots").is_dir() {
                        list_snapshots_unlocked(&ws_vault)
                    } else {
                        Ok(Vec::new())
                    }
                })
                .map(|s| s.len())
                .unwrap_or(0);
        }
    }

    let ok = compute_doctor_ok(
        apfs_verified,
        vault_writable,
        clonefile_probe_us,
        workspace_valid,
        free_gib,
    );
    let trash_roots = allowed_trash_roots();
    let trash_roots_readable = !trash_roots.is_empty() && trash_roots.iter().all(|t| fs::read_dir(t).is_ok());
    let icloud_trash_detected = real_home_dir()
        .map(|h| h.join("Library/Mobile Documents/com~apple~CloudDocs/.Trash").exists())
        .unwrap_or(false);
    let (vault_dir_count, orphan_dirs) = inspect_vault_orphans(vault_override, 0);

    Ok(DoctorReport {
        ok,
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: env::consts::OS.to_string(),
        arch: env::consts::ARCH.to_string(),
        apfs_verified,
        clonefile_probe_us,
        free_gib,
        vault_writable,
        workspace_valid,
        snapshot_count,
        trash_roots_readable,
        icloud_trash_detected,
        vault_dir_count,
        orphan_vault_count: orphan_dirs.len(),
    })
}
