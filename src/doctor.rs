use crate::apfs::{clonefile_nofollow, statfs_info, TMP_SEQ};
use crate::error::{AfuseError, ERR_EINVAL, ERR_ENOENT};
use crate::manifest::json_escape;
use crate::snapshot::list_snapshots_unlocked;
use crate::vault::{
    check_workspace_path_rules, prepare_workspace_vault_with, resolve_vault_base,
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
}

impl DoctorReport {
    pub fn to_json(&self) -> String {
        format_doctor_json(self)
    }
}

pub fn format_doctor_json(rep: &DoctorReport) -> String {
    format!(
        "{{\"ok\":{},\"version\":\"{}\",\"os\":\"{}\",\"arch\":\"{}\",\"apfs_verified\":{},\"clonefile_probe_us\":{},\"free_gib\":{:.2},\"vault_writable\":{},\"workspace_valid\":{},\"snapshot_count\":{}}}",
        rep.ok,
        json_escape(&rep.version),
        json_escape(&rep.os),
        json_escape(&rep.arch),
        rep.apfs_verified,
        rep.clonefile_probe_us,
        rep.free_gib,
        rep.vault_writable,
        rep.workspace_valid,
        rep.snapshot_count
    )
}

pub fn run_doctor(workspace: &Path) -> Result<DoctorReport, AfuseError> {
    run_doctor_with_vault(workspace, None)
}

pub fn run_doctor_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
) -> Result<DoctorReport, AfuseError> {
    if !workspace.exists() {
        return Err(AfuseError::new(
            ERR_ENOENT,
            "target workspace directory does not exist",
        ));
    }
    if !workspace.is_dir() {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "target workspace path is not a directory",
        ));
    }
    let target_ws = workspace.to_path_buf();
    let workspace_valid = check_workspace_path_rules(&target_ws).is_ok();
    let fs_info = statfs_info(&target_ws)
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

        if vault_writable && workspace_valid {
            snapshot_count = prepare_workspace_vault_with(&target_ws, Some(&probe_root))
                .and_then(|(_, ws_vault)| list_snapshots_unlocked(&ws_vault))
                .map(|s| s.len())
                .unwrap_or(0);
        }
    }

    let ok = apfs_verified && vault_writable && clonefile_probe_us > 0 && workspace_valid;

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
    })
}
