use crate::apfs::{
    freeze_kill_reap_pgid, lstat_inode_mode, pgid_alive, pgid_disk_bytes_written,
    spawn_in_new_pgroup, statfs_info, try_wait_pid,
};
use crate::error::{AfuseError, ERR_EINVAL, EXIT_FUSE_TRIPPED};
use crate::guard_probe::{
    check_destruction_threshold, collect_baseline_track, collect_workspace_written_bytes,
};
use crate::snapshot::{create_snapshot_opts_with_vault, restore_snapshot_with_vault};
use crate::vault::prepare_workspace_vault_with;
use std::ffi::CString;
use std::path::Path;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GuardConfig {
    pub max_delete: usize,
    pub max_write_mb: u64,
    pub poll_ms: u64,
    pub auto_rollback: bool,
}

#[derive(Debug, Clone)]
pub struct GuardReport {
    pub baseline_snapshot_id: String,
    pub tripped: bool,
    pub trip_reason: Option<String>,
    pub exit_code: i32,
    pub auto_restored: bool,
    pub restore_elapsed_us: Option<u128>,
    pub root_inode_preserved: bool,
    pub verified_sha256: Option<String>,
}

pub fn run_guarded_command(
    workspace: &Path,
    cfg: &GuardConfig,
    cmd_args: &[String],
) -> Result<GuardReport, AfuseError> {
    run_guarded_command_with_vault(workspace, None, cfg, cmd_args)
}

pub fn run_guarded_command_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
    cfg: &GuardConfig,
    cmd_args: &[String],
) -> Result<GuardReport, AfuseError> {
    if cmd_args.is_empty() {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "guard requires a command after '--'",
        ));
    }
    let (ws, _ws_vault) = prepare_workspace_vault_with(workspace, vault_override)?;
    let is_single = ws.is_file();
    let stat_dir = if is_single {
        ws.parent().unwrap_or(Path::new("/")).to_path_buf()
    } else {
        ws.clone()
    };
    let anchor_path = if is_single { &stat_dir } else { &ws };
    let (ino_start, _) = lstat_inode_mode(anchor_path)?;

    let baseline =
        create_snapshot_opts_with_vault(&ws, vault_override, "auto:guard-baseline", true)?;
    let start_sfs = statfs_info(&stat_dir)?;
    let track = collect_baseline_track(&ws, start_sfs.fsid);
    let threshold = if is_single { 1 } else { cfg.max_delete.max(1) };
    let max_write_bytes = cfg.max_write_mb.saturating_mul(1024 * 1024);

    let mut c_strs: Vec<CString> = Vec::with_capacity(cmd_args.len());
    for a in cmd_args {
        c_strs.push(
            CString::new(a.as_bytes())
                .map_err(|_| AfuseError::new(ERR_EINVAL, "command argument contains NUL"))?,
        );
    }
    let mut ptrs: Vec<*const i8> = c_strs.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    let child_pid = spawn_in_new_pgroup(&ptrs, &stat_dir).map_err(|spawn_rc| {
        AfuseError::new(
            spawn_rc,
            format!("failed to spawn guarded command: errno={}", spawn_rc),
        )
    })?;

    let measure_write_consumed = || -> u64 {
        let ws_written =
            collect_workspace_written_bytes(&ws, is_single, &track.baseline_file_lens);
        let proc_written = pgid_disk_bytes_written(child_pid);
        ws_written.max(proc_written)
    };

    let poll_dur = Duration::from_millis(cfg.poll_ms.max(5));
    let mut tripped = false;
    let mut trip_reason: Option<String> = None;
    let mut lead_exited = false;
    let mut lead_code: i32 = 0;
    let exit_code: i32;

    loop {
        if let Some((missing, truncated)) = check_destruction_threshold(&track, threshold) {
            freeze_kill_reap_pgid(child_pid);
            tripped = true;
            trip_reason = Some(format!(
                "deleted_entries={} truncated_entries={} reached threshold max_delete={}",
                missing, truncated, threshold
            ));
            exit_code = EXIT_FUSE_TRIPPED;
            break;
        }

        if max_write_bytes > 0 {
            let consumed = measure_write_consumed();
            if consumed >= max_write_bytes {
                freeze_kill_reap_pgid(child_pid);
                tripped = true;
                trip_reason = Some(format!(
                    "disk_write_spike_bytes={} exceeded max_write_mb={}",
                    consumed, cfg.max_write_mb
                ));
                exit_code = EXIT_FUSE_TRIPPED;
                break;
            }
        }

        if !lead_exited {
            let (wrc, exited, code) = try_wait_pid(child_pid);
            if wrc != 0 || exited != 0 {
                lead_exited = true;
                lead_code = code;
            }
        }

        if lead_exited && !pgid_alive(child_pid) {
            if let Some((missing, truncated)) = check_destruction_threshold(&track, threshold) {
                freeze_kill_reap_pgid(child_pid);
                tripped = true;
                trip_reason = Some(format!(
                    "deleted_entries={} truncated_entries={} reached threshold max_delete={} before exit",
                    missing, truncated, threshold
                ));
                exit_code = EXIT_FUSE_TRIPPED;
            } else {
                let consumed = if max_write_bytes > 0 {
                    measure_write_consumed()
                } else {
                    0
                };
                if max_write_bytes > 0 && consumed >= max_write_bytes {
                    freeze_kill_reap_pgid(child_pid);
                    tripped = true;
                    trip_reason = Some(format!(
                        "disk_write_spike_bytes={} exceeded max_write_mb={} before exit",
                        consumed, cfg.max_write_mb
                    ));
                    exit_code = EXIT_FUSE_TRIPPED;
                } else {
                    exit_code = lead_code;
                }
            }
            break;
        }

        thread::sleep(poll_dur);
    }

    let mut auto_restored = false;
    let mut restore_elapsed_us = None;
    let mut verified_sha256 = None;

    if tripped && cfg.auto_rollback {
        let rep = restore_snapshot_with_vault(&ws, vault_override, &baseline.id, false)?;
        auto_restored = true;
        restore_elapsed_us = Some(rep.elapsed_us);
        verified_sha256 = Some(rep.tree_sha256);
    }

    let ino_end = lstat_inode_mode(anchor_path).map(|x| x.0).unwrap_or(0);
    Ok(GuardReport {
        baseline_snapshot_id: baseline.id,
        tripped,
        trip_reason,
        exit_code,
        auto_restored,
        restore_elapsed_us,
        root_inode_preserved: ino_start == ino_end,
        verified_sha256,
    })
}
