use crate::apfs::{
    freeze_kill_reap_pgid, lstat_inode_mode, spawn_in_new_pgroup, statfs_info, try_wait_pid,
};
use crate::error::{AfuseError, ERR_EINVAL, EXIT_FUSE_TRIPPED};
use crate::snapshot::{create_snapshot_opts_with_vault, restore_snapshot_with_vault};
use crate::vault::{is_ignored_name, prepare_workspace_vault_with};
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
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

fn collect_git_critical_paths(git_dir: &Path, out: &mut Vec<PathBuf>) {
    out.push(git_dir.to_path_buf());
    for sub in ["HEAD", "config", "index"] {
        let p = git_dir.join(sub);
        if fs::symlink_metadata(&p).is_ok() {
            out.push(p);
        }
    }
    fn walk_sub(cur: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = fs::read_dir(cur) else { return };
        for entry in rd.flatten() {
            let p = entry.path();
            out.push(p.clone());
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                walk_sub(&p, out);
            }
        }
    }
    for sub_dir in ["refs", "logs", "hooks"] {
        let d = git_dir.join(sub_dir);
        if fs::symlink_metadata(&d).is_ok() {
            out.push(d.clone());
            walk_sub(&d, out);
        }
    }
}

fn collect_baseline_paths(ws: &Path) -> Vec<PathBuf> {
    if ws.is_file() {
        return vec![ws.to_path_buf()];
    }
    let mut paths = Vec::new();
    fn walk(cur: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = fs::read_dir(cur) else { return };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_ignored_name(&name) {
                continue;
            }
            let p = entry.path();
            if name == ".git" {
                collect_git_critical_paths(&p, out);
                continue;
            }
            out.push(p.clone());
            if let Ok(ft) = entry.file_type() {
                if ft.is_dir() {
                    walk(&p, out);
                }
            }
        }
    }
    walk(ws, &mut paths);
    paths
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
    let (ino_start, _) = lstat_inode_mode(&ws)?;
    let stat_dir = if ws.is_dir() {
        ws.clone()
    } else {
        ws.parent().unwrap_or(Path::new("/")).to_path_buf()
    };
    let baseline =
        create_snapshot_opts_with_vault(&ws, vault_override, "auto:guard-baseline", true)?;
    let baseline_paths = collect_baseline_paths(&ws);
    let baseline_avail = statfs_info(&stat_dir)?.avail_bytes;
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

    let poll_dur = Duration::from_millis(cfg.poll_ms.max(5));
    let mut tripped = false;
    let mut trip_reason: Option<String> = None;
    let exit_code: i32;

    loop {
        let mut missing = 0usize;
        for p in &baseline_paths {
            if fs::symlink_metadata(p).is_err() {
                missing += 1;
                if missing >= cfg.max_delete {
                    break;
                }
            }
        }
        if missing >= cfg.max_delete {
            freeze_kill_reap_pgid(child_pid);
            tripped = true;
            trip_reason = Some(format!(
                "deleted_entries={} reached threshold max_delete={}",
                missing, cfg.max_delete
            ));
            exit_code = EXIT_FUSE_TRIPPED;
            break;
        }

        if let Ok(cur_fs) = statfs_info(&stat_dir) {
            let consumed = baseline_avail.saturating_sub(cur_fs.avail_bytes);
            if max_write_bytes > 0 && consumed >= max_write_bytes {
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

        let (wrc, exited, code) = try_wait_pid(child_pid);
        if wrc != 0 || exited != 0 {
            let mut post_missing = 0usize;
            for p in &baseline_paths {
                if fs::symlink_metadata(p).is_err() {
                    post_missing += 1;
                    if post_missing >= cfg.max_delete {
                        break;
                    }
                }
            }
            if post_missing >= cfg.max_delete {
                freeze_kill_reap_pgid(child_pid);
                tripped = true;
                trip_reason = Some(format!(
                    "deleted_entries={} reached threshold max_delete={} before exit",
                    post_missing, cfg.max_delete
                ));
                exit_code = EXIT_FUSE_TRIPPED;
            } else {
                exit_code = code;
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

    let (ino_end, _) = lstat_inode_mode(&ws)?;
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

