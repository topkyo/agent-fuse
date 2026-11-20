use crate::apfs::{
    freeze_kill_reap_pgid, fsgetpath, lstat_inode_mode, spawn_in_new_pgroup, statfs_info,
    try_wait_pid,
};
use crate::error::{AfuseError, ERR_EINVAL, EXIT_FUSE_TRIPPED};
use crate::snapshot::{create_snapshot_opts_with_vault, restore_snapshot_with_vault};
use crate::vault::{is_ignored_name, prepare_workspace_vault_with};
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::MetadataExt;
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
    for sub in ["HEAD", "config", "index", "packed-refs"] {
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
    for sub_dir in ["refs", "logs", "hooks", "info"] {
        let d = git_dir.join(sub_dir);
        if fs::symlink_metadata(&d).is_ok() {
            out.push(d.clone());
            walk_sub(&d, out);
        }
    }
    let objects_dir = git_dir.join("objects");
    if fs::symlink_metadata(&objects_dir).is_ok() {
        out.push(objects_dir.clone());
        if let Ok(rd) = fs::read_dir(&objects_dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                out.push(p.clone());
                if entry.file_name() == "pack" && entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                    walk_sub(&p, out);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct BaselineTrack {
    ws_canon: PathBuf,
    fsid: (i32, i32),
    is_single_file: bool,
    paths: Vec<(PathBuf, u64)>,
    nonempty_files: Vec<PathBuf>,
    baseline_bytes: u64,
}

fn collect_workspace_logical_bytes(ws: &Path, is_single: bool) -> u64 {
    if is_single {
        return fs::symlink_metadata(ws).map(|m| if m.file_type().is_file() { m.len() } else { 0 }).unwrap_or(0);
    }
    fn walk_bytes(cur: &Path, total: &mut u64) {
        let Ok(rd) = fs::read_dir(cur) else { return };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == ".git" || is_ignored_name(&name) { continue; }
            let p = entry.path();
            if let Ok(m) = fs::symlink_metadata(&p) {
                if m.file_type().is_dir() && !m.file_type().is_symlink() {
                    walk_bytes(&p, total);
                } else if m.file_type().is_file() {
                    *total = total.saturating_add(m.len());
                }
            }
        }
    }
    let mut total = 0u64;
    walk_bytes(ws, &mut total);
    total
}

fn collect_baseline_track(ws: &Path, fsid: (i32, i32)) -> BaselineTrack {
    let ws_canon = fs::canonicalize(ws).unwrap_or_else(|_| ws.to_path_buf());
    if ws.is_file() {
        let mut nonempty_files = Vec::new();
        let mut ino = 0u64;
        let mut bytes = 0u64;
        if let Ok(m) = fs::symlink_metadata(ws) {
            ino = m.ino();
            if m.file_type().is_file() {
                bytes = m.len();
                if bytes > 0 { nonempty_files.push(ws.to_path_buf()); }
            }
        }
        return BaselineTrack {
            ws_canon, fsid, is_single_file: true,
            paths: vec![(ws.to_path_buf(), ino)],
            nonempty_files, baseline_bytes: bytes,
        };
    }
    let mut track = BaselineTrack {
        ws_canon, fsid, is_single_file: false,
        paths: Vec::new(), nonempty_files: Vec::new(), baseline_bytes: 0,
    };
    fn walk(cur: &Path, out: &mut BaselineTrack) {
        let Ok(rd) = fs::read_dir(cur) else { return };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_ignored_name(&name) { continue; }
            let p = entry.path();
            if name == ".git" {
                let mut git_paths = Vec::new();
                collect_git_critical_paths(&p, &mut git_paths);
                for gp in git_paths {
                    let gino = fs::symlink_metadata(&gp).map(|m| m.ino()).unwrap_or(0);
                    out.paths.push((gp, gino));
                }
                continue;
            }
            if let Ok(m) = fs::symlink_metadata(&p) {
                out.paths.push((p.clone(), m.ino()));
                if m.file_type().is_dir() {
                    walk(&p, out);
                } else if m.file_type().is_file() {
                    out.baseline_bytes = out.baseline_bytes.saturating_add(m.len());
                    if m.len() > 0 { out.nonempty_files.push(p); }
                }
            }
        }
    }
    walk(ws, &mut track);
    track
}

fn check_destruction_threshold(track: &BaselineTrack, threshold: usize) -> Option<(usize, usize)> {
    if track.is_single_file {
        if let Some((p, _)) = track.paths.first() {
            let intact = fs::symlink_metadata(p)
                .map(|m| !m.file_type().is_symlink() && m.file_type().is_file())
                .unwrap_or(false);
            if !intact { return Some((1, 0)); }
        }
    }
    let mut missing = 0usize;
    let mut truncated = 0usize;
    for (p, ino) in &track.paths {
        if fs::symlink_metadata(p).is_err() {
            if !track.is_single_file && *ino > 0 {
                if let Ok(cur_p) = fsgetpath(track.fsid, *ino) {
                    let canon_cur = cur_p.parent().and_then(|d| fs::canonicalize(d).ok())
                        .and_then(|cd| cur_p.file_name().map(|n| cd.join(n)))
                        .unwrap_or(cur_p);
                    if canon_cur.starts_with(&track.ws_canon) {
                        continue;
                    }
                }
            }
            missing += 1;
            if missing >= threshold { return Some((missing, truncated)); }
        }
    }
    for p in &track.nonempty_files {
        if let Ok(m) = fs::symlink_metadata(p) {
            if m.file_type().is_file() && m.len() == 0 {
                truncated += 1;
                if missing + truncated >= threshold { return Some((missing, truncated)); }
            }
        }
    }
    None
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
    let ws_fsid = statfs_info(&stat_dir)?.fsid;
    let track = collect_baseline_track(&ws, ws_fsid);
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

    let poll_dur = Duration::from_millis(cfg.poll_ms.max(5));
    let mut tripped = false;
    let mut trip_reason: Option<String> = None;
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
            let cur_bytes = collect_workspace_logical_bytes(&ws, is_single);
            let consumed = cur_bytes.saturating_sub(track.baseline_bytes);
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

        let (wrc, exited, code) = try_wait_pid(child_pid);
        if wrc != 0 || exited != 0 {
            if let Some((missing, truncated)) = check_destruction_threshold(&track, threshold) {
                freeze_kill_reap_pgid(child_pid);
                tripped = true;
                trip_reason = Some(format!(
                    "deleted_entries={} truncated_entries={} reached threshold max_delete={} before exit",
                    missing, truncated, threshold
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
