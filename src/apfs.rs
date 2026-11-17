use crate::error::{AfuseError, ERR_EEXIST, ERR_EINVAL, ERR_ENOTSUP, ERR_EXDEV};
use std::env;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;

extern "C" {
    fn afuse_clonefile_nofollow(src: *const i8, dst: *const i8) -> i32;
    fn afuse_swap_paths(path_a: *const i8, path_b: *const i8) -> i32;
    fn afuse_statfs_info(
        path: *const i8,
        fsid0: *mut i32,
        fsid1: *mut i32,
        avail_bytes: *mut u64,
        fstype_buf: *mut i8,
        fstype_len: usize,
    ) -> i32;
    fn afuse_lstat_inode_mode(path: *const i8, ino: *mut u64, mode: *mut u32) -> i32;
    fn afuse_force_unlock_path(path: *const i8) -> i32;
    fn afuse_acquire_flock(lock_path: *const i8, out_fd: *mut i32) -> i32;
    fn afuse_try_acquire_flock(lock_path: *const i8, out_fd: *mut i32) -> i32;
    fn afuse_release_flock(fd: i32);
    fn afuse_isatty_stdin() -> i32;
    fn afuse_real_home_dir(buf: *mut i8, len: usize) -> i32;
    fn afuse_spawn_in_new_pgroup(argv: *const *const i8, cwd: *const i8, out_pid: *mut i32)
        -> i32;
    fn afuse_try_wait_pid(pid: i32, out_exited: *mut i32, out_code: *mut i32) -> i32;
    fn afuse_fsgetpath(fsid0: i32, fsid1: i32, obj_id: u64, buf: *mut i8, len: usize) -> i32;
    fn afuse_can_write(path: *const i8) -> i32;
    fn afuse_freeze_kill_reap_pgid(pgid: i32);
}

pub(crate) static TMP_SEQ: AtomicU64 = AtomicU64::new(1);
#[derive(Debug, Clone)]
pub struct StatFsInfo {
    pub fsid: (i32, i32),
    pub avail_bytes: u64,
    pub fstype: String,
}
pub fn short_hash(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

pub(crate) fn c_path(p: &Path) -> Result<CString, AfuseError> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| {
        AfuseError::new(
            ERR_EINVAL,
            format!("path contains interior NUL: {}", p.display()),
        )
    })
}

pub fn real_home_dir() -> Result<PathBuf, AfuseError> {
    let mut buf = [0i8; 1024];
    let rc = unsafe { afuse_real_home_dir(buf.as_mut_ptr(), buf.len()) };
    if rc == 0 {
        let bytes: Vec<u8> = buf
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        if !bytes.is_empty() {
            let p = PathBuf::from(String::from_utf8_lossy(&bytes).into_owned());
            return Ok(fs::canonicalize(&p).unwrap_or(p));
        }
    }
    let home = env::var("HOME")
        .map_err(|_| AfuseError::new(ERR_EINVAL, "cannot resolve user home directory"))?;
    let p = PathBuf::from(home);
    Ok(fs::canonicalize(&p).unwrap_or(p))
}

pub fn statfs_info(p: &Path) -> Result<StatFsInfo, AfuseError> {
    let cp = c_path(p)?;
    let mut f0: i32 = 0;
    let mut f1: i32 = 0;
    let mut avail: u64 = 0;
    let mut buf = [0i8; 32];
    let rc = unsafe {
        afuse_statfs_info(
            cp.as_ptr(),
            &mut f0,
            &mut f1,
            &mut avail,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    if rc != 0 {
        return Err(AfuseError::new(
            rc,
            format!("statfs failed on {}: errno={}", p.display(), rc),
        ));
    }
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    Ok(StatFsInfo {
        fsid: (f0, f1),
        avail_bytes: avail,
        fstype: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

pub fn lstat_inode_mode(p: &Path) -> Result<(u64, u32), AfuseError> {
    let cp = c_path(p)?;
    let mut ino: u64 = 0;
    let mut mode: u32 = 0;
    let rc = unsafe { afuse_lstat_inode_mode(cp.as_ptr(), &mut ino, &mut mode) };
    if rc != 0 {
        return Err(AfuseError::new(
            rc,
            format!("lstat failed on {}: errno={}", p.display(), rc),
        ));
    }
    Ok((ino, mode))
}

pub fn clonefile_nofollow(src: &Path, dst: &Path) -> Result<(), AfuseError> {
    let c_src = c_path(src)?;
    let c_dst = c_path(dst)?;
    let rc = unsafe { afuse_clonefile_nofollow(c_src.as_ptr(), c_dst.as_ptr()) };
    if rc == 0 {
        return Ok(());
    }
    let hint = match rc {
        ERR_EEXIST => "destination already exists (EEXIST)",
        ERR_EXDEV => "cross-volume APFS clone forbidden (EXDEV)",
        ERR_ENOTSUP => "filesystem does not support APFS clonefile (ENOTSUP)",
        _ => "clonefile syscall error",
    };
    Err(AfuseError::new(
        rc,
        format!(
            "{}: {} -> {} (errno={})",
            hint,
            src.display(),
            dst.display(),
            rc
        ),
    ))
}

pub(crate) fn swap_paths(a: &Path, b: &Path) -> Result<(), AfuseError> {
    let ca = c_path(a)?;
    let cb = c_path(b)?;
    let rc = unsafe { afuse_swap_paths(ca.as_ptr(), cb.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(AfuseError::new(
            rc,
            format!("renamex_np swap failed: errno={}", rc),
        ))
    }
}

pub(crate) fn force_unlock(p: &Path) {
    if let Ok(cp) = c_path(p) {
        unsafe {
            let _ = afuse_force_unlock_path(cp.as_ptr());
        }
    }
}

pub fn force_remove_all(p: &Path) -> Result<(), AfuseError> {
    let meta = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(AfuseError::new(
                e.raw_os_error().unwrap_or(1),
                format!("stat failed on {}: {}", p.display(), e),
            ))
        }
    };
    force_unlock(p);
    if meta.file_type().is_dir() {
        let entries = fs::read_dir(p).map_err(|e| {
            AfuseError::new(
                e.raw_os_error().unwrap_or(1),
                format!("read_dir failed on {}: {}", p.display(), e),
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                AfuseError::new(
                    e.raw_os_error().unwrap_or(1),
                    format!("read_dir entry failed on {}: {}", p.display(), e),
                )
            })?;
            force_remove_all(&entry.path())?;
        }
        fs::remove_dir(p).map_err(|e| {
            AfuseError::new(
                e.raw_os_error().unwrap_or(1),
                format!("remove_dir failed on {}: {}", p.display(), e),
            )
        })
    } else {
        fs::remove_file(p).map_err(|e| {
            AfuseError::new(
                e.raw_os_error().unwrap_or(1),
                format!("remove_file failed on {}: {}", p.display(), e),
            )
        })
    }
}

pub(crate) fn acquire_flock_blocking(lock_path: &Path) -> Result<i32, i32> {
    let Ok(c_lock) = c_path(lock_path) else {
        return Err(ERR_EINVAL);
    };
    let mut fd: i32 = -1;
    let rc = unsafe { afuse_acquire_flock(c_lock.as_ptr(), &mut fd) };
    if rc != 0 {
        Err(rc)
    } else {
        Ok(fd)
    }
}

pub(crate) fn acquire_flock_nonblocking(lock_path: &Path) -> Result<i32, i32> {
    let Ok(c_lock) = c_path(lock_path) else {
        return Err(ERR_EINVAL);
    };
    let mut fd: i32 = -1;
    let rc = unsafe { afuse_try_acquire_flock(c_lock.as_ptr(), &mut fd) };
    if rc != 0 {
        Err(rc)
    } else {
        Ok(fd)
    }
}

pub(crate) fn release_flock(fd: i32) {
    unsafe { afuse_release_flock(fd) };
}

pub(crate) fn spawn_in_new_pgroup(ptrs: &[*const i8], cwd: &Path) -> Result<i32, i32> {
    let c_cwd = c_path(cwd).map_err(|_| ERR_EINVAL)?;
    let mut child_pid: i32 = 0;
    let rc = unsafe { afuse_spawn_in_new_pgroup(ptrs.as_ptr(), c_cwd.as_ptr(), &mut child_pid) };
    if rc != 0 {
        Err(rc)
    } else {
        Ok(child_pid)
    }
}

pub(crate) fn try_wait_pid(pid: i32) -> (i32, i32, i32) {
    let mut exited: i32 = 0;
    let mut code: i32 = 0;
    let wrc = unsafe { afuse_try_wait_pid(pid, &mut exited, &mut code) };
    (wrc, exited, code)
}

pub(crate) fn freeze_kill_reap_pgid(pgid: i32) {
    unsafe { afuse_freeze_kill_reap_pgid(pgid) };
}

pub(crate) fn is_tty_stdin() -> bool {
    unsafe { afuse_isatty_stdin() != 0 }
}

pub fn fsgetpath(fsid: (i32, i32), obj_id: u64) -> Result<PathBuf, AfuseError> {
    let mut buf = [0i8; 4096];
    let rc = unsafe { afuse_fsgetpath(fsid.0, fsid.1, obj_id, buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        return Err(AfuseError::new(rc, format!("fsgetpath failed: errno={}", rc)));
    }
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    if bytes.is_empty() {
        return Err(AfuseError::new(ERR_EINVAL, "fsgetpath returned empty path"));
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&bytes).into_owned()))
}

pub(crate) fn can_write_path(p: &Path) -> Result<(), AfuseError> {
    let cp = c_path(p)?;
    let rc = unsafe { afuse_can_write(cp.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(AfuseError::new(rc, format!("path not writable {}: errno={}", p.display(), rc)))
    }
}
