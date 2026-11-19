use crate::apfs::{clonefile_nofollow, force_unlock};
use crate::error::{AfuseError, ERR_EACCES, ERR_EINVAL};
use crate::vault::is_ignored_name;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(crate) struct TempPermGuard {
    restore: Option<(PathBuf, u32)>,
}

impl TempPermGuard {
    pub(crate) fn ensure(path: &Path, need_bits: u32) -> Self {
        let Ok(m) = fs::symlink_metadata(path) else {
            return Self { restore: None };
        };
        if m.file_type().is_symlink() {
            return Self { restore: None };
        }
        let orig = m.permissions().mode() & 0o7777;
        if (orig & need_bits) == need_bits {
            return Self { restore: None };
        }
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(orig | need_bits));
        Self {
            restore: Some((path.to_path_buf(), orig)),
        }
    }
}

impl Drop for TempPermGuard {
    fn drop(&mut self) {
        if let Some((p, orig)) = self.restore.take() {
            let _ = fs::set_permissions(p, fs::Permissions::from_mode(orig));
        }
    }
}

fn clone_dir_fallback_readable(src: &Path, dst: &Path, orig: u32) -> Result<(), AfuseError> {
    let _sg = TempPermGuard::ensure(src, 0o500);
    fs::create_dir_all(dst).map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))?;
    let _ = fs::set_permissions(dst, fs::Permissions::from_mode(orig | 0o700));
    let rd = fs::read_dir(src).map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))?;
    for entry in rd {
        let entry = entry.map_err(|e| AfuseError::new(1, e.to_string()))?;
        clonefile_readable(&entry.path(), &dst.join(entry.file_name()))?;
    }
    let _ = fs::set_permissions(dst, fs::Permissions::from_mode(orig));
    Ok(())
}

pub(crate) fn clonefile_readable(src: &Path, dst: &Path) -> Result<(), AfuseError> {
    if let Ok(m) = fs::symlink_metadata(src) {
        if !m.file_type().is_symlink() {
            let orig = m.permissions().mode() & 0o7777;
            let is_dir = m.file_type().is_dir();
            let need = if is_dir { 0o700 } else { 0o400 };
            if (orig & need) != need {
                let _g = TempPermGuard::ensure(src, need);
                match clonefile_nofollow(src, dst) {
                    Ok(()) => {
                        if fs::symlink_metadata(dst).is_ok() {
                            force_unlock(dst);
                            let _ = fs::set_permissions(dst, fs::Permissions::from_mode(orig));
                        }
                        return Ok(());
                    }
                    Err(e) if is_dir && e.code == ERR_EACCES => return clone_dir_fallback_readable(src, dst, orig),
                    Err(e) => return Err(e),
                }
            }
            return match clonefile_nofollow(src, dst) {
                Ok(()) => Ok(()),
                Err(e) if is_dir && e.code == ERR_EACCES => clone_dir_fallback_readable(src, dst, orig),
                Err(e) => Err(e),
            };
        }
    }
    clonefile_nofollow(src, dst)
}

pub struct UnlockedDirsGuard {
    saved_modes: Vec<(PathBuf, u32)>,
}

impl UnlockedDirsGuard {
    pub fn new() -> Self {
        Self {
            saved_modes: Vec::new(),
        }
    }

    pub fn unlock_if_needed(&mut self, dir: &Path) -> Result<(), AfuseError> {
        let meta = fs::symlink_metadata(dir)
            .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))?;
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "unsafe symlink or non-directory ancestor",
            ));
        }
        let mode = meta.permissions().mode() & 0o7777;
        force_unlock(dir);
        if (mode & 0o700) != 0o700 {
            if !self.saved_modes.iter().any(|(p, _)| p == dir) {
                self.saved_modes.push((dir.to_path_buf(), mode));
            }
            let cur = fs::symlink_metadata(dir)
                .map(|m| m.permissions().mode() & 0o7777)
                .unwrap_or(mode);
            fs::set_permissions(dir, fs::Permissions::from_mode(cur | 0o700))
                .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))?;
        }
        Ok(())
    }

    pub fn restore_all(&mut self) {
        while let Some((dir, mode)) = self.saved_modes.pop() {
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(mode));
        }
    }
}

impl Drop for UnlockedDirsGuard {
    fn drop(&mut self) {
        self.restore_all();
    }
}

pub fn prepare_ancestors_writable(
    ws: &Path,
    rel: &Path,
    create_missing: bool,
    guard: &mut UnlockedDirsGuard,
) -> Result<(), AfuseError> {
    guard.unlock_if_needed(ws)?;
    let mut cur = ws.to_path_buf();
    let comps: Vec<_> = rel.components().collect();
    for comp in comps.iter().take(comps.len().saturating_sub(1)) {
        cur.push(comp.as_os_str());
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() || !m.file_type().is_dir() => {
                return Err(AfuseError::new(
                    ERR_EINVAL,
                    "unsafe symlink or file ancestor",
                ));
            }
            Ok(_) => {
                guard.unlock_if_needed(&cur)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && create_missing => {
                fs::create_dir(&cur)
                    .map_err(|ce| AfuseError::new(ce.raw_os_error().unwrap_or(1), ce.to_string()))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string())),
        }
    }
    Ok(())
}

/// Temporarily grants `0o700` on `dir` if needed and restores original mode on drop.
pub fn lock_guard_single_dir(dir: &Path) -> Result<UnlockedDirsGuard, AfuseError> {
    let mut g = UnlockedDirsGuard::new();
    g.unlock_if_needed(dir)?;
    Ok(g)
}

pub fn force_unlock_tree_recursive(p: &Path) {
    force_unlock(p);
    if let Ok(meta) = fs::symlink_metadata(p) {
        if meta.file_type().is_dir() {
            if let Ok(rd) = fs::read_dir(p) {
                for entry in rd.flatten() {
                    if !is_ignored_name(&entry.file_name().to_string_lossy()) {
                        force_unlock_tree_recursive(&entry.path());
                    }
                }
            }
        }
    }
}
