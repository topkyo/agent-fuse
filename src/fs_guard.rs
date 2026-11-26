use crate::apfs::{
    chmod_nofollow, clonefile_nofollow, force_remove_all, force_unlock, random_hex_suffix,
    MAX_WALK_DEPTH, TMP_SEQ,
};
use crate::error::{AfuseError, ERR_EACCES, ERR_EINVAL};
use crate::vault::is_ignored_name;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

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
        let orig = m.permissions().mode() & 0o777;
        let need = need_bits & 0o777;
        if (orig & need) == need {
            return Self { restore: None };
        }
        if chmod_nofollow(path, orig | need).is_err() {
            return Self { restore: None };
        }
        Self {
            restore: Some((path.to_path_buf(), orig)),
        }
    }
}

impl Drop for TempPermGuard {
    fn drop(&mut self) {
        if let Some((p, orig)) = self.restore.take() {
            let _ = chmod_nofollow(&p, orig);
        }
    }
}

fn clone_dir_fallback_readable(
    src: &Path,
    dst: &Path,
    orig: u32,
    depth: usize,
) -> Result<(), AfuseError> {
    if depth >= MAX_WALK_DEPTH {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "directory nesting exceeded maximum depth limit",
        ));
    }
    let _sg = TempPermGuard::ensure(src, 0o500);
    fs::create_dir_all(dst)
        .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))?;
    let _ = chmod_nofollow(dst, (orig & 0o777) | 0o700);
    let rd = fs::read_dir(src)
        .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))?;
    for entry in rd {
        let entry = entry.map_err(|e| AfuseError::new(1, e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_ignored_name(&name) {
            continue;
        }
        let child_src = entry.path();
        if let Ok(cm) = fs::symlink_metadata(&child_src) {
            let cft = cm.file_type();
            if !cft.is_file() && !cft.is_dir() && !cft.is_symlink() {
                continue;
            }
        }
        clonefile_readable_depth(&child_src, &dst.join(entry.file_name()), depth + 1)?;
    }
    let _ = chmod_nofollow(dst, orig & 0o777);
    Ok(())
}

fn clonefile_readable_depth(src: &Path, dst: &Path, depth: usize) -> Result<(), AfuseError> {
    if let Ok(m) = fs::symlink_metadata(src) {
        if !m.file_type().is_symlink() {
            let orig = m.permissions().mode() & 0o777;
            let is_dir = m.file_type().is_dir();
            let need = if is_dir { 0o500 } else { 0o400 };
            if (orig & need) != need {
                let _g = TempPermGuard::ensure(src, need);
                match clonefile_nofollow(src, dst) {
                    Ok(()) => {
                        if fs::symlink_metadata(dst).is_ok() {
                            force_unlock(dst);
                            let _ = chmod_nofollow(dst, orig);
                        }
                        return Ok(());
                    }
                    Err(e) if is_dir && e.code == ERR_EACCES => {
                        return clone_dir_fallback_readable(src, dst, orig, depth)
                    }
                    Err(e) => return Err(e),
                }
            }
            return match clonefile_nofollow(src, dst) {
                Ok(()) => Ok(()),
                Err(e) if is_dir && e.code == ERR_EACCES => {
                    clone_dir_fallback_readable(src, dst, orig, depth)
                }
                Err(e) => Err(e),
            };
        }
    }
    clonefile_nofollow(src, dst)
}

pub(crate) fn clonefile_readable(src: &Path, dst: &Path) -> Result<(), AfuseError> {
    clonefile_readable_depth(src, dst, 0)
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
        let mode = meta.permissions().mode() & 0o777;
        force_unlock(dir);
        if (mode & 0o700) != 0o700 {
            if !self.saved_modes.iter().any(|(p, _)| p == dir) {
                self.saved_modes.push((dir.to_path_buf(), mode));
            }
            let cur = fs::symlink_metadata(dir)
                .map(|m| m.permissions().mode() & 0o777)
                .unwrap_or(mode);
            chmod_nofollow(dir, cur | 0o700)?;
        }
        Ok(())
    }

    pub fn restore_all(&mut self) {
        while let Some((dir, mode)) = self.saved_modes.pop() {
            let _ = chmod_nofollow(&dir, mode);
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
                fs::create_dir(&cur).map_err(|ce| {
                    AfuseError::new(ce.raw_os_error().unwrap_or(1), ce.to_string())
                })?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(AfuseError::new(
                    e.raw_os_error().unwrap_or(1),
                    e.to_string(),
                ))
            }
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

fn force_unlock_tree_depth(p: &Path, depth: usize) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    force_unlock(p);
    if let Ok(meta) = fs::symlink_metadata(p) {
        if !meta.file_type().is_symlink() && meta.file_type().is_dir() {
            if let Ok(rd) = fs::read_dir(p) {
                for entry in rd.flatten() {
                    if !is_ignored_name(&entry.file_name().to_string_lossy()) {
                        force_unlock_tree_depth(&entry.path(), depth + 1);
                    }
                }
            }
        }
    }
}

pub fn force_unlock_tree_recursive(p: &Path) {
    force_unlock_tree_depth(p, 0);
}

pub(crate) struct HeteroStashGuard {
    orig: PathBuf,
    stashed: Option<PathBuf>,
    pub(crate) cleared: bool,
    placeholder_created: bool,
    committed: bool,
}

impl HeteroStashGuard {
    fn unlock_parent_for(p: &Path) -> UnlockedDirsGuard {
        let mut guard = UnlockedDirsGuard::new();
        if let Some(parent) = p.parent() {
            if fs::symlink_metadata(parent).is_ok() {
                let _ = guard.unlock_if_needed(parent);
            }
        }
        guard
    }

    pub(crate) fn stash_if_needed(
        p: &Path,
        ws_vault: &Path,
        expect_dir: bool,
        safety_backup: bool,
    ) -> Result<Self, AfuseError> {
        let Ok(m) = fs::symlink_metadata(p) else {
            return Ok(Self {
                orig: p.to_path_buf(),
                stashed: None,
                cleared: false,
                placeholder_created: false,
                committed: true,
            });
        };
        let ft = m.file_type();
        let matches_kind = !ft.is_symlink() && if expect_dir { ft.is_dir() } else { ft.is_file() };
        if matches_kind {
            return Ok(Self {
                orig: p.to_path_buf(),
                stashed: None,
                cleared: false,
                placeholder_created: false,
                committed: true,
            });
        }
        let mut guard = Self::unlock_parent_for(p);
        let parent = p.parent().unwrap_or(Path::new("/"));
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let stashed = parent.join(format!(
            ".afuse.tmp.hetero.{}.{}.{}",
            std::process::id(),
            seq,
            random_hex_suffix()
        ));
        let mv_res = fs::rename(p, &stashed).map_err(|e| {
            AfuseError::new(
                e.raw_os_error().unwrap_or(1),
                format!("stash heterogeneous target failed: {}", e),
            )
        });
        guard.restore_all();
        mv_res?;
        if safety_backup && !ft.is_symlink() {
            let backup_root = ws_vault.join("hetero-backups");
            if fs::create_dir_all(&backup_root).is_ok() {
                let _ = chmod_nofollow(&backup_root, 0o700);
                let ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                let dst = backup_root.join(format!("hetero-{}-{}", ms, random_hex_suffix()));
                let _ = clonefile_readable(&stashed, &dst);
            }
        }
        Ok(Self {
            orig: p.to_path_buf(),
            stashed: Some(stashed),
            cleared: true,
            placeholder_created: false,
            committed: false,
        })
    }

    pub(crate) fn mark_placeholder_created(&mut self) {
        self.placeholder_created = true;
    }

    pub(crate) fn commit(&mut self) {
        self.committed = true;
        if let Some(st) = self.stashed.take() {
            let mut guard = Self::unlock_parent_for(&st);
            let _ = force_remove_all(&st);
            guard.restore_all();
        }
    }
}

impl Drop for HeteroStashGuard {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(st) = self.stashed.take() {
                let mut guard = Self::unlock_parent_for(&self.orig);
                if self.placeholder_created && fs::symlink_metadata(&self.orig).is_ok() {
                    let _ = force_remove_all(&self.orig);
                }
                if fs::symlink_metadata(&self.orig).is_err() {
                    let _ = fs::rename(&st, &self.orig);
                } else {
                    let _ = force_remove_all(&st);
                }
                guard.restore_all();
            }
        }
    }
}
