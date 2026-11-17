//! Tree restoration helpers: recursive readonly permission guards, deep ignored
//! subtree preservation (node_modules/target/.venv), and Unicode NFD path lookup.

use crate::apfs::{force_remove_all, force_unlock, TMP_SEQ};
use crate::error::{AfuseError, ERR_EINVAL};
use crate::unicode_norm::{components_equal_canonical, to_nfd};
use crate::vault::is_ignored_name;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::Ordering;

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
        if (mode & 0o700) != 0o700 {
            if !self.saved_modes.iter().any(|(p, _)| p == dir) {
                self.saved_modes.push((dir.to_path_buf(), mode));
            }
            fs::set_permissions(dir, fs::Permissions::from_mode(mode | 0o700))
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

/// Resolves a relative path inside `base` matching APFS NFD/NFC equivalent names,
/// returning the exact on-disk directory entry relative path when present.
pub fn resolve_disk_rel_path(base: &Path, rel: &Path) -> Result<Option<PathBuf>, AfuseError> {
    if rel.to_string_lossy().is_ascii() && fs::symlink_metadata(base.join(rel)).is_ok() {
        return Ok(Some(rel.to_path_buf()));
    }
    let mut disk_cur = base.to_path_buf();
    let mut disk_rel = PathBuf::new();
    for comp in rel.components() {
        let Component::Normal(seg) = comp else {
            return Ok(None);
        };
        if seg.to_string_lossy().is_ascii() {
            let exact = disk_cur.join(seg);
            if fs::symlink_metadata(&exact).is_ok() {
                disk_cur = exact;
                disk_rel.push(seg);
                continue;
            }
            return Ok(None);
        }
        let Ok(rd) = fs::read_dir(&disk_cur) else {
            return Ok(None);
        };
        let entries: Vec<_> = rd.flatten().map(|e| e.file_name()).collect();
        let matched = entries
            .iter()
            .find(|name| name.as_os_str() == seg)
            .or_else(|| {
                entries
                    .iter()
                    .find(|name| components_equal_canonical(Path::new(name), Path::new(seg)))
            });
        let Some(real_name) = matched else {
            return Ok(None);
        };
        disk_cur.push(real_name);
        disk_rel.push(real_name);
    }
    Ok(Some(disk_rel))
}

struct PreservedSubtree {
    rel: PathBuf,
    staged: PathBuf,
}

pub struct NestedIgnoredGuard {
    ws: PathBuf,
    stage_root: PathBuf,
    pub stage_name: String,
    moved: Vec<PreservedSubtree>,
}

fn collect_and_move_nested(
    dir: &Path,
    rel_prefix: &Path,
    depth: usize,
    stage_root: &Path,
    guard: &mut UnlockedDirsGuard,
    moved: &mut Vec<PreservedSubtree>,
) -> Result<(), AfuseError> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(".afuse.tmp.") || name_str == ".git" {
            continue;
        }
        if depth == 0 && is_ignored_name(&name_str) {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let rel = rel_prefix.join(&name);
        if depth >= 1 && is_ignored_name(&name_str) {
            guard.unlock_if_needed(dir)?;
            let staged = stage_root.join(format!("item-{}", moved.len()));
            fs::rename(&path, &staged).map_err(|e| {
                AfuseError::new(e.raw_os_error().unwrap_or(1), format!("preserve ignored subtree: {}", e))
            })?;
            moved.push(PreservedSubtree { rel, staged });
        } else if meta.file_type().is_dir() {
            collect_and_move_nested(&path, &rel, depth + 1, stage_root, guard, moved)?;
        }
    }
    Ok(())
}

impl NestedIgnoredGuard {
    pub fn preserve(ws: &Path) -> Result<Self, AfuseError> {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let stage_name = format!(".afuse.tmp.keep.{}.{}", std::process::id(), seq);
        let stage_root = ws.join(&stage_name);
        fs::create_dir_all(&stage_root)
            .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))?;
        let mut dir_guard = UnlockedDirsGuard::new();
        let mut moved = Vec::new();
        let res = collect_and_move_nested(ws, Path::new(""), 0, &stage_root, &mut dir_guard, &mut moved);
        dir_guard.restore_all();
        if let Err(e) = res {
            let mut rollback = Self {
                ws: ws.to_path_buf(),
                stage_root,
                stage_name,
                moved,
            };
            let _ = rollback.restore_back();
            return Err(e);
        }
        Ok(Self {
            ws: ws.to_path_buf(),
            stage_root,
            stage_name,
            moved,
        })
    }

    pub fn restore_back(&mut self) -> Result<(), AfuseError> {
        let mut dir_guard = UnlockedDirsGuard::new();
        let items = std::mem::take(&mut self.moved);
        let mut first_err: Option<AfuseError> = None;
        for item in items {
            let dst = self.ws.join(&item.rel);
            if fs::symlink_metadata(&dst).is_ok() {
                let _ = force_remove_all(&item.staged);
                continue;
            }
            if let Err(e) = prepare_ancestors_writable(&self.ws, &item.rel, true, &mut dir_guard) {
                if first_err.is_none() {
                    first_err = Some(e);
                }
                continue;
            }
            if let Err(e) = fs::rename(&item.staged, &dst) {
                if first_err.is_none() {
                    first_err = Some(AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()));
                }
            }
        }
        dir_guard.restore_all();
        let _ = force_remove_all(&self.stage_root);
        if let Some(e) = first_err {
            return Err(e);
        }
        Ok(())
    }
}

impl Drop for NestedIgnoredGuard {
    fn drop(&mut self) {
        if !self.moved.is_empty() {
            let _ = self.restore_back();
        } else {
            let _ = fs::remove_dir(&self.stage_root);
        }
    }
}

/// Normalizes top-level file names using NFD key comparison.
pub fn top_level_nfd_key(name: &std::ffi::OsStr) -> String {
    to_nfd(&name.to_string_lossy())
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

pub fn workspace_has_visible_files(ws: &Path) -> bool {
    let mut stack = vec![ws.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            if is_ignored_name(&entry.file_name().to_string_lossy()) { continue; }
            let p = entry.path();
            match fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_dir() => stack.push(p),
                Ok(_) => return true,
                Err(_) => {}
            }
        }
    }
    false
}

pub(crate) fn clear_heterogeneous_path_if_needed(p: &Path, expect_dir: bool) -> Result<bool, AfuseError> {
    let Ok(m) = fs::symlink_metadata(p) else {
        return Ok(false);
    };
    let ft = m.file_type();
    let matches_kind = !ft.is_symlink() && if expect_dir { ft.is_dir() } else { ft.is_file() };
    if matches_kind {
        return Ok(false);
    }
    let mut guard = UnlockedDirsGuard::new();
    if let Some(parent) = p.parent() {
        if fs::symlink_metadata(parent).is_ok() {
            let _ = guard.unlock_if_needed(parent);
        }
    }
    let res = force_remove_all(p);
    guard.restore_all();
    res?;
    Ok(true)
}

pub fn validate_rel_restore_path(raw: &str) -> Result<PathBuf, AfuseError> {
    if raw.is_empty() || raw.trim().is_empty() || raw.contains('\0') {
        return Err(AfuseError::new(ERR_EINVAL, "selective restore path must be relative"));
    }
    let p = Path::new(raw);
    if p.is_absolute() {
        return Err(AfuseError::new(ERR_EINVAL, "selective restore rejects absolute paths"));
    }
    let mut clean = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s.starts_with(".afuse.tmp.") || is_ignored_name(&s) {
                    return Err(AfuseError::new(ERR_EINVAL, "rejected internal or ignored segment"));
                }
                clean.push(seg);
            }
            Component::CurDir => {}
            _ => return Err(AfuseError::new(ERR_EINVAL, "rejected '..' or root traversal")),
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(AfuseError::new(ERR_EINVAL, "restore path resolves to workspace root"));
    }
    Ok(clean)
}
