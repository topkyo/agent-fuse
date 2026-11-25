//! Tree restoration helpers: recursive readonly permission guards, deep ignored
//! subtree preservation (node_modules/target/.venv), and Unicode NFD path lookup.

use crate::apfs::{force_remove_all, force_unlock, MAX_WALK_DEPTH, TMP_SEQ};
use crate::error::{AfuseError, ERR_EINVAL};
pub(crate) use crate::fs_guard::HeteroStashGuard;
pub use crate::fs_guard::{
    force_unlock_tree_recursive, lock_guard_single_dir, prepare_ancestors_writable,
    UnlockedDirsGuard,
};
use crate::manifest::{compute_single_file_manifest, compute_tree_manifest};
use crate::unicode_norm::{components_equal_canonical, components_equal_casefold_nfd, to_nfd};
use crate::vault::{is_ignored_name, TargetKind};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::Ordering;

pub fn same_disk_entry(a: &Path, b: &Path) -> bool {
    let Ok(ma) = fs::symlink_metadata(a) else { return false };
    let Ok(mb) = fs::symlink_metadata(b) else { return false };
    ma.dev() == mb.dev() && ma.ino() == mb.ino()
}

pub fn align_ancestor_case(
    ws: &Path,
    rel: &Path,
    guard: &mut UnlockedDirsGuard,
) -> Result<(), AfuseError> {
    let mut cur = ws.to_path_buf();
    let comps: Vec<_> = rel.components().collect();
    for comp in comps.iter().take(comps.len().saturating_sub(1)) {
        let seg = comp.as_os_str();
        let Ok(rd) = fs::read_dir(&cur) else { break };
        let entries: Vec<_> = rd.flatten().map(|e| e.file_name()).collect();
        let target = cur.join(seg);
        if let Some(real_name) = entries.iter().find(|n| {
            n.as_os_str() != seg
                && components_equal_casefold_nfd(Path::new(n), Path::new(seg))
                && same_disk_entry(&cur.join(n), &target)
        }) {
            let live_ancestor = cur.join(real_name);
            if fs::symlink_metadata(&live_ancestor).map(|m| m.file_type().is_dir() && !m.file_type().is_symlink()).unwrap_or(false) {
                guard.unlock_if_needed(&cur)?;
                guard.unlock_if_needed(&live_ancestor)?;
                fs::rename(&live_ancestor, &target)
                    .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))?;
            }
        }
        cur = target;
    }
    Ok(())
}

/// Resolves a relative path inside `base` matching APFS NFD/NFC or case-insensitive equivalent names,
/// returning the exact on-disk directory entry relative path when present.
pub fn resolve_disk_rel_path(base: &Path, rel: &Path) -> Result<Option<PathBuf>, AfuseError> {
    let mut disk_cur = base.to_path_buf();
    let mut disk_rel = PathBuf::new();
    let comps: Vec<_> = rel.components().collect();
    for (idx, comp) in comps.iter().enumerate() {
        let Component::Normal(seg) = comp else {
            return Ok(None);
        };
        let Ok(rd) = fs::read_dir(&disk_cur) else {
            return Ok(None);
        };
        let entries: Vec<_> = rd.flatten().map(|e| e.file_name()).collect();
        let matched = entries
            .iter()
            .find(|name| name.as_os_str() == *seg)
            .or_else(|| {
                entries
                    .iter()
                    .find(|name| components_equal_canonical(Path::new(name), Path::new(seg)))
            })
            .or_else(|| {
                let candidate = disk_cur.join(seg);
                entries.iter().find(|name| {
                    components_equal_casefold_nfd(Path::new(name), Path::new(seg))
                        && same_disk_entry(&disk_cur.join(name), &candidate)
                })
            });
        let Some(real_name) = matched else {
            return Ok(None);
        };
        disk_cur.push(real_name);
        disk_rel.push(real_name);
        if idx + 1 < comps.len() {
            let Ok(m) = fs::symlink_metadata(&disk_cur) else {
                return Ok(None);
            };
            if m.file_type().is_symlink() || !m.file_type().is_dir() {
                return Ok(None);
            }
        }
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
    if depth >= MAX_WALK_DEPTH {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "directory nesting exceeded maximum depth limit",
        ));
    }
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
            force_unlock(&path);
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

    fn is_real_dir_chain(root: &Path, rel: &Path, dir_guard: &mut UnlockedDirsGuard) -> bool {
        let mut cur = root.to_path_buf();
        for comp in rel.components() {
            cur.push(comp);
            match fs::symlink_metadata(&cur) {
                Ok(m) if !m.file_type().is_symlink() && m.file_type().is_dir() => {
                    if dir_guard.unlock_if_needed(&cur).is_err() {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    pub fn restore_back(&mut self) -> Result<(), AfuseError> {
        let mut dir_guard = UnlockedDirsGuard::new();
        let items = std::mem::take(&mut self.moved);
        let mut first_err: Option<AfuseError> = None;
        for item in items {
            let parent_rel = item.rel.parent().unwrap_or(Path::new(""));
            if !parent_rel.as_os_str().is_empty() && !Self::is_real_dir_chain(&self.ws, parent_rel, &mut dir_guard) {
                let _ = force_remove_all(&item.staged);
                continue;
            }
            let dst = self.ws.join(&item.rel);
            if fs::symlink_metadata(&dst).is_ok() {
                let _ = force_remove_all(&item.staged);
                continue;
            }
            if let Err(e) = prepare_ancestors_writable(&self.ws, &item.rel, false, &mut dir_guard) {
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

fn is_regular_non_symlink_file(p: &Path) -> bool {
    fs::symlink_metadata(p)
        .map(|m| !m.file_type().is_symlink() && m.file_type().is_file())
        .unwrap_or(false)
}

pub(crate) fn find_single_snap_file(ws: &Path, snap_tree: &Path) -> Option<PathBuf> {
    ws.file_name()
        .and_then(|n| resolve_disk_rel_path(snap_tree, Path::new(n)).ok().flatten())
        .map(|rel| snap_tree.join(rel))
        .filter(|p| is_regular_non_symlink_file(p))
        .or_else(|| {
            fs::read_dir(snap_tree)
                .ok()?
                .flatten()
                .map(|e| e.path())
                .find(|p| is_regular_non_symlink_file(p))
        })
}

pub(crate) fn workspace_differs_full(
    ws: &Path,
    kind: TargetKind,
    snap_tree: &Path,
    vault_hash: Option<&str>,
) -> bool {
    if kind == TargetKind::SingleFile {
        let Some(sf) = find_single_snap_file(ws, snap_tree) else { return true };
        let Ok((lw, _, _, _)) = compute_single_file_manifest(ws) else { return true };
        let Ok((ls, _, _, _)) = compute_single_file_manifest(&sf) else { return true };
        return lw != ls;
    }
    if !fs::symlink_metadata(ws).map(|m| !m.file_type().is_symlink() && m.file_type().is_dir()).unwrap_or(false) {
        return true;
    }
    let Ok((lw, _, _, _)) = compute_tree_manifest(ws) else { return true };
    if let Some(vh) = vault_hash {
        return lw != vh;
    }
    compute_tree_manifest(snap_tree).map(|t| t.0 != lw).unwrap_or(true)
}

pub(crate) fn selective_differs(
    ws: &Path,
    snap_tree: &Path,
    resolved: &[(Option<PathBuf>, Option<PathBuf>)],
) -> bool {
    for (snap_opt, live_opt) in resolved {
        match (snap_opt, live_opt) {
            (Some(sr), Some(lr)) if sr == lr => {
                let (sp, lp) = (snap_tree.join(sr), ws.join(lr));
                let (Ok(sm), Ok(lm)) = (fs::symlink_metadata(&sp), fs::symlink_metadata(&lp)) else { return true };
                let (sft, lft) = (sm.file_type(), lm.file_type());
                if sft.is_symlink() || lft.is_symlink() {
                    if !sft.is_symlink() || !lft.is_symlink() || fs::read_link(&sp).ok() != fs::read_link(&lp).ok() {
                        return true;
                    }
                } else if sft.is_file() && lft.is_file() {
                    if compute_single_file_manifest(&sp).map(|t| t.0).ok() != compute_single_file_manifest(&lp).map(|t| t.0).ok() {
                        return true;
                    }
                } else if sft.is_dir() && lft.is_dir() {
                    if compute_tree_manifest(&sp).map(|t| t.0).ok() != compute_tree_manifest(&lp).map(|t| t.0).ok() {
                        return true;
                    }
                } else {
                    return true;
                }
            }
            _ => return true,
        }
    }
    false
}

pub fn workspace_has_visible_files(ws: &Path) -> bool {
    let mut stack = vec![(ws.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth >= MAX_WALK_DEPTH {
            continue;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            if is_ignored_name(&entry.file_name().to_string_lossy()) { continue; }
            let p = entry.path();
            match fs::symlink_metadata(&p) {
                Ok(m) if !m.file_type().is_symlink() && m.file_type().is_dir() => {
                    stack.push((p, depth + 1))
                }
                Ok(_) => return true,
                Err(_) => {}
            }
        }
    }
    false
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
