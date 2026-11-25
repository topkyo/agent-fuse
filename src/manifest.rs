use crate::apfs::{chmod_nofollow, lstat_inode_mode, MAX_WALK_DEPTH};
use crate::error::{AfuseError, ERR_EINVAL, ERR_ENOENT};
use crate::fs_guard::{clonefile_readable, TempPermGuard};
pub(crate) use crate::meta::{read_meta, write_meta};
pub use crate::meta::{json_escape, sanitize_terminal_text, SnapshotMeta, SnapshotOrigin};
use crate::sha256::{sha256_hex, Sha256};
use crate::vault::{is_ignored_name, TargetKind};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn fast_entry_sig(path: &Path, meta: &fs::Metadata) -> Result<Option<String>, AfuseError> {
    let ft = meta.file_type();
    let mode = meta.permissions().mode() & 0o7777;
    if ft.is_dir() {
        Ok(Some(format!("D:{:04o}", mode)))
    } else if ft.is_symlink() {
        let target = fs::read_link(path).map_err(|e| {
            AfuseError::new(1, format!("read_link failed on {}: {}", path.display(), e))
        })?;
        Ok(Some(format!("L:{}", sha256_hex(target.as_os_str().as_bytes()))))
    } else if ft.is_file() {
        Ok(Some(format!(
            "F:{:04o}:{}:{}:{}",
            mode,
            meta.len(),
            meta.mtime(),
            meta.mtime_nsec()
        )))
    } else {
        // Safely skip FIFO pipes, sockets, and device nodes to prevent EINVAL/hangs
        Ok(None)
    }
}

pub(crate) fn compute_fast_entries(target: &Path, kind: TargetKind) -> Result<(BTreeMap<String, String>, u64, u64, u64), AfuseError> {
    if kind == TargetKind::SingleFile {
        let meta = fs::symlink_metadata(target).map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), format!("stat failed on {}: {}", target.display(), e)))?;
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(AfuseError::new(ERR_EINVAL, "target is not a regular file"));
        }
        let name = target.file_name().ok_or_else(|| AfuseError::new(ERR_EINVAL, "missing file name"))?.to_string_lossy().into_owned();
        let mut map = BTreeMap::new();
        map.insert(name, fast_entry_sig(target, &meta)?.unwrap_or_default());
        return Ok((map, 1, meta.len(), 1));
    }
    let mut entries: BTreeMap<String, String> = BTreeMap::new();
    let (mut files, mut bytes, mut proj_files) = (0u64, 0u64, 0u64);
    fn walk(base: &Path, cur: &Path, depth: usize, in_git: bool, map: &mut BTreeMap<String, String>, files: &mut u64, bytes: &mut u64, proj_files: &mut u64) -> Result<(), AfuseError> {
        if depth >= MAX_WALK_DEPTH {
            return Err(AfuseError::new(ERR_EINVAL, "directory nesting exceeded maximum depth limit"));
        }
        let _dir_guard = TempPermGuard::ensure(cur, 0o500);
        let rd = fs::read_dir(cur).map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), format!("read_dir failed on {}: {}", cur.display(), e)))?;
        for item in rd {
            let item = item.map_err(|e| AfuseError::new(1, e.to_string()))?;
            let name = item.file_name().to_string_lossy().into_owned();
            if is_ignored_name(&name) { continue; }
            let p = item.path();
            let rel = p.strip_prefix(base).unwrap_or(&p).to_string_lossy().into_owned();
            let meta = fs::symlink_metadata(&p).map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), format!("symlink_metadata failed on {}: {}", p.display(), e)))?;
            let ft = meta.file_type();
            if !ft.is_file() && !ft.is_dir() && !ft.is_symlink() { continue; }
            if let Some(sig) = fast_entry_sig(&p, &meta)? { map.insert(rel, sig); }
            let child_in_git = in_git || name == ".git";
            if ft.is_dir() {
                walk(base, &p, depth + 1, child_in_git, map, files, bytes, proj_files)?;
            } else if ft.is_symlink() {
                *files = files.saturating_add(1);
                if !child_in_git { *proj_files = proj_files.saturating_add(1); }
            } else if ft.is_file() {
                *files = files.saturating_add(1);
                *bytes = bytes.saturating_add(meta.len());
                if !child_in_git { *proj_files = proj_files.saturating_add(1); }
            }
        }
        Ok(())
    }
    walk(target, target, 0, false, &mut entries, &mut files, &mut bytes, &mut proj_files)?;
    Ok((entries, files, bytes, proj_files))
}

pub fn compute_fast_fingerprint(
    target: &Path,
    kind: TargetKind,
) -> Result<(String, u64, u64), AfuseError> {
    let (entries, files, bytes, _) = compute_fast_entries(target, kind)?;
    let mut overall = Sha256::new();
    for (rel, sig) in &entries {
        overall.update(rel.as_bytes());
        overall.update(b"\0");
        overall.update(sig.as_bytes());
        overall.update(b"\n");
    }
    Ok((format!("fast:{}", overall.finalize_hex()), files, bytes))
}

pub fn count_project_files(target: &Path, kind: TargetKind) -> u64 {
    if kind == TargetKind::SingleFile {
        return if target.is_file() { 1 } else { 0 };
    }
    fn walk_proj(cur: &Path, depth: usize, count: &mut u64) {
        if depth >= MAX_WALK_DEPTH {
            return;
        }
        let _dir_guard = TempPermGuard::ensure(cur, 0o500);
        let Ok(rd) = fs::read_dir(cur) else { return };
        for item in rd.flatten() {
            let name = item.file_name().to_string_lossy().into_owned();
            if name == ".git" || is_ignored_name(&name) {
                continue;
            }
            let Ok(meta) = fs::symlink_metadata(item.path()) else { continue };
            let ft = meta.file_type();
            if ft.is_dir() {
                walk_proj(&item.path(), depth + 1, count);
            } else if ft.is_file() || ft.is_symlink() {
                *count = count.saturating_add(1);
            }
        }
    }
    let mut count = 0u64;
    walk_proj(target, 0, &mut count);
    count
}
pub fn compute_tree_stats_fast(root: &Path) -> Result<(u64, u64), AfuseError> {
    let (_, files, bytes) = compute_fast_fingerprint(root, TargetKind::Directory)?;
    Ok((files, bytes))
}

pub(crate) fn hash_file_streaming(path: &Path) -> Result<String, AfuseError> {
    let _file_guard = TempPermGuard::ensure(path, 0o400);
    let mut f = fs::File::open(path).map_err(|e| {
        AfuseError::new(
            e.raw_os_error().unwrap_or(1),
            format!("open failed on {}: {}", path.display(), e),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).map_err(|e| {
            AfuseError::new(
                e.raw_os_error().unwrap_or(1),
                format!("read failed on {}: {}", path.display(), e),
            )
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize_hex())
}

pub fn compute_single_file_manifest(
    file_path: &Path,
) -> Result<(String, u64, u64, BTreeMap<String, String>), AfuseError> {
    let meta = fs::symlink_metadata(file_path).map_err(|e| {
        AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), format!("stat failed on {}: {}", file_path.display(), e))
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(AfuseError::new(ERR_EINVAL, "target is not a regular file"));
    }
    let name = file_path
        .file_name()
        .ok_or_else(|| AfuseError::new(ERR_EINVAL, "missing file name"))?
        .to_string_lossy()
        .into_owned();
    let mode = meta.permissions().mode() & 0o7777;
    let fhash = hash_file_streaming(file_path)?;
    let sig = format!("F:{:04o}:{}:{}", mode, meta.len(), fhash);
    let mut map = BTreeMap::new();
    map.insert(name.clone(), sig.clone());
    let mut overall = Sha256::new();
    overall.update(name.as_bytes());
    overall.update(b"\0");
    overall.update(sig.as_bytes());
    overall.update(b"\n");
    Ok((overall.finalize_hex(), 1, meta.len(), map))
}

pub(crate) fn compute_snap_tree_manifest(
    snap_tree: &Path,
    ws: &Path,
    kind: TargetKind,
) -> Result<(String, u64, u64, BTreeMap<String, String>), AfuseError> {
    if kind == TargetKind::SingleFile {
        let sf = crate::restore_tree::find_single_snap_file(ws, snap_tree)
            .ok_or_else(|| AfuseError::new(ERR_ENOENT, "snapshot file missing in tree"))?;
        compute_single_file_manifest(&sf)
    } else {
        compute_tree_manifest(snap_tree)
    }
}

pub(crate) fn count_non_git_entries(map: &BTreeMap<String, String>) -> u64 {
    map.iter()
        .filter(|(rel, sig)| {
            !sig.starts_with("D:") && *rel != ".git" && !rel.starts_with(".git/")
        })
        .count() as u64
}

pub fn compute_tree_manifest(
    root: &Path,
) -> Result<(String, u64, u64, BTreeMap<String, String>), AfuseError> {
    let mut entries_map: BTreeMap<String, String> = BTreeMap::new();
    let mut file_count: u64 = 0;
    let mut logical_bytes: u64 = 0;

    fn walk(
        base: &Path,
        cur: &Path,
        depth: usize,
        map: &mut BTreeMap<String, String>,
        files: &mut u64,
        bytes: &mut u64,
    ) -> Result<(), AfuseError> {
        if depth >= MAX_WALK_DEPTH {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "directory nesting exceeded maximum depth limit",
            ));
        }
        let _dir_guard = TempPermGuard::ensure(cur, 0o500);
        let mut children: Vec<(String, PathBuf)> = Vec::new();
        let rd = fs::read_dir(cur).map_err(|e| {
            AfuseError::new(
                e.raw_os_error().unwrap_or(1),
                format!("read_dir failed on {}: {}", cur.display(), e),
            )
        })?;
        for item in rd {
            let item = item.map_err(|e| AfuseError::new(1, e.to_string()))?;
            let name = item.file_name().to_string_lossy().into_owned();
            if is_ignored_name(&name) {
                continue;
            }
            children.push((name, item.path()));
        }
        children.sort_by(|a, b| a.0.cmp(&b.0));

        for (_name, path) in children {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            let meta = fs::symlink_metadata(&path).map_err(|e| {
                AfuseError::new(
                    e.raw_os_error().unwrap_or(1),
                    format!("symlink_metadata failed on {}: {}", path.display(), e),
                )
            })?;
            let ft = meta.file_type();
            let mode = meta.permissions().mode() & 0o7777;

            if ft.is_dir() {
                map.insert(rel.clone(), format!("D:{:04o}", mode));
                walk(base, &path, depth + 1, map, files, bytes)?;
            } else if ft.is_symlink() {
                *files = files.saturating_add(1);
                let target = fs::read_link(&path).map_err(|e| {
                    AfuseError::new(1, format!("read_link failed on {}: {}", path.display(), e))
                })?;
                let thash = sha256_hex(target.as_os_str().as_bytes());
                map.insert(rel, format!("L:{}", thash));
            } else if ft.is_file() {
                *files = files.saturating_add(1);
                *bytes = bytes.saturating_add(meta.len());
                let fhash = hash_file_streaming(&path)?;
                map.insert(rel, format!("F:{:04o}:{}:{}", mode, meta.len(), fhash));
            }
            // Skip FIFO pipes, sockets, and special devices safely
        }
        Ok(())
    }

    walk(
        root,
        root,
        0,
        &mut entries_map,
        &mut file_count,
        &mut logical_bytes,
    )?;
    let mut overall = Sha256::new();
    for (rel, sig) in &entries_map {
        overall.update(rel.as_bytes());
        overall.update(b"\0");
        overall.update(sig.as_bytes());
        overall.update(b"\n");
    }
    Ok((overall.finalize_hex(), file_count, logical_bytes, entries_map))
}

fn collect_filtered_dirs(
    dir: &Path,
    depth: usize,
    filtered: &mut std::collections::HashSet<PathBuf>,
) -> bool {
    if depth >= MAX_WALK_DEPTH {
        return false;
    }
    let mut need = fs::symlink_metadata(dir)
        .map(|m| !m.file_type().is_symlink() && (m.permissions().mode() & 0o500) != 0o500)
        .unwrap_or(false);
    let _g = TempPermGuard::ensure(dir, 0o500);
    let Ok(rd) = fs::read_dir(dir) else {
        if need { filtered.insert(dir.to_path_buf()); }
        return need;
    };
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_ignored_name(&name) {
            need = true;
            continue;
        }
        let child = entry.path();
        if let Ok(m) = fs::symlink_metadata(&child) {
            let ft = m.file_type();
            let mode = m.permissions().mode() & 0o777;
            if !ft.is_file() && !ft.is_dir() && !ft.is_symlink() {
                need = true;
                continue;
            }
            if !ft.is_symlink()
                && ((ft.is_file() && (mode & 0o400) == 0) || (ft.is_dir() && (mode & 0o500) != 0o500))
            {
                need = true;
            }
            if ft.is_dir() && name != ".git" && collect_filtered_dirs(&child, depth + 1, filtered) {
                need = true;
            }
        }
    }
    if need {
        filtered.insert(dir.to_path_buf());
    }
    need
}

fn clone_filtered_inner(
    src_dir: &Path,
    dst_dir: &Path,
    depth: usize,
    filtered: &std::collections::HashSet<PathBuf>,
) -> Result<(), AfuseError> {
    if depth >= MAX_WALK_DEPTH {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "directory nesting exceeded maximum depth limit",
        ));
    }
    fs::create_dir_all(dst_dir).map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), format!("create_dir_all failed on {}: {}", dst_dir.display(), e)))?;
    let (_, src_mode) = lstat_inode_mode(src_dir)?;
    let _src_guard = TempPermGuard::ensure(src_dir, 0o500);
    let _ = chmod_nofollow(dst_dir, (src_mode & 0o777) | 0o700);
    let rd = fs::read_dir(src_dir).map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), format!("read_dir failed on {}: {}", src_dir.display(), e)))?;
    for entry in rd {
        let entry = entry.map_err(|e| AfuseError::new(1, e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_ignored_name(&name) { continue; }
        let s_child = entry.path();
        let d_child = dst_dir.join(&entry.file_name());
        let meta = fs::symlink_metadata(&s_child).map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))?;
        let ft = meta.file_type();
        if !ft.is_file() && !ft.is_dir() && !ft.is_symlink() { continue; }
        if ft.is_dir() && name != ".git" && filtered.contains(&s_child) {
            clone_filtered_inner(&s_child, &d_child, depth + 1, filtered)?;
        } else {
            clonefile_readable(&s_child, &d_child)?;
        }
    }
    let _ = chmod_nofollow(dst_dir, src_mode & 0o777);
    Ok(())
}

pub(crate) fn clone_filtered_tree(src_dir: &Path, dst_dir: &Path) -> Result<(), AfuseError> {
    let mut filtered = std::collections::HashSet::new();
    let _ = collect_filtered_dirs(src_dir, 0, &mut filtered);
    clone_filtered_inner(src_dir, dst_dir, 0, &filtered)
}
