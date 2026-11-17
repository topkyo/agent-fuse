use crate::apfs::{clonefile_nofollow, lstat_inode_mode};
use crate::error::{AfuseError, ERR_EINVAL, ERR_ENOENT};
pub(crate) use crate::meta::{read_meta, write_meta};
pub use crate::meta::SnapshotMeta;
use crate::sha256::{sha256_hex, Sha256};
use crate::vault::{is_ignored_name, TargetKind};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
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
    } else if ft.is_fifo() || ft.is_socket() {
        Ok(Some(format!("S:{:04o}", mode)))
    } else {
        Ok(None)
    }
}

pub fn compute_fast_fingerprint(
    target: &Path,
    kind: TargetKind,
) -> Result<(String, u64, u64), AfuseError> {
    if kind == TargetKind::SingleFile {
        let meta = fs::symlink_metadata(target).map_err(|e| {
            AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), format!("stat failed on {}: {}", target.display(), e))
        })?;
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(AfuseError::new(ERR_EINVAL, "target is not a regular file"));
        }
        let name = target
            .file_name()
            .ok_or_else(|| AfuseError::new(ERR_EINVAL, "missing file name"))?
            .to_string_lossy()
            .into_owned();
        let sig = fast_entry_sig(target, &meta)?.unwrap_or_default();
        let mut h = Sha256::new();
        h.update(name.as_bytes());
        h.update(b"\0");
        h.update(sig.as_bytes());
        h.update(b"\n");
        return Ok((format!("fast:{}", h.finalize_hex()), 1, meta.len()));
    }
    let mut entries: BTreeMap<String, String> = BTreeMap::new();
    let (mut files, mut bytes) = (0u64, 0u64);
    fn walk(
        base: &Path,
        cur: &Path,
        map: &mut BTreeMap<String, String>,
        files: &mut u64,
        bytes: &mut u64,
    ) -> Result<(), AfuseError> {
        let rd = fs::read_dir(cur).map_err(|e| {
            AfuseError::new(e.raw_os_error().unwrap_or(1), format!("read_dir failed on {}: {}", cur.display(), e))
        })?;
        for item in rd {
            let item = item.map_err(|e| AfuseError::new(1, e.to_string()))?;
            let name = item.file_name().to_string_lossy().into_owned();
            if is_ignored_name(&name) {
                continue;
            }
            let p = item.path();
            let rel = p.strip_prefix(base).unwrap_or(&p).to_string_lossy().into_owned();
            let meta = fs::symlink_metadata(&p).map_err(|e| {
                AfuseError::new(e.raw_os_error().unwrap_or(1), format!("symlink_metadata failed on {}: {}", p.display(), e))
            })?;
            if let Some(sig) = fast_entry_sig(&p, &meta)? {
                map.insert(rel, sig);
            }
            let ft = meta.file_type();
            if ft.is_dir() {
                walk(base, &p, map, files, bytes)?;
            } else if ft.is_symlink() {
                *files += 1;
            } else if ft.is_file() {
                *files += 1;
                *bytes += meta.len();
            }
        }
        Ok(())
    }
    walk(target, target, &mut entries, &mut files, &mut bytes)?;
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
    fn walk_proj(cur: &Path, count: &mut u64) {
        let Ok(rd) = fs::read_dir(cur) else { return };
        for item in rd.flatten() {
            let name = item.file_name().to_string_lossy().into_owned();
            if name == ".git" || is_ignored_name(&name) {
                continue;
            }
            let Ok(meta) = fs::symlink_metadata(item.path()) else { continue };
            let ft = meta.file_type();
            if ft.is_dir() {
                walk_proj(&item.path(), count);
            } else if ft.is_file() || ft.is_symlink() {
                *count += 1;
            }
        }
    }
    let mut count = 0u64;
    walk_proj(target, &mut count);
    count
}
pub fn compute_tree_stats_fast(root: &Path) -> Result<(u64, u64), AfuseError> {
    let (_, files, bytes) = compute_fast_fingerprint(root, TargetKind::Directory)?;
    Ok((files, bytes))
}

fn hash_file_streaming(path: &Path) -> Result<String, AfuseError> {
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

pub fn compute_tree_manifest(
    root: &Path,
) -> Result<(String, u64, u64, BTreeMap<String, String>), AfuseError> {
    let mut entries_map: BTreeMap<String, String> = BTreeMap::new();
    let mut file_count: u64 = 0;
    let mut logical_bytes: u64 = 0;

    fn walk(
        base: &Path,
        cur: &Path,
        map: &mut BTreeMap<String, String>,
        files: &mut u64,
        bytes: &mut u64,
    ) -> Result<(), AfuseError> {
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
                walk(base, &path, map, files, bytes)?;
            } else if ft.is_symlink() {
                *files += 1;
                let target = fs::read_link(&path).map_err(|e| {
                    AfuseError::new(1, format!("read_link failed on {}: {}", path.display(), e))
                })?;
                let thash = sha256_hex(target.as_os_str().as_bytes());
                map.insert(rel, format!("L:{}", thash));
            } else if ft.is_file() {
                *files += 1;
                *bytes += meta.len();
                let fhash = hash_file_streaming(&path)?;
                map.insert(rel, format!("F:{:04o}:{}:{}", mode, meta.len(), fhash));
            } else if ft.is_fifo() || ft.is_socket() {
                map.insert(rel, format!("S:{:04o}", mode));
            }
        }
        Ok(())
    }

    walk(
        root,
        root,
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

pub(crate) fn clone_filtered_tree(src_dir: &Path, dst_dir: &Path) -> Result<(), AfuseError> {
    fs::create_dir_all(dst_dir).map_err(|e| {
        AfuseError::new(
            e.raw_os_error().unwrap_or(1),
            format!("create_dir_all failed on {}: {}", dst_dir.display(), e),
        )
    })?;
    let (_, src_mode) = lstat_inode_mode(src_dir)?;
    let _ = fs::set_permissions(dst_dir, fs::Permissions::from_mode(src_mode & 0o7777));

    fn has_ignored_descendant(dir: &Path) -> bool {
        let Ok(rd) = fs::read_dir(dir) else {
            return false;
        };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_ignored_name(&name) {
                return true;
            }
            if let Ok(m) = entry.file_type() {
                if m.is_dir() && name != ".git" && has_ignored_descendant(&entry.path()) {
                    return true;
                }
            }
        }
        false
    }

    let rd = fs::read_dir(src_dir).map_err(|e| {
        AfuseError::new(
            e.raw_os_error().unwrap_or(1),
            format!("read_dir failed on {}: {}", src_dir.display(), e),
        )
    })?;
    for entry in rd {
        let entry = entry.map_err(|e| AfuseError::new(1, e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_ignored_name(&name) {
            continue;
        }
        let s_child = entry.path();
        let d_child = dst_dir.join(&entry.file_name());
        let ft = entry
            .file_type()
            .map_err(|e| AfuseError::new(1, e.to_string()))?;
        if ft.is_dir() && name != ".git" && has_ignored_descendant(&s_child) {
            clone_filtered_tree(&s_child, &d_child)?;
        } else {
            clonefile_nofollow(&s_child, &d_child)?;
        }
    }
    Ok(())
}

pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                use std::fmt::Write;
                let _ = write!(&mut out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

pub fn sanitize_terminal_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                use std::fmt::Write;
                let _ = write!(&mut out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}
