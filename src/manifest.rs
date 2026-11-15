use crate::apfs::{clonefile_nofollow, lstat_inode_mode};
use crate::error::{AfuseError, ERR_EINVAL, ERR_ENOENT};
use crate::sha256::{sha256_hex, Sha256};
use crate::vault::{is_ignored_name, TargetKind};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SnapshotMeta {
    pub id: String,
    pub created_ms: u128,
    pub label: String,
    pub workspace: String,
    pub root_inode: u64,
    pub root_mode: u32,
    pub file_count: u64,
    pub logical_bytes: u64,
    pub tree_sha256: String,
    pub elapsed_us: u128,
    pub target_kind: TargetKind,
}
pub fn compute_tree_stats_fast(root: &Path) -> Result<(u64, u64), AfuseError> {
    let mut files: u64 = 0;
    let mut bytes: u64 = 0;

    fn walk(cur: &Path, files: &mut u64, bytes: &mut u64) -> Result<(), AfuseError> {
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
            let p = item.path();
            let meta = fs::symlink_metadata(&p).map_err(|e| {
                AfuseError::new(
                    e.raw_os_error().unwrap_or(1),
                    format!("symlink_metadata failed on {}: {}", p.display(), e),
                )
            })?;
            let ft = meta.file_type();
            if ft.is_dir() {
                walk(&p, files, bytes)?;
            } else if ft.is_symlink() {
                *files += 1;
            } else if ft.is_file() {
                *files += 1;
                *bytes += meta.len();
            }
        }
        Ok(())
    }

    walk(root, &mut files, &mut bytes)?;
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

fn sanitize_meta_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\n' | '\r' | '\t' => out.push(' '),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {}
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn write_meta(meta_path: &Path, m: &SnapshotMeta) -> Result<(), AfuseError> {
    let content = format!(
        "id={}\ncreated_ms={}\nlabel={}\nworkspace={}\nroot_inode={}\nroot_mode={}\nfile_count={}\nlogical_bytes={}\ntree_sha256={}\nelapsed_us={}\ntarget_kind={}\n",
        sanitize_meta_value(&m.id),
        m.created_ms,
        sanitize_meta_value(&m.label),
        sanitize_meta_value(&m.workspace),
        m.root_inode,
        m.root_mode,
        m.file_count,
        m.logical_bytes,
        sanitize_meta_value(&m.tree_sha256),
        m.elapsed_us,
        m.target_kind.as_str()
    );
    fs::write(meta_path, content).map_err(|e| {
        AfuseError::new(e.raw_os_error().unwrap_or(1), format!("failed to write meta {}: {}", meta_path.display(), e))
    })
}

impl SnapshotMeta {
    pub fn read_from(meta_path: &Path) -> Result<SnapshotMeta, AfuseError> {
        let raw = fs::read_to_string(meta_path).map_err(|e| {
            AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), format!("failed to read snapshot meta {}: {}", meta_path.display(), e))
        })?;
        let mut kv: BTreeMap<String, String> = BTreeMap::new();
        for line in raw.lines() {
            if let Some((k, v)) = line.split_once('=') {
                kv.insert(k.to_string(), v.to_string());
            }
        }
        let meta = SnapshotMeta {
            id: kv.get("id").cloned().unwrap_or_default(),
            created_ms: kv.get("created_ms").and_then(|v| v.parse().ok()).unwrap_or(0),
            label: kv.get("label").cloned().unwrap_or_default(),
            workspace: kv.get("workspace").cloned().unwrap_or_default(),
            root_inode: kv.get("root_inode").and_then(|v| v.parse().ok()).unwrap_or(0),
            root_mode: kv.get("root_mode").and_then(|v| v.parse().ok()).unwrap_or(0o755),
            file_count: kv.get("file_count").and_then(|v| v.parse().ok()).unwrap_or(0),
            logical_bytes: kv.get("logical_bytes").and_then(|v| v.parse().ok()).unwrap_or(0),
            tree_sha256: kv.get("tree_sha256").cloned().unwrap_or_default(),
            elapsed_us: kv.get("elapsed_us").and_then(|v| v.parse().ok()).unwrap_or(0),
            target_kind: kv.get("target_kind").map(|s| TargetKind::parse_str(s)).unwrap_or(TargetKind::Directory),
        };
        if !meta.id.starts_with("snap-") || meta.tree_sha256.is_empty() || meta.created_ms == 0 {
            return Err(AfuseError::new(ERR_EINVAL, "corrupted snapshot meta.kv"));
        }
        Ok(meta)
    }
}

pub(crate) fn read_meta(meta_path: &Path) -> Result<SnapshotMeta, AfuseError> {
    SnapshotMeta::read_from(meta_path)
}
