use crate::error::{AfuseError, ERR_EINVAL, ERR_ENOENT};
use crate::vault::TargetKind;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct SnapshotMeta {
    pub id: String,
    pub created_ms: u128,
    pub label: String,
    pub workspace: String,
    pub root_inode: u64,
    pub root_mode: u32,
    pub file_count: u64,
    pub project_files: u64,
    pub logical_bytes: u64,
    pub tree_sha256: String,
    pub elapsed_us: u128,
    pub target_kind: TargetKind,
    pub summary: Option<String>,
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

pub(crate) fn encode_summary(kind: char, first_path: &str, count: usize) -> String {
    let leaf = Path::new(first_path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| first_path.to_string());
    let mut clean = String::with_capacity(leaf.len());
    for ch in leaf.chars() {
        match ch {
            '\n' | '\r' | '\t' | '=' => clean.push('_'),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {}
            c => clean.push(c),
        }
    }
    let clean = sanitize_terminal_text(&clean);
    let safe_name = if clean.trim().is_empty() { "file".to_string() } else { clean };
    format!("{}:{}|{}", kind, safe_name, count.max(1))
}

pub(crate) fn summarize_project_diff(
    added: &[String],
    modified: &[String],
    deleted: &[String],
) -> Option<String> {
    if !deleted.is_empty() {
        Some(encode_summary('D', &deleted[0], deleted.len()))
    } else if !modified.is_empty() {
        Some(encode_summary('M', &modified[0], modified.len()))
    } else if !added.is_empty() {
        Some(encode_summary('A', &added[0], added.len()))
    } else {
        None
    }
}

pub(crate) fn write_meta(meta_path: &Path, m: &SnapshotMeta) -> Result<(), AfuseError> {
    let mut content = format!(
        "id={}\ncreated_ms={}\nlabel={}\nworkspace={}\nroot_inode={}\nroot_mode={}\nfile_count={}\nproject_files={}\nlogical_bytes={}\ntree_sha256={}\nelapsed_us={}\ntarget_kind={}\n",
        sanitize_meta_value(&m.id),
        m.created_ms,
        sanitize_meta_value(&m.label),
        sanitize_meta_value(&m.workspace),
        m.root_inode,
        m.root_mode,
        m.file_count,
        m.project_files,
        m.logical_bytes,
        sanitize_meta_value(&m.tree_sha256),
        m.elapsed_us,
        m.target_kind.as_str()
    );
    if let Some(ref sum) = m.summary {
        let safe_sum = sanitize_meta_value(sum).replace('=', "_");
        if !safe_sum.is_empty() {
            content.push_str("summary=");
            content.push_str(&safe_sum);
            content.push('\n');
        }
    }
    fs::write(meta_path, content).map_err(|e| {
        AfuseError::new(
            e.raw_os_error().unwrap_or(1),
            format!("failed to write meta {}: {}", meta_path.display(), e),
        )
    })
}

impl SnapshotMeta {
    pub fn read_from(meta_path: &Path) -> Result<SnapshotMeta, AfuseError> {
        let raw = fs::read_to_string(meta_path).map_err(|e| {
            AfuseError::new(
                e.raw_os_error().unwrap_or(ERR_ENOENT),
                format!("failed to read snapshot meta {}: {}", meta_path.display(), e),
            )
        })?;
        let mut kv: BTreeMap<String, String> = BTreeMap::new();
        for line in raw.lines() {
            if let Some((k, v)) = line.split_once('=') {
                kv.insert(k.to_string(), v.to_string());
            }
        }
        let file_count = kv.get("file_count").and_then(|v| v.parse().ok()).unwrap_or(0);
        let project_files = kv.get("project_files").and_then(|v| v.parse().ok()).unwrap_or(file_count);
        let meta = SnapshotMeta {
            id: kv.get("id").cloned().unwrap_or_default(),
            created_ms: kv.get("created_ms").and_then(|v| v.parse().ok()).unwrap_or(0),
            label: kv.get("label").cloned().unwrap_or_default(),
            workspace: kv.get("workspace").cloned().unwrap_or_default(),
            root_inode: kv.get("root_inode").and_then(|v| v.parse().ok()).unwrap_or(0),
            root_mode: kv.get("root_mode").and_then(|v| v.parse().ok()).unwrap_or(0o755),
            file_count,
            project_files,
            logical_bytes: kv.get("logical_bytes").and_then(|v| v.parse().ok()).unwrap_or(0),
            tree_sha256: kv.get("tree_sha256").cloned().unwrap_or_default(),
            elapsed_us: kv.get("elapsed_us").and_then(|v| v.parse().ok()).unwrap_or(0),
            target_kind: kv
                .get("target_kind")
                .map(|s| TargetKind::parse_str(s))
                .unwrap_or(TargetKind::Directory),
            summary: kv.get("summary").filter(|s| !s.is_empty()).cloned(),
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
