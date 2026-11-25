use crate::apfs::chmod_nofollow;
use crate::diff_rename::RenamePair;
use crate::error::{AfuseError, ERR_EINVAL, ERR_ENOENT};
use crate::vault::TargetKind;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const PIN_CONTAINS_DELETED: &str = "contains_deleted";

pub(crate) fn is_valid_snapshot_id(id: &str) -> bool {
    if !id.starts_with("snap-") || id.len() <= 5 || id.len() > 128 {
        return false;
    }
    id.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotOrigin {
    Initial,
    Manual,
    AutoSave,
    BeforeRestore,
    RestoredFrom,
    Hook,
}

impl SnapshotOrigin {
    pub fn as_str(&self) -> &'static str {
        match self {
            SnapshotOrigin::Initial => "initial",
            SnapshotOrigin::Manual => "manual",
            SnapshotOrigin::AutoSave => "auto_save",
            SnapshotOrigin::BeforeRestore => "before_restore",
            SnapshotOrigin::RestoredFrom => "restored_from",
            SnapshotOrigin::Hook => "hook",
        }
    }

    pub fn parse_str(s: &str) -> Option<Self> {
        match s.trim() {
            "initial" => Some(SnapshotOrigin::Initial),
            "manual" => Some(SnapshotOrigin::Manual),
            "auto_save" => Some(SnapshotOrigin::AutoSave),
            "before_restore" => Some(SnapshotOrigin::BeforeRestore),
            "restored_from" => Some(SnapshotOrigin::RestoredFrom),
            "hook" => Some(SnapshotOrigin::Hook),
            _ => None,
        }
    }

    pub fn infer_from_label(label: &str) -> Self {
        let clean = label.trim();
        if clean == "auto:pro:init" {
            SnapshotOrigin::Initial
        } else if clean == "auto:pre-restore" {
            SnapshotOrigin::BeforeRestore
        } else if clean == "auto:pro:restored" || clean.starts_with("auto:pro:restored:") {
            SnapshotOrigin::RestoredFrom
        } else if clean.starts_with("auto:claude")
            || clean.starts_with("auto:zsh")
            || clean.starts_with("auto:hook")
            || clean.starts_with("auto:guard")
        {
            SnapshotOrigin::Hook
        } else if clean.starts_with("auto:") {
            SnapshotOrigin::AutoSave
        } else {
            SnapshotOrigin::Manual
        }
    }
}

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
    pub origin: SnapshotOrigin,
    pub retention_pin: Option<String>,
    pub restored_from_id: Option<String>,
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

fn sanitize_summary_leaf(path: &str) -> String {
    let leaf = Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| path.to_string());
    let mut clean = String::with_capacity(leaf.len());
    for ch in leaf.chars() {
        match ch {
            '\n' | '\r' | '\t' | '=' | ';' => clean.push('_'),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {}
            c => clean.push(c),
        }
    }
    let clean = sanitize_terminal_text(&clean);
    if clean.trim().is_empty() {
        "file".to_string()
    } else {
        clean
    }
}

pub(crate) fn encode_summary(kind: char, first_path: &str, count: usize) -> String {
    let safe_name = sanitize_summary_leaf(first_path);
    format!("{}:{}|{}", kind, safe_name, count.max(1))
}

pub(crate) fn encode_rename_summary(from: &str, to: &str, count: usize) -> String {
    let from_leaf = sanitize_summary_leaf(from);
    let to_leaf = sanitize_summary_leaf(to);
    format!("R:{}->{}|{}", from_leaf, to_leaf, count.max(1))
}

pub(crate) fn summarize_project_diff(
    added: &[String],
    modified: &[String],
    deleted: &[String],
    renamed: &[RenamePair],
) -> Option<String> {
    let mut parts: Vec<String> = Vec::with_capacity(2);
    if !deleted.is_empty() {
        parts.push(encode_summary('D', &deleted[0], deleted.len()));
    }
    if parts.len() < 2 && !renamed.is_empty() {
        parts.push(encode_rename_summary(
            &renamed[0].from,
            &renamed[0].to,
            renamed.len(),
        ));
    }
    if parts.len() < 2 && !modified.is_empty() {
        parts.push(encode_summary('M', &modified[0], modified.len()));
    }
    if parts.len() < 2 && !added.is_empty() {
        parts.push(encode_summary('A', &added[0], added.len()));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(";"))
    }
}

pub(crate) fn write_meta(meta_path: &Path, m: &SnapshotMeta) -> Result<(), AfuseError> {
    let mut content = format!(
        "id={}\ncreated_ms={}\nlabel={}\nworkspace={}\nroot_inode={}\nroot_mode={}\nfile_count={}\nproject_files={}\nlogical_bytes={}\ntree_sha256={}\nelapsed_us={}\ntarget_kind={}\norigin={}\n",
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
        m.target_kind.as_str(),
        m.origin.as_str()
    );
    if let Some(ref sum) = m.summary {
        let safe_sum = sanitize_meta_value(sum).replace('=', "_");
        if !safe_sum.is_empty() {
            content.push_str("summary=");
            content.push_str(&safe_sum);
            content.push('\n');
        }
    }
    if let Some(ref pin) = m.retention_pin {
        let safe_pin = sanitize_meta_value(pin).replace('=', "_");
        if !safe_pin.is_empty() {
            content.push_str("retention_pin=");
            content.push_str(&safe_pin);
            content.push('\n');
        }
    }
    if let Some(ref rf) = m.restored_from_id {
        let safe_rf = sanitize_meta_value(rf).replace('=', "_");
        if !safe_rf.is_empty() {
            content.push_str("restored_from_id=");
            content.push_str(&safe_rf);
            content.push('\n');
        }
    }
    fs::write(meta_path, content).map_err(|e| {
        AfuseError::new(
            e.raw_os_error().unwrap_or(1),
            format!("failed to write meta {}: {}", meta_path.display(), e),
        )
    })?;
    let _ = chmod_nofollow(meta_path, 0o600);
    Ok(())
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
        let label = kv.get("label").cloned().unwrap_or_default();
        let origin = kv
            .get("origin")
            .and_then(|s| SnapshotOrigin::parse_str(s))
            .unwrap_or_else(|| SnapshotOrigin::infer_from_label(&label));
        let meta = SnapshotMeta {
            id: kv.get("id").cloned().unwrap_or_default(),
            created_ms: kv.get("created_ms").and_then(|v| v.parse().ok()).unwrap_or(0),
            label,
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
            origin,
            retention_pin: kv.get("retention_pin").filter(|s| !s.is_empty()).cloned(),
            restored_from_id: kv.get("restored_from_id").filter(|s| !s.is_empty()).cloned(),
        };
        if !is_valid_snapshot_id(&meta.id) || meta.tree_sha256.is_empty() || meta.created_ms == 0 {
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
