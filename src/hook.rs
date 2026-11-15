use crate::apfs::{is_tty_stdin, real_home_dir, statfs_info};
use crate::error::{AfuseError, ERR_EWOULDBLOCK};
use crate::manifest::SnapshotMeta;
use crate::prune::{prune_unlocked, ORPHAN_MAX_AGE_SECS};
use crate::snapshot::create_snapshot_unlocked_opts;
use crate::vault::{prepare_workspace_vault_with, try_lock_vault, validate_workspace_binding_with_vault, PROJECT_MARKERS};
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const HOOK_MIN_AVAIL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const HOOK_DEFAULT_THROTTLE_MS: u128 = 5_000;
const HOOK_MAX_AUTO_SNAPS: usize = 20;
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaudeHookPayload {
    pub cwd: Option<String>,
    pub tool_name: Option<String>,
    pub bash_command: Option<String>,
}
pub fn parse_claude_hook_json(input: &str) -> ClaudeHookPayload {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut brace_depth = 0i32;
    let mut bracket_depth = 0i32;
    let mut in_tool_input = false;
    let mut expecting_value_for: Option<&'static str> = None;
    let mut entering_tool_input = false;
    let mut out = ClaudeHookPayload::default();

    fn parse_json_string(bytes: &[u8], start_quote: usize) -> Option<(String, usize)> {
        let mut i = start_quote + 1;
        let mut buf: Vec<u8> = Vec::new();
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'"' {
                return Some((String::from_utf8_lossy(&buf).into_owned(), i + 1));
            }
            if b == b'\\' {
                i += 1;
                if i >= bytes.len() {
                    return None;
                }
                match bytes[i] {
                    b'"' => buf.push(b'"'),
                    b'\\' => buf.push(b'\\'),
                    b'/' => buf.push(b'/'),
                    b'n' => buf.push(b'\n'),
                    b'r' => buf.push(b'\r'),
                    b't' => buf.push(b'\t'),
                    b'b' => buf.push(0x08),
                    b'f' => buf.push(0x0c),
                    b'u' => {
                        if i + 4 < bytes.len() {
                            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 5]) {
                                if let Ok(code) = u32::from_str_radix(hex_str, 16) {
                                    if let Some(ch) = char::from_u32(code) {
                                        let mut tmp = [0u8; 4];
                                        buf.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                                        i += 4;
                                    }
                                }
                            }
                        }
                    }
                    other => buf.push(other),
                }
                i += 1;
            } else {
                buf.push(b);
                i += 1;
            }
        }
        None
    }

    while i < len {
        let b = bytes[i];
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'{' => {
                brace_depth += 1;
                if entering_tool_input && brace_depth == 2 && bracket_depth == 0 {
                    in_tool_input = true;
                }
                entering_tool_input = false;
                expecting_value_for = None;
                i += 1;
            }
            b'}' => {
                if in_tool_input && brace_depth == 2 && bracket_depth == 0 {
                    in_tool_input = false;
                }
                brace_depth = (brace_depth - 1).max(0);
                entering_tool_input = false;
                expecting_value_for = None;
                i += 1;
            }
            b'[' => {
                bracket_depth += 1;
                entering_tool_input = false;
                expecting_value_for = None;
                i += 1;
            }
            b']' => {
                bracket_depth = (bracket_depth - 1).max(0);
                entering_tool_input = false;
                expecting_value_for = None;
                i += 1;
            }
            b',' => {
                entering_tool_input = false;
                expecting_value_for = None;
                i += 1;
            }
            b'"' => {
                let Some((s, next_i)) = parse_json_string(bytes, i) else {
                    break;
                };
                i = next_i;
                if let Some(field) = expecting_value_for.take() {
                    match field {
                        "cwd" => out.cwd = Some(s),
                        "tool_name" => out.tool_name = Some(s),
                        "command" => out.bash_command = Some(s),
                        _ => {}
                    }
                    continue;
                }
                while i < len && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
                    i += 1;
                }
                if i < len && bytes[i] == b':' {
                    i += 1;
                    if brace_depth == 1 && bracket_depth == 0 {
                        match s.as_str() {
                            "cwd" => expecting_value_for = Some("cwd"),
                            "tool_name" => expecting_value_for = Some("tool_name"),
                            "tool_input" => entering_tool_input = true,
                            _ => {}
                        }
                    } else if in_tool_input && brace_depth == 2 && bracket_depth == 0 && s == "command"
                    {
                        expecting_value_for = Some("command");
                    }
                }
            }
            _ => {
                expecting_value_for = None;
                entering_tool_input = false;
                i += 1;
            }
        }
    }
    out
}

pub fn is_readonly_bash_command(cmd: &str) -> bool {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.bytes().any(|b| {
        matches!(
            b,
            b'>' | b'|' | b';' | b'&' | b'`' | b'$' | b'\n' | b'\r' | b'(' | b')'
        )
    }) {
        return false;
    }
    let mut parts = trimmed.split_whitespace();
    let Some(first) = parts.next() else {
        return true;
    };
    let second = parts.next().unwrap_or("");
    match first {
        "ls" | "pwd" | "whoami" | "uname" | "cat" | "head" | "tail" | "wc" | "grep" | "rg"
        | "which" | "type" | "stat" | "file" => true,
        "git" => {
            if !matches!(
                second,
                "status" | "diff" | "log" | "show" | "branch" | "rev-parse" | "remote"
            ) {
                return false;
            }
            !parts.any(|arg| {
                matches!(arg, "-d" | "-D" | "-m" | "-M" | "-f" | "--force" | "--delete" | "-o")
                    || arg.starts_with("--output")
                    || (second == "remote" && !matches!(arg, "-v" | "--verbose"))
            })
        }
        _ => false,
    }
}

pub fn find_project_root(start: &Path) -> Option<PathBuf> {
    let mut base = fs::canonicalize(start).ok()?;
    if base.is_file() {
        base = base.parent()?.to_path_buf();
    }
    let home = real_home_dir().ok();
    let is_skippable = |p: &Path| p.parent().is_none() || home.as_deref() == Some(p);

    let mut cur = base.clone();
    for _ in 0..64 {
        if !is_skippable(&cur) && fs::symlink_metadata(cur.join(".git")).is_ok() {
            return Some(cur);
        }
        let Some(parent) = cur.parent() else { break };
        if parent == cur {
            break;
        }
        cur = parent.to_path_buf();
    }

    let mut cur = base;
    for _ in 0..64 {
        if !is_skippable(&cur)
            && PROJECT_MARKERS[1..]
                .iter()
                .any(|m| fs::symlink_metadata(cur.join(m)).is_ok())
        {
            return Some(cur);
        }
        let Some(parent) = cur.parent() else { break };
        if parent == cur {
            break;
        }
        cur = parent.to_path_buf();
    }
    None
}

pub fn find_git_project_root(start: &Path) -> Option<PathBuf> {
    find_project_root(start)
}

pub fn execute_hook_auto_snap(
    start_cwd: &Path,
    label: &str,
    vault_override: Option<&Path>,
    throttle_ms: u128,
) -> Result<Option<SnapshotMeta>, AfuseError> {
    if env::var("AFUSE_HOOK_DISABLE").as_deref() == Ok("1")
        || env::var("AFUSE_GUARDED").as_deref() == Ok("1")
    {
        return Ok(None);
    }

    let Some(project_root) = find_project_root(start_cwd) else {
        return Ok(None);
    };
    let validated = validate_workspace_binding_with_vault(&project_root, vault_override)?;
    let ws = validated.canonical_path;
    let ws_fs = statfs_info(&ws)?;
    if ws_fs.avail_bytes < HOOK_MIN_AVAIL_BYTES {
        return Ok(None);
    }

    let (_ws_canon, ws_vault) = prepare_workspace_vault_with(&ws, vault_override)?;
    let _lock = match try_lock_vault(&ws_vault) {
        Ok(g) => g,
        Err(e) if e.code == ERR_EWOULDBLOCK => return Ok(None),
        Err(e) => return Err(e),
    };

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let stamp_path = ws_vault.join("hook_last_snap.stamp");
    if throttle_ms > 0 {
        if let Ok(raw) = fs::read_to_string(&stamp_path) {
            if let Ok(last_ms) = raw.trim().parse::<u128>() {
                if now_ms.saturating_sub(last_ms) < throttle_ms {
                    return Ok(None);
                }
            }
        }
    }
    let _ = fs::write(&stamp_path, format!("{}\n", now_ms));

    let clean_label = if label.starts_with("auto:hook:") {
        label.to_string()
    } else if let Some(rest) = label.strip_prefix("auto:") {
        format!("auto:hook:{}", rest)
    } else {
        format!("auto:hook:{}", label)
    };
    let meta = create_snapshot_unlocked_opts(&ws, &ws_vault, &clean_label, true)?;
    let _ = prune_unlocked(
        &ws_vault,
        HOOK_MAX_AUTO_SNAPS,
        Some("auto:hook:"),
        ORPHAN_MAX_AGE_SECS,
    );
    Ok(Some(meta))
}

pub fn run_claude_hook_exec_from_reader<R: Read>(
    mut reader: R,
    vault_override: Option<&Path>,
) -> Option<SnapshotMeta> {
    let mut buf = Vec::with_capacity(8192);
    let _ = (&mut reader).take(1024 * 1024).read_to_end(&mut buf);
    // Drain up to 16 MiB into sink with an 8 KiB stack buffer so upstream callers (e.g. Node/Python) never hit EPIPE
    let _ = std::io::copy(&mut reader.take(16 * 1024 * 1024), &mut std::io::sink());
    if buf.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(&buf);
    let payload = parse_claude_hook_json(&text);

    let tool = payload.tool_name.as_deref().unwrap_or("");
    if !tool.is_empty()
        && !matches!(
            tool,
            "Write" | "Edit" | "MultiEdit" | "NotebookEdit" | "Bash"
        )
    {
        return None;
    }
    if tool == "Bash" {
        if let Some(cmd) = payload.bash_command.as_deref() {
            if is_readonly_bash_command(cmd) {
                return None;
            }
        }
    }

    let cwd_str = payload
        .cwd
        .or_else(|| env::var("CLAUDE_PROJECT_DIR").ok())?;
    if cwd_str.trim().is_empty() {
        return None;
    }

    let throttle_ms = env::var("AFUSE_HOOK_THROTTLE_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(HOOK_DEFAULT_THROTTLE_MS);
    let label = if tool.is_empty() {
        "auto:claude".to_string()
    } else {
        format!("auto:claude:{}", tool)
    };
    execute_hook_auto_snap(Path::new(&cwd_str), &label, vault_override, throttle_ms)
        .ok()
        .flatten()
}

pub fn run_claude_hook_exec_stdio() {
    if is_tty_stdin() {
        return;
    }
    let stdin = std::io::stdin();
    let _ = run_claude_hook_exec_from_reader(stdin.lock(), None);
}

pub fn run_zsh_hook_exec(cwd: &Path, tool: &str) {
    let throttle_ms = env::var("AFUSE_HOOK_THROTTLE_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(HOOK_DEFAULT_THROTTLE_MS);
    let label = if tool.trim().is_empty() {
        "auto:zsh".to_string()
    } else {
        format!("auto:zsh:{}", tool.trim())
    };
    let _ = execute_hook_auto_snap(cwd, &label, None, throttle_ms);
}
