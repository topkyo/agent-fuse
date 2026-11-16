use crate::apfs::{is_tty_stdin, real_home_dir, statfs_info};
use crate::error::{AfuseError, ERR_EWOULDBLOCK};
use crate::hook_json::{extract_bash_candidate_paths, is_supported_claude_tool};
pub use crate::hook_json::{parse_claude_hook_json, ClaudeHookPayload};
use crate::manifest::SnapshotMeta;
use crate::prune::{prune_unlocked, ORPHAN_MAX_AGE_SECS};
use crate::snapshot::create_snapshot_unlocked_opts;
use crate::vault::{
    prepare_workspace_vault_with, resolve_workspace_vault_recovery, try_lock_vault,
    validate_workspace_binding_with_vault, PROJECT_MARKERS,
};
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const HOOK_MIN_AVAIL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const HOOK_DEFAULT_THROTTLE_MS: u128 = 5_000;
const HOOK_MAX_AUTO_SNAPS: usize = 20;

pub fn is_readonly_bash_command(cmd: &str) -> bool {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.contains('|') || trimmed.contains(';') || trimmed.contains('&')
        || trimmed.contains('\n') || trimmed.contains('`') || trimmed.contains("$(")
        || trimmed.contains('>') || trimmed.contains('<')
    {
        return false;
    }
    let mut parts = trimmed.split_whitespace();
    let Some(first) = parts.next() else { return true };
    let rest: Vec<&str> = parts.collect();
    match first {
        "ls" | "pwd" | "whoami" | "uname" | "cat" | "head" | "tail" | "wc" | "grep" | "which"
        | "type" | "stat" | "file" => true,
        "rg" => !rest.iter().any(|arg| {
            *arg == "--pre" || arg.starts_with("--pre=")
                || *arg == "--pre-glob" || arg.starts_with("--pre-glob=")
        }),
        "git" => {
            let Some(&second) = rest.first() else { return true };
            if !matches!(second, "status" | "diff" | "log" | "show" | "branch" | "rev-parse" | "remote") {
                return false;
            }
            !rest[1..].iter().any(|arg| {
                matches!(
                    *arg,
                    "-d" | "-D" | "-m" | "-M" | "-c" | "-C" | "-f" | "-u" | "--force"
                        | "--delete" | "--copy" | "--move" | "--set-upstream-to"
                        | "--unset-upstream" | "--edit-description" | "--create-reflog" | "-o"
                ) || arg.starts_with("--output")
                    || arg.starts_with("--set-upstream-to=")
                    || (second == "remote" && !matches!(*arg, "-v" | "--verbose"))
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
        if parent == cur { break; }
        cur = parent.to_path_buf();
    }
    let mut cur = base;
    for _ in 0..64 {
        if !is_skippable(&cur)
            && PROJECT_MARKERS[1..].iter().any(|m| fs::symlink_metadata(cur.join(m)).is_ok())
        {
            return Some(cur);
        }
        let Some(parent) = cur.parent() else { break };
        if parent == cur { break; }
        cur = parent.to_path_buf();
    }
    None
}

pub fn find_git_project_root(start: &Path) -> Option<PathBuf> {
    find_project_root(start)
}

fn vault_has_committed_snapshots(vault: &Path) -> bool {
    let Ok(rd) = fs::read_dir(vault.join("snapshots")) else { return false };
    rd.flatten().any(|ent| {
        !ent.file_name().to_string_lossy().starts_with(".tmp")
            && ent.path().join("meta.kv").is_file()
    })
}

fn find_existing_bound_target(start: &Path, vault_override: Option<&Path>) -> Option<PathBuf> {
    let abs = if start.is_absolute() { start.to_path_buf() } else { env::current_dir().ok()?.join(start) };
    let probe = fs::canonicalize(&abs).unwrap_or(abs);
    for anc in probe.ancestors() {
        if anc.parent().is_none() { break; }
        if let Ok((canon, ws_vault)) = resolve_workspace_vault_recovery(anc, vault_override) {
            if vault_has_committed_snapshots(&ws_vault)
                && validate_workspace_binding_with_vault(&canon, vault_override).is_ok()
            {
                return Some(canon);
            }
        }
    }
    None
}

fn resolve_candidate_path(cwd: &Path, raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Ok(home) = real_home_dir() {
            return home.join(rest);
        }
    }
    let p = Path::new(raw);
    if p.is_absolute() { p.to_path_buf() } else { cwd.join(p) }
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
    let target_candidate = find_existing_bound_target(start_cwd, vault_override)
        .or_else(|| find_project_root(start_cwd));
    let Some(target_candidate) = target_candidate else { return Ok(None) };
    let ws = validate_workspace_binding_with_vault(&target_candidate, vault_override)?.canonical_path;
    let stat_dir = if ws.is_dir() { ws.as_path() } else { ws.parent().unwrap_or(Path::new("/")) };
    if statfs_info(stat_dir)?.avail_bytes < HOOK_MIN_AVAIL_BYTES {
        return Ok(None);
    }

    let (_ws_canon, ws_vault) = prepare_workspace_vault_with(&ws, vault_override)?;
    let _lock = match try_lock_vault(&ws_vault) {
        Ok(g) => g,
        Err(e) if e.code == ERR_EWOULDBLOCK => return Ok(None),
        Err(e) => return Err(e),
    };

    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    let stamp_path = ws_vault.join("hook_last_snap.stamp");
    if throttle_ms > 0 {
        if let Ok(last_ms) = fs::read_to_string(&stamp_path).ok().and_then(|s| s.trim().parse::<u128>().ok()).ok_or(()) {
            if now_ms.saturating_sub(last_ms) < throttle_ms {
                return Ok(None);
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
    let _ = prune_unlocked(&ws_vault, HOOK_MAX_AUTO_SNAPS, Some("auto:hook:"), ORPHAN_MAX_AGE_SECS);
    Ok(Some(meta))
}

pub fn run_claude_hook_exec_from_reader<R: Read>(
    mut reader: R,
    vault_override: Option<&Path>,
) -> Option<SnapshotMeta> {
    let mut buf = Vec::with_capacity(8192);
    let _ = (&mut reader).take(1024 * 1024).read_to_end(&mut buf);
    let _ = std::io::copy(&mut reader.take(16 * 1024 * 1024), &mut std::io::sink());
    if buf.is_empty() {
        return None;
    }
    let payload = parse_claude_hook_json(&String::from_utf8_lossy(&buf));
    let tool = payload.tool_name.as_deref().unwrap_or("");
    if !is_supported_claude_tool(tool) {
        return None;
    }
    if tool == "Bash" && payload.bash_command.as_deref().map(is_readonly_bash_command).unwrap_or(false) {
        return None;
    }
    let cwd_str = payload.cwd.or_else(|| env::var("CLAUDE_PROJECT_DIR").ok())?;
    if cwd_str.trim().is_empty() {
        return None;
    }
    let cwd_path = Path::new(&cwd_str);
    let throttle_ms = env::var("AFUSE_HOOK_THROTTLE_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(HOOK_DEFAULT_THROTTLE_MS);
    let label = if tool.is_empty() { "auto:claude".to_string() } else { format!("auto:claude:{}", tool) };

    let mut cands = payload.candidate_paths;
    if tool == "Bash" {
        if let Some(cmd) = payload.bash_command.as_deref() {
            for tok in extract_bash_candidate_paths(cmd) {
                if !cands.contains(&tok) { cands.push(tok); }
            }
        }
    }
    for raw in cands {
        let resolved = resolve_candidate_path(cwd_path, &raw);
        if let Some(bound) = find_existing_bound_target(&resolved, vault_override) {
            return execute_hook_auto_snap(&bound, &label, vault_override, throttle_ms).ok().flatten();
        }
    }
    execute_hook_auto_snap(cwd_path, &label, vault_override, throttle_ms).ok().flatten()
}

pub fn run_claude_hook_exec_stdio() {
    if is_tty_stdin() { return; }
    let stdin = std::io::stdin();
    let _ = run_claude_hook_exec_from_reader(stdin.lock(), None);
}

pub fn run_zsh_hook_exec(cwd: &Path, tool: &str) {
    let throttle_ms = env::var("AFUSE_HOOK_THROTTLE_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(HOOK_DEFAULT_THROTTLE_MS);
    let label = if tool.trim().is_empty() { "auto:zsh".to_string() } else { format!("auto:zsh:{}", tool.trim()) };
    let _ = execute_hook_auto_snap(cwd, &label, None, throttle_ms);
}
