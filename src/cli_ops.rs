use crate::emit_error;
use agent_fuse::{
    json_escape, render_hook_snippet, run_claude_hook_exec_stdio, run_doctor_with_opts,
    run_guarded_command, run_zsh_hook_exec, uninstall_hooks, AfuseError, GuardConfig,
};
use std::path::{Path, PathBuf};
use std::process;

fn json_opt_str(v: &Option<String>) -> String {
    v.as_ref()
        .map(|s| format!("\"{}\"", json_escape(s)))
        .unwrap_or_else(|| "null".to_string())
}

fn take_str_flag(rest: &[String], idx: usize, flag: &str, code: i32, json: bool) -> String {
    if idx + 1 >= rest.len() {
        emit_error(json, &AfuseError::new(code, format!("{} requires an argument", flag)));
    }
    rest[idx + 1].clone()
}

pub(crate) fn cmd_hook(workspace: PathBuf, rest: &[String], mut json: bool) {
    let mut target = String::new();
    let (mut is_exec, mut apply, mut want_help, mut end_opts) = (false, false, false, false);
    let mut custom_cwd: Option<PathBuf> = None;
    let mut custom_tool = String::new();
    let mut custom_home: Option<PathBuf> = None;
    let want_exec = rest
        .iter()
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "--exec");

    let mut i = 0usize;
    while i < rest.len() {
        let arg = rest[i].as_str();
        if !want_exec && !end_opts && arg == "--" {
            end_opts = true;
            i += 1;
            continue;
        }
        if !end_opts {
            match arg {
                "--help" | "-h" if !want_exec => { want_help = true; i += 1; continue; }
                "--exec" => { is_exec = true; i += 1; continue; }
                "--apply" => { apply = true; i += 1; continue; }
                "--json" => { json = true; i += 1; continue; }
                "--cwd" => {
                    custom_cwd = Some(PathBuf::from(take_str_flag(rest, i, "--cwd", 2, json)));
                    i += 2;
                    continue;
                }
                "--tool" => {
                    custom_tool = take_str_flag(rest, i, "--tool", 2, json);
                    i += 2;
                    continue;
                }
                "--home" => {
                    custom_home = Some(PathBuf::from(take_str_flag(rest, i, "--home", 2, json)));
                    i += 2;
                    continue;
                }
                "--claude" => { target = "claude".to_string(); i += 1; continue; }
                "--zsh" | "--shell" => { target = "zsh".to_string(); i += 1; continue; }
                other if other.starts_with('-') => {
                    if !want_exec {
                        emit_error(json, &AfuseError::new(2, "unknown hook option"));
                    }
                    i += 1;
                    continue;
                }
                _ => {}
            }
        }
        match arg {
            "print" if !end_opts => {}
            "claude" | "zsh" | "uninstall" => {
                if !target.is_empty() && target != arg && !want_exec {
                    emit_error(json, &AfuseError::new(2, "unexpected extra hook target"));
                }
                target = arg.to_string();
            }
            other => {
                if want_exec {
                    if target.is_empty() {
                        target = other.to_string();
                    }
                } else {
                    emit_error(
                        json,
                        &AfuseError::new(
                            2,
                            format!(
                                "unsupported hook target '{}': expected 'zsh', 'claude', or 'uninstall'",
                                other
                            ),
                        ),
                    );
                }
            }
        }
        i += 1;
    }

    if want_help && !want_exec {
        let usage = "USAGE: afuse hook <zsh|claude|uninstall> [--apply] [--home <DIR>] [--json]";
        if json {
            println!("{{\"ok\":true,\"usage\":\"{}\"}}", json_escape(usage));
        } else {
            println!("USAGE:\n  afuse hook <zsh|claude> [--json]\n  afuse hook uninstall [--apply] [--home <DIR>] [--json]");
        }
        return;
    }

    if is_exec {
        match target.as_str() {
            "claude" => run_claude_hook_exec_stdio(),
            "zsh" => run_zsh_hook_exec(&custom_cwd.unwrap_or(workspace), &custom_tool),
            _ => {}
        }
        process::exit(0);
    }

    if target.is_empty() {
        target = "zsh".to_string();
    }

    if target == "uninstall" {
        match uninstall_hooks(apply, custom_home.as_deref(), &workspace) {
            Ok(actions) => {
                if json {
                    let items: Vec<String> = actions
                        .iter()
                        .map(|a| {
                            format!(
                                "{{\"path\":\"{}\",\"kind\":\"{}\",\"start_line\":{},\"end_line\":{},\"applied\":{},\"backup_path\":{}}}",
                                json_escape(&a.path),
                                json_escape(&a.kind),
                                a.start_line,
                                a.end_line,
                                a.applied,
                                json_opt_str(&a.backup_path)
                            )
                        })
                        .collect();
                    println!("{{\"ok\":true,\"dry_run\":{},\"actions\":[{}]}}", !apply, items.join(","));
                } else if actions.is_empty() {
                    let mode = if apply { "apply" } else { "dry-run" };
                    println!("afuse hook uninstall ({}): no afuse hook entries found.", mode);
                } else {
                    let mode = if apply { "apply" } else { "dry-run — no files modified" };
                    println!("afuse hook uninstall ({}):", mode);
                    for a in actions {
                        match a.kind.as_str() {
                            "zsh_marker_block" if a.applied => println!(
                                "  [REMOVED] {} lines {}..{} (backup: {})",
                                a.path, a.start_line, a.end_line, a.backup_path.as_deref().unwrap_or("none")
                            ),
                            "zsh_marker_block" => println!(
                                "  [DRY-RUN] {} lines {}..{} (marker block; pass --apply to remove with backup)",
                                a.path, a.start_line, a.end_line
                            ),
                            "manual_claude_settings_json" => println!(
                                "  [MANUAL]  {} line {}: remove the afuse PreToolUse hook object manually (afuse never rewrites JSON settings)",
                                a.path, a.start_line
                            ),
                            _ => println!(
                                "  [MANUAL]  {} line {}: inspect and remove custom afuse hook line",
                                a.path, a.start_line
                            ),
                        }
                    }
                    println!("  Note: vault snapshots are preserved. Run `afuse prune --keep 0` inside a workspace to reclaim snapshots.");
                }
            }
            Err(e) => emit_error(json, &e),
        }
        return;
    }

    match render_hook_snippet(&target) {
        Ok(snippet) => {
            if json {
                println!(
                    "{{\"ok\":true,\"target\":\"{}\",\"snippet\":\"{}\"}}",
                    json_escape(&target),
                    json_escape(&snippet)
                );
            } else {
                print!("{}", snippet);
            }
        }
        Err(e) => emit_error(json, &e),
    }
}

fn parse_u64_flag(rest: &[String], idx: usize, flag: &str, min_val: u64, json: bool) -> u64 {
    if idx + 1 >= rest.len() {
        emit_error(json, &AfuseError::new(22, format!("{} requires an integer", flag)));
    }
    match rest[idx + 1].parse::<u64>() {
        Ok(v) if v >= min_val => v,
        _ => emit_error(
            json,
            &AfuseError::new(22, format!("{} requires integer >= {}", flag, min_val)),
        ),
    }
}

pub(crate) fn cmd_guard(workspace: &Path, rest: &[String], mut json: bool) -> ! {
    let mut cfg = GuardConfig {
        max_delete: 20,
        max_write_mb: 256,
        poll_ms: 15,
        auto_rollback: false,
    };
    let mut cmd_start = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--help" | "-h" => {
                println!("USAGE: afuse [--workspace <DIR>] [--json] guard [--max-delete N] [--max-write-mb M] [--poll-ms MS] [--auto-rollback] -- <CMD...>");
                process::exit(0);
            }
            "--" => {
                cmd_start = Some(i + 1);
                break;
            }
            "--max-delete" => {
                cfg.max_delete = parse_u64_flag(rest, i, "--max-delete", 1, json) as usize;
                i += 2;
            }
            "--max-write-mb" => {
                cfg.max_write_mb = parse_u64_flag(rest, i, "--max-write-mb", 0, json);
                i += 2;
            }
            "--poll-ms" => {
                cfg.poll_ms = parse_u64_flag(rest, i, "--poll-ms", 1, json).max(5);
                i += 2;
            }
            "--auto-rollback" => {
                cfg.auto_rollback = true;
                i += 1;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            flag if flag.starts_with('-') => {
                emit_error(json, &AfuseError::new(22, "unknown guard option"));
            }
            _ => {
                cmd_start = Some(i);
                break;
            }
        }
    }
    let cmd_slice = match cmd_start {
        Some(pos) if pos < rest.len() => &rest[pos..],
        _ => emit_error(json, &AfuseError::new(22, "guard requires '-- <command...>'")),
    };
    match run_guarded_command(workspace, &cfg, cmd_slice) {
        Ok(rep) => {
            if json {
                let us = rep.restore_elapsed_us.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string());
                println!(
                    "{{\"ok\":{},\"tripped\":{},\"trip_reason\":{},\"exit_code\":{},\"baseline_snapshot_id\":\"{}\",\"auto_restored\":{},\"restore_elapsed_us\":{},\"root_inode_preserved\":{},\"verified_sha256\":{}}}",
                    !rep.tripped && rep.exit_code == 0,
                    rep.tripped,
                    json_opt_str(&rep.trip_reason),
                    rep.exit_code,
                    json_escape(&rep.baseline_snapshot_id),
                    rep.auto_restored,
                    us,
                    rep.root_inode_preserved,
                    json_opt_str(&rep.verified_sha256)
                );
            } else if rep.tripped {
                eprintln!(
                    "⚡️ FUSE TRIPPED ({}) | process-group killed | auto_restored={} ({:.3} ms) | root_inode_preserved={}",
                    rep.trip_reason.as_deref().unwrap_or("threshold"),
                    rep.auto_restored,
                    rep.restore_elapsed_us.unwrap_or(0) as f64 / 1000.0,
                    rep.root_inode_preserved
                );
            }
            process::exit(rep.exit_code);
        }
        Err(e) => emit_error(json, &e),
    }
}

pub(crate) fn cmd_doctor(workspace: &Path, explicit_ws: bool, rest: &[String], mut json: bool) -> ! {
    if rest.iter().any(|a| a == "--json") { json = true; }
    let (doc_json, doc_ws, want_help) = match parse_doctor_args(rest, json) {
        Ok(v) => v,
        Err(e) => emit_error(json, &e),
    };
    if want_help {
        println!("USAGE: afuse [-w | --workspace <DIR>] [--json] doctor [<DIR>]");
        process::exit(0);
    }
    json = doc_json;
    let target_ws = doc_ws.as_deref().unwrap_or(workspace);
    let skip_ws_check = doc_ws.is_none() && !explicit_ws && target_ws == Path::new("/");
    match run_doctor_with_opts(target_ws, None, skip_ws_check) {
        Ok(rep) => {
            if json {
                println!("{}", rep.to_json());
            } else {
                let (verdict, fix_hint) = if rep.ok {
                    ("Result: [PASS] Ready for zero-overhead agentic protection.", None)
                } else if !rep.apfs_verified || !rep.vault_writable || rep.clonefile_probe_us == 0 {
                    (
                        "Result: [FAIL] Environment check failed (require APFS + writable vault).",
                        Some(if !rep.apfs_verified {
                            "  Fix: move project and vault onto a macOS APFS volume."
                        } else {
                            "  Fix: verify write permissions on ~/.agent-fuse (chmod 700 ~/.agent-fuse) or check AFUSE_VAULT_DIR."
                        }),
                    )
                } else {
                    (
                        "Result: [FAIL] Workspace path rejected by safety policy.",
                        Some("  Fix: select a regular file or directory on APFS outside /, $HOME, system roots, container roots (~/Desktop, ~/Documents, ~/Downloads), and ~/.agent-fuse."),
                    )
                };
                println!(
                    "afuse doctor v{} ({}/{})\n  apfs_verified: {}\n  clonefile_probe_us: {} us\n  free_gib: {:.2} GiB\n  vault_writable: {}\n  workspace_valid: {}\n  snapshot_count: {}\n{}",
                    rep.version, rep.os, rep.arch, rep.apfs_verified, rep.clonefile_probe_us,
                    rep.free_gib, rep.vault_writable, rep.workspace_valid, rep.snapshot_count, verdict
                );
                if let Some(hint) = fix_hint {
                    println!("{}", hint);
                }
            }
            process::exit(if rep.ok { 0 } else { 1 });
        }
        Err(e) => emit_error(json, &e),
    }
}

fn parse_doctor_args(rest: &[String], default_json: bool) -> Result<(bool, Option<PathBuf>, bool), AfuseError> {
    let (mut json, mut doc_ws, mut want_help, mut end_opts) = (default_json, None, false, false);
    for arg in rest {
        if !end_opts && arg == "--" {
            end_opts = true;
            continue;
        }
        if !end_opts {
            match arg.as_str() {
                "--help" | "-h" => { want_help = true; continue; }
                "--json" => { json = true; continue; }
                flag if flag.starts_with('-') => return Err(AfuseError::new(22, "unknown doctor option")),
                _ => {}
            }
        }
        if doc_ws.is_some() {
            return Err(AfuseError::new(22, "doctor accepts at most one [<DIR>] argument"));
        }
        doc_ws = Some(PathBuf::from(arg));
    }
    Ok((json, doc_ws, want_help))
}
