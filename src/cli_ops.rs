use crate::emit_error;
use agent_fuse::{
    check_for_updates, json_escape, render_hook_snippet, run_claude_hook_exec_stdio, run_doctor,
    run_guarded_command, run_upgrade_apply, run_zsh_hook_exec, uninstall_hooks, AfuseError,
    GuardConfig,
};
use std::path::{Path, PathBuf};
use std::process;

fn json_opt_str(v: &Option<String>) -> String {
    v.as_ref()
        .map(|s| format!("\"{}\"", json_escape(s)))
        .unwrap_or_else(|| "null".to_string())
}

pub(crate) fn cmd_hook(workspace: PathBuf, rest: &[String], mut json: bool) {
    let mut target = String::new();
    let mut is_exec = false;
    let mut apply = false;
    let mut custom_cwd: Option<PathBuf> = None;
    let mut custom_tool = String::new();
    let mut custom_home: Option<PathBuf> = None;

    let mut i = 0usize;
    while i < rest.len() {
        match rest[i].as_str() {
            "--exec" => {
                is_exec = true;
                i += 1;
            }
            "--apply" => {
                apply = true;
                i += 1;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "--cwd" => {
                if i + 1 < rest.len() {
                    custom_cwd = Some(PathBuf::from(&rest[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--tool" => {
                if i + 1 < rest.len() {
                    custom_tool = rest[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--home" => {
                if i + 1 < rest.len() {
                    custom_home = Some(PathBuf::from(&rest[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "print" => i += 1,
            "--claude" | "claude" => {
                target = "claude".to_string();
                i += 1;
            }
            "--zsh" | "--shell" | "zsh" => {
                target = "zsh".to_string();
                i += 1;
            }
            "uninstall" => {
                target = "uninstall".to_string();
                i += 1;
            }
            other => {
                if target.is_empty() {
                    target = other.to_string();
                }
                i += 1;
            }
        }
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
            "--" => {
                cmd_start = Some(i + 1);
                break;
            }
            "--max-delete" => {
                if i + 1 >= rest.len() {
                    emit_error(json, &AfuseError::new(22, "--max-delete requires N"));
                }
                cfg.max_delete = rest[i + 1].parse().unwrap_or(20).max(1);
                i += 2;
            }
            "--max-write-mb" => {
                if i + 1 >= rest.len() {
                    emit_error(json, &AfuseError::new(22, "--max-write-mb requires MB"));
                }
                cfg.max_write_mb = rest[i + 1].parse().unwrap_or(256);
                i += 2;
            }
            "--poll-ms" => {
                if i + 1 >= rest.len() {
                    emit_error(json, &AfuseError::new(22, "--poll-ms requires MS"));
                }
                cfg.poll_ms = rest[i + 1].parse().unwrap_or(15).max(5);
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

pub(crate) fn cmd_doctor(workspace: &Path, rest: &[String], mut json: bool) -> ! {
    if rest.iter().any(|a| a == "--json") {
        json = true;
    }
    let (doc_json, doc_ws) = match parse_doctor_args(rest, json) {
        Ok(v) => v,
        Err(e) => emit_error(json, &e),
    };
    json = doc_json;
    let target_ws = doc_ws.as_deref().unwrap_or(workspace);
    match run_doctor(target_ws) {
        Ok(rep) => {
            if json {
                println!("{}", rep.to_json());
            } else {
                let verdict = if rep.ok {
                    "Result: [PASS] Ready for zero-overhead agentic protection."
                } else {
                    "Result: [FAIL] Environment check failed (require APFS + writable vault)."
                };
                println!(
                    "afuse doctor v{} ({}/{})\n  apfs_verified: {}\n  clonefile_probe_us: {} us\n  free_gib: {:.2} GiB\n  vault_writable: {}\n  snapshot_count: {}\n{}",
                    rep.version, rep.os, rep.arch, rep.apfs_verified, rep.clonefile_probe_us,
                    rep.free_gib, rep.vault_writable, rep.snapshot_count, verdict
                );
            }
            process::exit(if rep.ok { 0 } else { 1 });
        }
        Err(e) => emit_error(json, &e),
    }
}

pub(crate) fn cmd_upgrade(rest: &[String], mut json: bool) {
    let mut check_only = false;
    for arg in rest {
        match arg.as_str() {
            "--check" => check_only = true,
            "--json" => json = true,
            other => emit_error(json, &AfuseError::new(22, format!("unknown upgrade option '{}'", other))),
        }
    }
    if check_only {
        match check_for_updates() {
            Ok(rep) => {
                if json {
                    println!("{}", rep.to_json());
                } else if rep.update_available {
                    println!(
                        "Update available: v{} -> v{}\nRelease: {}\nHomebrew: {}",
                        rep.current_version, rep.latest_version, rep.release_url, rep.brew_cmd
                    );
                } else {
                    println!("afuse v{} is up to date (latest: v{}).", rep.current_version, rep.latest_version);
                }
            }
            Err(e) => emit_error(json, &e),
        }
    } else {
        match run_upgrade_apply() {
            Ok(rep) => {
                if json {
                    println!("{}", rep.to_json());
                } else if rep.updated {
                    println!(
                        "Upgraded afuse: v{} -> v{} (sha256={})",
                        rep.current_version,
                        rep.latest_version,
                        rep.verified_sha256.as_deref().unwrap_or("verified")
                    );
                } else {
                    println!("afuse v{} is already up to date (latest: v{}).", rep.current_version, rep.latest_version);
                }
            }
            Err(e) => emit_error(json, &e),
        }
    }
}

fn parse_doctor_args(
    rest: &[String],
    default_json: bool,
) -> Result<(bool, Option<PathBuf>), AfuseError> {
    let mut json = default_json;
    let mut doc_ws: Option<PathBuf> = None;
    for arg in rest {
        match arg.as_str() {
            "--json" => json = true,
            flag if flag.starts_with('-') => {
                return Err(AfuseError::new(22, "unknown doctor option"));
            }
            dir => {
                if doc_ws.is_some() {
                    return Err(AfuseError::new(22, "doctor accepts at most one [<DIR>] argument"));
                }
                doc_ws = Some(PathBuf::from(dir));
            }
        }
    }
    Ok((json, doc_ws))
}
