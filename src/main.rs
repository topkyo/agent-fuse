mod cli_cmds;
mod cli_ops;
mod cli_upgrade;

use agent_fuse::{json_escape, sanitize_terminal_text, AfuseError};
use std::env;
use std::path::{Path, PathBuf};
use std::process;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    eprintln!(
        "afuse {} — Millisecond-scale APFS CoW workspace time machine & runaway agent circuit breaker\n\
         \n\
         USAGE:\n\
           afuse [-w | --workspace <DIR>] [--json] <SUBCOMMAND> [OPTIONS]\n\
         \n\
         SUBCOMMANDS:\n\
           snap [-m <LABEL>] [--fast] [--rolling] [--if-changed]\n\
                                                 Take an APFS CoW workspace snapshot (0 B at t=0)\n\
           list                                  List timeline snapshots (newest first)\n\
           diff [<SNAP_ID|latest>] [--fast]    Compare dirty workspace against snapshot\n\
           restore [<SNAP_ID|latest>] [--fast] [--no-backup] [-- <REL_PATH>...]\n\
                                                 Atomically restore workspace (or selected paths) preserving root Inode\n\
           guard [--max-delete N] [--max-write-mb M] [--poll-ms P] [--auto-rollback] -- <CMD...>\n\
                                                 Run agent in isolated process group with instant fuse\n\
           hook <zsh|claude>                     Print opt-in hook snippet to stdout (never edits files)\n\
           hook uninstall [--apply] [--home DIR] Dry-run scan (or remove with backup) afuse hook blocks\n\
           validate [<DIR>]                      Validate safe APFS project root binding\n\
           locate [--ino <N>]                    Locate moved/trashed target by APFS inode\n\
           relocate --from <P1> --to <P2> [--ino <N>]\n\
                                                 Atomically migrate vault history after move/rename\n\
           purge-trash                           Purge stale restored copies remaining in Trash\n\
           doctor [--json] [<DIR>]               Print privacy-safe APFS & vault diagnostics\n\
           prune --keep <N> [--label-prefix P]   Reclaim snapshots & stale incomplete directories\n\
           prune --orphans [--min-age-days D] [--dry-run]\n\
                                                 Scan or reclaim orphan vaults whose target is gone\n\
           upgrade [--check]                     On-demand release check or self-upgrade CLI binary\n",
        VERSION
    );
}

fn cmd_purge_trash(workspace: &Path, rest: &[String], mut json: bool) {
    let mut want_help = false;
    for arg in rest {
        match arg.as_str() {
            "--json" => json = true,
            "--help" | "-h" => want_help = true,
            flag => emit_error(json, &AfuseError::new(22, format!("unknown purge-trash option '{}'", sanitize_terminal_text(flag)))),
        }
    }
    if want_help {
        let usage = "USAGE: afuse [-w | --workspace <DIR>] [--json] purge-trash";
        if json {
            println!("{{\"ok\":true,\"usage\":\"{}\"}}", json_escape(usage));
        } else {
            println!("{}", usage);
        }
        return;
    }
    match agent_fuse::purge_workspace_trash_with_vault(workspace, None) {
        Ok(st) => {
            if json {
                println!("{{\"ok\":true,\"trash_cleanup\":\"{}\"}}", st.as_str());
            } else {
                println!("TRASH_CLEANUP {}", st.as_str());
            }
        }
        Err(e) => emit_error(json, &e),
    }
}

fn cmd_locate(workspace: &Path, rest: &[String], mut json: bool) {
    let mut hint_ino: Option<u64> = None;
    let mut i = 0usize;
    while i < rest.len() {
        match rest[i].as_str() {
            "--json" => { json = true; i += 1; }
            "--help" | "-h" => {
                let u = "USAGE: afuse [-w | --workspace <DIR>] [--json] locate [--ino <N>]";
                if json { println!("{{\"ok\":true,\"usage\":\"{}\"}}", json_escape(u)); } else { println!("{}", u); }
                return;
            }
            "--ino" => {
                if i + 1 >= rest.len() { emit_error(json, &AfuseError::new(22, "--ino requires an integer")); }
                match rest[i + 1].parse::<u64>() {
                    Ok(v) => hint_ino = Some(v),
                    Err(_) => emit_error(json, &AfuseError::new(22, "invalid --ino integer")),
                }
                i += 2;
            }
            other => emit_error(json, &AfuseError::new(22, format!("unknown locate option '{}'", sanitize_terminal_text(other)))),
        }
    }
    match agent_fuse::locate_workspace_target_with_vault(workspace, None, hint_ino) {
        Ok(out) => {
            if json {
                println!("{}", out.to_json());
            } else {
                match &out {
                    agent_fuse::LocateOutcome::MovedValid { new_path, ino, kind } => println!(
                        "MOVED_VALID {} (kind={} ino={})",
                        sanitize_terminal_text(&new_path.to_string_lossy()),
                        kind.as_str(),
                        ino
                    ),
                    agent_fuse::LocateOutcome::MovedBlocked { new_path, reason } => println!(
                        "MOVED_BLOCKED {} ({})",
                        sanitize_terminal_text(&new_path.to_string_lossy()),
                        sanitize_terminal_text(reason)
                    ),
                    agent_fuse::LocateOutcome::Trashed { path } => println!(
                        "TRASHED {}",
                        sanitize_terminal_text(&path.to_string_lossy())
                    ),
                    agent_fuse::LocateOutcome::MissingOrTcc { errno } => {
                        println!("MISSING_OR_TCC (errno={})", errno)
                    }
                }
            }
        }
        Err(e) => emit_error(json, &e),
    }
}

fn cmd_relocate(rest: &[String], mut json: bool) {
    let mut from_p: Option<PathBuf> = None;
    let mut to_p: Option<PathBuf> = None;
    let mut exp_ino: Option<u64> = None;
    let mut i = 0usize;
    while i < rest.len() {
        match rest[i].as_str() {
            "--json" => { json = true; i += 1; }
            "--help" | "-h" => {
                let u = "USAGE: afuse [--json] relocate --from <OLD_PATH> --to <NEW_PATH> [--ino <N>]";
                if json { println!("{{\"ok\":true,\"usage\":\"{}\"}}", json_escape(u)); } else { println!("{}", u); }
                return;
            }
            "--from" => {
                if i + 1 >= rest.len() { emit_error(json, &AfuseError::new(22, "--from requires a path")); }
                from_p = Some(PathBuf::from(&rest[i + 1]));
                i += 2;
            }
            "--to" => {
                if i + 1 >= rest.len() { emit_error(json, &AfuseError::new(22, "--to requires a path")); }
                to_p = Some(PathBuf::from(&rest[i + 1]));
                i += 2;
            }
            "--ino" => {
                if i + 1 >= rest.len() { emit_error(json, &AfuseError::new(22, "--ino requires an integer")); }
                match rest[i + 1].parse::<u64>() {
                    Ok(v) => exp_ino = Some(v),
                    Err(_) => emit_error(json, &AfuseError::new(22, "invalid --ino integer")),
                }
                i += 2;
            }
            other => emit_error(json, &AfuseError::new(22, format!("unknown relocate option '{}'", sanitize_terminal_text(other)))),
        }
    }
    let (Some(from_path), Some(to_path)) = (from_p, to_p) else {
        emit_error(json, &AfuseError::new(22, "relocate requires --from <OLD_PATH> and --to <NEW_PATH>"));
    };
    match agent_fuse::relocate_workspace_vault_with(&from_path, &to_path, None, exp_ino) {
        Ok(rep) => {
            if json {
                println!(
                    "{{\"ok\":true,\"from\":\"{}\",\"to\":\"{}\",\"kind\":\"{}\",\"dev\":{},\"ino\":{},\"snapshots_updated\":{}}}",
                    json_escape(&rep.from.to_string_lossy()),
                    json_escape(&rep.to.to_string_lossy()),
                    rep.kind.as_str(), rep.dev, rep.ino, rep.snapshots_updated
                );
            } else {
                println!(
                    "RELOCATED {} -> {} (snapshots_updated={})",
                    sanitize_terminal_text(&rep.from.to_string_lossy()),
                    sanitize_terminal_text(&rep.to.to_string_lossy()),
                    rep.snapshots_updated
                );
            }
        }
        Err(e) => emit_error(json, &e),
    }
}

fn cmd_prune_orphans(rest: &[String], mut json: bool) {
    let mut min_age_days = 7u64;
    let mut dry_run = false;
    let mut i = 0usize;
    while i < rest.len() {
        match rest[i].as_str() {
            "--orphans" => i += 1,
            "--dry-run" => { dry_run = true; i += 1; }
            "--json" => { json = true; i += 1; }
            "--min-age-days" => {
                if i + 1 >= rest.len() { emit_error(json, &AfuseError::new(22, "--min-age-days requires an integer")); }
                match rest[i + 1].parse::<u64>() {
                    Ok(v) => min_age_days = v,
                    Err(_) => emit_error(json, &AfuseError::new(22, "invalid --min-age-days integer")),
                }
                i += 2;
            }
            "--help" | "-h" => {
                let u = "USAGE: afuse [--json] prune --orphans [--min-age-days <D>] [--dry-run]";
                if json { println!("{{\"ok\":true,\"usage\":\"{}\"}}", json_escape(u)); } else { println!("{}", u); }
                return;
            }
            other => emit_error(json, &AfuseError::new(22, format!("unknown prune --orphans option '{}'", sanitize_terminal_text(other)))),
        }
    }
    match agent_fuse::prune_orphan_vaults_with(None, min_age_days, dry_run) {
        Ok(rep) => {
            if json {
                let cands: Vec<String> = rep.candidates.iter().map(|s| format!("\"{}\"", json_escape(s))).collect();
                println!(
                    "{{\"ok\":true,\"scanned\":{},\"candidates\":[{}],\"removed\":{},\"dry_run\":{}}}",
                    rep.scanned, cands.join(","), rep.removed, rep.dry_run
                );
            } else {
                println!("Orphan vaults scanned={} candidates={} removed={} dry_run={}", rep.scanned, rep.candidates.len(), rep.removed, rep.dry_run);
            }
        }
        Err(e) => emit_error(json, &e),
    }
}

pub(crate) fn emit_error(json: bool, err: &AfuseError) -> ! {
    if json {
        println!(
            "{{\"ok\":false,\"error_code\":{},\"error\":\"{}\"}}",
            err.code,
            json_escape(&err.message)
        );
    } else {
        eprintln!(
            "afuse error (code {}): {}",
            err.code,
            sanitize_terminal_text(&err.message)
        );
    }
    process::exit(if (1..=125).contains(&err.code) { err.code } else { 1 });
}

fn main() {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    if raw_args.is_empty() {
        print_usage();
        process::exit(2);
    }

    let mut workspace = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut explicit_workspace = false;
    let mut json = false;
    let mut idx = 0usize;

    while idx < raw_args.len() {
        match raw_args[idx].as_str() {
            "--json" => {
                json = true;
                idx += 1;
            }
            "--workspace" | "-w" | "-C" => {
                if idx + 1 >= raw_args.len() {
                    emit_error(json, &AfuseError::new(22, "--workspace requires a path"));
                }
                workspace = PathBuf::from(&raw_args[idx + 1]);
                explicit_workspace = true;
                idx += 2;
            }
            "--help" | "-h" => {
                if json {
                    println!("{{\"ok\":true,\"version\":\"{}\",\"usage\":\"afuse [-w | --workspace <DIR>] [--json] <SUBCOMMAND> [OPTIONS]\"}}", VERSION);
                } else {
                    print_usage();
                }
                return;
            }
            "--version" | "-V" => {
                if json {
                    println!("{{\"ok\":true,\"version\":\"{}\"}}", VERSION);
                } else {
                    println!("afuse {}", VERSION);
                }
                return;
            }
            _ => break,
        }
    }

    if idx >= raw_args.len() {
        if json {
            emit_error(true, &AfuseError::new(2, "missing subcommand"));
        }
        print_usage();
        process::exit(2);
    }

    let sub = raw_args[idx].as_str();
    let raw_rest = &raw_args[idx + 1..];
    let allow_post_global = sub != "guard" && !(sub == "hook" && raw_rest.iter().any(|a| a == "--exec"));
    let mut rest_owned: Vec<String> = Vec::with_capacity(raw_rest.len());
    let mut r_idx = 0usize;
    while r_idx < raw_rest.len() {
        let tok = raw_rest[r_idx].as_str();
        if tok == "--" {
            rest_owned.extend_from_slice(&raw_rest[r_idx..]);
            break;
        }
        if matches!(
            tok,
            "-m" | "--label" | "--label-prefix" | "--keep" | "--min-age-days"
                | "--from" | "--to" | "--ino" | "--home" | "--cwd" | "--tool"
                | "--max-delete" | "--max-write-mb" | "--poll-ms"
        ) {
            rest_owned.push(raw_rest[r_idx].clone());
            if r_idx + 1 < raw_rest.len() {
                rest_owned.push(raw_rest[r_idx + 1].clone());
                r_idx += 2;
            } else {
                r_idx += 1;
            }
            continue;
        }
        if allow_post_global && (tok == "--workspace" || tok == "-w" || tok == "-C") {
            if r_idx + 1 >= raw_rest.len() {
                emit_error(json, &AfuseError::new(22, "-w/--workspace requires a path"));
            }
            workspace = PathBuf::from(&raw_rest[r_idx + 1]);
            explicit_workspace = true;
            r_idx += 2;
            continue;
        }
        if allow_post_global && tok == "--json" {
            json = true;
            r_idx += 1;
            continue;
        }
        rest_owned.push(raw_rest[r_idx].clone());
        r_idx += 1;
    }
    let rest = &rest_owned;

    match sub {
        "snap" => cli_cmds::cmd_snap(&workspace, rest, json),
        "validate" => cli_cmds::cmd_validate(&workspace, rest, json),
        "locate" => cmd_locate(&workspace, rest, json),
        "relocate" => cmd_relocate(rest, json),
        "purge-trash" => cmd_purge_trash(&workspace, rest, json),
        "list" => cli_cmds::cmd_list(&workspace, rest, json),
        "diff" => cli_cmds::cmd_diff(&workspace, rest, json),
        "restore" => cli_cmds::cmd_restore(&workspace, rest, json),
        "prune" if rest.iter().any(|a| a == "--orphans") => cmd_prune_orphans(rest, json),
        "prune" => cli_cmds::cmd_prune(&workspace, rest, json),
        "hook" => cli_ops::cmd_hook(workspace, rest, json),
        "guard" => cli_ops::cmd_guard(&workspace, rest, json),
        "doctor" => cli_ops::cmd_doctor(&workspace, explicit_workspace, rest, json),
        "upgrade" => cli_upgrade::cmd_upgrade(rest, json),
        other => emit_error(
            json,
            &AfuseError::new(2, format!("unknown subcommand '{}'", sanitize_terminal_text(other))),
        ),
    }
}
