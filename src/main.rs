mod cli_cmds;
mod cli_ops;
mod cli_upgrade;

use agent_fuse::{json_escape, sanitize_terminal_text, AfuseError};
use std::env;
use std::path::PathBuf;
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
           snap [-m <LABEL>] [--fast] [--if-changed]\n\
                                                 Take an APFS CoW workspace snapshot (0 B at t=0)\n\
           list                                  List timeline snapshots (newest first)\n\
           diff [<SNAP_ID|latest>]               Compare dirty workspace against snapshot\n\
           restore [<SNAP_ID|latest>] [--no-backup] [-- <REL_PATH>...]\n\
                                                 Atomically restore workspace (or selected paths) preserving root Inode\n\
           guard [--max-delete N] [--max-write-mb M] [--auto-rollback] -- <CMD...>\n\
                                                 Run agent in isolated process group with instant fuse\n\
           hook <zsh|claude>                     Print opt-in hook snippet to stdout (never edits files)\n\
           hook uninstall [--apply]              Dry-run scan (or remove with backup) afuse hook blocks\n\
           validate [<DIR>]                      Validate safe APFS project root binding\n\
           doctor [--json] [<DIR>]               Print privacy-safe APFS & vault diagnostics\n\
           prune --keep <N> [--label-prefix P]   Reclaim snapshots & stale incomplete directories\n\
           upgrade [--check]                     On-demand release check or self-upgrade CLI binary\n",
        VERSION
    );
}

pub(crate) fn emit_error(json: bool, err: &AfuseError) -> ! {
    if json {
        println!(
            "{{\"ok\":false,\"error_code\":{},\"error\":\"{}\"}}",
            err.code,
            json_escape(&err.message)
        );
    } else {
        eprintln!("afuse error (code {}): {}", err.code, err.message);
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
        print_usage();
        process::exit(2);
    }

    let sub = raw_args[idx].as_str();
    let raw_rest = &raw_args[idx + 1..];
    let allow_post_global = !(sub == "hook" && raw_rest.iter().any(|a| a == "--exec"));
    let mut rest_owned: Vec<String> = Vec::with_capacity(raw_rest.len());
    let mut r_idx = 0usize;
    while r_idx < raw_rest.len() {
        let tok = raw_rest[r_idx].as_str();
        if tok == "--" {
            rest_owned.extend_from_slice(&raw_rest[r_idx..]);
            break;
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
        "list" => cli_cmds::cmd_list(&workspace, rest, json),
        "diff" => cli_cmds::cmd_diff(&workspace, rest, json),
        "restore" => cli_cmds::cmd_restore(&workspace, rest, json),
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
