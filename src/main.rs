mod cli_ops;

use agent_fuse::{
    create_snapshot, create_snapshot_fast, create_snapshot_if_changed, diff_snapshot, json_escape,
    list_snapshots, parse_prune_args, prune_snapshots_filtered, restore_snapshot,
    restore_snapshot_paths, short_hash, validate_workspace_binding, AfuseError, RestoreReport,
};
use std::env;
use std::path::PathBuf;
use std::process;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    eprintln!(
        "afuse {} — Millisecond-scale APFS CoW workspace time machine & runaway agent circuit breaker\n\
         \n\
         USAGE:\n\
           afuse [--workspace <DIR>] [--json] <SUBCOMMAND> [OPTIONS]\n\
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

fn print_restore_report(r: &RestoreReport, json: bool) {
    if json {
        let sb = r
            .safety_snapshot_id
            .as_ref()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .unwrap_or_else(|| "null".to_string());
        let tail = if r.selective {
            format!(",\"selective\":true,\"restored_paths\":{}", r.restored_paths)
        } else {
            String::new()
        };
        println!(
            "{{\"ok\":true,\"snapshot_id\":\"{}\",\"safety_snapshot_id\":{},\"root_inode_before\":{},\"root_inode_after\":{},\"restored_files\":{},\"tree_sha256\":\"{}\",\"elapsed_us\":{}{}}}",
            json_escape(&r.snapshot_id),
            sb,
            r.root_inode_before,
            r.root_inode_after,
            r.restored_files,
            json_escape(&r.tree_sha256),
            r.elapsed_us,
            tail
        );
    } else if r.selective {
        println!(
            "RESTORED {} path(s) from {} in {:.3} ms | root_inode={} (PRESERVED) | receipt={}",
            r.restored_paths,
            r.snapshot_id,
            r.elapsed_us as f64 / 1000.0,
            r.root_inode_after,
            short_hash(&r.tree_sha256, 16)
        );
    } else {
        println!(
            "RESTORED {} in {:.3} ms | files={} | root_inode={} (PRESERVED) | receipt={}",
            r.snapshot_id,
            r.elapsed_us as f64 / 1000.0,
            r.restored_files,
            r.root_inode_after,
            short_hash(&r.tree_sha256, 16)
        );
    }
}

fn main() {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    if raw_args.is_empty() {
        print_usage();
        process::exit(2);
    }

    let mut workspace = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut json = false;
    let mut idx = 0usize;

    while idx < raw_args.len() {
        match raw_args[idx].as_str() {
            "--json" => {
                json = true;
                idx += 1;
            }
            "--workspace" | "-C" => {
                if idx + 1 >= raw_args.len() {
                    emit_error(json, &AfuseError::new(22, "--workspace requires a path"));
                }
                workspace = PathBuf::from(&raw_args[idx + 1]);
                idx += 2;
            }
            "--help" | "-h" => {
                print_usage();
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
    let rest = &raw_args[idx + 1..];

    match sub {
        "snap" => {
            let mut label = String::from("manual");
            let mut if_changed = false;
            let mut fast = false;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "-m" | "--label" => {
                        if i + 1 >= rest.len() {
                            emit_error(json, &AfuseError::new(22, "-m requires a label"));
                        }
                        label = rest[i + 1].clone();
                        i += 2;
                    }
                    "--if-changed" | "--dedup" => {
                        if_changed = true;
                        i += 1;
                    }
                    "--fast" => {
                        fast = true;
                        i += 1;
                    }
                    "--json" => {
                        json = true;
                        i += 1;
                    }
                    other => {
                        label = other.to_string();
                        i += 1;
                    }
                }
            }
            let res = if if_changed {
                create_snapshot_if_changed(&workspace, &label)
            } else if fast {
                create_snapshot_fast(&workspace, &label).map(|m| (m, false))
            } else {
                create_snapshot(&workspace, &label).map(|m| (m, false))
            };
            match res {
                Ok((m, dedup)) => {
                    if json {
                        println!(
                            "{{\"ok\":true,\"id\":\"{}\",\"label\":\"{}\",\"deduplicated\":{},\"created_ms\":{},\"root_inode\":{},\"file_count\":{},\"logical_bytes\":{},\"tree_sha256\":\"{}\",\"elapsed_us\":{}}}",
                            json_escape(&m.id), json_escape(&m.label), dedup, m.created_ms,
                            m.root_inode, m.file_count, m.logical_bytes, json_escape(&m.tree_sha256), m.elapsed_us
                        );
                    } else if dedup {
                        println!(
                            "SNAP {} (UNCHANGED · deduplicated) | files={} | sha256={}..",
                            m.id, m.file_count, short_hash(&m.tree_sha256, 12)
                        );
                    } else {
                        println!(
                            "SNAP {} | {:.3} ms | files={} | sha256={}.. | label={}",
                            m.id, m.elapsed_us as f64 / 1000.0, m.file_count, short_hash(&m.tree_sha256, 12), m.label
                        );
                    }
                }
                Err(e) => emit_error(json, &e),
            }
        }
        "validate" => {
            let mut candidate = workspace.clone();
            for a in rest {
                if a == "--json" {
                    json = true;
                } else {
                    candidate = PathBuf::from(a);
                }
            }
            match validate_workspace_binding(&candidate) {
                Ok(v) => {
                    if json {
                        println!(
                            "{{\"ok\":true,\"path\":\"{}\",\"dev\":{},\"ino\":{},\"marker\":\"{}\"}}",
                            json_escape(&v.canonical_path.to_string_lossy()), v.dev, v.ino, json_escape(&v.marker)
                        );
                    } else {
                        println!(
                            "VALID {} (dev={} ino={} marker={})",
                            v.canonical_path.display(), v.dev, v.ino, v.marker
                        );
                    }
                }
                Err(e) => emit_error(json, &e),
            }
        }
        "list" => {
            if rest.iter().any(|a| a == "--json") {
                json = true;
            }
            match list_snapshots(&workspace) {
                Ok(list) => {
                    if json {
                        let items: Vec<String> = list
                            .iter()
                            .map(|m| {
                                format!(
                                    "{{\"id\":\"{}\",\"label\":\"{}\",\"created_ms\":{},\"file_count\":{},\"logical_bytes\":{},\"tree_sha256\":\"{}\",\"elapsed_us\":{}}}",
                                    json_escape(&m.id), json_escape(&m.label), m.created_ms,
                                    m.file_count, m.logical_bytes, json_escape(&m.tree_sha256), m.elapsed_us
                                )
                            })
                            .collect();
                        println!("{{\"ok\":true,\"snapshots\":[{}]}}", items.join(","));
                    } else if list.is_empty() {
                        println!("No snapshots found for {}", workspace.display());
                    } else {
                        for m in list {
                            println!(
                                "{}  files={:<5}  clone={:>6}us  sha256={:<12}  [{}]",
                                m.id, m.file_count, m.elapsed_us, short_hash(&m.tree_sha256, 12), m.label
                            );
                        }
                    }
                }
                Err(e) => emit_error(json, &e),
            }
        }
        "diff" => {
            let mut target = "latest".to_string();
            for a in rest {
                if a == "--json" {
                    json = true;
                } else {
                    target = a.clone();
                }
            }
            match diff_snapshot(&workspace, &target) {
                Ok(d) => {
                    if json {
                        let fmt_vec = |v: &[String]| -> String {
                            v.iter().map(|x| format!("\"{}\"", json_escape(x))).collect::<Vec<_>>().join(",")
                        };
                        println!(
                            "{{\"ok\":true,\"snapshot_id\":\"{}\",\"added\":[{}],\"modified\":[{}],\"deleted\":[{}]}}",
                            json_escape(&d.snapshot_id), fmt_vec(&d.added), fmt_vec(&d.modified), fmt_vec(&d.deleted)
                        );
                    } else {
                        println!(
                            "DIFF against {} -> +{} added, ~{} modified, -{} deleted",
                            d.snapshot_id, d.added.len(), d.modified.len(), d.deleted.len()
                        );
                        for p in d.added {
                            println!("  + {}", p);
                        }
                        for p in d.modified {
                            println!("  ~ {}", p);
                        }
                        for p in d.deleted {
                            println!("  - {}", p);
                        }
                    }
                }
                Err(e) => emit_error(json, &e),
            }
        }
        "restore" => {
            let mut target = "latest".to_string();
            let mut safety_backup = true;
            let mut rel_paths: Vec<String> = Vec::new();
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--" => {
                        rel_paths.extend(rest[i + 1..].iter().cloned());
                        break;
                    }
                    "--no-backup" => safety_backup = false,
                    "--json" => json = true,
                    other => target = other.to_string(),
                }
                i += 1;
            }
            let res = if rel_paths.is_empty() {
                restore_snapshot(&workspace, &target, safety_backup)
            } else {
                restore_snapshot_paths(&workspace, &target, safety_backup, &rel_paths)
            };
            match res {
                Ok(r) => print_restore_report(&r, json),
                Err(e) => emit_error(json, &e),
            }
        }
        "prune" => {
            if rest.iter().any(|a| a == "--json") {
                json = true;
            }
            let (keep, label_prefix, parsed_json) = match parse_prune_args(rest) {
                Ok(v) => v,
                Err(e) => emit_error(json, &e),
            };
            if parsed_json {
                json = true;
            }
            match prune_snapshots_filtered(&workspace, keep, label_prefix.as_deref()) {
                Ok(removed) => {
                    if json {
                        let pfx = label_prefix
                            .as_ref()
                            .map(|s| format!("\"{}\"", json_escape(s)))
                            .unwrap_or_else(|| "null".to_string());
                        println!("{{\"ok\":true,\"removed\":{},\"kept\":{},\"label_prefix\":{}}}", removed, keep, pfx);
                    } else {
                        println!("Pruned {} snapshot(s) (kept={})", removed, keep);
                    }
                }
                Err(e) => emit_error(json, &e),
            }
        }
        "hook" => cli_ops::cmd_hook(workspace, rest, json),
        "guard" => cli_ops::cmd_guard(&workspace, rest, json),
        "doctor" => cli_ops::cmd_doctor(&workspace, rest, json),
        "upgrade" => cli_ops::cmd_upgrade(rest, json),
        other => emit_error(json, &AfuseError::new(2, format!("unknown subcommand '{}'", other))),
    }
}
