use agent_fuse::{
    create_snapshot, create_snapshot_fast_dedup, create_snapshot_if_changed, diff_snapshot,
    json_escape, list_snapshots, parse_prune_args, prune_snapshots_filtered, restore_snapshot,
    restore_snapshot_paths, sanitize_terminal_text, short_hash, validate_workspace_binding,
    AfuseError, RestoreReport,
};
use std::path::{Path, PathBuf};
use std::process;

fn subcmd_usage(sub: &str) -> &'static str {
    match sub {
        "snap" => "USAGE: afuse [--workspace <DIR>] [--json] snap [-m <LABEL>] [--fast] [--if-changed]",
        "list" => "USAGE: afuse [--workspace <DIR>] [--json] list",
        "diff" => "USAGE: afuse [--workspace <DIR>] [--json] diff [<SNAP_ID|latest>]",
        "restore" => "USAGE: afuse [--workspace <DIR>] [--json] restore [<SNAP_ID|latest>] [--no-backup] [-- <REL_PATH>...]",
        "validate" => "USAGE: afuse [--json] validate [<DIR>]",
        "prune" => "USAGE: afuse [--workspace <DIR>] [--json] prune --keep <N> [--label-prefix <P>]",
        _ => "USAGE: afuse [--workspace <DIR>] [--json] <SUBCOMMAND> [OPTIONS]",
    }
}

fn handle_common_sub_flag(arg: &str, sub: &str, json: &mut bool) -> bool {
    match arg {
        "--help" | "-h" => {
            println!("{}", subcmd_usage(sub));
            process::exit(0);
        }
        "--json" => {
            *json = true;
            true
        }
        _ => false,
    }
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
            "{{\"ok\":true,\"snapshot_id\":\"{}\",\"safety_snapshot_id\":{},\"root_inode_before\":{},\"root_inode_after\":{},\"restored_files\":{},\"project_files\":{},\"tree_sha256\":\"{}\",\"elapsed_us\":{},\"trash_cleanup\":\"{}\"{}}}",
            json_escape(&r.snapshot_id), sb, r.root_inode_before, r.root_inode_after,
            r.restored_files, r.project_files, json_escape(&r.tree_sha256), r.elapsed_us, r.trash_cleanup.as_str(), tail
        );
    } else {
        let ino_tag = if r.root_inode_before != 0 && r.root_inode_before == r.root_inode_after {
            "PRESERVED"
        } else {
            "RECREATED"
        };
        if r.selective {
            println!(
                "RESTORED {} path(s) from {} in {:.3} ms | root_inode={} ({}) | receipt={}",
                r.restored_paths,
                sanitize_terminal_text(&r.snapshot_id),
                r.elapsed_us as f64 / 1000.0,
                r.root_inode_after,
                ino_tag,
                short_hash(&r.tree_sha256, 16)
            );
        } else {
            println!(
                "RESTORED {} in {:.3} ms | files={} | root_inode={} ({}) | receipt={}",
                sanitize_terminal_text(&r.snapshot_id),
                r.elapsed_us as f64 / 1000.0,
                r.restored_files,
                r.root_inode_after,
                ino_tag,
                short_hash(&r.tree_sha256, 16)
            );
        }
    }
}

pub(crate) fn cmd_snap(workspace: &Path, rest: &[String], mut json: bool) {
    let mut label = String::from("manual");
    let mut has_label = false;
    let mut if_changed = false;
    let mut fast = false;
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        if handle_common_sub_flag(a, "snap", &mut json) {
            i += 1;
            continue;
        }
        match a {
            "-m" | "--label" => {
                if i + 1 >= rest.len() {
                    crate::emit_error(json, &AfuseError::new(22, "-m requires a label"));
                }
                label = rest[i + 1].clone();
                has_label = true;
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
            flag if flag.starts_with('-') => {
                crate::emit_error(json, &AfuseError::new(22, "unknown snap option"));
            }
            other => {
                if has_label {
                    crate::emit_error(json, &AfuseError::new(22, "snap accepts at most one label"));
                }
                label = other.to_string();
                has_label = true;
                i += 1;
            }
        }
    }
    let res = if if_changed {
        create_snapshot_if_changed(workspace, &label)
    } else if fast {
        create_snapshot_fast_dedup(workspace, &label)
    } else {
        create_snapshot(workspace, &label).map(|m| (m, false))
    };
    match res {
        Ok((m, dedup)) => {
            if json {
                println!(
                    "{{\"ok\":true,\"id\":\"{}\",\"label\":\"{}\",\"deduplicated\":{},\"created_ms\":{},\"root_inode\":{},\"file_count\":{},\"project_files\":{},\"logical_bytes\":{},\"tree_sha256\":\"{}\",\"elapsed_us\":{}}}",
                    json_escape(&m.id), json_escape(&m.label), dedup, m.created_ms,
                    m.root_inode, m.file_count, m.project_files, m.logical_bytes, json_escape(&m.tree_sha256), m.elapsed_us
                );
            } else if dedup {
                println!(
                    "SNAP {} (UNCHANGED · deduplicated) | files={} | sha256={}..",
                    sanitize_terminal_text(&m.id), m.file_count, short_hash(&m.tree_sha256, 12)
                );
            } else {
                println!(
                    "SNAP {} | {:.3} ms | files={} | sha256={}.. | label={}",
                    sanitize_terminal_text(&m.id), m.elapsed_us as f64 / 1000.0,
                    m.file_count, short_hash(&m.tree_sha256, 12), sanitize_terminal_text(&m.label)
                );
            }
        }
        Err(e) => crate::emit_error(json, &e),
    }
}

pub(crate) fn cmd_validate(workspace: &Path, rest: &[String], mut json: bool) {
    let mut candidate: Option<PathBuf> = None;
    let mut end_of_opts = false;
    for a in rest {
        if !end_of_opts && a == "--" {
            end_of_opts = true;
            continue;
        }
        if !end_of_opts && handle_common_sub_flag(a, "validate", &mut json) {
            continue;
        }
        if !end_of_opts && a.starts_with('-') {
            crate::emit_error(json, &AfuseError::new(22, "unknown validate option"));
        }
        if candidate.is_some() {
            crate::emit_error(json, &AfuseError::new(22, "validate accepts at most one [<DIR>]"));
        }
        candidate = Some(PathBuf::from(a));
    }
    match validate_workspace_binding(candidate.as_deref().unwrap_or(workspace)) {
        Ok(v) => {
            if json {
                println!(
                    "{{\"ok\":true,\"path\":\"{}\",\"dev\":{},\"ino\":{},\"kind\":\"{}\",\"marker\":\"{}\"}}",
                    json_escape(&v.canonical_path.to_string_lossy()), v.dev, v.ino, v.kind.as_str(), json_escape(&v.marker)
                );
            } else {
                println!(
                    "VALID {} (dev={} ino={} kind={} marker={})",
                    sanitize_terminal_text(&v.canonical_path.to_string_lossy()),
                    v.dev, v.ino, v.kind.as_str(), v.marker
                );
            }
        }
        Err(e) => crate::emit_error(json, &e),
    }
}

pub(crate) fn cmd_list(workspace: &Path, rest: &[String], mut json: bool) {
    for a in rest {
        if handle_common_sub_flag(a, "list", &mut json) {
            continue;
        }
        crate::emit_error(json, &AfuseError::new(22, "unknown list option or argument"));
    }
    match list_snapshots(workspace) {
        Ok(list) => {
            if json {
                let items: Vec<String> = list
                    .iter()
                    .map(|m| {
                        format!(
                            "{{\"id\":\"{}\",\"label\":\"{}\",\"created_ms\":{},\"file_count\":{},\"project_files\":{},\"logical_bytes\":{},\"tree_sha256\":\"{}\",\"elapsed_us\":{}}}",
                            json_escape(&m.id), json_escape(&m.label), m.created_ms,
                            m.file_count, m.project_files, m.logical_bytes, json_escape(&m.tree_sha256), m.elapsed_us
                        )
                    })
                    .collect();
                println!("{{\"ok\":true,\"snapshots\":[{}]}}", items.join(","));
            } else if list.is_empty() {
                println!("No snapshots found for {}", sanitize_terminal_text(&workspace.to_string_lossy()));
            } else {
                for m in list {
                    println!(
                        "{}  files={:<5}  clone={:>6}us  sha256={:<12}  [{}]",
                        sanitize_terminal_text(&m.id), m.file_count, m.elapsed_us,
                        short_hash(&m.tree_sha256, 12), sanitize_terminal_text(&m.label)
                    );
                }
            }
        }
        Err(e) => crate::emit_error(json, &e),
    }
}

pub(crate) fn cmd_diff(workspace: &Path, rest: &[String], mut json: bool) {
    let mut target: Option<String> = None;
    let mut end_of_opts = false;
    for a in rest {
        if !end_of_opts && a == "--" {
            end_of_opts = true;
            continue;
        }
        if !end_of_opts && handle_common_sub_flag(a, "diff", &mut json) {
            continue;
        }
        if !end_of_opts && a.starts_with('-') {
            crate::emit_error(json, &AfuseError::new(22, "unknown diff option"));
        }
        if target.is_some() {
            crate::emit_error(json, &AfuseError::new(22, "diff accepts at most one snapshot target"));
        }
        target = Some(a.clone());
    }
    match diff_snapshot(workspace, target.as_deref().unwrap_or("latest")) {
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
                    sanitize_terminal_text(&d.snapshot_id), d.added.len(), d.modified.len(), d.deleted.len()
                );
                for p in d.added {
                    println!("  + {}", sanitize_terminal_text(&p));
                }
                for p in d.modified {
                    println!("  ~ {}", sanitize_terminal_text(&p));
                }
                for p in d.deleted {
                    println!("  - {}", sanitize_terminal_text(&p));
                }
            }
        }
        Err(e) => crate::emit_error(json, &e),
    }
}

pub(crate) fn cmd_restore(workspace: &Path, rest: &[String], mut json: bool) {
    let mut target: Option<String> = None;
    let mut safety_backup = true;
    let mut rel_paths: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < rest.len() {
        let a = rest[i].as_str();
        if a == "--" {
            rel_paths.extend(rest[i + 1..].iter().cloned());
            break;
        }
        if handle_common_sub_flag(a, "restore", &mut json) {
            i += 1;
            continue;
        }
        match a {
            "--no-backup" => safety_backup = false,
            flag if flag.starts_with('-') => {
                crate::emit_error(json, &AfuseError::new(22, "unknown restore option"));
            }
            other => {
                if target.is_some() {
                    crate::emit_error(json, &AfuseError::new(22, "restore accepts one snapshot target before '--'"));
                }
                target = Some(other.to_string());
            }
        }
        i += 1;
    }
    let t = target.as_deref().unwrap_or("latest");
    let res = if rel_paths.is_empty() {
        restore_snapshot(workspace, t, safety_backup)
    } else {
        restore_snapshot_paths(workspace, t, safety_backup, &rel_paths)
    };
    match res {
        Ok(r) => print_restore_report(&r, json),
        Err(e) => crate::emit_error(json, &e),
    }
}

pub(crate) fn cmd_prune(workspace: &Path, rest: &[String], mut json: bool) {
    for a in rest {
        if handle_common_sub_flag(a, "prune", &mut json) {
            continue;
        }
    }
    let (keep, label_prefix, parsed_json) = match parse_prune_args(rest) {
        Ok(v) => v,
        Err(e) => crate::emit_error(json, &e),
    };
    if parsed_json {
        json = true;
    }
    match prune_snapshots_filtered(workspace, keep, label_prefix.as_deref()) {
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
        Err(e) => crate::emit_error(json, &e),
    }
}
