use crate::emit_error;
use agent_fuse::{check_for_updates, json_escape, run_upgrade_apply, AfuseError};

pub(crate) fn cmd_upgrade(rest: &[String], mut json: bool) {
    let (mut check_only, mut want_help, mut end_opts) = (false, false, false);
    for arg in rest {
        if !end_opts && arg == "--" {
            end_opts = true;
            continue;
        }
        if !end_opts {
            match arg.as_str() {
                "--help" | "-h" => {
                    want_help = true;
                    continue;
                }
                "--check" => {
                    check_only = true;
                    continue;
                }
                "--json" => {
                    json = true;
                    continue;
                }
                _ => emit_error(json, &AfuseError::new(2, "unknown upgrade option")),
            }
        }
        emit_error(json, &AfuseError::new(2, "unexpected upgrade argument"));
    }
    if want_help {
        let usage = "USAGE: afuse [-w | --workspace <DIR>] [--json] upgrade [--check]";
        if json {
            println!("{{\"ok\":true,\"usage\":\"{}\"}}", json_escape(usage));
        } else {
            println!("{}", usage);
        }
        return;
    }
    if check_only {
        match check_for_updates() {
            Ok(rep) => {
                if json {
                    println!("{}", rep.to_json());
                } else if rep.release_state == "unpublished" {
                    println!(
                        "afuse v{} is installed; no GitHub Release has been published yet.",
                        rep.current_version
                    );
                } else if rep.update_available {
                    println!(
                        "Update available: v{} -> v{}\nRelease: {}\nHomebrew: {}",
                        rep.current_version, rep.latest_version, rep.release_url, rep.brew_cmd
                    );
                } else {
                    println!(
                        "afuse v{} is up to date (latest: v{}).",
                        rep.current_version, rep.latest_version
                    );
                }
            }
            Err(e) => emit_error(json, &e),
        }
    } else {
        match run_upgrade_apply() {
            Ok(rep) => {
                if json {
                    println!("{}", rep.to_json());
                } else if rep.release_state == "unpublished" {
                    println!(
                        "afuse v{} is installed; no GitHub Release has been published yet.",
                        rep.current_version
                    );
                } else if rep.updated {
                    println!(
                        "Upgraded afuse: v{} -> v{} (sha256={})",
                        rep.current_version,
                        rep.latest_version,
                        rep.verified_sha256.as_deref().unwrap_or("verified")
                    );
                } else {
                    println!(
                        "afuse v{} is already up to date (latest: v{}).",
                        rep.current_version, rep.latest_version
                    );
                }
            }
            Err(e) => emit_error(json, &e),
        }
    }
}
