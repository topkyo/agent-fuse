use crate::doctor::run_doctor_with_opts;
use crate::error::{ERR_EINVAL, EXIT_FUSE_TRIPPED};
use crate::guard::{run_guarded_command_with_vault, GuardConfig};
use crate::hook::{is_readonly_bash_command, run_claude_hook_exec_from_reader};
use crate::hook_config::{render_hook_snippet, uninstall_hooks};
use crate::snapshot::{create_snapshot_fast_dedup_with_vault, list_snapshots_with_vault};
use crate::tests::{ScopedDir, TestEnvGuard, ENV_LOCK};
use std::fs;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

#[test]
fn guard_single_file_swap_vault_kind_and_doctor_root_cwd() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
    let sb = ScopedDir::new("gh-sf-doc");
    let (ws_file, vault) = (sb.0.join("solo.txt"), sb.0.join("vault"));
    fs::write(&ws_file, b"important-single").unwrap();
    let _ = create_snapshot_fast_dedup_with_vault(&ws_file, Some(&vault), "sf").unwrap();

    let cfg = GuardConfig {
        max_delete: 20,
        max_write_mb: 16,
        poll_ms: 5,
        auto_rollback: true,
    };
    let rep = run_guarded_command_with_vault(
        &ws_file,
        Some(&vault),
        &cfg,
        &[
            "sh".into(),
            "-c".into(),
            "rm -f solo.txt && ln -s /nonexistent solo.txt".into(),
        ],
    )
    .unwrap();
    assert!(rep.tripped && rep.auto_restored && ws_file.is_file());

    fs::remove_file(&ws_file).unwrap();
    fs::create_dir_all(&ws_file).unwrap();
    let kind_err =
        create_snapshot_fast_dedup_with_vault(&ws_file, Some(&vault), "bad-kind").unwrap_err();
    assert_eq!(kind_err.code, ERR_EINVAL);

    let doc_sys = run_doctor_with_opts(Path::new("/"), Some(&vault), true).unwrap();
    assert!(doc_sys.ok && doc_sys.workspace_valid);
    let doc_explicit_root = run_doctor_with_opts(Path::new("/"), Some(&vault), false).unwrap();
    assert!(!doc_explicit_root.ok && !doc_explicit_root.workspace_valid);
}

#[test]
fn guard_allows_internal_mv_but_trips_on_mv_truncate_and_uppercase_ignored() {
    let sb = ScopedDir::new("gh-mv-bypass");
    let vault = sb.0.join("vault");
    let ws = sb.0.join("ws");
    let old_pkg = ws.join("old_pkg");
    fs::create_dir_all(&vault).unwrap();
    fs::create_dir_all(&old_pkg).unwrap();
    for i in 0..25 {
        fs::write(old_pkg.join(format!("f{:02}.rs", i)), "pub fn f() {}\n").unwrap();
    }
    let cfg = GuardConfig {
        max_delete: 20,
        max_write_mb: 4,
        poll_ms: 10,
        auto_rollback: true,
    };
    let rep_ok = run_guarded_command_with_vault(
        &ws,
        Some(&vault),
        &cfg,
        &["mv".into(), "old_pkg".into(), "new_pkg".into()],
    )
    .unwrap();
    assert!(!rep_ok.tripped && rep_ok.exit_code == 0);
    assert!(ws.join("new_pkg/f24.rs").is_file());

    // W-L1-15: mv && truncate on moved non-empty files must trip guard
    let cfg_strict = GuardConfig {
        max_delete: 1,
        max_write_mb: 16,
        poll_ms: 5,
        auto_rollback: true,
    };
    let rep_trunc = run_guarded_command_with_vault(
        &ws,
        Some(&vault),
        &cfg_strict,
        &[
            "sh".into(),
            "-c".into(),
            "mv new_pkg/f00.rs new_pkg/f00_moved.rs && : > new_pkg/f00_moved.rs".into(),
        ],
    )
    .unwrap();
    assert!(rep_trunc.tripped && rep_trunc.exit_code == EXIT_FUSE_TRIPPED);
    assert_eq!(fs::read_to_string(ws.join("new_pkg/f00.rs")).unwrap(), "pub fn f() {}\n");

    // W-L1-15: moving tracked file into uppercase NODE_MODULES must trip guard
    let rep_case = run_guarded_command_with_vault(
        &ws,
        Some(&vault),
        &cfg_strict,
        &[
            "sh".into(),
            "-c".into(),
            "mkdir -p NODE_MODULES && mv new_pkg/f01.rs NODE_MODULES/f01.rs".into(),
        ],
    )
    .unwrap();
    assert!(rep_case.tripped && rep_case.exit_code == EXIT_FUSE_TRIPPED);
    assert!(ws.join("new_pkg/f01.rs").is_file());
}

#[test]
fn guard_max_write_mb_trips_on_workspace_spike_and_ignores_external_writes() {
    let sb = ScopedDir::new("gh-write-mb");
    let vault = sb.0.join("vault");
    let ws = sb.0.join("ws");
    let external = sb.0.join("external");
    fs::create_dir_all(&vault).unwrap();
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&external).unwrap();
    fs::write(ws.join("keep.txt"), b"hello").unwrap();

    // 1. Real 2 MiB write inside workspace trips --max-write-mb 1 and rolls back
    let cfg = GuardConfig {
        max_delete: 50,
        max_write_mb: 1,
        poll_ms: 5,
        auto_rollback: true,
    };
    let rep_trip = run_guarded_command_with_vault(
        &ws,
        Some(&vault),
        &cfg,
        &[
            "sh".into(),
            "-c".into(),
            "dd if=/dev/zero of=spike.bin bs=1048576 count=2 2>/dev/null".into(),
        ],
    )
    .unwrap();
    assert!(rep_trip.tripped && rep_trip.exit_code == EXIT_FUSE_TRIPPED);
    assert!(!ws.join("spike.bin").exists());

    // 2. Concurrent write by an unrelated sibling process outside workspace must NOT falsely trip guard
    let ext_file = external.join("unrelated.bin");
    let ext_clone = ext_file.clone();
    let writer = std::thread::spawn(move || {
        let buf = vec![0xABu8; 2 * 1024 * 1024];
        let _ = fs::write(ext_clone, buf);
    });
    let rep_clean = run_guarded_command_with_vault(
        &ws,
        Some(&vault),
        &cfg,
        &["sh".into(), "-c".into(), "sleep 0.08 && echo ok > small.txt".into()],
    )
    .unwrap();
    writer.join().unwrap();
    assert!(
        !rep_clean.tripped && rep_clean.exit_code == 0,
        "external unrelated write must not trigger guard: {:?}",
        rep_clean
    );
    assert!(ws.join("small.txt").is_file());
}

#[test]
fn hook_uninstall_orphan_end_unclosed_begin_readonly_and_home_dedup() {
    let sb = ScopedDir::new("gh-hook-un");
    let ws = sb.0.join("ws");
    fs::create_dir_all(&ws).unwrap();

    let home1 = sb.0.join("home1");
    fs::create_dir_all(home1.join(".claude")).unwrap();
    let snippet = render_hook_snippet("zsh").unwrap();
    let zshrc1 = home1.join(".zshrc");
    let content1 = format!(
        "export TOP=1\n# >>> afuse hook v1 >>>\nexport USER_SECRET_ENV=\"KEEP\"\n{}eval \"$(afuse hook zsh)\"\n# <<< afuse hook v1 <<<\nexport BOT=1\n",
        snippet
    );
    fs::write(&zshrc1, content1).unwrap();

    let dry1 = uninstall_hooks(false, Some(&home1), &ws).unwrap();
    assert!(dry1.iter().any(|a| a.kind == "zsh_marker_block"));
    // Unclosed BEGIN + manual eval + orphan END = 3 manual_shell_line entries
    assert_eq!(dry1.iter().filter(|a| a.kind == "manual_shell_line").count(), 3);

    let app1 = uninstall_hooks(true, Some(&home1), &ws).unwrap();
    assert!(app1.iter().any(|a| a.kind == "zsh_marker_block" && a.applied));
    let after1 = fs::read_to_string(&zshrc1).unwrap();
    assert!(after1.contains("export USER_SECRET_ENV=\"KEEP\""));
    assert!(!after1.contains("_afuse_preexec"));

    // Read-only 0444 .zshrc leaves zero orphan backup files on apply failure
    let home2 = sb.0.join("home2");
    fs::create_dir_all(&home2).unwrap();
    let zshrc2 = home2.join(".zshrc");
    fs::write(&zshrc2, &snippet).unwrap();
    fs::set_permissions(&zshrc2, PermissionsExt::from_mode(0o444)).unwrap();
    assert!(uninstall_hooks(true, Some(&home2), &ws).is_err());
    let leftovers: Vec<_> = fs::read_dir(&home2)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("afuse-bak"))
        .collect();
    assert!(leftovers.is_empty());
    let _ = fs::set_permissions(&zshrc2, PermissionsExt::from_mode(0o644));

    // Workspace == home deduplicates ~/.claude/settings.json
    let home3 = sb.0.join("home3");
    fs::create_dir_all(home3.join(".claude")).unwrap();
    fs::write(home3.join(".claude/settings.json"), render_hook_snippet("claude").unwrap()).unwrap();
    let dedup_actions = uninstall_hooks(false, Some(&home3), &home3).unwrap();
    assert_eq!(
        dedup_actions
            .iter()
            .filter(|a| a.kind == "manual_claude_settings_json")
            .count(),
        1
    );
}

#[test]
fn hook_destructive_bash_quoted_paths_spaceless_redirect_and_zsh_quoted_cmd() {
    let sb = ScopedDir::new("gh-hook-bash");
    let vault = sb.0.join("vault");
    let ws = sb.0.join("repo with space");
    fs::create_dir_all(ws.join(".git")).unwrap();
    fs::create_dir_all(&vault).unwrap();
    fs::write(ws.join("app.rs"), "v1\n").unwrap();

    // W-L1-17: spaceless redirection and git restore must NOT be treated as readonly
    assert!(!is_readonly_bash_command("echo hi>app.rs"));
    assert!(!is_readonly_bash_command("cat a>>app.rs"));
    assert!(!is_readonly_bash_command("git restore app.rs"));

    // First edit takes throttled snap
    let edit_json = format!(
        "{{\"tool_name\":\"Edit\",\"cwd\":\"{}\",\"tool_input\":{{\"file_path\":\"{}\"}}}}",
        ws.display(),
        ws.join("app.rs").display()
    );
    assert!(run_claude_hook_exec_from_reader(Cursor::new(edit_json), Some(&vault)).is_some());
    fs::write(ws.join("app.rs"), "v2_unsaved\n").unwrap();

    // Destructive spaceless redirect inside quoted path bypasses 5s throttle (W-L1-17)
    let redir_json = format!(
        "{{\"tool_name\":\"Bash\",\"cwd\":\"{}\",\"tool_input\":{{\"command\":\">'{}'\"}}}}",
        sb.0.display(),
        ws.join("app.rs").display()
    );
    assert!(
        run_claude_hook_exec_from_reader(Cursor::new(redir_json), Some(&vault)).is_some(),
        "spaceless redirect on quoted space path must resolve repo and bypass throttle"
    );
    assert_eq!(list_snapshots_with_vault(&ws, Some(&vault)).unwrap().len(), 2);

    // W-L1-16: Zsh hook snippet includes $HOME/.cargo/bin/afuse and strips quotes on command token
    let zsh_snippet = render_hook_snippet("zsh").unwrap();
    assert!(zsh_snippet.contains("$HOME/.cargo/bin/afuse"));
    let fake_cargo_bin = sb.0.join("fake-home/.cargo/bin");
    let log_file = sb.0.join("zsh-hook.log");
    fs::create_dir_all(&fake_cargo_bin).unwrap();
    fs::write(
        fake_cargo_bin.join("afuse"),
        format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\n", log_file.display()),
    )
    .unwrap();
    fs::set_permissions(fake_cargo_bin.join("afuse"), PermissionsExt::from_mode(0o755)).unwrap();

    let patched = zsh_snippet
        .replace("/Applications/AgentFuse.app/Contents/MacOS/afuse", "/nonexistent/app-afuse")
        .replace("/opt/homebrew/bin/afuse", "/nonexistent/brew-afuse")
        .replace("/usr/local/bin/afuse", "/nonexistent/usr-afuse");
    let st = Command::new("/bin/zsh")
        .args([
            "-fc",
            "eval \"$1\"; _afuse_preexec '\"claude\" --help'",
            "_",
            &patched,
        ])
        .env("HOME", sb.0.join("fake-home"))
        .env("PATH", "/usr/bin:/bin")
        .status()
        .unwrap();
    assert!(st.success());
    let logged = fs::read_to_string(&log_file).unwrap_or_default();
    assert!(
        logged.contains("--tool claude"),
        "quoted command + $HOME/.cargo/bin/afuse probe failed: {:?}",
        logged
    );
}
