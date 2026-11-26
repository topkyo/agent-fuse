use crate::apfs::{force_remove_all, force_unlock, lstat_inode_mode, TMP_SEQ};
use crate::hook_config::{HOOK_MARKER_BEGIN, HOOK_MARKER_END};
use crate::manifest::compute_tree_manifest;
use crate::prune::prune_unlocked;
use crate::sha256::sha256_hex;
use crate::snapshot::list_snapshots_unlocked;
use crate::vault::validate_workspace_binding_with_vault;
use crate::*;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Mutex;

pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

pub(crate) struct TestEnvGuard {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}
impl TestEnvGuard {
    pub(crate) fn clean(keys: &[&'static str]) -> Self {
        let mut saved = Vec::with_capacity(keys.len());
        for &k in keys {
            saved.push((k, env::var_os(k)));
            env::remove_var(k);
        }
        Self { saved }
    }
}
impl Drop for TestEnvGuard {
    fn drop(&mut self) {
        for (k, v) in self.saved.drain(..) {
            match v {
                Some(val) => env::set_var(k, val),
                None => env::remove_var(k),
            }
        }
    }
}

pub(crate) fn compile_dummy_afuse_macho(dest: &Path, version_str: &str) {
    let src = format!(
        "#include <stdio.h>\nint main(void){{ puts(\"afuse {}\"); return 0; }}\n",
        version_str
    );
    let c_path = dest.with_extension("c");
    fs::write(&c_path, src).unwrap();
    let st = std::process::Command::new("clang")
        .args(["-O2", "-o"])
        .arg(dest)
        .arg(&c_path)
        .status()
        .expect("clang compile dummy afuse");
    let _ = fs::remove_file(&c_path);
    assert!(st.success(), "clang dummy afuse failed");
}

pub(crate) struct ScopedDir(pub(crate) PathBuf);
impl ScopedDir {
    pub(crate) fn new(tag: &str) -> Self {
        let p = env::temp_dir().join(format!(
            "afuse-test-{}-{}-{}",
            tag,
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = force_remove_all(&p);
        fs::create_dir_all(&p).unwrap();
        Self(fs::canonicalize(&p).unwrap_or(p))
    }
}
impl Drop for ScopedDir {
    fn drop(&mut self) {
        let _ = force_remove_all(&self.0);
    }
}

    #[test]
    fn sha256_nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn snap_and_restore_preserves_root_inode_readonly_and_symlinks() {
        let sandbox = ScopedDir::new("core");
        let ws = sandbox.0.join("ws");
        let vault = sandbox.0.join("vault");
        fs::create_dir_all(ws.join("src/nested")).unwrap();
        fs::create_dir_all(ws.join(".git/objects/pack")).unwrap();
        fs::write(ws.join("src/main.rs"), b"fn main() { println!(\"clean\"); }\n").unwrap();
        fs::write(ws.join("src/nested/mod.rs"), b"pub const V: u32 = 1;\n").unwrap();
        let pack_file = ws.join(".git/objects/pack/pack-123.pack");
        fs::write(&pack_file, b"immutable-git-pack").unwrap();
        fs::set_permissions(&pack_file, fs::Permissions::from_mode(0o444)).unwrap();
        std::os::unix::fs::symlink("src/main.rs", ws.join("main_link")).unwrap();

        let (ino_0, _) = lstat_inode_mode(&ws).unwrap();
        let snap = create_snapshot_with_vault(&ws, Some(&vault), "v1-clean").unwrap();
        assert!(snap.file_count >= 4);

        force_remove_all(&ws.join("src")).unwrap();
        fs::remove_file(ws.join("main_link")).unwrap();
        fs::create_dir_all(ws.join("main_link/rogue_dir")).unwrap();
        fs::write(ws.join("main_link/rogue_dir/junk"), b"corrupted").unwrap();
        force_unlock(&pack_file);
        fs::write(&pack_file, b"corrupted-pack").unwrap();
        fs::set_permissions(&pack_file, fs::Permissions::from_mode(0o444)).unwrap();
        fs::write(ws.join("rogue_root.txt"), b"unwanted").unwrap();

        let diff = diff_snapshot_with_vault(&ws, Some(&vault), &snap.id).unwrap();
        assert!(!diff.deleted.is_empty());
        assert!(!diff.added.is_empty());

        let rep = restore_snapshot_with_vault(&ws, Some(&vault), &snap.id, false).unwrap();
        assert_eq!(rep.root_inode_before, ino_0);
        assert_eq!(rep.root_inode_after, ino_0);
        assert_eq!(rep.tree_sha256, snap.tree_sha256);
        assert_eq!(
            fs::read_to_string(ws.join("src/main.rs")).unwrap(),
            "fn main() { println!(\"clean\"); }\n"
        );
        assert!(!ws.join("rogue_root.txt").exists());
        assert!(fs::symlink_metadata(ws.join("main_link"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(prune_snapshots_with_vault(&ws, Some(&vault), 0).unwrap(), 1);
    }

    #[test]
    fn fast_snap_skips_hashing_and_restore_computes_real_receipt_hash() {
        let sandbox = ScopedDir::new("fastsnap");
        let ws = sandbox.0.join("ws");
        let vault = sandbox.0.join("vault");
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(ws.join("app.rs"), b"v1_original").unwrap();

        let snap = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro", true).unwrap();
        assert!(snap.tree_sha256.starts_with("fast:") && snap.tree_sha256.len() == 69);
        assert_eq!(snap.file_count, 1);

        fs::write(ws.join("app.rs"), b"v2_mutated").unwrap();
        let rep = restore_snapshot_with_vault(&ws, Some(&vault), &snap.id, true).unwrap();
        assert_eq!(rep.tree_sha256.len(), 64);
        assert_ne!(rep.tree_sha256, "fast");
        assert_eq!(fs::read_to_string(ws.join("app.rs")).unwrap(), "v1_original");
    }

    #[test]
    fn prune_label_prefix_preserves_manual_snapshots_and_cleans_orphans() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _eg = TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
        let sandbox = ScopedDir::new("prunepfx");
        let ws = sandbox.0.join("ws");
        let vault = sandbox.0.join("vault");
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(ws.join("f.txt"), b"1").unwrap();

        let manual = create_snapshot_with_vault(&ws, Some(&vault), "milestone-1").unwrap();
        for i in 0..5 {
            fs::write(ws.join("f.txt"), format!("v{}", i)).unwrap();
            let _ = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:claude:Edit", true)
                .unwrap();
        }
        let (_ws_c, ws_vault) = prepare_workspace_vault_with(&ws, Some(&vault)).unwrap();
        let orphan = ws_vault.join("snapshots").join("snap-orphan-incomplete");
        fs::create_dir_all(orphan.join("tree")).unwrap();

        let removed = prune_unlocked(&ws_vault, 2, Some("auto:"), 0).unwrap();
        assert_eq!(removed, 4); // 3 old auto: snapshots + 1 orphan without meta.kv
        let remaining = list_snapshots_unlocked(&ws_vault).unwrap();
        assert_eq!(remaining.len(), 3); // 1 manual + 2 latest auto:
        assert!(remaining.iter().any(|m| m.id == manual.id));
    }

    #[test]
    fn validate_workspace_binding_rejects_forbidden_containers_and_symlinks_accepts_dirs_and_files() {
        let sandbox = ScopedDir::new("validate");
        let vault = sandbox.0.join("vault");
        let real_home = real_home_dir().unwrap();

        assert!(validate_workspace_binding_with_vault(Path::new("/"), Some(&vault)).is_err());
        assert!(validate_workspace_binding_with_vault(&real_home, Some(&vault)).is_err());
        assert!(
            validate_workspace_binding_with_vault(&real_home.join("Desktop"), Some(&vault))
                .is_err()
        );

        let home_link = sandbox.0.join("sneaky_home_link");
        std::os::unix::fs::symlink(&real_home, &home_link).unwrap();
        assert!(validate_workspace_binding_with_vault(&home_link, Some(&vault)).is_err());

        let plain_file = sandbox.0.join("plain.txt");
        fs::write(&plain_file, b"hi").unwrap();
        let file_link = sandbox.0.join("plain_link.txt");
        std::os::unix::fs::symlink(&plain_file, &file_link).unwrap();
        assert!(validate_workspace_binding_with_vault(&file_link, Some(&vault)).is_err());

        let valid_file = validate_workspace_binding_with_vault(&plain_file, Some(&vault)).unwrap();
        assert_eq!(valid_file.kind, TargetKind::SingleFile);
        assert_eq!(valid_file.marker, "file");

        let unmarked_dir = sandbox.0.join("unmarked");
        fs::create_dir_all(&unmarked_dir).unwrap();
        let valid_dir = validate_workspace_binding_with_vault(&unmarked_dir, Some(&vault)).unwrap();
        assert_eq!(valid_dir.kind, TargetKind::Directory);
        assert_eq!(valid_dir.marker, "dir");

        let good_repo = sandbox.0.join("good_repo");
        fs::create_dir_all(good_repo.join(".git")).unwrap();
        let valid = validate_workspace_binding_with_vault(&good_repo, Some(&vault)).unwrap();
        assert_eq!(valid.kind, TargetKind::Directory);
        assert_eq!(valid.marker, ".git");
        assert!(valid.ino > 0);
    }

    #[test]
    fn claude_json_scanner_resists_nested_command_spoofing_and_malformed_inputs() {
        let spoofed = r#"{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo '{\"cwd\":\"/\",\"tool_name\":\"Write\"}' && touch a.txt"},"cwd":"/tmp/real/project"}"#;
        let parsed = parse_claude_hook_json(spoofed);
        assert_eq!(parsed.cwd.as_deref(), Some("/tmp/real/project"));
        assert_eq!(parsed.tool_name.as_deref(), Some("Bash"));
        assert!(parsed
            .bash_command
            .as_deref()
            .unwrap()
            .contains("\"cwd\":\"/\""));

        let truncated = r#"{"cwd":"/tmp/x","tool_name":"Edit","tool_inp"#;
        let p2 = parse_claude_hook_json(truncated);
        assert_eq!(p2.cwd.as_deref(), Some("/tmp/x"));
        assert_eq!(p2.tool_name.as_deref(), Some("Edit"));

        assert!(is_readonly_bash_command("git status"));
        assert!(is_readonly_bash_command("ls -la src"));
        assert!(!is_readonly_bash_command("rm -rf src"));
        assert!(!is_readonly_bash_command("cat a > b"));
        assert!(!is_readonly_bash_command("git status && rm a"));
        assert!(!is_readonly_bash_command("git branch -D feature"));
        assert!(!is_readonly_bash_command("git diff --output=/tmp/x.patch"));
        assert!(!is_readonly_bash_command("git remote remove origin"));
    }

    #[test]
    fn strict_prune_parser_and_core_forbidden_path_guards_prevent_accidents() {
        let s = |v: &[&str]| -> Vec<String> { v.iter().map(|x| x.to_string()).collect() };
        assert_eq!(
            parse_prune_args(&s(&["--keep", "5", "--label-prefix", "auto:hook:"])).unwrap(),
            (5, Some("auto:hook:".to_string()), false)
        );
        // B-3: typos, empty prefix, negative/non-integer keep, or missing --keep must fail with EINVAL
        for bad in [
            s(&[]),
            s(&["--keep", "2", "--label-prefx", "auto:hook"]),
            s(&["--keep", "2", "--label-prefix", ""]),
            s(&["--keep", "2", "--label-prefix", "   "]),
            s(&["--kepp", "2", "--label-prefix", "auto:hook"]),
            s(&["--keep", "abc", "--label-prefix", "auto:hook"]),
            s(&["--keep", "-1"]),
        ] {
            let err = parse_prune_args(&bad).unwrap_err();
            assert_eq!(err.code, ERR_EINVAL, "expected EINVAL for {:?}", bad);
        }

        // B-2: .venv is ignored alongside node_modules/target/.build
        assert!(is_ignored_name(".venv"));
        assert!(is_ignored_name("node_modules"));

        // A-1: core primitives (create_snapshot / prune) reject /, $HOME, and TCC subtrees directly
        let sandbox = ScopedDir::new("forbidcore");
        let vault = sandbox.0.join("vault");
        let real_home = real_home_dir().unwrap();
        assert_eq!(
            create_snapshot_with_vault(Path::new("/"), Some(&vault), "bad")
                .unwrap_err()
                .code,
            ERR_EINVAL
        );
        assert_eq!(
            create_snapshot_with_vault(&real_home, Some(&vault), "bad")
                .unwrap_err()
                .code,
            ERR_EINVAL
        );
        assert_eq!(
            create_snapshot_with_vault(&real_home.join("Desktop"), Some(&vault), "bad")
                .unwrap_err()
                .code,
            ERR_EINVAL
        );
    }

    #[test]
    fn hook_exec_throttles_caps_ring_at_20_and_uninstall_respects_dry_run() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _eg = TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS", "AFUSE_HOOK_DISABLE", "AFUSE_GUARDED", "AFUSE_HOOK_THROTTLE_MS"]);
        let sandbox = ScopedDir::new("hookexec");
        let repo = sandbox.0.join("repo");
        let sub = repo.join("src/deep");
        let vault = sandbox.0.join("vault");
        let fake_home = sandbox.0.join("home");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(&sub).unwrap();
        fs::create_dir_all(fake_home.join(".claude")).unwrap();
        fs::write(repo.join("src/lib.rs"), b"clean").unwrap();

        let manual = create_snapshot_with_vault(&repo, Some(&vault), "keep-me-forever").unwrap();
        let pro_base =
            create_snapshot_opts_with_vault(&repo, Some(&vault), "auto:pro", true).unwrap();
        let pre_rest =
            create_snapshot_opts_with_vault(&repo, Some(&vault), "auto:pre-restore", true).unwrap();

        // Throttled check (5000ms window -> second call skips)
        let s1 = execute_hook_auto_snap(&sub, "auto:claude:Write", Some(&vault), 5_000).unwrap();
        assert!(s1.is_some());
        let s2 = execute_hook_auto_snap(&sub, "auto:claude:Write", Some(&vault), 5_000).unwrap();
        assert!(s2.is_none());

        // Ring cap check (throttle=0, 25 rapid snaps -> capped at 20 auto:hook: while preserving manual, auto:pro & auto:pre-restore)
        for i in 0..25 {
            fs::write(repo.join("src/lib.rs"), format!("edit-{}", i)).unwrap();
            let _ = execute_hook_auto_snap(&sub, "auto:claude:Edit", Some(&vault), 0).unwrap();
        }
        let (_w, ws_vault) = prepare_workspace_vault_with(&repo, Some(&vault)).unwrap();
        let all = list_snapshots_unlocked(&ws_vault).unwrap();
        let hook_count = all
            .iter()
            .filter(|m| m.label.starts_with("auto:hook:"))
            .count();
        assert!(hook_count <= 20);
        assert!(all.iter().any(|m| m.id == manual.id));
        assert!(all.iter().any(|m| m.id == pro_base.id));
        assert!(all.iter().any(|m| m.id == pre_rest.id));

        // Uninstall dry-run vs apply (covering new PATH-fallback snippets, opencode|goose, & legacy Claude snippet)
        let zsh_snippet = render_hook_snippet("zsh").unwrap();
        assert!(zsh_snippet.contains("claude|cursor-agent|codex|aider|gemini|opencode|goose"));
        assert!(zsh_snippet.contains("$HOME/.local/bin/afuse"));
        assert!(zsh_snippet.contains("/Applications/AgentFuse.app/Contents/MacOS/afuse"));
        let claude_snippet = render_hook_snippet("claude").unwrap();
        assert!(claude_snippet.contains("$HOME/.local/bin/afuse"));
        assert!(claude_snippet.contains("/Applications/AgentFuse.app/Contents/MacOS/afuse"));
        assert!(claude_snippet.contains("hook claude --exec"));

        let zshrc = fake_home.join(".zshrc");
        let orig_zshrc = format!("export PATH=/usr/bin:$PATH\n{}alias ll='ls -l'\n", zsh_snippet);
        fs::write(&zshrc, &orig_zshrc).unwrap();
        let settings = fake_home.join(".claude/settings.json");
        fs::write(&settings, &claude_snippet).unwrap();
        fs::create_dir_all(repo.join(".claude")).unwrap();
        let legacy_claude = repo.join(".claude/settings.json");
        fs::write(
            &legacy_claude,
            "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"Bash\",\"hooks\":[{\"type\":\"command\",\"command\":\"command -v afuse >/dev/null 2>&1 && afuse hook claude --exec || true\"}]}]}}\n",
        )
        .unwrap();
        let sha_before = sha256_hex(&fs::read(&zshrc).unwrap());
        let set_sha_before = sha256_hex(&fs::read(&settings).unwrap());

        let dry = uninstall_hooks(false, Some(&fake_home), &repo).unwrap();
        assert!(dry.iter().any(|a| a.kind == "zsh_marker_block" && !a.applied));
        assert_eq!(
            dry.iter()
                .filter(|a| a.kind == "manual_claude_settings_json")
                .count(),
            2
        );
        assert_eq!(sha256_hex(&fs::read(&zshrc).unwrap()), sha_before);
        assert_eq!(sha256_hex(&fs::read(&settings).unwrap()), set_sha_before);

        let applied = uninstall_hooks(true, Some(&fake_home), &repo).unwrap();
        assert!(applied.iter().any(|a| a.applied && a.backup_path.is_some()));
        let after_zshrc = fs::read_to_string(&zshrc).unwrap();
        assert!(!after_zshrc.contains(HOOK_MARKER_BEGIN));
        assert!(!after_zshrc.contains(HOOK_MARKER_END));
        assert!(!after_zshrc.contains("_afuse_preexec"));
        assert!(after_zshrc.contains("alias ll='ls -l'"));
        assert_eq!(sha256_hex(&fs::read(&settings).unwrap()), set_sha_before);
    }

    #[test]
    fn guard_trips_process_group_and_auto_restores() {
        let sandbox = ScopedDir::new("guard");
        let ws = sandbox.0.join("ws");
        let vault = sandbox.0.join("vault");
        fs::create_dir_all(ws.join("src")).unwrap();
        for i in 0..8 {
            fs::write(ws.join("src").join(format!("f{}.rs", i)), format!("code {}", i)).unwrap();
        }
        let (ino_0, _) = lstat_inode_mode(&ws).unwrap();

        let cfg = GuardConfig {
            max_delete: 3,
            max_write_mb: 512,
            poll_ms: 10,
            auto_rollback: true,
        };
        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            "rm -rf src/* && sleep 2".to_string(),
        ];
        let rep = run_guarded_command_with_vault(&ws, Some(&vault), &cfg, &cmd).unwrap();
        assert!(rep.tripped);
        assert_eq!(rep.exit_code, EXIT_FUSE_TRIPPED);
        assert!(rep.auto_restored);
        assert!(rep.root_inode_preserved);
        let (ino_1, _) = lstat_inode_mode(&ws).unwrap();
        assert_eq!(ino_0, ino_1);
        for i in 0..8 {
            assert_eq!(
                fs::read_to_string(ws.join("src").join(format!("f{}.rs", i))).unwrap(),
                format!("code {}", i)
            );
        }
    }

    #[test]
    fn rejects_self_ingestion_and_recovers_chmod_0000_locked_workspace() {
        let sandbox = ScopedDir::new("chmod0000");
        let ws = sandbox.0.join("ws");
        let bad_vault = ws.join(".git/afuse-vault");
        fs::create_dir_all(ws.join("secrets")).unwrap();
        let err = create_snapshot_with_vault(&ws, Some(&bad_vault), "bad").unwrap_err();
        assert_eq!(err.code, ERR_EINVAL);

        let vault = sandbox.0.join("vault");
        let f = ws.join("secrets/key.txt");
        fs::write(&f, b"clean-secret").unwrap();
        let snap = create_snapshot_with_vault(&ws, Some(&vault), "clean").unwrap();
        fs::write(&f, b"corrupted").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o000)).unwrap();

        let rep = restore_snapshot_with_vault(&ws, Some(&vault), &snap.id, true).unwrap();
        assert!(rep.safety_snapshot_id.is_some());
        assert_eq!(fs::read_to_string(&f).unwrap(), "clean-secret");

        // Regression B4: `latest` must not resolve to `auto:pre-restore`, keeping post-restore diff clean and repeated `restore latest` idempotent
        let post_id = rep.post_snapshot_id.as_deref().unwrap_or(&snap.id);
        let diff_after = diff_snapshot_with_vault(&ws, Some(&vault), "latest").unwrap();
        assert_eq!(diff_after.snapshot_id, post_id);
        assert!(diff_after.added.is_empty() && diff_after.modified.is_empty() && diff_after.deleted.is_empty() && diff_after.renamed.is_empty());
        let rep_again = restore_snapshot_with_vault(&ws, Some(&vault), "latest", true).unwrap();
        assert_eq!(rep_again.snapshot_id, post_id);
        assert!(rep_again.safety_snapshot_id.is_none());
        assert!(rep_again.post_snapshot_id.is_none());
        assert_eq!(fs::read_to_string(&f).unwrap(), "clean-secret");
    }

    #[test]
    fn doctor_reports_privacy_safe_apfs_diagnostics() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _eg = TestEnvGuard::clean(&["AFUSE_VAULT_DIR"]);
        let sandbox = ScopedDir::new("doctor");
        let ws = sandbox.0.join("ws");
        let vault = sandbox.0.join("vault");
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(ws.join("main.rs"), b"fn main() {}").unwrap();
        create_snapshot_with_vault(&ws, Some(&vault), "init").unwrap();

        let rep = run_doctor_with_vault(&ws, Some(&vault)).unwrap();
        assert!(rep.ok);
        assert_eq!(rep.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(rep.os, env::consts::OS);
        assert_eq!(rep.arch, env::consts::ARCH);
        assert!(rep.apfs_verified);
        assert!(rep.vault_writable);
        assert!(rep.clonefile_probe_us > 0);
        assert!(rep.free_gib > 0.0);
        assert_eq!(rep.snapshot_count, 1);

        let rendered = rep.to_json();
        assert!(rendered.contains("\"ok\":true"));
        assert!(!rendered.contains("/Users/"));
        assert!(!rendered.contains("/tmp/"));

        let unwritable = run_doctor_with_vault(&ws, Some(Path::new("/dev/null/impossible"))).unwrap();
        assert!(!unwritable.ok);
        assert!(unwritable.apfs_verified);
        assert!(!unwritable.vault_writable);
        assert_eq!(unwritable.clonefile_probe_us, 0);
        assert_eq!(unwritable.snapshot_count, 0);
        assert!(unwritable.to_json().contains("\"ok\":false"));

        let missing_err = run_doctor_with_vault(
            Path::new("/Users/probe_user_invalid/nonexistent_secret_xyz"),
            Some(&vault),
        )
        .unwrap_err();
        assert_eq!(missing_err.code, ERR_ENOENT);
        assert!(!missing_err.message.contains("probe_user_invalid"));
        assert!(!missing_err.message.contains("nonexistent_secret_xyz"));

        let val_missing = validate_workspace_binding_with_vault(
            Path::new("/Users/probe_user_invalid/nonexistent_secret_xyz"),
            Some(&vault),
        )
        .unwrap_err();
        assert!(!val_missing.message.contains("probe_user_invalid"));
        assert!(!val_missing.message.contains("nonexistent_secret_xyz"));

        let desktop_err = validate_workspace_binding_with_vault(
            &real_home_dir().unwrap().join("Desktop"),
            Some(&vault),
        )
        .unwrap_err();
        assert_eq!(desktop_err.code, ERR_EINVAL);

        let prev_env = env::var_os("AFUSE_VAULT_DIR");
        env::set_var("AFUSE_VAULT_DIR", &vault);
        let env_ok = run_doctor(&ws).unwrap();
        assert!(env_ok.ok);
        assert!(env_ok.vault_writable);
        assert_eq!(env_ok.snapshot_count, 1);

        env::set_var("AFUSE_VAULT_DIR", "/dev/null/impossible");
        let env_bad = run_doctor(&ws).unwrap();
        assert!(!env_bad.ok);
        assert!(!env_bad.vault_writable);
        assert_eq!(env_bad.clonefile_probe_us, 0);
        assert_eq!(env_bad.snapshot_count, 0);

        match prev_env {
            Some(v) => env::set_var("AFUSE_VAULT_DIR", v),
            None => env::remove_var("AFUSE_VAULT_DIR"),
        }
    }

    #[test]
    fn hook_auto_snap_discovers_non_git_cargo_root_and_prefers_git() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _eg = TestEnvGuard::clean(&["AFUSE_HOOK_DISABLE", "AFUSE_GUARDED", "AFUSE_MAX_AUTO_SNAPS"]);
        let sandbox = ScopedDir::new("hook-markers");
        let cargo_ws = sandbox.0.join("cargo_only");
        let nested_src = cargo_ws.join("src");
        let vault = sandbox.0.join("vault");
        fs::create_dir_all(&nested_src).unwrap();
        fs::write(cargo_ws.join("Cargo.toml"), b"[package]\nname=\"demo\"\n").unwrap();
        fs::write(nested_src.join("lib.rs"), b"pub fn x() {}\n").unwrap();

        let prev_dis = env::var_os("AFUSE_HOOK_DISABLE");
        let prev_grd = env::var_os("AFUSE_GUARDED");
        env::remove_var("AFUSE_HOOK_DISABLE");
        env::remove_var("AFUSE_GUARDED");

        let meta = execute_hook_auto_snap(&nested_src, "cargo-edit", Some(&vault), 0)
            .unwrap()
            .expect("should auto-snap Cargo.toml project");
        assert_eq!(
            PathBuf::from(&meta.workspace),
            fs::canonicalize(&cargo_ws).unwrap()
        );

        let mono = sandbox.0.join("mono_git");
        let pkg_dir = mono.join("crates/sub/src");
        fs::create_dir_all(mono.join(".git")).unwrap();
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(mono.join("crates/sub/Cargo.toml"), b"[package]\n").unwrap();
        let discovered = find_project_root(&pkg_dir).unwrap();
        assert_eq!(discovered, fs::canonicalize(&mono).unwrap());

        if let Some(v) = prev_dis {
            env::set_var("AFUSE_HOOK_DISABLE", v);
        }
        if let Some(v) = prev_grd {
            env::set_var("AFUSE_GUARDED", v);
        }
    }

    #[test]
    fn guarded_command_uses_workspace_cwd_without_mutating_parent_dir() {
        let sandbox = ScopedDir::new("guard-cwd");
        let ws = sandbox.0.join("ws");
        let vault = sandbox.0.join("vault");
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(ws.join("keep.txt"), b"ok\n").unwrap();

        let parent_before = env::current_dir().unwrap();
        let cfg = GuardConfig {
            max_delete: 3,
            max_write_mb: 100,
            poll_ms: 10,
            auto_rollback: false,
        };
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "pwd > cwd.out".to_string(),
        ];
        let rep = run_guarded_command_with_vault(&ws, Some(&vault), &cfg, &cmd).unwrap();
        let parent_after = env::current_dir().unwrap();
        assert_eq!(parent_before, parent_after);
        assert!(!rep.tripped);
        let child_cwd = fs::read_to_string(ws.join("cwd.out")).unwrap();
        assert_eq!(
            PathBuf::from(child_cwd.trim()),
            fs::canonicalize(&ws).unwrap()
        );
    }

    #[test]
    fn fast_snapshot_restore_returns_real_merkle_hash_and_full_timing() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _eg = TestEnvGuard::clean(&["AFUSE_VAULT_DIR", "AFUSE_MAX_AUTO_SNAPS"]);
        let sandbox = ScopedDir::new("fast-restore");
        let ws = sandbox.0.join("ws");
        let vault = sandbox.0.join("vault");
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(ws.join("alpha.txt"), b"hello fast restore\n").unwrap();

        let prev_env = env::var_os("AFUSE_VAULT_DIR");
        env::set_var("AFUSE_VAULT_DIR", &vault);
        let fast_meta = create_snapshot_fast(&ws, "auto:pro:fsevents").unwrap();
        assert!(fast_meta.tree_sha256.starts_with("fast:") && fast_meta.tree_sha256.len() == 69);

        fs::remove_file(ws.join("alpha.txt")).unwrap();
        let rep = restore_snapshot_with_vault(&ws, Some(&vault), &fast_meta.id, true).unwrap();
        assert_ne!(rep.tree_sha256, "fast");
        assert_eq!(rep.tree_sha256.len(), 64);
        let (expected_hash, _, _, _) = compute_tree_manifest(&ws).unwrap();
        assert_eq!(rep.tree_sha256, expected_hash);
        assert!(rep.elapsed_us > 0);
        assert_eq!(
            fs::read_to_string(ws.join("alpha.txt")).unwrap(),
            "hello fast restore\n"
        );

        match prev_env {
            Some(v) => env::set_var("AFUSE_VAULT_DIR", v),
            None => env::remove_var("AFUSE_VAULT_DIR"),
        }
    }

    #[test]
    fn selective_restore_restores_targets_deletes_added_and_blocks_traversal() {
        let sandbox = ScopedDir::new("selective-restore");
        let ws = sandbox.0.join("ws");
        let vault = sandbox.0.join("vault");
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::create_dir_all(ws.join("src")).unwrap();
        fs::write(ws.join("src/keep.rs"), b"v1_keep\n").unwrap();
        fs::write(ws.join("src/target.rs"), b"v1_target\n").unwrap();

        let (ino_before, _) = lstat_inode_mode(&ws).unwrap();
        let snap = create_snapshot_with_vault(&ws, Some(&vault), "baseline").unwrap();

        fs::write(ws.join("src/keep.rs"), b"dirty_keep\n").unwrap();
        fs::remove_file(ws.join("src/target.rs")).unwrap();
        fs::write(ws.join("src/extra.rs"), b"added_after\n").unwrap();

        for bad in ["", "   ", "/etc/passwd", "../escape", "src/../../escape", ".afuse.tmp.123", "node_modules/x.js", "."] {
            let err = restore_snapshot_paths_with_vault(&ws, Some(&vault), &snap.id, false, &[bad.to_string()]).unwrap_err();
            assert_eq!(err.code, ERR_EINVAL, "expected EINVAL for '{}'", bad);
        }

        let phantom_err = restore_snapshot_paths_with_vault(
            &ws,
            Some(&vault),
            &snap.id,
            true,
            &["src/target.rs".to_string(), "src/phantom_never_existed.rs".to_string()],
        )
        .unwrap_err();
        assert_eq!(phantom_err.code, ERR_ENOENT);
        assert_eq!(phantom_err.message, "requested path does not exist in snapshot or workspace");
        let (_, sel_wv) = prepare_workspace_vault_with(&ws, Some(&vault)).unwrap();
        let pre_after_phantom = list_snapshots_unlocked(&sel_wv)
            .unwrap()
            .into_iter()
            .filter(|m| m.label == "auto:pre-restore")
            .count();
        assert_eq!(pre_after_phantom, 0, "phantom path must fail before taking auto:pre-restore backup");

        let rep = restore_snapshot_paths_with_vault(
            &ws,
            Some(&vault),
            &snap.id,
            true,
            &["src/target.rs".to_string(), "src/extra.rs".to_string()],
        )
        .unwrap();
        assert!(rep.selective);
        assert_eq!(rep.restored_paths, 2);
        assert_eq!(rep.root_inode_before, ino_before);
        assert_eq!(rep.root_inode_after, ino_before);
        assert_eq!(fs::read_to_string(ws.join("src/target.rs")).unwrap(), "v1_target\n");
        assert!(!ws.join("src/extra.rs").exists());
        assert_eq!(fs::read_to_string(ws.join("src/keep.rs")).unwrap(), "dirty_keep\n");
    }

    #[test]
    fn auto_snapshot_quota_gc_keeps_limit_and_preserves_manual() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _eg = TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
        let sandbox = ScopedDir::new("auto-quota");
        let ws = sandbox.0.join("ws");
        let vault = sandbox.0.join("vault");
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(ws.join("a.txt"), b"1\n").unwrap();

        env::set_var("AFUSE_MAX_AUTO_SNAPS", "3");

        let m1 = create_snapshot_opts_with_vault(&ws, Some(&vault), "manual", false).unwrap();
        let m2 = create_snapshot_opts_with_vault(&ws, Some(&vault), "release-v0.5", false).unwrap();
        let pre = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pre-restore", true).unwrap();

        let mut auto_ids = Vec::new();
        for i in 0..5 {
            fs::write(ws.join("a.txt"), format!("{}\n", i)).unwrap();
            let s = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:fsevents", true).unwrap();
            auto_ids.push(s.id);
        }

        let all = {
            let (_w, wv) = prepare_workspace_vault_with(&ws, Some(&vault)).unwrap();
            list_snapshots_unlocked(&wv).unwrap()
        };
        let auto_left: Vec<_> = all
            .iter()
            .filter(|m| m.label.starts_with("auto:") && m.label != "auto:pre-restore")
            .collect();
        assert_eq!(auto_left.len(), 3);
        assert!(all.iter().any(|m| m.id == m1.id));
        assert!(all.iter().any(|m| m.id == m2.id));
        assert!(all.iter().any(|m| m.id == pre.id));
        assert!(!all.iter().any(|m| m.id == auto_ids[0]));
        assert!(all.iter().any(|m| m.id == auto_ids[4]));
    }

    #[test]
    fn upgrade_check_and_offline_archive_sha256_self_replace() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _eg = TestEnvGuard::clean(&["AFUSE_RELEASE_JSON_URL", "AFUSE_UPGRADE_ARCHIVE_DIR"]);
        assert!(is_newer_version("0.5.0", "0.5.1"));
        assert!(!is_newer_version("0.5.0", "0.5.0"));
        assert!(!is_newer_version("0.5.0", "0.4.9"));

        let sandbox = ScopedDir::new("upgrade-offline");
        let bin_dir = sandbox.0.join("bin");
        let payload_dir = sandbox.0.join("payload");
        let archive_dir = sandbox.0.join("archive");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&payload_dir).unwrap();
        fs::create_dir_all(&archive_dir).unwrap();

        let fake_exe = bin_dir.join("afuse");
        fs::write(&fake_exe, b"OLD_AFUSE_BINARY").unwrap();
        compile_dummy_afuse_macho(&payload_dir.join("afuse"), "9.6.0");

        let tb_path = archive_dir.join("afuse-macos-universal.tar.gz");
        let tar_st = std::process::Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&tb_path)
            .args(["-C"])
            .arg(&payload_dir)
            .arg("afuse")
            .status()
            .unwrap();
        assert!(tar_st.success());

        let tb_bytes = fs::read(&tb_path).unwrap();
        let real_sha = sha256_hex(&tb_bytes);
        let sums_path = archive_dir.join("SHA256SUMS.txt");

        let rel_json_path = sandbox.0.join("release.json");
        fs::write(
            &rel_json_path,
            r#"{"tag_name":"v9.6.0","html_url":"https://github.com/topkyo/agent-fuse/releases/tag/v9.6.0","assets":[{"name":"afuse-macos-universal.tar.gz","browser_download_url":"https://example.invalid/tb.tar.gz"},{"name":"SHA256SUMS.txt","browser_download_url":"https://example.invalid/sums.txt"}]}"#,
        )
        .unwrap();

        env::set_var("AFUSE_RELEASE_JSON_URL", format!("file://{}", rel_json_path.display()));
        env::set_var("AFUSE_UPGRADE_ARCHIVE_DIR", &archive_dir);

        let chk = check_for_updates().unwrap();
        assert!(chk.update_available);
        assert_eq!(chk.latest_version, "9.6.0");

        // Tampered checksum must fail and keep existing binary untouched
        fs::write(
            &sums_path,
            "0000000000000000000000000000000000000000000000000000000000000000  afuse-macos-universal.tar.gz\n",
        )
        .unwrap();
        let bad_err = perform_upgrade_on_exe(&fake_exe).unwrap_err();
        assert_eq!(bad_err.code, ERR_EINVAL);
        assert_eq!(fs::read(&fake_exe).unwrap(), b"OLD_AFUSE_BINARY");

        // Valid checksum completes atomic replacement with codesign + --version probe
        fs::write(&sums_path, format!("{}  afuse-macos-universal.tar.gz\n", real_sha)).unwrap();
        let applied = perform_upgrade_on_exe(&fake_exe).unwrap();
        assert!(applied.updated);
        assert_eq!(applied.release_state, "updated");
        assert_eq!(applied.verified_sha256.as_deref(), Some(real_sha.as_str()));
        let ver_out = std::process::Command::new(&fake_exe).arg("--version").output().unwrap();
        assert!(ver_out.status.success());
        assert_eq!(String::from_utf8_lossy(&ver_out.stdout).trim(), "afuse 9.6.0");

        // .app bundle binary & symlink pointing inside .app refuse CLI self-overwrite with ERR_USAGE (even without network)
        env::set_var("AFUSE_RELEASE_JSON_URL", "http://127.0.0.1:9/unreachable");
        let app_bin = sandbox.0.join("AgentFuse.app/Contents/MacOS/afuse");
        fs::create_dir_all(app_bin.parent().unwrap()).unwrap();
        fs::write(&app_bin, b"APP_BUNDLED").unwrap();
        let app_err = perform_upgrade_on_exe(&app_bin).unwrap_err();
        assert_eq!(app_err.code, ERR_USAGE);
        assert!(app_err.message.contains("brew upgrade --cask --no-quarantine topkyo/tap/agent-fuse"));

        let local_bin_dir = sandbox.0.join("local/bin");
        fs::create_dir_all(&local_bin_dir).unwrap();
        let sym_bin = local_bin_dir.join("afuse");
        std::os::unix::fs::symlink(&app_bin, &sym_bin).unwrap();
        let sym_err = perform_upgrade_on_exe(&sym_bin).unwrap_err();
        assert_eq!(sym_err.code, ERR_USAGE);
        assert!(sym_err.message.contains("Check for Updates"));
        assert!(fs::symlink_metadata(&sym_bin).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&app_bin).unwrap(), b"APP_BUNDLED");
    }

    #[test]
    fn corrupted_meta_kv_filtered_in_list_and_rejected_on_explicit_target() {
        let sandbox = ScopedDir::new("corrupt-meta");
        let ws = sandbox.0.join("ws");
        let vault = sandbox.0.join("vault");
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("Cargo.toml"), b"[package]\nname=\"demo\"\n").unwrap();
        fs::write(ws.join("main.rs"), b"fn main() {}\n").unwrap();

        let good = create_snapshot_with_vault(&ws, Some(&vault), "good").unwrap();
        let bad = create_snapshot_with_vault(&ws, Some(&vault), "to-corrupt").unwrap();
        let (_, ws_vault) = prepare_workspace_vault_with(&ws, Some(&vault)).unwrap();
        assert_eq!(list_snapshots_unlocked(&ws_vault).unwrap().len(), 2);

        let bad_meta = ws_vault.join("snapshots").join(&bad.id).join("meta.kv");
        fs::write(&bad_meta, b"garbage=1\ncreated_ms=notanumber\n").unwrap();

        let listed = list_snapshots_unlocked(&ws_vault).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, good.id);
        assert!(!listed.iter().any(|m| m.id.is_empty()));

        let diff_err = diff_snapshot_with_vault(&ws, Some(&vault), &bad.id).unwrap_err();
        assert_eq!(diff_err.code, ERR_EINVAL);
        assert!(diff_err.message.contains("corrupted snapshot meta.kv"));

        let restore_err =
            restore_snapshot_with_vault(&ws, Some(&vault), &bad.id, false).unwrap_err();
        assert_eq!(restore_err.code, ERR_EINVAL);
        assert!(restore_err.message.contains("corrupted snapshot meta.kv"));
    }

    #[test]
    fn utf8_short_hash_backslash_reject_and_unicode_readonly_selective_restore() {
        assert_eq!(short_hash("中文测试abcd", 2), "中文");
        let cleaned = sanitize_terminal_text("safe\x1b[31m_text\nline\x7f");
        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('\n'));
        assert!(!cleaned.contains('\x7f'));

        let sandbox = ScopedDir::new("utf8-selective");
        let ws = sandbox.0.join("ws");
        let vault = sandbox.0.join("vault");
        fs::create_dir_all(ws.join("子目录 带空格")).unwrap();
        let rel = "子目录 带空格/配置 文稿.txt";
        let target = ws.join(rel);
        fs::write(&target, "初始内容 v1\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o444)).unwrap();

        let snap = create_snapshot_with_vault(&ws, Some(&vault), "utf8-v1").unwrap();

        let missing_bs = restore_snapshot_paths_with_vault(
            &ws,
            Some(&vault),
            &snap.id,
            false,
            &[String::from("sub\\file.txt")],
        )
        .unwrap_err();
        assert_eq!(missing_bs.code, ERR_ENOENT);

        let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o644));
        fs::write(&target, "被破坏的内容\n").unwrap();

        let rep = restore_snapshot_paths_with_vault(
            &ws,
            Some(&vault),
            &snap.id,
            true,
            &[String::from(rel)],
        )
        .unwrap();
        assert_eq!(rep.restored_paths, 1);
        assert_eq!(fs::read_to_string(&target).unwrap(), "初始内容 v1\n");
        let mode = fs::symlink_metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o444);
        let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o644));
    }

    #[test]
    fn git_critical_deletion_trips_guard_and_restores() {
        let sandbox = ScopedDir::new("guard-git");
        let ws = sandbox.0.join("ws");
        let vault = sandbox.0.join("vault");
        fs::create_dir_all(ws.join(".git/refs/heads")).unwrap();
        fs::create_dir_all(ws.join("src")).unwrap();
        fs::write(ws.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(ws.join(".git/config"), b"[core]\n\tbare = false\n").unwrap();
        fs::write(ws.join(".git/refs/heads/main"), b"0123456789abcdef\n").unwrap();
        fs::write(ws.join("src/lib.rs"), b"pub fn keep() {}\n").unwrap();

        let cfg = GuardConfig {
            max_delete: 2,
            max_write_mb: 512,
            poll_ms: 10,
            auto_rollback: true,
        };
        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            "rm -rf .git && sleep 2".to_string(),
        ];
        let rep = run_guarded_command_with_vault(&ws, Some(&vault), &cfg, &cmd).unwrap();
        assert!(rep.tripped);
        assert!(rep.auto_restored);
        assert_eq!(fs::read_to_string(ws.join(".git/HEAD")).unwrap(), "ref: refs/heads/main\n");
    }

    #[test]
    fn doctor_flags_forbidden_home_without_creating_vault_state() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let sandbox = ScopedDir::new("doctor-home");
        let vault = sandbox.0.join("vault");
        let real_home = crate::real_home_dir().unwrap();
        let rep = run_doctor_with_vault(&real_home, Some(&vault)).unwrap();
        assert!(!rep.workspace_valid);
        assert!(!rep.ok);
        if vault.exists() {
            assert_eq!(fs::read_dir(&vault).unwrap().count(), 0);
        }
    }

    #[test]
    fn blindspot_01_to_09_kernel_regressions() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _eg = TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
        let sandbox = ScopedDir::new("blindspots");
        let vault = sandbox.0.join("vault");

        // BLINDSPOT-01: selective restore on subtree preserves nested ignored dirs
        let ws1 = sandbox.0.join("ws1");
        fs::create_dir_all(ws1.join("packages/app/node_modules/pkg")).unwrap();
        fs::write(ws1.join("packages/app/node_modules/pkg/index.js"), b"keep-nm\n").unwrap();
        fs::write(ws1.join("packages/app/src.rs"), b"v1\n").unwrap();
        let s1 = create_snapshot_with_vault(&ws1, Some(&vault), "v1").unwrap();
        fs::write(ws1.join("packages/app/src.rs"), b"corrupt\n").unwrap();
        restore_snapshot_paths_with_vault(&ws1, Some(&vault), &s1.id, true, &["packages/app".to_string()]).unwrap();
        assert_eq!(fs::read_to_string(ws1.join("packages/app/src.rs")).unwrap(), "v1\n");
        assert_eq!(fs::read_to_string(ws1.join("packages/app/node_modules/pkg/index.js")).unwrap(), "keep-nm\n");

        // BLINDSPOT-02 & 03: FIFO pipe + 0o555 readonly dir filtered snapshot, restore & prune
        let ws2 = sandbox.0.join("ws2");
        let ro_sub = ws2.join("ro_dir");
        fs::create_dir_all(ro_sub.join("target")).unwrap();
        fs::write(ro_sub.join("target/junk.o"), b"ignored").unwrap();
        fs::write(ro_sub.join("keep.txt"), b"readonly-ok\n").unwrap();
        let st_fifo = std::process::Command::new("mkfifo").arg(ro_sub.join("pipe.fifo")).status().unwrap();
        assert!(st_fifo.success());
        fs::set_permissions(&ro_sub, fs::Permissions::from_mode(0o555)).unwrap();
        let (s2, _) = create_snapshot_fast_dedup_with_vault(&ws2, Some(&vault), "auto:pro:init").unwrap();
        let diff2 = diff_snapshot_with_vault(&ws2, Some(&vault), &s2.id).unwrap();
        assert!(diff2.added.is_empty() && diff2.deleted.is_empty());
        let ro_vault_mode = fs::symlink_metadata(
            prepare_live_workspace_vault_with(&ws2, Some(&vault)).unwrap().1
                .join("snapshots").join(&s2.id).join("tree/ro_dir"),
        ).unwrap().permissions().mode() & 0o777;
        assert_eq!(ro_vault_mode, 0o555);
        prune_snapshots_filtered_with_vault(&ws2, Some(&vault), 0, None).unwrap();
        let _ = fs::set_permissions(&ro_sub, fs::Permissions::from_mode(0o755));

        // BLINDSPOT-04: heterogeneous / symlink replacement on bound dir & single file
        let ws3 = sandbox.0.join("ws3_dir");
        let decoy = sandbox.0.join("decoy_dir");
        fs::create_dir_all(&ws3).unwrap();
        fs::create_dir_all(&decoy).unwrap();
        fs::write(ws3.join("real.txt"), b"real-dir-v1").unwrap();
        fs::write(decoy.join("decoy.txt"), b"decoy").unwrap();
        let _ = create_snapshot_with_vault(&ws3, Some(&vault), "v1").unwrap();
        fs::remove_dir_all(&ws3).unwrap();
        std::os::unix::fs::symlink(&decoy, &ws3).unwrap();
        let d_sym = diff_snapshot_with_vault(&ws3, Some(&vault), "latest").unwrap();
        assert!(d_sym.deleted.iter().any(|p| p == "real.txt"));
        restore_snapshot_with_vault(&ws3, Some(&vault), "latest", true).unwrap();
        assert!(!fs::symlink_metadata(&ws3).unwrap().file_type().is_symlink());
        assert_eq!(fs::read_to_string(ws3.join("real.txt")).unwrap(), "real-dir-v1");

        let sf = sandbox.0.join("single_a\\b.txt");
        fs::write(&sf, b"single-ok").unwrap();
        create_snapshot_with_vault(&sf, Some(&vault), "sf1").unwrap();
        fs::remove_file(&sf).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", &sf).unwrap();
        restore_snapshot_with_vault(&sf, Some(&vault), "latest", true).unwrap();
        assert_eq!(fs::read_to_string(&sf).unwrap(), "single-ok");

        // BLINDSPOT-05 & 06: project_files ignores .git objects & validate/doctor create 0 vault subdirs
        let ws5 = sandbox.0.join("ws5_git");
        fs::create_dir_all(ws5.join(".git/objects")).unwrap();
        fs::write(ws5.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
        for k in 0..5 {
            fs::write(ws5.join(format!(".git/objects/o{}", k)), b"obj").unwrap();
        }
        fs::write(ws5.join("main.rs"), b"fn main() {}\n").unwrap();
        let s5 = create_snapshot_with_vault(&ws5, Some(&vault), "v5").unwrap();
        assert_eq!(s5.project_files, 1);
        let r5 = restore_snapshot_with_vault(&ws5, Some(&vault), "latest", false).unwrap();
        assert_eq!(r5.project_files, 1);

        let unbound = sandbox.0.join("unbound_check");
        fs::create_dir_all(&unbound).unwrap();
        let v_clean = sandbox.0.join("vault_clean");
        fs::create_dir_all(&v_clean).unwrap();
        let _ = validate_workspace_binding_with_vault(&unbound, Some(&v_clean)).unwrap();
        let _ = run_doctor_with_vault(&unbound, Some(&v_clean)).unwrap();
        assert_eq!(fs::read_dir(&v_clean).unwrap().count(), 0);

        // BLINDSPOT-07 & 09: auto:init dedup, pre-restore quota cap=10, backslash selective path
        let (_, init_dedup) = create_snapshot_fast_dedup_with_vault(&ws5, Some(&vault), "auto:pro:init").unwrap();
        assert!(init_dedup);
        for k in 0..14 {
            fs::write(ws5.join("main.rs"), format!("fn main() {{ /* {} */ }}\n", k)).unwrap();
            let _ = create_snapshot_opts_with_vault(&ws5, Some(&vault), "auto:pre-restore", true).unwrap();
        }
        let (_, ws5_v) = resolve_workspace_vault_recovery(&ws5, Some(&vault)).unwrap();
        let pre_left = list_snapshots_unlocked(&ws5_v).unwrap().iter().filter(|m| m.label == "auto:pre-restore").count();
        assert!(pre_left <= 10);
        assert!(crate::restore_tree::validate_rel_restore_path("dir\\file.txt").is_ok());

        // BLINDSPOT-08: guard without auto_rollback when workspace is deleted exits 77 cleanly
        let ws8_parent = sandbox.0.join("ws8_host");
        let ws8 = ws8_parent.join("target");
        fs::create_dir_all(&ws8).unwrap();
        fs::write(ws8.join("code.rs"), b"important\n").unwrap();
        let gcfg = GuardConfig { max_delete: 1, max_write_mb: 128, poll_ms: 10, auto_rollback: false };
        let grep = run_guarded_command_with_vault(
            &ws8,
            Some(&vault),
            &gcfg,
            &["sh".to_string(), "-c".to_string(), format!("rm -rf '{}' && sleep 1", ws8.display())],
        ).unwrap();
        assert!(grep.tripped);
        assert_eq!(grep.exit_code, EXIT_FUSE_TRIPPED);
        assert!(!grep.root_inode_preserved);
    }

    #[test]
    fn selective_restore_preserves_other_trash_and_nested_ignore_and_fast_verify() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _env_guard = TestEnvGuard::clean(&["HOME"]);
        let sandbox = ScopedDir::new("sel_nest_fast");
        env::set_var("HOME", &sandbox.0);
        let vault = sandbox.0.join("vault");
        let ws = sandbox.0.join("ws");
        let trash = sandbox.0.join(".Trash");
        fs::create_dir_all(&ws).unwrap();
        fs::create_dir_all(&trash).unwrap();
        fs::write(ws.join("keep.txt"), b"keep-v1").unwrap();
        fs::write(ws.join("other.txt"), b"other-v1").unwrap();

        // P0-1: selective restore must not purge other trashed counterparts.
        let s1 = create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "s1").unwrap().0;
        let trash_other = trash.join("other.txt");
        fs::rename(ws.join("other.txt"), &trash_other).unwrap();
        fs::write(ws.join("keep.txt"), b"keep-mutated").unwrap();
        let r_sel = restore_snapshot_paths_with_vault(&ws, Some(&vault), &s1.id, false, &[String::from("keep.txt")]).unwrap();
        assert_eq!(r_sel.trash_cleanup, crate::trash::TrashCleanupStatus::NotInTrash);
        assert_eq!(fs::read_to_string(ws.join("keep.txt")).unwrap(), "keep-v1");
        assert!(trash_other.exists(), "unrelated trashed file must stay intact in Trash");

        // P0-2: NestedIgnoredGuard must drop staged ignored dir if parent dir did not exist in snapshot.
        fs::create_dir_all(ws.join("new_subpkg/node_modules/pkg")).unwrap();
        fs::write(ws.join("new_subpkg/node_modules/pkg/index.js"), b"x").unwrap();
        fs::write(ws.join("new_subpkg/mod.rs"), b"v1").unwrap();
        let r_full = restore_snapshot_with_vault(&ws, Some(&vault), &s1.id, false).unwrap();
        assert_eq!(r_full.snapshot_id, s1.id);
        assert!(!ws.join("new_subpkg").exists());

        // P1-7: corrupting a file inside fast: vault tree must fail fast fingerprint verification.
        let (_, ws_vault) = crate::vault::resolve_workspace_vault_recovery(&ws, Some(&vault)).unwrap();
        let corrupted = ws_vault.join("snapshots").join(&s1.id).join("tree/keep.txt");
        let _ = fs::set_permissions(&corrupted, fs::Permissions::from_mode(0o644));
        fs::write(&corrupted, b"corrupted-vault-payload").unwrap();
        let corrupt_err = restore_snapshot_with_vault(&ws, Some(&vault), &s1.id, false).unwrap_err();
        assert_eq!(corrupt_err.code, crate::error::ERR_EINVAL);

        // P1-perf: diff_snapshot_fast detects added, modified, and deleted entries without SHA256.
        let ws_fast = sandbox.0.join("ws_fast");
        fs::create_dir_all(&ws_fast).unwrap();
        fs::write(ws_fast.join("a.rs"), b"aaa").unwrap();
        fs::write(ws_fast.join("b.rs"), b"bbb").unwrap();
        let sf = create_snapshot_fast_dedup_with_vault(&ws_fast, Some(&vault), "fast-diff").unwrap().0;
        fs::write(ws_fast.join("a.rs"), b"modified-aaa").unwrap();
        fs::remove_file(ws_fast.join("b.rs")).unwrap();
        fs::write(ws_fast.join("c.rs"), b"ccc").unwrap();
        let df = diff_snapshot_opts_with_vault(&ws_fast, Some(&vault), &sf.id, true).unwrap();
        assert_eq!(df.added, vec![String::from("c.rs")]);
        assert_eq!(df.modified, vec![String::from("a.rs")]);
        assert_eq!(df.deleted, vec![String::from("b.rs")]);
    }

    #[test]
    fn doctor_low_space_and_upgrade_codesign_identity_checks() {
        assert!(!crate::doctor::compute_doctor_ok(true, true, 500, true, 1.99));
        assert!(crate::doctor::compute_doctor_ok(true, true, 500, true, 2.00));

        let adhoc = crate::upgrade_verify::parse_codesign_identity(
            "Identifier=afuse\nTeamIdentifier=not set\nSignature=adhoc\n",
        );
        assert!(adhoc.team_id.is_none());
        let dev_id = crate::upgrade_verify::parse_codesign_identity(
            "Identifier=afuse\nAuthority=Developer ID Application: Studio (TEAM999999)\nTeamIdentifier=TEAM999999\n",
        );
        assert_eq!(dev_id.team_id.as_deref(), Some("TEAM999999"));
        let wrong_team = crate::upgrade_verify::parse_codesign_identity(
            "Authority=Developer ID Application: Other (TEAM000000)\nTeamIdentifier=TEAM000000\n",
        );
        let wrong_auth = crate::upgrade_verify::parse_codesign_identity(
            "Authority=Apple Development: Dev (TEAM999999)\nTeamIdentifier=TEAM999999\n",
        );

        assert!(crate::upgrade_verify::validate_candidate_codesign_identity(&adhoc, true, &dev_id).is_ok());
        assert!(crate::upgrade_verify::validate_candidate_codesign_identity(&dev_id, true, &dev_id).is_ok());
        assert!(crate::upgrade_verify::validate_candidate_codesign_identity(&dev_id, false, &dev_id).is_err());
        assert!(crate::upgrade_verify::validate_candidate_codesign_identity(&dev_id, true, &adhoc).is_err());
        assert!(crate::upgrade_verify::validate_candidate_codesign_identity(&dev_id, true, &wrong_team).is_err());
        assert!(crate::upgrade_verify::validate_candidate_codesign_identity(&dev_id, true, &wrong_auth).is_err());

        let sb = ScopedDir::new("probe-ver");
        let bin = sb.0.join("afuse-cand");
        compile_dummy_afuse_macho(&bin, "0.9.0");
        assert!(crate::upgrade_verify::probe_staged_version(&bin, Some("0.9.0")).is_ok());
        assert!(crate::upgrade_verify::probe_staged_version(&bin, Some("0.9.1")).is_err());
    }
