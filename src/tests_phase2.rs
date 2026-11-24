#[cfg(test)]
mod tests_phase2 {
    use crate::apfs::force_remove_all;
    use crate::error::{ERR_EINVAL, EXIT_FUSE_TRIPPED};
    use crate::guard::{run_guarded_command_with_vault, GuardConfig};
    use crate::hook::{
        is_readonly_bash_command, parse_claude_hook_json, run_claude_hook_exec_from_reader,
    };
    use crate::restore::{restore_snapshot_paths_with_vault, restore_snapshot_with_vault};
    use crate::sha256::sha256_hex;
    use crate::snapshot::{
        create_snapshot_with_vault, diff_snapshot_with_vault, list_snapshots_with_vault,
    };
    use crate::tests::{compile_dummy_afuse_macho, TestEnvGuard, ENV_LOCK};
    use crate::unicode_norm::{canonical_rel_key, to_nfd};
    use crate::upgrade::{
        parse_release_json, perform_upgrade_on_exe, validate_release_asset_url,
    };
    use std::env;
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct ScopedDir(PathBuf);
    impl ScopedDir {
        fn new(prefix: &str) -> Self {
            let ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
            let base = env::temp_dir().join(format!("afuse-p2-{}-{}-{}", prefix, std::process::id(), ns));
            fs::create_dir_all(&base).unwrap();
            Self(base)
        }
    }
    impl Drop for ScopedDir {
        fn drop(&mut self) {
            fn unlock_all(p: &std::path::Path) {
                let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
                if let Ok(rd) = fs::read_dir(p) {
                    for e in rd.flatten() { unlock_all(&e.path()); }
                }
            }
            unlock_all(&self.0);
            let _ = force_remove_all(&self.0);
        }
    }

    #[test]
    fn k_r1_preserves_nested_ignored_subtrees_and_k_r3_0555_selective() {
        let sb = ScopedDir::new("kr1-kr3");
        let ws = sb.0.join("mono");
        let vault = sb.0.join("vault");
        fs::create_dir_all(ws.join("apps/web/node_modules/pkg")).unwrap();
        fs::create_dir_all(ws.join("crates/core/target/debug")).unwrap();
        fs::create_dir_all(ws.join("ro_sub/deep")).unwrap();
        fs::write(ws.join("apps/web/index.ts"), b"v1").unwrap();
        fs::write(ws.join("apps/web/node_modules/pkg/index.js"), b"dep-keep").unwrap();
        fs::write(ws.join("crates/core/target/debug/lib.a"), b"target-keep").unwrap();
        fs::write(ws.join("ro_sub/deep/keep.txt"), b"ro-v1").unwrap();

        let base = create_snapshot_with_vault(&ws, Some(&vault), "base").unwrap();
        fs::write(ws.join("apps/web/index.ts"), b"mutated").unwrap();
        fs::write(ws.join("apps/web/extra.ts"), b"junk").unwrap();

        let rep = restore_snapshot_with_vault(&ws, Some(&vault), &base.id, false).unwrap();
        assert_eq!(rep.root_inode_before, rep.root_inode_after);
        assert_eq!(fs::read_to_string(ws.join("apps/web/index.ts")).unwrap(), "v1");
        assert!(!ws.join("apps/web/extra.ts").exists());
        assert_eq!(fs::read_to_string(ws.join("apps/web/node_modules/pkg/index.js")).unwrap(), "dep-keep");
        assert_eq!(fs::read_to_string(ws.join("crates/core/target/debug/lib.a")).unwrap(), "target-keep");

        fs::write(ws.join("ro_sub/deep/keep.txt"), b"ro-broken").unwrap();
        fs::set_permissions(ws.join("ro_sub/deep"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(ws.join("ro_sub"), fs::Permissions::from_mode(0o555)).unwrap();
        restore_snapshot_paths_with_vault(
            &ws, Some(&vault), &base.id, false, &["ro_sub/deep/keep.txt".to_string()],
        ).unwrap();
        assert_eq!(fs::read_to_string(ws.join("ro_sub/deep/keep.txt")).unwrap(), "ro-v1");
        let m_sub = fs::symlink_metadata(ws.join("ro_sub")).unwrap().permissions().mode() & 0o777;
        let m_deep = fs::symlink_metadata(ws.join("ro_sub/deep")).unwrap().permissions().mode() & 0o777;
        assert_eq!((m_sub, m_deep), (0o555, 0o555));
    }

    #[test]
    fn k_r2_single_file_0444_backup_0555_parent_and_missing_inode_consistency() {
        let sb = ScopedDir::new("kr2");
        let dir = sb.0.join("locked_dir");
        let vault = sb.0.join("vault");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("secret.key");
        fs::write(&file, b"v1-key").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();

        let snap = create_snapshot_with_vault(&file, Some(&vault), "base").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&file, b"v2-dirty").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();

        let rep = restore_snapshot_with_vault(&file, Some(&vault), &snap.id, true).unwrap();
        assert_ne!(rep.root_inode_before, 0);
        assert_eq!(rep.root_inode_before, rep.root_inode_after);
        assert_eq!(fs::read_to_string(&file).unwrap(), "v1-key");
        assert_eq!(fs::symlink_metadata(&file).unwrap().permissions().mode() & 0o777, 0o444);
        assert_eq!(fs::symlink_metadata(&dir).unwrap().permissions().mode() & 0o777, 0o555);

        let pre_id = rep.safety_snapshot_id.unwrap();
        let (_, ws_vault) = crate::vault::resolve_workspace_vault_recovery(&file, Some(&vault)).unwrap();
        let pre_file = ws_vault.join("snapshots").join(pre_id).join("tree/secret.key");
        assert_eq!(fs::symlink_metadata(&pre_file).unwrap().permissions().mode() & 0o777, 0o444);
        assert_eq!(fs::read_to_string(&pre_file).unwrap(), "v2-dirty");

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_file(&file).unwrap();
        let rep2 = restore_snapshot_with_vault(&file, Some(&vault), &snap.id, false).unwrap();
        assert_ne!(rep2.root_inode_before, 0);
        assert_eq!(rep2.root_inode_before, rep2.root_inode_after);
        assert_eq!(fs::read_to_string(&file).unwrap(), "v1-key");
    }

    #[test]
    fn k_u1_unicode_nfd_nfc_normalization_and_diff_selective_restore() {
        assert_eq!(canonical_rel_key("caf\u{00e9}.txt"), canonical_rel_key("cafe\u{0301}.txt"));
        assert_eq!(to_nfd("が"), to_nfd("か\u{3099}"));
        assert_eq!(to_nfd("한"), "\u{1112}\u{1161}\u{11AB}");

        let sb = ScopedDir::new("ku1");
        let ws = sb.0.join("ws");
        let vault = sb.0.join("vault");
        fs::create_dir_all(&ws).unwrap();
        let nfd_name = "cafe\u{0301}.txt";
        fs::write(ws.join(nfd_name), b"espresso").unwrap();
        let snap = create_snapshot_with_vault(&ws, Some(&vault), "nfd").unwrap();

        fs::remove_file(ws.join(nfd_name)).unwrap();
        fs::write(ws.join("caf\u{00e9}.txt"), b"espresso").unwrap();
        let d = diff_snapshot_with_vault(&ws, Some(&vault), &snap.id).unwrap();
        assert!(d.added.is_empty() && d.deleted.is_empty() && d.modified.is_empty());

        fs::remove_file(ws.join("caf\u{00e9}.txt")).unwrap();
        restore_snapshot_paths_with_vault(
            &ws, Some(&vault), &snap.id, false, &["caf\u{00e9}.txt".to_string()],
        ).unwrap();
        let disk_names: Vec<String> = fs::read_dir(&ws).unwrap().flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(disk_names, vec![nfd_name.to_string()]);
    }

    #[test]
    fn k_g1_g2_g3_guard_single_file_git_objects_and_bulk_truncation() {
        let sb = ScopedDir::new("guard-p2");
        let vault = sb.0.join("vault");

        let single = sb.0.join("solo.env");
        fs::write(&single, b"SECRET_TOKEN=xyz\n").unwrap();
        let g1 = GuardConfig { max_delete: 20, max_write_mb: 0, poll_ms: 10, auto_rollback: true };
        let r1 = run_guarded_command_with_vault(
            &single, Some(&vault), &g1, &["/bin/sh".into(), "-c".into(), ": > solo.env".into()],
        ).unwrap();
        assert!(r1.tripped && r1.exit_code == EXIT_FUSE_TRIPPED && r1.auto_restored);
        assert_eq!(fs::read_to_string(&single).unwrap(), "SECRET_TOKEN=xyz\n");

        let ws = sb.0.join("repo");
        fs::create_dir_all(ws.join(".git/objects/ab")).unwrap();
        fs::write(ws.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(ws.join(".git/packed-refs"), b"0000 refs/heads/main\n").unwrap();
        fs::write(ws.join(".git/objects/ab/cd"), b"obj").unwrap();
        for i in 0..5 { fs::write(ws.join(format!("f{}.txt", i)), b"non-empty-data").unwrap(); }

        let g2 = GuardConfig { max_delete: 1, max_write_mb: 0, poll_ms: 10, auto_rollback: true };
        let r2 = run_guarded_command_with_vault(
            &ws, Some(&vault), &g2, &["/bin/rm".into(), "-f".into(), ".git/packed-refs".into()],
        ).unwrap();
        assert!(r2.tripped && r2.auto_restored && ws.join(".git/packed-refs").is_file());

        let g3 = GuardConfig { max_delete: 3, max_write_mb: 0, poll_ms: 10, auto_rollback: true };
        let r3 = run_guarded_command_with_vault(
            &ws, Some(&vault), &g3, &["/bin/sh".into(), "-c".into(), "for f in f*.txt; do : > \"$f\"; done".into()],
        ).unwrap();
        assert!(r3.tripped && r3.auto_restored);
        assert_eq!(fs::read_to_string(ws.join("f0.txt")).unwrap(), "non-empty-data");
    }

    #[test]
    fn k_h1_to_h4_hooks_surrogate_subtarget_bash_filters_and_mcp() {
        let _lock = ENV_LOCK.lock().unwrap();
        let p = parse_claude_hook_json(r#"{"cwd":"/tmp/w","tool_name":"Write","tool_input":{"file_path":"a/\uD83D\uDCA5.txt"}}"#);
        assert_eq!(p.candidate_paths, vec!["a/\u{1F4A5}.txt"]);

        assert!(!is_readonly_bash_command("rg --pre=rm foo"));
        assert!(!is_readonly_bash_command("git branch -C main evil"));
        assert!(!is_readonly_bash_command("git branch --set-upstream-to=origin/main"));
        assert!(is_readonly_bash_command("rg --color=never fn src/"));
        assert!(is_readonly_bash_command("git branch --list"));

        let sb = ScopedDir::new("hook-p2");
        let vault = sb.0.join("vault");
        let docs = sb.0.join("docs");
        fs::create_dir_all(&docs).unwrap();
        let target = docs.join("important.md");
        fs::write(&target, b"original-doc").unwrap();
        create_snapshot_with_vault(&target, Some(&vault), "bound").unwrap();

        let prev_dis = env::var_os("AFUSE_HOOK_DISABLE");
        let prev_grd = env::var_os("AFUSE_GUARDED");
        let prev_thr = env::var_os("AFUSE_HOOK_THROTTLE_MS");
        env::remove_var("AFUSE_HOOK_DISABLE");
        env::remove_var("AFUSE_GUARDED");
        env::set_var("AFUSE_HOOK_THROTTLE_MS", "0");

        let json_ro = format!(r#"{{"cwd":"{}","tool_name":"mcp__filesystem__read_file","tool_input":{{"path":"important.md"}}}}"#, docs.display());
        assert!(run_claude_hook_exec_from_reader(Cursor::new(json_ro), Some(&vault)).is_none());

        let json_mcp_w = format!(r#"{{"cwd":"{}","tool_name":"mcp__filesystem__write_file","tool_input":{{"file_path":"important.md"}}}}"#, docs.display());
        let deduped = run_claude_hook_exec_from_reader(Cursor::new(&json_mcp_w), Some(&vault)).expect("deduped mcp write");
        assert!(deduped.workspace.ends_with("important.md"));
        assert_eq!(list_snapshots_with_vault(&target, Some(&vault)).unwrap().len(), 1);
        fs::write(&target, b"modified-doc").unwrap();
        let snapped = run_claude_hook_exec_from_reader(Cursor::new(json_mcp_w), Some(&vault)).expect("bound subfile via mcp write");
        assert!(snapped.workspace.ends_with("important.md"));
        assert_eq!(list_snapshots_with_vault(&target, Some(&vault)).unwrap().len(), 2);

        if let Some(v) = prev_dis { env::set_var("AFUSE_HOOK_DISABLE", v); } else { env::remove_var("AFUSE_HOOK_DISABLE"); }
        if let Some(v) = prev_grd { env::set_var("AFUSE_GUARDED", v); } else { env::remove_var("AFUSE_GUARDED"); }
        if let Some(v) = prev_thr { env::set_var("AFUSE_HOOK_THROTTLE_MS", v); } else { env::remove_var("AFUSE_HOOK_THROTTLE_MS"); }
    }

    #[test]
    fn k_up1_to_up3_upgrade_url_draft_filter_and_symlink_target() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _eg = TestEnvGuard::clean(&["AFUSE_RELEASE_JSON_URL", "AFUSE_UPGRADE_ARCHIVE_DIR"]);
        assert!(validate_release_asset_url("https://github.com/topkyo/agent-fuse/releases/download/v0.9.0/afuse.tar.gz").is_ok());
        assert!(validate_release_asset_url("https://objects.githubusercontent.com/github-production-release-asset/foo").is_ok());
        assert!(validate_release_asset_url("https://release-assets.githubusercontent.com/foo").is_ok());
        assert_eq!(validate_release_asset_url("http://github.com/foo").unwrap_err().code, ERR_EINVAL);
        assert_eq!(validate_release_asset_url("https://evil.example/foo").unwrap_err().code, ERR_EINVAL);
        assert_eq!(validate_release_asset_url("https://github.com@evil.com/foo").unwrap_err().code, ERR_EINVAL);

        assert_eq!(parse_release_json(r#"{"tag_name":"v0.9.0","draft":true}"#).unwrap_err().code, ERR_EINVAL);
        assert_eq!(parse_release_json(r#"{"tag_name":"v0.9.0","prerelease":true}"#).unwrap_err().code, ERR_EINVAL);

        let sb = ScopedDir::new("up-sym");
        let real_dir = sb.0.join("cellar/bin");
        let link_dir = sb.0.join("local/bin");
        let payload = sb.0.join("payload");
        let archive = sb.0.join("archive");
        for d in [&real_dir, &link_dir, &payload, &archive] { fs::create_dir_all(d).unwrap(); }
        let real_exe = real_dir.join("afuse");
        let link_exe = link_dir.join("afuse");
        fs::write(&real_exe, b"OLD_BIN").unwrap();
        std::os::unix::fs::symlink(&real_exe, &link_exe).unwrap();
        compile_dummy_afuse_macho(&payload.join("afuse"), "0.9.0");
        let tb = archive.join("afuse-macos-universal.tar.gz");
        assert!(Command::new("/usr/bin/tar").args(["-czf"]).arg(&tb).args(["-C"]).arg(&payload).arg("afuse").status().unwrap().success());
        let sha = sha256_hex(&fs::read(&tb).unwrap());
        fs::write(archive.join("SHA256SUMS.txt"), format!("{}  afuse-macos-universal.tar.gz\n", sha)).unwrap();
        let rel = sb.0.join("rel.json");
        fs::write(&rel, r#"{"tag_name":"v0.9.0","html_url":"https://github.com/topkyo/agent-fuse/releases/tag/v0.9.0","assets":[]}"#).unwrap();

        env::set_var("AFUSE_RELEASE_JSON_URL", format!("file://{}", rel.display()));
        env::set_var("AFUSE_UPGRADE_ARCHIVE_DIR", &archive);
        let rep = perform_upgrade_on_exe(&link_exe).unwrap();
        assert!(rep.updated);
        assert!(fs::symlink_metadata(&link_exe).unwrap().file_type().is_symlink());
        let out = Command::new(&real_exe).arg("--version").output().unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "afuse 0.9.0");
    }

    #[test]
    fn f1_and_o1_block_remote_file_url_bypass_and_untrusted_redirect_host() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _eg = TestEnvGuard::clean(&["AFUSE_RELEASE_JSON_URL", "AFUSE_UPGRADE_ARCHIVE_DIR"]);

        let sb = ScopedDir::new("f1-o1-sec");
        let bin_dir = sb.0.join("bin");
        let evil_dir = sb.0.join("evil");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&evil_dir).unwrap();
        let target_exe = bin_dir.join("afuse");
        fs::write(&target_exe, b"ORIG_BIN").unwrap();
        let marker = sb.0.join("pwned.marker");
        let evil_bin = evil_dir.join("afuse");
        fs::write(&evil_bin, format!("#!/bin/sh\necho PWN > \"{}\"\necho afuse 0.9.9\n", marker.display())).unwrap();
        let tb = evil_dir.join("afuse-macos-universal.tar.gz");
        assert!(Command::new("/usr/bin/tar").args(["-czf"]).arg(&tb).args(["-C"]).arg(&evil_dir).arg("afuse").status().unwrap().success());
        let sha = sha256_hex(&fs::read(&tb).unwrap());
        let sums = evil_dir.join("SHA256SUMS.txt");
        fs::write(&sums, format!("{}  afuse-macos-universal.tar.gz\n", sha)).unwrap();

        for (tb_url, sum_url) in [
            (format!("file://{}", tb.display()), format!("file://{}", sums.display())),
            (tb.to_string_lossy().into_owned(), sums.to_string_lossy().into_owned()),
        ] {
            let rel = sb.0.join("rel-evil.json");
            let json = format!(
                "{{\"tag_name\":\"v0.9.9\",\"html_url\":\"https://github.com/topkyo/agent-fuse/releases/tag/v0.9.9\",\"assets\":[{{\"name\":\"afuse-macos-universal.tar.gz\",\"browser_download_url\":\"{}\"}},{{\"name\":\"SHA256SUMS.txt\",\"browser_download_url\":\"{}\"}}]}}",
                tb_url, sum_url
            );
            fs::write(&rel, json).unwrap();
            env::set_var("AFUSE_RELEASE_JSON_URL", format!("file://{}", rel.display()));
            let err = perform_upgrade_on_exe(&target_exe).unwrap_err();
            assert_eq!(err.code, ERR_EINVAL);
            assert!(!marker.exists(), "malicious payload must never execute");
            assert_eq!(fs::read(&target_exe).unwrap(), b"ORIG_BIN");
        }

        let staged = sb.0.join("staged.tar.gz");
        fs::write(&staged, b"valid").unwrap();
        assert!(crate::upgrade::validate_effective_download_url(
            "https://objects.githubusercontent.com/github-production-release-asset/1/a.tar.gz",
            &staged
        ).is_ok());
        assert!(crate::upgrade::validate_effective_download_url(
            "https://github-releases.githubusercontent.com/1/a.tar.gz",
            &staged
        ).is_ok());
        assert!(staged.exists());

        let redir_err = crate::upgrade::validate_effective_download_url(
            "https://evil.example.com/a.tar.gz",
            &staged
        ).unwrap_err();
        assert_eq!(redir_err.code, ERR_EINVAL);
        assert!(!staged.exists(), "untrusted post-redirect download must delete staged file");

        fs::write(&staged, b"downgraded").unwrap();
        let http_err = crate::upgrade::validate_effective_download_url(
            "http://objects.githubusercontent.com/a.tar.gz",
            &staged
        ).unwrap_err();
        assert_eq!(http_err.code, ERR_EINVAL);
        assert!(!staged.exists());
    }
}
