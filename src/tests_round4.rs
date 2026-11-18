#[cfg(test)]
mod tests_round4 {
    use crate::apfs::{force_remove_all, TMP_SEQ};
    use crate::error::{ERR_EINVAL, ERR_ENOENT, ERR_USAGE};
    use crate::hook_config::{render_hook_snippet, uninstall_hooks};
    use crate::sha256::sha256_hex;
    use crate::tests::{compile_dummy_afuse_macho, TestEnvGuard, ENV_LOCK};
    use crate::upgrade::{
        check_for_updates, is_trusted_github_url, parse_release_json, perform_upgrade_on_exe,
    };
    use std::env;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::Ordering;
    use std::thread;

    struct R4ScopedDir(PathBuf);
    impl R4ScopedDir {
        fn new(tag: &str) -> Self {
            let p = env::temp_dir().join(format!(
                "afuse-r4-{}-{}-{}",
                tag,
                std::process::id(),
                TMP_SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = force_remove_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(fs::canonicalize(&p).unwrap_or(p))
        }
    }
    impl Drop for R4ScopedDir {
        fn drop(&mut self) {
            let _ = force_remove_all(&self.0);
        }
    }

    fn make_tarball(archive_dir: &Path, payload_dir: &Path, entry: &str) {
        let tb = archive_dir.join("afuse-macos-universal.tar.gz");
        let st = Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&tb)
            .args(["-C"])
            .arg(payload_dir)
            .arg(entry)
            .status()
            .unwrap();
        assert!(st.success());
        let sha = sha256_hex(&fs::read(&tb).unwrap());
        fs::write(
            archive_dir.join("SHA256SUMS.txt"),
            format!("{}  afuse-macos-universal.tar.gz\n", sha),
        )
        .unwrap();
    }

    #[test]
    fn r4_upgrade_rejects_symlink_non_macho_and_applies_codesign_probe() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _eg = TestEnvGuard::clean(&["AFUSE_RELEASE_JSON_URL", "AFUSE_UPGRADE_ARCHIVE_DIR"]);
        let sb = R4ScopedDir::new("up-sec");

        let rel = sb.0.join("rel.json");
        fs::write(
            &rel,
            r#"{"tag_name":"v0.9.0","html_url":"https://github.com/topkyo/agent-fuse/releases/tag/v0.9.0","assets":[]}"#,
        )
        .unwrap();
        env::set_var("AFUSE_RELEASE_JSON_URL", format!("file://{}", rel.display()));

        let bin_dir = sb.0.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let exe = bin_dir.join("afuse");
        fs::write(&exe, b"OLD_STABLE_EXE").unwrap();

        // 1. Symlink payload pointing outside archive must be rejected
        let pay_sym = sb.0.join("pay-sym");
        let arch_sym = sb.0.join("arch-sym");
        fs::create_dir_all(&pay_sym).unwrap();
        fs::create_dir_all(&arch_sym).unwrap();
        symlink("/bin/echo", pay_sym.join("afuse")).unwrap();
        make_tarball(&arch_sym, &pay_sym, "afuse");
        env::set_var("AFUSE_UPGRADE_ARCHIVE_DIR", &arch_sym);
        let sym_err = perform_upgrade_on_exe(&exe).unwrap_err();
        assert_eq!(sym_err.code, ERR_ENOENT);
        assert_eq!(fs::read(&exe).unwrap(), b"OLD_STABLE_EXE");

        // 2. Symlink directory loop must fail cleanly without recursion hang
        let pay_loop = sb.0.join("pay-loop");
        let arch_loop = sb.0.join("arch-loop");
        fs::create_dir_all(&pay_loop).unwrap();
        fs::create_dir_all(&arch_loop).unwrap();
        symlink(".", pay_loop.join("loop")).unwrap();
        make_tarball(&arch_loop, &pay_loop, "loop");
        env::set_var("AFUSE_UPGRADE_ARCHIVE_DIR", &arch_loop);
        let loop_err = perform_upgrade_on_exe(&exe).unwrap_err();
        assert_eq!(loop_err.code, ERR_ENOENT);
        assert_eq!(fs::read(&exe).unwrap(), b"OLD_STABLE_EXE");

        // 3. Non-Mach-O plain text payload must be rejected by magic header check
        let pay_txt = sb.0.join("pay-txt");
        let arch_txt = sb.0.join("arch-txt");
        fs::create_dir_all(&pay_txt).unwrap();
        fs::create_dir_all(&arch_txt).unwrap();
        fs::write(pay_txt.join("afuse"), b"#!/bin/sh\necho fake\n").unwrap();
        make_tarball(&arch_txt, &pay_txt, "afuse");
        env::set_var("AFUSE_UPGRADE_ARCHIVE_DIR", &arch_txt);
        let txt_err = perform_upgrade_on_exe(&exe).unwrap_err();
        assert_eq!(txt_err.code, ERR_EINVAL);
        assert_eq!(fs::read(&exe).unwrap(), b"OLD_STABLE_EXE");

        // 4. Unsigned real Mach-O binary gets ad-hoc signed, passes --version probe, and runs cleanly
        let pay_real = sb.0.join("pay-real");
        let arch_real = sb.0.join("arch-real");
        fs::create_dir_all(&pay_real).unwrap();
        fs::create_dir_all(&arch_real).unwrap();
        let staged_payload = pay_real.join("afuse");
        compile_dummy_afuse_macho(&staged_payload, "0.9.0");
        let _ = Command::new("/usr/bin/codesign")
            .args(["--remove-signature"])
            .arg(&staged_payload)
            .status();
        make_tarball(&arch_real, &pay_real, "afuse");
        env::set_var("AFUSE_UPGRADE_ARCHIVE_DIR", &arch_real);

        let rep = perform_upgrade_on_exe(&exe).unwrap();
        assert!(rep.updated);
        assert_eq!(rep.release_state, "updated");
        assert!(Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict"])
            .arg(&exe)
            .status()
            .unwrap()
            .success());
        let ver_out = Command::new(&exe).arg("--version").output().unwrap();
        assert!(ver_out.status.success());
        assert_eq!(String::from_utf8_lossy(&ver_out.stdout).trim(), "afuse 0.9.0");
    }

    #[test]
    fn r4_upgrade_404_unpublished_app_preflight_and_json_edge_cases() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _eg = TestEnvGuard::clean(&["AFUSE_RELEASE_JSON_URL", "AFUSE_UPGRADE_ARCHIVE_DIR"]);
        let sb = R4ScopedDir::new("up-404");

        // App-bundled symlink refuses upgrade BEFORE attempting any network request
        env::set_var("AFUSE_RELEASE_JSON_URL", "http://127.0.0.1:1/must-not-connect");
        let app_bin = sb.0.join("AgentFuse.app/Contents/MacOS/afuse");
        fs::create_dir_all(app_bin.parent().unwrap()).unwrap();
        fs::write(&app_bin, b"APP").unwrap();
        let link_bin = sb.0.join("afuse");
        symlink(&app_bin, &link_bin).unwrap();
        let err = perform_upgrade_on_exe(&link_bin).unwrap_err();
        assert_eq!(err.code, ERR_USAGE);

        // HTTP 404 returns release_state="unpublished" in UpgradeApplyReport
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let h = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 23\r\nConnection: close\r\n\r\n{\"message\":\"Not Found\"}";
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        env::set_var("AFUSE_RELEASE_JSON_URL", format!("http://{}/latest", addr));
        let standalone = sb.0.join("standalone/afuse");
        fs::create_dir_all(standalone.parent().unwrap()).unwrap();
        fs::write(&standalone, b"OLD").unwrap();
        let rep404 = perform_upgrade_on_exe(&standalone).unwrap();
        h.join().unwrap();
        assert!(!rep404.updated);
        assert_eq!(rep404.release_state, "unpublished");
        assert!(rep404.to_json().contains("\"release_state\":\"unpublished\""));

        // JSON surrogate pair + \b\f escapes + malformed short \u12 + brace inside string before asset object
        let valid_json = r#"{"tag_name":"v0.9.1","body":"hi\b\f\uD83D\uDE80","assets":["{\"name\":\"decoy\"}",{"name":"afuse-macos-universal.tar.gz","browser_download_url":"https://github.com/topkyo/agent-fuse/releases/download/v0.9.1/afuse-macos-universal.tar.gz"}]}"#;
        let parsed = parse_release_json(valid_json).unwrap();
        assert_eq!(parsed.latest_version, "0.9.1");
        assert_eq!(parsed.assets.len(), 1);
        assert_eq!(parsed.assets[0].name, "afuse-macos-universal.tar.gz");

        let bad_escape_json = r#"{"tag_name":"v0.9\u12","html_url":"https://example.invalid"}"#;
        assert!(parse_release_json(bad_escape_json).is_err());
    }

    #[test]
    fn r4_hook_uninstall_unclosed_begin_mixed_readonly_and_home_dedup() {
        let sb = R4ScopedDir::new("hook-edges");
        let ws = sb.0.join("ws");
        fs::create_dir_all(&ws).unwrap();

        // 1. Unclosed BEGIN before valid block + mixed manual afuse hook line
        let home1 = sb.0.join("home1");
        fs::create_dir_all(home1.join(".claude")).unwrap();
        let snippet = render_hook_snippet("zsh").unwrap();
        let zshrc1 = home1.join(".zshrc");
        let content1 = format!(
            "export TOP=1\n# >>> afuse hook v1 >>>\nexport USER_SECRET_ENV=\"KEEP\"\n{}eval \"$(afuse hook zsh)\"\nexport BOT=1\n",
            snippet
        );
        fs::write(&zshrc1, content1).unwrap();

        let dry1 = uninstall_hooks(false, Some(&home1), &ws).unwrap();
        assert!(dry1.iter().any(|a| a.kind == "zsh_marker_block"));
        assert_eq!(dry1.iter().filter(|a| a.kind == "manual_shell_line").count(), 2);

        let app1 = uninstall_hooks(true, Some(&home1), &ws).unwrap();
        assert!(app1.iter().any(|a| a.kind == "zsh_marker_block" && a.applied));
        let after1 = fs::read_to_string(&zshrc1).unwrap();
        assert!(after1.contains("export USER_SECRET_ENV=\"KEEP\""));
        assert!(after1.contains("export TOP=1") && after1.contains("export BOT=1"));
        assert!(!after1.contains("_afuse_preexec"));

        // 2. Read-only 0444 .zshrc leaves zero orphan backup files on apply failure
        let home2 = sb.0.join("home2");
        fs::create_dir_all(&home2).unwrap();
        let zshrc2 = home2.join(".zshrc");
        fs::write(&zshrc2, &snippet).unwrap();
        fs::set_permissions(&zshrc2, PermissionsExt::from_mode(0o444)).unwrap();
        let ro_err = uninstall_hooks(true, Some(&home2), &ws).unwrap_err();
        assert!(ro_err.message.contains("permission") || ro_err.code != 0);
        let leftovers: Vec<_> = fs::read_dir(&home2)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains("afuse-bak"))
            .collect();
        assert!(leftovers.is_empty(), "leftover backups found: {:?}", leftovers);
        let _ = fs::set_permissions(&zshrc2, PermissionsExt::from_mode(0o644));

        // 3. Running with workspace == home deduplicates ~/.claude/settings.json
        let home3 = sb.0.join("home3");
        fs::create_dir_all(home3.join(".claude")).unwrap();
        fs::write(home3.join(".claude/settings.json"), render_hook_snippet("claude").unwrap()).unwrap();
        let dedup_actions = uninstall_hooks(false, Some(&home3), &home3).unwrap();
        let claude_hits = dedup_actions
            .iter()
            .filter(|a| a.kind == "manual_claude_settings_json")
            .count();
        assert_eq!(claude_hits, 1);
    }

    #[test]
    fn v060_dmg_urls_and_untrusted_host_filtering() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _eg = TestEnvGuard::clean(&["AFUSE_RELEASE_JSON_URL"]);

        assert!(is_trusted_github_url("https://github.com/topkyo/agent-fuse/releases/download/v0.6.0/AgentFuse-0.6.0-macos.dmg"));
        assert!(is_trusted_github_url("https://release-assets.githubusercontent.com/a/b"));
        assert!(!is_trusted_github_url("http://github.com/topkyo/agent-fuse/releases/download/v0.6.0/AgentFuse-0.6.0-macos.dmg"));
        assert!(!is_trusted_github_url("https://github.com@evil.invalid/AgentFuse-0.6.0-macos.dmg"));
        assert!(!is_trusted_github_url("https://evil.invalid/AgentFuse-0.6.0-macos.dmg"));

        let untrusted_rel = r#"{
          "tag_name":"v0.9.5",
          "html_url":"https://github.com/topkyo/agent-fuse/releases/tag/v0.9.5",
          "assets":[
            {"name":"AgentFuse-0.9.5-macos.dmg","browser_download_url":"https://evil.invalid/AgentFuse-0.9.5-macos.dmg"},
            {"name":"AgentFuse-0.9.5-macos.dmg.sha256","browser_download_url":"http://github.com/AgentFuse-0.9.5-macos.dmg.sha256"}
          ]
        }"#;
        let parsed_bad = parse_release_json(untrusted_rel).unwrap();
        assert_eq!(parsed_bad.dmg_url, None);
        assert_eq!(parsed_bad.dmg_sha256_url, None);

        let trusted_body = r#"{"tag_name":"v0.9.6","html_url":"https://github.com/topkyo/agent-fuse/releases/tag/v0.9.6","assets":[{"name":"AgentFuse-0.9.6-macos.dmg","browser_download_url":"https://github.com/topkyo/agent-fuse/releases/download/v0.9.6/AgentFuse-0.9.6-macos.dmg"},{"name":"AgentFuse-0.9.6-macos.dmg.sha256","browser_download_url":"https://objects.githubusercontent.com/agent-fuse/AgentFuse-0.9.6-macos.dmg.sha256"}]}"#;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body_clone = trusted_body.to_string();
        let h = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_clone.len(),
                    body_clone
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        env::set_var("AFUSE_RELEASE_JSON_URL", format!("http://{}/latest", addr));
        let rep = check_for_updates().unwrap();
        h.join().unwrap();
        assert_eq!(rep.dmg_url.as_deref(), Some("https://github.com/topkyo/agent-fuse/releases/download/v0.9.6/AgentFuse-0.9.6-macos.dmg"));
        assert_eq!(rep.dmg_sha256_url.as_deref(), Some("https://objects.githubusercontent.com/agent-fuse/AgentFuse-0.9.6-macos.dmg.sha256"));
        let rep_json = rep.to_json();
        assert!(rep_json.contains("\"dmg_url\":\"https://github.com/topkyo/agent-fuse/releases/download/v0.9.6/AgentFuse-0.9.6-macos.dmg\""));
        assert!(rep_json.contains("\"dmg_sha256_url\":\"https://objects.githubusercontent.com/agent-fuse/AgentFuse-0.9.6-macos.dmg.sha256\""));
    }
}
