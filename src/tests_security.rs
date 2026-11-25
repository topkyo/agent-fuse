#[cfg(test)]
mod sec_tests {
    use crate::apfs::{
        acquire_flock_blocking, chmod_nofollow, force_remove_all, force_unlock, release_flock,
        TMP_SEQ,
    };
    use crate::error::{ERR_EINVAL, EXIT_FUSE_TRIPPED};
    use crate::guard::{run_guarded_command_with_vault, GuardConfig};
    use crate::hook::{execute_hook_auto_snap, is_readonly_bash_command};
    use crate::hook_config::{render_hook_snippet, uninstall_hooks};
    use crate::meta::read_meta;
    use crate::relocate::{inspect_vault_orphans, prune_orphan_vaults_with};
    use crate::restore::restore_snapshot_with_vault;
    use crate::snapshot::{create_snapshot_with_vault, list_snapshots_with_vault};
    use crate::trash::validate_custom_trash_dir;
    use crate::upgrade_json::{
        parse_release_json, validate_effective_asset_url, validate_release_asset_url,
    };
    use crate::upgrade_tar::preflight_tar_listing;
    use crate::upgrade_verify::{
        find_extracted_afuse, parse_codesign_identity, validate_candidate_codesign_identity,
    };
    use crate::vault::resolve_workspace_vault_recovery;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::Ordering;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct SecDir(PathBuf);
    impl SecDir {
        fn new(tag: &str) -> Self {
            let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let p = PathBuf::from(format!(
                "/tmp/afuse-sec-{}-{}-{}",
                tag,
                std::process::id(),
                seq
            ));
            let _ = force_remove_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for SecDir {
        fn drop(&mut self) {
            let _ = force_remove_all(&self.0);
        }
    }

    #[test]
    fn meta_id_traversal_and_dirname_mismatch_rejected() {
        let sb = SecDir::new("meta-id");
        let ws = sb.0.join("ws");
        let vault = sb.0.join("vault");
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("a.txt"), b"ok").unwrap();
        let snap = create_snapshot_with_vault(&ws, Some(&vault), "base").unwrap();
        let (_, ws_vault) = resolve_workspace_vault_recovery(&ws, Some(&vault)).unwrap();
        let meta_p = ws_vault.join("snapshots").join(&snap.id).join("meta.kv");
        let orig = fs::read_to_string(&meta_p).unwrap();

        let traversal = orig.replace(&snap.id, "snap-1/../../escape");
        fs::write(&meta_p, &traversal).unwrap();
        assert_eq!(read_meta(&meta_p).unwrap_err().code, ERR_EINVAL);
        assert!(list_snapshots_with_vault(&ws, Some(&vault)).unwrap().is_empty());

        let mismatch = orig.replace(&snap.id, "snap-99999999-beef");
        fs::write(&meta_p, &mismatch).unwrap();
        assert!(read_meta(&meta_p).is_ok());
        assert!(list_snapshots_with_vault(&ws, Some(&vault)).unwrap().is_empty());

        let legacy_fast = orig
            .lines()
            .map(|l| if l.starts_with("tree_sha256=") { "tree_sha256=fast" } else { l })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(&meta_p, legacy_fast).unwrap();
        let err = restore_snapshot_with_vault(&ws, Some(&vault), &snap.id, false).unwrap_err();
        assert_eq!(err.code, ERR_EINVAL);
    }

    #[test]
    fn upgrade_tar_preflight_and_url_codesign_boundaries() {
        assert!(preflight_tar_listing(
            "-rwxr-xr-x  0 root wheel 1048576 Nov 26 00:40 afuse\n"
        )
        .is_ok());
        assert!(preflight_tar_listing(
            "-rwxr-xr-x  0 root wheel 1048576 Nov 26 00:40 /etc/afuse\n"
        )
        .is_err());
        assert!(preflight_tar_listing(
            "-rwxr-xr-x  0 root wheel 1048576 Nov 26 00:40 ../afuse\n"
        )
        .is_err());
        assert!(preflight_tar_listing(
            "lrwxr-xr-x  0 root wheel 0 Nov 26 00:40 bin -> /tmp\n-rwxr-xr-x  0 root wheel 100 Nov 26 00:40 bin/afuse\n"
        )
        .is_err());
        assert!(preflight_tar_listing(
            "hrwxr-xr-x  0 root wheel 0 Nov 26 00:40 afuse link to /bin/sh\n"
        )
        .is_err());
        assert!(preflight_tar_listing(
            "-rwxr-xr-x  0 root wheel 40000000 Nov 26 00:40 afuse\n"
        )
        .is_err());

        let sb = SecDir::new("tar-sym");
        let ext = sb.0.join("ext");
        let outside = sb.0.join("outside");
        fs::create_dir_all(&ext).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("afuse"), b"evil").unwrap();
        symlink(&outside, ext.join("bin")).unwrap();
        assert!(find_extracted_afuse(&ext).is_none());

        assert!(validate_release_asset_url(
            "https://github.com/topkyo/agent-fuse/releases/download/v0.7.0/afuse.tar.gz"
        )
        .is_ok());
        assert!(validate_release_asset_url(
            "https://github.com:443/topkyo/agent-fuse/releases/download/v0.7.0/afuse.tar.gz"
        )
        .is_ok());
        assert!(validate_release_asset_url(
            "https://github.com:8443/topkyo/agent-fuse/releases/download/v0.7.0/afuse.tar.gz"
        )
        .is_err());
        assert!(validate_release_asset_url(
            "https://objects.githubusercontent.com/attacker/afuse.tar.gz"
        )
        .is_err());
        assert!(validate_effective_asset_url(
            "https://objects.githubusercontent.com/github-production-release-asset/afuse.tar.gz"
        )
        .is_ok());

        let evil_rel = parse_release_json(
            r#"{"tag_name":"v0.7.0","html_url":"file:///Applications/Calculator.app","assets":[]}"#,
        )
        .unwrap();
        assert_eq!(evil_rel.html_url, "https://github.com/topkyo/agent-fuse/releases");

        let host = parse_codesign_identity(
            "Identifier=afuse\nAuthority=Developer ID Application: Studio (TEAM123456)\nTeamIdentifier=TEAM123456\n",
        );
        let wrong_ident = parse_codesign_identity(
            "Identifier=other-tool\nAuthority=Developer ID Application: Studio (TEAM123456)\nTeamIdentifier=TEAM123456\n",
        );
        assert_eq!(
            validate_candidate_codesign_identity(&host, true, &wrong_ident)
                .unwrap_err()
                .code,
            ERR_EINVAL
        );
    }

    #[test]
    fn symlink_toctou_nofollow_and_flock_protection() {
        let sb = SecDir::new("sym-guards");
        let ext_dir = sb.0.join("external_precious");
        fs::create_dir_all(&ext_dir).unwrap();
        let ext_file = ext_dir.join("keep.txt");
        fs::write(&ext_file, b"precious").unwrap();
        fs::set_permissions(&ext_file, fs::Permissions::from_mode(0o400)).unwrap();

        let dir_to_delete = sb.0.join("del_me");
        fs::create_dir_all(&dir_to_delete).unwrap();
        symlink(&ext_dir, dir_to_delete.join("link_to_ext")).unwrap();
        force_remove_all(&dir_to_delete).unwrap();
        assert!(ext_file.is_file(), "external dir behind symlink must survive");

        let sym_file = sb.0.join("sym_to_ext_file");
        symlink(&ext_file, &sym_file).unwrap();
        assert!(chmod_nofollow(&sym_file, 0o777).is_err());
        force_unlock(&sym_file);
        let ext_mode = fs::symlink_metadata(&ext_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(ext_mode, 0o400, "symlink target mode must remain untouched");

        let plain = sb.0.join("suid_test");
        fs::write(&plain, b"bin").unwrap();
        chmod_nofollow(&plain, 0o4755).unwrap();
        let stripped = fs::symlink_metadata(&plain).unwrap().permissions().mode() & 0o7777;
        assert_eq!(stripped, 0o755, "SUID/SGID/Sticky bits must be stripped");

        let lock_target = sb.0.join("real_target");
        fs::write(&lock_target, b"stay").unwrap();
        let sym_lock = sb.0.join("vault.lock");
        symlink(&lock_target, &sym_lock).unwrap();
        assert!(acquire_flock_blocking(&sym_lock).is_err());

        let good_lock = sb.0.join("good.lock");
        let fd = acquire_flock_blocking(&good_lock).unwrap();
        release_flock(fd);
    }

    #[test]
    fn guard_trips_when_files_hidden_into_ignored_dir_and_skips_git_symlink() {
        let sb = SecDir::new("guard-hide");
        let ws = sb.0.join("ws");
        let vault = sb.0.join("vault");
        let outside_git = sb.0.join("outside_git");
        fs::create_dir_all(&ws).unwrap();
        fs::create_dir_all(&outside_git).unwrap();
        fs::write(outside_git.join("secret.txt"), b"x").unwrap();
        symlink(&outside_git, ws.join(".git")).unwrap();
        fs::create_dir_all(ws.join("node_modules")).unwrap();
        fs::write(ws.join("a.rs"), b"fn a() {}").unwrap();
        fs::write(ws.join("b.rs"), b"fn b() {}").unwrap();

        let cfg = GuardConfig {
            max_delete: 2,
            max_write_mb: 0,
            poll_ms: 10,
            auto_rollback: true,
        };
        let rep = run_guarded_command_with_vault(
            &ws,
            Some(&vault),
            &cfg,
            &[
                "sh".into(),
                "-c".into(),
                "mv a.rs node_modules/a.rs && mv b.rs node_modules/b.rs".into(),
            ],
        )
        .unwrap();
        assert!(rep.tripped, "hiding files in node_modules must trip guard");
        assert_eq!(rep.exit_code, EXIT_FUSE_TRIPPED);
        assert!(ws.join("a.rs").is_file() && ws.join("b.rs").is_file());
    }

    #[test]
    fn trash_dir_guard_and_orphan_vault_marker_safety() {
        let sb = SecDir::new("trash-orphan");
        let ws = sb.0.join("ws");
        fs::create_dir_all(&ws).unwrap();
        let euid = crate::apfs::current_euid();
        let home = crate::apfs::real_home_dir().ok();

        assert!(validate_custom_trash_dir("/", home.as_deref(), Some(&ws), euid).is_none());
        assert!(validate_custom_trash_dir("/System", home.as_deref(), Some(&ws), euid).is_none());
        assert!(validate_custom_trash_dir("/Applications", home.as_deref(), Some(&ws), euid).is_none());
        assert!(validate_custom_trash_dir(&ws.to_string_lossy(), home.as_deref(), Some(&ws), euid).is_none());
        assert!(validate_custom_trash_dir(&sb.0.to_string_lossy(), home.as_deref(), Some(&ws), euid).is_none());
        if let Some(ref h) = home {
            assert!(validate_custom_trash_dir(&h.to_string_lossy(), home.as_deref(), Some(&ws), euid).is_none());
        }
        let sym_trash = sb.0.join("sym_trash");
        let real_trash = sb.0.join("ok_trash");
        fs::create_dir_all(&real_trash).unwrap();
        symlink(&real_trash, &sym_trash).unwrap();
        assert!(validate_custom_trash_dir(&sym_trash.to_string_lossy(), home.as_deref(), Some(&ws), euid).is_none());
        assert!(validate_custom_trash_dir(&real_trash.to_string_lossy(), home.as_deref(), Some(&ws), euid).is_some());

        let ordinary_root = sb.0.join("ordinary_projects");
        let precious_sub = ordinary_root.join("my_app");
        fs::create_dir_all(&precious_sub).unwrap();
        fs::write(precious_sub.join("code.rs"), b"keep").unwrap();
        let (scanned, orphans) = inspect_vault_orphans(Some(&ordinary_root), 0);
        assert_eq!(scanned, 0);
        assert!(orphans.is_empty());
        let pr = prune_orphan_vaults_with(Some(&ordinary_root), 0, false).unwrap();
        assert_eq!(pr.removed, 0);
        assert!(precious_sub.join("code.rs").is_file());
    }

    #[test]
    fn hook_hardening_future_stamp_and_hetero_backup() {
        assert!(!is_readonly_bash_command("git branch new-feature"));
        assert!(!is_readonly_bash_command("git branch -Df old"));
        assert!(!is_readonly_bash_command("git diff -o/tmp/out.patch"));
        assert!(!is_readonly_bash_command("git log -n5"));
        assert!(is_readonly_bash_command("git branch --show-current"));
        assert!(is_readonly_bash_command("git branch -a"));

        let zsh = render_hook_snippet("zsh").unwrap();
        assert!(zsh.contains("emulate -L zsh"));
        assert!(zsh.find("/Applications/AgentFuse.app/Contents/MacOS/afuse").unwrap() < zsh.find("command -v afuse").unwrap());

        let sb = SecDir::new("hook-hetero");
        let fake_home = sb.0.join("home");
        let real_rc = sb.0.join("outside.rc");
        fs::create_dir_all(&fake_home).unwrap();
        fs::write(&real_rc, format!("export A=1\n{}", zsh)).unwrap();
        symlink(&real_rc, fake_home.join(".zshrc")).unwrap();
        assert_eq!(
            uninstall_hooks(true, Some(&fake_home), Path::new("/tmp"))
                .unwrap_err()
                .code,
            ERR_EINVAL
        );

        let ws = sb.0.join("ws");
        let vault = sb.0.join("vault");
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(ws.join("a.txt"), b"v1").unwrap();
        let snap = create_snapshot_with_vault(&ws, Some(&vault), "base").unwrap();
        let (_, ws_vault) = resolve_workspace_vault_recovery(&ws, Some(&vault)).unwrap();
        let future_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            + 3_600_000;
        let stamp_p = ws_vault.join("hook_last_snap.stamp");
        fs::write(&stamp_p, format!("{}\n", future_ms)).unwrap();
        fs::write(ws.join("a.txt"), b"v2").unwrap();
        let got = execute_hook_auto_snap(&ws, "auto:hook:future", Some(&vault), 60_000).unwrap();
        assert!(got.is_some(), "future timestamp must not suppress hook snapshot");
        let rewritten: u128 = fs::read_to_string(&stamp_p).unwrap().trim().parse().unwrap();
        assert!(rewritten < future_ms);

        force_remove_all(&ws).unwrap();
        fs::write(&ws, b"user-important-hetero-file").unwrap();
        restore_snapshot_with_vault(&ws, Some(&vault), &snap.id, true).unwrap();
        assert!(ws.is_dir());
        assert_eq!(fs::read_to_string(ws.join("a.txt")).unwrap(), "v1");
        let backup_dir = ws_vault.join("hetero-backups");
        let backups: Vec<_> = fs::read_dir(&backup_dir).unwrap().flatten().collect();
        assert!(!backups.is_empty(), "heterogeneous live target must be backed up before overwrite");
        assert_eq!(
            fs::read_to_string(backups[0].path()).unwrap(),
            "user-important-hetero-file"
        );
    }
}
