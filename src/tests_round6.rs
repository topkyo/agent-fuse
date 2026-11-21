#[cfg(test)]
mod tests_round6 {
    use crate::apfs::force_remove_all;
    use crate::diff::diff_snapshot_opts_with_vault;
    use crate::error::ERR_EEXIST;
    use crate::guard::{run_guarded_command_with_vault, GuardConfig};
    use crate::hook::run_claude_hook_exec_from_reader;
    use crate::relocate::{
        locate_workspace_target_with_vault, prune_orphan_vaults_with,
        relocate_workspace_vault_with, LocateOutcome,
    };
    use crate::restore::{restore_snapshot_paths_with_vault, restore_snapshot_with_vault};
    use crate::snapshot::{create_snapshot_opts_with_vault, list_snapshots_with_vault};
    use crate::vault::TargetKind;
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static R6_SEQ: AtomicU64 = AtomicU64::new(1);

    struct R6ScopedDir(PathBuf);
    impl R6ScopedDir {
        fn new(tag: &str) -> Self {
            let n = R6_SEQ.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("afuse-r6-{}-{}-{}", tag, std::process::id(), n));
            let _ = force_remove_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for R6ScopedDir {
        fn drop(&mut self) {
            let _ = force_remove_all(&self.0);
        }
    }

    #[test]
    fn locate_and_relocate_single_file_rename_preserves_merkle_and_zero_orphan() {
        let sb = R6ScopedDir::new("reloc-file");
        let vault = sb.0.join("vault");
        let d1 = sb.0.join("d1");
        let d2 = sb.0.join("d2");
        fs::create_dir_all(&vault).unwrap();
        fs::create_dir_all(&d1).unwrap();
        fs::create_dir_all(&d2).unwrap();

        let p1 = d1.join("resume_old.pdf");
        let p2 = d2.join("resume_new.pdf");
        fs::write(&p1, b"%PDF-1.4 original\n").unwrap();
        let ino = fs::symlink_metadata(&p1).unwrap().ino();

        let full = create_snapshot_opts_with_vault(&p1, Some(&vault), "full-s1", false).unwrap();
        let fast = create_snapshot_opts_with_vault(&p1, Some(&vault), "fast-s2", true).unwrap();
        fs::rename(&p1, &p2).unwrap();

        let loc = locate_workspace_target_with_vault(&p1, Some(&vault), Some(ino)).unwrap();
        assert_eq!(
            loc,
            LocateOutcome::MovedValid {
                new_path: fs::canonicalize(&p2).unwrap(),
                ino,
                kind: TargetKind::SingleFile,
            }
        );

        let rel = relocate_workspace_vault_with(&p1, &p2, Some(&vault), Some(ino)).unwrap();
        assert_eq!(rel.snapshots_updated, 2);
        let vault_dirs: Vec<_> = fs::read_dir(&vault).unwrap().flatten().collect();
        assert_eq!(vault_dirs.len(), 1, "relocate must leave zero orphan vault_P1");

        let diff = diff_snapshot_opts_with_vault(&p2, Some(&vault), &full.id, false).unwrap();
        assert!(diff.added.is_empty() && diff.deleted.is_empty() && diff.modified.is_empty(), "diff after rename: {:?}", diff);

        fs::write(&p2, b"corrupted\n").unwrap();
        restore_snapshot_with_vault(&p2, Some(&vault), &full.id, false).unwrap();
        assert_eq!(fs::read(&p2).unwrap(), b"%PDF-1.4 original\n");
        restore_snapshot_with_vault(&p2, Some(&vault), &fast.id, false).unwrap();
        assert_eq!(fs::read(&p2).unwrap(), b"%PDF-1.4 original\n");
    }

    #[test]
    fn locate_distinguishes_trashed_and_relocate_blocks_eexist_collision() {
        let _guard = crate::tests::ENV_LOCK.lock().unwrap();
        let sb = R6ScopedDir::new("reloc-trash-eexist");
        let vault = sb.0.join("vault");
        let trash = sb.0.join("trash");
        let d1 = sb.0.join("a");
        let d2 = sb.0.join("b");
        fs::create_dir_all(&vault).unwrap();
        fs::create_dir_all(&trash).unwrap();
        fs::create_dir_all(&d1).unwrap();
        fs::create_dir_all(&d2).unwrap();
        fs::write(d1.join("x.txt"), "x\n").unwrap();
        fs::write(d2.join("y.txt"), "y\n").unwrap();
        let ino1 = fs::symlink_metadata(&d1).unwrap().ino();

        let prev = std::env::var_os("AFUSE_TRASH_DIR");
        std::env::set_var("AFUSE_TRASH_DIR", &trash);
        create_snapshot_opts_with_vault(&d1, Some(&vault), "s1", true).unwrap();
        create_snapshot_opts_with_vault(&d2, Some(&vault), "s2", true).unwrap();

        let trashed_d1 = trash.join("a");
        fs::rename(&d1, &trashed_d1).unwrap();
        let loc = locate_workspace_target_with_vault(&d1, Some(&vault), Some(ino1)).unwrap();
        match prev {
            Some(v) => std::env::set_var("AFUSE_TRASH_DIR", v),
            None => std::env::remove_var("AFUSE_TRASH_DIR"),
        }
        assert!(matches!(loc, LocateOutcome::Trashed { .. }), "expected Trashed, got {:?}", loc);

        // Collision check: moving d1 onto path d2 that already owns a vault returns ERR_EEXIST
        let d3 = sb.0.join("c");
        fs::rename(&trashed_d1, &d3).unwrap();
        create_snapshot_opts_with_vault(&d3, Some(&vault), "s3", true).unwrap();
        let d2_ino = fs::symlink_metadata(&d2).unwrap().ino();
        fs::remove_dir_all(&d3).unwrap();
        let err = relocate_workspace_vault_with(&d3, &d2, Some(&vault), Some(d2_ino)).unwrap_err();
        assert_eq!(err.code, ERR_EEXIST);

        // Zero-snapshot relocate (before initial vault dir is created) succeeds cleanly
        let d4 = sb.0.join("fresh_src");
        let d5 = sb.0.join("fresh_dst");
        fs::create_dir_all(&d4).unwrap();
        let d4_ino = fs::symlink_metadata(&d4).unwrap().ino();
        fs::rename(&d4, &d5).unwrap();
        let fresh_rel = relocate_workspace_vault_with(&d4, &d5, Some(&vault), Some(d4_ino)).unwrap();
        assert_eq!(fresh_rel.snapshots_updated, 0);
    }

    #[test]
    fn guard_does_not_kill_internal_mv_refactor_or_external_disk_writes() {
        let sb = R6ScopedDir::new("guard-no-false-kill");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("ws");
        let old_pkg = ws.join("old_pkg");
        fs::create_dir_all(&vault).unwrap();
        fs::create_dir_all(&old_pkg).unwrap();
        for i in 0..25 {
            fs::write(old_pkg.join(format!("f{:02}.rs", i)), "pub fn f() {}\n").unwrap();
        }
        let cfg = GuardConfig { max_delete: 20, max_write_mb: 4, poll_ms: 10, auto_rollback: true };
        let rep = run_guarded_command_with_vault(
            &ws,
            Some(&vault),
            &cfg,
            &["mv".into(), "old_pkg".into(), "new_pkg".into()],
        )
        .unwrap();
        assert!(!rep.tripped, "guard falsely killed internal mv refactor: {:?}", rep);
        assert_eq!(rep.exit_code, 0);
        assert!(ws.join("new_pkg/f24.rs").is_file());
    }

    #[test]
    fn hook_destructive_bash_bypasses_throttle_after_edit_and_prune_orphans_works() {
        let sb = R6ScopedDir::new("hook-and-orphans");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("repo");
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::create_dir_all(&vault).unwrap();
        fs::write(ws.join("app.rs"), "v1\n").unwrap();

        let edit_json = format!(
            "{{\"tool_name\":\"Edit\",\"cwd\":\"{}\",\"tool_input\":{{\"file_path\":\"{}\"}}}}",
            ws.display(),
            ws.join("app.rs").display()
        );
        assert!(run_claude_hook_exec_from_reader(Cursor::new(edit_json), Some(&vault)).is_some());
        fs::write(ws.join("app.rs"), "v2_unsaved\n").unwrap();

        let rm_json = format!(
            "{{\"tool_name\":\"Bash\",\"cwd\":\"{}\",\"tool_input\":{{\"command\":\"rm -rf app.rs\"}}}}",
            ws.display()
        );
        assert!(
            run_claude_hook_exec_from_reader(Cursor::new(rm_json), Some(&vault)).is_some(),
            "destructive Bash rm must bypass 5s throttle to protect v2"
        );
        assert_eq!(list_snapshots_with_vault(&ws, Some(&vault)).unwrap().len(), 2);

        fs::remove_dir_all(&ws).unwrap();
        let dry = prune_orphan_vaults_with(Some(&vault), 0, true).unwrap();
        assert_eq!(dry.candidates.len(), 1);
        assert_eq!(dry.removed, 0);
        let live = prune_orphan_vaults_with(Some(&vault), 0, false).unwrap();
        assert_eq!(live.removed, 1);
    }

    #[test]
    fn nested_dir_diff_excludes_dir_entries_and_matches_project_files() {
        let sb = R6ScopedDir::new("nested-diff-count");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("nested-ws");
        fs::create_dir_all(ws.join("a/b/c/d")).unwrap();
        fs::create_dir_all(&vault).unwrap();
        fs::write(ws.join("root.txt"), "r").unwrap();
        fs::write(ws.join("a/mid.txt"), "m").unwrap();
        fs::write(ws.join("a/b/c/d/leaf.txt"), "l").unwrap();

        let snap = create_snapshot_opts_with_vault(&ws, Some(&vault), "init", true).unwrap();
        assert_eq!(snap.project_files, 3);

        fs::remove_dir_all(&ws).unwrap();
        let d_fast = diff_snapshot_opts_with_vault(&ws, Some(&vault), &snap.id, true).unwrap();
        let d_full = diff_snapshot_opts_with_vault(&ws, Some(&vault), &snap.id, false).unwrap();
        for d in [&d_fast, &d_full] {
            assert_eq!(d.deleted.len(), 3, "deleted must exclude directory entries: {:?}", d.deleted);
            assert!(d.added.is_empty() && d.modified.is_empty());
            assert!(!d.deleted.iter().any(|p| p == "a" || p == "a/b" || p == "a/b/c" || p == "a/b/c/d"));
        }

        let sel = restore_snapshot_paths_with_vault(&ws, Some(&vault), &snap.id, true, &["root.txt".into()]).unwrap();
        assert_eq!(sel.project_files, 1);
        let d_part = diff_snapshot_opts_with_vault(&ws, Some(&vault), &snap.id, true).unwrap();
        assert_eq!(d_part.deleted.len(), 2, "partial diff must only list remaining 2 files: {:?}", d_part.deleted);

        let full_rep = restore_snapshot_with_vault(&ws, Some(&vault), &snap.id, false).unwrap();
        assert_eq!(full_rep.project_files, 3);

        // Replacing a regular file with a directory still reports modified (heterogeneous swap).
        fs::remove_file(ws.join("root.txt")).unwrap();
        fs::create_dir_all(ws.join("root.txt")).unwrap();
        let d_hetero = diff_snapshot_opts_with_vault(&ws, Some(&vault), &snap.id, true).unwrap();
        assert!(d_hetero.modified.contains(&"root.txt".to_string()), "heterogeneous file->dir must appear in modified: {:?}", d_hetero);
    }
}
