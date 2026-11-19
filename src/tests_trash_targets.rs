#[cfg(test)]
mod tests_trash_targets {
    use crate::apfs::{force_remove_all, lstat_inode_mode, real_home_dir};
    use crate::error::ERR_EINVAL;
    use crate::hook::execute_hook_auto_snap;
    use crate::restore::{restore_snapshot_with_vault, RestoreReport};
    use crate::snapshot::{create_snapshot_with_vault, diff_snapshot_with_vault};
    use crate::tests::ENV_LOCK;
    use crate::trash::TrashCleanupStatus;
    use crate::vault::{
        reject_forbidden_workspace_paths, validate_workspace_binding_with_vault, TargetKind,
    };
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct ScopedDir(PathBuf);
    impl ScopedDir {
        fn new(prefix: &str) -> Self {
            let ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
            let base = env::temp_dir().join(format!("afuse-tt-{}-{}-{}", prefix, std::process::id(), ns));
            fs::create_dir_all(&base).unwrap();
            Self(base)
        }
    }
    impl Drop for ScopedDir {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
            let _ = force_remove_all(&self.0);
        }
    }

    struct EnvGuard(&'static str, Option<std::ffi::OsString>);
    impl EnvGuard {
        fn set(key: &'static str, val: &Path) -> Self {
            let prev = env::var_os(key);
            env::set_var(key, val);
            Self(key, prev)
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.1 {
                Some(v) => env::set_var(self.0, v),
                None => env::remove_var(self.0),
            }
        }
    }

    #[test]
    fn plain_dir_and_desktop_subtree_rules_and_hook_blast_radius() {
        let _lock = ENV_LOCK.lock().unwrap();
        let sb = ScopedDir::new("plain");
        let vault = sb.0.join("vault");
        let plain = sb.0.join("notes-folder");
        fs::create_dir_all(plain.join("sub")).unwrap();
        fs::write(plain.join("a.md"), b"# Notes\n").unwrap();
        fs::write(plain.join("sub/b.txt"), b"hello").unwrap();

        // Unbound plain dir must NOT trigger hook auto-snap before vault snapshots exist
        assert!(execute_hook_auto_snap(&plain, "auto:claude:Write", Some(&vault), 0).unwrap().is_none());

        let vw = validate_workspace_binding_with_vault(&plain, Some(&vault)).unwrap();
        assert_eq!(vw.kind, TargetKind::Directory);
        assert_eq!(vw.marker, "dir");

        let meta = create_snapshot_with_vault(&plain, Some(&vault), "base").unwrap();
        assert_eq!(meta.target_kind, TargetKind::Directory);
        assert_eq!(meta.file_count, 2);

        // Once bound with existing snapshot, hook auto-snap is permitted for the plain dir
        fs::write(plain.join("a.md"), b"# Notes v2\n").unwrap();
        assert!(execute_hook_auto_snap(&plain, "auto:claude:Write", Some(&vault), 0).unwrap().is_some());

        // Whole plain dir deletion & in-place recovery
        force_remove_all(&plain).unwrap();
        let diff = diff_snapshot_with_vault(&plain, Some(&vault), &meta.id).unwrap();
        assert!(diff.deleted.contains(&"a.md".to_string()));
        let rep = restore_snapshot_with_vault(&plain, Some(&vault), &meta.id, false).unwrap();
        assert_eq!(rep.restored_files, 2);
        assert_eq!(fs::read_to_string(plain.join("a.md")).unwrap(), "# Notes\n");

        // Exact top-level ~/Desktop rejected, while nested path inside Desktop/sub is permitted
        let home = real_home_dir().unwrap();
        for top in ["Desktop", "Documents", "Downloads"] {
            assert_eq!(reject_forbidden_workspace_paths(&home.join(top)).unwrap_err().code, ERR_EINVAL);
            assert!(reject_forbidden_workspace_paths(&home.join(top).join("my-note.txt")).is_ok());
            assert!(reject_forbidden_workspace_paths(&home.join(top).join("projects/demo")).is_ok());
        }
        assert_eq!(reject_forbidden_workspace_paths(&home.join(".Trash/item")).unwrap_err().code, ERR_EINVAL);
    }

    #[test]
    fn single_file_lifecycle_isolates_siblings_and_blocks_dir_collision() {
        let _lock = ENV_LOCK.lock().unwrap();
        let sb = ScopedDir::new("singlefile");
        let vault = sb.0.join("vault");
        let work = sb.0.join("docs");
        fs::create_dir_all(&work).unwrap();
        let target = work.join("important.md");
        let sibling = work.join("untouched.txt");
        fs::write(&target, b"v1-original").unwrap();
        fs::write(&sibling, b"sibling-safe").unwrap();
        let (sib_ino_0, _) = lstat_inode_mode(&sibling).unwrap();

        let vw = validate_workspace_binding_with_vault(&target, Some(&vault)).unwrap();
        assert_eq!(vw.kind, TargetKind::SingleFile);
        let snap = create_snapshot_with_vault(&target, Some(&vault), "v1").unwrap();
        assert_eq!(snap.target_kind, TargetKind::SingleFile);
        assert_eq!(snap.file_count, 1);

        // Verify vault tree contains ONLY target, never sibling
        let canon_target = fs::canonicalize(&target).unwrap();
        let (_, ws_vault) = crate::vault::resolve_workspace_vault_recovery(&canon_target, Some(&vault)).unwrap();
        let tree_dir = ws_vault.join("snapshots").join(&snap.id).join("tree");
        assert!(tree_dir.join("important.md").is_file());
        assert!(!tree_dir.join("untouched.txt").exists());

        // Mutate & diff single file
        fs::write(&target, b"v2-corrupted").unwrap();
        let d1 = diff_snapshot_with_vault(&target, Some(&vault), "latest").unwrap();
        assert_eq!(d1.modified, vec!["important.md"]);
        assert!(d1.added.is_empty() && d1.deleted.is_empty());

        // Delete & diff & restore single file; sibling untouched
        fs::remove_file(&target).unwrap();
        let d2 = diff_snapshot_with_vault(&target, Some(&vault), &snap.id).unwrap();
        assert_eq!(d2.deleted, vec!["important.md"]);
        let rep: RestoreReport = restore_snapshot_with_vault(&target, Some(&vault), &snap.id, false).unwrap();
        assert!(target.is_file());
        assert_eq!(fs::read_to_string(&target).unwrap(), "v1-original");
        assert_eq!(rep.restored_files, 1);
        let (sib_ino_1, _) = lstat_inode_mode(&sibling).unwrap();
        assert_eq!(sib_ino_0, sib_ino_1);
        assert_eq!(fs::read_to_string(&sibling).unwrap(), "sibling-safe");

        // BLINDSPOT-04: heterogeneous dir/symlink at single-file path recovers cleanly
        fs::remove_file(&target).unwrap();
        fs::create_dir_all(target.join("keep")).unwrap();
        let dir_rec = restore_snapshot_with_vault(&target, Some(&vault), &snap.id, false).unwrap();
        assert!(target.is_file());
        assert_eq!(fs::read_to_string(&target).unwrap(), "v1-original");
        assert_eq!(dir_rec.restored_files, 1);
    }

    #[test]
    fn trash_purges_two_rounds_of_renamed_items_and_respects_anti_deletion_gates() {
        let _lock = ENV_LOCK.lock().unwrap();
        let sb = ScopedDir::new("trashgates");
        let vault = sb.0.join("vault");
        let trash = sb.0.join("custom_trash");
        let archive = sb.0.join("archive");
        fs::create_dir_all(&trash).unwrap();
        fs::create_dir_all(&archive).unwrap();
        let _tg = EnvGuard::set("AFUSE_TRASH_DIR", &trash);

        // Counter-example A: pre-existing same-named item with DIFFERENT inode in Trash must survive
        let decoy_dir = trash.join("my_folder");
        fs::create_dir_all(&decoy_dir).unwrap();
        fs::write(decoy_dir.join("decoy.txt"), b"keep-decoy").unwrap();
        let ws = sb.0.join("my_folder");
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("code.rs"), b"fn main() {}").unwrap();
        let snap = create_snapshot_with_vault(&ws, Some(&vault), "base").unwrap();

        // Round 1: Move folder to Trash with Finder-like conflict rename
        let trashed1 = trash.join("my_folder 23.59.01");
        fs::rename(&ws, &trashed1).unwrap();
        let r1 = restore_snapshot_with_vault(&ws, Some(&vault), &snap.id, false).unwrap();
        assert_eq!(r1.trash_cleanup, TrashCleanupStatus::Purged);
        assert!(!trashed1.exists());
        assert!(decoy_dir.join("decoy.txt").is_file());
        assert_eq!(fs::read_to_string(ws.join("code.rs")).unwrap(), "fn main() {}");

        // Round 2: Move newly restored folder (new inodes) to Trash again -> verify second purge works
        let trashed2 = trash.join("my_folder 23.59.02");
        fs::rename(&ws, &trashed2).unwrap();
        let r2 = restore_snapshot_with_vault(&ws, Some(&vault), &snap.id, false).unwrap();
        assert_eq!(r2.trash_cleanup, TrashCleanupStatus::Purged);
        assert!(!trashed2.exists());
        assert!(decoy_dir.join("decoy.txt").is_file());

        // Single file moved to Trash with conflict name -> purged cleanly
        let sfile = sb.0.join("notes.txt");
        fs::write(&sfile, b"important-note").unwrap();
        let fsnap = create_snapshot_with_vault(&sfile, Some(&vault), "f1").unwrap();
        let trashed_f = trash.join("notes 00.01.02.txt");
        fs::rename(&sfile, &trashed_f).unwrap();
        let rf = restore_snapshot_with_vault(&sfile, Some(&vault), &fsnap.id, false).unwrap();
        assert_eq!(rf.trash_cleanup, TrashCleanupStatus::Purged);
        assert!(!trashed_f.exists());

        // Counter-example B: Move folder OUTSIDE Trash to archive/ (same inode) -> must NOT delete archive
        let archived = archive.join("saved_copy");
        fs::rename(&ws, &archived).unwrap();
        let r_arch = restore_snapshot_with_vault(&ws, Some(&vault), &snap.id, false).unwrap();
        assert_eq!(r_arch.trash_cleanup, TrashCleanupStatus::NotInTrash);
        assert!(archived.join("code.rs").is_file());

        // Counter-example C: Read-only Trash (0500) with non-empty child simulates TCC denial -> restore succeeds with TccDenied & keeps retained inode
        let trashed3 = trash.join("my_folder 23.59.03");
        fs::rename(&ws, &trashed3).unwrap();
        let (trashed3_ino, _) = lstat_inode_mode(&trashed3).unwrap();
        fs::set_permissions(&trash, fs::Permissions::from_mode(0o500)).unwrap();
        let r_tcc = restore_snapshot_with_vault(&ws, Some(&vault), &snap.id, false).unwrap();
        assert_eq!(r_tcc.trash_cleanup, TrashCleanupStatus::TccDenied);
        assert!(trashed3.join("code.rs").is_file());
        assert!(ws.join("code.rs").is_file());
        let (_, ws_vault) = crate::vault::resolve_workspace_vault_recovery(&ws, Some(&vault)).unwrap();
        assert!(fs::read_to_string(ws_vault.join("latest_inodes.txt")).unwrap().contains(&trashed3_ino.to_string()));

        // Round 3: Restore again after granting permissions (0700) without re-trashing -> retained inode purges trashed3 cleanly
        fs::set_permissions(&trash, fs::Permissions::from_mode(0o700)).unwrap();
        let r_purged_later = restore_snapshot_with_vault(&ws, Some(&vault), &snap.id, false).unwrap();
        assert_eq!(r_purged_later.trash_cleanup, TrashCleanupStatus::Purged);
        assert!(!trashed3.exists());
    }

    #[test]
    fn fast_fsevents_dedup_noop_restore_and_prune_removes_outer_vault() {
        let _lock = ENV_LOCK.lock().unwrap();
        let sb = ScopedDir::new("fast-dedup-prune");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("proj");
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::write(ws.join("main.rs"), b"fn main() {}\n").unwrap();

        let (m1, d1) = crate::create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        assert!(!d1 && m1.tree_sha256.starts_with("fast:"));
        let (m2, d2) = crate::create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        assert!(d2 && m2.id == m1.id);
        assert_eq!(crate::list_snapshots_with_vault(&ws, Some(&vault)).unwrap().len(), 1);

        // Idempotent no-op restore creates zero auto:pre-restore
        let r_noop = restore_snapshot_with_vault(&ws, Some(&vault), &m1.id, true).unwrap();
        assert!(r_noop.safety_snapshot_id.is_none());
        assert_eq!(r_noop.project_files, 1);
        assert_eq!(crate::list_snapshots_with_vault(&ws, Some(&vault)).unwrap().len(), 1);

        // Selective restore on clean file also creates zero auto:pre-restore
        let r_sel = crate::restore_snapshot_paths_with_vault(&ws, Some(&vault), &m1.id, true, &["main.rs".into()]).unwrap();
        assert!(r_sel.safety_snapshot_id.is_none());

        // prune --keep 0 deletes outer ws_vault directory completely
        let (_, ws_vault) = crate::resolve_workspace_vault_recovery(&ws, Some(&vault)).unwrap();
        assert!(ws_vault.exists());
        let _ = crate::prune_snapshots_filtered_with_vault(&ws, Some(&vault), 0, None).unwrap();
        assert!(!ws_vault.exists());
    }

    #[test]
    fn expanded_forbidden_boundaries_leaf_names_owner_gate_and_single_file_manifest() {
        let _lock = ENV_LOCK.lock().unwrap();
        let sb = ScopedDir::new("boundary-rules");
        let vault = sb.0.join("vault");
        let home = crate::apfs::real_home_dir().unwrap();

        for p in [
            PathBuf::from("/private"),
            PathBuf::from("/PRIVATE"),
            PathBuf::from("/opt"),
            PathBuf::from("/OPT"),
            PathBuf::from("/Users/Shared"),
            PathBuf::from("/private/var/root"),
            PathBuf::from("/private/var/root/sub"),
            PathBuf::from("/private/var/db"),
            home.join("Pictures"),
            home.join("pictures"),
            home.join("Movies"),
            home.join("Music"),
            home.join("Public"),
            home.join(".ssh"),
            home.join(".ssh/id_ed25519"),
            home.join(".gnupg"),
            home.join(".aws"),
            home.join(".kube"),
            home.join("Applications"),
        ] {
            let err = crate::reject_forbidden_workspace_paths(&p).unwrap_err();
            assert_eq!(err.code, crate::error::ERR_EINVAL, "expected EINVAL for {}", p.display());
        }

        let host_tmp_proj = sb.0.join("host-var-folders-ok");
        fs::create_dir_all(&host_tmp_proj).unwrap();
        fs::write(host_tmp_proj.join("ok.txt"), b"ok").unwrap();
        assert!(crate::validate_workspace_binding_with_vault(&host_tmp_proj, Some(&vault)).is_ok());

        let git_leaf = sb.0.join("repo/.git");
        fs::create_dir_all(&git_leaf).unwrap();
        assert_eq!(crate::validate_workspace_binding_with_vault(&git_leaf, Some(&vault)).unwrap_err().code, crate::error::ERR_EINVAL);

        let ds_file = sb.0.join(".DS_Store");
        fs::write(&ds_file, b"ds").unwrap();
        assert_eq!(crate::validate_workspace_binding_with_vault(&ds_file, Some(&vault)).unwrap_err().code, crate::error::ERR_EINVAL);

        let nm_dir = sb.0.join("node_modules");
        fs::create_dir_all(&nm_dir).unwrap();
        assert_eq!(crate::validate_workspace_binding_with_vault(&nm_dir, Some(&vault)).unwrap_err().code, crate::error::ERR_EINVAL);

        let cargo_parent = sb.0.join("rust_app");
        fs::create_dir_all(cargo_parent.join("target")).unwrap();
        fs::write(cargo_parent.join("Cargo.toml"), b"[package]\nname=\"x\"\n").unwrap();
        assert_eq!(crate::validate_workspace_binding_with_vault(&cargo_parent.join("target"), Some(&vault)).unwrap_err().code, crate::error::ERR_EINVAL);

        let ro_owned = sb.0.join("own-ro");
        fs::create_dir_all(&ro_owned).unwrap();
        fs::write(ro_owned.join("f.rs"), b"v1").unwrap();
        fs::set_permissions(&ro_owned, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(crate::validate_workspace_binding_with_vault(&ro_owned, Some(&vault)).is_ok());
        fs::set_permissions(&ro_owned, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(crate::validate_workspace_binding_with_vault(&ro_owned, Some(&vault)).is_ok());
        let euid = crate::apfs::current_euid();
        assert_eq!(
            crate::vault_policy::check_owner_rw_gate(&ro_owned, euid.wrapping_add(1), euid).unwrap_err().code,
            crate::error::ERR_EACCES
        );
        fs::set_permissions(&ro_owned, fs::Permissions::from_mode(0o755)).unwrap();

        let sf = sb.0.join("single.rs");
        fs::write(&sf, b"v1").unwrap();
        let meta = crate::create_snapshot_with_vault(&sf, Some(&vault), "manual-sf").unwrap();
        let (expected_sha, fc, _, _) = crate::manifest::compute_single_file_manifest(&sf).unwrap();
        assert_eq!(fc, 1);
        assert_eq!(meta.tree_sha256, expected_sha);
        fs::write(&sf, b"mutated").unwrap();
        let rep = restore_snapshot_with_vault(&sf, Some(&vault), &meta.id, false).unwrap();
        assert_eq!(rep.tree_sha256, expected_sha);
        assert_eq!(fs::read_to_string(&sf).unwrap(), "v1");

        let upper_git = sb.0.join("repo_upper/.GIT");
        fs::create_dir_all(&upper_git).unwrap();
        assert_eq!(crate::validate_workspace_binding_with_vault(&upper_git, Some(&vault)).unwrap_err().code, crate::error::ERR_EINVAL);

        let plain_target_dir = sb.0.join("plain_notes");
        fs::create_dir_all(&plain_target_dir).unwrap();
        let target_sf = plain_target_dir.join("target");
        fs::write(&target_sf, b"init-target").unwrap();
        let vw = crate::validate_workspace_binding_with_vault(&target_sf, Some(&vault)).unwrap();
        assert_eq!(vw.kind, TargetKind::SingleFile);
        let t_meta = crate::create_snapshot_with_vault(&target_sf, Some(&vault), "manual-target").unwrap();
        let d_clean = crate::diff::diff_snapshot_with_vault(&target_sf, Some(&vault), &t_meta.id).unwrap();
        assert!(d_clean.added.is_empty() && d_clean.modified.is_empty() && d_clean.deleted.is_empty());
        fs::write(&target_sf, b"edited-target").unwrap();
        let d_dirty = crate::diff::diff_snapshot_with_vault(&target_sf, Some(&vault), &t_meta.id).unwrap();
        assert!(d_dirty.added.is_empty() && d_dirty.deleted.is_empty() && d_dirty.modified == vec!["target".to_string()]);
        let (t_meta2, dedup2) = crate::create_snapshot_if_changed_with_vault(&target_sf, Some(&vault), "auto:target-chg").unwrap();
        assert!(!dedup2 && t_meta2.id != t_meta.id);
        let t_rest = restore_snapshot_with_vault(&target_sf, Some(&vault), &t_meta.id, false).unwrap();
        assert_eq!(t_rest.snapshot_id, t_meta.id);
        assert_eq!(fs::read_to_string(&target_sf).unwrap(), "init-target");
    }

    #[test]
    fn purge_workspace_trash_respects_tcc_and_live_target_guard() {
        let _lock = ENV_LOCK.lock().unwrap();
        let sb = ScopedDir::new("purge-trash-cmd");
        let vault = sb.0.join("vault");
        let trash = sb.0.join("trash");
        let ws = sb.0.join("proj");
        fs::create_dir_all(&trash).unwrap();
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("main.rs"), b"v1").unwrap();
        let _tg = EnvGuard::set("AFUSE_TRASH_DIR", &trash);
        let snap = crate::create_snapshot_with_vault(&ws, Some(&vault), "base").unwrap();

        let trashed = trash.join("proj 10.00.00");
        fs::rename(&ws, &trashed).unwrap();
        let err = crate::purge_workspace_trash_with_vault(&ws, Some(&vault)).unwrap_err();
        assert_eq!(err.code, crate::error::ERR_ENOENT);
        assert!(trashed.join("main.rs").is_file());

        fs::write(&ws, b"accidental-hetero-file").unwrap();
        let hetero_err = crate::purge_workspace_trash_with_vault(&ws, Some(&vault)).unwrap_err();
        assert_eq!(hetero_err.code, crate::error::ERR_ENOENT);
        assert!(trashed.join("main.rs").is_file());
        fs::remove_file(&ws).unwrap();

        fs::set_permissions(&trash, fs::Permissions::from_mode(0o500)).unwrap();
        let rep = restore_snapshot_with_vault(&ws, Some(&vault), &snap.id, false).unwrap();
        assert_eq!(rep.trash_cleanup, TrashCleanupStatus::TccDenied);
        assert_eq!(crate::purge_workspace_trash_with_vault(&ws, Some(&vault)).unwrap(), TrashCleanupStatus::TccDenied);
        assert!(trashed.join("main.rs").is_file());

        fs::set_permissions(&trash, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(crate::purge_workspace_trash_with_vault(&ws, Some(&vault)).unwrap(), TrashCleanupStatus::Purged);
        assert!(!trashed.exists());
        assert_eq!(crate::purge_workspace_trash_with_vault(&ws, Some(&vault)).unwrap(), TrashCleanupStatus::NotInTrash);
    }
}
