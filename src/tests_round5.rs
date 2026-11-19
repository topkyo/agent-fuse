#[cfg(test)]
mod tests_round5 {
    use crate::apfs::{current_euid, force_remove_all};
    use crate::restore::restore_snapshot_with_vault;
    use crate::snapshot::create_snapshot_opts_with_vault;
    use crate::trash::{allowed_trash_roots_for, purge_workspace_trash_with_vault, TrashCleanupStatus};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static R5_SEQ: AtomicU64 = AtomicU64::new(1);

    struct R5ScopedDir(PathBuf);
    impl R5ScopedDir {
        fn new(tag: &str) -> Self {
            let n = R5_SEQ.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("afuse-r5-{}-{}-{}", tag, std::process::id(), n));
            let _ = force_remove_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for R5ScopedDir {
        fn drop(&mut self) {
            let _ = force_remove_all(&self.0);
        }
    }

    #[test]
    fn allowed_trash_roots_includes_icloud_clouddocs_trash() {
        let sb = R5ScopedDir::new("icloud-roots");
        let local_trash = sb.0.join(".Trash");
        let icloud_trash = sb.0.join("Library/Mobile Documents/com~apple~CloudDocs/.Trash");
        fs::create_dir_all(&local_trash).unwrap();
        fs::create_dir_all(&icloud_trash).unwrap();

        let roots = allowed_trash_roots_for(Some(&sb.0), None, None, current_euid());
        let canon_local = fs::canonicalize(&local_trash).unwrap();
        let canon_icloud = fs::canonicalize(&icloud_trash).unwrap();
        assert!(roots.contains(&canon_local), "missing local .Trash in {:?}", roots);
        assert!(roots.contains(&canon_icloud), "missing CloudDocs/.Trash in {:?}", roots);
    }

    #[test]
    fn icloud_desktop_resume_trashed_copy_is_purged_and_empty_readonly_trash_no_false_tcc() {
        let _guard = crate::tests::ENV_LOCK.lock().unwrap();
        let sb = R5ScopedDir::new("icloud-purge-and-empty-ro");
        let vault = sb.0.join("vault");
        let desktop = sb.0.join("Desktop");
        let icloud_trash = sb.0.join("Library/Mobile Documents/com~apple~CloudDocs/.Trash");
        let ro_empty_trash = sb.0.join("empty-ro-trash");
        fs::create_dir_all(&vault).unwrap();
        fs::create_dir_all(&desktop).unwrap();
        fs::create_dir_all(&icloud_trash).unwrap();
        fs::create_dir_all(&ro_empty_trash).unwrap();

        let resume = desktop.join("个人简历.pdf");
        fs::write(&resume, b"%PDF-1.4 resume-v1\n").unwrap();
        let orig_ino = fs::symlink_metadata(&resume).unwrap().ino();

        let prev_trash_env = std::env::var_os("AFUSE_TRASH_DIR");
        std::env::set_var("AFUSE_TRASH_DIR", &icloud_trash);
        let snap = create_snapshot_opts_with_vault(&resume, Some(&vault), "init", true).unwrap();

        // Simulate Finder moving Desktop PDF into iCloud CloudDocs/.Trash
        let trashed = icloud_trash.join("个人简历.pdf");
        fs::rename(&resume, &trashed).unwrap();
        assert_eq!(fs::symlink_metadata(&trashed).unwrap().ino(), orig_ino);

        let rep = restore_snapshot_with_vault(&resume, Some(&vault), &snap.id, false).unwrap();
        assert_eq!(rep.trash_cleanup, TrashCleanupStatus::Purged);
        assert!(resume.is_file(), "restored PDF must exist on Desktop");
        assert!(!trashed.exists(), "iCloud Trash duplicate must be purged");

        // Now simulate atomic-save replacing inode while AFUSE_TRASH_DIR is empty & 0500 read-only:
        // Must NOT false-positive as TccDenied and must clear stale retained_inodes.
        let tmp_save = desktop.join(".个人简历.pdf.tmp");
        fs::write(&tmp_save, b"%PDF-1.4 resume-v2\n").unwrap();
        fs::rename(&tmp_save, &resume).unwrap();
        fs::set_permissions(&ro_empty_trash, fs::Permissions::from_mode(0o500)).unwrap();
        std::env::set_var("AFUSE_TRASH_DIR", &ro_empty_trash);

        let rep2 = restore_snapshot_with_vault(&resume, Some(&vault), &snap.id, false).unwrap();
        let purge2 = purge_workspace_trash_with_vault(&resume, Some(&vault)).unwrap();

        fs::set_permissions(&ro_empty_trash, fs::Permissions::from_mode(0o700)).unwrap();
        match prev_trash_env {
            Some(v) => std::env::set_var("AFUSE_TRASH_DIR", v),
            None => std::env::remove_var("AFUSE_TRASH_DIR"),
        }

        assert_eq!(rep2.trash_cleanup, TrashCleanupStatus::NotInTrash, "empty 0500 Trash must not false-alarm tcc_denied");
        assert_eq!(purge2, TrashCleanupStatus::NotInTrash, "purge-trash on empty 0500 Trash must return NotInTrash");
    }
}
