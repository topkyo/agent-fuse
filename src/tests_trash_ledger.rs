#[cfg(test)]
mod tests_trash_ledger {
    use crate::apfs::force_remove_all;
    use crate::restore::{
        restore_snapshot_opts_with_vault, restore_snapshot_paths_with_vault,
    };
    use crate::rolling::create_snapshot_rolling_with_vault;
    use crate::snapshot::create_snapshot_opts_with_vault;
    use crate::trash::{purge_workspace_trash_with_vault, TrashCleanupStatus};
    use crate::trash_ledger::{load_ledger, KNOWN_INODES_FILE};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TL_SEQ: AtomicU64 = AtomicU64::new(1);

    struct ScopedEnv {
        dir: PathBuf,
        prev_trash: Option<std::ffi::OsString>,
    }

    impl ScopedEnv {
        fn new(tag: &str) -> (Self, PathBuf, PathBuf, PathBuf) {
            let n = TL_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("afuse-tl-{}-{}-{}", tag, std::process::id(), n));
            let _ = force_remove_all(&dir);
            let vault = dir.join("vault");
            let trash = dir.join("trash");
            let ws = dir.join("ws");
            fs::create_dir_all(&vault).unwrap();
            fs::create_dir_all(&trash).unwrap();
            fs::create_dir_all(&ws).unwrap();
            let prev_trash = std::env::var_os("AFUSE_TRASH_DIR");
            std::env::set_var("AFUSE_TRASH_DIR", &trash);
            (Self { dir, prev_trash }, vault, trash, ws)
        }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            let trash = self.dir.join("trash");
            let _ = fs::set_permissions(&trash, fs::Permissions::from_mode(0o700));
            match self.prev_trash.take() {
                Some(v) => std::env::set_var("AFUSE_TRASH_DIR", v),
                None => std::env::remove_var("AFUSE_TRASH_DIR"),
            }
            let _ = force_remove_all(&self.dir);
        }
    }

    fn ws_vault_path(ws: &Path, vault: &Path) -> PathBuf {
        crate::vault::resolve_workspace_vault_recovery(ws, Some(vault)).unwrap().1
    }

    #[test]
    fn ledger_1_single_file_two_round_trash_combo_with_pre_restore() {
        let _lock = crate::tests::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_env, vault, trash, ws) = ScopedEnv::new("sf-combo");
        fs::write(ws.join("CHANGELOG.md"), b"# Changelog v1\n").unwrap();
        fs::write(ws.join("keep.txt"), b"stay\n").unwrap();

        let snap = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();

        let t1 = trash.join("CHANGELOG.md");
        fs::rename(ws.join("CHANGELOG.md"), &t1).unwrap();
        let r1 = restore_snapshot_paths_with_vault(&ws, Some(&vault), &snap.id, true, &["CHANGELOG.md".into()]).unwrap();
        assert_eq!(r1.trash_cleanup, TrashCleanupStatus::Purged);
        assert!(!t1.exists(), "round-1 trashed CHANGELOG.md must be purged");
        assert!(ws.join("CHANGELOG.md").is_file());

        let t2 = trash.join("CHANGELOG 14.50.00.md");
        fs::rename(ws.join("CHANGELOG.md"), &t2).unwrap();
        let r2 = restore_snapshot_paths_with_vault(&ws, Some(&vault), &snap.id, true, &["CHANGELOG.md".into()]).unwrap();
        assert_eq!(r2.trash_cleanup, TrashCleanupStatus::Purged);
        assert!(!t2.exists(), "round-2 trashed CHANGELOG.md must be purged even after auto:pre-restore");
        assert_eq!(fs::read_to_string(ws.join("CHANGELOG.md")).unwrap(), "# Changelog v1\n");
    }

    #[test]
    fn ledger_2_batch_trash_a_and_b_then_staggered_selective_restore() {
        let _lock = crate::tests::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_env, vault, trash, ws) = ScopedEnv::new("staggered-ab");
        fs::write(ws.join("A.md"), b"alpha\n").unwrap();
        fs::write(ws.join("B.md"), b"beta\n").unwrap();
        fs::write(ws.join("keep.txt"), b"stay\n").unwrap();
        let unrelated = trash.join("unrelated.txt");
        fs::write(&unrelated, b"keep-me\n").unwrap();

        let snap = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
        let ta = trash.join("A.md");
        let tb = trash.join("B.md");
        fs::rename(ws.join("A.md"), &ta).unwrap();
        fs::rename(ws.join("B.md"), &tb).unwrap();

        let ra = restore_snapshot_paths_with_vault(&ws, Some(&vault), &snap.id, true, &["A.md".into()]).unwrap();
        assert_eq!(ra.trash_cleanup, TrashCleanupStatus::Purged);
        assert!(!ta.exists(), "A.md in Trash must be purged");
        assert!(tb.exists(), "B.md in Trash must remain until B.md is restored");
        assert!(unrelated.exists());

        let rb = restore_snapshot_paths_with_vault(&ws, Some(&vault), &snap.id, true, &["B.md".into()]).unwrap();
        assert_eq!(rb.trash_cleanup, TrashCleanupStatus::Purged);
        assert!(!tb.exists(), "B.md in Trash must be purged on second selective restore");
        assert!(unrelated.exists(), "unrelated Trash item must stay intact");
    }

    #[test]
    fn ledger_3_full_directory_two_round_trash_combo_with_pre_restore() {
        let _lock = crate::tests::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_env, vault, trash, ws) = ScopedEnv::new("dir-combo");
        fs::write(ws.join("main.rs"), b"fn main() {}\n").unwrap();
        fs::write(ws.join("LICENSE"), b"MIT\n").unwrap();

        let snap = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();

        let d1 = trash.join("ws-round1");
        fs::rename(&ws, &d1).unwrap();
        let r1 = restore_snapshot_opts_with_vault(&ws, Some(&vault), &snap.id, true, true).unwrap();
        assert_eq!(r1.trash_cleanup, TrashCleanupStatus::Purged);
        assert!(!d1.exists());

        let d2 = trash.join("ws-round2");
        fs::rename(&ws, &d2).unwrap();
        let r2 = restore_snapshot_opts_with_vault(&ws, Some(&vault), &snap.id, true, true).unwrap();
        assert_eq!(r2.trash_cleanup, TrashCleanupStatus::Purged);
        assert!(!d2.exists());
        assert_eq!(fs::read_to_string(ws.join("LICENSE")).unwrap(), "MIT\n");
    }

    #[test]
    fn ledger_4_legacy_snapshot_without_inode_map_purges_via_known_inodes() {
        let _lock = crate::tests::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_env, vault, trash, ws) = ScopedEnv::new("legacy-nomap");
        fs::write(ws.join("LICENSE"), b"MIT-legacy\n").unwrap();
        fs::write(ws.join("keep.txt"), b"stay\n").unwrap();

        let snap = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
        let wv = ws_vault_path(&ws, &vault);
        let snap_map = wv.join("snapshots").join(&snap.id).join("inode_map.tsv");
        let _ = fs::remove_file(&snap_map);
        assert!(!snap_map.exists());
        assert!(wv.join(KNOWN_INODES_FILE).is_file());

        let trashed = trash.join("LICENSE");
        fs::rename(ws.join("LICENSE"), &trashed).unwrap();
        let rep = restore_snapshot_paths_with_vault(&ws, Some(&vault), &snap.id, true, &["LICENSE".into()]).unwrap();
        assert_eq!(rep.trash_cleanup, TrashCleanupStatus::Purged);
        assert!(!trashed.exists(), "legacy snapshot missing inode_map.tsv must still purge via known_inodes.tsv");
    }

    #[test]
    fn ledger_5_rename_a_to_b_then_trash_b_restoring_a_preserves_trashed_b() {
        let _lock = crate::tests::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_env, vault, trash, ws) = ScopedEnv::new("rename-guard");
        fs::write(ws.join("a.txt"), b"shared-inode-content\n").unwrap();
        fs::write(ws.join("keep.txt"), b"stay\n").unwrap();

        let s0 = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
        fs::rename(ws.join("a.txt"), ws.join("b.txt")).unwrap();
        let _r1 = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();

        let trashed_b = trash.join("b.txt");
        fs::rename(ws.join("b.txt"), &trashed_b).unwrap();

        let rep = restore_snapshot_paths_with_vault(&ws, Some(&vault), &s0.id, true, &["a.txt".into()]).unwrap();
        assert_eq!(rep.trash_cleanup, TrashCleanupStatus::NotInTrash);
        assert!(ws.join("a.txt").is_file(), "a.txt must be restored from s0");
        assert!(trashed_b.is_file(), "renamed trashed b.txt sharing old inode must NOT be deleted when restoring a.txt");
    }

    #[test]
    fn ledger_6_selective_tcc_denied_retains_inode_and_purge_trash_recovers() {
        let _lock = crate::tests::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_env, vault, trash, ws) = ScopedEnv::new("sel-tcc");
        fs::write(ws.join("doc.md"), b"important-doc\n").unwrap();
        fs::write(ws.join("keep.txt"), b"stay\n").unwrap();

        let snap = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
        let trashed = trash.join("doc.md");
        let doc_ino = fs::symlink_metadata(ws.join("doc.md")).unwrap().ino();
        fs::rename(ws.join("doc.md"), &trashed).unwrap();

        fs::set_permissions(&trash, fs::Permissions::from_mode(0o000)).unwrap();
        let rep = restore_snapshot_paths_with_vault(&ws, Some(&vault), &snap.id, true, &["doc.md".into()]).unwrap();
        assert_eq!(rep.trash_cleanup, TrashCleanupStatus::TccDenied);
        assert!(ws.join("doc.md").is_file());

        let wv = ws_vault_path(&ws, &vault);
        let ledger_after_tcc = load_ledger(&wv);
        assert_eq!(
            ledger_after_tcc.get(&doc_ino).map(String::as_str),
            Some("doc.md"),
            "TccDenied must retain trashed inode in known_inodes.tsv"
        );

        fs::set_permissions(&trash, fs::Permissions::from_mode(0o700)).unwrap();
        let purged = purge_workspace_trash_with_vault(&ws, Some(&vault)).unwrap();
        assert_eq!(purged, TrashCleanupStatus::Purged);
        assert!(!trashed.exists(), "purge-trash after TCC grant must clear retained trashed file");
        let ledger_after_purge = load_ledger(&wv);
        assert!(!ledger_after_purge.contains_key(&doc_ino), "purged inode must be retired from ledger");
    }

    #[test]
    fn ledger_7_manually_emptied_trash_under_tcc_eperm_returns_not_in_trash_and_retires_inode() {
        let _lock = crate::tests::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (_env, vault, trash, ws) = ScopedEnv::new("tcc-emptied");
        fs::write(ws.join("note.md"), b"user-note-v1\n").unwrap();

        let snap = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
        let note_ino = fs::symlink_metadata(ws.join("note.md")).unwrap().ino();
        let trashed = trash.join("note.md");
        fs::rename(ws.join("note.md"), &trashed).unwrap();

        // Positive: file still sits inside unreadable Trash -> must report TccDenied
        fs::set_permissions(&trash, fs::Permissions::from_mode(0o000)).unwrap();
        let rep = restore_snapshot_paths_with_vault(&ws, Some(&vault), &snap.id, true, &["note.md".into()]).unwrap();
        assert_eq!(rep.trash_cleanup, TrashCleanupStatus::TccDenied);
        let still_denied = purge_workspace_trash_with_vault(&ws, Some(&vault)).unwrap();
        assert_eq!(still_denied, TrashCleanupStatus::TccDenied);

        // Negative: user manually empties Trash while FDA remains revoked (Trash stays 0000) -> must converge to NotInTrash
        fs::set_permissions(&trash, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(&trashed).unwrap();
        fs::set_permissions(&trash, fs::Permissions::from_mode(0o000)).unwrap();

        let after_empty = purge_workspace_trash_with_vault(&ws, Some(&vault)).unwrap();
        assert_eq!(
            after_empty,
            TrashCleanupStatus::NotInTrash,
            "emptied Trash must not stick on TccDenied when candidate inode is gone (ENOENT)"
        );
        let wv = ws_vault_path(&ws, &vault);
        let ledger = load_ledger(&wv);
        assert!(!ledger.contains_key(&note_ino), "physically destroyed inode must be retired from ledger");
        fs::set_permissions(&trash, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
