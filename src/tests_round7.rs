#[cfg(test)]
mod tests_round7 {
    use crate::apfs::force_remove_all;
    use crate::diff::diff_snapshot_opts_with_vault;
    use crate::error::ERR_EINVAL;
    use crate::meta::{encode_summary, SnapshotOrigin, PIN_CONTAINS_DELETED};
    use crate::restore::{
        restore_snapshot_opts_with_vault, restore_snapshot_paths_with_vault,
    };
    use crate::rolling::create_snapshot_rolling_with_vault;
    use crate::snapshot::{
        create_snapshot_fast_dedup_with_vault, create_snapshot_opts_with_vault,
        list_snapshots_with_vault,
    };
    use crate::trash::TrashCleanupStatus;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    static R7_SEQ: AtomicU64 = AtomicU64::new(1);

    struct R7ScopedDir(PathBuf);
    impl R7ScopedDir {
        fn new(tag: &str) -> Self {
            let n = R7_SEQ.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("afuse-r7-{}-{}-{}", tag, std::process::id(), n));
            let _ = force_remove_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for R7ScopedDir {
        fn drop(&mut self) {
            let _ = force_remove_all(&self.0);
        }
    }

    #[test]
    fn fast_diff_and_dedup_ignore_same_content_mtime_and_cap_large_rehash() {
        let sb = R7ScopedDir::new("fast-rehash");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("ws");
        fs::create_dir_all(&vault).unwrap();
        fs::create_dir_all(&ws).unwrap();

        let small = ws.join("small.txt");
        fs::write(&small, b"unchanged-content-123456\n").unwrap();
        let big = ws.join("big.bin");
        let big_bytes = vec![0x42u8; (16 * 1024 * 1024) + 64];
        fs::write(&big, &big_bytes).unwrap();

        let s0 = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
        thread::sleep(Duration::from_millis(25));
        fs::write(&small, b"unchanged-content-123456\n").unwrap();

        let d1 = diff_snapshot_opts_with_vault(&ws, Some(&vault), &s0.id, true).unwrap();
        assert!(d1.added.is_empty() && d1.modified.is_empty() && d1.deleted.is_empty(), "small same-content rewrite falsely flagged modified: {:?}", d1);

        let (dedup_meta, was_dedup) = create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        assert!(was_dedup && dedup_meta.id == s0.id, "snap --fast must dedup when only mtime changed on <=16 MiB file");

        thread::sleep(Duration::from_millis(25));
        fs::write(&big, &big_bytes).unwrap();
        let d2 = diff_snapshot_opts_with_vault(&ws, Some(&vault), &s0.id, true).unwrap();
        assert!(d2.modified.contains(&"big.bin".to_string()), ">16 MiB file mtime change must bypass rehash and report modified: {:?}", d2);
    }

    #[test]
    fn rolling_pure_delete_with_git_noise_holds_latest_and_rejects_empty_dir() {
        let sb = R7ScopedDir::new("rolling-pure-del");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("ws");
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::create_dir_all(&vault).unwrap();
        fs::write(ws.join(".git/index"), b"idx-v1").unwrap();
        fs::write(ws.join("keep.txt"), b"keep").unwrap();
        fs::write(ws.join("moved_out.txt"), b"important-file").unwrap();

        let s0 = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
        fs::remove_file(ws.join("moved_out.txt")).unwrap();
        fs::write(ws.join(".git/index"), b"idx-v2-noise").unwrap();

        let rep = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        assert!(rep.skipped && rep.reason == Some("pure_delete_hold"), "expected pure_delete_hold, got {:?}", rep);
        assert_eq!(rep.meta.id, s0.id);

        let snaps = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
        assert_eq!(snaps.len(), 1, "pure delete must not advance snapshot list");
        let d = diff_snapshot_opts_with_vault(&ws, Some(&vault), "latest", true).unwrap();
        assert!(d.deleted.contains(&"moved_out.txt".to_string()), "deleted file must remain visible in latest diff: {:?}", d);

        fs::remove_file(ws.join("keep.txt")).unwrap();
        let err = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap_err();
        assert_eq!(err.code, ERR_EINVAL);
        assert!(err.message.contains("empty directory"), "empty dir must trigger trip error: {}", err.message);
    }

    #[test]
    fn rolling_mixed_change_promotes_pre_delete_caps_at_10_and_preserves_manual_label() {
        let _guard = crate::tests::ENV_LOCK.lock().unwrap();
        let sb = R7ScopedDir::new("rolling-mixed-15");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("ws");
        fs::create_dir_all(&vault).unwrap();
        fs::create_dir_all(&ws).unwrap();

        let prev_max = std::env::var_os("AFUSE_MAX_AUTO_SNAPS");
        std::env::set_var("AFUSE_MAX_AUTO_SNAPS", "5");

        fs::write(ws.join("manual_target.txt"), b"manual-era").unwrap();
        fs::write(ws.join("live.txt"), b"v0").unwrap();
        let manual = create_snapshot_opts_with_vault(&ws, Some(&vault), "menubar", true).unwrap();

        fs::remove_file(ws.join("manual_target.txt")).unwrap();
        fs::write(ws.join("live.txt"), b"v1").unwrap();
        let r_after_manual = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        assert!(r_after_manual.promoted_pre_delete_id.is_none(), "manual snapshot must never be relabeled");
        let all_after_manual = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
        assert_eq!(
            all_after_manual.iter().find(|m| m.id == manual.id).map(|m| m.label.as_str()),
            Some("menubar"),
            "manual label must stay intact"
        );

        let mut pinned_records = Vec::new();
        for i in 0..15u32 {
            let victim = ws.join(format!("victim_{:02}.txt", i));
            fs::write(&victim, format!("payload-{}", i)).unwrap();
            let base = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
            assert!(!base.skipped);

            fs::remove_file(&victim).unwrap();
            fs::write(ws.join("live.txt"), format!("live-after-{}", i)).unwrap();
            let mixed = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
            assert!(!mixed.skipped);
            let pid = mixed.promoted_pre_delete_id.expect("mixed delete+modify must pin prior auto latest");
            assert_eq!(pid, base.meta.id);
            pinned_records.push((pid, base.meta.label.clone(), base.meta.summary.clone(), base.meta.origin));
        }

        let snaps = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
        let pinned_snaps: Vec<_> = snaps
            .iter()
            .filter(|m| m.retention_pin.as_deref() == Some(PIN_CONTAINS_DELETED))
            .collect();
        assert_eq!(pinned_snaps.len(), 10, "contains_deleted pin pool must keep latest 10 regardless of auto cap 5: {}", pinned_snaps.len());
        let (latest_pre_id, orig_label, orig_summary, orig_origin) = &pinned_records[14];
        let latest_pin = pinned_snaps.iter().find(|m| &m.id == latest_pre_id).unwrap();
        assert_eq!(&latest_pin.label, orig_label, "pinned snapshot label must stay immutable");
        assert_eq!(&latest_pin.summary, orig_summary, "pinned snapshot summary must stay immutable");
        assert_eq!(&latest_pin.origin, orig_origin, "pinned snapshot origin must stay immutable");

        let restored = restore_snapshot_paths_with_vault(&ws, Some(&vault), latest_pre_id, false, &["victim_14.txt".into()]).unwrap();
        assert_eq!(restored.restored_paths, 1);
        assert_eq!(restored.project_files, 2);
        assert_eq!(fs::read_to_string(ws.join("victim_14.txt")).unwrap(), "payload-14");

        match prev_max {
            Some(v) => std::env::set_var("AFUSE_MAX_AUTO_SNAPS", v),
            None => std::env::remove_var("AFUSE_MAX_AUTO_SNAPS"),
        }
    }

    #[test]
    fn rolling_pure_rename_does_not_promote_pre_delete() {
        let sb = R7ScopedDir::new("rolling-rename");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("ws");
        fs::create_dir_all(&vault).unwrap();
        fs::create_dir_all(&ws).unwrap();

        fs::write(ws.join("a.txt"), b"same-file-body").unwrap();
        fs::write(ws.join("dup1.txt"), b"dup-body").unwrap();
        fs::write(ws.join("dup2.txt"), b"dup-body").unwrap();
        let s0 = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();

        fs::rename(ws.join("a.txt"), ws.join("b.txt")).unwrap();
        let r1 = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        assert!(!r1.skipped);
        assert!(r1.promoted_pre_delete_id.is_none(), "pure rename must not mint pre-delete anchor");
        assert_ne!(r1.meta.id, s0.id);

        fs::remove_file(ws.join("dup1.txt")).unwrap();
        fs::rename(ws.join("dup2.txt"), ws.join("dup_moved.txt")).unwrap();
        let r2 = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        assert!(!r2.skipped);
        assert!(r2.promoted_pre_delete_id.is_some(), "deleting 2 identical files with only 1 added must count 1 unmatched real delete");
    }

    #[test]
    fn selective_restore_purges_only_restored_file_trash_preserves_sibling_and_prefix() {
        let _guard = crate::tests::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let sb = R7ScopedDir::new("sel-trash");
        let vault = sb.0.join("vault");
        let trash = sb.0.join("trash");
        let ws = sb.0.join("ws");
        fs::create_dir_all(&vault).unwrap();
        fs::create_dir_all(&trash).unwrap();
        fs::create_dir_all(&ws).unwrap();

        fs::write(ws.join("a"), b"file-a").unwrap();
        fs::write(ws.join("ab.txt"), b"prefix-sibling").unwrap();
        fs::write(ws.join("sibling.txt"), b"other-sibling").unwrap();
        fs::write(ws.join("keep.txt"), b"stay").unwrap();

        let prev_trash = std::env::var_os("AFUSE_TRASH_DIR");
        std::env::set_var("AFUSE_TRASH_DIR", &trash);

        let snap = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
        fs::rename(ws.join("a"), trash.join("a")).unwrap();
        fs::rename(ws.join("ab.txt"), trash.join("ab.txt")).unwrap();
        fs::rename(ws.join("sibling.txt"), trash.join("sibling.txt")).unwrap();

        let rep = restore_snapshot_paths_with_vault(&ws, Some(&vault), &snap.id, false, &["a".into()]).unwrap();
        match prev_trash {
            Some(v) => std::env::set_var("AFUSE_TRASH_DIR", v),
            None => std::env::remove_var("AFUSE_TRASH_DIR"),
        }

        assert_eq!(rep.trash_cleanup, TrashCleanupStatus::Purged);
        assert_eq!(rep.tree_sha256.len(), 64);
        assert!(!rep.tree_sha256.starts_with("fast:"));
        assert_eq!(fs::read_to_string(ws.join("a")).unwrap(), "file-a");
        assert!(!trash.join("a").exists(), "restored file trashed copy must be purged");
        assert!(trash.join("ab.txt").exists(), "prefix-similar trashed file ab.txt must be preserved");
        assert!(trash.join("sibling.txt").exists(), "unrestored sibling in trash must be preserved");
    }

    #[test]
    fn restore_fast_directory_and_selective_verify_receipts_and_strict_merkle_stays() {
        let sb = R7ScopedDir::new("fast-restore-opts");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("ws");
        fs::create_dir_all(&vault).unwrap();
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("f1.txt"), b"v1").unwrap();
        fs::write(ws.join("f2.txt"), b"v2").unwrap();

        let fast_snap = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
        fs::write(ws.join("f1.txt"), b"changed").unwrap();
        fs::write(ws.join("extra.txt"), b"added").unwrap();

        let rep_fast = restore_snapshot_opts_with_vault(&ws, Some(&vault), &fast_snap.id, true, true).unwrap();
        assert_eq!(rep_fast.tree_sha256.len(), 64);
        assert!(!rep_fast.tree_sha256.starts_with("fast:"));
        assert_eq!(fs::read_to_string(ws.join("f1.txt")).unwrap(), "v1");
        assert!(!ws.join("extra.txt").exists());

        let rep_noop = restore_snapshot_opts_with_vault(&ws, Some(&vault), &fast_snap.id, true, true).unwrap();
        assert!(rep_noop.safety_snapshot_id.is_none(), "fast restore on identical workspace must skip pre-restore");

        fs::write(ws.join("extra2.txt"), b"to-delete").unwrap();
        let rep_sel = restore_snapshot_paths_with_vault(&ws, Some(&vault), &fast_snap.id, false, &["extra2.txt".into()]).unwrap();
        assert_eq!(rep_sel.tree_sha256.len(), 64);
        assert!(!ws.join("extra2.txt").exists());

        let full_snap = create_snapshot_opts_with_vault(&ws, Some(&vault), "manual", false).unwrap();
        assert_eq!(full_snap.tree_sha256.len(), 64);
        let rep_full_with_fast_flag = restore_snapshot_opts_with_vault(&ws, Some(&vault), &full_snap.id, false, true).unwrap();
        assert_eq!(rep_full_with_fast_flag.tree_sha256, full_snap.tree_sha256);
    }

    #[test]
    fn summary_pipe_filename_git_noise_skip_and_pre_restore_dedup_cap_3() {
        let sb = R7ScopedDir::new("summary-and-noise");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("ws");
        fs::create_dir_all(ws.join(".git")).unwrap();
        fs::create_dir_all(&vault).unwrap();
        fs::write(ws.join(".git/index"), b"idx1").unwrap();
        fs::write(ws.join("foo|bar.txt"), b"pipe-name-data").unwrap();
        fs::write(ws.join("main.rs"), b"v1").unwrap();

        let encoded = encode_summary('H', "dir/foo|bar.txt", 2);
        let (head, cnt) = encoded.rsplit_once('|').unwrap();
        assert_eq!(head, "H:foo|bar.txt");
        assert_eq!(cnt, "2");

        let s0 = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
        fs::write(ws.join(".git/index"), b"idx2-noise-only").unwrap();
        let git_only = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        assert!(git_only.skipped && git_only.reason == Some("no_project_changes"));
        assert_eq!(git_only.meta.id, s0.id);

        fs::remove_file(ws.join("foo|bar.txt")).unwrap();
        fs::write(ws.join("main.rs"), b"v2").unwrap();
        let mixed = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        let pid = mixed.promoted_pre_delete_id.unwrap();
        let snaps = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
        let pinned = snaps.iter().find(|m| m.id == pid).unwrap();
        assert_eq!(pinned.label, "auto:pro:init");
        assert_eq!(pinned.origin, SnapshotOrigin::Initial);
        assert_eq!(pinned.summary, s0.summary);
        assert_eq!(pinned.retention_pin.as_deref(), Some(PIN_CONTAINS_DELETED));
        assert_eq!(mixed.meta.summary.as_deref(), Some("D:foo|bar.txt|1;M:main.rs|1"));

        let (_, dedup_same_as_latest) = create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pre-restore").unwrap();
        assert!(dedup_same_as_latest, "pre-restore identical to latest primary must dedup");

        for k in 0..12u32 {
            fs::write(ws.join("main.rs"), format!("pre-val-{}", k)).unwrap();
            let (m1, d1) = create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pre-restore").unwrap();
            assert!(!d1);
            let (m2, d2) = create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pre-restore").unwrap();
            assert!(d2 && m2.id == m1.id, "consecutive identical pre-restore must dedup");
        }
        let pre_count = list_snapshots_with_vault(&ws, Some(&vault))
            .unwrap()
            .into_iter()
            .filter(|m| m.label == "auto:pre-restore")
            .count();
        assert_eq!(pre_count, 10, "MAX_PRE_RESTORE_SNAPS must cap at 10");
    }
}
