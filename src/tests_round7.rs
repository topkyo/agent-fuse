#[cfg(test)]
mod tests_round7 {
    use crate::apfs::force_remove_all;
    use crate::diff::diff_snapshot_opts_with_vault;
    use crate::error::ERR_EINVAL;
    use crate::restore::restore_snapshot_paths_with_vault;
    use crate::rolling::{create_snapshot_rolling_with_vault, PRE_DELETE_LABEL};
    use crate::snapshot::{
        create_snapshot_fast_dedup_with_vault, create_snapshot_opts_with_vault,
        list_snapshots_with_vault,
    };
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

        let mut promoted_ids = Vec::new();
        for i in 0..15u32 {
            let victim = ws.join(format!("victim_{:02}.txt", i));
            fs::write(&victim, format!("payload-{}", i)).unwrap();
            let base = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
            assert!(!base.skipped);

            fs::remove_file(&victim).unwrap();
            fs::write(ws.join("live.txt"), format!("live-after-{}", i)).unwrap();
            let mixed = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
            assert!(!mixed.skipped);
            let pid = mixed.promoted_pre_delete_id.expect("mixed delete+modify must promote prior auto latest");
            assert_eq!(pid, base.meta.id);
            promoted_ids.push(pid);
        }

        let snaps = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
        let pre_deletes: Vec<_> = snaps.iter().filter(|m| m.label == PRE_DELETE_LABEL).collect();
        assert_eq!(pre_deletes.len(), 10, "pre-delete pool must keep latest 10 regardless of auto cap 5: {}", pre_deletes.len());
        let latest_pre_id = &promoted_ids[14];
        assert!(pre_deletes.iter().any(|m| &m.id == latest_pre_id));

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
}
