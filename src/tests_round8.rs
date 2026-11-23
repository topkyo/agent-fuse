#[cfg(test)]
mod tests_round8 {
    use crate::apfs::force_remove_all;
    use crate::diff::diff_snapshot_opts_with_vault;
    use crate::diff_rename::RenamePair;
    use crate::meta::{SnapshotMeta, SnapshotOrigin, PIN_CONTAINS_DELETED};
    use crate::restore::{
        restore_snapshot_opts_with_vault, restore_snapshot_paths_with_vault,
    };
    use crate::rolling::create_snapshot_rolling_with_vault;
    use crate::snapshot::{create_snapshot_opts_with_vault, list_snapshots_with_vault};
    use std::fs;
    use std::io::{Seek, SeekFrom, Write};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static R8_SEQ: AtomicU64 = AtomicU64::new(1);

    struct R8ScopedDir(PathBuf);
    impl R8ScopedDir {
        fn new(tag: &str) -> Self {
            let n = R8_SEQ.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("afuse-r8-{}-{}-{}", tag, std::process::id(), n));
            let _ = force_remove_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for R8ScopedDir {
        fn drop(&mut self) {
            let _ = force_remove_all(&self.0);
        }
    }

    #[test]
    fn devil_7_step_sequence_append_only_head_and_atomic_rename_undo() {
        let sb = R8ScopedDir::new("devil7");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("ws");
        fs::create_dir_all(&vault).unwrap();
        fs::create_dir_all(&ws).unwrap();

        fs::write(ws.join("A.txt"), b"A:v1").unwrap();
        fs::write(ws.join("B.txt"), b"B:body-unique").unwrap();
        fs::write(ws.join("D.txt"), b"D:victim").unwrap();
        fs::write(ws.join("E.txt"), b"E:v1").unwrap();
        let s0 = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
        assert_eq!(s0.origin, SnapshotOrigin::Initial);

        fs::write(ws.join("A.txt"), b"A:v2").unwrap();
        let r1 = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        assert_eq!(r1.meta.origin, SnapshotOrigin::AutoSave);
        assert_eq!(r1.meta.summary.as_deref(), Some("M:A.txt|1"));
        assert!(r1.meta.created_ms > s0.created_ms);

        fs::rename(ws.join("B.txt"), ws.join("C.txt")).unwrap();
        let d_ren = diff_snapshot_opts_with_vault(&ws, Some(&vault), "latest", true).unwrap();
        assert!(d_ren.deleted.is_empty() && d_ren.added.is_empty());
        assert_eq!(d_ren.renamed, vec![RenamePair { from: "B.txt".into(), to: "C.txt".into() }]);
        let r2 = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        assert!(r2.promoted_pre_delete_id.is_none());
        assert_eq!(r2.meta.summary.as_deref(), Some("R:B.txt->C.txt|1"));

        fs::remove_file(ws.join("D.txt")).unwrap();
        let r_hold = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        assert!(r_hold.skipped && r_hold.reason == Some("pure_delete_hold"));

        fs::write(ws.join("E.txt"), b"E:v2").unwrap();
        let r3 = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        assert_eq!(r3.promoted_pre_delete_id.as_deref(), Some(r2.meta.id.as_str()));
        assert_eq!(r3.meta.summary.as_deref(), Some("D:D.txt|1;M:E.txt|1"));

        let snaps_before = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
        let s2_after = snaps_before.iter().find(|m| m.id == r2.meta.id).unwrap();
        assert_eq!(s2_after.label, "auto:pro:fsevents");
        assert_eq!(s2_after.origin, SnapshotOrigin::AutoSave);
        assert_eq!(s2_after.summary.as_deref(), Some("R:B.txt->C.txt|1"));
        assert_eq!(s2_after.retention_pin.as_deref(), Some(PIN_CONTAINS_DELETED));

        let rep = restore_snapshot_opts_with_vault(&ws, Some(&vault), &r2.meta.id, true, true).unwrap();
        assert!(rep.safety_snapshot_id.is_none(), "Live == T[0](S3), so T[0] becomes T[1] without duplicate BeforeRestore");
        let post_id = rep.post_snapshot_id.expect("restoring older S2 must append S_post head");
        assert_eq!(fs::read_to_string(ws.join("D.txt")).unwrap(), "D:victim");
        assert_eq!(fs::read_to_string(ws.join("E.txt")).unwrap(), "E:v1");

        let d_post = diff_snapshot_opts_with_vault(&ws, Some(&vault), "latest", true).unwrap();
        assert_eq!(d_post.snapshot_id, post_id);
        assert!(d_post.added.is_empty() && d_post.modified.is_empty() && d_post.deleted.is_empty() && d_post.renamed.is_empty());

        let timeline = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
        for w in timeline.windows(2) {
            assert!(w[0].created_ms > w[1].created_ms, "strict monotonic descending timestamps violated");
        }
        assert_eq!(timeline[0].id, post_id);
        assert_eq!(timeline[0].origin, SnapshotOrigin::RestoredFrom);
        assert_eq!(timeline[0].restored_from_id.as_deref(), Some(r2.meta.id.as_str()));
        assert_eq!(timeline[1].id, r3.meta.id);

        let d_t1 = diff_snapshot_opts_with_vault(&ws, Some(&vault), &timeline[1].id, true).unwrap();
        assert!(d_t1.modified.contains(&"E.txt".to_string()));
        assert!(d_t1.added.contains(&"D.txt".to_string()));

        let sel_ren = restore_snapshot_paths_with_vault(
            &ws, Some(&vault), &r1.meta.id, true, &["B.txt".into(), "C.txt".into()],
        ).unwrap();
        assert!(sel_ren.safety_snapshot_id.is_some(), "removing live C.txt must take BeforeRestore");
        assert!(sel_ren.post_snapshot_id.is_none(), "selective restore must not append RestoredFrom head");
        assert_eq!(fs::read_to_string(ws.join("B.txt")).unwrap(), "B:body-unique");
        assert!(!ws.join("C.txt").exists(), "atomic rename undo must leave zero duplicate files");
    }

    #[test]
    fn large_file_over_16mib_rename_detected_and_mid_mutation_rejected() {
        let sb = R8ScopedDir::new("large-rename");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("ws");
        fs::create_dir_all(ws.join("sub")).unwrap();
        fs::create_dir_all(&vault).unwrap();

        let size: usize = (16 * 1024 * 1024) + (128 * 1024);
        let mut data = vec![0x2Au8; size];
        data[0..16].copy_from_slice(b"HEAD-MARKER-0001");
        data[size / 2..size / 2 + 16].copy_from_slice(b"MID--MARKER-0002");
        data[size - 16..size].copy_from_slice(b"TAIL-MARKER-0003");
        let orig = ws.join("huge.bin");
        fs::write(&orig, &data).unwrap();

        let s0 = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
        let moved = ws.join("sub/huge_moved.bin");
        fs::rename(&orig, &moved).unwrap();

        let d_fast = diff_snapshot_opts_with_vault(&ws, Some(&vault), &s0.id, true).unwrap();
        assert!(d_fast.deleted.is_empty() && d_fast.added.is_empty(), "fast diff: {:?}", d_fast);
        assert_eq!(d_fast.renamed, vec![RenamePair { from: "huge.bin".into(), to: "sub/huge_moved.bin".into() }]);

        let d_full = diff_snapshot_opts_with_vault(&ws, Some(&vault), &s0.id, false).unwrap();
        assert!(d_full.deleted.is_empty() && d_full.added.is_empty(), "full diff: {:?}", d_full);
        assert_eq!(d_full.renamed, vec![RenamePair { from: "huge.bin".into(), to: "sub/huge_moved.bin".into() }]);

        let mut f = fs::OpenOptions::new().write(true).open(&moved).unwrap();
        f.seek(SeekFrom::Start((size / 2) as u64)).unwrap();
        f.write_all(b"MID--CHANGED-999").unwrap();
        drop(f);
        let d_mut = diff_snapshot_opts_with_vault(&ws, Some(&vault), &s0.id, true).unwrap();
        assert!(d_mut.renamed.is_empty(), "mid-chunk mutation must not match sampled rename: {:?}", d_mut);
        assert_eq!(d_mut.deleted, vec!["huge.bin".to_string()]);
        assert_eq!(d_mut.added, vec!["sub/huge_moved.bin".to_string()]);
    }

    #[test]
    fn pre_restore_never_evaporates_and_pure_missing_selective_skips_backup() {
        let sb = R8ScopedDir::new("pre-restore-invariants");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("ws");
        fs::create_dir_all(&vault).unwrap();
        fs::create_dir_all(&ws).unwrap();

        fs::write(ws.join("doc.txt"), b"v1").unwrap();
        fs::write(ws.join("extra.txt"), b"stay").unwrap();
        let s1 = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();

        fs::write(ws.join("doc.txt"), b"v2").unwrap();
        let s2 = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:fsevents", true).unwrap();

        fs::write(ws.join("doc.txt"), b"dirty-alpha").unwrap();
        let r1 = restore_snapshot_opts_with_vault(&ws, Some(&vault), &s1.id, true, true).unwrap();
        let pre1 = r1.safety_snapshot_id.expect("Live=dirty-alpha != T[0](s2) must create BeforeRestore");
        assert!(r1.post_snapshot_id.is_some());

        fs::write(ws.join("doc.txt"), b"dirty-alpha").unwrap();
        let r2 = restore_snapshot_opts_with_vault(&ws, Some(&vault), &s2.id, true, true).unwrap();
        let pre2 = r2.safety_snapshot_id.expect("Live=dirty-alpha != T[0](post1) must NOT dedup against older pre1");
        assert_ne!(pre2, pre1, "BeforeRestore must never evaporate via cross-head deduplication");
        let tl = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
        assert_eq!(tl[0].id, r2.post_snapshot_id.unwrap());
        assert_eq!(tl[1].id, pre2);
        assert_eq!(tl[1].origin, SnapshotOrigin::BeforeRestore);

        fs::remove_file(ws.join("extra.txt")).unwrap();
        let pure_recover = restore_snapshot_paths_with_vault(
            &ws, Some(&vault), "latest", true, &["extra.txt".into()],
        ).unwrap();
        assert!(pure_recover.safety_snapshot_id.is_none(), "pure missing-file recovery must skip redundant BeforeRestore");
        assert!(pure_recover.post_snapshot_id.is_none());
        assert_eq!(fs::read_to_string(ws.join("extra.txt")).unwrap(), "stay");

        fs::remove_dir_all(&ws).unwrap();
        let rebuild_latest = restore_snapshot_opts_with_vault(&ws, Some(&vault), "latest", true, true).unwrap();
        assert!(rebuild_latest.safety_snapshot_id.is_none());
        assert!(rebuild_latest.post_snapshot_id.is_none(), "missing-root rebuild from T[0] needs no extra S_post");

        fs::remove_dir_all(&ws).unwrap();
        let rebuild_old = restore_snapshot_opts_with_vault(&ws, Some(&vault), &s1.id, true, true).unwrap();
        assert!(rebuild_old.safety_snapshot_id.is_none());
        assert!(rebuild_old.post_snapshot_id.is_some(), "missing-root rebuild from older S1 must append S_post");
    }

    #[test]
    fn legacy_meta_origin_inference_and_semicolon_summary_escaping() {
        let sb = R8ScopedDir::new("legacy-meta");
        let meta_p = sb.0.join("meta.kv");
        fs::write(
            &meta_p,
            "id=snap-1000-0001\ncreated_ms=1000\nlabel=auto:claude:pre\nworkspace=/tmp/w\nroot_inode=1\nroot_mode=493\nfile_count=1\nproject_files=1\nlogical_bytes=5\ntree_sha256=fast:abc\nelapsed_us=10\ntarget_kind=dir\n",
        ).unwrap();
        let m = SnapshotMeta::read_from(&meta_p).unwrap();
        assert_eq!(m.origin, SnapshotOrigin::Hook);
        assert!(m.retention_pin.is_none());
        assert!(m.restored_from_id.is_none());

        let s = crate::meta::summarize_project_diff(
            &["add;1.txt".into()],
            &["mod.txt".into()],
            &["del;x|y.txt".into()],
            &[RenamePair { from: "old;1.txt".into(), to: "new;2.txt".into() }],
        ).unwrap();
        assert_eq!(s, "D:del_x|y.txt|1;R:old_1.txt->new_2.txt|1");
    }

    #[test]
    fn prune_auto_preserves_pinned_initial_and_before_restore_while_keep_zero_clears() {
        let _lock = crate::tests::ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _eg = crate::tests::TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
        let sb = R8ScopedDir::new("prune-protect");
        let vault = sb.0.join("vault");
        let ws = sb.0.join("ws");
        fs::create_dir_all(&vault).unwrap();
        fs::create_dir_all(&ws).unwrap();

        fs::write(ws.join("keep.txt"), b"v0").unwrap();
        fs::write(ws.join("victim.txt"), b"bye").unwrap();
        let s_init = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
        assert_eq!(s_init.origin, SnapshotOrigin::Initial);

        fs::remove_file(ws.join("victim.txt")).unwrap();
        fs::write(ws.join("keep.txt"), b"v1").unwrap();
        let r_pin = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
        assert_eq!(r_pin.promoted_pre_delete_id.as_deref(), Some(s_init.id.as_str()));

        fs::write(ws.join("keep.txt"), b"dirty-before-restore").unwrap();
        let rep = restore_snapshot_opts_with_vault(&ws, Some(&vault), &s_init.id, true, true).unwrap();
        let pre_id = rep.safety_snapshot_id.expect("expected BeforeRestore snapshot");

        for i in 0..14 {
            fs::write(ws.join("keep.txt"), format!("auto-step-{}-{}", i, "x".repeat(i))).unwrap();
            let _ = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:fsevents", true).unwrap();
        }
        let before_all = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
        assert!(before_all.len() >= 16);

        let _ = crate::prune::prune_snapshots_filtered_with_vault(&ws, Some(&vault), 10, Some("auto:")).unwrap();
        let after_auto = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
        let ids: Vec<String> = after_auto.iter().map(|m| m.id.clone()).collect();
        assert!(ids.contains(&s_init.id), "Initial & delete-pinned snapshot must survive auto prune");
        assert!(ids.contains(&pre_id), "BeforeRestore snapshot must survive auto prune");
        let normal_auto = after_auto.iter().filter(|m| m.label.starts_with("auto:") && !crate::prune::is_prune_protected(m)).count();
        assert_eq!(normal_auto, 10, "non-protected auto snapshots should trim to keep=10");

        let _ = crate::prune::prune_snapshots_filtered_with_vault(&ws, Some(&vault), 0, None).unwrap();
        let after_zero = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
        assert!(after_zero.is_empty(), "prune --keep 0 must still wipe entire vault cleanly");
    }
}
