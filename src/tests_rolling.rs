use crate::diff::diff_snapshot_opts_with_vault;
use crate::diff_rename::RenamePair;
use crate::error::ERR_EINVAL;
use crate::meta::{encode_summary, SnapshotMeta, SnapshotOrigin, PIN_CONTAINS_DELETED};
use crate::restore::{restore_snapshot_opts_with_vault, restore_snapshot_paths_with_vault};
use crate::rolling::create_snapshot_rolling_with_vault;
use crate::snapshot::{
    create_snapshot_fast_dedup_with_vault, create_snapshot_opts_with_vault,
    list_snapshots_with_vault,
};
use crate::tests::{ScopedDir, TestEnvGuard, ENV_LOCK};
use std::fs;
use std::io::{Seek, SeekFrom, Write};

#[test]
fn git_repo_empty_project_files_blocks_auto_snapshot() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
    let sb = ScopedDir::new("roll-empty-git");
    let (ws, vault) = (sb.0.join("ws"), sb.0.join("vault"));
    fs::create_dir_all(ws.join(".git/objects")).unwrap();
    fs::write(ws.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(ws.join("main.rs"), b"fn main() {}").unwrap();

    let _init = create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pro:init").unwrap();
    fs::remove_file(ws.join("main.rs")).unwrap();
    let err =
        create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap_err();
    assert_eq!(err.code, ERR_EINVAL);
    let manual = create_snapshot_opts_with_vault(&ws, Some(&vault), "manual-empty", false).unwrap();
    assert_eq!(manual.project_files, 0);
}

#[test]
fn rolling_pure_delete_with_git_noise_holds_pins_latest_and_rejects_empty_dir() {
    let sb = ScopedDir::new("roll-pure-del");
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
    assert!(rep.skipped && rep.reason == Some("pure_delete_hold"), "got {:?}", rep);
    assert_eq!(rep.meta.id, s0.id);
    // W-L1-23: pure_delete_hold must immediately pin latest with contains_deleted
    assert_eq!(rep.promoted_pre_delete_id.as_deref(), Some(s0.id.as_str()));

    let snaps = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].retention_pin.as_deref(), Some(PIN_CONTAINS_DELETED));
    let d = diff_snapshot_opts_with_vault(&ws, Some(&vault), "latest", true).unwrap();
    assert!(d.deleted.contains(&"moved_out.txt".to_string()));

    fs::remove_file(ws.join("keep.txt")).unwrap();
    let err = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap_err();
    assert_eq!(err.code, ERR_EINVAL);
    assert!(err.message.contains("empty directory"));
}

#[test]
fn rolling_mixed_change_promotes_pre_delete_caps_at_10_and_preserves_manual_label() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
    let sb = ScopedDir::new("roll-mixed-15");
    let vault = sb.0.join("vault");
    let ws = sb.0.join("ws");
    fs::create_dir_all(&vault).unwrap();
    fs::create_dir_all(&ws).unwrap();
    std::env::set_var("AFUSE_MAX_AUTO_SNAPS", "5");

    fs::write(ws.join("manual_target.txt"), b"manual-era").unwrap();
    fs::write(ws.join("live.txt"), b"v0").unwrap();
    let manual = create_snapshot_opts_with_vault(&ws, Some(&vault), "menubar", true).unwrap();

    fs::remove_file(ws.join("manual_target.txt")).unwrap();
    fs::write(ws.join("live.txt"), b"v1").unwrap();
    let r_after_manual =
        create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
    assert!(r_after_manual.promoted_pre_delete_id.is_none());
    let all_after = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
    assert_eq!(
        all_after.iter().find(|m| m.id == manual.id).map(|m| m.label.as_str()),
        Some("menubar")
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
    assert_eq!(pinned_snaps.len(), 10);
    let (latest_pre_id, orig_label, orig_summary, orig_origin) = &pinned_records[14];
    let latest_pin = pinned_snaps.iter().find(|m| &m.id == latest_pre_id).unwrap();
    assert_eq!(&latest_pin.label, orig_label);
    assert_eq!(&latest_pin.summary, orig_summary);
    assert_eq!(&latest_pin.origin, orig_origin);

    let restored = restore_snapshot_paths_with_vault(
        &ws,
        Some(&vault),
        latest_pre_id,
        false,
        &["victim_14.txt".into()],
    )
    .unwrap();
    assert_eq!(restored.restored_paths, 1);
    assert_eq!(fs::read_to_string(ws.join("victim_14.txt")).unwrap(), "payload-14");
}

#[test]
fn rolling_pure_rename_and_summary_pipe_and_pre_restore_cap_10() {
    let sb = ScopedDir::new("roll-ren-sum");
    let vault = sb.0.join("vault");
    let ws = sb.0.join("ws");
    fs::create_dir_all(ws.join(".git")).unwrap();
    fs::create_dir_all(&vault).unwrap();
    fs::write(ws.join(".git/index"), b"idx1").unwrap();
    fs::write(ws.join("a.txt"), b"same-file-body").unwrap();
    fs::write(ws.join("dup1.txt"), b"dup-body").unwrap();
    fs::write(ws.join("dup2.txt"), b"dup-body").unwrap();
    fs::write(ws.join("foo|bar.txt"), b"pipe-name-data").unwrap();
    fs::write(ws.join("main.rs"), b"v1").unwrap();

    let encoded = encode_summary('H', "dir/foo|bar.txt", 2);
    assert_eq!(encoded.rsplit_once('|').unwrap(), ("H:foo|bar.txt", "2"));

    let s0 = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
    fs::write(ws.join(".git/index"), b"idx2-noise-only").unwrap();
    let git_only = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
    assert!(git_only.skipped && git_only.reason == Some("no_project_changes"));

    fs::rename(ws.join("a.txt"), ws.join("b.txt")).unwrap();
    let r1 = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
    assert!(!r1.skipped && r1.promoted_pre_delete_id.is_none() && r1.meta.id != s0.id);

    fs::remove_file(ws.join("dup1.txt")).unwrap();
    fs::rename(ws.join("dup2.txt"), ws.join("dup_moved.txt")).unwrap();
    let r2 = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
    assert!(!r2.skipped && r2.promoted_pre_delete_id.is_some());

    fs::remove_file(ws.join("foo|bar.txt")).unwrap();
    fs::write(ws.join("main.rs"), b"v2").unwrap();
    let mixed = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
    assert_eq!(mixed.meta.summary.as_deref(), Some("D:foo|bar.txt|1;M:main.rs|1"));

    let (_, dedup_same) =
        create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pre-restore").unwrap();
    assert!(dedup_same);
    for k in 0..12u32 {
        fs::write(ws.join("main.rs"), format!("pre-val-{}", k)).unwrap();
        let (m1, d1) =
            create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pre-restore").unwrap();
        assert!(!d1);
        let (m2, d2) =
            create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pre-restore").unwrap();
        assert!(d2 && m2.id == m1.id);
    }
    let pre_count = list_snapshots_with_vault(&ws, Some(&vault))
        .unwrap()
        .into_iter()
        .filter(|m| m.label == "auto:pre-restore")
        .count();
    assert_eq!(pre_count, 10);
}

#[test]
fn devil_7_step_sequence_append_only_head_and_atomic_rename_undo() {
    let sb = ScopedDir::new("roll-devil7");
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
    assert_eq!(r1.meta.summary.as_deref(), Some("M:A.txt|1"));

    fs::rename(ws.join("B.txt"), ws.join("C.txt")).unwrap();
    let d_ren = diff_snapshot_opts_with_vault(&ws, Some(&vault), "latest", true).unwrap();
    assert_eq!(d_ren.renamed, vec![RenamePair { from: "B.txt".into(), to: "C.txt".into() }]);
    let r2 = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
    assert_eq!(r2.meta.summary.as_deref(), Some("R:B.txt->C.txt|1"));

    fs::remove_file(ws.join("D.txt")).unwrap();
    let r_hold = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
    assert!(r_hold.skipped && r_hold.reason == Some("pure_delete_hold"));

    fs::write(ws.join("E.txt"), b"E:v2").unwrap();
    let r3 = create_snapshot_rolling_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
    assert_eq!(r3.promoted_pre_delete_id.as_deref(), Some(r2.meta.id.as_str()));
    assert_eq!(r3.meta.summary.as_deref(), Some("D:D.txt|1;M:E.txt|1"));

    let rep = restore_snapshot_opts_with_vault(&ws, Some(&vault), &r2.meta.id, true, true).unwrap();
    assert!(rep.safety_snapshot_id.is_none());
    let post_id = rep.post_snapshot_id.expect("restoring older S2 must append S_post head");
    assert_eq!(fs::read_to_string(ws.join("D.txt")).unwrap(), "D:victim");

    let timeline = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
    for w in timeline.windows(2) {
        assert!(w[0].created_ms > w[1].created_ms);
    }
    assert_eq!(timeline[0].id, post_id);
    assert_eq!(timeline[0].origin, SnapshotOrigin::RestoredFrom);

    let sel_ren = restore_snapshot_paths_with_vault(
        &ws,
        Some(&vault),
        &r1.meta.id,
        true,
        &["B.txt".into(), "C.txt".into()],
    )
    .unwrap();
    assert!(sel_ren.safety_snapshot_id.is_some() && sel_ren.post_snapshot_id.is_none());
    assert_eq!(fs::read_to_string(ws.join("B.txt")).unwrap(), "B:body-unique");
    assert!(!ws.join("C.txt").exists());
}

#[test]
fn large_file_rename_pre_restore_invariants_and_high_risk_hold() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _eg = TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
    let sb = ScopedDir::new("roll-large-hold");
    let vault = sb.0.join("vault");
    let ws = sb.0.join("ws");
    fs::create_dir_all(ws.join("sub")).unwrap();
    fs::create_dir_all(&vault).unwrap();

    // Large >16MiB sampled rename + mid mutation rejection
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
    assert_eq!(d_fast.renamed, vec![RenamePair { from: "huge.bin".into(), to: "sub/huge_moved.bin".into() }]);
    let mut f = fs::OpenOptions::new().write(true).open(&moved).unwrap();
    f.seek(SeekFrom::Start((size / 2) as u64)).unwrap();
    f.write_all(b"MID--CHANGED-999").unwrap();
    drop(f);
    let d_mut = diff_snapshot_opts_with_vault(&ws, Some(&vault), &s0.id, true).unwrap();
    assert!(d_mut.renamed.is_empty());

    // Legacy meta inference & semicolon summary escaping
    let meta_p = sb.0.join("meta.kv");
    fs::write(
        &meta_p,
        "id=snap-1000-0001\ncreated_ms=1000\nlabel=auto:claude:pre\nworkspace=/tmp/w\nroot_inode=1\nroot_mode=493\nfile_count=1\nproject_files=1\nlogical_bytes=5\ntree_sha256=fast:abc\nelapsed_us=10\ntarget_kind=dir\n",
    )
    .unwrap();
    assert_eq!(SnapshotMeta::read_from(&meta_p).unwrap().origin, SnapshotOrigin::Hook);
    let sum = crate::meta::summarize_project_diff(
        &["add;1.txt".into()],
        &["mod.txt".into()],
        &["del;x|y.txt".into()],
        &[RenamePair { from: "old;1.txt".into(), to: "new;2.txt".into() }],
    )
    .unwrap();
    assert_eq!(sum, "D:del_x|y.txt|1;R:old_1.txt->new_2.txt|1");

    // High-risk delete hold vs refactor replacement
    let ws_big = sb.0.join("ws-big");
    let ws_ref = sb.0.join("ws-ref");
    fs::create_dir_all(&ws_big).unwrap();
    fs::create_dir_all(&ws_ref).unwrap();
    for i in 0..30 {
        fs::write(ws_big.join(format!("f{:02}.txt", i)), format!("body-{}", i)).unwrap();
    }
    let b0 = create_snapshot_opts_with_vault(&ws_big, Some(&vault), "auto:pro:init", true).unwrap();
    for i in 0..25 {
        fs::remove_file(ws_big.join(format!("f{:02}.txt", i))).unwrap();
    }
    fs::write(ws_big.join("agent.log"), b"oops\n").unwrap();
    let r_big = create_snapshot_rolling_with_vault(&ws_big, Some(&vault), "auto:pro:fsevents").unwrap();
    assert!(r_big.skipped && r_big.reason == Some("high_risk_delete_hold") && r_big.meta.id == b0.id);

    for i in 0..25 {
        fs::write(ws_ref.join(format!("old_{:02}.rs", i)), format!("old-body-{}", i)).unwrap();
    }
    let _ = create_snapshot_opts_with_vault(&ws_ref, Some(&vault), "auto:pro:init", true).unwrap();
    for i in 0..25 {
        fs::remove_file(ws_ref.join(format!("old_{:02}.rs", i))).unwrap();
        fs::write(ws_ref.join(format!("new_{:02}.rs", i)), format!("rewritten-body-{}", i)).unwrap();
    }
    let r_ref = create_snapshot_rolling_with_vault(&ws_ref, Some(&vault), "auto:pro:fsevents").unwrap();
    assert!(!r_ref.skipped);

    // Pre-restore never evaporates + auto prune protects Initial/BeforeRestore/pinned
    let ws_p = sb.0.join("ws-prune");
    fs::create_dir_all(&ws_p).unwrap();
    fs::write(ws_p.join("keep.txt"), b"v0").unwrap();
    fs::write(ws_p.join("victim.txt"), b"bye").unwrap();
    let s_init = create_snapshot_opts_with_vault(&ws_p, Some(&vault), "auto:pro:init", true).unwrap();
    fs::remove_file(ws_p.join("victim.txt")).unwrap();
    fs::write(ws_p.join("keep.txt"), b"v1").unwrap();
    let _ = create_snapshot_rolling_with_vault(&ws_p, Some(&vault), "auto:pro:fsevents").unwrap();
    fs::write(ws_p.join("keep.txt"), b"dirty-before").unwrap();
    let rep_p = restore_snapshot_opts_with_vault(&ws_p, Some(&vault), &s_init.id, true, true).unwrap();
    let pre_id = rep_p.safety_snapshot_id.unwrap();
    for i in 0..14 {
        fs::write(ws_p.join("keep.txt"), format!("step-{}-{}", i, "x".repeat(i))).unwrap();
        let _ = create_snapshot_opts_with_vault(&ws_p, Some(&vault), "auto:pro:fsevents", true).unwrap();
    }
    let _ = crate::prune::prune_snapshots_filtered_with_vault(&ws_p, Some(&vault), 10, Some("auto:")).unwrap();
    let after = list_snapshots_with_vault(&ws_p, Some(&vault)).unwrap();
    let ids: Vec<String> = after.iter().map(|m| m.id.clone()).collect();
    assert!(ids.contains(&s_init.id) && ids.contains(&pre_id));
    let _ = crate::prune::prune_snapshots_filtered_with_vault(&ws_p, Some(&vault), 0, None).unwrap();
    assert!(list_snapshots_with_vault(&ws_p, Some(&vault)).unwrap().is_empty());
}

#[test]
fn rename_detection_bucket_handles_many_same_size_files_accurately() {
    let sb = ScopedDir::new("roll-ren-scale");
    let vault = sb.0.join("vault");
    let ws = sb.0.join("ws");
    fs::create_dir_all(&vault).unwrap();
    fs::create_dir_all(&ws).unwrap();

    // 120 files of identical byte length (16 bytes) but unique content -> tests O(D+A) content_sig buckets
    for i in 0..120u32 {
        fs::write(ws.join(format!("old_{:03}.txt", i)), format!("UNIQUE_BODY_{:04}", i)).unwrap();
    }
    let s0 = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
    for i in 0..120u32 {
        fs::rename(
            ws.join(format!("old_{:03}.txt", i)),
            ws.join(format!("new_{:03}.txt", i)),
        )
        .unwrap();
    }
    let d = diff_snapshot_opts_with_vault(&ws, Some(&vault), &s0.id, true).unwrap();
    assert!(d.added.is_empty() && d.deleted.is_empty());
    assert_eq!(d.renamed.len(), 120);
}
