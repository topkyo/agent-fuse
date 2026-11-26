use crate::apfs::{current_euid, force_unlock};
use crate::diff::diff_snapshot_opts_with_vault;
use crate::error::{ERR_EINVAL, ERR_ENOENT};
use crate::fs_guard::HeteroStashGuard;
use crate::prune::prune_unlocked;
use crate::restore::{
    restore_snapshot_opts_with_vault, restore_snapshot_paths_with_vault,
    restore_snapshot_with_vault,
};
use crate::snapshot::{
    create_snapshot_fast_dedup_with_vault, create_snapshot_if_changed_with_vault,
    create_snapshot_opts_with_vault, create_snapshot_with_vault, list_snapshots_unlocked,
    list_snapshots_with_vault,
};
use crate::tests::{ScopedDir, TestEnvGuard, ENV_LOCK};
use crate::trash::{allowed_trash_roots_for, purge_workspace_trash_with_vault, TrashCleanupStatus};
use crate::vault::{prepare_workspace_vault_with, resolve_workspace_vault_recovery, TargetKind};
use crate::vault_policy::VerifiedLiveTarget;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::process::Command;
use std::thread;
use std::time::Duration;

#[test]
fn case_insensitive_top_and_selective_restore_preserves_and_fixes_case() {
    let sb = ScopedDir::new("rest-case");
    let (ws, vault) = (sb.0.join("ws"), sb.0.join("vault"));
    fs::create_dir_all(ws.join("Src")).unwrap();
    fs::write(ws.join("Readme.md"), b"orig-readme").unwrap();
    fs::write(ws.join("Src/Utils.rs"), b"orig-utils").unwrap();

    let base = create_snapshot_with_vault(&ws, Some(&vault), "base").unwrap();
    fs::rename(ws.join("Readme.md"), ws.join("README.md")).unwrap();
    fs::rename(ws.join("Src/Utils.rs"), ws.join("Src/utils.rs")).unwrap();
    fs::rename(ws.join("Src"), ws.join("SRC")).unwrap();

    let sel_rep = restore_snapshot_paths_with_vault(
        &ws,
        Some(&vault),
        &base.id,
        true,
        &[String::from("Src/Utils.rs")],
    )
    .unwrap();
    assert!(sel_rep.safety_snapshot_id.is_some());
    let top_entries: Vec<String> = fs::read_dir(&ws)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(top_entries.contains(&"Src".to_string()), "top entries={:?}", top_entries);
    let src_entries: Vec<String> = fs::read_dir(ws.join("Src"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(src_entries.contains(&"Utils.rs".to_string()), "src entries={:?}", src_entries);
    assert_eq!(fs::read(ws.join("Src/Utils.rs")).unwrap(), b"orig-utils");

    restore_snapshot_with_vault(&ws, Some(&vault), &base.id, true).unwrap();
    let top_after: Vec<String> = fs::read_dir(&ws)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(top_after.contains(&"Readme.md".to_string()), "top_after={:?}", top_after);
    assert_eq!(fs::read(ws.join("Readme.md")).unwrap(), b"orig-readme");
}

#[test]
fn corrupt_zombie_snaps_and_if_changed_ignores_pre_restore() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
    let sb = ScopedDir::new("rest-zombie");
    let (ws, vault) = (sb.0.join("ws"), sb.0.join("vault"));
    fs::create_dir_all(&ws).unwrap();
    fs::write(ws.join("app.txt"), b"v1").unwrap();
    let s1 = create_snapshot_with_vault(&ws, Some(&vault), "base").unwrap();

    fs::write(ws.join("app.txt"), b"v2").unwrap();
    let _pre = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pre-restore", true).unwrap();
    let (s2, dedup) = create_snapshot_if_changed_with_vault(&ws, Some(&vault), "auto:new").unwrap();
    assert!(!dedup);
    assert_ne!(s2.id, s1.id);

    let (_, ws_vault) = prepare_workspace_vault_with(&ws, Some(&vault)).unwrap();
    let z_no_tree = ws_vault.join("snapshots").join("snap-9999999999999-z1");
    fs::create_dir_all(&z_no_tree).unwrap();
    fs::write(
        z_no_tree.join("meta.kv"),
        fs::read(ws_vault.join("snapshots").join(&s2.id).join("meta.kv")).unwrap(),
    )
    .unwrap();
    let z_corrupt = ws_vault.join("snapshots").join("snap-9999999999999-z2");
    fs::create_dir_all(z_corrupt.join("tree")).unwrap();
    fs::write(z_corrupt.join("meta.kv"), b"corrupt_data_missing_id").unwrap();

    let listed = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
    assert!(!listed.iter().any(|m| m.id.contains("-z")));

    let removed = crate::prune::prune_snapshots_with_vault(&ws, Some(&vault), 10).unwrap();
    assert!(removed >= 2, "expected zombies removed, removed={}", removed);
    assert!(!z_no_tree.exists() && !z_corrupt.exists());
}

#[test]
fn selective_restore_symlink_target_change_creates_pre_restore() {
    let sb = ScopedDir::new("rest-sym");
    let (ws, vault, outside) = (sb.0.join("ws"), sb.0.join("vault"), sb.0.join("outside"));
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"outside").unwrap();
    symlink(&outside, ws.join("link_out")).unwrap();

    let base = create_snapshot_with_vault(&ws, Some(&vault), "sym").unwrap();
    fs::remove_file(ws.join("link_out")).unwrap();
    symlink(sb.0.join("other_target"), ws.join("link_out")).unwrap();

    let rep = restore_snapshot_paths_with_vault(
        &ws,
        Some(&vault),
        &base.id,
        true,
        &[String::from("link_out")],
    )
    .unwrap();
    assert!(rep.safety_snapshot_id.is_some());
    assert_eq!(fs::read_link(ws.join("link_out")).unwrap(), outside);
}

#[test]
fn chmod_0000_snap_and_uchg_selective_restore() {
    let sb = ScopedDir::new("rest-0000");
    let (ws, vault) = (sb.0.join("ws"), sb.0.join("vault"));
    let sub = ws.join("locked_sub");
    fs::create_dir_all(&sub).unwrap();
    let f0 = sub.join("secret.key");
    fs::write(&f0, b"top-secret").unwrap();
    fs::set_permissions(&f0, fs::Permissions::from_mode(0o000)).unwrap();

    let s = create_snapshot_with_vault(&ws, Some(&vault), "zero-perm").unwrap();
    assert_eq!(s.file_count, 1);
    assert_eq!(fs::symlink_metadata(&f0).unwrap().permissions().mode() & 0o777, 0o000);

    fs::set_permissions(&f0, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&f0, b"tampered").unwrap();
    let _ = Command::new("chflags").args(["uchg", sub.to_str().unwrap()]).status();

    let res = restore_snapshot_paths_with_vault(
        &ws,
        Some(&vault),
        &s.id,
        true,
        &[String::from("locked_sub/secret.key")],
    );
    force_unlock(&sub);
    assert!(res.is_ok(), "uchg selective restore failed: {:?}", res);
    assert_eq!(fs::symlink_metadata(&f0).unwrap().permissions().mode() & 0o777, 0o000);

    fs::set_permissions(&f0, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&f0, b"tampered-full").unwrap();
    restore_snapshot_with_vault(&ws, Some(&vault), &s.id, true).unwrap();
    assert_eq!(fs::symlink_metadata(&f0).unwrap().permissions().mode() & 0o777, 0o000);
    fs::set_permissions(&f0, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fs::read(&f0).unwrap(), b"top-secret");
}

#[test]
fn dedup_adjacent_auto_snaps_and_calibrate_legacy_meta() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
    let sb = ScopedDir::new("rest-legacy");
    let (ws, vault) = (sb.0.join("ws"), sb.0.join("vault"));
    fs::create_dir_all(ws.join(".git")).unwrap();
    fs::write(ws.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(ws.join("src.rs"), b"v1").unwrap();

    let s1 = create_snapshot_with_vault(&ws, Some(&vault), "tmp1").unwrap();
    let s2 = create_snapshot_with_vault(&ws, Some(&vault), "tmp2").unwrap();
    let s3 = create_snapshot_with_vault(&ws, Some(&vault), "tmp3").unwrap();
    let (_, ws_vault) = prepare_workspace_vault_with(&ws, Some(&vault)).unwrap();

    for (idx, id) in [&s1.id, &s2.id, &s3.id].iter().enumerate() {
        let mp = ws_vault.join("snapshots").join(id).join("meta.kv");
        let lbl = if idx == 0 { "label=auto:pro:init" } else { "label=auto:pro:fsevents" };
        let filtered: Vec<String> = fs::read_to_string(&mp)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("project_files="))
            .map(|l| {
                if l.starts_with("tree_sha256=") {
                    "tree_sha256=fast".to_string()
                } else if l.starts_with("label=") {
                    lbl.to_string()
                } else {
                    l.to_string()
                }
            })
            .collect();
        fs::write(&mp, filtered.join("\n") + "\n").unwrap();
    }

    let removed = prune_unlocked(&ws_vault, 10, Some("auto:"), 0).unwrap();
    assert_eq!(removed, 2);
    let rem = list_snapshots_unlocked(&ws_vault).unwrap();
    assert_eq!(rem.len(), 1);
    assert_eq!(rem[0].project_files, 1);
    assert!(rem[0].tree_sha256.starts_with("fast:"));

    let sf = sb.0.join("legacy.txt");
    fs::write(&sf, b"sf").unwrap();
    let ssf = create_snapshot_with_vault(&sf, Some(&vault), "auto:pro:init").unwrap();
    let (_, sf_vault) = prepare_workspace_vault_with(&sf, Some(&vault)).unwrap();
    let sf_mp = sf_vault.join("snapshots").join(&ssf.id).join("meta.kv");
    let sf_legacy: Vec<String> = fs::read_to_string(&sf_mp)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("project_files="))
        .map(|l| {
            if l.starts_with("tree_sha256=") {
                "tree_sha256=fast".to_string()
            } else {
                l.to_string()
            }
        })
        .collect();
    fs::write(&sf_mp, sf_legacy.join("\n") + "\n").unwrap();
    let _ = prune_unlocked(&sf_vault, 10, Some("auto:"), 0).unwrap();
    let sf_rem = list_snapshots_unlocked(&sf_vault).unwrap();
    assert_eq!(sf_rem[0].project_files, 1);
    assert!(sf_rem[0].tree_sha256.starts_with("fast:"));
}

#[test]
fn nested_zero_mode_dir_and_symlink_nested_ignored_and_verified_live_target() {
    let sb = ScopedDir::new("rest-zero-vlt");
    let ws = sb.0.join("ws");
    let vault = sb.0.join("vault");
    let outer = ws.join("locked_dir");
    let inner = outer.join("inner");
    fs::create_dir_all(&inner).unwrap();
    fs::write(inner.join("secret.txt"), "deep\n").unwrap();
    fs::set_permissions(&inner, fs::Permissions::from_mode(0o000)).unwrap();
    fs::set_permissions(&outer, fs::Permissions::from_mode(0o000)).unwrap();

    let full = create_snapshot_opts_with_vault(&ws, Some(&vault), "full-zero", false).unwrap();
    restore_snapshot_with_vault(&ws, Some(&vault), &full.id, false).unwrap();
    assert_eq!(fs::symlink_metadata(&outer).unwrap().permissions().mode() & 0o777, 0o000);

    let fast = create_snapshot_opts_with_vault(&ws, Some(&vault), "fast-zero", true).unwrap();
    restore_snapshot_with_vault(&ws, Some(&vault), &fast.id, false).unwrap();
    let diff = diff_snapshot_opts_with_vault(&ws, Some(&vault), &fast.id, true).unwrap();
    assert!(diff.added.is_empty() && diff.deleted.is_empty() && diff.modified.is_empty());

    // Symlink replacing dir with nested ignored
    let ws2 = sb.0.join("ws2");
    let outside = sb.0.join("outside");
    fs::create_dir_all(&ws2).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(ws2.join("a.txt"), "root-a\n").unwrap();
    symlink(&outside, ws2.join("pkg")).unwrap();
    let snap2 = create_snapshot_opts_with_vault(&ws2, Some(&vault), "s1", false).unwrap();
    fs::remove_file(ws2.join("pkg")).unwrap();
    fs::create_dir_all(ws2.join("pkg/node_modules")).unwrap();
    fs::write(ws2.join("pkg/node_modules/dep.js"), "dep\n").unwrap();
    restore_snapshot_with_vault(&ws2, Some(&vault), &snap2.id, false).unwrap();
    assert!(fs::symlink_metadata(ws2.join("pkg")).unwrap().file_type().is_symlink());
    assert!(!outside.join("node_modules").exists());

    // VerifiedLiveTarget boundary checks
    let dir = sb.0.join("dir");
    let file = sb.0.join("note.txt");
    let sym = sb.0.join("sym-dir");
    fs::create_dir_all(&dir).unwrap();
    fs::write(&file, "hi\n").unwrap();
    symlink(&dir, &sym).unwrap();
    let ok_dir = VerifiedLiveTarget::open_matching(&dir, TargetKind::Directory).unwrap();
    assert_eq!(ok_dir.kind(), TargetKind::Directory);
    assert_eq!(ok_dir.path(), dir.as_path());
    assert_eq!(
        VerifiedLiveTarget::open_matching(&dir, TargetKind::SingleFile).unwrap_err().code,
        ERR_EINVAL
    );
    assert_eq!(
        VerifiedLiveTarget::open_matching(&sym, TargetKind::Directory).unwrap_err().code,
        ERR_EINVAL
    );
    assert_eq!(
        VerifiedLiveTarget::open_matching(&sb.0.join("absent"), TargetKind::Directory)
            .unwrap_err()
            .code,
        ERR_ENOENT
    );
}

#[test]
fn trash_icloud_purge_large_dir_tcc_and_selective_sibling_isolation() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = TestEnvGuard::clean(&["AFUSE_TRASH_DIR"]);
    let sb = ScopedDir::new("rest-trash");
    let local_trash = sb.0.join(".Trash");
    let icloud_trash = sb.0.join("Library/Mobile Documents/com~apple~CloudDocs/.Trash");
    let ro_empty_trash = sb.0.join("empty-ro-trash");
    let vault = sb.0.join("vault");
    let desktop = sb.0.join("Desktop");
    for d in [&local_trash, &icloud_trash, &ro_empty_trash, &vault, &desktop] {
        fs::create_dir_all(d).unwrap();
    }

    let roots = allowed_trash_roots_for(Some(&sb.0), None, None, current_euid());
    assert!(roots.contains(&fs::canonicalize(&local_trash).unwrap()));
    assert!(roots.contains(&fs::canonicalize(&icloud_trash).unwrap()));

    let resume = desktop.join("个人简历.pdf");
    fs::write(&resume, b"%PDF-1.4 resume-v1\n").unwrap();
    std::env::set_var("AFUSE_TRASH_DIR", &icloud_trash);
    let snap = create_snapshot_opts_with_vault(&resume, Some(&vault), "init", true).unwrap();
    let trashed = icloud_trash.join("个人简历.pdf");
    fs::rename(&resume, &trashed).unwrap();
    let rep = restore_snapshot_with_vault(&resume, Some(&vault), &snap.id, false).unwrap();
    assert_eq!(rep.trash_cleanup, TrashCleanupStatus::Purged);
    assert!(resume.is_file() && !trashed.exists());

    let tmp_save = desktop.join(".个人简历.pdf.tmp");
    fs::write(&tmp_save, b"%PDF-1.4 resume-v2\n").unwrap();
    fs::rename(&tmp_save, &resume).unwrap();
    fs::set_permissions(&ro_empty_trash, fs::Permissions::from_mode(0o500)).unwrap();
    std::env::set_var("AFUSE_TRASH_DIR", &ro_empty_trash);
    let rep2 = restore_snapshot_with_vault(&resume, Some(&vault), &snap.id, false).unwrap();
    let purge2 = purge_workspace_trash_with_vault(&resume, Some(&vault)).unwrap();
    fs::set_permissions(&ro_empty_trash, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(rep2.trash_cleanup, TrashCleanupStatus::NotInTrash);
    assert_eq!(purge2, TrashCleanupStatus::NotInTrash);

    // Large dir TccDenied retains live root & purges both generations
    let proj = sb.0.join("proj");
    let trash = sb.0.join("trash");
    fs::create_dir_all(&proj).unwrap();
    fs::create_dir_all(&trash).unwrap();
    for i in 0..32 {
        fs::write(proj.join(format!("f{:02}.txt", i)), format!("data-{}\n", i)).unwrap();
    }
    std::env::set_var("AFUSE_TRASH_DIR", &trash);
    let snap_p = create_snapshot_opts_with_vault(&proj, Some(&vault), "init", true).unwrap();
    let gen1 = trash.join("proj-gen1");
    fs::rename(&proj, &gen1).unwrap();
    fs::set_permissions(&trash, fs::Permissions::from_mode(0o500)).unwrap();
    let rep_tcc = restore_snapshot_with_vault(&proj, Some(&vault), &snap_p.id, false).unwrap();
    assert_eq!(rep_tcc.trash_cleanup, TrashCleanupStatus::TccDenied);
    let live_gen2_ino = fs::symlink_metadata(&proj).unwrap().ino();
    let (_, ws_vault) = resolve_workspace_vault_recovery(&proj, Some(&vault)).unwrap();
    let ledger_roots = crate::trash_ledger::load_root_inodes(&ws_vault);
    assert!(ledger_roots.contains(&live_gen2_ino) && ledger_roots.contains(&snap_p.root_inode));
    fs::set_permissions(&trash, fs::Permissions::from_mode(0o700)).unwrap();
    let gen2 = trash.join("proj-gen2");
    fs::rename(&proj, &gen2).unwrap();
    let rep_ok = restore_snapshot_with_vault(&proj, Some(&vault), &snap_p.id, false).unwrap();
    assert_eq!(rep_ok.trash_cleanup, TrashCleanupStatus::Purged);
    assert!(!gen1.exists() && !gen2.exists());

    // Selective restore purges only restored file in trash, preserves prefix-similar sibling
    let ws_sel = sb.0.join("ws-sel");
    let tr_sel = sb.0.join("tr-sel");
    fs::create_dir_all(&ws_sel).unwrap();
    fs::create_dir_all(&tr_sel).unwrap();
    fs::write(ws_sel.join("a"), b"file-a").unwrap();
    fs::write(ws_sel.join("ab.txt"), b"prefix-sibling").unwrap();
    fs::write(ws_sel.join("sibling.txt"), b"other-sibling").unwrap();
    std::env::set_var("AFUSE_TRASH_DIR", &tr_sel);
    let s_sel = create_snapshot_opts_with_vault(&ws_sel, Some(&vault), "auto:pro:init", true).unwrap();
    fs::rename(ws_sel.join("a"), tr_sel.join("a")).unwrap();
    fs::rename(ws_sel.join("ab.txt"), tr_sel.join("ab.txt")).unwrap();
    fs::rename(ws_sel.join("sibling.txt"), tr_sel.join("sibling.txt")).unwrap();
    let rep_s = restore_snapshot_paths_with_vault(&ws_sel, Some(&vault), &s_sel.id, false, &["a".into()]).unwrap();
    assert_eq!(rep_s.trash_cleanup, TrashCleanupStatus::Purged);
    assert!(!tr_sel.join("a").exists());
    assert!(tr_sel.join("ab.txt").exists() && tr_sel.join("sibling.txt").exists());
}

#[test]
fn fast_diff_nested_dir_counts_and_fast_restore_receipts() {
    let sb = ScopedDir::new("rest-fast");
    let vault = sb.0.join("vault");
    let ws = sb.0.join("ws");
    fs::create_dir_all(ws.join("a/b/c")).unwrap();
    fs::create_dir_all(&vault).unwrap();
    fs::write(ws.join("root.txt"), b"r").unwrap();
    fs::write(ws.join("a/b/c/leaf.txt"), b"l").unwrap();
    let big_bytes = vec![0x42u8; (16 * 1024 * 1024) + 64];
    fs::write(ws.join("big.bin"), &big_bytes).unwrap();

    let s0 = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:init", true).unwrap();
    assert_eq!(s0.project_files, 3);
    thread::sleep(Duration::from_millis(25));
    fs::write(ws.join("root.txt"), b"r").unwrap();
    let d1 = diff_snapshot_opts_with_vault(&ws, Some(&vault), &s0.id, true).unwrap();
    assert!(d1.added.is_empty() && d1.modified.is_empty() && d1.deleted.is_empty());
    let (dedup_m, was_dedup) =
        create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap();
    assert!(was_dedup && dedup_m.id == s0.id);

    thread::sleep(Duration::from_millis(25));
    fs::write(ws.join("big.bin"), &big_bytes).unwrap();
    let d2 = diff_snapshot_opts_with_vault(&ws, Some(&vault), &s0.id, true).unwrap();
    assert!(d2.modified.contains(&"big.bin".to_string()));

    let rep_fast = restore_snapshot_opts_with_vault(&ws, Some(&vault), &s0.id, true, true).unwrap();
    assert_eq!(rep_fast.tree_sha256.len(), 64);
    assert!(!rep_fast.tree_sha256.starts_with("fast:"));

    fs::remove_file(ws.join("root.txt")).unwrap();
    fs::create_dir_all(ws.join("root.txt")).unwrap();
    let d_het = diff_snapshot_opts_with_vault(&ws, Some(&vault), &s0.id, true).unwrap();
    assert!(d_het.modified.contains(&"root.txt".to_string()));
}

#[test]
fn hetero_stash_guard_readonly_parent_and_rollback_preserves_original_data() {
    let sb = ScopedDir::new("rest-hetero-ro");
    let ro_parent = sb.0.join("ro_parent");
    let vault = sb.0.join("vault");
    fs::create_dir_all(&ro_parent).unwrap();
    fs::create_dir_all(&vault).unwrap();

    let target = ro_parent.join("item");
    fs::write(&target, b"precious-user-file").unwrap();
    fs::set_permissions(&ro_parent, fs::Permissions::from_mode(0o555)).unwrap();

    {
        let mut g = HeteroStashGuard::stash_if_needed(&target, &vault, true, true).unwrap();
        assert!(g.cleared);
        // Simulate prepare_restore_stage creating an empty placeholder directory, then failing before commit()
        fs::set_permissions(&ro_parent, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&ro_parent, fs::Permissions::from_mode(0o555)).unwrap();
        g.mark_placeholder_created();
        // Drop without commit() must remove placeholder and move original file back even under 0555 parent
    }

    assert_eq!(fs::symlink_metadata(&ro_parent).unwrap().permissions().mode() & 0o777, 0o555);
    assert!(target.is_file(), "rollback must restore original regular file");
    assert_eq!(fs::read(&target).unwrap(), b"precious-user-file");
    fs::set_permissions(&ro_parent, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn sticky_bit_mode_01555_restore_matches_merkle_and_git_fifo_skipped() {
    let sb = ScopedDir::new("rest-sticky-fifo");
    let ws = sb.0.join("ws");
    let vault = sb.0.join("vault");
    let sticky_dir = ws.join("sticky_dir");
    fs::create_dir_all(&sticky_dir).unwrap();
    fs::create_dir_all(ws.join(".git")).unwrap();
    fs::write(ws.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(sticky_dir.join("note.txt"), b"sticky-ok").unwrap();
    fs::set_permissions(&sticky_dir, fs::Permissions::from_mode(0o1555)).unwrap();

    // Create a real FIFO inside .git to verify W-L1-11 skips special files under .git without EINVAL
    let fifo = ws.join(".git/fsmonitor.fifo");
    let mk_st = Command::new("/usr/bin/mkfifo").arg(&fifo).status().unwrap();
    assert!(mk_st.success());

    let snap = create_snapshot_opts_with_vault(&ws, Some(&vault), "sticky-fifo", false).unwrap();
    let rep = restore_snapshot_with_vault(&ws, Some(&vault), &snap.id, false).unwrap();
    assert_eq!(rep.tree_sha256, snap.tree_sha256);
    assert_eq!(fs::read(sticky_dir.join("note.txt")).unwrap(), b"sticky-ok");
    fs::set_permissions(&sticky_dir, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn max_walk_depth_128_boundary_completes_without_stack_overflow() {
    let sb = ScopedDir::new("rest-depth128");
    let ws_ok = sb.0.join("ws-ok");
    let ws_too_deep = sb.0.join("ws-too-deep");
    let vault = sb.0.join("vault");
    fs::create_dir_all(&vault).unwrap();

    // Depth 110 (< MAX_WALK_DEPTH=128) succeeds cleanly
    let mut cur_ok = ws_ok.clone();
    for i in 0..110 {
        cur_ok.push(format!("d{}", i));
    }
    fs::create_dir_all(&cur_ok).unwrap();
    fs::write(cur_ok.join("ok.txt"), b"within-limit").unwrap();
    let snap = create_snapshot_opts_with_vault(&ws_ok, Some(&vault), "deep-ok", true).unwrap();
    assert_eq!(snap.project_files, 1);

    // Depth 135 (> MAX_WALK_DEPTH=128) fails closed with ERR_EINVAL instead of stack overflow
    let mut cur_deep = ws_too_deep.clone();
    for i in 0..135 {
        cur_deep.push(format!("d{}", i));
    }
    fs::create_dir_all(&cur_deep).unwrap();
    fs::write(cur_deep.join("deep.txt"), b"beyond-128").unwrap();
    let err = create_snapshot_opts_with_vault(&ws_too_deep, Some(&vault), "too-deep", true)
        .unwrap_err();
    assert_eq!(err.code, ERR_EINVAL);
}
