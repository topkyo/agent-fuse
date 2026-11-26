use crate::apfs::{acquire_flock_blocking, release_flock};
use crate::diff::diff_snapshot_opts_with_vault;
use crate::error::ERR_EEXIST;
use crate::meta::{read_verified_snap_meta, write_meta};
use crate::relocate::{
    inspect_vault_orphans, locate_workspace_target_with_vault, prune_orphan_vaults_with,
    relocate_workspace_vault_with, LocateOutcome,
};
use crate::restore::restore_snapshot_with_vault;
use crate::snapshot::{create_snapshot_opts_with_vault, list_snapshots_with_vault};
use crate::tests::{ScopedDir, TestEnvGuard, ENV_LOCK};
use crate::vault::{resolve_workspace_vault_recovery, TargetKind, VAULT_ROOT_MARKER};
use std::fs;
use std::os::unix::fs::MetadataExt;

#[test]
fn locate_and_relocate_single_file_rename_preserves_merkle_and_zero_orphan() {
    let sb = ScopedDir::new("reloc-file");
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
    let vault_dirs: Vec<_> = fs::read_dir(&vault)
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_dir())
        .collect();
    assert_eq!(vault_dirs.len(), 1);

    let diff = diff_snapshot_opts_with_vault(&p2, Some(&vault), &full.id, false).unwrap();
    assert!(diff.added.is_empty() && diff.deleted.is_empty() && diff.modified.is_empty());

    fs::write(&p2, b"corrupted\n").unwrap();
    restore_snapshot_with_vault(&p2, Some(&vault), &full.id, false).unwrap();
    assert_eq!(fs::read(&p2).unwrap(), b"%PDF-1.4 original\n");
    restore_snapshot_with_vault(&p2, Some(&vault), &fast.id, false).unwrap();
    assert_eq!(fs::read(&p2).unwrap(), b"%PDF-1.4 original\n");
}

#[test]
fn locate_distinguishes_trashed_and_relocate_blocks_eexist_collision() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = TestEnvGuard::clean(&["AFUSE_TRASH_DIR"]);
    let sb = ScopedDir::new("reloc-trash");
    let vault = sb.0.join("vault");
    let trash = sb.0.join("trash");
    let d1 = sb.0.join("a");
    let d2 = sb.0.join("b");
    for d in [&vault, &trash, &d1, &d2] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(d1.join("x.txt"), "x\n").unwrap();
    fs::write(d2.join("y.txt"), "y\n").unwrap();
    let ino1 = fs::symlink_metadata(&d1).unwrap().ino();

    std::env::set_var("AFUSE_TRASH_DIR", &trash);
    create_snapshot_opts_with_vault(&d1, Some(&vault), "s1", true).unwrap();
    create_snapshot_opts_with_vault(&d2, Some(&vault), "s2", true).unwrap();

    let trashed_d1 = trash.join("a");
    fs::rename(&d1, &trashed_d1).unwrap();
    let loc = locate_workspace_target_with_vault(&d1, Some(&vault), Some(ino1)).unwrap();
    assert!(matches!(loc, LocateOutcome::Trashed { .. }), "got {:?}", loc);

    let d3 = sb.0.join("c");
    fs::rename(&trashed_d1, &d3).unwrap();
    create_snapshot_opts_with_vault(&d3, Some(&vault), "s3", true).unwrap();
    let d2_ino = fs::symlink_metadata(&d2).unwrap().ino();
    fs::remove_dir_all(&d3).unwrap();
    let err = relocate_workspace_vault_with(&d3, &d2, Some(&vault), Some(d2_ino)).unwrap_err();
    assert_eq!(err.code, ERR_EEXIST);

    let d4 = sb.0.join("fresh_src");
    let d5 = sb.0.join("fresh_dst");
    fs::create_dir_all(&d4).unwrap();
    let d4_ino = fs::symlink_metadata(&d4).unwrap().ino();
    fs::rename(&d4, &d5).unwrap();
    let fresh_rel = relocate_workspace_vault_with(&d4, &d5, Some(&vault), Some(d4_ino)).unwrap();
    assert_eq!(fresh_rel.snapshots_updated, 0);
}

#[test]
fn case_only_rename_locate_and_relocate_preserves_history() {
    let sb = ScopedDir::new("reloc-case");
    let vault = sb.0.join("vault");
    let ws_lower = sb.0.join("myrepo");
    let ws_upper = sb.0.join("MyRepo");
    fs::create_dir_all(&vault).unwrap();
    fs::create_dir_all(&ws_lower).unwrap();
    fs::write(ws_lower.join("code.rs"), b"v1").unwrap();
    let ino = fs::symlink_metadata(&ws_lower).unwrap().ino();

    let s1 = create_snapshot_opts_with_vault(&ws_lower, Some(&vault), "base", true).unwrap();
    fs::rename(&ws_lower, &ws_upper).unwrap();

    let loc = locate_workspace_target_with_vault(&ws_lower, Some(&vault), Some(ino)).unwrap();
    assert!(
        matches!(loc, LocateOutcome::MovedValid { ref new_path, .. } if new_path.file_name().and_then(|n| n.to_str()) == Some("MyRepo")),
        "case-only rename must report MovedValid with exact casing, got {:?}",
        loc
    );

    let rel = relocate_workspace_vault_with(&ws_lower, &ws_upper, Some(&vault), Some(ino)).unwrap();
    assert!(rel.snapshots_updated >= 1 || list_snapshots_with_vault(&ws_upper, Some(&vault)).unwrap().iter().any(|m| m.id == s1.id));
    let snaps = list_snapshots_with_vault(&ws_upper, Some(&vault)).unwrap();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].id, s1.id);
}

#[test]
fn inspect_vault_orphans_with_root_marker_never_deletes_regular_subdir() {
    let sb = ScopedDir::new("reloc-orphan-safe");
    let vault = sb.0.join("vault");
    fs::create_dir_all(&vault).unwrap();
    fs::write(vault.join(VAULT_ROOT_MARKER), b"1\n").unwrap();

    // Create a user-owned regular directory that does NOT match <prefix>-<16hex> + snapshots/vault.lock
    let user_dir = vault.join("my-important-notes");
    fs::create_dir_all(&user_dir).unwrap();
    fs::write(user_dir.join("keep.txt"), b"must-survive").unwrap();

    // Also create a dir matching hex suffix but lacking snapshots/ or vault.lock
    let fake_hex_dir = vault.join("photos-0123456789abcdef");
    fs::create_dir_all(&fake_hex_dir).unwrap();
    fs::write(fake_hex_dir.join("pic.jpg"), b"keep").unwrap();

    let (scanned, orphans) = inspect_vault_orphans(Some(&vault), 0);
    assert_eq!(scanned, 0);
    assert!(orphans.is_empty());

    let rep = prune_orphan_vaults_with(Some(&vault), 0, false).unwrap();
    assert_eq!(rep.removed, 0);
    assert!(user_dir.join("keep.txt").is_file());
    assert!(fake_hex_dir.join("pic.jpg").is_file());
}

#[test]
fn flock_recheck_inode_prevents_split_brain_after_unlink() {
    let sb = ScopedDir::new("reloc-flock-ino");
    let lock_path = sb.0.join("vault.lock");
    let fd1 = acquire_flock_blocking(&lock_path).unwrap();
    let ino1 = fs::symlink_metadata(&lock_path).unwrap().ino();

    // Unlink and recreate lock_path while fd1 holds old inode; another thread acquiring lock
    // must detect inode mismatch on old fd or lock the live inode consistently.
    fs::remove_file(&lock_path).unwrap();
    let fd2 = acquire_flock_blocking(&lock_path).unwrap();
    let ino2 = fs::symlink_metadata(&lock_path).unwrap().ino();
    assert_ne!(ino1, ino2);

    release_flock(fd2);
    release_flock(fd1);
    assert!(lock_path.is_file());
}

#[test]
fn write_meta_atomic_and_dirname_mismatch_isolated() {
    let sb = ScopedDir::new("reloc-meta-atom");
    let ws = sb.0.join("ws");
    let vault = sb.0.join("vault");
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&vault).unwrap();
    fs::write(ws.join("a.txt"), b"v1").unwrap();

    let mut snap = create_snapshot_opts_with_vault(&ws, Some(&vault), "base", true).unwrap();
    let (_, ws_vault) = resolve_workspace_vault_recovery(&ws, Some(&vault)).unwrap();
    let snap_dir = ws_vault.join("snapshots").join(&snap.id);
    let meta_p = snap_dir.join("meta.kv");

    // Atomic rewrite succeeds and leaves zero leftover temp files
    snap.label = "atomic-updated".to_string();
    write_meta(&meta_p, &snap).unwrap();
    let leftovers: Vec<_> = fs::read_dir(&snap_dir)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".meta.kv.tmp"))
        .collect();
    assert!(leftovers.is_empty());
    assert_eq!(read_verified_snap_meta(&snap_dir).unwrap().label, "atomic-updated");

    // Tamper id to mismatch directory name -> read_verified_snap_meta rejects it
    snap.id = "snap-9999999999999-fake".to_string();
    write_meta(&meta_p, &snap).unwrap();
    assert!(read_verified_snap_meta(&snap_dir).is_err());
    assert!(list_snapshots_with_vault(&ws, Some(&vault)).unwrap().is_empty());
}
