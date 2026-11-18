use super::*;
use crate::apfs::force_unlock;
use crate::prune::prune_unlocked;
use crate::snapshot::list_snapshots_unlocked;
use crate::vault::prepare_workspace_vault_with;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

struct R3ScopedDir(PathBuf);

impl R3ScopedDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "afuse-r3-{}-{}-{}",
            tag,
            std::process::id(),
            crate::apfs::TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for R3ScopedDir {
    fn drop(&mut self) {
        let _ = crate::apfs::force_remove_all(&self.0);
    }
}

#[test]
fn r3_bug_01_case_insensitive_top_and_selective_restore_preserves_and_fixes_case() {
    let sb = R3ScopedDir::new("r3b01");
    let (ws, vault) = (sb.0.join("ws"), sb.0.join("vault"));
    fs::create_dir_all(ws.join("Src")).unwrap();
    fs::write(ws.join("Readme.md"), b"orig-readme").unwrap();
    fs::write(ws.join("Src/Utils.rs"), b"orig-utils").unwrap();

    let base = create_snapshot_with_vault(&ws, Some(&vault), "base").unwrap();

    // Case-only rename on APFS (case-insensitive): Readme.md -> README.md, Src/Utils.rs -> SRC/utils.rs
    fs::rename(ws.join("Readme.md"), ws.join("README.md")).unwrap();
    fs::rename(ws.join("Src/Utils.rs"), ws.join("Src/utils.rs")).unwrap();
    fs::rename(ws.join("Src"), ws.join("SRC")).unwrap();

    // Selective restore must align both file case and parent dir case, AND keep file alive
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

    // Full restore when top-level Readme.md became README.md must NOT wipe Readme.md
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
fn r3_bug_02_git_repo_empty_project_files_blocks_auto_snapshot() {
    let _lock = crate::tests::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = crate::tests::TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
    let sb = R3ScopedDir::new("r3b02");
    let (ws, vault) = (sb.0.join("ws"), sb.0.join("vault"));
    fs::create_dir_all(ws.join(".git/objects")).unwrap();
    fs::write(ws.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(ws.join("main.rs"), b"fn main() {}").unwrap();

    let _init = create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pro:init").unwrap();
    fs::remove_file(ws.join("main.rs")).unwrap();
    // .git remains non-empty (file_count > 0), yet project_files == 0 -> must refuse auto:*!
    let err = create_snapshot_fast_dedup_with_vault(&ws, Some(&vault), "auto:pro:fsevents").unwrap_err();
    assert_eq!(err.code, ERR_EINVAL);
    // Manual snapshot is still permitted
    let manual = create_snapshot_opts_with_vault(&ws, Some(&vault), "manual-empty", false).unwrap();
    assert_eq!(manual.project_files, 0);
}

#[test]
fn r3_bug_03_06_corrupt_zombie_snaps_and_if_changed_ignores_pre_restore() {
    let _lock = crate::tests::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = crate::tests::TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
    let sb = R3ScopedDir::new("r3b0306");
    let (ws, vault) = (sb.0.join("ws"), sb.0.join("vault"));
    fs::create_dir_all(&ws).unwrap();
    fs::write(ws.join("app.txt"), b"v1").unwrap();
    let s1 = create_snapshot_with_vault(&ws, Some(&vault), "base").unwrap();

    // Write dirty change + take auto:pre-restore directly (same scenario as pre-restore backup)
    fs::write(ws.join("app.txt"), b"v2").unwrap();
    let _pre = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pre-restore", true).unwrap();
    // --if-changed compares against primary (`base`), NOT `auto:pre-restore` -> sees v2 != v1 -> takes new snap
    let (s2, dedup) = create_snapshot_if_changed_with_vault(&ws, Some(&vault), "auto:new").unwrap();
    assert!(!dedup);
    assert_ne!(s2.id, s1.id);

    // Inject zombie snapshots: missing tree/ + corrupt meta.kv
    let (_, ws_vault) = prepare_workspace_vault_with(&ws, Some(&vault)).unwrap();
    let z_no_tree = ws_vault.join("snapshots").join("snap-9999999999999-z1");
    fs::create_dir_all(&z_no_tree).unwrap();
    fs::write(z_no_tree.join("meta.kv"), fs::read(ws_vault.join("snapshots").join(&s2.id).join("meta.kv")).unwrap()).unwrap();
    let z_corrupt = ws_vault.join("snapshots").join("snap-9999999999999-z2");
    fs::create_dir_all(z_corrupt.join("tree")).unwrap();
    fs::write(z_corrupt.join("meta.kv"), b"corrupt_data_missing_id").unwrap();

    let listed = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
    assert!(!listed.iter().any(|m| m.id.contains("-z")));

    let removed = prune_snapshots_with_vault(&ws, Some(&vault), 10).unwrap();
    assert!(removed >= 2, "expected zombies removed, removed={}", removed);
    assert!(!z_no_tree.exists() && !z_corrupt.exists());
}

#[test]
fn r3_bug_04_selective_restore_symlink_target_change_creates_pre_restore() {
    let sb = R3ScopedDir::new("r3b04");
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
fn r3_bug_05_chmod_0000_snap_and_uchg_selective_restore() {
    let sb = R3ScopedDir::new("r3b05");
    let (ws, vault) = (sb.0.join("ws"), sb.0.join("vault"));
    let sub = ws.join("locked_sub");
    fs::create_dir_all(&sub).unwrap();
    let f0 = sub.join("secret.key");
    fs::write(&f0, b"top-secret").unwrap();
    fs::set_permissions(&f0, fs::Permissions::from_mode(0o000)).unwrap();

    let s = create_snapshot_with_vault(&ws, Some(&vault), "zero-perm").unwrap();
    assert_eq!(s.file_count, 1);
    assert_eq!(fs::symlink_metadata(&f0).unwrap().permissions().mode() & 0o777, 0o000);

    // Also test selective restore through uchg locked directory
    fs::set_permissions(&f0, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&f0, b"tampered").unwrap();
    let _ = Command::new("chflags").args(["uchg", sub.to_str().unwrap()]).status();

    let res = restore_snapshot_paths_with_vault(&ws, Some(&vault), &s.id, true, &[String::from("locked_sub/secret.key")]);
    force_unlock(&sub);
    assert!(res.is_ok(), "uchg selective restore failed: {:?}", res);
    assert_eq!(fs::symlink_metadata(&f0).unwrap().permissions().mode() & 0o777, 0o000);
    // Also verify full restore restores nested 0000 file properly
    fs::set_permissions(&f0, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&f0, b"tampered-full").unwrap();
    restore_snapshot_with_vault(&ws, Some(&vault), &s.id, true).unwrap();
    assert_eq!(fs::symlink_metadata(&f0).unwrap().permissions().mode() & 0o777, 0o000);
    fs::set_permissions(&f0, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fs::read(&f0).unwrap(), b"top-secret");
}

#[test]
fn r3_bug_07_08_guard_single_file_swap_vault_kind_and_doctor_root_cwd() {
    let _lock = crate::tests::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = crate::tests::TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
    let sb = R3ScopedDir::new("r3b0708");
    let (ws_file, vault) = (sb.0.join("solo.txt"), sb.0.join("vault"));
    fs::write(&ws_file, b"important-single").unwrap();
    let _ = create_snapshot_fast_dedup_with_vault(&ws_file, Some(&vault), "sf").unwrap();

    // Guard trips when single file is swapped with directory or dangling symlink
    let cfg = GuardConfig { max_delete: 20, max_write_mb: 16, poll_ms: 5, auto_rollback: true };
    let rep = run_guarded_command_with_vault(
        &ws_file,
        Some(&vault),
        &cfg,
        &[
            String::from("sh"),
            String::from("-c"),
            String::from("rm -f solo.txt && ln -s /nonexistent solo.txt"),
        ],
    )
    .unwrap();
    assert!(rep.tripped && rep.auto_restored);
    assert!(ws_file.is_file());

    // Vault target_kind conflict rejects snapshot when file swapped with dir
    fs::remove_file(&ws_file).unwrap();
    fs::create_dir_all(&ws_file).unwrap();
    let kind_err = create_snapshot_fast_dedup_with_vault(&ws_file, Some(&vault), "bad-kind").unwrap_err();
    assert_eq!(kind_err.code, ERR_EINVAL);

    // Doctor with skip_workspace_check=true on "/" passes when APFS + Vault valid, false when explicit
    let doc_sys = run_doctor_with_opts(Path::new("/"), Some(&vault), true).unwrap();
    assert!(doc_sys.ok && doc_sys.workspace_valid);
    let doc_explicit_root = run_doctor_with_opts(Path::new("/"), Some(&vault), false).unwrap();
    assert!(!doc_explicit_root.ok && !doc_explicit_root.workspace_valid);
}

#[test]
fn r3_bug_09_dedup_adjacent_auto_snaps_and_calibrate_legacy_meta() {
    let _lock = crate::tests::ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = crate::tests::TestEnvGuard::clean(&["AFUSE_MAX_AUTO_SNAPS"]);
    let sb = R3ScopedDir::new("r3b09");
    let (ws, vault) = (sb.0.join("ws"), sb.0.join("vault"));
    fs::create_dir_all(ws.join(".git")).unwrap();
    fs::write(ws.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(ws.join("src.rs"), b"v1").unwrap();

    let s1 = create_snapshot_with_vault(&ws, Some(&vault), "tmp1").unwrap();
    let s2 = create_snapshot_with_vault(&ws, Some(&vault), "tmp2").unwrap();
    let s3 = create_snapshot_with_vault(&ws, Some(&vault), "tmp3").unwrap();
    let (_, ws_vault) = prepare_workspace_vault_with(&ws, Some(&vault)).unwrap();

    // Rewrite s1/s2/s3 meta.kv as legacy auto:* format (no project_files=, tree_sha256=fast)
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
    assert_eq!(removed, 2, "expected 2 duplicate auto:* snapshots collapsed");
    let rem = list_snapshots_unlocked(&ws_vault).unwrap();
    assert_eq!(rem.len(), 1);
    assert_eq!(rem[0].project_files, 1);
    assert!(rem[0].tree_sha256.starts_with("fast:"));

    // Single-file legacy meta calibration must preserve project_files=1
    let sf = sb.0.join("legacy.txt");
    fs::write(&sf, b"sf").unwrap();
    let ssf = create_snapshot_with_vault(&sf, Some(&vault), "auto:pro:init").unwrap();
    let (_, sf_vault) = prepare_workspace_vault_with(&sf, Some(&vault)).unwrap();
    let sf_mp = sf_vault.join("snapshots").join(&ssf.id).join("meta.kv");
    let sf_legacy: Vec<String> = fs::read_to_string(&sf_mp)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("project_files="))
        .map(|l| if l.starts_with("tree_sha256=") { "tree_sha256=fast".to_string() } else { l.to_string() })
        .collect();
    fs::write(&sf_mp, sf_legacy.join("\n") + "\n").unwrap();
    let _ = prune_unlocked(&sf_vault, 10, Some("auto:"), 0).unwrap();
    let sf_rem = list_snapshots_unlocked(&sf_vault).unwrap();
    assert_eq!(sf_rem[0].project_files, 1);
    assert!(sf_rem[0].tree_sha256.starts_with("fast:"));
}
