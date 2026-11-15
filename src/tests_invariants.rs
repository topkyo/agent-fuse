use crate::apfs::{force_remove_all, lstat_inode_mode, TMP_SEQ};
use crate::snapshot::list_snapshots_unlocked;
use crate::tests::ENV_LOCK;
use crate::*;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::thread;

struct TempSandbox(PathBuf);

impl TempSandbox {
    fn new(tag: &str) -> Self {
        let p = env::temp_dir().join(format!(
            "afuse-inv-{}-{}-{}",
            tag,
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = force_remove_all(&p);
        fs::create_dir_all(&p).unwrap();
        Self(fs::canonicalize(&p).unwrap_or(p))
    }
}

impl Drop for TempSandbox {
    fn drop(&mut self) {
        let _ = force_remove_all(&self.0);
    }
}

struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn pick(&mut self, max_excl: u64) -> u64 {
        self.next_u64() % max_excl.max(1)
    }
}

fn spawn_single_http_server(status_line: &str, body: &str) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let status = status_line.to_string();
    let payload = body.to_string();
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                payload.len(),
                payload
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    (format!("http://{}/releases/latest", addr), handle)
}

#[test]
fn upgrade_http_contract_200_404_and_500_over_real_tcp() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let prev = env::var_os("AFUSE_RELEASE_JSON_URL");
    let pkg_ver = env!("CARGO_PKG_VERSION");

    // 1. HTTP 200 newer version
    let body_new = r#"{"tag_name":"v9.8.7","html_url":"https://github.com/topkyo/agent-fuse/releases/tag/v9.8.7","assets":[]}"#;
    let (url_new, h_new) = spawn_single_http_server("200 OK", body_new);
    env::set_var("AFUSE_RELEASE_JSON_URL", &url_new);
    let rep_new = check_for_updates().unwrap();
    h_new.join().unwrap();
    assert!(rep_new.update_available);
    assert_eq!(rep_new.release_state, "published");
    assert_eq!(rep_new.latest_version, "9.8.7");
    assert!(rep_new.to_json().contains("\"release_state\":\"published\""));

    // 2. HTTP 200 same version
    let body_same = format!(
        "{{\"tag_name\":\"v{}\",\"html_url\":\"https://github.com/topkyo/agent-fuse/releases/tag/v{}\",\"assets\":[]}}",
        pkg_ver, pkg_ver
    );
    let (url_same, h_same) = spawn_single_http_server("200 OK", &body_same);
    env::set_var("AFUSE_RELEASE_JSON_URL", &url_same);
    let rep_same = check_for_updates().unwrap();
    h_same.join().unwrap();
    assert!(!rep_same.update_available);
    assert_eq!(rep_same.release_state, "published");

    // 3. HTTP 404 -> Ok unpublished (no error modal for unreleased repo)
    let (url_404, h_404) = spawn_single_http_server("404 Not Found", r#"{"message":"Not Found"}"#);
    env::set_var("AFUSE_RELEASE_JSON_URL", &url_404);
    let rep_404 = check_for_updates().unwrap();
    h_404.join().unwrap();
    assert!(!rep_404.update_available);
    assert_eq!(rep_404.release_state, "unpublished");
    assert!(rep_404.to_json().contains("\"release_state\":\"unpublished\""));

    let (url_404_apply, h_404_apply) = spawn_single_http_server("404 Not Found", r#"{"message":"Not Found"}"#);
    env::set_var("AFUSE_RELEASE_JSON_URL", &url_404_apply);
    let sb = TempSandbox::new("404-apply");
    let fake_exe = sb.0.join("afuse");
    fs::write(&fake_exe, b"bin").unwrap();
    let apply_404 = perform_upgrade_on_exe(&fake_exe).unwrap();
    h_404_apply.join().unwrap();
    assert!(!apply_404.updated);

    // 4. HTTP 500 -> preserves error
    let (url_500, h_500) = spawn_single_http_server("500 Internal Server Error", "boom");
    env::set_var("AFUSE_RELEASE_JSON_URL", &url_500);
    let err_500 = check_for_updates().unwrap_err();
    h_500.join().unwrap();
    assert!(err_500.message.contains("HTTP 500"));

    match prev {
        Some(v) => env::set_var("AFUSE_RELEASE_JSON_URL", v),
        None => env::remove_var("AFUSE_RELEASE_JSON_URL"),
    }
}

#[test]
fn deleted_workspace_recovery_and_non_creation_invariants() {
    let sb = TempSandbox::new("delrec");
    let vault = sb.0.join("vault");
    let parent = sb.0.join("deep/folder");
    let ws = parent.join("repo-alpha");
    fs::create_dir_all(ws.join(".git")).unwrap();
    fs::write(ws.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(ws.join("src.rs"), b"pub fn main() {}\n").unwrap();

    // Unbound path query must not create empty vault directories
    let phantom = sb.0.join("never-bound-proj");
    let empty_snaps = list_snapshots_with_vault(&phantom, Some(&vault)).unwrap();
    assert!(empty_snaps.is_empty());
    let (_, phantom_vault) = resolve_workspace_vault_recovery(&phantom, Some(&vault)).unwrap();
    assert!(!phantom_vault.exists());

    let s1 = create_snapshot_opts_with_vault(&ws, Some(&vault), "baseline", false).unwrap();

    // Whole multi-level directory deletion
    fs::remove_dir_all(&parent).unwrap();
    assert!(!ws.exists());

    let snaps = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].id, s1.id);

    let diff = diff_snapshot_with_vault(&ws, Some(&vault), &s1.id).unwrap();
    assert!(diff.deleted.iter().any(|p| p == "src.rs"));

    // Selective file recovery recreates missing workspace cleanly without empty pre-restore
    let sel_rep = restore_snapshot_paths_with_vault(
        &ws,
        Some(&vault),
        &s1.id,
        true,
        &["src.rs".to_string()],
    )
    .unwrap();
    assert!(sel_rep.safety_snapshot_id.is_none());
    assert_eq!(fs::read_to_string(ws.join("src.rs")).unwrap(), "pub fn main() {}\n");

    // Full restore also recovers .git/HEAD and avoids empty auto:pre-restore after re-delete
    fs::remove_dir_all(&ws).unwrap();
    let full_rep = restore_snapshot_with_vault(&ws, Some(&vault), &s1.id, true).unwrap();
    assert!(full_rep.safety_snapshot_id.is_none());
    assert!(ws.join(".git/HEAD").is_file());
    assert_eq!(full_rep.restored_files, s1.file_count);
}

#[test]
fn stateful_280_step_property_invariants_i1_and_i2() {
    let sb = TempSandbox::new("prop280");
    let vault = sb.0.join("vault");
    let ws = sb.0.join("prop-repo");
    fs::create_dir_all(ws.join(".git")).unwrap();
    fs::write(ws.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(ws.join("seed.txt"), b"seed-0\n").unwrap();

    let s0 = create_snapshot_opts_with_vault(&ws, Some(&vault), "manual-seed", false).unwrap();
    let (_, ws_vault) = prepare_live_workspace_vault_with(&ws, Some(&vault)).unwrap();
    let mut non_empty_oracle: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut seed_oracle = BTreeMap::new();
    seed_oracle.insert("seed.txt".to_string(), b"seed-0\n".to_vec());
    let mut good_snaps: Vec<(String, BTreeMap<String, Vec<u8>>)> = vec![(s0.id, seed_oracle)];
    non_empty_oracle.insert("seed.txt".to_string(), b"seed-0\n".to_vec());

    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let file_names = ["a.rs", "b.txt", "sub/c.md", "d.json", "e.py"];

    for step in 0..280u64 {
        let op = rng.pick(7);
        match op {
            0 | 1 if ws.is_dir() => {
                // Mutate or add a file inside live workspace
                if !ws.join(".git/HEAD").is_file() {
                    let _ = fs::create_dir_all(ws.join(".git"));
                    let _ = fs::write(ws.join(".git/HEAD"), b"ref: refs/heads/main\n");
                }
                let name = file_names[rng.pick(file_names.len() as u64) as usize];
                let p = ws.join(name);
                if let Some(par) = p.parent() {
                    let _ = fs::create_dir_all(par);
                }
                let data = format!("step-{}-val-{}", step, rng.next_u64()).into_bytes();
                fs::write(&p, &data).unwrap();
                non_empty_oracle.insert(name.to_string(), data);
            }
            2 if ws.is_dir() => {
                // Attempt auto-snap; reject empty directory when non-empty history exists (I1)
                let res = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:fsevents", true);
                let live_empty = non_empty_oracle.is_empty() && !ws.join(".git/HEAD").is_file();
                if live_empty && !good_snaps.is_empty() {
                    assert_eq!(res.unwrap_err().code, ERR_EINVAL);
                } else if let Ok(meta) = res {
                    assert!(meta.file_count > 0);
                    good_snaps.push((meta.id, non_empty_oracle.clone()));
                }
            }
            3 if ws.is_dir() => {
                // Corrupt workspace: delete files & empty/strip .git so workspace is hollow
                let _ = force_remove_all(&ws.join("seed.txt"));
                for name in file_names {
                    let _ = force_remove_all(&ws.join(name));
                }
                let _ = force_remove_all(&ws.join("sub"));
                let _ = force_remove_all(&ws.join(".git"));
                if rng.pick(2) == 0 {
                    let _ = fs::create_dir_all(ws.join(".git"));
                }
                non_empty_oracle.clear();
                let blocked = create_snapshot_opts_with_vault(&ws, Some(&vault), "auto:pro:fsevents", true);
                assert_eq!(blocked.unwrap_err().code, ERR_EINVAL);
            }
            4 => {
                // Whole repo wipe or empty dir recreate
                let _ = force_remove_all(&ws);
                non_empty_oracle.clear();
                if rng.pick(2) == 0 {
                    fs::create_dir_all(&ws).unwrap();
                }
                let listed = list_snapshots_with_vault(&ws, Some(&vault)).unwrap();
                assert!(!listed.is_empty());
            }
            5 => {
                // Diff while missing or present must succeed
                let (target_id, _) = &good_snaps[0];
                let d = diff_snapshot_with_vault(&ws, Some(&vault), target_id).unwrap();
                if !ws.is_dir() {
                    assert!(!d.deleted.is_empty());
                }
            }
            _ => {
                // In-place restore must always succeed against a recorded non-empty snapshot
                let idx = rng.pick(good_snaps.len() as u64) as usize;
                let (target_id, expected_files) = good_snaps[idx].clone();
                let had_visible = !non_empty_oracle.is_empty() || ws.join(".git/HEAD").is_file();
                let ino_before = lstat_inode_mode(&ws).map(|x| x.0).unwrap_or(0);
                let rep = restore_snapshot_with_vault(&ws, Some(&vault), &target_id, true).unwrap();
                if ino_before != 0 {
                    assert_eq!(rep.root_inode_before, ino_before);
                    assert_eq!(rep.root_inode_after, ino_before);
                }
                if !had_visible {
                    assert!(rep.safety_snapshot_id.is_none());
                }
                for (rel, bytes) in &expected_files {
                    assert_eq!(fs::read(ws.join(rel)).unwrap(), *bytes);
                }
                assert!(ws.join(".git/HEAD").is_file());
                non_empty_oracle = expected_files;
            }
        }
        // Invariant check every step: no auto snapshot (except manual) has 0 files
        let all = list_snapshots_unlocked(&ws_vault).unwrap();
        assert!(all.iter().filter(|m| m.label.starts_with("auto:")).all(|m| m.file_count > 0));
    }
}
