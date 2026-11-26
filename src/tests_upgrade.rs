use crate::error::{ERR_EINVAL, ERR_USAGE};
use crate::sha256::sha256_hex;
use crate::tests::{compile_dummy_afuse_macho, ScopedDir, TestEnvGuard, ENV_LOCK};
use crate::upgrade::{
    check_for_updates, is_trusted_github_url, parse_release_json, perform_upgrade_on_exe,
};
use crate::upgrade_json::validate_effective_asset_url;
use crate::upgrade_tar::{preflight_tar_listing, validate_release_api_effective_url};
use crate::upgrade_verify::{
    parse_codesign_identity, validate_candidate_codesign_identity, CodesignIdentity,
};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;
use std::thread;

fn make_tarball(archive_dir: &Path, payload_dir: &Path, entry: &str) {
    let tb = archive_dir.join("afuse-macos-universal.tar.gz");
    let st = Command::new("/usr/bin/tar")
        .args(["-czf"])
        .arg(&tb)
        .args(["-C"])
        .arg(payload_dir)
        .arg(entry)
        .status()
        .unwrap();
    assert!(st.success());
    let sha = sha256_hex(&fs::read(&tb).unwrap());
    fs::write(
        archive_dir.join("SHA256SUMS.txt"),
        format!("{}  afuse-macos-universal.tar.gz\n", sha),
    )
    .unwrap();
}

#[test]
fn upgrade_rejects_symlink_non_macho_and_applies_codesign_probe() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = TestEnvGuard::clean(&["AFUSE_RELEASE_JSON_URL", "AFUSE_UPGRADE_ARCHIVE_DIR"]);
    let sb = ScopedDir::new("up-sec");

    let rel = sb.0.join("rel.json");
    fs::write(
        &rel,
        r#"{"tag_name":"v0.9.0","html_url":"https://github.com/topkyo/agent-fuse/releases/tag/v0.9.0","assets":[]}"#,
    )
    .unwrap();
    env::set_var("AFUSE_RELEASE_JSON_URL", format!("file://{}", rel.display()));

    let bin_dir = sb.0.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let exe = bin_dir.join("afuse");
    fs::write(&exe, b"OLD_STABLE_EXE").unwrap();

    // 1. Symlink payload rejected
    let (pay_sym, arch_sym) = (sb.0.join("pay-sym"), sb.0.join("arch-sym"));
    fs::create_dir_all(&pay_sym).unwrap();
    fs::create_dir_all(&arch_sym).unwrap();
    symlink("/bin/echo", pay_sym.join("afuse")).unwrap();
    make_tarball(&arch_sym, &pay_sym, "afuse");
    env::set_var("AFUSE_UPGRADE_ARCHIVE_DIR", &arch_sym);
    assert_eq!(perform_upgrade_on_exe(&exe).unwrap_err().code, ERR_EINVAL);
    assert_eq!(fs::read(&exe).unwrap(), b"OLD_STABLE_EXE");

    // 2. Symlink directory loop rejected
    let (pay_loop, arch_loop) = (sb.0.join("pay-loop"), sb.0.join("arch-loop"));
    fs::create_dir_all(&pay_loop).unwrap();
    fs::create_dir_all(&arch_loop).unwrap();
    symlink(".", pay_loop.join("loop")).unwrap();
    make_tarball(&arch_loop, &pay_loop, "loop");
    env::set_var("AFUSE_UPGRADE_ARCHIVE_DIR", &arch_loop);
    assert_eq!(perform_upgrade_on_exe(&exe).unwrap_err().code, ERR_EINVAL);

    // 3. Non-Mach-O payload rejected
    let (pay_txt, arch_txt) = (sb.0.join("pay-txt"), sb.0.join("arch-txt"));
    fs::create_dir_all(&pay_txt).unwrap();
    fs::create_dir_all(&arch_txt).unwrap();
    fs::write(pay_txt.join("afuse"), b"#!/bin/sh\necho fake\n").unwrap();
    make_tarball(&arch_txt, &pay_txt, "afuse");
    env::set_var("AFUSE_UPGRADE_ARCHIVE_DIR", &arch_txt);
    assert_eq!(perform_upgrade_on_exe(&exe).unwrap_err().code, ERR_EINVAL);

    // 4. Unsigned real Mach-O binary succeeds in test mode (ad-hoc signed host)
    let (pay_real, arch_real) = (sb.0.join("pay-real"), sb.0.join("arch-real"));
    fs::create_dir_all(&pay_real).unwrap();
    fs::create_dir_all(&arch_real).unwrap();
    let staged_payload = pay_real.join("afuse");
    compile_dummy_afuse_macho(&staged_payload, "0.9.0");
    let _ = Command::new("/usr/bin/codesign")
        .args(["--remove-signature"])
        .arg(&staged_payload)
        .status();
    make_tarball(&arch_real, &pay_real, "afuse");
    env::set_var("AFUSE_UPGRADE_ARCHIVE_DIR", &arch_real);

    let rep = perform_upgrade_on_exe(&exe).unwrap();
    assert!(rep.updated && rep.release_state == "updated");
    assert!(Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(&exe)
        .status()
        .unwrap()
        .success());
    let ver_out = Command::new(&exe).arg("--version").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&ver_out.stdout).trim(), "afuse 0.9.0");
}

#[test]
fn upgrade_404_unpublished_app_preflight_and_json_edge_cases() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = TestEnvGuard::clean(&["AFUSE_RELEASE_JSON_URL", "AFUSE_UPGRADE_ARCHIVE_DIR"]);
    let sb = ScopedDir::new("up-404");

    env::set_var("AFUSE_RELEASE_JSON_URL", "http://127.0.0.1:1/must-not-connect");
    let app_bin = sb.0.join("AgentFuse.app/Contents/MacOS/afuse");
    fs::create_dir_all(app_bin.parent().unwrap()).unwrap();
    fs::write(&app_bin, b"APP").unwrap();
    let link_bin = sb.0.join("afuse");
    symlink(&app_bin, &link_bin).unwrap();
    assert_eq!(perform_upgrade_on_exe(&link_bin).unwrap_err().code, ERR_USAGE);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let h = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 23\r\nConnection: close\r\n\r\n{\"message\":\"Not Found\"}";
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    env::set_var("AFUSE_RELEASE_JSON_URL", format!("http://{}/latest", addr));
    let standalone = sb.0.join("standalone/afuse");
    fs::create_dir_all(standalone.parent().unwrap()).unwrap();
    fs::write(&standalone, b"OLD").unwrap();
    let rep404 = perform_upgrade_on_exe(&standalone).unwrap();
    h.join().unwrap();
    assert!(!rep404.updated && rep404.release_state == "unpublished");

    let valid_json = r#"{"tag_name":"v0.9.1","body":"hi\b\f\uD83D\uDE80","assets":["{\"name\":\"decoy\"}",{"name":"afuse-macos-universal.tar.gz","browser_download_url":"https://github.com/topkyo/agent-fuse/releases/download/v0.9.1/afuse-macos-universal.tar.gz"}]}"#;
    let parsed = parse_release_json(valid_json).unwrap();
    assert_eq!(parsed.latest_version, "0.9.1");
    assert_eq!(parsed.assets.len(), 1);
    assert!(parse_release_json(r#"{"tag_name":"v0.9\u12","html_url":"https://example.invalid"}"#).is_err());
}

#[test]
fn dmg_urls_query_fragment_bypass_and_release_api_effective_url_checks() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _eg = TestEnvGuard::clean(&["AFUSE_RELEASE_JSON_URL"]);

    assert!(is_trusted_github_url("https://github.com/topkyo/agent-fuse/releases/download/v0.6.3/AgentFuse-0.6.3-macos.dmg"));
    assert!(!is_trusted_github_url("https://release-assets.githubusercontent.com/a/b"));
    assert!(!is_trusted_github_url("http://github.com/topkyo/agent-fuse/releases/download/v0.6.3/x.dmg"));
    assert!(!is_trusted_github_url("https://github.com@evil.invalid/x.dmg"));
    // W-L1-08: '?' or '#' directly after host must NOT smuggle path prefix
    assert!(!is_trusted_github_url("https://github.com?x=/topkyo/agent-fuse/releases/download/v0.6.3/x.dmg"));
    assert!(!is_trusted_github_url("https://github.com#/topkyo/agent-fuse/releases/download/v0.6.3/x.dmg"));
    assert!(validate_effective_asset_url("https://release-assets.githubusercontent.com/github-production-release-asset/x.dmg").is_ok());

    // W-L1-08: Release API post-redirect URL validation
    assert!(validate_release_api_effective_url("https://api.github.com/repos/topkyo/agent-fuse/releases/latest").is_ok());
    assert!(validate_release_api_effective_url("https://api.github.com:443/repos/topkyo/agent-fuse/releases/latest?foo=1").is_ok());
    assert!(validate_release_api_effective_url("https://evil.example/repos/topkyo/agent-fuse/releases/latest").is_err());
    assert!(validate_release_api_effective_url("https://api.github.com/repos/attacker/agent-fuse/releases/latest").is_err());
    assert!(validate_release_api_effective_url("https://api.github.com?x=/repos/topkyo/agent-fuse/releases/latest").is_err());

    let trusted_body = r#"{"tag_name":"v0.9.6","html_url":"https://github.com/topkyo/agent-fuse/releases/tag/v0.9.6","assets":[{"name":"AgentFuse-0.9.6-macos.dmg","browser_download_url":"https://github.com/topkyo/agent-fuse/releases/download/v0.9.6/AgentFuse-0.9.6-macos.dmg"},{"name":"AgentFuse-0.9.6-macos.dmg.sha256","browser_download_url":"https://github.com/topkyo/agent-fuse/releases/download/v0.9.6/AgentFuse-0.9.6-macos.dmg.sha256"}]}"#;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body_clone = trusted_body.to_string();
    let h = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_clone.len(),
                body_clone
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    env::set_var("AFUSE_RELEASE_JSON_URL", format!("http://{}/latest", addr));
    let rep = check_for_updates().unwrap();
    h.join().unwrap();
    assert_eq!(rep.dmg_url.as_deref(), Some("https://github.com/topkyo/agent-fuse/releases/download/v0.9.6/AgentFuse-0.9.6-macos.dmg"));
}

#[test]
fn tar_preflight_numeric_owner_rejects_glob_duplicate_and_multi_afuse() {
    // Numeric owner listing (no spaces in uid/gid) succeeds
    let ok_listing = "-rwxr-xr-x  0 501    20     102400 Nov 26 09:00 bin/afuse\n";
    assert_eq!(preflight_tar_listing(ok_listing).unwrap(), "bin/afuse");

    // Glob wildcards rejected (W-L1-05)
    let glob_star = "-rwxr-xr-x  0 501    20     102400 Nov 26 09:00 */afuse\n";
    assert!(preflight_tar_listing(glob_star).is_err());
    let glob_q = "-rwxr-xr-x  0 501    20     102400 Nov 26 09:00 a?/afuse\n";
    assert!(preflight_tar_listing(glob_q).is_err());
    let glob_br = "-rwxr-xr-x  0 501    20     102400 Nov 26 09:00 [ab]/afuse\n";
    assert!(preflight_tar_listing(glob_br).is_err());

    // Duplicate member paths rejected (W-L1-05)
    let dup = "-rwxr-xr-x  0 501    20     102400 Nov 26 09:00 afuse\n-rwxr-xr-x  0 501    20     102400 Nov 26 09:00 ./afuse\n";
    assert!(preflight_tar_listing(dup).is_err());

    // Multiple afuse binaries in distinct dirs rejected (W-L1-05)
    let multi = "-rwxr-xr-x  0 501    20     102400 Nov 26 09:00 a/afuse\n-rwxr-xr-x  0 501    20     102400 Nov 26 09:00 b/afuse\n";
    assert!(preflight_tar_listing(multi).is_err());
}

#[test]
fn codesign_identity_fail_closed_when_host_signed() {
    let host = CodesignIdentity {
        identifier: Some("dev.topkyo.afuse".into()),
        team_id: Some("ABCDE12345".into()),
        authorities: vec!["Developer ID Application: Topkyo (ABCDE12345)".into()],
    };
    let same = parse_codesign_identity(
        "Identifier=dev.topkyo.afuse\nTeamIdentifier=ABCDE12345\nAuthority=Developer ID Application: Topkyo (ABCDE12345)\n",
    );
    assert!(validate_candidate_codesign_identity(&host, true, &same).is_ok());
    assert!(validate_candidate_codesign_identity(&host, false, &same).is_err());

    let wrong_team = parse_codesign_identity(
        "Identifier=dev.topkyo.afuse\nTeamIdentifier=ZZZZZ99999\nAuthority=Developer ID Application: Evil (ZZZZZ99999)\n",
    );
    assert!(validate_candidate_codesign_identity(&host, true, &wrong_team).is_err());

    let adhoc_cand = parse_codesign_identity(
        "Identifier=dev.topkyo.afuse\nTeamIdentifier=not set\nSignature=adhoc\n",
    );
    assert!(validate_candidate_codesign_identity(&host, true, &adhoc_cand).is_err());
}
