use crate::error::{AfuseError, ERR_EINVAL};
use crate::upgrade_json::ReleaseAsset;
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_EXTRACT_DEPTH: usize = 4;

fn is_regular_non_symlink_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| !m.file_type().is_symlink() && m.file_type().is_file())
        .unwrap_or(false)
}

fn is_real_non_symlink_dir(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
        .unwrap_or(false)
}

fn find_extracted_afuse_at(dir: &Path, depth: usize) -> Option<PathBuf> {
    if !is_real_non_symlink_dir(dir) {
        return None;
    }
    for rel in ["afuse", "bin/afuse"] {
        let cand = dir.join(rel);
        if is_regular_non_symlink_file(&cand) {
            return Some(cand);
        }
    }
    if depth >= MAX_EXTRACT_DEPTH {
        return None;
    }
    let rd = fs::read_dir(dir).ok()?;
    let mut subdirs: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| is_real_non_symlink_dir(p))
        .collect();
    subdirs.sort();
    for p in subdirs {
        if let Some(found) = find_extracted_afuse_at(&p, depth + 1) {
            return Some(found);
        }
    }
    None
}

pub(crate) fn find_extracted_afuse(dir: &Path) -> Option<PathBuf> {
    find_extracted_afuse_at(dir, 0)
}

pub(crate) fn verify_executable_magic(path: &Path) -> Result<(), AfuseError> {
    if !is_regular_non_symlink_file(path) {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "staged upgrade payload is not a regular non-symlink file",
        ));
    }
    let mut f = File::open(path).map_err(|e| {
        AfuseError::new(
            e.raw_os_error().unwrap_or(ERR_EINVAL),
            format!("cannot open staged binary: {}", e),
        )
    })?;
    let mut header = [0u8; 64];
    let n = f
        .read(&mut header)
        .map_err(|e| AfuseError::new(ERR_EINVAL, format!("failed reading binary header: {}", e)))?;
    if n < 64 {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "staged binary rejected: truncated executable header",
        ));
    }
    let magic: [u8; 4] = [header[0], header[1], header[2], header[3]];
    #[cfg(target_os = "macos")]
    let valid_magic = matches!(
        magic,
        [0xcf, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    );
    #[cfg(target_os = "linux")]
    let valid_magic = magic == [0x7f, b'E', b'L', b'F'];
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let valid_magic = false;

    if !valid_magic {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "staged binary rejected: invalid executable magic header",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodesignIdentity {
    pub(crate) team_id: Option<String>,
    pub(crate) authorities: Vec<String>,
}

pub(crate) fn parse_codesign_identity(text: &str) -> CodesignIdentity {
    let mut team_id = None;
    let mut authorities = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(val) = line.strip_prefix("TeamIdentifier=") {
            let v = val.trim();
            if !v.is_empty() && v != "not set" {
                team_id = Some(v.to_string());
            }
        } else if let Some(val) = line.strip_prefix("Authority=") {
            let v = val.trim();
            if !v.is_empty() {
                authorities.push(v.to_string());
            }
        }
    }
    CodesignIdentity { team_id, authorities }
}

#[cfg(target_os = "macos")]
fn probe_codesign_identity(path: &Path) -> CodesignIdentity {
    let Ok(out) = Command::new("/usr/bin/codesign")
        .args(["-dvv"])
        .arg(path)
        .stdin(Stdio::null())
        .output()
    else {
        return CodesignIdentity { team_id: None, authorities: Vec::new() };
    };
    let merged = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    parse_codesign_identity(&merged)
}

pub(crate) fn validate_candidate_codesign_identity(
    host: &CodesignIdentity,
    cand_strict_ok: bool,
    cand: &CodesignIdentity,
) -> Result<(), AfuseError> {
    let Some(host_team) = host.team_id.as_deref() else {
        return Ok(());
    };
    if !cand_strict_ok {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "staged binary rejected: strict codesign verification failed against signed host",
        ));
    }
    if cand.team_id.as_deref() != Some(host_team) {
        return Err(AfuseError::new(
            ERR_EINVAL,
            format!(
                "staged binary TeamIdentifier mismatch ({} != {})",
                cand.team_id.as_deref().unwrap_or("none"),
                host_team
            ),
        ));
    }
    if !cand
        .authorities
        .iter()
        .any(|a| a.starts_with("Developer ID Application:"))
    {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "staged binary missing Developer ID Application authority",
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn ensure_macos_codesign(staged_bin: &Path, host_exe: Option<&Path>) -> Result<(), AfuseError> {
    let verify_ok = |p: &Path| -> bool {
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict"])
            .arg(p)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    let host_id = host_exe
        .filter(|p| verify_ok(p))
        .map(probe_codesign_identity)
        .unwrap_or(CodesignIdentity {
            team_id: None,
            authorities: Vec::new(),
        });
    if host_id.team_id.is_some() {
        let strict_ok = verify_ok(staged_bin);
        let cand_id = probe_codesign_identity(staged_bin);
        return validate_candidate_codesign_identity(&host_id, strict_ok, &cand_id);
    }
    if verify_ok(staged_bin) {
        return Ok(());
    }
    let sign_out = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-"])
        .arg(staged_bin)
        .output()
        .map_err(|e| AfuseError::new(ERR_EINVAL, format!("codesign invocation failed: {}", e)))?;
    if !sign_out.status.success() {
        let detail = String::from_utf8_lossy(&sign_out.stderr).trim().to_string();
        return Err(AfuseError::new(
            ERR_EINVAL,
            format!("ad-hoc codesign failed: {}", detail),
        ));
    }
    if !verify_ok(staged_bin) {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "staged binary failed strict codesign verification after signing",
        ));
    }
    Ok(())
}

pub(crate) fn probe_staged_version(
    staged_bin: &Path,
    expected_version: Option<&str>,
) -> Result<(), AfuseError> {
    let mut child = Command::new(staged_bin)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            AfuseError::new(
                ERR_EINVAL,
                format!("staged binary failed to spawn '--version' probe: {}", e),
            )
        })?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(15)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(AfuseError::new(
                    ERR_EINVAL,
                    "staged binary '--version' probe timed out",
                ));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(AfuseError::new(
                    ERR_EINVAL,
                    format!("staged binary probe wait failed: {}", e),
                ));
            }
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| AfuseError::new(ERR_EINVAL, format!("staged binary probe read failed: {}", e)))?;
    if !out.status.success() {
        return Err(AfuseError::new(
            ERR_EINVAL,
            format!(
                "staged binary '--version' probe exited with {:?}",
                out.status.code()
            ),
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("afuse") {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "staged binary '--version' probe output missing 'afuse'",
        ));
    }
    if let Some(exp_raw) = expected_version {
        let norm = exp_raw.trim().trim_start_matches('v');
        if !norm.is_empty()
            && !stdout
                .split_whitespace()
                .any(|tok| tok == norm || tok == format!("v{}", norm))
        {
            return Err(AfuseError::new(
                ERR_EINVAL,
                format!(
                    "staged binary '--version' mismatch: expected {}, got '{}'",
                    norm,
                    stdout.trim()
                ),
            ));
        }
    }
    Ok(())
}

pub(crate) fn prepare_and_verify_staged_binary(
    staged_bin: &Path,
    expected_version: Option<&str>,
) -> Result<(), AfuseError> {
    verify_executable_magic(staged_bin)?;
    #[cfg(target_os = "macos")]
    {
        let host_exe = env::current_exe().ok();
        ensure_macos_codesign(staged_bin, host_exe.as_deref())?;
    }
    probe_staged_version(staged_bin, expected_version)
}

pub fn validate_release_asset_url(url: &str) -> Result<(), AfuseError> {
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        AfuseError::new(ERR_EINVAL, "release asset URL must use https://")
    })?;
    let (authority, path_and_query) = rest.split_once('/').unwrap_or((rest, ""));
    let authority = authority.split(['?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(AfuseError::new(ERR_EINVAL, "invalid release asset authority"));
    }
    let host = authority.split(':').next().unwrap_or("").to_ascii_lowercase();
    let path_only = path_and_query.split(['?', '#']).next().unwrap_or("");
    match host.as_str() {
        "github.com" => {
            let lower_path = path_only.to_ascii_lowercase();
            let has_traversal = lower_path.contains("..")
                || lower_path.contains("%2e")
                || lower_path.contains('\\')
                || lower_path.contains("%5c");
            if has_traversal || !path_only.starts_with("topkyo/agent-fuse/releases/download/") {
                return Err(AfuseError::new(
                    ERR_EINVAL,
                    format!("untrusted github.com release asset path: /{}", path_only),
                ));
            }
        }
        "objects.githubusercontent.com"
        | "release-assets.githubusercontent.com"
        | "github-releases.githubusercontent.com" => {}
        _ => {
            return Err(AfuseError::new(ERR_EINVAL, format!("untrusted release asset host: {}", host)));
        }
    }
    Ok(())
}

pub fn is_trusted_github_url(url: &str) -> bool {
    validate_release_asset_url(url).is_ok()
}

pub(crate) fn extract_trusted_dmg_urls(assets: &[ReleaseAsset]) -> (Option<String>, Option<String>) {
    let dmg_asset = assets
        .iter()
        .find(|a| a.name.ends_with("-macos.dmg") && is_trusted_github_url(&a.download_url));
    let preferred_sha = dmg_asset.and_then(|d| {
        let exact = format!("{}.sha256", d.name);
        assets
            .iter()
            .find(|a| a.name == exact && is_trusted_github_url(&a.download_url))
    });
    let sha_asset = preferred_sha.or_else(|| {
        assets
            .iter()
            .find(|a| a.name.ends_with("-macos.dmg.sha256") && is_trusted_github_url(&a.download_url))
    });
    (
        dmg_asset.map(|a| a.download_url.clone()),
        sha_asset.map(|a| a.download_url.clone()),
    )
}
