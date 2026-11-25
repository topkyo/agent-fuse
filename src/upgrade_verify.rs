use crate::error::{AfuseError, ERR_EINVAL};
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_EXTRACT_DEPTH: usize = 4;

pub(crate) fn is_regular_non_symlink_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| !m.file_type().is_symlink() && m.file_type().is_file())
        .unwrap_or(false)
}

pub(crate) fn is_real_non_symlink_dir(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
        .unwrap_or(false)
}

fn find_extracted_afuse_at(dir: &Path, depth: usize) -> Option<PathBuf> {
    if !is_real_non_symlink_dir(dir) {
        return None;
    }
    let direct = dir.join("afuse");
    if is_regular_non_symlink_file(&direct) {
        return Some(direct);
    }
    let bin_dir = dir.join("bin");
    if is_real_non_symlink_dir(&bin_dir) {
        let nested = bin_dir.join("afuse");
        if is_regular_non_symlink_file(&nested) {
            return Some(nested);
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
    pub(crate) identifier: Option<String>,
    pub(crate) team_id: Option<String>,
    pub(crate) authorities: Vec<String>,
}

pub(crate) fn parse_codesign_identity(text: &str) -> CodesignIdentity {
    let mut identifier = None;
    let mut team_id = None;
    let mut authorities = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(val) = line.strip_prefix("Identifier=") {
            let v = val.trim();
            if !v.is_empty() {
                identifier = Some(v.to_string());
            }
        } else if let Some(val) = line.strip_prefix("TeamIdentifier=") {
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
    CodesignIdentity {
        identifier,
        team_id,
        authorities,
    }
}

#[cfg(target_os = "macos")]
fn probe_codesign_identity(path: &Path) -> CodesignIdentity {
    let Ok(out) = Command::new("/usr/bin/codesign")
        .args(["-dvv"])
        .arg(path)
        .stdin(Stdio::null())
        .output()
    else {
        return CodesignIdentity {
            identifier: None,
            team_id: None,
            authorities: Vec::new(),
        };
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
    if let Some(host_ident) = host.identifier.as_deref() {
        if cand.identifier.as_deref() != Some(host_ident) {
            return Err(AfuseError::new(
                ERR_EINVAL,
                format!(
                    "staged binary Identifier mismatch ({} != {})",
                    cand.identifier.as_deref().unwrap_or("none"),
                    host_ident
                ),
            ));
        }
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
    let host_signed = host_exe.map(verify_ok).unwrap_or(false);
    let host_id = if host_signed {
        host_exe.map(probe_codesign_identity).unwrap_or(CodesignIdentity {
            identifier: None,
            team_id: None,
            authorities: Vec::new(),
        })
    } else {
        CodesignIdentity {
            identifier: None,
            team_id: None,
            authorities: Vec::new(),
        }
    };
    if host_id.team_id.is_some() {
        let strict_ok = verify_ok(staged_bin);
        let cand_id = probe_codesign_identity(staged_bin);
        return validate_candidate_codesign_identity(&host_id, strict_ok, &cand_id);
    }
    if verify_ok(staged_bin) {
        return Ok(());
    }
    #[cfg(not(any(test, feature = "test-hooks")))]
    {
        if host_signed {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "staged binary rejected: unsigned payload cannot replace signed executable",
            ));
        }
        return Err(AfuseError::new(
            ERR_EINVAL,
            "staged binary failed strict codesign verification",
        ));
    }
    #[cfg(any(test, feature = "test-hooks"))]
    {
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
