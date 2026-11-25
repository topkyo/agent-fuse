use crate::apfs::{
    chmod_nofollow, create_exclusive_dir_0700, force_remove_all, random_hex_suffix, TMP_SEQ,
};
use crate::error::{AfuseError, ERR_EACCES, ERR_EINVAL, ERR_ENOENT, ERR_USAGE};
pub use crate::upgrade_json::{
    is_newer_version, is_trusted_github_url, parse_release_json, validate_release_asset_url,
    ReleaseAsset, ReleaseInfo, UpgradeApplyReport, UpgradeCheckReport,
};
#[cfg(test)]
pub(crate) use crate::upgrade_tar::validate_effective_download_url;
use crate::upgrade_tar::{
    expected_sha256_from_sums, fetch_asset_to_file, preflight_and_extract_afuse, sha256_file_hex,
};
use crate::upgrade_verify::prepare_and_verify_staged_binary;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::Ordering;

pub const DEFAULT_RELEASE_API_URL: &str =
    "https://api.github.com/repos/topkyo/agent-fuse/releases/latest";
pub const DEFAULT_RELEASES_WEB_URL: &str = "https://github.com/topkyo/agent-fuse/releases";
pub const BREW_UPGRADE_CMD: &str = "brew upgrade --cask --no-quarantine topkyo/tap/agent-fuse";
pub const DEFAULT_TARBALL_NAME: &str = "afuse-macos-universal.tar.gz";

enum ReleaseFetch {
    Published(ReleaseInfo),
    Unpublished,
}

#[cfg(any(test, feature = "test-hooks"))]
fn resolve_release_source_url() -> String {
    env::var("AFUSE_RELEASE_JSON_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_RELEASE_API_URL.to_string())
}

#[cfg(not(any(test, feature = "test-hooks")))]
fn resolve_release_source_url() -> String {
    DEFAULT_RELEASE_API_URL.to_string()
}

#[cfg(any(test, feature = "test-hooks"))]
fn resolve_upgrade_archive_override() -> Option<PathBuf> {
    env::var("AFUSE_UPGRADE_ARCHIVE_DIR")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

#[cfg(not(any(test, feature = "test-hooks")))]
fn resolve_upgrade_archive_override() -> Option<PathBuf> {
    None
}

fn fetch_release_outcome() -> Result<ReleaseFetch, AfuseError> {
    let source = resolve_release_source_url();
    #[cfg(any(test, feature = "test-hooks"))]
    if !source.starts_with("http://") && !source.starts_with("https://") {
        let local = source.strip_prefix("file://").unwrap_or(&source);
        let raw = fs::read_to_string(local).map_err(|e| {
            AfuseError::new(
                e.raw_os_error().unwrap_or(ERR_ENOENT),
                format!("failed to read release metadata: {}", e),
            )
        })?;
        return Ok(ReleaseFetch::Published(parse_release_json(&raw)?));
    }
    let ua = format!("afuse/{}", env!("CARGO_PKG_VERSION"));
    let mut cmd = Command::new("/usr/bin/curl");
    cmd.args([
        "-q", "-sSL", "--max-time", "10", "--max-redirs", "5", "--max-filesize", "1048576",
    ]);
    #[cfg(not(any(test, feature = "test-hooks")))]
    cmd.args(["--proto", "=https", "--proto-redir", "=https"]);
    #[cfg(any(test, feature = "test-hooks"))]
    if source.starts_with("https://") {
        cmd.args(["--proto", "=https", "--proto-redir", "=https"]);
    }
    let out = cmd
        .args([
            "-w", "\n%{http_code}", "-H", "Accept: application/vnd.github+json",
            "-H", &format!("User-Agent: {}", ua), &source,
        ])
        .output()
        .map_err(|e| AfuseError::new(1, format!("failed to invoke curl: {}", e)))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let detail = if msg.is_empty() {
            "curl failed to fetch latest release metadata".to_string()
        } else {
            format!("release check failed: {}", msg)
        };
        return Err(AfuseError::new(1, detail));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout.trim_end_matches(['\r', '\n']);
    let (body, code_str) = trimmed.rsplit_once('\n').unwrap_or(("", trimmed));
    let status: u16 = code_str.trim().parse().unwrap_or(0);
    if status == 404 {
        return Ok(ReleaseFetch::Unpublished);
    }
    if !(200..300).contains(&status) {
        return Err(AfuseError::new(1, format!("release check failed: HTTP {}", status)));
    }
    Ok(ReleaseFetch::Published(parse_release_json(body)?))
}

pub fn check_for_updates() -> Result<UpgradeCheckReport, AfuseError> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    match fetch_release_outcome()? {
        ReleaseFetch::Unpublished => Ok(UpgradeCheckReport {
            current_version: current.clone(),
            latest_version: current,
            update_available: false,
            release_state: "unpublished".to_string(),
            release_url: DEFAULT_RELEASES_WEB_URL.to_string(),
            brew_cmd: BREW_UPGRADE_CMD.to_string(),
            dmg_url: None,
            dmg_sha256_url: None,
        }),
        ReleaseFetch::Published(rel) => {
            let update_available = is_newer_version(&current, &rel.latest_version);
            Ok(UpgradeCheckReport {
                current_version: current,
                latest_version: rel.latest_version,
                update_available,
                release_state: "published".to_string(),
                release_url: rel.html_url,
                brew_cmd: BREW_UPGRADE_CMD.to_string(),
                dmg_url: rel.dmg_url,
                dmg_sha256_url: rel.dmg_sha256_url,
            })
        }
    }
}

struct StageCleanup(PathBuf);
impl Drop for StageCleanup {
    fn drop(&mut self) {
        let _ = force_remove_all(&self.0);
    }
}

pub fn perform_upgrade_on_exe(exe_path: &Path) -> Result<UpgradeApplyReport, AfuseError> {
    let canon_exe = fs::canonicalize(exe_path).ok();
    let is_app_bundled = exe_path.to_string_lossy().contains(".app/Contents/MacOS/")
        || canon_exe
            .as_ref()
            .map(|p| p.to_string_lossy().contains(".app/Contents/MacOS/"))
            .unwrap_or(false);
    if is_app_bundled {
        return Err(AfuseError::new(
            ERR_USAGE,
            format!(
                "afuse is bundled inside AgentFuse.app; update via menu bar 'Check for Updates…', DMG, or run: {}",
                BREW_UPGRADE_CMD
            ),
        ));
    }

    let current = env!("CARGO_PKG_VERSION").to_string();
    let rel = match fetch_release_outcome()? {
        ReleaseFetch::Unpublished => {
            return Ok(UpgradeApplyReport {
                current_version: current.clone(),
                latest_version: current,
                updated: false,
                release_state: "unpublished".to_string(),
                release_url: DEFAULT_RELEASES_WEB_URL.to_string(),
                brew_cmd: BREW_UPGRADE_CMD.to_string(),
                verified_sha256: None,
                target_path: Some(exe_path.to_string_lossy().into_owned()),
            });
        }
        ReleaseFetch::Published(rel) => rel,
    };
    if !is_newer_version(&current, &rel.latest_version) {
        return Ok(UpgradeApplyReport {
            current_version: current,
            latest_version: rel.latest_version,
            updated: false,
            release_state: "up_to_date".to_string(),
            release_url: rel.html_url,
            brew_cmd: BREW_UPGRADE_CMD.to_string(),
            verified_sha256: None,
            target_path: Some(exe_path.to_string_lossy().into_owned()),
        });
    }

    let is_symlink_exe = fs::symlink_metadata(exe_path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    let install_target = if is_symlink_exe {
        canon_exe.unwrap_or_else(|| exe_path.to_path_buf())
    } else {
        exe_path.to_path_buf()
    };
    let parent_dir = install_target.parent().ok_or_else(|| {
        AfuseError::new(ERR_EINVAL, "cannot determine binary parent directory")
    })?;
    let stage_dir = create_exclusive_dir_0700(parent_dir, ".afuse.upgrade").map_err(|_| {
        AfuseError::new(
            ERR_EACCES,
            format!("binary directory is not writable; update via menu bar or run: {}", BREW_UPGRADE_CMD),
        )
    })?;
    let _cleanup = StageCleanup(stage_dir.clone());

    let arch_name = format!("afuse-macos-{}.tar.gz", env::consts::ARCH);
    let override_dir = resolve_upgrade_archive_override();
    let allow_local = override_dir.is_some();
    let (tarball_name, tarball_src, sums_src) = if let Some(dir) = override_dir {
        let tb = [DEFAULT_TARBALL_NAME, arch_name.as_str()]
            .into_iter()
            .map(|n| (n, dir.join(n)))
            .find(|(_, p)| p.is_file())
            .ok_or_else(|| {
                AfuseError::new(ERR_ENOENT, format!("upgrade archive missing in {}", dir.display()))
            })?;
        let sums = ["SHA256SUMS.txt", "SHA256SUMS"]
            .into_iter()
            .map(|n| dir.join(n))
            .find(|p| p.is_file())
            .ok_or_else(|| {
                AfuseError::new(ERR_ENOENT, format!("SHA256SUMS missing in {}", dir.display()))
            })?;
        (tb.0.to_string(), tb.1.to_string_lossy().into_owned(), sums.to_string_lossy().into_owned())
    } else {
        let tb_asset = rel
            .assets
            .iter()
            .find(|a| a.name == DEFAULT_TARBALL_NAME)
            .or_else(|| rel.assets.iter().find(|a| a.name == arch_name))
            .ok_or_else(|| {
                AfuseError::new(ERR_ENOENT, format!("release {} missing macOS tarball asset", rel.tag_name))
            })?;
        let sums_asset = rel
            .assets
            .iter()
            .find(|a| a.name == "SHA256SUMS.txt" || a.name == "SHA256SUMS")
            .ok_or_else(|| {
                AfuseError::new(ERR_ENOENT, format!("release {} missing SHA256SUMS asset", rel.tag_name))
            })?;
        (tb_asset.name.clone(), tb_asset.download_url.clone(), sums_asset.download_url.clone())
    };

    let tarball_path = stage_dir.join(&tarball_name);
    let sums_path = stage_dir.join("SHA256SUMS.txt");
    fetch_asset_to_file(&tarball_src, &tarball_path, allow_local)?;
    fetch_asset_to_file(&sums_src, &sums_path, allow_local)?;

    let sums_text = fs::read_to_string(&sums_path)
        .map_err(|e| AfuseError::new(1, format!("failed to read SHA256SUMS: {}", e)))?;
    let expected_sha = expected_sha256_from_sums(&sums_text, &tarball_name)?;
    let actual_sha = sha256_file_hex(&tarball_path)?;
    if actual_sha != expected_sha {
        return Err(AfuseError::new(
            ERR_EINVAL,
            format!("SHA-256 verification failed for {}: expected {}, got {}", tarball_name, expected_sha, actual_sha),
        ));
    }

    let extract_dir = create_exclusive_dir_0700(&stage_dir, "extract")?;
    let extracted_bin = preflight_and_extract_afuse(&tarball_path, &extract_dir)?;

    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let staged_bin = parent_dir.join(format!(
        ".afuse.upgrade.bin.{}.{}.{}",
        std::process::id(),
        seq,
        random_hex_suffix()
    ));
    if fs::copy(&extracted_bin, &staged_bin).is_err() {
        let _ = force_remove_all(&staged_bin);
        return Err(AfuseError::new(
            ERR_EACCES,
            format!("cannot write replacement binary; run: {}", BREW_UPGRADE_CMD),
        ));
    }
    let _ = chmod_nofollow(&staged_bin, 0o755);
    if let Err(e) = prepare_and_verify_staged_binary(&staged_bin, Some(&rel.latest_version)) {
        let _ = force_remove_all(&staged_bin);
        return Err(e);
    }
    if let Err(e) = fs::rename(&staged_bin, &install_target) {
        let _ = force_remove_all(&staged_bin);
        return Err(AfuseError::new(
            e.raw_os_error().unwrap_or(ERR_EACCES),
            format!("atomic binary replacement failed: {}", e),
        ));
    }

    Ok(UpgradeApplyReport {
        current_version: current,
        latest_version: rel.latest_version,
        updated: true,
        release_state: "updated".to_string(),
        release_url: rel.html_url,
        brew_cmd: BREW_UPGRADE_CMD.to_string(),
        verified_sha256: Some(actual_sha),
        target_path: Some(install_target.to_string_lossy().into_owned()),
    })
}

pub fn run_upgrade_apply() -> Result<UpgradeApplyReport, AfuseError> {
    let exe = env::current_exe()
        .map_err(|e| AfuseError::new(1, format!("cannot resolve current executable: {}", e)))?;
    perform_upgrade_on_exe(&exe)
}
