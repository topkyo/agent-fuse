use crate::apfs::{force_remove_all, TMP_SEQ};
use crate::error::{AfuseError, ERR_EACCES, ERR_EINVAL, ERR_ENOENT, ERR_USAGE};
use crate::sha256::Sha256;
pub use crate::upgrade_json::{
    is_newer_version, parse_release_json, ReleaseAsset, ReleaseInfo, UpgradeApplyReport,
    UpgradeCheckReport,
};
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
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

fn fetch_release_outcome() -> Result<ReleaseFetch, AfuseError> {
    let source = env::var("AFUSE_RELEASE_JSON_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_RELEASE_API_URL.to_string());
    if !source.starts_with("http://") && !source.starts_with("https://") {
        let local = source.strip_prefix("file://").unwrap_or(&source);
        let raw = fs::read_to_string(local).map_err(|e| {
            AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), format!("failed to read release metadata: {}", e))
        })?;
        return Ok(ReleaseFetch::Published(parse_release_json(&raw)?));
    }
    let ua = format!("afuse/{}", env!("CARGO_PKG_VERSION"));
    let out = Command::new("/usr/bin/curl")
        .args(["-sSL", "--max-time", "10", "-w", "\n%{http_code}", "-H", "Accept: application/vnd.github+json", "-H", &format!("User-Agent: {}", ua), &source])
        .output()
        .map_err(|e| AfuseError::new(1, format!("failed to invoke curl: {}", e)))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let detail = if msg.is_empty() { "curl failed to fetch latest release metadata".to_string() } else { format!("release check failed: {}", msg) };
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
            })
        }
    }
}

fn fetch_asset_to_file(source: &str, dest: &Path) -> Result<(), AfuseError> {
    let local = source.strip_prefix("file://").unwrap_or(source);
    if !source.starts_with("http://") && !source.starts_with("https://") {
        fs::copy(local, dest).map_err(|e| {
            AfuseError::new(
                e.raw_os_error().unwrap_or(1),
                format!("failed to copy archive asset: {}", e),
            )
        })?;
        return Ok(());
    }
    let out = Command::new("/usr/bin/curl")
        .args(["-fsSL", "--max-time", "30", "-o"])
        .arg(dest)
        .arg(source)
        .output()
        .map_err(|e| AfuseError::new(1, format!("failed to invoke curl: {}", e)))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(AfuseError::new(1, format!("asset download failed: {}", msg)));
    }
    Ok(())
}

fn sha256_file_hex(path: &Path) -> Result<String, AfuseError> {
    let mut f = File::open(path).map_err(|e| {
        AfuseError::new(
            e.raw_os_error().unwrap_or(ERR_ENOENT),
            format!("cannot open {}: {}", path.display(), e),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| AfuseError::new(1, format!("read failed: {}", e)))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize_hex())
}

fn expected_sha256_from_sums(sums_text: &str, tarball_name: &str) -> Result<String, AfuseError> {
    for line in sums_text.lines() {
        let mut parts = line.trim().split_whitespace();
        let (Some(hash_tok), Some(file_tok)) = (parts.next(), parts.next()) else {
            continue;
        };
        let clean_name = file_tok.trim_start_matches('*');
        let base_name = Path::new(clean_name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(clean_name);
        if (clean_name == tarball_name || base_name == tarball_name)
            && hash_tok.len() == 64
            && hash_tok.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Ok(hash_tok.to_ascii_lowercase());
        }
    }
    Err(AfuseError::new(
        ERR_EINVAL,
        format!("checksum entry for '{}' not found in SHA256SUMS", tarball_name),
    ))
}

fn find_extracted_afuse(dir: &Path) -> Option<PathBuf> {
    for rel in ["afuse", "bin/afuse"] {
        let cand = dir.join(rel);
        if cand.is_file() {
            return Some(cand);
        }
    }
    if let Ok(rd) = fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                if let Some(found) = find_extracted_afuse(&p) {
                    return Some(found);
                }
            }
        }
    }
    None
}

struct StageCleanup(PathBuf);
impl Drop for StageCleanup {
    fn drop(&mut self) {
        let _ = force_remove_all(&self.0);
    }
}

pub fn perform_upgrade_on_exe(exe_path: &Path) -> Result<UpgradeApplyReport, AfuseError> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let rel = match fetch_release_outcome()? {
        ReleaseFetch::Unpublished => {
            return Ok(UpgradeApplyReport {
                current_version: current.clone(),
                latest_version: current,
                updated: false,
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
            release_url: rel.html_url,
            brew_cmd: BREW_UPGRADE_CMD.to_string(),
            verified_sha256: None,
            target_path: Some(exe_path.to_string_lossy().into_owned()),
        });
    }

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
                "afuse is bundled inside AgentFuse.app; update via menu bar 'Check for Updates…' or run: {}",
                BREW_UPGRADE_CMD
            ),
        ));
    }

    let parent_dir = exe_path.parent().ok_or_else(|| {
        AfuseError::new(ERR_EINVAL, "cannot determine binary parent directory")
    })?;
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let stage_dir = parent_dir.join(format!(".afuse.upgrade.{}.{}", std::process::id(), seq));
    if fs::create_dir_all(&stage_dir).is_err() {
        return Err(AfuseError::new(
            ERR_EACCES,
            format!("binary directory is not writable; update via menu bar or run: {}", BREW_UPGRADE_CMD),
        ));
    }
    let _cleanup = StageCleanup(stage_dir.clone());

    let arch_name = format!("afuse-macos-{}.tar.gz", env::consts::ARCH);
    let override_dir = env::var("AFUSE_UPGRADE_ARCHIVE_DIR")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

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
        (
            tb.0.to_string(),
            tb.1.to_string_lossy().into_owned(),
            sums.to_string_lossy().into_owned(),
        )
    } else {
        let tb_asset = rel
            .assets
            .iter()
            .find(|a| a.name == DEFAULT_TARBALL_NAME)
            .or_else(|| rel.assets.iter().find(|a| a.name == arch_name))
            .ok_or_else(|| {
                AfuseError::new(
                    ERR_ENOENT,
                    format!("release {} missing macOS tarball asset", rel.tag_name),
                )
            })?;
        let sums_asset = rel
            .assets
            .iter()
            .find(|a| a.name == "SHA256SUMS.txt" || a.name == "SHA256SUMS")
            .ok_or_else(|| {
                AfuseError::new(
                    ERR_ENOENT,
                    format!("release {} missing SHA256SUMS asset", rel.tag_name),
                )
            })?;
        (
            tb_asset.name.clone(),
            tb_asset.download_url.clone(),
            sums_asset.download_url.clone(),
        )
    };

    let tarball_path = stage_dir.join(&tarball_name);
    let sums_path = stage_dir.join("SHA256SUMS.txt");
    fetch_asset_to_file(&tarball_src, &tarball_path)?;
    fetch_asset_to_file(&sums_src, &sums_path)?;

    let sums_text = fs::read_to_string(&sums_path)
        .map_err(|e| AfuseError::new(1, format!("failed to read SHA256SUMS: {}", e)))?;
    let expected_sha = expected_sha256_from_sums(&sums_text, &tarball_name)?;
    let actual_sha = sha256_file_hex(&tarball_path)?;
    if actual_sha != expected_sha {
        return Err(AfuseError::new(
            ERR_EINVAL,
            format!(
                "SHA-256 verification failed for {}: expected {}, got {}",
                tarball_name, expected_sha, actual_sha
            ),
        ));
    }

    let extract_dir = stage_dir.join("extract");
    fs::create_dir_all(&extract_dir)
        .map_err(|e| AfuseError::new(1, format!("mkdir failed: {}", e)))?;
    let tar_out = Command::new("/usr/bin/tar")
        .arg("-xzf")
        .arg(&tarball_path)
        .arg("-C")
        .arg(&extract_dir)
        .output()
        .map_err(|e| AfuseError::new(1, format!("tar invocation failed: {}", e)))?;
    if !tar_out.status.success() {
        return Err(AfuseError::new(
            1,
            format!("tar extraction failed: {}", String::from_utf8_lossy(&tar_out.stderr).trim()),
        ));
    }

    let extracted_bin = find_extracted_afuse(&extract_dir).ok_or_else(|| {
        AfuseError::new(ERR_ENOENT, "extracted release archive does not contain 'afuse'")
    })?;
    let staged_bin = parent_dir.join(format!(".afuse.upgrade.bin.{}.{}", std::process::id(), seq));
    if fs::copy(&extracted_bin, &staged_bin).is_err() {
        let _ = force_remove_all(&staged_bin);
        return Err(AfuseError::new(
            ERR_EACCES,
            format!("cannot write replacement binary; run: {}", BREW_UPGRADE_CMD),
        ));
    }
    let _ = fs::set_permissions(&staged_bin, fs::Permissions::from_mode(0o755));
    if let Err(e) = fs::rename(&staged_bin, exe_path) {
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
        release_url: rel.html_url,
        brew_cmd: BREW_UPGRADE_CMD.to_string(),
        verified_sha256: Some(actual_sha),
        target_path: Some(exe_path.to_string_lossy().into_owned()),
    })
}

pub fn run_upgrade_apply() -> Result<UpgradeApplyReport, AfuseError> {
    let exe = env::current_exe()
        .map_err(|e| AfuseError::new(1, format!("cannot resolve current executable: {}", e)))?;
    perform_upgrade_on_exe(&exe)
}
