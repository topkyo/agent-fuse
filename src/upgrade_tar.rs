use crate::error::{AfuseError, ERR_EINVAL, ERR_ENOENT};
use crate::sha256::Sha256;
use crate::upgrade_json::{validate_effective_asset_url, validate_release_asset_url};
use crate::upgrade_verify::{find_extracted_afuse, is_real_non_symlink_dir, is_regular_non_symlink_file};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub(crate) const MAX_TAR_ENTRIES: usize = 64;
pub(crate) const MAX_TAR_EXTRACT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_TAR_PATH_DEPTH: usize = 5;

fn validate_tar_member_path(raw: &str) -> Result<PathBuf, AfuseError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('/')
        || trimmed.contains('\0')
        || trimmed.contains('\\')
        || trimmed.contains(" -> ")
        || trimmed.contains(" link to ")
        || trimmed.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f)
    {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "rejected unsafe archive member path",
        ));
    }
    let mut clean = PathBuf::new();
    let mut depth = 0usize;
    for comp in Path::new(trimmed).components() {
        match comp {
            Component::Normal(seg) => {
                clean.push(seg);
                depth += 1;
                if depth > MAX_TAR_PATH_DEPTH {
                    return Err(AfuseError::new(
                        ERR_EINVAL,
                        "archive member nesting exceeds limit",
                    ));
                }
            }
            Component::CurDir => {}
            _ => {
                return Err(AfuseError::new(
                    ERR_EINVAL,
                    "rejected traversal or root component in archive",
                ));
            }
        }
    }
    Ok(clean)
}

fn parse_bsdtar_verbose_line(line: &str) -> Result<(char, u64, String), AfuseError> {
    let trimmed = line.trim_end_matches('\r');
    let bytes = trimmed.as_bytes();
    let mut pos = 0usize;
    let mut tokens: [&str; 8] = [""; 8];
    for slot in &mut tokens {
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let start = pos;
        while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if start == pos {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "malformed tar listing entry",
            ));
        }
        *slot = &trimmed[start..pos];
    }
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    if pos >= bytes.len() {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "missing member path in tar listing",
        ));
    }
    let mode_tok = tokens[0];
    let kind = mode_tok
        .chars()
        .next()
        .ok_or_else(|| AfuseError::new(ERR_EINVAL, "missing tar mode prefix"))?;
    let size = tokens[4].parse::<u64>().map_err(|_| {
        AfuseError::new(ERR_EINVAL, "invalid tar entry size or device node")
    })?;
    let member_raw = trimmed[pos..].to_string();
    Ok((kind, size, member_raw))
}

pub(crate) fn preflight_tar_listing(listing: &str) -> Result<String, AfuseError> {
    let mut entry_count = 0usize;
    let mut total_bytes = 0u64;
    let mut target_member: Option<String> = None;

    for raw_line in listing.lines() {
        if raw_line.trim().is_empty() {
            continue;
        }
        entry_count += 1;
        if entry_count > MAX_TAR_ENTRIES {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "release archive exceeds maximum entry count",
            ));
        }
        let (kind, size, member_raw) = parse_bsdtar_verbose_line(raw_line)?;
        if kind != '-' && kind != 'd' {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "release archive contains forbidden non-regular entry (symlink/hardlink/special)",
            ));
        }
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_TAR_EXTRACT_BYTES {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "release archive exceeds 32 MiB extracted size limit",
            ));
        }
        let clean = validate_tar_member_path(&member_raw)?;
        if kind == '-' {
            if clean.file_name().and_then(|n| n.to_str()) == Some("afuse")
                && target_member.is_none()
            {
                target_member = Some(member_raw);
            }
        }
    }
    if entry_count == 0 {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "release archive listing is empty",
        ));
    }
    target_member.ok_or_else(|| {
        AfuseError::new(
            ERR_ENOENT,
            "release archive does not contain a regular 'afuse' binary",
        )
    })
}

fn verify_extracted_rel_chain(extract_dir: &Path, extracted_file: &Path) -> Result<(), AfuseError> {
    let rel = extracted_file
        .strip_prefix(extract_dir)
        .map_err(|_| AfuseError::new(ERR_EINVAL, "extracted binary escaped stage directory"))?;
    let mut cur = extract_dir.to_path_buf();
    let comps: Vec<_> = rel.components().collect();
    if comps.is_empty() {
        return Err(AfuseError::new(ERR_EINVAL, "empty extracted binary path"));
    }
    for (idx, comp) in comps.iter().enumerate() {
        let Component::Normal(seg) = comp else {
            return Err(AfuseError::new(ERR_EINVAL, "invalid extracted binary path"));
        };
        cur.push(seg);
        if idx + 1 < comps.len() {
            if !is_real_non_symlink_dir(&cur) {
                return Err(AfuseError::new(
                    ERR_EINVAL,
                    "extracted archive contains symlinked intermediate directory",
                ));
            }
        } else if !is_regular_non_symlink_file(&cur) {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "extracted afuse binary is not a regular non-symlink file",
            ));
        }
    }
    Ok(())
}

pub(crate) fn preflight_and_extract_afuse(
    tarball_path: &Path,
    extract_dir: &Path,
) -> Result<PathBuf, AfuseError> {
    let list_out = Command::new("/usr/bin/tar")
        .arg("-tvzf")
        .arg(tarball_path)
        .output()
        .map_err(|e| AfuseError::new(1, format!("tar listing failed: {}", e)))?;
    if !list_out.status.success() {
        return Err(AfuseError::new(
            ERR_EINVAL,
            format!(
                "tar preflight listing failed: {}",
                String::from_utf8_lossy(&list_out.stderr).trim()
            ),
        ));
    }
    let listing = String::from_utf8_lossy(&list_out.stdout);
    let target_member = preflight_tar_listing(&listing)?;
    let tar_out = Command::new("/usr/bin/tar")
        .args(["--no-same-owner", "--no-same-permissions", "-xzf"])
        .arg(tarball_path)
        .arg("-C")
        .arg(extract_dir)
        .arg("--")
        .arg(&target_member)
        .output()
        .map_err(|e| AfuseError::new(1, format!("tar invocation failed: {}", e)))?;
    if !tar_out.status.success() {
        return Err(AfuseError::new(
            1,
            format!(
                "tar extraction failed: {}",
                String::from_utf8_lossy(&tar_out.stderr).trim()
            ),
        ));
    }
    let extracted_bin = find_extracted_afuse(extract_dir).ok_or_else(|| {
        AfuseError::new(ERR_ENOENT, "extracted release archive does not contain 'afuse'")
    })?;
    verify_extracted_rel_chain(extract_dir, &extracted_bin)?;
    Ok(extracted_bin)
}

pub(crate) fn validate_effective_download_url(
    effective_url: &str,
    dest: &Path,
) -> Result<(), AfuseError> {
    let trimmed = effective_url.trim();
    if trimmed.is_empty() {
        let _ = fs::remove_file(dest);
        return Err(AfuseError::new(ERR_EINVAL, "missing effective download URL"));
    }
    if let Err(e) = validate_effective_asset_url(trimmed) {
        let _ = fs::remove_file(dest);
        return Err(AfuseError::new(
            ERR_EINVAL,
            format!("untrusted post-redirect download URL '{}': {}", trimmed, e.message),
        ));
    }
    Ok(())
}

pub(crate) fn fetch_asset_to_file(
    source: &str,
    dest: &Path,
    allow_local: bool,
) -> Result<(), AfuseError> {
    #[cfg(any(test, feature = "test-hooks"))]
    if allow_local {
        let local = source.strip_prefix("file://").unwrap_or(source);
        fs::copy(local, dest).map_err(|e| {
            AfuseError::new(
                e.raw_os_error().unwrap_or(1),
                format!("failed to copy archive asset: {}", e),
            )
        })?;
        return Ok(());
    }
    let _ = allow_local;
    validate_release_asset_url(source)?;
    let out = Command::new("/usr/bin/curl")
        .args([
            "-q", "-fsSL", "--proto", "=https", "--proto-redir", "=https",
            "--max-redirs", "5", "--max-time", "30", "--max-filesize", "26214400",
            "-w", "%{url_effective}", "-o",
        ])
        .arg(dest)
        .arg(source)
        .output()
        .map_err(|e| AfuseError::new(1, format!("failed to invoke curl: {}", e)))?;
    if !out.status.success() {
        let _ = fs::remove_file(dest);
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(AfuseError::new(1, format!("asset download failed: {}", msg)));
    }
    validate_effective_download_url(&String::from_utf8_lossy(&out.stdout), dest)
}

pub(crate) fn sha256_file_hex(path: &Path) -> Result<String, AfuseError> {
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

pub(crate) fn expected_sha256_from_sums(sums_text: &str, tarball_name: &str) -> Result<String, AfuseError> {
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
