use crate::error::{AfuseError, ERR_EINVAL};
use crate::manifest::json_escape;

#[derive(Debug, Clone)]
pub struct ReleaseAsset {
    pub name: String,
    pub download_url: String,
}

#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub tag_name: String,
    pub latest_version: String,
    pub html_url: String,
    pub assets: Vec<ReleaseAsset>,
    pub dmg_url: Option<String>,
    pub dmg_sha256_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpgradeCheckReport {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub release_state: String,
    pub release_url: String,
    pub brew_cmd: String,
    pub dmg_url: Option<String>,
    pub dmg_sha256_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpgradeApplyReport {
    pub current_version: String,
    pub latest_version: String,
    pub updated: bool,
    pub release_state: String,
    pub release_url: String,
    pub brew_cmd: String,
    pub verified_sha256: Option<String>,
    pub target_path: Option<String>,
}

fn json_opt_str(v: &Option<String>) -> String {
    v.as_ref()
        .map(|s| format!("\"{}\"", json_escape(s)))
        .unwrap_or_else(|| "null".to_string())
}

impl UpgradeCheckReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"ok\":true,\"current_version\":\"{}\",\"latest_version\":\"{}\",\"update_available\":{},\"release_state\":\"{}\",\"release_url\":\"{}\",\"brew_cmd\":\"{}\",\"dmg_url\":{},\"dmg_sha256_url\":{}}}",
            json_escape(&self.current_version), json_escape(&self.latest_version), self.update_available,
            json_escape(&self.release_state), json_escape(&self.release_url), json_escape(&self.brew_cmd),
            json_opt_str(&self.dmg_url), json_opt_str(&self.dmg_sha256_url)
        )
    }
}

impl UpgradeApplyReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"ok\":true,\"updated\":{},\"release_state\":\"{}\",\"current_version\":\"{}\",\"latest_version\":\"{}\",\"release_url\":\"{}\",\"brew_cmd\":\"{}\",\"verified_sha256\":{},\"target_path\":{}}}",
            self.updated, json_escape(&self.release_state), json_escape(&self.current_version),
            json_escape(&self.latest_version), json_escape(&self.release_url), json_escape(&self.brew_cmd),
            json_opt_str(&self.verified_sha256), json_opt_str(&self.target_path)
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ParsedSemver {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<String>,
}

pub(crate) fn parse_semver(raw: &str) -> Option<ParsedSemver> {
    let trimmed = raw.trim().trim_start_matches(['v', 'V']);
    let no_build = trimmed.split('+').next()?;
    let (core, pre_str) = match no_build.split_once('-') { Some((c, p)) => (c, Some(p)), None => (no_build, None) };
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    if parts.next().is_some() { return None; }
    let pre = pre_str.map(|s| s.split('.').map(|x| x.to_string()).collect()).unwrap_or_default();
    Some(ParsedSemver { major, minor, patch, pre })
}

pub fn is_newer_version(current: &str, latest: &str) -> bool {
    let (Some(cur), Some(lat)) = (parse_semver(current), parse_semver(latest)) else { return false };
    let (c_core, l_core) = ((cur.major, cur.minor, cur.patch), (lat.major, lat.minor, lat.patch));
    if l_core != c_core { return l_core > c_core; }
    match (cur.pre.is_empty(), lat.pre.is_empty()) {
        (true, true) => false,
        (false, true) => true,
        (true, false) => false,
        (false, false) => {
            for i in 0..cur.pre.len().max(lat.pre.len()) {
                match (cur.pre.get(i), lat.pre.get(i)) {
                    (None, Some(_)) => return true,
                    (Some(_), None) => return false,
                    (Some(a), Some(b)) if a != b => {
                        return match (a.parse::<u64>(), b.parse::<u64>()) {
                            (Ok(na), Ok(nb)) => nb > na,
                            (Ok(_), Err(_)) => true,
                            (Err(_), Ok(_)) => false,
                            (Err(_), Err(_)) => b > a,
                        };
                    }
                    _ => {}
                }
            }
            false
        }
    }
}

fn parse_hex4_bytes(bytes: &[u8], idx: usize) -> Option<u32> {
    let slice = bytes.get(idx..idx + 4)?;
    if !slice.iter().all(|b| b.is_ascii_hexdigit()) { return None; }
    u32::from_str_radix(std::str::from_utf8(slice).ok()?, 16).ok()
}

fn parse_json_string_at(bytes: &[u8], start_quote: usize) -> Option<(String, usize)> {
    if bytes.get(start_quote).copied() != Some(b'"') { return None; }
    let mut i = start_quote + 1;
    let mut out = String::new();
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Some((out, i + 1)),
            b'\\' => {
                i += 1;
                if i >= bytes.len() { return None; }
                let esc_ch = match bytes[i] {
                    b'"' => Some('"'), b'\\' => Some('\\'), b'/' => Some('/'),
                    b'b' => Some('\u{0008}'), b'f' => Some('\u{000C}'),
                    b'n' => Some('\n'), b'r' => Some('\r'), b't' => Some('\t'),
                    b'u' => {
                        let u1 = parse_hex4_bytes(bytes, i + 1)?;
                        i += 5;
                        if (0xD800..=0xDBFF).contains(&u1) && bytes.get(i..i + 2) == Some(b"\\u") {
                            if let Some(u2) = parse_hex4_bytes(bytes, i + 2).filter(|v| (0xDC00..=0xDFFF).contains(v)) {
                                i += 6;
                                out.push(char::from_u32(0x10000 + (((u1 - 0xD800) << 10) | (u2 - 0xDC00))).unwrap_or(char::REPLACEMENT_CHARACTER));
                            } else { out.push(char::REPLACEMENT_CHARACTER); }
                        } else if (0xD800..=0xDFFF).contains(&u1) { out.push(char::REPLACEMENT_CHARACTER); }
                        else if let Some(ch) = char::from_u32(u1) { out.push(ch); }
                        None
                    }
                    other => Some(other as char),
                };
                if let Some(c) = esc_ch { out.push(c); i += 1; }
            }
            _ => {
                let start = i;
                while i < bytes.len() && bytes[i] != b'"' && bytes[i] != b'\\' { i += 1; }
                out.push_str(&String::from_utf8_lossy(&bytes[start..i]));
            }
        }
    }
    None
}

fn skip_json_value(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() { i += 1; }
    if i >= bytes.len() { return i; }
    match bytes[i] {
        b'"' => parse_json_string_at(bytes, i).map(|(_, next)| next).unwrap_or(bytes.len()),
        b'{' | b'[' => {
            let mut depth = 0usize;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' => i = parse_json_string_at(bytes, i).map(|(_, n)| n).unwrap_or(bytes.len()),
                    b'{' | b'[' => { depth += 1; i += 1; }
                    b'}' | b']' => {
                        depth = depth.saturating_sub(1); i += 1;
                        if depth == 0 { return i; }
                    }
                    _ => i += 1,
                }
            }
            bytes.len()
        }
        _ => {
            while i < bytes.len() && !matches!(bytes[i], b',' | b'}' | b']') { i += 1; }
            i
        }
    }
}

fn find_json_field_in_object(obj_bytes: &[u8], target_key: &str) -> Option<(usize, usize)> {
    let mut i = 0usize;
    while i < obj_bytes.len() && obj_bytes[i].is_ascii_whitespace() { i += 1; }
    if obj_bytes.get(i).copied() != Some(b'{') { return None; }
    i += 1;
    while i < obj_bytes.len() {
        while i < obj_bytes.len() && matches!(obj_bytes[i], b' ' | b'\t' | b'\n' | b'\r' | b',') { i += 1; }
        if i >= obj_bytes.len() || obj_bytes[i] == b'}' { break; }
        if obj_bytes[i] != b'"' { i += 1; continue; }
        let (key, after_key) = parse_json_string_at(obj_bytes, i)?;
        i = after_key;
        while i < obj_bytes.len() && obj_bytes[i].is_ascii_whitespace() { i += 1; }
        if obj_bytes.get(i).copied() != Some(b':') { continue; }
        i += 1;
        while i < obj_bytes.len() && obj_bytes[i].is_ascii_whitespace() { i += 1; }
        let val_start = i;
        let val_end = skip_json_value(obj_bytes, val_start);
        if key == target_key { return Some((val_start, val_end)); }
        i = val_end;
    }
    None
}

fn extract_json_string_field(obj_bytes: &[u8], key: &str) -> Option<String> {
    find_json_field_in_object(obj_bytes, key).and_then(|(vs, _)| parse_json_string_at(obj_bytes, vs).map(|(s, _)| s))
}

fn extract_json_bool_field(obj_bytes: &[u8], key: &str) -> Option<bool> {
    let (vs, ve) = find_json_field_in_object(obj_bytes, key)?;
    match std::str::from_utf8(obj_bytes.get(vs..ve)?).ok()?.trim() {
        "true" => Some(true), "false" => Some(false), _ => None,
    }
}

pub(crate) fn sanitize_release_html_url(raw: Option<String>) -> String {
    const FALLBACK: &str = "https://github.com/topkyo/agent-fuse/releases";
    let Some(candidate) = raw else {
        return FALLBACK.to_string();
    };
    let trimmed = candidate.trim();
    let lower = trimmed.to_ascii_lowercase();
    let bad = trimmed.is_empty()
        || !trimmed.starts_with("https://github.com/topkyo/agent-fuse/releases/")
        || trimmed.chars().any(|c| c.is_whitespace() || (c as u32) < 0x20 || c as u32 == 0x7f)
        || lower.contains("..")
        || lower.contains("%2e")
        || lower.contains('\\')
        || lower.contains("%5c")
        || trimmed.contains('@');
    if bad {
        FALLBACK.to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn parse_release_json(raw: &str) -> Result<ReleaseInfo, AfuseError> {
    let bytes = raw.as_bytes();
    if extract_json_bool_field(bytes, "draft") == Some(true) {
        return Err(AfuseError::new(ERR_EINVAL, "draft releases are filtered and not eligible for upgrade"));
    }
    if extract_json_bool_field(bytes, "prerelease") == Some(true) {
        return Err(AfuseError::new(ERR_EINVAL, "prerelease versions are filtered and not eligible for upgrade"));
    }
    let tag_name = extract_json_string_field(bytes, "tag_name")
        .ok_or_else(|| AfuseError::new(ERR_EINVAL, "release metadata missing 'tag_name'"))?;
    let latest_version = tag_name.trim().trim_start_matches(['v', 'V']).to_string();
    if parse_semver(&latest_version).is_none() {
        return Err(AfuseError::new(ERR_EINVAL, format!("invalid release tag_name '{}'", tag_name)));
    }
    let html_url = sanitize_release_html_url(extract_json_string_field(bytes, "html_url"));
    let mut assets = Vec::new();
    if let Some((as_start, as_end)) = find_json_field_in_object(bytes, "assets") {
        let (arr, mut i) = (&bytes[as_start..as_end], 0usize);
        while i < arr.len() {
            if arr[i] == b'"' {
                i = parse_json_string_at(arr, i).map(|(_, n)| n).unwrap_or(arr.len());
            } else if arr[i] == b'{' {
                let end = skip_json_value(arr, i);
                if let (Some(name), Some(download_url)) = (
                    extract_json_string_field(&arr[i..end], "name"),
                    extract_json_string_field(&arr[i..end], "browser_download_url"),
                ) { assets.push(ReleaseAsset { name, download_url }); }
                i = end;
            } else { i += 1; }
        }
    }
    let (dmg_url, dmg_sha256_url) = extract_trusted_dmg_urls(&assets);
    Ok(ReleaseInfo { tag_name, latest_version, html_url, assets, dmg_url, dmg_sha256_url })
}

fn validate_asset_url_inner(url: &str, allow_cdn: bool) -> Result<(), AfuseError> {
    if url
        .chars()
        .any(|c| c.is_whitespace() || (c as u32) < 0x20 || c as u32 == 0x7f)
    {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "release asset URL contains control or whitespace characters",
        ));
    }
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| AfuseError::new(ERR_EINVAL, "release asset URL must use https://"))?;
    let (authority, path_only) = match rest.find(['/', '?', '#']) {
        Some(pos) if rest.as_bytes()[pos] == b'/' => {
            let after_slash = &rest[pos + 1..];
            (&rest[..pos], after_slash.split(['?', '#']).next().unwrap_or(""))
        }
        Some(pos) => (&rest[..pos], ""),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return Err(AfuseError::new(ERR_EINVAL, "invalid release asset authority"));
    }
    let (host_raw, port_opt) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if let Some(port) = port_opt {
        if port != "443" {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "non-443 port rejected for release asset URL",
            ));
        }
    }
    let host = host_raw.to_ascii_lowercase();
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
        | "github-releases.githubusercontent.com"
            if allow_cdn => {}
        _ => {
            return Err(AfuseError::new(
                ERR_EINVAL,
                format!("untrusted release asset host: {}", host),
            ));
        }
    }
    Ok(())
}

pub fn validate_release_asset_url(url: &str) -> Result<(), AfuseError> {
    validate_asset_url_inner(url, false)
}

pub(crate) fn validate_effective_asset_url(url: &str) -> Result<(), AfuseError> {
    validate_asset_url_inner(url, true)
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
