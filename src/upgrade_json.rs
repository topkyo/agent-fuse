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
}

#[derive(Debug, Clone)]
pub struct UpgradeCheckReport {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub release_state: String,
    pub release_url: String,
    pub brew_cmd: String,
}

#[derive(Debug, Clone)]
pub struct UpgradeApplyReport {
    pub current_version: String,
    pub latest_version: String,
    pub updated: bool,
    pub release_url: String,
    pub brew_cmd: String,
    pub verified_sha256: Option<String>,
    pub target_path: Option<String>,
}

impl UpgradeCheckReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"ok\":true,\"current_version\":\"{}\",\"latest_version\":\"{}\",\"update_available\":{},\"release_state\":\"{}\",\"release_url\":\"{}\",\"brew_cmd\":\"{}\"}}",
            json_escape(&self.current_version),
            json_escape(&self.latest_version),
            self.update_available,
            json_escape(&self.release_state),
            json_escape(&self.release_url),
            json_escape(&self.brew_cmd)
        )
    }
}

impl UpgradeApplyReport {
    pub fn to_json(&self) -> String {
        let sha = self
            .verified_sha256
            .as_ref()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .unwrap_or_else(|| "null".to_string());
        let tgt = self
            .target_path
            .as_ref()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"ok\":true,\"updated\":{},\"current_version\":\"{}\",\"latest_version\":\"{}\",\"release_url\":\"{}\",\"brew_cmd\":\"{}\",\"verified_sha256\":{},\"target_path\":{}}}",
            self.updated,
            json_escape(&self.current_version),
            json_escape(&self.latest_version),
            json_escape(&self.release_url),
            json_escape(&self.brew_cmd),
            sha,
            tgt
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
    let (core, pre_str) = match no_build.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (no_build, None),
    };
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let pre = pre_str
        .map(|s| s.split('.').map(|x| x.to_string()).collect())
        .unwrap_or_default();
    Some(ParsedSemver {
        major,
        minor,
        patch,
        pre,
    })
}

pub fn is_newer_version(current: &str, latest: &str) -> bool {
    let (Some(cur), Some(lat)) = (parse_semver(current), parse_semver(latest)) else {
        return false;
    };
    let c_core = (cur.major, cur.minor, cur.patch);
    let l_core = (lat.major, lat.minor, lat.patch);
    if l_core != c_core {
        return l_core > c_core;
    }
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

fn parse_json_string_at(bytes: &[u8], start_quote: usize) -> Option<(String, usize)> {
    if bytes.get(start_quote).copied() != Some(b'"') {
        return None;
    }
    let mut i = start_quote + 1;
    let mut out = String::new();
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Some((out, i + 1)),
            b'\\' => {
                i += 1;
                if i >= bytes.len() {
                    return None;
                }
                match bytes[i] {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' if i + 4 < bytes.len() => {
                        let hex = std::str::from_utf8(&bytes[i + 1..i + 5]).ok()?;
                        if let Ok(code) = u32::from_str_radix(hex, 16) {
                            if let Some(ch) = char::from_u32(code) {
                                out.push(ch);
                            }
                        }
                        i += 4;
                    }
                    other => out.push(other as char),
                }
                i += 1;
            }
            _ => {
                let start = i;
                while i < bytes.len() && bytes[i] != b'"' && bytes[i] != b'\\' {
                    i += 1;
                }
                out.push_str(&String::from_utf8_lossy(&bytes[start..i]));
            }
        }
    }
    None
}

fn skip_json_value(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return i;
    }
    match bytes[i] {
        b'"' => parse_json_string_at(bytes, i).map(|(_, next)| next).unwrap_or(bytes.len()),
        b'{' | b'[' => {
            let mut depth = 0usize;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' => i = parse_json_string_at(bytes, i).map(|(_, n)| n).unwrap_or(bytes.len()),
                    b'{' | b'[' => {
                        depth += 1;
                        i += 1;
                    }
                    b'}' | b']' => {
                        depth = depth.saturating_sub(1);
                        i += 1;
                        if depth == 0 {
                            return i;
                        }
                    }
                    _ => i += 1,
                }
            }
            bytes.len()
        }
        _ => {
            while i < bytes.len() && !matches!(bytes[i], b',' | b'}' | b']') {
                i += 1;
            }
            i
        }
    }
}

fn find_json_field_in_object(obj_bytes: &[u8], target_key: &str) -> Option<(usize, usize)> {
    let mut i = 0usize;
    while i < obj_bytes.len() && obj_bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if obj_bytes.get(i).copied() != Some(b'{') {
        return None;
    }
    i += 1;
    while i < obj_bytes.len() {
        while i < obj_bytes.len() && matches!(obj_bytes[i], b' ' | b'\t' | b'\n' | b'\r' | b',') {
            i += 1;
        }
        if i >= obj_bytes.len() || obj_bytes[i] == b'}' {
            break;
        }
        if obj_bytes[i] != b'"' {
            i += 1;
            continue;
        }
        let (key, after_key) = parse_json_string_at(obj_bytes, i)?;
        i = after_key;
        while i < obj_bytes.len() && obj_bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if obj_bytes.get(i).copied() != Some(b':') {
            continue;
        }
        i += 1;
        while i < obj_bytes.len() && obj_bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let val_start = i;
        let val_end = skip_json_value(obj_bytes, val_start);
        if key == target_key {
            return Some((val_start, val_end));
        }
        i = val_end;
    }
    None
}

fn extract_json_string_field(obj_bytes: &[u8], key: &str) -> Option<String> {
    let (vs, _) = find_json_field_in_object(obj_bytes, key)?;
    parse_json_string_at(obj_bytes, vs).map(|(s, _)| s)
}

fn extract_json_bool_field(obj_bytes: &[u8], key: &str) -> Option<bool> {
    let (vs, ve) = find_json_field_in_object(obj_bytes, key)?;
    let slice = obj_bytes.get(vs..ve)?;
    let text = std::str::from_utf8(slice).ok()?.trim();
    match text {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

pub fn parse_release_json(raw: &str) -> Result<ReleaseInfo, AfuseError> {
    let bytes = raw.as_bytes();
    if extract_json_bool_field(bytes, "draft") == Some(true) {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "draft releases are filtered and not eligible for upgrade",
        ));
    }
    if extract_json_bool_field(bytes, "prerelease") == Some(true) {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "prerelease versions are filtered and not eligible for upgrade",
        ));
    }
    let tag_name = extract_json_string_field(bytes, "tag_name").ok_or_else(|| {
        AfuseError::new(ERR_EINVAL, "release metadata missing 'tag_name'")
    })?;
    let latest_version = tag_name.trim().trim_start_matches(['v', 'V']).to_string();
    if parse_semver(&latest_version).is_none() {
        return Err(AfuseError::new(
            ERR_EINVAL,
            format!("invalid release tag_name '{}'", tag_name),
        ));
    }
    let html_url = extract_json_string_field(bytes, "html_url").unwrap_or_else(|| {
        format!("https://github.com/topkyo/agent-fuse/releases/tag/{}", tag_name)
    });

    let mut assets = Vec::new();
    if let Some((as_start, as_end)) = find_json_field_in_object(bytes, "assets") {
        let arr = &bytes[as_start..as_end];
        let mut i = 0usize;
        while i < arr.len() {
            if arr[i] == b'{' {
                let end = skip_json_value(arr, i);
                let slice = &arr[i..end];
                if let (Some(name), Some(dl)) = (
                    extract_json_string_field(slice, "name"),
                    extract_json_string_field(slice, "browser_download_url"),
                ) {
                    assets.push(ReleaseAsset {
                        name,
                        download_url: dl,
                    });
                }
                i = end;
            } else {
                i += 1;
            }
        }
    }

    Ok(ReleaseInfo {
        tag_name,
        latest_version,
        html_url,
        assets,
    })
}

pub fn validate_release_asset_url(url: &str) -> Result<(), AfuseError> {
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        AfuseError::new(ERR_EINVAL, "release asset URL must use https://")
    })?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(AfuseError::new(ERR_EINVAL, "invalid release asset authority"));
    }
    let host = authority.split(':').next().unwrap_or("").to_ascii_lowercase();
    if !matches!(
        host.as_str(),
        "github.com" | "objects.githubusercontent.com" | "release-assets.githubusercontent.com"
    ) {
        return Err(AfuseError::new(ERR_EINVAL, format!("untrusted release asset host: {}", host)));
    }
    Ok(())
}
