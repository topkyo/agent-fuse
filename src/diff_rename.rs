use crate::error::AfuseError;
use crate::fs_guard::TempPermGuard;
use crate::manifest::hash_file_streaming;
use crate::sha256::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub(crate) const RENAME_FULL_HASH_MAX: u64 = 16 * 1024 * 1024;
const SAMPLE_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenamePair {
    pub from: String,
    pub to: String,
}

fn is_git_path(rel: &str) -> bool {
    rel == ".git" || rel.starts_with(".git/")
}

fn extract_sig_len(sig: &str) -> Option<u64> {
    let rest = sig.strip_prefix("F:")?;
    let mut parts = rest.splitn(4, ':');
    let _mode = parts.next()?;
    parts.next()?.parse::<u64>().ok()
}

fn extract_full_manifest_hash(sig: &str) -> Option<&str> {
    let rest = sig.strip_prefix("F:")?;
    let mut parts = rest.split(':');
    let _mode = parts.next()?;
    let _len = parts.next()?;
    let third = parts.next()?;
    if parts.next().is_none() && third.len() == 64 {
        Some(third)
    } else {
        None
    }
}

fn read_chunk_at(file: &mut fs::File, offset: u64, buf: &mut [u8]) -> Result<usize, AfuseError> {
    file.seek(SeekFrom::Start(offset)).map_err(|e| {
        AfuseError::new(e.raw_os_error().unwrap_or(1), format!("seek failed: {}", e))
    })?;
    let mut total = 0usize;
    while total < buf.len() {
        let n = file.read(&mut buf[total..]).map_err(|e| {
            AfuseError::new(e.raw_os_error().unwrap_or(1), format!("read failed: {}", e))
        })?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

fn hash_large_file_sampled(path: &Path, len: u64) -> Result<String, AfuseError> {
    let _guard = TempPermGuard::ensure(path, 0o400);
    let mut file = fs::File::open(path).map_err(|e| {
        AfuseError::new(
            e.raw_os_error().unwrap_or(1),
            format!("open failed on {}: {}", path.display(), e),
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&len.to_le_bytes());
    let mut buf = vec![0u8; SAMPLE_CHUNK_BYTES];
    let head_n = read_chunk_at(&mut file, 0, &mut buf)?;
    hasher.update(&buf[..head_n]);
    let mid_off = (len / 2).saturating_sub((SAMPLE_CHUNK_BYTES as u64) / 2);
    let mid_n = read_chunk_at(&mut file, mid_off, &mut buf)?;
    hasher.update(&buf[..mid_n]);
    let tail_off = len.saturating_sub(SAMPLE_CHUNK_BYTES as u64);
    let tail_n = read_chunk_at(&mut file, tail_off, &mut buf)?;
    hasher.update(&buf[..tail_n]);
    Ok(format!("S:{}", hasher.finalize_hex()))
}

fn rename_content_sig(path: &Path, len: u64, sig_hint: &str) -> Option<String> {
    if len <= RENAME_FULL_HASH_MAX {
        if let Some(h) = extract_full_manifest_hash(sig_hint) {
            return Some(format!("H:{}", h));
        }
        hash_file_streaming(path).ok().map(|h| format!("H:{}", h))
    } else {
        hash_large_file_sampled(path, len).ok()
    }
}

fn match_priority(from: &str, to: &str) -> u8 {
    let fp = Path::new(from);
    let tp = Path::new(to);
    if fp.file_name().is_some() && fp.file_name() == tp.file_name() {
        2
    } else if fp.parent() == tp.parent() {
        1
    } else {
        0
    }
}

pub(crate) fn detect_renames_in_dir(
    snap_root: &Path,
    live_root: &Path,
    snap_entries: &BTreeMap<String, String>,
    live_entries: &BTreeMap<String, String>,
    deleted: &mut Vec<String>,
    added: &mut Vec<String>,
) -> Vec<RenamePair> {
    if deleted.is_empty() || added.is_empty() {
        return Vec::new();
    }
    let mut added_buckets: HashMap<(bool, u64), Vec<usize>> = HashMap::new();
    for (idx, rel) in added.iter().enumerate() {
        let Some(sig) = live_entries.get(rel) else {
            continue;
        };
        let Some(len) = extract_sig_len(sig) else {
            continue;
        };
        added_buckets
            .entry((is_git_path(rel), len))
            .or_default()
            .push(idx);
    }
    let mut used_added = vec![false; added.len()];
    let mut used_deleted = vec![false; deleted.len()];
    let mut added_sigs: HashMap<usize, Option<String>> = HashMap::new();
    let mut renamed = Vec::new();

    for (d_idx, d_rel) in deleted.iter().enumerate() {
        let Some(d_sig) = snap_entries.get(d_rel) else {
            continue;
        };
        let Some(d_len) = extract_sig_len(d_sig) else {
            continue;
        };
        let Some(candidates) = added_buckets.get(&(is_git_path(d_rel), d_len)) else {
            continue;
        };
        let Some(d_content) = rename_content_sig(&snap_root.join(d_rel), d_len, d_sig) else {
            continue;
        };
        let mut best: Option<(u8, usize)> = None;
        for &a_idx in candidates {
            if used_added[a_idx] {
                continue;
            }
            let a_rel = &added[a_idx];
            let a_hint = live_entries.get(a_rel).map(|s| s.as_str()).unwrap_or("");
            let a_content = added_sigs
                .entry(a_idx)
                .or_insert_with(|| rename_content_sig(&live_root.join(a_rel), d_len, a_hint));
            if a_content.as_deref() != Some(d_content.as_str()) {
                continue;
            }
            let prio = match_priority(d_rel, a_rel);
            let better = match best {
                None => true,
                Some((bp, bi)) => prio > bp || (prio == bp && a_rel < &added[bi]),
            };
            if better {
                best = Some((prio, a_idx));
            }
        }
        if let Some((_, win_idx)) = best {
            used_deleted[d_idx] = true;
            used_added[win_idx] = true;
            renamed.push(RenamePair {
                from: d_rel.clone(),
                to: added[win_idx].clone(),
            });
        }
    }

    if !renamed.is_empty() {
        let mut keep_del = Vec::with_capacity(deleted.len() - renamed.len());
        for (i, item) in deleted.drain(..).enumerate() {
            if !used_deleted[i] {
                keep_del.push(item);
            }
        }
        *deleted = keep_del;
        let mut keep_add = Vec::with_capacity(added.len() - renamed.len());
        for (i, item) in added.drain(..).enumerate() {
            if !used_added[i] {
                keep_add.push(item);
            }
        }
        *added = keep_add;
        renamed.sort_by(|a, b| a.from.cmp(&b.from).then_with(|| a.to.cmp(&b.to)));
    }
    renamed
}
