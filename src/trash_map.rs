use crate::apfs::{can_write_path, current_euid, force_remove_all, fsgetpath, lstat_inode_mode, real_home_dir, statfs_info};
use crate::error::{ERR_EACCES, ERR_EPERM};
use crate::trash::{allowed_trash_roots_for, collect_target_inodes, TrashCleanupStatus};
use crate::unicode_norm::canonical_rel_key;
use crate::vault::{is_ignored_name, TargetKind};
use std::collections::{BTreeSet, VecDeque};
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const MAX_MAP_ENTRIES: usize = 100_000;

fn escape_tsv_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

fn unescape_tsv_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

pub(crate) fn collect_target_path_inodes(ws: &Path, kind: TargetKind) -> Vec<(u64, String)> {
    if kind != TargetKind::Directory {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut q = VecDeque::new();
    q.push_back(ws.to_path_buf());
    while let Some(dir) = q.pop_front() {
        if out.len() >= MAX_MAP_ENTRIES {
            break;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            if out.len() >= MAX_MAP_ENTRIES {
                break;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_ignored_name(&name) {
                continue;
            }
            let p = entry.path();
            let Ok(meta) = fs::symlink_metadata(&p) else { continue };
            let ino = meta.ino();
            if ino > 0 {
                if let Ok(rel) = p.strip_prefix(ws) {
                    let canon = canonical_rel_key(&rel.to_string_lossy());
                    let trimmed = canon.trim_matches('/').to_string();
                    if !trimmed.is_empty() {
                        out.push((ino, trimmed));
                    }
                }
            }
            if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
                q.push_back(p);
            }
        }
    }
    out
}

fn write_inode_map_file(path: &Path, entries: &[(u64, String)]) {
    let mut buf = String::with_capacity(entries.len() * 32);
    for (ino, rel) in entries {
        buf.push_str(&format!("{}\t{}\n", ino, escape_tsv_path(rel)));
    }
    let _ = fs::write(path, buf);
}

fn path_matches_target(canon_rel: &str, target: &str) -> bool {
    if canon_rel == target {
        return true;
    }
    canon_rel.len() > target.len()
        && canon_rel.starts_with(target)
        && canon_rel.as_bytes()[target.len()] == b'/'
}

fn collect_matching_inodes_from_file(
    map_path: &Path,
    targets: &[String],
    out: &mut Vec<u64>,
    seen: &mut BTreeSet<u64>,
) {
    let Ok(raw) = fs::read_to_string(map_path) else { return };
    for line in raw.lines() {
        let Some((ino_s, esc_rel)) = line.split_once('\t') else { continue };
        let Ok(ino) = ino_s.trim().parse::<u64>() else { continue };
        if ino == 0 {
            continue;
        }
        let rel = unescape_tsv_path(esc_rel);
        let rel_norm = rel.trim_matches('/');
        if !rel_norm.is_empty() && targets.iter().any(|t| path_matches_target(rel_norm, t)) && seen.insert(ino) {
            out.push(ino);
        }
    }
}

fn normalize_parent_keep_leaf(raw: &Path) -> PathBuf {
    let Some(name) = raw.file_name() else {
        return raw.to_path_buf();
    };
    match raw.parent().and_then(|p| fs::canonicalize(p).ok()) {
        Some(canon_parent) => canon_parent.join(name),
        None => raw.to_path_buf(),
    }
}

pub(crate) fn record_snapshot_inode_map(ws: &Path, kind: TargetKind, snap_dir: &Path, ws_vault: &Path) {
    if kind != TargetKind::Directory {
        return;
    }
    let entries = collect_target_path_inodes(ws, kind);
    write_inode_map_file(&snap_dir.join("inode_map.tsv"), &entries);
    write_inode_map_file(&ws_vault.join("latest_inode_map.tsv"), &entries);
}

pub(crate) fn purge_trashed_selective_paths(
    restored_ws: &Path,
    ws_vault: &Path,
    snap_dir: &Path,
    clean_paths: &[PathBuf],
    fsid: (i32, i32),
) -> TrashCleanupStatus {
    let targets: Vec<String> = clean_paths
        .iter()
        .map(|p| canonical_rel_key(&p.to_string_lossy()).trim_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if targets.is_empty() {
        return TrashCleanupStatus::NotInTrash;
    }

    let mut seen = BTreeSet::new();
    let mut cands = Vec::new();
    collect_matching_inodes_from_file(&snap_dir.join("inode_map.tsv"), &targets, &mut cands, &mut seen);
    collect_matching_inodes_from_file(&ws_vault.join("latest_inode_map.tsv"), &targets, &mut cands, &mut seen);
    if cands.is_empty() {
        return TrashCleanupStatus::NotInTrash;
    }

    let home = real_home_dir().ok();
    let custom = env::var("AFUSE_TRASH_DIR").ok();
    let trash_roots = allowed_trash_roots_for(home.as_deref(), custom.as_deref(), Some(restored_ws), current_euid());
    if trash_roots.is_empty() {
        return TrashCleanupStatus::NotInTrash;
    }

    let mut live_inodes: BTreeSet<u64> = collect_target_inodes(restored_ws, TargetKind::Directory).into_iter().collect();
    if let Ok((root_ino, _)) = lstat_inode_mode(restored_ws) {
        if root_ino > 0 {
            live_inodes.insert(root_ino);
        }
    }

    let canon_ws = fs::canonicalize(restored_ws).unwrap_or_else(|_| restored_ws.to_path_buf());
    let mut purged_any = false;
    let mut saw_tcc_denied = false;

    for &cand_ino in &cands {
        if live_inodes.contains(&cand_ino) {
            continue;
        }
        let raw_path = match fsgetpath(fsid, cand_ino) {
            Ok(p) => p,
            Err(e) if e.code == ERR_EPERM || e.code == ERR_EACCES => {
                saw_tcc_denied = true;
                continue;
            }
            Err(_) => continue,
        };
        let cand_path = normalize_parent_keep_leaf(&raw_path);
        if cand_path == canon_ws || cand_path.starts_with(&canon_ws) || canon_ws.starts_with(&cand_path) {
            continue;
        }
        let Some(matched_trash) = trash_roots.iter().find(|t| cand_path.starts_with(t) && &cand_path != *t) else {
            continue;
        };
        let actual_ino = match lstat_inode_mode(&cand_path) {
            Ok((ino, _)) => ino,
            Err(e) if e.code == ERR_EPERM || e.code == ERR_EACCES => {
                saw_tcc_denied = true;
                continue;
            }
            Err(_) => continue,
        };
        if actual_ino != cand_ino {
            continue;
        }
        let same_vol = statfs_info(cand_path.parent().unwrap_or(&cand_path))
            .map(|s| s.fsid == fsid)
            .unwrap_or(false);
        if !same_vol {
            continue;
        }
        let parent = cand_path.parent().unwrap_or(&cand_path);
        if let Err(e) = can_write_path(matched_trash).and_then(|_| can_write_path(parent)) {
            if e.code == ERR_EPERM || e.code == ERR_EACCES {
                saw_tcc_denied = true;
            }
            continue;
        }
        match force_remove_all(&cand_path) {
            Ok(()) => purged_any = true,
            Err(e) if e.code == ERR_EPERM || e.code == ERR_EACCES => saw_tcc_denied = true,
            Err(_) => {}
        }
    }

    let refreshed = collect_target_path_inodes(restored_ws, TargetKind::Directory);
    write_inode_map_file(&ws_vault.join("latest_inode_map.tsv"), &refreshed);
    if saw_tcc_denied {
        TrashCleanupStatus::TccDenied
    } else if purged_any {
        TrashCleanupStatus::Purged
    } else {
        TrashCleanupStatus::NotInTrash
    }
}
