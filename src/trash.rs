use crate::apfs::{can_write_path, force_remove_all, fsgetpath, lstat_inode_mode, real_home_dir, statfs_info};
use crate::error::{ERR_EACCES, ERR_EPERM};
use crate::manifest::SnapshotMeta;
use crate::snapshot::list_snapshots_unlocked;
use crate::vault::{is_ignored_name, TargetKind};
use std::collections::{BTreeSet, VecDeque};
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const MAX_TRACKED_INODES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrashCleanupStatus {
    NotInTrash,
    Purged,
    TccDenied,
}

impl TrashCleanupStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TrashCleanupStatus::NotInTrash => "not_in_trash",
            TrashCleanupStatus::Purged => "purged",
            TrashCleanupStatus::TccDenied => "tcc_denied",
        }
    }
}

pub(crate) fn collect_target_inodes(ws: &Path, kind: TargetKind) -> Vec<u64> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    if let Ok((ino, _)) = lstat_inode_mode(ws) {
        if ino > 0 && seen.insert(ino) {
            out.push(ino);
        }
    }
    if kind == TargetKind::SingleFile {
        return out;
    }
    let mut q = VecDeque::new();
    q.push_back(ws.to_path_buf());
    while let Some(dir) = q.pop_front() {
        if out.len() >= MAX_TRACKED_INODES {
            break;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            if out.len() >= MAX_TRACKED_INODES {
                break;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_ignored_name(&name) {
                continue;
            }
            let p = entry.path();
            let Ok(meta) = fs::symlink_metadata(&p) else { continue };
            let ino = meta.ino();
            if ino > 0 && seen.insert(ino) {
                out.push(ino);
            }
            if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
                q.push_back(p);
            }
        }
    }
    out
}

fn write_inode_file(path: &Path, inodes: &[u64]) {
    let mut buf = String::with_capacity(inodes.len() * 14);
    for &ino in inodes {
        buf.push_str(&format!("{}\n", ino));
    }
    let _ = fs::write(path, buf);
}

fn read_inode_file(path: &Path, out: &mut Vec<u64>, seen: &mut BTreeSet<u64>) {
    let Ok(raw) = fs::read_to_string(path) else { return };
    for line in raw.lines() {
        if let Ok(ino) = line.trim().parse::<u64>() {
            if ino > 0 && seen.insert(ino) {
                out.push(ino);
            }
        }
    }
}

pub(crate) fn record_snapshot_inodes(ws: &Path, kind: TargetKind, snap_dir: &Path, ws_vault: &Path) {
    let inodes = collect_target_inodes(ws, kind);
    write_inode_file(&snap_dir.join("inodes.txt"), &inodes);
    write_inode_file(&ws_vault.join("latest_inodes.txt"), &inodes);
}

pub(crate) fn refresh_latest_inodes(ws: &Path, kind: TargetKind, ws_vault: &Path) {
    let inodes = collect_target_inodes(ws, kind);
    write_inode_file(&ws_vault.join("latest_inodes.txt"), &inodes);
}

pub fn allowed_trash_roots() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut push_if_ok = |p: PathBuf| {
        if let Ok(c) = fs::canonicalize(&p) {
            if !out.contains(&c) {
                out.push(c);
            }
        } else if p.exists() && !out.contains(&p) {
            out.push(p);
        }
    };
    if let Ok(custom) = env::var("AFUSE_TRASH_DIR") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            push_if_ok(PathBuf::from(trimmed));
        }
    }
    if let Ok(home) = real_home_dir() {
        push_if_ok(home.join(".Trash"));
    }
    out
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

pub(crate) fn purge_trashed_counterparts(
    restored_ws: &Path,
    kind: TargetKind,
    ws_vault: &Path,
    snap_dir: &Path,
    target_meta: &SnapshotMeta,
    fsid: (i32, i32),
) -> TrashCleanupStatus {
    let live_inodes: BTreeSet<u64> = collect_target_inodes(restored_ws, kind).into_iter().collect();
    let trash_roots = allowed_trash_roots();
    if trash_roots.is_empty() {
        refresh_latest_inodes(restored_ws, kind, ws_vault);
        return TrashCleanupStatus::NotInTrash;
    }

    let mut seen = BTreeSet::new();
    let mut cands = Vec::new();
    if target_meta.root_inode > 0 && seen.insert(target_meta.root_inode) {
        cands.push(target_meta.root_inode);
    }
    if let Ok(all) = list_snapshots_unlocked(ws_vault) {
        for m in all {
            if m.root_inode > 0 && seen.insert(m.root_inode) {
                cands.push(m.root_inode);
            }
        }
    }
    read_inode_file(&ws_vault.join("latest_inodes.txt"), &mut cands, &mut seen);
    read_inode_file(&snap_dir.join("inodes.txt"), &mut cands, &mut seen);

    let canon_ws = fs::canonicalize(restored_ws).unwrap_or_else(|_| restored_ws.to_path_buf());
    let mut purged_any = false;
    let mut saw_tcc_denied = false;

    for cand_ino in cands {
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
        // Gate 1: Must not overlap or match the restored target path
        if cand_path == canon_ws || cand_path.starts_with(&canon_ws) || canon_ws.starts_with(&cand_path) {
            continue;
        }
        // Gate 2: Must strictly reside inside an allowed Trash directory
        let Some(matched_trash) = trash_roots.iter().find(|t| cand_path.starts_with(t) && &cand_path != *t) else {
            continue;
        };
        // Gate 3: Strict lstat inode + fsid match (zero filename heuristics)
        let Ok((actual_ino, _)) = lstat_inode_mode(&cand_path) else { continue };
        if actual_ino != cand_ino {
            continue;
        }
        let same_vol = statfs_info(cand_path.parent().unwrap_or(&cand_path))
            .map(|s| s.fsid == fsid)
            .unwrap_or(false);
        if !same_vol {
            continue;
        }
        // Gate 4: Safe deletion with TCC degradation on EPERM / EACCES
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

    refresh_latest_inodes(restored_ws, kind, ws_vault);
    if saw_tcc_denied {
        TrashCleanupStatus::TccDenied
    } else if purged_any {
        TrashCleanupStatus::Purged
    } else {
        TrashCleanupStatus::NotInTrash
    }
}
