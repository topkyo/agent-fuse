use crate::apfs::{
    can_write_path, current_euid, force_remove_all, fsgetpath, lstat_inode_mode, real_home_dir,
    statfs_info,
};
use crate::error::{AfuseError, ERR_EACCES, ERR_EPERM};
use crate::manifest::SnapshotMeta;
use crate::snapshot::list_snapshots_unlocked;
use crate::vault::{is_ignored_name, lock_vault, resolve_workspace_vault_recovery, TargetKind};
use crate::vault_policy::VerifiedLiveTarget;
use std::collections::{BTreeSet, VecDeque};
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const MAX_TRACKED_INODES: usize = 100_000;
const MAX_RETAINED_ROOT_INODES: usize = 16;

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

fn update_retained_root_inodes(
    ws_vault: &Path,
    prepend: &[u64],
    remove: &BTreeSet<u64>,
) -> Vec<u64> {
    let mut existing = Vec::new();
    let mut seen = BTreeSet::new();
    for &ino in prepend {
        if ino > 0 && !remove.contains(&ino) && seen.insert(ino) {
            existing.push(ino);
        }
    }
    let path = ws_vault.join("retained_inodes.txt");
    if let Ok(raw) = fs::read_to_string(&path) {
        for line in raw.lines() {
            if let Ok(ino) = line.trim().parse::<u64>() {
                if ino > 0 && !remove.contains(&ino) && seen.insert(ino) {
                    existing.push(ino);
                }
            }
        }
    }
    existing.truncate(MAX_RETAINED_ROOT_INODES);
    write_inode_file(&path, &existing);
    existing
}

fn write_latest_with_retained(ws: &Path, kind: TargetKind, ws_vault: &Path, retained: &[u64]) -> Vec<u64> {
    let mut inodes = collect_target_inodes(ws, kind);
    let mut seen: BTreeSet<u64> = inodes.iter().copied().collect();
    for &ino in retained {
        if ino > 0 && seen.insert(ino) {
            inodes.push(ino);
        }
    }
    write_inode_file(&ws_vault.join("latest_inodes.txt"), &inodes);
    inodes
}

pub(crate) fn record_snapshot_inodes(ws: &Path, kind: TargetKind, snap_dir: &Path, ws_vault: &Path) {
    let inodes = collect_target_inodes(ws, kind);
    write_inode_file(&snap_dir.join("inodes.txt"), &inodes);
    let root_ino = lstat_inode_mode(ws).map(|x| x.0).unwrap_or(0);
    let retained = update_retained_root_inodes(ws_vault, &[root_ino], &BTreeSet::new());
    let mut latest = inodes;
    let mut seen: BTreeSet<u64> = latest.iter().copied().collect();
    for &ino in &retained {
        if ino > 0 && seen.insert(ino) {
            latest.push(ino);
        }
    }
    write_inode_file(&ws_vault.join("latest_inodes.txt"), &latest);
}

pub(crate) fn refresh_latest_inodes(ws: &Path, kind: TargetKind, ws_vault: &Path) {
    let retained = update_retained_root_inodes(ws_vault, &[], &BTreeSet::new());
    let _ = write_latest_with_retained(ws, kind, ws_vault, &retained);
}

pub(crate) fn record_live_target_inode_if_new(ws: &Path, kind: TargetKind, ws_vault: &Path) {
    let Ok((live_ino, _)) = lstat_inode_mode(ws) else { return };
    if live_ino == 0 {
        return;
    }
    let retained = update_retained_root_inodes(ws_vault, &[live_ino], &BTreeSet::new());
    let _ = write_latest_with_retained(ws, kind, ws_vault, &retained);
}

pub(crate) fn allowed_trash_roots_for(
    home: Option<&Path>,
    custom_env: Option<&str>,
    ws: Option<&Path>,
    euid: u32,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut push_if_ok = |p: PathBuf| {
        let resolved = fs::canonicalize(&p).ok().or_else(|| fs::symlink_metadata(&p).ok().map(|_| p));
        if let Some(r) = resolved {
            if !out.contains(&r) {
                out.push(r);
            }
        }
    };
    if let Some(custom) = custom_env.map(str::trim).filter(|s| !s.is_empty()) {
        push_if_ok(PathBuf::from(custom));
    }
    if let Some(h) = home {
        push_if_ok(h.join(".Trash"));
        push_if_ok(h.join("Library/Mobile Documents/com~apple~CloudDocs/.Trash"));
    }
    if let Some(w) = ws {
        let mut comps = w.components();
        if matches!(comps.next(), Some(std::path::Component::RootDir)) {
            if let (Some(c1), Some(c2)) = (comps.next(), comps.next()) {
                if c1.as_os_str() == "Volumes" {
                    push_if_ok(PathBuf::from("/Volumes").join(c2.as_os_str()).join(".Trashes").join(euid.to_string()));
                }
            }
        }
    }
    out
}

pub fn allowed_trash_roots() -> Vec<PathBuf> {
    let home = real_home_dir().ok();
    let custom = env::var("AFUSE_TRASH_DIR").ok();
    allowed_trash_roots_for(home.as_deref(), custom.as_deref(), None, current_euid())
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
    let home = real_home_dir().ok();
    let custom = env::var("AFUSE_TRASH_DIR").ok();
    let trash_roots = allowed_trash_roots_for(home.as_deref(), custom.as_deref(), Some(restored_ws), current_euid());
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
    read_inode_file(&ws_vault.join("retained_inodes.txt"), &mut cands, &mut seen);
    let root_cands: BTreeSet<u64> = cands.iter().copied().collect();
    read_inode_file(&ws_vault.join("latest_inodes.txt"), &mut cands, &mut seen);
    read_inode_file(&snap_dir.join("inodes.txt"), &mut cands, &mut seen);

    let canon_ws = fs::canonicalize(restored_ws).unwrap_or_else(|_| restored_ws.to_path_buf());
    let mut purged_any = false;
    let mut saw_tcc_denied = false;
    let mut purged_inos = BTreeSet::new();
    let mut denied_inos = Vec::new();

    for &cand_ino in &cands {
        if live_inodes.contains(&cand_ino) {
            continue;
        }
        let raw_path = match fsgetpath(fsid, cand_ino) {
            Ok(p) => p,
            Err(e) if e.code == ERR_EPERM || e.code == ERR_EACCES => {
                saw_tcc_denied = true;
                denied_inos.push(cand_ino);
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
        let actual_ino = match lstat_inode_mode(&cand_path) {
            Ok((ino, _)) => ino,
            Err(e) if e.code == ERR_EPERM || e.code == ERR_EACCES => {
                saw_tcc_denied = true;
                denied_inos.push(cand_ino);
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
        // Gate 4: Safe deletion with TCC degradation on EPERM / EACCES
        let parent = cand_path.parent().unwrap_or(&cand_path);
        if let Err(e) = can_write_path(matched_trash).and_then(|_| can_write_path(parent)) {
            if e.code == ERR_EPERM || e.code == ERR_EACCES {
                saw_tcc_denied = true;
                denied_inos.push(cand_ino);
            }
            continue;
        }
        match force_remove_all(&cand_path) {
            Ok(()) => {
                purged_any = true;
                purged_inos.insert(cand_ino);
            }
            Err(e) if e.code == ERR_EPERM || e.code == ERR_EACCES => {
                saw_tcc_denied = true;
                denied_inos.push(cand_ino);
            }
            Err(_) => {}
        }
    }

    let live_root = lstat_inode_mode(restored_ws).map(|x| x.0).unwrap_or(0);
    if !saw_tcc_denied && !purged_any {
        let stale_roots: BTreeSet<u64> = root_cands.iter().copied()
            .filter(|ino| !live_inodes.contains(ino) && !purged_inos.contains(ino))
            .collect();
        if !stale_roots.is_empty() {
            let icloud_trash = home.as_deref()
                .map(|h| h.join("Library/Mobile Documents/com~apple~CloudDocs/.Trash"))
                .and_then(|p| fs::canonicalize(&p).ok());
            let is_icloud_desk_doc = home.as_deref().map(|h| {
                canon_ws.starts_with(h.join("Desktop")) || canon_ws.starts_with(h.join("Documents"))
            }).unwrap_or(false) && icloud_trash.as_ref().map(|p| fs::read_dir(p).is_ok()).unwrap_or(false);
            let local_trash = home.as_deref().and_then(|h| fs::canonicalize(h.join(".Trash")).ok());
            for tr in &trash_roots {
                if is_icloud_desk_doc && local_trash.as_deref() == Some(tr.as_path()) {
                    continue;
                }
                match fs::read_dir(tr) {
                    Err(e) if matches!(e.raw_os_error(), Some(c) if c == ERR_EPERM || c == ERR_EACCES) => {
                        saw_tcc_denied = true;
                        denied_inos.extend(stale_roots.iter().copied());
                        break;
                    }
                    Ok(rd) => {
                        let has_match = rd.flatten().any(|ent| {
                            fs::symlink_metadata(ent.path()).map(|m| stale_roots.contains(&m.ino())).unwrap_or(false)
                        });
                        if has_match && matches!(can_write_path(tr), Err(e) if e.code == ERR_EPERM || e.code == ERR_EACCES) {
                            saw_tcc_denied = true;
                            denied_inos.extend(stale_roots.iter().copied());
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }
    let retained = if saw_tcc_denied {
        let mut keep_roots = Vec::new();
        if live_root > 0 { keep_roots.push(live_root); }
        if target_meta.root_inode > 0 && !purged_inos.contains(&target_meta.root_inode) {
            keep_roots.push(target_meta.root_inode);
        }
        keep_roots.extend(denied_inos.into_iter().filter(|ino| root_cands.contains(ino)));
        update_retained_root_inodes(ws_vault, &keep_roots, &purged_inos)
    } else {
        let clean_roots: Vec<u64> = if live_root > 0 { vec![live_root] } else { Vec::new() };
        write_inode_file(&ws_vault.join("retained_inodes.txt"), &clean_roots);
        clean_roots
    };
    let _ = write_latest_with_retained(restored_ws, kind, ws_vault, &retained);
    if saw_tcc_denied {
        TrashCleanupStatus::TccDenied
    } else if purged_any {
        TrashCleanupStatus::Purged
    } else {
        TrashCleanupStatus::NotInTrash
    }
}

pub fn purge_workspace_trash_with_vault(
    workspace: &Path,
    vault_override: Option<&Path>,
) -> Result<TrashCleanupStatus, AfuseError> {
    let (ws, ws_vault) = resolve_workspace_vault_recovery(workspace, vault_override)?;
    let _guard = lock_vault(&ws_vault)?;
    let snaps = list_snapshots_unlocked(&ws_vault)?;
    let Some(latest) = snaps.first() else {
        return Ok(TrashCleanupStatus::NotInTrash);
    };
    let live = VerifiedLiveTarget::open_matching(&ws, latest.target_kind)?;
    let snap_dir = ws_vault.join("snapshots").join(&latest.id);
    let stat_p = if live.kind() == TargetKind::SingleFile {
        live.path().parent().unwrap_or(live.path())
    } else {
        live.path()
    };
    let fsi = statfs_info(stat_p)?;
    Ok(purge_trashed_counterparts(live.path(), live.kind(), &ws_vault, &snap_dir, latest, fsi.fsid))
}
