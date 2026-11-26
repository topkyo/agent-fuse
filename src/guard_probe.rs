use crate::apfs::{fsgetpath, MAX_WALK_DEPTH};
use crate::unicode_norm::{components_equal_casefold_nfd, path_starts_with_casefold_nfd};
use crate::vault::is_ignored_name;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

fn is_real_dir_non_symlink(p: &Path) -> bool {
    fs::symlink_metadata(p)
        .map(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
        .unwrap_or(false)
}

fn collect_git_critical_paths(git_dir: &Path, out: &mut Vec<PathBuf>) {
    out.push(git_dir.to_path_buf());
    if !is_real_dir_non_symlink(git_dir) {
        return;
    }
    for sub in ["HEAD", "config", "index", "packed-refs"] {
        let p = git_dir.join(sub);
        if fs::symlink_metadata(&p).is_ok() {
            out.push(p);
        }
    }
    fn walk_sub(cur: &Path, depth: usize, out: &mut Vec<PathBuf>) {
        if depth >= MAX_WALK_DEPTH || !is_real_dir_non_symlink(cur) {
            return;
        }
        let Ok(rd) = fs::read_dir(cur) else { return };
        for entry in rd.flatten() {
            let p = entry.path();
            out.push(p.clone());
            if is_real_dir_non_symlink(&p) {
                walk_sub(&p, depth + 1, out);
            }
        }
    }
    for sub_dir in ["refs", "logs", "hooks", "info"] {
        let d = git_dir.join(sub_dir);
        if fs::symlink_metadata(&d).is_ok() {
            out.push(d.clone());
            if is_real_dir_non_symlink(&d) {
                walk_sub(&d, 1, out);
            }
        }
    }
    let objects_dir = git_dir.join("objects");
    if fs::symlink_metadata(&objects_dir).is_ok() {
        out.push(objects_dir.clone());
        if is_real_dir_non_symlink(&objects_dir) {
            if let Ok(rd) = fs::read_dir(&objects_dir) {
                for entry in rd.flatten() {
                    let p = entry.path();
                    out.push(p.clone());
                    if entry.file_name() == "pack" && is_real_dir_non_symlink(&p) {
                        walk_sub(&p, 2, out);
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BaselineTrack {
    pub(crate) ws_canon: PathBuf,
    pub(crate) fsid: (i32, i32),
    pub(crate) is_single_file: bool,
    pub(crate) paths: Vec<(PathBuf, u64)>,
    pub(crate) nonempty_files: Vec<PathBuf>,
    pub(crate) nonempty_inos: HashSet<u64>,
    pub(crate) baseline_file_lens: HashMap<u64, u64>,
}

pub(crate) fn moved_into_ignored_or_git(ws_canon: &Path, canon_cur: &Path) -> bool {
    let mut cur_iter = canon_cur.components();
    for pre_comp in ws_canon.components() {
        let Some(c_comp) = cur_iter.next() else {
            return true;
        };
        if !components_equal_casefold_nfd(
            Path::new(pre_comp.as_os_str()),
            Path::new(c_comp.as_os_str()),
        ) {
            return true;
        }
    }
    cur_iter.any(|c| {
        let lower = c.as_os_str().to_string_lossy().to_ascii_lowercase();
        lower == ".git" || is_ignored_name(&lower)
    })
}

pub(crate) fn collect_baseline_track(ws: &Path, fsid: (i32, i32)) -> BaselineTrack {
    let ws_canon = fs::canonicalize(ws).unwrap_or_else(|_| ws.to_path_buf());
    if ws.is_file() {
        let mut nonempty_files = Vec::new();
        let mut nonempty_inos = HashSet::new();
        let mut baseline_file_lens = HashMap::new();
        let mut ino = 0u64;
        if let Ok(m) = fs::symlink_metadata(ws) {
            ino = m.ino();
            if m.file_type().is_file() {
                baseline_file_lens.insert(ino, m.len());
                if m.len() > 0 {
                    nonempty_files.push(ws.to_path_buf());
                    nonempty_inos.insert(ino);
                }
            }
        }
        return BaselineTrack {
            ws_canon,
            fsid,
            is_single_file: true,
            paths: vec![(ws.to_path_buf(), ino)],
            nonempty_files,
            nonempty_inos,
            baseline_file_lens,
        };
    }
    let mut track = BaselineTrack {
        ws_canon,
        fsid,
        is_single_file: false,
        paths: Vec::new(),
        nonempty_files: Vec::new(),
        nonempty_inos: HashSet::new(),
        baseline_file_lens: HashMap::new(),
    };
    fn record_all_lens(cur: &Path, depth: usize, lens: &mut HashMap<u64, u64>) {
        if depth >= MAX_WALK_DEPTH {
            return;
        }
        let Ok(rd) = fs::read_dir(cur) else { return };
        for entry in rd.flatten() {
            let p = entry.path();
            if let Ok(m) = fs::symlink_metadata(&p) {
                if m.file_type().is_dir() && !m.file_type().is_symlink() {
                    record_all_lens(&p, depth + 1, lens);
                } else if m.file_type().is_file() {
                    lens.insert(m.ino(), m.len());
                }
            }
        }
    }
    fn walk(cur: &Path, depth: usize, out: &mut BaselineTrack) {
        if depth >= MAX_WALK_DEPTH {
            return;
        }
        let Ok(rd) = fs::read_dir(cur) else { return };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_ignored_name(&name) {
                continue;
            }
            let p = entry.path();
            if name == ".git" {
                let mut git_paths = Vec::new();
                collect_git_critical_paths(&p, &mut git_paths);
                for gp in git_paths {
                    if let Ok(gm) = fs::symlink_metadata(&gp) {
                        out.paths.push((gp.clone(), gm.ino()));
                        if gm.file_type().is_file() && gm.len() > 0 {
                            out.nonempty_files.push(gp);
                            out.nonempty_inos.insert(gm.ino());
                        }
                    }
                }
                continue;
            }
            if let Ok(m) = fs::symlink_metadata(&p) {
                out.paths.push((p.clone(), m.ino()));
                if m.file_type().is_dir() && !m.file_type().is_symlink() {
                    walk(&p, depth + 1, out);
                } else if m.file_type().is_file() && m.len() > 0 {
                    out.nonempty_files.push(p);
                    out.nonempty_inos.insert(m.ino());
                }
            }
        }
    }
    walk(ws, 0, &mut track);
    record_all_lens(ws, 0, &mut track.baseline_file_lens);
    track
}

pub(crate) fn collect_workspace_written_bytes(
    ws: &Path,
    is_single: bool,
    baseline_file_lens: &HashMap<u64, u64>,
) -> u64 {
    if is_single {
        return fs::symlink_metadata(ws)
            .map(|m| {
                if m.file_type().is_file() {
                    let base = baseline_file_lens.get(&m.ino()).copied().unwrap_or(0);
                    m.len().saturating_sub(base)
                } else {
                    0
                }
            })
            .unwrap_or(0);
    }
    fn walk_delta(
        cur: &Path,
        depth: usize,
        base_lens: &HashMap<u64, u64>,
        seen_inos: &mut HashSet<u64>,
        total: &mut u64,
    ) {
        if depth >= MAX_WALK_DEPTH {
            return;
        }
        let Ok(rd) = fs::read_dir(cur) else { return };
        for entry in rd.flatten() {
            let p = entry.path();
            if let Ok(m) = fs::symlink_metadata(&p) {
                if m.file_type().is_dir() && !m.file_type().is_symlink() {
                    walk_delta(&p, depth + 1, base_lens, seen_inos, total);
                } else if m.file_type().is_file() && seen_inos.insert(m.ino()) {
                    let base = base_lens.get(&m.ino()).copied().unwrap_or(0);
                    *total = total.saturating_add(m.len().saturating_sub(base));
                }
            }
        }
    }
    let mut seen_inos = HashSet::new();
    let mut total = 0u64;
    walk_delta(ws, 0, baseline_file_lens, &mut seen_inos, &mut total);
    total
}

pub(crate) fn check_destruction_threshold(
    track: &BaselineTrack,
    threshold: usize,
) -> Option<(usize, usize)> {
    if track.is_single_file {
        if let Some((p, _)) = track.paths.first() {
            let intact = fs::symlink_metadata(p)
                .map(|m| !m.file_type().is_symlink() && m.file_type().is_file())
                .unwrap_or(false);
            if !intact {
                return Some((1, 0));
            }
        }
    }
    let mut missing = 0usize;
    let mut truncated = 0usize;
    for (p, ino) in &track.paths {
        if fs::symlink_metadata(p).is_err() {
            let was_in_git = p
                .strip_prefix(&track.ws_canon)
                .map(|rel| {
                    rel.components()
                        .any(|c| c.as_os_str().to_string_lossy().eq_ignore_ascii_case(".git"))
                })
                .unwrap_or(false);
            if !track.is_single_file && *ino > 0 {
                if let Ok(cur_p) = fsgetpath(track.fsid, *ino) {
                    let canon_cur = cur_p
                        .parent()
                        .and_then(|d| fs::canonicalize(d).ok())
                        .and_then(|cd| cur_p.file_name().map(|n| cd.join(n)))
                        .unwrap_or(cur_p);
                    if path_starts_with_casefold_nfd(&canon_cur, &track.ws_canon)
                        && (was_in_git || !moved_into_ignored_or_git(&track.ws_canon, &canon_cur))
                    {
                        if track.nonempty_inos.contains(ino) {
                            if let Ok(cm) = fs::symlink_metadata(&canon_cur) {
                                if cm.file_type().is_file() && cm.len() == 0 {
                                    truncated += 1;
                                    if missing + truncated >= threshold {
                                        return Some((missing, truncated));
                                    }
                                }
                            }
                        }
                        continue;
                    }
                }
            }
            missing += 1;
            if missing + truncated >= threshold {
                return Some((missing, truncated));
            }
        }
    }
    for p in &track.nonempty_files {
        if let Ok(m) = fs::symlink_metadata(p) {
            if m.file_type().is_file() && m.len() == 0 {
                truncated += 1;
                if missing + truncated >= threshold {
                    return Some((missing, truncated));
                }
            }
        }
    }
    None
}
