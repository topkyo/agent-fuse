use crate::apfs::{chmod_nofollow, fsgetpath, lstat_inode_mode};
use crate::error::ERR_ENOENT;
use crate::manifest::SnapshotMeta;
use crate::snapshot::list_snapshots_unlocked;
use crate::unicode_norm::canonical_rel_key;
use crate::vault::{is_ignored_name, TargetKind};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(crate) const KNOWN_INODES_FILE: &str = "known_inodes.tsv";
const MAX_TRACKED_INODES: usize = 100_000;
const LEDGER_GC_LIMIT: usize = 8192;

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

pub(crate) fn path_matches_target(canon_rel: &str, target: &str) -> bool {
    canon_rel == target
        || (canon_rel.len() > target.len()
            && canon_rel.starts_with(target)
            && canon_rel.as_bytes()[target.len()] == b'/')
}

pub(crate) fn collect_live_path_inodes(ws: &Path, kind: TargetKind) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    if let Ok((root_ino, _)) = lstat_inode_mode(ws) {
        if root_ino > 0 && seen.insert(root_ino) {
            out.push((root_ino, ".".to_string()));
        }
    }
    if kind == TargetKind::SingleFile {
        return out;
    }
    let mut q = VecDeque::new();
    q.push_back(ws.to_path_buf());
    while let Some(dir) = q.pop_front() {
        if out.len() >= MAX_TRACKED_INODES { break; }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            if out.len() >= MAX_TRACKED_INODES { break; }
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_ignored_name(&name) { continue; }
            let p = entry.path();
            let Ok(meta) = fs::symlink_metadata(&p) else { continue };
            let ino = meta.ino();
            if ino > 0 && seen.insert(ino) {
                if let Ok(rel) = p.strip_prefix(ws) {
                    let trimmed = canonical_rel_key(&rel.to_string_lossy()).trim_matches('/').to_string();
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

fn read_tsv_map_fill(path: &Path, ledger: &mut BTreeMap<u64, String>, overwrite: bool) {
    let Ok(raw) = fs::read_to_string(path) else { return };
    for line in raw.lines() {
        let Some((ino_s, esc_rel)) = line.split_once('\t') else { continue };
        let Ok(ino) = ino_s.trim().parse::<u64>() else { continue };
        if ino == 0 { continue; }
        let rel = unescape_tsv_path(esc_rel);
        let norm = if rel == "." {
            ".".to_string()
        } else {
            let t = rel.trim_matches('/').to_string();
            if t.is_empty() { continue; }
            t
        };
        if overwrite {
            ledger.insert(ino, norm);
        } else {
            ledger.entry(ino).or_insert(norm);
        }
    }
}

fn read_plain_inodes(path: &Path, out: &mut Vec<u64>, seen: &mut BTreeSet<u64>) {
    let Ok(raw) = fs::read_to_string(path) else { return };
    for line in raw.lines() {
        if let Ok(ino) = line.trim().parse::<u64>() {
            if ino > 0 && seen.insert(ino) {
                out.push(ino);
            }
        }
    }
}

pub(crate) fn load_ledger(ws_vault: &Path) -> BTreeMap<u64, String> {
    let mut ledger = BTreeMap::new();
    read_tsv_map_fill(&ws_vault.join(KNOWN_INODES_FILE), &mut ledger, true);
    read_tsv_map_fill(&ws_vault.join("latest_inode_map.tsv"), &mut ledger, false);
    if let Ok(raw) = fs::read_to_string(ws_vault.join("retained_inodes.txt")) {
        for line in raw.lines() {
            if let Ok(ino) = line.trim().parse::<u64>() {
                if ino > 0 {
                    ledger.entry(ino).or_insert_with(|| ".".to_string());
                }
            }
        }
    }
    ledger
}

fn serialize_tsv_entries<'a>(entries: impl Iterator<Item = (u64, &'a str)>) -> String {
    let mut buf = String::new();
    for (ino, rel) in entries {
        buf.push_str(&format!("{}\t{}\n", ino, escape_tsv_path(rel)));
    }
    buf
}

fn cleanup_legacy_inode_files(ws_vault: &Path) {
    for legacy in ["retained_inodes.txt", "latest_inodes.txt", "latest_inode_map.tsv"] {
        let _ = fs::remove_file(ws_vault.join(legacy));
    }
}

fn write_ledger_atomic(ws_vault: &Path, ledger: &BTreeMap<u64, String>) {
    let dst = ws_vault.join(KNOWN_INODES_FILE);
    let tmp = ws_vault.join(format!("{}.tmp.{}", KNOWN_INODES_FILE, std::process::id()));
    let body = serialize_tsv_entries(ledger.iter().map(|(&ino, rel)| (ino, rel.as_str())));
    let wrote = if fs::write(&tmp, &body).is_ok()
        && chmod_nofollow(&tmp, 0o600).is_ok()
        && fs::rename(&tmp, &dst).is_ok()
    {
        true
    } else {
        let _ = fs::remove_file(&tmp);
        let ok = fs::write(&dst, body).is_ok();
        if ok {
            let _ = chmod_nofollow(&dst, 0o600);
        }
        ok
    };
    if wrote {
        cleanup_legacy_inode_files(ws_vault);
    }
}

pub(crate) fn merge_live_entries_into_ledger(ws_vault: &Path, live_entries: &[(u64, String)]) {
    let mut ledger = load_ledger(ws_vault);
    for (ino, rel) in live_entries {
        if *ino > 0 {
            ledger.insert(*ino, rel.clone());
        }
    }
    write_ledger_atomic(ws_vault, &ledger);
}

pub(crate) fn record_snapshot_inodes(ws: &Path, kind: TargetKind, snap_dir: &Path, ws_vault: &Path) {
    let live = collect_live_path_inodes(ws, kind);
    let snap_body = serialize_tsv_entries(live.iter().map(|(ino, rel)| (*ino, rel.as_str())));
    let map_path = snap_dir.join("inode_map.tsv");
    if fs::write(&map_path, snap_body).is_ok() {
        let _ = chmod_nofollow(&map_path, 0o600);
    }
    merge_live_entries_into_ledger(ws_vault, &live);
}

pub(crate) fn record_live_target_inode_if_new(ws: &Path, kind: TargetKind, ws_vault: &Path) {
    let live = collect_live_path_inodes(ws, kind);
    if !live.is_empty() {
        merge_live_entries_into_ledger(ws_vault, &live);
    }
}

pub(crate) fn retire_and_gc_ledger(
    ws_vault: &Path,
    live_entries: &[(u64, String)],
    purged_inos: &BTreeSet<u64>,
    fsid: (i32, i32),
) {
    let mut ledger = load_ledger(ws_vault);
    let mut live_set = BTreeSet::new();
    for (ino, rel) in live_entries {
        if *ino > 0 {
            live_set.insert(*ino);
            ledger.insert(*ino, rel.clone());
        }
    }
    for &ino in purged_inos {
        if !live_set.contains(&ino) {
            ledger.remove(&ino);
        }
    }
    if ledger.len() > LEDGER_GC_LIMIT {
        let stale: Vec<u64> = ledger
            .keys()
            .copied()
            .filter(|ino| !live_set.contains(ino))
            .filter(|&ino| matches!(fsgetpath(fsid, ino), Err(e) if e.code == ERR_ENOENT))
            .collect();
        for ino in stale {
            ledger.remove(&ino);
        }
    }
    write_ledger_atomic(ws_vault, &ledger);
}

pub(crate) fn load_root_inodes(ws_vault: &Path) -> Vec<u64> {
    load_ledger(ws_vault)
        .into_iter()
        .filter_map(|(ino, rel)| (rel == ".").then_some(ino))
        .collect()
}

pub(crate) fn collect_selective_candidates(ws_vault: &Path, snap_dir: &Path, targets: &[String]) -> Vec<u64> {
    let mut auth = load_ledger(ws_vault);
    read_tsv_map_fill(&snap_dir.join("inode_map.tsv"), &mut auth, false);
    auth.into_iter()
        .filter_map(|(ino, rel)| {
            (rel != "." && targets.iter().any(|t| path_matches_target(&rel, t))).then_some(ino)
        })
        .collect()
}

pub(crate) fn collect_all_candidates(
    ws_vault: &Path,
    snap_dir: &Path,
    target_meta: &SnapshotMeta,
) -> (Vec<u64>, BTreeSet<u64>) {
    let mut seen = BTreeSet::new();
    let mut cands = Vec::new();
    let mut root_cands = BTreeSet::new();
    let mut push_root = |ino: u64| {
        if ino > 0 {
            root_cands.insert(ino);
            if seen.insert(ino) { cands.push(ino); }
        }
    };
    push_root(target_meta.root_inode);
    if let Ok(all) = list_snapshots_unlocked(ws_vault) {
        for m in all { push_root(m.root_inode); }
    }
    let mut auth = load_ledger(ws_vault);
    read_tsv_map_fill(&snap_dir.join("inode_map.tsv"), &mut auth, false);
    for (&ino, rel) in &auth {
        if rel == "." { push_root(ino); }
    }
    for (&ino, rel) in &auth {
        if rel != "." && ino > 0 && seen.insert(ino) { cands.push(ino); }
    }
    read_plain_inodes(&ws_vault.join("latest_inodes.txt"), &mut cands, &mut seen);
    read_plain_inodes(&snap_dir.join("inodes.txt"), &mut cands, &mut seen);
    (cands, root_cands)
}
