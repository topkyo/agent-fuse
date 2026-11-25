use crate::apfs::{can_read_write, current_euid, real_home_dir};
use crate::error::{AfuseError, ERR_EACCES, ERR_EINVAL, ERR_ENOENT};
use crate::meta::read_meta;
use crate::unicode_norm::{path_eq_casefold_nfd, path_starts_with_casefold_nfd};
use crate::vault::{is_ignored_name, TargetKind};
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

fn path_eq_icase(a: &Path, b: &Path) -> bool {
    path_eq_casefold_nfd(a, b)
}

fn path_starts_with_icase(ws: &Path, sub: &Path) -> bool {
    path_starts_with_casefold_nfd(ws, sub)
}

pub(crate) fn lexical_normalize_path(path: &Path) -> Result<PathBuf, AfuseError> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(1), e.to_string()))?
            .join(path)
    };
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    for comp in abs.components() {
        match comp {
            std::path::Component::ParentDir => {
                parts.pop();
            }
            std::path::Component::Normal(s) => parts.push(s.to_os_string()),
            _ => {}
        }
    }
    let mut out = PathBuf::from("/");
    for part in parts {
        out.push(part);
    }
    Ok(out)
}

pub(crate) fn resolve_norm_or_canon(p: &Path) -> PathBuf {
    fs::canonicalize(p)
        .unwrap_or_else(|_| lexical_normalize_path(p).unwrap_or_else(|_| p.to_path_buf()))
}

pub fn reject_forbidden_workspace_paths(ws: &Path) -> Result<PathBuf, AfuseError> {
    let real_home = real_home_dir()?;
    let env_home = env::var("HOME")
        .ok()
        .map(|s| resolve_norm_or_canon(Path::new(&s)));
    let forbidden_exact = [
        PathBuf::from("/"),
        PathBuf::from("/Users"),
        PathBuf::from("/Users/Shared"),
        PathBuf::from("/Volumes"),
        PathBuf::from("/tmp"),
        PathBuf::from("/private"),
        PathBuf::from("/private/tmp"),
        PathBuf::from("/var"),
        PathBuf::from("/private/var"),
        PathBuf::from("/opt"),
        real_home.clone(),
        real_home.join("Desktop"),
        real_home.join("Documents"),
        real_home.join("Downloads"),
        real_home.join("Pictures"),
        real_home.join("Movies"),
        real_home.join("Music"),
        real_home.join("Public"),
    ];
    if env_home.as_deref().map(|h| path_eq_icase(ws, h)).unwrap_or(false)
        || forbidden_exact
            .iter()
            .any(|ex| path_eq_icase(ws, ex) || path_eq_icase(ws, &resolve_norm_or_canon(ex)))
    {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "binding system root, HOME, or protected user/top-level folder itself is forbidden",
        ));
    }
    let forbidden_subtrees = vec![
        PathBuf::from("/System"),
        PathBuf::from("/Library"),
        PathBuf::from("/Applications"),
        PathBuf::from("/bin"),
        PathBuf::from("/sbin"),
        PathBuf::from("/usr"),
        PathBuf::from("/dev"),
        PathBuf::from("/etc"),
        PathBuf::from("/private/etc"),
        PathBuf::from("/cores"),
        PathBuf::from("/private/var/db"),
        PathBuf::from("/private/var/log"),
        PathBuf::from("/private/var/root"),
        PathBuf::from("/private/var/vm"),
        PathBuf::from("/private/var/run"),
        PathBuf::from("/private/var/spool"),
        PathBuf::from("/private/var/audit"),
        real_home.join(".agent-fuse"),
        real_home.join(".Trash"),
        real_home.join("Library"),
        real_home.join("Applications"),
        real_home.join(".ssh"),
        real_home.join(".gnupg"),
        real_home.join(".aws"),
        real_home.join(".kube"),
    ];
    let env_paths: Vec<PathBuf> = ["AFUSE_TRASH_DIR"]
        .iter()
        .filter_map(|k| {
            env::var(k)
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(|s| PathBuf::from(s.trim()))
        })
        .collect();
    for sub in forbidden_subtrees.iter().chain(env_paths.iter()) {
        let canon_sub = resolve_norm_or_canon(sub);
        if path_starts_with_icase(ws, sub) || path_starts_with_icase(ws, &canon_sub) {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "binding protected/system/trash subtree is forbidden",
            ));
        }
    }
    if let Some(v_canon) = env::var("AFUSE_VAULT_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| resolve_norm_or_canon(Path::new(s.trim())))
    {
        if path_starts_with_icase(ws, &v_canon) || path_starts_with_icase(&v_canon, ws) {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "self-ingestion forbidden: vault and target must not overlap",
            ));
        }
    }
    Ok(real_home)
}

pub(crate) fn check_owner_rw_gate(path: &Path, uid: u32, euid: u32) -> Result<(), AfuseError> {
    if !can_read_write(path) && uid != euid {
        return Err(AfuseError::new(
            ERR_EACCES,
            format!("insufficient permissions on '{}' (not owner or missing rw access)", path.display()),
        ));
    }
    Ok(())
}

pub(crate) fn enforce_target_leaf_and_access(
    ws: &Path,
    meta: &fs::Metadata,
    kind: TargetKind,
) -> Result<(), AfuseError> {
    if let Some(name) = ws.file_name().and_then(|n| n.to_str()) {
        let is_cargo_target = name == "target"
            && ws
                .parent()
                .map(|p| fs::symlink_metadata(p.join("Cargo.toml")).is_ok())
                .unwrap_or(false);
        if name.eq_ignore_ascii_case(".git") || (is_ignored_name(name) && (name != "target" || is_cargo_target)) {
            return Err(AfuseError::new(
                ERR_EINVAL,
                format!("binding protected or ignored leaf '{}' is forbidden", name),
            ));
        }
    }
    let euid = current_euid();
    check_owner_rw_gate(ws, meta.uid(), euid)?;
    if kind == TargetKind::SingleFile {
        if let Some(parent) = ws.parent() {
            if let Ok(pm) = fs::symlink_metadata(parent) {
                check_owner_rw_gate(parent, pm.uid(), euid)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn enforce_vault_target_kind(
    ws_vault: &Path,
    live_kind: TargetKind,
) -> Result<(), AfuseError> {
    let snaps_dir = ws_vault.join("snapshots");
    let Ok(rd) = fs::read_dir(&snaps_dir) else {
        return Ok(());
    };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for dir in entries.into_iter().rev() {
        let meta_p = dir.join("meta.kv");
        if meta_p.is_file() && dir.join("tree").is_dir() {
            if let Ok(m) = read_meta(&meta_p) {
                if m.target_kind != live_kind {
                    return Err(AfuseError::new(
                        ERR_EINVAL,
                        format!(
                            "target kind mismatch: vault is bound as '{}' while target path is '{}'",
                            m.target_kind.as_str(),
                            live_kind.as_str()
                        ),
                    ));
                }
                return Ok(());
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct VerifiedLiveTarget {
    path: PathBuf,
    kind: TargetKind,
    dev: u64,
    ino: u64,
}

impl VerifiedLiveTarget {
    pub(crate) fn open_matching(ws: &Path, expected_kind: TargetKind) -> Result<Self, AfuseError> {
        let meta = fs::symlink_metadata(ws).map_err(|e| {
            AfuseError::new(
                e.raw_os_error().unwrap_or(ERR_ENOENT),
                format!("live target missing at '{}'", ws.display()),
            )
        })?;
        if meta.file_type().is_symlink() {
            return Err(AfuseError::new(ERR_EINVAL, "live target must not be a symbolic link"));
        }
        let live_kind = if meta.file_type().is_dir() {
            TargetKind::Directory
        } else if meta.file_type().is_file() {
            TargetKind::SingleFile
        } else {
            return Err(AfuseError::new(ERR_EINVAL, "live target must be a regular file or directory"));
        };
        if live_kind != expected_kind {
            return Err(AfuseError::new(
                ERR_EINVAL,
                format!(
                    "target kind mismatch: expected '{}' while live path is '{}'",
                    expected_kind.as_str(),
                    live_kind.as_str()
                ),
            ));
        }
        Ok(Self { path: ws.to_path_buf(), kind: live_kind, dev: meta.dev(), ino: meta.ino() })
    }

    pub(crate) fn path(&self) -> &Path { &self.path }
    pub(crate) fn kind(&self) -> TargetKind { self.kind }
    #[allow(dead_code)]
    pub(crate) fn dev(&self) -> u64 { self.dev }
    #[allow(dead_code)]
    pub(crate) fn ino(&self) -> u64 { self.ino }
}
