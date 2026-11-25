use crate::apfs::{
    acquire_flock_blocking, acquire_flock_nonblocking, chmod_nofollow, real_home_dir,
    release_flock, statfs_info,
};
use crate::error::{AfuseError, ERR_EACCES, ERR_EINVAL, ERR_ENOENT, ERR_ENOTSUP, ERR_EXDEV};
use crate::sha256::sha256_hex;
use crate::unicode_norm::{path_eq_casefold_nfd, path_starts_with_casefold_nfd};
pub use crate::vault_policy::reject_forbidden_workspace_paths;
use crate::vault_policy::{
    enforce_target_leaf_and_access, enforce_vault_target_kind, lexical_normalize_path,
};
use std::env;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(crate) const VAULT_ROOT_MARKER: &str = ".afuse-vault-root";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Directory,
    SingleFile,
}

impl TargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetKind::Directory => "dir",
            TargetKind::SingleFile => "file",
        }
    }

    pub fn parse_str(s: &str) -> Self {
        if s.trim().eq_ignore_ascii_case("file") {
            TargetKind::SingleFile
        } else {
            TargetKind::Directory
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedWorkspace {
    pub canonical_path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub marker: String,
    pub kind: TargetKind,
}

pub(crate) struct VaultLock {
    fd: i32,
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        release_flock(self.fd);
    }
}
pub fn is_ignored_name(name: &str) -> bool {
    matches!(
        name,
        "node_modules" | "target" | ".build" | ".venv" | "DerivedData" | ".DS_Store"
    ) || name.starts_with(".afuse.tmp.")
}

pub fn resolve_vault_base() -> Result<PathBuf, AfuseError> {
    if let Ok(custom) = env::var("AFUSE_VAULT_DIR") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    let home = real_home_dir()?;
    let base_root = home.join(".agent-fuse");
    fs::create_dir_all(&base_root).map_err(|e| {
        AfuseError::new(e.raw_os_error().unwrap_or(ERR_EACCES), format!("cannot create vault base dir: errno={}", e.raw_os_error().unwrap_or(ERR_EACCES)))
    })?;
    let _ = chmod_nofollow(&base_root, 0o700);
    Ok(base_root.join("vault.noindex"))
}

pub(crate) const PROJECT_MARKERS: &[&str] = &[
    ".git", "Cargo.toml", "Package.swift", "package.json", "pyproject.toml", "go.mod", "Makefile",
];

fn strip_trailing_slashes(candidate: &Path) -> PathBuf {
    let raw = candidate.as_os_str().as_bytes();
    let trimmed = if raw.len() > 1 {
        let mut end = raw.len();
        while end > 1 && raw[end - 1] == b'/' {
            end -= 1;
        }
        &raw[..end]
    } else {
        raw
    };
    PathBuf::from(std::ffi::OsStr::from_bytes(trimmed))
}

fn verify_leaf_regular_or_dir(candidate: &Path) -> Result<(PathBuf, fs::Metadata), AfuseError> {
    let trimmed = strip_trailing_slashes(candidate);
    let sym = fs::symlink_metadata(&trimmed).map_err(|e| {
        AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), "target path does not exist or is inaccessible")
    })?;
    let ft = sym.file_type();
    if ft.is_symlink() {
        return Err(AfuseError::new(ERR_EINVAL, "binding symbolic links directly is forbidden"));
    }
    if !ft.is_dir() && !ft.is_file() {
        return Err(AfuseError::new(ERR_EINVAL, "target must be a regular directory or regular file"));
    }
    Ok((trimmed, sym))
}

fn resolve_live_target(candidate: &Path) -> Result<(PathBuf, fs::Metadata, TargetKind), AfuseError> {
    let (trimmed, _) = verify_leaf_regular_or_dir(candidate)?;
    let ws = fs::canonicalize(&trimmed).map_err(|e| {
        AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), "target path does not exist or is inaccessible")
    })?;
    let meta = fs::symlink_metadata(&ws)
        .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), "cannot stat target path"))?;
    let ft = meta.file_type();
    if !ft.is_dir() && !ft.is_file() {
        return Err(AfuseError::new(ERR_EINVAL, "target must be a regular directory or regular file"));
    }
    let _real_home = reject_forbidden_workspace_paths(&ws)?;
    let kind = if ft.is_file() { TargetKind::SingleFile } else { TargetKind::Directory };
    enforce_target_leaf_and_access(&ws, &meta, kind)?;
    Ok((ws, meta, kind))
}

pub fn check_workspace_path_rules(
    candidate: &Path,
) -> Result<(PathBuf, fs::Metadata, String, TargetKind), AfuseError> {
    let (ws, meta, kind) = resolve_live_target(candidate)?;
    if kind == TargetKind::SingleFile {
        return Ok((ws, meta, "file".to_string(), TargetKind::SingleFile));
    }
    let marker = PROJECT_MARKERS
        .iter()
        .find(|&&m| fs::symlink_metadata(ws.join(m)).is_ok())
        .map(|&m| m.to_string())
        .unwrap_or_else(|| "dir".to_string());
    Ok((ws, meta, marker, TargetKind::Directory))
}

pub fn validate_workspace_binding_with_vault(
    candidate: &Path,
    vault_override: Option<&Path>,
) -> Result<ValidatedWorkspace, AfuseError> {
    let (ws, meta, marker, kind) = check_workspace_path_rules(candidate)?;
    let (_, _ws_vault) = workspace_vault_common(&ws, stat_dir_for(&ws), vault_override, false)?;
    Ok(ValidatedWorkspace {
        canonical_path: ws,
        dev: meta.dev(),
        ino: meta.ino(),
        marker,
        kind,
    })
}

pub fn validate_workspace_binding(candidate: &Path) -> Result<ValidatedWorkspace, AfuseError> {
    validate_workspace_binding_with_vault(candidate, None)
}

fn resolve_via_existing_ancestor(path: &Path) -> Result<(PathBuf, PathBuf), AfuseError> {
    let mut cur = lexical_normalize_path(path)?;
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    while !cur.exists() {
        let Some(name) = cur.file_name().map(|n| n.to_os_string()) else {
            break;
        };
        tail.push(name);
        if !cur.pop() {
            break;
        }
    }
    let anc_canon = fs::canonicalize(&cur).map_err(|e| {
        AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), "workspace ancestor path is inaccessible")
    })?;
    let mut stat_dir = anc_canon.clone();
    while !stat_dir.is_dir() && stat_dir.pop() {}
    let mut full = anc_canon;
    for part in tail.into_iter().rev() {
        full.push(part);
    }
    Ok((full, stat_dir))
}

fn resolve_vault_paths(vault_override: Option<&Path>, create: bool) -> Result<(PathBuf, PathBuf), AfuseError> {
    let base = match vault_override {
        Some(v) => v.to_path_buf(),
        None if create => resolve_vault_base()?,
        None => match env::var("AFUSE_VAULT_DIR").ok().filter(|s| !s.trim().is_empty()) {
            Some(c) => PathBuf::from(c.trim()),
            None => real_home_dir()?.join(".agent-fuse").join("vault.noindex"),
        },
    };
    if !create {
        return resolve_via_existing_ancestor(&base);
    }
    fs::create_dir_all(&base)
        .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(ERR_EACCES), "cannot create vault directory"))?;
    let _ = chmod_nofollow(&base, 0o700);
    let canon = fs::canonicalize(&base)
        .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), "cannot resolve vault directory"))?;
    let marker = canon.join(VAULT_ROOT_MARKER);
    if fs::symlink_metadata(&marker).is_err() {
        let _ = fs::write(&marker, b"agent-fuse-vault-v1\n");
        let _ = chmod_nofollow(&marker, 0o600);
    }
    Ok((canon.clone(), canon))
}

fn workspace_vault_common(
    ws: &Path,
    ws_stat_dir: &Path,
    vault_override: Option<&Path>,
    create_if_missing: bool,
) -> Result<(PathBuf, PathBuf), AfuseError> {
    reject_forbidden_workspace_paths(ws)?;
    let (vault_canon, vault_stat_dir) = resolve_vault_paths(vault_override, create_if_missing)?;
    if path_eq_casefold_nfd(&vault_canon, ws)
        || path_starts_with_casefold_nfd(&vault_canon, ws)
        || path_starts_with_casefold_nfd(ws, &vault_canon)
    {
        return Err(AfuseError::new(ERR_EINVAL, "self-ingestion forbidden: vault and workspace must not overlap"));
    }

    let ws_fs = statfs_info(ws_stat_dir)?;
    let vault_fs = statfs_info(&vault_stat_dir)?;
    if ws_fs.fstype.to_lowercase() != "apfs" {
        return Err(AfuseError::new(ERR_ENOTSUP, format!("workspace filesystem is '{}'; agent-fuse requires macOS APFS", ws_fs.fstype)));
    }
    if ws_fs.fsid != vault_fs.fsid {
        return Err(AfuseError::new(
            ERR_EXDEV,
            format!("cross-volume vault rejected (EXDEV): workspace fsid={:?} vs vault fsid={:?}; both must reside on the same APFS volume", ws_fs.fsid, vault_fs.fsid),
        ));
    }

    let ws_hash = &sha256_hex(ws.as_os_str().as_bytes())[..16];
    let ws_name: String = ws
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("root")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let ws_vault = vault_canon.join(format!("{}-{}", ws_name, ws_hash));
    if create_if_missing {
        let snaps_dir = ws_vault.join("snapshots");
        fs::create_dir_all(&snaps_dir).map_err(|e| {
            AfuseError::new(e.raw_os_error().unwrap_or(ERR_EACCES), format!("cannot create snapshots dir: {}", e))
        })?;
        let _ = chmod_nofollow(&ws_vault, 0o700);
        let _ = chmod_nofollow(&snaps_dir, 0o700);
    }
    Ok((ws.to_path_buf(), ws_vault))
}

fn stat_dir_for(ws: &Path) -> &Path {
    if ws.is_dir() {
        ws
    } else {
        ws.parent().unwrap_or(Path::new("/"))
    }
}

pub fn prepare_live_workspace_vault_with(
    workspace: &Path,
    vault_override: Option<&Path>,
) -> Result<(PathBuf, PathBuf), AfuseError> {
    let (ws, _meta, live_kind) = resolve_live_target(workspace)?;
    let (resolved_ws, ws_vault) = workspace_vault_common(&ws, stat_dir_for(&ws), vault_override, true)?;
    enforce_vault_target_kind(&ws_vault, live_kind)?;
    Ok((resolved_ws, ws_vault))
}

pub fn prepare_workspace_vault_with(
    workspace: &Path,
    vault_override: Option<&Path>,
) -> Result<(PathBuf, PathBuf), AfuseError> {
    prepare_live_workspace_vault_with(workspace, vault_override)
}

fn resolve_parent_keep_leaf(trimmed: &Path) -> Result<(PathBuf, PathBuf), AfuseError> {
    let norm = lexical_normalize_path(trimmed)?;
    let Some(name) = norm.file_name().map(|n| n.to_os_string()) else {
        return Err(AfuseError::new(ERR_EINVAL, "target path has no leaf component"));
    };
    let parent = norm.parent().unwrap_or(Path::new("/"));
    let canon_parent = fs::canonicalize(parent).map_err(|e| {
        AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), "workspace ancestor path is inaccessible")
    })?;
    Ok((canon_parent.join(name), canon_parent))
}

pub fn resolve_workspace_vault_recovery(
    workspace: &Path,
    vault_override: Option<&Path>,
) -> Result<(PathBuf, PathBuf), AfuseError> {
    let trimmed = strip_trailing_slashes(workspace);
    if let Ok(sym) = fs::symlink_metadata(&trimmed) {
        let ft = sym.file_type();
        if !ft.is_symlink() && (ft.is_dir() || ft.is_file()) {
            let ws = fs::canonicalize(&trimmed).map_err(|e| {
                AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), "target path does not exist or is inaccessible")
            })?;
            return workspace_vault_common(&ws, stat_dir_for(&ws), vault_override, false);
        }
        let (ws, stat_dir) = resolve_parent_keep_leaf(&trimmed)?;
        return workspace_vault_common(&ws, &stat_dir, vault_override, false);
    }
    let (ws, stat_dir) = resolve_via_existing_ancestor(workspace)?;
    workspace_vault_common(&ws, &stat_dir, vault_override, false)
}

pub fn prepare_workspace_vault(workspace: &Path) -> Result<(PathBuf, PathBuf), AfuseError> {
    prepare_workspace_vault_with(workspace, None)
}

pub(crate) fn lock_vault(ws_vault: &Path) -> Result<VaultLock, AfuseError> {
    let fd = acquire_flock_blocking(&ws_vault.join("vault.lock"))
        .map_err(|rc| AfuseError::new(rc, format!("failed to acquire exclusive lock: errno={}", rc)))?;
    Ok(VaultLock { fd })
}

pub(crate) fn try_lock_vault(ws_vault: &Path) -> Result<VaultLock, AfuseError> {
    let fd = acquire_flock_nonblocking(&ws_vault.join("vault.lock"))
        .map_err(|rc| AfuseError::new(rc, format!("vault lock busy: errno={}", rc)))?;
    Ok(VaultLock { fd })
}
