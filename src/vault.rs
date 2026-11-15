use crate::apfs::{
    acquire_flock_blocking, acquire_flock_nonblocking, real_home_dir, release_flock, statfs_info,
};
use crate::error::{AfuseError, ERR_EACCES, ERR_EINVAL, ERR_ENOENT, ERR_ENOTSUP, ERR_EXDEV};
use crate::sha256::sha256_hex;
use std::env;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

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
    let _ = fs::set_permissions(&base_root, fs::Permissions::from_mode(0o700));
    Ok(base_root.join("vault.noindex"))
}

pub(crate) const PROJECT_MARKERS: &[&str] = &[
    ".git", "Cargo.toml", "Package.swift", "package.json", "pyproject.toml", "go.mod", "Makefile",
];

fn resolve_norm_or_canon(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| lexical_normalize_path(p).unwrap_or_else(|_| p.to_path_buf()))
}

pub fn reject_forbidden_workspace_paths(ws: &Path) -> Result<PathBuf, AfuseError> {
    let real_home = real_home_dir()?;
    let env_home = env::var("HOME").ok().map(|s| resolve_norm_or_canon(Path::new(&s)));
    let forbidden_exact = [
        PathBuf::from("/"), PathBuf::from("/Users"), PathBuf::from("/Volumes"),
        PathBuf::from("/tmp"), PathBuf::from("/private/tmp"),
        PathBuf::from("/var"), PathBuf::from("/private/var"),
        real_home.clone(), real_home.join("Desktop"), real_home.join("Documents"), real_home.join("Downloads"),
    ];
    if env_home.as_deref() == Some(ws)
        || forbidden_exact.iter().any(|ex| ws == ex || ws == &resolve_norm_or_canon(ex))
    {
        return Err(AfuseError::new(ERR_EINVAL, "binding system root, HOME, or top-level Desktop/Documents/Downloads folder itself is forbidden"));
    }
    let mut forbidden_subtrees = vec![
        PathBuf::from("/System"), PathBuf::from("/Library"), PathBuf::from("/Applications"),
        PathBuf::from("/bin"), PathBuf::from("/sbin"), PathBuf::from("/usr"),
        PathBuf::from("/dev"), PathBuf::from("/etc"), PathBuf::from("/private/etc"), PathBuf::from("/cores"),
        real_home.join(".agent-fuse"), real_home.join(".Trash"), real_home.join("Library"),
    ];
    if let Ok(tdir) = env::var("AFUSE_TRASH_DIR") {
        if !tdir.trim().is_empty() {
            forbidden_subtrees.push(PathBuf::from(tdir.trim()));
        }
    }
    for sub in &forbidden_subtrees {
        let canon_sub = resolve_norm_or_canon(sub);
        if ws == sub || ws.starts_with(sub) || ws == &canon_sub || ws.starts_with(&canon_sub) {
            return Err(AfuseError::new(ERR_EINVAL, "binding protected/system/trash subtree is forbidden"));
        }
    }
    if let Ok(vdir) = env::var("AFUSE_VAULT_DIR") {
        if !vdir.trim().is_empty() {
            let v_canon = resolve_norm_or_canon(Path::new(vdir.trim()));
            if ws == &v_canon || ws.starts_with(&v_canon) || v_canon.starts_with(ws) {
                return Err(AfuseError::new(ERR_EINVAL, "self-ingestion forbidden: vault and target must not overlap"));
            }
        }
    }
    Ok(real_home)
}

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

pub fn check_workspace_path_rules(
    candidate: &Path,
) -> Result<(PathBuf, fs::Metadata, String, TargetKind), AfuseError> {
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
    if ft.is_file() {
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
    let (_, _ws_vault) = prepare_live_workspace_vault_with(&ws, vault_override)?;
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

fn lexical_normalize_path(path: &Path) -> Result<PathBuf, AfuseError> {
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
    let _ = fs::set_permissions(&base, fs::Permissions::from_mode(0o700));
    let canon = fs::canonicalize(&base)
        .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), "cannot resolve vault directory"))?;
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
    if vault_canon == ws || vault_canon.starts_with(ws) || ws.starts_with(&vault_canon) {
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
        fs::create_dir_all(ws_vault.join("snapshots")).map_err(|e| {
            AfuseError::new(e.raw_os_error().unwrap_or(ERR_EACCES), format!("cannot create snapshots dir: {}", e))
        })?;
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
    let (trimmed, _) = verify_leaf_regular_or_dir(workspace)?;
    let ws = fs::canonicalize(&trimmed).map_err(|e| {
        AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), "target path does not exist or is inaccessible")
    })?;
    let ft = fs::symlink_metadata(&ws)
        .map_err(|e| AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), "cannot stat target path"))?
        .file_type();
    if !ft.is_dir() && !ft.is_file() {
        return Err(AfuseError::new(ERR_EINVAL, "target must be a regular directory or regular file"));
    }
    workspace_vault_common(&ws, stat_dir_for(&ws), vault_override, true)
}

pub fn prepare_workspace_vault_with(
    workspace: &Path,
    vault_override: Option<&Path>,
) -> Result<(PathBuf, PathBuf), AfuseError> {
    prepare_live_workspace_vault_with(workspace, vault_override)
}

pub fn resolve_workspace_vault_recovery(
    workspace: &Path,
    vault_override: Option<&Path>,
) -> Result<(PathBuf, PathBuf), AfuseError> {
    let trimmed = strip_trailing_slashes(workspace);
    if fs::symlink_metadata(&trimmed).is_ok() {
        let (_, _) = verify_leaf_regular_or_dir(&trimmed)?;
        let ws = fs::canonicalize(&trimmed).map_err(|e| {
            AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), "target path does not exist or is inaccessible")
        })?;
        return workspace_vault_common(&ws, stat_dir_for(&ws), vault_override, false);
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
