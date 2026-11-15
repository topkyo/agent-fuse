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

#[derive(Debug, Clone)]
pub struct ValidatedWorkspace {
    pub canonical_path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub marker: String,
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
        AfuseError::new(
            e.raw_os_error().unwrap_or(ERR_EACCES),
            format!("cannot create vault base directory: errno={}", e.raw_os_error().unwrap_or(ERR_EACCES)),
        )
    })?;
    let _ = fs::set_permissions(&base_root, fs::Permissions::from_mode(0o700));
    Ok(base_root.join("vault.noindex"))
}

pub(crate) const PROJECT_MARKERS: &[&str] = &[
    ".git",
    "Cargo.toml",
    "Package.swift",
    "package.json",
    "pyproject.toml",
    "go.mod",
    "Makefile",
];

pub fn reject_forbidden_workspace_paths(ws: &Path) -> Result<PathBuf, AfuseError> {
    let real_home = real_home_dir()?;
    let env_home = env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .map(|p| fs::canonicalize(&p).unwrap_or(p));

    let forbidden_exact: &[&str] = &[
        "/",
        "/Users",
        "/Volumes",
        "/System",
        "/Library",
        "/Applications",
        "/bin",
        "/sbin",
        "/usr",
        "/var",
        "/private",
        "/private/var",
        "/private/tmp",
        "/tmp",
        "/etc",
        "/dev",
        "/cores",
    ];
    for exact in forbidden_exact {
        if ws == Path::new(exact) {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "binding system/root directory is forbidden",
            ));
        }
    }
    if ws == real_home || env_home.as_deref() == Some(ws) {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "binding user HOME directory is forbidden",
        ));
    }

    let forbidden_subtrees = [
        PathBuf::from("/System"),
        PathBuf::from("/Library"),
        PathBuf::from("/Applications"),
        real_home.join(".agent-fuse"),
        real_home.join("Desktop"),
        real_home.join("Documents"),
        real_home.join("Downloads"),
        real_home.join("Library"),
    ];
    for sub in &forbidden_subtrees {
        let canon_sub = fs::canonicalize(sub).unwrap_or_else(|_| sub.clone());
        if ws == canon_sub || ws.starts_with(&canon_sub) {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "binding protected/TCC subtree is forbidden",
            ));
        }
    }
    Ok(real_home)
}

pub fn check_workspace_path_rules(
    candidate: &Path,
) -> Result<(PathBuf, fs::Metadata, String), AfuseError> {
    let ws = fs::canonicalize(candidate).map_err(|e| {
        AfuseError::new(
            e.raw_os_error().unwrap_or(ERR_ENOENT),
            "workspace path does not exist or is inaccessible",
        )
    })?;
    let meta = fs::metadata(&ws).map_err(|e| {
        AfuseError::new(
            e.raw_os_error().unwrap_or(ERR_ENOENT),
            "cannot stat workspace path",
        )
    })?;
    if !meta.is_dir() {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "workspace must be a directory",
        ));
    }

    let _real_home = reject_forbidden_workspace_paths(&ws)?;

    let mut found_marker: Option<String> = None;
    for &m in PROJECT_MARKERS {
        if fs::symlink_metadata(ws.join(m)).is_ok() {
            found_marker = Some(m.to_string());
            break;
        }
    }
    let marker = found_marker.ok_or_else(|| {
        AfuseError::new(
            ERR_EINVAL,
            "workspace directory has no project root marker (.git, Cargo.toml, Package.swift, package.json, pyproject.toml, go.mod, Makefile)",
        )
    })?;
    Ok((ws, meta, marker))
}

pub fn validate_workspace_binding_with_vault(
    candidate: &Path,
    vault_override: Option<&Path>,
) -> Result<ValidatedWorkspace, AfuseError> {
    let (ws, meta, marker) = check_workspace_path_rules(candidate)?;
    let (_, _ws_vault) = prepare_live_workspace_vault_with(&ws, vault_override)?;

    Ok(ValidatedWorkspace {
        canonical_path: ws,
        dev: meta.dev(),
        ino: meta.ino(),
        marker,
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

pub fn prepare_live_workspace_vault_with(
    workspace: &Path,
    vault_override: Option<&Path>,
) -> Result<(PathBuf, PathBuf), AfuseError> {
    let ws = fs::canonicalize(workspace).map_err(|e| {
        AfuseError::new(e.raw_os_error().unwrap_or(ERR_ENOENT), "workspace path does not exist or is inaccessible")
    })?;
    if !ws.is_dir() {
        return Err(AfuseError::new(ERR_EINVAL, "workspace is not a directory"));
    }
    workspace_vault_common(&ws, &ws, vault_override, true)
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
    if let Ok(ws) = fs::canonicalize(workspace) {
        if !ws.is_dir() {
            return Err(AfuseError::new(ERR_EINVAL, "workspace is not a directory"));
        }
        return workspace_vault_common(&ws, &ws, vault_override, false);
    }
    if fs::symlink_metadata(workspace).is_ok() && !workspace.is_dir() {
        return Err(AfuseError::new(ERR_EINVAL, "workspace is not a directory"));
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
