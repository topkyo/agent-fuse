use crate::apfs::real_home_dir;
use crate::error::{AfuseError, ERR_EINVAL};
use crate::meta::read_meta;
use crate::vault::TargetKind;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

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
        PathBuf::from("/Volumes"),
        PathBuf::from("/tmp"),
        PathBuf::from("/private/tmp"),
        PathBuf::from("/var"),
        PathBuf::from("/private/var"),
        real_home.clone(),
        real_home.join("Desktop"),
        real_home.join("Documents"),
        real_home.join("Downloads"),
    ];
    if env_home.as_deref() == Some(ws)
        || forbidden_exact
            .iter()
            .any(|ex| ws == ex || ws == &resolve_norm_or_canon(ex))
    {
        return Err(AfuseError::new(
            ERR_EINVAL,
            "binding system root, HOME, or top-level Desktop/Documents/Downloads folder itself is forbidden",
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
        real_home.join(".agent-fuse"),
        real_home.join(".Trash"),
        real_home.join("Library"),
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
        if ws == sub || ws.starts_with(sub) || ws == &canon_sub || ws.starts_with(&canon_sub) {
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
        if ws == &v_canon || ws.starts_with(&v_canon) || v_canon.starts_with(ws) {
            return Err(AfuseError::new(
                ERR_EINVAL,
                "self-ingestion forbidden: vault and target must not overlap",
            ));
        }
    }
    Ok(real_home)
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
