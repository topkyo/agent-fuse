//! `agent-fuse` (`afuse`) — Zero-dependency APFS CoW snapshot & circuit-breaker engine.
//!
//! Architecture overview (< 400 LOC per module, 0 external crates, 0 background network calls):
//! - `sha256`: Pure Rust FIPS 180-4 SHA-256 implementation.
//! - `error`: Unified errno-backed error type (`AfuseError`) & fuse exit code.
//! - `apfs`: Exclusive `unsafe` C-shim boundary (`darwin_shim.c`: `clonefile(2)`,
//!   `renamex_np(2) RENAME_SWAP`, `statfs64(2)`, `flock(2)`, `fork`/`execvp` in pgroup).
//! - `vault`: Workspace boundary & project-marker validation (`$HOME`/root refusal,
//!   same-APFS-volume verification, exclusive vault locking).
//! - `manifest`: Filtered tree cloning, fast tree stats, Merkle SHA-256 & `meta.kv`.
//! - `snapshot` / `restore`: Atomic root-Inode-preserving snapshot, diff & selective restore.
//! - `prune`: Orphan staging cleanup and retention-policy pruning.
//! - `hook_config` / `hook`: Opt-in zsh preexec & Claude Code PreToolUse auto-snap.
//! - `guard`: Isolated process-group fuse tripping on runaway deletes or write spikes.
//! - `doctor`: Privacy-safe offline APFS & vault health diagnostics.
//! - `upgrade_json` / `upgrade`: Opt-in manual release check & SHA-256 verified self-upgrade.

pub mod apfs;
pub mod doctor;
pub mod error;
pub mod guard;
pub mod hook;
pub mod hook_config;
pub mod hook_json;
pub mod manifest;
pub mod prune;
pub mod restore;
pub mod restore_tree;
pub mod sha256;
pub mod snapshot;
pub mod trash;
pub mod unicode_norm;
pub mod upgrade;
pub mod upgrade_json;
pub mod vault;

pub use apfs::{
    clonefile_nofollow, force_remove_all, fsgetpath, lstat_inode_mode, real_home_dir, short_hash,
    statfs_info, StatFsInfo,
};
pub use doctor::{format_doctor_json, run_doctor, run_doctor_with_vault, DoctorReport};
pub use error::{
    AfuseError, ERR_EACCES, ERR_EEXIST, ERR_EINVAL, ERR_ENOENT, ERR_ENOTSUP, ERR_EPERM,
    ERR_USAGE, ERR_EWOULDBLOCK, ERR_EXDEV, EXIT_FUSE_TRIPPED,
};
pub use guard::{run_guarded_command, run_guarded_command_with_vault, GuardConfig, GuardReport};
pub use hook::{
    execute_hook_auto_snap, find_git_project_root, find_project_root, is_readonly_bash_command,
    parse_claude_hook_json, run_claude_hook_exec_from_reader, run_claude_hook_exec_stdio,
    run_zsh_hook_exec, ClaudeHookPayload,
};
pub use hook_config::{render_hook_snippet, uninstall_hooks, UninstallAction};
pub use manifest::{
    compute_single_file_manifest, compute_tree_manifest, compute_tree_stats_fast, json_escape,
    sanitize_terminal_text, SnapshotMeta,
};
pub use prune::{
    parse_prune_args, prune_snapshots, prune_snapshots_filtered,
    prune_snapshots_filtered_with_vault, prune_snapshots_with_vault,
};
pub use restore::{
    restore_snapshot, restore_snapshot_paths, restore_snapshot_paths_with_vault,
    restore_snapshot_with_vault, RestoreReport,
};
pub use snapshot::{
    create_snapshot, create_snapshot_fast, create_snapshot_if_changed,
    create_snapshot_if_changed_with_vault, create_snapshot_opts_with_vault,
    create_snapshot_with_vault, diff_snapshot, diff_snapshot_with_vault, list_snapshots,
    list_snapshots_with_vault, DiffReport,
};
pub use trash::{allowed_trash_roots, TrashCleanupStatus};
pub use upgrade::{
    check_for_updates, is_newer_version, parse_release_json, perform_upgrade_on_exe,
    run_upgrade_apply, validate_release_asset_url, ReleaseAsset, ReleaseInfo, UpgradeApplyReport,
    UpgradeCheckReport,
};
pub use vault::{
    is_ignored_name, prepare_live_workspace_vault_with, prepare_workspace_vault,
    prepare_workspace_vault_with, reject_forbidden_workspace_paths, resolve_vault_base,
    resolve_workspace_vault_recovery, validate_workspace_binding,
    validate_workspace_binding_with_vault, TargetKind, ValidatedWorkspace,
};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_invariants;
#[cfg(test)]
mod tests_phase2;
#[cfg(test)]
mod tests_trash_targets;
