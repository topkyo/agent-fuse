//! `agent-fuse` (`afuse`) — Zero-dependency APFS CoW snapshot & circuit-breaker engine.
//!
//! Architecture overview (< 400 LOC per module, 0 external crates, 0 background network calls):
//! - `error`: Unified errno-backed error type (`AfuseError`) & fuse exit code.
//! - `sha256`: Pure Rust FIPS 180-4 SHA-256 implementation.
//! - `unicode_norm`: Pure Rust Unicode NFD decomposition & CCC ordering for APFS path parity.
//! - `apfs`: Exclusive `unsafe` C-shim boundary (`darwin_shim.c`: `clonefile(2)`,
//!   `renamex_np(2) RENAME_SWAP`, `statfs64(2)`, `flock(2)`, `fsgetpath`, `fork`/`execvp` in pgroup).
//! - `vault` / `vault_policy`: Arbitrary plain folder (`.git` optional) & single-file (`TargetKind`)
//!   guardian with physical system/container-root blacklist, same-APFS check & exclusive vault flock.
//! - `fs_guard`: Temporary readonly permission unlocker & single-file sibling isolation guards.
//! - `meta`: `SnapshotMeta`, `SnapshotOrigin` key-value serializer, compound summaries & sanitizer.
//! - `manifest`: Filtered tree cloning, fast tree stats, Merkle SHA-256 & `meta.kv` persistence.
//! - `snapshot` / `diff` / `diff_rename` / `rolling`: Atomic snapshot creation, fast dedup, NFD-safe diffing, first-class `RenamePair` detection & append-only rolling baseline.
//! - `restore` / `restore_tree` / `restore_fast`: Atomic root-Inode-preserving full/selective restore, append-only head progression & ignored-subtree stash.
//! - `trash` / `trash_ledger`: Monotonic `known_inodes.tsv` ledger & Darwin `fsgetpath` exact `(fsid, ino)` Trash cleanup with TCC fallback.
//! - `relocate`: Same-volume `fsgetpath` target locate, atomic `O(1)` vault relocation & orphan vault GC.
//! - `prune`: Orphan staging cleanup, `auto:*` rolling quota GC & label-filtered pruning.
//! - `hook_json` / `hook_config` / `hook`: Opt-in zsh preexec & Claude Code PreToolUse auto-snap.
//! - `guard`: Isolated process-group fuse tripping on runaway deletes, renames or truncation spikes.
//! - `doctor`: Privacy-safe offline APFS & vault health diagnostics.
//! - `upgrade_json` / `upgrade_verify` / `upgrade`: Opt-in release check & SHA-256 verified self-upgrade.
//! - `cli_cmds` / `cli_ops` / `cli_upgrade`: CLI subcommand dispatch & structured `--json` formatting.

pub mod apfs;
pub mod diff;
pub mod diff_rename;
pub mod doctor;
pub mod error;
pub(crate) mod fs_guard;
pub mod guard;
pub mod hook;
pub mod hook_config;
pub mod hook_json;
pub mod manifest;
mod meta;
pub mod prune;
pub mod relocate;
pub mod restore;
pub(crate) mod restore_fast;
pub mod restore_tree;
pub mod rolling;
pub mod sha256;
pub mod snapshot;
pub mod trash;
pub(crate) mod trash_ledger;
pub mod unicode_norm;
pub mod upgrade;
pub mod upgrade_json;
pub(crate) mod upgrade_verify;
pub mod vault;
mod vault_policy;

pub use apfs::{
    clonefile_nofollow, force_remove_all, fsgetpath, lstat_inode_mode, real_home_dir, short_hash,
    statfs_info, StatFsInfo,
};
pub use doctor::{
    format_doctor_json, run_doctor, run_doctor_with_opts, run_doctor_with_vault, DoctorReport,
};
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
    sanitize_terminal_text, SnapshotMeta, SnapshotOrigin,
};
pub use meta::PIN_CONTAINS_DELETED;
pub use prune::{
    parse_prune_args, prune_snapshots, prune_snapshots_filtered,
    prune_snapshots_filtered_with_vault, prune_snapshots_with_vault,
};
pub use relocate::{
    inspect_vault_orphans, locate_workspace_target_with_vault, prune_orphan_vaults_with,
    relocate_workspace_vault_with, LocateOutcome, OrphanPruneReport, RelocateReport,
};
pub use restore::{
    restore_snapshot, restore_snapshot_fast, restore_snapshot_opts_with_vault,
    restore_snapshot_paths, restore_snapshot_paths_with_vault, restore_snapshot_with_vault,
    RestoreReport,
};
pub use diff::{diff_snapshot, diff_snapshot_fast, diff_snapshot_opts_with_vault, diff_snapshot_with_vault, DiffReport};
pub use diff_rename::RenamePair;
pub use rolling::{
    create_snapshot_rolling, create_snapshot_rolling_with_vault, RollingSnapReport,
    PRE_DELETE_LABEL,
};
pub use snapshot::{
    create_snapshot, create_snapshot_fast, create_snapshot_fast_dedup,
    create_snapshot_fast_dedup_with_vault, create_snapshot_if_changed,
    create_snapshot_if_changed_with_vault, create_snapshot_opts_with_vault,
    create_snapshot_with_vault, list_snapshots, list_snapshots_with_vault,
};
pub use trash::{allowed_trash_roots, purge_workspace_trash_with_vault, TrashCleanupStatus};
pub use upgrade::{
    check_for_updates, is_newer_version, is_trusted_github_url, parse_release_json,
    perform_upgrade_on_exe, run_upgrade_apply, validate_release_asset_url, ReleaseAsset,
    ReleaseInfo, UpgradeApplyReport, UpgradeCheckReport,
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
mod tests_round3;
#[cfg(test)]
mod tests_round4;
#[cfg(test)]
mod tests_round5;
#[cfg(test)]
mod tests_round6;
#[cfg(test)]
mod tests_round7;
#[cfg(test)]
mod tests_round8;
#[cfg(test)]
mod tests_trash_ledger;
#[cfg(test)]
mod tests_trash_targets;
