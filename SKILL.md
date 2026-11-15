---
name: agent-fuse
description: >-
  Millisecond-scale APFS Copy-on-Write workspace time machine and process-group
  circuit breaker (`afuse`) for macOS coding agents. Activate before executing
  multi-file refactors, destructive shell commands (`rm`, `mv`, `git clean`,
  migrations), or untrusted scripts so uncommitted/untracked files can be
  restored atomically in ~12.6 ms (on a 142-file repo, including safety backup)
  or selectively per path with 100% SHA-256 Merkle parity while preserving the
  active shell's root cwd Inode.
---

# Agent-Fuse (`afuse` v0.5.0) · APFS Workspace Safety Airbag

`afuse` snapshots uncommitted edits, untracked files, and `.git` state on macOS APFS volumes into an external same-volume vault (`~/.agent-fuse/vault.noindex`, `0700` permissions) using kernel `clonefile(2)` (`0 Bytes` at `t=0` until blocks diverge) and `renamex_np(RENAME_SWAP)` root-Inode-preserving rollback. Automatic `auto:*` snapshots enforce a rolling cap via `AFUSE_MAX_AUTO_SNAPS` (default `50`) while preserving manual milestones.

## 1. Verify Availability & Safe Project Root

```bash
command -v afuse && afuse --json --version
afuse doctor "$PWD" --json
afuse --workspace "$PWD" --json validate
```

Always pass `--json` for deterministic machine parsing. `afuse validate` rejects `/`, `$HOME`, TCC-protected folders (`~/Desktop`, `~/Documents`, `~/Downloads`), non-APFS mounts, and directories without a project root marker (`.git`, `Cargo.toml`, `Package.swift`, `package.json`, `pyproject.toml`, `go.mod`, `Makefile`).

## 2. Core Agent Workflows

### A. Pre-Mutation CoW Checkpoint (`snap --fast` or `snap --if-changed`)
Before performing broad edits, file moves, or build/migration scripts:

```bash
# High-frequency zero-hash CoW checkpoint (O(files) metadata only, skips reading bytes)
afuse --workspace "$PWD" --json snap --fast -m "auto:agent-step"

# Full SHA-256 Merkle deduplicated checkpoint (skips duplicate if tree unchanged)
afuse --workspace "$PWD" --json snap --if-changed -m "pre-refactor"
```

### B. Inspect Exact Blast Radius (`diff`)
Inspect added, modified, and deleted paths (including untracked files) against any snapshot:

```bash
afuse --workspace "$PWD" --json diff latest
```

### C. Atomic Full or Selective Rollback (`restore`)
If a refactor, script, or subagent corrupts the workspace or specific files:

```bash
# Whole-workspace atomic restore (verifies full Merkle tree_sha256 Recovery Receipt)
afuse --workspace "$PWD" --json restore latest

# Surgical single-file / relative-path restore (rejects '..' traversal and absolute paths)
afuse --workspace "$PWD" --json restore latest -- src/lib.rs Cargo.toml
```

- **Root Inode Guarantee**: `afuse` never unlinks or replaces the workspace root directory itself. Active terminals, IDE language servers, and agent processes keep a valid `cwd` file descriptor without `cd .. && cd -`.
- Automatically takes an `auto:pre-restore` safety backup unless `--no-backup` is passed.

### D. Process-Group Circuit Breaker (`guard`)
Wrap risky subshells, cleanup scripts, or autonomous subagents so runaway mass deletions or disk-write spikes freeze (`SIGSTOP`), kill (`SIGKILL -pgid`), reap all grandchild processes, and auto-rollback:

```bash
afuse --workspace "$PWD" --json guard --max-delete 15 --max-write-mb 256 --auto-rollback -- sh -c "<risky-command>"
```

- Exit code `99` indicates the circuit breaker tripped and rolled back the workspace cleanly.

### E. Snapshot Garbage Collection & Manual Upgrade (`prune` / `upgrade`)
 Automatic `auto:*` snapshots self-cap at `AFUSE_MAX_AUTO_SNAPS` (`50` by default). You can also prune explicitly or check for verified CLI releases on manual demand:

```bash
afuse --workspace "$PWD" --json prune --keep 20 --label-prefix "auto:hook:"
afuse --json upgrade --check
```

## 3. Transparent Opt-In Hooks (Zero Silent Dotfile Edits)

Never modify `~/.zshrc` or `.claude/settings.json` without explicit user consent. Print hook snippets to `stdout` for user inspection:

```bash
# 1. Print Zsh interactive preexec hook (zero-fork builtin matcher; covers CLI agent launches)
afuse hook zsh

# 2. Print Claude Code PreToolUse JSON hook (fail-open exit 0, empty stdout, 5s throttle, max 20 auto:hook: ring)
afuse hook claude

# 3. Dry-run scan of installed hook blocks (pass --apply to remove Zsh marker block with backup)
afuse hook uninstall
```
