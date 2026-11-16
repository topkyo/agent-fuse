#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REAL_HOME="$(python3 -c 'import os,pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')"
if [ -z "$REAL_HOME" ] || [ "$REAL_HOME" = "/" ] || [ ! -d "$REAL_HOME" ]; then
  echo "FAIL: invalid REAL_HOME='$REAL_HOME'" >&2
  exit 2
fi
if [ -z "${RUSTUP_HOME:-}" ] || [ ! -d "${RUSTUP_HOME:-}" ]; then
  [ -d "$REAL_HOME/.rustup" ] && export RUSTUP_HOME="$REAL_HOME/.rustup"
fi
if [ -z "${CARGO_HOME:-}" ] || [ ! -d "${CARGO_HOME:-}" ]; then
  [ -d "$REAL_HOME/.cargo" ] && export CARGO_HOME="$REAL_HOME/.cargo"
fi
[ -n "${CARGO_HOME:-}" ] && [ -d "$CARGO_HOME/bin" ] && export PATH="$CARGO_HOME/bin:${PATH:-}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REAL_HOME/.cache/afuse-cargo-target}"
export CARGO_NET_OFFLINE=true
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"

echo "=== [Gate 2.0] Production Module Size Gate (< 400 LOC per .rs file) ==="
for rs_file in "$PROJECT_DIR"/src/*.rs; do
  [ "$(basename "$rs_file")" = "tests.rs" ] && continue
  rs_lines=$(wc -l < "$rs_file" | tr -d ' ')
  if [ "$rs_lines" -ge 400 ]; then
    echo "FAIL: production module $(basename "$rs_file") has ${rs_lines} lines (must be < 400 LOC)" >&2
    exit 1
  fi
done
echo "All production .rs modules strictly < 400 LOC."

echo "=== [Gate 2.1] Offline Unit & Kernel Integration Tests ==="
cargo test --offline --manifest-path "$PROJECT_DIR/Cargo.toml"

echo "=== [Gate 2.2] Release Build & Binary Size Gate (< 10 MB) ==="
cargo build --release --offline --manifest-path "$PROJECT_DIR/Cargo.toml"
BIN_PATH="$CARGO_TARGET_DIR/release/afuse"
BIN_BYTES=$(stat -f%z "$BIN_PATH")
echo "Binary: $BIN_PATH (${BIN_BYTES} bytes)"
if [ "$BIN_BYTES" -ge 10485760 ]; then
  echo "FAIL: binary size ${BIN_BYTES} >= 10 MB" >&2
  exit 1
fi

echo "=== [Gate 2.3] End-to-End 1,000-File Chaos + Fast Clone + Process-Group Breaker + Peak RSS (< 30 MB) ==="
TMP_SANDBOX="$(mktemp -d /tmp/afuse-verify-XXXXXX)"
trap 'rm -rf "$TMP_SANDBOX"' EXIT

WS="$TMP_SANDBOX/workspace"
VAULT="$TMP_SANDBOX/vault"
SNAP_TIME_LOG="$TMP_SANDBOX/snap-time.log"
GUARD_TIME_LOG="$TMP_SANDBOX/guard-time.log"
mkdir -p "$WS/src" "$WS/.git" "$VAULT"
export AFUSE_VAULT_DIR="$VAULT"

python3 - "$WS" << 'PY'
import os, sys
ws = sys.argv[1]
for d in range(10):
    sub = os.path.join(ws, "src", f"pkg_{d}")
    os.makedirs(sub, exist_ok=True)
    for f in range(100):
        with open(os.path.join(sub, f"mod_{f}.rs"), "w") as fp:
            fp.write(f"pub const ID: usize = {d * 100 + f};\n")
PY

INO_BEFORE=$(stat -f%i "$WS")
FAST_SNAP_JSON=$("$BIN_PATH" --workspace "$WS" --json snap --fast -m "auto:bench-fast")
echo "FAST_SNAP_JSON: $FAST_SNAP_JSON"
SNAP_JSON=$(/usr/bin/time -l "$BIN_PATH" --workspace "$WS" --json snap -m "1000-files-baseline" 2>"$SNAP_TIME_LOG")
echo "SNAP_JSON: $SNAP_JSON"

set +e
GUARD_JSON=$(/usr/bin/time -l "$BIN_PATH" --workspace "$WS" --json guard --max-delete 10 --auto-rollback -- sh -c 'rm -rf src/pkg_* && echo "rogue" > PWNED.txt' 2>"$GUARD_TIME_LOG")
GUARD_RC=$?
set -e
echo "GUARD_JSON (rc=$GUARD_RC): $GUARD_JSON"
if [ "$GUARD_RC" -ne 99 ]; then
  echo "FAIL: expected guard circuit breaker exit code 99, got $GUARD_RC" >&2
  exit 1
fi

INO_AFTER=$(stat -f%i "$WS")
if [ "$INO_BEFORE" != "$INO_AFTER" ]; then
  echo "FAIL: root Inode changed ($INO_BEFORE -> $INO_AFTER)" >&2
  exit 1
fi

RESTORED_COUNT=$(find "$WS/src" -name '*.rs' | wc -l | tr -d ' ')
if [ "$RESTORED_COUNT" -ne 1000 ] || [ -e "$WS/PWNED.txt" ]; then
  echo "FAIL: expected 1000 restored files and no PWNED.txt, got count=$RESTORED_COUNT" >&2
  exit 1
fi

SNAP_RSS=$(awk '/maximum resident set size/ {print $1}' "$SNAP_TIME_LOG")
GUARD_RSS=$(awk '/maximum resident set size/ {print $1}' "$GUARD_TIME_LOG")
if ! [[ "${SNAP_RSS:-}" =~ ^[1-9][0-9]*$ ]] || ! [[ "${GUARD_RSS:-}" =~ ^[1-9][0-9]*$ ]]; then
  echo "FAIL: unable to parse valid positive RSS metrics (snap='${SNAP_RSS:-}', guard='${GUARD_RSS:-}')" >&2
  exit 1
fi
RSS_BYTES=$(( SNAP_RSS > GUARD_RSS ? SNAP_RSS : GUARD_RSS ))
echo "Peak RSS (max of 1,000-file snap=${SNAP_RSS}B, guard+restore=${GUARD_RSS}B): ${RSS_BYTES} bytes"
if [ "$RSS_BYTES" -ge 31457280 ]; then
  echo "FAIL: peak RSS ${RSS_BYTES} >= 30 MB" >&2
  exit 1
fi

echo "=== [Gate 2.4] Hook Security, Zsh Syntax/Perf (<100ms/1000 noop), Hostile JSON & Concurrency ==="
ZSH_HOOK_FILE="$TMP_SANDBOX/hook.zsh"
"$BIN_PATH" hook zsh > "$ZSH_HOOK_FILE"
zsh -n "$ZSH_HOOK_FILE"

ZSH_BENCH=$(BIN_DIR="$(dirname "$BIN_PATH")" HOOK_FILE="$ZSH_HOOK_FILE" zsh -c '
  export PATH="$BIN_DIR:$PATH"
  source "$HOOK_FILE"
  source "$HOOK_FILE"
  local reg_count=${#preexec_functions[(r)_afuse_preexec]}
  [[ "${preexec_functions[(Ie)_afuse_preexec]}" -gt 0 ]] || exit 11
  local c=0
  for fn in "${preexec_functions[@]}"; do [[ "$fn" == "_afuse_preexec" ]] && (( c++ )); done
  [[ "$c" -eq 1 ]] || exit 12
  zmodload zsh/datetime
  local t0=$EPOCHREALTIME
  repeat 1000 { _afuse_preexec "git status" }
  local t1=$EPOCHREALTIME
  printf "%.2f" $(( (t1 - t0) * 1000.0 ))
')
echo "Zsh hook idempotency verified; 1,000 non-matching preexec calls took ${ZSH_BENCH} ms"
python3 -c "import sys; v=float(sys.argv[1]); assert v < 100.0, f'zsh preexec too slow: {v}ms >= 100ms'" "$ZSH_BENCH"

# Regression A-1 & B-3: core primitives reject REAL_HOME and prune rejects malformed flags without deleting milestones
if "$BIN_PATH" --workspace "$REAL_HOME" --json snap -m "must-fail" >/dev/null 2>&1; then
  echo "FAIL: snap accepted REAL_HOME" >&2
  exit 1
fi

"$BIN_PATH" hook claude | python3 -m json.tool >/dev/null

# Hostile stdin: 2 MiB garbage + invalid UTF-8 + nested cwd="/" spoof + forbidden $HOME cwd
HOSTILE_OUT=$(python3 -c 'import sys; sys.stdout.buffer.write(b"\xff\xfe" + b"A" * 2100000)' | "$BIN_PATH" hook claude --exec)
[ -z "$HOSTILE_OUT" ] || { echo "FAIL: non-empty stdout on garbage stdin" >&2; exit 1; }

SPOOF_OUT=$(printf '{"cwd":"%s","tool_name":"Bash","tool_input":{"command":"echo '\''{\\"cwd\\":\\"/\\"}'\'' && touch x"}}' "$REAL_HOME" | "$BIN_PATH" hook claude --exec)
[ -z "$SPOOF_OUT" ] || { echo "FAIL: non-empty stdout on forbidden HOME cwd" >&2; exit 1; }

# 50 concurrent --exec invocations against valid repo -> LOCK_NB + 5s throttle guarantees <= 2 auto snapshots & zero hangs
HOOK_REPO="$TMP_SANDBOX/hook-repo"
HOOK_VAULT="$TMP_SANDBOX/hook-vault"
mkdir -p "$HOOK_REPO/.git" "$HOOK_REPO/src" "$HOOK_VAULT"
echo "hello" > "$HOOK_REPO/src/a.rs"
AFUSE_VAULT_DIR="$HOOK_VAULT" "$BIN_PATH" --workspace "$HOOK_REPO" snap -m "manual-milestone" >/dev/null

for idx in $(seq 1 50); do
  printf '{"cwd":"%s","tool_name":"Write","tool_input":{"file_path":"src/a.rs"}}' "$HOOK_REPO" \
    | AFUSE_VAULT_DIR="$HOOK_VAULT" "$BIN_PATH" hook claude --exec &
done
wait

SNAP_COUNTS=$(AFUSE_VAULT_DIR="$HOOK_VAULT" "$BIN_PATH" --workspace "$HOOK_REPO" --json list | python3 -c '
import json, sys
d = json.load(sys.stdin)
snaps = d["snapshots"]
auto_n = sum(1 for s in snaps if s["label"].startswith("auto:"))
man_n = sum(1 for s in snaps if s["label"] == "manual-milestone")
print(f"{auto_n}:{man_n}")
assert 1 <= auto_n <= 2 and man_n == 1, f"unexpected counts auto={auto_n} manual={man_n}"
')
echo "50x concurrent claude --exec verified (auto:manual = $SNAP_COUNTS)"

# Uninstall dry-run preserves exact file SHA-256
FAKE_HOME="$TMP_SANDBOX/fake-home"
mkdir -p "$FAKE_HOME/.claude"
{ echo "export FOO=1"; "$BIN_PATH" hook zsh; } > "$FAKE_HOME/.zshrc"
"$BIN_PATH" hook claude > "$FAKE_HOME/.claude/settings.json"
SHA_BEFORE=$(shasum -a 256 "$FAKE_HOME/.zshrc" "$FAKE_HOME/.claude/settings.json")
"$BIN_PATH" --workspace "$HOOK_REPO" hook uninstall --home "$FAKE_HOME" >/dev/null
SHA_AFTER=$(shasum -a 256 "$FAKE_HOME/.zshrc" "$FAKE_HOME/.claude/settings.json")
[ "$SHA_BEFORE" = "$SHA_AFTER" ] || { echo "FAIL: uninstall dry-run mutated config files" >&2; exit 1; }

[ -s "$PROJECT_DIR/SKILL.md" ] || { echo "FAIL: missing SKILL.md" >&2; exit 1; }
[ -s "$PROJECT_DIR/llms.txt" ] || { echo "FAIL: missing llms.txt" >&2; exit 1; }
python3 - "$PROJECT_DIR/README.md" "$PROJECT_DIR/SKILL.md" "$PROJECT_DIR/llms.txt" "$PROJECT_DIR/Cargo.toml" <<'PY'
import re, sys
banned = re.compile(r"\b(revolutionary|game-changer|blazing|seamless|supercharge|sub-millisecond)\b|🚀|\[FILL|agentfuse\.pages\.dev", re.I)
for path in sys.argv[1:]:
    txt = open(path, encoding="utf-8").read()
    m = banned.search(txt)
    assert not m, f"banned/dead token {m.group(0)!r} in {path}"
print("README, SKILL, llms.txt & Cargo.toml verified (zero banned tokens, zero sub-ms/dead links)")
PY

# B-3 end-to-end check: malformed prune flags return non-zero and keep manual-milestone intact
for bad_args in "--keep 2 --label-prefx auto:hook:" "--keep abc --label-prefix auto:hook:" "--kepp 2"; do
  # shellcheck disable=SC2086
  if AFUSE_VAULT_DIR="$HOOK_VAULT" "$BIN_PATH" --workspace "$HOOK_REPO" --json prune $bad_args >/dev/null 2>&1; then
    echo "FAIL: prune accepted malformed args: $bad_args" >&2
    exit 1
  fi
done
if AFUSE_VAULT_DIR="$HOOK_VAULT" "$BIN_PATH" --workspace "$HOOK_REPO" --json prune --keep 2 --label-prefix "" >/dev/null 2>&1; then
  echo "FAIL: prune accepted empty --label-prefix" >&2
  exit 1
fi
if AFUSE_VAULT_DIR="$HOOK_VAULT" "$BIN_PATH" --workspace "$HOOK_REPO" --json prune >/dev/null 2>&1; then
  echo "FAIL: bare prune without --keep succeeded" >&2
  exit 1
fi
AFUSE_VAULT_DIR="$HOOK_VAULT" "$BIN_PATH" --workspace "$HOOK_REPO" --json list | grep -q '"manual-milestone"' || {
  echo "FAIL: manual-milestone deleted by malformed prune" >&2
  exit 1
}

# YF-7 + B-1/B-2 end-to-end check: doctor reflects real health (ok/exit code) & zero username/path leakage on errors
set +e
DOC_BAD_JSON=$(AFUSE_VAULT_DIR="/dev/null/impossible" "$BIN_PATH" --workspace "$WS" --json doctor)
DOC_BAD_RC=$?
DOC_BAD_TXT=$(AFUSE_VAULT_DIR="/dev/null/impossible" "$BIN_PATH" doctor "$WS" 2>&1)
DOC_BAD_TXT_RC=$?
set -e
echo "DOC_BAD_JSON (rc=$DOC_BAD_RC): $DOC_BAD_JSON"
[ "$DOC_BAD_RC" -eq 1 ] && [ "$DOC_BAD_TXT_RC" -eq 1 ] || { echo "FAIL: expected doctor exit code 1 on unwritable vault, got json=$DOC_BAD_RC txt=$DOC_BAD_TXT_RC" >&2; exit 1; }
printf '%s' "$DOC_BAD_TXT" | grep -Fq "Result: [FAIL] Environment check failed (require APFS + writable vault)." || { echo "FAIL: missing [FAIL] banner in doctor text output" >&2; exit 1; }
printf '%s' "$DOC_BAD_JSON" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["ok"] is False and d["vault_writable"] is False and d["clonefile_probe_us"] == 0 and d["snapshot_count"] == 0, d
'

DOC_POS_JSON=$(AFUSE_VAULT_DIR="$VAULT" "$BIN_PATH" doctor "$WS" --json)
DOC_POS_TXT=$(AFUSE_VAULT_DIR="$VAULT" "$BIN_PATH" doctor "$WS")
echo "DOC_POS_JSON: $DOC_POS_JSON"
printf '%s' "$DOC_POS_TXT" | grep -Fq "Result: [PASS] Ready for zero-overhead agentic protection." || { echo "FAIL: missing [PASS] banner in doctor text output" >&2; exit 1; }
printf '%s' "$DOC_POS_JSON" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["ok"] is True and d["apfs_verified"] is True and d["vault_writable"] is True and d["clonefile_probe_us"] > 0 and d["snapshot_count"] >= 1, d
'

# B-1 privacy check: nonexistent path, unknown flag with secret path, and extra positional arg must NEVER echo username/path
set +e
LEAK_OUT_A=$("$BIN_PATH" doctor /Users/probe_secret_99/nonexistent_secret_xyz --json 2>&1)
LEAK_RC_A=$?
LEAK_OUT_B=$("$BIN_PATH" doctor --bad=/Users/probe_secret_99/secret --json 2>&1)
LEAK_RC_B=$?
LEAK_OUT_C=$("$BIN_PATH" doctor "$WS" /Users/probe_secret_99/secret_extra --json 2>&1)
LEAK_RC_C=$?
LEAK_OUT_D=$("$BIN_PATH" validate /Users/probe_secret_99/nonexistent_secret_xyz --json 2>&1)
LEAK_RC_D=$?
set -e
[ "$LEAK_RC_A" -ne 0 ] && [ "$LEAK_RC_B" -eq 22 ] && [ "$LEAK_RC_C" -eq 22 ] && [ "$LEAK_RC_D" -ne 0 ] || {
  echo "FAIL: unexpected error exit codes: a=$LEAK_RC_A b=$LEAK_RC_B c=$LEAK_RC_C d=$LEAK_RC_D" >&2
  exit 1
}
python3 - "$LEAK_OUT_A" "$LEAK_OUT_B" "$LEAK_OUT_C" "$LEAK_OUT_D" <<'PY'
import os, pwd, sys
cur_user = pwd.getpwuid(os.getuid()).pw_name
tokens = ("probe_secret_99", "Users", "nonexistent_secret_xyz", "secret")
if cur_user and len(cur_user) >= 2:
    tokens = tokens + (cur_user,)
for idx, out in enumerate(sys.argv[1:], start=1):
    for token in tokens:
        assert token not in out, f"privacy leak ({token!r}) in CLI error #{idx}: {out!r}"
PY

# v0.5.0 gates: selective path restore + phantom rejection (no backup) + traversal rejection + upgrade --check (file:// offline) + AFUSE_MAX_AUTO_SNAPS
SEL_WS="$TMP_SANDBOX/selective-ws"
SEL_VAULT="$TMP_SANDBOX/selective-vault"
mkdir -p "$SEL_WS/.git" "$SEL_WS/src" "$SEL_VAULT"
echo "keep-v1" > "$SEL_WS/src/keep.rs"
echo "fix-v1" > "$SEL_WS/src/fix.rs"
SEL_SNAP=$(AFUSE_VAULT_DIR="$SEL_VAULT" "$BIN_PATH" --workspace "$SEL_WS" --json snap -m "v050-base" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "keep-dirty" > "$SEL_WS/src/keep.rs"
rm -f "$SEL_WS/src/fix.rs"
echo "rogue" > "$SEL_WS/src/extra.rs"
if AFUSE_VAULT_DIR="$SEL_VAULT" "$BIN_PATH" --workspace "$SEL_WS" --json restore "$SEL_SNAP" -- "../escape" >/dev/null 2>&1; then
  echo "FAIL: selective restore allowed path traversal" >&2
  exit 1
fi
if AFUSE_VAULT_DIR="$SEL_VAULT" "$BIN_PATH" --workspace "$SEL_WS" --json restore "$SEL_SNAP" -- "src/phantom_never_existed.rs" >/dev/null 2>&1; then
  echo "FAIL: selective restore accepted phantom nonexistent path" >&2
  exit 1
fi
PHANTOM_PRE_COUNT=$(AFUSE_VAULT_DIR="$SEL_VAULT" "$BIN_PATH" --workspace "$SEL_WS" --json list | python3 -c 'import json,sys; print(sum(1 for s in json.load(sys.stdin)["snapshots"] if s["label"]=="auto:pre-restore"))')
[ "$PHANTOM_PRE_COUNT" -eq 0 ] || { echo "FAIL: phantom restore created unwanted auto:pre-restore snapshot" >&2; exit 1; }
SEL_JSON=$(AFUSE_VAULT_DIR="$SEL_VAULT" "$BIN_PATH" --workspace "$SEL_WS" --json restore "$SEL_SNAP" -- "src/fix.rs" "src/extra.rs")
python3 - "$SEL_JSON" "$SEL_WS" <<'PY'
import json, os, sys
d = json.loads(sys.argv[1])
ws = sys.argv[2]
assert d["ok"] is True and d["selective"] is True and d["restored_paths"] == 2, d
assert open(os.path.join(ws, "src/fix.rs")).read() == "fix-v1\n"
assert open(os.path.join(ws, "src/keep.rs")).read() == "keep-dirty\n"
assert not os.path.exists(os.path.join(ws, "src/extra.rs"))
PY

REL_JSON="$TMP_SANDBOX/release.json"
echo '{"tag_name":"v0.9.0","html_url":"https://github.com/topkyo/agent-fuse/releases/tag/v0.9.0","assets":[]}' > "$REL_JSON"
UP_JSON=$(AFUSE_RELEASE_JSON_URL="file://$REL_JSON" "$BIN_PATH" --json upgrade --check)
python3 - "$UP_JSON" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
assert d["ok"] is True and d["current_version"] == "0.5.0" and d["latest_version"] == "0.9.0" and d["update_available"] is True, d
PY

AFUSE_VAULT_DIR="$SEL_VAULT" AFUSE_MAX_AUTO_SNAPS=2 "$BIN_PATH" --workspace "$SEL_WS" --json snap -m "manual-keep" >/dev/null
for idx in 1 2 3 4; do
  echo "auto-$idx" > "$SEL_WS/src/keep.rs"
  AFUSE_VAULT_DIR="$SEL_VAULT" AFUSE_MAX_AUTO_SNAPS=2 "$BIN_PATH" --workspace "$SEL_WS" --json snap --fast -m "auto:pro:gc" >/dev/null
done
AFUSE_VAULT_DIR="$SEL_VAULT" "$BIN_PATH" --workspace "$SEL_WS" --json list | python3 -c '
import json, sys
snaps = json.load(sys.stdin)["snapshots"]
auto_n = sum(1 for s in snaps if s["label"].startswith("auto:") and s["label"] != "auto:pre-restore")
assert auto_n == 2, f"expected 2 auto snaps after GC, got {auto_n}"
assert any(s["label"] == "manual-keep" for s in snaps), "manual-keep vanished"
'
AFUSE_VAULT_DIR="$SEL_VAULT" "$BIN_PATH" --workspace "$SEL_WS" --json prune --keep 0 >/dev/null

# Deep-audit regressions: (1) corrupted meta.kv list/diff safety; (2) snap --help / --bad-flag; (3) 64 MiB streaming SHA-256 RSS < 15 MiB; (4) UTF-8/space/0444 selective restore
ADV_WS="$TMP_SANDBOX/adv-ws"
ADV_VAULT="$TMP_SANDBOX/adv-vault"
mkdir -p "$ADV_WS/.git" "$ADV_WS/中文 目录" "$ADV_VAULT"
printf "utf8-readonly-v1\n" > "$ADV_WS/中文 目录/配置 文稿.txt"
chmod 0444 "$ADV_WS/中文 目录/配置 文稿.txt"
GOOD_ID=$(AFUSE_VAULT_DIR="$ADV_VAULT" "$BIN_PATH" --workspace "$ADV_WS" --json snap -m "adv-good" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
BAD_ID=$(AFUSE_VAULT_DIR="$ADV_VAULT" "$BIN_PATH" --workspace "$ADV_WS" --json snap -m "adv-corrupt" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
BAD_META_FILE=$(find "$ADV_VAULT" -path "*/snapshots/${BAD_ID}/meta.kv" -type f | head -n 1)
[ -n "$BAD_META_FILE" ] || { echo "FAIL: could not locate meta.kv for $BAD_ID" >&2; exit 1; }
printf "corrupt=garbage\ncreated_ms=nope\n" > "$BAD_META_FILE"

AFUSE_VAULT_DIR="$ADV_VAULT" "$BIN_PATH" --workspace "$ADV_WS" --json list | python3 -c '
import json, sys
snaps = json.load(sys.stdin)["snapshots"]
assert len(snaps) == 1 and snaps[0]["id"] != "", f"expected clean single snap, got {snaps}"
'
set +e
AFUSE_VAULT_DIR="$ADV_VAULT" "$BIN_PATH" --workspace "$ADV_WS" --json diff "$BAD_ID" >/dev/null 2>&1
DIFF_CORRUPT_RC=$?
set -e
[ "$DIFF_CORRUPT_RC" -eq 22 ] || { echo "FAIL: diff corrupted snapshot returned rc=$DIFF_CORRUPT_RC (expected 22)" >&2; exit 1; }

AFUSE_VAULT_DIR="$ADV_VAULT" "$BIN_PATH" --workspace "$ADV_WS" snap --help >/dev/null
SNAP_COUNT_BEFORE_HELP=$(AFUSE_VAULT_DIR="$ADV_VAULT" "$BIN_PATH" --workspace "$ADV_WS" --json list | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["snapshots"]))')
[ "$SNAP_COUNT_BEFORE_HELP" -eq 1 ] || { echo "FAIL: snap --help mutated snapshots" >&2; exit 1; }
set +e
AFUSE_VAULT_DIR="$ADV_VAULT" "$BIN_PATH" --workspace "$ADV_WS" --json snap --bad-flag >/dev/null 2>&1
BAD_FLAG_RC=$?
set -e
[ "$BAD_FLAG_RC" -eq 22 ] || { echo "FAIL: snap --bad-flag returned rc=$BAD_FLAG_RC (expected 22)" >&2; exit 1; }

chmod 0644 "$ADV_WS/中文 目录/配置 文稿.txt"
printf "corrupted-content\n" > "$ADV_WS/中文 目录/配置 文稿.txt"
AFUSE_VAULT_DIR="$ADV_VAULT" "$BIN_PATH" --workspace "$ADV_WS" --json restore "$GOOD_ID" -- "中文 目录/配置 文稿.txt" >/dev/null
[ "$(cat "$ADV_WS/中文 目录/配置 文稿.txt")" = "utf8-readonly-v1" ] || { echo "FAIL: UTF-8 space selective restore content mismatch" >&2; exit 1; }
ADV_MODE=$(stat -f%Lp "$ADV_WS/中文 目录/配置 文稿.txt")
[ "$ADV_MODE" = "444" ] || { echo "FAIL: UTF-8 selective restore lost 0444 mode (got $ADV_MODE)" >&2; exit 1; }
chmod 0644 "$ADV_WS/中文 目录/配置 文稿.txt"

BIG_WS="$TMP_SANDBOX/big-ws"
BIG_VAULT="$TMP_SANDBOX/big-vault"
BIG_TIME_LOG="$TMP_SANDBOX/big-time.log"
mkdir -p "$BIG_WS/.git" "$BIG_VAULT"
python3 - "$BIG_WS/payload.bin" <<'PY'
import sys
with open(sys.argv[1], "wb") as f:
    chunk = b"0123456789abcdef" * 65536
    for _ in range(64):
        f.write(chunk)
PY
/usr/bin/time -l env AFUSE_VAULT_DIR="$BIG_VAULT" "$BIN_PATH" --workspace "$BIG_WS" --json snap -m "big-64mib" >/dev/null 2>"$BIG_TIME_LOG"
BIG_RSS=$(awk '/maximum resident set size/ {print $1}' "$BIG_TIME_LOG")
if ! [[ "${BIG_RSS:-}" =~ ^[1-9][0-9]*$ ]] || [ "$BIG_RSS" -ge 15728640 ]; then
  echo "FAIL: 64 MiB streaming snap RSS ${BIG_RSS:-} >= 15 MiB (15728640 B)" >&2
  exit 1
fi
AFUSE_VAULT_DIR="$BIG_VAULT" "$BIN_PATH" --workspace "$BIG_WS" --json prune --keep 0 >/dev/null
AFUSE_VAULT_DIR="$ADV_VAULT" "$BIN_PATH" --workspace "$ADV_WS" --json prune --keep 0 >/dev/null

P2_WS="$TMP_SANDBOX/p2-cli-ws"
P2_VAULT="$TMP_SANDBOX/p2-cli-vault"
mkdir -p "$P2_WS/apps/web/node_modules/pkg" "$P2_VAULT"
printf "v1\n" > "$P2_WS/apps/web/app.ts"
printf "keep\n" > "$P2_WS/apps/web/node_modules/pkg/index.js"
AFUSE_VAULT_DIR="$P2_VAULT" "$BIN_PATH" --workspace "$P2_WS" --json snap -m "p2-base" >/dev/null
printf "v2\n" > "$P2_WS/apps/web/app.ts"
AFUSE_VAULT_DIR="$P2_VAULT" "$BIN_PATH" --workspace "$P2_WS" --json restore latest >/dev/null
[ -f "$P2_WS/apps/web/node_modules/pkg/index.js" ] || { echo "FAIL: nested node_modules lost on CLI restore" >&2; exit 1; }

DOC_HOME_OUT="$("$BIN_PATH" --workspace "$HOME" doctor 2>&1 || true)"
if printf '%s' "$DOC_HOME_OUT" | grep -qi "project root marker"; then
  echo "FAIL: doctor output retains stale project root marker hint" >&2
  exit 1
fi

P2_FAKE_BIN="$TMP_SANDBOX/p2-fake-bin"
P2_HOOK_LOG="$TMP_SANDBOX/p2-hook.log"
mkdir -p "$P2_FAKE_BIN"
cat > "$P2_FAKE_BIN/afuse" <<SH
#!/bin/sh
printf '%s\n' "\$*" >> "$P2_HOOK_LOG"
SH
chmod +x "$P2_FAKE_BIN/afuse"
: > "$P2_HOOK_LOG"
zsh -fc "
  PATH=\"$P2_FAKE_BIN:\$PATH\"
  AFUSE_HOOK_DISABLE=0; AFUSE_GUARDED=0
  eval \"\$('$BIN_PATH' hook zsh)\"
  _afuse_preexec 'FOO=1 env BAR=2 npx -y @anthropic-ai/claude-code --help'
  _afuse_preexec 'command codex --full-auto'
  _afuse_preexec 'uvx --from aider-chat aider'
"
P2_ZSH_CHECK="$(cat "$P2_HOOK_LOG")"
echo "$P2_ZSH_CHECK" | grep -q -- "--tool claude-code" || { echo "FAIL: zsh wrapper parse claude-code ($P2_ZSH_CHECK)" >&2; exit 1; }
echo "$P2_ZSH_CHECK" | grep -q -- "--tool codex" || { echo "FAIL: zsh wrapper parse codex ($P2_ZSH_CHECK)" >&2; exit 1; }
echo "$P2_ZSH_CHECK" | grep -q -- "--tool aider" || { echo "FAIL: zsh wrapper parse aider ($P2_ZSH_CHECK)" >&2; exit 1; }
AFUSE_VAULT_DIR="$P2_VAULT" "$BIN_PATH" --workspace "$P2_WS" --json prune --keep 0 >/dev/null

"$BIN_PATH" --workspace "$WS" --json prune --keep 0 >/dev/null
AFUSE_VAULT_DIR="$HOOK_VAULT" "$BIN_PATH" --workspace "$HOOK_REPO" --json prune --keep 0 >/dev/null
echo "PASS: Gate 2 verified (1,000 files restored, root Inode=$INO_AFTER preserved, binary=${BIN_BYTES}B, RSS=${RSS_BYTES}B, 64MiB_RSS=${BIG_RSS}B, hook & deep-audit suite green)."
