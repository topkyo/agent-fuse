# Contributing to `agent-fuse` (`afuse`) / 参与贡献指南

**English** | **[简体中文](#简体中文指南)**

Thank you for auditing, testing, or contributing to `agent-fuse` (`afuse`). Because `afuse` acts as a last-line safety airbag for uncommitted developer workspaces, we enforce strict engineering invariants to keep the codebase auditable in 60 seconds.

## Engineering Invariants

1. **Zero External Rust Crates (`[dependencies]` must stay empty)**:
   - `afuse` relies solely on the Rust standard library (`std`) and direct Darwin `libc` FFI bindings (`clonefile(2)`, `renamex_np(2)`, `statfs`, `flock`, `setpgid`, `kill`).
   - Do not add third-party crates from `crates.io`. Zero supply-chain bloat ensures instant offline builds and a `< 600 KiB` stripped binary.
2. **Modular `< 400` LOC Limit**:
   - Keep each `.rs` module focused and under `400` lines of code. Never pack multiple statements onto one line with semicolons to game line counts.
3. **Strict APFS & Workspace Safety Boundaries**:
   - Never fall back silently to recursive byte copying (`cp -R`) when `clonefile(2)` fails (`EXDEV` / `ENOTSUP` must fail fast with actionable exit codes).
   - Preserve the workspace root directory Inode during `restore`. Reject `/`, `$HOME`, TCC-protected folders, symlink escapes, and `..` path traversal in selective restores.
   - Zero background telemetry or silent dotfile edits (`~/.zshrc`, `~/.claude/settings.json`). Network calls are permitted strictly inside explicit manual `afuse upgrade`.

## Local Build & Verification Gates

Run the full test and chaos verification suite on an APFS volume (macOS 12.0+) before opening a Pull Request:

```bash
# 1. Unit & integration tests (zero warnings)
cargo test

# 2. Release build & end-to-end 1,000-file chaos / selective restore / auto-GC verification
./scripts/verify.sh
```

## Pull Request Checklist

- [ ] `Cargo.toml` `[dependencies]` remains completely empty (`0` external crates).
- [ ] `cargo test` and `./scripts/verify.sh` pass with zero compiler warnings.
- [ ] CLI `--json` output contracts remain backward-compatible and deterministic.
- [ ] Both `README.md` (English) and `README.zh-CN.md` (Simplified Chinese) are updated if user-facing flags or behaviors change.

---

<a id="简体中文指南"></a>
## 简体中文指南

感谢你审计、测试或参与共建 `agent-fuse` (`afuse`)。作为开发者未提交代码工作区的最后一道物理安全气囊，本仓库执行极简可审计工程约束，确保任何工程师都能在 60 秒内读完并信任核心代码。

### 核心工程红线

1. **零外部第三方依赖（`Cargo.toml` 的 `[dependencies]` 必须保持为空）**：
   - `afuse` 仅使用 Rust 标准库（`std`）与 macOS Darwin 内核 `libc` 系统调用绑定（`clonefile(2)`、`renamex_np(2)`、`statfs`、`flock`、`setpgid`、`kill`）。
   - 严禁引入任何 `crates.io` 第三方包，保障 100% 离线确定性编译、零供应链投毒风险与 `< 600 KiB` 极致体积。
2. **单文件 `< 400` 行模块化约束**：
   - 每个源文件职责单一且控制在 `400` 行以内，严禁通过单行塞入多个分号压行作弊。
3. **严格的 APFS 与工作区安全边界**：
   - 当非 APFS 卷或跨卷导致 `clonefile(2)` 失败时，必须立即报错退出，严禁静默退化为缓慢的字节级拷贝（`cp -R`）。
   - 全量或单文件 `restore` 必须保持工作区根目录 Inode 不变，并严格拦截 `/`、`$HOME`、TCC 隐私目录、符号链接逃逸及 `..` 路径穿越。
   - 严禁任何启动/后台联网遥测，严禁静默修改用户配置文件（`~/.zshrc` 等）；全仓唯一允许的联网操作仅限用户显式手动执行的 `afuse upgrade`。

### 本地构建与门禁自检

提交 Pull Request 前，请在 macOS 12.0+ APFS 卷上跑通完整测试与混沌验收脚本：

```bash
# 1. 运行全部单元测试与边界集成测试（零编译警告）
cargo test

# 2. 运行 Release 编译及 1,000 文件混沌压测 / 单文件恢复 / 自动配额 GC 验收
./scripts/verify.sh
```

### 提交检查清单

- [ ] `Cargo.toml` 中 `[dependencies]` 保持 `0` 外部依赖。
- [ ] `cargo test` 与 `./scripts/verify.sh` 全部通过且零警告。
- [ ] `--json` 输出字段保持向后兼容与确定性。
- [ ] 若新增或变更了命令行参数，请同步更新英文版 `README.md` 与中文版 `README.zh-CN.md`。
