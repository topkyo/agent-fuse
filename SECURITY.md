# Security Policy / 安全策略与漏洞披露

**English** | **[简体中文](#安全策略中文说明)**

## Supported Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `0.6.3+` | Yes | Active security & APFS boundary maintenance |
| `< 0.6.3` | Upgrade recommended | Run `afuse upgrade` or reinstall via Homebrew / Cargo |

## Threat Model & Security Architecture

`agent-fuse` (`afuse`) operates strictly as a **local-first, zero-telemetry workspace recovery tool**:

1. **Isolated Local Vault (`0700`)**: Snapshots are stored on the same APFS volume under `~/.agent-fuse/vault.noindex/<repo>-<hash>` with `chmod 0700` owner-only permissions (`0600` metadata and lock files, `.afuse-vault-root` root marker) and Spotlight `.noindex` exclusion.
2. **Path Traversal, Symlink TOCTOU & Self-Ingestion Guards**:
   - Workspace validation accepts any plain APFS folder or regular single file (including items inside Desktop/Documents/Downloads), while rejecting `/`, `$HOME`, system roots, top-level TCC container roots (`~/Desktop`, `~/Documents`, `~/Downloads` themselves), symlinks, and vault subdirectories under case-insensitive Unicode NFD comparison.
   - Recursive removal and permission adjustments operate via `O_NOFOLLOW` / `openat` / `fdopendir` / `unlinkat` / `fchmodat(AT_SYMLINK_NOFOLLOW)` primitives and strip `SUID`/`SGID`/sticky bits.
   - Selective path restore (`afuse restore <snap> -- <paths>`) rejects absolute paths, `..` parent traversal segments, and internal `.afuse.tmp.*` staging names.
   - Snapshot metadata IDs (`meta.kv`) are strictly validated against `[A-Za-z0-9_-]` and must match the on-disk snapshot directory name.
3. **Zero Background Network Activity & Verified Updates**:
   - Neither `afuse` nor `AgentFuse.app` initiates network connections on launch or during background watching.
   - Manual CLI self-upgrade (`afuse upgrade`) fetches official GitHub release metadata over HTTPS strictly when invoked by the user, enforces initial `https://github.com/topkyo/agent-fuse/releases/download/...` asset URLs and GitHub CDN post-redirect URLs, verifies the `SHA256SUMS` digest, preflights tar members (`-tvzf`) before extraction, and validates Mach-O/codesign identity (`TeamIdentifier` and `Identifier`) before atomic replacement.
   - Desktop in-app updates (`AgentFuse.app`) verify HTTPS asset URLs and post-redirect URLs, verify DMG `SHA-256`, mount read-only, validate `CFBundleIdentifier`, enforce monotonic `CFBundleVersion` anti-downgrade checks, and run `codesign --verify --deep --strict` plus `TeamIdentifier` / `Developer ID Application` checks before atomic app swap.
4. **Process-Group Circuit Breaker Boundary (`afuse guard`)**:
   - `afuse guard` launches the target command in an isolated process group (`POSIX_SPAWN_SETPGROUP`) and terminates the group with `SIGSTOP` + `SIGKILL` upon deletion, truncation, or disk write spikes.
   - **OS Boundary**: Unprivileged macOS user-space processes cannot prevent a child process from calling `setsid()` or `setpgid()` to detach from the monitored process group. For untrusted or adversarial code execution, combine `afuse guard` with OS sandboxing, containers, or VM isolation.
5. **Zero Supply-Chain Dependencies**:
   - `afuse` compiles with `0` external crates (`Cargo.toml` `[dependencies]` is empty) and dynamically links only macOS `/usr/lib/libSystem.B.dylib`.
6. **Offline Pro License Verification**:
   - `AgentFuse Pro` verifies `AFUSE1.<payload>.<sig>` keys locally via macOS `CryptoKit` `Ed25519` public-key verification (`0600` local storage, species `scope` binding, zero activation servers).

## Reporting a Vulnerability

Please **do NOT open a public GitHub issue** for exploitable security vulnerabilities (such as symlink escape, arbitrary file overwrite outside workspace boundaries, command injection in hook snippets, or upgrade SHA-256 verification bypass).

- **Preferred Channel**: Submit a private report via **[GitHub Private Vulnerability Reporting (Security Advisories)](https://github.com/topkyo/agent-fuse/security/advisories/new)** on this repository.
- **Response SLA**: We acknowledge receipt within **48 hours** and aim to ship a verified patch and regression test within **7 days**.

---

<a id="安全策略中文说明"></a>
## 安全策略中文说明

### 受支持版本

| 版本范围 | 安全维护状态 | 说明 |
| :--- | :--- | :--- |
| `0.6.3+` | 支持中 | 持续维护安全边界与 APFS 原子性补丁 |
| `< 0.6.3` | 建议升级 | 请执行 `afuse upgrade` 或通过 Homebrew / Cargo 更新至最新版 |

### 安全架构边界与威胁模型

`agent-fuse` (`afuse`) 严格遵循**纯本地运行、零后台遥测**的安全设计：

1. **外部同卷权限隔离保险库（`0700`）**：所有快照均存储于同卷外部 `~/.agent-fuse/vault.noindex/<repo>-<hash>` 目录，强制 `0700` 仅属主可读写权限（元数据与锁文件 `0600`，根目录写入 `.afuse-vault-root` 标记），并默认排除 Spotlight 全局索引。
2. **目录越界、符号链接 TOCTOU 与自吞噬拦截**：
   - 目标校验器支持任意普通文件夹与单文件（含桌面/文稿/下载内部子目录与文件），并在大小写不敏感 Unicode NFD 归一比较下强制拒绝挂载 `/`、`$HOME`、系统目录、顶级 TCC 容器根目录（`~/Desktop`、`~/Documents`、`~/Downloads` 本身）、符号链接以及保险库自身子目录。
   - 递归清理与权限修改基于 `O_NOFOLLOW` / `openat` / `fdopendir` / `unlinkat` / `fchmodat(AT_SYMLINK_NOFOLLOW)` 原语实现，并自动剥离 `SUID`/`SGID`/Sticky 特权位。
   - 单文件精准恢复（`afuse restore <snap> -- <paths>`）强制拒绝绝对路径、`..` 父目录穿越以及 `.afuse.tmp.*` 内部暂存路径。
   - 快照元数据 `id`（`meta.kv`）强制校验仅含 `[A-Za-z0-9_-]` 且必须与磁盘快照子目录名完全一致。
3. **零启动/后台网络请求与校验升级边界**：
   - `afuse` 与 `AgentFuse.app` 在启动及守护期间均保持 `0` 联网请求。
   - CLI 按需升级（`afuse upgrade`）仅在用户手动触发时通过 HTTPS 拉取官方发布物，严格区分初始 `https://github.com/topkyo/agent-fuse/releases/download/...` 资产地址与重定向后 GitHub CDN 地址，完成 `SHA256SUMS` 校验、`tar -tvzf` 预检及 Mach-O/代码签名（`TeamIdentifier` 与 `Identifier`）校验后方可执行原子替换。
   - 桌面端应用内更新（`AgentFuse.app`）执行 HTTPS 与重定向后 URL 白名单校验、DMG `SHA-256` 校验、只读挂载、`CFBundleIdentifier` 匹配、`CFBundleVersion` 单调防降级校验，以及 `codesign --verify --deep --strict` 与 `TeamIdentifier` / `Developer ID Application` 签名链校验后方可原子覆盖。
4. **进程组熔断器边界（`afuse guard`）**：
   - `afuse guard` 通过 `POSIX_SPAWN_SETPGROUP` 在独立进程组启动目标命令，并在触发批量删除、截断或磁盘写爆阈值时向进程组发送 `SIGSTOP` + `SIGKILL`。
   - **操作系统边界**：非 root 的 macOS 用户态进程无法阻止子进程主动调用 `setsid()` 或 `setpgid()` 脱离受控进程组。执行不可信或对抗性代码时，请结合系统沙盒、容器或虚拟机隔离使用。
5. **零第三方供应链攻击面**：
   - Rust 内核保持 `0` 外部依赖（`[dependencies]` 为空），二进制仅动态链接苹果系统底层库 `/usr/lib/libSystem.B.dylib`。
6. **100% 离线授权验签**：
   - `AgentFuse Pro` 使用苹果原生 `CryptoKit` `Ed25519` 公钥在本地离线校验激活码（本地授权文件权限 `0600`、绑定产品 `scope`、无远程验签服务器）。

### 私密报告安全漏洞

若发现可被利用的安全漏洞（例如符号链接逃逸、工作区外文件覆盖、Shell 钩子注入或升级包哈希校验绕过），**请勿直接提交公开 GitHub Issue**。

- **私密上报通道**：请直接通过本仓库的 **[GitHub Security Advisories 私密漏洞报告通道](https://github.com/topkyo/agent-fuse/security/advisories/new)** 提交复现步骤。
- **响应承诺**：我们将在 **48 小时内**确认收到报告，并在 **7 天内**发布修复补丁与回归测试用例。
