# Branch Summary: `wportnoy/vscode-server-in-litebox`

Delta from `origin/wdcui/agent-sandbox-fork` — ~195 commits, 106 files changed, ~20k lines added.

---

## 1. VS Code & Coding Agent Isolation

*~12k lines, 62 files — new `litebox_tool_executor` crate + scripts/policies/rootfs tooling*

### Tool Executor

New CLI entrypoint (`litebox_tool_executor`) that orchestrates broker + runner
subprocesses to sandbox Linux workloads. Supports three modes:

- **Direct mode**: run a single command in a sandbox
- **Interactive mode**: persistent bash session with shell state across commands
- **VS Code Server mode**: dropbear SSH inside the sandbox with port forwarding

### SSH-Based VS Code Remote Architecture

- Evolved from embedded russh → **dropbear SSH inside the sandbox** for full
  POSIX compatibility
- VS Code Remote-SSH connects via port forwarding (host:2222 → guest:22)
- Dropbear fork+execs bash, sftp-server, and VS Code Server — all sharing one
  sandboxed filesystem
- Pre-installed VS Code CLI in rootfs; runtime syscall rewriting eliminates
  pre-download requirement

### Policy Enforcement

- JSON glob-pattern sandbox policy (filesystem allow/deny + network allowlists)
- Policy enforcement moved from shim to broker (central enforcement at
  9P/network boundary)
- `--policy` XOR `--record-baseline` CLI contract — no implicit defaults
- Baseline recording mode captures all operations for policy generation
- Demo policy covers VS Code/Copilot/GitHub endpoints + package registries
  (npm, pypi)

### Network Isolation

- DNS queries redirected to host resolver via broker
- Inbound TCP port forwarding (`--forward-port`) for SSH access
- Port registration + cross-worker TCP bridging for loopback routing
- Loopback redirect (127.0.0.1 → gateway + broker hairpin)
- IPv6 → IPv4 mapping for Node.js compatibility

### Audit System

- Structured JSONL audit logging with PID/TID, ioctl fd+command, IP:port
  correlation
- Per-session log files with broker events alongside syscall traces
- VS Code tasks for live tail + PowerShell pretty-printer

### Rootfs Evolution

- Progressed from busybox → bash → full rootfs with dropbear, sftp-server,
  Node.js, VS Code CLI
- Latest: **Dockerfile as single source of truth** for reproducible rootfs
  builds

---

## 2. LiteBox Platform Improvements

*~7k lines, 34 files — filesystem, shim, broker, and process lifecycle*

### Layered Filesystem (`litebox/src/fs/`)

- `LowerLayerWritableFiles` semantics for 9P-backed directory rootfs
- Fixed `unlink` to actually remove from writable lower layer (not just
  tombstone) — resolved `rmdir` ENOTEMPTY on VS Code log rotation
- Tombstone-aware `read_dir` merging upper/lower entries
- Cross-layer rename returning EXDEV, tombstone-aware destination checks

### Shim Syscall Coverage (`litebox_shim_linux/`)

- **AF_NETLINK ROUTE socket** for `getifaddrs()` — virtual eth0 with MAC
  address, RTM_GETLINK/RTM_GETADDR responses, MSG_PEEK|MSG_TRUNC handling
- `/dev/fd/N` support (open, readlink, stat)
- **Terminal ioctls**: TCSETS shadow fix (eliminated Node.js hang), TCGETS
- Credential syscalls: geteuid, access, prctl(SetDumpable) as no-ops
- IPv6 setsockopt mapping, getsockname for bound TCP sockets

### Broker (`litebox_broker/`)

- GlobPolicy strips rootfs prefix before matching
- Cross-worker TCP bridging and port registration
- Network listener cleanup after use

### Process Lifecycle

- Pipe pair_id made monotonic (resolved contamination)
- Bridge threads joined before exit_group
- Seccomp filter activation deferred until after wrgsbase

---

## 3. Testing & Validation

*~4k+ lines — new `litebox_test_harness` crate + systematic debugging*

### Test Harness Architecture

New `litebox_test_harness` crate — process-tree integration test framework:

- **Coordinator** (init) drives child agents via pipe-based protocol with
  two-phase ready/go handshake
- **Declarative matrix testing**: Topology (in-process, parent→child, sibling,
  grandchild, cross-subtree) × FsScope (/shared vs /tmp) × operation type
- **SpawnRemote protocol** for cross-worker test execution
- **Zero xfail on WSL2 baseline** — all static xfail markers eliminated

### Test Categories

| Category | Coverage |
|----------|----------|
| FS I/O | 6 operations × 2 path scopes |
| Symlinks | basic, directory, dangling, nested, relative |
| Unix sockets | in-process, server+fork-client, cross-agent |
| Network | IPv4/IPv6, TCP, cross-worker |
| Fork/exec | PIE vs non-PIE × open-file matrix |
| Terminal ioctl | op × fd matrix |
| VS Code server | socket connectivity |
| Netlink | getifaddrs path |

### Systematic Debugging Methodology

- **Pipe contamination**: narrowed via isolation tests X49-X59, proved
  contamination crosses agent boundaries, traced to mux relay, fixed with
  monotonic pair_id
- **Node.js exit**: EX1-EX9 reproduction tests, narrowed to TCSETS hang, fixed
  with shadow ioctl
- **VS Code bootstrap**: captured bootstrap script for replay testing, syscall
  gap analysis tooling
