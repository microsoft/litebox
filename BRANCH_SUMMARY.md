# Branch Summary: `wportnoy/vscode-server-in-litebox`

Delta from `origin/wdcui/agent-sandbox-fork` — ~399 commits, ~145 files changed,
~50k lines added (~33k net after deletions). Originally ~195 commits / 20k lines;
last summary update at `491ab049` added another ~204 commits / ~13k net lines
focused on cross-worker connectivity, bash/shell platform fixes, Docker rootfs,
and test infrastructure.

---

## 1. VS Code & Coding Agent Isolation

*New `litebox_tool_executor` crate + scripts/policies/rootfs/Docker tooling*

### Tool Executor

CLI entrypoint (`litebox_tool_executor`) that orchestrates broker + runner
subprocesses to sandbox Linux workloads. Modes:

- **Direct mode**: run a single command in a sandbox
- **Interactive mode**: persistent bash session with shell state across commands
- **VS Code Server mode**: dropbear SSH inside the sandbox with port forwarding

Direct and VS Code Server modes were unified into a single dispatch path.
A `--debug` flag wraps the whole executor under `gdbserver` for remote
debugging (with shell-script CRLF fixes for WSL2).

### SSH-Based VS Code Remote Architecture

- Evolved from embedded russh → **dropbear SSH inside the sandbox** for full
  POSIX compatibility
- VS Code Remote-SSH connects via port forwarding (host:2222 → guest:22)
- Dropbear fork+execs bash, sftp-server, and VS Code Server — all sharing one
  sandboxed filesystem
- VS Code CLI **pre-cached at commit-specific path** so first connect skips
  download
- `code-server` path discovered dynamically (fails loudly if missing)

### Policy Enforcement

- JSON glob-pattern sandbox policy (filesystem allow/deny + network allowlists)
- Policy enforcement lives in the broker (central enforcement at 9P/network
  boundary), with rootfs-prefix stripping before glob match
- `--policy` XOR `--record-baseline` CLI contract — no implicit defaults
- Demo policy covers VS Code/Copilot/GitHub endpoints + npm/pypi

### Network Isolation

- DNS queries redirected to host resolver via broker
- Inbound TCP port forwarding (`--forward-port`) for SSH access
- Port registration + cross-worker TCP bridging for loopback routing
- Loopback redirect (127.0.0.1, 0.0.0.0, and guest IP 10.0.0.2 → gateway +
  broker hairpin)
- IPv6 → IPv4-mapped addresses returned from `getsockname` for Node.js
- `INADDR_ANY` used for TCP listen sockets so cross-worker SYNs are accepted
- Listen ports re-registered after fork-restore; ownership tracking prevents
  fork-child clobbering of parent's listen socket

### Audit System

- Structured JSONL audit logging with PID/TID, **worker ID**, **monotonic
  nanosecond timestamps**, ioctl fd+command, IP:port correlation
- Per-session log files; broker events alongside syscall traces
- Performance: stack-based formatting, skip when disabled
- Audit-log setup unified into `run()` before worker dispatch (covers
  fork-restore and `run_worker_exec` paths)
- VS Code tasks for live tail + PowerShell pretty-printer; tasks.json
  auto-starts with `--record-baseline`

### Rootfs / Docker

- **Dockerfile is single source of truth** for reproducible rootfs
- Multi-target Dockerfile: shared base → `litebox-test` and `litebox-vscode`
- VS Code tasks use Docker bind mounts (no binary copying); WSL-native
  filesystem to avoid NTFS bind-mount limitations
- Removed ad-hoc `prepare-bash-rootfs.sh` staging
- `litebox_tool_executor/scripts/` is now bring-up-only; new `test-*`/`debug-*`/
  `verify-*` probes are forbidden there (use `litebox_test_harness` instead).
  Surviving keepers relocated under `audit/` and `vscode/`

---

## 2. LiteBox Platform Improvements

### Layered Filesystem (`litebox/src/fs/`)

- `LowerLayerWritableFiles` semantics for 9P-backed directory rootfs
- `unlink` removes from writable lower layer (not just tombstone) — fixes
  `rmdir` ENOTEMPTY on VS Code log rotation
- Tombstone-aware `read_dir` merging upper/lower entries
- Cross-layer rename → EXDEV; tombstone-aware destination checks
- Layered FS shareable cache: fix EIO on access-mode mismatch
- Synthetic `/proc` files made seekable (in-memory file, not pipe)

### Cross-Worker Connectivity

Major theme: making sockets and files behave correctly when peers live in
different worker processes (post-fork-exec).

- **Cross-worker loopback TCP**: SYN routing via broker, close-data flush,
  half-close FIN propagation, CloseWait promotion, `shutdown(Write)` preserves
  read path, `close()` never returns EAGAIN, drains TX before shutdown
- **TCP event bridge** for cross-worker unix socket accept readiness
- **Cross-worker unix sockets** backed by TCP (`UnixTransport` enum); both
  connect and accept sides; bidirectional socketpair bridging across
  `SpawnRemote` workers
- **Socketpair fd inheritance through fork+exec**: bridge non-stdio unix
  socket fds via `pipe-bridge`, install bridge on all exec worker paths
  (9P + non-9P), dup OS socketpair fds to high numbers to avoid clobbering,
  accept unix socket fds on any slot in fork snapshot
- TCP proxy: register observer on pollee for connected streams, set
  `Connected` state on accepted proxy, unified `wait_on_events` for unix
  socket accept, `pending_tcp_connections` added to backlog for epoll
  readiness

### Pipe & Fork Lifecycle

- Pipe `pair_id` made monotonic (resolved cross-agent contamination)
- Bridge threads joined before `exit_group`
- Seccomp activation deferred until after `wrgsbase`
- **vfork pipe ring-buffer**: restore pipe position after vfork child exits
  (fixes shared ring buffer corruption)
- Mux relay pipes created `NON_BLOCKING` for dispatch end; orphan pipe data
  routed via local-pipe; orphan mux data sent from main thread; old data
  drained during mux fd replacement
- Nested delayed-fork: `clone`/`vfork`/`fork` added to pre-exec allowlist;
  `read`/`wait4` in pre-exec allowlist for nested fork

### Shim Syscall Coverage (`litebox_shim_linux/`)

- **AF_NETLINK ROUTE socket** for `getifaddrs()` — virtual eth0 with MAC,
  RTM_GETLINK/RTM_GETADDR (returns smoltcp virtual IP, not Docker IP),
  MSG_PEEK|MSG_TRUNC handling
- **POSIX timers** (`timer_create` family) and **`rt_sigsuspend`** (returns
  EINTR immediately, bounded wait variant)
- `/dev/fd/N` (open, readlink, stat); `/proc/<N>/` synthetic entries; `kill -0`
  for all sandbox PIDs; `sys_kill` signal-0 uses control plane for
  cross-worker PIDs
- Terminal ioctls: TCSETS shadow (eliminated Node.js hang), TCGETS
- Credential syscalls: `geteuid`, `access`, `prctl(SetDumpable)` as no-ops
- IPv6 setsockopt mapping; `getsockname` returns v4-mapped sockaddr_in6 for
  AF_INET6
- Loopback connect: `0.0.0.0` / `10.0.0.2` mapped to loopback in
  `GlobalState::connect`

### Performance / Resource Usage

- Network worker: replaced busy-spin (100% CPU per worker) with eventfd wake
- Mux dispatcher: replaced busy-polling with `ppoll`
- Audit log: stack-based formatting, skip when disabled

### Diagnostics

- `debug_log_print` routed exclusively to `/tmp/rst-diag.log`; never to
  stdout/stderr (reserved for guest)
- RST packet detection at runner and broker transmit paths
- Listen socket lifecycle logging

---

## 3. Testing & Validation

*`litebox_test_harness` crate — process-tree integration framework*

### Test Harness Architecture

- **Coordinator** (init) drives child agents via pipe-based protocol with
  two-phase ready/go handshake
- **Declarative matrix testing**: Topology (in-process, parent→child, sibling,
  grandchild, cross-subtree) × FsScope (`/shared` vs `/tmp`) × operation
- **Protocol primitives**: `Fork`, `GetPid`,
  `NetListen`, unified `Exec` (Exec + ExecBackground merged)
- **`SpawnRemote`** for cross-worker test execution
- **`--filter=`** flag on `spawn-tree` to run specific suites
- **Runtime environment detection** in spawn-tree coordinator distinguishes
  Docker vs bare WSL2 vs litebox sandbox
- **Host-side tests** via TCP agent through port forwarding
- Missing-dependency skips now FAIL loudly (no silent passes)
- Tests reorganized into clear domain-based filters; suite ordering fixed
  (FR/LB before destructive KP)
- Zero static xfail on WSL2 native baseline

### Test Categories (current)

| Category | Coverage |
|----------|----------|
| FS I/O | 6 ops × 2 path scopes |
| Symlinks | basic, directory, dangling, nested, relative |
| Unix sockets (US) | in-process, fork-client, cross-agent, socketpair-fork bidi (US6a/b/c/d) |
| Network (LB/PR/XCONN/ADDR) | IPv4/IPv6, TCP, cross-worker, loopback variants, address matrix |
| Fork/exec | PIE vs non-PIE × open-file × fd-inheritance |
| Pipes (PN/P1/P2) | EOF lifecycle, O_NONBLOCK, fork/exec |
| TCP stress | concurrency, data integrity, reconnect, full-duplex, half-close |
| Cross-worker file (CWF) | inherited-fd EIO, hold variant, read coherence |
| File+TCP (FT) | combined 9P deadlock repro |
| Touch/redirect (TR) | file coherence |
| Bash subst (SC/SS/CC) | command substitution, stdin-piped scripts, concurrent fork/exec/pipe |
| /proc + PID (KP) | full visibility matrix, ppid, kill -0 |
| Terminal ioctl | op × fd matrix |
| Netlink | `getifaddrs` path |
| VS Code (VSI) | bootstrap replay, install-script patterns, exec server connectivity |
| Platform fixes | validation matrix |
| Fork-restore (FR), Half-close (LB), Port-router (PR), Fork-listen-close (FKLC) | regressions for specific bugs |

### Systematic Debugging Methodology

Investigate failures by reproducing in `litebox_test_harness` first, never via
audit logs or gdb against the full Docker stack (codified in `AGENTS.md` /
`CLAUDE.md`):

- **Pipe contamination**: X49–X59 isolation tests → mux relay → monotonic
  pair_id
- **Node.js exit**: EX1–EX9 → TCSETS hang → shadow ioctl
- **VS Code RST**: listen+unlisten+cross-worker connect repro → listen socket
  bypass of `do_close` → fork-restore listen re-registration
- **vfork ring buffer**: minimal pipe position tests proved shared ring buffer
  bug
- **Bash command substitution**: nested_fork capture-pipe minimal repro →
  delayed-fork fixes
- **Cross-worker unix accept**: tokio task scheduling identified as root cause

GDB remote debugging supported via `gdbserver` in Docker; `--debug` wraps the
entire `tool_executor` under it.
