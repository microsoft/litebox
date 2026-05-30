# Cross-worker shared-state inventory

Status: **complete** — discovery-only inventory grounded in the VS Code
remote server scenario. Eleven categories filled with citations into
the litebox tree, the combined-trace summaries, and the audit docs.

> **Update 2026-05-30 (Phase F.3 landed):** all references below to
> `net_proxy/` smoltcp internals and `PortRouter` describe code that
> has been DELETED. Inet sockets (TCP listener, outbound TCP, UDP,
> raw) are now broker-held `StateObject`s under `cwfd/`; host-inbound
> connections route through `BrokerHeldListenerRegistry`. The
> `net_proxy/` directory now contains only post-F.3 survivors:
> `inbound_forward.rs`, `lbnp_handshake.rs`, `lb9p_handshake.rs`,
> `host_dns.rs`. The shim no longer constructs
> `litebox::net::Network<Platform>` for linux_userland builds. See
> `PHASE_F2_SCOPING.md` and `PHASE_F3_SCOPING.md` for the deletion
> inventory.

This document inventories every category of Linux state that litebox's
multi-worker model has to share (or knowingly diverge from), grounded
in the **VS Code remote server (VSCS)** workload.

For each entry the inventory records:

- **what** the state is at the Linux level,
- **where it lives today** (broker / shim / both / host kernel / not
  implemented),
- **cross-worker mechanism** (if any),
- **status** — `OK` (works), `BROKEN` (known-bad, has a failing test
  or panic), `UNTESTED`, `GAP` (not implemented; would need
  cross-worker design if added),
- **VSCS verdict** — `HOT` / `WARM` / `COLD` / `UNKNOWN` per the
  combined-trace evidence in `docs/audit/vscode-syscall-trace-combined.md`
  and the trace summaries under
  `dev_tools/syscall_analysis/results-combined/`,
- **citations** into the code, the audit docs, and the trace summaries.

The goal is **knowing what to fix next for VSCS**, not a generic
kernel survey. Items marked `COLD` or `GAP` with no VSCS pressure
are listed for completeness but are explicitly deferral candidates.

## Evidence sources

Code (citations are against this worktree on
`wportnoy/pid-uniqueness-test`, which is rebased off
`wportnoy/vscode-server-in-litebox`):

- `litebox_shim_linux/src/syscalls/*` — per-syscall handlers + shim
  state structs (`process.rs`, `eventfd.rs`, `unix.rs`,
  `signal/*`, `net.rs`, `epoll.rs`, `file.rs`, `external_fd.rs`, …).
- `litebox/src/process/*`, `litebox/src/fd/*`, `litebox/src/net/*`,
  `litebox/src/fs/*`, `litebox/src/event/*` — shared shim types.
- `litebox_broker/src/*` — broker-hosted state:
  `nine_p/` (filesystem), `net_proxy/` (smoltcp + PortRouter),
  `cwfd/` (cross-worker fd transport, eventfd state, fd-token
  service), `audit.rs`, `policy.rs`.
- `litebox_runner_linux_userland/src/*` — per-worker glue
  (`broker_eventfd_provider.rs`, etc.).
- `litebox_test_harness/src/coordinator/*` — what's actually
  cross-worker tested (especially `vscode_shape.rs`,
  `eventfd.rs`, `pidfd_tests.rs`, `signalfd_tests.rs`,
  `scm_rights.rs`, `inotify.rs`, `pty.rs`, `pipe_bridge.rs`,
  `fork_matrix.rs`, `tcp_state.rs`).

VSCS evidence:

- `docs/audit/vscode-syscall-trace-combined.md` — capability-level
  analysis of the full combined session (connect → workspace open →
  integrated terminal → file edit → Copilot Chat) over a 146 MB,
  889 K-line, 122-unique-syscall strace.
- `docs/audit/vscode-syscall-trace.md` — connect-only predecessor.
- `dev_tools/syscall_analysis/results-combined/`:
  `top50-by-count.txt`, `syscall-unique.txt`,
  `socket-families.txt`, `key-syscalls-by-scenario.txt`.
- `dev_tools/syscall_analysis/results-native-fresh/` — earlier
  connect-only summaries.
- `docs/audit/vscode-capabilities.md` — 37-row capability matrix
  with hot/warm/cold tier.
- `docs/audit/synchronization-primitives.md`,
  `docs/audit/test-scenario-priorities.md` — derived rankings.
- `docs/audit/litebox-failures-triage.md` — known broken paths.

## Summary table

Status: 🟢 OK · 🔴 BROKEN · ⚪ UNTESTED · ⛔ GAP. VSCS:
🔥 HOT · ⚠️ WARM · 💤 COLD · ❔ UNKNOWN.

| # | State | Where today | XW mechanism | Status | VSCS | Notes |
|---|---|---|---|:-:|:-:|---|
| 1.1 | Guest pid (`Task.pid`) | per-shim, argv `--guest-pid` | argv-only at exec | 🔴 | 🔥 | PIDUNIQ panics; collisions confirmed |
| 1.2 | `ProcessId` allocator | per-shim `next_pid` from 1 | none | 🔴 | 🔥 | First fork in migrated worker collides with init pid |
| 1.3 | Parent / child links | shim registry + placeholders | host-pid bridge thread | ⚪ | 🔥 | mod.rs:620 panic implicates this |
| 1.4 | `pid_to_process_id` map | per-shim global | none | 🔴 | 🔥 | Overwritten on collision (do_fork:2791) |
| 1.5 | Host-pid side tables | per-shim + control plane | `owner_of_running_process` | ⚪ | ⚠️ | Internal bookkeeping; correctness implicated by PIDUNIQ |
| 1.6 | Pgrp / session / ctty | per-shim registry | none | ⚪ | 🔥 | TIOCSPGRP/TIOCGPGRP ×450+; cross-shim pgrp untested |
| 1.7 | Thread groups (tid/tgid) | per-shim | bounded to one worker by construction | 🟢 | ⚠️ | Threads don't migrate |
| 2.1 | Per-process fd table | per-shim | n/a (local) | 🟢 | 🔥 | Local table OK |
| 2.2 | Cross-worker fd transport | broker `BrokerStateRegistry` (CWFD) | broker handle + refcount | ⚪ | 🔥 | Active workstream; SCM_RIGHTS partial |
| 2.3 | Host fd ranges | per-worker constants (protocol) | shared constants | 🟢 | ⚠️ | Convention-enforced |
| 2.4 | dup/dup2/CLOEXEC across workers | shim fd table + posix_spawn dup2 | runner materialises file_actions | 🟢 | 🔥 | Covered by BS/PB tests |
| 3.1 | TCP/UDP smoltcp | broker `SocketSet` | broker RPC, no host fd | 🟢 | 🔥 | Long-established |
| 3.2 | PortRouter (bind) | broker | broker RPC | 🟢 | 🔥 | SO_REUSEPORT recently fixed |
| 3.3 | Unix domain sockets | shim `UnixTransport` + CWFD | partial | 🔴 | 🔥 | SCM_RIGHTS drops inet fds (unix.rs:704); ext-host blocker |
| 3.4 | Netlink | per-shim | none | ⚪ | 💤 | Defer |
| 3.5 | Raw / packet sockets | not implemented | n/a | ⛔ | 💤 | Defer |
| 4.1 | shm-ring pipe bridge | shim + shm region | shm + broker setup | 🟢 | 🔥 | PB.*/BPipe.* cover it |
| 4.2 | FIFOs | via 9P | broker-hosted | 🟢 | 💤 | Not hot |
| 5.1 | 9P FS state | broker `nine_p/` | broker is fileserver | 🟢 | 🔥 | Foundation |
| 5.2 | OFD (offset/flags) | broker 9P `Fid` | broker-hosted | 🟢 | 🔥 | Implicit cross-worker correctness |
| 5.3 | File locks | not implemented | n/a | ⛔ | ❔ | fcntl ×8252 but locking subset not broken out |
| 5.4 | cwd / mounts | cwd in Task; no mount() | migration argv carries cwd | 🟢/⛔ | 🔥/💤 | cwd hot, mount cold |
| 5.5 | inotify | per-shim | per-shim today | ⚪ | 🔥 | ×1343 — vs-code-blocker (audit upgrade) |
| 5.6 | fanotify | not implemented | n/a | ⛔ | 💤 | Defer |
| 5.7 | `/proc/<pid>/*` cross-worker | 9P + worker→broker reports | broker mediates | 🟢 | 🔥 | KPX.* covers |
| 6.1 | eventfd | shim counter + broker provider | `BrokerEventfdProvider` | 🟢 | 🔥 | Cross-worker poll wakeup landed |
| 6.2 | timerfd | per-shim | none | ⚪ | 💤 | Defer |
| 6.3 | signalfd | not implemented | n/a | ⛔ | 💤 | Defer |
| 6.4 | pidfd | per-shim; XW rejected | rejection at sys_pidfd_open | 🔴 | ⚠️ | Cross-worker pidfd_open blocked |
| 6.5 | futex | per-shim address-space | shared futex untested | 🟢/⚪ | 🔥 | Private futex hot; cross-process shared rare |
| 7.1 | Signal mask / pending | per-task | broker `owner_of_running_process` for cross-shim kill | ⚪ | ⚠️ | rt_sigaction/procmask hot but in-process |
| 7.2 | Pgrp signal delivery | per-shim iteration | no XW fanout | 🔴 | ⚠️ | Cross-worker ^C in terminal would break |
| 7.3 | Handler / disposition | per-process | reset on execve | 🟢 | 🔥 | Linux-standard |
| 7.4 | SIGCHLD on XW child exit | bridge thread + `exit_process_with_callback` | host-pid wait + callback | 🔴 | 🔥 | Panic site (process/mod.rs:620) |
| 7.5 | SIGWINCH on resize | shim PTY handler + pgrp delivery | local pgrp only | ⚪ | 🔥 | TIOCSWINSZ ×33 |
| 7.6 | RT signals | per-task | per-shim | ❔ | ❔ | Not visible in trace |
| 8.1 | Zombie + wait4 | shim registry | bridge thread sets Zombie | 🔴 | 🔥 | PIDUNIQ panic occurs here |
| 8.2 | Exit notification fan-out | bridge thread + control plane | host-pid wait | 🔴 | 🔥 | Stale-id race |
| 8.3 | PR_SET_PDEATHSIG | per-process | XW delivery not designed | ⚪ | ⚠️ | Audit row 17 missing |
| 8.4 | INIT reparenting | shim registry (process/mod.rs:657) | per-shim only | 🟢/⚪ | ⚠️ | Cross-shim untested |
| 9.1 | SysV IPC | not implemented | n/a | ⛔ | 💤 | Defer |
| 9.2 | POSIX shm / mqueue | not implemented | n/a | ⛔ | 💤 | Defer |
| 9.3 | memfd_create | per-shim | none | ⚪ | 💤 | Defer (XW sharing untested) |
| 9.4 | Namespaces / unshare | not implemented | n/a | ⛔ | 💤 | Defer |
| 9.5 | prctl global state | per-process | survives execve | 🟢 | 🔥-ish | PR_SET_NAME/DUMPABLE dominant |
| 10.1 | rlimits | per-process | argv-carried at migration | ⚪ | ⚠️ | prlimit64 ×786 |
| 10.2 | getrusage / times | per-process | n/a (local) | ⚪ | ❔ | Untested |
| 10.3 | CPU affinity / sched | passthrough/fixed | n/a | 🟢 | 💤 | Cold |
| 10.4 | nice / priority | n/a | n/a | ❔ | ❔ | Not hot |
| 11.1 | Audit log | broker | broker-hosted by design | 🟢 | — | Internal |
| 11.2 | getrandom | per-shim | uncorrelated bytes, no sharing needed | 🟢 | 🔥 | ×680 |
| 11.3 | uname / hostname | per-shim fixed | identical across workers | 🟢 | 🔥 | Trivial |
| 11.4 | uid / gid / caps | per-task | argv-carried at migration | 🟢 | 🔥 | get{e,}{u,g}id hot |

### What stands out

- **All four 🔴 BROKEN-with-🔥-HOT rows cluster around the process
  tree**: 1.1 / 1.2 / 1.4 (pid identity & maps), 7.4 / 8.1 / 8.2
  (cross-worker exit + wait), and 7.2 (pgrp signal fanout). They
  share a root cause: per-shim ProcessRegistry + no global pid
  identity → the bridge thread that signals exit can land on a
  stale ProcessId, panicking at `mod.rs:620`. PIDUNIQ surfaced
  this; fixing pid allocation likely dissolves several of the
  others.
- **3.3 Unix-domain SCM_RIGHTS** is the other 🔴-🔥 row, on the
  extension-host wireup path (vs-code-blocker per audit). It's
  the active CWFD work-stream.
- **1.6 (pgrp / session / ctty) + 7.5 (SIGWINCH) + 5.5 (inotify)**
  are 🔥-HOT-but-⚪-UNTESTED at cross-worker. The audit
  flagged 1.6 and 5.5 as upgrades after the combined-trace data.
- **Almost every ⛔ GAP row is also 💤 COLD** in the combined
  trace (SysV IPC, POSIX shm/mqueue, namespaces, fanotify,
  signalfd, file locks where evidence available). Deferral is
  evidence-backed.
- **The two well-established broker-hosted surfaces (smoltcp net,
  9P fs) carry the highest syscall counts (~70 K read+write,
  ~80 K stat/openat) without trouble.** They're the existence
  proof that the broker-hosted approach scales — and the reason
  the natural fix shape for the broken rows is "host it in the
  broker too."

## 1. Process identity & tree

### 1.1 Guest pid (`Task.pid`)
- **What**: the Linux-visible pid returned by `getpid()` / `getppid()`,
  carried in `Task.pid` and into a new worker's init task via the
  `--guest-pid` CLI flag.
- **Where**: per-shim `Task` field; CLI parsed in
  `litebox_runner_linux_userland/src/lib.rs:163` and threaded into
  the new worker's init `Task.pid`. Passed at spawn from
  `litebox_platform_linux_userland/src/lib.rs:1431`.
- **XW mechanism**: argv-only at exec/migration time. After spawn,
  the new shim has no way to coordinate with the parent shim about
  subsequent pid allocations.
- **Status**: 🔴 BROKEN. Demonstrated by
  `PIDUNIQ.cross_bt_nonpie` / `.cross_bt_diverse` on
  `wportnoy/pid-uniqueness-test`: cross-worker forks produce
  colliding pids and trigger a panic at
  `litebox/src/process/mod.rs:620` ("process must exist").
- **VSCS**: 🔥 HOT. `getpid` ×2 131 in combined trace
  (`top50-by-count.txt:27`), plus `wait4` ×1 110
  (`top50-by-count.txt:41`); pid identity also reads through every
  `/proc/<pid>/*` and `kill` call. Bash and Node both observe pids.
- **Citations**:
  `litebox/src/process/mod.rs:471` (`pub struct ProcessRegistry`),
  `:473` (`next_pid: AtomicU32`),
  `:487` (`AtomicU32::new(1)` — per-shim start),
  `:511` (`fetch_add(1)`);
  `litebox_runner_linux_userland/src/lib.rs:163` (CLI);
  `litebox_platform_linux_userland/src/lib.rs:1431`
  (argv injection at spawn).

### 1.2 `ProcessId` / `ProcessRegistry`
- **What**: shim-local handle for a process; allocated by
  `ProcessRegistry::next_pid` from 1.
- **Where**: per-shim `ProcessRegistry` (`litebox/src/process/mod.rs:471`).
- **XW mechanism**: none. Each worker starts fresh at `ProcessId(1)`
  for its own init.
- **Status**: 🔴 BROKEN. The current within-shim
  `ProcessId.0 == Task.pid` coincidence collapses as soon as the
  parent has migrated a process: the migrated init's `pid` (from
  argv) and the next freshly-allocated `ProcessId.0` collide.
- **VSCS**: 🔥 HOT (same syscalls as 1.1).
- **Citations**: same as 1.1; first-fork collision walked through
  in checkpoint 010.

### 1.3 Parent / child links
- **What**: `entry.context.parent` and `entry.children` in the
  registry; used by `wait4` to find reapable zombies and by
  reparent-to-INIT on parent exit.
- **Where**: `litebox/src/process/mod.rs` (ProcessRegistry entries);
  reparenting site at `litebox/src/process/mod.rs:657`.
- **XW mechanism**: parent shim creates a *placeholder* `Task` in its
  registry that owns the migrated child; the new worker is the
  "true" host of that ProcessId. Bookkeeping bridges via host pids.
- **Status**: ⚪ UNTESTED at the cross-worker tree level outside
  the PIDUNIQ test; the panic at `mod.rs:620` indicates the
  exit-notification path here has a stale-id bug.
- **VSCS**: 🔥 HOT. `wait4` ×1 110, `clone` ×695, `clone3` ×92,
  `execve` ×758 (`top50-by-count.txt:41, :47, …`).
  Extension-host spawn pattern relies on parent/child correctness.
- **Citations**: `litebox/src/process/mod.rs:620` (panic site),
  `:657` (INIT reparent), `:471` (registry).

### 1.4 `pid_to_process_id` / `pid_to_thread`
- **What**: side tables mapping the Linux-visible pid back to the
  shim's `ProcessId` / thread handle. `pid_to_process_id` is used
  by every `kill(pid, …)`, `pidfd_open`, `/proc/<pid>` lookup.
- **Where**: shim-global (`litebox_shim_linux/src/syscalls/process.rs`
  — accessed at `:1750` for pidfd_open, `:2791` in do_fork).
- **XW mechanism**: none. Each shim has its own map.
- **Status**: 🔴 BROKEN. `do_fork` unconditionally overwrites the
  entry for the freshly-allocated guest pid; if a migrated init
  already had that pid, the mapping is silently lost.
- **VSCS**: 🔥 HOT. `kill` is on the combined-trace unique list
  (`syscall-unique.txt`); every `/proc/<pid>` read traverses this
  map.
- **Citations**: `litebox_shim_linux/src/syscalls/process.rs:1750`,
  `:2791`.

### 1.5 Host-pid / pidfd side tables
- **What**: `fork_child_host_pids` (BTreeMap<u32, i32>),
  `process_thread_handles` (per-shim handle to spawned thread),
  `control_plane.owner_of_running_process` (which worker host
  currently owns a given ProcessId).
- **Where**: per-shim globals;
  `litebox_shim_linux/src/syscalls/process.rs:914-924` (thread
  handles), `:1057` (`owner_of_running_process` lookup), `:6377-6405`
  (fork_child_host_pids drain on exit), `:1193`
  (cross-worker parent_pid lookup).
- **XW mechanism**: `owner_of_running_process` is the closest thing
  to a global; it's hosted in the broker-adjacent control plane.
  The other two are strictly per-shim.
- **Status**: ⚪ UNTESTED for cross-worker cleanup correctness;
  the PIDUNIQ panic implicates this layer too.
- **VSCS**: ⚠️ WARM. Internal to the shim; user code doesn't see
  these directly, but pidfd_open (×6) and wait4 (×1110) depend on
  them.
- **Citations**: as above.

### 1.6 Process groups / sessions / controlling tty
- **What**: `pgid` for `setpgid`/`getpgid`/`tcsetpgrp` (foreground
  pgrp on a tty), `sid` for `setsid`. The controlling tty (and its
  foreground pgrp) is the dominant terminal-affordance state.
- **Where**: `litebox/src/process/mod.rs:53` (`ProcessGroupId(pub u32)`),
  `:70` (`SessionId`), `:992` (`process_group_exists_in_session`).
  Syscall entry points: `litebox_shim_linux/src/syscalls/process.rs:8295`
  (`sys_getpgid`), `:8321` (`sys_setpgid`), `:8350` (`sys_getsid`),
  `:8369` (`sys_setsid`).
- **XW mechanism**: none documented. Process groups span workers in
  Linux but here are scoped to a single shim's `ProcessRegistry`.
- **Status**: ⚪ UNTESTED for cross-worker pgrp membership. Local
  `PTY.tioc{g,s}pgrp.*` tests exist
  (`litebox_test_harness/src/coordinator/pty.rs:202-205`).
- **VSCS**: 🔥 HOT. From combined trace:
  `TIOCGPGRP` ×453, `TIOCSPGRP` ×21, `TIOCSWINSZ` ×33,
  `setsid` ×13, `setpgid` (on `syscall-unique.txt`). All explicitly
  vs-code-blocker per
  `docs/audit/vscode-syscall-trace-combined.md:147-160`.
- **Citations**: as above.

### 1.7 Thread groups (tids vs pids)
- **What**: `tgid` (Linux's "pid" for a multi-threaded process) vs
  `tid` (kernel pid per thread). `gettid` returns the latter.
- **Where**: per-shim `ProcessRegistry` allocates thread ids
  separately from process ids; `reserve_thread_id` advances
  `next_thread_id` independently.
- **XW mechanism**: none; threads don't migrate across workers
  (each shim hosts the full `CLONE_THREAD` group locally).
- **Status**: 🟢 OK at the cross-worker level (thread groups are
  bounded to a single worker by construction), but the local id
  allocator shares the collision risk of 1.2 once a migrated init's
  pid is in play.
- **VSCS**: ⚠️ WARM. `gettid` is on the unique list; `clone` with
  `CLONE_THREAD` is the Node/V8 worker pool.
- **Citations**: registry as 1.2.

---

## 2. File descriptor table

### 2.1 Per-process fd table
- **What**: shim-local map from guest fd number → owned object
  (file, socket, pipe, eventfd, etc.). Each `OwnedFd.raw` is the
  guest-visible fd index, not a host fd.
- **Where**: `litebox/src/fd/mod.rs:1092` (`OwnedFd`); fd table is
  in `litebox/src/fd/` (`mod.rs` + submodules).
- **XW mechanism**: per-process and per-shim; not directly shared
  across workers. fd inheritance across `posix_spawn` happens via
  the cross-worker fd transport (see 2.2).
- **Status**: 🟢 OK locally; the cross-worker side is the CWFD
  work (2.2).
- **VSCS**: 🔥 HOT (close ×17 317, dup2 ×851, fcntl ×8 252 —
  `top50-by-count.txt`).
- **Citations**: `litebox/src/fd/mod.rs:1092`,
  `litebox/src/fd/mod.rs:662` (`PassedFd`).

### 2.2 Cross-worker fd transport (CWFD)
- **What**: mechanism for migrating fd-backed objects (eventfd
  counters, sockets, file handles) between workers when a process
  migrates via `posix_spawn`/`execve` or when fds are sent via
  `SCM_RIGHTS`.
- **Where**: `litebox_broker/src/cwfd/` (`state_registry.rs:162`
  `pub struct BrokerStateRegistry`, `state_service.rs`,
  `fd_token_service.rs`, `fd_tokens.rs`, `subscription_list.rs`).
- **XW mechanism**: broker hosts the canonical kernel-shaped state;
  each worker holds an opaque `StateHandle` and RPCs in.
  Refcount-aware (see `BrokerStateRegistry::dup` /
  `StateRegistryError::RefcountOverflow`).
- **Status**: ⚪ UNTESTED at full coverage; this is the active
  workstream (see prior CWFD checkpoints in this session).
  Eventfd cross-worker poll wakeup landed
  (checkpoint 005); SCM_RIGHTS still drops fds for inet
  (per stored memory at `unix.rs:704-734`).
- **VSCS**: 🔥 HOT. SCM_RIGHTS ×4 in combined trace
  (`vscode-syscall-trace-combined.md:117-127`) on the
  `VSCODE_EXTHOST_IPC_SOCKET` extension-host wireup — explicitly
  vs-code-blocker. Eventfd2 ×28, socketpair ×262 also imply heavy
  fd-bearing-object lifecycle.
- **Citations**: as above + `litebox_shim_linux/src/syscalls/net.rs:1962-1966`
  (SCM_RIGHTS parse — sendmsg path).

### 2.3 Host fd ranges
- **What**: convention to avoid collisions between stdio,
  bridge fds, and infrastructure fds during `posix_spawn`/dup2.
- **Where**: `litebox_platform_linux_userland/src/lib.rs:61`
  (`PARENT_BRIDGE_FD_MIN=100`), `:66`
  (`WORKER_BRIDGE_FD_MIN=200`), `:72` (`INFRA_FD_MIN=500`).
- **XW mechanism**: each worker observes the same constants. The
  ranges aren't shared state — they're a *protocol* enforced by all
  workers.
- **Status**: 🟢 OK by convention. Memory-store fact:
  "All new fd allocation in `litebox_platform_linux_userland` must
  respect these ranges. Use the named constants — never hardcode
  fd minimums."
- **VSCS**: ⚠️ WARM (internal; touches every fd-bearing migration).
- **Citations**: as above; `:1359, :1815, :2570` are
  usage sites.

### 2.4 dup / dup2 / CLOEXEC across workers
- **What**: `dup`/`dup2` semantics including close-on-exec flag
  preservation across `posix_spawn`.
- **Where**: fd table impl in `litebox/src/fd/` plus
  `posix_spawn` dup2 in
  `litebox_platform_linux_userland/src/lib.rs` (worker-spawn path).
- **XW mechanism**: the parent shim records `posix_spawn_file_actions`
  including dup2 ops; the new worker materialises them at startup
  via `litebox_runner_linux_userland`.
- **Status**: 🟢 OK for the cases exercised by existing tests
  (`BS.*` bridge stdio, `PB.*` pipe bridge); cross-bt fd inheritance
  is the active CWFD workstream.
- **VSCS**: 🔥 HOT. `dup2` ×851 combined; CLOEXEC is part of every
  `O_CLOEXEC` flag on openat (×11 830).
- **Citations**: `litebox_platform_linux_userland/src/lib.rs`
  worker-spawn dup2 plumbing.

---

## 3. Sockets

### 3.1 TCP/UDP via smoltcp `SocketSet`
- **What**: TCP and UDP socket state (handles, connection state,
  send/recv buffers) lives in a single smoltcp `SocketSet` shared
  by all workers via broker RPC.
- **Where**: `litebox_broker/src/net_proxy/mod.rs:157`
  (`pub struct PortRouter`); device/dns submodules under
  `net_proxy/`.
- **XW mechanism**: workers hold `SocketProxy` shim-side handles
  (`litebox_shim_linux/src/syscalls/net.rs:183`); broker owns
  the actual smoltcp socket. No worker has a host fd.
- **Status**: 🟢 OK (long-established broker-hosted state).
  Cross-worker scenarios covered by `TCP.*` and `tcp_state.rs`
  coordinator tests.
- **VSCS**: 🔥 HOT. connect ×851, sendto ×1 932, recvfrom ×18 423,
  shutdown ×214 (`top50-by-count.txt:43-58`).
- **Citations**: as above.

### 3.2 PortRouter (inet binding)
- **What**: maps `bind(port)` calls to the broker's listener
  registry; allows multiple workers to "share" a listen socket via
  `SO_REUSEPORT`-style coordination.
- **Where**: `litebox_broker/src/net_proxy/mod.rs:157`.
- **XW mechanism**: broker-hosted (same as 3.1).
- **Status**: 🟢 OK. Covered by `PR.*` coordinator family
  (`port_router.rs`), with recent `SO_REUSEPORT` fix
  (commit `e6c7c8da`).
- **VSCS**: 🔥 HOT. VS Code Server `listen()` flows through here.
- **Citations**: as above.

### 3.3 Unix domain sockets (`UnixTransport`)
- **What**: AF_UNIX listeners, bound paths, accepted sockets, and
  SCM_RIGHTS fd-carry across workers.
- **Where**: `litebox_shim_linux/src/syscalls/unix.rs`,
  including the `UnixTransport` enum at `:704`.
- **XW mechanism**: partially broker-hosted (paths registered for
  bind/connect resolution); SCM_RIGHTS fd transfer goes through CWFD
  (2.2).
- **Status**: 🔴 PARTIAL. From stored memory:
  `UnixTransport::Tcp::try_sendto drops passed_fds entirely today`
  (`unix.rs:704-734`). Inet-over-Unix path is not yet wired through
  CWFD.
- **VSCS**: 🔥 HOT. SCM_RIGHTS ×4 on the extension-host critical
  path; socketpair ×262; AF_UNIX is the IPC backbone between server
  and extension host.
- **Citations**: `litebox_shim_linux/src/syscalls/unix.rs:704-734`;
  `vscode-syscall-trace-combined.md:117-127`.

### 3.4 Netlink
- **What**: NETLINK_ROUTE / NETLINK_AUDIT etc.
- **Where**: `litebox_shim_linux/src/syscalls/netlink.rs`.
  Test family: `special_cases::register_netlink`.
- **XW mechanism**: per-shim; not cross-worker shared.
- **Status**: ⚪ UNTESTED for cross-worker scenarios; per-shim
  coverage exists.
- **VSCS**: 💤 COLD. No netlink syscalls visible in
  `syscall-unique.txt` (122 entries; netlink absent).
- **Citations**: as above.

### 3.5 Raw / packet sockets
- **VSCS**: 💤 COLD (not in `syscall-unique.txt`).
- **Status**: ⛔ GAP (not implemented). Deferral safe.

---

## 4. Pipes & FIFOs

### 4.1 shm-ring pipe bridge
- **What**: cross-worker pipe implementation backed by shared
  memory rings, used when a pipe spans worker boundaries.
- **Where**: shim side in `litebox/src/pipes.rs`,
  `litebox_shim_linux/src/syscalls/external_fd.rs`; shared shm ring
  primitive in `litebox_common_*` crates.
- **XW mechanism**: shm region + atomic indices; broker mediates
  setup (handshake via fd-token).
- **Status**: 🟢 OK at the basic level (covered by `PB.*`,
  `BPipe.*`, `nonpie_pipe_chain` families). `pipe-bridge` and
  `pipe_nonblock` recently fixed.
- **VSCS**: 🔥 HOT. pipe2 (`syscall-unique.txt`) + the large
  `read`/`write` syscall counts presumably include pipe traffic
  between sshd, VS Code Server, and the extension host.
- **Citations**: `litebox_test_harness/src/coordinator/pipe_bridge.rs`
  (test surface), shim impl at `external_fd.rs`.

### 4.2 FIFO (named pipe)
- **VSCS**: 💤 COLD. `mkfifo` not on unique list.
- **Status**: implementation through 9P (file open with FIFO mode);
  not on a cross-worker hot path.

---

## 5. Filesystem

### 5.1 9P filesystem state
- **What**: directory entries, file metadata, open-file state for
  all guest filesystem access.
- **Where**: `litebox_broker/src/nine_p/` (`server.rs`, `fcall.rs`,
  `transport.rs`, `fs_compat.rs`).
- **XW mechanism**: broker is the file server; each worker is a
  9P client. Canonical kernel-shaped state lives in the broker.
- **Status**: 🟢 OK as a foundation. Per-file behaviours
  (OFD, locks, inotify) are separately tracked below.
- **VSCS**: 🔥 HOT. statx ×23 246, openat ×11 830, newfstatat
  ×13 284, getdents64 ×6 101, utimensat ×2 978
  (`top50-by-count.txt`). FS traffic dominates.
- **Citations**: `litebox_broker/src/nine_p/mod.rs`.

### 5.2 Open File Description (OFD) — offset + flags
- **What**: per-open-fd seek offset and status flags shared between
  `dup`'d fds and across `fork`.
- **Where**: broker-side 9P `Fid` state (`nine_p/server.rs`).
- **XW mechanism**: broker-hosted by construction.
- **Status**: 🟢 OK for standard read/write/lseek; cross-worker
  `dup`'d offsets implicitly correct because broker owns them.
- **VSCS**: 🔥 HOT (lseek ×1 673, every pread/pwrite).
- **Citations**: `nine_p/server.rs`.

### 5.3 File locks (flock, POSIX, OFD)
- **What**: `flock(2)`, `fcntl(F_SETLK)`, OFD locks
  (`F_OFD_SETLK`).
- **Where**: not visibly implemented — no `sys_flock` found in
  `litebox_shim_linux/src/syscalls/`. `fcntl` exists but the
  `F_SETLK` cases would need broker coordination.
- **XW mechanism**: ⛔ GAP. Would need broker-side lock table.
- **VSCS**: ❔ UNKNOWN. `flock` not on
  `syscall-unique.txt`; `fcntl` ×8 252 but those are mostly flag
  reads (F_GETFL/F_SETFL/F_GETFD/F_SETFD/F_DUPFD). Locking
  subset not separately broken out — would need raw-trace grep.
- **Citations**: absence in `litebox_shim_linux/src/syscalls/`.

### 5.4 Mounts / cwd / rootfs
- **What**: per-process cwd, mount table.
- **Where**: cwd in `Task`; rootfs is a flag at runner startup
  (`--rootfs`). No mount syscall implementation.
- **XW mechanism**: cwd is per-process and travels with the process
  via the migration metadata; mounts effectively don't exist at the
  guest level.
- **Status**: 🟢 OK for cwd. ⛔ GAP for mounts (no `mount`/`umount2`
  in shim).
- **VSCS**: 🔥 HOT for cwd (chdir, getcwd on `syscall-unique.txt`);
  💤 COLD for mount/umount2/pivot_root (explicitly cold per
  `vscode-syscall-trace-combined.md:129-145`).
- **Citations**: `litebox_shim_linux/src/syscalls/file.rs`
  chdir/getcwd handlers.

### 5.5 inotify
- **What**: per-process inotify instances + per-instance watch
  list keyed by inode/path. Events queued on the inotify fd.
- **Where**: `litebox_shim_linux/src/syscalls/file.rs:4641` (init1),
  `:4681` (add_watch), `:4701` (rm_watch). Test family:
  `litebox_test_harness/src/coordinator/inotify.rs`.
- **XW mechanism**: per-shim today; events generated by 9P
  operations would need broker-side fanout if cross-worker watchers
  must see writes from another worker.
- **Status**: ⚪ UNTESTED for cross-worker event delivery
  specifically.
- **VSCS**: 🔥 HOT (audit-upgraded vs-code-blocker).
  `inotify_add_watch` ×1 343, `inotify_init1` ×2
  (`vscode-syscall-trace-combined.md:84-86`). +268× over connect-only.
- **Citations**: as above.

### 5.6 fanotify
- **Status**: ⛔ GAP (no fanotify in shim).
- **VSCS**: 💤 COLD (explicit cold list).

### 5.7 `/proc/<pid>/*` cross-worker views
- **What**: `/proc/<pid>/cmdline`, `/stat`, `/status`, `/fd`, etc.
  reading another worker's process metadata.
- **Where**: 9P-backed proc emulation in `litebox_broker/src/nine_p/`;
  shim helpers for pid → metadata.
- **XW mechanism**: broker mediates the read; each worker reports
  its processes' metadata to the broker (or via `owner_of_running_process`).
- **Status**: 🟢 OK in the basic case (covered by `KPX.*` family,
  `KP.proc_self.*`). Recent fix
  `fix: proc — track cmdline per pid` indicates active maintenance.
- **VSCS**: 🔥 HOT. Per
  `docs/audit/vscode-capabilities.md:18-19`, /proc reads are
  on the VS Code Server warm path.
- **Citations**: `nine_p/` + `KPX.*` tests.

---

## 6. Sync primitives (shim-emulated)

### 6.1 eventfd
- **What**: 64-bit counter + read/write semantics with
  EFD_SEMAPHORE and EFD_NONBLOCK variants.
- **Where**: `litebox_shim_linux/src/syscalls/eventfd.rs:31`
  (`EventfdSubsystem` / `EventFile` /
  `EventFileInner::Eventfd { counter: u64, semaphore: bool }`,
  per stored memory).
- **XW mechanism**: data plane via broker-hosted
  `BrokerEventfdProvider` (memory: trait in
  `litebox_common_linux::broker_eventfd_provider`, impl in
  `litebox_runner_linux_userland::broker_eventfd_provider`; shim
  accesses via `OnceBox<Arc<dyn BrokerEventfdProvider>>` —
  `eventfd.rs:39-60`). Cross-worker poll wakeup landed in
  checkpoint 005.
- **Status**: 🟢 OK for basic counter + cross-worker poll; some
  fork-inherit edge cases still in flight.
- **VSCS**: 🔥 HOT. `eventfd2` ×28 combined;
  `EV.cross_agent_wakeup.*` + `EV.fork_inherit.*` cover the
  cross-worker dimensions.
- **Citations**: `eventfd.rs:31-95`, `:39-60`.

### 6.2 timerfd
- **Where**: `litebox_shim_linux/src/syscalls/file.rs:4710`
  (create), `:4760` (settime), `:4794` (gettime).
- **XW mechanism**: per-shim today; cross-worker timer delivery
  would need broker-side timer dispatch.
- **Status**: ⚪ UNTESTED at cross-worker.
- **VSCS**: 💤 COLD. `timerfd_create/settime/gettime` all in the
  explicit cold list (`vscode-syscall-trace-combined.md:129-145`).
  Per `vscode-capabilities.md` row 13, still 💤 even with audit
  re-ranking.
- **Citations**: as above.

### 6.3 signalfd
- **Status**: ⛔ GAP. No `sys_signalfd` found.
- **VSCS**: 💤 COLD (explicit cold list).
- **Citations**: absence in `syscalls/`; row 12 of
  `vscode-capabilities.md` ranks it 💤.

### 6.4 pidfd
- **What**: `pidfd_open`, pidfd readiness via epoll, `pidfd_send_signal`,
  `pidfd_getfd`.
- **Where**: `litebox_shim_linux/src/syscalls/process.rs:1737`
  (`sys_pidfd_open`); test family
  `litebox_test_harness/src/coordinator/pidfd_tests.rs`,
  `epoll_pidfd.rs`.
- **XW mechanism**: shim rejects cross-worker pidfd_open on a
  remote-owned running process today (see `:1755`
  `reject_remote_running_process_control`). Local pidfd works.
- **Status**: 🔴 PARTIAL. Cross-worker pidfd_open is intentionally
  blocked; cross-worker pidfd readiness on epoll wakes was the
  subject of recent fixes.
- **VSCS**: ⚠️ WARM. `pidfd_open` ×6 combined; explicit
  `pidfd_send_signal` / `pidfd_getfd` cold
  (`vscode-syscall-trace-combined.md:135-136`).
- **Citations**: as above.

### 6.5 futex
- **What**: `FUTEX_WAIT` / `FUTEX_WAKE` on a memory address;
  `FUTEX_PRIVATE_FLAG` controls private (process-local) vs shared
  (across address spaces).
- **Where**: `litebox_shim_linux/src/syscalls/process.rs:8492`
  (`sys_futex`).
- **XW mechanism**: private futexes are per-shim by construction.
  Shared futexes (FUTEX_PRIVATE_FLAG=0) across two workers would
  need broker mediation; current implementation likely treats
  shared as private.
- **Status**: 🟢 OK for private; ⚪ UNTESTED / likely BROKEN for
  shared futexes across workers (rare in practice).
- **VSCS**: 🔥 HOT (top syscall by count: ×112 061), but the
  combined trace shows `set_robust_list` ×1 269 and `futex` calls
  from rust/glibc thread management — all *within* a single process.
  Cross-process shared futexes aren't visible in trace; assume not
  on VSCS critical path.
- **Citations**: as above.

---

## 7. Signals

### 7.1 Signal mask / pending set
- **What**: per-task blocked mask, per-thread `pending_signals`.
- **Where**:
  `litebox_shim_linux/src/syscalls/process.rs:157`
  (`pending_signals: Mutex<…, PendingSignals>` on Task);
  `litebox_shim_linux/src/syscalls/signal/mod.rs:530`
  (`set_signal_mask`).
- **XW mechanism**: per-shim. Cross-process signal delivery
  (`kill(pid, …)`) routes through the registry's pid lookup;
  cross-worker delivery requires the broker's
  `owner_of_running_process` to forward.
- **Status**: ⚪ UNTESTED for cross-worker `kill`-from-A-to-B
  semantics specifically.
- **VSCS**: ⚠️ WARM. `kill` on unique list; `rt_sigaction` ×11 679,
  `rt_sigprocmask` ×6 461 (`top50-by-count.txt:12, :16`) are all
  in-process disposition/mask management. Cross-process signalling
  is rare on the hot path.
- **Citations**: as above.

### 7.2 Process-group signal delivery
- **What**: `kill(-pgid, sig)` — deliver to every member of a pgrp.
- **Where**: `sys_kill` at
  `litebox_shim_linux/src/syscalls/signal/mod.rs:811`.
- **XW mechanism**: shim iterates its local pgrp membership; no
  cross-worker fanout today.
- **Status**: 🔴 BROKEN at cross-worker. A pgrp that spans workers
  (e.g. terminal shell + child subshell that migrated bts) won't
  receive a Ctrl+C correctly.
- **VSCS**: ⚠️ WARM. Integrated terminal sends pgrp signals on
  ^C/^Z; `TIOCSPGRP` pressure (×21) indicates the pgrp model is
  exercised.
- **Citations**: as above.

### 7.3 Signal handlers / disposition
- **What**: `rt_sigaction` table per process.
- **Where**: per-Task; `litebox_shim_linux/src/syscalls/signal/mod.rs`
  delivery via `signal::x86_64`.
- **XW mechanism**: per-shim; handlers don't survive `execve` (per
  Linux semantics) so migration is a no-op for disposition.
- **Status**: 🟢 OK.
- **VSCS**: 🔥 HOT (rt_sigaction ×11 679 — every process startup
  installs handlers).
- **Citations**: as above.

### 7.4 SIGCHLD on cross-worker child exit
- **What**: when a migrated child exits in worker B, the parent in
  worker A must receive SIGCHLD and observe a reapable zombie.
- **Where**: `do_true_fork` / `commit_delayed_fork` background
  thread that calls `wait_worker_host` then
  `exit_process_with_callback` (panic site at
  `litebox/src/process/mod.rs:620`).
- **XW mechanism**: broker (via control plane) tracks worker host
  exit; shim's background thread bridges that to the registry.
- **Status**: 🔴 BROKEN. The PIDUNIQ panic implicates this path.
- **VSCS**: 🔥 HOT. `wait4` ×1 110 + `clone` ×695 means SIGCHLD
  delivery is on every spawn path.
- **Citations**: `litebox/src/process/mod.rs:620`,
  `litebox_shim_linux/src/syscalls/process.rs:9316` (synchronous
  `wait_worker_host` in placeholder Task — exec_on_remote_host hang
  root cause).

### 7.5 SIGWINCH on terminal resize
- **What**: kernel sends SIGWINCH to the foreground pgrp on a tty
  when `TIOCSWINSZ` changes window size.
- **Where**: PTY handler in `litebox_shim_linux` + signal/mod.rs;
  test `PTY.resize.*` in `coordinator/pty.rs`.
- **XW mechanism**: the pgrp may span workers (see 7.2). If so,
  delivery is currently single-shim.
- **Status**: ⚪ UNTESTED at cross-worker pgrp.
- **VSCS**: 🔥 HOT. `TIOCSWINSZ` ×33 + `TIOCGPGRP` ×453
  (`vscode-syscall-trace-combined.md:88-93`) — explicit upgrade in
  the audit.
- **Citations**: as above.

### 7.6 Real-time signals
- **VSCS**: ❔ UNKNOWN (not visible in unique list at SIGRTMIN+ level).

---

## 8. Wait / exit

### 8.1 Zombie state + `wait4` / `waitid`
- **What**: zombie Task entries in the registry, drained by `wait4`.
- **Where**: `sys_wait4` at
  `litebox_shim_linux/src/syscalls/process.rs:1505`;
  `wait_for_child_inner` at `litebox/src/process/mod.rs:789`,
  matcher at `:811`.
- **XW mechanism**: parent's registry must observe the migrated
  child's zombie. Driven by the cross-worker exit-notification
  fan-out (8.2).
- **Status**: 🔴 BROKEN. PIDUNIQ panic occurs in this very path.
- **VSCS**: 🔥 HOT (wait4 ×1 110).
- **Citations**: as above.

### 8.2 Exit notification fan-out
- **What**: when a process exits, its placeholder Task in any other
  worker's registry must be transitioned to Zombie, and SIGCHLD
  delivered to the parent.
- **Where**: `exit_process_with_callback`
  (`litebox/src/process/mod.rs:600`+); driven by `do_true_fork`'s
  background thread waiting on `wait_worker_host`.
- **XW mechanism**: each parent worker spawns a host thread that
  waits on the child worker host's pid; on completion it calls
  `exit_process_with_callback` to mark the placeholder zombie.
- **Status**: 🔴 BROKEN. Stale-id race causes
  `expect("process must exist")` panic.
- **VSCS**: 🔥 HOT (same as 8.1).
- **Citations**: `litebox/src/process/mod.rs:600-657`,
  `litebox_shim_linux/src/syscalls/process.rs:6377-6405`.

### 8.3 `prctl(PR_SET_PDEATHSIG)`
- **What**: deliver a signal to the calling process when its
  parent exits.
- **Where**: `prctl` ×187 in trace; PDEATHSIG specifically not
  separately broken out.
- **XW mechanism**: would need parent worker to notify on exit.
- **Status**: ⚪ UNTESTED. Audit (`vscode-capabilities.md` row 17)
  flags PDEATHSIG as missing.
- **VSCS**: ⚠️ WARM. prctl ×187, but PDEATHSIG count unknown
  without raw trace.
- **Citations**: `vscode-capabilities.md:18` row 17.

### 8.4 INIT reparenting
- **What**: when a process exits with running children, those
  children are reparented to INIT.
- **Where**: `litebox/src/process/mod.rs:657`.
- **XW mechanism**: works per-shim. Cross-shim: a worker's INIT is
  `ProcessId(1)` in that shim; if the cross-shim parent dies, its
  children in another worker don't reparent to the *sandbox*'s
  INIT.
- **Status**: 🟢 OK within a shim; ⚪ UNTESTED at cross-shim.
- **VSCS**: ⚠️ WARM (matters for daemon-style detached processes
  in the integrated terminal).
- **Citations**: as above.

---

## 9. Namespaces & IPC (mostly gaps)

### 9.1 SysV IPC (shm, sem, msg)
- **Status**: ⛔ GAP. `shmget`/`semget`/`msgget` not in
  `syscalls/`.
- **VSCS**: 💤 COLD (none on `syscall-unique.txt`).
- **Deferral**: safe.

### 9.2 POSIX shm (`shm_open`) / mqueue (`mq_open`)
- **Status**: ⛔ GAP.
- **VSCS**: 💤 COLD.

### 9.3 memfd_create
- **Where**: `litebox_shim_linux/src/syscalls/file.rs:4585`
  (`sys_memfd_create`) — handler exists.
- **XW mechanism**: per-shim; sharing a memfd across workers would
  need fd-token transport (2.2).
- **Status**: ⚪ UNTESTED at cross-worker.
- **VSCS**: 💤 COLD (explicit cold list).

### 9.4 Namespaces (PID/mount/net/user) + `unshare`
- **Status**: ⛔ GAP. The sandbox itself is a single namespace
  context; nested namespaces aren't supported.
- **VSCS**: 💤 COLD (`unshare` on cold list).

### 9.5 `prctl` global state (NO_NEW_PRIVS, dumpable, name)
- **VSCS**: 🔥 HOT-ish — `prctl` ×187 combined. Most are
  `PR_SET_NAME` (thread names) and `PR_SET_DUMPABLE`.
- **XW mechanism**: per-process state; survives execve but doesn't
  need cross-worker sharing.
- **Status**: 🟢 OK for common prctl args.

---

## 10. Time & scheduling

### 10.1 rlimits
- **What**: `getrlimit`/`setrlimit`/`prlimit64`.
- **Where**: `litebox_shim_linux/src/syscalls/process.rs:7647`
  (`sys_prlimit`), `:7677` (`sys_getrlimit`), `:7688`
  (`sys_setrlimit`).
- **XW mechanism**: per-process; if a parent sets a rlimit and
  forks across workers, the child should inherit it — that's
  carried via migration metadata.
- **Status**: ⚪ UNTESTED cross-worker.
- **VSCS**: ⚠️ WARM (prlimit64 ×786, `top50-by-count.txt:46`).
- **Citations**: as above.

### 10.2 getrusage / times
- **Where**: `:7994` (`sys_getrusage`).
- **VSCS**: ❔ UNKNOWN (not on unique list at top — would be in tail).
- **Status**: ⚪ UNTESTED.

### 10.3 CPU affinity / scheduler policy
- **Where**: `:8453` (`sys_sched_getaffinity`), `:8459`
  (`sys_sched_setscheduler`).
- **VSCS**: 💤 COLD (sched_setaffinity on cold list).
- **Status**: 🟢 OK (passthrough or fixed-value).

### 10.4 nice / priority
- **VSCS**: ❔ UNKNOWN; not on hot list.

---

## 11. Auxiliary

### 11.1 Audit log
- **Where**: broker hosts the audit log fd; shim writes via the
  worker. `litebox_broker/src/audit.rs`.
- **XW mechanism**: broker-hosted (shared by design).
- **Status**: 🟢 OK.
- **VSCS**: not user-visible.

### 11.2 getrandom / random pool
- **Where**: `litebox_shim_linux/src/syscalls/misc.rs:17`
  (`sys_getrandom`).
- **XW mechanism**: each shim has its own RNG; no sharing required
  (kernel's getrandom is global but its contract is just
  "uncorrelated random bytes").
- **Status**: 🟢 OK.
- **VSCS**: 🔥 HOT (getrandom ×680, `top50-by-count.txt:48`).

### 11.3 uname / hostname
- **Where**: `litebox_shim_linux/src/syscalls/misc.rs:78`
  (`sys_uname`).
- **XW mechanism**: returns fixed-value sandbox uname; same in
  every worker by construction.
- **Status**: 🟢 OK.
- **VSCS**: 🔥 HOT (uname on unique list).

### 11.4 uid / gid / capabilities
- **Where**: per-task uid/gid in `Task`; capabilities mostly
  passthrough.
- **VSCS**: 🔥 HOT (geteuid ×1 263, getuid ×1 221, getgid ×1 207,
  getegid ×1 207, getgroups, set{fs}{uid,gid}).
- **XW mechanism**: travels with the process via migration argv.
- **Status**: 🟢 OK.

