# Test scenario priorities + coverage gaps

This doc combines:

- **View A** — per-family priority table for **trimming low-value
  tests** (P4) and **focusing fix attention** on high-pressure rows
  (P0+P1).
- **View B** — coverage-by-capability **gaps view** ★. The direct
  answer to "what are the testing gaps?" — capabilities VS Code
  Remote-SSH actually exercises but where the test suite has no
  coverage or only weak coverage.

Pressure data comes from the combined trace at
`docs/audit/vscode-syscall-trace-combined.md` (5-min real-VS-Code
session covering connect → workspace open → terminal → file edit →
trivial Copilot-Chat conversation; 889 K trace lines, 122 unique
syscalls). Connect-only pressure is sourced from
`docs/audit/vscode-syscall-trace.md`.

`litebox_status` is a snapshot at the time of writing. It will
drift as the parallel "fix tests in waves" work lands; the
methodology block at the end shows how to refresh.

---

## View A — per-family priority table

Pressure tiers: 🔥 hot · ⚠️ warm · 💤 cold · n/a (not exercised).
Priority tiers: **P0** drop-anything-to-fix · **P1** vs-code-blocker
· **P2** regression-risk · **P3** cleanup · **P4** trim candidate.

### Tier-1 families (recently authored, well-understood)

| family | tests | target_capability | vs_code_pressure | litebox_status | priority | notes |
|---|---:|---|---|---|---|---|
| `PTY.*` | 30 | pty alloc + `TIOCSCTTY`/`TIOCSPGRP`/`TIOCSWINSZ`/`SIGWINCH` | 🔥 (TIOCGPGRP 453, TIOCSCTTY 9, TIOCSWINSZ 33 in combined trace) | green (post W1 + shim fixes) | **P1** | tiocsctty/resize-sigwinch shim fixes already landed |
| `EPI.*` | 30 (5 scen × 6 axes incl. pie-glibc) | `epoll_create1` + `epoll_ctl` + `epoll_pwait` + `pidfd_open` | 🔥 (`epoll_pwait` is #4 syscall, 39 K calls) | green (post W2 + multi-socket shim fix) | **P1** | hottest single non-trivial syscall path; preserve as core regression |
| `CL3.*` | 20 (5 kinds × 4 axes) | `clone3` flag matrix | 🔥 (clone3 92, CLONE_THREAD 177, CLONE_VFORK 6 NEW) | green for `thread`/`process`/`with_pidfd`/`with_set_tid`/`with_cgroup`; CLONE_VFORK not yet tested | **P1** | add a `CL3.with_vfork` scenario — surfaced by combined trace |
| `EV.*` | 16 (4 scen × 4 axes) | `eventfd2` | 🔥 (28 calls; `epoll_add_eventfd` wakeups) | green | **P2** | regression coverage; not on critical path of failures |
| `IOR.*` | 9 | `io_uring_setup` consistent-ENOSYS contract | 🔥 (347 enters from VS Code; libuv falls back) | green | **P1** | **must keep** — locks in libuv fallback safety |
| `TCS.*` | 21 | stateful TCP conn registry | 🔥 (`recvmsg` 476, `setsockopt` 1385, `shutdown` 214) | green (post B + shim) | **P2** | regression coverage |
| `THC.*` | 4 | TCP half-close write→shutdown(WR)→read-EOF | 🔥 (subset of TCS pressure) | green | **P2** | partial overlap with TCS; consider deduping |
| `TLB.*` | 5 | TCP listen-busy (Node.js init delay shape) | 🔥 (post-listen connect path) | green (post readiness primitive) | **P2** | regression coverage |
| `XSI.*` | 4 | `Exec` with stdin payload | 🔥 (`execve` 758, `read` from stdin) | green (post Exec stdout fix) | **P2** | regression coverage |
| `KP.*` | 27 | `/proc/<pid>/cmdline` + `kill -0` (own + bg child) | 🔥 (`/proc` reads heavy; `wait4` 1 110, `kill` reachable via clone3 cleanup) | green | **P2** | regression coverage |
| `KPX.*` | 9 | cross-worker `/proc` visibility | ⚠️ (cross-worker `pidfd_open` 6) | green (post `/proc/<pid>/cmdline` shim fix) | **P2** | proves cross-axis pid visibility; keep |
| `FKLC.*` | 6 | `Fork.inherit_listen_ports` end-to-end | 🔥 (VS Code CLI fd-inheritance pattern) | **red** under litebox (pre-existing broker/worker routing bug — `FKLC-inherit-regression-fix` blocked todo) | **P0** | concrete bug, manifests at every Remote-SSH connect via fd-inheritance |

### Tier-2 families (heritage / capability-broad)

| family | tests | target_capability | vs_code_pressure | litebox_status | priority | notes |
|---|---:|---|---|---|---|---|
| `CF.*` | 169 | shell pipelines under fork (`pipe2_cat`, `pipe3_grep`, `pipe4_vscode` — VS Code-shaped pipe chains) | 🔥 (pipe + clone heavy) | not assessed in this pass | **P2** | the `pipe4_vscode` scenarios are direct VS-Code-shape proxies — explicitly keep |
| `CP.*` | 140 | concurrent process spawn (sh + binary-type axis) | 🔥 (`clone` 695, `execve` 758) | not assessed | **P2** | covers fork-tree under load; keep |
| `PB.*` | 118 | parent↔child pipe bridges | 🔥 (`pipe2`, `dup2` 851) | not assessed | **P2** | foundational — keep |
| `BPIPE.*` | 60 | bash pipe behavior across binary types | ⚠️ | not assessed | P3 | bash-specific; some redundancy with CF |
| `BRS.*` | 72 | bash subshell stdin redirection | ⚠️ | not assessed | P3 | bash-specific; trim candidates likely if redundant with X.exec_shell_session |
| `BR.*` | 33 | bash redirection variants | ⚠️ | not assessed | P3 | check for redundancy with BRS |
| `BS1.*` / `BS2.*` / `BS3.*` | 25 each | bash sourcing variants | ⚠️ | not assessed | P3 | likely redundancy across BS1-3 |
| `BASH.*` | 6 | bash fork-bg-fg / fork-substitution | ⚠️ | not assessed | P3 | tautology audit flagged some BASH tests as weak — re-audit |
| `US1.*`–`US5.*`, `US6.*` | 5–90 | Unix-domain socket variants | 🔥 (AF_UNIX 136, **SCM_RIGHTS confirmed real**) | not assessed | **P1** | the `US6.socketpair_*` family overlaps with VS Code's extension-host socket-pair handoff |
| `U.*` | 59 | Unix-socket listen / accept | 🔥 | not assessed | **P2** | foundational — keep |
| `UA.*` | 10 | Unix-socket abstract namespace | ⚠️ | not assessed | P3 | check VS Code abstract-socket usage in deeper trace |
| `UF.*` | 15 | Unix-socket file-backed | ⚠️ | not assessed | P3 | likely VS Code uses path-backed UDS for `/tmp/code-…` |
| `FS.*` | 90 | filesystem write-read across binary types | 🔥 (`statx` 23 K, `openat` 11 K) | not assessed | **P2** | foundational — keep |
| `F.*` | 73 | filesystem ops broad | 🔥 | not assessed | **P2** | foundational — keep but de-overlap with FS |
| `TERM.*` | 75 | terminal/tty probe (`tcgets_fd0` etc.) | 🔥 (`TCGETS` 129, `TIOCGPGRP` 453) | not assessed | **P1** | confirmed hot under terminal session |
| `XB.*` | 54 | exec basic | 🔥 (every `execve` path) | not assessed | **P2** | broad — likely some axes redundant with X |
| `XDF.*` | 53 | exec delayed-fork | ⚠️ | not assessed | P3 | check redundancy with X / FX |
| `X.*` (and `X48`–`X59`, `XW1`–`XW11`) | ~85 | exec across binary-type matrix | 🔥 | not assessed | **P2** | the 1-test-each `X48`/…/`X59` and `XW*` families may be over-fragmented; consolidation candidate |
| `XS.*` | 30 | exec stress | ⚠️ | not assessed | P3 | check for flakes |
| `XC.*` | 17 | exec compat | ⚠️ | not assessed | P3 | |
| `XCONN.*` | 7 | exec connection | ⚠️ | not assessed | P3 | |
| `XM.*` | 10 | exec mixed | ⚠️ | not assessed | P3 | |
| `XNP.*` | 15 | exec non-PIE | ⚠️ | not assessed | P3 | |

### Tier-3 families (specialized — many candidate for trim)

| family | tests | target_capability | vs_code_pressure | litebox_status | priority | notes |
|---|---:|---|---|---|---|---|
| `NL1.*`–`NL6.*` (incl. NL3b/c/d) | 45 | netlink probes (getifaddrs, sendmsg/recvmsg) | ⚠️ (`AF_NETLINK` 34 sockets — for DNS/iface lookup) | not assessed | P3 | keep at least one per kind; some are very narrow |
| `NET1.*`–`NET6.*` | 25 | network family probes | ⚠️ | not assessed | P3 | check redundancy with US/U |
| `NA.*` | 30 | network-address listing (`self_ip`) | 💤 | known pseudo-pass skip flagged in xfail-census | **P3** | the `NA.*.self_ip` pseudo-skip should become a real test or be removed (already noted in `xfail-census.md`) |
| `EXITD.*` | 30 | exit-status delivery across binary types | ⚠️ | not assessed | P3 | check redundancy with X |
| `EXIT*`/`EX1`–`EX9` | ~9 | exit code variants | ⚠️ | not assessed | P3 | likely consolidation candidates |
| `EP.*` | 20 | epoll basic (pre-W2) | 💤 partial overlap with `EPI.*` | not assessed | P3 | check for redundancy with EPI; trim if covered |
| `EXITD.256.pie-glibc` etc. | – | exit-status × binary-type matrix | ⚠️ | not assessed | P3 | matrix probably over-broad |
| `M1.*`–`M4.*` | 25 each | matrix-test variants | ⚠️ | not assessed | P3 | check for redundancy across M1-4 |
| `BS1.*`–`BS3.*` | 25 each | binary-spawn matrix | ⚠️ | not assessed | P3 | cross-check with the new "BinaryType axis" merge mentioned in canonical's last commit |
| `SS.*` | 32 | shell substitution | ⚠️ | not assessed | P3 | tautology audit flagged some as weak |
| `SP.*` | 18 | shell pipe | ⚠️ | not assessed | P3 | overlap with CF / PB |
| `SC.*` | 24 | shell command | ⚠️ | not assessed | P3 | overlap with X |
| `SK.*` | 3 | (unknown) | ? | not assessed | P3 | inspect |
| `S.*` (small) | 25 | shell broad | ⚠️ | not assessed | P3 | overlap suspected |
| `N.*` | 36 | net broad | ⚠️ | not assessed | P3 | overlap with NET / NL |
| `P1.*`/`P2.*` | 30+18 | parent-child variants | ⚠️ | not assessed | P3 | overlap with PB |
| `PR.*` | 13 | parent-routing? | ⚠️ | not assessed | P3 | inspect |
| `PN.*` | 18 | pipe nonblock | ⚠️ | not assessed | P3 | |
| `PROC.*` | 9 | /proc reads | 🔥 | not assessed | **P2** | confirmed hot — keep |
| `PID.*` | 3 | pid lookup | ⚠️ | not assessed | P3 | |
| `POLL.*` | 3 | poll(2) — note: not `epoll_pwait` | ⚠️ (`poll` 1 566 calls but `epoll_pwait` is the dominant path) | not assessed | P3 | thin coverage of `poll` syscall family — fine to keep small |
| `GSN.*` | 4 | getsockname / getpeername | ⚠️ | not assessed | P3 | |
| `NPIPE.*` | 30 | named pipe | ⚠️ | not assessed | P3 | overlap with PB |
| `FT.*` | 22 | fork transitive | ⚠️ | not assessed | P3 | overlap with FX/PB |
| `TR.*` | 15 | touch redirect | ⚠️ | not assessed | P3 | |
| `TRR.*` | 7 | touch redirect rare | ⚠️ | not assessed | P3 | |
| `TC.*` | 10 | TCP cross | ⚠️ | not assessed | P3 | overlap with TCS |
| `TD.*` | 8 | TCP depth | ⚠️ | not assessed | P3 | overlap with TCS |
| `TW.*` | 8 | TCP write | ⚠️ | not assessed | P3 | overlap with TCS |
| `CC.*` | 12 | concurrent fork | ⚠️ | not assessed | P3 | overlap with CF |
| `CSM.*` | 30 | (unknown) | ? | not assessed | P3 | inspect |
| `CWF.*` | 21 | cross-worker file | ⚠️ | not assessed | P3 | |
| `FR.*` | 27 | fork redirect | ⚠️ | not assessed | P3 | |
| `FWE.*` | 10 | (unknown) | ? | not assessed | P3 | inspect |
| `VS1.*` | 5 | VS Code-1 pattern | 🔥 (likely a VS-Code-shaped scenario) | not assessed | **P2** | inspect; keep if VS-Code-aligned |

---

## View B — coverage-by-capability gaps

For every capability seen in the combined trace at non-trivial
volume (≥ 10 calls or known critical-path) plus the canonical list
from `docs/audit/vscode-capabilities.md`. Coverage strength assessed
against the View A `target_capability` mappings.

`gap_priority`: **G0** hot + missing · **G1** hot + weak · **G2**
warm + missing/weak · **G3** cold + missing · `n/a`.

| capability | trace_count | covering_family(s) | coverage_strength | gap_type | gap_priority | recommended_action |
|---|---:|---|---|---|---|---|
| `epoll_pwait` + `epoll_ctl` + `epoll_create1` | 39 514 | `EPI.*` | strong | n/a | n/a | well-covered |
| `pidfd_open` (bare) | 6 | `EPI.pidfd_exit.*` | strong | n/a | n/a | well-covered |
| `clone3 (CLONE_THREAD)` | 177 | `CL3.thread.*` | strong | n/a | n/a | well-covered (post shim fix) |
| `clone3 (CLONE_VFORK)` ★ NEW | 6 | **MISSING** | MISSING | no_test_family | **G2** | add `CL3.with_vfork` scenario (terminal posix_spawn pattern) |
| `clone3 (with_pidfd)` | 0 | `CL3.with_pidfd.*` | over-coverage relative to trace | n/a | n/a | retain (still possible in deeper scenarios) |
| `clone3.set_tid` | 0 | `CL3.with_set_tid.*` | over-coverage | n/a | n/a | already deferred; keep test as guard |
| `eventfd2` | 28 | `EV.*` | strong | n/a | n/a | well-covered |
| `signalfd` / `signalfd4` | 0 | **MISSING** | MISSING | no_test_family | G3 | defer — cold even under combined workload |
| `timerfd_*` | 0 | **MISSING** | MISSING | no_test_family | G3 | defer |
| `inotify_add_watch` | **1 343 ★** | **MISSING** | MISSING | no_test_family | **G0** | **add `INO.*` family** — workspace file watcher; biggest single gap |
| `inotify_init1` | 2 | (no test) | MISSING | no_test_family | G2 | covered by INO.* once added |
| `fanotify_*` | 0 | **MISSING** | MISSING | no_test_family | G3 | defer |
| **`SCM_RIGHTS` fd-passing** ★ | 4 | **MISSING** | MISSING | no_test_family | **G0** | **add `SCM.*` family** — VSCODE_EXTHOST_IPC_SOCKET path; small in count but on critical wireup |
| `pidfd_send_signal` / `pidfd_getfd` | 0 | **MISSING** | MISSING | no_test_family | G3 | defer |
| `io_uring_setup` + `io_uring_enter` | 372 | `IOR.*` | strong (contract: ENOSYS-fallback) | n/a | n/a | retain — locks in fallback safety |
| `setsid` | 13 | `PTY.*` (via `PtyExec ctrl_tty=true`) | proxy | n/a | n/a | covered |
| `prctl(PR_SET_NAME)` | 91 | (no test) | MISSING | no_test_family | G2 | low-risk; defer unless bug surfaces |
| `arch_prctl(ARCH_SET_FS)` | 579 | proxy via clone3 thread tests | proxy | n/a | n/a | covered indirectly through CL3 |
| `setsockopt` (mostly SO_REUSEADDR/SO_KEEPALIVE) | 1 385 | `TCS.*`, `TLB.*` | proxy (no per-option assertion) | weak_assertions | G2 | one focused `SOCKOPT.*` family asserting REUSEADDR/KEEPALIVE behavior — small, optional |
| `getrandom` | 680 | (no test) | MISSING | no_test_family | G2 | the `CrngProvider` stored-memory fact says it's the security RNG contract — worth a thin coverage row |
| `statx` | 23 246 | `FS.*` (proxy) | proxy | n/a | n/a | covered by file ops; explicit `STATX.*` not needed |
| `mmap (MAP_FIXED \| MAP_SHARED)` | 51 / 5 758 | `XDF.*` (proxy) | proxy | n/a | n/a | covered by exec mmap paths |
| `getrandom`, `randomness` | 680 | proxy | proxy | n/a | n/a | covered |
| `splice` / `sendfile` / `tee` | 0 | **MISSING** | MISSING | no_test_family | G3 | defer |
| `memfd_create` | 0 | **MISSING** | MISSING | no_test_family | G3 | defer |
| `O_TMPFILE` | 0 | **MISSING** | MISSING | no_test_family | G3 | defer |
| `linkat`, `renameat2` | 0 / 1 | **MISSING** | MISSING | no_test_family | G3 | defer |
| `mount` / `umount2` / `pivot_root` | 0 | **MISSING** | MISSING | no_test_family | G3 | not used by VS Code |
| `vfork`, `unshare`, `ptrace` | 0 | **MISSING** | MISSING | no_test_family | G3 | defer |
| `sched_yield` | 974 | proxy | proxy | n/a | n/a | covered indirectly |
| `Fork.inherit_listen_ports` | (used at every connect via the bootstrap) | `FKLC.inherit.*` | strong tests but **shim broken** | n/a — shim issue | **product bug** | not a coverage gap; tracked as `FKLC-inherit-regression-fix` |
| **TTY ioctls**: `TIOCSCTTY`, `TIOCSPGRP`, `TIOCGPGRP`, `TIOCGPTPEER`, `TIOCSPTLCK`, `TIOCSWINSZ` | 9 / 21 / 453 / 9 / 9 / 33 | `PTY.*` | strong (post W1 + shim fixes) | n/a | n/a | well-covered |
| `TCGETS` / `TCSETSF` / `TCSETSW` | 138 / 9 / 9 | `TERM.*`, `PTY.*` | proxy → strong | n/a | n/a | covered |
| `dup2` / `dup3` | 851 / ? | many families (proxy) | proxy | n/a | n/a | covered |
| `socketpair` | 262 | `US6.*` | strong | n/a | n/a | covered |
| `recvmsg` / `sendmsg` | 476 / 2 | `TCS.*`, `US*` | proxy | n/a | n/a | covered |
| `shutdown` (TCP) | 214 | `THC.*`, `TCS.*` | strong | n/a | n/a | covered |
| AF_UNIX, AF_INET, AF_NETLINK, AF_INET6 | 136 / 145 / 34 / 1 | `US.*` / `NET.*` / `NL.*` | strong | n/a | n/a | covered |

---

## End sections

### Trim candidates (P4)

None of the 70+ existing families are flagged as outright trim
candidates in this pass. Reason: most P3-tagged rows have
**suspected redundancy** (e.g., `XDF` vs `X` vs `XB`; `M1`–`M4`
matrices; `BR`/`BRS`/`BS1`–`BS3`) but I haven't done the
side-by-side coverage diff to be certain. Recommended next step
before any deletions: a **redundancy audit** that pairwise diffs
the suspected-overlap families' `target_capability`, then promotes
specific families to P4 once it's clear they're strictly subsumed.

The closest current trim candidates from the test-framework audit
are (still unactioned):

- The `NA.*.self_ip` pseudo-pass skips (flagged in
  `docs/audit/xfail-census.md`).
- The `F.host.*` pseudo-pass skips (same source).
- Any of the Tier-3 P3 families that side-by-side proves redundant.

Until that diff is done, **no P4 deletions recommended in this batch.**

### Must-keep / focus-fix (P0 + P1)

- **P0 — `FKLC.inherit.*`**: 5/6 fail on litebox; this is the VS
  Code Remote-SSH connection's fd-inheritance path. Tracked as
  `FKLC-inherit-regression-fix` (blocked — broker/worker routing
  bug).
- **P1** — `PTY.*`, `EPI.*`, `CL3.*`, `IOR.*`, `US*` (esp. `US6`),
  `TERM.*`. All hot in the combined trace; preserve.

### Testing gaps (G0 + G1) — direct answer to "what are the testing gaps?"

| gap | trace evidence | proposed test family | size | priority |
|---|---|---|---:|---|
| **`inotify_add_watch`** workspace file-watcher | **1 343** calls — biggest single new finding | `INO.*` — watch a directory, modify files, assert events come back across the protocol | 4–6 scenarios × 4 axes | **G0** |
| **`SCM_RIGHTS` fd-passing** over UDS | 4 calls, `VSCODE_EXTHOST_IPC_SOCKET` handoff between server and extension host | `SCM.*` — pass a socket fd via `sendmsg`/`recvmsg`, assert the receiver can read/write through it | 3–4 scenarios × 3 axes | **G0** |
| `clone3` with `CLONE_VFORK` (terminal `posix_spawn`) | 6 calls (NEW vs connection-only) | extend `CL3.with_vfork` scenario | +1 scenario × 4 axes | **G2** |
| `setsockopt` per-option behavior | 1 385 calls; option breakdown not yet asserted | `SOCKOPT.*` — narrow tests for SO_REUSEADDR/REUSEPORT/KEEPALIVE that assert kernel state | 3 scenarios × 2 axes | **G2** |
| `getrandom` semantics | 680 calls; well-defined contract | tiny `RAND.*` family asserting size + monotonic novelty | 2 scenarios × 2 axes | **G2** |

These five additions are the **direct testing gaps** vs current
VS Code Remote-SSH workload. The first two (G0) directly block
real VS Code paths; the others are regression-risk hardening.

Items moved to **explicit defer** based on combined-trace
evidence:

- `signalfd` / `signalfd4` (cold).
- `timerfd_*` (cold).
- `fanotify_*` (cold).
- `pidfd_send_signal` / `pidfd_getfd` (cold).
- `splice` / `sendfile` / `tee` (cold).
- `memfd_create` (cold).
- `vfork` / `unshare` / `ptrace` (cold).
- `O_TMPFILE` / `linkat` / `mount` / `pivot_root` (cold).

These remain valid **layer-2** candidates if a deeper trace
(debug session, large project search, long-lived background
build) surfaces them.

### Methodology block (re-running on a future trace)

To refresh this doc against a new trace:

1. Run a fresh combined trace following
   `docs/audit/vscode-syscall-trace-combined.md` "Methodology"
   section. Output `top50-by-count.txt`,
   `key-syscalls-by-scenario.txt`.
2. For each row in **View A**, re-evaluate `vs_code_pressure`
   against the new top-50 / key-syscalls data; revise tier.
3. For each row in **View B**, re-evaluate `trace_count`. Promote
   any newly-hot capability to a higher gap tier if it lacks
   coverage.
4. Run a quick `cargo test … 'litebox::<prefix>'` sweep across
   the listed families to refresh `litebox_status`. Native is
   assumed green per the gold-standard rule.
5. Cross-reference recently-merged shim fixes; downgrade any
   priority where the underlying bug is now fixed.
6. The redundancy audit (precondition for P4 trims) is a
   separate workstream — not part of the routine refresh.

### Cross-references

- `docs/audit/vscode-syscall-trace.md` — connection-only trace
  (predecessor).
- `docs/audit/vscode-syscall-trace-combined.md` — combined trace
  driving this doc's pressure data.
- `docs/audit/vscode-capabilities.md` — original 37-row capability
  matrix from the test-framework audit.
- `docs/audit/axis-coverage.md` — per-family axis enumeration
  (input to View A).
- `docs/audit/xfail-census.md` — pseudo-pass skip flags
  (input to trim candidates).
- `docs/test-framework-audit.md` — master audit report.
