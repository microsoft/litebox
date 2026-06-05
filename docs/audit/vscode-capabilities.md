# VS Code capability matrix

Scope: `audit-vscode-capabilities` from the test-framework audit. Inputs were `protocol-coverage.md`, `axis-coverage.md`, `bash-census.md`, `xfail-census.md`, `synchronization-primitives.md`, `lazy-matrix.md`, `protocol-surface.md`, `docs/orphan-diff-findings.md`, `litebox_test_harness/CLAUDE.md`, and the last 50 commits on `wportnoy/vscode-server-in-litebox`.

Pressure key:

- 🔥 actively observed/recently fixed or called out as a VS Code blocker in this branch's VS Code work.
- ⚠️ likely touched by VS Code remote server, sshd, or Node.js, but not confirmed as the active failure.
- 💤 useful hardening with weak current VS Code pressure.

Coverage key:

- **COVERED**: there is a focused harness test for the capability.
- **PARTIAL**: adjacent tests exist, but a VS-Code-relevant exact behavior is still missing.
- **MISSING**: no focused harness test found.
- **EXCLUDED**: considered, but not recommended as a VS Code blocker without more evidence.

## capability matrix table

| # | capability | coverage | citation / current evidence | VS-Code pressure | gap / note |
|---:|---|---|---|---|---|
| 1 | `epoll` + `pidfd` process-exit notification | **PARTIAL** | `EP.*` covers epoll socket readiness (`axis-coverage.md:56`, `:277-279`; `main.rs:1011-1021`). `PB.epoll*` covers epoll on pipe/socketpair bridge (`axis-coverage.md:73`, `:346-352`; `main.rs:4610-4617`, `:4750-4759`). Grep found no `pidfd` in the harness. | 🔥 | Exact pidfd-open/pidfd-poll/epoll-wait-for-child-exit flow is missing. |
| 2 | `epoll` socket/pipe/socketpair readiness wakeups | **COVERED** | `EP.direct.*`, `EP.tokio.*`, `PB.epoll.*`, and `PB.epoll_sp.*` (`axis-coverage.md:56`, `:73`, `:277-279`, `:346-352`; `main.rs:1011-1021`, `:4610-4617`, `:4750-4759`). Recent commits include network wakeups and pipe bridge fixes. | 🔥 | Strong base coverage, but add deeper/cross-agent axes already recommended for `EP`/`PB` (`axis-coverage.md:84-86`). |
| 3 | PTY allocation + `setsid`/`TIOCSCTTY`/`TIOCSPGRP` controlling-tty handover | **MISSING** | `TERM.*` only probes termios/ioctl behavior on inherited stdio fds (`axis-coverage.md:23`, `:123-125`). `protocol-surface.md:116-197` says no PTY commands exist. | 🔥 | Real pty allocation, foreground pgrp, and controlling-tty handover are not expressible. |
| 4 | fork + `CLOEXEC` listen-fd inheritance (`Fork.inherit_listen_ports`) | **PARTIAL** | Standalone `FKLC.cross_connect` uses `tcp-fork-listen-accept` (`axis-coverage.md:59`, `:288-289`; `main.rs:720-740`). `CLAUDE.md:272-288` says this is the VS Code pattern and the protocol field is not implemented. `protocol-surface.md:20-115` ranks this first. | 🔥 | Current test bypasses the agent protocol; true `Fork.inherit_listen_ports` + real `NetAccept`/`NetCloseListener` is missing. |
| 5 | generic fd inheritance across fork/exec for pipes/socketpairs/stdout bridges | **COVERED** | `P.*` pipe EOF, `PB.*` pipe/socketpair bridge direction/epoll, `US6.*` socketpair, `BS.*` stdio bridge (`axis-coverage.md:72-73`, `:46`, `:68`, `:325-352`). | 🔥 | Keep; this area has had recent branch fixes (`bridge worker stdout`, `pipe nonblock`, `unix socket fork inheritance`). |
| 6 | `io_uring` probe-only fallback | **MISSING** | `CLAUDE.md:16-18` names it as a suspect capability; no `io_uring` harness hit found. | ⚠️ | Need a probe that treats `ENOSYS`/`EPERM`/unsupported as graceful fallback, not product failure. |
| 7 | `/proc/self/*` reads: cmdline/stat/status/fd/exe/maps | **PARTIAL** | `PROC.self_stat.*`, `PROC.stat_seekable.*`, `KP.proc_self.*`, and `CF.vscode.proc_*` (`axis-coverage.md:60`, `:291-293`; `bash-census.md:20`, `:49-50`; `main.rs:1299-1336`). | 🔥 | `cmdline`/`stat` are covered; focused `status`, `fd`, `exe`, and `maps` assertions are missing. Recent commit `fix: proc — track cmdline per pid` shows active pressure. |
| 8 | `/proc/<pid>/*` cross-pid reads and liveness | **COVERED** | `KPX.*` full cross-agent matrix and `KP.*` local process metadata (`axis-coverage.md:52-53`, `:258-266`; `main.rs:1285-1344`). | 🔥 | Strong for cmdline/liveness; extend only if adding `/proc/<pid>/fd`, `/exe`, or `/maps` from row 7. |
| 9 | `clone3` / thread creation with `CLONE_THREAD` + `CLONE_VM` pressure | **PARTIAL** | `XDF.thread.*` uses `trigger-delayed-fork-thread`; comments say this uses thread creation (`clone3`) like Node/V8 (`axis-coverage.md:64`, `:310-314`; `main.rs:1586-1599`). | 🔥 | It is behavior-level thread creation coverage, not an explicit clone3 flag/errno matrix. |
| 10 | `clone3` with `CLONE_PIDFD` / pidfd-return semantics | **MISSING** | No `pidfd` or explicit `clone3` flag test found beyond thread creation comments. | ⚠️ | Add a raw clone3 probe if Litebox implements or intentionally rejects this path. |
| 11 | direct `eventfd` semantics and epoll integration | **MISSING** | `main.rs:1016-1021` describes Tokio's eventfd wakeup pattern, but the test does not create/assert eventfd directly. | 🔥 | Add direct eventfd read/write, counter saturation/EAGAIN, and epoll readability tests. |
| 12 | `signalfd` delivery | **MISSING** | No `signalfd` harness coverage found. `protocol-surface.md:324-391` notes signal testing is currently missing beyond cleanup `Kill`. | 💤 | Useful if Node/sshd moves signal handling through fd-based paths; lower pressure than ordinary signal masks. |
| 13 | `timerfd` / POSIX timer / `rt_sigsuspend` | **MISSING** | `orphan-diff-findings.md:58-83` says deleted `syscall-test` POSIX timer and `sigsuspend` assertions have no live coverage. No `timerfd` coverage found. | ⚠️ | Restore as focused syscall probes; include `timerfd_create/settime/read` if Node/libuv timerfd use is suspected. |
| 14 | `inotify` file watcher semantics | **MISSING** | No `inotify` harness coverage found. | ⚠️ | VS Code file watching makes this more than nice-to-have even though no recent failure was confirmed. |
| 15 | `fanotify` semantics | **MISSING** | No `fanotify` harness coverage found. | 💤 | Likely not needed by VS Code remote server in normal operation; add only after evidence. |
| 16 | `SCM_RIGHTS` fd-passing over Unix domain sockets | **MISSING** | `protocol-surface.md:199-260` says Unix echo/socketpair tests exist but no SCM_RIGHTS protocol/helper path; design docs also call fd passing unsupported. | 🔥 | Common ptyHost/Node IPC shape; top-3 protocol-surface blocker. |
| 17 | `setsid` / orphan reparenting / `prctl(PR_SET_PDEATHSIG)` | **MISSING** | `KP.*`, `KPX.*`, and `SK.*` cover parent pid visibility and subtree kill (`axis-coverage.md:52-53`, `:61`, `:258-266`, `:295-296`) but no `setsid` or `PDEATHSIG` probe was found. | ⚠️ | Add exact session/orphan/PDEATHSIG assertions, separate from generic `/proc` visibility. |
| 18 | `mmap(MAP_SHARED | MAP_FIXED)` and fork/COW behavior | **PARTIAL** | `XDF.mmap.*` exercises delayed-fork after mmap (`axis-coverage.md:64`, `:310-314`). `orphan-diff-findings.md:13-57` says low-level COW/fork state assertions remain gaps. | ⚠️ | Add exact MAP_SHARED/MAP_FIXED aliasing plus parent/child COW assertions. |
| 19 | `getrandom` and `/dev/urandom` semantics | **MISSING** | No `getrandom` or `/dev/urandom` harness coverage found. | ⚠️ | Node crypto startup and ssh key paths likely touch this; assert nonblocking success and byte variability. |
| 20 | DNS + netlink combined glibc flow | **PARTIAL** | `NL3b`, `NL3c`, `NL3d`, `NL5`, `NL6`, `X48.node_networkInterfaces`, and `XM.node_networkInterfaces` cover pieces (`axis-coverage.md:19-20`, `:63`, `:100-105`, `:307-308`; `orphan-diff-findings.md:85-117`). | ⚠️ | Missing exact combined glibc flow: same socket, `RTM_GETLINK` then `RTM_GETADDR`, `sendmsg`, `MSG_PEEK|MSG_TRUNC`, and `NLMSG_DONE` for both. DNS resolver flow itself also lacks focused coverage. |
| 21 | `posix_spawn` behavior for `child_process.spawn` | **MISSING** | No `posix_spawn` harness coverage found; many tests use Rust `Command`/fork+exec but not explicit posix_spawn. | ⚠️ | Add a self-contained helper using `posix_spawn_file_actions` and env/stdout redirection. |
| 22 | abstract Unix domain sockets | **COVERED** | `US5.abstract_unix` is listed in the Unix special-case family (`axis-coverage.md:68`, `:325-327`). | ⚠️ | Keep; add axis coverage only if VS Code demonstrates cross-agent abstract socket use. |
| 23 | filesystem `O_TMPFILE` + `linkat` | **MISSING** | General filesystem/symlink/stat coverage exists (`S.*`, `F.*`, protocol `Fs*` in `protocol-coverage.md:17-22`) but no `O_TMPFILE`/`linkat` probe found. | ⚠️ | Relevant to installer/atomic-file patterns. |
| 24 | filesystem `renameat2` semantics | **MISSING** | No `renameat2` harness coverage found. | ⚠️ | Add `RENAME_NOREPLACE` and exchange/atomicity assertions if supported. |
| 25 | filesystem `statx` semantics | **MISSING** | `FsStat` has two protocol callsites (`protocol-coverage.md:22`) and `PROC.stat_seekable.*` exists, but no `statx` probe found. | ⚠️ | Node/libuv may prefer `statx`; assert fallback or real fields deliberately. |
| 26 | `dup3` fd duplication/`O_CLOEXEC` | **MISSING** | No `dup3` harness coverage found; pipe and fd bridge tests cover related duplication effects only indirectly. | ⚠️ | Add exact `dup3(old,new,O_CLOEXEC)` and exec-inheritance assertions. |
| 27 | `fcntl(F_SETPIPE_SZ)` | **MISSING** | No `F_SETPIPE_SZ` harness coverage found. | 💤 | Useful for pipe buffering/backpressure hardening, but not a top VS Code blocker without evidence. |
| 28 | `fcntl(F_GETFL/F_SETFL)` and `O_NONBLOCK` | **COVERED** | `PN.*` pipe nonblocking family (`axis-coverage.md:55`, `:272-275`) and `pipe-nonblock`/`pipe-child-nonblock` (`main.rs:1165-1248`). | 🔥 | Keep; recent pipe nonblock fixes show real pressure. |
| 29 | `SO_REUSEADDR` | **PARTIAL** | `epoll-socket` sets `SO_REUSEADDR` before bind (`main.rs:1029-1036`); `GSN.*`/`NET*` cover local socket state (`axis-coverage.md:37`, `:120-121`). | ⚠️ | The option is used, but there is no focused assertion that rebinding behavior matches Linux. |
| 30 | `SO_REUSEPORT` | **MISSING** | No `SO_REUSEPORT` harness coverage found. | ⚠️ | Add multi-listener distribution or at least option accept/reject semantics. |
| 31 | `SO_KEEPALIVE` | **MISSING** | No `SO_KEEPALIVE` harness coverage found. | 💤 | Likely lower pressure than listen/connect/EOF unless VS Code long-lived socket failures point here. |
| 32 | signal masks across fork+exec (`sigprocmask`) | **MISSING** | No `sigprocmask`/mask-inheritance harness coverage found. `protocol-surface.md:324-391` says signals beyond `Kill` are not expressible. | ⚠️ | Add child inherits blocked mask, exec preserves mask, and unblocking delivers pending signal. |
| 33 | `ptrace` | **EXCLUDED** | No harness coverage found; no recent branch evidence that VS Code/Node/sshd requires ptrace in the Litebox path. | 💤 | Do not prioritize unless an sshd-specific minimal repro points here. |
| 34 | `Exec` environment overrides | **MISSING** | `protocol-surface.md:264-322` says `Command::Exec` lacks `env`, `env_remove`, and clear/inherit mode. | ⚠️ | VS Code/Node startup is env-sensitive; add protocol support before relying on shell wrappers. |
| 35 | background helper readiness / observed-state waits | **MISSING** | `synchronization-primitives.md:53-73` recommends `ExecReady`/`WaitReady` and `WaitFor`; current `Exec background` discards stdout (`protocol-surface.md:470-519`). | 🔥 | Many loopback/Unix/TCP helper tests sleep instead of observing readiness, including `LB.*` and `FKLC.cross_connect`. |
| 36 | stateful TCP connection registry / multi-step half-close | **PARTIAL** | `NetHalfCloseEcho` and `THC.*` cover one-shot EOF (`protocol-coverage.md:26`, `:54`; `axis-coverage.md:58`, `:285-286`). `protocol-surface.md:393-468` explains the missing stateful registry. | 🔥 | Add `NetOpen`/`NetSend`/`NetRecv`/`NetShutdown` handles for VS Code socket state machines. |
| 37 | arbitrary signal delivery / process-group signals | **MISSING** | Existing `Kill` is cleanup-only and responses are often ignored (`protocol-coverage.md:34`). `protocol-surface.md:324-391` proposes explicit signal trap/send/wait primitives. | ⚠️ | Needed for PTY job control, graceful termination, and sshd/session behavior. |

## MISSING-with-sketch list

1. **PTY allocation + controlling tty (`#3`, 🔥).** Add `PtyOpen`, `PtyExec`, `PtyWrite`, `PtyRead`, `PtyResize`, `PtyClose` commands as sketched in `protocol-surface.md:126-191`. Axes: `A`, `AA`, `B`, `D4`; then parent→child and child→parent pty handover. Assertions: slave becomes controlling tty after `setsid`/`TIOCSCTTY`, `tcsetpgrp`/`TIOCSPGRP` succeeds, child sees correct `ttyname`, echo/read works, and foreground process group matches.
2. **`io_uring` probe-only fallback (`#6`, ⚠️).** Current protocol can use `Exec` of a tiny self-exe probe. Axes: `A`, `AA`, `D4`. Assertions: `io_uring_setup` or liburing probe returns either usable ring or a documented refusal (`ENOSYS`, `EPERM`, `EINVAL`) and the process continues without enabling io_uring.
3. **`clone3(CLONE_PIDFD)` / pidfd-return (`#10`, ⚠️).** Add a self-exe raw-syscall probe or protocol command. Axes: `A`, `AA`, `D4`. Assertions: supported path returns a valid pidfd that polls on child exit; unsupported path fails with the same errno as native baseline.
4. **Direct `eventfd` (`#11`, 🔥).** Add `EventfdRoundTrip` or self-exe probe: create `eventfd(EFD_NONBLOCK|EFD_CLOEXEC)`, read EAGAIN, write `1`, epoll for readability, read counter, assert value and reset. Axes: `A`, `AA`, `B`, `D4`.
5. **`signalfd` (`#12`, 💤).** Add a signal-mask + signalfd probe: block `SIGUSR1`, create signalfd, send signal from a child or protocol `SignalSend`, poll/read `signalfd_siginfo`, assert signal number and pid.
6. **`timerfd` / POSIX timers / `rt_sigsuspend` (`#13`, ⚠️).** Restore deleted `syscall-test` coverage from `orphan-diff-findings.md:58-83`; add `timerfd_create(CLOCK_MONOTONIC)`, `timerfd_settime`, read expiration count. Axes: `A`, `AA`, `D4`, `NP` where applicable.
7. **`inotify` (`#14`, ⚠️).** Protocol sketch: `FsWatchStart { path }`, `FsWrite`, `FsRename`, `FsDelete`, `FsWatchRead`. Current protocol can approximate with a self-exe helper. Assertions: create/modify/rename/delete events arrive in order with expected masks.
8. **`fanotify` (`#15`, 💤).** Add only if native baseline supports it in the container. Assertions: unsupported permission errors are stable and graceful; if supported, open event metadata is readable.
9. **SCM_RIGHTS fd passing (`#16`, 🔥).** Use `UnixSocketPair`, `FdCreate`, `ScmSendFd`, `ScmRecvFd`, `FdRead/FdWrite` as sketched in `protocol-surface.md:209-254`. Start same-agent, then child-inherited, then cross-agent if socket endpoint routing supports it. Assert received fd count, tag, and actual I/O on the received fd.
10. **`setsid` / orphan reparenting / `PR_SET_PDEATHSIG` (`#17`, ⚠️).** Add a self-exe helper: parent forks child, child optionally `setsid`, installs `PDEATHSIG`, parent exits through protocol `Exit` or helper control pipe. Assertions: `getsid`, `getppid`/`/proc`, and signal delivery match native baseline.
11. **`getrandom` and `/dev/urandom` (`#19`, ⚠️).** Use current `Exec` with a self-exe probe. Assertions: `getrandom(32, 0)` returns 32 bytes, `/dev/urandom` read returns requested bytes, nonblocking semantics match native, two reads are not identical all-zero buffers.
12. **`posix_spawn` (`#21`, ⚠️).** Add a helper using `posix_spawn_file_actions_adddup2`, `addclose`, envp, and argv. Axes: `A`, `AA`, `B`, `D4`. Assertions: child stdout redirection works, close-on-exec is honored, env changes are visible, exit status is exact.
13. **`O_TMPFILE` + `linkat` (`#23`, ⚠️).** Add `FsTmpfileLink` helper/protocol command. Assertions: anonymous tmpfile write/read works, `linkat(AT_EMPTY_PATH)` either links successfully or fails with native-matching errno; linked file has expected contents.
14. **`renameat2` (`#24`, ⚠️).** Add `FsRenameAt2` helper: assert `RENAME_NOREPLACE` refuses overwrites and succeeds on empty target; optionally assert `RENAME_EXCHANGE` swaps contents atomically.
15. **`statx` (`#25`, ⚠️).** Add `FsStatx` helper: query file, directory, symlink, and `/proc/self/exe`; assert mode/type, size, and stable fallback errno if statx is intentionally unsupported.
16. **`dup3` (`#26`, ⚠️).** Add `Dup3Cloexec` helper: duplicate pipe fd to a chosen number with `O_CLOEXEC`, fork+exec child, assert fd is absent; repeat without cloexec and assert inherited fd works.
17. **`fcntl(F_SETPIPE_SZ)` (`#27`, 💤).** Add pipe-size helper: get default size, attempt set to a modest size, assert returned size or native-matching permission/limit error; write enough data to observe capacity if feasible.
18. **`SO_REUSEPORT` (`#30`, ⚠️).** Add socket-option helper: create two listeners with reuseport on same addr, assert either both bind or native-matching unsupported errno; optionally connect many clients and assert both accept.
19. **`SO_KEEPALIVE` (`#31`, 💤).** Add option set/get helper: set keepalive and TCP keepalive tunables if available; assert `getsockopt` sees them.
20. **Signal masks across fork+exec (`#32`, ⚠️).** Add helper: block `SIGUSR1`, fork, exec child that reports mask with `sigprocmask`, send pending signal, unblock and assert handler fires once.
21. **`Exec.env` (`#34`, ⚠️).** Extend `Command::Exec` with `env`, `env_remove`, and `env_mode` as sketched in `protocol-surface.md:274-315`. Assertions: child-only env var appears in stdout, removed var is absent, clear mode removes inherited variables except explicit entries.
22. **Background readiness / `WaitFor` (`#35`, 🔥).** Add `ExecReady` and `WaitFor` (`synchronization-primitives.md:53-59`; `protocol-surface.md:480-512`). Assertions: helper server ready line is consumed before connect; file/pid/cmdline/TCP/Unix predicates include failure details instead of sleeps.
23. **Arbitrary signal delivery / process group signals (`#37`, ⚠️).** Add `SignalTrapStart`, `SignalSend`, `SignalWait`, `SignalClose` as sketched in `protocol-surface.md:340-385`. Axes: same-agent, sibling, parent→child; process-group variant after PTY support.

## top-10 ranking

Ranked by combined missingness/partial-exact-gap and VS Code pressure:

1. **`Fork.inherit_listen_ports` + true inherited `NetAccept` (`#4`, PARTIAL, 🔥).** Documented VS Code CLI listen-socket handoff; protocol field exists but is unimplemented.
2. **PTY allocation + controlling-tty handover (`#3`, MISSING, 🔥).** VS Code terminal/ptyHost cannot be validated without real PTY + session/pgrp tests.
3. **SCM_RIGHTS fd passing (`#16`, MISSING, 🔥).** Common Unix/Node/ptyHost IPC pattern; no harness surface.
4. **`epoll` + `pidfd` exit notification (`#1`, PARTIAL, 🔥).** Epoll is covered, but pidfd process-exit notification is not.
5. **Background readiness / `WaitFor` (`#35`, MISSING, 🔥).** Multiple current VS-Code-relevant tests are timer-driven; missing primitive causes flakes and weak localization.
6. **Direct `eventfd` semantics (`#11`, MISSING, 🔥).** Tokio/libuv wake paths rely on eventfd-like readiness; current coverage is only indirect.
7. **Stateful TCP connection handles (`#36`, PARTIAL, 🔥).** One-shot half-close cannot express VS Code/Node multi-step socket state machines.
8. **`/proc/self` and `/proc/<pid>` expansion to `fd`/`exe`/`maps`/`status` (`#7`, PARTIAL, 🔥).** `/proc/cmdline` was recently fixed; remaining proc metadata is likely to be hit by Node/VS Code diagnostics.
9. **`clone3` flag matrix including pidfd (`#9/#10`, PARTIAL/MISSING, 🔥/⚠️).** Node/V8 thread startup is covered behaviorally, but exact clone3 flags and pidfd combinations are not.
10. **`inotify` file watcher semantics (`#14`, MISSING, ⚠️).** VS Code file watching is likely to touch this; no focused harness test exists.

Near misses: `posix_spawn` (`#21`), exact glibc DNS/netlink flow (`#20`), `io_uring` graceful probe (`#6`), and `Exec.env` (`#34`).

## discovered-additional-capabilities

- **PTY-external fd/socketpair bridge is already a separate VS Code pressure area.** The seed listed `epoll`+`pidfd`, but current tests also cover the ptyHost-style pipe/socketpair bridge via `PB.epoll*` (`main.rs:4610-4617`, `:4750-4759`). Keep it separate from real PTY work so regressions localize correctly.
- **`Exec.env` is a protocol blocker for child-process realism.** `protocol-surface.md:264-322` shows `Exec` cannot set, remove, or clear environment variables. VS Code/Node startup is heavily env-sensitive.
- **Background readiness and observed-state waits are capabilities, not only framework ergonomics.** `synchronization-primitives.md:53-73` shows they directly gate loopback TCP, Unix socket, and inherited-listener tests.
- **Exact glibc netlink flow remains missing even with multiple netlink ingredients covered.** `orphan-diff-findings.md:85-117` identifies the combined `sendmsg` + `MSG_PEEK|MSG_TRUNC` + `GETLINK`/`GETADDR` sequence gap.
- **POSIX timers and `rt_sigsuspend` became gaps after orphan deletion.** `orphan-diff-findings.md:58-83` should feed signal/timer test design alongside `signalfd`/`timerfd`.

## summary counts

| metric | count |
|---|---:|
| Capability rows | 37 |
| **MISSING** rows | 23 |
| **PARTIAL** rows with exact VS-Code-relevant gaps | 8 |
| **COVERED** rows | 5 |
| **EXCLUDED** rows | 1 |
