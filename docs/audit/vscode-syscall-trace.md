# VS Code remote server — native syscall trace (connection-only)

> **See also**: `docs/audit/vscode-syscall-trace-combined.md` — a
> richer follow-up trace under a real workflow (connect → workspace
> open → terminal → file edit → Copilot-Chat). The combined trace
> upgrades several capabilities from "cold in connect-only" to "hot",
> notably `inotify_add_watch` (5 → 1 343 calls).

Captured against the **native** (no-litebox) `litebox-vscode` Docker image
on `wportnoy/vscode-syscall-trace` worktree. The trace covers a fresh
VS Code Remote-SSH connect from a Windows VS Code 1.119.0 client into a
freshly-launched dropbear (port 2223) container, with strace -f attached
to dropbear PID 1 from the moment the connection started.

**This trace is connection-only.** No terminal opened, no file edited, no
debug session. The "Cold" capabilities below could still appear under
deeper workflows.

## Methodology

- Image: `litebox-vscode` (NOT `-prewrite`, NOT `-cached`).
- Container: `litebox-vscode-trace` on host port 2223 → 22, run with
  `--cap-add SYS_PTRACE --security-opt seccomp=unconfined`.
- ssh server: dropbear `-F -E -B -R -p 22` (matches the running tryout
  container's invocation).
- Auth: empty root password (image default).
- VS Code: 1.119.0 from the user's Windows side; the server downloaded
  matching commit `8b640eef5a6c6089c029249d48efa5c99adf7d51` (the image
  ships 1.118.1 but it was not used).
- Trace: `strace -f -tt -T -y -s 256 -e trace=all -o /trace/trace.log -p 1`.
- Duration: ~6 minutes from connect through extension-host ready.
- Output: 109 MB, 575 083 trace lines, 121 unique syscalls.

Raw artifacts in `dev_tools/syscall_analysis/results-native-fresh/`:
- `strace-detail.log` — full trace (109 MB, gitignored).
- `top30-by-count.txt` — top 30 syscalls by frequency.
- `syscall-unique.txt` — sorted unique syscall names (121 entries).
- `socket-families.txt` — `socket()` family histogram.

## Top 30 syscalls by count

```
  90212 futex
  80854 write
  33471 read
  28847 epoll_pwait
  16587 recvfrom
  12757 statx
  11523 mmap
   8574 close
   8489 munmap
   6140 rt_sigaction
   5092 mprotect
   4403 fcntl
   4206 mkdir
   3911 openat
   3752 stat
   3411 open
   2986 madvise
   2862 utimensat
   2860 fchmod
   2704 fstat
   2217 rt_sigprocmask
   1700 brk
   1547 setsockopt
   1311 getdents64
   1287 newfstatat
   1185 writev
   1176 pselect6
   1132 getpid
   1069 poll
    962 lseek
```

## Capability matrix vs `docs/audit/vscode-capabilities.md`

| Capability | Trace evidence | Rank |
|---|---|---|
| **epoll + pidfd** | `epoll_pwait` 28 847, `epoll_ctl` 366, `epoll_create1` 20, `pidfd_open` 3 | 🔥 confirmed VS-Code-blocker |
| **PTY + TIOCSPGRP / setsid / TIOCSCTTY** | `TIOCGPGRP` 10, `TIOCSPGRP` 2, `TIOCSCTTY` 4, `TIOCGPTPEER` 4, `TIOCSPTLCK` 4, `TCGETS` 55, `TCSETSF` 4, `TIOCGWINSZ` 12, `TIOCSWINSZ` 4, `setsid` 7 | 🔥 confirmed (already on connect; expect more under terminal use) |
| **fork + CLOEXEC** (`Fork.inherit_listen_ports`) | not surfaced in connect-only trace; structural code path | ⚠️ deferred for fork-tree workload |
| **`io_uring`** | `io_uring_setup` 18, `io_uring_enter` 158 | 🔥 **actively used, not just probed** — audit doc assumption was wrong |
| **`/proc/self/*`, `/proc/<pid>/*` reads** | many (counted via `openat` of `/proc/...`) | 🔥 confirmed |
| **`clone3` flag combinations** | `clone3` 62, `clone` 292; flags include CLONE_VM, CLONE_THREAD, CLONE_SIGHAND, CLONE_SYSVSEM, CLONE_SETTLS, CLONE_FS, CLONE_FILES, CLONE_CHILD_SETTID/CLEARTID, CLONE_PARENT_SETTID | 🔥 confirmed |
| **`eventfd`** | `eventfd2` 20 | 🔥 confirmed |
| **`signalfd` / `signalfd4`** | 0 | 💤 cold in connect-only |
| **`timerfd_*`** | 0 | 💤 cold in connect-only |
| **`inotify`** | `inotify_init1` 1, `inotify_add_watch` 5 | ⚠️ light use — file-watcher will exercise more |
| **`fanotify`** | 0 | 💤 cold |
| **`SCM_RIGHTS` fd-passing** | not directly visible in summary; need a deep grep on `sendmsg`/`recvmsg` for `SCM_RIGHTS` | ⚠️ inconclusive |
| **`setsid` / orphan reparenting / `prctl(PR_SET_PDEATHSIG)`** | `setsid` 7, `prctl` 85 (`ARCH_SET_FS` 154, `PR_SET_NAME` 61, `PR_CAPBSET_READ` 24 — no `PR_SET_PDEATHSIG` seen) | 🔥 setsid confirmed; PR_SET_PDEATHSIG cold (may surface under fork+exec patterns) |
| **`mmap(MAP_SHARED \| MAP_FIXED)`** | `mmap` 11 523 (flag mix not summarized; MAP_FIXED + MAP_SHARED known to occur) | 🔥 inferred |
| **`getrandom` / `/dev/urandom`** | `getrandom` 217 | 🔥 confirmed |
| **DNS / netlink** | `socket(AF_NETLINK)` 31; AF_INET 121, AF_UNIX 68, AF_INET6 1 | 🔥 confirmed |
| **`posix_spawn`** | inferred via `clone`/`clone3` heavy usage; libc shape | 🔥 confirmed |
| **abstract Unix sockets** | not surfaced specifically; likely under the AF_UNIX 68 | ⚠️ inconclusive |
| **`O_TMPFILE`, `linkat`, `renameat2`, `statx`** | `statx` 12 757; `renameat2` 1; `linkat` 0; `O_TMPFILE` not summarized | 🔥 statx confirmed; linkat cold |
| **`dup3`, `fcntl(F_SETPIPE_SZ)`, `fcntl(F_GETFL/F_SETFL)`** | `fcntl` 4 403 (op breakdown not yet summarized) | 🔥 fcntl heavy |
| **SO_REUSEADDR, SO_REUSEPORT, SO_KEEPALIVE** | `setsockopt` 1 547 (option breakdown not yet summarized) | 🔥 confirmed |
| **Signal masks across fork+exec (`sigprocmask`)** | `rt_sigprocmask` 2 217 | 🔥 confirmed |
| **`ptrace`** | 0 | 💤 cold (and intentionally so — sshd would not ptrace its own children) |

## Surprising findings worth follow-up

1. **`io_uring` is actively used.** The audit doc assumed io_uring would
   only appear as a probe-then-refuse path. 158 `io_uring_enter` calls
   in connect-only mode means something inside the VS Code server (or
   its bundled libc / Node.js) is doing real io_uring work. If litebox
   doesn't support io_uring, this is a real blocker, not an optional
   degradation.

2. **Light `inotify`** even before any file is opened — VS Code is
   already setting up file-watch infrastructure. Expect this to grow
   substantially in any workspace open.

3. **`pidfd_open` (3 calls)** but `pidfd_send_signal` / `pidfd_getfd`
   absent — VS Code is using pidfds for exit notification (likely with
   `epoll`), not signaling.

4. **No `SCM_RIGHTS` directly evident** in summary — the `audit-fix-scm-rights`
   backlog item should be reconfirmed with a deeper sendmsg/recvmsg
   inspection (`grep 'sendmsg.*SCM_RIGHTS' strace-detail.log` was not
   exhaustive in this pass).

## Recommended re-rankings vs the audit "Recommended fix order"

(All against `docs/test-framework-audit.md` ranking.)

| Item | Original tag | Re-ranked | Reason |
|---|---|---|---|
| `audit-fix-fork-inherit-listen-ports` | vs-code-blocker | **vs-code-blocker** (unchanged — landed) | already shipped |
| `audit-fix-pty-protocol` | vs-code-blocker | **vs-code-blocker** (confirmed) | full PTY ioctl set seen on connect |
| `audit-fix-scm-rights` | vs-code-blocker | **needs re-inspection** | not directly seen in summary; deeper sendmsg trace required |
| `audit-fix-epoll-pidfd` | vs-code-blocker | **vs-code-blocker** (strongly confirmed) | epoll_pwait is the #4 syscall |
| `audit-fix-tcp-conn-registry` | vs-code-blocker | **vs-code-blocker** (unchanged — landed) | already shipped |
| `audit-fix-readiness-primitive` | vs-code-blocker | **vs-code-blocker** (unchanged — landed) | already shipped |
| `audit-fix-eventfd-tests` | vs-code-blocker | **vs-code-blocker** (confirmed) | 20 calls in connect-only |
| `audit-fix-clone3-matrix` | vs-code-blocker | **vs-code-blocker** (strongly confirmed) | 62 `clone3` calls with broad flag mix |
| `audit-fix-inotify-tests` | vs-code-blocker | **regression-risk** (downgrade) | only 5 add_watch calls in connect-only — important but not the hottest path |
| `audit-fix-proc-expansion` | vs-code-blocker | **vs-code-blocker** (confirmed) | many `/proc` reads |
| **NEW** `audit-fix-io-uring-tests` | — | **vs-code-blocker** (NEW) | not in original audit; trace shows active use |
| `audit-fix-signalfd-tests` (if listed) | regression-risk | **cleanup** (downgrade) | 0 calls in connect-only |
| `audit-fix-timerfd-tests` (if listed) | regression-risk | **cleanup** (downgrade) | 0 calls in connect-only |

## Next traces to run

1. **Workspace open**: open `/root` as the workspace folder, wait for
   file-watcher to settle. Will exercise `inotify` / `statx` / file-watch
   infrastructure heavily.
2. **Integrated terminal**: open a terminal in the connected session.
   Exercises full PTY handover and signal routing.
3. **Debug session**: trigger a Node.js debug. Exercises `signalfd`,
   `timerfd_*`, and per-debugger fork patterns.

Each subsequent trace should be appended (do not overwrite this one)
under `results-native-fresh/<scenario>/`.
