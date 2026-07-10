# VS Code remote server — combined native syscall trace

Captured against the **native** (no-litebox) `litebox-vscode` Docker
image on `wportnoy/vscode-trace2-and-priorities` worktree. Single
combined session covering connect → workspace open → integrated
terminal with a few commands and a resize → file edit (typed and
saved) → trivial Copilot-Chat conversation.

This is a **richer follow-up** to
`docs/audit/vscode-syscall-trace.md` (which captured connection-only).
Use the two together to see which capabilities surface only under
real workloads.

## Methodology

- Image: `litebox-vscode` (not `-prewrite`, not `-cached`).
- Container: `litebox-vscode-trace2` on host port 2223 → 22, with
  `--cap-add SYS_PTRACE --security-opt seccomp=unconfined`.
- ssh server: `dropbear -F -E -B -R -p 22`.
- Auth: empty root password.
- VS Code: 1.119.0 from the user's Windows side.
- Trace: `strace -f -tt -T -y -s 256 -e trace=all -o /trace/trace.log -p 1`.
- Duration: ~5 min from connect through Copilot-Chat conversation
  to disconnect.
- Output: 146 MB, **889 131** trace lines, **122** unique syscalls.

Raw artifacts in this directory (the 146 MB raw log is gitignored):

- `trace.log` — full strace output (gitignored).
- `top50-by-count.txt` — top 50 syscalls by frequency.
- `syscall-unique.txt` — sorted unique syscall names (122 entries).
- `socket-families.txt` — `socket()` family histogram.
- `key-syscalls-by-scenario.txt` — capability-relevant syscall counts.

## Top syscalls by count

```
 112061 futex
  87904 write
  62469 read
  39141 epoll_pwait
  23246 statx
  21593 mmap
  18423 recvfrom
  17317 close
  13342 munmap
  13284 newfstatat
  11830 openat
  11679 rt_sigaction
  10199 mprotect
   8252 fcntl
   7682 fstat
   6461 rt_sigprocmask
   6101 getdents64
   6064 stat
   5459 madvise
   4214 mkdir
   4170 open
   3929 brk
   3069 pselect6
   3018 writev
   2978 utimensat
   2861 fchmod
   2131 getpid
   1932 sendto
   1877 ioctl
   1796 access
   1673 lseek
   1566 poll
   1564 pread64
   1385 setsockopt
   1343 inotify_add_watch
   1269 set_robust_list
   1263 geteuid
   1221 getuid
   1207 getgid
   1207 getegid
   1110 wait4
    974 sched_yield
    851 dup2
    851 connect
    786 prlimit64
    758 execve
    709 readlink
    695 clone
    680 getrandom
    665 rseq
```

## Hot/Warm/Cold delta vs connection-only trace

| Capability | connect-only | combined | delta | tier |
|---|---:|---:|---:|---|
| **`inotify_add_watch`** | 5 | **1 343** | **+268× ⚡** | 🔥 hot (was ⚠️ warm) |
| `inotify_init1` | 1 | 2 | +1× | ⚠️ warm |
| **`TIOCGPGRP`** (terminal) | 10 | **453** | **+45×** | 🔥 hot |
| **`TIOCSPGRP`** (terminal) | 2 | **21** | **+10×** | 🔥 hot |
| **`TIOCSWINSZ`** (terminal resize) | 4 | **33** | **+8×** | 🔥 hot |
| **`TIOCSCTTY`** | 4 | 9 | +1× | 🔥 hot |
| `TCGETS` | 55 | 129 | +1× | 🔥 hot |
| `epoll_pwait` | 28 847 | **39 141** | +35% | 🔥 hot |
| `epoll_ctl` | 366 | 345 | flat | 🔥 hot |
| `clone3` | 62 | 92 | +48% | 🔥 hot |
| `clone` | 292 | 695 | +138% | 🔥 hot |
| `clone3 CLONE_VFORK` | 0 | **6** | **NEW** | ⚠️ warm |
| `eventfd2` | 20 | 28 | +40% | 🔥 hot |
| `pidfd_open` | 3 | 6 | +1× | ⚠️ warm |
| `io_uring_setup` | 18 | 25 | +39% | 🔥 hot |
| `io_uring_enter` | 158 | 347 | +120% | 🔥 hot |
| `socketpair` | 312 | 262 | flat | 🔥 hot |
| `setsockopt` | 1 547 | 1 385 | flat | 🔥 hot |
| `shutdown` | 59 | **214** | +260% | 🔥 hot |
| `sendmsg` | 1 | 2 | flat | ⚠️ warm |
| `recvmsg` | 213 | **476** | +124% | 🔥 hot |
| **`SCM_RIGHTS`** | 0 (search miss) | **4** | **CONFIRMED** | ⚠️ warm |
| `getrandom` | 217 | 680 | +213% | 🔥 hot |
| **`statx`** | 12 757 | **23 246** | +82% | 🔥 hot |
| `mmap MAP_FIXED` | not reported | **5 758** | NEW data | 🔥 hot |
| `mmap MAP_SHARED` | not reported | 51 | new data | ⚠️ warm |
| `setsid` | 7 | 13 | +1× | 🔥 hot |
| `prctl` | 85 | 187 | +120% | 🔥 hot |
| `arch_prctl` | 154 | 579 | +276% | 🔥 hot |

### Capabilities still cold (0 calls in combined trace)

- `signalfd` / `signalfd4`
- `timerfd_create`, `timerfd_settime`, `timerfd_gettime`
- `fanotify_init`, `fanotify_mark`
- `pidfd_send_signal`, `pidfd_getfd`
- `memfd_create`
- `splice`, `sendfile`, `tee`
- `vfork`, `unshare`, `ptrace`
- `mount`, `umount2`, `pivot_root`
- `epoll_create` (only `epoll_create1` is used)
- `epoll_wait` (only `epoll_pwait` is used)
- `epoll_pwait2`
- `linkat`, `O_TMPFILE`
- `io_uring_register`
- `membarrier`, `sched_setaffinity`

These could still surface under workflows we didn't drive (heavy
debug session; running large builds; very long-lived watchers).
The trace doesn't refute their use; it just shows VS Code's
connect+workspace+terminal+edit+chat path doesn't need them.

## Key new findings vs the connection-only trace

1. **`inotify_add_watch` exploded from 5 → 1 343** the moment a
   workspace was opened. This is by far the biggest capability
   delta. VS Code is watching a substantial number of paths.
   Previously borderline cold; now firmly hot.

2. **`SCM_RIGHTS` is confirmed real** — was inconclusive in the
   connect-only trace. The combined trace has 4 calls passing
   `VSCODE_EXTHOST_IPC_SOCKET` fds between the server and the
   extension host. Sample line:
   ```
   sendmsg(…, {msg_iov=[{iov_base="{\"cmd\":\"NODE_HANDLE\",\"type\":\"net.Socket\",\"msg\":{\"type\":\"VSCODE_EXTHOST_IPC_SOCKET\",…}\n", iov_len=239}],
            msg_control=[{cmsg_len=20, cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, cmsg_data=[22<socket:…>]}], …}, 0 …)
   ```
   Light usage (4 calls), but it's on the **critical extension-host
   wireup path** — a litebox shim that drops SCM_RIGHTS would break
   the extension host loading.

3. **TTY ioctl pressure jumped substantially** (`TIOCGPGRP` 10 →
   453, `TIOCSPGRP` 2 → 21, `TIOCSWINSZ` 4 → 33) — the integrated
   terminal exercises foreground-pgrp management heavily. The
   shim's TIOCSPGRP / TIOCGPGRP handlers must work correctly for
   any terminal command to run.

4. **`clone3` with `CLONE_VFORK`** appeared (6 calls) — wasn't in
   connect-only. Probably the integrated terminal's posix_spawn
   for the shell.

5. **`io_uring_enter` more than doubled** (158 → 347). VS Code
   uses io_uring more under sustained load. Litebox's
   consistent-ENOSYS contract still holds; libuv must be falling
   back to epoll cleanly.

6. **`statx` doubled and is the #5 syscall** (23 K calls) — heavy
   stat traffic from file-watcher and editor file-info reads.

## Recommended re-rankings

(Against the layer-1 audit doc plus the new findings.)

| Item | Combined-trace ranking |
|---|---|
| inotify_add_watch shim coverage | **upgrade to 🔥 vs-code-blocker** (was warm in connect-only) |
| TIOCSPGRP / TIOCGPGRP handlers | **upgrade — confirmed hot under terminal use** |
| TIOCSWINSZ + SIGWINCH delivery | **upgrade — terminal resize is real, not just connect-time** |
| SCM_RIGHTS | **confirmed real, not just theoretical** — upgrade `audit-fix-scm-rights` from "needs re-inspection" to vs-code-blocker |
| clone3 CLONE_VFORK path | **NEW row** — terminal posix_spawn pattern |
| signalfd / timerfd_* | **still cold** in combined trace; deferral remains correct unless deeper traces (debug session) surface them |
| splice / sendfile / memfd_create | **still cold** — defer |

## Methodology block (for re-running on a later trace)

```sh
export DOCKER_HOST="${DOCKER_HOST:-unix:///run/litebox-docker.sock}"
docker rm -f litebox-vscode-trace2
docker run -d --name litebox-vscode-trace2 \
  --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
  -p 2223:22 --entrypoint /usr/sbin/dropbear \
  litebox-vscode -F -E -B -R -p 22

# Start strace inside the container
docker exec -d litebox-vscode-trace2 bash -c \
  'mkdir -p /trace && strace -f -tt -T -y -s 256 -e trace=all -o /trace/trace.log -p 1 & sleep 999999'

# (Drive the workflow from a real VS Code; empty-password root on port 2223.)

# Capture & teardown
docker cp litebox-vscode-trace2:/trace/trace.log results-combined/trace.log
docker rm -f litebox-vscode-trace2

# Analysis
cd dev_tools/syscall_analysis/results-combined
grep -oP '^\d+\s+\d+:\d+:\d+\.\d+ \K[a-z_0-9]+(?=\()' trace.log \
  | sort | uniq -c | sort -rn | head -50 > top50-by-count.txt
grep -oP '^\d+\s+\d+:\d+:\d+\.\d+ \K[a-z_0-9]+(?=\()' trace.log \
  | sort -u > syscall-unique.txt
grep -oP 'socket\(\K[A-Z_0-9]+' trace.log \
  | sort | uniq -c | sort -rn > socket-families.txt
```

## Cross-references

- `docs/audit/vscode-syscall-trace.md` — connection-only trace
  (predecessor; smaller workload).
- `docs/audit/vscode-capabilities.md` — original 37-row capability
  matrix from the test-framework audit.
- `docs/audit/test-scenario-priorities.md` — uses this trace's data
  to rank existing test families and surface coverage gaps.
- `docs/test-framework-audit.md` — master audit report.