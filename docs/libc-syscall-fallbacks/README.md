# libc syscall fallbacks: what the Linux shim can defer, and what it must get right

glibc and musl try a newer syscall first and fall back to an older one when the kernel
says it does not exist. This note lists those fallbacks, checks them by injecting failures,
and turns them into a priority order for `litebox_shim_linux`.

Sources and runtimes:

- glibc source: master `badd7eb667c7` (2.44.9000).
- glibc runtime: Ubuntu 2.39, the host's.
- musl source: master `7813e911`, built locally (VERSION 1.2.6). Its `pwrite` was
  checked against Alpine 3.24's musl 1.2.6-r3.
- LiteBox: debug build of this worktree's shim (`053c3a4dc`) plus the `renameat2` stub
  from `ulitebox-stub-renameat2`.

## How the fallbacks work

- **glibc** assumes a minimum kernel: 3.2 on x86_64, 3.7 on aarch64. Any syscall added
  later is probed at run time (`__ASSUME_*` in `sysdeps/unix/sysv/linux/kernel-features.h`).
  Distro builds keep these run-time fallbacks; the 2.39 host build took every one we tested.
  Almost all of them trigger only on `ENOSYS`.
- **musl** has no minimum kernel and probes at run time. Fallbacks to legacy syscalls
  (`pipe`, `dup2`, `epoll_wait`, `signalfd`, `futimesat`, ...) are compiled only when the
  architecture has the legacy syscall. x86_64 has them; aarch64 does not, so on aarch64
  `pipe2`, `dup3`, `epoll_pwait`, `ppoll`, `pselect6`, the `*at` calls, etc. are required.
- **Fixed at build time, not a fallback:** on x86_64 both libcs call some legacy syscalls
  directly and never retry. glibc calls `access`, `unlink`, `rmdir`, `mkdir`, `rename`,
  `link`, `symlink`, `readlink`, `chmod`, `chown`, `lchown`, `creat`, `dup2`, `poll`,
  `epoll_wait`, `epoll_create`, `inotify_init`, `pause`, `alarm`, `getpgrp`, `vfork`.
  musl adds `open`, `stat`, `lstat`, `select`. glibc's `pipe()` always uses `pipe2`, and
  `open()` always uses `openat`.
- **No vDSO in LiteBox.** `get_vdso_address()` returns `None`, so `clock_gettime`,
  `gettimeofday`, `time`, `clock_getres`, `getcpu` (and `getrandom` in glibc 2.41 and
  later) become real syscalls.

## Bugs found: the shim breaks a libc fallback (confirmed under LiteBox)

| # | Symptom | Cause | Fix |
|---|---|---|---|
| 1 | glibc: `pthread_mutex_init(PTHREAD_PRIO_INHERIT)` then lock aborts: *"The futex facility returned an unexpected error code"* | glibc probes PI support with `FUTEX_UNLOCK_PI` and falls back only on `ENOSYS`. The shim answers unknown futex ops with `EINVAL` (`parse_futex` → `unsupported_einval`); Linux returns `ENOSYS` | Unknown futex op → `ENOSYS`. glibc then reports `ENOTSUP` cleanly (checked) |
| 2 | musl: `pthread_cond_broadcast` with 2 or more waiters hangs forever | musl's condvar hands waiters over with `FUTEX_REQUEUE`. Its only fallback (on `ENOSYS`) is the same op without `FUTEX_PRIVATE`. There is no real fallback, so `FUTEX_REQUEUE` is required for musl | Implement `FUTEX_REQUEUE` (and `FUTEX_CMP_REQUEUE`) |
| 3 | glibc `tmpfile()` makes the shim panic (`file.rs:355`, `unimplemented!("{flags:?}")`) | glibc tries `open(P_tmpdir, O_TMPFILE)` first and falls back on *any* error. A panic gives it no chance | Unsupported open flags → error, not panic. For `O_TMPFILE`, `EOPNOTSUPP` (what Linux returns when the filesystem lacks support) |
| 4 | glibc: a thread exits holding a robust mutex → shim panics (`process.rs:1238` `todo!`) | `set_robust_list` succeeds, so glibc relies on the kernel to mark the dead owner. glibc has no fallback: with `set_robust_list` → `ENOSYS` the next lock hangs (checked). musl cleans up in userspace and is unaffected | Implement `handle_futex_death` |
| 5 | `fchmodat(..., AT_SYMLINK_NOFOLLOW)` fails: glibc `EOPNOTSUPP`, musl `ENOENT`. coreutils 9.4 `cp -a`/`cp -r` and `tar` call it | `fchmodat2` is missing. Both libcs fall back to `openat(O_PATH)` + `chmod("/proc/self/fd/N")`; the shim answers `stat` on that path but not `chmod` (`ENOENT`) | Implement `fchmodat2`: it is `fchmodat` plus "NOFOLLOW on a symlink → `EOPNOTSUPP`" |
| 6 | `sched_getcpu()` → `ENOSYS` | glibc tries rseq `cpu_id`, then the vDSO, then the `getcpu` syscall. musl tries the vDSO, then the syscall. In LiteBox all three are missing | Add `getcpu` |
| 7 | (main branch) `renameat2` with flags panics (`unimplemented!`) | glibc and gnulib `mv` expect `EINVAL`/`ENOSYS` and retry `renameat` | Already fixed on `ulitebox-stub-renameat2` (`EINVAL`) |

Lesser cases:

- `fexecve` fails (glibc `ENOSYS`, musl `EBADF`): `execveat` is missing and the fallback,
  `execve("/proc/self/fd/N")`, does not resolve.
- `posix_fallocate`: glibc emulates it only on `EOPNOTSUPP`, not `ENOSYS`. Until
  `fallocate` is implemented, returning `EOPNOTSUPP` makes glibc write the blocks itself.

## Safe to defer: libc recovers from `ENOSYS`

These were checked by injecting `ENOSYS` with strace, one syscall at a time
(`matrix.txt`); each wrapper still succeeds:

| Advanced syscall (Linux version) | Used by | Falls back to | Libc | Shim today |
|---|---|---|---|---|
| `clone3` (5.3) | `pthread_create`; `posix_spawn`/`system` (also on `EINVAL`) | `clone`, `clone(CLONE_VM\|CLONE_VFORK)` | glibc | implemented |
| `faccessat2` (5.8) | `faccessat` (glibc: every call; musl: flags ≠ 0) | `faccessat` (+ `fstatat` emulation) | both | implemented |
| `statx` (4.11) | the `statx()` API only; `stat`/`fstat` don't use it on 64-bit | `fstatat`/`stat` | both | implemented |
| `close_range` (5.9) | `closefrom`, `posix_spawn` closefrom action | walk `/proc/self/fd` | glibc | implemented |
| `preadv2`/`pwritev2` (4.6), flags = 0 | `preadv2`/`pwritev2` | `preadv`/`pwritev` | glibc | missing (ok) |
| `pwritev2(RWF_NOAPPEND)` (6.9) | **every** musl ≥ 1.2.6 `pwrite`/`pwritev` (`ENOSYS` or `EOPNOTSUPP`) | `fcntl(F_GETFL)` + `pwrite64` | musl | missing: works, but 3 syscalls per `pwrite` and a WARN log each time |
| `prlimit64` | `getrlimit`/`setrlimit` | `getrlimit`/`setrlimit` | musl (glibc: none) | implemented |
| `pipe2`, `dup3`, `accept4`, `signalfd4` | flag variants | legacy call + `fcntl` | musl, x86_64 only | implemented except `signalfd*` |
| `eventfd2`, `epoll_create1`, `inotify_init1` | only with flags = 0 | legacy call | musl, x86_64 | implemented except `inotify*` |
| `epoll_pwait` | musl `epoll_wait` | `epoll_wait` | musl | implemented |
| `utimensat` | flags = 0 | `futimesat` → `utimes` | musl, x86_64 | implemented |
| `socket`/`socketpair` with `SOCK_CLOEXEC`, `fcntl(F_DUPFD_CLOEXEC)`, `F_GETOWN_EX` (all on `EINVAL`) | | flagless call + `fcntl`; `F_GETOWN` | musl | first two implemented; `F_GETOWN*` missing (`EINVAL`) |
| `rseq` | thread start (any error) | rseq disabled | glibc | `ENOSYS` (quiet) ✓ |
| `membarrier` | musl `dlopen` of TLS libraries (any error) | signal broadcast | musl | missing (ok) |
| `MADV_GUARD_INSTALL` (6.13) | glibc ≥ 2.42 thread stacks (any error) | `mprotect(PROT_NONE)` guard | glibc | `EINVAL` ✓ (from source; no 2.42 runtime here) |
| `getrandom` | malloc tcache key, temp names (any error) | clock bits | glibc | implemented |
| `getrandom` | `arc4random` | `/dev/urandom` from glibc 2.40; **2.39 aborts** | glibc | implemented |
| `FUTEX_LOCK_PI2` (5.14) | PI timed lock | `FUTEX_LOCK_PI` | glibc | n/a |
| `renameat2`/`mlock2` with flags ≠ 0 | | glibc turns `ENOSYS` into `EINVAL`; musl passes it through | | stub / missing |

## No libc fallback: the caller sees the error

- **Startup** (strace of hello world plus one thread):
  - glibc: `execve`, `brk`, `mmap`, `munmap`, `mprotect`, `arch_prctl(SET_FS)`,
    `set_tid_address`, `set_robust_list`, `openat`, `read`, `pread64`, `fstat`, `close`,
    `write`, `ioctl(TCGETS)`, `exit_group`. Threads add `clone3`/`clone`, `futex`,
    `rt_sigprocmask`, `rt_sigaction`, `madvise`, `exit`. A failing `rseq`, `getrandom` or
    `prlimit64` is tolerated at startup.
  - musl: `arch_prctl`, `set_tid_address`, `ioctl(TIOCGWINSZ)`, `writev`, `exit_group`
    (dynamic adds `brk`, `mmap`, `mprotect`). Threads add `clone`, `futex`,
    `rt_sigprocmask`.
- **glibc on x86_64:** `newfstatat` (`stat`/`lstat`/`fstatat`), `fstat` (the loader dies
  without it), `prlimit64`, `pipe2`, `dup3`, `accept4`, `eventfd2`, `epoll_create1`,
  `signalfd4`, `inotify_init1`, `utimensat`.
- **Futex ops:** `WAIT`, `WAKE`, `WAIT_BITSET` with `CLOCK_REALTIME` (glibc); add
  `REQUEUE` for musl. glibc aborts on unexpected futex errors such as `EFAULT`/`ENOSYS`
  from `WAIT`.
- **Missing in the shim and called directly by libc wrappers.** Seen in a common-tools
  trace (cp, tar, git, python3 + sqlite3, find, ln, install, ls):
  - `fdatasync`/`fsync`: sqlite3, git
  - `fchmod`: cp
  - `fchdir`: find, mkdir -p
  - `link`: git (x86_64 glibc uses `link`, not `linkat`)
  - `linkat`: ln
  - `fchmodat2`: cp, tar
  - `*xattr`: cp -a, ls, install
  - `fadvise64`: cp, sort
  - `copy_file_range`: cp
  - `openat2`: GNU tar

  Also missing and libc-direct: `fchown`, `lchown`, `truncate`, `waitid`, `getres[ug]id`,
  the `set*id` family, `rt_sigtimedwait`, `sched_setaffinity`, `mlock`/`munlock`, `msync`,
  `timer_*`, `memfd_create`, `fallocate`, `inotify*`, `signalfd*`.
  `copy_file_range` and `fadvise64` have fallbacks in the applications (cp retries with
  read/write on `ENOSYS`, `EINVAL` or `EXDEV`; hints are ignored), but not in libc.

## Suggested priority

1. **Fix the errno contract and the panics on paths libc already probes** (bugs 1–4 and 7):
   futex `ENOSYS`, `FUTEX_REQUEUE`, no `unimplemented!`/`todo!` on reachable inputs,
   robust futex death. Each is small, and each currently turns a working fallback into a
   crash or hang.
2. **Required, no fallback, used by common tools:** `fsync`/`fdatasync`, `fchmod`, `fchown`,
   `fchdir` (in progress on `ulitebox-fchdir`), `link`/`linkat`, `lchown`, `truncate`,
   `getcpu`.
3. **Advanced, but the libc fallback depends on something the shim lacks**
   (`/proc/self/fd` chmod/execve): `fchmodat2` (trivial, and hit by cp/tar), then
   `execveat`.
4. **Advanced with a working fallback; worth it for speed or log noise only:**
   `pwritev2`/`preadv2` (musl pays 3× per `pwrite`), `membarrier`, `rseq`,
   `MADV_GUARD_INSTALL`, `mlock2`, `renameat2` flags, `FUTEX_LOCK_PI2`, a vDSO.
   `clone3`, `faccessat2`, `statx`, `close_range`, `prlimit64` and `epoll_pwait` are
   already done.
5. **No libc fallback, applications cope:** `copy_file_range`, `memfd_create`, `openat2`,
   `epoll_pwait2`, `pidfd_*`, `io_uring` (already a quiet `ENOSYS`). `fallocate` belongs
   here; meanwhile return `EOPNOTSUPP` (see above).

## Rules for the shim's error codes

- Unknown syscall → `ENOSYS`. Unknown futex op (or `CLOCK_REALTIME` on an op that does not
  allow it) → `ENOSYS`, as Linux does.
- Known syscall with unknown flags or arguments → `EINVAL`. A feature the filesystem does
  not support → `EOPNOTSUPP` (`O_TMPFILE`, `fallocate`).
- Never panic on input a guest can supply. libc's "try the new thing" probes reach these
  paths routinely.
- Never return success for something that is not implemented. libc stops looking for
  alternatives once a probe succeeds. Bug 4 is this case, and a no-op `MADV_GUARD_INSTALL`
  would silently remove thread-stack guard pages.
- aarch64 has no legacy syscalls, so the `*at`/`2`/`1`/`p*` variants are required there for
  both libcs.

## Reproducing

```sh
# Host, glibc and musl, one ENOSYS injection at a time (+ futex errno simulation):
MUSL_GCC=/path/to/musl-gcc ./run-matrix.sh      # -> matrix.txt
# Under LiteBox (static probes; one guest per test so a crash loses only that test):
gcc -O1 -static -pthread -o probe-glibc-static probe.c
LB=/path/to/target/debug ./run-litebox.sh probe-glibc-static probe-musl   # -> litebox-results.txt
```

`probe.c` calls each libc wrapper once and prints `OK` or `FAIL errno=...`.
`SIM_FUTEX_ERRNO=<n>` installs a seccomp filter that fails futex ops other than
`WAIT`/`WAKE`/`*_BITSET` with errno `n`, mimicking the shim on the host.
