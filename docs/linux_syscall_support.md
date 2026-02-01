# Linux Syscall Support Status in `litebox_shim_linux`

This document provides a comprehensive overview of Linux syscall support in the LiteBox Linux shim (`litebox_shim_linux`).

## Overview

The Linux shim provides a POSIX-like interface for running unmodified Linux programs in sandboxed environments. It intercepts Linux syscalls and translates them to LiteBox's platform-agnostic APIs.

**Total Supported Syscalls: ~90+**

---

## Fully Implemented Syscalls

### Process/Thread Management

| Syscall | Status | Notes |
|---------|--------|-------|
| `exit` | ✅ Implemented | |
| `exit_group` | ✅ Implemented | |
| `clone` | ✅ Implemented | Some flags unsupported (see limitations) |
| `clone3` | ✅ Implemented | Some flags unsupported (see limitations) |
| `execve` | ✅ Implemented | |
| `getpid` | ✅ Implemented | |
| `getppid` | ✅ Implemented | |
| `gettid` | ✅ Implemented | |
| `getuid` | ✅ Implemented | |
| `geteuid` | ✅ Implemented | |
| `getgid` | ✅ Implemented | |
| `getegid` | ✅ Implemented | |
| `set_tid_address` | ✅ Implemented | |
| `set_robust_list` | ✅ Implemented | |
| `get_robust_list` | ✅ Implemented | Current process only |
| `set_thread_area` | ✅ Implemented | x86 only; returns ENOSYS on x86_64 |
| `prctl` | ✅ Implemented | PR_SET_NAME, PR_GET_NAME, PR_CAPBSET_READ |
| `arch_prctl` | ✅ Implemented | ARCH_SET_FS, ARCH_GET_FS, CET_STATUS, CET_DISABLE, CET_LOCK |
| `kill` | ✅ Implemented | |
| `tkill` | ✅ Implemented | |
| `tgkill` | ✅ Implemented | |

### Memory Management

| Syscall | Status | Notes |
|---------|--------|-------|
| `mmap` | ✅ Implemented | |
| `munmap` | ✅ Implemented | |
| `mprotect` | ✅ Implemented | |
| `mremap` | ✅ Implemented | |
| `brk` | ✅ Implemented | |
| `madvise` | ✅ Implemented | |

### File Operations

| Syscall | Status | Notes |
|---------|--------|-------|
| `open` | ✅ Implemented | Translated to `openat` with AT_FDCWD |
| `openat` | ✅ Implemented | |
| `creat` | ✅ Implemented | Translated to `openat` with O_CREAT\|O_WRONLY\|O_TRUNC |
| `read` | ✅ Implemented | Chunked for large reads to prevent OOM |
| `write` | ✅ Implemented | |
| `pread64` | ✅ Implemented | |
| `pwrite64` | ✅ Implemented | |
| `readv` | ✅ Implemented | |
| `writev` | ✅ Implemented | |
| `lseek` | ✅ Implemented | |
| `close` | ✅ Implemented | |
| `dup` | ✅ Implemented | |
| `dup2` | ✅ Implemented | |
| `dup3` | ✅ Implemented | |
| `fcntl` | ✅ Implemented | |
| `fcntl64` | ✅ Implemented | x86 only |
| `ioctl` | ✅ Implemented | TCGETS, TCSETS, TIOCGWINSZ, TIOCGPTN, FIONBIO, FIOCLEX |
| `stat` | ✅ Implemented | |
| `lstat` | ✅ Implemented | |
| `fstat` | ✅ Implemented | |
| `newfstatat` | ✅ Implemented | x86_64 only |
| `fstatat64` | ✅ Implemented | x86 only |
| `access` | ✅ Implemented | |
| `readlink` | ✅ Implemented | |
| `readlinkat` | ✅ Implemented | |
| `mkdir` | ✅ Implemented | |
| `unlink` | ✅ Implemented | Translated to `unlinkat` with AT_FDCWD |
| `unlinkat` | ✅ Implemented | |
| `ftruncate` | ✅ Implemented | |
| `getcwd` | ✅ Implemented | |
| `getdents64` | ✅ Implemented | |
| `pipe` | ✅ Implemented | Translated to `pipe2` with flags=0 |
| `pipe2` | ✅ Implemented | |
| `umask` | ✅ Implemented | |

### Networking

| Syscall | Status | Notes |
|---------|--------|-------|
| `socket` | ✅ Implemented | AF_INET (TCP/UDP), AF_UNIX |
| `socketpair` | ✅ Implemented | |
| `bind` | ✅ Implemented | |
| `listen` | ✅ Implemented | |
| `accept` | ✅ Implemented | x86_64 only |
| `accept4` | ✅ Implemented | |
| `connect` | ✅ Implemented | |
| `sendto` | ✅ Implemented | |
| `sendmsg` | ✅ Implemented | |
| `recvfrom` | ✅ Implemented | |
| `setsockopt` | ✅ Implemented | |
| `getsockopt` | ✅ Implemented | |
| `getsockname` | ✅ Implemented | |
| `getpeername` | ✅ Implemented | |
| `socketcall` | ✅ Implemented | x86 only (multiplexed socket syscall) |

### I/O Multiplexing

| Syscall | Status | Notes |
|---------|--------|-------|
| `poll` | ✅ Implemented | Translated to `ppoll` |
| `ppoll` | ✅ Implemented | |
| `ppoll_time64` | ✅ Implemented | x86 only |
| `select` | ✅ Implemented | x86_64 only |
| `_newselect` | ✅ Implemented | x86 only |
| `pselect6` | ✅ Implemented | x86_64 only |
| `pselect6_time64` | ✅ Implemented | x86 only |
| `epoll_create` | ✅ Implemented | |
| `epoll_create1` | ✅ Implemented | |
| `epoll_ctl` | ✅ Implemented | ADD/DEL fully supported; MOD partial |
| `epoll_wait` | ✅ Implemented | |
| `epoll_pwait` | ✅ Implemented | |
| `eventfd` | ✅ Implemented | |
| `eventfd2` | ✅ Implemented | |

### Signals

| Syscall | Status | Notes |
|---------|--------|-------|
| `rt_sigprocmask` | ✅ Implemented | |
| `rt_sigaction` | ✅ Implemented | |
| `rt_sigreturn` | ✅ Implemented | |
| `sigreturn` | ✅ Implemented | x86 only |
| `sigaltstack` | ✅ Implemented | |

### Time

| Syscall | Status | Notes |
|---------|--------|-------|
| `clock_gettime` | ✅ Implemented | |
| `clock_gettime64` | ✅ Implemented | x86 only |
| `clock_getres` | ✅ Implemented | |
| `clock_getres_time64` | ✅ Implemented | x86 only |
| `clock_nanosleep` | ✅ Implemented | |
| `clock_nanosleep_time64` | ✅ Implemented | x86 only |
| `nanosleep` | ✅ Implemented | Translated to `clock_nanosleep` with CLOCK_MONOTONIC |
| `gettimeofday` | ✅ Implemented | |
| `time` | ✅ Implemented | |

### Synchronization

| Syscall | Status | Notes |
|---------|--------|-------|
| `futex` | ✅ Implemented | FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAKE |
| `futex_time64` | ✅ Implemented | x86 only |

### Resource Limits & System Information

| Syscall | Status | Notes |
|---------|--------|-------|
| `getrlimit` | ✅ Implemented | |
| `ugetrlimit` | ✅ Implemented | x86 only |
| `setrlimit` | ✅ Implemented | |
| `prlimit64` | ✅ Implemented | Current process only |
| `sysinfo` | ✅ Implemented | |
| `uname` | ✅ Implemented | |
| `getrandom` | ✅ Implemented | |
| `capget` | ✅ Implemented | |
| `sched_getaffinity` | ✅ Implemented | |
| `sched_yield` | ✅ Implemented | No-op currently |

---

## Explicitly Not Implemented

These syscalls are recognized but explicitly return `ENOSYS`:

| Syscall | Notes |
|---------|-------|
| `statx` | Extended file status - not implemented |
| `io_uring_setup` | io_uring not supported |
| `rseq` | Restartable sequences not supported |
| `statfs` | Filesystem statistics not implemented |

---

## Parsed But Not Fully Handled

These syscalls are parsed from the syscall request but may not be fully implemented in the handler:

| Syscall | Notes |
|---------|-------|
| `alarm` | Parsed; implementation status unclear |
| `setitimer` | Parsed; implementation status unclear |

---

## Known Limitations

### Clone Flags
The following `clone` flags are **not supported**:
- `CLONE_INTO_CGROUP` - Clone into a specific cgroup
- `CLONE_SET_TID` - Set specific TID for new thread

### Futex
- **Shared futexes** (`FUTEX_PRIVATE_FLAG` not set) are not supported
- Only private (process-local) futexes work

### File Descriptors
- `fcntl` `F_SETFL` on non-stdio file descriptors has limited support
- `openat` with `FsPath::Fd` or `FsPath::FdRelative` is not implemented

### Epoll
- `epoll_ctl` with `EPOLL_CTL_MOD` is only partially implemented

### Poll/Select with Signals
- `ppoll` and `pselect` sigmask parameter is not fully supported

### Resource Limits
- `prlimit64` for processes other than the current process is not supported
- `get_robust_list` for other PIDs is not supported

### UNIX Sockets
- `SO_PEERCRED` socket option is not implemented for all socket types

### Pipes
- `SIGPIPE` signal is not sent on write to closed pipe (logged as unimplemented)

---

## Architecture-Specific Notes

### x86_64
- `set_thread_area` returns `ENOSYS` (use `arch_prctl` with `ARCH_SET_FS` instead)
- `accept` syscall is available (in addition to `accept4`)

### x86 (32-bit)
- `set_thread_area` is fully implemented
- `socketcall` multiplexed syscall is supported
- Time64 variants of syscalls are available for Y2038 compatibility

---

## Build & Test Commands

```bash
# Build the linux userland runner
cargo build -p litebox_runner_linux_userland

# Run all tests
cargo nextest run -p litebox_runner_linux_userland

# Run a specific test
cargo nextest run -p litebox_runner_linux_userland test_static_exec_with_rewriter

# Run tests with output visible
cargo nextest run -p litebox_runner_linux_userland -- --nocapture

# Run with release build (for performance tests like iperf3)
cargo test --package litebox_runner_linux_userland --test run --release -- test_tun_and_runner_with_iperf3 --exact --nocapture

# Build 32-bit version
cargo build -p litebox_runner_linux_userland --target=i686-unknown-linux-gnu
```

### TUN Device Setup (Required for Network Tests)

```bash
sudo ./litebox_platform_linux_userland/scripts/tun-setup.sh
```

---

## Related Files

- **Syscall dispatcher**: `litebox_shim_linux/src/lib.rs` (see `do_syscall` method)
- **Syscall request parsing**: `litebox_common_linux/src/lib.rs` (see `SyscallRequest` enum)
- **File operations**: `litebox_shim_linux/src/syscalls/file.rs`
- **Memory management**: `litebox_shim_linux/src/syscalls/mm.rs`
- **Process management**: `litebox_shim_linux/src/syscalls/process.rs`
- **Networking**: `litebox_shim_linux/src/syscalls/net.rs`
- **UNIX sockets**: `litebox_shim_linux/src/syscalls/unix.rs`
- **Signals**: `litebox_shim_linux/src/syscalls/signal/mod.rs`
- **Epoll**: `litebox_shim_linux/src/syscalls/epoll.rs`
- **Eventfd**: `litebox_shim_linux/src/syscalls/eventfd.rs`
