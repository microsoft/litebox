# LiteBox Linux Syscall Implementation Plan

This document provides a prioritized plan for improving and implementing Linux syscalls in `litebox_shim_linux`, based on research from:
1. **Asterinas** and other Rust OS projects
2. **Current LiteBox codebase** gap analysis
3. **Syscall frequency data** and real-world usage patterns

---

## Executive Summary

LiteBox already has excellent coverage of critical syscalls (~95% of Tier 1, ~90% of Tier 2). The focus should be on:
1. **Completing partial implementations** (highest ROI)
2. **Adding commonly-needed syscalls** that block real applications
3. **Stubbing syscalls** that can be safely ignored

---

## Priority Matrix

| Priority | Criteria | Implementation Strategy |
|----------|----------|------------------------|
| **P0 - Critical** | Blocking real apps, easy fix | Implement immediately |
| **P1 - High** | Commonly needed, moderate effort | Implement in next sprint |
| **P2 - Medium** | Feature completeness | Implement when needed |
| **P3 - Low** | Edge cases, complex | Defer or stub |

---

## P0: Critical - Complete Partial Implementations

These are already parsed/partially implemented but have `todo!()`, `unimplemented!()`, or `log_unsupported!()` markers that break real applications.

### 1. Alarm & Timer Handlers
**Files:** `litebox_shim_linux/src/lib.rs`, `litebox_shim_linux/src/syscalls/process.rs`
**Status:** Parsed in `SyscallRequest` but not handled in `do_syscall`
**Difficulty:** Medium
**Impact:** High - needed for timeouts in many applications

```
Syscalls: alarm, setitimer, getitimer
```

**Implementation notes:**
- Need timer infrastructure in the shim
- Can integrate with existing `clock_nanosleep` mechanism
- Asterinas implements via `timer_create`/`timer_settime` infrastructure

### 2. EPOLL_CTL_MOD Support
**File:** `litebox_shim_linux/src/syscalls/epoll.rs` (line 184)
**Status:** `log_unsupported!("epoll_ctl mod")`
**Difficulty:** Easy-Medium
**Impact:** Critical - Node.js, Python asyncio, and most event-driven apps need this

**Implementation notes:**
- Already have ADD/DEL working
- MOD is essentially DEL + ADD with updated events
- Look at Asterinas `epoll_ctl` for reference

### 3. SIGPIPE Signal Delivery
**Files:** Multiple locations in `file.rs`, `net.rs`, `unix.rs`
**Status:** `unimplemented!("send SIGPIPE to the current task")`
**Difficulty:** Medium
**Impact:** High - proper pipe/socket error handling

**Locations needing fix:**
- `syscalls/file.rs:348` - pipe write
- `syscalls/file.rs:607` - pipe write
- `syscalls/net.rs:364` - network EPIPE
- `syscalls/unix.rs:1240` - unix socket EPIPE

### 4. pselect/ppoll with Signal Mask
**File:** `litebox_shim_linux/src/syscalls/file.rs`
**Status:** `unimplemented!("no sigmask support yet")` (line 1544, 1676)
**Difficulty:** Medium
**Impact:** High - signal-safe I/O multiplexing

**Implementation notes:**
- Need to atomically set signal mask during wait
- Restore original mask after wait completes

### 5. fcntl F_SETFL on Non-Stdio
**File:** `litebox_shim_linux/src/syscalls/file.rs` (line 1041)
**Status:** `unimplemented!("SETFL on non-stdio")`
**Difficulty:** Easy
**Impact:** High - setting O_NONBLOCK on files/sockets

---

## P1: High Priority - Add Missing Syscalls

These syscalls are commonly needed and have reasonable implementation effort.

### File Operations

| Syscall | Difficulty | Notes |
|---------|------------|-------|
| `fsync`, `fdatasync` | Easy | Can stub as no-op initially; needed for databases |
| `sync` | Easy | Sync all files to disk |
| `rename`, `renameat`, `renameat2` | Medium | Common file operation |
| `chmod`, `fchmod`, `fchmodat` | Easy | Permission changes |
| `chown`, `fchown`, `fchownat`, `lchown` | Easy | Ownership changes |
| `link`, `linkat` | Easy | Hard links |
| `symlink`, `symlinkat` | Easy | Symbolic links |
| `flock` | Medium | File locking - many apps depend on it |
| `utimes`, `utimensat`, `futimesat` | Easy | Timestamp modification |
| `faccessat` | Easy | Permission check with flags |

### Networking

| Syscall | Difficulty | Notes |
|---------|------------|-------|
| `recvmsg` | Medium | Complete socket API; high value |
| `shutdown` | Easy | Proper socket cleanup |
| `sendfile` | Medium | Zero-copy; major performance win |
| `sendmmsg`, `recvmmsg` | Medium | Batch send/receive |

### Process Management

| Syscall | Difficulty | Notes |
|---------|------------|-------|
| `wait4`, `waitpid`, `waitid` | Medium | Process waiting (needed if supporting fork) |
| `getrusage` | Easy | Resource usage statistics |
| `getpgid`, `setpgid` | Easy | Process groups |
| `getsid`, `setsid` | Easy | Sessions |
| `capset` | Easy | Set capabilities |
| `sched_setaffinity` | Easy | Set CPU affinity |

### Memory

| Syscall | Difficulty | Notes |
|---------|------------|-------|
| `msync` | Easy | Sync mapped file |
| `mlock`, `munlock` | Medium | Lock memory pages |

---

## P2: Medium Priority - Feature Completeness

### Complete IPv6 Support
**File:** `litebox_shim_linux/src/syscalls/net.rs`
**Status:** `todo!("copy_sockaddr_to_user for IPv6")`
**Difficulty:** Medium

### openat with Directory FD
**File:** `litebox_shim_linux/src/syscalls/file.rs` (lines 170, 174, 226)
**Status:** `log_unsupported!("openat with FsPath::Fd")`
**Difficulty:** Medium
**Notes:** Need to resolve paths relative to directory file descriptors

### Shared Futex Support
**File:** `litebox_shim_linux/src/syscalls/process.rs` (line 1214)
**Status:** `log_unsupported!("shared futex")`
**Difficulty:** Hard
**Notes:** Inter-process synchronization; complex but needed for some IPC

### Unix Socket Filesystem Paths
**File:** `litebox_shim_linux/src/syscalls/unix.rs`
**Status:** `TODO: extend fs to support sock file`
**Difficulty:** Medium
**Notes:** Currently only abstract namespace works

### SO_PEERCRED for Unix Sockets
**File:** `litebox_shim_linux/src/syscalls/unix.rs` (line 1422)
**Status:** `log_unsupported!("get PEERCRED for unix socket")`
**Difficulty:** Medium
**Notes:** Credential passing for IPC authentication

### Additional Syscalls

| Syscall | Difficulty | Notes |
|---------|------------|-------|
| `statx` | Medium | Extended file status; modern apps use this |
| `statfs`, `fstatfs` | Easy | Filesystem statistics |
| `copy_file_range` | Medium | Efficient in-kernel file copy |
| `splice`, `tee` | Hard | Zero-copy data movement |
| `fallocate` | Medium | Preallocate file space |
| `fadvise64` | Easy | Can stub; advisory only |
| `signalfd4` | Medium | Alternative signal delivery |
| `timerfd_create`, `timerfd_settime`, `timerfd_gettime` | Medium | Timer file descriptors |
| `inotify_init`, `inotify_add_watch`, `inotify_rm_watch` | Medium | File system monitoring |

---

## P3: Low Priority - Defer or Stub

### Very Complex Syscalls

| Syscall | Difficulty | Recommendation |
|---------|------------|----------------|
| `fork`, `vfork` | Very Hard | Defer; use clone-only approach like gVisor |
| `io_uring_*` | Very Hard | Return ENOSYS; apps fall back to other APIs |
| `ptrace` | Very Hard | Return EPERM; typically disabled in sandboxes |
| `seccomp` | Hard | Return ENOSYS; meta-sandboxing not needed |

### Safe to Stub (Return Success)

| Syscall | Stub Approach | Notes |
|---------|---------------|-------|
| `rseq` | Return ENOSYS | glibc optimization; has fallback |
| `fadvise64` | Return 0 | Advisory; non-fatal if ignored |
| `madvise` (some flags) | Return 0 | Many flags are hints |
| `mincore` | Return success | Can pretend pages are resident |
| `membarrier` | Return 0 | Memory barrier; safe to stub |
| `pkey_*` | Return ENOSYS | Memory protection keys |
| `ioprio_*` | Return 0 | I/O priority hints |

---

## Implementation Roadmap

### Phase 1: Quick Wins (1-2 weeks)
Focus on P0 items that unblock applications:

1. ✅ Add `alarm`/`setitimer` handlers to `do_syscall`
2. ✅ Implement `EPOLL_CTL_MOD`
3. ✅ Fix `fcntl F_SETFL` on non-stdio
4. ✅ Add `fsync`/`fdatasync`/`sync` (stub as no-op)
5. ✅ Add `shutdown` for sockets
6. ✅ Stub `rseq` to reduce log noise

### Phase 2: Core Completeness (2-4 weeks)
Focus on P1 items for broader compatibility:

1. Implement SIGPIPE delivery infrastructure
2. Add `pselect`/`ppoll` sigmask support
3. Implement `rename`/`renameat`
4. Implement `chmod`/`fchmod`/`chown`/`fchown`
5. Add `recvmsg` for complete socket API
6. Add `wait4`/`waitpid` (if fork support planned)
7. Add `flock` for file locking

### Phase 3: Feature Parity (4-8 weeks)
Focus on P2 items:

1. Complete IPv6 support
2. Add `statx` support
3. Implement `openat` with directory FD
4. Add `sendfile` for zero-copy
5. Add timer FD support (`timerfd_*`)
6. Add inotify support

### Phase 4: Advanced Features (ongoing)
Address P3 items as needed:

1. Consider shared futex if IPC is needed
2. Evaluate fork/vfork necessity
3. Add specialized syscalls based on user requests

---

## Lessons from Asterinas

1. **Macro-based dispatch**: Consider using macros to reduce boilerplate in syscall handling
2. **Architecture separation**: Keep arch-specific code isolated (already done well)
3. **Context passing**: Consider a unified `Context` object for cleaner syscall signatures
4. **Error handling**: Use consistent error macros with debugging context

---

## Testing Strategy

For each new syscall implementation:

1. **Unit tests**: Add to `litebox_shim_linux/src/syscalls/tests.rs`
2. **Integration tests**: Add C test programs to `litebox_runner_linux_userland/tests/`
3. **Real application tests**: Verify with existing test suite (node, python, ls, iperf3)

### Suggested Test Programs

| Program | Syscalls Exercised |
|---------|-------------------|
| `node` | epoll, timers, signals, networking |
| `python` | mmap, signals, threading, filesystem |
| `nginx` | epoll, sendfile, socket options |
| `redis` | fork, fsync, networking |
| `sqlite` | flock, fsync, mmap |

---

## Metrics for Success

Track progress with:

1. **Syscall coverage**: % of top-100 syscalls implemented
2. **Application compatibility**: # of real programs running successfully
3. **Test pass rate**: % of integration tests passing
4. **ENOSYS rate**: Monitor how often unsupported syscalls are hit

---

## References

- [Asterinas Syscall Implementation](https://github.com/asterinas/asterinas)
- [gVisor Syscall Support](https://gvisor.dev/docs/user_guide/compatibility/linux/amd64/)
- [Linux Syscall Reference](https://man7.org/linux/man-pages/man2/syscalls.2.html)
- [Docker Seccomp Default Profile](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)
