# LiteBox Linux Userland Compatibility Test Results

## Summary

This document summarizes the compatibility testing performed on LiteBox's Linux userland runner to identify gaps in syscall support.

## Testing Methodology

Tests were created based on:
1. **Asterinas Project** - Their syscall test suite at `test/initramfs/src/apps/`
2. **Linux Test Project (LTP)** - Standard syscall conformance tests
3. **Common application patterns** - Syscalls used by web servers, databases, and runtimes

## Tests That PASS (Working Syscalls)

### New Tests Added (All Passing)

| Test File | Syscalls Tested | Status |
|-----------|-----------------|--------|
| `mmap_advanced.c` | mmap, munmap, mprotect, mremap | ✅ PASS |
| `poll_select.c` | poll, select | ✅ PASS |
| `eventfd_test.c` | eventfd, eventfd2 | ✅ PASS |
| `getdents_test.c` | getdents64, readdir | ✅ PASS |
| `dup_test.c` | dup, dup2, dup3 | ✅ PASS |
| `truncate_test.c` | ftruncate | ✅ PASS |

### Existing Tests (Continuing to Pass)

| Test File | Description |
|-----------|-------------|
| `hello.c` | Basic I/O |
| `execve.c` | Process execution |
| `signal.c` | Signal handling |
| `thread.c` | Threading |
| `thread_exit.c` | Thread termination |
| `unix.c` | Unix domain sockets |
| `efault.c` | EFAULT handling |

## Identified Gaps (Unsupported Syscalls)

### High Priority (Common in Applications)

| Syscall | Use Case | Impact |
|---------|----------|--------|
| **rename** | File renaming | Breaks file management, temp file patterns |
| **fsync/fdatasync** | Data durability | Breaks databases, log writers |
| **flock** | File locking | Breaks lock files, concurrent access |
| **truncate** | File size via path | Minor (ftruncate works) |
| **rmdir** | Directory removal | Breaks cleanup operations |

### Medium Priority (Event-Driven Applications)

| Syscall | Use Case | Impact |
|---------|----------|--------|
| **timerfd_create/settime/gettime** | Timer file descriptors | Breaks event loops (libuv, tokio) |
| **signalfd4** | Signal file descriptors | Breaks signal-driven I/O |
| **inotify_init/add_watch/rm_watch** | File system monitoring | Breaks file watchers, hot reload |

### Lower Priority (Specialized)

| Syscall | Use Case | Impact |
|---------|----------|--------|
| **sendfile** | Zero-copy file transfer | Performance impact on web servers |
| **splice/tee** | Zero-copy pipe transfer | Performance impact |
| **getrusage** | Resource usage stats | Breaks profiling, monitoring |
| **prlimit/getrlimit/setrlimit** | Resource limits | Breaks resource management |

### Other Warnings Observed

- **Shared futex** - Warning printed but doesn't block execution

## Detailed Test Results by Category

### File Operations
- ✅ open, openat, close, read, write, lseek
- ✅ ftruncate, fstat, stat, lstat
- ✅ unlink, mkdir, getdents64
- ❌ rename, renameat
- ❌ truncate (by path)
- ❌ rmdir
- ❌ fsync, fdatasync, sync
- ❌ flock

### Memory Management
- ✅ mmap, munmap, mprotect, mremap
- ✅ brk

### I/O Multiplexing
- ✅ poll, ppoll
- ✅ select, pselect
- ✅ epoll_create, epoll_ctl, epoll_wait
- ✅ eventfd, eventfd2
- ❌ timerfd_create, timerfd_settime, timerfd_gettime
- ❌ signalfd4
- ❌ inotify_init, inotify_add_watch, inotify_rm_watch

### File Descriptors
- ✅ dup, dup2, dup3
- ✅ fcntl (basic operations)
- ❌ flock

### Process/Thread
- ✅ clone, fork (with caveats)
- ✅ exit, exit_group
- ✅ execve
- ✅ getpid, gettid
- ❌ getrusage
- ❌ prlimit, getrlimit, setrlimit

### Networking
- ✅ socket, bind, listen, accept, connect
- ✅ send, recv, sendto, recvfrom
- ✅ socketpair (Unix domain)
- ❌ sendfile

### Signals
- ✅ rt_sigaction, rt_sigprocmask
- ✅ kill, tgkill
- ❌ signalfd4

## Recommendations

### For Maximum Compatibility

1. **Implement rename/renameat** - Essential for atomic file operations
2. **Implement fsync/fdatasync** - Required for data durability
3. **Implement timerfd** - Critical for event loops
4. **Implement rmdir** - Basic filesystem operation

### For Database Workloads

Priority syscalls: fsync, fdatasync, flock, rename

### For Web Server Workloads

Priority syscalls: sendfile, timerfd, signalfd

### For Runtime/Language Support (Node.js, Python, etc.)

Priority syscalls: inotify, timerfd, signalfd

## Test File Locations

### Enabled Tests
```
litebox_runner_linux_userland/tests/
├── dup_test.c           # NEW - fd duplication
├── eventfd_test.c       # NEW - event file descriptors
├── getdents_test.c      # NEW - directory reading
├── mmap_advanced.c      # NEW - memory mapping
├── poll_select.c        # NEW - I/O multiplexing
├── truncate_test.c      # NEW - file truncation
└── (existing tests...)
```

### Disabled Tests (Gaps Found)
```
litebox_runner_linux_userland/tests/
├── flock_test.c.disabled      # flock not supported
├── fsync_test.c.disabled      # fsync not supported
├── inotify_test.c.disabled    # inotify not supported
├── rename_test.c.disabled     # rename not supported
├── rlimit_test.c.disabled     # getrusage not supported
├── signalfd_test.c.disabled   # signalfd4 not supported
├── timerfd_test.c.disabled    # timerfd not supported
└── zerocopy_test.c.disabled   # sendfile/splice not supported
```

## External Test Suites for Future Testing

### Asterinas Test Suite
- Repository: https://github.com/asterinas/asterinas
- Location: `test/initramfs/src/apps/`
- Recommended tests: mmap_err.c, pipe_err.c, epoll_err.c, iovec_err.c

### Linux Test Project (LTP)
- Repository: https://github.com/linux-test-project/ltp
- Recommended: syscalls/* tests

### libc Test Suite
- musl libc tests
- glibc conformance tests
