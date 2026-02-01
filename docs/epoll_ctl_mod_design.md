# Design: Implement EPOLL_CTL_MOD Support

## Overview

This document describes the plan to enable the `EPOLL_CTL_MOD` operation in LiteBox's Linux shim. The implementation already exists as dead code (`mod_interest` function) but is not connected to the syscall dispatch.

## Background

The `epoll_ctl` syscall with `EPOLL_CTL_MOD` operation allows modifying the events associated with an already-registered file descriptor in an epoll instance. This is critical for event-driven applications like Node.js, Python asyncio, and most async frameworks.

**Syscall signature:**
```c
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
```

**EPOLL_CTL_MOD behavior:**
- Modifies the event mask and user data for an existing fd in the interest list
- Returns `ENOENT` if the fd is not registered
- Returns `EINVAL` if `EPOLLEXCLUSIVE` is in the new flags (not allowed for MOD)
- Returns `EINVAL` if the existing entry has `EPOLLEXCLUSIVE` set

## Current State

- `EpollFile::mod_interest()` is fully implemented in `litebox_shim_linux/src/syscalls/epoll.rs` (lines 234-287)
- The function is marked with `#[expect(dead_code)]` because it's not used
- `epoll_ctl()` dispatches ADD and DEL but returns `EINVAL` for MOD with `log_unsupported!`

## Implementation Plan

### Step 1: Connect mod_interest to epoll_ctl

**File:** `litebox_shim_linux/src/syscalls/epoll.rs`

**Changes:**
1. Remove `#[expect(dead_code)]` attribute from `mod_interest`
2. Update `epoll_ctl` match arm for `EpollOp::EpollCtlMod` to call `self.mod_interest()`

**Code change:**
```rust
// Before (lines 183-186):
EpollOp::EpollCtlMod => {
    log_unsupported!("epoll_ctl mod");
    Err(Errno::EINVAL)
}

// After:
EpollOp::EpollCtlMod => self.mod_interest(global, fd, file, event.unwrap()),
```

### Step 2: Remove dead_code attribute

**File:** `litebox_shim_linux/src/syscalls/epoll.rs`

Remove line 233:
```rust
#[expect(dead_code, reason = "currently unused, but might want to use soon")]
```

### Step 3: Add unit tests

**File:** `litebox_shim_linux/src/syscalls/epoll.rs` (test module)

Add tests for:
1. `test_epoll_ctl_mod_basic` - Modify events on an existing entry
2. `test_epoll_ctl_mod_not_found` - Returns ENOENT for unregistered fd
3. `test_epoll_ctl_mod_exclusive_not_allowed` - Returns EINVAL if EPOLLEXCLUSIVE in new flags

### Step 4: Add C integration test

**File:** `litebox_runner_linux_userland/tests/epoll_test.c` (new file)

Create a C test that:
1. Creates an epoll instance and eventfd
2. Adds the eventfd with EPOLLIN
3. Modifies to EPOLLOUT using EPOLL_CTL_MOD
4. Verifies the modification took effect

## Test Strategy

### Unit Tests (Rust)
- Test MOD on existing entry succeeds
- Test MOD on non-existent entry returns ENOENT
- Test MOD with EPOLLEXCLUSIVE returns EINVAL
- Test MOD on entry with EPOLLEXCLUSIVE returns EINVAL

### Integration Tests (C)
- Create epoll + eventfd
- Add with EPOLLIN, verify EPOLLIN events
- MOD to EPOLLOUT, verify EPOLLOUT events
- Test edge cases (bad fd, etc.)

## Error Handling

| Error | Condition |
|-------|-----------|
| ENOENT | fd not registered in epoll |
| EINVAL | EPOLLEXCLUSIVE in new flags |
| EINVAL | Existing entry has EPOLLEXCLUSIVE |
| EBADF | fd is closed during operation |

## Files to Modify

1. `litebox_shim_linux/src/syscalls/epoll.rs` - Connect mod_interest, add tests
2. `litebox_runner_linux_userland/tests/epoll_test.c` - New integration test
3. `litebox_runner_linux_userland/tests/run.rs` - Register new test

## References

- Linux man page: `man 2 epoll_ctl`
- Asterinas implementation: `/workspace/asterinas/kernel/src/syscall/epoll.rs`
- Linux source: `/workspace/linux/fs/eventpoll.c`
