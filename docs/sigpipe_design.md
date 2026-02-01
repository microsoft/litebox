# SIGPIPE Signal Delivery Implementation Design

## Overview

This document describes the design for implementing SIGPIPE signal delivery in LiteBox. Currently, writing to a closed pipe or socket results in `unimplemented!()` panics instead of proper SIGPIPE signal delivery.

## Background

### What is SIGPIPE?

SIGPIPE is a POSIX signal sent to a process when it attempts to write to a pipe or socket that has been closed on the reading end. The default action is to terminate the process.

### Current State

LiteBox has full signal infrastructure (PR #524), but SIGPIPE delivery is not implemented. There are 4 locations with `unimplemented!()` markers:

| Location | File | Line | Context |
|----------|------|------|---------|
| 1 | `syscalls/file.rs` | ~358 | `sys_write()` to pipe |
| 2 | `syscalls/file.rs` | ~617 | `sys_pwritev()` to pipe |
| 3 | `syscalls/net.rs` | ~763 | `send_socket()` for INET sockets |
| 4 | `syscalls/unix.rs` | ~1240 | `sendto()` for Unix sockets |

### Signal Infrastructure Available

- `Signal::SIGPIPE` - defined in `litebox_common_linux/src/signal/mod.rs`
- `send_signal()` - private method in `SignalState` that queues signals
- `process_signals()` - delivers pending signals on syscall return
- `siginfo_kill()` - helper to create siginfo for signals
- Default disposition for SIGPIPE is `Terminate`

## Design

### Approach

Implement full SIGPIPE signal delivery using the existing signal infrastructure. This provides correct POSIX semantics:

1. If signal handler is `SIG_DFL` → process terminates
2. If signal handler is `SIG_IGN` → signal ignored, `EPIPE` returned
3. If custom handler installed → handler runs, then `EPIPE` returned
4. If `MSG_NOSIGNAL` flag is set (sockets only) → no signal, just `EPIPE`

### Implementation Steps

#### 1. Expose signal sending capability

The `send_signal()` method is currently private. We need to expose a way for syscall handlers to send SIGPIPE. Options:

- **Option A**: Add a public `send_sigpipe()` method to `Task`
- **Option B**: Make `send_signal()` `pub(crate)`
- **Option C**: Add a helper function `siginfo_pipe()` and public signal send method

**Decision**: Option A - Add `send_sigpipe()` method. This is more explicit and self-documenting.

#### 2. Update pipe write handlers (file.rs)

For `sys_write()` and `sys_pwritev()`:
- When write to pipe returns `EPIPE`, send SIGPIPE before returning error
- No flag to suppress (unlike sockets, pipes always send SIGPIPE)

```rust
// Before returning EPIPE for pipe write:
self.send_sigpipe();
return Err(Errno::EPIPE);
```

#### 3. Update socket handlers (net.rs, unix.rs)

For socket operations:
- Check `MSG_NOSIGNAL` flag (already done in these locations)
- If flag NOT set and EPIPE occurs, send SIGPIPE
- Return EPIPE error

```rust
if let Err(Errno::EPIPE) = ret && !flags.contains(SendFlags::NOSIGNAL) {
    self.send_sigpipe();
}
```

### Signal Info

Use `SI_KERNEL` as the signal code, similar to other kernel-generated signals:

```rust
fn send_sigpipe(&self) {
    let siginfo = Siginfo {
        signo: Signal::SIGPIPE.as_i32(),
        errno: 0,
        code: SI_KERNEL,
        data: SiginfoData::new_zeroed(),
    };
    self.send_signal(Signal::SIGPIPE, siginfo);
}
```

### Error Handling Flow

```
Write to closed pipe/socket
    ↓
Detect EPIPE condition
    ↓
Check MSG_NOSIGNAL (sockets only)
    ↓ (not set)
Queue SIGPIPE via send_signal()
    ↓
Return Err(EPIPE) to syscall handler
    ↓
Syscall returns to user
    ↓
process_signals() checks pending signals
    ↓
SIGPIPE delivered (handler runs or process terminates)
```

## Testing

### Unit Tests

Add tests in `litebox_shim_linux/src/syscalls/tests.rs`:

1. `test_sigpipe_write_closed_pipe` - Write to pipe after reader closes
2. `test_sigpipe_ignored` - Set SIG_IGN, verify EPIPE returned without termination
3. `test_sigpipe_handler` - Install custom handler, verify it runs
4. `test_sigpipe_blocked` - Block SIGPIPE, verify EPIPE returned
5. `test_socket_nosignal_flag` - Verify MSG_NOSIGNAL suppresses signal

### Integration Tests

Add C test in `litebox_runner_linux_userland/tests/sigpipe_test.c`:

1. Test pipe SIGPIPE delivery
2. Test socket SIGPIPE delivery
3. Test MSG_NOSIGNAL flag
4. Test signal handler invocation

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Signal delivery timing | Signals are delivered after syscall returns via `process_signals()` - same as other signals |
| Breaking existing code | Default behavior (terminate) matches POSIX - well-behaved programs already handle this |
| Single-process model | Signal delivery is to self only, which is correct for SIGPIPE |

## References

- Linux man page: signal(7), write(2), send(2)
- POSIX specification for SIGPIPE
- LiteBox PR #524: Thread signal support
