# signalfd/signalfd4 Implementation Summary

## Overview

This document summarizes the implementation of `signalfd` and `signalfd4` syscalls for LiteBox, a security-focused library OS.

**PR**: #623 (draft)
**Branch**: `wdcui/signalfd`
**Status**: CI Passed

## What Was Implemented

### signalfd System Calls

The `signalfd` family of syscalls allows applications to receive signals via a file descriptor instead of asynchronous signal handlers. This enables synchronous, event-driven signal handling using `read()`, `poll()`, `epoll()`, or `select()`.

- `signalfd(int fd, const sigset_t *mask, int flags)` - Legacy syscall (always uses 8-byte mask)
- `signalfd4(int fd, const sigset_t *mask, size_t sizemask, int flags)` - Extended version with size validation

### Key Behaviors

1. **Creating**: `fd=-1` creates a new signalfd with the specified signal mask
2. **Updating**: `fd>=0` updates an existing signalfd's mask
3. **Reading**: Returns `SignalfdSiginfo` structures (128 bytes each) for pending signals
4. **Flags**: Supports `SFD_CLOEXEC` and `SFD_NONBLOCK`
5. **SIGKILL/SIGSTOP**: Automatically masked out (cannot be caught)

## Files Changed

### New Files
- `litebox_shim_linux/src/syscalls/signalfd.rs` - SignalFile struct and IOPollable implementation

### Modified Files
- `litebox_common_linux/src/lib.rs` - Added SfdFlags, SignalfdSiginfo, Signalfd4 syscall
- `litebox_common_linux/src/signal/mod.rs` - Added PartialEq, Eq, Debug to SigSet
- `litebox_shim_linux/src/lib.rs` - Added Descriptor::Signalfd, syscall dispatch
- `litebox_shim_linux/src/syscalls/mod.rs` - Added signalfd module
- `litebox_shim_linux/src/syscalls/file.rs` - sys_signalfd4(), read handler, fstat/fcntl/ioctl/dup/close
- `litebox_shim_linux/src/syscalls/signal/mod.rs` - read_signals_for_signalfd() helper
- `litebox_shim_linux/src/syscalls/epoll.rs` - EpollDescriptor::Signalfd, DescriptorRef::Signalfd
- `litebox_shim_linux/src/syscalls/tests.rs` - Syscall-level tests

## Implementation Details

### SignalfdSiginfo Structure
- Exactly 128 bytes (Linux ABI requirement)
- Uses zerocopy derives for safe serialization
- Contains signal number, errno, code, pid, uid, fd, etc.

### SignalFile
- Stores signal mask and status flags (NONBLOCK)
- Implements `IOPollable` trait for epoll integration
- Thread-safe using RefCell for mask/status

### Signal Consumption
- Signals matching the mask are removed from the pending queue
- Only consumes up to `buffer_size / 128` signals to prevent loss
- Blocking mode currently returns EAGAIN (TODO: proper blocking wait)

## Code Review Findings and Fixes

### Critical Bugs Fixed
1. **Signal loss**: Original code consumed ALL pending signals but only wrote what fit in buffer. Fixed by limiting consumption to `max_count`.

2. **Potential panics**: Replaced `.expect()` calls with safe casts:
   - u32→i32: Saturating conversion with `.min(i32::MAX as u32)`
   - i32→u32: Direct cast with `#[allow]` (Signal guarantees 1-64 range)

### Known Limitation
- Epoll integration returns `Events::empty()` - proper readiness notification would require hooking signal delivery in Task

## Testing

### Unit Tests (8 total)
1. `test_signalfd_siginfo_size` - Verifies 128-byte structure size
2. `test_signalfd_create` - Basic creation with CLOEXEC
3. `test_signalfd_update_mask` - Update mask on existing fd
4. `test_signalfd_nonblock` - Non-blocking flag handling
5. `test_signalfd_invalid_sizemask` - Invalid sizemask returns EINVAL
6. `test_signalfd_nonblock_read_eagain` - Non-blocking read with no signals
7. Integration tests for signal consumption

### CI Results
- **CI workflow**: ✅ Passed
- **SemverChecks**: ✅ Passed
- **Local clippy**: ✅ Clean
- **Local fmt**: ✅ Clean

## Future Enhancements

1. **Proper blocking wait**: Currently blocking mode returns EAGAIN; should implement proper wait using polling infrastructure
2. **Epoll wakeup**: Hook signal delivery to notify epoll when signals arrive
3. **ssi_addr field**: Populate for hardware signals (SIGILL, SIGFPE, SIGSEGV, SIGBUS)

## References

- Linux signalfd implementation: `fs/signalfd.c`
- Linux signalfd man page: signalfd(2)
- Asterinas implementation: Referenced for design patterns
