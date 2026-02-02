# Signal Mask Support for pselect, ppoll, and epoll_pwait

## Overview

This document summarizes the implementation of signal mask support for the `pselect6`, `ppoll`, and `epoll_pwait` syscalls in litebox. Previously, these syscalls would panic with `unimplemented!()` when a signal mask was provided.

## PR

- **PR #610**: https://github.com/microsoft/litebox/pull/610
- **Branch**: `wdcui/pselect-ppoll-sigmask`

## Problem Statement

The `pselect`, `ppoll`, and `epoll_pwait` syscalls accept an optional signal mask parameter that allows callers to atomically:
1. Set a temporary signal mask
2. Wait for I/O events
3. Restore the original signal mask

This is critical for applications that need to safely handle signals during blocking I/O operations without race conditions.

## Implementation Details

### 1. Fixed `SigSetPack` Structure (`litebox_common_linux/src/lib.rs`)

**Problem**: The original `SigSetPack` stored a `SigSet` directly, but Linux's `pselect6` syscall passes a pointer to a structure containing `{sigset_ptr, size}`.

**Solution**: Changed `SigSetPack` to be generic over a pointer type:

```rust
#[repr(C, packed)]
pub struct SigSetPack<P: RawConstPointer<SigSet>> {
    pub sigset_ptr: P,  // Pointer to the actual sigset
    pub size: usize,    // Size of the sigset
}
```

### 2. Added `with_sigmask` Helper (`litebox_shim_linux/src/syscalls/signal/mod.rs`)

Implements the POSIX semantics for temporary signal mask changes:

```rust
pub(crate) fn with_sigmask<F, R>(&self, new_mask: SigSet, f: F) -> R
where
    F: FnOnce() -> R,
{
    // Guard struct ensures mask is restored even on panic
    struct MaskGuard<'a> {
        signals: &'a SignalState,
        old_mask: SigSet,
    }
    impl Drop for MaskGuard<'_> {
        fn drop(&mut self) {
            self.signals.set_signal_mask(self.old_mask);
        }
    }

    let old_mask = self.signals.blocked.get();
    let _guard = MaskGuard { signals: &self.signals, old_mask };
    self.signals.set_signal_mask(new_mask);
    f()
}
```

Key features:
- Uses drop guard pattern for panic safety
- Restores mask even if the operation returns an error or panics
- Documented atomicity deviation from Linux kernel

### 3. Added `with_optional_sigmask` Helper

Reduces code duplication when sigmask is optional:

```rust
pub(crate) fn with_optional_sigmask<F, R>(&self, mask: Option<SigSet>, f: F) -> R
where
    F: FnOnce() -> R,
{
    match mask {
        Some(m) => self.with_sigmask(m, f),
        None => f(),
    }
}
```

### 4. Updated Syscall Implementations (`litebox_shim_linux/src/syscalls/file.rs`)

#### `sys_epoll_pwait`
- Validates `sigsetsize` matches `sizeof(SigSet)`
- Reads sigmask from user space if provided
- Wraps epoll_wait with `with_optional_sigmask`

#### `sys_ppoll`
- Same pattern as `sys_epoll_pwait`
- Validates sigsetsize and applies mask during poll

#### `sys_pselect`
- Reads `SigSetPack` structure from user space
- Handles NULL `sigset_ptr` inside sigsetpack (glibc compatibility)
- Validates size field before reading actual mask
- Wraps select with `with_optional_sigmask`

### 5. glibc Compatibility Fix

When glibc's `pselect()` is called with `NULL` sigmask, it still passes a `SigSetPack` structure to the kernel with `sigset_ptr=NULL`. The implementation handles this case:

```rust
if sigset_ptr.as_usize() == 0 {
    None  // Treat as no sigmask
} else if size != core::mem::size_of::<SigSet>() {
    return Err(Errno::EINVAL);
} else {
    Some(sigset_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?)
}
```

## Testing

### Unit Tests (`litebox_shim_linux/src/syscalls/tests.rs`)

1. **`test_ppoll_with_sigmask`**
   - Tests ppoll with NULL sigmask
   - Tests ppoll with valid sigmask
   - Tests ppoll with invalid sigsetsize (expects EINVAL)

2. **`test_ppoll_sigmask_restored_after_call`**
   - Sets initial mask (blocks SIGUSR2)
   - Calls ppoll with different mask (blocks SIGUSR1)
   - Verifies original mask is restored

3. **`test_epoll_pwait_with_sigmask`**
   - Tests epoll_pwait with NULL sigmask
   - Tests epoll_pwait with valid sigmask
   - Tests epoll_pwait with invalid sigsetsize (expects EINVAL)

4. **`test_pselect_with_sigsetpack`**
   - Tests pselect with NULL sigsetpack
   - Tests pselect with valid sigsetpack
   - Tests pselect with invalid size (expects EINVAL)
   - Tests pselect with NULL sigset_ptr in sigsetpack (glibc compat)

### C Integration Tests (`litebox_runner_linux_userland/tests/sigmask_test.c`)

6 tests covering real syscall behavior:
- `test_ppoll_null_sigmask`
- `test_pselect_null_sigmask` (skipped on 32-bit)
- `test_epoll_pwait_null_sigmask`
- `test_ppoll_sigmask_restored`
- `test_pselect_sigmask_restored` (skipped on 32-bit)
- `test_epoll_pwait_sigmask_restored`

Note: pselect tests are skipped on 32-bit because the `pselect6` syscall is not handled on x86 (only `pselect6_time64`).

## Review Process

Three review agents analyzed the PR from different perspectives:

### Correctness Review
- Identified need for drop guard pattern (implemented)
- Noted atomicity deviation from Linux kernel (documented)
- Verified ABI compatibility with Linux

### Code Quality Review
- Suggested `with_optional_sigmask` helper (implemented)
- Recommended simplifying nested if/else (implemented)
- Identified type verbosity (acceptable trade-off)

### Test Coverage Review
- Identified missing test for NULL sigset_ptr (implemented)
- Suggested EINTR testing (deferred - requires multi-threading)
- Suggested EFAULT testing (partial coverage exists)

## Files Modified

| File | Changes |
|------|---------|
| `litebox_common_linux/src/lib.rs` | Fixed `SigSetPack` structure |
| `litebox_shim_linux/src/syscalls/signal/mod.rs` | Added `with_sigmask` and `with_optional_sigmask` helpers |
| `litebox_shim_linux/src/syscalls/file.rs` | Updated `sys_ppoll`, `sys_pselect`, `sys_epoll_pwait` |
| `litebox_shim_linux/src/syscalls/tests.rs` | Added 4 unit tests |
| `litebox_runner_linux_userland/tests/sigmask_test.c` | Added C integration test |

## CI Status

All CI checks passing:
- ✅ Build and Test (64-bit)
- ✅ Build and Test (32-bit)
- ✅ Build and Test LVBS
- ✅ Build and Test SNP
- ✅ Build and Test Windows
- ✅ Analyze (all languages)
- ✅ CodeQL
- ✅ Confirm no_std
- ✅ Check SemVer Correctness

## Known Limitations

1. **Atomicity**: The implementation is a cooperative approximation of Linux's atomic signal mask semantics. In the kernel, the mask change and wait are truly atomic with respect to signal delivery. In litebox's single-threaded per-task model, signals are checked during the wait with the new mask.

2. **32-bit pselect6**: The `pselect6` syscall is not handled on 32-bit x86 (only `pselect6_time64` is implemented). C integration tests skip pselect on 32-bit.

3. **epoll_pwait2**: Not implemented (Linux 5.11+ syscall with timespec timeout).
