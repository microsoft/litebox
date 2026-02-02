# signalfd/signalfd4 Syscall Design Document

## Overview

This document describes the design and implementation plan for the `signalfd` and `signalfd4` Linux syscalls in LiteBox.

## Syscall Signatures

```c
int signalfd(int fd, const sigset_t *mask, int flags);
int signalfd4(int fd, const sigset_t *mask, size_t sizemask, int flags);
```

### Parameters
- `fd`: -1 to create a new signalfd, or existing signalfd to modify its mask
- `mask`: Set of signals to monitor
- `sizemask`: Size of the sigset_t (must equal sizeof(sigset_t))
- `flags`: `SFD_CLOEXEC` (0x80000) and/or `SFD_NONBLOCK` (0x800)

### Return Value
- On success: file descriptor (new or same as `fd`)
- On error: -1 with errno set

## Key Data Structures

### signalfd_siginfo (128 bytes)
The struct returned when reading from a signalfd:
```c
struct signalfd_siginfo {
    uint32_t ssi_signo;    // Signal number
    int32_t  ssi_errno;    // Error number (unused)
    int32_t  ssi_code;     // Signal code
    uint32_t ssi_pid;      // Sender's PID
    uint32_t ssi_uid;      // Sender's UID
    int32_t  ssi_fd;       // File descriptor (SIGIO)
    uint32_t ssi_tid;      // Kernel timer ID
    uint32_t ssi_band;     // Band event (SIGIO)
    uint32_t ssi_overrun;  // POSIX timer overrun count
    uint32_t ssi_trapno;   // Trap number
    int32_t  ssi_status;   // Exit status or signal (SIGCHLD)
    int32_t  ssi_int;      // sigqueue() integer
    uint64_t ssi_ptr;      // sigqueue() pointer
    uint64_t ssi_utime;    // User CPU time (SIGCHLD)
    uint64_t ssi_stime;    // System CPU time (SIGCHLD)
    uint64_t ssi_addr;     // Fault address
    uint16_t ssi_addr_lsb; // LSB of address
    uint16_t __pad2;
    int32_t  ssi_syscall;  // Syscall number (SIGSYS)
    uint64_t ssi_call_addr;// Syscall address (SIGSYS)
    uint32_t ssi_arch;     // Arch (SIGSYS)
    uint8_t  __pad[28];    // Reserved
};
```

### SfdFlags
```rust
bitflags! {
    pub struct SfdFlags: i32 {
        const CLOEXEC = 0x80000;   // O_CLOEXEC
        const NONBLOCK = 0x800;    // O_NONBLOCK
    }
}
```

## Implementation Plan

### 1. Add Types to litebox_common_linux

- Add `SfdFlags` bitflags
- Add `SignalfdSiginfo` struct (128 bytes, matching Linux ABI)
- Add `Signalfd4` variant to `SyscallRequest` enum
- Add syscall number parsing for `signalfd` and `signalfd4`

### 2. Create SignalFile in litebox_shim_linux

Location: `litebox_shim_linux/src/syscalls/signalfd.rs`

```rust
pub struct SignalFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// The signal mask being monitored
    mask: litebox::sync::Mutex<Platform, SigSet>,
    /// File status flags (O_NONBLOCK, etc.)
    status: AtomicU32,
    /// Pollee for event notification
    pollee: Pollee<Platform>,
}
```

Key methods:
- `new(mask: SigSet, flags: SfdFlags) -> Self`
- `update_mask(&self, mask: SigSet)`
- `read(&self, task: &Task, cx: &WaitContext) -> Result<Vec<SignalfdSiginfo>, Errno>`
- Implement `IOPollable` trait for epoll integration

### 3. Add Descriptor Variant

In `syscalls/file.rs`, add to `Descriptor` enum:
```rust
Signalfd {
    file: Arc<SignalFile<Platform>>,
    close_on_exec: bool,
}
```

### 4. Implement sys_signalfd4

In `Task`:
```rust
pub fn sys_signalfd4(
    &self,
    fd: i32,
    mask_ptr: ConstPtr<SigSet>,
    sizemask: usize,
    flags: SfdFlags,
) -> Result<i32, Errno>
```

Logic:
1. Validate `sizemask == sizeof(SigSet)`
2. Validate flags (only CLOEXEC and NONBLOCK allowed)
3. Read mask from user space
4. Mask out SIGKILL and SIGSTOP (can't be caught)
5. If `fd == -1`: create new SignalFile and allocate fd
6. If `fd >= 0`: update existing SignalFile's mask

### 5. Implement Signal Consumption

When reading from signalfd:
1. Check pending signals against signalfd's mask
2. Dequeue matching signals from task's pending queue
3. Convert each `Siginfo` to `SignalfdSiginfo`
4. Return multiple structs if multiple signals pending
5. If no signals and blocking: wait using pollee
6. If no signals and non-blocking: return EAGAIN

### 6. Integration with Signal Delivery

Modify `send_signal()` in signal/mod.rs:
- After pushing to pending queue, notify any registered signalfd pollers
- This allows epoll/poll/select to wake up when signals arrive

### 7. Epoll Integration

In `syscalls/epoll.rs`, add handling for `Descriptor::Signalfd`:
- Call `check_io_events()` which checks if watched signals are pending
- Return `Events::IN` when readable

## Error Handling

| Error | Condition |
|-------|-----------|
| EBADF | `fd` is not -1 and not a valid signalfd |
| EINVAL | Invalid flags, or sizemask != sizeof(sigset_t) |
| EFAULT | Invalid mask pointer |
| EMFILE | Too many open file descriptors |
| ENOMEM | Insufficient memory |

## Testing Plan

### Unit Tests
1. `test_signalfd_create` - Basic creation
2. `test_signalfd_update_mask` - Update existing signalfd
3. `test_signalfd_read_signal` - Read pending signal
4. `test_signalfd_nonblock_eagain` - Non-blocking returns EAGAIN
5. `test_signalfd_invalid_flags` - Reject invalid flags
6. `test_signalfd_mask_sigkill` - SIGKILL masked out
7. `test_signalfd_with_epoll` - Integration with epoll

### Behavioral Tests
- Signal is consumed (not delivered via normal path)
- Multiple signals can be read in one read()
- Signalfd mask can be updated without closing fd

## References

- Linux source: `/workspace/linux/fs/signalfd.c`
- Linux header: `/workspace/linux/include/linux/signalfd.h`
- Asterinas: `/workspace/asterinas/kernel/src/syscall/signalfd.rs`
- man page: signalfd(2)
