# Design Document: preadv/pwritev Syscall Implementation

## Overview

This document describes the implementation plan for the Linux `preadv(2)`, `pwritev(2)`, `preadv2(2)`, and `pwritev2(2)` syscalls in litebox. These syscalls enable vectored I/O at a specified offset without affecting the file pointer position.

## Background

LiteBox already has `readv` and `writev` syscalls implemented, which perform scatter-gather I/O using the file's current position. The `preadv`/`pwritev` variants add the ability to specify an offset, similar to how `pread`/`pwrite` extend `read`/`write`.

The `v2` variants add support for RWF_* flags that modify the I/O behavior.

## Syscall Signatures

### preadv

```c
ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
```

On x86-64, the offset is split into low/high parts:
```c
ssize_t preadv(unsigned long fd, const struct iovec *vec, unsigned long vlen, 
               unsigned long pos_l, unsigned long pos_h);
```

### preadv2

```c
ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
```

### pwritev

```c
ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
```

### pwritev2

```c
ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `fd` | `int` | File descriptor |
| `iov` | `const struct iovec *` | Array of iovec structures |
| `iovcnt` | `int` | Number of elements in iov array |
| `offset` | `off_t` | File offset to read/write at |
| `flags` | `int` | RWF_* flags (v2 variants only) |

## RWF Flags (v2 variants)

| Flag | Value | Description |
|------|-------|-------------|
| `RWF_HIPRI` | `0x00000001` | High priority request, may use polling |
| `RWF_DSYNC` | `0x00000002` | Per-I/O O_DSYNC equivalent |
| `RWF_SYNC` | `0x00000004` | Per-I/O O_SYNC equivalent |
| `RWF_NOWAIT` | `0x00000008` | Don't block, return EAGAIN if would block |
| `RWF_APPEND` | `0x00000010` | Per-I/O O_APPEND |

For our initial implementation:
- `RWF_NOWAIT`: Ignored (LiteBox I/O is typically synchronous)
- `RWF_DSYNC`, `RWF_SYNC`: Ignored (data is persisted synchronously)
- `RWF_HIPRI`: Ignored (no polling support)
- `RWF_APPEND`: Should be supported for pwritev2

Unknown flags should return EOPNOTSUPP.

## Special Behavior

### offset == -1 for v2 variants

When offset is -1 in preadv2/pwritev2, the syscall behaves like readv/writev (uses current file position). This is a Linux-specific behavior to allow using RWF flags with non-positioned I/O.

## Return Values

- On success: Total number of bytes read/written
- On error: -1 with errno set

## Error Handling

| Error | Condition |
|-------|-----------|
| `EBADF` | Invalid file descriptor or fd not open for reading/writing |
| `EINVAL` | Invalid offset (negative), invalid iovcnt, or sum of iov_len overflows |
| `EFAULT` | iov points outside accessible address space |
| `ESPIPE` | fd refers to a pipe or socket (can't seek) |
| `EOPNOTSUPP` | Unknown flags specified |

## Implementation Plan

### Phase 1: Add Types to `litebox_common_linux/src/lib.rs`

1. Add `RwfFlags` bitflags type for RWF_* flags
2. Add `Preadv` variant to `SyscallRequest` enum
3. Add `Pwritev` variant to `SyscallRequest` enum
4. Add `Preadv2` variant to `SyscallRequest` enum  
5. Add `Pwritev2` variant to `SyscallRequest` enum
6. Add syscall number parsing for all four syscalls

### Phase 2: Add Syscall Handlers to `litebox_shim_linux`

1. Add dispatch cases in `litebox_shim_linux/src/lib.rs`
2. Implement `sys_preadv()` in `litebox_shim_linux/src/syscalls/file.rs`
3. Implement `sys_pwritev()` in `litebox_shim_linux/src/syscalls/file.rs`
4. Implement `sys_preadv2()` in `litebox_shim_linux/src/syscalls/file.rs`
5. Implement `sys_pwritev2()` in `litebox_shim_linux/src/syscalls/file.rs`

### Phase 3: Implementation Details

#### sys_preadv Implementation

```
1. Validate fd (must be valid, open for reading)
2. Validate offset (must be non-negative)
3. Validate iovcnt (must be > 0, <= IOV_MAX)
4. Read iovec array from user space
5. Get file descriptor from file table
6. For each iovec element:
   a. Read from file at current offset
   b. Copy data to user buffer
   c. Advance offset by bytes read
   d. Stop if fewer bytes than requested (EOF or error)
7. Return total bytes read
```

#### sys_pwritev Implementation

```
1. Validate fd (must be valid, open for writing)
2. Validate offset (must be non-negative)
3. Validate iovcnt (must be > 0, <= IOV_MAX)
4. Read iovec array from user space
5. Get file descriptor from file table
6. For each iovec element:
   a. Copy data from user buffer
   b. Write to file at current offset
   c. Advance offset by bytes written
   d. Stop if fewer bytes than requested (error or partial write)
7. Return total bytes written
```

#### sys_preadv2/sys_pwritev2 Implementation

Same as above, but:
1. Parse and validate RWF flags
2. If offset == -1, delegate to sys_readv/sys_writev
3. Otherwise proceed as preadv/pwritev with flags handling

## Key Design Decisions

### 1. Reuse Existing readv/writev Infrastructure

The existing `sys_readv` and `sys_writev` implementations read/write using the file's current position. Our preadv/pwritev can share the iovec processing logic but pass an explicit offset to the underlying fs.read/fs.write calls.

### 2. Offset Parameter on x86-64

On 64-bit Linux, the offset is passed as two parameters (pos_l, pos_h) for historical ABI reasons, but on x86-64 the high part is always 0 and can be ignored. We'll accept both parameters in the syscall parsing but use only pos_l as a 64-bit offset.

### 3. Flag Handling Strategy

For initial implementation, we'll accept all valid RWF flags but implement only essential behavior. Unknown flags return EOPNOTSUPP as required by the API contract.

## Files to Modify

1. `litebox_common_linux/src/lib.rs` - Add types and syscall parsing
2. `litebox_shim_linux/src/lib.rs` - Add syscall dispatch
3. `litebox_shim_linux/src/syscalls/file.rs` - Implement handlers

## Test Plan

### Unit Tests

1. `test_preadv_basic` - Basic vectored read at offset
2. `test_pwritev_basic` - Basic vectored write at offset
3. `test_preadv_offset_unchanged` - Verify file position not affected
4. `test_pwritev_offset_unchanged` - Verify file position not affected
5. `test_preadv2_flags` - Test with various RWF flags
6. `test_pwritev2_flags` - Test with various RWF flags
7. `test_preadv2_offset_minus_one` - Test offset=-1 behavior
8. `test_preadv_espipe` - Error on pipe/socket
9. `test_preadv_invalid_offset` - Error on negative offset

## References

- Linux man pages: `man 2 preadv`, `man 2 preadv2`
- Linux source: `/workspace/linux/fs/read_write.c`
- Asterinas implementation: `/workspace/asterinas/kernel/src/syscall/preadv.rs`
- Existing readv/writev in litebox
