# Design Document: splice and tee Syscall Implementation

## Overview

This document describes the implementation plan for the Linux `splice(2)` and `tee(2)` syscalls in litebox. These syscalls enable zero-copy data transfer between file descriptors, using pipes as an intermediary buffer.

## Background

The `splice` family of syscalls was introduced in Linux 2.6.17 to provide efficient data movement:
- **splice**: Moves data between a pipe and a file descriptor (or vice versa)
- **tee**: Duplicates data from one pipe to another without consuming it

These complement the already-implemented `sendfile` syscall, which transfers data directly between file descriptors.

## Syscall Signatures

### splice

```c
ssize_t splice(int fd_in, off64_t *off_in, int fd_out, off64_t *off_out,
               size_t len, unsigned int flags);
```

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `fd_in` | `int` | Input file descriptor |
| `off_in` | `off64_t *` | Offset for input (NULL to use current position) |
| `fd_out` | `int` | Output file descriptor |
| `off_out` | `off64_t *` | Offset for output (NULL to use current position) |
| `len` | `size_t` | Number of bytes to transfer |
| `flags` | `unsigned int` | Splice flags |

#### Constraints

- At least one of `fd_in` or `fd_out` must be a pipe
- If `fd_in` is a pipe, `off_in` must be NULL
- If `fd_out` is a pipe, `off_out` must be NULL
- Offsets are only valid for seekable file descriptors (regular files)

### tee

```c
ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);
```

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `fd_in` | `int` | Input pipe file descriptor |
| `fd_out` | `int` | Output pipe file descriptor |
| `len` | `size_t` | Maximum number of bytes to duplicate |
| `flags` | `unsigned int` | Splice flags |

#### Constraints

- Both `fd_in` and `fd_out` must be pipes
- Data is copied (not moved) from input to output

## Flags

| Flag | Value | Description |
|------|-------|-------------|
| `SPLICE_F_MOVE` | `0x01` | Hint to move pages instead of copying (advisory) |
| `SPLICE_F_NONBLOCK` | `0x02` | Don't block on pipe I/O |
| `SPLICE_F_MORE` | `0x04` | More data will be coming (hint for sockets) |
| `SPLICE_F_GIFT` | `0x08` | Pages are a "gift" to the kernel (vmsplice only) |

For our implementation:
- `SPLICE_F_NONBLOCK`: Respected - returns EAGAIN instead of blocking
- `SPLICE_F_MOVE`, `SPLICE_F_MORE`, `SPLICE_F_GIFT`: Accepted but advisory (no special handling needed)

## Return Values

- On success: Number of bytes transferred/duplicated
- On error: -1 with errno set

## Error Handling

| Error | Condition |
|-------|-----------|
| `EBADF` | Invalid file descriptor |
| `EINVAL` | Neither fd is a pipe (splice), or either fd is not a pipe (tee) |
| `EINVAL` | Offset provided for a pipe fd |
| `EINVAL` | Invalid flags |
| `EINVAL` | fd_in and fd_out refer to same pipe |
| `EAGAIN` | SPLICE_F_NONBLOCK set and operation would block |
| `ESPIPE` | Offset provided for non-seekable fd |

## Implementation Plan

### Phase 1: Add Types to `litebox_common_linux/src/lib.rs`

1. Add `SpliceFlags` bitflags type
2. Add `Splice` variant to `SyscallRequest` enum
3. Add `Tee` variant to `SyscallRequest` enum
4. Add syscall number parsing for `Sysno::splice` and `Sysno::tee`

### Phase 2: Add Syscall Handlers to `litebox_shim_linux`

1. Add dispatch cases in `litebox_shim_linux/src/lib.rs`
2. Implement `sys_splice()` in `litebox_shim_linux/src/syscalls/file.rs`
3. Implement `sys_tee()` in `litebox_shim_linux/src/syscalls/file.rs`

### Phase 3: Implementation Details

#### sys_splice Implementation

```
1. Validate flags (reject unknown bits)
2. If len == 0, return 0
3. Get both file descriptors
4. Determine which fd is the pipe (at least one must be)
5. Validate offset constraints:
   - If fd is pipe, offset must be NULL
   - If fd is file and offset provided, use it
6. Based on configuration:
   - Pipe → File: Read from pipe, write to file at offset
   - File → Pipe: Read from file at offset, write to pipe
   - Pipe → Pipe: Read from input pipe, write to output pipe
7. Handle SPLICE_F_NONBLOCK for pipe operations
8. Update offsets if provided
9. Return bytes transferred
```

#### sys_tee Implementation

```
1. Validate flags (reject unknown bits)
2. If len == 0, return 0
3. Verify both fds are pipes
4. Verify fd_in != fd_out (same pipe check)
5. Read data from input pipe WITHOUT consuming it (peek)
6. Write peeked data to output pipe
7. Handle SPLICE_F_NONBLOCK
8. Return bytes duplicated
```

### Phase 4: Pipe Infrastructure Enhancement

The current pipe implementation needs a "peek" capability for `tee`:
- Add method to read pipe data without consuming it
- Or copy data from pipe buffer directly

## Key Design Decisions

### 1. Zero-Copy vs Copy

True zero-copy would require page-level manipulation which is complex in userspace. Our implementation will:
- Use efficient buffer-based copying
- Accept `SPLICE_F_MOVE` as advisory (no-op)
- Focus on correctness over kernel-level performance

### 2. Pipe Peek for tee

For `tee`, we need to read pipe data without consuming it. Options:
- **Option A**: Add peek capability to pipe (preferred)
- **Option B**: Read then write back to same pipe (inefficient, ordering issues)

We'll implement Option A by adding a `peek` method to the pipe read end.

### 3. Blocking Behavior

- Default: Block until at least 1 byte transferred
- With `SPLICE_F_NONBLOCK`: Return immediately with EAGAIN if would block
- Respect pipe's O_NONBLOCK flag as well

## Files to Modify

1. `litebox_common_linux/src/lib.rs` - Add types and syscall parsing
2. `litebox_shim_linux/src/lib.rs` - Add syscall dispatch
3. `litebox_shim_linux/src/syscalls/file.rs` - Implement handlers
4. `litebox/src/pipes.rs` - Add peek capability for tee

## Test Plan

### Unit Tests

1. `test_splice_pipe_to_file` - Splice from pipe to regular file
2. `test_splice_file_to_pipe` - Splice from file to pipe
3. `test_splice_pipe_to_pipe` - Splice between two pipes
4. `test_splice_with_offset` - Verify offset handling for files
5. `test_splice_nonblock` - SPLICE_F_NONBLOCK behavior
6. `test_splice_invalid_args` - Error cases (no pipe, same fd, etc.)
7. `test_tee_basic` - Basic pipe duplication
8. `test_tee_nonblock` - TEE with SPLICE_F_NONBLOCK
9. `test_tee_not_pipes` - Error when fds are not pipes

### C Integration Tests

Create `splice_test.c` with comprehensive tests for real syscall behavior.

## References

- Linux man pages: `man 2 splice`, `man 2 tee`
- Linux source: `/workspace/linux/fs/splice.c`
- Existing sendfile implementation in litebox (PR #602)
