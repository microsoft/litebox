# Design: fcntl F_SETFL Support for Non-Stdio File Descriptors

## Problem Statement

Currently, `fcntl(F_SETFL)` panics with `unimplemented!("SETFL on non-stdio")` when called on regular file descriptors (not stdin/stdout/stderr). This is a P0 critical issue because:

1. Many applications use `fcntl(F_SETFL, O_NONBLOCK)` to set non-blocking mode on files
2. It blocks async I/O patterns that are common in modern applications
3. The fix is straightforward - rated "Easy" in the implementation plan

## Current Implementation Analysis

### How stdio works (correctly)
```rust
// In lib.rs line 342
let status_flags = OFlags::APPEND | OFlags::RDWR;
dt.set_entry_metadata(&fd, StdioStatusFlags(status_flags));
```

Stdio FDs (0, 1, 2) get `StdioStatusFlags` metadata attached during initialization, so `fcntl(F_SETFL)` can update them via `with_metadata_mut`.

### The problem with regular files
When `sys_open()` creates a regular file FD, no `StdioStatusFlags` metadata is attached. When `fcntl(F_SETFL)` is called:

```rust
// file.rs line 1029-1043
.with_metadata_mut(fd, |crate::StdioStatusFlags(f)| { ... })
.map_err(|err| match err {
    MetadataError::ClosedFd => Errno::EBADF,
    MetadataError::NoSuchMetadata => {
        unimplemented!("SETFL on non-stdio")  // <-- PANIC!
    }
})
```

## Linux Kernel Reference

From `linux/fs/fcntl.c`:
```c
#define SETFL_MASK (O_APPEND | O_NONBLOCK | O_NDELAY | O_DIRECT | O_NOATIME)

static int setfl(int fd, struct file * filp, unsigned int arg)
{
    // Validation checks for O_APPEND, O_NOATIME, O_DIRECT...

    // Then simply store the flags:
    filp->f_flags = (arg & SETFL_MASK) | (filp->f_flags & ~SETFL_MASK);
}
```

Linux stores status flags directly on the file structure and allows modification.

## Proposed Solution

### Option A: Store status flags per-FD (Recommended)

Attach `StdioStatusFlags` metadata to ALL file FDs when opened, not just stdio.

**Changes required:**
1. In `sys_open()` (file.rs), after creating the FD, attach status flags metadata with the flags used to open the file
2. In `GETFL` handler, the existing code already handles missing metadata gracefully (returns `OFlags::empty()`)
3. In `SETFL` handler, change the `NoSuchMetadata` error handling to create the metadata if missing, rather than panic

**Pros:**
- Consistent with how sockets and stdio already work
- Properly tracks flag state across the FD lifetime
- Follows Linux semantics closely

**Cons:**
- Slight memory overhead per FD (but minimal)

### Option B: No-op for regular files (Not recommended)

For regular files, O_NONBLOCK doesn't really affect disk I/O (disk reads don't truly block in the kernel wait sense). We could just return success without storing anything.

**Pros:**
- Simplest implementation
- Works for common case (setting O_NONBLOCK)

**Cons:**
- GETFL would not reflect the set flags
- O_APPEND behavior would be incorrect
- Not faithful to Linux semantics

## Chosen Approach: Option A

We will:
1. Rename `StdioStatusFlags` to `FileStatusFlags` (more accurate name)
2. Attach `FileStatusFlags` metadata when opening files via `sys_open()`
3. In `SETFL` handler for the `NoSuchMetadata` case, initialize the metadata rather than panic

## Implementation Details

### Step 1: Rename StdioStatusFlags
```rust
// lib.rs
pub(crate) struct FileStatusFlags(pub litebox::fs::OFlags);
```

### Step 2: Attach metadata on file open
```rust
// file.rs in sys_open()
let status_flags = flags & OFlags::STATUS_FLAGS_MASK;
self.global
    .litebox
    .descriptor_table_mut()
    .set_entry_metadata(&file, FileStatusFlags(status_flags));
```

### Step 3: Handle NoSuchMetadata gracefully in SETFL

For the rare case where a FD doesn't have metadata (e.g., inherited FDs or edge cases), we'll initialize it on first SETFL:

```rust
MetadataError::NoSuchMetadata => {
    // Initialize metadata with the requested flags
    self.global
        .litebox
        .descriptor_table_mut()
        .set_entry_metadata(&fd, FileStatusFlags(flags & setfl_mask));
    Ok(())
}
```

## Test Plan

1. **Unit test**: Test `fcntl(F_SETFL, O_NONBLOCK)` on a regular file
2. **Unit test**: Test `fcntl(F_GETFL)` returns the set flags
3. **Unit test**: Test flag toggling (set then unset)
4. **Unit test**: Test unsupported flags return appropriate errors
5. **Integration test**: C program that opens a file and sets O_NONBLOCK

## Files to Modify

1. `litebox_shim_linux/src/lib.rs` - Rename `StdioStatusFlags` to `FileStatusFlags`
2. `litebox_shim_linux/src/syscalls/file.rs`:
   - Attach metadata in `sys_open()`
   - Handle `NoSuchMetadata` case in `SETFL` handler
3. Add unit tests in `litebox_shim_linux/src/syscalls/tests.rs` or a new test file

## Risk Assessment

- **Low risk**: The change is additive and doesn't modify existing behavior for stdio or sockets
- **Backward compatible**: Existing code paths remain unchanged
- **Testable**: Clear test cases can verify correctness

## References

- Linux source: `/workspace/linux/fs/fcntl.c`
- LiteBox syscall plan: `docs/syscall_implementation_plan.md`
- Current implementation: `litebox_shim_linux/src/syscalls/file.rs` line 1041
