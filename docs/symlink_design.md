# Symlink Syscall Implementation Design

## Overview

This document describes the design for implementing the `symlink(2)` and `symlinkat(2)` Linux syscalls in litebox.

## Syscall Signatures

```c
int symlink(const char *target, const char *linkpath);
int symlinkat(const char *target, int newdirfd, const char *linkpath);
```

### Parameters

- `target`: The path that the symbolic link will point to (can be relative or absolute, does NOT need to exist)
- `linkpath` / `newdirfd + linkpath`: Where to create the symbolic link
- `newdirfd`: Directory file descriptor for relative `linkpath` resolution (or `AT_FDCWD`)

### Return Value

- Returns 0 on success
- Returns -1 on error with errno set

## Error Handling

| Error | Condition |
|-------|-----------|
| `EACCES` | Write access to directory containing linkpath denied |
| `EDQUOT` | User's quota of resources exhausted |
| `EEXIST` | linkpath already exists |
| `EFAULT` | target or linkpath points outside accessible address space |
| `EIO` | I/O error occurred |
| `ELOOP` | Too many symbolic links in resolving linkpath |
| `ENAMETOOLONG` | target or linkpath too long |
| `ENOENT` | A directory component in linkpath does not exist, or target is empty string |
| `ENOMEM` | Insufficient kernel memory |
| `ENOSPC` | Device has no room for new directory entry |
| `ENOTDIR` | A component in linkpath prefix is not a directory |
| `EPERM` | Filesystem does not support symlinks |
| `EROFS` | linkpath is on a read-only filesystem |
| `EBADF` | (symlinkat) newdirfd is not a valid fd |

## Implementation Plan

### Phase 1: Add Syscall Parsing in litebox_common_linux

1. Add `Symlink` and `Symlinkat` variants to `SyscallRequest` enum
2. Add syscall number parsing for `Sysno::symlink` and `Sysno::symlinkat`

### Phase 2: Add Filesystem Layer Support

1. Add `SymlinkError` enum to `litebox/src/fs/errors.rs`
2. Add `FileType::SymbolicLink` variant to file type enum
3. Add `symlink()` method to `FileSystem` trait in `litebox/src/fs/mod.rs`
4. Implement `symlink()` in each filesystem implementation:
   - `in_mem`: Store symlink target as file data with SymLink type
   - `layered`: Delegate to upper layer after migration if needed
   - `tar_ro`: Return `ReadOnlyFileSystem` error
   - `devices`: Return error (device files don't support symlinks)
   - `nine_p`: Return `todo!()` (9p not yet implemented)

### Phase 3: Add Syscall Handler in litebox_shim_linux

1. Add `sys_symlink()` and `sys_symlinkat()` methods to `Task`
2. Implement path resolution and validation
3. Call filesystem `symlink()` method
4. Add dispatch case in main syscall handler

### Phase 4: Update readlink Implementation

1. Modify `do_readlink()` to check filesystem for symlinks
2. Return symlink target from filesystem if it exists

### Phase 5: Unit Tests

1. Test basic symlink creation
2. Test symlink to non-existent target (should succeed)
3. Test symlink already exists (EEXIST)
4. Test symlink in non-existent directory (ENOENT)
5. Test symlinkat with AT_FDCWD
6. Test symlinkat with valid dirfd
7. Test readlink on created symlink

## Key Design Decisions

### 1. Symlink Target Validation

Following POSIX/Linux semantics, the `target` path does NOT need to exist when creating a symlink. The symlink simply stores the target string. This is checked when the symlink is followed, not when it's created.

### 2. FileType Handling

Need to add `FileType::SymbolicLink` to properly distinguish symlinks from regular files in directory listings and stat calls.

### 3. Storage Model

In `in_mem` filesystem:
- Create a new `Entry::Symlink` variant that stores the target path as a String
- Alternatively, store symlinks as files with a special flag (simpler but less clean)

Recommend: Add `Entry::Symlink` variant for clarity.

### 4. Empty Target String

Linux returns `ENOENT` if target is an empty string. We follow this behavior.

## Files to Modify

1. `litebox_common_linux/src/lib.rs` - Add syscall variants and parsing
2. `litebox/src/fs/errors.rs` - Add `SymlinkError` enum
3. `litebox/src/fs/mod.rs` - Add `symlink()` to trait, add `FileType::SymbolicLink`
4. `litebox/src/fs/in_mem.rs` - Implement symlink support
5. `litebox/src/fs/layered.rs` - Implement symlink support
6. `litebox/src/fs/tar_ro.rs` - Return read-only error
7. `litebox/src/fs/devices.rs` - Return error
8. `litebox/src/fs/nine_p.rs` - Return todo!()
9. `litebox_shim_linux/src/lib.rs` - Add dispatch case
10. `litebox_shim_linux/src/syscalls/file.rs` - Add syscall handlers, update readlink

## References

- Linux man page: https://man7.org/linux/man-pages/man2/symlink.2.html
- Asterinas implementation: `/workspace/asterinas/kernel/src/syscall/symlink.rs`
- Linux source: `/workspace/linux/fs/namei.c` (do_symlinkat function)
