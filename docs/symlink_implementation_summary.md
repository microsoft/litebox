# Symlink Syscall Implementation Summary

**Date:** 2026-02-01  
**PR:** [#616](https://github.com/microsoft/litebox/pull/616)  
**Status:** Draft PR, all CI passing

## Overview

This document summarizes the implementation of `symlink(2)` and `symlinkat(2)` Linux syscalls in litebox, a security-focused library OS.

## What Was Implemented

### 1. Syscall Parsing (litebox_common_linux)

- Added `Symlinkat` variant to `SyscallRequest` enum
- Added syscall number parsing for `Sysno::symlink` and `Sysno::symlinkat`
- Added `From<SymlinkError>` and `From<ReadlinkError>` for `Errno` conversions

### 2. Filesystem Layer (litebox/src/fs)

**New Error Types (errors.rs):**
- `SymlinkError` - errors for symlink creation (NoWritePerms, AlreadyExists, ReadOnlyFileSystem, EmptyTarget, PathError)
- `ReadlinkError` - errors for reading symlinks (NotASymlink, PathError)

**FileSystem Trait Updates (mod.rs):**
- Added `FileType::SymbolicLink` variant
- Added `symlink()` method with full documentation
- Added `readlink()` method with full documentation

**Filesystem Implementations:**
- `in_mem.rs`: Full implementation with `Entry::Symlink` and `SymlinkX` types
- `layered.rs`: Delegates to upper/lower layers appropriately
- `tar_ro.rs`: Returns `ReadOnlyFileSystem` for symlink
- `devices.rs`: Returns `ReadOnlyFileSystem` (virtual filesystem)
- `nine_p.rs`: Returns `todo!()` (not yet implemented)

### 3. Syscall Handlers (litebox_shim_linux)

- Added `sys_symlink()` and `sys_symlinkat()` methods to `Task`
- Updated `do_readlink()` to check filesystem for symlinks
- Added `SyscallRequest::Symlinkat` dispatch case in main handler

### 4. Unit Tests

Added 7 unit tests in `litebox/src/fs/tests.rs`:
- `symlink_creation_and_readlink`
- `symlink_to_nonexistent_target`
- `symlink_already_exists`
- `symlink_empty_target`
- `readlink_not_a_symlink`
- `symlink_unlink`
- `symlink_in_directory_listing`

## Files Modified

| File | Changes |
|------|---------|
| `litebox/src/fs/errors.rs` | Added SymlinkError, ReadlinkError; added #[non_exhaustive] to TruncateError |
| `litebox/src/fs/mod.rs` | Added symlink/readlink to FileSystem trait, FileType::SymbolicLink |
| `litebox/src/fs/in_mem.rs` | Full symlink implementation with Entry::Symlink |
| `litebox/src/fs/layered.rs` | Symlink delegation to layers |
| `litebox/src/fs/tar_ro.rs` | Read-only error handling |
| `litebox/src/fs/devices.rs` | Error handling for virtual filesystem |
| `litebox/src/fs/nine_p.rs` | Todo stubs |
| `litebox/src/fs/tests.rs` | 7 new unit tests |
| `litebox_common_linux/src/lib.rs` | Syscall variants and parsing |
| `litebox_common_linux/src/errno/mod.rs` | Errno conversions |
| `litebox_shim_linux/src/lib.rs` | Syscall dispatch |
| `litebox_shim_linux/src/syscalls/file.rs` | Syscall handlers |

## Design Decisions

### 1. Symlink Target Validation
Following POSIX/Linux semantics, the target path does NOT need to exist when creating a symlink. The target is validated only when the symlink is followed, not when it's created.

### 2. Error Handling (Linux Compatible)
- Empty target string → `ENOENT`
- Empty linkpath/pathname → `ENOENT`
- Target path ≥ PATH_MAX (4096) → `ENAMETOOLONG`
- Linkpath already exists → `EEXIST`
- Not a symlink (for readlink) → `EINVAL`

### 3. Storage Model
In the in-memory filesystem, symlinks are stored as `Entry::Symlink(Arc<RwLock<SymlinkX>>)` where `SymlinkX` contains the target path string and metadata.

## Code Review Findings & Fixes

Three automated review agents analyzed the implementation:

### Security Review
- **Fixed:** Added target path length validation to prevent memory exhaustion
- **Documented:** Symlink target not normalized - security consideration for future symlink following implementation

### API Design Review
- **Fixed:** Added `#[non_exhaustive]` to `TruncateError` for consistency
- **Fixed:** Added comprehensive documentation to symlink/readlink trait methods
- **Fixed:** devices.rs now returns `ReadOnlyFileSystem` instead of misleading `NoSuchFileOrDirectory`

### Linux Semantics Review
- **Fixed:** Empty linkpath now returns `ENOENT` (was returning `EEXIST`)
- **Fixed:** Empty pathname in readlinkat now returns `ENOENT` (was returning `EINVAL`)
- **Fixed:** Added `ENAMETOOLONG` check for target paths ≥ 4096 bytes

## Testing Results

| Test Suite | Result |
|------------|--------|
| Unit tests (symlink) | 7/7 passed |
| Full local tests | 182 passed, 6 skipped |
| CI workflow | ✅ All jobs passed |
| SemverChecks | ✅ Passed |

## Known Limitations

1. **Symlink following not implemented:** Opening a symlink or using it as a path component is not yet supported (returns `unimplemented!()` or `ComponentNotADirectory`)

2. **nine_p filesystem:** Symlink operations return `todo!()` as 9P protocol support is incomplete

3. **FdRelative paths:** `symlinkat` with file descriptor relative paths is not implemented

## Future Work

1. Implement symlink following in `open()` and path traversal
2. Add security boundary checks when symlink following is implemented
3. Complete 9P filesystem symlink support
4. Consider adding symlink loop detection (ELOOP)

## References

- Linux man page: https://man7.org/linux/man-pages/man2/symlink.2.html
- Linux source: `fs/namei.c` (do_symlinkat function)
- Asterinas implementation: `kernel/src/syscall/symlink.rs`
