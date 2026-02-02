# Design Document: statx Syscall Implementation

## Overview

This document describes the implementation plan for the Linux `statx(2)` syscall in litebox. The `statx` syscall provides extended file metadata retrieval capabilities beyond the traditional `stat` family of syscalls.

## Syscall Signature

```c
int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `dirfd` | `int` | Directory file descriptor for relative paths, or `AT_FDCWD` |
| `pathname` | `const char *` | Path to the file (can be empty with `AT_EMPTY_PATH`) |
| `flags` | `int` | Flags controlling path resolution and sync behavior |
| `mask` | `unsigned int` | Bitmask of requested fields |
| `statxbuf` | `struct statx *` | Output buffer for file metadata |

### Flags (for `flags` parameter)

| Flag | Value | Description |
|------|-------|-------------|
| `AT_EMPTY_PATH` | `0x1000` | Allow empty pathname, operate on `dirfd` itself |
| `AT_NO_AUTOMOUNT` | `0x0800` | Suppress terminal automount traversal |
| `AT_SYMLINK_NOFOLLOW` | `0x0100` | Do not follow symbolic links |
| `AT_STATX_SYNC_AS_STAT` | `0x0000` | Default: do whatever stat() does |
| `AT_STATX_FORCE_SYNC` | `0x2000` | Force attributes to be synced with server |
| `AT_STATX_DONT_SYNC` | `0x4000` | Don't sync attributes with the server |

### Mask (for `mask` parameter)

| Mask | Value | Description |
|------|-------|-------------|
| `STATX_TYPE` | `0x0001` | Want `stx_mode & S_IFMT` |
| `STATX_MODE` | `0x0002` | Want `stx_mode & ~S_IFMT` |
| `STATX_NLINK` | `0x0004` | Want `stx_nlink` |
| `STATX_UID` | `0x0008` | Want `stx_uid` |
| `STATX_GID` | `0x0010` | Want `stx_gid` |
| `STATX_ATIME` | `0x0020` | Want `stx_atime` |
| `STATX_MTIME` | `0x0040` | Want `stx_mtime` |
| `STATX_CTIME` | `0x0080` | Want `stx_ctime` |
| `STATX_INO` | `0x0100` | Want `stx_ino` |
| `STATX_SIZE` | `0x0200` | Want `stx_size` |
| `STATX_BLOCKS` | `0x0400` | Want `stx_blocks` |
| `STATX_BASIC_STATS` | `0x07ff` | All of the above |
| `STATX_BTIME` | `0x0800` | Want `stx_btime` (birth/creation time) |
| `STATX_MNT_ID` | `0x1000` | Want `stx_mnt_id` |
| `STATX__RESERVED` | `0x80000000` | Reserved for future expansion |

## Struct Definitions

### `struct statx` (256 bytes)

```rust
#[repr(C)]
pub struct Statx {
    pub stx_mask: u32,           // What results were written
    pub stx_blksize: u32,        // Preferred I/O block size
    pub stx_attributes: u64,     // Flags conveying file info
    pub stx_nlink: u32,          // Number of hard links
    pub stx_uid: u32,            // User ID of owner
    pub stx_gid: u32,            // Group ID of owner
    pub stx_mode: u16,           // File mode
    __spare0: [u16; 1],
    pub stx_ino: u64,            // Inode number
    pub stx_size: u64,           // File size
    pub stx_blocks: u64,         // Number of 512-byte blocks
    pub stx_attributes_mask: u64, // Supported attributes
    pub stx_atime: StatxTimestamp, // Last access time
    pub stx_btime: StatxTimestamp, // Creation time
    pub stx_ctime: StatxTimestamp, // Last status change time
    pub stx_mtime: StatxTimestamp, // Last modification time
    pub stx_rdev_major: u32,     // Device ID (major) for special files
    pub stx_rdev_minor: u32,     // Device ID (minor) for special files
    pub stx_dev_major: u32,      // ID of device containing file (major)
    pub stx_dev_minor: u32,      // ID of device containing file (minor)
    pub stx_mnt_id: u64,         // Mount ID
    pub stx_dio_mem_align: u32,  // Direct I/O memory alignment
    pub stx_dio_offset_align: u32, // Direct I/O offset alignment
    __spare3: [u64; 12],         // Spare space for future expansion
}
```

### `struct statx_timestamp` (16 bytes)

```rust
#[repr(C)]
pub struct StatxTimestamp {
    pub tv_sec: i64,    // Seconds since epoch
    pub tv_nsec: u32,   // Nanoseconds
    __reserved: i32,
}
```

## Implementation Plan

### 1. Add Types to `litebox_common_linux/src/lib.rs`

- Define `Statx` struct (256 bytes, matching Linux ABI)
- Define `StatxTimestamp` struct (16 bytes)
- Define `StatxFlags` bitflags for the `flags` parameter
- Define `StatxMask` bitflags for the `mask` parameter
- Add `Statx` variant to `SyscallRequest` enum
- Add parsing logic in `SyscallRequest::try_from_raw`

### 2. Add Syscall Handler to `litebox_shim_linux/src/lib.rs`

- Add dispatch case for `SyscallRequest::Statx`
- Call new `sys_statx` method on `Task`

### 3. Implement `sys_statx` in `litebox_shim_linux/src/syscalls/file.rs`

- Validate flags (mutually exclusive `FORCE_SYNC` and `DONT_SYNC`)
- Validate mask (reject `STATX__RESERVED`)
- Handle path resolution based on flags:
  - `AT_EMPTY_PATH` with empty pathname: operate on `dirfd`
  - Otherwise: resolve path relative to `dirfd`
- Handle `AT_SYMLINK_NOFOLLOW` flag
- Reuse existing `do_stat` / `sys_fstat` infrastructure
- Convert `FileStatus` to `Statx` struct
- Write result to user buffer

### 4. Conversion from `FileStatus` to `Statx`

The conversion will populate fields based on available data:

| Statx Field | Source | Notes |
|-------------|--------|-------|
| `stx_mask` | computed | Set bits for fields we provide |
| `stx_blksize` | `FileStatus::blksize` | |
| `stx_attributes` | 0 | No special attributes supported yet |
| `stx_nlink` | 1 | Hardcoded (same as FileStat) |
| `stx_uid` | `FileStatus::owner.user` | |
| `stx_gid` | `FileStatus::owner.group` | |
| `stx_mode` | `FileStatus::mode` + `FileStatus::file_type` | Combined as in FileStat |
| `stx_ino` | `FileStatus::node_info.ino` | |
| `stx_size` | `FileStatus::size` | |
| `stx_blocks` | 0 | Not tracked |
| `stx_attributes_mask` | 0 | No attributes supported |
| `stx_atime/mtime/ctime` | 0 | Not currently tracked in FileStatus |
| `stx_btime` | 0 | Birth time not tracked |
| `stx_rdev_major/minor` | `FileStatus::node_info.rdev` | Split into major/minor |
| `stx_dev_major/minor` | `FileStatus::node_info.dev` | Split into major/minor |
| `stx_mnt_id` | 0 | Not tracked |
| `stx_dio_*` | 0 | Direct I/O not supported |

### 5. Error Handling

| Error | Condition |
|-------|-----------|
| `EACCES` | Search permission denied on path prefix |
| `EBADF` | `dirfd` is not a valid fd (when not `AT_FDCWD`) |
| `EFAULT` | Bad address for `pathname` or `statxbuf` |
| `EINVAL` | Invalid flags (both FORCE_SYNC and DONT_SYNC) |
| `EINVAL` | Reserved bits set in mask |
| `ENOENT` | File does not exist |
| `ENOMEM` | Out of memory |
| `ENOTDIR` | Path component is not a directory |

## Test Plan

### Unit Tests (Rust)

1. **`test_statx_basic`** - Basic statx on a regular file
2. **`test_statx_empty_path`** - AT_EMPTY_PATH with fd
3. **`test_statx_symlink_nofollow`** - AT_SYMLINK_NOFOLLOW flag
4. **`test_statx_invalid_flags`** - EINVAL for conflicting flags
5. **`test_statx_invalid_mask`** - EINVAL for reserved mask bits
6. **`test_statx_ebadf`** - EBADF for invalid dirfd
7. **`test_statx_enoent`** - ENOENT for non-existent file

### C Integration Tests

Create `statx_test.c` with tests for:
- Basic file metadata retrieval
- Directory metadata
- AT_EMPTY_PATH functionality
- Error cases

## References

- Linux man page: `man 2 statx`
- Linux source: `/workspace/linux/fs/stat.c` (SYSCALL_DEFINE5(statx, ...))
- Linux headers: `/workspace/linux/include/uapi/linux/stat.h`
- Asterinas implementation: `/workspace/asterinas/kernel/src/syscall/statx.rs`

## Architecture Notes

- The `statx` struct is architecture-independent (same layout on x86 and x86_64)
- The struct size is 256 bytes with 12 spare u64 fields for future expansion
- litebox currently doesn't track timestamps, so atime/mtime/ctime/btime will be 0
