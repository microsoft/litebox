# PR Summary: Linux Syscall Improvements

## Commits in this PR

### Commit 1: Add comprehensive C test suite for Linux syscalls
- **29 files changed, +3,862 lines**
- Added 26 new C test files for various syscall categories
- 3 tests disabled (inotify, signalfd, zerocopy) pending syscall implementation

### Commit 2: Implement timerfd, flock, and chdir syscalls with filesystem improvements
- **14 files changed, +1,228 lines, -40 lines**

## New Syscalls Implemented

### 1. timerfd (timerfd_create, timerfd_settime, timerfd_gettime)
**Files:**
- `litebox_shim_linux/src/syscalls/timerfd.rs` (NEW)
- `litebox_common_linux/src/lib.rs` (types: Itimerspec, TfdFlags, TfdSetTimeFlags)

**Features:**
- One-shot and periodic timer support
- IOPollable implementation for epoll/poll integration
- Non-blocking read support
- Proper expiration counting

### 2. flock
**Files:**
- `litebox_shim_linux/src/syscalls/file.rs`
- `litebox_common_linux/src/lib.rs` (FlockOperation flags)

**Features:**
- LOCK_SH, LOCK_EX, LOCK_UN, LOCK_NB operations
- Simplified for single-process (locks always succeed)
- Proper operation validation

### 3. chdir
**Files:**
- `litebox_shim_linux/src/syscalls/file.rs`

**Features:**
- Dynamic cwd tracking in FsState
- Path normalization (resolves . and ..)
- Directory existence validation
- ENOTDIR error handling

## Filesystem Improvements

**Files modified:**
- `litebox/src/fs/devices.rs`
- `litebox/src/fs/errors.rs`
- `litebox/src/fs/in_mem.rs`
- `litebox/src/fs/layered.rs`
- `litebox/src/fs/mod.rs`
- `litebox/src/fs/nine_p.rs`
- `litebox/src/fs/tar_ro.rs`

**Features added:**
- Truncate support
- chmod/chown operations
- Rename functionality
- New error types (FileStatusError, etc.)
- Additional errno mappings

## Integration Points

### Descriptor System Updates
- Added `Timerfd` variant to `Descriptor` enum
- Updated all match statements in file.rs for new descriptor type
- Epoll/poll integration via `EpollDescriptor::Timerfd`

### Syscall Dispatch
- Added parsing for timerfd_create, timerfd_settime, timerfd_gettime, flock, chdir
- Updated `do_syscall` in lib.rs

## Test Coverage

### Enabled Tests (26 files)
| Category | Tests |
|----------|-------|
| File ops | access, chmod, dup, fcntl, fileio, flock, fsync, lseek, mkdir, rename, stat, truncate |
| I/O | getdents, iovec, pipe, preadwrite |
| Memory | mmap_advanced |
| Time | time, timerfd |
| Process | procid, rlimit, uname |
| Events | epoll, eventfd, poll_select |
| Directory | cwd |

### Disabled Tests (3 files)
- inotify_test.c.disabled
- signalfd_test.c.disabled
- zerocopy_test.c.disabled

## Known Limitations

1. **timerfd**: The `clockid` field is stored but not used (warning exists)
2. **flock**: Simplified for single-process - no actual lock contention
3. **chdir**: Symlink resolution not fully implemented in path normalization

## Unit Tests
- timerfd: 2 tests (test_timerfd_oneshot, test_timerfd_disarm)
- All existing tests continue to pass
