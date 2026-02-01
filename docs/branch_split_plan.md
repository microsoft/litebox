# Branch Split Plan

## Goal
Split the current `wdcui/linux-syscalls` branch into 3 clean commits:
1. **Commit 1** (to be tabled): Disabled tests + boilerplate.rs changes
2. **Commit 2** (separate PR): Tests for existing syscalls + supporting bug fixes
3. **Commit 3** (separate PR): New syscalls + their tests

## Commit 1: Disabled Tests
**Files:**
- `litebox_runner_linux_userland/tests/inotify_test.c.disabled`
- `litebox_runner_linux_userland/tests/link_test.c.disabled`
- `litebox_runner_linux_userland/tests/signalfd_test.c.disabled`
- `litebox_runner_linux_userland/tests/zerocopy_test.c.disabled`
- `dev_tests/src/boilerplate.rs` (only the "disabled" extension line)

## Commit 2: Tests for Existing Syscalls
**Test files:**
- `access_test.c` (with CodeQL comment)
- `dup_test.c`
- `epoll_test.c`
- `eventfd_test.c`
- `fcntl_test.c`
- `fileio_test.c` (with CodeQL comment)
- `getdents_test.c`
- `iovec_test.c`
- `lseek_test.c`
- `mkdir_test.c` (with CodeQL comment)
- `mmap_advanced.c`
- `pipe_test.c`
- `poll_select.c`
- `preadwrite_test.c`
- `rlimit_test.c`
- `stat_test.c` (with CodeQL comment)
- `time_test.c`
- `uname_test.c`

**Supporting changes:**
- `litebox/src/fs/in_mem.rs`: O_APPEND support, seek past EOF fix, insert_in_range fix (NOT rename)
- `litebox/src/fs/layered.rs`: O_APPEND support (NOT rename)
- `litebox/src/fs/tar_ro.rs`: seek past EOF fix (NOT rename)
- `litebox_runner_linux_userland/tests/run.rs`: 32-bit skip for existing tests only
  - `lseek_test.c`, `fileio_test.c`, `preadwrite_test.c`, `poll_select.c`

## Commit 3: New Syscalls + Tests
**New syscalls implemented:**
- chmod, fchmod, fchmodat
- chown, fchown, fchownat, lchown
- rename, renameat, renameat2
- truncate, ftruncate
- fsync, fdatasync, sync, syncfs
- timerfd_create, timerfd_settime, timerfd_gettime
- flock
- chdir, getcwd (getcwd existed but chdir is new)
- getpgid, setpgid, getsid, setsid

**Test files:**
- `chmod_test.c` (with CodeQL comment)
- `cwd_test.c`
- `flock_test.c`
- `fsync_test.c`
- `procid_test.c`
- `rename_test.c` (with CodeQL comment)
- `timerfd_test.c`
- `truncate_test.c` (with CodeQL comment)

**Implementation files:**
- `litebox_common_linux/src/lib.rs` (new SyscallRequest variants, types)
- `litebox_common_linux/src/errno/mod.rs` (new error From impls)
- `litebox/src/fs/mod.rs` (rename trait method)
- `litebox/src/fs/errors.rs` (RenameError)
- `litebox/src/fs/in_mem.rs` (rename implementation only)
- `litebox/src/fs/layered.rs` (rename implementation only)
- `litebox/src/fs/tar_ro.rs` (rename stub only)
- `litebox/src/fs/nine_p.rs` (rename stub)
- `litebox/src/fs/devices.rs` (rename stub)
- `litebox_shim_linux/src/lib.rs` (Timerfd descriptor, syscall dispatch)
- `litebox_shim_linux/src/syscalls/mod.rs` (timerfd module)
- `litebox_shim_linux/src/syscalls/file.rs` (new syscall handlers)
- `litebox_shim_linux/src/syscalls/timerfd.rs` (new file)
- `litebox_shim_linux/src/syscalls/epoll.rs` (timerfd support)
- `litebox_shim_linux/src/syscalls/tests.rs` (unit tests)
- `litebox_runner_linux_userland/tests/run.rs`: 32-bit skip for new tests
  - `truncate_test.c`, `timerfd_test.c`

---

## Branch Structure

```
main
 ├── wdcui/disabled-tests (Commit 1 - separate branch, to be tabled)
 │
 └── wdcui/linux-syscalls (rebased)
      ├── Commit 2: Tests for existing syscalls
      └── Commit 3: New syscalls + tests
```

## Execution Steps

### Phase 1: Preparation
- [ ] Save current branch state to backup branch
- [ ] Note current commit hash

### Phase 2: Create Commit 1 on separate branch (wdcui/disabled-tests)
- [ ] Create new branch from main
- [ ] Add disabled test files
- [ ] Add boilerplate.rs change (disabled extension only)
- [ ] Commit and push

### Phase 3: Create Commit 2 on wdcui/linux-syscalls (from main)
- [ ] Reset wdcui/linux-syscalls to main
- [ ] Add existing syscall test files (with CodeQL comments where needed)
- [ ] Add in_mem.rs changes (O_APPEND, seek past EOF, insert_in_range - NOT rename)
- [ ] Add layered.rs changes (O_APPEND - NOT rename)
- [ ] Add tar_ro.rs changes (seek past EOF - NOT rename)
- [ ] Add run.rs changes (32-bit skip for existing tests only)
- [ ] Commit

### Phase 4: Create Commit 3 on top of Commit 2
- [ ] Add all litebox_common_linux changes
- [ ] Add all litebox_shim_linux changes
- [ ] Add remaining fs changes (rename implementations)
- [ ] Add new syscall test files (with CodeQL comments where needed)
- [ ] Add run.rs changes (32-bit skip for new tests)
- [ ] Commit

### Phase 5: Final
- [ ] Force push wdcui/linux-syscalls
- [ ] Verify both commits are clean
- [ ] Verify CI passes

---

## Progress Log

### Started: Now

**Phase 1: Preparation**
- [x] Backup branch created: `wdcui/linux-syscalls-backup` at `be8c8c21`

**Phase 2: Commit 1 (wdcui/disabled-tests)**
- [x] Created branch from main
- [x] Added 4 disabled test files
- [x] Added "disabled" extension to boilerplate.rs
- [x] Committed: `ab252181`
- [x] Pushed to origin

**Phase 3: Commit 2 (wdcui/linux-syscalls)**
- [x] Reset branch to main
- [x] Added 18 existing syscall test files
- [x] Added O_APPEND support to in_mem.rs and layered.rs
- [x] Added seek past EOF fix to in_mem.rs and tar_ro.rs
- [x] Added 32-bit skip for existing tests in run.rs
- [x] Committed: `cba8c90d`

**Phase 5: Final**
- [x] Force pushed wdcui/linux-syscalls with 2 clean commits
- [ ] Verify CI passes

### Branch Structure (Final)
```
main (ec317ab7)
 ├── wdcui/disabled-tests (ab252181) - Commit 1: Disabled tests (separate branch)
 │
 └── wdcui/linux-syscalls
      ├── cba8c90d - Commit 2: Tests for existing syscalls
      └── aafcf3c5 - Commit 3: New syscalls + tests
```

### Backup
- Original branch preserved at: `wdcui/linux-syscalls-backup` (be8c8c21)

