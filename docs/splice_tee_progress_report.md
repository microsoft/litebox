# Splice/Tee Implementation Progress Report

This is an append-only progress report tracking the implementation of splice and tee syscalls.

## Entry 1: Initial Setup (2026-02-02)

### Completed
1. Created feature branch `wdcui/splice-tee` from main
2. Researched Linux splice/tee implementation in `/workspace/linux/fs/splice.c`
3. Reviewed existing litebox sendfile implementation for patterns
4. Analyzed litebox pipe infrastructure in `litebox/src/pipes.rs`
5. Created design document at `docs/splice_tee_design.md`

### Key Findings
- splice requires at least one pipe fd; tee requires both to be pipes
- Flags: SPLICE_F_MOVE (0x01), SPLICE_F_NONBLOCK (0x02), SPLICE_F_MORE (0x04), SPLICE_F_GIFT (0x08)
- tee needs to read pipe data without consuming it (peek operation)
- sendfile implementation provides good patterns for file-to-fd transfers

### Next Steps
- Implement Phase 1: Add types and syscall parsing in litebox_common_linux
- Implement Phase 2: Add syscall handlers in litebox_shim_linux
- Add peek capability to pipes for tee implementation

## Entry 2: Implementation Complete (2026-02-02)

### Completed
1. Added `SpliceFlags` bitflags type in `litebox_common_linux/src/lib.rs`
2. Added `Splice` and `Tee` variants to `SyscallRequest` enum
3. Added syscall number parsing for `Sysno::splice` and `Sysno::tee`
4. Added `SpliceFlags` to `reinterpret_truncated_from_usize_for!` macro
5. Added dispatch cases in `litebox_shim_linux/src/lib.rs`
6. Implemented `sys_splice()` with three helper methods:
   - `do_splice_pipe_to_pipe`: Splice between two pipes
   - `do_splice_pipe_to_file`: Splice from pipe to file
   - `do_splice_file_to_pipe`: Splice from file to pipe
7. Implemented `sys_tee()` for pipe duplication

### Implementation Details
- splice validates that at least one fd is a pipe
- splice rejects offset pointers for pipe fds (returns ESPIPE)
- splice uses temporary buffer (max 64KB) for data transfer
- tee implements a simplified version that reads from source, writes to both pipes
- SPLICE_F_NONBLOCK flag is respected for non-blocking operation

### Files Modified
- `litebox_common_linux/src/lib.rs` - SpliceFlags type, syscall variants, parsing
- `litebox_shim_linux/src/lib.rs` - Syscall dispatch
- `litebox_shim_linux/src/syscalls/file.rs` - sys_splice, sys_tee implementations

### Build Status
- Build successful

### Next Steps
- Add unit tests
- Run clippy and fmt
- Create draft PR

## Entry 5: Final Status (2026-02-02)

### Completed
- CI passed on rerun (Windows flaky test `test_pselect_read_hup` timeout was unrelated)
- PR #618 is ready for human review
- All 178 tests pass locally
- All 6 CI jobs pass (Build and Test, 32-bit, LVBS, Windows, SNP, no_std)

### Summary of Changes
1. Added `SpliceFlags` bitflags type with MOVE, NONBLOCK, MORE, GIFT flags
2. Added `Splice` and `Tee` syscall variants to `SyscallRequest` enum
3. Implemented `sys_splice()` with three helper methods for different fd combinations
4. Implemented `sys_tee()` with documentation noting the simplified read+write-back approach
5. Added 8 unit tests covering error cases
6. Applied security fixes from code review (TOCTOU, overflow, same-pipe check, negative offset)

### PR Link
https://github.com/microsoft/litebox/pull/618
