# preadv/pwritev Implementation Progress Report

This is an append-only progress report for the preadv/pwritev syscall implementation.

---

## Entry 1 - Project Setup

**Status**: Completed

### Completed
- [x] Created feature branch `wdcui/preadv-pwritev` from main
- [x] Reviewed existing readv/writev implementation in litebox
- [x] Reviewed Linux source code for preadv/pwritev syscalls
- [x] Reviewed Asterinas implementation for reference
- [x] Created design document

### Next Steps
- Add RwfFlags bitflags type to litebox_common_linux
- Add syscall variants to SyscallRequest enum
- Add syscall number parsing

---

## Entry 2 - Implementation Complete

**Status**: Completed

### Changes Made

#### litebox_common_linux/src/lib.rs
- Added `RwfFlags` bitflags type with RWF_HIPRI, RWF_DSYNC, RWF_SYNC, RWF_NOWAIT, RWF_APPEND
- Added SyscallRequest variants: Preadv, Pwritev, Preadv2, Pwritev2
- Added syscall number parsing for preadv, pwritev, preadv2, pwritev2
- Added RwfFlags to `reinterpret_truncated_from_usize_for!` macro
- Handles x86 vs x86_64 offset parameter differences

#### litebox_shim_linux/src/lib.rs
- Added dispatch cases for Preadv, Pwritev, Preadv2, Pwritev2

#### litebox_shim_linux/src/syscalls/file.rs
- Implemented sys_preadv(): vectored read at offset
- Implemented sys_pwritev(): vectored write at offset
- Implemented sys_preadv2(): vectored read with flags, offset=-1 falls back to readv
- Implemented sys_pwritev2(): vectored write with flags, offset=-1 falls back to writev
- Implemented do_preadv() and do_pwritev() helper functions
- Returns ESPIPE for pipes/sockets (positioned I/O not supported)
- Returns EINVAL for negative offsets and invalid flags
- Returns EOPNOTSUPP for unknown flags

#### litebox_shim_linux/src/syscalls/tests.rs
- Added test_preadv_pwritev_basic: tests basic preadv and pwritev operations
- Added test_preadv2_offset_minus_one: tests preadv2 fallback to readv when offset=-1
- Added test_preadv_invalid_offset: tests EINVAL for negative offset
- Added test_preadv2_invalid_flags: tests EINVAL for RWF_APPEND on read

### Test Results
- All 174 tests pass
- No clippy warnings
- Code formatted with cargo fmt

---

