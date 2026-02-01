# Progress Report: Remove Trampoline Section from ELF

## Goal
Remove the injected `.trampolineLB0` section from ELF files and use a deterministic approach to locate trampoline data appended at the end of the file.

## Rationale
1. Some ELF files have no space for additional sections in the text segment
2. The `object` crate has bugs with unusual offsets (issue #477)
3. The section is essentially just metadata pointing to appended data anyway

## New Trampoline Header Format
```
Offset  Size   Field
0       8      Magic "LITEBOX0"
8       8      Trampoline size (u64, includes header)
16      4/8    Handler function pointer (arch-dependent)
...            Trampoline code entries
```

## Files to Modify
1. `litebox_syscall_rewriter/src/lib.rs` - Remove section creation, update header format
2. `litebox_common_linux/src/loader.rs` - Change detection to use file-end scanning
3. `litebox_rtld_audit/rtld_audit.c` - Update shared library loading to use file-end approach

---

## Progress Log

### 2026-02-01 - Started

- [x] Explored codebase to understand current implementation
- [x] Created branch `remove-trampoline-section`
- [x] Created this progress report
- [x] Found rtld_audit.c also needs updates (user reminder)
- [x] Modify `litebox_syscall_rewriter/src/lib.rs`
  - Removed section creation code
  - Added `is_already_hooked()` function using magic header detection
  - Updated header format to include size at offset 8
  - Updated handler offset calculations (now at offset 16)
- [x] Modify `litebox_common_linux/src/loader.rs`
  - Changed `parse_trampoline()` to scan file end for magic header
  - Updated `load_trampoline()` to read handler from offset 16
- [x] Modify `litebox_rtld_audit/rtld_audit.c`
  - Updated `parse_object()` to read handler from offset 16
  - Rewrote shared library loading to use file-end scanning instead of section headers
- [x] Run 64-bit tests
  - syscall_rewriter: 2 tests passed (after updating snapshots)
  - litebox_shim_linux: 53 tests passed
  - litebox_runner_linux_userland: 10 tests passed
- [x] Run 32-bit tests
  - litebox_runner_linux_userland (i686): 3 tests passed
- [x] All tests passing!
- [x] Fixed clippy warnings (truncation casts in loader.rs)

### Summary of Changes

**litebox_syscall_rewriter/src/lib.rs:**
- Removed `TRAMPOLINE_SECTION_NAME` and `TRAMPOLINE_SECTION_NAME_PREFIX` constants
- Added `TRAMPOLINE_MAGIC` constant and `HANDLER_OFFSET` constant (16)
- Removed `setup_trampoline_section()` function
- Added `is_already_hooked()` function that scans for magic header at page boundaries
- Updated header format: magic (8) + size (8) + handler (4/8)
- Updated all offset calculations to use `HANDLER_OFFSET` (16 instead of 8)

**litebox_common_linux/src/loader.rs:**
- Removed `REWRITER_MAGIC_NUMBER`, `REWRITER_VERSION_NUMBER`, and `TRAMPOLINE_SECTION_NAME` constants
- Added `REWRITER_MAGIC` constant
- Rewrote `parse_trampoline()` to scan file end for magic header instead of reading section headers
- Updated `load_trampoline()` to write handler at offset 16 instead of 8

**litebox_rtld_audit/rtld_audit.c:**
- Removed `TARGET_SECTION_NAME` and `HEADER_MAGIC` constants
- Updated `parse_object()` to read handler from offset 16
- Rewrote shared library loading to scan for trampoline at file end instead of using section headers
