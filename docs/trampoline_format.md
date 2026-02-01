# Trampoline Data Format (PR #600)

This document describes the trampoline data format used by LiteBox syscall rewriting.

## Overview

The syscall rewriter modifies ELF binaries to redirect `syscall` instructions through a trampoline. The trampoline data is appended at a **page-aligned offset** at the end of the hooked ELF file.

## Motivation

Previous implementation injected a `.trampolineLB0` section into the ELF. This was changed because:
1. Some ELF files have no space for additional section headers
2. The `object` crate has bugs with unusual section offsets (#477)
3. Repurposing section header fields (`sh_addr`, `sh_offset`, `sh_entsize`) was a non-standard hack

## File Layout

```
+---------------------------+
|     Original ELF          |
|     (PT_LOAD segments,    |
|      section headers,     |
|      debug info, etc.)    |
+---------------------------+
|     Padding to page       |  <- Zero-filled to align to 0x1000
+---------------------------+  <- Page-aligned offset (trampoline start)
|     Trampoline Header     |
|     (24 bytes for x64)    |
+---------------------------+
|     Trampoline Code       |
|     (per-syscall stubs)   |
+---------------------------+  <- EOF
```

## Header Format

```
Offset  Size    Field               Description
------  ----    -----               -----------
0       8       Magic               "LITEBOX0" (0x30584f424554494c LE)
8       8       Size                Total trampoline size including header (u64)
16      4/8     Handler Pointer     Syscall handler address (4 bytes x86, 8 bytes x64)
```

**Note:** The header size is architecture-dependent:
- x86-64: 24 bytes (8 + 8 + 8)
- x86-32: 20 bytes (8 + 8 + 4)

## Trampoline Code Structure

After the header, each hooked syscall has a stub that:
1. Loads the return address into a register (RCX on x64)
2. Jumps to the handler pointer at offset 16
3. Handler executes the syscall and returns to the original code

### x86-64 Stub Format
```asm
lea rcx, [rip + return_offset]   ; Load return address
jmp [rip + handler_offset]       ; Jump to handler (reads from offset 16)
```

### x86-32 Stub Format
```asm
push eax
call next_instruction            ; Get EIP into EAX
pop eax
call [eax + handler_offset]      ; Call handler (reads from offset 16)
jmp return_address               ; Return to original code
```

## Locating the Trampoline

### At Load Time (Rust loader and rtld_audit)

1. Scan backwards from file end at page boundaries
2. Check for "LITEBOX0" magic at each page offset
3. Validate: `offset + size == file_size`
4. Limit scan to 16 pages (64KB max trampoline)

```rust
let mut offset = file_size & !(PAGE_SIZE - 1);
if offset == file_size {
    offset -= PAGE_SIZE;
}
for _ in 0..16 {
    if magic_at(offset) && offset + read_size(offset) == file_size {
        return Some(offset);
    }
    offset -= PAGE_SIZE;
}
```

### Virtual Address Calculation

The trampoline is mapped at:
```
vaddr = page_align_up(max(p_vaddr + p_memsz for all PT_LOAD segments))
```

This is calculated identically in:
- `litebox_syscall_rewriter/src/lib.rs` (`find_addr_for_trampoline_code`)
- `litebox_common_linux/src/loader.rs` (`parse_trampoline`)
- `litebox_rtld_audit/rtld_audit.c` (`la_objopen`)

## Components

| Component | Role |
|-----------|------|
| `litebox_syscall_rewriter` | Generates hooked ELF with trampoline appended |
| `litebox_common_linux/loader.rs` | Parses and maps trampoline for static binaries |
| `litebox_rtld_audit/rtld_audit.c` | Runtime patching for dynamically loaded shared libraries |
| `litebox_shim_linux` | Provides the syscall handler that trampoline jumps to |

## Handler Pointer Patching

The handler pointer at offset 16 is initially 0 (or a placeholder). It is patched at load time:

1. **Static binaries**: `loader.rs` writes the handler address after mapping
2. **Shared libraries**: `rtld_audit.c` patches via `la_objopen` callback

## Detection of Already-Hooked Binaries

The `is_already_hooked()` function prevents double-hooking by scanning for the magic:

```rust
fn is_already_hooked(binary: &[u8]) -> bool {
    // Scan page boundaries for "LITEBOX0" magic
    // Returns true if found within 16 pages of file end
}
```

## Limits and Constraints

- **Maximum trampoline size**: ~64KB (16 pages)
- **Page alignment**: 4KB (0x1000)
- **Supported architectures**: x86-64, x86-32 (rtld_audit.c is x86-64 only)

## Breaking Change from Previous Format

Old format (section-based):
```
Header: magic (8) + handler (4/8)
Location: Stored in repurposed section header fields
```

New format (file-end):
```
Header: magic (8) + size (8) + handler (4/8)
Location: Page-aligned at file end
```

**Binaries hooked with the old format are incompatible with the new loader.**

## Related Files

- `litebox_syscall_rewriter/src/lib.rs` - Trampoline generation
- `litebox_common_linux/src/loader.rs` - ELF parsing and loading
- `litebox_rtld_audit/rtld_audit.c` - Runtime audit library
- `litebox_shim_linux/src/lib.rs` - Syscall handler implementation
