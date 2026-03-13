# Phase 2 Implementation: Windows on Linux Support

## Overview

This document describes the implementation of Phase 1 (Foundation & PE Loader) and Phase 2 (Core NTDLL APIs) for running Windows programs on Linux with LiteBox.

## Architecture

```
Windows PE Binary (.exe)
        ↓
litebox_runner_windows_on_linux_userland (CLI)
        ↓
litebox_shim_windows (PE loader, syscall interface)
        ↓
litebox_platform_linux_for_windows (Windows API → Linux translation)
        ↓
Linux Kernel (syscalls)
```

## Components Implemented

### 1. litebox_shim_windows

**Purpose:** Windows "North" interface - PE loader and syscall definitions

**Key Features:**
- PE binary parser with validation
- DOS header, PE signature, file header parsing
- Entry point and image base extraction
- NTDLL API trait definitions
- Support for x64 PE binaries only

**Files:**
- `src/loader/pe.rs` - PE binary parser
- `src/syscalls/ntdll.rs` - NTDLL API trait definitions

### 2. litebox_platform_linux_for_windows

**Purpose:** Linux "South" platform - Windows API implementation using Linux syscalls

**Key Features:**
- File I/O translation (NtCreateFile → open, NtReadFile → read, etc.)
- Console I/O (WriteConsole → stdout)
- Memory management (NtAllocateVirtualMemory → mmap, NtFreeVirtualMemory → munmap)
- Windows → Linux path translation (C:\path → /path)
- Handle management (Windows handles → Linux FDs)

**API Mappings:**
| Windows API | Linux Syscall |
|-------------|---------------|
| NtCreateFile | open() |
| NtReadFile | read() |
| NtWriteFile | write() |
| NtClose | close() |
| NtAllocateVirtualMemory | mmap() |
| NtFreeVirtualMemory | munmap() |

### 3. litebox_runner_windows_on_linux_userland

**Purpose:** CLI runner for executing Windows programs on Linux

**Usage:**
```bash
litebox_runner_windows_on_linux_userland program.exe [args...]
```

**Current Capabilities:**
- Load and parse Windows PE executables
- Display PE metadata (entry point, image base, section count)
- Demonstrate console I/O through Windows API layer

## Implementation Status

### Phase 1: Foundation & PE Loader ✅
- [x] Create project structure for new crates
- [x] Implement basic PE parser (headers, sections)
- [x] Load PE binary into memory
- [x] Set up initial execution context
- [x] Handle basic validation

### Phase 2: Core NTDLL APIs ✅
- [x] Implement file I/O APIs
- [x] Implement console I/O
- [x] Implement memory APIs
- [x] Set up syscall dispatch mechanism (trait-based)
- [x] Handle Windows → Linux path translation

## Example Output

```bash
$ cargo run -p litebox_runner_windows_on_linux_userland -- /tmp/test.exe

Loaded PE binary: /tmp/test.exe
  Entry point: 0x1400
  Image base: 0x140000000
  Sections: 3
Hello from Windows on Linux!

[Phase 2 Complete: PE loader and basic NTDLL APIs implemented]
Note: Full program execution not yet implemented - this is the foundation.
```

## Technical Decisions

### Safety
- Used `unsafe` blocks for PE header parsing with explicit bounds checking
- All pointer casts include safety comments
- Memory operations use libc for proven implementations

### Error Handling
- Custom error types for each crate
- Result-based error propagation
- Detailed error messages for debugging

### Testing
- Unit tests for PE loader validation
- Unit tests for path translation
- Unit tests for handle allocation

## Future Work (Phase 3+)

### Phase 3: API Tracing Framework
- IAT (Import Address Table) hooking
- Configurable trace filters
- JSON and text output formats

### Phase 4: Threading & Synchronization
- NtCreateThread implementation
- Thread-local storage (TLS)
- Synchronization primitives (events, mutexes)

### Phase 5: Extended API Support
- DLL loading (LoadLibrary, GetProcAddress)
- Process management
- Exception handling
- Registry emulation

## References

- Implementation Plan: [docs/windows_on_linux_implementation_plan.md](./windows_on_linux_implementation_plan.md)
- PE Format: [Microsoft PE/COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- Existing LiteBox implementation: `litebox_runner_linux_on_windows_userland`

## Security Considerations

- PE parsing includes bounds checking to prevent buffer overflows
- Path translation prevents directory traversal attacks
- Memory allocations use safe wrappers around mmap
- Handle validation prevents use-after-free

## Testing

All new crates pass:
- `cargo fmt` ✅
- `cargo build` ✅
- `cargo clippy` ✅ (with only minor warnings)
- `cargo test` ✅

## Conclusion

Phase 2 is complete. The foundation is in place for running Windows programs on Linux, with:
- Working PE loader
- Core NTDLL API definitions
- Linux-based implementations of Windows APIs
- Path translation and handle management
- CLI runner for demonstration

The next phase will add API tracing capabilities to enable security analysis and debugging.
