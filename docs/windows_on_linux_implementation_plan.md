# Implementation Plan: Running Windows Programs on Linux with API Tracing

## Executive Summary

This document outlines the architecture and implementation plan for enabling LiteBox to run unmodified Windows PE binaries on Linux while tracing Windows API calls. This is the inverse of the existing capability that runs Linux ELF binaries on Windows.

## Background

### Current State
- LiteBox currently supports running **Linux programs on Windows** via:
  - `litebox_shim_linux`: Handles Linux syscalls and ELF loading
  - `litebox_platform_windows_userland`: Provides Windows-based platform implementation
  - `litebox_runner_linux_on_windows_userland`: Runner that combines them

### Goal
Enable running **Windows programs on Linux** with the ability to trace all Windows API calls for security analysis and debugging.

## Architecture Overview

### Key Components to Implement

1. **litebox_shim_windows** - Windows PE binary support and syscall handling
2. **litebox_platform_linux_for_windows** - Linux platform that implements Windows APIs
3. **litebox_runner_windows_on_linux_userland** - Runner executable with CLI

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│  Windows PE Binary (unmodified .exe)                    │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  litebox_shim_windows (NEW)                             │
│  - PE/DLL loader                                        │
│  - Windows syscall interface (NTDLL)                    │
│  - API tracing hooks                                    │
│  - Thread management (Windows ABI)                      │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  LiteBox Core (existing)                                │
│  - Platform abstraction layer                           │
│  - Memory management                                    │
│  - Event system                                         │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  litebox_platform_linux_for_windows (NEW)               │
│  - Linux syscall implementations                        │
│  - Windows API → Linux translation layer                │
│  - Process/thread management                            │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  Linux Kernel                                           │
└─────────────────────────────────────────────────────────┘
```

## Detailed Component Design

### 1. litebox_shim_windows

**Purpose:** Handle Windows PE binaries and provide Windows syscall interface

**Key Modules:**

#### 1.1 PE Loader (`loader/pe.rs`)
- Parse PE headers (DOS, NT, Optional)
- Load code and data sections into memory
- Handle relocations for ASLR
- Process import/export tables
- Set up initial execution context

#### 1.2 Windows Syscalls (`syscalls/`)
- `ntdll.rs` - Core NTDLL APIs (NtCreateFile, NtReadFile, etc.)
- `kernel32.rs` - Win32 APIs that wrap NTDLL
- `syscall_handler.rs` - Dispatch mechanism

#### 1.3 API Tracing (`tracing/`)
- Hook mechanism for IAT (Import Address Table)
- Configurable filtering (by DLL, API, category)
- Multiple output formats (text, JSON, CSV)
- Low-overhead when disabled

### 2. litebox_platform_linux_for_windows

**Purpose:** Implement Windows platform APIs using Linux syscalls

**Key Translations:**

#### File I/O
- NtCreateFile → open() with flag translation
- NtReadFile → read()/pread()
- NtWriteFile → write()/pwrite()
- NtClose → close()

#### Memory Management
- NtAllocateVirtualMemory → mmap()
- NtFreeVirtualMemory → munmap()
- NtProtectVirtualMemory → mprotect()

#### Threading
- NtCreateThread → clone() with CLONE_VM | CLONE_THREAD
- NtTerminateThread → exit via futex
- Thread Local Storage handling

#### Synchronization
- NtCreateEvent → eventfd()
- NtWaitForSingleObject → poll()/epoll()
- NtSetEvent → eventfd_write()

### 3. litebox_runner_windows_on_linux_userland

**Purpose:** CLI tool to run Windows programs with tracing

**Features:**
- Load and execute Windows PE binaries
- Configure tracing options
- Set up environment (registry stubs, etc.)
- Handle program arguments and environment variables

## API Tracing Design

### Tracing Levels

1. **Syscall Level** - Intercept NTDLL native API calls
2. **Win32 API Level** - Hook higher-level APIs (kernel32, user32)
3. **Full IAT Hooking** - Replace import table entries

### Trace Output Format

**Text Format:**
```
[timestamp] [TID:thread_id] CALL   dll!FunctionName(arg1, arg2, ...)
[timestamp] [TID:thread_id] RETURN dll!FunctionName -> return_value
```

**JSON Format:**
```json
{
  "timestamp": "2026-02-07T12:44:58.123Z",
  "thread_id": 1001,
  "event": "call",
  "dll": "kernel32",
  "function": "CreateFileW",
  "args": {"filename": "test.txt", "access": "GENERIC_WRITE"}
}
```

### Configurable Filters
- By DLL name (e.g., "kernel32.dll")
- By function pattern (e.g., "Nt*", "*File*")
- By category (file_io, memory, threading, etc.)

## Implementation Phases

### Phase 1: Foundation & PE Loader (2-3 weeks)

**Tasks:**
- [ ] Create project structure for new crates
- [ ] Implement basic PE parser (headers, sections)
- [ ] Load PE binary into memory
- [ ] Set up initial execution context
- [ ] Handle relocations

**Milestone:** Can load and inspect PE binaries

### Phase 2: Core NTDLL APIs (3-4 weeks)

**Tasks:**
- [ ] Implement file I/O APIs (NtCreateFile, NtReadFile, NtWriteFile, NtClose)
- [ ] Implement console I/O (for "Hello World")
- [ ] Implement memory APIs (NtAllocateVirtualMemory, NtFreeVirtualMemory)
- [ ] Set up syscall dispatch mechanism
- [ ] Handle Windows → Linux path translation

**Milestone:** Can run simple "Hello World" console app

### Phase 3: API Tracing Framework (2 weeks)

**Tasks:**
- [ ] Design tracing hook architecture
- [ ] Implement syscall-level tracing
- [ ] Add text output formatter
- [ ] Add JSON output formatter
- [ ] Implement filtering mechanism
- [ ] Add configuration via CLI flags

**Milestone:** Can trace API calls from simple programs

### Phase 4: Threading & Synchronization (2-3 weeks)

**Tasks:**
- [ ] Implement NtCreateThread
- [ ] Handle thread termination
- [ ] Implement synchronization primitives (events, mutexes)
- [ ] Handle TLS (Thread Local Storage)
- [ ] Support multi-threaded programs

**Milestone:** Can run multi-threaded Windows programs

### Phase 5: Extended API Support (3-4 weeks)

**Tasks:**
- [ ] DLL loading support (LoadLibrary, GetProcAddress)
- [ ] Registry emulation (minimal, for compatibility)
- [ ] Process management APIs
- [ ] Exception handling
- [ ] Environment variables

**Milestone:** Can run moderately complex Windows applications

### Phase 6: Testing & Documentation (2 weeks)

**Tasks:**
- [ ] Write comprehensive test suite
- [ ] Create example programs
- [ ] Write user documentation
- [ ] Write developer documentation
- [ ] Performance benchmarking
- [ ] CI/CD integration

**Milestone:** Production-ready implementation

## Technical Challenges & Solutions

### Challenge 1: Calling Convention Differences
**Problem:** Windows x64 uses Microsoft fastcall, Linux uses System V AMD64 ABI

**Solution:**
- Maintain separate register contexts for Windows and Linux code
- Translate registers on syscall boundary (similar to existing reverse direction)
- Use assembly trampolines for context switching

### Challenge 2: Handle Management
**Problem:** Windows uses opaque handles, Linux uses file descriptors

**Solution:**
- Maintain handle translation table
- Map Windows handles → Linux FDs where applicable
- Implement handle inheritance and duplication

### Challenge 3: Path Translation
**Problem:** Windows uses backslashes and drive letters, Linux uses forward slashes

**Solution:**
- Translate paths at API boundary
- Map Windows paths to Linux filesystem
- Handle special paths (C:\Windows → /opt/litebox/windows, etc.)

### Challenge 4: DLL Dependencies
**Problem:** Windows programs expect DLLs (kernel32.dll, ntdll.dll, etc.)

**Solution:**
- Create stub DLLs with export tables
- Redirect exports to our implementations
- Lazy implementation: add APIs as needed

## Testing Strategy

### Unit Tests
- PE loader with various binary types
- Individual API translations
- Tracing framework components
- Path translation logic

### Integration Tests
```rust
#[test]
fn test_hello_world() {
    let output = run_windows_program("hello.exe");
    assert_eq!(output.stdout, "Hello, World!\n");
}

#[test]
fn test_file_io_with_tracing() {
    let trace = run_with_tracing("fileio.exe", &["--trace-apis"]);
    assert!(trace.contains("NtCreateFile"));
    assert!(trace.contains("NtWriteFile"));
}
```

### Sample Test Programs
1. **hello.exe** - Simple console output
2. **fileio.exe** - File read/write operations
3. **threads.exe** - Multi-threaded program
4. **memory.exe** - VirtualAlloc/VirtualFree
5. **dlls.exe** - LoadLibrary/GetProcAddress

## Minimal API Set for MVP

### Critical NTDLL APIs (Must Have)
- NtCreateFile, NtOpenFile, NtReadFile, NtWriteFile, NtClose
- NtAllocateVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory
- NtCreateThread, NtTerminateThread
- NtWaitForSingleObject, NtCreateEvent, NtSetEvent
- NtQueryInformationFile, NtSetInformationFile

### Important Kernel32 APIs (Should Have)
- CreateFileW/A, ReadFile, WriteFile, CloseHandle
- GetStdHandle, WriteConsoleW/A
- VirtualAlloc, VirtualFree, VirtualProtect
- CreateThread, ExitThread
- WaitForSingleObject, CreateEventW/A, SetEvent
- GetLastError, SetLastError

### Nice-to-Have APIs (for Extended Compatibility)
- LoadLibraryW/A, GetProcAddress, FreeLibrary
- RegOpenKeyExW/A, RegQueryValueExW/A, RegCloseKey
- CreateProcessW/A, TerminateProcess
- GetEnvironmentVariableW/A, SetEnvironmentVariableW/A

## Success Criteria

### Functional Requirements
✅ Run simple Windows console applications (hello world, basic I/O)
✅ Support file operations with path translation
✅ Handle multi-threaded programs
✅ Trace all API calls with configurable filtering
✅ Support basic DLL loading

### Non-Functional Requirements
✅ Performance overhead < 50% vs Wine (when tracing disabled)
✅ Tracing overhead < 20% (when enabled)
✅ Code passes all clippy lints and cargo fmt
✅ Comprehensive documentation
✅ Test coverage > 70%

## Future Enhancements

1. **GUI Support** - user32, gdi32 APIs for windowed applications
2. **Network APIs** - ws2_32 (Winsock) implementation
3. **Wine Interoperability** - Use Wine libraries as fallback for unimplemented APIs
4. **Advanced Tracing** - Call stacks, memory access tracking, performance profiling
5. **Security Features** - Sandboxing, permission controls

## References

- Wine Architecture: https://wiki.winehq.org/Wine_Developer%27s_Guide
- PE Format: Microsoft PE/COFF Specification
- Windows Internals: Russinovich, Solomon, Ionescu
- NTDLL Documentation: Windows NT Native API Reference
- Existing LiteBox code: litebox_runner_linux_on_windows_userland

## Appendix: Project Structure

```
litebox/
├── litebox_shim_windows/                    # NEW
│   ├── Cargo.toml
│   ├── README.md
│   ├── src/
│   │   ├── lib.rs
│   │   ├── loader/
│   │   │   ├── mod.rs
│   │   │   ├── pe.rs                        # PE loader
│   │   │   └── dll.rs                       # DLL handling
│   │   ├── syscalls/
│   │   │   ├── mod.rs
│   │   │   ├── ntdll.rs                     # NTDLL syscalls
│   │   │   ├── kernel32.rs                  # Kernel32 APIs
│   │   │   └── dispatch.rs                  # Syscall dispatcher
│   │   └── tracing/
│   │       ├── mod.rs
│   │       ├── hooks.rs                     # IAT hooking
│   │       ├── filters.rs                   # Trace filters
│   │       └── formatters.rs                # Output formats
│   └── tests/
│       └── pe_loader_tests.rs
│
├── litebox_platform_linux_for_windows/      # NEW
│   ├── Cargo.toml
│   ├── README.md
│   ├── src/
│   │   ├── lib.rs
│   │   ├── file_io.rs                       # File operations
│   │   ├── memory.rs                        # Memory management
│   │   ├── threading.rs                     # Thread support
│   │   ├── sync.rs                          # Synchronization primitives
│   │   ├── objects.rs                       # Object manager emulation
│   │   ├── registry.rs                      # Registry emulation
│   │   └── path.rs                          # Path translation
│   └── tests/
│       └── api_translation_tests.rs
│
└── litebox_runner_windows_on_linux_userland/  # NEW
    ├── Cargo.toml
    ├── README.md
    ├── src/
    │   ├── main.rs                          # CLI entry point
    │   └── lib.rs                           # Core runner logic
    ├── tests/
    │   ├── integration/
    │   │   ├── hello_world.rs
    │   │   ├── file_io.rs
    │   │   └── threading.rs
    │   └── fixtures/                        # Test PE binaries
    │       ├── hello.exe
    │       └── fileio.exe
    └── examples/
        └── run_with_tracing.rs
```
