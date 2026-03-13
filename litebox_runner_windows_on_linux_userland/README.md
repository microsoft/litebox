# litebox_runner_windows_on_linux_userland

CLI runner for executing Windows programs on Linux.

## Overview

This is the main executable that combines the Windows shim and Linux platform layers to run Windows PE binaries on Linux.

## Usage

```bash
# Run a Windows executable on Linux
litebox_runner_windows_on_linux_userland program.exe [args...]

# Run with API tracing enabled (text format to stdout)
litebox_runner_windows_on_linux_userland --trace-apis program.exe

# Run with API tracing in JSON format
litebox_runner_windows_on_linux_userland --trace-apis --trace-format json program.exe

# Run with tracing to a file
litebox_runner_windows_on_linux_userland --trace-apis --trace-output trace.log program.exe

# Run with filtered tracing (only trace file I/O operations)
litebox_runner_windows_on_linux_userland --trace-apis --trace-category file_io program.exe

# Run with pattern-based filtering (only trace functions matching pattern)
litebox_runner_windows_on_linux_userland --trace-apis --trace-filter "Nt*File" program.exe
```

## CLI Options

- `--trace-apis`: Enable API call tracing
- `--trace-format <text|json>`: Output format (default: text)
- `--trace-output <file>`: Output file (default: stdout)
- `--trace-filter <pattern>`: Filter by function pattern (e.g., "Nt*File")
- `--trace-category <category>`: Filter by category (file_io, console_io, memory)

## Current Status

### Phase 1: Foundation ✅
- PE binary loading and parsing
- Section enumeration and metadata extraction

### Phase 2: Core APIs ✅
- File I/O APIs (NtCreateFile, NtReadFile, NtWriteFile, NtClose)
- Console I/O (WriteConsole)
- Memory management APIs (NtAllocateVirtualMemory, NtFreeVirtualMemory)
- Path translation (Windows → Linux paths)
- Trait-based integration between shim and platform layers

### Phase 3: API Tracing ✅
- API call tracing framework
- Multiple output formats (text, JSON)
- Configurable filtering (by pattern, category)
- CLI integration with tracing options
- Zero-overhead when disabled

### What Works
- Loading Windows PE executables
- Parsing PE headers and sections
- Allocating memory for the PE image
- Loading sections into memory
- Basic console output through platform API
- Memory management (allocation and deallocation)
- **API call tracing with flexible filtering and formatting**

### What's Next (Phase 4+)
- Actual program execution (calling entry point)
- Threading support
- DLL loading and import resolution
- Exception handling

## Example Output

### Without Tracing
```bash
litebox_runner_windows_on_linux_userland hello.exe

# Output:
# Loaded PE binary: hello.exe
#   Entry point: 0x1400
#   Image base: 0x140000000
#   Sections: 4
# 
# Sections:
#   .text - VA: 0x1000, Size: 8192 bytes, Characteristics: 0x60000020
#   .data - VA: 0x3000, Size: 4096 bytes, Characteristics: 0xC0000040
#   .rdata - VA: 0x4000, Size: 2048 bytes, Characteristics: 0x40000040
#   .pdata - VA: 0x5000, Size: 512 bytes, Characteristics: 0x40000040
# 
# Allocating memory for PE image:
#   Image size: 20480 bytes (20 KB)
#   Allocated at: 0x7F1234567000
# 
# Loading sections into memory...
#   Loaded 14848 bytes
# 
# Hello from Windows on Linux!
# 
# Memory deallocated successfully.
```

### With Tracing Enabled (Text Format)
```bash
litebox_runner_windows_on_linux_userland --trace-apis hello.exe

# Output includes API traces:
# [timestamp] [TID:main] CALL   NtAllocateVirtualMemory(size=20480, protect=0x40)
# [timestamp] [TID:main] RETURN NtAllocateVirtualMemory() -> Ok(address=0x7F1234567000)
# [timestamp] [TID:main] CALL   WriteConsole(handle=0xFFFFFFFF0001, text="Hello from Windows on Linux!\n")
# Hello from Windows on Linux!
# [timestamp] [TID:main] RETURN WriteConsole() -> Ok(bytes_written=29)
# [timestamp] [TID:main] CALL   NtFreeVirtualMemory(address=0x7F1234567000, size=20480)
# [timestamp] [TID:main] RETURN NtFreeVirtualMemory() -> Ok(())
```

### With JSON Tracing
```bash
litebox_runner_windows_on_linux_userland --trace-apis --trace-format json hello.exe

# Output includes JSON-formatted traces:
# {"timestamp":1234567890.123,"thread_id":null,"event":"call","category":"memory","function":"NtAllocateVirtualMemory","args":"size=20480, protect=0x40"}
# {"timestamp":1234567890.124,"thread_id":null,"event":"return","category":"memory","function":"NtAllocateVirtualMemory","return":"Ok(address=0x7F1234567000)"}
```
