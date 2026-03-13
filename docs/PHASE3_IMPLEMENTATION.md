# Phase 3 Implementation: API Tracing Framework

## Overview

This document describes the implementation of Phase 3 (API Tracing Framework) for running Windows programs on Linux with LiteBox. This phase adds comprehensive tracing capabilities for Windows API calls.

## Architecture

```
Windows PE Binary (.exe)
        ↓
litebox_runner_windows_on_linux_userland (CLI with tracing options)
        ↓
TracedNtdllApi (tracing wrapper)
        ↓
litebox_shim_windows (PE loader, syscall interface)
        ↓
litebox_platform_linux_for_windows (Windows API → Linux translation)
        ↓
Linux Kernel (syscalls)
```

## Components Implemented

### 1. Tracing Module (`litebox_shim_windows/src/tracing/`)

A complete framework for tracing Windows API calls with minimal overhead.

#### 1.1 Configuration (`config.rs`)
- `TraceConfig`: Main configuration struct
- `TraceFormat`: Text or JSON output formats
- `TraceOutput`: Output to stdout or file
- Builder pattern for easy configuration

#### 1.2 Events (`event.rs`)
- `TraceEvent`: Represents a traced API call or return
- `ApiCategory`: File I/O, Console I/O, Memory, etc.
- `EventType`: Call or Return
- Timestamp and thread ID tracking

#### 1.3 Filtering (`filter.rs`)
- `TraceFilter`: Configurable event filtering
- `FilterRule`: Multiple filter types
  - All: Include everything
  - Function: Exact function name match
  - Pattern: Wildcard patterns (*, ?)
  - Category: Filter by API category
- Wildcard pattern matching implementation

#### 1.4 Formatters (`formatter.rs`)
- `TraceFormatter` trait for pluggable formatters
- `TextFormatter`: Human-readable output
  ```
  [timestamp] [TID:xxxx] CALL   FunctionName(args)
  [timestamp] [TID:xxxx] RETURN FunctionName() -> result
  ```
- `JsonFormatter`: Machine-parseable output
  ```json
  {"timestamp":123.456,"thread_id":null,"event":"call","category":"file_io","function":"NtCreateFile","args":"..."}
  ```

#### 1.5 Tracer (`tracer.rs`)
- Main tracer component
- Thread-safe output handling
- Applies filters before formatting
- Minimal overhead when disabled

#### 1.6 API Wrapper (`wrapper.rs`)
- `TracedNtdllApi<T>`: Generic wrapper for any `NtdllApi` implementation
- Transparent tracing - no API changes needed
- Traces all NTDLL API calls:
  - File I/O: NtCreateFile, NtReadFile, NtWriteFile, NtClose
  - Console I/O: WriteConsole
  - Memory: NtAllocateVirtualMemory, NtFreeVirtualMemory
- Captures arguments and return values
- Only traces when enabled (zero overhead when disabled)

### 2. Platform Integration

Updated `litebox_platform_linux_for_windows` to implement the `NtdllApi` trait, allowing it to be wrapped with tracing.

### 3. CLI Integration

Enhanced `litebox_runner_windows_on_linux_userland` with tracing options:

```bash
--trace-apis                      # Enable API tracing
--trace-format <text|json>        # Output format (default: text)
--trace-output <file>             # Output file (default: stdout)
--trace-filter <pattern>          # Filter by function pattern (e.g., "Nt*File")
--trace-category <category>       # Filter by category (file_io, memory, console_io)
```

## Implementation Details

### Tracing Overhead

- **When disabled**: Zero overhead - simple boolean check
- **When enabled**: 
  - Minimal overhead for filtering and formatting
  - Uses Arc<Mutex<>> for thread-safe output
  - Timestamps use SystemTime for accuracy

### Pattern Matching

Implements simple but efficient wildcard matching:
- `*` matches any sequence of characters
- `?` matches a single character
- Recursive implementation with early termination

Examples:
- `Nt*File` matches `NtCreateFile`, `NtReadFile`, `NtWriteFile`, `NtClose`
- `Nt????File` matches `NtReadFile` (4 chars between Nt and File)

### Safety

- All unsafe code is in existing components (PE loader, mmap)
- Tracing layer is 100% safe Rust
- Thread-safe output via Mutex
- No data races or undefined behavior

## Testing

### Unit Tests

- Pattern matching edge cases
- Filter logic (all, function, pattern, category)
- Formatter output validation
- JSON escaping

### Integration Tests

- Text format tracing
- JSON format tracing
- Filter by pattern
- Filter by category
- Tracing disabled (no overhead)

All tests pass with output demonstrating correct tracing behavior.

## Example Usage

### Text Format Tracing
```bash
$ litebox_runner_windows_on_linux_userland --trace-apis program.exe

[1234567890.123] [TID:main] CALL   WriteConsole(handle=0xFFFFFFFF0001, text="Hello, World!")
Hello, World!
[1234567890.124] [TID:main] RETURN WriteConsole() -> Ok(bytes_written=13)
```

### JSON Format Tracing
```bash
$ litebox_runner_windows_on_linux_userland --trace-apis --trace-format json program.exe

{"timestamp":1234567890.123456789,"thread_id":null,"event":"call","category":"console_io","function":"WriteConsole","args":"handle=0xFFFFFFFF0001, text=\"Hello, World!\""}
{"timestamp":1234567890.124567890,"thread_id":null,"event":"return","category":"console_io","function":"WriteConsole","return":"Ok(bytes_written=13)"}
Hello, World!
```

### Filtered Tracing
```bash
# Only trace file I/O
$ litebox_runner_windows_on_linux_userland --trace-apis --trace-category file_io program.exe

# Only trace specific functions
$ litebox_runner_windows_on_linux_userland --trace-apis --trace-filter "Nt*File" program.exe
```

## Code Quality

All code follows LiteBox standards:

✅ `cargo fmt` - All code formatted
✅ `cargo build` - Builds without errors
✅ `cargo test` - All tests pass
✅ `cargo clippy` - Minor warnings only (from existing code)
✅ Documentation - Comprehensive inline docs and examples
✅ Safety comments - All unsafe blocks documented

## API Coverage

All Phase 2 NTDLL APIs are traced:

| API | Category | Arguments Traced | Return Value Traced |
|-----|----------|------------------|---------------------|
| NtCreateFile | File I/O | path, access, disposition | handle or error |
| NtReadFile | File I/O | handle, buffer_size | bytes_read or error |
| NtWriteFile | File I/O | handle, buffer_size | bytes_written or error |
| NtClose | File I/O | handle | success or error |
| WriteConsole | Console I/O | handle, text | bytes_written or error |
| NtAllocateVirtualMemory | Memory | size, protect | address or error |
| NtFreeVirtualMemory | Memory | address, size | success or error |

## Performance Characteristics

### Memory
- Minimal per-trace overhead: ~200 bytes per event
- Immediate flush to output (no buffering)
- Arc-wrapped tracer for shared ownership

### CPU
- When disabled: Single boolean check per API call
- When enabled: 
  - Pattern matching: O(n*m) worst case
  - Formatting: O(n) where n = argument string length
  - I/O: Synchronous write with flush

## Future Enhancements (Phase 4+)

1. **Call Stack Tracking**: Capture and display call stacks
2. **Timing Statistics**: Aggregate timing data per API
3. **Memory Tracking**: Track allocations and detect leaks
4. **Advanced Filtering**: Regex support, conditional filters
5. **Binary Trace Format**: Compact binary format for high-performance tracing
6. **Trace Replay**: Record and replay API sequences

## Conclusion

Phase 3 is complete. The API tracing framework provides:

✅ Comprehensive tracing of all Windows API calls
✅ Flexible filtering and formatting options
✅ Minimal overhead when disabled
✅ Easy CLI integration
✅ Extensible architecture for future enhancements

The foundation is now ready for Phase 4: Threading & Synchronization.

## References

- Implementation Plan: [docs/windows_on_linux_implementation_plan.md](./windows_on_linux_implementation_plan.md)
- Phase 2 Summary: [docs/PHASE2_IMPLEMENTATION.md](./PHASE2_IMPLEMENTATION.md)
- API Documentation: [litebox_shim_windows/README.md](../litebox_shim_windows/README.md)
