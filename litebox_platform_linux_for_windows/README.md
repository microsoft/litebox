# litebox_platform_linux_for_windows

Linux platform implementation for Windows APIs.

## Overview

This crate provides the "South" platform layer that implements Windows NTDLL APIs using Linux syscalls. It enables running Windows programs on Linux by translating Windows API calls to equivalent Linux operations.

## Implementation Status

### Phase 2: Core NTDLL API Implementation ✅

- ✅ File I/O: NtCreateFile → open(), NtReadFile → read(), NtWriteFile → write(), NtClose → close()
- ✅ Console I/O: WriteConsole → stdout
- ✅ Memory Management: NtAllocateVirtualMemory → mmap(), NtFreeVirtualMemory → munmap()
- ✅ Path Translation: Windows paths (C:\path) → Linux paths (/path)
- ✅ Handle Management: Windows handles → Linux file descriptors
- ✅ `NtdllApi` trait implementation for shim integration

### Phase 4: Threading & Synchronization ✅

- ✅ Thread Creation: NtCreateThread → std::thread::spawn()
- ✅ Thread Management: NtTerminateThread, NtWaitForSingleObject
- ✅ Event Synchronization: NtCreateEvent, NtSetEvent, NtResetEvent, NtWaitForEvent
- ✅ Handle Cleanup: NtCloseHandle for threads and events
- ✅ Thread-Safe Implementation: Mutex-protected state, atomic handle allocation
- ✅ Manual and auto-reset events with proper timeout handling

## Architecture

```
Windows API Call (NtCreateFile/NtCreateThread)
    ↓
litebox_shim_windows::NtdllApi trait
    ↓
litebox_platform_linux_for_windows (translation)
    ↓
Linux Syscall (open/thread::spawn)
```

### Thread Safety

The platform implementation is fully thread-safe:
- **AtomicU64** for lock-free handle generation
- **Mutex<PlatformState>** protects shared maps
- **Arc cloning** for safe concurrent access to event state

## Usage

### File I/O

```rust
use litebox_platform_linux_for_windows::LinuxPlatformForWindows;
use litebox_shim_windows::syscalls::ntdll::NtdllApi;

let mut platform = LinuxPlatformForWindows::new();

// Create and write to a file
let handle = platform.nt_create_file("/tmp/test.txt", GENERIC_WRITE, CREATE_ALWAYS)?;
platform.nt_write_file(handle, b"Hello")?;
platform.nt_close(handle)?;
```

### Memory Management

```rust
// Allocate virtual memory
let addr = platform.nt_allocate_virtual_memory(4096, PAGE_READWRITE)?;
// Use the memory...
platform.nt_free_virtual_memory(addr, 4096)?;
```

### Threading

```rust
// Thread entry point
extern "C" fn thread_func(param: *mut core::ffi::c_void) -> u32 {
    // Do work...
    0  // Exit code
}

// Create and wait for thread
let thread = platform.nt_create_thread(thread_func, std::ptr::null_mut(), 1024 * 1024)?;
let result = platform.nt_wait_for_single_object(thread, u32::MAX)?;  // Infinite wait
platform.nt_close_handle(thread.0)?;
```

### Event Synchronization

```rust
// Create a manual-reset event
let event = platform.nt_create_event(true, false)?;  // manual_reset=true, initial_state=false

// Signal the event
platform.nt_set_event(event)?;

// Wait for event (5 second timeout)
let result = platform.nt_wait_for_event(event, 5000)?;
if result == 0 {
    println!("Event was signaled!");
} else {
    println!("Timeout!");
}

// Reset the event
platform.nt_reset_event(event)?;

// Clean up
platform.nt_close_handle(event.0)?;
```

## Testing

Run tests with:
```bash
cargo test -p litebox_platform_linux_for_windows
```

All 8 unit tests pass, covering:
- Thread creation and parameter passing
- Event synchronization (manual and auto-reset)
- Handle allocation and cleanup
- Path translation

