# litebox_shim_windows

Windows shim layer for running Windows PE binaries on Linux.

## Overview

This crate provides the "North" interface for Windows programs, implementing:

- **PE Loader**: Parses and loads Windows PE (Portable Executable) binaries
- **Section Loading**: Maps PE sections into memory
- **NTDLL Interface**: Defines Windows NTDLL syscall APIs
- **API Tracing**: (Planned) Hooks for tracing Windows API calls

## Implementation Status

### Phase 1: Foundation & PE Loader ✅

- ✅ PE header parsing (DOS, NT, Optional headers)
- ✅ Basic validation (signature, machine type)
- ✅ Extract entry point and image base
- ✅ Section enumeration and metadata
- ✅ Section loading into allocated memory

### Phase 2: Core NTDLL APIs ✅

- ✅ File I/O API definitions (NtCreateFile, NtReadFile, NtWriteFile, NtClose)
- ✅ Console I/O APIs
- ✅ Memory management APIs (NtAllocateVirtualMemory, NtFreeVirtualMemory)
- ✅ `NtdllApi` trait for platform implementations

## Usage

This is a library crate used by `litebox_runner_windows_on_linux_userland`.

```rust
use litebox_shim_windows::loader::PeLoader;
use litebox_shim_windows::syscalls::ntdll::memory_protection;

// Load PE binary
let pe_data = std::fs::read("program.exe")?;
let loader = PeLoader::new(pe_data)?;
println!("Entry point: 0x{:X}", loader.entry_point());

// Get section information
let sections = loader.sections()?;
for section in sections {
    println!("Section: {} @ 0x{:X}", section.name, section.virtual_address);
}

// Load sections into memory (requires allocated memory)
unsafe {
    let size = loader.load_sections(base_address)?;
    println!("Loaded {} bytes", size);
}
```
