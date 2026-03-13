// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Standalone NTDLL function implementations
//!
//! These are `extern "C"` functions (System V AMD64 ABI on Linux) that receive
//! parameters already translated from Windows x64 by the trampoline layer.
//!
//! The trampoline maps Windows calling convention to System V:
//!   - Windows RCX/RDX/R8/R9 → Linux RDI/RSI/RDX/RCX (params 1-4)
//!   - Windows stack params 5-6 → Linux R8/R9 (params 5-6)
//!   - Windows stack params 7+  → Linux stack [RSP+8], [RSP+16], ... (params 7+)

// Allow unsafe operations inside unsafe functions since the entire function is unsafe
#![allow(unsafe_op_in_unsafe_fn)]
// Windows API uses specific integer widths
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

/// NTSTATUS codes
mod status {
    /// Operation completed successfully.
    pub const STATUS_SUCCESS: u32 = 0x0000_0000;
    /// The request is not supported.
    pub const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
    /// An invalid HANDLE was specified.
    pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    /// An invalid parameter was passed to a service or function.
    pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    /// The end-of-file marker has been reached. No further reads can be done.
    pub const STATUS_END_OF_FILE: u32 = 0xC000_0011;
    /// An I/O error occurred on the device.
    pub const STATUS_IO_DEVICE_ERROR: u32 = 0xC000_0185;
}

/// Windows handle values for standard I/O (as returned by GetStdHandle in kernel32.rs).
/// kernel32_GetStdHandle(-11) returns 0x11, (-12) returns 0x12, (-10) returns 0x10.
const STDIN_HANDLE: u64 = 0x10;
const STDOUT_HANDLE: u64 = 0x11;
const STDERR_HANDLE: u64 = 0x12;

/// IO_STATUS_BLOCK layout (two consecutive u64 fields):
///   \[0\] = Status  (u64 to match alignment)
///   \[1\] = Information (bytes transferred)
unsafe fn set_io_status(io_sb: *mut u64, status: u32, information: u64) {
    if !io_sb.is_null() {
        *io_sb = u64::from(status);
        *io_sb.add(1) = information;
    }
}

/// Map a Windows standard-device handle to a Linux file descriptor.
/// Returns `None` for unrecognised handles.
fn std_handle_to_fd(handle: u64) -> Option<i32> {
    match handle {
        STDIN_HANDLE => Some(0),
        STDOUT_HANDLE => Some(1),
        STDERR_HANDLE => Some(2),
        _ => None,
    }
}

/// NtWriteFile — write data to a file or device
///
/// Handles the standard console handles (stdin, stdout, stderr) via direct
/// `libc::write` calls, and regular file handles opened by `kernel32_CreateFileW`
/// via the kernel32 file-handle registry.
///
/// Windows prototype (9 params, params 7-9 arrive on the Linux stack):
/// ```c
/// NTSTATUS NtWriteFile(
///     HANDLE FileHandle,          // param 1 → RDI
///     HANDLE Event,               // param 2 → RSI  (ignored)
///     PIO_APC_ROUTINE ApcRoutine, // param 3 → RDX  (ignored)
///     PVOID ApcContext,           // param 4 → RCX  (ignored)
///     PIO_STATUS_BLOCK IoStatusBlock, // param 5 → R8
///     PVOID Buffer,               // param 6 → R9
///     ULONG Length,               // param 7 → [RSP+8] at function entry
///     PLARGE_INTEGER ByteOffset,  // param 8 → [RSP+16]  (ignored)
///     PULONG Key                  // param 9 → [RSP+24]  (ignored)
/// );
/// ```
///
/// # Safety
/// Caller must ensure `buffer` is valid for `length` bytes and `io_status_block`
/// (if non-null) is valid for two consecutive `u64` writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntdll_NtWriteFile(
    file_handle: u64,
    _event: u64,
    _apc_routine: u64,
    _apc_context: u64,
    io_status_block: *mut u64,
    buffer: *const u8,
    length: u32,
    _byte_offset: u64,
    _key: u64,
) -> u32 {
    if buffer.is_null() || length == 0 {
        set_io_status(io_status_block, status::STATUS_SUCCESS, 0);
        return status::STATUS_SUCCESS;
    }

    // SAFETY: Caller guarantees buffer is valid for length bytes.
    let data = core::slice::from_raw_parts(buffer, length as usize);

    // First try standard console handles (stdin=0x10, stdout=0x11, stderr=0x12)
    if let Some(fd) = std_handle_to_fd(file_handle) {
        let written = libc::write(fd, buffer.cast::<libc::c_void>(), length as libc::size_t);
        if written < 0 {
            set_io_status(io_status_block, status::STATUS_IO_DEVICE_ERROR, 0);
            return status::STATUS_IO_DEVICE_ERROR;
        }
        set_io_status(io_status_block, status::STATUS_SUCCESS, written as u64);
        return status::STATUS_SUCCESS;
    }

    // Fall back to the kernel32 CreateFileW handle registry
    if let Some(written) = crate::kernel32::nt_write_file_handle(file_handle, data) {
        set_io_status(io_status_block, status::STATUS_SUCCESS, written as u64);
        return status::STATUS_SUCCESS;
    }

    set_io_status(io_status_block, status::STATUS_INVALID_HANDLE, 0);
    status::STATUS_INVALID_HANDLE
}

/// NtReadFile — read data from a file or device
///
/// Handles the standard console handles and regular file handles opened by
/// `kernel32_CreateFileW` via the kernel32 file-handle registry.
///
/// Windows prototype (9 params, params 7-9 arrive on the Linux stack):
/// ```c
/// NTSTATUS NtReadFile(
///     HANDLE FileHandle,          // param 1 → RDI
///     HANDLE Event,               // param 2 → RSI  (ignored)
///     PIO_APC_ROUTINE ApcRoutine, // param 3 → RDX  (ignored)
///     PVOID ApcContext,           // param 4 → RCX  (ignored)
///     PIO_STATUS_BLOCK IoStatusBlock, // param 5 → R8
///     PVOID Buffer,               // param 6 → R9
///     ULONG Length,               // param 7 → [RSP+8]
///     PLARGE_INTEGER ByteOffset,  // param 8 → [RSP+16]  (ignored)
///     PULONG Key                  // param 9 → [RSP+24]  (ignored)
/// );
/// ```
///
/// # Safety
/// Caller must ensure `buffer` is valid for `length` bytes and `io_status_block`
/// (if non-null) is valid for two consecutive `u64` writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntdll_NtReadFile(
    file_handle: u64,
    _event: u64,
    _apc_routine: u64,
    _apc_context: u64,
    io_status_block: *mut u64,
    buffer: *mut u8,
    length: u32,
    _byte_offset: u64,
    _key: u64,
) -> u32 {
    if buffer.is_null() || length == 0 {
        set_io_status(io_status_block, status::STATUS_SUCCESS, 0);
        return status::STATUS_SUCCESS;
    }

    // First try standard console handles
    if let Some(fd) = std_handle_to_fd(file_handle) {
        // SAFETY: Caller guarantees buffer is valid for length bytes.
        let nread = libc::read(fd, buffer.cast::<libc::c_void>(), length as libc::size_t);
        if nread == 0 {
            set_io_status(io_status_block, status::STATUS_END_OF_FILE, 0);
            return status::STATUS_END_OF_FILE;
        }
        if nread < 0 {
            set_io_status(io_status_block, status::STATUS_IO_DEVICE_ERROR, 0);
            return status::STATUS_IO_DEVICE_ERROR;
        }
        set_io_status(io_status_block, status::STATUS_SUCCESS, nread as u64);
        return status::STATUS_SUCCESS;
    }

    // Fall back to the kernel32 CreateFileW handle registry
    // SAFETY: Caller guarantees buffer is valid for length bytes.
    let buf = core::slice::from_raw_parts_mut(buffer, length as usize);
    match crate::kernel32::nt_read_file_handle(file_handle, buf) {
        Some(0) => {
            set_io_status(io_status_block, status::STATUS_END_OF_FILE, 0);
            status::STATUS_END_OF_FILE
        }
        Some(n) => {
            set_io_status(io_status_block, status::STATUS_SUCCESS, n as u64);
            status::STATUS_SUCCESS
        }
        None => {
            set_io_status(io_status_block, status::STATUS_INVALID_HANDLE, 0);
            status::STATUS_INVALID_HANDLE
        }
    }
}

/// NtCreateFile — create or open a file or device object (stub)
///
/// This stub returns STATUS_NOT_IMPLEMENTED. Real file creation would require
/// path translation and a handle table.
///
/// Windows prototype has 11 parameters (params 7-11 arrive on the Linux stack).
///
/// # Safety
/// This function does not dereference any pointers (it is a stub).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntdll_NtCreateFile(
    _file_handle: *mut u64,
    _desired_access: u32,
    _object_attributes: u64,
    _io_status_block: u64,
    _allocation_size: u64,
    _file_attributes: u32,
    _share_access: u32,
    _create_disposition: u32,
    _create_options: u32,
    _ea_buffer: u64,
    _ea_length: u32,
) -> u32 {
    // Stub – full file creation not yet implemented
    status::STATUS_NOT_IMPLEMENTED
}

/// NtOpenFile — open an existing file or device object (stub)
///
/// This stub returns STATUS_NOT_IMPLEMENTED.
///
/// Windows prototype (6 params, all in registers after trampoline translation).
///
/// # Safety
/// This function does not dereference any pointers (it is a stub).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntdll_NtOpenFile(
    _file_handle: *mut u64,
    _desired_access: u32,
    _object_attributes: u64,
    _io_status_block: u64,
    _share_access: u32,
    _open_options: u32,
) -> u32 {
    status::STATUS_NOT_IMPLEMENTED
}

/// NtClose — close an object handle
///
/// Delegates to `kernel32_CloseHandle` to release the handle from the shared
/// kernel32 handle tables (file handles, event handles, etc.).
/// Always returns `STATUS_SUCCESS` regardless of whether the handle was known,
/// matching Windows behaviour for best-effort close.
///
/// # Safety
/// `handle` must be a valid handle value or a value that was previously
/// returned by one of the kernel32 handle-creating functions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntdll_NtClose(handle: u64) -> u32 {
    crate::kernel32::kernel32_CloseHandle(handle as usize as *mut core::ffi::c_void);
    status::STATUS_SUCCESS
}

/// NtAllocateVirtualMemory — allocate virtual memory in a process
///
/// Simplified implementation: ignores ProcessHandle (assumes current process),
/// ZeroBits, and calls mmap directly.
///
/// Windows prototype (6 params, all in registers after trampoline):
/// ```c
/// NTSTATUS NtAllocateVirtualMemory(
///     HANDLE  ProcessHandle,      // param 1 → RDI (ignored)
///     PVOID*  BaseAddress,        // param 2 → RSI (in/out: desired/actual address)
///     ULONG_PTR ZeroBits,         // param 3 → RDX (ignored)
///     PSIZE_T RegionSize,         // param 4 → RCX (in/out)
///     ULONG   AllocationType,     // param 5 → R8
///     ULONG   Protect             // param 6 → R9
/// );
/// ```
///
/// # Safety
/// Caller must ensure `base_address` and `region_size` are valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntdll_NtAllocateVirtualMemory(
    _process_handle: u64,
    base_address: *mut *mut u8,
    _zero_bits: u64,
    region_size: *mut usize,
    _allocation_type: u32,
    protect: u32,
) -> u32 {
    if base_address.is_null() || region_size.is_null() {
        return status::STATUS_INVALID_PARAMETER;
    }

    let size = *region_size;
    if size == 0 {
        return status::STATUS_INVALID_PARAMETER;
    }

    // Map Windows page-protection flags to POSIX prot flags (simplified)
    let prot = win_protect_to_prot(protect);

    let hint = *base_address;
    let ptr = libc::mmap(
        hint.cast::<libc::c_void>(),
        size,
        prot,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr == libc::MAP_FAILED {
        return status::STATUS_IO_DEVICE_ERROR;
    }

    *base_address = ptr.cast::<u8>();
    *region_size = size;
    status::STATUS_SUCCESS
}

/// NtFreeVirtualMemory — release or decommit virtual memory in a process
///
/// Windows prototype (4 params, all in registers):
/// ```c
/// NTSTATUS NtFreeVirtualMemory(
///     HANDLE  ProcessHandle,      // param 1 → RDI (ignored)
///     PVOID*  BaseAddress,        // param 2 → RSI
///     PSIZE_T RegionSize,         // param 3 → RDX
///     ULONG   FreeType            // param 4 → RCX
/// );
/// ```
///
/// # Safety
/// Caller must ensure `base_address` and `region_size` are valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntdll_NtFreeVirtualMemory(
    _process_handle: u64,
    base_address: *mut *mut u8,
    region_size: *mut usize,
    _free_type: u32,
) -> u32 {
    if base_address.is_null() {
        return status::STATUS_INVALID_PARAMETER;
    }

    let ptr = *base_address;
    let size = if region_size.is_null() {
        0
    } else {
        *region_size
    };

    if ptr.is_null() {
        return status::STATUS_INVALID_PARAMETER;
    }

    let ret = libc::munmap(ptr.cast::<libc::c_void>(), size);
    if ret != 0 {
        return status::STATUS_IO_DEVICE_ERROR;
    }

    status::STATUS_SUCCESS
}

/// NtCreateNamedPipeFile — create a named pipe (stub)
///
/// This stub returns STATUS_NOT_IMPLEMENTED.
///
/// # Safety
/// This function does not dereference any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntdll_NtCreateNamedPipeFile(
    _file_handle: *mut u64,
    _desired_access: u32,
    _object_attributes: u64,
    _io_status_block: u64,
    _share_access: u32,
    _create_disposition: u32,
    _create_options: u32,
    _named_pipe_type: u32,
    _read_mode: u32,
    _completion_mode: u32,
    _maximum_instances: u32,
    _inbound_quota: u32,
    _outbound_quota: u32,
    _default_timeout: u64,
) -> u32 {
    status::STATUS_NOT_IMPLEMENTED
}

/// RtlNtStatusToDosError — convert an NTSTATUS code to a Win32 error code
///
/// Provides a minimal mapping for the most common status codes.
///
/// # Safety
/// This function is pure (no side effects, no pointer dereference).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntdll_RtlNtStatusToDosError(ntstatus: u32) -> u32 {
    match ntstatus {
        0x0000_0000 => 0,  // STATUS_SUCCESS → ERROR_SUCCESS
        0xC000_0002 => 50, // STATUS_NOT_IMPLEMENTED → ERROR_NOT_SUPPORTED
        0xC000_0005 => 5,  // STATUS_ACCESS_DENIED → ERROR_ACCESS_DENIED
        0xC000_0008 => 6,  // STATUS_INVALID_HANDLE → ERROR_INVALID_HANDLE
        0xC000_000D => 87, // STATUS_INVALID_PARAMETER → ERROR_INVALID_PARAMETER
        0xC000_0011 => 38, // STATUS_END_OF_FILE → ERROR_HANDLE_EOF
        0xC000_0034 => 2,  // STATUS_OBJECT_NAME_NOT_FOUND → ERROR_FILE_NOT_FOUND
        0xC000_0040 => 33, // STATUS_SHARING_VIOLATION → ERROR_SHARING_VIOLATION
        _ => {
            // Generic mapping: high 2 bits indicate severity, extract a rough Win32 code.
            let facility = (ntstatus >> 16) & 0x0FFF;
            let code = ntstatus & 0xFFFF;
            if facility == 0 {
                code
            } else {
                // Unknown NT error; return a generic "operation failed" code.
                317 // ERROR_MR_MID_NOT_FOUND
            }
        }
    }
}

/// Convert a Windows PAGE_* protection constant to POSIX PROT_* flags.
fn win_protect_to_prot(protect: u32) -> i32 {
    match protect & 0xFF {
        0x01 => libc::PROT_NONE,
        0x02 => libc::PROT_READ,
        0x04 | 0x08 => libc::PROT_READ | libc::PROT_WRITE, // PAGE_READWRITE / PAGE_WRITECOPY
        0x10 | 0x20 => libc::PROT_READ | libc::PROT_EXEC,  // PAGE_EXECUTE / PAGE_EXECUTE_READ
        _ => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rlt_ntstatus_to_dos_success() {
        unsafe {
            assert_eq!(ntdll_RtlNtStatusToDosError(0), 0);
        }
    }

    #[test]
    fn test_rlt_ntstatus_to_dos_invalid_handle() {
        unsafe {
            // STATUS_INVALID_HANDLE (0xC0000008) → ERROR_INVALID_HANDLE (6)
            assert_eq!(ntdll_RtlNtStatusToDosError(0xC000_0008), 6);
        }
    }

    #[test]
    fn test_rlt_ntstatus_to_dos_not_implemented() {
        unsafe {
            // STATUS_NOT_IMPLEMENTED (0xC0000002) → ERROR_NOT_SUPPORTED (50)
            assert_eq!(ntdll_RtlNtStatusToDosError(0xC000_0002), 50);
        }
    }

    #[test]
    fn test_win_protect_to_prot_readwrite() {
        // PAGE_READWRITE = 0x04
        let prot = win_protect_to_prot(0x04);
        assert_eq!(prot, libc::PROT_READ | libc::PROT_WRITE);
    }

    #[test]
    fn test_nt_write_file_invalid_handle() {
        unsafe {
            let mut io_sb = [0u64; 2];
            let buf = b"hello";
            let ret = ntdll_NtWriteFile(
                0x999, // invalid handle
                0,
                0,
                0,
                io_sb.as_mut_ptr(),
                buf.as_ptr(),
                buf.len() as u32,
                0,
                0,
            );
            assert_eq!(ret, status::STATUS_INVALID_HANDLE);
        }
    }

    #[test]
    fn test_nt_write_file_null_buffer() {
        unsafe {
            let mut io_sb = [0u64; 2];
            let ret = ntdll_NtWriteFile(
                STDOUT_HANDLE,
                0,
                0,
                0,
                io_sb.as_mut_ptr(),
                core::ptr::null(),
                0,
                0,
                0,
            );
            assert_eq!(ret, status::STATUS_SUCCESS);
            assert_eq!(io_sb[1], 0); // 0 bytes written
        }
    }

    #[test]
    fn test_nt_close_always_succeeds() {
        unsafe {
            assert_eq!(ntdll_NtClose(0x11), status::STATUS_SUCCESS);
            assert_eq!(ntdll_NtClose(0xDEAD_BEEF), status::STATUS_SUCCESS);
        }
    }

    #[test]
    fn test_nt_write_file_via_kernel32_handle() {
        // Create a file via kernel32 and verify NtWriteFile can write to it
        use crate::kernel32::{
            kernel32_CloseHandle, kernel32_CreateFileW, kernel32_SetFilePointerEx,
        };

        let path = "/tmp/litebox_ntdll_write_test.txt";
        let _ = std::fs::remove_file(path);

        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0u16)).collect();

        unsafe {
            let handle = kernel32_CreateFileW(
                wide.as_ptr(),
                0x4000_0000 | 0x8000_0000, // GENERIC_READ | GENERIC_WRITE
                0,
                core::ptr::null_mut(),
                2, // CREATE_ALWAYS
                0x80,
                core::ptr::null_mut(),
            );
            assert_ne!(handle as usize, usize::MAX, "CreateFileW failed");

            let data = b"NtWriteFile test data";
            let mut io_sb = [0u64; 2];
            let status = ntdll_NtWriteFile(
                handle as u64,
                0,
                0,
                0,
                io_sb.as_mut_ptr(),
                data.as_ptr(),
                data.len() as u32,
                0,
                0,
            );
            assert_eq!(status, status::STATUS_SUCCESS, "NtWriteFile failed");
            assert_eq!(io_sb[1], data.len() as u64, "bytes written mismatch");

            // Seek back to start for reading
            kernel32_SetFilePointerEx(handle, 0, core::ptr::null_mut(), 0);

            let mut buf = [0u8; 32];
            let mut io_sb2 = [0u64; 2];
            let status2 = ntdll_NtReadFile(
                handle as u64,
                0,
                0,
                0,
                io_sb2.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                0,
                0,
            );
            assert_eq!(status2, status::STATUS_SUCCESS, "NtReadFile failed");
            let nread = io_sb2[1] as usize;
            assert_eq!(&buf[..nread], data);

            kernel32_CloseHandle(handle);
        }
        let _ = std::fs::remove_file(path);
    }
}
