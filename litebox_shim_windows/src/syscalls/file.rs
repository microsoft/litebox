// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT file I/O syscall handlers.
//!
//! Implements NtCreateFile, NtReadFile, NtQueryInformationFile, and
//! NtSetInformationFile. For Phase 2, file operations pass through to the
//! host OS. A proper sandboxed VFS will be added in later phases.

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

use litebox_common_windows::nt_types::{
    FileBasicInformation, FilePositionInformation, FileStandardInformation, IoStatusBlock,
    ObjectAttributes, UnicodeString, file_disposition, file_options,
};
use litebox_common_windows::ntstatus::NtStatus;

use crate::handle_table::{HandleTable, NtObject};

use super::NtSyscallArgs;

// ========================================================================
// Host file operations (Windows FFI)
// ========================================================================

#[cfg(target_os = "windows")]
pub(crate) mod host {
    /// INVALID_HANDLE_VALUE
    pub const INVALID_HANDLE: usize = usize::MAX;

    /// FILE_ATTRIBUTE_DIRECTORY
    pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    /// INVALID_FILE_ATTRIBUTES (GetFileAttributesW failure sentinel).
    pub const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;

    /// Query file attributes on the host. Returns INVALID_FILE_ATTRIBUTES
    /// on failure.
    pub fn get_file_attributes(path: &str) -> u32 {
        use alloc::vec::Vec;

        unsafe extern "system" {
            fn GetFileAttributesW(name: *const u16) -> u32;
        }

        let mut wide: Vec<u16> = path.encode_utf16().collect();
        wide.push(0);
        unsafe { GetFileAttributesW(wide.as_ptr()) }
    }

    /// Get the last Win32 error code.
    pub fn get_last_error() -> u32 {
        unsafe extern "system" {
            fn GetLastError() -> u32;
        }
        unsafe { GetLastError() }
    }

    /// Create a directory on the host. Returns 0 on success, or a Win32 error code.
    pub fn create_directory(path: &str) -> u32 {
        use alloc::vec::Vec;

        unsafe extern "system" {
            fn CreateDirectoryW(name: *const u16, security: usize) -> i32;
        }

        let mut wide: Vec<u16> = path.encode_utf16().collect();
        wide.push(0);
        if unsafe { CreateDirectoryW(wide.as_ptr(), 0) } != 0 {
            0 // success
        } else {
            get_last_error()
        }
    }

    /// Open a file on the host. `disposition` is the Win32 creation disposition
    /// (CREATE_NEW=1, CREATE_ALWAYS=2, OPEN_EXISTING=3, OPEN_ALWAYS=4,
    /// TRUNCATE_EXISTING=5). `share_mode` and `flags_and_attrs` are passed
    /// through to the host CreateFileW. Returns a Windows HANDLE as usize, or
    /// INVALID_HANDLE on failure.
    pub fn open_file(
        path: &str,
        read: bool,
        write: bool,
        disposition: u32,
        share_mode: u32,
        flags_and_attrs: u32,
    ) -> usize {
        use alloc::vec::Vec;

        unsafe extern "system" {
            fn CreateFileW(
                name: *const u16,
                access: u32,
                share_mode: u32,
                security: usize,
                disposition: u32,
                flags: u32,
                template: usize,
            ) -> usize;
        }

        let mut wide: Vec<u16> = path.encode_utf16().collect();
        wide.push(0);

        let access = if read && write {
            0x8000_0000u32 | 0x4000_0000 // GENERIC_READ | GENERIC_WRITE
        } else if write {
            0x4000_0000 // GENERIC_WRITE
        } else {
            0x8000_0000 // GENERIC_READ
        };

        // Default to FILE_ATTRIBUTE_NORMAL if the caller passed 0 for attrs.
        let flags = if flags_and_attrs == 0 {
            0x80
        } else {
            flags_and_attrs
        };

        unsafe { CreateFileW(wide.as_ptr(), access, share_mode, 0, disposition, flags, 0) }
    }

    /// Read bytes from a host file handle.
    pub fn read_file(handle: usize, buf: *mut u8, len: u32) -> (bool, u32) {
        unsafe extern "system" {
            fn ReadFile(
                handle: usize,
                buffer: *mut u8,
                bytes_to_read: u32,
                bytes_read: *mut u32,
                overlapped: usize,
            ) -> i32;
        }

        let mut bytes_read: u32 = 0;
        let ok = unsafe { ReadFile(handle, buf, len, &raw mut bytes_read, 0) };
        (ok != 0, bytes_read)
    }

    /// Read bytes from a host file handle at an explicit byte offset.
    ///
    /// Uses OVERLAPPED to specify the file position so that the host kernel's
    /// implicit file pointer is never consulted. This makes the caller's
    /// cached position the single source of truth.
    pub fn read_file_at(handle: usize, buf: *mut u8, len: u32, offset: u64) -> (bool, u32) {
        unsafe extern "system" {
            fn ReadFile(
                handle: usize,
                buffer: *mut u8,
                bytes_to_read: u32,
                bytes_read: *mut u32,
                overlapped: usize,
            ) -> i32;
        }

        #[repr(C)]
        struct Overlapped {
            internal: usize,
            internal_high: usize,
            offset_low: u32,
            offset_high: u32,
            h_event: usize,
        }

        let mut ovl = Overlapped {
            internal: 0,
            internal_high: 0,
            offset_low: offset as u32,
            offset_high: (offset >> 32) as u32,
            h_event: 0,
        };
        let mut bytes_read: u32 = 0;
        // Safety: overlapped pointer is valid for the duration of the call.
        let ok = unsafe { ReadFile(handle, buf, len, &raw mut bytes_read, &raw mut ovl as usize) };
        (ok != 0, bytes_read)
    }

    /// Read bytes from the host's stdin handle.
    pub fn read_stdin(buf: *mut u8, len: u32) -> (bool, u32) {
        unsafe extern "system" {
            fn GetStdHandle(n: u32) -> usize;
            fn ReadFile(
                handle: usize,
                buffer: *mut u8,
                bytes_to_read: u32,
                bytes_read: *mut u32,
                overlapped: usize,
            ) -> i32;
        }

        let stdin = unsafe { GetStdHandle(0xFFFF_FFF6) }; // STD_INPUT_HANDLE
        if stdin == 0 || stdin == usize::MAX {
            return (false, 0);
        }
        let mut bytes_read: u32 = 0;
        let ok = unsafe { ReadFile(stdin, buf, len, &raw mut bytes_read, 0) };
        (ok != 0, bytes_read)
    }

    /// Write bytes to a host file handle.
    pub fn write_file(handle: usize, buf: *const u8, len: u32) -> (bool, u32) {
        unsafe extern "system" {
            fn WriteFile(
                handle: usize,
                buffer: *const u8,
                bytes_to_write: u32,
                bytes_written: *mut u32,
                overlapped: usize,
            ) -> i32;
        }

        let mut bytes_written: u32 = 0;
        let ok = unsafe { WriteFile(handle, buf, len, &raw mut bytes_written, 0) };
        (ok != 0, bytes_written)
    }

    /// Write bytes to a host file handle at an explicit byte offset.
    ///
    /// Uses OVERLAPPED to specify the file position so that the host kernel's
    /// implicit file pointer is never consulted.
    pub fn write_file_at(handle: usize, buf: *const u8, len: u32, offset: u64) -> (bool, u32) {
        unsafe extern "system" {
            fn WriteFile(
                handle: usize,
                buffer: *const u8,
                bytes_to_write: u32,
                bytes_written: *mut u32,
                overlapped: usize,
            ) -> i32;
        }

        #[repr(C)]
        struct Overlapped {
            internal: usize,
            internal_high: usize,
            offset_low: u32,
            offset_high: u32,
            h_event: usize,
        }

        let mut ovl = Overlapped {
            internal: 0,
            internal_high: 0,
            offset_low: offset as u32,
            offset_high: (offset >> 32) as u32,
            h_event: 0,
        };
        let mut bytes_written: u32 = 0;
        // Safety: overlapped pointer is valid for the duration of the call.
        let ok = unsafe {
            WriteFile(
                handle,
                buf,
                len,
                &raw mut bytes_written,
                &raw mut ovl as usize,
            )
        };
        (ok != 0, bytes_written)
    }

    /// Get file size in bytes. Returns -1 on failure.
    pub fn get_file_size(handle: usize) -> i64 {
        unsafe extern "system" {
            fn GetFileSizeEx(handle: usize, size: *mut i64) -> i32;
        }

        let mut size: i64 = 0;
        let ok = unsafe { GetFileSizeEx(handle, &raw mut size) };
        if ok != 0 { size } else { -1 }
    }

    /// Set file position. Returns new position or -1 on failure.
    pub fn set_file_position(handle: usize, offset: i64, method: u32) -> i64 {
        unsafe extern "system" {
            fn SetFilePointerEx(
                handle: usize,
                distance: i64,
                new_pointer: *mut i64,
                method: u32,
            ) -> i32;
        }

        let mut new_pos: i64 = 0;
        let ok = unsafe { SetFilePointerEx(handle, offset, &raw mut new_pos, method) };
        if ok != 0 { new_pos } else { -1 }
    }

    /// Set end-of-file at the given position.
    pub fn set_end_of_file(handle: usize, position: i64) -> bool {
        unsafe extern "system" {
            fn SetFilePointerEx(
                handle: usize,
                distance: i64,
                new_pointer: *mut i64,
                method: u32,
            ) -> i32;
            fn SetEndOfFile(handle: usize) -> i32;
        }

        // First seek to the position, then set EOF there.
        let ok = unsafe { SetFilePointerEx(handle, position, core::ptr::null_mut(), 0) };
        if ok == 0 {
            return false;
        }
        unsafe { SetEndOfFile(handle) != 0 }
    }

    /// Get file attributes/times.
    pub fn get_file_info(handle: usize) -> Option<(u32, i64, i64, i64, i64)> {
        #[repr(C)]
        struct ByHandleFileInformation {
            attributes: u32,
            creation_time_low: u32,
            creation_time_high: u32,
            last_access_time_low: u32,
            last_access_time_high: u32,
            last_write_time_low: u32,
            last_write_time_high: u32,
            volume_serial: u32,
            size_high: u32,
            size_low: u32,
            num_links: u32,
            file_index_high: u32,
            file_index_low: u32,
        }

        unsafe extern "system" {
            fn GetFileInformationByHandle(handle: usize, info: *mut ByHandleFileInformation)
            -> i32;
        }

        let mut info = core::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
        let ok = unsafe { GetFileInformationByHandle(handle, info.as_mut_ptr()) };
        if ok == 0 {
            return None;
        }
        let info = unsafe { info.assume_init() };
        let ft = |low: u32, high: u32| -> i64 { ((high as i64) << 32) | (low as i64) };
        Some((
            info.attributes,
            ft(info.creation_time_low, info.creation_time_high),
            ft(info.last_access_time_low, info.last_access_time_high),
            ft(info.last_write_time_low, info.last_write_time_high),
            ft(info.last_write_time_low, info.last_write_time_high), // change = write
        ))
    }

    /// A single directory entry returned by `find_files`.
    pub struct FindFileEntry {
        pub name: alloc::string::String,
        pub attributes: u32,
        pub file_size: i64,
        pub creation_time: i64,
        pub last_access_time: i64,
        pub last_write_time: i64,
    }

    /// Enumerate directory entries matching a search pattern (e.g. "C:\\dir\\*").
    pub fn find_files(pattern: &str) -> alloc::vec::Vec<FindFileEntry> {
        use alloc::vec::Vec;

        #[repr(C)]
        struct Win32FindDataW {
            attributes: u32,
            creation_time_low: u32,
            creation_time_high: u32,
            last_access_time_low: u32,
            last_access_time_high: u32,
            last_write_time_low: u32,
            last_write_time_high: u32,
            size_high: u32,
            size_low: u32,
            _reserved0: u32,
            _reserved1: u32,
            file_name: [u16; 260],
            alternate_name: [u16; 14],
        }

        unsafe extern "system" {
            fn FindFirstFileW(name: *const u16, data: *mut Win32FindDataW) -> usize;
            fn FindNextFileW(handle: usize, data: *mut Win32FindDataW) -> i32;
            fn FindClose(handle: usize) -> i32;
        }

        const INVALID_HANDLE_VALUE: usize = usize::MAX;

        let mut wide: Vec<u16> = pattern.encode_utf16().collect();
        wide.push(0);

        let mut results = Vec::new();
        let mut data = core::mem::MaybeUninit::<Win32FindDataW>::uninit();

        // Safety: FFI call with valid aligned buffer.
        let find_handle = unsafe { FindFirstFileW(wide.as_ptr(), data.as_mut_ptr()) };
        if find_handle == INVALID_HANDLE_VALUE {
            return results;
        }

        let ft = |low: u32, high: u32| -> i64 { ((high as i64) << 32) | (low as i64) };

        loop {
            let d = unsafe { data.assume_init_ref() };
            // Read the NUL-terminated filename.
            let name_len = d.file_name.iter().position(|&c| c == 0).unwrap_or(260);
            let name = alloc::string::String::from_utf16_lossy(&d.file_name[..name_len]);

            results.push(FindFileEntry {
                name,
                attributes: d.attributes,
                file_size: ((d.size_high as i64) << 32) | (d.size_low as i64),
                creation_time: ft(d.creation_time_low, d.creation_time_high),
                last_access_time: ft(d.last_access_time_low, d.last_access_time_high),
                last_write_time: ft(d.last_write_time_low, d.last_write_time_high),
            });

            // Safety: FFI call.
            if unsafe { FindNextFileW(find_handle, data.as_mut_ptr()) } == 0 {
                break;
            }
        }

        // Safety: FFI call.
        unsafe {
            FindClose(find_handle);
        }
        results
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) mod host {
    pub const INVALID_HANDLE: usize = usize::MAX;
    pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    pub const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
    pub fn get_file_attributes(_path: &str) -> u32 {
        INVALID_FILE_ATTRIBUTES
    }
    pub fn get_last_error() -> u32 {
        2 // ERROR_FILE_NOT_FOUND
    }
    pub fn create_directory(_path: &str) -> u32 {
        5 // ERROR_ACCESS_DENIED
    }
    pub fn open_file(
        _path: &str,
        _read: bool,
        _write: bool,
        _disposition: u32,
        _share_mode: u32,
        _flags_and_attrs: u32,
    ) -> usize {
        INVALID_HANDLE
    }
    pub fn read_file(_handle: usize, _buf: *mut u8, _len: u32) -> (bool, u32) {
        (false, 0)
    }
    pub fn read_file_at(_handle: usize, _buf: *mut u8, _len: u32, _offset: u64) -> (bool, u32) {
        (false, 0)
    }
    pub fn read_stdin(_buf: *mut u8, _len: u32) -> (bool, u32) {
        (false, 0)
    }
    pub fn write_file(_handle: usize, _buf: *const u8, _len: u32) -> (bool, u32) {
        (false, 0)
    }
    pub fn write_file_at(_handle: usize, _buf: *const u8, _len: u32, _offset: u64) -> (bool, u32) {
        (false, 0)
    }
    pub fn get_file_size(_handle: usize) -> i64 {
        -1
    }
    pub fn set_file_position(_handle: usize, _offset: i64, _method: u32) -> i64 {
        -1
    }
    pub fn set_end_of_file(_handle: usize, _position: i64) -> bool {
        false
    }
    pub fn get_file_info(_handle: usize) -> Option<(u32, i64, i64, i64, i64)> {
        None
    }
    pub struct FindFileEntry {
        pub name: alloc::string::String,
        pub attributes: u32,
        pub file_size: i64,
        pub creation_time: i64,
        pub last_access_time: i64,
        pub last_write_time: i64,
    }
    pub fn find_files(_pattern: &str) -> alloc::vec::Vec<FindFileEntry> {
        alloc::vec::Vec::new()
    }
}

// ========================================================================
// NT path translation
// ========================================================================

/// Translate an NT object path to a host filesystem path.
///
/// Handles these prefixes:
/// - `\??\C:\...` → `C:\...`
/// - `\??\UNC\...` → `\\...`
/// - `\DosDevices\C:\...` → `C:\...`
/// - `\SystemRoot\...` → `C:\Windows\...`
///
/// Returns `None` for device paths (\Device\...) that can't be mapped.
pub(crate) fn translate_nt_path(nt_path: &str) -> Option<String> {
    // Strip common NT prefixes.
    if let Some(rest) = nt_path.strip_prefix("\\??\\") {
        if let Some(stripped) = rest.strip_prefix("UNC\\") {
            // UNC path: \??\UNC\server\share → \\server\share
            return Some(String::from("\\\\") + stripped);
        }
        // Standard drive path: \??\C:\... → C:\...
        return Some(String::from(rest));
    }
    if let Some(rest) = nt_path.strip_prefix("\\DosDevices\\") {
        return Some(String::from(rest));
    }
    if let Some(rest) = nt_path.strip_prefix("\\SystemRoot\\") {
        return Some(String::from("C:\\Windows\\") + rest);
    }
    if let Some(rest) = nt_path.strip_prefix("\\SystemRoot")
        && rest.is_empty()
    {
        return Some(String::from("C:\\Windows"));
    }
    // If it looks like a drive letter path already, pass through.
    if nt_path.len() >= 3 && nt_path.as_bytes()[1] == b':' {
        return Some(String::from(nt_path));
    }
    // Unknown — return None to signal "object not found".
    None
}

/// Read a UNICODE_STRING from guest memory and return the string contents.
fn read_unicode_string_from_guest(us_va: usize) -> Option<String> {
    if us_va == 0 {
        return None;
    }
    // Safety: guest VA is directly accessible on userland platform.
    let us = unsafe { core::ptr::read(us_va as *const UnicodeString) };
    if us.buffer == 0 || us.length == 0 {
        return None;
    }
    let char_count = (us.length as usize) / 2;
    let wchars =
        unsafe { core::slice::from_raw_parts(us.buffer as usize as *const u16, char_count) };
    Some(alloc::string::String::from_utf16_lossy(wchars))
}

// ========================================================================
// NtCreateFile
// ========================================================================

/// NtCreateFile — open or create a file.
///
/// NT signature:
/// ```text
/// NTSTATUS NtCreateFile(
///     PHANDLE FileHandle,                 // r10 (out)
///     ACCESS_MASK DesiredAccess,           // rdx
///     POBJECT_ATTRIBUTES ObjectAttributes, // r8
///     PIO_STATUS_BLOCK IoStatusBlock,      // r9
///     PLARGE_INTEGER AllocationSize,       // [rsp+0x28]
///     ULONG FileAttributes,               // [rsp+0x30]
///     ULONG ShareAccess,                  // [rsp+0x38]
///     ULONG CreateDisposition,            // [rsp+0x40]
///     ULONG CreateOptions,                // [rsp+0x48]
///     PVOID EaBuffer,                     // [rsp+0x50]
///     ULONG EaLength                      // [rsp+0x58]
/// );
/// ```
pub(crate) fn nt_create_file(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_ptr = args.arg0;
    let desired_access = args.arg1 as u32;
    let obj_attr_ptr = args.arg2;
    let io_status_ptr = args.arg3;

    // Read stack arguments.
    let file_attributes = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const u32) };
    let share_access = unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const u32) };
    let create_disposition = unsafe { core::ptr::read((ctx.regs.rsp + 0x40) as *const u32) };
    let create_options = unsafe { core::ptr::read((ctx.regs.rsp + 0x48) as *const u32) };

    if handle_out_ptr == 0 || obj_attr_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Read OBJECT_ATTRIBUTES from guest memory.
    let obj_attr = unsafe { core::ptr::read(obj_attr_ptr as *const ObjectAttributes) };

    // Read the path from UNICODE_STRING.
    let Some(nt_path) = read_unicode_string_from_guest(obj_attr.object_name as usize) else {
        return NtStatus::STATUS_OBJECT_NAME_INVALID;
    };

    // Handle device paths that don't go through the filesystem.
    let nt_path_lower = nt_path.to_lowercase();
    let is_condrv_path = nt_path_lower.contains("\\device\\condrv\\");
    // Check if root directory handle is a ConDrv stub (relative open).
    let is_condrv_relative = if obj_attr.root_directory != 0 && !is_condrv_path {
        let root_h = obj_attr.root_directory as u32;
        handles
            .get(root_h)
            .is_some_and(|obj| matches!(obj, NtObject::Stub { kind } if kind == "ConDrv"))
    } else {
        false
    };
    if is_condrv_path || is_condrv_relative {
        // Console driver device — dispatch to proper handle type based on
        // the path suffix: \\Input → ConsoleInput, \\Output → ConsoleOutput,
        // everything else → generic ConDrv stub.
        let path_lower = nt_path.to_lowercase();
        let obj = if path_lower.ends_with("\\input") {
            NtObject::ConsoleInput
        } else if path_lower.ends_with("\\output") {
            NtObject::ConsoleOutput { is_stderr: false }
        } else {
            NtObject::Stub {
                kind: alloc::string::String::from("ConDrv"),
            }
        };
        let h = handles.insert(obj);
        if handle_out_ptr != 0 {
            unsafe {
                core::ptr::write(handle_out_ptr as *mut u64, u64::from(h));
            }
        }
        if io_status_ptr != 0 {
            unsafe {
                core::ptr::write(io_status_ptr as *mut u64, 0); // Status = SUCCESS
                core::ptr::write((io_status_ptr + 8) as *mut u64, 0); // Information = FILE_OPENED
            }
        }
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtCreateFile ConDrv stub handle=0x{h:X} path={nt_path:?}\n",
            ));
        }
        return NtStatus::STATUS_SUCCESS;
    }

    // Check for directory opens.
    let is_directory = create_options & file_options::FILE_DIRECTORY_FILE != 0;

    // Translate NT path to host path.
    let Some(host_path) = translate_nt_path(&nt_path) else {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!("NT shim: NtCreateFile path not translatable: {nt_path:?}\n");
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
    };

    if is_directory {
        let attrs = host::get_file_attributes(&host_path);
        let dir_exists =
            attrs != host::INVALID_FILE_ATTRIBUTES && attrs & host::FILE_ATTRIBUTE_DIRECTORY != 0;

        match create_disposition {
            file_disposition::FILE_OPEN => {
                // Must exist.
                if !dir_exists {
                    return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
                }
            }
            file_disposition::FILE_CREATE => {
                // Must NOT exist.
                if dir_exists {
                    return NtStatus::STATUS_OBJECT_NAME_COLLISION;
                }
                // Create the directory on the host.
                let err = host::create_directory(&host_path);
                if err != 0 {
                    return map_win32_error_to_ntstatus(err);
                }
            }
            file_disposition::FILE_OPEN_IF => {
                // Open if exists, create if missing.
                if !dir_exists {
                    let err = host::create_directory(&host_path);
                    if err != 0 {
                        return map_win32_error_to_ntstatus(err);
                    }
                }
            }
            _ => {
                // FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF don't
                // apply to directories — treat as "open existing".
                if !dir_exists {
                    return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
                }
            }
        }

        // Validate it's actually a directory (may have just been created).
        if !dir_exists {
            let check = host::get_file_attributes(&host_path);
            if check == host::INVALID_FILE_ATTRIBUTES || check & host::FILE_ATTRIBUTE_DIRECTORY == 0
            {
                return NtStatus::STATUS_NOT_A_DIRECTORY;
            }
        }

        // Directory handle — store as a Directory object.
        let handle = handles.insert(NtObject::Directory {
            path: nt_path.clone(),
            enum_entries: alloc::vec::Vec::new(),
            enum_index: 0,
        });
        unsafe {
            core::ptr::write(handle_out_ptr as *mut u32, handle);
        }
        let iosb_info = if create_disposition == file_disposition::FILE_CREATE
            || (create_disposition == file_disposition::FILE_OPEN_IF && !dir_exists)
        {
            2 // FILE_CREATED
        } else {
            1 // FILE_OPENED
        };
        if io_status_ptr != 0 {
            let iosb = IoStatusBlock {
                status: NtStatus::STATUS_SUCCESS.0,
                _pad: 0,
                information: iosb_info,
            };
            unsafe {
                core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
            }
        }
        return NtStatus::STATUS_SUCCESS;
    }

    // Determine access mode.
    let want_read = desired_access & 0x8000_0001 != 0; // GENERIC_READ or FILE_READ_DATA
    let want_write = desired_access & 0x4000_0006 != 0; // GENERIC_WRITE or FILE_WRITE_DATA|APPEND

    // Map NT file disposition to Win32 creation disposition.
    let win32_disposition = match create_disposition {
        file_disposition::FILE_SUPERSEDE => 2,    // CREATE_ALWAYS
        file_disposition::FILE_OPEN => 3,         // OPEN_EXISTING
        file_disposition::FILE_CREATE => 1,       // CREATE_NEW
        file_disposition::FILE_OPEN_IF => 4,      // OPEN_ALWAYS
        file_disposition::FILE_OVERWRITE => 5,    // TRUNCATE_EXISTING
        file_disposition::FILE_OVERWRITE_IF => 2, // CREATE_ALWAYS (create + truncate)
        _ => 3,                                   // OPEN_EXISTING (default)
    };

    // Map NT share_access to Win32 share mode (same bit values).
    // Zero means exclusive open — no sharing.
    let win32_share = share_access;

    // Map file attributes. FILE_ATTRIBUTE_NORMAL = 0x80.
    let win32_attrs = if file_attributes == 0 {
        0x80 // FILE_ATTRIBUTE_NORMAL
    } else {
        file_attributes
    };

    let host_handle = host::open_file(
        &host_path,
        want_read || !want_write,
        want_write,
        win32_disposition,
        win32_share,
        win32_attrs,
    );

    if host_handle == host::INVALID_HANDLE {
        let win_err = host::get_last_error();
        return map_win32_error_to_ntstatus(win_err);
    }

    // Insert into handle table.
    let handle = handles.insert(NtObject::File {
        path: nt_path,
        host_handle,
        position: Arc::new(AtomicU64::new(0)),
    });

    unsafe {
        core::ptr::write(handle_out_ptr as *mut u32, handle);
    }

    if io_status_ptr != 0 {
        let info = match create_disposition {
            file_disposition::FILE_OPEN => 1,   // FILE_OPENED
            file_disposition::FILE_CREATE => 2, // FILE_CREATED
            file_disposition::FILE_OPEN_IF => {
                // OPEN_ALWAYS sets ERROR_ALREADY_EXISTS(183) when file existed.
                let err = host::get_last_error();
                if err == 183 { 1 } else { 2 } // FILE_OPENED vs FILE_CREATED
            }
            file_disposition::FILE_SUPERSEDE => {
                // CREATE_ALWAYS: ERROR_ALREADY_EXISTS(183) if existing file replaced.
                let err = host::get_last_error();
                if err == 183 { 0 } else { 2 } // FILE_SUPERSEDED(0) vs FILE_CREATED(2)
            }
            file_disposition::FILE_OVERWRITE_IF => {
                let err = host::get_last_error();
                if err == 183 { 3 } else { 2 } // FILE_OVERWRITTEN vs FILE_CREATED
            }
            _ => 1,
        };
        let iosb = IoStatusBlock {
            status: NtStatus::STATUS_SUCCESS.0,
            _pad: 0,
            information: info,
        };
        unsafe {
            core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
        }
    }

    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// NtReadFile
// ========================================================================

/// NtReadFile — read from a host file handle.
///
/// Called after handle-table lock is dropped. Takes extracted handle info.
pub(crate) fn nt_read_file_host(
    ctx: &mut super::super::ExecutionContext,
    host_handle: usize,
    position: &alloc::sync::Arc<AtomicU64>,
) -> NtStatus {
    // Stack arguments.
    let io_status_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let buffer_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const usize) };
    let length = unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const u32) };
    let byte_offset_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x40) as *const usize) };

    if buffer_ptr == 0 || length == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // NT ByteOffset sentinels:
    //   >= 0                      → positional I/O (pread), no position mutation
    //   -2 (USE_FILE_POINTER_POS) → use & advance the shared current position
    //   -1 and all others         → invalid for reads
    //   NULL pointer              → use & advance the shared current position
    const FILE_USE_FILE_POINTER_POSITION: i64 = -2;

    let (read_pos, reserved) = if byte_offset_ptr != 0 {
        let offset = unsafe { core::ptr::read(byte_offset_ptr as *const i64) };
        if offset >= 0 {
            // Positional read: don't mutate the shared position.
            (offset as u64, 0u64)
        } else if offset == FILE_USE_FILE_POINTER_POSITION {
            let start = position.fetch_add(length as u64, Relaxed);
            (start, length as u64)
        } else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }
    } else {
        let start = position.fetch_add(length as u64, Relaxed);
        (start, length as u64)
    };

    let (ok, bytes_read) = host::read_file_at(host_handle, buffer_ptr as *mut u8, length, read_pos);

    if ok {
        if reserved > 0 {
            let over = reserved - bytes_read as u64;
            if over > 0 {
                position.fetch_sub(over, Relaxed);
            }
        }
        if io_status_ptr != 0 {
            let iosb = IoStatusBlock {
                status: NtStatus::STATUS_SUCCESS.0,
                _pad: 0,
                information: bytes_read as u64,
            };
            unsafe {
                core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
            }
        }
        if bytes_read == 0 {
            NtStatus::STATUS_END_OF_FILE
        } else {
            NtStatus::STATUS_SUCCESS
        }
    } else {
        if reserved > 0 {
            position.fetch_sub(reserved, Relaxed);
        }
        NtStatus::STATUS_ACCESS_DENIED
    }
}

/// NtReadFile — read from ConsoleInput.
///
/// Called after handle-table lock is dropped.
pub(crate) fn nt_read_file_console(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let io_status_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let buffer_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const usize) };
    let length = unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const u32) };

    if buffer_ptr == 0 || length == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Read from the platform's StdioProvider (same path as Linux shim).
    let buf = unsafe { core::slice::from_raw_parts_mut(buffer_ptr as *mut u8, length as usize) };
    use litebox::platform::StdioProvider as _;
    match litebox_platform_multiplex::platform().read_from_stdin(buf) {
        Ok(bytes_read) => {
            if io_status_ptr != 0 {
                let iosb = IoStatusBlock {
                    status: NtStatus::STATUS_SUCCESS.0,
                    _pad: 0,
                    information: bytes_read as u64,
                };
                unsafe {
                    core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
                }
            }
            if bytes_read == 0 {
                NtStatus::STATUS_END_OF_FILE
            } else {
                NtStatus::STATUS_SUCCESS
            }
        }
        Err(_) => NtStatus::STATUS_END_OF_FILE,
    }
}

// ========================================================================
// NtWriteFile (enhanced for file handles)
// ========================================================================

/// NtWriteFile — write to ConsoleOutput via platform StdioProvider.
///
/// Called after handle-table lock is dropped.
pub(crate) fn nt_write_file_console(
    ctx: &mut super::super::ExecutionContext,
    is_stderr: bool,
) -> NtStatus {
    let io_status_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let buffer_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const usize) };
    let length = unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const u32) };

    let mut bytes_written = 0u32;
    if buffer_ptr != 0 && length > 0 {
        let buf = unsafe { core::slice::from_raw_parts(buffer_ptr as *const u8, length as usize) };
        let stream = if is_stderr {
            litebox::platform::StdioOutStream::Stderr
        } else {
            litebox::platform::StdioOutStream::Stdout
        };
        use litebox::platform::StdioProvider as _;
        match litebox_platform_multiplex::platform().write_to(stream, buf) {
            Ok(n) => bytes_written = n as u32,
            Err(_) => return NtStatus::STATUS_UNSUCCESSFUL,
        }
    }
    if io_status_ptr != 0 {
        let iosb = IoStatusBlock {
            status: NtStatus::STATUS_SUCCESS.0,
            _pad: 0,
            information: bytes_written as u64,
        };
        unsafe {
            core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
        }
    }
    NtStatus::STATUS_SUCCESS
}

/// NtWriteFile — write to a host file handle.
///
/// Called after handle-table lock is dropped. Takes extracted handle info.
/// Supports ByteOffset at [rsp+0x40].
pub(crate) fn nt_write_file_host(
    ctx: &mut super::super::ExecutionContext,
    host_handle: usize,
    position: &alloc::sync::Arc<AtomicU64>,
) -> NtStatus {
    let io_status_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let buffer_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const usize) };
    let length = unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const u32) };
    let byte_offset_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x40) as *const usize) };

    if buffer_ptr == 0 || length == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // NT ByteOffset sentinels:
    //   >= 0                        → positional I/O (pwrite), no position mutation
    //   -2 (USE_FILE_POINTER_POS)   → use & advance the shared current position
    //   -1 (WRITE_TO_END_OF_FILE)   → append at EOF
    //   all others                  → invalid
    //   NULL pointer                → use & advance the shared current position
    const FILE_USE_FILE_POINTER_POSITION: i64 = -2;
    const FILE_WRITE_TO_END_OF_FILE: i64 = -1;

    let (write_pos, reserved) = if byte_offset_ptr != 0 {
        let offset = unsafe { core::ptr::read(byte_offset_ptr as *const i64) };
        if offset >= 0 {
            // Positional write: don't mutate the shared position.
            (offset as u64, 0u64)
        } else if offset == FILE_USE_FILE_POINTER_POSITION {
            let start = position.fetch_add(length as u64, Relaxed);
            (start, length as u64)
        } else if offset == FILE_WRITE_TO_END_OF_FILE {
            // Append at EOF: query actual file size for the write offset.
            // Don't mutate the shared position — the caller explicitly asked
            // for EOF, not "advance current pointer."
            let size = host::get_file_size(host_handle);
            if size < 0 {
                return NtStatus::STATUS_UNSUCCESSFUL;
            }
            (size as u64, 0u64)
        } else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }
    } else {
        let start = position.fetch_add(length as u64, Relaxed);
        (start, length as u64)
    };

    let (ok, bytes_written) =
        host::write_file_at(host_handle, buffer_ptr as *const u8, length, write_pos);

    if ok {
        if reserved > 0 {
            let over = reserved - bytes_written as u64;
            if over > 0 {
                position.fetch_sub(over, Relaxed);
            }
        }
        if io_status_ptr != 0 {
            let iosb = IoStatusBlock {
                status: NtStatus::STATUS_SUCCESS.0,
                _pad: 0,
                information: bytes_written as u64,
            };
            unsafe {
                core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
            }
        }
        NtStatus::STATUS_SUCCESS
    } else {
        if reserved > 0 {
            position.fetch_sub(reserved, Relaxed);
        }
        NtStatus::STATUS_ACCESS_DENIED
    }
}

// ========================================================================
// NtQueryInformationFile
// ========================================================================

/// NtQueryInformationFile — query file metadata.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryInformationFile(
///     HANDLE FileHandle,                    // r10
///     PIO_STATUS_BLOCK IoStatusBlock,       // rdx
///     PVOID FileInformation,                // r8
///     ULONG Length,                         // r9
///     FILE_INFORMATION_CLASS FileInfoClass  // [rsp+0x28]
/// );
/// ```
pub(crate) fn nt_query_information_file(
    ctx: &mut super::super::ExecutionContext,
    handles: &HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let file_handle = args.arg0 as u32;
    let io_status_ptr = args.arg1;
    let info_ptr = args.arg2;
    let info_length = args.arg3 as u32;

    let info_class = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const u32) };

    let Some(obj) = handles.get(file_handle) else {
        return NtStatus::STATUS_INVALID_HANDLE;
    };

    match obj {
        NtObject::File {
            host_handle,
            position,
            ..
        } => match info_class {
            // FileBasicInformation (4)
            4 => {
                let size = core::mem::size_of::<FileBasicInformation>();
                if (info_length as usize) < size || info_ptr == 0 {
                    return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                }
                let info = if let Some((attrs, ctime, atime, wtime, chtime)) =
                    host::get_file_info(*host_handle)
                {
                    FileBasicInformation {
                        creation_time: ctime,
                        last_access_time: atime,
                        last_write_time: wtime,
                        change_time: chtime,
                        file_attributes: attrs,
                        _pad: 0,
                    }
                } else {
                    FileBasicInformation::default()
                };
                unsafe {
                    core::ptr::write(info_ptr as *mut FileBasicInformation, info);
                }
                write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                NtStatus::STATUS_SUCCESS
            }
            // FileStandardInformation (5)
            5 => {
                let size = core::mem::size_of::<FileStandardInformation>();
                if (info_length as usize) < size || info_ptr == 0 {
                    return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                }
                let file_size = host::get_file_size(*host_handle);
                let info = FileStandardInformation {
                    allocation_size: (file_size + 4095) & !4095, // round up to page
                    end_of_file: file_size,
                    number_of_links: 1,
                    delete_pending: 0,
                    directory: 0,
                    _pad: [0; 2],
                };
                unsafe {
                    core::ptr::write(info_ptr as *mut FileStandardInformation, info);
                }
                write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                NtStatus::STATUS_SUCCESS
            }
            // FilePositionInformation (14)
            14 => {
                let size = core::mem::size_of::<FilePositionInformation>();
                if (info_length as usize) < size || info_ptr == 0 {
                    return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                }
                let info = FilePositionInformation {
                    current_byte_offset: position.load(Relaxed) as i64,
                };
                unsafe {
                    core::ptr::write(info_ptr as *mut FilePositionInformation, info);
                }
                write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                NtStatus::STATUS_SUCCESS
            }
            _ => NtStatus::STATUS_INVALID_INFO_CLASS,
        },
        NtObject::ConsoleOutput { .. } | NtObject::ConsoleInput => {
            // Console handles: return minimal info.
            match info_class {
                5 => {
                    let size = core::mem::size_of::<FileStandardInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let info = FileStandardInformation::default();
                    unsafe {
                        core::ptr::write(info_ptr as *mut FileStandardInformation, info);
                    }
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                _ => NtStatus::STATUS_INVALID_INFO_CLASS,
            }
        }
        NtObject::Directory { .. } => {
            // Directory handles: return basic metadata.
            match info_class {
                // FileBasicInformation (4)
                4 => {
                    let size = core::mem::size_of::<FileBasicInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let info = FileBasicInformation {
                        file_attributes: host::FILE_ATTRIBUTE_DIRECTORY,
                        ..FileBasicInformation::default()
                    };
                    unsafe {
                        core::ptr::write(info_ptr as *mut FileBasicInformation, info);
                    }
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                // FileStandardInformation (5)
                5 => {
                    let size = core::mem::size_of::<FileStandardInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let info = FileStandardInformation {
                        directory: 1,
                        ..FileStandardInformation::default()
                    };
                    unsafe {
                        core::ptr::write(info_ptr as *mut FileStandardInformation, info);
                    }
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                _ => NtStatus::STATUS_INVALID_INFO_CLASS,
            }
        }
        _ => NtStatus::STATUS_INVALID_HANDLE,
    }
}

// ========================================================================
// NtSetInformationFile
// ========================================================================

/// NtSetInformationFile — set file metadata (mainly position/seek).
///
/// NT signature:
/// ```text
/// NTSTATUS NtSetInformationFile(
///     HANDLE FileHandle,                    // r10
///     PIO_STATUS_BLOCK IoStatusBlock,       // rdx
///     PVOID FileInformation,                // r8
///     ULONG Length,                         // r9
///     FILE_INFORMATION_CLASS FileInfoClass  // [rsp+0x28]
/// );
/// ```
pub(crate) fn nt_set_information_file(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let file_handle = args.arg0 as u32;
    let io_status_ptr = args.arg1;
    let info_ptr = args.arg2;
    let info_length = args.arg3 as u32;

    let info_class = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const u32) };

    let Some(obj) = handles.get(file_handle) else {
        return NtStatus::STATUS_INVALID_HANDLE;
    };

    match obj {
        NtObject::File {
            host_handle,
            position,
            ..
        } => match info_class {
            // FilePositionInformation (14) — seek
            14 => {
                let size = core::mem::size_of::<FilePositionInformation>();
                if (info_length as usize) < size || info_ptr == 0 {
                    return NtStatus::STATUS_INVALID_PARAMETER;
                }
                let info = unsafe { core::ptr::read(info_ptr as *const FilePositionInformation) };
                let new_pos = host::set_file_position(*host_handle, info.current_byte_offset, 0);
                if new_pos >= 0 {
                    position.store(new_pos as u64, Relaxed);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                } else {
                    NtStatus::STATUS_INVALID_PARAMETER
                }
            }
            // FileDispositionInformation (13) — mark for delete-on-close
            13 => {
                // Accept but ignore for now.
                write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 0);
                NtStatus::STATUS_SUCCESS
            }
            _ => NtStatus::STATUS_INVALID_INFO_CLASS,
        },
        _ => {
            // Non-file handles: accept silently.
            write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 0);
            NtStatus::STATUS_SUCCESS
        }
    }
}

// ========================================================================
// NtQueryAttributesFile
// ========================================================================

/// NtQueryAttributesFile — quick file existence/attribute check.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryAttributesFile(
///     POBJECT_ATTRIBUTES ObjectAttributes,           // r10
///     PFILE_BASIC_INFORMATION FileInformation         // rdx
/// );
/// ```
pub(crate) fn nt_query_attributes_file(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let obj_attr_ptr = args.arg0;
    let info_ptr = args.arg1;

    if obj_attr_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let obj_attr = unsafe { core::ptr::read(obj_attr_ptr as *const ObjectAttributes) };
    let Some(nt_path) = read_unicode_string_from_guest(obj_attr.object_name as usize) else {
        return NtStatus::STATUS_OBJECT_NAME_INVALID;
    };

    let Some(host_path) = translate_nt_path(&nt_path) else {
        return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
    };

    // Use GetFileAttributesW which works for both files and directories
    // without needing FILE_FLAG_BACKUP_SEMANTICS.
    let attrs = host::get_file_attributes(&host_path);
    if attrs == host::INVALID_FILE_ATTRIBUTES {
        return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if info_ptr != 0 {
        // GetFileAttributesW only returns attributes, not timestamps.
        // Open the file with BACKUP_SEMANTICS to get full info if possible.
        let open_flags = if attrs & host::FILE_ATTRIBUTE_DIRECTORY != 0 {
            0x02000000 | 0x80 // FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL
        } else {
            0x80 // FILE_ATTRIBUTE_NORMAL
        };
        let handle = host::open_file(
            &host_path,
            true,
            false,
            3,
            0x01 | 0x02 | 0x04, // FILE_SHARE_READ | WRITE | DELETE
            open_flags,
        );
        let info = if handle == host::INVALID_HANDLE {
            // Fallback: at least return the attributes from GetFileAttributesW.
            FileBasicInformation {
                file_attributes: attrs,
                ..FileBasicInformation::default()
            }
        } else {
            let result = if let Some((a, ctime, atime, wtime, chtime)) = host::get_file_info(handle)
            {
                FileBasicInformation {
                    creation_time: ctime,
                    last_access_time: atime,
                    last_write_time: wtime,
                    change_time: chtime,
                    file_attributes: a,
                    _pad: 0,
                }
            } else {
                FileBasicInformation {
                    file_attributes: attrs,
                    ..FileBasicInformation::default()
                }
            };
            #[cfg(target_os = "windows")]
            {
                unsafe extern "system" {
                    fn CloseHandle(handle: usize) -> i32;
                }
                unsafe {
                    CloseHandle(handle);
                }
            }
            result
        };
        unsafe {
            core::ptr::write(info_ptr as *mut FileBasicInformation, info);
        }
    }

    NtStatus::STATUS_SUCCESS
}

/// Helper: write an IO_STATUS_BLOCK to guest memory.
fn write_iosb(io_status_ptr: usize, status: NtStatus, info: usize) {
    if io_status_ptr != 0 {
        let iosb = IoStatusBlock {
            status: status.0,
            _pad: 0,
            information: info as u64,
        };
        unsafe {
            core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
        }
    }
}

/// Map a Win32 error code to an NTSTATUS value.
fn map_win32_error_to_ntstatus(win_err: u32) -> NtStatus {
    match win_err {
        2 => NtStatus::STATUS_OBJECT_NAME_NOT_FOUND, // ERROR_FILE_NOT_FOUND
        3 => NtStatus::STATUS_OBJECT_PATH_NOT_FOUND, // ERROR_PATH_NOT_FOUND
        5 => NtStatus::STATUS_ACCESS_DENIED,         // ERROR_ACCESS_DENIED
        32 => NtStatus::STATUS_SHARING_VIOLATION,    // ERROR_SHARING_VIOLATION
        80 => NtStatus::STATUS_OBJECT_NAME_COLLISION, // ERROR_FILE_EXISTS
        183 => NtStatus::STATUS_OBJECT_NAME_COLLISION, // ERROR_ALREADY_EXISTS
        _ => NtStatus::STATUS_UNSUCCESSFUL,
    }
}

// ========================================================================
// NtQueryVolumeInformationFile
// ========================================================================

/// NtQueryVolumeInformationFile — return basic volume metadata.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryVolumeInformationFile(
///     HANDLE FileHandle,                        // r10
///     PIO_STATUS_BLOCK IoStatusBlock,           // rdx
///     PVOID FsInformation,                      // r8
///     ULONG Length,                             // r9
///     FS_INFORMATION_CLASS FsInformationClass   // [rsp+0x28]
/// );
/// ```
pub(crate) fn nt_query_volume_information_file(
    ctx: &mut super::super::ExecutionContext,
) -> NtStatus {
    let args = super::NtSyscallArgs::from_ctx(ctx);
    let _file_handle = args.arg0 as u32;
    let io_status_ptr = args.arg1;
    let info_ptr = args.arg2;
    let info_length = args.arg3 as u32;

    let info_class = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const u32) };

    match info_class {
        // FileFsDeviceInformation (4) — device type and characteristics.
        4 => {
            // FILE_FS_DEVICE_INFORMATION is 8 bytes: DeviceType(u32) + Characteristics(u32)
            if info_length < 8 || info_ptr == 0 {
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            unsafe {
                // FILE_DEVICE_DISK = 7
                core::ptr::write(info_ptr as *mut u32, 7);
                // No special characteristics
                core::ptr::write((info_ptr + 4) as *mut u32, 0);
            }
            write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 8);
            NtStatus::STATUS_SUCCESS
        }
        // FileFsSizeInformation (3) — total/available units.
        3 => {
            // FILE_FS_SIZE_INFORMATION: 24 bytes
            if info_length < 24 || info_ptr == 0 {
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            unsafe {
                // TotalAllocationUnits: large number
                core::ptr::write(info_ptr as *mut i64, 0x1_0000_0000);
                // AvailableAllocationUnits
                core::ptr::write((info_ptr + 8) as *mut i64, 0x8000_0000);
                // SectorsPerAllocationUnit
                core::ptr::write((info_ptr + 16) as *mut u32, 8);
                // BytesPerSector
                core::ptr::write((info_ptr + 20) as *mut u32, 512);
            }
            write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, 24);
            NtStatus::STATUS_SUCCESS
        }
        _ => NtStatus::STATUS_INVALID_INFO_CLASS,
    }
}

// ========================================================================
// NtQueryDirectoryFile
// ========================================================================

/// NtQueryDirectoryFile — enumerate directory entries.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryDirectoryFile(
///     HANDLE FileHandle,                 // r10
///     HANDLE Event,                      // rdx
///     PIO_APC_ROUTINE ApcRoutine,        // r8
///     PVOID ApcContext,                   // r9
///     PIO_STATUS_BLOCK IoStatusBlock,     // [rsp+0x28]
///     PVOID FileInformation,             // [rsp+0x30]
///     ULONG Length,                      // [rsp+0x38]
///     FILE_INFORMATION_CLASS InfoClass,   // [rsp+0x40]
///     BOOLEAN ReturnSingleEntry,         // [rsp+0x48]
///     PUNICODE_STRING FileName,          // [rsp+0x50]
///     BOOLEAN RestartScan                // [rsp+0x58]
/// );
/// ```
///
/// Supports FileDirectoryInformation (1), FileBothDirectoryInformation (3),
/// and FileIdBothDirectoryInformation (37).
/// Tracks enumeration state per directory handle for forward progress.
pub(crate) fn nt_query_directory_file(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut crate::handle_table::HandleTable,
) -> NtStatus {
    use crate::handle_table::DirEnumEntry;

    let args = super::NtSyscallArgs::from_ctx(ctx);
    let file_handle = args.arg0 as u32;

    let io_status_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let info_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const usize) };
    let info_length = unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const u32) };
    let info_class = unsafe { core::ptr::read((ctx.regs.rsp + 0x40) as *const u32) };
    let return_single = unsafe { core::ptr::read((ctx.regs.rsp + 0x48) as *const u8) } != 0;
    let filename_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x50) as *const usize) };
    let restart_scan = unsafe { core::ptr::read((ctx.regs.rsp + 0x58) as *const u8) } != 0;

    if info_ptr == 0 || info_length < 72 {
        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
    }

    // Only support FileDirectoryInformation(1), FileBothDirectoryInformation(3),
    // and FileIdBothDirectoryInformation(37).
    if info_class != 1 && info_class != 3 && info_class != 37 {
        write_iosb(io_status_ptr, NtStatus::STATUS_INVALID_INFO_CLASS, 0);
        return NtStatus::STATUS_INVALID_INFO_CLASS;
    }

    // Verify it's a directory handle, then populate entries and pack buffer.
    if let Some(NtObject::Directory {
        path,
        enum_entries,
        enum_index,
    }) = handles.get_mut(file_handle)
    {
        // Restart scan or first call — (re)populate from host filesystem.
        if restart_scan || enum_entries.is_empty() {
            let Some(host_dir) = translate_nt_path(path) else {
                write_iosb(io_status_ptr, NtStatus::STATUS_OBJECT_PATH_NOT_FOUND, 0);
                return NtStatus::STATUS_OBJECT_PATH_NOT_FOUND;
            };

            let filter = if filename_ptr != 0 {
                read_unicode_string_from_guest(filename_ptr)
            } else {
                None
            };

            let search_pattern = if let Some(ref f) = filter {
                alloc::format!("{host_dir}\\{f}")
            } else {
                alloc::format!("{host_dir}\\*")
            };

            let host_entries = host::find_files(&search_pattern);
            *enum_entries = host_entries
                .into_iter()
                .map(|e| DirEnumEntry {
                    name: e.name,
                    attributes: e.attributes,
                    file_size: e.file_size,
                    creation_time: e.creation_time,
                    last_access_time: e.last_access_time,
                    last_write_time: e.last_write_time,
                })
                .collect();
            *enum_index = 0;
        }

        // Check if enumeration is exhausted.
        if *enum_index >= enum_entries.len() {
            write_iosb(io_status_ptr, NtStatus::STATUS_NO_MORE_FILES, 0);
            return NtStatus::STATUS_NO_MORE_FILES;
        }

        // Pack entries into the output buffer.
        // Info class layout:
        //   1 = FileDirectoryInformation — 64-byte header + FileName
        //   3 = FileBothDirectoryInformation — 94-byte header + FileName
        //   37 = FileIdBothDirectoryInformation — 104-byte header + FileName
        let (is_both, has_file_id) = match info_class {
            3 => (true, false),
            37 => (true, true),
            1 => (false, false),
            _ => unreachable!(), // rejected by early check above
        };
        let header_size: usize = if has_file_id {
            104 // FileBothDir(94) + padding(2) + FileId(8)
        } else if is_both {
            94
        } else {
            64
        };

        let buf_base = info_ptr;
        let buf_end = info_ptr + info_length as usize;
        let mut offset: usize = 0;
        let mut prev_entry_offset: usize = 0;
        let mut count = 0;

        while *enum_index < enum_entries.len() {
            let entry = &enum_entries[*enum_index];
            let name_u16: alloc::vec::Vec<u16> = entry.name.encode_utf16().collect();
            let name_bytes = name_u16.len() * 2;
            let entry_size = (header_size + name_bytes + 7) & !7;

            if buf_base + offset + entry_size > buf_end {
                break;
            }

            let entry_ptr = buf_base + offset;
            // Safety: we verified the buffer is large enough.
            unsafe {
                core::ptr::write_bytes(entry_ptr as *mut u8, 0, entry_size);

                core::ptr::write((entry_ptr + 8) as *mut i64, entry.creation_time);
                core::ptr::write((entry_ptr + 16) as *mut i64, entry.last_access_time);
                core::ptr::write((entry_ptr + 24) as *mut i64, entry.last_write_time);
                core::ptr::write((entry_ptr + 32) as *mut i64, entry.last_write_time);
                core::ptr::write((entry_ptr + 40) as *mut i64, entry.file_size);
                let alloc_size = (entry.file_size + 4095) & !4095;
                core::ptr::write((entry_ptr + 48) as *mut i64, alloc_size);
                core::ptr::write((entry_ptr + 56) as *mut u32, entry.attributes);
                core::ptr::write((entry_ptr + 60) as *mut u32, name_bytes as u32);

                if has_file_id {
                    // FileIdBothDirectoryInformation: FileName at offset 104.
                    // FileId (i64) at offset 96 — generate a unique synthetic ID
                    // by hashing the filename (FNV-1a).
                    let file_id = {
                        let mut h: u64 = 0xcbf29ce484222325;
                        for w in &name_u16 {
                            let bytes = w.to_le_bytes();
                            for &b in &bytes {
                                h ^= b as u64;
                                h = h.wrapping_mul(0x100000001b3);
                            }
                        }
                        h as i64
                    };
                    core::ptr::write((entry_ptr + 96) as *mut i64, file_id);
                    core::ptr::copy_nonoverlapping(
                        name_u16.as_ptr() as *const u8,
                        (entry_ptr + 104) as *mut u8,
                        name_bytes,
                    );
                } else if is_both {
                    // FileBothDirectoryInformation: FileName at offset 94.
                    core::ptr::copy_nonoverlapping(
                        name_u16.as_ptr() as *const u8,
                        (entry_ptr + 94) as *mut u8,
                        name_bytes,
                    );
                } else {
                    // FileDirectoryInformation: FileName at offset 64.
                    core::ptr::copy_nonoverlapping(
                        name_u16.as_ptr() as *const u8,
                        (entry_ptr + 64) as *mut u8,
                        name_bytes,
                    );
                }

                if count > 0 {
                    core::ptr::write(
                        (buf_base + prev_entry_offset) as *mut u32,
                        (offset - prev_entry_offset) as u32,
                    );
                }
            }

            prev_entry_offset = offset;
            offset += entry_size;
            count += 1;
            *enum_index += 1;

            if return_single {
                break;
            }
        }

        if count == 0 {
            // No entries fit in the buffer. If the enumeration isn't exhausted,
            // this means the buffer is too small — not that the directory is empty.
            if *enum_index < enum_entries.len() {
                write_iosb(io_status_ptr, NtStatus::STATUS_BUFFER_OVERFLOW, 0);
                return NtStatus::STATUS_BUFFER_OVERFLOW;
            }
            write_iosb(io_status_ptr, NtStatus::STATUS_NO_MORE_FILES, 0);
            return NtStatus::STATUS_NO_MORE_FILES;
        }

        write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, offset);
        NtStatus::STATUS_SUCCESS
    } else {
        write_iosb(io_status_ptr, NtStatus::STATUS_INVALID_HANDLE, 0);
        NtStatus::STATUS_INVALID_HANDLE
    }
}

// ========================================================================
// NtOpenFile
// ========================================================================

/// NtOpenFile — open an existing file.
///
/// NT signature:
/// ```text
/// NTSTATUS NtOpenFile(
///     PHANDLE FileHandle,                 // r10 (out)
///     ACCESS_MASK DesiredAccess,           // rdx
///     POBJECT_ATTRIBUTES ObjectAttributes, // r8
///     PIO_STATUS_BLOCK IoStatusBlock,      // r9
///     ULONG ShareAccess,                  // [rsp+0x28]
///     ULONG OpenOptions                   // [rsp+0x30]
/// );
/// ```
///
/// During ntdll-driven initialization, ntdll's loader calls NtOpenFile to
/// open DLL files. We first check the tar archive (dll_tar_files) and
/// return a `MemoryFile` handle if found; otherwise fall back to the host.
pub(crate) fn nt_open_file(
    ctx: &mut super::super::ExecutionContext,
    handles: &mut HandleTable,
    dll_tar_files: &std::sync::Mutex<
        Option<alloc::collections::BTreeMap<alloc::string::String, alloc::vec::Vec<u8>>>,
    >,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_ptr = args.arg0;
    let _desired_access = args.arg1 as u32;
    let obj_attr_ptr = args.arg2;
    let io_status_ptr = args.arg3;

    // Stack arguments.
    let share_access = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const u32) };
    let open_options = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const u32) };

    if handle_out_ptr == 0 || obj_attr_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Read OBJECT_ATTRIBUTES from guest memory.
    let obj_attr = unsafe { core::ptr::read(obj_attr_ptr as *const ObjectAttributes) };

    // Read the path from UNICODE_STRING.
    let Some(nt_path) = read_unicode_string_from_guest(obj_attr.object_name as usize) else {
        return NtStatus::STATUS_OBJECT_NAME_INVALID;
    };

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!("NT shim: NtOpenFile path={nt_path:?}\n");
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    // Extract the filename (last path component) for tar lookup.
    let filename = nt_path
        .rsplit('\\')
        .next()
        .unwrap_or(&nt_path)
        .to_ascii_lowercase();

    // Check if the file is available in the DLL tar archive.
    let tar_data = {
        let tar_guard = dll_tar_files.lock().unwrap();
        if let Some(ref files) = *tar_guard {
            files.get(&filename).cloned()
        } else {
            None
        }
    };

    if let Some(data) = tar_data {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtOpenFile serving '{}' from tar ({} bytes)\n",
                filename,
                data.len()
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }

        let handle = handles.insert(NtObject::MemoryFile {
            path: nt_path,
            data: Arc::new(data),
            position: Arc::new(AtomicU64::new(0)),
        });
        unsafe {
            core::ptr::write(handle_out_ptr as *mut u32, handle);
        }
        if io_status_ptr != 0 {
            let iosb = IoStatusBlock {
                status: NtStatus::STATUS_SUCCESS.0,
                _pad: 0,
                information: 1, // FILE_OPENED
            };
            unsafe {
                core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
            }
        }
        return NtStatus::STATUS_SUCCESS;
    }

    // Not in tar — check if it's a directory open.
    let is_directory = open_options & file_options::FILE_DIRECTORY_FILE != 0;

    // Translate NT path to host path.
    let Some(host_path) = translate_nt_path(&nt_path) else {
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!("NT shim: NtOpenFile path not translatable: {nt_path:?}\n");
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
    };

    if is_directory {
        let attrs = host::get_file_attributes(&host_path);
        if attrs == host::INVALID_FILE_ATTRIBUTES || attrs & host::FILE_ATTRIBUTE_DIRECTORY == 0 {
            return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
        }
        let handle = handles.insert(NtObject::Directory {
            path: nt_path,
            enum_entries: alloc::vec::Vec::new(),
            enum_index: 0,
        });
        unsafe {
            core::ptr::write(handle_out_ptr as *mut u32, handle);
        }
        if io_status_ptr != 0 {
            let iosb = IoStatusBlock {
                status: NtStatus::STATUS_SUCCESS.0,
                _pad: 0,
                information: 1, // FILE_OPENED
            };
            unsafe {
                core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
            }
        }
        return NtStatus::STATUS_SUCCESS;
    }

    // Open as a regular file via host pass-through.
    let host_handle = host::open_file(
        &host_path,
        true,  // read access
        false, // no write
        3,     // OPEN_EXISTING
        share_access,
        0x80, // FILE_ATTRIBUTE_NORMAL
    );

    if host_handle == host::INVALID_HANDLE {
        let win_err = host::get_last_error();
        return map_win32_error_to_ntstatus(win_err);
    }

    let handle = handles.insert(NtObject::File {
        path: nt_path,
        host_handle,
        position: Arc::new(AtomicU64::new(0)),
    });
    unsafe {
        core::ptr::write(handle_out_ptr as *mut u32, handle);
    }
    if io_status_ptr != 0 {
        let iosb = IoStatusBlock {
            status: NtStatus::STATUS_SUCCESS.0,
            _pad: 0,
            information: 1, // FILE_OPENED
        };
        unsafe {
            core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
        }
    }
    NtStatus::STATUS_SUCCESS
}

// ========================================================================
// NtReadFile for MemoryFile handles
// ========================================================================

/// NtReadFile — read from an in-memory file (DLLs served from tar).
pub(crate) fn nt_read_file_memory(
    ctx: &mut super::super::ExecutionContext,
    data: &[u8],
    position: &Arc<AtomicU64>,
) -> NtStatus {
    // Stack arguments (same layout as NtReadFile for host files).
    let io_status_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let buffer_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const usize) };
    let length = unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const u32) };
    let byte_offset_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x40) as *const usize) };

    if buffer_ptr == 0 || length == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Determine read offset.
    let offset = if byte_offset_ptr != 0 {
        let off = unsafe { core::ptr::read(byte_offset_ptr as *const i64) };
        if off >= 0 {
            off as u64
        } else {
            position.load(Relaxed)
        }
    } else {
        position.load(Relaxed)
    };

    let file_len = data.len() as u64;
    if offset >= file_len {
        // At or past EOF.
        if io_status_ptr != 0 {
            let iosb = IoStatusBlock {
                status: NtStatus::STATUS_END_OF_FILE.0,
                _pad: 0,
                information: 0,
            };
            unsafe {
                core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
            }
        }
        return NtStatus::STATUS_END_OF_FILE;
    }

    let avail = (file_len - offset) as usize;
    let to_read = (length as usize).min(avail);

    // Copy data to guest buffer.
    let src = &data[offset as usize..offset as usize + to_read];
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), buffer_ptr as *mut u8, to_read);
    }

    // Update position.
    position.store(offset + to_read as u64, Relaxed);

    if io_status_ptr != 0 {
        let iosb = IoStatusBlock {
            status: NtStatus::STATUS_SUCCESS.0,
            _pad: 0,
            information: to_read as u64,
        };
        unsafe {
            core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
        }
    }
    NtStatus::STATUS_SUCCESS
}

/// NtQueryInformationFile for MemoryFile handles.
pub(crate) fn nt_query_information_file_memory(
    ctx: &mut super::super::ExecutionContext,
    data_len: u64,
    position: &Arc<AtomicU64>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let io_status_ptr = args.arg1;

    // Stack args for NtQueryInformationFile.
    let buffer_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let buffer_len = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const u32) };
    let info_class = unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const u32) };

    match info_class {
        // FileStandardInformation (5)
        5 => {
            if buffer_len < core::mem::size_of::<FileStandardInformation>() as u32 {
                return NtStatus::STATUS_BUFFER_TOO_SMALL;
            }
            let info = FileStandardInformation {
                allocation_size: data_len as i64,
                end_of_file: data_len as i64,
                number_of_links: 1,
                delete_pending: 0,
                directory: 0,
                _pad: [0; 2],
            };
            unsafe {
                core::ptr::write(buffer_ptr as *mut FileStandardInformation, info);
            }
            if io_status_ptr != 0 {
                let iosb = IoStatusBlock {
                    status: NtStatus::STATUS_SUCCESS.0,
                    _pad: 0,
                    information: core::mem::size_of::<FileStandardInformation>() as u64,
                };
                unsafe {
                    core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // FilePositionInformation (14)
        14 => {
            if buffer_len < core::mem::size_of::<FilePositionInformation>() as u32 {
                return NtStatus::STATUS_BUFFER_TOO_SMALL;
            }
            let info = FilePositionInformation {
                current_byte_offset: position.load(Relaxed) as i64,
            };
            unsafe {
                core::ptr::write(buffer_ptr as *mut FilePositionInformation, info);
            }
            if io_status_ptr != 0 {
                let iosb = IoStatusBlock {
                    status: NtStatus::STATUS_SUCCESS.0,
                    _pad: 0,
                    information: core::mem::size_of::<FilePositionInformation>() as u64,
                };
                unsafe {
                    core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        other => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "NT shim: NtQueryInformationFile(MemoryFile) unhandled class {other}\n"
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            NtStatus::STATUS_NOT_IMPLEMENTED
        }
    }
}
