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
// NT-style wildcard matching
// ========================================================================

/// Match a filename against an NT wildcard pattern (case-insensitive).
///
/// Supports `*` (match zero or more characters), `?` (match exactly one
/// character), and the DOS-era `*.*` idiom which matches everything.
/// Both `name` and `pattern` must already be lowercased by the caller.
pub(crate) fn nt_wildcard_match(name: &str, pattern: &str) -> bool {
    // Common fast paths.
    if pattern == "*" || pattern == "*.*" {
        return true;
    }
    glob_match(name.as_bytes(), pattern.as_bytes())
}

/// Recursive glob matcher for `*` and `?` wildcards.
fn glob_match(name: &[u8], pattern: &[u8]) -> bool {
    let mut ni = 0;
    let mut pi = 0;
    let mut star_pi = usize::MAX; // pattern index after last '*'
    let mut star_ni = 0; // name index when last '*' was seen

    while ni < name.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == name[ni]) {
            ni += 1;
            pi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi + 1;
            star_ni = ni;
            pi += 1;
        } else if star_pi != usize::MAX {
            // Backtrack: let the '*' consume one more character.
            star_ni += 1;
            ni = star_ni;
            pi = star_pi;
        } else {
            return false;
        }
    }
    // Consume trailing '*' in pattern.
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

// ========================================================================
// NT path translation
// ========================================================================

/// Result of translating an NT object path.
pub(crate) enum TranslatedPath {
    /// A VFS filesystem path (e.g., `/c/windows/system32/ntdll.dll`).
    Vfs(String),
    /// A device path routed through DeviceFS.
    Device(String),
    /// A registry path — not handled by VFS.
    Registry(String),
}

/// Translate an NT object path to a VFS path.
///
/// All VFS paths are lowercased (VFS is case-sensitive; Windows is not).
/// Backslashes are converted to forward slashes.
///
/// | NT Path                              | VFS Path                        |
/// |--------------------------------------|---------------------------------|
/// | `\??\C:\Windows\System32\ntdll.dll`  | `/c/windows/system32/ntdll.dll` |
/// | `\DosDevices\C:\foo.txt`             | `/c/foo.txt`                    |
/// | `\SystemRoot\System32\ntdll.dll`     | `/c/windows/system32/ntdll.dll` |
/// | `C:\Windows\System32\ntdll.dll`      | `/c/windows/system32/ntdll.dll` |
/// | `\Device\ConDrv\Input`               | `/dev/stdin`                    |
/// | `\Device\ConDrv\Output`              | `/dev/stdout`                   |
/// | `\??\NUL`                            | `/dev/null`                     |
/// | `\??\CON`                            | `/dev/stdout`                   |
/// | `\??\CONIN$`                         | `/dev/stdin`                    |
/// | `\??\CONOUT$`                        | `/dev/stdout`                   |
///
/// Returns `None` for paths that can't be mapped.
pub(crate) fn translate_nt_path(nt_path: &str) -> Option<TranslatedPath> {
    // \Device\ConDrv paths → DeviceFS
    if let Some(rest) = nt_path.strip_prefix("\\Device\\ConDrv\\") {
        let lower = rest.to_ascii_lowercase();
        return match lower.as_str() {
            "input" | "currentin" => Some(TranslatedPath::Device(String::from("/dev/stdin"))),
            "output" | "currentout" => Some(TranslatedPath::Device(String::from("/dev/stdout"))),
            _ => Some(TranslatedPath::Device(String::from("/dev/stdout"))),
        };
    }

    // Registry paths
    if nt_path.starts_with("\\Registry\\") || nt_path.starts_with("\\REGISTRY\\") {
        return Some(TranslatedPath::Registry(String::from(nt_path)));
    }

    // \??\<something> paths
    if let Some(rest) = nt_path.strip_prefix("\\??\\") {
        // Special device names
        let upper = rest.to_ascii_uppercase();
        if upper == "NUL" {
            return Some(TranslatedPath::Device(String::from("/dev/null")));
        }
        if upper == "CON" || upper == "CONOUT$" {
            return Some(TranslatedPath::Device(String::from("/dev/stdout")));
        }
        if upper == "CONIN$" {
            return Some(TranslatedPath::Device(String::from("/dev/stdin")));
        }

        // UNC path: \??\UNC\server\share → //server/share
        if let Some(unc) = rest.strip_prefix("UNC\\") {
            let vfs = alloc::format!("//{}", unc.replace('\\', "/").to_ascii_lowercase());
            return Some(TranslatedPath::Vfs(vfs));
        }

        // Drive path: \??\C:\path → /c/path
        return drive_path_to_vfs(rest);
    }

    // \DosDevices\C:\path → /c/path
    if let Some(rest) = nt_path.strip_prefix("\\DosDevices\\") {
        return drive_path_to_vfs(rest);
    }

    // \SystemRoot\path → /c/windows/path
    if let Some(rest) = nt_path.strip_prefix("\\SystemRoot\\") {
        let vfs = alloc::format!(
            "/c/windows/{}",
            rest.replace('\\', "/").to_ascii_lowercase()
        );
        return Some(TranslatedPath::Vfs(vfs));
    }
    if nt_path == "\\SystemRoot" {
        return Some(TranslatedPath::Vfs(String::from("/c/windows")));
    }

    // Bare drive path: C:\path → /c/path
    if nt_path.len() >= 3 && nt_path.as_bytes()[1] == b':' {
        return drive_path_to_vfs(nt_path);
    }

    None
}

/// Convert a drive-letter path like `C:\foo\bar` to VFS `/c/foo/bar`.
pub(crate) fn drive_path_to_vfs(path: &str) -> Option<TranslatedPath> {
    if path.len() < 2 || path.as_bytes()[1] != b':' {
        return None;
    }
    let drive = (path.as_bytes()[0] as char).to_ascii_lowercase();
    let rest = if path.len() > 2 {
        &path[2..] // includes leading backslash
    } else {
        ""
    };
    let vfs = alloc::format!("/{drive}{}", rest.replace('\\', "/").to_ascii_lowercase());
    Some(TranslatedPath::Vfs(vfs))
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

/// Map a VFS `MkdirError` to the appropriate NTSTATUS.
fn map_mkdir_error(e: litebox::fs::errors::MkdirError) -> NtStatus {
    use litebox::fs::errors::MkdirError;
    match e {
        MkdirError::AlreadyExists => NtStatus::STATUS_OBJECT_NAME_COLLISION,
        MkdirError::ReadOnlyFileSystem => NtStatus::STATUS_ACCESS_DENIED,
        MkdirError::NoWritePerms => NtStatus::STATUS_ACCESS_DENIED,
        MkdirError::Io => NtStatus::STATUS_UNEXPECTED_IO_ERROR,
        MkdirError::PathError(_) => NtStatus::STATUS_OBJECT_NAME_NOT_FOUND,
        _ => NtStatus::STATUS_OBJECT_NAME_NOT_FOUND,
    }
}

fn map_open_error_to_ntstatus(e: &litebox::fs::errors::OpenError) -> NtStatus {
    use litebox::fs::errors::OpenError;
    match e {
        OpenError::PathError(_) => NtStatus::STATUS_OBJECT_PATH_NOT_FOUND,
        OpenError::AccessNotAllowed => NtStatus::STATUS_ACCESS_DENIED,
        OpenError::NoWritePerms => NtStatus::STATUS_ACCESS_DENIED,
        OpenError::ReadOnlyFileSystem => NtStatus::STATUS_ACCESS_DENIED,
        OpenError::AlreadyExists => NtStatus::STATUS_OBJECT_NAME_COLLISION,
        OpenError::NotADirectory => NtStatus::STATUS_NOT_A_DIRECTORY,
        OpenError::Io => NtStatus::STATUS_UNEXPECTED_IO_ERROR,
        _ => NtStatus::STATUS_OBJECT_NAME_NOT_FOUND,
    }
}

fn map_readdir_error_to_ntstatus(e: &litebox::fs::errors::ReadDirError) -> NtStatus {
    use litebox::fs::errors::ReadDirError;
    match e {
        ReadDirError::ClosedFd => NtStatus::STATUS_INVALID_HANDLE,
        ReadDirError::NotADirectory => NtStatus::STATUS_NOT_A_DIRECTORY,
        ReadDirError::Io => NtStatus::STATUS_UNEXPECTED_IO_ERROR,
        _ => NtStatus::STATUS_UNEXPECTED_IO_ERROR,
    }
}

/// Helper: insert a `NtObject::Directory` handle and write the IOSB.
fn insert_directory_handle(
    handles: &mut HandleTable,
    nt_path: &str,
    handle_out_ptr: usize,
    io_status_ptr: usize,
    iosb_information: u64,
) -> NtStatus {
    let dir_handle = handles.insert(NtObject::Directory {
        path: alloc::string::String::from(nt_path),
        enum_entries: alloc::vec::Vec::new(),
        enum_index: 0,
    });
    unsafe {
        core::ptr::write(handle_out_ptr as *mut u32, dir_handle);
    }
    if io_status_ptr != 0 {
        let iosb = IoStatusBlock {
            status: NtStatus::STATUS_SUCCESS.0,
            _pad: 0,
            information: iosb_information,
        };
        unsafe {
            core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
        }
    }
    NtStatus::STATUS_SUCCESS
}

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
    shared: &super::super::NtSharedState,
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

    // Translate NT path using the VFS-aware translator.
    let translated = translate_nt_path(&nt_path);

    // Try VFS path first if VFS is available.
    if let Some(ref translated) = translated
        && let Some(fs) = shared.fs.get()
    {
        let vfs_path = match translated {
            TranslatedPath::Vfs(p) => Some(p.as_str()),
            TranslatedPath::Device(p) => Some(p.as_str()),
            TranslatedPath::Registry(_) => None,
        };

        if let Some(path) = vfs_path {
            use litebox::fs::FileSystem as _;

            if is_directory {
                // Directory operations on VFS-translatable paths stay in VFS.
                let is_vfs_dir = fs
                    .file_status(path)
                    .is_ok_and(|s| s.file_type == litebox::fs::FileType::Directory);

                match create_disposition {
                    file_disposition::FILE_CREATE => {
                        if is_vfs_dir {
                            if io_status_ptr != 0 {
                                write_iosb(
                                    io_status_ptr,
                                    NtStatus::STATUS_OBJECT_NAME_COLLISION,
                                    0,
                                );
                            }
                            return NtStatus::STATUS_OBJECT_NAME_COLLISION;
                        }
                        // Create in VFS.
                        if let Err(e) = fs.mkdir(path, litebox::fs::Mode::RWXU) {
                            return map_mkdir_error(e);
                        }
                        return insert_directory_handle(
                            handles,
                            &nt_path,
                            handle_out_ptr,
                            io_status_ptr,
                            2, // FILE_CREATED
                        );
                    }
                    file_disposition::FILE_OPEN => {
                        if is_vfs_dir {
                            return insert_directory_handle(
                                handles,
                                &nt_path,
                                handle_out_ptr,
                                io_status_ptr,
                                1, // FILE_OPENED
                            );
                        }
                        return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
                    }
                    file_disposition::FILE_OPEN_IF => {
                        if is_vfs_dir {
                            return insert_directory_handle(
                                handles,
                                &nt_path,
                                handle_out_ptr,
                                io_status_ptr,
                                1, // FILE_OPENED
                            );
                        }
                        // Create in VFS.
                        if let Err(e) = fs.mkdir(path, litebox::fs::Mode::RWXU) {
                            return map_mkdir_error(e);
                        }
                        return insert_directory_handle(
                            handles,
                            &nt_path,
                            handle_out_ptr,
                            io_status_ptr,
                            2, // FILE_CREATED
                        );
                    }
                    _ => {
                        // FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF —
                        // treat as "open existing" for directories.
                        if is_vfs_dir {
                            return insert_directory_handle(
                                handles,
                                &nt_path,
                                handle_out_ptr,
                                io_status_ptr,
                                1, // FILE_OPENED
                            );
                        }
                        return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
                    }
                }
            }

            // Map NT disposition to VFS OFlags.
            let mut oflags = litebox::fs::OFlags::empty();
            match create_disposition {
                file_disposition::FILE_OPEN => {
                    // Open existing — no CREAT
                    oflags |= litebox::fs::OFlags::RDONLY;
                }
                file_disposition::FILE_CREATE => {
                    oflags |= litebox::fs::OFlags::CREAT | litebox::fs::OFlags::EXCL;
                }
                file_disposition::FILE_OPEN_IF => {
                    oflags |= litebox::fs::OFlags::CREAT;
                }
                file_disposition::FILE_OVERWRITE => {
                    oflags |= litebox::fs::OFlags::TRUNC;
                }
                file_disposition::FILE_OVERWRITE_IF | file_disposition::FILE_SUPERSEDE => {
                    oflags |= litebox::fs::OFlags::CREAT | litebox::fs::OFlags::TRUNC;
                }
                _ => {}
            }

            // Determine read/write from DesiredAccess.
            let want_read = desired_access & 0x8000_0001 != 0;
            let want_write = desired_access & 0x4000_0006 != 0;
            if want_write {
                if want_read {
                    oflags |= litebox::fs::OFlags::RDWR;
                } else {
                    oflags |= litebox::fs::OFlags::WRONLY;
                }
            } else {
                oflags |= litebox::fs::OFlags::RDONLY;
            }

            match fs.open(
                path,
                oflags,
                litebox::fs::Mode::RUSR | litebox::fs::Mode::WUSR,
            ) {
                Ok(typed_fd) => {
                    let raw_fd = {
                        let mut rds = shared.raw_fds.lock();
                        rds.fd_into_raw_integer(typed_fd)
                    };
                    let handle = handles.insert(NtObject::File {
                        path: nt_path,
                        position: Arc::new(AtomicU64::new(0)),
                        raw_fd,
                        vfs_refcount: Arc::new(core::sync::atomic::AtomicUsize::new(1)),
                    });
                    unsafe {
                        core::ptr::write(handle_out_ptr as *mut u32, handle);
                    }
                    if io_status_ptr != 0 {
                        let info = match create_disposition {
                            file_disposition::FILE_CREATE => 2, // FILE_CREATED
                            file_disposition::FILE_OPEN => 1,   // FILE_OPENED
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
                    #[cfg(debug_assertions)]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtCreateFile VFS OK path={path:?} raw_fd={raw_fd}\n",
                        ));
                    }
                    return NtStatus::STATUS_SUCCESS;
                }
                Err(e) => {
                    // VFS open failed — authoritative error, no host fallback.
                    #[cfg(debug_assertions)]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtCreateFile VFS error path={path:?} err={e:?}\n",
                        ));
                    }
                    return map_open_error_to_ntstatus(&e);
                }
            }
        }
    }

    // Path not translatable to VFS — no host fallback.
    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!("NT shim: NtCreateFile path not translatable: {nt_path:?}\n");
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }
    NtStatus::STATUS_OBJECT_NAME_NOT_FOUND
}

// ========================================================================
// NtReadFile / NtWriteFile — VFS path
// ========================================================================

/// NtReadFile — read from a VFS file descriptor.
///
/// Called after handle-table lock is dropped. Uses the raw_fd to look up
/// the TypedFd in RawDescriptorStorage and reads via the VFS.
pub(crate) fn nt_read_file_vfs(
    ctx: &mut super::super::ExecutionContext,
    raw_fd: usize,
    position: &alloc::sync::Arc<AtomicU64>,
    shared: &super::super::NtSharedState,
) -> NtStatus {
    let io_status_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let buffer_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const usize) };
    let length = unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const u32) };
    let byte_offset_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x40) as *const usize) };

    if buffer_ptr == 0 || length == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    const FILE_USE_FILE_POINTER_POSITION: i64 = -2;

    let (read_offset, advance_pos) = if byte_offset_ptr != 0 {
        let offset = unsafe { core::ptr::read(byte_offset_ptr as *const i64) };
        if offset >= 0 {
            (Some(offset as u64), false) // positional read
        } else if offset == FILE_USE_FILE_POINTER_POSITION {
            let pos = position.load(Relaxed);
            (Some(pos), true) // sequential read
        } else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }
    } else {
        let pos = position.load(Relaxed);
        (Some(pos), true) // no offset pointer → sequential
    };

    let buf = unsafe { core::slice::from_raw_parts_mut(buffer_ptr as *mut u8, length as usize) };

    // Look up the TypedFd from RDS and do the read.
    let Some(fs) = shared.fs.get() else {
        return NtStatus::STATUS_INVALID_HANDLE;
    };

    let typed_fd = {
        let rds = shared.raw_fds.lock();
        match rds.fd_from_raw_integer::<super::super::NtFS>(raw_fd) {
            Ok(fd) => fd,
            Err(_) => return NtStatus::STATUS_INVALID_HANDLE,
        }
    };

    use litebox::fs::FileSystem as _;
    match fs.read(&typed_fd, buf, read_offset.map(|o| o as usize)) {
        Ok(bytes_read) => {
            if advance_pos {
                position.fetch_add(bytes_read as u64, Relaxed);
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
        }
        Err(_) => NtStatus::STATUS_END_OF_FILE,
    }
}

/// NtWriteFile — write to a VFS file descriptor.
pub(crate) fn nt_write_file_vfs(
    ctx: &mut super::super::ExecutionContext,
    raw_fd: usize,
    position: &alloc::sync::Arc<AtomicU64>,
    shared: &super::super::NtSharedState,
) -> NtStatus {
    let io_status_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };
    let buffer_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const usize) };
    let length = unsafe { core::ptr::read((ctx.regs.rsp + 0x38) as *const u32) };
    let byte_offset_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x40) as *const usize) };

    if buffer_ptr == 0 || length == 0 {
        if io_status_ptr != 0 {
            let iosb = IoStatusBlock {
                status: NtStatus::STATUS_SUCCESS.0,
                _pad: 0,
                information: 0,
            };
            unsafe {
                core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
            }
        }
        return NtStatus::STATUS_SUCCESS;
    }

    let (write_offset, advance_pos) = if byte_offset_ptr != 0 {
        let offset = unsafe { core::ptr::read(byte_offset_ptr as *const i64) };
        if offset >= 0 {
            (Some(offset as u64), false)
        } else {
            let pos = position.load(Relaxed);
            (Some(pos), true)
        }
    } else {
        let pos = position.load(Relaxed);
        (Some(pos), true)
    };

    let buf = unsafe { core::slice::from_raw_parts(buffer_ptr as *const u8, length as usize) };

    let Some(fs) = shared.fs.get() else {
        return NtStatus::STATUS_INVALID_HANDLE;
    };

    let typed_fd = {
        let rds = shared.raw_fds.lock();
        match rds.fd_from_raw_integer::<super::super::NtFS>(raw_fd) {
            Ok(fd) => fd,
            Err(_) => return NtStatus::STATUS_INVALID_HANDLE,
        }
    };

    use litebox::fs::FileSystem as _;
    match fs.write(&typed_fd, buf, write_offset.map(|o| o as usize)) {
        Ok(bytes_written) => {
            if advance_pos {
                position.fetch_add(bytes_written as u64, Relaxed);
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
        Err(_) => NtStatus::STATUS_UNSUCCESSFUL,
    }
}

/// FILE_ATTRIBUTE_DIRECTORY — used for directory metadata.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

// ========================================================================
// NtReadFile — console only; host read path removed (all files via VFS).
// ========================================================================

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
    shared: &super::super::NtSharedState,
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
            raw_fd, position, ..
        } => {
            // All files are now VFS-backed (raw_fd is always Some).
            match info_class {
                // FileBasicInformation (4) — synthesize from VFS.
                4 => {
                    let size = core::mem::size_of::<FileBasicInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    // Return default timestamps for VFS files.
                    let info = FileBasicInformation {
                        file_attributes: 0x80, // FILE_ATTRIBUTE_NORMAL
                        ..FileBasicInformation::default()
                    };
                    unsafe {
                        core::ptr::write(info_ptr as *mut FileBasicInformation, info);
                    }
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                }
                // FileStandardInformation (5) — get size from VFS.
                5 => {
                    let size = core::mem::size_of::<FileStandardInformation>();
                    if (info_length as usize) < size || info_ptr == 0 {
                        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
                    }
                    let file_size = (|| -> Option<i64> {
                        let fs = shared.fs.get()?;
                        let rds = shared.raw_fds.lock();
                        let typed_fd = rds
                            .fd_from_raw_integer::<super::super::NtFS>(*raw_fd)
                            .ok()?;
                        use litebox::fs::FileSystem as _;
                        let st = fs.fd_file_status(&typed_fd).ok()?;
                        Some(st.size as i64)
                    })()
                    .unwrap_or(0);
                    let info = FileStandardInformation {
                        allocation_size: (file_size + 4095) & !4095,
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
                // FilePositionInformation (14) — from cached position.
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
            }
        }
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
                        file_attributes: FILE_ATTRIBUTE_DIRECTORY,
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
        NtObject::File { position, .. } => match info_class {
            // FilePositionInformation (14) — seek. VFS files just update cached position.
            14 => {
                let size = core::mem::size_of::<FilePositionInformation>();
                if (info_length as usize) < size || info_ptr == 0 {
                    return NtStatus::STATUS_INVALID_PARAMETER;
                }
                let info = unsafe { core::ptr::read(info_ptr as *const FilePositionInformation) };
                if info.current_byte_offset >= 0 {
                    position.store(info.current_byte_offset as u64, Relaxed);
                    write_iosb(io_status_ptr, NtStatus::STATUS_SUCCESS, size);
                    NtStatus::STATUS_SUCCESS
                } else {
                    NtStatus::STATUS_INVALID_PARAMETER
                }
            }
            13 => {
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
pub(crate) fn nt_query_attributes_file(
    ctx: &mut super::super::ExecutionContext,
    shared: &super::super::NtSharedState,
) -> NtStatus {
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

    // Try VFS first — only for file paths (not directories).
    if let Some(TranslatedPath::Vfs(ref vfs_path)) = translate_nt_path(&nt_path)
        && let Some(fs) = shared.fs.get()
    {
        use litebox::fs::FileSystem as _;
        if let Ok(status) = fs.file_status(&**vfs_path) {
            if info_ptr != 0 {
                let is_dir = status.file_type == litebox::fs::FileType::Directory;
                let info = FileBasicInformation {
                    file_attributes: if is_dir { 0x10 } else { 0x80 },
                    ..FileBasicInformation::default()
                };
                unsafe {
                    core::ptr::write(info_ptr as *mut FileBasicInformation, info);
                }
            }
            return NtStatus::STATUS_SUCCESS;
        }
        // VFS file_status failed — authoritative, no host fallback.
    }

    // Path not translatable to VFS — not found.
    NtStatus::STATUS_OBJECT_NAME_NOT_FOUND
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
    shared: &super::super::NtSharedState,
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
        // Restart scan or first call — (re)populate entries.
        if restart_scan || enum_entries.is_empty() {
            // Determine if this is a VFS-translatable path AND VFS is available.
            let is_vfs_path = shared.fs.get().is_some()
                && (matches!(
                    drive_path_to_vfs(path),
                    Some(TranslatedPath::Vfs(_) | TranslatedPath::Device(_))
                ) || matches!(
                    translate_nt_path(path),
                    Some(TranslatedPath::Vfs(_) | TranslatedPath::Device(_))
                ));

            // Try VFS first. Returns Ok(entries) on success, Err(status) for
            // real VFS errors, or the outer Option is None if not VFS-translatable.
            let vfs_result: Option<Result<alloc::vec::Vec<DirEnumEntry>, NtStatus>> =
                (|| -> Option<Result<alloc::vec::Vec<DirEnumEntry>, NtStatus>> {
                    let vfs_path = match drive_path_to_vfs(path) {
                        Some(TranslatedPath::Vfs(p)) => p,
                        _ => match translate_nt_path(path) {
                            Some(TranslatedPath::Vfs(p)) => p,
                            _ => return None,
                        },
                    };
                    let fs = shared.fs.get()?;
                    use litebox::fs::FileSystem as _;
                    let dir_fd = match fs.open(
                        &*vfs_path,
                        litebox::fs::OFlags::DIRECTORY | litebox::fs::OFlags::RDONLY,
                        litebox::fs::Mode::empty(),
                    ) {
                        Ok(fd) => fd,
                        Err(ref e) => return Some(Err(map_open_error_to_ntstatus(e))),
                    };
                    let entries = match fs.read_dir(&dir_fd) {
                        Ok(e) => {
                            let _ = fs.close(&dir_fd);
                            e
                        }
                        Err(ref e) => {
                            let _ = fs.close(&dir_fd);
                            return Some(Err(map_readdir_error_to_ntstatus(e)));
                        }
                    };
                    Some(Ok(entries
                        .into_iter()
                        .map(|e| {
                            let is_dir = e.file_type == litebox::fs::FileType::Directory;
                            let file_size = if is_dir {
                                0
                            } else {
                                let full = alloc::format!("{}/{}", vfs_path, e.name);
                                fs.file_status(&*full).map(|s| s.size as i64).unwrap_or(0)
                            };
                            let attrs = if is_dir {
                                0x10 // FILE_ATTRIBUTE_DIRECTORY
                            } else {
                                0x80 // FILE_ATTRIBUTE_NORMAL
                            };
                            DirEnumEntry {
                                name: e.name,
                                attributes: attrs,
                                file_size,
                                creation_time: 0,
                                last_access_time: 0,
                                last_write_time: 0,
                            }
                        })
                        .collect()))
                })();

            match vfs_result {
                Some(Ok(entries)) => {
                    // Apply filename filter if provided.
                    let filter = if filename_ptr != 0 {
                        read_unicode_string_from_guest(filename_ptr)
                    } else {
                        None
                    };
                    *enum_entries = if let Some(ref pattern) = filter {
                        let pat_lower = pattern.to_ascii_lowercase();
                        entries
                            .into_iter()
                            .filter(|e| nt_wildcard_match(&e.name.to_ascii_lowercase(), &pat_lower))
                            .collect()
                    } else {
                        entries
                    };
                }
                Some(Err(status)) => {
                    // Real VFS error — return immediately.
                    write_iosb(io_status_ptr, status, 0);
                    return status;
                }
                None if is_vfs_path => {
                    // VFS-translatable but no fs available — empty result.
                    *enum_entries = alloc::vec::Vec::new();
                }
                None => {
                    // Path not VFS-translatable — no host fallback.
                    write_iosb(io_status_ptr, NtStatus::STATUS_OBJECT_PATH_NOT_FOUND, 0);
                    return NtStatus::STATUS_OBJECT_PATH_NOT_FOUND;
                }
            }
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
    shared: &super::super::NtSharedState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_ptr = args.arg0;
    let _desired_access = args.arg1 as u32;
    let obj_attr_ptr = args.arg2;
    let io_status_ptr = args.arg3;

    // Stack arguments.
    let _share_access = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const u32) };
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

    // ── VFS path ─────────────────────────────────────────────────────
    if let Some(translated) = translate_nt_path(&nt_path) {
        let vfs_path = match &translated {
            TranslatedPath::Vfs(p) => Some(p.as_str()),
            TranslatedPath::Device(p) => Some(p.as_str()),
            TranslatedPath::Registry(_) => None,
        };
        if let (Some(path), Some(fs)) = (vfs_path, shared.fs.get()) {
            let is_directory = open_options & file_options::FILE_DIRECTORY_FILE != 0;

            if is_directory {
                // NtOpenFile is always "open existing" — validate the directory.
                // VFS-translatable paths must not escape to host.
                use litebox::fs::FileSystem as _;
                let is_vfs_dir = fs
                    .file_status(path)
                    .is_ok_and(|s| s.file_type == litebox::fs::FileType::Directory);
                if is_vfs_dir {
                    return insert_directory_handle(
                        handles,
                        &nt_path,
                        handle_out_ptr,
                        io_status_ptr,
                        1, // FILE_OPENED
                    );
                }
                // Directory not found in VFS — authoritative failure.
                return NtStatus::STATUS_OBJECT_NAME_NOT_FOUND;
            }

            use litebox::fs::FileSystem as _;
            match fs.open(
                path,
                litebox::fs::OFlags::RDONLY,
                litebox::fs::Mode::RUSR | litebox::fs::Mode::WUSR,
            ) {
                Ok(typed_fd) => {
                    let raw_fd = {
                        let mut rds = shared.raw_fds.lock();
                        rds.fd_into_raw_integer(typed_fd)
                    };
                    let handle = handles.insert(NtObject::File {
                        path: nt_path,
                        position: Arc::new(AtomicU64::new(0)),
                        raw_fd,
                        vfs_refcount: Arc::new(core::sync::atomic::AtomicUsize::new(1)),
                    });
                    unsafe {
                        core::ptr::write(handle_out_ptr as *mut u32, handle);
                    }
                    if io_status_ptr != 0 {
                        let iosb = IoStatusBlock {
                            status: NtStatus::STATUS_SUCCESS.0,
                            _pad: 0,
                            information: 1,
                        };
                        unsafe {
                            core::ptr::write(io_status_ptr as *mut IoStatusBlock, iosb);
                        }
                    }
                    #[cfg(debug_assertions)]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtOpenFile VFS OK path={path:?} raw_fd={raw_fd}\n",
                        ));
                    }
                    return NtStatus::STATUS_SUCCESS;
                }
                Err(e) => {
                    // VFS open failed — authoritative error, no host fallback.
                    #[cfg(debug_assertions)]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtOpenFile VFS error path={path:?} err={e:?}\n",
                        ));
                    }
                    return map_open_error_to_ntstatus(&e);
                }
            }
        }
    }

    // Path not translatable to VFS — no host fallback.
    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!("NT shim: NtOpenFile path not translatable: {nt_path:?}\n");
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }
    NtStatus::STATUS_OBJECT_NAME_NOT_FOUND
}
