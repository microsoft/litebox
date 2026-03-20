from pathlib import Path
from textwrap import dedent

root = Path(r'C:\Users\wdcui\litebox')


def replace_between(text: str, start_marker: str, end_marker: str, new_block: str) -> str:
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    return text[:start] + new_block + text[end:]


def replace_once(text: str, old: str, new: str) -> str:
    if old not in text:
        raise ValueError(f'old text not found: {old[:80]!r}')
    return text.replace(old, new, 1)


# file.rs
file_path = root / 'litebox_shim_windows' / 'src' / 'syscalls' / 'file.rs'
text = file_path.read_text()
text = replace_once(
    text,
    "use alloc::string::String;\nuse alloc::sync::Arc;\nuse core::sync::atomic::{AtomicU64, Ordering::Relaxed};\n\nuse litebox_common_windows::nt_types::{\n    FileBasicInformation, FilePositionInformation, FileStandardInformation, IoStatusBlock,\n    ObjectAttributes, UnicodeString, file_disposition, file_options,\n};\nuse litebox_common_windows::ntstatus::NtStatus;\n\nuse crate::handle_table::{HandleTable, NtObject};\n\nuse super::NtSyscallArgs;\n",
    "use alloc::string::String;\nuse alloc::sync::Arc;\nuse core::sync::atomic::{AtomicU64, Ordering::Relaxed};\n\nuse litebox::fs::errors::{FileStatusError, MkdirError, OpenError, ReadDirError, ReadError, TruncateError, WriteError};\nuse litebox::fs::{FileStatus, FileSystem as _, FileType as FsFileType, Mode, OFlags};\nuse litebox_common_windows::nt_types::{\n    FileBasicInformation, FilePositionInformation, FileStandardInformation, IoStatusBlock,\n    ObjectAttributes, UnicodeString, file_disposition, file_options,\n};\nuse litebox_common_windows::ntstatus::NtStatus;\n\nuse crate::handle_table::{DirEnumEntry, HandleTable, NtObject};\nuse crate::{RawDescriptorStorage, WindowsFS};\n\nuse super::NtSyscallArgs;\n",
)
text = replace_between(
    text,
    "pub(crate) fn translate_nt_path(nt_path: &str) -> Option<String> {",
    "/// Read a UNICODE_STRING from guest memory and return the string contents.\n",
    dedent(
        '''
        pub(crate) const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

        pub(crate) fn default_file_mode() -> Mode {
            Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH
        }

        pub(crate) fn default_dir_mode() -> Mode {
            Mode::RUSR | Mode::WUSR | Mode::XUSR | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH
        }

        pub(crate) fn open_flags_from_desired_access(desired_access: u32, is_directory: bool) -> OFlags {
            let want_read = desired_access & 0x8000_0001 != 0;
            let want_write = desired_access & 0x4000_0006 != 0;
            let mut flags = if want_write {
                if want_read {
                    OFlags::RDWR
                } else {
                    OFlags::WRONLY
                }
            } else {
                OFlags::RDONLY
            };
            flags |= OFlags::NOCTTY | OFlags::LARGEFILE;
            if desired_access & 0x4 != 0 {
                flags |= OFlags::APPEND;
            }
            if is_directory {
                flags |= OFlags::DIRECTORY;
            }
            flags
        }

        pub(crate) fn file_status_to_attributes(status: &FileStatus) -> u32 {
            match status.file_type {
                FsFileType::Directory => host::FILE_ATTRIBUTE_DIRECTORY,
                _ => FILE_ATTRIBUTE_NORMAL,
            }
        }

        pub(crate) fn wildcard_match_case_insensitive(name: &str, pattern: &str) -> bool {
            let name = name.as_bytes();
            let pattern = pattern.as_bytes();
            let mut name_idx = 0usize;
            let mut pattern_idx = 0usize;
            let mut star_idx = None;
            let mut match_idx = 0usize;

            while name_idx < name.len() {
                if pattern_idx < pattern.len()
                    and (pattern[pattern_idx] == b'?' or bytes([pattern[pattern_idx]]).decode().upper().encode() == bytes([name[name_idx]]).decode().upper().encode())
                {
                    name_idx += 1
                    pattern_idx += 1
                } elif pattern_idx < pattern.len() and pattern[pattern_idx] == b'*':
                    star_idx = pattern_idx
                    pattern_idx += 1
                    match_idx = name_idx
                elif star_idx is not None:
                    pattern_idx = star_idx + 1
                    match_idx += 1
                    name_idx = match_idx
                else:
                    return False

            while pattern_idx < pattern.len() and pattern[pattern_idx] == b'*':
                pattern_idx += 1
            return pattern_idx == pattern.len()

        pub(crate) fn nt_path_to_windows_path(nt_path: &str) -> Option<String> {
            if let Some(rest) = nt_path.strip_prefix("\\??\\") {
                if rest.starts_with("UNC\\") {
                    return Some(String::from("\\\\") + &rest[4..]);
                }
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
            if nt_path.len() >= 2 && nt_path.as_bytes()[1] == b':' {
                return Some(String::from(nt_path));
            }
            None
        }

        pub(crate) fn translate_windows_path_to_vfs(path: &str) -> Option<String> {
            let path = path.strip_prefix("\\\\?\\").unwrap_or(path);
            if path.starts_with("\\\\") {
                return None;
            }
            let bytes = path.as_bytes();
            if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
                let mut out = String::from("/");
                out.push((bytes[0] as char).to_ascii_lowercase());
                for component in path[2..].split(['\\', '/']).filter(|component| !component.is_empty()) {
                    out.push('/');
                    out.push_str(component);
                }
                return Some(out);
            }
            None
        }

        pub(crate) fn translate_nt_path(nt_path: &str) -> Option<String> {
            nt_path_to_windows_path(nt_path).and_then(|path| translate_windows_path_to_vfs(&path))
        }

        fn join_guest_path(base: &str, child: &str) -> String {
            let base = base.trim_end_matches(['\\', '/']);
            let child = child.trim_start_matches(['\\', '/']);
            if base.is_empty() {
                String::from(child)
            } else if child.is_empty() {
                String::from(base)
            } else {
                alloc::format!("{base}\\{child}")
            }
        }

        fn resolve_nt_path(handles: &HandleTable, obj_attr: &ObjectAttributes, raw_path: &str) -> Option<String> {
            let is_absolute = raw_path.starts_with("\\??\\")
                || raw_path.starts_with("\\DosDevices\\")
                || raw_path.starts_with("\\SystemRoot")
                || raw_path.starts_with("\\\\")
                || (raw_path.len() >= 2 && raw_path.as_bytes()[1] == b':');
            if is_absolute {
                return Some(String::from(raw_path));
            }
            if obj_attr.root_directory == 0 {
                return Some(String::from(raw_path));
            }
            let base = match handles.get(obj_attr.root_directory as u32) {
                Some(NtObject::Directory { path, .. })
                | Some(NtObject::File { path, .. })
                | Some(NtObject::MemoryFile { path, .. }) => path,
                _ => return None,
            };
            if raw_path.starts_with('\\') {
                let base_windows = nt_path_to_windows_path(base)?;
                if base_windows.len() >= 2 && base_windows.as_bytes()[1] == b':' {
                    return Some(alloc::format!("\\??\\{}{}", &base_windows[..2], raw_path.replace('/', "\\")));
                }
            }
            Some(join_guest_path(base, raw_path))
        }

        pub(crate) fn lookup_vfs_fd(
            raw_fds: &std::sync::Mutex<RawDescriptorStorage>,
            raw_fd: usize,
        ) -> Result<Arc<litebox::fd::TypedFd<WindowsFS>>, NtStatus> {
            let fd = {
                let raw_fds = raw_fds.lock().unwrap();
                raw_fds
                    .fd_from_raw_integer::<WindowsFS>(raw_fd)
                    .map_err(|_| NtStatus::STATUS_INVALID_HANDLE)?
            };
            Ok(fd)
        }

        fn map_path_error_to_ntstatus(err: &litebox::fs::errors::PathError) -> NtStatus {
            match err {
                litebox::fs::errors::PathError::NoSuchFileOrDirectory
                | litebox::fs::errors::PathError::MissingComponent => NtStatus::STATUS_OBJECT_NAME_NOT_FOUND,
                litebox::fs::errors::PathError::ComponentNotADirectory => NtStatus::STATUS_NOT_A_DIRECTORY,
                litebox::fs::errors::PathError::NoSearchPerms { .. } => NtStatus::STATUS_ACCESS_DENIED,
                litebox::fs::errors::PathError::InvalidPathname => NtStatus::STATUS_OBJECT_NAME_INVALID,
            }
        }

        fn map_open_error_to_ntstatus(err: &OpenError) -> NtStatus {
            match err {
                OpenError::AccessNotAllowed | OpenError::NoWritePerms => NtStatus::STATUS_ACCESS_DENIED,
                OpenError::ReadOnlyFileSystem | OpenError::Io | OpenError::Interrupted => NtStatus::STATUS_UNSUCCESSFUL,
                OpenError::AlreadyExists => NtStatus::STATUS_OBJECT_NAME_COLLISION,
                OpenError::ClosedFd => NtStatus::STATUS_INVALID_HANDLE,
                OpenError::NotADirectory => NtStatus::STATUS_NOT_A_DIRECTORY,
                OpenError::PathError(path) => map_path_error_to_ntstatus(path),
                OpenError::TruncateError(err) => map_truncate_error_to_ntstatus(err),
            }
        }

        fn map_mkdir_error_to_ntstatus(err: &MkdirError) -> NtStatus {
            match err {
                MkdirError::NoWritePerms => NtStatus::STATUS_ACCESS_DENIED,
                MkdirError::AlreadyExists => NtStatus::STATUS_OBJECT_NAME_COLLISION,
                MkdirError::ReadOnlyFileSystem | MkdirError::Io => NtStatus::STATUS_UNSUCCESSFUL,
                MkdirError::PathError(path) => map_path_error_to_ntstatus(path),
            }
        }

        fn map_file_status_error_to_ntstatus(err: &FileStatusError) -> NtStatus {
            match err {
                FileStatusError::ClosedFd => NtStatus::STATUS_INVALID_HANDLE,
                FileStatusError::NotADirectory => NtStatus::STATUS_NOT_A_DIRECTORY,
                FileStatusError::Io | FileStatusError::SymlinkLoop => NtStatus::STATUS_UNSUCCESSFUL,
                FileStatusError::PathError(path) => map_path_error_to_ntstatus(path),
            }
        }

        fn map_read_error_to_ntstatus(err: &ReadError) -> NtStatus {
            match err {
                ReadError::ClosedFd => NtStatus::STATUS_INVALID_HANDLE,
                ReadError::NotAFile => NtStatus::STATUS_INVALID_DEVICE_REQUEST,
                ReadError::NotForReading => NtStatus::STATUS_ACCESS_DENIED,
                ReadError::Io | ReadError::WouldBlock | ReadError::Interrupted => NtStatus::STATUS_UNSUCCESSFUL,
            }
        }

        fn map_write_error_to_ntstatus(err: &WriteError) -> NtStatus {
            match err {
                WriteError::ClosedFd => NtStatus::STATUS_INVALID_HANDLE,
                WriteError::NotAFile => NtStatus::STATUS_INVALID_DEVICE_REQUEST,
                WriteError::NotForWriting => NtStatus::STATUS_ACCESS_DENIED,
                WriteError::Io | WriteError::Interrupted => NtStatus::STATUS_UNSUCCESSFUL,
            }
        }

        fn map_truncate_error_to_ntstatus(err: &TruncateError) -> NtStatus {
            match err {
                TruncateError::ClosedFd => NtStatus::STATUS_INVALID_HANDLE,
                TruncateError::IsDirectory | TruncateError::IsTerminalDevice => NtStatus::STATUS_INVALID_DEVICE_REQUEST,
                TruncateError::NotForWriting => NtStatus::STATUS_ACCESS_DENIED,
                TruncateError::Io => NtStatus::STATUS_UNSUCCESSFUL,
            }
        }

        fn map_read_dir_error_to_ntstatus(err: &ReadDirError) -> NtStatus {
            match err {
                ReadDirError::ClosedFd => NtStatus::STATUS_INVALID_HANDLE,
                ReadDirError::NotADirectory => NtStatus::STATUS_NOT_A_DIRECTORY,
                ReadDirError::Io => NtStatus::STATUS_UNSUCCESSFUL,
            }
        }

        /// Read a UNICODE_STRING from guest memory and return the string contents.
        '''
    ),
)
# fix the Pythonic accidental section later after write if present
file_path.write_text(text)

# runner quick imports and constructor
runner_path = root / 'litebox_runner_windows_userland' / 'src' / 'lib.rs'
text = runner_path.read_text()
text = replace_once(
    text,
    "use anyhow::{Result, anyhow};\nuse clap::Parser;\nuse std::path::PathBuf;\nuse std::sync::Arc;\n",
    "use anyhow::{Result, anyhow};\nuse clap::Parser;\nuse litebox::fs::{FileSystem as _, Mode, OFlags};\nuse std::path::PathBuf;\nuse std::sync::Arc;\n",
)
text = replace_once(
    text,
    "    let litebox = litebox::LiteBox::new(platform);\n",
    "    let litebox = litebox::LiteBox::new(platform);\n    let mut windows_fs = litebox_shim_windows::WindowsFS::new(&litebox);\n",
)
text = replace_once(
    text,
    "        litebox_shim_windows::NtShimEntrypoints::new(alloc::sync::Arc::clone(&process_state));\n",
    "        litebox_shim_windows::NtShimEntrypoints::new(alloc::sync::Arc::clone(&process_state), Arc::new(windows_fs));\n",
)
runner_path.write_text(text)

print('partial')
