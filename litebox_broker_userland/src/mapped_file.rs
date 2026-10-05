// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Read-only file mappings for userland brokers.

use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::path::Path;

/// Map the whole file at `path` read-only for the rest of the process's life.
///
/// This lets the broker serve a large read-only input, such as the initial file system archive,
/// without first copying all of it into memory: pages come from the host's page cache as they are
/// read. The mapping is never unmapped, so use this only for files needed until the process exits.
///
/// # Safety
///
/// The file must not be modified, by this or any other process, for the rest of the process's
/// life. The mapping can observe such changes, which would break the immutability of the returned
/// bytes, and reading past the end of a file truncated in the meantime faults.
pub unsafe fn map_static(path: &Path) -> IoResult<&'static [u8]> {
    let file = File::open(path)?;
    let len = usize::try_from(file.metadata()?.len())
        .map_err(|_| IoError::new(ErrorKind::InvalidInput, "file is too large to map"))?;
    if len == 0 {
        // Hosts refuse to map empty files, and there are no bytes to lend out anyway.
        return Ok(&[]);
    }
    let address = host::map(&file, len)?;
    // SAFETY: `address` is the start of a readable mapping of `len` bytes that is never unmapped,
    // and the caller keeps its contents unchanged.
    Ok(unsafe { std::slice::from_raw_parts(address, len) })
}

#[cfg(target_os = "linux")]
mod host {
    use std::fs::File;
    use std::io::{Error as IoError, Result as IoResult};
    use std::os::fd::AsRawFd;

    /// Map the first `len` bytes of `file` read-only. The mapping outlives `file`.
    pub(super) fn map(file: &File, len: usize) -> IoResult<*const u8> {
        // SAFETY: A new private mapping at an address chosen by the kernel aliases no existing
        // memory, and `file` is a live descriptor.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(IoError::last_os_error());
        }
        Ok(address.cast())
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
mod host {
    use std::fs::File;
    use std::io::{Error as IoError, Result as IoResult};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_READ, MapViewOfFile, PAGE_READONLY,
    };

    /// Map the first `len` bytes of `file` read-only. The mapping outlives `file`.
    pub(super) fn map(file: &File, len: usize) -> IoResult<*const u8> {
        // SAFETY: `file` is a live handle, and the unnamed read-only mapping spans the whole file.
        let mapping = unsafe {
            CreateFileMappingW(
                file.as_raw_handle(),
                std::ptr::null(),
                PAGE_READONLY,
                0,
                0,
                std::ptr::null(),
            )
        };
        if mapping.is_null() {
            return Err(IoError::last_os_error());
        }
        // SAFETY: `mapping` is a fresh handle owned by nothing else. Closing it once the view is
        // mapped is fine, since the view keeps the mapping alive.
        let mapping = unsafe { OwnedHandle::from_raw_handle(mapping) };
        // SAFETY: `mapping` is a live read-only file mapping spanning `len` bytes, and a view at an
        // address chosen by the system aliases no existing memory.
        let view = unsafe { MapViewOfFile(mapping.as_raw_handle(), FILE_MAP_READ, 0, 0, len) };
        if view.Value.is_null() {
            return Err(IoError::last_os_error());
        }
        Ok(view.Value.cast_const().cast())
    }
}
