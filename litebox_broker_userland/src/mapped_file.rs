// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Read-only file mappings for userland brokers.

use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::path::Path;
use std::ptr::NonNull;

use litebox_broker_core::fs::errors::ReadError;
use litebox_broker_core::fs::tar_ro::TarStorage;

/// The contents of a file, mapped read-only into the broker's address space.
///
/// This lets the broker serve a large read-only input, such as the initial file system archive,
/// without first copying all of it into memory: pages come from the host's page cache as they are
/// read. Reads at an offset copy from the page cache directly, sparing the broker the cost of
/// mapping those pages in and tearing them down again.
pub struct MappedFile {
    file: File,
    /// Start of the mapping, or dangling if `len` is zero.
    address: NonNull<u8>,
    len: usize,
}

// SAFETY: The mapping is read-only and owned by this value alone, so it can be sent and shared
// across threads just like an owned `Box<[u8]>`.
unsafe impl Send for MappedFile {}
// SAFETY: See `Send` above.
unsafe impl Sync for MappedFile {}

impl MappedFile {
    /// Map the whole file at `path`.
    ///
    /// # Safety
    ///
    /// The file must not be modified, by this or any other process, while the mapping is alive.
    /// The mapping can observe such changes, which would break the immutability of the bytes it
    /// lends out, and reading past the end of a file truncated in the meantime faults.
    pub unsafe fn open(path: &Path) -> IoResult<Self> {
        let file = File::open(path)?;
        let len = usize::try_from(file.metadata()?.len())
            .map_err(|_| IoError::new(ErrorKind::InvalidInput, "file is too large to map"))?;
        let address = if len == 0 {
            // Hosts refuse to map empty files, and there are no bytes to lend out anyway.
            NonNull::dangling()
        } else {
            host::map(&file, len)?
        };
        Ok(Self { file, address, len })
    }
}

impl TarStorage for MappedFile {
    fn bytes(&self) -> &[u8] {
        // SAFETY: `address` is either dangling with a zero `len`, or the start of a live, readable
        // mapping of `len` bytes owned by `self`, whose contents the contract of `open` keeps
        // unchanged.
        unsafe { std::slice::from_raw_parts(self.address.as_ptr(), self.len) }
    }

    fn read_exact_at(&self, buf: &mut [u8], offset: usize) -> Result<(), ReadError> {
        host::read_exact_at(&self.file, buf, offset as u64).map_err(|_| ReadError::Io)
    }
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        if self.len != 0 {
            // SAFETY: A non-empty `self` owns the live mapping at `address`, and no borrow of its
            // bytes can outlive `self`.
            unsafe { host::unmap(self.address, self.len) };
        }
    }
}

#[cfg(target_os = "linux")]
mod host {
    use std::fs::File;
    use std::io::{Error as IoError, Result as IoResult};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileExt as _;
    use std::ptr::NonNull;

    /// Fill `buf` with the bytes of `file` at `offset`.
    pub(super) fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> IoResult<()> {
        file.read_exact_at(buf, offset)
    }

    /// Map the first `len` bytes of `file` read-only.
    pub(super) fn map(file: &File, len: usize) -> IoResult<NonNull<u8>> {
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
        Ok(NonNull::new(address.cast()).expect("a successful mmap is not at address zero"))
    }

    /// Unmap a mapping returned by [`map`].
    ///
    /// # Safety
    ///
    /// `address` and `len` must describe a live mapping returned by [`map`] that is no longer
    /// borrowed.
    pub(super) unsafe fn unmap(address: NonNull<u8>, len: usize) {
        // SAFETY: Guaranteed by the caller.
        unsafe { libc::munmap(address.as_ptr().cast(), len) };
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
mod host {
    use std::fs::File;
    use std::io::{Error as IoError, ErrorKind, Result as IoResult};
    use std::os::windows::fs::FileExt as _;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr::NonNull;

    /// Fill `buf` with the bytes of `file` at `offset`.
    pub(super) fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> IoResult<()> {
        while !buf.is_empty() {
            match file.seek_read(buf, offset) {
                Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
                Ok(read) => {
                    buf = &mut buf[read..];
                    offset += read as u64;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
        PAGE_READONLY, UnmapViewOfFile,
    };

    /// Map the first `len` bytes of `file` read-only.
    pub(super) fn map(file: &File, len: usize) -> IoResult<NonNull<u8>> {
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
        NonNull::new(view.Value.cast()).ok_or_else(IoError::last_os_error)
    }

    /// Unmap a mapping returned by [`map`].
    ///
    /// # Safety
    ///
    /// `address` must be a live mapping returned by [`map`] that is no longer borrowed.
    pub(super) unsafe fn unmap(address: NonNull<u8>, _len: usize) {
        // SAFETY: Guaranteed by the caller.
        unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: address.as_ptr().cast(),
            })
        };
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::io::Write;

    use litebox_broker_core::fs::tar_ro::TarStorage as _;

    use super::MappedFile;

    fn mapped(contents: &[u8]) -> MappedFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        // SAFETY: Nothing modifies the temporary file while it is mapped.
        unsafe { MappedFile::open(file.path()) }.unwrap()
    }

    #[test]
    fn maps_file_contents() {
        let contents: Vec<u8> = (0..10_000u32).flat_map(u32::to_le_bytes).collect();
        assert_eq!(mapped(&contents).bytes(), contents);
    }

    #[test]
    fn reads_file_contents_at_an_offset() {
        let contents: Vec<u8> = (0..10_000u32).flat_map(u32::to_le_bytes).collect();
        let mut buf = [0; 100];
        mapped(&contents).read_exact_at(&mut buf, 5000).unwrap();
        assert_eq!(buf, contents[5000..5100]);
    }

    #[test]
    fn maps_empty_file() {
        let file = mapped(b"");
        assert!(file.bytes().is_empty());
        file.read_exact_at(&mut [], 0).unwrap();
    }
}
