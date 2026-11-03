// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Error as IoError, ErrorKind};
use std::os::windows::fs::OpenOptionsExt as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use litebox_broker_core::fs::shared_memory::{
    HostHandle, SharedFileMemory, SharedFileMemoryError, SharedFileMemoryProvider,
};
use litebox_broker_core::transfer::bounce_buffer;
use windows_sys::Win32::Foundation::{GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_DELETE_ON_CLOSE,
};

use super::host_file::{Exported, HostFileMemory, STAGING_SIZE, create, memory_error};

/// The file's size, which the broker keeps itself.
///
/// Windows refuses to shrink a file while any section of it exists, and runners hold sections
/// for as long as they map the file. A shrink it refuses therefore zeroes the bytes past the new
/// end and lowers this size only, leaving the host file longer until a later resize can shrink
/// it. Runners receive no right to resize sections, so only the broker changes the host file's
/// size.
#[derive(Default)]
pub(super) struct State {
    len: AtomicU64,
}

impl HostFileMemory {
    /// Returns the file's size. Callers hold `io`.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "reading the size fails only on Linux"
    )]
    pub(super) fn len(&self) -> Result<u64, SharedFileMemoryError> {
        Ok(self.state.len.load(Ordering::Relaxed))
    }

    /// Returns the size past which reads stop short of the host file's end, since the host
    /// file may hold stale bytes past the end of the file.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "only Windows keeps a size of its own"
    )]
    pub(super) fn read_limit(&self) -> Option<u64> {
        Some(self.state.len.load(Ordering::Relaxed))
    }

    /// Resizes the file to `length` bytes. Callers hold `io` alone.
    ///
    /// Bytes between the old and the new size that the host file already holds are zeroed,
    /// since runners may have written there through mappings past the end of the file, and a
    /// shrink the host refuses while the file is mapped leaves them in the host file.
    pub(super) fn resize(&self, length: u64) -> Result<(), SharedFileMemoryError> {
        let old_len = self.len()?;
        let old_host_len = self.host_len()?;
        let host_len = if length == old_host_len {
            length
        } else {
            match self.file.set_len(length) {
                Ok(()) => length,
                Err(error)
                    if length < old_host_len
                        && memory_error(&error) == SharedFileMemoryError::Busy =>
                {
                    old_host_len
                }
                Err(error) => return Err(memory_error(&error)),
            }
        };
        // Bytes the host file had before this resize and still has may be stale.
        let stale_end = old_host_len.min(host_len);
        let (start, end) = if length > old_len {
            (old_len, length)
        } else {
            (length, old_len)
        };
        self.zero(start, end.min(stale_end))?;
        self.state.len.store(length, Ordering::Relaxed);
        Ok(())
    }

    /// Zeroes stale bytes the host file may hold between the end of the file and a write at
    /// `position`. Callers hold `io` alone.
    pub(super) fn before_write(&self, position: u64) -> Result<(), SharedFileMemoryError> {
        let len = self.len()?;
        if position > len {
            self.zero(len, position.min(self.host_len()?))?;
        }
        Ok(())
    }

    /// Records a write that ended at `end`. Callers hold `io` alone.
    pub(super) fn after_write(&self, end: u64) {
        self.state.len.fetch_max(end, Ordering::Relaxed);
    }

    /// Returns the storage's own handle for exporting it.
    ///
    /// The handle never leaves the broker: the deployment derives a section from it, and the
    /// section's protection and the rights of the section handle sent to a runner enforce
    /// `writable`, so readers and writers share the storage's own handle.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "exporting a reader fails only on Linux"
    )]
    pub(super) fn export(
        &self,
        _writable: bool,
    ) -> Result<Box<dyn HostHandle + '_>, SharedFileMemoryError> {
        use std::os::windows::io::AsHandle as _;

        Ok(Box::new(Exported(self.file.as_handle())))
    }

    /// Zeroes the host file's bytes from `start` to `end`. Callers hold `io` alone.
    fn zero(&self, start: u64, end: u64) -> Result<(), SharedFileMemoryError> {
        if start >= end {
            return Ok(());
        }
        let zeros = bounce_buffer(
            usize::try_from(end - start).map_or(STAGING_SIZE, |length| length.min(STAGING_SIZE)),
        )
        .map_err(|_| SharedFileMemoryError::NoMemory)?;
        let mut position = start;
        while position < end {
            let length = usize::try_from(end - position)
                .map_or(zeros.len(), |remaining| remaining.min(zeros.len()));
            self.write_all(&zeros[..length], position, &mut 0)
                .map_err(|error| memory_error(&error))?;
            position += length as u64;
        }
        Ok(())
    }
}

impl<H: std::os::windows::io::AsHandle + Send> HostHandle for Exported<H> {
    fn raw(&self) -> u64 {
        use std::os::windows::io::AsRawHandle as _;

        self.0.as_handle().as_raw_handle() as usize as u64
    }
}

/// Returns the most bytes the host lets the broker's files hold: as many as positions address.
pub(super) fn size_limit() -> u64 {
    i64::MAX.cast_unsigned()
}

/// Returns what the host error `code` means for shared file memory, if more than an I/O error.
pub(super) fn memory_error_for(code: i32) -> Option<SharedFileMemoryError> {
    use windows_sys::Win32::Foundation::{
        ERROR_COMMITMENT_LIMIT, ERROR_DISK_FULL, ERROR_HANDLE_DISK_FULL, ERROR_NOACCESS,
        ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_ENOUGH_QUOTA, ERROR_OUTOFMEMORY, ERROR_USER_MAPPED_FILE,
    };

    match u32::try_from(code).ok()? {
        ERROR_USER_MAPPED_FILE => Some(SharedFileMemoryError::Busy),
        ERROR_DISK_FULL
        | ERROR_HANDLE_DISK_FULL
        | ERROR_NOT_ENOUGH_MEMORY
        | ERROR_OUTOFMEMORY
        | ERROR_COMMITMENT_LIMIT
        | ERROR_NOT_ENOUGH_QUOTA => Some(SharedFileMemoryError::NoMemory),
        ERROR_NOACCESS => Some(SharedFileMemoryError::Fault),
        _ => None,
    }
}

/// Returns whether a positional read failed only because it started past the end of the file.
pub(super) fn read_reached_end(error: &IoError) -> bool {
    error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_HANDLE_EOF.cast_signed())
}
/// Creates memory for files in the host's temporary directory.
pub struct TempFileMemoryProvider;

fn temp_file() -> Result<std::fs::File, SharedFileMemoryError> {
    let directory = std::env::temp_dir();
    loop {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(|_| SharedFileMemoryError::Io)?;
        let path = directory.join(format!(
            "litebox-shared-file-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(nonce),
        ));
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE)
            .share_mode(0)
            .attributes(FILE_ATTRIBUTE_TEMPORARY)
            .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
            .open(path)
        {
            Ok(file) => return Ok(file),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(memory_error(&error)),
        }
    }
}

impl SharedFileMemoryProvider for TempFileMemoryProvider {
    fn create(&self, contents: &[u8]) -> Result<Arc<dyn SharedFileMemory>, SharedFileMemoryError> {
        create(temp_file()?, contents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_file_memory_reads_writes_and_resizes() {
        super::super::host_file::tests::check_reads_writes_and_resizes(&TempFileMemoryProvider);
    }

    #[test]
    fn temp_file_memory_stays_within_size_limits() {
        super::super::host_file::tests::check_size_limit(temp_file().unwrap());
    }

    #[test]
    fn shrinking_mapped_memory_hides_and_zeroes_the_tail() {
        use std::mem::ManuallyDrop;
        use std::os::windows::io::FromRawHandle as _;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::Memory::{
            CreateFileMappingW, FILE_MAP_WRITE, MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
        };

        let memory = TempFileMemoryProvider.create(b"hello").unwrap();
        let handle = usize::try_from(memory.host_handle(true).unwrap().raw()).unwrap() as HANDLE;
        let host_len = || {
            // SAFETY: The handle stays open while `memory` lives, and `ManuallyDrop` leaves
            // closing it to `memory`.
            let file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(handle) });
            file.metadata().unwrap().len()
        };
        let contents = |length: usize| {
            let mut bytes = vec![0u8; length + 1];
            let read = memory.read_at(0, &mut bytes.as_mut_slice()).unwrap();
            bytes.truncate(read);
            bytes
        };
        // SAFETY: `handle` is a live file handle lent by `memory`, and the call creates a
        // new section handle.
        let section = unsafe {
            CreateFileMappingW(
                handle,
                std::ptr::null(),
                PAGE_READWRITE,
                0,
                0,
                std::ptr::null(),
            )
        };
        assert!(!section.is_null());
        // SAFETY: `section` is a live section handle, and the call maps a new view of it.
        let view = unsafe { MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, 0) };
        assert!(!view.Value.is_null());
        let byte = view.Value.cast::<u8>();
        // SAFETY: The view maps the five bytes of the file as they were mapped, which the
        // host may change behind the reference-free volatile accesses.
        let peek = |index: usize| unsafe { byte.add(index).read_volatile() };
        // SAFETY: As for `peek`.
        let poke = |index: usize, value: u8| unsafe { byte.add(index).write_volatile(value) };

        // The host cannot shrink the mapped file, so the bytes past the new end read as
        // gone and become zeros in the mapping.
        memory.set_len(1).unwrap();
        assert_eq!(memory.size().unwrap(), 1);
        assert_eq!(host_len(), 5);
        assert_eq!(contents(8), b"h");
        assert_eq!((1..5).map(peek).collect::<Vec<_>>(), [0; 4]);

        // What a runner stores past the end through its mapping is zero once the file grows
        // over it, whether by resizing or by writing past it.
        poke(3, b'x');
        poke(4, b'y');
        memory.set_len(4).unwrap();
        assert_eq!(contents(8), b"h\0\0\0");
        assert_eq!(memory.write_at(6, &b"!".as_slice()).unwrap(), 1);
        assert_eq!(contents(8), b"h\0\0\0\0\0!");
        assert_eq!(peek(4), 0);
        assert_eq!(host_len(), 7);

        // SAFETY: `view` and `section` were created above and are not used again.
        unsafe {
            assert_ne!(UnmapViewOfFile(view), 0);
            assert_ne!(CloseHandle(section), 0);
        }
        // Once nothing maps the file, resizing it shrinks the host file too.
        memory.set_len(2).unwrap();
        assert_eq!(memory.size().unwrap(), 2);
        assert_eq!(host_len(), 2);
    }
}
