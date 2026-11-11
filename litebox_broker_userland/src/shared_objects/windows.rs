// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::File;
use std::io::{Error as IoError, ErrorKind};
use std::os::windows::fs::OpenOptionsExt as _;

use litebox_broker_core::fs::errors::{MapSharedError, StorageError};
use litebox_broker_core::fs::shared_memory::{
    HostHandle, SharedFileMemory, SharedFileMemoryProvider,
};
use litebox_broker_core::transfer::bounce_buffer;
use litebox_platform::buffer::{Buffer as _, ReadBuffer};
use windows_sys::Win32::Foundation::{GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_DELETE_ON_CLOSE,
};

use super::host_file::{
    Exported, HostFile, STAGING_SIZE, create, host_len, memory_error, read_to_host_end,
};
use crate::fs::write_slice_at;

/// A temporary file, with the file's size, which the broker keeps itself.
///
/// Windows refuses to shrink a file while any section of it exists, and runners hold sections
/// for as long as they map the file. A shrink it refuses therefore zeroes the bytes past the new
/// end and lowers this size only, leaving the host file longer until a later resize can shrink
/// it. Runners receive no right to resize sections, so only the broker changes the host file's
/// size. Runners may still store past the end through their mappings, and those bytes become
/// part of the file again if it grows over them.
#[derive(Default)]
pub(super) struct TempFile {
    len: u64,
}

impl HostFile for TempFile {
    fn len(&self, _file: &File) -> Result<u64, StorageError> {
        Ok(self.len)
    }

    fn read_at(
        &self,
        file: &File,
        offset: usize,
        buffer: &mut dyn ReadBuffer,
    ) -> Result<usize, StorageError> {
        // The host file may hold stale bytes past the end of the file, so reads stop there.
        let available =
            usize::try_from(self.len.saturating_sub(offset as u64)).unwrap_or(usize::MAX);
        if available < buffer.len() {
            return read_to_host_end::<Self>(
                file,
                offset,
                &mut (&mut *buffer).sub_buffer(0, available),
            );
        }
        read_to_host_end::<Self>(file, offset, buffer)
    }

    /// A shrink the host refuses while the file is mapped zeroes the bytes past the new size
    /// instead, so that mappings no longer see them.
    fn resize(&mut self, file: &File, length: u64) -> Result<(), StorageError> {
        let old_host_len = host_len::<Self>(file)?;
        let host_len = if length == old_host_len {
            length
        } else {
            match file.set_len(length) {
                Ok(()) => length,
                Err(error)
                    if length < old_host_len
                        && memory_error::<Self>(&error) == StorageError::Busy =>
                {
                    old_host_len
                }
                Err(error) => return Err(memory_error::<Self>(&error)),
            }
        };
        if length < self.len {
            zero(file, length, self.len.min(host_len))?;
        }
        self.len = length;
        Ok(())
    }

    fn after_write(&mut self, end: u64) {
        self.len = self.len.max(end);
    }

    /// Returns `file`'s own handle.
    ///
    /// The handle never leaves the broker: the deployment derives a section from it, and the
    /// section's protection and the rights of the section handle sent to a runner enforce
    /// `writable`, so readers and writers share the file's own handle.
    fn export(file: &File, _writable: bool) -> Result<Box<dyn HostHandle + '_>, MapSharedError> {
        use std::os::windows::io::AsHandle as _;

        Ok(Box::new(Exported(file.as_handle())))
    }

    /// As many bytes as positions address.
    fn size_limit() -> u64 {
        i64::MAX.cast_unsigned()
    }

    fn error_for(code: i32) -> Option<StorageError> {
        use windows_sys::Win32::Foundation::{
            ERROR_COMMITMENT_LIMIT, ERROR_DISK_FULL, ERROR_HANDLE_DISK_FULL, ERROR_NOACCESS,
            ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_ENOUGH_QUOTA, ERROR_OUTOFMEMORY,
            ERROR_USER_MAPPED_FILE,
        };

        match u32::try_from(code).ok()? {
            ERROR_USER_MAPPED_FILE => Some(StorageError::Busy),
            ERROR_DISK_FULL
            | ERROR_HANDLE_DISK_FULL
            | ERROR_NOT_ENOUGH_MEMORY
            | ERROR_OUTOFMEMORY
            | ERROR_COMMITMENT_LIMIT
            | ERROR_NOT_ENOUGH_QUOTA => Some(StorageError::NoSpace),
            ERROR_NOACCESS => Some(StorageError::Fault),
            _ => None,
        }
    }

    fn read_reached_end(error: &IoError) -> bool {
        error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_HANDLE_EOF.cast_signed())
    }
}

/// Writes all of `data` to `file` at `offset`.
fn write_all(file: &File, mut data: &[u8], mut offset: u64) -> std::io::Result<()> {
    while !data.is_empty() {
        match write_slice_at(file, data, offset) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(count) => {
                data = &data[count..];
                offset += count as u64;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Zeroes the bytes of `file` from `start` to `end`.
fn zero(file: &File, start: u64, end: u64) -> Result<(), StorageError> {
    if start >= end {
        return Ok(());
    }
    let zeros = bounce_buffer(
        usize::try_from(end - start).map_or(STAGING_SIZE, |length| length.min(STAGING_SIZE)),
    )
    .map_err(|_| StorageError::NoSpace)?;
    let mut position = start;
    while position < end {
        let length = usize::try_from(end - position)
            .map_or(zeros.len(), |remaining| remaining.min(zeros.len()));
        write_all(file, &zeros[..length], position)
            .map_err(|error| memory_error::<TempFile>(&error))?;
        position += length as u64;
    }
    Ok(())
}

impl<T: std::os::windows::io::AsHandle + Send> HostHandle for Exported<T> {
    fn raw(&self) -> u64 {
        use std::os::windows::io::AsRawHandle as _;

        self.0.as_handle().as_raw_handle() as usize as u64
    }
}

/// Creates memory for files in the host's temporary directory.
pub struct TempFileMemoryProvider;

fn temp_file() -> Result<File, StorageError> {
    let directory = std::env::temp_dir();
    loop {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(|_| StorageError::Io)?;
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
            Err(error) => return Err(memory_error::<TempFile>(&error)),
        }
    }
}

impl SharedFileMemoryProvider for TempFileMemoryProvider {
    fn create(&self) -> Result<SharedFileMemory, StorageError> {
        Ok(create::<TempFile>(temp_file()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_core::fs::storage::FileStorage;

    #[test]
    fn temp_file_memory_reads_writes_and_resizes() {
        super::super::host_file::tests::check_reads_writes_and_resizes(&TempFileMemoryProvider);
    }

    #[test]
    fn temp_file_memory_stays_within_size_limits() {
        super::super::host_file::tests::check_size_limit::<TempFile>(temp_file().unwrap());
    }

    #[test]
    fn shrinking_mapped_memory_hides_and_zeroes_the_tail() {
        use std::mem::ManuallyDrop;
        use std::os::windows::io::FromRawHandle as _;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::Memory::{
            CreateFileMappingW, FILE_MAP_WRITE, MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
        };

        let SharedFileMemory {
            storage: mut memory,
            object,
        } = super::super::host_file::tests::create_with(&TempFileMemoryProvider, b"hello");
        let handle = usize::try_from(object.host_handle(true).unwrap().raw()).unwrap() as HANDLE;
        let host_len = || {
            // SAFETY: The handle stays open while `object` lives, and `ManuallyDrop` leaves
            // closing it to `object`.
            let file = ManuallyDrop::new(unsafe { File::from_raw_handle(handle) });
            file.metadata().unwrap().len()
        };
        let contents = |memory: &dyn FileStorage, length: usize| {
            let mut bytes = vec![0u8; length + 1];
            let read = memory.read_at(0, &mut bytes.as_mut_slice()).unwrap();
            bytes.truncate(read);
            bytes
        };
        // SAFETY: `handle` is a live file handle lent by `object`, and the call creates a
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

        // The host cannot shrink the mapped file, so the bytes past the new end read as
        // gone and become zeros in the mapping.
        memory.set_len(1).unwrap();
        assert_eq!(memory.len().unwrap(), 1);
        assert_eq!(host_len(), 5);
        assert_eq!(contents(&*memory, 8), b"h");
        assert_eq!((1..5).map(peek).collect::<Vec<_>>(), [0; 4]);

        // Writing past the end grows the mapped file over the zeroed tail.
        assert_eq!(memory.write_at(6, &b"!".as_slice()).unwrap(), 1);
        assert_eq!(contents(&*memory, 8), b"h\0\0\0\0\0!");
        assert_eq!(host_len(), 7);

        // SAFETY: `view` and `section` were created above and are not used again.
        unsafe {
            assert_ne!(UnmapViewOfFile(view), 0);
            assert_ne!(CloseHandle(section), 0);
        }
        // Once nothing maps the file, resizing it shrinks the host file too.
        memory.set_len(2).unwrap();
        assert_eq!(memory.len().unwrap(), 2);
        assert_eq!(host_len(), 2);
    }
}
