// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::ErrorKind;
use std::os::windows::fs::OpenOptionsExt as _;
use std::sync::Arc;

use litebox_broker_core::fs::shared_memory::{
    SharedFileMemory, SharedFileMemoryError, SharedFileMemoryProvider,
};
use windows_sys::Win32::Foundation::{GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_DELETE_ON_CLOSE,
};

use super::host_file::{create, memory_error};

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
