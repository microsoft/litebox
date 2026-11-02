// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{BorrowedHandle, FromRawHandle as _, OwnedHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use litebox_broker_core::fs::shared_memory::{
    HostHandle, SharedFileMemory, SharedFileMemoryError, SharedFileMemoryProvider, SharedFileObject,
};
use litebox_broker_core::transfer::bounce_buffer;
use litebox_broker_transport_windows_userland::shared_objects::SectionSender;
use windows_sys::Win32::Foundation::{
    ERROR_FILE_INVALID, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_DELETE_ON_CLOSE,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
};

use super::SharedObjectDelivery;
use super::host_file::{Exported, HostFileMemory, STAGING_SIZE, create, memory_error};

/// The file's size, which the broker keeps itself.
///
/// Windows refuses to shrink a file while any section of it exists, and runners hold sections
/// for as long as they map the file. A shrink it refuses therefore zeroes the bytes past the new
/// end and lowers this size only, leaving the host file longer until a later resize can shrink
/// it. Runners receive no right to resize sections, so only the broker changes the host file's
/// size. Runners may still store past the end through their mappings, and those bytes become
/// part of the file again if it grows over them.
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
    /// A shrink the host refuses while the file is mapped zeroes the bytes past the new size
    /// instead, so that mappings no longer see them.
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
        if length < old_len {
            self.zero(length, old_len.min(host_len))?;
        }
        self.state.len.store(length, Ordering::Relaxed);
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

    /// Copies `contents` into a temporary file that the broker never writes again and that
    /// no other process may open, and that it delivers only as read-only sections, which no
    /// runner can map writable but may map copy-on-write.
    fn create_sealed(
        &self,
        contents: &[u8],
    ) -> Result<Arc<dyn SharedFileObject>, SharedFileMemoryError> {
        let file = temp_file()?;
        std::io::Write::write_all(&mut &file, contents).map_err(|error| memory_error(&error))?;
        Ok(Arc::new(SnapshotFile(file)))
    }
}

/// A temporary file holding a snapshot that never changes.
struct SnapshotFile(std::fs::File);

impl SharedFileObject for SnapshotFile {
    /// Lends the file's handle for read-only sections only.
    fn host_handle(
        &self,
        writable: bool,
    ) -> Result<Box<dyn HostHandle + '_>, SharedFileMemoryError> {
        use std::os::windows::io::AsHandle as _;

        if writable {
            return Err(SharedFileMemoryError::Unsupported);
        }
        Ok(Box::new(super::host_file::Exported(self.0.as_handle())))
    }
}

/// Delivers sections of temporary files into a runner process.
pub(crate) struct SectionDelivery(SectionSender);

impl SectionDelivery {
    /// Delivers sections into `process`, which must allow duplicating handles into it.
    pub(crate) fn new(process: BorrowedHandle<'_>) -> IoResult<Self> {
        SectionSender::new(process).map(Self)
    }
}

impl SharedObjectDelivery for SectionDelivery {
    fn deliver(&self, object: &dyn SharedFileObject, writable: bool) -> IoResult<u64> {
        // The object lends the file's handle, from which the section derives the rights.
        let file = super::host_handle(object, writable)?;
        let file = usize::try_from(file.raw())
            .map_err(|_| IoError::other("host handle does not fit a pointer"))?;
        // A runner that may only read the file gets a read-only section, which no handle
        // rights can map writable.
        let protection = if writable {
            PAGE_EXECUTE_READWRITE
        } else {
            PAGE_EXECUTE_READ
        };
        // SAFETY: `file` lends a handle that stays open while it is borrowed. Zero sizes make
        // the section the file's size, and the section is unnamed with default security.
        let section = unsafe {
            CreateFileMappingW(
                file as windows_sys::Win32::Foundation::HANDLE,
                std::ptr::null(),
                protection,
                0,
                0,
                std::ptr::null(),
            )
        };
        if section.is_null() {
            let error = IoError::last_os_error();
            // An empty file has no section; the runner leaves all its pages inaccessible.
            if error.raw_os_error() == i32::try_from(ERROR_FILE_INVALID).ok() {
                return Ok(0);
            }
            return Err(error);
        }
        // SAFETY: CreateFileMappingW returned a new handle that this process owns.
        let section = unsafe { OwnedHandle::from_raw_handle(section) };
        self.0.send(section, writable)
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

        // The host cannot shrink the mapped file, so the bytes past the new end read as
        // gone and become zeros in the mapping.
        memory.set_len(1).unwrap();
        assert_eq!(memory.size().unwrap(), 1);
        assert_eq!(host_len(), 5);
        assert_eq!(contents(8), b"h");
        assert_eq!((1..5).map(peek).collect::<Vec<_>>(), [0; 4]);

        // Writing past the end grows the mapped file over the zeroed tail.
        assert_eq!(memory.write_at(6, &b"!".as_slice()).unwrap(), 1);
        assert_eq!(contents(8), b"h\0\0\0\0\0!");
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

    mod delivery {
        use super::*;
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::System::Memory::{
            FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
            UnmapViewOfFile,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        #[test]
        fn snapshots_map_copy_on_write_but_never_writable() {
            use windows_sys::Win32::System::Memory::FILE_MAP_COPY;

            // SAFETY: The pseudo-handle names this process and is always valid.
            let process = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) };
            let delivery = SectionDelivery::new(process).unwrap();
            let snapshot = TempFileMemoryProvider.create_sealed(b"hello").unwrap();
            assert_eq!(
                delivery
                    .deliver(&*snapshot, true)
                    .map_err(|error| error.kind()),
                Err(ErrorKind::Unsupported)
            );
            let token = delivery.deliver(&*snapshot, false).unwrap();
            // SAFETY: The token is a section handle that `deliver` duplicated into this process
            // for this caller alone.
            let section =
                unsafe { OwnedHandle::from_raw_handle(usize::try_from(token).unwrap() as HANDLE) };
            let map = |access| {
                // SAFETY: Maps a fresh view of a live section.
                let view = unsafe { MapViewOfFile(section.as_raw_handle(), access, 0, 0, 0) };
                (!view.Value.is_null()).then_some(view)
            };
            assert!(map(FILE_MAP_READ | FILE_MAP_WRITE).is_none());
            let private = map(FILE_MAP_COPY).unwrap();
            let again = map(FILE_MAP_READ).unwrap();
            // SAFETY: Both views are live and at least five bytes long.
            unsafe {
                assert_eq!(
                    core::slice::from_raw_parts(private.Value.cast::<u8>(), 5),
                    b"hello"
                );
                private.Value.cast::<u8>().write(b'J');
                assert_eq!(again.Value.cast::<u8>().read(), b'h');
                assert_ne!(UnmapViewOfFile(private), 0);
                assert_ne!(UnmapViewOfFile(again), 0);
            }
        }

        #[test]
        fn delivered_sections_share_pages_and_keep_read_only_rights() {
            // SAFETY: The pseudo-handle names this process and is always valid.
            let process = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) };
            let delivery = SectionDelivery::new(process).unwrap();
            let memory = TempFileMemoryProvider.create(&[0; 4096]).unwrap();
            let take = |writable| {
                let token = delivery.deliver(&*memory, writable).unwrap();
                // SAFETY: The token is a section handle that `deliver` duplicated into this
                // process for this caller alone.
                unsafe { OwnedHandle::from_raw_handle(usize::try_from(token).unwrap() as HANDLE) }
            };
            let map = |section: &OwnedHandle, access| {
                // SAFETY: Maps a fresh view of a live section.
                let view = unsafe { MapViewOfFile(section.as_raw_handle(), access, 0, 0, 4096) };
                (!view.Value.is_null()).then_some(view)
            };
            let unmap = |view: MEMORY_MAPPED_VIEW_ADDRESS| {
                // SAFETY: Unmaps a view mapped above that nothing else uses.
                assert_ne!(unsafe { UnmapViewOfFile(view) }, 0);
            };

            let read_only = take(false);
            assert!(map(&read_only, FILE_MAP_READ | FILE_MAP_WRITE).is_none());
            let writable = take(true);
            let view = map(&writable, FILE_MAP_READ | FILE_MAP_WRITE).unwrap();
            let reader = map(&read_only, FILE_MAP_READ).unwrap();

            // Stores through one view are what file reads and other views see, and the reverse.
            // SAFETY: The views are live and at least a page long.
            unsafe { view.Value.cast::<u8>().write(42) };
            let mut byte = [0];
            memory.read_at(0, &mut byte.as_mut_slice()).unwrap();
            assert_eq!(byte, [42]);
            memory.write_at(1, &[7].as_slice()).unwrap();
            // SAFETY: As above.
            assert_eq!(unsafe { reader.Value.cast::<u8>().add(1).read() }, 7);

            // Shrinking the mapped file hides its bytes, which the views then see as zeros,
            // and it can grow again.
            memory.set_len(0).unwrap();
            assert_eq!(memory.size().unwrap(), 0);
            // SAFETY: As above.
            assert_eq!(unsafe { reader.Value.cast::<u8>().add(1).read() }, 0);
            memory.set_len(8192).unwrap();
            unmap(view);
            unmap(reader);
            drop((read_only, writable));
            memory.set_len(0).unwrap();

            // An empty file has no section.
            assert_eq!(delivery.deliver(&*memory, true).unwrap(), 0);
        }
    }
}
