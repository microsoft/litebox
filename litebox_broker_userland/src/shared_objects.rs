// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared file mappings: host shared memory for file contents, and its delivery to runners.
//!
//! The in-memory file system keeps a mapped file's contents in [`SharedFileMemory`] from a
//! [`SharedFileMemoryProvider`](litebox_broker_core::fs::shared_memory::SharedFileMemoryProvider).
//! When a runner asks to map the file, the association's [`SharedObjectDelivery`] hands it the
//! memory out of band, and the response carries the token it takes the memory with.

use std::io::Result as IoResult;

use litebox_broker_core::BrokerProcess;
use litebox_broker_core::fs::shared_memory::SharedFileMemory;
use litebox_broker_host::RequestFailure;
use litebox_broker_protocol::fs::{FileError, MapFileRequest, MapFileResponse};
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult, FileRequest, FileResponse};

/// Delivers host shared objects to the runner of one association.
pub trait SharedObjectDelivery: Send + Sync {
    /// Delivers `memory` to the runner, readable and, if `writable` is set, writable, returning
    /// the token the runner takes it with.
    fn deliver(&self, memory: &dyn SharedFileMemory, writable: bool) -> IoResult<u64>;
}

/// Handles a request to map a file, delivering its shared memory through `delivery`, or returns
/// `None` for other operations.
pub(crate) fn handle_map_file(
    delivery: Option<&dyn SharedObjectDelivery>,
    process: &BrokerProcess,
    operation: &BrokerOperation,
) -> Option<Result<BrokerResult, RequestFailure>> {
    let BrokerOperation::File(FileRequest::Map(MapFileRequest { handle, writable })) = *operation
    else {
        return None;
    };
    let response = match delivery {
        None => FileResponse::Failed(FileError::NoSuchDevice),
        Some(delivery) => match litebox_broker_core::fs::map_shared(process, handle, writable) {
            Err(error) => return Some(Err(RequestFailure::from(error))),
            Ok(Err(error)) => FileResponse::Failed(error),
            Ok(Ok(mapping)) => match delivery.deliver(&*mapping.memory, mapping.writable) {
                Ok(token) => FileResponse::Map(MapFileResponse {
                    memory: mapping.memory_id,
                    token,
                    writable: mapping.writable,
                }),
                Err(error) => {
                    litebox_util_log::warn!(error:% = error; "failed to deliver a shared file");
                    FileResponse::Failed(FileError::NoSpace)
                }
            },
        },
    };
    Some(Ok(BrokerResult::File(response)))
}

/// A file's contents in a host file, accessed with positional I/O.
#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
mod host_file {
    use std::any::Any;
    use std::fs::File;
    use std::io::{Error as IoError, ErrorKind};

    use litebox_broker_core::fs::shared_memory::{SharedFileMemory, SharedFileMemoryError};
    use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

    /// Size of the stack buffer that copies to and from buffers whose bytes cannot be reached
    /// directly, such as a guest's memory.
    const STAGING_SIZE: usize = 4096;

    /// A file's contents in a host file: a memfd on Linux, or a temporary file on Windows. Its
    /// size is the file's.
    pub(super) struct HostFileMemory {
        pub(super) file: File,
        /// The file opened again read-only, for runners that may only read it.
        #[cfg(target_os = "linux")]
        pub(super) read_only: std::sync::OnceLock<File>,
    }

    impl HostFileMemory {
        pub(super) fn new(file: File) -> Self {
            Self {
                file,
                #[cfg(target_os = "linux")]
                read_only: std::sync::OnceLock::new(),
            }
        }

        /// Reads into `buffer` at `offset` with one positional read, returning 0 at the end.
        fn read_once(&self, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
            loop {
                #[cfg(target_os = "linux")]
                let read = std::os::unix::fs::FileExt::read_at(&self.file, buffer, offset);
                #[cfg(windows)]
                let read = std::os::windows::fs::FileExt::seek_read(&self.file, buffer, offset);
                match read {
                    Err(error) if error.kind() == ErrorKind::Interrupted => {}
                    #[cfg(windows)]
                    Err(error)
                        if error.raw_os_error()
                            == Some(
                                windows_sys::Win32::Foundation::ERROR_HANDLE_EOF.cast_signed(),
                            ) =>
                    {
                        return Ok(0);
                    }
                    read => return read,
                }
            }
        }

        /// Writes all of `data` at `offset`.
        fn write_all(&self, mut data: &[u8], mut offset: u64) -> std::io::Result<()> {
            while !data.is_empty() {
                #[cfg(target_os = "linux")]
                let written = std::os::unix::fs::FileExt::write_at(&self.file, data, offset);
                #[cfg(windows)]
                let written = std::os::windows::fs::FileExt::seek_write(&self.file, data, offset);
                match written {
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
    }

    /// Classifies a host error accessing a file's memory.
    pub(super) fn memory_error(error: &IoError) -> SharedFileMemoryError {
        let code = error.raw_os_error();
        #[cfg(target_os = "linux")]
        if code == Some(libc::ENOSPC) || code == Some(libc::ENOMEM) {
            return SharedFileMemoryError::NoMemory;
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{
                ERROR_DISK_FULL, ERROR_HANDLE_DISK_FULL, ERROR_USER_MAPPED_FILE,
            };
            let code = code.and_then(|code| u32::try_from(code).ok());
            if code == Some(ERROR_USER_MAPPED_FILE) {
                return SharedFileMemoryError::Busy;
            }
            if code == Some(ERROR_DISK_FULL) || code == Some(ERROR_HANDLE_DISK_FULL) {
                return SharedFileMemoryError::NoMemory;
            }
        }
        SharedFileMemoryError::Io
    }

    fn position(offset: usize) -> Result<u64, SharedFileMemoryError> {
        u64::try_from(offset).map_err(|_| SharedFileMemoryError::Io)
    }

    impl SharedFileMemory for HostFileMemory {
        fn read_at(
            &self,
            offset: usize,
            buffer: &mut dyn ReadBuffer,
        ) -> Result<usize, SharedFileMemoryError> {
            let position = position(offset)?;
            #[cfg(target_os = "linux")]
            let direct = crate::fs::linux::read_at(&self.file, buffer, position);
            #[cfg(windows)]
            let direct = crate::fs::windows::read_at(&self.file, buffer, position);
            if let Some(read) = direct {
                return read.map_err(|error| memory_error(&error));
            }
            let mut staging = [0; STAGING_SIZE];
            let mut read = 0;
            while read < buffer.len() {
                let chunk = &mut staging[..STAGING_SIZE.min(buffer.len() - read)];
                let count = self
                    .read_once(chunk, position + read as u64)
                    .map_err(|error| memory_error(&error))?;
                if count == 0 {
                    break;
                }
                buffer.copy_from_slice_at(read, &chunk[..count])?;
                read += count;
            }
            Ok(read)
        }

        fn write_at(
            &self,
            offset: usize,
            data: &dyn WriteBuffer,
        ) -> Result<(), SharedFileMemoryError> {
            let position = position(offset)?;
            #[cfg(target_os = "linux")]
            let direct = crate::fs::linux::write_at(&self.file, data, position);
            #[cfg(windows)]
            let direct = crate::fs::windows::write_at(&self.file, data, position);
            // A short direct write, which the memory being large enough makes unlikely, goes on
            // through the stack buffer.
            let mut written = match direct {
                Some(written) => written.map_err(|error| memory_error(&error))?,
                None => 0,
            };
            let mut staging = [0; STAGING_SIZE];
            while written < data.len() {
                let chunk = &mut staging[..STAGING_SIZE.min(data.len() - written)];
                data.copy_to_slice_at(written, chunk)?;
                self.write_all(chunk, position + written as u64)
                    .map_err(|error| memory_error(&error))?;
                written += chunk.len();
            }
            Ok(())
        }

        fn size(&self) -> Result<usize, SharedFileMemoryError> {
            let length = self
                .file
                .metadata()
                .map_err(|error| memory_error(&error))?
                .len();
            usize::try_from(length).map_err(|_| SharedFileMemoryError::Io)
        }

        fn set_len(&self, length: usize) -> Result<(), SharedFileMemoryError> {
            self.file
                .set_len(position(length)?)
                .map_err(|error| memory_error(&error))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// Creates memory holding `contents` in `file`, which must be empty.
    pub(super) fn create(
        file: File,
        contents: &[u8],
    ) -> Result<std::sync::Arc<dyn SharedFileMemory>, SharedFileMemoryError> {
        let memory = HostFileMemory::new(file);
        memory.set_len(contents.len())?;
        memory.write_at(0, &contents)?;
        Ok(std::sync::Arc::new(memory))
    }

    #[cfg(test)]
    pub(super) mod tests {
        use super::*;
        use litebox_broker_core::fs::shared_memory::SharedFileMemoryProvider;
        use litebox_platform::buffer::{Buffer, Fault};

        /// A buffer whose bytes cannot be reached directly, like a guest's memory.
        struct IndirectBuffer(Vec<u8>);

        impl Buffer for IndirectBuffer {
            fn len(&self) -> usize {
                self.0.len()
            }
        }

        impl ReadBuffer for IndirectBuffer {
            fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
                self.0[offset..][..source.len()].copy_from_slice(source);
                Ok(())
            }

            fn copy_from_raw_at(
                &mut self,
                offset: usize,
                source: litebox_platform::buffer::RawBytes<'_>,
            ) -> Result<(), Fault> {
                source.copy_to_slice(&mut self.0[offset..][..source.len()]);
                Ok(())
            }
        }

        impl WriteBuffer for IndirectBuffer {
            fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
                destination.copy_from_slice(&self.0[offset..][..destination.len()]);
                Ok(())
            }

            fn copy_to_raw_at(
                &self,
                offset: usize,
                destination: litebox_platform::buffer::RawBytes<'_>,
            ) -> Result<(), Fault> {
                destination.copy_from_slice(&self.0[offset..][..destination.len()]);
                Ok(())
            }
        }

        /// Checks memory from `provider` through both direct and staged copies.
        pub(in crate::shared_objects) fn check_reads_writes_and_resizes(
            provider: &dyn SharedFileMemoryProvider,
        ) {
            let memory = provider.create(b"hello").unwrap();
            assert_eq!(memory.size().unwrap(), 5);
            let mut bytes = [0; 8];
            assert_eq!(memory.read_at(0, &mut bytes.as_mut_slice()).unwrap(), 5);
            assert_eq!(&bytes[..5], b"hello");
            memory.set_len(8).unwrap();
            memory.write_at(6, &b"!!".as_slice()).unwrap();
            assert_eq!(memory.read_at(0, &mut bytes.as_mut_slice()).unwrap(), 8);
            assert_eq!(&bytes, b"hello\0!!");

            // Buffers that only faulting copies reach go through the stack buffer, in chunks.
            let large: Vec<u8> = (0..3 * STAGING_SIZE + 5)
                .map(|i| u8::try_from(i % 251).unwrap())
                .collect();
            memory.set_len(large.len() + 1).unwrap();
            memory.write_at(1, &IndirectBuffer(large.clone())).unwrap();
            let mut read = IndirectBuffer(vec![0; large.len() + 7]);
            assert_eq!(memory.read_at(1, &mut read).unwrap(), large.len());
            assert_eq!(&read.0[..large.len()], large.as_slice());

            memory.set_len(2).unwrap();
            assert_eq!(memory.size().unwrap(), 2);
            assert_eq!(memory.read_at(1, &mut bytes.as_mut_slice()).unwrap(), 1);
            assert_eq!(memory.read_at(4, &mut bytes.as_mut_slice()).unwrap(), 0);
        }
    }
}

/// Memfd-backed shared file memory for Linux.
#[cfg(target_os = "linux")]
pub mod linux {
    use std::fs::File;
    use std::io::{Error as IoError, Result as IoResult};
    use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _};
    use std::sync::Arc;

    use litebox_broker_core::fs::shared_memory::{
        SharedFileMemory, SharedFileMemoryError, SharedFileMemoryProvider,
    };
    use litebox_broker_transport_linux_userland::shared_objects::SharedObjectSender;

    use super::SharedObjectDelivery;
    use super::host_file::{HostFileMemory, create, memory_error};

    /// Creates memory for files in memfds.
    ///
    /// The broker only ever accesses a memfd with positional I/O, which cannot fault. A runner
    /// that may map a memfd writable can grow it with `write`, though its syscall filter denies
    /// `ftruncate` and `fallocate`, which the broker sees as the file growing.
    pub struct MemfdFileMemoryProvider;

    impl SharedFileMemoryProvider for MemfdFileMemoryProvider {
        fn create(
            &self,
            contents: &[u8],
        ) -> Result<Arc<dyn SharedFileMemory>, SharedFileMemoryError> {
            // SAFETY: The name is a valid C string, and the call creates a new descriptor.
            let fd =
                unsafe { libc::memfd_create(c"litebox-shared-file".as_ptr(), libc::MFD_CLOEXEC) };
            if fd < 0 {
                return Err(memory_error(&IoError::last_os_error()));
            }
            // SAFETY: `memfd_create` returned a new descriptor that nothing else owns.
            let file = unsafe { File::from_raw_fd(fd) };
            create(file, contents)
        }
    }

    /// Delivers [`MemfdFileMemory`] over a runner's shared-object socket.
    pub struct MemfdDelivery(pub Arc<SharedObjectSender>);

    impl SharedObjectDelivery for MemfdDelivery {
        fn deliver(&self, memory: &dyn SharedFileMemory, writable: bool) -> IoResult<u64> {
            let memory = memory
                .as_any()
                .downcast_ref::<HostFileMemory>()
                .ok_or_else(|| IoError::other("shared memory is not a memfd"))?;
            if writable {
                return self.0.send(memory.file.as_fd());
            }
            // A runner that may only read the file gets a descriptor that cannot be mapped
            // writable, opened anew once so that it does not share the broker's access mode.
            let read_only = if let Some(read_only) = memory.read_only.get() {
                read_only
            } else {
                let file = File::open(format!("/proc/self/fd/{}", memory.file.as_raw_fd()))?;
                memory.read_only.get_or_init(|| file)
            };
            self.0.send(read_only.as_fd())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use litebox_platform_linux_userland::shared_objects::SharedObjectChannel;
        use std::os::fd::OwnedFd;

        #[test]
        fn memfd_memory_reads_writes_and_resizes() {
            super::super::host_file::tests::check_reads_writes_and_resizes(
                &MemfdFileMemoryProvider,
            );
        }

        #[test]
        fn read_only_delivery_cannot_be_mapped_writable() {
            let (sender, runner) = SharedObjectSender::pair().unwrap();
            let channel = SharedObjectChannel::new(runner);
            let delivery = MemfdDelivery(Arc::new(sender));
            let memory = MemfdFileMemoryProvider.create(&[0; 4096]).unwrap();
            let read_only = delivery.deliver(&*memory, false).unwrap();
            let again = delivery.deliver(&*memory, false).unwrap();
            let writable = delivery.deliver(&*memory, true).unwrap();

            let map = |fd: &OwnedFd, prot| {
                // SAFETY: Maps fresh pages that nothing else uses.
                let address = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        4096,
                        prot,
                        libc::MAP_SHARED,
                        fd.as_raw_fd(),
                        0,
                    )
                };
                if address != libc::MAP_FAILED {
                    // SAFETY: Unmaps the mapping just created.
                    unsafe { libc::munmap(address, 4096) };
                }
                address != libc::MAP_FAILED
            };
            for token in [read_only, again] {
                let fd = channel.take(token).unwrap();
                assert!(map(&fd, libc::PROT_READ));
                assert!(!map(&fd, libc::PROT_READ | libc::PROT_WRITE));
            }
            let fd = channel.take(writable).unwrap();
            assert!(map(&fd, libc::PROT_READ | libc::PROT_WRITE));
        }
    }
}

/// Temporary-file-backed shared file memory for Windows.
///
/// Pagefile-backed sections cannot grow, but sections of a file can be created at any size the
/// file has, so a mapped file's contents live in a temporary file that is deleted when the broker
/// closes it. Every runner mapping the file gets its own section of it, sized to the file when
/// mapped, and all sections of one file share the file's pages.
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows {
    use std::io::{Error as IoError, ErrorKind, Result as IoResult};
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::{AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle};
    use std::sync::Arc;

    use litebox_broker_core::fs::shared_memory::{
        SharedFileMemory, SharedFileMemoryError, SharedFileMemoryProvider,
    };
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
    use super::host_file::{HostFileMemory, create, memory_error};

    /// Creates memory for files in the host's temporary directory.
    pub struct TempFileMemoryProvider;

    impl SharedFileMemoryProvider for TempFileMemoryProvider {
        fn create(
            &self,
            contents: &[u8],
        ) -> Result<Arc<dyn SharedFileMemory>, SharedFileMemoryError> {
            let directory = std::env::temp_dir();
            let file = loop {
                let mut nonce = [0u8; 8];
                getrandom::fill(&mut nonce).map_err(|_| SharedFileMemoryError::Io)?;
                let path = directory.join(format!(
                    "litebox-shared-file-{}-{:016x}",
                    std::process::id(),
                    u64::from_le_bytes(nonce),
                ));
                // Sections need execute access to the file for runners to map it executable, as
                // Linux allows for a shared file mapping. No other process may open the file, and
                // it is deleted when the broker closes it.
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
                    Ok(file) => break file,
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(memory_error(&error)),
                }
            };
            create(file, contents)
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
        fn deliver(&self, memory: &dyn SharedFileMemory, writable: bool) -> IoResult<u64> {
            let memory = memory
                .as_any()
                .downcast_ref::<HostFileMemory>()
                .ok_or_else(|| IoError::other("shared memory is not a temporary file"))?;
            // A runner that may only read the file gets a read-only section, which no handle
            // rights can map writable.
            let protection = if writable {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_EXECUTE_READ
            };
            // SAFETY: The file handle is live. Zero sizes make the section the file's size, and
            // the section is unnamed with default security.
            let section = unsafe {
                CreateFileMappingW(
                    memory.file.as_raw_handle(),
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
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::System::Memory::{
            FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
            UnmapViewOfFile,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        #[test]
        fn temp_file_memory_reads_writes_and_resizes() {
            super::super::host_file::tests::check_reads_writes_and_resizes(&TempFileMemoryProvider);
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

            // The file cannot shrink while it is mapped, but can grow.
            assert_eq!(memory.set_len(0), Err(SharedFileMemoryError::Busy));
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
