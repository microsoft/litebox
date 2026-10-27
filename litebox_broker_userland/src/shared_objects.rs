// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared file mappings: host shared memory for file contents, and its delivery to runners.
//!
//! The in-memory file system keeps a mapped file's contents in [`SharedFileMemory`] from a
//! [`SharedFileMemoryProvider`]. When a runner asks to map the file, the association's
//! [`SharedObjectDelivery`] hands it the memory out of band, and the response carries the token
//! it takes the memory with.

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
            Ok(Ok(mapping)) => match delivery.deliver(&*mapping.memory, writable) {
                Ok(token) => FileResponse::Map(MapFileResponse {
                    identity: mapping.identity,
                    token,
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

/// Memfd-backed shared file memory for Linux.
#[cfg(target_os = "linux")]
pub mod linux {
    use std::any::Any;
    use std::fs::File;
    use std::io::{Error as IoError, Result as IoResult};
    use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::FileExt as _;
    use std::sync::Arc;

    use litebox_broker_core::fs::shared_memory::{
        SharedFileMemory, SharedFileMemoryError, SharedFileMemoryProvider,
    };
    use litebox_broker_transport_linux_userland::shared_objects::SharedObjectSender;

    use super::SharedObjectDelivery;

    /// A file's contents in a memfd, whose size is the file's.
    ///
    /// The broker only ever accesses it with positional I/O, which cannot fault. Runners cannot
    /// resize it, since their syscall filter denies `ftruncate` and `fallocate`.
    pub struct MemfdFileMemory {
        file: File,
    }

    fn io_error(_: IoError) -> SharedFileMemoryError {
        SharedFileMemoryError::Io
    }

    impl SharedFileMemory for MemfdFileMemory {
        fn read_at(
            &self,
            offset: usize,
            buffer: &mut [u8],
        ) -> Result<usize, SharedFileMemoryError> {
            let mut read = 0;
            while read < buffer.len() {
                match self
                    .file
                    .read_at(&mut buffer[read..], (offset + read) as u64)
                {
                    Ok(0) => break,
                    Ok(count) => read += count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(io_error(error)),
                }
            }
            Ok(read)
        }

        fn write_at(&self, offset: usize, data: &[u8]) -> Result<(), SharedFileMemoryError> {
            self.file
                .write_all_at(data, offset as u64)
                .map_err(io_error)
        }

        fn set_len(&self, length: usize) -> Result<(), SharedFileMemoryError> {
            self.file.set_len(length as u64).map_err(|error| {
                if error.raw_os_error() == Some(libc::ENOSPC) {
                    SharedFileMemoryError::NoMemory
                } else {
                    SharedFileMemoryError::Io
                }
            })
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// Creates [`MemfdFileMemory`].
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
                return Err(SharedFileMemoryError::NoMemory);
            }
            // SAFETY: `memfd_create` returned a new descriptor that nothing else owns.
            let file = unsafe { File::from_raw_fd(fd) };
            let memory = MemfdFileMemory { file };
            memory.set_len(contents.len())?;
            memory.write_at(0, contents)?;
            Ok(Arc::new(memory))
        }
    }

    /// Delivers [`MemfdFileMemory`] over a runner's shared-object socket.
    pub struct MemfdDelivery(pub Arc<SharedObjectSender>);

    impl SharedObjectDelivery for MemfdDelivery {
        fn deliver(&self, memory: &dyn SharedFileMemory, writable: bool) -> IoResult<u64> {
            let memory = memory
                .as_any()
                .downcast_ref::<MemfdFileMemory>()
                .ok_or_else(|| IoError::other("shared memory is not a memfd"))?;
            if writable {
                return self.0.send(memory.file.as_fd());
            }
            // A runner that may only read the file gets a descriptor that cannot be mapped
            // writable, opened anew so that it does not share the broker's access mode.
            let read_only = File::open(format!("/proc/self/fd/{}", memory.file.as_raw_fd()))?;
            self.0.send(read_only.as_fd())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn memfd_memory_reads_writes_and_resizes() {
            let memory = MemfdFileMemoryProvider.create(b"hello").unwrap();
            let mut bytes = [0; 8];
            assert_eq!(memory.read_at(0, &mut bytes).unwrap(), 5);
            assert_eq!(&bytes[..5], b"hello");
            memory.set_len(8).unwrap();
            memory.write_at(6, b"!!").unwrap();
            assert_eq!(memory.read_at(0, &mut bytes).unwrap(), 8);
            assert_eq!(&bytes, b"hello\0!!");
            memory.set_len(2).unwrap();
            assert_eq!(memory.read_at(1, &mut bytes).unwrap(), 1);
        }

        #[test]
        fn read_only_delivery_cannot_be_mapped_writable() {
            use std::os::fd::OwnedFd;

            let (sender, runner) = SharedObjectSender::pair().unwrap();
            let delivery = MemfdDelivery(Arc::new(sender));
            let memory = MemfdFileMemoryProvider.create(&[0; 4096]).unwrap();
            delivery.deliver(&*memory, false).unwrap();
            delivery.deliver(&*memory, true).unwrap();

            let receive = || -> OwnedFd {
                let mut token = [0u8; 8];
                let mut control = [0u64; 4];
                let mut iov = libc::iovec {
                    iov_base: token.as_mut_ptr().cast(),
                    iov_len: 8,
                };
                // SAFETY: `msghdr` is plain data, for which all-zero bytes are valid.
                let mut header: libc::msghdr = unsafe { core::mem::zeroed() };
                header.msg_iov = &raw mut iov;
                header.msg_iovlen = 1;
                header.msg_control = control.as_mut_ptr().cast();
                header.msg_controllen = size_of_val(&control) as _;
                // SAFETY: `header` describes live buffers.
                assert_eq!(
                    unsafe { libc::recvmsg(runner.as_raw_fd(), &raw mut header, 0) },
                    8
                );
                // SAFETY: The message carries one descriptor.
                unsafe {
                    let message = libc::CMSG_FIRSTHDR(&raw const header);
                    OwnedFd::from_raw_fd(libc::CMSG_DATA(message).cast::<i32>().read_unaligned())
                }
            };
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
            let read_only = receive();
            assert!(map(&read_only, libc::PROT_READ));
            assert!(!map(&read_only, libc::PROT_READ | libc::PROT_WRITE));
            let writable = receive();
            assert!(map(&writable, libc::PROT_READ | libc::PROT_WRITE));
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
    use std::any::Any;
    use std::fs::File;
    use std::io::{Error as IoError, ErrorKind, Result as IoResult};
    use std::os::windows::fs::{FileExt as _, OpenOptionsExt as _};
    use std::os::windows::io::{AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle};
    use std::sync::Arc;

    use litebox_broker_core::fs::shared_memory::{
        SharedFileMemory, SharedFileMemoryError, SharedFileMemoryProvider,
    };
    use windows_sys::Win32::Foundation::{
        DUPLICATE_CLOSE_SOURCE, DuplicateHandle, ERROR_DISK_FULL, ERROR_FILE_INVALID,
        ERROR_HANDLE_DISK_FULL, ERROR_HANDLE_EOF, ERROR_USER_MAPPED_FILE, GENERIC_EXECUTE,
        GENERIC_READ, GENERIC_WRITE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_DELETE_ON_CLOSE,
    };
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, SECTION_MAP_EXECUTE,
        SECTION_MAP_READ, SECTION_MAP_WRITE, SECTION_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, PROCESS_DUP_HANDLE};

    use super::SharedObjectDelivery;

    /// A file's contents in a temporary file, whose size is the file's.
    ///
    /// Runners only ever receive sections of it, which cannot change its size, and Windows keeps
    /// file I/O coherent with every view of those sections.
    pub struct TempFileMemory {
        file: File,
    }

    fn memory_error(error: &IoError) -> SharedFileMemoryError {
        match error
            .raw_os_error()
            .and_then(|code| u32::try_from(code).ok())
        {
            Some(ERROR_USER_MAPPED_FILE) => SharedFileMemoryError::Busy,
            Some(ERROR_DISK_FULL | ERROR_HANDLE_DISK_FULL) => SharedFileMemoryError::NoMemory,
            _ => SharedFileMemoryError::Io,
        }
    }

    impl SharedFileMemory for TempFileMemory {
        fn read_at(
            &self,
            offset: usize,
            buffer: &mut [u8],
        ) -> Result<usize, SharedFileMemoryError> {
            let mut read = 0;
            while read < buffer.len() {
                match self
                    .file
                    .seek_read(&mut buffer[read..], (offset + read) as u64)
                {
                    Ok(0) => break,
                    Ok(count) => read += count,
                    Err(error) if error.kind() == ErrorKind::Interrupted => {}
                    // Reading at or past the end of the file is the end of the memory.
                    Err(error) if error.raw_os_error() == i32::try_from(ERROR_HANDLE_EOF).ok() => {
                        break;
                    }
                    Err(error) => return Err(memory_error(&error)),
                }
            }
            Ok(read)
        }

        fn write_at(&self, offset: usize, data: &[u8]) -> Result<(), SharedFileMemoryError> {
            let mut written = 0;
            while written < data.len() {
                match self
                    .file
                    .seek_write(&data[written..], (offset + written) as u64)
                {
                    Ok(0) => return Err(SharedFileMemoryError::Io),
                    Ok(count) => written += count,
                    Err(error) if error.kind() == ErrorKind::Interrupted => {}
                    Err(error) => return Err(memory_error(&error)),
                }
            }
            Ok(())
        }

        fn set_len(&self, length: usize) -> Result<(), SharedFileMemoryError> {
            // Windows refuses to shrink a file while any section of it is mapped.
            self.file
                .set_len(length as u64)
                .map_err(|error| memory_error(&error))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// Creates [`TempFileMemory`] in the host's temporary directory.
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
            let memory = TempFileMemory { file };
            memory.set_len(contents.len())?;
            memory.write_at(0, contents)?;
            Ok(Arc::new(memory))
        }
    }

    /// Delivers [`TempFileMemory`] to a runner process as a section handle in its handle table.
    pub struct SectionDelivery {
        process: OwnedHandle,
    }

    impl SectionDelivery {
        /// Delivers sections into `process`, which must allow duplicating handles into it.
        pub fn new(process: BorrowedHandle<'_>) -> IoResult<Self> {
            let mut duplicate = std::ptr::null_mut();
            // SAFETY: `process` is a live process handle, and the output is writable.
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    process.as_raw_handle(),
                    GetCurrentProcess(),
                    &raw mut duplicate,
                    PROCESS_DUP_HANDLE,
                    0,
                    0,
                )
            } == 0
            {
                return Err(IoError::last_os_error());
            }
            // SAFETY: DuplicateHandle returned a new handle that this process owns.
            let process = unsafe { OwnedHandle::from_raw_handle(duplicate) };
            Ok(Self { process })
        }
    }

    impl SharedObjectDelivery for SectionDelivery {
        fn deliver(&self, memory: &dyn SharedFileMemory, writable: bool) -> IoResult<u64> {
            let memory = memory
                .as_any()
                .downcast_ref::<TempFileMemory>()
                .ok_or_else(|| IoError::other("shared memory is not a temporary file"))?;
            // A runner that may only read the file gets a read-only section, which no handle
            // rights can map writable.
            let (protection, access) = if writable {
                (PAGE_EXECUTE_READWRITE, SECTION_MAP_WRITE)
            } else {
                (PAGE_EXECUTE_READ, 0)
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
            let mut delivered = std::ptr::null_mut();
            // SAFETY: `section` is a new handle that this process owns, which the call closes
            // whether or not it succeeds, and `self.process` allows duplicating handles into it.
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    section,
                    self.process.as_raw_handle(),
                    &raw mut delivered,
                    SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_EXECUTE | access,
                    0,
                    DUPLICATE_CLOSE_SOURCE,
                )
            } == 0
            {
                return Err(IoError::last_os_error());
            }
            Ok(delivered as u64)
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

        #[test]
        fn temp_file_memory_reads_writes_and_resizes() {
            let memory = TempFileMemoryProvider.create(b"hello").unwrap();
            let mut bytes = [0; 8];
            assert_eq!(memory.read_at(0, &mut bytes).unwrap(), 5);
            assert_eq!(&bytes[..5], b"hello");
            memory.set_len(8).unwrap();
            memory.write_at(6, b"!!").unwrap();
            assert_eq!(memory.read_at(0, &mut bytes).unwrap(), 8);
            assert_eq!(&bytes, b"hello\0!!");
            memory.set_len(2).unwrap();
            assert_eq!(memory.read_at(1, &mut bytes).unwrap(), 1);
            assert_eq!(memory.read_at(4, &mut bytes).unwrap(), 0);
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
            memory.read_at(0, &mut byte).unwrap();
            assert_eq!(byte, [42]);
            memory.write_at(1, &[7]).unwrap();
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
