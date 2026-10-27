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
    pub struct MemfdDelivery(pub SharedObjectSender);

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
            let delivery = MemfdDelivery(sender);
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
