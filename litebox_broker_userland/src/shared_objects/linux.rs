// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::File;
use std::io::{Error as IoError, Result as IoResult};
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _};
use std::sync::Arc;

use litebox_broker_core::fs::shared_memory::{
    HostHandle, SharedFileMemory, SharedFileMemoryError, SharedFileMemoryProvider, SharedFileObject,
};
use litebox_broker_transport_linux_userland::shared_objects::SharedObjectSender;

use super::SharedObjectDelivery;
use super::host_file::{Exported, HostFileMemory, create, memory_error};

/// Linux keeps no state of its own: a memfd's size is the file's size.
#[derive(Default)]
pub(super) struct State {}

impl HostFileMemory {
    /// Returns the file's size. Callers hold `io`.
    pub(super) fn len(&self) -> Result<u64, SharedFileMemoryError> {
        self.host_len()
    }

    /// Returns the size past which reads stop short of the host file's end, if any.
    #[expect(clippy::unused_self, reason = "Windows keeps a size of its own")]
    pub(super) fn read_limit(&self) -> Option<u64> {
        None
    }

    /// Resizes the file to `length` bytes. Callers hold `io` alone.
    pub(super) fn resize(&self, length: u64) -> Result<(), SharedFileMemoryError> {
        self.file
            .set_len(length)
            .map_err(|error| memory_error(&error))
    }

    /// Records a write that ended at `end`. Callers hold `io` alone.
    #[expect(clippy::unused_self, reason = "Windows keeps a size of its own")]
    pub(super) fn after_write(&self, _end: u64) {}

    /// Returns a handle for exporting the memfd, writable only if `writable` is set.
    pub(super) fn export(
        &self,
        writable: bool,
    ) -> Result<Box<dyn HostHandle + '_>, SharedFileMemoryError> {
        use std::os::fd::{AsFd as _, AsRawFd as _};

        if writable {
            return Ok(Box::new(Exported(self.file.as_fd())));
        }
        // The host checks a descriptor's access mode when mapping it, so readers get a
        // read-only open, made for this export alone so that no extra descriptor stays open
        // between deliveries. Duplication preserves the access mode, so reopen.
        let reader = File::open(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
            .map_err(|_| SharedFileMemoryError::Unsupported)?;
        Ok(Box::new(Exported(reader)))
    }
}

impl<H: std::os::fd::AsFd + Send> HostHandle for Exported<H> {
    fn raw(&self) -> u64 {
        use std::os::fd::AsRawFd as _;

        // Open descriptors are never negative.
        u64::from(self.0.as_fd().as_raw_fd().cast_unsigned())
    }
}

/// Returns the most bytes the host lets the broker's files hold.
///
/// Growing a file past `RLIMIT_FSIZE` would raise `SIGXFSZ`, which ends the broker by default,
/// so the memory never tries to.
pub(super) fn size_limit() -> u64 {
    let limit = i64::MAX.cast_unsigned();
    let mut rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `rlimit` is valid for the call to fill.
    if unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &raw mut rlimit) } == 0
        && rlimit.rlim_cur != libc::RLIM_INFINITY
    {
        return limit.min(rlimit.rlim_cur);
    }
    limit
}

/// Returns what the host error `code` means for shared file memory, if more than an I/O error.
pub(super) fn memory_error_for(code: i32) -> Option<SharedFileMemoryError> {
    match code {
        libc::ENOSPC | libc::ENOMEM | libc::EFBIG | libc::EMFILE | libc::ENFILE => {
            Some(SharedFileMemoryError::NoMemory)
        }
        libc::EFAULT => Some(SharedFileMemoryError::Fault),
        _ => None,
    }
}

/// Returns whether a positional read failed only because it started past the end of the file,
/// which Linux reports as reading nothing instead.
pub(super) fn read_reached_end(_error: &IoError) -> bool {
    false
}

/// Creates memory for files in memfds, accessed only through positional I/O by the broker.
pub struct MemfdFileMemoryProvider;

/// Creates a memfd with `flags`, executable if the host allows.
fn new_memfd(flags: libc::c_uint) -> Result<File, SharedFileMemoryError> {
    // Ask for execution support where the host otherwise seals memfds against execution.
    // Older kernels and hosts that forbid it leave a plain memfd as the best available.
    let memfd = |flags| {
        // SAFETY: The name is a valid C string, and the call creates a new descriptor.
        unsafe { libc::memfd_create(c"litebox-shared-file".as_ptr(), flags) }
    };
    let mut fd = memfd(flags | libc::MFD_CLOEXEC | libc::MFD_EXEC);
    if fd < 0 {
        fd = memfd(flags | libc::MFD_CLOEXEC);
    }
    if fd < 0 {
        return Err(memory_error(&IoError::last_os_error()));
    }
    // SAFETY: `memfd_create` returned a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

impl SharedFileMemoryProvider for MemfdFileMemoryProvider {
    fn create(&self, contents: &[u8]) -> Result<Arc<dyn SharedFileMemory>, SharedFileMemoryError> {
        create(new_memfd(0)?, contents)
    }

    /// Copies `contents` into a memfd sealed against any change of its contents or size,
    /// which the kernel enforces on every holder of the descriptor, runners and broker
    /// alike: writes and writable shared mappings fail, while private mappings stay
    /// writable, with their writes in copies of the pages.
    fn create_sealed(
        &self,
        contents: &[u8],
    ) -> Result<Arc<dyn SharedFileObject>, SharedFileMemoryError> {
        let file = new_memfd(libc::MFD_ALLOW_SEALING)?;
        let length = u64::try_from(contents.len()).map_err(|_| SharedFileMemoryError::NoMemory)?;
        file.set_len(length).map_err(|error| memory_error(&error))?;
        std::os::unix::fs::FileExt::write_all_at(&file, contents, 0)
            .map_err(|error| memory_error(&error))?;
        let seals =
            libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
        // SAFETY: Seals a descriptor that `file` owns.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(memory_error(&IoError::last_os_error()));
        }
        Ok(Arc::new(SealedMemfd(file)))
    }
}

/// A memfd sealed so that its contents never change.
struct SealedMemfd(File);

impl SharedFileObject for SealedMemfd {
    /// Lends the memfd itself, even to a reader: its seals, rather than its access mode,
    /// refuse every writable shared mapping.
    fn host_handle(
        &self,
        _writable: bool,
    ) -> Result<Box<dyn HostHandle + '_>, SharedFileMemoryError> {
        use std::os::fd::AsFd as _;

        Ok(Box::new(super::host_file::Exported(self.0.as_fd())))
    }
}

/// Delivers memfds over a runner's shared-object socket.
pub struct MemfdDelivery(pub Arc<SharedObjectSender>);

impl SharedObjectDelivery for MemfdDelivery {
    fn deliver(&self, object: &dyn SharedFileObject, writable: bool) -> IoResult<u64> {
        // The object lends a descriptor whose access mode allows writable mappings exactly
        // when `writable` is set.
        let handle = super::host_handle(object, writable)?;
        let raw = std::os::fd::RawFd::try_from(handle.raw())
            .map_err(|_| IoError::other("host handle is not a descriptor"))?;
        // SAFETY: `handle` lends a descriptor that stays open while it is borrowed, which
        // outlasts the send.
        self.0.send(unsafe { BorrowedFd::borrow_raw(raw) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memfd_memory_reads_writes_and_resizes() {
        super::super::host_file::tests::check_reads_writes_and_resizes(&MemfdFileMemoryProvider);
    }

    #[test]
    fn memfd_memory_stays_within_size_limits() {
        super::super::host_file::tests::check_size_limit(new_memfd(0).unwrap());
    }

    #[test]
    fn reader_handles_are_read_only_and_closed_after_export() {
        let open_descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let memory = MemfdFileMemoryProvider.create(b"hello").unwrap();
        let before = open_descriptors();
        let reader = memory.host_handle(false).unwrap();
        let raw = libc::c_int::try_from(reader.raw()).unwrap();
        // SAFETY: The handle lends a live descriptor.
        assert_eq!(
            unsafe { libc::fcntl(raw, libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDONLY
        );
        drop(reader);
        assert_eq!(open_descriptors(), before);

        let writer = memory.host_handle(true).unwrap();
        let raw = libc::c_int::try_from(writer.raw()).unwrap();
        // SAFETY: The handle lends a live descriptor.
        assert_eq!(
            unsafe { libc::fcntl(raw, libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDWR
        );
        drop(writer);
        assert_eq!(open_descriptors(), before);
    }

    mod delivery {
        use super::*;
        use litebox_platform_linux_userland::shared_objects::SharedObjectChannel;
        use std::os::fd::OwnedFd;

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

        #[test]
        fn sealed_snapshots_map_privately_but_never_change() {
            let (sender, runner) = SharedObjectSender::pair().unwrap();
            let channel = SharedObjectChannel::new(runner);
            let delivery = MemfdDelivery(Arc::new(sender));
            let snapshot = MemfdFileMemoryProvider.create_sealed(b"hello").unwrap();
            let fd = channel
                .take(delivery.deliver(&*snapshot, false).unwrap())
                .unwrap();

            let map = |flags| {
                // SAFETY: Maps fresh pages that nothing else uses.
                let address = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                        flags,
                        fd.as_raw_fd(),
                        0,
                    )
                };
                (address != libc::MAP_FAILED).then_some(address.cast::<u8>())
            };
            assert!(map(libc::MAP_SHARED).is_none());
            let private = map(libc::MAP_PRIVATE).unwrap();
            let again = map(libc::MAP_PRIVATE).unwrap();
            // SAFETY: Both mappings are 4096 bytes, readable and writable, and nothing else uses
            // them.
            unsafe {
                assert_eq!(core::slice::from_raw_parts(private, 5), b"hello");
                *private = b'J';
                assert_eq!(*again, b'h', "a private write is the writer's alone");
                libc::munmap(private.cast(), 4096);
                libc::munmap(again.cast(), 4096);
            }

            // Neither writes nor size changes reach the snapshot, through any descriptor.
            let file = File::from(fd);
            assert!(std::os::unix::fs::FileExt::write_at(&file, b"J", 0).is_err());
            assert!(file.set_len(1).is_err());
            assert!(file.set_len(8192).is_err());
            let mut bytes = [0; 8];
            let read = std::os::unix::fs::FileExt::read_at(&file, &mut bytes, 0).unwrap();
            assert_eq!(&bytes[..read], b"hello");
        }
    }
}
