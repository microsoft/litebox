// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::File;
use std::io::Error as IoError;
use std::os::fd::FromRawFd as _;

use litebox_broker_core::fs::errors::{MapSharedError, StorageError};
use litebox_broker_core::fs::shared_memory::{
    HostHandle, SharedFileMemory, SharedFileMemoryProvider,
};

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use super::host_file::{Exported, HostFile, create, host_len, memory_error};

/// A memfd, whose size is the file's size, so Linux keeps no state of its own.
#[derive(Default)]
pub(super) struct Memfd;

impl HostFile for Memfd {
    fn len(&self, file: &File) -> Result<u64, StorageError> {
        host_len::<Self>(file)
    }

    fn resize(&mut self, file: &File, length: u64) -> Result<(), StorageError> {
        file.set_len(length)
            .map_err(|error| memory_error::<Self>(&error))
    }

    fn export(memfd: &File, writable: bool) -> Result<Box<dyn HostHandle + '_>, MapSharedError> {
        use std::os::fd::{AsFd as _, AsRawFd as _};

        if writable {
            return Ok(Box::new(Exported(memfd.as_fd())));
        }
        // The host checks a descriptor's access mode when mapping it, so readers get a
        // read-only open, made for this export alone so that no extra descriptor stays open
        // between deliveries. Duplication preserves the access mode, so reopen.
        let reader = File::open(format!("/proc/self/fd/{}", memfd.as_raw_fd()))
            .map_err(|_| MapSharedError::Unsupported)?;
        Ok(Box::new(Exported(reader)))
    }

    /// Growing a file past `RLIMIT_FSIZE` would raise `SIGXFSZ`, which ends the broker by
    /// default, so the memory never tries to.
    fn size_limit() -> u64 {
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

    fn error_for(code: i32) -> Option<StorageError> {
        match code {
            libc::ENOSPC | libc::ENOMEM | libc::EFBIG | libc::EMFILE | libc::ENFILE => {
                Some(StorageError::NoSpace)
            }
            libc::EFAULT => Some(StorageError::Fault),
            _ => None,
        }
    }

    fn direct_read_at(
        file: &File,
        buffer: &mut dyn ReadBuffer,
        start: usize,
        offset: u64,
    ) -> Option<std::io::Result<usize>> {
        crate::fs::linux::read_at(file, buffer, start, offset)
    }

    fn direct_write_at(
        file: &File,
        data: &dyn WriteBuffer,
        start: usize,
        offset: u64,
    ) -> Option<std::io::Result<usize>> {
        crate::fs::linux::write_at(file, data, start, offset)
    }
}

impl<T: std::os::fd::AsFd + Send> HostHandle for Exported<T> {
    fn raw(&self) -> u64 {
        use std::os::fd::AsRawFd as _;

        // Open descriptors are never negative.
        u64::from(self.0.as_fd().as_raw_fd().cast_unsigned())
    }
}

/// Creates memory for files in memfds, accessed only through positional I/O by the broker.
pub struct MemfdFileMemoryProvider;

fn memfd() -> Result<File, StorageError> {
    // Ask for execution support where the host otherwise seals memfds against execution.
    // Older kernels and hosts that forbid it leave a plain memfd as the best available.
    let memfd = |flags| {
        // SAFETY: The name is a valid C string, and the call creates a new descriptor.
        unsafe { libc::memfd_create(c"litebox-shared-file".as_ptr(), flags) }
    };
    let mut fd = memfd(libc::MFD_CLOEXEC | libc::MFD_EXEC);
    if fd < 0 {
        fd = memfd(libc::MFD_CLOEXEC);
    }
    if fd < 0 {
        return Err(memory_error::<Memfd>(&IoError::last_os_error()));
    }
    // SAFETY: `memfd_create` returned a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

impl SharedFileMemoryProvider for MemfdFileMemoryProvider {
    fn create(&self) -> Result<SharedFileMemory, StorageError> {
        Ok(create::<Memfd>(memfd()?))
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
        super::super::host_file::tests::check_size_limit::<Memfd>(memfd().unwrap());
    }

    #[test]
    fn reader_handles_are_read_only_and_closed_after_export() {
        let open_descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let memory =
            super::super::host_file::tests::create_with(&MemfdFileMemoryProvider, b"hello").object;
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
}
