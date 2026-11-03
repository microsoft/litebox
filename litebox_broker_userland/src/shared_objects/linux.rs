// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::{File, Permissions};
use std::io::Error as IoError;
use std::os::fd::FromRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;

use litebox_broker_core::fs::shared_memory::{
    SharedFileMemory, SharedFileMemoryError, SharedFileMemoryProvider,
};

use super::host_file::{create, memory_error};

/// Creates memory for files in memfds, accessed only through positional I/O by the broker.
pub struct MemfdFileMemoryProvider;

fn memfd() -> Result<File, SharedFileMemoryError> {
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
        return Err(memory_error(&IoError::last_os_error()));
    }
    // SAFETY: `memfd_create` returned a new descriptor that nothing else owns.
    let file = unsafe { File::from_raw_fd(fd) };
    // A runner holding the writable descriptor must not seal the memfd against the broker's
    // writes. Memfds created without sealing are sealed against further seals already, but
    // hosts that seal memfds against execution allow more seals, so forbid them here.
    // SAFETY: `fd` is a live memfd that `file` owns.
    unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, libc::F_SEAL_SEAL) };
    // SAFETY: As above.
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0 || seals & libc::F_SEAL_SEAL == 0 {
        return Err(SharedFileMemoryError::Io);
    }
    // Reopening `/proc/<pid>/fd/<fd>` checks the inode's mode rather than the descriptor's
    // access mode, so drop write permission to stop read-only descriptors from being
    // reopened for writing. This holds only against openers that cannot bypass or change
    // the mode: a process with `CAP_DAC_OVERRIDE` ignores it, and the memfd's owner (the
    // broker's uid) or a process with `CAP_FOWNER` can restore it with `fchmod`. Runners
    // therefore rely on their seccomp filter, which allows neither `fchmod` nor `open`.
    // Execute bits stay, since hosts may seal them.
    let mode = file
        .metadata()
        .map_err(|error| memory_error(&error))?
        .permissions()
        .mode();
    file.set_permissions(Permissions::from_mode((mode & 0o111) | 0o400))
        .map_err(|error| memory_error(&error))?;
    Ok(file)
}

impl SharedFileMemoryProvider for MemfdFileMemoryProvider {
    fn create(&self, contents: &[u8]) -> Result<Arc<dyn SharedFileMemory>, SharedFileMemoryError> {
        create(memfd()?, contents)
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
        super::super::host_file::tests::check_size_limit(memfd().unwrap());
    }

    #[test]
    fn memfds_accept_no_seals() {
        let memory = MemfdFileMemoryProvider.create(b"hello").unwrap();
        let raw = libc::c_int::try_from(memory.host_handle(true).unwrap().raw()).unwrap();
        // SAFETY: The handle lends a live descriptor.
        let seals = unsafe { libc::fcntl(raw, libc::F_GET_SEALS) };
        assert!(seals >= 0);
        assert_ne!(seals & libc::F_SEAL_SEAL, 0);
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
        // Reopening the reader through procfs checks the inode's mode, which must grant no
        // write access, whatever capabilities the test runs with.
        let mode = std::fs::metadata(format!("/proc/self/fd/{raw}"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o222, 0);
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
