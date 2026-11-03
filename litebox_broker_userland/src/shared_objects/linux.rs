// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::{File, Permissions};
use std::io::Error as IoError;
use std::os::fd::FromRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;

use litebox_broker_core::fs::shared_memory::{
    HostHandle, SharedFileMemory, SharedFileMemoryError, SharedFileMemoryProvider,
};

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

    /// Prepares for a write at `position`. Callers hold `io` alone.
    #[expect(
        clippy::unnecessary_wraps,
        clippy::unused_self,
        reason = "Windows clears stale bytes before writes"
    )]
    pub(super) fn before_write(&self, _position: u64) -> Result<(), SharedFileMemoryError> {
        Ok(())
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
    fn host_errors_map_to_memory_errors() {
        for (code, expected) in [
            (libc::ENOSPC, SharedFileMemoryError::NoMemory),
            (libc::ENOMEM, SharedFileMemoryError::NoMemory),
            (libc::EFBIG, SharedFileMemoryError::NoMemory),
            (libc::EMFILE, SharedFileMemoryError::NoMemory),
            (libc::ENFILE, SharedFileMemoryError::NoMemory),
            (libc::EFAULT, SharedFileMemoryError::Fault),
            (libc::EIO, SharedFileMemoryError::Io),
        ] {
            assert_eq!(memory_error(&IoError::from_raw_os_error(code)), expected);
        }
    }
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
