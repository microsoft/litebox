// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-file-backed storage for the broker's in-memory files.
//!
//! Linux uses memfds and Windows uses temporary files. Both providers access contents through
//! positional I/O, including staged copies for buffers that cannot expose their bytes directly.
//! Requesting an object and delivering it to a runner are separate from creating its storage.

/// A file's contents in a host file, accessed with positional I/O.
#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
mod host_file {
    use std::fs::File;
    use std::io::{Error as IoError, ErrorKind};
    #[cfg(target_os = "linux")]
    use std::sync::OnceLock;
    use std::sync::{PoisonError, RwLock};

    use litebox_broker_core::fs::shared_memory::{
        HostHandle, SharedFileMemory, SharedFileMemoryError, SharedFileObject,
    };
    use litebox_broker_core::transfer::bounce_buffer;
    use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

    use crate::fs::{read_slice_at, write_slice_at};

    /// The most bytes staged at once for buffers that cannot expose their bytes directly.
    const STAGING_SIZE: usize = 64 * 1024;

    pub(super) struct HostFileMemory {
        file: File,
        /// Makes each of the broker's accesses atomic with respect to the others, as
        /// [`SharedFileMemory`] requires: reads share it, while writes and resizes take it alone.
        io: RwLock<()>,
        /// A read-only open of the file, made the first time a reader exports it.
        #[cfg(target_os = "linux")]
        read_only: OnceLock<File>,
    }

    /// Returns `offset` as a host file position, or `None` past `i64::MAX`, which hosts reject or,
    /// on Windows, treat as special values.
    fn position(offset: usize) -> Option<u64> {
        i64::try_from(offset).ok().map(i64::cast_unsigned)
    }

    /// Returns the most bytes the host lets the broker's files hold.
    ///
    /// On Linux, growing a file past `RLIMIT_FSIZE` would raise `SIGXFSZ`, which ends the broker
    /// by default, so the memory never tries to.
    fn size_limit() -> u64 {
        let limit = i64::MAX.cast_unsigned();
        #[cfg(target_os = "linux")]
        {
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
        }
        limit
    }

    impl HostFileMemory {
        fn new(file: File) -> Self {
            Self {
                file,
                io: RwLock::new(()),
                #[cfg(target_os = "linux")]
                read_only: OnceLock::new(),
            }
        }

        /// Opens the contents again with read and execute rights only.
        #[cfg(target_os = "linux")]
        fn open_read_only(&self) -> Result<File, SharedFileMemoryError> {
            use std::os::fd::AsRawFd as _;

            // Duplication preserves the access mode, so reopen for readers.
            File::open(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
                .map_err(|_| SharedFileMemoryError::Unsupported)
        }

        /// Returns the handle to export, writable only if `writable` is set.
        ///
        /// The host checks a descriptor's access mode when mapping it, so readers get a read-only
        /// open, made once and kept.
        #[cfg(target_os = "linux")]
        fn export(&self, writable: bool) -> Result<&File, SharedFileMemoryError> {
            if writable {
                return Ok(&self.file);
            }
            if let Some(file) = self.read_only.get() {
                return Ok(file);
            }
            let file = self.open_read_only()?;
            Ok(self.read_only.get_or_init(|| file))
        }
        fn len(&self) -> Result<u64, SharedFileMemoryError> {
            Ok(self
                .file
                .metadata()
                .map_err(|error| memory_error(&error))?
                .len())
        }

        fn read_once(&self, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
            loop {
                match read_slice_at(&self.file, buffer, offset) {
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

        /// Writes all of `data` at `offset`, adding the bytes written to `written` as it goes.
        fn write_all(
            &self,
            mut data: &[u8],
            mut offset: u64,
            written: &mut usize,
        ) -> std::io::Result<()> {
            while !data.is_empty() {
                match write_slice_at(&self.file, data, offset) {
                    Ok(0) => return Err(ErrorKind::WriteZero.into()),
                    Ok(count) => {
                        data = &data[count..];
                        offset += count as u64;
                        *written += count;
                    }
                    Err(error) if error.kind() == ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        }

        /// Writes like [`SharedFileMemory::write_at`], but grows the memory to at most `limit`
        /// bytes, writing only the bytes that fit before it, as Linux does at `RLIMIT_FSIZE`.
        fn write_limited(
            &self,
            offset: usize,
            data: &dyn WriteBuffer,
            limit: u64,
        ) -> Result<usize, SharedFileMemoryError> {
            if data.is_empty() {
                return Ok(0);
            }
            let position = position(offset)
                .filter(|position| *position < limit)
                .ok_or(SharedFileMemoryError::NoMemory)?;
            let length =
                usize::try_from(limit - position).map_or(data.len(), |room| room.min(data.len()));
            let _io = self.io.write().unwrap_or_else(PoisonError::into_inner);
            // Only a write that fits whole may transfer directly, since it cannot stop early.
            let direct = if length == data.len() {
                #[cfg(target_os = "linux")]
                let direct = crate::fs::linux::write_at(&self.file, data, position);
                #[cfg(windows)]
                let direct = crate::fs::windows::write_at(&self.file, data, position);
                direct
            } else {
                None
            };
            // A short or interrupted direct write continues through the staging buffer.
            let mut written = match direct {
                Some(Err(error)) if error.kind() == ErrorKind::Interrupted => 0,
                Some(written) => written.map_err(|error| memory_error(&error))?,
                None => 0,
            };
            if written == length {
                return Ok(written);
            }
            let mut staging = match bounce_buffer(STAGING_SIZE.min(length - written)) {
                Ok(staging) => staging,
                Err(_) if written > 0 => return Ok(written),
                Err(_) => return Err(SharedFileMemoryError::NoMemory),
            };
            while written < length {
                let chunk = &mut staging[..STAGING_SIZE.min(length - written)];
                let result = data
                    .copy_to_slice_at(written, chunk)
                    .map_err(SharedFileMemoryError::from)
                    .and_then(|()| {
                        self.write_all(chunk, position + written as u64, &mut written)
                            .map_err(|error| memory_error(&error))
                    });
                match result {
                    Ok(()) => {}
                    // Like `pwrite`, report the bytes already written rather than the error.
                    Err(_) if written > 0 => break,
                    Err(error) => return Err(error),
                }
            }
            Ok(written)
        }

        /// Resizes like [`SharedFileMemory::set_len`], but to at most `limit` bytes.
        fn set_len_limited(&self, length: usize, limit: u64) -> Result<(), SharedFileMemoryError> {
            let length = u64::try_from(length)
                .ok()
                .filter(|length| *length <= limit)
                .ok_or(SharedFileMemoryError::NoMemory)?;
            let _io = self.io.write().unwrap_or_else(PoisonError::into_inner);
            self.file
                .set_len(length)
                .map_err(|error| memory_error(&error))
        }
    }

    pub(super) fn memory_error(error: &IoError) -> SharedFileMemoryError {
        let code = error.raw_os_error();
        #[cfg(target_os = "linux")]
        {
            if matches!(
                code,
                Some(libc::ENOSPC | libc::ENOMEM | libc::EFBIG | libc::EMFILE | libc::ENFILE)
            ) {
                return SharedFileMemoryError::NoMemory;
            }
            if code == Some(libc::EFAULT) {
                return SharedFileMemoryError::Fault;
            }
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{
                ERROR_COMMITMENT_LIMIT, ERROR_DISK_FULL, ERROR_HANDLE_DISK_FULL, ERROR_NOACCESS,
                ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_ENOUGH_QUOTA, ERROR_OUTOFMEMORY,
                ERROR_USER_MAPPED_FILE,
            };
            let code = code.and_then(|code| u32::try_from(code).ok());
            if code == Some(ERROR_USER_MAPPED_FILE) {
                return SharedFileMemoryError::Busy;
            }
            if matches!(
                code,
                Some(
                    ERROR_DISK_FULL
                        | ERROR_HANDLE_DISK_FULL
                        | ERROR_NOT_ENOUGH_MEMORY
                        | ERROR_OUTOFMEMORY
                        | ERROR_COMMITMENT_LIMIT
                        | ERROR_NOT_ENOUGH_QUOTA
                )
            ) {
                return SharedFileMemoryError::NoMemory;
            }
            if code == Some(ERROR_NOACCESS) {
                return SharedFileMemoryError::Fault;
            }
        }
        SharedFileMemoryError::Io
    }

    impl SharedFileMemory for HostFileMemory {
        fn read_at(
            &self,
            offset: usize,
            buffer: &mut dyn ReadBuffer,
        ) -> Result<usize, SharedFileMemoryError> {
            // Nothing lies past the largest position the host accepts.
            let Some(position) = position(offset) else {
                return Ok(0);
            };
            let _io = self.io.read().unwrap_or_else(PoisonError::into_inner);
            #[cfg(target_os = "linux")]
            let direct = crate::fs::linux::read_at(&self.file, buffer, position);
            #[cfg(windows)]
            let direct = crate::fs::windows::read_at(&self.file, buffer, position);
            // A short or interrupted direct read continues through the staging buffer, so that
            // only the end of the memory stops a read short.
            let mut read = match direct {
                Some(Ok(0)) => return Ok(0),
                Some(Ok(read)) => read,
                Some(Err(error)) if error.kind() == ErrorKind::Interrupted => 0,
                Some(Err(error)) => return Err(memory_error(&error)),
                None => 0,
            };
            if read == buffer.len() {
                return Ok(read);
            }
            // A short direct read usually stopped at the end, which the size confirms without
            // staging anything.
            if read > 0 && position + read as u64 >= self.len()? {
                return Ok(read);
            }
            let mut staging = match bounce_buffer(STAGING_SIZE.min(buffer.len() - read)) {
                Ok(staging) => staging,
                Err(_) if read > 0 => return Ok(read),
                Err(_) => return Err(SharedFileMemoryError::NoMemory),
            };
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
        ) -> Result<usize, SharedFileMemoryError> {
            self.write_limited(offset, data, size_limit())
        }

        fn size(&self) -> Result<usize, SharedFileMemoryError> {
            let _io = self.io.read().unwrap_or_else(PoisonError::into_inner);
            usize::try_from(self.len()?).map_err(|_| SharedFileMemoryError::Io)
        }

        fn set_len(&self, length: usize) -> Result<(), SharedFileMemoryError> {
            self.set_len_limited(length, size_limit())
        }
    }

    impl SharedFileObject for HostFileMemory {
        fn host_handle(&self, writable: bool) -> Result<HostHandle<'_>, SharedFileMemoryError> {
            #[cfg(target_os = "linux")]
            let raw = u64::try_from(std::os::fd::AsRawFd::as_raw_fd(self.export(writable)?))
                .map_err(|_| SharedFileMemoryError::Io)?;
            // The handle never leaves the broker: the deployment derives a section from it, and
            // the section's protection and the rights of the section handle sent to a runner
            // enforce `writable`, so readers and writers share the storage's own handle.
            #[cfg(windows)]
            let raw = {
                let _ = writable;
                std::os::windows::io::AsRawHandle::as_raw_handle(&self.file) as usize as u64
            };
            // SAFETY: The handle belongs to `self`, which keeps it open while borrowed.
            Ok(unsafe { HostHandle::borrow_raw(raw) })
        }
    }

    pub(super) fn create(
        file: File,
        contents: &[u8],
    ) -> Result<std::sync::Arc<dyn SharedFileMemory>, SharedFileMemoryError> {
        if u64::try_from(contents.len()).map_or(true, |length| length > size_limit()) {
            return Err(SharedFileMemoryError::NoMemory);
        }
        let memory = HostFileMemory::new(file);
        // Nothing else can reach the memory yet, so the contents go straight to the file.
        memory
            .write_all(contents, 0, &mut 0)
            .map_err(|error| memory_error(&error))?;
        Ok(std::sync::Arc::new(memory))
    }

    #[cfg(test)]
    pub(super) mod tests {
        use super::*;
        use litebox_broker_core::fs::shared_memory::SharedFileMemoryProvider;
        use litebox_broker_core::test_support::FaultingBuffer;
        use litebox_platform::buffer::{Buffer, Fault};

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

        #[test]
        fn host_errors_map_to_memory_errors() {
            #[cfg(target_os = "linux")]
            let cases = [
                (libc::ENOSPC, SharedFileMemoryError::NoMemory),
                (libc::ENOMEM, SharedFileMemoryError::NoMemory),
                (libc::EFBIG, SharedFileMemoryError::NoMemory),
                (libc::EMFILE, SharedFileMemoryError::NoMemory),
                (libc::ENFILE, SharedFileMemoryError::NoMemory),
                (libc::EFAULT, SharedFileMemoryError::Fault),
                (libc::EIO, SharedFileMemoryError::Io),
            ];
            #[cfg(windows)]
            let cases = {
                use windows_sys::Win32::Foundation::{
                    ERROR_COMMITMENT_LIMIT, ERROR_DISK_FULL, ERROR_HANDLE_DISK_FULL,
                    ERROR_IO_DEVICE, ERROR_NOACCESS, ERROR_NOT_ENOUGH_MEMORY,
                    ERROR_NOT_ENOUGH_QUOTA, ERROR_OUTOFMEMORY, ERROR_USER_MAPPED_FILE,
                };
                [
                    (ERROR_USER_MAPPED_FILE, SharedFileMemoryError::Busy),
                    (ERROR_DISK_FULL, SharedFileMemoryError::NoMemory),
                    (ERROR_HANDLE_DISK_FULL, SharedFileMemoryError::NoMemory),
                    (ERROR_NOT_ENOUGH_MEMORY, SharedFileMemoryError::NoMemory),
                    (ERROR_OUTOFMEMORY, SharedFileMemoryError::NoMemory),
                    (ERROR_COMMITMENT_LIMIT, SharedFileMemoryError::NoMemory),
                    (ERROR_NOT_ENOUGH_QUOTA, SharedFileMemoryError::NoMemory),
                    (ERROR_NOACCESS, SharedFileMemoryError::Fault),
                    (ERROR_IO_DEVICE, SharedFileMemoryError::Io),
                ]
                .map(|(code, error)| (code.cast_signed(), error))
            };
            for (code, expected) in cases {
                assert_eq!(memory_error(&IoError::from_raw_os_error(code)), expected);
            }
        }

        /// Checks that memory in `file` never grows past the host's size limit, here a small
        /// one, nor to positions the host cannot address.
        pub(in crate::shared_objects) fn check_size_limit(file: File) {
            let memory = HostFileMemory::new(file);
            // A write crossing the limit writes only what fits, directly or staged, and one at
            // the limit fails without growing the memory.
            assert_eq!(memory.write_limited(0, &b"hello".as_slice(), 4), Ok(4));
            assert_eq!(
                memory.write_limited(2, &IndirectBuffer(b"abc".to_vec()), 4),
                Ok(2)
            );
            assert_eq!(
                memory.write_limited(4, &b"!".as_slice(), 4),
                Err(SharedFileMemoryError::NoMemory)
            );
            assert_eq!(
                memory.set_len_limited(5, 4),
                Err(SharedFileMemoryError::NoMemory)
            );
            assert_eq!(memory.size(), Ok(4));
            memory.set_len_limited(4, 4).unwrap();
            let mut bytes = [0; 4];
            assert_eq!(memory.read_at(0, &mut bytes.as_mut_slice()), Ok(4));
            assert_eq!(&bytes, b"heab");

            // Positions past `i64::MAX` hold nothing and cannot be written.
            assert_eq!(
                memory.write_at(usize::MAX - 1, &b"!".as_slice()),
                Err(SharedFileMemoryError::NoMemory)
            );
            assert_eq!(
                memory.set_len(usize::MAX),
                Err(SharedFileMemoryError::NoMemory)
            );
            assert_eq!(
                memory.read_at(usize::MAX - 1, &mut bytes.as_mut_slice()),
                Ok(0)
            );
            assert_eq!(memory.size(), Ok(4));
        }

        pub(in crate::shared_objects) fn check_reads_writes_and_resizes(
            provider: &dyn SharedFileMemoryProvider,
        ) {
            let memory = provider.create(b"hello").unwrap();
            assert_eq!(memory.size().unwrap(), 5);
            let mut bytes = [0; 8];
            assert_eq!(memory.read_at(0, &mut bytes.as_mut_slice()).unwrap(), 5);
            assert_eq!(&bytes[..5], b"hello");
            // Writes past the end grow the memory with zeros.
            assert_eq!(memory.write_at(6, &b"!!".as_slice()).unwrap(), 2);
            assert_eq!(memory.size().unwrap(), 8);
            assert_eq!(memory.read_at(0, &mut bytes.as_mut_slice()).unwrap(), 8);
            assert_eq!(&bytes, b"hello\0!!");

            // A fault before anything is written fails without growing the memory, and one
            // after the first staged chunk reports the bytes written before it.
            assert_eq!(
                memory.write_at(9, &FaultingBuffer::new(4, 0)),
                Err(SharedFileMemoryError::Fault)
            );
            assert_eq!(memory.size().unwrap(), 8);
            assert_eq!(
                memory
                    .write_at(8, &FaultingBuffer::new(2 * STAGING_SIZE, STAGING_SIZE + 1))
                    .unwrap(),
                STAGING_SIZE
            );
            assert_eq!(memory.size().unwrap(), 8 + STAGING_SIZE);

            let large: Vec<u8> = (0..3 * STAGING_SIZE + 5)
                .map(|i| u8::try_from(i % 251).unwrap())
                .collect();
            assert_eq!(
                memory.write_at(1, &IndirectBuffer(large.clone())).unwrap(),
                large.len()
            );
            assert_eq!(memory.size().unwrap(), large.len() + 1);
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
        fn create(
            &self,
            contents: &[u8],
        ) -> Result<Arc<dyn SharedFileMemory>, SharedFileMemoryError> {
            create(memfd()?, contents)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn memfd_memory_reads_writes_and_resizes() {
            super::super::host_file::tests::check_reads_writes_and_resizes(
                &MemfdFileMemoryProvider,
            );
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
        fn reader_handles_are_read_only_and_reused() {
            let memory = MemfdFileMemoryProvider.create(b"hello").unwrap();
            let reader = memory.host_handle(false).unwrap();
            assert_eq!(reader.raw(), memory.host_handle(false).unwrap().raw());
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
            let writer = memory.host_handle(true).unwrap();
            let raw = libc::c_int::try_from(writer.raw()).unwrap();
            // SAFETY: The handle lends a live descriptor.
            assert_eq!(
                unsafe { libc::fcntl(raw, libc::F_GETFL) } & libc::O_ACCMODE,
                libc::O_RDWR
            );
        }
    }
}

/// Temporary-file-backed shared file memory for Windows.
///
/// Pagefile-backed sections cannot grow, so file contents live in temporary files that are
/// deleted when their storage closes. A later deployment may derive sections from these files.
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows {
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
        fn create(
            &self,
            contents: &[u8],
        ) -> Result<Arc<dyn SharedFileMemory>, SharedFileMemoryError> {
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
        fn shrinking_mapped_memory_reports_busy() {
            use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
            use windows_sys::Win32::System::Memory::{
                CreateFileMappingW, FILE_MAP_READ, MapViewOfFile, PAGE_READONLY, UnmapViewOfFile,
            };

            let memory = TempFileMemoryProvider.create(b"hello").unwrap();
            let handle =
                usize::try_from(memory.host_handle(false).unwrap().raw()).unwrap() as HANDLE;
            // SAFETY: `handle` is a live file handle lent by `memory`, and the call creates a
            // new section handle.
            let section = unsafe {
                CreateFileMappingW(
                    handle,
                    std::ptr::null(),
                    PAGE_READONLY,
                    0,
                    0,
                    std::ptr::null(),
                )
            };
            assert!(!section.is_null());
            // SAFETY: `section` is a live section handle, and the call maps a new view of it.
            let view = unsafe { MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0) };
            assert!(!view.Value.is_null());

            assert_eq!(memory.set_len(1), Err(SharedFileMemoryError::Busy));
            assert_eq!(memory.size().unwrap(), 5);
            memory.set_len(8).unwrap();
            assert_eq!(memory.size().unwrap(), 8);

            // SAFETY: `view` and `section` were created above and are not used again.
            unsafe {
                assert_ne!(UnmapViewOfFile(view), 0);
                assert_ne!(CloseHandle(section), 0);
            }
            memory.set_len(1).unwrap();
            assert_eq!(memory.size().unwrap(), 1);
        }
    }
}
