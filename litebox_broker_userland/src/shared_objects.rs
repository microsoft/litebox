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

    use litebox_broker_core::fs::shared_memory::{
        HostHandle, SharedFileMemory, SharedFileMemoryError, SharedFileObject,
    };
    use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

    const STAGING_SIZE: usize = 4096;

    pub(super) struct HostFileMemory {
        file: File,
        #[cfg(target_os = "linux")]
        read_only: std::sync::OnceLock<File>,
    }

    impl HostFileMemory {
        fn new(file: File) -> Self {
            Self {
                file,
                #[cfg(target_os = "linux")]
                read_only: std::sync::OnceLock::new(),
            }
        }

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
            // A short direct write continues through the stack buffer.
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
    }

    impl SharedFileObject for HostFileMemory {
        #[cfg(target_os = "linux")]
        fn host_handle(&self, writable: bool) -> Result<HostHandle<'_>, SharedFileMemoryError> {
            use std::os::fd::AsRawFd as _;

            let file = if writable {
                &self.file
            } else if let Some(read_only) = self.read_only.get() {
                read_only
            } else {
                // Duplication preserves the access mode, so reopen for readers.
                let file = File::open(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
                    .map_err(|_| SharedFileMemoryError::Unsupported)?;
                self.read_only.get_or_init(|| file)
            };
            let raw = u64::try_from(file.as_raw_fd()).map_err(|_| SharedFileMemoryError::Io)?;
            // SAFETY: The descriptor belongs to `self`, which keeps it open while borrowed.
            Ok(unsafe { HostHandle::borrow_raw(raw) })
        }

        #[cfg(windows)]
        fn host_handle(&self, _writable: bool) -> Result<HostHandle<'_>, SharedFileMemoryError> {
            use std::os::windows::io::AsRawHandle as _;

            let raw = self.file.as_raw_handle() as usize as u64;
            // SAFETY: The handle belongs to `self`, which keeps it open while borrowed.
            Ok(unsafe { HostHandle::borrow_raw(raw) })
        }
    }

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
    use std::io::Error as IoError;
    use std::os::fd::FromRawFd as _;
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
        Ok(unsafe { File::from_raw_fd(fd) })
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
    }
}
