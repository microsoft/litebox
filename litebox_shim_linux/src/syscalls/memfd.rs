// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Memory file for anonymous in-memory storage.
//!
//! `memfd_create()` creates an anonymous file and returns a file descriptor
//! referring to it. The file behaves like a regular file and can be modified,
//! truncated, and memory-mapped. However, unlike a regular file, it lives in
//! RAM and has volatile backing storage.

use core::sync::atomic::AtomicU32;

use alloc::string::String;
use alloc::vec::Vec;
use litebox::{
    event::{Events, IOPollable, observer::Observer, polling::Pollee},
    fs::OFlags,
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{MfdFlags, errno::Errno};

/// Maximum size limit for memfd files (1 GiB) to prevent DoS via unbounded memory allocation.
pub const MAX_MEMFD_SIZE: usize = 1 << 30;

/// An anonymous memory-backed file.
pub(crate) struct MemfdFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// The name for debugging (shown in /proc/self/fd/).
    /// TODO: Use this for /proc/self/fd/ symlink implementation.
    #[allow(dead_code)]
    name: String,
    /// File contents stored in memory.
    data: litebox::sync::Mutex<Platform, Vec<u8>>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`]).
    status: AtomicU32,
    /// Whether sealing operations are allowed.
    allow_sealing: bool,
    /// Pollee for event notification.
    pollee: Pollee<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> MemfdFile<Platform> {
    /// Create a new memory file with the given name and flags.
    pub(crate) fn new(name: String, flags: MfdFlags) -> Self {
        let status = OFlags::RDWR;

        Self {
            name,
            data: litebox::sync::Mutex::new(Vec::new()),
            status: AtomicU32::new(status.bits()),
            allow_sealing: flags.contains(MfdFlags::ALLOW_SEALING),
            pollee: Pollee::new(),
        }
    }

    /// Get the file name (for debugging purposes).
    /// TODO: Use for /proc/self/fd/ symlink implementation.
    #[allow(dead_code)]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether sealing is allowed on this file.
    #[allow(dead_code)]
    pub(crate) fn allow_sealing(&self) -> bool {
        self.allow_sealing
    }

    /// Read data from the file at the specified offset.
    #[expect(clippy::unnecessary_wraps)]
    pub(crate) fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, Errno> {
        let data = self.data.lock();
        if offset >= data.len() {
            return Ok(0);
        }

        let available = data.len() - offset;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&data[offset..offset + to_read]);
        Ok(to_read)
    }

    /// Write data to the file at the specified offset.
    pub(crate) fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize, Errno> {
        // Check for overflow and enforce size limit
        let required_len = offset.checked_add(buf.len()).ok_or(Errno::EFBIG)?;
        if required_len > MAX_MEMFD_SIZE {
            return Err(Errno::EFBIG);
        }

        let mut data = self.data.lock();
        // Extend the file if necessary
        if required_len > data.len() {
            data.resize(required_len, 0);
        }

        data[offset..offset + buf.len()].copy_from_slice(buf);

        drop(data);
        self.pollee.notify_observers(Events::IN | Events::OUT);
        Ok(buf.len())
    }

    /// Get the current size of the file.
    pub(crate) fn size(&self) -> usize {
        self.data.lock().len()
    }

    /// Truncate or extend the file to the specified length.
    pub(crate) fn truncate(&self, length: usize) -> Result<(), Errno> {
        if length > MAX_MEMFD_SIZE {
            return Err(Errno::EFBIG);
        }
        let mut data = self.data.lock();
        data.resize(length, 0);
        drop(data);
        self.pollee.notify_observers(Events::IN | Events::OUT);
        Ok(())
    }

    super::common_functions_for_file_status!();
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for MemfdFile<Platform> {
    fn check_io_events(&self) -> Events {
        // memfd is always readable and writable
        Events::IN | Events::OUT
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use litebox_common_linux::MfdFlags;
    use litebox_platform_multiplex::Platform;

    #[test]
    fn test_memfd_basic_write_read() {
        let _task = crate::syscalls::tests::init_platform(None);

        let memfd = alloc::sync::Arc::new(super::MemfdFile::<Platform>::new(
            "test".into(),
            MfdFlags::empty(),
        ));

        // Write some data
        let write_buf = b"Hello, memfd!";
        let written = memfd.write_at(0, write_buf).unwrap();
        assert_eq!(written, write_buf.len());

        // Read it back
        let mut read_buf = [0u8; 32];
        let read = memfd.read_at(0, &mut read_buf).unwrap();
        assert_eq!(read, write_buf.len());
        assert_eq!(&read_buf[..read], write_buf);
    }

    #[test]
    fn test_memfd_sparse_write() {
        let _task = crate::syscalls::tests::init_platform(None);

        let memfd = alloc::sync::Arc::new(super::MemfdFile::<Platform>::new(
            "sparse".into(),
            MfdFlags::empty(),
        ));

        // Write at offset 100
        let write_buf = b"sparse";
        let written = memfd.write_at(100, write_buf).unwrap();
        assert_eq!(written, write_buf.len());
        assert_eq!(memfd.size(), 106);

        // Read from beginning should give zeros
        let mut read_buf = [0xFFu8; 10];
        let read = memfd.read_at(0, &mut read_buf).unwrap();
        assert_eq!(read, 10);
        assert_eq!(read_buf, [0u8; 10]);

        // Read from offset 100
        let mut read_buf = [0u8; 10];
        let read = memfd.read_at(100, &mut read_buf).unwrap();
        assert_eq!(read, 6);
        assert_eq!(&read_buf[..6], write_buf);
    }

    #[test]
    fn test_memfd_truncate() {
        let _task = crate::syscalls::tests::init_platform(None);

        let memfd = alloc::sync::Arc::new(super::MemfdFile::<Platform>::new(
            "truncate".into(),
            MfdFlags::empty(),
        ));

        // Write some data
        let write_buf = b"Hello, world!";
        memfd.write_at(0, write_buf).unwrap();
        assert_eq!(memfd.size(), 13);

        // Truncate to smaller size
        memfd.truncate(5).unwrap();
        assert_eq!(memfd.size(), 5);

        // Read back
        let mut read_buf = [0u8; 10];
        let read = memfd.read_at(0, &mut read_buf).unwrap();
        assert_eq!(read, 5);
        assert_eq!(&read_buf[..5], b"Hello");

        // Extend
        memfd.truncate(10).unwrap();
        assert_eq!(memfd.size(), 10);

        // Read extended part should be zeros
        let mut read_buf = [0xFFu8; 10];
        let read = memfd.read_at(0, &mut read_buf).unwrap();
        assert_eq!(read, 10);
        assert_eq!(&read_buf[..5], b"Hello");
        assert_eq!(&read_buf[5..], &[0u8; 5]);
    }

    #[test]
    fn test_memfd_read_past_end() {
        let _task = crate::syscalls::tests::init_platform(None);

        let memfd = alloc::sync::Arc::new(super::MemfdFile::<Platform>::new(
            "read_past".into(),
            MfdFlags::empty(),
        ));

        // Write some data
        memfd.write_at(0, b"short").unwrap();

        // Read starting past the end
        let mut read_buf = [0xFFu8; 10];
        let read = memfd.read_at(100, &mut read_buf).unwrap();
        assert_eq!(read, 0);
    }

    #[test]
    fn test_memfd_allow_sealing_flag() {
        let _task = crate::syscalls::tests::init_platform(None);

        let memfd_no_seal: super::MemfdFile<Platform> =
            super::MemfdFile::new("no_seal".into(), MfdFlags::empty());
        assert!(!memfd_no_seal.allow_sealing());

        let memfd_seal: super::MemfdFile<Platform> =
            super::MemfdFile::new("seal".into(), MfdFlags::ALLOW_SEALING);
        assert!(memfd_seal.allow_sealing());
    }

    #[test]
    fn test_memfd_size_limit() {
        let _task = crate::syscalls::tests::init_platform(None);

        let memfd = alloc::sync::Arc::new(super::MemfdFile::<Platform>::new(
            "limit".into(),
            MfdFlags::empty(),
        ));

        // Write at an offset that would exceed MAX_MEMFD_SIZE should fail
        let result = memfd.write_at(super::MAX_MEMFD_SIZE, b"overflow");
        assert_eq!(result, Err(litebox_common_linux::errno::Errno::EFBIG));

        // Truncate beyond MAX_MEMFD_SIZE should fail
        let result = memfd.truncate(super::MAX_MEMFD_SIZE + 1);
        assert_eq!(result, Err(litebox_common_linux::errno::Errno::EFBIG));

        // Write at exactly MAX_MEMFD_SIZE - 1 with 1 byte should succeed
        // (boundary test: offset 1073741823 + 1 byte = exactly 1 GiB)
        // Skip this test as it would allocate 1 GiB of memory
    }
}
