// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A file's contents in a host file, accessed with positional I/O.
//!
//! Each host provides a [`HostFile`]. [`create`] wraps a host file in a [`HostFileStorage`],
//! which the file system reads and writes, and a [`HostFileObject`], which is shared with
//! callers that map the file. The positional I/O they share is at the end of this module.

use std::fs::File;
use std::io::Error as IoError;
use std::marker::PhantomData;
use std::sync::Arc;

use litebox_broker_core::fs::errors::{MapSharedError, StorageError};
use litebox_broker_core::fs::shared_storage::{HostHandle, SharedFileMemory, SharedFileObject};
use litebox_broker_core::fs::storage::{FileStorage, FileStorageMut};
use litebox_broker_core::transfer::bounce_buffer;
use litebox_platform::buffer::{Buffer as _, ReadBuffer, WriteBuffer};

use crate::fs::{read_slice_at, write_slice_at};

/// A kind of host file that holds a file's contents, with any state the host keeps for it.
pub(super) trait HostFile: Default + Send + Sync + 'static {
    /// Returns the file's size.
    fn len(&self, file: &File) -> Result<u64, StorageError>;

    /// Reads at `offset` into `buffer`, as [`FileStorage::read_at`] does.
    fn read_at(
        &self,
        file: &File,
        offset: usize,
        buffer: &mut dyn ReadBuffer,
    ) -> Result<usize, StorageError> {
        read_to_host_end::<Self>(file, offset, buffer)
    }

    /// Resizes the file to `length` bytes.
    fn resize(&mut self, file: &File, length: u64) -> Result<(), StorageError>;

    /// Records a write that ended at `end`.
    fn after_write(&mut self, _end: u64) {}

    /// Returns a handle for exporting `file`, writable only if `writable` is set.
    fn export(file: &File, writable: bool) -> Result<Box<dyn HostHandle + '_>, MapSharedError>;

    /// Returns the most bytes the host lets the broker's files hold.
    fn size_limit() -> u64;

    /// Returns what the host error `code` means for the storage, if more than an I/O error.
    fn error_for(code: i32) -> Option<StorageError>;

    /// Reads `file` at `offset` directly into `buffer` from `start` on, or returns `None`
    /// without reading unless those bytes of `buffer` allow it.
    fn direct_read_at(
        file: &File,
        buffer: &mut dyn ReadBuffer,
        start: usize,
        offset: u64,
    ) -> Option<std::io::Result<usize>>;

    /// Writes `data` from `start` on directly to `file` at `offset`, or returns `None` without
    /// writing unless those bytes of `data` allow it.
    fn direct_write_at(
        file: &File,
        data: &dyn WriteBuffer,
        start: usize,
        offset: u64,
    ) -> Option<std::io::Result<usize>>;
}

/// Creates empty memory in `file`, a host file of kind `H`.
pub(super) fn create<H: HostFile>(file: File) -> SharedFileMemory {
    let file = Arc::new(file);
    SharedFileMemory {
        storage: Box::new(HostFileStorage::<H>::new(Arc::clone(&file))),
        object: Arc::new(HostFileObject::<H>(file, PhantomData)),
    }
}

/// A file's contents in a host file of kind `H`, as the file system reads and writes them.
///
/// The file owns its storage, so each change has the storage to itself.
struct HostFileStorage<H> {
    file: Arc<File>,
    host: H,
}

impl<H: HostFile> HostFileStorage<H> {
    fn new(file: Arc<File>) -> Self {
        Self {
            file,
            host: H::default(),
        }
    }

    /// Writes like [`FileStorageMut::write_at`], but grows the file to at most `limit` bytes,
    /// writing only the bytes that fit before it, as Linux does at `RLIMIT_FSIZE`.
    fn write_limited(
        &mut self,
        offset: usize,
        data: &dyn WriteBuffer,
        limit: u64,
    ) -> Result<usize, StorageError> {
        if data.is_empty() {
            return Ok(0);
        }
        let position = position(offset)
            .filter(|position| *position < limit)
            .ok_or(StorageError::NoSpace)?;
        let length =
            usize::try_from(limit - position).map_or(data.len(), |room| room.min(data.len()));
        let written = write_from::<H>(&self.file, position, &data.sub_buffer(0, length))?;
        if written > 0 {
            self.host.after_write(position + written as u64);
        }
        Ok(written)
    }

    /// Resizes like [`FileStorageMut::set_len`], but to at most `limit` bytes.
    fn set_len_limited(&mut self, length: usize, limit: u64) -> Result<(), StorageError> {
        let length = u64::try_from(length)
            .ok()
            .filter(|length| *length <= limit)
            .ok_or(StorageError::NoSpace)?;
        self.host.resize(&self.file, length)
    }
}

impl<H: HostFile> FileStorage for HostFileStorage<H> {
    fn len(&self) -> Result<usize, StorageError> {
        usize::try_from(self.host.len(&self.file)?).map_err(|_| StorageError::Io)
    }

    fn read_at(&self, offset: usize, buffer: &mut dyn ReadBuffer) -> Result<usize, StorageError> {
        self.host.read_at(&self.file, offset, buffer)
    }
}

impl<H: HostFile> FileStorageMut for HostFileStorage<H> {
    fn write_at(&mut self, offset: usize, data: &dyn WriteBuffer) -> Result<usize, StorageError> {
        self.write_limited(offset, data, H::size_limit())
    }

    fn set_len(&mut self, length: usize) -> Result<(), StorageError> {
        self.set_len_limited(length, H::size_limit())
    }
}

/// A host file of kind `H` holding a file's contents, as shared with callers that map it.
struct HostFileObject<H>(Arc<File>, PhantomData<fn() -> H>);

impl<H: HostFile> SharedFileObject for HostFileObject<H> {
    fn host_handle(&self, writable: bool) -> Result<Box<dyn HostHandle + '_>, MapSharedError> {
        H::export(&self.0, writable)
    }
}

/// A host handle exported from a host file, either lent by it, as a borrowed handle, or made
/// for the export, as an owned one that closes when dropped.
pub(super) struct Exported<T>(pub(super) T);

/// The most bytes staged at once for buffers that cannot expose their bytes directly.
pub(super) const STAGING_SIZE: usize = 64 * 1024;

/// Returns `offset` as a host file position, or `None` past `i64::MAX`, which hosts reject or,
/// on Windows, treat as special values.
fn position(offset: usize) -> Option<u64> {
    i64::try_from(offset).ok().map(i64::cast_unsigned)
}

/// Converts a host error into the error it means for the storage.
pub(super) fn storage_error<H: HostFile>(error: &IoError) -> StorageError {
    error
        .raw_os_error()
        .and_then(H::error_for)
        .unwrap_or(StorageError::Io)
}

/// Returns the size of `file` on the host.
pub(super) fn host_len<H: HostFile>(file: &File) -> Result<u64, StorageError> {
    Ok(file
        .metadata()
        .map_err(|error| storage_error::<H>(&error))?
        .len())
}

/// Reads `file` at `offset` into `buffer`, as [`FileStorage::read_at`] does, up to the host
/// file's end.
pub(super) fn read_to_host_end<H: HostFile>(
    file: &File,
    offset: usize,
    buffer: &mut dyn ReadBuffer,
) -> Result<usize, StorageError> {
    // Nothing lies past the largest position the host accepts.
    let Some(position) = position(offset) else {
        return Ok(0);
    };
    let length = buffer.len();
    let mut staging = None;
    transfer_all(length, |done| {
        let offset = position + done as u64;
        if let Some(result) = H::direct_read_at(file, buffer, done, offset) {
            return result.map_err(|error| storage_error::<H>(&error));
        }
        // The rest of the buffer cannot take a direct read, so stage a chunk of it.
        let chunk = staging_chunk(&mut staging, length - done)?;
        let count =
            read_slice_at(file, chunk, offset).map_err(|error| storage_error::<H>(&error))?;
        buffer.copy_from_slice_at(done, &chunk[..count])?;
        Ok(count)
    })
}

/// Writes `data` to `file` at `position`, as [`FileStorageMut::write_at`] does.
pub(super) fn write_from<H: HostFile>(
    file: &File,
    position: u64,
    data: &dyn WriteBuffer,
) -> Result<usize, StorageError> {
    let mut staging = None;
    transfer_all(data.len(), |done| {
        let offset = position + done as u64;
        let result = if let Some(result) = H::direct_write_at(file, data, done, offset) {
            result
        } else {
            // The rest of `data` cannot take a direct write, so stage a chunk of it.
            let chunk = staging_chunk(&mut staging, data.len() - done)?;
            data.copy_to_slice_at(done, chunk)?;
            write_slice_at(file, chunk, offset)
        };
        match result.map_err(|error| storage_error::<H>(&error))? {
            0 => Err(StorageError::Io),
            count => Ok(count),
        }
    })
}

/// Transfers `length` bytes by calling `transfer` with how many are done so far until it has
/// done them all or transfers nothing, and returns how many it did.
///
/// As `pread` and `pwrite` do, an error after some progress is reported as the short count.
/// Positional I/O on host files fails with `Interrupted` only for signals that end the broker,
/// so nothing retries it.
fn transfer_all(
    length: usize,
    mut transfer: impl FnMut(usize) -> Result<usize, StorageError>,
) -> Result<usize, StorageError> {
    let mut done = 0;
    while done < length {
        match transfer(done) {
            Ok(0) => break,
            Ok(count) => done += count,
            Err(_) if done > 0 => break,
            Err(error) => return Err(error),
        }
    }
    Ok(done)
}

/// Returns the part of the staging buffer that stages the next of `remaining` bytes, allocating
/// the buffer on first use.
fn staging_chunk(
    staging: &mut Option<Vec<u8>>,
    remaining: usize,
) -> Result<&mut [u8], StorageError> {
    let length = STAGING_SIZE.min(remaining);
    let staging = match staging {
        Some(staging) => staging,
        // Later chunks are no longer than the first, since `remaining` only shrinks.
        None => staging.insert(bounce_buffer(length).map_err(|_| StorageError::NoSpace)?),
    };
    Ok(&mut staging[..length])
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use litebox_broker_core::fs::shared_storage::SharedFileMemoryProvider;
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

    /// Creates memory from `provider` that holds `contents`.
    pub(in crate::shared_objects) fn create_with(
        provider: &dyn SharedFileMemoryProvider,
        contents: &[u8],
    ) -> SharedFileMemory {
        let mut memory = provider.create().unwrap();
        assert_eq!(
            memory.storage.write_at(0, &contents).unwrap(),
            contents.len()
        );
        memory
    }

    /// Checks that memory in `file` never grows past the host's size limit, here a small
    /// one, nor to positions the host cannot address.
    pub(in crate::shared_objects) fn check_size_limit<H: HostFile>(file: File) {
        let mut memory = HostFileStorage::<H>::new(Arc::new(file));
        // A write crossing the limit writes only what fits, directly or staged, and one at
        // the limit fails without growing the memory.
        assert_eq!(memory.write_limited(0, &b"hello".as_slice(), 4), Ok(4));
        assert_eq!(
            memory.write_limited(2, &IndirectBuffer(b"abc".to_vec()), 4),
            Ok(2)
        );
        assert_eq!(
            memory.write_limited(4, &b"!".as_slice(), 4),
            Err(StorageError::NoSpace)
        );
        assert_eq!(memory.set_len_limited(5, 4), Err(StorageError::NoSpace));
        assert_eq!(memory.len(), Ok(4));
        memory.set_len_limited(4, 4).unwrap();
        let mut bytes = [0; 4];
        assert_eq!(memory.read_at(0, &mut bytes.as_mut_slice()), Ok(4));
        assert_eq!(&bytes, b"heab");

        // Positions past `i64::MAX` hold nothing and cannot be written.
        assert_eq!(
            memory.write_at(usize::MAX - 1, &b"!".as_slice()),
            Err(StorageError::NoSpace)
        );
        assert_eq!(memory.set_len(usize::MAX), Err(StorageError::NoSpace));
        assert_eq!(
            memory.read_at(usize::MAX - 1, &mut bytes.as_mut_slice()),
            Ok(0)
        );
        assert_eq!(memory.len(), Ok(4));
    }

    pub(in crate::shared_objects) fn check_reads_writes_and_resizes(
        provider: &dyn SharedFileMemoryProvider,
    ) {
        let mut memory = create_with(provider, b"hello").storage;
        assert_eq!(memory.len().unwrap(), 5);
        let mut bytes = [0; 8];
        assert_eq!(memory.read_at(0, &mut bytes.as_mut_slice()).unwrap(), 5);
        assert_eq!(&bytes[..5], b"hello");
        // Writes past the end grow the memory with zeros, unless they write nothing.
        assert_eq!(memory.write_at(9, &b"".as_slice()).unwrap(), 0);
        assert_eq!(memory.len().unwrap(), 5);
        assert_eq!(memory.write_at(6, &b"!!".as_slice()).unwrap(), 2);
        assert_eq!(memory.len().unwrap(), 8);
        assert_eq!(memory.read_at(0, &mut bytes.as_mut_slice()).unwrap(), 8);
        assert_eq!(&bytes, b"hello\0!!");

        // A fault before anything is written fails without growing the memory, and one
        // after the first staged chunk reports the bytes written before it.
        assert_eq!(
            memory.write_at(9, &FaultingBuffer::new(4, 0)),
            Err(StorageError::Fault)
        );
        assert_eq!(memory.len().unwrap(), 8);
        assert_eq!(
            memory
                .write_at(8, &FaultingBuffer::new(2 * STAGING_SIZE, STAGING_SIZE + 1))
                .unwrap(),
            STAGING_SIZE
        );
        assert_eq!(memory.len().unwrap(), 8 + STAGING_SIZE);

        let large: Vec<u8> = (0..3 * STAGING_SIZE + 5)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        assert_eq!(
            memory.write_at(1, &IndirectBuffer(large.clone())).unwrap(),
            large.len()
        );
        assert_eq!(memory.len().unwrap(), large.len() + 1);
        let mut read = IndirectBuffer(vec![0; large.len() + 7]);
        assert_eq!(memory.read_at(1, &mut read).unwrap(), large.len());
        assert_eq!(&read.0[..large.len()], large.as_slice());

        memory.set_len(2).unwrap();
        assert_eq!(memory.len().unwrap(), 2);
        assert_eq!(memory.read_at(1, &mut bytes.as_mut_slice()).unwrap(), 1);
        assert_eq!(memory.read_at(4, &mut bytes.as_mut_slice()).unwrap(), 0);
    }
}
