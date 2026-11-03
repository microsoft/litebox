// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::File;
use std::io::{Error as IoError, ErrorKind};
use std::sync::{PoisonError, RwLock};

use litebox_broker_core::fs::shared_memory::{
    HostHandle, SharedFileMemory, SharedFileMemoryError, SharedFileObject,
};
use litebox_broker_core::transfer::bounce_buffer;
use litebox_platform::buffer::{Buffer as _, ReadBuffer, WriteBuffer};

use super::platform::{self, State};
#[cfg(target_os = "linux")]
use crate::fs::linux as direct;
#[cfg(windows)]
use crate::fs::windows as direct;
use crate::fs::{read_slice_at, write_slice_at};

/// The most bytes staged at once for buffers that cannot expose their bytes directly.
pub(super) const STAGING_SIZE: usize = 64 * 1024;

/// A file's contents in a host file, accessed with positional I/O.
pub(super) struct HostFileMemory {
    pub(super) file: File,
    /// Makes each of the broker's accesses atomic with respect to the others.
    io: RwLock<()>,
    /// Host-specific state, changed only while holding `io` alone.
    #[cfg_attr(
        target_os = "linux",
        expect(dead_code, reason = "Linux keeps no state of its own")
    )]
    pub(super) state: State,
}

/// Returns `offset` as a host file position, or `None` past `i64::MAX`, which hosts reject or,
/// on Windows, treat as special values.
fn position(offset: usize) -> Option<u64> {
    i64::try_from(offset).ok().map(i64::cast_unsigned)
}

impl HostFileMemory {
    fn new(file: File) -> Self {
        Self {
            file,
            io: RwLock::new(()),
            state: State::default(),
        }
    }

    /// Reads at `position` into `buffer`, as [`SharedFileMemory::read_at`] does. Callers hold
    /// `io`.
    fn read_locked(
        &self,
        position: u64,
        buffer: &mut dyn ReadBuffer,
    ) -> Result<usize, SharedFileMemoryError> {
        // Short and interrupted reads continue, so that only the end of the memory stops a
        // read short.
        let mut read = 0;
        let mut staging = None;
        while read < buffer.len() {
            let offset = position + read as u64;
            let count = match direct::read_at(&self.file, buffer, read, offset) {
                Some(Err(error)) if error.kind() == ErrorKind::Interrupted => continue,
                Some(result) => result.map_err(|error| memory_error(&error))?,
                // The rest of the buffer cannot take a direct read, so stage a chunk of it.
                None => {
                    let chunk = staging_chunk(&mut staging, buffer.len() - read)?;
                    let count = self
                        .read_once(chunk, offset)
                        .map_err(|error| memory_error(&error))?;
                    buffer.copy_from_slice_at(read, &chunk[..count])?;
                    count
                }
            };
            if count == 0 {
                break;
            }
            read += count;
        }
        Ok(read)
    }

    /// Returns the host file's size.
    pub(super) fn host_len(&self) -> Result<u64, SharedFileMemoryError> {
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
                Err(error) if platform::read_reached_end(&error) => return Ok(0),
                read => return read,
            }
        }
    }

    /// Writes all of `data` at `offset`, adding the bytes written to `written` as it goes.
    pub(super) fn write_all(
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
        let written = self.write_locked(position, &data.sub_buffer(0, length))?;
        if written > 0 {
            self.after_write(position + written as u64);
        }
        Ok(written)
    }

    /// Writes `data` at `position`, as [`SharedFileMemory::write_at`] does. Callers hold `io`
    /// alone.
    fn write_locked(
        &self,
        position: u64,
        data: &dyn WriteBuffer,
    ) -> Result<usize, SharedFileMemoryError> {
        // Short and interrupted writes continue, so that only an error stops a write short.
        let mut written = 0;
        let mut staging = None;
        while written < data.len() {
            match self.write_once(data, written, position + written as u64, &mut staging) {
                Ok(count) => written += count,
                // Like `pwrite`, report the bytes already written rather than the error.
                Err(_) if written > 0 => break,
                Err(error) => return Err(error),
            }
        }
        Ok(written)
    }

    /// Writes some of `data` from `start` on at `offset`, directly if those bytes allow it and
    /// otherwise through `staging`, and returns how many it wrote. Callers hold `io` alone.
    fn write_once(
        &self,
        data: &dyn WriteBuffer,
        start: usize,
        offset: u64,
        staging: &mut Option<Vec<u8>>,
    ) -> Result<usize, SharedFileMemoryError> {
        loop {
            let result = if let Some(result) = direct::write_at(&self.file, data, start, offset) {
                result
            } else {
                // The rest of `data` cannot take a direct write, so stage a chunk of it.
                let chunk = staging_chunk(staging, data.len() - start)?;
                data.copy_to_slice_at(start, chunk)?;
                write_slice_at(&self.file, chunk, offset)
            };
            match result {
                Ok(0) => return Err(SharedFileMemoryError::Io),
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(memory_error(&error)),
            }
        }
    }

    /// Resizes like [`SharedFileMemory::set_len`], but to at most `limit` bytes.
    fn set_len_limited(&self, length: usize, limit: u64) -> Result<(), SharedFileMemoryError> {
        let length = u64::try_from(length)
            .ok()
            .filter(|length| *length <= limit)
            .ok_or(SharedFileMemoryError::NoMemory)?;
        let _io = self.io.write().unwrap_or_else(PoisonError::into_inner);
        self.resize(length)
    }
}

/// Converts a host error into the error it means for shared file memory.
pub(super) fn memory_error(error: &IoError) -> SharedFileMemoryError {
    error
        .raw_os_error()
        .and_then(platform::memory_error_for)
        .unwrap_or(SharedFileMemoryError::Io)
}

/// Returns the part of the staging buffer that stages the next of `remaining` bytes, allocating
/// the buffer on first use.
fn staging_chunk(
    staging: &mut Option<Vec<u8>>,
    remaining: usize,
) -> Result<&mut [u8], SharedFileMemoryError> {
    let length = STAGING_SIZE.min(remaining);
    let staging = match staging {
        Some(staging) => staging,
        // Later chunks are no longer than the first, since `remaining` only shrinks.
        None => staging.insert(bounce_buffer(length).map_err(|_| SharedFileMemoryError::NoMemory)?),
    };
    Ok(&mut staging[..length])
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
        // The host file may hold bytes past the end of the file.
        if let Some(len) = self.read_limit() {
            let available = len.saturating_sub(position);
            if available < buffer.len() as u64 {
                // `available` is less than the buffer's length, so it fits.
                let length = usize::try_from(available).unwrap_or(0);
                if length == 0 {
                    return Ok(0);
                }
                return self.read_locked(position, &mut (&mut *buffer).sub_buffer(0, length));
            }
        }
        self.read_locked(position, buffer)
    }

    fn write_at(
        &self,
        offset: usize,
        data: &dyn WriteBuffer,
    ) -> Result<usize, SharedFileMemoryError> {
        self.write_limited(offset, data, platform::size_limit())
    }

    fn size(&self) -> Result<usize, SharedFileMemoryError> {
        let _io = self.io.read().unwrap_or_else(PoisonError::into_inner);
        usize::try_from(self.len()?).map_err(|_| SharedFileMemoryError::Io)
    }

    fn set_len(&self, length: usize) -> Result<(), SharedFileMemoryError> {
        self.set_len_limited(length, platform::size_limit())
    }
}

/// A host handle exported from shared file memory, either lent by the memory, as a
/// borrowed handle, or made for the export, as an owned one that closes when dropped.
pub(super) struct Exported<H>(pub(super) H);

impl SharedFileObject for HostFileMemory {
    fn host_handle(
        &self,
        writable: bool,
    ) -> Result<Box<dyn HostHandle + '_>, SharedFileMemoryError> {
        self.export(writable)
    }
}

pub(super) fn create(
    file: File,
    contents: &[u8],
) -> Result<std::sync::Arc<dyn SharedFileMemory>, SharedFileMemoryError> {
    if u64::try_from(contents.len()).map_or(true, |length| length > platform::size_limit()) {
        return Err(SharedFileMemoryError::NoMemory);
    }
    let memory = HostFileMemory::new(file);
    // Nothing else can reach the memory yet, so the contents go straight to the file.
    memory
        .write_all(contents, 0, &mut 0)
        .map_err(|error| memory_error(&error))?;
    memory.after_write(contents.len() as u64);
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
