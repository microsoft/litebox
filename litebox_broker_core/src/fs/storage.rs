// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Byte storage backing the contents of regular files.
//!
//! A storage owns a file's bytes and length, and nothing else; how a backend exposes those bytes
//! elsewhere is up to the backend.

use alloc::borrow::Cow;
use core::any::Any;

use litebox_platform::buffer::{Buffer, ReadBuffer, WriteBuffer};

use super::errors::StorageError;

/// The read-only contents of a single regular file.
pub trait FileStorage: Any + Send + Sync {
    /// The current length of the contents, in bytes.
    fn len(&self) -> Result<usize, StorageError>;

    /// Returns `true` if the contents are empty.
    fn is_empty(&self) -> Result<bool, StorageError> {
        Ok(self.len()? == 0)
    }

    /// Reads into `buf` starting at `offset`, returning the number of bytes read (0 at or past
    /// the end).
    ///
    /// May read fewer bytes than `buf` holds even before the end (such as when copying into `buf`
    /// faults partway), in which case it returns the number of bytes actually read, all starting
    /// at `offset`. Returns an error only if no bytes could be read at all. Use
    /// [`Self::read_exact_at`] to fill `buf` as far as the contents allow.
    fn read_at(&self, offset: usize, buf: &mut dyn ReadBuffer) -> Result<usize, StorageError>;

    /// Reads into `buf` starting at `offset`, retrying short reads until `buf` is full or the end
    /// is reached, and returns the number of bytes read.
    ///
    /// Returns an error only if no bytes could be read at all; an error after some progress is
    /// reported as the short count read so far.
    fn read_exact_at(
        &self,
        offset: usize,
        buf: &mut dyn ReadBuffer,
    ) -> Result<usize, StorageError> {
        let mut done = 0;
        while done < buf.len() {
            let remaining = buf.len() - done;
            let mut rest = Buffer::sub_buffer(&mut *buf, done, remaining);
            match self.read_at(offset + done, &mut rest) {
                Ok(0) => break,
                Ok(read) => done += read,
                Err(_) if done > 0 => break,
                Err(error) => return Err(error),
            }
        }
        Ok(done)
    }

    /// Bytes that live for the program's lifetime, if the contents are backed by such bytes.
    fn static_bytes(&self) -> Option<&'static [u8]> {
        None
    }
}

/// The contents of a single regular file that can also be modified.
pub trait FileStorageMut: FileStorage {
    /// Writes `buf` starting at `offset`, zero-filling any gap past the current end.
    ///
    /// May write fewer bytes than `buf` holds (such as when running out of space partway), in
    /// which case it returns the number of bytes actually written, all starting at `offset`.
    /// Returns an error only if no bytes could be written at all.
    fn write_at(&mut self, offset: usize, buf: &dyn WriteBuffer) -> Result<usize, StorageError>;

    /// Truncates or zero-extends the contents to `len` bytes.
    fn set_len(&mut self, len: usize) -> Result<(), StorageError>;
}

/// Heap-backed storage that keeps borrowed static data borrowed until the first write.
pub struct MemoryStorage(Cow<'static, [u8]>);

impl MemoryStorage {
    /// Storage holding `data`.
    #[must_use]
    pub fn new(data: Cow<'static, [u8]>) -> Self {
        Self(data)
    }
}

impl FileStorage for MemoryStorage {
    fn len(&self) -> Result<usize, StorageError> {
        Ok(self.0.len())
    }

    fn read_at(&self, offset: usize, buf: &mut dyn ReadBuffer) -> Result<usize, StorageError> {
        let start = offset.min(self.0.len());
        let end = offset.saturating_add(buf.len()).min(self.0.len());
        // A fault may leave any of the bytes copied, so none can be reported as a short count.
        buf.copy_from_slice_at(0, &self.0[start..end])?;
        Ok(end - start)
    }

    fn static_bytes(&self) -> Option<&'static [u8]> {
        match self.0 {
            Cow::Borrowed(data) => Some(data),
            Cow::Owned(_) => None,
        }
    }
}

impl FileStorageMut for MemoryStorage {
    fn write_at(&mut self, offset: usize, buf: &dyn WriteBuffer) -> Result<usize, StorageError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let end = offset.checked_add(buf.len()).ok_or(StorageError::NoSpace)?;
        let data = self.0.to_mut();
        let previous_len = data.len();
        if end > previous_len {
            data.resize(end, 0);
        }
        // XXX(jayb): a fault partway through discards the whole write rather than reporting the
        // bytes copied so far as a short count, as `FileStorageMut::write_at` permits.
        if let Err(fault) = buf.copy_to_slice_at(0, &mut data[offset..end]) {
            data.truncate(previous_len);
            return Err(fault.into());
        }
        Ok(buf.len())
    }

    fn set_len(&mut self, len: usize) -> Result<(), StorageError> {
        match &mut self.0 {
            Cow::Borrowed(data) if len <= data.len() => *data = &data[..len],
            data => data.to_mut().resize(len, 0),
        }
        Ok(())
    }
}
