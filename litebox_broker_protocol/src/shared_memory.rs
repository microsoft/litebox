// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Transport-neutral shared-memory resources.

use alloc::{boxed::Box, sync::Arc};
use core::ops::Range;

use thiserror::Error;

/// Error accessing a shared-memory resource.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedMemoryError {
    /// The requested byte range is outside the shared-memory resource.
    #[error("shared-memory range is out of bounds")]
    InvalidRange,
}

/// Byte-copy access to a shared-memory resource.
///
/// A value may own a distinct shared-memory object or identify a region in a
/// larger shared-memory arena. Implementations must keep the backing resource
/// alive and make concurrent calls within the local process safe without
/// exposing Rust references into memory writable by another process.
///
/// Coordination with other processes is the responsibility of the protocol
/// using the shared memory.
pub trait SharedMemory: Send + Sync + 'static {
    /// Returns the mapped resource length in bytes.
    ///
    /// The length must remain stable for the lifetime of the resource.
    fn len(&self) -> usize;

    /// Returns whether the resource is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies bytes from shared memory into `destination`.
    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError>;

    /// Copies bytes from `source` into shared memory.
    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError>;
}

impl<Memory: SharedMemory + ?Sized> SharedMemory for Arc<Memory> {
    fn len(&self) -> usize {
        (**self).len()
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        (**self).read(offset, destination)
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        (**self).write(offset, source)
    }
}

impl<Memory: SharedMemory + ?Sized> SharedMemory for Box<Memory> {
    fn len(&self) -> usize {
        (**self).len()
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        (**self).read(offset, destination)
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        (**self).write(offset, source)
    }
}

/// Error validating or accessing a shared buffer region.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedBufferError {
    /// The descriptor does not identify a range within the region.
    #[error("shared buffer range is out of bounds")]
    InvalidRange,
    /// The supplied buffer length does not match the descriptor.
    #[error("buffer length does not match the shared buffer descriptor")]
    BufferLengthMismatch,
    /// The backing shared-memory access failed.
    #[error("shared-memory access failed: {0}")]
    SharedMemory(#[from] SharedMemoryError),
}

/// Location and length of one operation's bytes in a shared buffer region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedBufferDescriptor {
    /// Byte offset from the start of the region.
    pub offset: u64,
    /// Number of bytes in the range.
    pub length: u64,
}

impl SharedBufferDescriptor {
    /// Creates a descriptor for a byte range.
    pub const fn new(offset: u64, length: u64) -> Self {
        Self { offset, length }
    }

    /// Validates this descriptor and returns its native byte range.
    pub fn range(self, region_length: usize) -> Result<Range<usize>, SharedBufferError> {
        let offset = usize::try_from(self.offset).map_err(|_| SharedBufferError::InvalidRange)?;
        let length = usize::try_from(self.length).map_err(|_| SharedBufferError::InvalidRange)?;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= region_length)
            .ok_or(SharedBufferError::InvalidRange)?;
        Ok(offset..end)
    }
}

/// A contiguous shared-memory region used for operation buffers.
///
/// Allocation, ownership, handoff, and reuse are protocol responsibilities.
/// Accesses are not cross-process atomic, and consumers must not treat
/// peer-writable bytes as trusted or stable without copying and validating
/// them.
pub struct SharedBufferRegion<Memory: SharedMemory> {
    memory: Memory,
}

impl<Memory: SharedMemory> SharedBufferRegion<Memory> {
    /// Wraps a shared-memory resource as a contiguous buffer region.
    pub const fn new(memory: Memory) -> Self {
        Self { memory }
    }

    /// Returns the region length in bytes.
    pub fn len(&self) -> usize {
        self.memory.len()
    }

    /// Returns whether the region is empty.
    pub fn is_empty(&self) -> bool {
        self.memory.is_empty()
    }

    /// Returns the backing shared-memory resource.
    pub const fn memory(&self) -> &Memory {
        &self.memory
    }

    /// Consumes this view and returns the backing shared-memory resource.
    pub fn into_memory(self) -> Memory {
        self.memory
    }

    /// Copies `source` at `offset` and returns its validated descriptor.
    pub fn write(
        &self,
        offset: u64,
        source: &[u8],
    ) -> Result<SharedBufferDescriptor, SharedBufferError> {
        let length = u64::try_from(source.len()).map_err(|_| SharedBufferError::InvalidRange)?;
        let descriptor = SharedBufferDescriptor::new(offset, length);
        let range = descriptor.range(self.len())?;
        self.memory.write(range.start, source)?;
        Ok(descriptor)
    }

    /// Copies the bytes described by `descriptor` into `destination`.
    pub fn read(
        &self,
        descriptor: SharedBufferDescriptor,
        destination: &mut [u8],
    ) -> Result<(), SharedBufferError> {
        if usize::try_from(descriptor.length).ok() != Some(destination.len()) {
            return Err(SharedBufferError::BufferLengthMismatch);
        }
        let range = descriptor.range(self.len())?;
        self.memory.read(range.start, destination)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn writes_and_reads_described_ranges() {
        let memory = Arc::new(TestSharedMemory::new(24));
        let region = SharedBufferRegion::new(Arc::clone(&memory));

        let first = region.write(0, &[1, 2, 3]).unwrap();
        let third = region.write(16, &[4, 5]).unwrap();

        let mut first_bytes = [0; 3];
        region.read(first, &mut first_bytes).unwrap();
        assert_eq!(first_bytes, [1, 2, 3]);
        let mut third_bytes = [0; 2];
        region.read(third, &mut third_bytes).unwrap();
        assert_eq!(third_bytes, [4, 5]);
        assert_eq!(&memory.bytes()[8..16], &[0; 8]);
    }

    #[test]
    fn region_uses_backing_memory_length() {
        let region = SharedBufferRegion::new(TestSharedMemory::new(15));
        assert_eq!(region.len(), 15);
        assert!(!region.is_empty());

        let empty = SharedBufferRegion::new(TestSharedMemory::new(0));
        assert!(empty.is_empty());
    }

    #[test]
    fn descriptors_and_buffer_lengths_are_checked() {
        let region = SharedBufferRegion::new(TestSharedMemory::new(16));

        assert_eq!(region.write(16, &[1]), Err(SharedBufferError::InvalidRange));
        assert_eq!(
            region.write(12, &[0; 5]),
            Err(SharedBufferError::InvalidRange)
        );
        assert_eq!(
            region.read(SharedBufferDescriptor::new(0, 2), &mut [0; 1]),
            Err(SharedBufferError::BufferLengthMismatch)
        );
        assert_eq!(
            region.read(SharedBufferDescriptor::new(u64::MAX, 0), &mut []),
            Err(SharedBufferError::InvalidRange)
        );

        let empty = region.write(16, &[]).unwrap();
        region.read(empty, &mut []).unwrap();
    }

    struct TestSharedMemory(Mutex<Vec<u8>>);

    impl TestSharedMemory {
        fn new(length: usize) -> Self {
            Self(Mutex::new(vec![0; length]))
        }

        fn bytes(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
    }

    impl SharedMemory for TestSharedMemory {
        fn len(&self) -> usize {
            self.0.lock().unwrap().len()
        }

        fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
            let memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(destination.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let source = memory
                .get(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }

        fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
            let mut memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(source.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let destination = memory
                .get_mut(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }
    }
}
