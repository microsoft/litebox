// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Transport-neutral shared-memory resources.

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
/// larger shared-memory resource. Each endpoint has its own implementation, and
/// peers may use different implementation types, such as user and kernel
/// mappings of the same physical memory. Implementations must keep the backing
/// resource alive and make concurrent local calls safe without exposing Rust
/// references into memory writable by the peer.
///
/// Establishing the shared resource and coordinating access between endpoints
/// are responsibilities of the deployment and protocol using the shared
/// memory.
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

/// Location and length of one operation's bytes in shared memory.
///
/// Allocation, ownership, handoff, and reuse are protocol responsibilities.
/// A descriptor does not make peer-writable bytes trusted or stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedBufferDescriptor {
    /// Byte offset from the start of the shared memory.
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
    pub fn range(self, memory_length: usize) -> Result<Range<usize>, SharedMemoryError> {
        let offset = usize::try_from(self.offset).map_err(|_| SharedMemoryError::InvalidRange)?;
        let length = usize::try_from(self.length).map_err(|_| SharedMemoryError::InvalidRange)?;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= memory_length)
            .ok_or(SharedMemoryError::InvalidRange)?;
        Ok(offset..end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_ranges_are_checked() {
        assert_eq!(SharedBufferDescriptor::new(8, 3).range(16), Ok(8..11));
        assert_eq!(SharedBufferDescriptor::new(16, 0).range(16), Ok(16..16));
        assert_eq!(
            SharedBufferDescriptor::new(16, 1).range(16),
            Err(SharedMemoryError::InvalidRange)
        );
        assert_eq!(
            SharedBufferDescriptor::new(12, 5).range(16),
            Err(SharedMemoryError::InvalidRange)
        );
        assert_eq!(
            SharedBufferDescriptor::new(u64::MAX, 1).range(usize::MAX),
            Err(SharedMemoryError::InvalidRange)
        );
    }
}
