// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runtime shared-memory access for broker transports.
//!
//! [`SharedMemory`] and [`ControlRingMemory`] abstract a concrete shared-memory
//! resource. [`SharedBufferPool`] applies the peer-visible fixed-slot layout
//! from [`litebox_broker_protocol::shared_buffer`] and bounds-checks each slot
//! access.

use alloc::sync::Arc;

use thiserror::Error;

use litebox_broker_protocol::shared_buffer::{
    SharedBufferLayout, SharedBufferLayoutError, SharedBufferSlotIndex,
};

/// Error accessing a shared-memory resource.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedMemoryError {
    /// The requested byte range is outside the shared-memory resource.
    #[error("shared-memory range is out of bounds")]
    InvalidRange,
    /// A typed word access is not naturally aligned.
    #[error("shared-memory word access is not naturally aligned")]
    UnalignedWord,
    /// The backing resource could not complete an otherwise valid access.
    #[error("shared-memory backing resource access failed")]
    AccessFailed,
}

/// Byte-copy access to a shared-memory mapping.
///
/// A value may own a distinct shared-memory object or identify a region within
/// a larger resource. Each endpoint has its own value, and peers may use
/// different implementation types, such as user and kernel mappings of the same
/// physical memory. Implementations must keep the backing resource alive, make
/// concurrent local calls safe, and never expose Rust references into memory
/// writable by a peer.
///
/// A peer may access the same bytes concurrently, even if doing so violates the
/// higher-level protocol. Implementations must keep such access memory-safe;
/// callers that require a coherent snapshot must validate it separately.
///
/// The concrete transport establishes and shares the resource. The protocol
/// using it determines which endpoint may access each byte range.
pub trait SharedMemory: Send + Sync + 'static {
    /// Returns the mapped resource length in bytes.
    ///
    /// The length must remain stable for the lifetime of the resource.
    fn len(&self) -> usize;

    /// Returns whether the resource is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies bytes from shared memory at `offset` into `destination`.
    ///
    /// The entire range must be validated before any bytes are copied.
    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError>;

    /// Copies `source` into shared memory at `offset`.
    ///
    /// The entire range must be validated before any bytes are copied.
    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError>;
}

/// Ordered access to shared control-ring synchronization values.
///
/// A peer may modify any backing byte through an uncontrolled alias, including
/// with non-atomic or mixed-width accesses. Implementations must therefore
/// perform these operations without creating Rust references into peer-writable
/// memory. Reads return untrusted snapshots that may contain any bit pattern;
/// the control ring validates them against trusted endpoint-local state.
///
/// Word operations must be indivisible and ordered between conforming
/// endpoints. An uncontrolled peer alias may bypass those guarantees, but must
/// not compromise the implementation's Rust memory safety.
///
/// Safe implementations must enforce disjoint byte, `u32`, and `u64` access
/// regions for their own APIs. The `u32` increment must be indivisible between
/// conforming endpoints and must wrap on overflow.
pub trait ControlRingMemory: SharedMemory {
    /// Reads a naturally aligned native-endian `u32` with acquire semantics.
    fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError>;

    /// Indivisibly increments a naturally aligned native-endian `u32` with
    /// release semantics, wrapping on overflow.
    fn increment_u32_release(&self, offset: usize) -> Result<(), SharedMemoryError>;

    /// Reads a naturally aligned native-endian `u64` with acquire semantics.
    fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError>;

    /// Writes a naturally aligned native-endian `u64` with release semantics.
    ///
    /// On error, the value must not have been stored.
    fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError>;

    /// Release-writes a native-endian `u64`, then indivisibly increments a
    /// native-endian `u32` with release semantics.
    ///
    /// Both values must be naturally aligned and occupy non-overlapping ranges.
    /// Implementations must validate both accesses before writing either value.
    /// The two operations are ordered but are not one indivisible transaction,
    /// so a backing-resource failure may leave only the `u64` written.
    fn store_u64_and_increment_u32_release(
        &self,
        store_offset: usize,
        value: u64,
        increment_offset: usize,
    ) -> Result<(), SharedMemoryError>;
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

/// Error validating or accessing a fixed-slot shared-buffer pool.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedBufferError {
    /// The requested slot or byte range is invalid for the layout.
    #[error("invalid shared-buffer layout access: {0}")]
    Layout(#[from] SharedBufferLayoutError),
    /// The backing shared-memory length does not exactly match the layout.
    #[error("shared-memory length does not match the shared-buffer layout")]
    MemoryLengthMismatch,
    /// The backing shared-memory access failed.
    #[error("shared-memory access failed: {0}")]
    SharedMemory(#[from] SharedMemoryError),
}

/// A shared-memory resource with bounds-checked fixed-slot access.
///
/// Construction validates that the backing memory has the layout's exact size.
/// Each read or write validates its slot and byte count before deriving an
/// offset and copying data. The pool does not allocate, lease, or synchronize
/// slots; the protocol using it owns those responsibilities.
pub struct SharedBufferPool<Memory: SharedMemory> {
    memory: Memory,
    layout: SharedBufferLayout,
}

impl<Memory: SharedMemory> SharedBufferPool<Memory> {
    /// Creates a fixed-slot view over an exact-size shared-memory resource.
    pub fn new(memory: Memory, layout: SharedBufferLayout) -> Result<Self, SharedBufferError> {
        if memory.len() != layout.total_len() {
            return Err(SharedBufferError::MemoryLengthMismatch);
        }
        Ok(Self { memory, layout })
    }

    /// Returns the fixed-slot layout.
    pub const fn layout(&self) -> SharedBufferLayout {
        self.layout
    }

    /// Returns the backing shared-memory resource.
    ///
    /// Direct access is not constrained by the pool's fixed-slot layout.
    pub const fn memory(&self) -> &Memory {
        &self.memory
    }

    /// Copies bytes from the start of `slot` into `destination`.
    pub fn read(
        &self,
        slot: SharedBufferSlotIndex,
        destination: &mut [u8],
    ) -> Result<(), SharedBufferError> {
        let range = self.layout.range(slot, destination.len())?;
        self.memory.read(range.start, destination)?;
        Ok(())
    }

    /// Copies `source` into the start of `slot`.
    pub fn write(
        &self,
        slot: SharedBufferSlotIndex,
        source: &[u8],
    ) -> Result<(), SharedBufferError> {
        let range = self.layout.range(slot, source.len())?;
        self.memory.write(range.start, source)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    #[test]
    fn pool_checks_backing_length_and_slot_boundaries() {
        let layout = SharedBufferLayout::new(8, 3).unwrap();
        assert!(matches!(
            SharedBufferPool::new(TestSharedMemory::new(23), layout),
            Err(SharedBufferError::MemoryLengthMismatch)
        ));
        let memory = Arc::new(TestSharedMemory::new(layout.total_len()));
        let pool = SharedBufferPool::new(Arc::clone(&memory), layout).unwrap();

        pool.write(SharedBufferSlotIndex(0), &[1, 2, 3]).unwrap();
        pool.write(SharedBufferSlotIndex(2), &[4, 5]).unwrap();
        let mut first = [0; 3];
        pool.read(SharedBufferSlotIndex(0), &mut first).unwrap();
        assert_eq!(first, [1, 2, 3]);
        assert_eq!(&memory.bytes()[8..16], &[0; 8]);
        assert_eq!(
            pool.write(SharedBufferSlotIndex(2), &[0; 9]),
            Err(SharedBufferError::Layout(
                SharedBufferLayoutError::RangeExceedsSlot
            ))
        );
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
