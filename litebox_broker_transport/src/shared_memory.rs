// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runtime shared-memory interfaces and the checked shared-buffer pool.
//!
//! These interfaces describe how an endpoint reaches association shared memory
//! at runtime. The peer-visible slot geometry they are attached to lives in
//! [`litebox_broker_protocol::shared_buffer`].

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
    /// An atomic access is not naturally aligned.
    #[error("shared-memory atomic access is not naturally aligned")]
    UnalignedAtomic,
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

/// Ordered atomic access to shared-memory synchronization values.
///
/// Implementations must provide naturally aligned, indivisible, system-visible
/// operations over coherent shared memory. Atomic values must not also be
/// accessed through [`SharedMemory::read`] or [`SharedMemory::write`] by a
/// conforming endpoint.
pub trait AtomicSharedMemory: SharedMemory {
    /// Atomically loads a naturally aligned native-endian `u32` with acquire
    /// ordering.
    fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError>;

    /// Atomically increments a naturally aligned native-endian `u32` with
    /// release ordering and returns its previous value.
    fn fetch_add_u32_release(&self, offset: usize, value: u32) -> Result<u32, SharedMemoryError>;

    /// Atomically loads a naturally aligned native-endian `u64` with acquire
    /// ordering.
    fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError>;

    /// Atomically stores a naturally aligned native-endian `u64` with release
    /// ordering.
    ///
    /// On error, the value must not have been stored.
    fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError>;

    /// Atomically release-stores a native-endian `u64`, then release-adds to a
    /// native-endian `u32`, returning the previous `u32`.
    ///
    /// Both values must be naturally aligned and occupy non-overlapping ranges.
    /// Implementations must validate both accesses before storing either value.
    /// On error, neither value may have been modified.
    fn store_u64_and_fetch_add_u32_release(
        &self,
        store_offset: usize,
        value: u64,
        add_offset: usize,
        add_value: u32,
    ) -> Result<u32, SharedMemoryError>;
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
    /// The layout rejected the pool or the requested slot range.
    #[error("invalid shared-buffer layout access: {0}")]
    Layout(#[from] SharedBufferLayoutError),
    /// The backing shared-memory length does not exactly match the layout.
    #[error("shared-memory length does not match the shared-buffer layout")]
    MemoryLengthMismatch,
    /// The backing shared-memory access failed.
    #[error("shared-memory access failed: {0}")]
    SharedMemory(#[from] SharedMemoryError),
}

/// A shared-memory resource viewed as a checked fixed-slot buffer pool.
///
/// Slot ownership and reuse remain responsibilities of the protocol using the
/// pool. Accessors copy bytes and never expose references into peer-writable
/// memory.
pub struct SharedBufferPool<Memory: SharedMemory> {
    memory: Memory,
    layout: SharedBufferLayout,
}

impl<Memory: SharedMemory> SharedBufferPool<Memory> {
    /// Attaches a layout to an exact-size shared-memory resource.
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
