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

/// Error validating or accessing fixed-slot shared transfer memory.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedTransferError {
    /// The slot layout is empty or exceeds the addressable range.
    #[error("invalid shared transfer layout")]
    InvalidLayout,
    /// The backing shared-memory length does not match the slot layout.
    #[error("shared-memory length does not match the transfer layout")]
    MemoryLengthMismatch,
    /// The descriptor names a slot outside the layout.
    #[error("shared transfer slot is out of bounds")]
    InvalidSlot,
    /// The transfer does not fit in one slot.
    #[error("shared transfer length exceeds the slot size")]
    TransferTooLarge,
    /// The supplied buffer length does not match the descriptor.
    #[error("buffer length does not match the shared transfer descriptor")]
    BufferLengthMismatch,
    /// The backing shared-memory access failed.
    #[error("shared-memory access failed: {0}")]
    SharedMemory(#[from] SharedMemoryError),
}

/// Immutable fixed-slot layout for association-scoped shared transfer memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedTransferLayout {
    slot_size: u32,
    slot_count: u32,
    total_len: usize,
}

impl SharedTransferLayout {
    /// Creates a checked fixed-slot layout.
    pub fn new(slot_size: u32, slot_count: u32) -> Result<Self, SharedTransferError> {
        if slot_size == 0 || slot_count == 0 {
            return Err(SharedTransferError::InvalidLayout);
        }
        let total_len = usize::try_from(slot_size)
            .ok()
            .and_then(|slot_size| {
                usize::try_from(slot_count)
                    .ok()
                    .and_then(|slot_count| slot_size.checked_mul(slot_count))
            })
            .filter(|total_len| isize::try_from(*total_len).is_ok())
            .ok_or(SharedTransferError::InvalidLayout)?;
        Ok(Self {
            slot_size,
            slot_count,
            total_len,
        })
    }

    /// Returns the size of each slot in bytes.
    pub const fn slot_size(self) -> u32 {
        self.slot_size
    }

    /// Returns the number of non-overlapping slots.
    pub const fn slot_count(self) -> u32 {
        self.slot_count
    }

    /// Returns the exact backing-memory length required by this layout.
    pub const fn total_len(self) -> usize {
        self.total_len
    }

    /// Validates a descriptor and returns its byte range in the shared memory.
    pub fn range(
        self,
        descriptor: SharedTransferDescriptor,
    ) -> Result<Range<usize>, SharedTransferError> {
        if descriptor.slot.index() >= self.slot_count {
            return Err(SharedTransferError::InvalidSlot);
        }
        if descriptor.length > self.slot_size {
            return Err(SharedTransferError::TransferTooLarge);
        }
        let offset = usize::try_from(descriptor.slot.index())
            .ok()
            .and_then(|slot| {
                usize::try_from(self.slot_size)
                    .ok()
                    .and_then(|slot_size| slot.checked_mul(slot_size))
            })
            .ok_or(SharedTransferError::InvalidLayout)?;
        let end = offset
            .checked_add(
                usize::try_from(descriptor.length)
                    .map_err(|_| SharedTransferError::TransferTooLarge)?,
            )
            .ok_or(SharedTransferError::TransferTooLarge)?;
        Ok(offset..end)
    }
}

/// Index of one fixed shared-transfer slot.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SharedTransferSlotIndex(u32);

impl SharedTransferSlotIndex {
    /// Creates a slot index.
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Returns the numeric slot index.
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// Location and length of one operation's bytes in shared transfer memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedTransferDescriptor {
    /// Fixed slot used by the operation.
    pub slot: SharedTransferSlotIndex,
    /// Number of bytes used from the start of the slot.
    pub length: u32,
}

impl SharedTransferDescriptor {
    /// Creates a descriptor for `length` bytes at the start of `slot`.
    pub const fn new(slot: SharedTransferSlotIndex, length: u32) -> Self {
        Self { slot, length }
    }
}

/// A shared-memory resource viewed through an immutable fixed-slot layout.
///
/// Slot ownership, handoff, and reuse are protocol responsibilities. Accesses
/// are not cross-process atomic, and consumers must not treat peer-writable
/// bytes as trusted or stable without copying and validating them.
pub struct SharedTransferMemory<Memory: SharedMemory> {
    memory: Memory,
    layout: SharedTransferLayout,
}

impl<Memory: SharedMemory> SharedTransferMemory<Memory> {
    /// Attaches a checked layout to an exact-size shared-memory resource.
    pub fn new(memory: Memory, layout: SharedTransferLayout) -> Result<Self, SharedTransferError> {
        if memory.len() != layout.total_len() {
            return Err(SharedTransferError::MemoryLengthMismatch);
        }
        Ok(Self { memory, layout })
    }

    /// Returns the fixed-slot layout.
    pub const fn layout(&self) -> SharedTransferLayout {
        self.layout
    }

    /// Returns the backing shared-memory resource.
    pub const fn memory(&self) -> &Memory {
        &self.memory
    }

    /// Consumes this view and returns the backing shared-memory resource.
    pub fn into_memory(self) -> Memory {
        self.memory
    }

    /// Copies `source` into `slot` and returns its validated descriptor.
    pub fn write(
        &self,
        slot: SharedTransferSlotIndex,
        source: &[u8],
    ) -> Result<SharedTransferDescriptor, SharedTransferError> {
        let length =
            u32::try_from(source.len()).map_err(|_| SharedTransferError::TransferTooLarge)?;
        let descriptor = SharedTransferDescriptor::new(slot, length);
        let range = self.layout.range(descriptor)?;
        self.memory.write(range.start, source)?;
        Ok(descriptor)
    }

    /// Copies the bytes described by `descriptor` into `destination`.
    pub fn read(
        &self,
        descriptor: SharedTransferDescriptor,
        destination: &mut [u8],
    ) -> Result<(), SharedTransferError> {
        if usize::try_from(descriptor.length).ok() != Some(destination.len()) {
            return Err(SharedTransferError::BufferLengthMismatch);
        }
        let range = self.layout.range(descriptor)?;
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
    fn fixed_slots_are_disjoint() {
        let layout = SharedTransferLayout::new(8, 3).unwrap();
        let memory = Arc::new(TestSharedMemory::new(layout.total_len()));
        let transfer = SharedTransferMemory::new(Arc::clone(&memory), layout).unwrap();

        let first = transfer
            .write(SharedTransferSlotIndex::new(0), &[1, 2, 3])
            .unwrap();
        let third = transfer
            .write(SharedTransferSlotIndex::new(2), &[4, 5])
            .unwrap();

        let mut first_bytes = [0; 3];
        transfer.read(first, &mut first_bytes).unwrap();
        assert_eq!(first_bytes, [1, 2, 3]);
        let mut third_bytes = [0; 2];
        transfer.read(third, &mut third_bytes).unwrap();
        assert_eq!(third_bytes, [4, 5]);
        assert_eq!(&memory.bytes()[8..16], &[0; 8]);
    }

    #[test]
    fn layout_and_backing_length_are_checked() {
        assert_eq!(
            SharedTransferLayout::new(0, 1),
            Err(SharedTransferError::InvalidLayout)
        );
        assert_eq!(
            SharedTransferLayout::new(1, 0),
            Err(SharedTransferError::InvalidLayout)
        );
        assert_eq!(
            SharedTransferLayout::new(u32::MAX, u32::MAX),
            Err(SharedTransferError::InvalidLayout)
        );

        let layout = SharedTransferLayout::new(8, 2).unwrap();
        assert!(matches!(
            SharedTransferMemory::new(TestSharedMemory::new(15), layout),
            Err(SharedTransferError::MemoryLengthMismatch)
        ));
    }

    #[test]
    fn descriptors_and_buffer_lengths_are_checked() {
        let layout = SharedTransferLayout::new(8, 2).unwrap();
        let transfer =
            SharedTransferMemory::new(TestSharedMemory::new(layout.total_len()), layout).unwrap();

        assert_eq!(
            transfer.write(SharedTransferSlotIndex::new(2), &[1]),
            Err(SharedTransferError::InvalidSlot)
        );
        assert_eq!(
            transfer.write(SharedTransferSlotIndex::new(1), &[0; 9]),
            Err(SharedTransferError::TransferTooLarge)
        );
        assert_eq!(
            transfer.read(
                SharedTransferDescriptor::new(SharedTransferSlotIndex::new(0), 2),
                &mut [0; 1],
            ),
            Err(SharedTransferError::BufferLengthMismatch)
        );

        let empty = transfer
            .write(SharedTransferSlotIndex::new(1), &[])
            .unwrap();
        transfer.read(empty, &mut []).unwrap();
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
