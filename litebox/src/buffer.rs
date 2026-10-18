// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Buffers that objects read into and write from.
//!
//! An object reads into a [`ReadBuffer`] and writes from a [`WriteBuffer`],
//! which copy directly between themselves and wherever the object keeps its
//! bytes: a slice, or [`SharedBytes`] shared with the broker that owns the
//! object. A buffer need not be memory LiteBox can reference, such as a
//! guest's memory, so its copies may [`Fault`].

use litebox_broker_local::transfer::CopyFailed;

use crate::mm::exception_table::Fault;
use litebox_broker_transport::shared_memory::SharedBytes;

/// A buffer that an object reads into.
pub trait ReadBuffer {
    /// Returns the buffer's length in bytes.
    fn len(&self) -> usize;

    /// Returns whether the buffer is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies `source` into the buffer at `offset`.
    ///
    /// On a fault, any of the bytes may have been copied.
    ///
    /// # Panics
    ///
    /// Panics if `source` does not fit in the buffer at `offset`.
    fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault>;

    /// Copies `source` into the buffer at `offset`.
    ///
    /// On a fault, any of the bytes may have been copied.
    ///
    /// # Panics
    ///
    /// Panics if `source` does not fit in the buffer at `offset`.
    fn copy_from_shared_at(&mut self, offset: usize, source: SharedBytes<'_>) -> Result<(), Fault>;
}

/// A buffer that an object writes from.
pub trait WriteBuffer {
    /// Returns the buffer's length in bytes.
    fn len(&self) -> usize;

    /// Returns whether the buffer is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies the bytes at `offset` in the buffer into `destination`.
    ///
    /// On a fault, any of the bytes may have been copied.
    ///
    /// # Panics
    ///
    /// Panics if the buffer has fewer than `destination.len()` bytes at
    /// `offset`.
    fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault>;

    /// Copies the bytes at `offset` in the buffer into `destination`.
    ///
    /// On a fault, any of the bytes may have been copied.
    ///
    /// # Panics
    ///
    /// Panics if the buffer has fewer than `destination.len()` bytes at
    /// `offset`.
    fn copy_to_shared_at(&self, offset: usize, destination: SharedBytes<'_>) -> Result<(), Fault>;
}

impl ReadBuffer for [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
        self[offset..][..source.len()].copy_from_slice(source);
        Ok(())
    }

    fn copy_from_shared_at(&mut self, offset: usize, source: SharedBytes<'_>) -> Result<(), Fault> {
        source.copy_to_slice(&mut self[offset..][..source.len()]);
        Ok(())
    }
}

impl WriteBuffer for [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
        destination.copy_from_slice(&self[offset..][..destination.len()]);
        Ok(())
    }

    fn copy_to_shared_at(&self, offset: usize, destination: SharedBytes<'_>) -> Result<(), Fault> {
        destination.copy_from_slice(&self[offset..][..destination.len()]);
        Ok(())
    }
}

/// Returns a copier that copies the parts a broker lends it into `buffer`,
/// one after another from `offset`.
pub(crate) fn copy_into<B: ReadBuffer + ?Sized>(
    buffer: &mut B,
    mut offset: usize,
) -> impl FnMut(SharedBytes<'_>) -> Result<(), CopyFailed> + '_ {
    move |part| {
        let length = part.len();
        buffer
            .copy_from_shared_at(offset, part)
            .map_err(|Fault| CopyFailed)?;
        offset += length;
        Ok(())
    }
}

/// Returns a filler that fills the parts a broker lends it from `buffer`, one
/// after another from `offset`.
pub(crate) fn fill_from<B: WriteBuffer + ?Sized>(
    buffer: &B,
    mut offset: usize,
) -> impl FnMut(SharedBytes<'_>) -> Result<(), CopyFailed> + '_ {
    move |part| {
        let length = part.len();
        buffer
            .copy_to_shared_at(offset, part)
            .map_err(|Fault| CopyFailed)?;
        offset += length;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_transport::shared_memory::{HeapSharedMemory, MappedSharedMemory as _};

    #[test]
    fn slices_copy_at_offsets() {
        let memory = HeapSharedMemory::new(4);
        let shared = memory.bytes(0, 4).unwrap();
        let source: &[u8] = &[1, 2, 3, 4, 5, 6];
        source.copy_to_shared_at(1, shared).unwrap();
        let mut destination = [0; 6];
        destination.copy_from_shared_at(2, shared).unwrap();
        assert_eq!(destination, [0, 0, 2, 3, 4, 5]);
        ReadBuffer::copy_from_slice_at(&mut destination[..], 0, &[9]).unwrap();
        let mut copied = [0; 2];
        WriteBuffer::copy_to_slice_at(&destination[..], 4, &mut copied).unwrap();
        assert_eq!((destination[0], copied), (9, [4, 5]));
    }

    #[test]
    fn copiers_and_fillers_continue_across_parts() {
        let memory = HeapSharedMemory::new(5);
        let source: &[u8] = &[0, 1, 2, 3, 4, 5];
        let mut fill = fill_from(source, 1);
        fill(memory.bytes(0, 2).unwrap()).unwrap();
        fill(memory.bytes(2, 3).unwrap()).unwrap();
        let mut destination = [0; 6];
        {
            let mut copy = copy_into(&mut destination[..], 1);
            copy(memory.bytes(3, 2).unwrap()).unwrap();
            copy(memory.bytes(0, 3).unwrap()).unwrap();
        }
        assert_eq!(destination, [0, 4, 5, 1, 2, 3]);
    }

    #[test]
    #[should_panic(expected = "out of range for slice")]
    fn slices_reject_copies_past_their_end() {
        let memory = HeapSharedMemory::new(4);
        let source: &[u8] = &[1, 2, 3];
        let _ = source.copy_to_shared_at(1, memory.bytes(0, 3).unwrap());
    }
}
