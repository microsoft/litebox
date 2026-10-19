// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Buffers that objects read into and write from.
//!
//! An object reads into a [`ReadBuffer`] and writes from a [`WriteBuffer`],
//! which copy directly between themselves and wherever the object keeps its
//! bytes: a slice, or [`SharedBytes`] shared with the broker that owns the
//! object. A buffer need not be memory LiteBox can reference, such as a
//! guest's memory, so its copies may [`Fault`]. A [`Window`] onto part of a
//! buffer is a buffer too.
//!
//! A copy reports no progress when it faults, so objects count progress a
//! chunk at a time: a fault reports only the bytes of earlier chunks, where
//! Linux also counts the bytes copied before the fault. A write does not send
//! the faulting chunk, and a read has already consumed it, so it is lost.

use alloc::boxed::Box;
use alloc::vec::Vec;
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

    /// Returns the window of the `length` bytes at `offset` in the buffer.
    ///
    /// # Panics
    ///
    /// Panics if the bytes exceed the buffer.
    fn window(&mut self, offset: usize, length: usize) -> Window<&mut Self> {
        let buffer_length = self.len();
        Window::new(self, buffer_length, offset, length)
    }
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

    /// Returns the window of the `length` bytes at `offset` in the buffer.
    ///
    /// # Panics
    ///
    /// Panics if the bytes exceed the buffer.
    fn window(&self, offset: usize, length: usize) -> Window<&Self> {
        Window::new(self, self.len(), offset, length)
    }
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

impl<const N: usize> ReadBuffer for [u8; N] {
    fn len(&self) -> usize {
        N
    }

    fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
        ReadBuffer::copy_from_slice_at(self.as_mut_slice(), offset, source)
    }

    fn copy_from_shared_at(&mut self, offset: usize, source: SharedBytes<'_>) -> Result<(), Fault> {
        ReadBuffer::copy_from_shared_at(self.as_mut_slice(), offset, source)
    }
}

impl<const N: usize> WriteBuffer for [u8; N] {
    fn len(&self) -> usize {
        N
    }

    fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
        WriteBuffer::copy_to_slice_at(self.as_slice(), offset, destination)
    }

    fn copy_to_shared_at(&self, offset: usize, destination: SharedBytes<'_>) -> Result<(), Fault> {
        WriteBuffer::copy_to_shared_at(self.as_slice(), offset, destination)
    }
}

impl ReadBuffer for Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
        ReadBuffer::copy_from_slice_at(self.as_mut_slice(), offset, source)
    }

    fn copy_from_shared_at(&mut self, offset: usize, source: SharedBytes<'_>) -> Result<(), Fault> {
        ReadBuffer::copy_from_shared_at(self.as_mut_slice(), offset, source)
    }
}

impl WriteBuffer for Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
        WriteBuffer::copy_to_slice_at(self.as_slice(), offset, destination)
    }

    fn copy_to_shared_at(&self, offset: usize, destination: SharedBytes<'_>) -> Result<(), Fault> {
        WriteBuffer::copy_to_shared_at(self.as_slice(), offset, destination)
    }
}

impl ReadBuffer for Box<[u8]> {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
        ReadBuffer::copy_from_slice_at(&mut **self, offset, source)
    }

    fn copy_from_shared_at(&mut self, offset: usize, source: SharedBytes<'_>) -> Result<(), Fault> {
        ReadBuffer::copy_from_shared_at(&mut **self, offset, source)
    }
}

impl WriteBuffer for Box<[u8]> {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
        WriteBuffer::copy_to_slice_at(&**self, offset, destination)
    }

    fn copy_to_shared_at(&self, offset: usize, destination: SharedBytes<'_>) -> Result<(), Fault> {
        WriteBuffer::copy_to_shared_at(&**self, offset, destination)
    }
}

/// The bytes at an offset in a buffer, as a buffer of their own.
///
/// [`ReadBuffer::window`] and [`WriteBuffer::window`] return windows.
pub struct Window<B> {
    buffer: B,
    offset: usize,
    length: usize,
}

impl<B> Window<B> {
    fn new(buffer: B, buffer_length: usize, offset: usize, length: usize) -> Self {
        assert!(
            offset
                .checked_add(length)
                .is_some_and(|end| end <= buffer_length),
            "{length} bytes at {offset} exceed a buffer of {buffer_length} bytes"
        );
        Self {
            buffer,
            offset,
            length,
        }
    }

    /// Returns the offset in the buffer of the `length` bytes at `offset` in
    /// the window.
    ///
    /// # Panics
    ///
    /// Panics if the bytes exceed the window.
    fn at(&self, offset: usize, length: usize) -> usize {
        assert!(
            offset
                .checked_add(length)
                .is_some_and(|end| end <= self.length),
            "{length} bytes at {offset} exceed a window of {} bytes",
            self.length
        );
        self.offset + offset
    }
}

impl<B: ReadBuffer + ?Sized> ReadBuffer for Window<&mut B> {
    fn len(&self) -> usize {
        self.length
    }

    fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
        let at = self.at(offset, source.len());
        self.buffer.copy_from_slice_at(at, source)
    }

    fn copy_from_shared_at(&mut self, offset: usize, source: SharedBytes<'_>) -> Result<(), Fault> {
        let at = self.at(offset, source.len());
        self.buffer.copy_from_shared_at(at, source)
    }
}

impl<B: WriteBuffer + ?Sized> WriteBuffer for Window<&B> {
    fn len(&self) -> usize {
        self.length
    }

    fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
        self.buffer
            .copy_to_slice_at(self.at(offset, destination.len()), destination)
    }

    fn copy_to_shared_at(&self, offset: usize, destination: SharedBytes<'_>) -> Result<(), Fault> {
        self.buffer
            .copy_to_shared_at(self.at(offset, destination.len()), destination)
    }
}

/// Returns a `CopyFromFn` that copies into `buffer`, from `offset` on, the parts
/// a broker passes it.
pub(crate) fn copy_to_buffer<B: ReadBuffer + ?Sized>(
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

/// Returns a `CopyToFn` that fills the parts a broker passes it with `buffer`'s
/// bytes from `offset` on.
pub(crate) fn copy_from_buffer<B: WriteBuffer + ?Sized>(
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
    use litebox_broker_transport::shared_memory::{AsSharedBytes as _, HeapSharedMemory};

    #[test]
    fn slices_copy_at_offsets() {
        let memory = HeapSharedMemory::new(4);
        let shared = memory.shared_bytes(0, 4).unwrap();
        let source: &[u8] = &[1, 2, 3, 4, 5, 6];
        source.copy_to_shared_at(1, shared).unwrap();
        let mut destination = [0; 6];
        destination.copy_from_shared_at(2, shared).unwrap();
        assert_eq!(destination, [0, 0, 2, 3, 4, 5]);
        ReadBuffer::copy_from_slice_at(&mut destination, 0, &[9]).unwrap();
        let mut copied = [0; 2];
        WriteBuffer::copy_to_slice_at(&destination, 4, &mut copied).unwrap();
        assert_eq!((destination[0], copied), (9, [4, 5]));
    }

    #[test]
    fn copy_fns_continue_across_parts() {
        let memory = HeapSharedMemory::new(5);
        let source: &[u8] = &[0, 1, 2, 3, 4, 5];
        let mut copy_to = copy_from_buffer(source, 1);
        copy_to(memory.shared_bytes(0, 2).unwrap()).unwrap();
        copy_to(memory.shared_bytes(2, 3).unwrap()).unwrap();
        let mut destination = [0; 6];
        {
            let mut copy_from = copy_to_buffer(&mut destination, 1);
            copy_from(memory.shared_bytes(3, 2).unwrap()).unwrap();
            copy_from(memory.shared_bytes(0, 3).unwrap()).unwrap();
        }
        assert_eq!(destination, [0, 4, 5, 1, 2, 3]);
    }

    #[test]
    fn windows_copy_within_their_buffers() {
        let memory = HeapSharedMemory::new(2);
        let shared = memory.shared_bytes(0, 2).unwrap();
        let source: &[u8] = &[1, 2, 3, 4, 5];
        let window = WriteBuffer::window(source, 1, 4);
        let window = window.window(1, 3);
        assert_eq!(window.len(), 3);
        window.copy_to_shared_at(1, shared).unwrap();
        let mut destination = [0; 6];
        let mut outer = ReadBuffer::window(&mut destination, 2, 4);
        let mut inner = outer.window(1, 3);
        inner.copy_from_shared_at(1, shared).unwrap();
        inner.copy_from_slice_at(0, &[9]).unwrap();
        assert_eq!(destination, [0, 0, 0, 9, 4, 5]);
    }

    #[test]
    #[should_panic(expected = "exceed a buffer")]
    fn windows_past_their_buffer_panic() {
        let mut bytes = [0; 4];
        let _ = ReadBuffer::window(&mut bytes, 3, 2);
    }

    #[test]
    #[should_panic(expected = "exceed a window")]
    fn copies_past_a_window_panic() {
        let bytes: &[u8] = &[0; 4];
        let _ = WriteBuffer::window(bytes, 0, 2).copy_to_slice_at(1, &mut [0; 2]);
    }

    #[test]
    #[should_panic(expected = "out of range for slice")]
    fn slices_reject_copies_past_their_end() {
        let memory = HeapSharedMemory::new(4);
        let source: &[u8] = &[1, 2, 3];
        let _ = source.copy_to_shared_at(1, memory.shared_bytes(0, 3).unwrap());
    }
}
