// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Buffers that objects read into and write from.
//!
//! An object reads into a [`ReadBuffer`] and writes from a [`WriteBuffer`],
//! which copy between themselves and wherever the object keeps its bytes: a
//! slice, or [`RawBytes`], such as memory shared with another process. A
//! buffer need not be memory its user can reference, such as a guest's
//! memory, so its copies may [`Fault`]. Both are a [`Buffer`], which has a
//! length and [`SubBuffer`]s of its bytes, which are buffers too.
//!
//! A buffer whose bytes are [`RawBytes`] also lets an object transfer them
//! directly, such as with a system call, through [`ReadBuffer::read_direct_at`]
//! and [`WriteBuffer::write_direct_at`]. [`ReadBuffer::copy_from_buffer_at`]
//! copies between two buffers.
//!
//! As with `std::io::Read` and `std::io::Write`, generic functions take
//! buffers by value, as does [`Buffer::sub_buffer`]. A reference to a buffer
//! is a buffer too, so a caller passes `&mut buf` (or `&buf`) to keep using
//! `buf`. A dyn-compatible trait method takes `&mut dyn ReadBuffer` (or
//! `&dyn WriteBuffer`) instead, to which a slice, being unsized, is passed
//! through a reference to it.
//!
//! A copy reports no progress when it faults, so objects count progress a
//! chunk at a time: a fault reports only the bytes of earlier chunks, whereas
//! Linux also counts those copied before the fault. A write does not send the
//! faulting chunk, but a read may already have consumed it, losing it.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::Range;
use core::ptr::NonNull;

use crate::peer_memory;

/// Represents a fault during a fallible memory operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault;

/// Bytes that a buffer copies to or from but never references, such as
/// memory another process may access at any time.
///
/// They are readable and writable for `'a`, but never through Rust
/// references. Copy them with [`Self::copy_to_slice`] and
/// [`Self::copy_from_slice`], or through [`Self::as_ptr`] with a copy that
/// forms no references to them, such as one in inline assembly or a system
/// call, so a concurrent access by another process cannot make it unsound.
#[derive(Clone, Copy, Debug)]
pub struct RawBytes<'a> {
    address: NonNull<u8>,
    length: usize,
    _bytes: PhantomData<&'a ()>,
}

impl RawBytes<'_> {
    /// Returns the `length` bytes at `address`.
    ///
    /// # Safety
    ///
    /// `address..address + length` must be readable and writable for the
    /// returned value's lifetime, and must never be accessed through Rust
    /// references.
    pub const unsafe fn from_raw_parts(address: NonNull<u8>, length: usize) -> Self {
        Self {
            address,
            length,
            _bytes: PhantomData,
        }
    }

    /// Returns the length in bytes.
    pub const fn len(&self) -> usize {
        self.length
    }

    /// Returns whether there are no bytes.
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns the address of the first byte.
    pub const fn as_ptr(&self) -> *mut u8 {
        self.address.as_ptr()
    }

    /// Returns the bytes at `range` within these bytes.
    ///
    /// # Panics
    ///
    /// Panics if `range` is reversed or exceeds the length.
    #[must_use]
    pub fn subrange(self, range: Range<usize>) -> Self {
        assert!(
            range.start <= range.end && range.end <= self.length,
            "raw byte range {range:?} exceeds length {}",
            self.length
        );
        // SAFETY: The range lies within these bytes, which are valid as
        // required for the same lifetime.
        unsafe { Self::from_raw_parts(self.address.add(range.start), range.len()) }
    }

    /// Copies the bytes into `destination`, which must be the same length.
    ///
    /// The copy is an untrusted snapshot that a concurrent write by another
    /// process may tear.
    ///
    /// # Panics
    ///
    /// Panics if the lengths differ.
    pub fn copy_to_slice(self, destination: &mut [u8]) {
        assert_eq!(
            destination.len(),
            self.length,
            "destination must match the raw bytes"
        );
        // SAFETY: The bytes are readable and, never being referenced, cannot
        // overlap the destination.
        unsafe { peer_memory::copy_from_peer(self.as_ptr(), destination) };
    }

    /// Copies `source`, which must be the same length, into the bytes.
    ///
    /// # Panics
    ///
    /// Panics if the lengths differ.
    pub fn copy_from_slice(self, source: &[u8]) {
        assert_eq!(source.len(), self.length, "source must match the raw bytes");
        // SAFETY: The bytes are writable and, never being referenced, cannot
        // overlap the source.
        unsafe { peer_memory::copy_to_peer(source, self.as_ptr()) };
    }
}

impl<'a> From<&'a mut [u8]> for RawBytes<'a> {
    fn from(bytes: &'a mut [u8]) -> Self {
        let length = bytes.len();
        // SAFETY: The bytes are exclusively borrowed, so nothing else
        // references them, for the returned value's lifetime.
        unsafe { Self::from_raw_parts(NonNull::from(bytes).cast(), length) }
    }
}

/// A buffer of bytes, which an object reads into if it is a [`ReadBuffer`]
/// and writes from if it is a [`WriteBuffer`].
pub trait Buffer {
    /// Returns the buffer's length in bytes.
    fn len(&self) -> usize;

    /// Returns whether the buffer is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the sub-buffer of the `length` bytes at `offset` in the buffer.
    ///
    /// As with `std::io::Read::take`, this takes the buffer by value, so a
    /// caller passes `&mut buf` for a sub-buffer to read into, or `&buf` for
    /// one to write from, to keep using `buf`.
    ///
    /// # Panics
    ///
    /// Panics if the bytes exceed the buffer.
    fn sub_buffer(self, offset: usize, length: usize) -> SubBuffer<Self>
    where
        Self: Sized,
    {
        let buffer_length = self.len();
        SubBuffer::new(self, buffer_length, offset, length)
    }
}

/// A buffer that an object reads into.
pub trait ReadBuffer: Buffer {
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
    fn copy_from_raw_at(&mut self, offset: usize, source: RawBytes<'_>) -> Result<(), Fault>;

    /// Copies `source` into the buffer at `offset`: through a direct transfer
    /// if either's bytes are [`RawBytes`], and otherwise through a small
    /// staging buffer. A slice overrides this to copy straight from `source`.
    ///
    /// On a fault, any of the bytes may have been copied.
    ///
    /// # Panics
    ///
    /// Panics if `source` does not fit in the buffer at `offset`.
    fn copy_from_buffer_at(
        &mut self,
        offset: usize,
        source: &dyn WriteBuffer,
    ) -> Result<(), Fault> {
        const STAGING_SIZE: usize = 256;

        let length = source.len();
        assert_within(offset, length, self.len(), "buffer");
        let mut result = Ok(());
        // Copies to or from each part with `copy`, and returns how many bytes
        // it copied, which is all of them unless `copy` faults.
        let mut copy_parts =
            |parts: &[RawBytes<'_>],
             copy: &mut dyn FnMut(usize, RawBytes<'_>) -> Result<(), Fault>| {
                let mut copied = 0;
                for &part in parts {
                    if let Err(fault) = copy(copied, part) {
                        result = Err(fault);
                        return 0;
                    }
                    copied += part.len();
                }
                copied
            };
        if self
            .read_direct_at(offset, length, &mut |parts| {
                copy_parts(parts, &mut |at, part| source.copy_to_raw_at(at, part))
            })
            .is_some()
            || source
                .write_direct_at(0, length, &mut |parts| {
                    copy_parts(parts, &mut |at, part| {
                        self.copy_from_raw_at(offset + at, part)
                    })
                })
                .is_some()
        {
            return result;
        }
        let mut staging = [0; STAGING_SIZE];
        let mut copied = 0;
        while copied < length {
            let staged = &mut staging[..STAGING_SIZE.min(length - copied)];
            source.copy_to_slice_at(copied, staged)?;
            self.copy_from_slice_at(offset + copied, staged)?;
            copied += staged.len();
        }
        Ok(())
    }

    /// Lets `read` read directly into the `length` bytes at `offset` in the
    /// buffer, if they are [`RawBytes`].
    ///
    /// `read` is passed the bytes in order, in parts whose lengths sum to
    /// `length`, and returns how many it read from their start; this returns
    /// that count. Returns `None` without calling `read` if the bytes are not
    /// [`RawBytes`], such as a guest's memory, which only faulting copies can
    /// reach.
    ///
    /// # Panics
    ///
    /// Panics if the bytes exceed the buffer.
    fn read_direct_at(
        &mut self,
        offset: usize,
        length: usize,
        read: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
    ) -> Option<usize> {
        let _ = read;
        assert_within(offset, length, self.len(), "buffer");
        None
    }
}

/// A buffer that an object writes from.
pub trait WriteBuffer: Buffer {
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
    fn copy_to_raw_at(&self, offset: usize, destination: RawBytes<'_>) -> Result<(), Fault>;

    /// Lets `write` write directly from the `length` bytes at `offset` in the
    /// buffer, if they are [`RawBytes`].
    ///
    /// `write` is passed the bytes in order, in parts whose lengths sum to
    /// `length`, which it must only read, and returns how many it wrote from
    /// their start; this returns that count. Returns `None` without calling
    /// `write` if the bytes are not [`RawBytes`], such as a guest's memory,
    /// which only faulting copies can reach.
    ///
    /// # Panics
    ///
    /// Panics if the bytes exceed the buffer.
    fn write_direct_at(
        &self,
        offset: usize,
        length: usize,
        write: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
    ) -> Option<usize> {
        let _ = write;
        assert_within(offset, length, self.len(), "buffer");
        None
    }
}

/// Panics unless the `length` bytes at `offset` lie within `limit` bytes of
/// `what`.
fn assert_within(offset: usize, length: usize, limit: usize, what: &str) {
    assert!(
        offset.checked_add(length).is_some_and(|end| end <= limit),
        "{length} bytes at {offset} exceed a {what} of {limit} bytes"
    );
}

impl Buffer for [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

impl ReadBuffer for [u8] {
    fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
        self[offset..][..source.len()].copy_from_slice(source);
        Ok(())
    }

    fn copy_from_raw_at(&mut self, offset: usize, source: RawBytes<'_>) -> Result<(), Fault> {
        source.copy_to_slice(&mut self[offset..][..source.len()]);
        Ok(())
    }

    /// Copies `source` straight into the slice.
    fn copy_from_buffer_at(
        &mut self,
        offset: usize,
        source: &dyn WriteBuffer,
    ) -> Result<(), Fault> {
        assert_within(offset, source.len(), self.len(), "buffer");
        source.copy_to_slice_at(0, &mut self[offset..][..source.len()])
    }

    fn read_direct_at(
        &mut self,
        offset: usize,
        length: usize,
        read: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
    ) -> Option<usize> {
        Some(read(&[RawBytes::from(&mut self[offset..][..length])]))
    }
}

impl WriteBuffer for [u8] {
    fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
        destination.copy_from_slice(&self[offset..][..destination.len()]);
        Ok(())
    }

    fn copy_to_raw_at(&self, offset: usize, destination: RawBytes<'_>) -> Result<(), Fault> {
        destination.copy_from_slice(&self[offset..][..destination.len()]);
        Ok(())
    }
}

impl<B: Buffer + ?Sized> Buffer for &B {
    fn len(&self) -> usize {
        (**self).len()
    }
}

impl<B: Buffer + ?Sized> Buffer for &mut B {
    fn len(&self) -> usize {
        (**self).len()
    }
}

impl<B: ReadBuffer + ?Sized> ReadBuffer for &mut B {
    fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
        (**self).copy_from_slice_at(offset, source)
    }

    fn copy_from_raw_at(&mut self, offset: usize, source: RawBytes<'_>) -> Result<(), Fault> {
        (**self).copy_from_raw_at(offset, source)
    }

    fn copy_from_buffer_at(
        &mut self,
        offset: usize,
        source: &dyn WriteBuffer,
    ) -> Result<(), Fault> {
        (**self).copy_from_buffer_at(offset, source)
    }

    fn read_direct_at(
        &mut self,
        offset: usize,
        length: usize,
        read: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
    ) -> Option<usize> {
        (**self).read_direct_at(offset, length, read)
    }
}

impl<B: WriteBuffer + ?Sized> WriteBuffer for &B {
    fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
        (**self).copy_to_slice_at(offset, destination)
    }

    fn copy_to_raw_at(&self, offset: usize, destination: RawBytes<'_>) -> Result<(), Fault> {
        (**self).copy_to_raw_at(offset, destination)
    }

    fn write_direct_at(
        &self,
        offset: usize,
        length: usize,
        write: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
    ) -> Option<usize> {
        (**self).write_direct_at(offset, length, write)
    }
}

/// Implements the buffer traits for an owner of a byte slice by forwarding to
/// the slice.
macro_rules! forward_to_slice {
    ($({$($generics:tt)*})? $owner:ty) => {
        impl$(<$($generics)*>)? Buffer for $owner {
            fn len(&self) -> usize {
                <[u8]>::len(self)
            }
        }

        impl$(<$($generics)*>)? ReadBuffer for $owner {
            fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
                ReadBuffer::copy_from_slice_at(&mut self[..], offset, source)
            }

            fn copy_from_raw_at(
                &mut self,
                offset: usize,
                source: RawBytes<'_>,
            ) -> Result<(), Fault> {
                ReadBuffer::copy_from_raw_at(&mut self[..], offset, source)
            }

            fn copy_from_buffer_at(
                &mut self,
                offset: usize,
                source: &dyn WriteBuffer,
            ) -> Result<(), Fault> {
                ReadBuffer::copy_from_buffer_at(&mut self[..], offset, source)
            }

            fn read_direct_at(
                &mut self,
                offset: usize,
                length: usize,
                read: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
            ) -> Option<usize> {
                ReadBuffer::read_direct_at(&mut self[..], offset, length, read)
            }
        }

        impl$(<$($generics)*>)? WriteBuffer for $owner {
            fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
                WriteBuffer::copy_to_slice_at(&self[..], offset, destination)
            }

            fn copy_to_raw_at(&self, offset: usize, destination: RawBytes<'_>) -> Result<(), Fault> {
                WriteBuffer::copy_to_raw_at(&self[..], offset, destination)
            }
        }
    };
}

forward_to_slice!({const N: usize} [u8; N]);
forward_to_slice!(Vec<u8>);
forward_to_slice!(Box<[u8]>);

/// The bytes at an offset in a buffer, as a buffer of their own.
///
/// [`Buffer::sub_buffer`] returns one.
pub struct SubBuffer<B> {
    buffer: B,
    offset: usize,
    length: usize,
}

impl<B> SubBuffer<B> {
    fn new(buffer: B, buffer_length: usize, offset: usize, length: usize) -> Self {
        assert_within(offset, length, buffer_length, "buffer");
        Self {
            buffer,
            offset,
            length,
        }
    }

    /// Returns the offset in the buffer of the `length` bytes at `offset` in
    /// the sub-buffer.
    ///
    /// # Panics
    ///
    /// Panics if the bytes exceed the sub-buffer.
    fn at(&self, offset: usize, length: usize) -> usize {
        assert_within(offset, length, self.length, "sub-buffer");
        self.offset + offset
    }
}

impl<B: Buffer> Buffer for SubBuffer<B> {
    fn len(&self) -> usize {
        self.length
    }
}

impl<B: ReadBuffer> ReadBuffer for SubBuffer<B> {
    fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
        let at = self.at(offset, source.len());
        self.buffer.copy_from_slice_at(at, source)
    }

    fn copy_from_raw_at(&mut self, offset: usize, source: RawBytes<'_>) -> Result<(), Fault> {
        let at = self.at(offset, source.len());
        self.buffer.copy_from_raw_at(at, source)
    }

    fn copy_from_buffer_at(
        &mut self,
        offset: usize,
        source: &dyn WriteBuffer,
    ) -> Result<(), Fault> {
        let at = self.at(offset, source.len());
        self.buffer.copy_from_buffer_at(at, source)
    }

    fn read_direct_at(
        &mut self,
        offset: usize,
        length: usize,
        read: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
    ) -> Option<usize> {
        let at = self.at(offset, length);
        self.buffer.read_direct_at(at, length, read)
    }
}

impl<B: WriteBuffer> WriteBuffer for SubBuffer<B> {
    fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
        self.buffer
            .copy_to_slice_at(self.at(offset, destination.len()), destination)
    }

    fn copy_to_raw_at(&self, offset: usize, destination: RawBytes<'_>) -> Result<(), Fault> {
        self.buffer
            .copy_to_raw_at(self.at(offset, destination.len()), destination)
    }

    fn write_direct_at(
        &self,
        offset: usize,
        length: usize,
        write: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
    ) -> Option<usize> {
        self.buffer
            .write_direct_at(self.at(offset, length), length, write)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// A buffer whose bytes are reachable only through copies, as a guest's
    /// memory is.
    struct Copied(Vec<u8>);

    impl Buffer for Copied {
        fn len(&self) -> usize {
            self.0.len()
        }
    }

    impl ReadBuffer for Copied {
        fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
            ReadBuffer::copy_from_slice_at(&mut self.0, offset, source)
        }

        fn copy_from_raw_at(&mut self, offset: usize, source: RawBytes<'_>) -> Result<(), Fault> {
            ReadBuffer::copy_from_raw_at(&mut self.0, offset, source)
        }
    }

    impl WriteBuffer for Copied {
        fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
            WriteBuffer::copy_to_slice_at(&self.0, offset, destination)
        }

        fn copy_to_raw_at(&self, offset: usize, destination: RawBytes<'_>) -> Result<(), Fault> {
            WriteBuffer::copy_to_raw_at(&self.0, offset, destination)
        }
    }

    /// A buffer that can copy only into slices, so a copy that would stage
    /// through raw bytes panics.
    struct SliceCopied(Vec<u8>);

    impl Buffer for SliceCopied {
        fn len(&self) -> usize {
            self.0.len()
        }
    }

    impl WriteBuffer for SliceCopied {
        fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
            WriteBuffer::copy_to_slice_at(&self.0, offset, destination)
        }

        fn copy_to_raw_at(&self, _: usize, _: RawBytes<'_>) -> Result<(), Fault> {
            unreachable!("slices copy from buffers straight into themselves")
        }

        fn write_direct_at(
            &self,
            _: usize,
            _: usize,
            _: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
        ) -> Option<usize> {
            unreachable!("slices copy from buffers straight into themselves")
        }
    }

    #[test]
    fn slices_copy_from_buffers_straight_into_themselves() {
        let source = SliceCopied(vec![1, 2, 3]);
        let mut destination = vec![0; 7];
        destination.copy_from_buffer_at(0, &source).unwrap();
        let mut outer = (&mut destination).sub_buffer(1, 6);
        (&mut outer)
            .sub_buffer(2, 4)
            .copy_from_buffer_at(1, &source)
            .unwrap();
        assert_eq!(destination, [1, 2, 3, 0, 1, 2, 3]);
    }

    #[test]
    fn slices_copy_at_offsets() {
        let mut memory = [0; 4];
        let raw = RawBytes::from(&mut memory[..]);
        let source: &[u8] = &[1, 2, 3, 4, 5, 6];
        source.copy_to_raw_at(1, raw).unwrap();
        let mut destination = [0; 6];
        destination.copy_from_raw_at(2, raw).unwrap();
        assert_eq!(destination, [0, 0, 2, 3, 4, 5]);
        ReadBuffer::copy_from_slice_at(&mut destination, 0, &[9]).unwrap();
        let mut copied = [0; 2];
        WriteBuffer::copy_to_slice_at(&destination, 4, &mut copied).unwrap();
        assert_eq!((destination[0], copied), (9, [4, 5]));
    }

    #[test]
    fn slices_read_directly() {
        let mut bytes = vec![0; 6];
        let mut sub_buffer = (&mut bytes).sub_buffer(1, 4);
        let read = sub_buffer.read_direct_at(1, 3, &mut |parts| {
            assert_eq!(parts.len(), 1);
            parts[0].subrange(0..2).copy_from_slice(&[7, 8]);
            2
        });
        assert_eq!(read, Some(2));
        assert_eq!(bytes, [0, 0, 7, 8, 0, 0]);
        let source: &[u8] = &bytes;
        assert_eq!(source.write_direct_at(0, 6, &mut |_| unreachable!()), None);
    }

    #[test]
    fn sub_buffers_copy_within_their_buffers() {
        let mut memory = [0; 2];
        let raw = RawBytes::from(&mut memory[..]);
        let source: &[u8] = &[1, 2, 3, 4, 5];
        let sub_buffer = source.sub_buffer(1, 4);
        let sub_buffer = sub_buffer.sub_buffer(1, 3);
        assert_eq!(sub_buffer.len(), 3);
        sub_buffer.copy_to_raw_at(1, raw).unwrap();
        let mut destination = [0; 6];
        let mut outer = (&mut destination).sub_buffer(2, 4);
        let mut inner = (&mut outer).sub_buffer(1, 3);
        inner.copy_from_raw_at(1, raw).unwrap();
        inner.copy_from_slice_at(0, &[9]).unwrap();
        assert_eq!(destination, [0, 0, 0, 9, 4, 5]);
    }

    #[test]
    fn buffers_copy_with_or_without_raw_bytes() {
        let bytes: Vec<u8> = (0..=255).cycle().take(700).collect();
        let mut expected = vec![0; 701];
        expected[1..].copy_from_slice(&bytes);
        let mut into_raw = vec![0; 701];
        into_raw
            .copy_from_buffer_at(1, &Copied(bytes.clone()))
            .unwrap();
        assert_eq!(into_raw, expected);
        let mut from_raw = Copied(vec![0; 701]);
        from_raw.copy_from_buffer_at(1, &bytes).unwrap();
        assert_eq!(from_raw.0, expected);
        let mut staged = Copied(vec![0; 701]);
        staged.copy_from_buffer_at(1, &Copied(bytes)).unwrap();
        assert_eq!(staged.0, expected);
    }

    #[test]
    #[should_panic(expected = "exceed a buffer")]
    fn buffer_copies_past_the_destination_panic() {
        let mut destination = vec![0; 4];
        let _ = destination.copy_from_buffer_at(2, &[0; 3]);
    }

    #[test]
    #[should_panic(expected = "exceed a buffer")]
    fn sub_buffers_past_their_buffer_panic() {
        let mut bytes = [0; 4];
        let _ = (&mut bytes).sub_buffer(3, 2);
    }

    #[test]
    #[should_panic(expected = "exceed a sub-buffer")]
    fn copies_past_a_sub_buffer_panic() {
        let bytes: &[u8] = &[0; 4];
        let _ = bytes.sub_buffer(0, 2).copy_to_slice_at(1, &mut [0; 2]);
    }

    #[test]
    #[should_panic(expected = "exceeds length")]
    fn raw_bytes_reject_subranges_past_their_end() {
        let mut memory = [0; 4];
        let _ = RawBytes::from(&mut memory[..]).subrange(2..5);
    }

    #[test]
    #[should_panic(expected = "out of range for slice")]
    fn slices_reject_copies_past_their_end() {
        let mut memory = [0; 3];
        let source: &[u8] = &[1, 2, 3];
        let _ = source.copy_to_raw_at(1, RawBytes::from(&mut memory[..]));
    }
}
