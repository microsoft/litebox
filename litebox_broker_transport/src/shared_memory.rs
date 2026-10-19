// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runtime shared-memory access for broker transports.
//!
//! [`SharedMemory`] and [`ControlRingMemory`] abstract a concrete shared-memory
//! resource. [`SharedBufferPool`] applies the peer-visible fixed-slot layout
//! from [`litebox_broker_protocol::shared_buffer`] and bounds-checks each slot
//! access, and a [`SharedBuffer`] is a sequence of its slots as a buffer that
//! objects read into and write from.

use alloc::alloc::Layout;
use alloc::sync::Arc;
use core::convert::Infallible;
use core::ops::Range;
use core::ptr::NonNull;

use thiserror::Error;

use litebox_broker_protocol::shared_buffer::{
    MAX_SHARED_BUFFER_SEQUENCE_SLOTS, SharedBufferLayout, SharedBufferLayoutError,
    SharedBufferSequence, SharedBufferSlotIndex,
};
use litebox_platform::buffer::{Buffer, Fault, RawBytes, ReadBuffer, WriteBuffer};

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

    /// Returns the resource's bytes, if they are mapped for as long as it is
    /// borrowed, so callers can transfer them directly, such as with a system
    /// call, or copy them to and from memory of their own that they cannot
    /// expose as a slice, such as a guest's memory.
    ///
    /// A resource reachable only through fault-recovering copies, such as a
    /// user mapping accessed from a kernel, or whose copies are limited to
    /// some ranges, such as control-ring memory, returns `None`.
    fn raw_bytes(&self) -> Option<RawBytes<'_>> {
        None
    }
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

    /// Writes a naturally aligned native-endian `u32` with release semantics.
    ///
    /// On error, the value must not have been stored.
    fn store_u32_release(&self, offset: usize, value: u32) -> Result<(), SharedMemoryError>;

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

    fn raw_bytes(&self) -> Option<RawBytes<'_>> {
        (**self).raw_bytes()
    }
}

/// Shared memory in a private heap allocation, for endpoints in one address
/// space, such as an in-process broker and its tests.
///
/// It is intended only for tests and development. Production transports map
/// shared memory that the broker and LiteBox, in separate processes, both
/// access.
///
/// Its bytes are zeroed and, like a mapping's, page-aligned.
pub struct HeapSharedMemory {
    address: NonNull<u8>,
    length: usize,
    layout: Layout,
}

// SAFETY: The allocation is accessed only as `RawBytes`, which tolerate
// concurrent access from any thread.
unsafe impl Send for HeapSharedMemory {}
// SAFETY: As for `Send`.
unsafe impl Sync for HeapSharedMemory {}

impl HeapSharedMemory {
    const ALIGNMENT: usize = 4096;

    /// Allocates `length` zeroed bytes.
    ///
    /// # Panics
    ///
    /// Panics if `length` exceeds the allocator's limits, or aborts if the
    /// allocation fails.
    pub fn new(length: usize) -> Self {
        let layout = Layout::from_size_align(length.max(1), Self::ALIGNMENT)
            .expect("shared memory length must fit an allocation");
        // SAFETY: The layout has a nonzero size.
        let address = unsafe { alloc::alloc::alloc_zeroed(layout) };
        let Some(address) = NonNull::new(address) else {
            alloc::alloc::handle_alloc_error(layout);
        };
        Self {
            address,
            length,
            layout,
        }
    }

    /// Returns the `length` bytes at `offset`.
    fn range(&self, offset: usize, length: usize) -> Result<RawBytes<'_>, SharedMemoryError> {
        let end = offset
            .checked_add(length)
            .filter(|&end| end <= self.length)
            .ok_or(SharedMemoryError::InvalidRange)?;
        Ok(self.bytes().subrange(offset..end))
    }

    fn bytes(&self) -> RawBytes<'_> {
        // SAFETY: The allocation lives as long as `self` and is accessed only
        // as `RawBytes`.
        unsafe { RawBytes::from_raw_parts(self.address, self.length) }
    }
}

impl Drop for HeapSharedMemory {
    fn drop(&mut self) {
        // SAFETY: The allocation was made with this layout and is no longer
        // borrowed, since the `RawBytes` it exposes borrow `self`.
        unsafe { alloc::alloc::dealloc(self.address.as_ptr(), self.layout) };
    }
}

impl SharedMemory for HeapSharedMemory {
    fn len(&self) -> usize {
        self.length
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        self.range(offset, destination.len())?
            .copy_to_slice(destination);
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        self.range(offset, source.len())?.copy_from_slice(source);
        Ok(())
    }

    fn raw_bytes(&self) -> Option<RawBytes<'_>> {
        Some(self.bytes())
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
    /// The requested transfer does not fit in the shared-buffer sequence.
    #[error("shared-buffer sequence does not cover the requested transfer")]
    TransferExceedsSequence,
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

    /// Returns the shared-memory ranges holding the first `length` bytes of
    /// `sequence`, in transfer order.
    ///
    /// Slots adjacent in memory share one range.
    pub fn sequence_ranges(
        &self,
        sequence: SharedBufferSequence,
        length: usize,
    ) -> Result<impl Iterator<Item = Range<usize>> + use<Memory>, SharedBufferError> {
        let descriptors = sequence.descriptors(self.layout)?;
        if length > sequence.length() as usize {
            return Err(SharedBufferError::TransferExceedsSequence);
        }
        let mut ranges: [Range<usize>; MAX_SHARED_BUFFER_SEQUENCE_SLOTS] =
            core::array::from_fn(|_| 0..0);
        let mut count = 0_usize;
        let mut remaining = length;
        for descriptor in descriptors {
            if remaining == 0 {
                break;
            }
            let slot_length = remaining.min(descriptor.length as usize);
            let range = self.layout.range(descriptor.slot_index, slot_length)?;
            remaining -= slot_length;
            match count.checked_sub(1).map(|last| &mut ranges[last]) {
                Some(last) if last.end == range.start => last.end = range.end,
                _ => {
                    ranges[count] = range;
                    count += 1;
                }
            }
        }
        if remaining != 0 {
            return Err(SharedBufferError::TransferExceedsSequence);
        }
        Ok(ranges.into_iter().take(count))
    }

    /// Copies the bytes at `offset` in `sequence` into `destination`.
    pub fn read_sequence(
        &self,
        sequence: SharedBufferSequence,
        offset: usize,
        destination: &mut [u8],
    ) -> Result<(), SharedBufferError> {
        let mut copied = 0;
        for range in self.ranges_at(sequence, offset, destination.len())? {
            let end = copied + range.len();
            self.memory
                .read(range.start, &mut destination[copied..end])?;
            copied = end;
        }
        Ok(())
    }

    /// Copies `source` into `sequence` at `offset`.
    pub fn write_sequence(
        &self,
        sequence: SharedBufferSequence,
        offset: usize,
        source: &[u8],
    ) -> Result<(), SharedBufferError> {
        let mut copied = 0;
        for range in self.ranges_at(sequence, offset, source.len())? {
            let end = copied + range.len();
            self.memory.write(range.start, &source[copied..end])?;
            copied = end;
        }
        Ok(())
    }

    /// Returns the shared-memory ranges holding the `length` bytes at
    /// `offset` in `sequence`, in transfer order.
    fn ranges_at(
        &self,
        sequence: SharedBufferSequence,
        offset: usize,
        length: usize,
    ) -> Result<impl Iterator<Item = Range<usize>> + use<Memory>, SharedBufferError> {
        let end = offset
            .checked_add(length)
            .ok_or(SharedBufferError::TransferExceedsSequence)?;
        let mut skip = offset;
        Ok(self
            .sequence_ranges(sequence, end)?
            .filter_map(move |range| {
                if skip >= range.len() {
                    skip -= range.len();
                    None
                } else {
                    let start = range.start + skip;
                    skip = 0;
                    Some(start..range.end)
                }
            }))
    }
}

/// The first bytes of a shared-buffer sequence, as a buffer that objects read
/// into and write from.
///
/// [`SharedBufferPool::buffer`] returns one. Its bytes are transferred
/// directly if the memory has [`SharedMemory::raw_bytes`], and its copies
/// fault only if the memory cannot be accessed.
pub struct SharedBuffer<'a> {
    memory: &'a dyn SharedMemory,
    /// The memory ranges holding the bytes, in order; `ranges[..parts]` are
    /// used.
    ranges: [Range<usize>; MAX_SHARED_BUFFER_SEQUENCE_SLOTS],
    parts: usize,
    length: usize,
}

impl<Memory: SharedMemory> SharedBufferPool<Memory> {
    /// Returns the first `length` bytes of `sequence` as a buffer.
    pub fn buffer(
        &self,
        sequence: SharedBufferSequence,
        length: usize,
    ) -> Result<SharedBuffer<'_>, SharedBufferError> {
        let mut ranges: [Range<usize>; MAX_SHARED_BUFFER_SEQUENCE_SLOTS] =
            core::array::from_fn(|_| 0..0);
        let mut parts = 0;
        for range in self.sequence_ranges(sequence, length)? {
            ranges[parts] = range;
            parts += 1;
        }
        Ok(SharedBuffer {
            memory: &self.memory,
            ranges,
            parts,
            length,
        })
    }
}

impl SharedBuffer<'_> {
    /// Calls `part` with each part of the `length` bytes at `offset` in the
    /// buffer, in order: its offset in the memory, and its range within those
    /// bytes.
    ///
    /// # Panics
    ///
    /// Panics if the bytes exceed the buffer.
    fn for_each_part<E>(
        &self,
        offset: usize,
        length: usize,
        mut part: impl FnMut(usize, Range<usize>) -> Result<(), E>,
    ) -> Result<(), E> {
        self.assert_within(offset, length);
        let mut skip = offset;
        let mut done = 0;
        for range in &self.ranges[..self.parts] {
            if done == length {
                break;
            }
            if skip >= range.len() {
                skip -= range.len();
                continue;
            }
            let start = range.start + skip;
            skip = 0;
            let end = done + (range.end - start).min(length - done);
            part(start, done..end)?;
            done = end;
        }
        Ok(())
    }

    /// Passes the `length` bytes at `offset` in the buffer to `transfer` as
    /// raw bytes, if the memory has them.
    ///
    /// # Panics
    ///
    /// Panics if the bytes exceed the buffer.
    fn transfer_direct_at(
        &self,
        offset: usize,
        length: usize,
        transfer: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
    ) -> Option<usize> {
        self.assert_within(offset, length);
        let memory = self.memory.raw_bytes()?;
        let mut parts = [memory.subrange(0..0); MAX_SHARED_BUFFER_SEQUENCE_SLOTS];
        let mut count = 0;
        let Ok(()) = self.for_each_part(offset, length, |at, range| {
            parts[count] = memory.subrange(at..at + range.len());
            count += 1;
            Ok::<_, Infallible>(())
        });
        Some(transfer(&parts[..count]))
    }

    /// Panics unless the `length` bytes at `offset` lie within the buffer.
    fn assert_within(&self, offset: usize, length: usize) {
        assert!(
            offset
                .checked_add(length)
                .is_some_and(|end| end <= self.length),
            "{length} bytes at {offset} exceed a shared buffer of {} bytes",
            self.length
        );
    }
}

/// Copies `length` bytes a chunk at a time through a stack buffer: `fill`
/// fills each chunk from its offset in the bytes, and `drain` copies it on.
fn copy_staged(
    length: usize,
    mut fill: impl FnMut(usize, &mut [u8]) -> Result<(), SharedMemoryError>,
    mut drain: impl FnMut(usize, &[u8]) -> Result<(), SharedMemoryError>,
) -> Result<(), SharedMemoryError> {
    const STAGING_SIZE: usize = 256;
    let mut staging = [0; STAGING_SIZE];
    let mut offset = 0;
    while offset < length {
        let staged = &mut staging[..STAGING_SIZE.min(length - offset)];
        fill(offset, staged)?;
        drain(offset, staged)?;
        offset += staged.len();
    }
    Ok(())
}

impl Buffer for SharedBuffer<'_> {
    fn len(&self) -> usize {
        self.length
    }
}

impl ReadBuffer for SharedBuffer<'_> {
    fn copy_from_slice_at(&mut self, offset: usize, source: &[u8]) -> Result<(), Fault> {
        self.for_each_part(offset, source.len(), |at, range| {
            self.memory.write(at, &source[range])
        })
        .map_err(|_| Fault)
    }

    fn copy_from_raw_at(&mut self, offset: usize, source: RawBytes<'_>) -> Result<(), Fault> {
        self.for_each_part(offset, source.len(), |at, range| {
            copy_staged(
                range.len(),
                |copied, chunk| {
                    let start = range.start + copied;
                    source
                        .subrange(start..start + chunk.len())
                        .copy_to_slice(chunk);
                    Ok(())
                },
                |copied, chunk| self.memory.write(at + copied, chunk),
            )
        })
        .map_err(|_| Fault)
    }

    fn read_direct_at(
        &mut self,
        offset: usize,
        length: usize,
        read: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
    ) -> Option<usize> {
        self.transfer_direct_at(offset, length, read)
    }
}

impl WriteBuffer for SharedBuffer<'_> {
    fn copy_to_slice_at(&self, offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
        self.for_each_part(offset, destination.len(), |at, range| {
            self.memory.read(at, &mut destination[range])
        })
        .map_err(|_| Fault)
    }

    fn copy_to_raw_at(&self, offset: usize, destination: RawBytes<'_>) -> Result<(), Fault> {
        self.for_each_part(offset, destination.len(), |at, range| {
            copy_staged(
                range.len(),
                |copied, chunk| self.memory.read(at + copied, chunk),
                |copied, chunk| {
                    let start = range.start + copied;
                    destination
                        .subrange(start..start + chunk.len())
                        .copy_from_slice(chunk);
                    Ok(())
                },
            )
        })
        .map_err(|_| Fault)
    }

    fn write_direct_at(
        &self,
        offset: usize,
        length: usize,
        write: &mut dyn FnMut(&[RawBytes<'_>]) -> usize,
    ) -> Option<usize> {
        self.transfer_direct_at(offset, length, write)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn pool_checks_backing_length_and_slot_boundaries() {
        let layout = SharedBufferLayout::new(8, 3).unwrap();
        assert!(matches!(
            SharedBufferPool::new(HeapSharedMemory::new(23), layout),
            Err(SharedBufferError::MemoryLengthMismatch)
        ));
        let memory = Arc::new(HeapSharedMemory::new(layout.total_len()));
        let pool = SharedBufferPool::new(Arc::clone(&memory), layout).unwrap();

        pool.write(SharedBufferSlotIndex(0), &[1, 2, 3]).unwrap();
        pool.write(SharedBufferSlotIndex(2), &[4, 5]).unwrap();
        let mut first = [0; 3];
        pool.read(SharedBufferSlotIndex(0), &mut first).unwrap();
        assert_eq!(first, [1, 2, 3]);
        assert_eq!(&contents(&memory)[8..16], &[0; 8]);
        assert_eq!(
            pool.write(SharedBufferSlotIndex(2), &[0; 9]),
            Err(SharedBufferError::Layout(
                SharedBufferLayoutError::RangeExceedsSlot
            ))
        );
    }

    #[test]
    fn pool_copies_sequence_prefixes_across_slots() {
        let layout = SharedBufferLayout::new(4, 3).unwrap();
        let memory = Arc::new(HeapSharedMemory::new(layout.total_len()));
        let pool = SharedBufferPool::new(Arc::clone(&memory), layout).unwrap();
        let sequence =
            SharedBufferSequence::new(&[SharedBufferSlotIndex(0), SharedBufferSlotIndex(2)], 6)
                .unwrap();

        pool.write_sequence(sequence, 0, &[1, 2, 3, 4, 5, 6])
            .unwrap();
        assert_eq!(contents(&memory), [1, 2, 3, 4, 0, 0, 0, 0, 5, 6, 0, 0]);

        let mut destination = [0; 5];
        pool.read_sequence(sequence, 0, &mut destination).unwrap();
        assert_eq!(destination, [1, 2, 3, 4, 5]);
        assert_eq!(
            pool.write_sequence(sequence, 0, &[0; 7]),
            Err(SharedBufferError::TransferExceedsSequence)
        );
        assert_eq!(
            pool.read_sequence(sequence, 0, &mut [0; 7]),
            Err(SharedBufferError::TransferExceedsSequence)
        );
    }

    #[test]
    fn pool_copies_sequence_ranges_at_offsets_across_slots() {
        let layout = SharedBufferLayout::new(4, 3).unwrap();
        let memory = Arc::new(HeapSharedMemory::new(layout.total_len()));
        let pool = SharedBufferPool::new(Arc::clone(&memory), layout).unwrap();
        let sequence =
            SharedBufferSequence::new(&[SharedBufferSlotIndex(0), SharedBufferSlotIndex(2)], 7)
                .unwrap();

        pool.write_sequence(sequence, 2, &[1, 2, 3, 4]).unwrap();
        pool.write_sequence(sequence, 6, &[5]).unwrap();
        assert_eq!(contents(&memory), [0, 0, 1, 2, 0, 0, 0, 0, 3, 4, 5, 0]);

        let mut destination = [0; 3];
        pool.read_sequence(sequence, 3, &mut destination).unwrap();
        assert_eq!(destination, [2, 3, 4]);
        pool.read_sequence(sequence, 7, &mut []).unwrap();
        assert_eq!(
            pool.write_sequence(sequence, 6, &[0; 2]),
            Err(SharedBufferError::TransferExceedsSequence)
        );
        assert_eq!(
            pool.read_sequence(sequence, usize::MAX, &mut [0; 1]),
            Err(SharedBufferError::TransferExceedsSequence)
        );
    }

    #[test]
    fn pool_merges_slots_adjacent_in_memory() {
        let layout = SharedBufferLayout::new(4, 4).unwrap();
        let pool =
            SharedBufferPool::new(HeapSharedMemory::new(layout.total_len()), layout).unwrap();
        let sequence = SharedBufferSequence::new(
            &[
                SharedBufferSlotIndex(1),
                SharedBufferSlotIndex(2),
                SharedBufferSlotIndex(0),
                SharedBufferSlotIndex(3),
            ],
            14,
        )
        .unwrap();

        let ranges = |length| {
            pool.sequence_ranges(sequence, length)
                .unwrap()
                .collect::<Vec<_>>()
        };
        assert_eq!(ranges(14), [4..12, 0..4, 12..14]);
        assert_eq!(ranges(6), core::iter::once(4..10).collect::<Vec<_>>());
        assert_eq!(ranges(0), []);
    }

    /// Returns a pool of four four-byte slots, with a buffer sequence of
    /// slots 2, 3, and 0, which hold 11 bytes at memory offsets 8..16 and
    /// 0..3.
    fn pool_with_sequence<Memory: SharedMemory>(
        memory: Memory,
    ) -> (SharedBufferPool<Memory>, SharedBufferSequence) {
        let layout = SharedBufferLayout::new(4, 4).unwrap();
        let pool = SharedBufferPool::new(memory, layout).unwrap();
        let sequence = SharedBufferSequence::new(
            &[
                SharedBufferSlotIndex(2),
                SharedBufferSlotIndex(3),
                SharedBufferSlotIndex(0),
            ],
            11,
        )
        .unwrap();
        (pool, sequence)
    }

    #[test]
    fn shared_buffers_copy_at_offsets_across_slots() {
        let memory = Arc::new(HeapSharedMemory::new(16));
        let (pool, sequence) = pool_with_sequence(Arc::clone(&memory));
        let mut buffer = pool.buffer(sequence, 10).unwrap();
        assert_eq!(buffer.len(), 10);

        buffer
            .copy_from_slice_at(1, &[1, 2, 3, 4, 5, 6, 7, 8, 9])
            .unwrap();
        assert_eq!(
            contents(&memory),
            [8, 9, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7]
        );
        let mut copied = [0; 3];
        buffer.copy_to_slice_at(6, &mut copied).unwrap();
        assert_eq!(copied, [6, 7, 8]);
        let mut private = [0; 4];
        buffer
            .copy_to_raw_at(7, RawBytes::from(&mut private[..3]))
            .unwrap();
        assert_eq!(private, [7, 8, 9, 0]);
        buffer
            .copy_from_raw_at(6, RawBytes::from(&mut [10, 11][..]))
            .unwrap();
        assert_eq!(&contents(&memory)[14..], [10, 11]);
        assert!(matches!(
            pool.buffer(sequence, 12),
            Err(SharedBufferError::TransferExceedsSequence)
        ));
    }

    #[test]
    fn shared_buffers_transfer_directly_in_parts() {
        let memory = Arc::new(HeapSharedMemory::new(16));
        let (pool, sequence) = pool_with_sequence(Arc::clone(&memory));
        let mut buffer = pool.buffer(sequence, 11).unwrap();
        let lengths = |buffer: &SharedBuffer<'_>, offset, length| {
            let mut lengths = Vec::new();
            let written = buffer.write_direct_at(offset, length, &mut |parts| {
                lengths.extend(parts.iter().map(RawBytes::len));
                1
            });
            assert_eq!(written, Some(1));
            lengths
        };
        assert_eq!(lengths(&buffer, 1, 9), [7, 2]);
        assert_eq!(lengths(&buffer, 8, 3), [3]);
        assert_eq!(lengths(&buffer, 11, 0), [0; 0]);

        let read = buffer.read_direct_at(6, 3, &mut |parts| {
            parts[0].copy_from_slice(&[1, 2]);
            parts[1].copy_from_slice(&[3]);
            3
        });
        assert_eq!(read, Some(3));
        assert_eq!(&contents(&memory)[..2], [3, 0]);
        assert_eq!(&contents(&memory)[14..], [1, 2]);
    }

    #[test]
    #[should_panic(expected = "exceed a shared buffer")]
    fn shared_buffers_reject_transfers_past_their_end() {
        let (pool, sequence) = pool_with_sequence(HeapSharedMemory::new(16));
        let buffer = pool.buffer(sequence, 4).unwrap();
        let _ = buffer.write_direct_at(2, 3, &mut |_| 0);
    }

    /// Shared memory reachable only through copies.
    struct CopiedSharedMemory(HeapSharedMemory);

    impl SharedMemory for CopiedSharedMemory {
        fn len(&self) -> usize {
            self.0.len()
        }

        fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
            self.0.read(offset, destination)
        }

        fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
            self.0.write(offset, source)
        }
    }

    #[test]
    fn shared_buffers_without_raw_bytes_only_copy() {
        let (pool, sequence) = pool_with_sequence(CopiedSharedMemory(HeapSharedMemory::new(16)));
        let mut buffer = pool.buffer(sequence, 11).unwrap();
        assert_eq!(buffer.read_direct_at(0, 11, &mut |_| unreachable!()), None);
        let source: Vec<u8> = (1..=11).collect();
        buffer
            .copy_from_raw_at(0, RawBytes::from(&mut source.clone()[..]))
            .unwrap();
        let mut copied = vec![0; 11];
        buffer
            .copy_to_raw_at(0, RawBytes::from(&mut copied[..]))
            .unwrap();
        assert_eq!(copied, source);
    }

    #[test]
    fn heap_shared_memory_exposes_its_bytes() {
        let memory = HeapSharedMemory::new(8);
        memory.write(2, &[1, 2]).unwrap();
        let bytes = memory.raw_bytes().unwrap();
        assert_eq!(bytes.len(), 8);
        let mut copied = [0; 3];
        bytes.subrange(1..4).copy_to_slice(&mut copied);
        assert_eq!(copied, [0, 1, 2]);
        assert_eq!(
            memory.write(7, &[0; 2]),
            Err(SharedMemoryError::InvalidRange)
        );
        assert_eq!(
            memory.read(usize::MAX, &mut [0; 2]),
            Err(SharedMemoryError::InvalidRange)
        );
    }

    #[test]
    fn heap_shared_memory_is_zeroed_and_page_aligned() {
        let memory = HeapSharedMemory::new(5000);
        assert_eq!(memory.len(), 5000);
        assert!(contents(&memory).iter().all(|&byte| byte == 0));
        assert!(
            memory
                .raw_bytes()
                .unwrap()
                .as_ptr()
                .addr()
                .is_multiple_of(4096)
        );
        assert!(HeapSharedMemory::new(0).is_empty());
    }

    fn contents(memory: &HeapSharedMemory) -> Vec<u8> {
        let mut contents = vec![0; memory.len()];
        memory.read(0, &mut contents).unwrap();
        contents
    }
}
