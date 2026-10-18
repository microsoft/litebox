// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runtime shared-memory access for broker transports.
//!
//! [`SharedMemory`] and [`ControlRingMemory`] abstract a concrete shared-memory
//! resource, and [`AsSharedBytes`] one that also lends its bytes as
//! [`SharedBytes`]. [`SharedBufferPool`] applies the peer-visible
//! fixed-slot layout from [`litebox_broker_protocol::shared_buffer`] and
//! bounds-checks each slot access.

use alloc::alloc::Layout;
use alloc::sync::Arc;
use core::marker::PhantomData;
use core::ops::Range;
use core::ptr::NonNull;

use thiserror::Error;

use litebox_broker_protocol::shared_buffer::{
    MAX_SHARED_BUFFER_SEQUENCE_SLOTS, SharedBufferLayout, SharedBufferLayoutError,
    SharedBufferSequence, SharedBufferSlotIndex,
};

use crate::peer_memory;

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
}

/// Shared memory that lends its bytes as [`SharedBytes`], stably addressable
/// for as long as it is borrowed, so callers can copy directly between them
/// and memory of their own that they cannot expose as a slice, such as a
/// guest's memory.
///
/// A resource that is reachable only through fault-recovering copies, such
/// as a user mapping accessed from a kernel, provides only [`SharedMemory`].
pub trait AsSharedBytes: SharedMemory {
    /// Returns the `length` bytes at `offset`.
    ///
    /// The range is validated as for [`SharedMemory::read`] and
    /// [`SharedMemory::write`].
    fn shared_bytes(
        &self,
        offset: usize,
        length: usize,
    ) -> Result<SharedBytes<'_>, SharedMemoryError>;
}

impl<Memory: AsSharedBytes + ?Sized> AsSharedBytes for Arc<Memory> {
    fn shared_bytes(
        &self,
        offset: usize,
        length: usize,
    ) -> Result<SharedBytes<'_>, SharedMemoryError> {
        (**self).shared_bytes(offset, length)
    }
}

/// A range of mapped shared memory, which a peer may access at any time.
///
/// The bytes are readable and writable for `'a`, but never through Rust
/// references. Copy them with [`Self::copy_to_slice`] and
/// [`Self::copy_from_slice`], or through [`Self::as_ptr`] with a copy that,
/// like those in [`crate::peer_memory`], performs its accesses in inline
/// assembly, so a concurrent peer access cannot make it unsound.
#[derive(Clone, Copy, Debug)]
pub struct SharedBytes<'a> {
    address: NonNull<u8>,
    length: usize,
    _memory: PhantomData<&'a ()>,
}

impl SharedBytes<'_> {
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
            _memory: PhantomData,
        }
    }

    /// Returns the length in bytes.
    pub const fn len(&self) -> usize {
        self.length
    }

    /// Returns whether the range is empty.
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns the address of the first byte.
    pub const fn as_ptr(&self) -> *mut u8 {
        self.address.as_ptr()
    }

    /// Splits the range in two at `mid`.
    ///
    /// # Panics
    ///
    /// Panics if `mid` exceeds the length.
    pub fn split_at(self, mid: usize) -> (Self, Self) {
        (self.subrange(0..mid), self.subrange(mid..self.length))
    }

    /// Returns the bytes at `range` within this range.
    ///
    /// # Panics
    ///
    /// Panics if `range` is reversed or exceeds the length.
    #[must_use]
    pub fn subrange(self, range: Range<usize>) -> Self {
        assert!(
            range.start <= range.end && range.end <= self.length,
            "shared byte range {range:?} exceeds length {}",
            self.length
        );
        // SAFETY: The range lies within this one, which is valid as required
        // for the same lifetime.
        unsafe { Self::from_raw_parts(self.address.add(range.start), range.len()) }
    }

    /// Copies the bytes into `destination`, which must be the same length.
    ///
    /// The copy is an untrusted snapshot that a concurrent peer write may
    /// tear.
    ///
    /// # Panics
    ///
    /// Panics if the lengths differ.
    pub fn copy_to_slice(self, destination: &mut [u8]) {
        assert_eq!(
            destination.len(),
            self.length,
            "destination must match the shared bytes"
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
        assert_eq!(
            source.len(),
            self.length,
            "source must match the shared bytes"
        );
        // SAFETY: The bytes are writable and, never being referenced, cannot
        // overlap the source.
        unsafe { peer_memory::copy_to_peer(source, self.as_ptr()) };
    }
}

/// Shared memory in a private heap allocation, for endpoints in one address
/// space, such as an in-process broker and its tests.
///
/// Its bytes are zeroed and, like a mapping's, page-aligned.
pub struct HeapSharedMemory {
    address: NonNull<u8>,
    length: usize,
    layout: Layout,
}

// SAFETY: The allocation is accessed only through peer-memory copies and
// `SharedBytes`, which tolerate concurrent access from any thread.
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
}

impl Drop for HeapSharedMemory {
    fn drop(&mut self) {
        // SAFETY: The allocation was made with this layout and is no longer
        // lent, since lent bytes borrow `self`.
        unsafe { alloc::alloc::dealloc(self.address.as_ptr(), self.layout) };
    }
}

impl SharedMemory for HeapSharedMemory {
    fn len(&self) -> usize {
        self.length
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        self.shared_bytes(offset, destination.len())?
            .copy_to_slice(destination);
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        self.shared_bytes(offset, source.len())?
            .copy_from_slice(source);
        Ok(())
    }
}

impl AsSharedBytes for HeapSharedMemory {
    fn shared_bytes(
        &self,
        offset: usize,
        length: usize,
    ) -> Result<SharedBytes<'_>, SharedMemoryError> {
        offset
            .checked_add(length)
            .filter(|&end| end <= self.len())
            .ok_or(SharedMemoryError::InvalidRange)?;
        // SAFETY: The range lies within the allocation, which lives as long as
        // `self` and is accessed only through peer-memory copies.
        Ok(unsafe { SharedBytes::from_raw_parts(self.address.add(offset), length) })
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

impl<Memory: AsSharedBytes> SharedBufferPool<Memory> {
    /// Returns the shared bytes holding the `length` bytes at `offset` in
    /// `sequence`, in transfer order.
    ///
    /// Slots adjacent in memory share one part.
    pub fn sequence_bytes(
        &self,
        sequence: SharedBufferSequence,
        offset: usize,
        length: usize,
    ) -> Result<impl Iterator<Item = SharedBytes<'_>>, SharedBufferError> {
        let memory = self.memory.shared_bytes(0, self.memory.len())?;
        Ok(self
            .ranges_at(sequence, offset, length)?
            .map(move |range| memory.subrange(range)))
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

    #[test]
    fn pool_lends_sequence_bytes_at_offsets_across_slots() {
        let layout = SharedBufferLayout::new(4, 4).unwrap();
        let memory = Arc::new(HeapSharedMemory::new(layout.total_len()));
        let pool = SharedBufferPool::new(Arc::clone(&memory), layout).unwrap();
        let sequence = SharedBufferSequence::new(
            &[
                SharedBufferSlotIndex(2),
                SharedBufferSlotIndex(3),
                SharedBufferSlotIndex(0),
            ],
            11,
        )
        .unwrap();

        let mut source = 1..;
        for part in pool.sequence_bytes(sequence, 1, 9).unwrap() {
            let bytes: Vec<u8> = source.by_ref().take(part.len()).collect();
            part.copy_from_slice(&bytes);
        }
        assert_eq!(
            contents(&memory),
            [8, 9, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7]
        );
        let lengths = |offset, length| {
            pool.sequence_bytes(sequence, offset, length)
                .unwrap()
                .map(|part| part.len())
                .collect::<Vec<_>>()
        };
        assert_eq!(lengths(1, 9), [7, 2]);
        assert_eq!(lengths(8, 3), [3]);
        assert_eq!(lengths(11, 0), [0; 0]);
        assert!(matches!(
            pool.sequence_bytes(sequence, 4, 8),
            Err(SharedBufferError::TransferExceedsSequence)
        ));
    }

    #[test]
    fn shared_bytes_split_and_copy_within_their_range() {
        let memory = HeapSharedMemory::new(8);
        let bytes = memory.shared_bytes(2, 5).unwrap();
        let (front, back) = bytes.split_at(2);
        assert_eq!((front.len(), back.len()), (2, 3));
        front.copy_from_slice(&[1, 2]);
        back.subrange(1..3).copy_from_slice(&[3, 4]);
        let mut copied = [0; 5];
        bytes.copy_to_slice(&mut copied);
        assert_eq!(copied, [1, 2, 0, 3, 4]);
        assert_eq!(contents(&memory), [0, 0, 1, 2, 0, 3, 4, 0]);
        assert!(bytes.subrange(5..5).is_empty());
        assert_eq!(memory.shared_bytes(8, 0).unwrap().len(), 0);
        assert_eq!(
            memory.shared_bytes(4, 5).map(|bytes| bytes.len()),
            Err(SharedMemoryError::InvalidRange)
        );
        assert_eq!(
            memory.shared_bytes(usize::MAX, 2).map(|bytes| bytes.len()),
            Err(SharedMemoryError::InvalidRange)
        );
    }

    #[test]
    #[should_panic(expected = "exceeds length")]
    fn shared_bytes_reject_subranges_past_their_end() {
        let memory = HeapSharedMemory::new(8);
        let _ = memory.shared_bytes(0, 4).unwrap().subrange(2..5);
    }

    #[test]
    fn heap_shared_memory_is_zeroed_and_page_aligned() {
        let memory = HeapSharedMemory::new(5000);
        assert_eq!(memory.len(), 5000);
        assert!(contents(&memory).iter().all(|&byte| byte == 0));
        assert!(
            memory
                .shared_bytes(0, 1)
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
