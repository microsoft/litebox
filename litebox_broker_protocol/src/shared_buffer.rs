// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Peer-visible association shared-buffer layout.
//!
//! Both peers agree on this fixed-slot layout before any payload moves, so the
//! slot geometry and the descriptors that name one slot are part of the
//! protocol contract. Attaching real memory to the layout and copying bytes
//! through it are runtime transport concerns that live in
//! `litebox_broker_transport`.

use core::ops::Range;

use thiserror::Error;

/// Size of each association shared-buffer slot.
pub const SHARED_BUFFER_SLOT_SIZE: u32 = 64 * 1024;

/// Number of slots in one association shared-buffer pool.
pub const SHARED_BUFFER_SLOT_COUNT: u32 = 256;

/// Maximum number of slots named by one operation-scoped sequence.
pub const MAX_SHARED_BUFFER_SEQUENCE_SLOTS: usize = 8;

const _: () = assert!(MAX_SHARED_BUFFER_SEQUENCE_SLOTS <= SHARED_BUFFER_SLOT_COUNT as usize);

/// Fixed layout of one association shared-buffer pool.
pub const SHARED_BUFFER_LAYOUT: SharedBufferLayout =
    match SharedBufferLayout::new(SHARED_BUFFER_SLOT_SIZE, SHARED_BUFFER_SLOT_COUNT) {
        Ok(layout) => layout,
        Err(_) => panic!("broker shared-buffer constants must form a valid layout"),
    };

/// Exact shared-memory size required for one association shared-buffer pool.
pub const SHARED_BUFFER_POOL_SIZE: usize = SHARED_BUFFER_LAYOUT.total_len();

/// Error validating a fixed-slot shared-buffer layout or one of its ranges.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedBufferLayoutError {
    /// The layout has no slots, has empty slots, or exceeds the addressable range.
    #[error("invalid shared-buffer layout")]
    InvalidLayout,
    /// The requested slot does not exist in the layout.
    #[error("shared-buffer slot is out of bounds")]
    InvalidSlot,
    /// The requested byte range does not fit in one slot.
    #[error("shared-buffer range exceeds the slot size")]
    RangeExceedsSlot,
    /// A slot sequence does not canonically cover its declared length.
    #[error("invalid shared-buffer sequence")]
    InvalidSequence,
}

/// Immutable fixed-slot layout for an association shared-buffer pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedBufferLayout {
    slot_size: u32,
    slot_count: u32,
    total_len: usize,
}

impl SharedBufferLayout {
    /// Creates a checked fixed-slot layout.
    pub const fn new(slot_size: u32, slot_count: u32) -> Result<Self, SharedBufferLayoutError> {
        if slot_size == 0 || slot_count == 0 {
            return Err(SharedBufferLayoutError::InvalidLayout);
        }
        let Some(total_len) = (slot_size as usize).checked_mul(slot_count as usize) else {
            return Err(SharedBufferLayoutError::InvalidLayout);
        };
        if total_len > isize::MAX as usize {
            return Err(SharedBufferLayoutError::InvalidLayout);
        }
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

    /// Returns the number of slots.
    pub const fn slot_count(self) -> u32 {
        self.slot_count
    }

    /// Returns the exact backing-memory length required by this layout.
    pub const fn total_len(self) -> usize {
        self.total_len
    }

    /// Returns the shared-memory range for a prefix of one slot.
    pub fn range(
        self,
        slot: SharedBufferSlotIndex,
        length: usize,
    ) -> Result<Range<usize>, SharedBufferLayoutError> {
        if slot.0 >= self.slot_count {
            return Err(SharedBufferLayoutError::InvalidSlot);
        }
        if length > self.slot_size as usize {
            return Err(SharedBufferLayoutError::RangeExceedsSlot);
        }
        let offset = (slot.0 as usize)
            .checked_mul(self.slot_size as usize)
            .ok_or(SharedBufferLayoutError::InvalidLayout)?;
        let end = offset
            .checked_add(length)
            .ok_or(SharedBufferLayoutError::RangeExceedsSlot)?;
        Ok(offset..end)
    }
}

/// Index of one fixed shared-buffer slot.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SharedBufferSlotIndex(pub u32);

/// Identifies one slot segment within an operation-scoped shared-buffer sequence.
///
/// The slot offset is derived from the trusted association layout and is never
/// supplied by the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedBufferSlotDescriptor {
    /// Slot containing this segment.
    pub slot_index: SharedBufferSlotIndex,
    /// Number of sequence bytes stored from the start of the slot.
    pub length: u32,
}

/// Identifies one operation-scoped byte sequence spread across fixed shared-buffer slots.
///
/// Slots are consumed in the listed order. Every slot except the last
/// contributes its full capacity; the last contributes the remaining bytes.
/// The bounded list keeps per-operation wire size independent of the total
/// number of slots in the association pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedBufferSequence {
    slot_indices: [SharedBufferSlotIndex; MAX_SHARED_BUFFER_SEQUENCE_SLOTS],
    slot_count: u8,
    length: u32,
}

impl SharedBufferSequence {
    /// Creates a sequence from slots in transfer order.
    pub fn new(
        slot_indices: &[SharedBufferSlotIndex],
        length: u32,
    ) -> Result<Self, SharedBufferLayoutError> {
        if slot_indices.is_empty() || slot_indices.len() > MAX_SHARED_BUFFER_SEQUENCE_SLOTS {
            return Err(SharedBufferLayoutError::InvalidSequence);
        }
        for (index, slot) in slot_indices.iter().enumerate() {
            if slot_indices[..index].contains(slot) {
                return Err(SharedBufferLayoutError::InvalidSequence);
            }
        }
        let mut stored_indices =
            [SharedBufferSlotIndex::default(); MAX_SHARED_BUFFER_SEQUENCE_SLOTS];
        stored_indices[..slot_indices.len()].copy_from_slice(slot_indices);
        let slot_count = u8::try_from(slot_indices.len())
            .map_err(|_| SharedBufferLayoutError::InvalidSequence)?;
        Ok(Self {
            slot_indices: stored_indices,
            slot_count,
            length,
        })
    }

    /// Returns the slots in transfer order.
    #[must_use]
    pub fn slot_indices(&self) -> &[SharedBufferSlotIndex] {
        &self.slot_indices[..usize::from(self.slot_count)]
    }

    /// Returns the aggregate number of bytes in the sequence.
    #[must_use]
    pub const fn length(self) -> u32 {
        self.length
    }

    /// Validates the sequence and returns its slot descriptors in transfer order.
    pub fn descriptors(
        self,
        layout: SharedBufferLayout,
    ) -> Result<impl ExactSizeIterator<Item = SharedBufferSlotDescriptor>, SharedBufferLayoutError>
    {
        let required_slots = if self.length == 0 {
            1
        } else {
            self.length.div_ceil(layout.slot_size())
        };
        if usize::try_from(required_slots).ok() != Some(self.slot_indices().len()) {
            return Err(SharedBufferLayoutError::InvalidSequence);
        }
        if self
            .slot_indices()
            .iter()
            .any(|slot_index| slot_index.0 >= layout.slot_count())
        {
            return Err(SharedBufferLayoutError::InvalidSlot);
        }
        let slot_size = layout.slot_size();
        let mut remaining_length = self.length;
        Ok(self
            .slot_indices
            .into_iter()
            .take(usize::from(self.slot_count))
            .map(move |slot_index| {
                let length = remaining_length.min(slot_size);
                remaining_length -= length;
                SharedBufferSlotDescriptor { slot_index, length }
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn association_layout_has_expected_size() {
        assert_eq!(SHARED_BUFFER_LAYOUT.slot_size(), 64 * 1024);
        assert_eq!(SHARED_BUFFER_LAYOUT.slot_count(), 256);
        assert_eq!(SHARED_BUFFER_POOL_SIZE, 16 * 1024 * 1024);
    }

    #[test]
    fn larger_slots_do_not_change_existing_transfer_limits() {
        assert_eq!(crate::pipe::MAX_PIPE_TRANSFER_SIZE, 32 * 1024);
        assert_eq!(crate::fs::MAX_FILE_TRANSFER_SIZE, 512 * 1024);
        assert_eq!(crate::socket::MAX_SOCKET_TRANSFER_SIZE, 32 * 1024);
        assert_eq!(crate::socket::MAX_UDP_DATAGRAM_SIZE, 65_507);
        assert_eq!(crate::stdio::MAX_STDIO_TRANSFER_SIZE, 32 * 1024);
    }

    #[test]
    fn layout_rejects_empty_and_overflowing_configurations() {
        assert_eq!(
            SharedBufferLayout::new(0, 1),
            Err(SharedBufferLayoutError::InvalidLayout)
        );
        assert_eq!(
            SharedBufferLayout::new(1, 0),
            Err(SharedBufferLayoutError::InvalidLayout)
        );
        assert_eq!(
            SharedBufferLayout::new(u32::MAX, u32::MAX),
            Err(SharedBufferLayoutError::InvalidLayout)
        );
    }

    #[test]
    fn layout_derives_disjoint_slot_ranges() {
        let layout = SharedBufferLayout::new(8, 3).unwrap();

        assert_eq!(layout.range(SharedBufferSlotIndex(0), 8), Ok(0..8));
        assert_eq!(layout.range(SharedBufferSlotIndex(1), 8), Ok(8..16));
        assert_eq!(layout.range(SharedBufferSlotIndex(2), 8), Ok(16..24));
        assert_eq!(
            layout.range(SharedBufferSlotIndex(3), 0),
            Err(SharedBufferLayoutError::InvalidSlot)
        );
        assert_eq!(
            layout.range(SharedBufferSlotIndex(0), 9),
            Err(SharedBufferLayoutError::RangeExceedsSlot)
        );
    }

    #[test]
    fn sequence_descriptors_follow_slot_order_and_length() {
        let layout = SharedBufferLayout::new(8, 5).unwrap();
        let descriptors = SharedBufferSequence::new(
            &[
                SharedBufferSlotIndex(1),
                SharedBufferSlotIndex(3),
                SharedBufferSlotIndex(4),
            ],
            18,
        )
        .unwrap()
        .descriptors(layout)
        .unwrap()
        .collect::<alloc::vec::Vec<_>>();

        assert_eq!(
            descriptors,
            [
                SharedBufferSlotDescriptor {
                    slot_index: SharedBufferSlotIndex(1),
                    length: 8,
                },
                SharedBufferSlotDescriptor {
                    slot_index: SharedBufferSlotIndex(3),
                    length: 8,
                },
                SharedBufferSlotDescriptor {
                    slot_index: SharedBufferSlotIndex(4),
                    length: 2,
                },
            ]
        );
    }

    #[test]
    fn sequence_validation_rejects_noncanonical_slot_sets() {
        let layout = SharedBufferLayout::new(8, 3).unwrap();

        assert_eq!(
            SharedBufferSequence::new(&[], 0),
            Err(SharedBufferLayoutError::InvalidSequence)
        );
        assert_eq!(
            SharedBufferSequence::new(&[SharedBufferSlotIndex(1), SharedBufferSlotIndex(1)], 1,),
            Err(SharedBufferLayoutError::InvalidSequence)
        );
        assert_eq!(
            SharedBufferSequence::new(&[SharedBufferSlotIndex(3)], 1)
                .unwrap()
                .descriptors(layout)
                .err(),
            Some(SharedBufferLayoutError::InvalidSlot)
        );
        assert_eq!(
            SharedBufferSequence::new(&[SharedBufferSlotIndex(0), SharedBufferSlotIndex(1)], 8,)
                .unwrap()
                .descriptors(layout)
                .err(),
            Some(SharedBufferLayoutError::InvalidSequence)
        );
        assert_eq!(
            SharedBufferSequence::new(&[SharedBufferSlotIndex(0)], 9)
                .unwrap()
                .descriptors(layout)
                .err(),
            Some(SharedBufferLayoutError::InvalidSequence)
        );
    }

    #[test]
    fn sequence_slot_indexes_are_independent_of_pool_bitmap_width() {
        let layout = SharedBufferLayout::new(8, 128).unwrap();
        let sequence = SharedBufferSequence::new(&[SharedBufferSlotIndex(100)], 8).unwrap();

        assert_eq!(
            sequence
                .descriptors(layout)
                .unwrap()
                .collect::<alloc::vec::Vec<_>>(),
            [SharedBufferSlotDescriptor {
                slot_index: SharedBufferSlotIndex(100),
                length: 8,
            }]
        );
    }
}
