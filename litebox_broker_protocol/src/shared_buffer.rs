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
pub const SHARED_BUFFER_SLOT_SIZE: u32 = 32 * 1024;

/// Number of slots in one association shared-buffer pool.
pub const SHARED_BUFFER_SLOT_COUNT: u32 = 16;

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

/// Identifies one operation-scoped region in the association shared-buffer pool.
///
/// The slot offset is derived from the trusted association layout and is never
/// supplied by the peer. The request variant determines the transfer direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedBufferDescriptor {
    /// Slot used by this operation.
    pub slot_index: SharedBufferSlotIndex,
    /// Number of bytes used from the start of the slot.
    pub length: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn association_layout_has_expected_size() {
        assert_eq!(SHARED_BUFFER_LAYOUT.slot_size(), 32 * 1024);
        assert_eq!(SHARED_BUFFER_LAYOUT.slot_count(), 16);
        assert_eq!(SHARED_BUFFER_POOL_SIZE, 512 * 1024);
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
}
