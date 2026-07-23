// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared control-ring protocol layout and progress messages.

use core::ops::Range;

use thiserror::Error;

/// Size of one shared control-ring slot.
pub const CONTROL_RING_SLOT_SIZE: usize = 4096;

/// Size of the fixed metadata at the start of a control-ring slot.
pub const CONTROL_RING_SLOT_HEADER_SIZE: usize = 16;

/// Maximum encoded request or response size in one control-ring slot.
pub const CONTROL_RING_PAYLOAD_CAPACITY: usize =
    CONTROL_RING_SLOT_SIZE - CONTROL_RING_SLOT_HEADER_SIZE;

/// Number of slots in each direction of the shared control ring.
pub const CONTROL_RING_SLOT_COUNT: u64 = 64;

/// Exact shared-memory size required for both control-ring directions.
pub const CONTROL_RING_MEMORY_SIZE: usize =
    CONTROL_RING_DATA_SIZE + CONTROL_RING_SYNC_DIRECTION_SIZE * 2;

// The fixed count is representable by `usize` on every supported target.
#[allow(clippy::cast_possible_truncation)]
const CONTROL_RING_DIRECTION_SIZE: usize =
    CONTROL_RING_SLOT_SIZE * CONTROL_RING_SLOT_COUNT as usize;
const CONTROL_RING_DATA_SIZE: usize = CONTROL_RING_DIRECTION_SIZE * 2;
const CONTROL_RING_SYNC_DIRECTION_SIZE: usize = 16;
const PRODUCER_EPOCH_OFFSET: usize = 0;
const CONSUMER_EPOCH_OFFSET: usize = 4;
const CONSUMER_HEAD_OFFSET: usize = 8;

/// One direction in the shared control-ring mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlRingDirection {
    /// Local-to-broker request ring.
    Requests,
    /// Broker-to-local response ring.
    Responses,
}

impl ControlRingDirection {
    /// Returns the shared-memory range for one slot in this direction.
    pub fn slot_range(self, slot: u64) -> Result<Range<usize>, ControlRingLayoutError> {
        if slot >= CONTROL_RING_SLOT_COUNT {
            return Err(ControlRingLayoutError::InvalidSlot);
        }
        let slot = usize::try_from(slot).map_err(|_| ControlRingLayoutError::InvalidSlot)?;
        let direction_offset = match self {
            Self::Requests => 0,
            Self::Responses => CONTROL_RING_DIRECTION_SIZE,
        };
        let start = direction_offset + slot * CONTROL_RING_SLOT_SIZE;
        Ok(start..start + CONTROL_RING_SLOT_SIZE)
    }

    /// Returns the atomic `u32` epoch incremented when the producer publishes
    /// work for this direction.
    pub const fn producer_epoch_offset(self) -> usize {
        self.sync_offset() + PRODUCER_EPOCH_OFFSET
    }

    /// Returns the atomic `u32` epoch incremented when the consumer publishes
    /// progress for this direction.
    pub const fn consumer_epoch_offset(self) -> usize {
        self.sync_offset() + CONSUMER_EPOCH_OFFSET
    }

    /// Returns the atomic `u64` consumer-head offset for this direction.
    pub const fn consumer_head_offset(self) -> usize {
        self.sync_offset() + CONSUMER_HEAD_OFFSET
    }

    const fn sync_offset(self) -> usize {
        CONTROL_RING_DATA_SIZE
            + match self {
                Self::Requests => 0,
                Self::Responses => CONTROL_RING_SYNC_DIRECTION_SIZE,
            }
    }
}

/// Error deriving a range in the fixed control-ring layout.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlRingLayoutError {
    /// The requested slot does not exist.
    #[error("control-ring slot is out of bounds")]
    InvalidSlot,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_derives_disjoint_directional_slot_ranges() {
        assert_eq!(ControlRingDirection::Requests.slot_range(0), Ok(0..4096));
        assert_eq!(
            ControlRingDirection::Requests.slot_range(63),
            Ok(258_048..262_144)
        );
        assert_eq!(
            ControlRingDirection::Responses.slot_range(0),
            Ok(262_144..266_240)
        );
        assert_eq!(
            ControlRingDirection::Responses.slot_range(63),
            Ok(520_192..524_288)
        );
        assert_eq!(
            ControlRingDirection::Requests.slot_range(64),
            Err(ControlRingLayoutError::InvalidSlot)
        );
    }
}
