// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation-linked layout/range proof. Independently check the protocol
//! crate; this target does not verify imported bodies or prove transport safety.

use crate::spec::shared_buffer_layout_spec::{ranges_separated, shared_buffer_layout_policy};
use litebox_broker_protocol::shared_buffer::{
    SharedBufferLayout, SharedBufferLayoutError, SharedBufferSlotIndex, slot_range,
};
use vstd::prelude::*;

verus! {

pub proof fn shared_buffer_geometry_is_checked_and_ranges_are_bounded()
    ensures shared_buffer_layout_policy(),
{
    litebox_broker_protocol::shared_buffer::prove_shared_buffer_layout();
}

pub proof fn distinct_shared_buffer_slots_have_separated_ranges(
    layout: SharedBufferLayout,
    first_slot: SharedBufferSlotIndex,
    first_length: usize,
    first_range: core::ops::Range<usize>,
    second_slot: SharedBufferSlotIndex,
    second_length: usize,
    second_range: core::ops::Range<usize>,
)
    requires
        first_slot.0 != second_slot.0,
        slot_range(layout, first_slot, first_length, Ok(first_range)),
        slot_range(layout, second_slot, second_length, Ok(second_range)),
    ensures ranges_separated(first_range, second_range),
{
    litebox_broker_protocol::shared_buffer::prove_distinct_slot_ranges_separated(
        layout, first_slot, first_length, first_range,
        second_slot, second_length, second_range,
    );
}

// Actual native calls, including their error paths; no layout invariant is assumed.
pub fn check_distinct_slot_ranges(
    layout: SharedBufferLayout,
    first_slot: SharedBufferSlotIndex,
    first_length: usize,
    second_slot: SharedBufferSlotIndex,
    second_length: usize,
) -> (result: Result<(core::ops::Range<usize>, core::ops::Range<usize>), SharedBufferLayoutError>)
    requires first_slot.0 != second_slot.0,
    ensures match result {
        Ok((first, second)) => ranges_separated(first, second),
        Err(_) => true,
    },
{
    let first = layout.range(first_slot, first_length)?;
    let second = layout.range(second_slot, second_length)?;

    proof {
        distinct_shared_buffer_slots_have_separated_ranges(
            layout, first_slot, first_length, first,
            second_slot, second_length, second,
        );
    }

    Ok((first, second))
}

// Cross-crate actual calls also check that the exported contracts are usable.
pub fn check_empty_first_slot_prefix(
    slot_size: u32,
    slot_count: u32,
) -> (result: Result<core::ops::Range<usize>, SharedBufferLayoutError>)
    requires
        slot_size > 0,
        slot_count > 0,
        (slot_size as int) * (slot_count as int) <= isize::MAX,
    ensures match result {
        Ok(range) => range.start == 0 && range.end == 0,
        Err(_) => false,
    },
{
    let layout = SharedBufferLayout::new(slot_size, slot_count)?;

    layout.range(SharedBufferSlotIndex(0), 0)
}

}
