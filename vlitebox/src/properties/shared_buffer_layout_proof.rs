// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation-linked layout/range proof. Independently check the protocol
//! crate; this target does not verify imported bodies or prove transport safety.

use crate::shared_buffer_layout_spec::shared_buffer_layout_policy;
use litebox_broker_protocol::shared_buffer::{
    SharedBufferLayout, SharedBufferLayoutError, SharedBufferSlotIndex,
};
use vstd::prelude::*;

verus! {

pub proof fn shared_buffer_geometry_is_checked_and_ranges_are_bounded()
    ensures shared_buffer_layout_policy(),
{
    litebox_broker_protocol::shared_buffer::prove_shared_buffer_layout();
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
