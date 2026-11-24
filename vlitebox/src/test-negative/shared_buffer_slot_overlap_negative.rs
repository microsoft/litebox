// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately claims that full prefixes of adjacent slots overlap.

use litebox_broker_protocol::shared_buffer::{
    SharedBufferLayout, SharedBufferLayoutError, SharedBufferSlotIndex,
};
use vstd::prelude::*;

verus! {

pub fn reject_adjacent_slot_overlap()
    -> (result: Result<(core::ops::Range<usize>, core::ops::Range<usize>), SharedBufferLayoutError>)
    ensures match result {
        Ok((first, second)) => {
            &&& first.end > second.start
            &&& second.end > first.start
        },
        Err(_) => false,
    },
{
    let layout = SharedBufferLayout::new(8, 2)?;
    let first = layout.range(SharedBufferSlotIndex(0), 8)?;
    let second = layout.range(SharedBufferSlotIndex(1), 8)?;

    Ok((first, second))
}

}

fn main() {}
