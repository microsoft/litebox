// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately puts range-length failure ahead of an invalid slot index.

use litebox_broker_protocol::shared_buffer::{
    SharedBufferLayout, SharedBufferLayoutError, SharedBufferSlotIndex,
};
use vstd::prelude::*;

verus! {

pub fn reject_wrong_shared_buffer_error_precedence()
    -> (result: Result<core::ops::Range<usize>, SharedBufferLayoutError>)
    ensures result == Err(SharedBufferLayoutError::RangeExceedsSlot),
{
    let layout = SharedBufferLayout::new(4, 2)?;

    layout.range(SharedBufferSlotIndex(2), 5)
}

}

fn main() {}
