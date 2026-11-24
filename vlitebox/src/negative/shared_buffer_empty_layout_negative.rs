// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately accepts a zero-sized shared-buffer layout.

use litebox_broker_protocol::shared_buffer::{SharedBufferLayout, SharedBufferLayoutError};
use vstd::prelude::*;

verus! {

pub fn reject_empty_shared_buffer_layout()
    -> (result: Result<SharedBufferLayout, SharedBufferLayoutError>)
    ensures matches!(result, Ok(_)),
{
    SharedBufferLayout::new(0, 1)
}

}

fn main() {}
