// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately false: an over-capacity channel has positive room.

use vstd::prelude::*;

verus! {

pub fn reject_over_capacity_room() -> (room: usize)
    ensures room > 0,
{
    litebox_broker_core::channel::check_saturated_room(2, 3)
}

}

fn main() {}
