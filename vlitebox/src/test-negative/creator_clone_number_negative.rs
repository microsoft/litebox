// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ProcessId;
use vstd::prelude::*;

verus! {

pub fn wrongly_zeros_a_cloned_creator(creator: ProcessId) -> (cur: ProcessId)
    requires creator.0 != 0,
    ensures cur.0 == 0,
{
    creator.clone()
}

}

fn main() {}
