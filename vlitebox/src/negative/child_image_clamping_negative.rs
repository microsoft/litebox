// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::BrokerCoreLimits;
use vstd::prelude::*;

verus! {

pub fn wrongly_clamps_child_image(
    prev: BrokerCoreLimits,
    per_child: u64,
    total: u64,
) -> (cur: BrokerCoreLimits)
    requires per_child > total,
    ensures cur.max_child_image_size <= cur.max_total_child_image_size,
{
    prev.with_child_image_size_limits(per_child, total)
}

}

fn main() {}
