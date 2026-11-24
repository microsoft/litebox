// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::BrokerCoreLimits;
use vstd::prelude::*;

verus! {

pub fn wrongly_preserves_default_local_quotas() -> (cur: BrokerCoreLimits)
    ensures cur == BrokerCoreLimits::DEFAULT,
{
    BrokerCoreLimits::new(
        BrokerCoreLimits::DEFAULT.max_references,
        BrokerCoreLimits::DEFAULT.max_total_pipe_capacity,
    )
}

}

fn main() {}
