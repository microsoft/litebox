// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::BrokerCoreLimits;
use vstd::prelude::*;

verus! {

pub fn wrongly_equates_default_with_constructor()
    -> (result: (BrokerCoreLimits, BrokerCoreLimits))
    ensures result.0 == result.1,
{
    let prev = BrokerCoreLimits::default();

    let cur = BrokerCoreLimits::new(prev.max_references, prev.max_total_pipe_capacity);

    (prev, cur)
}

}

fn main() {}
