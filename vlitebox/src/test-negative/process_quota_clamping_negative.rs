// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::BrokerCoreLimits;
use vstd::prelude::*;

verus! {

pub fn wrongly_clamps_process_quota(prev: BrokerCoreLimits, references: usize)
    -> (cur: BrokerCoreLimits)
    requires references > prev.max_references,
    ensures cur.max_references_per_process <= prev.max_references,
{
    prev.with_process_quotas(references, 0)
}

}

fn main() {}
