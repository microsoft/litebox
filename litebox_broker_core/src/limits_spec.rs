// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Exact owned-value frames for original configuration builders.
//! Arbitrary input limits are allowed; live accounting and authority are not modeled.

use crate::BrokerCoreLimits;
use vstd::prelude::*;

verus! {

pub open spec fn process_quota_transition(
    prev: BrokerCoreLimits,
    cur: BrokerCoreLimits,
    references: usize,
    pipe_capacity: usize,
) -> bool {
    cur == BrokerCoreLimits {
        max_references_per_process: references,
        max_pipe_capacity_per_process: pipe_capacity,
        ..prev
    }
}

pub open spec fn process_limit_transition(
    prev: BrokerCoreLimits,
    cur: BrokerCoreLimits,
    processes: usize,
) -> bool {
    cur == BrokerCoreLimits { max_processes: processes, ..prev }
}

pub closed spec fn limit_builder_policy() -> bool {
    &&& forall|prev: BrokerCoreLimits, cur: BrokerCoreLimits, references: usize, pipe_capacity: usize|
        #[trigger] BrokerCoreLimits::with_process_quotas.ensures((prev, references, pipe_capacity), cur)
            ==> process_quota_transition(prev, cur, references, pipe_capacity)
    &&& forall|prev: BrokerCoreLimits, cur: BrokerCoreLimits, processes: usize|
        #[trigger] BrokerCoreLimits::with_process_limit.ensures((prev, processes), cur)
            ==> process_limit_transition(prev, cur, processes)
}

pub proof fn prove_limit_builder_frames()
    ensures limit_builder_policy(),
{
}

}
