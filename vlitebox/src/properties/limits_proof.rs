// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Original builder calls preserve unrelated configuration fields.
//! These are not syscall transitions or proofs of live quota enforcement.

use litebox_broker_core::{BrokerCoreLimits, limits_spec};
use vstd::prelude::*;

verus! {

pub proof fn original_limit_builders_preserve_value_frames()
    ensures limits_spec::limit_builder_policy(),
{
    limits_spec::prove_limit_builder_frames();
}

pub fn check_above_broker_process_quotas(
    prev: BrokerCoreLimits,
    references: usize,
    pipe_capacity: usize,
) -> (cur: BrokerCoreLimits)
    requires {
        &&& references > prev.max_references
        &&& pipe_capacity > prev.max_total_pipe_capacity
    },
    ensures {
        &&& limits_spec::process_quota_transition(prev, cur, references, pipe_capacity)
        &&& cur.max_references_per_process == references
        &&& cur.max_pipe_capacity_per_process == pipe_capacity
        &&& cur.max_references == prev.max_references
        &&& cur.max_total_pipe_capacity == prev.max_total_pipe_capacity
    },
{
    prev.with_process_quotas(references, pipe_capacity)
}

pub fn check_independent_limit_updates_commute(
    prev: BrokerCoreLimits,
    references: usize,
    pipe_capacity: usize,
    processes: usize,
) -> (result: (BrokerCoreLimits, BrokerCoreLimits))
    ensures result.0 == result.1,
{
    let quota_first = prev.with_process_quotas(references, pipe_capacity)
        .with_process_limit(processes);

    let process_first = prev.with_process_limit(processes)
        .with_process_quotas(references, pipe_capacity);

    (quota_first, process_first)
}

}
