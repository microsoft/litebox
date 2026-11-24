// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Original builder calls preserve unrelated configuration fields.
//! These are not syscall transitions or proofs of live quota enforcement.

use litebox_broker_core::{BrokerCoreLimits, limits_spec};
use vstd::prelude::*;

verus! {

pub proof fn original_limit_clone_preserves_the_complete_configuration()
    ensures limits_spec::limit_clone_policy(),
{
    limits_spec::prove_limit_clone();
}

pub fn check_cloned_process_quota_update(
    prev: BrokerCoreLimits,
    references: usize,
    pipe_capacity: usize,
) -> (result: (BrokerCoreLimits, BrokerCoreLimits))
    ensures {
        &&& result.0 == prev
        &&& limits_spec::process_quota_transition(prev, result.1, references, pipe_capacity)
    },
{
    let cloned = prev.clone();

    let updated = cloned.with_process_quotas(references, pipe_capacity);

    (cloned, updated)
}

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

pub fn check_other_limit_updates_commute(
    prev: BrokerCoreLimits,
    updates: BrokerCoreLimits,
) -> (result: (BrokerCoreLimits, BrokerCoreLimits))
    ensures {
        &&& limits_spec::other_limit_updates_transition(prev, result.0, updates)
        &&& result.0 == result.1
    },
{
    let forward = prev
        .with_unix_socket_limits(updates.max_total_unix_socket_bytes, updates.max_unix_socket_bytes_per_process)
        .with_readiness_queue_limits(updates.max_readiness_queue_entries, updates.max_readiness_queue_entries_per_process)
        .with_thread_quotas(updates.max_threads, updates.max_threads_per_process)
        .with_child_image_size_limits(updates.max_child_image_size, updates.max_total_child_image_size)
        .with_shared_file_limit(updates.max_shared_files);

    let reverse = prev
        .with_shared_file_limit(updates.max_shared_files)
        .with_child_image_size_limits(updates.max_child_image_size, updates.max_total_child_image_size)
        .with_thread_quotas(updates.max_threads, updates.max_threads_per_process)
        .with_readiness_queue_limits(updates.max_readiness_queue_entries, updates.max_readiness_queue_entries_per_process)
        .with_unix_socket_limits(updates.max_total_unix_socket_bytes, updates.max_unix_socket_bytes_per_process);

    (forward, reverse)
}

pub fn check_oversized_child_image_limit(
    prev: BrokerCoreLimits,
    per_child: u64,
    total: u64,
) -> (cur: BrokerCoreLimits)
    requires per_child > total,
    ensures {
        &&& limits_spec::child_image_limit_transition(prev, cur, per_child, total)
        &&& cur.max_child_image_size > cur.max_total_child_image_size
    },
{
    prev.with_child_image_size_limits(per_child, total)
}

pub proof fn original_limit_constructors_preserve_default_frames()
    ensures limits_spec::limit_constructor_policy(),
{
    limits_spec::prove_limit_constructor_frames();
}

pub fn check_new_at_default_ceilings_changes_local_quotas()
    -> (cur: BrokerCoreLimits)
    ensures {
        &&& limits_spec::reference_pipe_limit_transition(
            BrokerCoreLimits::DEFAULT,
            cur,
            BrokerCoreLimits::DEFAULT.max_references,
            BrokerCoreLimits::DEFAULT.max_total_pipe_capacity,
        )
        &&& cur.max_references_per_process > BrokerCoreLimits::DEFAULT.max_references_per_process
        &&& cur.max_pipe_capacity_per_process > BrokerCoreLimits::DEFAULT.max_pipe_capacity_per_process
    },
{
    BrokerCoreLimits::new(
        BrokerCoreLimits::DEFAULT.max_references,
        BrokerCoreLimits::DEFAULT.max_total_pipe_capacity,
    )
}

pub fn check_constructor_accepts_above_broker_socket_quota(
    sockets: usize,
    per_process: usize,
) -> (cur: BrokerCoreLimits)
    requires per_process > sockets,
    ensures {
        &&& limits_spec::constructor_socket_limit_transition(
            BrokerCoreLimits::DEFAULT, cur, 0, 0, sockets, per_process,
        )
        &&& cur.max_sockets_per_process > cur.max_sockets
    },
{
    BrokerCoreLimits::new_with_all_limits(0, 0, sockets, per_process)
}

pub proof fn original_default_returns_the_registered_native_value()
    ensures limits_spec::limit_default_policy(),
{
    limits_spec::prove_limit_default();
}

pub fn check_default_and_new_differ_in_local_quotas()
    -> (result: (BrokerCoreLimits, BrokerCoreLimits))
    ensures {
        &&& result.0 == BrokerCoreLimits::DEFAULT
        &&& limits_spec::reference_pipe_limit_transition(
            result.0, result.1, result.0.max_references, result.0.max_total_pipe_capacity,
        )
        &&& result.1.max_references_per_process > result.0.max_references_per_process
        &&& result.1.max_pipe_capacity_per_process > result.0.max_pipe_capacity_per_process
    },
{
    let prev = BrokerCoreLimits::default();

    let cur = BrokerCoreLimits::new(prev.max_references, prev.max_total_pipe_capacity);

    (prev, cur)
}

}
