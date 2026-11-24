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

pub open spec fn unix_socket_limit_transition(
    prev: BrokerCoreLimits,
    cur: BrokerCoreLimits,
    total: usize,
    per_process: usize,
) -> bool {
    cur == BrokerCoreLimits {
        max_total_unix_socket_bytes: total,
        max_unix_socket_bytes_per_process: per_process,
        ..prev
    }
}

pub open spec fn readiness_limit_transition(
    prev: BrokerCoreLimits,
    cur: BrokerCoreLimits,
    total: usize,
    per_process: usize,
) -> bool {
    cur == BrokerCoreLimits {
        max_readiness_queue_entries: total,
        max_readiness_queue_entries_per_process: per_process,
        ..prev
    }
}

pub open spec fn thread_limit_transition(
    prev: BrokerCoreLimits,
    cur: BrokerCoreLimits,
    total: usize,
    per_process: usize,
) -> bool {
    cur == BrokerCoreLimits {
        max_threads: total,
        max_threads_per_process: per_process,
        ..prev
    }
}

pub open spec fn child_image_limit_transition(
    prev: BrokerCoreLimits,
    cur: BrokerCoreLimits,
    per_child: u64,
    total: u64,
) -> bool {
    cur == BrokerCoreLimits {
        max_child_image_size: per_child,
        max_total_child_image_size: total,
        ..prev
    }
}

pub open spec fn shared_file_limit_transition(
    prev: BrokerCoreLimits,
    cur: BrokerCoreLimits,
    files: usize,
) -> bool {
    cur == BrokerCoreLimits { max_shared_files: files, ..prev }
}

pub open spec fn other_limit_updates_transition(
    prev: BrokerCoreLimits,
    cur: BrokerCoreLimits,
    updates: BrokerCoreLimits,
) -> bool {
    cur == BrokerCoreLimits {
        max_total_unix_socket_bytes: updates.max_total_unix_socket_bytes,
        max_unix_socket_bytes_per_process: updates.max_unix_socket_bytes_per_process,
        max_readiness_queue_entries: updates.max_readiness_queue_entries,
        max_readiness_queue_entries_per_process: updates.max_readiness_queue_entries_per_process,
        max_threads: updates.max_threads,
        max_threads_per_process: updates.max_threads_per_process,
        max_child_image_size: updates.max_child_image_size,
        max_total_child_image_size: updates.max_total_child_image_size,
        max_shared_files: updates.max_shared_files,
        ..prev
    }
}

pub closed spec fn limit_builder_policy() -> bool {
    &&& forall|prev: BrokerCoreLimits, cur: BrokerCoreLimits, references: usize, pipe_capacity: usize|
        #[trigger] BrokerCoreLimits::with_process_quotas.ensures((prev, references, pipe_capacity), cur)
            ==> process_quota_transition(prev, cur, references, pipe_capacity)
    &&& forall|prev: BrokerCoreLimits, cur: BrokerCoreLimits, processes: usize|
        #[trigger] BrokerCoreLimits::with_process_limit.ensures((prev, processes), cur)
            ==> process_limit_transition(prev, cur, processes)
    &&& forall|prev: BrokerCoreLimits, cur: BrokerCoreLimits, total: usize, per_process: usize|
        #[trigger] BrokerCoreLimits::with_unix_socket_limits.ensures((prev, total, per_process), cur)
            ==> unix_socket_limit_transition(prev, cur, total, per_process)
    &&& forall|prev: BrokerCoreLimits, cur: BrokerCoreLimits, total: usize, per_process: usize|
        #[trigger] BrokerCoreLimits::with_readiness_queue_limits.ensures((prev, total, per_process), cur)
            ==> readiness_limit_transition(prev, cur, total, per_process)
    &&& forall|prev: BrokerCoreLimits, cur: BrokerCoreLimits, total: usize, per_process: usize|
        #[trigger] BrokerCoreLimits::with_thread_quotas.ensures((prev, total, per_process), cur)
            ==> thread_limit_transition(prev, cur, total, per_process)
    &&& forall|prev: BrokerCoreLimits, cur: BrokerCoreLimits, per_child: u64, total: u64|
        #[trigger] BrokerCoreLimits::with_child_image_size_limits.ensures((prev, per_child, total), cur)
            ==> child_image_limit_transition(prev, cur, per_child, total)
    &&& forall|prev: BrokerCoreLimits, cur: BrokerCoreLimits, files: usize|
        #[trigger] BrokerCoreLimits::with_shared_file_limit.ensures((prev, files), cur)
            ==> shared_file_limit_transition(prev, cur, files)
}

pub proof fn prove_limit_builder_frames()
    ensures limit_builder_policy(),
{
}

}
