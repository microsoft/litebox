// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The original immutable sender query, not mutation, coalescing or delivery.

use litebox_broker_core::signal::verification;
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::signal::MAX_SIGNAL;
use vstd::prelude::*;

verus! {

pub proof fn original_pending_sender_clone_preserves_the_complete_array()
    ensures verification::pending_sender_clone_policy(),
{
    verification::prove_pending_sender_clone();
}

pub fn check_sender_clone_query_equivalence(senders: [Option<ProcessId>; MAX_SIGNAL as usize])
    -> (result: ([Option<ProcessId>; MAX_SIGNAL as usize], bool, bool))
    ensures {
        &&& result.0 == senders
        &&& result.1 == result.2
        &&& result.1 == (forall|i: int| 0 <= i < MAX_SIGNAL as int ==> senders[i].is_none())
    },
{
    verification::check_cloned_pending_sender_array(senders)
}

pub proof fn original_pending_sender_empty_query_is_exact()
    ensures verification::pending_sender_empty_policy(),
{
    verification::prove_pending_sender_empty_query();
}

pub fn check_any_pending_sender(senders: [Option<ProcessId>; MAX_SIGNAL as usize], index: usize)
    -> (result: bool)
    requires {
        &&& index < MAX_SIGNAL as usize
        &&& senders[index as int].is_some()
    },
    ensures !result,
{
    verification::check_pending_sender_array(senders)
}

pub fn check_no_pending_senders(senders: [Option<ProcessId>; MAX_SIGNAL as usize])
    -> (result: bool)
    requires forall|i: int| 0 <= i < MAX_SIGNAL as int ==> senders[i].is_none(),
    ensures result,
{
    verification::check_pending_sender_array(senders)
}

}
