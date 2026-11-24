// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Original signals-kind projection and immutable pending-sender query.
//! Not send, coalescing, delivery, or ownership policy.

use super::{MAX_SIGNAL, PendingSenders, ProcessId, SignalsObject};
use crate::object::ObjectEntry;
use crate::{BrokerError, Result};
use vstd::prelude::*;

verus! {

pub closed spec fn pending_sender_clone_policy() -> bool {
    forall|prev: PendingSenders, cur: PendingSenders|
        #[trigger] PendingSenders::clone.ensures((&prev,), cur) ==> cur == prev
}

pub proof fn prove_pending_sender_clone()
    ensures pending_sender_clone_policy(),
{
}

pub fn check_cloned_pending_sender_array(senders: [Option<ProcessId>; MAX_SIGNAL as usize])
    -> (result: ([Option<ProcessId>; MAX_SIGNAL as usize], bool, bool))
    ensures {
        &&& result.0 == senders
        &&& result.1 == result.2
        &&& result.1 == (forall|i: int| 0 <= i < MAX_SIGNAL as int ==> senders[i].is_none())
    },
{
    let prev = PendingSenders(senders);

    let cur = prev.clone();

    let prior_empty = prev.is_empty();

    let current_empty = cur.is_empty();

    (cur.0, prior_empty, current_empty)
}

pub closed spec fn pending_sender_empty_policy() -> bool {
    forall|prev: PendingSenders, result: bool|
        #[trigger] PendingSenders::is_empty.ensures((&prev,), result)
            ==> result == (forall|i: int| 0 <= i < MAX_SIGNAL as int ==> prev.0[i].is_none())
}

pub proof fn prove_pending_sender_empty_query()
    ensures pending_sender_empty_policy(),
{
}

// An erased consumer of the original query, not the add/coalescing algorithm.
pub fn check_pending_sender_array(senders: [Option<ProcessId>; MAX_SIGNAL as usize])
    -> (result: bool)
    ensures result == (forall|i: int| 0 <= i < MAX_SIGNAL as int ==> senders[i].is_none()),
{
    PendingSenders(senders).is_empty()
}

pub(crate) open spec fn signals_projection(entry: &ObjectEntry, result: Result<&SignalsObject>) -> bool {
    match entry {
        ObjectEntry::Signals(signals) => result == Ok(signals),
        _ => result == Err(BrokerError::InvalidRights),
    }
}

pub closed spec fn signals_projection_policy() -> bool {
    forall|entry: &ObjectEntry, result: Result<&SignalsObject>|
        #[trigger] ObjectEntry::as_signals.ensures((entry,), result)
            ==> signals_projection(entry, result)
}

pub proof fn prove_signals_projection()
    ensures signals_projection_policy(),
{
}

}
