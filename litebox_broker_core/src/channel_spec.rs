// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Must-read semantics for original scalar channel-state operations.
// Included in the original module to preserve private-field visibility.
// Arithmetic callers must prove no overflow/underflow; there is deliberately
// no assumed relation between the counter, capacity, and actual queued data.
// Locking, waiter lifetime/wakeup, and data-transfer correctness are unproved.
// FnDef reflection establishes sufficient call domains, not their necessity.

use vstd::prelude::*;

verus! {

pub(crate) closed spec fn channel_count<Q, W>(state: &ChannelState<Q, W>) -> usize {
    state.queued
}

pub(crate) closed spec fn channel_capacity<Q, W>(state: &ChannelState<Q, W>) -> usize {
    state.capacity
}

pub(crate) closed spec fn channel_is_shut<Q, W>(state: &ChannelState<Q, W>) -> bool {
    state.shut
}

pub(crate) closed spec fn same_count_frame<Q, W>(
    prev: ChannelState<Q, W>,
    cur: ChannelState<Q, W>,
) -> bool {
    &&& cur.queue == prev.queue
    &&& cur.capacity == prev.capacity
    &&& cur.shut == prev.shut
    &&& cur.waiters == prev.waiters
}

pub(crate) closed spec fn shut_state<Q, W>(
    prev: ChannelState<Q, W>,
    cur: ChannelState<Q, W>,
) -> bool {
    &&& cur.shut
    &&& cur.queue == prev.queue
    &&& cur.queued == prev.queued
    &&& cur.capacity == prev.capacity
    &&& cur.waiters == prev.waiters
}

pub closed spec fn empty_wakeups<W>(wakeups: Wakeups<W>) -> bool {
    wakeups.0@.len() == 0
}

pub closed spec fn channel_accounting_policy<Q, W>() -> bool {
    &&& (forall|prev: ChannelState<Q, W>, result: usize|
        #[trigger] ChannelState::queued.ensures((&prev,), result)
            ==> result == channel_count(&prev))
    &&& (forall|prev: ChannelState<Q, W>, result: usize|
        #[trigger] ChannelState::room.ensures((&prev,), result)
            ==> result == if channel_count(&prev) <= channel_capacity(&prev) {
                channel_capacity(&prev) - channel_count(&prev)
            } else {
                0
            })
    &&& (forall|prev: ChannelState<Q, W>, result: bool|
        #[trigger] ChannelState::is_shut.ensures((&prev,), result)
            ==> result == channel_is_shut(&prev))
    &&& (forall|prev: ChannelState<Q, W>, bytes: usize|
        bytes <= usize::MAX - channel_count(&prev)
            ==> #[trigger] apply_channel_add.requires((prev, bytes)))
    &&& (forall|prev: ChannelState<Q, W>, cur: ChannelState<Q, W>, bytes: usize|
        #[trigger] channel_add_transition(prev, cur, bytes)
            ==> {
                &&& channel_count(&cur) == channel_count(&prev) + bytes
                &&& same_count_frame(prev, cur)
            })
    &&& (forall|prev: ChannelState<Q, W>, bytes: usize|
        bytes <= channel_count(&prev)
            ==> #[trigger] apply_channel_remove.requires((prev, bytes)))
    &&& (forall|prev: ChannelState<Q, W>, cur: ChannelState<Q, W>, bytes: usize|
        #[trigger] channel_remove_transition(prev, cur, bytes)
            ==> {
                &&& channel_count(&cur) == channel_count(&prev) - bytes
                &&& same_count_frame(prev, cur)
            })
    &&& (forall|prev: ChannelState<Q, W>, cur: ChannelState<Q, W>|
        #[trigger] channel_shut_transition(prev, cur)
            ==> shut_state(prev, cur))
}

pub proof fn prove_channel_accounting<Q, W>()
    ensures channel_accounting_policy::<Q, W>(),
{
}

pub closed spec fn empty_wakeup_policy<W>() -> bool {
    forall|wakeups: Wakeups<W>|
        #[trigger] Wakeups::default.ensures((), wakeups) ==> empty_wakeups(wakeups)
}

pub proof fn prove_empty_wakeups<W>()
    ensures empty_wakeup_policy::<W>(),
{
}

pub fn check_empty_wakeups() -> (count: usize)
    ensures count == 0,
{
    let wakeups = Wakeups::<()>::default();

    wakeups.0.len()
}

// Verification-only callers exercise the original bodies' exported contracts.
pub(crate) fn check_accounting_round_trip<Q, W>(state: &mut ChannelState<Q, W>, bytes: usize)
    requires bytes <= usize::MAX - channel_count(old(state)),
    ensures *final(state) == *old(state),
{
    state.add(bytes);
    state.remove(bytes);
}

pub fn check_saturated_room(capacity: usize, queued: usize) -> (room: usize)
    ensures room == if queued <= capacity { capacity - queued } else { 0 },
{
    let state = ChannelState::<(), ()> {
        queue: (),
        queued,
        capacity,
        shut: false,
        waiters: Vec::new(),
    };

    state.room()
}


pub(crate) fn apply_channel_add<Q, W>(
    prev: ChannelState<Q, W>,
    bytes: usize,
) -> (cur: ChannelState<Q, W>)
    requires bytes <= usize::MAX - channel_count(&prev),
    ensures
        channel_count(&cur) == channel_count(&prev) + bytes,
        same_count_frame(prev, cur),
{
    let mut cur = prev;

    cur.add(bytes);

    cur
}


pub(crate) fn apply_channel_remove<Q, W>(
    prev: ChannelState<Q, W>,
    bytes: usize,
) -> (cur: ChannelState<Q, W>)
    requires bytes <= channel_count(&prev),
    ensures
        channel_count(&cur) == channel_count(&prev) - bytes,
        same_count_frame(prev, cur),
{
    let mut cur = prev;

    cur.remove(bytes);

    cur
}


pub(crate) fn apply_channel_shut<Q, W>(
    prev: ChannelState<Q, W>,
) -> (cur: ChannelState<Q, W>)
    ensures shut_state(prev, cur),
{
    let mut cur = prev;

    cur.shut();

    cur
}


pub(crate) closed spec fn channel_add_transition<Q, W>(
    prev: ChannelState<Q, W>,
    cur: ChannelState<Q, W>,
    bytes: usize,
) -> bool {
    &&& bytes <= usize::MAX - channel_count(&prev)
    &&& apply_channel_add.ensures((prev, bytes), cur)
}


pub(crate) closed spec fn channel_remove_transition<Q, W>(
    prev: ChannelState<Q, W>,
    cur: ChannelState<Q, W>,
    bytes: usize,
) -> bool {
    &&& bytes <= channel_count(&prev)
    &&& apply_channel_remove.ensures((prev, bytes), cur)
}


pub(crate) closed spec fn channel_shut_transition<Q, W>(
    prev: ChannelState<Q, W>,
    cur: ChannelState<Q, W>,
) -> bool {
    apply_channel_shut.ensures((prev,), cur)
}

}
