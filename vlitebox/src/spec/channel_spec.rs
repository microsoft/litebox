// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read with native `ChannelState` and its six method annotations,
//! `litebox_broker_core/src/channel_spec.rs`, and the type-only opaque Weak
//! registration in `vlitebox-thirdparty/src/opaque/alloc.rs`.
//!
//! Proves scalar queries, saturating room, arithmetic under explicit
//! no-overflow/underflow conditions, and exact non-counter/shutdown framing.
//! No invariant equates the count to queued data or bounds it by capacity.
//! Locking, waiter liveness/wakeup, resource quotas and transfers are unproved.
//! The separate default-wakeup guarantee covers only an initially empty list,
//! not extraction of registered waiters or delivery.

use vstd::prelude::*;

verus! {

pub open spec fn channel_accounting_policy<Q, W>() -> bool {
    litebox_broker_core::channel::channel_accounting_policy::<Q, W>()
}

pub open spec fn default_wakeup_policy<W>() -> bool {
    litebox_broker_core::channel::empty_wakeup_policy::<W>()
}

}
