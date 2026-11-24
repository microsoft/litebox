// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! CONDITIONAL implementation proof: requires the UNPROVED std mem::take
//! contract in `vlitebox-thirdparty/src/mem_spec.rs`. Also must read the opaque
//! Weak registration there in `alloc_spec.rs`, the original ChannelState::wake
//! annotation, and `litebox_broker_core/src/channel_spec.rs`.
//!
//! The returned list is exactly the previous list of logical Weak values; the
//! stored list becomes empty, preserving queue/count/capacity/shutdown fields.
//! No physical identity, live target, deduplication, lock or delivery claim.

use vstd::prelude::*;

verus! {

pub open spec fn channel_waiter_extraction_policy<Q, W>() -> bool {
    litebox_broker_core::verification::waiter_extraction_policy::<Q, W>()
}

}
