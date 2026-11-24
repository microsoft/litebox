// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! CONDITIONAL on the explicit, unproved third-party std mem::take contract.
//! Check the original core body as well as this composition target.

use crate::channel_waiters_spec::channel_waiter_extraction_policy;
use vstd::prelude::*;

verus! {

pub proof fn channel_wake_extracts_the_registered_values<Q, W>()
    ensures channel_waiter_extraction_policy::<Q, W>(),
{
    litebox_broker_core::channel::prove_waiter_extraction::<Q, W>();
}

}
