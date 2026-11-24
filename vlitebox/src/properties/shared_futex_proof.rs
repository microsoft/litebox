// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Verify the original protocol and broker crates as well as this target.
//! No custom assumptions are used.

use crate::shared_futex_spec::shared_futex_leaf_policy;
use vstd::prelude::*;

verus! {

pub proof fn shared_futex_validation_and_waiter_projection_are_exact()
    ensures shared_futex_leaf_policy(),
{
    litebox_broker_core::verification::prove_shared_futex_leaves();
}

}
