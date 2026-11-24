// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! UNPROVED standard-library contract, pending developer review.
//! Normal-return value movement and Default delegation only; no allocation,
//! abort freedom, broker policy, waiter liveness, or wakeup delivery guarantee.

use vstd::prelude::*;

verus! {

pub assume_specification<T: Default>[core::mem::take](destination: &mut T) -> (value: T)
    ensures
        value == *old(destination),
        <T as Default>::default.ensures((), *final(destination)),
;

}
