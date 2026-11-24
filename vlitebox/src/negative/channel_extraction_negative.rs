// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately false: extraction leaves a stored waiter.
//! Uses the explicit, unproved third-party std mem::take contract.

use std::sync::Weak;
use vstd::prelude::*;

verus! {

pub fn reject_retained_waiters(waiters: Vec<Weak<()>>) -> (remaining: usize)
    ensures remaining > 0,
{
    let (_, remaining) = litebox_broker_core::verification::check_waiter_extraction(waiters);

    remaining
}

}

fn main() {}
