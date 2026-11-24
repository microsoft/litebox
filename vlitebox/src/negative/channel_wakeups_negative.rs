// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately false: the original wakeup default contains a waiter.

use vstd::prelude::*;

verus! {

pub fn reject_nonempty_default_wakeups() -> (count: usize)
    ensures count > 0,
{
    litebox_broker_core::channel::check_empty_wakeups()
}

}

fn main() {}
