// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately accepts an empty selection mask: verification must fail.

use litebox_broker_protocol::shared_futex::SharedFutexKey;
use vstd::prelude::*;

verus! {

pub fn reject_empty_bitset_acceptance(key: SharedFutexKey) -> (accepted: bool)
    ensures accepted,
{
    litebox_broker_core::verification::check_key_validation(key, 0)
}

}

fn main() {}
