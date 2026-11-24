// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately accepts an unaligned word: verification must fail.

use litebox_broker_protocol::shared_futex::{SharedFutexKey, SharedMemoryId};
use vstd::prelude::*;

verus! {

pub fn reject_unaligned_word_acceptance(memory: SharedMemoryId) -> (accepted: bool)
    ensures accepted,
{
    litebox_broker_core::verification::check_key_validation(
        SharedFutexKey { memory, offset: 1 },
        1,
    )
}

}

fn main() {}
