// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately gives a blocking object the nonblocking error category.

use litebox_broker_core::BrokerError;
use vstd::prelude::*;

verus! {

pub fn reject_blocking_as_nonblocking() -> (error: BrokerError)
    ensures error == BrokerError::NonBlockingWouldBlock,
{
    litebox_broker_core::error::verification::check_blocking_error(false)
}

}

fn main() {}
