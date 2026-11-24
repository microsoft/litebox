// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately false: a successfully allocated staging byte is one, not zero.

use litebox_broker_core::{BrokerError, Result};
use vstd::prelude::*;

verus! {

pub fn reject_nonzero_staging_byte() -> (result: Result<Vec<u8>>)
    ensures match result {
        Ok(buffer) => buffer@.len() == 1 && buffer@[0] == 1u8,
        Err(error) => error == BrokerError::OutOfMemory,
    },
{
    litebox_broker_core::transfer::bounce_buffer(1)
}

}

fn main() {}
