// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read with the original `transfer::bounce_buffer` annotation. This is a
//! normal-return contract, not allocation success, absence of allocator aborts,
//! quota enforcement, or correctness of transfers involving runner memory.

use alloc::vec::Vec;
use litebox_broker_core::{BrokerError, Result, transfer::bounce_buffer};
use vstd::prelude::*;

verus! {

pub open spec fn staging_buffer_result(length: usize, result: Result<Vec<u8>>) -> bool {
    match result {
        Ok(buffer) => buffer@.len() == length
            && forall|index: int| 0 <= index < length ==> buffer@[index] == 0u8,
        Err(error) => error == BrokerError::OutOfMemory,
    }
}

pub open spec fn staging_buffer_policy() -> bool {
    forall|length: usize, result: Result<Vec<u8>>|
        #[trigger] bounce_buffer.ensures((length,), result)
            ==> staging_buffer_result(length, result)
}

}
