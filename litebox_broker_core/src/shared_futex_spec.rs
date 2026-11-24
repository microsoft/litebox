// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Original futex input-shape validation and waiter kind projection.
//! No ID authentication, memory provenance, queue, or wake guarantee is assumed.

use super::{FutexWaiterObject, validate_key_and_bitset};
use crate::object::ObjectEntry;
use crate::{BrokerError, Result};
use litebox_broker_protocol::shared_futex::{FUTEX_WORD_SIZE, SharedFutexKey};
use vstd::prelude::*;

verus! {

pub open spec fn well_formed_futex_request(key: SharedFutexKey, bitset: u32) -> bool {
    &&& key.offset % FUTEX_WORD_SIZE == 0
    &&& bitset != 0
}

pub(crate) open spec fn key_validation(key: SharedFutexKey, bitset: u32, result: Result<()>) -> bool {
    if well_formed_futex_request(key, bitset) {
        result == Ok(())
    } else {
        result == Err(BrokerError::UnsupportedOperation)
    }
}

pub(crate) open spec fn waiter_projection(
    entry: &ObjectEntry,
    result: Result<&FutexWaiterObject>,
) -> bool {
    match entry {
        ObjectEntry::FutexWaiter(waiter) => result == Ok(waiter),
        _ => result == Err(BrokerError::InvalidRights),
    }
}

pub closed spec fn shared_futex_leaf_policy() -> bool {
    &&& (forall|key: SharedFutexKey, bitset: u32, result: Result<()>|
        #[trigger] validate_key_and_bitset.ensures((key, bitset), result)
            ==> key_validation(key, bitset, result))
    &&& (forall|entry: &ObjectEntry, result: Result<&FutexWaiterObject>|
        #[trigger] ObjectEntry::as_futex_waiter.ensures((entry,), result)
            ==> waiter_projection(entry, result))
}

pub proof fn prove_shared_futex_leaves()
    ensures shared_futex_leaf_policy(),
{
}

// Verification-only executable caller, also used by the negative examples.
pub fn check_key_validation(key: SharedFutexKey, bitset: u32) -> (accepted: bool)
    ensures accepted == well_formed_futex_request(key, bitset),
{
    validate_key_and_bitset(key, bitset).is_ok()
}

}
