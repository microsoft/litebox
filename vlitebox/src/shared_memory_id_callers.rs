// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Verification-only executable caller regression for the original methods.

use crate::shared_memory_id_proof::{
    shared_memory_id_accessors_recover_fields, shared_memory_id_construction_is_lossless,
};
use litebox_broker_protocol::shared_futex::SharedMemoryId;
use vstd::prelude::*;

verus! {

fn check_actual_id_round_trip(serial: u64, tag: u64) -> (result: (u64, u64))
    ensures result == (serial, tag),
{
    let id = SharedMemoryId::new(serial, tag);
    let observed_serial = id.serial();
    let observed_tag = id.tag();

    proof {
        shared_memory_id_construction_is_lossless(serial, tag, id);
        shared_memory_id_accessors_recover_fields(id, serial, tag, observed_serial, observed_tag);
    }

    (observed_serial, observed_tag)
}

}
