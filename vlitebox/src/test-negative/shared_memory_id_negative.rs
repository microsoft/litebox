// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately swapped serial/tag fields: verification must fail.

use litebox_broker_protocol::shared_futex::SharedMemoryId;
use vstd::prelude::*;

verus! {

pub fn reject_swapped_id_fields(serial: u64, tag: u64) -> (id: SharedMemoryId)
    ensures vlitebox::spec::shared_memory_id_spec::shared_memory_id_encodes(id, tag, serial),
{
    let id = SharedMemoryId::new(serial, tag);
    proof {
        vlitebox::shared_memory_id_proof::shared_memory_id_construction_is_lossless(serial, tag, id);
    }

    id
}

}

fn main() {}
