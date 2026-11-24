// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Verify the original protocol implementation as well as this target.
//! These are encoding guarantees, not uniqueness of broker-issued IDs.

use crate::shared_memory_id_spec::shared_memory_id_encodes;
use litebox_broker_protocol::shared_futex::SharedMemoryId;
use vstd::prelude::*;

verus! {

pub proof fn shared_memory_id_construction_is_lossless(serial: u64, tag: u64, id: SharedMemoryId)
    requires SharedMemoryId::new.ensures((serial, tag), id),
    ensures shared_memory_id_encodes(id, serial, tag),
{
    let bits = id.0;
    assert(bits == (((serial as u128) << 64) | tag as u128));

    assert(bits == (((serial as u128) << 64) | tag as u128)
        ==> bits / 0x1_0000_0000_0000_0000u128 == serial as u128) by(bit_vector);
    assert(bits == (((serial as u128) << 64) | tag as u128)
        ==> bits % 0x1_0000_0000_0000_0000u128 == tag as u128) by(bit_vector);
}

pub proof fn shared_memory_id_accessors_recover_fields(
    id: SharedMemoryId,
    serial: u64,
    tag: u64,
    observed_serial: u64,
    observed_tag: u64,
)
    requires
        shared_memory_id_encodes(id, serial, tag),
        SharedMemoryId::serial.ensures((id,), observed_serial),
        SharedMemoryId::tag.ensures((id,), observed_tag),
    ensures observed_serial == serial, observed_tag == tag,
{
    let bits = id.0;

    assert((bits >> 64) as u64 == (bits / 0x1_0000_0000_0000_0000u128) as u64) by(bit_vector);
    assert((bits & (u64::MAX as u128)) as u64
        == (bits % 0x1_0000_0000_0000_0000u128) as u64) by(bit_vector);
}

pub proof fn shared_memory_id_packing_is_injective(
    first_serial: u64,
    first_tag: u64,
    second_serial: u64,
    second_tag: u64,
    id: SharedMemoryId,
)
    requires
        SharedMemoryId::new.ensures((first_serial, first_tag), id),
        SharedMemoryId::new.ensures((second_serial, second_tag), id),
    ensures first_serial == second_serial, first_tag == second_tag,
{
    shared_memory_id_construction_is_lossless(first_serial, first_tag, id);
    shared_memory_id_construction_is_lossless(second_serial, second_tag, id);
}

}
