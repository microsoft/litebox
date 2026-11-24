// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Representation only: two unsigned 64-bit fields, high serial and low tag.
//! This does not assert serial freshness, tag authenticity, or ID provenance.
//! Also review the original protocol type and its three accessor contracts.

use litebox_broker_protocol::shared_futex::SharedMemoryId;
use vstd::prelude::*;

verus! {

pub open spec fn shared_memory_id_encodes(id: SharedMemoryId, serial: u64, tag: u64) -> bool {
    &&& id.0 as int / 0x1_0000_0000_0000_0000int == serial as int
    &&& id.0 as int % 0x1_0000_0000_0000_0000int == tag as int
}

}
