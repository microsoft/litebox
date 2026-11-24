// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read with the original DirectoryPayloadDecoder::take and the complete
//! directory_take_outcome/decoder_take relations in the protocol crate.
//! Successful extraction returns exactly the requested payload subrange and
//! advances only the offset; overflow/out-of-bounds leave both fields unchanged.
//! No custom assumptions. Full wire decoding, directory semantics, external
//! concurrent memory snapshots, ownership, and authorization remain unverified.

use vstd::prelude::*;

verus! {

pub open spec fn directory_decoder_policy() -> bool {
    litebox_broker_protocol::fs::directory_decoder_policy()
}

}
