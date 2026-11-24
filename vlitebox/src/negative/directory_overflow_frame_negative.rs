// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately claims rejected extraction resets the original offset.

use litebox_broker_protocol::fs::DirectoryPayloadError;
use vstd::prelude::*;

verus! {

pub fn reject_directory_overflow_reset(payload: &[u8])
    -> (result: (usize, Result<&[u8], DirectoryPayloadError>))
    ensures result.0 == 0,
{
    vlitebox::directory_decoder_proof::check_directory_extraction(payload, usize::MAX, 1)
}

}

fn main() {}
