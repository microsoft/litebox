// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately claims the failed second read rolls back first-byte progress.

use litebox_broker_protocol::fs::DirectoryPayloadError;
use vstd::prelude::*;

verus! {

pub fn reject_directory_pair_rollback()
    -> (result: (usize, Result<(u8, u8), DirectoryPayloadError>))
    ensures result.0 == 0,
{
    let payload = [7u8];

    vlitebox::directory_decoder_proof::check_directory_pair(&payload)
}

}

fn main() {}
