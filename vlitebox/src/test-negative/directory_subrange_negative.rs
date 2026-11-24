// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately claims extraction ignores its offset and returns the first byte.

use litebox_broker_protocol::fs::DirectoryPayloadError;
use vstd::prelude::*;

verus! {

pub fn reject_directory_wrong_subrange() -> (result: Result<u8, DirectoryPayloadError>)
    ensures result == Ok(7),
{
    let payload = [7u8, 9u8];
    let (_, bytes) = vlitebox::directory_decoder_proof::check_directory_extraction(&payload, 1, 1);
    let bytes = bytes?;

    Ok(bytes[0])
}

}

fn main() {}
