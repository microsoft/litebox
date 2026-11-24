// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately replaces an existing malformed payload error with TooLarge.

use litebox_broker_protocol::fs::{DirectoryPayloadError, DirectoryTransferError};
use vstd::prelude::*;

verus! {

pub fn reject_directory_payload_error() -> (cur: DirectoryPayloadError)
    ensures cur == DirectoryPayloadError::TooLarge,
{
    vlitebox::directory_decoder_proof::check_directory_error(
        DirectoryTransferError::Payload(DirectoryPayloadError::Malformed),
    )
}

}

fn main() {}
