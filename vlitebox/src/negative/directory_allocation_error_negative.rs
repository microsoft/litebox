// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately misclassifies allocation failure as malformed payload.

use litebox_broker_protocol::fs::{DirectoryPayloadError, DirectoryTransferError};
use vstd::prelude::*;

verus! {

pub fn reject_directory_allocation_error() -> (cur: DirectoryPayloadError)
    ensures cur == DirectoryPayloadError::Malformed,
{
    vlitebox::directory_decoder_proof::check_directory_error(DirectoryTransferError::OutOfMemory)
}

}

fn main() {}
