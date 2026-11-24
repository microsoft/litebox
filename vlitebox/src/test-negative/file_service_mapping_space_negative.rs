// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately loses NoSpace through the original two-stage mapping conversion.

use litebox_broker_core::fs::errors::StorageError;
use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub fn reject_mapping_space_as_io() -> (result: FileError)
    ensures result == FileError::Io,
{
    vlitebox::filesystem_errors_proof::check_storage_to_guest_mapping_error(StorageError::NoSpace)
}

}

fn main() {}
