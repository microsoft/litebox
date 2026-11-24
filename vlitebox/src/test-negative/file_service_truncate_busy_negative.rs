// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately loses Busy through the original two-stage truncate conversion.

use litebox_broker_core::fs::errors::StorageError;
use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub fn reject_truncate_busy_as_io() -> (result: FileError)
    ensures result == FileError::Io,
{
    vlitebox::filesystem_errors_proof::check_storage_to_guest_truncate_error(StorageError::Busy)
}

}

fn main() {}
