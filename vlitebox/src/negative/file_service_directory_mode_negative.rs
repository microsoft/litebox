// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately conflates a path-only directory descriptor with a read-access error.

use litebox_broker_core::fs::errors::ReadDirError;
use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub fn reject_directory_path_only_as_not_for_reading() -> (result: FileError)
    ensures result == FileError::NotForReading,
{
    vlitebox::filesystem_errors_proof::check_file_read_directory_error(ReadDirError::NotOpenForReading)
}

}

fn main() {}
