// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately reverses the not-a-directory classification.

use litebox_broker_core::fs::errors::ReadDirError;
use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub fn reject_not_directory_as_is_directory() -> (result: FileError)
    ensures result == FileError::IsDirectory,
{
    vlitebox::filesystem_errors_proof::check_file_read_directory_error(ReadDirError::NotADirectory)
}

}

fn main() {}
