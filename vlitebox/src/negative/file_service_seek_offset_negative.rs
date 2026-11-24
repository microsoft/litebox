// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately loses the invalid-offset classification.

use litebox_broker_core::fs::errors::SeekError;
use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub fn reject_seek_invalid_offset_as_io() -> (result: FileError)
    ensures result == FileError::Io,
{
    vlitebox::filesystem_errors_proof::check_file_seek_error(SeekError::InvalidOffset)
}

}

fn main() {}
