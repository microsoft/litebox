// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately conflates a path-only descriptor with a non-seekable object.

use litebox_broker_core::fs::errors::SeekError;
use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub fn reject_seek_path_only_as_non_seekable() -> (result: FileError)
    ensures result == FileError::NonSeekable,
{
    vlitebox::filesystem_errors_proof::check_file_seek_error(SeekError::NotOpenForSeeking)
}

}

fn main() {}
