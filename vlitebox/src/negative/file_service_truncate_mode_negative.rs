// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately conflates a path-only descriptor with one not opened for writing.

use litebox_broker_core::fs::errors::TruncateError;
use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub fn reject_path_only_as_not_for_writing() -> (result: FileError)
    ensures result == FileError::NotForWriting,
{
    vlitebox::filesystem_errors_proof::check_file_truncate_error(TruncateError::NotOpenForWriting)
}

}

fn main() {}
