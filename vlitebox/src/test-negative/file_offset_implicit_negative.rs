// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately treats an implicit offset as a rejected explicit byte range.

use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub fn reject_implicit_file_offset() -> (result: Result<Option<usize>, FileError>)
    ensures result == Err(FileError::InvalidOffset),
{
    vlitebox::file_offset_proof::check_file_offset(None, usize::MAX)
}

}

fn main() {}
