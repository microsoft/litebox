// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately accepts an explicit byte range whose addition overflows.

use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub fn reject_overflowing_file_range() -> (result: Result<Option<usize>, FileError>)
    ensures result == Ok(Some(usize::MAX)),
{
    vlitebox::file_offset_proof::check_file_offset(Some(usize::MAX as u64), 1)
}

}

fn main() {}
