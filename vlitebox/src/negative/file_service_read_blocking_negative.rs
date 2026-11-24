// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately misclassifies the read helper's WouldBlock compatibility result.

use litebox_broker_core::fs::errors::ReadError;
use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub fn reject_read_blocking_as_access_denied() -> (result: FileError)
    ensures result == FileError::AccessNotAllowed,
{
    vlitebox::filesystem_errors_proof::check_file_read_error(ReadError::WouldBlock)
}

}

fn main() {}
