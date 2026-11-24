// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately misclassifies busy storage as a retryable read.

use litebox_broker_core::fs::errors::{ReadError, StorageError};
use vstd::prelude::*;

verus! {

pub fn reject_busy_storage_as_would_block() -> (error: ReadError)
    ensures error == ReadError::WouldBlock,
{
    StorageError::Busy.into()
}

}

fn main() {}
