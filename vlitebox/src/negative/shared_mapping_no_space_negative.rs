// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately loses the shared-mapping out-of-memory distinction.

use litebox_broker_core::fs::errors::{MapSharedError, StorageError};
use vstd::prelude::*;

verus! {

pub fn reject_mapping_exhaustion_as_io() -> (result: MapSharedError)
    ensures result == MapSharedError::Io,
{
    StorageError::NoSpace.into()
}

}

fn main() {}
