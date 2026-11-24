// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately misclassifies a shared-mapping storage fault as exhaustion.

use litebox_broker_core::fs::errors::{MapSharedError, StorageError};
use vstd::prelude::*;

verus! {

pub fn reject_mapping_fault_as_exhaustion() -> (result: MapSharedError)
    ensures result == MapSharedError::NoMemory,
{
    StorageError::Fault.into()
}

}

fn main() {}
