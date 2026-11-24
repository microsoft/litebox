// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately misclassifies a buffer fault as broker policy denial.

use litebox_broker_core::{
    BrokerError,
    fs::errors::{StorageError, WriteError},
};
use vstd::prelude::*;

verus! {

pub fn reject_storage_fault_as_policy_denial() -> (error: WriteError)
    ensures error == WriteError::Broker(BrokerError::PolicyDenied),
{
    StorageError::Fault.into()
}

}

fn main() {}
