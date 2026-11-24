// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately turns a buffer fault into an unknown-object error.

use litebox_broker_core::BrokerError;
use vstd::prelude::*;

verus! {

pub fn reject_fault_as_unknown_object() -> (error: BrokerError)
    ensures error == BrokerError::UnknownObject,
{
    litebox_broker_core::verification::check_fault_translation()
}

}

fn main() {}
