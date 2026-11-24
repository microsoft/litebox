// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Deliberately confuses an unknown object with policy denial.

use litebox_broker_core::BrokerError;
use litebox_broker_protocol::error::ErrorCode;
use vstd::prelude::*;

verus! {

pub fn reject_unknown_as_policy_denial() -> (code: ErrorCode)
    ensures code == ErrorCode::PolicyDenied,
{
    ErrorCode::from(BrokerError::UnknownObject)
}

}

fn main() {}
