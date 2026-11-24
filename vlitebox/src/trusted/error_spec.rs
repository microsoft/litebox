// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read with both original enum declarations, the two original helper
//! annotations, and `litebox_broker_core/src/error_spec.rs`. Internal and
//! BrokerCoreAlreadyExists deliberately share the Internal protocol category.
//! This says nothing about whether an operation should have failed.

use litebox_broker_core::BrokerError;
use litebox_broker_protocol::error::ErrorCode;
use vstd::prelude::*;

verus! {

pub open spec fn expected_protocol_error(error: BrokerError) -> ErrorCode {
    litebox_broker_core::verification::protocol_error_code(error)
}

pub open spec fn error_category_policy() -> bool {
    litebox_broker_core::verification::error_category_policy()
}

}
