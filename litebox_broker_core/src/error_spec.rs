// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Exact error-category helpers, not operation success or authorization.
//! Derived formatting and fallible memory operations remain outside this slice.

use super::BrokerError;
use litebox_broker_protocol::error::ErrorCode;
use litebox_platform::buffer::Fault;
use vstd::prelude::*;
use vstd::std_specs::convert::FromSpecImpl;

verus! {

pub open spec fn would_block_error(nonblocking: bool, error: BrokerError) -> bool {
    if nonblocking {
        error == BrokerError::NonBlockingWouldBlock
    } else {
        error == BrokerError::WouldBlock
    }
}

pub open spec fn protocol_error_code(error: BrokerError) -> ErrorCode {
    match error {
        BrokerError::PolicyDenied => ErrorCode::PolicyDenied,
        BrokerError::UnknownObject => ErrorCode::UnknownObject,
        BrokerError::InvalidRights => ErrorCode::InvalidRights,
        BrokerError::ResourceExhausted => ErrorCode::ResourceExhausted,
        BrokerError::BrokerCoreAlreadyExists | BrokerError::Internal => ErrorCode::Internal,
        BrokerError::WouldBlock => ErrorCode::WouldBlock,
        BrokerError::NonBlockingWouldBlock => ErrorCode::NonBlockingWouldBlock,
        BrokerError::PeerClosed => ErrorCode::PeerClosed,
        BrokerError::OutOfMemory => ErrorCode::OutOfMemory,
        BrokerError::UnsupportedOperation => ErrorCode::UnsupportedOperation,
    }
}

pub open spec fn error_code_matches(error: BrokerError, code: ErrorCode) -> bool {
    code == protocol_error_code(error)
}

// This law is an obligation checked against the original executable From impl.
impl FromSpecImpl<BrokerError> for ErrorCode {
    open spec fn obeys_from_spec() -> bool {
        true
    }

    open spec fn from_spec(error: BrokerError) -> Self {
        protocol_error_code(error)
    }
}

impl FromSpecImpl<Fault> for BrokerError {
    open spec fn obeys_from_spec() -> bool {
        true
    }

    open spec fn from_spec(_fault: Fault) -> Self {
        BrokerError::Internal
    }
}

pub closed spec fn error_category_policy() -> bool {
    &&& (forall|nonblocking: bool, error: BrokerError|
        #[trigger] BrokerError::would_block.ensures((nonblocking,), error)
            ==> would_block_error(nonblocking, error))
    &&& (forall|error: BrokerError, code: ErrorCode|
        #[trigger] <ErrorCode as From<BrokerError>>::from.ensures((error,), code)
            ==> error_code_matches(error, code))
    &&& (forall|fault: Fault, error: BrokerError|
        #[trigger] <BrokerError as From<Fault>>::from.ensures((fault,), error)
            ==> error == BrokerError::Internal)
}

pub proof fn prove_error_categories()
    ensures error_category_policy(),
{
}

// Verification-only executable callers for the private helper and std Into.
pub fn check_blocking_error(nonblocking: bool) -> (error: BrokerError)
    ensures would_block_error(nonblocking, error),
{
    BrokerError::would_block(nonblocking)
}

pub fn check_error_into(error: BrokerError) -> (code: ErrorCode)
    ensures error_code_matches(error, code),
{
    error.into()
}

pub fn check_fault_translation() -> (error: BrokerError)
    ensures error == BrokerError::Internal,
{
    BrokerError::from(Fault)
}

}
