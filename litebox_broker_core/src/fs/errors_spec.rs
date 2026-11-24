// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Must-read exact semantics for the original filesystem error conversions.
//! These are checked conversion laws, not assumptions about operation failure.
//! Derived implementations, filesystem effects and fault occurrence are unverified.

use super::{FileStatusError, ReadError, StorageError, TruncateError, WriteError};
use crate::BrokerError;
use litebox_platform::buffer::Fault;
use vstd::prelude::*;
use vstd::std_specs::convert::FromSpecImpl;

verus! {

pub open spec fn storage_read_error(error: StorageError) -> ReadError {
    match error {
        StorageError::Fault => ReadError::Broker(BrokerError::Internal),
        StorageError::NoSpace | StorageError::Busy | StorageError::Io => ReadError::Io,
    }
}

pub open spec fn storage_write_error(error: StorageError) -> WriteError {
    match error {
        StorageError::NoSpace => WriteError::NoSpace,
        StorageError::Fault => WriteError::Broker(BrokerError::Internal),
        StorageError::Busy | StorageError::Io => WriteError::Io,
    }
}

pub open spec fn storage_truncate_error(error: StorageError) -> TruncateError {
    match error {
        StorageError::NoSpace => TruncateError::NoSpace,
        StorageError::Busy => TruncateError::Busy,
        StorageError::Fault | StorageError::Io => TruncateError::Io,
    }
}

// Each enabled FromSpecImpl law is checked against its original From body.
impl FromSpecImpl<Fault> for ReadError {
    open spec fn obeys_from_spec() -> bool { true }
    open spec fn from_spec(_fault: Fault) -> Self {
        ReadError::Broker(BrokerError::Internal)
    }
}

impl FromSpecImpl<Fault> for WriteError {
    open spec fn obeys_from_spec() -> bool { true }
    open spec fn from_spec(_fault: Fault) -> Self {
        WriteError::Broker(BrokerError::Internal)
    }
}

impl FromSpecImpl<Fault> for StorageError {
    open spec fn obeys_from_spec() -> bool { true }
    open spec fn from_spec(_fault: Fault) -> Self { StorageError::Fault }
}

impl FromSpecImpl<StorageError> for ReadError {
    open spec fn obeys_from_spec() -> bool { true }
    open spec fn from_spec(error: StorageError) -> Self { storage_read_error(error) }
}

impl FromSpecImpl<StorageError> for WriteError {
    open spec fn obeys_from_spec() -> bool { true }
    open spec fn from_spec(error: StorageError) -> Self { storage_write_error(error) }
}

impl FromSpecImpl<StorageError> for TruncateError {
    open spec fn obeys_from_spec() -> bool { true }
    open spec fn from_spec(error: StorageError) -> Self { storage_truncate_error(error) }
}

impl FromSpecImpl<StorageError> for FileStatusError {
    open spec fn obeys_from_spec() -> bool { true }
    open spec fn from_spec(_error: StorageError) -> Self { FileStatusError::Io }
}

pub closed spec fn filesystem_error_policy() -> bool {
    &&& (forall|fault: Fault, error: StorageError|
        #[trigger] <StorageError as From<Fault>>::from.ensures((fault,), error)
            ==> error == StorageError::Fault)
    &&& (forall|fault: Fault, error: ReadError|
        #[trigger] <ReadError as From<Fault>>::from.ensures((fault,), error)
            ==> error == ReadError::Broker(BrokerError::Internal))
    &&& (forall|fault: Fault, error: WriteError|
        #[trigger] <WriteError as From<Fault>>::from.ensures((fault,), error)
            ==> error == WriteError::Broker(BrokerError::Internal))
    &&& (forall|source: StorageError, error: ReadError|
        #[trigger] <ReadError as From<StorageError>>::from.ensures((source,), error)
            ==> error == storage_read_error(source))
    &&& (forall|source: StorageError, error: WriteError|
        #[trigger] <WriteError as From<StorageError>>::from.ensures((source,), error)
            ==> error == storage_write_error(source))
    &&& (forall|source: StorageError, error: TruncateError|
        #[trigger] <TruncateError as From<StorageError>>::from.ensures((source,), error)
            ==> error == storage_truncate_error(source))
    &&& (forall|source: StorageError, error: FileStatusError|
        #[trigger] <FileStatusError as From<StorageError>>::from.ensures((source,), error)
            ==> error == FileStatusError::Io)
}

pub proof fn prove_filesystem_error_conversions()
    ensures filesystem_error_policy(),
{
}

// Actual std Into dispatch through the checked native conversions.
pub fn check_storage_into_read(error: StorageError) -> (result: ReadError)
    ensures result == storage_read_error(error),
{
    error.into()
}

pub fn check_fault_into_write() -> (result: WriteError)
    ensures result == WriteError::Broker(BrokerError::Internal),
{
    let storage: StorageError = Fault.into();

    storage.into()
}

}
