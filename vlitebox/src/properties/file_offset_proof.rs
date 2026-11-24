// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Actual calls to the original optional-offset guard.

use crate::file_offset_spec::{file_offset_outcome, file_offset_policy};
use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub proof fn original_file_offset_guard_has_exact_outcomes()
    ensures file_offset_policy(),
{
    litebox_broker_core::fs::prove_file_offset_validation();
}

pub fn check_file_offset(offset: Option<u64>, length: usize)
    -> (result: Result<Option<usize>, FileError>)
    ensures file_offset_outcome(offset, length, result),
{
    litebox_broker_core::fs::check_file_offset(offset, length)
}

pub fn check_implicit_file_offset(length: usize)
    -> (result: Result<Option<usize>, FileError>)
    ensures result == Ok(None),
{
    check_file_offset(None, length)
}

pub fn check_last_addressable_file_range(length: usize)
    -> (result: Result<Option<usize>, FileError>)
    ensures result == Ok(Some((usize::MAX - length) as usize)),
{
    check_file_offset(Some((usize::MAX - length) as u64), length)
}

pub fn check_file_offset_addition_overflow(length: usize)
    -> (result: Result<Option<usize>, FileError>)
    requires length > 0,
    ensures result == Err(FileError::InvalidOffset),
{
    check_file_offset(Some(usize::MAX as u64), length)
}

}
