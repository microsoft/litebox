// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Original file-kind projection and request-offset guard, not file-system
//! policy, actual file-position bounds or native authority.
//! The file payload remains opaque and explicitly in progress in object_spec.

use super::{File, FileResult};
use crate::object::ObjectEntry;
use crate::{BrokerError, Result};
use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub open spec fn file_offset_outcome(
    offset: Option<u64>,
    length: usize,
    result: FileResult<Option<usize>>,
) -> bool {
    match offset {
        None => result == Ok(None),
        Some(offset) => {
            if offset as int + length as int <= usize::MAX {
                result == Ok(Some(offset as usize))
            } else {
                result == Err(FileError::InvalidOffset)
            }
        },
    }
}

pub closed spec fn file_offset_policy() -> bool {
    forall|offset: Option<u64>, length: usize, result: FileResult<Option<usize>>|
        #[trigger] super::checked_offset.ensures((offset, length), result)
            ==> file_offset_outcome(offset, length, result)
}

pub proof fn prove_file_offset_validation()
    ensures file_offset_policy(),
{
}

pub fn check_file_offset(offset: Option<u64>, length: usize)
    -> (result: FileResult<Option<usize>>)
    ensures file_offset_outcome(offset, length, result),
{
    super::checked_offset(offset, length)
}

pub(crate) open spec fn file_projection(entry: &ObjectEntry, result: Result<&File>) -> bool {
    match entry {
        ObjectEntry::File(file) => result == Ok(file),
        _ => result == Err(BrokerError::InvalidRights),
    }
}

pub closed spec fn file_projection_policy() -> bool {
    forall|entry: &ObjectEntry, result: Result<&File>|
        #[trigger] ObjectEntry::as_file.ensures((entry,), result) ==> file_projection(entry, result)
}

pub proof fn prove_file_projection()
    ensures file_projection_policy(),
{
}

}
