// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Original file-kind projection, request-offset guard and error translations, not file-system
//! policy, actual file-position bounds or native authority.
//! The file payload remains opaque and explicitly in progress in object_spec.

use super::{File, FileResult, MapSharedError, ReadError, WriteError};
use crate::object::ObjectEntry;
use crate::{BrokerError, Result};
use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub open spec fn file_read_error_value(error: ReadError) -> FileError {
    match error {
        ReadError::NotAFile => FileError::NotFile,
        ReadError::NotForReading => FileError::NotForReading,
        ReadError::ClosedFd | ReadError::Io | ReadError::WouldBlock | ReadError::Broker(_)
            => FileError::Io,
    }
}

pub open spec fn file_write_error_value(error: WriteError) -> FileError {
    match error {
        WriteError::NotAFile => FileError::NotFile,
        WriteError::NotForWriting => FileError::NotForWriting,
        WriteError::NoSpace => FileError::NoSpace,
        WriteError::ClosedFd | WriteError::Io | WriteError::WouldBlock | WriteError::Broker(_)
            => FileError::Io,
    }
}

pub open spec fn file_map_shared_error_value(error: MapSharedError) -> FileError {
    match error {
        MapSharedError::IsDirectory => FileError::IsDirectory,
        MapSharedError::NotForReading => FileError::NotForReading,
        MapSharedError::PathOnly => FileError::PathOnly,
        MapSharedError::Unsupported => FileError::NoSuchDevice,
        MapSharedError::NoMemory => FileError::NoSpace,
        MapSharedError::Io => FileError::Io,
    }
}

pub closed spec fn file_service_error_policy() -> bool {
    &&& forall|error: ReadError, result: FileError|
        #[trigger] super::file_read_error.ensures((error,), result)
            ==> result == file_read_error_value(error)
    &&& forall|error: WriteError, result: FileError|
        #[trigger] super::file_write_error.ensures((error,), result)
            ==> result == file_write_error_value(error)
    &&& forall|error: MapSharedError, result: FileError|
        #[trigger] super::file_map_shared_error.ensures((error,), result)
            ==> result == file_map_shared_error_value(error)
}

pub proof fn prove_file_service_error_translations()
    ensures file_service_error_policy(),
{
}

pub fn check_file_read_error(error: ReadError) -> (result: FileError)
    ensures result == file_read_error_value(error),
{
    super::file_read_error(error)
}

pub fn check_file_write_error(error: WriteError) -> (result: FileError)
    ensures result == file_write_error_value(error),
{
    super::file_write_error(error)
}

pub fn check_file_map_shared_error(error: MapSharedError) -> (result: FileError)
    ensures result == file_map_shared_error_value(error),
{
    super::file_map_shared_error(error)
}

pub fn check_file_fault_read_error() -> (result: FileError)
    ensures result == FileError::Io,
{
    let read_error: ReadError = litebox_platform::buffer::Fault.into();

    super::file_read_error(read_error)
}

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
