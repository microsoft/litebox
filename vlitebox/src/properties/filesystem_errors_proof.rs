// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation-linked; independently check the original platform and core.
//! The filesystem-error slice uses no custom behavioral assumptions.

use crate::spec::filesystem_errors_spec::{
    file_map_shared_error_value, file_read_directory_error_value, file_read_error_value,
    file_seek_error_value, file_service_error_policy, file_truncate_error_value,
    file_write_error_value, filesystem_error_policy,
};
use litebox_broker_core::fs::errors::{
    MapSharedError, ReadDirError, ReadError, SeekError, StorageError, TruncateError, WriteError,
};
use litebox_broker_protocol::fs::FileError;
use vstd::prelude::*;

verus! {

pub proof fn original_file_service_error_translations_are_exact()
    ensures file_service_error_policy(),
{
    litebox_broker_core::fs::prove_file_service_error_translations();
}

pub fn check_file_read_error(error: ReadError) -> (result: FileError)
    ensures result == file_read_error_value(error),
{
    litebox_broker_core::fs::check_file_read_error(error)
}

pub fn check_file_write_error(error: WriteError) -> (result: FileError)
    ensures result == file_write_error_value(error),
{
    litebox_broker_core::fs::check_file_write_error(error)
}

pub fn check_file_map_shared_error(error: MapSharedError) -> (result: FileError)
    ensures result == file_map_shared_error_value(error),
{
    litebox_broker_core::fs::check_file_map_shared_error(error)
}

pub fn check_storage_to_guest_mapping_error(error: StorageError) -> (result: FileError)
    ensures result == match error {
        StorageError::NoSpace => FileError::NoSpace,
        _ => FileError::Io,
    },
{
    let mapping_error: MapSharedError = error.into();

    check_file_map_shared_error(mapping_error)
}

pub fn check_fault_to_guest_read_compatibility() -> (result: FileError)
    ensures result == FileError::Io,
{
    litebox_broker_core::fs::check_file_fault_read_error()
}

pub fn check_file_truncate_error(error: TruncateError) -> (result: FileError)
    ensures result == file_truncate_error_value(error),
{
    litebox_broker_core::fs::check_file_truncate_error(error)
}

pub fn check_file_seek_error(error: SeekError) -> (result: FileError)
    ensures result == file_seek_error_value(error),
{
    litebox_broker_core::fs::check_file_seek_error(error)
}

pub fn check_file_read_directory_error(error: ReadDirError) -> (result: FileError)
    ensures result == file_read_directory_error_value(error),
{
    litebox_broker_core::fs::check_file_read_directory_error(error)
}

pub fn check_storage_to_guest_truncate_error(error: StorageError) -> (result: FileError)
    ensures result == match error {
        StorageError::NoSpace => FileError::NoSpace,
        StorageError::Busy => FileError::Busy,
        StorageError::Fault | StorageError::Io => FileError::Io,
    },
{
    let truncate_error: TruncateError = error.into();

    check_file_truncate_error(truncate_error)
}

pub proof fn filesystem_fault_and_storage_error_conversions_are_exact()
    ensures filesystem_error_policy(),
{
    litebox_broker_core::fs::errors::verification::prove_filesystem_error_conversions();
}

pub fn check_shared_mapping_storage_errors(error: StorageError) -> (result: MapSharedError)
    ensures result == litebox_broker_core::fs::errors::verification::storage_mapping_error(error),
{
    error.into()
}

}
