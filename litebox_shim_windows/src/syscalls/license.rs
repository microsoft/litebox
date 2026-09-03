// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::UnicodeString;
use crate::{ConstPtr, MutPtr, ShimPlatform, Task};

impl<Platform: ShimPlatform> Task<Platform> {
    pub(crate) fn sys_nt_query_license_value(
        value_name: ConstPtr<Platform, UnicodeString>,
        _value_type: MutPtr<Platform, u32>,
        _data: MutPtr<Platform, u8>,
        _data_size: u32,
        result_data_size: MutPtr<Platform, u32>,
    ) -> NtStatus {
        if value_name.as_usize() == 0 || result_data_size.as_usize() == 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        let Some(value_name) = value_name.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        match value_name.character_count() {
            Ok(0) | Err(_) => return NtStatus::INVALID_PARAMETER,
            Ok(_) if value_name.buffer != 0 => {}
            Ok(_) => return NtStatus::INVALID_PARAMETER,
        }
        if !value_name
            .buffer
            .is_multiple_of(core::mem::align_of::<u16>())
        {
            return NtStatus::DATATYPE_MISALIGNMENT;
        }
        let Some(result_data_size_value) = result_data_size.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let value_name = match value_name.read_string::<Platform>() {
            Ok(value_name) => value_name,
            Err(status) => return status,
        };
        if result_data_size
            .write_at_offset(0, result_data_size_value)
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(value_name:% = value_name; "Queried Windows license value");

        // TODO(license-store): Report every policy as absent until LiteBox has a license store.
        NtStatus::OBJECT_NAME_NOT_FOUND
    }
}
