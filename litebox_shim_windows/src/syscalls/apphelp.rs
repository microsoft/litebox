// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::offset_of;
use int_enum::IntEnum;

use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::AhcServiceData;
use crate::{MutPtr, ShimPlatform};

#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
#[repr(u32)]
pub enum AhcServiceClass {
    Lookup = 0,
    Remove = 1,
    Update = 2,
    Clear = 3,
    SnapStatistics = 4,
    SnapCache = 5,
    LookupCdb = 6,
    RefreshCdb = 7,
    MapQuirks = 8,
    HwIdQuery = 9,
    InitProcessData = 10,
    LookupAndWriteToProcess = 11,
}

fn handle_lookup_cdb<Platform: ShimPlatform>(
    service_data: Option<MutPtr<Platform, AhcServiceData>>,
) -> NtStatus {
    let Some(data_ptr) = service_data else {
        return NtStatus::INVALID_PARAMETER;
    };

    let Some(service_data) = data_ptr.read_at_offset(0) else {
        return NtStatus::ACCESS_VIOLATION;
    };

    if service_data.params_out == 0 || service_data.params_out_size != size_of::<u32>().trunc() {
        return NtStatus::INVALID_PARAMETER;
    }

    match service_data.lookup_cdb.name.read_string::<Platform>() {
        Ok(name) => {
            litebox_util_log::debug!(
                lookup_cdb_name:% = name,
                params_out:% = format_args!("{:#x}", service_data.params_out),
                params_out_size = service_data.params_out_size;
                "Decoded NtApphelpCacheControl LookupCdb service data"
            );
        }
        Err(status) => {
            litebox_util_log::warn!(
                status:? = status,
                params_out:% = format_args!("{:#x}", service_data.params_out),
                params_out_size = service_data.params_out_size;
                "Failed to decode NtApphelpCacheControl LookupCdb name"
            );
        }
    }

    // TODO: zero seems to indicate no matches.
    let params_out = MutPtr::<Platform, u32>::from_usize(service_data.params_out);
    if params_out.write_at_offset(0, 0).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }

    if crate::write_field_at_offset::<Platform, _>(
        data_ptr.as_usize(),
        offset_of!(AhcServiceData, driver_status),
        NtStatus::SUCCESS.as_raw(),
    )
    .is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }

    NtStatus::SUCCESS
}

pub(crate) fn sys_nt_apphelp_cache_control<Platform: ShimPlatform>(
    service_class: u32,
    service_data: Option<MutPtr<Platform, AhcServiceData>>,
) -> NtStatus {
    let Ok(service_class) = AhcServiceClass::try_from(service_class) else {
        litebox_util_log::debug!(
            service_class,
            service_data:% = format_args!("{:#x}", service_data.map_or(0, |ptr| ptr.as_usize()));
            "Rejected NtApphelpCacheControl service class"
        );
        return NtStatus::INVALID_PARAMETER;
    };

    let status = match service_class {
        AhcServiceClass::LookupCdb => handle_lookup_cdb::<Platform>(service_data),
        AhcServiceClass::Lookup | AhcServiceClass::LookupAndWriteToProcess => {
            NtStatus::NOT_SUPPORTED
        }
        AhcServiceClass::Remove
        | AhcServiceClass::Update
        | AhcServiceClass::Clear
        | AhcServiceClass::SnapStatistics
        | AhcServiceClass::SnapCache
        | AhcServiceClass::RefreshCdb
        | AhcServiceClass::MapQuirks
        | AhcServiceClass::HwIdQuery
        | AhcServiceClass::InitProcessData => NtStatus::NOT_SUPPORTED,
    };

    litebox_util_log::debug!(
        service_class:? = service_class,
        service_data:% = format_args!("{:#x}", service_data.map_or(0, |ptr| ptr.as_usize())),
        status:? = status;
        "Handled NtApphelpCacheControl with empty apphelp cache"
    );

    status
}
