// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::platform::RawConstPointer as _;
use litebox_common_windows::AhcServiceClass;
use litebox_common_windows::nt_status::NtStatus;

use crate::{MutPtr, ShimPlatform};

pub(crate) fn sys_nt_apphelp_cache_control<Platform: ShimPlatform>(
    service_class: u32,
    service_data: Option<MutPtr<Platform, u8>>,
) -> NtStatus {
    let Ok(service_class) = AhcServiceClass::try_from(service_class) else {
        litebox_util_log::debug!(
            service_class,
            service_data:% = format_args!("{:#x}", service_data.map_or(0, |ptr| ptr.as_usize()));
            "Rejected NtApphelpCacheControl service class"
        );
        return NtStatus::INVALID_PARAMETER;
    };

    // ReactOS reports empty apphelp-cache lookups as STATUS_NOT_FOUND and its
    // loader caller treats any non-success as a cache miss; Wine leaves this
    // syscall stubbed, which confirms Windows binaries tolerate no writeback.
    let status = match service_class {
        AhcServiceClass::Lookup
        | AhcServiceClass::LookupCdb
        | AhcServiceClass::LookupAndWriteToProcess => NtStatus::NOT_FOUND,
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tests::TestPlatform;

    fn service_value(service_class: AhcServiceClass) -> u32 {
        service_class as u32
    }

    fn invalid_service_data_ptr() -> MutPtr<TestPlatform, u8> {
        MutPtr::<TestPlatform, u8>::from_usize(usize::MAX)
    }

    #[test]
    fn apphelp_cache_lookup_family_reports_cache_miss_without_touching_service_data() {
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(AhcServiceClass::LookupCdb),
                Some(invalid_service_data_ptr()),
            ),
            NtStatus::NOT_FOUND
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(AhcServiceClass::Lookup),
                None,
            ),
            NtStatus::NOT_FOUND
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(AhcServiceClass::LookupAndWriteToProcess),
                Some(invalid_service_data_ptr()),
            ),
            NtStatus::NOT_FOUND
        );
    }

    #[test]
    fn apphelp_cache_unmodeled_operations_are_not_supported() {
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(AhcServiceClass::Update),
                Some(invalid_service_data_ptr()),
            ),
            NtStatus::NOT_SUPPORTED
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(AhcServiceClass::SnapCache),
                None,
            ),
            NtStatus::NOT_SUPPORTED
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(AhcServiceClass::InitProcessData),
                Some(invalid_service_data_ptr()),
            ),
            NtStatus::NOT_SUPPORTED
        );
    }

    #[test]
    fn apphelp_cache_rejects_unknown_service() {
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(999, Some(invalid_service_data_ptr())),
            NtStatus::INVALID_PARAMETER
        );
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn host_invalid_service_status_matches_litebox() {
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtApphelpCacheControl(service_class: u32, service_data: *mut u8) -> i32;
        }

        let mut service_data = 0u8;
        // SAFETY: Invalid service classes are rejected before host ntdll uses
        // the data pointer; this probes the externally observable status only.
        let host_status = unsafe { NtApphelpCacheControl(999, &raw mut service_data) };
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(999, Some(invalid_service_data_ptr()))
                .as_raw(),
            host_status
        );
    }
}
