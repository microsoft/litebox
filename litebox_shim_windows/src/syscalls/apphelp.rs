// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use int_enum::IntEnum;
use litebox::platform::RawConstPointer as _;
use litebox_common_windows::nt_status::NtStatus;

use crate::{MutPtr, ShimPlatform};

const STATUS_NOT_FOUND: NtStatus = NtStatus::from_raw(0xC000_0225);

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum ApphelpCacheServiceClass {
    Lookup = 0,
    Remove = 1,
    Update = 2,
    Clear = 3,
    SnapStatistics = 4,
    SnapCache = 5,
    LookupCdb = 6,
}

pub(crate) fn sys_nt_apphelp_cache_control<Platform: ShimPlatform>(
    service_class: u32,
    service_data: Option<MutPtr<Platform, u8>>,
) -> NtStatus {
    let Ok(service_class) = ApphelpCacheServiceClass::try_from(service_class) else {
        litebox_util_log::debug!(
            service_class,
            service_data:% = format_args!("{:#x}", service_data.map_or(0, |ptr| ptr.as_usize()));
            "Rejected NtApphelpCacheControl service class"
        );
        return NtStatus::INVALID_PARAMETER;
    };

    // ReactOS' older NDK names classes 3/4 Flush/Dump; current phnt and
    // minwin ahcache.h expose 3..6 as Clear/SnapStatistics/SnapCache/LookupCdb.
    // LiteBox has no shim cache/CDB yet, so cache lookups miss while CDB
    // lookups, mutations, and snapshots are accepted as no-ops.
    let status = match service_class {
        ApphelpCacheServiceClass::Lookup => {
            service_data.map_or(NtStatus::INVALID_PARAMETER, |_| STATUS_NOT_FOUND)
        }
        ApphelpCacheServiceClass::Remove => {
            service_data.map_or(NtStatus::INVALID_PARAMETER, |_| STATUS_NOT_FOUND)
        }
        ApphelpCacheServiceClass::Update => {
            service_data.map_or(NtStatus::INVALID_PARAMETER, |_| NtStatus::SUCCESS)
        }
        ApphelpCacheServiceClass::LookupCdb => {
            service_data.map_or(NtStatus::INVALID_PARAMETER, |_| NtStatus::SUCCESS)
        }
        ApphelpCacheServiceClass::Clear
        | ApphelpCacheServiceClass::SnapStatistics
        | ApphelpCacheServiceClass::SnapCache => NtStatus::SUCCESS,
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

    fn service_value(service_class: ApphelpCacheServiceClass) -> u32 {
        service_class as u32
    }

    fn service_data_ptr() -> MutPtr<TestPlatform, u8> {
        MutPtr::<TestPlatform, u8>::from_usize(0x1000)
    }

    #[test]
    fn apphelp_cache_lookup_reports_empty_cache() {
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::Lookup),
                Some(service_data_ptr()),
            ),
            STATUS_NOT_FOUND
        );
    }

    #[test]
    fn apphelp_cache_mutations_match_empty_cache_contract() {
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::Remove),
                Some(service_data_ptr()),
            ),
            STATUS_NOT_FOUND
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::Update),
                Some(service_data_ptr()),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::LookupCdb),
                Some(service_data_ptr()),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::Clear),
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::SnapStatistics),
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(ApphelpCacheServiceClass::SnapCache),
                None,
            ),
            NtStatus::SUCCESS
        );
    }

    #[test]
    fn apphelp_cache_rejects_required_missing_data_and_unknown_service() {
        for service_class in [
            ApphelpCacheServiceClass::Lookup,
            ApphelpCacheServiceClass::LookupCdb,
            ApphelpCacheServiceClass::Remove,
            ApphelpCacheServiceClass::Update,
        ] {
            assert_eq!(
                sys_nt_apphelp_cache_control::<TestPlatform>(service_value(service_class), None),
                NtStatus::INVALID_PARAMETER
            );
        }

        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(999, Some(service_data_ptr())),
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
            sys_nt_apphelp_cache_control::<TestPlatform>(999, Some(service_data_ptr())).as_raw(),
            host_status
        );
    }
}
