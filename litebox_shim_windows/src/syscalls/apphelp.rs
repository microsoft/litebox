// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::AhcServiceClass;
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::AhcServiceData;
use crate::{ConstPtr, MutPtr, ShimPlatform};

fn handle_lookup_cdb<Platform: ShimPlatform>(
    service_data: Option<MutPtr<Platform, u8>>,
) -> NtStatus {
    let Some(service_data_ptr) = service_data else {
        return NtStatus::INVALID_PARAMETER;
    };

    let data_ptr = ConstPtr::<Platform, AhcServiceData>::from_usize(service_data_ptr.as_usize());
    let Some(mut service_data) = data_ptr.read_at_offset(0) else {
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

    let params_out = MutPtr::<Platform, u32>::from_usize(service_data.params_out);
    if params_out.write_at_offset(0, 0).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }

    service_data.driver_status = NtStatus::SUCCESS.as_raw();
    let service_data_out =
        MutPtr::<Platform, AhcServiceData>::from_usize(service_data_ptr.as_usize());
    if service_data_out.write_at_offset(0, service_data).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }

    NtStatus::SUCCESS
}

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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::nt_types::{AhcServiceData, AhcServiceLookupCdb, UnicodeString};
    use crate::tests::TestPlatform;
    use crate::tests::{mut_byte_ptr, unicode_string, utf16_units};
    use litebox::platform::ThreadProvider;

    fn service_value(service_class: AhcServiceClass) -> u32 {
        service_class as u32
    }

    fn invalid_service_data_ptr() -> MutPtr<TestPlatform, u8> {
        MutPtr::<TestPlatform, u8>::from_usize(0x1000)
    }

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn apphelp_service_data(
        name: UnicodeString,
        params_out: Option<&mut u32>,
        params_out_size: u32,
    ) -> AhcServiceData {
        AhcServiceData {
            reserved_0: [0; 0xf8],
            lookup_cdb: AhcServiceLookupCdb { name },
            reserved_1: [0; 0x68],
            driver_status: 0x1234_5678,
            reserved_2: [0; 4],
            params_out: params_out.map_or(0, |value| core::ptr::from_mut(value) as usize),
            params_out_size,
            reserved_3: [0; 4],
        }
    }

    #[test]
    fn apphelp_cache_lookup_cdb_writes_host_empty_result() {
        let name_units = utf16_units("KERNELBASE.dll");
        let name = unicode_string(&name_units);
        let mut params_out = 0xffff_ffff;
        let mut service_data =
            apphelp_service_data(name, Some(&mut params_out), size_of::<u32>().trunc());

        assert_eq!(
            ConstPtr::<TestPlatform, AhcServiceData>::from_usize(
                core::ptr::from_ref(&service_data) as usize,
            )
            .read_at_offset(0)
            .expect("service data should be readable")
            .lookup_cdb
            .name
            .read_string::<TestPlatform>()
            .expect("lookup name should decode"),
            "KERNELBASE.dll"
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(AhcServiceClass::LookupCdb),
                Some(mut_byte_ptr(&mut service_data)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(params_out, 0);
        assert_eq!(service_data.driver_status, NtStatus::SUCCESS.as_raw());
        assert_eq!(service_data.params_out_size, size_of::<u32>().trunc());
    }

    #[test]
    fn apphelp_cache_lookup_cdb_rejects_missing_or_mis_sized_output_slot() {
        let name_units = utf16_units("KERNELBASE.dll");
        let name = unicode_string(&name_units);
        let mut missing_output = apphelp_service_data(name, None, size_of::<u32>().trunc());
        let mut params_out = 0xffff_ffff;
        let mut short_output = apphelp_service_data(name, Some(&mut params_out), 3);
        let mut long_output = apphelp_service_data(name, Some(&mut params_out), 8);

        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(AhcServiceClass::LookupCdb),
                Some(mut_byte_ptr(&mut missing_output)),
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(AhcServiceClass::LookupCdb),
                Some(mut_byte_ptr(&mut short_output)),
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(AhcServiceClass::LookupCdb),
                Some(mut_byte_ptr(&mut long_output)),
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(params_out, 0xffff_ffff);
    }

    #[test]
    fn apphelp_cache_lookup_cdb_read_fault_returns_access_violation() {
        run_with_test_platform_pointers(|| {
            assert_eq!(
                sys_nt_apphelp_cache_control::<TestPlatform>(
                    service_value(AhcServiceClass::LookupCdb),
                    Some(invalid_service_data_ptr()),
                ),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[test]
    fn apphelp_cache_unmodeled_operations_are_not_supported() {
        for service_class in [
            AhcServiceClass::Lookup,
            AhcServiceClass::LookupAndWriteToProcess,
            AhcServiceClass::Update,
            AhcServiceClass::SnapCache,
            AhcServiceClass::InitProcessData,
        ] {
            assert_eq!(
                sys_nt_apphelp_cache_control::<TestPlatform>(service_value(service_class), None),
                NtStatus::NOT_SUPPORTED
            );
        }
    }

    #[test]
    fn apphelp_cache_lookup_cdb_missing_service_data_is_invalid_parameter() {
        assert_eq!(
            sys_nt_apphelp_cache_control::<TestPlatform>(
                service_value(AhcServiceClass::LookupCdb),
                None,
            ),
            NtStatus::INVALID_PARAMETER
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
    fn host_lookup_cdb_status_and_empty_result_match_litebox() {
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtApphelpCacheControl(service_class: u32, service_data: *mut u8) -> i32;
        }

        let name_units = utf16_units("KERNELBASE.dll");
        let name = unicode_string(&name_units);
        let mut host_params_out = 0xffff_ffff;
        let mut host_data =
            apphelp_service_data(name, Some(&mut host_params_out), size_of::<u32>().trunc());
        let mut litebox_params_out = 0xffff_ffff;
        let mut litebox_data = apphelp_service_data(
            name,
            Some(&mut litebox_params_out),
            size_of::<u32>().trunc(),
        );

        // SAFETY: The service-data buffer and its output slot are live host
        // memory with the Win11 layout and output size accepted by host ntdll.
        let host_status = unsafe {
            NtApphelpCacheControl(
                service_value(AhcServiceClass::LookupCdb),
                (&raw mut host_data).cast::<u8>(),
            )
        };
        let litebox_status = sys_nt_apphelp_cache_control::<TestPlatform>(
            service_value(AhcServiceClass::LookupCdb),
            Some(mut_byte_ptr(&mut litebox_data)),
        );

        assert_eq!(litebox_status.as_raw(), host_status);
        assert_eq!(litebox_params_out, host_params_out);
    }
}
