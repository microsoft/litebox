// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;

use int_enum::IntEnum;
use litebox::platform::{
    Instant as _, PageManagementProvider, RawConstPointer as _, RawMutPointer as _,
};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::GroupAffinity;
use crate::{ConstPtr, MutPtr, PAGE_SIZE, ShimFS, ShimPlatform, Task};

const QPC_FREQUENCY_HZ: i64 = 1_000_000_000;
const MAXIMUM_NODE_COUNT: usize = 0x40;
const SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE_COUNT: usize = 4;
const TIMER_RESOLUTION_100NS: u32 = 156_250;
const ALLOCATION_GRANULARITY: u32 = 0x1_0000;
const DEFAULT_PHYSICAL_PAGES: u32 = 1024 * 1024;
const NUMBER_OF_PROCESSORS: u8 = 1;
const SUPPORTED_FLUSH_METHODS: u32 = 0x7;
const SUPPORTED_FLUSH_PROCESSOR_FEATURES: u32 = 0x40;
const LOGICAL_PROCESSOR_RELATION_ALL: u32 = u32::MAX;
const LOGICAL_PROCESSOR_RELATION_PROCESSOR_CORE: u32 = 0;
const LOGICAL_PROCESSOR_RELATION_NUMA_NODE: u32 = 1;
const LOGICAL_PROCESSOR_RELATION_PROCESSOR_PACKAGE: u32 = 3;
const LOGICAL_PROCESSOR_RELATION_GROUP: u32 = 4;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum SystemInformationClass {
    Basic = 0,
    Verifier = 50,
    NumaProcessorMap = 55,
    EmulationBasic = 62,
    LogicalProcessorAndGroup = 107,
    Flush = 192,
    HypervisorSharedPage = 197,
    FeatureConfigurationSection = 211,
    ProcessorFeaturesBitMap = 250,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemBasicInformation {
    reserved: u32,
    timer_resolution: u32,
    page_size: u32,
    number_of_physical_pages: u32,
    lowest_physical_page_number: u32,
    highest_physical_page_number: u32,
    allocation_granularity: u32,
    _padding0: u32,
    minimum_user_mode_address: usize,
    maximum_user_mode_address: usize,
    active_processors_affinity_mask: usize,
    number_of_processors: u8,
    _padding1: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemNumaInformation {
    highest_node_number: u32,
    reserved: u32,
    active_processors_group_affinity: [GroupAffinity; MAXIMUM_NODE_COUNT],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemFlushInformation {
    supported_flush_methods: u32,
    processor_features: u32,
    reserved: [u32; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemHypervisorSharedPageInformation {
    hypervisor_shared_user_va: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemProcessorFeaturesBitMapInformation {
    feature_bits: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemVerifierInformation {
    flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ProcessorRelationship {
    flags: u8,
    efficiency_class: u8,
    reserved: [u8; 20],
    group_count: u16,
    group_mask: [GroupAffinity; 1],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct NumaNodeRelationship {
    node_number: u32,
    reserved: [u8; 20],
    group_mask: GroupAffinity,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ProcessorGroupInfo {
    maximum_processor_count: u8,
    active_processor_count: u8,
    reserved: [u8; 38],
    active_processor_mask: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct GroupRelationship {
    maximum_group_count: u16,
    active_group_count: u16,
    reserved: [u8; 20],
    group_info: [ProcessorGroupInfo; 1],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ProcessorRelationshipInformation {
    relationship: u32,
    size: u32,
    processor: ProcessorRelationship,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct NumaNodeRelationshipInformation {
    relationship: u32,
    size: u32,
    numa_node: NumaNodeRelationship,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct GroupRelationshipInformation {
    relationship: u32,
    size: u32,
    group: GroupRelationship,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemFeatureConfigurationSectionsRequest {
    previous_change_stamps: [u64; SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE_COUNT],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemFeatureConfigurationSectionsInformationEntry {
    change_stamp: u64,
    section_handle: usize,
    size: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemFeatureConfigurationSectionsInformation {
    overall_change_stamp: u64,
    descriptors: [SystemFeatureConfigurationSectionsInformationEntry;
        SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE_COUNT],
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_query_system_information(
        system_information_class: u32,
        system_information: MutPtr<Platform, u8>,
        system_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        let Ok(system_information_class) =
            SystemInformationClass::try_from(system_information_class)
        else {
            litebox_util_log::debug!(
                system_information_class = system_information_class;
                "Unsupported NtQuerySystemInformation class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        let status = match system_information_class {
            SystemInformationClass::Basic | SystemInformationClass::EmulationBasic => {
                Self::write_system_information(
                    system_information,
                    system_information_length,
                    return_length,
                    &system_basic_information::<Platform>(),
                )
            }
            SystemInformationClass::Verifier => Self::write_system_information(
                system_information,
                system_information_length,
                return_length,
                &SystemVerifierInformation { flags: 0 },
            ),
            SystemInformationClass::NumaProcessorMap => Self::write_system_information(
                system_information,
                system_information_length,
                return_length,
                &system_numa_information(),
            ),
            SystemInformationClass::Flush => Self::write_system_information(
                system_information,
                system_information_length,
                return_length,
                &system_flush_information(),
            ),
            SystemInformationClass::HypervisorSharedPage => Self::write_system_information(
                system_information,
                system_information_length,
                return_length,
                &SystemHypervisorSharedPageInformation {
                    hypervisor_shared_user_va: 0,
                },
            ),
            SystemInformationClass::ProcessorFeaturesBitMap => Self::write_system_information(
                system_information,
                system_information_length,
                return_length,
                &SystemProcessorFeaturesBitMapInformation {
                    feature_bits: [0; 2],
                },
            ),
            SystemInformationClass::LogicalProcessorAndGroup
            | SystemInformationClass::FeatureConfigurationSection => NtStatus::INVALID_INFO_CLASS,
        };

        if status == NtStatus::SUCCESS {
            litebox_util_log::debug!(
                system_information_class:? = system_information_class,
                system_information_length = system_information_length;
                "Handled NtQuerySystemInformation syscall"
            );
        }

        status
    }

    pub(crate) fn sys_nt_query_system_information_ex(
        system_information_class: u32,
        input_buffer: Option<ConstPtr<Platform, u8>>,
        input_buffer_length: u32,
        system_information: MutPtr<Platform, u8>,
        system_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        if input_buffer_length < u32::try_from(size_of::<u32>()).expect("DWORD fits in ULONG") {
            return NtStatus::INVALID_PARAMETER;
        }
        let Some(input_buffer) = input_buffer else {
            return NtStatus::INVALID_PARAMETER;
        };

        let Ok(system_information_class) =
            SystemInformationClass::try_from(system_information_class)
        else {
            litebox_util_log::debug!(
                system_information_class = system_information_class;
                "Unsupported NtQuerySystemInformationEx class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        let status = match system_information_class {
            SystemInformationClass::LogicalProcessorAndGroup => {
                Self::write_logical_processor_and_group_information(
                    input_buffer,
                    system_information,
                    system_information_length,
                    return_length,
                )
            }
            SystemInformationClass::FeatureConfigurationSection => {
                Self::write_feature_configuration_section_information(
                    input_buffer,
                    input_buffer_length,
                    system_information,
                    system_information_length,
                    return_length,
                )
            }
            _ => {
                litebox_util_log::debug!(
                    system_information_class:? = system_information_class;
                    "Unsupported NtQuerySystemInformationEx class"
                );
                NtStatus::INVALID_INFO_CLASS
            }
        };

        if status == NtStatus::SUCCESS {
            litebox_util_log::debug!(
                system_information_class:? = system_information_class,
                system_information_length = system_information_length;
                "Handled NtQuerySystemInformationEx syscall"
            );
        }

        status
    }

    fn write_logical_processor_and_group_information(
        input_buffer: ConstPtr<Platform, u8>,
        system_information: MutPtr<Platform, u8>,
        system_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        let input_buffer = ConstPtr::<Platform, u32>::from_usize(input_buffer.as_usize());
        let Some(relationship) = input_buffer.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };

        let core = processor_relationship_information(LOGICAL_PROCESSOR_RELATION_PROCESSOR_CORE);
        let numa = numa_node_relationship_information();
        let package =
            processor_relationship_information(LOGICAL_PROCESSOR_RELATION_PROCESSOR_PACKAGE);
        let group = group_relationship_information();

        let mut records = [&[][..]; 4];
        let mut record_count = 0;
        push_logical_processor_record(
            relationship,
            LOGICAL_PROCESSOR_RELATION_PROCESSOR_CORE,
            core.as_bytes(),
            &mut records,
            &mut record_count,
        );
        push_logical_processor_record(
            relationship,
            LOGICAL_PROCESSOR_RELATION_NUMA_NODE,
            numa.as_bytes(),
            &mut records,
            &mut record_count,
        );
        push_logical_processor_record(
            relationship,
            LOGICAL_PROCESSOR_RELATION_PROCESSOR_PACKAGE,
            package.as_bytes(),
            &mut records,
            &mut record_count,
        );
        push_logical_processor_record(
            relationship,
            LOGICAL_PROCESSOR_RELATION_GROUP,
            group.as_bytes(),
            &mut records,
            &mut record_count,
        );

        Self::write_system_information_records(
            system_information,
            system_information_length,
            return_length,
            &records[..record_count],
        )
    }

    fn write_feature_configuration_section_information(
        input_buffer: ConstPtr<Platform, u8>,
        input_buffer_length: u32,
        system_information: MutPtr<Platform, u8>,
        system_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        if input_buffer_length
            < u32::try_from(size_of::<SystemFeatureConfigurationSectionsRequest>())
                .expect("feature configuration sections request length fits in ULONG")
        {
            return NtStatus::INVALID_PARAMETER;
        }
        let input_buffer =
            ConstPtr::<Platform, SystemFeatureConfigurationSectionsRequest>::from_usize(
                input_buffer.as_usize(),
            );
        if input_buffer.read_at_offset(0).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        Self::write_system_information(
            system_information,
            system_information_length,
            return_length,
            &system_feature_configuration_sections_information(),
        )
    }

    fn write_system_information<T: Immutable + IntoBytes>(
        system_information: MutPtr<Platform, u8>,
        system_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
        information: &T,
    ) -> NtStatus {
        let required_len = u32::try_from(size_of::<T>()).expect("system information fits in ULONG");
        if let Some(return_length) = return_length
            && return_length.write_at_offset(0, required_len).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if system_information_length < required_len {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if system_information
            .write_slice_at_offset(0, information.as_bytes())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    fn write_system_information_records(
        system_information: MutPtr<Platform, u8>,
        system_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
        records: &[&[u8]],
    ) -> NtStatus {
        let required_len = records.iter().try_fold(0u32, |total, record| {
            total.checked_add(u32::try_from(record.len()).ok()?)
        });
        let Some(required_len) = required_len else {
            return NtStatus::INVALID_PARAMETER;
        };

        if let Some(return_length) = return_length
            && return_length.write_at_offset(0, required_len).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if system_information_length < required_len {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }

        let mut offset = 0;
        for record in records {
            if system_information
                .write_slice_at_offset(offset, record)
                .is_none()
            {
                return NtStatus::ACCESS_VIOLATION;
            }
            offset += isize::try_from(record.len()).expect("record length fits in isize");
        }

        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_performance_counter(
        &self,
        performance_counter: MutPtr<Platform, i64>,
        performance_frequency: Option<MutPtr<Platform, i64>>,
    ) -> NtStatus {
        let elapsed = self
            .global
            .platform
            .now()
            .duration_since(&self.global.qpc_boot_instant);
        let ticks = duration_as_qpc_ticks(elapsed);

        if performance_counter.write_at_offset(0, ticks).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if let Some(performance_frequency) = performance_frequency
            && performance_frequency
                .write_at_offset(0, QPC_FREQUENCY_HZ)
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            performance_counter = ticks,
            performance_frequency = QPC_FREQUENCY_HZ;
            "Handled NtQueryPerformanceCounter syscall"
        );
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_convert_between_auxiliary_counter_and_performance_counter(
        _flag: u32,
        source: ConstPtr<Platform, u64>,
        _destination: MutPtr<Platform, u64>,
        _conversion_error: Option<MutPtr<Platform, u64>>,
    ) -> NtStatus {
        if source.as_usize() == 0 {
            return NtStatus::ACCESS_VIOLATION;
        }

        // Wine reports auxiliary counter conversion as unsupported after validating the source.
        NtStatus::NOT_SUPPORTED
    }
}

fn system_basic_information<Platform: ShimPlatform>() -> SystemBasicInformation {
    let maximum_user_mode_address =
        <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX.saturating_sub(1);
    SystemBasicInformation {
        reserved: 0,
        timer_resolution: TIMER_RESOLUTION_100NS,
        page_size: u32::try_from(PAGE_SIZE).expect("PAGE_SIZE fits in ULONG"),
        number_of_physical_pages: DEFAULT_PHYSICAL_PAGES,
        lowest_physical_page_number: 0,
        highest_physical_page_number: DEFAULT_PHYSICAL_PAGES.saturating_sub(1),
        allocation_granularity: ALLOCATION_GRANULARITY,
        _padding0: 0,
        minimum_user_mode_address: <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN,
        maximum_user_mode_address,
        active_processors_affinity_mask: usize::from(NUMBER_OF_PROCESSORS),
        number_of_processors: NUMBER_OF_PROCESSORS,
        _padding1: [0; 7],
    }
}

fn system_numa_information() -> SystemNumaInformation {
    let mut active_processors_group_affinity = [GroupAffinity {
        mask: 0,
        group: 0,
        reserved: [0; 3],
    }; MAXIMUM_NODE_COUNT];
    active_processors_group_affinity[0].mask = usize::from(NUMBER_OF_PROCESSORS);

    SystemNumaInformation {
        highest_node_number: 0,
        reserved: 0,
        active_processors_group_affinity,
    }
}

fn system_flush_information() -> SystemFlushInformation {
    SystemFlushInformation {
        supported_flush_methods: SUPPORTED_FLUSH_METHODS,
        processor_features: SUPPORTED_FLUSH_PROCESSOR_FEATURES,
        reserved: [0; 6],
    }
}

fn processor_group_affinity() -> GroupAffinity {
    GroupAffinity {
        mask: usize::from(NUMBER_OF_PROCESSORS),
        group: 0,
        reserved: [0; 3],
    }
}

fn processor_relationship_information(relationship: u32) -> ProcessorRelationshipInformation {
    ProcessorRelationshipInformation {
        relationship,
        size: u32::try_from(size_of::<ProcessorRelationshipInformation>())
            .expect("processor relationship information length fits in ULONG"),
        processor: ProcessorRelationship {
            flags: 0,
            efficiency_class: 0,
            reserved: [0; 20],
            group_count: 1,
            group_mask: [processor_group_affinity()],
        },
    }
}

fn numa_node_relationship_information() -> NumaNodeRelationshipInformation {
    NumaNodeRelationshipInformation {
        relationship: LOGICAL_PROCESSOR_RELATION_NUMA_NODE,
        size: u32::try_from(size_of::<NumaNodeRelationshipInformation>())
            .expect("NUMA node relationship information length fits in ULONG"),
        numa_node: NumaNodeRelationship {
            node_number: 0,
            reserved: [0; 20],
            group_mask: processor_group_affinity(),
        },
    }
}

fn group_relationship_information() -> GroupRelationshipInformation {
    GroupRelationshipInformation {
        relationship: LOGICAL_PROCESSOR_RELATION_GROUP,
        size: u32::try_from(size_of::<GroupRelationshipInformation>())
            .expect("group relationship information length fits in ULONG"),
        group: GroupRelationship {
            maximum_group_count: 1,
            active_group_count: 1,
            reserved: [0; 20],
            group_info: [ProcessorGroupInfo {
                maximum_processor_count: NUMBER_OF_PROCESSORS,
                active_processor_count: NUMBER_OF_PROCESSORS,
                reserved: [0; 38],
                active_processor_mask: usize::from(NUMBER_OF_PROCESSORS),
            }],
        },
    }
}

fn push_logical_processor_record<'a>(
    requested_relationship: u32,
    record_relationship: u32,
    record: &'a [u8],
    records: &mut [&'a [u8]; 4],
    record_count: &mut usize,
) {
    if requested_relationship == record_relationship
        || requested_relationship == LOGICAL_PROCESSOR_RELATION_ALL
    {
        records[*record_count] = record;
        *record_count += 1;
    }
}

fn system_feature_configuration_sections_information()
-> SystemFeatureConfigurationSectionsInformation {
    SystemFeatureConfigurationSectionsInformation {
        overall_change_stamp: 0,
        descriptors: [SystemFeatureConfigurationSectionsInformationEntry {
            change_stamp: 0,
            section_handle: 0,
            size: 0,
        }; SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE_COUNT],
    }
}

fn duration_as_qpc_ticks(duration: core::time::Duration) -> i64 {
    i64::try_from(core::cmp::min(duration.as_nanos(), i64::MAX as u128)).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{const_ptr, mut_byte_ptr, mut_ptr, null_const_ptr, null_mut_ptr};
    use core::mem::align_of;
    use core::time::Duration;
    use litebox::platform::ThreadProvider;

    extern crate std;

    const QPC_SLEEP_DURATION: Duration = Duration::from_millis(25);
    const QPC_SLEEP_TOLERANCE: Duration = Duration::from_millis(10);

    type TestPlatform = crate::tests::TestPlatform;

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    unsafe extern "system" {
        fn NtQuerySystemInformation(
            system_information_class: u32,
            system_information: *mut core::ffi::c_void,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> i32;

        fn NtQueryPerformanceCounter(counter: *mut i64, frequency: *mut i64) -> i32;

        fn NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
            flag: u32,
            source: *const u64,
            destination: *mut u64,
            conversion_error: *mut u64,
        ) -> i32;
    }

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn sys_nt_convert_between_auxiliary_counter_and_performance_counter(
        flag: u32,
        source: ConstPtr<TestPlatform, u64>,
        destination: MutPtr<TestPlatform, u64>,
        conversion_error: Option<MutPtr<TestPlatform, u64>>,
    ) -> NtStatus {
        Task::<TestPlatform, crate::tests::TestFS>::sys_nt_convert_between_auxiliary_counter_and_performance_counter(
            flag,
            source,
            destination,
            conversion_error,
        )
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn host_status(status: i32) -> NtStatus {
        NtStatus::from_raw(u32::from_ne_bytes(status.to_ne_bytes()))
    }

    fn qpc_delta_nanos(start: i64, end: i64) -> u128 {
        assert!(end >= start);
        u128::try_from(end - start).unwrap()
    }

    fn empty_basic_information() -> SystemBasicInformation {
        SystemBasicInformation {
            reserved: u32::MAX,
            timer_resolution: 0,
            page_size: 0,
            number_of_physical_pages: 0,
            lowest_physical_page_number: 0,
            highest_physical_page_number: 0,
            allocation_granularity: 0,
            _padding0: 0,
            minimum_user_mode_address: 0,
            maximum_user_mode_address: 0,
            active_processors_affinity_mask: 0,
            number_of_processors: 0,
            _padding1: [0; 7],
        }
    }

    fn class_value(class: SystemInformationClass) -> u32 {
        class as u32
    }

    fn sys_nt_query_system_information(
        system_information_class: u32,
        system_information: MutPtr<TestPlatform, u8>,
        system_information_length: u32,
        return_length: Option<MutPtr<TestPlatform, u32>>,
    ) -> NtStatus {
        Task::<TestPlatform, crate::tests::TestFS>::sys_nt_query_system_information(
            system_information_class,
            system_information,
            system_information_length,
            return_length,
        )
    }

    fn sys_nt_query_system_information_ex(
        system_information_class: u32,
        input_buffer: Option<ConstPtr<TestPlatform, u8>>,
        input_buffer_length: u32,
        system_information: MutPtr<TestPlatform, u8>,
        system_information_length: u32,
        return_length: Option<MutPtr<TestPlatform, u32>>,
    ) -> NtStatus {
        Task::<TestPlatform, crate::tests::TestFS>::sys_nt_query_system_information_ex(
            system_information_class,
            input_buffer,
            input_buffer_length,
            system_information,
            system_information_length,
            return_length,
        )
    }

    fn const_byte_ptr<T>(value: &T) -> ConstPtr<TestPlatform, u8> {
        ConstPtr::<TestPlatform, u8>::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    #[test]
    fn system_information_ex_layout_matches_windows_abi() {
        assert_eq!(
            class_value(SystemInformationClass::LogicalProcessorAndGroup),
            107
        );
        assert_eq!(
            class_value(SystemInformationClass::FeatureConfigurationSection),
            211
        );
        assert_eq!(size_of::<ProcessorRelationshipInformation>(), 48);
        assert_eq!(align_of::<ProcessorRelationshipInformation>(), 8);
        assert_eq!(size_of::<NumaNodeRelationshipInformation>(), 48);
        assert_eq!(align_of::<NumaNodeRelationshipInformation>(), 8);
        assert_eq!(size_of::<GroupRelationshipInformation>(), 80);
        assert_eq!(align_of::<GroupRelationshipInformation>(), 8);
        assert_eq!(size_of::<SystemFeatureConfigurationSectionsRequest>(), 32);
        assert_eq!(align_of::<SystemFeatureConfigurationSectionsRequest>(), 8);
        assert_eq!(
            size_of::<SystemFeatureConfigurationSectionsInformation>(),
            104
        );
        assert_eq!(
            align_of::<SystemFeatureConfigurationSectionsInformation>(),
            8
        );
    }

    #[test]
    fn nt_query_system_information_ex_validates_query_input() {
        run_with_test_platform_pointers(|| {
            let relationship = LOGICAL_PROCESSOR_RELATION_ALL;
            let mut output = [0u8; size_of::<ProcessorRelationshipInformation>()];
            let mut return_length = 0;

            assert_eq!(
                sys_nt_query_system_information_ex(
                    class_value(SystemInformationClass::LogicalProcessorAndGroup),
                    None,
                    u32::try_from(size_of::<u32>()).unwrap(),
                    mut_byte_ptr(&mut output),
                    u32::try_from(output.len()).unwrap(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INVALID_PARAMETER
            );
            assert_eq!(return_length, 0);

            assert_eq!(
                sys_nt_query_system_information_ex(
                    class_value(SystemInformationClass::LogicalProcessorAndGroup),
                    Some(const_byte_ptr(&relationship)),
                    u32::try_from(size_of::<u32>() - 1).unwrap(),
                    mut_byte_ptr(&mut output),
                    u32::try_from(output.len()).unwrap(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INVALID_PARAMETER
            );

            assert_eq!(
                sys_nt_query_system_information_ex(
                    class_value(SystemInformationClass::LogicalProcessorAndGroup),
                    Some(null_const_ptr()),
                    u32::try_from(size_of::<u32>()).unwrap(),
                    mut_byte_ptr(&mut output),
                    u32::try_from(output.len()).unwrap(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[test]
    fn nt_query_system_information_ex_rejects_unsupported_classes() {
        run_with_test_platform_pointers(|| {
            let query = LOGICAL_PROCESSOR_RELATION_ALL;
            let mut output = [0u8; size_of::<ProcessorRelationshipInformation>()];

            assert_eq!(
                sys_nt_query_system_information_ex(
                    class_value(SystemInformationClass::Basic),
                    Some(const_byte_ptr(&query)),
                    u32::try_from(size_of::<u32>()).unwrap(),
                    mut_byte_ptr(&mut output),
                    u32::try_from(output.len()).unwrap(),
                    None,
                ),
                NtStatus::INVALID_INFO_CLASS
            );

            assert_eq!(
                sys_nt_query_system_information_ex(
                    u32::MAX,
                    Some(const_byte_ptr(&query)),
                    u32::try_from(size_of::<u32>()).unwrap(),
                    mut_byte_ptr(&mut output),
                    u32::try_from(output.len()).unwrap(),
                    None,
                ),
                NtStatus::INVALID_INFO_CLASS
            );
        });
    }

    #[test]
    fn nt_query_system_information_ex_reports_required_logical_processor_length() {
        run_with_test_platform_pointers(|| {
            let relationship = LOGICAL_PROCESSOR_RELATION_ALL;
            let mut output = [0u8; 1];
            let mut return_length = 0;
            let expected_len = size_of::<ProcessorRelationshipInformation>() * 2
                + size_of::<NumaNodeRelationshipInformation>()
                + size_of::<GroupRelationshipInformation>();

            assert_eq!(
                sys_nt_query_system_information_ex(
                    class_value(SystemInformationClass::LogicalProcessorAndGroup),
                    Some(const_byte_ptr(&relationship)),
                    u32::try_from(size_of::<u32>()).unwrap(),
                    mut_byte_ptr(&mut output),
                    0,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(return_length, u32::try_from(expected_len).unwrap());
        });
    }

    #[test]
    fn nt_query_system_information_ex_filters_logical_processor_relationships() {
        run_with_test_platform_pointers(|| {
            let relationship = LOGICAL_PROCESSOR_RELATION_PROCESSOR_CORE;
            let mut info = processor_relationship_information(LOGICAL_PROCESSOR_RELATION_GROUP);
            let mut return_length = 0;

            assert_eq!(
                sys_nt_query_system_information_ex(
                    class_value(SystemInformationClass::LogicalProcessorAndGroup),
                    Some(const_byte_ptr(&relationship)),
                    u32::try_from(size_of::<u32>()).unwrap(),
                    mut_byte_ptr(&mut info),
                    u32::try_from(size_of::<ProcessorRelationshipInformation>()).unwrap(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );

            assert_eq!(info.relationship, LOGICAL_PROCESSOR_RELATION_PROCESSOR_CORE);
            assert_eq!(
                info.size,
                u32::try_from(size_of::<ProcessorRelationshipInformation>()).unwrap()
            );
            assert_eq!(info.processor.group_count, 1);
            assert_eq!(info.processor.group_mask[0].mask, 1);
            assert_eq!(return_length, info.size);
        });
    }

    #[test]
    fn nt_query_system_information_ex_writes_all_logical_processor_records() {
        run_with_test_platform_pointers(|| {
            let relationship = LOGICAL_PROCESSOR_RELATION_ALL;
            let mut output = [0u8; size_of::<ProcessorRelationshipInformation>() * 2
                + size_of::<NumaNodeRelationshipInformation>()
                + size_of::<GroupRelationshipInformation>()];
            let mut return_length = 0;

            assert_eq!(
                sys_nt_query_system_information_ex(
                    class_value(SystemInformationClass::LogicalProcessorAndGroup),
                    Some(const_byte_ptr(&relationship)),
                    u32::try_from(size_of::<u32>()).unwrap(),
                    mut_byte_ptr(&mut output),
                    u32::try_from(output.len()).unwrap(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(return_length, u32::try_from(output.len()).unwrap());

            let mut offset = 0;
            let expected_relationships = [
                LOGICAL_PROCESSOR_RELATION_PROCESSOR_CORE,
                LOGICAL_PROCESSOR_RELATION_NUMA_NODE,
                LOGICAL_PROCESSOR_RELATION_PROCESSOR_PACKAGE,
                LOGICAL_PROCESSOR_RELATION_GROUP,
            ];
            for expected_relationship in expected_relationships {
                let relationship =
                    u32::from_ne_bytes(output[offset..offset + 4].try_into().unwrap());
                let size = u32::from_ne_bytes(output[offset + 4..offset + 8].try_into().unwrap());
                assert_eq!(relationship, expected_relationship);
                assert!(size > 0);
                offset += usize::try_from(size).unwrap();
            }
            assert_eq!(offset, output.len());
        });
    }

    #[test]
    fn nt_query_system_information_ex_reports_feature_configuration_sections() {
        run_with_test_platform_pointers(|| {
            let request = SystemFeatureConfigurationSectionsRequest {
                previous_change_stamps: [u64::MAX; SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE_COUNT],
            };
            let mut info = SystemFeatureConfigurationSectionsInformation {
                overall_change_stamp: u64::MAX,
                descriptors: [SystemFeatureConfigurationSectionsInformationEntry {
                    change_stamp: u64::MAX,
                    section_handle: usize::MAX,
                    size: usize::MAX,
                }; SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE_COUNT],
            };
            let mut return_length = 0;

            assert_eq!(
                sys_nt_query_system_information_ex(
                    class_value(SystemInformationClass::FeatureConfigurationSection),
                    Some(const_byte_ptr(&request)),
                    u32::try_from(size_of::<SystemFeatureConfigurationSectionsRequest>()).unwrap(),
                    mut_byte_ptr(&mut info),
                    u32::try_from(size_of::<SystemFeatureConfigurationSectionsInformation>())
                        .unwrap(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(
                return_length,
                u32::try_from(size_of::<SystemFeatureConfigurationSectionsInformation>()).unwrap()
            );
            assert_eq!(info.overall_change_stamp, 0);
            assert!(info.descriptors.iter().all(|descriptor| {
                descriptor.change_stamp == 0
                    && descriptor.section_handle == 0
                    && descriptor.size == 0
            }));
        });
    }

    #[test]
    fn nt_query_system_information_reports_basic_information() {
        run_with_test_platform_pointers(|| {
            let mut info = empty_basic_information();
            let mut return_length = 0;

            assert_eq!(
                sys_nt_query_system_information(
                    class_value(SystemInformationClass::Basic),
                    mut_byte_ptr(&mut info),
                    u32::try_from(size_of::<SystemBasicInformation>()).unwrap(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );

            assert_eq!(
                return_length,
                u32::try_from(size_of::<SystemBasicInformation>()).unwrap()
            );
            assert_eq!(info.page_size, u32::try_from(PAGE_SIZE).unwrap());
            assert_eq!(info.allocation_granularity, ALLOCATION_GRANULARITY);
            assert_eq!(info.number_of_processors, NUMBER_OF_PROCESSORS);
            assert_eq!(
                info.minimum_user_mode_address,
                <TestPlatform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN
            );
            assert_eq!(
                info.maximum_user_mode_address,
                <TestPlatform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX - 1
            );
        });
    }

    #[test]
    fn nt_query_system_information_reports_selected_fixed_information() {
        run_with_test_platform_pointers(|| {
            let mut emulation = empty_basic_information();
            let mut numa = SystemNumaInformation {
                highest_node_number: u32::MAX,
                reserved: u32::MAX,
                active_processors_group_affinity: [GroupAffinity {
                    mask: usize::MAX,
                    group: u16::MAX,
                    reserved: [u16::MAX; 3],
                }; MAXIMUM_NODE_COUNT],
            };
            let mut flush = SystemFlushInformation {
                supported_flush_methods: 0,
                processor_features: 0,
                reserved: [u32::MAX; 6],
            };
            let mut hypervisor = SystemHypervisorSharedPageInformation {
                hypervisor_shared_user_va: usize::MAX,
            };
            let mut features = SystemProcessorFeaturesBitMapInformation {
                feature_bits: [u64::MAX; 2],
            };
            let mut verifier = SystemVerifierInformation { flags: u64::MAX };

            assert_eq!(
                sys_nt_query_system_information(
                    class_value(SystemInformationClass::EmulationBasic),
                    mut_byte_ptr(&mut emulation),
                    u32::try_from(size_of::<SystemBasicInformation>()).unwrap(),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(emulation.page_size, u32::try_from(PAGE_SIZE).unwrap());

            assert_eq!(
                sys_nt_query_system_information(
                    class_value(SystemInformationClass::NumaProcessorMap),
                    mut_byte_ptr(&mut numa),
                    u32::try_from(size_of::<SystemNumaInformation>()).unwrap(),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(numa.highest_node_number, 0);
            assert_eq!(numa.reserved, 0);
            assert_eq!(
                numa.active_processors_group_affinity[0].mask,
                usize::from(NUMBER_OF_PROCESSORS)
            );
            assert!(
                numa.active_processors_group_affinity[1..]
                    .iter()
                    .all(|affinity| affinity.mask == 0 && affinity.group == 0)
            );

            assert_eq!(
                sys_nt_query_system_information(
                    class_value(SystemInformationClass::Flush),
                    mut_byte_ptr(&mut flush),
                    u32::try_from(size_of::<SystemFlushInformation>()).unwrap(),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(flush.supported_flush_methods, SUPPORTED_FLUSH_METHODS);
            assert_eq!(flush.processor_features, SUPPORTED_FLUSH_PROCESSOR_FEATURES);
            assert_eq!(flush.reserved, [0; 6]);

            assert_eq!(
                sys_nt_query_system_information(
                    class_value(SystemInformationClass::HypervisorSharedPage),
                    mut_byte_ptr(&mut hypervisor),
                    u32::try_from(size_of::<SystemHypervisorSharedPageInformation>()).unwrap(),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(hypervisor.hypervisor_shared_user_va, 0);

            assert_eq!(
                sys_nt_query_system_information(
                    class_value(SystemInformationClass::ProcessorFeaturesBitMap),
                    mut_byte_ptr(&mut features),
                    u32::try_from(size_of::<SystemProcessorFeaturesBitMapInformation>()).unwrap(),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(features.feature_bits, [0; 2]);

            assert_eq!(
                sys_nt_query_system_information(
                    class_value(SystemInformationClass::Verifier),
                    mut_byte_ptr(&mut verifier),
                    u32::try_from(size_of::<SystemVerifierInformation>()).unwrap(),
                    None,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(verifier.flags, 0);
        });
    }

    #[test]
    fn nt_query_system_information_validates_class_and_buffer_length() {
        run_with_test_platform_pointers(|| {
            let mut info = [0u8; size_of::<SystemBasicInformation>()];
            let mut return_length = 0;

            assert_eq!(
                sys_nt_query_system_information(
                    class_value(SystemInformationClass::Basic),
                    mut_byte_ptr(&mut info),
                    u32::try_from(size_of::<SystemBasicInformation>() - 1).unwrap(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                return_length,
                u32::try_from(size_of::<SystemBasicInformation>()).unwrap()
            );

            assert_eq!(
                sys_nt_query_system_information(
                    1,
                    mut_byte_ptr(&mut info),
                    u32::try_from(info.len()).unwrap(),
                    None,
                ),
                NtStatus::INVALID_INFO_CLASS
            );
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_query_system_information_basic_status_matches_host_ntdll() {
        run_with_test_platform_pointers(|| {
            let mut host_info = [0u8; size_of::<SystemBasicInformation>()];
            let mut host_return_length = 0;
            let mut guest_info = empty_basic_information();
            let mut guest_return_length = 0;
            let information_length = u32::try_from(size_of::<SystemBasicInformation>()).unwrap();

            // SAFETY: The output buffer and return-length pointer are valid locals and ntdll does
            // not retain them.
            let host_basic_status = unsafe {
                host_status(NtQuerySystemInformation(
                    class_value(SystemInformationClass::Basic),
                    host_info.as_mut_ptr().cast(),
                    information_length,
                    &raw mut host_return_length,
                ))
            };
            let guest_status = sys_nt_query_system_information(
                class_value(SystemInformationClass::Basic),
                mut_byte_ptr(&mut guest_info),
                information_length,
                Some(mut_ptr(&mut guest_return_length)),
            );
            assert_eq!(guest_status, host_basic_status);
            assert_eq!(guest_return_length, host_return_length);
            assert_eq!(guest_info.page_size, u32::try_from(PAGE_SIZE).unwrap());
            assert_eq!(guest_info.allocation_granularity, ALLOCATION_GRANULARITY);

            let mut host_short_return_length = 0;
            let mut guest_short_return_length = 0;
            // SAFETY: Passing a short valid output buffer probes host ntdll's length handling; all
            // pointers are valid local variables.
            let host_short_status = unsafe {
                host_status(NtQuerySystemInformation(
                    class_value(SystemInformationClass::Basic),
                    host_info.as_mut_ptr().cast(),
                    information_length - 1,
                    &raw mut host_short_return_length,
                ))
            };
            let guest_short_status = sys_nt_query_system_information(
                class_value(SystemInformationClass::Basic),
                mut_byte_ptr(&mut guest_info),
                information_length - 1,
                Some(mut_ptr(&mut guest_short_return_length)),
            );
            assert_eq!(guest_short_status, host_short_status);
            assert_eq!(guest_short_return_length, host_short_return_length);
        });
    }

    #[test]
    fn nt_query_performance_counter_writes_monotonic_counter_and_frequency() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut first_counter = -1i64;
            let mut second_counter = -1i64;
            let mut frequency = 0i64;

            assert_eq!(
                task.sys_nt_query_performance_counter(
                    mut_ptr(&mut first_counter),
                    Some(mut_ptr(&mut frequency)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(frequency, QPC_FREQUENCY_HZ);
            assert!(first_counter >= 0);

            assert_eq!(
                task.sys_nt_query_performance_counter(mut_ptr(&mut second_counter), None),
                NtStatus::SUCCESS
            );
            assert!(second_counter >= first_counter);
        });
    }

    #[test]
    fn nt_query_performance_counter_rejects_null_counter() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut frequency = 0i64;

            assert_eq!(
                task.sys_nt_query_performance_counter(
                    null_mut_ptr(),
                    Some(mut_ptr(&mut frequency)),
                ),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[test]
    fn nt_convert_between_auxiliary_counter_and_performance_counter_is_not_supported() {
        run_with_test_platform_pointers(|| {
            let source = 0u64;
            let mut destination = 0u64;
            let mut conversion_error = 0u64;

            assert_eq!(
                sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                    0,
                    null_const_ptr(),
                    mut_ptr(&mut destination),
                    Some(mut_ptr(&mut conversion_error)),
                ),
                NtStatus::ACCESS_VIOLATION
            );
            assert_eq!(
                sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                    0,
                    const_ptr(&source),
                    mut_ptr(&mut destination),
                    Some(mut_ptr(&mut conversion_error)),
                ),
                NtStatus::NOT_SUPPORTED
            );
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_query_performance_counter_status_matches_host_ntdll() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut host_counter = 0i64;
            let mut host_frequency = 0i64;
            let mut guest_counter = 0i64;
            let mut guest_frequency = 0i64;

            // SAFETY: This Windows-only test calls the process ntdll export with valid local
            // output pointers and checks only the returned status and written scalar values.
            let host_valid_status = unsafe {
                host_status(NtQueryPerformanceCounter(
                    &raw mut host_counter,
                    &raw mut host_frequency,
                ))
            };
            let guest_status = task.sys_nt_query_performance_counter(
                mut_ptr(&mut guest_counter),
                Some(mut_ptr(&mut guest_frequency)),
            );

            assert_eq!(guest_status, host_valid_status);
            assert!(guest_counter >= 0);
            assert!(guest_frequency > 0);
            assert!(host_counter >= 0);
            assert!(host_frequency > 0);

            // SAFETY: Passing a null counter pointer intentionally probes host ntdll's invalid
            // output behavior; the non-null frequency pointer is a valid local output.
            let host_null_counter_status = unsafe {
                host_status(NtQueryPerformanceCounter(
                    core::ptr::null_mut(),
                    &raw mut host_frequency,
                ))
            };
            let guest_null_counter_status = task.sys_nt_query_performance_counter(
                null_mut_ptr(),
                Some(mut_ptr(&mut guest_frequency)),
            );
            assert_eq!(guest_null_counter_status, host_null_counter_status);
        });
    }

    #[test]
    fn nt_query_performance_counter_duration_tracks_sleep_duration() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut guest_frequency = 0i64;
            let mut guest_start = 0i64;
            let mut guest_end = 0i64;

            let guest_start_status = task.sys_nt_query_performance_counter(
                mut_ptr(&mut guest_start),
                Some(mut_ptr(&mut guest_frequency)),
            );

            std::thread::sleep(QPC_SLEEP_DURATION);

            let guest_end_status = task.sys_nt_query_performance_counter(
                mut_ptr(&mut guest_end),
                Some(mut_ptr(&mut guest_frequency)),
            );

            assert_eq!(guest_start_status, NtStatus::SUCCESS);
            assert_eq!(guest_end_status, NtStatus::SUCCESS);
            assert_eq!(guest_frequency, QPC_FREQUENCY_HZ);

            let guest_duration_nanos = qpc_delta_nanos(guest_start, guest_end);
            let minimum_duration_nanos = QPC_SLEEP_DURATION
                .saturating_sub(QPC_SLEEP_TOLERANCE)
                .as_nanos();
            let maximum_duration_nanos = QPC_SLEEP_DURATION
                .saturating_add(QPC_SLEEP_TOLERANCE)
                .as_nanos();

            assert!(
                guest_duration_nanos >= minimum_duration_nanos,
                "guest duration {guest_duration_nanos}ns was shorter than requested sleep minus tolerance {minimum_duration_nanos}ns",
            );
            assert!(
                guest_duration_nanos <= maximum_duration_nanos,
                "guest duration {guest_duration_nanos}ns was longer than requested sleep plus tolerance {maximum_duration_nanos}ns",
            );
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_convert_between_auxiliary_counter_status_matches_host_ntdll() {
        run_with_test_platform_pointers(|| {
            let source = 0u64;
            let mut destination = 0u64;
            let mut conversion_error = 0u64;

            // SAFETY: Passing a null source pointer intentionally probes host ntdll's invalid
            // input behavior; the output pointers are valid local scalars for the duration.
            let host_null_source_status = unsafe {
                host_status(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
                    0,
                    core::ptr::null(),
                    &raw mut destination,
                    &raw mut conversion_error,
                ))
            };
            let guest_null_source_status =
                sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                    0,
                    null_const_ptr(),
                    mut_ptr(&mut destination),
                    Some(mut_ptr(&mut conversion_error)),
                );
            assert_eq!(guest_null_source_status, host_null_source_status);

            // SAFETY: All pointers passed to host ntdll point at local scalar variables that live
            // for the whole call; the function does not retain them.
            let host_valid_source_status = unsafe {
                host_status(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
                    0,
                    &raw const source,
                    &raw mut destination,
                    &raw mut conversion_error,
                ))
            };
            let guest_valid_source_status =
                sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                    0,
                    const_ptr(&source),
                    mut_ptr(&mut destination),
                    Some(mut_ptr(&mut conversion_error)),
                );
            assert_eq!(guest_valid_source_status, host_valid_source_status);
        });
    }
}
