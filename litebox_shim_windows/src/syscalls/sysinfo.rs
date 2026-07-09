// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;

use int_enum::IntEnum;
use litebox::platform::{
    Instant as _, PageManagementProvider, RawConstPointer as _, RawMutPointer as _,
};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::GroupAffinity;
use crate::syscalls::mm::ALLOCATION_GRANULARITY;
use crate::{ConstPtr, MutPtr, PAGE_SIZE, ShimFS, ShimPlatform, Task};

const QPC_FREQUENCY_HZ: i64 = 1_000_000_000;
// These fixed values are deterministic sandbox answers: a default 15.625 ms
// timer tick, one synthetic processor, and a stable 4 GiB physical-memory view.
// They avoid leaking host topology while satisfying Windows CRT/environment
// probes that require plausible system-information success outputs.
const TIMER_RESOLUTION_100NS: u32 = 156_250;
const DEFAULT_PHYSICAL_PAGES: u32 = 1024 * 1024;
const NUMBER_OF_PROCESSORS: u8 = 1;
const PROCESSOR_AFFINITY_MASK: usize = (1usize << NUMBER_OF_PROCESSORS) - 1;
// SystemFlushInformation values observed from host ntdll on Windows 11 24H2.
// LiteBox keeps them fixed because they describe the synthetic CPU contract.
const SUPPORTED_FLUSH_METHODS: u32 = 0x7;
const SUPPORTED_FLUSH_PROCESSOR_FEATURES: u32 = 0x40;
const CACHE_UNIFIED: u32 = 0;
const DWORD_SIZE_U32: u32 = 4;
const NUMA_NODE_COUNT: usize = NUMBER_OF_PROCESSORS as usize;
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
const SYSTEM_VERIFIER_INFORMATION_LENGTH: u32 = 0x90;
const SYSTEM_VERIFIER_INFORMATION_LENGTH_USIZE: usize = 0x90;
const X64_SYSTEM_RANGE_START: usize = 0xffff_8000_0000_0000;

pub(crate) const WINDOWS_TIME_ZONE_ID_INVALID: u32 = u32::MAX;
pub(crate) const WINDOWS_OS_MAJOR_VERSION: u16 = 10;
pub(crate) const WINDOWS_OS_MINOR_VERSION: u16 = 0;
pub(crate) const WINDOWS_OS_BUILD_NUMBER: u16 = 19041;
pub(crate) const WINDOWS_OS_PLATFORM_WIN32_NT: u32 = 2;
#[cfg(not(target_os = "windows"))]
pub(crate) const WINDOWS_NT_PRODUCT_WORKSTATION: u32 = 1;
pub(crate) const WINDOWS_DIRECTORY: &str = r"C:\Windows";
pub(crate) const WINDOWS_SYSTEM_DIRECTORY: &str = r"C:\Windows\System32";
pub(crate) const WINDOWS_NAMED_OBJECT_DIRECTORY: &str = r"\BaseNamedObjects";

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum SystemInformationClass {
    Basic = 0,
    Processor = 1,
    RangeStart = 50,
    Verifier = 51,
    NumaProcessorMap = 55,
    EmulationBasic = 62,
    LogicalProcessorAndGroup = 107,
    Flush = 192,
    HypervisorSharedPage = 197,
    FeatureConfigurationSection = 211,
    ProcessorFeaturesBitMap = 250,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum LogicalProcessorRelationship {
    ProcessorCore = 0,
    NumaNode = 1,
    Cache = 2,
    ProcessorPackage = 3,
    Group = 4,
    All = 0xffff,
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
struct SystemProcessorInformation {
    processor_architecture: u16,
    processor_level: u16,
    processor_revision: u16,
    maximum_processors: u16,
    processor_feature_bits: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemNumaInformation {
    highest_node_number: u32,
    reserved: u32,
    active_processors_group_affinity: [GroupAffinity; NUMA_NODE_COUNT],
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
struct SystemRangeStartInformation {
    system_range_start: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SystemProcessorFeaturesBitMapInformation {
    feature_bits: [u64; 2],
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
    reserved: [u8; 18],
    group_count: u16,
    group_mask: GroupAffinity,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct CacheRelationship {
    level: u8,
    associativity: u8,
    line_size: u16,
    cache_size: u32,
    cache_type: u32,
    reserved: [u8; 18],
    group_count: u16,
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
struct CacheRelationshipInformation {
    relationship: u32,
    size: u32,
    cache: CacheRelationship,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct GroupRelationshipInformation {
    relationship: u32,
    size: u32,
    group: GroupRelationship,
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
                Self::write_exact_system_information(
                    system_information,
                    system_information_length,
                    return_length,
                    &system_basic_information::<Platform>(),
                )
            }
            SystemInformationClass::Processor => Self::write_system_information(
                system_information,
                system_information_length,
                return_length,
                &system_processor_information(),
            ),
            SystemInformationClass::RangeStart => Self::write_exact_system_information(
                system_information,
                system_information_length,
                return_length,
                &SystemRangeStartInformation {
                    system_range_start: X64_SYSTEM_RANGE_START,
                },
            ),
            SystemInformationClass::Verifier => Self::write_system_verifier_information(
                system_information,
                system_information_length,
                return_length,
            ),
            SystemInformationClass::NumaProcessorMap => Self::write_numa_processor_map_information(
                system_information,
                system_information_length,
                return_length,
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
        if input_buffer_length < DWORD_SIZE_U32 {
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
            // TODO: Windows returns section handles for this class. LiteBox does not yet model those
            // NT section objects, so do not publish a fabricated success payload.
            SystemInformationClass::FeatureConfigurationSection => NtStatus::INVALID_INFO_CLASS,
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

        let Ok(relationship) = LogicalProcessorRelationship::try_from(relationship) else {
            return NtStatus::UNSUCCESSFUL;
        };

        match relationship {
            LogicalProcessorRelationship::ProcessorCore => Self::write_system_information(
                system_information,
                system_information_length,
                return_length,
                &processor_relationship_information(LogicalProcessorRelationship::ProcessorCore),
            ),
            LogicalProcessorRelationship::NumaNode => Self::write_system_information(
                system_information,
                system_information_length,
                return_length,
                &numa_node_relationship_information(),
            ),
            LogicalProcessorRelationship::Cache => Self::write_system_information(
                system_information,
                system_information_length,
                return_length,
                &cache_relationship_information(),
            ),
            LogicalProcessorRelationship::ProcessorPackage => Self::write_system_information(
                system_information,
                system_information_length,
                return_length,
                &processor_relationship_information(LogicalProcessorRelationship::ProcessorPackage),
            ),
            LogicalProcessorRelationship::Group => Self::write_system_information(
                system_information,
                system_information_length,
                return_length,
                &group_relationship_information(),
            ),
            LogicalProcessorRelationship::All => {
                let core =
                    processor_relationship_information(LogicalProcessorRelationship::ProcessorCore);
                let numa = numa_node_relationship_information();
                let cache = cache_relationship_information();
                let package = processor_relationship_information(
                    LogicalProcessorRelationship::ProcessorPackage,
                );
                let group = group_relationship_information();
                let records = [
                    core.as_bytes(),
                    numa.as_bytes(),
                    cache.as_bytes(),
                    package.as_bytes(),
                    group.as_bytes(),
                ];
                let required_len = records.iter().try_fold(0u32, |total, record| {
                    total.checked_add(u32::try_from(record.len()).ok()?)
                });
                let Some(required_len) = required_len else {
                    return NtStatus::INVALID_PARAMETER;
                };

                Self::write_sized_system_information(
                    system_information,
                    system_information_length,
                    return_length,
                    required_len,
                    move |system_information| {
                        let mut offset = 0;
                        for record in records {
                            system_information
                                .write_slice_at_offset(offset, record)
                                .ok_or(NtStatus::ACCESS_VIOLATION)?;
                            offset = offset.wrapping_add_unsigned(record.len());
                        }
                        Ok(())
                    },
                )
            }
        }
    }

    fn write_system_information<T: Immutable + IntoBytes>(
        system_information: MutPtr<Platform, u8>,
        system_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
        information: &T,
    ) -> NtStatus {
        let required_len = size_of::<T>().trunc();
        Self::write_sized_system_information(
            system_information,
            system_information_length,
            return_length,
            required_len,
            |system_information| {
                system_information
                    .write_slice_at_offset(0, information.as_bytes())
                    .ok_or(NtStatus::ACCESS_VIOLATION)
            },
        )
    }

    fn write_exact_system_information<T: Immutable + IntoBytes>(
        system_information: MutPtr<Platform, u8>,
        system_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
        information: &T,
    ) -> NtStatus {
        let required_len = size_of::<T>().trunc();
        if system_information_length != required_len {
            return Self::write_return_length_for_short_buffer(return_length, required_len);
        }

        Self::write_system_information(
            system_information,
            system_information_length,
            return_length,
            information,
        )
    }

    fn write_numa_processor_map_information(
        system_information: MutPtr<Platform, u8>,
        system_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        if system_information_length < DWORD_SIZE_U32 {
            return Self::write_return_length_for_short_buffer(return_length, DWORD_SIZE_U32);
        }

        if system_information_length < size_of::<SystemNumaInformation>().trunc() {
            let highest_node_number =
                MutPtr::<Platform, u32>::from_usize(system_information.as_usize());
            if highest_node_number.write_at_offset(0, 0).is_none() {
                return NtStatus::ACCESS_VIOLATION;
            }
            if Self::write_return_length(return_length, DWORD_SIZE_U32).is_err() {
                return NtStatus::ACCESS_VIOLATION;
            }
            return NtStatus::SUCCESS;
        }

        Self::write_system_information(
            system_information,
            system_information_length,
            return_length,
            &system_numa_information(),
        )
    }

    fn write_system_verifier_information(
        system_information: MutPtr<Platform, u8>,
        system_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        if system_information_length < SYSTEM_VERIFIER_INFORMATION_LENGTH {
            return Self::write_return_length_for_short_buffer(
                return_length,
                SYSTEM_VERIFIER_INFORMATION_LENGTH,
            );
        }

        let verifier_information = [0u8; SYSTEM_VERIFIER_INFORMATION_LENGTH_USIZE];
        if system_information
            .write_slice_at_offset(0, &verifier_information)
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if Self::write_return_length(return_length, 0).is_err() {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    fn write_sized_system_information(
        system_information: MutPtr<Platform, u8>,
        system_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
        required_len: u32,
        write_payload: impl FnOnce(MutPtr<Platform, u8>) -> Result<(), NtStatus>,
    ) -> NtStatus {
        if system_information_length < required_len {
            return Self::write_return_length_for_short_buffer(return_length, required_len);
        }
        if let Err(status) = write_payload(system_information) {
            return status;
        }
        if Self::write_return_length(return_length, required_len).is_err() {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    fn write_return_length_for_short_buffer(
        return_length: Option<MutPtr<Platform, u32>>,
        required_len: u32,
    ) -> NtStatus {
        if Self::write_return_length(return_length, required_len).is_err() {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::INFO_LENGTH_MISMATCH
    }

    fn write_return_length(
        return_length: Option<MutPtr<Platform, u32>>,
        required_len: u32,
    ) -> Result<(), NtStatus> {
        if let Some(return_length) = return_length
            && return_length.write_at_offset(0, required_len).is_none()
        {
            return Err(NtStatus::ACCESS_VIOLATION);
        }
        Ok(())
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
        allocation_granularity: ALLOCATION_GRANULARITY.trunc(),
        _padding0: 0,
        minimum_user_mode_address: <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MIN,
        maximum_user_mode_address,
        active_processors_affinity_mask: PROCESSOR_AFFINITY_MASK,
        number_of_processors: NUMBER_OF_PROCESSORS,
        _padding1: [0; 7],
    }
}

fn system_processor_information() -> SystemProcessorInformation {
    // TODO: x64 Windows reports AMD64 architecture with family/level 6 for modern
    // x86-64 CPUs. The revision and feature bitmap are synthetic.
    SystemProcessorInformation {
        processor_architecture: PROCESSOR_ARCHITECTURE_AMD64,
        processor_level: 6,
        processor_revision: 0,
        maximum_processors: u16::from(NUMBER_OF_PROCESSORS),
        processor_feature_bits: 0,
    }
}

fn system_numa_information() -> SystemNumaInformation {
    let mut active_processors_group_affinity = [GroupAffinity {
        mask: 0,
        group: 0,
        reserved: [0; 3],
    }; NUMA_NODE_COUNT];
    active_processors_group_affinity[0] = processor_group_affinity();

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
        mask: PROCESSOR_AFFINITY_MASK,
        group: 0,
        reserved: [0; 3],
    }
}

fn processor_relationship_information(
    relationship: LogicalProcessorRelationship,
) -> ProcessorRelationshipInformation {
    ProcessorRelationshipInformation {
        relationship: relationship as u32,
        size: size_of::<ProcessorRelationshipInformation>().trunc(),
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
        relationship: LogicalProcessorRelationship::NumaNode as u32,
        size: size_of::<NumaNodeRelationshipInformation>().trunc(),
        numa_node: NumaNodeRelationship {
            node_number: 0,
            reserved: [0; 18],
            group_count: 1,
            group_mask: processor_group_affinity(),
        },
    }
}

fn cache_relationship_information() -> CacheRelationshipInformation {
    // Deliberate sandbox topology: one generic L1 unified cache for one synthetic processor.
    // The relationship ABI follows WDK winnt.h; the field values avoid leaking host cache details.
    CacheRelationshipInformation {
        relationship: LogicalProcessorRelationship::Cache as u32,
        size: size_of::<CacheRelationshipInformation>().trunc(),
        cache: CacheRelationship {
            level: 1,
            associativity: 0xff,
            line_size: 64,
            cache_size: 32 * 1024,
            cache_type: CACHE_UNIFIED,
            reserved: [0; 18],
            group_count: 1,
            group_mask: processor_group_affinity(),
        },
    }
}

fn group_relationship_information() -> GroupRelationshipInformation {
    GroupRelationshipInformation {
        relationship: LogicalProcessorRelationship::Group as u32,
        size: size_of::<GroupRelationshipInformation>().trunc(),
        group: GroupRelationship {
            maximum_group_count: 1,
            active_group_count: 1,
            reserved: [0; 20],
            group_info: [ProcessorGroupInfo {
                maximum_processor_count: NUMBER_OF_PROCESSORS,
                active_processor_count: NUMBER_OF_PROCESSORS,
                reserved: [0; 38],
                active_processor_mask: PROCESSOR_AFFINITY_MASK,
            }],
        },
    }
}

fn duration_as_qpc_ticks(duration: core::time::Duration) -> i64 {
    i64::try_from(duration.as_nanos().min(i64::MAX as u128)).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{const_ptr, mut_byte_ptr, mut_ptr, null_const_ptr, null_mut_ptr};
    use core::time::Duration;
    use litebox::platform::ThreadProvider;

    extern crate std;

    const QPC_SLEEP_DURATION: Duration = Duration::from_millis(25);
    const QPC_SLEEP_TOLERANCE: Duration = Duration::from_millis(10);

    type TestPlatform = crate::tests::TestPlatform;
    type TestTask = Task<TestPlatform, crate::tests::TestFS>;

    const LOGICAL_PROCESSOR_ALL_INFORMATION_SIZE: usize =
        size_of::<ProcessorRelationshipInformation>() * 2
            + size_of::<NumaNodeRelationshipInformation>()
            + size_of::<CacheRelationshipInformation>()
            + size_of::<GroupRelationshipInformation>();

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    unsafe extern "system" {
        fn NtQuerySystemInformation(
            system_information_class: u32,
            system_information: *mut core::ffi::c_void,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> i32;

        fn NtQuerySystemInformationEx(
            system_information_class: u32,
            input_buffer: *const core::ffi::c_void,
            input_buffer_length: u32,
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

    fn const_byte_ptr<T>(value: &T) -> ConstPtr<TestPlatform, u8> {
        ConstPtr::<TestPlatform, u8>::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    #[test]
    fn nt_query_system_information_ex_validates_query_input() {
        run_with_test_platform_pointers(|| {
            let relationship = LogicalProcessorRelationship::All as u32;
            let mut output = [0u8; size_of::<ProcessorRelationshipInformation>()];
            let mut return_length = 0;

            assert_eq!(
                TestTask::sys_nt_query_system_information_ex(
                    SystemInformationClass::LogicalProcessorAndGroup as u32,
                    None,
                    DWORD_SIZE_U32,
                    mut_byte_ptr(&mut output),
                    u32::try_from(output.len()).unwrap(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INVALID_PARAMETER
            );
            assert_eq!(return_length, 0);

            assert_eq!(
                TestTask::sys_nt_query_system_information_ex(
                    SystemInformationClass::LogicalProcessorAndGroup as u32,
                    Some(const_byte_ptr(&relationship)),
                    DWORD_SIZE_U32 - 1,
                    mut_byte_ptr(&mut output),
                    u32::try_from(output.len()).unwrap(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INVALID_PARAMETER
            );

            assert_eq!(
                TestTask::sys_nt_query_system_information_ex(
                    SystemInformationClass::LogicalProcessorAndGroup as u32,
                    Some(null_const_ptr()),
                    DWORD_SIZE_U32,
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
            let query = LogicalProcessorRelationship::All as u32;
            let mut output = [0u8; size_of::<ProcessorRelationshipInformation>()];

            assert_eq!(
                TestTask::sys_nt_query_system_information_ex(
                    SystemInformationClass::Basic as u32,
                    Some(const_byte_ptr(&query)),
                    DWORD_SIZE_U32,
                    mut_byte_ptr(&mut output),
                    u32::try_from(output.len()).unwrap(),
                    None,
                ),
                NtStatus::INVALID_INFO_CLASS
            );

            assert_eq!(
                TestTask::sys_nt_query_system_information_ex(
                    SystemInformationClass::FeatureConfigurationSection as u32,
                    Some(const_byte_ptr(&query)),
                    DWORD_SIZE_U32,
                    mut_byte_ptr(&mut output),
                    u32::try_from(output.len()).unwrap(),
                    None,
                ),
                NtStatus::INVALID_INFO_CLASS
            );

            assert_eq!(
                TestTask::sys_nt_query_system_information_ex(
                    u32::MAX,
                    None,
                    0,
                    mut_byte_ptr(&mut output),
                    u32::try_from(output.len()).unwrap(),
                    None,
                ),
                NtStatus::INVALID_PARAMETER
            );

            assert_eq!(
                TestTask::sys_nt_query_system_information_ex(
                    u32::MAX,
                    Some(const_byte_ptr(&query)),
                    DWORD_SIZE_U32,
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
            let relationship = LogicalProcessorRelationship::All as u32;
            let mut output = [0u8; 1];
            let mut return_length = 0;
            assert_eq!(
                TestTask::sys_nt_query_system_information_ex(
                    SystemInformationClass::LogicalProcessorAndGroup as u32,
                    Some(const_byte_ptr(&relationship)),
                    DWORD_SIZE_U32,
                    mut_byte_ptr(&mut output),
                    0,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                return_length,
                u32::try_from(LOGICAL_PROCESSOR_ALL_INFORMATION_SIZE).unwrap()
            );
        });
    }

    #[test]
    fn nt_query_system_information_reports_basic_information() {
        run_with_test_platform_pointers(|| {
            let mut info = empty_basic_information();
            let mut return_length = 0;

            assert_eq!(
                TestTask::sys_nt_query_system_information(
                    SystemInformationClass::Basic as u32,
                    mut_byte_ptr(&mut info),
                    size_of::<SystemBasicInformation>().trunc(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );

            assert_eq!(return_length, size_of::<SystemBasicInformation>().trunc());
            assert_eq!(info.page_size, u32::try_from(PAGE_SIZE).unwrap());
            assert_eq!(
                info.allocation_granularity,
                u32::try_from(ALLOCATION_GRANULARITY).unwrap()
            );
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
    fn nt_query_system_information_validates_class_and_buffer_length() {
        run_with_test_platform_pointers(|| {
            let mut info = [0u8; size_of::<SystemBasicInformation>()];
            let mut return_length = 0;
            let basic_len: u32 = size_of::<SystemBasicInformation>().trunc();

            assert_eq!(
                TestTask::sys_nt_query_system_information(
                    SystemInformationClass::Basic as u32,
                    mut_byte_ptr(&mut info),
                    basic_len - 1,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(return_length, basic_len);

            assert_eq!(
                TestTask::sys_nt_query_system_information(
                    SystemInformationClass::Basic as u32,
                    mut_byte_ptr(&mut info),
                    basic_len + 1,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(return_length, basic_len);

            assert_eq!(
                TestTask::sys_nt_query_system_information(
                    u32::MAX,
                    mut_byte_ptr(&mut info),
                    u32::try_from(info.len()).unwrap(),
                    None,
                ),
                NtStatus::INVALID_INFO_CLASS
            );
        });
    }

    #[test]
    fn nt_query_system_information_reports_partial_numa_processor_map() {
        run_with_test_platform_pointers(|| {
            let mut highest_node_number = u32::MAX;
            let mut return_length = 0;

            assert_eq!(
                TestTask::sys_nt_query_system_information(
                    SystemInformationClass::NumaProcessorMap as u32,
                    mut_byte_ptr(&mut highest_node_number),
                    DWORD_SIZE_U32,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(highest_node_number, 0);
            assert_eq!(return_length, DWORD_SIZE_U32);
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
            let information_length = size_of::<SystemBasicInformation>().trunc();

            // SAFETY: The output buffer and return-length pointer are valid locals and ntdll does
            // not retain them.
            let host_basic_status = unsafe {
                host_status(NtQuerySystemInformation(
                    SystemInformationClass::Basic as u32,
                    host_info.as_mut_ptr().cast(),
                    information_length,
                    &raw mut host_return_length,
                ))
            };
            let guest_status = TestTask::sys_nt_query_system_information(
                SystemInformationClass::Basic as u32,
                mut_byte_ptr(&mut guest_info),
                information_length,
                Some(mut_ptr(&mut guest_return_length)),
            );
            assert_eq!(guest_status, host_basic_status);
            assert_eq!(guest_return_length, host_return_length);
            assert_eq!(guest_info.page_size, u32::try_from(PAGE_SIZE).unwrap());
            assert_eq!(
                guest_info.allocation_granularity,
                u32::try_from(ALLOCATION_GRANULARITY).unwrap()
            );

            let mut host_short_return_length = 0;
            let mut guest_short_return_length = 0;
            // SAFETY: Passing a short valid output buffer probes host ntdll's length handling; all
            // pointers are valid local variables.
            let host_short_status = unsafe {
                host_status(NtQuerySystemInformation(
                    SystemInformationClass::Basic as u32,
                    host_info.as_mut_ptr().cast(),
                    information_length - 1,
                    &raw mut host_short_return_length,
                ))
            };
            let guest_short_status = TestTask::sys_nt_query_system_information(
                SystemInformationClass::Basic as u32,
                mut_byte_ptr(&mut guest_info),
                information_length - 1,
                Some(mut_ptr(&mut guest_short_return_length)),
            );
            assert_eq!(guest_short_status, host_short_status);
            assert_eq!(guest_short_return_length, host_short_return_length);
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_query_system_information_fixed_class_lengths_match_host_ntdll() {
        fn query_host(
            class: SystemInformationClass,
            output: &mut [u8],
            return_length: &mut u32,
        ) -> NtStatus {
            // SAFETY: The output buffer and return-length pointer are valid locals and ntdll does
            // not retain them.
            unsafe {
                host_status(NtQuerySystemInformation(
                    class as u32,
                    output.as_mut_ptr().cast(),
                    u32::try_from(output.len()).unwrap(),
                    return_length,
                ))
            }
        }

        run_with_test_platform_pointers(|| {
            let cases = [
                (
                    SystemInformationClass::Processor,
                    size_of::<SystemProcessorInformation>(),
                ),
                (
                    SystemInformationClass::RangeStart,
                    size_of::<SystemRangeStartInformation>(),
                ),
                (
                    SystemInformationClass::Verifier,
                    SYSTEM_VERIFIER_INFORMATION_LENGTH_USIZE,
                ),
                (
                    SystemInformationClass::NumaProcessorMap,
                    size_of::<SystemNumaInformation>(),
                ),
                (
                    SystemInformationClass::EmulationBasic,
                    size_of::<SystemBasicInformation>(),
                ),
                (
                    SystemInformationClass::Flush,
                    size_of::<SystemFlushInformation>(),
                ),
                (
                    SystemInformationClass::HypervisorSharedPage,
                    size_of::<SystemHypervisorSharedPageInformation>(),
                ),
                (
                    SystemInformationClass::ProcessorFeaturesBitMap,
                    size_of::<SystemProcessorFeaturesBitMapInformation>(),
                ),
            ];

            for (class, length) in cases {
                let mut host_output = std::vec![0u8; length];
                let mut guest_output = std::vec![0u8; length];
                let mut host_return_length = 0;
                let mut guest_return_length = 0;
                let information_length = u32::try_from(length).unwrap();

                let host_status = query_host(class, &mut host_output, &mut host_return_length);
                let guest_status = TestTask::sys_nt_query_system_information(
                    class as u32,
                    mut_byte_ptr(&mut guest_output[0]),
                    information_length,
                    Some(mut_ptr(&mut guest_return_length)),
                );

                assert_eq!(guest_status, host_status, "{class:?}");
                assert_eq!(guest_return_length, host_return_length, "{class:?}");
            }

            let exact_length_cases = [
                (
                    SystemInformationClass::Basic,
                    size_of::<SystemBasicInformation>(),
                ),
                (
                    SystemInformationClass::EmulationBasic,
                    size_of::<SystemBasicInformation>(),
                ),
                (
                    SystemInformationClass::RangeStart,
                    size_of::<SystemRangeStartInformation>(),
                ),
            ];

            for (class, length) in exact_length_cases {
                let mut host_output = std::vec![0u8; length + 1];
                let mut guest_output = std::vec![0u8; length + 1];
                let mut host_return_length = 0;
                let mut guest_return_length = 0;
                let information_length = u32::try_from(length + 1).unwrap();

                let host_status = query_host(class, &mut host_output, &mut host_return_length);
                let guest_status = TestTask::sys_nt_query_system_information(
                    class as u32,
                    mut_byte_ptr(&mut guest_output[0]),
                    information_length,
                    Some(mut_ptr(&mut guest_return_length)),
                );

                assert_eq!(guest_status, host_status, "{class:?}");
                assert_eq!(guest_return_length, host_return_length, "{class:?}");
            }
        });
    }

    #[test]
    fn nt_query_system_information_does_not_publish_return_length_before_output_probe() {
        run_with_test_platform_pointers(|| {
            let mut return_length = u32::MAX;

            assert_eq!(
                TestTask::sys_nt_query_system_information(
                    SystemInformationClass::Basic as u32,
                    null_mut_ptr(),
                    size_of::<SystemBasicInformation>().trunc(),
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::ACCESS_VIOLATION
            );
            assert_eq!(return_length, u32::MAX);
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_query_system_information_null_output_return_length_order_matches_host_ntdll() {
        run_with_test_platform_pointers(|| {
            let mut host_return_length = u32::MAX;
            let mut guest_return_length = u32::MAX;
            let information_length = size_of::<SystemBasicInformation>().trunc();

            // SAFETY: This intentionally passes a null output buffer to probe host ntdll's
            // NTSTATUS and return-length ordering; the return-length pointer is a valid local.
            let host_status = unsafe {
                host_status(NtQuerySystemInformation(
                    SystemInformationClass::Basic as u32,
                    core::ptr::null_mut(),
                    information_length,
                    &raw mut host_return_length,
                ))
            };
            let guest_status = TestTask::sys_nt_query_system_information(
                SystemInformationClass::Basic as u32,
                null_mut_ptr(),
                information_length,
                Some(mut_ptr(&mut guest_return_length)),
            );

            assert_eq!(guest_status, host_status);
            assert_eq!(guest_return_length, host_return_length);
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_query_system_information_ex_input_validation_order_matches_host_ntdll() {
        run_with_test_platform_pointers(|| {
            let query = LogicalProcessorRelationship::All as u32;
            let mut host_output = [0u8; size_of::<ProcessorRelationshipInformation>()];
            let mut guest_output = [0u8; size_of::<ProcessorRelationshipInformation>()];
            let mut host_return_length = u32::MAX;
            let mut guest_return_length = u32::MAX;

            // SAFETY: This intentionally passes a null input buffer to probe host ntdll's
            // validation order. Output and return-length pointers are valid locals.
            let host_null_status = unsafe {
                host_status(NtQuerySystemInformationEx(
                    SystemInformationClass::Basic as u32,
                    core::ptr::null(),
                    0,
                    host_output.as_mut_ptr().cast(),
                    u32::try_from(host_output.len()).unwrap(),
                    &raw mut host_return_length,
                ))
            };
            let guest_null_status = TestTask::sys_nt_query_system_information_ex(
                SystemInformationClass::Basic as u32,
                None,
                0,
                mut_byte_ptr(&mut guest_output),
                u32::try_from(guest_output.len()).unwrap(),
                Some(mut_ptr(&mut guest_return_length)),
            );
            assert_eq!(guest_null_status, host_null_status);
            assert_eq!(guest_null_status, NtStatus::INVALID_PARAMETER);
            assert_eq!(guest_return_length, u32::MAX);

            // SAFETY: This uses a valid input DWORD and local output buffers to confirm that
            // class validation still happens after the required input-buffer check succeeds.
            let host_unknown_status = unsafe {
                host_status(NtQuerySystemInformationEx(
                    u32::MAX,
                    core::ptr::from_ref(&query).cast(),
                    DWORD_SIZE_U32,
                    host_output.as_mut_ptr().cast(),
                    u32::try_from(host_output.len()).unwrap(),
                    &raw mut host_return_length,
                ))
            };
            let guest_unknown_status = TestTask::sys_nt_query_system_information_ex(
                u32::MAX,
                Some(const_byte_ptr(&query)),
                DWORD_SIZE_U32,
                mut_byte_ptr(&mut guest_output),
                u32::try_from(guest_output.len()).unwrap(),
                Some(mut_ptr(&mut guest_return_length)),
            );
            assert_eq!(guest_unknown_status, host_unknown_status);
            assert_eq!(guest_unknown_status, NtStatus::INVALID_INFO_CLASS);
            assert_eq!(guest_return_length, u32::MAX);
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_query_system_information_ex_logical_processor_status_matches_host_ntdll() {
        fn query_host(relationship: u32, output: &mut [u8], return_length: &mut u32) -> NtStatus {
            // SAFETY: This Windows-only test passes valid local input, output, and length pointers
            // to ntdll and ntdll does not retain them.
            unsafe {
                host_status(NtQuerySystemInformationEx(
                    SystemInformationClass::LogicalProcessorAndGroup as u32,
                    core::ptr::from_ref(&relationship).cast(),
                    DWORD_SIZE_U32,
                    output.as_mut_ptr().cast(),
                    u32::try_from(output.len()).unwrap(),
                    return_length,
                ))
            }
        }

        run_with_test_platform_pointers(|| {
            let mut host_output = [0u8; 4096];
            let mut guest_output = [0u8; LOGICAL_PROCESSOR_ALL_INFORMATION_SIZE];
            let mut host_return_length = 0;
            let mut guest_return_length = 0;

            let host_all_status = query_host(
                LogicalProcessorRelationship::All as u32,
                &mut host_output,
                &mut host_return_length,
            );
            let all_relationship = LogicalProcessorRelationship::All as u32;
            let guest_all_status = TestTask::sys_nt_query_system_information_ex(
                SystemInformationClass::LogicalProcessorAndGroup as u32,
                Some(const_byte_ptr(&all_relationship)),
                DWORD_SIZE_U32,
                mut_byte_ptr(&mut guest_output),
                u32::try_from(guest_output.len()).unwrap(),
                Some(mut_ptr(&mut guest_return_length)),
            );
            assert_eq!(guest_all_status, host_all_status);
            assert_eq!(guest_all_status, NtStatus::SUCCESS);
            assert!(host_return_length > 0);
            assert_eq!(
                guest_return_length,
                u32::try_from(guest_output.len()).unwrap()
            );

            host_return_length = 0;
            guest_return_length = 0;
            let host_cache_status = query_host(
                LogicalProcessorRelationship::Cache as u32,
                &mut host_output,
                &mut host_return_length,
            );
            let cache_relationship = LogicalProcessorRelationship::Cache as u32;
            let guest_cache_status = TestTask::sys_nt_query_system_information_ex(
                SystemInformationClass::LogicalProcessorAndGroup as u32,
                Some(const_byte_ptr(&cache_relationship)),
                DWORD_SIZE_U32,
                mut_byte_ptr(&mut guest_output),
                u32::try_from(guest_output.len()).unwrap(),
                Some(mut_ptr(&mut guest_return_length)),
            );
            assert_eq!(guest_cache_status, host_cache_status);
            assert_eq!(guest_cache_status, NtStatus::SUCCESS);
            assert!(host_return_length >= size_of::<CacheRelationshipInformation>().trunc());
            assert_eq!(
                guest_return_length,
                size_of::<CacheRelationshipInformation>().trunc()
            );

            host_return_length = u32::MAX;
            guest_return_length = u32::MAX;
            let host_unknown_status =
                query_host(u32::MAX, &mut host_output, &mut host_return_length);
            let guest_unknown_status = TestTask::sys_nt_query_system_information_ex(
                SystemInformationClass::LogicalProcessorAndGroup as u32,
                Some(const_byte_ptr(&u32::MAX)),
                DWORD_SIZE_U32,
                mut_byte_ptr(&mut guest_output),
                u32::try_from(guest_output.len()).unwrap(),
                Some(mut_ptr(&mut guest_return_length)),
            );
            assert_eq!(guest_unknown_status, host_unknown_status);
            assert_eq!(guest_return_length, u32::MAX);
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_query_system_information_ex_feature_configuration_section_is_not_fabricated() {
        run_with_test_platform_pointers(|| {
            let request = [0u64; 4];
            let mut host_output = [0u8; 0x68];
            let mut guest_output = [0u8; 0x68];
            let mut host_return_length = 0;
            let mut guest_return_length = u32::MAX;

            // SAFETY: This Windows-only test passes valid local input, output, and length pointers
            // to ntdll and ntdll does not retain them.
            let host_status = unsafe {
                host_status(NtQuerySystemInformationEx(
                    SystemInformationClass::FeatureConfigurationSection as u32,
                    core::ptr::from_ref(&request).cast(),
                    u32::try_from(core::mem::size_of_val(&request)).unwrap(),
                    host_output.as_mut_ptr().cast(),
                    u32::try_from(host_output.len()).unwrap(),
                    &raw mut host_return_length,
                ))
            };
            if host_status == NtStatus::SUCCESS {
                assert_eq!(
                    host_return_length,
                    u32::try_from(host_output.len()).unwrap()
                );
                assert!(host_output.iter().any(|byte| *byte != 0));
            }

            assert_eq!(
                TestTask::sys_nt_query_system_information_ex(
                    SystemInformationClass::FeatureConfigurationSection as u32,
                    Some(const_byte_ptr(&request)),
                    u32::try_from(core::mem::size_of_val(&request)).unwrap(),
                    mut_byte_ptr(&mut guest_output),
                    u32::try_from(guest_output.len()).unwrap(),
                    Some(mut_ptr(&mut guest_return_length)),
                ),
                NtStatus::INVALID_INFO_CLASS
            );
            assert_eq!(guest_return_length, u32::MAX);
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
                TestTask::sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                    0,
                    null_const_ptr(),
                    mut_ptr(&mut destination),
                    Some(mut_ptr(&mut conversion_error)),
                ),
                NtStatus::ACCESS_VIOLATION
            );
            assert_eq!(
                TestTask::sys_nt_convert_between_auxiliary_counter_and_performance_counter(
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
                TestTask::sys_nt_convert_between_auxiliary_counter_and_performance_counter(
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
                TestTask::sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                    0,
                    const_ptr(&source),
                    mut_ptr(&mut destination),
                    Some(mut_ptr(&mut conversion_error)),
                );
            assert_eq!(guest_valid_source_status, host_valid_source_status);
        });
    }
}
