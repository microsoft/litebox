// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::{offset_of, size_of};
use core::sync::atomic::Ordering;
use int_enum::IntEnum;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox::utils::TruncateExt;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::ThreadEnvironmentBlock;
use crate::syscalls::ProcessHandle;
use crate::{ConstPtr, MutPtr, ShimFS, ShimPlatform, Task};

const ACTIVE_PROCESS_EXIT_STATUS: i32 = 0x0000_0103;
const NORMAL_PROCESS_BASE_PRIORITY: i32 = 8;
pub(crate) const INITIAL_PROCESS_ID: usize = 1;
pub(crate) const INITIAL_THREAD_ID: usize = 1;
const GUEST_PARENT_PROCESS_ID: usize = 0;
const GUEST_PROCESS_AFFINITY_MASK: usize = 1;
const PROCESS_DEBUG_FLAGS_NO_DEBUGGER: u32 = 1;
const PROCESS_COOKIE: u32 = 0xdead_beef;
const TEB_TLS_SLOT_COUNT: usize = 64;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum ProcessInformationClass {
    BasicInformation = 0,
    DebugPort = 7,
    DefaultHardErrorMode = 12,
    Wow64Information = 26,
    DebugFlags = 31,
    TlsInformation = 35,
    Cookie = 36,
    ConsoleHostProcess = 49,
    ImageInformation = 53,
    SchedulerSharedData = 112,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntEnum)]
enum ProcessTlsOperation {
    ReplaceIndex = 0,
    ReplaceVector = 1,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ProcessTlsThreadDataFlags: u32 {
        const OLD_DATA_WRITTEN = 0x2;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ProcessBasicInformation {
    exit_status: i32,
    _padding0: u32,
    peb_base_address: usize,
    affinity_mask: usize,
    base_priority: i32,
    _padding1: u32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ProcessDefaultHardErrorMode {
    default_hard_error_mode: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable)]
struct ProcessSchedulerSharedDataSlotInformation {
    scheduler_shared_data_handle: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ProcessTlsInformationHeader {
    flags: u32,
    operation_type: u32,
    thread_data_count: u32,
    tls_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ProcessTlsInformationExtendedHeader {
    header: ProcessTlsInformationHeader,
    _reserved: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ProcessTlsThreadDataSimple {
    flags: u32,
    _padding0: u32,
    tls_data: usize,
    _reserved: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ProcessTlsThreadDataExtended {
    flags: u32,
    _padding0: u32,
    new_tls_data: usize,
    old_tls_data: usize,
    _reserved: usize,
}

enum ProcessTlsThreadData<Platform: RawPointerProvider> {
    Simple(MutPtr<Platform, ProcessTlsThreadDataSimple>),
    Extended(MutPtr<Platform, ProcessTlsThreadDataExtended>),
}

impl<Platform: RawPointerProvider> ProcessTlsThreadData<Platform> {
    fn read_tls_data(&self) -> Option<usize> {
        match self {
            Self::Simple(ptr) => crate::read_field_at_offset::<Platform, _>(
                ptr.as_usize(),
                offset_of!(ProcessTlsThreadDataSimple, tls_data),
            ),
            Self::Extended(ptr) => crate::read_field_at_offset::<Platform, _>(
                ptr.as_usize(),
                offset_of!(ProcessTlsThreadDataExtended, new_tls_data),
            ),
        }
    }

    fn write_tls_data(&self, value: usize) -> Option<()> {
        match self {
            Self::Simple(ptr) => crate::write_field_at_offset::<Platform, _>(
                ptr.as_usize(),
                offset_of!(ProcessTlsThreadDataSimple, tls_data),
                value,
            ),
            Self::Extended(ptr) => crate::write_field_at_offset::<Platform, _>(
                ptr.as_usize(),
                offset_of!(ProcessTlsThreadDataExtended, old_tls_data),
                value,
            ),
        }
    }

    fn write_flags(&self, flags: ProcessTlsThreadDataFlags) -> Option<()> {
        match self {
            Self::Simple(ptr) => crate::write_field_at_offset::<Platform, _>(
                ptr.as_usize(),
                offset_of!(ProcessTlsThreadDataSimple, flags),
                flags.bits(),
            ),
            Self::Extended(ptr) => crate::write_field_at_offset::<Platform, _>(
                ptr.as_usize(),
                offset_of!(ProcessTlsThreadDataExtended, flags),
                flags.bits(),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ProcessTlsLayout {
    Simple,
    Extended,
}

impl ProcessTlsLayout {
    fn detect(thread_data_count: u32, process_information_length: u32) -> Result<Self, NtStatus> {
        let count = thread_data_count as usize;
        let extended_len = size_of::<ProcessTlsInformationExtendedHeader>()
            .checked_add(
                count
                    .checked_mul(size_of::<ProcessTlsThreadDataExtended>())
                    .ok_or(NtStatus::INFO_LENGTH_MISMATCH)?,
            )
            .ok_or(NtStatus::INFO_LENGTH_MISMATCH)?;
        let simple_len = size_of::<ProcessTlsInformationHeader>()
            .checked_add(
                count
                    .checked_mul(size_of::<ProcessTlsThreadDataSimple>())
                    .ok_or(NtStatus::INFO_LENGTH_MISMATCH)?,
            )
            .ok_or(NtStatus::INFO_LENGTH_MISMATCH)?;
        let provided_len = process_information_length as usize;

        if provided_len >= extended_len {
            Ok(Self::Extended)
        } else if provided_len >= simple_len {
            Ok(Self::Simple)
        } else {
            Err(NtStatus::INFO_LENGTH_MISMATCH)
        }
    }

    const fn header_size(self) -> usize {
        match self {
            Self::Simple => size_of::<ProcessTlsInformationHeader>(),
            Self::Extended => size_of::<ProcessTlsInformationExtendedHeader>(),
        }
    }

    const fn entry_size(self) -> usize {
        match self {
            Self::Simple => size_of::<ProcessTlsThreadDataSimple>(),
            Self::Extended => size_of::<ProcessTlsThreadDataExtended>(),
        }
    }

    const fn old_data_offset(self) -> usize {
        match self {
            Self::Simple => offset_of!(ProcessTlsThreadDataSimple, tls_data),
            Self::Extended => offset_of!(ProcessTlsThreadDataExtended, old_tls_data),
        }
    }

    fn thread_data<Platform: RawPointerProvider>(
        self,
        base: MutPtr<Platform, u8>,
        index: usize,
    ) -> Option<ProcessTlsThreadData<Platform>> {
        match self {
            Self::Simple => {
                let arr = MutPtr::<Platform, ProcessTlsThreadDataSimple>::from_usize(
                    base.as_usize().checked_add(
                        size_of::<ProcessTlsInformationHeader>()
                            + index.checked_mul(size_of::<ProcessTlsThreadDataSimple>())?,
                    )?,
                );
                Some(ProcessTlsThreadData::Simple(arr))
            }
            Self::Extended => {
                let arr = MutPtr::<Platform, ProcessTlsThreadDataExtended>::from_usize(
                    base.as_usize().checked_add(
                        size_of::<ProcessTlsInformationExtendedHeader>()
                            + index.checked_mul(size_of::<ProcessTlsThreadDataExtended>())?,
                    )?,
                );
                Some(ProcessTlsThreadData::Extended(arr))
            }
        }
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_query_information_process(
        &self,
        process_handle: ProcessHandle,
        process_information_class: u32,
        process_information: MutPtr<Platform, u8>,
        process_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        let Ok(process_information_class) =
            ProcessInformationClass::try_from(process_information_class)
        else {
            litebox_util_log::debug!(
                process_information_class = process_information_class;
                "Unsupported NtQueryInformationProcess class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        let status = match process_information_class {
            ProcessInformationClass::BasicInformation => Self::write_process_information(
                process_information,
                process_information_length,
                return_length,
                &self.process_basic_information(),
            ),
            ProcessInformationClass::DebugPort | ProcessInformationClass::Wow64Information => {
                Self::write_process_information(
                    process_information,
                    process_information_length,
                    return_length,
                    &0usize,
                )
            }
            ProcessInformationClass::DebugFlags => Self::write_process_information(
                process_information,
                process_information_length,
                return_length,
                &PROCESS_DEBUG_FLAGS_NO_DEBUGGER,
            ),
            ProcessInformationClass::DefaultHardErrorMode => Self::write_process_information(
                process_information,
                process_information_length,
                return_length,
                &ProcessDefaultHardErrorMode {
                    default_hard_error_mode: self
                        .process
                        .default_hard_error_mode
                        .load(Ordering::Acquire),
                },
            ),
            ProcessInformationClass::Cookie => Self::write_process_information(
                process_information,
                process_information_length,
                return_length,
                &self.process.cookie,
            ),
            ProcessInformationClass::ConsoleHostProcess
            | ProcessInformationClass::TlsInformation
            | ProcessInformationClass::ImageInformation
            | ProcessInformationClass::SchedulerSharedData => {
                litebox_util_log::debug!(
                    process_information_class:? = process_information_class;
                    "Unsupported NtQueryInformationProcess class"
                );
                NtStatus::INVALID_INFO_CLASS
            }
        };

        if status == NtStatus::SUCCESS {
            litebox_util_log::debug!(
                process_information_class:? = process_information_class,
                process_information_length = process_information_length;
                "Handled NtQueryInformationProcess syscall"
            );
        }

        status
    }

    pub(crate) fn sys_nt_set_information_process(
        &self,
        process_handle: ProcessHandle,
        process_information_class: u32,
        process_information: MutPtr<Platform, u8>,
        process_information_length: u32,
    ) -> NtStatus {
        let Ok(process_information_class) =
            ProcessInformationClass::try_from(process_information_class)
        else {
            litebox_util_log::debug!(
                process_information_class = process_information_class;
                "Unsupported NtSetInformationProcess class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };

        let status = match process_information_class {
            ProcessInformationClass::SchedulerSharedData => {
                Self::set_process_scheduler_shared_data(
                    process_handle,
                    process_information,
                    process_information_length,
                )
            }
            ProcessInformationClass::TlsInformation => self.write_process_tls_information(
                process_handle,
                process_information,
                process_information_length,
            ),
            // TODO: implement additional settable process information classes when a guest
            // exercises them.
            ProcessInformationClass::BasicInformation
            | ProcessInformationClass::DebugPort
            | ProcessInformationClass::DefaultHardErrorMode
            | ProcessInformationClass::Wow64Information
            | ProcessInformationClass::DebugFlags
            | ProcessInformationClass::Cookie
            | ProcessInformationClass::ConsoleHostProcess
            | ProcessInformationClass::ImageInformation => {
                litebox_util_log::debug!(
                    process_information_class:? = process_information_class;
                    "Unsupported NtSetInformationProcess class"
                );
                NtStatus::INVALID_INFO_CLASS
            }
        };

        if status == NtStatus::SUCCESS {
            litebox_util_log::debug!(
                process_information_class:? = process_information_class,
                process_information_length = process_information_length;
                "Handled NtSetInformationProcess syscall"
            );
        }

        status
    }

    fn write_process_information<T: Immutable + IntoBytes>(
        process_information: MutPtr<Platform, u8>,
        process_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
        information: &T,
    ) -> NtStatus {
        let required_len = size_of::<T>().trunc();
        if process_information_length < required_len {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if process_information
            .write_slice_at_offset(0, information.as_bytes())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if let Some(return_length) = return_length
            && return_length.write_at_offset(0, required_len).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        NtStatus::SUCCESS
    }

    fn set_process_scheduler_shared_data(
        process_handle: ProcessHandle,
        process_information: MutPtr<Platform, u8>,
        process_information_length: u32,
    ) -> NtStatus {
        if process_information_length
            < size_of::<ProcessSchedulerSharedDataSlotInformation>().trunc()
        {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        let process_information =
            ConstPtr::<Platform, ProcessSchedulerSharedDataSlotInformation>::from_usize(
                process_information.as_usize(),
            );
        if process_information.read_at_offset(0).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        // Host 25H2 returns SUCCESS after probing this struct even when the inner scheduler
        // shared-data handle is null or bogus; LiteBox has no scheduler-shared-data object to bind.
        NtStatus::SUCCESS
    }

    fn write_process_tls_information(
        &self,
        process_handle: ProcessHandle,
        process_information: MutPtr<Platform, u8>,
        process_information_length: u32,
    ) -> NtStatus {
        if (process_information_length as usize) < size_of::<ProcessTlsInformationHeader>() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if !process_handle.is_current() {
            return NtStatus::INVALID_HANDLE;
        }

        let Some(header) = ConstPtr::<Platform, ProcessTlsInformationHeader>::from_usize(
            process_information.as_usize(),
        )
        .read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let layout =
            match ProcessTlsLayout::detect(header.thread_data_count, process_information_length) {
                Ok(layout) => layout,
                Err(status) => return status,
            };

        litebox_util_log::debug!(
            operation_type = header.operation_type,
            thread_data_count = header.thread_data_count,
            tls_index = header.tls_index,
            process_information_length,
            layout_header_size = layout.header_size(),
            layout_entry_size = layout.entry_size(),
            layout_old_data_offset = layout.old_data_offset();
            "Handling ProcessTlsInformation"
        );

        if header.thread_data_count > 1 {
            // TODO(multi-thread-tls): PROCESS_TLS_INFORMATION entries are positional per-thread
            // data. The shim currently models only the active TEB, so handling multiple entries
            // would corrupt prior TLS values by repeatedly writing one TEB's vector.
            return NtStatus::NOT_SUPPORTED;
        }

        match ProcessTlsOperation::try_from(header.operation_type) {
            Ok(ProcessTlsOperation::ReplaceVector) => {
                self.replace_tls_vector(process_information, header, layout)
            }
            Ok(ProcessTlsOperation::ReplaceIndex) => {
                self.replace_tls_index(process_information, header, layout)
            }
            Err(_) => {
                litebox_util_log::debug!(
                    operation_type = header.operation_type,
                    thread_data_count = header.thread_data_count,
                    tls_index = header.tls_index;
                    "Unsupported ProcessTlsInformation operation"
                );
                NtStatus::INVALID_INFO_CLASS
            }
        }
    }

    fn replace_tls_vector(
        &self,
        process_information: MutPtr<Platform, u8>,
        header: ProcessTlsInformationHeader,
        layout: ProcessTlsLayout,
    ) -> NtStatus {
        for index in 0..header.thread_data_count as usize {
            let Some(thread_data) = layout.thread_data::<Platform>(process_information, index)
            else {
                return NtStatus::INFO_LENGTH_MISMATCH;
            };
            let Some(new_tls_data) = thread_data.read_tls_data() else {
                return NtStatus::ACCESS_VIOLATION;
            };
            // TODO(multi-thread-tls): read ith thread's tls
            let teb = MutPtr::<Platform, ThreadEnvironmentBlock>::from_usize(self.teb_address);
            let Some(old_tls_data) = Self::read_teb_tls_pointer(teb) else {
                return NtStatus::ACCESS_VIOLATION;
            };

            litebox_util_log::debug!(
                thread_data_index = index,
                new_tls_data:% = format_args!("{new_tls_data:#x}"),
                old_tls_data:% = format_args!("{old_tls_data:#x}");
                "Replacing process TLS vector"
            );

            if let Err(status) = self.copy_initial_tls_slots(old_tls_data, new_tls_data) {
                return status;
            }
            let old_tls_data_for_guest = self.guest_visible_old_tls_vector(old_tls_data);

            if thread_data.write_tls_data(old_tls_data_for_guest).is_none()
                || Self::write_teb_tls_pointer(teb, new_tls_data).is_none()
            {
                return NtStatus::ACCESS_VIOLATION;
            }
            if old_tls_data_for_guest == 0
                && thread_data
                    .write_flags(ProcessTlsThreadDataFlags::OLD_DATA_WRITTEN)
                    .is_none()
            {
                return NtStatus::ACCESS_VIOLATION;
            }
        }

        NtStatus::SUCCESS
    }

    fn replace_tls_index(
        &self,
        process_information: MutPtr<Platform, u8>,
        header: ProcessTlsInformationHeader,
        layout: ProcessTlsLayout,
    ) -> NtStatus {
        let tls_index = header.tls_index as usize;
        if tls_index >= TEB_TLS_SLOT_COUNT {
            return NtStatus::INVALID_PARAMETER;
        }

        for index in 0..header.thread_data_count as usize {
            let Some(thread_data) = layout.thread_data::<Platform>(process_information, index)
            else {
                return NtStatus::INFO_LENGTH_MISMATCH;
            };
            let Some(new_tls_data) = thread_data.read_tls_data() else {
                return NtStatus::ACCESS_VIOLATION;
            };
            // TODO(multi-thread-tls): read ith thread's tls
            let teb = ConstPtr::<Platform, ThreadEnvironmentBlock>::from_usize(self.teb_address);
            let Some(tls_array) = Self::read_teb_tls_pointer(teb) else {
                return NtStatus::ACCESS_VIOLATION;
            };
            if tls_array == 0 {
                continue;
            }
            let tls_slots = MutPtr::<Platform, usize>::from_usize(tls_array);
            let Some(old_tls_data) = tls_slots.read_at_offset(tls_index.cast_signed()) else {
                return NtStatus::ACCESS_VIOLATION;
            };

            litebox_util_log::debug!(
                thread_data_index = index,
                tls_index,
                tls_array:% = format_args!("{tls_array:#x}"),
                new_tls_data:% = format_args!("{new_tls_data:#x}"),
                old_tls_data:% = format_args!("{old_tls_data:#x}");
                "Replacing process TLS index"
            );

            if thread_data.write_tls_data(old_tls_data).is_none()
                || tls_slots
                    .write_at_offset(tls_index.cast_signed(), new_tls_data)
                    .is_none()
                || thread_data
                    .write_flags(ProcessTlsThreadDataFlags::OLD_DATA_WRITTEN)
                    .is_none()
            {
                return NtStatus::ACCESS_VIOLATION;
            }
        }

        NtStatus::SUCCESS
    }

    fn guest_visible_old_tls_vector(&self, old_tls_data: usize) -> usize {
        if old_tls_data > 0x10010
            && old_tls_data >= self.teb_address
            && old_tls_data
                < self
                    .teb_address
                    .saturating_add(size_of::<ThreadEnvironmentBlock>())
        {
            // The loader frees the returned old vector. The initial vector lives inside
            // TEB.tls_slots, so report no heap-backed vector instead of exposing TEB memory.
            0
        } else {
            old_tls_data
        }
    }

    fn copy_initial_tls_slots(
        &self,
        old_tls_data: usize,
        new_tls_data: usize,
    ) -> Result<(), NtStatus> {
        if old_tls_data <= 0x10010 || new_tls_data <= 0x10010 {
            return Ok(());
        }
        let initial_tls_slots = self
            .teb_address
            .checked_add(offset_of!(ThreadEnvironmentBlock, tls_slots))
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if old_tls_data != initial_tls_slots {
            return Ok(());
        }
        let old_tls_slots = ConstPtr::<Platform, usize>::from_usize(old_tls_data);
        let new_tls_slots = MutPtr::<Platform, usize>::from_usize(new_tls_data);
        for index in 0..TEB_TLS_SLOT_COUNT.cast_signed() {
            let slot_value = old_tls_slots
                .read_at_offset(index)
                .ok_or(NtStatus::ACCESS_VIOLATION)?;
            new_tls_slots
                .write_at_offset(index, slot_value)
                .ok_or(NtStatus::ACCESS_VIOLATION)?;
        }

        Ok(())
    }

    fn read_teb_tls_pointer<Ptr: litebox::platform::RawConstPointer<ThreadEnvironmentBlock>>(
        teb: Ptr,
    ) -> Option<usize> {
        crate::read_field_at_offset::<Platform, _>(
            teb.as_usize(),
            offset_of!(ThreadEnvironmentBlock, thread_local_storage_pointer),
        )
    }

    fn write_teb_tls_pointer(
        teb: MutPtr<Platform, ThreadEnvironmentBlock>,
        value: usize,
    ) -> Option<()> {
        crate::write_field_at_offset::<Platform, _>(
            teb.as_usize(),
            offset_of!(ThreadEnvironmentBlock, thread_local_storage_pointer),
            value,
        )
    }

    fn process_basic_information(&self) -> ProcessBasicInformation {
        ProcessBasicInformation {
            exit_status: ACTIVE_PROCESS_EXIT_STATUS,
            _padding0: 0,
            peb_base_address: self.process.peb_address,
            affinity_mask: GUEST_PROCESS_AFFINITY_MASK,
            base_priority: NORMAL_PROCESS_BASE_PRIORITY,
            _padding1: 0,
            unique_process_id: INITIAL_PROCESS_ID,
            inherited_from_unique_process_id: GUEST_PARENT_PROCESS_ID,
        }
    }
}

pub(crate) const fn default_process_cookie() -> u32 {
    // TODO: use CrngProvider to generate a random cookie
    PROCESS_COOKIE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{mut_byte_ptr, mut_ptr, null_mut_ptr};
    use litebox::platform::ThreadProvider;

    const RETURN_LENGTH_SENTINEL: u32 = 0xaaaa_aaaa;

    type TestPlatform = crate::tests::TestPlatform;

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    #[test]
    fn nt_query_information_process_validates_arguments() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut info = [0u8; size_of::<ProcessBasicInformation>()];
            let mut return_length = 0;
            let basic_information_len: u32 = size_of::<ProcessBasicInformation>().trunc();

            assert_eq!(
                task.sys_nt_query_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::BasicInformation as u32,
                    mut_byte_ptr(&mut info),
                    basic_information_len - 1,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                return_length, 0,
                "ReactOS sets ReturnLength only after the exact-size check for this class; a host Windows probe shows the same result"
            );

            assert_eq!(
                task.sys_nt_query_information_process(
                    ProcessHandle::from_raw(0x1234),
                    ProcessInformationClass::BasicInformation as u32,
                    mut_byte_ptr(&mut info),
                    basic_information_len,
                    None,
                ),
                NtStatus::INVALID_HANDLE
            );

            assert_eq!(
                task.sys_nt_query_information_process(
                    ProcessHandle::CURRENT,
                    0xffff,
                    mut_byte_ptr(&mut info),
                    basic_information_len,
                    None,
                ),
                NtStatus::INVALID_INFO_CLASS
            );

            assert_eq!(
                task.sys_nt_query_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::BasicInformation as u32,
                    null_mut_ptr::<u8>(),
                    basic_information_len,
                    None,
                ),
                NtStatus::ACCESS_VIOLATION
            );

            return_length = RETURN_LENGTH_SENTINEL;
            assert_eq!(
                task.sys_nt_query_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::BasicInformation as u32,
                    null_mut_ptr::<u8>(),
                    basic_information_len,
                    Some(mut_ptr(&mut return_length)),
                ),
                NtStatus::ACCESS_VIOLATION
            );
            assert_eq!(
                return_length, RETURN_LENGTH_SENTINEL,
                "a host Windows probe leaves ReturnLength unchanged when ProcessInformation faults"
            );
        });
    }

    #[test]
    fn nt_set_information_process_scheduler_shared_data_validates_arguments() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut information = ProcessSchedulerSharedDataSlotInformation {
                scheduler_shared_data_handle: 0,
            };
            let information_len: u32 =
                size_of::<ProcessSchedulerSharedDataSlotInformation>().trunc();
            let bad_handle = ProcessHandle::from_raw(0x1234);

            assert_eq!(
                task.sys_nt_set_information_process(
                    bad_handle,
                    ProcessInformationClass::SchedulerSharedData as u32,
                    null_mut_ptr::<u8>(),
                    information_len - 1,
                ),
                NtStatus::INFO_LENGTH_MISMATCH
            );

            assert_eq!(
                task.sys_nt_set_information_process(
                    bad_handle,
                    0xffff,
                    mut_byte_ptr(&mut information),
                    information_len - 1,
                ),
                NtStatus::INVALID_INFO_CLASS
            );

            assert_eq!(
                task.sys_nt_set_information_process(
                    bad_handle,
                    ProcessInformationClass::SchedulerSharedData as u32,
                    null_mut_ptr::<u8>(),
                    information_len,
                ),
                NtStatus::INVALID_HANDLE
            );

            assert_eq!(
                task.sys_nt_set_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::SchedulerSharedData as u32,
                    null_mut_ptr::<u8>(),
                    information_len,
                ),
                NtStatus::ACCESS_VIOLATION
            );

            assert_eq!(
                task.sys_nt_set_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::SchedulerSharedData as u32,
                    mut_byte_ptr(&mut information),
                    information_len,
                ),
                NtStatus::SUCCESS
            );
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    mod host_fidelity {
        use core::ffi::c_void;

        use super::*;

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryInformationProcess(
                process_handle: *mut c_void,
                process_information_class: u32,
                process_information: *mut c_void,
                process_information_length: u32,
                return_length: *mut u32,
            ) -> i32;
            fn NtSetInformationProcess(
                process_handle: *mut c_void,
                process_information_class: u32,
                process_information: *const c_void,
                process_information_length: u32,
            ) -> i32;
        }

        fn empty_basic_information() -> ProcessBasicInformation {
            ProcessBasicInformation {
                exit_status: 0,
                _padding0: 0,
                peb_base_address: 0,
                affinity_mask: 0,
                base_priority: 0,
                _padding1: 0,
                unique_process_id: 0,
                inherited_from_unique_process_id: usize::MAX,
            }
        }

        fn host_nt_query_information_process(
            process_information_class: ProcessInformationClass,
            process_information: *mut c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> NtStatus {
            // SAFETY: The host ntdll call treats these as user-mode output pointers, probes them,
            // and does not retain them. Tests pass either valid locals or null to observe NTSTATUS
            // and output side effects.
            let status = unsafe {
                NtQueryInformationProcess(
                    usize::MAX as *mut c_void,
                    process_information_class as u32,
                    process_information,
                    process_information_length,
                    return_length,
                )
            };
            NtStatus::from_raw(u32::from_ne_bytes(status.to_ne_bytes()))
        }

        fn host_nt_set_information_process(
            process_handle: *mut c_void,
            process_information_class: u32,
            process_information: *const c_void,
            process_information_length: u32,
        ) -> NtStatus {
            // SAFETY: The host ntdll call treats these as user-mode input pointers, probes them,
            // and does not retain them. Tests pass either valid locals or null to observe NTSTATUS.
            let status = unsafe {
                NtSetInformationProcess(
                    process_handle,
                    process_information_class,
                    process_information,
                    process_information_length,
                )
            };
            NtStatus::from_raw(u32::from_ne_bytes(status.to_ne_bytes()))
        }

        #[test]
        fn nt_query_information_process_basic_length_mismatch_matches_host() {
            run_with_test_platform_pointers(|| {
                let task = crate::tests::test_task();
                let mut host_info = empty_basic_information();
                let mut shim_info = empty_basic_information();
                let mut host_return_length = RETURN_LENGTH_SENTINEL;
                let mut shim_return_length = RETURN_LENGTH_SENTINEL;
                let basic_information_len: u32 = size_of::<ProcessBasicInformation>().trunc();
                let short_length = basic_information_len - 1;

                let host = host_nt_query_information_process(
                    ProcessInformationClass::BasicInformation,
                    core::ptr::addr_of_mut!(host_info).cast::<c_void>(),
                    short_length,
                    core::ptr::addr_of_mut!(host_return_length),
                );
                let shim = task.sys_nt_query_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::BasicInformation as u32,
                    mut_byte_ptr(&mut shim_info),
                    short_length,
                    Some(mut_ptr(&mut shim_return_length)),
                );

                assert_eq!(shim, host);
                assert_eq!(shim_return_length, host_return_length);
                assert_eq!(shim_info.peb_base_address, 0);
            });
        }

        #[test]
        fn nt_query_information_process_invalid_output_leaves_return_length_unchanged() {
            run_with_test_platform_pointers(|| {
                let task = crate::tests::test_task();
                let mut host_return_length = RETURN_LENGTH_SENTINEL;
                let mut shim_return_length = RETURN_LENGTH_SENTINEL;
                let basic_information_len: u32 = size_of::<ProcessBasicInformation>().trunc();

                let host = host_nt_query_information_process(
                    ProcessInformationClass::BasicInformation,
                    core::ptr::null_mut(),
                    basic_information_len,
                    core::ptr::addr_of_mut!(host_return_length),
                );
                let shim = task.sys_nt_query_information_process(
                    ProcessHandle::CURRENT,
                    ProcessInformationClass::BasicInformation as u32,
                    null_mut_ptr::<u8>(),
                    basic_information_len,
                    Some(mut_ptr(&mut shim_return_length)),
                );

                assert_eq!(shim, host);
                assert_eq!(shim_return_length, host_return_length);
            });
        }

        #[test]
        fn nt_set_information_process_scheduler_shared_data_matches_host_statuses() {
            run_with_test_platform_pointers(|| {
                let mut null_information = ProcessSchedulerSharedDataSlotInformation {
                    scheduler_shared_data_handle: 0,
                };
                let mut bogus_information = ProcessSchedulerSharedDataSlotInformation {
                    scheduler_shared_data_handle: 0x1234,
                };
                let information_len: u32 =
                    size_of::<ProcessSchedulerSharedDataSlotInformation>().trunc();
                let current_process = usize::MAX as *mut c_void;
                let bad_process = 0x1234usize as *mut c_void;
                let scheduler_class = ProcessInformationClass::SchedulerSharedData as u32;
                let bad_class = 0xffff;

                let supported_status = host_nt_set_information_process(
                    current_process,
                    scheduler_class,
                    core::ptr::from_ref(&null_information).cast::<c_void>(),
                    information_len,
                );

                if supported_status != NtStatus::INVALID_INFO_CLASS {
                    assert_eq!(supported_status, NtStatus::SUCCESS);

                    for (
                        process_handle,
                        shim_process_handle,
                        process_information_class,
                        host_process_information,
                        shim_process_information,
                        process_information_length,
                    ) in [
                        (
                            current_process,
                            ProcessHandle::CURRENT,
                            scheduler_class,
                            core::ptr::from_ref(&null_information).cast::<c_void>(),
                            mut_byte_ptr(&mut null_information),
                            information_len,
                        ),
                        (
                            current_process,
                            ProcessHandle::CURRENT,
                            scheduler_class,
                            core::ptr::from_ref(&bogus_information).cast::<c_void>(),
                            mut_byte_ptr(&mut bogus_information),
                            information_len,
                        ),
                        (
                            current_process,
                            ProcessHandle::CURRENT,
                            scheduler_class,
                            core::ptr::from_ref(&null_information).cast::<c_void>(),
                            mut_byte_ptr(&mut null_information),
                            information_len - 1,
                        ),
                        (
                            current_process,
                            ProcessHandle::CURRENT,
                            scheduler_class,
                            core::ptr::null(),
                            null_mut_ptr::<u8>(),
                            information_len,
                        ),
                        (
                            current_process,
                            ProcessHandle::CURRENT,
                            bad_class,
                            core::ptr::from_ref(&null_information).cast::<c_void>(),
                            mut_byte_ptr(&mut null_information),
                            information_len,
                        ),
                        (
                            bad_process,
                            ProcessHandle::from_raw(0x1234),
                            scheduler_class,
                            core::ptr::from_ref(&null_information).cast::<c_void>(),
                            mut_byte_ptr(&mut null_information),
                            information_len,
                        ),
                        (
                            bad_process,
                            ProcessHandle::from_raw(0x1234),
                            scheduler_class,
                            core::ptr::null(),
                            null_mut_ptr::<u8>(),
                            information_len - 1,
                        ),
                        (
                            bad_process,
                            ProcessHandle::from_raw(0x1234),
                            bad_class,
                            core::ptr::from_ref(&null_information).cast::<c_void>(),
                            mut_byte_ptr(&mut null_information),
                            information_len - 1,
                        ),
                        (
                            bad_process,
                            ProcessHandle::from_raw(0x1234),
                            scheduler_class,
                            core::ptr::null(),
                            null_mut_ptr::<u8>(),
                            information_len,
                        ),
                        (
                            current_process,
                            ProcessHandle::CURRENT,
                            scheduler_class,
                            core::ptr::null(),
                            null_mut_ptr::<u8>(),
                            information_len - 1,
                        ),
                        (
                            current_process,
                            ProcessHandle::CURRENT,
                            bad_class,
                            core::ptr::from_ref(&null_information).cast::<c_void>(),
                            mut_byte_ptr(&mut null_information),
                            information_len - 1,
                        ),
                    ] {
                        let host = host_nt_set_information_process(
                            process_handle,
                            process_information_class,
                            host_process_information,
                            process_information_length,
                        );
                        let task = crate::tests::test_task();
                        let shim = task.sys_nt_set_information_process(
                            shim_process_handle,
                            process_information_class,
                            shim_process_information,
                            process_information_length,
                        );

                        assert_eq!(shim, host);
                    }
                }
            });
        }
    }
}
