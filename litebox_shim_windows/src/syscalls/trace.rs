// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::mem::size_of;

use int_enum::IntEnum;
use litebox::platform::RawConstPointer as _;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::Guid;
use crate::syscalls::Handle;
use crate::syscalls::event::{EventAccess, EventSubsystem};
use crate::{ConstPtr, MutPtr, ShimFS, ShimPlatform, Task};

const ETW_NT_TRACE_TYPE_MASK: u32 = 0x0000_ff00;
const USER_LOADER_PROVIDER_ID: Guid = Guid {
    // {b059b83f-d946-4b13-87ca-4292839dc2f2}, in native GUID byte order.
    data: [
        0x3f, 0xb8, 0x59, 0xb0, 0x46, 0xd9, 0x13, 0x4b, 0x87, 0xca, 0x42, 0x92, 0x83, 0x9d, 0xc2,
        0xf2,
    ],
};

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum EtwNtTraceType {
    Header = 0x0000_0100,
    Message = 0x0000_0200,
    Event = 0x0000_0300,
    System = 0x0000_0400,
    Security = 0x0000_0500,
    Mark = 0x0000_0600,
    EventNoRegistration = 0x0000_0700,
    Instance = 0x0000_0800,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum EtwTraceControlCode {
    AddNotificationEvent = 27,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct EtwNtTraceModifiers: u32 {
        const USE_NATIVE_HEADER = 0x4000_0000;
        const WOW64_CALL = 0x8000_0000;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct EventHeaderFlags: u16 {
        const EXTENDED_INFO = 0x0001;
        const PRIVATE_SESSION = 0x0002;
        const STRING_ONLY = 0x0004;
        const TRACE_MESSAGE = 0x0008;
        const NO_CPUTIME = 0x0010;
        const HEADER_32_BIT = 0x0020;
        const HEADER_64_BIT = 0x0040;
        const CLASSIC_HEADER = 0x0100;
        const PROCESSOR_INDEX = 0x0200;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct EventDescriptor {
    id: u16,
    version: u8,
    channel: u8,
    level: u8,
    opcode: u8,
    task: u16,
    keyword: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct EventHeader {
    size: u16,
    header_type: u16,
    flags: u16,
    event_property: u16,
    thread_id: u32,
    process_id: u32,
    timestamp: i64,
    provider_id: Guid,
    event_descriptor: EventDescriptor,
    processor_time: u64,
    activity_id: Guid,
}

const _: () = assert!(size_of::<EventDescriptor>() == 16);
const _: () = assert!(size_of::<EventHeader>() == 80);

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_trace_control(
        &self,
        function_code: u32,
        input_buffer: ConstPtr<Platform, u32>,
        input_buffer_length: u32,
        output_buffer: Option<MutPtr<Platform, u8>>,
        output_buffer_length: u32,
        _return_length: MutPtr<Platform, u32>,
    ) -> NtStatus {
        let Ok(EtwTraceControlCode::AddNotificationEvent) =
            EtwTraceControlCode::try_from(function_code)
        else {
            // TODO(etw-trace-control): Model logger and provider control operations.
            litebox_util_log::debug!(function_code; "Unsupported NtTraceControl operation");
            return NtStatus::NOT_SUPPORTED;
        };
        if input_buffer_length != u32::try_from(size_of::<u32>()).unwrap()
            || output_buffer.is_some()
            || output_buffer_length != 0
        {
            return NtStatus::INVALID_PARAMETER;
        }
        let Some(event_handle) = input_buffer.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let entry = match self.typed_handle_entry_with_access::<EventSubsystem<Platform>>(
            Handle::from_raw(event_handle as usize),
            EventAccess::MODIFY_STATE.bits(),
        ) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        let event = entry.with_entry(|entry| entry.event.clone());
        let mut registered = self.process.trace_notification_event.lock();
        if registered.is_some() {
            return NtStatus::from_raw(0xc000_0718);
        }
        *registered = Some(event);
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_trace_event(
        &self,
        trace_handle: Handle,
        flags: u32,
        field_size: u32,
        fields: ConstPtr<Platform, EventHeader>,
    ) -> NtStatus {
        if trace_handle.is_null() {
            return NtStatus::INVALID_PARAMETER;
        }

        let modifiers = EtwNtTraceModifiers::from_bits_retain(flags & !ETW_NT_TRACE_TYPE_MASK);
        let known_flags = ETW_NT_TRACE_TYPE_MASK | EtwNtTraceModifiers::all().bits();
        if flags & !known_flags != 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        let Ok(trace_type) = EtwNtTraceType::try_from(flags & ETW_NT_TRACE_TYPE_MASK) else {
            return NtStatus::INVALID_PARAMETER;
        };
        if trace_type != EtwNtTraceType::EventNoRegistration {
            // TODO(etw-trace-types): model registered providers and logger sessions.
            return NtStatus::NOT_SUPPORTED;
        }

        let Some(ntdll) = self.process.ntdll else {
            return NtStatus::INVALID_PARAMETER;
        };
        let trace_handle = trace_handle.as_raw();
        let Some(ntdll_end) = ntdll
            .mapping
            .base_addr
            .checked_add(ntdll.mapping.image_size)
        else {
            return NtStatus::INVALID_PARAMETER;
        };
        let Some(provider_end) = trace_handle.checked_add(size_of::<Guid>()) else {
            return NtStatus::INVALID_PARAMETER;
        };
        if trace_handle < ntdll.mapping.base_addr || provider_end > ntdll_end {
            return NtStatus::INVALID_PARAMETER;
        }
        let Some(provider_id) =
            ConstPtr::<Platform, Guid>::from_usize(trace_handle).read_at_offset(0)
        else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if provider_id.data != USER_LOADER_PROVIDER_ID.data {
            return NtStatus::WMI_ALREADY_DISABLED;
        }

        if fields.as_usize() == 0 {
            return NtStatus::ACCESS_VIOLATION;
        }
        if field_size < u32::try_from(size_of::<EventHeader>()).unwrap() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        let Some(header) = fields.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };

        let header_flags = EventHeaderFlags::from_bits_retain(header.flags);
        litebox_util_log::debug!(
            trace_handle:% = format_args!("{trace_handle:#x}"),
            trace_type:? = trace_type,
            modifiers:? = modifiers,
            field_size,
            header_flags:? = header_flags,
            event_id = header.event_descriptor.id,
            event_version = header.event_descriptor.version,
            event_level = header.event_descriptor.level,
            event_opcode = header.event_descriptor.opcode;
            "Handled NtTraceEvent as local UserLoader ETW sink"
        );
        // Native Windows reports WMI_ALREADY_DISABLED when this provider has no
        // active session. LiteBox has no ETW consumers, so a validated UserLoader
        // event is consumed by the local sink instead of failing optional telemetry.
        NtStatus::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use litebox::platform::ThreadProvider;

    use super::*;
    use crate::syscalls::event::EventType;
    use crate::tests::{const_ptr, mut_ptr, null_const_ptr};

    type TestPlatform = crate::tests::TestPlatform;

    #[repr(C)]
    struct ProviderIds {
        user_loader: Guid,
        forged: Guid,
    }

    fn event_header() -> EventHeader {
        EventHeader {
            size: 0,
            header_type: 0,
            flags: EventHeaderFlags::HEADER_64_BIT.bits(),
            event_property: 0,
            thread_id: 1,
            process_id: 1,
            timestamp: 0,
            provider_id: Guid { data: [0; 16] },
            event_descriptor: EventDescriptor {
                id: 1,
                version: 0,
                channel: 0,
                level: 4,
                opcode: 0,
                task: 0,
                keyword: 0,
            },
            processor_time: 0,
            activity_id: Guid { data: [0; 16] },
        }
    }

    #[test]
    fn nt_trace_event_enforces_host_probed_handle_classes() {
        <TestPlatform as ThreadProvider>::run_test_thread(|| {
            let providers = ProviderIds {
                user_loader: USER_LOADER_PROVIDER_ID,
                forged: Guid { data: [0; 16] },
            };
            let base = core::ptr::from_ref(&providers) as usize;
            let mut task = crate::tests::test_task();
            Arc::get_mut(&mut task.process)
                .expect("test task has unique process")
                .ntdll = Some(crate::loader::NtDllInfo {
                mapping: litebox_common_windows::loader::MappingInfo {
                    base_addr: base,
                    image_size: size_of::<ProviderIds>(),
                    mapping_size: size_of::<ProviderIds>(),
                    entry_point: 0,
                },
                ldr_initialize_thunk: 0,
                rtl_user_thread_start: 0,
            });
            let header = event_header();
            let field_size = u32::try_from(size_of::<EventHeader>()).unwrap();
            let flags = EtwNtTraceType::EventNoRegistration as u32;

            assert_eq!(
                task.sys_nt_trace_event(Handle::default(), flags, field_size, const_ptr(&header)),
                NtStatus::INVALID_PARAMETER
            );
            assert_eq!(
                task.sys_nt_trace_event(
                    Handle::from_raw(base),
                    flags,
                    field_size,
                    const_ptr(&header),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(
                task.sys_nt_trace_event(
                    Handle::from_raw(base + size_of::<Guid>()),
                    flags,
                    field_size,
                    const_ptr(&header),
                ),
                NtStatus::WMI_ALREADY_DISABLED
            );
            assert_eq!(
                task.sys_nt_trace_event(
                    Handle::from_raw(base),
                    flags,
                    field_size,
                    null_const_ptr(),
                ),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[test]
    fn nt_trace_control_registers_one_notification_event() {
        let task = crate::tests::test_task();
        let mut event = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut event),
                EventAccess::MODIFY_STATE.bits(),
                None,
                EventType::Notification as u32,
                0,
            ),
            NtStatus::SUCCESS
        );
        let event_handle: u32 = event.as_raw().try_into().unwrap();
        let mut return_length = u32::MAX;
        assert_eq!(
            task.sys_nt_trace_control(
                EtwTraceControlCode::AddNotificationEvent as u32,
                const_ptr(&event_handle),
                4,
                None,
                0,
                mut_ptr(&mut return_length),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(return_length, u32::MAX);
        assert_eq!(
            task.sys_nt_trace_control(
                EtwTraceControlCode::AddNotificationEvent as u32,
                const_ptr(&event_handle),
                4,
                None,
                0,
                mut_ptr(&mut return_length),
            ),
            NtStatus::from_raw(0xc000_0718)
        );
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_trace_event_terminal_statuses_match_host() {
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtTraceEvent(
                trace_handle: usize,
                flags: u32,
                field_size: u32,
                fields: *const EventHeader,
            ) -> i32;
        }

        let header = event_header();
        let field_size = u32::try_from(size_of::<EventHeader>()).unwrap();
        let flags = EtwNtTraceType::EventNoRegistration as u32;
        // SAFETY: The host call receives either a null handle or valid local buffers
        // and does not retain any pointer after returning.
        let null_status =
            unsafe { NtStatus::from(NtTraceEvent(0, flags, field_size, &raw const header)) };
        let forged_status = unsafe {
            NtStatus::from(NtTraceEvent(
                core::ptr::from_ref(&header.provider_id) as usize,
                flags,
                field_size,
                &raw const header,
            ))
        };

        assert_eq!(null_status, NtStatus::INVALID_PARAMETER);
        assert_eq!(forged_status, NtStatus::WMI_ALREADY_DISABLED);
    }
}
