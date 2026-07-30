// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use core::marker::PhantomData;
use core::mem::size_of;

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::Handle;
use crate::nt_types::{ProcessEnvironmentBlock, ThreadEnvironmentBlock, UnicodeString};
use crate::{ConstPtr, MutPtr, ShimFS, ShimPlatform, Task, probe_guest_output_preserving_value};

const CSR_MAX_MESSAGE_LENGTH: u32 = 0x148;
const CSR_SERVER_PROCESS_ID: usize = 1;
const CSR_API_MESSAGE_LENGTH: u16 = 0x58;
const CSR_API_DATA_LENGTH: u16 = 0x30;
const USERSRV_SERVER_DLL_INDEX: u32 = 3;
const USER_CONNECT_VERSION: u64 = 0x0e41_05d9;
const USER_CONNECT_TRAILING_VALUE: u64 = 0x6658;
const USER_HANDLE_ENTRY_SIZE: u32 = 0x20;
const USERSRV_BACKING_SIZE: usize = crate::PAGE_SIZE;
const USERSRV_BACKING_ALIGNMENT: usize = 0x20;
// TODO(csr-server-dll-names): report names once the CSR connect contract models them.
const CSR_NUMBER_OF_SERVER_DLL_NAMES: u32 = 0;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct AlpcMessageFlags: u32 {
        const REPLY_MESSAGE = 0x0000_0001;
        const LPC_MODE = 0x0000_0002;
        const RELEASE_MESSAGE = 0x0001_0000;
        const SYNC_REQUEST = 0x0002_0000;
        const TRACK_PORT_REFERENCES = 0x0004_0000;
        const WAIT_USER_MODE = 0x0010_0000;
        const WAIT_ALERTABLE = 0x0020_0000;
        const SIGNAL_ALERTABLE = 0x0040_0000;
        const INTERNAL_REJECT = 0x0100_0000;
        const WOW64_CALL = 0x8000_0000;

        const _ = !0;
    }
}

pub(crate) struct LpcPortSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: ShimPlatform> FdEnabledSubsystem for LpcPortSubsystem<Platform> {
    type Entry = LpcPortHandleObject;
}

impl FdEnabledSubsystemEntry for LpcPortHandleObject {}

impl<Platform: ShimPlatform> crate::WindowsHandleSubsystem for LpcPortSubsystem<Platform> {
    fn normalize_desired_access(desired_access: u32) -> u32 {
        desired_access
    }

    fn resolve_duplicate_access(
        _entry: &Self::Entry,
        desired_access: u32,
    ) -> Result<u32, NtStatus> {
        Ok(desired_access & !crate::nt_types::AccessMask::MAXIMUM_ALLOWED.bits())
    }
}

pub(crate) struct LpcPortHandleObject {
    _port_name: String,
    usersrv_backing_base: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct SecurityQualityOfService {
    length: u32,
    impersonation_level: u32,
    context_tracking_mode: u8,
    effective_only: u8,
    padding: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct PortView {
    length: u32,
    padding: u32,
    section_handle: Handle,
    section_offset: u64,
    view_size: usize,
    view_base: usize,
    view_remote_base: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct RemotePortView {
    length: u32,
    padding: u32,
    view_size: usize,
    view_base: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct CsrApiConnectInfo {
    shared_section_base: usize,
    shared_static_server_data: usize,
    shared_section_heap: usize,
    debug_flags: u32,
    size_of_peb_data: u32,
    size_of_teb_data: u32,
    number_of_server_dll_names: u32,
    server_process_id: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct PortMessage {
    data_length: u16,
    total_length: u16,
    message_type: u16,
    data_info_offset: u16,
    client_id: [usize; 2],
    message_id: u32,
    padding: u32,
    client_view_size: usize,
}

const _: () = assert!(size_of::<PortMessage>() == 0x28);

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct CsrClientConnect {
    server_dll_index: u32,
    padding: u32,
    connection_info: usize,
    connection_info_size: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct CsrApiMessage {
    header: PortMessage,
    capture_data: usize,
    api_number: u32,
    status: i32,
    reserved: u32,
    padding: u32,
    client_connect: CsrClientConnect,
}

const _: () = assert!(size_of::<CsrApiMessage>() == CSR_API_MESSAGE_LENGTH as usize);

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct UserWindowMessage {
    max_messages: usize,
    message_bits: usize,
}

impl UserWindowMessage {
    const fn new(max_messages: usize, message_bits: usize) -> Self {
        Self {
            max_messages,
            message_bits,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct UserSharedInfo {
    server_info: usize,
    handle_entries: usize,
    handle_entry_size: u32,
    padding: u32,
    display_info: usize,
    shared_data: usize,
    reserved_message_0: UserWindowMessage,
    reserved: [u8; 0x10],
    reserved_message_1: UserWindowMessage,
    reserved_message_2: UserWindowMessage,
    padding_2: [u8; 0x30],
    control_messages: [UserWindowMessage; 24],
    default_window_messages: UserWindowMessage,
    default_window_spec_messages: UserWindowMessage,
}

const _: () = assert!(size_of::<UserSharedInfo>() == 0x238);

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct UserConnect {
    version: u64,
    shared_info: UserSharedInfo,
    trailing_value: u64,
}

const _: () = assert!(size_of::<UserConnect>() == 0x248);

pub(crate) struct ConnectPortParameters<Platform: ShimPlatform> {
    pub(crate) port_handle: MutPtr<Platform, Handle>,
    pub(crate) port_name: ConstPtr<Platform, UnicodeString>,
    pub(crate) security_qos: ConstPtr<Platform, SecurityQualityOfService>,
    pub(crate) client_view: Option<MutPtr<Platform, PortView>>,
    pub(crate) server_view: Option<MutPtr<Platform, RemotePortView>>,
    pub(crate) max_message_length: Option<MutPtr<Platform, u32>>,
    pub(crate) connection_information: Option<MutPtr<Platform, u8>>,
    pub(crate) connection_information_length: Option<MutPtr<Platform, u32>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_connect_port(&self, params: ConnectPortParameters<Platform>) -> NtStatus {
        if params.security_qos.read_at_offset(0).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        let port_name = match params
            .port_name
            .read_at_offset(0)
            .ok_or(NtStatus::ACCESS_VIOLATION)
            .and_then(UnicodeString::read_string::<Platform>)
        {
            Ok(name) => name,
            Err(status) => return status,
        };
        if let Err(status) = self.process.object_manager.resolve_port(&port_name) {
            return status;
        }

        let Some(client_view) = params.client_view else {
            return NtStatus::INVALID_PARAMETER;
        };
        let Some(connection_information) = params.connection_information else {
            return NtStatus::INVALID_PARAMETER;
        };
        let Some(connection_information_length) = params.connection_information_length else {
            return NtStatus::INVALID_PARAMETER;
        };

        let Some(client_view_value) = client_view.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if client_view_value.length as usize != size_of::<PortView>()
            || client_view_value.section_offset != 0
            || client_view_value.view_size == 0
        {
            return NtStatus::INVALID_PARAMETER;
        }
        let server_view_value = match params.server_view {
            Some(server_view) => match server_view.read_at_offset(0) {
                Some(view) if view.length as usize == size_of::<RemotePortView>() => Some(view),
                Some(_) => return NtStatus::INVALID_PARAMETER,
                None => return NtStatus::ACCESS_VIOLATION,
            },
            None => None,
        };

        let connection_info_len = match connection_information_length.read_at_offset(0) {
            Some(length) => length as usize,
            None => return NtStatus::ACCESS_VIOLATION,
        };
        if connection_info_len != size_of::<CsrApiConnectInfo>() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }

        if let Err(status) = probe_lpc_outputs::<Platform>(
            params.port_handle,
            client_view,
            params.server_view,
            params.max_message_length,
            connection_information,
            connection_information_length,
            connection_info_len,
        ) {
            return status;
        }

        let Some(connect_info) = self.csr_api_connect_info() else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let mapped_view = match self.map_client_port_section(
            client_view_value.section_handle,
            client_view_value.view_size,
        ) {
            Ok(mapped_view) => mapped_view,
            Err(status) => return status,
        };
        let Some(client_view_size) = mapped_view.view_size.checked_sub(USERSRV_BACKING_SIZE) else {
            self.rollback_pagefile_section_view(mapped_view.base);
            return NtStatus::INVALID_VIEW_SIZE;
        };
        if client_view_size == 0 {
            self.rollback_pagefile_section_view(mapped_view.base);
            return NtStatus::INVALID_VIEW_SIZE;
        }
        let usersrv_backing_base = mapped_view.base + client_view_size;
        if let Err(status) = zero_guest_usersrv_backing::<Platform>(usersrv_backing_base) {
            self.rollback_pagefile_section_view(mapped_view.base);
            return status;
        }
        let port = LpcPortHandleObject {
            _port_name: port_name.clone(),
            usersrv_backing_base,
        };
        let handle = match self.insert_typed_handle::<LpcPortSubsystem<Platform>>(port, 0, drop) {
            Ok(handle) => handle,
            Err(status) => {
                self.rollback_pagefile_section_view(mapped_view.base);
                return status;
            }
        };

        let mut written_client_view = client_view_value;
        written_client_view.view_size = client_view_size;
        written_client_view.view_base = mapped_view.base;
        written_client_view.view_remote_base = mapped_view.base;

        let write_failed = client_view
            .write_at_offset(0, written_client_view)
            .is_none()
            || params
                .max_message_length
                .is_some_and(|ptr| ptr.write_at_offset(0, CSR_MAX_MESSAGE_LENGTH).is_none())
            || connection_information
                .write_slice_at_offset(0, connect_info.as_bytes())
                .is_none()
            || connection_information_length
                .write_at_offset(0, size_of::<CsrApiConnectInfo>().trunc())
                .is_none()
            || params.port_handle.write_at_offset(0, handle).is_none();
        if write_failed {
            self.close_lpc_port_handle(handle);
            self.rollback_pagefile_section_view(mapped_view.base);
            return NtStatus::ACCESS_VIOLATION;
        }

        if let (Some(server_view), Some(mut server_view_value)) =
            (params.server_view, server_view_value)
        {
            server_view_value.view_size = mapped_view.mapped_size;
            server_view_value.view_base = mapped_view.base;
            if server_view.write_at_offset(0, server_view_value).is_none() {
                self.close_lpc_port_handle(handle);
                self.rollback_pagefile_section_view(mapped_view.base);
                return NtStatus::ACCESS_VIOLATION;
            }
        }

        litebox_util_log::debug!(
            port_name:% = port_name,
            handle:% = format_args!("{:#x}", handle.as_raw()),
            client_view_base:% = format_args!("{:#x}", mapped_view.base),
            client_view_size;
            "Handled NtConnectPort for CSR API port"
        );
        NtStatus::SUCCESS
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sys_nt_alpc_send_wait_receive_port(
        &self,
        port_handle: Handle,
        flags: AlpcMessageFlags,
        send_message: MutPtr<Platform, CsrApiMessage>,
        send_message_attributes: Option<ConstPtr<Platform, u8>>,
        receive_message: MutPtr<Platform, CsrApiMessage>,
        buffer_length: MutPtr<Platform, usize>,
        receive_message_attributes: Option<MutPtr<Platform, u8>>,
        timeout: Option<ConstPtr<Platform, i64>>,
    ) -> NtStatus {
        if !flags.contains(AlpcMessageFlags::SYNC_REQUEST)
            || flags
                .intersects(AlpcMessageFlags::RELEASE_MESSAGE | AlpcMessageFlags::INTERNAL_REJECT)
            || send_message_attributes.is_some()
            || receive_message_attributes.is_some()
            || timeout.is_some()
            || send_message.as_usize() != receive_message.as_usize()
        {
            // TODO(alpc-async): model independent send/receive and attribute paths.
            return NtStatus::INVALID_PARAMETER;
        }

        let port = match self
            .typed_handle_entry_with_access::<LpcPortSubsystem<Platform>>(port_handle, 0)
        {
            Ok(entry) => entry.with_entry(|entry| entry.usersrv_backing_base),
            Err(status) => return status,
        };
        let Some(mut message) = send_message.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let Some(receive_capacity) = buffer_length.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if receive_capacity < size_of::<CsrApiMessage>() {
            return NtStatus::BUFFER_TOO_SMALL;
        }
        if message.header.data_length != CSR_API_DATA_LENGTH
            || message.header.total_length != CSR_API_MESSAGE_LENGTH
            || message.header.message_type != 0
            || message.header.data_info_offset != 0
            || message.api_number != 0
            || message.client_connect.server_dll_index != USERSRV_SERVER_DLL_INDEX
            || message.client_connect.connection_info_size != size_of::<UserConnect>()
        {
            // TODO(csr-api-dispatch): dispatch other CSR APIs and server DLLs.
            return NtStatus::INVALID_PARAMETER;
        }

        if probe_guest_output_preserving_value::<Platform, CsrApiMessage>(receive_message).is_err()
            || probe_guest_output_preserving_value::<Platform, usize>(buffer_length).is_err()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        let connection_info =
            MutPtr::<Platform, UserConnect>::from_usize(message.client_connect.connection_info);
        if probe_guest_output_preserving_value::<Platform, UserConnect>(connection_info).is_err() {
            return NtStatus::ACCESS_VIOLATION;
        }

        let Some(user_connect) = build_user_connect(port) else {
            return NtStatus::INVALID_VIEW_SIZE;
        };
        // TODO(usersrv-shared-content): populate real win32k shared data when USER APIs need it.
        // TODO(usersrv-ro-section): move this backing to a read-only shared mapping.
        if connection_info.write_at_offset(0, user_connect).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        message.header.message_type = 2;
        message.status = NtStatus::SUCCESS.as_raw();
        if receive_message.write_at_offset(0, message).is_none()
            || buffer_length
                .write_at_offset(0, size_of::<CsrApiMessage>())
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn close_lpc_port_handle(&self, handle: Handle) {
        self.close_typed_handle::<LpcPortSubsystem<Platform>>(handle, drop);
    }

    pub(crate) fn close_lpc_port(port: LpcPortHandleObject) {
        drop(port);
    }

    fn csr_api_connect_info(&self) -> Option<CsrApiConnectInfo> {
        let read_only_shared_memory_base = crate::read_field_at_offset::<Platform, usize>(
            self.process.peb_address,
            core::mem::offset_of!(ProcessEnvironmentBlock, read_only_shared_memory_base),
        )?;
        let read_only_static_server_data = crate::read_field_at_offset::<Platform, usize>(
            self.process.peb_address,
            core::mem::offset_of!(ProcessEnvironmentBlock, read_only_static_server_data),
        )?;
        Some(CsrApiConnectInfo {
            shared_section_base: read_only_shared_memory_base,
            shared_static_server_data: read_only_static_server_data,
            shared_section_heap: read_only_shared_memory_base,
            debug_flags: 0,
            size_of_peb_data: size_of::<ProcessEnvironmentBlock>().trunc(),
            size_of_teb_data: size_of::<ThreadEnvironmentBlock>().trunc(),
            number_of_server_dll_names: CSR_NUMBER_OF_SERVER_DLL_NAMES,
            server_process_id: CSR_SERVER_PROCESS_ID,
        })
    }
}

fn zero_guest_usersrv_backing<Platform: RawPointerProvider>(
    backing_base: usize,
) -> Result<(), NtStatus> {
    let zeros = [0u8; 0x100];
    let backing = MutPtr::<Platform, u8>::from_usize(backing_base);
    for offset in (0..USERSRV_BACKING_SIZE).step_by(zeros.len()) {
        backing
            .write_slice_at_offset(
                offset.try_into().map_err(|_| NtStatus::INVALID_PARAMETER)?,
                &zeros,
            )
            .ok_or(NtStatus::ACCESS_VIOLATION)?;
    }
    Ok(())
}

fn build_user_connect(backing_base: usize) -> Option<UserConnect> {
    let mut backing_offset = 0usize;
    let mut allocate = |size: usize| {
        let size = size.checked_next_multiple_of(USERSRV_BACKING_ALIGNMENT)?;
        let next_offset = backing_offset.checked_add(size)?;
        if next_offset > USERSRV_BACKING_SIZE {
            return None;
        }
        let pointer = backing_base.checked_add(backing_offset)?;
        backing_offset = next_offset;
        Some(pointer)
    };
    let server_info = allocate(USERSRV_BACKING_ALIGNMENT)?;
    let handle_entries = allocate(USERSRV_BACKING_ALIGNMENT)?;
    let display_info = allocate(USERSRV_BACKING_ALIGNMENT)?;
    let shared_data = allocate(USERSRV_BACKING_ALIGNMENT)?;
    let mut window_message = |max_messages: usize| {
        Some(UserWindowMessage::new(
            max_messages,
            if max_messages == 0 {
                0
            } else {
                allocate(max_messages.div_ceil(8))?
            },
        ))
    };
    let reserved_message_0 = window_message(0x318)?;
    let reserved_message_1 = window_message(0x318)?;
    let reserved_message_2 = window_message(0x14)?;
    let mut control_messages = [UserWindowMessage::new(0, 0); 24];
    for (index, max_messages) in [
        0x318usize, 0x318, 0x318, 0x402, 0x318, 0x318, 0, 0x318, 0x288, 0x82,
    ]
    .into_iter()
    .enumerate()
    {
        control_messages[index] = window_message(max_messages)?;
    }

    Some(UserConnect {
        version: USER_CONNECT_VERSION,
        shared_info: UserSharedInfo {
            server_info,
            handle_entries,
            handle_entry_size: USER_HANDLE_ENTRY_SIZE,
            padding: 0,
            display_info,
            shared_data,
            reserved_message_0,
            reserved: [0; 0x10],
            reserved_message_1,
            reserved_message_2,
            padding_2: [0; 0x30],
            control_messages,
            default_window_messages: window_message(0x33f)?,
            default_window_spec_messages: window_message(0x349)?,
        },
        trailing_value: USER_CONNECT_TRAILING_VALUE,
    })
}

fn probe_lpc_outputs<Platform: ShimPlatform>(
    port_handle: MutPtr<Platform, Handle>,
    client_view: MutPtr<Platform, PortView>,
    server_view: Option<MutPtr<Platform, RemotePortView>>,
    max_message_length: Option<MutPtr<Platform, u32>>,
    connection_information: MutPtr<Platform, u8>,
    connection_information_length: MutPtr<Platform, u32>,
    connection_information_len: usize,
) -> Result<(), NtStatus> {
    probe_guest_output_preserving_value::<Platform, Handle>(port_handle)?;
    probe_guest_output_preserving_value::<Platform, PortView>(client_view)?;
    if let Some(server_view) = server_view {
        probe_guest_output_preserving_value::<Platform, RemotePortView>(server_view)?;
    }
    if let Some(max_message_length) = max_message_length {
        probe_guest_output_preserving_value::<Platform, u32>(max_message_length)?;
    }
    probe_guest_byte_buffer_preserving::<Platform>(
        connection_information,
        connection_information_len,
        size_of::<CsrApiConnectInfo>(),
    )?;
    probe_guest_output_preserving_value::<Platform, u32>(connection_information_length)
}

fn probe_guest_byte_buffer_preserving<Platform: ShimPlatform>(
    ptr: MutPtr<Platform, u8>,
    len: usize,
    max_len: usize,
) -> Result<(), NtStatus> {
    if len > max_len {
        return Err(NtStatus::INFO_LENGTH_MISMATCH);
    }
    let bytes = ptr.to_owned_slice(len).ok_or(NtStatus::ACCESS_VIOLATION)?;
    ptr.write_slice_at_offset(0, bytes.as_ref())
        .ok_or(NtStatus::ACCESS_VIOLATION)
}

#[cfg(test)]
mod tests {
    use zerocopy::FromZeros as _;

    use super::*;
    use crate::syscalls::mm::PageProtection;
    use crate::syscalls::object_manager::WINDOWS_API_PORT;
    use crate::tests::{
        TestFS, TestPlatform, const_ptr, mut_byte_ptr, mut_ptr, test_task, unicode_string,
        utf16_units,
    };

    const SECTION_MAP_WRITE: u32 = 0x0002;
    const SECTION_MAP_READ: u32 = 0x0004;
    const SEC_COMMIT: u32 = 0x0800_0000;

    fn task_with_peb(peb: &mut ProcessEnvironmentBlock) -> Task<TestPlatform, TestFS> {
        let mut task = test_task();
        alloc::sync::Arc::get_mut(&mut task.process)
            .expect("test task has a unique process reference")
            .peb_address = core::ptr::from_mut(peb) as usize;
        task
    }

    fn security_qos() -> SecurityQualityOfService {
        SecurityQualityOfService {
            length: size_of::<SecurityQualityOfService>().trunc(),
            impersonation_level: 2,
            context_tracking_mode: 0,
            effective_only: 1,
            padding: [0; 2],
        }
    }

    fn api_port_name(value: &str) -> (alloc::vec::Vec<u16>, UnicodeString) {
        let units = utf16_units(value);
        let unicode = unicode_string(&units);
        (units, unicode)
    }

    fn empty_connect_info() -> CsrApiConnectInfo {
        CsrApiConnectInfo {
            shared_section_base: 0,
            shared_static_server_data: 0,
            shared_section_heap: 0,
            debug_flags: 0,
            size_of_peb_data: 0,
            size_of_teb_data: 0,
            number_of_server_dll_names: 0,
            server_process_id: 0,
        }
    }

    fn create_client_section(task: &Task<TestPlatform, TestFS>, access: u32) -> Handle {
        let mut handle = Handle::default();
        let size = i64::try_from(crate::PAGE_SIZE * 2).expect("test section size fits in i64");
        assert_eq!(
            task.sys_nt_create_section(
                mut_ptr(&mut handle),
                access,
                None,
                Some(const_ptr(&size)),
                PageProtection::PAGE_READWRITE.bits(),
                SEC_COMMIT,
                Handle::default(),
            ),
            NtStatus::SUCCESS
        );
        handle
    }

    #[test]
    fn nt_connect_port_and_usersrv_alpc_reply_match_guest_contract() {
        let mut peb = ProcessEnvironmentBlock::new_zeroed();
        peb.read_only_shared_memory_base = 0x7000_0000;
        peb.read_only_static_server_data = 0x7000_1000;
        peb.csr_server_read_only_shared_memory_base = 0x7100_0000;
        let task = task_with_peb(&mut peb);
        let (_name_units, name) = api_port_name(WINDOWS_API_PORT);
        let qos = security_qos();
        let section_handle = create_client_section(&task, SECTION_MAP_READ | SECTION_MAP_WRITE);
        let mut handle = Handle::default();
        let mut client_view = PortView {
            length: size_of::<PortView>().trunc(),
            padding: 0,
            section_handle,
            section_offset: 0,
            view_size: crate::PAGE_SIZE * 2,
            view_base: 0,
            view_remote_base: 0,
        };
        let mut max_message_length = 0u32;
        let mut connection_info = empty_connect_info();
        let mut connection_info_len = size_of::<CsrApiConnectInfo>().trunc();

        assert_eq!(
            task.sys_nt_connect_port(ConnectPortParameters {
                port_handle: mut_ptr(&mut handle),
                port_name: const_ptr(&name),
                security_qos: const_ptr(&qos),
                client_view: Some(mut_ptr(&mut client_view)),
                server_view: None,
                max_message_length: Some(mut_ptr(&mut max_message_length)),
                connection_information: Some(mut_byte_ptr(&mut connection_info)),
                connection_information_length: Some(mut_ptr(&mut connection_info_len)),
            }),
            NtStatus::SUCCESS
        );

        assert!(!handle.is_null());
        assert_ne!(client_view.view_base, 0);
        assert_eq!(client_view.view_remote_base, client_view.view_base);
        assert_eq!(max_message_length, CSR_MAX_MESSAGE_LENGTH);
        assert_eq!(
            connection_info.shared_section_base,
            peb.read_only_shared_memory_base
        );
        assert_eq!(
            connection_info.shared_static_server_data,
            peb.read_only_static_server_data
        );
        assert_ne!(
            u64::try_from(connection_info.shared_section_base).unwrap(),
            peb.csr_server_read_only_shared_memory_base
        );
        assert_eq!(
            connection_info.size_of_peb_data,
            size_of::<ProcessEnvironmentBlock>().trunc()
        );
        assert_eq!(
            connection_info.size_of_teb_data,
            size_of::<ThreadEnvironmentBlock>().trunc()
        );

        let mut usersrv_info = UserConnect::new_zeroed();
        let mut message = CsrApiMessage::new_zeroed();
        message.header.data_length = CSR_API_DATA_LENGTH;
        message.header.total_length = CSR_API_MESSAGE_LENGTH;
        message.client_connect.server_dll_index = USERSRV_SERVER_DLL_INDEX;
        message.client_connect.connection_info = core::ptr::from_mut(&mut usersrv_info) as usize;
        message.client_connect.connection_info_size = size_of::<UserConnect>();
        let mut receive_capacity = 0x3b8usize;

        assert_eq!(
            task.sys_nt_alpc_send_wait_receive_port(
                handle,
                AlpcMessageFlags::SYNC_REQUEST,
                mut_ptr(&mut message),
                None,
                mut_ptr(&mut message),
                mut_ptr(&mut receive_capacity),
                None,
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(message.header.message_type, 2);
        assert_eq!(message.status, NtStatus::SUCCESS.as_raw());
        assert_eq!(receive_capacity, size_of::<CsrApiMessage>());
        assert_eq!(usersrv_info.version, USER_CONNECT_VERSION);
        assert_eq!(
            usersrv_info.shared_info.handle_entry_size,
            USER_HANDLE_ENTRY_SIZE
        );
        assert_eq!(
            usersrv_info.shared_info.control_messages[3].max_messages,
            0x402
        );
        assert_eq!(
            usersrv_info
                .shared_info
                .default_window_messages
                .max_messages,
            0x33f
        );
        assert_eq!(usersrv_info.trailing_value, USER_CONNECT_TRAILING_VALUE);
        for pointer in [
            usersrv_info.shared_info.server_info,
            usersrv_info.shared_info.handle_entries,
            usersrv_info.shared_info.display_info,
            usersrv_info.shared_info.shared_data,
        ] {
            assert_ne!(pointer, 0);
            assert_eq!(
                ConstPtr::<TestPlatform, u8>::from_usize(pointer).read_at_offset(0),
                Some(0)
            );
        }
    }
}
