// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::marker::PhantomData;
use core::mem::{align_of, size_of};

use int_enum::IntEnum;
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::Handle;
use crate::nt_types::{ProcessEnvironmentBlock, ThreadEnvironmentBlock, UnicodeString};
use crate::syscalls::object_manager::WINDOWS_API_PORT;
use crate::{ConstPtr, MutPtr, ShimFS, ShimPlatform, Task, probe_guest_output_preserving_value};

// Maximum total message length advertised by `\Windows\ApiPort` on the target x64 Windows build.
// TODO(csr-api-message-union): model the full CSR API message union and derive this from its size.
const CSR_MAX_MESSAGE_LENGTH: u32 = 0x148;
const CSR_SERVER_PROCESS_ID: usize = 1;
const USERSRV_SERVER_DLL_INDEX: u32 = 3;
const USER_CONNECT_VERSION: u64 = 0x0e41_05d9;
const USERSRV_BACKING_SIZE: usize = crate::PAGE_SIZE;
const USER_MESSAGE_BITMAP_ALIGNMENT: usize = 0x20;
const RESERVED_MESSAGE_MAX_MESSAGES: [usize; 3] = [0x318, 0x318, 0x14];
const FNID_MESSAGE_MAX_MESSAGES: [usize; 10] = [
    0x318, // FNID_SCROLLBAR
    0x318, // FNID_ICONTITLE
    0x318, // FNID_MENU
    0x402, // FNID_DESKTOP
    0x318, // FNID_DEFWINDOWPROC
    0x318, // FNID_MESSAGEWND
    0,     // FNID_SWITCH
    0x318, // FNID_BUTTON
    0x288, // FNID_COMBOBOX
    0x82,  // FNID_COMBOLBOX
];
const DEFAULT_WINDOW_MAX_MESSAGES: usize = 0x33f;
const DEFAULT_WINDOW_SPECIAL_MAX_MESSAGES: usize = 0x349;
// TODO(csr-server-dll-names): report names once the CSR connect contract models them.
const CSR_NUMBER_OF_SERVER_DLL_NAMES: u32 = 0;

const fn user_message_bitmap_storage_size(max_messages: usize) -> usize {
    let word_bits = u32::BITS as usize;
    let words = max_messages.div_ceil(word_bits);
    let bytes = words * size_of::<u32>();
    bytes.next_multiple_of(USER_MESSAGE_BITMAP_ALIGNMENT)
}

const _: () = assert!(USER_MESSAGE_BITMAP_ALIGNMENT.is_power_of_two());

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum LpcMessageType {
    NewMessage = 0,
    Request = 1,
    Reply = 2,
    Datagram = 3,
    LostReply = 4,
    PortClosed = 5,
    ClientDied = 6,
    Exception = 7,
    DebugEvent = 8,
    ErrorEvent = 9,
    ConnectionRequest = 10,
}

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

pub(crate) enum LpcPortHandleObject {
    CsrApi { usersrv_backing_base: usize },
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
struct CsrApiMessage {
    header: PortMessage,
    capture_data: usize,
    api_number: u32,
    status: i32,
    reserved: u32,
    padding: u32,
    client_connect: CsrClientConnect,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct UserWindowMessageTable {
    max_messages: usize,
    message_bitmap: usize,
}

impl UserWindowMessageTable {
    const fn new(max_messages: usize, message_bitmap: usize) -> Self {
        Self {
            max_messages,
            message_bitmap,
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
    reserved_message_table_0: UserWindowMessageTable,
    reserved: [u8; 0x10],
    reserved_message_table_1: UserWindowMessageTable,
    reserved_message_table_2: UserWindowMessageTable,
    padding_2: [u8; 0x30],
    fnid_message_tables: [UserWindowMessageTable; 24],
    default_window_message_table: UserWindowMessageTable,
    default_window_special_message_table: UserWindowMessageTable,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct UserConnect {
    version: u64,
    shared_info: UserSharedInfo,
    trailing_value: u64,
}

#[repr(C)]
struct UserServerInfo {
    reserved: [u8; 0x20],
}

#[repr(C)]
struct UserHandleEntry {
    reserved: [u8; 0x20],
}

#[repr(C)]
struct UserDisplayInfo {
    reserved: [u8; 0x20],
}

#[repr(C)]
struct UserSharedData {
    reserved: [u8; 0x20],
}

#[repr(C, align(32))]
struct UsersrvBackingLayout {
    server_info: UserServerInfo,
    // TODO(usersrv-handle-table): size this table from the entry count published by server_info.
    handle_entries: [UserHandleEntry; 1],
    display_info: UserDisplayInfo,
    shared_data: UserSharedData,
    reserved_message_bitmap_0:
        [u8; user_message_bitmap_storage_size(RESERVED_MESSAGE_MAX_MESSAGES[0])],
    reserved_message_bitmap_1:
        [u8; user_message_bitmap_storage_size(RESERVED_MESSAGE_MAX_MESSAGES[1])],
    reserved_message_bitmap_2:
        [u8; user_message_bitmap_storage_size(RESERVED_MESSAGE_MAX_MESSAGES[2])],
    scrollbar_message_bitmap: [u8; user_message_bitmap_storage_size(FNID_MESSAGE_MAX_MESSAGES[0])],
    icon_title_message_bitmap: [u8; user_message_bitmap_storage_size(FNID_MESSAGE_MAX_MESSAGES[1])],
    menu_message_bitmap: [u8; user_message_bitmap_storage_size(FNID_MESSAGE_MAX_MESSAGES[2])],
    desktop_message_bitmap: [u8; user_message_bitmap_storage_size(FNID_MESSAGE_MAX_MESSAGES[3])],
    default_window_proc_message_bitmap:
        [u8; user_message_bitmap_storage_size(FNID_MESSAGE_MAX_MESSAGES[4])],
    message_window_message_bitmap:
        [u8; user_message_bitmap_storage_size(FNID_MESSAGE_MAX_MESSAGES[5])],
    button_message_bitmap: [u8; user_message_bitmap_storage_size(FNID_MESSAGE_MAX_MESSAGES[7])],
    combo_box_message_bitmap: [u8; user_message_bitmap_storage_size(FNID_MESSAGE_MAX_MESSAGES[8])],
    combo_list_box_message_bitmap:
        [u8; user_message_bitmap_storage_size(FNID_MESSAGE_MAX_MESSAGES[9])],
    default_window_message_bitmap:
        [u8; user_message_bitmap_storage_size(DEFAULT_WINDOW_MAX_MESSAGES)],
    default_window_special_message_bitmap:
        [u8; user_message_bitmap_storage_size(DEFAULT_WINDOW_SPECIAL_MAX_MESSAGES)],
    reserved: [u8; 0x940],
}

const _: () = assert!(size_of::<UsersrvBackingLayout>() == USERSRV_BACKING_SIZE);
const _: () = assert!(align_of::<UsersrvBackingLayout>() == 0x20);

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
        if port_name != WINDOWS_API_PORT {
            litebox_util_log::debug!(port_name:% = port_name; "Unsupported LPC port");
            return NtStatus::NOT_SUPPORTED;
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
        // TODO(usersrv-ro-section): replace this client-writable page with server-owned backing
        // exposed to the guest through a read-only mapping.
        let port = LpcPortHandleObject::CsrApi {
            usersrv_backing_base,
        };
        let handle = match self.insert_typed_handle::<LpcPortSubsystem<Platform>>(
            port,
            0,
            Self::close_lpc_port,
        ) {
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
        send_message: MutPtr<Platform, u8>,
        send_message_attributes: Option<ConstPtr<Platform, u8>>,
        receive_message: MutPtr<Platform, u8>,
        buffer_length: MutPtr<Platform, usize>,
        receive_message_attributes: Option<MutPtr<Platform, u8>>,
        timeout: Option<ConstPtr<Platform, i64>>,
    ) -> NtStatus {
        // This models the synchronous, in-place CSR request observed during process startup.
        // Expand the contract only with a trace that exercises additional ALPC wait semantics.
        if flags != AlpcMessageFlags::SYNC_REQUEST
            || send_message_attributes.is_some()
            || receive_message_attributes.is_some()
            || timeout.is_some()
            || send_message.as_usize() != receive_message.as_usize()
        {
            litebox_util_log::debug!(
                flags:% = format_args!("{:#x}", flags.bits()),
                send_attributes = send_message_attributes.is_some(),
                receive_attributes = receive_message_attributes.is_some(),
                timeout = timeout.is_some(),
                distinct_message_buffers = send_message.as_usize() != receive_message.as_usize();
                "Unsupported ALPC send/wait/receive parameters"
            );
            // TODO(alpc-async): model independent send/receive and attribute paths.
            return NtStatus::INVALID_PARAMETER;
        }

        match self.typed_handle_entry_with_access::<LpcPortSubsystem<Platform>>(port_handle, 0) {
            Ok(entry) => entry.with_entry(|entry| match entry {
                LpcPortHandleObject::CsrApi {
                    usersrv_backing_base,
                } => Self::handle_csr_api_port_message(
                    *usersrv_backing_base,
                    send_message,
                    receive_message,
                    buffer_length,
                ),
            }),
            Err(status) => status,
        }
    }

    fn handle_csr_api_port_message(
        usersrv_backing_base: usize,
        send_message: MutPtr<Platform, u8>,
        receive_message: MutPtr<Platform, u8>,
        buffer_length: MutPtr<Platform, usize>,
    ) -> NtStatus {
        let send_message = MutPtr::<Platform, CsrApiMessage>::from_usize(send_message.as_usize());
        let receive_message =
            MutPtr::<Platform, CsrApiMessage>::from_usize(receive_message.as_usize());
        let Some(mut message) = send_message.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let Some(receive_capacity) = buffer_length.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if receive_capacity < size_of::<CsrApiMessage>() {
            return NtStatus::BUFFER_TOO_SMALL;
        }
        if message.api_number != 0
            || message.client_connect.server_dll_index != USERSRV_SERVER_DLL_INDEX
        {
            litebox_util_log::debug!(
                api_number:% = format_args!("{:#x}", message.api_number),
                server_dll_index = message.client_connect.server_dll_index;
                "Unsupported CSR API request"
            );
            // TODO(csr-api-dispatch): dispatch other CSR APIs and server DLLs.
            return NtStatus::INVALID_PARAMETER;
        }
        if message.header.data_length
            != (size_of::<CsrApiMessage>() - core::mem::offset_of!(CsrApiMessage, capture_data))
                .trunc()
            || message.header.total_length != size_of::<CsrApiMessage>().trunc()
            || !matches!(
                LpcMessageType::try_from(message.header.message_type),
                Ok(LpcMessageType::NewMessage)
            )
            || message.header.data_info_offset != 0
        {
            litebox_util_log::debug!(
                data_length:% = format_args!("{:#x}", message.header.data_length),
                total_length:% = format_args!("{:#x}", message.header.total_length),
                message_type:% = format_args!("{:#x}", message.header.message_type),
                data_info_offset:% = format_args!("{:#x}", message.header.data_info_offset);
                "Invalid CSR API port message header"
            );
            return NtStatus::INVALID_PARAMETER;
        }
        if message.client_connect.connection_info_size != size_of::<UserConnect>() {
            litebox_util_log::debug!(
                connection_info_size = message.client_connect.connection_info_size;
                "Invalid USERSRV connection information size"
            );
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

        let Some(user_connect) = build_user_connect(usersrv_backing_base) else {
            return NtStatus::INVALID_VIEW_SIZE;
        };
        // TODO(usersrv-shared-content): populate real win32k shared data when USER APIs need it.
        if connection_info.write_at_offset(0, user_connect).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }

        message.header.message_type = LpcMessageType::Reply as u16;
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
        self.close_typed_handle::<LpcPortSubsystem<Platform>>(handle, Self::close_lpc_port);
    }

    pub(crate) fn close_lpc_port(_port: LpcPortHandleObject) {}

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

fn build_user_connect(backing_base: usize) -> Option<UserConnect> {
    let pointer = |offset| backing_base.checked_add(offset);
    let message_table =
        |max_messages, offset| Some(UserWindowMessageTable::new(max_messages, pointer(offset)?));
    let reserved_message_table_0 = message_table(
        RESERVED_MESSAGE_MAX_MESSAGES[0],
        core::mem::offset_of!(UsersrvBackingLayout, reserved_message_bitmap_0),
    )?;
    let reserved_message_table_1 = message_table(
        RESERVED_MESSAGE_MAX_MESSAGES[1],
        core::mem::offset_of!(UsersrvBackingLayout, reserved_message_bitmap_1),
    )?;
    let reserved_message_table_2 = message_table(
        RESERVED_MESSAGE_MAX_MESSAGES[2],
        core::mem::offset_of!(UsersrvBackingLayout, reserved_message_bitmap_2),
    )?;
    let mut fnid_message_tables = [UserWindowMessageTable::new(0, 0); 24];
    // Indices follow the historical FNID order. Presence and message limits are captured from
    // the target x64 Windows build; the meaning of each bitmap bit remains private.
    for (index, bitmap_offset) in [
        Some(core::mem::offset_of!(
            UsersrvBackingLayout,
            scrollbar_message_bitmap
        )),
        Some(core::mem::offset_of!(
            UsersrvBackingLayout,
            icon_title_message_bitmap
        )),
        Some(core::mem::offset_of!(
            UsersrvBackingLayout,
            menu_message_bitmap
        )),
        Some(core::mem::offset_of!(
            UsersrvBackingLayout,
            desktop_message_bitmap
        )),
        Some(core::mem::offset_of!(
            UsersrvBackingLayout,
            default_window_proc_message_bitmap
        )),
        Some(core::mem::offset_of!(
            UsersrvBackingLayout,
            message_window_message_bitmap
        )),
        None, // FNID_SWITCH is captured as (0, NULL), so it needs no backing bitmap.
        Some(core::mem::offset_of!(
            UsersrvBackingLayout,
            button_message_bitmap
        )),
        Some(core::mem::offset_of!(
            UsersrvBackingLayout,
            combo_box_message_bitmap
        )),
        Some(core::mem::offset_of!(
            UsersrvBackingLayout,
            combo_list_box_message_bitmap
        )),
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(bitmap_offset) = bitmap_offset {
            fnid_message_tables[index] =
                message_table(FNID_MESSAGE_MAX_MESSAGES[index], bitmap_offset)?;
        }
    }

    Some(UserConnect {
        version: USER_CONNECT_VERSION,
        shared_info: UserSharedInfo {
            server_info: pointer(core::mem::offset_of!(UsersrvBackingLayout, server_info))?,
            handle_entries: pointer(core::mem::offset_of!(UsersrvBackingLayout, handle_entries))?,
            handle_entry_size: size_of::<UserHandleEntry>().trunc(),
            padding: 0,
            display_info: pointer(core::mem::offset_of!(UsersrvBackingLayout, display_info))?,
            shared_data: pointer(core::mem::offset_of!(UsersrvBackingLayout, shared_data))?,
            reserved_message_table_0,
            reserved: [0; 0x10],
            reserved_message_table_1,
            reserved_message_table_2,
            padding_2: [0; 0x30],
            fnid_message_tables,
            default_window_message_table: message_table(
                DEFAULT_WINDOW_MAX_MESSAGES,
                core::mem::offset_of!(UsersrvBackingLayout, default_window_message_bitmap),
            )?,
            default_window_special_message_table: message_table(
                DEFAULT_WINDOW_SPECIAL_MAX_MESSAGES,
                core::mem::offset_of!(UsersrvBackingLayout, default_window_special_message_bitmap),
            )?,
        },
        // TODO(usersrv-connect-layout): identify and model this field's native semantics.
        trailing_value: 0,
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
        message.header.data_length = (size_of::<CsrApiMessage>()
            - core::mem::offset_of!(CsrApiMessage, capture_data))
        .trunc();
        message.header.total_length = size_of::<CsrApiMessage>().trunc();
        message.client_connect.server_dll_index = USERSRV_SERVER_DLL_INDEX;
        message.client_connect.connection_info = core::ptr::from_mut(&mut usersrv_info) as usize;
        message.client_connect.connection_info_size = size_of::<UserConnect>();
        let mut receive_capacity = 0x3b8usize;

        let original_message = message;
        assert_eq!(
            task.sys_nt_alpc_send_wait_receive_port(
                handle,
                AlpcMessageFlags::SYNC_REQUEST | AlpcMessageFlags::WAIT_ALERTABLE,
                mut_byte_ptr(&mut message),
                None,
                mut_byte_ptr(&mut message),
                mut_ptr(&mut receive_capacity),
                None,
                None,
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(message.as_bytes(), original_message.as_bytes());

        assert_eq!(
            task.sys_nt_alpc_send_wait_receive_port(
                handle,
                AlpcMessageFlags::SYNC_REQUEST,
                mut_byte_ptr(&mut message),
                None,
                mut_byte_ptr(&mut message),
                mut_ptr(&mut receive_capacity),
                None,
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(message.header.message_type, LpcMessageType::Reply as u16);
        assert_eq!(message.status, NtStatus::SUCCESS.as_raw());
        assert_eq!(receive_capacity, size_of::<CsrApiMessage>());
    }
}
