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
const CSR_API_MESSAGE_LENGTH: u16 = 0x58;
const CSR_API_DATA_LENGTH: u16 = 0x30;
// BASESRV `BasepCreateActivationContext2`. Identified by the request payload shape (0x210-byte
// V2 SxS message with manifest/policy streams), not the ordinal: BASESRV API numbers drift across
// Windows builds (ReactOS/Win2003 lists 0x1e as NlsGetUserInfo, Geoff Chappell's Win10 table as
// 0x17 for the ActCtx routine), so this value is anchored to the validated trace on the target
// Win11 build and may be renumbered by a future build.
const BASESRV_CREATE_ACTIVATION_CONTEXT2_API: u32 = 0x0001_001e;
const BASESRV_CREATE_ACTIVATION_CONTEXT2_DATA_LENGTH: u16 = 0x210;
const BASESRV_CREATE_ACTIVATION_CONTEXT2_MESSAGE_LENGTH: u16 = 0x238;
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
const BASESRV_BACKING_SIZE: usize = crate::PAGE_SIZE;
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
    CsrApi {
        usersrv_backing_base: usize,
        basesrv_backing_base: usize,
    },
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
struct CsrCaptureBufferFourPointers {
    length: u32,
    padding_0: u32,
    related_capture_buffer: usize,
    count_message_pointers: u32,
    padding_1: u32,
    free_space: usize,
    message_pointer_offsets: [usize; 4],
}

const _: () = assert!(size_of::<CsrCaptureBufferFourPointers>() == 0x40);

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

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct BaseMsgSxsFlags: u32 {
        const MANIFEST_PRESENT = 0x0001;
        const POLICY_PRESENT = 0x0002;
        const SYSTEM_DEFAULT_TEXTUAL_ASSEMBLY_IDENTITY_PRESENT = 0x0004;
        const TEXTUAL_ASSEMBLY_IDENTITY_PRESENT = 0x0008;
        const NO_ISOLATION = 0x0020;
        const REMOTE = 0x0040;
        const DEV_OVERRIDE_PRESENT = 0x0080;
        const MANIFEST_OVERRIDE_PRESENT = 0x0100;
        const PACKAGE_IDENTITY_PRESENT = 0x0400;
        const FULL_TRUST_INTEGRITY_PRESENT = 0x0800;

        const _ = !0;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct BaseMsgSxsStream {
    file_type: u8,
    path_type: u8,
    handle_type: u8,
    padding: [u8; 5],
    path: UnicodeString,
    file_handle: Handle,
    handle: Handle,
    offset: u64,
    size: usize,
}

const _: () = assert!(size_of::<BaseMsgSxsStream>() == 0x38);

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextRunLevelInformation {
    flags: u32,
    run_level: u32,
    ui_access: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct SupportedOsInfo {
    major_version: u16,
    minor_version: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct BaseSxsCreateActivationContextMessageV2 {
    flags: u32,
    processor_architecture: u16,
    padding_0: u16,
    culture_fallbacks: UnicodeString,
    manifest: BaseMsgSxsStream,
    policy: BaseMsgSxsStream,
    assembly_directory: UnicodeString,
    textual_assembly_identity: UnicodeString,
    file_last_write_time: i64,
    resource_id: u64,
    activation_context_data: usize,
    activation_context_data_wow64: usize,
    run_level: ActivationContextRunLevelInformation,
    supported_os_info: SupportedOsInfo,
    assembly_name: UnicodeString,
    max_version_tested: u64,
    application_user_model_id: [u16; 130],
    application_user_model_id_length: u32,
}

const _: () = assert!(size_of::<BaseSxsCreateActivationContextMessageV2>() == 0x1f8);

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextData {
    magic: u32,
    header_size: u32,
    format_version: u32,
    total_size: u32,
    default_toc_offset: u32,
    extended_toc_offset: u32,
    assembly_roster_offset: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextDataAssemblyRosterHeader {
    header_size: u32,
    hash_algorithm: u32,
    entry_count: u32,
    first_entry_offset: u32,
    assembly_information_section_offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextDataAssemblyRosterEntry {
    flags: u32,
    pseudo_key: u32,
    assembly_name_offset: u32,
    assembly_name_length: u32,
    assembly_information_offset: u32,
    assembly_information_length: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextDataTocHeader {
    header_size: u32,
    entry_count: u32,
    first_entry_offset: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextDataTocEntry {
    id: u32,
    offset: u32,
    length: u32,
    format: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextStringSectionHeader {
    magic: u32,
    header_size: u32,
    format_version: u32,
    data_format_version: u32,
    flags: u32,
    element_count: u32,
    element_list_offset: u32,
    hash_algorithm: u32,
    search_structure_offset: u32,
    user_data_offset: u32,
    user_data_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextStringSectionEntry {
    pseudo_key: u32,
    key_offset: u32,
    key_length: u32,
    offset: u32,
    length: u32,
    assembly_roster_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextAssemblyGlobalInformation {
    size: u32,
    flags: u32,
    policy_coherency_guid: [u8; 16],
    policy_override_guid: [u8; 16],
    application_directory_path_type: u32,
    application_directory_length: u32,
    application_directory_offset: u32,
    resource_name: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextAssemblyInformation {
    size: u32,
    flags: u32,
    encoded_assembly_identity_length: u32,
    encoded_assembly_identity_offset: u32,
    manifest_path_type: u32,
    manifest_path_length: u32,
    manifest_path_offset: u32,
    manifest_last_write_time: [u32; 2],
    policy_path_type: u32,
    policy_path_length: u32,
    policy_path_offset: u32,
    policy_last_write_time: [u32; 2],
    metadata_satellite_roster_index: u32,
    unused: u32,
    manifest_version_major: u32,
    manifest_version_minor: u32,
    policy_version_major: u32,
    policy_version_minor: u32,
    assembly_directory_name_length: u32,
    assembly_directory_name_offset: u32,
    number_of_files: u32,
    language_length: u32,
    language_offset: u32,
    run_level: u32,
    ui_access: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextAssemblySection {
    header: ActivationContextStringSectionHeader,
    global_information: ActivationContextAssemblyGlobalInformation,
    application_directory: [u16; 88],
    entry: ActivationContextStringSectionEntry,
    assembly_information: ActivationContextAssemblyInformation,
    encoded_assembly_identity: [u16; 76],
    manifest_path: [u16; 104],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextGuidSectionHeader {
    magic: u32,
    header_size: u32,
    format_version: u32,
    data_format_version: u32,
    flags: u32,
    element_count: u32,
    element_list_offset: u32,
    search_structure_offset: u32,
    user_data_offset: u32,
    user_data_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextCompatibilityInformation {
    element_count: u32,
    elements_offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct ActivationContextBlob {
    header: ActivationContextData,
    roster: ActivationContextDataAssemblyRosterHeader,
    roster_entries: [ActivationContextDataAssemblyRosterEntry; 2],
    toc: ActivationContextDataTocHeader,
    toc_entries: [ActivationContextDataTocEntry; 6],
    assembly_section: ActivationContextAssemblySection,
    empty_guid_sections: [ActivationContextGuidSectionHeader; 4],
    compatibility_information: ActivationContextCompatibilityInformation,
}

const _: () = assert!(size_of::<ActivationContextAssemblyInformation>() == 0x6c);
const _: () = assert!(size_of::<ActivationContextAssemblySection>() == 0x300);
const _: () = assert!(size_of::<ActivationContextBlob>() == 0x47c);
// The blob is written into the BASESRV backing page; guarantee it fits so a future
// blob or PAGE_SIZE change cannot silently spill into the adjacent USERSRV backing.
const _: () = assert!(size_of::<ActivationContextBlob>() <= BASESRV_BACKING_SIZE);

#[expect(
    clippy::cast_possible_truncation,
    reason = "all activation-context offsets and sizes are compile-time values below one page"
)]
fn build_activation_context_blob(run_level: u32, ui_access: u32) -> ActivationContextBlob {
    const HEADER_MAGIC: u32 = 0x7874_6341;
    const STRING_SECTION_MAGIC: u32 = 0x6448_7353;
    const GUID_SECTION_MAGIC: u32 = 0x6448_7347;
    const ASSEMBLY_SECTION_OFFSET: u32 =
        core::mem::offset_of!(ActivationContextBlob, assembly_section) as u32;
    const ASSEMBLY_INFORMATION_OFFSET: u32 = ASSEMBLY_SECTION_OFFSET
        + core::mem::offset_of!(ActivationContextAssemblySection, assembly_information) as u32;
    const ASSEMBLY_INFORMATION_LENGTH: u32 = (size_of::<ActivationContextAssemblyInformation>()
        + size_of::<[u16; 76]>()
        + size_of::<[u16; 104]>()) as u32;
    const EMPTY_GUID_SECTION: ActivationContextGuidSectionHeader =
        ActivationContextGuidSectionHeader {
            magic: GUID_SECTION_MAGIC,
            header_size: size_of::<ActivationContextGuidSectionHeader>() as u32,
            format_version: 1,
            data_format_version: 1,
            flags: 1,
            element_count: 0,
            element_list_offset: 0,
            search_structure_offset: 0,
            user_data_offset: 0,
            user_data_size: 0,
        };
    let guid_sections_offset =
        core::mem::offset_of!(ActivationContextBlob, empty_guid_sections) as u32;
    let compatibility_offset =
        core::mem::offset_of!(ActivationContextBlob, compatibility_information) as u32;
    ActivationContextBlob {
        header: ActivationContextData {
            magic: HEADER_MAGIC,
            header_size: size_of::<ActivationContextData>() as u32,
            format_version: 1,
            total_size: size_of::<ActivationContextBlob>() as u32,
            default_toc_offset: core::mem::offset_of!(ActivationContextBlob, toc) as u32,
            extended_toc_offset: 0,
            assembly_roster_offset: core::mem::offset_of!(ActivationContextBlob, roster) as u32,
            flags: 0,
        },
        roster: ActivationContextDataAssemblyRosterHeader {
            header_size: size_of::<ActivationContextDataAssemblyRosterHeader>() as u32,
            hash_algorithm: 1,
            entry_count: 2,
            first_entry_offset: core::mem::offset_of!(ActivationContextBlob, roster_entries) as u32,
            assembly_information_section_offset: ASSEMBLY_SECTION_OFFSET,
        },
        roster_entries: [
            ActivationContextDataAssemblyRosterEntry {
                flags: 1,
                pseudo_key: 0,
                assembly_name_offset: 0,
                assembly_name_length: 0,
                assembly_information_offset: 0,
                assembly_information_length: 0,
            },
            ActivationContextDataAssemblyRosterEntry {
                flags: 2,
                pseudo_key: 0,
                assembly_name_offset: 0,
                assembly_name_length: 0,
                assembly_information_offset: ASSEMBLY_INFORMATION_OFFSET,
                assembly_information_length: ASSEMBLY_INFORMATION_LENGTH,
            },
        ],
        toc: ActivationContextDataTocHeader {
            header_size: size_of::<ActivationContextDataTocHeader>() as u32,
            entry_count: 6,
            first_entry_offset: core::mem::offset_of!(ActivationContextBlob, toc_entries) as u32,
            flags: 2,
        },
        toc_entries: [
            ActivationContextDataTocEntry {
                id: 1,
                offset: ASSEMBLY_SECTION_OFFSET,
                length: size_of::<ActivationContextAssemblySection>() as u32,
                format: 1,
            },
            ActivationContextDataTocEntry {
                id: 4,
                offset: guid_sections_offset,
                length: size_of::<ActivationContextGuidSectionHeader>() as u32,
                format: 2,
            },
            ActivationContextDataTocEntry {
                id: 5,
                offset: guid_sections_offset
                    + size_of::<ActivationContextGuidSectionHeader>() as u32,
                length: size_of::<ActivationContextGuidSectionHeader>() as u32,
                format: 2,
            },
            ActivationContextDataTocEntry {
                id: 6,
                offset: guid_sections_offset
                    + 2 * size_of::<ActivationContextGuidSectionHeader>() as u32,
                length: size_of::<ActivationContextGuidSectionHeader>() as u32,
                format: 2,
            },
            ActivationContextDataTocEntry {
                id: 9,
                offset: guid_sections_offset
                    + 3 * size_of::<ActivationContextGuidSectionHeader>() as u32,
                length: size_of::<ActivationContextGuidSectionHeader>() as u32,
                format: 2,
            },
            ActivationContextDataTocEntry {
                id: 11,
                offset: compatibility_offset,
                length: size_of::<ActivationContextCompatibilityInformation>() as u32,
                format: 1,
            },
        ],
        assembly_section: ActivationContextAssemblySection {
            header: ActivationContextStringSectionHeader {
                magic: STRING_SECTION_MAGIC,
                header_size: size_of::<ActivationContextStringSectionHeader>() as u32,
                format_version: 1,
                data_format_version: 1,
                flags: 3,
                element_count: 1,
                element_list_offset: core::mem::offset_of!(ActivationContextAssemblySection, entry)
                    as u32,
                hash_algorithm: 1,
                search_structure_offset: 0,
                user_data_offset: size_of::<ActivationContextStringSectionHeader>() as u32,
                user_data_size: core::mem::offset_of!(ActivationContextAssemblySection, entry)
                    as u32
                    - size_of::<ActivationContextStringSectionHeader>() as u32,
            },
            global_information: ActivationContextAssemblyGlobalInformation {
                size: core::mem::offset_of!(ActivationContextAssemblySection, entry) as u32
                    - size_of::<ActivationContextStringSectionHeader>() as u32,
                flags: 0,
                policy_coherency_guid: [0; 16],
                policy_override_guid: [0; 16],
                application_directory_path_type: 0,
                application_directory_length: 0,
                application_directory_offset: 0,
                resource_name: 0,
            },
            application_directory: [0; 88],
            entry: ActivationContextStringSectionEntry {
                pseudo_key: 0,
                key_offset: 0,
                key_length: 0,
                offset: core::mem::offset_of!(
                    ActivationContextAssemblySection,
                    assembly_information
                ) as u32,
                length: ASSEMBLY_INFORMATION_LENGTH,
                assembly_roster_index: 1,
            },
            assembly_information: ActivationContextAssemblyInformation {
                size: size_of::<ActivationContextAssemblyInformation>() as u32,
                flags: 0x11,
                encoded_assembly_identity_length: 0,
                encoded_assembly_identity_offset: 0,
                manifest_path_type: 0,
                manifest_path_length: 0,
                manifest_path_offset: 0,
                manifest_last_write_time: [0; 2],
                policy_path_type: 0,
                policy_path_length: 0,
                policy_path_offset: 0,
                policy_last_write_time: [0; 2],
                metadata_satellite_roster_index: 0,
                unused: 0,
                manifest_version_major: 1,
                manifest_version_minor: 0,
                policy_version_major: 0,
                policy_version_minor: 0,
                assembly_directory_name_length: 0,
                assembly_directory_name_offset: 0,
                number_of_files: 0,
                language_length: 0,
                language_offset: 0,
                run_level,
                ui_access,
            },
            encoded_assembly_identity: [0; 76],
            manifest_path: [0; 104],
        },
        empty_guid_sections: [EMPTY_GUID_SECTION; 4],
        compatibility_information: ActivationContextCompatibilityInformation {
            element_count: 0,
            elements_offset: 0,
        },
    }
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
        let Some(client_view_size) = mapped_view
            .view_size
            .checked_sub(USERSRV_BACKING_SIZE + BASESRV_BACKING_SIZE)
        else {
            self.rollback_pagefile_section_view(mapped_view.base);
            return NtStatus::INVALID_VIEW_SIZE;
        };
        if client_view_size == 0 {
            self.rollback_pagefile_section_view(mapped_view.base);
            return NtStatus::INVALID_VIEW_SIZE;
        }
        let basesrv_backing_base = mapped_view.base + client_view_size;
        let usersrv_backing_base = basesrv_backing_base + BASESRV_BACKING_SIZE;
        // TODO(usersrv-ro-section): replace this client-writable page with server-owned backing
        // exposed to the guest through a read-only mapping.
        if let Err(status) = zero_guest_csr_backing::<Platform>(
            basesrv_backing_base,
            BASESRV_BACKING_SIZE + USERSRV_BACKING_SIZE,
        ) {
            self.rollback_pagefile_section_view(mapped_view.base);
            return status;
        }
        let port = LpcPortHandleObject::CsrApi {
            basesrv_backing_base,
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
                    basesrv_backing_base,
                } => Self::handle_csr_api_port_message(
                    *usersrv_backing_base,
                    *basesrv_backing_base,
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
        basesrv_backing_base: usize,
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
        if message.api_number == BASESRV_CREATE_ACTIVATION_CONTEXT2_API {
            return Self::handle_basesrv_create_activation_context2(
                message,
                send_message,
                receive_message,
                buffer_length,
                receive_capacity,
                basesrv_backing_base,
            );
        }
        if message.header.data_length != CSR_API_DATA_LENGTH
            || message.header.total_length != CSR_API_MESSAGE_LENGTH
            || message.header.message_type != 0
            || message.header.data_info_offset != 0
            || message.api_number != 0
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

    fn handle_basesrv_create_activation_context2(
        mut message: CsrApiMessage,
        send_message: MutPtr<Platform, CsrApiMessage>,
        receive_message: MutPtr<Platform, CsrApiMessage>,
        buffer_length: MutPtr<Platform, usize>,
        receive_capacity: usize,
        basesrv_backing_base: usize,
    ) -> NtStatus {
        if message.header.data_length != BASESRV_CREATE_ACTIVATION_CONTEXT2_DATA_LENGTH
            || message.header.total_length != BASESRV_CREATE_ACTIVATION_CONTEXT2_MESSAGE_LENGTH
            || message.header.message_type != 0
            || message.header.data_info_offset != 0
            || receive_capacity < BASESRV_CREATE_ACTIVATION_CONTEXT2_MESSAGE_LENGTH as usize
        {
            return NtStatus::INVALID_PARAMETER;
        }

        let request = ConstPtr::<Platform, BaseSxsCreateActivationContextMessageV2>::from_usize(
            send_message.as_usize() + 0x40,
        );
        let Some(request) = request.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let flags = BaseMsgSxsFlags::from_bits_retain(request.flags);
        if !flags.contains(BaseMsgSxsFlags::MANIFEST_PRESENT)
            || request.processor_architecture != 9
            || request.activation_context_data == 0
            || request.activation_context_data_wow64 != 0
        {
            return NtStatus::INVALID_PARAMETER;
        }

        let capture =
            ConstPtr::<Platform, CsrCaptureBufferFourPointers>::from_usize(message.capture_data);
        let Some(capture) = capture.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if capture.count_message_pointers != 4
            || capture.free_space != 0
            || capture.length as usize > BASESRV_BACKING_SIZE
            || capture
                .message_pointer_offsets
                .iter()
                .any(|offset| *offset >= message.header.total_length as usize)
        {
            return NtStatus::INVALID_PARAMETER;
        }

        let output = MutPtr::<Platform, usize>::from_usize(request.activation_context_data);
        if probe_guest_output_preserving_value::<Platform, usize>(output).is_err()
            || probe_guest_output_preserving_value::<Platform, CsrApiMessage>(receive_message)
                .is_err()
            || probe_guest_output_preserving_value::<Platform, usize>(buffer_length).is_err()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        let data = MutPtr::<Platform, ActivationContextBlob>::from_usize(basesrv_backing_base);
        let blob =
            build_activation_context_blob(request.run_level.run_level, request.run_level.ui_access);
        // TODO(multiple-activation-contexts): allocate distinct backing for each successful call
        // instead of replacing the process-startup activation context.
        if data.write_at_offset(0, blob).is_none()
            || output.write_at_offset(0, basesrv_backing_base).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        // TODO(sxs-manifest-sections): populate captured manifest redirections and compatibility
        // settings when a guest depends on activation-context lookup beyond process startup.
        message.header.message_type = 2;
        message.status = NtStatus::SUCCESS.as_raw();
        // The ALPC path requires send and receive to alias, so writing the fixed header preserves
        // the request payload in place while the reply retains its full native message length.
        if receive_message.write_at_offset(0, message).is_none()
            || buffer_length
                .write_at_offset(
                    0,
                    BASESRV_CREATE_ACTIVATION_CONTEXT2_MESSAGE_LENGTH as usize,
                )
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

fn zero_guest_csr_backing<Platform: ShimPlatform>(
    backing_base: usize,
    backing_size: usize,
) -> Result<(), NtStatus> {
    let zeros = [0u8; 0x100];
    let backing = MutPtr::<Platform, u8>::from_usize(backing_base);
    for offset in (0..backing_size).step_by(zeros.len()) {
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
        let size = i64::try_from(crate::PAGE_SIZE * 3).expect("test section size fits in i64");
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
            view_size: crate::PAGE_SIZE * 3,
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

    #[test]
    fn basesrv_create_activation_context2_materializes_blob_and_replies() {
        const BUFFER_LEN: usize = BASESRV_CREATE_ACTIVATION_CONTEXT2_MESSAGE_LENGTH as usize;
        // Native ntdll overlays the SxS request onto the CSR message starting at this offset;
        // `capture_data` (0x28) and `api_number` (0x30) sit below it and stay intact.
        const REQUEST_OFFSET: usize = 0x40;
        const AMD64_PROCESSOR_ARCHITECTURE: u16 = 9;
        const ACTIVATION_CONTEXT_HEADER_MAGIC: u32 = 0x7874_6341;

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
            view_size: crate::PAGE_SIZE * 3,
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

        // Guest-visible slot into which the server writes the activation-context data pointer.
        let mut activation_context_data_out = 0usize;

        let mut request = BaseSxsCreateActivationContextMessageV2::new_zeroed();
        request.flags = BaseMsgSxsFlags::MANIFEST_PRESENT.bits();
        request.processor_architecture = AMD64_PROCESSOR_ARCHITECTURE;
        request.activation_context_data =
            core::ptr::from_mut(&mut activation_context_data_out) as usize;
        request.activation_context_data_wow64 = 0;
        request.run_level.run_level = 3;
        request.run_level.ui_access = 0;

        // A well-formed four-pointer capture buffer; every offset stays within the message.
        let capture = CsrCaptureBufferFourPointers {
            length: 0x100,
            padding_0: 0,
            related_capture_buffer: 0,
            count_message_pointers: 4,
            padding_1: 0,
            free_space: 0,
            message_pointer_offsets: [0x40, 0x48, 0x50, 0x58],
        };

        let build_message =
            |capture_ptr: usize, request: &BaseSxsCreateActivationContextMessageV2| {
                let mut header = CsrApiMessage::new_zeroed();
                header.header.data_length = BASESRV_CREATE_ACTIVATION_CONTEXT2_DATA_LENGTH;
                header.header.total_length = BASESRV_CREATE_ACTIVATION_CONTEXT2_MESSAGE_LENGTH;
                header.header.message_type = 0;
                header.header.data_info_offset = 0;
                header.api_number = BASESRV_CREATE_ACTIVATION_CONTEXT2_API;
                header.capture_data = capture_ptr;
                let mut buffer = [0u8; BUFFER_LEN];
                buffer[..size_of::<CsrApiMessage>()].copy_from_slice(header.as_bytes());
                buffer[REQUEST_OFFSET..].copy_from_slice(request.as_bytes());
                buffer
            };

        let send = |buffer: &mut [u8; BUFFER_LEN], receive_capacity: &mut usize| {
            task.sys_nt_alpc_send_wait_receive_port(
                handle,
                AlpcMessageFlags::SYNC_REQUEST,
                mut_byte_ptr(buffer),
                None,
                mut_byte_ptr(buffer),
                mut_ptr(receive_capacity),
                None,
                None,
            )
        };

        let capture_ptr = core::ptr::from_ref(&capture) as usize;

        // Happy path: the request is accepted, the blob is materialised, and the reply is fixed up.
        let mut buffer = build_message(capture_ptr, &request);
        let mut receive_capacity = BUFFER_LEN;
        assert_eq!(send(&mut buffer, &mut receive_capacity), NtStatus::SUCCESS);

        let reply = ConstPtr::<TestPlatform, CsrApiMessage>::from_usize(
            core::ptr::from_ref(&buffer) as usize,
        )
        .read_at_offset(0)
        .expect("reply message is readable");
        assert_eq!(reply.header.message_type, 2);
        assert_eq!(reply.status, NtStatus::SUCCESS.as_raw());
        assert_eq!(receive_capacity, BUFFER_LEN);

        // The server returns the guest address of the freshly materialised activation-context blob.
        assert_ne!(activation_context_data_out, 0);
        let blob = ConstPtr::<TestPlatform, ActivationContextData>::from_usize(
            activation_context_data_out,
        )
        .read_at_offset(0)
        .expect("activation-context blob header is readable");
        assert_eq!(blob.magic, ACTIVATION_CONTEXT_HEADER_MAGIC);
        assert_eq!(blob.header_size, size_of::<ActivationContextData>().trunc());
        assert_eq!(blob.total_size, size_of::<ActivationContextBlob>().trunc());

        // Contract negatives: each malformed field is rejected with INVALID_PARAMETER.
        let mut wrong_arch = request;
        wrong_arch.processor_architecture = 0;
        let mut buffer = build_message(capture_ptr, &wrong_arch);
        let mut receive_capacity = BUFFER_LEN;
        assert_eq!(
            send(&mut buffer, &mut receive_capacity),
            NtStatus::INVALID_PARAMETER
        );

        let mut no_manifest = request;
        no_manifest.flags = 0;
        let mut buffer = build_message(capture_ptr, &no_manifest);
        let mut receive_capacity = BUFFER_LEN;
        assert_eq!(
            send(&mut buffer, &mut receive_capacity),
            NtStatus::INVALID_PARAMETER
        );

        let bad_capture = CsrCaptureBufferFourPointers {
            count_message_pointers: 3,
            ..capture
        };
        let mut buffer = build_message(core::ptr::from_ref(&bad_capture) as usize, &request);
        let mut receive_capacity = BUFFER_LEN;
        assert_eq!(
            send(&mut buffer, &mut receive_capacity),
            NtStatus::INVALID_PARAMETER
        );
    }
}
