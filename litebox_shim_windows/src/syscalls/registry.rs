// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows registry syscalls backed by a private file-system-shaped store (i.e.,
//! an overlay file system with in-memory and tar backends).
//!
//! Registry keys are represented as directories and values as files under each
//! key's `.values` directory:
//!
//! ```text
//! /registry/machine/system/currentcontrolset/control/nls/codepage/
//!     .values/
//!         acp
//!         oemcp
//!         maccp
//!         ...
//!     EUDCCodeRange/
//!         .values/
//!             932
//!             ...
//!     ...
//! ```
//!
//! This is only an implementation detail: syscall handlers must expose registry
//! object semantics rather than file semantics.

use core::marker::PhantomData;
use core::mem::{offset_of, size_of};

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use int_enum::IntEnum;
use litebox::LiteBox;
use litebox::event::{
    Events,
    polling::{Pollee, TryOpError},
};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd};
use litebox::fs::errors::{
    FileStatusError, MkdirError, OpenError, PathError, ReadDirError, ReadError, WriteError,
};
use litebox::fs::{FileType, Mode, OFlags};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::sync::Mutex;
use litebox::utils::TruncateExt;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::syscalls::Handle;
use crate::{ConstPtr, MutPtr, Task, probe_guest_output_preserving_value, raw_handle_entry};

use crate::nt_types::{
    AccessMask, IoStatusBlock, ObjectAttributes, UnicodeString, read_object_attributes,
    read_unicode_string_at,
};

type RegistryFileSystem<Platform> = litebox::fs::resolver::Resolver<Platform>;

pub(crate) struct RegistryKeySubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for RegistryKeySubsystem<Platform> {
    type Entry = RegistryKeyObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry for RegistryKeyObject<Platform> {}

impl<Platform: crate::ShimPlatform> crate::WindowsHandleSubsystem
    for RegistryKeySubsystem<Platform>
{
    fn normalize_desired_access(desired_access: u32) -> u32 {
        RegistryKeyAccess::from_desired_access(desired_access).bits()
    }
}

pub(crate) struct RegistryKeyObject<Platform: crate::ShimPlatform> {
    path: String,
    fd: TypedFd<RegistryFileSystem<Platform>>,
}

pub(crate) struct RegistryStore<Platform: crate::ShimPlatform> {
    fs: RegistryFileSystem<Platform>,
    fs_context: litebox::fs::resolver::Context,
    notification_state: Mutex<Platform, RegistryNotificationState>,
    notification_pollee: Pollee<Platform>,
}

/// Reserved backing-store directory that contains a registry key's value files.
const VALUES_DIR_NAME: &str = ".values";
const DEFAULT_CODE_PAGE_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage";
const DEFAULT_SESSION_MANAGER_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager";
const DEFAULT_SEGMENT_HEAP_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Segment Heap";
const DEFAULT_IMAGE_FILE_EXECUTION_OPTIONS_KEY: &str = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";

/* Seed separate providers for TCP streams and UDP datagrams in both IPv4 and
IPv6 so Winsock can resolve each address-family, socket-type, and protocol
combination used by applications. */
const DEFAULT_WINSOCK_PARAMETERS_KEY: &str =
    "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters";
const DEFAULT_WINSOCK_PROTOCOL_CATALOG_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9";
/// IPv4 TCP
const DEFAULT_WINSOCK_IPV4_TCP_ENTRY_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries64\\000000000001";
/// IPv4 UDP
const DEFAULT_WINSOCK_IPV4_UDP_ENTRY_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries64\\000000000002";
/// IPv6 TCP
const DEFAULT_WINSOCK_IPV6_TCP_ENTRY_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries64\\000000000003";
/// IPv6 UDP
const DEFAULT_WINSOCK_IPV6_UDP_ENTRY_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries64\\000000000004";
const DEFAULT_WINSOCK_NAMESPACE_CATALOG_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5";
/// DNS/name-resolution providers
const DEFAULT_WINSOCK_NAMESPACE_ENTRY_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64\\000000000001";
const DEFAULT_ACP_VALUE: &[u8] = &[b'1', 0, b'2', 0, b'5', 0, b'2', 0, 0, 0];
const DEFAULT_OEMCP_VALUE: &[u8] = &[b'4', 0, b'3', 0, b'7', 0, 0, 0];
const DEFAULT_MACCP_VALUE: &[u8] = &[b'1', 0, b'0', 0, b'0', 0, b'0', 0, b'0', 0, 0, 0];
const REGISTRY_VALUE_TYPE_SIZE: usize = size_of::<u32>();

const WINSOCK_IPV4_PROVIDER_ID: [u8; 16] = [
    0xa0, 0x1a, 0x0f, 0xe7, 0x8b, 0xab, 0xcf, 0x11, 0x8c, 0xa3, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92,
];
const WINSOCK_IPV6_PROVIDER_ID: [u8; 16] = [
    0xc0, 0xb0, 0xea, 0xf9, 0xd4, 0x26, 0xd0, 0x11, 0xbb, 0xbf, 0x00, 0xaa, 0x00, 0x6c, 0x34, 0xe4,
];
/// Number of TCP/UDP providers across IPv4 and IPv6 in `Protocol_Catalog9`.
const WINSOCK_PROTOCOL_CATALOG_ENTRY_COUNT: u32 = 4;
/// First catalog entry ID available after the four seeded protocol providers.
const WINSOCK_NEXT_PROTOCOL_CATALOG_ENTRY_ID: u32 = 5;
/// Initial catalog revision used by Winsock to detect catalog changes.
const WINSOCK_INITIAL_CATALOG_SERIAL: u32 = 1;
/// Number of name-resolution providers in `NameSpace_Catalog5`.
const WINSOCK_NAMESPACE_CATALOG_ENTRY_COUNT: u32 = 1;
/// `NS_DNS`: the Winsock namespace identifier for DNS name resolution.
const WINSOCK_NAMESPACE_DNS: u32 = 12;
/// Microsoft TCP/IP namespace provider GUID, encoded using the Windows GUID layout.
const WINSOCK_NAMESPACE_PROVIDER_ID: [u8; 16] = [
    0x40, 0x9d, 0x05, 0x22, 0x9e, 0x7e, 0xcf, 0x11, 0xae, 0x5a, 0x00, 0xaa, 0x00, 0xa7, 0x11, 0x2b,
];
/// The seeded DNS namespace provider is active.
const WINSOCK_NAMESPACE_PROVIDER_ENABLED: u32 = 1;
/// Version reported by the built-in Microsoft DNS namespace provider.
const WINSOCK_NAMESPACE_PROVIDER_VERSION: u32 = 0;
/// The DNS provider does not persist Winsock service-class metadata.
const WINSOCK_NAMESPACE_STORES_SERVICE_CLASS_INFO: u32 = 0;
const WINSOCK_PROVIDER_PATH_SIZE: usize = 260;

#[derive(Clone, Copy)]
struct DefaultWinsockProtocol {
    entry_key: &'static str,
    catalog_entry_id: u32,
    service_flags: u32,
    provider_id: [u8; 16],
    address_family: i32,
    socket_address_size: i32,
    socket_type: i32,
    protocol: i32,
    message_size: u32,
    protocol_name: &'static str,
}

const DEFAULT_WINSOCK_PROTOCOLS: [DefaultWinsockProtocol; 4] = [
    DefaultWinsockProtocol {
        entry_key: DEFAULT_WINSOCK_IPV4_TCP_ENTRY_KEY,
        catalog_entry_id: 1,
        service_flags: 0x0002_0066,
        provider_id: WINSOCK_IPV4_PROVIDER_ID,
        address_family: 2,
        socket_address_size: 16,
        socket_type: 1,
        protocol: 6,
        message_size: 0,
        protocol_name: "@%SystemRoot%\\System32\\mswsock.dll,-60100",
    },
    DefaultWinsockProtocol {
        entry_key: DEFAULT_WINSOCK_IPV4_UDP_ENTRY_KEY,
        catalog_entry_id: 2,
        service_flags: 0x0002_0609,
        provider_id: WINSOCK_IPV4_PROVIDER_ID,
        address_family: 2,
        socket_address_size: 16,
        socket_type: 2,
        protocol: 17,
        message_size: 65_527,
        protocol_name: "@%SystemRoot%\\System32\\mswsock.dll,-60101",
    },
    DefaultWinsockProtocol {
        entry_key: DEFAULT_WINSOCK_IPV6_TCP_ENTRY_KEY,
        catalog_entry_id: 3,
        service_flags: 0x0002_0066,
        provider_id: WINSOCK_IPV6_PROVIDER_ID,
        address_family: 23,
        socket_address_size: 28,
        socket_type: 1,
        protocol: 6,
        message_size: 0,
        protocol_name: "@%SystemRoot%\\System32\\mswsock.dll,-60200",
    },
    DefaultWinsockProtocol {
        entry_key: DEFAULT_WINSOCK_IPV6_UDP_ENTRY_KEY,
        catalog_entry_id: 4,
        service_flags: 0x0002_0609,
        provider_id: WINSOCK_IPV6_PROVIDER_ID,
        address_family: 23,
        socket_address_size: 28,
        socket_type: 2,
        protocol: 17,
        message_size: 65_527,
        protocol_name: "@%SystemRoot%\\System32\\mswsock.dll,-60201",
    },
];

#[repr(C)]
#[derive(Immutable, IntoBytes)]
struct WinsockPackedCatalogItem {
    provider_path: [u8; WINSOCK_PROVIDER_PATH_SIZE],
    protocol_info: WsaProtocolInfo,
}

#[repr(C)]
#[derive(Immutable, IntoBytes)]
struct WsaProtocolChain {
    chain_len: i32,
    chain_entries: [u32; 7],
}

#[repr(C)]
#[derive(Immutable, IntoBytes)]
struct WsaProtocolInfo {
    service_flags1: u32,
    service_flags2: u32,
    service_flags3: u32,
    service_flags4: u32,
    provider_flags: u32,
    provider_id: [u8; 16],
    catalog_entry_id: u32,
    protocol_chain: WsaProtocolChain,
    version: i32,
    address_family: i32,
    max_socket_address: i32,
    min_socket_address: i32,
    socket_type: i32,
    protocol: i32,
    protocol_max_offset: i32,
    network_byte_order: i32,
    security_scheme: i32,
    message_size: u32,
    provider_reserved: u32,
    protocol_name: [u16; 256],
}

bitflags::bitflags! {
    /// Registry key `ACCESS_MASK` rights accepted by `NtOpenKey`/`NtCreateKey`.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RegistryKeyAccess: u32 {
        const QUERY_VALUE = 0x0001;
        const SET_VALUE = 0x0002;
        const CREATE_SUB_KEY = 0x0004;
        const ENUMERATE_SUB_KEYS = 0x0008;
        const NOTIFY = 0x0010;
        const CREATE_LINK = 0x0020;

        const READ = AccessMask::STANDARD_RIGHTS_READ.bits()
            | Self::QUERY_VALUE.bits()
            | Self::ENUMERATE_SUB_KEYS.bits()
            | Self::NOTIFY.bits();
        const WRITE = AccessMask::STANDARD_RIGHTS_WRITE.bits()
            | Self::SET_VALUE.bits()
            | Self::CREATE_SUB_KEY.bits();
        const EXECUTE = Self::READ.bits();
        const ALL_ACCESS = (AccessMask::STANDARD_RIGHTS_ALL.bits()
            | Self::QUERY_VALUE.bits()
            | Self::SET_VALUE.bits()
            | Self::CREATE_SUB_KEY.bits()
            | Self::ENUMERATE_SUB_KEYS.bits()
            | Self::NOTIFY.bits()
            | Self::CREATE_LINK.bits())
            & !AccessMask::SYNCHRONIZE.bits();

        const FS_READ_ACCESS = Self::QUERY_VALUE.bits()
            | Self::ENUMERATE_SUB_KEYS.bits()
            | Self::NOTIFY.bits()
            | AccessMask::GENERIC_READ.bits()
            | AccessMask::GENERIC_EXECUTE.bits()
            | AccessMask::GENERIC_ALL.bits();
        const FS_WRITE_ACCESS = Self::SET_VALUE.bits()
            | Self::CREATE_SUB_KEY.bits()
            | Self::CREATE_LINK.bits()
            | AccessMask::DELETE.bits()
            | AccessMask::WRITE_DAC.bits()
            | AccessMask::WRITE_OWNER.bits()
            | AccessMask::GENERIC_WRITE.bits()
            | AccessMask::GENERIC_ALL.bits();

        const _ = !0;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RegistryOpenOptions: u32 {
        const BACKUP_RESTORE = 0x0000_0004;
        const OPEN_LINK = 0x0000_0008;
        const DONT_VIRTUALIZE = 0x0000_0010;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RegistryCreateOptions: u32 {
        const VOLATILE = 0x0000_0001;
        const CREATE_LINK = 0x0000_0002;
        const BACKUP_RESTORE = 0x0000_0004;
        const OPEN_LINK = 0x0000_0008;
        const DONT_VIRTUALIZE = 0x0000_0010;
    }
}

bitflags::bitflags! {
    /// Changes accepted by `NtNotifyChangeKey`.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RegistryNotifyFilter: u32 {
        const NAME = 0x0000_0001;
        const ATTRIBUTES = 0x0000_0002;
        const LAST_SET = 0x0000_0004;
        const SECURITY = 0x0000_0008;
        const THREAD_AGNOSTIC = 0x1000_0000;
    }
}

fn registry_notify_filter_indices(filter: RegistryNotifyFilter) -> impl Iterator<Item = usize> {
    [
        (RegistryNotifyFilter::NAME, 0),
        (RegistryNotifyFilter::ATTRIBUTES, 1),
        (RegistryNotifyFilter::LAST_SET, 2),
        (RegistryNotifyFilter::SECURITY, 3),
    ]
    .into_iter()
    .filter_map(move |(flag, index)| filter.contains(flag).then_some(index))
}

#[derive(Default)]
struct RegistryNotificationState {
    generation: u64,
    keys: BTreeMap<String, RegistryKeyChangeState>,
}

#[derive(Default)]
struct RegistryKeyChangeState {
    direct: [u64; 4],
    subtree: [u64; 4],
}

pub(crate) struct NtNotifyChangeKeyRequest<Platform: litebox::platform::RawPointerProvider> {
    pub(crate) key_handle: Handle,
    pub(crate) event: Handle,
    pub(crate) apc_routine: Option<ConstPtr<Platform, u8>>,
    pub(crate) apc_context: Option<ConstPtr<Platform, u8>>,
    pub(crate) io_status_block: MutPtr<Platform, IoStatusBlock>,
    pub(crate) completion_filter: u32,
    pub(crate) watch_tree: bool,
    pub(crate) buffer: Option<MutPtr<Platform, u8>>,
    pub(crate) buffer_size: u32,
    pub(crate) asynchronous: bool,
}

impl RegistryKeyAccess {
    fn from_desired_access(desired_access: u32) -> Self {
        // MAXIMUM_ALLOWED requests every right the (unrestricted) key grants, so
        // expand it to ALL_ACCESS — mirroring the token/file/handle subsystems.
        // Without this a MAXIMUM_ALLOWED open (e.g. 7za's) would grant no usable
        // rights and later NtQueryKey access checks would spuriously fail.
        let maximum_allowed = desired_access & AccessMask::MAXIMUM_ALLOWED.bits() != 0;
        let explicit_access = desired_access & !AccessMask::MAXIMUM_ALLOWED.bits();
        let normalized = AccessMask::expand_generic_access(
            explicit_access,
            Self::READ.bits(),
            Self::WRITE.bits(),
            Self::EXECUTE.bits(),
            Self::ALL_ACCESS.bits(),
        );
        Self::from_bits_retain(if maximum_allowed {
            normalized | Self::ALL_ACCESS.bits()
        } else {
            normalized
        })
    }
}

impl From<RegistryKeyAccess> for OFlags {
    fn from(desired_access: RegistryKeyAccess) -> Self {
        let wants_read = desired_access.intersects(RegistryKeyAccess::FS_READ_ACCESS);
        let wants_write = desired_access.intersects(RegistryKeyAccess::FS_WRITE_ACCESS);

        let access = match (wants_read, wants_write) {
            (true, true) => OFlags::RDWR,
            (false, true) => OFlags::WRONLY,
            _ => OFlags::RDONLY,
        };
        access | OFlags::DIRECTORY
    }
}

/// System-defined `REG_*` value types stored in `KEY_VALUE_*_INFORMATION::Type`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum RegistryValueType {
    /// `REG_NONE`: data with no particular type.
    None = 0,
    /// `REG_SZ`: a null-terminated Unicode string.
    Sz = 1,
    /// `REG_EXPAND_SZ`: a null-terminated Unicode string with unexpanded environment references.
    ExpandSz = 2,
    /// `REG_BINARY`: binary data in any form.
    Binary = 3,
    /// `REG_DWORD` / `REG_DWORD_LITTLE_ENDIAN`: a little-endian 4-byte value.
    Dword = 4,
    /// `REG_DWORD_BIG_ENDIAN`: a big-endian 4-byte value.
    DwordBigEndian = 5,
    /// `REG_LINK`: a Unicode string naming a symbolic link.
    Link = 6,
    /// `REG_MULTI_SZ`: null-terminated strings terminated by another zero.
    MultiSz = 7,
    /// `REG_RESOURCE_LIST`: a device driver's hardware resource list.
    ResourceList = 8,
    /// `REG_FULL_RESOURCE_DESCRIPTOR`: hardware resources used by a physical device.
    FullResourceDescriptor = 9,
    /// `REG_RESOURCE_REQUIREMENTS_LIST`: possible hardware resources for a device.
    ResourceRequirementsList = 10,
    /// `REG_QWORD` / `REG_QWORD_LITTLE_ENDIAN`: a little-endian 8-byte value.
    Qword = 11,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum KeyValueInformationClass {
    Basic = 0,
    Full = 1,
    Partial = 2,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum KeyInformationClass {
    Basic = 0,
    Node = 1,
    Full = 2,
    Name = 3,
    Cached = 4,
    Flags = 5,
    Virtualization = 6,
    HandleTags = 7,
    Trust = 8,
    Layer = 9,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum RegistryKeyDisposition {
    CreatedNewKey = 1,
    OpenedExistingKey = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct KeyBasicInformation {
    last_write_time: [u8; 8],
    /// Legacy registry title index. Reserved; callers should ignore this field.
    title_index: u32,
    name_length: u32,
    name: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct KeyNodeInformation {
    last_write_time: [u8; 8],
    /// Legacy registry title index. Reserved; callers should ignore this field.
    title_index: u32,
    class_offset: u32,
    class_length: u32,
    name_length: u32,
    name: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct KeyFullInformation {
    last_write_time: [u8; 8],
    /// Legacy registry title index. Reserved; callers should ignore this field.
    title_index: u32,
    class_offset: u32,
    class_length: u32,
    sub_keys: u32,
    max_name_len: u32,
    max_class_len: u32,
    values: u32,
    max_value_name_len: u32,
    max_value_data_len: u32,
    class: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct KeyNameInformation {
    name_length: u32,
    name: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct KeyCachedInformation {
    last_write_time: [u8; 8],
    /// Legacy registry title index. Reserved; callers should ignore this field.
    title_index: u32,
    sub_keys: u32,
    max_name_len: u32,
    values: u32,
    max_value_name_len: u32,
    max_value_data_len: u32,
    name_length: u32,
    // LARGE_INTEGER gives the Windows structure 8-byte alignment and a 40-byte size.
    padding: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct KeyHandleTagsInformation {
    handle_tags: u32,
}

#[derive(Default)]
struct KeySummary {
    sub_keys: usize,
    max_name_len: usize,
    values: usize,
    max_value_name_len: usize,
    max_value_data_len: usize,
}

/// The `KEY_VALUE_BASIC_INFORMATION` structure defines a subset of the full
/// information available for a value entry of a registry key.
///
/// The variable-length `Name` field follows this fixed-size header.
/// See <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_key_value_basic_information>.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct KeyValueBasicInformation {
    /// Legacy registry title index. Reserved; callers should ignore this field.
    title_index: u32,
    value_type: u32,
    name_length: u32,
    // Followed by a variable-length name.
    name: [u8; 0],
}

/// The `KEY_VALUE_FULL_INFORMATION` structure defines information available
/// for a value entry of a registry key.
///
/// The variable-length `Name` field follows this fixed-size header. The value
/// data starts at `data_offset` after any alignment padding.
/// See <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_key_value_full_information>.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct KeyValueFullInformation {
    /// Legacy registry title index. Reserved; callers should ignore this field.
    title_index: u32,
    value_type: u32,
    data_offset: u32,
    data_length: u32,
    name_length: u32,
    // Followed by a variable-length name and aligned value data.
    name: [u8; 0],
    // Followed by aligned value data.
    // ...
    // Data[u8; data_length];
}

/// The `KEY_VALUE_PARTIAL_INFORMATION` structure defines a subset of the value
/// information available for a value entry of a registry key.
///
/// The variable-length `Data` field follows this fixed-size header.
/// See <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_key_value_partial_information>.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct KeyValuePartialInformation {
    /// Legacy registry title index. Reserved; callers should ignore this field.
    title_index: u32,
    value_type: u32,
    data_length: u32,
    // Followed by variable-length value data.
    data: [u8; 0],
}

struct RegistryValue {
    value_type: u32,
    data: Vec<u8>,
}

impl<Platform: crate::ShimPlatform> RegistryStore<Platform> {
    pub(crate) fn new(litebox: &LiteBox<Platform>) -> Self {
        #[cfg(not(any(test, feature = "local_filesystem")))]
        let fs = litebox::fs::resolver::Resolver::new_brokered_windows_registry(litebox);
        #[cfg(any(test, feature = "local_filesystem"))]
        let in_mem = litebox::fs::in_mem::InMem::<Platform>::new_initialized([(
            "/",
            litebox::fs::in_mem::InitialNode::Directory {
                mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                owner: litebox::fs::UserInfo::ROOT,
            },
        )]);
        #[cfg(any(test, feature = "local_filesystem"))]
        let fs = litebox::fs::resolver::Resolver::new(
            litebox,
            litebox::fs::composer::Composer::builder()
                .mount_nestable("/", |allocators| {
                    litebox::fs::overlay::Overlay::<Platform>::new(
                        in_mem,
                        litebox::fs::tar_ro::TarRo::new(
                            // TODO: Replace with tar file provided by the user
                            litebox::fs::tar_ro::EMPTY_TAR_FILE.into(),
                            allocators.next(),
                        ),
                        allocators.next(),
                    )
                })
                .build()
                .unwrap(),
        );
        let fs_context = litebox::fs::resolver::Context::new();
        {
            let fs = &fs;
            for key in [
                DEFAULT_SESSION_MANAGER_KEY,
                DEFAULT_SEGMENT_HEAP_KEY,
                DEFAULT_IMAGE_FILE_EXECUTION_OPTIONS_KEY,
                DEFAULT_WINSOCK_PARAMETERS_KEY,
                DEFAULT_WINSOCK_PROTOCOL_CATALOG_KEY,
                DEFAULT_WINSOCK_IPV4_TCP_ENTRY_KEY,
                DEFAULT_WINSOCK_IPV4_UDP_ENTRY_KEY,
                DEFAULT_WINSOCK_IPV6_TCP_ENTRY_KEY,
                DEFAULT_WINSOCK_IPV6_UDP_ENTRY_KEY,
                DEFAULT_WINSOCK_NAMESPACE_CATALOG_KEY,
                DEFAULT_WINSOCK_NAMESPACE_ENTRY_KEY,
            ] {
                if let Err(status) = create_key_in_fs(fs, &fs_context, key) {
                    litebox_util_log::error!(key:% = key, status:? = status; "failed to initialize registry key");
                    break;
                }
            }
            for (name, value) in [
                ("ACP", DEFAULT_ACP_VALUE),
                ("OEMCP", DEFAULT_OEMCP_VALUE),
                ("MACCP", DEFAULT_MACCP_VALUE),
            ] {
                if let Err(status) = write_value_in_fs(
                    fs,
                    &fs_context,
                    DEFAULT_CODE_PAGE_KEY,
                    name,
                    RegistryValueType::Sz,
                    value,
                ) {
                    litebox_util_log::error!(name:% = name, status:? = status; "failed to initialize registry value");
                    break;
                }
            }

            let mut winsock_values = vec![
                (
                    DEFAULT_WINSOCK_PARAMETERS_KEY,
                    "WinSock_Registry_Version",
                    RegistryValueType::Sz,
                    utf16le_nul("2.0"),
                ),
                (
                    DEFAULT_WINSOCK_PARAMETERS_KEY,
                    "Current_Protocol_Catalog",
                    RegistryValueType::Sz,
                    utf16le_nul("Protocol_Catalog9"),
                ),
                (
                    DEFAULT_WINSOCK_PARAMETERS_KEY,
                    "Current_NameSpace_Catalog",
                    RegistryValueType::Sz,
                    utf16le_nul("NameSpace_Catalog5"),
                ),
                (
                    DEFAULT_WINSOCK_PROTOCOL_CATALOG_KEY,
                    "Num_Catalog_Entries64",
                    RegistryValueType::Dword,
                    WINSOCK_PROTOCOL_CATALOG_ENTRY_COUNT.to_le_bytes().to_vec(),
                ),
                (
                    DEFAULT_WINSOCK_PROTOCOL_CATALOG_KEY,
                    "Next_Catalog_Entry_ID",
                    RegistryValueType::Dword,
                    WINSOCK_NEXT_PROTOCOL_CATALOG_ENTRY_ID
                        .to_le_bytes()
                        .to_vec(),
                ),
                (
                    DEFAULT_WINSOCK_PROTOCOL_CATALOG_KEY,
                    "Serial_Access_Num",
                    RegistryValueType::Dword,
                    WINSOCK_INITIAL_CATALOG_SERIAL.to_le_bytes().to_vec(),
                ),
                (
                    DEFAULT_WINSOCK_NAMESPACE_CATALOG_KEY,
                    "Num_Catalog_Entries64",
                    RegistryValueType::Dword,
                    WINSOCK_NAMESPACE_CATALOG_ENTRY_COUNT.to_le_bytes().to_vec(),
                ),
                (
                    DEFAULT_WINSOCK_NAMESPACE_CATALOG_KEY,
                    "Serial_Access_Num",
                    RegistryValueType::Dword,
                    WINSOCK_INITIAL_CATALOG_SERIAL.to_le_bytes().to_vec(),
                ),
                (
                    DEFAULT_WINSOCK_NAMESPACE_ENTRY_KEY,
                    "LibraryPath",
                    RegistryValueType::Sz,
                    utf16le_nul("%SystemRoot%\\System32\\mswsock.dll"),
                ),
                (
                    DEFAULT_WINSOCK_NAMESPACE_ENTRY_KEY,
                    "DisplayString",
                    RegistryValueType::Sz,
                    utf16le_nul("@%SystemRoot%\\system32\\wshtcpip.dll,-60103"),
                ),
                (
                    DEFAULT_WINSOCK_NAMESPACE_ENTRY_KEY,
                    "ProviderId",
                    RegistryValueType::Binary,
                    WINSOCK_NAMESPACE_PROVIDER_ID.to_vec(),
                ),
                (
                    DEFAULT_WINSOCK_NAMESPACE_ENTRY_KEY,
                    "SupportedNameSpace",
                    RegistryValueType::Dword,
                    WINSOCK_NAMESPACE_DNS.to_le_bytes().to_vec(),
                ),
                (
                    DEFAULT_WINSOCK_NAMESPACE_ENTRY_KEY,
                    "Enabled",
                    RegistryValueType::Dword,
                    WINSOCK_NAMESPACE_PROVIDER_ENABLED.to_le_bytes().to_vec(),
                ),
                (
                    DEFAULT_WINSOCK_NAMESPACE_ENTRY_KEY,
                    "Version",
                    RegistryValueType::Dword,
                    WINSOCK_NAMESPACE_PROVIDER_VERSION.to_le_bytes().to_vec(),
                ),
                (
                    DEFAULT_WINSOCK_NAMESPACE_ENTRY_KEY,
                    "StoresServiceClassInfo",
                    RegistryValueType::Dword,
                    WINSOCK_NAMESPACE_STORES_SERVICE_CLASS_INFO
                        .to_le_bytes()
                        .to_vec(),
                ),
                (
                    DEFAULT_WINSOCK_NAMESPACE_ENTRY_KEY,
                    "ProviderInfo",
                    RegistryValueType::Binary,
                    Vec::new(),
                ),
            ];
            for protocol in &DEFAULT_WINSOCK_PROTOCOLS {
                winsock_values.push((
                    protocol.entry_key,
                    "PackedCatalogItem",
                    RegistryValueType::Binary,
                    default_winsock_protocol_catalog_item(protocol),
                ));
                winsock_values.push((
                    protocol.entry_key,
                    "ProtocolName",
                    RegistryValueType::Sz,
                    utf16le_nul(protocol.protocol_name),
                ));
            }
            for (key, name, value_type, value) in winsock_values {
                if let Err(status) =
                    write_value_in_fs(fs, &fs_context, key, name, value_type, &value)
                {
                    litebox_util_log::error!(name:% = name, status:? = status; "failed to initialize Winsock registry value");
                    break;
                }
            }
        }
        Self {
            fs,
            fs_context,
            notification_state: Mutex::new(RegistryNotificationState::default()),
            notification_pollee: Pollee::new(),
        }
    }

    fn open_key(
        &self,
        path: &str,
        desired_access: RegistryKeyAccess,
    ) -> Result<TypedFd<RegistryFileSystem<Platform>>, NtStatus> {
        self.fs
            .open(&self.fs_context, path, desired_access.into(), Mode::empty())
            .map_err(map_open_error)
    }

    fn read_value_at_path(
        &self,
        key_path: &str,
        value_name: &str,
    ) -> Result<RegistryValue, NtStatus> {
        let value_path = value_path(key_path, value_name)?;
        let status = self
            .fs
            .file_status(&self.fs_context, &*value_path)
            .map_err(map_file_status_error)?;
        if status.file_type != FileType::RegularFile {
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        }
        if status.size < REGISTRY_VALUE_TYPE_SIZE {
            return Err(NtStatus::UNSUCCESSFUL);
        }

        let fd = self
            .fs
            .open(
                &self.fs_context,
                &*value_path,
                OFlags::RDONLY,
                Mode::empty(),
            )
            .map_err(map_open_error)?;
        let mut data = vec![0; status.size];
        let result = read_exact_at(&self.fs, &fd, &mut data);
        let _ = self.fs.close(&fd);
        result?;

        let value_type = u32::from_le_bytes(
            data[..REGISTRY_VALUE_TYPE_SIZE]
                .try_into()
                .map_err(|_| NtStatus::UNSUCCESSFUL)?,
        );
        data.drain(..REGISTRY_VALUE_TYPE_SIZE);

        Ok(RegistryValue { value_type, data })
    }

    fn write_value_at_path(
        &self,
        key_path: &str,
        value_name: &str,
        value_type: u32,
        value: &[u8],
    ) -> Result<(), NtStatus> {
        write_value_at_path(
            &self.fs,
            &self.fs_context,
            key_path,
            value_name,
            value_type,
            value,
        )?;
        self.record_change(key_path, RegistryNotifyFilter::LAST_SET);
        Ok(())
    }

    fn record_key_created(&self, path: &str) {
        let Some((parent, _)) = path.rsplit_once('/') else {
            return;
        };
        if parent.is_empty() {
            return;
        }
        self.record_change(parent, RegistryNotifyFilter::NAME);
    }

    fn notification_generation(
        &self,
        path: &str,
        filter: RegistryNotifyFilter,
        watch_tree: bool,
    ) -> u64 {
        let state = self.notification_state.lock();
        let Some(changes) = state.keys.get(path) else {
            return 0;
        };
        let generations = if watch_tree {
            &changes.subtree
        } else {
            &changes.direct
        };
        registry_notify_filter_indices(filter)
            .map(|index| generations[index])
            .max()
            .unwrap_or(0)
    }

    fn record_change(&self, path: &str, filter: RegistryNotifyFilter) {
        let mut state = self.notification_state.lock();
        state.generation = state.generation.wrapping_add(1);
        if state.generation == 0 {
            state.generation = 1;
        }
        let generation = state.generation;
        let direct = state.keys.entry(String::from(path)).or_default();
        for index in registry_notify_filter_indices(filter) {
            direct.direct[index] = generation;
        }

        let mut ancestor = Some(path);
        while let Some(path) = ancestor {
            let changes = state.keys.entry(String::from(path)).or_default();
            for index in registry_notify_filter_indices(filter) {
                changes.subtree[index] = generation;
            }
            ancestor = path
                .rsplit_once('/')
                .map(|(parent, _)| parent)
                .filter(|parent| !parent.is_empty());
        }
        drop(state);
        self.notification_pollee.notify_observers(Events::IN);
    }

    fn key_summary(&self, key: &RegistryKeyObject<Platform>) -> Result<KeySummary, NtStatus> {
        let mut summary = KeySummary::default();
        for entry in self.fs.read_dir(&key.fd).map_err(map_read_dir_error)? {
            if entry.file_type == FileType::Directory
                && entry.name != "."
                && entry.name != ".."
                && entry.name != VALUES_DIR_NAME
            {
                summary.sub_keys += 1;
                summary.max_name_len = summary
                    .max_name_len
                    .max(entry.name.encode_utf16().count() * size_of::<u16>());
            }
        }

        let values_path = format!("{}/{}", key.path.trim_end_matches('/'), VALUES_DIR_NAME);
        let values_fd = self
            .fs
            .open(
                &self.fs_context,
                &*values_path,
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .map_err(map_open_error)?;
        let values = self.fs.read_dir(&values_fd).map_err(map_read_dir_error);
        let _ = self.fs.close(&values_fd);
        for entry in values? {
            if entry.file_type != FileType::RegularFile {
                continue;
            }
            summary.values += 1;
            summary.max_value_name_len = summary
                .max_value_name_len
                .max(entry.name.encode_utf16().count() * size_of::<u16>());
            let path = format!("{values_path}/{}", entry.name);
            let size = self
                .fs
                .file_status(&self.fs_context, &*path)
                .map_err(map_file_status_error)?
                .size;
            if size < REGISTRY_VALUE_TYPE_SIZE {
                return Err(NtStatus::UNSUCCESSFUL);
            }
            summary.max_value_data_len = summary
                .max_value_data_len
                .max(size - REGISTRY_VALUE_TYPE_SIZE);
        }
        Ok(summary)
    }

    /// Returns the deterministically-ordered leaf name of the `index`-th direct
    /// subkey of `key`, or `None` when `index` is out of range.
    ///
    /// `NtEnumerateKey` requires a stable subkey ordering across successive calls,
    /// but the backing directory iteration order is unspecified, so the filtered
    /// subkey names are sorted before indexing.
    fn nth_subkey_name(
        &self,
        key: &RegistryKeyObject<Platform>,
        index: u32,
    ) -> Result<Option<String>, NtStatus> {
        let mut names = Vec::new();
        for entry in self.fs.read_dir(&key.fd).map_err(map_read_dir_error)? {
            if entry.file_type == FileType::Directory
                && entry.name != "."
                && entry.name != ".."
                && entry.name != VALUES_DIR_NAME
            {
                names.push(entry.name);
            }
        }
        names.sort_unstable();
        Ok(names.into_iter().nth(index as usize))
    }

    /// Computes a [`KeySummary`] for the named direct subkey of `key`.
    fn subkey_summary(
        &self,
        key: &RegistryKeyObject<Platform>,
        name: &str,
    ) -> Result<KeySummary, NtStatus> {
        let child_path = format!("{}/{}", key.path.trim_end_matches('/'), name);
        let child_fd = self
            .fs
            .open(
                &self.fs_context,
                &*child_path,
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .map_err(map_open_error)?;
        let child = RegistryKeyObject {
            path: child_path,
            fd: child_fd,
        };
        let summary = self.key_summary(&child);
        let _ = self.fs.close(&child.fd);
        summary
    }

    /// Returns the deterministically-ordered name of the `index`-th value of
    /// `key`, or `None` when `index` is out of range.
    ///
    /// Like [`Self::nth_subkey_name`], `NtEnumerateValueKey` requires a stable
    /// ordering across successive calls, so the value names (stored as regular
    /// files under the key's `.values` directory) are sorted before indexing.
    fn nth_value_name(
        &self,
        key: &RegistryKeyObject<Platform>,
        index: u32,
    ) -> Result<Option<String>, NtStatus> {
        let values_path = format!("{}/{}", key.path.trim_end_matches('/'), VALUES_DIR_NAME);
        let values_fd = self
            .fs
            .open(
                &self.fs_context,
                &*values_path,
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .map_err(map_open_error)?;
        let entries = self.fs.read_dir(&values_fd).map_err(map_read_dir_error);
        let _ = self.fs.close(&values_fd);
        let mut names = Vec::new();
        for entry in entries? {
            if entry.file_type == FileType::RegularFile {
                names.push(entry.name);
            }
        }
        names.sort_unstable();
        Ok(names.into_iter().nth(index as usize))
    }
}

impl<Platform: crate::ShimPlatform> Task<Platform> {
    fn registry_key_entry(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, RegistryKeySubsystem<Platform>>, NtStatus> {
        raw_handle_entry::<Platform, RegistryKeySubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            handle,
        )
        .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn insert_registry_key_handle(
        &self,
        key: RegistryKeyObject<Platform>,
        granted_access: RegistryKeyAccess,
    ) -> Result<Handle, NtStatus> {
        self.insert_typed_handle::<RegistryKeySubsystem<Platform>>(
            key,
            granted_access.bits(),
            |key| {
                self.close_registry_key(key);
            },
        )
    }

    pub(crate) fn close_registry_key_handle(&self, handle: Handle) {
        self.close_typed_handle::<RegistryKeySubsystem<Platform>>(handle, |key| {
            self.close_registry_key(key);
        });
    }

    pub(crate) fn close_registry_key(&self, key: RegistryKeyObject<Platform>) {
        let _ = self.global.registry.fs.close(&key.fd);
    }

    pub(crate) fn sys_nt_open_key(
        &self,
        key_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        self.sys_nt_open_key_ex(key_handle, desired_access, object_attributes, 0)
    }

    pub(crate) fn sys_nt_open_key_ex(
        &self,
        key_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        open_options: u32,
    ) -> NtStatus {
        let Some(open_options) = RegistryOpenOptions::from_bits(open_options) else {
            return NtStatus::INVALID_PARAMETER_4;
        };
        // TODO(registry-symlink): Honor OPEN_LINK once registry symbolic links are modeled.
        // TODO(registry-backup): Apply backup/restore privileges once the security model exists.
        // TODO(registry-virtualization): Honor DONT_VIRTUALIZE once registry virtualization exists.
        if !open_options.is_empty() {
            litebox_util_log::debug!(
                open_options:? = open_options;
                "NtOpenKeyEx options have no effect in the current registry model"
            );
        }
        let Some(object_attributes) = object_attributes else {
            return NtStatus::INVALID_PARAMETER;
        };
        let object_attributes = match read_object_attributes::<Platform>(object_attributes) {
            Ok(object_attributes) => object_attributes,
            Err(status) => return status,
        };
        match self.do_nt_open_key(desired_access, object_attributes) {
            Ok(handle) => {
                if key_handle.write_at_offset(0, handle).is_none() {
                    self.close_registry_key_handle(handle);
                    return NtStatus::ACCESS_VIOLATION;
                }

                NtStatus::SUCCESS
            }
            Err(status) => status,
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "preserves the seven-argument NtCreateKey ABI"
    )]
    pub(crate) fn sys_nt_create_key(
        &self,
        key_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        title_index: u32,
        class: Option<ConstPtr<Platform, UnicodeString>>,
        create_options: u32,
        disposition: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        let Some(create_options) = RegistryCreateOptions::from_bits(create_options) else {
            return NtStatus::INVALID_PARAMETER;
        };
        if create_options
            .intersects(RegistryCreateOptions::VOLATILE | RegistryCreateOptions::CREATE_LINK)
        {
            // TODO(registry-volatile): Model volatile key lifetime and symbolic-link keys.
            return NtStatus::NOT_SUPPORTED;
        }
        if create_options.contains(RegistryCreateOptions::BACKUP_RESTORE) {
            // TODO(registry-backup): Apply backup/restore privileges to access checks.
            return NtStatus::NOT_SUPPORTED;
        }

        let Some(object_attributes) = object_attributes else {
            return NtStatus::INVALID_PARAMETER;
        };
        let object_attributes = match read_object_attributes::<Platform>(object_attributes) {
            Ok(object_attributes) => object_attributes,
            Err(status) => return status,
        };
        if let Some(class) = class {
            let Some(class) = class.read_at_offset(0) else {
                return NtStatus::ACCESS_VIOLATION;
            };
            if let Err(status) = class.read_string::<Platform>() {
                return status;
            }
            // TODO(registry-class): Persist this optional legacy class string so
            // NtQueryKey can return it in key node and full information.
        }
        if title_index != 0
            || create_options.intersects(
                RegistryCreateOptions::OPEN_LINK | RegistryCreateOptions::DONT_VIRTUALIZE,
            )
        {
            // TODO(registry-metadata): Preserve title indices and virtualization/open-link options.
            litebox_util_log::debug!(
                title_index,
                create_options:? = create_options;
                "NtCreateKey metadata has no effect in the current registry model"
            );
        }

        match self.do_nt_create_key(desired_access, object_attributes) {
            Ok((handle, key_disposition)) => {
                if let Some(disposition) = disposition
                    && disposition
                        .write_at_offset(0, u32::from(key_disposition))
                        .is_none()
                {
                    self.close_registry_key_handle(handle);
                    return NtStatus::ACCESS_VIOLATION;
                }
                if key_handle.write_at_offset(0, handle).is_none() {
                    self.close_registry_key_handle(handle);
                    return NtStatus::ACCESS_VIOLATION;
                }
                NtStatus::SUCCESS
            }
            Err(status) => status,
        }
    }

    fn do_nt_create_key(
        &self,
        desired_access: u32,
        object_attributes: ObjectAttributes,
    ) -> Result<(Handle, RegistryKeyDisposition), NtStatus> {
        let path = self.registry_key_path(object_attributes)?;
        let disposition = match self
            .global
            .registry
            .fs
            .file_status(&self.global.registry.fs_context, &path)
        {
            Ok(status) if status.file_type == FileType::Directory => {
                RegistryKeyDisposition::OpenedExistingKey
            }
            Ok(_) => return Err(NtStatus::OBJECT_TYPE_MISMATCH),
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => {
                for created_path in create_key_path_in_fs(
                    &self.global.registry.fs,
                    &self.global.registry.fs_context,
                    &path,
                )? {
                    self.global.registry.record_key_created(&created_path);
                }
                RegistryKeyDisposition::CreatedNewKey
            }
            Err(FileStatusError::PathError(error)) => {
                return Err(map_path_error(error, NtStatus::OBJECT_NAME_NOT_FOUND));
            }
            Err(_) => return Err(NtStatus::UNSUCCESSFUL),
        };

        let desired_access = RegistryKeyAccess::from_desired_access(desired_access);
        let fd = self.global.registry.open_key(&path, desired_access)?;
        let handle =
            self.insert_registry_key_handle(RegistryKeyObject { path, fd }, desired_access)?;
        Ok((handle, disposition))
    }

    fn do_nt_open_key(
        &self,
        desired_access: u32,
        object_attributes: ObjectAttributes,
    ) -> Result<Handle, NtStatus> {
        let path = self.registry_key_path(object_attributes)?;
        let desired_access = RegistryKeyAccess::from_desired_access(desired_access);
        let fd = self
            .global
            .registry
            .open_key(&path, desired_access)
            .inspect_err(|status| {
                if *status != NtStatus::OBJECT_NAME_NOT_FOUND {
                    litebox_util_log::debug!(
                        desired_access:? = desired_access,
                        path:% = path,
                        status:? = status;
                        "NtOpenKey failed"
                    );
                }
            })?;
        self.insert_registry_key_handle(RegistryKeyObject { path, fd }, desired_access)
    }

    fn registry_key_path(&self, object_attributes: ObjectAttributes) -> Result<String, NtStatus> {
        if object_attributes.object_name == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }

        let key_name = read_unicode_string_at::<Platform>(object_attributes.object_name)?;
        let path = if object_attributes.root_directory.is_null() || key_name.starts_with('\\') {
            absolute_nt_key_name_to_fs_path(&key_name)?
        } else {
            let root_key = self.registry_key_entry(object_attributes.root_directory)?;
            root_key
                .with_entry(|root_key| relative_nt_key_name_to_fs_path(&root_key.path, &key_name))?
        };
        Ok(path)
    }

    pub(crate) fn sys_nt_query_value_key(
        &self,
        key_handle: Handle,
        value_name: ConstPtr<Platform, UnicodeString>,
        key_value_information_class: u32,
        key_value_information: MutPtr<Platform, u8>,
        length: u32,
        result_length: MutPtr<Platform, u32>,
    ) -> NtStatus {
        let Some(value_name) = value_name.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let Ok(key_value_information_class) =
            KeyValueInformationClass::try_from(key_value_information_class)
        else {
            litebox_util_log::debug!(
                key_value_information_class = key_value_information_class;
                "Unsupported NtQueryValueKey class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };
        match self.do_nt_query_value_key(
            key_handle,
            value_name,
            key_value_information_class,
            key_value_information,
            length,
            result_length,
        ) {
            Ok(()) => NtStatus::SUCCESS,
            Err(status) => {
                litebox_util_log::debug!(
                    value_name:? = value_name.read_string::<Platform>(),
                    status:? = status;
                    "NtQueryValueKey failed"
                );
                status
            }
        }
    }

    pub(crate) fn sys_nt_enumerate_value_key(
        &self,
        key_handle: Handle,
        index: u32,
        key_value_information_class: u32,
        key_value_information: MutPtr<Platform, u8>,
        length: u32,
        result_length: MutPtr<Platform, u32>,
    ) -> NtStatus {
        let Ok(key_value_information_class) =
            KeyValueInformationClass::try_from(key_value_information_class)
        else {
            litebox_util_log::debug!(
                key_value_information_class = key_value_information_class;
                "Unsupported NtEnumerateValueKey class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };
        match self.do_nt_enumerate_value_key(
            key_handle,
            index,
            key_value_information_class,
            key_value_information,
            length,
            result_length,
        ) {
            Ok(()) => NtStatus::SUCCESS,
            Err(status) => status,
        }
    }

    fn do_nt_enumerate_value_key(
        &self,
        key_handle: Handle,
        index: u32,
        key_value_information_class: KeyValueInformationClass,
        key_value_information: MutPtr<Platform, u8>,
        length: u32,
        result_length: MutPtr<Platform, u32>,
    ) -> Result<(), NtStatus> {
        let key = self.typed_handle_entry_with_access::<RegistryKeySubsystem<Platform>>(
            key_handle,
            RegistryKeyAccess::QUERY_VALUE.bits(),
        )?;
        let (value_name, value) = key
            .with_entry(|key| {
                let Some(value_name) = self.global.registry.nth_value_name(key, index)? else {
                    return Ok(None);
                };
                let value = self
                    .global
                    .registry
                    .read_value_at_path(&key.path, &value_name)?;
                Ok::<_, NtStatus>(Some((value_name, value)))
            })?
            .ok_or(NtStatus::NO_MORE_ENTRIES)?;
        let name = utf16le(&value_name);
        write_key_value_information::<Platform>(
            key_value_information_class,
            key_value_information,
            length,
            &name,
            &value,
            result_length,
        )?;

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", key_handle.as_raw()),
            index = index,
            value_name:% = value_name,
            key_value_information_class:? = key_value_information_class,
            length = length;
            "Handled NtEnumerateValueKey syscall"
        );
        Ok(())
    }

    pub(crate) fn sys_nt_set_value_key(
        &self,
        key_handle: Handle,
        value_name: ConstPtr<Platform, UnicodeString>,
        title_index: u32,
        value_type: u32,
        data: Option<ConstPtr<Platform, u8>>,
        data_size: u32,
    ) -> NtStatus {
        let key = match self.typed_handle_entry_with_access::<RegistryKeySubsystem<Platform>>(
            key_handle,
            RegistryKeyAccess::SET_VALUE.bits(),
        ) {
            Ok(key) => key,
            Err(status) => return status,
        };
        let Some(value_name) = value_name.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let value_name = match value_name.read_string::<Platform>() {
            Ok(value_name) => value_name,
            Err(status) => return status,
        };
        let data = match (data, data_size) {
            (None, 0) => Vec::new(),
            (Some(data), data_size) => {
                let Some(data) = data.to_owned_slice(data_size as usize) else {
                    return NtStatus::ACCESS_VIOLATION;
                };
                data.into_vec()
            }
            (None, _) => return NtStatus::ACCESS_VIOLATION,
        };

        if title_index != 0 {
            // TODO(registry-metadata): Persist value title indices.
            litebox_util_log::debug!(
                title_index;
                "NtSetValueKey title index has no effect in the current registry model"
            );
        }
        match key.with_entry(|key| {
            self.global
                .registry
                .write_value_at_path(&key.path, &value_name, value_type, &data)
        }) {
            Ok(()) => NtStatus::SUCCESS,
            Err(status) => status,
        }
    }

    pub(crate) fn sys_nt_notify_change_key(
        &self,
        params: NtNotifyChangeKeyRequest<Platform>,
    ) -> NtStatus {
        let key = match self.typed_handle_entry_with_access::<RegistryKeySubsystem<Platform>>(
            params.key_handle,
            RegistryKeyAccess::NOTIFY.bits(),
        ) {
            Ok(key) => key,
            Err(status) => return status,
        };
        let Some(completion_filter) = RegistryNotifyFilter::from_bits(params.completion_filter)
        else {
            return NtStatus::INVALID_PARAMETER;
        };
        if probe_guest_output_preserving_value::<Platform, IoStatusBlock>(params.io_status_block)
            .is_err()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        if !params.asynchronous {
            let path = key.with_entry(|key| key.path.clone());
            let generation = self.global.registry.notification_generation(
                &path,
                completion_filter,
                params.watch_tree,
            );
            let wait_result = self.wait_on_events(
                false,
                false,
                None,
                Events::IN,
                |observer, mask| {
                    self.global
                        .registry
                        .notification_pollee
                        .register_observer(observer, mask);
                    Ok(())
                },
                || {
                    if self.global.registry.notification_generation(
                        &path,
                        completion_filter,
                        params.watch_tree,
                    ) == generation
                    {
                        Err(TryOpError::<NtStatus>::TryAgain)
                    } else {
                        Ok(())
                    }
                },
            );
            let status = match wait_result {
                Ok(()) => NtStatus::NOTIFY_ENUM_DIR,
                Err(TryOpError::WaitError(litebox::event::wait::WaitError::Interrupted)) => {
                    NtStatus::ALERTED
                }
                Err(TryOpError::WaitError(litebox::event::wait::WaitError::TimedOut)) => {
                    unreachable!("synchronous registry notifications have no timeout")
                }
                Err(TryOpError::TryAgain) => {
                    unreachable!("blocking registry notification cannot return TryAgain")
                }
                Err(TryOpError::Other(status)) => status,
            };
            if status == NtStatus::NOTIFY_ENUM_DIR
                && params
                    .io_status_block
                    .write_at_offset(0, IoStatusBlock::new(status, 0))
                    .is_none()
            {
                return NtStatus::ACCESS_VIOLATION;
            }
            return status;
        }
        if !params.event.is_null()
            && let Err(status) = self.check_event_modify_access(params.event)
        {
            return status;
        }
        if !params.event.is_null()
            && let Err(status) = self.clear_event(params.event)
        {
            return status;
        }
        if params
            .io_status_block
            .write_at_offset(0, IoStatusBlock::new(NtStatus::PENDING, 0))
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        if params.apc_routine.is_some()
            || params.apc_context.is_some()
            || params.buffer.is_some()
            || params.buffer_size != 0
        {
            litebox_util_log::warn!(
                key_handle = params.key_handle.as_raw(),
                apc_routine = params.apc_routine.is_some(),
                apc_context = params.apc_context.is_some(),
                buffer = params.buffer.is_some(),
                buffer_size = params.buffer_size;
                "NtNotifyChangeKey completion data cannot be delivered without registry change subscriptions"
            );
        }
        litebox_util_log::debug!(
            key_handle = params.key_handle.as_raw(),
            completion_filter = completion_filter.bits(),
            watch_tree = params.watch_tree,
            asynchronous = params.asynchronous;
            "Registered pending NtNotifyChangeKey request without a change subscription"
        );
        // TODO(registry-notify): Retain the request and complete it when a matching key changes.
        NtStatus::PENDING
    }

    pub(crate) fn sys_nt_query_key(
        &self,
        key_handle: Handle,
        key_information_class: u32,
        key_information: MutPtr<Platform, u8>,
        length: u32,
        result_length: MutPtr<Platform, u32>,
    ) -> NtStatus {
        let Ok(key_information_class) = KeyInformationClass::try_from(key_information_class) else {
            litebox_util_log::debug!(
                key_information_class = key_information_class;
                "Unsupported NtQueryKey class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        };
        if matches!(
            key_information_class,
            KeyInformationClass::Flags
                | KeyInformationClass::Virtualization
                | KeyInformationClass::Trust
                | KeyInformationClass::Layer
        ) {
            // TODO(registry-key-info): Model the extended key information classes.
            litebox_util_log::debug!(
                key_information_class:? = key_information_class;
                "Unsupported NtQueryKey class"
            );
            return NtStatus::INVALID_INFO_CLASS;
        }

        match self.do_nt_query_key(
            key_handle,
            key_information_class,
            key_information,
            length,
            result_length,
        ) {
            Ok(()) => NtStatus::SUCCESS,
            Err(status) => status,
        }
    }

    fn do_nt_query_key(
        &self,
        key_handle: Handle,
        key_information_class: KeyInformationClass,
        key_information: MutPtr<Platform, u8>,
        length: u32,
        result_length: MutPtr<Platform, u32>,
    ) -> Result<(), NtStatus> {
        let key = if key_information_class == KeyInformationClass::Name {
            // Windows permits KeyNameInformation with any nonzero granted access.
            self.typed_handle_entry_with_any_access::<RegistryKeySubsystem<Platform>>(key_handle)?
        } else {
            self.typed_handle_entry_with_access::<RegistryKeySubsystem<Platform>>(
                key_handle,
                RegistryKeyAccess::QUERY_VALUE.bits(),
            )?
        };
        let path = key.with_entry(|key| key.path.clone());
        let summary = if matches!(
            key_information_class,
            KeyInformationClass::Full | KeyInformationClass::Cached
        ) {
            key.with_entry(|key| self.global.registry.key_summary(key))?
        } else {
            KeySummary::default()
        };
        let leaf = path.rsplit('/').next().ok_or(NtStatus::UNSUCCESSFUL)?;
        let leaf_name = utf16le(leaf);

        match key_information_class {
            KeyInformationClass::Basic => {
                let header_len = offset_of!(KeyBasicInformation, name);
                let required_length = header_len
                    .checked_add(leaf_name.len())
                    .ok_or(NtStatus::UNSUCCESSFUL)?;
                let information = KeyBasicInformation {
                    // TODO(registry-time): Track registry key last-write timestamps.
                    last_write_time: [0; 8],
                    title_index: 0,
                    name_length: leaf_name.len().trunc(),
                    name: [],
                };
                write_query_information::<Platform>(
                    result_length,
                    key_information,
                    length,
                    header_len,
                    required_length,
                    information.as_bytes(),
                    &[(header_len, leaf_name.as_slice())],
                )?;
            }
            KeyInformationClass::Node => {
                let header_len = offset_of!(KeyNodeInformation, name);
                let required_length = header_len
                    .checked_add(leaf_name.len())
                    .ok_or(NtStatus::UNSUCCESSFUL)?;
                let information = KeyNodeInformation {
                    last_write_time: [0; 8],
                    title_index: 0,
                    class_offset: u32::MAX,
                    class_length: 0,
                    name_length: leaf_name.len().trunc(),
                    name: [],
                };
                write_query_information::<Platform>(
                    result_length,
                    key_information,
                    length,
                    header_len,
                    required_length,
                    information.as_bytes(),
                    &[(header_len, leaf_name.as_slice())],
                )?;
            }
            KeyInformationClass::Full => {
                let required_length = offset_of!(KeyFullInformation, class);
                let information = KeyFullInformation {
                    last_write_time: [0; 8],
                    title_index: 0,
                    class_offset: u32::MAX,
                    class_length: 0,
                    sub_keys: summary.sub_keys.trunc(),
                    max_name_len: summary.max_name_len.trunc(),
                    max_class_len: 0,
                    values: summary.values.trunc(),
                    max_value_name_len: summary.max_value_name_len.trunc(),
                    max_value_data_len: summary.max_value_data_len.trunc(),
                    class: [],
                };
                write_query_information::<Platform>(
                    result_length,
                    key_information,
                    length,
                    required_length,
                    required_length,
                    information.as_bytes(),
                    &[],
                )?;
            }
            KeyInformationClass::Name => {
                // TODO(registry-case): Preserve original subkey casing in the registry store.
                let name = utf16le(&format!(
                    "\\{}",
                    path.trim_start_matches('/')
                        .replace('/', "\\")
                        .to_ascii_uppercase()
                ));
                let header_len = offset_of!(KeyNameInformation, name);
                let required_length = header_len
                    .checked_add(name.len())
                    .ok_or(NtStatus::UNSUCCESSFUL)?;
                let information = KeyNameInformation {
                    name_length: name.len().trunc(),
                    name: [],
                };
                write_query_information::<Platform>(
                    result_length,
                    key_information,
                    length,
                    header_len,
                    required_length,
                    information.as_bytes(),
                    &[(header_len, name.as_slice())],
                )?;
            }
            KeyInformationClass::Cached => {
                let required_length = size_of::<KeyCachedInformation>();
                let information = KeyCachedInformation {
                    last_write_time: [0; 8],
                    title_index: 0,
                    sub_keys: summary.sub_keys.trunc(),
                    max_name_len: summary.max_name_len.trunc(),
                    values: summary.values.trunc(),
                    max_value_name_len: summary.max_value_name_len.trunc(),
                    max_value_data_len: summary.max_value_data_len.trunc(),
                    name_length: leaf_name.len().trunc(),
                    padding: [0; 4],
                };
                write_query_information::<Platform>(
                    result_length,
                    key_information,
                    length,
                    required_length,
                    required_length,
                    information.as_bytes(),
                    &[],
                )?;
            }
            KeyInformationClass::HandleTags => {
                let required_length = size_of::<KeyHandleTagsInformation>();
                let information = KeyHandleTagsInformation {
                    // Non-virtualized keys have no tags.
                    // TODO(registry-virtualization): Reflect tags once virtualization is modeled.
                    handle_tags: 0,
                };
                write_query_information::<Platform>(
                    result_length,
                    key_information,
                    length,
                    required_length,
                    required_length,
                    information.as_bytes(),
                    &[],
                )?;
            }
            KeyInformationClass::Flags
            | KeyInformationClass::Virtualization
            | KeyInformationClass::Trust
            | KeyInformationClass::Layer => return Err(NtStatus::INVALID_INFO_CLASS),
        }

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", key_handle.as_raw()),
            key_information_class:? = key_information_class,
            length = length;
            "Handled NtQueryKey syscall"
        );
        Ok(())
    }

    pub(crate) fn sys_nt_enumerate_key(
        &self,
        key_handle: Handle,
        index: u32,
        key_information_class: u32,
        key_information: MutPtr<Platform, u8>,
        length: u32,
        result_length: MutPtr<Platform, u32>,
    ) -> NtStatus {
        let Ok(key_information_class) = KeyInformationClass::try_from(key_information_class) else {
            litebox_util_log::debug!(
                key_information_class = key_information_class;
                "Unsupported NtEnumerateKey class"
            );
            return NtStatus::INVALID_PARAMETER;
        };
        if !matches!(
            key_information_class,
            KeyInformationClass::Basic | KeyInformationClass::Node | KeyInformationClass::Full
        ) {
            // NtEnumerateKey only produces KEY_BASIC/NODE/FULL_INFORMATION.
            litebox_util_log::debug!(
                key_information_class:? = key_information_class;
                "Unsupported NtEnumerateKey class"
            );
            return NtStatus::INVALID_PARAMETER;
        }

        match self.do_nt_enumerate_key(
            key_handle,
            index,
            key_information_class,
            key_information,
            length,
            result_length,
        ) {
            Ok(()) => NtStatus::SUCCESS,
            Err(status) => status,
        }
    }

    fn do_nt_enumerate_key(
        &self,
        key_handle: Handle,
        index: u32,
        key_information_class: KeyInformationClass,
        key_information: MutPtr<Platform, u8>,
        length: u32,
        result_length: MutPtr<Platform, u32>,
    ) -> Result<(), NtStatus> {
        let key = self.typed_handle_entry_with_access::<RegistryKeySubsystem<Platform>>(
            key_handle,
            RegistryKeyAccess::ENUMERATE_SUB_KEYS.bits(),
        )?;
        let Some(subkey_name) =
            key.with_entry(|key| self.global.registry.nth_subkey_name(key, index))?
        else {
            return Err(NtStatus::NO_MORE_ENTRIES);
        };
        let summary = if key_information_class == KeyInformationClass::Full {
            key.with_entry(|key| self.global.registry.subkey_summary(key, &subkey_name))?
        } else {
            KeySummary::default()
        };
        let leaf_name = utf16le(&subkey_name);

        match key_information_class {
            KeyInformationClass::Basic => {
                let header_len = offset_of!(KeyBasicInformation, name);
                let required_length = header_len
                    .checked_add(leaf_name.len())
                    .ok_or(NtStatus::UNSUCCESSFUL)?;
                let information = KeyBasicInformation {
                    // TODO(registry-time): Track registry key last-write timestamps.
                    last_write_time: [0; 8],
                    title_index: 0,
                    name_length: leaf_name.len().trunc(),
                    name: [],
                };
                write_query_information::<Platform>(
                    result_length,
                    key_information,
                    length,
                    header_len,
                    required_length,
                    information.as_bytes(),
                    &[(header_len, leaf_name.as_slice())],
                )?;
            }
            KeyInformationClass::Node => {
                let header_len = offset_of!(KeyNodeInformation, name);
                let required_length = header_len
                    .checked_add(leaf_name.len())
                    .ok_or(NtStatus::UNSUCCESSFUL)?;
                let information = KeyNodeInformation {
                    last_write_time: [0; 8],
                    title_index: 0,
                    class_offset: u32::MAX,
                    class_length: 0,
                    name_length: leaf_name.len().trunc(),
                    name: [],
                };
                write_query_information::<Platform>(
                    result_length,
                    key_information,
                    length,
                    header_len,
                    required_length,
                    information.as_bytes(),
                    &[(header_len, leaf_name.as_slice())],
                )?;
            }
            KeyInformationClass::Full => {
                let required_length = offset_of!(KeyFullInformation, class);
                let information = KeyFullInformation {
                    last_write_time: [0; 8],
                    title_index: 0,
                    class_offset: u32::MAX,
                    class_length: 0,
                    sub_keys: summary.sub_keys.trunc(),
                    max_name_len: summary.max_name_len.trunc(),
                    max_class_len: 0,
                    values: summary.values.trunc(),
                    max_value_name_len: summary.max_value_name_len.trunc(),
                    max_value_data_len: summary.max_value_data_len.trunc(),
                    class: [],
                };
                write_query_information::<Platform>(
                    result_length,
                    key_information,
                    length,
                    required_length,
                    required_length,
                    information.as_bytes(),
                    &[],
                )?;
            }
            _ => return Err(NtStatus::INVALID_INFO_CLASS),
        }

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", key_handle.as_raw()),
            index = index,
            key_information_class:? = key_information_class,
            length = length;
            "Handled NtEnumerateKey syscall"
        );
        Ok(())
    }

    fn do_nt_query_value_key(
        &self,
        key_handle: Handle,
        value_name: UnicodeString,
        key_value_information_class: KeyValueInformationClass,
        key_value_information: MutPtr<Platform, u8>,
        length: u32,
        result_length: MutPtr<Platform, u32>,
    ) -> Result<(), NtStatus> {
        let key = self.typed_handle_entry_with_access::<RegistryKeySubsystem<Platform>>(
            key_handle,
            RegistryKeyAccess::QUERY_VALUE.bits(),
        )?;
        let value_name = value_name.read_string::<Platform>()?;
        let value = key.with_entry(|key| {
            // TODO: Open the value relative to `key.fd` once the FS has an openat-style API.
            self.global
                .registry
                .read_value_at_path(&key.path, &value_name)
        })?;
        let name = utf16le(&value_name);
        write_key_value_information::<Platform>(
            key_value_information_class,
            key_value_information,
            length,
            &name,
            &value,
            result_length,
        )?;

        litebox_util_log::debug!(
            handle:% = format_args!("{:#x}", key_handle.as_raw()),
            value_name:% = value_name,
            key_value_information_class:? = key_value_information_class,
            length = length;
            "Handled NtQueryValueKey syscall"
        );

        Ok(())
    }
}

/// Serializes a registry value into the requested `KEY_VALUE_*_INFORMATION`
/// layout, shared by `NtQueryValueKey` and `NtEnumerateValueKey`.
fn write_key_value_information<Platform: litebox::platform::RawPointerProvider>(
    key_value_information_class: KeyValueInformationClass,
    key_value_information: MutPtr<Platform, u8>,
    length: u32,
    name: &[u8],
    value: &RegistryValue,
    result_length: MutPtr<Platform, u32>,
) -> Result<(), NtStatus> {
    match key_value_information_class {
        KeyValueInformationClass::Basic => {
            let required_length = size_of::<KeyValueBasicInformation>()
                .checked_add(name.len())
                .ok_or(NtStatus::UNSUCCESSFUL)?;
            let information = KeyValueBasicInformation {
                title_index: 0,
                value_type: value.value_type,
                name_length: name.len().trunc(),
                name: [0u8; 0],
            };
            write_query_information::<Platform>(
                result_length,
                key_value_information,
                length,
                offset_of!(KeyValueBasicInformation, name),
                required_length,
                information.as_bytes(),
                &[(offset_of!(KeyValueBasicInformation, name), name)],
            )?;
        }
        KeyValueInformationClass::Full => {
            let name_end = offset_of!(KeyValueFullInformation, name)
                .checked_add(name.len())
                .ok_or(NtStatus::UNSUCCESSFUL)?;
            let data_offset = name_end
                .checked_next_multiple_of(4)
                .ok_or(NtStatus::UNSUCCESSFUL)?;
            let required_length = data_offset
                .checked_add(value.data.len())
                .ok_or(NtStatus::UNSUCCESSFUL)?;
            let information = KeyValueFullInformation {
                title_index: 0,
                value_type: value.value_type,
                data_offset: data_offset.trunc(),
                data_length: value.data.len().trunc(),
                name_length: name.len().trunc(),
                name: [0u8; 0],
            };
            write_query_information::<Platform>(
                result_length,
                key_value_information,
                length,
                offset_of!(KeyValueFullInformation, name),
                required_length,
                information.as_bytes(),
                &[
                    (offset_of!(KeyValueFullInformation, name), name),
                    (data_offset, value.data.as_slice()),
                ],
            )?;
        }
        KeyValueInformationClass::Partial => {
            let required_length = size_of::<KeyValuePartialInformation>()
                .checked_add(value.data.len())
                .ok_or(NtStatus::UNSUCCESSFUL)?;
            let information = KeyValuePartialInformation {
                title_index: 0,
                value_type: value.value_type,
                data_length: value.data.len().trunc(),
                data: [0u8; 0],
            };
            write_query_information::<Platform>(
                result_length,
                key_value_information,
                length,
                offset_of!(KeyValuePartialInformation, data),
                required_length,
                information.as_bytes(),
                &[(
                    offset_of!(KeyValuePartialInformation, data),
                    value.data.as_slice(),
                )],
            )?;
        }
    }
    Ok(())
}

fn write_query_information<Platform: litebox::platform::RawPointerProvider>(
    result_length: MutPtr<Platform, u32>,
    information: MutPtr<Platform, u8>,
    buffer_length: u32,
    header_length: usize,
    required_length: usize,
    header: &[u8],
    trailing_slices: &[(usize, &[u8])],
) -> Result<(), NtStatus> {
    result_length
        .write_at_offset(0, required_length.trunc())
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    let buffer_length = buffer_length as usize;
    if buffer_length < header_length {
        return Err(NtStatus::BUFFER_TOO_SMALL);
    }
    information
        .write_slice_at_offset(0, header)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    for &(offset, bytes) in trailing_slices {
        let write_length = bytes.len().min(buffer_length.saturating_sub(offset));
        if write_length == 0 {
            continue;
        }
        information
            .write_slice_at_offset(offset.cast_signed(), &bytes[..write_length])
            .ok_or(NtStatus::ACCESS_VIOLATION)?;
    }
    if buffer_length < required_length {
        return Err(NtStatus::BUFFER_OVERFLOW);
    }
    Ok(())
}

fn utf16le(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for code_unit in value.encode_utf16() {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
    bytes
}

fn utf16le_nul(value: &str) -> Vec<u8> {
    let mut bytes = utf16le(value);
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

fn default_winsock_protocol_catalog_item(protocol: &DefaultWinsockProtocol) -> Vec<u8> {
    let provider_path = b"%SystemRoot%\\system32\\mswsock.dll\0";
    let mut packed_provider_path = [0; WINSOCK_PROVIDER_PATH_SIZE];
    packed_provider_path[..provider_path.len()].copy_from_slice(provider_path);

    let protocol_name: Vec<u16> = protocol.protocol_name.encode_utf16().collect();
    let mut packed_protocol_name = [0; 256];
    assert!(protocol_name.len() < packed_protocol_name.len());
    packed_protocol_name[..protocol_name.len()].copy_from_slice(&protocol_name);

    let item = WinsockPackedCatalogItem {
        provider_path: packed_provider_path,
        protocol_info: WsaProtocolInfo {
            service_flags1: protocol.service_flags,
            service_flags2: 0,
            service_flags3: 0,
            service_flags4: 0,
            provider_flags: 8,
            provider_id: protocol.provider_id,
            catalog_entry_id: protocol.catalog_entry_id,
            protocol_chain: WsaProtocolChain {
                chain_len: 1,
                chain_entries: [0; 7],
            },
            version: 2,
            address_family: protocol.address_family,
            max_socket_address: protocol.socket_address_size,
            min_socket_address: protocol.socket_address_size,
            socket_type: protocol.socket_type,
            protocol: protocol.protocol,
            protocol_max_offset: 0,
            network_byte_order: 0,
            security_scheme: 0,
            message_size: protocol.message_size,
            provider_reserved: 0,
            protocol_name: packed_protocol_name,
        },
    };
    item.as_bytes().to_vec()
}

fn absolute_nt_key_name_to_fs_path(name: &str) -> Result<String, NtStatus> {
    if !name.starts_with('\\') {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    let mut path = String::from("/");
    append_registry_components(&mut path, name.trim_start_matches('\\'))?;
    Ok(path)
}

fn relative_nt_key_name_to_fs_path(root: &str, name: &str) -> Result<String, NtStatus> {
    if name.starts_with('\\') {
        return absolute_nt_key_name_to_fs_path(name);
    }
    let mut path = String::from(root);
    append_registry_components(&mut path, name)?;
    Ok(path)
}

fn append_registry_components(path: &mut String, name: &str) -> Result<(), NtStatus> {
    if name.is_empty() {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    for component in name.split('\\') {
        if !is_valid_key_component(component) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str(&component.to_ascii_lowercase());
    }
    Ok(())
}

fn is_valid_key_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && !component.eq_ignore_ascii_case(VALUES_DIR_NAME)
        && !component.contains('/')
}

fn write_value_in_fs<Platform: crate::ShimPlatform>(
    fs: &RegistryFileSystem<Platform>,
    context: &litebox::fs::resolver::Context,
    key_nt_path: &str,
    value_name: &str,
    value_type: RegistryValueType,
    value: &[u8],
) -> Result<(), NtStatus> {
    let key_path = create_key_in_fs(fs, context, key_nt_path)?;
    write_value_at_path(fs, context, &key_path, value_name, value_type.into(), value)
}

fn write_value_at_path<Platform: crate::ShimPlatform>(
    fs: &RegistryFileSystem<Platform>,
    context: &litebox::fs::resolver::Context,
    key_path: &str,
    value_name: &str,
    value_type: u32,
    value: &[u8],
) -> Result<(), NtStatus> {
    let value_path = value_path(key_path, value_name)?;
    let fd = fs
        .open(
            context,
            &*value_path,
            OFlags::CREAT | OFlags::WRONLY | OFlags::TRUNC,
            Mode::RUSR | Mode::WUSR | Mode::ROTH | Mode::WOTH,
        )
        .map_err(map_open_error)?;
    let result = (|| {
        write_all_at(fs, &fd, &value_type.to_le_bytes(), 0)?;
        write_all_at(fs, &fd, value, REGISTRY_VALUE_TYPE_SIZE)
    })();
    let _ = fs.close(&fd);
    result
}

fn read_exact_at<Platform: crate::ShimPlatform>(
    fs: &RegistryFileSystem<Platform>,
    fd: &TypedFd<RegistryFileSystem<Platform>>,
    mut data: &mut [u8],
) -> Result<(), NtStatus> {
    let mut offset = 0;
    while !data.is_empty() {
        let read = fs.read(fd, data, Some(offset)).map_err(map_read_error)?;
        if read == 0 {
            return Err(NtStatus::UNSUCCESSFUL);
        }
        offset = offset.checked_add(read).ok_or(NtStatus::UNSUCCESSFUL)?;
        data = &mut data[read..];
    }
    Ok(())
}

fn write_all_at<Platform: crate::ShimPlatform>(
    fs: &RegistryFileSystem<Platform>,
    fd: &TypedFd<RegistryFileSystem<Platform>>,
    mut data: &[u8],
    mut offset: usize,
) -> Result<(), NtStatus> {
    while !data.is_empty() {
        let written = fs.write(fd, data, Some(offset)).map_err(map_write_error)?;
        if written == 0 {
            return Err(NtStatus::DISK_FULL);
        }
        offset = offset.checked_add(written).ok_or(NtStatus::DISK_FULL)?;
        data = &data[written..];
    }
    Ok(())
}

fn create_key_in_fs<Platform: crate::ShimPlatform>(
    fs: &RegistryFileSystem<Platform>,
    context: &litebox::fs::resolver::Context,
    nt_path: &str,
) -> Result<String, NtStatus> {
    let path = absolute_nt_key_name_to_fs_path(nt_path)?;
    create_key_path_in_fs(fs, context, &path)?;
    Ok(path)
}

fn create_key_path_in_fs<Platform: crate::ShimPlatform>(
    fs: &RegistryFileSystem<Platform>,
    context: &litebox::fs::resolver::Context,
    path: &str,
) -> Result<Vec<String>, NtStatus> {
    let mut current = String::new();
    let mut created_keys = Vec::new();
    for component in path.trim_start_matches('/').split('/') {
        if component.is_empty() {
            continue;
        }
        current.push('/');
        current.push_str(component);
        if ensure_directory_in_fs(fs, context, &current)? {
            created_keys.push(current.clone());
        }

        let mut values_dir = current.clone();
        values_dir.push('/');
        values_dir.push_str(VALUES_DIR_NAME);
        ensure_directory_in_fs(fs, context, &values_dir)?;
    }
    Ok(created_keys)
}

fn ensure_directory_in_fs<Platform: crate::ShimPlatform>(
    fs: &RegistryFileSystem<Platform>,
    context: &litebox::fs::resolver::Context,
    path: &str,
) -> Result<bool, NtStatus> {
    match fs.file_status(context, path) {
        Ok(status) if status.file_type == FileType::Directory => Ok(false),
        Ok(_) => Err(NtStatus::OBJECT_TYPE_MISMATCH),
        Err(FileStatusError::PathError(
            PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
        )) => match fs.mkdir(
            context,
            path,
            Mode::RUSR | Mode::WUSR | Mode::XUSR | Mode::ROTH | Mode::WOTH | Mode::XOTH,
        ) {
            Ok(()) => Ok(true),
            Err(MkdirError::AlreadyExists) => Ok(false),
            Err(error) => Err(map_mkdir_error(error)),
        },
        Err(FileStatusError::PathError(error)) => {
            Err(map_path_error(error, NtStatus::OBJECT_NAME_NOT_FOUND))
        }
        Err(_) => Err(NtStatus::UNSUCCESSFUL),
    }
}

fn value_path(key_path: &str, value_name: &str) -> Result<String, NtStatus> {
    if !is_valid_value_name(value_name) {
        return Err(NtStatus::INVALID_PARAMETER);
    }

    let mut path = String::from(key_path);
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(VALUES_DIR_NAME);
    path.push('/');
    path.push_str(&value_name.to_ascii_lowercase());
    Ok(path)
}

fn is_valid_value_name(value_name: &str) -> bool {
    !value_name.is_empty()
        && value_name != "."
        && value_name != ".."
        && !value_name.contains('/')
        && !value_name.contains('\\')
}

fn map_open_error(error: OpenError) -> NtStatus {
    match error {
        OpenError::PathError(error) => map_path_error(error, NtStatus::OBJECT_NAME_NOT_FOUND),
        OpenError::AccessNotAllowed | OpenError::NoWritePerms | OpenError::ReadOnlyFileSystem => {
            NtStatus::ACCESS_DENIED
        }
        OpenError::AlreadyExists => NtStatus::OBJECT_NAME_COLLISION,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_file_status_error(error: FileStatusError) -> NtStatus {
    match error {
        FileStatusError::PathError(error) => map_path_error(error, NtStatus::OBJECT_NAME_NOT_FOUND),
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_mkdir_error(error: MkdirError) -> NtStatus {
    match error {
        MkdirError::AlreadyExists => NtStatus::OBJECT_NAME_COLLISION,
        MkdirError::PathError(error) => map_path_error(error, NtStatus::OBJECT_PATH_NOT_FOUND),
        MkdirError::NoWritePerms | MkdirError::ReadOnlyFileSystem => NtStatus::ACCESS_DENIED,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_path_error(error: PathError, not_found_status: NtStatus) -> NtStatus {
    match error {
        PathError::NoSuchFileOrDirectory | PathError::MissingComponent => not_found_status,
        PathError::ComponentNotADirectory => NtStatus::NOT_A_DIRECTORY,
        PathError::InvalidPathname => NtStatus::INVALID_PARAMETER,
        PathError::NoSearchPerms { .. } => NtStatus::ACCESS_DENIED,
    }
}

fn map_write_error(error: WriteError) -> NtStatus {
    match error {
        WriteError::NotForWriting => NtStatus::ACCESS_DENIED,
        WriteError::NotAFile => NtStatus::OBJECT_TYPE_MISMATCH,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_read_error(error: ReadError) -> NtStatus {
    match error {
        ReadError::NotForReading => NtStatus::ACCESS_DENIED,
        ReadError::NotAFile => NtStatus::OBJECT_TYPE_MISMATCH,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

fn map_read_dir_error(error: ReadDirError) -> NtStatus {
    match error {
        ReadDirError::NotADirectory => NtStatus::NOT_A_DIRECTORY,
        _ => NtStatus::UNSUCCESSFUL,
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{
        TestPlatform, const_ptr, mut_byte_ptr, mut_ptr, object_attributes, test_platform,
        unicode_string, utf16_units as utf16,
    };

    use super::*;
    use core::mem::size_of;
    use litebox::LiteBox;

    extern crate std;

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    const ERROR_ACCESS_DENIED: i32 = 5;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    const ERROR_SUCCESS: i32 = 0;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    const HKEY_CURRENT_USER: *mut core::ffi::c_void = 0xffffffff80000001usize as _;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    const HKEY_LOCAL_MACHINE: *mut core::ffi::c_void = 0xffffffff80000002usize as _;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    const HOST_CODE_PAGE_KEY: &str = "SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage";
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    const HOST_ACCESS_TEST_KEY: &str = "Software\\LiteBoxRegistryAccessTest";

    const KEY_VALUE_PARTIAL_INFORMATION_DATA_OFFSET: usize =
        offset_of!(KeyValuePartialInformation, data);

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[allow(non_snake_case)]
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegCreateKeyExW(
            hKey: *mut core::ffi::c_void,
            lpSubKey: *const u16,
            Reserved: u32,
            lpClass: *const u16,
            dwOptions: u32,
            samDesired: u32,
            lpSecurityAttributes: *const core::ffi::c_void,
            phkResult: *mut *mut core::ffi::c_void,
            lpdwDisposition: *mut u32,
        ) -> i32;
        fn RegOpenKeyExW(
            hKey: *mut core::ffi::c_void,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut *mut core::ffi::c_void,
        ) -> i32;
        fn RegQueryValueExW(
            hKey: *mut core::ffi::c_void,
            lpValueName: *const u16,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            hKey: *mut core::ffi::c_void,
            lpValueName: *const u16,
            Reserved: u32,
            dwType: u32,
            lpData: *const u8,
            cbData: u32,
        ) -> i32;
        fn RegCloseKey(hKey: *mut core::ffi::c_void) -> i32;
        fn RegDeleteTreeW(hKey: *mut core::ffi::c_void, lpSubKey: *const u16) -> i32;
    }

    fn test_registry() -> (LiteBox<TestPlatform>, RegistryStore<TestPlatform>) {
        let litebox = LiteBox::new(test_platform());
        let registry = RegistryStore::new(&litebox);
        (litebox, registry)
    }

    fn open_key(
        task: &Task<TestPlatform>,
        object_attributes: ObjectAttributes,
    ) -> Result<Handle, NtStatus> {
        task.do_nt_open_key(RegistryKeyAccess::READ.bits(), object_attributes)
    }

    fn const_byte_ptr<T>(value: &T) -> ConstPtr<TestPlatform, u8> {
        ConstPtr::<TestPlatform, u8>::from_usize(core::ptr::from_ref(value).cast::<u8>() as usize)
    }

    fn open_code_page_key(task: &Task<TestPlatform>) -> Handle {
        let code_page_name = utf16(DEFAULT_CODE_PAGE_KEY);
        let code_page_name = unicode_string(&code_page_name);
        let object_attributes = object_attributes(&code_page_name, 0);
        open_key(task, object_attributes).expect("Failed to open code page key")
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn nul_terminated_utf16(value: &str) -> Vec<u16> {
        let mut value = utf16(value);
        value.push(0);
        value
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn host_registry_value(key_path: &str, value_name: &str) -> RegistryValue {
        let key_path = nul_terminated_utf16(key_path);
        let value_name = nul_terminated_utf16(value_name);
        let mut key = core::ptr::null_mut();
        // SAFETY: The key path is NUL-terminated, `phkResult` points to a live output
        // slot, and `HKEY_LOCAL_MACHINE` is the documented predefined registry handle.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                key_path.as_ptr(),
                0,
                RegistryKeyAccess::QUERY_VALUE.bits(),
                &raw mut key,
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "failed to open host registry key");

        let mut value_type = 0;
        let mut data_len = 0;
        // SAFETY: The key handle was returned by `RegOpenKeyExW`, the value name is
        // NUL-terminated, and the null data buffer requests the required byte length.
        let status = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                core::ptr::null_mut(),
                &raw mut value_type,
                core::ptr::null_mut(),
                &raw mut data_len,
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "failed to size host registry value");

        let mut data = vec![0; data_len as usize];
        // SAFETY: `data` has exactly the byte length returned by the sizing query,
        // and all other pointers remain valid for the duration of the call.
        let status = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                core::ptr::null_mut(),
                &raw mut value_type,
                data.as_mut_ptr(),
                &raw mut data_len,
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "failed to read host registry value");
        data.truncate(data_len as usize);

        // SAFETY: The key handle was returned by `RegOpenKeyExW` and has not been closed yet.
        let status = unsafe { RegCloseKey(key) };
        assert_eq!(status, ERROR_SUCCESS, "failed to close host registry key");

        RegistryValue { value_type, data }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn host_query_value_with_set_only_access() -> i32 {
        let key_path = nul_terminated_utf16(HOST_ACCESS_TEST_KEY);
        let value_name = nul_terminated_utf16("Value");
        let mut key = core::ptr::null_mut();
        // SAFETY: The key path is NUL-terminated, output pointers are live slots,
        // and `HKEY_CURRENT_USER` is the documented predefined registry handle.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                key_path.as_ptr(),
                0,
                core::ptr::null(),
                0,
                RegistryKeyAccess::QUERY_VALUE.bits() | RegistryKeyAccess::SET_VALUE.bits(),
                core::ptr::null(),
                &raw mut key,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "failed to create host test key");

        let data = [b'x', 0, 0, 0];
        // SAFETY: The key handle was returned by `RegCreateKeyExW`, the value name
        // is NUL-terminated, and `data` is valid for the specified byte length.
        let status = unsafe {
            RegSetValueExW(
                key,
                value_name.as_ptr(),
                0,
                RegistryValueType::Sz.into(),
                data.as_ptr(),
                data.len().trunc(),
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "failed to seed host test value");
        // SAFETY: The key handle was returned by `RegCreateKeyExW` and has not
        // been closed yet.
        let status = unsafe { RegCloseKey(key) };
        assert_eq!(status, ERROR_SUCCESS, "failed to close host test key");

        // SAFETY: The key path is NUL-terminated, `phkResult` points to a live
        // output slot, and `HKEY_CURRENT_USER` is the documented predefined handle.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                key_path.as_ptr(),
                0,
                RegistryKeyAccess::SET_VALUE.bits(),
                &raw mut key,
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "failed to reopen host test key");

        let mut value_type = 0;
        let mut data_len = 0;
        // SAFETY: The key handle was returned by `RegOpenKeyExW`, the value name
        // is NUL-terminated, and the null data buffer requests the required length.
        let query_status = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                core::ptr::null_mut(),
                &raw mut value_type,
                core::ptr::null_mut(),
                &raw mut data_len,
            )
        };

        // SAFETY: The key handle was returned by `RegOpenKeyExW` and has not been closed yet.
        let close_status = unsafe { RegCloseKey(key) };
        assert_eq!(close_status, ERROR_SUCCESS, "failed to close host test key");
        // SAFETY: The key path is NUL-terminated and rooted under the documented
        // predefined `HKEY_CURRENT_USER` handle.
        let delete_status = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, key_path.as_ptr()) };
        assert_eq!(
            delete_status, ERROR_SUCCESS,
            "failed to delete host test key"
        );

        query_status
    }

    #[test]
    fn registry_store_separates_values_from_subkeys() {
        let (_litebox, registry) = test_registry();
        let key_path = absolute_nt_key_name_to_fs_path(DEFAULT_CODE_PAGE_KEY).unwrap();
        let value_path = value_path(&key_path, "ACP").unwrap();

        assert_eq!(
            registry
                .fs
                .file_status(&registry.fs_context, &*value_path)
                .unwrap()
                .file_type,
            FileType::RegularFile
        );
        assert_eq!(
            registry
                .fs
                .file_status(&registry.fs_context, &*value_path)
                .unwrap()
                .size,
            REGISTRY_VALUE_TYPE_SIZE + DEFAULT_ACP_VALUE.len()
        );
        let value = registry.read_value_at_path(&key_path, "ACP").unwrap();
        assert_eq!(value.value_type, u32::from(RegistryValueType::Sz));
        assert_eq!(value.data, DEFAULT_ACP_VALUE);

        let values_dir = absolute_nt_key_name_to_fs_path(
            "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage\\.values",
        );
        assert_eq!(values_dir, Err(NtStatus::INVALID_PARAMETER));
    }

    #[test]
    fn nt_create_key_reports_disposition_and_created_key_is_queryable() {
        let task = crate::tests::test_task();
        let key_name = r"\Registry\Machine\Software\LiteBoxCreatedKey";
        let key_name_utf16 = utf16(key_name);
        let key_name = unicode_string(&key_name_utf16);
        let object_attributes = object_attributes(&key_name, 0);
        let mut handle = Handle::default();
        let mut disposition = 0;

        assert_eq!(
            task.sys_nt_create_key(
                mut_ptr(&mut handle),
                RegistryKeyAccess::READ.bits(),
                Some(const_ptr(&object_attributes)),
                0,
                None,
                0,
                Some(mut_ptr(&mut disposition)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            disposition,
            u32::from(RegistryKeyDisposition::CreatedNewKey)
        );

        let mut information = [0u8; 128];
        let mut result_length = 0;
        assert_eq!(
            task.sys_nt_query_key(
                handle,
                u32::from(KeyInformationClass::Name),
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::SUCCESS
        );
        let expected_name = utf16le(r"\REGISTRY\MACHINE\SOFTWARE\LITEBOXCREATEDKEY");
        let header_len = offset_of!(KeyNameInformation, name);
        assert_eq!(
            &information[header_len..header_len + expected_name.len()],
            expected_name.as_slice()
        );
        task.close_registry_key_handle(handle);

        let mut second_handle = Handle::default();
        disposition = 0;
        assert_eq!(
            task.sys_nt_create_key(
                mut_ptr(&mut second_handle),
                RegistryKeyAccess::READ.bits(),
                Some(const_ptr(&object_attributes)),
                0,
                None,
                0,
                Some(mut_ptr(&mut disposition)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            disposition,
            u32::from(RegistryKeyDisposition::OpenedExistingKey)
        );
        task.close_registry_key_handle(second_handle);

        assert_eq!(
            task.sys_nt_create_key(
                mut_ptr(&mut handle),
                RegistryKeyAccess::READ.bits(),
                Some(const_ptr(&object_attributes)),
                0,
                None,
                0x20,
                None,
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(
            task.sys_nt_create_key(
                mut_ptr(&mut handle),
                RegistryKeyAccess::READ.bits(),
                Some(const_ptr(&object_attributes)),
                0,
                None,
                RegistryCreateOptions::VOLATILE.bits(),
                None,
            ),
            NtStatus::NOT_SUPPORTED
        );
        assert_eq!(
            task.sys_nt_create_key(
                mut_ptr(&mut handle),
                RegistryKeyAccess::READ.bits(),
                Some(const_ptr(&object_attributes)),
                0,
                None,
                RegistryCreateOptions::CREATE_LINK.bits(),
                None,
            ),
            NtStatus::NOT_SUPPORTED
        );
    }

    #[test]
    fn nt_enumerate_key_lists_subkeys_in_stable_sorted_order() {
        let task = crate::tests::test_task();

        let create_key = |path: &str| -> Handle {
            let name_utf16 = utf16(path);
            let name = unicode_string(&name_utf16);
            let attributes = object_attributes(&name, 0);
            let mut handle = Handle::default();
            assert_eq!(
                task.sys_nt_create_key(
                    mut_ptr(&mut handle),
                    RegistryKeyAccess::READ.bits(),
                    Some(const_ptr(&attributes)),
                    0,
                    None,
                    0,
                    None,
                ),
                NtStatus::SUCCESS
            );
            handle
        };

        let parent_path = r"\Registry\Machine\Software\LiteBoxEnumParent";
        let parent = create_key(parent_path);
        // Create the subkeys out of alphabetical order to prove enumeration
        // imposes a deterministic sorted ordering independent of insertion order.
        task.close_registry_key_handle(create_key(&format!(r"{parent_path}\Beta")));
        task.close_registry_key_handle(create_key(&format!(r"{parent_path}\Alpha")));

        let enumerate_name = |index: u32| -> Option<Vec<u8>> {
            let mut information = [0u8; 128];
            let mut result_length = 0u32;
            let status = task.sys_nt_enumerate_key(
                parent,
                index,
                u32::from(KeyInformationClass::Basic),
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            );
            if status == NtStatus::NO_MORE_ENTRIES {
                return None;
            }
            assert_eq!(status, NtStatus::SUCCESS);
            let header_len = offset_of!(KeyBasicInformation, name);
            let name_len = result_length as usize - header_len;
            Some(information[header_len..header_len + name_len].to_vec())
        };

        // Key path components are stored lower-cased in the backing store.
        assert_eq!(enumerate_name(0), Some(utf16le("alpha")));
        assert_eq!(enumerate_name(1), Some(utf16le("beta")));
        assert_eq!(enumerate_name(2), None);

        // A class that `NtEnumerateKey` does not produce is rejected.
        let mut information = [0u8; 128];
        let mut result_length = 0u32;
        assert_eq!(
            task.sys_nt_enumerate_key(
                parent,
                0,
                u32::from(KeyInformationClass::Name),
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::INVALID_PARAMETER
        );

        task.close_registry_key_handle(parent);
    }

    fn notify_params(
        key_handle: Handle,
        io_status_block: &mut IoStatusBlock,
        completion_filter: u32,
        asynchronous: bool,
    ) -> NtNotifyChangeKeyRequest<TestPlatform> {
        NtNotifyChangeKeyRequest {
            key_handle,
            event: Handle::default(),
            apc_routine: None,
            apc_context: None,
            io_status_block: mut_ptr(io_status_block),
            completion_filter,
            watch_tree: false,
            buffer: None,
            buffer_size: 0,
            asynchronous,
        }
    }

    #[test]
    fn nt_set_value_key_replaces_and_round_trips_raw_types_and_empty_data() {
        let task = crate::tests::test_task();
        let key_name_utf16 = utf16(r"\Registry\Machine\Software\LiteBoxSetValueKey");
        let key_name = unicode_string(&key_name_utf16);
        let object_attributes = object_attributes(&key_name, 0);
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_key(
                mut_ptr(&mut handle),
                (RegistryKeyAccess::QUERY_VALUE | RegistryKeyAccess::SET_VALUE).bits(),
                Some(const_ptr(&object_attributes)),
                0,
                None,
                0,
                None,
            ),
            NtStatus::SUCCESS
        );

        let value_name_utf16 = utf16("Value");
        let value_name = unicode_string(&value_name_utf16);
        let initial_data = [1u8, 2, 3, 4, 5];
        assert_eq!(
            task.sys_nt_set_value_key(
                handle,
                const_ptr(&value_name),
                0,
                u32::from(RegistryValueType::Binary),
                Some(const_byte_ptr(&initial_data)),
                initial_data.len().trunc(),
            ),
            NtStatus::SUCCESS
        );

        let replacement_data = [9u8, 8];
        let custom_type = 0xfeed_beefu32;
        assert_eq!(
            task.sys_nt_set_value_key(
                handle,
                const_ptr(&value_name),
                0,
                custom_type,
                Some(const_byte_ptr(&replacement_data)),
                replacement_data.len().trunc(),
            ),
            NtStatus::SUCCESS
        );

        let mut information = [0u8; 64];
        let mut result_length = 0;
        assert_eq!(
            task.sys_nt_query_value_key(
                handle,
                const_ptr(&value_name),
                u32::from(KeyValueInformationClass::Partial),
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::SUCCESS
        );
        let (information, data) =
            KeyValuePartialInformation::read_from_prefix(&information[..result_length as usize])
                .unwrap();
        assert_eq!(information.value_type, custom_type);
        assert_eq!(data, replacement_data);

        let empty_name_utf16 = utf16("Empty");
        let empty_name = unicode_string(&empty_name_utf16);
        assert_eq!(
            task.sys_nt_set_value_key(handle, const_ptr(&empty_name), 0, custom_type, None, 0,),
            NtStatus::SUCCESS
        );
        let empty_value = task
            .global
            .registry
            .read_value_at_path("/registry/machine/software/liteboxsetvaluekey", "Empty")
            .unwrap();
        assert_eq!(empty_value.value_type, custom_type);
        assert!(empty_value.data.is_empty());

        task.close_registry_key_handle(handle);
        let read_only_handle = open_key(&task, object_attributes).unwrap();
        assert_eq!(
            task.sys_nt_set_value_key(
                read_only_handle,
                const_ptr(&value_name),
                0,
                custom_type,
                None,
                0,
            ),
            NtStatus::ACCESS_DENIED
        );
        task.close_registry_key_handle(read_only_handle);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn registry_default_code_page_values_match_host() {
        let task = crate::tests::test_task();
        let key_handle = open_code_page_key(&task);

        for name in ["ACP", "OEMCP", "MACCP"] {
            let host_value = host_registry_value(HOST_CODE_PAGE_KEY, name);
            let value_name = utf16(name);
            let value_name = unicode_string(&value_name);
            let mut information = [0u8; 64];
            let mut result_length = 0;

            assert!(
                task.do_nt_query_value_key(
                    key_handle,
                    value_name,
                    KeyValueInformationClass::Partial,
                    mut_byte_ptr(&mut information),
                    information.len().trunc(),
                    mut_ptr(&mut result_length),
                )
                .is_ok()
            );

            let information = &information[..(result_length as usize)];
            let (information, data) =
                KeyValuePartialInformation::read_from_prefix(information).unwrap();

            assert_eq!(host_value.value_type, u32::from(RegistryValueType::Sz));
            assert_eq!(information.value_type, host_value.value_type);
            assert_eq!(information.data_length as usize, host_value.data.len());
            assert_eq!(data, host_value.data.as_slice());
        }
    }

    #[test]
    fn nt_open_key_opens_existing_absolute_and_relative_keys() {
        let task = crate::tests::test_task();
        let nls_name = utf16("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls");
        let nls_name = unicode_string(&nls_name);
        let nls_object_attributes = object_attributes(&nls_name, 0);
        let nls_handle = open_key(&task, nls_object_attributes).expect("Failed to open NLS key");
        assert_ne!(nls_handle, Handle::default());

        let code_page_name = utf16("CodePage");
        let code_page_name = unicode_string(&code_page_name);
        let mut code_page_object_attributes = object_attributes(&code_page_name, 0);
        code_page_object_attributes.root_directory = nls_handle;
        let code_page_handle =
            open_key(&task, code_page_object_attributes).expect("Failed to open code page key");
        assert_ne!(code_page_handle, Handle::default());
    }

    #[test]
    fn nt_open_key_reports_missing_absolute_key() {
        let task = crate::tests::test_task();
        let name = utf16("\\Registry\\Machine\\Software\\Missing");
        let name = unicode_string(&name);
        let object_attributes = object_attributes(&name, 0);
        assert_eq!(
            open_key(&task, object_attributes).unwrap_err(),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
    }

    #[test]
    fn synchronous_nt_notify_change_key_completes_after_matching_mutation() {
        use std::time::Duration;

        let task = crate::tests::test_task();
        let key_name_utf16 = utf16(r"\Registry\Machine\Software\LiteBoxSynchronousNotify");
        let key_name = unicode_string(&key_name_utf16);
        let object_attributes = object_attributes(&key_name, 0);
        let mut key = Handle::default();
        assert_eq!(
            task.sys_nt_create_key(
                mut_ptr(&mut key),
                (RegistryKeyAccess::NOTIFY | RegistryKeyAccess::SET_VALUE).bits(),
                Some(const_ptr(&object_attributes)),
                0,
                None,
                0,
                None,
            ),
            NtStatus::SUCCESS
        );

        let writer = task.clone_for_test().expect("process is live");
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            let value_name_utf16 = utf16("Changed");
            let value_name = unicode_string(&value_name_utf16);
            let value = 1u32;
            writer.sys_nt_set_value_key(
                key,
                const_ptr(&value_name),
                0,
                u32::from(RegistryValueType::Dword),
                Some(const_byte_ptr(&value)),
                size_of::<u32>().trunc(),
            )
        });

        let mut io_status = IoStatusBlock::new(NtStatus::PENDING, usize::MAX);
        assert_eq!(
            task.sys_nt_notify_change_key(notify_params(
                key,
                &mut io_status,
                RegistryNotifyFilter::LAST_SET.bits(),
                false,
            )),
            NtStatus::NOTIFY_ENUM_DIR
        );
        assert_eq!(thread.join().unwrap(), NtStatus::SUCCESS);
        assert_eq!(io_status.status, NtStatus::NOTIFY_ENUM_DIR.as_raw());
        assert_eq!(io_status.information, 0);
    }

    #[test]
    fn synchronous_nt_notify_change_key_completes_after_subkey_creation() {
        use std::time::Duration;

        let task = crate::tests::test_task();
        let key_name_utf16 = utf16(r"\Registry\Machine\Software\LiteBoxSynchronousNameNotify");
        let key_name = unicode_string(&key_name_utf16);
        let parent_attributes = object_attributes(&key_name, 0);
        let mut key = Handle::default();
        assert_eq!(
            task.sys_nt_create_key(
                mut_ptr(&mut key),
                RegistryKeyAccess::NOTIFY.bits(),
                Some(const_ptr(&parent_attributes)),
                0,
                None,
                0,
                None,
            ),
            NtStatus::SUCCESS
        );

        let writer = task.clone_for_test().expect("process is live");
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            let child_name_utf16 = utf16(
                r"\Registry\Machine\Software\LiteBoxSynchronousNameNotify\Intermediate\Child",
            );
            let child_name = unicode_string(&child_name_utf16);
            let child_attributes = object_attributes(&child_name, 0);
            let mut child = Handle::default();
            writer.sys_nt_create_key(
                mut_ptr(&mut child),
                RegistryKeyAccess::QUERY_VALUE.bits(),
                Some(const_ptr(&child_attributes)),
                0,
                None,
                0,
                None,
            )
        });

        let mut io_status = IoStatusBlock::new(NtStatus::PENDING, usize::MAX);
        assert_eq!(
            task.sys_nt_notify_change_key(notify_params(
                key,
                &mut io_status,
                RegistryNotifyFilter::NAME.bits(),
                false,
            )),
            NtStatus::NOTIFY_ENUM_DIR
        );
        assert_eq!(thread.join().unwrap(), NtStatus::SUCCESS);
        assert_eq!(io_status.status, NtStatus::NOTIFY_ENUM_DIR.as_raw());
        assert_eq!(io_status.information, 0);
    }

    #[test]
    fn nt_open_key_rejects_invalid_relative_root() {
        let task = crate::tests::test_task();
        let name = utf16("Child");
        let name = unicode_string(&name);
        let mut object_attributes = object_attributes(&name, 0);
        object_attributes.root_directory = Handle::from_raw(0x1234);
        assert_eq!(
            open_key(&task, object_attributes).unwrap_err(),
            NtStatus::INVALID_HANDLE
        );
    }

    #[test]
    fn nt_open_key_checks_backing_fs_permissions() {
        let task = crate::tests::test_task();
        let private_key = "\\Registry\\Machine\\Software\\Private";
        let private_path = create_key_in_fs(
            &task.global.registry.fs,
            &task.global.registry.fs_context,
            private_key,
        )
        .unwrap();
        task.global
            .registry
            .fs
            .chmod(
                &task.global.registry.fs_context,
                &*private_path,
                Mode::WUSR | Mode::XUSR,
            )
            .unwrap();

        let private_name = utf16(private_key);
        let private_name = unicode_string(&private_name);
        let read_object_attributes = object_attributes(&private_name, 0);
        assert_eq!(
            open_key(&task, read_object_attributes).unwrap_err(),
            NtStatus::ACCESS_DENIED
        );

        let private_name = utf16(private_key);
        let private_name = unicode_string(&private_name);
        let write_object_attributes = object_attributes(&private_name, 0);
        let handle = task
            .do_nt_open_key(RegistryKeyAccess::SET_VALUE.bits(), write_object_attributes)
            .expect("write-only access should use write filesystem permissions");
        assert_ne!(handle, Handle::default());
    }

    #[test]
    fn nt_close_removes_registry_key_handle() {
        let task = crate::tests::test_task();
        let key_handle = open_code_page_key(&task);
        let value_name = utf16("ACP");
        let value_name = unicode_string(&value_name);
        let mut information = [0u8; 64];
        let mut result_length = 0;

        assert!(
            task.do_nt_query_value_key(
                key_handle,
                value_name,
                KeyValueInformationClass::Partial,
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            )
            .is_ok()
        );
        assert_eq!(task.sys_nt_close(key_handle), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_close(key_handle), NtStatus::INVALID_HANDLE);
        assert_eq!(
            task.do_nt_query_value_key(
                key_handle,
                value_name,
                KeyValueInformationClass::Partial,
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            )
            .unwrap_err(),
            NtStatus::INVALID_HANDLE
        );
    }

    #[test]
    fn nt_query_value_key_reports_partial_information() {
        let task = crate::tests::test_task();
        let key_handle = open_code_page_key(&task);
        let value_name = utf16("ACP");
        let value_name = unicode_string(&value_name);
        let mut information = [0u8; 64];
        let mut result_length = 0;

        assert!(
            task.do_nt_query_value_key(
                key_handle,
                value_name,
                KeyValueInformationClass::Partial,
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            )
            .is_ok()
        );

        assert_eq!(
            result_length as usize,
            size_of::<KeyValuePartialInformation>() + DEFAULT_ACP_VALUE.len()
        );
        let information = &information[..(result_length as usize)];
        let (information, data) =
            KeyValuePartialInformation::read_from_prefix(information).unwrap();
        assert_eq!(information.title_index, 0);
        assert_eq!(information.value_type, RegistryValueType::Sz.into());
        assert_eq!(information.data_length, DEFAULT_ACP_VALUE.len().trunc());
        assert_eq!(data, DEFAULT_ACP_VALUE);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_query_value_key_without_query_access_matches_host() {
        assert_eq!(host_query_value_with_set_only_access(), ERROR_ACCESS_DENIED);

        let task = crate::tests::test_task();
        let code_page_name = utf16(DEFAULT_CODE_PAGE_KEY);
        let code_page_name = unicode_string(&code_page_name);
        let object_attributes = object_attributes(&code_page_name, 0);
        let key_handle = task
            .do_nt_open_key(RegistryKeyAccess::SET_VALUE.bits(), object_attributes)
            .expect("write-only open should succeed against the seeded registry store");
        let value_name = utf16("ACP");
        let value_name = unicode_string(&value_name);
        let mut information = [0u8; 64];
        let mut result_length = 0;

        assert_eq!(
            task.do_nt_query_value_key(
                key_handle,
                value_name,
                KeyValueInformationClass::Partial,
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            )
            .unwrap_err(),
            NtStatus::ACCESS_DENIED
        );
    }

    #[test]
    fn nt_query_value_key_reports_basic_and_full_information() {
        let task = crate::tests::test_task();
        let key_handle = open_code_page_key(&task);
        let value_name = utf16("OEMCP");
        let value_name = unicode_string(&value_name);
        let mut basic_information = [0u8; 64];
        let mut full_information = [0u8; 64];
        let mut result_length = 0;

        assert!(
            task.do_nt_query_value_key(
                key_handle,
                value_name,
                KeyValueInformationClass::Basic,
                mut_byte_ptr(&mut basic_information),
                basic_information.len().trunc(),
                mut_ptr(&mut result_length),
            )
            .is_ok()
        );
        let name = utf16le("OEMCP");
        assert_eq!(
            result_length as usize,
            size_of::<KeyValueBasicInformation>() + name.len()
        );
        let basic_information = &basic_information[..(result_length as usize)];
        let (basic_information, basic_name) =
            KeyValueBasicInformation::read_from_prefix(basic_information).unwrap();
        assert_eq!(basic_information.title_index, 0);
        assert_eq!(basic_information.value_type, RegistryValueType::Sz.into());
        assert_eq!(basic_information.name_length as usize, name.len());
        assert_eq!(basic_name, name.as_slice());

        assert!(
            task.do_nt_query_value_key(
                key_handle,
                value_name,
                KeyValueInformationClass::Full,
                mut_byte_ptr(&mut full_information),
                full_information.len().trunc(),
                mut_ptr(&mut result_length),
            )
            .is_ok()
        );
        let full_information = &full_information[..(result_length as usize)];
        let (full_header, full_tail) =
            KeyValueFullInformation::read_from_prefix(full_information).unwrap();
        let data_offset = full_header.data_offset as usize;
        assert_eq!(full_header.title_index, 0);
        assert_eq!(full_header.value_type, RegistryValueType::Sz.into());
        assert_eq!(full_header.data_length as usize, DEFAULT_OEMCP_VALUE.len());
        assert_eq!(full_header.name_length as usize, name.len());
        assert_eq!(&full_tail[..name.len()], name.as_slice());
        assert_eq!(
            &full_information[data_offset..data_offset + DEFAULT_OEMCP_VALUE.len()],
            DEFAULT_OEMCP_VALUE
        );
    }

    #[test]
    fn nt_enumerate_value_key_lists_values_in_stable_sorted_order() {
        let task = crate::tests::test_task();
        // The code-page key is seeded with ACP, OEMCP, and MACCP values, which
        // are stored lower-cased and therefore enumerate as acp, maccp, oemcp.
        let key_handle = open_code_page_key(&task);

        let expected = [("acp", DEFAULT_ACP_VALUE), ("maccp", DEFAULT_MACCP_VALUE)];
        for (index, (name, data)) in expected.iter().enumerate() {
            let index = u32::try_from(index).unwrap();
            let mut information = [0u8; 96];
            let mut result_length = 0;
            assert_eq!(
                task.sys_nt_enumerate_value_key(
                    key_handle,
                    index,
                    u32::from(KeyValueInformationClass::Full),
                    mut_byte_ptr(&mut information),
                    information.len().trunc(),
                    mut_ptr(&mut result_length),
                ),
                NtStatus::SUCCESS
            );
            let (full_header, full_tail) =
                KeyValueFullInformation::read_from_prefix(&information[..result_length as usize])
                    .unwrap();
            let name_utf16 = utf16le(name);
            assert_eq!(full_header.name_length as usize, name_utf16.len());
            assert_eq!(&full_tail[..name_utf16.len()], name_utf16.as_slice());
            let data_offset = full_header.data_offset as usize;
            assert_eq!(full_header.data_length as usize, data.len());
            assert_eq!(&information[data_offset..data_offset + data.len()], *data);
        }

        // The third value (oemcp) is reachable via Basic information at index 2.
        let mut information = [0u8; 96];
        let mut result_length = 0;
        assert_eq!(
            task.sys_nt_enumerate_value_key(
                key_handle,
                2,
                u32::from(KeyValueInformationClass::Basic),
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::SUCCESS
        );
        let (_, basic_name) =
            KeyValueBasicInformation::read_from_prefix(&information[..result_length as usize])
                .unwrap();
        assert_eq!(basic_name, utf16le("oemcp").as_slice());

        // Enumerating past the final value reports STATUS_NO_MORE_ENTRIES.
        assert_eq!(
            task.sys_nt_enumerate_value_key(
                key_handle,
                3,
                u32::from(KeyValueInformationClass::Basic),
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::NO_MORE_ENTRIES
        );

        // An unsupported information class is rejected.
        assert_eq!(
            task.sys_nt_enumerate_value_key(
                key_handle,
                0,
                0xffff,
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::INVALID_INFO_CLASS
        );
    }

    #[test]
    fn nt_query_value_key_rejects_invalid_arguments() {
        let task = crate::tests::test_task();
        let key_handle = open_code_page_key(&task);
        let value_name = utf16("ACP");
        let value_name = unicode_string(&value_name);
        let missing_value_name = utf16("Missing");
        let missing_value_name = unicode_string(&missing_value_name);
        let mut information = [0u8; 64];
        let mut short_information = [0xa5; KEY_VALUE_PARTIAL_INFORMATION_DATA_OFFSET - 1];
        let mut result_length = 0;

        assert_eq!(
            task.do_nt_query_value_key(
                Handle::from_raw(0x1234),
                value_name,
                KeyValueInformationClass::Partial,
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            )
            .unwrap_err(),
            NtStatus::INVALID_HANDLE
        );

        assert_eq!(
            task.do_nt_query_value_key(
                key_handle,
                missing_value_name,
                KeyValueInformationClass::Partial,
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            )
            .unwrap_err(),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );

        assert_eq!(
            task.sys_nt_query_value_key(
                key_handle,
                const_ptr(&value_name),
                0xffff,
                mut_byte_ptr(&mut information),
                information.len().trunc(),
                mut_ptr(&mut result_length),
            ),
            NtStatus::INVALID_INFO_CLASS
        );

        assert_eq!(
            task.do_nt_query_value_key(
                key_handle,
                value_name,
                KeyValueInformationClass::Partial,
                mut_byte_ptr(&mut short_information),
                short_information.len().trunc(),
                mut_ptr(&mut result_length),
            )
            .unwrap_err(),
            NtStatus::BUFFER_TOO_SMALL
        );
        assert_eq!(result_length, 22);
        assert_eq!(
            short_information,
            [0xa5; KEY_VALUE_PARTIAL_INFORMATION_DATA_OFFSET - 1]
        );

        let header_len = offset_of!(KeyValueBasicInformation, name);
        information.fill(0xa5);
        assert_eq!(
            task.do_nt_query_value_key(
                key_handle,
                value_name,
                KeyValueInformationClass::Basic,
                mut_byte_ptr(&mut information),
                (header_len + 1).trunc(),
                mut_ptr(&mut result_length),
            ),
            Err(NtStatus::BUFFER_OVERFLOW)
        );
        assert_eq!(result_length as usize, header_len + utf16le("ACP").len());
        assert_eq!(information[header_len], b'A');
        assert_eq!(information[header_len + 1], 0xa5);
    }

    #[test]
    fn nt_query_key_reports_full_and_cached_information() {
        let task = crate::tests::test_task();
        let key_handle = open_code_page_key(&task);

        let mut full_bytes = [0u8; 64];
        let mut result_length = 0;
        assert!(
            task.do_nt_query_key(
                key_handle,
                KeyInformationClass::Full,
                mut_byte_ptr(&mut full_bytes),
                full_bytes.len().trunc(),
                mut_ptr(&mut result_length),
            )
            .is_ok()
        );
        assert_eq!(
            result_length as usize,
            offset_of!(KeyFullInformation, class)
        );
        let full = KeyFullInformation::read_from_prefix(&full_bytes).unwrap().0;
        assert_eq!(full.sub_keys, 0);
        assert_eq!(full.max_name_len, 0);
        assert_eq!(full.values, 3);
        assert_eq!(full.max_value_name_len, utf16le("oemcp").len().trunc());
        assert_eq!(full.max_value_data_len, DEFAULT_MACCP_VALUE.len().trunc());
        assert_eq!(full.class_offset, u32::MAX);
        assert_eq!(full.class_length, 0);

        let mut cached_bytes = [0u8; size_of::<KeyCachedInformation>()];
        assert!(
            task.do_nt_query_key(
                key_handle,
                KeyInformationClass::Cached,
                mut_byte_ptr(&mut cached_bytes),
                cached_bytes.len().trunc(),
                mut_ptr(&mut result_length),
            )
            .is_ok()
        );
        let cached = KeyCachedInformation::read_from_bytes(&cached_bytes).unwrap();
        assert_eq!(cached.values, full.values);
        assert_eq!(cached.max_value_name_len, full.max_value_name_len);
        assert_eq!(cached.max_value_data_len, full.max_value_data_len);
        assert_eq!(cached.name_length, utf16le("codepage").len().trunc());
    }
}
