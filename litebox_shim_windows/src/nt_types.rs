// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use core::mem::offset_of;
use litebox::platform::{RawConstPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{ConstPtr, syscalls::Handle};

pub const X64_CONTEXT_CONTROL: u32 = 0x0010_0001;
pub const X64_CONTEXT_INTEGER: u32 = 0x0010_0002;
pub const X64_CONTEXT_FLOATING_POINT: u32 = 0x0010_0008;
pub const X64_CONTEXT_DEBUG_REGISTERS: u32 = 0x0010_0010;

const INITIAL_CONTEXT_MXCSR: u32 = 0x1f80;
const USER_MODE_CODE_SELECTOR: u16 = 0x33;
const USER_MODE_STACK_SELECTOR: u16 = 0x2b;
const INITIAL_CONTEXT_EFLAGS: u32 = 0x200;

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct X64Context {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mx_csr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub e_flags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub extended_state: [u8; 0x3d0],
}

impl Default for X64Context {
    fn default() -> Self {
        Self {
            p1_home: 0,
            p2_home: 0,
            p3_home: 0,
            p4_home: 0,
            p5_home: 0,
            p6_home: 0,
            context_flags: 0,
            mx_csr: 0,
            seg_cs: 0,
            seg_ds: 0,
            seg_es: 0,
            seg_fs: 0,
            seg_gs: 0,
            seg_ss: 0,
            e_flags: 0,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rsp: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            extended_state: [0; 0x3d0],
        }
    }
}

impl X64Context {
    pub(crate) fn initial_thread_context(
        thread_entry_point: usize,
        application_entry_point: usize,
        stack_top: usize,
        peb: usize,
    ) -> X64Context {
        X64Context {
            context_flags: X64_CONTEXT_CONTROL
                | X64_CONTEXT_INTEGER
                | X64_CONTEXT_FLOATING_POINT
                | X64_CONTEXT_DEBUG_REGISTERS,
            mx_csr: INITIAL_CONTEXT_MXCSR,
            seg_cs: USER_MODE_CODE_SELECTOR,
            seg_ss: USER_MODE_STACK_SELECTOR,
            e_flags: INITIAL_CONTEXT_EFLAGS,
            rcx: application_entry_point as u64,
            rdx: peb as u64,
            rsp: stack_top as u64,
            rip: thread_entry_point as u64,
            ..X64Context::default()
        }
    }
}

bitflags::bitflags! {
    /// Common Windows object-manager `ACCESS_MASK` rights shared by NT object types.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct AccessMask: u32 {
        const DELETE = 0x0001_0000;
        const READ_CONTROL = 0x0002_0000;
        const WRITE_DAC = 0x0004_0000;
        const WRITE_OWNER = 0x0008_0000;
        const SYNCHRONIZE = 0x0010_0000;
        const STANDARD_RIGHTS_READ = Self::READ_CONTROL.bits();
        const STANDARD_RIGHTS_WRITE = Self::READ_CONTROL.bits();
        const STANDARD_RIGHTS_EXECUTE = Self::READ_CONTROL.bits();
        const STANDARD_RIGHTS_ALL = Self::DELETE.bits()
            | Self::READ_CONTROL.bits()
            | Self::WRITE_DAC.bits()
            | Self::WRITE_OWNER.bits()
            | Self::SYNCHRONIZE.bits();

        const GENERIC_ALL = 0x1000_0000;
        const GENERIC_EXECUTE = 0x2000_0000;
        const GENERIC_WRITE = 0x4000_0000;
        const GENERIC_READ = 0x8000_0000;

        const _ = !0;
    }
}

bitflags::bitflags! {
    /// Flags carried in `OBJECT_ATTRIBUTES.Attributes`.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct ObjectAttributesFlags: u32 {
        const CASE_INSENSITIVE = 0x0000_0040;
        const OPENIF = 0x0000_0080;
        const OPENLINK = 0x0000_0100;

        const _ = !0;
    }
}

impl AccessMask {
    pub(crate) fn expand_generic_access(
        desired_access: u32,
        generic_read: u32,
        generic_write: u32,
        generic_execute: u32,
        generic_all: u32,
    ) -> u32 {
        let mut access = desired_access;
        if desired_access & Self::GENERIC_READ.bits() != 0 {
            access |= generic_read;
        }
        if desired_access & Self::GENERIC_WRITE.bits() != 0 {
            access |= generic_write;
        }
        if desired_access & Self::GENERIC_EXECUTE.bits() != 0 {
            access |= generic_execute;
        }
        if desired_access & Self::GENERIC_ALL.bits() != 0 {
            access |= generic_all;
        }
        access
            & !(Self::GENERIC_READ.bits()
                | Self::GENERIC_WRITE.bits()
                | Self::GENERIC_EXECUTE.bits()
                | Self::GENERIC_ALL.bits())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable)]
pub(crate) struct ObjectAttributes {
    pub(crate) length: u32,
    pub(crate) root_directory: Handle,
    pub(crate) object_name: usize,
    pub(crate) attributes: u32,
    pub(crate) security_descriptor: usize,
    pub(crate) security_quality_of_service: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable)]
pub(crate) struct IoStatusBlock {
    pub(crate) status: i32,
    pub(crate) padding_0: [u8; 4],
    pub(crate) information: usize,
}

const _: () = assert!(offset_of!(IoStatusBlock, information) == 0x8);

impl IoStatusBlock {
    pub(crate) const fn new(status: NtStatus, information: usize) -> Self {
        Self {
            status: status.as_raw(),
            padding_0: [0; 4],
            information,
        }
    }
}

pub(crate) fn read_object_attributes<Platform: RawPointerProvider>(
    object_attributes: ConstPtr<Platform, ObjectAttributes>,
) -> Result<ObjectAttributes, NtStatus> {
    let Some(object_attributes) = object_attributes.read_at_offset(0) else {
        return Err(NtStatus::ACCESS_VIOLATION);
    };
    if object_attributes.length as usize != size_of::<ObjectAttributes>() {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    Ok(object_attributes)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub(crate) struct UnicodeString {
    pub(crate) length: u16,
    pub(crate) maximum_length: u16,
    pub(crate) padding_0: [u8; 4],
    pub(crate) buffer: usize,
}

impl UnicodeString {
    pub(crate) fn read_string<Platform: RawPointerProvider>(self) -> Result<String, NtStatus> {
        if !self.length.is_multiple_of(2) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if self.maximum_length < self.length {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if self.length == 0 {
            return Ok(String::new());
        }
        if self.buffer == 0 {
            return Err(NtStatus::ACCESS_VIOLATION);
        }

        let chars = usize::from(self.length / 2);
        let buffer =
            <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<u16>::from_usize(
                self.buffer,
            );
        let Some(units) = buffer.to_owned_slice(chars) else {
            return Err(NtStatus::ACCESS_VIOLATION);
        };
        Ok(String::from_utf16_lossy(&units))
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub(crate) struct AhcServiceLookupCdb {
    pub(crate) name: UnicodeString,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub(crate) struct AhcServiceData {
    // TODO(ahc-service-data): model the full Win11 AHC_SERVICE_DATA sub-structs
    // once their live boundaries are probed; phnt's ntmisc.h layout diverges
    // from the observed guest layout before the verified fields below.
    pub(crate) reserved_0: [u8; 0xf8],
    pub(crate) lookup_cdb: AhcServiceLookupCdb,
    pub(crate) reserved_1: [u8; 0x68],
    pub(crate) driver_status: i32,
    pub(crate) reserved_2: [u8; 4],
    pub(crate) params_out: usize,
    pub(crate) params_out_size: u32,
    pub(crate) reserved_3: [u8; 4],
}

bitflags::bitflags! {
    /// Packed process flags stored in `PEB.BitField`.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct PebBitField: u8 {
        const IMAGE_USES_LARGE_PAGES = 1 << 0;
        const IS_PROTECTED_PROCESS = 1 << 1;
        const IS_IMAGE_DYNAMICALLY_RELOCATED = 1 << 2;
        const SKIP_PATCHING_USER32_FORWARDERS = 1 << 3;
        const IS_PACKAGED_PROCESS = 1 << 4;
        const IS_APP_CONTAINER = 1 << 5;
        const IS_PROTECTED_PROCESS_LIGHT = 1 << 6;
        const IS_LONG_PATH_AWARE_PROCESS = 1 << 7;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct ProcessEnvironmentBlock {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,
    /// [`PebBitField`]
    pub bit_field: u8,
    pub padding_0: [u8; 4],
    pub mutant: usize,
    pub image_base_address: usize,
    pub ldr: usize,
    /// Pointer to [`RtlUserProcessParameters`].
    pub process_parameters: usize,
    pub sub_system_data: usize,
    pub process_heap: usize,
    pub fast_peb_lock: usize,
    pub atl_thunk_s_list_ptr: usize,
    pub ifeo_key: usize,
    pub cross_process_flags: u32,
    pub padding_1: [u8; 4],
    pub kernel_callback_table: usize,
    pub system_reserved: u32,
    pub atl_thunk_s_list_ptr_32: u32,
    pub api_set_map: usize,
    pub tls_expansion_counter: u32,
    pub padding_2: [u8; 4],
    pub tls_bitmap: usize,
    pub tls_bitmap_bits: [u32; 2],
    pub read_only_shared_memory_base: usize,
    pub shared_data: usize,
    pub read_only_static_server_data: usize,
    pub ansi_code_page_data: usize,
    pub oem_code_page_data: usize,
    pub unicode_case_table_data: usize,
    pub number_of_processors: u32,
    pub nt_global_flag: u32,
    pub critical_section_timeout: i64,
    pub heap_segment_reserve: u64,
    pub heap_segment_commit: u64,
    pub heap_de_commit_total_free_threshold: u64,
    pub heap_de_commit_free_block_threshold: u64,
    pub number_of_heaps: u32,
    pub maximum_number_of_heaps: u32,
    pub process_heaps: usize,
    pub gdi_shared_handle_table: usize,
    pub process_starter_helper: usize,
    pub gdi_dc_attribute_list: u32,
    pub padding_3: [u8; 4],
    pub loader_lock: usize,
    pub os_major_version: u32,
    pub os_minor_version: u32,
    pub os_build_number: u16,
    pub os_csd_version: u16,
    pub os_platform_id: u32,
    pub image_subsystem: u32,
    pub image_subsystem_major_version: u32,
    pub image_subsystem_minor_version: u32,
    pub padding_4: [u8; 4],
    pub active_process_affinity_mask: u64,
    pub gdi_handle_buffer: [u32; 60],
    pub post_process_init_routine: usize,
    pub tls_expansion_bitmap: usize,
    pub tls_expansion_bitmap_bits: [u32; 32],
    pub session_id: u32,
    pub padding_5: [u8; 4],
    pub app_compat_flags: u64,
    pub app_compat_flags_user: u64,
    pub p_shim_data: usize,
    pub app_compat_info: usize,
    pub csd_version: UnicodeString,
    pub activation_context_data: usize,
    pub process_assembly_storage_map: usize,
    pub system_default_activation_context_data: usize,
    pub system_assembly_storage_map: usize,
    pub minimum_stack_commit: u64,
    pub spare_pointers: [usize; 2],
    pub patch_loader_data: usize,
    pub chpe_v2_process_info: usize,
    pub app_model_feature_state: u32,
    pub spare_ulongs: [u32; 2],
    pub active_code_page: u16,
    pub oem_code_page: u16,
    pub use_case_mapping: u16,
    pub unused_nls_field: u16,
    pub padding_6a: [u8; 4],
    pub wer_registration_data: usize,
    pub wer_ship_assert_ptr: usize,
    pub ec_code_bit_map: usize,
    pub p_image_header_hash: usize,
    pub tracing_flags: u32,
    pub padding_6: [u8; 4],
    pub csr_server_read_only_shared_memory_base: u64,
    pub tpp_workerp_list_lock: u64,
    pub tpp_workerp_list: ListEntry,
    pub wait_on_address_hash_table: [usize; 128],
    pub telemetry_coverage_header: usize,
    pub cloud_file_flags: u32,
    pub cloud_file_diag_flags: u32,
    pub placeholder_compatibility_mode: i8,
    pub placeholder_compatibility_mode_reserved: [i8; 7],
    pub leap_second_data: usize,
    pub leap_second_flags: u32,
    pub nt_global_flag_2: u32,
    pub extended_feature_disable_mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct NtTib {
    pub exception_list: usize,
    pub stack_base: usize,
    pub stack_limit: usize,
    pub sub_system_tib: usize,
    pub fiber_data_or_version: usize,
    pub arbitrary_user_pointer: usize,
    pub self_pointer: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct ActivationContextStack {
    _reserved: [u8; 0x28],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct GdiTebBatch {
    _reserved: [u8; 0x4e8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, Immutable)]
pub struct ClientId {
    pub unique_process: usize,
    pub unique_thread: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct ListEntry {
    pub flink: usize,
    pub blink: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct Guid {
    pub data: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct GroupAffinity {
    pub mask: usize,
    pub group: u16,
    pub reserved: [u16; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct ThreadEnvironmentBlock {
    pub nt_tib: NtTib,
    pub environment_pointer: usize,
    pub client_id: ClientId,
    pub active_rpc_handle: usize,
    pub thread_local_storage_pointer: usize,
    /// Pointer to [`ProcessEnvironmentBlock`].
    pub process_environment_block: usize,
    pub last_error_value: u32,
    pub count_of_owned_critical_sections: u32,
    pub csr_client_thread: usize,
    pub win_32_thread_info: usize,
    pub user_32_reserved: [u32; 26],
    pub user_reserved: [u32; 5],
    pub padding_user_reserved: [u8; 4],
    pub wow_32_reserved: usize,
    pub current_locale: u32,
    pub fp_software_status_register: u32,
    pub reserved_for_debugger_instrumentation: [usize; 16],
    pub system_reserved_1: [usize; 25],
    pub heap_fls_data: usize,
    pub rng_state: [u64; 4],
    pub placeholder_compatibility_mode: i8,
    pub placeholder_hydration_always_explicit: u8,
    pub placeholder_reserved: [i8; 10],
    pub proxied_process_id: u32,
    pub activation_stack: ActivationContextStack,
    pub working_on_behalf_ticket: [u8; 8],
    pub exception_code: i32,
    pub padding_0: [u8; 4],
    pub activation_context_stack_pointer: usize,
    pub instrumentation_callback_sp: u64,
    pub instrumentation_callback_previous_pc: u64,
    pub instrumentation_callback_previous_sp: u64,
    pub tx_fs_context: u32,
    pub instrumentation_callback_disabled: u8,
    pub unaligned_load_store_exceptions: u8,
    pub padding_1: [u8; 2],
    pub gdi_teb_batch: GdiTebBatch,
    pub real_client_id: ClientId,
    pub gdi_cached_process_handle: usize,
    pub gdi_client_pid: u32,
    pub gdi_client_tid: u32,
    pub gdi_thread_local_info: usize,
    pub win_32_client_info: [u64; 62],
    pub gl_dispatch_table: [usize; 233],
    pub gl_reserved_1: [u64; 29],
    pub gl_reserved_2: usize,
    pub gl_section_info: usize,
    pub gl_section: usize,
    pub gl_table: usize,
    pub gl_current_rc: usize,
    pub gl_context: usize,
    pub last_status_value: u32,
    pub padding_2: [u8; 4],
    pub static_unicode_string: UnicodeString,
    pub static_unicode_buffer: [u16; 261],
    pub padding_3: [u8; 6],
    pub deallocation_stack: usize,
    pub tls_slots: [usize; 64],
    pub tls_links: ListEntry,
    pub vdm: usize,
    pub reserved_for_nt_rpc: usize,
    pub dbg_ss_reserved: [usize; 2],
    pub hard_error_mode: u32,
    pub padding_4: [u8; 4],
    pub instrumentation: [usize; 11],
    pub activity_id: Guid,
    pub sub_process_tag: usize,
    pub perflib_data: usize,
    pub etw_trace_data: usize,
    pub win_sock_data: usize,
    pub gdi_batch_count: u32,
    pub ideal_processor_value: u32,
    pub guaranteed_stack_bytes: u32,
    pub padding_5: [u8; 4],
    pub reserved_for_perf: usize,
    pub reserved_for_ole: usize,
    pub waiting_on_loader_lock: u32,
    pub padding_6: [u8; 4],
    pub saved_priority_state: usize,
    pub reserved_for_code_coverage: u64,
    pub thread_pool_data: usize,
    pub tls_expansion_slots: usize,
    pub chpe_v_2_cpu_area_info: usize,
    pub unused: usize,
    pub mui_generation: u32,
    pub is_impersonating: u32,
    pub nls_cache: usize,
    pub p_shim_data: usize,
    pub heap_data: u32,
    pub padding_7: [u8; 4],
    pub current_transaction_handle: usize,
    pub active_frame: usize,
    pub fls_data: usize,
    pub preferred_languages: usize,
    pub user_pref_languages: usize,
    pub merged_pref_languages: usize,
    pub mui_impersonation: u32,
    pub cross_teb_flags: u16,
    pub same_teb_flags: u16,
    pub txn_scope_enter_callback: usize,
    pub txn_scope_exit_callback: usize,
    pub txn_scope_context: usize,
    pub lock_count: u32,
    pub wow_teb_offset: i32,
    pub resource_ret_value: usize,
    pub reserved_for_wdf: usize,
    pub reserved_for_crt: u64,
    pub effective_container_id: Guid,
    pub last_sleep_counter: u64,
    pub spin_call_count: u32,
    pub padding_8: [u8; 4],
    pub extended_feature_disable_mask: u64,
    pub scheduler_shared_data_slot: usize,
    pub heap_walk_context: usize,
    pub primary_group_affinity: GroupAffinity,
    pub rcu: [u32; 2],
}

bitflags::bitflags! {
    /// Flags stored in `RTL_USER_PROCESS_PARAMETERS.Flags`.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct RtlUserProcFlags: u32 {
        /// Pointers in the process-parameter block are absolute addresses.
        const NORMALIZED = 0x0000_0001;
        const PROFILE_USER = 0x0000_0002;
        const PROFILE_KERNEL = 0x0000_0004;
        const PROFILE_SERVER = 0x0000_0008;
        const UNKNOWN = 0x0000_0010;
        /// Reserve low address space at process creation.
        const RESERVE_1MB = 0x0000_0020;
        /// Reserve low address space at process creation.
        const RESERVE_16MB = 0x0000_0040;
        const CASE_SENSITIVE = 0x0000_0080;
        const DISABLE_HEAP_DECOMMIT = 0x0000_0100;
        const PROCESS_OR_1 = 0x0000_0200;
        const PROCESS_OR_2 = 0x0000_0400;
        const DLL_REDIRECTION_LOCAL = 0x0000_1000;
        /// An application manifest was detected during process creation.
        const APP_MANIFEST_PRESENT = 0x0000_2000;
        /// The corresponding Image File Execution Options key was missing at process creation.
        const IMAGE_KEY_MISSING = 0x0000_4000;
        /// System-global IFEO development override support is enabled.
        const DEV_OVERRIDE_ENABLED = 0x0000_8000;
        const OPTIN_PROCESS = 0x0002_0000;
        const SESSION_OWNER = 0x0004_0000;
        const HANDLE_USER_CALLBACK_EXCEPTIONS = 0x0008_0000;
        const PROTECTED_PROCESS = 0x0040_0000;
        const NO_IMAGE_EXPANSION_MITIGATION = 0x0200_0000;
        const APPX_LOADER_ALTERNATE_FORWARDER = 0x0400_0000;
        const APPX_GLOBAL_OVERRIDE = 0x0800_0000;
        /// Allow the loader to use OneCore API-set forwarders when resolving imports.
        const ONECORE_FORWARDERS_ENABLED = 0x2000_0000;
        /// Opt back in to the normal `ExitProcess` path that detaches DLLs on exit.
        const EXIT_PROCESS_NORMAL = 0x4000_0000;
        const SECURE_PROCESS = 0x8000_0000;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct CurDir {
    pub dos_path: UnicodeString,
    pub handle: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct RtlDriveLetterCurdir {
    /// Per-drive current-directory flags.
    pub flags: u16,
    /// Length of the drive current-directory entry.
    pub length: u16,
    /// Timestamp associated with this drive current-directory entry.
    pub time_stamp: u32,
    /// DOS path for this drive's current directory.
    pub dos_path: UnicodeString,
}

/// Memory layout of this struct:
///
/// ```text
/// +-------------------------------+
/// | RTL_USER_PROCESS_PARAMETERS   |
/// | fixed-size struct             |
/// +-------------------------------+
/// | CurrentDirectory.DosPath      |
/// | (string buffer)               |
/// +-------------------------------+
/// | DllPath                       |
/// +-------------------------------+
/// | ImagePathName                 |
/// +-------------------------------+
/// | CommandLine                   |
/// +-------------------------------+
/// | WindowTitle                   |
/// +-------------------------------+
/// | DesktopInfo                   |
/// +-------------------------------+
/// | ShellInfo                     |
/// +-------------------------------+
/// | RuntimeData                   |
/// +-------------------------------+
/// | RedirectionDllName            |
/// +-------------------------------+
/// ```
///
/// See <https://ntdoc.m417z.com/rtl_user_process_parameters> for details on the fields of this struct.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct RtlUserProcessParameters {
    /// Total allocated size of this process-parameter buffer, in bytes.
    pub maximum_length: u32,
    /// Size of the process-parameter block, including any inline variable-length strings.
    pub length: u32,
    /// Process-parameter flags (see [`RtlUserProcFlags`]).
    pub flags: u32,
    /// Debug flags associated with these process parameters.
    pub debug_flags: u32,
    /// Console session handle, inherited or derived from process creation options.
    pub console_handle: usize,
    /// Console behavior flags, such as ignoring Ctrl+C requests.
    pub console_flags: u32,
    /// Reserved alignment padding.
    pub padding_0: [u8; 4],
    /// Standard input handle from `STARTUPINFO.hStdInput`.
    pub standard_input: usize,
    /// Standard output handle from `STARTUPINFO.hStdOutput`.
    pub standard_output: usize,
    /// Standard error handle from `STARTUPINFO.hStdError`.
    pub standard_error: usize,
    /// Current directory path and handle.
    pub current_directory: CurDir,
    /// Semicolon-separated DOS-style DLL search paths.
    pub dll_path: UnicodeString,
    /// Full DOS-style path to the executable image.
    pub image_path_name: UnicodeString,
    /// Command line string passed to the process.
    pub command_line: UnicodeString,
    /// Pointer to the separately allocated environment block.
    pub environment: usize,
    /// Initial window X position when `window_flags` requests a position.
    pub starting_x: u32,
    /// Initial window Y position when `window_flags` requests a position.
    pub starting_y: u32,
    /// Initial window width when `window_flags` requests a size.
    pub count_x: u32,
    /// Initial window height when `window_flags` requests a size.
    pub count_y: u32,
    /// Initial console screen-buffer width in character cells.
    pub count_chars_x: u32,
    /// Initial console screen-buffer height in character cells.
    pub count_chars_y: u32,
    /// Initial console text/background color attributes.
    pub fill_attribute: u32,
    /// `STARTUPINFO` flags describing which startup fields are valid.
    pub window_flags: u32,
    /// `ShowWindow` value used when `window_flags` includes `STARTF_USESHOWWINDOW`.
    pub show_window_flags: u32,
    /// Reserved alignment padding.
    pub padding_1: [u8; 4],
    /// Console window title, shortcut path, or AppUserModelID depending on `window_flags`.
    pub window_title: UnicodeString,
    /// Window station and desktop name, such as `WinSta0\Default`.
    pub desktop_info: UnicodeString,
    /// Startup shell data corresponding to `STARTUPINFO.lpReserved`.
    pub shell_info: UnicodeString,
    /// Runtime data corresponding to `STARTUPINFO.lpReserved2` and `cbReserved2`.
    pub runtime_data: UnicodeString,
    /// Per-drive current-directory entries for the 32 DOS drive letters.
    pub current_directories: [RtlDriveLetterCurdir; 32],
    /// Allocated size of the environment block, in bytes.
    pub environment_size: u64,
    /// Environment version incremented when environment strings change.
    pub environment_version: u64,
    /// Package dependency metadata pointer.
    pub package_dependency_data: usize,
    /// Console process group identifier used to scope control-signal delivery.
    pub process_group_id: u32,
    /// Requested worker-thread count for parallel DLL loading.
    pub loader_threads: u32,
    /// DLL path used for packaged-app import redirection.
    pub redirection_dll_name: UnicodeString,
    /// Heap partition name.
    pub heap_partition_name: UnicodeString,
    /// Pointer to default thread-pool CPU-set masks.
    pub default_threadpool_cpu_set_masks: usize,
    /// Number of default thread-pool CPU-set masks.
    pub default_threadpool_cpu_set_mask_count: u32,
    /// Maximum default thread-pool thread count.
    pub default_threadpool_thread_maximum: u32,
    /// Heap memory type mask.
    pub heap_memory_type_mask: u32,
    /// Reserved tail padding.
    pub padding_2: [u8; 4],
}

const _: [(); 0x1878] = [(); core::mem::size_of::<ThreadEnvironmentBlock>()];
const _: [(); 0x7d0] = [(); core::mem::size_of::<ProcessEnvironmentBlock>()];
const _: [(); 0x4d0] = [(); core::mem::size_of::<X64Context>()];
const _: [(); 0x448] = [(); core::mem::size_of::<RtlUserProcessParameters>()];

#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct KSystemTime {
    pub low_part: u32,
    pub high_1_time: i32,
    pub high_2_time: i32,
}

#[cfg(not(target_os = "windows"))]
const WINDOWS_KUSER_SHARED_DATA_XSTATE_CONFIGURATION_SIZE: usize = 0x348;

/// Layout from Wine `include/ddk/wdm.h` and ReactOS `sdk/include/wine/ddk/wdm.h`.
#[cfg(not(target_os = "windows"))]
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct KUserSharedData {
    tick_count_low_deprecated: u32,
    tick_count_multiplier: u32,
    interrupt_time: KSystemTime,
    system_time: KSystemTime,
    time_zone_bias: KSystemTime,
    image_number_low: u16,
    image_number_high: u16,
    pub nt_system_root: [u16; 260],
    max_stack_trace_depth: u32,
    crypto_exponent: u32,
    time_zone_id: u32,
    large_page_minimum: u32,
    ait_sampling_value: u32,
    app_compat_flag: u32,
    rng_seed_version: u64,
    global_validation_run_level: u32,
    time_zone_bias_stamp: u32,
    pub nt_build_number: u32,
    pub nt_product_type: u32,
    pub product_type_is_valid: u8,
    reserved_0: u8,
    native_processor_architecture: u16,
    pub nt_major_version: u32,
    pub nt_minor_version: u32,
    processor_features: [u8; 64],
    reserved_1: u32,
    reserved_3: u32,
    time_slip: u32,
    alternative_architecture: u32,
    boot_id: u32,
    system_expiration_date: i64,
    suite_mask: u32,
    kd_debugger_enabled: u8,
    nx_support_policy: u8,
    cycles_per_yield: u16,
    active_console_id: u32,
    dismount_count: u32,
    com_plus_package: u32,
    last_system_rit_event_tick_count: u32,
    number_of_physical_pages: u32,
    safe_boot_mode: u8,
    virtualization_flags: u8,
    padding_2ee: [u8; 2],
    shared_data_flags: u32,
    data_flags_pad: [u32; 1],
    test_ret_instruction: u64,
    qpc_frequency: i64,
    system_call: u32,
    user_cet_available_environments: u32,
    system_call_pad: [u64; 2],
    tick_count: [u8; 0x10],
    cookie: u32,
    cookie_pad: [u32; 1],
    console_session_foreground_process_id: i64,
    time_update_lock: u64,
    baseline_system_time_qpc: u64,
    baseline_interrupt_time_qpc: u64,
    qpc_system_time_increment: u64,
    qpc_interrupt_time_increment: u64,
    qpc_system_time_increment_shift: u8,
    qpc_interrupt_time_increment_shift: u8,
    unparked_processor_count: u16,
    enclave_feature_mask: [u32; 4],
    telemetry_coverage_round: u32,
    user_mode_global_logger: [u16; 16],
    image_file_execution_options: u32,
    lang_generation_count: u32,
    active_processor_affinity: u32,
    padding_3ac: u32,
    interrupt_time_bias: u64,
    qpc_bias: u64,
    active_processor_count: u32,
    active_group_count: u8,
    padding_3c5: u8,
    qpc_data: u16,
    time_zone_bias_effective_start: i64,
    time_zone_bias_effective_end: i64,
    x_state: [u8; WINDOWS_KUSER_SHARED_DATA_XSTATE_CONFIGURATION_SIZE],
    feature_configuration_change_stamp: KSystemTime,
    spare: u32,
    user_pointer_auth_mask: u64,
}
