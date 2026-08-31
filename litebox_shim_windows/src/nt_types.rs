// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use core::mem::offset_of;
use litebox::platform::{RawConstPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{ConstPtr, syscalls::Handle};

bitflags::bitflags! {
    /// Flags carried in `CONTEXT.ContextFlags`, selecting which register groups
    /// a `CONTEXT` structure describes.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct ContextFlags: u32 {
        const CONTROL = 0x0010_0001;
        const INTEGER = 0x0010_0002;
        const FLOATING_POINT = 0x0010_0008;
        const DEBUG_REGISTERS = 0x0010_0010;
        const XSTATE = 0x0010_0040;

        const _ = !0;
    }
}

const INITIAL_CONTEXT_MXCSR: u32 = 0x1f80;
const USER_MODE_CODE_SELECTOR: u16 = 0x33;
const USER_MODE_STACK_SELECTOR: u16 = 0x2b;
const INITIAL_CONTEXT_EFLAGS: u32 = 0x200;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
pub(crate) struct Luid {
    pub(crate) low_part: u32,
    pub(crate) high_part: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub(crate) struct X64Context {
    pub(crate) p1_home: u64,
    pub(crate) p2_home: u64,
    pub(crate) p3_home: u64,
    pub(crate) p4_home: u64,
    pub(crate) p5_home: u64,
    pub(crate) p6_home: u64,
    pub(crate) context_flags: u32,
    pub(crate) mx_csr: u32,
    pub(crate) seg_cs: u16,
    pub(crate) seg_ds: u16,
    pub(crate) seg_es: u16,
    pub(crate) seg_fs: u16,
    pub(crate) seg_gs: u16,
    pub(crate) seg_ss: u16,
    pub(crate) e_flags: u32,
    pub(crate) dr0: u64,
    pub(crate) dr1: u64,
    pub(crate) dr2: u64,
    pub(crate) dr3: u64,
    pub(crate) dr6: u64,
    pub(crate) dr7: u64,
    pub(crate) rax: u64,
    pub(crate) rcx: u64,
    pub(crate) rdx: u64,
    pub(crate) rbx: u64,
    pub(crate) rsp: u64,
    pub(crate) rbp: u64,
    pub(crate) rsi: u64,
    pub(crate) rdi: u64,
    pub(crate) r8: u64,
    pub(crate) r9: u64,
    pub(crate) r10: u64,
    pub(crate) r11: u64,
    pub(crate) r12: u64,
    pub(crate) r13: u64,
    pub(crate) r14: u64,
    pub(crate) r15: u64,
    pub(crate) rip: u64,
    pub(crate) extended_state: [u8; 0x3d0],
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
        thread_start_argument: usize,
    ) -> X64Context {
        X64Context {
            context_flags: ContextFlags::CONTROL
                .union(ContextFlags::INTEGER)
                .union(ContextFlags::FLOATING_POINT)
                .union(ContextFlags::DEBUG_REGISTERS)
                .bits(),
            mx_csr: INITIAL_CONTEXT_MXCSR,
            seg_cs: USER_MODE_CODE_SELECTOR,
            seg_ss: USER_MODE_STACK_SELECTOR,
            e_flags: INITIAL_CONTEXT_EFLAGS,
            rcx: application_entry_point as u64,
            rdx: thread_start_argument as u64,
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
        const MAXIMUM_ALLOWED = 0x0200_0000;
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

    pub(crate) const fn success(information: usize) -> Self {
        Self::new(NtStatus::SUCCESS, information)
    }

    pub(crate) const fn failure(status: NtStatus) -> Self {
        Self::new(status, 0)
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
    pub(crate) fn character_count(self) -> Result<usize, NtStatus> {
        if !self.length.is_multiple_of(2) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if self.maximum_length < self.length {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(usize::from(self.length / 2))
    }

    pub(crate) fn read_string<Platform: RawPointerProvider>(self) -> Result<String, NtStatus> {
        let character_count = self.character_count()?;
        if character_count == 0 {
            return Ok(String::new());
        }
        if self.buffer == 0 {
            return Err(NtStatus::ACCESS_VIOLATION);
        }

        let buffer =
            <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<u16>::from_usize(
                self.buffer,
            );
        let Some(units) = buffer.to_owned_slice(character_count) else {
            return Err(NtStatus::ACCESS_VIOLATION);
        };
        Ok(String::from_utf16_lossy(&units))
    }
}

pub(crate) fn read_unicode_string_at<Platform: RawPointerProvider>(
    address: usize,
) -> Result<String, NtStatus> {
    ConstPtr::<Platform, UnicodeString>::from_usize(address)
        .read_at_offset(0)
        .ok_or(NtStatus::ACCESS_VIOLATION)?
        .read_string::<Platform>()
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
    pub(crate) struct PebBitField: u8 {
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
pub(crate) struct ProcessEnvironmentBlock {
    pub(crate) inherited_address_space: u8,
    pub(crate) read_image_file_exec_options: u8,
    pub(crate) being_debugged: u8,
    /// [`PebBitField`]
    pub(crate) bit_field: u8,
    pub(crate) padding_0: [u8; 4],
    pub(crate) mutant: usize,
    pub(crate) image_base_address: usize,
    pub(crate) ldr: usize,
    /// Pointer to [`RtlUserProcessParameters`].
    pub(crate) process_parameters: usize,
    pub(crate) sub_system_data: usize,
    pub(crate) process_heap: usize,
    pub(crate) fast_peb_lock: usize,
    pub(crate) atl_thunk_s_list_ptr: usize,
    pub(crate) ifeo_key: usize,
    pub(crate) cross_process_flags: u32,
    pub(crate) padding_1: [u8; 4],
    pub(crate) kernel_callback_table: usize,
    pub(crate) system_reserved: u32,
    pub(crate) atl_thunk_s_list_ptr_32: u32,
    pub(crate) api_set_map: usize,
    pub(crate) tls_expansion_counter: u32,
    pub(crate) padding_2: [u8; 4],
    pub(crate) tls_bitmap: usize,
    pub(crate) tls_bitmap_bits: [u32; 2],
    pub(crate) read_only_shared_memory_base: usize,
    pub(crate) shared_data: usize,
    pub(crate) read_only_static_server_data: usize,
    pub(crate) ansi_code_page_data: usize,
    pub(crate) oem_code_page_data: usize,
    pub(crate) unicode_case_table_data: usize,
    pub(crate) number_of_processors: u32,
    pub(crate) nt_global_flag: u32,
    pub(crate) critical_section_timeout: i64,
    pub(crate) heap_segment_reserve: u64,
    pub(crate) heap_segment_commit: u64,
    pub(crate) heap_de_commit_total_free_threshold: u64,
    pub(crate) heap_de_commit_free_block_threshold: u64,
    pub(crate) number_of_heaps: u32,
    pub(crate) maximum_number_of_heaps: u32,
    pub(crate) process_heaps: usize,
    pub(crate) gdi_shared_handle_table: usize,
    pub(crate) process_starter_helper: usize,
    pub(crate) gdi_dc_attribute_list: u32,
    pub(crate) padding_3: [u8; 4],
    pub(crate) loader_lock: usize,
    pub(crate) os_major_version: u32,
    pub(crate) os_minor_version: u32,
    pub(crate) os_build_number: u16,
    pub(crate) os_csd_version: u16,
    pub(crate) os_platform_id: u32,
    pub(crate) image_subsystem: u32,
    pub(crate) image_subsystem_major_version: u32,
    pub(crate) image_subsystem_minor_version: u32,
    pub(crate) padding_4: [u8; 4],
    pub(crate) active_process_affinity_mask: u64,
    pub(crate) gdi_handle_buffer: [u32; 60],
    pub(crate) post_process_init_routine: usize,
    pub(crate) tls_expansion_bitmap: usize,
    pub(crate) tls_expansion_bitmap_bits: [u32; 32],
    pub(crate) session_id: u32,
    pub(crate) padding_5: [u8; 4],
    pub(crate) app_compat_flags: u64,
    pub(crate) app_compat_flags_user: u64,
    pub(crate) p_shim_data: usize,
    pub(crate) app_compat_info: usize,
    pub(crate) csd_version: UnicodeString,
    pub(crate) activation_context_data: usize,
    pub(crate) process_assembly_storage_map: usize,
    pub(crate) system_default_activation_context_data: usize,
    pub(crate) system_assembly_storage_map: usize,
    pub(crate) minimum_stack_commit: u64,
    pub(crate) spare_pointers: [usize; 2],
    pub(crate) patch_loader_data: usize,
    pub(crate) chpe_v2_process_info: usize,
    pub(crate) app_model_feature_state: u32,
    pub(crate) spare_ulongs: [u32; 2],
    pub(crate) active_code_page: u16,
    pub(crate) oem_code_page: u16,
    pub(crate) use_case_mapping: u16,
    pub(crate) unused_nls_field: u16,
    pub(crate) padding_6a: [u8; 4],
    pub(crate) wer_registration_data: usize,
    pub(crate) wer_ship_assert_ptr: usize,
    pub(crate) ec_code_bit_map: usize,
    pub(crate) p_image_header_hash: usize,
    pub(crate) tracing_flags: u32,
    pub(crate) padding_6: [u8; 4],
    pub(crate) csr_server_read_only_shared_memory_base: u64,
    pub(crate) tpp_workerp_list_lock: u64,
    pub(crate) tpp_workerp_list: ListEntry,
    pub(crate) wait_on_address_hash_table: [usize; 128],
    pub(crate) telemetry_coverage_header: usize,
    pub(crate) cloud_file_flags: u32,
    pub(crate) cloud_file_diag_flags: u32,
    pub(crate) placeholder_compatibility_mode: i8,
    pub(crate) placeholder_compatibility_mode_reserved: [i8; 7],
    pub(crate) leap_second_data: usize,
    pub(crate) leap_second_flags: u32,
    pub(crate) nt_global_flag_2: u32,
    pub(crate) extended_feature_disable_mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub(crate) struct NtTib {
    pub(crate) exception_list: usize,
    pub(crate) stack_base: usize,
    pub(crate) stack_limit: usize,
    pub(crate) sub_system_tib: usize,
    pub(crate) fiber_data_or_version: usize,
    pub(crate) arbitrary_user_pointer: usize,
    pub(crate) self_pointer: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub(crate) struct ActivationContextStack {
    pub(crate) active_frame: usize,
    pub(crate) frame_list_cache: ListEntry,
    pub(crate) flags: u32,
    pub(crate) next_cookie_sequence_number: u32,
    pub(crate) stack_id: u32,
    pub(crate) _padding: u32,
}

const _: () = assert!(core::mem::size_of::<ActivationContextStack>() == 0x28);

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub(crate) struct GdiTebBatch {
    _reserved: [u8; 0x4e8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, Immutable)]
pub(crate) struct ClientId {
    pub(crate) unique_process: usize,
    pub(crate) unique_thread: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, Immutable)]
pub(crate) struct ListEntry {
    pub(crate) flink: usize,
    pub(crate) blink: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable)]
pub(crate) struct Guid {
    pub(crate) data: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub(crate) struct GroupAffinity {
    pub(crate) mask: usize,
    pub(crate) group: u16,
    pub(crate) reserved: [u16; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub(crate) struct ThreadEnvironmentBlock {
    pub(crate) nt_tib: NtTib,
    pub(crate) environment_pointer: usize,
    pub(crate) client_id: ClientId,
    pub(crate) active_rpc_handle: usize,
    pub(crate) thread_local_storage_pointer: usize,
    /// Pointer to [`ProcessEnvironmentBlock`].
    pub(crate) process_environment_block: usize,
    pub(crate) last_error_value: u32,
    pub(crate) count_of_owned_critical_sections: u32,
    pub(crate) csr_client_thread: usize,
    pub(crate) win_32_thread_info: usize,
    pub(crate) user_32_reserved: [u32; 26],
    pub(crate) user_reserved: [u32; 5],
    pub(crate) padding_user_reserved: [u8; 4],
    pub(crate) wow_32_reserved: usize,
    pub(crate) current_locale: u32,
    pub(crate) fp_software_status_register: u32,
    pub(crate) reserved_for_debugger_instrumentation: [usize; 16],
    pub(crate) system_reserved_1: [usize; 25],
    pub(crate) heap_fls_data: usize,
    pub(crate) rng_state: [u64; 4],
    pub(crate) placeholder_compatibility_mode: i8,
    pub(crate) placeholder_hydration_always_explicit: u8,
    pub(crate) placeholder_reserved: [i8; 10],
    pub(crate) proxied_process_id: u32,
    pub(crate) activation_stack: ActivationContextStack,
    pub(crate) working_on_behalf_ticket: [u8; 8],
    pub(crate) exception_code: i32,
    pub(crate) padding_0: [u8; 4],
    pub(crate) activation_context_stack_pointer: usize,
    pub(crate) instrumentation_callback_sp: u64,
    pub(crate) instrumentation_callback_previous_pc: u64,
    pub(crate) instrumentation_callback_previous_sp: u64,
    pub(crate) tx_fs_context: u32,
    pub(crate) instrumentation_callback_disabled: u8,
    pub(crate) unaligned_load_store_exceptions: u8,
    pub(crate) padding_1: [u8; 2],
    pub(crate) gdi_teb_batch: GdiTebBatch,
    pub(crate) real_client_id: ClientId,
    pub(crate) gdi_cached_process_handle: usize,
    pub(crate) gdi_client_pid: u32,
    pub(crate) gdi_client_tid: u32,
    pub(crate) gdi_thread_local_info: usize,
    pub(crate) win_32_client_info: [u64; 62],
    pub(crate) gl_dispatch_table: [usize; 233],
    pub(crate) gl_reserved_1: [u64; 29],
    pub(crate) gl_reserved_2: usize,
    pub(crate) gl_section_info: usize,
    pub(crate) gl_section: usize,
    pub(crate) gl_table: usize,
    pub(crate) gl_current_rc: usize,
    pub(crate) gl_context: usize,
    pub(crate) last_status_value: u32,
    pub(crate) padding_2: [u8; 4],
    pub(crate) static_unicode_string: UnicodeString,
    pub(crate) static_unicode_buffer: [u16; 261],
    pub(crate) padding_3: [u8; 6],
    pub(crate) deallocation_stack: usize,
    pub(crate) tls_slots: [usize; 64],
    pub(crate) tls_links: ListEntry,
    pub(crate) vdm: usize,
    pub(crate) reserved_for_nt_rpc: usize,
    pub(crate) dbg_ss_reserved: [usize; 2],
    pub(crate) hard_error_mode: u32,
    pub(crate) padding_4: [u8; 4],
    pub(crate) instrumentation: [usize; 11],
    pub(crate) activity_id: Guid,
    pub(crate) sub_process_tag: usize,
    pub(crate) perflib_data: usize,
    pub(crate) etw_trace_data: usize,
    pub(crate) win_sock_data: usize,
    pub(crate) gdi_batch_count: u32,
    pub(crate) ideal_processor_value: u32,
    pub(crate) guaranteed_stack_bytes: u32,
    pub(crate) padding_5: [u8; 4],
    pub(crate) reserved_for_perf: usize,
    pub(crate) reserved_for_ole: usize,
    pub(crate) waiting_on_loader_lock: u32,
    pub(crate) padding_6: [u8; 4],
    pub(crate) saved_priority_state: usize,
    pub(crate) reserved_for_code_coverage: u64,
    pub(crate) thread_pool_data: usize,
    pub(crate) tls_expansion_slots: usize,
    pub(crate) chpe_v_2_cpu_area_info: usize,
    pub(crate) unused: usize,
    pub(crate) mui_generation: u32,
    pub(crate) is_impersonating: u32,
    pub(crate) nls_cache: usize,
    pub(crate) p_shim_data: usize,
    pub(crate) heap_data: u32,
    pub(crate) padding_7: [u8; 4],
    pub(crate) current_transaction_handle: usize,
    pub(crate) active_frame: usize,
    pub(crate) fls_data: usize,
    pub(crate) preferred_languages: usize,
    pub(crate) user_pref_languages: usize,
    pub(crate) merged_pref_languages: usize,
    pub(crate) mui_impersonation: u32,
    pub(crate) cross_teb_flags: u16,
    pub(crate) same_teb_flags: u16,
    pub(crate) txn_scope_enter_callback: usize,
    pub(crate) txn_scope_exit_callback: usize,
    pub(crate) txn_scope_context: usize,
    pub(crate) lock_count: u32,
    pub(crate) wow_teb_offset: i32,
    pub(crate) resource_ret_value: usize,
    pub(crate) reserved_for_wdf: usize,
    pub(crate) reserved_for_crt: u64,
    pub(crate) effective_container_id: Guid,
    pub(crate) last_sleep_counter: u64,
    pub(crate) spin_call_count: u32,
    pub(crate) padding_8: [u8; 4],
    pub(crate) extended_feature_disable_mask: u64,
    pub(crate) scheduler_shared_data_slot: usize,
    pub(crate) heap_walk_context: usize,
    pub(crate) primary_group_affinity: GroupAffinity,
    pub(crate) rcu: [u32; 2],
}

bitflags::bitflags! {
    /// Flags stored in `RTL_USER_PROCESS_PARAMETERS.Flags`.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) struct RtlUserProcFlags: u32 {
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
pub(crate) struct CurDir {
    pub(crate) dos_path: UnicodeString,
    pub(crate) handle: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub(crate) struct RtlDriveLetterCurdir {
    /// Per-drive current-directory flags.
    pub(crate) flags: u16,
    /// Length of the drive current-directory entry.
    pub(crate) length: u16,
    /// Timestamp associated with this drive current-directory entry.
    pub(crate) time_stamp: u32,
    /// DOS path for this drive's current directory.
    pub(crate) dos_path: UnicodeString,
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
pub(crate) struct RtlUserProcessParameters {
    /// Total allocated size of this process-parameter buffer, in bytes.
    pub(crate) maximum_length: u32,
    /// Size of the process-parameter block, including any inline variable-length strings.
    pub(crate) length: u32,
    /// Process-parameter flags (see [`RtlUserProcFlags`]).
    pub(crate) flags: u32,
    /// Debug flags associated with these process parameters.
    pub(crate) debug_flags: u32,
    /// Console session handle, inherited or derived from process creation options.
    pub(crate) console_handle: usize,
    /// Console behavior flags, such as ignoring Ctrl+C requests.
    pub(crate) console_flags: u32,
    /// Reserved alignment padding.
    pub(crate) padding_0: [u8; 4],
    /// Standard input handle from `STARTUPINFO.hStdInput`.
    pub(crate) standard_input: usize,
    /// Standard output handle from `STARTUPINFO.hStdOutput`.
    pub(crate) standard_output: usize,
    /// Standard error handle from `STARTUPINFO.hStdError`.
    pub(crate) standard_error: usize,
    /// Current directory path and handle.
    pub(crate) current_directory: CurDir,
    /// Semicolon-separated DOS-style DLL search paths.
    pub(crate) dll_path: UnicodeString,
    /// Full DOS-style path to the executable image.
    pub(crate) image_path_name: UnicodeString,
    /// Command line string passed to the process.
    pub(crate) command_line: UnicodeString,
    /// Pointer to the separately allocated environment block.
    pub(crate) environment: usize,
    /// Initial window X position when `window_flags` requests a position.
    pub(crate) starting_x: u32,
    /// Initial window Y position when `window_flags` requests a position.
    pub(crate) starting_y: u32,
    /// Initial window width when `window_flags` requests a size.
    pub(crate) count_x: u32,
    /// Initial window height when `window_flags` requests a size.
    pub(crate) count_y: u32,
    /// Initial console screen-buffer width in character cells.
    pub(crate) count_chars_x: u32,
    /// Initial console screen-buffer height in character cells.
    pub(crate) count_chars_y: u32,
    /// Initial console text/background color attributes.
    pub(crate) fill_attribute: u32,
    /// `STARTUPINFO` flags describing which startup fields are valid.
    pub(crate) window_flags: u32,
    /// `ShowWindow` value used when `window_flags` includes `STARTF_USESHOWWINDOW`.
    pub(crate) show_window_flags: u32,
    /// Reserved alignment padding.
    pub(crate) padding_1: [u8; 4],
    /// Console window title, shortcut path, or AppUserModelID depending on `window_flags`.
    pub(crate) window_title: UnicodeString,
    /// Window station and desktop name, such as `WinSta0\Default`.
    pub(crate) desktop_info: UnicodeString,
    /// Startup shell data corresponding to `STARTUPINFO.lpReserved`.
    pub(crate) shell_info: UnicodeString,
    /// Runtime data corresponding to `STARTUPINFO.lpReserved2` and `cbReserved2`.
    pub(crate) runtime_data: UnicodeString,
    /// Per-drive current-directory entries for the 32 DOS drive letters.
    pub(crate) current_directories: [RtlDriveLetterCurdir; 32],
    /// Allocated size of the environment block, in bytes.
    pub(crate) environment_size: u64,
    /// Environment version incremented when environment strings change.
    pub(crate) environment_version: u64,
    /// Package dependency metadata pointer.
    pub(crate) package_dependency_data: usize,
    /// Console process group identifier used to scope control-signal delivery.
    pub(crate) process_group_id: u32,
    /// Requested worker-thread count for parallel DLL loading.
    pub(crate) loader_threads: u32,
    /// DLL path used for packaged-app import redirection.
    pub(crate) redirection_dll_name: UnicodeString,
    /// Heap partition name.
    pub(crate) heap_partition_name: UnicodeString,
    /// Pointer to default thread-pool CPU-set masks.
    pub(crate) default_threadpool_cpu_set_masks: usize,
    /// Number of default thread-pool CPU-set masks.
    pub(crate) default_threadpool_cpu_set_mask_count: u32,
    /// Maximum default thread-pool thread count.
    pub(crate) default_threadpool_thread_maximum: u32,
    /// Heap memory type mask.
    pub(crate) heap_memory_type_mask: u32,
    /// Reserved tail padding.
    pub(crate) padding_2: [u8; 4],
}

const _: [(); 0x1878] = [(); core::mem::size_of::<ThreadEnvironmentBlock>()];
const _: [(); 0x7d0] = [(); core::mem::size_of::<ProcessEnvironmentBlock>()];
const _: [(); 0x4d0] = [(); core::mem::size_of::<X64Context>()];
const _: [(); 0x448] = [(); core::mem::size_of::<RtlUserProcessParameters>()];

#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub(crate) struct KSystemTime {
    pub(crate) low_part: u32,
    pub(crate) high_1_time: i32,
    pub(crate) high_2_time: i32,
}

#[cfg(not(target_os = "windows"))]
const WINDOWS_KUSER_SHARED_DATA_XSTATE_CONFIGURATION_SIZE: usize = 0x348;

/// Layout from Wine `include/ddk/wdm.h` and ReactOS `sdk/include/wine/ddk/wdm.h`.
#[cfg(not(target_os = "windows"))]
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub(crate) struct KUserSharedData {
    tick_count_low_deprecated: u32,
    tick_count_multiplier: u32,
    interrupt_time: KSystemTime,
    system_time: KSystemTime,
    time_zone_bias: KSystemTime,
    image_number_low: u16,
    image_number_high: u16,
    pub(crate) nt_system_root: [u16; 260],
    max_stack_trace_depth: u32,
    crypto_exponent: u32,
    time_zone_id: u32,
    large_page_minimum: u32,
    ait_sampling_value: u32,
    app_compat_flag: u32,
    rng_seed_version: u64,
    global_validation_run_level: u32,
    time_zone_bias_stamp: u32,
    pub(crate) nt_build_number: u32,
    pub(crate) nt_product_type: u32,
    pub(crate) product_type_is_valid: u8,
    reserved_0: u8,
    native_processor_architecture: u16,
    pub(crate) nt_major_version: u32,
    pub(crate) nt_minor_version: u32,
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
    pub(crate) qpc_frequency: i64,
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
