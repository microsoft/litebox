//! Windows x64 TEB layout shared by the shim and host platform.

use core::mem::{offset_of, size_of};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Counted UTF-16 string descriptor containing a guest virtual address.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct UnicodeString {
    /// Length in bytes, excluding a terminator.
    pub length: u16,
    /// Buffer capacity in bytes.
    pub maximum_length: u16,
    /// Explicit x64 alignment padding.
    pub padding_0: [u8; 4],
    /// Guest virtual address of the UTF-16 buffer.
    pub buffer: usize,
}

impl UnicodeString {
    /// Returns the character count after validating the descriptor lengths.
    pub fn character_count(self) -> Result<usize, crate::nt_status::NtStatus> {
        if !self.length.is_multiple_of(2) || self.maximum_length < self.length {
            return Err(crate::nt_status::NtStatus::INVALID_PARAMETER);
        }
        Ok(usize::from(self.length / 2))
    }
}

/// Native thread information block at the beginning of a TEB.
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

/// Per-thread activation-context stack and cached frame list.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct ActivationContextStack {
    pub active_frame: usize,
    pub frame_list_cache: ListEntry,
    pub flags: u32,
    pub next_cookie_sequence_number: u32,
    pub stack_id: u32,
    pub padding: u32,
}

/// Opaque GDI batching storage within the x64 TEB.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct GdiTebBatch {
    _reserved: [u8; 0x4e8],
}

/// Process and thread identifiers in the Windows ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, Immutable)]
pub struct ClientId {
    pub unique_process: usize,
    pub unique_thread: usize,
}

/// Doubly linked list entry containing guest virtual addresses.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, Immutable)]
pub struct ListEntry {
    pub flink: usize,
    pub blink: usize,
}

/// Opaque 128-bit identifier stored in a TEB.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable)]
pub struct Guid {
    pub data: [u8; 16],
}

/// Processor-group affinity in the Windows x64 ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct GroupAffinity {
    pub mask: usize,
    pub group: u16,
    pub reserved: [u16; 3],
}

/// Modeled Windows x64 thread environment block.
///
/// Address fields are guest virtual addresses, not Rust pointers. This layout
/// describes the guest ABI, not a dynamically discovered host Windows layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct ThreadEnvironmentBlock {
    pub nt_tib: NtTib,
    pub environment_pointer: usize,
    pub client_id: ClientId,
    pub active_rpc_handle: usize,
    pub thread_local_storage_pointer: usize,
    /// Guest virtual address of the process environment block.
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

const _: () = {
    assert!(size_of::<ActivationContextStack>() == 0x28);
    assert!(size_of::<ThreadEnvironmentBlock>() == 0x1878);
    assert!(offset_of!(ThreadEnvironmentBlock, nt_tib.self_pointer) == 0x30);
    assert!(offset_of!(ThreadEnvironmentBlock, thread_local_storage_pointer) == 0x58);
    assert!(offset_of!(ThreadEnvironmentBlock, activation_stack) == 0x290);
    assert!(offset_of!(ActivationContextStack, active_frame) == 0);
    assert!(offset_of!(ActivationContextStack, frame_list_cache) == 8);
    assert!(offset_of!(ListEntry, blink) == 8);
    assert!(
        offset_of!(
            ThreadEnvironmentBlock,
            activation_stack.frame_list_cache.flink
        ) == 0x298
    );
    assert!(
        offset_of!(
            ThreadEnvironmentBlock,
            activation_stack.frame_list_cache.blink
        ) == 0x2a0
    );
    assert!(offset_of!(ThreadEnvironmentBlock, activation_context_stack_pointer) == 0x2c8);
    assert!(offset_of!(ThreadEnvironmentBlock, static_unicode_string.buffer) == 0x1260);
};
