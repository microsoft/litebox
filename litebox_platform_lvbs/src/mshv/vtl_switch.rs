// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VTL switch related functions

use crate::host::{
    hv_hypercall_page_address,
    per_cpu_variables::{
        PerCpuVariables, PerCpuVariablesAsm, with_per_cpu_variables, with_per_cpu_variables_asm,
    },
};
use crate::mshv::{
    HV_FLUSH_EX_VP_SET_BANKS, HV_REGISTER_VSM_CODEPAGE_OFFSETS, HvRegisterVsmCodePageOffsets,
    NUM_VTLCALL_PARAMS, VTL_ENTRY_REASON_INTERRUPT, VTL_ENTRY_REASON_LOWER_VTL_CALL,
    VTL_ENTRY_REASON_RESERVED, error::VsmError, hvcall_vp::hvcall_get_vp_registers,
    vsm_intercept::vsm_handle_intercept,
};
use core::sync::atomic::{AtomicU64, Ordering};
use litebox::utils::{ReinterpretUnsignedExt, TruncateExt};
use num_enum::TryFromPrimitive;

/// Bitmask of VPs currently executing VTL1 code.
///
/// Bit *N* is set when VP index *N* is inside VTL1 (between VTL entry and
/// VTL return). The TLB flush hypercalls read this mask so they only target
/// VPs that are in VTL1. VPs running in VTL0 use a separate address space
/// and will receive a full TLB flush on their next VTL1 entry (i.e., CR3 reload).
///
/// Each VP only ever sets/clears its own bit, so plain `fetch_or` / `fetch_and`
/// with `Relaxed` ordering is sufficient. No cross-VP data dependency exists.
///
/// Aligned to a 64-byte cache line to prevent false sharing with adjacent data.
///
/// Supports up to `MAX_CORES` VPs. [`vtl1_vp_enter`] asserts that the VP index fits.
#[repr(C, align(64))]
struct AtomicVpMask {
    banks: [AtomicU64; HV_FLUSH_EX_VP_SET_BANKS],
}

impl AtomicVpMask {
    const fn new() -> Self {
        #[allow(clippy::declare_interior_mutable_const)]
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            banks: [ZERO; HV_FLUSH_EX_VP_SET_BANKS],
        }
    }

    /// Set bit `index` (VP enters VTL1).
    #[inline]
    fn set(&self, index: usize) {
        let bank = index / 64;
        let bit = index % 64;
        self.banks[bank].fetch_or(1u64 << bit, Ordering::Relaxed);
    }

    /// Clear bit `index` (VP exits VTL1).
    #[inline]
    fn clear(&self, index: usize) {
        let bank = index / 64;
        let bit = index % 64;
        self.banks[bank].fetch_and(!(1u64 << bit), Ordering::Relaxed);
    }

    /// Snapshot the mask for use in TLB flush hypercalls.
    #[cfg(not(test))]
    #[inline]
    fn snapshot(&self) -> [u64; HV_FLUSH_EX_VP_SET_BANKS] {
        let mut out = [0u64; HV_FLUSH_EX_VP_SET_BANKS];
        for (dst, src) in out.iter_mut().zip(self.banks.iter()) {
            *dst = src.load(Ordering::Relaxed);
        }
        out
    }

    /// Check whether `vp_index` is the only bit set in the mask.
    #[cfg(not(test))]
    #[inline]
    fn is_single_vp(&self, vp_index: u32) -> bool {
        let bank = vp_index as usize / 64;
        let expected = 1u64 << (vp_index as usize % 64);
        for (i, b) in self.banks.iter().enumerate() {
            let val = b.load(Ordering::Relaxed);
            if i == bank {
                if val != expected {
                    return false;
                }
            } else if val != 0 {
                return false;
            }
        }
        true
    }
}

static VTL1_VP_MASK: AtomicVpMask = AtomicVpMask::new();

/// Mark the current VP as executing in VTL1.
#[inline]
fn vtl1_vp_enter() {
    VTL1_VP_MASK.set(with_per_cpu_variables(PerCpuVariables::vp_index) as usize);
}

/// Remove the current VP from the VTL1 mask (it is returning to VTL0).
#[inline]
fn vtl1_vp_exit() {
    VTL1_VP_MASK.clear(with_per_cpu_variables(PerCpuVariables::vp_index) as usize);
}

/// Return the current VTL1 VP mask for use in TLB flush hypercalls.
///
/// The returned value is a snapshot. VPs may enter or leave VTL1
/// between the load and the hypercall, but that is benign:
/// - A VP that left VTL1 after the snapshot merely receives a redundant flush.
/// - A VP that entered VTL1 after the snapshot performs a full TLB flush
///   because CR3 is reloaded at the entry and PCID is not enabled in VTL1.
#[cfg(not(test))]
#[inline]
pub(crate) fn vtl1_vp_mask() -> [u64; HV_FLUSH_EX_VP_SET_BANKS] {
    VTL1_VP_MASK.snapshot()
}

/// Return `true` if the current VP is the only VP executing in VTL1.
///
/// Used to decide whether a local TLB flush is sufficient (no other VP
/// is in VTL1 to flush).
#[cfg(not(test))]
#[inline]
pub(crate) fn is_only_vp_in_vtl1() -> bool {
    VTL1_VP_MASK.is_single_vp(with_per_cpu_variables(PerCpuVariables::vp_index))
}

// ============================================================================
// VTL0 XSAVE/XRSTOR macros (simplified, always use plain XSAVE/XRSTOR)
// ============================================================================
// VTL0's kernel may do XRSTOR to different buffers during its execution (e.g., process
// context switches), so we cannot rely on XSAVEOPT's tracking. Always use plain XSAVE.

/// Assembly macro to save VTL0 extended states using plain XSAVE.
/// Clobbers: rax, rcx, rdx
macro_rules! XSAVE_VTL0_ASM {
    ($xsave_area_off:tt, $mask_lo_off:tt, $mask_hi_off:tt) => {
        concat!(
            "mov rcx, gs:[",
            stringify!($xsave_area_off),
            "]\n",
            "mov eax, gs:[",
            stringify!($mask_lo_off),
            "]\n",
            "mov edx, gs:[",
            stringify!($mask_hi_off),
            "]\n",
            "xsave [rcx]\n",
        )
    };
}

/// Assembly macro to restore VTL0 extended states using plain XRSTOR.
/// Clobbers: rax, rcx, rdx
macro_rules! XRSTOR_VTL0_ASM {
    ($xsave_area_off:tt, $mask_lo_off:tt, $mask_hi_off:tt) => {
        concat!(
            "mov rcx, gs:[",
            stringify!($xsave_area_off),
            "]\n",
            "mov eax, gs:[",
            stringify!($mask_lo_off),
            "]\n",
            "mov edx, gs:[",
            stringify!($mask_hi_off),
            "]\n",
            "xrstor [rcx]\n",
        )
    };
}

/// Assembly macro to return to VTL0 using the Hyper-V hypercall stub.
/// Although Hyper-V lets each core use the same VTL return address, this implementation
/// uses per-CPU return address to avoid using a mutable global variable.
/// `ret_off` is the offset of the PerCpuVariablesAsm which holds the VTL return address.
macro_rules! VTL_RETURN_ASM {
    ($ret_off:tt) => {
        concat!(
            "xor ecx, ecx\n",
            "mov rax, gs:[",
            stringify!($ret_off),
            "]\n",
            "call rax\n",
        )
    };
}

// The following registers are shared between different VTLs.
// If VTL entry is due to VTL call, we don't need to worry about VTL0 registers because
// the caller saves them. However, if VTL entry is due to interrupt or intercept,
// we should save/restore VTL0 registers. For now, we conservatively save/restore all
// VTL0/VTL1 registers (results in performance degradation) but we can optimize it later.
/// Struct to save VTL state (general-purpose registers)
#[derive(Default, Clone, Copy)]
#[repr(C)]
pub struct VtlState {
    pub rbp: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
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
    // CR2
    // DR[0-6]
    // We use a separeate buffer to save/register extended states
    // X87, XMM, AVX, XCR
}

impl VtlState {
    pub fn new() -> Self {
        VtlState {
            ..VtlState::default()
        }
    }

    pub fn get_rax_rcx(&self) -> (u64, u64) {
        (self.rax, self.rcx)
    }

    pub fn get_vtlcall_params(&self) -> [u64; NUM_VTLCALL_PARAMS] {
        [self.rdi, self.rsi, self.rdx, self.r8]
    }
}

/// Initialize VTL switch for the current CPU.
///
/// This function sets the platform reference for the current CPU.
/// It should be called once before entering the VTL switch loop.
pub fn vtl_switch_init(platform: Option<&'static crate::Platform>) {
    if let Some(platform) = platform {
        crate::set_platform_low(platform);
    }

    // The VP is already in VTL1 when the runner calls this; register it
    // in the mask so TLB flushes during the first VTL call dispatch
    // target this VP.
    vtl1_vp_enter();
}

/// Assembly macro to save VTL state to the VtlState memory area.
///
/// This macro saves the current `rsp` to scratch, sets `rsp` to point to the top of
/// the VtlState area, pushes all general-purpose registers, then restores `rsp` from scratch.
///
/// Clobbers: none (rsp is saved and restored)
macro_rules! SAVE_VTL_STATE_ASM {
    ($scratch_off:tt, $vtl_state_top_addr_off:tt) => {
        concat!(
            "mov gs:[",
            stringify!($scratch_off),
            "], rsp\n",
            "mov rsp, gs:[",
            stringify!($vtl_state_top_addr_off),
            "]\n",
            "push r15\n",
            "push r14\n",
            "push r13\n",
            "push r12\n",
            "push r11\n",
            "push r10\n",
            "push r9\n",
            "push r8\n",
            "push rdi\n",
            "push rsi\n",
            "push rdx\n",
            "push rcx\n",
            "push rbx\n",
            "push rax\n",
            "push rbp\n",
            "mov rsp, gs:[",
            stringify!($scratch_off),
            "]\n",
        )
    };
}

/// Assembly macro to restore VTL state from the VtlState memory area.
///
/// This macro saves the current `rsp` to scratch, sets `rsp` to point to the start of
/// the VtlState area (top - size), pops all general-purpose registers, then restores
/// `rsp` from scratch.
///
/// Clobbers: none (rsp is saved and restored)
macro_rules! LOAD_VTL_STATE_ASM {
    ($scratch_off:tt, $vtl_state_top_addr_off:tt, $vtl_state_size:tt) => {
        concat!(
            "mov gs:[",
            stringify!($scratch_off),
            "], rsp\n",
            "mov rsp, gs:[",
            stringify!($vtl_state_top_addr_off),
            "]\n",
            "sub rsp, ",
            stringify!($vtl_state_size),
            "\n",
            "pop rbp\n",
            "pop rax\n",
            "pop rbx\n",
            "pop rcx\n",
            "pop rdx\n",
            "pop rsi\n",
            "pop rdi\n",
            "pop r8\n",
            "pop r9\n",
            "pop r10\n",
            "pop r11\n",
            "pop r12\n",
            "pop r13\n",
            "pop r14\n",
            "pop r15\n",
            "mov rsp, gs:[",
            stringify!($scratch_off),
            "]\n",
        )
    };
}

/// Handle a VTL entry event.
///
/// This function processes one VTL entry (VtlCall or Intercept) and returns.
///
/// For a VtlCall entry, returns `Some(params)` containing the VTL call parameters.
/// The caller should dispatch the call and then call `set_vtl_return_value` with the result.
///
/// For an intercept entry, handles it by calling `vsm_handle_intercept` and returns `None`.
///
/// # Safety
///
/// This function must only be called after `vtl_switch_asm` has saved VTL0 state.
/// The caller must ensure that VTL0 general-purpose registers have been saved to
/// per-CPU variables
fn handle_vtl_entry() -> Option<[u64; NUM_VTLCALL_PARAMS]> {
    let reason = get_vtl_entry_reason()?;
    match reason {
        VtlEntryReason::VtlCall => Some(get_vtlcall_params()),
        VtlEntryReason::Interrupt => {
            // TODO: Consider whether to handle VTL interrupts/intercepts here or
            // in the runner. Unlike other HVCI/HEKI and OP-TEE functions, this
            // function relies on many host/platform-specific features to control
            // VTL0's architecture state like injecting GP or advancing RIP.
            vsm_handle_intercept();
            None
        }
        VtlEntryReason::Reserved => None,
    }
}

/// Get the VTL entry reason from the per-CPU VP assist page.
///
/// Returns `None` if the entry reason is not a valid `VtlEntryReason`.
#[inline]
fn get_vtl_entry_reason() -> Option<VtlEntryReason> {
    let reason = with_per_cpu_variables(|per_cpu_variables| unsafe {
        (*per_cpu_variables.hv_vp_assist_page_as_ptr()).vtl_entry_reason
    });
    VtlEntryReason::try_from(reason).ok()
}

/// Get the VTL call parameters from the saved VTL0 state.
#[inline]
fn get_vtlcall_params() -> [u64; NUM_VTLCALL_PARAMS] {
    with_per_cpu_variables(|per_cpu_variables| {
        per_cpu_variables.vtl0_state.get().get_vtlcall_params()
    })
}

/// Set the VTL return value that will be returned to VTL0.
#[inline]
fn set_vtl_return_value(value: i64) {
    with_per_cpu_variables(|per_cpu_variables| {
        per_cpu_variables.set_vtl_return_value(value.reinterpret_as_unsigned());
    });
}

/// VTL Entry Reason
#[derive(Debug, TryFromPrimitive, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum VtlEntryReason {
    Reserved = VTL_ENTRY_REASON_RESERVED,
    VtlCall = VTL_ENTRY_REASON_LOWER_VTL_CALL,
    Interrupt = VTL_ENTRY_REASON_INTERRUPT,
}

pub(crate) fn mshv_vsm_get_code_page_offsets() -> Result<(), VsmError> {
    let value = hvcall_get_vp_registers(HV_REGISTER_VSM_CODEPAGE_OFFSETS)
        .map_err(VsmError::HypercallFailed)?;
    let code_page_offsets = HvRegisterVsmCodePageOffsets::from_u64(value);
    let hvcall_page: usize = hv_hypercall_page_address().truncate();
    let vtl_return_address = hvcall_page
        .checked_add(usize::from(code_page_offsets.vtl_return_offset()))
        .ok_or(VsmError::CodePageOffsetOverflow)?;
    with_per_cpu_variables_asm(|pcv_asm| {
        pcv_asm.set_vtl_return_addr(vtl_return_address);
    });
    Ok(())
}

/// This function performs a VTL switch.
///
/// It sets a VTL return value (0 if `None` is provided) before the VTL switch.
/// It handles VTL entries for intercepts/interrupts internally and loops until
/// a VtlCall entry.
///
/// TODO: We must save/restore VTL1's state when there is RPC from VTL1 to VTL0 (e.g., dynamically
/// loading OP-TEE TAs). This should use global data structures since the core which makes the RPC
/// can be different from the core where the VTL1 is running.
///
/// TODO: Even if we don't have RPC from VTL1 to VTL0, we may still need to save VTL1's state for
/// debugging purposes.
pub fn vtl_switch(return_value: Option<i64>) -> [u64; NUM_VTLCALL_PARAMS] {
    let value = return_value.unwrap_or(0);
    set_vtl_return_value(value);

    loop {
        vtl1_vp_exit();
        // Note. The below asm block only touches stable memory locations (no on-demand memory
        // allocation, no permission changes). So, it is safe to exclude the current VP from
        // the VTL1 mask before the asm block.

        // Inline asm performs the VTL switch:
        // 1. Restore VTL0 state (XRSTOR + load GP registers)
        // 2. Return to VTL0 (cli + hypercall)
        // 3. Save VTL0 state when VTL1 resumes (save GP registers + XSAVE)
        //
        // All GP registers are clobbered by loading VTL0's state.
        // - rbx and rbp cannot be in clobber list (LLVM restriction), so we manually save/restore
        // - r12-r15: use out() clobbers so compiler saves only if needed
        // - caller-saved registers: clobber_abi("C")
        unsafe {
            #[cfg(target_arch = "x86_64")]
            #[rustfmt::skip]
            core::arch::asm!(
                "push rbx",
                "push rbp",
                XRSTOR_VTL0_ASM!({vtl0_xsave_area_off}, {vtl0_xsave_mask_lo_off}, {vtl0_xsave_mask_hi_off}),
                LOAD_VTL_STATE_ASM!({scratch_off}, {vtl0_state_top_addr_off}, {VTL_STATE_SIZE}),
                // *** VTL0 state is restored. Return to VTL0 immediately ***
                "cli", // disable VTL1 interrupts before returning to VTL0
                VTL_RETURN_ASM!({vtl_ret_addr_off}),
                // *** VTL1 resumes here regardless of the entry reason (VTL switch or intercept) ***
                // Hyper-V restored VTL1's rip and rsp, so we're back on the original stack.
                SAVE_VTL_STATE_ASM!({scratch_off}, {vtl0_state_top_addr_off}),
                XSAVE_VTL0_ASM!({vtl0_xsave_area_off}, {vtl0_xsave_mask_lo_off}, {vtl0_xsave_mask_hi_off}),
                "sti", // enable VTL1 interrupts after saving VTL0 state
                // A pending SINT can be fired here. Our SINT handler only executes `iretq` so returns to here immediately.
                "pop rbp",
                "pop rbx",
                vtl_ret_addr_off = const { PerCpuVariablesAsm::vtl_return_addr_offset() },
                scratch_off = const { PerCpuVariablesAsm::scratch_offset() },
                vtl0_state_top_addr_off = const { PerCpuVariablesAsm::vtl0_state_top_addr_offset() },
                vtl0_xsave_area_off = const { PerCpuVariablesAsm::vtl0_xsave_area_addr_offset() },
                vtl0_xsave_mask_lo_off = const { PerCpuVariablesAsm::vtl0_xsave_mask_lo_offset() },
                vtl0_xsave_mask_hi_off = const { PerCpuVariablesAsm::vtl0_xsave_mask_hi_offset() },
                VTL_STATE_SIZE = const core::mem::size_of::<VtlState>(),
                clobber_abi("C"),
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
            );
        }

        vtl1_vp_enter();

        if let Some(params) = handle_vtl_entry() {
            // Reset VTL1 xsaved flags. The CPU's XSAVEOPT tracking is global - it only tracks
            // one buffer at a time. At this point, the CPU's tracking might rely on VTL0's
            // buffer (if VTL0 called XRSTOR). Thus, we shouldn't use XSAVEOPT until XRSTOR
            // re-establishes tracking for VTL1's buffer.
            with_per_cpu_variables_asm(PerCpuVariablesAsm::reset_vtl1_xsaved);

            return params;
        }
    }
}
