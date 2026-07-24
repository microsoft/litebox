// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VTL switch related functions

use crate::host::{
    hv_hypercall_page_address,
    per_cpu_variables::{
        PER_CPU_ALIGN, PerCpuVariables, PerCpuVariablesAsm, with_per_cpu_variables,
    },
};
use crate::mshv::{
    HV_FLUSH_EX_VP_SET_BANKS, HV_REGISTER_VSM_CODEPAGE_OFFSETS, HvRegisterVsmCodePageOffsets,
    NUM_VTLCALL_PARAMS, VTL_ENTRY_REASON_INTERRUPT, VTL_ENTRY_REASON_LOWER_VTL_CALL,
    VTL_ENTRY_REASON_RESERVED, error::VsmError, hvcall_vp::hvcall_get_vp_registers,
    vsm_intercept::vsm_handle_intercept,
};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
/// `$base` is a register holding the `PerCpuVariables` pointer; it must not
/// be rax/rcx/rdx (clobbered by this macro).
/// Clobbers: rax, rcx, rdx
macro_rules! XSAVE_VTL0_ASM {
    ($base:tt, $xsave_area_off:tt, $mask_lo_off:tt, $mask_hi_off:tt) => {
        concat!(
            "mov rcx, [",
            stringify!($base),
            " + ",
            stringify!($xsave_area_off),
            "]\n",
            "mov eax, [",
            stringify!($base),
            " + ",
            stringify!($mask_lo_off),
            "]\n",
            "mov edx, [",
            stringify!($base),
            " + ",
            stringify!($mask_hi_off),
            "]\n",
            "xsave [rcx]\n",
        )
    };
}

/// Assembly macro to restore VTL0 extended states using plain XRSTOR.
/// `$base` is a register holding the `PerCpuVariables` pointer; it must not
/// be rax/rcx/rdx (clobbered by this macro).
/// Clobbers: rax, rcx, rdx
macro_rules! XRSTOR_VTL0_ASM {
    ($base:tt, $xsave_area_off:tt, $mask_lo_off:tt, $mask_hi_off:tt) => {
        concat!(
            "mov rcx, [",
            stringify!($base),
            " + ",
            stringify!($xsave_area_off),
            "]\n",
            "mov eax, [",
            stringify!($base),
            " + ",
            stringify!($mask_lo_off),
            "]\n",
            "mov edx, [",
            stringify!($base),
            " + ",
            stringify!($mask_hi_off),
            "]\n",
            "xrstor [rcx]\n",
        )
    };
}

/// VTL return address inside the Hyper-V hypercall page (hypercall page
/// address + the hypervisor-reported VTL-return code offset). The value is
/// identical on every core; it is written by
/// [`mshv_vsm_get_code_page_offsets`] during each core's boot (BSP first,
/// before any AP exists) and read by the `vtl_switch` asm via RIP-relative
/// addressing.
static VTL_RETURN_TARGET: AtomicUsize = AtomicUsize::new(0);

/// Whether the VTL return target (and hence the hypercall page) has been
/// configured. Used by `is_hvcall_ready`.
#[cfg(not(test))]
pub(crate) fn is_vtl_return_target_set() -> bool {
    VTL_RETURN_TARGET.load(Ordering::Relaxed) != 0
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

/// Byte offset of `PerCpuVariables::vtl0_state` (a `#[repr(transparent)]`
/// `Cell<VtlState>`, so this is also the offset of the inner `VtlState`).
/// Used by the `vtl_switch` asm to address VTL0 GPR slots directly.
#[cfg(target_arch = "x86_64")]
const VTL0_STATE_OFF: usize = core::mem::offset_of!(PerCpuVariables, vtl0_state);

/// Negated `PER_CPU_ALIGN` for `and reg, imm32` per-CPU base derivation.
#[cfg(target_arch = "x86_64")]
#[allow(clippy::cast_possible_wrap)]
const PER_CPU_ALIGN_NEG: i64 = -(PER_CPU_ALIGN as i64);

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
    let reason = with_per_cpu_variables(|per_cpu_variables| {
        per_cpu_variables.with_vp_assist_page(|page| page.vtl_entry_reason)
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
    let hvcall_page: usize = hv_hypercall_page_address().trunc();
    let vtl_return_address = hvcall_page
        .checked_add(usize::from(code_page_offsets.vtl_return_offset()))
        .ok_or(VsmError::CodePageOffsetOverflow)?;
    // Every core computes the same value (the hypercall page is shared and
    // the offset is partition-wide); the redundant stores from APs are
    // benign. The BSP's store happens during its boot, strictly before any
    // AP is started (APs boot via a BootAps VTL call, which requires the BSP
    // to have completed init and entered its vtl_switch loop), so the target
    // is always non-zero by the time any core executes a VTL return.
    VTL_RETURN_TARGET.store(vtl_return_address, Ordering::Relaxed);
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
        // Never hand the VP back to VTL0 with the preemption timer live.
        crate::arch::timer::disarm_preemption();
        if crate::arch::timer::take_user_timeout_kill() {
            crate::serial_println!(
                "Terminated user-mode code which exceeded its execution quantum"
            );
        }
        vtl1_vp_exit();
        // Note. The below asm block only touches stable memory locations (no on-demand memory
        // allocation, no permission changes). So, it is safe to exclude the current VP from
        // the VTL1 mask before the asm block.

        // Inline asm performs the VTL switch:
        // 1. Restore VTL0 state (XRSTOR + load GP registers from vtl0_state)
        // 2. Return to VTL0 (cli + hypercall)
        // 3. Save VTL0 state when VTL1 resumes (store GP registers + XSAVE)
        //
        // The per-CPU base is derived by masking RSP (the kernel stack lives
        // inside the 256 KiB-aligned PerCpuVariables) and parked on the
        // hypervisor-preserved kernel stack across the VTL round trip.
        // VTL0 GPRs are moved directly between registers and the vtl0_state
        // cell — RSP never leaves the kernel stack (the old push/pop scheme
        // pointed RSP into vtl0_state while IF was still set, so an
        // interrupt there could clobber adjacent per-CPU data).
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
                // rsi := per-CPU base; park it for the resume side.
                "mov rsi, rsp",
                "and rsi, {neg_pcv_align}",
                "push rsi",
                XRSTOR_VTL0_ASM!(rsi, {vtl0_xsave_area_off}, {vtl0_xsave_mask_lo_off}, {vtl0_xsave_mask_hi_off}),
                // Load VTL0 GPRs from vtl0_state (base register rsi last).
                // rax and rcx are skipped: they are immediately clobbered by
                // the VTL return sequence below (the old code popped them and
                // then clobbered them the same way).
                "mov rbp, [rsi + {o_rbp}]",
                "mov rbx, [rsi + {o_rbx}]",
                "mov rdx, [rsi + {o_rdx}]",
                "mov rdi, [rsi + {o_rdi}]",
                "mov r8, [rsi + {o_r8}]",
                "mov r9, [rsi + {o_r9}]",
                "mov r10, [rsi + {o_r10}]",
                "mov r11, [rsi + {o_r11}]",
                "mov r12, [rsi + {o_r12}]",
                "mov r13, [rsi + {o_r13}]",
                "mov r14, [rsi + {o_r14}]",
                "mov r15, [rsi + {o_r15}]",
                "mov rsi, [rsi + {o_rsi}]",
                // *** VTL0 state is restored. Return to VTL0 immediately ***
                "cli", // disable VTL1 interrupts before returning to VTL0
                "xor ecx, ecx",
                "mov rax, [rip + {vtl_return_target}]",
                "call rax",
                // *** VTL1 resumes here regardless of the entry reason (VTL switch or intercept) ***
                // Hyper-V restored VTL1's rip and rsp, so we're back on the
                // original stack with the parked per-CPU base at [rsp].
                // All 15 GPRs hold live VTL0 values; free rdi by pushing it.
                "push rdi",
                "mov rdi, [rsp + 8]", // rdi := parked per-CPU base
                "mov [rdi + {o_rbp}], rbp",
                "mov [rdi + {o_rax}], rax",
                "mov [rdi + {o_rbx}], rbx",
                "mov [rdi + {o_rcx}], rcx",
                "mov [rdi + {o_rdx}], rdx",
                "mov [rdi + {o_rsi}], rsi",
                "mov [rdi + {o_r8}], r8",
                "mov [rdi + {o_r9}], r9",
                "mov [rdi + {o_r10}], r10",
                "mov [rdi + {o_r11}], r11",
                "mov [rdi + {o_r12}], r12",
                "mov [rdi + {o_r13}], r13",
                "mov [rdi + {o_r14}], r14",
                "mov [rdi + {o_r15}], r15",
                "pop rax", // VTL0's rdi
                "mov [rdi + {o_rdi}], rax",
                XSAVE_VTL0_ASM!(rdi, {vtl0_xsave_area_off}, {vtl0_xsave_mask_lo_off}, {vtl0_xsave_mask_hi_off}),
                "sti", // enable VTL1 interrupts after saving VTL0 state
                // A pending SINT can be fired here. Our SINT handler only executes `iretq` so returns to here immediately.
                "add rsp, 8", // drop the parked per-CPU base
                "pop rbp",
                "pop rbx",
                vtl0_xsave_area_off = const { PerCpuVariablesAsm::vtl0_xsave_area_addr_offset() },
                vtl0_xsave_mask_lo_off = const { PerCpuVariablesAsm::vtl0_xsave_mask_lo_offset() },
                vtl0_xsave_mask_hi_off = const { PerCpuVariablesAsm::vtl0_xsave_mask_hi_offset() },
                neg_pcv_align = const { PER_CPU_ALIGN_NEG },
                vtl_return_target = sym VTL_RETURN_TARGET,
                o_rbp = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, rbp) },
                o_rax = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, rax) },
                o_rbx = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, rbx) },
                o_rcx = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, rcx) },
                o_rdx = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, rdx) },
                o_rsi = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, rsi) },
                o_rdi = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, rdi) },
                o_r8 = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, r8) },
                o_r9 = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, r9) },
                o_r10 = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, r10) },
                o_r11 = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, r11) },
                o_r12 = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, r12) },
                o_r13 = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, r13) },
                o_r14 = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, r14) },
                o_r15 = const { VTL0_STATE_OFF + core::mem::offset_of!(VtlState, r15) },
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
            with_per_cpu_variables(|pcv| pcv.asm.reset_vtl1_xsaved());

            return params;
        }
    }
}
