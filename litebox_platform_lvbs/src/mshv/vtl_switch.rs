// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VTL switch related functions

use crate::{
    host::{
        hv_hypercall_page_address,
        per_cpu_variables::{
            PerCpuVariablesAsm, with_per_cpu_variables, with_per_cpu_variables_asm,
            with_per_cpu_variables_mut,
        },
    },
    mshv::{
        HV_REGISTER_VSM_CODEPAGE_OFFSETS, HvRegisterVsmCodePageOffsets, NUM_VTLCALL_PARAMS,
        VTL_ENTRY_REASON_INTERRUPT, VTL_ENTRY_REASON_LOWER_VTL_CALL, VsmFunction,
        hvcall_vp::hvcall_get_vp_registers, vsm::vsm_dispatch, vsm_intercept::vsm_handle_intercept,
        vsm_optee_smc,
    },
};
use core::arch::{asm, naked_asm};
use litebox::utils::{ReinterpretUnsignedExt, TruncateExt};
use litebox_common_linux::errno::Errno;
use num_enum::TryFromPrimitive;

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

pub fn vtl_switch_loop_entry(platform: Option<&'static crate::Platform>) -> ! {
    if let Some(platform) = platform {
        crate::set_platform_low(platform);
    }
    unsafe {
        asm!(
            "jmp {vtl_switch_loop_asm}",
            vtl_switch_loop_asm = sym vtl_switch_loop_asm,
            options(noreturn, nostack, preserves_flags),
        );
    }
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
/// This macro sets `rsp` to point to the start of the VtlState area (top - size),
/// then pops all general-purpose registers.
///
/// Note: After this macro, `rsp` will be at the top of VtlState area, but this doesn't
/// matter because the next iteration resets `rsp` to the kernel stack.
macro_rules! LOAD_VTL_STATE_ASM {
    ($vtl_state_top_addr_off:tt, $vtl_state_size:tt) => {
        concat!(
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
        )
    };
}

/// Assembly macro to save extended states (XSAVE/XSAVEOPT).
///
/// Uses xsaveopt for better performance after the first save.
/// Clobbers: rax, rcx, rdx
macro_rules! XSAVE_ASM {
    ($xsave_area_off:tt, $mask_lo_off:tt, $mask_hi_off:tt, $xsaved_off:tt) => {
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
            "cmp byte ptr gs:[",
            stringify!($xsaved_off),
            "], 0\n",
            "je 2f\n",
            "xsaveopt [rcx]\n",
            "jmp 3f\n",
            "2:\n",
            "xsave [rcx]\n",
            "mov byte ptr gs:[",
            stringify!($xsaved_off),
            "], 1\n",
            "3:\n",
        )
    };
}

/// Assembly macro to restore extended states (XRSTOR).
///
/// Skips restore if state was never saved.
/// Clobbers: rax, rcx, rdx
macro_rules! XRSTOR_ASM {
    ($xsave_area_off:tt, $mask_lo_off:tt, $mask_hi_off:tt, $xsaved_off:tt) => {
        concat!(
            "cmp byte ptr gs:[",
            stringify!($xsaved_off),
            "], 0\n",
            "je 4f\n",
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
            "4:\n",
        )
    };
}

/// VTL switch loop implemented in assembly.
///
/// # Register Assumptions
///
/// At each iteration start, this code only relies on `rip`, `rsp`, and `gs` which Hyper-V
/// saves/restores across VTL switches. All other registers may contain VTL0 state and must
/// be saved before use and restored before returning to VTL0.
///
/// VTL1 registers can be freely clobbered since this loop is stateless -- `rsp` is reset to
/// the kernel stack each iteration and all state lives in per-CPU variables via `gs`.
#[unsafe(naked)]
unsafe extern "C" fn vtl_switch_loop_asm() -> ! {
    naked_asm!(
        "1:",
        "mov rsp, gs:[{kernel_sp_off}]", // reset kernel stack pointer. Hyper-V saves/restores rsp and rip.
        "cli", // disable VTL1 interrupts before returning to VTL0
        VTL_RETURN_ASM!({vtl_ret_addr_off}),
        // *** VTL1 resumes here regardless of the entry reason (VTL switch or intercept) ***
        SAVE_VTL_STATE_ASM!({scratch_off}, {vtl0_state_top_addr_off}),
        XSAVE_ASM!({vtl0_xsave_area_off}, {vtl0_xsave_mask_lo_off}, {vtl0_xsave_mask_hi_off}, {vtl0_xsaved_off}),
        "mov rbp, rsp", // rbp contains VTL0's stack frame, so update it.
        "sti", // enable VTL1 interrupts after saving VTL0 state
        // A pending SINT can be fired here. Our SINT handler only executes `iretq` so returns to here immediately.
        "call {loop_body}",
        ".globl panic_vtl_switch",
        "panic_vtl_switch:", // jump to here on panic to switch back to VTL0
        XRSTOR_ASM!({vtl0_xsave_area_off}, {vtl0_xsave_mask_lo_off}, {vtl0_xsave_mask_hi_off}, {vtl0_xsaved_off}),
        LOAD_VTL_STATE_ASM!({vtl0_state_top_addr_off}, {VTL_STATE_SIZE}),
        // *** VTL0 state is recovered. Do not put any code tampering with them here ***
        "jmp 1b",
        kernel_sp_off = const { PerCpuVariablesAsm::kernel_stack_ptr_offset() },
        vtl_ret_addr_off = const { PerCpuVariablesAsm::vtl_return_addr_offset() },
        scratch_off = const { PerCpuVariablesAsm::scratch_offset() },
        vtl0_state_top_addr_off =
            const { PerCpuVariablesAsm::vtl0_state_top_addr_offset() },
        vtl0_xsave_area_off = const { PerCpuVariablesAsm::vtl0_xsave_area_addr_offset() },
        vtl0_xsave_mask_lo_off = const { PerCpuVariablesAsm::vtl0_xsave_mask_lo_offset() },
        vtl0_xsave_mask_hi_off = const { PerCpuVariablesAsm::vtl0_xsave_mask_hi_offset() },
        vtl0_xsaved_off = const { PerCpuVariablesAsm::vtl0_xsaved_offset() },
        VTL_STATE_SIZE = const core::mem::size_of::<VtlState>(),
        loop_body = sym vtl_switch_loop_body,
    )
}

unsafe extern "C" fn vtl_switch_loop_body() {
    // TODO: We must save/restore VTL1's state when there is RPC from VTL1 to VTL0 (e.g., dynamically
    // loading OP-TEE TAs). This should use global data structures since the core which makes the RPC
    // can be different from the core where the VTL1 is running.
    // TODO: Even if we don't have RPC from VTL1 to VTL0, we may still need to save VTL1's state for
    // debugging purposes.

    // VTL0 extended states (XSAVE/XRSTOR) are now saved and restored in vtl_switch_loop_asm.

    let reason = with_per_cpu_variables(|per_cpu_variables| unsafe {
        (*per_cpu_variables.hv_vp_assist_page_as_ptr()).vtl_entry_reason
    });
    match VtlEntryReason::try_from(reason).unwrap_or(VtlEntryReason::Unknown) {
        VtlEntryReason::VtlCall => {
            let params = with_per_cpu_variables(|per_cpu_variables| {
                per_cpu_variables.vtl0_state.get_vtlcall_params()
            });
            if VsmFunction::try_from(u32::try_from(params[0]).unwrap_or(u32::MAX))
                .unwrap_or(VsmFunction::Unknown)
                == VsmFunction::Unknown
            {
                todo!("unknown function ID = {:#x}", params[0]);
            } else {
                let result = vtlcall_dispatch(&params);
                with_per_cpu_variables_mut(|per_cpu_variables| {
                    per_cpu_variables.set_vtl_return_value(result.reinterpret_as_unsigned());
                });
            }
        }
        VtlEntryReason::Interrupt => {
            vsm_handle_intercept();
        }
        VtlEntryReason::Unknown => {}
    }
}

fn vtlcall_dispatch(params: &[u64; NUM_VTLCALL_PARAMS]) -> i64 {
    let func_id = VsmFunction::try_from(u32::try_from(params[0]).unwrap_or(u32::MAX))
        .unwrap_or(VsmFunction::Unknown);
    match func_id {
        VsmFunction::Unknown => Errno::EINVAL.as_neg().into(),
        VsmFunction::OpteeMessage => vsm_optee_smc::optee_smc_dispatch(params[1]),
        _ => vsm_dispatch(func_id, &params[1..]),
    }
}

pub(crate) fn mshv_vsm_get_code_page_offsets() -> Result<(), Errno> {
    let value =
        hvcall_get_vp_registers(HV_REGISTER_VSM_CODEPAGE_OFFSETS).map_err(|_| Errno::EIO)?;
    let code_page_offsets = HvRegisterVsmCodePageOffsets::from_u64(value);
    let hvcall_page: usize = hv_hypercall_page_address().truncate();
    let vtl_return_address = hvcall_page
        .checked_add(usize::from(code_page_offsets.vtl_return_offset()))
        .ok_or(Errno::EOVERFLOW)?;
    with_per_cpu_variables_asm(|pcv_asm| {
        pcv_asm.set_vtl_return_addr(vtl_return_address);
    });
    Ok(())
}

/// VTL Entry Reason
#[derive(Debug, TryFromPrimitive)]
#[repr(u32)]
pub enum VtlEntryReason {
    VtlCall = VTL_ENTRY_REASON_LOWER_VTL_CALL,
    Interrupt = VTL_ENTRY_REASON_INTERRUPT,
    Unknown = 0xffff_ffff,
}
