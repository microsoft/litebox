//! VTL switch related functions

use crate::{
    host::{
        hv_hypercall_page_address,
        per_cpu_variables::{
            PerCpuVariablesAsmOffset, with_per_cpu_variables, with_per_cpu_variables_asm_mut,
            with_per_cpu_variables_mut,
        },
    },
    mshv::{
        HV_REGISTER_VSM_CODEPAGE_OFFSETS, HV_VTL_NORMAL, HvRegisterVsmCodePageOffsets,
        NUM_VTLCALL_PARAMS, VTL_ENTRY_REASON_INTERRUPT, VTL_ENTRY_REASON_LOWER_VTL_CALL,
        VsmFunction, hvcall_vp::hvcall_get_vp_registers, vsm::vsm_dispatch,
        vsm_intercept::vsm_handle_intercept, vsm_optee_smc,
    },
};
use core::arch::{asm, naked_asm};
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
#[allow(clippy::pub_underscore_fields)]
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

/// Assembly macro to save VTL state to the memory area pointed by the current
/// stack pointer (`rsp`).
///
/// `rsp` can point to the current CPU stack or the *top address* of a memory area which
/// has enough space for storing the `VtlState` structure using the `push` instructions
/// (i.e., from high addresses down to low ones).
macro_rules! SAVE_VTL_STATE_ASM {
    () => {
        "
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8
        push rdi
        push rsi
        push rdx
        push rcx
        push rbx
        push rax
        push rbp
        "
    };
}

/// Assembly macro to restore VTL state from the memory area pointed by the current `rsp`.
///
/// This macro uses the `pop` instructions (i.e., from low addresses up to high ones) such that
/// it requires the start address of the memory area (not the top one).
///
/// Prerequisite: The memory area has `VtlState` structure containing user context.
macro_rules! LOAD_VTL_STATE_ASM {
    () => {
        "
        pop rbp
        pop rax
        pop rbx
        pop rcx
        pop rdx
        pop rsi
        pop rdi
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15
        "
    };
}

#[unsafe(naked)]
unsafe extern "C" fn vtl_switch_loop_asm() -> ! {
    naked_asm!(
        "1:",
        "mov rsp, gs:[{kernel_sp_off}]", // reset kernel stack pointer. Hyper-V saves/restores rsp and rip.
        VTL_RETURN_ASM!({vtl_ret_addr_off}),
        // *** VTL1 resumes here regardless of the entry reason (VTL switch or intercept) ***
        "mov gs:[{scratch_off}], rsp", // save VTL1's rsp to scratch
        "mov rsp, gs:[{vtl0_state_top_addr_off}]", // point rsp to the top address of VtlState for VTL0
        SAVE_VTL_STATE_ASM!(),
        "mov rsp, gs:[{scratch_off}]", // restore VTL1's rsp from scratch
        // TODO: XSAVE
        "mov rbp, rsp", // rbp contains VTL0's stack frame, so update it.
        "call {loop_body}",
        // TODO: XRSTOR
        "mov r8, gs:[{vtl0_state_top_addr_off}]",
        "lea rsp, [r8 - {VTL_STATE_SIZE}]", // point rsp to the start address of VtlState
        LOAD_VTL_STATE_ASM!(),
        // *** VTL0 state is recovered. Do not put any code tampering with them here ***
        "jmp 1b",
        kernel_sp_off = const { PerCpuVariablesAsmOffset::KernelStackPtr as usize },
        vtl_ret_addr_off = const { PerCpuVariablesAsmOffset::VtlReturnAddr as usize },
        scratch_off = const { PerCpuVariablesAsmOffset::Scratch as usize },
        vtl0_state_top_addr_off =
            const { PerCpuVariablesAsmOffset::Vtl0StateTopAddr as usize },
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

    // Since we do not know whether the VTL0 kernel saves its extended states (e.g., if a VTL switch
    // is due to memory or register access violation, the VTL0 kernel might not have saved
    // its states), we conservatively save and restore its extended states on every VTL switch.
    with_per_cpu_variables_mut(|per_cpu_variables| {
        per_cpu_variables.save_extended_states(HV_VTL_NORMAL);
    });

    let reason = with_per_cpu_variables(|per_cpu_variables| unsafe {
        (*per_cpu_variables.hv_vp_assist_page_as_ptr()).vtl_entry_reason
    });
    match VtlEntryReason::try_from(reason).unwrap_or(VtlEntryReason::Unknown) {
        #[allow(clippy::cast_sign_loss)]
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
                    per_cpu_variables.set_vtl_return_value(result as u64);
                });
            }
        }
        VtlEntryReason::Interrupt => {
            vsm_handle_intercept();
        }
        VtlEntryReason::Unknown => {}
    }

    with_per_cpu_variables(|per_cpu_variables| {
        per_cpu_variables.restore_extended_states(HV_VTL_NORMAL);
    });
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
    let hvcall_page = usize::try_from(hv_hypercall_page_address()).unwrap();
    let vtl_return_address = hvcall_page
        .checked_add(usize::from(code_page_offsets.vtl_return_offset()))
        .ok_or(Errno::EOVERFLOW)?;
    with_per_cpu_variables_asm_mut(|pcv_asm| {
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
