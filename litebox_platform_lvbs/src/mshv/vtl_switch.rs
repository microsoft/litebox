//! VTL switch related functions

use crate::{
    host::{
        hv_hypercall_page_address,
        per_cpu_variables::{
            KernelTlsOffset, with_kernel_tls_mut, with_per_cpu_variables,
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

/// A function to return to VTL0 using the Hyper-V hypercall stub.
/// Although Hyper-V lets each core use the same VTL return address, this implementation
/// uses per-TLS return address to avoid using a mutable global variable.
macro_rules! VTL_RETURN_ASM {
    () => {
        "
        xor ecx, ecx
        mov rax, gs:[{vtl_ret_addr_off}]
        call rax
        "
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
    vtl_switch_loop()
}

fn vtl_switch_loop() -> ! {
    unsafe {
        asm!(
            "jmp {vtl_switch_loop_asm}",
            vtl_switch_loop_asm = sym vtl_switch_loop_asm,
            options(noreturn, nostack, preserves_flags),
        );
    }
}

macro_rules! SAVE_VTL0_STATE_ASM {
    () => {
        "
        mov gs:[{scratch_off}], rsp
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
        push rbp /*  15 * 8 = 120. 120 % 16 == 8 */
        lea rdi, [rsp]
        push rbp /* alignment */
        call {save_vtl0_state}
        mov rsp, gs:[{scratch_off}]
        "
    };
}

macro_rules! LOAD_VTL0_STATE_ASM {
    () => {
        "
        mov gs:[{scratch_off}], rsp
        sub rsp, {vtl_state_size} /* 15 * 8 = 120. 120 % 16 == 8 */
        lea rdi, [rsp]
        push rbp /* alignment */
        call {load_vtl0_state}
        mov rsp, gs:[{scratch_off}] /* anchor */
        sub rsp, {vtl_state_size}
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
        mov rsp, gs:[{scratch_off}]
        "
    };
}

unsafe extern "C" fn save_vtl0_state(vtl_state: *const VtlState) {
    let addr = with_per_cpu_variables(|per_cpu_variables| &raw const per_cpu_variables.vtl0_state);
    unsafe {
        core::ptr::copy_nonoverlapping(
            vtl_state.cast::<u8>(),
            addr.cast::<u8>().cast_mut(),
            size_of::<VtlState>(),
        );
    }
}

unsafe extern "C" fn load_vtl0_state(vtl_state: *mut VtlState) {
    let addr = with_per_cpu_variables(|pcv| &raw const pcv.vtl0_state);
    unsafe {
        core::ptr::copy_nonoverlapping(
            addr.cast::<u8>(),
            vtl_state.cast::<u8>(),
            size_of::<VtlState>(),
        );
    }
}

#[unsafe(naked)]
unsafe extern "C" fn vtl_switch_loop_asm() -> ! {
    naked_asm!(
        "1:",
        "mov rsp, gs:[{kernel_sp_off}]", // reset kernel stack pointer. Hyper-V saves/restores rsp and rip.
        VTL_RETURN_ASM!(),
        // *** VTL1 resumes here regardless of the entry reason (VTL switch or intercept) ***
        SAVE_VTL0_STATE_ASM!(),
        "mov rbp, rsp", // rbp contains VTL0's stack frame, so update it.
        "call {loop_body}",
        LOAD_VTL0_STATE_ASM!(),
        "jmp 1b",
        kernel_sp_off = const { KernelTlsOffset::KernelStackPtr as usize },
        vtl_ret_addr_off = const { KernelTlsOffset::VtlReturnAddr as usize },
        scratch_off = const { KernelTlsOffset::Scratch as usize },
        save_vtl0_state = sym save_vtl0_state,
        load_vtl0_state = sym load_vtl0_state,
        vtl_state_size = const core::mem::size_of::<VtlState>(),
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
    with_kernel_tls_mut(|ktls| {
        ktls.set_vtl_return_addr(vtl_return_address);
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
