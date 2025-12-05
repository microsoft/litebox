use core::arch::{asm, naked_asm};
use litebox_common_linux::errno::Errno;
use litebox_platform_lvbs::{
    host::per_cpu_variables::{
        KernelTlsOffset, PerCpuVariables, VtlState, with_per_cpu_variables,
        with_per_cpu_variables_mut,
    },
    mshv::{
        HV_VTL_NORMAL, HV_VTL_SECURE, NUM_VTLCALL_PARAMS, VTL_ENTRY_REASON_INTERRUPT,
        VTL_ENTRY_REASON_LOWER_VTL_CALL, VsmFunction, vsm::vsm_dispatch,
        vsm_intercept::vsm_handle_intercept, vsm_optee_smc, vtl_return,
    },
};
use num_enum::TryFromPrimitive;

unsafe extern "C" fn save_vtl0_state(vtl_state: *const VtlState) {
    let addr = with_per_cpu_variables(|per_cpu_variables| &raw const per_cpu_variables.vtl0_state);
    unsafe {
        core::ptr::copy_nonoverlapping(
            vtl_state as *const u8,
            addr as *const u8 as *mut u8,
            size_of::<VtlState>(),
        );
    }
}

unsafe extern "C" fn save_vtl1_state(vtl_state: *const VtlState) {
    let addr = with_per_cpu_variables(|pcv| &raw const pcv.vtl1_state);
    unsafe {
        core::ptr::copy_nonoverlapping(
            vtl_state as *const u8,
            addr as *const u8 as *mut u8,
            size_of::<VtlState>(),
        );
    }
}

unsafe extern "C" fn load_vtl0_state(vtl_state: *mut VtlState) {
    let addr = with_per_cpu_variables(|pcv| &raw const pcv.vtl0_state);
    unsafe {
        core::ptr::copy_nonoverlapping(
            addr as *const u8 as *mut u8,
            vtl_state as *const u8 as *mut u8,
            size_of::<VtlState>(),
        );
    }
}

unsafe extern "C" fn load_vtl1_state(vtl_state: *mut VtlState) {
    let addr = with_per_cpu_variables(|pcv| &raw const pcv.vtl1_state);
    unsafe {
        core::ptr::copy_nonoverlapping(
            addr as *const u8 as *mut u8,
            vtl_state as *const u8 as *mut u8,
            size_of::<VtlState>(),
        );
    }
}

pub fn vtlcall_dispatch(params: &[u64; NUM_VTLCALL_PARAMS]) -> i64 {
    let func_id = VsmFunction::try_from(u32::try_from(params[0]).unwrap_or(u32::MAX))
        .unwrap_or(VsmFunction::Unknown);
    match func_id {
        VsmFunction::Unknown => Errno::EINVAL.as_neg().into(),
        VsmFunction::OpteeMessage => vsm_optee_smc::optee_smc_dispatch(params[1]),
        _ => vsm_dispatch(func_id, &params[1..]),
    }
}

pub fn vtl_switch_loop() -> ! {
    let stack_top = with_per_cpu_variables(PerCpuVariables::kernel_stack_top);
    let stack_top = stack_top & !0xf; // align to 16 bytes
    unsafe {
        asm!(
            "mov gs:[-{kernel_sp_off}], {stack_top}",
            stack_top = in(reg) stack_top,
            kernel_sp_off = const {KernelTlsOffset::KernelStackPtr as usize},
            options(nostack, preserves_flags),
        );
    }
    // unsafe { vtl_switch_loop_asm() }
    unsafe {
        asm!(
            "jmp {vtl_switch_loop_asm}",
            vtl_switch_loop_asm = sym vtl_switch_loop_asm,
            options(noreturn)
        )
    }
}

#[unsafe(naked)]
unsafe extern "C" fn vtl_switch_loop_asm() -> ! {
    naked_asm!(
        // VTL1 state saving
        "mov gs:[-{kernel_sp_off}], rsp",
        "sub rsp, 8 * 16", // 16 bytes aligned
        "mov [rsp + 0], r15",
        "mov [rsp + 8], r14",
        "mov [rsp + 16], r13",
        "mov [rsp + 24], r12",
        "mov [rsp + 32], r11",
        "mov [rsp + 40], r10",
        "mov [rsp + 48], r9",
        "mov [rsp + 56], r8",
        "mov [rsp + 64], rdi",
        "mov [rsp + 72], rsi",
        "mov [rsp + 80], rdx",
        "mov [rsp + 88], rcx",
        "mov [rsp + 96], rbx",
        "mov [rsp + 104], rax",
        "mov rax, cr2",
        "mov [rsp + 112], rax",
        "mov [rsp + 120], rbp",
        "lea rdi, [rsp]",
        "call {save_vtl1_state}",
        "mov rsp, gs:[-{kernel_sp_off}]",
        "1:",
        // VTL switch back to VTL0 (architecture-neutral call-based hypercall).
        "xor ecx, ecx",
        "mov rax, gs:[-{vtl_ret_addr_off}]",
        "call rax",
        // *** This is where VTL1 resumes its execution (i.e., VTL0-to-VTL1 switch lands here) ***
        // VTL0 state saving
        // "mov rsp, gs:[-{kernel_sp_off}]",
        "mov gs:[-{kernel_sp_off}], rsp",
        "sub rsp, 8 * 16",
        "mov [rsp + 0], r15",
        "mov [rsp + 8], r14",
        "mov [rsp + 16], r13",
        "mov [rsp + 24], r12",
        "mov [rsp + 32], r11",
        "mov [rsp + 40], r10",
        "mov [rsp + 48], r9",
        "mov [rsp + 56], r8",
        "mov [rsp + 64], rdi",
        "mov [rsp + 72], rsi",
        "mov [rsp + 80], rdx",
        "mov [rsp + 88], rcx",
        "mov [rsp + 96], rbx",
        "mov [rsp + 104], rax",
        "mov rax, cr2",
        "mov [rsp + 112], rax",
        "mov [rsp + 120], rbp",
        "lea rdi, [rsp]",
        "call {save_vtl0_state}",
        "mov rsp, gs:[-{kernel_sp_off}]",
        // VTL1 state loading
        // "mov gs:[-{kernel_sp_off}], rsp",
        "sub rsp, 8 * 16",
        "lea rdi, [rsp]",
        "call {load_vtl1_state}",
        "mov r15, [rsp + 0]",
        "mov r14, [rsp + 8]",
        "mov r13, [rsp + 16]",
        "mov r12, [rsp + 24]",
        "mov r11, [rsp + 32]",
        "mov r10, [rsp + 40]",
        "mov r9, [rsp + 48]",
        "mov r8, [rsp + 56]",
        "mov rdi, [rsp + 64]",
        "mov rsi, [rsp + 72]",
        "mov rdx, [rsp + 80]",
        "mov rcx, [rsp + 88]",
        "mov rbx, [rsp + 96]",
        "mov rax, [rsp + 104]",
        "mov rax, [rsp + 112]",
        "mov cr2, rax",
        "mov rbp, [rsp + 120]",
        "mov rsp, gs:[-{kernel_sp_off}]",
        "call {loop_body}",
        // VTL0 state loading
        // "mov rsp, gs:[-{kernel_sp_off}]",
        "mov gs:[-{kernel_sp_off}], rsp",
        "sub rsp, 8 * 16",
        "lea rdi, [rsp]",
        "call {load_vtl0_state}",
        "mov r15, [rsp + 0]",
        "mov r14, [rsp + 8]",
        "mov r13, [rsp + 16]",
        "mov r12, [rsp + 24]",
        "mov r11, [rsp + 32]",
        "mov r10, [rsp + 40]",
        "mov r9, [rsp + 48]",
        "mov r8, [rsp + 56]",
        "mov rdi, [rsp + 64]",
        "mov rsi, [rsp + 72]",
        "mov rdx, [rsp + 80]",
        "mov rcx, [rsp + 88]",
        "mov rbx, [rsp + 96]",
        "mov rax, [rsp + 104]",
        "mov rax, [rsp + 112]",
        "mov cr2, rax",
        "mov rbp, [rsp + 120]",
        "mov rsp, gs:[-{kernel_sp_off}]",
        "jmp 1b",
        loop_body = sym vtl_switch_loop_body,
        save_vtl0_state = sym save_vtl0_state,
        save_vtl1_state = sym save_vtl1_state,
        load_vtl0_state = sym load_vtl0_state,
        load_vtl1_state = sym load_vtl1_state,
        kernel_sp_off = const {KernelTlsOffset::KernelStackPtr as usize},
        vtl_ret_addr_off = const { KernelTlsOffset::VtlReturnAddr as usize },
    )
}

unsafe extern "C" fn vtl_switch_loop_body() {
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

/// VTL Entry Reason
#[derive(Debug, TryFromPrimitive)]
#[repr(u32)]
pub enum VtlEntryReason {
    VtlCall = VTL_ENTRY_REASON_LOWER_VTL_CALL,
    Interrupt = VTL_ENTRY_REASON_INTERRUPT,
    Unknown = 0xffff_ffff,
}
