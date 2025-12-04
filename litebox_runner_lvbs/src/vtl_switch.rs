use core::arch::naked_asm;
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

const STACK_ALIGNMENT: isize = -16;

// Save CPU registers to a global data structure through using a stack
#[unsafe(naked)]
pub unsafe extern "C" fn save_vtl0_state() {
    naked_asm!(
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push rbx",
        "push rax",
        "mov rax, cr2",
        "push rax",
        "push rbp",
        "mov rbp, rsp",
        "mov edi, {vtl}",
        "mov rsi, rsp",
        "and rsp, {stack_alignment}",
        "call {save_vtl_state_to_per_cpu_variables}",
        "mov rsp, rbp",
        "add rsp, {register_space}",
        "ret",
        vtl = const HV_VTL_NORMAL,
        stack_alignment = const STACK_ALIGNMENT,
        save_vtl_state_to_per_cpu_variables = sym save_vtl_state_to_per_cpu_variables,
        register_space = const core::mem::size_of::<VtlState>(),
    );
}

#[unsafe(naked)]
pub unsafe extern "C" fn save_vtl1_state() {
    naked_asm!(
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push rbx",
        "push rax",
        "mov rax, cr2",
        "push rax",
        "push rbp",
        "mov rbp, rsp",
        "mov edi, {vtl}",
        "mov rsi, rsp",
        "and rsp, {stack_alignment}",
        "call {save_vtl_state_to_per_cpu_variables}",
        "mov rsp, rbp",
        "add rsp, {register_space}",
        "ret",
        vtl = const HV_VTL_SECURE,
        stack_alignment = const STACK_ALIGNMENT,
        save_vtl_state_to_per_cpu_variables = sym save_vtl_state_to_per_cpu_variables,
        register_space = const core::mem::size_of::<VtlState>(),
    );
}

fn save_vtl_state_to_per_cpu_variables(vtl: u8, vtl_state: *const VtlState) {
    with_per_cpu_variables_mut(|per_cpu_variables| match vtl {
        HV_VTL_NORMAL => per_cpu_variables
            .vtl0_state
            .clone_from(unsafe { &*vtl_state }),
        HV_VTL_SECURE => per_cpu_variables
            .vtl1_state
            .clone_from(unsafe { &*vtl_state }),
        _ => panic!("Invalid VTL number: {}", vtl),
    });
}

fn load_vtl_state_from_per_cpu_variables(vtl: u8, vtl_state: *mut VtlState) {
    with_per_cpu_variables_mut(|per_cpu_variables| match vtl {
        HV_VTL_NORMAL => unsafe { vtl_state.copy_from(&raw const per_cpu_variables.vtl0_state, 1) },
        HV_VTL_SECURE => unsafe { vtl_state.copy_from(&raw const per_cpu_variables.vtl1_state, 1) },
        _ => panic!("Invalid VTL number: {}", vtl),
    });
}

// Restore CPU registers from the global data structure through using a stack.
#[unsafe(naked)]
pub unsafe extern "C" fn load_vtl_state(vtl: u8) {
    naked_asm!(
        "sub rsp, {register_space}",
        "mov rbp, rsp",
        // rdi holds the VTL number
        "mov rsi, rsp",
        "and rsp, {stack_alignment}",
        "call {load_vtl_state_from_per_cpu_variables}",
        "mov rsp, rbp",
        "pop rbp",
        "pop rax",
        "mov cr2, rax",
        "pop rax",
        "pop rbx",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "pop r8",
        "pop r9",
        "pop r10",
        "pop r11",
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",
        "ret",
        register_space = const core::mem::size_of::<VtlState>(),
        stack_alignment = const STACK_ALIGNMENT,
        load_vtl_state_from_per_cpu_variables = sym load_vtl_state_from_per_cpu_variables,
    );
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
    let stack_top = stack_top & !0xf;
    unsafe {
        core::arch::asm!(
            "mov gs:[-{kernel_sp_off}], {stack_top}",
            stack_top = in(reg) stack_top,
            kernel_sp_off = const {KernelTlsOffset::KernelStackPtr as usize},
            options(nostack, preserves_flags),
        );
    }

    // This is a dummy call to satisfy load_vtl0_state() with reasonable register values.
    // We do not save VTL0 registers during VTL1 initialization.
    unsafe {
        save_vtl0_state();
    }

    unsafe { vtl_switch_loop_asm() }
}

#[unsafe(naked)]
unsafe extern "C" fn vtl_switch_loop_asm() -> ! {
    core::arch::naked_asm!(
        "1:",
        "call {loop_body}",
        "mov rsp, gs:[-{kernel_sp_off}]",
        "jmp 1b",
        loop_body = sym vtl_switch_loop_body,
        kernel_sp_off = const {KernelTlsOffset::KernelStackPtr as usize},
    );
}

fn vtl_switch_loop_body() {
    unsafe {
        save_vtl1_state();
        load_vtl_state(HV_VTL_NORMAL);
    }

    vtl_return();
    // *** This is where VTL1 starts to execute code (i.e., VTL0-to-VTL1 switch lands here) ***

    unsafe {
        save_vtl0_state();
        load_vtl_state(HV_VTL_SECURE);
    }

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
