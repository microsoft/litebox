//! VTL switch related functions

use crate::{
    host::{
        hv_hypercall_page_address,
        per_cpu_variables::{with_per_cpu_variables, with_per_cpu_variables_mut},
    },
    mshv::{
        HV_REGISTER_VSM_CODEPAGE_OFFSETS, HV_VTL_NORMAL, HV_VTL_SECURE,
        HvRegisterVsmCodePageOffsets, NUM_VTLCALL_PARAMS, VTL_ENTRY_REASON_INTERRUPT,
        VTL_ENTRY_REASON_LOWER_VTL_CALL, VsmFunction, hvcall_vp::hvcall_get_vp_registers,
        vsm::vsm_dispatch, vsm_intercept::vsm_handle_intercept,
    },
};
use core::arch::{asm, naked_asm};
use litebox_common_linux::errno::Errno;
use num_enum::TryFromPrimitive;

static mut VTL_RETURN_ADDRESS: u64 = 0;

/// Return to VTL0
#[expect(clippy::inline_always)]
#[inline(always)]
fn vtl_return() {
    unsafe {
        asm!(
            "call rax",
            in("rax") VTL_RETURN_ADDRESS, in("rcx") 0x0,
        );
    }
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
    pub cr2: u64,
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
    // DR[0-6]
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

// Save CPU registers to a global data structure through using a stack
#[unsafe(naked)]
unsafe extern "C" fn save_vtl0_state() {
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
const STACK_ALIGNMENT: isize = -16;

#[unsafe(naked)]
unsafe extern "C" fn save_vtl1_state() {
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

fn load_vtl_state_from_per_cpu_variables(vtl: u8, vtl_state: *mut VtlState) {
    with_per_cpu_variables_mut(|per_cpu_variables| match vtl {
        HV_VTL_NORMAL => unsafe { vtl_state.copy_from(&raw const per_cpu_variables.vtl0_state, 1) },
        HV_VTL_SECURE => unsafe { vtl_state.copy_from(&raw const per_cpu_variables.vtl1_state, 1) },
        _ => panic!("Invalid VTL number: {}", vtl),
    });
}

// Restore CPU registers from the global data structure through using a stack.
#[unsafe(naked)]
unsafe extern "C" fn load_vtl_state(vtl: u8) {
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

pub fn vtl_switch_loop_entry(platform: Option<&'static crate::Platform>) -> ! {
    if let Some(platform) = platform {
        crate::set_platform_low(platform);
    }

    unsafe {
        save_vtl0_state();
    }
    // This is a dummy call to satisfy load_vtl0_state() with reasonable register values.
    // We do not save VTL0 registers during VTL1 initialization.

    jump_to_vtl_switch_loop_with_stack_cleanup();
}

/// This function lets VTL1 return to VTL0. Before returning to VTL0, it re-initializes
/// the VTL1 kernel stack to discard any leftovers (e.g., unwind, panic, ...).
#[allow(clippy::inline_always)]
#[inline(always)]
fn jump_to_vtl_switch_loop_with_stack_cleanup() -> ! {
    with_per_cpu_variables_mut(|per_cpu_variables| {
        per_cpu_variables.restore_extended_states(HV_VTL_NORMAL);
    });

    let stack_top =
        with_per_cpu_variables(crate::host::per_cpu_variables::PerCpuVariables::kernel_stack_top);
    unsafe {
        asm!(
            "mov rsp, rax",
            "and rsp, {stack_alignment}",
            "call {loop}",
            in("rax") stack_top, loop = sym vtl_switch_loop,
            stack_alignment = const STACK_ALIGNMENT,
            options(noreturn)
        );
    }
}

/// expose `vtl_switch_loop` to the outside (e.g., the syscall handler)
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn jump_to_vtl_switch_loop() -> ! {
    naked_asm!(
        "call {loop}",
        loop = sym vtl_switch_loop,
    );
}

/// VTL switch loop
///
/// # Panics
/// Panic if it encounters an unknown VTL entry reason.
fn vtl_switch_loop() -> ! {
    loop {
        unsafe {
            save_vtl1_state();
            load_vtl_state(HV_VTL_NORMAL);
        }

        vtl_return();
        // VTL calls and intercepts (i.e., returns from synthetic interrupt handlers) land here.

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
                    jump_to_vtl_switch_loop_with_stack_cleanup();
                }
            }
            VtlEntryReason::Interrupt => {
                vsm_handle_intercept();
                jump_to_vtl_switch_loop_with_stack_cleanup();
            }
            VtlEntryReason::Unknown => {
                panic!("Unknown VTL entry reason");
            }
        }
        // do not put any code which might corrupt registers
    }
}

fn vtlcall_dispatch(params: &[u64; NUM_VTLCALL_PARAMS]) -> i64 {
    let func_id = VsmFunction::try_from(u32::try_from(params[0]).unwrap_or(u32::MAX))
        .unwrap_or(VsmFunction::Unknown);
    match func_id {
        VsmFunction::Unknown => Errno::EINVAL.as_neg().into(),
        VsmFunction::OpteeMessage => {
            // Since we do not know whether an upcall handler uses extended states, we conservatively
            // save and restore extended states before and after invoking the upcall handler.
            with_per_cpu_variables_mut(|per_cpu_variables| {
                per_cpu_variables.save_extended_states(HV_VTL_SECURE);
            });

            // TODO: invoke the OP-TEE upcall once it is merged.

            with_per_cpu_variables_mut(|per_cpu_variables| {
                per_cpu_variables.restore_extended_states(HV_VTL_SECURE);
            });
            0
        }
        _ => vsm_dispatch(func_id, &params[1..]),
    }
}

pub(crate) fn mshv_vsm_get_code_page_offsets() -> Result<(), Errno> {
    let value =
        hvcall_get_vp_registers(HV_REGISTER_VSM_CODEPAGE_OFFSETS).map_err(|_| Errno::EIO)?;
    let code_page_offsets = HvRegisterVsmCodePageOffsets::from_u64(value);
    unsafe {
        VTL_RETURN_ADDRESS =
            hv_hypercall_page_address() + u64::from(code_page_offsets.vtl_return_offset());
    }
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
