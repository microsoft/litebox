//! VTL switch related functions

use crate::{
    kernel_context::get_per_core_kernel_context,
    mshv::{
        VTL_ENTRY_REASON_INTERRUPT, VTL_ENTRY_REASON_LOWER_VTL_CALL,
        vsm::{NUM_VTLCALL_PARAMS, VSMFunction, vsm_dispatch},
        vsm_intercept::vsm_handle_intercept,
    },
    serial_println,
};
use core::{arch::asm, mem};
use num_enum::TryFromPrimitive;

/// Return to VTL0
#[expect(clippy::inline_always)]
#[inline(always)]
pub fn vtl_return() {
    unsafe {
        asm!(
            "vmcall",
            in("rax") 0x0, in("rcx") 0x12
        );
    }
}

// The following registers are shared between different VTLs.
// If VTL entry is due to VTL call, we don't need to worry about VTL0 registers because
// the caller saves them. However, if VTL entry is due to interrupt or intercept,
// we should save/restore VTL0 registers. For now, we conservately save/restore all
// VTL0/VTL1 registers (results in performance degradation)
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
const NUM_SAVED_REGISTERS: usize = 16;

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

// This only uses a stack to save registers while ensuring no register corruption.
#[expect(clippy::inline_always)]
#[inline(always)]
fn push_vtl_state_to_stack() -> *mut VtlState {
    let stack_top: u64;
    unsafe {
        asm!(
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
            "mov rax, rsp",
            lateout("rax") stack_top
        );
    }

    stack_top as *mut VtlState
}

// This only uses a stack to restore registers while ensuring no register corruption.
// Ignores rax and rcx because vmcall wipes them out.
#[expect(clippy::inline_always)]
#[inline(always)]
fn pop_vtl_state(state: &VtlState) {
    unsafe {
        asm!("mov rbp, rax", in("rax") state.rbp);
        asm!("mov cr2, rax", in("rax") state.cr2);
        asm!("mov rbx, rax", in("rax") state.rbx);
        asm!("mov rdx, rax", in("rax") state.rdx);
        asm!("mov rsi, rax", in("rax") state.rsi);
        asm!("mov r8, rax", in("rax") state.r8);
        asm!("mov r9, rax", in("rax") state.r9);
        asm!("mov r10, rax", in("rax") state.r10);
        asm!("mov r11, rax", in("rax") state.r11);
        asm!("mov r12, rax", in("rax") state.r12);
        asm!("mov r13, rax", in("rax") state.r13);
        asm!("mov r14, rax", in("rax") state.r14);
        asm!("mov r15, rax", in("rax") state.r15);
        asm!("mov rdi, rax", in("rax") state.rdi);
    }
}

#[expect(clippy::inline_always)]
#[inline(always)]
fn drop_vtl_state_from_stack() {
    unsafe {
        asm!("add rsp, {}", const mem::size_of::<u64>() * NUM_SAVED_REGISTERS);
    }
}
// This function heavily relies on the stack alignment and packed struct.

#[expect(clippy::inline_always)]
#[inline(always)]
fn assert_rsp_eq(exected_rsp: u64) {
    let mut match_flag: u8;
    unsafe {
        asm!(
            "cmp rsp, rax",
            "sete al",
            in("rax") exected_rsp,
            lateout("al") match_flag,
            options(nostack, preserves_flags)
        );
    }

    assert!(match_flag != 0, "RSP does not match expected value");
}

#[expect(clippy::inline_always)]
#[inline(always)]
fn save_vtl0_state() {
    let vtl0_state = push_vtl_state_to_stack();
    let kernel_context = get_per_core_kernel_context();
    kernel_context
        .vtl0_state
        .clone_from(unsafe { &*vtl0_state });
    // any code between push and drop must not leave any data on the stack
    // to avoid memory leak. the following assert is to confirm this.
    assert_rsp_eq(vtl0_state as u64);
    drop_vtl_state_from_stack();
}

#[expect(clippy::inline_always)]
#[inline(always)]
fn save_vtl1_state() {
    let vtl1_state = push_vtl_state_to_stack();
    let kernel_context = get_per_core_kernel_context();
    kernel_context
        .vtl1_state
        .clone_from(unsafe { &*vtl1_state });
    // any code between push and drop must not leave any data on the stack
    // to avoid memory leak. the following assert is to confirm this.
    assert_rsp_eq(vtl1_state as u64);
    drop_vtl_state_from_stack();
}

#[expect(clippy::inline_always)]
#[inline(always)]
fn load_vtl0_state() {
    let kernel_context = get_per_core_kernel_context();
    let vtl0_state: VtlState = kernel_context.vtl0_state;
    pop_vtl_state(&vtl0_state);
}

#[expect(clippy::inline_always)]
#[inline(always)]
fn load_vtl1_state() {
    let kernel_context = get_per_core_kernel_context();
    let vtl1_state: VtlState = kernel_context.vtl1_state;
    pop_vtl_state(&vtl1_state);
}

pub fn vtl_switch_loop_entry(platform: Option<&'static crate::Platform>) -> ! {
    if let Some(platform) = platform {
        crate::set_platform_low(platform);
    }

    save_vtl0_state();
    // This is a dummy call to satisfy load_vtl0_state() with reasonable register values.
    // We do not save VTL0 registers during VTL1 initialization.

    vtl_switch_loop();
}

/// VTL switch loop
/// # Panics
/// Panics if VTL call parameter 0 is greater than u32::MAX
pub fn vtl_switch_loop() -> ! {
    loop {
        save_vtl1_state();
        load_vtl0_state();

        vtl_return();

        save_vtl0_state();
        load_vtl1_state();

        let kernel_context = get_per_core_kernel_context();
        let reason = unsafe { (*kernel_context.hv_vp_assist_page_as_ptr()).vtl_entry_reason };
        match VtlEntryReason::try_from(reason).unwrap_or(VtlEntryReason::Unknown) {
            #[allow(clippy::cast_sign_loss)]
            VtlEntryReason::VtlCall => {
                let params = kernel_context.vtl0_state.get_vtlcall_params();
                if VSMFunction::try_from(u32::try_from(params[0]).expect("VTL call param 0"))
                    .unwrap_or(VSMFunction::Unknown)
                    == VSMFunction::Unknown
                {
                    todo!("unknown function ID = {:#x}", params[0]);
                } else {
                    let new_result = vsm_dispatch(&params);
                    kernel_context.set_vtl_return_value(new_result as u64);
                }
            }
            #[allow(clippy::cast_sign_loss)]
            VtlEntryReason::Interrupt => {
                let new_result = vsm_handle_intercept();
                kernel_context.set_vtl_return_value(new_result as u64);
            }
            VtlEntryReason::Unknown => {
                serial_println!("Unknown VTL entry reason");
                kernel_context.set_vtl_return_value(0);
            }
        }
        // do not put any code which might corrupt registers
    }
}

/// VTL Entry Reason
#[derive(Debug, TryFromPrimitive)]
#[repr(u32)]
pub enum VtlEntryReason {
    VtlCall = VTL_ENTRY_REASON_LOWER_VTL_CALL,
    Interrupt = VTL_ENTRY_REASON_INTERRUPT,
    Unknown = 0xffff_ffff,
}
