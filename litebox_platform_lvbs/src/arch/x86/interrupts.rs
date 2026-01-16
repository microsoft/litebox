// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Interrupt Descriptor Table (IDT)
//!
//! This module sets up the IDT with assembly-based ISR stubs, avoiding the need for
//! the unstable `abi_x86_interrupt` feature.

use crate::mshv::HYPERVISOR_CALLBACK_VECTOR;
use core::ops::IndexMut;
use litebox_common_linux::PtRegs;
use spin::Once;
use x86_64::{VirtAddr, structures::idt::InterruptDescriptorTable};

// Include assembly ISR stubs
core::arch::global_asm!(include_str!("interrupts.S"));

// External symbols for assembly ISR stubs
unsafe extern "C" {
    fn isr_divide_error();
    fn isr_breakpoint();
    fn isr_double_fault();
    fn isr_general_protection_fault();
    fn isr_page_fault();
    fn isr_invalid_opcode();
    fn isr_hyperv_sint();
}

const DOUBLE_FAULT_IST_INDEX: u16 = 0;

fn idt() -> &'static InterruptDescriptorTable {
    static IDT_ONCE: Once<InterruptDescriptorTable> = Once::new();
    IDT_ONCE.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();

        // Safety: These are valid function pointers to assembly ISR stubs that properly
        // handle the interrupt calling convention (save/restore registers, iretq).
        unsafe {
            idt.divide_error
                .set_handler_addr(VirtAddr::from_ptr(isr_divide_error as *const ()));
            idt.breakpoint
                .set_handler_addr(VirtAddr::from_ptr(isr_breakpoint as *const ()));
            idt.double_fault
                .set_handler_addr(VirtAddr::from_ptr(isr_double_fault as *const ()))
                .set_stack_index(DOUBLE_FAULT_IST_INDEX);
            idt.general_protection_fault
                .set_handler_addr(VirtAddr::from_ptr(
                    isr_general_protection_fault as *const (),
                ));
            idt.page_fault
                .set_handler_addr(VirtAddr::from_ptr(isr_page_fault as *const ()));
            idt.invalid_opcode
                .set_handler_addr(VirtAddr::from_ptr(isr_invalid_opcode as *const ()));
            idt.index_mut(HYPERVISOR_CALLBACK_VECTOR)
                .set_handler_addr(VirtAddr::from_ptr(isr_hyperv_sint as *const ()));
        }
        idt
    })
}

/// Initialize IDT (for a core)
pub fn init_idt() {
    idt().load();
}

// TODO: carefully handle exceptions/interrupts. If an exception or interrupt is due to userspace code,
// we should destroy the corresponding user context rather than halt the entire kernel.

/// Rust handler for divide error exception (vector 0).
/// Called from assembly stub with pointer to saved register state.
#[unsafe(no_mangle)]
extern "C" fn divide_error_handler_impl(regs: &PtRegs) {
    todo!("EXCEPTION: DIVIDE BY ZERO\n{:#x?}", regs);
}

/// Rust handler for breakpoint exception (vector 3).
/// Called from assembly stub with pointer to saved register state.
#[unsafe(no_mangle)]
extern "C" fn breakpoint_handler_impl(regs: &PtRegs) {
    todo!("EXCEPTION: BREAKPOINT\n{:#x?}", regs);
}

/// Rust handler for double fault exception (vector 8).
/// Called from assembly stub with pointer to saved register state.
#[unsafe(no_mangle)]
extern "C" fn double_fault_handler_impl(regs: &PtRegs) {
    panic!(
        "EXCEPTION: DOUBLE FAULT (Error Code: {:#x})\n{:#x?}",
        regs.orig_rax, regs
    );
}

/// Rust handler for general protection fault exception (vector 13).
/// Called from assembly stub with pointer to saved register state.
#[unsafe(no_mangle)]
extern "C" fn general_protection_fault_handler_impl(regs: &PtRegs) {
    todo!(
        "EXCEPTION: GENERAL PROTECTION FAULT (Error Code: {:#x})\n{:#x?}",
        regs.orig_rax,
        regs
    );
}

/// Rust handler for page fault exception (vector 14).
/// Called from assembly stub with pointer to saved register state.
#[unsafe(no_mangle)]
extern "C" fn page_fault_handler_impl(regs: &PtRegs) {
    use x86_64::registers::control::Cr2;

    todo!(
        "EXCEPTION: PAGE FAULT\nAccessed Address: {:?}\nError Code: {:#x}\n{:#x?}",
        Cr2::read(),
        regs.orig_rax,
        regs
    );
}

/// Rust handler for invalid opcode exception (vector 6).
/// Called from assembly stub with pointer to saved register state.
#[unsafe(no_mangle)]
extern "C" fn invalid_opcode_handler_impl(regs: &PtRegs) {
    use x86_64::registers::control::Cr2;

    todo!(
        "EXCEPTION: INVALID OPCODE\nAccessed Address: {:?}\n{:#x?}",
        Cr2::read(),
        regs
    );
}

/// Rust handler for Hyper-V synthetic interrupt (vector 0xf3).
/// Called from assembly stub with pointer to saved register state.
///
/// This handler is called when there is a synthetic interrupt.
/// Instead of implementing this handler, we let it immediately return to the VTL switch loop
/// (i.e., the current RIP) which will handle synthetic interrupts.
#[unsafe(no_mangle)]
extern "C" fn hyperv_sint_handler_impl(_regs: &PtRegs) {
    // Intentionally empty - just return to let the VTL switch loop handle it
}
