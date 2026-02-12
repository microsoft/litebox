// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Interrupt Descriptor Table (IDT)
//!
//! This module sets up the IDT with assembly-based ISR stubs, avoiding the need for
//! the unstable `abi_x86_interrupt` feature.
//!
//! # Exceptions Not Handled
//!
//! The following exceptions are intentionally not handled in this IDT:
//!
//! - **NMI (Vector 2)**: Non-Maskable Interrupts are delivered to VTL0 and handled
//!   by the VTL0 kernel. VTL1 does not receive NMIs.
//!
//! - **MCE (Vector 18)**: Machine Check Exceptions are delivered to VTL0 and handled
//!   by the VTL0 kernel. VTL1 does not receive MCEs.

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
    fn isr_debug();
    fn isr_breakpoint();
    fn isr_overflow();
    fn isr_bound_range_exceeded();
    fn isr_invalid_opcode();
    fn isr_device_not_available();
    fn isr_double_fault();
    fn isr_stack_segment_fault();
    fn isr_general_protection_fault();
    fn isr_page_fault();
    fn isr_x87_floating_point();
    fn isr_alignment_check();
    fn isr_simd_floating_point();
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
            idt.debug
                .set_handler_addr(VirtAddr::from_ptr(isr_debug as *const ()));
            idt.breakpoint
                .set_handler_addr(VirtAddr::from_ptr(isr_breakpoint as *const ()));
            idt.overflow
                .set_handler_addr(VirtAddr::from_ptr(isr_overflow as *const ()));
            idt.bound_range_exceeded
                .set_handler_addr(VirtAddr::from_ptr(isr_bound_range_exceeded as *const ()));
            idt.invalid_opcode
                .set_handler_addr(VirtAddr::from_ptr(isr_invalid_opcode as *const ()));
            idt.device_not_available
                .set_handler_addr(VirtAddr::from_ptr(isr_device_not_available as *const ()));
            idt.double_fault
                .set_handler_addr(VirtAddr::from_ptr(isr_double_fault as *const ()))
                .set_stack_index(DOUBLE_FAULT_IST_INDEX);
            idt.stack_segment_fault
                .set_handler_addr(VirtAddr::from_ptr(isr_stack_segment_fault as *const ()));
            idt.general_protection_fault
                .set_handler_addr(VirtAddr::from_ptr(
                    isr_general_protection_fault as *const (),
                ));
            idt.page_fault
                .set_handler_addr(VirtAddr::from_ptr(isr_page_fault as *const ()));
            idt.x87_floating_point
                .set_handler_addr(VirtAddr::from_ptr(isr_x87_floating_point as *const ()));
            idt.alignment_check
                .set_handler_addr(VirtAddr::from_ptr(isr_alignment_check as *const ()));
            idt.simd_floating_point
                .set_handler_addr(VirtAddr::from_ptr(isr_simd_floating_point as *const ()));
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

// TODO: Let's consider whether we can recover some of the below exceptions instead of panicking.

/// Kernel-mode handler for divide error exception (vector 0).
#[unsafe(no_mangle)]
extern "C" fn divide_error_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: DIVIDE BY ZERO\n{:#x?}", regs);
}

/// Kernel-mode handler for debug exception (vector 1).
#[unsafe(no_mangle)]
extern "C" fn debug_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: DEBUG\n{:#x?}", regs);
}

/// Kernel-mode handler for breakpoint exception (vector 3).
#[unsafe(no_mangle)]
extern "C" fn breakpoint_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: BREAKPOINT\n{:#x?}", regs);
}

/// Kernel-mode handler for overflow exception (vector 4).
#[unsafe(no_mangle)]
extern "C" fn overflow_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: OVERFLOW\n{:#x?}", regs);
}

/// Kernel-mode handler for bound range exceeded exception (vector 5).
#[unsafe(no_mangle)]
extern "C" fn bound_range_exceeded_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: BOUND RANGE EXCEEDED\n{:#x?}", regs);
}

/// Kernel-mode handler for invalid opcode exception (vector 6).
#[unsafe(no_mangle)]
extern "C" fn invalid_opcode_handler_impl(regs: &PtRegs) {
    panic!(
        "EXCEPTION: INVALID OPCODE at RIP {:#x}\n{:#x?}",
        regs.rip, regs
    );
}

/// Kernel-mode handler for device not available exception (vector 7).
#[unsafe(no_mangle)]
extern "C" fn device_not_available_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: DEVICE NOT AVAILABLE (FPU/SSE)\n{:#x?}", regs);
}

/// Kernel-mode handler for double fault exception (vector 8).
#[unsafe(no_mangle)]
extern "C" fn double_fault_handler_impl(regs: &PtRegs) {
    panic!(
        "EXCEPTION: DOUBLE FAULT (Error Code: {:#x})\n{:#x?}",
        regs.orig_rax, regs
    );
}

/// Kernel-mode handler for stack-segment fault exception (vector 12).
#[unsafe(no_mangle)]
extern "C" fn stack_segment_fault_handler_impl(regs: &PtRegs) {
    panic!(
        "EXCEPTION: STACK-SEGMENT FAULT (Error Code: {:#x})\n{:#x?}",
        regs.orig_rax, regs
    );
}

/// Kernel-mode handler for general protection fault exception (vector 13).
#[unsafe(no_mangle)]
extern "C" fn general_protection_fault_handler_impl(regs: &PtRegs) {
    panic!(
        "EXCEPTION: GENERAL PROTECTION FAULT (Error Code: {:#x})\n{:#x?}",
        regs.orig_rax, regs
    );
}

/// Kernel-mode handler for x87 floating-point exception (vector 16).
#[unsafe(no_mangle)]
extern "C" fn x87_floating_point_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: x87 FLOATING-POINT ERROR\n{:#x?}", regs);
}

/// Kernel-mode handler for alignment check exception (vector 17).
#[unsafe(no_mangle)]
extern "C" fn alignment_check_handler_impl(regs: &PtRegs) {
    panic!(
        "EXCEPTION: ALIGNMENT CHECK (Error Code: {:#x})\n{:#x?}",
        regs.orig_rax, regs
    );
}

/// Kernel-mode handler for SIMD floating-point exception (vector 19).
#[unsafe(no_mangle)]
extern "C" fn simd_floating_point_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: SIMD FLOATING-POINT ERROR\n{:#x?}", regs);
}

// Note: isr_hyperv_sint is defined in interrupts.S as a minimal stub that only
// performs iretq. This synthetic interrupt is an exception for VTL0 security
// violations (e.g., tampering with write-protected MSRs) delivered by Hyper-V
// to VTL1 as a SINT. Since the handler does nothing, registers are naturally
// preserved. After iretq, the VTL switch loop will save registers and handle
// the violation. VTL1 is not executed concurrently with VTL0, so an immediate
// iretq is safe.
