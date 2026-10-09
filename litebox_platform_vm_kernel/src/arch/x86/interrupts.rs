// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Interrupt entry requires the GDT/TSS and per-CPU stacks.
//! NMI entry cannot assume kernel GS or a completed syscall stack switch.
//! CR4.MCE remains off; machine checks shut down the CPU.

use core::sync::atomic::{AtomicU64, Ordering};
use litebox_common_linux::PtRegs;
use spin::Once;
use x86_64::{VirtAddr, structures::idt::InterruptDescriptorTable};

core::arch::global_asm!(include_str!("interrupts.S"));

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
    fn isr_ignore();
    /// One stub per vector from 32, each entering `isr_external`.
    fn isr_external_stubs();
}

/// Stride of the per-vector stubs in `isr_external_stubs`.
const UNEXPECTED_STUB_SIZE: usize = 8;

const DOUBLE_FAULT_IST_INDEX: u16 = 0;
const NMI_IST_INDEX: u16 = 1;

/// The IDT, and the state of the external interrupts it dispatches.
struct Interrupts {
    idt: InterruptDescriptorTable,
    /// See [`crate::set_interrupt_handler`].
    handler: Once<fn(u8) -> bool>,
    /// Bit `v % 64` of word `v / 64`: vector `v` was handled since it was
    /// last taken ([`take_pending`]).
    pending: [AtomicU64; 4],
}

static INTERRUPTS: Once<Interrupts> = Once::new();

fn idt(ignored_vectors: &[u8]) -> &'static InterruptDescriptorTable {
    &INTERRUPTS
        .call_once(|| Interrupts {
            idt: build_idt(ignored_vectors),
            handler: Once::new(),
            pending: [const { AtomicU64::new(0) }; 4],
        })
        .idt
}

fn build_idt(ignored_vectors: &[u8]) -> InterruptDescriptorTable {
    let mut idt = InterruptDescriptorTable::new();

    // Safety: the stubs follow the interrupt calling convention.
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
        for vector in 32..=u8::MAX {
            let stub = isr_external_stubs as *const () as usize
                + usize::from(vector - 32) * UNEXPECTED_STUB_SIZE;
            idt[vector].set_handler_addr(VirtAddr::new(stub as u64));
        }
        idt.non_maskable_interrupt
            .set_handler_addr(VirtAddr::from_ptr(isr_ignore as *const ()))
            .set_stack_index(NMI_IST_INDEX);
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
        for &vector in ignored_vectors {
            idt[vector].set_handler_addr(VirtAddr::from_ptr(isr_ignore as *const ()));
        }
    }
    idt
}

/// Requires [`super::gdt::init`]. The first call fixes `ignored_vectors`;
/// these handlers return without acknowledging the interrupt controller.
///
/// # Panics
///
/// Panics if a vector in `ignored_vectors` is a CPU exception vector (< 32).
pub fn init_idt(ignored_vectors: &[u8]) {
    assert!(
        ignored_vectors.iter().all(|&v| v >= 32),
        "vectors below 32 are CPU exceptions"
    );
    idt(ignored_vectors).load();
}

/// # Panics
///
/// Before [`init_idt`], or if a handler is already set.
pub(crate) fn set_external_interrupt_handler(handler: fn(u8) -> bool) {
    let interrupts = INTERRUPTS.get().expect("the IDT is initialized at boot");
    let mut installed = false;
    interrupts.handler.call_once(|| {
        installed = true;
        handler
    });
    assert!(installed, "an interrupt handler is already set");
}

/// The vectors handled since the last call, as a 256-bit set.
pub(crate) fn take_pending() -> [u64; 4] {
    INTERRUPTS.get().map_or([0; 4], |interrupts| {
        core::array::from_fn(|word| interrupts.pending[word].swap(0, Ordering::Relaxed))
    })
}

/// Runs with interrupts disabled, on whatever stack and GS the interrupted
/// context had (see `isr_external`).
#[unsafe(no_mangle)]
extern "C" fn external_interrupt_handler_impl(vector: u64, rip: u64, cs: u64) {
    if let (Some(interrupts), Ok(vector)) = (INTERRUPTS.get(), u8::try_from(vector))
        && interrupts
            .handler
            .get()
            .is_some_and(|handler| handler(vector))
    {
        interrupts.pending[usize::from(vector / 64)]
            .fetch_or(1 << (vector % 64), Ordering::Relaxed);
        return;
    }
    panic!("EXCEPTION: UNEXPECTED INTERRUPT (vector {vector:#x}, RIP {rip:#x}, CS {cs:#x})");
}

#[unsafe(no_mangle)]
extern "C" fn divide_error_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: DIVIDE BY ZERO\n{regs:#x?}");
}

#[unsafe(no_mangle)]
extern "C" fn debug_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: DEBUG\n{regs:#x?}");
}

#[unsafe(no_mangle)]
extern "C" fn breakpoint_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: BREAKPOINT\n{regs:#x?}");
}

#[unsafe(no_mangle)]
extern "C" fn overflow_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: OVERFLOW\n{regs:#x?}");
}

#[unsafe(no_mangle)]
extern "C" fn bound_range_exceeded_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: BOUND RANGE EXCEEDED\n{regs:#x?}");
}

#[unsafe(no_mangle)]
extern "C" fn invalid_opcode_handler_impl(regs: &PtRegs) {
    panic!(
        "EXCEPTION: INVALID OPCODE at RIP {:#x}\n{regs:#x?}",
        regs.rip
    );
}

#[unsafe(no_mangle)]
extern "C" fn device_not_available_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: DEVICE NOT AVAILABLE (FPU/SSE)\n{regs:#x?}");
}

#[unsafe(no_mangle)]
extern "C" fn double_fault_handler_impl(regs: &PtRegs) {
    panic!(
        "EXCEPTION: DOUBLE FAULT (Error Code: {:#x})\n{regs:#x?}",
        regs.orig_rax
    );
}

#[unsafe(no_mangle)]
extern "C" fn stack_segment_fault_handler_impl(regs: &PtRegs) {
    panic!(
        "EXCEPTION: STACK-SEGMENT FAULT (Error Code: {:#x})\n{regs:#x?}",
        regs.orig_rax
    );
}

#[unsafe(no_mangle)]
extern "C" fn general_protection_fault_handler_impl(regs: &PtRegs) {
    panic!(
        "EXCEPTION: GENERAL PROTECTION FAULT (Error Code: {:#x})\n{regs:#x?}",
        regs.orig_rax
    );
}

#[unsafe(no_mangle)]
extern "C" fn x87_floating_point_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: x87 FLOATING-POINT ERROR\n{regs:#x?}");
}

#[unsafe(no_mangle)]
extern "C" fn alignment_check_handler_impl(regs: &PtRegs) {
    panic!(
        "EXCEPTION: ALIGNMENT CHECK (Error Code: {:#x})\n{regs:#x?}",
        regs.orig_rax
    );
}

#[unsafe(no_mangle)]
extern "C" fn simd_floating_point_handler_impl(regs: &PtRegs) {
    panic!("EXCEPTION: SIMD FLOATING-POINT ERROR\n{regs:#x?}");
}
