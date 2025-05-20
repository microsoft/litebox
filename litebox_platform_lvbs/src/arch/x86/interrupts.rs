//! Interrupt Descriptor Table (IDT)

use crate::{mshv::HYPERVISOR_CALLBACK_VECTOR, serial_println};
use core::ops::IndexMut;
use spin::Once;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

const DOUBLE_FAULT_IST_INDEX: u16 = 0;

fn idt() -> &'static InterruptDescriptorTable {
    static IDT_ONCE: Once<InterruptDescriptorTable> = Once::new();
    IDT_ONCE.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();
        idt.divide_error.set_handler_fn(divide_error_handler);
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(DOUBLE_FAULT_IST_INDEX);
        }
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt.general_protection_fault
            .set_handler_fn(general_protection_fault_handler);

        idt.index_mut(HYPERVISOR_CALLBACK_VECTOR)
            .set_handler_fn(hyperv_sint_handler);

        idt
    })
}

/// Initialize IDT (for a core)
pub fn init_idt() {
    idt().load();
}

extern "x86-interrupt" fn divide_error_handler(stack_frame: InterruptStackFrame) {
    serial_println!("EXCEPTION: DIVIDE BY ZERO\n{:#?}", stack_frame);
    #[cfg(debug_assertions)]
    panic!("Divide by zero");
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    serial_println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
    #[cfg(debug_assertions)]
    panic!("Breakpoint");
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    serial_println!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
    panic!("Double fault")
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    panic!("EXCEPTION: GENERAL PROTECTION FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    serial_println!(
        "EXCEPTION: PAGE FAULT\nAccessed Address: {:?}\nError Code: {:?}\n{:#?}",
        Cr2::read(),
        error_code,
        stack_frame
    );
    #[cfg(debug_assertions)]
    panic!("Page fault");
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    use x86_64::registers::control::Cr2;

    serial_println!(
        "EXCEPTION: INVALID OPCODE\nAccessed Address: {:?}\n{:#?}",
        Cr2::read(),
        stack_frame
    );
    #[cfg(debug_assertions)]
    panic!("Invalid opcode");
}

extern "x86-interrupt" fn hyperv_sint_handler(_stack_frame: InterruptStackFrame) {
    // Hyper-V invokes this handler when a syntethic interrupt occurs.
    // Instead of implementing this handler, we let it return to the VTL switch loop
    // (i.e., the current RIP) immediately and handle synthethic interrupts there.
}
