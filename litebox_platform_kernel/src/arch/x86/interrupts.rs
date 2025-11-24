//! Interrupt Descriptor Table (IDT)

use spin::Once;
use x86_64::structures::idt::{
    HandlerFuncType, HandlerFuncWithErrCode, InterruptDescriptorTable, InterruptStackFrame,
    PageFaultErrorCode,
};

const DOUBLE_FAULT_IST_INDEX: u16 = 0;

fn idt() -> &'static InterruptDescriptorTable {
    static IDT_ONCE: Once<InterruptDescriptorTable> = Once::new();
    IDT_ONCE.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();
        idt.divide_error.set_handler_fn(divide_error_handler);
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        unsafe {
            // Rust no longer allows a function with the custom ABI to have a return type.
            // Unfortunately, the `x86_64` crate has not caught up this change.
            // Below is a workaround mentioned in [link](https://github.com/rust-lang/rust/issues/143072).
            let addr =
                HandlerFuncType::to_virt_addr(double_fault_handler as HandlerFuncWithErrCode);
            idt.double_fault
                .set_handler_addr(addr)
                .set_stack_index(DOUBLE_FAULT_IST_INDEX);
        }
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt.general_protection_fault
            .set_handler_fn(general_protection_fault_handler);
        idt
    })
}

/// Initialize IDT (for a core)
pub fn init_idt() {
    idt().load();
}

// TODO: carefully handle exceptions/interrupts. If an exception or interrupt is due to userspace code,
// we should destroy the corresponding user context rather than halt the entire kernel.

extern "x86-interrupt" fn divide_error_handler(stack_frame: InterruptStackFrame) {
    todo!("EXCEPTION: DIVIDE BY ZERO\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    todo!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(stack_frame: InterruptStackFrame, _error_code: u64) {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    todo!("EXCEPTION: GENERAL PROTECTION FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    todo!(
        "EXCEPTION: PAGE FAULT\nAccessed Address: {:?}\nError Code: {:?}\n{:#?}",
        Cr2::read(),
        error_code,
        stack_frame
    );
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    use x86_64::registers::control::Cr2;

    todo!(
        "EXCEPTION: INVALID OPCODE\nAccessed Address: {:?}\n{:#?}",
        Cr2::read(),
        stack_frame
    );
}
