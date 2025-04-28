//! Interrupt Descriptor Table (IDT)

use spin::Once;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
// use lazy_static::lazy_static;

const DOUBLE_FAULT_IST_INDEX: u16 = 0;

// lazy_static! {
//     static ref IDT: InterruptDescriptorTable = {
//         let mut idt = InterruptDescriptorTable::new();
//         idt.divide_error.set_handler_fn(divide_error_handler);
//         idt.breakpoint.set_handler_fn(breakpoint_handler);
//         unsafe {
//             idt.double_fault
//                 .set_handler_fn(double_fault_handler)
//                 .set_stack_index(DOUBLE_FAULT_IST_INDEX);
//         }
//         idt.page_fault.set_handler_fn(page_fault_handler);
//         idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
//         idt.general_protection_fault
//             .set_handler_fn(general_protection_fault_handler);

//         idt
//     };
// }

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
        idt
    })
}

/// Initialize IDT (for a core)
pub fn init_idt() {
    // IDT.load();
    idt().load();
}

extern "x86-interrupt" fn divide_error_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DIVIDE BY ZERO\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
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

    panic!(
        "EXCEPTION: PAGE FAULT\nAccessed Address: {:?}\nError Code: {:?}\n{:#?}",
        Cr2::read(),
        error_code,
        stack_frame
    );
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    use x86_64::registers::control::Cr2;

    panic!(
        "EXCEPTION: INVALID OPCODE\nAccessed Address: {:?}\n{:#?}",
        Cr2::read(),
        stack_frame
    );
}
