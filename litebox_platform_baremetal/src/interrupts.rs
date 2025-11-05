//! Interrupt handling for the baremetal platform
//! Sets up IDT (Interrupt Descriptor Table) and basic exception handlers

use spin::Once;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

static IDT: Once<InterruptDescriptorTable> = Once::new();

/// Initialize the Interrupt Descriptor Table
pub fn init() {
    IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();

        // Exception handlers
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.double_fault.set_handler_fn(double_fault_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.general_protection_fault
            .set_handler_fn(general_protection_fault_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt.segment_not_present
            .set_handler_fn(segment_not_present_handler);

        idt
    });

    IDT.get().unwrap().load();
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    crate::serial::write_str("EXCEPTION: BREAKPOINT\n");
    crate::serial::write_str(&alloc::format!("{:#?}\n", stack_frame));
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    crate::serial::write_str("EXCEPTION: DOUBLE FAULT\n");
    crate::serial::write_str(&alloc::format!("Error Code: {}\n", error_code));
    crate::serial::write_str(&alloc::format!("{:#?}\n", stack_frame));

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    crate::serial::write_str("EXCEPTION: PAGE FAULT\n");
    crate::serial::write_str(&alloc::format!("Accessed Address: {:?}\n", Cr2::read()));
    crate::serial::write_str(&alloc::format!("Error Code: {:?}\n", error_code));
    crate::serial::write_str(&alloc::format!("{:#?}\n", stack_frame));

    // For now, just halt - a real implementation would handle this
    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    crate::serial::write_str("EXCEPTION: GENERAL PROTECTION FAULT\n");
    crate::serial::write_str(&alloc::format!("Error Code: {}\n", error_code));
    crate::serial::write_str(&alloc::format!("{:#?}\n", stack_frame));

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    crate::serial::write_str("EXCEPTION: INVALID OPCODE\n");
    crate::serial::write_str(&alloc::format!("{:#?}\n", stack_frame));

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn segment_not_present_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    crate::serial::write_str("EXCEPTION: SEGMENT NOT PRESENT\n");
    crate::serial::write_str(&alloc::format!("Error Code: {}\n", error_code));
    crate::serial::write_str(&alloc::format!("{:#?}\n", stack_frame));

    loop {
        x86_64::instructions::hlt();
    }
}
