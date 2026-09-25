// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LVBS interrupt composition. NMI and MCE remain delegated to VTL0, as before.

use super::timer;
use crate::{
    arch::{apic::SPURIOUS_VECTOR, interrupts::exception_idt},
    mshv::HYPERVISOR_CALLBACK_VECTOR,
};
use core::ops::IndexMut;
use litebox_common_linux::PtRegs;
use spin::Once;
use x86_64::{VirtAddr, structures::idt::InterruptDescriptorTable};

core::arch::global_asm!(
    include_str!("../../arch/x86/interrupts_macros.S"),
    include_str!("interrupts.S"),
    stimer_vector = const timer::STIMER_VECTOR,
);

unsafe extern "C" {
    fn isr_hyperv_sint();
    fn isr_stimer();
    fn isr_spurious();
}

fn idt() -> &'static InterruptDescriptorTable {
    static IDT: Once<InterruptDescriptorTable> = Once::new();
    IDT.call_once(|| {
        let mut idt = exception_idt();
        // SAFETY: the assembly entries preserve the existing interrupt ABI and
        // return with IRETQ. The STIMER entry uses the same vector constant as
        // its IDT slot and the hardware configuration.
        unsafe {
            idt.index_mut(HYPERVISOR_CALLBACK_VECTOR)
                .set_handler_addr(VirtAddr::from_ptr(isr_hyperv_sint as *const ()));
            idt.index_mut(timer::STIMER_VECTOR)
                .set_handler_addr(VirtAddr::from_ptr(isr_stimer as *const ()));
            idt.index_mut(SPURIOUS_VECTOR)
                .set_handler_addr(VirtAddr::from_ptr(isr_spurious as *const ()));
        }
        idt
    })
}

/// Load the LVBS-composed IDT on the current CPU before enabling interrupts.
pub fn init_idt() {
    idt().load();
}

/// Kernel-mode STIMER safety net. User-mode interrupts go through the shared
/// exception callback and the runner-selected ExecutionTimer instead.
#[unsafe(no_mangle)]
extern "C" fn stimer_handler_impl(_regs: &PtRegs) {
    timer::on_kernel_interrupt();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_entries_are_added_without_changing_cpu_exceptions() {
        let base = exception_idt();
        let composed = idt();
        assert_eq!(
            composed.page_fault.handler_addr(),
            base.page_fault.handler_addr()
        );
        assert_eq!(
            composed.double_fault.handler_addr(),
            base.double_fault.handler_addr()
        );
        assert_eq!(
            composed.general_protection_fault.handler_addr(),
            base.general_protection_fault.handler_addr()
        );
        for (vector, handler) in [
            (HYPERVISOR_CALLBACK_VECTOR, isr_hyperv_sint as *const ()),
            (timer::STIMER_VECTOR, isr_stimer as *const ()),
            (SPURIOUS_VECTOR, isr_spurious as *const ()),
        ] {
            assert_eq!(base[vector].handler_addr(), VirtAddr::zero());
            assert_eq!(composed[vector].handler_addr(), VirtAddr::from_ptr(handler));
        }
    }
}
