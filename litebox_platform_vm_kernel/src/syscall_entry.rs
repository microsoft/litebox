// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::per_cpu::with_per_cpu_variables;
use x86_64::{
    VirtAddr,
    registers::{
        model_specific::{Efer, EferFlags, LStar, SFMask, Star},
        rflags::RFlags,
    },
};

unsafe extern "C" {
    /// The `syscall` entry point, a label in `run_thread_arch`.
    fn syscall_callback();
}

/// Requires the current core's GDT before enabling user syscalls.
///
/// # Panics
///
/// Panics if GDT is not initialized for the current core.
pub(crate) fn init() {
    let mut efer = Efer::read();
    efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
    // Safety: enables `syscall`; LSTAR, SFMASK and STAR are set below before
    // any user code runs.
    unsafe { Efer::write(efer) };

    let syscall_entry_addr = syscall_callback as *const () as u64;
    LStar::write(VirtAddr::new(syscall_entry_addr));

    // Kernel entry requires IRQs and single-stepping off, forward string
    // operations, SMAP enforced, and no inherited task/I/O privileges.
    let rflags = RFlags::INTERRUPT_FLAG
        | RFlags::DIRECTION_FLAG
        | RFlags::ALIGNMENT_CHECK
        | RFlags::TRAP_FLAG
        | RFlags::NESTED_TASK
        | RFlags::IOPL_LOW
        | RFlags::IOPL_HIGH;
    SFMask::write(rflags);

    let selectors = with_per_cpu_variables(crate::per_cpu::PerCpuVariables::segment_selectors)
        .expect("GDT not initialized for the current core");
    Star::write(
        selectors.user_code,
        selectors.user_data,
        selectors.kernel_code,
        selectors.kernel_data,
    )
    .expect("the GDT layout does not fit SYSCALL/SYSRET");
}
