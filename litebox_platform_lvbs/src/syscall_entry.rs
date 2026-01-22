use crate::host::per_cpu_variables::with_per_cpu_variables;
use core::arch::naked_asm;
use litebox_common_linux::PtRegs;
use x86_64::{
    VirtAddr,
    registers::{
        model_specific::{Efer, EferFlags, LStar, SFMask, Star},
        rflags::RFlags,
    },
};

pub(crate) static SHIM: spin::Once<
    &'static (dyn litebox::shim::EnterShim<ExecutionContext = PtRegs> + Send + Sync),
> = spin::Once::new();

#[unsafe(naked)]
unsafe extern "C" fn syscall_entry_wrapper() {
    naked_asm!("jmp syscall_callback");
}

/// This function enables 64-bit syscall extensions and sets up the necessary MSRs.
/// It must be called for each core.
/// # Panics
/// Panics if GDT is not initialized for the current core.
#[cfg(target_arch = "x86_64")]
pub(crate) fn init(
    shim: &'static (dyn litebox::shim::EnterShim<ExecutionContext = PtRegs> + Send + Sync),
) {
    SHIM.call_once(|| shim);

    // enable 64-bit syscall/sysret
    let mut efer = Efer::read();
    efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
    unsafe { Efer::write(efer) };

    let syscall_entry_addr = syscall_entry_wrapper as *const () as u64;
    LStar::write(VirtAddr::new(syscall_entry_addr));

    let rflags = RFlags::INTERRUPT_FLAG;
    SFMask::write(rflags);

    // configure STAR MSR for CS/SS selectors
    let (kernel_cs, user_cs, _) = with_per_cpu_variables(|per_cpu_variables| {
        per_cpu_variables
            .get_segment_selectors()
            .expect("GDT not initialized for the current core")
    });
    unsafe { Star::write_raw(user_cs, kernel_cs) };
}

#[cfg(target_arch = "x86")]
pub(crate) fn init(_syscall_handler: SyscallHandler) {
    todo!("we don't support 32-bit mode syscalls for now");
    // AMD and Intel CPUs have different syscall mechanisms in 32-bit mode.
}
