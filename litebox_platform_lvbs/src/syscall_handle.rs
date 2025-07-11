use crate::arch::instrs::{rdmsr, wrmsr};
use core::arch::naked_asm;

const MSR_EFER: u32 = 0xc000_0080;
const MSR_STAR: u32 = 0xc000_0081;
const MSR_LSTAR: u32 = 0xc000_0082;

// unsafe extern "C" fn syscall_dispatcher_wrapper() {
//     todo!("System call is captured. Handle it!!");
// }

// assume op-tee syscall
#[allow(clippy::too_many_arguments)]
fn handle_syscall(
    _arg0: u64,
    _arg1: u64,
    _arg2: u64,
    _arg3: u64,
    _arg4: u64,
    _arg5: u64,
    _arg6: u64,
    _arg7: u64,
    sysnr: u64,
) {
    todo!("syscall {} invoked!", sysnr);
}

#[unsafe(naked)]
unsafe extern "C" fn syscall_dispatcher_wrapper() {
    naked_asm!(
        "push rax",
        "push r13",
        "push r12",
        "push r9",
        "push r8",
        "push r10",
        "push rdx",
        "push rsi",
        "push rdi",
        "call {handle_syscall}",
        handle_syscall = sym handle_syscall,
    );
}

/// Initialize the syscall handler.
///
/// This function enables 64-bit syscall extensions and sets up the necessary MSRs.
/// It must be called for each core.
/// Note that this function only covers syscall/sysret (64-bit mode).
/// It does not support other 32-bit mode syscalls like sysenter/sysexit and int 0x80.
#[cfg(target_arch = "x86_64")]
pub fn init() {
    // TODO: AMD and Intel use different MSRs for syscall. make the below code (only for Intel for now)
    // deal with this difference.
    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | 0x101);
    let handler_addr = syscall_dispatcher_wrapper as *const () as u64;
    wrmsr(MSR_LSTAR, handler_addr);
    wrmsr(MSR_STAR, 0x230008 << 32);
}

#[cfg(target_arch = "x86")]
pub fn init() {
    todo!("we don't support 32-bit mode syscalls for now");
}
