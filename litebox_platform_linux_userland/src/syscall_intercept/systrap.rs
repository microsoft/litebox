//! The systrap platform relies on seccomp’s `SECCOMP_RET_TRAP` feature to intercept system calls.

use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use std::os::raw::{c_int, c_uint};
use std::{arch::global_asm, sync::OnceLock};

// Define a custom structure to reinterpret siginfo_t
#[repr(C)]
struct SyscallSiginfo {
    signo: c_int,
    errno: c_int,
    code: c_int,
    call_addr: *mut libc::c_void,
    syscall: c_int,
    arch: c_uint,
}

type SyscallHandler = dyn Fn(i64, &[usize]) -> i64 + Send + Sync;
static SYSCALL_HANDLER: OnceLock<Box<SyscallHandler>> = OnceLock::new();

global_asm!(
    "
    .text
    .align  4
    .globl  sigsys_callback
    .type   sigsys_callback,@function
sigsys_callback:
    /* TODO: save floating point registers if needed */
    /* Save caller-saved registers */
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    pushf

    /* Save the original stack pointer */
    mov r11, rsp

    /* Align the stack to 16 bytes */
    and rsp, -16

    /* Reserve space on the stack for syscall arguments */
    sub rsp, 48

    /* Save syscall arguments (rdi, rsi, rdx, r10, r8, r9) into the reserved space */
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], r10
    mov [rsp + 32], r8
    mov [rsp + 40], r9

    /* Pass the syscall number to the syscall dispatcher */
    mov rdi, rax
    /* Pass the pointer to the syscall arguments to syscall_dispatcher */
    mov rsi, rsp

    /* Call syscall_dispatcher */
    call syscall_dispatcher

    /* Restore the original stack pointer */
    mov rsp, r11

    /* Restore caller-saved registers */
    popf
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx

    /* Return to the caller */
    ret
"
);
unsafe extern "C" {
    fn sigsys_callback() -> i64;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn syscall_dispatcher(syscall_number: i64, args: *const usize) -> i64 {
    let syscall_args = unsafe { std::slice::from_raw_parts(args, 6) };
    SYSCALL_HANDLER.get().unwrap()(syscall_number, syscall_args)
}

extern "C" fn sigsys_handler(sig: c_int, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
    unsafe {
        assert!(sig == libc::SIGSYS);
        let custom_info = &*info.cast::<SyscallSiginfo>();
        let addr = custom_info.call_addr;

        // Ensure the address is valid
        if addr.is_null() {
            std::process::abort();
        }

        // Get the stack pointer (RSP) from the context
        let ucontext = &mut *(context.cast::<libc::ucontext_t>());
        let stack_pointer = &mut ucontext.uc_mcontext.gregs[libc::REG_RSP as usize];
        // push the return address onto the stack
        *stack_pointer -= 8;
        *(*stack_pointer as *mut usize) = addr as usize;

        // TODO: hotpatch the syscall instruction to jump to the `sigsys_callback`
        // to avoid traps again.
        let rip = &mut ucontext.uc_mcontext.gregs[libc::REG_RIP as usize];
        // Set the instruction pointer to the syscall dispatcher
        *rip = i64::try_from(sigsys_callback as usize).unwrap();
    }
}

fn register_sigsys_handler() {
    let sig_action = SigAction::new(
        SigHandler::SigAction(sigsys_handler),
        SaFlags::SA_SIGINFO,
        SigSet::empty(),
    );

    unsafe {
        signal::sigaction(Signal::SIGSYS, &sig_action).expect("Failed to register SIGSYS handler");
    }
}

#[cfg(not(test))]
fn register_seccomp_filter() {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};

    let rule_map = std::collections::BTreeMap::<i64, Vec<SeccompRule>>::new();

    // TODO: switch to allow list and implement necessary syscalls
    let filter = SeccompFilter::new(
        rule_map,
        SeccompAction::Allow,
        SeccompAction::Trap,
        seccompiler::TargetArch::x86_64,
    )
    .unwrap();
    // TODO: bpf program can be compiled offline
    let bpf_prog: BpfProgram = filter.try_into().unwrap();

    seccompiler::apply_filter(&bpf_prog).unwrap();
}

/// Initialize the syscall interception mechanism.
///
/// This function sets up the syscall handler and registers seccomp
/// filters and the SIGSYS signal handler.
pub(crate) fn init_sys_intercept(handler: impl Fn(i64, &[usize]) -> i64 + Send + Sync + 'static) {
    #[allow(
        clippy::match_wild_err_arm,
        reason = "Debug is not implemented for the type"
    )]
    match SYSCALL_HANDLER.set(Box::new(handler)) {
        Ok(()) => {}
        Err(_) => {
            panic!("Syscall handler already set");
        }
    }

    register_sigsys_handler();

    // Cargo unit test does not forward signals to tests.
    // Use integration tests to test it.
    #[cfg(not(test))]
    register_seccomp_filter();
}
