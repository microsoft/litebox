use crossbeam::channel::Sender;
use litebox_common_linux::errno::Errno;
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use std::os::raw::{c_int, c_uint};
use std::{arch::global_asm, collections::BTreeMap, sync::OnceLock};

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};

// Define a custom structure to reinterpret siginfo_t
#[repr(C)]
struct CustomSiginfo {
    si_signo: c_int,
    si_errno: c_int,
    si_code: c_int,
    si_call_addr: *mut libc::c_void,
    si_syscall: c_int,
    si_arch: c_uint,
}

#[derive(Debug)]
struct SyscallContext {
    syscall_number: i64,
    syscall_args: [usize; 6],
}

static SYS_SENDER: OnceLock<Sender<(SyscallContext, Sender<Result<i64, Errno>>)>> =
    OnceLock::new();

global_asm!(
    "
    .text
    .align  4
    .globl  sigsys_callback
    .type   sigsys_callback,@function
sigsys_callback:
    /* Save the original stack pointer */
    mov r11, rsp

    /* Align the stack to 16 bytes */
    and rsp, -16

    /* Reserve space on the stack for syscall arguments */
    /* note ensure stack is 16-byte aligned by taking into account the following `push` */
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

    /* Save caller-saved registers */
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11

    /* Call syscall_dispatcher */
    call syscall_dispatcher

    /* Restore caller-saved registers */
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx

    /* Restore the original stack pointer */
    add rsp, 48
    mov rsp, r11

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
    unsafe { request_syscall(syscall_number, syscall_args.try_into().unwrap())
        .unwrap_or_else(|e| e.as_neg() as i64) }
}

unsafe fn request_syscall(syscall_number: i64, args: [usize; 6]) -> Result<i64, Errno> {
    let s = SYS_SENDER.get().unwrap();
    let (resp_tx, resp_rx) = crossbeam::channel::bounded(1);
    s.send((
        SyscallContext {
            syscall_number,
            syscall_args: args,
        },
        resp_tx,
    ))
    .unwrap();
    resp_rx.recv().unwrap()
}

pub(crate) unsafe fn request_mmap(
    addr: usize,
    len: usize,
    prot: nix::sys::mman::ProtFlags,
    flags: nix::sys::mman::MapFlags,
    fd: i32,
    offset: usize,
) -> Result<i64, Errno> {
    let args = [
        addr,
        len,
        prot.bits() as _,
        flags.bits() as _,
        fd as _,
        offset,
    ];
    unsafe { request_syscall(libc::SYS_mmap, args) }
}

extern "C" fn sigsys_handler(sig: c_int, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
    unsafe {
        assert!(sig == libc::SIGSYS);
        // Reinterpret the siginfo_t pointer as a CustomSiginfo pointer
        let custom_info = &*(info as *const CustomSiginfo);
        let syscall_number = custom_info.si_syscall;
        let addr = custom_info.si_call_addr;
        eprintln!("Caught SIGSYS: syscall={} addr={:?}", syscall_number, addr);

        // Ensure the address is valid
        if addr.is_null() {
            eprintln!("Invalid syscall address");
            panic!();
        }

        // Get the instruction pointer (RIP) from the context
        let ucontext = &mut *(context as *mut libc::ucontext_t);
        let rsp = &mut ucontext.uc_mcontext.gregs[libc::REG_RSP as usize];
        // push the return address onto the stack
        *rsp -= 8;
        *(*rsp as *mut usize) = addr as usize;

        let rip = &mut ucontext.uc_mcontext.gregs[libc::REG_RIP as usize];
        // Set the instruction pointer to the syscall dispatcher
        *rip = sigsys_callback as i64;
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
    // allow list
    let rules = vec![
        // (libc::SYS_getpid, vec![])
        (libc::SYS_write, vec![]),
        (libc::SYS_munmap, vec![]),
        (libc::SYS_rt_sigreturn, vec![]),
        (libc::SYS_sigaltstack, vec![]),
        (libc::SYS_futex, vec![]),
        (libc::SYS_exit_group, vec![]),
    ];
    let rule_map: BTreeMap<i64, Vec<SeccompRule>> = rules.into_iter().collect();

    let filter = SeccompFilter::new(
        rule_map,
        SeccompAction::Trap,
        SeccompAction::Allow,
        seccompiler::TargetArch::x86_64,
    )
    .unwrap();
    // TODO: bpf program can be compiled offline
    let bpf_prog: BpfProgram = filter.try_into().unwrap();

    seccompiler::apply_filter(&bpf_prog).unwrap();
}

pub(crate) fn init_sys_intercept() {
    register_sigsys_handler();

    let (s, r) = crossbeam::channel::unbounded();
    SYS_SENDER.set(s).unwrap();

    std::thread::spawn(move || {
        loop {
            match r.recv() {
                Ok((syscall_context, resp_tx)) => {
                    std::println!("Received syscall context: {:?}", syscall_context);
                    let resp: Result<i64, Errno> = match syscall_context.syscall_number {
                        // libc::SYS_getpid => {
                        //     std::println!("getpid syscall intercepted");
                        //     unsafe { libc::getpid() as i64 }
                        // }
                        libc::SYS_mmap => {
                            let args = syscall_context.syscall_args;
                            let res = unsafe {
                                libc::syscall(
                                    syscall_context.syscall_number,
                                    args[0], args[1], args[2], args[3], args[4], args[5],
                                )
                            };
                            // map the result to a Result<isize, Errno>, compared with Errno::MAX
                            match res {
                                -4096..=-1 => todo!(),
                                0.. => Ok(res),
                                _ => panic!("unknown result"),
                            }
                        }
                        _ => {
                            std::println!("Unknown syscall intercepted");
                            panic!();
                        }
                    };
                    resp_tx.send(resp).unwrap();
                }
                Err(_) => {
                    std::println!("Receiver closed");
                    break;
                }
            }
        }
    });

    #[cfg(not(test))]
    register_sigsys_handler();
}
