//! The systrap platform relies on seccomp’s `SECCOMP_RET_TRAP` feature to intercept system calls.

use core::ffi::{c_int, c_uint};

use litebox::utils::ReinterpretSignedExt as _;

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

/// Certain syscalls with this magic argument are allowed.
/// This is useful for syscall interception where we need to invoke the original syscall.
pub(crate) const SYSCALL_ARG_MAGIC: usize = usize::from_le_bytes(*b"LITE BOX");
pub(crate) const MMAP_FLAG_MAGIC: u32 = 1 << 31;

/// Signal handler for SIGSYS.
///
/// Note: only async-signal-safe functions should be used in this handler.
/// See full list at <https://www.man7.org/linux/man-pages/man7/signal-safety.7.html>
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
        *rip = i64::try_from(crate::syscall_callback as usize).unwrap();
    }
}

fn register_sigsys_handler() {
    // TODO: reimplement signal trampoline so that we can use raw syscalls.
    // See https://codebrowser.dev/glibc/glibc/sysdeps/unix/sysv/linux/x86_64/libc_sigaction.c.html#70
    // for reference.
    let mut sig_mask = core::mem::MaybeUninit::<libc::sigset_t>::uninit();
    unsafe { libc::sigemptyset(sig_mask.as_mut_ptr()) };
    let sig_action = libc::sigaction {
        sa_sigaction: sigsys_handler as usize,
        sa_flags: litebox_common_linux::SaFlags::SIGINFO
            .bits()
            .reinterpret_as_signed(),
        // SAFETY: Initialized by `libc::sigemptyset`
        sa_mask: unsafe { sig_mask.assume_init() },
        sa_restorer: None,
    };

    let ret = unsafe { libc::sigaction(libc::SIGSYS, &raw const sig_action, std::ptr::null_mut()) };
    assert_eq!(ret, 0, "Failed to register SIGSYS handler: {ret}");
}

#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
fn register_seccomp_filter() {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule,
    };

    // allow list
    // TODO: remove syscalls once they are implemented in the shim
    let rules = vec![
        (
            libc::SYS_read,
            vec![
                // A backdoor to allow invoking read for devices.
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        3,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::Eq,
                        SYSCALL_ARG_MAGIC as u64,
                    )
                    .unwrap(),
                ])
                .unwrap(),
            ],
        ),
        (
            libc::SYS_write,
            vec![
                SeccompRule::new(vec![
                    // A backdoor to allow invoking write for devices.
                    SeccompCondition::new(
                        3,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::Eq,
                        SYSCALL_ARG_MAGIC as u64,
                    )
                    .unwrap(),
                ])
                .unwrap(),
            ],
        ),
        (
            libc::SYS_mmap,
            vec![
                // A backdoor to allow invoking mmap.
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        3,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq(u64::from(MMAP_FLAG_MAGIC)),
                        u64::from(MMAP_FLAG_MAGIC),
                    )
                    .unwrap(),
                ])
                .unwrap(),
            ],
        ),
        (
            libc::SYS_mprotect,
            vec![
                // A backdoor to allow invoking mprotect.
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        3,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::Eq,
                        SYSCALL_ARG_MAGIC as u64,
                    )
                    .unwrap(),
                ])
                .unwrap(),
            ],
        ),
        (
            libc::SYS_munmap,
            vec![
                // A backdoor to allow invoking munmap.
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        2,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::Eq,
                        SYSCALL_ARG_MAGIC as u64,
                    )
                    .unwrap(),
                ])
                .unwrap(),
            ],
        ),
        (
            libc::SYS_rt_sigaction,
            vec![
                // Allow rt_sigaction for non-SIGSYS signals
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        0,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Ne,
                        litebox_common_linux::Signal::SIGSYS as u64,
                    )
                    .unwrap(),
                ])
                .unwrap(),
                SeccompRule::new(vec![
                    // The second argument `act` is null, so it does not change the signal handler.
                    SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0).unwrap(),
                ])
                .unwrap(),
            ],
        ),
        (
            // allow rt_sigprocmask that does not block SIGSYS
            libc::SYS_rt_sigprocmask,
            vec![
                SeccompRule::new(vec![
                    // A backdoor to allow invoking rt_sigprocmask.
                    // A malicious program can use this to block SIGSYS. However, it only
                    // causes the program to crash when any syscall is invoked.
                    SeccompCondition::new(
                        4,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::Eq,
                        SYSCALL_ARG_MAGIC as u64,
                    )
                    .unwrap(),
                ])
                .unwrap(),
                SeccompRule::new(vec![
                    // The second argument `set` is null, so it does not change the block set.
                    // Unfortunately, seccomp does not allow to inspect memory so we cannot set
                    // more precise condition.
                    SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0).unwrap(),
                ])
                .unwrap(),
            ],
        ),
        (libc::SYS_rt_sigreturn, vec![]),
        (libc::SYS_sched_yield, vec![]),
        (
            libc::SYS_mremap,
            vec![
                // A backdoor to allow invoking mremap.
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        5,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::Eq,
                        SYSCALL_ARG_MAGIC as u64,
                    )
                    .unwrap(),
                ])
                .unwrap(),
            ],
        ),
        (libc::SYS_getpid, vec![]),
        (libc::SYS_getuid, vec![]),
        (libc::SYS_getgid, vec![]),
        (libc::SYS_geteuid, vec![]),
        (libc::SYS_getegid, vec![]),
        (libc::SYS_capget, vec![]),
        (libc::SYS_sigaltstack, vec![]),
        (
            libc::SYS_arch_prctl,
            vec![
                // A backdoor to allow invoking arch_prctl.
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        2,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::Eq,
                        SYSCALL_ARG_MAGIC as u64,
                    )
                    .unwrap(),
                ])
                .unwrap(),
            ],
        ),
        (libc::SYS_futex, vec![]),
        (
            libc::SYS_exit,
            vec![
                // A backdoor to allow invoking exit.
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        1,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::Eq,
                        SYSCALL_ARG_MAGIC as u64,
                    )
                    .unwrap(),
                ])
                .unwrap(),
            ],
        ),
        (
            libc::SYS_exit_group,
            vec![
                // A backdoor to allow invoking exit_group.
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        1,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::Eq,
                        SYSCALL_ARG_MAGIC as u64,
                    )
                    .unwrap(),
                ])
                .unwrap(),
            ],
        ),
        (libc::SYS_tgkill, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        (libc::SYS_prlimit64, vec![]),
        (
            libc::SYS_clone3,
            vec![
                // A backdoor to allow invoking clone3.
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        2,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::Eq,
                        SYSCALL_ARG_MAGIC as u64,
                    )
                    .unwrap(),
                ])
                .unwrap(),
            ],
        ),
    ];
    let rule_map: std::collections::BTreeMap<i64, Vec<SeccompRule>> = rules.into_iter().collect();

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

/// Initialize the syscall interception mechanism.
///
/// This function sets up the syscall handler and registers seccomp
/// filters and the SIGSYS signal handler.
pub(crate) fn init_sys_intercept() {
    register_sigsys_handler();

    // Cargo unit test does not forward signals to tests.
    // Use integration tests to test it.
    #[cfg(not(test))]
    register_seccomp_filter();
}
