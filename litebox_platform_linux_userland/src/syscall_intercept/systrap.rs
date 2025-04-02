//! The systrap platform relies on seccomp’s `SECCOMP_RET_TRAP` feature to intercept system calls.

use crate::utils::{ReinterpretSignedExt as _, TruncateExt as _};
use core::arch::global_asm;
use core::ffi::{c_int, c_uint};
use litebox::platform::RawMutPointer as _;
use litebox::platform::trivial_providers::{TransparentConstPtr, TransparentMutPtr};
use litebox_common_linux::SyscallRequest;
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};

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

type SyscallHandler = dyn Fn(SyscallRequest<crate::LinuxUserland>) -> i64 + Send + Sync;
static SYSCALL_HANDLER: spin::Once<Box<SyscallHandler>> = spin::Once::new();

global_asm!(
    "
    .text
    .align  4
    .globl  sigsys_callback
    .type   sigsys_callback,@function
sigsys_callback:
    /* TODO: save float and vector registers (xsave or fxsave) */
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
    push rbp
    mov  rbp, rsp

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
    mov  rsp, rbp
    pop  rbp

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

/*
 * Depending on whether `fsgsbase` instructions are enabled, we can choose
 * between `arch_prctl` or `rdfsbase/wrfsbase` to get/set the fs base.
 */
/// Function pointer to get the current fs base.
static GET_FS_BASE: spin::Once<fn() -> u64> = spin::Once::new();
/// Function pointer to set the fs base.
static SET_FS_BASE: spin::Once<fn(u64)> = spin::Once::new();
/// Litebox's fs base.
///
/// TODO: Currently we assume there is only one thread in the process.
/// Need to change it to per-thread.
static FS_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Certain syscalls with this magic argument are allowed.
/// This is useful for syscall interception where we need to invoke the original syscall.
const SYSCALL_ARG_MAGIC: u64 = u64::from_le_bytes(*b"LITE BOX");

/// Get fs register value via syscall `arch_prctl`.
fn get_fs_base_arch_prctl() -> u64 {
    const ARCH_GET_FS: u64 = 0x1003;
    let mut fs_base = core::mem::MaybeUninit::<u64>::uninit();
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_GET_FS, fs_base.as_mut_ptr()) },
        0
    );
    unsafe { fs_base.assume_init() }
}

/// Set fs register value via syscall `arch_prctl`.
fn set_fs_base_arch_prctl(fs_base: u64) {
    const ARCH_SET_FS: u64 = 0x1002;
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_FS, fs_base) },
        0
    );
}

/// Get fs register value via `rdfsbase` instruction.
fn get_fs_base_rdfsbase() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "rdfsbase {}",
            out(reg) ret,
            options(nostack, nomem)
        );
    }
    ret
}

/// Set fs register value via `wrfsbase` instruction.
fn set_fs_base_wrfsbase(fs_base: u64) {
    unsafe {
        core::arch::asm!(
            "wrfsbase {}",
            in(reg) fs_base,
            options(nostack, nomem)
        );
    }
}

#[allow(clippy::too_many_lines)]
#[unsafe(no_mangle)]
unsafe extern "C" fn syscall_dispatcher(syscall_number: i64, args: *const usize) -> i64 {
    // Litebox and the loaded program have different fs bases. Save and restore fs base
    // whenever switching between them.
    // TODO: we may also need to do in other places where switching world happens,
    // e.g., signal handlers.
    let old_fs_base = {
        let old_fs_base = GET_FS_BASE.get().unwrap()();
        SET_FS_BASE.get().unwrap()(FS_BASE.load(core::sync::atomic::Ordering::Relaxed));
        old_fs_base
    };

    let syscall_args = unsafe { core::slice::from_raw_parts(args, 6) };
    let dispatcher = match syscall_number {
        libc::SYS_read => SyscallRequest::Read {
            fd: syscall_args[0].reinterpret_as_signed().truncate(),
            buf: TransparentMutPtr {
                inner: syscall_args[1] as *mut u8,
            },
            count: syscall_args[2],
        },
        libc::SYS_write => SyscallRequest::Write {
            fd: syscall_args[0].reinterpret_as_signed().truncate(),
            buf: TransparentConstPtr {
                inner: syscall_args[1] as *const u8,
            },
            count: syscall_args[2],
        },
        libc::SYS_close => SyscallRequest::Close {
            fd: syscall_args[0].reinterpret_as_signed().truncate(),
        },
        libc::SYS_fstat => SyscallRequest::Fstat {
            fd: syscall_args[0].reinterpret_as_signed().truncate(),
            buf: TransparentMutPtr {
                inner: syscall_args[1] as *mut litebox_common_linux::FileStat,
            },
        },
        libc::SYS_mmap => SyscallRequest::Mmap {
            addr: syscall_args[0],
            length: syscall_args[1],
            prot: litebox_common_linux::ProtFlags::from_bits_truncate(
                syscall_args[2].reinterpret_as_signed().truncate(),
            ),
            flags: litebox_common_linux::MapFlags::from_bits_truncate(
                syscall_args[3].reinterpret_as_signed().truncate(),
            ),
            fd: syscall_args[4].reinterpret_as_signed().truncate(),
            offset: syscall_args[5],
        },
        libc::SYS_pread64 => SyscallRequest::Pread64 {
            fd: syscall_args[0].reinterpret_as_signed().truncate(),
            buf: TransparentMutPtr {
                inner: syscall_args[1] as *mut u8,
            },
            count: syscall_args[2],
            offset: syscall_args[3],
        },
        libc::SYS_readv => SyscallRequest::Readv {
            fd: syscall_args[0].reinterpret_as_signed().truncate(),
            iovec: TransparentConstPtr {
                inner: syscall_args[1]
                    as *const litebox_common_linux::IoReadVec<TransparentMutPtr<u8>>,
            },
            iovcnt: syscall_args[2],
        },
        libc::SYS_writev => SyscallRequest::Writev {
            fd: syscall_args[0].reinterpret_as_signed().truncate(),
            iovec: TransparentConstPtr {
                inner: syscall_args[1]
                    as *const litebox_common_linux::IoWriteVec<TransparentConstPtr<u8>>,
            },
            iovcnt: syscall_args[2],
        },
        libc::SYS_access => SyscallRequest::Access {
            pathname: TransparentConstPtr {
                inner: syscall_args[0] as *const i8,
            },
            mode: litebox_common_linux::AccessFlags::from_bits_truncate(
                syscall_args[1].reinterpret_as_signed().truncate(),
            ),
        },
        libc::SYS_fcntl => SyscallRequest::Fcntl {
            fd: syscall_args[0].reinterpret_as_signed().truncate(),
            arg: litebox_common_linux::FcntlArg::from(
                syscall_args[1].reinterpret_as_signed().truncate(),
                syscall_args[2],
            ),
        },
        libc::SYS_getcwd => SyscallRequest::Getcwd {
            buf: TransparentMutPtr {
                inner: syscall_args[0] as *mut u8,
            },
            size: syscall_args[1],
        },
        libc::SYS_readlink => SyscallRequest::Readlink {
            pathname: TransparentConstPtr {
                inner: syscall_args[0] as *const i8,
            },
            buf: TransparentMutPtr {
                inner: syscall_args[1] as *mut u8,
            },
            bufsiz: syscall_args[2],
        },
        libc::SYS_readlinkat => SyscallRequest::Readlinkat {
            dirfd: syscall_args[0].reinterpret_as_signed().truncate(),
            pathname: TransparentConstPtr {
                inner: syscall_args[1] as *const i8,
            },
            buf: TransparentMutPtr {
                inner: syscall_args[2] as *mut u8,
            },
            bufsiz: syscall_args[3],
        },
        libc::SYS_openat => SyscallRequest::Openat {
            dirfd: syscall_args[0].reinterpret_as_signed().truncate(),
            pathname: TransparentConstPtr {
                inner: syscall_args[1] as *const i8,
            },
            flags: litebox::fs::OFlags::from_bits_truncate(syscall_args[2].truncate()),
            mode: litebox::fs::Mode::from_bits_truncate(syscall_args[3].truncate()),
        },
        libc::SYS_newfstatat => SyscallRequest::Newfstatat {
            dirfd: syscall_args[0].reinterpret_as_signed().truncate(),
            pathname: TransparentConstPtr {
                inner: syscall_args[1] as *const i8,
            },
            buf: TransparentMutPtr {
                inner: syscall_args[2] as *mut litebox_common_linux::FileStat,
            },
            flags: litebox_common_linux::AtFlags::from_bits_truncate(
                syscall_args[3].reinterpret_as_signed().truncate(),
            ),
        },
        libc::SYS_rt_sigaction => {
            let mut ret = 0;
            let signo: i32 = syscall_args[0].reinterpret_as_signed().truncate();
            debug_assert_eq!(signo, libc::SIGSYS);
            let newaction = syscall_args[1] as *const libc::sigaction;
            if newaction.is_null() {
                let oldaction = syscall_args[2] as *mut libc::sigaction;
                if !oldaction.is_null() {
                    // return our registered handler
                    let oldaction = TransparentMutPtr { inner: oldaction };
                    let mut sigset = core::mem::MaybeUninit::uninit();
                    let _ = unsafe { libc::sigemptyset(sigset.as_mut_ptr()) };
                    if unsafe {
                        oldaction.write_at_offset(
                            0,
                            libc::sigaction {
                                sa_sigaction: sigsys_handler as usize,
                                sa_flags: libc::SA_SIGINFO,
                                // SAFETY: Initialized by `libc::sigemptyset`
                                sa_mask: sigset.assume_init(),
                                sa_restorer: None,
                            },
                        )
                    }
                    .is_none()
                    {
                        ret = libc::EFAULT;
                    }
                }
            } else {
                // don't allow changing the SIGSYS handler
                ret = libc::EINVAL;
            }
            SyscallRequest::Ret(i64::from(ret))
        }
        libc::SYS_rt_sigprocmask => {
            // never block SIGSYS
            let mut set = unsafe { *(syscall_args[1] as *const libc::sigset_t) };
            unsafe { libc::sigdelset(&raw mut set, libc::SIGSYS) };
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    syscall_args[0],
                    &raw const set,
                    syscall_args[2],
                    syscall_args[3],
                    SYSCALL_ARG_MAGIC,
                )
            };
            SyscallRequest::Ret(ret)
        }
        _ => todo!(),
    };
    let ret = if let SyscallRequest::Ret(v) = dispatcher {
        v
    } else {
        SYSCALL_HANDLER.get().unwrap()(dispatcher)
    };

    SET_FS_BASE.get().unwrap()(old_fs_base);
    ret
}

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
        // TODO: before we support standard input/output, allow writes
        // to fd <= 2
        (
            libc::SYS_write,
            vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        0,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Le,
                        libc::STDERR_FILENO as u64,
                    )
                    .unwrap(),
                ])
                .unwrap(),
            ],
        ),
        (
            libc::SYS_mmap,
            vec![
                // Allow mmap with MAP_ANONYMOUS (i.e., non-file-backed)
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        3,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq(
                            u64::try_from(nix::sys::mman::MapFlags::MAP_ANONYMOUS.bits()).unwrap(),
                        ),
                        u64::try_from(nix::sys::mman::MapFlags::MAP_ANONYMOUS.bits()).unwrap(),
                    )
                    .unwrap(),
                ])
                .unwrap(),
            ],
        ),
        (libc::SYS_mprotect, vec![]),
        (libc::SYS_munmap, vec![]),
        (libc::SYS_brk, vec![]),
        (
            libc::SYS_rt_sigaction,
            vec![
                // Allow rt_sigaction for non-SIGSYS signals
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        0,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Ne,
                        Signal::SIGSYS as u64,
                    )
                    .unwrap(),
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
                        SYSCALL_ARG_MAGIC,
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
        (libc::SYS_getpid, vec![]),
        (libc::SYS_uname, vec![]),
        (libc::SYS_getuid, vec![]),
        (libc::SYS_getgid, vec![]),
        (libc::SYS_geteuid, vec![]),
        (libc::SYS_getegid, vec![]),
        (libc::SYS_sigaltstack, vec![]),
        (libc::SYS_arch_prctl, vec![]),
        (libc::SYS_gettid, vec![]),
        (libc::SYS_futex, vec![]),
        (libc::SYS_set_tid_address, vec![]),
        (libc::SYS_exit_group, vec![]),
        (libc::SYS_tgkill, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        (libc::SYS_prlimit64, vec![]),
        (libc::SYS_getrandom, vec![]),
        (libc::SYS_rseq, vec![]),
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

/// Save the current thread's fs base to thread local storage.
///
/// TODO: make FS_BASE per-thread.
fn save_current_fs_base() {
    FS_BASE.store(
        GET_FS_BASE.get().unwrap()(),
        core::sync::atomic::Ordering::Relaxed,
    );
}

fn init_fs_base() {
    // from asm/hwcap2.h
    const HWCAP2_FSGSBASE: u64 = 1 << 1;
    if unsafe { libc::getauxval(libc::AT_HWCAP2) } & HWCAP2_FSGSBASE != 0 {
        GET_FS_BASE.call_once(|| get_fs_base_rdfsbase);
        SET_FS_BASE.call_once(|| set_fs_base_wrfsbase);
    } else {
        GET_FS_BASE.call_once(|| get_fs_base_arch_prctl);
        SET_FS_BASE.call_once(|| set_fs_base_arch_prctl);
    }

    save_current_fs_base();
}

/// Initialize the syscall interception mechanism.
///
/// This function sets up the syscall handler and registers seccomp
/// filters and the SIGSYS signal handler.
pub(crate) fn init_sys_intercept(
    handler: impl Fn(SyscallRequest<crate::LinuxUserland>) -> i64 + Send + Sync + 'static,
) {
    SYSCALL_HANDLER.call_once(|| Box::new(handler));

    register_sigsys_handler();

    // Cargo unit test does not forward signals to tests.
    // Use integration tests to test it.
    #[cfg(not(test))]
    register_seccomp_filter();

    init_fs_base();
}
