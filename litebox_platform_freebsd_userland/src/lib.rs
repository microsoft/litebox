// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland FreeBSD.

// Restrict this crate to only work on FreeBSD. For now, we are restricting this to only x86-64
// FreeBSD, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "freebsd", target_arch = "x86_64"))]

use core::sync::atomic::AtomicU32;
use core::time::Duration;
use std::sync::atomic::{AtomicI32, Ordering};

use litebox::fs::OFlags;
use litebox::platform::page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions};
use litebox::platform::{ImmediatelyWokenUp, RawConstPointer as _, UnblockedOrTimedOut};
use litebox::shim::ContinueOperation;
use litebox::utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{ProtFlags, PunchthroughSyscall};

use zerocopy::{FromBytes, IntoBytes};

mod syscall_raw;
use syscall_raw::syscalls;

mod errno;

mod freebsd_types;

extern crate alloc;

/// The userland FreeBSD platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct FreeBSDUserland {
    /// TUN device file descriptor for IP packet I/O (networking).
    tun_socket_fd: std::sync::RwLock<Option<std::os::fd::OwnedFd>>,
    /// Reserved pages that are not available for guest programs to use.
    reserved_pages: Vec<core::ops::Range<usize>>,
}

impl core::fmt::Debug for FreeBSDUserland {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FreeBSDUserland").finish_non_exhaustive()
    }
}

const SELFPROC_MAPS_PATH: &str = "/proc/curproc/map";

impl FreeBSDUserland {
    /// Create a new userland-FreeBSD platform for use in `LiteBox`.
    ///
    /// Takes an optional tun device name (such as `"tun0"` or `"tun1"`) to connect networking
    /// (if not specified, networking is disabled).
    ///
    /// # Panics
    ///
    /// Panics if the tun device could not be successfully opened.
    pub fn new(tun_device_name: Option<&str>) -> &'static Self {
        register_exception_handlers();

        let tun_socket_fd = tun_device_name
            .map(|tun_device_name| {
                // On FreeBSD, TUN devices are opened directly as /dev/tunN.
                let dev_path = alloc::format!("/dev/{tun_device_name}\0");

                let tun_fd = unsafe {
                    syscalls::syscall3(
                        syscalls::Sysno::Open,
                        dev_path.as_ptr() as usize,
                        (litebox::fs::OFlags::RDWR
                            | litebox::fs::OFlags::CLOEXEC
                            | litebox::fs::OFlags::NONBLOCK)
                            .bits() as usize,
                        0,
                    )
                }
                .expect("failed to open tun device");

                // Disable the address-family header so that raw IP packets are
                // read/written without any framing, matching Linux IFF_NO_PI.
                let zero: i32 = 0;
                unsafe {
                    syscalls::syscall3(
                        syscalls::Sysno::Ioctl,
                        tun_fd,
                        usize::try_from(freebsd_types::TUNSIFHEAD).unwrap(),
                        core::ptr::from_ref(&zero) as usize,
                    )
                }
                .expect("failed to set TUNSIFHEAD on tun device");

                // Take ownership so that `drop` will close the fd.
                unsafe {
                    use std::os::fd::FromRawFd as _;
                    std::os::fd::OwnedFd::from_raw_fd(tun_fd.reinterpret_as_signed().truncate())
                }
            })
            .into();

        let platform = Self {
            tun_socket_fd,
            reserved_pages: Self::read_proc_self_maps(),
        };

        Box::leak(Box::new(platform))
    }

    /// Wait until there is data available on the TUN device.
    ///
    /// # Panics
    ///
    /// Panics if the TUN device is not initialized.
    pub fn wait_on_tun(&self, timeout: Option<Duration>) {
        use std::os::fd::AsRawFd as _;
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let mut pfd = libc::pollfd {
            fd: tun_fd.as_ref().unwrap().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let _ = unsafe {
            libc::poll(
                &raw mut pfd,
                1,
                timeout.map_or(-1, |t| {
                    let ms = t.as_millis();
                    i32::try_from(ms).unwrap_or(i32::MAX)
                }),
            )
        };
    }

    fn read_proc_self_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
        let path = SELFPROC_MAPS_PATH;

        let Ok(c_path) = std::ffi::CString::new(path) else {
            return alloc::vec::Vec::new();
        };

        let fd = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::Open,
                c_path.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };

        let Ok(fd) = fd else {
            return alloc::vec::Vec::new();
        };

        let mut buf = [0u8; 8192];
        let mut total_read = 0;

        loop {
            if total_read >= buf.len() {
                break;
            }

            let remaining = buf.len() - total_read;
            let n = unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::Read,
                    fd,
                    buf.as_mut_ptr() as usize + total_read,
                    remaining,
                )
            };

            match n {
                Ok(0) => break,
                Ok(bytes_read) => {
                    if bytes_read <= remaining {
                        total_read += bytes_read;
                    } else {
                        break;
                    }
                }
                Err(_) => {
                    // Close the file descriptor before returning
                    let _ = unsafe { syscalls::syscall1(syscalls::Sysno::Close, fd) };
                    return alloc::vec::Vec::new();
                }
            }
        }

        // Close the file descriptor
        let _ = unsafe { syscalls::syscall1(syscalls::Sysno::Close, fd) };

        if total_read == 0 {
            return alloc::vec::Vec::new();
        }

        let Ok(content) = core::str::from_utf8(&buf[..total_read]) else {
            return alloc::vec::Vec::new();
        };

        let mut reserved_pages = alloc::vec::Vec::new();

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let parts: alloc::vec::Vec<&str> = line.split_whitespace().collect();

            if parts.len() < 2 {
                continue;
            }

            // Parse FreeBSD format: start_addr end_addr ...other_fields...
            let start_str = parts[0].strip_prefix("0x").unwrap_or(parts[0]);
            let end_str = parts[1].strip_prefix("0x").unwrap_or(parts[1]);

            let Ok(start) = usize::from_str_radix(start_str, 16) else {
                continue;
            };

            let Ok(end) = usize::from_str_radix(end_str, 16) else {
                continue;
            };

            if start <= end {
                reserved_pages.push(start..end);
            }
        }

        reserved_pages
    }

    /// Returns parameters about the initial task for the shim.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panicking only on failures of documented FreeBSD contracts"
    )]
    #[expect(
        clippy::similar_names,
        reason = "pid and ppid are standard POSIX terms"
    )]
    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        let mut tid: isize = 0;
        unsafe {
            syscalls::syscall1(syscalls::Sysno::ThrSelf, &raw mut tid as usize)
                .expect("thr_self failed");
        }
        let pid = i32::try_from(tid).expect("tid should fit in i32");
        let ppid =
            unsafe { syscalls::syscall0(syscalls::Sysno::Getppid) }.expect("Failed to get PPID");
        let ppid: i32 = ppid.try_into().expect("ppid should fit in i32");

        litebox_common_linux::TaskParams {
            pid,
            ppid,
            uid: unsafe { syscalls::syscall0(syscalls::Sysno::Getuid) }
                .expect("getuid failed")
                .try_into()
                .unwrap(),
            euid: unsafe { syscalls::syscall0(syscalls::Sysno::Geteuid) }
                .expect("geteuid failed")
                .try_into()
                .unwrap(),
            gid: unsafe { syscalls::syscall0(syscalls::Sysno::Getgid) }
                .expect("getgid failed")
                .try_into()
                .unwrap(),
            egid: unsafe { syscalls::syscall0(syscalls::Sysno::Getegid) }
                .expect("getegid failed")
                .try_into()
                .unwrap(),
        }
    }
}

impl litebox::platform::Provider for FreeBSDUserland {}

// ---------------------------------------------------------------------------
// TLS (`.tbss`) access helpers
//
// On FreeBSD x86_64, the ELF TLS model uses `@tpoff` with `fs` as the
// TLS segment register. This is the same as Linux x86_64.
// At guest-host transitions we swap `fs` and `gs`, so after the swap the
// host TLS base is in the normal segment register.
// ---------------------------------------------------------------------------

/// TLS relocation suffix.
macro_rules! tls_suffix {
    () => {
        "@tpoff"
    };
}

/// Segment register used for TLS in normal host context.
macro_rules! tls_seg {
    () => {
        "fs"
    };
}

/// Segment register where the host TLS base is saved during guest execution.
macro_rules! saved_tls_seg {
    () => {
        "gs"
    };
}

/// Full TLS memory operand for a `.tbss` variable in normal host context.
macro_rules! tls {
    ($var:literal) => {
        concat!(tls_seg!(), ":", $var, tls_suffix!())
    };
}

/// Full TLS memory operand for a `.tbss` variable accessed via the saved
/// segment register (before the fs/gs swap, e.g. from a signal handler).
macro_rules! saved_tls {
    ($var:literal) => {
        concat!(saved_tls_seg!(), ":", $var, tls_suffix!())
    };
}

impl litebox::platform::TimerProvider for FreeBSDUserland {
    type TimerHandle = litebox::platform::trivial_providers::UnsupportedTimerHandle;
    type Signal = litebox_common_linux::signal::Signal;
}

impl litebox::platform::SignalProvider for FreeBSDUserland {
    type Signal = litebox_common_linux::signal::Signal;

    fn take_pending_signals(&self, mut f: impl FnMut(Self::Signal)) {
        // Atomically swap out pending signals and process them.
        let signals = unsafe {
            let mut ret: u32;
            core::arch::asm!(
                concat!("xchg ", tls!("pending_host_signals"), ", {val:e}"),
                val = inout(reg) 0u32 => ret,
                options(nostack),
            );
            ret
        };
        for bit in 0..32u32 {
            if signals & (1 << bit) != 0 {
                // Map bit positions to signals. Currently only SIGINT.
                if bit == 0 {
                    f(litebox_common_linux::signal::Signal::SIGINT);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Thread context structure and shim handlers
// ---------------------------------------------------------------------------

struct ThreadContext<'a> {
    shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &'a mut litebox_common_linux::PtRegs,
}

impl ThreadContext<'_> {
    fn call_shim(
        &mut self,
        f: impl FnOnce(
            &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
            &mut litebox_common_linux::PtRegs,
        ) -> ContinueOperation,
    ) {
        // Clear the interrupt flag before calling the shim.
        unsafe {
            core::arch::asm!(
                concat!("mov BYTE PTR ", tls!("interrupt"), ", 0"),
                options(nostack, preserves_flags)
            );
        }
        let op = f(self.shim, self.ctx);
        match op {
            ContinueOperation::Resume => unsafe { switch_to_guest(self.ctx) },
            ContinueOperation::Terminate => {}
        }
    }
}

unsafe extern "C-unwind" fn init_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.init(ctx));
}

unsafe extern "C-unwind" fn reenter_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.reenter(ctx));
}

#[allow(clippy::cast_sign_loss)]
unsafe extern "C-unwind" fn syscall_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.syscall(ctx));
}

extern "C-unwind" fn exception_handler(
    thread_ctx: &mut ThreadContext,
    trapno: usize,
    error: usize,
    cr2: usize,
) {
    let info = litebox::shim::ExceptionInfo {
        exception: litebox::shim::Exception(trapno.try_into().unwrap()),
        error_code: error.try_into().unwrap(),
        cr2,
        kernel_mode: false,
    };
    thread_ctx.call_shim(|shim, ctx| shim.exception(ctx, &info));
}

extern "C-unwind" fn interrupt_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.interrupt(ctx));
}

// ---------------------------------------------------------------------------
// Guest-host context switching (x86_64)
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    "
    .section .tbss
    .align 8
scratch:
    .quad 0
host_sp:
    .quad 0
host_bp:
    .quad 0
guest_context_top:
    .quad 0
.globl guest_fsbase
guest_fsbase:
    .quad 0
in_guest:
    .byte 0
.globl interrupt
interrupt:
    .byte 0
    .align 4
.globl pending_host_signals
pending_host_signals:
    .long 0
    .align 8
.globl wait_waker_addr
wait_waker_addr:
    .quad 0
    "
);

// Ensure the linker retains the naked functions that define assembly-level
// labels (syscall_callback, exception_callback, interrupt_callback,
// switch_to_guest_start, switch_to_guest_end).
// Without this, `--gc-sections` may discard them in test builds.
#[used]
static _KEEP_ASM_FUNCTIONS: [unsafe extern "C-unwind" fn(
    &mut ThreadContext,
    *mut litebox_common_linux::PtRegs,
    u8,
); 1] = [run_thread_arch];
#[used]
static _KEEP_SWITCH_TO_GUEST: [unsafe extern "C" fn(&litebox_common_linux::PtRegs) -> !; 1] =
    [switch_to_guest];

fn set_guest_fsbase(value: usize) {
    unsafe {
        core::arch::asm! {
            "mov fs:guest_fsbase@tpoff, {}",
            in(reg) value,
            options(nostack, preserves_flags)
        }
    }
}

fn get_guest_fsbase() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm! {
            "mov {}, fs:guest_fsbase@tpoff",
            out(reg) value,
            options(nostack, preserves_flags)
        }
    }
    value
}

/// Runs the guest thread until it terminates.
///
/// This saves all non-volatile register state then switches to the guest
/// context. When the guest makes a syscall, it jumps back into the middle of
/// this routine, at `syscall_callback`. This code then updates the guest
/// context structure, switches back to the host stack, and calls the syscall
/// handler.
///
/// When the guest thread terminates, this function returns after restoring
/// non-volatile register state.
#[unsafe(naked)]
unsafe extern "C-unwind" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut litebox_common_linux::PtRegs,
    reenter: u8,
) {
    core::arch::naked_asm!(
    "
    .cfi_startproc
    // Push all non-volatiles.
    push rbp
    mov rbp, rsp
    .cfi_def_cfa rbp, 16
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rdi // save thread context

    // Save host rsp and rbp and guest context top in TLS.
    mov fs:host_sp@tpoff, rsp
    mov fs:host_bp@tpoff, rbp
    lea r8, [rsi + {GUEST_CONTEXT_SIZE}]
    mov fs:guest_context_top@tpoff, r8

    // Save host fs base in gs base. This will stay set for the lifetime
    // of this call stack.
    rdfsbase r8
    wrgsbase r8

    // Call init_handler or reenter_handler based on reenter flag (in dl).
    test dl, dl
    jnz 1f
    call {init_handler}
    jmp .Ldone
1:
    call {reenter_handler}
    jmp .Ldone

    // This entry point is called from the guest when it issues a syscall
    // instruction.
    //
    // At entry, the register context is the guest context with the
    // return address in rcx. r11 is an available scratch register (it would
    // contain rflags if the syscall instruction had actually been issued).
    .globl syscall_callback
syscall_callback:
    // Clear in_guest flag. This must be the first instruction to match the
    // expectations of `interrupt_signal_handler`.
    mov      BYTE PTR gs:in_guest@tpoff, 0

    // Restore host fs base.
    rdfsbase r11
    mov      gs:guest_fsbase@tpoff, r11
    rdgsbase r11
    wrfsbase r11

    // Switch to the top of the guest context.
    mov     r11, rsp
    mov     rsp, fs:guest_context_top@tpoff

    // TODO: save float and vector registers (xsave or fxsave)
    // Save caller-saved registers
    push    0x2b       // pt_regs->ss = __USER_DS
    push    r11        // pt_regs->sp
    pushfq             // pt_regs->eflags
    push    0x33       // pt_regs->cs = __USER_CS
    push    rcx        // pt_regs->ip
    push    rax        // pt_regs->orig_ax

    push    rdi         // pt_regs->di
    push    rsi         // pt_regs->si
    push    rdx         // pt_regs->dx
    push    rcx         // pt_regs->cx
    push    -38         // pt_regs->ax = ENOSYS
    push    r8          // pt_regs->r8
    push    r9          // pt_regs->r9
    push    r10         // pt_regs->r10
    push    [rsp + 88]  // pt_regs->r11 = rflags
    push    rbx         // pt_regs->bx
    push    rbp         // pt_regs->bp
    push    r12         // pt_regs->r12
    push    r13         // pt_regs->r13
    push    r14         // pt_regs->r14
    push    r15         // pt_regs->r15

    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    // Handle the syscall. This will jump back to the guest but
    // will return if the thread is exiting.
    mov rdi, [rsp] // pass thread_ctx
    call {syscall_handler}
    // This thread is done. Return.
    jmp .Ldone

    .globl exception_callback
exception_callback:
    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    mov rdi, [rsp] // pass thread_ctx
    call {exception_handler}
    jmp .Ldone

    .globl interrupt_callback
interrupt_callback:
    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    mov rdi, [rsp] // pass thread_ctx
    call {interrupt_handler}

.Ldone:

    lea  rsp, [rbp - 5*8]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    .cfi_def_cfa rsp, 8
    ret
    .cfi_endproc
",
    GUEST_CONTEXT_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
    init_handler = sym init_handler,
    reenter_handler = sym reenter_handler,
    syscall_handler = sym syscall_handler,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    );
}

/// Switches to the provided guest context.
///
/// # Safety
/// The context must be valid guest context. This can only be called if
/// `run_thread_arch` is on the stack; after the guest exits, it will return to
/// the interior of `run_thread_arch`.
///
/// Do not call this at a point where the stack needs to be unwound to run
/// destructors.
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    core::arch::naked_asm!(
        ".globl switch_to_guest_start",
        "switch_to_guest_start:",
        // Set `in_guest` now, then check if there is a pending interrupt. If
        // so, jump to the interrupt handler.
        //
        // If an interrupt arrives after the check, then the signal handler will
        // see that the IP is between `switch_to_guest_start` and
        // `switch_to_guest_end` and will set the `interrupt` and jump to
        // `interrupt_callback`.
        "mov BYTE PTR fs:in_guest@tpoff, 1",
        "cmp BYTE PTR fs:interrupt@tpoff, 0",
        "jne interrupt_callback",
        // Restore guest context from ctx.
        "mov rsp, rdi",
        // Switch to the guest fsbase
        "mov rdx, fs:guest_fsbase@tpoff",
        "wrfsbase rdx",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "add rsp, 8",           // skip orig_rax
        "pop gs:scratch@tpoff", // read rip into scratch
        "add rsp, 8",           // skip cs
        "popfq",
        "pop rsp",
        "jmp gs:scratch@tpoff", // jump to the guest
        ".globl switch_to_guest_end",
        "switch_to_guest_end:",
    );
}

unsafe extern "C" {
    // Defined in asm blocks above
    fn syscall_callback() -> isize;
    fn exception_callback();
    fn interrupt_callback();
    fn switch_to_guest_start();
    fn switch_to_guest_end();
}

// ---------------------------------------------------------------------------
// Thread management
// ---------------------------------------------------------------------------

fn run_thread_inner(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &mut litebox_common_linux::PtRegs,
    reenter: bool,
) {
    let ctx_ptr = core::ptr::from_mut(ctx);
    let mut thread_ctx = ThreadContext { shim, ctx };
    ThreadHandle::run_with_handle(|| {
        with_signal_alt_stack(|| unsafe {
            run_thread_arch(&mut thread_ctx, ctx_ptr, u8::from(reenter));
        });
    });
}

fn thread_start(
    init_thread: Box<
        dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
    >,
    mut ctx: litebox_common_linux::PtRegs,
) {
    let shim = init_thread.init();
    run_thread_inner(shim.as_ref(), &mut ctx, false);
}

/// A handle to a platform thread.
#[derive(Clone)]
pub struct ThreadHandle(std::sync::Arc<std::sync::Mutex<Option<libc::pthread_t>>>);

thread_local! {
    static CURRENT_THREAD: std::cell::RefCell<Option<ThreadHandle>> = const { std::cell::RefCell::new(None) };
}

impl ThreadHandle {
    fn run_with_handle<R>(f: impl FnOnce() -> R) -> R {
        let handle = ThreadHandle(std::sync::Arc::new(std::sync::Mutex::new(Some(unsafe {
            libc::pthread_self()
        }))));
        CURRENT_THREAD.with_borrow_mut(|current| {
            assert!(
                current.is_none(),
                "nested run_with_handle calls are not supported"
            );
            *current = Some(handle);
        });
        let _guard = litebox::utils::defer(|| {
            let current = CURRENT_THREAD.take().unwrap();
            *current.0.lock().unwrap() = None;
        });
        f()
    }

    fn current() -> Self {
        CURRENT_THREAD.with_borrow(|thread| {
            thread
                .clone()
                .expect("current_thread called outside of a LiteBox thread")
        })
    }

    fn interrupt(&self) {
        let thread = self.0.lock().unwrap();
        if let Some(&thread) = thread.as_ref() {
            unsafe {
                libc::pthread_kill(thread, INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed));
            }
        }
    }
}

fn block_guest_signals() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGALRM);
        libc::sigaddset(&raw mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
    }
}

/// Spawn a non-guest ("host") thread that automatically blocks guest interrupt
/// signals before running `f`.
pub fn spawn_host_thread<F, T>(f: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        block_guest_signals();
        f()
    })
}

impl litebox::platform::ThreadProvider for FreeBSDUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ThreadHandle;

    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        init_thread: Box<
            dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        let ctx = ctx.clone();
        let _handle = std::thread::Builder::new().spawn(move || thread_start(init_thread, ctx))?;
        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        ThreadHandle::current()
    }

    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        thread.interrupt();
    }

    #[cfg(debug_assertions)]
    fn run_test_thread<R>(f: impl FnOnce() -> R) -> R {
        unsafe {
            core::arch::asm!(
                "rdfsbase {tmp}",
                "wrgsbase {tmp}",
                tmp = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
        ThreadHandle::run_with_handle(f)
    }
}

// ---------------------------------------------------------------------------
// RawMutex (using FreeBSD umtx_op)
// ---------------------------------------------------------------------------

impl litebox::platform::RawMutexProvider for FreeBSDUserland {
    type RawMutex = RawMutex;
}

/// Raw mutex for FreeBSD using `_umtx_op`.
pub struct RawMutex {
    inner: AtomicU32,
}

impl RawMutex {
    const fn new() -> Self {
        Self {
            inner: AtomicU32::new(0),
        }
    }

    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        use core::sync::atomic::Ordering::SeqCst;

        // Immediately wake up if the value is different.
        if self.inner.load(SeqCst) != val {
            return Err(ImmediatelyWokenUp);
        }

        match umtx_op_operation_timeout(
            &self.inner,
            freebsd_types::UmtxOpOperation::UMTX_OP_WAIT_UINT,
            val as usize,
            timeout,
        ) {
            Ok(0) => Ok(UnblockedOrTimedOut::Unblocked),
            Err(e) if e == i32::from(crate::errno::Errno::EINTR) as isize => {
                Ok(UnblockedOrTimedOut::Unblocked)
            }
            Err(e) if e == i32::from(crate::errno::Errno::EAGAIN) as isize => {
                Err(ImmediatelyWokenUp)
            }
            Err(e) if e == i32::from(crate::errno::Errno::ETIMEDOUT) as isize => {
                Ok(UnblockedOrTimedOut::TimedOut)
            }
            Err(e) => {
                panic!("Unexpected errno={e} for UMTX_OP_WAIT")
            }
            _ => unreachable!(),
        }
    }
}

impl litebox::platform::RawMutex for RawMutex {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        assert!(n > 0);
        let n: u32 = n.try_into().unwrap();

        // FreeBSD umtx_op WAKE always returns 0 on success and we cannot
        // determine how many threads were actually woken up.
        match umtx_op_operation_timeout(
            &self.inner,
            freebsd_types::UmtxOpOperation::UMTX_OP_WAKE,
            n as usize,
            None,
        ) {
            Err(_) => 0,
            Ok(_) => n as usize,
        }
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.block_or_maybe_timeout(val, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => unreachable!(),
            Err(ImmediatelyWokenUp) => Err(ImmediatelyWokenUp),
        }
    }

    fn block_or_timeout(
        &self,
        val: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val, Some(timeout))
    }
}

// ---------------------------------------------------------------------------
// IP Interface
// ---------------------------------------------------------------------------

impl litebox::platform::IPInterfaceProvider for FreeBSDUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        use std::os::fd::AsRawFd as _;
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let Some(tun_socket_fd) = tun_fd.as_ref() else {
            unimplemented!("networking without tun is unimplemented")
        };
        match unsafe {
            syscalls::syscall3(
                syscalls::Sysno::Write,
                usize::try_from(tun_socket_fd.as_raw_fd()).unwrap(),
                packet.as_ptr() as usize,
                packet.len(),
            )
        } {
            Ok(n) => {
                if n != packet.len() {
                    unimplemented!("unexpected size {n}")
                }
                Ok(())
            }
            Err(errno) => {
                unimplemented!("unexpected error {errno}")
            }
        }
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        use std::os::fd::AsRawFd as _;
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let Some(tun_socket_fd) = tun_fd.as_ref() else {
            unimplemented!("networking without tun is unimplemented")
        };
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::Read,
                usize::try_from(tun_socket_fd.as_raw_fd()).unwrap(),
                packet.as_mut_ptr() as usize,
                packet.len(),
            )
        }
        .map_err(|errno| match errno {
            #[allow(unreachable_patterns, reason = "EAGAIN == EWOULDBLOCK")]
            crate::errno::Errno::EWOULDBLOCK | crate::errno::Errno::EAGAIN => {
                litebox::platform::ReceiveError::WouldBlock
            }
            _ => unimplemented!("unexpected error {errno}"),
        })
    }
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

impl litebox::platform::TimeProvider for FreeBSDUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        Instant {
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned(),
                t.tv_nsec.reinterpret_as_unsigned().truncate(),
            ),
        }
    }

    fn current_time(&self) -> Self::SystemTime {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        SystemTime {
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned(),
                t.tv_nsec.reinterpret_as_unsigned().truncate(),
            ),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    inner: Duration,
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.inner.checked_sub(earlier.inner)
    }
    fn checked_add(&self, duration: Duration) -> Option<Self> {
        Some(Self {
            inner: self.inner.checked_add(duration)?,
        })
    }
}

pub struct SystemTime {
    inner: Duration,
}

impl litebox::platform::SystemTime for SystemTime {
    const UNIX_EPOCH: Self = SystemTime {
        inner: Duration::ZERO,
    };

    fn duration_since(&self, earlier: &Self) -> Result<Duration, Duration> {
        self.inner
            .checked_sub(earlier.inner)
            .ok_or_else(|| earlier.inner.checked_sub(self.inner).unwrap())
    }
}

// ---------------------------------------------------------------------------
// Punchthrough
// ---------------------------------------------------------------------------

pub struct PunchthroughToken<'a> {
    punchthrough: PunchthroughSyscall<'a, FreeBSDUserland>,
}

impl<'a> litebox::platform::PunchthroughToken for PunchthroughToken<'a> {
    type Punchthrough = PunchthroughSyscall<'a, FreeBSDUserland>;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<
            <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnFailure,
        >,
    > {
        match self.punchthrough {
            PunchthroughSyscall::SetFsBase { addr } => {
                set_guest_fsbase(addr);
                Ok(0)
            }
            PunchthroughSyscall::GetFsBase => Ok(get_guest_fsbase()),
            _ => Err(litebox::platform::PunchthroughError::Unimplemented(
                "PunchthroughToken for FreeBSDUserland",
            )),
        }
    }
}

impl litebox::platform::PunchthroughProvider for FreeBSDUserland {
    type PunchthroughToken<'a> = PunchthroughToken<'a>;
    fn get_punchthrough_token_for<'a>(
        &self,
        punchthrough: <Self::PunchthroughToken<'a> as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'a>> {
        Some(PunchthroughToken { punchthrough })
    }
}

// ---------------------------------------------------------------------------
// Debug log
// ---------------------------------------------------------------------------

impl litebox::platform::DebugLogProvider for FreeBSDUserland {
    fn debug_log_print(&self, msg: &str) {
        let _ = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::Write,
                freebsd_types::STDERR_FILENO as usize,
                msg.as_ptr() as usize,
                msg.len(),
            )
        };
    }
}

// ---------------------------------------------------------------------------
// Raw pointers
// ---------------------------------------------------------------------------

type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;

impl litebox::platform::RawPointerProvider for FreeBSDUserland {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

// ---------------------------------------------------------------------------
// umtx_op helper
// ---------------------------------------------------------------------------

#[expect(
    clippy::similar_names,
    reason = "tv_sec/tv_nsec and pid/ppid are standard POSIX names"
)]
fn umtx_op_operation_timeout(
    obj: &AtomicU32,
    op: freebsd_types::UmtxOpOperation,
    val: usize,
    timeout: Option<Duration>,
) -> Result<usize, isize> {
    let obj_ptr = core::ptr::from_ref(obj) as usize;
    let op: i32 = op as _;
    let timeout_spec = timeout.map(|t| {
        let tv_sec = t.as_secs().cast_signed();
        let tv_nsec = i64::from(t.subsec_nanos());
        libc::timespec { tv_sec, tv_nsec }
    });

    let (uaddr, uaddr2) = if let Some(ref ts) = timeout_spec {
        (
            core::mem::size_of::<libc::timespec>(),
            core::ptr::from_ref(ts) as usize,
        )
    } else {
        (obj_ptr, 0)
    };

    #[expect(
        clippy::cast_sign_loss,
        reason = "umtx op codes are small positive values"
    )]
    let op = op as usize;

    unsafe { syscalls::syscall5(syscalls::Sysno::UmtxOp, obj_ptr, op, val, uaddr, uaddr2) }
        .map_err(|err| i32::from(err) as isize)
}

// ---------------------------------------------------------------------------
// Page management
// ---------------------------------------------------------------------------

fn prot_flags(flags: MemoryRegionPermissions) -> ProtFlags {
    let mut res = ProtFlags::PROT_NONE;
    res.set(
        ProtFlags::PROT_READ,
        flags.contains(MemoryRegionPermissions::READ),
    );
    res.set(
        ProtFlags::PROT_WRITE,
        flags.contains(MemoryRegionPermissions::WRITE),
    );
    res.set(
        ProtFlags::PROT_EXEC,
        flags.contains(MemoryRegionPermissions::EXEC),
    );
    if flags.contains(MemoryRegionPermissions::SHARED) {
        unimplemented!()
    }
    res
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for FreeBSDUserland {
    const TASK_ADDR_MIN: usize = 0x1000;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let map_flags = freebsd_types::MapFlags::MAP_PRIVATE
            | freebsd_types::MapFlags::MAP_ANONYMOUS
            | (match fixed_address_behavior {
                FixedAddressBehavior::Replace => freebsd_types::MapFlags::MAP_FIXED,
                FixedAddressBehavior::NoReplace => {
                    freebsd_types::MapFlags::MAP_FIXED | freebsd_types::MapFlags::MAP_EXCL
                }
                FixedAddressBehavior::Hint => freebsd_types::MapFlags::empty(),
            } | if can_grow_down {
                freebsd_types::MapFlags::MAP_STACK
            } else {
                freebsd_types::MapFlags::empty()
            } | if populate_pages_immediately {
                freebsd_types::MapFlags::MAP_PREFAULT_READ
            } else {
                freebsd_types::MapFlags::empty()
            });

        let ptr = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::Mmap,
                suggested_range.start,
                suggested_range.len(),
                prot_flags(initial_permissions)
                    .bits()
                    .reinterpret_as_unsigned() as usize,
                map_flags.bits().reinterpret_as_unsigned() as usize,
                (-1isize).cast_unsigned(),
                0,
            )
        }
        .expect("mmap failed");

        Ok(UserMutPtr::from_usize(ptr))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let _ = unsafe { syscalls::syscall2(syscalls::Sysno::Munmap, range.start, range.len()) }
            .expect("munmap failed");
        Ok(())
    }

    // remap_pages: FreeBSD lacks mremap(), so we use the default trait
    // implementation which does allocate_pages + memcpy + deallocate_pages.

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::Mprotect,
                range.start,
                range.len(),
                prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
            )
        }
        .expect("mprotect failed");
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        self.reserved_pages.iter()
    }
}

// ---------------------------------------------------------------------------
// VmemPageFaultHandler (dummy - host kernel handles page faults)
// ---------------------------------------------------------------------------

/// Dummy `VmemPageFaultHandler`.
///
/// Page faults are handled transparently by the host FreeBSD kernel.
/// Provided to satisfy trait bounds for `PageManager::handle_page_fault`.
impl litebox::mm::linux::VmemPageFaultHandler for FreeBSDUserland {
    unsafe fn handle_page_fault(
        &self,
        _fault_addr: usize,
        _flags: litebox::mm::linux::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unreachable!("host kernel handles page faults for FreeBSD userland")
    }

    fn access_error(_error_code: u64, _flags: litebox::mm::linux::VmFlags) -> bool {
        unreachable!("host kernel handles page faults for FreeBSD userland")
    }
}

// ---------------------------------------------------------------------------
// Stdio
// ---------------------------------------------------------------------------

impl litebox::platform::StdioProvider for FreeBSDUserland {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        use std::io::Read as _;
        std::io::stdin().read(buf).map_err(|err| {
            if err.kind() == std::io::ErrorKind::BrokenPipe {
                litebox::platform::StdioReadError::Closed
            } else {
                panic!("unhandled error {err}")
            }
        })
    }

    fn write_to(
        &self,
        stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        match unsafe {
            syscalls::syscall3(
                syscalls::Sysno::Write,
                usize::try_from(match stream {
                    litebox::platform::StdioOutStream::Stdout => freebsd_types::STDOUT_FILENO,
                    litebox::platform::StdioOutStream::Stderr => freebsd_types::STDERR_FILENO,
                })
                .unwrap(),
                buf.as_ptr() as usize,
                buf.len(),
            )
        } {
            Ok(n) => Ok(n),
            Err(err) => panic!("unhandled error {err}"),
        }
    }

    fn is_a_tty(&self, stream: litebox::platform::StdioStream) -> bool {
        use litebox::platform::StdioStream;
        use std::io::IsTerminal as _;
        match stream {
            StdioStream::Stdin => std::io::stdin().is_terminal(),
            StdioStream::Stdout => std::io::stdout().is_terminal(),
            StdioStream::Stderr => std::io::stderr().is_terminal(),
        }
    }
}

// ---------------------------------------------------------------------------
// Allocator
// ---------------------------------------------------------------------------

#[global_allocator]
static SLAB_ALLOC: litebox::mm::allocator::SafeZoneAllocator<'static, 28, FreeBSDUserland> =
    litebox::mm::allocator::SafeZoneAllocator::new();

impl litebox::mm::allocator::MemoryProvider for FreeBSDUserland {
    fn alloc(layout: &std::alloc::Layout) -> Option<(usize, usize)> {
        let size = core::cmp::max(
            layout.size().next_power_of_two(),
            core::cmp::max(layout.align(), 0x1000) << 1,
        );
        unsafe {
            syscalls::syscall6(
                syscalls::Sysno::Mmap,
                0,
                size,
                ProtFlags::PROT_READ_WRITE.bits().reinterpret_as_unsigned() as usize,
                ((freebsd_types::MapFlags::MAP_PRIVATE | freebsd_types::MapFlags::MAP_ANON)
                    .bits()
                    .reinterpret_as_unsigned()) as usize,
                usize::MAX,
                0,
            )
        }
        .map(|addr| (addr, size))
        .ok()
    }

    unsafe fn free(_addr: usize) {
        todo!();
    }
}

// ---------------------------------------------------------------------------
// System info
// ---------------------------------------------------------------------------

impl litebox::platform::SystemInfoProvider for FreeBSDUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as *const () as usize
    }

    fn get_vdso_address(&self) -> Option<usize> {
        None
    }
}

// ---------------------------------------------------------------------------
// Thread-local storage
// ---------------------------------------------------------------------------

thread_local! {
    static PLATFORM_TLS: std::cell::Cell<*mut ()> = const { std::cell::Cell::new(core::ptr::null_mut()) };
}

unsafe impl litebox::platform::ThreadLocalStorageProvider for FreeBSDUserland {
    fn get_thread_local_storage() -> *mut () {
        PLATFORM_TLS.get()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        PLATFORM_TLS.replace(value)
    }

    fn clear_guest_thread_local_storage() {
        set_guest_fsbase(0);
    }
}

// ---------------------------------------------------------------------------
// CRNG
// ---------------------------------------------------------------------------

impl litebox::platform::CrngProvider for FreeBSDUserland {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom failed");
    }
}

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

static INTERRUPT_SIGNAL_NUMBER: AtomicI32 = AtomicI32::new(0);

fn with_signal_alt_stack<R>(f: impl FnOnce() -> R) -> R {
    let alt_stack_size = libc::SIGSTKSZ * 2;
    let guard_page_size = 0x1000;
    let stack_base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            guard_page_size + alt_stack_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(
        stack_base != libc::MAP_FAILED,
        "failed to allocate memory for alternate signal stack: {}",
        std::io::Error::last_os_error()
    );
    let _unmap_guard = litebox::utils::defer(|| {
        let r = unsafe { libc::munmap(stack_base, guard_page_size + alt_stack_size) };
        assert!(
            r == 0,
            "failed to free memory for alternate signal stack: {}",
            std::io::Error::last_os_error()
        );
    });

    // Set up a guard page to catch stack overflows.
    let r = unsafe { libc::mprotect(stack_base, guard_page_size, libc::PROT_NONE) };
    assert!(
        r == 0,
        "failed to set guard page for alternate signal stack: {}",
        std::io::Error::last_os_error()
    );

    let alt_stack = libc::stack_t {
        ss_sp: stack_base.cast(),
        ss_flags: 0,
        ss_size: alt_stack_size,
    };
    let mut oss = libc::stack_t {
        ss_sp: std::ptr::null_mut(),
        ss_flags: 0,
        ss_size: 0,
    };
    unsafe {
        let r = libc::sigaltstack(&raw const alt_stack, &raw mut oss);
        assert!(
            r >= 0,
            "failed to set up alternate signal stack: {}",
            std::io::Error::last_os_error(),
        );
    }
    let _restore_guard = litebox::utils::defer(|| unsafe {
        let r = libc::sigaltstack(&raw const oss, std::ptr::null_mut());
        assert!(r >= 0);
    });

    f()
}

/// Copy signal context into the guest context structure.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "register values are reinterpreted between i64 and usize on x86_64"
)]
fn copy_signal_context(regs: &mut litebox_common_linux::PtRegs, context: *mut libc::c_void) {
    // SAFETY: The context pointer is guaranteed to be a valid ucontext_t by the
    // signal handler calling convention.
    let uc = unsafe { &*context.cast::<libc::ucontext_t>() };
    let mc = &uc.uc_mcontext;
    regs.r15 = mc.mc_r15 as usize;
    regs.r14 = mc.mc_r14 as usize;
    regs.r13 = mc.mc_r13 as usize;
    regs.r12 = mc.mc_r12 as usize;
    regs.rbp = mc.mc_rbp as usize;
    regs.rbx = mc.mc_rbx as usize;
    regs.r11 = mc.mc_r11 as usize;
    regs.r10 = mc.mc_r10 as usize;
    regs.r9 = mc.mc_r9 as usize;
    regs.r8 = mc.mc_r8 as usize;
    regs.rax = mc.mc_rax as usize;
    regs.rcx = mc.mc_rcx as usize;
    regs.rdx = mc.mc_rdx as usize;
    regs.rsi = mc.mc_rsi as usize;
    regs.rdi = mc.mc_rdi as usize;
    regs.orig_rax = mc.mc_rax as usize;
    regs.rip = mc.mc_rip as usize;
    regs.cs = mc.mc_cs as usize;
    regs.eflags = mc.mc_rflags as usize;
    regs.rsp = mc.mc_rsp as usize;
    regs.ss = mc.mc_ss as usize;
}

/// Modify the signal context to jump to a different instruction address when
/// the signal handler returns.
#[expect(
    clippy::cast_possible_wrap,
    clippy::ptr_as_ptr,
    reason = "register values are reinterpreted between usize and i64 on x86_64"
)]
fn set_signal_return(
    context: *mut libc::c_void,
    target: unsafe extern "C" fn(),
    rdi: usize,
    rsi: usize,
    rdx: usize,
    rcx: usize,
) {
    // SAFETY: The context pointer is guaranteed to be a valid ucontext_t.
    let uc = unsafe { &mut *(context as *mut libc::ucontext_t) };
    let mc = &mut uc.uc_mcontext;
    mc.mc_rip = target as usize as i64;
    mc.mc_rdi = rdi as i64;
    mc.mc_rsi = rsi as i64;
    mc.mc_rdx = rdx as i64;
    mc.mc_rcx = rcx as i64;
}

unsafe extern "C" fn record_pending_signal(signal: litebox_common_linux::signal::Signal) {
    let bit = match signal {
        litebox_common_linux::signal::Signal::SIGINT => 0,
        litebox_common_linux::signal::Signal::SIGALRM => 1,
        _ => return,
    };
    unsafe {
        core::arch::asm!(
            concat!("lock or DWORD PTR ", saved_tls!("pending_host_signals"), ", {bit:e}"),
            bit = in(reg) 1u32 << bit,
            options(nostack),
        );
    }
}

/// Signal handler for exceptions (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    reason = "register values are reinterpreted between i64 and usize on x86_64"
)]
unsafe extern "C" fn exception_signal_handler(
    sig: i32,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    // SAFETY: The context pointer is guaranteed to be a valid ucontext_t by the
    // signal handler calling convention.
    let uc = unsafe { &*context.cast::<libc::ucontext_t>() };
    let rip = uc.uc_mcontext.mc_rip as usize;

    // Before checking TLS state (which may not be initialized), check the
    // exception table for fallible memory access recovery. This handles the
    // case where host code (e.g. read_u8_fallible) triggers a SIGSEGV.
    if sig == libc::SIGSEGV
        && let Some(fixup) = litebox::mm::exception_table::search_exception_tables(rip)
    {
        let uc_mut = unsafe { &mut *context.cast::<libc::ucontext_t>() };
        uc_mut.uc_mcontext.mc_rip = fixup as i64;
        return;
    }

    // If we are in host code (not in guest), just record the signal and return.
    let in_guest: u8;
    unsafe {
        core::arch::asm!(
            concat!("mov {out}, BYTE PTR ", saved_tls!("in_guest")),
            out = out(reg_byte) in_guest,
            options(nostack, preserves_flags, readonly),
        );
    }

    if in_guest == 0 {
        // Host-side exception. Check if this is in the switch_to_guest code.
        let start = switch_to_guest_start as *const () as usize;
        let end = switch_to_guest_end as *const () as usize;
        if rip >= start && rip < end {
            // The signal arrived in switch_to_guest. Redirect to interrupt handler.
            unsafe {
                core::arch::asm!(
                    concat!("mov BYTE PTR ", saved_tls!("interrupt"), ", 1"),
                    options(nostack, preserves_flags),
                );
            }
            set_signal_return(context, interrupt_callback, 0, 0, 0, 0);
            return;
        }
        // True host exception - this is a bug. Let the default handler deal with it.
        return;
    }

    // Guest exception. Save context and redirect.
    let trapno: usize = unsafe { (*info).si_signo } as usize;
    let error: usize = uc.uc_mcontext.mc_err as usize;
    let cr2: usize = unsafe { (*info).si_addr as usize };

    // Save guest context
    let guest_ctx_top: usize;
    unsafe {
        core::arch::asm!(
            concat!("mov {}, ", saved_tls!("guest_context_top")),
            out(reg) guest_ctx_top,
            options(nostack, preserves_flags, readonly),
        );
    }
    let regs = unsafe {
        &mut *((guest_ctx_top - size_of::<litebox_common_linux::PtRegs>())
            as *mut litebox_common_linux::PtRegs)
    };
    copy_signal_context(regs, context);

    // Restore host fsbase
    unsafe {
        core::arch::asm!(
            concat!("mov BYTE PTR ", saved_tls!("in_guest"), ", 0"),
            options(nostack, preserves_flags),
        );
    }
    set_signal_return(context, exception_callback, 0, trapno, error, cr2);
}

/// Signal handler for interrupt signals (SIGINT, SIGALRM, and the RT interrupt signal).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "register values are reinterpreted between i64 and usize on x86_64"
)]
unsafe extern "C" fn interrupt_signal_handler(
    sig: i32,
    _info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    let uc = unsafe { &*context.cast::<libc::ucontext_t>() };
    let rip = uc.uc_mcontext.mc_rip as usize;

    if sig == libc::SIGINT {
        unsafe { record_pending_signal(litebox_common_linux::signal::Signal::SIGINT) };
    } else if sig == libc::SIGALRM {
        unsafe { record_pending_signal(litebox_common_linux::signal::Signal::SIGALRM) };
    }

    let in_guest: u8;
    unsafe {
        core::arch::asm!(
            concat!("mov {out}, BYTE PTR ", saved_tls!("in_guest")),
            out = out(reg_byte) in_guest,
            options(nostack, preserves_flags, readonly),
        );
    }

    if in_guest == 0 {
        // Case 1: signal is the RT signal and we're in switch_to_guest.
        let start = switch_to_guest_start as *const () as usize;
        let end = switch_to_guest_end as *const () as usize;
        if rip >= start && rip < end {
            unsafe {
                core::arch::asm!(
                    concat!("mov BYTE PTR ", saved_tls!("interrupt"), ", 1"),
                    options(nostack, preserves_flags),
                );
            }
            set_signal_return(context, interrupt_callback, 0, 0, 0, 0);
        }
        // Case 2: signal in host code but interrupting a wait or other host operation.
        // This is fine; the wait will see the pending_host_signals flag.
        return;
    }

    // Case 3 & 4: in guest. Copy out the context and jump to interrupt handler.
    let guest_ctx_top: usize;
    unsafe {
        core::arch::asm!(
            concat!("mov {}, ", saved_tls!("guest_context_top")),
            out(reg) guest_ctx_top,
            options(nostack, preserves_flags, readonly),
        );
    }
    let regs = unsafe {
        &mut *((guest_ctx_top - size_of::<litebox_common_linux::PtRegs>())
            as *mut litebox_common_linux::PtRegs)
    };
    copy_signal_context(regs, context);

    unsafe {
        core::arch::asm!(
            concat!("mov BYTE PTR ", saved_tls!("in_guest"), ", 0"),
            options(nostack, preserves_flags),
        );
    }
    set_signal_return(context, interrupt_callback, 0, 0, 0, 0);
}

fn register_exception_handlers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        fn sigaction_fn(sig: i32, sa: Option<&libc::sigaction>, old_sa: &mut libc::sigaction) {
            unsafe {
                let r = libc::sigaction(
                    sig,
                    sa.map_or(std::ptr::null(), |sa| &raw const *sa),
                    &raw mut *old_sa,
                );
                assert!(
                    r >= 0,
                    "failed to query existing signal handler for signal {}: {}",
                    sig,
                    std::io::Error::last_os_error()
                );
            }
        }

        // Find an available signal for thread interrupts
        let interrupt_signal = {
            // On FreeBSD, use SIGUSR1 as the interrupt signal since there
            // are no RT signals in the Linux sense.
            let sig = libc::SIGUSR1;
            let mut sa: libc::sigaction = unsafe { core::mem::zeroed() };
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
            sa.sa_sigaction = interrupt_signal_handler as *const () as usize;
            let mut old_sa = unsafe { core::mem::zeroed() };
            sigaction_fn(sig, Some(&sa), &mut old_sa);
            INTERRUPT_SIGNAL_NUMBER.store(sig, Ordering::Relaxed);
            sig
        };

        // Register exception signal handlers
        let exception_signals = &[
            libc::SIGSEGV,
            libc::SIGBUS,
            libc::SIGFPE,
            libc::SIGILL,
            libc::SIGTRAP,
        ];
        for &sig in exception_signals {
            let mut sa: libc::sigaction = unsafe { core::mem::zeroed() };
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
            sa.sa_sigaction = exception_signal_handler as *const () as usize;
            let mut old_sa = unsafe { core::mem::zeroed() };
            sigaction_fn(sig, Some(&sa), &mut old_sa);
        }

        // Register SIGINT and SIGALRM handlers to record pending signals
        for &sig in &[libc::SIGINT, libc::SIGALRM] {
            if sig == interrupt_signal {
                continue; // already registered
            }
            let mut sa: libc::sigaction = unsafe { core::mem::zeroed() };
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
            sa.sa_sigaction = interrupt_signal_handler as *const () as usize;
            let mut old_sa = unsafe { core::mem::zeroed() };
            sigaction_fn(sig, Some(&sa), &mut old_sa);
        }
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    use litebox::platform::RawMutex;
    use std::thread::sleep;

    use crate::FreeBSDUserland;
    use litebox::platform::{DebugLogProvider, PageManagementProvider};

    extern crate std;

    #[test]
    fn test_raw_mutex() {
        let mutex = std::sync::Arc::new(super::RawMutex {
            inner: AtomicU32::new(0),
        });

        let copied_mutex = mutex.clone();
        std::thread::spawn(move || {
            sleep(core::time::Duration::from_millis(500));
            copied_mutex.wake_many(10);
        });

        assert!(mutex.block(0).is_ok());
    }

    #[test]
    fn test_reserved_pages() {
        let platform = FreeBSDUserland::new(None);

        platform.debug_log_print("msg from FreeBSDUserland test_reserved_pages\n");

        let reserved_pages: Vec<_> =
            <FreeBSDUserland as PageManagementProvider<4096>>::reserved_pages(platform).collect();

        // Check that the reserved pages are in order and non-overlapping
        let mut prev = 0;
        for page in reserved_pages {
            assert!(page.start >= prev);
            assert!(page.end > page.start);
            prev = page.end;
        }
    }
}
