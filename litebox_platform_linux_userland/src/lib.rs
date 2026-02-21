// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Linux.

// Restrict this crate to only work on Linux. For now, we are restricting this to only x86/x86-64
// Linux, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "x86")))]

use std::cell::Cell;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::Duration;

use litebox::fs::OFlags;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions};
use litebox::platform::{ImmediatelyWokenUp, RawConstPointer as _};
use litebox::shim::ContinueOperation;
use litebox::utils::{ReinterpretSignedExt, ReinterpretUnsignedExt as _, TruncateExt};
use litebox_common_linux::{
    MRemapFlags, MapFlags, ProtFlags, PunchthroughSyscall, vmap::VmapManager,
};

use zerocopy::{FromBytes, IntoBytes};

mod syscall_intercept;

extern crate alloc;

/// The userland Linux platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct LinuxUserland {
    tun_socket_fd: std::sync::RwLock<Option<std::os::fd::OwnedFd>>,
    #[cfg(feature = "systrap_backend")]
    seccomp_interception_enabled: std::sync::atomic::AtomicBool,
    /// Reserved pages that are not available for guest programs to use.
    reserved_pages: Vec<core::ops::Range<usize>>,
    /// The base address of the VDSO.
    vdso_address: Option<usize>,
}

impl core::fmt::Debug for LinuxUserland {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinuxUserland").finish_non_exhaustive()
    }
}

const IF_NAMESIZE: usize = 16;
/// Use TUN device
const IFF_TUN: i32 = 0x0001;
/// Do not provide packet information
const IFF_NO_PI: i32 = 0x1000;
/// libc `ifreq` structure, used for TUN/TAP devices.
#[repr(C)]
struct Ifreq {
    /// interface name, e.g. "en0"
    pub ifr_name: [i8; IF_NAMESIZE],
    pub ifr_ifru: Ifru,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ifmap {
    mem_start: usize,
    mem_end: usize,
    base_addr: u16,
    irq: u8,
    dma: u8,
    port: u8,
}

/// libc `ifreq.ifr_ifru` union, used for TUN/TAP devices.
///
/// We only need `ifru_flags` for now; `ifru_map` is to ensure the size of the union
/// matches libc.
#[repr(C)]
pub union Ifru {
    // pub ifru_addr: crate::sockaddr,
    // pub ifru_dstaddr: crate::sockaddr,
    // pub ifru_broadaddr: crate::sockaddr,
    // pub ifru_netmask: crate::sockaddr,
    // pub ifru_hwaddr: crate::sockaddr,
    ifru_flags: i16,
    // pub ifru_ifindex: i32,
    // pub ifru_metric: i32,
    // pub ifru_mtu: i32,
    ifru_map: Ifmap,
    // pub ifru_slave: [i8; IF_NAMESIZE],
    // pub ifru_newname: [i8; IF_NAMESIZE],
    // pub ifru_data: *mut i8,
}

impl LinuxUserland {
    /// Create a new userland-Linux platform for use in `LiteBox`.
    ///
    /// Takes an optional tun device name (such as `"tun0"` or `"tun99"`) to connect networking (if
    /// not specified, networking is disabled).
    ///
    /// # Panics
    ///
    /// Panics if the tun device could not be successfully opened.
    pub fn new(tun_device_name: Option<&str>) -> &'static Self {
        register_exception_handlers();

        let tun_socket_fd = tun_device_name
            .map(|tun_device_name| {
                let tun_path = b"/dev/net/tun\0";
                let tun_fd = unsafe {
                    syscalls::syscall3(
                        syscalls::Sysno::open,
                        tun_path.as_ptr() as usize,
                        (litebox::fs::OFlags::RDWR
                            | litebox::fs::OFlags::CLOEXEC
                            | litebox::fs::OFlags::NONBLOCK)
                            .bits() as usize,
                        litebox::fs::Mode::empty().bits() as usize,
                    )
                }
                .expect("failed to open tun device");

                let tunsetiff = |fd: usize, ifreq: *const Ifreq| {
                    let cmd =
                        litebox_common_linux::iow!(b'T', 202, size_of::<::core::ffi::c_int>());
                    unsafe {
                        syscalls::syscall3(syscalls::Sysno::ioctl, fd, cmd as usize, ifreq as usize)
                    }
                    .expect("failed to set TUN interface flags");
                };
                let ifreq = Ifreq {
                    ifr_name: {
                        let mut name = [0i8; 16];
                        assert!(tun_device_name.len() < 16); // Note: strictly-less-than 16, to ensure it fits
                        for (i, b) in tun_device_name.char_indices() {
                            let b = b as u32;
                            assert!(b < 128);
                            name[i] = i8::try_from(b).unwrap();
                        }
                        name
                    },
                    ifr_ifru: Ifru {
                        // IFF_NO_PI: no tun header
                        // IFF_TUN: create tun (i.e., IP)
                        ifru_flags: i16::try_from(IFF_TUN | IFF_NO_PI).unwrap(),
                    },
                };
                tunsetiff(tun_fd, &raw const ifreq);

                // By taking ownership, we are letting the drop handler automatically run `libc::close`
                // when necessary.
                unsafe {
                    std::os::fd::OwnedFd::from_raw_fd(tun_fd.reinterpret_as_signed().truncate())
                }
            })
            .into();

        let (reserved_pages, vdso_address) = Self::read_maps_and_vdso();
        let platform = Self {
            tun_socket_fd,
            #[cfg(feature = "systrap_backend")]
            seccomp_interception_enabled: std::sync::atomic::AtomicBool::new(false),
            reserved_pages,
            vdso_address,
        };
        Box::leak(Box::new(platform))
    }

    /// Enable seccomp syscall interception on the platform.
    ///
    /// # Panics
    ///
    /// Panics if this function has already been invoked on the platform earlier.
    #[cfg(feature = "systrap_backend")]
    pub fn enable_seccomp_based_syscall_interception(&self) {
        assert!(
            self.seccomp_interception_enabled
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst
                )
                .is_ok()
        );
        syscall_intercept::init_sys_intercept();
    }

    fn read_maps_and_vdso() -> (alloc::vec::Vec<core::ops::Range<usize>>, Option<usize>) {
        // TODO: this function is not guaranteed to return all allocated pages, as it may
        // allocate more pages after the mapping file is read. Missing allocated pages may
        // cause the program to crash when calling `mmap` or `mremap` with the `MAP_FIXED` flag later.
        // We should either fix `mmap` to handle this error, or let global allocator call this function
        // whenever it get more pages from the host.
        let path = "/proc/self/maps";
        let fd = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::open,
                path.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };
        let Ok(fd) = fd else {
            return (alloc::vec::Vec::new(), None);
        };
        let mut buf = [0u8; 8192];
        let mut total_read = 0;
        while total_read < buf.len() {
            let n = unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::read,
                    fd,
                    buf.as_mut_ptr() as usize + total_read,
                    buf.len() - total_read,
                )
            }
            .expect("read failed");
            if n == 0 {
                break;
            }
            total_read += n;
        }
        assert!(total_read < buf.len(), "buffer too small");

        let mut reserved_pages = alloc::vec::Vec::new();
        #[cfg_attr(not(feature = "systrap_backend"), expect(unused_mut))]
        let mut vdso_address = None;
        let s = core::str::from_utf8(&buf[..total_read]).expect("invalid UTF-8");
        for line in s.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }
            let range = parts[0].split('-').collect::<Vec<&str>>();
            let start = usize::from_str_radix(range[0], 16).expect("invalid start address");
            let end = usize::from_str_radix(range[1], 16).expect("invalid end address");
            reserved_pages.push(start..end);

            // Check if the line corresponds to the vdso
            // Alternatively, we could read it from `/proc/self/auxv`
            #[cfg(feature = "systrap_backend")]
            {
                if let Some(last) = parts.last()
                    && *last == "[vdso]"
                {
                    vdso_address = Some(start);
                }
            }
        }
        (reserved_pages, vdso_address)
    }

    #[expect(
        clippy::missing_panics_doc,
        reason = "panicking only on failures of documented linux contracts"
    )]
    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        let tid = unsafe { syscalls::raw::syscall0(syscalls::Sysno::gettid) }
            .try_into()
            .unwrap();
        let ppid = unsafe { syscalls::raw::syscall0(syscalls::Sysno::getppid) }
            .try_into()
            .unwrap();
        litebox_common_linux::TaskParams {
            pid: tid,
            ppid,
            uid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::getuid) }
                .try_into()
                .unwrap(),
            euid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::geteuid) }
                .try_into()
                .unwrap(),
            gid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::getgid) }
                .try_into()
                .unwrap(),
            egid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::getegid) }
                .try_into()
                .unwrap(),
        }
    }

    /// Wait until there is data available on the TUN device.
    ///
    /// # Panics
    ///
    /// Panics if the TUN device is not initialized.
    pub fn wait_on_tun(&self, timeout: Option<Duration>) {
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
}

impl litebox::platform::Provider for LinuxUserland {}

/// Runs a guest thread using the provided shim and the given initial context.
///
/// This will run until the thread terminates or returns.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread<T>(shim: T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    run_thread_inner(&shim, ctx, false);
}

/// Run a guest thread using a reference to the shim.
///
/// Unlike `run_thread`, this version takes a reference instead of ownership,
/// avoiding struct moves that could invalidate internal state.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread_ref<T>(shim: &T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    run_thread_inner(shim, ctx, false);
}

/// Re-enter a guest thread using a reference to the shim.
///
/// This version takes a reference instead of ownership, avoiding struct moves
/// that could invalidate internal state.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn reenter_thread<T>(shim: &T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    run_thread_inner(shim, ctx, true);
}

struct ThreadContext<'a> {
    shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &'a mut litebox_common_linux::PtRegs,
}

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

#[cfg(target_arch = "x86_64")]
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
    "
);

#[cfg(target_arch = "x86_64")]
fn set_guest_fsbase(value: usize) {
    unsafe {
        core::arch::asm! {
            "mov fs:guest_fsbase@tpoff, {}",
            in(reg) value,
            options(nostack, preserves_flags)
        }
    }
}

#[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86_64")]
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

exception_callback:
    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    mov rdi, [rsp] // pass thread_ctx
    call {exception_handler}
    jmp .Ldone

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
#[cfg(target_arch = "x86")]
#[unsafe(naked)]
unsafe extern "fastcall-unwind" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut litebox_common_linux::PtRegs,
    reenter: u8,
) {
    core::arch::naked_asm!(
    "
    .cfi_startproc
    push    ebp
    mov ebp, esp
    .cfi_def_cfa ebp, 8
    push ebx
    push esi
    push edi
    sub esp, 8 // align
    push ecx // save thread context

    // Save host esp and ebp and guest context top in TLS
    mov gs:host_sp@ntpoff, esp
    mov gs:host_bp@ntpoff, ebp
    lea edi, [edx + {GUEST_CONTEXT_SIZE}]
    mov gs:guest_context_top@ntpoff, edi

    // Save host gs in fs
    mov ax, gs
    mov fs, ax

    // Call init_handler or reenter_handler based on reenter flag (on stack at [ebp+8])
    sub esp, 12 // align
    push ecx
    mov al, [ebp + 8]  // reenter is 3rd arg, first stack arg for fastcall
    test al, al
    jnz 1f
    call {init_handler}
    jmp .Ldone
1:
    call {reenter_handler}
    jmp .Ldone

    // This entry point is called from the guest when it issues a syscall
    // instruction.
    //
    // The stack layout at the entry of the callback (see litebox_syscall_rewriter
    // for more details):
    //
    // Addr |   data   |
    // 0    | eax      |
    // -4:  | ret addr |  <-- esp
    //
    // The first two instructions adjust the stack such that it saves one
    // instruction (i.e., `pop eax`) from the caller (trampoline code).
    .globl  syscall_callback
syscall_callback:
    // Clear in_guest flag. This must be the first instruction to match the
    // expectations of `interrupt_signal_handler`.
    mov     BYTE PTR fs:in_guest@ntpoff, 0

    // Save the parameters and switch esp to the guest context
    pop  dword ptr fs:scratch@ntpoff  // pop ret addr
    pop  eax                          // pop eax
    mov  dword ptr fs:scratch2@ntpoff, esp
    mov  esp, fs:guest_context_top@ntpoff

    // Save registers and constructs pt_regs
    push    0x2b       // pt_regs->xss = __USER_DS
    push    dword ptr fs:scratch2@ntpoff   // pt_regs->esp
    pushfd             // pt_regs->eflags
    push    0x33       // pt_regs->xcs = __USER_CS
    push    dword ptr fs:scratch@ntpoff    // pt_regs->eip
    push    eax        // pt_regs->orig_ax

    // Use explicit encodings because LLVM emits 16-bit pushes and we want 32-bit
    .byte 0x0f, 0xa8    // push gs
    .byte 0x0f, 0xa0    // push fs
    .byte 0x06          // push es
    .byte 0x1e          // push ds

    push    -38         // pt_regs->eax = ENOSYS
    push    ebp         // pt_regs->ebp
    push    edi         // pt_regs->edi
    push    esi         // pt_regs->esi
    push    edx         // pt_regs->edx
    push    ecx         // pt_regs->ecx
    push    ebx         // pt_regs->ebx

    // Restore esp and ebp
    mov esp, fs:host_sp@ntpoff
    mov ebp, fs:host_bp@ntpoff

    // Switch to host gs
    mov ax, fs
    mov gs, ax

    // Handle the syscall. This will jump back to the guest but
    // will return if the thread is exiting.
    mov ecx, [esp] // pass thread_ctx
    call {syscall_handler_fast}
    jmp .Ldone

exception_callback:
    // Restore esp and ebp
    mov esp, gs:host_sp@ntpoff
    mov ebp, gs:host_bp@ntpoff

    mov edi, [esp] // pass thread_ctx
    push ecx
    push edx
    push esi
    push edi
    call {exception_handler}
    jmp .Ldone

interrupt_callback:
    // Restore esp and ebp
    mov esp, gs:host_sp@ntpoff
    mov ebp, gs:host_bp@ntpoff

    mov ecx, [esp] // pass thread_ctx
    sub esp, 12 // align
    push ecx
    call {interrupt_handler}

.Ldone:

    lea  esp, [ebp - 3*4]
    pop  edi
    pop  esi
    pop  ebx
    pop  ebp
    .cfi_def_cfa esp, 4
    ret 4  // pop the reenter argument (fastcall callee cleanup)
    .cfi_endproc
",
    GUEST_CONTEXT_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
    init_handler = sym init_handler,
    reenter_handler = sym reenter_handler,
    syscall_handler_fast = sym syscall_handler_fast,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    );
}

/// Wrapper around `syscall_handler` to use the fastcall convention.
#[cfg(target_arch = "x86")]
unsafe extern "fastcall-unwind" fn syscall_handler_fast(thread_ctx: &mut ThreadContext) {
    unsafe { syscall_handler(thread_ctx) }
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
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    core::arch::naked_asm!(
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
        "switch_to_guest_end:",
    );
}

#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    "
    .section .tbss
    .align 4
scratch:
    .long 0
scratch2:
    .long 0
host_sp:
    .long 0
host_bp:
    .long 0
guest_context_top:
    .long 0
in_guest:
    .byte 0
.globl interrupt
interrupt:
    .byte 0
    "
);

#[cfg(target_arch = "x86")]
#[unsafe(naked)]
unsafe extern "fastcall" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    core::arch::naked_asm!(
        "switch_to_guest_start:",
        // Set `in_guest` now, then check if there is a pending interrupt. If
        // so, jump to the interrupt handler.
        //
        // If an interrupt arrives after the check, then the signal handler will
        // see that the IP is between `switch_to_guest_start` and
        // `switch_to_guest_end` and will set the `interrupt` and jump to
        // `interrupt_callback`.
        "mov BYTE PTR gs:in_guest@ntpoff, 1",
        "cmp BYTE PTR gs:interrupt@ntpoff, 0",
        "jne interrupt_callback",
        // Restore guest context from ctx.
        "mov esp, ecx",
        "pop ebx",
        "pop ecx",
        "pop edx",
        "pop esi",
        "pop edi",
        "pop ebp",
        "pop eax",
        "add esp, 12",           // skip xds, xes, xfs
        ".byte 0x0f, 0xa9",      // pop gs
        "add esp, 4",            // skip orig_eax
        "pop fs:scratch@ntpoff", // read eip into scratch
        "add esp, 4",            // skip xcs
        "popfd",
        "pop esp",
        "jmp fs:scratch@ntpoff", // jump to the guest
        "switch_to_guest_end:",
    );
}

fn thread_start(
    init_thread: Box<
        dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
    >,
    mut ctx: litebox_common_linux::PtRegs,
) {
    // Allow caller to run some code before we return to the new thread.
    let shim = init_thread.init();

    run_thread_inner(shim.as_ref(), &mut ctx, false);
    // TODO: have syscall_callback return if we need to terminate the process.
    // We should return this value to the caller so load_program can return it
    // to the user.
}

// A handle to a platform thread.
#[derive(Clone)]
pub struct ThreadHandle(std::sync::Arc<std::sync::Mutex<Option<libc::pthread_t>>>);

thread_local! {
    static CURRENT_THREAD: std::cell::RefCell<Option<ThreadHandle>> = const { std::cell::RefCell::new(None) };
}

impl ThreadHandle {
    /// Runs `f`, ensuring that [`ThreadHandle::current`] can be called within `f`.
    fn run_with_handle<R>(f: impl FnOnce() -> R) -> R {
        let handle = ThreadHandle(std::sync::Arc::new(std::sync::Mutex::new(Some(unsafe {
            libc::pthread_self()
        }))));
        CURRENT_THREAD.with_borrow_mut(|current| {
            assert!(
                current.is_none(),
                "nested with_thread_handle calls are not supported"
            );
            *current = Some(handle);
        });
        let _guard = litebox::utils::defer(|| {
            let current = CURRENT_THREAD.take().unwrap();
            *current.0.lock().unwrap() = None;
        });
        f()
    }

    /// Returns the current thread handle.
    fn current() -> Self {
        CURRENT_THREAD.with_borrow(|thread| {
            thread
                .clone()
                .expect("current_thread called outside of a LiteBox thread")
        })
    }

    /// Interrupts the thread, delivering a signal to it.
    fn interrupt(&self) {
        let thread = self.0.lock().unwrap();
        if let Some(&thread) = thread.as_ref() {
            unsafe {
                libc::pthread_kill(thread, INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed));
            }
        }
    }
}

impl litebox::platform::ThreadProvider for LinuxUserland {
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
        // TODO: do we need to wait for the handle in the main thread?
        let _handle = std::thread::Builder::new().spawn(move || thread_start(init_thread, ctx))?;

        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        ThreadHandle::current()
    }

    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        thread.interrupt();
    }
}

impl litebox::platform::RawMutexProvider for LinuxUserland {
    type RawMutex = RawMutex;
}

pub struct RawMutex {
    // The `inner` is the value shown to the outside world as an underlying atomic.
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
        // We immediately wake up (without even hitting syscalls) if we can clearly see that the
        // value is different.
        if self.inner.load(Ordering::SeqCst) != val {
            return Err(ImmediatelyWokenUp);
        }

        // We wait on the futex, with a timeout if needed
        loop {
            break match futex_timeout(
                &self.inner,
                FutexOperation::Wait,
                /* expected value */ val,
                timeout,
                /* ignored */ None,
            ) {
                Ok(0) => Ok(UnblockedOrTimedOut::Unblocked),
                Err(syscalls::Errno::EAGAIN) => Err(ImmediatelyWokenUp),
                Err(syscalls::Errno::ETIMEDOUT) => Ok(UnblockedOrTimedOut::TimedOut),
                Err(syscalls::Errno::EINTR) => continue,
                Err(e) => {
                    panic!("Unexpected errno={e} for FUTEX_WAIT")
                }
                _ => unreachable!(),
            };
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

        futex_val2(
            &self.inner,
            FutexOperation::Wake,
            /* number to wake up */ n,
            /* val2: ignored */ 0,
            /* uaddr2: ignored */ None,
        )
        .expect("failed to wake up waiters")
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

impl litebox::platform::IPInterfaceProvider for LinuxUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let Some(tun_socket_fd) = tun_fd.as_ref() else {
            unimplemented!("networking without tun is unimplemented")
        };
        match unsafe {
            syscalls::syscall4(
                syscalls::Sysno::write,
                usize::try_from(tun_socket_fd.as_raw_fd()).unwrap(),
                packet.as_ptr() as usize,
                packet.len(),
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::SYSCALL_ARG_MAGIC,
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
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let Some(tun_socket_fd) = tun_fd.as_ref() else {
            unimplemented!("networking without tun is unimplemented")
        };
        unsafe {
            syscalls::syscall4(
                syscalls::Sysno::read,
                usize::try_from(tun_socket_fd.as_raw_fd()).unwrap(),
                packet.as_mut_ptr() as usize,
                packet.len(),
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
        }
        .map_err(|errno| match errno {
            #[allow(unreachable_patterns, reason = "EAGAIN == EWOULDBLOCK")]
            syscalls::Errno::EWOULDBLOCK | syscalls::Errno::EAGAIN => {
                litebox::platform::ReceiveError::WouldBlock
            }
            _ => unimplemented!("unexpected error {errno}"),
        })
    }
}

impl litebox::platform::TimeProvider for LinuxUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        Instant {
            #[cfg_attr(target_arch = "x86_64", expect(clippy::useless_conversion))]
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned().into(),
                t.tv_nsec.reinterpret_as_unsigned().truncate(),
            ),
        }
    }

    fn current_time(&self) -> Self::SystemTime {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        SystemTime {
            #[cfg_attr(target_arch = "x86_64", expect(clippy::useless_conversion))]
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned().into(),
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
    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
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

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        self.inner
            .checked_sub(earlier.inner)
            .ok_or_else(|| earlier.inner.checked_sub(self.inner).unwrap())
    }
}

#[cfg(target_arch = "x86")]
fn set_thread_area(
    user_desc: &mut litebox_common_linux::UserDesc,
) -> Result<usize, litebox_common_linux::errno::Errno> {
    unsafe {
        syscalls::syscall1(
            syscalls::Sysno::set_thread_area,
            core::ptr::from_mut(user_desc) as usize,
        )
    }
    .map_err(|err| match err {
        syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
        syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
        syscalls::Errno::ENOSYS => litebox_common_linux::errno::Errno::ENOSYS,
        syscalls::Errno::ESRCH => litebox_common_linux::errno::Errno::ESRCH,
        _ => panic!("unexpected error {err}"),
    })
}

#[cfg(target_arch = "x86")]
fn clear_thread_area(entry_number: u32) {
    if entry_number == u32::MAX {
        return;
    }

    let flags = litebox_common_linux::UserDescFlags(0);
    let mut user_desc = litebox_common_linux::UserDesc {
        entry_number,
        base_addr: 0,
        limit: 0,
        flags,
    };

    set_thread_area(&mut user_desc).expect("failed to clear TLS entry");
}

pub struct PunchthroughToken<'a> {
    punchthrough: PunchthroughSyscall<'a, LinuxUserland>,
}

impl<'a> litebox::platform::PunchthroughToken for PunchthroughToken<'a> {
    type Punchthrough = PunchthroughSyscall<'a, LinuxUserland>;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<
            <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnFailure,
        >,
    > {
        match self.punchthrough {
            // We swap gs and fs before and after a syscall so at this point guest's fs base is stored in gs
            #[cfg(target_arch = "x86_64")]
            PunchthroughSyscall::SetFsBase { addr } => {
                set_guest_fsbase(addr);
                Ok(0)
            }
            #[cfg(target_arch = "x86_64")]
            PunchthroughSyscall::GetFsBase => Ok(get_guest_fsbase()),
            #[cfg(target_arch = "x86")]
            PunchthroughSyscall::SetThreadArea { user_desc } => {
                set_thread_area(user_desc).map_err(litebox::platform::PunchthroughError::Failure)
            }
        }
    }
}

impl litebox::platform::PunchthroughProvider for LinuxUserland {
    type PunchthroughToken<'a> = PunchthroughToken<'a>;
    fn get_punchthrough_token_for<'a>(
        &self,
        punchthrough: <Self::PunchthroughToken<'a> as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'a>> {
        Some(PunchthroughToken { punchthrough })
    }
}

impl litebox::platform::DebugLogProvider for LinuxUserland {
    fn debug_log_print(&self, msg: &str) {
        let _ = unsafe {
            syscalls::syscall4(
                syscalls::Sysno::write,
                litebox_common_linux::STDERR_FILENO as usize,
                msg.as_ptr() as usize,
                msg.len(),
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
        };
    }
}

type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
impl litebox::platform::RawPointerProvider for LinuxUserland {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

/// Operations currently supported by the safer variants of the Linux futex syscall
/// ([`futex_timeout`] and [`futex_val2`]).
#[repr(i32)]
enum FutexOperation {
    Wait = litebox_common_linux::FUTEX_WAIT,
    Wake = litebox_common_linux::FUTEX_WAKE,
}

/// Safer invocation of the Linux futex syscall, with the "timeout" variant of the arguments.
#[expect(clippy::similar_names, reason = "sec/nsec are as needed by libc")]
fn futex_timeout(
    uaddr: &AtomicU32,
    futex_op: FutexOperation,
    val: u32,
    timeout: Option<Duration>,
    uaddr2: Option<&AtomicU32>,
) -> Result<usize, syscalls::Errno> {
    let uaddr: *const AtomicU32 = uaddr as _;
    let futex_op: i32 = futex_op as _;
    let timeout = timeout.map(|t| {
        const TEN_POWER_NINE: u128 = 1_000_000_000;
        let nanos: u128 = t.as_nanos();
        let tv_sec = nanos
            .checked_div(TEN_POWER_NINE)
            .unwrap()
            .try_into()
            .unwrap();
        let tv_nsec = nanos
            .checked_rem(TEN_POWER_NINE)
            .unwrap()
            .try_into()
            .unwrap();
        litebox_common_linux::Timespec { tv_sec, tv_nsec }
    });
    let uaddr2: *const AtomicU32 = uaddr2.map_or(std::ptr::null(), |u| u);
    unsafe {
        syscalls::syscall6(
            {
                #[cfg(target_arch = "x86_64")]
                {
                    syscalls::Sysno::futex
                }
                #[cfg(target_arch = "x86")]
                {
                    syscalls::Sysno::futex_time64
                }
            },
            uaddr as usize,
            usize::try_from(futex_op).unwrap(),
            val as usize,
            if let Some(t) = timeout.as_ref() {
                core::ptr::from_ref(t) as usize
            } else {
                0 // No timeout
            },
            uaddr2 as usize,
            // argument `val3` is ignored for this futex operation;
            // we reinterpret it as the magic value to pass through the Seccomp filter.
            syscall_intercept::SYSCALL_ARG_MAGIC,
        )
    }
}

/// Safer invocation of the Linux futex syscall, with the "val2" variant of the arguments.
fn futex_val2(
    uaddr: &AtomicU32,
    futex_op: FutexOperation,
    val: u32,
    val2: u32,
    uaddr2: Option<&AtomicU32>,
) -> Result<usize, syscalls::Errno> {
    let uaddr: *const AtomicU32 = uaddr as _;
    let futex_op: i32 = futex_op as _;
    let uaddr2: *const AtomicU32 = uaddr2.map_or(std::ptr::null(), |u| u);
    unsafe {
        syscalls::syscall6(
            {
                #[cfg(target_arch = "x86_64")]
                {
                    syscalls::Sysno::futex
                }
                #[cfg(target_arch = "x86")]
                {
                    syscalls::Sysno::futex_time64
                }
            },
            uaddr as usize,
            usize::try_from(futex_op).unwrap(),
            val as usize,
            val2 as usize,
            uaddr2 as usize,
            // argument `val3` is ignored for this futex operation;
            // we reinterpret it as the magic value to pass through the Seccomp filter.
            syscall_intercept::SYSCALL_ARG_MAGIC,
        )
    }
}

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

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for LinuxUserland {
    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux config
    #[cfg(target_arch = "x86_64")]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    #[cfg(all(target_arch = "x86", not(feature = "x86_on_x64")))]
    const TASK_ADDR_MAX: usize = 0xC000_0000; // 3 GiB (see arch/x86/include/asm/page_32_types.h)
    #[cfg(all(target_arch = "x86", feature = "x86_on_x64"))]
    const TASK_ADDR_MAX: usize = 0xFFFF_F000; // Note running 32-bit programs on x86_64 kernel has a different limit than native x86

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let flags = MapFlags::MAP_PRIVATE
            | MapFlags::MAP_ANONYMOUS
            | match fixed_address_behavior {
                FixedAddressBehavior::Hint => MapFlags::empty(),
                FixedAddressBehavior::Replace => MapFlags::MAP_FIXED,
                FixedAddressBehavior::NoReplace => MapFlags::MAP_FIXED_NOREPLACE,
            }
            | if can_grow_down {
                MapFlags::MAP_GROWSDOWN
            } else {
                MapFlags::empty()
            }
            | if populate_pages_immediately {
                MapFlags::MAP_POPULATE
            } else {
                MapFlags::empty()
            };
        let r = unsafe {
            syscalls::syscall6(
                {
                    #[cfg(target_arch = "x86_64")]
                    {
                        syscalls::Sysno::mmap
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        syscalls::Sysno::mmap2
                    }
                },
                suggested_range.start,
                suggested_range.len(),
                prot_flags(initial_permissions)
                    .bits()
                    .reinterpret_as_unsigned() as usize,
                (flags.bits().reinterpret_as_unsigned()
                    // This is to ensure it won't be intercepted by Seccomp if enabled.
                    | syscall_intercept::MMAP_FLAG_MAGIC) as usize,
                usize::MAX,
                0,
            )
        };
        let ptr = r.map_err(|err| match err {
            syscalls::Errno::ENOMEM => litebox::platform::page_mgmt::AllocationError::OutOfMemory,
            syscalls::Errno::EEXIST => {
                assert!(matches!(
                    fixed_address_behavior,
                    FixedAddressBehavior::NoReplace
                ));
                litebox::platform::page_mgmt::AllocationError::AddressInUse
            }
            _ => panic!("unhandled mmap error {err}"),
        })?;
        Ok(UserMutPtr::from_usize(ptr))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let _ = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::munmap,
                range.start,
                range.len(),
                // This is to ensure it won't be intercepted by Seccomp if enabled.
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
        }
        .expect("munmap failed");
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
        _permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
        let res = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::mremap,
                old_range.start,
                old_range.len(),
                new_range.len(),
                MRemapFlags::MREMAP_MAYMOVE.bits() as usize,
                new_range.start,
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
            .expect("mremap failed")
        };
        Ok(UserMutPtr::from_usize(res))
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        unsafe {
            syscalls::syscall4(
                syscalls::Sysno::mprotect,
                range.start,
                range.len(),
                prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
                // This is to ensure it won't be intercepted by Seccomp if enabled.
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
        }
        .expect("mprotect failed");
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        self.reserved_pages.iter()
    }
}

impl litebox::platform::StdioProvider for LinuxUserland {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        unsafe {
            syscalls::syscall4(
                syscalls::Sysno::read,
                usize::try_from(litebox_common_linux::STDIN_FILENO).unwrap(),
                buf.as_ptr() as usize,
                buf.len(),
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
        }
        .map_err(|err| match err {
            syscalls::Errno::EPIPE => litebox::platform::StdioReadError::Closed,
            _ => panic!("unhandled error {err}"),
        })
    }

    fn write_to(
        &self,
        stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        unsafe {
            syscalls::syscall4(
                syscalls::Sysno::write,
                usize::try_from(match stream {
                    litebox::platform::StdioOutStream::Stdout => {
                        litebox_common_linux::STDOUT_FILENO
                    }
                    litebox::platform::StdioOutStream::Stderr => {
                        litebox_common_linux::STDERR_FILENO
                    }
                })
                .unwrap(),
                buf.as_ptr() as usize,
                buf.len(),
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::SYSCALL_ARG_MAGIC,
            )
        }
        .map_err(|err| match err {
            syscalls::Errno::EPIPE => litebox::platform::StdioWriteError::Closed,
            _ => panic!("unhandled error {err}"),
        })
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

unsafe extern "C" {
    // Defined in asm blocks above
    fn syscall_callback() -> isize;
    fn exception_callback();
    fn interrupt_callback();
    fn switch_to_guest_start();
    fn switch_to_guest_end();
}

unsafe extern "C-unwind" fn init_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.init(ctx));
}

unsafe extern "C-unwind" fn reenter_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.reenter(ctx));
}

/// Handles Linux syscalls and dispatches them to LiteBox implementations.
///
/// Returns only if the guest thread is exiting. Otherwise, resumes the guest
/// without returning.
///
/// # Safety
///
/// - The `ctx` pointer must be valid pointer to a `litebox_common_linux::PtRegs` structure.
/// - If any syscall argument is a pointer, it must be valid.
///
/// # Panics
///
/// Unsupported syscalls or arguments would trigger a panic for development
/// purposes.
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

/// Calls `f` in order to call into a shim entrypoint.
impl ThreadContext<'_> {
    fn call_shim(
        &mut self,
        f: impl FnOnce(
            &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
            &mut litebox_common_linux::PtRegs,
        ) -> ContinueOperation,
    ) {
        // Clear the interrupt flag before calling the shim, since we've handled it
        // now (by calling into the shim), and it might be set again by the shim
        // before returning.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!(
                "mov BYTE PTR fs:interrupt@tpoff, 0",
                options(nostack, preserves_flags)
            );
            #[cfg(target_arch = "x86")]
            core::arch::asm!(
                "mov BYTE PTR gs:interrupt@ntpoff, 0",
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

impl litebox::platform::SystemInfoProvider for LinuxUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as *const () as usize
    }

    fn get_vdso_address(&self) -> Option<usize> {
        if cfg!(target_arch = "x86") {
            // Enabling VDSO on x86 causes glibc to not set a restorer in signal
            // handlers, which we do not currently support. Disable VDSO for
            // now.
            //
            // TODO: implement VDSO in the shim, don't try to pass through the
            // platform VDSO.
            return None;
        }
        self.vdso_address
    }
}

thread_local! {
    // Use `ManuallyDrop` for more efficient TLS accesses, since this is always
    // dropped manually before the thread exits.
    static PLATFORM_TLS: Cell<*mut ()> = const { Cell::new(core::ptr::null_mut()) };
}

/// LinuxUserland platform's thread-local storage implementation.
unsafe impl litebox::platform::ThreadLocalStorageProvider for LinuxUserland {
    fn get_thread_local_storage() -> *mut () {
        PLATFORM_TLS.get()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        PLATFORM_TLS.replace(value)
    }

    #[cfg(target_arch = "x86_64")]
    fn clear_guest_thread_local_storage() {
        set_guest_fsbase(0);
    }

    #[cfg(target_arch = "x86")]
    fn clear_guest_thread_local_storage(selector: u16) {
        if selector != 0 {
            clear_thread_area(u32::from(selector) >> 3);
        }
    }
}

static mut NEXT_SA: [libc::sigaction; 64] = unsafe { core::mem::zeroed() };
static INTERRUPT_SIGNAL_NUMBER: AtomicI32 = AtomicI32::new(0);

fn register_exception_handlers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        fn sigaction(sig: i32, sa: Option<&libc::sigaction>, old_sa: &mut libc::sigaction) {
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

        let interrupt_signal = {
            // Find an RT signal number for interrupt handling.
            let sig = (libc::SIGRTMIN()..=libc::SIGRTMAX())
                .find(|&i| {
                    let mut old_sa = unsafe { core::mem::zeroed() };
                    sigaction(i, None, &mut old_sa);
                    old_sa.sa_sigaction == libc::SIG_DFL
                })
                .expect("no available real-time signal for interrupt handling");

            let mut sa: libc::sigaction = unsafe { core::mem::zeroed() };
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
            sa.sa_sigaction = interrupt_signal_handler as *const () as usize;
            let mut old_sa = unsafe { core::mem::zeroed() };
            sigaction(sig, Some(&sa), &mut old_sa);
            assert_eq!(
                old_sa.sa_sigaction,
                libc::SIG_DFL,
                "signal {sig} handler already installed",
            );
            INTERRUPT_SIGNAL_NUMBER.store(sig, Ordering::Relaxed);
            sig
        };

        let exception_signals = &[
            libc::SIGSEGV,
            libc::SIGBUS,
            libc::SIGFPE,
            libc::SIGILL,
            libc::SIGTRAP,
        ];
        for &sig in exception_signals {
            unsafe {
                let mut sa: libc::sigaction = core::mem::zeroed();
                sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
                sa.sa_sigaction = exception_signal_handler as *const () as usize;
                // Block the interrupt signal while handling exceptions to avoid
                // saving the exception signal handler state as guest state.
                libc::sigaddset(&raw mut sa.sa_mask, interrupt_signal);
                // Note: the handler could start running before this call even
                // returns, so pass `&mut NEXT_SA` directly.
                sigaction(
                    sig,
                    Some(&sa),
                    &mut NEXT_SA[sig.reinterpret_as_unsigned() as usize],
                );
            }
        }
    });
}

/// Runs `f` with an alternate signal stack set up.
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
        assert!(
            r >= 0,
            "failed to restore original signal stack: {}",
            std::io::Error::last_os_error()
        );
    });
    f()
}

/// Called from signal handlers to fix up thread state after potentially running
/// in the guest.
///
/// Restores the proper host `fsbase` so that TLS can be used. Clears `in_guest`
/// and optionally sets `interrupt`. If `in_guest` was previously set, returns
/// the guest context pointer (which does not necessarily have up-to-date guest
/// register state yet).
#[cfg(target_arch = "x86_64")]
fn signal_handler_exit_guest(
    _context: &libc::ucontext_t,
    set_interrupt: bool,
) -> Option<*mut litebox_common_linux::PtRegs> {
    unsafe {
        let gsbase: u64;
        core::arch::asm! {
            "rdgsbase {}", out(reg) gsbase
        };
        let is_in_guest = if gsbase == 0 {
            false
        } else {
            let in_guest: u8;
            core::arch::asm! {
                "mov {in_guest}, BYTE PTR gs:in_guest@tpoff",
                "mov BYTE PTR gs:in_guest@tpoff, 0",
                in_guest = out(reg_byte) in_guest,
                options(nostack, preserves_flags)
            }
            if set_interrupt {
                core::arch::asm! {
                    "mov BYTE PTR gs:interrupt@tpoff, 1",
                    options(nostack, preserves_flags)
                };
            }
            in_guest != 0
        };
        if !is_in_guest {
            return None;
        }

        let guest_context_top: *mut litebox_common_linux::PtRegs;
        core::arch::asm! {
            "wrfsbase {gsbase}",
            "mov {guest_context_top}, fs:guest_context_top@tpoff",
            gsbase = in(reg) gsbase,
            guest_context_top = out(reg) guest_context_top,
            options(nostack, preserves_flags)
        };
        Some(guest_context_top.offset(-1))
    }
}

/// Called from signal handlers to fix up thread state after potentially running
/// in the guest.
///
/// Restores the proper host `gs` so that TLS can be used. Clears `in_guest` and
/// optionally sets `interrupt`. If `in_guest` was previously set, returns the
/// guest context pointer (which does not necessarily have up-to-date guest
/// register state yet).
#[cfg(target_arch = "x86")]
fn signal_handler_exit_guest(
    context: &libc::ucontext_t,
    set_interrupt: bool,
) -> Option<*mut litebox_common_linux::PtRegs> {
    unsafe {
        let is_in_guest = if context.uc_mcontext.gregs[libc::REG_FS as usize] == 0 {
            false
        } else {
            let in_guest: u8;
            core::arch::asm! {
                "mov {in_guest}, BYTE PTR fs:in_guest@ntpoff",
                "mov BYTE PTR fs:in_guest@ntpoff, 0",
                in_guest = out(reg_byte) in_guest,
                options(nostack, preserves_flags)
            }
            if set_interrupt {
                core::arch::asm! {
                    "mov BYTE PTR fs:interrupt@ntpoff, 1",
                    options(nostack, preserves_flags)
                };
            }
            in_guest != 0
        };
        if !is_in_guest {
            return None;
        }

        let guest_context_top: *mut litebox_common_linux::PtRegs;
        core::arch::asm! {
            "mov gs, {gs}",
            "mov {guest_context_top}, gs:guest_context_top@ntpoff",
            gs = in(reg) context.uc_mcontext.gregs[libc::REG_FS as usize],
            guest_context_top = out(reg) guest_context_top,
            options(nostack, preserves_flags)
        };
        Some(guest_context_top.offset(-1))
    }
}

/// Copies register state from a Linux signal context to a LiteBox PtRegs
/// structure.
#[cfg(target_arch = "x86_64")]
fn copy_signal_context(regs: &mut litebox_common_linux::PtRegs, context: &libc::ucontext_t) {
    let litebox_common_linux::PtRegs {
        r15,
        r14,
        r13,
        r12,
        rbp,
        rbx,
        r11,
        r10,
        r9,
        r8,
        rax,
        rcx,
        rdx,
        rsi,
        rdi,
        orig_rax,
        rip,
        cs: _,
        eflags,
        rsp,
        ss: _,
    } = regs;
    for (reg, sig_reg) in [
        (r15, libc::REG_R15),
        (r14, libc::REG_R14),
        (r13, libc::REG_R13),
        (r12, libc::REG_R12),
        (rbp, libc::REG_RBP),
        (rbx, libc::REG_RBX),
        (r11, libc::REG_R11),
        (r10, libc::REG_R10),
        (r9, libc::REG_R9),
        (r8, libc::REG_R8),
        (rax, libc::REG_RAX),
        (rcx, libc::REG_RCX),
        (rdx, libc::REG_RDX),
        (rsi, libc::REG_RSI),
        (rdi, libc::REG_RDI),
        (rip, libc::REG_RIP),
        (rsp, libc::REG_RSP),
        (eflags, libc::REG_EFL),
    ] {
        *reg = context.uc_mcontext.gregs[sig_reg.reinterpret_as_unsigned() as usize]
            .reinterpret_as_unsigned()
            .truncate();
    }
    *orig_rax = *rax;
}

/// Copies register state from a Linux signal context to a LiteBox PtRegs
/// structure.
#[cfg(target_arch = "x86")]
fn copy_signal_context(regs: &mut litebox_common_linux::PtRegs, context: &libc::ucontext_t) {
    let litebox_common_linux::PtRegs {
        ebx,
        ecx,
        edx,
        esi,
        edi,
        ebp,
        eax,
        xds,
        xes,
        xfs: _,
        xgs,
        orig_eax,
        eip,
        xcs,
        eflags,
        esp,
        xss,
    } = regs;
    for (reg, sig_reg) in [
        (ebx, libc::REG_EBX),
        (ecx, libc::REG_ECX),
        (edx, libc::REG_EDX),
        (esi, libc::REG_ESI),
        (edi, libc::REG_EDI),
        (ebp, libc::REG_EBP),
        (eax, libc::REG_EAX),
        (eip, libc::REG_EIP),
        (eflags, libc::REG_EFL),
        (esp, libc::REG_ESP),
        (xds, libc::REG_DS),
        (xes, libc::REG_ES),
        (xgs, libc::REG_GS),
        (xss, libc::REG_SS),
        (xcs, libc::REG_CS),
    ] {
        *reg = context.uc_mcontext.gregs[sig_reg.reinterpret_as_unsigned() as usize]
            .reinterpret_as_unsigned() as usize;
    }
    *orig_eax = *eax;
}

/// Updates a Linux signal context to return to `f` with the given arguments.
#[cfg(target_arch = "x86_64")]
fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    p0: isize,
    p1: isize,
    p2: isize,
    p3: isize,
) {
    let sigctx = &mut context.uc_mcontext;
    sigctx.gregs[libc::REG_RIP as usize] = (f as usize).reinterpret_as_signed() as i64;
    sigctx.gregs[libc::REG_RDI as usize] = p0 as i64;
    sigctx.gregs[libc::REG_RSI as usize] = p1 as i64;
    sigctx.gregs[libc::REG_RDX as usize] = p2 as i64;
    sigctx.gregs[libc::REG_RCX as usize] = p3 as i64;
}

/// Updates a Linux signal context to return to `f` with the given arguments.
#[cfg(target_arch = "x86")]
fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    p0: isize,
    p1: isize,
    p2: isize,
    p3: isize,
) {
    let sigctx = &mut context.uc_mcontext;
    sigctx.gregs[libc::REG_EIP as usize] = (f as usize).reinterpret_as_signed().truncate();
    sigctx.gregs[libc::REG_EDI as usize] = p0.truncate();
    sigctx.gregs[libc::REG_ESI as usize] = p1.truncate();
    sigctx.gregs[libc::REG_EDX as usize] = p2.truncate();
    sigctx.gregs[libc::REG_ECX as usize] = p3.truncate();
    // Restore host `gs` from `fs`.
    sigctx.gregs[libc::REG_GS as usize] = sigctx.gregs[libc::REG_FS as usize];
}

/// Signal handler for hardware exceptions (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP).
unsafe extern "C" fn exception_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    let Some(regs) = signal_handler_exit_guest(context, false) else {
        return unsafe { next_signal_handler(signum, info, context) };
    };
    copy_signal_context(unsafe { &mut *regs }, context);

    // Ensure that `run_thread_arch` is linked in so that `exception_callback` is visible.
    let _ = run_thread_arch as *const () as usize;

    // Jump to exception_callback.
    let sigctx = &context.uc_mcontext;
    #[cfg(target_arch = "x86_64")]
    let (trapno, err, cr2) = (
        sigctx.gregs[libc::REG_TRAPNO as usize].truncate(),
        sigctx.gregs[libc::REG_ERR as usize].truncate(),
        sigctx.gregs[libc::REG_CR2 as usize].truncate(),
    );
    #[cfg(target_arch = "x86")]
    let (trapno, err, cr2) = (
        sigctx.gregs[libc::REG_TRAPNO as usize] as isize,
        sigctx.gregs[libc::REG_ERR as usize] as isize,
        sigctx.cr2.reinterpret_as_signed() as isize,
    );
    set_signal_return(context, exception_callback, 0, trapno, err, cr2);
}

/// Runs the next signal handler in the chain.
unsafe fn next_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    if signum == libc::SIGSEGV {
        let ip: usize = {
            #[cfg(target_arch = "x86_64")]
            {
                context.uc_mcontext.gregs[libc::REG_RIP as usize]
                    .reinterpret_as_unsigned()
                    .truncate()
            }
            #[cfg(target_arch = "x86")]
            {
                context.uc_mcontext.gregs[libc::REG_EIP as usize].reinterpret_as_unsigned() as usize
            }
        };
        if let Some(fixup_addr) = litebox::mm::exception_table::search_exception_tables(ip) {
            #[cfg(target_arch = "x86_64")]
            {
                context.uc_mcontext.gregs[libc::REG_RIP as usize] =
                    fixup_addr.reinterpret_as_signed() as i64;
            }
            #[cfg(target_arch = "x86")]
            {
                context.uc_mcontext.gregs[libc::REG_EIP as usize] =
                    fixup_addr.reinterpret_as_signed().truncate();
            }
            return;
        }
    }

    unsafe {
        let next_sa = &NEXT_SA[signum.reinterpret_as_unsigned() as usize];
        match next_sa.sa_sigaction {
            libc::SIG_DFL => {
                // Block this signal and raise.
                let mut set: libc::sigset_t = core::mem::zeroed();
                libc::sigemptyset(&raw mut set);
                libc::sigaddset(&raw mut set, signum);
                libc::sigprocmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
                libc::raise(signum);
                unreachable!()
            }
            libc::SIG_IGN => {}
            _ => {
                // Call the next handler
                if next_sa.sa_flags & libc::SA_SIGINFO == 0 {
                    let handler: extern "C" fn(libc::c_int) =
                        core::mem::transmute(next_sa.sa_sigaction);
                    handler(signum);
                } else {
                    let handler: extern "C" fn(
                        libc::c_int,
                        *mut libc::siginfo_t,
                        *mut libc::ucontext_t,
                    ) = core::mem::transmute(next_sa.sa_sigaction);
                    handler(signum, info, context);
                }
            }
        }
    }
}

/// Signal handler for interrupt signals.
unsafe fn interrupt_signal_handler(
    _signum: libc::c_int,
    _info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    // The interrupt signal can arrive in different contexts:
    // 1. The thread is running in the host at the beginning of the syscall
    //    handler. Do nothing--the syscall handler will handle the interrupt.
    // 2. The thread is running in the host, with in_guest = 0. Just record that
    //    an interrupt is pending; it will be checked next time we switch to the
    //    guest.
    // 3. The thread is running in the host, with in_guest = 1, in the middle of
    //    restoring the guest context. We need to jump to the interrupt handler
    //    without overwriting the saved guest context.
    // 4. The thread is running in the guest. We need to save the context and
    //    jump to the interrupt handler.
    //
    // Note that this signal can't arrive while in an exception signal handler
    // since we mask the interrupt signal while handling exceptions.

    #[cfg(target_arch = "x86_64")]
    let ip = context.uc_mcontext.gregs[libc::REG_RIP as usize]
        .reinterpret_as_unsigned()
        .truncate();
    #[cfg(target_arch = "x86")]
    let ip = context.uc_mcontext.gregs[libc::REG_EIP as usize].reinterpret_as_unsigned() as usize;

    // Case 1: at the beginning of the syscall handler.
    //
    // FUTURE: handle trampoline code, too. This is somewhat less important
    // because it's probably fine for the shim to observe a guest context that
    // is inside the trampoline.
    if ip == syscall_callback as *const () as usize {
        // No need to clear `in_guest` or set interrupt; the syscall handler will
        // clear `in_guest` and call into the shim.
        return;
    }

    // Clear `in_guest` and set `interrupt`.
    let Some(regs) = signal_handler_exit_guest(context, true) else {
        // Case 2: not in guest.
        return;
    };

    // If the interrupt happened while returning to the guest, don't overwrite
    // the saved context.
    let in_switch_to_guest = (switch_to_guest_start as *const () as usize
        ..switch_to_guest_end as *const () as usize)
        .contains(&ip);
    if in_switch_to_guest {
        // Case 3: in the middle of restoring guest context. Don't overwrite it.
    } else {
        // Case 4: in guest. Copy out the context.
        copy_signal_context(unsafe { &mut *regs }, context);
    }
    // Cases 3 and 4: jump to interrupt handler.
    set_signal_return(context, interrupt_callback, 0, 0, 0, 0);
}

impl litebox::platform::CrngProvider for LinuxUserland {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom failed");
    }
}

/// Dummy `VmapManager`.
///
/// In general, userland platforms do not support `vmap` and `vunmap` (which are kernel functions).
/// We might need to emulate these functions' behaviors using virtual addresses for development or
/// testing, or use a kernel module to provide this functionality (if needed).
impl<const ALIGN: usize> VmapManager<ALIGN> for LinuxUserland {}

/// Dummy `VmemPageFaultHandler`.
///
/// Page faults are handled transparently by the host Linux kernel.
/// Provided to satisfy trait bounds for `PageManager::handle_page_fault`.
impl litebox::mm::linux::VmemPageFaultHandler for LinuxUserland {
    unsafe fn handle_page_fault(
        &self,
        _fault_addr: usize,
        _flags: litebox::mm::linux::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unreachable!("host kernel handles page faults for Linux userland")
    }

    fn access_error(_error_code: u64, _flags: litebox::mm::linux::VmFlags) -> bool {
        unreachable!("host kernel handles page faults for Linux userland")
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    use std::thread::sleep;

    use litebox::platform::RawMutex;

    use crate::LinuxUserland;
    use litebox::platform::PageManagementProvider;

    extern crate std;

    #[test]
    fn test_raw_mutex() {
        let mutex = std::sync::Arc::new(super::RawMutex {
            inner: AtomicU32::new(0),
        });

        let copied_mutex = mutex.clone();
        std::thread::spawn(move || {
            sleep(core::time::Duration::from_millis(500));
            copied_mutex
                .inner
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            copied_mutex.wake_many(10);
        });

        assert!(mutex.block(0).is_ok());
    }

    #[test]
    fn test_reserved_pages() {
        let platform = LinuxUserland::new(None);
        let reserved_pages: Vec<_> =
            <LinuxUserland as PageManagementProvider<4096>>::reserved_pages(platform).collect();

        // Check that the reserved pages are in order and non-overlapping
        let mut prev = 0;
        for page in reserved_pages {
            assert!(page.start >= prev);
            assert!(page.end > page.start);
            prev = page.end;
        }
    }
}
