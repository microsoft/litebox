//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Linux.

// Restrict this crate to only work on Linux. For now, we are restricting this to only x86/x86-64
// Linux, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "x86")))]

use std::cell::Cell;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;

use litebox::fs::OFlags;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::{ImmediatelyWokenUp, RawConstPointer};
use litebox::utils::{ReinterpretSignedExt, ReinterpretUnsignedExt as _, TruncateExt};
use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, PunchthroughSyscall};

mod syscall_intercept;

extern crate alloc;

cfg_if::cfg_if! {
    if #[cfg(feature = "linux_syscall")] {
        use litebox_common_linux::ContinueOperation;
        pub type SyscallReturnType = litebox_common_linux::ContinueOperation;
    } else if #[cfg(feature = "optee_syscall")] {
        use litebox_common_optee::ContinueOperation;
        pub type SyscallReturnType = litebox_common_optee::ContinueOperation;
    } else {
        compile_error!(r##"No syscall handler specified."##);
    }
}
/// The syscall handler passed down from the shim.
static SHIM: std::sync::OnceLock<
    &'static dyn litebox::shim::EnterShim<
        ExecutionContext = litebox_common_linux::PtRegs,
        ContinueOperation = ContinueOperation,
    >,
> = const { std::sync::OnceLock::new() };

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

    /// Register the syscall handler (provided by the Linux shim)
    ///
    /// # Panics
    ///
    /// Panics if the function has already been invoked earlier.
    pub fn register_shim(
        &self,
        shim: &'static dyn litebox::shim::EnterShim<
            ExecutionContext = litebox_common_linux::PtRegs,
            ContinueOperation = ContinueOperation,
        >,
    ) {
        SHIM.set(shim)
            .ok()
            .expect("Should not register more than one shim");
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
            if let Some(last) = parts.last()
                && *last == "[vdso]"
            {
                vdso_address = Some(start);
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
            tid,
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
}

impl litebox::platform::Provider for LinuxUserland {}

/// Runs a guest thread with the given initial context.
///
/// This will run until the thread terminates.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread(ctx: &mut litebox_common_linux::PtRegs) {
    with_signal_alt_stack(|| unsafe { run_thread_inner(ctx) });
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
    .quad 0
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
unsafe extern "C-unwind" fn run_thread_inner(ctx: &mut litebox_common_linux::PtRegs) {
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
    push r15 // align

    // Save host rsp and rbp and guest context top in TLS.
    mov fs:host_sp@tpoff, rsp
    mov fs:host_bp@tpoff, rbp
    lea r8, [rdi + {GUEST_CONTEXT_SIZE}]
    mov fs:guest_context_top@tpoff, r8

    // Save host fs base in gs base. This will stay set for the lifetime
    // of this call stack.
    rdfsbase r8
    wrgsbase r8

    // Switch to the guest context. When the guest issues a syscall, it will
    // jump back into the middle of this function, at `syscall_callback`.
    call {switch_to_guest}
    ud2

    // This entry point is called from the guest when it issues a syscall
    // instruction.
    //
    // At entry, the register context is the guest context with the
    // return address in rcx. r11 is an available scratch register (it would
    // contain rflags if the syscall instruction had actually been issued).
    .globl syscall_callback
syscall_callback:
    // Restore host fs base.
    rdfsbase r11
    mov      gs:guest_fsbase@tpoff, r11
    rdgsbase r11
    wrfsbase r11

    // Clear in_guest flag.
    mov     BYTE PTR fs:in_guest@tpoff, 0

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

    // Pass pt_regs to syscall_handler.
    mov     rdi, rsp

    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    // Handle the syscall. This will jump back to the guest but
    // will return if the thread is exiting.
    call {syscall_handler}
    // This thread is done. Return.
    jmp .Ldone

exception_callback:
    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    call {exception_handler}

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
    syscall_handler = sym syscall_handler,
    exception_handler = sym exception_handler,
    switch_to_guest = sym switch_to_guest,
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
unsafe extern "fastcall-unwind" fn run_thread_inner(ctx: &mut litebox_common_linux::PtRegs) {
    core::arch::naked_asm!(
    "
    .cfi_startproc
    push    ebp
    mov ebp, esp
    .cfi_def_cfa ebp, 8
    push ebx
    push esi
    push edi
    sub esp, 12 // align

    // Save host esp and ebp and guest context top in TLS
    mov gs:host_sp@ntpoff, esp
    mov gs:host_bp@ntpoff, ebp
    lea edi, [ecx + {GUEST_CONTEXT_SIZE}]
    mov gs:guest_context_top@ntpoff, edi

    // Save host gs in fs
    mov ax, gs
    mov fs, ax

    // Switch to the guest context. When the guest issues a syscall, it will
    // jump back into the middle of this function, at `syscall_callback`.
    call {switch_to_guest}
    ud2

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

    // Pass the pointer to pt_regs to syscall_handler.
    mov ecx, esp

    // Restore esp and ebp
    mov esp, fs:host_sp@ntpoff
    mov ebp, fs:host_bp@ntpoff

    // Switch to host gs
    mov ax, fs
    mov gs, ax

    // Handle the syscall. This will jump back to the guest but
    // will return if the thread is exiting.
    call {syscall_handler_fast}
    jmp .Ldone

exception_callback:
    // Restore esp and ebp
    mov esp, gs:host_sp@ntpoff
    mov ebp, gs:host_bp@ntpoff

    push ecx
    push edx
    push esi
    push edi
    call {exception_handler}

.Ldone:

    lea  esp, [ebp - 3*4]
    pop  edi
    pop  esi
    pop  ebx
    pop  ebp
    .cfi_def_cfa esp, 4
    ret
    .cfi_endproc
",
    GUEST_CONTEXT_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
    syscall_handler_fast = sym syscall_handler_fast,
    exception_handler = sym exception_handler,
    switch_to_guest = sym switch_to_guest,
        );
}

/// Wrapper around `syscall_handler` to use the fastcall convention.
#[cfg(target_arch = "x86")]
unsafe extern "fastcall-unwind" fn syscall_handler_fast(ctx: &mut litebox_common_linux::PtRegs) {
    unsafe { syscall_handler(ctx) }
}

/// Switches to the provided guest context.
///
/// # Safety
/// The context must be valid guest context. This can only be called if
/// `run_thread_inner` is on the stack; after the guest exits, it will return to
/// the interior of `run_thread_inner`.
///
/// Do not call this at a point where the stack needs to be unwound to run
/// destructors.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    unsafe {
        core::arch::asm!(
            "mov rsp, {ctx}",
            // Switch to the guest fsbase
            "mov BYTE PTR fs:in_guest@tpoff, 1",
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
            "add rsp, 8", // skip orig_rax
            "pop gs:scratch@tpoff", // read rip into scratch
            "add rsp, 8", // skip cs
            "popfq",
            "pop rsp",
            "jmp gs:scratch@tpoff", // jump to the guest
            ctx = in(reg) ctx,
            options(noreturn, nostack),
        );
    }
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
    .long 0
    "
);

#[cfg(target_arch = "x86")]
unsafe extern "fastcall" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    unsafe {
        core::arch::asm!(
            "mov esp, {ctx}",
            "mov BYTE PTR gs:in_guest@ntpoff, 1",
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
            ctx = in(reg) ctx,
            options(noreturn, nostack)
        );
    }
}

fn thread_start(
    init_thread: Box<dyn litebox::shim::InitThread>,
    mut ctx: litebox_common_linux::PtRegs,
) {
    // Allow caller to run some code before we return to the new thread.
    init_thread.init();

    unsafe { run_thread(&mut ctx) };
    // TODO: have syscall_callback return if we need to terminate the process.
    // We should return this value to the caller so load_program can return it
    // to the user.
}

impl litebox::platform::ThreadProvider for LinuxUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = litebox_common_linux::errno::Errno;

    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        init_thread: Box<dyn litebox::shim::InitThread>,
    ) -> Result<(), Self::ThreadSpawnError> {
        let ctx = *ctx;
        // TODO: do we need to wait for the handle in the main thread?
        let _handle = std::thread::spawn(move || thread_start(init_thread, ctx));

        Ok(())
    }
}

impl litebox::platform::RawMutexProvider for LinuxUserland {
    type RawMutex = RawMutex;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        RawMutex {
            inner: AtomicU32::new(0),
        }
    }
}

pub struct RawMutex {
    // The `inner` is the value shown to the outside world as an underlying atomic.
    inner: AtomicU32,
}

impl RawMutex {
    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // We immediately wake up (without even hitting syscalls) if we can clearly see that the
        // value is different.
        if self.inner.load(SeqCst) != val {
            return Err(ImmediatelyWokenUp);
        }

        // We wait on the futex, with a timeout if needed
        match futex_timeout(
            &self.inner,
            FutexOperation::Wait,
            /* expected value */ val,
            timeout,
            /* ignored */ None,
        ) {
            Ok(0) => Ok(UnblockedOrTimedOut::Unblocked),
            Err(syscalls::Errno::EAGAIN) => Err(ImmediatelyWokenUp),
            Err(syscalls::Errno::ETIMEDOUT) => Ok(UnblockedOrTimedOut::TimedOut),
            Err(e) => {
                panic!("Unexpected errno={e} for FUTEX_WAIT")
            }
            _ => unreachable!(),
        }
    }
}

impl litebox::platform::RawMutex for RawMutex {
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
            inner: litebox_common_linux::Timespec {
                tv_sec: i64::from(t.tv_sec),
                tv_nsec: u64::from(t.tv_nsec.reinterpret_as_unsigned()),
            },
        }
    }

    fn current_time(&self) -> Self::SystemTime {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        SystemTime {
            #[cfg_attr(target_arch = "x86_64", expect(clippy::useless_conversion))]
            inner: litebox_common_linux::Timespec {
                tv_sec: i64::from(t.tv_sec),
                tv_nsec: u64::from(t.tv_nsec.reinterpret_as_unsigned()),
            },
        }
    }
}

pub struct Instant {
    inner: litebox_common_linux::Timespec,
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        self.inner.sub_timespec(&earlier.inner).ok()
    }
}

impl From<litebox_common_linux::Timespec> for Instant {
    fn from(inner: litebox_common_linux::Timespec) -> Self {
        Instant { inner }
    }
}

pub struct SystemTime {
    inner: litebox_common_linux::Timespec,
}

impl litebox::platform::SystemTime for SystemTime {
    const UNIX_EPOCH: Self = SystemTime {
        inner: litebox_common_linux::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        self.inner
            .sub_timespec(&earlier.inner)
            .map_err(|_errno| earlier.inner.sub_timespec(&self.inner).unwrap())
    }
}

#[cfg(target_arch = "x86")]
fn set_thread_area(
    user_desc: litebox::platform::trivial_providers::TransparentMutPtr<
        litebox_common_linux::UserDesc,
    >,
) -> Result<usize, litebox_common_linux::errno::Errno> {
    unsafe { syscalls::syscall1(syscalls::Sysno::set_thread_area, user_desc.as_usize()) }.map_err(
        |err| match err {
            syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
            syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
            syscalls::Errno::ENOSYS => litebox_common_linux::errno::Errno::ENOSYS,
            syscalls::Errno::ESRCH => litebox_common_linux::errno::Errno::ESRCH,
            _ => panic!("unexpected error {err}"),
        },
    )
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
    let user_desc_ptr = litebox::platform::trivial_providers::TransparentMutPtr {
        inner: &raw mut user_desc,
    };

    set_thread_area(user_desc_ptr).expect("failed to clear TLS entry");
}

pub struct PunchthroughToken {
    punchthrough: PunchthroughSyscall<LinuxUserland>,
}

impl litebox::platform::PunchthroughToken for PunchthroughToken {
    type Punchthrough = PunchthroughSyscall<LinuxUserland>;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<
            <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnFailure,
        >,
    > {
        match self.punchthrough {
            PunchthroughSyscall::RtSigprocmask { how, set, oldset } => {
                let set = match set {
                    Some(ptr) => {
                        let mut set = unsafe { ptr.read_at_offset(0) }
                            .ok_or(litebox::platform::PunchthroughError::Failure(
                                litebox_common_linux::errno::Errno::EFAULT,
                            ))?
                            .into_owned();
                        // never block SIGSYS (required by Seccomp to intercept syscalls)
                        set.remove(litebox_common_linux::Signal::SIGSYS);
                        Some(set)
                    }
                    None => None,
                };
                unsafe {
                    syscalls::syscall5(
                        syscalls::Sysno::rt_sigprocmask,
                        how as usize,
                        if let Some(set) = set.as_ref() {
                            core::ptr::from_ref(set) as usize
                        } else {
                            0
                        },
                        oldset.map_or(0, |ptr| ptr.as_usize()),
                        size_of::<litebox_common_linux::SigSet>(),
                        // Unused by the syscall but would be checked by Seccomp filter if enabled.
                        syscall_intercept::SYSCALL_ARG_MAGIC,
                    )
                }
                .map_err(|err| match err {
                    syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
                    syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                    _ => panic!("unexpected error {err}"),
                })
                .map_err(litebox::platform::PunchthroughError::Failure)
            }
            PunchthroughSyscall::RtSigaction {
                signum,
                act,
                oldact,
            } => {
                if signum == litebox_common_linux::Signal::SIGSYS && act.is_some() {
                    // don't allow changing the SIGSYS handler
                    return Err(litebox::platform::PunchthroughError::Failure(
                        litebox_common_linux::errno::Errno::EINVAL,
                    ));
                }

                let act = act.map_or(0, |ptr| ptr.as_usize());
                let oldact = oldact.map_or(0, |ptr| ptr.as_usize());
                unsafe {
                    syscalls::syscall4(
                        syscalls::Sysno::rt_sigaction,
                        signum as usize,
                        act,
                        oldact,
                        size_of::<litebox_common_linux::SigSet>(),
                    )
                }
                .map_err(|err| match err {
                    syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
                    syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                    _ => panic!("unexpected error {err}"),
                })
                .map_err(litebox::platform::PunchthroughError::Failure)
            }
            PunchthroughSyscall::RtSigreturn { stack } => {
                // The stack pointer should point to a `ucontext` structure.
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    core::arch::asm!(
                        "mov rsp, {0}",
                        "syscall", // invokes rt_sigreturn
                        in(reg) stack,
                        in("rax") syscalls::Sysno::rt_sigreturn as usize,
                        options(noreturn)
                    );
                }
                #[cfg(target_arch = "x86")]
                unsafe {
                    core::arch::asm!(
                        "mov esp, {0}",
                        "int 0x80", // invokes rt_sigreturn
                        in(reg) stack,
                        in("rax") syscalls::Sysno::rt_sigreturn as usize,
                        options(noreturn)
                    );
                }
            }
            // We swap gs and fs before and after a syscall so at this point guest's fs base is stored in gs
            #[cfg(target_arch = "x86_64")]
            PunchthroughSyscall::SetFsBase { addr } => {
                set_guest_fsbase(addr);
                Ok(0)
            }
            #[cfg(target_arch = "x86_64")]
            PunchthroughSyscall::GetFsBase { addr } => {
                use litebox::platform::RawMutPointer as _;
                let fs_base = get_guest_fsbase();
                unsafe { addr.write_at_offset(0, fs_base) }.ok_or(
                    litebox::platform::PunchthroughError::Failure(
                        litebox_common_linux::errno::Errno::EFAULT,
                    ),
                )?;
                Ok(0)
            }
            #[cfg(target_arch = "x86")]
            PunchthroughSyscall::SetThreadArea { user_desc } => {
                set_thread_area(user_desc).map_err(litebox::platform::PunchthroughError::Failure)
            }
            PunchthroughSyscall::Alarm { seconds } => unsafe {
                let remain = syscalls::syscall2(
                    syscalls::Sysno::alarm,
                    seconds as usize,
                    // Unused by the syscall but would be checked by Seccomp filter if enabled.
                    syscall_intercept::SYSCALL_ARG_MAGIC,
                )
                .expect("failed to set alarm");
                Ok(remain)
            },
            PunchthroughSyscall::ThreadKill {
                thread_group_id,
                thread_id,
                sig,
            } => unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::tgkill,
                    thread_group_id.reinterpret_as_unsigned() as usize,
                    thread_id.reinterpret_as_unsigned() as usize,
                    (sig as i32 as isize).reinterpret_as_unsigned(),
                )
            }
            .map_err(|err| match err {
                syscalls::Errno::EAGAIN => litebox_common_linux::errno::Errno::EAGAIN,
                syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                syscalls::Errno::EPERM => litebox_common_linux::errno::Errno::EPERM,
                syscalls::Errno::ESRCH => litebox_common_linux::errno::Errno::ESRCH,
                _ => panic!("unexpected error {err}"),
            })
            .map_err(litebox::platform::PunchthroughError::Failure),
            PunchthroughSyscall::SetITimer {
                which,
                new_value,
                old_value,
            } => unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::setitimer,
                    which as usize,
                    new_value.as_usize(),
                    if let Some(old_value) = old_value {
                        old_value.as_usize()
                    } else {
                        0
                    },
                )
            }
            .map_err(|err| match err {
                syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
                syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                _ => panic!("unexpected error {err}"),
            })
            .map_err(litebox::platform::PunchthroughError::Failure),
        }
    }
}

impl litebox::platform::PunchthroughProvider for LinuxUserland {
    type PunchthroughToken = PunchthroughToken;
    fn get_punchthrough_token_for(
        &self,
        punchthrough: <Self::PunchthroughToken as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
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

impl litebox::platform::RawPointerProvider for LinuxUserland {
    type RawConstPointer<T: Clone> = litebox::platform::trivial_providers::TransparentConstPtr<T>;
    type RawMutPointer<T: Clone> = litebox::platform::trivial_providers::TransparentMutPtr<T>;
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
            syscalls::Sysno::futex,
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
            syscalls::Sysno::futex,
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
    #[cfg(target_arch = "x86")]
    const TASK_ADDR_MAX: usize = 0xC000_0000; // 3 GiB (see arch/x86/include/asm/page_32_types.h)

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address: bool,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let flags = MapFlags::MAP_PRIVATE
            | MapFlags::MAP_ANONYMOUS
            | (if fixed_address {
                MapFlags::MAP_FIXED
            } else {
                MapFlags::empty()
            } | if can_grow_down {
                MapFlags::MAP_GROWSDOWN
            } else {
                MapFlags::empty()
            } | if populate_pages_immediately {
                MapFlags::MAP_POPULATE
            } else {
                MapFlags::empty()
            });
        let ptr = unsafe {
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
        }
        .expect("mmap failed");
        Ok(litebox::platform::trivial_providers::TransparentMutPtr {
            inner: ptr as *mut u8,
        })
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
        Ok(litebox::platform::trivial_providers::TransparentMutPtr {
            inner: res as *mut u8,
        })
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

#[global_allocator]
static SLAB_ALLOC: litebox::mm::allocator::SafeZoneAllocator<'static, 28, LinuxUserland> =
    litebox::mm::allocator::SafeZoneAllocator::new();

impl litebox::mm::allocator::MemoryProvider for LinuxUserland {
    fn alloc(layout: &std::alloc::Layout) -> Option<(usize, usize)> {
        let size = core::cmp::max(
            layout.size().next_power_of_two(),
            // Note `mmap` provides no guarantee of alignment, so we double the size to ensure we
            // can always find a required chunk within the returned memory region.
            core::cmp::max(layout.align(), 0x1000) << 1,
        );
        unsafe {
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
                0,
                size,
                ProtFlags::PROT_READ_WRITE.bits().reinterpret_as_unsigned() as usize,
                ((MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON)
                    .bits()
                    .reinterpret_as_unsigned()
                    // This is to ensure it won't be intercepted by Seccomp if enabled.
                    | syscall_intercept::MMAP_FLAG_MAGIC) as usize,
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

unsafe extern "C" {
    // Defined in asm blocks above
    fn syscall_callback() -> isize;
    fn exception_callback();
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
unsafe extern "C-unwind" fn syscall_handler(ctx: &mut litebox_common_linux::PtRegs) {
    let &shim = SHIM
        .get()
        .expect("should have called `register_shim` by now");
    continue_operation(shim.syscall(ctx), ctx);
}

extern "C-unwind" fn exception_handler(
    ctx: &mut litebox_common_linux::PtRegs,
    trapno: usize,
    error: usize,
    cr2: usize,
) {
    let info = litebox::shim::ExceptionInfo {
        exception: litebox::shim::Exception(trapno.try_into().unwrap()),
        error_code: error.try_into().unwrap(),
        cr2,
    };
    let shim = SHIM
        .get()
        .expect("should have called `register_shim` by now");
    continue_operation(shim.exception(ctx, &info), ctx);
}

fn continue_operation(op: ContinueOperation, ctx: &mut litebox_common_linux::PtRegs) {
    match op {
        ContinueOperation::ResumeGuest => unsafe { switch_to_guest(ctx) },
        ContinueOperation::ExitThread(status) | ContinueOperation::ExitProcess(status) => {
            #[cfg(target_arch = "x86_64")]
            {
                cfg_if::cfg_if! {
                    if #[cfg(feature = "linux_syscall")] {
                        ctx.rax = status.reinterpret_as_unsigned() as usize;
                    } else if #[cfg(feature = "optee_syscall")] {
                        ctx.rax = status;
                    }
                }
            }
            #[cfg(target_arch = "x86")]
            {
                ctx.eax = status.reinterpret_as_unsigned() as usize;
            }
        }
    }
}

impl litebox::platform::SystemInfoProvider for LinuxUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as usize
    }

    fn get_vdso_address(&self) -> Option<usize> {
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

fn register_exception_handlers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
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
                sa.sa_sigaction = exception_signal_handler as usize;
                let r = libc::sigaction(
                    sig,
                    &raw const sa,
                    &raw mut NEXT_SA[sig.reinterpret_as_unsigned() as usize],
                );
                assert!(
                    r >= 0,
                    "failed to register exception handler for signal {}: {}",
                    sig,
                    std::io::Error::last_os_error()
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
        let stack_base = libc::mmap(
            std::ptr::null_mut(),
            guard_page_size + alt_stack_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert!(
            stack_base != libc::MAP_FAILED,
            "failed to allocate memory for alternate signal stack: {}",
            std::io::Error::last_os_error()
        );
        // Set up a guard page to catch stack overflows.
        let r = libc::mprotect(stack_base, guard_page_size, libc::PROT_NONE);
        assert!(
            r == 0,
            "failed to set guard page for alternate signal stack: {}",
            std::io::Error::last_os_error()
        );
        stack_base
    };
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
    let r = f();
    unsafe {
        let r = libc::sigaltstack(&raw const oss, std::ptr::null_mut());
        assert!(
            r >= 0,
            "failed to restore original signal stack: {}",
            std::io::Error::last_os_error()
        );
        let r = libc::munmap(stack_base, guard_page_size + alt_stack_size);
        assert!(
            r == 0,
            "failed to free memory for alternate signal stack: {}",
            std::io::Error::last_os_error()
        );
    }
    r
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn exception_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    let regs = unsafe {
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
            in_guest != 0
        };
        if !is_in_guest {
            return next_signal_handler(signum, info, context);
        }

        let guest_context_top: *mut litebox_common_linux::PtRegs;
        core::arch::asm! {
            "wrfsbase {gsbase}",
            "mov {guest_context_top}, fs:guest_context_top@tpoff",
            gsbase = in(reg) gsbase,
            guest_context_top = out(reg) guest_context_top,
            options(nostack, preserves_flags)
        };
        &mut *guest_context_top.offset(-1)
    };
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
    let sigctx = &mut context.uc_mcontext;
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
        *reg = sigctx.gregs[sig_reg.reinterpret_as_unsigned() as usize]
            .reinterpret_as_unsigned()
            .truncate();
    }
    *orig_rax = *rax;

    // Ensure that `run_thread` is linked in so that `exception_callback` is visible.
    let _ = run_thread as usize;

    // Jump to exception_callback.
    sigctx.gregs[libc::REG_RIP as usize] =
        (exception_callback as usize).reinterpret_as_signed() as i64;
    sigctx.gregs[libc::REG_RDI as usize] = core::ptr::from_mut(regs) as i64;
    sigctx.gregs[libc::REG_RSI as usize] = sigctx.gregs[libc::REG_TRAPNO as usize];
    sigctx.gregs[libc::REG_RDX as usize] = sigctx.gregs[libc::REG_ERR as usize];
    sigctx.gregs[libc::REG_RCX as usize] = sigctx.gregs[libc::REG_CR2 as usize];
}

#[cfg(target_arch = "x86")]
unsafe extern "C" fn exception_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    let regs = unsafe {
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
            in_guest != 0
        };
        if !is_in_guest {
            return next_signal_handler(signum, info, context);
        }

        let guest_context_top: *mut litebox_common_linux::PtRegs;
        core::arch::asm! {
            "mov {guest_context_top}, fs:guest_context_top@ntpoff",
            guest_context_top = out(reg) guest_context_top,
            options(nostack, preserves_flags)
        };
        &mut *guest_context_top.offset(-1)
    };
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
    let sigctx = &mut context.uc_mcontext;
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
        *reg = sigctx.gregs[sig_reg.reinterpret_as_unsigned() as usize].reinterpret_as_unsigned()
            as usize;
    }
    *orig_eax = *eax;

    // Ensure that `run_thread` is linked in so that `exception_callback` is visible.
    let _ = run_thread as usize;

    // Jump to exception_callback.
    sigctx.gregs[libc::REG_EIP as usize] = (exception_callback as usize)
        .reinterpret_as_signed()
        .truncate();
    sigctx.gregs[libc::REG_GS as usize] = sigctx.gregs[libc::REG_FS as usize];
    sigctx.gregs[libc::REG_EDI as usize] = core::ptr::from_mut(regs) as i32;
    sigctx.gregs[libc::REG_ESI as usize] = sigctx.gregs[libc::REG_TRAPNO as usize];
    sigctx.gregs[libc::REG_EDX as usize] = sigctx.gregs[libc::REG_ERR as usize];
    sigctx.gregs[libc::REG_ECX as usize] = sigctx.cr2.reinterpret_as_signed();
}

unsafe fn next_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
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
