//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland FreeBSD.

// Restrict this crate to only work on FreeBSD. For now, we are restricting this to only x86/x86-64
// FreeBSD, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "freebsd", target_arch = "x86_64"))]

use core::sync::atomic::AtomicU32;
use core::time::Duration;

use litebox::fs::OFlags;
use litebox::platform::ImmediatelyWokenUp;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::trivial_providers::TransparentMutPtr;
use litebox::platform::{ThreadLocalStorageProvider, UnblockedOrTimedOut};
use litebox::utils::ReinterpretUnsignedExt as _;
use litebox_common_linux::{ProtFlags, PunchthroughSyscall};

pub mod syscall_raw;
use syscall_raw::syscalls;

mod freebsd_types;

extern crate alloc;

/// Connector to a shim-exposed syscall-handling interface.
pub type SyscallHandler = fn(litebox_common_linux::SyscallRequest<FreeBSDUserland>) -> isize;

/// The syscall handler passed down from the shim.
static SYSCALL_HANDLER: std::sync::RwLock<Option<SyscallHandler>> = std::sync::RwLock::new(None);

/// The userland FreeBSD platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct FreeBSDUserland {
    /// Reserved pages that are not available for guest programs to use.
    reserved_pages: Vec<core::ops::Range<usize>>,
}

const SELFPROC_MAPS_PATH: &str = "/proc/curproc/map";

impl FreeBSDUserland {
    /// Create a new userland-FreeBSD platform for use in `LiteBox`.
    ///
    /// # Panics
    ///
    /// Panics if the tun device could not be successfully opened.
    pub fn new(_tun_device_name: Option<&str>) -> &'static Self {
        let platform = Self {
            reserved_pages: Self::read_proc_self_maps(),
        };

        platform.set_init_tls();
        Box::leak(Box::new(platform))
    }

    /// Register the syscall handler (provided by the Linux shim)
    ///
    /// # Panics
    ///
    /// Panics if the function has already been invoked earlier.
    pub fn register_syscall_handler(&self, syscall_handler: SyscallHandler) {
        let old = SYSCALL_HANDLER.write().unwrap().replace(syscall_handler);
        assert!(
            old.is_none(),
            "Should not register more than one syscall_handler"
        );
    }

    fn read_proc_self_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
        // TODO: this function is same as the on in LinuxUserland and might have
        // similar issues to be resolved.

        let path = SELFPROC_MAPS_PATH;

        let c_path = match std::ffi::CString::new(path) {
            Ok(p) => p,
            Err(_) => return alloc::vec::Vec::new(),
        };

        let fd = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::Open,
                c_path.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };

        let fd = match fd {
            Ok(fd) => fd,
            Err(_) => return alloc::vec::Vec::new(),
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

        let content = match core::str::from_utf8(&buf[..total_read]) {
            Ok(s) => s,
            Err(_) => return alloc::vec::Vec::new(),
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

            let start = match usize::from_str_radix(start_str, 16) {
                Ok(addr) => addr,
                Err(_) => continue,
            };

            let end = match usize::from_str_radix(end_str, 16) {
                Ok(addr) => addr,
                Err(_) => continue,
            };

            if start <= end {
                reserved_pages.push(start..end);
            }
        }

        reserved_pages
    }

    fn get_user_info() -> litebox_common_linux::Credentials {
        litebox_common_linux::Credentials {
            uid: unsafe { syscalls::syscall0(syscalls::Sysno::Getuid) }.expect("getuid failed"),
            euid: unsafe { syscalls::syscall0(syscalls::Sysno::Geteuid) }.expect("geteuid failed"),
            gid: unsafe { syscalls::syscall0(syscalls::Sysno::Getgid) }.expect("getgid failed"),
            egid: unsafe { syscalls::syscall0(syscalls::Sysno::Getegid) }.expect("getegid failed"),
        }
    }

    fn set_init_tls(&self) {
        let mut tid: isize = 0;
        unsafe {
            syscalls::syscall1(syscalls::Sysno::ThrSelf, &mut tid as *mut isize as usize)
                .expect("thr_self failed");
        }

        let task = alloc::boxed::Box::new(litebox_common_linux::Task {
            tid: i32::try_from(tid).expect("tid should fit in i32"),
            clear_child_tid: None,
            robust_list: None,
            credentials: alloc::sync::Arc::new(Self::get_user_info()),
        });

        let tls = litebox_common_linux::ThreadLocalStorage::new(task);
        self.set_thread_local_storage(tls);
    }
}

impl litebox::platform::Provider for FreeBSDUserland {}

impl litebox::platform::ExitProvider for FreeBSDUserland {
    type ExitCode = i32;
    const EXIT_SUCCESS: Self::ExitCode = 0;
    const EXIT_FAILURE: Self::ExitCode = 1;

    fn exit(&self, code: Self::ExitCode) -> ! {
        let Self { reserved_pages: _ } = self;

        unsafe { syscalls::syscall1(syscalls::Sysno::Exit, code as usize) }
            .expect("Failed to exit group");

        unreachable!("exit_group should not return");
    }
}

impl litebox::platform::ThreadProvider for FreeBSDUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadArgs = litebox_common_linux::NewThreadArgs<FreeBSDUserland>;
    type ThreadSpawnError = litebox_common_linux::errno::Errno;
    type ThreadId = usize;

    #[expect(unused_variables)]
    #[expect(unused_mut)]
    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        stack: TransparentMutPtr<u8>,
        stack_size: usize,
        entry_point: usize,
        mut thread_args: Box<Self::ThreadArgs>,
    ) -> Result<usize, Self::ThreadSpawnError> {
        unimplemented!("spawn_thread is not implemented for FreeBSD yet.");
    }

    fn terminate_thread(&self, code: Self::ExitCode) -> ! {
        unimplemented!(
            "terminate_thread is not implemented for FreeBSD yet. code: {}",
            code
        );
    }
}

impl litebox::platform::RawMutexProvider for FreeBSDUserland {
    type RawMutex = RawMutex;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        RawMutex {
            inner: AtomicU32::new(0),
            num_to_wake_up: AtomicU32::new(0),
        }
    }
}

// A skeleton of a raw mutex for FreeBSD.
#[allow(dead_code)]
pub struct RawMutex {
    // The `inner` is the value shown to the outside world as an underlying atomic.
    inner: AtomicU32,
    num_to_wake_up: AtomicU32,
}

impl RawMutex {
    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        unimplemented!(
            "block_or_maybe_timeout is not implemented for FreeBSD yet. val: {}, timeout: {:?}",
            val,
            timeout
        );
    }
}

impl litebox::platform::RawMutex for RawMutex {
    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        unimplemented!("wake_many is not implemented for FreeBSD yet. n: {}", n);
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

impl litebox::platform::IPInterfaceProvider for FreeBSDUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        unimplemented!(
            "send_ip_packet is not implemented for FreeBSD yet. packet length: {}",
            packet.len()
        );
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        unimplemented!(
            "receive_ip_packet is not implemented for FreeBSD yet. packet length: {}",
            packet.len()
        );
    }
}

impl litebox::platform::TimeProvider for FreeBSDUserland {
    type Instant = Instant;

    fn now(&self) -> Self::Instant {
        Instant {
            inner: std::time::Instant::now(),
        }
    }
}

pub struct Instant {
    inner: std::time::Instant,
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        self.inner.checked_duration_since(earlier.inner)
    }
}

#[allow(dead_code)]
pub struct PunchthroughToken {
    punchthrough: PunchthroughSyscall<FreeBSDUserland>,
}

impl litebox::platform::PunchthroughToken for PunchthroughToken {
    type Punchthrough = PunchthroughSyscall<FreeBSDUserland>;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<
            <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnFailure,
        >,
    > {
        unimplemented!("punchthrough is not implemented for FreeBSDUserland");
    }
}

impl litebox::platform::PunchthroughProvider for FreeBSDUserland {
    type PunchthroughToken = PunchthroughToken;
    fn get_punchthrough_token_for(
        &self,
        punchthrough: <Self::PunchthroughToken as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
        Some(PunchthroughToken { punchthrough })
    }
}

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

impl litebox::platform::RawPointerProvider for FreeBSDUserland {
    type RawConstPointer<T: Clone> = litebox::platform::trivial_providers::TransparentConstPtr<T>;
    type RawMutPointer<T: Clone> = litebox::platform::trivial_providers::TransparentMutPtr<T>;
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

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for FreeBSDUserland {
    fn allocate_pages(
        &self,
        range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages: bool,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        // Use FreeBSD's mmap flags
        let map_flags = freebsd_types::MapFlags::MAP_PRIVATE
            | freebsd_types::MapFlags::MAP_ANONYMOUS
            | freebsd_types::MapFlags::MAP_FIXED
            | (if can_grow_down {
                freebsd_types::MapFlags::MAP_STACK
            } else {
                freebsd_types::MapFlags::empty()
            } | if populate_pages {
                freebsd_types::MapFlags::MAP_PREFAULT_READ
            } else {
                freebsd_types::MapFlags::empty()
            });

        let ptr = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::Mmap,
                range.start,
                range.len(),
                prot_flags(initial_permissions)
                    .bits()
                    .reinterpret_as_unsigned() as usize,
                map_flags.bits().reinterpret_as_unsigned() as usize,
                -1isize as usize,
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
        let _ = unsafe { syscalls::syscall2(syscalls::Sysno::Munmap, range.start, range.len()) }
            .expect("munmap failed");
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
        unimplemented!(
            "remap_pages is not implemented for FreeBSDUserland. old_range: {:?}, new_range: {:?}",
            old_range,
            new_range
        );
    }

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

#[global_allocator]
static SLAB_ALLOC: litebox::mm::allocator::SafeZoneAllocator<'static, 28, FreeBSDUserland> =
    litebox::mm::allocator::SafeZoneAllocator::new();

impl litebox::mm::allocator::MemoryProvider for FreeBSDUserland {
    fn alloc(layout: &std::alloc::Layout) -> Option<(usize, usize)> {
        let size = core::cmp::max(
            layout.size().next_power_of_two(),
            // Note `mmap` provides no guarantee of alignment, so we double the size to ensure we
            // can always find a required chunk within the returned memory region.
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

core::arch::global_asm!(
    "
    .text
    .align  4
    .globl  syscall_callback
    .type   syscall_callback,@function
syscall_callback:
    /* TODO: save float and vector registers (xsave or fxsave) */
    /* Save caller-saved registers */
    push    0x2b       /* pt_regs->ss = __USER_DS */
    push    rsp        /* pt_regs->sp */
    pushfq             /* pt_regs->eflags */
    push    0x33       /* pt_regs->cs = __USER_CS */
    push    rcx
    mov     rcx, [rsp + 0x28] /* get the return address from the stack */
    xchg    rcx, [rsp] /* pt_regs->ip */
    push    rax        /* pt_regs->orig_ax */

    push    rdi         /* pt_regs->di */
    push    rsi         /* pt_regs->si */
    push    rdx         /* pt_regs->dx */
    push    rcx         /* pt_regs->cx */
    push    -38         /* pt_regs->ax = ENOSYS */
    push    r8          /* pt_regs->r8 */
    push    r9          /* pt_regs->r9 */
    push    r10         /* pt_regs->r10 */
    push    r11         /* pt_regs->r11 */
    push    rbx         /* pt_regs->bx */
    push    rbp         /* pt_regs->bp */

    sub rsp, 32         /* skip r12-r15 */

    /* Save the original stack pointer */
    mov  rbp, rsp

    /* Align the stack to 16 bytes */
    and rsp, -16

    /* Pass the syscall number to the syscall dispatcher */
    mov rdi, rax
    /* Pass pt_regs saved on stack to syscall_dispatcher */
    mov rsi, rbp

    /* Call syscall_handler */
    call syscall_handler

    /* Restore the original stack pointer */
    mov  rsp, rbp
    add  rsp, 32         /* skip r12-r15 */

    /* Restore caller-saved registers */
    pop  rbp
    pop  rbx
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rcx             /* skip pt_regs->ax */
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi

    add  rsp, 24         /* skip orig_rax, rip, cs */
    popfq
    add  rsp, 16         /* skip rsp, ss */

    /* Return to the caller */
    ret
"
);

unsafe extern "C" {
    // Defined in asm blocks above
    fn syscall_callback() -> isize;
}

/// Handles Linux syscalls and dispatches them to LiteBox implementations.
///
/// # Safety
///
/// - The `ctx` pointer must be valid pointer to a `litebox_common_linux::PtRegs` structure.
/// - If any syscall argument is a pointer, it must be valid.
///
/// # Panics
///
/// Unsupported syscalls or arguments would trigger a panic for development purposes.
#[unsafe(no_mangle)]
unsafe extern "C" fn syscall_handler(
    syscall_number: usize,
    ctx: *mut litebox_common_linux::PtRegs,
) -> isize {
    // SAFETY: By the requirements of this function, it's safe to dereference a valid pointer to `PtRegs`.
    let ctx = unsafe { &mut *ctx };
    match litebox_common_linux::SyscallRequest::try_from_raw(syscall_number, ctx) {
        Ok(d) => {
            let syscall_handler: SyscallHandler = SYSCALL_HANDLER
                .read()
                .unwrap()
                .expect("Should have run `register_syscall_handler` by now");
            syscall_handler(d)
        }
        Err(err) => err.as_neg() as isize,
    }
}

impl litebox::platform::SystemInfoProvider for FreeBSDUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as usize
    }
}

impl FreeBSDUserland {
    fn get_thread_local_storage() -> *mut litebox_common_linux::ThreadLocalStorage<FreeBSDUserland>
    {
        let tls = unsafe { litebox_common_linux::rdgsbase() };
        if tls == 0 {
            return core::ptr::null_mut();
        }
        tls as *mut litebox_common_linux::ThreadLocalStorage<FreeBSDUserland>
    }
}

/// Similar to libc, we use fs/gs registers to store thread-local storage (TLS).
/// To avoid conflicts with libc's TLS, we choose to use gs on x86_64 and fs on x86
/// as libc uses fs on x86_64 and gs on x86.
impl litebox::platform::ThreadLocalStorageProvider for FreeBSDUserland {
    // todo(chuqi): we may change the TLS type later on to adapt FreeBSD's robust_list
    // tbd anyways
    type ThreadLocalStorage = litebox_common_linux::ThreadLocalStorage<FreeBSDUserland>;

    fn set_thread_local_storage(&self, tls: Self::ThreadLocalStorage) {
        let old_gs_base = unsafe { litebox_common_linux::rdgsbase() };
        assert!(old_gs_base == 0, "TLS already set for this thread");
        let tls = Box::new(tls);
        unsafe { litebox_common_linux::wrgsbase(Box::into_raw(tls) as usize) };
    }

    fn release_thread_local_storage(&self) -> Self::ThreadLocalStorage {
        let tls = Self::get_thread_local_storage();
        assert!(!tls.is_null(), "TLS must be set before releasing it");
        unsafe {
            litebox_common_linux::wrgsbase(0);
        }
        let tls = unsafe { Box::from_raw(tls) };
        assert!(!tls.borrowed, "TLS must not be borrowed when releasing it");
        *tls
    }

    fn with_thread_local_storage_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::ThreadLocalStorage) -> R,
    {
        let tls = Self::get_thread_local_storage();
        assert!(!tls.is_null(), "TLS must be set before accessing it");
        let tls = unsafe { &mut *tls };
        assert!(!tls.borrowed, "TLS is already borrowed");
        tls.borrowed = true; // Mark as borrowed
        let res = f(tls);
        tls.borrowed = false; // Mark as not borrowed anymore
        res
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    use litebox::platform::RawMutex;
    use litebox::platform::ThreadLocalStorageProvider as _;
    use std::thread::sleep;

    use crate::FreeBSDUserland;
    use litebox::platform::{DebugLogProvider, PageManagementProvider};

    extern crate std;

    #[test]
    fn test_raw_mutex() {
        let mutex = std::sync::Arc::new(super::RawMutex {
            inner: AtomicU32::new(0),
            num_to_wake_up: AtomicU32::new(0),
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

    #[test]
    fn test_tls() {
        let platform = FreeBSDUserland::new(None);
        let tls = FreeBSDUserland::get_thread_local_storage();
        assert!(!tls.is_null(), "TLS should not be null");
        let tid = unsafe { (*tls).current_task.tid };

        platform.with_thread_local_storage_mut(|tls| {
            assert_eq!(
                tls.current_task.tid, tid,
                "TLS should have the correct task ID"
            );
            tls.current_task.tid = 0x1234; // Change the task ID
        });
        let tls = platform.release_thread_local_storage();
        assert_eq!(
            tls.current_task.tid, 0x1234,
            "TLS should have the correct task ID"
        );

        let tls = FreeBSDUserland::get_thread_local_storage();
        assert!(tls.is_null(), "TLS should be null after releasing it");
    }
}
