//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Windows.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use core::sync::atomic::AtomicU32;
use core::time::Duration;
use std::os::raw::c_void;

use litebox::platform::ImmediatelyWokenUp;
use litebox::platform::ThreadLocalStorageProvider;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::trivial_providers::TransparentMutPtr;
use litebox_common_linux::PunchthroughSyscall;

use windows_sys::Win32::{
    Foundation::{GetLastError, WIN32_ERROR},
    System::Memory::{
        self as Win32_Memory, PrefetchVirtualMemory, VirtualAlloc2, VirtualFree, VirtualProtect,
    },
    System::SystemInformation::{self as Win32_SysInfo},
    System::Threading::{
        self as Win32_Threading, GetCurrentProcess, TlsAlloc, TlsFree, TlsGetValue, TlsSetValue,
    },
};

extern crate alloc;

/// Connector to a shim-exposed syscall-handling interface.
pub type SyscallHandler = fn(litebox_common_linux::SyscallRequest<WindowsUserland>) -> isize;

/// The syscall handler passed down from the shim.
static SYSCALL_HANDLER: std::sync::RwLock<Option<SyscallHandler>> = std::sync::RwLock::new(None);

struct TlsSlot {
    dwtlsindex: u32,
}

impl TlsSlot {
    fn new() -> Result<Self, WIN32_ERROR> {
        let tls_index = unsafe { TlsAlloc() };
        if tls_index == Win32_Threading::TLS_OUT_OF_INDEXES {
            Err(unsafe { GetLastError() })
        } else {
            Ok(Self {
                dwtlsindex: tls_index,
            })
        }
    }
}

impl Drop for TlsSlot {
    fn drop(&mut self) {
        // Free the TLS index when the slot is dropped
        unsafe {
            TlsFree(self.dwtlsindex);
        }
    }
}

/// The userland Windows platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct WindowsUserland {
    tls_slot: TlsSlot,
    reserved_pages: alloc::vec::Vec<core::ops::Range<usize>>,
    sys_info: std::sync::RwLock<Win32_SysInfo::SYSTEM_INFO>,
}

// Safety: Given that SYSTEM_INFO is not Send/Sync (it contains *mut c_void), we use RwLock to
// ensure that the sys_info is only accessed in a thread-safe manner.
// Moreover, SYSTEM_INFO is only initialized once during platform creation, and it is read-only
// after that.
unsafe impl Send for WindowsUserland {}
unsafe impl Sync for WindowsUserland {}

impl WindowsUserland {
    /// Create a new userland-Windows platform for use in `LiteBox`.
    ///
    /// # Panics
    ///
    /// Panics if the TLS slot cannot be created.
    pub fn new() -> &'static Self {
        let mut sys_info = Win32_SysInfo::SYSTEM_INFO::default();
        Self::get_system_information(&mut sys_info);

        let reserved_pages = Self::read_memory_maps();

        let platform = Self {
            tls_slot: TlsSlot::new().expect("Failed to create TLS slot!"),
            reserved_pages: reserved_pages,
            sys_info: std::sync::RwLock::new(sys_info),
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

    fn read_memory_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
        let mut reserved_pages = alloc::vec::Vec::new();
        let mut address = 0usize;

        loop {
            let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
            let ok = unsafe {
                Win32_Memory::VirtualQuery(
                    address as *const c_void,
                    &mut mbi,
                    core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>() as usize,
                ) != 0
            };
            if !ok {
                break;
            }

            if mbi.State == Win32_Memory::MEM_RESERVE || mbi.State == Win32_Memory::MEM_COMMIT {
                reserved_pages.push(core::ops::Range {
                    start: mbi.BaseAddress as usize,
                    end: (mbi.BaseAddress as usize + mbi.RegionSize) as usize,
                });
            }

            address = (mbi.BaseAddress as usize + mbi.RegionSize) as usize;
            if address == 0 {
                break;
            }
        }

        reserved_pages
    }

    fn set_init_tls(&self) {
        // TODO: Currently we are using a static thread ID and credentials (faked).
        // This is a placeholder for future implementation to use passthrough.
        let creds = litebox_common_linux::Credentials {
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
        };
        let task = alloc::boxed::Box::new(litebox_common_linux::Task::<WindowsUserland> {
            tid: 1000,
            clear_child_tid: None,
            robust_list: None,
            credentials: alloc::sync::Arc::new(creds),
        });
        let tls = litebox_common_linux::ThreadLocalStorage::new(task);
        self.set_thread_local_storage(tls);
    }

    /// Retrieves information about the host platform (Windows).
    fn get_system_information(sys_info: &mut Win32_SysInfo::SYSTEM_INFO) {
        unsafe {
            Win32_SysInfo::GetSystemInfo(sys_info);
        }
    }

    fn round_up_to_granu(&self, x: usize) -> usize {
        let gran = self.sys_info.read().unwrap().dwAllocationGranularity as usize;
        (x + gran - 1) & !(gran - 1)
    }

    fn round_down_to_granu(&self, x: usize) -> usize {
        let gran = self.sys_info.read().unwrap().dwAllocationGranularity as usize;
        x & !(gran - 1)
    }
}

impl litebox::platform::Provider for WindowsUserland {}

impl litebox::platform::ExitProvider for WindowsUserland {
    type ExitCode = i32;
    const EXIT_SUCCESS: Self::ExitCode = 0;
    const EXIT_FAILURE: Self::ExitCode = 1;

    fn exit(&self, code: Self::ExitCode) -> ! {
        let Self {
            tls_slot: _,
            sys_info: _,
            reserved_pages: _,
        } = self;
        // TODO: Implement Windows process exit
        // For now, use standard process exit
        std::process::exit(code);
    }
}

impl litebox::platform::ThreadProvider for WindowsUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadArgs = litebox_common_linux::NewThreadArgs<WindowsUserland>;
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
        unimplemented!("spawn_thread is not implemented for Windows yet.");
    }

    fn terminate_thread(&self, code: Self::ExitCode) -> ! {
        unimplemented!(
            "terminate_thread is not implemented for Windows yet. code: {}",
            code
        );
    }
}

impl litebox::platform::RawMutexProvider for WindowsUserland {
    type RawMutex = RawMutex;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        RawMutex {
            inner: AtomicU32::new(0),
        }
    }
}

// A skeleton of a raw mutex for Windows.
pub struct RawMutex {
    // The `inner` is the value shown to the outside world as an underlying atomic.
    inner: AtomicU32,
}

impl RawMutex {
    #[expect(unused, reason = "This is a placeholder for future implementation.")]
    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        unimplemented!("block_or_maybe_timeout is not implemented for Windows yet.");
    }
}

impl litebox::platform::RawMutex for RawMutex {
    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        unimplemented!("wake_many is not implemented for Windows yet. n: {}", n);
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

impl litebox::platform::IPInterfaceProvider for WindowsUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        unimplemented!(
            "send_ip_packet is not implemented for Windows yet. packet length: {}",
            packet.len()
        );
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        unimplemented!(
            "receive_ip_packet is not implemented for Windows yet. packet length: {}",
            packet.len()
        );
    }
}

impl litebox::platform::TimeProvider for WindowsUserland {
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

#[expect(dead_code)]
pub struct PunchthroughToken {
    punchthrough: PunchthroughSyscall<WindowsUserland>,
}

impl litebox::platform::PunchthroughToken for PunchthroughToken {
    type Punchthrough = PunchthroughSyscall<WindowsUserland>;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<
            <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnFailure,
        >,
    > {
        unimplemented!("punchthrough is not implemented for Windows yet");
    }
}

impl litebox::platform::PunchthroughProvider for WindowsUserland {
    type PunchthroughToken = PunchthroughToken;
    fn get_punchthrough_token_for(
        &self,
        punchthrough: <Self::PunchthroughToken as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
        Some(PunchthroughToken { punchthrough })
    }
}

impl litebox::platform::DebugLogProvider for WindowsUserland {
    fn debug_log_print(&self, msg: &str) {
        // TODO: Implement Windows debug logging
        // For now, use standard error output
        use std::io::Write;
        let _ = std::io::stderr().write_all(msg.as_bytes());
    }
}

impl litebox::platform::RawPointerProvider for WindowsUserland {
    type RawConstPointer<T: Clone> = litebox::platform::trivial_providers::TransparentConstPtr<T>;
    type RawMutPointer<T: Clone> = litebox::platform::trivial_providers::TransparentMutPtr<T>;
}

#[allow(
    clippy::match_same_arms,
    reason = "Iterate over all cases for prot_flags."
)]
fn prot_flags(flags: MemoryRegionPermissions) -> Win32_Memory::PAGE_PROTECTION_FLAGS {
    match (
        flags.contains(MemoryRegionPermissions::READ),
        flags.contains(MemoryRegionPermissions::WRITE),
        flags.contains(MemoryRegionPermissions::EXEC),
    ) {
        // no permissions
        (false, false, false) => Win32_Memory::PAGE_NOACCESS,
        // read-only
        (true, false, false) => Win32_Memory::PAGE_READONLY,
        // write-only (Windows doesn't have write-only, so we use r+w)
        (false, true, false) => Win32_Memory::PAGE_READWRITE,
        // read-write
        (true, true, false) => Win32_Memory::PAGE_READWRITE,
        // exeute-only (Windows doesn't have execute-only, so we use r+x)
        (false, false, true) => Win32_Memory::PAGE_EXECUTE_READ,
        // read-execute
        (true, false, true) => Win32_Memory::PAGE_EXECUTE_READ,
        // write-execute (Windows doesn't have write-execute, so we use rwx)
        (false, true, true) => Win32_Memory::PAGE_EXECUTE_READWRITE,
        // read-write-execute
        (true, true, true) => Win32_Memory::PAGE_EXECUTE_READWRITE,
    }
}

fn do_prefetch_on_range(start: usize, size: usize) {
    println!(
        "Prefetching memory range: {:p} - {:p}, size: {}",
        start as *const c_void,
        (start + size) as *const c_void,
        size
    );
    let ok = unsafe {
        let prefetch_entry = Win32_Memory::WIN32_MEMORY_RANGE_ENTRY {
            VirtualAddress: start as *mut c_void,
            NumberOfBytes: size,
        };
        PrefetchVirtualMemory(GetCurrentProcess(), 1, &raw const prefetch_entry, 0) != 0
    };
    assert!(ok, "PrefetchVirtualMemory failed with error: {}", unsafe {
        GetLastError()
    });
}

#[expect(unused, reason = "Will be added for PageManagementProvider soon.")]
impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for WindowsUserland {
    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address: bool,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let mut base_addr = suggested_range.start as *mut c_void;
        let mut size = suggested_range.len();
        // TODO: For Windows, there is no MAP_GROWDOWN features so far.
        if can_grow_down {
            println!("Warning: can_grow_down is not supported on Windows, ignoring it.");
        }
        if fixed_address {
            println!("Warning: fixed_address is not supported on Windows, ignoring it.");
        }

        // 1) In case we have a suggested VA range, we first check and deal with the case
        // that the address is already reserved.
        if suggested_range.start != 0 {
            let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
            let ok = unsafe {
                Win32_Memory::VirtualQuery(
                    base_addr,
                    &raw mut mbi,
                    core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
                ) != 0
            };
            assert!(ok, "VirtualQuery failed: {}", unsafe { GetLastError() });

            // For already-reserved memory, we just need to commit it.
            if mbi.State == Win32_Memory::MEM_RESERVE {
                let addr = unsafe {
                    VirtualAlloc2(
                        GetCurrentProcess(),
                        base_addr.cast::<c_void>(),
                        size,
                        Win32_Memory::MEM_COMMIT,
                        prot_flags(initial_permissions),
                        core::ptr::null_mut(),
                        0,
                    )
                };
                assert!(!addr.is_null(), "VirtualAlloc2 failed: {}", unsafe {
                    GetLastError()
                });

                // Prefetch the memory range if requested
                if populate_pages_immediately {
                    do_prefetch_on_range(suggested_range.start, suggested_range.len());
                }

                return Ok(litebox::platform::trivial_providers::TransparentMutPtr {
                    inner: addr.cast::<u8>(),
                });
            }

            // For already-committed memory, we just need to overlay its permissions.
            if mbi.State == Win32_Memory::MEM_COMMIT {
                let mut old_protect: u32 = 0;
                let ok = unsafe {
                    VirtualProtect(
                        base_addr,
                        size,
                        prot_flags(initial_permissions),
                        &raw mut old_protect,
                    ) != 0
                };
                assert!(ok, "VirtualProtect failed: {}", unsafe { GetLastError() });

                // Prefetch the memory range if requested
                if populate_pages_immediately {
                    do_prefetch_on_range(suggested_range.start, suggested_range.len());
                }

                return Ok(litebox::platform::trivial_providers::TransparentMutPtr {
                    inner: base_addr.cast::<u8>(),
                });
            }
        }

        // 2) In case that the (indicated) VA is not reserved, we have to reserve & commit it.

        // Align the size and base address to the allocation granularity.
        let aligned_size = self.round_up_to_granu(size);
        let mut aligned_base_addr = self.round_down_to_granu(base_addr as usize) as *mut c_void;

        // Reserve and commit the memory.
        let addr: *mut c_void = unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                aligned_base_addr,
                aligned_size,
                Win32_Memory::MEM_COMMIT | Win32_Memory::MEM_RESERVE,
                prot_flags(initial_permissions),
                core::ptr::null_mut(),
                0,
            )
        };
        assert!(
            !addr.is_null(),
            "VirtualAlloc2 failed. Address: {:p}, Size: {}, Permissions: {:?}. Error: {}",
            aligned_base_addr,
            aligned_size,
            initial_permissions,
            unsafe { GetLastError() }
        );

        // Prefetch the memory range if requested
        if populate_pages_immediately {
            do_prefetch_on_range(addr as usize, aligned_size);
        }
        Ok(litebox::platform::trivial_providers::TransparentMutPtr {
            inner: addr.cast::<u8>(),
        })
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let ok = unsafe {
            VirtualFree(
                range.start as *mut c_void,
                range.len(),
                Win32_Memory::MEM_DECOMMIT,
            ) != 0
        };
        assert!(ok, "VirtualFree failed: {}", unsafe { GetLastError() });
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
        unimplemented!(
            "remap_pages is not implemented for Windows yet. old_range: {:?}, new_range: {:?}",
            old_range,
            new_range
        );
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        let mut old_protect: u32 = 0;
        let ok = unsafe {
            VirtualProtect(
                range.start as *mut c_void,
                range.len(),
                prot_flags(new_permissions),
                &raw mut old_protect,
            ) != 0
        };
        assert!(ok, "VirtualProtect failed: {}", unsafe { GetLastError() });
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &std::ops::Range<usize>> {
        self.reserved_pages.iter()
    }
}

impl litebox::platform::StdioProvider for WindowsUserland {
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
        use std::io::Write as _;
        match stream {
            litebox::platform::StdioOutStream::Stdout => {
                std::io::stdout().write(buf).map_err(|err| {
                    if err.kind() == std::io::ErrorKind::BrokenPipe {
                        litebox::platform::StdioWriteError::Closed
                    } else {
                        panic!("unhandled error {err}")
                    }
                })
            }
            litebox::platform::StdioOutStream::Stderr => {
                std::io::stderr().write(buf).map_err(|err| {
                    if err.kind() == std::io::ErrorKind::BrokenPipe {
                        litebox::platform::StdioWriteError::Closed
                    } else {
                        panic!("unhandled error {err}")
                    }
                })
            }
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
static SLAB_ALLOC: litebox::mm::allocator::SafeZoneAllocator<'static, 28, WindowsUserland> =
    litebox::mm::allocator::SafeZoneAllocator::new();

impl litebox::mm::allocator::MemoryProvider for WindowsUserland {
    fn alloc(layout: &std::alloc::Layout) -> Option<(usize, usize)> {
        let size = core::cmp::max(
            layout.size().next_power_of_two(),
            // Note `mmap` provides no guarantee of alignment, so we double the size to ensure we
            // can always find a required chunk within the returned memory region.
            core::cmp::max(layout.align(), 0x1000) << 1,
        );

        match unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                core::ptr::null_mut(),
                size,
                Win32_Memory::MEM_COMMIT | Win32_Memory::MEM_RESERVE,
                Win32_Memory::PAGE_READWRITE,
                core::ptr::null_mut(),
                0,
            )
        } {
            addr if addr.is_null() => None,
            addr => Some((addr as usize, size)),
        }
    }

    unsafe fn free(_addr: usize) {
        unimplemented!("Memory deallocation is not implemented for Windows yet.");
    }
}

core::arch::global_asm!(
    "
    .text
    .align  4
    .globl  syscall_callback
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
    mov rcx, rax
    /* Pass pt_regs saved on stack to syscall dispatcher */
    mov rdx, rbp

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

/// Windows syscall handler (placeholder - needs Windows implementation)
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

impl litebox::platform::SystemInfoProvider for WindowsUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as usize
    }

    fn get_vdso_address(&self) -> Option<usize> {
        // Windows doesn't have VDSO equivalent, return None
        None
    }
}

impl WindowsUserland {
    fn get_thread_local_storage(
        &self,
    ) -> *mut litebox_common_linux::ThreadLocalStorage<WindowsUserland> {
        let tls_ptr = unsafe { TlsGetValue(self.tls_slot.dwtlsindex) };
        if tls_ptr.is_null() {
            return core::ptr::null_mut();
        }
        tls_ptr.cast::<litebox_common_linux::ThreadLocalStorage<WindowsUserland>>()
    }
}

/// Windows thread-local storage implementation (placeholder)
/// Windows uses different TLS mechanisms than Unix systems
impl litebox::platform::ThreadLocalStorageProvider for WindowsUserland {
    type ThreadLocalStorage = litebox_common_linux::ThreadLocalStorage<WindowsUserland>;

    fn set_thread_local_storage(&self, tls: Self::ThreadLocalStorage) {
        let tls_ptr = Box::into_raw(Box::new(tls)) as *const core::ffi::c_void;
        let succ = unsafe { TlsSetValue(self.tls_slot.dwtlsindex, tls_ptr) };
        assert!(succ != 0, "Failed to set TLS value. Error={}.", unsafe {
            GetLastError()
        });
    }

    fn release_thread_local_storage(&self) -> Self::ThreadLocalStorage {
        let tls = self.get_thread_local_storage();
        assert!(!tls.is_null(), "TLS must be set before releasing it");
        // reset the TLS slot
        unsafe {
            TlsSetValue(self.tls_slot.dwtlsindex, core::ptr::null_mut());
        }
        let tls = unsafe { Box::from_raw(tls) };
        assert!(!tls.borrowed, "TLS must not be borrowed when releasing it");
        *tls
    }

    fn with_thread_local_storage_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::ThreadLocalStorage) -> R,
    {
        let tls = self.get_thread_local_storage();
        assert!(!tls.is_null(), "TLS must be set before accessing it");
        let tls = unsafe { &mut *tls };
        assert!(!tls.borrowed, "TLS must not be borrowed when accessing it");
        tls.borrowed = true;
        let ret = f(tls);
        tls.borrowed = false;
        ret
    }
}

#[cfg(test)]
mod tests {
    use crate::WindowsUserland;
    use litebox::platform::PageManagementProvider;
    use litebox::platform::ThreadLocalStorageProvider as _;

    #[test]
    fn test_reserved_pages() {
        let platform = WindowsUserland::new();
        let reserved_pages: Vec<_> =
            <WindowsUserland as PageManagementProvider<4096>>::reserved_pages(platform).collect();

        // Check that the reserved pages are not empty
        assert!(!reserved_pages.is_empty(), "No reserved pages found");

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
        let platform = WindowsUserland::new();
        let tls = platform.get_thread_local_storage();
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

        let tls = platform.get_thread_local_storage();
        assert!(tls.is_null(), "TLS should be null after releasing it");
    }
}
