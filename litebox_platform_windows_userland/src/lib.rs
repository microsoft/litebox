//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Windows.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use core::cell::Cell;
use core::cell::RefCell;
use core::mem::ManuallyDrop;
use core::panic;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::SeqCst;
use core::time::Duration;
use std::os::raw::c_void;

use litebox::platform::RawConstPointer;
use litebox::platform::ThreadLocalStorageProvider;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::trivial_providers::TransparentMutPtr;
use litebox::platform::{ImmediatelyWokenUp, RawMutPointer};
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::PunchthroughSyscall;

use windows_sys::Win32::Foundation::{self as Win32_Foundation, FILETIME};
use windows_sys::Win32::{
    Foundation::GetLastError,
    System::Diagnostics::Debug::{
        AddVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
        EXCEPTION_POINTERS,
    },
    System::Memory::{
        self as Win32_Memory, PrefetchVirtualMemory, VirtualAlloc2, VirtualFree, VirtualProtect,
    },
    System::SystemInformation::{self as Win32_SysInfo, GetSystemTimeAsFileTime},
    System::Threading::{self as Win32_Threading, CreateThread, GetCurrentProcess},
};

mod perf_counter;

extern crate alloc;

/// Per-thread FS base storage structure
/// Clone and Copy are required to use std::cell::Cell.
#[derive(Debug, Clone, Copy)]
struct ThreadFsBaseState {
    /// The current FS base value for this thread
    fs_base: usize,
}

impl ThreadFsBaseState {
    const fn new() -> Self {
        // There's no point in trying to read the current FS base since it will
        // likely be 0 (as set by Windows scheduler). We just initialize it to 0.
        Self { fs_base: 0 }
    }

    fn set_fs_base(&mut self, new_base: usize) {
        self.fs_base = new_base;
        unsafe {
            litebox_common_linux::wrfsbase(new_base);
        }
    }

    fn restore_fs_base(self) {
        unsafe {
            litebox_common_linux::wrfsbase(self.fs_base);
        }
    }
}

// Thread-local storage for FS base state
thread_local! {
    static THREAD_FS_BASE: Cell<ThreadFsBaseState> = const { Cell::new(ThreadFsBaseState::new()) };
}

/// Connector to a shim-exposed syscall-handling interface.
pub type SyscallHandler = fn(litebox_common_linux::SyscallRequest<WindowsUserland>) -> usize;

/// The syscall handler passed down from the shim.
static SYSCALL_HANDLER: std::sync::RwLock<Option<SyscallHandler>> = std::sync::RwLock::new(None);

/// The userland Windows platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct WindowsUserland {
    reserved_pages: alloc::vec::Vec<core::ops::Range<usize>>,
    sys_info: std::sync::RwLock<Win32_SysInfo::SYSTEM_INFO>,
}

// Safety: Given that SYSTEM_INFO is not Send/Sync (it contains *mut c_void), we use RwLock to
// ensure that the sys_info is only accessed in a thread-safe manner.
// Moreover, SYSTEM_INFO is only initialized once during platform creation, and it is read-only
// after that.
unsafe impl Send for WindowsUserland {}
unsafe impl Sync for WindowsUserland {}

/// Helper functions for managing per-thread FS base
impl WindowsUserland {
    /// Get the current thread's FS base state
    fn get_thread_fs_base_state() -> ThreadFsBaseState {
        THREAD_FS_BASE.with(std::cell::Cell::get)
    }

    /// Set the current thread's FS base
    fn set_thread_fs_base(new_base: usize) {
        THREAD_FS_BASE.with(|state| {
            let mut current_state = state.get();
            current_state.set_fs_base(new_base);
            state.set(current_state);
        });
    }

    /// Restore the current thread's FS base from saved state
    fn restore_thread_fs_base() {
        THREAD_FS_BASE.with(|state| {
            state.get().restore_fs_base();
        });
    }

    /// Initialize FS base state for a new thread
    fn init_thread_fs_base() {
        THREAD_FS_BASE.with(|state| {
            state.set(ThreadFsBaseState::new());
        });
    }
}

unsafe extern "system" fn exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        let info = *exception_info;
        let exception_record = *info.ExceptionRecord;
        if exception_record.ExceptionCode == Win32_Foundation::EXCEPTION_ACCESS_VIOLATION {
            let current_fsbase = litebox_common_linux::rdfsbase();

            // Get the saved FS base from the per-thread FS state
            let thread_state = WindowsUserland::get_thread_fs_base_state();

            if current_fsbase == 0 && current_fsbase != thread_state.fs_base {
                // Restore the FS base from the saved state
                WindowsUserland::restore_thread_fs_base();

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        EXCEPTION_CONTINUE_SEARCH
    }
}

impl WindowsUserland {
    /// Create a new userland-Windows platform for use in `LiteBox`.
    ///
    /// # Panics
    ///
    /// Panics if the TLS slot cannot be created.
    pub fn new() -> &'static Self {
        let mut sys_info = Win32_SysInfo::SYSTEM_INFO::default();
        Self::get_system_information(&mut sys_info);

        // TODO(chuqi): Currently we just print system information for
        // `TASK_ADDR_MIN` and `TASK_ADDR_MAX`.
        // Will remove these prints once we have a better way to replace
        // the current `const` values in PageManagementProvider.
        println!("System information.");
        println!(
            "=> Max user address: {:#x}",
            sys_info.lpMaximumApplicationAddress as usize
        );
        println!(
            "=> Min user address: {:#x}",
            sys_info.lpMinimumApplicationAddress as usize
        );

        let reserved_pages = Self::read_memory_maps();

        let platform = Self {
            reserved_pages,
            sys_info: std::sync::RwLock::new(sys_info),
        };
        platform.set_init_tls();

        // Initialize it's own fs-base (for the main thread)
        WindowsUserland::init_thread_fs_base();

        // Windows sets FS_BASE to 0 regularly upon scheduling; we register an exception handler
        // to set FS_BASE back to a "stored" value whenever we notice that it has become 0.
        unsafe {
            let _ = AddVectoredExceptionHandler(0, Some(exception_handler));
        }

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
                    &raw mut mbi,
                    core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
                ) != 0
            };
            if !ok {
                break;
            }

            if mbi.State == Win32_Memory::MEM_RESERVE || mbi.State == Win32_Memory::MEM_COMMIT {
                reserved_pages.push(core::ops::Range {
                    start: mbi.BaseAddress as usize,
                    end: (mbi.BaseAddress as usize + mbi.RegionSize),
                });
            }

            address = mbi.BaseAddress as usize + mbi.RegionSize;
            if address == 0 {
                break;
            }
        }

        reserved_pages
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

    fn is_aligned_to_granu(&self, x: usize) -> bool {
        let gran = self.sys_info.read().unwrap().dwAllocationGranularity as usize;
        x.is_multiple_of(gran)
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
            pid: 1000,
            tid: 1000,
            // TODO: placeholder for actual PPID
            ppid: 0,
            clear_child_tid: None,
            robust_list: None,
            credentials: alloc::sync::Arc::new(creds),
            comm: [0; litebox_common_linux::TASK_COMM_LEN],
        });
        let tls = litebox_common_linux::ThreadLocalStorage::new(task);
        self.set_thread_local_storage(tls);
    }
}

impl litebox::platform::Provider for WindowsUserland {}

impl litebox::platform::ExitProvider for WindowsUserland {
    type ExitCode = u32;
    const EXIT_SUCCESS: Self::ExitCode = 0;
    const EXIT_FAILURE: Self::ExitCode = 1;

    fn exit(&self, code: Self::ExitCode) -> ! {
        let Self {
            sys_info: _,
            reserved_pages: _,
        } = self;
        unsafe { windows_sys::Win32::System::Threading::ExitProcess(code) }
    }
}

/// Thread start wrapper function for Windows userland.
unsafe extern "system" fn thread_start(param: *mut c_void) -> u32 {
    // Initialize FS base state for this new thread
    WindowsUserland::init_thread_fs_base();

    let thread_start_args = unsafe { Box::from_raw(param.cast::<ThreadStartArgs>()) };

    // store the guest pt_regs onto the stack (for restoration later on)
    let pt_regs_stack = *thread_start_args.pt_regs;

    // Set up thread-local storage for the new thread. This is done by
    // calling the actual thread callback with the unpacked arguments
    (thread_start_args.thread_args.callback)(*(thread_start_args.thread_args));

    // Restore the context
    unsafe {
        core::arch::asm!(
            "mov rbx, {0}",
            "xor rax, rax",
            "mov rsp, {1}",
            "pop r11",
            "pop r10",
            "pop r9",
            "pop r8",
            "pop rcx",      // skip pt_regs.rax
            "pop rcx",
            "pop rdx",
            "pop rsi",
            "pop rdi",
            "add rsp, 24",  // skip orig_rax, rip, cs, eflags
            "popfq",
            "pop rsp",      // restore the stack pointer (which points to the entry point of the thread)
            "jmp rbx",
            in(reg) thread_start_args.entry_point,
            in(reg) &raw const pt_regs_stack.r11, // restore registers, starting from r11
            out("rax") _,
            options(nostack, preserves_flags)
        );
    }
    0
}

struct ThreadStartArgs {
    pt_regs: Box<litebox_common_linux::PtRegs>,
    thread_args: Box<litebox_common_linux::NewThreadArgs<WindowsUserland>>,
    entry_point: usize,
}

impl litebox::platform::ThreadProvider for WindowsUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadArgs = litebox_common_linux::NewThreadArgs<WindowsUserland>;
    type ThreadSpawnError = litebox_common_linux::errno::Errno;
    type ThreadId = usize;

    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        stack: TransparentMutPtr<u8>,
        stack_size: usize,
        entry_point: usize,
        mut thread_args: Box<Self::ThreadArgs>,
    ) -> Result<usize, Self::ThreadSpawnError> {
        let child_tid_ptr = core::ptr::from_mut(thread_args.task.as_mut()) as u64
            + core::mem::offset_of!(litebox_common_linux::Task<WindowsUserland>, tid) as u64;

        let mut copied_pt_regs = Box::new(*ctx);

        // Reset the child stack pointer to the top of the allocated thread stack.
        copied_pt_regs.rsp = stack.as_usize() + stack_size;

        let thread_args = thread_args;

        let thread_start_args = ThreadStartArgs {
            pt_regs: copied_pt_regs,
            thread_args,
            entry_point,
        };

        // We should always use heap to pass the parameter to `CreateThread`. This is to avoid using the parents'
        // stack, which may be freed (race-condition) before the child thread starts.
        let thread_start_arg_ptr = Box::into_raw(Box::new(thread_start_args));

        let handle: Win32_Foundation::HANDLE = unsafe {
            CreateThread(
                core::ptr::null_mut(),
                // just let the OS to allocate a dummy stack
                0,
                Some(thread_start),
                thread_start_arg_ptr.cast::<c_void>(),
                // This flag indicates that the stack size is a reservation, not a commit.
                Win32_Threading::STACK_SIZE_PARAM_IS_A_RESERVATION,
                child_tid_ptr as *mut u32,
            )
        };
        assert!(!handle.is_null(), "Failed to create thread");
        Ok(unsafe { *(child_tid_ptr as *const u32) as usize })
    }

    fn terminate_thread(&self, code: Self::ExitCode) -> ! {
        unsafe { Win32_Threading::ExitThread(code) }
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

        // Compute timeout in ms
        let timeout_ms = match timeout {
            None => Win32_Threading::INFINITE, // no timeout
            Some(timeout) => {
                let ms = timeout.as_millis();
                ms.min(u128::from(Win32_Threading::INFINITE - 1)).truncate()
            }
        };

        let ok = unsafe {
            Win32_Threading::WaitOnAddress(
                (&raw const self.inner).cast::<c_void>(),
                (&raw const val).cast::<c_void>(),
                std::mem::size_of::<u32>(),
                timeout_ms,
            ) != 0
        };

        if ok {
            Ok(UnblockedOrTimedOut::Unblocked)
        } else {
            // Check why WaitOnAddress failed
            let err = unsafe { GetLastError() };
            match err {
                Win32_Foundation::WAIT_TIMEOUT => {
                    // Timed out
                    Ok(UnblockedOrTimedOut::TimedOut)
                }
                e => {
                    // Other error, possibly spurious wakeup or value changed
                    // Continue the loop to check the value again
                    panic!("Unexpected error={e} for WaitOnAddress");
                }
            }
        }
    }
}

impl litebox::platform::RawMutex for RawMutex {
    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        assert!(n > 0, "wake_many should be called with n > 0");
        let n: u32 = n.try_into().unwrap();

        let mutex = core::ptr::from_ref(self.underlying_atomic()).cast::<c_void>();
        unsafe {
            if n == 1 {
                Win32_Threading::WakeByAddressSingle(mutex);
            } else if n >= i32::MAX as u32 {
                Win32_Threading::WakeByAddressAll(mutex);
            } else {
                // Wake up `n` threads iteratively
                for _ in 0..n {
                    Win32_Threading::WakeByAddressSingle(mutex);
                }
            }
        }

        // For windows, the OS kernel does not tell us how many threads were actually woken up,
        // so we just return `n`
        n as usize
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
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        perf_counter::PerformanceCounterInstant::now().into()
    }

    fn current_time(&self) -> Self::SystemTime {
        let mut filetime = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        unsafe {
            GetSystemTimeAsFileTime(&raw mut filetime);
        }
        let FILETIME {
            dwLowDateTime: low,
            dwHighDateTime: high,
        } = filetime;
        let filetime = (u64::from(high) << 32) | u64::from(low);
        SystemTime { filetime }
    }
}

pub struct Instant {
    inner: core::time::Duration,
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        // On windows there's a threshold below which we consider two timestamps
        // equivalent due to measurement error. For more details + doc link,
        // check the docs on [epsilon](perf_counter::PerformanceCounterInstant::epsilon).
        let epsilon = perf_counter::PerformanceCounterInstant::epsilon();
        if earlier.inner > self.inner && earlier.inner - self.inner <= epsilon {
            Some(Duration::new(0, 0))
        } else {
            self.inner.checked_sub(earlier.inner)
        }
    }
}

impl From<litebox_common_linux::Timespec> for Instant {
    fn from(value: litebox_common_linux::Timespec) -> Self {
        Instant {
            inner: value.into(),
        }
    }
}

pub struct SystemTime {
    // 100ns intervals since Windows epoch
    filetime: u64,
}

impl litebox::platform::SystemTime for SystemTime {
    // Windows epoch: Jan 1, 1601
    // Unix epoch: Jan 1, 1970
    // Difference: 11644473600 seconds
    // Intervals: 100ns intervals
    // Seconds per interval: 10^-7
    const UNIX_EPOCH: Self = SystemTime {
        filetime: 11_644_473_600 * 10_000_000,
    };

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        if self.filetime >= earlier.filetime {
            let diff_100ns = self.filetime - earlier.filetime;
            let nanos = diff_100ns * 100;
            let secs = nanos / 1_000_000_000;
            let remaining_nanos = nanos % 1_000_000_000;
            Ok(core::time::Duration::new(secs, remaining_nanos as u32))
        } else {
            let diff_100ns = earlier.filetime - self.filetime;
            let nanos = diff_100ns * 100;
            let secs = nanos / 1_000_000_000;
            let remaining_nanos = nanos % 1_000_000_000;
            Err(core::time::Duration::new(secs, remaining_nanos as u32))
        }
    }
}

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
        match self.punchthrough {
            PunchthroughSyscall::SetFsBase { addr } => {
                // Use WindowsUserland's per-thread FS base management system
                WindowsUserland::set_thread_fs_base(addr);
                Ok(0)
            }
            PunchthroughSyscall::GetFsBase { addr } => {
                // Read from the per-thread FS base storage to get the current value
                let thread_state = WindowsUserland::get_thread_fs_base_state();

                // Use the stored FS base value from our per-thread storage
                let fs_base = thread_state.fs_base;

                unsafe { addr.write_at_offset(0, fs_base) }.ok_or(
                    litebox::platform::PunchthroughError::Failure(
                        litebox_common_linux::errno::Errno::EFAULT,
                    ),
                )?;
                Ok(0)
            }
            _ => {
                unimplemented!(
                    "PunchthroughToken for WindowsUserland is not fully implemented yet"
                );
            }
        }
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

fn do_query_on_region(mbi: &mut Win32_Memory::MEMORY_BASIC_INFORMATION, base_addr: *mut c_void) {
    let ok = unsafe {
        Win32_Memory::VirtualQuery(
            base_addr,
            mbi,
            core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
        ) != 0
    };
    assert!(ok, "VirtualQuery addr={:p} failed: {}", base_addr, unsafe {
        GetLastError()
    });
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for WindowsUserland {
    // TODO(chuqi): These are currently "magic numbers" grabbed from my Windows 11 SystemInformation.
    // The actual values should be determined by `GetSystemInfo()`.
    //
    // NOTE: make sure the values are PAGE_ALIGNED.
    const TASK_ADDR_MIN: usize = 0x1_0000;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;
    #[expect(clippy::too_many_lines)]
    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address: bool,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let base_addr = suggested_range.start as *mut c_void;
        let size = suggested_range.len();
        // TODO: For Windows, there is no MAP_GROWDOWN features so far.
        let _ = can_grow_down;

        // 1) In case we have a suggested VA range, we first check and deal with the case
        // that the address (range) is already reserved.
        if suggested_range.start != 0 {
            assert!(suggested_range.start >= <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::
                                                            TASK_ADDR_MIN);
            assert!(suggested_range.end <= <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::
                                                            TASK_ADDR_MAX);

            let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
            do_query_on_region(&mut mbi, base_addr);

            // The region is already either reserved or committed, and we need to handle both cases.
            if mbi.State == Win32_Memory::MEM_RESERVE || mbi.State == Win32_Memory::MEM_COMMIT {
                let region_base = mbi.BaseAddress as usize;
                let region_size = mbi.RegionSize;
                let region_end = region_base + region_size;
                let request_end = suggested_range.start + size;

                assert!(
                    suggested_range.start <= region_end,
                    "Requested start address ({:p}) is beyond the reserved region end ({:p})",
                    base_addr,
                    region_end as *mut c_void
                );

                let size_within_region = core::cmp::min(size, region_end - suggested_range.start);
                unsafe {
                    match mbi.State {
                        // In case the region is already reserved, we just need to commit it.
                        Win32_Memory::MEM_RESERVE => {
                            let ptr = VirtualAlloc2(
                                GetCurrentProcess(),
                                base_addr.cast::<c_void>(),
                                size_within_region,
                                Win32_Memory::MEM_COMMIT,
                                prot_flags(initial_permissions),
                                core::ptr::null_mut(),
                                0,
                            );
                            assert!(
                                !ptr.is_null(),
                                "VirtualAlloc2(COMMIT addr={:p}, size=0x{:x}) failed: err={}",
                                base_addr,
                                size_within_region,
                                GetLastError()
                            );
                        }
                        // In case the region is already committed, we just need to change its permissions.
                        Win32_Memory::MEM_COMMIT => {
                            let mut old_protect: u32 = 0;
                            assert!(
                                Win32_Memory::VirtualProtect(
                                    base_addr,
                                    size_within_region,
                                    prot_flags(initial_permissions),
                                    &raw mut old_protect,
                                ) != 0,
                                "VirtualProtect(addr={:p}, size=0x{:x}) failed: {}",
                                base_addr,
                                size_within_region,
                                GetLastError()
                            );
                        }
                        _ => {
                            panic!("Unexpected memory state: {:?}", mbi.State);
                        }
                    }
                }

                // If the requested end address is beyond the reserved region (cross the region),
                // we need to allocate more memory.
                if request_end > region_end {
                    // Windows region should be aligned to its allocation granularity.
                    assert!(
                        self.is_aligned_to_granu(region_end),
                        "Region end address {:p} is not aligned to allocation granularity",
                        region_end as *mut c_void
                    );

                    // In case of cross-region allocation, we must ensure that the virtual address
                    // returned by VirtualAlloc2 is the expected start address (contiguous with the
                    // already reserved region).
                    <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::allocate_pages(
                            self,
                            region_end..request_end,
                            initial_permissions,
                            can_grow_down,
                            populate_pages_immediately,
                            true,
                        )?;
                }
                // Prefetch the memory range if requested
                if populate_pages_immediately {
                    do_prefetch_on_range(suggested_range.start, suggested_range.len());
                }

                return Ok(litebox::platform::trivial_providers::TransparentMutPtr {
                    inner: base_addr.cast::<u8>(),
                });
            }
            // If the region is not reserved or committed, we just need to reserve and commit it.
            // Fallthrough to the next step.
            else {
            }
        }

        // 2) In case that the (indicated) VA is not reserved, or there is no suggested VA, we
        // just have to reserve & commit a VA range.

        // Align the size and base address to the allocation granularity.
        let aligned_size = self.round_up_to_granu(size);
        let aligned_base_addr = self.round_down_to_granu(base_addr as usize) as *mut c_void;

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

        if fixed_address {
            assert!(
                addr == aligned_base_addr,
                "VirtualAlloc2 returned address {addr:p} which is not the expected fixed address {aligned_base_addr:p}"
            );
        }

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
) -> usize {
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
        Err(err) => (err.as_neg() as isize).reinterpret_as_unsigned(),
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

thread_local! {
    // Use `ManuallyDrop` for more efficient TLS accesses, since this is always
    // dropped manually before the thread exits.
    static PLATFORM_TLS: RefCell<Option<ManuallyDrop<litebox_common_linux::ThreadLocalStorage<WindowsUserland>>>> = const { RefCell::new(None) };
}

/// WindowsUserland platform's thread-local storage implementation.
impl litebox::platform::ThreadLocalStorageProvider for WindowsUserland {
    type ThreadLocalStorage = litebox_common_linux::ThreadLocalStorage<WindowsUserland>;

    fn set_thread_local_storage(&self, tls: Self::ThreadLocalStorage) {
        PLATFORM_TLS.with_borrow_mut(|cell| {
            assert!(cell.is_none(), "TLS is already set for this thread");
            *cell = Some(ManuallyDrop::new(tls));
        });
    }

    fn release_thread_local_storage(&self) -> Self::ThreadLocalStorage {
        ManuallyDrop::into_inner(
            PLATFORM_TLS
                .take()
                .expect("TLS must be set before releasing it"),
        )
    }

    fn with_thread_local_storage_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::ThreadLocalStorage) -> R,
    {
        PLATFORM_TLS.with_borrow_mut(|cell| {
            let tls = cell.as_mut().expect("TLS must be set before accessing it");
            f(tls)
        })
    }

    fn clear_guest_thread_local_storage(&self) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    use std::thread::sleep;

    use crate::WindowsUserland;
    use litebox::platform::PageManagementProvider;
    use litebox::platform::{RawMutex, ThreadLocalStorageProvider as _};

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
        let tid = super::PLATFORM_TLS
            .with_borrow(|cell| cell.as_ref().expect("TLS should be set").current_task.tid);

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

        super::PLATFORM_TLS
            .with_borrow(|cell| assert!(cell.is_none(), "TLS should be null after releasing it"));
    }
}
