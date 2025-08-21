//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Windows.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use core::panic;
use core::sync::atomic::{AtomicU32, AtomicUsize};
use core::time::Duration;
use std::cell::Cell;
use std::os::raw::c_void;
use std::sync::atomic::Ordering::SeqCst;

use litebox::platform::ImmediatelyWokenUp;
use litebox::platform::RawConstPointer;
use litebox::platform::ThreadLocalStorageProvider;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::trivial_providers::TransparentMutPtr;
use litebox_common_linux::PunchthroughSyscall;
use rangemap::RangeSet;

use windows_sys::Win32::Foundation as Win32_Foundation;
use windows_sys::Win32::{
    Foundation::{GetLastError, WIN32_ERROR},
    System::Diagnostics::Debug::{
        self as Win32_Debug, AddVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION,
        EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
    },
    System::Memory::{
        self as Win32_Memory, PrefetchVirtualMemory, VirtualAlloc2, VirtualFree, VirtualProtect,
    },
    System::SystemInformation::{self as Win32_SysInfo},
    System::Threading::{
        self as Win32_Threading, CreateThread, GetCurrentProcess, TlsAlloc, TlsFree, TlsGetValue,
        TlsSetValue,
    },
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
    fn new() -> Self {
        let current_fs_base = unsafe { litebox_common_linux::rdfsbase() };

        Self {
            fs_base: current_fs_base,
        }
    }

    fn set_fs_base(&mut self, new_base: usize) {
        self.fs_base = new_base;
        unsafe {
            litebox_common_linux::wrfsbase(new_base);
        }
    }

    fn restore_fs_base(&self) {
        unsafe {
            litebox_common_linux::wrfsbase(self.fs_base);
        }
    }
}

// Thread-local storage for FS base state
thread_local! {
    static THREAD_FS_BASE: Cell<ThreadFsBaseState> = Cell::new(ThreadFsBaseState::new());
}

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

/// Information about a system reservation-granularity (64KB)-aligned allocation region
#[derive(Debug, Clone)]
struct AllocationInfo {
    /// The reservation granularity (64KB)-aligned range that this AllocationInfo represents
    current_granularity_range: core::ops::Range<usize>,
    /// The actual full range reserved by VirtualAlloc2 that contains this granularity range
    full_reserved_range: core::ops::Range<usize>,
    /// Set of subranges currently in use within this granularity range
    used_subranges: RangeSet<usize>,
}

/// The userland Windows platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct WindowsUserland {
    tls_slot: TlsSlot,
    reserved_pages: alloc::vec::Vec<core::ops::Range<usize>>,
    sys_info: std::sync::RwLock<Win32_SysInfo::SYSTEM_INFO>,
    /// Track reservation granularity (64KB)-aligned allocations for bookkeeping
    allocation_tracker: std::sync::RwLock<std::collections::BTreeMap<usize, AllocationInfo>>,
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
        THREAD_FS_BASE.with(|state| state.get())
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
            tls_slot: TlsSlot::new().expect("Failed to create TLS slot!"),
            reserved_pages: reserved_pages,
            sys_info: std::sync::RwLock::new(sys_info),
            allocation_tracker: std::sync::RwLock::new(std::collections::BTreeMap::new()),
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
        });
        let tls = litebox_common_linux::ThreadLocalStorage::new(task);
        self.set_thread_local_storage(tls);
    }

    // Track a new platform allocation granularity (64KB)-aligned allocation (with MEM_RESERVE)
    fn track_allocation(
        &self,
        current_granularity_range: core::ops::Range<usize>,
        full_reserved_range: core::ops::Range<usize>,
        used_subrange: core::ops::Range<usize>,
    ) {
        let mut tracker = self.allocation_tracker.write().unwrap();
        let mut used_subranges = RangeSet::new();
        used_subranges.insert(used_subrange.clone());

        let info = AllocationInfo {
            current_granularity_range: current_granularity_range.clone(),
            full_reserved_range: full_reserved_range.clone(),
            used_subranges,
        };

        tracker.insert(current_granularity_range.start, info);
    }

    // Add a subrange to existing allocations (may span multiple platform_allocation_granularity-aligned regions)
    fn add_subrange_to_allocations(&self, subrange: core::ops::Range<usize>) {
        let mut tracker = self.allocation_tracker.write().unwrap();

        // Start from the aligned address of the subrange start
        let mut current_addr = self.round_down_to_granu(subrange.start);
        let subrange_end = subrange.end;

        // Process all potential allocation regions that the subrange might span
        while current_addr < subrange_end {
            if let Some(info) = tracker.get_mut(&current_addr) {
                // Calculate the portion of the subrange that overlaps with this granularity range
                let overlap_start = subrange.start.max(info.current_granularity_range.start);
                let overlap_end = subrange_end.min(info.current_granularity_range.end);

                if overlap_start < overlap_end {
                    let overlap_range = overlap_start..overlap_end;
                    info.used_subranges.insert(overlap_range.clone());
                }

                // Move to the next potential allocation region
                current_addr = info.current_granularity_range.end;
            } else {
                // No allocation at this address, move to the next granularity-aligned address
                panic!("No allocation found for address: {:#x}", current_addr);
            }
        }
    }

    // Remove a subrange from allocation(s) and return reserved ranges that should be freed
    fn remove_subrange_from_allocations(
        &self,
        range: core::ops::Range<usize>,
    ) -> Vec<core::ops::Range<usize>> {
        let granularity = self.sys_info.read().unwrap().dwAllocationGranularity as usize;
        let mut tracker = self.allocation_tracker.write().unwrap();
        let mut reserved_ranges_to_check = std::collections::HashSet::new();
        let mut reserved_ranges_to_free = Vec::new();

        // Start from the aligned address of the range start
        let mut current_addr = self.round_down_to_granu(range.start);
        let range_end = range.end;

        // Process all potential allocation regions that the range might span
        while current_addr < range_end {
            if let Some(info) = tracker.get_mut(&current_addr) {
                // Calculate the portion of the range that overlaps with this granularity range
                let overlap_start = range.start.max(info.current_granularity_range.start);
                let overlap_end = range_end.min(info.current_granularity_range.end);

                if overlap_start < overlap_end {
                    let overlap_range = overlap_start..overlap_end;

                    // Record the reserved range for later checking
                    reserved_ranges_to_check.insert(info.full_reserved_range.clone());

                    // Directly remove the overlap range from RangeSet (it handles all the complexity)
                    info.used_subranges.remove(overlap_range.clone());
                }

                // Move to the next potential allocation region
                current_addr = info.current_granularity_range.end;
            } else {
                // No allocation at this address, move to the next granularity-aligned address
                current_addr += self.sys_info.read().unwrap().dwAllocationGranularity as usize;
            }
        }

        // Check each reserved range to see if it's completely empty
        for reserved_range in reserved_ranges_to_check {
            let mut is_reserved_range_empty = true;

            // Check all granularity chunks within this reserved range
            let mut check_addr = reserved_range.start;

            while check_addr < reserved_range.end {
                if let Some(info) = tracker.get(&check_addr) {
                    assert!(info.full_reserved_range == reserved_range);
                    if !info.used_subranges.is_empty() {
                        is_reserved_range_empty = false;
                        break;
                    }
                }
                check_addr += granularity;
            }

            // If the entire reserved range is empty, mark it for freeing and remove all its allocations
            if is_reserved_range_empty {
                // Remove all allocation entries for this reserved range
                let mut addrs_to_remove = Vec::new();
                check_addr = reserved_range.start;
                while check_addr < reserved_range.end {
                    if let Some(info) = tracker.get(&check_addr) {
                        if info.full_reserved_range == reserved_range {
                            addrs_to_remove.push(check_addr);
                        }
                    }
                    check_addr += granularity;
                }

                for addr in addrs_to_remove {
                    tracker.remove(&addr);
                }

                // Add to the list of reserved ranges to be freed
                reserved_ranges_to_free.push(reserved_range);
            }
        }

        reserved_ranges_to_free
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
            allocation_tracker: _,
        } = self;
        // TODO: Implement Windows process exit
        // For now, use standard process exit
        std::process::exit(code);
    }
}

/// Thread start wrapper function for Windows userland.
unsafe extern "system" fn thread_start(param: *mut c_void) -> u32 {
    // Initialize FS base state for this new thread
    WindowsUserland::init_thread_fs_base();

    let thread_start_args = unsafe { Box::from_raw(param as *mut ThreadStartArgs) };

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
        copied_pt_regs.rsp = stack.as_usize() + stack_size - 0x8;

        let thread_args = thread_args;

        let thread_start_args = ThreadStartArgs {
            pt_regs: copied_pt_regs,
            thread_args: thread_args,
            entry_point: entry_point,
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
                thread_start_arg_ptr as *mut c_void,
                // This flag indicates that the stack size is a reservation, not a commit.
                Win32_Threading::STACK_SIZE_PARAM_IS_A_RESERVATION,
                child_tid_ptr as *mut u32,
            )
        };
        assert!(!handle.is_null(), "Failed to create thread");
        Ok(unsafe { *(child_tid_ptr as *const i32) as usize })
    }

    #[allow(unreachable_code)]
    fn terminate_thread(&self, code: Self::ExitCode) -> ! {
        unsafe {
            Win32_Threading::ExitThread(code as u32);
        };

        unreachable!("exit should not return");
    }
}

impl litebox::platform::RawMutexProvider for WindowsUserland {
    type RawMutex = RawMutex;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        RawMutex {
            inner: AtomicU32::new(0),
            waiter_count: AtomicUsize::new(0),
        }
    }
}

// A skeleton of a raw mutex for Windows.
pub struct RawMutex {
    // The `inner` is the value shown to the outside world as an underlying atomic.
    inner: AtomicU32,
    waiter_count: AtomicUsize,
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

        // Track some initial information.
        let start = std::time::Instant::now();

        // Indicate we are about to wait.
        self.waiter_count.fetch_add(1, SeqCst);

        let result = loop {
            // Check if value changed before waiting
            if self.inner.load(SeqCst) != val {
                break Err(ImmediatelyWokenUp);
            }

            // Compute timeout in ms
            let timeout_ms = match timeout {
                None => Win32_Threading::INFINITE, // no timeout
                Some(timeout) => match timeout.checked_sub(start.elapsed()) {
                    None => {
                        // Already timed out
                        break Ok(UnblockedOrTimedOut::TimedOut);
                    }
                    Some(remaining_time) => {
                        let ms = remaining_time.as_millis();
                        ms.min((u32::MAX - 1) as u128) as u32
                    }
                },
            };

            let ok = unsafe {
                Win32_Threading::WaitOnAddress(
                    &self.inner as *const AtomicU32 as *const c_void,
                    &val as *const u32 as *const c_void,
                    std::mem::size_of::<u32>(),
                    timeout_ms,
                ) != 0
            };

            if ok {
                if self.inner.load(SeqCst) != val {
                    break Ok(UnblockedOrTimedOut::Unblocked);
                }
            } else {
                // Check why WaitOnAddress failed
                let err = unsafe { GetLastError() };
                match err {
                    Win32_Foundation::WAIT_TIMEOUT => {
                        // Timed out
                        break Ok(UnblockedOrTimedOut::TimedOut);
                    }
                    e => {
                        // Other error, possibly spurious wakeup or value changed
                        // Continue the loop to check the value again
                        panic!("Unexpected error={e} for WaitOnAddress");
                    }
                }
            }
        };

        // Decrement waiter count before returning
        self.waiter_count.fetch_sub(1, SeqCst);
        result
    }
}

impl litebox::platform::RawMutex for RawMutex {
    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        assert!(n > 0, "wake_many should be called with n > 0");
        let n: u32 = n.try_into().unwrap();
        let waiting = self.waiter_count.load(SeqCst);

        unsafe {
            if n == 1 {
                Win32_Threading::WakeByAddressSingle(
                    self.underlying_atomic().as_ptr() as *const c_void
                );
            } else if (n as usize) >= waiting {
                Win32_Threading::WakeByAddressAll(
                    self.underlying_atomic().as_ptr() as *const c_void
                );
            } else {
                // Wake up `n` threads iteratively
                for _ in 0..n {
                    Win32_Threading::WakeByAddressSingle(
                        self.underlying_atomic().as_ptr() as *const c_void
                    );
                }
            }
        }

        // For windows, the OS kernel does not tell us how many threads were actually woken up,
        // so we just return the minimum of `n` and the current number of waiters
        waiting.min(n as usize)
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
        perf_counter::PerformanceCounterInstant::now().into()
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
                use litebox::platform::RawMutPointer as _;

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
            PunchthroughSyscall::WakeByAddress { addr } => unsafe {
                Win32_Threading::WakeByAddressAll(addr.as_usize() as *const c_void);
                Ok(0)
            },
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

fn werr_text(err: u32) -> String {
    unsafe {
        let mut buf: *mut u16 = std::ptr::null_mut();
        let flags = Win32_Debug::FORMAT_MESSAGE_ALLOCATE_BUFFER
            | Win32_Debug::FORMAT_MESSAGE_FROM_SYSTEM
            | Win32_Debug::FORMAT_MESSAGE_IGNORE_INSERTS;
        // If dwFlags includes FORMAT_MESSAGE_ALLOCATE_BUFFER, the function 
        // allocates a buffer using the LocalAlloc function, and places the 
        // pointer to the buffer at the address specified in lpBuffer.
        let len = Win32_Debug::FormatMessageW(
            flags,
            std::ptr::null_mut(),
            err,
            0,
            (&mut buf) as *mut *mut u16 as *mut u16,
            0,
            std::ptr::null_mut(),
        );
        if len == 0 || buf.is_null() {
            return format!("Win32 error {}", err);
        }
        // Turn to String and free the buffer via LocalFree.
        let slice = std::slice::from_raw_parts(buf, len as usize);
        let s = String::from_utf16_lossy(slice).trim().to_string();
        // LocalFree
        let _ = Win32_Foundation::LocalFree(buf as *mut c_void);
        s
    }
}

fn state_to_str(s: u32) -> &'static str {
    match s {
        Win32_Memory::MEM_COMMIT => "COMMIT",
        Win32_Memory::MEM_RESERVE => "RESERVE",
        Win32_Memory::MEM_FREE => "FREE",
        _ => "UNKNOWN",
    }
}

fn type_to_str(t: u32) -> &'static str {
    match t {
        Win32_Memory::MEM_IMAGE => "IMAGE",
        Win32_Memory::MEM_MAPPED => "MAPPED",
        Win32_Memory::MEM_PRIVATE => "PRIVATE",
        0 => "—",
        _ => "UNKNOWN",
    }
}

fn protect_to_str(p: u32) -> &'static str {
    match p & 0xff {
        Win32_Memory::PAGE_NOACCESS => "NOACCESS",
        Win32_Memory::PAGE_READONLY => "READONLY",
        Win32_Memory::PAGE_READWRITE => "READWRITE",
        Win32_Memory::PAGE_WRITECOPY => "WRITECOPY",
        Win32_Memory::PAGE_EXECUTE => "EXECUTE",
        Win32_Memory::PAGE_EXECUTE_READ => "EXECUTE_READ",
        Win32_Memory::PAGE_EXECUTE_READWRITE => "EXECUTE_READWRITE",
        Win32_Memory::PAGE_EXECUTE_WRITECOPY => "EXECUTE_WRITECOPY",
        0 => "—",
        _ => "UNKNOWN",
    }
}

#[allow(
    unused,
    reason = "This is a debug function for development. To be removed soon."
)]
unsafe fn walk_range(hproc: Win32_Foundation::HANDLE, mut addr: usize, end: usize) {
    println!(
        "-- VirtualQuery walk: ({:p} - {:p}) --",
        addr as *const c_void, end as *const c_void
    );
    while addr < end {
        let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        let got = unsafe {
            Win32_Memory::VirtualQueryEx(
                hproc,
                addr as *const c_void,
                &mut mbi,
                std::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
            )
        };
        if got == 0 {
            let e = unsafe { GetLastError() };
            println!("VirtualQueryEx failed at {:#x}: {}", addr, werr_text(e));
            break;
        }
        let base = mbi.BaseAddress as usize;
        let size = mbi.RegionSize;
        let next = base.saturating_add(size);
        println!(
            "[{:#016x} - {:#016x}) size={:#x}  State={}  Protect={}  Type={}",
            base,
            next,
            size,
            state_to_str(mbi.State),
            protect_to_str(mbi.Protect),
            type_to_str(mbi.Type)
        );
        if next <= addr {
            break;
        }
        addr = next;
    }
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for WindowsUserland {
    // TODO(chuqi): These are currently "magic numbers" grabbed from my Windows 11 SystemInformation.
    // The actual values should be determined by `GetSystemInfo()`.
    //
    // NOTE: make sure the values are PAGE_ALIGNED.
    const TASK_ADDR_MIN: usize = 0x1_0000;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;
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

        // 1) In case we have a suggested VA range, we first check and deal with the case
        // that the address (range) is already reserved.
        if suggested_range.start != 0 {
            assert!(suggested_range.start as usize >= <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::
                                                            TASK_ADDR_MIN);
            assert!(suggested_range.end as usize <= <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::
                                                            TASK_ADDR_MAX);

            let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
            do_query_on_region(&mut mbi, base_addr);

            // The region is already either reserved or committed, and we need to handle both cases.
            if mbi.State == Win32_Memory::MEM_RESERVE || mbi.State == Win32_Memory::MEM_COMMIT {
                let region_base = mbi.BaseAddress as usize;
                let region_size = mbi.RegionSize as usize;
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
                                    &mut old_protect,
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

                // Update tracker for existing reserved region
                let current_request_end = core::cmp::min(suggested_range.end, region_end);
                let current_subrange = suggested_range.start..current_request_end;
                self.add_subrange_to_allocations(current_subrange);

                // If the requested end address is beyond the reserved region (cross the region),
                // we need to allocate more memory.
                if request_end > region_end {
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
        let mut region_free_end_addr = aligned_base_addr as usize + aligned_size;
        let mut region_free_size = aligned_size;

        if !aligned_base_addr.is_null() {
            let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
            do_query_on_region(&mut mbi, aligned_base_addr);

            region_free_end_addr = core::cmp::min(
                region_free_end_addr,
                mbi.BaseAddress as usize + mbi.RegionSize as usize,
            );
            region_free_size = core::cmp::min(
                region_free_size,
                region_free_end_addr - aligned_base_addr as usize,
            );
        }

        // Do the real VirtualAlloc to reserve and commit the memory.
        let addr: *mut c_void = unsafe {
            VirtualAlloc2(
                GetCurrentProcess(),
                aligned_base_addr,
                region_free_size,
                Win32_Memory::MEM_COMMIT | Win32_Memory::MEM_RESERVE,
                prot_flags(initial_permissions),
                core::ptr::null_mut(),
                0,
            )
        };
        assert!(
            !addr.is_null(),
            "VirtualAlloc2 failed. Address: {:p}, Size: {}, Permissions: {:?}. Error: {} str: {}",
            aligned_base_addr,
            region_free_size,
            initial_permissions,
            unsafe { GetLastError() },
            werr_text(unsafe { GetLastError() })
        );

        if fixed_address {
            assert!(
                addr == aligned_base_addr,
                "VirtualAlloc2 returned address {:p} which is not the expected fixed address {:p}",
                addr,
                aligned_base_addr
            );
        }

        let granularity = self.sys_info.read().unwrap().dwAllocationGranularity as usize;
        let range_allocated = (addr as usize)..(addr as usize + region_free_size);

        // Track the new allocation - break down to allocation_granularity-sized chunk. This is to avoid the
        // gap when tracking `AllocationInformation` in huge memory chunks such as 4 * 64KB sizes.
        let suggested_size = size; // The requested size
        let mut current_actual = range_allocated.start;
        let mut remaining_size = core::cmp::min(suggested_size, region_free_size);

        while current_actual < range_allocated.end && remaining_size > 0 {
            assert!(current_actual + granularity <= range_allocated.end);
            let chunk_end = current_actual + granularity;
            let current_chunk = current_actual..chunk_end;

            // Calculate how much of this chunk is actually used
            let used_size_in_chunk = core::cmp::min(remaining_size, granularity);
            let used_subrange = current_actual..(current_actual + used_size_in_chunk);

            self.track_allocation(
                current_chunk.clone(),
                range_allocated.clone(),
                used_subrange,
            );

            remaining_size -= used_size_in_chunk;
            current_actual = chunk_end;
        }

        // Prefetch the memory range if requested
        if populate_pages_immediately {
            do_prefetch_on_range(addr as usize, aligned_size);
        }

        // Do another allocate_pages if region_free_size < aligned_size
        if region_free_size < aligned_size {
            let supposed_request_end = addr as usize + aligned_size as usize;
            <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::allocate_pages(
                self,
                range_allocated.end..supposed_request_end,
                initial_permissions,
                can_grow_down,
                populate_pages_immediately,
                true,
            )?;
        }

        Ok(litebox::platform::trivial_providers::TransparentMutPtr {
            inner: addr.cast::<u8>(),
        })
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        // Use our tracking mechanism to handle proper deallocation
        let reserved_regions_to_free = self.remove_subrange_from_allocations(range.clone());
        if !reserved_regions_to_free.is_empty() {
            // Release all reserved regions that are now completely unused
            for region_to_free in reserved_regions_to_free {
                let ok = unsafe {
                    VirtualFree(
                        region_to_free.start as *mut c_void,
                        0,
                        Win32_Memory::MEM_RELEASE,
                    ) != 0
                };
                assert!(
                    ok,
                    "VirtualFree(MEM_RELEASE) on range ({:p} - {:p}) failed: {}. str: {}",
                    region_to_free.start as *mut c_void,
                    region_to_free.end as *mut c_void,
                    unsafe { GetLastError() },
                    werr_text(unsafe { GetLastError() })
                );
            }
        } else {
            let mut decommit_base = range.start;
            // Decommit the region at mbi boundary
            while decommit_base < range.end {
                let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
                do_query_on_region(&mut mbi, decommit_base as *mut c_void);
                assert!(mbi.BaseAddress as usize == decommit_base);

                let base = mbi.BaseAddress as usize;
                let size = mbi.RegionSize as usize;
                let next = base + size;
                let free_size = core::cmp::min(range.len(), size);

                let ok = unsafe {
                    VirtualFree(
                        decommit_base as *mut c_void,
                        free_size,
                        Win32_Memory::MEM_DECOMMIT,
                    ) != 0
                };
                assert!(
                    ok,
                    "VirtualFree(MEM_DECOMMIT) on range ({:p} - {:p}) failed: {}. str: {}",
                    decommit_base as *mut c_void,
                    (decommit_base + free_size) as *mut c_void,
                    unsafe { GetLastError() },
                    werr_text(unsafe { GetLastError() })
                );

                decommit_base = next;
            }
        }
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
    let res = match litebox_common_linux::SyscallRequest::try_from_raw(syscall_number, ctx) {
        Ok(d) => {
            let syscall_handler: SyscallHandler = SYSCALL_HANDLER
                .read()
                .unwrap()
                .expect("Should have run `register_syscall_handler` by now");
            syscall_handler(d)
        }
        Err(err) => err.as_neg() as isize,
    };

    res
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

/// WindowsUserland platform's thread-local storage implementation.
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
    use core::sync::atomic::{AtomicU32, AtomicUsize};
    use std::thread::sleep;

    use crate::WindowsUserland;
    use litebox::platform::PageManagementProvider;
    use litebox::platform::{RawMutex, ThreadLocalStorageProvider as _};

    #[test]
    fn test_raw_mutex() {
        let mutex = std::sync::Arc::new(super::RawMutex {
            inner: AtomicU32::new(0),
            waiter_count: AtomicUsize::new(0),
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
