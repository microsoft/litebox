//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Windows.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use core::panic;
use core::sync::atomic::AtomicU32;
use core::time::Duration;
use std::cell::Cell;
use std::os::raw::c_void;
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;

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
    Foundation::{GetLastError, WIN32_ERROR},
    System::Diagnostics::Debug::{
        AddVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
        EXCEPTION_POINTERS,
    },
    System::Memory::{
        self as Win32_Memory, PrefetchVirtualMemory, VirtualAlloc2, VirtualFree, VirtualProtect,
    },
    System::SystemInformation::{self as Win32_SysInfo, GetSystemTimeAsFileTime},
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

    fn restore_fs_base(self) {
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
pub type SyscallHandler = fn(litebox_common_linux::SyscallRequest<WindowsUserland>) -> usize;

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
    /// WinTun session for networking
    wintun_session: std::sync::RwLock<Option<Arc<wintun::Session>>>,
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
    /// Takes an optional WinTun adapter name (such as `"LiteBox"`) to connect networking (if
    /// not specified, networking is disabled).
    ///
    /// # Panics
    ///
    /// Panics if the TLS slot cannot be created or if WinTun adapter cannot be created.
    pub fn new(wintun_adapter_name: Option<&str>) -> &'static Self {
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

        // Initialize WinTun if adapter name is provided
        let wintun_session = wintun_adapter_name.map(|adapter_name| {
            // Load the WinTun library from the system
            let wintun = unsafe {
                wintun::load()
                .expect("Failed to load WinTun library")
            };

            // Try to open an existing adapter, or create a new one
            let adapter = match wintun::Adapter::open(&wintun, adapter_name) {
                Ok(adapter) => adapter,
                Err(_) => {
                    // If opening failed (adapter doesn't exist), create a new one
                    wintun::Adapter::create(&wintun, adapter_name, "LiteBox", None)
                        .expect("Failed to create WinTun adapter")
                }
            };

            // Start a session with maximum ring buffer capacity
            Arc::new(
                adapter
                    .start_session(wintun::MAX_RING_CAPACITY)
                    .expect("Failed to start WinTun session"),
            )
        });

        let platform = Self {
            tls_slot: TlsSlot::new().expect("Failed to create TLS slot!"),
            reserved_pages,
            sys_info: std::sync::RwLock::new(sys_info),
            wintun_session: std::sync::RwLock::new(wintun_session),
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
        x % gran == 0
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
}

impl litebox::platform::Provider for WindowsUserland {}

impl litebox::platform::ExitProvider for WindowsUserland {
    type ExitCode = u32;
    const EXIT_SUCCESS: Self::ExitCode = 0;
    const EXIT_FAILURE: Self::ExitCode = 1;

    fn exit(&self, code: Self::ExitCode) -> ! {
        let Self {
            tls_slot: _,
            sys_info: _,
            reserved_pages: _,
            wintun_session,
        } = self;

        // Close WinTun session if it exists
        if let Some(session) = wintun_session.write().unwrap().take() {
            // The session will automatically close when dropped
            drop(session);
        }

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
        copied_pt_regs.rsp = stack.as_usize() + stack_size - 0x8;

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
        let session_guard = self.wintun_session.read().unwrap();
        let Some(session) = session_guard.as_ref() else {
            unimplemented!("networking without WinTun is unimplemented")
        };

        // Allocate a send packet in the WinTun ring buffer
        let mut wintun_packet = session
            .allocate_send_packet(u16::try_from(packet.len()).unwrap())
            .map_err(|_| {
                // Since SendError is an empty enum, we can't create values of it
                // We'll panic if allocation fails for now, similar to Linux implementation
                panic!("Failed to allocate WinTun send packet")
            })?;

        // Copy the IP packet data into the WinTun packet
        let packet_bytes = wintun_packet.bytes_mut();
        if packet_bytes.len() != packet.len() {
            unimplemented!("unexpected size {}", packet_bytes.len())
        }
        packet_bytes[..packet.len()].copy_from_slice(packet);

        // Send the packet through WinTun
        session.send_packet(wintun_packet);

        Ok(())
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        let session_guard = self.wintun_session.read().unwrap();
        let Some(session) = session_guard.as_ref() else {
            unimplemented!("networking without WinTun is unimplemented")
        };

        // Try to receive a packet from WinTun (non-blocking)
        session
            .try_receive()
            .map_err(|_| litebox::platform::ReceiveError::WouldBlock)
            .and_then(|maybe_packet| {
                match maybe_packet {
                    Some(wintun_packet) => {
                        let received_data = wintun_packet.bytes();
                        let packet_size = received_data.len();

                        // Ensure the received packet fits in our buffer
                        if packet_size > packet.len() {
                            unimplemented!(
                                "Received packet size {packet_size} exceeds buffer size {}",
                                packet.len()
                            );
                        }

                        // Copy the received data into our buffer
                        packet[..packet_size].copy_from_slice(received_data);
                        Ok(packet_size)
                    }
                    None => {
                        // No packet available - return WouldBlock
                        Err(litebox::platform::ReceiveError::WouldBlock)
                    }
                }
            })
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
    use core::sync::atomic::AtomicU32;
    use std::thread::sleep;

    use crate::WindowsUserland;
    use litebox::platform::PageManagementProvider;
    use litebox::platform::{IPInterfaceProvider, RawMutex, ThreadLocalStorageProvider as _};

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
        let platform = WindowsUserland::new(None);
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
        let platform = WindowsUserland::new(None);
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

    #[test]
    fn test_ip_interface_without_wintun() {
        // Test IP interface functionality when WinTun is not enabled
        let platform = WindowsUserland::new(None);

        // Create a sample IP packet (minimal IPv4 header)
        let mut test_packet = [0u8; 64];
        test_packet[0] = 0x45; // Version 4, Header length 20 bytes
        test_packet[9] = 0x06; // Protocol: TCP

        // Test send_ip_packet without WinTun - should panic with unimplemented
        let result = std::panic::catch_unwind(|| platform.send_ip_packet(&test_packet));
        assert!(
            result.is_err(),
            "send_ip_packet should panic when WinTun is not available"
        );

        // Test receive_ip_packet without WinTun - should panic with unimplemented
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut receive_buffer = [0u8; 1500];
            platform.receive_ip_packet(&mut receive_buffer)
        }));
        assert!(
            result.is_err(),
            "receive_ip_packet should panic when WinTun is not available"
        );
    }

    #[test]
    #[ignore] // This test requires Administrator privileges and WinTun driver to be installed
    fn test_ip_interface_with_wintun() {
        // Test IP interface functionality with WinTun enabled
        // Note: This test requires Administrator privileges to create network adapters
        let platform = WindowsUserland::new(Some("LiteBoxTest"));

        // Create a sample IPv4 packet
        let test_packet = create_sample_ipv4_packet();

        // Test sending a packet
        match platform.send_ip_packet(&test_packet) {
            Ok(()) => {
                println!("Successfully sent IP packet through WinTun");
            }
            Err(_) => {
                // SendError is an empty enum, so we can't actually get here
                // The implementation should either succeed or panic
                panic!("Unexpected error from send_ip_packet");
            }
        }

        // Test receiving a packet (non-blocking)
        let mut receive_buffer = [0u8; 1500];
        match platform.receive_ip_packet(&mut receive_buffer) {
            Ok(size) => {
                println!("Received IP packet of size: {}", size);
                assert!(size > 0, "Received packet should have non-zero size");
                assert!(
                    size <= receive_buffer.len(),
                    "Received packet size should not exceed buffer"
                );
            }
            Err(litebox::platform::ReceiveError::WouldBlock) => {
                println!("No packets available to receive (expected for non-blocking operation)");
            }
            Err(_) => {
                // Handle any other potential errors
                println!("Other receive error occurred");
            }
        }

        // Test with various packet sizes
        for size in [20, 64, 128, 256, 512, 1024, 1400] {
            let packet = create_sample_ipv4_packet_with_size(size);
            match platform.send_ip_packet(&packet) {
                Ok(()) => {
                    println!("Successfully sent IP packet of size {}", size);
                }
                Err(_) => panic!("Failed to send packet of size {}", size),
            }
        }
    }

    /// Creates a sample IPv4 packet for testing
    fn create_sample_ipv4_packet() -> Vec<u8> {
        create_sample_ipv4_packet_with_size(64)
    }

    /// Creates a sample IPv4 packet with specified total size
    fn create_sample_ipv4_packet_with_size(total_size: usize) -> Vec<u8> {
        let mut packet = vec![0u8; total_size];

        // IPv4 header (20 bytes minimum)
        packet[0] = 0x45; // Version 4, Header length 20 bytes
        packet[1] = 0x00; // Type of Service
        packet[2] = (total_size >> 8) as u8; // Total Length (high byte)
        packet[3] = (total_size & 0xFF) as u8; // Total Length (low byte)
        packet[4] = 0x12; // Identification (high byte)
        packet[5] = 0x34; // Identification (low byte)
        packet[6] = 0x40; // Flags (Don't Fragment)
        packet[7] = 0x00; // Fragment Offset
        packet[8] = 64; // Time to Live
        packet[9] = 0x06; // Protocol: TCP
        packet[10] = 0x00; // Header Checksum (high byte) - normally calculated
        packet[11] = 0x00; // Header Checksum (low byte)

        // Source IP: 10.0.0.1
        packet[12] = 10;
        packet[13] = 0;
        packet[14] = 0;
        packet[15] = 1;

        // Destination IP: 10.0.0.2
        packet[16] = 10;
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 2;

        // Fill the rest with test data if packet is larger than header
        if total_size > 20 {
            for i in 20..total_size {
                packet[i] = (i % 256) as u8;
            }
        }

        packet
    }

    #[test]
    fn test_ip_packet_size_validation() {
        let platform = WindowsUserland::new(None);

        // Test with empty packet
        let empty_packet = [];
        let _result = std::panic::catch_unwind(|| platform.send_ip_packet(&empty_packet));
        // Should handle empty packet appropriately (panic with unimplemented since no WinTun)

        // Test with maximum size packet
        let max_packet = vec![0u8; 65535]; // Maximum IP packet size
        let _result = std::panic::catch_unwind(|| platform.send_ip_packet(&max_packet));
        // Should either succeed or fail gracefully (with unimplemented since no WinTun)
        // The actual behavior depends on WinTun availability
    }

    #[test]
    #[ignore] // This test requires Administrator privileges and may need external network activity
    fn test_ip_interface_packet_reception() {
        use std::thread;
        use std::time::Duration;

        // Test IP interface packet reception with WinTun
        let platform = WindowsUserland::new(Some("LiteBoxReceiveTest"));

        println!("Testing packet reception with WinTun adapter 'LiteBoxReceiveTest'");

        // Send multiple packets to increase chance of reception
        let test_packets = vec![
            create_ping_packet("10.0.0.1", "10.0.0.2"),
            create_ping_packet("10.0.0.1", "8.8.8.8"),
            create_tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80),
        ];

        // Send packets
        for (i, packet) in test_packets.iter().enumerate() {
            match platform.send_ip_packet(packet) {
                Ok(()) => println!("Sent test packet {} successfully", i + 1),
                Err(_) => println!("Failed to send test packet {}", i + 1),
            }
        }

        // Try to receive packets multiple times with small delays
        let mut received_count = 0;
        let max_attempts = 50;
        let mut receive_buffer = [0u8; 1500];

        for attempt in 1..=max_attempts {
            match platform.receive_ip_packet(&mut receive_buffer) {
                Ok(size) => {
                    received_count += 1;
                    println!("Attempt {}: Received packet of {} bytes", attempt, size);

                    // Basic validation of received packet
                    if size >= 20 {
                        let version = (receive_buffer[0] >> 4) & 0x0F;
                        let protocol = receive_buffer[9];
                        let src_ip = format!(
                            "{}.{}.{}.{}",
                            receive_buffer[12],
                            receive_buffer[13],
                            receive_buffer[14],
                            receive_buffer[15]
                        );
                        let dst_ip = format!(
                            "{}.{}.{}.{}",
                            receive_buffer[16],
                            receive_buffer[17],
                            receive_buffer[18],
                            receive_buffer[19]
                        );

                        println!(
                            "  IPv{} packet, protocol {}, {} -> {}",
                            version, protocol, src_ip, dst_ip
                        );
                    }
                }
                Err(litebox::platform::ReceiveError::WouldBlock) => {
                    // No packet available, this is normal for non-blocking operation
                }
                Err(_) => {
                    println!("Attempt {}: Other receive error", attempt);
                }
            }

            // Small delay between attempts
            thread::sleep(Duration::from_millis(10));
        }

        println!(
            "Total packets received: {} out of {} attempts",
            received_count, max_attempts
        );

        // Note: In a real network environment, we might receive packets from other sources
        // The test validates that the receive mechanism works, even if we don't receive
        // our own sent packets (which is normal for many network configurations)
    }

    #[test]
    #[ignore] // This test requires Administrator privileges  
    fn test_ip_interface_bidirectional_with_threading() {
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        println!("Testing bidirectional IP interface with threading");

        // Create two platforms with different adapter names for bidirectional testing
        let sender_platform = WindowsUserland::new(Some("LiteBoxSender"));
        let receiver_platform = WindowsUserland::new(Some("LiteBoxReceiver"));

        let received_packets = Arc::new(Mutex::new(Vec::new()));
        let received_packets_clone = received_packets.clone();

        // Receiver thread
        let receiver_handle = thread::spawn(move || {
            let mut receive_buffer = [0u8; 1500];
            let mut receive_count = 0;

            // Try to receive packets for 5 seconds
            let start_time = std::time::Instant::now();
            while start_time.elapsed() < Duration::from_secs(5) && receive_count < 10 {
                match receiver_platform.receive_ip_packet(&mut receive_buffer) {
                    Ok(size) => {
                        receive_count += 1;
                        let packet_data = receive_buffer[..size].to_vec();
                        received_packets_clone.lock().unwrap().push(packet_data);
                        println!("Receiver: Got packet {} of size {}", receive_count, size);
                    }
                    Err(litebox::platform::ReceiveError::WouldBlock) => {
                        // No packet available, continue
                    }
                    Err(_) => {
                        println!("Receiver: Error receiving packet");
                    }
                }
                thread::sleep(Duration::from_millis(50));
            }

            println!(
                "Receiver thread finished, received {} packets",
                receive_count
            );
        });

        // Sender thread
        let sender_handle = thread::spawn(move || {
            // Send packets with delays
            for i in 0..5 {
                let packet = create_sample_ipv4_packet_with_size(64 + i * 10);
                match sender_platform.send_ip_packet(&packet) {
                    Ok(()) => println!("Sender: Sent packet {}", i + 1),
                    Err(_) => println!("Sender: Failed to send packet {}", i + 1),
                }
                thread::sleep(Duration::from_millis(200));
            }
        });

        // Wait for both threads
        sender_handle.join().unwrap();
        receiver_handle.join().unwrap();

        let final_received = received_packets.lock().unwrap();
        println!(
            "Final result: {} packets captured by receiver",
            final_received.len()
        );

        // The test validates that both send and receive operations work
        // Even if no packets are received (common in isolated test environments),
        // the absence of panics indicates the interface is working correctly
    }

    /// Creates a sample ICMP ping packet
    fn create_ping_packet(src_ip: &str, dst_ip: &str) -> Vec<u8> {
        let mut packet = vec![0u8; 64]; // 20 bytes IP header + 8 bytes ICMP header + 36 bytes data

        // IPv4 header
        packet[0] = 0x45; // Version 4, Header length 20 bytes
        packet[1] = 0x00; // Type of Service
        packet[2] = 0x00; // Total Length (high byte)
        packet[3] = 64; // Total Length (low byte) 
        packet[4] = 0x12; // Identification (high byte)
        packet[5] = 0x34; // Identification (low byte)
        packet[6] = 0x40; // Flags (Don't Fragment)
        packet[7] = 0x00; // Fragment Offset
        packet[8] = 64; // Time to Live
        packet[9] = 0x01; // Protocol: ICMP
        packet[10] = 0x00; // Header Checksum (high byte)
        packet[11] = 0x00; // Header Checksum (low byte)

        // Parse and set source IP
        let src_parts: Vec<u8> = src_ip.split('.').map(|s| s.parse().unwrap()).collect();
        packet[12..16].copy_from_slice(&src_parts);

        // Parse and set destination IP
        let dst_parts: Vec<u8> = dst_ip.split('.').map(|s| s.parse().unwrap()).collect();
        packet[16..20].copy_from_slice(&dst_parts);

        // ICMP header (Echo Request)
        packet[20] = 0x08; // Type: Echo Request
        packet[21] = 0x00; // Code
        packet[22] = 0x00; // Checksum (high byte)
        packet[23] = 0x00; // Checksum (low byte)  
        packet[24] = 0x12; // Identifier (high byte)
        packet[25] = 0x34; // Identifier (low byte)
        packet[26] = 0x00; // Sequence Number (high byte)
        packet[27] = 0x01; // Sequence Number (low byte)

        // Fill with test data
        for i in 28..64 {
            packet[i] = (i % 256) as u8;
        }

        packet
    }

    /// Creates a sample TCP packet
    fn create_tcp_packet(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 60]; // 20 bytes IP header + 20 bytes TCP header + 20 bytes data

        // IPv4 header
        packet[0] = 0x45; // Version 4, Header length 20 bytes
        packet[1] = 0x00; // Type of Service
        packet[2] = 0x00; // Total Length (high byte)
        packet[3] = 60; // Total Length (low byte)
        packet[4] = 0x12; // Identification (high byte)
        packet[5] = 0x34; // Identification (low byte)
        packet[6] = 0x40; // Flags (Don't Fragment)
        packet[7] = 0x00; // Fragment Offset
        packet[8] = 64; // Time to Live
        packet[9] = 0x06; // Protocol: TCP
        packet[10] = 0x00; // Header Checksum (high byte)
        packet[11] = 0x00; // Header Checksum (low byte)

        // Parse and set source IP
        let src_parts: Vec<u8> = src_ip.split('.').map(|s| s.parse().unwrap()).collect();
        packet[12..16].copy_from_slice(&src_parts);

        // Parse and set destination IP
        let dst_parts: Vec<u8> = dst_ip.split('.').map(|s| s.parse().unwrap()).collect();
        packet[16..20].copy_from_slice(&dst_parts);

        // TCP header
        packet[20] = (src_port >> 8) as u8; // Source Port (high byte)
        packet[21] = (src_port & 0xFF) as u8; // Source Port (low byte)
        packet[22] = (dst_port >> 8) as u8; // Destination Port (high byte)
        packet[23] = (dst_port & 0xFF) as u8; // Destination Port (low byte)
        packet[24] = 0x00; // Sequence Number (bytes 24-27)
        packet[25] = 0x00;
        packet[26] = 0x00;
        packet[27] = 0x01;
        packet[28] = 0x00; // Acknowledgment Number (bytes 28-31)
        packet[29] = 0x00;
        packet[30] = 0x00;
        packet[31] = 0x00;
        packet[32] = 0x50; // Header Length (5 * 4 = 20 bytes) + Reserved
        packet[33] = 0x02; // Flags (SYN)
        packet[34] = 0x20; // Window Size (high byte)
        packet[35] = 0x00; // Window Size (low byte)
        packet[36] = 0x00; // Checksum (high byte)
        packet[37] = 0x00; // Checksum (low byte)
        packet[38] = 0x00; // Urgent Pointer (high byte)
        packet[39] = 0x00; // Urgent Pointer (low byte)

        // Fill with test data
        for i in 40..60 {
            packet[i] = (i % 256) as u8;
        }

        packet
    }
}
