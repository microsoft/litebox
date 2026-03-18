// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Windows.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use core::cell::Cell;
use core::panic;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::cell::RefCell;
use std::os::raw::c_void;
use std::os::windows::io::AsRawHandle as _;
use std::sync::{Arc, Mutex, OnceLock};

use litebox::platform::ImmediatelyWokenUp;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::{
    AllocationError, FixedAddressBehavior, MemoryRegionPermissions,
};
use litebox::shim::{ContinueOperation, Exception};
use litebox::utils::TruncateExt as _;
use litebox_common_linux::PunchthroughSyscall;

use windows_sys::Win32::Foundation::{self as Win32_Foundation, FILETIME};
use windows_sys::Win32::{
    Foundation::GetLastError,
    System::Diagnostics::Debug::{
        AddVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
        EXCEPTION_POINTERS, EXCEPTION_RECORD,
    },
    System::Memory::{
        self as Win32_Memory, PrefetchVirtualMemory, VirtualAlloc2, VirtualFree, VirtualProtect,
    },
    System::SystemInformation::{self as Win32_SysInfo, GetSystemTimePreciseAsFileTime},
    System::Threading::{self as Win32_Threading, GetCurrentProcess},
    System::WindowsProgramming::QueryUnbiasedInterruptTimePrecise,
};
use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

// Thread-local storage for FS base state
thread_local! {
    static THREAD_FS_BASE: Cell<usize> = const { Cell::new(0) };
}

// Thread-local storage for guest GS base. When non-zero, switch_to_guest
// writes this value via wrgsbase before entering the guest. This allows
// NT-mode guests (Windows PE) to see a synthesized TEB via gs:[...].
// For Linux-mode guests this stays 0 and GS is left unchanged.
thread_local! {
    static THREAD_GS_BASE: Cell<u64> = const { Cell::new(0) };
}

/// VA-partition constants for multi-process support.
///
/// Each guest process is assigned a non-overlapping 1 TiB VA partition.
/// The number of partitions is determined at runtime from the platform's
/// actual maximum user-mode address.
mod va_partitions {
    /// Size of each VA partition (1 TiB).
    pub const PARTITION_SIZE: usize = 1 << 40;

    /// The lowest usable guest address (matches `TASK_ADDR_MIN`).
    pub const VA_MIN: usize = 0x1_0000;
}

/// Hardcoded upper bound for guest VA (one-past-the-end).
///
/// This must not exceed `GetSystemInfo().lpMaximumApplicationAddress + 1`.
/// A `debug_assert` in `WindowsUserland::new()` validates this at runtime.
const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;

/// Tracks which VA partition slots are allocated.
///
/// Uses `Vec<bool>` so the number of slots can be determined at runtime
/// from `GetSystemInfo().lpMaximumApplicationAddress`.
struct PartitionState {
    allocated: alloc::vec::Vec<bool>,
}

impl PartitionState {
    /// Create a new partition state sized for the given VA range.
    fn new(va_max: usize) -> Self {
        let num_slots = va_max / va_partitions::PARTITION_SIZE;
        Self {
            allocated: alloc::vec![false; num_slots],
        }
    }

    /// Number of partition slots.
    fn num_slots(&self) -> usize {
        self.allocated.len()
    }

    /// Claim the next free slot without checking for host allocations.
    ///
    /// Used for the initial address space (slot 0), which shares the VA
    /// partition with the host process. Host allocations in this range are
    /// expected and harmless because the initial guest pages are explicitly
    /// mapped by the loader.
    fn allocate(&mut self) -> Option<u32> {
        for (i, used) in self.allocated.iter_mut().enumerate() {
            if !*used {
                *used = true;
                return Some(i as u32);
            }
        }
        None
    }

    /// Claim the next free slot whose VA range has no host allocations.
    ///
    /// Calls `probe` on each candidate slot's range. If `probe` returns `true`
    /// (clean), the slot is allocated. Slots where `probe` returns `false` are
    /// skipped (not marked allocated — they may become usable later).
    fn allocate_probed(&mut self, probe: impl Fn(core::ops::Range<usize>) -> bool) -> Option<u32> {
        let num_slots = self.num_slots();
        for i in 0..num_slots {
            if !self.allocated[i] {
                let range = Self::compute_range(i as u32, num_slots);
                if probe(range) {
                    self.allocated[i] = true;
                    return Some(i as u32);
                }
            }
        }
        None
    }

    /// Release a previously allocated slot.
    ///
    /// Returns `false` if the slot is out of range or not currently allocated.
    fn deallocate(&mut self, slot: u32) -> bool {
        let idx = slot as usize;
        if idx >= self.num_slots() {
            return false;
        }
        if !self.allocated[idx] {
            return false;
        }
        self.allocated[idx] = false;
        true
    }

    /// Returns `true` if the given slot is currently allocated.
    fn is_allocated(&self, slot: u32) -> bool {
        let idx = slot as usize;
        idx < self.num_slots() && self.allocated[idx]
    }

    /// Return the VA range for the given slot, clipped to `VA_MIN..va_max`.
    fn range_of(&self, slot: u32) -> core::ops::Range<usize> {
        Self::compute_range(slot, self.num_slots())
    }

    /// Compute the VA range for a slot given the total number of slots.
    fn compute_range(slot: u32, num_slots: usize) -> core::ops::Range<usize> {
        let base = (slot as usize) * va_partitions::PARTITION_SIZE;
        let va_max = num_slots * va_partitions::PARTITION_SIZE;
        let start = base.max(va_partitions::VA_MIN);
        let end = (base + va_partitions::PARTITION_SIZE).min(va_max);
        start..end
    }
}

/// Probe a VA range with `VirtualQuery` to check for host allocations.
///
/// Returns `true` if the entire range is free (`MEM_FREE`), meaning no
/// host DLLs, heap, or system allocations occupy it. Used at partition
/// allocation time to skip slots with ASLR-placed host mappings.
fn is_va_range_clean(range: core::ops::Range<usize>) -> bool {
    let mut addr = range.start;
    while addr < range.end {
        let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        let ok = unsafe {
            Win32_Memory::VirtualQuery(
                addr as *const c_void,
                &raw mut mbi,
                core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
            ) != 0
        };
        if !ok {
            // VirtualQuery failed — treat as unclean to be safe.
            return false;
        }
        if mbi.State != Win32_Memory::MEM_FREE {
            return false;
        }
        addr = mbi.BaseAddress as usize + mbi.RegionSize;
        if addr == 0 {
            break;
        }
    }
    true
}

/// Terminal state shared by all stdio streams backed by the same Windows
/// console. This provides the Linux-compatible terminal attributes that the
/// guest expects (via TCGETS/TCSETS) and a stored window size override (for
/// TIOCSWINSZ round-trip).
struct ConsoleTerminalState {
    attrs: litebox::platform::TerminalAttributes,
    winsize: litebox::platform::WindowSize,
    /// Whether `set_window_size` has been called (enables stored override).
    winsize_overridden: bool,
}

impl Default for ConsoleTerminalState {
    fn default() -> Self {
        Self {
            attrs: litebox::platform::TerminalAttributes::new_default(),
            winsize: litebox::platform::WindowSize {
                rows: 0,
                cols: 0,
                xpixel: 0,
                ypixel: 0,
            },
            winsize_overridden: false,
        }
    }
}

/// Minimal FFI wrapper for WinTUN (Layer-3 TUN driver for Windows).
///
/// Loads `wintun.dll` dynamically via `LoadLibraryW`/`GetProcAddress` to avoid
/// adding a crate dependency. Only the functions needed for IP packet I/O are
/// resolved.
mod wintun_ffi {
    use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HANDLE, HMODULE};
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    type WintunOpenAdapterFn = unsafe extern "system" fn(name: *const u16) -> HANDLE;
    type WintunCloseAdapterFn = unsafe extern "system" fn(adapter: HANDLE);
    type WintunStartSessionFn = unsafe extern "system" fn(adapter: HANDLE, capacity: u32) -> HANDLE;
    type WintunEndSessionFn = unsafe extern "system" fn(session: HANDLE);
    type WintunGetReadWaitEventFn = unsafe extern "system" fn(session: HANDLE) -> HANDLE;
    type WintunReceivePacketFn =
        unsafe extern "system" fn(session: HANDLE, packet_size: *mut u32) -> *mut u8;
    type WintunReleaseReceivePacketFn =
        unsafe extern "system" fn(session: HANDLE, packet: *const u8);
    type WintunAllocateSendPacketFn =
        unsafe extern "system" fn(session: HANDLE, packet_size: u32) -> *mut u8;
    type WintunSendPacketFn =
        unsafe extern "system" fn(session: HANDLE, packet: *const u8, packet_size: u32);

    /// Resolved function pointers from `wintun.dll`.
    struct WintunDll {
        _module: HMODULE,
        open_adapter: WintunOpenAdapterFn,
        close_adapter: WintunCloseAdapterFn,
        start_session: WintunStartSessionFn,
        end_session: WintunEndSessionFn,
        get_read_wait_event: WintunGetReadWaitEventFn,
        receive_packet: WintunReceivePacketFn,
        release_receive_packet: WintunReleaseReceivePacketFn,
        allocate_send_packet: WintunAllocateSendPacketFn,
        send_packet: WintunSendPacketFn,
    }

    impl Drop for WintunDll {
        fn drop(&mut self) {
            // Safety: _module is a valid HMODULE from a successful LoadLibraryW.
            unsafe {
                FreeLibrary(self._module);
            }
        }
    }

    /// Encode a Rust `&str` as a null-terminated UTF-16 wide string.
    fn to_wide(s: &str) -> alloc::vec::Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0)).collect()
    }

    /// Resolve a single function pointer from a loaded DLL.
    ///
    /// # Safety
    ///
    /// The caller must ensure `module` is a valid HMODULE and the resolved
    /// pointer matches the expected function signature `T`.
    unsafe fn resolve<T: Copy>(module: HMODULE, name: &[u8]) -> Result<T, String> {
        // Safety: `name` is a null-terminated byte slice, module is valid.
        let proc = unsafe { GetProcAddress(module, name.as_ptr()) };
        match proc {
            Some(p) => {
                // Safety: caller guarantees T matches the actual function signature.
                Ok(unsafe { core::mem::transmute_copy(&p) })
            }
            None => Err(format!(
                "GetProcAddress failed for {}: error {}",
                core::str::from_utf8(&name[..name.len() - 1]).unwrap_or("?"),
                unsafe { GetLastError() }
            )),
        }
    }

    impl WintunDll {
        /// Load `wintun.dll` from the given path and resolve all required exports.
        fn load(dll_path: &str) -> Result<Self, String> {
            let wide_path = to_wide(dll_path);
            // Safety: wide_path is a valid null-terminated UTF-16 string.
            let module = unsafe { LoadLibraryW(wide_path.as_ptr()) };
            if module.is_null() {
                return Err(format!(
                    "LoadLibraryW({dll_path}) failed: error {}",
                    unsafe { GetLastError() }
                ));
            }
            // Safety: module is a valid HMODULE; function name byte strings are
            // null-terminated and the type parameters match the WinTUN ABI.
            unsafe {
                Ok(Self {
                    _module: module,
                    open_adapter: resolve(module, b"WintunOpenAdapter\0")?,
                    close_adapter: resolve(module, b"WintunCloseAdapter\0")?,
                    start_session: resolve(module, b"WintunStartSession\0")?,
                    end_session: resolve(module, b"WintunEndSession\0")?,
                    get_read_wait_event: resolve(module, b"WintunGetReadWaitEvent\0")?,
                    receive_packet: resolve(module, b"WintunReceivePacket\0")?,
                    release_receive_packet: resolve(module, b"WintunReleaseReceivePacket\0")?,
                    allocate_send_packet: resolve(module, b"WintunAllocateSendPacket\0")?,
                    send_packet: resolve(module, b"WintunSendPacket\0")?,
                })
            }
        }
    }

    /// An active WinTUN session for sending and receiving IP packets.
    ///
    /// Owns the adapter and session handles. Dropping this struct ends the
    /// session and closes the adapter.
    pub struct WinTunSession {
        dll: WintunDll,
        adapter: HANDLE,
        session: HANDLE,
        read_wait_event: HANDLE,
    }

    // Safety: WinTUN session handles are thread-safe — the DLL synchronises
    // internally with ring buffer atomics.
    unsafe impl Send for WinTunSession {}
    unsafe impl Sync for WinTunSession {}

    /// Maximum ring buffer capacity for WinTUN sessions (0x400_0000 = 64 MiB).
    const WINTUN_MAX_RING_CAPACITY: u32 = 0x400_0000;

    impl WinTunSession {
        /// Open an existing WinTUN adapter by name and start a packet session.
        ///
        /// The adapter must already exist (created by the `wintun_create_adapter`
        /// tool running as Administrator).
        ///
        /// `dll_path` is the filesystem path to `wintun.dll`.
        /// `adapter_name` is the human-readable adapter name (e.g. "litebox0").
        pub fn open(dll_path: &str, adapter_name: &str) -> Result<Self, String> {
            let dll = WintunDll::load(dll_path)?;
            let wide_name = to_wide(adapter_name);

            // Safety: wide_name is a valid null-terminated UTF-16 string.
            let adapter = unsafe { (dll.open_adapter)(wide_name.as_ptr()) };
            if adapter.is_null() {
                return Err(format!(
                    "WintunOpenAdapter('{adapter_name}') failed: error {}. \
                     Create the adapter first with: wintun_create_adapter {adapter_name}",
                    unsafe { GetLastError() }
                ));
            }

            // Safety: adapter is a valid, non-null WinTUN adapter handle.
            let session = unsafe { (dll.start_session)(adapter, WINTUN_MAX_RING_CAPACITY) };
            if session.is_null() {
                // Safety: adapter is valid — close it before returning error.
                unsafe { (dll.close_adapter)(adapter) };
                return Err(format!("WintunStartSession failed: error {}", unsafe {
                    GetLastError()
                }));
            }

            // Safety: session is a valid, non-null WinTUN session handle.
            let read_wait_event = unsafe { (dll.get_read_wait_event)(session) };

            Ok(Self {
                dll,
                adapter,
                session,
                read_wait_event,
            })
        }

        /// Send an IP packet through the TUN interface.
        pub fn send(&self, packet: &[u8]) -> Result<(), i32> {
            let len = packet.len() as u32;
            // Safety: session is valid; requesting `len` bytes for send buffer.
            let buf = unsafe { (self.dll.allocate_send_packet)(self.session, len) };
            if buf.is_null() {
                let err = unsafe { GetLastError() } as i32;
                return Err(err);
            }
            // Safety: WinTUN guarantees `buf` points to at least `len` bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(packet.as_ptr(), buf, packet.len());
                (self.dll.send_packet)(self.session, buf, len);
            }
            Ok(())
        }

        /// Try to receive an IP packet (non-blocking).
        ///
        /// Returns `Ok(n)` with number of bytes written to `out`, or
        /// `Err(ERROR_NO_MORE_ITEMS)` when no packet is available.
        pub fn try_receive(&self, out: &mut [u8]) -> Result<usize, i32> {
            let mut pkt_size: u32 = 0;
            // Safety: session is valid; pkt_size is a valid output pointer.
            let pkt = unsafe { (self.dll.receive_packet)(self.session, &mut pkt_size) };
            if pkt.is_null() {
                let err = unsafe { GetLastError() } as i32;
                return Err(err);
            }
            let n = (pkt_size as usize).min(out.len());
            // Safety: WinTUN guarantees `pkt` points to `pkt_size` bytes.
            // We must release the packet even if it's larger than `out`.
            unsafe {
                core::ptr::copy_nonoverlapping(pkt, out.as_mut_ptr(), n);
                (self.dll.release_receive_packet)(self.session, pkt);
            }
            Ok(n)
        }

        /// Get the Windows event HANDLE that is signalled when a packet is ready
        /// to be received. Use with `WaitForSingleObject` for efficient polling.
        pub fn read_wait_event(&self) -> HANDLE {
            self.read_wait_event
        }
    }

    impl Drop for WinTunSession {
        fn drop(&mut self) {
            // Safety: session and adapter are valid handles obtained from
            // WintunStartSession/WintunOpenAdapter.
            unsafe {
                (self.dll.end_session)(self.session);
                (self.dll.close_adapter)(self.adapter);
            }
        }
    }
}

/// The userland Windows platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct WindowsUserland {
    reserved_pages: alloc::vec::Vec<core::ops::Range<usize>>,
    sys_info: std::sync::RwLock<Win32_SysInfo::SYSTEM_INFO>,
    partitions: Mutex<PartitionState>,
    /// Shared console terminal state for all stdio streams backed by the same
    /// Windows console. Protected by a mutex for thread safety (guest threads
    /// may call TCGETS/TCSETS concurrently).
    console_terminal: Mutex<ConsoleTerminalState>,
    /// Atomic flag for cancelling pending `read_from_stdin()` calls.
    stdin_cancelled: core::sync::atomic::AtomicBool,
    /// WinTUN session for IP packet I/O (None when networking is disabled).
    tun_session: Option<wintun_ffi::WinTunSession>,
    /// Host-owned guest GS → host GS lookup table for NT-mode guests.
    /// The table is Box-allocated so its address is stable for the
    /// lifetime of the platform (trampoline code holds a raw pointer).
    guest_gs_table: Box<GuestGsTable>,
}

impl core::fmt::Debug for WindowsUserland {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WindowsUserland").finish_non_exhaustive()
    }
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
    fn get_thread_fs_base() -> usize {
        THREAD_FS_BASE.get()
    }

    /// Set the current thread's FS base
    fn set_thread_fs_base(new_base: usize) {
        THREAD_FS_BASE.set(new_base);
        Self::restore_thread_fs_base();
    }

    /// Restore the current thread's FS base from saved state
    fn restore_thread_fs_base() {
        unsafe {
            litebox_common_linux::wrfsbase(THREAD_FS_BASE.get());
        }
    }

    /// Initialize FS base state for a new thread
    fn init_thread_fs_base() {
        Self::set_thread_fs_base(0);
    }
}

/// Guest GS base management for NT-mode (Windows PE) guests.
///
/// When running NT-mode guests, GS must point to the guest's synthesized TEB
/// so that `gs:[...]` accesses in guest code see the correct TEB/PEB. The
/// platform handles GS transitions:
///
/// - **Host → Guest** (`switch_to_guest`): reads `guest_gs_base` from
///   `TlsState` and executes `wrgsbase` in naked asm (after all host
///   GS-dependent operations, before the jump to guest code).
///
/// - **Guest → Host** (syscall via trampoline): the stub DLL trampoline
///   executes `wrgsbase(host_gs)` before jumping to `syscall_callback`.
///
/// - **Guest → Host** (exception): the Windows kernel restores GS to the
///   host TEB when delivering exceptions to user mode.
///
/// For Linux-mode guests, `guest_gs_base` stays 0 and GS is left unchanged.
impl WindowsUserland {
    /// Set the guest GS base for the current thread.
    ///
    /// Must be called before [`run_thread`] / [`run_thread_ref`] on the
    /// thread that will execute the guest.
    pub fn set_guest_gs_base(value: u64) {
        THREAD_GS_BASE.set(value);
    }

    /// Returns a pointer to the GS lookup table's first entry.
    ///
    /// This pointer is stable for the lifetime of the platform and is passed
    /// to stub DLL builders so the trampoline asm can find the table.
    pub fn guest_gs_table_ptr(&self) -> *const litebox_common_windows::gs_table::GsTableEntry {
        self.guest_gs_table.base_ptr()
    }
}

/// Host-owned guest GS → host GS lookup table.
///
/// Entries are written by the platform during thread start and removed on
/// thread exit. The stub DLL trampolines do a lock-free linear scan of
/// the raw entry array on every syscall entry.
///
/// # Concurrency
///
/// Insertions and removals go through a `Mutex`. The trampoline reads are
/// lock-free — they rely on the publishing protocol:
/// - insert: write `host_gs` first, then `guest_gs` (sentinel is 0)
/// - remove: zero `guest_gs` first
///
/// This is safe because x86-64 guarantees that aligned 8-byte stores are
/// atomic with respect to aligned 8-byte loads.
struct GuestGsTable {
    entries: Mutex<GuestGsTableInner>,
}

struct GuestGsTableInner {
    /// The raw table read by the trampoline asm. The last entry is always
    /// the zero sentinel.
    data: [litebox_common_windows::gs_table::GsTableEntry;
        litebox_common_windows::gs_table::MAX_GS_TABLE_ENTRIES + 1],
}

#[derive(Debug)]
enum GuestGsTableError {
    /// The table is full (all MAX_GS_TABLE_ENTRIES slots are in use).
    Full,
    /// An entry with this guest_gs already exists.
    DuplicateGuestGs(u64),
}

impl core::fmt::Display for GuestGsTableError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Full => write!(f, "GS table full"),
            Self::DuplicateGuestGs(gs) => write!(f, "duplicate guest GS: 0x{gs:X}"),
        }
    }
}

impl GuestGsTable {
    fn new() -> Self {
        Self {
            entries: Mutex::new(GuestGsTableInner {
                data: [litebox_common_windows::gs_table::GsTableEntry::default();
                    litebox_common_windows::gs_table::MAX_GS_TABLE_ENTRIES + 1],
            }),
        }
    }

    /// Returns a stable pointer to the first entry for the trampoline asm.
    fn base_ptr(&self) -> *const litebox_common_windows::gs_table::GsTableEntry {
        // Safety: the Mutex protects the inner data, but we need a raw
        // pointer for the trampoline. The pointer is stable because the
        // GuestGsTable (and its inner array) lives in a Box with a stable
        // address.
        let guard = self.entries.lock().unwrap();
        guard.data.as_ptr()
    }

    /// Insert a mapping. Writes `host_gs` before `guest_gs` so the
    /// trampoline never sees a non-zero `guest_gs` with stale `host_gs`.
    fn insert(&self, guest_gs: u64, host_gs: u64) -> Result<(), GuestGsTableError> {
        assert_ne!(guest_gs, 0, "cannot insert zero guest_gs (sentinel)");
        let mut guard = self.entries.lock().unwrap();
        // Check for duplicates and find first reusable slot (empty or tombstone).
        let mut empty_idx = None;
        for (i, entry) in guard.data.iter().enumerate() {
            if entry.guest_gs == guest_gs {
                return Err(GuestGsTableError::DuplicateGuestGs(guest_gs));
            }
            if (entry.guest_gs == 0
                || entry.guest_gs == litebox_common_windows::gs_table::TOMBSTONE_GUEST_GS)
                && empty_idx.is_none()
            {
                // Don't use the very last slot — it's the sentinel.
                if i < litebox_common_windows::gs_table::MAX_GS_TABLE_ENTRIES {
                    empty_idx = Some(i);
                }
            }
        }
        let idx = empty_idx.ok_or(GuestGsTableError::Full)?;
        // Publish: host_gs first, then guest_gs (makes entry visible).
        let entry = &mut guard.data[idx];
        // Use volatile writes to prevent reordering across the fence.
        unsafe {
            core::ptr::write_volatile(&raw mut entry.host_gs, host_gs);
        }
        core::sync::atomic::fence(Ordering::Release);
        unsafe {
            core::ptr::write_volatile(&raw mut entry.guest_gs, guest_gs);
        }
        Ok(())
    }

    /// Remove a mapping by guest_gs. Writes a tombstone so the lock-free
    /// trampoline scanner continues past the slot rather than stopping.
    fn remove(&self, guest_gs: u64) {
        let mut guard = self.entries.lock().unwrap();
        for entry in guard.data.iter_mut() {
            if entry.guest_gs == guest_gs {
                // Write tombstone instead of zero so the scanner doesn't
                // treat this as end-of-table.
                unsafe {
                    core::ptr::write_volatile(
                        &raw mut entry.guest_gs,
                        litebox_common_windows::gs_table::TOMBSTONE_GUEST_GS,
                    );
                }
                core::sync::atomic::fence(Ordering::Release);
                unsafe {
                    core::ptr::write_volatile(&raw mut entry.host_gs, 0);
                }
                return;
            }
        }
    }

    /// Lock-free lookup of host_gs for a given guest_gs.
    ///
    /// Used by the VEH handler to restore host GS when an exception occurs
    /// while guest GS is active. Returns `None` if `current_gs` is not a
    /// known guest GS (i.e., it's already the host GS).
    #[allow(dead_code)]
    fn lookup(&self, current_gs: u64) -> Option<u64> {
        if current_gs == 0 {
            return None;
        }
        // Lock-free scan using the raw base pointer (same as the trampoline asm).
        // Safety: the base_ptr is stable, entries are published with volatile
        // writes and a release fence, and we read with volatile loads.
        let ptr = {
            // base_ptr() locks the mutex, but we might be in VEH where we can't.
            // The data address is stable (it's inside a Box that was leaked),
            // so we can compute it from the known table base_ptr that was already
            // saved at init time.
            GS_TABLE_PTR.load(core::sync::atomic::Ordering::Acquire) as *const Self
        };
        if ptr.is_null() {
            return None;
        }
        // Safety: we read from the stable address computed from the leaked allocation.
        // The entries are valid as long as the platform exists (forever).
        let entries = unsafe {
            let table = &*ptr;
            // Lock the mutex if possible; otherwise just read raw.
            if let Ok(guard) = table.entries.try_lock() {
                let base = guard.data.as_ptr();
                drop(guard);
                base
            } else {
                // Can't lock — another thread holds it. The data is still
                // readable at the same address; we just might see a partially
                // updated entry. For the VEH use case (restoring host GS),
                // a false negative is acceptable (we'd just fail to find TLS
                // and return EXCEPTION_CONTINUE_SEARCH).
                return None;
            }
        };
        for i in 0..litebox_common_windows::gs_table::MAX_GS_TABLE_ENTRIES + 1 {
            let entry = unsafe { &*entries.add(i) };
            let gs = unsafe { core::ptr::read_volatile(&entry.guest_gs) };
            if gs == 0 {
                break;
            }
            if gs == current_gs {
                let host = unsafe { core::ptr::read_volatile(&entry.host_gs) };
                return Some(host);
            }
        }
        None
    }
}

/// Global pointer to the platform's GS lookup table. Set once during
/// `WindowsUserland::new()` and read by `run_thread_inner` / RAII guard.
static GS_TABLE_PTR: std::sync::atomic::AtomicPtr<GuestGsTable> =
    std::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Raw pointer to the first GsTableEntry in the table. Used by the VEH
/// handler for lock-free, allocation-free GS restoration. Set once in
/// `WindowsUserland::new()` alongside `GS_TABLE_PTR`.
static GS_TABLE_BASE_PTR: std::sync::atomic::AtomicPtr<
    litebox_common_windows::gs_table::GsTableEntry,
> = std::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Helper to get the global GS table reference.
fn global_gs_table() -> &'static GuestGsTable {
    let ptr = GS_TABLE_PTR.load(core::sync::atomic::Ordering::Acquire);
    assert!(!ptr.is_null(), "GS table not initialized");
    // Safety: the pointer was set during WindowsUserland::new() and the
    // GuestGsTable lives inside the Box-leaked WindowsUserland — stable
    // for the lifetime of the process.
    unsafe { &*ptr }
}

/// Naked asm trampoline for the VEH handler.
///
/// The Windows kernel restores whatever GS base was active at the time of
/// the exception. If the guest had set GS to its synthetic TEB, the Rust
/// function prologue (stack cookies, TLS) would use the guest TEB and crash.
///
/// This naked trampoline:
/// 1. Saves the current (possibly guest) GS
/// 2. Scans the GS lookup table to find the host GS
/// 3. Restores host GS via wrgsbase
/// 4. Calls the real Rust VEH handler
/// 5. On return, restores the original GS (so the CONTEXT's GS is preserved)
#[unsafe(naked)]
unsafe extern "system" fn vectored_exception_handler_trampoline(
    _exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    core::arch::naked_asm!(
        // Save non-volatile registers we'll use
        "push rbx",
        "push rdi",
        "push rsi",
        // Save exception_info (rcx on Windows x64)
        "mov rdi, rcx",
        // Read current GS base
        "rdgsbase rbx",
        // Load the GS table base pointer (global static)
        "mov rsi, QWORD PTR [rip + {GS_TABLE_BASE_PTR}]",
        "test rsi, rsi",
        "jz 2f",     // null → skip scan
        "test rbx, rbx",
        "jz 2f",     // GS=0 → skip scan
        // Linear scan: find entry where guest_gs == rbx
        "1:",
        "mov rax, QWORD PTR [rsi]",   // entry.guest_gs
        "test rax, rax",
        "jz 2f",                       // sentinel → not found (GS is already host)
        "cmp rax, rbx",
        "je 3f",                       // match!
        "add rsi, 16",                 // next entry
        "jmp 1b",
        // 3: found — restore host GS
        "3:",
        "mov rax, QWORD PTR [rsi + 8]", // entry.host_gs
        "wrgsbase rax",
        // 2: GS is now host (either restored or was already host).
        // Call the real Rust VEH handler.
        "2:",
        "mov rcx, rdi",               // restore exception_info arg
        "sub rsp, 0x20",              // shadow space for Windows x64 ABI
        "call {real_handler}",
        "add rsp, 0x20",
        // Save return value
        "mov esi, eax",
        // Only restore original GS if we did NOT handle the exception.
        // EXCEPTION_CONTINUE_SEARCH = 0: restore original GS so the next
        //   VEH handler or default handler sees the GS it expects.
        // EXCEPTION_CONTINUE_EXECUTION = -1: leave host GS active because
        //   the inner handler redirected RIP to a host callback that needs
        //   host TLS access via GS.
        "test eax, eax",
        "jnz 4f",                     // handled → skip GS restore
        "wrgsbase rbx",               // not handled → restore original GS
        "4:",
        // Restore return value and non-volatile registers
        "mov eax, esi",
        "pop rsi",
        "pop rdi",
        "pop rbx",
        "ret",
        GS_TABLE_BASE_PTR = sym GS_TABLE_BASE_PTR,
        real_handler = sym vectored_exception_handler_inner,
    );
}

/// The real VEH handler, called from the trampoline after GS is restored.
unsafe extern "system" fn vectored_exception_handler_inner(
    exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    let (info, exception_record, context);
    unsafe {
        info = *exception_info;
        exception_record = &*info.ExceptionRecord;
        context = &mut *info.ContextRecord;
    }

    let Some(tls) = get_tls_ptr() else {
        // TLS slot not initialized yet; cannot be in guest.
        return EXCEPTION_CONTINUE_SEARCH;
    };
    let tls = unsafe { &*tls };

    if !tls.is_in_guest.get() {
        // This might be a faulting guest memory access in LiteBox code. Try to
        // recover.
        if exception_record.ExceptionCode == Win32_Foundation::EXCEPTION_ACCESS_VIOLATION
            && let Some(recover) =
                litebox::mm::exception_table::search_exception_tables(context.Rip.truncate())
        {
            // Found a matching exception table entry.
            context.Rip = recover as u64;
            return EXCEPTION_CONTINUE_EXECUTION;
        } else {
            // Not one of our exceptions; let other handlers process it.
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    tls.is_in_guest.set(false);

    // Debug output exceptions raised by the guest (e.g., OutputDebugStringA/W
    // under CRT init). These are informational only; silently resume.
    // We must restore guest GS before returning because the trampoline skips
    // GS restore on EXCEPTION_CONTINUE_EXECUTION (it assumes RIP was
    // redirected to host code). Here we're resuming guest code which needs
    // guest GS.
    const DBG_PRINTEXCEPTION_C: u32 = 0x40010006;
    const DBG_PRINTEXCEPTION_WIDE_C: u32 = 0x4001000A;
    if exception_record.ExceptionCode == DBG_PRINTEXCEPTION_C as i32
        || exception_record.ExceptionCode == DBG_PRINTEXCEPTION_WIDE_C as i32
    {
        tls.is_in_guest.set(true);
        let guest_gs = tls.guest_gs_base.get();
        if guest_gs != 0 {
            unsafe {
                core::arch::asm!(
                    "wrgsbase {gs}",
                    gs = in(reg) guest_gs,
                    options(nostack, preserves_flags)
                );
            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Cast to ExecutionContext — PtRegs is at offset 0 of ExecutionContext, so
    // the pointer to PtRegs is also a valid pointer to ExecutionContext.
    let exec_ctx = unsafe {
        &mut *(tls.guest_context_top.get().wrapping_sub(1)
            as *mut litebox_common_linux::ExecutionContext)
    };
    save_guest_context(exec_ctx, context);

    // If it looks like fs base was cleared, then go through the interrupt path
    // instead of the exception path to restore the fs base and try again.
    //
    // This is done instead of just fixing up fsbase and returning here to avoid
    // missing a real interrupt that arrives while resuming the guest. Go through
    // the interrupt path to ensure that any pending interrupts are also handled.
    if exception_record.ExceptionCode == Win32_Foundation::EXCEPTION_ACCESS_VIOLATION
        && unsafe { litebox_common_linux::rdfsbase() } == 0
        && WindowsUserland::get_thread_fs_base() != 0
    {
        set_context_to_interrupt_callback(tls, context);
    } else {
        // Push the exception record onto the host stack.
        let exception_record_ptr = tls.host_sp.get().cast::<EXCEPTION_RECORD>().wrapping_sub(1);
        assert!(exception_record_ptr.is_aligned());
        unsafe { exception_record_ptr.write(*exception_record) };

        // Re-align the stack pointer.
        let rsp = exception_record_ptr as usize & !15;

        // Ensure that `run_thread_arch` is linked in so that `exception_callback` is visible.
        let _ = run_thread_arch as *const () as usize;

        // Update the thread context to jump to the exception handler.
        context.Rip = exception_callback as *const () as usize as u64;
        context.Rsp = rsp as u64;
        context.Rbp = tls.host_bp.get() as u64;
        context.Rdx = exception_record_ptr as u64;
    }

    EXCEPTION_CONTINUE_EXECUTION
}

fn save_guest_context(
    guest_context: &mut litebox_common_linux::ExecutionContext,
    context: &windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
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
    } = &mut guest_context.regs;
    *r15 = context.R15.truncate();
    *r14 = context.R14.truncate();
    *r13 = context.R13.truncate();
    *r12 = context.R12.truncate();
    *rbp = context.Rbp.truncate();
    *rbx = context.Rbx.truncate();
    *r11 = context.R11.truncate();
    *r10 = context.R10.truncate();
    *r9 = context.R9.truncate();
    *r8 = context.R8.truncate();
    *rax = context.Rax.truncate();
    *rcx = context.Rcx.truncate();
    *rdx = context.Rdx.truncate();
    *rsi = context.Rsi.truncate();
    *rdi = context.Rdi.truncate();
    *orig_rax = context.Rax.truncate();
    *rip = context.Rip.truncate();
    *eflags = context.EFlags as usize;
    *rsp = context.Rsp.truncate();

    // Save FP/SIMD state from the CONTEXT's FXSAVE area into FpRegs.
    // The Windows CONTEXT.FltSave (XSAVE_FORMAT) is layout-compatible with the
    // 512-byte FXSAVE image stored in FpRegs.data.
    unsafe {
        core::ptr::copy_nonoverlapping(
            &raw const context.Anonymous.FltSave as *const u8,
            guest_context.fp_regs.data.as_mut_ptr(),
            core::mem::size_of::<litebox_common_linux::FpRegs>(),
        );
    }
}

impl WindowsUserland {
    /// Create a new userland-Windows platform for use in `LiteBox`.
    ///
    /// `tun_device_name` is the name of the WinTUN adapter to open/create for
    /// networking. Pass `None` to disable networking.
    ///
    /// # Panics
    ///
    /// Panics if the TLS slot cannot be created.
    pub fn new(tun_device_name: Option<&str>) -> &'static Self {
        let mut sys_info = Win32_SysInfo::SYSTEM_INFO::default();
        Self::get_system_information(&mut sys_info);

        let va_min = sys_info.lpMinimumApplicationAddress as usize;
        let va_max = sys_info.lpMaximumApplicationAddress as usize;
        #[cfg(debug_assertions)]
        {
            println!("System information.");
            println!("=> Max user address: {va_max:#x}");
            println!("=> Min user address: {va_min:#x}");
        }

        // Validate that the hardcoded PageManagementProvider constants are
        // consistent with the runtime values from GetSystemInfo. These run
        // once at startup, so assert! (not debug_assert!) is appropriate.
        assert!(
            va_min <= va_partitions::VA_MIN,
            "runtime lpMinimumApplicationAddress ({va_min:#x}) is above \
             VA_MIN ({:#x})",
            va_partitions::VA_MIN,
        );
        // va_max from GetSystemInfo is the last usable byte (inclusive).
        // TASK_ADDR_MAX is one-past-the-end, so compare without overflow.
        assert!(
            TASK_ADDR_MAX - 1 <= va_max,
            "hardcoded TASK_ADDR_MAX ({TASK_ADDR_MAX:#x}) exceeds runtime \
             lpMaximumApplicationAddress ({va_max:#x})",
        );

        // +1 to convert from inclusive last-byte to exclusive upper bound.
        // Safe: on 64-bit Windows, va_max is always well below usize::MAX.
        let partitions = PartitionState::new(va_max + 1);
        #[cfg(debug_assertions)]
        println!(
            "=> VA partitions: {} slots of {} bytes each",
            partitions.num_slots(),
            va_partitions::PARTITION_SIZE,
        );

        let reserved_pages = Self::read_memory_maps();

        // Initialize WinTUN session if a TUN device name was provided.
        let tun_session = tun_device_name.map(|name| {
            // Look for wintun.dll next to the runner executable first, then
            // fall back to plain "wintun.dll" (system PATH).
            let dll_path = std::env::current_exe()
                .ok()
                .and_then(|p| {
                    let dir = p.parent()?;
                    let candidate = dir.join("wintun.dll");
                    candidate
                        .exists()
                        .then(|| candidate.to_string_lossy().into_owned())
                })
                .unwrap_or_else(|| "wintun.dll".to_string());
            wintun_ffi::WinTunSession::open(&dll_path, name)
                .unwrap_or_else(|e| panic!("Failed to initialize WinTUN adapter '{name}': {e}"))
        });

        let platform = Self {
            reserved_pages,
            sys_info: std::sync::RwLock::new(sys_info),
            partitions: Mutex::new(partitions),
            console_terminal: Mutex::new(ConsoleTerminalState::default()),
            stdin_cancelled: core::sync::atomic::AtomicBool::new(false),
            tun_session,
            guest_gs_table: Box::new(GuestGsTable::new()),
        };

        // Initialize it's own fs-base (for the main thread)
        WindowsUserland::init_thread_fs_base();

        // Windows sets FS_BASE to 0 regularly upon scheduling; we register an exception handler
        // to set FS_BASE back to a "stored" value whenever we notice that it has become 0.
        unsafe {
            let _ = AddVectoredExceptionHandler(1, Some(vectored_exception_handler_trampoline));
        }

        // Register a console control handler to receive Ctrl+C
        unsafe {
            windows_sys::Win32::System::Console::SetConsoleCtrlHandler(
                Some(ctrl_c_handler),
                1, // TRUE — add the handler
            );
        }

        let leaked = Box::leak(Box::new(platform));

        // Publish the GS table pointer globally so run_thread_inner can find it.
        GS_TABLE_PTR.store(
            leaked.guest_gs_table.as_ref() as *const GuestGsTable as *mut GuestGsTable,
            core::sync::atomic::Ordering::Release,
        );
        // Also publish the raw base pointer for the VEH handler's lock-free scan.
        GS_TABLE_BASE_PTR.store(
            leaked.guest_gs_table.base_ptr() as *mut litebox_common_windows::gs_table::GsTableEntry,
            core::sync::atomic::Ordering::Release,
        );

        leaked
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

    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        // TODO: Currently we are using a static thread ID and credentials (faked).
        // This is a placeholder for future implementation to use passthrough.
        litebox_common_linux::TaskParams {
            pid: 1000,
            // TODO: placeholder for actual PPID
            ppid: 0,
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
        }
    }

    /// Wait for the TUN device to have a packet ready to read, or until
    /// `timeout` expires. Uses `WaitForSingleObject` on the WinTUN read-wait
    /// event for efficient polling.
    pub fn wait_on_tun(&self, timeout: Option<Duration>) {
        let Some(session) = &self.tun_session else {
            // No TUN device — just sleep for the timeout duration.
            if let Some(t) = timeout {
                std::thread::sleep(t);
            }
            return;
        };
        let ms = timeout.map_or(windows_sys::Win32::System::Threading::INFINITE, |t| {
            let ms = t.as_millis();
            u32::try_from(ms).unwrap_or(u32::MAX)
        });
        // Safety: read_wait_event() returns a valid HANDLE from WintunGetReadWaitEvent.
        unsafe {
            Win32_Threading::WaitForSingleObject(session.read_wait_event(), ms);
        }
    }
}

impl litebox::platform::RawMessageProvider for WindowsUserland {}

impl litebox::platform::Provider for WindowsUserland {}

impl litebox::platform::SignalProvider for WindowsUserland {
    type Signal = litebox_common_linux::signal::Signal;

    fn take_pending_signals(&self, mut f: impl FnMut(Self::Signal)) {
        let bits = get_tls_ptr().map_or(0, |p| {
            unsafe { &*p }
                .pending_host_signals
                .swap(0, Ordering::SeqCst)
        });
        let sigs = litebox_common_linux::signal::SigSet::from_u64(u64::from(bits));
        for signal in sigs {
            f(signal);
        }
    }
}

impl litebox::platform::AddressSpaceProvider for WindowsUserland {
    type AddressSpaceId = u32;

    // The Windows exception dispatcher, allocator metadata, and globals all
    // live in the shared address space. A CoW page fault inside the handler
    // would be fatal, so we must eagerly snapshot all writable pages.
    const EAGER_COW_FOR_VFORK: bool = true;

    fn create_address_space(
        &self,
    ) -> Result<Self::AddressSpaceId, litebox::platform::address_space::AddressSpaceError> {
        // The initial address space shares slot 0 with the host process.
        // Host allocations (exe, DLLs, heap) are expected in this range,
        // so skip the VirtualQuery cleanliness probe.
        self.partitions
            .lock()
            .unwrap()
            .allocate()
            .ok_or(litebox::platform::address_space::AddressSpaceError::NoSpace)
    }

    fn destroy_address_space(
        &self,
        id: Self::AddressSpaceId,
    ) -> Result<(), litebox::platform::address_space::AddressSpaceError> {
        if !self.partitions.lock().unwrap().deallocate(id) {
            return Err(litebox::platform::address_space::AddressSpaceError::InvalidId);
        }
        Ok(())
    }

    fn fork_address_space(
        &self,
        parent: Self::AddressSpaceId,
    ) -> Result<
        litebox::platform::address_space::ForkedAddressSpace<Self::AddressSpaceId>,
        litebox::platform::address_space::AddressSpaceError,
    > {
        // Validate parent and allocate child under a single lock to avoid
        // TOCTOU races (the Linux impl drops and re-acquires the lock).
        let mut partitions = self.partitions.lock().unwrap();
        if !partitions.is_allocated(parent) {
            return Err(litebox::platform::address_space::AddressSpaceError::InvalidId);
        }
        let child = partitions
            .allocate_probed(is_va_range_clean)
            .ok_or(litebox::platform::address_space::AddressSpaceError::NoSpace)?;
        Ok(litebox::platform::address_space::ForkedAddressSpace::SharedWithParent(child))
    }

    fn activate_address_space(
        &self,
        _id: Self::AddressSpaceId,
    ) -> Result<(), litebox::platform::address_space::AddressSpaceError> {
        // No-op on userland — all processes share the host address space.
        Ok(())
    }

    fn address_space_range(
        &self,
        id: Self::AddressSpaceId,
    ) -> Result<core::ops::Range<usize>, litebox::platform::address_space::AddressSpaceError> {
        let partitions = self.partitions.lock().unwrap();
        if !partitions.is_allocated(id) {
            return Err(litebox::platform::address_space::AddressSpaceError::InvalidId);
        }
        Ok(partitions.range_of(id))
    }
}

/// Ensures the module-wide TLS slot index ([`TLS_INDEX`]) has been allocated.
///
/// This must be called before any code that reads `TLS_INDEX`. Both
/// [`run_thread`] (guest threads) and [`run_test_thread`](WindowsUserland::run_test_thread)
/// (test threads) go through here.
fn ensure_tls_index() {
    // Allocate a TLS slot for this module if not already done. This is used as
    // a place to store data across calls to the guest, since all the registers
    // are used by the guest and will be clobbered.
    //
    // We use this instead of native TLS because accesses are easier from
    // assembly. In particular, finding the module's TLS base requires extra
    // registers and/or clobbering flags, whereas we can get the value of a
    // TLS slot with only one register and no changes to flags.
    static REGISTER_KEY: std::sync::Once = const { std::sync::Once::new() };
    REGISTER_KEY.call_once(|| {
        let index = unsafe { windows_sys::Win32::System::Threading::TlsAlloc() };
        assert!(
            index < 64,
            "no non-extended TLS slots available: {index:#x}"
        );
        TLS_INDEX.store(index, Ordering::Relaxed);
    });
}

/// Runs a guest thread using the provided shim and the given initial context.
///
/// This will run until the thread terminates.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread(
    shim: impl litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
    ctx: &mut litebox_common_linux::ExecutionContext,
) {
    ensure_tls_index();
    run_thread_inner(&shim, ctx);
}

/// Run a guest thread using a reference to the shim.
///
/// Unlike [`run_thread`], this version takes a reference instead of
/// ownership, so the caller retains access to the shim after the thread
/// terminates. This is useful when the shim carries state that must be
/// read after execution (e.g., [`NtShimEntrypoints::exit_code`]).
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread_ref<T>(shim: &T, ctx: &mut litebox_common_linux::ExecutionContext)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
{
    ensure_tls_index();
    run_thread_inner(shim, ctx);
}

fn run_thread_inner(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
    ctx: &mut litebox_common_linux::ExecutionContext,
) {
    let tls_state = TlsState::new();
    tls_state
        .guest_context_top
        .set(core::ptr::from_mut(&mut ctx.regs).wrapping_add(1));

    // If this is an NT-mode guest thread (guest_gs_base != 0), register the
    // (guest_gs → host_gs) mapping in the platform-owned GS table so the
    // trampoline can find the host GS on syscall entry.
    let guest_gs = tls_state.guest_gs_base.get();
    let _gs_guard = if guest_gs != 0 {
        let host_gs: u64;
        unsafe {
            core::arch::asm!("rdgsbase {}", out(reg) host_gs, options(nostack, preserves_flags));
        }
        global_gs_table()
            .insert(guest_gs, host_gs)
            .unwrap_or_else(|e| panic!("failed to register GS mapping: {e}"));
        Some(GuestGsMappingGuard { guest_gs })
    } else {
        None
    };

    let mut thread_ctx = ThreadContext {
        shim,
        ctx,
        tls: &tls_state,
    };
    ThreadHandle::run_with_handle(&tls_state, || unsafe {
        run_thread_arch(&mut thread_ctx, &tls_state);
    });
    // Clear guest GS base so a subsequent Linux-mode guest on this thread
    // does not inherit a stale Windows TEB address.
    THREAD_GS_BASE.set(0);
    // _gs_guard drops here → removes the GS table entry
}

/// RAII guard that removes the guest GS → host GS mapping on drop.
struct GuestGsMappingGuard {
    guest_gs: u64,
}

impl Drop for GuestGsMappingGuard {
    fn drop(&mut self) {
        global_gs_table().remove(self.guest_gs);
    }
}

static TLS_INDEX: AtomicU32 = AtomicU32::new(u32::MAX);

struct TlsState {
    host_sp: Cell<*mut u128>,
    host_bp: Cell<*mut u128>,
    guest_context_top: Cell<*mut litebox_common_linux::PtRegs>,
    scratch: Cell<usize>,
    /// Second scratch slot used by the syscall callback to preserve the
    /// syscall number (rax) across fxsave64 which clobbers rax.
    scratch2: Cell<usize>,
    is_in_guest: Cell<bool>,
    interrupt: Cell<bool>,
    /// Guest GS base address. When non-zero, switch_to_guest restores this
    /// via wrgsbase before entering the guest (NT-mode guests need GS → TEB).
    guest_gs_base: Cell<u64>,
    continue_context:
        Box<std::cell::UnsafeCell<windows_sys::Win32::System::Diagnostics::Debug::CONTEXT>>,
    /// Bitmask of pending host-originated signals for this thread.
    pending_host_signals: AtomicU32,
    /// Pointer to the `Waker` currently being waited on, or null if not
    /// waiting.
    waiting_waker: std::sync::atomic::AtomicPtr<litebox::event::wait::Waker<WindowsUserland>>,
}

impl TlsState {
    /// Creates a new `TlsState` with all fields zeroed / defaulted.
    ///
    /// Copies `THREAD_GS_BASE` into the struct so the switch_to_guest asm
    /// can read it without going through the Windows thread_local! API.
    fn new() -> Self {
        Self {
            host_sp: Cell::new(core::ptr::null_mut()),
            host_bp: Cell::new(core::ptr::null_mut()),
            guest_context_top: core::ptr::null_mut::<litebox_common_linux::PtRegs>().into(),
            scratch: 0.into(),
            scratch2: 0.into(),
            is_in_guest: false.into(),
            interrupt: false.into(),
            guest_gs_base: Cell::new(THREAD_GS_BASE.get()),
            continue_context: Box::default(),
            pending_host_signals: AtomicU32::new(0),
            waiting_waker: std::sync::atomic::AtomicPtr::new(std::ptr::null_mut()),
        }
    }
}

/// Stores `tls` in the current thread's Windows TLS slot.
///
/// # Safety
///
/// The caller must ensure `tls` remains valid for the duration of its use.
unsafe fn install_tls(tls: &TlsState) {
    let tls_index = TLS_INDEX.load(Ordering::Relaxed);
    unsafe {
        windows_sys::Win32::System::Threading::TlsSetValue(
            tls_index,
            core::ptr::from_ref(tls).cast(),
        );
    }
}

/// Clears the current thread's Windows TLS slot.
fn uninstall_tls() {
    let tls_index = TLS_INDEX.load(Ordering::Relaxed);
    unsafe { windows_sys::Win32::System::Threading::TlsSetValue(tls_index, core::ptr::null()) };
}

fn get_tls_ptr() -> Option<*const TlsState> {
    let tls_index = TLS_INDEX.load(Ordering::Relaxed);
    if tls_index == u32::MAX {
        return None;
    }
    let ptr =
        unsafe { windows_sys::Win32::System::Threading::TlsGetValue(tls_index).cast::<TlsState>() };
    if ptr.is_null() {
        return None;
    }
    Some(ptr)
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
unsafe extern "C-unwind" fn run_thread_arch(thread_ctx: &mut ThreadContext, tls_state: &TlsState) {
    core::arch::naked_asm!(
    "
    .seh_proc run_thread
    // Push all non-volatiles
    push rbp
    .seh_pushreg rbp
    mov rbp, rsp
    .seh_setframe rbp, 0
    push rbx
    .seh_pushreg rbx
    push rdi
    .seh_pushreg rdi
    push rsi
    .seh_pushreg rsi
    push r12
    .seh_pushreg r12
    push r13
    .seh_pushreg r13
    push r14
    .seh_pushreg r14
    push r15
    .seh_pushreg r15
    sub rsp, 168 // align + space for xmm6-xmm15
    .seh_stackalloc 168
    movdqa [rsp + 0*16], xmm6
    .seh_savexmm xmm6, 0*16
    movdqa [rsp + 1*16], xmm7
    .seh_savexmm xmm7, 1*16
    movdqa [rsp + 2*16], xmm8
    .seh_savexmm xmm8, 2*16
    movdqa [rsp + 3*16], xmm9
    .seh_savexmm xmm9, 3*16
    movdqa [rsp + 4*16], xmm10
    .seh_savexmm xmm10, 4*16
    movdqa [rsp + 5*16], xmm11
    .seh_savexmm xmm11, 5*16
    movdqa [rsp + 6*16], xmm12
    .seh_savexmm xmm12, 6*16
    movdqa [rsp + 7*16], xmm13
    .seh_savexmm xmm13, 7*16
    movdqa [rsp + 8*16], xmm14
    .seh_savexmm xmm14, 8*16
    movdqa [rsp + 9*16], xmm15
    .seh_savexmm xmm15, 9*16
    .seh_endprologue

    // Offset into the TEB (gs segment) where TLS slots are stored.
    .equ TEB_TLS_SLOTS_OFFSET, 5248

    push    rcx // Alignment
    push    rcx // Save thread_ctx

    // Save the host rsp and rbp into the TLS state.
    mov     QWORD PTR [rdx + {HOST_SP}], rsp
    mov     QWORD PTR [rdx + {HOST_BP}], rbp

    call {init_handler}
    jmp .Ldone

    // This entry point is called from the guest when it issues a syscall
    // instruction.
    //
    // At entry, the register context is the guest context with the
    // return address in rcx. r11 is an available scratch register (it would
    // contain rflags if the syscall instruction had actually been issued).
    .globl  syscall_callback
syscall_callback:
    // Get the TLS state from the TLS slot and clear the in-guest flag.
    mov     r11d, DWORD PTR [rip + {TLS_INDEX}]
    mov     r11, QWORD PTR gs:[r11 * 8 + TEB_TLS_SLOTS_OFFSET]
    mov     BYTE PTR [r11 + {IS_IN_GUEST}], 0
    // Set rsp to the top of the guest context.
    mov     QWORD PTR [r11 + {SCRATCH}], rsp
    mov     rsp, QWORD PTR [r11 + {GUEST_CONTEXT_TOP}]

    // Save guest FP/SIMD state. fp_regs is at GUEST_CONTEXT_TOP + FP_REGS_PAD
    // (padding between end of PtRegs and start of 64-byte-aligned FpRegs).
    // Preserve rax (syscall number) in scratch2 because fxsave setup clobbers it.
    mov     QWORD PTR [r11 + {SCRATCH2}], rax
    lea     rax, [rsp + {FP_REGS_PAD}]
    fxsave64 [rax]
    // Sanitize MXCSR for host Rust code (guest may have set denormals-are-zero
    // or flush-to-zero bits that could cause unexpected behavior in host math).
    ldmxcsr DWORD PTR [rip + DEFAULT_MXCSR]
    // Restore syscall number from scratch2.
    mov     rax, QWORD PTR [r11 + {SCRATCH2}]
    // Save caller-saved registers
    push    0x2b       // pt_regs->ss = __USER_DS
    push    QWORD PTR [r11 + {SCRATCH}] // pt_regs->sp
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
    push    r12
    push    r13
    push    r14
    push    r15

    /// Reestablish the stack and frame pointers.
    mov     rsp, [r11 + {HOST_SP}]
    mov     rbp, [r11 + {HOST_BP}]

    // Handle the syscall. This will jump back to the guest but
    // will return if the thread is exiting.
    mov  rcx, QWORD PTR [rsp] // thread_ctx
    call {syscall_handler}
    jmp .Ldone

exception_callback:
    // Handle the exception. The stack and frame pointers are already restored,
    // and the guest context is up to date. rcx contains a pointer to the
    // guest pt_regs, and rdx contains a pointer to the exception record.
    mov  rcx, QWORD PTR [rsp] // thread_ctx
    call {exception_handler}
    jmp .Ldone

interrupt_callback:
    mov  rcx, QWORD PTR [rsp] // thread_ctx
    call {interrupt_handler}
    jmp .Ldone

.Ldone:
    // Restore non-volatile registers and return.
    lea  rsp, [rbp - (168 + 56)]
    movdqa xmm6, [rsp + 0*16]
    movdqa xmm7, [rsp + 1*16]
    movdqa xmm8, [rsp + 2*16]
    movdqa xmm9, [rsp + 3*16]
    movdqa xmm10, [rsp + 4*16]
    movdqa xmm11, [rsp + 5*16]
    movdqa xmm12, [rsp + 6*16]
    movdqa xmm13, [rsp + 7*16]
    movdqa xmm14, [rsp + 8*16]
    movdqa xmm15, [rsp + 9*16]
    add rsp, 168 // 10 * 16 + 8 (for stack alignment)
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rsi
    pop  rdi
    pop  rbx
    pop  rbp
    ret
    .seh_endproc

    // Read-only data for MXCSR sanitization (default value with all exceptions
    // masked, round-to-nearest).
    .section .rdata, \"dr\"
    .balign 4
DEFAULT_MXCSR:
    .long 0x1F80
    .text
    ",
    init_handler = sym init_handler,
    syscall_handler = sym syscall_handler,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    TLS_INDEX = sym TLS_INDEX,
    HOST_SP = const core::mem::offset_of!(TlsState, host_sp),
    HOST_BP = const core::mem::offset_of!(TlsState, host_bp),
    GUEST_CONTEXT_TOP = const core::mem::offset_of!(TlsState, guest_context_top),
    SCRATCH = const core::mem::offset_of!(TlsState, scratch),
    SCRATCH2 = const core::mem::offset_of!(TlsState, scratch2),
    IS_IN_GUEST = const core::mem::offset_of!(TlsState, is_in_guest),
    // Padding between end of PtRegs and start of FpRegs in ExecutionContext.
    // FpRegs is align(64); PtRegs is 168 bytes; next 64-byte boundary is 192.
    FP_REGS_PAD = const {
        core::mem::offset_of!(litebox_common_linux::ExecutionContext, fp_regs)
            - core::mem::size_of::<litebox_common_linux::PtRegs>()
    },
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
///
unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::ExecutionContext) -> ! {
    #[unsafe(naked)]
    extern "C" fn switch_to_guest_sysret(ctx: &litebox_common_linux::ExecutionContext) -> ! {
        core::arch::naked_asm!(
            // Restore guest FP/SIMD state before touching any guest registers.
            // rcx = ptr to ExecutionContext; fp_regs is at offset FP_REGS_OFFSET.
            "fxrstor64 [rcx + {FP_REGS_OFFSET}]",
            // Restore guest GS base (if set) from the TlsState. GS still
            // points to the host TEB here, so we can read the TLS slot.
            // This must happen AFTER fxrstor (so any fxrstor fault sees
            // host GS) and BEFORE we start restoring guest registers.
            "mov     r11d, DWORD PTR [rip + {TLS_INDEX}]",
            "mov     r11, QWORD PTR gs:[r11 * 8 + 5248]", // TEB_TLS_SLOTS
            "mov     r11, QWORD PTR [r11 + {GUEST_GS_BASE}]",
            "test    r11, r11",
            "jz      2f",
            "wrgsbase r11",
            "2:",
            // Load all registers from the guest context structure.
            "switch_to_guest_start:",
            "mov rsp, rcx",
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
            "pop rcx",    // skip orig_rax
            "pop rcx",    // read rip into rcx
            "add rsp, 8", // skip cs
            "popfq",
            "pop rsp",
            "jmp rcx", // jump to the entry point of the thread
            "switch_to_guest_end:",
            FP_REGS_OFFSET = const core::mem::offset_of!(litebox_common_linux::ExecutionContext, fp_regs),
            TLS_INDEX = sym TLS_INDEX,
            GUEST_GS_BASE = const core::mem::offset_of!(TlsState, guest_gs_base),
        );
    }

    fn switch_to_guest_ntcontinue(
        tls: &TlsState,
        ctx: &litebox_common_linux::ExecutionContext,
    ) -> ! {
        use litebox::utils::ReinterpretSignedExt;
        use windows_sys::Win32::System::Diagnostics::Debug::{
            CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_FLOATING_POINT_AMD64, CONTEXT_INTEGER_AMD64,
        };
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtContinue(
                ctx: *const CONTEXT,
                raise_alert: u8,
            ) -> windows_sys::Win32::Foundation::NTSTATUS;
        }
        let win_ctx = tls.continue_context.get();
        // SAFETY: no other code accesses `continue_context` while `is_in_guest` is false.
        unsafe {
            win_ctx.write(CONTEXT {
                ContextFlags: CONTEXT_CONTROL_AMD64
                    | CONTEXT_INTEGER_AMD64
                    | CONTEXT_FLOATING_POINT_AMD64,
                EFlags: ctx.eflags.truncate(),
                Rax: ctx.rax as u64,
                Rcx: ctx.rcx as u64,
                Rdx: ctx.rdx as u64,
                Rbx: ctx.rbx as u64,
                Rsp: ctx.rsp as u64,
                Rbp: ctx.rbp as u64,
                Rsi: ctx.rsi as u64,
                Rdi: ctx.rdi as u64,
                R8: ctx.r8 as u64,
                R9: ctx.r9 as u64,
                R10: ctx.r10 as u64,
                R11: ctx.r11 as u64,
                R12: ctx.r12 as u64,
                R13: ctx.r13 as u64,
                R14: ctx.r14 as u64,
                R15: ctx.r15 as u64,
                Rip: ctx.rip as u64,
                ..CONTEXT::default()
            });
            // Copy guest FP state into the CONTEXT's FXSAVE area (FltSave).
            // FltSave is a XSAVE_FORMAT struct which is layout-compatible with
            // the 512-byte FXSAVE image in FpRegs.
            core::ptr::copy_nonoverlapping(
                ctx.fp_regs.data.as_ptr(),
                &raw mut (*win_ctx).Anonymous.FltSave as *mut u8,
                core::mem::size_of::<litebox_common_linux::FpRegs>(),
            );
        }
        // Ensure the context is written before we set `is_in_guest` so that
        // `ThreadHandle::interrupt` can see a consistent state.
        std::sync::atomic::compiler_fence(Ordering::Release);
        tls.is_in_guest.set(true);
        // Restore guest GS base before entering the kernel. SWAPGS in the
        // NtContinue syscall entry/exit preserves the user GS base across
        // the round-trip, so the guest resumes with GS = guest TEB.
        let guest_gs = tls.guest_gs_base.get();
        unsafe {
            if guest_gs != 0 {
                core::arch::asm!(
                    "wrgsbase {gs}",
                    gs = in(reg) guest_gs,
                    options(nostack, preserves_flags)
                );
            }
            let status = NtContinue(win_ctx, 0);
            panic!(
                "NtContinue failed: {}",
                std::io::Error::from_raw_os_error(
                    windows_sys::Win32::Foundation::RtlNtStatusToDosError(status)
                        .reinterpret_as_signed(),
                ),
            );
        }
    }

    let tls = unsafe { &*get_tls_ptr().expect("TLS not initialized") };
    assert!(!tls.is_in_guest.get());

    // Restore fsbase for the guest.
    WindowsUserland::restore_thread_fs_base();

    // The fast path for switching to the guest relies on rcx == rip.This is
    // the common case, because the syscall instruction sets rcx to rip at entry
    // to the kernel. When this is not the case, we use NtContinue to jump to
    // the guest with the full register state.
    //
    // This is much slower, but it is only used for things like signal handlers,
    // so it should not be on the critical path.
    if ctx.rcx == ctx.rip {
        tls.is_in_guest.set(true);
        switch_to_guest_sysret(ctx)
    } else {
        switch_to_guest_ntcontinue(tls, ctx)
    }
}

fn thread_start(
    init_thread: Box<
        dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::ExecutionContext>,
    >,
    mut ctx: litebox_common_linux::ExecutionContext,
) {
    // Allow caller to run some code before we return to the new thread.
    let shim = init_thread.init();

    run_thread_inner(shim.as_ref(), &mut ctx);
}

impl litebox::platform::ThreadProvider for WindowsUserland {
    type ExecutionContext = litebox_common_linux::ExecutionContext;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ThreadHandle;

    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::ExecutionContext,
        init_thread: Box<
            dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::ExecutionContext>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        let ctx = ctx.clone();
        // Use 8 MiB stack (matching Linux default) to avoid overflow from
        // deeply-nested shim call chains. Windows default is only 1 MiB.
        let _handle = std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || thread_start(init_thread, ctx))?;

        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        CURRENT_THREAD_HANDLE.with_borrow(|current| {
            current
                .clone()
                .expect("current thread is not managed by LiteBox")
        })
    }

    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        CURRENT_THREAD_HANDLE.with_borrow(|current| {
            thread.interrupt(current.as_ref());
        });
    }

    #[cfg(debug_assertions)]
    fn run_test_thread<R>(f: impl FnOnce() -> R) -> R {
        // Ensure the module-wide TLS slot is allocated.
        ensure_tls_index();
        let tls = TlsState::new();
        ThreadHandle::run_with_handle(&tls, f)
    }
}

impl litebox::platform::TimerProvider for WindowsUserland {
    type TimerHandle = TimerHandle;
    type Signal = litebox_common_linux::signal::Signal;

    fn create_timer(
        &self,
        signal: Self::Signal,
    ) -> Result<Self::TimerHandle, litebox::platform::TimerCreationError> {
        let ctx = Box::new(TimerCallbackContext { signal });

        // Create a threadpool timer with the callback registered up-front.
        // The callback fires whenever the timer is armed via
        // `SetThreadpoolTimer` and the due time elapses.
        //
        // Safety: We pass a raw pointer to `ctx` which is heap-allocated via
        // `Box` and lives as long as the `TimerHandle`. The `Drop` impl
        // cancels and waits for all in-flight callbacks before the `Box` is
        // dropped, so the pointer remains valid for every callback invocation.
        let tp_timer = unsafe {
            Win32_Threading::CreateThreadpoolTimer(
                Some(threadpool_timer_callback),
                &raw const *ctx as *mut c_void,
                std::ptr::null(),
            )
        };
        assert!(
            tp_timer != 0,
            "CreateThreadpoolTimer failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(TimerHandle {
            tp_timer,
            _ctx: ctx,
        })
    }
}

pub struct TimerHandle {
    tp_timer: Win32_Threading::PTP_TIMER,
    /// Prevent the context from being dropped while the timer is alive.
    /// The raw pointer passed to the threadpool callback points into this box.
    _ctx: Box<TimerCallbackContext>,
}

impl Drop for TimerHandle {
    fn drop(&mut self) {
        // Cancel any pending callback, wait for in-flight callbacks to
        // complete, then close the threadpool timer.
        //
        // After this sequence completes the callback will never run again, so
        // it is safe to let `self.ctx` (the `Box`) drop normally.
        unsafe {
            Win32_Threading::SetThreadpoolTimer(self.tp_timer, std::ptr::null(), 0, 0);
            Win32_Threading::WaitForThreadpoolTimerCallbacks(self.tp_timer, 1);
            Win32_Threading::CloseThreadpoolTimer(self.tp_timer);
        }
    }
}

impl litebox::platform::TimerHandle for TimerHandle {
    fn set_timer(&self, duration: core::time::Duration) {
        if duration.is_zero() {
            // A zero duration cancels the timer without firing.
            // Passing NULL as the due-time pointer tells Windows to cancel
            // the pending callback.
            unsafe {
                Win32_Threading::SetThreadpoolTimer(self.tp_timer, std::ptr::null(), 0, 0);
            }
            return;
        }

        // Due time is in 100 ns intervals; negative means relative.
        // Pack into a FILETIME for SetThreadpoolTimer.
        let due_time_100ns: i64 = {
            let intervals = duration.as_nanos() / 100;
            -(i64::try_from(intervals).unwrap_or(i64::MAX))
        };
        let due_time = FILETIME {
            dwLowDateTime: due_time_100ns.cast_unsigned().truncate(),
            dwHighDateTime: (due_time_100ns >> 32).cast_unsigned().truncate(),
        };

        // Arm the threadpool timer. The callback registered at creation
        // time will fire after `duration` elapses.
        unsafe {
            Win32_Threading::SetThreadpoolTimer(
                self.tp_timer,
                &raw const due_time,
                0, // no repeat
                0, // no window
            );
        }
    }
}

/// Context shared between the `TimerHandle` and the threadpool timer callback.
struct TimerCallbackContext {
    signal: litebox_common_linux::signal::Signal,
}

/// Threadpool timer callback registered via `CreateThreadpoolTimer`.
///
/// Picks an arbitrary active thread and delivers the signal.
unsafe extern "system" fn threadpool_timer_callback(
    _instance: Win32_Threading::PTP_CALLBACK_INSTANCE,
    context: *mut c_void,
    _timer: Win32_Threading::PTP_TIMER,
) {
    // Safety: `context` points to the `TimerCallbackContext` owned by the
    // `TimerHandle`. The handle's `Drop` impl waits for all in-flight
    // callbacks before dropping the context, so this reference is valid.
    let ctx = unsafe { &*context.cast::<TimerCallbackContext>() };
    let thread = ACTIVE_THREADS.lock().unwrap().first().cloned();
    if let Some(thread) = thread {
        thread.deliver_signal(ctx.signal);
    }
}

/// Console control handler registered via `SetConsoleCtrlHandler`.
///
/// When the user presses Ctrl+C, this sets the SIGINT bit on every active
/// managed thread and interrupts them so the shim can deliver the signal.
unsafe extern "system" fn ctrl_c_handler(ctrl_type: u32) -> i32 {
    if ctrl_type != windows_sys::Win32::System::Console::CTRL_C_EVENT {
        return 0; // FALSE — let the next handler deal with it
    }

    // Pick one arbitrary thread to deliver the signal to.
    let thread = ACTIVE_THREADS.lock().unwrap().first().cloned();

    if let Some(thread) = thread {
        thread.deliver_signal(litebox_common_linux::signal::Signal::SIGINT);
    }

    1 // TRUE — we handled it
}

#[derive(Clone)]
pub struct ThreadHandle(Arc<Mutex<Option<ThreadHandleInner>>>);

struct ThreadHandleInner {
    handle: std::os::windows::io::OwnedHandle,
    tls: SendConstPtr<TlsState>,
}

struct SendConstPtr<T>(*const T);
unsafe impl<T> Send for SendConstPtr<T> {}

thread_local! {
    static CURRENT_THREAD_HANDLE: RefCell<Option<ThreadHandle>> = const { RefCell::new(None) };
}

/// Global registry of all active managed thread handles.
///
/// Threads are registered in [`ThreadHandle::run_with_handle`] and
/// removed when the guard drops.
///
/// TODO: This global list only works when we support a single process. For
/// multi-process support, each process (or `WindowsUserland` instance) should
/// track its own thread list.
static ACTIVE_THREADS: Mutex<alloc::vec::Vec<ThreadHandle>> = Mutex::new(alloc::vec::Vec::new());

impl ThreadHandle {
    /// Creates a [`ThreadHandle`] referencing the calling OS thread.
    fn for_current_thread(tls: &TlsState) -> ThreadHandle {
        let win_handle = unsafe {
            std::os::windows::io::BorrowedHandle::borrow_raw(
                windows_sys::Win32::System::Threading::GetCurrentThread(),
            )
        };
        ThreadHandle(Arc::new(Mutex::new(Some(ThreadHandleInner {
            handle: win_handle
                .try_clone_to_owned()
                .expect("failed to clone current thread handle"),
            tls: SendConstPtr(tls),
        }))))
    }

    /// Runs `f`, ensuring that [`CURRENT_THREAD_HANDLE`] is set while in the call to `f`.
    fn run_with_handle<R>(tls: &TlsState, f: impl FnOnce() -> R) -> R {
        // Safety: `tls_state` lives for the duration of this call.
        unsafe { install_tls(tls) };

        let handle = Self::for_current_thread(tls);
        ACTIVE_THREADS.lock().unwrap().push(handle.clone());
        CURRENT_THREAD_HANDLE.with_borrow_mut(|current| {
            assert!(
                current.is_none(),
                "thread is already registered with LiteBox",
            );
            *current = Some(handle.clone());
        });
        let _guard = litebox::utils::defer(move || {
            let current = CURRENT_THREAD_HANDLE.take().unwrap();
            // Remove from the global registry.
            ACTIVE_THREADS
                .lock()
                .unwrap()
                .retain(|h| !Arc::ptr_eq(&h.0, &current.0));
            *current.0.lock().unwrap() = None;
            uninstall_tls();
        });
        f()
    }

    /// Sets a pending signal on this thread, wakes it from any condvar wait,
    /// and interrupts it so the shim processes the signal promptly.
    fn deliver_signal(&self, signal: litebox_common_linux::signal::Signal) {
        let bit: u32 = 1 << (signal.as_i32() - 1);

        // Set the pending signal bit and wake the condvar in one lock scope.
        {
            let inner = self.0.lock().unwrap();
            if let Some(inner) = inner.as_ref() {
                // Safety: the TLS pointer is valid as long as the thread is
                // alive, and we hold the thread handle lock.
                let tls = unsafe { &*inner.tls.0 };
                tls.pending_host_signals.fetch_or(bit, Ordering::SeqCst);

                let waker = tls.waiting_waker.load(Ordering::Acquire);
                if !waker.is_null() {
                    // SAFETY: `waker` was heap-allocated via `Box::into_raw` in
                    // `update_waker`. It remains valid here because
                    // `update_waker` acquires this same `ThreadHandleInner`
                    // mutex before freeing the old pointer, and we hold that
                    // mutex now.
                    let waker = unsafe { &*waker };
                    waker.wake();
                }
            }
        }

        self.interrupt(None);
    }

    /// Interrupt the thread represented by this handle, where `current` is the
    /// current thread's handle if it is managed by LiteBox.
    ///
    /// The basic strategy is this:
    /// 1. Suspend the target thread.
    /// 2. Access its TLS state to check if it's in the guest.
    /// 3. If it's not actually in the guest, set the interrupt flag and resume,
    ///    with some careful handling to make sure the interrupt flag is
    ///    evaluated upon return to the guest in all cases.
    /// 4. If it is in the guest, save the guest context and set the thread
    ///    context to resume at the interrupt callback.
    /// 5. Resume the target thread.
    fn interrupt(&self, current: Option<&ThreadHandle>) {
        /// Helper to lock two mutexes in address order, to prevent deadlock.
        fn lock_two<'a, T, U>(
            left: &'a Mutex<T>,
            right: &'a Mutex<U>,
        ) -> (std::sync::MutexGuard<'a, T>, std::sync::MutexGuard<'a, U>) {
            if std::ptr::from_ref(left).addr() < std::ptr::from_ref(right).addr() {
                let l = left.lock().unwrap();
                let r = right.lock().unwrap();
                (l, r)
            } else {
                let r = right.lock().unwrap();
                let l = left.lock().unwrap();
                (l, r)
            }
        }

        let (_current_guard, target) = if let Some(current) = current {
            if Arc::ptr_eq(&current.0, &self.0) {
                // Interrupting self; just set the flag.
                (unsafe { &*get_tls_ptr().unwrap() }).interrupt.set(true);
                return;
            }

            // Lock both the current and target thread handles so that this
            // thread is not suspended while holding the target thread lock.
            let (c, t) = lock_two(&current.0, &self.0);
            (Some(c), t)
        } else {
            // The current thread can't be suspended since it's not managed by LiteBox.
            (None, self.0.lock().unwrap())
        };
        let Some(inner) = target.as_ref() else {
            // The target is no longer managed by LiteBox.
            return;
        };

        // Suspend the target thread.
        unsafe {
            windows_sys::Win32::System::Threading::SuspendThread(inner.handle.as_raw_handle());
        }
        let _resume_guard = litebox::utils::defer(|| unsafe {
            windows_sys::Win32::System::Threading::ResumeThread(inner.handle.as_raw_handle());
        });

        // SAFETY: The target TLS state is accessible while the thread is
        // suspended.
        let target_tls = unsafe { &*inner.tls.0 };

        // Write the target interrupt flag.
        target_tls.interrupt.set(true);

        if !target_tls.is_in_guest.get() {
            // Not running in the guest. The interrupt flag will be checked
            // before returning to the guest, so just resume.
            return;
        }

        let guest_context = target_tls.guest_context_top.get().wrapping_sub(1);

        // Running in the guest. There are multiple possibilities:
        //
        // 1. The thread is in the middle of returning to the guest via the
        //    register pop path. Don't save context but do jump to the interrupt
        //    callback.
        // 2. The thread is in the middle of returning to the guest via the
        //    NtContinue path. Update the NtContinue context to point to the
        //    interrupt callback.
        // 3. The thread is beginning to handle an exception. Don't do anything;
        //    this path will check the interrupt flag.
        // 4. In the guest. Save the guest context and jump to the interrupt callback.

        // Get the current register context (including FP state for save).
        let mut context = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT {
            ContextFlags: windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64
                | windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_INTEGER_AMD64
                | windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_FLOATING_POINT_AMD64,
            ..Default::default()
        };
        let r = unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::GetThreadContext(
                inner.handle.as_raw_handle(),
                &raw mut context,
            )
        };
        assert_ne!(
            r,
            0,
            "GetThreadContext failed: {}",
            std::io::Error::last_os_error()
        );

        let run_interrupt_callback = if (switch_to_guest_start as *const () as usize
            ..switch_to_guest_end as *const () as usize)
            .contains(&(context.Rip.truncate()))
        {
            // Case 1: jump to interrupt callback without saving the guest
            // context, since it's already saved.
            true
        } else if is_in_ntdll_or_this(context.Rip.truncate()) {
            // Case 2/3: we can't distinguish between them. For case 2 we don't
            // need to do anything, but for case 3 we need to update the
            // NtContinue context to point to the interrupt callback (the guest
            // context is already up to date).
            //
            // In case 2, the NtContinue context is not being used, so it is
            // safe to update it anyway.

            // SAFETY: `continue_context` is not accessed by user-mode code
            // while `is_in_guest` is true.
            let continue_context = unsafe { &mut *target_tls.continue_context.get() };
            set_context_to_interrupt_callback(target_tls, continue_context);
            false
        } else {
            // Case 4: save the guest context and jump to interrupt callback.
            save_guest_context(
                unsafe { &mut *(guest_context as *mut litebox_common_linux::ExecutionContext) },
                &context,
            );
            true
        };
        if run_interrupt_callback {
            set_context_to_interrupt_callback(target_tls, &mut context);
            unsafe {
                windows_sys::Win32::System::Diagnostics::Debug::SetThreadContext(
                    inner.handle.as_raw_handle(),
                    &raw const context,
                );
            }
        }
    }
}

/// Updates `context` to jump to the interrupt callback with the given
/// `guest_context` pointer.
fn set_context_to_interrupt_callback(
    tls: &TlsState,
    context: &mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
) {
    let required_flags = windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64
        | windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_INTEGER_AMD64;
    assert!(context.ContextFlags & required_flags == required_flags);
    context.Rip = interrupt_callback as *const () as usize as u64;
    context.Rsp = tls.host_sp.get().addr() as u64;
    context.Rbp = tls.host_bp.get().addr() as u64;
}

/// Returns true if the given instruction pointer is in ntdll.dll or this module.
fn is_in_ntdll_or_this(ip: usize) -> bool {
    static BOUNDS: OnceLock<[std::ops::Range<usize>; 2]> = const { OnceLock::new() };

    let bounds = BOUNDS.get_or_init(|| {
        unsafe extern "C" {
            safe static __ImageBase: c_void;
        }
        fn module_bounds(module: *const c_void) -> std::ops::Range<usize> {
            let mut module_info = windows_sys::Win32::System::ProcessStatus::MODULEINFO::default();
            let r = unsafe {
                windows_sys::Win32::System::ProcessStatus::GetModuleInformation(
                    windows_sys::Win32::System::Threading::GetCurrentProcess(),
                    module.cast_mut(),
                    &raw mut module_info,
                    size_of_val(&module_info).try_into().unwrap(),
                )
            };
            assert_ne!(
                r,
                0,
                "GetModuleInformation failed: {}",
                std::io::Error::last_os_error()
            );
            let start = module_info.lpBaseOfDll.addr();
            let end = start + module_info.SizeOfImage as usize;
            start..end
        }

        let ntdll = unsafe {
            windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(windows_sys::w!(
                "ntdll.dll"
            ))
        };
        [module_bounds(ntdll), module_bounds(&raw const __ImageBase)]
    });

    bounds.iter().any(|b| b.contains(&ip))
}

impl litebox::platform::RawMutexProvider for WindowsUserland {
    type RawMutex = RawMutex;

    fn update_waker(&self, waker: Option<litebox::event::wait::Waker<Self>>)
    where
        Self: litebox::sync::RawSyncPrimitivesProvider,
    {
        if let Some(tls) = get_tls_ptr().map(|p| unsafe { &*p }) {
            let waker_ptr = waker.map_or(std::ptr::null_mut(), |w| Box::into_raw(Box::new(w)));
            let old = tls.waiting_waker.swap(waker_ptr, Ordering::AcqRel);
            if !old.is_null() {
                // Synchronize with `deliver_signal`, which may be concurrently
                // reading the old waker pointer on another thread while holding
                // the `ThreadHandleInner` mutex. Acquiring the same mutex here
                // ensures that `deliver_signal` has finished using the pointer
                // before we free it.
                CURRENT_THREAD_HANDLE.with_borrow(|handle| {
                    let _guard = handle.as_ref().map(|handle| handle.0.lock().unwrap());
                    // SAFETY: old pointer was created by Box::into_raw in a previous
                    // call to update_waker. No other thread can be accessing it now
                    // because we synchronized via the ThreadHandleInner mutex above.
                    unsafe { drop(Box::from_raw(old)) };
                });
            }
        }
    }
}

// A skeleton of a raw mutex for Windows.
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

    #[expect(clippy::unnecessary_wraps)]
    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
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
                Win32_Foundation::ERROR_TIMEOUT => Ok(UnblockedOrTimedOut::TimedOut),
                e => panic!("Unexpected error={e} for WaitOnAddress"),
            }
        }
    }
}

impl litebox::platform::RawMutex for RawMutex {
    const INIT: Self = Self::new();

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
        let session = self
            .tun_session
            .as_ref()
            .expect("send_ip_packet called without TUN device configured");
        session
            .send(packet)
            .map_err(|errno| litebox::platform::SendError::Io(errno))
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        let session = self
            .tun_session
            .as_ref()
            .expect("receive_ip_packet called without TUN device configured");
        session
            .try_receive(packet)
            .map_err(|_| litebox::platform::ReceiveError::WouldBlock)
    }
}

impl litebox::platform::TimeProvider for WindowsUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        let mut ts = 0;
        unsafe { QueryUnbiasedInterruptTimePrecise(&raw mut ts) };
        Instant(ts)
    }

    fn current_time(&self) -> Self::SystemTime {
        let mut filetime = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        unsafe {
            GetSystemTimePreciseAsFileTime(&raw mut filetime);
        }
        let FILETIME {
            dwLowDateTime: low,
            dwHighDateTime: high,
        } = filetime;
        let filetime = (u64::from(high) << 32) | u64::from(low);
        SystemTime { filetime }
    }
}

/// 100ns units returned by `QueryUnbiasedInterruptTimePrecise`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        let diff = self.0.checked_sub(earlier.0)?;
        // Convert from 100ns intervals to nanoseconds. This won't overflow in
        // our lifetimes.
        Some(Duration::from_nanos(diff * 100))
    }

    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        let duration_100ns: u64 = (duration.as_nanos() / 100).try_into().ok()?;
        let new = self.0.checked_add(duration_100ns)?;
        Some(Instant(new))
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

pub struct PunchthroughToken<'a> {
    punchthrough: PunchthroughSyscall<'a, WindowsUserland>,
}

impl<'a> litebox::platform::PunchthroughToken for PunchthroughToken<'a> {
    type Punchthrough = PunchthroughSyscall<'a, WindowsUserland>;
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
            PunchthroughSyscall::GetFsBase => {
                // Use the stored FS base value from our per-thread storage
                Ok(WindowsUserland::get_thread_fs_base())
            }
        }
    }
}

impl litebox::platform::PunchthroughProvider for WindowsUserland {
    type PunchthroughToken<'a> = PunchthroughToken<'a>;
    fn get_punchthrough_token_for<'a>(
        &self,
        punchthrough: <Self::PunchthroughToken<'a> as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken<'a>> {
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

type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;

impl litebox::platform::RawPointerProvider for WindowsUserland {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
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

/// Helper method to process a memory range by iterating through Windows memory regions.
///
/// Windows memory is managed in Virtual Address Descriptors (VADs) at the NT kernel level,
/// which means a single user-space range might span multiple regions. This helper method
/// queries each region within the specified range and applies the given operation.
///
/// # Parameters
/// - `range`: The memory range to process
/// - `operation`: A closure that takes (region_range, region_state) and returns Result<bool, E>.
///
/// # Panics
///
/// Panics if the operation returns false for any region.
fn process_memory_range_by_regions<F, E>(
    mut range: core::ops::Range<usize>,
    mut operation: F,
) -> Result<(), E>
where
    F: FnMut(core::ops::Range<usize>, Win32_Memory::VIRTUAL_ALLOCATION_TYPE) -> Result<bool, E>,
{
    while !range.is_empty() {
        let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
        do_query_on_region(&mut mbi, range.start as *mut c_void);
        debug_assert_eq!(range.start, mbi.BaseAddress as usize);
        let len = mbi.RegionSize.min(range.len());
        let success = operation(range.start..range.start + len, mbi.State)?;
        assert!(
            success,
            "operation failed on region {:p}-{:p}: {}",
            range.start as *mut c_void,
            (range.start + len) as *mut c_void,
            std::io::Error::last_os_error()
        );
        range = (range.start + len)..range.end;
    }
    Ok(())
}

macro_rules! debug_assert_alignment {
    ($r:ident, $page_size:expr) => {
        debug_assert!($r.start.is_multiple_of($page_size));
        debug_assert!($r.end.is_multiple_of($page_size));
    };
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for WindowsUserland {
    const TASK_ADDR_MIN: usize = va_partitions::VA_MIN;
    const TASK_ADDR_MAX: usize = TASK_ADDR_MAX;
    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        debug_assert!(ALIGN.is_multiple_of(self.sys_info.read().unwrap().dwPageSize as usize));
        debug_assert_alignment!(suggested_range, ALIGN);

        // A helper closure to reserve and commit memory in one go.
        //
        // Note that MEM_RESERVE requires the base address to be aligned to system allocation granularity,
        // while MEM_COMMIT only requires page-aligned address.
        //
        // To ensure future MEM_COMMIT calls on sub-ranges succeed, we always reserve the entire aligned range
        // (i.e., MEM_RESERVE size is also made aligned to system allocation granularity).
        let reserve_and_commit = |r: core::ops::Range<usize>,
                                  flags: Win32_Memory::PAGE_PROTECTION_FLAGS|
         -> *mut c_void {
            let aligned_start_addr = self.round_down_to_granu(r.start);
            let aligned_end_addr = self.round_up_to_granu(r.end);
            let ptr = unsafe {
                VirtualAlloc2(
                    GetCurrentProcess(),
                    aligned_start_addr as *mut c_void,
                    aligned_end_addr - aligned_start_addr,
                    Win32_Memory::MEM_RESERVE,
                    Win32_Memory::PAGE_NOACCESS,
                    core::ptr::null_mut(),
                    0,
                )
            };
            if ptr.is_null() {
                core::ptr::null_mut()
            } else {
                unsafe {
                    VirtualAlloc2(
                        GetCurrentProcess(),
                        if r.start == 0 {
                            ptr
                        } else {
                            r.start as *mut c_void
                        },
                        r.len(),
                        Win32_Memory::MEM_COMMIT,
                        flags,
                        core::ptr::null_mut(),
                        0,
                    )
                }
            }
        };

        let mut base_addr = suggested_range.start as *mut c_void;
        let size = suggested_range.len();
        // TODO: For Windows, there is no MAP_GROWDOWN features so far.
        let _ = can_grow_down;

        if suggested_range.start != 0 {
            assert!(suggested_range.start >= <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::
                                                            TASK_ADDR_MIN);
            assert!(suggested_range.end <= <WindowsUserland as litebox::platform::PageManagementProvider<ALIGN>>::
                                                            TASK_ADDR_MAX);

            let has_committed_page =
                process_memory_range_by_regions(suggested_range.clone(), |_r, state| {
                    if state == Win32_Memory::MEM_COMMIT {
                        Err(())
                    } else {
                        Ok(true)
                    }
                })
                .is_err();
            if has_committed_page && fixed_address_behavior == FixedAddressBehavior::Hint {
                // If any page in the suggested range is already committed, and the caller
                // did not request a fixed address, we ask the OS to allocate a new region.
                base_addr = core::ptr::null_mut();
            } else if has_committed_page
                && fixed_address_behavior == FixedAddressBehavior::NoReplace
            {
                return Err(AllocationError::AddressInUse);
            } else {
                process_memory_range_by_regions(
                    suggested_range,
                    |r, state| -> Result<bool, std::convert::Infallible> {
                        let ok = match state {
                            // In case the region is already reserved, we just need to commit it.
                            // In case the region is already committed, decommit and recommit it.
                            Win32_Memory::MEM_RESERVE | Win32_Memory::MEM_COMMIT => {
                                if state == Win32_Memory::MEM_COMMIT {
                                    // TODO: handle this race condition properly.
                                    assert_eq!(
                                        fixed_address_behavior,
                                        FixedAddressBehavior::Replace,
                                        "raced with another memory allocator"
                                    );
                                    let decommit_ok = unsafe {
                                        VirtualFree(
                                            r.start as *mut c_void,
                                            r.len(),
                                            Win32_Memory::MEM_DECOMMIT,
                                        )
                                    } != 0;
                                    assert!(
                                        decommit_ok,
                                        "VirtualFree(DECOMMIT) failed: {}",
                                        unsafe { GetLastError() }
                                    );
                                }
                                let ptr = unsafe {
                                    VirtualAlloc2(
                                        GetCurrentProcess(),
                                        r.start as *mut c_void,
                                        r.len(),
                                        Win32_Memory::MEM_COMMIT,
                                        prot_flags(initial_permissions),
                                        core::ptr::null_mut(),
                                        0,
                                    )
                                };
                                !ptr.is_null()
                            }
                            // In case the region is free, we need to reserve and commit it.
                            Win32_Memory::MEM_FREE => {
                                let ptr =
                                    reserve_and_commit(r.clone(), prot_flags(initial_permissions));
                                !ptr.is_null()
                            }
                            _ => unimplemented!(
                                "Unexpected memory state: {:?} when allocating pages",
                                state
                            ),
                        };
                        // Prefetch the memory range if requested
                        if ok && populate_pages_immediately {
                            do_prefetch_on_range(r.start, r.len());
                        }
                        Ok(ok)
                    },
                )
                .unwrap();
                return Ok(UserMutPtr::from_ptr(base_addr.cast()));
            }
        }

        debug_assert!(base_addr.is_null());
        let ptr = reserve_and_commit(0..size, prot_flags(initial_permissions));
        assert!(
            !ptr.is_null(),
            "VirtualAlloc2(RESERVE|COMMIT size=0x{:x}) failed: {}",
            size,
            std::io::Error::last_os_error()
        );

        // Prefetch the memory range if requested
        if populate_pages_immediately {
            do_prefetch_on_range(ptr as usize, size);
        }
        Ok(UserMutPtr::from_ptr(ptr.cast::<u8>()))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        debug_assert_alignment!(range, ALIGN);

        // Slot 0 shares its VA partition with the host process: the Rust
        // runtime heap, thread stacks, TEB/PEB, and other host allocations
        // all live in the same 1 TiB range.  VirtualFree(MEM_DECOMMIT) on
        // guest pages in slot 0 can inadvertently decommit pages whose
        // underlying VA the host still needs (e.g. allocator metadata),
        // leading to silent crashes or hangs.  Skip the explicit decommit
        // for slot 0 — the OS reclaims all memory on process exit.
        //
        // Child partitions (slots 1+) are probed-clean and only contain
        // guest-allocated pages, so VirtualFree is safe for them.
        if range.start < va_partitions::PARTITION_SIZE {
            return Ok(());
        }

        process_memory_range_by_regions(
            range,
            |r, state| -> Result<bool, std::convert::Infallible> {
                if state == Win32_Memory::MEM_FREE {
                    return Ok(true);
                }
                let ret = unsafe {
                    VirtualFree(r.start as *mut c_void, r.len(), Win32_Memory::MEM_DECOMMIT)
                };
                debug_assert_ne!(
                    ret,
                    0,
                    "VirtualFree(MEM_DECOMMIT) failed on child partition region {:p}-{:p}: {}",
                    r.start as *mut c_void,
                    r.end as *mut c_void,
                    std::io::Error::last_os_error()
                );
                Ok(true)
            },
        )
        .expect("deallocate_pages failed");
        Ok(())
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        debug_assert_alignment!(range, ALIGN);
        let flags = prot_flags(new_permissions);
        process_memory_range_by_regions(
            range,
            |r, state| -> Result<bool, std::convert::Infallible> {
                debug_assert_eq!(
                    state,
                    Win32_Memory::MEM_COMMIT,
                    "Trying to change permissions on a non-committed region: {:p}-{:p}",
                    r.start as *mut c_void,
                    r.end as *mut c_void
                );
                let mut old_protect: u32 = 0;
                Ok(unsafe {
                    VirtualProtect(r.start as *mut c_void, r.len(), flags, &raw mut old_protect)
                } != 0)
            },
        )
        .expect("update_permissions failed");
        Ok(())
    }

    /// Returns host memory regions that are reserved or committed at boot time.
    ///
    /// These are scanned once during `WindowsUserland::new()` via `VirtualQuery`
    /// and remain static for the platform's lifetime. The `PageManager` for each
    /// child process clamps these to its partition VA range automatically
    /// (see `Vmem::new()` in `litebox/src/mm/linux.rs`).
    ///
    /// **Known limitation:** Post-boot host allocations (lazy `LoadLibrary`,
    /// thread stacks, heap growth) are not reflected here. The partition-time
    /// `VirtualQuery` probing in `allocate_probed(is_va_range_clean)` provides
    /// a runtime safety net at partition creation time, but not at every
    /// individual page allocation.
    fn reserved_pages(&self) -> impl Iterator<Item = &std::ops::Range<usize>> {
        self.reserved_pages.iter()
    }
}

/// Check whether a console input buffer contains actual keyboard character
/// data (KEY_EVENT with bKeyDown and a non-zero character). Returns `false`
/// for pipe/file handles (they don't support `PeekConsoleInputW`).
///
/// This avoids entering `stdin().read()` when the console input buffer only
/// contains mouse, focus, or window-resize events — those events signal
/// `WaitForSingleObject` but are not consumable by `ReadFile`/`ReadConsole`,
/// which would block.
fn console_has_key_data(handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    let mut events_available: u32 = 0;
    let ok = unsafe {
        windows_sys::Win32::System::Console::GetNumberOfConsoleInputEvents(
            handle,
            &mut events_available,
        )
    };
    if ok == 0 || events_available == 0 {
        return false;
    }

    // Peek up to 32 events without removing them.
    let mut buf: [windows_sys::Win32::System::Console::INPUT_RECORD; 32] =
        unsafe { core::mem::zeroed() };
    let mut events_read: u32 = 0;
    let peek_count = core::cmp::min(events_available, 32);
    let ok = unsafe {
        windows_sys::Win32::System::Console::PeekConsoleInputW(
            handle,
            buf.as_mut_ptr(),
            peek_count,
            &mut events_read,
        )
    };
    if ok == 0 {
        return false;
    }

    for record in &buf[..events_read as usize] {
        if u32::from(record.EventType) == windows_sys::Win32::System::Console::KEY_EVENT {
            // SAFETY: EventType == KEY_EVENT guarantees the KeyEvent union variant.
            let key = unsafe { record.Event.KeyEvent };
            if key.bKeyDown != 0 {
                let ch = unsafe { key.uChar.UnicodeChar };
                if ch != 0 {
                    return true;
                }
            }
        }
    }
    false
}

/// Drain non-key (mouse, focus, resize) events from the console input buffer
/// so that `WaitForSingleObject` does not immediately re-signal. Stops when
/// a key event with character data is found (leaving it for `stdin().read()`).
fn drain_non_key_console_events(handle: windows_sys::Win32::Foundation::HANDLE) {
    loop {
        let mut record: windows_sys::Win32::System::Console::INPUT_RECORD =
            unsafe { core::mem::zeroed() };
        let mut events_read: u32 = 0;
        let ok = unsafe {
            windows_sys::Win32::System::Console::PeekConsoleInputW(
                handle,
                &mut record,
                1,
                &mut events_read,
            )
        };
        if ok == 0 || events_read == 0 {
            return;
        }

        // If this is a key-down event with a real character, leave it for
        // stdin().read() to consume.
        if u32::from(record.EventType) == windows_sys::Win32::System::Console::KEY_EVENT {
            let key = unsafe { record.Event.KeyEvent };
            if key.bKeyDown != 0 {
                let ch = unsafe { key.uChar.UnicodeChar };
                if ch != 0 {
                    return;
                }
            }
        }

        // Consume this non-character event.
        unsafe {
            windows_sys::Win32::System::Console::ReadConsoleInputW(
                handle,
                &mut record,
                1,
                &mut events_read,
            );
        }
    }
}

/// Check if a handle is a console (as opposed to a pipe or file).
fn is_console_handle(handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    let mut mode: u32 = 0;
    unsafe { windows_sys::Win32::System::Console::GetConsoleMode(handle, &mut mode) != 0 }
}

/// Try `GetConsoleScreenBufferInfo` on the given handle IDs in order, returning
/// the first successful result as a `WindowSize`.
fn query_console_window_size(handle_ids: &[u32]) -> Option<litebox::platform::WindowSize> {
    for &id in handle_ids {
        let handle = unsafe { windows_sys::Win32::System::Console::GetStdHandle(id) };
        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            continue;
        }
        let mut csbi = windows_sys::Win32::System::Console::CONSOLE_SCREEN_BUFFER_INFO::default();
        let ok = unsafe {
            windows_sys::Win32::System::Console::GetConsoleScreenBufferInfo(handle, &mut csbi)
        };
        if ok != 0 {
            return Some(litebox::platform::WindowSize {
                rows: (csbi.srWindow.Bottom - csbi.srWindow.Top + 1) as u16,
                cols: (csbi.srWindow.Right - csbi.srWindow.Left + 1) as u16,
                xpixel: 0,
                ypixel: 0,
            });
        }
    }
    // Last resort: open CONOUT$ to bypass stdout/stderr redirection.
    // This gives us a handle to the active console screen buffer even when
    // all three standard handles are redirected away from the console.
    if let Some(conout) = open_conout() {
        let mut csbi = windows_sys::Win32::System::Console::CONSOLE_SCREEN_BUFFER_INFO::default();
        let ok = unsafe {
            windows_sys::Win32::System::Console::GetConsoleScreenBufferInfo(conout, &mut csbi)
        };
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(conout);
        }
        if ok != 0 {
            return Some(litebox::platform::WindowSize {
                rows: (csbi.srWindow.Bottom - csbi.srWindow.Top + 1) as u16,
                cols: (csbi.srWindow.Right - csbi.srWindow.Left + 1) as u16,
                xpixel: 0,
                ypixel: 0,
            });
        }
    }

    None
}

/// RAII guard that closes a Win32 HANDLE on drop. Used when we open console
/// device handles (CONIN$/CONOUT$) via `CreateFileW` that must be closed.
struct OwnedConsoleHandle(windows_sys::Win32::Foundation::HANDLE);

impl Drop for OwnedConsoleHandle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// Open `CONIN$` to get a handle to the console input buffer, bypassing any
/// stdin redirection. Returns `None` if the process has no attached console.
fn open_conin() -> Option<windows_sys::Win32::Foundation::HANDLE> {
    use windows_sys::Win32::Storage::FileSystem;
    // "CONIN$\0" as UTF-16.
    let name: [u16; 7] = [
        b'C' as u16,
        b'O' as u16,
        b'N' as u16,
        b'I' as u16,
        b'N' as u16,
        b'$' as u16,
        0,
    ];
    let handle = unsafe {
        FileSystem::CreateFileW(
            name.as_ptr(),
            Win32_Foundation::GENERIC_READ | Win32_Foundation::GENERIC_WRITE,
            FileSystem::FILE_SHARE_READ,
            core::ptr::null(),
            FileSystem::OPEN_EXISTING,
            0,
            core::ptr::null_mut(),
        )
    };
    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        None
    } else {
        Some(handle)
    }
}

/// Open `CONOUT$` to get a handle to the active console screen buffer,
/// bypassing any stdout/stderr redirection. Returns `None` if the process
/// has no attached console.
fn open_conout() -> Option<windows_sys::Win32::Foundation::HANDLE> {
    use windows_sys::Win32::Storage::FileSystem;
    // "CONOUT$\0" as UTF-16.
    let name: [u16; 8] = [
        b'C' as u16,
        b'O' as u16,
        b'N' as u16,
        b'O' as u16,
        b'U' as u16,
        b'T' as u16,
        b'$' as u16,
        0,
    ];
    let handle = unsafe {
        FileSystem::CreateFileW(
            name.as_ptr(),
            Win32_Foundation::GENERIC_READ | Win32_Foundation::GENERIC_WRITE,
            FileSystem::FILE_SHARE_WRITE,
            core::ptr::null(),
            FileSystem::OPEN_EXISTING,
            0,
            core::ptr::null_mut(),
        )
    };
    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        None
    } else {
        Some(handle)
    }
}

impl litebox::platform::StdioProvider for WindowsUserland {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        let stdin_handle = unsafe {
            windows_sys::Win32::System::Console::GetStdHandle(
                windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
            )
        };
        let is_console = stdin_handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
            && is_console_handle(stdin_handle);

        loop {
            if self
                .stdin_cancelled
                .load(core::sync::atomic::Ordering::Acquire)
            {
                return Err(litebox::platform::StdioReadError::Closed);
            }

            if stdin_handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }

            // Wait with 500ms timeout so we can re-check cancellation.
            let result = unsafe { Win32_Threading::WaitForSingleObject(stdin_handle, 500) };
            if result != Win32_Foundation::WAIT_OBJECT_0 {
                continue; // timeout — loop back
            }

            if is_console {
                // Console handles signal for ANY input event (mouse, focus,
                // resize). Only enter stdin().read() when there is actual
                // keyboard character data, otherwise drain the non-key events
                // and loop back to WaitForSingleObject.
                if !console_has_key_data(stdin_handle) {
                    drain_non_key_console_events(stdin_handle);
                    continue;
                }
            }

            // Either pipe/file (signal means data) or console with key data.
            use std::io::Read as _;
            return std::io::stdin().read(buf).map_err(|err| {
                if err.kind() == std::io::ErrorKind::BrokenPipe {
                    litebox::platform::StdioReadError::Closed
                } else {
                    panic!("unhandled error {err}")
                }
            });
        }
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

    fn get_terminal_attributes(
        &self,
        stream: litebox::platform::StdioStream,
    ) -> Result<litebox::platform::TerminalAttributes, litebox::platform::StdioIoctlError> {
        if !self.is_a_tty(stream) {
            return Err(litebox::platform::StdioIoctlError::NotATerminal);
        }
        let state = self.console_terminal.lock().unwrap();
        Ok(state.attrs.clone())
    }

    fn set_terminal_attributes(
        &self,
        stream: litebox::platform::StdioStream,
        attrs: &litebox::platform::TerminalAttributes,
        _when: litebox::platform::SetTermiosWhen,
    ) -> Result<(), litebox::platform::StdioIoctlError> {
        if !self.is_a_tty(stream) {
            return Err(litebox::platform::StdioIoctlError::NotATerminal);
        }

        // Find a usable console input handle for GetConsoleMode/SetConsoleMode.
        // Try STD_INPUT_HANDLE first; if stdin is redirected, fall back to
        // opening CONIN$ which bypasses redirection to reach the actual
        // console input buffer.
        let stdin_handle = unsafe {
            windows_sys::Win32::System::Console::GetStdHandle(
                windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
            )
        };
        let conin_guard: Option<OwnedConsoleHandle>;
        let input_handle;

        if stdin_handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
            && is_console_handle(stdin_handle)
        {
            input_handle = stdin_handle;
            conin_guard = None;
        } else if let Some(h) = open_conin() {
            input_handle = h;
            conin_guard = Some(OwnedConsoleHandle(h));
        } else {
            // No console input handle available — do NOT update cached state.
            return Err(litebox::platform::StdioIoctlError::OsError(
                windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE as i32,
            ));
        }
        // Keep the guard alive until the end of this function.
        let _conin_guard = conin_guard;

        let mut mode: u32 = 0;
        let ok =
            unsafe { windows_sys::Win32::System::Console::GetConsoleMode(input_handle, &mut mode) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(litebox::platform::StdioIoctlError::OsError(err as i32));
        }

        const ECHO: u32 = 0x0008;
        const ICANON: u32 = 0x0002;
        const ISIG: u32 = 0x0001;
        const ENABLE_ECHO_INPUT: u32 = windows_sys::Win32::System::Console::ENABLE_ECHO_INPUT;
        const ENABLE_LINE_INPUT: u32 = windows_sys::Win32::System::Console::ENABLE_LINE_INPUT;
        const ENABLE_PROCESSED_INPUT: u32 =
            windows_sys::Win32::System::Console::ENABLE_PROCESSED_INPUT;

        if attrs.c_lflag & ECHO != 0 {
            mode |= ENABLE_ECHO_INPUT;
        } else {
            mode &= !ENABLE_ECHO_INPUT;
        }
        if attrs.c_lflag & ICANON != 0 {
            mode |= ENABLE_LINE_INPUT;
        } else {
            mode &= !ENABLE_LINE_INPUT;
        }
        if attrs.c_lflag & ISIG != 0 {
            mode |= ENABLE_PROCESSED_INPUT;
        } else {
            mode &= !ENABLE_PROCESSED_INPUT;
        }

        let ok = unsafe { windows_sys::Win32::System::Console::SetConsoleMode(input_handle, mode) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(litebox::platform::StdioIoctlError::OsError(err as i32));
        }

        // Store attributes in shared state only AFTER SetConsoleMode succeeds.
        // This ensures get_terminal_attributes never returns attributes that
        // were not actually applied to the host console.
        {
            let mut state = self.console_terminal.lock().unwrap();
            state.attrs = attrs.clone();
        }

        Ok(())
    }

    fn get_window_size(
        &self,
        stream: litebox::platform::StdioStream,
    ) -> Result<litebox::platform::WindowSize, litebox::platform::StdioIoctlError> {
        if !self.is_a_tty(stream) {
            return Err(litebox::platform::StdioIoctlError::NotATerminal);
        }

        let state = self.console_terminal.lock().unwrap();
        if state.winsize_overridden {
            return Ok(state.winsize);
        }
        drop(state);

        // Map the stream to the corresponding Windows console handle ID.
        let primary_id = match stream {
            litebox::platform::StdioStream::Stdin => {
                windows_sys::Win32::System::Console::STD_INPUT_HANDLE
            }
            litebox::platform::StdioStream::Stdout => {
                windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE
            }
            litebox::platform::StdioStream::Stderr => {
                windows_sys::Win32::System::Console::STD_ERROR_HANDLE
            }
        };

        // GetConsoleScreenBufferInfo only works on output handles.
        // Try the selected handle first, then fall back to stdout, then stderr.
        // This handles the mixed-redirection case (e.g. stdin is tty, stdout
        // is redirected — stderr may still be attached to the console).
        let fallback_ids = [
            primary_id,
            windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE,
            windows_sys::Win32::System::Console::STD_ERROR_HANDLE,
        ];

        query_console_window_size(&fallback_ids)
            .ok_or(litebox::platform::StdioIoctlError::NotATerminal)
    }

    fn set_window_size(
        &self,
        stream: litebox::platform::StdioStream,
        size: &litebox::platform::WindowSize,
    ) -> Result<(), litebox::platform::StdioIoctlError> {
        if !self.is_a_tty(stream) {
            return Err(litebox::platform::StdioIoctlError::NotATerminal);
        }
        // Store so TIOCSWINSZ round-trips with TIOCGWINSZ.
        let mut state = self.console_terminal.lock().unwrap();
        state.winsize = *size;
        state.winsize_overridden = true;
        Ok(())
    }

    fn poll_stdin_readable(&self) -> bool {
        let stdin_handle = unsafe {
            windows_sys::Win32::System::Console::GetStdHandle(
                windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
            )
        };
        if stdin_handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return false;
        }

        if is_console_handle(stdin_handle) {
            // For console handles, check for actual keyboard character data.
            // WaitForSingleObject alone would report readable for mouse/focus
            // events that stdin().read() cannot consume.
            console_has_key_data(stdin_handle)
        } else {
            // For pipe/file handles, WaitForSingleObject is reliable.
            let result = unsafe { Win32_Threading::WaitForSingleObject(stdin_handle, 0) };
            result == Win32_Foundation::WAIT_OBJECT_0
        }
    }

    fn cancel_stdin(&self) {
        self.stdin_cancelled
            .store(true, core::sync::atomic::Ordering::Release);
    }
}

#[global_allocator]
static SLAB_ALLOC: litebox::mm::allocator::SafeZoneAllocator<'static, 30, WindowsUserland> =
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

unsafe extern "C" {
    // Defined in asm blocks above
    fn syscall_callback() -> isize;
    fn exception_callback() -> isize;
    fn interrupt_callback();
    fn switch_to_guest_start();
    fn switch_to_guest_end();
}

unsafe extern "C-unwind" fn init_handler(thread_ctx: &mut ThreadContext<'_>) {
    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.init(ctx));
}

unsafe extern "C-unwind" fn syscall_handler(thread_ctx: &mut ThreadContext<'_>) {
    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.syscall(ctx));
}

/// Check whether the page at `addr` is committed (has physical storage).
///
/// Uses `VirtualQuery` to inspect the page state. Returns `true` only for
/// `MEM_COMMIT` pages; `MEM_RESERVE` and `MEM_FREE` return `false`.
fn is_page_committed(addr: usize) -> bool {
    let mut mbi = Win32_Memory::MEMORY_BASIC_INFORMATION::default();
    // Safety: VirtualQuery reads kernel VA metadata; the address may be
    // unmapped but VirtualQuery still succeeds (returns MEM_FREE).
    let ok = unsafe {
        Win32_Memory::VirtualQuery(
            addr as *const c_void,
            &raw mut mbi,
            core::mem::size_of::<Win32_Memory::MEMORY_BASIC_INFORMATION>(),
        ) != 0
    };
    ok && mbi.State == Win32_Memory::MEM_COMMIT
}

/// Synthesize a Linux-style x86 page-fault error code from Windows
/// exception information.
///
/// Bits:
/// - 0: present (page committed but access denied)
/// - 1: write fault
/// - 2: user-mode (always set)
/// - 4: instruction fetch (DEP)
///
/// `read_write_flag` is `ExceptionInformation[0]` from
/// `EXCEPTION_ACCESS_VIOLATION`: 0 = read, 1 = write, 8 = DEP.
fn synthesize_pf_error_code(is_present: bool, read_write_flag: usize) -> u32 {
    (if is_present { 1 } else { 0 })
        | match read_write_flag {
            0 => 0,      // read fault
            8 => 1 << 4, // DEP (instruction fetch)
            _ => 1 << 1, // write fault
        }
        | 4 // bit 2: user-mode
}

unsafe extern "C-unwind" fn exception_handler(
    thread_ctx: &mut ThreadContext<'_>,
    exception_record: &EXCEPTION_RECORD,
) {
    let (exception, error_code, cr2) = match exception_record.ExceptionCode {
        Win32_Foundation::EXCEPTION_ACCESS_VIOLATION => {
            let info = exception_record.ExceptionInformation;
            let read_write_flag = info[0];
            let faulting_address = info[1];
            if read_write_flag == 0 && faulting_address == !0 {
                // This is probably a #GP, not a #PF.
                (Exception::GENERAL_PROTECTION_FAULT, 0, 0)
            } else {
                let is_present = is_page_committed(faulting_address);
                let error_code = synthesize_pf_error_code(is_present, read_write_flag);
                (Exception::PAGE_FAULT, error_code, faulting_address)
            }
        }
        Win32_Foundation::EXCEPTION_ILLEGAL_INSTRUCTION => (Exception::INVALID_OPCODE, 0, 0),
        Win32_Foundation::EXCEPTION_PRIV_INSTRUCTION => {
            // Maps to #GP (General Protection Fault). On x86, HLT triggers
            // this in user mode; glibc uses HLT as an unreachable abort trap.
            (Exception::GENERAL_PROTECTION_FAULT, 0, 0)
        }
        Win32_Foundation::EXCEPTION_BREAKPOINT => (Exception::BREAKPOINT, 0, 0),
        Win32_Foundation::EXCEPTION_INT_DIVIDE_BY_ZERO => (Exception::DIVIDE_ERROR, 0, 0),
        code => panic!("Unhandled Win32 exception code: {:#x}", code),
    };

    let info = litebox::shim::ExceptionInfo {
        exception,
        error_code,
        cr2,
        kernel_mode: false,
    };

    thread_ctx.call_shim(|shim, ctx, _interrupt| shim.exception(ctx, &info));
}

unsafe extern "C-unwind" fn interrupt_handler(thread_ctx: &mut ThreadContext<'_>) {
    thread_ctx.tls.is_in_guest.set(false);
    thread_ctx.call_shim(|shim, ctx, interrupt| {
        if interrupt {
            shim.interrupt(ctx)
        } else {
            // We likely got here just to restore fsbase, so don't bother the
            // shim.
            ContinueOperation::Resume
        }
    });
}

struct ThreadContext<'a> {
    shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
    ctx: &'a mut litebox_common_linux::ExecutionContext,
    tls: &'a TlsState,
}

impl ThreadContext<'_> {
    /// Calls `f` in order to call into a shim entrypoint.
    fn call_shim(
        &mut self,
        f: impl FnOnce(
            &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::ExecutionContext>,
            &mut litebox_common_linux::ExecutionContext,
            bool,
        ) -> ContinueOperation,
    ) {
        // Clear the interrupt flag before calling the shim, since we've handled it
        // now (by calling into the shim), and it might be set again by the shim
        // before returning.
        let op = f(self.shim, self.ctx, self.tls.interrupt.replace(false));
        match op {
            ContinueOperation::Resume => unsafe { switch_to_guest(self.ctx) },
            ContinueOperation::Terminate => {}
        }
    }
}

impl litebox::platform::SystemInfoProvider for WindowsUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as *const () as usize
    }

    fn get_vdso_address(&self) -> Option<usize> {
        // Windows doesn't have VDSO equivalent, return None
        None
    }
}

thread_local! {
    // Use `ManuallyDrop` for more efficient TLS accesses, since this is always
    // dropped manually before the thread exits.
    static PLATFORM_TLS: Cell<*mut ()> = const { Cell::new(core::ptr::null_mut()) };
}

/// WindowsUserland platform's thread-local storage implementation.
unsafe impl litebox::platform::ThreadLocalStorageProvider for WindowsUserland {
    fn get_thread_local_storage() -> *mut () {
        PLATFORM_TLS.get()
    }

    unsafe fn replace_thread_local_storage(new_tls: *mut ()) -> *mut () {
        PLATFORM_TLS.replace(new_tls)
    }

    fn clear_guest_thread_local_storage() {
        Self::init_thread_fs_base();
    }
}

impl litebox::platform::CrngProvider for WindowsUserland {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom failed");
    }
}

/// Dummy `VmemPageFaultHandler`.
///
/// Page faults are handled transparently by the host Windows kernel.
/// Provided to satisfy trait bounds for `PageManager::handle_page_fault`.
impl litebox::mm::linux::VmemPageFaultHandler for WindowsUserland {
    unsafe fn handle_page_fault(
        &self,
        _fault_addr: usize,
        _flags: litebox::mm::linux::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unreachable!("host kernel handles page faults for Windows userland")
    }

    fn access_error(_error_code: u64, _flags: litebox::mm::linux::VmFlags) -> bool {
        unreachable!("host kernel handles page faults for Windows userland")
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    use std::thread::sleep;

    use crate::WindowsUserland;
    use crate::process_memory_range_by_regions;
    use litebox::platform::PageManagementProvider;
    use litebox::platform::RawConstPointer;
    use litebox::platform::RawMutex;
    use litebox::platform::page_mgmt::FixedAddressBehavior;
    use litebox::platform::page_mgmt::MemoryRegionPermissions;

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
    fn test_page_provider() {
        let collect_regions = |r| {
            let mut regions = Vec::new();
            process_memory_range_by_regions(
                r,
                |region, state| -> Result<bool, core::convert::Infallible> {
                    regions.push((region, state));
                    Ok(true)
                },
            )
            .unwrap();
            regions
        };

        let platform = WindowsUserland::new(None);
        let system_allocation_granularity =
            platform.sys_info.read().unwrap().dwAllocationGranularity as usize;
        // Allocate some pages: it should reserve `system_allocation_granularity` bytes but only commit 0x1000 bytes
        let addr = <WindowsUserland as PageManagementProvider<4096>>::allocate_pages(
            platform,
            0..0x1000,
            MemoryRegionPermissions::WRITE,
            false,
            true,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        assert_eq!(
            collect_regions(addr..addr + system_allocation_granularity),
            vec![
                (
                    addr..addr + 0x1000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
                (
                    addr + 0x1000..addr + system_allocation_granularity,
                    windows_sys::Win32::System::Memory::MEM_RESERVE
                ),
            ]
        );

        assert!(system_allocation_granularity >= 0x1_0000);
        // We should be able to allocate [addr + 0x8000, addr + 0x1_0000)
        let addr2 = <WindowsUserland as PageManagementProvider<4096>>::allocate_pages(
            platform,
            (addr + 0x8000)..(addr + 0x1_0000),
            MemoryRegionPermissions::WRITE,
            false,
            true,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        // Even though `fixed_address` is false, we should still get the requested address if it's free.
        assert_eq!(addr2, addr + 0x8000);
        assert_eq!(
            collect_regions(addr..addr + 0x1_0000),
            vec![
                (
                    addr..addr + 0x1000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
                (
                    addr + 0x1000..addr + 0x8000,
                    windows_sys::Win32::System::Memory::MEM_RESERVE
                ),
                (
                    addr + 0x8000..addr + 0x1_0000,
                    windows_sys::Win32::System::Memory::MEM_COMMIT
                ),
            ]
        );

        // Try to allocate [addr + 0x4000, addr + 0x1_0000), which overlaps with existing committed pages.
        // OS should allocate a new region instead of the requested one (as `fixed_address` is false)
        let addr3 = <WindowsUserland as PageManagementProvider<4096>>::allocate_pages(
            platform,
            (addr + 0x4000)..(addr + 0x1_0000),
            MemoryRegionPermissions::WRITE,
            false,
            true,
            FixedAddressBehavior::Hint,
        )
        .unwrap()
        .as_usize();
        assert_ne!(addr3, addr + 0x4000);
    }

    // -- Step 3.2: error-code synthesis tests --

    #[test]
    fn test_synthesize_pf_error_code() {
        use super::synthesize_pf_error_code;

        // Write to committed (present) page → CoW case: bits 0+1+2 = 0b111 = 0x7
        assert_eq!(synthesize_pf_error_code(true, 1), 0x7);
        // Shim CoW check: (error_code & 0x3) == 0x3
        assert_eq!(synthesize_pf_error_code(true, 1) & 0x3, 0x3);

        // Write to unmapped page: bits 1+2 = 0b110 = 0x6
        assert_eq!(synthesize_pf_error_code(false, 1), 0x6);
        assert_ne!(synthesize_pf_error_code(false, 1) & 0x3, 0x3);

        // Read, committed page: bits 0+2 = 0b101 = 0x5
        assert_eq!(synthesize_pf_error_code(true, 0), 0x5);

        // Read, unmapped page: bit 2 only = 0b100 = 0x4
        assert_eq!(synthesize_pf_error_code(false, 0), 0x4);

        // DEP, committed page: bits 0+4+2 = 0x15
        assert_eq!(synthesize_pf_error_code(true, 8), 0x15);

        // DEP, uncommitted page: bits 4+2 = 0x14
        assert_eq!(synthesize_pf_error_code(false, 8), 0x14);
    }

    #[test]
    fn test_is_page_committed_states() {
        use super::is_page_committed;

        // Committed page → true
        let addr = unsafe {
            super::VirtualAlloc2(
                super::GetCurrentProcess(),
                core::ptr::null_mut(),
                0x1000,
                super::Win32_Memory::MEM_COMMIT | super::Win32_Memory::MEM_RESERVE,
                super::Win32_Memory::PAGE_READWRITE,
                core::ptr::null_mut(),
                0,
            )
        };
        assert!(!addr.is_null());
        assert!(is_page_committed(addr as usize));

        // Change to read-only — still committed
        let mut old_protect = 0u32;
        let ok = unsafe {
            super::VirtualProtect(
                addr,
                0x1000,
                super::Win32_Memory::PAGE_READONLY,
                &mut old_protect,
            ) != 0
        };
        assert!(ok);
        assert!(is_page_committed(addr as usize));

        // Free the page → not committed
        let ok = unsafe { super::VirtualFree(addr, 0, super::Win32_Memory::MEM_RELEASE) != 0 };
        assert!(ok);
        assert!(!is_page_committed(addr as usize));

        // Reserved-only (no commit) → not committed
        let reserved = unsafe {
            super::VirtualAlloc2(
                super::GetCurrentProcess(),
                core::ptr::null_mut(),
                0x1000,
                super::Win32_Memory::MEM_RESERVE,
                super::Win32_Memory::PAGE_READWRITE,
                core::ptr::null_mut(),
                0,
            )
        };
        assert!(!reserved.is_null());
        assert!(!is_page_committed(reserved as usize));
        let ok = unsafe { super::VirtualFree(reserved, 0, super::Win32_Memory::MEM_RELEASE) != 0 };
        assert!(ok);
    }

    // -- Step 3.3: VirtualProtect round-trip tests --

    #[test]
    fn test_virtualprotect_cow_roundtrip() {
        let addr = unsafe {
            super::VirtualAlloc2(
                super::GetCurrentProcess(),
                core::ptr::null_mut(),
                0x1000,
                super::Win32_Memory::MEM_COMMIT | super::Win32_Memory::MEM_RESERVE,
                super::Win32_Memory::PAGE_READWRITE,
                core::ptr::null_mut(),
                0,
            )
        };
        assert!(!addr.is_null());

        let mut old_protect = 0u32;

        // RW → RO
        assert_ne!(
            unsafe {
                super::VirtualProtect(
                    addr,
                    0x1000,
                    super::Win32_Memory::PAGE_READONLY,
                    &mut old_protect,
                )
            },
            0
        );
        // RO → RW
        assert_ne!(
            unsafe {
                super::VirtualProtect(
                    addr,
                    0x1000,
                    super::Win32_Memory::PAGE_READWRITE,
                    &mut old_protect,
                )
            },
            0
        );

        // XRW → XR
        assert_ne!(
            unsafe {
                super::VirtualProtect(
                    addr,
                    0x1000,
                    super::Win32_Memory::PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
            },
            0
        );
        assert_ne!(
            unsafe {
                super::VirtualProtect(
                    addr,
                    0x1000,
                    super::Win32_Memory::PAGE_EXECUTE_READ,
                    &mut old_protect,
                )
            },
            0
        );
        // XR → XRW
        assert_ne!(
            unsafe {
                super::VirtualProtect(
                    addr,
                    0x1000,
                    super::Win32_Memory::PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
            },
            0
        );

        assert_ne!(
            unsafe { super::VirtualFree(addr, 0, super::Win32_Memory::MEM_RELEASE) },
            0
        );
    }
}
