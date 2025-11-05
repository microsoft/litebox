//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on baremetal x86_64 in QEMU (non-KVM)
//!
//! This platform provides a minimal baremetal environment that can be run in QEMU's system emulator
//! without requiring KVM or any host-assisted virtualization. It implements the full Platform Provider
//! trait with basic hardware support (serial port, page tables, interrupts).

#![cfg(target_arch = "x86_64")]
#![no_std]
#![feature(abi_x86_interrupt)]

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};
use litebox::platform::{
    DebugLogProvider, IPInterfaceProvider, PageManagementProvider, Punchthrough,
    PunchthroughProvider, PunchthroughToken, RawMutPointer, RawMutexProvider, RawPointerProvider,
    StdioProvider, SystemInfoProvider, ThreadLocalStorageProvider, TimeProvider,
};
use litebox_common_linux::{errno::Errno, PunchthroughSyscall};
use x86_64::structures::paging::{PageSize, PhysFrame, Size4KiB};

pub mod arch;
pub mod interrupts;
pub mod memory;
pub mod serial;
pub mod time;

static CPU_MHZ: AtomicU64 = AtomicU64::new(2000); // Default 2GHz, can be updated

/// The baremetal platform for running LiteBox in QEMU without KVM
pub struct BaremetalPlatform {
    page_table_root: PhysFrame,
}

impl BaremetalPlatform {
    /// Create a new baremetal platform instance with the given page table root
    pub fn new(page_table_root: PhysFrame) -> &'static Self {
        let platform = Box::leak(Box::new(Self { page_table_root }));
        platform
    }

    /// Initialize the platform (called once at boot)
    pub fn init(&'static self) {
        // Initialize serial port for debug output
        serial::init();

        // Initialize interrupt handlers
        interrupts::init();

        // Enable interrupts
        x86_64::instructions::interrupts::enable();

        self.debug_log_print("Baremetal platform initialized\n");
    }

    /// Get task initialization parameters
    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        litebox_common_linux::TaskParams {
            pid: 1,
            ppid: 0,
            tid: 1,
            uid: 0,
            euid: 0,
            gid: 0,
            egid: 0,
        }
    }
}

// Pointer types for userspace access
pub mod ptr {
    use alloc::borrow::Cow;
    use alloc::boxed::Box;
    use core::marker::PhantomData;
    use litebox::platform::{RawConstPointer, RawMutPointer};

    #[derive(Clone)]
    pub struct UserConstPtr<T> {
        addr: usize,
        _phantom: PhantomData<*const T>,
    }

    #[derive(Clone)]
    pub struct UserMutPtr<T> {
        addr: usize,
        _phantom: PhantomData<*mut T>,
    }

    impl<T: Clone> Copy for UserConstPtr<T> {}
    impl<T: Clone> Copy for UserMutPtr<T> {}

    impl<T> core::fmt::Debug for UserConstPtr<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_tuple("UserConstPtr").field(&self.addr).finish()
        }
    }

    impl<T> core::fmt::Debug for UserMutPtr<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_tuple("UserMutPtr").field(&self.addr).finish()
        }
    }

    impl<T> UserConstPtr<T> {
        pub fn new(addr: usize) -> Self {
            Self {
                addr,
                _phantom: PhantomData,
            }
        }

        pub fn addr(&self) -> usize {
            self.addr
        }

        pub unsafe fn as_ptr(&self) -> *const T {
            self.addr as *const T
        }
    }

    impl<T: Clone> RawConstPointer<T> for UserConstPtr<T> {
        fn as_usize(&self) -> usize {
            self.addr
        }

        fn from_usize(addr: usize) -> Self {
            Self::new(addr)
        }

        unsafe fn read_at_offset<'a>(self, count: isize) -> Option<Cow<'a, T>> {
            if self.addr == 0 {
                return None;
            }
            let ptr = self
                .addr
                .wrapping_add((count * core::mem::size_of::<T>() as isize) as usize)
                as *const T;
            Some(Cow::Owned(unsafe { ptr.read() }))
        }

        unsafe fn to_cow_slice<'a>(self, len: usize) -> Option<Cow<'a, [T]>> {
            if self.addr == 0 {
                return None;
            }
            let ptr = self.addr as *const T;
            let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
            let mut vec = alloc::vec::Vec::with_capacity(len);
            vec.extend_from_slice(slice);
            Some(Cow::Owned(vec))
        }
    }

    impl<T> UserMutPtr<T> {
        pub fn new(addr: usize) -> Self {
            Self {
                addr,
                _phantom: PhantomData,
            }
        }

        pub fn addr(&self) -> usize {
            self.addr
        }

        pub unsafe fn as_ptr(&self) -> *const T {
            self.addr as *const T
        }

        pub unsafe fn as_mut_ptr(&mut self) -> *mut T {
            self.addr as *mut T
        }

        pub unsafe fn write_at_offset(&self, offset: usize, value: T) -> Option<()> {
            let ptr = (self.addr + offset * core::mem::size_of::<T>()) as *mut T;
            unsafe { ptr.write_volatile(value) };
            Some(())
        }

        pub fn cast<U>(&self) -> UserMutPtr<U> {
            UserMutPtr {
                addr: self.addr,
                _phantom: PhantomData,
            }
        }
    }

    impl<T: Clone> RawConstPointer<T> for UserMutPtr<T> {
        fn as_usize(&self) -> usize {
            self.addr
        }

        fn from_usize(addr: usize) -> Self {
            Self::new(addr)
        }

        unsafe fn read_at_offset<'a>(self, count: isize) -> Option<Cow<'a, T>> {
            if self.addr == 0 {
                return None;
            }
            let ptr = self
                .addr
                .wrapping_add((count * core::mem::size_of::<T>() as isize) as usize)
                as *const T;
            Some(Cow::Owned(unsafe { ptr.read() }))
        }

        unsafe fn to_cow_slice<'a>(self, len: usize) -> Option<Cow<'a, [T]>> {
            if self.addr == 0 {
                return None;
            }
            let ptr = self.addr as *const T;
            let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
            let mut vec = alloc::vec::Vec::with_capacity(len);
            vec.extend_from_slice(slice);
            Some(Cow::Owned(vec))
        }
    }

    impl<T: Clone> RawMutPointer<T> for UserMutPtr<T> {
        unsafe fn write_at_offset(self, count: isize, value: T) -> Option<()> {
            if self.addr == 0 {
                return None;
            }
            let ptr = self
                .addr
                .wrapping_add((count * core::mem::size_of::<T>() as isize) as usize)
                as *mut T;
            unsafe { ptr.write(value) };
            Some(())
        }

        fn mutate_subslice_with<R>(
            self,
            range: impl core::ops::RangeBounds<isize>,
            f: impl FnOnce(&mut [T]) -> R,
        ) -> Option<R> {
            if self.addr == 0 {
                return None;
            }

            use core::ops::Bound;
            let start = match range.start_bound() {
                Bound::Included(&s) => s,
                Bound::Excluded(&s) => s.checked_add(1)?,
                Bound::Unbounded => 0,
            };
            let len = match range.end_bound() {
                Bound::Included(&e) => (e.checked_sub(start)? + 1).try_into().ok()?,
                Bound::Excluded(&e) => (e.checked_sub(start)?).try_into().ok()?,
                Bound::Unbounded => return None, // Can't have unbounded range
            };

            let ptr = self
                .addr
                .wrapping_add((start * core::mem::size_of::<T>() as isize) as usize)
                as *mut T;
            let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
            Some(f(slice))
        }
    }
}

// RawPointerProvider implementation
impl RawPointerProvider for BaremetalPlatform {
    type RawConstPointer<T: Clone> = ptr::UserConstPtr<T>;
    type RawMutPointer<T: Clone> = ptr::UserMutPtr<T>;
}

// Punchthrough token for system-specific operations
pub struct BaremetalPunchthroughToken {
    punchthrough: PunchthroughSyscall<BaremetalPlatform>,
}

impl PunchthroughToken for BaremetalPunchthroughToken {
    type Punchthrough = PunchthroughSyscall<BaremetalPlatform>;

    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<<Self::Punchthrough as Punchthrough>::ReturnFailure>,
    > {
        let r = match self.punchthrough {
            PunchthroughSyscall::SetFsBase { addr } => {
                unsafe { litebox_common_linux::wrfsbase(addr) };
                Ok(0)
            }
            PunchthroughSyscall::GetFsBase { addr } => {
                let fs_base = unsafe { litebox_common_linux::rdfsbase() };
                let ptr: ptr::UserMutPtr<usize> = addr.cast();
                unsafe { ptr.write_at_offset(0, fs_base) }
                    .map(|()| 0)
                    .ok_or(Errno::EFAULT)
            }
            _ => Err(Errno::ENOSYS),
        };
        match r {
            Ok(v) => Ok(v),
            Err(e) => Err(litebox::platform::PunchthroughError::Failure(e)),
        }
    }
}

impl PunchthroughProvider for BaremetalPlatform {
    type PunchthroughToken = BaremetalPunchthroughToken;

    fn get_punchthrough_token_for(
        &self,
        punchthrough: <Self::PunchthroughToken as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
        Some(BaremetalPunchthroughToken { punchthrough })
    }
}

// DebugLogProvider implementation - uses serial port
impl DebugLogProvider for BaremetalPlatform {
    fn debug_log_print(&self, msg: &str) {
        serial::write_str(msg);
    }
}

// StdioProvider implementation - also uses serial port
impl StdioProvider for BaremetalPlatform {
    fn write_to(
        &self,
        _stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        serial::write_bytes(buf);
        Ok(buf.len())
    }

    fn read_from_stdin(&self, _buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        // For now, stdin is not supported in baremetal
        Err(litebox::platform::StdioReadError::Closed)
    }

    fn is_a_tty(&self, _stream: litebox::platform::StdioStream) -> bool {
        false // Serial port is not a TTY
    }
}

// SystemInfoProvider implementation
impl SystemInfoProvider for BaremetalPlatform {
    fn get_syscall_entry_point(&self) -> usize {
        0 // Not used in baremetal
    }

    fn get_vdso_address(&self) -> Option<usize> {
        None // No VDSO in baremetal
    }
}

// TimeProvider implementation
impl TimeProvider for BaremetalPlatform {
    type Instant = time::Instant;
    type SystemTime = time::SystemTime;

    fn now(&self) -> Self::Instant {
        time::Instant::now()
    }

    fn current_time(&self) -> Self::SystemTime {
        time::SystemTime::now()
    }
}

// RawMutexProvider - simple spinlock implementation
impl RawMutexProvider for BaremetalPlatform {
    type RawMutex = memory::SpinlockRawMutex;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        memory::SpinlockRawMutex::new()
    }
}

// PageManagementProvider implementation
impl PageManagementProvider<{ Size4KiB::SIZE as usize }> for BaremetalPlatform {
    const TASK_ADDR_MIN: usize = 0x1000; // Start at 4KB
    const TASK_ADDR_MAX: usize = 0x0000_8000_0000_0000; // 128TB

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
        _can_grow_down: bool,
        _populate_pages_immediately: bool,
        _fixed_address: bool,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        memory::allocate_pages_in_range(suggested_range, initial_permissions)
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        memory::deallocate_pages(range)
    }

    unsafe fn remap_pages(
        &self,
        _old_range: core::ops::Range<usize>,
        _new_range: core::ops::Range<usize>,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
        Err(litebox::platform::page_mgmt::RemapError::OutOfMemory)
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        memory::update_permissions(range, new_permissions)
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        core::iter::empty()
    }
}

// IPInterfaceProvider - not supported in basic baremetal
impl IPInterfaceProvider for BaremetalPlatform {
    fn send_ip_packet(&self, _packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        // No network support
        loop {
            x86_64::instructions::hlt();
        }
    }

    fn receive_ip_packet(
        &self,
        _buffer: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        Err(litebox::platform::ReceiveError::WouldBlock)
    }
}

// ThreadLocalStorageProvider - basic implementation
unsafe impl ThreadLocalStorageProvider for BaremetalPlatform {
    fn get_thread_local_storage() -> *mut () {
        unsafe { litebox_common_linux::rdfsbase() as *mut () }
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        let old = Self::get_thread_local_storage();
        unsafe { litebox_common_linux::wrfsbase(value as usize) };
        old
    }
}

// Main Provider trait - aggregates all sub-traits
impl litebox::platform::Provider for BaremetalPlatform {}

/// Update the CPU frequency in MHz
pub fn update_cpu_mhz(mhz: u64) {
    CPU_MHZ.store(mhz, Ordering::Relaxed);
}

/// Get the CPU frequency in MHz
pub fn get_cpu_mhz() -> u64 {
    CPU_MHZ.load(Ordering::Relaxed)
}
