//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox in kernel mode

#![no_std]

use core::sync::atomic::AtomicU64;
use core::{arch::asm, sync::atomic::AtomicU32};

use litebox::mm::linux::PageRange;
use litebox::platform::{
    DebugLogProvider, IPInterfaceProvider, ImmediatelyWokenUp, PageManagementProvider,
    RawMutexProvider, TimeProvider, UnblockedOrTimedOut,
};
use litebox::platform::{RawMutex as _, RawPointerProvider};
use litebox_common_linux::errno::Errno;

extern crate alloc;

pub mod arch;
pub mod host;
pub mod mm;
pub mod ptr;

static CPU_MHZ: AtomicU64 = AtomicU64::new(0);

pub struct VtlCallParam {
    entry_reason: u32,
    args: [u64; 4],
}

/// This is the platform for running LiteBox in kernel mode.
/// It requires a host that implements the [`HostInterface`] trait.
pub struct LinuxKernel<Host: HostInterface> {
    host_and_task: core::marker::PhantomData<Host>,
    page_table: mm::PageTable<4096>,
}

impl<Host: HostInterface> RawPointerProvider for LinuxKernel<Host> {
    type RawConstPointer<T: Clone> = ptr::UserConstPtr<T>;
    type RawMutPointer<T: Clone> = ptr::UserMutPtr<T>;
}

impl<Host: HostInterface> LinuxKernel<Host> {
    pub fn new(init_page_table_addr: x86_64::PhysAddr) -> &'static Self {
        // There is only one long-running platform ever expected, thus this leak is perfectly ok in
        // order to simplify usage of the platform.
        alloc::boxed::Box::leak(alloc::boxed::Box::new(Self {
            host_and_task: core::marker::PhantomData,
            // TODO: Update the init physaddr
            page_table: unsafe { mm::PageTable::new(init_page_table_addr) },
        }))
    }

    pub fn init(&self, cpu_mhz: u64) {
        CPU_MHZ.store(cpu_mhz, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn switch(&self, result: u64) -> VtlCallParam {
        Host::switch(result)
    }
}

impl<Host: HostInterface> RawMutexProvider for LinuxKernel<Host> {
    type RawMutex = RawMutex<Host>;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        Self::RawMutex {
            inner: AtomicU32::new(0),
            host: core::marker::PhantomData,
        }
    }
}

/// An implementation of [`litebox::platform::RawMutex`]
pub struct RawMutex<Host: HostInterface> {
    inner: AtomicU32,
    host: core::marker::PhantomData<Host>,
}

unsafe impl<Host: HostInterface> Send for RawMutex<Host> {}
unsafe impl<Host: HostInterface> Sync for RawMutex<Host> {}

/// TODO: common mutex implementation could be moved to a shared crate
impl<Host: HostInterface> litebox::platform::RawMutex for RawMutex<Host> {
    fn underlying_atomic(&self) -> &core::sync::atomic::AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        Host::wake_many(&self.inner, n).unwrap()
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
        time: core::time::Duration,
    ) -> Result<litebox::platform::UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(val, Some(time))
    }
}

impl<Host: HostInterface> RawMutex<Host> {
    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        loop {
            // No need to wait if the value already changed.
            if self
                .underlying_atomic()
                .load(core::sync::atomic::Ordering::Relaxed)
                != val
            {
                return Err(ImmediatelyWokenUp);
            }

            let ret = Host::block_or_maybe_timeout(&self.inner, val, timeout);

            match ret {
                Ok(()) => {
                    if self
                        .underlying_atomic()
                        .load(core::sync::atomic::Ordering::Relaxed)
                        != val
                    {
                        return Ok(UnblockedOrTimedOut::Unblocked);
                    }
                }
                Err(Errno::EAGAIN) => {
                    // If the futex value does not match val, then the call fails
                    // immediately with the error EAGAIN.
                    return Err(ImmediatelyWokenUp);
                }
                Err(Errno::EINTR) => {
                    // return Err(ImmediatelyWokenUp);
                    todo!("EINTR");
                }
                Err(Errno::ETIMEDOUT) => {
                    return Ok(UnblockedOrTimedOut::TimedOut);
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            }
        }
    }
}

impl<Host: HostInterface> DebugLogProvider for LinuxKernel<Host> {
    fn debug_log_print(&self, msg: &str) {
        Host::log(msg);
    }
}

/// An implementation of [`litebox::platform::Instant`]
pub struct Instant(u64);

impl<Host: HostInterface> TimeProvider for LinuxKernel<Host> {
    type Instant = Instant;

    fn now(&self) -> Self::Instant {
        Instant::now()
    }
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        self.0.checked_sub(earlier.0).map(|v| {
            core::time::Duration::from_micros(
                v / CPU_MHZ.load(core::sync::atomic::Ordering::Relaxed),
            )
        })
    }
}

impl Instant {
    fn rdtsc() -> u64 {
        let lo: u32;
        let hi: u32;
        unsafe {
            asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
            );
        }
        (u64::from(hi) << 32) | u64::from(lo)
    }

    fn now() -> Self {
        Instant(Self::rdtsc())
    }
}

impl<Host: HostInterface> IPInterfaceProvider for LinuxKernel<Host> {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        match Host::send_ip_packet(packet) {
            Ok(n) => {
                if n != packet.len() {
                    unimplemented!()
                }
                Ok(())
            }
            Err(e) => {
                unimplemented!("Error: {:?}", e)
            }
        }
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        match Host::receive_ip_packet(packet) {
            Ok(n) => Ok(n),
            Err(e) => {
                unimplemented!("Error: {:?}", e)
            }
        }
    }
}

/// Platform-Host Interface
pub trait HostInterface {
    /// Switch
    ///
    /// Switch enables a context switch from VTL1 kernel to VTL0 kernel while passing a value
    /// through a CPU register. VTL1 kernel will execute the next instruction of `switch()`
    /// when VTL0 kernel switches back to VTL1 kernel.
    fn switch(result: u64) -> VtlCallParam;

    fn wake_many(mutex: &AtomicU32, n: usize) -> Result<usize, Errno>;

    fn block_or_maybe_timeout(
        mutex: &AtomicU32,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<(), Errno>;

    /// For Network
    fn send_ip_packet(packet: &[u8]) -> Result<usize, Errno>;

    fn receive_ip_packet(packet: &mut [u8]) -> Result<usize, Errno>;

    /// For Debugging
    fn log(msg: &str);
}

impl<Host: HostInterface, const ALIGN: usize> PageManagementProvider<ALIGN> for LinuxKernel<Host> {
    fn allocate_pages(
        &self,
        range: core::ops::Range<usize>,
        initial_permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
        can_grow_down: bool,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let range = PageRange::new(range.start, range.end)
            .ok_or(litebox::platform::page_mgmt::AllocationError::Unaligned)?;
        let flags = u32::from(initial_permissions.bits())
            | if can_grow_down {
                litebox::mm::linux::VmFlags::VM_GROWSDOWN.bits()
            } else {
                0
            };
        let flags = litebox::mm::linux::VmFlags::from_bits(flags).unwrap();
        Ok(self.page_table.map_pages(range, flags))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let range = PageRange::new(range.start, range.end)
            .ok_or(litebox::platform::page_mgmt::DeallocationError::Unaligned)?;
        unsafe { self.page_table.unmap_pages(range) }
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::RemapError> {
        let old_range = PageRange::new(old_range.start, old_range.end)
            .ok_or(litebox::platform::page_mgmt::RemapError::Unaligned)?;
        let new_range = PageRange::new(new_range.start, new_range.end)
            .ok_or(litebox::platform::page_mgmt::RemapError::Unaligned)?;
        if old_range.start.max(new_range.start) <= old_range.end.min(new_range.end) {
            return Err(litebox::platform::page_mgmt::RemapError::Overlapping);
        }
        unsafe { self.page_table.remap_pages(old_range, new_range) }
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        let range = PageRange::new(range.start, range.end)
            .ok_or(litebox::platform::page_mgmt::PermissionUpdateError::Unaligned)?;
        let new_flags =
            litebox::mm::linux::VmFlags::from_bits(new_permissions.bits().into()).unwrap();
        unsafe { self.page_table.mprotect_pages(range, new_flags) }
    }
}

impl<Host: HostInterface> litebox::mm::linux::VmemPageFaultHandler for LinuxKernel<Host> {
    unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        flags: litebox::mm::linux::VmFlags,
        error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unsafe {
            self.page_table
                .handle_page_fault(fault_addr, flags, error_code)
        }
    }

    fn access_error(error_code: u64, flags: litebox::mm::linux::VmFlags) -> bool {
        mm::PageTable::<4096>::access_error(error_code, flags)
    }
}
