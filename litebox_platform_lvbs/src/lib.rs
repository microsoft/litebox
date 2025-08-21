//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox in VTL1 kernel mode

#![cfg(target_arch = "x86_64")]
#![no_std]
#![cfg_attr(feature = "interrupt", feature(abi_x86_interrupt))]

use crate::{
    mshv::{vsm::Vtl0KernelInfo, vtl1_mem_layout::PAGE_SIZE},
    syscall_entry::SyscallHandler,
    user_context::UserContextMap,
};

use core::{
    arch::asm,
    sync::atomic::{AtomicU32, AtomicU64},
};
use host::linux::sigset_t;
use litebox::mm::linux::PageRange;
use litebox::platform::page_mgmt::DeallocationError;
use litebox::platform::{
    DebugLogProvider, ExitProvider, IPInterfaceProvider, ImmediatelyWokenUp,
    PageManagementProvider, RawMutexProvider, StdioProvider, TimeProvider, UnblockedOrTimedOut,
};
use litebox::platform::{RawMutex as _, RawPointerProvider};
use litebox_common_linux::errno::Errno;
use ptr::{UserConstPtr, UserMutPtr};
use x86_64::structures::paging::{
    PageOffset, PageSize, PageTableFlags, PhysFrame, Size4KiB, frame::PhysFrameRange,
    mapper::MapToError,
};

extern crate alloc;

pub mod arch;
pub mod host;
pub mod kernel_context;
pub mod mm;
pub mod mshv;
pub mod ptr;

pub mod syscall_entry;
pub(crate) mod user_context;

static CPU_MHZ: AtomicU64 = AtomicU64::new(0);

/// This is the platform for running LiteBox in kernel mode.
/// It requires a host that implements the [`HostInterface`] trait.
pub struct LinuxKernel<Host: HostInterface> {
    host_and_task: core::marker::PhantomData<Host>,
    page_table: mm::PageTable<PAGE_SIZE>,
    vtl1_phys_frame_range: PhysFrameRange<Size4KiB>,
    vtl0_kernel_info: Vtl0KernelInfo,
    user_contexts: UserContextMap,
}

impl<Host: HostInterface> ExitProvider for LinuxKernel<Host> {
    type ExitCode = i32;
    const EXIT_SUCCESS: Self::ExitCode = 0;
    const EXIT_FAILURE: Self::ExitCode = 1;
    fn exit(&self, _code: Self::ExitCode) -> ! {
        // TODO: We should probably expand the host to handle an error code?
        Host::exit()
    }
}

impl<Host: HostInterface> RawPointerProvider for LinuxKernel<Host> {
    type RawConstPointer<T: Clone> = ptr::UserConstPtr<T>;
    type RawMutPointer<T: Clone> = ptr::UserMutPtr<T>;
}

impl<Host: HostInterface> LinuxKernel<Host> {
    /// This function initializes the VTL1 kernel platform (mostly the kernel page table).
    /// `init_page_table_addr` specifies the physical address of the initial page table prepared by the VTL0 kernel.
    /// `phys_start` and `phys_end` specify the entire range of physical memory that is reserved for the VTL1 kernel.
    /// Since the VTL0 kernel does not fully map this physical address range to the initial page table, this function
    /// creates and maintains a kernel page table covering the entire VTL1 physical memory range. The caller must
    /// ensure that the heap has enough space for this page table creation.
    ///
    /// # Panics
    ///
    /// Panics if the heap is not initialized yet or it does not have enough space to allocate page table entries.
    /// Panics if `phys_start` or `phys_end` is invalid
    pub fn new(
        init_page_table_addr: x86_64::PhysAddr,
        phys_start: x86_64::PhysAddr,
        phys_end: x86_64::PhysAddr,
    ) -> &'static Self {
        let pt = unsafe { mm::PageTable::new(init_page_table_addr) };
        let physframe_start = PhysFrame::containing_address(phys_start);
        let physframe_end = PhysFrame::containing_address(phys_end.align_up(Size4KiB::SIZE));
        if pt
            .map_phys_frame_range(
                PhysFrame::range(physframe_start, physframe_end),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            )
            .is_err()
        {
            panic!("Failed to map VTL1 physical memory");
        }

        // There is only one long-running platform ever expected, thus this leak is perfectly ok in
        // order to simplify usage of the platform.
        alloc::boxed::Box::leak(alloc::boxed::Box::new(Self {
            host_and_task: core::marker::PhantomData,
            page_table: pt,
            vtl1_phys_frame_range: PhysFrame::range(physframe_start, physframe_end),
            vtl0_kernel_info: Vtl0KernelInfo::new(),
            user_contexts: UserContextMap::new(),
        }))
    }

    pub fn init(&self, cpu_mhz: u64) {
        CPU_MHZ.store(cpu_mhz, core::sync::atomic::Ordering::Relaxed);
    }

    /// This function maps VTL0 physical page frames containing the physical addresses
    /// from `phys_start` to `phys_end` to the VTL1 kernel page table. It internally page aligns
    /// the input addresses to ensure the mapped memory area covers the entire input addresses
    /// at the page level. It returns a page-aligned address (as `mmap` does) and the length of the mapped memory.
    fn map_vtl0_phys_range(
        &self,
        phys_start: x86_64::PhysAddr,
        phys_end: x86_64::PhysAddr,
        flags: PageTableFlags,
    ) -> Result<(*mut u8, usize), MapToError<Size4KiB>> {
        let frame_range = PhysFrame::range(
            PhysFrame::containing_address(phys_start),
            PhysFrame::containing_address(phys_end.align_up(Size4KiB::SIZE)),
        );

        // ensure the input address range does not overlap with VTL1 memory
        if frame_range.start < self.vtl1_phys_frame_range.end
            && self.vtl1_phys_frame_range.start < frame_range.end
        {
            return Err(MapToError::FrameAllocationFailed);
        }

        Ok((
            self.page_table.map_phys_frame_range(frame_range, flags)?,
            usize::try_from(frame_range.len()).unwrap() * PAGE_SIZE,
        ))
    }

    /// This unmaps VTL0 pages from the page table. Allocator does not allocate frames
    /// for VTL0 pages (i.e., it is always shared mapping), so it must not attempt to deallocate them.
    fn unmap_vtl0_pages(
        &self,
        page_addr: *const u8,
        length: usize,
    ) -> Result<(), DeallocationError> {
        let page_addr = x86_64::VirtAddr::new(page_addr as u64);
        if page_addr.page_offset() != PageOffset::new(0) {
            return Err(DeallocationError::Unaligned);
        }
        unsafe {
            self.page_table.unmap_pages(
                PageRange::<PAGE_SIZE>::new(
                    usize::try_from(page_addr.as_u64()).unwrap(),
                    usize::try_from(
                        (page_addr + u64::try_from(length).unwrap())
                            .align_up(Size4KiB::SIZE)
                            .as_u64(),
                    )
                    .unwrap(),
                )
                .ok_or(DeallocationError::Unaligned)?,
                false,
            )
        }
    }

    /// This function copies data from VTL0 physical memory to the VTL1 kernel through `Box`.
    /// Use this function instead of map/unmap functions to avoid potential TOCTTOU.
    /// Better to replace this function with `<data type>::from_bytes()` or similar
    /// # Safety
    ///
    /// The caller must ensure that the `phys_addr` is a valid VTL0 physical address
    /// # Panics
    ///
    /// Panics if `phys_addr` is invalid
    pub unsafe fn copy_from_vtl0_phys<T: Copy>(
        &self,
        phys_addr: x86_64::PhysAddr,
    ) -> Option<alloc::boxed::Box<T>> {
        use alloc::boxed::Box;

        if let Ok((page_addr, length)) = self.map_vtl0_phys_range(
            phys_addr,
            phys_addr + u64::try_from(core::mem::size_of::<T>()).unwrap(),
            PageTableFlags::PRESENT,
        ) {
            let page_offset =
                usize::try_from(phys_addr - phys_addr.align_down(Size4KiB::SIZE)).unwrap();
            let raw = Box::into_raw(Box::new(core::mem::MaybeUninit::<T>::uninit()));

            unsafe {
                core::ptr::copy_nonoverlapping(
                    page_addr.wrapping_add(page_offset).cast::<u8>(),
                    (*raw).as_mut_ptr().cast::<u8>(),
                    core::mem::size_of::<T>(),
                );
            }

            assert!(
                self.unmap_vtl0_pages(page_addr, length).is_ok(),
                "Failed to unmap VTL0 pages"
            );

            return Some(unsafe { Box::from_raw((*raw).as_mut_ptr()) });
        }

        None
    }

    /// This function copies data from the VTL1 kernel to VTL0 physical memory.
    /// Use this function instead of map/unmap functions to avoid potential TOCTTOU.
    /// # Safety
    ///
    /// The caller must ensure that the `phys_addr` is a valid VTL0 physical address
    /// # Panics
    ///
    /// Panics if phys_addr is invalid
    pub unsafe fn copy_to_vtl0_phys<T: Copy>(
        &self,
        phys_addr: x86_64::PhysAddr,
        value: &T,
    ) -> bool {
        if let Ok((page_addr, length)) = self.map_vtl0_phys_range(
            phys_addr,
            phys_addr + u64::try_from(core::mem::size_of::<T>()).unwrap(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        ) {
            let page_offset =
                usize::try_from(phys_addr - phys_addr.align_down(Size4KiB::SIZE)).unwrap();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    core::ptr::from_ref::<T>(value).cast::<u8>(),
                    page_addr.wrapping_add(page_offset).cast::<u8>(),
                    core::mem::size_of::<T>(),
                );
            }
            assert!(
                self.unmap_vtl0_pages(page_addr, length).is_ok(),
                "Failed to unmap VTL0 pages"
            );
            true
        } else {
            false
        }
    }

    /// This function copies a slice from the VTL1 kernel to VTL0 physical memory.
    /// Use this function instead of map/unmap functions to avoid potential TOCTTOU.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `phys_addr` is a valid VTL0 physical address.
    ///
    /// # Panics
    ///
    /// Panics if phys_addr is invalid
    pub unsafe fn copy_slice_to_vtl0_phys<T: Copy>(
        &self,
        phys_addr: x86_64::PhysAddr,
        value: &[T],
    ) -> bool {
        if let Ok((page_addr, length)) = self.map_vtl0_phys_range(
            phys_addr,
            phys_addr + u64::try_from(core::mem::size_of_val(value)).unwrap(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        ) {
            let page_offset =
                usize::try_from(phys_addr - phys_addr.align_down(Size4KiB::SIZE)).unwrap();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    value.as_ptr().cast::<u8>(),
                    page_addr.wrapping_add(page_offset).cast::<u8>(),
                    core::mem::size_of_val(value),
                );
            }
            assert!(
                self.unmap_vtl0_pages(page_addr, length).is_ok(),
                "Failed to unmap VTL0 pages"
            );
            true
        } else {
            false
        }
    }

    /// This function copies a slice from VTL0 physical memory to the VTL1 kernel.
    /// Use this function instead of map/unmap functions to avoid potential TOCTTOU.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `phys_addr` is a valid VTL0 physical address.
    ///
    /// # Panics
    ///
    /// Panics if phys_addr is invalid
    pub unsafe fn copy_slice_from_vtl0_phys<T: Copy>(
        &self,
        phys_addr: x86_64::PhysAddr,
        buf: &mut [T],
    ) -> bool {
        if let Ok((page_addr, length)) = self.map_vtl0_phys_range(
            phys_addr,
            phys_addr + u64::try_from(core::mem::size_of_val(buf)).unwrap(),
            PageTableFlags::PRESENT,
        ) {
            let page_offset =
                usize::try_from(phys_addr - phys_addr.align_down(Size4KiB::SIZE)).unwrap();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    page_addr.wrapping_add(page_offset).cast::<u8>(),
                    buf.as_mut_ptr().cast::<u8>(),
                    core::mem::size_of_val(buf),
                );
            }

            assert!(
                self.unmap_vtl0_pages(page_addr, length).is_ok(),
                "Failed to unmap VTL0 pages"
            );

            return true;
        }

        false
    }

    /// Create a new page table for VTL1 user space. Currently, it maps the entire VTL1 kernel memory for
    /// proper operations (e.g., syscall handling). We should consider implementing
    /// partial mapping to mitigate side-channel attacks and shallow copying to get rid of redudant
    /// page table data structures for kernel space.
    #[allow(dead_code)]
    pub(crate) fn new_user_page_table(&self) -> mm::PageTable<PAGE_SIZE> {
        let pt = unsafe { mm::PageTable::new_top_level() };
        if pt
            .map_phys_frame_range(
                self.vtl1_phys_frame_range,
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            )
            .is_err()
        {
            panic!("Failed to map VTL1 physical memory");
        }

        pt
    }

    /// Register `syscall_handler` passed down from the shim. This function must be called
    /// for each core to program its MSRs.
    pub fn register_syscall_handler(syscall_handler: SyscallHandler) {
        syscall_entry::init(syscall_handler);
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
                    return Ok(UnblockedOrTimedOut::Unblocked);
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
    /// Page allocation from host.
    ///
    /// It can return more than requested size. On success, it returns the start address
    /// and the size of the allocated memory.
    fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)>;
    // TODO: leave this for now for testing. LVBS does not allow dynamic memory allocation,
    // so it should be no-op or removed.

    /// Returns the memory back to host.
    ///
    /// Note host should know the size of allocated memory and needs to check the validity
    /// of the given address.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `addr` is valid and was allocated by this [`Self::alloc`].
    unsafe fn free(addr: usize);
    // TODO: leave this for now for testing. LVBS does not allow dynamic memory allocation,
    // so it should be no-op or removed.

    /// Exit
    ///
    /// Exit allows to come back to handle some requests from host,
    /// but it should not return back to the caller.
    fn exit() -> !;
    // TODO: leave this for now for testing. LVBS does exit (or return) but it resumes execution
    // from this instruction point (i.e., there is no separate entry point unlike SNP).

    /// Terminate LiteBox
    fn terminate(reason_set: u64, reason_code: u64) -> !;
    // TODO: leave this for now for testing. LVBS does not terminate, so it should be no-op or
    // removed.

    /// For Punchthrough
    fn rt_sigprocmask(
        how: i32,
        set: UserConstPtr<sigset_t>,
        old_set: UserMutPtr<sigset_t>,
        sigsetsize: usize,
    ) -> Result<usize, Errno>;
    // TODO: leave this for now for testing. We might need this if we plan to run Linux apps inside VTL1.

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

    /// Switch
    ///
    /// Switch enables a context switch from VTL1 kernel to VTL0 kernel while passing a value
    /// through a CPU register. VTL1 kernel will execute the next instruction of `switch()`
    /// when VTL0 kernel switches back to VTL1 kernel.
    fn switch(result: u64) -> !;
}

impl<Host: HostInterface, const ALIGN: usize> PageManagementProvider<ALIGN> for LinuxKernel<Host> {
    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux config
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        /* ignored because the suggested address is guaranteed to be available when running in kernel mode */
        _fixed_address: bool,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let range = PageRange::new(suggested_range.start, suggested_range.end)
            .ok_or(litebox::platform::page_mgmt::AllocationError::Unaligned)?;
        let flags = u32::from(initial_permissions.bits())
            | if can_grow_down {
                litebox::mm::linux::VmFlags::VM_GROWSDOWN.bits()
            } else {
                0
            };
        let flags = litebox::mm::linux::VmFlags::from_bits(flags).unwrap();
        Ok(self
            .page_table
            .map_pages(range, flags, populate_pages_immediately))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let range = PageRange::new(range.start, range.end)
            .ok_or(litebox::platform::page_mgmt::DeallocationError::Unaligned)?;
        unsafe { self.page_table.unmap_pages(range, true) }
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
    ) -> Result<UserMutPtr<u8>, litebox::platform::page_mgmt::RemapError> {
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

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        core::iter::empty()
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
        mm::PageTable::<PAGE_SIZE>::access_error(error_code, flags)
    }
}

impl<Host: HostInterface> StdioProvider for LinuxKernel<Host> {
    fn read_from_stdin(&self, _buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        unimplemented!()
    }

    fn write_to(
        &self,
        _stream: litebox::platform::StdioOutStream,
        _buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        unimplemented!()
    }

    fn is_a_tty(&self, _stream: litebox::platform::StdioStream) -> bool {
        unimplemented!()
    }
}

// NOTE: The below code is a naive workaround to let LVBS code to access the platform.
// Rather than doing this, we should implement LVBS interface/provider for the platform.

pub type Platform = crate::host::LvbsLinuxKernel;

static PLATFORM_LOW: once_cell::race::OnceBox<&'static Platform> = once_cell::race::OnceBox::new();

/// # Panics
///
/// Panics if invoked more than once
#[expect(
    clippy::match_wild_err_arm,
    reason = "the platform itself is not Debug thus we cannot use `expect`"
)]
pub fn set_platform_low(platform: &'static Platform) {
    match PLATFORM_LOW.set(alloc::boxed::Box::new(platform)) {
        Ok(()) => {}
        Err(_) => panic!("set_platform should only be called once per crate"),
    }
}

/// # Panics
///
/// Panics if [`set_platform_low`] has not been invoked before this
pub fn platform_low() -> &'static Platform {
    PLATFORM_LOW
        .get()
        .expect("set_platform_low should have already been called before this point")
}
