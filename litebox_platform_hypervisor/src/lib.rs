//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox in kernel mode

#![cfg(target_arch = "x86_64")]
#![no_std]
#![cfg_attr(feature = "interrupt", feature(abi_x86_interrupt))]

use crate::user_context::UserContextMap;

use core::{
    arch::asm,
    sync::atomic::{AtomicU32, AtomicU64},
};
use host::linux::sigset_t;
use litebox::platform::{
    DebugLogProvider, IPInterfaceProvider, ImmediatelyWokenUp, PageManagementProvider,
    Punchthrough, RawMutexProvider, StdioProvider, TimeProvider, UnblockedOrTimedOut,
};
use litebox::platform::{
    PunchthroughProvider, PunchthroughToken, RawMutPointer, RawMutex as _, RawPointerProvider,
};
use litebox::{mm::linux::PageRange, platform::page_mgmt::FixedAddressBehavior};
use litebox_common_linux::{PunchthroughSyscall, errno::Errno};
use ptr::{UserConstPtr, UserMutPtr};

extern crate alloc;

pub mod arch;
pub mod host;
pub mod mm;
pub mod ptr;

pub mod syscall_entry;
pub mod user_context;

const PAGE_SIZE: usize = 4096;

static CPU_MHZ: AtomicU64 = AtomicU64::new(0);

/// This is the platform for running LiteBox in kernel mode.
/// It requires a host that implements the [`HostInterface`] trait.
pub struct LinuxKernel<Host: HostInterface> {
    host_and_task: core::marker::PhantomData<Host>,
    page_table: mm::PageTable<PAGE_SIZE>,
    user_contexts: UserContextMap,
}

pub struct LinuxPunchthroughToken<Host: HostInterface> {
    punchthrough: PunchthroughSyscall<LinuxKernel<Host>>,
    host: core::marker::PhantomData<Host>,
}

impl<Host: HostInterface> RawPointerProvider for LinuxKernel<Host> {
    type RawConstPointer<T: Clone> = ptr::UserConstPtr<T>;
    type RawMutPointer<T: Clone> = ptr::UserMutPtr<T>;
}

impl<Host: HostInterface> PunchthroughToken for LinuxPunchthroughToken<Host> {
    type Punchthrough = PunchthroughSyscall<LinuxKernel<Host>>;

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
                let ptr: UserMutPtr<usize> = addr.cast();
                unsafe { ptr.write_at_offset(0, fs_base) }
                    .map(|()| 0)
                    .ok_or(Errno::EFAULT)
            }
            _ => unimplemented!(),
        };
        match r {
            Ok(v) => Ok(v),
            Err(e) => Err(litebox::platform::PunchthroughError::Failure(e)),
        }
    }
}

impl<Host: HostInterface> PunchthroughProvider for LinuxKernel<Host> {
    type PunchthroughToken = LinuxPunchthroughToken<Host>;

    fn get_punchthrough_token_for(
        &self,
        punchthrough: <Self::PunchthroughToken as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
        Some(LinuxPunchthroughToken {
            punchthrough,
            host: core::marker::PhantomData,
        })
    }
}

impl<Host: HostInterface> LinuxKernel<Host> {
    /// This function initializes the kernel platform (mostly the kernel page table).
    /// `init_page_table_addr` specifies the physical address of the initial page table prepared by the kernel.
    ///
    /// # Panics
    ///
    /// Panics if the heap is not initialized yet or it does not have enough space to allocate page table entries.
    pub fn new(init_page_table_addr: x86_64::PhysAddr) -> &'static Self {
        // There is only one long-running platform ever expected, thus this leak is perfectly ok in
        // order to simplify usage of the platform.
        alloc::boxed::Box::leak(alloc::boxed::Box::new(Self {
            host_and_task: core::marker::PhantomData,
            page_table: unsafe { mm::PageTable::new(init_page_table_addr) },
            user_contexts: UserContextMap::new(),
        }))
    }

    pub fn init(&self, cpu_mhz: u64) {
        CPU_MHZ.store(cpu_mhz, core::sync::atomic::Ordering::Relaxed);
    }

    /// Create a new page table for user space. Currently, it maps the entire kernel memory for
    /// proper operations (e.g., syscall handling). We should consider implementing
    /// partial mapping to mitigate side-channel attacks and shallow copying to get rid of redudant
    /// page table data structures for kernel space.
    #[allow(clippy::unused_self)]
    pub(crate) fn new_user_page_table(&self) -> mm::PageTable<PAGE_SIZE> {
        // let pt = unsafe { mm::PageTable::new_top_level() };
        // if pt
        //     .map_phys_frame_range(
        //         self.phys_frame_range,
        //         PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        //     )
        //     .is_err()
        // {
        //     panic!("Failed to map physical memory");
        // }
        // pt

        // TODO: use separate page table later
        let (cr3, _) = x86_64::registers::control::Cr3::read_raw();
        unsafe { mm::PageTable::new(cr3.start_address()) }
    }

    /// Register the shim. This function must be called for each core to program
    /// its MSRs.
    pub fn register_shim(
        shim: &'static dyn litebox::shim::EnterShim<
            ExecutionContext = litebox_common_linux::PtRegs,
            ContinueOperation = syscall_entry::SyscallReturnType,
        >,
    ) {
        syscall_entry::init(shim);
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

/// An implementation of [`litebox::platform::SystemTime`]
pub struct SystemTime();

impl<Host: HostInterface> TimeProvider for LinuxKernel<Host> {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        Instant::now()
    }

    fn current_time(&self) -> Self::SystemTime {
        unimplemented!()
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

impl litebox::platform::SystemTime for SystemTime {
    const UNIX_EPOCH: Self = SystemTime();

    fn duration_since(
        &self,
        _earlier: &Self,
    ) -> Result<core::time::Duration, core::time::Duration> {
        unimplemented!()
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
    // TODO: leave this for now for testing. We might need this if we plan to run Linux apps.

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
    /// Switch enables a context switch from kernel to kernel while passing a value
    /// through a CPU register.
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
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let range = PageRange::new(suggested_range.start, suggested_range.end)
            .ok_or(litebox::platform::page_mgmt::AllocationError::Unaligned)?;
        match fixed_address_behavior {
            FixedAddressBehavior::Hint | FixedAddressBehavior::NoReplace => {}
            FixedAddressBehavior::Replace => {
                // Clear the existing mappings first.
                unsafe { self.page_table.unmap_pages(range, true).unwrap() };
            }
        }
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
        _permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
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

pub type Platform = crate::host::Hypervisor;

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
