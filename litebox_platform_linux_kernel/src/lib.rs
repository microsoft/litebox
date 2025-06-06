//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox in kernel mode

#![cfg(target_arch = "x86_64")]
#![no_std]

use core::sync::atomic::AtomicU64;
use core::{arch::asm, sync::atomic::AtomicU32};

use host::linux::sigset_t;
use litebox::mm::linux::PageRange;
use litebox::platform::{
    DebugLogProvider, ExitProvider, IPInterfaceProvider, ImmediatelyWokenUp,
    PageManagementProvider, Provider, Punchthrough, PunchthroughError, PunchthroughProvider,
    PunchthroughToken, RawConstPointer, RawMutPointer, RawMutexProvider, TimeProvider,
    UnblockedOrTimedOut,
};
use litebox::platform::{RawMutex as _, RawPointerProvider};
use litebox_common_linux::PunchthroughSyscall;
use litebox_common_linux::errno::Errno;
use ptr::{UserConstPtr, UserMutPtr};

extern crate alloc;

pub mod arch;
pub mod host;
pub mod mm;
pub mod ptr;

static CPU_MHZ: AtomicU64 = AtomicU64::new(0);

/// This is the platform for running LiteBox in kernel mode.
/// It requires a host that implements the [`HostInterface`] trait.
pub struct LinuxKernel<Host: HostInterface> {
    host_and_task: core::marker::PhantomData<Host>,
    page_table: mm::PageTable<4096>,
}

pub struct LinuxPunchthroughToken<Host: HostInterface> {
    punchthrough: PunchthroughSyscall<LinuxKernel<Host>>,
    host: core::marker::PhantomData<Host>,
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
            PunchthroughSyscall::RtSigprocmask {
                how,
                set,
                old_set,
                sigsetsize,
            } => Host::rt_sigprocmask(how, set.cast(), old_set.cast(), sigsetsize),
            PunchthroughSyscall::SetFsBase { addr } => {
                unsafe { litebox_common_linux::wrfsbase(addr.as_usize()) };
                Ok(0)
            }
            PunchthroughSyscall::GetFsBase { addr } => {
                let fs_base = unsafe { litebox_common_linux::rdfsbase() };
                let ptr: UserMutPtr<usize> = addr.cast();
                unsafe { ptr.write_at_offset(0, fs_base) }
                    .map(|()| 0)
                    .ok_or(Errno::EFAULT)
            }
        };
        match r {
            Ok(v) => Ok(v),
            Err(e) => Err(litebox::platform::PunchthroughError::Failure(e)),
        }
    }
}

impl<Host: HostInterface> Provider for LinuxKernel<Host> {}

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

    /// rt_sigprocmask: examine and change blocked signals.
    /// sigprocmask() is used to fetch and/or change the signal mask of the calling thread.
    /// The signal mask is the set of signals whose delivery is currently blocked for the
    /// caller (see also signal(7) for more details).
    ///
    ///The behavior of the call is dependent on the value of how, as follows.
    ///
    /// *SIG_BLOCK*
    /// The set of blocked signals is the union of the current set and the set argument.
    ///
    /// *SIG_UNBLOCK*
    /// The signals in set are removed from the current set of blocked signals. It is permissible to attempt to unblock a signal which is not blocked.
    ///
    /// *SIG_SETMASK*
    /// The set of blocked signals is set to the argument set.
    /// If oldset is non-NULL, the previous value of the signal mask is stored in oldset.
    /// If set is NULL, then the signal mask is unchanged (i.e., how is ignored), but the current value of the signal mask is nevertheless returned in oldset (if it is not NULL).
    /// The use of sigprocmask() is unspecified in a multithreaded process; see pthread_sigmask(3).
    ///
    /// **Return Value**
    ///
    /// sigprocmask() returns 0 on success and -1 on error.
    ///
    /// **Errors**
    ///
    /// *EFAULT* the set or oldset argument points outside the process's allocated address space.
    ///
    /// *EINVAL* The value specified in how was invalid.
    ///
    /// set and old_set are pointers in user space
    pub fn rt_sigprocmask(
        &mut self,
        how: i32,
        set: UserConstPtr<sigset_t>,
        old_set: UserMutPtr<sigset_t>,
        sigsetsize: usize,
    ) -> Result<usize, PunchthroughError<Errno>> {
        let punchthrough = PunchthroughSyscall::RtSigprocmask {
            how,
            set: set.cast(),
            old_set: old_set.cast(),
            sigsetsize,
        };
        let token = self
            .get_punchthrough_token_for(punchthrough)
            .ok_or(PunchthroughError::Unsupported)?;
        token.execute()
    }

    pub fn exit(&self) -> ! {
        Host::exit();
    }

    pub fn terminate(&self, reason_set: u64, reason_code: u64) -> ! {
        Host::terminate(reason_set, reason_code)
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
    /// Page allocation from host.
    ///
    /// It can return more than requested size. On success, it returns the start address
    /// and the size of the allocated memory.
    fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)>;

    /// Returns the memory back to host.
    ///
    /// Note host should know the size of allocated memory and needs to check the validity
    /// of the given address.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `addr` is valid and was allocated by this [`Self::alloc`].
    unsafe fn free(addr: usize);

    /// Exit
    ///
    /// Exit allows to come back to handle some requests from host,
    /// but it should not return back to the caller.
    fn exit() -> !;

    /// Terminate LiteBox
    fn terminate(reason_set: u64, reason_code: u64) -> !;

    /// For Punchthrough
    fn rt_sigprocmask(
        how: i32,
        set: UserConstPtr<sigset_t>,
        old_set: UserMutPtr<sigset_t>,
        sigsetsize: usize,
    ) -> Result<usize, Errno>;

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
        populate_pages: bool,
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
        Ok(self.page_table.map_pages(range, flags, populate_pages))
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
