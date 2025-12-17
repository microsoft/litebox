//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox in kernel mode

#![cfg(target_arch = "x86_64")]
#![no_std]
#![cfg_attr(feature = "interrupt", feature(abi_x86_interrupt))]

use crate::user_context::UserContextMap;

use core::{
    arch::asm,
    sync::atomic::{AtomicU32, AtomicU64},
};
use litebox::platform::{
    DebugLogProvider, IPInterfaceProvider, ImmediatelyWokenUp, PageManagementProvider,
    Punchthrough, RawMutexProvider, StdioProvider, TimeProvider, UnblockedOrTimedOut,
};
use litebox::platform::{
    PunchthroughProvider, PunchthroughToken, RawMutPointer, RawPointerProvider,
};
use litebox::{mm::linux::PageRange, platform::page_mgmt::FixedAddressBehavior};
use litebox_common_linux::{PunchthroughSyscall, errno::Errno};
use ptr::UserMutPtr;
use x86_64::VirtAddr;

extern crate alloc;

pub mod arch;
pub mod mm;
pub mod ptr;

pub mod per_cpu_variables;
pub mod syscall_entry;
pub mod user_context;

mod alloc_impl;

#[cfg(test)]
pub mod mock;

const PAGE_SIZE: usize = 4096;

static CPU_MHZ: AtomicU64 = AtomicU64::new(0);

/// This is the platform for running LiteBox in kernel mode.
pub struct LiteBoxKernel {
    page_table: mm::PageTable<PAGE_SIZE>,
    user_contexts: UserContextMap,
}

impl RawPointerProvider for LiteBoxKernel {
    type RawConstPointer<T: Clone> = ptr::UserConstPtr<T>;
    type RawMutPointer<T: Clone> = ptr::UserMutPtr<T>;
}

pub struct LiteBoxPunchthroughToken {
    punchthrough: PunchthroughSyscall<LiteBoxKernel>,
}

impl PunchthroughToken for LiteBoxPunchthroughToken {
    type Punchthrough = PunchthroughSyscall<LiteBoxKernel>;

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

impl PunchthroughProvider for LiteBoxKernel {
    type PunchthroughToken = LiteBoxPunchthroughToken;

    fn get_punchthrough_token_for(
        &self,
        punchthrough: <Self::PunchthroughToken as PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
        Some(LiteBoxPunchthroughToken { punchthrough })
    }
}

impl LiteBoxKernel {
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
            page_table: unsafe { mm::PageTable::new(init_page_table_addr) },
            user_contexts: UserContextMap::new(),
        }))
    }

    pub fn init(&self, cpu_mhz: u64) {
        CPU_MHZ.store(cpu_mhz, core::sync::atomic::Ordering::Relaxed);
    }

    /// Create a new page table for user space. Currently, it maps the entire kernel memory for
    /// proper operations (e.g., syscall handling). We should consider implementing
    /// partial mapping to mitigate side-channel attacks and shallow copying to get rid of redundant
    /// page table data structures for kernel space.
    #[allow(clippy::unused_self)]
    pub(crate) fn new_user_page_table(&self) -> mm::PageTable<PAGE_SIZE> {
        // TODO: use separate page table later
        let (cr3, _) = x86_64::registers::control::Cr3::read_raw();
        unsafe { mm::PageTable::new(cr3.start_address()) }
    }

    /// Register the shim. This function must be called for each core to program
    /// its MSRs.
    pub fn register_shim(
        shim: &'static dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ) {
        syscall_entry::init(shim);
    }

    // TODO: replace it with actual implementation (e.g., atomically increment PID/TID)
    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        litebox_common_linux::TaskParams {
            pid: 1,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
        }
    }
}

impl RawMutexProvider for LiteBoxKernel {
    type RawMutex = RawMutex;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        Self::RawMutex {
            inner: AtomicU32::new(0),
        }
    }
}

/// An implementation of [`litebox::platform::RawMutex`]
pub struct RawMutex {
    inner: AtomicU32,
}

/// TODO: common mutex implementation could be moved to a shared crate
impl litebox::platform::RawMutex for RawMutex {
    fn underlying_atomic(&self) -> &core::sync::atomic::AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, _n: usize) -> usize {
        unimplemented!()
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

impl RawMutex {
    fn block_or_maybe_timeout(
        &self,
        _val: u32,
        _timeout: Option<core::time::Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        unimplemented!()
    }
}

impl DebugLogProvider for LiteBoxKernel {
    fn debug_log_print(&self, msg: &str) {
        crate::arch::ioport::serial_print_string(msg);
    }
}

/// An implementation of [`litebox::platform::Instant`]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

/// An implementation of [`litebox::platform::SystemTime`]
pub struct SystemTime();

impl TimeProvider for LiteBoxKernel {
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

    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        let duration_micros: u64 = duration.as_micros().try_into().ok()?;
        Some(Instant(self.0.checked_add(
            duration_micros.checked_mul(CPU_MHZ.load(core::sync::atomic::Ordering::Relaxed))?,
        )?))
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

impl IPInterfaceProvider for LiteBoxKernel {
    fn send_ip_packet(&self, _packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        unimplemented!()
    }

    fn receive_ip_packet(
        &self,
        _packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        unimplemented!()
    }
}

impl<const ALIGN: usize> PageManagementProvider<ALIGN> for LiteBoxKernel {
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
        // TODO: Consider whether we need to reserve some pages in the kernel context.
        // For example, we might have to reserve some pages for hardware operations like
        // memory-mapped I/O.
        core::iter::empty()
    }
}

impl litebox::mm::linux::VmemPageFaultHandler for LiteBoxKernel {
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

impl StdioProvider for LiteBoxKernel {
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

/// Runs a guest thread with the given initial context.
///
/// # Safety
/// The context must be valid guest context.
/// # Panics
/// Panics if `gsbase` is larger than `u64::MAX`.
pub unsafe fn run_thread(ctx: &mut litebox_common_linux::PtRegs) {
    // Currently, `litebox_platform_kernel` uses `swapgs` to efficiently switch between
    // kernel and user GS base values during kernel-user mode transitions.
    // This `swapgs` usage can pontetially leak a kernel address to the user, so
    // we clear the `KernelGsBase` MSR before running the user thread.
    crate::arch::write_kernel_gsbase_msr(VirtAddr::zero());
    unsafe {
        run_thread_inner(ctx);
    }
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn run_thread_inner(ctx: &mut litebox_common_linux::PtRegs) {
    core::arch::naked_asm!(
        "push rbp",
        "mov rbp, rsp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "push r15", // align
        "mov rax, rsp",
        // Save host rsp and rbp and guest context top in TLS.
        "mov gs:host_sp@tpoff, rsp",
        "mov gs:host_bp@tpoff, rbp",
        "call {init_handler}",
        "jmp done",
        "done:",
        "mov rbp, gs:host_bp@tpoff",
        "mov rsp, gs:host_sp@tpoff",
        "lea rsp, [rbp - 5 * 8]",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret",
        init_handler = sym init_handler
    );
}

/// TODO: call shim init.
/// # Safety
/// This function assumes that the caller uses `call` not `jmp` as it
/// gets the return address from the stack top and store it to TLS.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn init_handler(_ctx: &litebox_common_linux::PtRegs) -> ! {
    core::arch::naked_asm!(
        "mov r11, [rsp]",
        "mov gs:run_thread_done@tpoff, r11",
        "call {switch_to_guest}",
        switch_to_guest = sym switch_to_guest
    );
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    "
    .section .tbss
    .align 8
scratch:
    .quad 0
scratch2:
    .quad 0
.globl host_sp
host_sp:
    .quad 0
.globl host_bp
host_bp:
    .quad 0
.globl guest_sp
guest_sp:
    .quad 0
.globl guest_ret
guest_ret:
    .quad 0
.globl guest_rflags
guest_rflags:
    .quad 0
.globl run_thread_done
run_thread_done:
    .quad 0
    "
);

/// Switches to the provided guest context in kernel mode (for testing).
///
/// # Safety
/// The context must be valid guest context.
///
/// Do not call this at a point where the stack needs to be unwound to run
/// destructors.
#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest_kernel_mode(ctx: &litebox_common_linux::PtRegs) -> ! {
    core::arch::naked_asm!(
        // Restore guest context from ctx.
        "mov rsp, rdi",
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
        "add rsp, 8",           // skip orig_rax
        "pop gs:scratch@tpoff", // read rip into scratch
        "add rsp, 8",           // skip cs
        "popfq",
        "pop rsp",
        "jmp gs:scratch@tpoff", // jump to the guest
    );
}

/// Switches to the provided guest context with the user mode.
///
/// # Safety
/// The context must be valid guest context.
///
/// Do not call this at a point where the stack needs to be unwound to run
/// destructors.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn switch_to_guest(_ctx: &litebox_common_linux::PtRegs) -> ! {
    unsafe {
        core::arch::asm!(
            // Restore guest context from ctx.
            "mov rsp, rdi",
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
            "add rsp, 8", // skip orig_rax
            // Flush TLB by reloading CR3
            "mov rax, cr3",
            "mov cr3, rax",
            "xor eax, eax",
            // Stack already has all the values needed for iretq (rip, cs, flags, rsp, ds)
            // from the PtRegs structure.
            // clear the GS base register (as the `KernelGsBase` MSR contains 0)
            // while writing the current GS base value to `KernelGsBase`.
            "swapgs",
            "iretq",
            options(noreturn)
        );
    }
}

unsafe impl litebox::platform::ThreadLocalStorageProvider for LiteBoxKernel {
    fn get_thread_local_storage() -> *mut () {
        let tls = per_cpu_variables::with_per_cpu_variables_mut(|pcv| pcv.tls);
        tls.as_mut_ptr::<()>()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        per_cpu_variables::with_per_cpu_variables_mut(|pcv| {
            let old = pcv.tls;
            pcv.tls = x86_64::VirtAddr::new(value as u64);
            old.as_u64() as *mut ()
        })
    }
}

impl litebox::platform::CrngProvider for LiteBoxKernel {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        // FIXME: generate real random data.
        static RANDOM: spin::mutex::SpinMutex<litebox::utils::rng::FastRng> =
            spin::mutex::SpinMutex::new(litebox::utils::rng::FastRng::new_from_seed(
                core::num::NonZeroU64::new(0x4d595df4d0f33173).unwrap(),
            ));
        let mut random = RANDOM.lock();
        for b in buf.chunks_mut(8) {
            b.copy_from_slice(&random.next_u64().to_ne_bytes()[..b.len()]);
        }
    }
}
