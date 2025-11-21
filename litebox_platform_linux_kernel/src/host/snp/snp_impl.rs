//! An implementation of [`HostInterface`] for SNP VMM
use ::alloc::boxed::Box;
use core::arch::asm;

use litebox::{
    platform::{RawConstPointer, RawMutPointer},
    utils::ReinterpretUnsignedExt as _,
};
use litebox_common_linux::{CloneFlags, SigSet, SigmaskHow};

use super::ghcb::ghcb_prints;
use crate::{
    Errno, HostInterface,
    ptr::{UserConstPtr, UserMutPtr},
};

#[expect(dead_code, reason = "bindings are generated from C header files")]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use bindings::vmpl2_boot_params;

pub type SnpLinuxKernel = crate::LinuxKernel<HostSnpInterface>;

const MAX_ARGS_SIZE: usize = 6;
type ArgsArray = [u64; MAX_ARGS_SIZE];

#[cfg(not(test))]
mod alloc {
    use crate::HostInterface;
    use crate::mm::MemoryProvider;
    use litebox::utils::TruncateExt as _;

    const HEAP_ORDER: usize = super::bindings::SNP_VMPL_ALLOC_MAX_ORDER as usize + 12 + 1;
    const PGDIR_SHIFT: u64 = 39;
    const LINUX_PAGE_OFFSET: u64 = 0xffff888000000000;
    const LITEBOX_PAGE_OFFSET: u64 = LINUX_PAGE_OFFSET + (1 << PGDIR_SHIFT);

    #[global_allocator]
    static SNP_ALLOCATOR: litebox::mm::allocator::SafeZoneAllocator<
        'static,
        HEAP_ORDER,
        super::SnpLinuxKernel,
    > = litebox::mm::allocator::SafeZoneAllocator::new();

    impl litebox::mm::allocator::MemoryProvider for super::SnpLinuxKernel {
        fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
            super::HostSnpInterface::alloc(layout).map(|(addr, size)| {
                (
                    Self::pa_to_va(crate::arch::PhysAddr::new_truncate(addr as u64))
                        .as_u64()
                        .truncate(),
                    size,
                )
            })
        }

        unsafe fn free(addr: usize) {
            unsafe { super::HostSnpInterface::free(addr) }
        }
    }

    impl crate::mm::MemoryProvider for super::SnpLinuxKernel {
        const GVA_OFFSET: crate::arch::VirtAddr = crate::arch::VirtAddr::new(LITEBOX_PAGE_OFFSET);
        const PRIVATE_PTE_MASK: u64 = 1 << 51; // SNP encryption bit

        fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
            SNP_ALLOCATOR.allocate_pages(order)
        }

        unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
            unsafe { SNP_ALLOCATOR.free_pages(ptr, order) }
        }
    }
}

/// Get the current task
fn current() -> Option<&'static mut bindings::vsbox_task> {
    let task: u64;
    unsafe {
        asm!("rdgsbase {}", out(reg) task, options(nostack, preserves_flags));

        let addr = crate::arch::VirtAddr::new(task);
        if addr.is_null() {
            return None;
        }

        Some(&mut *addr.as_mut_ptr())
    }
}

impl SnpLinuxKernel {
    pub fn init_task(
        &self,
        boot_params: &bindings::vmpl2_boot_params,
    ) -> litebox_common_linux::TaskParams {
        litebox_common_linux::TaskParams {
            pid: boot_params.pid,
            ppid: boot_params.ppid,
            uid: boot_params.uid,
            gid: boot_params.gid,
            euid: boot_params.euid,
            egid: boot_params.egid,
        }
    }
}

unsafe impl litebox::platform::ThreadLocalStorageProvider for SnpLinuxKernel {
    fn get_thread_local_storage() -> *mut () {
        current()
            .expect("Current task must be available")
            .tls
            .cast()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        let current_task = current().expect("Current task must be available");
        core::mem::replace(&mut current_task.tls, value.cast()).cast()
    }
}

core::arch::global_asm!(include_str!("entry.S"));

struct ThreadStartArgs {
    ctx: litebox_common_linux::PtRegs,
    init_thread: Box<dyn litebox::shim::InitThread>,
}

const RIP_OFFSET: usize = core::mem::offset_of!(litebox_common_linux::PtRegs, rip);
const EFLAGS_OFFSET: usize = core::mem::offset_of!(litebox_common_linux::PtRegs, eflags);

/// Callback function for a new thread
///
/// This is called by `sandbox_process_ret_from_fork` from `entry.S`.
/// Arguments should be set up by host.
#[unsafe(no_mangle)]
extern "C" fn thread_start(
    regs: &mut litebox_common_linux::PtRegs,
    thread_start_args: Box<ThreadStartArgs>,
) -> ! {
    *regs = thread_start_args.ctx;

    // Set up thread-local storage for the new thread. This is done by
    // calling the actual thread callback with the unpacked arguments
    thread_start_args.init_thread.init();

    // Restore the context
    unsafe {
        core::arch::asm!(
            "mov     rsp, {0}",
            "mov     rcx, [rsp + {rip_off}]",
            "mov     r11, [rsp + {eflags_off}]",
            "pop     r15",
            "pop     r14",
            "pop     r13",
            "pop     r12",
            "pop     rbp",
            "pop     rbx",
            "pop     rsi",        /* skip r11 */
            "pop     r10",
            "pop     r9",
            "pop     r8",
            "pop     rax",
            "pop     rsi",        /* skip rcx */
            "pop     rdx",
            "pop     rsi",
            "pop     rdi",
            "mov     rsp, [rsp + 0x20]",   /* original rsp */
            "swapgs",
            "sysretq",
            in(reg) regs,
            rip_off = const RIP_OFFSET,
            eflags_off = const EFLAGS_OFFSET,
        );
    }
    unreachable!("Thread should not return");
}

impl litebox::platform::ThreadProvider for SnpLinuxKernel {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = litebox_common_linux::errno::Errno;
    type ThreadHandle = ();

    unsafe fn spawn_thread(
        &self,
        ctx: &Self::ExecutionContext,
        init_thread: Box<dyn litebox::shim::InitThread>,
    ) -> Result<(), Self::ThreadSpawnError> {
        let flags = CloneFlags::THREAD
            | CloneFlags::VM
            | CloneFlags::FS
            | CloneFlags::FILES
            | CloneFlags::SIGHAND
            | CloneFlags::SYSVSEM
            | CloneFlags::CHILD_SETTID;
        let thread_start_args = Box::new(ThreadStartArgs {
            ctx: *ctx,
            init_thread,
        });
        let thread_start_arg_ptr = Box::into_raw(thread_start_args);
        // Note this is different from the usual clone3 syscall as we have a driver running
        // in VMPL0's kernel and handling the syscall differently.
        // The first argument will be placed into the new thread's RSI register (i.e. the second argument).
        HostSnpInterface::syscalls(SyscallN::<2, NR_SYSCALL_CLONE3> {
            args: [thread_start_arg_ptr as u64, flags.bits()],
        })?;
        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        // TODO
    }

    fn interrupt_thread(&self, &(): &Self::ThreadHandle) {
        // TODO
    }
}

impl bindings::SnpVmplRequestArgs {
    #[inline]
    fn new_request(code: u32, size: u32, args: ArgsArray) -> Self {
        bindings::SnpVmplRequestArgs {
            code,
            status: bindings::SNP_VMPL_REQ_INCOMPLETE,
            size,
            padding: 0,
            args,
            ret: 0,
        }
    }

    pub fn new_exit_request() -> Self {
        bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_EXIT_REQ,
            0,
            ArgsArray::default(),
        )
    }
}

pub struct HostSnpInterface;

const HVCALL_VTL_CALL: u16 = 0x0011;
const MAX_ERRNO: u64 = 4095;
#[inline]
const fn is_err_value(x: u64) -> bool {
    x >= !MAX_ERRNO
}

const PAGE_SIZE: u64 = litebox::mm::linux::PAGE_SIZE as u64;
/// Max physical address
const PHYS_ADDR_MAX: u64 = 0x10_0000_0000u64; // 64GB

const NR_SYSCALL_FUTEX: u32 = 202;
const NR_SYSCALL_RT_SIGPROCMASK: u32 = 14;
const NR_SYSCALL_READ: u32 = 0;
const NR_SYSCALL_WRITE: u32 = 1;
#[allow(dead_code)]
const NR_SYSCALL_EXIT: u32 = 60;
const NR_SYSCALL_EXIT_GROUP: u32 = 231;
const NR_SYSCALL_CLONE3: u32 = 435;

const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;

/// Punchthrough for syscalls
///
/// The generic parameter `N` is the number of arguments for the syscall
/// The generic parameter `ID` is the syscall number
pub struct SyscallN<const N: usize, const ID: u32> {
    /// Arguments for the syscall
    args: [u64; N],
}

impl HostSnpInterface {
    /// [VTL CALL](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm#vtl-call) via VMMCALL
    fn request(arg: &mut bindings::SnpVmplRequestArgs) {
        unsafe {
            asm!("vmmcall",
                in("rcx") HVCALL_VTL_CALL,
                in("r14") core::ptr::from_ref(arg) as u64,
            );
        }
    }

    fn syscalls<const N: usize, const ID: u32>(arg: SyscallN<N, ID>) -> Result<usize, Errno> {
        let mut args = [0; MAX_ARGS_SIZE];
        args[..N].copy_from_slice(&arg.args);
        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_SYSCALL_REQ,
            ID, // repurpose size field to syscall id
            args,
        );
        Self::request(&mut req);
        Self::parse_result(req.ret)
    }

    fn parse_result(res: u64) -> Result<usize, Errno> {
        if is_err_value(res) {
            #[expect(clippy::cast_possible_wrap)]
            let v = res as i64;
            Err(Errno::try_from(i32::try_from(v.abs()).unwrap()).unwrap())
        } else {
            Ok(usize::try_from(res).unwrap())
        }
    }

    fn parse_alloc_result(order: u32, addr: u64) -> Result<usize, Errno> {
        if addr == 0 {
            if order > bindings::SNP_VMPL_ALLOC_MAX_ORDER {
                Err(Errno::EINVAL)
            } else {
                Err(Errno::ENOMEM)
            }
        } else if !addr.is_multiple_of(PAGE_SIZE << order)
            || addr > PHYS_ADDR_MAX - (PAGE_SIZE << order)
        {
            // Address is not aligned or out of bounds
            Err(Errno::EINVAL)
        } else {
            Ok(usize::try_from(addr).unwrap())
        }
    }
}

impl HostInterface for HostSnpInterface {
    fn send_ip_packet(packet: &[u8]) -> Result<usize, Errno> {
        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_TUN_WRITE_REQ,
            3,
            [packet.as_ptr() as u64, packet.len() as u64, 0, 0, 0, 0],
        );
        Self::request(&mut req);
        Self::parse_result(req.ret)
    }

    fn receive_ip_packet(packet: &mut [u8]) -> Result<usize, Errno> {
        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_TUN_READ_REQ,
            3,
            [packet.as_ptr() as u64, packet.len() as u64, 0, 0, 0, 0],
        );
        Self::request(&mut req);
        Self::parse_result(req.ret)
    }

    fn log(msg: &str) {
        ghcb_prints(msg);
    }

    fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        // To reduce the number of hypercalls, we allocate the maximum order.
        // Assertion is added to prevent the allocation size from exceeding the maximum order.
        let size = core::cmp::max(
            layout.size().next_power_of_two(),
            usize::try_from(PAGE_SIZE).unwrap(),
        );
        assert!(size <= usize::try_from(PAGE_SIZE << bindings::SNP_VMPL_ALLOC_MAX_ORDER).unwrap());

        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_ALLOC_REQ,
            1,
            [u64::from(bindings::SNP_VMPL_ALLOC_MAX_ORDER), 0, 0, 0, 0, 0],
        );
        Self::request(&mut req);
        match Self::parse_alloc_result(bindings::SNP_VMPL_ALLOC_MAX_ORDER, req.ret) {
            Ok(addr) => Some((
                addr,
                usize::try_from(PAGE_SIZE << bindings::SNP_VMPL_ALLOC_MAX_ORDER).unwrap(),
            )),
            Err(Errno::ENOMEM) => None,
            Err(e) => unimplemented!("Unexpected error: {}", e),
        }
    }

    unsafe fn free(_addr: usize) {
        unimplemented!()
    }

    fn return_to_host() -> ! {
        let mut req = bindings::SnpVmplRequestArgs::new_exit_request();
        Self::request(&mut req);
        unreachable!("Should not return to the caller after returning to host");
    }

    fn terminate(reason_set: u64, reason_code: u64) -> ! {
        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_TERMINATE_REQ,
            2,
            [reason_set, reason_code, 0, 0, 0, 0],
        );
        Self::request(&mut req);

        // In case hypervisor fails to terminate it or intentionally reschedules it,
        // halt the CPU to prevent further execution
        unreachable!("Should not return to the caller after terminating the vm");
    }

    fn rt_sigprocmask(
        how: SigmaskHow,
        set: Option<UserConstPtr<SigSet>>,
        oldset: Option<UserMutPtr<SigSet>>,
    ) -> Result<usize, Errno> {
        // Instead of passing the user space pointers to host, here we perform extra read and write
        // and pass kernel pointers to host. As long as we don't have large data to deal with, this
        // scheme is more straightforward. Alternative solution from previous implementation requires
        // the user space memory has mapped to physical pages as host operates on physical pages.
        // For kernel memory, it is always mapped to physical pages.
        let kset: Option<SigSet> = match set {
            Some(s) => Some(
                unsafe { s.read_at_offset(0) }
                    .ok_or(Errno::EFAULT)?
                    .into_owned(),
            ),
            None => None,
        };
        let mut koldset: Option<SigSet> = if oldset.is_none() {
            None
        } else {
            Some(SigSet::empty())
        };
        let args = SyscallN::<4, NR_SYSCALL_RT_SIGPROCMASK> {
            args: [
                u64::try_from(how as i32).unwrap(),
                kset.as_ref().map_or(0, |v| core::ptr::from_ref(v) as u64),
                koldset
                    .as_mut()
                    .map_or(0, |v| core::ptr::from_mut(v) as u64),
                size_of::<SigSet>() as _,
            ],
        };
        let r = Self::syscalls(args)?;
        if let Some(v) = koldset {
            unsafe { oldset.unwrap().write_at_offset(0, v) }.ok_or(Errno::EFAULT)?;
        }
        Ok(r)
    }

    fn wake_many(mutex: &core::sync::atomic::AtomicU32, n: usize) -> Result<usize, Errno> {
        // TODO: sandbox driver needs to be updated to accept a kernel pointer from the guest
        Self::syscalls(SyscallN::<6, NR_SYSCALL_FUTEX> {
            args: [mutex.as_ptr() as u64, FUTEX_WAKE as u64, n as u64, 0, 0, 0],
        })
    }

    fn block_or_maybe_timeout(
        mutex: &core::sync::atomic::AtomicU32,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<(), Errno> {
        let timeout = timeout.map(|t| litebox_common_linux::Timespec {
            tv_sec: i64::try_from(t.as_secs()).unwrap(),
            tv_nsec: u64::from(t.subsec_nanos()),
        });
        // TODO: sandbox driver needs to be updated to accept a kernel pointer from the guest
        Self::syscalls(SyscallN::<6, NR_SYSCALL_FUTEX> {
            args: [
                mutex.as_ptr() as u64,
                FUTEX_WAIT as u64,
                u64::from(val),
                timeout
                    .as_ref()
                    .map_or(0, |t| core::ptr::from_ref(t) as u64),
                0,
                0,
            ],
        })
        .map(|_| ())
    }

    fn read_from_stdin(buf: &mut [u8]) -> Result<usize, Errno> {
        Self::syscalls(SyscallN::<3, NR_SYSCALL_READ> {
            args: [
                litebox_common_linux::STDIN_FILENO as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            ],
        })
    }

    fn write_to(stream: litebox::platform::StdioOutStream, buf: &[u8]) -> Result<usize, Errno> {
        Self::syscalls(SyscallN::<3, NR_SYSCALL_WRITE> {
            args: [
                u64::from(
                    match stream {
                        litebox::platform::StdioOutStream::Stdout => {
                            litebox_common_linux::STDOUT_FILENO
                        }
                        litebox::platform::StdioOutStream::Stderr => {
                            litebox_common_linux::STDERR_FILENO
                        }
                    }
                    .reinterpret_as_unsigned(),
                ),
                buf.as_ptr() as u64,
                buf.len() as u64,
            ],
        })
    }

    fn terminate_process(code: i32) -> ! {
        let _ = Self::syscalls(SyscallN::<1, NR_SYSCALL_EXIT_GROUP> {
            args: [u64::from(code.reinterpret_as_unsigned())],
        });
        unreachable!("Should not return to the caller after terminating the process");
    }
}

impl litebox::platform::CrngProvider for SnpLinuxKernel {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        // FIXME: call into the trusted host to get random bytes.
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
