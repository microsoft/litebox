//! An implementation of [`HostInterface`] for SNP VMM

use core::arch::asm;

use litebox::{
    platform::{RawConstPointer, RawMutPointer, ThreadLocalStorageProvider},
    utils::ReinterpretUnsignedExt as _,
};
use litebox_common_linux::{SigSet, SigmaskHow};

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
    pub fn set_init_tls(&self, boot_params: &bindings::vmpl2_boot_params) {
        let task = ::alloc::boxed::Box::new(litebox_common_linux::Task {
            pid: boot_params.pid,
            tid: boot_params.pid,
            ppid: boot_params.ppid,
            clear_child_tid: None,
            robust_list: None,
            credentials: ::alloc::sync::Arc::new(litebox_common_linux::Credentials {
                uid: boot_params.uid as usize,
                gid: boot_params.gid as usize,
                euid: boot_params.euid as usize,
                egid: boot_params.egid as usize,
            }),
        });
        let tls = litebox_common_linux::ThreadLocalStorage::new(task);
        self.set_thread_local_storage(tls);
    }
}

impl litebox::platform::ThreadLocalStorageProvider for SnpLinuxKernel {
    type ThreadLocalStorage = litebox_common_linux::ThreadLocalStorage<SnpLinuxKernel>;

    fn set_thread_local_storage(&self, value: Self::ThreadLocalStorage) {
        let current_task = current().expect("Current task must be available");
        assert!(current_task.tls.is_null(), "TLS should not be set yet");
        let tls = ::alloc::boxed::Box::new(value);
        current_task.tls = ::alloc::boxed::Box::into_raw(tls).cast();
    }

    fn with_thread_local_storage_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::ThreadLocalStorage) -> R,
    {
        let current_task = current().expect("Current task must be available");
        assert!(!current_task.tls.is_null(), "TLS should be set");
        let tls = unsafe { &mut *current_task.tls.cast::<Self::ThreadLocalStorage>() };
        assert!(!tls.borrowed, "TLS should not be borrowed");
        tls.borrowed = true; // mark as borrowed
        let ret = f(tls);
        tls.borrowed = false; // mark as not borrowed
        ret
    }

    fn release_thread_local_storage(&self) -> Self::ThreadLocalStorage {
        let current_task = current().expect("Current task must be available");
        assert!(!current_task.tls.is_null(), "TLS should be set");
        let tls = unsafe {
            ::alloc::boxed::Box::from_raw(current_task.tls.cast::<Self::ThreadLocalStorage>())
        };
        current_task.tls = ::core::ptr::null_mut();
        *tls
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

const PAGE_SIZE: u64 = 4096;
/// Max physical address
const PHYS_ADDR_MAX: u64 = 0x10_0000_0000u64; // 64GB

const NR_SYSCALL_FUTEX: u32 = 202;
const NR_SYSCALL_RT_SIGPROCMASK: u32 = 14;
const NR_SYSCALL_READ: u32 = 0;
const NR_SYSCALL_WRITE: u32 = 1;

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
            // FIXME: need to update sandbox driver for the change of this interface
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

    fn exit() -> ! {
        let mut req = bindings::SnpVmplRequestArgs::new_exit_request();
        Self::request(&mut req);
        loop {
            unsafe { asm!("hlt") }
        }
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
        loop {
            unsafe { asm!("hlt") }
        }
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
                // TODO: sandbox driver needs to be updated to accept a kernel pointer from the guest
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
}
