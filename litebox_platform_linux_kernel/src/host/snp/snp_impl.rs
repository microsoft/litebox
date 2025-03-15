//! An implementation of [`HostInterface`] for SNP VMM

use core::arch::asm;

use super::ghcb::ghcb_prints;
use crate::{
    Errno, HostInterface,
    host::linux::{self, sigset_t},
    ptr::{UserConstPtr, UserMutPtr},
};

#[allow(dead_code)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub type SnpLinuxKenrel = crate::LinuxKernel<HostSnpInterface>;

const MAX_ARGS_SIZE: usize = 6;
type ArgsArray = [u64; MAX_ARGS_SIZE];

#[cfg(not(test))]
mod alloc {
    use crate::HostInterface;

    const HEAP_ORDER: usize = super::bindings::SNP_VMPL_ALLOC_MAX_ORDER as usize + 12 + 1;
    const PGDIR_SHIFT: u64 = 39;
    const LINUX_PAGE_OFFSET: u64 = 0xffff888000000000;
    const LITEBOX_PAGE_OFFSET: u64 = LINUX_PAGE_OFFSET + (1 << PGDIR_SHIFT);

    #[global_allocator]
    static SNP_ALLOCATOR: crate::mm::alloc::SafeZoneAllocator<
        'static,
        HEAP_ORDER,
        super::SnpLinuxKenrel,
    > = crate::mm::alloc::SafeZoneAllocator::new();

    impl crate::mm::MemoryProvider for super::SnpLinuxKenrel {
        const GVA_OFFSET: crate::arch::VirtAddr = crate::arch::VirtAddr::new(LITEBOX_PAGE_OFFSET);
        const PRIVATE_PTE_MASK: u64 = 1 << 51; // SNP encryption bit

        fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
            SNP_ALLOCATOR.allocate_pages(order)
        }

        unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
            unsafe { SNP_ALLOCATOR.free_pages(ptr, order) }
        }

        fn alloc(layout: &core::alloc::Layout) -> Result<(usize, usize), crate::Errno> {
            super::HostSnpInterface::alloc(layout)
        }

        unsafe fn free(addr: usize) {
            unsafe { super::HostSnpInterface::free(addr) }
        }
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
        } else if addr % (PAGE_SIZE << order) != 0 || addr > PHYS_ADDR_MAX - (PAGE_SIZE << order) {
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

    fn alloc(layout: &core::alloc::Layout) -> Result<(usize, usize), Errno> {
        // To reduce the number of hypercalls, we allocate the maximum order.
        // Assertion is added to prevent the allocation size from exceeding the maximum order.
        let size = core::cmp::max(
            layout.size().next_power_of_two(),
            usize::try_from(PAGE_SIZE).unwrap(),
        );
        assert!(size > usize::try_from(PAGE_SIZE << bindings::SNP_VMPL_ALLOC_MAX_ORDER).unwrap());

        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_ALLOC_REQ,
            1,
            [u64::from(bindings::SNP_VMPL_ALLOC_MAX_ORDER), 0, 0, 0, 0, 0],
        );
        Self::request(&mut req);
        Self::parse_alloc_result(bindings::SNP_VMPL_ALLOC_MAX_ORDER, req.ret).map(|addr| {
            (
                addr,
                usize::try_from(PAGE_SIZE << bindings::SNP_VMPL_ALLOC_MAX_ORDER).unwrap(),
            )
        })
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
        how: i32,
        set: UserConstPtr<sigset_t>,
        oldset: UserMutPtr<sigset_t>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        // Instead of passing the user space pointers to host, here we perform extra read and write
        // and pass kernel pointers to host. As long as we don't have large data to deal with, this
        // scheme is more straightforward. Alternative solution from previous implementation requires
        // the user space memory has mapped to physical pages as host operates on physical pages.
        // For kernel memory, it is always mapped to physical pages.
        let kset: Option<sigset_t> = if set.is_null() {
            None
        } else {
            Some(set.from_user_at_offset(0).ok_or(Errno::EFAULT)?)
        };
        let mut koldset: Option<sigset_t> = if oldset.is_null() { None } else { Some(0) };
        let args = SyscallN::<4, NR_SYSCALL_RT_SIGPROCMASK> {
            args: [
                u64::from(u32::try_from(how).unwrap()),
                // TODO: sandbox driver needs to be updated to accept a kernel pointer from the guest
                kset.as_ref().map_or(0, |v| core::ptr::from_ref(v) as u64),
                koldset
                    .as_mut()
                    .map_or(0, |v| core::ptr::from_mut(v) as u64),
                sigsetsize as _,
            ],
        };
        let r = Self::syscalls(args)?;
        if let Some(v) = koldset {
            oldset.to_user_at_offset(0, v).ok_or(Errno::EFAULT)?;
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
        let timeout = timeout.map(|t| linux::Timespec {
            tv_sec: i64::try_from(t.as_secs()).unwrap(),
            tv_nsec: i64::from(t.subsec_nanos()),
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
}
