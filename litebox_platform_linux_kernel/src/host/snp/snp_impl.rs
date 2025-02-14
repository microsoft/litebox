//! An implementation of [`HostInterface`] for SNP VMM

use core::arch::asm;

use super::ghcb::ghcb_prints;
use crate::{error, host::linux, HostInterface, Task};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

const MAX_ARGS_SIZE: usize = 6;
type ArgsArray = [u64; MAX_ARGS_SIZE];

impl SnpVmplRequestArgs {
    #[inline]
    fn new_request(code: u32, size: u32, args: ArgsArray) -> Self {
        SnpVmplRequestArgs {
            code,
            status: SNP_VMPL_REQ_INCOMPLETE,
            size,
            padding: 0,
            args,
            ret: 0,
        }
    }

    pub fn new_exit_request() -> Self {
        SnpVmplRequestArgs::new_request(SNP_VMPL_EXIT_REQ, 0, ArgsArray::default())
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
    fn request(arg: &mut SnpVmplRequestArgs) {
        unsafe {
            asm!("vmmcall",
                in("rcx") HVCALL_VTL_CALL,
                in("r14") arg as *const _ as u64,
            );
        }
    }

    fn syscalls<const N: usize, const ID: u32>(
        arg: SyscallN<N, ID>,
    ) -> Result<usize, crate::error::Errno> {
        let mut args = [0; MAX_ARGS_SIZE];
        args[..N].copy_from_slice(&arg.args);
        let mut req = SnpVmplRequestArgs::new_request(
            // FIXME: need to update sandbox driver for the change of this interface
            SNP_VMPL_SYSCALL_REQ,
            ID, // repurpose size field to syscall id
            args,
        );
        Self::request(&mut req);
        Self::parse_result(req.ret)
    }

    /// To be used by [`Self::alloc_raw_mutex`]
    #[allow(dead_code)]
    fn alloc_futex_page() -> Result<u64, error::Errno> {
        let mut req =
            SnpVmplRequestArgs::new_request(SNP_VMPL_ALLOC_FUTEX_REQ, 0, [0, 0, 0, 0, 0, 0]);
        Self::request(&mut req);
        Self::parse_alloc_result(0, req.ret)
    }

    fn parse_result(res: u64) -> Result<usize, crate::error::Errno> {
        if is_err_value(res) {
            let v = res as i64;
            Err(error::Errno::from_raw(v.abs() as i32))
        } else {
            Ok(res as usize)
        }
    }

    fn parse_alloc_result(order: u32, addr: u64) -> Result<u64, crate::error::Errno> {
        if addr == 0 {
            if order > SNP_VMPL_ALLOC_MAX_ORDER {
                Err(error::Errno::EINVAL)
            } else {
                Err(error::Errno::ENOMEM)
            }
        } else if addr % (PAGE_SIZE << order) != 0 || addr > PHYS_ADDR_MAX - (PAGE_SIZE << order) {
            // Address is not aligned or out of bounds
            Err(error::Errno::EINVAL)
        } else {
            Ok(addr)
        }
    }
}

impl HostInterface for HostSnpInterface {
    fn send_ip_packet(packet: &[u8]) -> Result<usize, crate::error::Errno> {
        let mut req = SnpVmplRequestArgs::new_request(
            SNP_VMPL_TUN_WRITE_REQ,
            3,
            [packet.as_ptr() as u64, packet.len() as u64, 0, 0, 0, 0],
        );
        Self::request(&mut req);
        Self::parse_result(req.ret)
    }

    fn receive_ip_packet(packet: &mut [u8]) -> Result<usize, crate::error::Errno> {
        let mut req = SnpVmplRequestArgs::new_request(
            SNP_VMPL_TUN_READ_REQ,
            3,
            [packet.as_ptr() as u64, packet.len() as u64, 0, 0, 0, 0],
        );
        Self::request(&mut req);
        Self::parse_result(req.ret)
    }

    fn log(msg: &str) {
        ghcb_prints(msg);
    }

    fn alloc(order: u32) -> Result<u64, error::Errno> {
        let mut req =
            SnpVmplRequestArgs::new_request(SNP_VMPL_ALLOC_REQ, 1, [order as u64, 0, 0, 0, 0, 0]);
        Self::request(&mut req);
        Self::parse_alloc_result(order, req.ret)
    }

    fn exit() -> ! {
        let mut req = SnpVmplRequestArgs::new_exit_request();
        Self::request(&mut req);
        loop {
            unsafe { asm!("hlt") }
        }
    }

    fn terminate(reason_set: u64, reason_code: u64) -> ! {
        let mut req = SnpVmplRequestArgs::new_request(
            SNP_VMPL_TERMINATE_REQ,
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
        set: Option<*const crate::host::linux::sigset_t>,
        oldset: Option<*mut crate::host::linux::sigset_t>,
        sigsetsize: usize,
    ) -> Result<usize, error::Errno> {
        let args = SyscallN::<4, NR_SYSCALL_RT_SIGPROCMASK> {
            args: [
                how as u32 as _,
                set.map_or(0, |v| v as u64),
                oldset.map_or(0, |v| v as u64),
                sigsetsize as _,
            ],
        };
        Self::syscalls(args)
    }

    fn wake_many<T: Task>(
        mutex: &core::sync::atomic::AtomicU32,
        n: usize,
    ) -> Result<usize, error::Errno> {
        let mutex = T::current()
            .unwrap()
            .convert_mut_ptr_to_host(mutex.as_ptr());
        Self::syscalls(SyscallN::<6, NR_SYSCALL_FUTEX> {
            args: [mutex as u64, FUTEX_WAKE as u64, n as u64, 0, 0, 0],
        })
    }

    fn block_or_maybe_timeout<T: Task>(
        mutex: &core::sync::atomic::AtomicU32,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<(), error::Errno> {
        let timeout = timeout.map(|t| linux::Timespec {
            tv_sec: t.as_secs() as i64,
            tv_nsec: t.subsec_nanos() as i64,
        });
        let mutex = T::current()
            .unwrap()
            .convert_mut_ptr_to_host(mutex.as_ptr());
        Self::syscalls(SyscallN::<6, NR_SYSCALL_FUTEX> {
            args: [
                mutex as u64,
                FUTEX_WAIT as u64,
                val as u64,
                timeout.as_ref().map_or(0, |t| t as *const _ as u64),
                0,
                0,
            ],
        })
        .map(|_| ())
    }
}

/// The base address of the one-to-one mapping for all physical memory
/// to kernel virtual memory.
const VMPL2_PAGE_OFFSET: u64 = 0xffff890000000000;

/// Convert physical address to kernel virtual address
#[allow(dead_code)]
fn phys_to_virt(addr: u64) -> u64 {
    // assume(addr < PHYS_ADDR_MAX);
    addr + VMPL2_PAGE_OFFSET
}

/// Convert kernel virtual address to physical address
fn virt_to_phys(addr: u64) -> u64 {
    assert!(addr > VMPL2_PAGE_OFFSET);
    addr - VMPL2_PAGE_OFFSET
}

impl Task for vsbox_task {
    fn current<'a>() -> Option<&'a Self> {
        let task: u64;
        unsafe {
            asm!("rdgsbase {}", out(reg) task, options(nostack, preserves_flags));

            if task == 0 {
                return None;
            }
            Some(&*(task as *const Self))
        }
    }

    fn convert_ptr_to_host<T>(&self, ptr: *const T) -> *const T {
        let mem_base = self.snp_vmpl0_mem_base;
        (virt_to_phys(ptr as u64) + mem_base) as *const T
    }

    fn convert_mut_ptr_to_host<T>(&self, ptr: *mut T) -> *mut T {
        let mem_base = self.snp_vmpl0_mem_base;
        (virt_to_phys(ptr as u64) + mem_base) as *mut T
    }
}
