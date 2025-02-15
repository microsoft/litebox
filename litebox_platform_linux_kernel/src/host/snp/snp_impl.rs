//! An implementation of [`HostInterface`] for SNP VMM

use core::arch::asm;

use super::ghcb::ghcb_prints;
use crate::{
    error,
    host::linux::{self, sigset_t},
    ptr::{UserConstPtr, UserMutPtr},
    HostInterface,
};

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
        set: UserConstPtr<sigset_t>,
        oldset: UserMutPtr<sigset_t>,
        sigsetsize: usize,
    ) -> Result<usize, error::Errno> {
        // Instead of passing the user space pointers to host, here we perform extra read and write
        // and pass kernel pointers to host. As long as we don't have large data to deal with, this
        // scheme is more straightforward. Alternative solution from previous implementation requires
        // the user space memory has mapped to physical pages as host operates on physical pages.
        // For kernel memory, it is always mapped to physical pages.
        let kset: Option<sigset_t> = if set.is_null() {
            None
        } else {
            Some(set.read_from_user(0).ok_or(error::Errno::EFAULT)?)
        };
        let mut koldset: Option<sigset_t> = if oldset.is_null() { None } else { Some(0) };
        let args = SyscallN::<4, NR_SYSCALL_RT_SIGPROCMASK> {
            args: [
                how as u32 as _,
                // TODO: sandbox driver needs to be updated to accept a kernel pointer from the guest
                kset.as_ref().map_or(0, |v| v as *const _ as u64),
                koldset.as_mut().map_or(0, |v| v as *mut _ as u64),
                sigsetsize as _,
            ],
        };
        let r = Self::syscalls(args)?;
        if let Some(v) = koldset {
            oldset.write_to_user(0, v).ok_or(error::Errno::EFAULT)?;
        }
        Ok(r)
    }

    fn wake_many(mutex: &core::sync::atomic::AtomicU32, n: usize) -> Result<usize, error::Errno> {
        // TODO: sandbox driver needs to be updated to accept a kernel pointer from the guest
        Self::syscalls(SyscallN::<6, NR_SYSCALL_FUTEX> {
            args: [mutex.as_ptr() as u64, FUTEX_WAKE as u64, n as u64, 0, 0, 0],
        })
    }

    fn block_or_maybe_timeout(
        mutex: &core::sync::atomic::AtomicU32,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<(), error::Errno> {
        let timeout = timeout.map(|t| linux::Timespec {
            tv_sec: t.as_secs() as i64,
            tv_nsec: t.subsec_nanos() as i64,
        });
        // TODO: sandbox driver needs to be updated to accept a kernel pointer from the guest
        Self::syscalls(SyscallN::<6, NR_SYSCALL_FUTEX> {
            args: [
                mutex.as_ptr() as u64,
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
