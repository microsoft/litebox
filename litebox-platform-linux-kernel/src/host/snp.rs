use core::sync::atomic::AtomicU32;

use thiserror::Error;

use super::{
    hypercall::HyperVInterface,
    linux::{pt_regs, Timespec},
    HostInterface, HostRequest, HyperCallArgs,
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

    fn new_exit_request() -> Self {
        SnpVmplRequestArgs::new_request(SNP_VMPL_EXIT_REQ, 0, ArgsArray::default())
    }
}

impl<'a> From<HostRequest<'a, OtherHostRequest<'a>>> for SnpVmplRequestArgs {
    fn from(request: HostRequest<'a, OtherHostRequest>) -> Self {
        match request {
            HostRequest::Alloc { order } => {
                SnpVmplRequestArgs::new_request(SNP_VMPL_ALLOC_REQ, 1, [order, 0, 0, 0, 0, 0])
            }
            HostRequest::RecvPacket(buf) => SnpVmplRequestArgs::new_request(
                SNP_VMPL_TUN_READ_REQ,
                3,
                [buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0, 0],
            ),
            HostRequest::SendPacket(data) => SnpVmplRequestArgs::new_request(
                SNP_VMPL_TUN_WRITE_REQ,
                3,
                [data.as_ptr() as u64, data.len() as u64, 0, 0, 0, 0],
            ),
            HostRequest::Exit => SnpVmplRequestArgs::new_exit_request(),
            HostRequest::Terminate {
                reason_set,
                reason_code,
            } => SnpVmplRequestArgs::new_request(
                SNP_VMPL_TERMINATE_REQ,
                2,
                [reason_set, reason_code, 0, 0, 0, 0],
            ),
            HostRequest::Other(other) => match other {
                OtherHostRequest::AllocFutexPage => {
                    SnpVmplRequestArgs::new_request(SNP_VMPL_ALLOC_FUTEX_REQ, 0, [0, 0, 0, 0, 0, 0])
                }
                OtherHostRequest::Syscall { num, pt_regs } => SnpVmplRequestArgs::new_request(
                    SNP_VMPL_SYSCALL_REQ,
                    2,
                    [pt_regs as *mut _ as u64, num, 0, 0, 0, 0],
                ),
                #[cfg(debug_assertions)]
                OtherHostRequest::DumpStack { rsp, len } => SnpVmplRequestArgs::new_request(
                    SNP_VMPL_PRINT_REQ,
                    3,
                    [SNP_VMPL_PRINT_STACK as u64, rsp, len, 0, 0, 0],
                ),
                #[cfg(debug_assertions)]
                OtherHostRequest::DumpRegs(regs) => SnpVmplRequestArgs::new_request(
                    SNP_VMPL_PRINT_REQ,
                    2,
                    [
                        SNP_VMPL_PRINT_PT_REGS as u64,
                        regs as *const _ as u64,
                        0,
                        0,
                        0,
                        0,
                    ],
                ),
            },
        }
    }
}

const PAGE_SIZE: u64 = 4096;
/// Max physical address
const PHYS_ADDR_MAX: u64 = 0x10_0000_0000u64; // 64GB

const EINTR: i64 = 4;
const EAGAIN: i64 = 11;
const ETIMEDOUT: i64 = 110;
const ERESTARTSYS: i64 = 512;

impl<'a> HyperCallArgs<'a, OtherHostRequest<'a>> for SnpVmplRequestArgs {
    fn parse_alloc_result(&self, order: u64, _r: ()) -> Result<u64, super::AllocError> {
        let ret = self.ret;
        if ret == 0 {
            if order > SNP_VMPL_ALLOC_MAX_ORDER as u64 {
                Err(super::AllocError::InvalidInput(order))
            } else {
                Err(super::AllocError::OutOfMemory)
            }
        } else if ret % (PAGE_SIZE << order) != 0 || ret > PHYS_ADDR_MAX - (PAGE_SIZE << order) {
            // Address is not aligned or out of bounds
            Err(super::AllocError::InvalidOutput(ret))
        } else {
            Ok(self.ret)
        }
    }

    fn parse_recv_result(&self, _r: ()) -> Result<usize, super::NetworkError> {
        let ret = self.ret as i64;
        if ret < 0 {
            match ret.abs() {
                EAGAIN => Err(super::NetworkError::WouldBlock),
                EINTR => Err(super::NetworkError::Interrupted),
                _ => panic!("Unknown error: {}", ret),
            }
        } else {
            Ok(ret as usize)
        }
    }

    fn parse_send_result(&self, _r: ()) -> Result<usize, super::NetworkError> {
        let ret = self.ret as i64;
        if ret <= 0 {
            match ret.abs() {
                0 | EAGAIN => Err(super::NetworkError::WouldBlock),
                EINTR => Err(super::NetworkError::Interrupted),
                _ => panic!("Unknown error: {}", ret),
            }
        } else {
            Ok(ret as usize)
        }
    }
}

enum OtherHostRequest<'a> {
    AllocFutexPage,

    /// Syscalls forwarded to the host
    Syscall {
        num: u64,
        pt_regs: &'a mut pt_regs,
    },

    /// Special hypercall for debugging purposes
    #[cfg(debug_assertions)]
    DumpStack {
        rsp: u64,
        len: u64,
    },
    #[cfg(debug_assertions)]
    DumpRegs(&'a pt_regs),
}

pub struct SnpInterface;

impl<'a> HostInterface<'a, SnpVmplRequestArgs, OtherHostRequest<'a>> for SnpInterface {
    type HyperCallInterface = HyperVInterface;

    fn post_check(req: &SnpVmplRequestArgs, _res: ()) {
        if req.status != SNP_VMPL_REQ_SUCCESS {
            let status = req.status;
            panic!("Request failed with status: {}", status);
        }
    }
}

const NR_SYSCALL_FUTEX: u64 = 202;

#[derive(Error, Debug)]
pub enum SysFutexError {
    #[error("Would block")]
    WouldBlock,
    #[error("Interrupted")]
    Interrupted,
    #[error("Timeout")]
    Timeout,
}

macro_rules! sys_forward_0 {
    ($num:expr, $regs:ident) => {{
        let orig_rax = $regs.rax;
        let ret = Self::syscall($num, $regs);
        $regs.rax = orig_rax;
        ret
    }};
}

macro_rules! sys_forward_1 {
    ($num:expr, $regs:ident, $arg0:expr) => {{
        let orig_rdi = $regs.rdi;
        $regs.rdi = $arg0;
        let ret = sys_forward_0!($num, $regs);
        $regs.rdi = orig_rdi;
        ret
    }};
}

macro_rules! sys_forward_2 {
    ($num:expr, $regs:ident, $arg0:expr, $arg1:expr) => {{
        let orig_rsi = $regs.rsi;
        $regs.rsi = $arg1;
        let ret = sys_forward_1!($num, $regs, $arg0);
        $regs.rsi = orig_rsi;
        ret
    }};
}

macro_rules! sys_forward_3 {
    ($num:expr, $regs:ident, $arg0:expr, $arg1:expr, $arg2:expr) => {{
        let orig_rdx = $regs.rdx;
        $regs.rdx = $arg2;
        let ret = sys_forward_2!($num, $regs, $arg0, $arg1);
        $regs.rdx = orig_rdx;
        ret
    }};
}

macro_rules! sys_forward_4 {
    ($num:expr, $regs:ident, $arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr) => {{
        let orig_r10 = $regs.r10;
        $regs.r10 = $arg3;
        let ret = sys_forward_3!($num, $regs, $arg0, $arg1, $arg2);
        $regs.r10 = orig_r10;
        ret
    }};
}

macro_rules! sys_forward_5 {
    ($num:expr, $regs:ident, $arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr) => {{
        let orig_r8 = $regs.r8;
        $regs.r8 = $arg4;
        let ret = sys_forward_4!($num, $regs, $arg0, $arg1, $arg2, $arg3);
        $regs.r8 = orig_r8;
        ret
    }};
}

macro_rules! sys_forward_6 {
    ($num:expr, $regs:ident, $arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, $arg5:expr) => {{
        let orig_r9 = $regs.r9;
        $regs.r9 = $arg5;
        let ret = sys_forward_5!($num, $regs, $arg0, $arg1, $arg2, $arg3, $arg4);
        $regs.r9 = orig_r9;
        ret
    }};
}

impl SnpInterface {
    pub fn alloc_futex_page() -> Result<u64, super::AllocError> {
        let req = &mut HostRequest::Other(OtherHostRequest::AllocFutexPage).into();
        Self::call(req);
        req.parse_alloc_result(0, ())
    }

    #[inline]
    fn syscall(num: u64, pt_regs: &mut pt_regs) -> i64 {
        let req = &mut HostRequest::Other(OtherHostRequest::Syscall { num, pt_regs }).into();
        Self::call(req);
        req.ret as i64
    }

    pub fn sys_futex(
        pt_regs: &mut pt_regs,
        uaddr: Option<*const AtomicU32>,
        futex_op: i32,
        val: u32,
        timeout: Option<*const Timespec>,
        uaddr2: Option<*const AtomicU32>,
        val3: u32,
    ) -> Result<usize, SysFutexError> {
        let ret = sys_forward_6!(
            NR_SYSCALL_FUTEX,
            pt_regs,
            match uaddr {
                Some(uaddr) => uaddr as _,
                None => 0,
            },
            futex_op as _,
            val as _,
            match timeout {
                Some(timeout) => timeout as _,
                None => 0,
            },
            match uaddr2 {
                Some(uaddr2) => uaddr2 as _,
                None => 0,
            },
            val3 as _
        );

        if ret < 0 {
            match ret.abs() {
                EAGAIN => Err(SysFutexError::WouldBlock),
                EINTR | ERESTARTSYS => Err(SysFutexError::Interrupted),
                ETIMEDOUT => Err(SysFutexError::Timeout),
                _ => panic!("Unknown error: {}", ret),
            }
        } else {
            Ok(ret as usize)
        }
    }

    pub fn dump_stack(rsp: u64) {
        Self::call(&mut HostRequest::Other(OtherHostRequest::DumpStack { rsp, len: 512 }).into())
    }

    pub fn dump_pt_regs(regs: &pt_regs) {
        Self::call(&mut HostRequest::Other(OtherHostRequest::DumpRegs(regs)).into())
    }
}
