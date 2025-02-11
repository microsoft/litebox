//! Host interface for SEV-SNP platform

use litebox::platform::{Punchthrough, PunchthroughError, PunchthroughToken};

use crate::error;

use super::{
    hypercall::HyperVInterface,
    linux::{pt_regs, Timespec},
    HostPunchthrough, HostPunchthroughProvider, HostPunchthroughToken, HyperCallInterface,
};

use paste::paste;
use seq_macro::seq;

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

/// Punchthrough for syscalls
pub struct SyscallN<'a, const N: usize> {
    num: u64,
    pt_regs: &'a mut pt_regs,
    args: [u64; N],
    saved_args: [u64; N],
    saved_rax: u64,
}

seq!(N in 0..=6 {
    /// vsbox specific punchthrough
    pub enum OtherPunchthrough<'a> {
        /// Allocate one page for futex
        AllocFutexPage,

        /// Syscalls forwarded to the host
        #(
            Syscall~N(SyscallN<'a, N>),
        )*

        /// Special hypercall for debugging purposes
        #[cfg(debug_assertions)]
        DumpStack {
            rsp: u64,
            len: u64,
        },
        #[cfg(debug_assertions)]
        DumpRegs(&'a pt_regs),
    }
});

pub type SnpPunchthrough<'b> = HostPunchthrough<'b, OtherPunchthrough<'b>>;

impl From<&SnpPunchthrough<'_>> for SnpVmplRequestArgs {
    fn from(request: &SnpPunchthrough) -> Self {
        match *request {
            HostPunchthrough::Alloc { order } => {
                SnpVmplRequestArgs::new_request(SNP_VMPL_ALLOC_REQ, 1, [order, 0, 0, 0, 0, 0])
            }
            HostPunchthrough::RecvPacket(ref buf) => SnpVmplRequestArgs::new_request(
                SNP_VMPL_TUN_READ_REQ,
                3,
                [buf.as_ptr() as u64, buf.len() as u64, 0, 0, 0, 0],
            ),
            HostPunchthrough::SendPacket(data) => SnpVmplRequestArgs::new_request(
                SNP_VMPL_TUN_WRITE_REQ,
                3,
                [data.as_ptr() as u64, data.len() as u64, 0, 0, 0, 0],
            ),
            HostPunchthrough::Exit => SnpVmplRequestArgs::new_exit_request(),
            HostPunchthrough::Terminate {
                reason_set,
                reason_code,
            } => SnpVmplRequestArgs::new_request(
                SNP_VMPL_TERMINATE_REQ,
                2,
                [reason_set, reason_code, 0, 0, 0, 0],
            ),
            HostPunchthrough::Other(ref other) => other.into(),
        }
    }
}

const PAGE_SIZE: u64 = 4096;
/// Max physical address
const PHYS_ADDR_MAX: u64 = 0x10_0000_0000u64; // 64GB

impl<'a, const N: usize> From<&SyscallN<'a, N>> for SnpVmplRequestArgs {
    fn from(v: &SyscallN<'a, N>) -> Self {
        SnpVmplRequestArgs::new_request(
            SNP_VMPL_SYSCALL_REQ,
            2,
            [v.pt_regs as *const _ as u64, v.num, 0, 0, 0, 0],
        )
    }
}

impl From<&OtherPunchthrough<'_>> for SnpVmplRequestArgs {
    fn from(req: &OtherPunchthrough) -> Self {
        match *req {
            OtherPunchthrough::AllocFutexPage => {
                SnpVmplRequestArgs::new_request(SNP_VMPL_ALLOC_FUTEX_REQ, 0, [0, 0, 0, 0, 0, 0])
            }
            #[cfg(debug_assertions)]
            OtherPunchthrough::DumpStack { rsp, len } => SnpVmplRequestArgs::new_request(
                SNP_VMPL_PRINT_REQ,
                3,
                [SNP_VMPL_PRINT_STACK as u64, rsp, len, 0, 0, 0],
            ),
            #[cfg(debug_assertions)]
            OtherPunchthrough::DumpRegs(regs) => SnpVmplRequestArgs::new_request(
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
            OtherPunchthrough::Syscall0(ref v) => v.into(),
            OtherPunchthrough::Syscall1(ref v) => v.into(),
            OtherPunchthrough::Syscall2(ref v) => v.into(),
            OtherPunchthrough::Syscall3(ref v) => v.into(),
            OtherPunchthrough::Syscall4(ref v) => v.into(),
            OtherPunchthrough::Syscall5(ref v) => v.into(),
            OtherPunchthrough::Syscall6(ref v) => v.into(),
        }
    }
}

const NR_SYSCALL_KILL: u64 = 62;
const NR_SYSCALL_FUTEX: u64 = 202;

macro_rules! sys_forward {
    ($self:ident, $num:expr, $regs:ident, $i:literal, $($args:expr),*) => {{
        paste! {
            let args = SyscallN::<$i> {
                num: $num,
                $regs,
                args: [$($args),*],
                saved_args: [0; $i],
                saved_rax: 0,
            };
            let req = SnpPunchthrough::Other(OtherPunchthrough::[<Syscall$i>](args));
            $self.get_punchthrough_token_for(req)
        }
    }};
}

macro_rules! sys_save_0 {
    ($v:ident) => {{
        $v.saved_rax = $v.pt_regs.rax;
    }};
}
macro_rules! sys_restore_0 {
    ($v:ident) => {{
        $v.pt_regs.rax = $v.saved_rax;
    }};
}

macro_rules! sys_restore_1 {
    ($v:ident) => {{
        sys_restore_0!($v);
        $v.pt_regs.rdi = $v.saved_args[0];
    }};
}

macro_rules! sys_save_1 {
    ($v:ident) => {{
        sys_save_0!($v);
        $v.saved_args[0] = $v.pt_regs.rdi;
        $v.pt_regs.rdi = $v.args[0];
    }};
}

macro_rules! sys_restore_2 {
    ($v:ident) => {{
        sys_restore_1!($v);
        $v.pt_regs.rsi = $v.saved_args[1];
    }};
}

macro_rules! sys_save_2 {
    ($v:ident) => {{
        sys_save_1!($v);
        $v.saved_args[1] = $v.pt_regs.rsi;
        $v.pt_regs.rsi = $v.args[1];
    }};
}

macro_rules! sys_restore_3 {
    ($v:ident) => {{
        sys_restore_2!($v);
        $v.pt_regs.rdx = $v.saved_args[2];
    }};
}

macro_rules! sys_save_3 {
    ($v:ident) => {{
        sys_save_2!($v);
        $v.saved_args[2] = $v.pt_regs.rdx;
        $v.pt_regs.rdx = $v.args[2];
    }};
}

macro_rules! sys_restore_4 {
    ($v:ident) => {{
        sys_restore_3!($v);
        $v.pt_regs.r10 = $v.saved_args[3];
    }};
}

macro_rules! sys_save_4 {
    ($v:ident) => {{
        sys_save_3!($v);
        $v.saved_args[3] = $v.pt_regs.r10;
        $v.pt_regs.r10 = $v.args[3];
    }};
}

macro_rules! sys_restore_5 {
    ($v:ident) => {{
        sys_restore_4!($v);
        $v.pt_regs.r8 = $v.saved_args[4];
    }};
}

macro_rules! sys_save_5 {
    ($v:ident) => {{
        sys_save_4!($v);
        $v.saved_args[4] = $v.pt_regs.r8;
        $v.pt_regs.r8 = $v.args[4];
    }};
}

macro_rules! sys_restore_6 {
    ($v:ident) => {{
        sys_restore_5!($v);
        $v.pt_regs.r9 = $v.saved_args[5];
    }};
}

macro_rules! sys_save_6 {
    ($v:ident) => {{
        sys_save_5!($v);
        $v.saved_args[5] = $v.pt_regs.r9;
        $v.pt_regs.r9 = $v.args[5];
    }};
}

pub struct SnpPunchthroughToken<'a> {
    punchthrough: SnpPunchthrough<'a>,
}

impl SnpPunchthroughToken<'_> {
    fn parse_alloc_result(order: u64, addr: u64) -> Result<u64, PunchthroughError<error::Errno>> {
        if addr == 0 {
            if order > SNP_VMPL_ALLOC_MAX_ORDER as u64 {
                Err(PunchthroughError::Failure(error::Errno::EINVAL))
            } else {
                Err(PunchthroughError::Failure(error::Errno::ENOMEM))
            }
        } else if addr % (PAGE_SIZE << order) != 0 || addr > PHYS_ADDR_MAX - (PAGE_SIZE << order) {
            // Address is not aligned or out of bounds
            Err(PunchthroughError::Failure(error::Errno::EINVAL))
        } else {
            Ok(addr)
        }
    }
}

impl<'a> PunchthroughToken for SnpPunchthroughToken<'a> {
    type Punchthrough = SnpPunchthrough<'a>;

    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as Punchthrough>::ReturnSuccess,
        PunchthroughError<<Self::Punchthrough as Punchthrough>::ReturnFailure>,
    > {
        let mut punchthrough = self.punchthrough;
        match punchthrough {
            SnpPunchthrough::Other(OtherPunchthrough::Syscall0(ref mut v)) => {
                sys_save_0!(v)
            }
            SnpPunchthrough::Other(OtherPunchthrough::Syscall1(ref mut v)) => {
                sys_save_1!(v)
            }
            SnpPunchthrough::Other(OtherPunchthrough::Syscall2(ref mut v)) => {
                sys_save_2!(v)
            }
            SnpPunchthrough::Other(OtherPunchthrough::Syscall3(ref mut v)) => {
                sys_save_3!(v)
            }
            SnpPunchthrough::Other(OtherPunchthrough::Syscall4(ref mut v)) => {
                sys_save_4!(v)
            }
            SnpPunchthrough::Other(OtherPunchthrough::Syscall5(ref mut v)) => {
                sys_save_5!(v)
            }
            SnpPunchthrough::Other(OtherPunchthrough::Syscall6(ref mut v)) => {
                sys_save_6!(v)
            }
            _ => {}
        }

        let mut req = SnpVmplRequestArgs::from(&punchthrough);
        <Self as HostPunchthroughToken<'a, SnpVmplRequestArgs>>::HyperCallInterface::request(
            &mut req,
        );
        let ret = req.ret as i64;

        match punchthrough {
            SnpPunchthrough::Alloc { order } => return Self::parse_alloc_result(order, ret as u64),
            SnpPunchthrough::Other(OtherPunchthrough::AllocFutexPage) => {
                return Self::parse_alloc_result(0, ret as u64)
            }
            SnpPunchthrough::Other(OtherPunchthrough::Syscall0(v)) => {
                sys_restore_0!(v)
            }
            SnpPunchthrough::Other(OtherPunchthrough::Syscall1(v)) => {
                sys_restore_1!(v)
            }
            SnpPunchthrough::Other(OtherPunchthrough::Syscall2(v)) => {
                sys_restore_2!(v)
            }
            SnpPunchthrough::Other(OtherPunchthrough::Syscall3(v)) => {
                sys_restore_3!(v)
            }
            SnpPunchthrough::Other(OtherPunchthrough::Syscall4(v)) => {
                sys_restore_4!(v)
            }
            SnpPunchthrough::Other(OtherPunchthrough::Syscall5(v)) => {
                sys_restore_5!(v)
            }
            SnpPunchthrough::Other(OtherPunchthrough::Syscall6(v)) => {
                sys_restore_6!(v)
            }
            _ => {}
        }

        // Common handling for all requests
        if ret < 0 {
            Err(PunchthroughError::Failure(error::Errno::from_raw(
                ret as i32,
            )))
        } else {
            Ok(ret as u64)
        }
    }
}

impl From<&SnpPunchthroughToken<'_>> for SnpVmplRequestArgs {
    fn from(value: &SnpPunchthroughToken<'_>) -> Self {
        SnpVmplRequestArgs::from(&value.punchthrough)
    }
}

impl<'a, InOut> HostPunchthroughToken<'a, InOut> for SnpPunchthroughToken<'a> {
    type HyperCallInterface = HyperVInterface;
}

pub struct SnpPunchthroughProvider;

impl<'a> HostPunchthroughProvider<'a, SnpVmplRequestArgs, OtherPunchthrough<'a>>
    for SnpPunchthroughProvider
{
    type Token = SnpPunchthroughToken<'a>;

    fn get_punchthrough_token_for(
        &mut self,
        punchthrough: SnpPunchthrough<'a>,
    ) -> Option<Self::Token> {
        Some(SnpPunchthroughToken { punchthrough })
    }
}

impl Default for SnpPunchthroughProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SnpPunchthroughProvider {
    pub const fn new() -> Self {
        Self
    }

    pub fn alloc_futex_page<'a>(&mut self) -> Option<SnpPunchthroughToken<'a>> {
        let req = SnpPunchthrough::Other(OtherPunchthrough::AllocFutexPage);
        self.get_punchthrough_token_for(req)
    }

    /// Call futex syscall
    ///
    /// uaddr and uaddr2 are pointers to the underlying integer obtained from
    /// e.g., [`core::sync::atomic::AtomicU32::as_ptr`].
    #[allow(clippy::too_many_arguments)]
    pub fn sys_futex<'a>(
        &mut self,
        pt_regs: &'a mut pt_regs,
        uaddr: Option<*mut u32>,
        futex_op: i32,
        val: u32,
        timeout: Option<*const Timespec>,
        uaddr2: Option<*mut u32>,
        val3: u32,
    ) -> Option<SnpPunchthroughToken<'a>> {
        sys_forward!(
            self,
            NR_SYSCALL_FUTEX,
            pt_regs,
            6,
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
        )
    }

    pub fn sys_kill<'a>(
        &mut self,
        pt_regs: &'a mut pt_regs,
        pid: i32,
        sig: i32,
    ) -> Option<SnpPunchthroughToken<'a>> {
        sys_forward!(self, NR_SYSCALL_KILL, pt_regs, 2, pid as _, sig as _)
    }

    #[cfg(debug_assertions)]
    pub fn dump_stack<'a>(&mut self, rsp: u64) -> Option<SnpPunchthroughToken<'a>> {
        self.get_punchthrough_token_for(SnpPunchthrough::Other(OtherPunchthrough::DumpStack {
            rsp,
            len: 512,
        }))
    }

    #[cfg(debug_assertions)]
    pub fn dump_pt_regs<'a>(&mut self, regs: &'a pt_regs) -> Option<SnpPunchthroughToken<'a>> {
        self.get_punchthrough_token_for(SnpPunchthrough::Other(OtherPunchthrough::DumpRegs(regs)))
    }
}
