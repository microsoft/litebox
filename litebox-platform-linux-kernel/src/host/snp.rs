use super::{hypercall::HyperVInterface, HostInterface, HostRequest, HyperCallArgs};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

const MAX_ARGS_SIZE: usize = 6;
type ArgsArray = [u64; MAX_ARGS_SIZE];

impl SnpVmplRequestArgs {
    #[inline]
    pub fn new_request(code: u32, size: u32, args: ArgsArray) -> Self {
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

impl<'a> From<HostRequest<'a, OtherHostRequest>> for SnpVmplRequestArgs {
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
                    [SNP_VMPL_PRINT_PT_REGS as u64, regs, 0, 0, 0, 0],
                ),
            },
        }
    }
}

const PAGE_SIZE: u64 = 4096;
/// Max physical address
const PHYS_ADDR_MAX: u64 = 0x10_0000_0000u64; // 64GB

const EAGAIN: i64 = 11;
const EINTR: i64 = 4;

impl HyperCallArgs<'_, OtherHostRequest> for SnpVmplRequestArgs {
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

enum OtherHostRequest {
    AllocFutexPage,

    /// Special hypercall for debugging purposes
    #[cfg(debug_assertions)]
    DumpStack {
        rsp: u64,
        len: u64,
    },
    #[cfg(debug_assertions)]
    DumpRegs(u64),
}

pub struct SnpInterface;

impl HostInterface<'_, SnpVmplRequestArgs, OtherHostRequest> for SnpInterface {
    type HyperCallInterface = HyperVInterface;

    fn post_check(req: &SnpVmplRequestArgs, _res: ()) {
        if req.status != SNP_VMPL_REQ_SUCCESS {
            let status = req.status;
            panic!("Request failed with status: {}", status);
        }
    }
}

impl SnpInterface {
    pub fn alloc_futex_page() {
        Self::call(&mut HostRequest::Other(OtherHostRequest::AllocFutexPage).into())
    }

    pub fn dump_stack(rsp: u64) {
        Self::call(&mut HostRequest::Other(OtherHostRequest::DumpStack { rsp, len: 512 }).into())
    }

    pub fn dump_pt_regs(regs: u64) {
        Self::call(&mut HostRequest::Other(OtherHostRequest::DumpRegs(regs)).into())
    }
}
