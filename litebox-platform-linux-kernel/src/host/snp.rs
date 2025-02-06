use super::{hypercall::HyperVInterface, HostInterface, HostRequest};

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

impl HostInterface<SnpVmplRequestArgs, OtherHostRequest> for SnpInterface {
    type HyperCallInterface = HyperVInterface;

    fn get_request(request: HostRequest<OtherHostRequest>) -> SnpVmplRequestArgs {
        match request {
            HostRequest::Alloc { order } => {
                SnpVmplRequestArgs::new_request(SNP_VMPL_ALLOC_REQ, 1, [order, 0, 0, 0, 0, 0])
            }
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

impl SnpInterface {
    pub fn alloc_futex_page() {
        Self::call(HostRequest::Other(OtherHostRequest::AllocFutexPage))
    }

    pub fn dump_stack(rsp: u64) {
        Self::call(HostRequest::Other(OtherHostRequest::DumpStack {
            rsp,
            len: 512,
        }))
    }

    pub fn dump_pt_regs(regs: u64) {
        Self::call(HostRequest::Other(OtherHostRequest::DumpRegs(regs)))
    }
}
