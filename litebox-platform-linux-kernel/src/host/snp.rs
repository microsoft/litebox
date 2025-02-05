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

pub struct SnpInterface;

impl HostInterface<SnpVmplRequestArgs> for SnpInterface {
    type HyperCallInterface = HyperVInterface;

    fn get_request(request: HostRequest) -> SnpVmplRequestArgs {
        match request {
            HostRequest::Exit => SnpVmplRequestArgs::new_exit_request(),
            HostRequest::Terminate {
                reason_set,
                reason_code,
            } => SnpVmplRequestArgs::new_request(
                SNP_VMPL_TERMINATE_REQ,
                2,
                [reason_set, reason_code, 0, 0, 0, 0],
            ),
        }
    }
}
