//! VSM OP-TEE functions

use crate::mshv::VsmFunction;
use litebox_common_linux::errno::Errno;

pub fn vsm_optee_dispatch(func_id: VsmFunction, _params: &[u64]) -> i64 {
    let result = match func_id {
        VsmFunction::OpteeOpenSession
        | VsmFunction::OpteeInvokeCommand
        | VsmFunction::OpteeCloseSession
        | VsmFunction::OpteeCancel
        | VsmFunction::OpteeRegisterShm
        | VsmFunction::OpteeUnregisterShm => {
            todo!("OP-TEE function dispatcher")
        }
        _ => Err(Errno::EINVAL),
    };
    match result {
        Ok(value) => value,
        Err(errno) => errno.as_neg().into(),
    }
}
