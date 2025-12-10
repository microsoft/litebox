use litebox_common_linux::errno::Errno;
use litebox_common_optee::{
    OpteeMsgArg, OpteeSecureWorldCapabilities, OpteeSmcArgs, OpteeSmcFunction, OpteeSmcResult,
    OpteeSmcReturn,
};

// TODO: Replace these with version and build info
const OPTEE_MSG_REVISION_MAJOR: usize = 2;
const OPTEE_MSG_REVISION_MINOR: usize = 0;
const OPTEE_MSG_BUILD_ID: usize = 0;

// TODO: Replace this with an actual UID
const OPTEE_MSG_UID_0: u32 = 0x384f_b3e0;
const OPTEE_MSG_UID_1: u32 = 0xe7f8_11e3;
const OPTEE_MSG_UID_2: u32 = 0xaf63_0002;
const OPTEE_MSG_UID_3: u32 = 0xa5d5_c51b;

// We do not support notification for now
const MAX_NOTIF_VALUE: usize = 0;
const NUM_RPC_PARMS: usize = 4;

pub fn handle_optee_smc_args(smc: &mut OpteeSmcArgs) -> Result<OpteeSmcResult, Errno> {
    let func_id = smc.func_id()?;

    match func_id {
        OpteeSmcFunction::CallWithArg
        | OpteeSmcFunction::CallWithRpcArg
        | OpteeSmcFunction::CallWithRegdArg => {
            // TODO: handle the contained `OpteeMsgArg` and return appropriate result
            Ok(OpteeSmcResult::new(OpteeSmcReturn::Ok))
        }
        OpteeSmcFunction::ExchangeCapabilities => {
            // TODO: update the below when we support more features
            let default_cap = OpteeSecureWorldCapabilities::DYNAMIC_SHM
                | OpteeSecureWorldCapabilities::MEMREF_NULL
                | OpteeSecureWorldCapabilities::RPC_ARG;
            Ok(OpteeSmcResult::new_exchange_capabilities(
                OpteeSmcReturn::Ok,
                default_cap,
                MAX_NOTIF_VALUE,
                NUM_RPC_PARMS,
            ))
        }
        OpteeSmcFunction::DisableShmCache => {
            // We do not support this feature
            Ok(OpteeSmcResult::new_disable_shm_cache(
                OpteeSmcReturn::ENotAvail,
                0,
                0,
            ))
        }
        OpteeSmcFunction::CallsUid => Ok(OpteeSmcResult::new_uuid(&[
            OPTEE_MSG_UID_0,
            OPTEE_MSG_UID_1,
            OPTEE_MSG_UID_2,
            OPTEE_MSG_UID_3,
        ])),
        OpteeSmcFunction::GetOsRevision => Ok(OpteeSmcResult::new_os_revision(
            OPTEE_MSG_REVISION_MAJOR,
            OPTEE_MSG_REVISION_MINOR,
            OPTEE_MSG_BUILD_ID,
        )),
        OpteeSmcFunction::CallsRevision => Ok(OpteeSmcResult::new_revision(
            OPTEE_MSG_REVISION_MAJOR,
            OPTEE_MSG_REVISION_MINOR,
        )),
        _ => Err(Errno::EINVAL),
    }
}

pub fn halde_optee_msg_arg(_msg: &OpteeMsgArg) {}
