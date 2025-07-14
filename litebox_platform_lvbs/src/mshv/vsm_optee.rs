//! VSM OP-TEE functions

use crate::{debug_serial_println, serial_println};

use crate::{mshv::VsmFunction, user_context::UserSpaceManagement};
use litebox_common_linux::errno::Errno;

// TODO: OP-TEE uses `OpteeMsgArg` (stored in a page) to exchange arguments
// between normal and secure world.

// A placeholder for testing purposes. This isn't a real function signature.
pub fn mshv_vsm_optee_open_session(function_id: u64) -> Result<i64, Errno> {
    if let Ok(session_id) = crate::platform_low().create_userspace() {
        debug_serial_println!("VSM: Created userspace with ID {:#x}", session_id);

        // TODO: use `function_id` to determine which TA binary to load

        let _ = crate::platform_low().load_program(session_id, &[0; 1]);
        debug_serial_println!(
            "VSM: load a program/function {:#x} into userspace",
            function_id
        );

        Ok(session_id)
    } else {
        serial_println!("VSM: Failed to create userspace");
        Err(Errno::EINVAL)
    }
}

// A placeholder for testing purposes. This isn't a real function signature.
#[allow(unreachable_code)]
pub fn mshv_vsm_optee_invoke_command(session_id: i64, _cmd_id: u64) -> Result<i64, Errno> {
    if crate::platform_low().check_userspace(session_id) {
        crate::platform_low().enter_userspace(session_id, None);
        unreachable!("enter_userspace should never return");
    } else {
        Err(Errno::ENOENT)
    }
}

// A placeholder for testing purposes. This isn't a real function signature.
pub fn mshv_vsm_optee_close_session(session_id: i64) -> Result<i64, Errno> {
    if crate::platform_low().check_userspace(session_id) {
        let _ = crate::platform_low().delete_userspace(session_id);
        debug_serial_println!("VSM: Deleted userspace with ID {}", session_id);
        Ok(0)
    } else {
        Err(Errno::EINVAL)
    }
}

pub fn vsm_optee_dispatch(func_id: VsmFunction, params: &[u64]) -> i64 {
    let result = match func_id {
        VsmFunction::OpteeOpenSession => mshv_vsm_optee_open_session(params[0]),
        #[allow(clippy::cast_possible_wrap)]
        VsmFunction::OpteeInvokeCommand => {
            mshv_vsm_optee_invoke_command(params[0] as i64, params[1])
        }
        #[allow(clippy::cast_possible_wrap)]
        VsmFunction::OpteeCloseSession => mshv_vsm_optee_close_session(params[0] as i64),
        VsmFunction::OpteeCancel
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
