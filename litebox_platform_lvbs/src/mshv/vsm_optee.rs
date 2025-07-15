//! VSM OP-TEE functions

use crate::debug_serial_println;

use crate::user_context::UserSpaceManagement;
use litebox_common_linux::errno::Errno;
use num_enum::TryFromPrimitive;

const UUID_LEN: usize = 16;

const OPTE_MSG_CMD_OPEN_SESSION: u32 = 0;
const OPTE_MSG_CMD_INVOKE_COMMAND: u32 = 1;
const OPTE_MSG_CMD_CLOSE_SESSION: u32 = 2;
const OPTE_MSG_CMD_CANCEL: u32 = 3;
const OPTE_MSG_CMD_REGISTER_SHM: u32 = 4;
const OPTE_MSG_CMD_UNREGISTER_SHM: u32 = 5;
const OPTE_MSG_CMD_DO_BOTTOM_HALF: u32 = 6;
const OPTE_MSG_CMD_STOP_ASYNC_NOTIF: u32 = 7;

#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum OpteeMessageCommand {
    OpenSession = OPTE_MSG_CMD_OPEN_SESSION,
    InvokeCommand = OPTE_MSG_CMD_INVOKE_COMMAND,
    CloseSession = OPTE_MSG_CMD_CLOSE_SESSION,
    Cancel = OPTE_MSG_CMD_CANCEL,
    RegisterShm = OPTE_MSG_CMD_REGISTER_SHM,
    UnregisterShm = OPTE_MSG_CMD_UNREGISTER_SHM,
    DoBottomHalf = OPTE_MSG_CMD_DO_BOTTOM_HALF,
    StopAsyncNotif = OPTE_MSG_CMD_STOP_ASYNC_NOTIF,
    Unknown = 0xffff_ffff,
}

/// buf_ptr: Address of the buffer
/// size: Size of the buffer
/// shm_ref: Temporary shared memory reference, pointer to a struct tee_shm
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct OpteeMsgParamTmem {
    buf_ptr: u64,
    size: u64,
    shm_ref: u64,
}

/// Registered memory reference parameter
/// offs: Offset into shared memory reference
/// size: Size of the buffer
/// shm_ref: Shared memory reference, pointer to a struct tee_shm
#[derive(Clone, Copy)]
#[repr(C)]
struct OpteeMsgParamRmem {
    offs: u64,
    size: u64,
    shm_ref: u64,
}

/// Opaque value parameter
/// Value parameters are passed unchecked between normal and secure world.
#[derive(Clone, Copy)]
#[repr(C)]
struct OpteeMsgParamValue {
    a: u64,
    b: u64,
    c: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
union OpteeMsgParamUnion {
    tmem: OpteeMsgParamTmem,
    rmem: OpteeMsgParamRmem,
    value: OpteeMsgParamValue,
    octets: [u8; 24],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct OpteeMsgParam {
    attr: u64, // TODO: modular_bitfield
    u: OpteeMsgParamUnion,
}

#[expect(dead_code)]
#[derive(Clone, Copy)]
#[repr(C)]
struct OpteeMsgArg {
    cmd: u32,
    func: u32,
    session: u32,
    cancel_id: u32,
    pad: u32,
    ret: u32,
    ret_origin: u32,
    num_params: u32,
    params: [OpteeMsgParam; 0],
}

// A placeholder for testing purposes. This isn't a real function signature.
pub fn mshv_vsm_optee_open_session(
    _ta_uuid: &[u8],
    _client_uuid: &[u8],
    _login_class: u32,
) -> Result<i64, Errno> {
    // TODO: use `ta_uuid` and `client_uuid` to determine whether it should create a new session or reuse an existing one.
    let session_id = crate::platform_low().create_userspace()?;
    debug_serial_println!("VSM: Created userspace with ID {:#x}", session_id);

    // TODO: use `ta_uuid` to determine the TA binary to load

    crate::platform_low().load_program(session_id, &[0; 1])?;
    debug_serial_println!("VSM: load a program/function into userspace");

    Ok(session_id.into())
}

// A placeholder for testing purposes. This isn't a real function signature.
#[allow(unreachable_code)]
pub fn mshv_vsm_optee_invoke_command(
    session_id: u32,
    _function_id: u32,
    _cmd_id: u32,
    _params: Option<&[u64]>,
) -> Result<i64, Errno> {
    if crate::platform_low().check_userspace(session_id) {
        crate::platform_low().enter_userspace(session_id, None);
        unreachable!("enter_userspace should never return");
    } else {
        Err(Errno::ENOENT)
    }
}

// A placeholder for testing purposes. This isn't a real function signature.
pub fn mshv_vsm_optee_close_session(session_id: u32) -> Result<i64, Errno> {
    if crate::platform_low().check_userspace(session_id) {
        crate::platform_low().delete_userspace(session_id)?;
        debug_serial_println!("VSM: Deleted userspace with ID {}", session_id);
        Ok(0)
    } else {
        Err(Errno::ENOENT)
    }
}

pub fn optee_dispatch(msg_cmd_id: OpteeMessageCommand, _params: &[u64]) -> i64 {
    // TODO: params[0] will have a VTL0 physical address containing `OpteeMsgArg`. Copy and parse it.

    let result = match msg_cmd_id {
        OpteeMessageCommand::OpenSession => {
            // OpteeMsgArg.params[0].a-b: TA UUID
            // OpteeMsgArg.params[1].a-b: client UUID
            // OpteeMsgArg.params[1].c: login_class
            mshv_vsm_optee_open_session(&[1u8; UUID_LEN], &[2u8; UUID_LEN], 3)
        }
        #[allow(clippy::cast_possible_wrap)]
        OpteeMessageCommand::InvokeCommand => {
            // OpteeMsgArg.session: session ID
            // OpteeMsgArg.func: function ID
            // OpteeMsgArg.cmd: command ID
            mshv_vsm_optee_invoke_command(1, 2, 3, None)
        }
        #[allow(clippy::cast_possible_wrap)]
        OpteeMessageCommand::CloseSession => {
            // OpteeMsgArg.session: session ID
            mshv_vsm_optee_close_session(1)
        }
        _ => todo!("OP-TEE function ID = {:#x}", msg_cmd_id as u32),
    };
    match result {
        Ok(value) => value,
        Err(errno) => errno.as_neg().into(),
    }
}
