//! VSM OP-TEE functions

// TODO: relocate this file to `litebox_runner_lvbs`

use crate::debug_serial_println;

use crate::user_context::UserSpaceManagement;
use litebox_common_linux::errno::Errno;
use num_enum::TryFromPrimitive;

use litebox_common_optee::{TeeLogin, TeeUuid, UteeEntryFunc, UteeParamOwned, UteeParams};

const OPTEE_MSG_CMD_OPEN_SESSION: u32 = 0;
const OPTEE_MSG_CMD_INVOKE_COMMAND: u32 = 1;
const OPTEE_MSG_CMD_CLOSE_SESSION: u32 = 2;
const OPTEE_MSG_CMD_CANCEL: u32 = 3;
const OPTEE_MSG_CMD_REGISTER_SHM: u32 = 4;
const OPTEE_MSG_CMD_UNREGISTER_SHM: u32 = 5;
const OPTEE_MSG_CMD_DO_BOTTOM_HALF: u32 = 6;
const OPTEE_MSG_CMD_STOP_ASYNC_NOTIF: u32 = 7;

#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum OpteeMessageCommand {
    OpenSession = OPTEE_MSG_CMD_OPEN_SESSION,
    InvokeCommand = OPTEE_MSG_CMD_INVOKE_COMMAND,
    CloseSession = OPTEE_MSG_CMD_CLOSE_SESSION,
    Cancel = OPTEE_MSG_CMD_CANCEL,
    RegisterShm = OPTEE_MSG_CMD_REGISTER_SHM,
    UnregisterShm = OPTEE_MSG_CMD_UNREGISTER_SHM,
    DoBottomHalf = OPTEE_MSG_CMD_DO_BOTTOM_HALF,
    StopAsyncNotif = OPTEE_MSG_CMD_STOP_ASYNC_NOTIF,
    Unknown = 0xffff_ffff,
}

/// Temporary reference memory parameter
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
#[expect(dead_code)]
pub fn mshv_vsm_optee_open_session(
    _ta_uuid: TeeUuid,
    _client_uuid: TeeUuid,
    _login_class: TeeLogin,
) -> Result<i64, Errno> {
    // TODO: check `ta_uuid` and `client_uuid` to determine whether it should create a new session or reuse an existing one.
    let session_id = crate::platform_low().create_userspace()?;
    debug_serial_println!("VSM: Created userspace with ID {:#x}", session_id);

    // TODO: use `ta_uuid` to determine the TA binary to load (through tee_supplicant)

    // crate::platform_low().load_program(session_id, &[0; 1])?;
    debug_serial_println!("VSM: load a program/function into userspace");

    Ok(i64::try_from(session_id).unwrap_or(-1))
}

// A placeholder for testing purposes. This isn't a real function signature.
#[expect(dead_code)]
pub fn mshv_vsm_optee_invoke_command(
    session_id: usize,
    _function_id: u32,
    _cmd_id: u32,
    _params: Option<UteeParams>,
) -> Result<i64, Errno> {
    if crate::platform_low().check_userspace(session_id) {
        crate::platform_low().enter_userspace(session_id, None);
    } else {
        Err(Errno::ENOENT)
    }
}

// A placeholder for testing purposes. This isn't a real function signature.
#[expect(dead_code)]
pub fn mshv_vsm_optee_close_session(session_id: usize) -> Result<i64, Errno> {
    if crate::platform_low().check_userspace(session_id) {
        crate::platform_low().delete_userspace(session_id)?;
        debug_serial_println!("VSM: Deleted userspace with ID {}", session_id);
        Ok(0)
    } else {
        Err(Errno::ENOENT)
    }
}

#[allow(clippy::unnecessary_wraps)]
fn optee_test() -> Result<i64, Errno> {
    // open session for other example TAs
    let params = [
        UteeParamOwned::None,
        UteeParamOwned::None,
        UteeParamOwned::None,
        UteeParamOwned::None,
    ];
    crate::optee_call(1, UteeEntryFunc::OpenSession, 0, &params);

    // open session for the KMPP TA
    // let params = [
    //     UteeParamOwned::ValueInput {
    //         value_a: 1, // session ID
    //         value_b: 0,
    //     },
    //     UteeParamOwned::ValueOutput { out_address: 0 },
    //     UteeParamOwned::None,
    //     UteeParamOwned::None,
    // ];
    // crate::optee_call(1, UteeEntryFunc::OpenSession, 0, &params);

    // commands for hello world TA
    // let params = [
    //     UteeParamOwned::ValueInout {
    //         value_a: 100,
    //         value_b: 0,
    //         out_address: 0,
    //     },
    //     UteeParamOwned::None,
    //     UteeParamOwned::None,
    //     UteeParamOwned::None,
    // ];
    // crate::optee_call(1, UteeEntryFunc::InvokeCommand, 0, &params);

    // let params = [
    //     UteeParamOwned::ValueInout {
    //         value_a: 200,
    //         value_b: 0,
    //         out_address: 0,
    //     },
    //     UteeParamOwned::None,
    //     UteeParamOwned::None,
    //     UteeParamOwned::None,
    // ];
    // crate::optee_call(1, UteeEntryFunc::InvokeCommand, 1, &params);

    // command for random TA
    // let params = [
    //     UteeParamOwned::MemrefOutput { buffer_size: 64, out_address: 0 },
    //     UteeParamOwned::None,
    //     UteeParamOwned::None,
    //     UteeParamOwned::None,
    // ];
    // crate::optee_call(1, UteeEntryFunc::InvokeCommand, 0, &params);

    let params = [
        UteeParamOwned::None,
        UteeParamOwned::None,
        UteeParamOwned::None,
        UteeParamOwned::None,
    ];
    crate::optee_call(1, UteeEntryFunc::CloseSession, 0, &params);

    // switch back to VTL0
    crate::optee_call_done(1);

    Ok(0)
}

/// OP-TEE message command dispatcher
#[allow(clippy::unnecessary_wraps)]
pub fn optee_msg_cmd_dispatch(_msg_cmd_id: OpteeMessageCommand, _params: &[u64]) -> i64 {
    // TODO: params[0] will have a VTL0 physical address containing `OpteeMsgArg`. Copy and parse it.

    // for testing only
    let _ = optee_test();
    0

    /*
    let result = match msg_cmd_id {
        OpteeMessageCommand::OpenSession => {
            // OpteeMsgArg.params[0].a-b: TA UUID
            // OpteeMsgArg.params[1].a-b: client UUID
            // OpteeMsgArg.params[1].c: login_class
            mshv_vsm_optee_open_session(TeeUuid::default(), TeeUuid::default(), TeeLogin::User)
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
    */
}
