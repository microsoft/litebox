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
#[allow(clippy::too_many_lines)]
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

    // commands for KMPP TA
    // let params = [
    //     UteeParamOwned::MemrefInput {
    //         data: alloc::boxed::Box::new([
    //             3, 0, 0, 0, 3, 0, 0, 0, 74, 136, 36, 205, 228, 97, 78, 179, 166, 190, 22, 5, 192,
    //             70, 157, 182, 0, 8, 0, 0, 3, 0, 0, 0,
    //         ]),
    //     },
    //     UteeParamOwned::MemrefOutput {
    //         buffer_size: 1024,
    //         out_address: 0,
    //     },
    //     UteeParamOwned::None,
    //     UteeParamOwned::None,
    // ];
    // crate::optee_call(1, UteeEntryFunc::InvokeCommand, 4, &params);

    // let params = [
    //     UteeParamOwned::MemrefInput {
    //         data: alloc::boxed::Box::new([
    //             3, 0, 0, 0, 0, 0, 0, 0, 74, 136, 36, 205, 228, 97, 78, 179, 166, 190, 22, 5, 192,
    //             70, 157, 182, 48, 46, 87, 86, 108, 87, 72, 122, 100, 99, 104, 55, 56, 119, 115,
    //             100, 120, 87, 77, 75, 55, 87, 112, 105, 47, 111, 85, 87, 107, 61, 0, 0, 3, 0, 0, 0,
    //             8, 0, 0, 0, 16, 0, 0, 0, 32, 0, 0, 0, 48, 2, 0, 0, 224, 102, 169, 73, 92, 86, 192,
    //             132, 90, 179, 84, 248, 147, 36, 33, 230, 63, 67, 107, 16, 239, 222, 196, 187, 201,
    //             117, 215, 168, 21, 146, 27, 49, 46, 77, 137, 166, 129, 53, 101, 78, 74, 23, 220,
    //             190, 72, 91, 226, 165, 183, 180, 253, 131, 200, 224, 67, 160, 43, 246, 59, 38, 28,
    //             66, 33, 244, 42, 224, 189, 171, 120, 140, 77, 206, 66, 46, 227, 126, 43, 99, 14,
    //             179, 205, 229, 198, 3, 35, 53, 61, 122, 107, 83, 112, 99, 47, 58, 86, 39, 62, 188,
    //             127, 125, 54, 161, 103, 226, 33, 124, 113, 254, 228, 96, 11, 216, 10, 44, 31, 74,
    //             154, 232, 133, 27, 203, 200, 209, 53, 190, 162, 220, 136, 128, 60, 71, 1, 205, 92,
    //             80, 150, 115, 118, 128, 150, 88, 33, 199, 5, 218, 159, 94, 43, 213, 87, 29, 3, 196,
    //             29, 190, 219, 80, 112, 67, 163, 170, 8, 237, 48, 101, 6, 76, 103, 208, 19, 253,
    //             155, 91, 29, 217, 249, 100, 82, 24, 101, 47, 101, 193, 243, 220, 182, 24, 123, 171,
    //             38, 168, 254, 70, 174, 139, 10, 49, 35, 229, 138, 146, 109, 60, 145, 73, 228, 117,
    //             254, 72, 177, 211, 111, 59, 172, 197, 201, 179, 81, 9, 147, 220, 174, 175, 112,
    //             247, 53, 67, 154, 79, 62, 46, 10, 189, 77, 29, 244, 6, 98, 223, 209, 205, 141, 84,
    //             217, 32, 49, 22, 75, 166, 16, 190, 236, 229, 152, 129, 10, 78, 128, 71, 229, 238,
    //             168, 39, 218, 153, 116, 179, 172, 111, 105, 25, 232, 28, 252, 161, 40, 252, 132, 9,
    //             40, 8, 240, 14, 183, 129, 73, 69, 136, 253, 82, 163, 193, 176, 208, 97, 236, 74,
    //             57, 190, 75, 203, 75, 163, 209, 198, 173, 155, 24, 74, 88, 102, 43, 133, 242, 110,
    //             169, 3, 90, 79, 123, 194, 94, 17, 220, 146, 79, 140, 28, 164, 18, 63, 126, 89, 165,
    //             174, 219, 210, 58, 206, 182, 164, 206, 126, 179, 10, 168, 77, 68, 69, 191, 43, 153,
    //             87, 186, 48, 252, 240, 37, 29, 179, 35, 245, 144, 112, 228, 97, 161, 89, 187, 219,
    //             170, 128, 185, 125, 8, 114, 237, 150, 66, 221, 11, 72, 159, 149, 189, 211, 93, 252,
    //             3, 107, 251, 171, 211, 212, 15, 184, 236, 34, 46, 13, 228, 208, 62, 54, 122, 102,
    //             5, 199, 208, 32, 179, 234, 134, 132, 97, 18, 129, 192, 229, 210, 129, 187, 204,
    //             248, 179, 130, 99, 78, 114, 69, 133, 126, 175, 48, 64, 92, 253, 36, 4, 209, 249,
    //             100, 177, 255, 64, 7, 174, 65, 21, 0, 156, 26, 105, 107, 69, 202, 24, 57, 139, 180,
    //             129, 41, 203, 9, 42, 167, 114, 136, 115, 164, 159, 158, 108, 53, 95, 130, 139, 242,
    //             124, 74, 7, 243, 26, 171, 57, 108, 175, 161, 212, 247, 113, 108, 176, 142, 151,
    //             167, 141, 203, 104, 246, 245, 213, 76, 7, 103, 117, 106, 124, 128, 38, 87, 21, 41,
    //             87, 238, 228, 183, 72, 225, 217, 205, 81, 219, 227, 225, 188, 225, 110, 99, 161,
    //             69, 221, 81, 124, 144, 170, 215, 202, 171, 215, 252, 114, 106, 71, 224, 6, 243, 82,
    //             190, 141, 253, 90, 204, 80, 132, 254, 78, 107, 198, 192, 84, 142, 150, 194, 136,
    //             152, 70, 111, 224, 74, 9, 209, 27, 206, 188, 42, 60, 221, 116, 10, 142, 212, 50,
    //             114, 165, 82, 75, 88, 184, 199, 136, 189, 241, 183, 134, 100, 142, 38, 172, 42, 71,
    //             66, 178, 151, 194, 118, 12, 232, 96, 24, 126, 144, 135, 5, 156, 128,
    //         ]),
    //     },
    //     UteeParamOwned::MemrefOutput {
    //         buffer_size: 1024,
    //         out_address: 0,
    //     },
    //     UteeParamOwned::None,
    //     UteeParamOwned::None,
    // ];
    // crate::optee_call(1, UteeEntryFunc::InvokeCommand, 0, &params);

    // let params = [
    //     UteeParamOwned::MemrefInput {
    //         data: alloc::boxed::Box::new([
    //             3, 0, 0, 0, 3, 0, 0, 0, 74, 136, 36, 205, 228, 97, 78, 179, 166, 190, 22, 5, 192,
    //             70, 157, 182, 0, 0, 0, 0, 246, 250, 127, 106, 2, 0, 0, 0, 6, 0, 0, 0, 0, 3, 0, 0,
    //             40, 0, 0, 0, 0, 0, 0, 0, 160, 2, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    //         ]),
    //     },
    //     UteeParamOwned::MemrefOutput {
    //         buffer_size: 1024,
    //         out_address: 0,
    //     },
    //     UteeParamOwned::None,
    //     UteeParamOwned::None,
    // ];
    // crate::optee_call(1, UteeEntryFunc::InvokeCommand, 3, &params);

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

/// OP-TEE SMC call arguments. OP-TEE assumes that the underlying architecture is Arm with TrustZone.
/// This is why it uses SMC calling convention (SMCCC). We need to translate this into VTL switch convention.
#[derive(Clone, Copy)]
#[repr(C)]
struct OpteeSmcArgs {
    args: [usize; NUM_OPTEE_SMC_ARGS],
}
const NUM_OPTEE_SMC_ARGS: usize = 9;

impl OpteeSmcArgs {
    #[expect(dead_code)]
    pub fn arg_index(&self, index: usize) -> usize {
        match index {
            0..8 => self.args[index],
            _ => panic!("BUG: Invalid OPTEE SMC argument index: {}", index),
        }
    }

    pub fn func_id(&self) -> Result<OpteeSmcFunction, Errno> {
        OpteeSmcFunction::try_from(self.args[0] & 0xffff).map_err(|_| Errno::EINVAL)
    }

    pub fn set_result(&mut self, result: &OpteeSmcResult) {
        match result {
            OpteeSmcResult::Generic { status } => {
                self.args[0] = *status as usize;
            }
            OpteeSmcResult::ExchangeCapabilities {
                status,
                capabilities,
                max_notif_value,
                data,
            } => {
                self.args[0] = *status as usize;
                self.args[1] = *capabilities;
                self.args[2] = *max_notif_value;
                self.args[3] = *data;
            }
            OpteeSmcResult::Uuid { data } => {
                self.args[0] = usize::try_from(data[0]).unwrap();
                self.args[1] = usize::try_from(data[1]).unwrap();
                self.args[2] = usize::try_from(data[2]).unwrap();
                self.args[3] = usize::try_from(data[3]).unwrap();
            }
            OpteeSmcResult::Revision { major, minor } => {
                self.args[0] = *major;
                self.args[1] = *minor;
            }
            OpteeSmcResult::OsRevision {
                major,
                minor,
                build_id,
            } => {
                self.args[0] = *major;
                self.args[1] = *minor;
                self.args[2] = *build_id;
            }
            OpteeSmcResult::DisableShmCache {
                status,
                shm_upper32,
                shm_lower32,
            } => {
                self.args[0] = *status as usize;
                self.args[1] = *shm_upper32;
                self.args[2] = *shm_lower32;
            }
        }
    }
}

const OPTEE_SMC_FUNCID_GET_OS_REVISION: usize = 0x1;
const OPTEE_SMC_FUNCID_CALL_WITH_ARG: usize = 0x4;
const OPTEE_SMC_FUNCID_EXCHANGE_CAPABILITIES: usize = 0x9;
const OPTEE_SMC_FUNCID_DISABLE_SHM_CACHE: usize = 0xa;

const OPTEE_SMC_FUNCID_CALLS_UID: usize = 0xff01;
const OPTEE_SMC_FUNCID_CALLS_REVISION: usize = 0xff03;

#[derive(PartialEq, TryFromPrimitive)]
#[repr(usize)]
pub enum OpteeSmcFunction {
    GetOsRevision = OPTEE_SMC_FUNCID_GET_OS_REVISION,
    CallWithArg = OPTEE_SMC_FUNCID_CALL_WITH_ARG,
    ExchangeCapabilities = OPTEE_SMC_FUNCID_EXCHANGE_CAPABILITIES,
    DisableShmCache = OPTEE_SMC_FUNCID_DISABLE_SHM_CACHE,
    CallsUid = OPTEE_SMC_FUNCID_CALLS_UID,
    CallsRevision = OPTEE_SMC_FUNCID_CALLS_REVISION,
}

pub enum OpteeSmcResult {
    Generic {
        status: OpteeSmcReturn,
    },
    ExchangeCapabilities {
        status: OpteeSmcReturn,
        capabilities: usize,
        max_notif_value: usize,
        data: usize,
    },
    Uuid {
        data: [u32; 4],
    },
    Revision {
        major: usize,
        minor: usize,
    },
    OsRevision {
        major: usize,
        minor: usize,
        build_id: usize,
    },
    DisableShmCache {
        status: OpteeSmcReturn,
        shm_upper32: usize,
        shm_lower32: usize,
    },
}

bitflags::bitflags! {
    #[derive(PartialEq, Clone, Copy)]
    pub struct OpteeSecureWorldCapabilities: usize {
        const HAVE_RESERVED_SHM = 1 << 0;
        const UNREGISTERED_SHM = 1 << 1;
        const DYNAMIC_SHM = 1 << 2;
        const MEMREF_NULL = 1 << 4;
        const RPC_ARG = 1 << 6;
    }
}

const OPTEE_MSG_REVISION_MAJOR: usize = 2;
const OPTEE_MSG_REVISION_MINOR: usize = 0;

const NUM_RPC_PARAMS: usize = 4;

const OPTEE_MSG_UID_0: u32 = 0x384f_b3e0;
const OPTEE_MSG_UID_1: u32 = 0xe7f8_11e3;
const OPTEE_MSG_UID_2: u32 = 0xaf63_0002;
const OPTEE_MSG_UID_3: u32 = 0xa5d5_c51b;

const OPTEE_SMC_RETURN_OK: usize = 0x0;
const OPTEE_SMC_RETURN_ETHREAD_LIMIT: usize = 0x1;
const OPTEE_SMC_RETURN_EBUSY: usize = 0x2;
const OPTEE_SMC_RETURN_ERESUME: usize = 0x3;
const OPTEE_SMC_RETURN_EBADADDR: usize = 0x4;
const OPTEE_SMC_RETURN_EBADCMD: usize = 0x5;
const OPTEE_SMC_RETURN_ENOMEM: usize = 0x6;
const OPTEE_SMC_RETURN_ENOTAVAIL: usize = 0x7;
// OPTEE_SMC_RETURN_IS_RPC()

#[derive(Copy, Clone, PartialEq, TryFromPrimitive)]
#[repr(usize)]
pub enum OpteeSmcReturn {
    Ok = OPTEE_SMC_RETURN_OK,
    EThreadLimit = OPTEE_SMC_RETURN_ETHREAD_LIMIT,
    EBusy = OPTEE_SMC_RETURN_EBUSY,
    EResume = OPTEE_SMC_RETURN_ERESUME,
    EBadAddr = OPTEE_SMC_RETURN_EBADADDR,
    EBadCmd = OPTEE_SMC_RETURN_EBADCMD,
    ENomem = OPTEE_SMC_RETURN_ENOMEM,
    ENotAvail = OPTEE_SMC_RETURN_ENOTAVAIL,
}

#[allow(clippy::unnecessary_wraps)]
pub fn optee_smc_dispatch(optee_smc_args_pfn: u64) -> i64 {
    if let Ok(optee_smc_args_page_addr) =
        x86_64::PhysAddr::try_new(optee_smc_args_pfn << crate::mshv::vtl1_mem_layout::PAGE_SHIFT)
        && let Some(mut optee_smc_args) = unsafe {
            crate::platform_low().copy_from_vtl0_phys::<OpteeSmcArgs>(optee_smc_args_page_addr)
        }
    {
        match optee_smc_args.func_id() {
            Ok(func_id) => match func_id {
                OpteeSmcFunction::CallWithArg => {
                    debug_serial_println!(
                        "OP-TEE SMC SMC function ID: CallWithArg. 2nd argument would contain OpteeMsgArg"
                    );
                    optee_smc_args.set_result(&OpteeSmcResult::Generic {
                        status: OpteeSmcReturn::Ok,
                    });
                }
                OpteeSmcFunction::ExchangeCapabilities => {
                    debug_serial_println!("OP-TEE SMC function ID: ExchangeCapabilities");
                    optee_smc_args.set_result(&OpteeSmcResult::ExchangeCapabilities {
                        status: OpteeSmcReturn::Ok,
                        capabilities: (OpteeSecureWorldCapabilities::DYNAMIC_SHM
                            | OpteeSecureWorldCapabilities::MEMREF_NULL
                            | OpteeSecureWorldCapabilities::RPC_ARG)
                            .bits(),
                        max_notif_value: 0,
                        data: NUM_RPC_PARAMS,
                    });
                }
                OpteeSmcFunction::DisableShmCache => {
                    debug_serial_println!("OP-TEE SMC function ID: DisableShmCache");
                    optee_smc_args.set_result(&OpteeSmcResult::DisableShmCache {
                        status: OpteeSmcReturn::ENotAvail,
                        shm_upper32: 0,
                        shm_lower32: 0,
                    });
                }
                OpteeSmcFunction::CallsUid => {
                    debug_serial_println!("OP-TEE SMC function ID: CallsUid");
                    optee_smc_args.set_result(&OpteeSmcResult::Uuid {
                        data: [
                            OPTEE_MSG_UID_0,
                            OPTEE_MSG_UID_1,
                            OPTEE_MSG_UID_2,
                            OPTEE_MSG_UID_3,
                        ],
                    });
                }
                OpteeSmcFunction::GetOsRevision => {
                    debug_serial_println!("OP-TEE SMC function ID: GetOsRevision");
                    optee_smc_args.set_result(&OpteeSmcResult::OsRevision {
                        major: OPTEE_MSG_REVISION_MAJOR,
                        minor: OPTEE_MSG_REVISION_MINOR,
                        build_id: 0,
                    });
                }
                OpteeSmcFunction::CallsRevision => {
                    debug_serial_println!("OP-TEE SMC function ID: CallsRevision");
                    optee_smc_args.set_result(&OpteeSmcResult::Revision {
                        major: OPTEE_MSG_REVISION_MAJOR,
                        minor: OPTEE_MSG_REVISION_MINOR,
                    });
                }
            },
            Err(errno) => {
                debug_serial_println!(
                    "OP-TEE SMC Invalid function ID {:#x}, errno={}",
                    optee_smc_args.args[0],
                    errno
                );
                return Errno::EINVAL.as_neg().into();
            }
        }

        if unsafe {
            crate::platform_low()
                .copy_to_vtl0_phys::<OpteeSmcArgs>(optee_smc_args_page_addr, &optee_smc_args)
        } {
            0
        } else {
            debug_serial_println!("Failed to copy OpteeSmcArgs back to VTL0");
            Errno::EINVAL.as_neg().into()
        }
    } else {
        Errno::EINVAL.as_neg().into()
    }
}
