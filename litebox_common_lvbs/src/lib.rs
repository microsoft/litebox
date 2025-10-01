//! Common elements of LVBS functionalities

#![cfg(target_arch = "x86_64")]
#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use num_enum::TryFromPrimitive;

const VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL: u32 = 0x1_ffe0;
const VSM_VTL_CALL_FUNC_ID_BOOT_APS: u32 = 0x1_ffe1;
const VSM_VTL_CALL_FUNC_ID_LOCK_REGS: u32 = 0x1_ffe2;
const VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT: u32 = 0x1_ffe3;
const VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY: u32 = 0x1_ffe4;
const VSM_VTL_CALL_FUNC_ID_LOAD_KDATA: u32 = 0x1_ffe5;
const VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE: u32 = 0x1_ffe6;
const VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT: u32 = 0x1_ffe7;
const VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE: u32 = 0x1_ffe8;
const VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY: u32 = 0x1_ffe9;
const VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE: u32 = 0x1_ffea;
const VSM_VTL_CALL_FUNC_ID_PATCH_TEXT: u32 = 0x1_ffeb;

// This VSM function ID for OP-TEE messages is subject to change
const VSM_VTL_CALL_FUNC_ID_OPTEE_MESSAGE: u32 = 0x1f_ffff;

/// VSM Functions
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum VsmFunction {
    // VSM/Heki functions
    EnableAPsVtl = VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL,
    BootAPs = VSM_VTL_CALL_FUNC_ID_BOOT_APS,
    LockRegs = VSM_VTL_CALL_FUNC_ID_LOCK_REGS,
    SignalEndOfBoot = VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT,
    ProtectMemory = VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY,
    LoadKData = VSM_VTL_CALL_FUNC_ID_LOAD_KDATA,
    ValidateModule = VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE,
    FreeModuleInit = VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT,
    UnloadModule = VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE,
    CopySecondaryKey = VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY,
    KexecValidate = VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE,
    PatchText = VSM_VTL_CALL_FUNC_ID_PATCH_TEXT,
    OpteeMessage = VSM_VTL_CALL_FUNC_ID_OPTEE_MESSAGE,
    Unknown = 0xffff_ffff,
}

impl VsmFunction {
    /// VTL call parameters (`param[0]`: function ID, `param[1..4]`: parameters)
    pub const NUM_VTLCALL_PARAMS: usize = 4;
}

/// VSM-VTL call command representation. This command is delivered from
/// the VTL0 kernel to the VTL1 kernel. Except for the OP-TEE message
/// command (which will be converted into `OpteeSmcCommand`), all other
/// commands are handled by the VSM-VTL call command handler.
/// TODO: use enum to strongly type the commands
pub struct VsmVtlCommand {
    pub func: VsmFunction,
    pub params: Box<[u64; VsmFunction::NUM_VTLCALL_PARAMS - 1]>,
}
