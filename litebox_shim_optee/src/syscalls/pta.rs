// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of pseudo TAs (PTAs) which export system services as
//! the functions of built-in TAs.

use crate::{Task, UserConstPtr, UserMutPtr};
use litebox::{
    platform::{RawConstPointer as _, RawMutPointer as _},
    utils::TruncateExt,
};
use litebox_common_optee::{TeeParamType, TeeResult, TeeUuid, UteeParams};
use num_enum::TryFromPrimitive;

pub const PTA_SYSTEM_UUID: TeeUuid = TeeUuid {
    time_low: 0x3a2f_8978,
    time_mid: 0x5dc0,
    time_hi_and_version: 0x11e8,
    clock_seq_and_node: [0x9c, 0x2d, 0xfa, 0x7a, 0xe0, 0x1b, 0xbe, 0xbc],
};

const PTA_SYSTEM_ADD_RNG_ENTROPY: u32 = 0;
const PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY: u32 = 1;
const PTA_SYSTEM_MAP_ZI: u32 = 2;
const PTA_SYSTEM_UNMAP: u32 = 3;
const PTA_SYSTEM_OPEN_TA_BINARY: u32 = 4;
const PTA_SYSTEM_CLOSE_TA_BINARY: u32 = 5;
const PTA_SYSTEM_MAP_TA_BINARY: u32 = 6;
const PTA_SYSTEM_COPY_FROM_TA_BINARY: u32 = 7;
const PTA_SYSTEM_SET_PROT: u32 = 8;
const PTA_SYSTEM_REMAP: u32 = 9;
const PTA_SYSTEM_DLOPEN: u32 = 10;
const PTA_SYSTEM_DLSYM: u32 = 11;
const PTA_SYSTEM_GET_TPM_EVENT_LOG: u32 = 12;
const PTA_SYSTEM_SUPP_PLUGIN_INVOKE: u32 = 13;

/// `PTA_SYSTEM_*` command ID from `optee_os/lib/libutee/include/pta_system.h`
#[derive(Clone, Copy, TryFromPrimitive)]
#[repr(u32)]
pub enum PtaSystemCommandId {
    AddRngEntropy = PTA_SYSTEM_ADD_RNG_ENTROPY,
    DeriveTaUniqueKey = PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY,
    MapZi = PTA_SYSTEM_MAP_ZI,
    Unmap = PTA_SYSTEM_UNMAP,
    OpenTaBinary = PTA_SYSTEM_OPEN_TA_BINARY,
    CloseTaBinary = PTA_SYSTEM_CLOSE_TA_BINARY,
    MapTaBinary = PTA_SYSTEM_MAP_TA_BINARY,
    CopyFromTaBinary = PTA_SYSTEM_COPY_FROM_TA_BINARY,
    SetProt = PTA_SYSTEM_SET_PROT,
    Remap = PTA_SYSTEM_REMAP,
    Dlopen = PTA_SYSTEM_DLOPEN,
    Dlsym = PTA_SYSTEM_DLSYM,
    GetTpmEventLog = PTA_SYSTEM_GET_TPM_EVENT_LOG,
    SuppPluginInvoke = PTA_SYSTEM_SUPP_PLUGIN_INVOKE,
}

/// Checks whether a given TA is a (system) PTA and its parameter is valid.
pub fn is_pta(ta_uuid: &TeeUuid, params: &UteeParams) -> bool {
    // TODO: consider other PTAs
    *ta_uuid == PTA_SYSTEM_UUID
        && params.get_type(0).is_ok_and(|t| t == TeeParamType::None)
        && params.get_type(1).is_ok_and(|t| t == TeeParamType::None)
        && params.get_type(2).is_ok_and(|t| t == TeeParamType::None)
        && params.get_type(3).is_ok_and(|t| t == TeeParamType::None)
}

// TODO: replace it with a proper implementation.
pub fn close_pta_session(_ta_session_id: u32) {}

/// Check whether a given session ID is associated with a PTA.
pub fn is_pta_session(ta_sess_id: u32) -> bool {
    ta_sess_id == crate::SessionIdPool::get_pta_session_id()
}

impl Task {
    /// Handle a command of the system PTA.
    pub fn handle_system_pta_command(
        &self,
        cmd_id: u32,
        params: &UteeParams,
    ) -> Result<(), TeeResult> {
        #[allow(clippy::single_match_else)]
        match PtaSystemCommandId::try_from(cmd_id).map_err(|_| TeeResult::BadParameters)? {
            PtaSystemCommandId::DeriveTaUniqueKey => {
                if params
                    .get_type(0)
                    .is_ok_and(|t| t == TeeParamType::MemrefInput)
                    && params
                        .get_type(1)
                        .is_ok_and(|t| t == TeeParamType::MemrefOutput)
                    && params.get_type(2).is_ok_and(|t| t == TeeParamType::None)
                    && params.get_type(3).is_ok_and(|t| t == TeeParamType::None)
                    && let Ok(Some(input)) =
                        params.get_values(0).map_err(|_| TeeResult::BadParameters)
                    && let Ok(Some(output)) =
                        params.get_values(1).map_err(|_| TeeResult::BadParameters)
                {
                    // TODO: revisit buffer size limits based on OP-TEE spec and deployment constraints
                    let input_len =
                        usize::try_from(input.1).map_err(|_| TeeResult::BadParameters)?;
                    if input_len > crate::MAX_KERNEL_BUF_SIZE {
                        return Err(TeeResult::BadParameters);
                    }
                    let input_addr: usize = input.0.truncate();
                    let input_ptr = UserConstPtr::<u8>::from_usize(input_addr);
                    let _extra_data = input_ptr
                        .to_owned_slice(input_len)
                        .ok_or(TeeResult::BadParameters)?;

                    let output_len =
                        usize::try_from(output.1).map_err(|_| TeeResult::BadParameters)?;
                    if output_len > crate::MAX_KERNEL_BUF_SIZE {
                        return Err(TeeResult::BadParameters);
                    }
                    let output_addr: usize = output.0.truncate();
                    let output_ptr = UserMutPtr::<u8>::from_usize(output_addr);

                    // TODO: checks whether output is within the secure memory

                    // TODO: derive a TA unique key using the hardware unique key (HUK), TA's UUID, and `extra_data`
                    litebox::log_println!(
                        self.global.platform,
                        "derive a key and store it in the secure memory (ptr: {:#x}, size: {})",
                        output_addr,
                        output_len
                    );
                    // TODO: replace below with a secure key derivation function
                    let mut key_buf = alloc::vec![0u8; output_len];
                    self.sys_cryp_random_number_generate(&mut key_buf)?;
                    output_ptr
                        .copy_from_slice(0, &key_buf)
                        .ok_or(TeeResult::BadParameters)?;

                    Ok(())
                } else {
                    Err(TeeResult::BadParameters)
                }
            }
            _ => todo!("support other system PTA commands {cmd_id}"),
        }
    }
}
