// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of pseudo TAs (PTAs) which export system services as
//! the functions of built-in TAs.

use crate::{Task, UserConstPtr, UserMutPtr};
use alloc::vec;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use litebox::platform::{
    DerivedKeyError, DerivedKeyProvider, KDFParams, RawConstPointer as _, RawMutPointer as _,
};
use litebox::utils::TruncateExt;
use litebox_common_optee::{
    HUK_SUBKEY_MAX_LEN, HukSubkeyUsage, TeeParamType, TeeResult, TeeUuid, UteeParams,
};
use num_enum::TryFromPrimitive;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

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

/// Minimum size of a derived key in bytes.
const TA_DERIVED_KEY_MIN_SIZE: usize = 16;
/// Maximum size of a derived key in bytes.
const TA_DERIVED_KEY_MAX_SIZE: usize = 32;
/// Maximum size of extra data for key derivation in bytes.
const TA_DERIVED_EXTRA_DATA_MAX_SIZE: usize = 1024;

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

type HmacSha256 = Hmac<Sha256>;

impl Task {
    /// Handle a command of the system PTA.
    pub fn handle_system_pta_command(
        &self,
        cmd_id: u32,
        params: &UteeParams,
    ) -> Result<(), TeeResult> {
        #[allow(clippy::single_match_else)]
        match PtaSystemCommandId::try_from(cmd_id).map_err(|_| TeeResult::BadParameters)? {
            PtaSystemCommandId::DeriveTaUniqueKey => self.derive_ta_unique_key(params),
            _ => {
                #[cfg(debug_assertions)]
                todo!("support other system PTA commands {cmd_id}");
                #[cfg(not(debug_assertions))]
                Err(TeeResult::NotSupported)
            }
        }
    }

    /// Derives a unique key for a TA using HUK.
    ///
    /// This follows the OP-TEE `system_derive_ta_unique_key` implementation from
    /// `core/pta/system.c`.
    fn derive_ta_unique_key(&self, params: &UteeParams) -> Result<(), TeeResult> {
        use TeeParamType::{MemrefInput, MemrefOutput, None};

        if !params.has_types([MemrefInput, MemrefOutput, None, None]) {
            return Err(TeeResult::BadParameters);
        }

        let (extra_data_addr, extra_data_size_u64) = params
            .get_values(0)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let extra_data_size: usize = extra_data_size_u64.truncate();

        let (subkey_addr, subkey_size_u64) = params
            .get_values(1)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let subkey_size: usize = subkey_size_u64.truncate();

        if extra_data_size > TA_DERIVED_EXTRA_DATA_MAX_SIZE
            || !(TA_DERIVED_KEY_MIN_SIZE..=TA_DERIVED_KEY_MAX_SIZE).contains(&subkey_size)
            || (extra_data_size > 0 && extra_data_addr == 0)
            || subkey_addr == 0
        {
            return Err(TeeResult::BadParameters);
        }

        let extra_data = if extra_data_size == 0 {
            Vec::new().into_boxed_slice()
        } else {
            let extra_data_ptr = UserConstPtr::<u8>::from_usize(extra_data_addr.truncate());
            extra_data_ptr
                .to_owned_slice(extra_data_size)
                .ok_or(TeeResult::BadParameters)?
        };

        // Unlike OP-TEE OS, `UserMutPtr` (and `UserConstPtr`) in LiteBox ensure this
        // pointer can never be used to access normal-world memory. That is, we don't
        // need extra security check for detecting key leakage here.
        let subkey_ptr = UserMutPtr::<u8>::from_usize(subkey_addr.truncate());

        // subkey = KDF(huk, usage || ta_uuid || extra_data)
        let ta_uuid_bytes = self.ta_app_id.to_le_bytes();
        let mut subkey_buf = Zeroizing::new(vec![0u8; subkey_size]);
        self.huk_subkey_derive(
            HukSubkeyUsage::UniqueTa,
            &[&ta_uuid_bytes, &extra_data],
            &mut subkey_buf,
        )
        .and_then(|()| {
            subkey_ptr
                .copy_from_slice(0, &subkey_buf)
                .ok_or(TeeResult::AccessDenied)
        })
    }

    /// Derive a subkey using HUK and constant data.
    ///
    /// This follows the OP-TEE `huk_subkey_derive` interface from `core/kernel/huk_subkey.c`.
    fn huk_subkey_derive(
        &self,
        usage: HukSubkeyUsage,
        const_data: &[&[u8]],
        subkey: &mut [u8],
    ) -> Result<(), TeeResult> {
        let subkey_len = subkey.len();
        if subkey_len > HUK_SUBKEY_MAX_LEN {
            return Err(TeeResult::BadParameters);
        }

        let kdf_context_len =
            core::mem::size_of::<u32>() + const_data.iter().map(|chunk| chunk.len()).sum::<usize>();
        let mut kdf_context = Zeroizing::new(Vec::with_capacity(kdf_context_len));
        kdf_context.extend_from_slice(&(usage as u32).to_le_bytes());
        for chunk in const_data {
            kdf_context.extend_from_slice(chunk);
        }
        let kdf_params = KDFParams {
            context: kdf_context.as_slice(),
            output: subkey,
        };

        self.global
            .platform
            .derive_key(Some(huk_subkey_derive_inner), kdf_params)
            .map_err(|err| match err {
                DerivedKeyError::ShimKDFRequired
                | DerivedKeyError::UnsupportedRebootPersistentKey => TeeResult::NotSupported,
                DerivedKeyError::ShimKDFError(err) => err,
            })?;

        Ok(())
    }
}

/// A KDF callback that derives a subkey from `huk` and `params.context` to be passed to
/// the underlying platform implementation of `derive_key`.
fn huk_subkey_derive_inner(huk: &[u8], params: KDFParams<'_>) -> Result<(), TeeResult> {
    let subkey_len = params.output.len();
    if subkey_len > HUK_SUBKEY_MAX_LEN {
        return Err(TeeResult::BadParameters);
    }

    let mut hmac_bytes = HmacSha256::new_from_slice(huk)
        .map_err(|_| TeeResult::BadParameters)?
        .chain_update(params.context)
        .finalize()
        .into_bytes();
    params.output.copy_from_slice(&hmac_bytes[..subkey_len]);
    hmac_bytes.zeroize();
    Ok(())
}
