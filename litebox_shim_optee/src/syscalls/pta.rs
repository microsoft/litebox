// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of pseudo TAs (PTAs) which export system services as
//! the functions of built-in TAs.

use crate::{Task, UserConstPtr, UserMutPtr};
use alloc::vec;
use hmac::{Hmac, Mac};
use litebox::platform::{RawConstPointer, RawMutPointer, UniquePlatformKeyProvider};
use litebox::utils::TruncateExt;
use litebox_common_optee::{
    HUK_SUBKEY_MAX_LEN, HukSubkeyUsage, TeeParamType, TeeResult, TeeUuid, UteeParams,
};
use num_enum::TryFromPrimitive;
use sha2::Sha256;
use zeroize::Zeroizing;

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
const PTA_SYSTEM_DERIVE_TA_SVN_KEY_STACK: u32 = 14;

/// Minimum size of a derived key in bytes.
const TA_DERIVED_KEY_MIN_SIZE: usize = 16;
/// Maximum size of a derived key in bytes.
const TA_DERIVED_KEY_MAX_SIZE: usize = 32;
/// Maximum size of extra data for key derivation in bytes.
const TA_DERIVED_EXTRA_DATA_MAX_SIZE: usize = 1024;
/// Maximum number of keys in SVN key stack.
const SVN_KEY_STACK_MAX_SIZE: u32 = 4096;

/// `PTA_SYSTEM_*` command ID from `optee_os/lib/libutee/include/pta_system.h`
#[derive(Clone, Copy, TryFromPrimitive)]
#[non_exhaustive]
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
    DeriveTaSvnKeyStack = PTA_SYSTEM_DERIVE_TA_SVN_KEY_STACK,
}

/// Checks whether a given TA is a (system) PTA and its parameter is valid.
pub fn is_pta(ta_uuid: &TeeUuid, params: &UteeParams) -> bool {
    // TODO: consider other PTAs
    use TeeParamType::None;
    *ta_uuid == PTA_SYSTEM_UUID && params.has_types([None, None, None, None])
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
            PtaSystemCommandId::DeriveTaSvnKeyStack => self.derive_ta_svn_key_stack(params),
            _ => todo!("support other system PTA commands {cmd_id}"),
        }
    }

    /// Derive a subkey using HUK and constant data
    ///
    /// This follows the OP-TEE `huk_subkey_derive` interface from `core/kernel/huk_subkey.c`.
    ///
    /// - `usage` - The intended usage for the subkey
    /// - `const_data` - Constant data chunks to include in derivation
    /// - `subkey` - Output buffer to store the derived key
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

        // We use the unique platform key as the HUK
        let huk = self
            .global
            .platform
            .unique_platform_key()
            .map_err(|_| TeeResult::NotSupported)?;

        // subkey = HMAC(huk, usage || const_data)
        let mut hmac = HmacSha256::new_from_slice(huk).map_err(|_| TeeResult::BadParameters)?;

        hmac.update(&(usage as u32).to_le_bytes());

        for chunk in const_data {
            hmac.update(chunk);
        }

        let hmac_bytes = hmac.finalize().into_bytes();
        subkey.copy_from_slice(&hmac_bytes[..subkey_len]);
        Ok(())
    }

    /// Derives a unique key for a TA using HUK
    ///
    /// This follows the OP-TEE `system_derive_ta_unique_key` implementation from
    /// `core/pta/system.c`.
    fn derive_ta_unique_key(&self, params: &UteeParams) -> Result<(), TeeResult> {
        use TeeParamType::{MemrefInput, MemrefOutput, None};
        // Validate parameter types:
        // [in]  params[0].memref.buffer   Extra data for key derivation
        // [in]  params[0].memref.size     Extra data size
        // [out] params[1].memref.buffer   Output buffer for derived key
        // [out] params[1].memref.size     Buffer size
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
            || subkey_addr == 0
        {
            return Err(TeeResult::BadParameters);
        }

        let extra_data_ptr = UserConstPtr::<u8>::from_usize(
            usize::try_from(extra_data_addr).map_err(|_| TeeResult::BadParameters)?,
        );
        let extra_data = extra_data_ptr
            .to_owned_slice(extra_data_size)
            .ok_or(TeeResult::BadParameters)?;

        let subkey_ptr = UserMutPtr::<u8>::from_usize(
            usize::try_from(subkey_addr).map_err(|_| TeeResult::BadParameters)?,
        );

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

    /// Derives a stack of unique keys for a TA, one for each possible
    /// Secure Version Number (SVN) value up to a maximum.
    ///
    /// The key derivation follows a two-stage process:
    /// 1. First stage: KDF(huk, uuid || extra_data) -> base key
    /// 2. Second stage: Iterate from max SVN down to 0, chaining keys:
    ///    - Key\[max\] = HMAC(base_key, max)
    ///    - Key\[n\] = HMAC(Key\[n+1\], n)
    ///
    /// Only keys for SVN values <= current TA version are copied to output.
    ///
    /// NOTE: This function requires `unique_platform_key()` to return a stable
    /// value across calls. If the HUK changes between invocations (specifically,
    /// between reboots), the derived key stack will be inconsistent.
    fn derive_ta_svn_key_stack(&self, params: &UteeParams) -> Result<(), TeeResult> {
        use TeeParamType::{MemrefInput, MemrefOutput, None, ValueInput};
        // Validate parameter types:
        // [in]  params[0].value.a         Size of each key
        // [in]  params[0].value.b         Number of keys to derive
        // [in]  params[1].memref.buffer   Extra data for key derivation
        // [in]  params[1].memref.size     Extra data size
        // [out] params[2].memref.buffer   Output buffer for key stack
        // [out] params[2].memref.size     Buffer size
        if !params.has_types([ValueInput, MemrefInput, MemrefOutput, None]) {
            return Err(TeeResult::BadParameters);
        }

        let (key_size_u64, svn_key_stack_size_u64) = params
            .get_values(0)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let key_size: usize = key_size_u64.truncate();
        let svn_key_stack_size =
            u32::try_from(svn_key_stack_size_u64).map_err(|_| TeeResult::BadParameters)?;

        let (extra_data_addr, extra_data_size_u64) = params
            .get_values(1)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let extra_data_size: usize = extra_data_size_u64.truncate();

        let (key_stack_addr, key_stack_buffer_size_u64) = params
            .get_values(2)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let key_stack_buffer_size: usize = key_stack_buffer_size_u64.truncate();

        if !(TA_DERIVED_KEY_MIN_SIZE..=TA_DERIVED_KEY_MAX_SIZE).contains(&key_size)
            || extra_data_size > TA_DERIVED_EXTRA_DATA_MAX_SIZE
            || svn_key_stack_size > SVN_KEY_STACK_MAX_SIZE
            || svn_key_stack_size == 0
            || key_stack_addr == 0
        {
            return Err(TeeResult::BadParameters);
        }

        // Validate TA version is within the key stack bounds
        let ta_version = self.ta_svn;
        if ta_version >= svn_key_stack_size {
            return Err(TeeResult::BadParameters);
        }

        let required_stack_buffer_size = key_size
            .checked_mul(ta_version as usize + 1)
            .ok_or(TeeResult::BadParameters)?;
        if key_stack_buffer_size < required_stack_buffer_size {
            return Err(TeeResult::BadParameters);
        }

        let extra_data_ptr = UserConstPtr::<u8>::from_usize(
            usize::try_from(extra_data_addr).map_err(|_| TeeResult::BadParameters)?,
        );
        let extra_data = extra_data_ptr
            .to_owned_slice(extra_data_size)
            .ok_or(TeeResult::BadParameters)?;

        let key_stack_ptr = UserMutPtr::<u8>::from_usize(
            usize::try_from(key_stack_addr).map_err(|_| TeeResult::BadParameters)?,
        );

        let uuid_bytes = self.ta_app_id.to_le_bytes();
        let mut stage_key = Zeroizing::new(vec![0u8; key_size]);

        // Derive keys from max SVN down to 0
        for svn_idx in (0..svn_key_stack_size).rev() {
            if svn_idx == svn_key_stack_size - 1 {
                // First iteration: derive base key = KDF(huk, usage || ta_uuid || extra data)
                self.huk_subkey_derive(
                    HukSubkeyUsage::UniqueTa,
                    &[&uuid_bytes, &extra_data],
                    &mut stage_key,
                )?;
            }

            // Second stage KDF: HMAC(current_key, SVN_index)
            // Key_v2047 = KDF(KDF(HUK, UUID), 2047)
            // Key_v2046 = KDF(Key_v2047, 2046)
            // ...
            // Key_v001 = KDF(Key_v002, 001)
            // Key_v000 = KDF(Key_v001, 000)
            let mut hmac =
                HmacSha256::new_from_slice(&stage_key).map_err(|_| TeeResult::BadParameters)?;
            hmac.update(&svn_idx.to_le_bytes());

            let hmac_bytes = hmac.finalize().into_bytes();
            let derived_key = &hmac_bytes[..key_size];

            // Only copy keys for SVN values <= current TA version to userspace
            if svn_idx <= ta_version {
                let offset = svn_idx as usize * key_size;
                key_stack_ptr
                    .copy_from_slice(offset, derived_key)
                    .ok_or(TeeResult::AccessDenied)?;
            }
            stage_key.copy_from_slice(derived_key);
        }

        Ok(())
    }
}
