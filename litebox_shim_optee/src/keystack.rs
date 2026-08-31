// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of the SVN key stack pseudo TA.
//!
//! This PTA derives a stack of TA-unique keys, one per Secure Version Number (SVN),
//! so that a TA running at SVN `n` can unseal data sealed by any of its older
//! versions while remaining unable to derive the keys of any newer version.

use crate::syscalls::Cleanup;
use crate::syscalls::pta::{
    HmacSha256, PTA_DEFAULT_FLAGS, TA_DERIVED_EXTRA_DATA_MAX_SIZE, TA_DERIVED_KEY_MAX_SIZE,
    TA_DERIVED_KEY_MIN_SIZE, huk_subkey_derive, open_pta_session_no_params,
};
use crate::{Task, UserConstPtr, UserMutPtr};
use alloc::{vec, vec::Vec};
use hmac::Mac;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::TruncateExt;
use litebox_common_optee::{HukSubkeyUsage, TaFlags, TeeParamType, TeeResult, TeeUuid, UteeParams};
use num_enum::TryFromPrimitive;
use zeroize::Zeroizing;

/// Maximum number of keys in SVN key stack.
const SVN_KEY_STACK_MAX_SIZE: u32 = 4096;

pub(crate) struct KeyStackPta;

/// Command IDs accepted by [`KeyStackPta`].
#[derive(Clone, Copy, TryFromPrimitive)]
#[repr(u32)]
pub(crate) enum KeyStackCommandId {
    DeriveTaSvnKeyStack = 0,
}

impl KeyStackPta {
    pub(crate) const FLAGS: TaFlags = PTA_DEFAULT_FLAGS.union(TaFlags::CONCURRENT);

    // TODO: Replace this placeholder with the UUID agreed upon with the
    // consuming TA before this PTA is treated as a stable interface.
    pub(crate) const UUID: TeeUuid = TeeUuid {
        time_low: 0x978a_f7a7,
        time_mid: 0x074f,
        time_hi_and_version: 0x4f59,
        clock_seq_and_node: [0xb3, 0xae, 0x33, 0xa5, 0x93, 0xc1, 0xd4, 0x88],
    };

    pub(crate) fn open_session(params: &UteeParams) -> Result<u32, TeeResult> {
        open_pta_session_no_params(params)
    }

    pub(crate) fn close_session(_task: &Task, _session_id: u32) {
        // The key stack PTA has no per-session state.
    }

    pub(crate) fn invoke_command(
        task: &Task,
        cmd_id: u32,
        params: &mut UteeParams,
    ) -> Result<Cleanup, TeeResult> {
        match KeyStackCommandId::try_from(cmd_id).map_err(|_| TeeResult::BadParameters)? {
            KeyStackCommandId::DeriveTaSvnKeyStack => {
                Self::derive_ta_svn_key_stack(task, params).map(|()| Cleanup::None)
            }
        }
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
    fn derive_ta_svn_key_stack(task: &Task, params: &mut UteeParams) -> Result<(), TeeResult> {
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
        let key_size: usize = key_size_u64.trunc();
        let svn_key_stack_size =
            u32::try_from(svn_key_stack_size_u64).map_err(|_| TeeResult::BadParameters)?;

        let (extra_data_addr, extra_data_size_u64) = params
            .get_values(1)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let extra_data_size: usize = extra_data_size_u64.trunc();

        let (key_stack_addr, key_stack_buffer_size_u64) = params
            .get_values(2)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;

        if !(TA_DERIVED_KEY_MIN_SIZE..=TA_DERIVED_KEY_MAX_SIZE).contains(&key_size)
            || extra_data_size > TA_DERIVED_EXTRA_DATA_MAX_SIZE
            || svn_key_stack_size > SVN_KEY_STACK_MAX_SIZE
            || svn_key_stack_size == 0
            || (extra_data_size > 0 && extra_data_addr == 0)
            || key_stack_addr == 0
        {
            return Err(TeeResult::BadParameters);
        }

        // Only keys for SVN <= ta_svn are emitted, and the chain is only
        // `svn_key_stack_size` deep, so the buffer need cover just that many.
        let ta_svn = task.ta_svn;
        let emitted_key_count = ta_svn.saturating_add(1).min(svn_key_stack_size);
        let required_stack_buffer_size = key_size
            .checked_mul(emitted_key_count as usize)
            .ok_or(TeeResult::BadParameters)?;
        let required_stack_buffer_size_u64 =
            u64::try_from(required_stack_buffer_size).map_err(|_| TeeResult::BadParameters)?;
        if key_stack_buffer_size_u64 < required_stack_buffer_size_u64 {
            // Report the required size so the caller can probe with a small
            // buffer and retry, mirroring the GP short-buffer convention.
            params
                .set_values(2, key_stack_addr, required_stack_buffer_size_u64)
                .map_err(|_| TeeResult::BadParameters)?;
            return Err(TeeResult::ShortBuffer);
        }

        let extra_data = if extra_data_size == 0 {
            Vec::new().into_boxed_slice()
        } else {
            let extra_data_ptr = UserConstPtr::<u8>::from_usize(extra_data_addr.trunc());
            extra_data_ptr
                .to_owned_slice(extra_data_size)
                .ok_or(TeeResult::BadParameters)?
        };

        // Unlike OP-TEE OS, `UserMutPtr` (and `UserConstPtr`) in LiteBox ensure this
        // pointer can never be used to access normal-world memory. That is, we don't
        // need extra security check for detecting key leakage here.
        let key_stack_ptr = UserMutPtr::<u8>::from_usize(key_stack_addr.trunc());

        // First stage: derive base key = KDF(huk, usage || ta_uuid || extra data)
        let uuid_bytes = task.ta_app_id.to_le_bytes();
        let mut stage_key = Zeroizing::new(vec![0u8; key_size]);
        huk_subkey_derive(
            task,
            HukSubkeyUsage::UniqueTa,
            &[&uuid_bytes, &extra_data],
            &mut stage_key,
        )?;

        // Derive keys from max SVN down to 0
        for svn_idx in (0..svn_key_stack_size).rev() {
            // Second stage KDF: HMAC(current_key, SVN_index)
            // Key_v2047 = KDF(KDF(HUK, UUID), 2047)
            // Key_v2046 = KDF(Key_v2047, 2046)
            // ...
            // Key_v001 = KDF(Key_v002, 001)
            // Key_v000 = KDF(Key_v001, 000)
            let mut hmac =
                HmacSha256::new_from_slice(&stage_key).map_err(|_| TeeResult::BadParameters)?;
            hmac.update(&svn_idx.to_le_bytes());

            let hmac_bytes = Zeroizing::new(hmac.finalize().into_bytes());
            let derived_key = &hmac_bytes[..key_size];

            // Only copy keys for SVN values <= current TA version to userspace
            if svn_idx <= ta_svn {
                let offset = svn_idx as usize * key_size;
                key_stack_ptr
                    .copy_from_slice(offset, derived_key)
                    .ok_or(TeeResult::AccessDenied)?;
            }
            stage_key.copy_from_slice(derived_key);
        }

        // Report how many bytes were actually written.
        params
            .set_values(2, key_stack_addr, required_stack_buffer_size_u64)
            .map_err(|_| TeeResult::BadParameters)
    }
}
