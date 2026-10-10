// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of pseudo TAs (PTAs) which export system services as
//! the functions of built-in TAs.

use crate::msg_handler::ShmInfo;
use crate::{Task, UserConstPtr, UserMutPtr, idk::IdksPta, syscalls::Cleanup};
use alloc::vec;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use litebox::platform::{DerivedKeyError, KDFParams, RawConstPointer as _, RawMutPointer as _};
use litebox::utils::TruncateExt;
use litebox_common_linux::vmem::PAGE_SIZE;
use litebox_common_optee::{
    HUK_SUBKEY_MAX_LEN, HukSubkeyUsage, LdelfMapFlags, OpteeSmcReturnCode, TaFlags, TeeParamType,
    TeeResult, TeeUuid, UteeParams,
};
use num_enum::TryFromPrimitive;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

struct SystemPta;

/// A common interface to interact with various PTAs including the system PTA.
///
/// Add new PTAs here as needed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum PseudoTa {
    System,
    Idks,
}

impl PseudoTa {
    pub(crate) fn from_uuid(uuid: &TeeUuid) -> Option<Self> {
        match *uuid {
            SystemPta::UUID => Some(Self::System),
            IdksPta::UUID => Some(Self::Idks),
            _ => None,
        }
    }

    /// Open a session to this PTA, returning the allocated session ID.
    fn open_session(self, params: &UteeParams) -> Result<u32, TeeResult> {
        match self {
            Self::System => SystemPta::open_session(params),
            Self::Idks => IdksPta::open_session(params),
        }
    }

    pub(crate) fn invoke_command<Platform: crate::OpteeShimPlatform>(
        self,
        task: &Task<Platform>,
        cmd_id: u32,
        params: &mut UteeParams,
    ) -> Result<Cleanup, TeeResult> {
        let _busy = task.try_set_busy(self)?;
        match self {
            Self::System => SystemPta::invoke_command(task, cmd_id, params),
            Self::Idks => IdksPta::invoke_command(task, cmd_id, params),
        }
    }

    fn close_session<Platform: crate::OpteeShimPlatform>(
        self,
        task: &Task<Platform>,
        session_id: u32,
    ) {
        match self {
            Self::System => SystemPta::close_session(task, session_id),
            Self::Idks => IdksPta::close_session(task, session_id),
        }
    }

    fn flags(self) -> TaFlags {
        match self {
            Self::System => SystemPta::FLAGS,
            Self::Idks => IdksPta::FLAGS,
        }
    }
}

/// PTAs reachable by normal-world clients via OP-TEE messages.
///
/// A separate registry from `PseudoTa`: a PTA is reachable only by the
/// callers it is registered for (OP-TEE OS instead has one registry and each
/// PTA gates callers itself). Like OP-TEE PTAs, these update `UteeParams` in
/// place and write memref outputs directly into the client's shared memory.
///
/// Assumptions: all are stateless, and none has an open-session hook (so
/// open-session params and client identity are ignored and opening fails
/// only on TEE resource limits).
#[derive(Clone, Copy, Debug)]
pub enum ClientPta {
    Device,
}

impl ClientPta {
    pub fn from_uuid(uuid: &TeeUuid) -> Option<Self> {
        match *uuid {
            DevicePta::UUID => Some(Self::Device),
            _ => None,
        }
    }

    /// `params` follows [`crate::msg_handler::client_pta_params`]: memref
    /// buffers are `shm_info[i]`, not addresses.
    ///
    /// # Errors
    ///
    /// `EBadAddr` if writing to shared memory fails; the TEE result otherwise.
    pub fn invoke_command<Platform: crate::OpteeShimPlatform>(
        self,
        platform: &Platform,
        cmd_id: u32,
        params: &mut UteeParams,
        shm_info: &[Option<ShmInfo<PAGE_SIZE>>; UteeParams::TEE_NUM_PARAMS],
    ) -> Result<TeeResult, OpteeSmcReturnCode> {
        match self {
            Self::Device => DevicePta::invoke_command(platform, cmd_id, params, shm_info),
        }
    }
}

pub(crate) const PTA_DEFAULT_FLAGS: TaFlags = TaFlags::SINGLE_INSTANCE
    .union(TaFlags::MULTI_SESSION)
    .union(TaFlags::INSTANCE_KEEP_ALIVE);

const MAX_PTA_SESSIONS_PER_TASK: usize = 100;

pub(crate) fn open_default_pta_session(params: &UteeParams) -> Result<u32, TeeResult> {
    if !params.has_types([
        TeeParamType::None,
        TeeParamType::None,
        TeeParamType::None,
        TeeParamType::None,
    ]) {
        return Err(TeeResult::BadParameters);
    }

    crate::SessionIdPool::allocate().ok_or(TeeResult::Busy)
}

struct PtaBusyGuard<'a, Platform: crate::OpteeShimPlatform> {
    task: &'a Task<Platform>,
    pta: PseudoTa,
}

impl<Platform: crate::OpteeShimPlatform> Drop for PtaBusyGuard<'_, Platform> {
    fn drop(&mut self) {
        self.task.global.pta_busy.lock().remove(&self.pta);
    }
}

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
enum PtaSystemCommandId {
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

type HmacSha256 = Hmac<Sha256>;

impl<Platform: crate::OpteeShimPlatform> Task<Platform> {
    /// Try to mark a non-concurrent PTA as busy, returning a guard that clears
    /// the busy state on drop. This gates both session opening and command
    /// invocation.
    ///
    /// Returns `Ok(None)` for PTAs flagged `TaFlags::CONCURRENT` (no gating).
    /// For a non-concurrent PTA that is busy, returns `Err(Busy)` immediately.
    fn try_set_busy(&self, pta: PseudoTa) -> Result<Option<PtaBusyGuard<'_, Platform>>, TeeResult> {
        if pta.flags().contains(TaFlags::CONCURRENT) {
            return Ok(None);
        }

        let mut busy = self.global.pta_busy.lock();
        if busy.contains(&pta) {
            return Err(TeeResult::Busy);
        }

        busy.insert(pta);
        Ok(Some(PtaBusyGuard { task: self, pta }))
    }

    pub(crate) fn open_pta_session(
        &self,
        pta: PseudoTa,
        params: &UteeParams,
    ) -> Result<u32, TeeResult> {
        let _busy = self.try_set_busy(pta)?;

        // OP-TEE OS permits multiple sessions to the same PTA. We cap the number
        // of PTA sessions per TA instance to prevent a TA from exhausting session
        // IDs or memory. The cap is checked while holding the lock, then the lock
        // is released before `open_session` runs.
        {
            let pta_sessions = self.pta_sessions.lock();
            if pta_sessions.len() >= MAX_PTA_SESSIONS_PER_TASK {
                return Err(TeeResult::Busy);
            }
        }

        // Run the PTA hook without holding `pta_sessions`. OP-TEE `Task` is
        // single-threaded, so nothing else mutates `pta_sessions` in the meantime.
        // Keeping the hook outside the lock to avoid a self deadlock.
        let session_id = pta.open_session(params)?;

        let prev = self.pta_sessions.lock().insert(session_id, pta);
        debug_assert!(
            prev.is_none(),
            "freshly allocated session ID collided with an existing PTA session",
        );
        Ok(session_id)
    }

    pub(crate) fn close_pta_session(&self, ta_session_id: u32) -> Option<PseudoTa> {
        let mut pta_sessions = self.pta_sessions.lock();
        let pta = pta_sessions.remove(&ta_session_id)?;
        drop(pta_sessions);
        pta.close_session(self, ta_session_id);
        crate::SessionIdPool::recycle(ta_session_id);
        Some(pta)
    }

    /// Get the PTA associated with a session (if exists).
    pub(crate) fn pta_for_session(&self, ta_sess_id: u32) -> Option<PseudoTa> {
        self.pta_sessions.lock().get(&ta_sess_id).copied()
    }

    pub(crate) fn close_all_pta_sessions(&self) {
        // Drain into a local buffer and release the lock before invoking
        // `close_session` to avoid potential dead locks.
        let sessions: Vec<(u32, PseudoTa)> = self.pta_sessions.lock().drain().collect();
        for (session_id, pta) in sessions {
            pta.close_session(self, session_id);
            crate::SessionIdPool::recycle(session_id);
        }
    }
}

impl SystemPta {
    const FLAGS: TaFlags = PTA_DEFAULT_FLAGS.union(TaFlags::CONCURRENT);

    const UUID: TeeUuid = TeeUuid {
        time_low: 0x3a2f_8978,
        time_mid: 0x5dc0,
        time_hi_and_version: 0x11e8,
        clock_seq_and_node: [0x9c, 0x2d, 0xfa, 0x7a, 0xe0, 0x1b, 0xbe, 0xbc],
    };

    fn open_session(params: &UteeParams) -> Result<u32, TeeResult> {
        open_default_pta_session(params)
    }

    fn close_session<Platform: crate::OpteeShimPlatform>(_task: &Task<Platform>, _session_id: u32) {
        // System PTA has no per-session state
    }

    /// Handle a command of the system PTA.
    ///
    /// See `Cleanup` for the returned rollback; most commands have no cleanup.
    fn invoke_command<Platform: crate::OpteeShimPlatform>(
        task: &Task<Platform>,
        cmd_id: u32,
        params: &mut UteeParams,
    ) -> Result<Cleanup, TeeResult> {
        match PtaSystemCommandId::try_from(cmd_id).map_err(|_| TeeResult::BadParameters)? {
            PtaSystemCommandId::DeriveTaUniqueKey => {
                Self::derive_ta_unique_key(task, params).map(|()| Cleanup::None)
            }
            PtaSystemCommandId::MapZi => Self::map_zi(task, params),
            PtaSystemCommandId::Unmap => Self::unmap(task, params).map(|()| Cleanup::None),
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
    fn derive_ta_unique_key<Platform: crate::OpteeShimPlatform>(
        task: &Task<Platform>,
        params: &UteeParams,
    ) -> Result<(), TeeResult> {
        use TeeParamType::{MemrefInput, MemrefOutput, None};

        if !params.has_types([MemrefInput, MemrefOutput, None, None]) {
            return Err(TeeResult::BadParameters);
        }

        let (extra_data_addr, extra_data_size_u64) = params
            .get_values(0)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let extra_data_size: usize = extra_data_size_u64.trunc();

        let (subkey_addr, subkey_size_u64) = params
            .get_values(1)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let subkey_size: usize = subkey_size_u64.trunc();

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
            let extra_data_ptr = UserConstPtr::<Platform, u8>::from_usize(extra_data_addr.trunc());
            extra_data_ptr
                .to_owned_slice(extra_data_size)
                .ok_or(TeeResult::BadParameters)?
        };

        // Unlike OP-TEE OS, `UserMutPtr` (and `UserConstPtr`) in LiteBox ensure this
        // pointer can never be used to access normal-world memory. That is, we don't
        // need extra security check for detecting key leakage here.
        let subkey_ptr = UserMutPtr::<Platform, u8>::from_usize(subkey_addr.trunc());

        // subkey = KDF(huk, usage || ta_uuid || extra_data)
        let ta_uuid_bytes = task.ta_app_id.to_le_bytes();
        let mut subkey_buf = Zeroizing::new(vec![0u8; subkey_size]);
        Self::huk_subkey_derive(
            task,
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
    fn huk_subkey_derive<Platform: crate::OpteeShimPlatform>(
        task: &Task<Platform>,
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

        task.global
            .platform
            .derive_key(Some(huk_subkey_derive_inner), kdf_params)
            .map_err(|err| match err {
                DerivedKeyError::ShimKDFRequired
                | DerivedKeyError::UnsupportedRebootPersistentKey => TeeResult::NotSupported,
                DerivedKeyError::ShimKDFError(err) => err,
            })?;

        Ok(())
    }

    fn map_zi<Platform: crate::OpteeShimPlatform>(
        task: &Task<Platform>,
        params: &mut UteeParams,
    ) -> Result<Cleanup, TeeResult> {
        use TeeParamType::{None, ValueInout, ValueInput};

        if !params.has_types([ValueInput, ValueInout, ValueInput, None]) {
            return Err(TeeResult::BadParameters);
        }

        let (num_bytes, flags) = params
            .get_values(0)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        if num_bytes == 0 {
            return Err(TeeResult::BadParameters);
        }
        let (addr_high, addr_low) = params
            .get_values(1)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let (pad_begin, pad_end) = params
            .get_values(2)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;

        if addr_high & 0xffff_ffff_0000_0000 != 0 || addr_low & 0xffff_ffff_0000_0000 != 0 {
            return Err(TeeResult::BadParameters);
        }
        let addr: usize = ((addr_high << 32) | addr_low).trunc();
        let (mapped, cleanup) = task.sys_map_zi(
            addr,
            num_bytes.trunc(),
            pad_begin.trunc(),
            pad_end.trunc(),
            LdelfMapFlags::from_bits_retain(flags.trunc()),
        )?;

        // Return the mapped address to the caller via the inout value param.
        // This `set_values` cannot fail because the index is fixed/known.
        let _ = params.set_values(1, (mapped as u64) >> 32, (mapped as u64) & 0xffff_ffff);

        // The caller runs `cleanup` (unmap) if it encounters an error.
        Ok(cleanup)
    }

    fn unmap<Platform: crate::OpteeShimPlatform>(
        task: &Task<Platform>,
        params: &UteeParams,
    ) -> Result<(), TeeResult> {
        use TeeParamType::{None, ValueInput};

        if !params.has_types([ValueInput, ValueInput, None, None]) {
            return Err(TeeResult::BadParameters);
        }

        let (size, must_be_zero) = params
            .get_values(0)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        if must_be_zero != 0 {
            return Err(TeeResult::BadParameters);
        }
        let (addr_high, addr_low) = params
            .get_values(1)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;

        if addr_high & 0xffff_ffff_0000_0000 != 0 || addr_low & 0xffff_ffff_0000_0000 != 0 {
            return Err(TeeResult::BadParameters);
        }
        let addr: usize = ((addr_high << 32) | addr_low).trunc();
        let size: usize = size.trunc();
        let size = size
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(TeeResult::BadParameters)?;

        task.sys_munmap(UserMutPtr::<Platform, u8>::from_usize(addr), size)
            .map_err(|_| TeeResult::BadParameters)
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

/// Device enumeration PTA, following OP-TEE OS `core/pta/device.c`.
///
/// Called by the Linux driver (`__optee_enumerate_devices()`) with
/// `TEE_LOGIN_PUBLIC`; Linux treats any open-session failure as "PTA absent",
/// so opening must not be restricted (OP-TEE registers no open hook).
///
/// Differences from OP-TEE OS:
/// - Only embedded TAs are listed: no LiteBox PTA needs a Linux driver bound
///   to it, and there is no StMM.
/// - No persistent storage (neither `CFG_REE_FS` nor `CFG_RPMB_FS`):
///   `TEE_STORAGE_PRIVATE` TAs are never enumerated and `GET_DEVICES_RPMB`
///   returns an empty list.
/// - UUIDs are sorted rather than in link order.
struct DevicePta;

const PTA_CMD_GET_DEVICES: u32 = 0;
const PTA_CMD_GET_DEVICES_SUPP: u32 = 1;
const PTA_CMD_GET_DEVICES_RPMB: u32 = 2;

const UUID_OCTETS: usize = 16;

/// A TA may carry at most one of these.
const DEVICE_ENUM_MASK: TaFlags = TaFlags::DEVICE_ENUM
    .union(TaFlags::DEVICE_ENUM_SUPP)
    .union(TaFlags::DEVICE_ENUM_TEE_STORAGE_PRIVATE);

impl DevicePta {
    /// 7011a688-ddde-4053-a5a9-7b3c4ddf13b8
    const UUID: TeeUuid = TeeUuid {
        time_low: 0x7011_a688,
        time_mid: 0xddde,
        time_hi_and_version: 0x4053,
        clock_seq_and_node: [0xa5, 0xa9, 0x7b, 0x3c, 0x4d, 0xdf, 0x13, 0xb8],
    };

    fn invoke_command<Platform: crate::OpteeShimPlatform>(
        platform: &Platform,
        cmd_id: u32,
        params: &mut UteeParams,
        shm_info: &[Option<ShmInfo<PAGE_SIZE>>; UteeParams::TEE_NUM_PARAMS],
    ) -> Result<TeeResult, OpteeSmcReturnCode> {
        let rflags = match cmd_id {
            PTA_CMD_GET_DEVICES => TaFlags::DEVICE_ENUM,
            PTA_CMD_GET_DEVICES_SUPP => TaFlags::DEVICE_ENUM_SUPP,
            PTA_CMD_GET_DEVICES_RPMB => TaFlags::empty(),
            _ => return Ok(TeeResult::NotImplemented),
        };

        if !params.has_types([
            TeeParamType::MemrefOutput,
            TeeParamType::None,
            TeeParamType::None,
            TeeParamType::None,
        ]) {
            return Ok(TeeResult::BadParameters);
        }
        let Ok(Some((_, blen))) = params.get_values(0) else {
            return Ok(TeeResult::BadParameters);
        };
        let blen = usize::try_from(blen).map_err(|_| OpteeSmcReturnCode::EBadAddr)?;
        // A NULL buffer has an empty `shm_info` regardless of `blen`.
        let Some(out) = shm_info[0].as_ref().filter(|shm| shm.len() == blen) else {
            return Ok(TeeResult::BadParameters);
        };

        let tas = crate::embedded_ta_uuid_map()
            .inner
            .read()
            .iter()
            .map(|(uuid, info)| (*uuid, info.flags))
            .collect();
        let (size, data) = Self::device_list(rflags, tas, blen);
        out.write_at(platform, 0, &data)?;
        let _ = params.set_values(0, 0, size as u64);
        Ok(if size > blen {
            TeeResult::ShortBuffer
        } else {
            TeeResult::Success
        })
    }

    /// Returns `(size, data)` like OP-TEE's `get_devices()`: `size` covers all
    /// matching UUIDs (RFC 4122 octets); `data` holds the whole UUIDs that fit
    /// in `blen`.
    fn device_list(
        rflags: TaFlags,
        mut tas: Vec<(TeeUuid, TaFlags)>,
        blen: usize,
    ) -> (usize, Vec<u8>) {
        tas.sort_unstable_by_key(|(uuid, _)| uuid.to_bytes());

        let mut size = 0usize;
        let mut data = Vec::new();
        for (uuid, flags) in tas {
            let flags = flags.intersection(DEVICE_ENUM_MASK);
            if flags.bits().count_ones() > 1 {
                litebox_util_log::warn!(uuid:? = uuid; "device PTA: skipping TA with inconsistent flags");
                continue;
            }
            if flags.intersects(rflags) {
                if size + UUID_OCTETS <= blen {
                    data.extend_from_slice(&uuid.to_bytes());
                }
                size += UUID_OCTETS;
            }
        }
        (size, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(seed: u8) -> TeeUuid {
        TeeUuid::from_bytes([seed; 16])
    }

    fn octets(uuids: &[TeeUuid]) -> Vec<u8> {
        uuids.iter().flat_map(|u| u.to_bytes()).collect()
    }

    #[test]
    fn device_list_filters_and_encodes() {
        let tas = alloc::vec![
            (uuid(3), TaFlags::DEVICE_ENUM_SUPP),
            (uuid(2), TaFlags::DEVICE_ENUM | TaFlags::SINGLE_INSTANCE),
            (uuid(1), TaFlags::DEVICE_ENUM),
            (uuid(4), TaFlags::SINGLE_INSTANCE),
            // More than one stage: skipped.
            (uuid(5), TaFlags::DEVICE_ENUM | TaFlags::DEVICE_ENUM_SUPP),
            (
                uuid(6),
                TaFlags::DEVICE_ENUM | TaFlags::DEVICE_ENUM_TEE_STORAGE_PRIVATE
            ),
        ];
        let list = |rflags, blen| DevicePta::device_list(rflags, tas.clone(), blen);

        assert_eq!(list(TaFlags::DEVICE_ENUM, 0), (32, Vec::new()));
        // Partial copy on short buffer.
        assert_eq!(list(TaFlags::DEVICE_ENUM, 31), (32, octets(&[uuid(1)])));
        assert_eq!(
            list(TaFlags::DEVICE_ENUM, 64),
            (32, octets(&[uuid(1), uuid(2)]))
        );
        assert_eq!(
            list(TaFlags::DEVICE_ENUM_SUPP, 16),
            (16, octets(&[uuid(3)]))
        );
    }
}
