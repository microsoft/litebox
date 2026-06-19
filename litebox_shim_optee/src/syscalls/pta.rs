// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of pseudo TAs (PTAs) which export system services as
//! the functions of built-in TAs.

use crate::syscalls::Cleanup;
use crate::{Task, UserConstPtr, UserMutPtr};
use alloc::vec;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use litebox::mm::linux::PAGE_SIZE;
use litebox::platform::{
    DerivedKeyError, DerivedKeyProvider, KDFParams, RawConstPointer as _, RawMutPointer as _,
};
use litebox::utils::TruncateExt;
use litebox_common_optee::{
    HUK_SUBKEY_MAX_LEN, HukSubkeyUsage, LdelfMapFlags, TaFlags, TeeParamType, TeeResult, TeeUuid,
    UteeParams,
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
}

impl PseudoTa {
    pub(crate) fn from_uuid(uuid: &TeeUuid) -> Option<Self> {
        match *uuid {
            SystemPta::UUID => Some(Self::System),
            _ => None,
        }
    }

    /// Open a session to this PTA, returning the allocated session ID.
    fn open_session(self, params: &UteeParams) -> Result<u32, TeeResult> {
        match self {
            Self::System => SystemPta::open_session(params),
        }
    }

    pub(crate) fn invoke_command(
        self,
        task: &Task,
        cmd_id: u32,
        params: &mut UteeParams,
    ) -> Result<Cleanup, TeeResult> {
        let _busy = task.try_set_busy(self)?;
        match self {
            Self::System => SystemPta::invoke_command(task, cmd_id, params),
        }
    }

    fn close_session(self, task: &Task, session_id: u32) {
        match self {
            Self::System => SystemPta::close_session(task, session_id),
        }
    }

    fn flags(self) -> TaFlags {
        match self {
            Self::System => SystemPta::FLAGS,
        }
    }
}

const PTA_DEFAULT_FLAGS: TaFlags = TaFlags::SINGLE_INSTANCE
    .union(TaFlags::MULTI_SESSION)
    .union(TaFlags::INSTANCE_KEEP_ALIVE);

const MAX_PTA_SESSIONS_PER_TASK: usize = 100;

struct PtaBusyGuard<'a> {
    task: &'a Task,
    pta: PseudoTa,
}

impl Drop for PtaBusyGuard<'_> {
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

impl Task {
    /// Try to mark a non-concurrent PTA as busy, returning a guard that clears
    /// the busy state on drop. This gates both session opening and command
    /// invocation.
    ///
    /// Returns `Ok(None)` for PTAs flagged `TaFlags::CONCURRENT` (no gating).
    /// For a non-concurrent PTA that is busy, returns `Err(Busy)` immediately.
    fn try_set_busy(&self, pta: PseudoTa) -> Result<Option<PtaBusyGuard<'_>>, TeeResult> {
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

    fn close_session(_task: &Task, _session_id: u32) {
        // System PTA has no per-session state
    }

    /// Handle a command of the system PTA.
    ///
    /// See `Cleanup` for the returned rollback; most commands have no cleanup.
    fn invoke_command(
        task: &Task,
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
    fn derive_ta_unique_key(task: &Task, params: &UteeParams) -> Result<(), TeeResult> {
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
            let extra_data_ptr = UserConstPtr::<u8>::from_usize(extra_data_addr.trunc());
            extra_data_ptr
                .to_owned_slice(extra_data_size)
                .ok_or(TeeResult::BadParameters)?
        };

        // Unlike OP-TEE OS, `UserMutPtr` (and `UserConstPtr`) in LiteBox ensure this
        // pointer can never be used to access normal-world memory. That is, we don't
        // need extra security check for detecting key leakage here.
        let subkey_ptr = UserMutPtr::<u8>::from_usize(subkey_addr.trunc());

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
    fn huk_subkey_derive(
        task: &Task,
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

    fn map_zi(task: &Task, params: &mut UteeParams) -> Result<Cleanup, TeeResult> {
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

    fn unmap(task: &Task, params: &UteeParams) -> Result<(), TeeResult> {
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

        task.sys_munmap(UserMutPtr::<u8>::from_usize(addr), size)
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
