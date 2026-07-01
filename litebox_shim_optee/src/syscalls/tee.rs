// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of generic TEE related syscalls

use litebox::mm::linux::{NonZeroAddress, NonZeroPageSize, PAGE_SIZE};
use litebox::path::Arg;
use litebox::platform::RawMutPointer;
use litebox::platform::{RawConstPointer, page_mgmt::MemoryRegionPermissions};
use litebox::utils::TruncateExt;
use litebox_common_optee::{
    TeeIdentity, TeeMemoryAccessRights, TeeOrigin, TeePropSet, TeeResult, TeeUuid, UserTaPropType,
    UteeParams,
};
use num_enum::TryFromPrimitive;
use zerocopy::IntoBytes;

use crate::{
    Task, UserConstPtr, UserMutPtr,
    syscalls::{Cleanup, pta::PseudoTa},
};

#[inline]
fn align_up(addr: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two());
    addr.checked_next_multiple_of(align)
}

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

impl Task {
    /// A system call to return to the kernel. A TA calls this function when
    /// it finishes its job delivered through a TA command invocation.
    #[allow(clippy::unused_self)]
    pub fn sys_return(&self, ret: usize) -> usize {
        #[cfg(debug_assertions)]
        litebox_util_log::debug!(ret:% = ret; "sys_return");

        ret
    }

    /// A system call that a TA calls when it panics.
    ///
    /// Per OP-TEE OS behavior: when a TA panics, the kernel returns `TEE_ERROR_TARGET_DEAD`
    /// to the caller, regardless of the panic code. The panic code is logged for debugging.
    #[expect(
        clippy::unused_self,
        reason = "self was used by the old platform-threaded logging API"
    )]
    pub fn sys_panic(&self, code: usize) -> usize {
        litebox_util_log::error!(code:% = format_args!("{:#x}", code); "TA panic");

        // Return TARGET_DEAD to match OP-TEE OS behavior
        litebox_common_optee::TeeResult::TargetDead as usize
    }

    /// A system call to print out a message.
    #[expect(
        clippy::unused_self,
        reason = "self was used by the old platform-threaded logging API"
    )]
    pub fn sys_log(&self, buf: &[u8]) -> Result<(), TeeResult> {
        let msg = core::str::from_utf8(buf).map_err(|_| TeeResult::BadFormat)?;
        litebox_util_log::info!(msg:% = msg; "sys_log");
        Ok(())
    }

    /// A system call to get system, client, or TA property information.
    #[allow(clippy::too_many_arguments)]
    pub fn sys_get_property(
        &self,
        prop_set: TeePropSet,
        index: u32,
        name_buf: Option<UserMutPtr<u8>>,
        name_len: Option<UserMutPtr<u32>>,
        prop_buf: &mut [u8],
        prop_len: UserMutPtr<u32>,
        prop_type: UserMutPtr<u32>,
    ) -> Result<(), TeeResult> {
        if name_buf.is_some() || name_len.is_some() {
            #[cfg(debug_assertions)]
            todo!("return the name of a given property index");
            #[cfg(not(debug_assertions))]
            return Err(TeeResult::NotSupported);
        }
        match GpdPropertyIndex::try_from(index).unwrap_or(GpdPropertyIndex::None) {
            GpdPropertyIndex::ClientIdentity => {
                if prop_set != TeePropSet::CurrentClient {
                    return Err(TeeResult::BadParameters);
                }
                if prop_buf.len() < core::mem::size_of::<TeeIdentity>() {
                    return Err(TeeResult::ShortBuffer);
                }
                let identity = self.current_client_identity();
                prop_buf[..core::mem::size_of::<TeeIdentity>()]
                    .copy_from_slice(identity.as_bytes());
                prop_len
                    .write_at_offset(0, core::mem::size_of::<TeeIdentity>().trunc())
                    .ok_or(TeeResult::AccessDenied)?;
                prop_type
                    .write_at_offset(0, UserTaPropType::Identity as u32)
                    .ok_or(TeeResult::AccessDenied)?;
                Ok(())
            }
            GpdPropertyIndex::ClientEndian => {
                const CLIENT_ENDIAN_LITTLE: u32 = 0;
                if prop_set != TeePropSet::CurrentClient {
                    return Err(TeeResult::BadParameters);
                }
                if prop_buf.len() < core::mem::size_of::<u32>() {
                    return Err(TeeResult::ShortBuffer);
                }
                prop_buf[..core::mem::size_of::<u32>()]
                    .copy_from_slice(&CLIENT_ENDIAN_LITTLE.to_le_bytes());
                prop_len
                    .write_at_offset(0, core::mem::size_of::<u32>().trunc())
                    .ok_or(TeeResult::AccessDenied)?;
                prop_type
                    .write_at_offset(0, UserTaPropType::U32 as u32)
                    .ok_or(TeeResult::AccessDenied)?;
                Ok(())
            }
            GpdPropertyIndex::CurrentTaUuid => {
                if prop_set != TeePropSet::CurrentTa {
                    return Err(TeeResult::BadParameters);
                }
                if prop_buf.len() < core::mem::size_of::<TeeUuid>() {
                    return Err(TeeResult::ShortBuffer);
                }
                let ta_uuid = self.ta_app_id;
                prop_buf[..core::mem::size_of::<TeeUuid>()].copy_from_slice(ta_uuid.as_bytes());
                prop_len
                    .write_at_offset(0, core::mem::size_of::<TeeUuid>().trunc())
                    .ok_or(TeeResult::AccessDenied)?;
                prop_type
                    .write_at_offset(0, UserTaPropType::Uuid as u32)
                    .ok_or(TeeResult::AccessDenied)?;
                Ok(())
            }
            GpdPropertyIndex::None => Err(TeeResult::BadParameters),
        }
    }

    /// A system call to get the index of property information by its name.
    pub fn sys_get_property_name_to_index(
        prop_set: TeePropSet,
        name: &[u8],
        index: UserMutPtr<u32>,
    ) -> Result<(), TeeResult> {
        let name_str =
            core::ffi::CStr::from_bytes_with_nul(name).map_err(|_| TeeResult::BadParameters)?;
        match name_str
            .as_rust_str()
            .map_err(|_| TeeResult::BadParameters)?
        {
            "gpd.client.identity" => {
                if prop_set == TeePropSet::CurrentClient {
                    index
                        .write_at_offset(0, GpdPropertyIndex::ClientIdentity as u32)
                        .ok_or(TeeResult::AccessDenied)?;
                    Ok(())
                } else {
                    Err(TeeResult::BadParameters)
                }
            }
            "gpd.client.endian" => {
                if prop_set == TeePropSet::CurrentClient {
                    index
                        .write_at_offset(0, GpdPropertyIndex::ClientEndian as u32)
                        .ok_or(TeeResult::AccessDenied)?;
                    Ok(())
                } else {
                    Err(TeeResult::BadParameters)
                }
            }
            "gpd.ta.appID" => {
                if prop_set == TeePropSet::CurrentTa {
                    index
                        .write_at_offset(0, GpdPropertyIndex::CurrentTaUuid as u32)
                        .ok_or(TeeResult::AccessDenied)?;
                    Ok(())
                } else {
                    Err(TeeResult::BadParameters)
                }
            }
            _ => Err(TeeResult::ItemNotFound),
        }
    }

    /// A system call to open a session with a PTA or another user-mode TA.
    pub fn sys_open_ta_session(
        &self,
        ta_uuid: TeeUuid,
        _cancel_req_to: u32,
        usr_params: UteeParams,
        ta_sess_id: UserMutPtr<u32>,
        ret_orig: UserMutPtr<TeeOrigin>,
    ) -> Result<(), TeeResult> {
        // `cancel_req_to` is a timeout value. Ignore it for now.
        if let Some(pta) = PseudoTa::from_uuid(&ta_uuid) {
            // `open_ta_session` syscall lets a user-mode TA open a session to a PTA which provides
            // several import services (it works as a proxy for extra system calls).
            let session_id = self.open_pta_session(pta, &usr_params)?;
            if ta_sess_id.write_at_offset(0, session_id).is_none() {
                self.close_pta_session(session_id);
                return Err(TeeResult::AccessDenied);
            }
            // Best-effort write-back of the return origin, matching OP-TEE OS
            // (`syscall_open_ta_session`): the copy result is ignored.
            let _ = ret_orig.write_at_offset(0, TeeOrigin::Tee);
            Ok(())
        } else {
            // `open_ta_session` syscall lets a user-mode TA open a session to another user-mode TA
            // (using its UUID) to leverage its functions.
            // TODO: if this TA hasn't been loaded, we need to load its ELF and prepare its stack (hopefully
            // in a separate page table). We can do this here or at `sys_invoke_ta_command` (in a lazy manner).
            #[cfg(debug_assertions)]
            todo!("support inter TA interaction");
            #[cfg(not(debug_assertions))]
            Err(TeeResult::NotSupported)
        }
    }

    /// A system call to close an opened session.
    #[allow(clippy::unnecessary_wraps)]
    pub fn sys_close_ta_session(&self, ta_sess_id: u32) -> Result<(), TeeResult> {
        if self.close_pta_session(ta_sess_id).is_some() {
            Ok(())
        } else {
            #[cfg(debug_assertions)]
            todo!("support inter TA interaction");
            #[cfg(not(debug_assertions))]
            Err(TeeResult::NotSupported)
        }
    }

    /// A system call to invoke a command on a TA.
    ///
    /// Returns `Cleanup` that the caller must run if the surrounding
    /// dispatch then fails.
    pub fn sys_invoke_ta_command(
        &self,
        ta_sess_id: u32,
        _cancel_req_to: u32,
        cmd_id: u32,
        params: &mut UteeParams,
        ret_orig: UserMutPtr<TeeOrigin>,
    ) -> Result<Cleanup, TeeResult> {
        // `cancel_req_to` is a timeout value. Ignore it for now.
        if let Some(pta) = self.pta_for_session(ta_sess_id) {
            let cleanup = pta.invoke_command(self, cmd_id, params)?;
            // Best-effort write-back of the return origin, matching OP-TEE OS
            // (`syscall_invoke_ta_command`): the copy result is ignored.
            let _ = ret_orig.write_at_offset(0, TeeOrigin::Tee);
            Ok(cleanup)
        } else {
            #[cfg(debug_assertions)]
            todo!("support inter TA interaction");
            #[cfg(not(debug_assertions))]
            Err(TeeResult::NotSupported)
        }
    }

    /// A system call to check the memory permissions of a given buffer.
    pub fn sys_check_access_rights(
        &self,
        flags: TeeMemoryAccessRights,
        buf: UserConstPtr<u8>,
        len: usize,
    ) -> Result<(), TeeResult> {
        // Ignore the unknown bits of `TeeMemoryAccessRights` for now.
        let flags = TeeMemoryAccessRights::from_bits_truncate(flags.bits());

        if flags.contains(TeeMemoryAccessRights::TEE_MEMORY_ACCESS_NONSECURE)
            && flags.contains(TeeMemoryAccessRights::TEE_MEMORY_ACCESS_SECURE)
        {
            // `TEE_MEMORY_ACCESS_NONSECURE` and `TEE_MEMORY_ACCESS_SECURE` are mutually exclusive.
            return Err(TeeResult::AccessDenied);
        }

        let start = NonZeroAddress::<PAGE_SIZE>::new(align_down(buf.as_usize(), PAGE_SIZE))
            .ok_or(TeeResult::AccessConflict)?;
        let aligned_len = {
            let len = len
                .checked_add(buf.as_usize() - align_down(buf.as_usize(), PAGE_SIZE))
                .ok_or(TeeResult::AccessConflict)?;
            NonZeroPageSize::<PAGE_SIZE>::new(
                align_up(len, PAGE_SIZE).ok_or(TeeResult::AccessConflict)?,
            )
            .ok_or(TeeResult::AccessConflict)?
        };
        // Reject ranges where `start + aligned_len` would wrap, so downstream
        // permission lookups don't operate on a truncated address range.
        let _ = start
            .as_usize()
            .checked_add(aligned_len.as_usize())
            .ok_or(TeeResult::AccessConflict)?;
        if let Some(perms) = self.global.pm.get_memory_permissions(start, aligned_len) {
            if (flags.contains(TeeMemoryAccessRights::TEE_MEMORY_ACCESS_READ)
                && !perms.contains(MemoryRegionPermissions::READ))
                || (flags.contains(TeeMemoryAccessRights::TEE_MEMORY_ACCESS_WRITE)
                    && !perms.contains(MemoryRegionPermissions::WRITE))
                || (!flags.contains(TeeMemoryAccessRights::TEE_MEMORY_ACCESS_ANY_OWNER)
                    && perms.contains(MemoryRegionPermissions::SHARED))
            {
                // TODO: currently, we don't consider the following flags:
                // - `TEE_MEMORY_ACCESS_NONSECURE`: should be non-secure (VTL0) mapping
                // - `TEE_MEMORY_ACCESS_SECURE`: should be secure (VTL1) mapping
                Err(TeeResult::AccessDenied)
            } else {
                Ok(())
            }
        } else {
            Err(TeeResult::AccessDenied)
        }
    }
}

/// Global Platform Device property indexes.
/// Note. The specification does not define constant values, so these are internal representations.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum GpdPropertyIndex {
    ClientIdentity = 0xffff_0000,
    ClientEndian = 0xffff_0001,
    CurrentTaUuid = 0xffff_0002,
    None = 0xffff_ffff,
}
