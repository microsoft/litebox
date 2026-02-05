// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of generic TEE related syscalls

use litebox::mm::linux::{NonZeroAddress, NonZeroPageSize, PAGE_SIZE};
use litebox::path::Arg;
use litebox::platform::RawMutPointer;
use litebox::platform::{RawConstPointer, page_mgmt::MemoryRegionPermissions};
use litebox_common_optee::{
    TeeIdentity, TeeMemoryAccessRights, TeeOrigin, TeePropSet, TeeResult, TeeUuid, UserTaPropType,
    UteeParams,
};
use num_enum::TryFromPrimitive;
use zerocopy::IntoBytes;

use crate::{
    Task, UserConstPtr, UserMutPtr,
    syscalls::pta::{close_pta_session, is_pta, is_pta_session},
};

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

impl Task {
    /// A system call to return to the kernel. A TA calls this function when
    /// it finishes its job delivered through a TA command invocation.
    pub fn sys_return(&self, ret: usize) -> usize {
        #[cfg(debug_assertions)]
        litebox::log_println!(self.global.platform, "sys_return: ret {}", ret);

        ret
    }

    /// A system call that a TA calls when it panics.
    ///
    /// Per OP-TEE OS behavior: when a TA panics, the kernel returns `TEE_ERROR_TARGET_DEAD`
    /// to the caller, regardless of the panic code. The panic code is logged for debugging.
    pub fn sys_panic(&self, code: usize) -> usize {
        litebox::log_println!(self.global.platform, "TA panic with code {:#x}", code,);

        // Return TARGET_DEAD to match OP-TEE OS behavior
        litebox_common_optee::TeeResult::TargetDead as usize
    }

    /// A system call to print out a message.
    pub fn sys_log(&self, buf: &[u8]) -> Result<(), TeeResult> {
        let msg = core::str::from_utf8(buf).map_err(|_| TeeResult::BadFormat)?;
        litebox::log_println!(self.global.platform, "{}", msg);
        Ok(())
    }

    /// A system call to get system, client, or TA property information.
    #[allow(clippy::too_many_arguments)]
    pub fn sys_get_property(
        &self,
        prop_set: TeePropSet,
        index: u32,
        name_buf: Option<&mut [u8]>,
        name_len: Option<UserMutPtr<u32>>,
        prop_buf: &mut [u8],
        prop_len: UserMutPtr<u32>,
        prop_type: UserMutPtr<u32>,
    ) -> Result<(), TeeResult> {
        if name_buf.is_some() && name_len.is_some() {
            todo!("return the name of a given property index")
        }
        match GpdPropertyIndex::try_from(index).unwrap_or(GpdPropertyIndex::None) {
            GpdPropertyIndex::ClientIdentity => {
                if prop_set != TeePropSet::CurrentClient {
                    return Err(TeeResult::BadParameters);
                }
                if prop_buf.len() < core::mem::size_of::<TeeIdentity>() {
                    return Err(TeeResult::ShortBuffer);
                }
                let identity = self.client_identity;
                prop_buf.copy_from_slice(identity.as_bytes());
                prop_len
                    .write_at_offset(
                        0,
                        u32::try_from(core::mem::size_of::<TeeIdentity>()).unwrap(),
                    )
                    .ok_or(TeeResult::AccessDenied)?;
                prop_type
                    .write_at_offset(0, UserTaPropType::Identity as u32)
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
                prop_buf.copy_from_slice(ta_uuid.as_bytes());
                prop_len
                    .write_at_offset(0, u32::try_from(core::mem::size_of::<TeeUuid>()).unwrap())
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
            _ => todo!(),
        }
    }

    /// A system call to open a session with a PTA or another user-mode TA.
    pub fn sys_open_ta_session(
        ta_uuid: TeeUuid,
        _cancel_req_to: u32,
        usr_params: UteeParams,
        ta_sess_id: UserMutPtr<u32>,
        ret_orig: UserMutPtr<TeeOrigin>,
    ) -> Result<(), TeeResult> {
        // `cancel_req_to` is a timeout value. Ignore it for now.
        ret_orig
            .write_at_offset(0, TeeOrigin::Tee)
            .ok_or(TeeResult::AccessDenied)?;
        if is_pta(&ta_uuid, &usr_params) {
            // `open_ta_session` syscall lets a user-mode TA open a session to a PTA which provides
            // several import services (it works as a proxy for extra system calls).
            ta_sess_id
                .write_at_offset(0, crate::SessionIdPool::get_pta_session_id())
                .ok_or(TeeResult::AccessDenied)?;
            Ok(())
        } else {
            // `open_ta_session` syscall lets a user-mode TA open a session to another user-mode TA
            // (using its UUID) to leverage its functions.
            // TODO: if this TA hasn't been loaded, we need to load its ELF and prepare its stack (hopefully
            // in a separate page table). We can do this here or at `sys_invoke_ta_command` (in a lazy manner).
            todo!("support inter TA interaction")
        }
    }

    /// A system call to close an opened session.
    #[allow(clippy::unnecessary_wraps)]
    pub fn sys_close_ta_session(ta_sess_id: u32) -> Result<(), TeeResult> {
        if is_pta_session(ta_sess_id) {
            close_pta_session(ta_sess_id);
            Ok(())
        } else {
            todo!("support inter TA interaction")
        }
    }

    /// A system call to invoke a command on a TA.
    pub fn sys_invoke_ta_command(
        &self,
        ta_sess_id: u32,
        _cancel_req_to: u32,
        cmd_id: u32,
        params: UteeParams,
        ret_orig: UserMutPtr<TeeOrigin>,
    ) -> Result<(), TeeResult> {
        // `cancel_req_to` is a timeout value. Ignore it for now.
        ret_orig
            .write_at_offset(0, TeeOrigin::Tee)
            .ok_or(TeeResult::AccessDenied)?;
        if is_pta_session(ta_sess_id) {
            // TODO: check whether `ta_sess_id` is associated with the system PTA.
            self.handle_system_pta_command(cmd_id, &params)
        } else {
            todo!("support inter TA interaction")
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
            NonZeroPageSize::<PAGE_SIZE>::new(align_up(len, PAGE_SIZE))
                .ok_or(TeeResult::AccessConflict)?
        };
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
    CurrentTaUuid = 0xffff_0001,
    None = 0xffff_ffff,
}
