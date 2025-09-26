//! Implementation of generic TEE related syscalls

use litebox::mm::linux::{NonZeroAddress, NonZeroPageSize, PAGE_SIZE};
use litebox::path::Arg;
use litebox::platform::RawMutPointer;
use litebox::platform::{RawConstPointer, page_mgmt::MemoryRegionPermissions};
use litebox_common_optee::{
    TeeIdentity, TeeLogin, TeeMemoryAccessRights, TeeOrigin, TeePropSet, TeeResult, TeeUuid,
    UserTaPropType, UteeParams,
};

use crate::{
    litebox_page_manager,
    syscalls::pta::{
        close_pta_session, get_pta_session_id, handle_system_pta_command, is_pta, is_pta_session,
    },
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

/// A system call to return to the kernel. A TA calls this function when
/// it finishes its job delivered through a TA command invocation.
pub fn sys_return(ret: usize) -> ! {
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "sys_return: ret {}",
        ret
    );

    litebox_runner_command_dispatcher::command_dispatcher().return_to_command_dispatcher()
}

/// A system call to print out a message.
pub fn sys_log(buf: &[u8]) -> Result<(), TeeResult> {
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "sys_log: buf {:#x}",
        buf.as_ptr() as usize
    );
    let msg = core::str::from_utf8(buf).map_err(|_| TeeResult::BadFormat)?;
    litebox::log_println!(litebox_platform_multiplex::platform(), "{}", msg);
    Ok(())
}

/// A system call that a TA calls when it panics.
pub fn sys_panic(code: usize) -> ! {
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "panic with code {}",
        code,
    );

    litebox_runner_command_dispatcher::command_dispatcher().return_to_command_dispatcher()
}

// TODO: replace this with a proper implementation
const GPD_CLIENT_IDENTITY: u32 = 0xffff_0000;

/// A system call to get system, client, or TA property information.
pub fn sys_get_property(
    prop_set: TeePropSet,
    index: u32,
    name_buf: Option<&mut [u8]>,
    name_len: Option<crate::MutPtr<u32>>,
    prop_buf: &mut [u8],
    prop_len: crate::MutPtr<u32>,
    prop_type: crate::MutPtr<u32>,
) -> Result<(), TeeResult> {
    if name_buf.is_some() && name_len.is_some() {
        todo!("return the name of a given property index")
    }
    match index {
        GPD_CLIENT_IDENTITY => {
            if prop_set != TeePropSet::CurrentClient {
                return Err(TeeResult::BadParameters);
            }
            if prop_buf.len() < core::mem::size_of::<TeeIdentity>() {
                return Err(TeeResult::ShortBuffer);
            }
            // for now, return an arbitrary user identity
            let identity = TeeIdentity {
                login: TeeLogin::User,
                uuid: TeeUuid::default(),
            };
            prop_buf.copy_from_slice(unsafe {
                core::slice::from_raw_parts(
                    (&raw const identity).cast::<u8>(),
                    core::mem::size_of::<TeeIdentity>(),
                )
            });
            unsafe {
                prop_len
                    .write_at_offset(
                        0,
                        u32::try_from(core::mem::size_of::<TeeIdentity>()).unwrap(),
                    )
                    .ok_or(TeeResult::AccessDenied)?;
                prop_type
                    .write_at_offset(0, UserTaPropType::Identity as u32)
                    .ok_or(TeeResult::AccessDenied)?;
            }
            Ok(())
        }
        _ => Err(TeeResult::BadParameters),
    }
}

/// A system call to get the index of property information by its name.
pub fn sys_get_property_name_to_index(
    prop_set: TeePropSet,
    name: &[u8],
    index: crate::MutPtr<u32>,
) -> Result<(), TeeResult> {
    let name_str =
        core::ffi::CStr::from_bytes_with_nul(name).map_err(|_| TeeResult::BadParameters)?;
    match name_str
        .as_rust_str()
        .map_err(|_| TeeResult::BadParameters)?
    {
        "gpd.client.identity" => {
            if prop_set == TeePropSet::CurrentClient {
                unsafe {
                    index
                        .write_at_offset(0, GPD_CLIENT_IDENTITY)
                        .ok_or(TeeResult::AccessDenied)?;
                }
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
    ta_sess_id: crate::MutPtr<u32>,
    ret_orig: crate::MutPtr<TeeOrigin>,
) -> Result<(), TeeResult> {
    // `cancel_req_to` is a timeout value. Ignore it for now.
    unsafe {
        ret_orig
            .write_at_offset(0, TeeOrigin::Tee)
            .ok_or(TeeResult::AccessDenied)?;
    }
    if is_pta(&ta_uuid, &usr_params) {
        // `open_ta_session` syscall lets a user-mode TA open a session to a PTA which provides
        // several import services (it works as a proxy for extra system calls).
        unsafe {
            ta_sess_id
                .write_at_offset(0, get_pta_session_id())
                .ok_or(TeeResult::AccessDenied)?;
        }
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
    ta_sess_id: u32,
    _cancel_req_to: u32,
    cmd_id: u32,
    params: UteeParams,
    ret_orig: crate::MutPtr<TeeOrigin>,
) -> Result<(), TeeResult> {
    // `cancel_req_to` is a timeout value. Ignore it for now.
    unsafe {
        ret_orig
            .write_at_offset(0, TeeOrigin::Tee)
            .ok_or(TeeResult::AccessDenied)?;
    }
    if is_pta_session(ta_sess_id) {
        // TODO: check whether `ta_sess_id` is associated with the system PTA.
        handle_system_pta_command(cmd_id, &params)
    } else {
        todo!("support inter TA interaction")
    }
}

/// A system call to check the memory permissions of a given buffer.
pub fn sys_check_access_rights(
    flags: TeeMemoryAccessRights,
    buf: crate::ConstPtr<u8>,
    len: usize,
) -> Result<(), TeeResult> {
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
    if let Some(perms) = litebox_page_manager().get_memory_permissions(start, aligned_len) {
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
