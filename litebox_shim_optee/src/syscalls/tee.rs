use litebox::mm::linux::{NonZeroAddress, NonZeroPageSize, PAGE_SIZE};
use litebox::platform::{RawConstPointer, page_mgmt::MemoryRegionPermissions};
use litebox_common_optee::{TeeMemoryAccessRights, TeeResult};

#[cfg(feature = "platform_linux_userland")]
use litebox::platform::ThreadLocalStorageProvider;
#[cfg(feature = "platform_linux_userland")]
use litebox::platform::ThreadProvider;

use crate::litebox_page_manager;

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

// placeholder
pub fn sys_return(ret: usize) -> ! {
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "sys_return: ret {}",
        ret
    );

    cfg_if::cfg_if! {
        if #[cfg(feature = "platform_linux_userland")] {
            let tid = litebox_platform_multiplex::platform()
                .with_thread_local_storage_mut(|tls| tls.current_task.tid);
            #[allow(clippy::cast_sign_loss)]
            let session_id = tid as u32;
            crate::optee_command_dispatcher(session_id, true);
        } else if #[cfg(feature = "platform_lvbs")] {
            todo!("switch to VTL0");
        } else {
            compile_error!(r##"No platform specified."##);
        }
    }
}

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

// placeholder
pub fn sys_panic(code: usize) -> ! {
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "panic with code {}",
        code,
    );

    cfg_if::cfg_if! {
        if #[cfg(feature = "platform_linux_userland")] {
            litebox_platform_multiplex::platform().terminate_thread(i32::try_from(code).unwrap_or(0));
        } else if #[cfg(feature = "platform_lvbs")] {
            todo!("switch to VTL0");
        } else {
            compile_error!(r##"No platform specified."##);
        }
    }
}

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
