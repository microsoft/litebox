use litebox::mm::linux::PAGE_SIZE;
use litebox::platform::{RawConstPointer, RawMutPointer};
use litebox_common_linux::{MapFlags, ProtFlags};
use litebox_common_optee::{LdelfMapFlags, TeeResult, TeeUuid};

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}

const DUMMY_HANDLE: u32 = 1;

pub fn sys_map_zi(
    va: crate::MutPtr<usize>,
    num_bytes: usize,
    pad_begin: usize,
    pad_end: usize,
    flags: LdelfMapFlags,
) -> Result<(), TeeResult> {
    let Some(addr) = (unsafe { va.read_at_offset(0) }) else {
        return Err(TeeResult::BadParameters);
    };

    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "sys_map_zi: va {:#x} (addr {:#x}), num_bytes {}, flags {:#x}",
        va.as_usize(),
        *addr,
        num_bytes,
        flags
    );

    if flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_WRITEABLE)
        || flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE)
    {
        return Err(TeeResult::BadParameters);
    }

    let total_size = align_up(
        num_bytes
            .checked_add(pad_begin)
            .and_then(|t| t.checked_add(pad_end))
            .ok_or(TeeResult::BadParameters)?,
        PAGE_SIZE,
    );
    if (*addr).checked_add(total_size).is_none() {
        return Err(TeeResult::BadParameters);
    }
    let prot = ProtFlags::PROT_READ_WRITE;
    let flags = if flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_SHAREABLE) {
        MapFlags::MAP_SHARED
    } else {
        MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED
    };

    match crate::syscalls::mm::sys_mmap(*addr, total_size, prot, flags, -1, 0) {
        Ok(addr) => {
            unsafe {
                let _ = va.write_at_offset(0, addr.as_usize() + pad_begin);
            }
            Ok(())
        }
        Err(_) => Err(TeeResult::OutOfMemory),
    }
}

pub fn sys_unmap(_va: crate::MutPtr<u8>, _num_bytes: usize) -> Result<(), TeeResult> {
    todo!("implement sys_unmap which is aware of pad_begin and pad_end");
}

#[expect(clippy::unnecessary_wraps)]
pub fn sys_open_bin(ta_uuid: TeeUuid, handle: crate::MutPtr<u32>) -> Result<(), TeeResult> {
    // TODO: This function requires an RPC from the secure world to the normal world to
    // open the TA binary identified by `ta_uuid` and return a handle to it in `handle`.
    // Since we don't have RPC implementation yet, we just return a dummy handle value.
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "sys_open_bin: ta_uuid {:?}, handle {:#x}",
        ta_uuid,
        handle.as_usize()
    );

    unsafe {
        let _ = handle.write_at_offset(0, DUMMY_HANDLE); // TODO: use real handle
    }

    Ok(())
}

#[expect(clippy::unnecessary_wraps)]
pub fn sys_close_bin(handle: u32) -> Result<(), TeeResult> {
    // TODO: This function requires an RPC from the secure world to the normal world to
    // close the TA binary identified by `handle`.
    // Since we don't have RPC implementation yet, we just do nothing.
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "sys_close_bin: handle {}",
        handle
    );

    assert!(handle == DUMMY_HANDLE, "invalid handle");
    // TODO: check whether `handle` is valid

    Ok(())
}

pub fn sys_map_bin(
    va: crate::MutPtr<usize>,
    num_bytes: usize,
    handle: u32,
    offs: usize,
    pad_begin: usize,
    pad_end: usize,
    flags: LdelfMapFlags,
) -> Result<(), TeeResult> {
    let Some(addr) = (unsafe { va.read_at_offset(0) }) else {
        return Err(TeeResult::BadParameters);
    };

    // TODO: this function requires an RPC from the secure world to the normal world to
    // map a portion of the TA binary identified by `handle` at offset `offs` into
    // the secure world. Since we don't have RPC implementation yet, we use a contained
    // TA binary to do this.
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "sys_map_bin: va {:#x} (addr {:#x}), num_bytes {}, handle {}, offs {}, pad_begin {}, pad_end {}, flags {:#x}",
        va.as_usize(),
        *addr,
        num_bytes,
        handle,
        offs,
        pad_begin,
        pad_end,
        flags
    );

    assert!(handle == DUMMY_HANDLE, "invalid handle");
    // TODO: check whether `handle` is valid

    if flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_SHAREABLE)
        && flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_WRITEABLE)
    {
        return Err(TeeResult::BadParameters);
    }
    if flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE)
        && flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_WRITEABLE)
    {
        return Err(TeeResult::BadParameters);
    }

    let total_size = align_up(
        num_bytes
            .checked_add(pad_begin)
            .and_then(|t| t.checked_add(pad_end))
            .ok_or(TeeResult::BadParameters)?,
        PAGE_SIZE,
    );
    if (*addr).checked_add(total_size).is_none() {
        return Err(TeeResult::BadParameters);
    }
    // TODO: check whether shared mapping is needed
    let flags_internal = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED;

    match crate::syscalls::mm::sys_mmap(
        *addr,
        total_size,
        ProtFlags::PROT_READ_WRITE,
        flags_internal,
        -1,
        0,
    ) {
        Ok(addr) => {
            let padded_addr = addr.as_usize() + pad_begin;
            unsafe {
                if crate::read_ta_bin(padded_addr as *mut u8, offs, num_bytes).is_none() {
                    return Err(TeeResult::ShortBuffer);
                }
            }

            let mut prot = ProtFlags::PROT_READ;
            if flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_WRITEABLE) {
                prot |= ProtFlags::PROT_WRITE;
            } else if flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE) {
                prot |= ProtFlags::PROT_EXEC;
            }
            crate::syscalls::mm::sys_mprotect(addr, total_size, prot)
                .expect("sys_map_bin: failed to set memory protection");

            if offs == PAGE_SIZE
                && flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE)
                && crate::get_ta_base_addr().is_none()
            {
                crate::set_ta_base_addr(padded_addr);
            }

            unsafe {
                let _ = va.write_at_offset(0, padded_addr);
            }

            Ok(())
        }
        Err(_) => Err(TeeResult::OutOfMemory),
    }
}

pub fn sys_cp_from_bin(
    dst: usize,
    offs: usize,
    num_bytes: usize,
    handle: u32,
) -> Result<(), TeeResult> {
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "sys_cp_from_bin: dst {:#x}, offs {}, num_bytes {}, handle {}",
        dst,
        offs,
        num_bytes,
        handle,
    );

    unsafe {
        if crate::read_ta_bin(dst as *mut u8, offs, num_bytes).is_none() {
            return Err(TeeResult::ShortBuffer);
        }
    }

    Ok(())
}

pub fn sys_set_prot(
    va: crate::MutPtr<usize>,
    num_bytes: usize,
    flags: LdelfMapFlags,
) -> Result<(), TeeResult> {
    let Some(addr) = (unsafe { va.read_at_offset(0) }) else {
        return Err(TeeResult::BadParameters);
    };
    #[cfg(debug_assertions)]
    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "sys_set_prot: va {:#x} (addr {:#x}), num_bytes {}, flags {:#x}",
        va.as_usize(),
        *addr,
        num_bytes,
        flags
    );
    Ok(())
}
