use crate::UserMutPtr;
use litebox::mm::linux::PAGE_SIZE;
use litebox::platform::{RawConstPointer, RawMutPointer};
use litebox_common_linux::{MapFlags, ProtFlags};
use litebox_common_optee::{LdelfMapFlags, TeeResult, TeeUuid};

#[inline]
fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    addr & !(align - 1)
}

const DUMMY_HANDLE: u32 = 1;

/// OP-TEE's syscall to map zero-initialized memory with padding.
/// This function pads `pad_begin` bytes before and `pad_end` bytes after the
/// zero-initialized `num_bytes` bytes. `va` can contain a hint address which
/// is `pad_begin` bytes lower than the starting address of the memory region.
/// (`start - pad_begin`, ...,  `start`, ..., `start + num_bytes`, ..., `start + num_bytes + pad_end`)
/// Memory regions between `start - pad_begin` and `start` and between
/// `start + num_bytes` and `start + num_bytes + pad_end` are reserved and must not be used.
pub fn sys_map_zi(
    va: UserMutPtr<usize>,
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

    let accept_flags = LdelfMapFlags::LDELF_MAP_FLAG_SHAREABLE;
    if flags.bits() & !accept_flags.bits() != 0 {
        return Err(TeeResult::BadParameters);
    }
    // TODO: Check whether flags contains `LDELF_MAP_FLAG_SHAREABLE` once we support sharing of file-based mappings.

    let total_size = num_bytes
        .checked_add(pad_begin)
        .and_then(|t| t.checked_add(pad_end))
        .ok_or(TeeResult::BadParameters)?
        .next_multiple_of(PAGE_SIZE);
    if (*addr).checked_add(total_size).is_none() {
        return Err(TeeResult::BadParameters);
    }
    // `sys_map_zi` always creates read/writeable mapping
    let prot = ProtFlags::PROT_READ_WRITE;
    let flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED;

    // OP-TEE maintains data structures to ensure padded regions are not used. It does not use page tables because
    // it targets systems with inefficient CPU and MMU. Instead of reproducing OP-TEE's behavior, we create
    // mappings with `PROT_NONE` for padded regions to prevent others from using them.
    let addr = crate::syscalls::mm::sys_mmap(*addr, total_size, ProtFlags::PROT_NONE, flags, -1, 0)
        .map_err(|_| TeeResult::OutOfMemory)?;
    let padded_start = addr.as_usize() + pad_begin;
    if crate::syscalls::mm::sys_mprotect(
        UserMutPtr::from_usize(align_down(padded_start, PAGE_SIZE)),
        (num_bytes + padded_start - align_down(padded_start, PAGE_SIZE))
            .next_multiple_of(PAGE_SIZE),
        prot,
    )
    .is_err()
    {
        let _ = crate::syscalls::mm::sys_munmap(addr, total_size).ok();
        return Err(TeeResult::OutOfMemory);
    }
    unsafe {
        let _ = va.write_at_offset(0, padded_start);
    }
    Ok(())
}

/// OP-TEE's syscall to open a TA binary.
#[expect(clippy::unnecessary_wraps)]
pub fn sys_open_bin(ta_uuid: TeeUuid, handle: UserMutPtr<u32>) -> Result<(), TeeResult> {
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

/// OP-TEE's syscall to close a TA binary.
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

    // TODO: unmap all mappings related to `handle` which are no longer used.

    Ok(())
}

/// OP-TEE's syscall to map a portion of a TA binary into memory.
pub fn sys_map_bin(
    va: UserMutPtr<usize>,
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

    let accept_flags = LdelfMapFlags::LDELF_MAP_FLAG_SHAREABLE
        | LdelfMapFlags::LDELF_MAP_FLAG_WRITEABLE
        | LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE;
    if flags.bits() & !accept_flags.bits() != 0 {
        return Err(TeeResult::BadParameters);
    }

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

    let total_size = num_bytes
        .checked_add(pad_begin)
        .and_then(|t| t.checked_add(pad_end))
        .ok_or(TeeResult::BadParameters)?
        .next_multiple_of(PAGE_SIZE);
    if (*addr).checked_add(total_size).is_none() {
        return Err(TeeResult::BadParameters);
    }
    let flags_internal = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED;
    // TODO: on Arm, check whether flags contains `LDELF_MAP_FLAG_SHAREABLE` to control cache behaviors

    // Currently, we do not support TA binary mapping. So, we create an anonymous mapping and copy
    // the content of the TA binary into it.
    let addr = crate::syscalls::mm::sys_mmap(
        *addr,
        total_size,
        ProtFlags::PROT_NONE,
        flags_internal,
        -1,
        0,
    )
    .map_err(|_| TeeResult::OutOfMemory)?;
    let padded_start = addr.as_usize() + pad_begin;
    if crate::syscalls::mm::sys_mprotect(
        UserMutPtr::from_usize(align_down(padded_start, PAGE_SIZE)),
        (num_bytes + padded_start - align_down(padded_start, PAGE_SIZE))
            .next_multiple_of(PAGE_SIZE),
        ProtFlags::PROT_READ_WRITE,
    )
    .is_err()
    {
        let _ = crate::syscalls::mm::sys_munmap(addr, total_size).ok();
        return Err(TeeResult::OutOfMemory);
    }

    unsafe {
        if crate::read_ta_bin(UserMutPtr::from_usize(padded_start), offs, num_bytes).is_none() {
            return Err(TeeResult::ShortBuffer);
        }
    }

    let mut prot = ProtFlags::PROT_READ;
    if flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_WRITEABLE) {
        prot |= ProtFlags::PROT_WRITE;
    } else if flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE) {
        prot |= ProtFlags::PROT_EXEC;
    }
    if crate::syscalls::mm::sys_mprotect(
        UserMutPtr::from_usize(align_down(padded_start, PAGE_SIZE)),
        (num_bytes + padded_start - align_down(padded_start, PAGE_SIZE))
            .next_multiple_of(PAGE_SIZE),
        prot,
    )
    .is_err()
    {
        let _ = crate::syscalls::mm::sys_munmap(addr, total_size).ok();
        return Err(TeeResult::OutOfMemory);
    }

    if offs == PAGE_SIZE
        && flags.contains(LdelfMapFlags::LDELF_MAP_FLAG_EXECUTABLE)
        && crate::get_ta_base_addr().is_none()
    {
        crate::set_ta_base_addr(padded_start);
    }

    unsafe {
        let _ = va.write_at_offset(0, padded_start);
    }

    Ok(())
}

/// OP-TEE's syscall to copy data from the TA binary to memory.
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
        crate::read_ta_bin(UserMutPtr::from_usize(dst), offs, num_bytes)
            .ok_or(TeeResult::ShortBuffer)?;
    }

    Ok(())
}
