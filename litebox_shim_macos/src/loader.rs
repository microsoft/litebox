// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Load an AOT-rewritten Mach-O and finalize its syscall/TLS gates.
//! Shared shim state owns the guest mappings and releases them when its last
//! owner is dropped.

use crate::ShimPlatform;
use alloc::{ffi::CString, vec, vec::Vec};
use core::ops::Range;
use litebox::mm::{
    PageManager,
    linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize},
};
use litebox::platform::page_mgmt::MemoryRegionPermissions as Permissions;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_macos::{PAGE_SIZE, PtRegs, loader::MachoParsedFile, user_pointers::UserPtrMut};
use litebox_syscall_rewriter::{
    TargetHost,
    macho::{CodeMetadata, Rewriter},
};

pub use litebox_common_macos::loader::MachoLoaderError;

const STACK_SIZE: usize = 1024 * 1024;

fn reserve<P: ShimPlatform>(
    pm: &PageManager<P, PAGE_SIZE>,
    len: usize,
) -> Result<usize, MachoLoaderError> {
    // SAFETY: no FIXED_ADDR: the PageManager and platform select an unused
    // range. The consuming loader's GlobalState releases it on failure/exit.
    unsafe {
        pm.create_inaccessible_pages(
            NonZeroAddress::new(P::TASK_ADDR_MIN),
            NonZeroPageSize::new(len).ok_or(MachoLoaderError::Memory)?,
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    }
    .map(|ptr| ptr.as_usize())
    .map_err(|_| MachoLoaderError::Memory)
}

fn protect<P: ShimPlatform>(
    pm: &PageManager<P, PAGE_SIZE>,
    range: Range<usize>,
    permissions: Permissions,
) -> Result<(), MachoLoaderError> {
    // SAFETY: this range was reserved in pm by this load and is not executing.
    unsafe {
        pm.change_page_permissions(
            P::RawMutPointer::from_usize(range.start),
            range.len(),
            permissions,
        )
    }
    .map_err(|_| MachoLoaderError::Memory)
}

pub(crate) fn load<P: ShimPlatform>(
    pm: &PageManager<P, PAGE_SIZE>,
    platform: &P,
    data: &[u8],
    argv: &[CString],
    envp: &[CString],
) -> Result<PtRegs, MachoLoaderError> {
    let mut plan = MachoParsedFile::parse(data)?;
    let trampoline = plan.parse_trampoline(data)?;
    CodeMetadata::parse(data).map_err(|_| MachoLoaderError::Rewrite)?;
    let rewriter = Rewriter::new(TargetHost::MacOs).map_err(|_| MachoLoaderError::Rewrite)?;
    // Finalize in staging before publishing any executable pages. The rewriter
    // leaves callback=0 and a guest-TLS-offset placeholder for the loader.
    let gates = if let Some(trampoline) = &trampoline {
        let mut gates = data[trampoline.file_range.clone()].to_vec();
        let callback = platform.get_syscall_entry_point();
        if callback == 0 {
            return Err(MachoLoaderError::Rewrite);
        }
        let tls_offset = platform
            .guest_thread_pointer_offset()
            .and_then(|offset| u16::try_from(offset).ok())
            .ok_or(MachoLoaderError::Rewrite)?;
        gates[..8].copy_from_slice(&callback.to_le_bytes());
        rewriter
            .finalize_trampoline_gates(&mut gates, tls_offset)
            .map_err(|_| MachoLoaderError::Rewrite)?;
        gates
    } else {
        Vec::new()
    };
    let base = reserve(pm, plan.virtual_range.len())?;
    let relocate = |address: usize| base + (address - plan.virtual_range.start);
    for segment in &plan.segments {
        let address = relocate(segment.virtual_range.start);
        let range = address..address + segment.virtual_range.len();
        protect(pm, range.clone(), Permissions::READ | Permissions::WRITE)?;
        let ptr = P::RawMutPointer::<u8>::from_usize(address);
        ptr.copy_from_slice(0, &data[segment.file_range.clone()])
            .ok_or(MachoLoaderError::Memory)?;
        // Anonymous allocations are zero-filled, including BSS and padding.
        let mut protection = Permissions::empty();
        protection.set(Permissions::READ, segment.protection & 1 != 0);
        protection.set(Permissions::WRITE, segment.protection & 2 != 0);
        protection.set(Permissions::EXEC, segment.protection & 4 != 0);
        // The macOS platform synchronizes instruction caches on RW -> RX.
        protect(pm, range, protection)?;
    }
    if let Some(trampoline) = trampoline {
        let start = relocate(trampoline.virtual_range.start);
        let range = start..start + trampoline.virtual_range.len();
        protect(pm, range.clone(), Permissions::READ | Permissions::WRITE)?;
        P::RawMutPointer::<u8>::from_usize(start)
            .copy_from_slice(0, &gates)
            .ok_or(MachoLoaderError::Memory)?;
        protect(pm, range, Permissions::READ | Permissions::EXEC)?;
    }
    let stack_base = reserve(pm, STACK_SIZE + PAGE_SIZE)? + PAGE_SIZE;
    let stack_range = stack_base..stack_base + STACK_SIZE;
    // Leave the first page inaccessible. This fixed-size initial stack must
    // not use IS_STACK, which would allow PageManager's grow-down behavior.
    protect(pm, stack_range, Permissions::READ | Permissions::WRITE)?;
    let sp = initialize_stack::<P>(stack_base, argv, envp)?;
    let ctx = PtRegs {
        pc: relocate(plan.entry),
        sp,
        ..PtRegs::default()
    };
    Ok(ctx)
}

/// Darwin's static startup stack: argc, argv[], NULL, envp[], NULL,
/// followed by an empty apple vector.
fn initialize_stack<P: ShimPlatform>(
    base: usize,
    argv: &[CString],
    envp: &[CString],
) -> Result<usize, MachoLoaderError> {
    let (bytes, offset) = stack_image(base, STACK_SIZE, argv, envp)?;
    UserPtrMut::from_usize(base + offset)
        .copy_from_slice::<P>(0, &bytes)
        .ok_or(MachoLoaderError::Memory)?;
    Ok(base + offset)
}

fn stack_image(
    base: usize,
    size: usize,
    argv: &[CString],
    envp: &[CString],
) -> Result<(Vec<u8>, usize), MachoLoaderError> {
    // Compute the used suffix before allocating: the rest of the anonymous
    // guest stack is already zero-filled and needs neither staging nor copying.
    base.checked_add(size)
        .ok_or(MachoLoaderError::ArgumentsTooLarge)?;
    let pointer_bytes = argv
        .len()
        .checked_add(envp.len())
        .and_then(|count| count.checked_add(4)) // argc and three terminators
        .and_then(|count| count.checked_mul(size_of::<usize>()))
        .ok_or(MachoLoaderError::ArgumentsTooLarge)?;
    let string_bytes = argv
        .iter()
        .chain(envp)
        .try_fold(0usize, |size, string| {
            size.checked_add(string.as_bytes_with_nul().len())
        })
        .ok_or(MachoLoaderError::ArgumentsTooLarge)?;
    let sp = size
        .checked_sub(string_bytes)
        .and_then(|position| position.checked_sub(pointer_bytes))
        .ok_or(MachoLoaderError::ArgumentsTooLarge)?
        & !15;
    let mut bytes = vec![0u8; size - sp];
    let mut position = bytes.len();
    let mut pointers = vec![argv.len()];
    for strings in [argv, envp] {
        for string in strings {
            let data = string.as_bytes_with_nul();
            position = position
                .checked_sub(data.len())
                .ok_or(MachoLoaderError::ArgumentsTooLarge)?;
            bytes[position..position + data.len()].copy_from_slice(data);
            pointers.push(base + sp + position);
        }
        pointers.push(0);
    }
    pointers.push(0); // empty apple[]
    for (slot, value) in bytes[..pointer_bytes]
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(pointers)
    {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    Ok((bytes, sp))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stack_layout_and_overflow() {
        let argv = [
            CString::new("program").unwrap(),
            CString::new("arg").unwrap(),
        ];
        let env = [CString::new("KEY=VALUE").unwrap()];
        let (bytes, sp) = stack_image(0x1000, 256, &argv, &env).unwrap();
        assert_eq!(sp % 16, 0);
        assert_eq!(bytes.len(), 256 - sp);
        let words: Vec<_> = bytes[..7 * 8]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|w| usize::from_le_bytes(*w))
            .collect();
        assert_eq!(words[0], 2);
        assert_eq!((words[3], words[5], words[6]), (0, 0, 0));
        for (ptr, string) in [
            (words[1], &argv[0]),
            (words[2], &argv[1]),
            (words[4], &env[0]),
        ] {
            let pos = ptr - (0x1000 + sp);
            assert_eq!(
                &bytes[pos..pos + string.as_bytes_with_nul().len()],
                string.as_bytes_with_nul()
            );
        }
        // A larger guest mapping must not increase the heap staging size.
        let (large_bytes, large_sp) = stack_image(0x1000, STACK_SIZE, &argv, &env).unwrap();
        assert_eq!(large_bytes.len(), bytes.len());
        assert_eq!(large_sp + large_bytes.len(), STACK_SIZE);
        assert!(matches!(
            stack_image(0, 16, &argv, &env),
            Err(MachoLoaderError::ArgumentsTooLarge)
        ));
        assert!(matches!(
            stack_image(usize::MAX, 256, &argv, &env),
            Err(MachoLoaderError::ArgumentsTooLarge)
        ));
        let (empty, empty_sp) = stack_image(0x1000, STACK_SIZE, &[], &[]).unwrap();
        assert_eq!(empty, [0; 32]);
        assert_eq!(empty_sp, STACK_SIZE - 32);
    }
}
