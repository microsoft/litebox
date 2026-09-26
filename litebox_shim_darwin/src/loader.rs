// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Loading a Mach-O executable into a fresh address space.
//!
//! The image is mapped at its preferred address (see [`crate::macho`] for why
//! it is never slid). One auxiliary region is mapped directly above it: its
//! first page holds the stub `main` returns into, which calls `exit(2)` with
//! `main`'s result; the rest is the trampoline the runtime patcher redirects
//! each `syscall` instruction through. Keeping the trampoline next to the image
//! keeps every patched site within a 32-bit jump of its stub.

use alloc::ffi::CString;
use alloc::vec;
use alloc::vec::Vec;
use litebox::fs::{Mode, OFlags};
use litebox::mm::vmem::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::TruncateExt;
use object::macho::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use thiserror::Error;

use crate::macho::{self, MachOError};
use crate::{ConstPtr, DarwinPageManager, MutPtr, PAGE_SIZE, ShimFS, ShimPlatform};

/// The stack a program gets when `LC_MAIN` does not ask for a size; macOS gives
/// the main thread 8 MiB.
const DEFAULT_STACK_SIZE: usize = 8 << 20;

/// The auxiliary region above the image: one page for the exit stub, the rest
/// for syscall trampolines.
const AUX_SIZE: usize = 16 * PAGE_SIZE;
const TRAMPOLINE_OFFSET: usize = PAGE_SIZE;

/// `main` returns into this: `mov edi, eax; mov eax, SYS_exit; syscall; ud2`.
/// Its `syscall` is patched like any other, so it reaches the shim.
const EXIT_STUB: [u8; 11] = [
    0x89, 0xc7, // mov edi, eax
    0xb8, 0x01, 0x00, 0x00, 0x02, // mov eax, 0x2000001 (SYS_exit)
    0x0f, 0x05, // syscall
    0x0f, 0x0b, // ud2
];

/// The encoding of `syscall`.
const SYSCALL: [u8; 2] = [0x0f, 0x05];

/// Why a program could not be loaded.
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("cannot open the program: {0}")]
    Open(#[from] litebox::fs::errors::OpenError),
    #[error("cannot read the program")]
    Read,
    #[error(transparent)]
    MachO(#[from] MachOError),
    #[error("the image's address range {start:#x}..{end:#x} is not available")]
    AddressRange { start: usize, end: usize },
    #[error("cannot map the program's memory")]
    Map,
    #[error("cannot redirect the program's system calls: {0}")]
    Patch(litebox_syscall_rewriter::Error),
    #[error("the program has more system calls than its trampoline has room for")]
    TrampolineFull,
    #[error("the arguments and environment do not fit on the stack")]
    ArgumentsTooLarge,
}

/// Register state for entering `main`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Start {
    pub(crate) entry: usize,
    /// Points at `main`'s return address, which is 8 bytes into a 16-byte
    /// aligned slot, as the x86-64 ABI requires at function entry.
    pub(crate) stack_pointer: usize,
    pub(crate) argc: usize,
    pub(crate) argv: usize,
    pub(crate) envp: usize,
    pub(crate) apple: usize,
}

/// Read the whole file at `path`.
pub(crate) fn read_file<FS: ShimFS>(fs: &FS, path: &str) -> Result<Vec<u8>, LoadError> {
    let fd = fs.open(path, OFlags::RDONLY, Mode::empty())?;
    let result = (|| {
        let size = fs.fd_file_status(&fd).map_err(|_| LoadError::Read)?.size;
        let mut data = vec![0u8; size];
        let mut done = 0;
        while done < size {
            let read = fs
                .read(&fd, &mut data[done..], Some(done))
                .map_err(|_| LoadError::Read)?;
            if read == 0 {
                return Err(LoadError::Read);
            }
            done += read;
        }
        Ok(data)
    })();
    let _ = fs.close(&fd);
    result
}

/// Map `data`, redirect its system calls, and build its initial stack.
pub(crate) fn load<Platform: ShimPlatform>(
    platform: &Platform,
    page_manager: &DarwinPageManager<Platform>,
    data: &[u8],
    path: &str,
    argv: &[CString],
    envp: &[CString],
) -> Result<Start, LoadError> {
    let image = macho::parse(data)?;
    let start = usize::try_from(image.start()).map_err(|_| LoadError::Map)?;
    let end = usize::try_from(image.end())
        .map_err(|_| LoadError::Map)?
        .checked_next_multiple_of(PAGE_SIZE)
        .ok_or(LoadError::Map)?;
    if !start.is_multiple_of(PAGE_SIZE) {
        return Err(MachOError::MalformedSegment.into());
    }
    let aux = end;

    map_fixed::<Platform>(page_manager, start, end - start, |ptr| {
        for segment in &image.segments {
            let from: usize = segment.fileoff.trunc();
            let bytes = &data[from..from + TruncateExt::<usize>::trunc(segment.filesize)];
            ptr.copy_from_slice(TruncateExt::<usize>::trunc(segment.vmaddr) - start, bytes)?;
        }
        Some(())
    })?;
    let entry_slot = platform.get_syscall_entry_point().to_le_bytes();
    map_fixed::<Platform>(page_manager, aux, AUX_SIZE, |ptr| {
        ptr.copy_from_slice(0, &EXIT_STUB)?;
        ptr.copy_from_slice(TRAMPOLINE_OFFSET, &entry_slot)
    })?;

    // Redirect every `syscall` in the image's code, and the exit stub's own.
    let trampoline = aux + TRAMPOLINE_OFFSET;
    let mut cursor = entry_slot.len();
    let code = image
        .code
        .iter()
        .map(|range| (range.start.trunc(), (range.end - range.start).trunc()))
        .chain(core::iter::once((aux, EXIT_STUB.len())));
    for (address, len) in code {
        cursor = patch::<Platform>(address, len, trampoline, cursor)?;
    }

    for segment in &image.segments {
        let len = TruncateExt::<usize>::trunc(segment.vmsize).next_multiple_of(PAGE_SIZE);
        protect::<Platform>(page_manager, segment.vmaddr.trunc(), len, segment.initprot)?;
    }
    protect::<Platform>(page_manager, aux, AUX_SIZE, VM_PROT_READ | VM_PROT_EXECUTE)?;

    let stack_size = match usize::try_from(image.stack_size).map_err(|_| LoadError::Map)? {
        0 => DEFAULT_STACK_SIZE,
        size => size.next_multiple_of(PAGE_SIZE),
    };
    let mut start_state = build_stack::<Platform>(page_manager, stack_size, path, argv, envp)?;
    start_state.entry = usize::try_from(image.entry).map_err(|_| LoadError::Map)?;
    // `main` returns to the exit stub.
    let return_address = MutPtr::<Platform, usize>::from_usize(start_state.stack_pointer);
    return_address
        .write_at_offset(0, aux)
        .ok_or(LoadError::Map)?;
    Ok(start_state)
}

/// Map `len` writable bytes at exactly `address`, fill them with `fill`, and
/// fail rather than replace anything already there.
fn map_fixed<Platform: ShimPlatform>(
    page_manager: &DarwinPageManager<Platform>,
    address: usize,
    len: usize,
    fill: impl FnOnce(MutPtr<Platform, u8>) -> Option<()>,
) -> Result<(), LoadError> {
    let range = LoadError::AddressRange {
        start: address,
        end: address + len,
    };
    let (Some(at), Some(length)) = (NonZeroAddress::new(address), NonZeroPageSize::new(len)) else {
        return Err(range);
    };
    // SAFETY: `NOREPLACE` makes the fixed mapping fail instead of replacing
    // anything already mapped there.
    unsafe {
        page_manager.create_writable_pages(
            Some(at),
            length,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
            |ptr| {
                fill(ptr).ok_or(litebox::mm::vmem::MappingError::OutOfMemory)?;
                Ok(0)
            },
        )
    }
    .map(|_| ())
    .map_err(|error| match error {
        litebox::mm::vmem::MappingError::MapError(_) => range,
        _ => LoadError::Map,
    })
}

/// Redirect the `syscall` instructions in `len` bytes of code at `address`,
/// appending the trampoline stubs at `trampoline + cursor`. Returns the new
/// cursor.
fn patch<Platform: ShimPlatform>(
    address: usize,
    len: usize,
    trampoline: usize,
    cursor: usize,
) -> Result<usize, LoadError> {
    let original = ConstPtr::<Platform, u8>::from_usize(address)
        .to_owned_slice(len)
        .ok_or(LoadError::Map)?;
    let mut code = original.into_vec();
    let (stubs, skipped) = litebox_syscall_rewriter::patch_code_segment(
        &mut code,
        address as u64,
        (trampoline + cursor) as u64,
        trampoline as u64,
    )
    .map_err(LoadError::Patch)?;
    if !skipped.is_empty() {
        litebox_util_log::warn!(
            count:? = skipped.len(), addrs:? = skipped;
            "syscall instruction(s) could not be redirected; they will fault"
        );
    }
    // A site the patcher could not redirect must not reach the host kernel as a
    // real system call: turn it into `icebp; hlt`, the same trap the rewriter
    // uses, so it faults into the shim instead.
    for site in skipped {
        let offset = usize::try_from(site).map_err(|_| LoadError::Map)? - address;
        if code.get(offset..offset + 2) == Some(&SYSCALL[..]) {
            code[offset..offset + 2].copy_from_slice(&[0xf1, 0xf4]);
        }
    }
    let new_cursor = cursor + stubs.len();
    if new_cursor > AUX_SIZE - TRAMPOLINE_OFFSET {
        return Err(LoadError::TrampolineFull);
    }
    // Stubs first, so no rewritten jump ever targets an unwritten stub.
    MutPtr::<Platform, u8>::from_usize(trampoline + cursor)
        .copy_from_slice(0, &stubs)
        .ok_or(LoadError::Map)?;
    MutPtr::<Platform, u8>::from_usize(address)
        .copy_from_slice(0, &code)
        .ok_or(LoadError::Map)?;
    Ok(new_cursor)
}

/// Give `len` bytes at `address` the `VM_PROT_*` protection `prot`.
fn protect<Platform: ShimPlatform>(
    page_manager: &DarwinPageManager<Platform>,
    address: usize,
    len: usize,
    prot: u32,
) -> Result<(), LoadError> {
    let ptr = MutPtr::<Platform, u8>::from_usize(address);
    let write = prot & VM_PROT_WRITE != 0;
    let execute = prot & VM_PROT_EXECUTE != 0;
    // SAFETY: the loader owns every page it protects, and no guest code runs yet.
    unsafe {
        match (prot & VM_PROT_READ != 0, write, execute) {
            (_, true, true) => page_manager.make_pages_rwx(ptr, len),
            // x86 cannot express execute-only; it reads as r-x, as on macOS.
            (_, false, true) => page_manager.make_pages_executable(ptr, len),
            (_, true, false) => page_manager.make_pages_writable(ptr, len),
            (true, false, false) => page_manager.make_pages_readable(ptr, len),
            (false, false, false) => page_manager.make_pages_inaccessible(ptr, len),
        }
    }
    .map_err(|_| LoadError::Map)
}

/// Allocate the stack and lay out what XNU puts at its top for a new process
/// (`argc`, then `argv`, `envp` and `apple`, each NULL-terminated, then the
/// strings), with `main`'s return-address slot just below `argc`.
fn build_stack<Platform: ShimPlatform>(
    page_manager: &DarwinPageManager<Platform>,
    stack_size: usize,
    path: &str,
    argv: &[CString],
    envp: &[CString],
) -> Result<Start, LoadError> {
    let length = NonZeroPageSize::new(stack_size).ok_or(LoadError::Map)?;
    // SAFETY: no fixed address is requested, so nothing can be replaced.
    let base = unsafe { page_manager.create_stack_pages(None, length, CreatePagesFlags::empty()) }
        .map_err(|_| LoadError::Map)?
        .as_usize();
    let top = base + stack_size;

    // `apple[0]` is how a Darwin process finds its own executable path.
    let mut executable_path = b"executable_path=".to_vec();
    executable_path.extend_from_slice(path.as_bytes());
    executable_path.push(0);

    let mut strings = Vec::new();
    let mut offsets = |bytes: &[u8]| {
        let offset = strings.len();
        strings.extend_from_slice(bytes);
        offset
    };
    let apple_offset = offsets(&executable_path);
    let argv_offsets: Vec<usize> = argv
        .iter()
        .map(|s| offsets(s.as_bytes_with_nul()))
        .collect();
    let envp_offsets: Vec<usize> = envp
        .iter()
        .map(|s| offsets(s.as_bytes_with_nul()))
        .collect();

    let strings_start = (top - strings.len()) & !15;
    let pointer_words = 1 + (argv.len() + 1) + (envp.len() + 1) + 2;
    // `argc` sits on a 16-byte boundary, so the return-address slot below it
    // leaves the stack pointer 8 bytes off alignment, as at any function entry.
    let table_at = (strings_start - pointer_words * 8) & !15;
    let stack_pointer = table_at - 8;
    // Leave most of the stack for the program itself.
    if top - stack_pointer > stack_size / 2 {
        return Err(LoadError::ArgumentsTooLarge);
    }

    let mut words = Vec::with_capacity(pointer_words);
    words.push(argv.len());
    words.extend(argv_offsets.iter().map(|offset| strings_start + offset));
    words.push(0);
    words.extend(envp_offsets.iter().map(|offset| strings_start + offset));
    words.push(0);
    words.push(strings_start + apple_offset);
    words.push(0);
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();

    MutPtr::<Platform, u8>::from_usize(strings_start)
        .copy_from_slice(0, &strings)
        .ok_or(LoadError::Map)?;
    MutPtr::<Platform, u8>::from_usize(table_at)
        .copy_from_slice(0, &bytes)
        .ok_or(LoadError::Map)?;

    let argv_array = table_at + 8;
    let envp_at = argv_array + (argv.len() + 1) * 8;
    Ok(Start {
        entry: 0,
        stack_pointer,
        argc: argv.len(),
        argv: argv_array,
        envp: envp_at,
        apple: envp_at + (envp.len() + 1) * 8,
    })
}
