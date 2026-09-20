// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mach-O loading through the shim's file and virtual-memory subsystems.
//!
//! Parsing and rewriting use the same in-memory snapshot, isolating the load plan
//! from later file changes. Dynamically linked executables enter a standalone
//! copy of host dyld and use a private instance of the current boot's cache.

use crate::{ShimPlatform, Task};
use alloc::{borrow::Cow, ffi::CString, format, vec, vec::Vec};
use core::ops::Range;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::ReinterpretSignedExt as _;
use litebox_broker_protocol::fs::FileMode;
use litebox_common_macos::{
    MmapFlags, OpenFlags, PAGE_SIZE, PtRegs, VmProtection,
    loader::{MAX_IMAGE_SIZE, MachoParsedFile, TrampolineInfo, arm64_slice},
};
use litebox_syscall_rewriter::{
    TargetHost,
    macho::{CodeMetadata, Rewriter, hook_syscalls_in_macho},
};

use crate::MachoLoaderError;

mod dyld;
mod stack;
#[cfg(all(test, target_os = "macos"))]
mod tests;

const STACK_SIZE: usize = 8 * 1024 * 1024;

/// Owns the descriptor opened for loading, never an inherited guest descriptor.
struct MachoFile<'a, P: ShimPlatform> {
    task: &'a Task<P>,
    fd: i32,
}

impl<P: ShimPlatform> Drop for MachoFile<'_, P> {
    fn drop(&mut self) {
        if let Err(error) = self.task.sys_close(self.fd) {
            litebox_util_log::warn!(error:? = error; "failed to close Mach-O descriptor");
        }
    }
}

fn read_image<P: ShimPlatform>(task: &Task<P>, path: &str) -> Result<Vec<u8>, MachoLoaderError> {
    let file = MachoFile {
        task,
        fd: task
            .sys_open(path, OpenFlags::RDONLY, FileMode::empty())?
            .reinterpret_as_signed(),
    };
    let fd = task.files.typed_fd(file.fd)?;
    let status = task
        .global
        .litebox
        .file_status(&fd)
        .map_err(crate::syscalls::file::file_status_error)?;
    let size =
        usize::try_from(status.size).map_err(|_| MachoLoaderError::Unsupported("file size"))?;
    if size > MAX_IMAGE_SIZE {
        return Err(MachoLoaderError::Unsupported("file larger than 256 MiB"));
    }
    let mut data = vec![0; size];
    let mut offset = 0;
    while offset < size {
        let end = size.min(offset + crate::MAX_KERNEL_BUF_SIZE);
        let read = task.do_read(&fd, &mut data[offset..end], Some(offset))?;
        if read == 0 {
            return Err(MachoLoaderError::Invalid("truncated executable"));
        }
        offset += read;
    }
    Ok(data)
}

fn reserve<P: ShimPlatform>(task: &Task<P>, len: usize) -> Result<usize, MachoLoaderError> {
    task.sys_mmap(
        P::TASK_ADDR_MIN,
        len,
        VmProtection::empty(),
        MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
        -1,
        0,
    )
    .map_err(|_| MachoLoaderError::Memory)
}

fn protect<P: ShimPlatform>(
    task: &Task<P>,
    range: Range<usize>,
    protection: VmProtection,
) -> Result<(), MachoLoaderError> {
    task.sys_mprotect(range.start, range.len(), protection)
        .map_err(|_| MachoLoaderError::Memory)
}

struct Image<'a> {
    data: Cow<'a, [u8]>,
    plan: MachoParsedFile,
    trampoline: Option<TrampolineInfo>,
}

impl<'a> Image<'a> {
    fn prepare(data: &'a [u8]) -> Result<Self, MachoLoaderError> {
        let data = arm64_slice(data)?;
        let mut plan = MachoParsedFile::parse(data)?;
        let (data, trampoline) = match plan.parse_trampoline(data) {
            Ok(trampoline) => (Cow::Borrowed(data), trampoline),
            Err(MachoLoaderError::Unrewritten) => {
                // Only absent rewrite metadata permits rewriting; invalid metadata is an error.
                let patched_dyld;
                let rewrite_input = if plan.is_dyld {
                    patched_dyld = {
                        let mut bytes = data.to_vec();
                        dyld::patch(&mut bytes)?;
                        bytes
                    };
                    patched_dyld.as_slice()
                } else {
                    data
                };
                let rewritten = hook_syscalls_in_macho(rewrite_input, None)
                    .map_err(|_| MachoLoaderError::Rewrite)?;
                plan = MachoParsedFile::parse(&rewritten)?;
                let trampoline = plan.parse_trampoline(&rewritten)?;
                (Cow::Owned(rewritten), trampoline)
            }
            Err(error) => return Err(error),
        };
        CodeMetadata::parse(&data).map_err(|_| MachoLoaderError::Rewrite)?;
        Ok(Self {
            data,
            plan,
            trampoline,
        })
    }

    fn map<P: ShimPlatform>(&self, task: &Task<P>) -> Result<MappedImage, MachoLoaderError> {
        let platform = task.global.platform;
        let rewriter = Rewriter::new(TargetHost::MacOs).map_err(|_| MachoLoaderError::Rewrite)?;
        // Callback and TLS-offset placeholders must be resolved before gates become executable.
        let gates = if let Some(trampoline) = &self.trampoline {
            let mut gates = self.data[trampoline.file_range.clone()].to_vec();
            let callback = platform.get_syscall_entry_point();
            if callback == 0 {
                return Err(MachoLoaderError::Rewrite);
            }
            let tls_offset = platform
                .guest_thread_pointer_offset()
                .and_then(|offset| u16::try_from(offset).ok())
                .ok_or(MachoLoaderError::Rewrite)?;
            gates[..size_of::<usize>()].copy_from_slice(&callback.to_le_bytes());
            rewriter
                .finalize_trampoline_gates(&mut gates, tls_offset)
                .map_err(|_| MachoLoaderError::Rewrite)?;
            gates
        } else {
            Vec::new()
        };
        // TODO: support images requiring preferred-address placement (without
        // replacing host mappings) or rebasing when slid.
        let base = reserve(task, self.plan.virtual_range.len())?;
        let relocate = |address: usize| base + (address - self.plan.virtual_range.start);
        for segment in &self.plan.segments {
            let address = relocate(segment.virtual_range.start);
            let range = address..address + segment.virtual_range.len();
            protect(
                task,
                range.clone(),
                VmProtection::READ | VmProtection::WRITE,
            )?;
            P::RawMutPointer::<u8>::from_usize(address)
                .copy_from_slice(0, &self.data[segment.file_range.clone()])
                .ok_or(MachoLoaderError::Memory)?;
            // Anonymous pages supply zero-filled BSS/padding; holes remain
            // inaccessible. macOS synchronizes instruction caches on RW -> RX.
            protect(task, range, segment.protection)?;
        }
        if let Some(trampoline) = &self.trampoline {
            let start = relocate(trampoline.virtual_range.start);
            let range = start..start + trampoline.virtual_range.len();
            protect(
                task,
                range.clone(),
                VmProtection::READ | VmProtection::WRITE,
            )?;
            P::RawMutPointer::<u8>::from_usize(start)
                .copy_from_slice(0, &gates)
                .ok_or(MachoLoaderError::Memory)?;
            protect(task, range, VmProtection::READ | VmProtection::EXECUTE)?;
        }
        Ok(MappedImage {
            entry: relocate(self.plan.entry),
            header: relocate(self.plan.virtual_range.start),
        })
    }
}

struct MappedImage {
    entry: usize,
    header: usize,
}

pub(super) fn load<P: ShimPlatform>(
    task: &Task<P>,
    path: &str,
    image: Option<&[u8]>,
    dyld: Option<&[u8]>,
    argv: &[CString],
    envp: &[CString],
) -> Result<PtRegs, MachoLoaderError> {
    let owned_image;
    let data = if let Some(image) = image {
        image
    } else {
        owned_image = read_image(task, path)?;
        &owned_image
    };
    let image = Image::prepare(data)?;
    let uses_dyld = image.plan.uses_dyld;
    if image.plan.is_dyld {
        return Err(MachoLoaderError::Unsupported(
            "dyld cannot be the main executable",
        ));
    }
    let main = image.map(task)?;
    let dyld = match (uses_dyld, dyld) {
        (false, None) => None,
        (false, Some(_)) => {
            return Err(MachoLoaderError::Unsupported(
                "dyld supplied for static executable",
            ));
        }
        (true, None) => {
            return Err(MachoLoaderError::Unsupported(
                "dynamic executable requires standalone dyld",
            ));
        }
        (true, Some(bytes)) => {
            let image = Image::prepare(bytes)?;
            if !image.plan.is_dyld {
                return Err(MachoLoaderError::Invalid(
                    "supplied dyld is not MH_DYLINKER",
                ));
            }
            Some(image.map(task)?)
        }
    };
    let mut apple = vec![
        CString::new(format!("executable_path={path}"))
            .map_err(|_| MachoLoaderError::Invalid("executable path"))?,
    ];
    if uses_dyld {
        apple.push(
            CString::new(format!("executable_mh=0x{:x}", main.header))
                .map_err(|_| MachoLoaderError::Invalid("executable header"))?,
        );
    }
    let stack_base = reserve(task, STACK_SIZE + PAGE_SIZE)? + PAGE_SIZE;
    // Keep the guard page inaccessible; this fixed-size stack must not use IS_STACK grow-down.
    protect(
        task,
        stack_base..stack_base + STACK_SIZE,
        VmProtection::READ | VmProtection::WRITE,
    )?;
    let sp = stack::initialize::<P>(
        stack_base,
        argv,
        envp,
        &apple,
        dyld.as_ref().map(|_| main.header),
    )?;
    Ok(PtRegs {
        pc: dyld.as_ref().map_or(main.entry, |dyld| dyld.entry),
        sp,
        ..PtRegs::default()
    })
}
