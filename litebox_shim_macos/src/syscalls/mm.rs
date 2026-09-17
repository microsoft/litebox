// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Darwin virtual-memory syscalls and mmap-time Mach-O rewriting.

use alloc::{collections::BTreeSet, sync::Arc, vec, vec::Vec};
use core::ops::Range;
use litebox::{
    mm::linux::{CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize},
    platform::{
        RawConstPointer as _, RawMutPointer as _, page_mgmt::MemoryRegionPermissions as Permissions,
    },
};
use litebox_common_macos::{MmapFlags, PAGE_SIZE, VmProtection, errno::Errno};
use litebox_syscall_rewriter::{
    TargetHost,
    macho::{CodeMetadata, Rewriter},
};

use crate::{ShimPlatform, Task};

const MAX_MACHO_IMAGE_SIZE: usize = 256 * 1024 * 1024;

pub(crate) struct MachoMapping {
    range: Range<usize>,
    file_offset: usize,
    image: Arc<MachoImage>,
    patched_ranges: BTreeSet<(usize, usize)>,
    trampolines: Vec<Range<usize>>,
}

struct MachoImage {
    bytes: Arc<[u8]>,
    metadata: CodeMetadata,
}

fn permissions(protection: VmProtection) -> Permissions {
    let mut permissions = Permissions::empty();
    permissions.set(Permissions::READ, protection.contains(VmProtection::READ));
    permissions.set(Permissions::WRITE, protection.contains(VmProtection::WRITE));
    permissions.set(
        Permissions::EXEC,
        protection.contains(VmProtection::EXECUTE),
    );
    permissions
}

fn mapping_flags(flags: MmapFlags, file_backed: bool) -> CreatePagesFlags {
    let mut result = CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
    result.set(
        CreatePagesFlags::FIXED_ADDR,
        flags.contains(MmapFlags::FIXED),
    );
    result.set(CreatePagesFlags::SHARED, flags.contains(MmapFlags::SHARED));
    result.set(CreatePagesFlags::MAP_FILE, file_backed);
    result
}

fn mapping_error(error: MappingError) -> Errno {
    match error {
        MappingError::BadFD(_) => Errno::EBADF,
        MappingError::NotForReading => Errno::EACCES,
        MappingError::OutOfMemory | MappingError::MapError(_) => Errno::ENOMEM,
        _ => Errno::EINVAL,
    }
}

fn protection_from_permissions(permissions: Permissions) -> VmProtection {
    let mut protection = VmProtection::empty();
    protection.set(VmProtection::READ, permissions.contains(Permissions::READ));
    protection.set(
        VmProtection::WRITE,
        permissions.contains(Permissions::WRITE),
    );
    protection.set(
        VmProtection::EXECUTE,
        permissions.contains(Permissions::EXEC),
    );
    protection
}

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_mmap(
        &self,
        address: usize,
        length: usize,
        protection: VmProtection,
        flags: MmapFlags,
        fd: i32,
        offset: i64,
    ) -> Result<usize, Errno> {
        if length == 0
            || !address.is_multiple_of(PAGE_SIZE)
            || flags.contains(MmapFlags::SHARED) == flags.contains(MmapFlags::PRIVATE)
        {
            return Err(Errno::EINVAL);
        }
        let length = length
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::ENOMEM)?;
        let offset = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        if !offset.is_multiple_of(PAGE_SIZE)
            || offset.checked_add(length).is_none()
            || address.checked_add(length).is_none()
        {
            return Err(Errno::EINVAL);
        }
        if flags.contains(MmapFlags::SHARED)
            && protection.contains(VmProtection::WRITE)
            && !flags.contains(MmapFlags::ANONYMOUS)
        {
            return Err(Errno::ENOTSUP);
        }
        let suggested = NonZeroAddress::new(address);
        let length = NonZeroPageSize::new(length).ok_or(Errno::EINVAL)?;
        if flags.contains(MmapFlags::ANONYMOUS) {
            // SAFETY: MAP_FIXED has Darwin's replacement semantics; otherwise
            // PageManager treats `suggested` only as an allocation hint.
            return unsafe {
                self.global.pm.create_pages_with_permissions(
                    suggested,
                    length,
                    mapping_flags(flags, false),
                    permissions(protection),
                    |_| Ok(0),
                )
            }
            .map(|pointer| pointer.as_usize())
            .map_err(mapping_error);
        }

        let file = self.files.typed_fd(fd)?;
        if protection.contains(VmProtection::EXECUTE) {
            let image = self.read_macho_file(&file)?;
            return self.mmap_buffer(suggested, length, protection, flags, offset, image);
        }

        let macho = self.try_read_macho_file(&file);
        let final_permissions = permissions(protection);
        let mut create_flags = mapping_flags(flags, true);
        if macho.is_some() && !flags.contains(MmapFlags::FIXED) {
            create_flags |= CreatePagesFlags::ENSURE_SPACE_AFTER;
        }
        let mut file_offset = offset;
        let mut buffer = [0; PAGE_SIZE];
        // SAFETY: MAP_FIXED has Darwin's replacement semantics. Initialization
        // runs while the new mapping is private to this syscall and still RW.
        let pointer = unsafe {
            self.global.pm.create_pages_with_permissions(
                suggested,
                length,
                create_flags,
                final_permissions,
                |pointer| {
                    let mut copied = 0;
                    while copied < length.as_usize() {
                        let chunk = (length.as_usize() - copied).min(buffer.len());
                        let read = self
                            .global
                            .litebox
                            .read_file(&file, &mut buffer[..chunk], Some(file_offset))
                            .map_err(|_| MappingError::NotForReading)?;
                        if read == 0 {
                            break;
                        }
                        pointer
                            .copy_from_slice(copied, &buffer[..read])
                            .ok_or(MappingError::OutOfMemory)?;
                        copied += read;
                        file_offset = file_offset
                            .checked_add(read)
                            .ok_or(MappingError::OutOfMemory)?;
                    }
                    Ok(copied)
                },
            )
        }
        .map_err(mapping_error)?;
        let address = pointer.as_usize();
        if let Some(image) = macho {
            self.track_macho_mapping(MachoMapping {
                range: address..address + length.as_usize(),
                file_offset: offset,
                image,
                patched_ranges: BTreeSet::new(),
                trampolines: Vec::new(),
            });
        }
        Ok(address)
    }

    fn mmap_buffer(
        &self,
        suggested: Option<NonZeroAddress<PAGE_SIZE>>,
        length: NonZeroPageSize<PAGE_SIZE>,
        protection: VmProtection,
        flags: MmapFlags,
        offset: usize,
        image: Arc<MachoImage>,
    ) -> Result<usize, Errno> {
        let ranges = image
            .metadata
            .ranges_for_mapping(offset as u64, length.as_usize())
            .map_err(|_| Errno::ENOEXEC)?;
        let source = image.bytes.get(offset..).unwrap_or_default();
        let mut create_flags = mapping_flags(flags, true);
        if !flags.contains(MmapFlags::FIXED) {
            create_flags |= CreatePagesFlags::ENSURE_SPACE_AFTER;
        }
        // SAFETY: MAP_FIXED has Darwin's replacement semantics. The source is
        // copied and rewritten while the new mapping is private and still RW.
        let mut trampoline = None;
        let result = unsafe {
            self.global.pm.create_pages_with_permissions(
                suggested,
                length,
                create_flags,
                permissions(protection),
                |pointer| {
                    let copied = source.len().min(length.as_usize());
                    pointer
                        .copy_from_slice(0, &source[..copied])
                        .ok_or(MappingError::OutOfMemory)?;
                    trampoline = self.rewrite_macho_mapping(
                        pointer,
                        length.as_usize(),
                        &ranges,
                        &image.bytes,
                        &image.metadata,
                    )?;
                    Ok(copied)
                },
            )
        };
        let pointer = match result {
            Ok(pointer) => pointer,
            Err(error) => {
                if let Some(range) = trampoline {
                    self.remove_trampoline(range);
                }
                return Err(mapping_error(error));
            }
        };
        let address = pointer.as_usize();
        self.track_macho_mapping(MachoMapping {
            range: address..address + length.as_usize(),
            file_offset: offset,
            image,
            patched_ranges: BTreeSet::from([(address, length.as_usize())]),
            trampolines: trampoline.into_iter().collect(),
        });
        Ok(address)
    }

    fn rewrite_macho_mapping(
        &self,
        pointer: P::RawMutPointer<u8>,
        length: usize,
        ranges: &[core::ops::Range<usize>],
        image: &[u8],
        metadata: &CodeMetadata,
    ) -> Result<Option<Range<usize>>, MappingError> {
        if ranges.is_empty() {
            return Ok(None);
        }
        let rewriter = Rewriter::new(TargetHost::MacOs).map_err(|_| MappingError::OutOfMemory)?;
        let capacity = metadata
            .trampoline_size_upper_bound(image, rewriter)
            .and_then(|size| {
                size.max(PAGE_SIZE)
                    .checked_next_multiple_of(PAGE_SIZE)
                    .ok_or_else(|| {
                        litebox_syscall_rewriter::Error::AddressOverflow(
                            "Mach-O trampoline size".into(),
                        )
                    })
            })
            .map_err(|_| MappingError::OutOfMemory)?;
        let callback = self.global.platform.get_syscall_entry_point();
        let tls_offset = self
            .global
            .platform
            .guest_thread_pointer_offset()
            .and_then(|offset| u16::try_from(offset).ok())
            .ok_or(MappingError::OutOfMemory)?;
        let hint = self
            .trampoline_address_after(pointer.as_usize(), length, capacity)
            .and_then(NonZeroAddress::new)
            .ok_or(MappingError::OutOfMemory)?;
        let trampoline_length = NonZeroPageSize::new(capacity).ok_or(MappingError::OutOfMemory)?;
        let mut code = pointer
            .to_owned_slice(length)
            .ok_or(MappingError::OutOfMemory)?
            .into_vec();
        // SAFETY: the trampoline is private staging. The callback patches code
        // before either mapping is executable, and create_executable_pages
        // performs the cache-synchronizing RW-to-RX transition.
        let trampoline = unsafe {
            self.global.pm.create_executable_pages(
                Some(hint),
                trampoline_length,
                CreatePagesFlags::FIXED_ADDR
                    | CreatePagesFlags::NOREPLACE
                    | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                |trampoline| {
                    let (gates, trapped) = rewriter
                        .patch_code_segment(
                            &mut code,
                            pointer.as_usize() as u64,
                            ranges,
                            trampoline.as_usize() as u64,
                            callback as u64,
                            tls_offset,
                        )
                        .map_err(|_| MappingError::OutOfMemory)?;
                    if !trapped.is_empty() || gates.len() > capacity {
                        return Err(MappingError::OutOfMemory);
                    }
                    trampoline
                        .copy_from_slice(0, &gates)
                        .ok_or(MappingError::OutOfMemory)?;
                    Ok(gates.len())
                },
            )
        }?;
        let range = trampoline.as_usize()..trampoline.as_usize() + capacity;
        if pointer.copy_from_slice(0, &code).is_none() {
            self.remove_trampoline(range);
            return Err(MappingError::OutOfMemory);
        }
        Ok(Some(range))
    }

    fn track_macho_mapping(&self, mapping: MachoMapping) {
        let mut mappings = self.global.macho_mappings.lock();
        mappings.retain(|_, existing| {
            existing.range.end <= mapping.range.start || existing.range.start >= mapping.range.end
        });
        mappings.insert(mapping.range.start, mapping);
    }

    fn remove_trampoline(&self, range: Range<usize>) {
        // SAFETY: only unpublished or no-longer-referenced trampoline ranges
        // are passed here.
        if let Err(error) = unsafe {
            self.global
                .pm
                .remove_pages(P::RawMutPointer::from_usize(range.start), range.len())
        } {
            litebox_util_log::warn!(error:? = error; "failed to release Mach-O trampoline");
        }
    }

    fn read_macho_file(&self, file: &litebox::fs::FileFd) -> Result<Arc<MachoImage>, Errno> {
        let size = usize::try_from(
            self.global
                .litebox
                .file_status(file)
                .map_err(|_| Errno::EIO)?
                .size,
        )
        .map_err(|_| Errno::EFBIG)?;
        if size > MAX_MACHO_IMAGE_SIZE {
            return Err(Errno::EFBIG);
        }
        let mut bytes = vec![0; size];
        self.read_file_exact_at(file, &mut bytes, 0)?;
        let metadata = CodeMetadata::parse(&bytes).map_err(|error| {
            litebox_util_log::warn!(error:% = error; "refusing executable mmap of invalid Mach-O");
            Errno::ENOEXEC
        })?;
        Ok(Arc::new(MachoImage {
            bytes: bytes.into(),
            metadata,
        }))
    }

    fn try_read_macho_file(&self, file: &litebox::fs::FileFd) -> Option<Arc<MachoImage>> {
        self.read_macho_file(file).ok()
    }

    fn rewrite_mprotect_range(&self, address: usize, length: usize) -> Result<(), Errno> {
        struct Patch {
            mapping_start: usize,
            range: Range<usize>,
            file_offset: usize,
            image: Arc<MachoImage>,
        }

        let end = address + length;
        let patches = {
            let mappings = self.global.macho_mappings.lock();
            let mut patches = Vec::new();
            for (&mapping_start, mapping) in mappings.iter() {
                let start = address.max(mapping.range.start);
                let patch_end = end.min(mapping.range.end);
                if start >= patch_end {
                    continue;
                }
                let mut cursor = start;
                for &(patched_start, patched_len) in &mapping.patched_ranges {
                    let patched_end = patched_start.saturating_add(patched_len);
                    if patched_end <= cursor || patched_start >= patch_end {
                        continue;
                    }
                    if cursor < patched_start {
                        patches.push(Patch {
                            mapping_start,
                            range: cursor..patched_start.min(patch_end),
                            file_offset: mapping.file_offset + cursor - mapping.range.start,
                            image: Arc::clone(&mapping.image),
                        });
                    }
                    cursor = cursor.max(patched_end);
                    if cursor >= patch_end {
                        break;
                    }
                }
                if cursor < patch_end {
                    patches.push(Patch {
                        mapping_start,
                        range: cursor..patch_end,
                        file_offset: mapping.file_offset + cursor - mapping.range.start,
                        image: Arc::clone(&mapping.image),
                    });
                }
            }
            patches
        };

        for patch in patches {
            let ranges = patch
                .image
                .metadata
                .ranges_for_mapping(patch.file_offset as u64, patch.range.len())
                .map_err(|_| Errno::ENOEXEC)?;
            let previous: Vec<_> = self
                .global
                .pm
                .mappings()
                .into_iter()
                .filter_map(|(range, flags)| {
                    let start = patch.range.start.max(range.start);
                    let end = patch.range.end.min(range.end);
                    (start < end).then(|| {
                        (
                            start..end,
                            protection_from_permissions(Permissions::from(flags)),
                        )
                    })
                })
                .collect();
            self.change_permissions(
                patch.range.clone(),
                VmProtection::READ | VmProtection::WRITE,
            )?;
            let rewrite = self.rewrite_macho_mapping(
                P::RawMutPointer::from_usize(patch.range.start),
                patch.range.len(),
                &ranges,
                &patch.image.bytes,
                &patch.image.metadata,
            );
            let mut restore_error = None;
            for (range, protection) in previous {
                if let Err(error) = self.change_permissions(range, protection)
                    && restore_error.is_none()
                {
                    restore_error = Some(error);
                }
            }
            let trampoline = rewrite.map_err(mapping_error)?;
            let mut mappings = self.global.macho_mappings.lock();
            if let Some(mapping) = mappings.get_mut(&patch.mapping_start) {
                mapping
                    .patched_ranges
                    .insert((patch.range.start, patch.range.len()));
                mapping.trampolines.extend(trampoline);
            } else if let Some(range) = trampoline {
                drop(mappings);
                self.remove_trampoline(range);
                return Err(Errno::ENOMEM);
            }
            if let Some(error) = restore_error {
                return Err(error);
            }
        }
        Ok(())
    }

    fn change_permissions(
        &self,
        range: Range<usize>,
        protection: VmProtection,
    ) -> Result<(), Errno> {
        // SAFETY: PageManager validates the tracked range and maximum allowed
        // permissions. Callers prevent concurrent execution while rewriting.
        unsafe {
            self.global.pm.change_page_permissions(
                P::RawMutPointer::from_usize(range.start),
                range.len(),
                permissions(protection),
            )
        }
        .map_err(|_| Errno::EACCES)
    }

    fn trampoline_address_after(
        &self,
        code_address: usize,
        code_length: usize,
        trampoline_length: usize,
    ) -> Option<usize> {
        let mut candidate = code_address.checked_add(code_length)?;
        for (range, _) in self.global.pm.mappings() {
            if range.end <= candidate {
                continue;
            }
            let candidate_end = candidate.checked_add(trampoline_length)?;
            if range.start >= candidate_end {
                return Some(candidate);
            }
            candidate = range.end;
        }
        candidate.checked_add(trampoline_length)?;
        Some(candidate)
    }

    fn read_file_exact_at(
        &self,
        file: &litebox::fs::FileFd,
        mut bytes: &mut [u8],
        mut offset: usize,
    ) -> Result<(), Errno> {
        while !bytes.is_empty() {
            let read = self
                .global
                .litebox
                .read_file(file, bytes, Some(offset))
                .map_err(|_| Errno::EIO)?;
            if read == 0 || read > bytes.len() {
                return Err(Errno::EIO);
            }
            offset = offset.checked_add(read).ok_or(Errno::EFBIG)?;
            bytes = &mut bytes[read..];
        }
        Ok(())
    }

    pub(crate) fn sys_munmap(&self, address: usize, length: usize) -> Result<(), Errno> {
        let length = length
            .checked_next_multiple_of(PAGE_SIZE)
            .filter(|length| *length != 0)
            .ok_or(Errno::EINVAL)?;
        address.checked_add(length).ok_or(Errno::EINVAL)?;
        // SAFETY: Darwin munmap relinquishes the caller-selected guest range.
        unsafe {
            self.global
                .pm
                .remove_pages(P::RawMutPointer::from_usize(address), length)
        }
        .map_err(|_| Errno::EINVAL)?;
        let end = address + length;
        let trampolines = {
            let mut mappings = self.global.macho_mappings.lock();
            let overlapping: Vec<_> = mappings
                .iter()
                .filter(|(_, mapping)| mapping.range.start < end && address < mapping.range.end)
                .map(|(&start, mapping)| {
                    let release = address <= mapping.range.start && end >= mapping.range.end;
                    (start, release)
                })
                .collect();
            let mut trampolines = Vec::new();
            for (start, release) in overlapping {
                if let Some(mapping) = mappings.remove(&start)
                    && release
                {
                    trampolines.extend(
                        mapping
                            .trampolines
                            .into_iter()
                            .filter(|range| address > range.start || end < range.end),
                    );
                }
            }
            trampolines
        };
        for range in trampolines {
            self.remove_trampoline(range);
        }
        Ok(())
    }

    pub(crate) fn sys_mprotect(
        &self,
        address: usize,
        length: usize,
        protection: VmProtection,
    ) -> Result<(), Errno> {
        if length == 0 {
            return Ok(());
        }
        if !address.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        let length = length
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::EINVAL)?;
        address.checked_add(length).ok_or(Errno::EINVAL)?;
        if protection.contains(VmProtection::EXECUTE) {
            self.rewrite_mprotect_range(address, length)?;
        }
        self.change_permissions(address..address + length, protection)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    extern crate std;

    use super::*;
    use alloc::{sync::Arc, vec::Vec};
    use core::sync::atomic::AtomicI32;
    use litebox::{LiteBox, mm::linux::VmFlags};
    use litebox_broker_core::{
        ObjectRights, PolicyEngine,
        fs::{
            in_mem::{InMem, InitialNode},
            resolver::Resolver,
        },
        test_support::TestBrokerCoreBuilder,
    };
    use litebox_broker_host::test_support::InProcessBrokerSetup;
    use litebox_broker_local::BrokerLocal;
    use litebox_broker_protocol::fs::{FileAccessMode, FileMode, FileOpenFlags, FileUser};
    use litebox_common_macos::{PtRegs, TaskParams, syscall::nr, user_pointers::UserPtr};
    use litebox_platform_macos_userland::MacosUserland as Platform;
    use litebox_syscall_rewriter::aarch64::{GateMetadata, decode_branch_target};

    use crate::{MacosShimBuilder, Process};

    const TEXT: usize = 0x400;
    const SVC: u32 = 0xd400_1001;

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn macho_image() -> Vec<u8> {
        const BASE: u64 = 0x1_0000_0000;
        const SECTION: usize = 32 + 72;
        let mut bytes = vec![0; PAGE_SIZE];
        put32(&mut bytes, 0, 0xfeed_facf); // MH_MAGIC_64
        put32(&mut bytes, 4, 0x0100_000c); // CPU_TYPE_ARM64
        put32(&mut bytes, 12, 6); // MH_DYLIB
        put32(&mut bytes, 16, 1);
        put32(&mut bytes, 20, 72 + 80);
        put32(&mut bytes, 24, 0x20_0000); // MH_PIE
        put32(&mut bytes, 32, 0x19); // LC_SEGMENT_64
        put32(&mut bytes, 36, 72 + 80);
        bytes[40..46].copy_from_slice(b"__TEXT");
        put64(&mut bytes, 56, BASE);
        put64(&mut bytes, 64, PAGE_SIZE as u64);
        put64(&mut bytes, 80, PAGE_SIZE as u64);
        put32(&mut bytes, 88, 5);
        put32(&mut bytes, 92, 5);
        put32(&mut bytes, 96, 1);
        bytes[SECTION..SECTION + 6].copy_from_slice(b"__text");
        bytes[SECTION + 16..SECTION + 22].copy_from_slice(b"__TEXT");
        put64(&mut bytes, SECTION + 32, BASE + TEXT as u64);
        put64(&mut bytes, SECTION + 40, 4);
        put32(&mut bytes, SECTION + 48, u32::try_from(TEXT).unwrap());
        put32(&mut bytes, SECTION + 52, 2);
        put32(&mut bytes, SECTION + 64, 0x8000_0000); // S_ATTR_PURE_INSTRUCTIONS
        put32(&mut bytes, TEXT, SVC);
        bytes
    }

    fn task_with_file(data: &[u8]) -> Task<Platform> {
        let platform = Platform::new();
        let mode = FileMode::RWXU | FileMode::RWXG | FileMode::RWXO;
        let fs = InMem::<Platform>::new_initialized(vec![
            (
                "/",
                InitialNode::Directory {
                    mode,
                    owner: FileUser::ROOT,
                },
            ),
            (
                "/image",
                InitialNode::File {
                    mode,
                    owner: FileUser::ROOT,
                    data: data.to_vec().into(),
                },
            ),
        ]);
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_file_service(Arc::new(Resolver::<Platform, _>::new(fs)))
        .build()
        .unwrap();
        let setup = InProcessBrokerSetup::new(broker);
        let readiness = setup.readiness_sink();
        let (local, ()) = BrokerLocal::negotiate(setup, |setup| {
            let memory = setup.shared_memory();
            Ok((setup.activate(), memory, ()))
        })
        .unwrap();
        let litebox = LiteBox::new_with_broker_local(platform, local);
        readiness.attach(litebox.broker_notification_dispatcher());
        let mut builder = MacosShimBuilder::new_with_litebox(platform, litebox);
        let file = builder
            .litebox()
            .open_file(
                &litebox::fs::Context::new(),
                "/image",
                FileAccessMode::ReadOnly,
                FileOpenFlags::NONE,
                FileMode::empty(),
            )
            .unwrap();
        assert_eq!(builder.inherit_file(file), Ok(0));
        let shim = builder.build();
        Task {
            global: shim.global,
            files: shim.files,
            params: TaskParams::default(),
            process: Process(Arc::new(AtomicI32::new(-1))),
        }
    }

    fn mmap_with_protection(
        task: &Task<Platform>,
        protection: VmProtection,
    ) -> Result<usize, Errno> {
        let mut ctx = PtRegs::default();
        ctx.regs[16] = nr::MMAP;
        ctx.regs[1] = PAGE_SIZE;
        ctx.regs[2] = usize::try_from(protection.bits().cast_unsigned()).unwrap();
        ctx.regs[3] = usize::try_from(MmapFlags::PRIVATE.bits().cast_unsigned()).unwrap();
        ctx.regs[4] = 0;
        task.do_syscall(&ctx)
    }

    #[test]
    fn executable_file_mmap_publishes_rewritten_code_and_rx_gate() {
        let image = macho_image();
        let task = task_with_file(&image);
        let address =
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE).unwrap();
        let code_address = address + TEXT;
        let code = u32::from_le_bytes(
            *UserPtr::<u8>::from_usize(code_address)
                .to_owned_slice::<Platform>(4)
                .unwrap()
                .first_chunk()
                .unwrap(),
        );
        let target =
            usize::try_from(decode_branch_target(code, code_address as u64).unwrap()).unwrap();
        let mappings = task.global.pm.mappings();
        assert!(mappings.iter().any(|(range, flags)| {
            range.contains(&target)
                && flags.contains(VmFlags::VM_EXEC)
                && !flags.contains(VmFlags::VM_WRITE)
        }));
        let gate = UserPtr::<u8>::from_usize(target)
            .to_owned_slice::<Platform>(64)
            .unwrap();
        let classified = Rewriter::new(TargetHost::MacOs)
            .unwrap()
            .classify_gate_slot(&gate, target as u64, target as u64)
            .unwrap();
        assert_eq!(classified.metadata(), GateMetadata::Svc);
        assert_eq!(classified.original_site(), code_address as u64);
        task.sys_munmap(address, PAGE_SIZE).unwrap();
        assert!(
            !task
                .global
                .pm
                .mappings()
                .iter()
                .any(|(range, _)| range.contains(&target))
        );
    }

    #[test]
    fn executable_file_mmap_rejects_non_macho_without_publishing_pages() {
        let task = task_with_file(b"not a Mach-O");
        let before = task.global.pm.mappings();
        assert_eq!(
            mmap_with_protection(&task, VmProtection::READ | VmProtection::EXECUTE),
            Err(Errno::ENOEXEC)
        );
        assert_eq!(task.global.pm.mappings(), before);
    }

    #[test]
    fn mprotect_exec_rewrites_after_the_file_descriptor_is_closed() {
        let task = task_with_file(&macho_image());
        let address = mmap_with_protection(&task, VmProtection::READ).unwrap();
        task.sys_close(0).unwrap();
        let code_address = address + TEXT;
        let original = UserPtr::<u8>::from_usize(code_address)
            .to_owned_slice::<Platform>(4)
            .unwrap();
        assert_eq!(u32::from_le_bytes(*original.first_chunk().unwrap()), SVC);
        task.sys_mprotect(address, 1, VmProtection::READ | VmProtection::EXECUTE)
            .unwrap();
        let rewritten = UserPtr::<u8>::from_usize(code_address)
            .to_owned_slice::<Platform>(4)
            .unwrap();
        let target = usize::try_from(
            decode_branch_target(
                u32::from_le_bytes(*rewritten.first_chunk().unwrap()),
                code_address as u64,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            task.sys_mprotect(usize::MAX, 0, VmProtection::empty()),
            Ok(())
        );
        task.sys_munmap(address, PAGE_SIZE).unwrap();
        assert!(
            !task
                .global
                .pm
                .mappings()
                .iter()
                .any(|(range, _)| range.contains(&target))
        );
    }

    #[test]
    fn invalid_ranges_and_unsupported_shared_writeback_are_rejected() {
        let task = task_with_file(&macho_image());
        let address = usize::MAX & !(PAGE_SIZE - 1);
        assert_eq!(task.sys_munmap(address, PAGE_SIZE), Err(Errno::EINVAL));
        assert_eq!(
            task.sys_mprotect(address, PAGE_SIZE, VmProtection::READ),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            task.sys_mmap(
                0,
                PAGE_SIZE,
                VmProtection::READ | VmProtection::WRITE,
                MmapFlags::SHARED,
                0,
                0,
            ),
            Err(Errno::ENOTSUP)
        );
    }
}
