// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ELF loader for LiteBox

use alloc::{ffi::CString, vec::Vec};
use litebox::{
    fs::{Mode, OFlags},
    mm::vmem::{CreatePagesFlags, MappingError, PAGE_SIZE, VmFlags},
    platform::PageManagementProvider,
    utils::{ReinterpretSignedExt, TruncateExt},
};
use litebox_common_linux::{MapFlags, errno::Errno, loader::ElfParsedFile};
use thiserror::Error;

use crate::{
    UserPtrMut,
    loader::auxv::{AuxKey, AuxVec},
};

use super::stack::UserStack;
use crate::{ShimPlatform, Task};

// Match the guard gap used by LiteBox's private Vmem allocator.
const STACK_GUARD_GAP: usize = 256 << 12;

fn find_bottom_up_gap<Platform: ShimPlatform>(
    task: &Task<Platform>,
    low_limit: usize,
    len: usize,
) -> Option<usize> {
    debug_assert!(low_limit.is_multiple_of(PAGE_SIZE));
    debug_assert!(len.is_multiple_of(PAGE_SIZE));
    let high_limit = <Platform as PageManagementProvider<PAGE_SIZE>>::TASK_ADDR_MAX;
    let mut candidate = low_limit..low_limit.checked_add(len)?;
    if candidate.end > high_limit {
        return None;
    }

    // PageManager::mappings() is ordered by ascending start address.
    for (range, flags) in task.global.pm.mappings() {
        let protected_start = if flags.contains(VmFlags::VM_GROWSDOWN) {
            range.start.saturating_sub(STACK_GUARD_GAP << 1)
        } else {
            range.start
        };
        if candidate.end <= protected_start {
            return Some(candidate.start);
        }
        if candidate.start < range.end {
            candidate = range.end..range.end.checked_add(len)?;
            if candidate.end > high_limit {
                return None;
            }
        }
    }
    Some(candidate.start)
}

fn claim_bottom_up<Platform: ShimPlatform>(
    task: &Task<Platform>,
    mut low_limit: usize,
    len: usize,
    mut claim: impl FnMut(usize) -> Result<usize, MappingError>,
) -> Result<usize, MappingError> {
    loop {
        let address = find_bottom_up_gap(task, low_limit, len).ok_or(MappingError::OutOfMemory)?;
        match claim(address) {
            Ok(address) => return Ok(address),
            // Retry if another Vmem thread claimed the selected gap, or if
            // the platform owns a mapping that is absent from Vmem's snapshot.
            Err(MappingError::MapError(
                litebox::platform::page_mgmt::AllocationError::AddressInUse
                | litebox::platform::page_mgmt::AllocationError::AddressInUseByPlatform,
            )) => {
                low_limit = address
                    .checked_add(PAGE_SIZE)
                    .ok_or(MappingError::OutOfMemory)?;
            }
            Err(error) => return Err(error),
        }
    }
}

// An opened elf file
struct ElfFile<'a, Platform: ShimPlatform> {
    task: &'a Task<Platform>,
    fd: i32,
    load_high: bool,
    reserve_runtime_trampoline: bool,
}

impl<'a, Platform: ShimPlatform> ElfFile<'a, Platform> {
    fn new(task: &'a Task<Platform>, path: impl litebox::path::Arg) -> Result<Self, Errno> {
        let fd = task
            .sys_open(path, OFlags::RDONLY, Mode::empty())?
            .reinterpret_as_signed();
        Ok(ElfFile {
            task,
            fd,
            load_high: false,
            reserve_runtime_trampoline: false,
        })
    }
}

impl<Platform: ShimPlatform> Drop for ElfFile<'_, Platform> {
    fn drop(&mut self) {
        self.task.sys_close(self.fd).expect("failed to close fd");
    }
}

impl<Platform: ShimPlatform> litebox_common_linux::loader::ReadAt for &'_ ElfFile<'_, Platform> {
    type Error = Errno;

    fn read_at(&mut self, mut offset: u64, mut buf: &mut [u8]) -> Result<(), Self::Error> {
        loop {
            if buf.is_empty() {
                return Ok(());
            }
            // Try to read the remaining bytes
            let bytes_read = self.task.sys_read(self.fd, buf, Some(offset.trunc()))?;
            if bytes_read == 0 {
                // reached the end of the file
                return Err(Errno::ENODATA);
            } else {
                // Successfully read some bytes
                buf = &mut buf[bytes_read..];
                offset += bytes_read as u64;
            }
        }
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        Ok(self.task.sys_fstat(self.fd)?.st_size as u64)
    }
}

impl<Platform: ShimPlatform> litebox_common_linux::loader::MapMemory for ElfFile<'_, Platform> {
    type Error = Errno;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        // Allocate a mapping which should be large enough to fit `len` bytes.
        // For an unpatched ELF, also include the runtime trampoline.
        let mapping_len = len
            .checked_add(align.max(PAGE_SIZE) - PAGE_SIZE)
            .and_then(|len| {
                len.checked_add(if self.reserve_runtime_trampoline {
                    litebox::mm::vmem::DEFAULT_RESERVED_SPACE_SIZE
                } else {
                    0
                })
            })
            .ok_or(Errno::ENOMEM)?;
        let aligned_len = mapping_len
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::ENOMEM)?;
        // Must report `MappingError`: `claim_bottom_up` distinguishes an address
        // conflict from a real out-of-memory failure, which `Errno` cannot express.
        let reserve = |address: Option<usize>| {
            let mut flags = litebox_common_linux::MapFlags::MAP_ANONYMOUS
                | litebox_common_linux::MapFlags::MAP_PRIVATE;
            if address.is_some() {
                flags |= litebox_common_linux::MapFlags::MAP_FIXED_NOREPLACE;
            }
            self.task
                .do_mmap(
                    address,
                    aligned_len,
                    litebox_common_linux::ProtFlags::PROT_NONE,
                    flags,
                    false,
                    |_| Ok(0),
                )
                .map(|address| address.as_usize())
        };
        let mapping_ptr = if self.load_high {
            // Reserve the interpreter top-down by passing no hint. LiteBox's
            // get_unmmaped_area() then returns the highest free slot, which is
            // where we want ld.so so it does not cap the low main executable's
            // upward-growing brk heap.
            reserve(None).map_err(Errno::from)?
        } else {
            // Place the main PIE in the first gap at or above DEFAULT_LOW_ADDR,
            // preserving the low executable and upward-growing brk layout.
            claim_bottom_up(self.task, super::DEFAULT_LOW_ADDR, aligned_len, |address| {
                reserve(Some(address))
            })
            .map_err(Errno::from)?
        };

        // See `compute_reserved_regions` for why the trim regions must be
        // computed in page units: `len` (an ELF's `max_vaddr - min_vaddr`
        // span) is in general not page-aligned, and `munmap` rejects
        // non-page-aligned start addresses with EINVAL.
        let regions = litebox_common_linux::loader::compute_reserved_regions(
            mapping_ptr,
            mapping_len,
            len,
            align,
        );
        if let Some((addr, size)) = regions.head_unmap {
            self.task.sys_munmap(UserPtrMut::from_usize(addr), size)?;
        }
        if let Some((addr, size)) = regions.tail_unmap {
            self.task.sys_munmap(UserPtrMut::from_usize(addr), size)?;
        }
        Ok(regions.aligned_ptr)
    }

    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.task.sys_mmap(
            address,
            len,
            prot.flags(),
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            self.fd,
            offset.trunc(),
        )?;
        Ok(())
    }

    fn map_zero(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        self.task.sys_mmap(
            address,
            len,
            prot.flags(),
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            -1,
            0,
        )?;
        Ok(())
    }

    fn protect(
        &mut self,
        address: usize,
        len: usize,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        let addr = UserPtrMut::<u8>::from_usize(address);
        self.task.sys_mprotect(addr, len, prot.flags())
    }
}

/// Struct to hold the information needed to start the program
/// (entry point and user stack top).
pub struct ElfLoadInfo {
    pub entry_point: usize,
    pub user_stack_top: usize,
}

/// Loader for ELF files
pub(crate) struct ElfLoader<'a, Platform: ShimPlatform> {
    path: &'a str,
    main: FileAndParsed<'a, Platform>,
    interp: Option<FileAndParsed<'a, Platform>>,
}

struct FileAndParsed<'a, Platform: ShimPlatform> {
    file: ElfFile<'a, Platform>,
    parsed: ElfParsedFile,
}

impl<'a, Platform: ShimPlatform> FileAndParsed<'a, Platform> {
    fn new(
        task: &'a Task<Platform>,
        path: impl litebox::path::Arg,
    ) -> Result<Self, ElfLoaderError> {
        let file = ElfFile::new(task, path).map_err(ElfLoaderError::OpenError)?;
        let mut parsed = litebox_common_linux::loader::ElfParsedFile::parse(&mut &file)
            .map_err(ElfLoaderError::ParseError)?;

        let syscall_entry_point = task.global.platform.get_syscall_entry_point();

        // Try to parse an embedded trampoline. For pre-patched binaries this
        // succeeds and load_trampoline() will map it. For unpatched binaries
        // (UnpatchedBinary error), the runtime patching during mmap will patch
        // code segments as they are mapped.
        if syscall_entry_point != 0 {
            match parsed.parse_trampoline(&mut &file, syscall_entry_point) {
                Ok(()) | Err(litebox_common_linux::loader::ElfParseError::UnpatchedBinary) => {
                    // Ok: pre-patched trampoline found, or unpatched binary
                    // that the runtime mmap hook will handle.
                }
                Err(e) => return Err(ElfLoaderError::ParseError(e)),
            }
        }

        Ok(Self { file, parsed })
    }

    /// Load the ELF into guest memory.
    fn load_mapped(
        &mut self,
        platform: &(impl litebox::platform::RawPointerProvider + litebox::platform::SystemInfoProvider),
    ) -> Result<litebox_common_linux::loader::MappingInfo, ElfLoaderError> {
        let syscall_entry_point = self.file.task.global.platform.get_syscall_entry_point();
        // When the platform requires syscall rewriting but the binary has no
        // embedded trampoline, reserve space so that brk starts past the
        // runtime trampoline region.
        let reserve = if syscall_entry_point != 0 && !self.parsed.has_trampoline() {
            Some(litebox::mm::vmem::DEFAULT_RESERVED_SPACE_SIZE)
        } else {
            None
        };
        self.file.reserve_runtime_trampoline = reserve.is_some();
        let result = self.parsed.load(&mut self.file, &mut &*platform, reserve);
        Ok(result?)
    }
}

impl<'a, Platform: ShimPlatform> ElfLoader<'a, Platform> {
    /// Parses an ELF file from the given path.
    pub fn new(task: &'a Task<Platform>, path: &'a str) -> Result<Self, ElfLoaderError> {
        // Parse the main ELF file.
        let main = FileAndParsed::new(task, path)?;

        // Parse the interpreter ELF file, if any.
        let interp = if let Some(interp_name) = main.parsed.interp(&mut &main.file)? {
            // e.g., /lib64/ld-linux-x86-64.so.2
            let mut interp = FileAndParsed::new(task, interp_name)?;
            // Linux places the ET_EXEC interpreter high so brk can grow above
            // the fixed-address main image without hitting ld.so.
            interp.file.load_high = true;
            Some(interp)
        } else {
            None
        };

        Ok(Self { path, main, interp })
    }

    /// Load an ELF file and prepare the stack for the new process.
    pub fn load(
        &mut self,
        argv: Vec<CString>,
        envp: Vec<CString>,
        mut aux: AuxVec,
    ) -> Result<ElfLoadInfo, ElfLoaderError> {
        let global = &self.main.file.task.global;

        // Load the main ELF file first so that it gets privileged addresses.
        let info = self.main.load_mapped(global.platform)?;

        // Load the interpreter ELF file, if any.
        let interp = if let Some(interp) = &mut self.interp {
            Some(interp.load_mapped(global.platform)?)
        } else {
            None
        };

        global.pm.set_initial_brk(info.brk);
        aux.insert(AuxKey::AT_PAGESZ, PAGE_SIZE);
        aux.insert(AuxKey::AT_PHDR, info.phdrs_addr);
        aux.insert(AuxKey::AT_PHENT, info.phent_size());
        aux.insert(AuxKey::AT_PHNUM, info.num_phdrs);
        aux.insert(AuxKey::AT_ENTRY, info.entry_point);
        let entry = if let Some(interp) = &interp {
            aux.insert(AuxKey::AT_BASE, interp.base_addr);
            interp.entry_point
        } else {
            info.entry_point
        };

        let sp = unsafe {
            let length = litebox::mm::vmem::NonZeroPageSize::new(super::DEFAULT_STACK_SIZE)
                .expect("DEFAULT_STACK_SIZE is not page-aligned");
            global
                .pm
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .map_err(ElfLoaderError::MappingError)?
        };
        let mut stack = UserStack::<Platform>::new(
            UserPtrMut::from_platform_ptr::<Platform>(sp),
            super::DEFAULT_STACK_SIZE,
        )
        .ok_or(ElfLoaderError::InvalidStackAddr)?;
        stack
            .init(argv, envp, aux)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;

        Ok(ElfLoadInfo {
            entry_point: entry,
            user_stack_top: stack.get_cur_stack_top(),
        })
    }

    /// Returns the command name from the ELF path.
    pub fn comm(&self) -> &[u8] {
        self.path.rsplit('/').next().unwrap_or("unknown").as_bytes()
    }
}

#[derive(Error, Debug)]
pub enum ElfLoaderError {
    #[error("failed to open the ELF file")]
    OpenError(#[from] Errno),
    #[error("failed to parse the ELF file")]
    ParseError(#[from] litebox_common_linux::loader::ElfParseError<Errno>),
    #[error("failed to load the ELF file")]
    LoadError(#[from] litebox_common_linux::loader::ElfLoadError<Errno>),
    #[error("invalid stack")]
    InvalidStackAddr,
    #[error("failed to mmap")]
    MappingError(#[from] MappingError),
}

impl From<ElfLoaderError> for litebox_common_linux::errno::Errno {
    fn from(value: ElfLoaderError) -> Self {
        match value {
            ElfLoaderError::OpenError(e) => e,
            ElfLoaderError::ParseError(e) => e.into(),
            ElfLoaderError::InvalidStackAddr | ElfLoaderError::MappingError(_) => {
                litebox_common_linux::errno::Errno::ENOMEM
            }
            ElfLoaderError::LoadError(e) => e.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec::Vec;

    use crate::syscalls::tests::TestPlatform;
    use litebox::{
        fs::{Mode, OFlags},
        platform::PageManagementProvider,
    };

    use super::*;

    const ELF_HEADER_SIZE: usize = 64;
    const ELF_HEADER_SIZE_U16: u16 = 64;
    const PROGRAM_HEADER_SIZE_U16: u16 = 56;
    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;
    const EM_X86_64: u16 = 62;
    const PT_LOAD: u32 = 1;
    const PT_INTERP: u32 = 3;
    const PF_X: u32 = 1;
    const PF_R: u32 = 4;
    const EXEC_LOAD_ADDR: u64 = 0x400000;
    const INTERP_PATH_OFFSET: usize = 0x200;
    const INTERP_PATH: &[u8] = b"/ld.so\0";

    #[derive(Clone, Copy)]
    struct ProgramHeader {
        typ: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
        align: u64,
    }

    fn push_u16(buf: &mut Vec<u8>, value: u16) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(buf: &mut Vec<u8>, value: u64) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn append_elf_header(buf: &mut Vec<u8>, elf_type: u16, entry: u64, phnum: u16) {
        buf.extend_from_slice(b"\x7fELF");
        buf.extend_from_slice(&[2, 1, 1, 0]);
        buf.extend_from_slice(&[0; 8]);
        push_u16(buf, elf_type);
        push_u16(buf, EM_X86_64);
        push_u32(buf, 1);
        push_u64(buf, entry);
        push_u64(buf, u64::from(ELF_HEADER_SIZE_U16));
        push_u64(buf, 0);
        push_u32(buf, 0);
        push_u16(buf, ELF_HEADER_SIZE_U16);
        push_u16(buf, PROGRAM_HEADER_SIZE_U16);
        push_u16(buf, phnum);
        push_u16(buf, 0);
        push_u16(buf, 0);
        push_u16(buf, 0);
        assert_eq!(buf.len(), ELF_HEADER_SIZE);
    }

    fn append_program_header(buf: &mut Vec<u8>, ph: ProgramHeader) {
        push_u32(buf, ph.typ);
        push_u32(buf, ph.flags);
        push_u64(buf, ph.offset);
        push_u64(buf, ph.vaddr);
        push_u64(buf, ph.vaddr);
        push_u64(buf, ph.filesz);
        push_u64(buf, ph.memsz);
        push_u64(buf, ph.align);
    }

    fn minimal_elf(elf_type: u16, interp: Option<&[u8]>) -> Vec<u8> {
        let phnum = if interp.is_some() { 2 } else { 1 };
        let page_size = u64::try_from(PAGE_SIZE).expect("PAGE_SIZE fits u64");
        let entry = if elf_type == ET_EXEC {
            EXEC_LOAD_ADDR
        } else {
            0
        };
        let mut buf = Vec::new();
        append_elf_header(&mut buf, elf_type, entry, phnum);
        append_program_header(
            &mut buf,
            ProgramHeader {
                typ: PT_LOAD,
                flags: PF_R | PF_X,
                offset: 0,
                vaddr: if elf_type == ET_EXEC {
                    EXEC_LOAD_ADDR
                } else {
                    0
                },
                filesz: page_size,
                memsz: page_size,
                align: page_size,
            },
        );
        if let Some(interp) = interp {
            append_program_header(
                &mut buf,
                ProgramHeader {
                    typ: PT_INTERP,
                    flags: PF_R,
                    offset: u64::try_from(INTERP_PATH_OFFSET).expect("offset fits u64"),
                    vaddr: 0,
                    filesz: u64::try_from(interp.len()).expect("interpreter path length fits u64"),
                    memsz: u64::try_from(interp.len()).expect("interpreter path length fits u64"),
                    align: 1,
                },
            );
        }
        buf.resize(PAGE_SIZE, 0);
        if let Some(interp) = interp {
            buf[INTERP_PATH_OFFSET..INTERP_PATH_OFFSET + interp.len()].copy_from_slice(interp);
        }
        buf
    }

    fn write_file(task: &Task<TestPlatform>, path: &str, data: &[u8]) {
        let fd = task
            .sys_open(path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("failed to create test ELF");
        let fd = i32::try_from(fd).expect("fd fits i32");
        task.sys_write(fd, data, None)
            .expect("failed to write test ELF");
        task.sys_close(fd).expect("failed to close test ELF");
    }

    #[test]
    fn elf_placement_keeps_main_low_and_interpreter_high() {
        let task = crate::syscalls::tests::init_platform(None);

        // Occupy exactly one page at the preferred address. The first
        // bottom-up gap must be the immediately following page.
        let hint = crate::loader::DEFAULT_LOW_ADDR;
        let occupied = task
            .sys_mmap(
                hint,
                PAGE_SIZE,
                litebox_common_linux::ProtFlags::PROT_NONE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .expect("the low ELF hint must be available for this test");
        write_file(&task, "/pie", &minimal_elf(ET_DYN, None));
        let mut pie = ElfFile::new(&task, "/pie").expect("test PIE should open");
        let reserved =
            litebox_common_linux::loader::MapMemory::reserve(&mut pie, PAGE_SIZE, PAGE_SIZE)
                .expect("PIE reservation should retry at the next low gap");
        assert_eq!(reserved, hint + PAGE_SIZE);
        task.sys_munmap(UserPtrMut::from_usize(reserved), PAGE_SIZE)
            .expect("failed to release test PIE reservation");
        task.sys_munmap(occupied, PAGE_SIZE)
            .expect("failed to release occupied hint");

        // Runtime-trampoline space participates in the gap search.
        let trampoline_blocker = task
            .sys_mmap(
                hint + PAGE_SIZE,
                PAGE_SIZE,
                litebox_common_linux::ProtFlags::PROT_NONE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
            .expect("failed to block the runtime-trampoline region");
        pie.reserve_runtime_trampoline = true;
        let reserved =
            litebox_common_linux::loader::MapMemory::reserve(&mut pie, PAGE_SIZE, PAGE_SIZE)
                .expect("PIE reservation should include runtime-trampoline space");
        assert_eq!(reserved, hint + 2 * PAGE_SIZE);
        task.sys_munmap(UserPtrMut::from_usize(reserved), PAGE_SIZE)
            .expect("failed to release trampoline-aware reservation");
        task.sys_munmap(trampoline_blocker, PAGE_SIZE)
            .expect("failed to release trampoline blocker");

        // Exercise both retryable collision sources deterministically.
        let mut attempts = Vec::new();
        let retried = claim_bottom_up(&task, hint, PAGE_SIZE, |address| {
            use litebox::platform::page_mgmt::AllocationError;

            attempts.push(address);
            match attempts.len() {
                1 => Err(MappingError::MapError(AllocationError::AddressInUse)),
                2 => Err(MappingError::MapError(
                    AllocationError::AddressInUseByPlatform,
                )),
                _ => Ok(address),
            }
        })
        .expect("address collisions should retry");
        assert_eq!(attempts, [hint, hint + PAGE_SIZE, hint + 2 * PAGE_SIZE]);
        assert_eq!(retried, hint + 2 * PAGE_SIZE);

        // A grow-down mapping protects its guard gap below the mapped pages.
        // Bottom-up placement must skip the guard and the stack itself.
        let stack_start = hint + (STACK_GUARD_GAP << 1);
        let stack_address = litebox::mm::vmem::NonZeroAddress::new(stack_start).unwrap();
        let stack_len = litebox::mm::vmem::NonZeroPageSize::new(PAGE_SIZE).unwrap();
        // SAFETY: FIXED_ADDR is paired with NOREPLACE, so this cannot replace
        // an existing mapping. The test does not retain or access the returned
        // pointer and unmaps the exact range before continuing.
        unsafe {
            task.global
                .pm
                .create_stack_pages(
                    Some(stack_address),
                    stack_len,
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE,
                )
                .expect("failed to create test stack mapping");
        }
        assert_eq!(
            find_bottom_up_gap(&task, hint, PAGE_SIZE),
            Some(stack_start + PAGE_SIZE)
        );
        task.sys_munmap(UserPtrMut::from_usize(stack_start), PAGE_SIZE)
            .expect("failed to release test stack mapping");

        write_file(&task, "/main", &minimal_elf(ET_EXEC, Some(INTERP_PATH)));
        write_file(&task, "/ld.so", &minimal_elf(ET_DYN, None));

        let mut loader = ElfLoader::new(&task, "/main").expect("loader should parse test ELFs");
        let main = loader
            .main
            .load_mapped(task.global.platform)
            .expect("main should load");
        assert_eq!(main.base_addr, 0);

        let interp = loader
            .interp
            .as_mut()
            .expect("test main should have PT_INTERP")
            .load_mapped(task.global.platform)
            .expect("interpreter should load");

        // The interpreter must land high — via the top-down search — so the
        // low ET_EXEC brk heap below it is not capped. The exact address is
        // not asserted: `get_unmmaped_area` returns the highest free gap, and
        // host mappings seeded into the userland VMA tree can sit near the top
        // and push that gap below the very top slot (see `mm/linux.rs`). Assert
        // the invariant that matters — placement in the high half of the
        // address space, far above the low-heap region — not one exact slot.
        let addr_max = <TestPlatform as PageManagementProvider<{ PAGE_SIZE }>>::TASK_ADDR_MAX;
        assert!(
            interp.base_addr >= addr_max / 2,
            "ET_EXEC interpreter loaded at {:#x}, near the low-heap region {:#x} rather than top-down high (>= {:#x})",
            interp.base_addr,
            crate::loader::DEFAULT_LOW_ADDR,
            addr_max / 2,
        );
    }
}
