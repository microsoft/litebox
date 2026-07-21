// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ELF loader for LiteBox

use alloc::{ffi::CString, vec::Vec};
use litebox::{
    fs::{Mode, OFlags},
    mm::linux::{CreatePagesFlags, MappingError, PAGE_SIZE},
    platform::SystemInfoProvider as _,
    utils::{ReinterpretSignedExt, TruncateExt},
};
use litebox_common_linux::{MapFlags, errno::Errno, loader::ElfParsedFile};
use litebox_platform_multiplex::Platform;
use thiserror::Error;

use crate::{
    UserPtrMut,
    loader::auxv::{AuxKey, AuxVec},
};

use super::stack::UserStack;
use crate::{ShimFS, Task};

// An opened elf file
struct ElfFile<'a, FS: ShimFS> {
    task: &'a Task<FS>,
    fd: i32,
    load_high: bool,
}

impl<'a, FS: ShimFS> ElfFile<'a, FS> {
    fn new(task: &'a Task<FS>, path: impl litebox::path::Arg) -> Result<Self, Errno> {
        let fd = task
            .sys_open(path, OFlags::RDONLY, Mode::empty())?
            .reinterpret_as_signed();
        Ok(ElfFile {
            task,
            fd,
            load_high: false,
        })
    }
}

impl<FS: ShimFS> Drop for ElfFile<'_, FS> {
    fn drop(&mut self) {
        self.task.sys_close(self.fd).expect("failed to close fd");
    }
}

impl<FS: ShimFS> litebox_common_linux::loader::ReadAt for &'_ ElfFile<'_, FS> {
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

impl<FS: ShimFS> litebox_common_linux::loader::MapMemory for ElfFile<'_, FS> {
    type Error = Errno;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        // Allocate a mapping large enough that even if it's maximally misaligned we can
        // still fit `len` bytes.
        let mapping_len = len + (align.max(PAGE_SIZE) - PAGE_SIZE);
        let hint = if self.load_high {
            // Reserve the interpreter top-down by passing no hint: LiteBox's
            // `get_unmmaped_area` then runs its top-down search and returns
            // the highest free slot (see `litebox/src/mm/linux.rs`), which is
            // where we want `ld.so` so the low ET_EXEC brk heap below stays
            // uncapped. This needs no explicit `TASK_ADDR_MAX` arithmetic and
            // no reserve-once bookkeeping, and it does not rely on any
            // platform honoring an out-of-range hint.
            0
        } else {
            super::DEFAULT_LOW_ADDR
        };
        let mapping_ptr = self
            .task
            .sys_mmap(
                hint,
                mapping_len,
                litebox_common_linux::ProtFlags::PROT_NONE,
                litebox_common_linux::MapFlags::MAP_ANONYMOUS
                    | litebox_common_linux::MapFlags::MAP_PRIVATE,
                -1,
                0,
            )?
            .as_usize();

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
pub(crate) struct ElfLoader<'a, FS: ShimFS> {
    path: &'a str,
    main: FileAndParsed<'a, FS>,
    interp: Option<FileAndParsed<'a, FS>>,
}

struct FileAndParsed<'a, FS: ShimFS> {
    file: ElfFile<'a, FS>,
    parsed: ElfParsedFile,
}

impl<'a, FS: ShimFS> FileAndParsed<'a, FS> {
    fn new(task: &'a Task<FS>, path: impl litebox::path::Arg) -> Result<Self, ElfLoaderError> {
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
            Some(litebox::mm::linux::DEFAULT_RESERVED_SPACE_SIZE)
        } else {
            None
        };
        let result = self.parsed.load(&mut self.file, &mut &*platform, reserve);
        Ok(result?)
    }
}

impl<'a, FS: ShimFS> ElfLoader<'a, FS> {
    /// Parses an ELF file from the given path.
    pub fn new(task: &'a Task<FS>, path: &'a str) -> Result<Self, ElfLoaderError> {
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
            let length = litebox::mm::linux::NonZeroPageSize::new(super::DEFAULT_STACK_SIZE)
                .expect("DEFAULT_STACK_SIZE is not page-aligned");
            global
                .pm
                .create_stack_pages(None, length, CreatePagesFlags::empty())
                .map_err(ElfLoaderError::MappingError)?
        };
        let mut stack = UserStack::new(
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

    use litebox::{
        fs::{Mode, OFlags},
        platform::PageManagementProvider,
    };
    use litebox_platform_multiplex::Platform;

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

    fn write_file(task: &Task<crate::DefaultFS>, path: &str, data: &[u8]) {
        let fd = task
            .sys_open(path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("failed to create test ELF");
        let fd = i32::try_from(fd).expect("fd fits i32");
        task.sys_write(fd, data, None)
            .expect("failed to write test ELF");
        task.sys_close(fd).expect("failed to close test ELF");
    }

    #[test]
    fn et_exec_interpreter_loads_top_down_above_low_heap() {
        let task = crate::syscalls::tests::init_platform(None);
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
        let addr_max = <Platform as PageManagementProvider<{ PAGE_SIZE }>>::TASK_ADDR_MAX;
        assert!(
            interp.base_addr >= addr_max / 2,
            "ET_EXEC interpreter loaded at {:#x}, near the low-heap region {:#x} rather than top-down high (>= {:#x})",
            interp.base_addr,
            crate::loader::DEFAULT_LOW_ADDR,
            addr_max / 2,
        );
    }
}
