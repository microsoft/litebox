// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ELF loader for LiteBox customized for loading and running `ldelf` and
//! eventially the target OP-TEE TA.
//!
//! Unlike the ELF loader for Linux Shim, this loader does not load the main
//! ELF. This is because OP-TEE's `ldelf` has several non-standard features
//! to load TA ELF and we decide not to implement them. Instead, this loader
//! loads and runs a `ldelf` binary which in turn makes several ldelf syscalls
//! loads the target TA. Then, this loader collects the necessary information
//! to start the loaded TA (e.g., entry point). Note that we run `ldelf` in
//! the user mode. That is, it is not in our TCB.
//!
//! Since OP-TEE Shim does not support file-backed mapping, this module uses
//! anonymous mappings and manually loads the ELF segments into memory, which
//! result in uncessary data copies and higher memory usage. To avoid this,
//! we need to implement file-backed mapping, demand paging, and/or shared
//! mapping in the future.
use litebox::{
    mm::linux::{MappingError, PAGE_SIZE},
    platform::{
        PunchthroughProvider, PunchthroughToken, RawConstPointer as _, SystemInfoProvider as _,
    },
    utils::TruncateExt,
};
use litebox_common_linux::{MapFlags, ProtFlags, errno::Errno, loader::ElfParsedFile};
use litebox_common_optee::{LdelfArg, TeeUuid};
use thiserror::Error;

use crate::MutPtr;

use crate::{Task, UserMutPtr};

/// An ELF file loaded in memory
struct ElfFileInMemory<'a> {
    task: &'a Task,
    buffer: alloc::boxed::Box<[u8]>,
}

fn read_at(elf: &ElfFileInMemory, offset: u64, buf: &mut [u8]) -> Result<(), Errno> {
    if buf.is_empty() {
        return Ok(());
    }
    let offset = offset.truncate();
    if offset >= elf.buffer.len() {
        return Err(Errno::ENODATA);
    }
    let end = core::cmp::min(offset + buf.len(), elf.buffer.len());
    let len = end - offset;
    buf[..len].copy_from_slice(&elf.buffer[offset..end]);
    Ok(())
}

impl<'a> ElfFileInMemory<'a> {
    fn new(task: &'a Task, elf_buf: &[u8]) -> Self {
        Self {
            task,
            buffer: elf_buf.into(),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), Errno> {
        read_at(self, offset, buf)
    }
}

impl litebox_common_linux::loader::ReadAt for &'_ ElfFileInMemory<'_> {
    type Error = Errno;

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        read_at(self, offset, buf)
    }

    fn size(&mut self) -> Result<u64, Self::Error> {
        Ok(self.buffer.len() as u64)
    }
}

impl litebox_common_linux::loader::MapMemory for ElfFileInMemory<'_> {
    type Error = Errno;

    fn reserve(&mut self, len: usize, align: usize) -> Result<usize, Self::Error> {
        // Allocate a mapping large enough that even if it's maximally misaligned we can
        // still fit `len` bytes.
        let mapping_len = len + (align.max(PAGE_SIZE) - PAGE_SIZE);
        let mapping_ptr = self
            .task
            .sys_mmap(
                super::DEFAULT_LOW_ADDR,
                mapping_len,
                ProtFlags::PROT_NONE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_POPULATE,
                -1,
                0,
            )?
            .as_usize();

        let ptr = mapping_ptr.next_multiple_of(align);
        let end = ptr + len;
        let mapping_end = mapping_ptr + mapping_len;
        if ptr != mapping_ptr {
            self.task
                .sys_munmap(MutPtr::from_usize(mapping_ptr), ptr - mapping_ptr)?;
        }
        if end != mapping_end {
            self.task
                .sys_munmap(MutPtr::from_usize(end), mapping_end - end)?;
        }
        Ok(ptr)
    }

    /// This function imitates file-based mapping by using the in-memory ELF file.
    ///
    /// TODO: Optimize this function to avoid unnecessary copies with demand paging.
    fn map_file(
        &mut self,
        address: usize,
        len: usize,
        offset: u64,
        prot: &litebox_common_linux::loader::Protection,
    ) -> Result<(), Self::Error> {
        let mapped_addr = self
            .task
            .sys_mmap(
                address,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANONYMOUS
                    | MapFlags::MAP_PRIVATE
                    | MapFlags::MAP_FIXED
                    | MapFlags::MAP_POPULATE,
                -1,
                offset.truncate(),
            )?
            .as_usize();
        let mapped_slice: &mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(mapped_addr as *mut u8, len) };
        self.read_at(offset, mapped_slice)?;
        self.task
            .sys_mprotect(UserMutPtr::from_usize(mapped_addr), len, prot.flags())
            .expect("sys_mprotect failed");
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
            MapFlags::MAP_ANONYMOUS
                | MapFlags::MAP_PRIVATE
                | MapFlags::MAP_FIXED
                | MapFlags::MAP_POPULATE,
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
        let addr = crate::MutPtr::<u8>::from_usize(address);
        self.task.sys_mprotect(addr, len, prot.flags())
    }
}

/// Loader for ELF files
pub(crate) struct ElfLoader<'a> {
    ldelf: FileAndParsed<'a>,
}

struct FileAndParsed<'a> {
    file: ElfFileInMemory<'a>,
    parsed: ElfParsedFile,
}

impl<'a> FileAndParsed<'a> {
    fn new(task: &'a Task, elf_buf: &[u8]) -> Result<Self, ElfLoaderError> {
        let file = ElfFileInMemory::new(task, elf_buf);
        let mut parsed = litebox_common_linux::loader::ElfParsedFile::parse(&mut &file)
            .map_err(ElfLoaderError::ParseError)?;
        parsed.parse_trampoline(&mut &file, task.global.platform.get_syscall_entry_point())?;
        Ok(Self { file, parsed })
    }
}

impl<'a> ElfLoader<'a> {
    /// Create an ELF loader with a `ldelf` binary.
    pub fn new(task: &'a Task, ldelf_bin: &[u8]) -> Result<Self, ElfLoaderError> {
        let ldelf = FileAndParsed::new(task, ldelf_bin)?;
        Ok(Self { ldelf })
    }

    /// Load `ldelf` and prepare the stack and CPU context for it with the given TA UUID and
    /// optional TA binary (to compensate for the lack of RPC).
    ///
    /// The runner should run the returned CPU context to start `ldelf` which in turn loads
    /// the target TA through using several ldelf syscalls.
    ///
    /// `ta_bin` is an optional TA binary to load without using RPC.
    pub fn load_ldelf(
        &mut self,
        ta_uuid: TeeUuid,
        ta_bin: Option<&[u8]>,
    ) -> Result<litebox_common_linux::PtRegs, ElfLoaderError> {
        let task = self.ldelf.file.task;
        let global = &task.global;
        let Some(ta_bin) = ta_bin else {
            todo!("RPC is not implemented yet. TA binary must be provided");
        };
        global.ta_uuid_map.insert(ta_uuid, ta_bin.into());

        let ldelf_info = self
            .ldelf
            .parsed
            .load(&mut self.ldelf.file, &mut &*global.platform)?;

        let ldelf_arg = LdelfArg::new(ta_uuid);
        let mut ta_stack = crate::loader::ta_stack::allocate_stack(task, None).ok_or(
            ElfLoaderError::MappingError(litebox::mm::linux::MappingError::OutOfMemory),
        )?;
        ta_stack
            .init_with_ldelf_arg(&ldelf_arg)
            .ok_or(ElfLoaderError::InvalidStackAddr)?;
        task.set_ta_stack_base_addr(ta_stack.get_stack_base());

        #[cfg(target_arch = "x86_64")]
        let ctx = litebox_common_linux::PtRegs {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: ta_stack.get_ldelf_arg_address(),
            orig_rax: 0,
            rip: ldelf_info.entry_point,
            cs: 0x33, // __USER_CS
            eflags: 0,
            rsp: ta_stack.get_cur_stack_top(),
            ss: 0x2b, // __USER_DS
        };
        Ok(ctx)
    }
}

/// Load the CPU context to run the loaded TA for the first time.
///
/// The caller should call `load_ldelf` and run `ldelf` with `run_thread` before
/// calling this function. If not, this function returns an error.
pub(crate) fn load_ta_context(
    task: &mut crate::Task,
    params: &[litebox_common_optee::UteeParamOwned],
    session_id: Option<u32>,
    func_id: u32,
    cmd_id: Option<u32>,
) -> Result<litebox_common_linux::PtRegs, ElfLoaderError> {
    // Expected to be the first invocation of this function after `ldelf` has loaded the TA.
    if !task.ta_loaded.load(core::sync::atomic::Ordering::SeqCst) {
        // `load_ldelf` invokes `set_ta_stack_base_addr`, so the stack base addr must be set here.
        if task.get_ta_stack_base_addr().is_none() {
            return Err(ElfLoaderError::InvalidStackAddr);
        }
        let ta_stack = crate::loader::ta_stack::allocate_stack(task, task.get_ta_stack_base_addr())
            .ok_or(ElfLoaderError::MappingError(
                litebox::mm::linux::MappingError::OutOfMemory,
            ))?;
        // SAFETY: `load_ldelf` must be called before this function. If not, the below access will fail.
        let ldelf_arg_out = unsafe { &*(ta_stack.get_ldelf_arg_address() as *const LdelfArg) };
        let entry_func = usize::try_from(ldelf_arg_out.entry_func).unwrap();
        // If `ldelf` has been successfully executed, it will parse the given TA and stores the TA's entry
        // point into `ldelf_arg.entry_func`. `entry_func == 0` implies that `ldelf` has not yet executed
        // or failed.
        if entry_func == 0 {
            return Err(ElfLoaderError::InvalidStackAddr);
        }
        task.set_ta_entry_point(entry_func);
        load_ta_trampoline(task)?;
        allocate_guest_tls(None, task).map_err(|_| {
            ElfLoaderError::MappingError(litebox::mm::linux::MappingError::OutOfMemory)
        })?;
        task.ta_loaded
            .store(true, core::sync::atomic::Ordering::SeqCst);
    }

    // Note: `ldelf` allocates stack (returned via `stack_ptr`) but we don't use it and instead re-use the stack
    // allocated for running `ldelf`.
    // Need to revisit this to see whether the stack is large enough for our use cases (e.g.,
    // copy owned data through stack to minimize TOCTTOU threats).
    let mut ta_stack = crate::loader::ta_stack::allocate_stack(task, task.get_ta_stack_base_addr())
        .ok_or(ElfLoaderError::MappingError(
            litebox::mm::linux::MappingError::OutOfMemory,
        ))?;
    ta_stack
        .init(params)
        .ok_or(ElfLoaderError::InvalidStackAddr)?;

    #[cfg(target_arch = "x86_64")]
    let ctx = litebox_common_linux::PtRegs {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rax: 0,
        rcx: usize::try_from(cmd_id.unwrap_or(0)).unwrap(),
        rdx: ta_stack.get_params_address(),
        rsi: usize::try_from(session_id.unwrap_or(task.session_id)).unwrap(),
        rdi: usize::try_from(func_id).unwrap(),
        orig_rax: 0,
        rip: task.get_ta_entry_point(),
        cs: 0x33, // __USER_CS
        eflags: 0,
        rsp: ta_stack.get_cur_stack_top(),
        ss: 0x2b, // __USER_DS
    };
    Ok(ctx)
}

/// Load the TA trampoline.
pub(crate) fn load_ta_trampoline(task: &mut crate::Task) -> Result<(), ElfLoaderError> {
    let base_addr = task
        .get_ta_base_addr()
        .ok_or(ElfLoaderError::OpenError(Errno::ENOENT))?;
    let ta_bin = task
        .global
        .ta_uuid_map
        .get(&task.ta_app_id)
        .ok_or(ElfLoaderError::OpenError(Errno::ENOENT))?;
    let mut file = ElfFileInMemory::new(task, &ta_bin);
    let mut parsed = litebox_common_linux::loader::ElfParsedFile::parse(&mut &file)
        .map_err(ElfLoaderError::ParseError)?;
    parsed.parse_trampoline(&mut &file, task.global.platform.get_syscall_entry_point())?;
    parsed
        .load_secondary_trampoline(&mut file, &mut &*task.global.platform, base_addr)
        .map_err(|_| ElfLoaderError::MappingError(litebox::mm::linux::MappingError::OutOfMemory))
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

/// Allocate the guest TLS for an OP-TEE TA.
/// This function is required to overcome the compatibility issue coming from
/// system and build toolchain differences. OP-TEE OS only supports a single thread and
/// thus does not explicitly set up the TLS area. In contrast, we do use an x86 toolchain to
/// compile OP-TEE TAs and this toolchain assumes there is a valid TLS areas for various purposes
/// including stack protection. To this end, the toolchain generates binaries using
/// the `FS` register for TLS access.
/// This function allocates a TLS area on behalf of the TA to satisfy the toolchain's assumption.
/// Instead of using this function, we could change the flags of the toolchain to not use TLS
/// (e.g., `-fno-stack-protector`), but this might be insecure. Also, the toolchain might have
/// other features relying on TLS.
#[cfg(target_arch = "x86_64")]
fn allocate_guest_tls(
    tls_size: Option<usize>,
    task: &crate::Task,
) -> Result<(), litebox_common_linux::errno::Errno> {
    let tls_size = tls_size.unwrap_or(PAGE_SIZE).next_multiple_of(PAGE_SIZE);
    let addr = task.sys_mmap(
        0,
        tls_size,
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_POPULATE,
        -1,
        0,
    )?;
    let punchthrough = litebox_common_linux::PunchthroughSyscall::SetFsBase {
        addr: addr.as_usize(),
    };
    let token = litebox_platform_multiplex::platform()
        .get_punchthrough_token_for(punchthrough)
        .expect("Failed to get punchthrough token for SET_FS");
    let _ = token.execute().map(|_| ()).map_err(|e| match e {
        litebox::platform::PunchthroughError::Failure(errno) => errno,
        _ => unimplemented!("Unsupported punchthrough error {:?}", e),
    });
    Ok(())
}
