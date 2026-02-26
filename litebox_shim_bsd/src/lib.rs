// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides a BSD/macOS-compatible ABI via LiteBox.
//!
//! This shim is designed for running static x86_64 Mach-O binaries on Linux.

#![no_std]

extern crate alloc;

use alloc::ffi::CString;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use litebox::LiteBox;
use litebox::mm::PageManager;
use litebox::mm::linux::PAGE_SIZE;
use litebox::platform::{RawConstPointer as _, StdioOutStream, StdioProvider as _};
use litebox::shim::ContinueOperation;
use litebox_common_bsd::loader::{MachoParseError, MachoParsedFile};
use litebox_common_bsd::syscall_nr;
use litebox_common_linux::PtRegs;
use litebox_platform_multiplex::Platform;
use thiserror::Error;

pub mod loader;

#[cfg(target_arch = "x86_64")]
const LINUX_SYS_EXIT_GROUP: usize = 231;
#[cfg(target_arch = "x86_64")]
const SYSCALL_ARG_MAGIC: usize = usize::from_le_bytes(*b"LITE BOX");

/// Shim entry points for one guest task
pub struct BsdShimEntrypoints {
    task: Task,
    /// The task should not be moved once it's bound to a platform thread
    _not_send: core::marker::PhantomData<*const ()>,
}

impl litebox::shim::EnterShim for BsdShimEntrypoints {
    type ExecutionContext = PtRegs;

    fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
        if self
            .task
            .global
            .seccomp_enabled
            .compare_exchange(
                false,
                true,
                core::sync::atomic::Ordering::SeqCst,
                core::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
        {
            litebox_platform_multiplex::platform().enable_seccomp_based_syscall_interception();
        }

        // Set instruction pointer and stack pointer from loaded values
        ctx.rip = self.task.entry_point;
        ctx.rsp = self.task.stack_top;
        if let Some(main_entry) = self.task.dynamic_main_entry {
            ctx.rdi = main_entry;
            ctx.rsi = self.task.stack_top;
        }
        // Linux x86_64 user-mode selectors/flags.
        ctx.cs = 0x33;
        ctx.ss = 0x2b;
        ctx.eflags = 0x202;
        ContinueOperation::Resume
    }

    fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.task.handle_syscall(ctx)
    }

    fn exception(
        &self,
        _ctx: &mut PtRegs,
        info: &litebox::shim::ExceptionInfo,
    ) -> ContinueOperation {
        if info.kernel_mode && info.exception == litebox::shim::Exception::PAGE_FAULT {
            if unsafe {
                self.task
                    .global
                    .pm
                    .handle_page_fault(info.cr2, info.error_code.into())
            }
            .is_ok()
            {
                return ContinueOperation::Resume;
            }
        }
        ContinueOperation::Terminate
    }

    fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        ContinueOperation::Resume
    }
}

struct GlobalState {
    pm: PageManager<Platform, PAGE_SIZE>,
    seccomp_enabled: core::sync::atomic::AtomicBool,
    #[expect(dead_code, reason = "keeping for future use")]
    litebox: LiteBox<Platform>,
}

struct Task {
    global: Arc<GlobalState>,
    entry_point: usize,
    stack_top: usize,
    dynamic_main_entry: Option<usize>,
}

impl Task {
    fn handle_syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        // On x86_64 interception paths, syscall number is preserved in orig_rax.
        let nr = ctx.orig_rax as u64;

        match nr {
            syscall_nr::SYS_WRITE => {
                let fd = ctx.rdi as i32;
                let ptr = ctx.rsi;
                let count = ctx.rdx;
                let result = self.do_write(fd, ptr, count);
                ctx.rax = result as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_EXIT => {
                #[cfg(target_arch = "x86_64")]
                {
                    // SAFETY: This intentionally terminates the current process using the host Linux
                    // syscall ABI. We provide the seccomp magic in the second argument so the
                    // platform filter allows this syscall.
                    unsafe {
                        terminate_process(ctx.rdi);
                    }
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    ContinueOperation::Terminate
                }
            }
            _ => {
                self.log_unknown_syscall(nr);
                // Return -ENOSYS (78 on macOS)
                // On macOS, errors are returned as negative values
                ctx.rax = (-78isize) as usize;
                ContinueOperation::Resume
            }
        }
    }

    fn log_unknown_syscall(&self, nr: u64) {
        let msg = format!("litebox_shim_bsd: unimplemented macOS syscall 0x{nr:x}\n");
        let _ =
            litebox_platform_multiplex::platform().write_to(StdioOutStream::Stderr, msg.as_bytes());
    }

    fn do_write(&self, fd: i32, ptr: usize, count: usize) -> isize {
        // Only handle stdout (1) and stderr (2) for now
        if fd != 1 && fd != 2 {
            return -9; // EBADF
        }

        // Read bytes from guest memory
        let guest_ptr =
            <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<u8>::from_usize(
                ptr,
            );

        let mut buf = alloc::vec![0u8; count];
        for i in 0..count {
            // Safety: We trust the guest provided a valid pointer
            if let Some(byte) = guest_ptr.read_at_offset(i as isize) {
                buf[i] = byte;
            } else {
                return -14; // EFAULT
            }
        }

        // Write to platform stdout/stderr
        let platform = litebox_platform_multiplex::platform();
        let stream = if fd == 1 {
            StdioOutStream::Stdout
        } else {
            StdioOutStream::Stderr
        };

        match platform.write_to(stream, &buf) {
            Ok(n) => n as isize,
            Err(_) => -5, // EIO
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn terminate_process(status: usize) -> ! {
    // SAFETY: We invoke the Linux `exit_group` syscall directly and never return.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") LINUX_SYS_EXIT_GROUP,
            in("rdi") status,
            in("rsi") SYSCALL_ARG_MAGIC,
            options(noreturn)
        );
    }
}

/// The built shim, ready to load programs.
pub struct BsdShim(Arc<GlobalState>);

impl Clone for BsdShim {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// A loaded program ready to run.
pub struct LoadedProgram {
    /// The entry points for the shim.
    pub entrypoints: BsdShimEntrypoints,
}

/// Errors that can occur when loading a program.
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("Failed to parse Mach-O: {0}")]
    Parse(#[from] MachoParseError),
    #[error("Failed to load program: {0}")]
    Load(#[source] litebox::mm::linux::MappingError),
    #[error("Failed to create stack")]
    StackCreation,
    #[error("Dynamic runtime linker '{0}' was not provided")]
    MissingRuntimeLinker(String),
    #[error("Failed to parse dynamic runtime linker: {0}")]
    RuntimeLinkerParse(#[source] MachoParseError),
}

/// Runtime file resolver used to provide dyld and dylibs for dynamic Mach-O execution.
pub trait RuntimeFileResolver {
    /// Read a file by guest path.
    fn read_file(&self, path: &str) -> Option<&[u8]>;
}

struct EmptyRuntimeFileResolver;

impl RuntimeFileResolver for EmptyRuntimeFileResolver {
    fn read_file(&self, _path: &str) -> Option<&[u8]> {
        None
    }
}

impl BsdShim {
    /// Load a program from binary data.
    pub fn load_program(
        &self,
        binary_data: &[u8],
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram, LoadError> {
        let resolver = EmptyRuntimeFileResolver;
        self.load_program_with_runtime_files(binary_data, argv, envp, &resolver)
    }

    /// Load a program from binary data, optionally resolving runtime files for dynamic images.
    pub fn load_program_with_runtime_files(
        &self,
        binary_data: &[u8],
        argv: Vec<CString>,
        envp: Vec<CString>,
        runtime_files: &dyn RuntimeFileResolver,
    ) -> Result<LoadedProgram, LoadError> {
        // Parse the Mach-O file
        let parsed = MachoParsedFile::parse(binary_data)?;

        // Create a mapper that uses PageManager
        let mut mapper = loader::PageManagerMapper::new(&self.0.pm);

        // Create a simple reader for the binary data
        let mut reader = loader::SliceReader::new(binary_data);

        // Load the binary
        let mapping_info = parsed.load(&mut reader, &mut mapper).map_err(|e| match e {
            litebox_common_bsd::loader::MachoLoadError::Map(e) => LoadError::Load(e),
            litebox_common_bsd::loader::MachoLoadError::Io(_) => LoadError::StackCreation,
            litebox_common_bsd::loader::MachoLoadError::InvalidSegment => LoadError::StackCreation,
        })?;

        for dylib in parsed.required_dylibs() {
            if runtime_files.read_file(dylib).is_none() {
                let msg = format!(
                    "litebox_shim_bsd: runtime bundle missing dylib '{}'\n",
                    dylib
                );
                let _ = litebox_platform_multiplex::platform()
                    .write_to(StdioOutStream::Stderr, msg.as_bytes());
            }
        }

        let mut dynamic_main_entry = None;
        let mut entry_point = mapping_info.entry_point;
        if let Some(runtime_linker_path) = parsed.runtime_linker_path() {
            if let Some(linker_data) = runtime_files.read_file(runtime_linker_path) {
                let linker_parsed =
                    MachoParsedFile::parse(linker_data).map_err(LoadError::RuntimeLinkerParse)?;
                let mut linker_reader = loader::SliceReader::new(linker_data);
                let linker_slide = 0x1_0000_0000usize;
                let linker_mapping = linker_parsed
                    .load_with_slide(&mut linker_reader, &mut mapper, linker_slide)
                    .map_err(|e| match e {
                        litebox_common_bsd::loader::MachoLoadError::Map(e) => LoadError::Load(e),
                        litebox_common_bsd::loader::MachoLoadError::Io(_) => {
                            LoadError::StackCreation
                        }
                        litebox_common_bsd::loader::MachoLoadError::InvalidSegment => {
                            LoadError::StackCreation
                        }
                    })?;
                dynamic_main_entry = Some(mapping_info.entry_point);
                entry_point = linker_mapping.entry_point;
            } else if !parsed.required_dylibs().is_empty() {
                let msg = format!(
                    "litebox_shim_bsd: runtime linker '{}' not provided; continuing with main entry\n",
                    runtime_linker_path
                );
                let _ = litebox_platform_multiplex::platform()
                    .write_to(StdioOutStream::Stderr, msg.as_bytes());
            }
        }

        // Create a stack
        let stack_size = 8 * 1024 * 1024; // 8 MB
        let stack_top = loader::create_stack(&self.0.pm, stack_size, &argv, &envp)
            .ok_or(LoadError::StackCreation)?;

        let task = Task {
            global: self.0.clone(),
            entry_point,
            stack_top,
            dynamic_main_entry,
        };

        let entrypoints = BsdShimEntrypoints {
            task,
            _not_send: core::marker::PhantomData,
        };

        Ok(LoadedProgram { entrypoints })
    }

    /// Get the global page manager.
    pub fn page_manager(&self) -> &PageManager<Platform, PAGE_SIZE> {
        &self.0.pm
    }
}

/// Builder for creating a [`BsdShim`].
pub struct BsdShimBuilder {
    litebox: LiteBox<Platform>,
}

impl Default for BsdShimBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BsdShimBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        let platform = litebox_platform_multiplex::platform();
        Self {
            litebox: LiteBox::new(platform),
        }
    }

    /// Build the shim.
    #[must_use]
    pub fn build(self) -> BsdShim {
        let global = Arc::new(GlobalState {
            pm: PageManager::new(&self.litebox),
            seccomp_enabled: core::sync::atomic::AtomicBool::new(false),
            litebox: self.litebox,
        });
        BsdShim(global)
    }
}
