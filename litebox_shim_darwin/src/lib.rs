// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A Darwin (macOS) shim for LiteBox.
//!
//! It runs x86-64 Mach-O executables that need no dynamic linker: the image is
//! mapped at its preferred address, the `syscall` instructions in its code are
//! redirected into the shim at load time (with the same runtime patcher the
//! Linux shim uses for unpatched ELF code), and `main` is entered the way dyld
//! would enter it. The system-call surface is the small BSD subset such
//! programs need, listed in the `syscalls` module.
//!
//! Anything that needs dyld and Apple's libraries (`libSystem`, and therefore
//! every ordinary macOS program) is out of reach: those cannot be redistributed,
//! so there is nothing for LiteBox to load in their place.

// The Darwin guest ABI this shim implements is the x86-64 one: the loader
// accepts only x86-64 images, system calls arrive through the x86-64 runtime
// patcher, and the register conventions below are x86-64's.
#![cfg(target_arch = "x86_64")]
#![no_std]

extern crate alloc;

use alloc::borrow::Cow;
use alloc::ffi::CString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use litebox::LiteBox;
use litebox::mm::PageManager;
use litebox::platform::{
    CrngProvider, PageManagementProvider, RawPointerProvider, StdioProvider, SystemInfoProvider,
};
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
use litebox::sync::RawSyncPrimitivesProvider;
use litebox_common_linux::PtRegs;

mod errno;
mod loader;
mod macho;
mod syscalls;

pub use loader::LoadError;
pub use macho::MachOError;

/// The page size of the Darwin x86-64 ABI.
pub const PAGE_SIZE: usize = 4096;

/// A LiteBox platform with the services the Darwin shim needs.
pub trait ShimPlatform:
    RawSyncPrimitivesProvider
    + RawPointerProvider
    + PageManagementProvider<PAGE_SIZE>
    + SystemInfoProvider
    + StdioProvider
    + CrngProvider
    + 'static
{
}

impl<T> ShimPlatform for T where
    T: RawSyncPrimitivesProvider
        + RawPointerProvider
        + PageManagementProvider<PAGE_SIZE>
        + SystemInfoProvider
        + StdioProvider
        + CrngProvider
        + 'static
{
}

/// A file system the Darwin shim can serve files from.
pub trait ShimFS: litebox::fs::FileSystem + Send + Sync + 'static {}
impl<T: litebox::fs::FileSystem + Send + Sync + 'static> ShimFS for T {}

/// The file system [`DarwinShimBuilder::default_fs`] builds: a writable
/// in-memory layer over `/dev` and a read-only tar archive.
pub type DefaultFS<Platform> = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::resolver::Resolver<Platform, litebox::fs::composer::Composer>,
        litebox::fs::resolver::Resolver<Platform, litebox::fs::composer::Composer>,
    >,
>;

pub(crate) type DarwinPageManager<Platform> = PageManager<Platform, PAGE_SIZE>;
pub(crate) type ConstPtr<Platform, T> =
    <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
pub(crate) type MutPtr<Platform, T> =
    <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

/// Builds a Darwin shim instance.
pub struct DarwinShimBuilder<Platform: ShimPlatform> {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
}

impl<Platform: ShimPlatform> DarwinShimBuilder<Platform> {
    #[must_use]
    pub fn new(platform: &'static Platform) -> Self {
        Self {
            platform,
            litebox: LiteBox::new(platform),
        }
    }

    #[must_use]
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    /// Build the default file system: `in_mem_fs` layered over `/dev` and the
    /// read-only contents of the tar archive `tar_data`.
    ///
    /// # Panics
    ///
    /// Panics if the fixed mount layout fails to compose, which it cannot for
    /// these two distinct mount points.
    #[must_use]
    pub fn default_fs(
        &self,
        in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
        tar_data: Cow<'static, [u8]>,
    ) -> DefaultFS<Platform> {
        let litebox = &self.litebox;
        let devices = litebox::fs::resolver::Resolver::new(
            litebox,
            litebox::fs::composer::Composer::builder()
                .mount("/dev", |allocator| {
                    litebox::fs::devices::Devices::new(litebox, allocator)
                })
                .build()
                .unwrap(),
        );
        let tar_ro = litebox::fs::resolver::Resolver::new(
            litebox,
            litebox::fs::composer::Composer::builder()
                .mount("/", |allocator| {
                    litebox::fs::tar_ro::TarRo::new(tar_data, allocator)
                })
                .build()
                .unwrap(),
        );
        litebox::fs::layered::FileSystem::new(
            litebox,
            in_mem_fs,
            litebox::fs::layered::FileSystem::new(
                litebox,
                devices,
                tar_ro,
                litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
            ),
            litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
        )
    }

    #[must_use]
    pub fn build<FS: ShimFS>(self) -> DarwinShim<Platform, FS> {
        DarwinShim(Arc::new(GlobalState {
            platform: self.platform,
            page_manager: PageManager::new(&self.litebox),
            litebox: self.litebox,
            _fs: core::marker::PhantomData,
        }))
    }
}

/// A built Darwin shim, ready to load programs.
pub struct DarwinShim<Platform: ShimPlatform, FS: ShimFS>(Arc<GlobalState<Platform, FS>>);

impl<Platform: ShimPlatform, FS: ShimFS> DarwinShim<Platform, FS> {
    /// Load the Mach-O executable at `path` in `fs` as the initial program.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be read, is not a Mach-O image this shim can
    /// run, or its address range or stack cannot be mapped.
    pub fn load_program(
        &self,
        fs: Arc<FS>,
        path: &str,
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram<Platform, FS>, LoadError> {
        let image = loader::read_file(&*fs, path)?;
        let loaded = loader::load(
            self.0.platform,
            &self.0.page_manager,
            &image,
            path,
            &argv,
            &envp,
        )?;
        let process = Arc::new(Process {
            exit_code: AtomicI32::new(0),
        });
        Ok(LoadedProgram {
            entrypoints: DarwinShimEntrypoints {
                task: Task {
                    global: self.0.clone(),
                    process: process.clone(),
                    fs,
                    files: litebox::sync::Mutex::new(syscalls::FileTable::new()),
                    start: loaded,
                },
            },
            process,
        })
    }
}

struct GlobalState<Platform: ShimPlatform, FS: ShimFS> {
    platform: &'static Platform,
    page_manager: DarwinPageManager<Platform>,
    #[expect(
        dead_code,
        reason = "keeps alive the LiteBox the page manager and file system were created from"
    )]
    litebox: LiteBox<Platform>,
    _fs: core::marker::PhantomData<FS>,
}

/// A loaded Darwin process.
pub struct Process {
    exit_code: AtomicI32,
}

impl Process {
    /// The process's exit status, once its thread has returned from
    /// [`EnterShim`] with [`ContinueOperation::Terminate`].
    #[must_use]
    pub fn wait(&self) -> i32 {
        self.exit_code.load(Ordering::Relaxed)
    }
}

struct Task<Platform: ShimPlatform, FS: ShimFS> {
    global: Arc<GlobalState<Platform, FS>>,
    process: Arc<Process>,
    fs: Arc<FS>,
    files: litebox::sync::Mutex<Platform, syscalls::FileTable<FS>>,
    start: loader::Start,
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
        // Enter `main(argc, argv, envp, apple)` with the return address already
        // pushed, exactly as dyld's start glue calls it.
        ctx.rip = self.start.entry;
        ctx.rsp = self.start.stack_pointer;
        ctx.rdi = self.start.argc;
        ctx.rsi = self.start.argv;
        ctx.rdx = self.start.envp;
        ctx.rcx = self.start.apple;
        ctx.eflags = 0x202;
        litebox_util_log::debug!(
            entry:% = format_args!("{:#x}", self.start.entry),
            stack:% = format_args!("{:#x}", self.start.stack_pointer);
            "starting Darwin guest"
        );
        ContinueOperation::Resume
    }

    fn exit(&self, status: i32) -> ContinueOperation {
        self.process.exit_code.store(status, Ordering::Relaxed);
        ContinueOperation::Terminate
    }
}

/// The shim's entry points for the initial thread of a loaded program.
pub struct DarwinShimEntrypoints<Platform: ShimPlatform, FS: ShimFS> {
    task: Task<Platform, FS>,
}

impl<Platform: ShimPlatform, FS: ShimFS> EnterShim for DarwinShimEntrypoints<Platform, FS> {
    type ExecutionContext = PtRegs;

    fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.task.init(ctx)
    }

    fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.task.handle_syscall(ctx)
    }

    fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
        const SIGILL: i32 = 4;
        const SIGSEGV: i32 = 11;
        // There are no guest signal handlers yet, so every fault is fatal, and
        // reported the way a shell reports a process killed by SIGSEGV/SIGILL.
        litebox_util_log::error!(
            rip:% = format_args!("{:#x}", ctx.rip),
            fault_address:% = format_args!("{:#x}", info.cr2),
            exception:? = info.exception;
            "Darwin guest faulted"
        );
        let signal = if info.exception == litebox::shim::Exception::INVALID_OPCODE {
            SIGILL
        } else {
            SIGSEGV
        };
        self.task.exit(128 + signal)
    }

    fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        // Nothing is ever pending: there are no guest signals or timers yet.
        ContinueOperation::Resume
    }
}

/// A program loaded by [`DarwinShim::load_program`].
pub struct LoadedProgram<Platform: ShimPlatform, FS: ShimFS> {
    /// Hand these to the platform's `run_thread`.
    pub entrypoints: DarwinShimEntrypoints<Platform, FS>,
    /// Holds the exit status once the thread finishes.
    pub process: Arc<Process>,
}
