// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides a Linux-compatible ABI via LiteBox.
//!
//! This shim is generic over the choice of [LiteBox platform](../litebox/platform/index.html).
//! The concrete platform is threaded in by the runner via [`LinuxShimBuilder::new`].

#![no_std]
#![expect(
    clippy::unused_self,
    reason = "by convention, syscalls and related methods take &self even if unused"
)]

extern crate alloc;

use alloc::borrow::Cow;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use core::cell::{Cell, RefCell};
use litebox::{
    LiteBox,
    fd::TypedFd,
    mm::{PageManager, vmem::PAGE_SIZE},
    net::Network,
    pipes::Pipes,
    platform::TimeProvider,
    shim::ContinueOperation,
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _},
};
use litebox_common_linux::{
    SyscallRequest,
    errno::Errno,
    user_pointers::{UserPtr, UserPtrMut},
};

/// Logs that the guest attempted to use an unsupported feature -- once per
/// distinct message, in every build (see [`unsupported`]).
// DEVNOTE: this is before the `mod` declarations so that it can be used within them.
macro_rules! log_unsupported {
    ($($arg:tt)*) => {
        $crate::log_unsupported_fmt(core::format_args!($($arg)*));
    };
}

pub(crate) mod channel;
pub mod host_service;
pub mod loader;
pub(crate) mod stdio;
pub mod syscalls;
pub mod transport;
pub mod vsock_transport;
mod wait;

use crate::syscalls::file::get_file_descriptor_flags;

pub type DefaultFS<Platform> = LinuxFS<Platform>;

pub(crate) type LinuxFS<Platform> = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::resolver::Resolver<Platform, litebox::fs::composer::Composer>,
        litebox::fs::resolver::Resolver<Platform, litebox::fs::composer::Composer>,
    >,
>;

pub(crate) type FileFd<FS> = litebox::fd::TypedFd<FS>;

/// A trait required for file systems to be used in the shim.
pub trait ShimFS: litebox::fs::FileSystem + Send + Sync + 'static {}
impl<T: litebox::fs::FileSystem + Send + Sync + 'static> ShimFS for T {}

/// Aggregate bound capturing everything the shim requires of a platform.
///
/// This exists so that the (many) `impl` blocks throughout the shim can be written
/// as `impl<Platform: ShimPlatform, ..>` rather than repeating a large `where` clause.
pub trait ShimPlatform:
    litebox::platform::RawPointerProvider
    + litebox::platform::TimeProvider
    + litebox::platform::PageManagementProvider<{ PAGE_SIZE }>
    + litebox::mm::vmem::VmemPageFaultHandler
    + litebox::platform::RawMutexProvider
    + litebox::sync::RawSyncPrimitivesProvider
    + litebox::platform::CrngProvider
    + litebox::platform::SystemInfoProvider
    + litebox::platform::StdioProvider
    + litebox::platform::ArchSpecificProvider
    + litebox::platform::ThreadProvider<ExecutionContext = litebox_common_linux::PtRegs>
    + litebox::platform::TimerProvider<Signal = litebox_common_linux::signal::Signal>
    + litebox::platform::SignalProvider<Signal = litebox_common_linux::signal::Signal>
    + litebox::platform::IPInterfaceProvider
    + 'static
{
}

impl<T> ShimPlatform for T where
    T: litebox::platform::RawPointerProvider
        + litebox::platform::TimeProvider
        + litebox::platform::PageManagementProvider<{ PAGE_SIZE }>
        + litebox::mm::vmem::VmemPageFaultHandler
        + litebox::platform::RawMutexProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::CrngProvider
        + litebox::platform::SystemInfoProvider
        + litebox::platform::StdioProvider
        + litebox::platform::ArchSpecificProvider
        + litebox::platform::ThreadProvider<ExecutionContext = litebox_common_linux::PtRegs>
        + litebox::platform::TimerProvider<Signal = litebox_common_linux::signal::Signal>
        + litebox::platform::SignalProvider<Signal = litebox_common_linux::signal::Signal>
        + litebox::platform::IPInterfaceProvider
        + 'static
{
}

/// Logs that the guest attempted to use an unsupported feature.
///
/// Every build logs this, but only the first sighting of each distinct message
/// is emitted at `warn`; repeats are counted and shown only at `trace`, next to
/// the per-syscall trace. The previous `debug_assertions`-only gate made the
/// whole class invisible in the release runner, which is where real guests run
/// (a Chromium startup hit `mseal` and `prctl(PR_SET_VMA)` thousands of times
/// with nothing logged), and an ungated per-call line at that rate would bury
/// everything else. See [`unsupported`] for the bounded dedupe table.
fn log_unsupported_fmt(args: core::fmt::Arguments<'_>) {
    let shape = unsupported::shape_of(args);
    match unsupported::record(None, &shape) {
        unsupported::Sighting::First => {
            litebox_util_log::warn!(
                feature:% = shape;
                "unsupported (first sighting; repeats logged at trace level)"
            );
        }
        unsupported::Sighting::Repeat(count) => {
            litebox_util_log::trace!(feature:% = shape, count:? = count; "unsupported (repeat)");
        }
    }
}

/// A bounded, deduplicated record of the unsupported guest requests seen so
/// far, so that release builds can report each distinct one exactly once.
///
/// Keyed by the syscall number (when the caller knows it) and the formatted
/// message, which doubles as the "argument shape": `prctl(SetVma)` and
/// `prctl(PR_SET_KEEPCAPS, 7)` are distinct rows, while the ten-thousandth
/// `mseal` is the same row as the first. The table is fixed-size and lives in a
/// `static` because the reporting entry points (`log_unsupported!`) have no
/// task in scope; when it fills up (a caller formatting a pointer into the
/// message, say), distinct-ness degrades to "one line per syscall number" via
/// a bitmap, and to nothing at all for number-less callers -- never to a
/// per-call flood, and never to unbounded growth.
mod unsupported {
    use arrayvec::{ArrayString, ArrayVec};
    use core::fmt::Write as _;

    /// Longest message kept per row; longer ones are truncated, which only
    /// makes two long messages collide, never a lost row.
    pub(crate) const SHAPE_LEN: usize = 96;
    const TABLE_LEN: usize = 128;
    /// Bits for syscall numbers `0..SYSNO_BITMAP_BITS`; the bitmap is the
    /// overflow fallback once the row table is full.
    const SYSNO_BITMAP_WORDS: usize = 16;

    pub(crate) type Shape = ArrayString<SHAPE_LEN>;

    struct Row {
        nr: Option<usize>,
        shape: Shape,
        count: u64,
    }

    struct Table {
        rows: ArrayVec<Row, TABLE_LEN>,
        /// Syscall numbers that have had at least one line emitted after the
        /// row table filled up.
        overflow_seen: [u64; SYSNO_BITMAP_WORDS],
        /// Sightings that found the table full and their number already
        /// reported (or had no number): counted so the loss is measurable.
        overflow_dropped: u64,
    }

    static TABLE: spin::Mutex<Table> = spin::Mutex::new(Table {
        rows: ArrayVec::new_const(),
        overflow_seen: [0; SYSNO_BITMAP_WORDS],
        overflow_dropped: 0,
    });

    /// What [`record`] found: the caller logs a `First` loudly and a `Repeat`
    /// only at trace level.
    pub(crate) enum Sighting {
        First,
        Repeat(u64),
    }

    /// Format `args` into a bounded key; truncation is silent by design.
    pub(crate) fn shape_of(args: core::fmt::Arguments<'_>) -> Shape {
        let mut shape = Shape::new_const();
        let _ = write!(shape, "{args}");
        shape
    }

    /// Record one sighting of (`nr`, `shape`).
    pub(crate) fn record(nr: Option<usize>, shape: &Shape) -> Sighting {
        let mut table = TABLE.lock();
        if let Some(row) = table
            .rows
            .iter_mut()
            .find(|row| row.nr == nr && row.shape == *shape)
        {
            row.count = row.count.saturating_add(1);
            return Sighting::Repeat(row.count);
        }
        if table
            .rows
            .try_push(Row {
                nr,
                shape: *shape,
                count: 1,
            })
            .is_ok()
        {
            return Sighting::First;
        }
        // Table full: fall back to once-per-syscall-number.
        if let Some(nr) = nr
            && let Some(word) = table.overflow_seen.get_mut(nr / 64)
        {
            let bit = 1u64 << (nr % 64);
            if *word & bit == 0 {
                *word |= bit;
                return Sighting::First;
            }
        }
        table.overflow_dropped = table.overflow_dropped.saturating_add(1);
        Sighting::Repeat(table.overflow_dropped)
    }

    /// The Linux name of syscall `nr`, from the `syscalls` crate's table, with
    /// a local tail for numbers newer than that table (`mseal` is the one a
    /// current Chromium probes on every large mapping).
    pub(crate) fn syscall_name(nr: usize) -> &'static str {
        if let Some(sysno) = ::syscalls::Sysno::new(nr) {
            return sysno.name();
        }
        match nr {
            462 => "mseal",
            463 => "setxattrat",
            464 => "getxattrat",
            465 => "listxattrat",
            466 => "removexattrat",
            467 => "open_tree_attr",
            468 => "file_getattr",
            469 => "file_setattr",
            _ => "?",
        }
    }
}

#[cfg(target_pointer_width = "64")]
fn preadv_pwritev_offset(pos_l: usize, _pos_h: usize) -> i64 {
    pos_l.reinterpret_as_signed() as i64
}

#[cfg(target_pointer_width = "32")]
fn preadv_pwritev_offset(pos_l: usize, pos_h: usize) -> i64 {
    ((pos_h as u64) << 32 | pos_l as u64).reinterpret_as_signed()
}

pub struct LinuxShimEntrypoints<Platform: ShimPlatform, FS: ShimFS> {
    task: Task<Platform, FS>,
    // The task should not be moved once it's bound to a platform thread so that
    // we preserve the ability to use TLS in the future.
    _not_send: core::marker::PhantomData<*const ()>,
}

/// Decodes a host exception into the pair the memory manager needs to service a
/// demand fault -- the faulting address and the architecture's raw fault status
/// word -- or `None` when the exception is not a memory fault at all.
///
/// x86-64 reports the address in `CR2` and the status in the hardware error
/// code; aarch64 reports them in `FAR_EL1` and `ESR_EL1`. Both are opaque here:
/// the platform's [`VmemPageFaultHandler`](litebox::mm::vmem::VmemPageFaultHandler)
/// is what decodes the status word.
#[cfg(target_arch = "x86_64")]
fn page_fault_info(info: &litebox::shim::ExceptionInfo) -> Option<(usize, u64)> {
    (info.exception == litebox::shim::Exception::PAGE_FAULT)
        .then(|| (info.cr2, u64::from(info.error_code)))
}

#[cfg(target_arch = "aarch64")]
fn page_fault_info(info: &litebox::shim::ExceptionInfo) -> Option<(usize, u64)> {
    use litebox::shim::Exception;

    // Both abort classes are memory faults; the current-EL variants are the
    // ones raised by LiteBox's own accesses to guest memory.
    let is_abort = matches!(
        info.exception,
        Exception::DATA_ABORT_CURRENT_EL
            | Exception::DATA_ABORT_LOWER_EL
            | Exception::INSTRUCTION_ABORT_CURRENT_EL
            | Exception::INSTRUCTION_ABORT_LOWER_EL
    );
    is_abort.then_some((info.fault_address, info.esr))
}

impl<Platform: ShimPlatform, FS: ShimFS> litebox::shim::EnterShim
    for LinuxShimEntrypoints<Platform, FS>
{
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(true, ctx, Task::handle_init_request)
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, Task::handle_syscall_request)
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &litebox::shim::ExceptionInfo,
    ) -> ContinueOperation {
        if info.kernel_mode
            && let Some((fault_address, error_code)) = page_fault_info(info)
        {
            if unsafe {
                self.task
                    .global
                    .pm
                    .handle_page_fault(fault_address, error_code)
            }
            .is_ok()
            {
                return ContinueOperation::Resume;
            } else {
                return ContinueOperation::Terminate;
            }
        }
        // Best-effort symbolization of a genuine guest fault: name the guest
        // ELF image (and image-relative offset) containing the fault PC and
        // the return address, in the `path+0xoffset` form `llvm-symbolizer`
        // resolves directly against the guest's own binaries. Debug level so
        // it is inert unless logging is enabled -- guests also take faults on
        // purpose (e.g. OpenSSL's SIGILL CPU-feature probes).
        {
            let symbolize = |addr: usize| match self.task.symbolize_guest_address(addr) {
                Some((path, offset)) => alloc::format!("{path}+{offset:#x}"),
                None => alloc::format!("{addr:#x} (no image)"),
            };
            #[cfg(target_arch = "aarch64")]
            {
                litebox_util_log::debug!(
                    pc:% = symbolize(ctx.pc), x30:% = symbolize(ctx.regs[30]),
                    exception:? = info.exception;
                    "guest fault location"
                );
                // The integer register file, so a data abort's faulting address can be
                // reconstructed from the disassembly at `pc` (the platform's `fault_address`
                // is not always populated).
                let mut regs = alloc::string::String::new();
                for (i, r) in ctx.regs.iter().enumerate() {
                    use core::fmt::Write as _;
                    let _ = write!(regs, "x{i}={r:#x} ");
                }
                litebox_util_log::debug!(
                    sp:% = alloc::format!("{:#x}", ctx.sp), regs:% = regs;
                    "guest fault registers"
                );
            }
            #[cfg(target_arch = "x86_64")]
            litebox_util_log::debug!(
                rip:% = symbolize(ctx.rip), rsp:% = alloc::format!("{:#x}", ctx.rsp),
                exception:? = info.exception;
                "guest fault location"
            );
        }
        self.enter_shim(false, ctx, |task, _ctx| task.handle_exception_request(info))
    }

    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, |_, _| {})
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> LinuxShimEntrypoints<Platform, FS> {
    fn enter_shim(
        &self,
        is_init: bool,
        ctx: &mut litebox_common_linux::PtRegs,
        f: impl FnOnce(&Task<Platform, FS>, &mut litebox_common_linux::PtRegs),
    ) -> ContinueOperation {
        if !is_init {
            self.task.enter_from_guest();
        }
        // Recorded on every entry so that a snapshot taken later -- at a blocking point deep
        // inside a syscall, where no `PtRegs` is in reach -- knows where this task's live guest
        // stack starts. See `syscalls::process::Task::save_address_space`.
        self.task
            .record_guest_sp(syscalls::process::guest_stack_pointer(ctx));
        f(&self.task, ctx);
        if self.task.prepare_to_run_guest(ctx) {
            ContinueOperation::Resume
        } else {
            ContinueOperation::Terminate
        }
    }
}

/// The shim entry point structure.
pub struct LinuxShimBuilder<Platform: ShimPlatform> {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
    /// Handle to the `/proc` backend mounted by [`Self::default_fs`], if it was called.
    /// [`Self::build`] moves this into [`GlobalState`] so the shim can publish the guest task's
    /// identity into it as that becomes known (see `syscalls::process::Task::set_task_comm`).
    proc_handle: Cell<Option<litebox::fs::proc::Proc<Platform>>>,
    /// Handle to the `/dev/fb0` framebuffer mounted by [`Self::default_fs`], if it was called.
    /// [`Self::build`] moves this into [`GlobalState`] so `sys_ioctl` can service `FBIO*`
    /// requests directly, without threading the framebuffer through the generic `FS` type.
    framebuffer: Cell<Option<litebox::fs::devices::Framebuffer<Platform>>>,
    /// Handle to the `/dev/input` event-device registry mounted by [`Self::default_fs`], if it
    /// was called. Same lifecycle as `framebuffer`: [`Self::build`] moves it into
    /// [`GlobalState`] for `sys_ioctl`/`sys_read`/poll interception, and the runner takes a
    /// clone (via [`LinuxShim::input_registry`]) to inject RFB input events through.
    input_registry: Cell<Option<litebox::fs::devices::InputRegistry<Platform>>>,
}

impl<Platform: ShimPlatform> LinuxShimBuilder<Platform> {
    /// Returns a new shim builder using the given platform.
    pub fn new(platform: &'static Platform) -> Self {
        Self::new_with_litebox(platform, LiteBox::new(platform))
    }

    /// Returns a new shim builder using an already-created LiteBox instance.
    pub fn new_with_litebox(platform: &'static Platform, litebox: LiteBox<Platform>) -> Self {
        Self {
            platform,
            litebox,
            proc_handle: Cell::new(None),
            framebuffer: Cell::new(None),
            input_registry: Cell::new(None),
        }
    }

    /// Returns the litebox object for the shim.
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    /// Create a default layered file system with the given in-memory layer and tar data.
    ///
    /// Also mounts a `/proc` backend and a `/dev/fb0` framebuffer, stashing handles to both on
    /// `self`; [`Self::build`] moves them into the built shim's `GlobalState` so the guest task's
    /// identity can be published into `/proc/<pid>/*` once it's known, and `sys_ioctl` can
    /// service `FBIO*` requests. Calling this more than once replaces the stashed handles with
    /// the most recent call's -- only the filesystem actually passed to
    /// `LinuxShim::load_program` should be kept live.
    pub fn default_fs(
        &self,
        in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
        tar_data: Cow<'static, [u8]>,
    ) -> DefaultFS<Platform> {
        let (fs, proc_handle, framebuffer, input_registry) =
            default_fs(&self.litebox, in_mem_fs, tar_data);
        self.proc_handle.set(Some(proc_handle));
        self.framebuffer.set(Some(framebuffer));
        self.input_registry.set(Some(input_registry));
        fs
    }

    /// Build the shim.
    pub fn build<FS: ShimFS>(self) -> LinuxShim<Platform, FS> {
        self.build_with_net_config(None, None)
    }

    /// Same as [`Self::build`], but lets the caller override this instance's
    /// interface/gateway addresses (`None` = use `Network::new`'s default of
    /// `10.0.0.2`/`10.0.0.1`). Needed to run more than one shim on the same
    /// host at once, each independently reachable.
    pub fn build_with_net_config<FS: ShimFS>(
        self,
        interface_ip: Option<core::net::Ipv4Addr>,
        gateway_ip: Option<core::net::Ipv4Addr>,
    ) -> LinuxShim<Platform, FS> {
        let mut net = Network::new_with_optional_addrs(&self.litebox, interface_ip, gateway_ip);
        net.set_platform_interaction(litebox::net::PlatformInteraction::Manual);
        let global = Arc::new(GlobalState {
            platform: self.platform,
            pm: PageManager::new(&self.litebox),
            pipes: Pipes::new(&self.litebox),
            net: litebox::sync::Mutex::new(net),
            boot_time: self.platform.now(),
            next_thread_id: 2.into(), // start from 2, as 1 is used by the main thread
            proc_handle: self.proc_handle.take(),
            framebuffer: self.framebuffer.take(),
            input_registry: self.input_registry.take(),
            litebox: self.litebox,
            unix_addr_table: litebox::sync::RwLock::new(syscalls::unix::UnixAddrTable::new()),
            pty_registry: Arc::new(syscalls::file::PtyRegistry::new()),
            guest_images: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
            loaded_images: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
            shared_file_backings: litebox::sync::Mutex::new(alloc::collections::BTreeMap::new()),
            termios: litebox::sync::Mutex::new(litebox_common_linux::Termios::default_cooked()),
            stdio_foreground_pgid: core::sync::atomic::AtomicI32::new(0),
            processes: syscalls::process::ProcessTable::new(),
            brk_lock: litebox::sync::Mutex::new(()),
        });
        LinuxShim(global)
    }
}

pub struct LinuxShim<Platform: ShimPlatform, FS: ShimFS>(Arc<GlobalState<Platform, FS>>);
impl<Platform: ShimPlatform, FS: ShimFS> Clone for LinuxShim<Platform, FS> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> LinuxShim<Platform, FS> {
    /// A cheap handle to this shim's `/dev/fb0` framebuffer, if [`LinuxShimBuilder::default_fs`]
    /// mounted one -- for a runner-side reader (e.g. an RFB server) to read guest-painted pixels
    /// independently of any guest fd. `None` when the shim was built with a filesystem that
    /// doesn't mount `/dev/fb0`.
    #[must_use]
    pub fn framebuffer(&self) -> Option<litebox::fs::devices::Framebuffer<Platform>> {
        self.0.framebuffer.clone()
    }

    /// A cheap handle to this shim's `/dev/input` event-device registry, if
    /// [`LinuxShimBuilder::default_fs`] mounted one -- for a runner-side injector (e.g. the RFB
    /// server's input events) to feed guest-visible keyboard/pointer events through.
    #[must_use]
    pub fn input_registry(&self) -> Option<litebox::fs::devices::InputRegistry<Platform>> {
        self.0.input_registry.clone()
    }

    /// Loads the program at `path` as the shim's initial task, returning the
    /// initial register state.
    pub fn load_program(
        &self,
        fs: alloc::sync::Arc<FS>,
        task: litebox_common_linux::TaskParams,
        path: &str,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
    ) -> Result<LoadedProgram<Platform, FS>, loader::elf::ElfLoaderError> {
        let litebox_common_linux::TaskParams {
            pid,
            ppid,
            uid,
            euid,
            gid,
            egid,
        } = task;

        let files = syscalls::file::FilesState::new(fs);
        // Actual fd-allocation ceiling stays at the hard limit regardless of the reported soft
        // `RLIMIT_NOFILE` default (see that constant's own doc comment): a process that never
        // calls `setrlimit` can still open as many fds as it needs, matching this shim's existing
        // choice not to enforce rlimits, while `getrlimit`/`prlimit64` still *report* a realistic
        // low soft default so close-every-fd-up-to-the-limit startup loops (real daemons do this,
        // `dbus-daemon` observed live) stay fast instead of scanning up to a million fds.
        files.set_max_fd(syscalls::process::RLIMIT_NOFILE_MAX - 1);
        let files = Arc::new(files);
        files.initialize_stdio_in_shared_descriptors_table(&self.0);

        // Keep the pid/tid allocator clear of the initial task's own pid, so that no `fork`ed
        // child can ever collide with it.
        self.0
            .next_thread_id
            .fetch_max(pid.saturating_add(1), core::sync::atomic::Ordering::Relaxed);
        self.0
            .stdio_foreground_pgid
            .store(pid, core::sync::atomic::Ordering::Release);

        let entrypoints = crate::LinuxShimEntrypoints {
            _not_send: core::marker::PhantomData,
            task: Task {
                global: self.0.clone(),
                thread: syscalls::process::ThreadState::new_process(pid, pid),
                wait_state: wait::WaitState::new(self.0.platform),
                pid,
                ppid,
                tid: pid,
                credentials: RefCell::new(
                    syscalls::process::Credentials::new(uid, euid, gid, egid).into(),
                ),
                comm: [0; litebox_common_linux::TASK_COMM_LEN].into(), // set at load time
                fs: Arc::new(syscalls::file::FsState::new()).into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::new_process(),
                guest_sp: Cell::new(0),
            },
        };

        let (path, argv) = entrypoints
            .task
            .resolve_shebang(alloc::string::String::from(path), argv)
            .map_err(loader::elf::ElfLoaderError::OpenError)?;

        entrypoints.task.load_program(
            loader::elf::ElfLoader::new(&entrypoints.task, &path)?,
            argv,
            envp,
        )?;
        let process = LinuxShimProcess(entrypoints.task.process().clone());
        Ok(LoadedProgram {
            entrypoints,
            process,
        })
    }

    /// Get the global page manager
    pub fn page_manager(&self) -> &PageManager<Platform, PAGE_SIZE> {
        &self.0.pm
    }

    /// Perform queued network interactions with the outside world.
    ///
    /// This function should be invoked in a loop, based on the returned advice.
    pub fn perform_network_interaction(
        &self,
    ) -> litebox::net::PlatformInteractionReinvocationAdvice {
        self.0.net.lock().perform_platform_interaction()
    }

    /// Establish a TCP connection to the given address.
    ///
    /// Returns a [`transport::ShimTransport`] that can be used as a
    /// byte-stream transport (e.g., for a 9P filesystem client).
    pub fn tcp_connection(
        &self,
        addr: core::net::SocketAddr,
    ) -> Result<transport::ShimTransport<Platform>, Errno> {
        transport::ShimTransport::connect(self.0.clone(), addr)
    }

    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.0.litebox
    }

    /// Create a host-owned TCP listener inside the guest's network stack (typically on the
    /// guest's loopback), whose accepted connections host code services directly -- the
    /// listening-side counterpart of [`Self::tcp_connection`]. The guest never sees an fd for
    /// any of these sockets.
    ///
    /// # Errors
    ///
    /// Fails if the socket cannot be created, bound (e.g. the guest already owns the port), or
    /// put into the listening state.
    pub fn listen_in_guest(
        &self,
        addr: core::net::SocketAddr,
        backlog: u16,
    ) -> Result<host_service::GuestListener<Platform>, Errno> {
        host_service::listen_in_guest(&self.0, addr, backlog)
    }

    /// Create a host-owned UDP socket bound inside the guest's network stack (typically on the
    /// guest's loopback) -- the datagram counterpart of [`Self::listen_in_guest`]. The guest
    /// never sees an fd for it.
    ///
    /// # Errors
    ///
    /// Fails if the socket cannot be created or bound (e.g. the guest already owns the port).
    pub fn bind_udp_in_guest(
        &self,
        addr: core::net::SocketAddr,
    ) -> Result<host_service::GuestDatagramSocket<Platform>, Errno> {
        host_service::bind_udp_in_guest(&self.0, addr)
    }

    /// Returns the platform this shim was built with.
    pub fn platform(&self) -> &'static Platform {
        self.0.platform
    }
}

pub struct LoadedProgram<Platform: ShimPlatform, FS: ShimFS> {
    pub entrypoints: LinuxShimEntrypoints<Platform, FS>,
    pub process: LinuxShimProcess<Platform>,
}

/// A handle to a process loaded via [`LinuxShim::load_program`].
///
/// This can be used to wait for the process to exit.
pub struct LinuxShimProcess<Platform: ShimPlatform>(Arc<syscalls::process::Process<Platform>>);

impl<Platform: ShimPlatform> LinuxShimProcess<Platform> {
    /// Wait for the process to exit, returning its exit code.
    pub fn wait(&self) -> i32 {
        match self.0.wait_for_exit() {
            syscalls::process::ExitStatus::Exit(v) => v.into(),
            // TODO: return the enum instead of just a code?
            syscalls::process::ExitStatus::Signal(signal) => signal.as_i32() + 256,
        }
    }
}

/// Create a default layered file system with the given in-memory layer and tar data.
///
/// Also returns a handle to the mounted `/proc` backend, and to the mounted `/dev/fb0`
/// framebuffer; the caller (`LinuxShimBuilder`) is responsible for keeping the `/proc` handle
/// reachable so the guest task's identity can be published into it once known -- see
/// `syscalls::process::Task::set_task_comm` -- and stashes the framebuffer handle into
/// `GlobalState` so `sys_ioctl` can service `FBIO*` requests without threading it through the
/// generic `FS` type.
fn default_fs<Platform: ShimPlatform>(
    litebox: &LiteBox<Platform>,
    in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
    tar_data: Cow<'static, [u8]>,
) -> (
    LinuxFS<Platform>,
    litebox::fs::proc::Proc<Platform>,
    litebox::fs::devices::Framebuffer<Platform>,
    litebox::fs::devices::InputRegistry<Platform>,
) {
    let mut proc_handle = None;
    let mut framebuffer = None;
    let input_registry = litebox::fs::devices::InputRegistry::new();
    let input_registry_for_mount = input_registry.clone();
    let current_user = in_mem_fs.current_user();
    let dev_stdio = litebox::fs::resolver::Resolver::new_with_user(
        litebox,
        litebox::fs::composer::Composer::builder()
            .mount("/dev", |allocator| {
                let devices = litebox::fs::devices::Devices::new(litebox, allocator);
                framebuffer = Some(devices.framebuffer());
                devices
            })
            .mount("/dev/input", |allocator| {
                litebox::fs::devices::InputDevices::new(allocator, input_registry_for_mount)
            })
            .mount("/proc", |allocator| {
                let proc = litebox::fs::proc::Proc::new(allocator);
                proc_handle = Some(proc.clone());
                proc
            })
            .build()
            .unwrap(),
        current_user,
    );
    let proc_handle = proc_handle.expect("mounted immediately above");
    // `Composer::builder().mount("/dev", ..)`'s closure runs synchronously inside `.build()`
    // above, so `framebuffer` is always `Some` here in practice; falling back to a fresh,
    // unmounted `Framebuffer` rather than panicking keeps this path total even if that
    // invariant is ever violated by a future refactor.
    let framebuffer = framebuffer.unwrap_or_else(litebox::fs::devices::Framebuffer::new);
    let tar_ro = litebox::fs::resolver::Resolver::new_with_user(
        litebox,
        litebox::fs::composer::Composer::builder()
            .mount("/", |allocator| {
                litebox::fs::tar_ro::TarRo::new(tar_data, allocator)
            })
            .build()
            .unwrap(),
        current_user,
    );
    let fs = litebox::fs::layered::FileSystem::new_with_user(
        litebox,
        in_mem_fs,
        litebox::fs::layered::FileSystem::new_with_user(
            litebox,
            dev_stdio,
            tar_ro,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
            current_user,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
        current_user,
    );
    (fs, proc_handle, framebuffer, input_registry)
}

// Special override so that `GETFL` can return stdio-specific flags
#[derive(Clone)]
pub(crate) struct StdioStatusFlags(litebox::fs::OFlags);

impl<Platform: ShimPlatform, FS: ShimFS> syscalls::file::FilesState<Platform, FS> {
    fn initialize_stdio_in_shared_descriptors_table(&self, global: &GlobalState<Platform, FS>) {
        use litebox::fs::{Mode, OFlags};
        let stdin = self
            .fs
            .open("/dev/stdin", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let stdout = self
            .fs
            .open("/dev/stdout", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let stderr = self
            .fs
            .open("/dev/stderr", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let mut dt = global.litebox.descriptor_table_mut();
        let mut rds = self.raw_descriptor_store.write();
        for (raw_fd, fd, stream) in [
            (0, stdin, litebox::platform::StdioStream::Stdin),
            (1, stdout, litebox::platform::StdioStream::Stdout),
            (2, stderr, litebox::platform::StdioStream::Stderr),
        ] {
            let status_flags = OFlags::APPEND | OFlags::RDWR;
            debug_assert_eq!(OFlags::STATUS_FLAGS_MASK & status_flags, status_flags);
            let old = dt.set_entry_metadata(&fd, StdioStatusFlags(status_flags));
            assert!(old.is_none());
            let old = dt.set_entry_metadata(&fd, stream);
            assert!(old.is_none());
            let success = rds.fd_into_specific_raw_integer(fd, raw_fd);
            assert!(success);
        }
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn close_on_exec(&self) {
        let files = self.files.borrow();
        let alive_fds: Vec<usize> = files.raw_descriptor_store.read().iter_alive().collect();
        for raw_fd in alive_fds {
            if let Ok(flags) = get_file_descriptor_flags(raw_fd, &self.global, &files)
                && flags.contains(litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC)
            {
                let _ = self.do_close(raw_fd);
            }
        }
    }

    /// Explicitly closes every fd still alive in this (process-wide-last) file table.
    ///
    /// See `syscalls::process::Task::prepare_for_exit` for why this has to be explicit rather
    /// than relying on `FilesState`'s `Drop`.
    pub(crate) fn close_all_fds_on_exit(&self) {
        let files = self.files.borrow();
        let alive_fds: Vec<usize> = files.raw_descriptor_store.read().iter_alive().collect();
        for raw_fd in alive_fds {
            let _ = self.do_close(raw_fd);
        }
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> syscalls::file::FilesState<Platform, FS> {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn run_on_raw_fd<R>(
        &self,
        fd: usize,
        fs: impl FnOnce(&TypedFd<FS>) -> R,
        net: impl FnOnce(&TypedFd<Network<Platform>>) -> R,
        pipes: impl FnOnce(&TypedFd<Pipes<Platform>>) -> R,
        eventfd: impl FnOnce(&TypedFd<syscalls::eventfd::EventfdSubsystem<Platform>>) -> R,
        epoll: impl FnOnce(&TypedFd<syscalls::epoll::EpollSubsystem<Platform, FS>>) -> R,
        unix: impl FnOnce(&TypedFd<syscalls::unix::UnixSocketSubsystem<Platform, FS>>) -> R,
        netlink: impl FnOnce(&TypedFd<syscalls::netlink::NetlinkSubsystem<Platform>>) -> R,
    ) -> Result<R, Errno> {
        let rds = self.raw_descriptor_store.read();
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(fs(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(net(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(pipes(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(eventfd(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(epoll(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(unix(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(netlink(&fd));
        }
        Err(Errno::EBADF)
    }
}

// This places size limits on maximum read/write sizes that might occur; it exists primarily to
// prevent OOM due to the user asking for a _massive_ read or such at once. Keeping this too small
// has the downside of requiring too many syscalls, while having it be too large allows for massive
// allocations to be triggered by the userland program. For now, this is set to a
// hopefully-reasonable middle ground.
const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

trait ToSyscallResult {
    fn to_syscall_result(self) -> Result<usize, Errno>;
}
impl ToSyscallResult for Result<(), Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self.map(|()| 0)
    }
}
impl ToSyscallResult for Result<usize, Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self
    }
}
impl ToSyscallResult for Result<u32, Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self.map(|v| v as usize)
    }
}
impl ToSyscallResult for Result<i32, Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        // `inotify_add_watch(2)`'s only current caller of this impl returns a small positive
        // watch descriptor; the raw syscall ABI still reinterprets it as an unsigned register
        // value exactly like every other non-negative-int-returning syscall here.
        self.map(|v| v.reinterpret_as_unsigned() as usize)
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// A wrapper function around `sys_pread64` that copies data in chunks to avoid OOMing.
    fn pread_with_user_buf(
        &self,
        fd: i32,
        buf: UserPtrMut<u8>,
        count: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
        let mut read_total = 0;
        while read_total < count {
            let to_read = (count - read_total).min(kernel_buf.len());
            match self.sys_pread64(
                fd,
                &mut kernel_buf[..to_read],
                offset + (read_total.reinterpret_as_signed() as i64),
            ) {
                Ok(0) => break, // EOF
                Ok(size) => {
                    buf.copy_from_slice::<Platform>(read_total, &kernel_buf[..size])
                        .ok_or(Errno::EFAULT)?;
                    read_total += size;
                }
                Err(e) => return Err(e),
            }
        }
        assert!(read_total <= count);
        Ok(read_total)
    }

    /// A wrapper around `sys_write`/`sys_pwrite64` that copies the guest buffer
    /// in bounded chunks to avoid a single unbounded allocation for a huge
    /// guest-supplied `count`, mirroring [`Self::pread_with_user_buf`].
    ///
    /// Unlike the read direction, a write is not itself retried past a short
    /// result: `sys_write` may legitimately write fewer bytes than asked (a
    /// pipe or socket at capacity), and real `write(2)` semantics leave
    /// retrying a short write to the caller, not the kernel. So only the
    /// copy-from-guest-memory step is chunked; a chunk that is not fully
    /// consumed ends the loop, exactly as a single unchunked write to that
    /// same destination would have.
    fn write_with_user_buf(
        &self,
        fd: i32,
        buf: UserPtr<u8>,
        count: usize,
        offset: Option<usize>,
    ) -> Result<usize, Errno> {
        // A zero-length write must still dispatch: Linux checks fd validity
        // and writability before it looks at count, so write(read_end, buf, 0)
        // is EBADF, not a silent 0 (witnessed live by pipe_broker's lifecycle
        // sub-test under the broker runner). The descriptor layers already
        // handle empty buffers correctly past that check.
        if count == 0 {
            return self.sys_write(fd, &[], offset);
        }
        let mut written_total = 0;
        while written_total < count {
            let to_write = (count - written_total).min(MAX_KERNEL_BUF_SIZE);
            let chunk_ptr = UserPtr::<u8>::from_usize(buf.as_usize() + written_total);
            let Some(chunk) = chunk_ptr.to_owned_slice::<Platform>(to_write) else {
                return if written_total > 0 {
                    Ok(written_total)
                } else {
                    Err(Errno::EFAULT)
                };
            };
            match self.sys_write(fd, &chunk, offset.map(|o| o + written_total)) {
                Ok(size) => {
                    written_total += size;
                    if size < to_write {
                        // A short write: the destination could not currently
                        // accept the full chunk. Stop here, matching what a
                        // single unchunked write to the same destination
                        // would have returned.
                        break;
                    }
                }
                Err(e) => {
                    return if written_total > 0 {
                        Ok(written_total)
                    } else {
                        Err(e)
                    };
                }
            }
        }
        assert!(written_total <= count);
        Ok(written_total)
    }

    /// Handle Linux syscalls and dispatch them to LiteBox implementations.
    ///
    /// # Panics
    ///
    /// Unsupported syscalls or arguments would trigger a panic for development purposes.
    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let result = self.do_syscall(ctx);
        // The request-side twin of this line lives in `do_syscall` (the
        // `req=` trace). Logging the result too is what turns the trace into
        // a usable differential record: a guest that aborts after a burst of
        // syscalls (libuv's `uv_loop_init` cleanup was the motivating case)
        // is undiagnosable from requests alone, because the failing call and
        // the cleanup that follows it look identical without return values.
        litebox_util_log::trace!(pid:? = self.pid, tid:? = self.tid, ret:? = result; "sysret");
        let return_value = match result {
            Ok(v) => v,
            Err(err) => (err.as_neg() as isize).reinterpret_as_unsigned(),
        };
        #[cfg(target_arch = "x86_64")]
        {
            ctx.rax = return_value;
        }
        #[cfg(target_arch = "aarch64")]
        {
            // The aarch64 Linux syscall ABI returns in x0.
            ctx.regs[0] = return_value;
        }
    }

    fn do_syscall(&self, ctx: &mut litebox_common_linux::PtRegs) -> Result<usize, Errno> {
        // Helper macro to unify the return value from `sys_*`.
        macro_rules! syscall {
            ($func:ident($($args:expr),*)) => {
                self.$func($($args),*).to_syscall_result()
            };
        }

        #[cfg(target_arch = "x86_64")]
        let syscall_number = ctx.orig_rax;
        // The aarch64 Linux syscall ABI passes the number in x8, which the entry
        // path records in `pt_regs::syscallno`. Sign-extending keeps an
        // out-of-range value (the kernel writes -1 for "no syscall") looking the
        // same as it does in x86-64's `orig_rax`, so the dispatch below rejects
        // it identically on both architectures.
        #[cfg(target_arch = "aarch64")]
        let syscall_number = (ctx.syscallno as isize).reinterpret_as_unsigned();
        // The decoder reports what it could not decode through the callback; keep
        // that message out of band so the one line logged below can carry the
        // syscall number, its name, the decoder's own description of the
        // unsupported shape, and the errno the guest is about to see -- and so
        // that a decode failure the decoder does *not* flag (a bare `EINVAL`
        // for an unknown `prctl` option, say) is still visible, once.
        let decode_note: RefCell<Option<unsupported::Shape>> = RefCell::new(None);
        let request = SyscallRequest::try_from_raw(syscall_number, ctx, |args| {
            *decode_note.borrow_mut() = Some(unsupported::shape_of(args));
        });
        let request = match request {
            Ok(request) => {
                if let Some(shape) = decode_note.take() {
                    self.report_unsupported_syscall(syscall_number, shape, Ok(()));
                }
                request
            }
            Err(errno) => {
                let shape = decode_note.take().unwrap_or_else(|| {
                    let args = raw_syscall_args(ctx);
                    unsupported::shape_of(format_args!(
                        "decode failed, args=[{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}]",
                        args[0], args[1], args[2], args[3], args[4], args[5]
                    ))
                });
                self.report_unsupported_syscall(syscall_number, shape, Err(errno));
                return Err(errno);
            }
        };
        // A permanent, trace-gated record of every decoded syscall
        // (`LITEBOX_LOG=litebox_shim_linux=trace`). Off by default and a single level check when
        // it is off, but it is the only view of what a real guest is actually asking for: it is
        // what showed that busybox's blocking `wait` is a `sigsuspend` loop, and that the shim
        // was answering `sigsuspend` with an unimplemented-syscall error that release builds did
        // not even log (`log_unsupported_fmt` is `debug_assertions`-only).
        litebox_util_log::trace!(pid:? = self.pid, tid:? = self.tid, req:? = request; "syscall");

        match request {
            SyscallRequest::Exit { status } => {
                self.sys_exit(status);
                Ok(0)
            }
            SyscallRequest::ExitGroup { status } => {
                self.sys_exit_group(status);
                Ok(0)
            }
            SyscallRequest::Execve {
                pathname,
                argv,
                envp,
            } => self.sys_execve(pathname, argv, envp, ctx),
            SyscallRequest::Read { fd, buf, count } => {
                // Note some applications (e.g., `node`) seem to assume that getting fewer bytes than
                // requested indicates EOF.
                if count <= MAX_KERNEL_BUF_SIZE {
                    let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
                    self.sys_read(fd, &mut kernel_buf, None).and_then(|size| {
                        buf.copy_from_slice::<Platform>(0, &kernel_buf[..size])
                            .map(|()| size)
                            .ok_or(Errno::EFAULT)
                    })
                } else {
                    // If the read size is too large, we need to do some extra work to avoid OOMing.
                    // We read data in chunks and update the file offset ourselves only if the read succeeds.
                    self.sys_lseek(fd, 0, litebox::fs::SeekWhence::RelativeToCurrentOffset)
                    .inspect_err(|e| {
                        match *e {
                            Errno::EBADF => (), // safe errors to return
                            Errno::ESPIPE => {
                                unimplemented!("read on non-seekable fds with large buffers");
                            }
                            Errno::EINVAL => {
                                unreachable!("seekable file should not return EINVAL when getting current offset");
                            }
                            _ => {
                                unimplemented!("unexpected error from lseek: {}", e);
                            }
                        }
                    })
                    .and_then(|cur_loc| {
                        self.pread_with_user_buf(fd, buf, count, i64::try_from(cur_loc).unwrap())
                            .inspect(|read_total| {
                                // Update the file offset to reflect the read we just did.
                                self.sys_lseek(
                                    fd,
                                    (cur_loc + read_total).reinterpret_as_signed(),
                                    litebox::fs::SeekWhence::RelativeToBeginning,
                                )
                                // Given that previous lseek and pread succeeded, this lseek should also succeed.
                                .expect("lseek failed");
                            })
                    })
                }
            }
            SyscallRequest::Write { fd, buf, count } => {
                self.write_with_user_buf(fd, buf, count, None)
            }
            SyscallRequest::Close { fd } => syscall!(sys_close(fd)),
            SyscallRequest::Lseek { fd, offset, whence } => {
                use litebox::utils::TruncateExt as _;
                syscalls::file::try_into_whence(whence.trunc())
                    .map_err(|_| Errno::EINVAL)
                    .and_then(|seekwhence| self.sys_lseek(fd, offset, seekwhence))
            }
            SyscallRequest::Mkdirat {
                dirfd,
                pathname,
                mode,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_mkdirat(dirfd, path, mode))
                }),
            SyscallRequest::Chdir { pathname } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EINVAL), |path| syscall!(sys_chdir(path))),
            SyscallRequest::Chroot { path } => path
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| syscall!(sys_chroot(path))),
            SyscallRequest::Fchdir { fd } => syscall!(sys_fchdir(fd)),
            SyscallRequest::RtSigprocmask {
                how,
                set,
                oldset,
                sigsetsize,
            } => self.sys_rt_sigprocmask(how, set, oldset, sigsetsize),
            SyscallRequest::RtSigaction {
                signum,
                act,
                oldact,
                sigsetsize,
            } => self.sys_rt_sigaction(signum, act, oldact, sigsetsize),
            SyscallRequest::RtSigreturn => self.sys_rt_sigreturn(ctx),
            SyscallRequest::RtSigsuspend { mask, sigsetsize } => {
                self.sys_rt_sigsuspend(mask, sigsetsize)
            }
            SyscallRequest::Ioctl { fd, arg } => syscall!(sys_ioctl(fd, arg)),
            SyscallRequest::Pread64 {
                fd,
                buf,
                count,
                offset,
            } => self.pread_with_user_buf(fd, buf, count, offset),
            SyscallRequest::Pwrite64 {
                fd,
                buf,
                count,
                offset,
            } => {
                let pos = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
                self.write_with_user_buf(fd, buf, count, Some(pos))
            }
            SyscallRequest::Sendfile {
                out_fd,
                in_fd,
                offset,
                count,
            } => syscall!(sys_sendfile(out_fd, in_fd, offset, count)),
            SyscallRequest::Mmap {
                addr,
                length,
                prot,
                flags,
                fd,
                offset,
            } => {
                // GUARD (litebox-ordinary-syscall-cross-process-clobber): see
                // `Task::touches_another_process`'s doc comment. Only `MAP_FIXED` is destructive
                // to whatever is already there; an ordinary hinted/hint-free mapping always goes
                // through the placement allocator, which cannot land on another process's live
                // memory (`Vmem::reserve_external` already covers the one gap that existed there).
                if flags.contains(litebox_common_linux::MapFlags::MAP_FIXED)
                    && self.touches_another_process(addr, length)
                {
                    Err(Errno::ENOMEM)
                } else {
                    self.sys_mmap(addr, length, prot, flags, fd, offset)
                        .map(|ptr| ptr.as_usize())
                }
            }
            SyscallRequest::Mprotect { addr, length, prot } => {
                // GUARD (litebox-ordinary-syscall-cross-process-clobber): see
                // `Task::touches_another_process`'s doc comment. Mirrors real Linux's own
                // `mprotect` response to a range that is not entirely this process's own mapping.
                if self.touches_another_process(addr.as_usize(), length) {
                    Err(Errno::ENOMEM)
                } else {
                    syscall!(sys_mprotect(addr, length, prot))
                }
            }
            SyscallRequest::Mremap {
                old_addr,
                old_size,
                new_size,
                flags,
                new_addr,
            } => {
                // GUARD (litebox-ordinary-syscall-cross-process-clobber): see
                // `Task::touches_another_process`'s doc comment. This was the last
                // unguarded hole, and the one that actually reproduced live: a
                // node process walks a descending run of what it believes are its
                // own adjacent pages with `mremap(addr, 1 page -> 2 pages, 0)` and
                // takes the first success. On real Linux those neighbours are its
                // own (a process's successive mmaps are contiguous) and a foreign
                // address is unmappable, so the loop only ever sees success or
                // ENOMEM. Under one shared address space the neighbour is another
                // process's live page; the grow "succeeded", `record_mapped` handed
                // that page to the caller, and the caller's exit unmapped it under
                // its real owner -- a translation fault in musl's malloc for the
                // victim, several seconds later. ENOMEM rather than EFAULT on
                // purpose: it is the answer the same loop already gets for a page
                // of its own that cannot grow in place, so it keeps walking to
                // pages it really owns instead of aborting on an error real Linux
                // never produces for a valid pointer.
                let foreign_old = self.touches_another_process(old_addr.as_usize(), old_size);
                let foreign_new = flags.contains(litebox_common_linux::MRemapFlags::MREMAP_FIXED)
                    && self.touches_another_process(new_addr, new_size);
                if foreign_old || foreign_new {
                    Err(Errno::ENOMEM)
                } else {
                    self.sys_mremap(old_addr, old_size, new_size, flags, new_addr)
                        .map(|ptr| ptr.as_usize())
                }
            }
            SyscallRequest::Munmap { addr, length } => {
                // GUARD (litebox-ordinary-syscall-cross-process-clobber): see
                // `Task::touches_another_process`'s doc comment. Real Linux's own `munmap` is a
                // silent no-op over a range this process never had mapped; treating a range that
                // turns out to be a stranger's memory the same way is the closest honest match --
                // no case exists where correctly unmapping this process's own memory requires
                // touching another process's.
                if self.touches_another_process(addr.as_usize(), length) {
                    Ok(0)
                } else {
                    syscall!(sys_munmap(addr, length))
                }
            }
            SyscallRequest::Brk { addr } => self.sys_brk(addr),
            SyscallRequest::Readv { fd, iovec, iovcnt } => self.sys_readv(fd, iovec, iovcnt),
            SyscallRequest::Writev { fd, iovec, iovcnt } => self.sys_writev(fd, iovec, iovcnt),
            SyscallRequest::Preadv {
                fd,
                iovec,
                iovcnt,
                pos_l,
                pos_h,
            } => self.sys_preadv(fd, iovec, iovcnt, preadv_pwritev_offset(pos_l, pos_h)),
            SyscallRequest::Pwritev {
                fd,
                iovec,
                iovcnt,
                pos_l,
                pos_h,
            } => self.sys_pwritev(fd, iovec, iovcnt, preadv_pwritev_offset(pos_l, pos_h)),
            SyscallRequest::Faccessat {
                dirfd,
                pathname,
                mode,
                flags,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_faccessat(dirfd, path, mode, flags))
                }),
            SyscallRequest::Madvise {
                addr,
                length,
                behavior,
            } => syscall!(sys_madvise(addr, length, behavior)),
            SyscallRequest::Dup {
                oldfd,
                newfd,
                flags,
            } => syscall!(sys_dup(oldfd, newfd, flags)),
            SyscallRequest::Socket {
                domain,
                type_and_flags,
                protocol,
            } => syscall!(sys_socket(domain, type_and_flags, protocol)),
            SyscallRequest::Socketpair {
                domain,
                type_and_flags,
                protocol,
                sockvec,
            } => syscall!(sys_socketpair(domain, type_and_flags, protocol, sockvec)),
            SyscallRequest::Connect {
                sockfd,
                sockaddr,
                addrlen,
            } => syscall!(sys_connect(sockfd, sockaddr, addrlen)),
            SyscallRequest::Accept {
                sockfd,
                addr,
                addrlen,
                flags,
            } => syscall!(sys_accept(sockfd, addr, addrlen, flags)),
            SyscallRequest::Sendto {
                sockfd,
                buf,
                len,
                flags,
                addr,
                addrlen,
            } => self.sys_sendto(sockfd, buf, len, flags, addr, addrlen),
            SyscallRequest::Sendmsg { sockfd, msg, flags } => self.sys_sendmsg(sockfd, msg, flags),
            SyscallRequest::Sendmmsg {
                sockfd,
                msgvec,
                vlen,
                flags,
            } => self.sys_sendmmsg(sockfd, msgvec, vlen, flags),
            SyscallRequest::Recvfrom {
                sockfd,
                buf,
                len,
                flags,
                addr,
                addrlen,
            } => self.sys_recvfrom(sockfd, buf, len, flags, addr, addrlen),
            SyscallRequest::Recvmsg { sockfd, msg, flags } => self.sys_recvmsg(sockfd, msg, flags),
            SyscallRequest::Recvmmsg {
                sockfd,
                msgvec,
                vlen,
                flags,
                timeout,
            } => self.sys_recvmmsg(sockfd, msgvec, vlen, flags, timeout),
            SyscallRequest::Shutdown { sockfd, how } => syscall!(sys_shutdown(sockfd, how)),
            SyscallRequest::Bind {
                sockfd,
                sockaddr,
                addrlen,
            } => syscall!(sys_bind(sockfd, sockaddr, addrlen)),
            SyscallRequest::Listen { sockfd, backlog } => {
                syscall!(sys_listen(sockfd, backlog))
            }
            SyscallRequest::Setsockopt {
                sockfd,
                level,
                optname,
                optval,
                optlen,
            } => syscall!(sys_setsockopt(sockfd, level, optname, optval, optlen)),
            SyscallRequest::Getsockopt {
                sockfd,
                level,
                optname,
                optval,
                optlen,
            } => syscall!(sys_getsockopt(sockfd, level, optname, optval, optlen)),
            SyscallRequest::Getsockname {
                sockfd,
                addr,
                addrlen,
            } => syscall!(sys_getsockname(sockfd, addr, addrlen)),
            SyscallRequest::Getpeername {
                sockfd,
                addr,
                addrlen,
            } => syscall!(sys_getpeername(sockfd, addr, addrlen)),
            SyscallRequest::Uname { buf } => syscall!(sys_uname(buf)),
            SyscallRequest::Fcntl { fd, arg } => syscall!(sys_fcntl(fd, arg)),
            SyscallRequest::Flock { fd, operation } => syscall!(sys_flock(fd, operation)),
            SyscallRequest::Getcwd { buf, size: count } => {
                let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
                self.sys_getcwd(&mut kernel_buf).and_then(|size| {
                    buf.copy_from_slice::<Platform>(0, &kernel_buf[..size])
                        .map(|()| size)
                        .ok_or(Errno::EFAULT)
                })
            }
            SyscallRequest::EpollCtl {
                epfd,
                op,
                fd,
                event,
            } => syscall!(sys_epoll_ctl(epfd, op, fd, event)),
            SyscallRequest::EpollCreate { size, flags } => {
                // the `size` argument is ignored, but must be greater than zero;
                if size > 0 {
                    syscall!(sys_epoll_create(flags))
                } else {
                    Err(Errno::EINVAL)
                }
            }
            SyscallRequest::EpollPwait {
                epfd,
                events,
                maxevents,
                timeout,
                sigmask,
                sigsetsize,
            } => self.sys_epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize),
            // PR_SET_VMA (PartitionAlloc names every large anonymous mapping): decoded so it
            // is visible in the syscall trace, answered EINVAL exactly like a kernel built
            // without CONFIG_ANON_VMA_NAME -- callers already tolerate that.
            SyscallRequest::Prctl {
                args:
                    litebox_common_linux::PrctlArg::SetVma {
                        opcode, addr, len, ..
                    },
            } => {
                // One line per opcode, not per mapping: the per-call `addr`/`len` are
                // already in the trace-level `syscall req=` record.
                let _ = (addr, len);
                log_unsupported!("prctl(PR_SET_VMA, opcode = {opcode}) -> EINVAL");
                Err(Errno::EINVAL)
            }
            SyscallRequest::Prctl { args } => self.sys_prctl(args),
            // seccomp(2) and prctl(PR_SET_SECCOMP): no BPF filtering exists in the shim, so
            // `sys_seccomp` answers an honest ENOSYS (a kernel without CONFIG_SECCOMP), never a
            // fake success, and Chromium's layer-2 sandbox degrades instead of believing itself
            // enforced.
            SyscallRequest::Seccomp {
                operation,
                flags,
                args,
            } => syscall!(sys_seccomp(operation, flags, args)),
            // mseal(2): nothing seals mappings yet; ENOSYS is what a pre-6.10 kernel says and
            // PartitionAlloc's probe tolerates it. Decoded (rather than "unknown syscall 462")
            // so the trace shows what was asked.
            SyscallRequest::Mseal { addr, len, flags } => {
                // One line per flags value, not per call (Chromium probes this on every
                // large mapping); `addr`/`len` are in the trace-level `syscall req=` record.
                let _ = (addr, len);
                log_unsupported!("mseal(flags = {flags}) -> ENOSYS");
                Err(Errno::ENOSYS)
            }
            SyscallRequest::ArchPrctl { arg } => syscall!(sys_arch_prctl(arg)),
            SyscallRequest::Readlink {
                pathname,
                buf,
                bufsiz,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
                    self.sys_readlink(path, &mut kernel_buf).and_then(|size| {
                        buf.copy_from_slice::<Platform>(0, &kernel_buf[..size])
                            .map(|()| size)
                            .ok_or(Errno::EFAULT)
                    })
                }),
            SyscallRequest::Ppoll {
                fds,
                nfds,
                timeout,
                sigmask,
                sigsetsize,
            } => self.sys_ppoll(fds, nfds, timeout, sigmask, sigsetsize),
            SyscallRequest::Pselect {
                nfds,
                readfds,
                writefds,
                exceptfds,
                timeout,
                sigsetpack,
            } => self.sys_pselect(nfds, readfds, writefds, exceptfds, timeout, sigsetpack),
            SyscallRequest::Readlinkat {
                dirfd,
                pathname,
                buf,
                bufsiz,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
                    self.sys_readlinkat(dirfd, path, &mut kernel_buf)
                        .and_then(|size| {
                            buf.copy_from_slice::<Platform>(0, &kernel_buf[..size])
                                .map(|()| size)
                                .ok_or(Errno::EFAULT)
                        })
                }),
            SyscallRequest::Gettimeofday { tv, tz } => syscall!(sys_gettimeofday(tv, tz)),
            SyscallRequest::ClockGettime { clockid, tp } => {
                litebox_common_linux::ClockId::try_from(clockid)
                    .map_err(|_| {
                        log_unsupported!("clock_gettime(clockid = {clockid})");
                        Errno::EINVAL
                    })
                    .and_then(|clock_id| syscall!(sys_clock_gettime(clock_id, tp)))
            }
            SyscallRequest::ClockGetres { clockid, res } => {
                litebox_common_linux::ClockId::try_from(clockid)
                    .map_err(|_| {
                        log_unsupported!("clock_getres(clockid = {clockid})");
                        Errno::EINVAL
                    })
                    .and_then(|clock_id| syscall!(sys_clock_getres(clock_id, res)))
            }
            SyscallRequest::ClockNanosleep {
                clockid,
                flags,
                request,
                remain,
            } => litebox_common_linux::ClockId::try_from(clockid)
                .map_err(|_| {
                    log_unsupported!("clock_nanosleep(clockid = {clockid})");
                    Errno::EINVAL
                })
                .and_then(|clock_id| {
                    syscall!(sys_clock_nanosleep(clock_id, flags, request, remain))
                }),
            SyscallRequest::Time { tloc } => self
                .sys_time(tloc)
                .and_then(|second| usize::try_from(second).or(Err(Errno::EOVERFLOW))),
            SyscallRequest::Openat {
                dirfd,
                pathname,
                flags,
                mode,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_openat(dirfd, path, flags, mode))
                }),
            SyscallRequest::Ftruncate { fd, length } => syscall!(sys_ftruncate(fd, length)),
            SyscallRequest::Fallocate {
                fd,
                mode,
                offset,
                len,
            } => syscall!(sys_fallocate(fd, mode, offset, len)),
            SyscallRequest::Fadvise64 {
                fd,
                offset,
                len,
                advice,
            } => syscall!(sys_fadvise64(fd, offset, len, advice)),
            SyscallRequest::Preadv2 {
                fd,
                iovec,
                iovcnt,
                pos_l,
                pos_h,
                flags,
            } => self.sys_preadv2(
                fd,
                iovec,
                iovcnt,
                preadv_pwritev_offset(pos_l, pos_h),
                flags,
            ),
            SyscallRequest::Pwritev2 {
                fd,
                iovec,
                iovcnt,
                pos_l,
                pos_h,
                flags,
            } => self.sys_pwritev2(
                fd,
                iovec,
                iovcnt,
                preadv_pwritev_offset(pos_l, pos_h),
                flags,
            ),
            SyscallRequest::MemfdCreate { name, flags } => name
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |name| {
                    syscall!(sys_memfd_create(&name, flags))
                }),
            SyscallRequest::Mknodat {
                dirfd,
                pathname,
                mode_and_type,
                dev,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_mknodat(dirfd, path, mode_and_type, dev))
                }),
            SyscallRequest::Unlinkat {
                dirfd,
                pathname,
                flags,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_unlinkat(dirfd, path, flags))
                }),
            SyscallRequest::Symlinkat {
                target,
                newdirfd,
                linkpath,
            } => match (
                target.to_cstring::<Platform>(),
                linkpath.to_cstring::<Platform>(),
            ) {
                (Some(target), Some(linkpath)) => {
                    syscall!(sys_symlinkat(target, newdirfd, linkpath))
                }
                _ => Err(Errno::EFAULT),
            },
            SyscallRequest::Linkat {
                olddirfd,
                oldpath,
                newdirfd,
                newpath,
                flags,
            } => match (
                oldpath.to_cstring::<Platform>(),
                newpath.to_cstring::<Platform>(),
            ) {
                (Some(oldpath), Some(newpath)) => {
                    syscall!(sys_linkat(olddirfd, oldpath, newdirfd, newpath, flags))
                }
                _ => Err(Errno::EFAULT),
            },
            SyscallRequest::Renameat2 {
                olddirfd,
                oldpath,
                newdirfd,
                newpath,
                flags,
            } => match (
                oldpath.to_cstring::<Platform>(),
                newpath.to_cstring::<Platform>(),
            ) {
                (Some(oldpath), Some(newpath)) => {
                    syscall!(sys_renameat2(olddirfd, oldpath, newdirfd, newpath, flags))
                }
                _ => Err(Errno::EFAULT),
            },
            SyscallRequest::Fchmodat {
                dirfd,
                pathname,
                mode,
                flags,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_fchmodat(dirfd, path, mode, flags))
                }),
            SyscallRequest::Fchownat {
                dirfd,
                pathname,
                owner,
                group,
                flags,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_fchownat(dirfd, path, owner, group, flags))
                }),
            SyscallRequest::Fchmod { fd, mode } => syscall!(sys_fchmod(fd, mode)),
            SyscallRequest::Fchown { fd, owner, group } => {
                syscall!(sys_fchown(fd, owner, group))
            }
            SyscallRequest::Fsync { fd } => syscall!(sys_fsync(fd)),
            SyscallRequest::Utimensat {
                dirfd,
                pathname,
                times,
                flags,
            } => {
                let times = times
                    .map(|ptr| -> Result<_, Errno> {
                        let a = ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                        let b = ptr.read_at_offset::<Platform>(1).ok_or(Errno::EFAULT)?;
                        Ok([a, b])
                    })
                    .transpose()?;
                match pathname {
                    Some(pathname) => pathname
                        .to_cstring::<Platform>()
                        .map_or(Err(Errno::EFAULT), |path| {
                            syscall!(sys_utimensat(dirfd, path, times, flags))
                        }),
                    // `futimens(fd, times)`, emulated by glibc as `utimensat(fd, NULL, times, 0)`.
                    None => syscall!(sys_futimens(dirfd, times)),
                }
            }
            SyscallRequest::Stat { pathname, buf } => {
                pathname
                    .to_cstring::<Platform>()
                    .map_or(Err(Errno::EFAULT), |path| {
                        self.sys_stat(path).and_then(|stat| {
                            buf.write_at_offset::<Platform>(0, stat)
                                .ok_or(Errno::EFAULT)
                                .map(|()| 0)
                        })
                    })
            }
            SyscallRequest::Lstat { pathname, buf } => {
                pathname
                    .to_cstring::<Platform>()
                    .map_or(Err(Errno::EFAULT), |path| {
                        self.sys_lstat(path).and_then(|stat| {
                            buf.write_at_offset::<Platform>(0, stat)
                                .ok_or(Errno::EFAULT)
                                .map(|()| 0)
                        })
                    })
            }
            SyscallRequest::Fstat { fd, buf } => self.sys_fstat(fd).and_then(|stat| {
                buf.write_at_offset::<Platform>(0, stat)
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }),
            // Reached through `newfstatat` on x86-64 and `fstatat` on aarch64,
            // where it is the only path-based stat syscall the kernel offers.
            SyscallRequest::Newfstatat {
                dirfd,
                pathname,
                buf,
                flags,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    self.sys_newfstatat(dirfd, path, flags).and_then(|stat| {
                        buf.write_at_offset::<Platform>(0, stat)
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                }),
            SyscallRequest::Statx {
                dirfd,
                pathname,
                flags,
                mask,
                statxbuf,
            } => {
                let (path, flags) = match pathname {
                    // Linux 6.11+ treats a NULL statx path as a request to stat dirfd.
                    None => (
                        Ok(c"".into()),
                        flags | litebox_common_linux::AtFlags::AT_EMPTY_PATH,
                    ),
                    Some(p) => (p.to_cstring::<Platform>().ok_or(Errno::EFAULT), flags),
                };
                path.and_then(|path| {
                    self.sys_statx(dirfd, path, flags, mask).and_then(|sx| {
                        statxbuf
                            .write_at_offset::<Platform>(0, sx)
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                })
            }
            SyscallRequest::Statfs { pathname, buf } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| syscall!(sys_statfs(path, buf))),
            SyscallRequest::Fstatfs { fd, buf } => syscall!(sys_fstatfs(fd, buf)),
            SyscallRequest::Eventfd2 { initval, flags } => {
                syscall!(sys_eventfd2(initval, flags))
            }
            SyscallRequest::InotifyInit1 { flags } => syscall!(sys_inotify_init1(flags)),
            SyscallRequest::InotifyAddWatch { fd, pathname, mask } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_inotify_add_watch(fd, path, mask))
                }),
            SyscallRequest::InotifyRmWatch { fd, wd } => syscall!(sys_inotify_rm_watch(fd, wd)),
            SyscallRequest::Pipe2 { pipefd, flags } => {
                self.sys_pipe2(flags).and_then(|(read_fd, write_fd)| {
                    pipefd
                        .write_at_offset::<Platform>(0, read_fd)
                        .ok_or(Errno::EFAULT)?;
                    pipefd
                        .write_at_offset::<Platform>(1, write_fd)
                        .ok_or(Errno::EFAULT)?;
                    Ok(0)
                })
            }
            SyscallRequest::Clone { args } => self.sys_clone(ctx, &args),
            SyscallRequest::Clone3 { args } => self.sys_clone3(ctx, args),
            SyscallRequest::Unshare { flags } => self.sys_unshare(flags),
            SyscallRequest::SetThreadArea { user_desc } => {
                #[cfg(target_arch = "x86_64")]
                {
                    let _ = user_desc;
                    Err(Errno::ENOSYS) // x86_64 does not support set_thread_area
                }
                #[cfg(target_arch = "aarch64")]
                {
                    // aarch64 has no `set_thread_area` either; the thread
                    // pointer is `TPIDR_EL0`, set through `clone`'s `tls`
                    // argument.
                    let _ = user_desc;
                    Err(Errno::ENOSYS)
                }
            }
            SyscallRequest::SetTidAddress { tidptr } => {
                Ok(self.sys_set_tid_address(tidptr).reinterpret_as_unsigned() as usize)
            }
            SyscallRequest::Gettid => Ok(self.sys_gettid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getrlimit { resource, rlim } => {
                syscall!(sys_getrlimit(resource, rlim))
            }
            SyscallRequest::Setrlimit { resource, rlim } => {
                syscall!(sys_setrlimit(resource, rlim))
            }
            SyscallRequest::Prlimit {
                pid,
                resource,
                new_limit,
                old_limit,
            } => syscall!(sys_prlimit(pid, resource, new_limit, old_limit)),
            SyscallRequest::SetRobustList { head } => {
                self.sys_set_robust_list(head);
                Ok(0)
            }
            SyscallRequest::GetRobustList { pid, head, len } => self
                .sys_get_robust_list(pid, head)
                .and_then(|()| {
                    len.write_at_offset::<Platform>(
                        0,
                        size_of::<litebox_common_linux::RobustListHead>(),
                    )
                    .ok_or(Errno::EFAULT)
                })
                .map(|()| 0),
            SyscallRequest::GetRandom { buf, count, flags } => {
                self.sys_getrandom(buf, count, flags)
            }
            SyscallRequest::Getpid => Ok(self.sys_getpid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getppid => Ok(self.sys_getppid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getpgid { pid } => self
                .sys_getpgid(pid)
                .map(|pgid| pgid.reinterpret_as_unsigned() as usize),
            SyscallRequest::Setpgid { pid, pgid } => syscall!(sys_setpgid(pid, pgid)),
            SyscallRequest::Setsid => self
                .sys_setsid()
                .map(|sid| sid.reinterpret_as_unsigned() as usize),
            SyscallRequest::Wait4 {
                pid,
                wstatus,
                options,
                rusage,
            } => self
                .sys_wait4(pid, wstatus, options, rusage)
                .map(|pid| pid.reinterpret_as_unsigned() as usize),
            SyscallRequest::Getuid => Ok(self.sys_getuid() as usize),
            SyscallRequest::Getgid => Ok(self.sys_getgid() as usize),
            SyscallRequest::Geteuid => Ok(self.sys_geteuid() as usize),
            SyscallRequest::Getegid => Ok(self.sys_getegid() as usize),
            SyscallRequest::Getgroups { size, list } => syscall!(sys_getgroups(size, list)),
            SyscallRequest::Setgroups { size, list } => syscall!(sys_setgroups(size, list)),
            SyscallRequest::Setuid { uid } => syscall!(sys_setuid(uid)),
            SyscallRequest::Setgid { gid } => syscall!(sys_setgid(gid)),
            SyscallRequest::Setresuid { ruid, euid, suid } => {
                syscall!(sys_setresuid(ruid, euid, suid))
            }
            SyscallRequest::Setresgid { rgid, egid, sgid } => {
                syscall!(sys_setresgid(rgid, egid, sgid))
            }
            SyscallRequest::Getresuid { ruid, euid, suid } => {
                syscall!(sys_getresuid(ruid, euid, suid))
            }
            SyscallRequest::Getresgid { rgid, egid, sgid } => {
                syscall!(sys_getresgid(rgid, egid, sgid))
            }
            SyscallRequest::Sysinfo { buf } => {
                let sysinfo = self.sys_sysinfo();
                buf.write_at_offset::<Platform>(0, sysinfo)
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }
            SyscallRequest::Getrusage { who, usage } => {
                let rusage = self.sys_getrusage(who);
                usage
                    .write_at_offset::<Platform>(0, rusage)
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }
            SyscallRequest::CapGet { header, data } => syscall!(sys_capget(header, data)),
            SyscallRequest::CapSet { header, data } => syscall!(sys_capset(header, data)),
            SyscallRequest::GetDirent64 { fd, dirp, count } => {
                self.sys_getdirent64(fd, dirp, count)
            }
            SyscallRequest::SchedGetAffinity { pid, len, mask } => {
                const BITS_PER_BYTE: usize = 8;
                let cpuset = self.sys_sched_getaffinity(pid);
                if len * BITS_PER_BYTE < cpuset.len()
                    || len & (core::mem::size_of::<usize>() - 1) != 0
                {
                    Err(Errno::EINVAL)
                } else {
                    let raw_bytes = cpuset.as_bytes();
                    mask.copy_from_slice::<Platform>(0, raw_bytes)
                        .map(|()| raw_bytes.len())
                        .ok_or(Errno::EFAULT)
                }
            }
            SyscallRequest::SchedYield => {
                // Do nothing until we have more scheduler integration with the
                // platform.
                Ok(0)
            }
            SyscallRequest::SchedGetParam { pid, param } => {
                syscall!(sys_sched_getparam(pid, param))
            }
            SyscallRequest::SchedSetParam { pid, param } => {
                syscall!(sys_sched_setparam(pid, param))
            }
            SyscallRequest::SchedGetScheduler { pid } => syscall!(sys_sched_getscheduler(pid)),
            SyscallRequest::SchedSetScheduler { pid, policy, param } => {
                syscall!(sys_sched_setscheduler(pid, policy, param))
            }
            SyscallRequest::Futex { args } => self.sys_futex(args),
            SyscallRequest::Umask { mask } => {
                let old_mask = self.sys_umask(mask);
                Ok(old_mask.bits() as usize)
            }
            SyscallRequest::Kill { pid, sig } => self.sys_kill(pid, sig),
            SyscallRequest::Tkill { tid, sig } => self.sys_tkill(tid, sig),
            SyscallRequest::Tgkill { tgid, tid, sig } => self.sys_tgkill(tgid, tid, sig),
            SyscallRequest::RtSigtimedwait {
                set,
                info,
                timeout,
                sigsetsize,
            } => self.sys_rt_sigtimedwait(set, info, timeout, sigsetsize),
            SyscallRequest::RtSigqueueinfo { pid, sig, info } => {
                self.sys_rt_sigqueueinfo(pid, sig, info)
            }
            SyscallRequest::RtTgsigqueueinfo {
                tgid,
                tid,
                sig,
                info,
            } => self.sys_rt_tgsigqueueinfo(tgid, tid, sig, info),
            SyscallRequest::Getpriority { which, who } => self.sys_getpriority(which, who),
            SyscallRequest::Setpriority {
                which,
                who,
                niceval,
            } => syscall!(sys_setpriority(which, who, niceval)),
            SyscallRequest::Membarrier { cmd, flags, cpu_id } => {
                self.sys_membarrier(cmd, flags, cpu_id)
            }
            SyscallRequest::Sigaltstack { ss, old_ss } => self.sys_sigaltstack(ss, old_ss, ctx),
            SyscallRequest::Alarm { seconds } => syscall!(sys_alarm(seconds)),
            SyscallRequest::Pause => syscall!(sys_pause()),
            SyscallRequest::GetITimer { which, curr_value } => {
                syscall!(sys_getitimer(which, curr_value))
            }
            SyscallRequest::SetITimer {
                which,
                new_value,
                old_value,
            } => syscall!(sys_setitimer(which, new_value, old_value)),
            #[cfg(target_arch = "aarch64")]
            SyscallRequest::Ptrace {
                request,
                pid,
                addr,
                data,
            } => self.sys_ptrace(request, pid, addr, data),
            #[cfg(target_arch = "x86_64")]
            SyscallRequest::Ptrace { .. } => Err(Errno::ENOSYS),
            _ => {
                log_unsupported!("{request:?}");
                Err(Errno::ENOSYS)
            }
        }
    }
}

/// The six syscall arguments as the guest passed them, for naming an undecodable
/// request by its shape when the decoder itself said nothing about it (the argument
/// values are what tell an unknown `madvise` advice or `prctl` option apart).
#[cfg(target_arch = "aarch64")]
fn raw_syscall_args(ctx: &litebox_common_linux::PtRegs) -> [usize; 6] {
    [
        ctx.regs[0],
        ctx.regs[1],
        ctx.regs[2],
        ctx.regs[3],
        ctx.regs[4],
        ctx.regs[5],
    ]
}
#[cfg(target_arch = "x86_64")]
fn raw_syscall_args(ctx: &litebox_common_linux::PtRegs) -> [usize; 6] {
    [ctx.rdi, ctx.rsi, ctx.rdx, ctx.r10, ctx.r8, ctx.r9]
}

/// A guest ELF image placed by the shim's own loader -- the main executable
/// and its `PT_INTERP` -- recorded at load time for fault symbolization.
///
/// Kept apart from [`syscalls::mm::GuestImage`] deliberately: that list is
/// filled from the `mmap` path and named through the mapping fd's recorded
/// path, but the loader opens its images with `open_executable_as` and inserts
/// the descriptor raw, so no path ever exists for it there -- and the main
/// executable, where an official Chromium's `NOTREACHED()` traps land, was
/// precisely the image the fault line printed as "(no image)". Rows carry the
/// loading pid so that a later `execve` by the same process replaces its own
/// rows (exec replaces the whole address space); a forked child shares its
/// parent's placement and resolves through the parent's row by address.
pub(crate) struct LoadedImage {
    pid: i32,
    /// Lowest guest address covered by the image's `PT_LOAD` segments.
    lo: usize,
    /// One past the highest guest address covered by the image.
    hi: usize,
    /// The load bias: guest address minus ELF vaddr. `addr - base` is the
    /// image-relative offset `llvm-symbolizer` resolves against the file.
    base: usize,
    /// The path the loader opened the image with.
    path: alloc::string::String,
}

/// Rows kept in [`GlobalState::loaded_images`] before the oldest are dropped.
/// Two rows per exec, so this covers thousands of short-lived processes while
/// bounding a desktop session that forks forever.
const LOADED_IMAGES_CAP: usize = 4096;

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Drop the loader-placed rows of this pid: an image load replaces the
    /// whole address space, so whatever was recorded for it is gone.
    pub(crate) fn forget_loaded_images(&self) {
        self.global
            .loaded_images
            .lock()
            .retain(|img| img.pid != self.pid);
    }

    /// Record an image the loader has just placed at bias `base`, spanning
    /// guest addresses `lo..hi`.
    pub(crate) fn record_loaded_image(&self, path: &str, base: usize, lo: usize, hi: usize) {
        let mut images = self.global.loaded_images.lock();
        if images.len() >= LOADED_IMAGES_CAP {
            let excess = images.len() + 1 - LOADED_IMAGES_CAP;
            images.drain(..excess);
        }
        images.push(LoadedImage {
            pid: self.pid,
            lo,
            hi,
            base,
            path: alloc::string::String::from(path),
        });
    }

    /// Name the guest ELF image containing `addr` as `(path, image-relative
    /// offset)`. This task's own loader-placed images win (they are exact for
    /// the live process), then any loader-placed image by address (a forked
    /// child), then the `mmap`-recorded shared libraries, latest first.
    pub(crate) fn symbolize_guest_address(
        &self,
        addr: usize,
    ) -> Option<(alloc::string::String, usize)> {
        {
            let images = self.global.loaded_images.lock();
            let contains = |img: &&LoadedImage| (img.lo..img.hi).contains(&addr);
            let hit = images
                .iter()
                .rev()
                .filter(|img| img.pid == self.pid)
                .find(contains)
                .or_else(|| images.iter().rev().find(contains));
            if let Some(img) = hit {
                return Some((img.path.clone(), addr - img.base));
            }
        }
        self.find_guest_image(addr)
    }

    /// Log one undecodable syscall, once per distinct (number, shape).
    ///
    /// `warn` when the decoder flagged the request as unsupported or unknown,
    /// `debug` when it merely refused the arguments (`result` is the errno the
    /// guest gets); repeats of the same row are shown only at `trace`.
    fn report_unsupported_syscall(
        &self,
        nr: usize,
        shape: unsupported::Shape,
        result: Result<(), Errno>,
    ) {
        let name = unsupported::syscall_name(nr);
        // Only the fallback shape built in `do_syscall` starts this way; every
        // other shape came from the decoder naming what it does not support.
        let flagged = !shape.starts_with("decode failed");
        let result = match result {
            Ok(()) => "decoded",
            Err(errno) => errno.as_str(),
        };
        match unsupported::record(Some(nr), &shape) {
            unsupported::Sighting::First if flagged => {
                litebox_util_log::warn!(
                    nr:? = nr, name:% = name, what:% = shape, result:% = result, pid:? = self.pid;
                    "unsupported syscall (first sighting; repeats logged at trace level)"
                );
            }
            unsupported::Sighting::First => {
                litebox_util_log::debug!(
                    nr:? = nr, name:% = name, what:% = shape, result:% = result, pid:? = self.pid;
                    "undecodable syscall arguments (first sighting; repeats logged at trace level)"
                );
            }
            unsupported::Sighting::Repeat(count) => {
                litebox_util_log::trace!(
                    nr:? = nr, name:% = name, what:% = shape, result:% = result, count:? = count,
                    pid:? = self.pid;
                    "unsupported syscall (repeat)"
                );
            }
        }
    }
}

/// Global shim state, shared across all tasks.
struct GlobalState<Platform: ShimPlatform, FS: ShimFS> {
    /// The platform instance used throughout the shim.
    platform: &'static Platform,
    /// The LiteBox instance used throughout the shim.
    litebox: litebox::LiteBox<Platform>,
    /// The page manager for managing virtual memory.
    pm: litebox::mm::PageManager<Platform, { PAGE_SIZE }>,
    /// The anonymous pipe implementation.
    pipes: Pipes<Platform>,
    /// The network subsystem.
    net: litebox::sync::Mutex<Platform, Network<Platform>>,
    /// The time when the shim was started.
    boot_time: <Platform as TimeProvider>::Instant,
    /// Next thread ID to assign.
    // TODO: better management of thread IDs
    next_thread_id: core::sync::atomic::AtomicI32,
    /// UNIX domain socket address table
    unix_addr_table: litebox::sync::RwLock<Platform, syscalls::unix::UnixAddrTable<Platform, FS>>,
    /// Unix98 pseudoterminal namespace shared by every guest task.
    pty_registry: Arc<syscalls::file::PtyRegistry<Platform, FS>>,
    /// Guest ELF images recorded at map time, for fault symbolization. Grows
    /// monotonically (never pruned on unmap) and survives the mapping fd's
    /// close, unlike [`Process::elf_patch_cache`](syscalls::process::Process::elf_patch_cache).
    /// See `Task::find_guest_image`.
    guest_images: litebox::sync::Mutex<Platform, alloc::vec::Vec<syscalls::mm::GuestImage>>,
    /// Guest ELF images placed by the shim's own loader, for fault
    /// symbolization; see [`LoadedImage`] for why these are not in
    /// [`Self::guest_images`].
    loaded_images: litebox::sync::Mutex<Platform, alloc::vec::Vec<LoadedImage>>,
    /// Stable shared-page identities keyed by filesystem device/inode, so aliases opened through
    /// different file descriptions still converge on one backing object.
    shared_file_backings: litebox::sync::Mutex<
        Platform,
        alloc::collections::BTreeMap<(usize, usize), litebox::mm::vmem::SharedFutexBacking>,
    >,
    /// Handle to the `/proc` backend mounted by [`LinuxShimBuilder::default_fs`], if any --
    /// `None` when the shim was built with a filesystem that doesn't mount one.
    /// `Task::set_task_comm` publishes the guest task's identity here as it becomes known.
    proc_handle: Option<litebox::fs::proc::Proc<Platform>>,
    /// Handle to the `/dev/fb0` framebuffer mounted by [`LinuxShimBuilder::default_fs`], if any
    /// -- `None` when the shim was built with a filesystem that doesn't mount one.
    /// `syscalls::file::Task::sys_ioctl` services `FBIO*` requests through this handle directly,
    /// rather than by routing through the generic `FS` backend trait: the ioctl structs
    /// (`FbVarScreeninfo`/`FbFixScreeninfo`) live on the concrete [`litebox::fs::devices::Framebuffer`]
    /// type, not on the `FileSystem`/`Backend` traits, so there's no generic path from an `FS`-typed
    /// fd to them.
    framebuffer: Option<litebox::fs::devices::Framebuffer<Platform>>,
    /// Handle to the `/dev/input` event-device registry mounted by
    /// [`LinuxShimBuilder::default_fs`], if any -- `None` when the shim was built with a
    /// filesystem that doesn't mount one. `sys_read`/`sys_ioctl`/poll intercept evdev fds
    /// through this, and the runner injects input events into it.
    input_registry: Option<litebox::fs::devices::InputRegistry<Platform>>,
    /// Real termios state for the process's controlling terminal (shared by stdin/stdout/stderr,
    /// like a real Linux `tty_struct`), as read by `TCGETS` and written by `TCSETS`.
    termios: litebox::sync::Mutex<Platform, litebox_common_linux::Termios>,
    /// Foreground process group of the host-backed stdin/stdout/stderr terminal. This belongs to
    /// the terminal, not to any guest process; pseudoterminals keep the same state in `PtyState`.
    stdio_foreground_pgid: core::sync::atomic::AtomicI32,
    /// Parent/child relationships and exit statuses for every guest process, so that `fork`ed
    /// children can be reaped by `wait4`.
    processes: syscalls::process::ProcessTable<Platform>,
    /// Serializes the swap-operate-restore sequence that gives each guest process its own program
    /// break on top of the single break [`litebox::mm::PageManager`] tracks. See
    /// `Task::sys_brk`.
    brk_lock: litebox::sync::Mutex<Platform, ()>,
}

struct Task<Platform: ShimPlatform, FS: ShimFS> {
    global: Arc<GlobalState<Platform, FS>>,
    wait_state: wait::WaitState<Platform>,
    thread: syscalls::process::ThreadState<Platform>,
    /// Process ID
    pid: i32,
    /// Parent Process ID
    ppid: i32,
    /// Thread ID
    tid: i32,
    /// Task credentials. These are set per task but are Arc'd to save space
    /// since most tasks never change their credentials. `setuid`/`setgid`
    /// replace the `Arc` rather than mutate through it, so a thread that
    /// still shares the old one (e.g. a sibling from `clone`) is unaffected
    /// -- matching the raw syscall, which (unlike glibc's thread-broadcasting
    /// wrapper) only ever updates the calling thread's credentials.
    credentials: RefCell<Arc<syscalls::process::Credentials>>,
    /// Command name (usually the executable name, excluding the path)
    comm: Cell<[u8; litebox_common_linux::TASK_COMM_LEN]>,
    /// Filesystem state. `RefCell` to support `unshare` in the future.
    fs: RefCell<Arc<syscalls::file::FsState<Platform>>>,
    /// File descriptors. `RefCell` to support `unshare` in the future.
    files: RefCell<Arc<syscalls::file::FilesState<Platform, FS>>>,
    /// Signal state
    signals: syscalls::signal::SignalState<Platform>,
    /// The guest stack pointer as of the most recent entry into the shim.
    ///
    /// Needed because a snapshot of this task's memory can be taken at any blocking point, not
    /// just at a syscall that was handed a `PtRegs`; see
    /// `syscalls::process::Task::save_address_space` for what it is used for.
    guest_sp: Cell<usize>,
}

impl<Platform: ShimPlatform, FS: ShimFS> Drop for Task<Platform, FS> {
    fn drop(&mut self) {
        self.prepare_for_exit();
    }
}

#[cfg(test)]
mod test_utils {
    extern crate std;
    use super::*;

    impl<Platform: ShimPlatform, FS: ShimFS> GlobalState<Platform, FS> {
        /// Make a new task with default values for testing.
        pub(crate) fn new_test_task(
            self: Arc<Self>,
            fs: alloc::sync::Arc<FS>,
        ) -> Task<Platform, FS> {
            let pid = self
                .next_thread_id
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let files = Arc::new(syscalls::file::FilesState::new(fs));
            files.initialize_stdio_in_shared_descriptors_table(&self);
            Task {
                wait_state: wait::WaitState::new(self.platform),
                thread: syscalls::process::ThreadState::new_process(pid, 0),
                pid,
                ppid: 0,
                tid: pid,
                credentials: RefCell::new(Arc::new(syscalls::process::Credentials::new(
                    0, 0, 0, 0,
                ))),
                comm: Cell::new(*b"test\0\0\0\0\0\0\0\0\0\0\0\0"),
                fs: Arc::new(syscalls::file::FsState::new()).into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::new_process(),
                guest_sp: Cell::new(0),
                global: self,
            }
        }
    }

    impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
        /// Returns a clone of this task with a new TID for testing.
        pub(crate) fn clone_for_test(&self) -> Option<Self> {
            let tid = self
                .global
                .next_thread_id
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let task = Task {
                wait_state: wait::WaitState::new(self.global.platform),
                global: self.global.clone(),
                thread: self.thread.new_thread(tid)?,
                pid: self.pid,
                ppid: self.ppid,
                tid,
                credentials: RefCell::new(self.credentials.borrow().clone()),
                comm: self.comm.clone(),
                fs: self.fs.clone(),
                files: self.files.clone(),
                signals: self.signals.clone_for_new_task(),
                guest_sp: Cell::new(0),
            };
            Some(task)
        }

        /// Spawns a thread that runs with a clone of this task and a new TID.
        ///
        /// # Panics
        /// Panics if the test process is already terminating.
        pub(crate) fn spawn_clone_for_test<R>(
            &self,
            f: impl 'static + Send + FnOnce(Task<Platform, FS>) -> R,
        ) -> std::thread::JoinHandle<R>
        where
            R: 'static + Send,
        {
            let task = self.clone_for_test().unwrap();
            std::thread::spawn(move || f(task))
        }
    }
}
