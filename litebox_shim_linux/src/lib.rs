//! A shim that provides a Linux-compatible ABI via LiteBox.
//!
//! This shim is parametric in the choice of [LiteBox platform](../litebox/platform/index.html),
//! chosen by the [platform multiplex](../litebox_platform_multiplex/index.html).

#![no_std]
#![expect(
    clippy::unused_self,
    reason = "by convention, syscalls and related methods take &self even if unused"
)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use alloc::sync::Arc;
use core::cell::{Cell, RefCell};
use litebox::{
    LiteBox,
    fd::{ErrRawIntFd, TypedFd},
    mm::{PageManager, linux::PAGE_SIZE},
    net::Network,
    pipes::Pipes,
    platform::{RawConstPointer as _, RawMutPointer as _, TimeProvider},
    shim::ContinueOperation,
    sync::futex::FutexManager,
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _},
};
use litebox_common_linux::{SyscallRequest, errno::Errno};
use litebox_platform_multiplex::Platform;

/// On debug builds, logs that the user attempted to use an unsupported feature.
// DEVNOTE: this is before the `mod` declarations so that it can be used within them.
macro_rules! log_unsupported {
    ($($arg:tt)*) => {
        $crate::log_unsupported_fmt(core::format_args!($($arg)*));
    };
}

pub(crate) mod channel;
pub mod loader;
pub(crate) mod stdio;
pub mod syscalls;
mod wait;

pub type DefaultFS = LinuxFS;

pub(crate) type LinuxFS = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::devices::FileSystem<Platform>,
        litebox::fs::tar_ro::FileSystem<Platform>,
    >,
>;

pub(crate) type FileFd = litebox::fd::TypedFd<LinuxFS>;

/// On debug builds, logs that the user attempted to use an unsupported feature.
fn log_unsupported_fmt(args: core::fmt::Arguments<'_>) {
    use litebox::platform::DebugLogProvider as _;

    if cfg!(debug_assertions) {
        let msg = alloc::format!("WARNING: unsupported: {args}\n");
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }
}

pub struct LinuxShimEntrypoints {
    task: Task,
    // The task should not be moved once it's bound to a platform thread so that
    // we preserve the ability to use TLS in the future.
    _not_send: core::marker::PhantomData<*const ()>,
}

impl litebox::shim::EnterShim for LinuxShimEntrypoints {
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
        self.enter_shim(false, ctx, |task, _ctx| task.handle_exception_request(info))
    }

    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, |_, _| {})
    }
}

impl LinuxShimEntrypoints {
    fn enter_shim(
        &self,
        is_init: bool,
        ctx: &mut litebox_common_linux::PtRegs,
        f: impl FnOnce(&Task, &mut litebox_common_linux::PtRegs),
    ) -> ContinueOperation {
        if !is_init {
            self.task.enter_from_guest();
        }
        f(&self.task, ctx);
        if self.task.prepare_to_run_guest(ctx) {
            ContinueOperation::ResumeGuest
        } else {
            ContinueOperation::ExitThread
        }
    }
}

/// The shim entry point structure.
pub struct LinuxShimBuilder {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
    fs: Option<LinuxFS>,
    load_filter: Option<LoadFilter>,
}

impl Default for LinuxShimBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxShimBuilder {
    /// Returns a new shim builder.
    pub fn new() -> Self {
        let platform = litebox_platform_multiplex::platform();
        Self {
            platform,
            litebox: LiteBox::new(platform),
            fs: None,
            load_filter: None,
        }
    }

    /// Returns the litebox object for the shim.
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    /// Set the global file system
    ///
    /// NOTE: This function signature might change as better parametricity is added to file systems.
    /// Related: <https://github.com/MSRSSP/litebox/issues/24>
    pub fn set_fs(&mut self, fs: LinuxFS) {
        self.fs = Some(fs);
    }

    /// Create a default layered file system with the given in-memory and tar read-only layers.
    pub fn default_fs(
        &self,
        in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
        tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
    ) -> DefaultFS {
        default_fs(&self.litebox, in_mem_fs, tar_ro_fs)
    }

    /// Set the load filter, which can augment envp or auxv when starting a new program.
    pub fn set_load_filter(&mut self, callback: LoadFilter) {
        self.load_filter = Some(callback);
    }

    /// Build the shim.
    ///
    /// # Panics
    /// Panics if the file system has not been set with [`set_fs`](Self::set_fs)
    /// before calling this method.
    pub fn build(self) -> LinuxShim {
        let mut net = Network::new(&self.litebox);
        net.set_platform_interaction(litebox::net::PlatformInteraction::Manual);
        let global = Arc::new(GlobalState {
            platform: self.platform,
            pm: PageManager::new(&self.litebox),
            fs: self
                .fs
                .expect("File system must be set before calling build"),
            futex_manager: FutexManager::new(),
            pipes: Pipes::new(&self.litebox),
            net: litebox::sync::Mutex::new(net),
            boot_time: self.platform.now(),
            load_filter: self.load_filter,
            next_thread_id: 2.into(), // start from 2, as 1 is used by the main thread
            litebox: self.litebox,
            unix_addr_table: litebox::sync::RwLock::new(syscalls::unix::UnixAddrTable::new()),
        });
        LinuxShim(global)
    }
}

#[derive(Clone)]
pub struct LinuxShim(Arc<GlobalState>);

impl LinuxShim {
    /// Loads the program at `path` as the shim's initial task, returning the
    /// initial register state.
    pub fn load_program(
        &self,
        task: litebox_common_linux::TaskParams,
        path: &str,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
    ) -> Result<LoadedProgram, loader::elf::ElfLoaderError> {
        let litebox_common_linux::TaskParams {
            pid,
            ppid,
            uid,
            euid,
            gid,
            egid,
        } = task;

        let files = Arc::new(syscalls::file::FilesState::new());
        files.initialize_stdio_in_shared_descriptors_table(&self.0);

        let entrypoints = crate::LinuxShimEntrypoints {
            _not_send: core::marker::PhantomData,
            task: Task {
                global: self.0.clone(),
                thread: syscalls::process::ThreadState::new_process(pid),
                wait_state: wait::WaitState::new(self.0.platform),
                pid,
                ppid,
                tid: pid,
                credentials: syscalls::process::Credentials {
                    uid,
                    euid,
                    gid,
                    egid,
                }
                .into(),
                comm: [0; litebox_common_linux::TASK_COMM_LEN].into(), // set at load time
                fs: Arc::new(syscalls::file::FsState::new()).into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::new_process(),
            },
        };
        entrypoints.task.load_program(
            loader::elf::ElfLoader::new(&entrypoints.task, path)?,
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
}

pub struct LoadedProgram {
    pub entrypoints: LinuxShimEntrypoints,
    pub process: LinuxShimProcess,
}

/// A handle to a process loaded via [`LinuxShim::load_program`].
///
/// This can be used to wait for the process to exit.
pub struct LinuxShimProcess(Arc<syscalls::process::Process>);

impl LinuxShimProcess {
    /// Wait for the process to exit, returning its exit code.
    pub fn wait(&self) -> i32 {
        match self.0.wait_for_exit() {
            syscalls::process::ExitStatus::Exit(v) => v.into(),
            // TODO: return the enum instead of just a code?
            syscalls::process::ExitStatus::Signal(signal) => signal.as_i32() + 256,
        }
    }
}

/// Create a default layered file system with the given in-memory and tar read-only layers.
fn default_fs(
    litebox: &LiteBox<Platform>,
    in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
    tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
) -> LinuxFS {
    let dev_stdio = litebox::fs::devices::FileSystem::new(litebox);
    litebox::fs::layered::FileSystem::new(
        litebox,
        in_mem_fs,
        litebox::fs::layered::FileSystem::new(
            litebox,
            dev_stdio,
            tar_ro_fs,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    )
}

// Special override so that `GETFL` can return stdio-specific flags
pub(crate) struct StdioStatusFlags(litebox::fs::OFlags);

impl syscalls::file::FilesState {
    fn initialize_stdio_in_shared_descriptors_table(&self, global: &GlobalState) {
        use litebox::fs::{FileSystem as _, Mode, OFlags};
        let stdin = global
            .fs
            .open("/dev/stdin", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let stdout = global
            .fs
            .open("/dev/stdout", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let stderr = global
            .fs
            .open("/dev/stderr", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let mut dt = global.litebox.descriptor_table_mut();
        let mut rds = self.raw_descriptor_store.write();
        for (raw_fd, fd) in [(0, stdin), (1, stdout), (2, stderr)] {
            let status_flags = OFlags::APPEND | OFlags::RDWR;
            debug_assert_eq!(OFlags::STATUS_FLAGS_MASK & status_flags, status_flags);
            let old = dt.set_entry_metadata(&fd, StdioStatusFlags(status_flags));
            assert!(old.is_none());
            let success = rds.fd_into_specific_raw_integer(fd, raw_fd);
            assert!(success);
        }
    }
}

// Convenience type aliases
type ConstPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

struct Descriptors {
    descriptors: Vec<Option<Descriptor>>,
}

impl Descriptors {
    fn new() -> Self {
        Self {
            descriptors: vec![
                Some(Descriptor::LiteBoxRawFd(0)),
                Some(Descriptor::LiteBoxRawFd(1)),
                Some(Descriptor::LiteBoxRawFd(2)),
            ],
        }
    }
    fn insert(&mut self, task: &Task, descriptor: Descriptor) -> Result<u32, Descriptor> {
        let idx = self
            .descriptors
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.descriptors.push(None);
                self.descriptors.len() - 1
            });
        if idx
            >= task
                .process()
                .limits
                .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE)
        {
            return Err(descriptor);
        }
        let old = self.descriptors[idx].replace(descriptor);
        assert!(old.is_none());
        Ok(u32::try_from(idx).unwrap())
    }
    fn insert_at(&mut self, descriptor: Descriptor, idx: usize) -> Option<Descriptor> {
        if idx >= self.descriptors.len() {
            self.descriptors.resize_with(idx + 1, Default::default);
        }
        self.descriptors
            .get_mut(idx)
            .and_then(|v| v.replace(descriptor))
    }
    fn remove(&mut self, fd: u32) -> Option<Descriptor> {
        let fd = fd as usize;
        self.descriptors.get_mut(fd)?.take()
    }
    fn get_fd(&self, fd: u32) -> Option<&Descriptor> {
        self.descriptors.get(fd as usize)?.as_ref()
    }

    fn len(&self) -> usize {
        self.descriptors.len()
    }
}

impl Task {
    fn close_on_exec(&self) {
        let files = self.files.borrow();
        files
            .file_descriptors
            .write()
            .descriptors
            .iter_mut()
            .for_each(|slot| {
                if let Some(desc) = slot.take()
                    && let Ok(flags) = desc.get_file_descriptor_flags(&self.global, &files)
                {
                    if flags.contains(litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC) {
                        let _ = self.do_close(desc);
                    } else {
                        *slot = Some(desc);
                    }
                }
            });
    }
}

enum Descriptor {
    LiteBoxRawFd(usize),
    Eventfd {
        file: alloc::sync::Arc<syscalls::eventfd::EventFile<Platform>>,
        close_on_exec: core::sync::atomic::AtomicBool,
    },
    Epoll {
        file: alloc::sync::Arc<syscalls::epoll::EpollFile>,
        close_on_exec: core::sync::atomic::AtomicBool,
    },
    Unix {
        file: alloc::sync::Arc<syscalls::unix::UnixSocket>,
        close_on_exec: core::sync::atomic::AtomicBool,
    },
}

/// A strongly-typed FD.
///
/// This enum only ever stores `Arc<TypedFd<..>>`s, and should not store any additional data
/// alongside them (i.e., it is a trivial tagged union across the subsystems being used).
enum StrongFd {
    FileSystem(Arc<TypedFd<LinuxFS>>),
    Network(Arc<TypedFd<Network<Platform>>>),
    Pipes(Arc<TypedFd<Pipes<Platform>>>),
}
impl StrongFd {
    fn from_raw(files: &syscalls::file::FilesState, fd: usize) -> Result<Self, Errno> {
        match files
            .raw_descriptor_store
            .read()
            .typed_fd_at_raw_3::<StrongFd, LinuxFS, Network<Platform>, Pipes<Platform>>(fd)
        {
            Ok(r) => Ok(r),
            Err(ErrRawIntFd::InvalidSubsystem) => {
                // We currently only have net and fs FDs at the moment, when we add more, we need to
                // expand out `StrongFd` too.
                unreachable!()
            }
            Err(ErrRawIntFd::NotFound) => Err(Errno::EBADF),
        }
    }
}
impl From<Arc<TypedFd<LinuxFS>>> for StrongFd {
    fn from(v: Arc<TypedFd<LinuxFS>>) -> Self {
        StrongFd::FileSystem(v)
    }
}
impl From<Arc<TypedFd<Network<Platform>>>> for StrongFd {
    fn from(v: Arc<TypedFd<Network<Platform>>>) -> Self {
        StrongFd::Network(v)
    }
}
impl From<Arc<TypedFd<Pipes<Platform>>>> for StrongFd {
    fn from(v: Arc<TypedFd<Pipes<Platform>>>) -> Self {
        StrongFd::Pipes(v)
    }
}

impl syscalls::file::FilesState {
    pub(crate) fn run_on_raw_fd<R>(
        &self,
        fd: usize,
        fs: impl FnOnce(&TypedFd<LinuxFS>) -> R,
        net: impl FnOnce(&TypedFd<Network<Platform>>) -> R,
        pipes: impl FnOnce(&TypedFd<Pipes<Platform>>) -> R,
    ) -> Result<R, Errno> {
        match StrongFd::from_raw(self, fd)? {
            StrongFd::FileSystem(fd) => Ok(fs(&fd)),
            StrongFd::Network(fd) => Ok(net(&fd)),
            StrongFd::Pipes(fd) => Ok(pipes(&fd)),
        }
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

impl Task {
    /// A wrapper function around `sys_pread64` that copies data in chunks to avoid OOMing.
    fn pread_with_user_buf(
        &self,
        fd: i32,
        buf: MutPtr<u8>,
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
                    buf.copy_from_slice(read_total, &kernel_buf[..size])
                        .ok_or(Errno::EFAULT)?;
                    read_total += size;
                }
                Err(e) => return Err(e),
            }
        }
        assert!(read_total <= count);
        Ok(read_total)
    }

    /// Handle Linux syscalls and dispatch them to LiteBox implementations.
    ///
    /// # Panics
    ///
    /// Unsupported syscalls or arguments would trigger a panic for development purposes.
    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let return_value = match self.do_syscall(ctx) {
            Ok(v) => v,
            Err(err) => (err.as_neg() as isize).reinterpret_as_unsigned(),
        };
        #[cfg(target_arch = "x86")]
        {
            ctx.eax = return_value;
        }
        #[cfg(target_arch = "x86_64")]
        {
            ctx.rax = return_value;
        }
    }

    fn do_syscall(&self, ctx: &mut litebox_common_linux::PtRegs) -> Result<usize, Errno> {
        // Helper macro to unify the return value from `sys_*`.
        macro_rules! syscall {
            ($func:ident($($args:expr),*)) => {
                self.$func($($args),*).to_syscall_result()
            };
        }

        #[cfg(target_arch = "x86")]
        let syscall_number = ctx.orig_eax;
        #[cfg(target_arch = "x86_64")]
        let syscall_number = ctx.orig_rax;
        let request =
            SyscallRequest::<Platform>::try_from_raw(syscall_number, ctx, log_unsupported_fmt)?;

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
                        buf.copy_from_slice(0, &kernel_buf[..size])
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
            SyscallRequest::Write { fd, buf, count } => match unsafe { buf.to_cow_slice(count) } {
                Some(buf) => self.sys_write(fd, &buf, None),
                None => Err(Errno::EFAULT),
            },
            SyscallRequest::Close { fd } => syscall!(sys_close(fd)),
            SyscallRequest::Lseek { fd, offset, whence } => {
                use litebox::utils::TruncateExt as _;
                syscalls::file::try_into_whence(whence.truncate())
                    .map_err(|_| Errno::EINVAL)
                    .and_then(|seekwhence| self.sys_lseek(fd, offset, seekwhence))
            }
            SyscallRequest::Mkdir { pathname, mode } => pathname
                .to_cstring()
                .map_or(Err(Errno::EINVAL), |path| syscall!(sys_mkdir(path, mode))),
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
            #[cfg(target_arch = "x86")]
            SyscallRequest::Sigreturn => self.sys_sigreturn(ctx),
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
            } => match unsafe { buf.to_cow_slice(count) } {
                Some(buf) => self.sys_pwrite64(fd, &buf, offset),
                None => Err(Errno::EFAULT),
            },
            SyscallRequest::Mmap {
                addr,
                length,
                prot,
                flags,
                fd,
                offset,
            } => self
                .sys_mmap(addr, length, prot, flags, fd, offset)
                .map(|ptr| ptr.as_usize()),
            SyscallRequest::Mprotect { addr, length, prot } => {
                syscall!(sys_mprotect(addr, length, prot))
            }
            SyscallRequest::Mremap {
                old_addr,
                old_size,
                new_size,
                flags,
                new_addr,
            } => self
                .sys_mremap(old_addr, old_size, new_size, flags, new_addr)
                .map(|ptr| ptr.as_usize()),
            SyscallRequest::Munmap { addr, length } => syscall!(sys_munmap(addr, length)),
            SyscallRequest::Brk { addr } => self.sys_brk(addr),
            SyscallRequest::Readv { fd, iovec, iovcnt } => self.sys_readv(fd, iovec, iovcnt),
            SyscallRequest::Writev { fd, iovec, iovcnt } => self.sys_writev(fd, iovec, iovcnt),
            SyscallRequest::Access { pathname, mode } => pathname
                .to_cstring()
                .map_or(Err(Errno::EFAULT), |path| syscall!(sys_access(path, mode))),
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
            #[cfg(target_arch = "x86")]
            SyscallRequest::Socketcall { call, args } => self.sys_socketcall(call, args),
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
            SyscallRequest::Recvfrom {
                sockfd,
                buf,
                len,
                flags,
                addr,
                addrlen,
            } => self.sys_recvfrom(sockfd, buf, len, flags, addr, addrlen),
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
            SyscallRequest::Getcwd { buf, size: count } => {
                let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
                self.sys_getcwd(&mut kernel_buf).and_then(|size| {
                    buf.copy_from_slice(0, &kernel_buf[..size])
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
            SyscallRequest::Prctl { args } => self.sys_prctl(args),
            SyscallRequest::ArchPrctl { arg } => syscall!(sys_arch_prctl(arg)),
            SyscallRequest::Readlink {
                pathname,
                buf,
                bufsiz,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
                self.sys_readlink(path, &mut kernel_buf).and_then(|size| {
                    buf.copy_from_slice(0, &kernel_buf[..size])
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
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
                self.sys_readlinkat(dirfd, path, &mut kernel_buf)
                    .and_then(|size| {
                        buf.copy_from_slice(0, &kernel_buf[..size])
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
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscall!(sys_openat(dirfd, path, flags, mode))
            }),
            SyscallRequest::Ftruncate { fd, length } => syscall!(sys_ftruncate(fd, length)),
            SyscallRequest::Unlinkat {
                dirfd,
                pathname,
                flags,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscall!(sys_unlinkat(dirfd, path, flags))
            }),
            SyscallRequest::Stat { pathname, buf } => {
                pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                    self.sys_stat(path).and_then(|stat| {
                        unsafe { buf.write_at_offset(0, stat) }
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                })
            }
            SyscallRequest::Lstat { pathname, buf } => {
                pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                    self.sys_lstat(path).and_then(|stat| {
                        unsafe { buf.write_at_offset(0, stat) }
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                })
            }
            SyscallRequest::Fstat { fd, buf } => self.sys_fstat(fd).and_then(|stat| {
                unsafe { buf.write_at_offset(0, stat) }
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }),
            #[cfg(target_arch = "x86_64")]
            SyscallRequest::Newfstatat {
                dirfd,
                pathname,
                buf,
                flags,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                self.sys_newfstatat(dirfd, path, flags).and_then(|stat| {
                    unsafe { buf.write_at_offset(0, stat) }
                        .ok_or(Errno::EFAULT)
                        .map(|()| 0)
                })
            }),
            #[cfg(target_arch = "x86")]
            SyscallRequest::Fstatat64 {
                dirfd,
                pathname,
                buf,
                flags,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                self.sys_newfstatat(dirfd, path, flags).and_then(|stat| {
                    unsafe { buf.write_at_offset(0, stat.into()) }
                        .ok_or(Errno::EFAULT)
                        .map(|()| 0)
                })
            }),
            SyscallRequest::Eventfd2 { initval, flags } => {
                syscall!(sys_eventfd2(initval, flags))
            }
            SyscallRequest::Pipe2 { pipefd, flags } => {
                self.sys_pipe2(flags).and_then(|(read_fd, write_fd)| {
                    unsafe { pipefd.write_at_offset(0, read_fd).ok_or(Errno::EFAULT) }?;
                    unsafe { pipefd.write_at_offset(1, write_fd).ok_or(Errno::EFAULT) }?;
                    Ok(0)
                })
            }
            SyscallRequest::Clone { args } => self.sys_clone(ctx, &args),
            SyscallRequest::Clone3 { args } => self.sys_clone3(ctx, args),
            SyscallRequest::SetThreadArea { user_desc } => {
                #[cfg(target_arch = "x86_64")]
                {
                    let _ = user_desc;
                    Err(Errno::ENOSYS) // x86_64 does not support set_thread_area
                }
                #[cfg(target_arch = "x86")]
                {
                    unsafe { user_desc.read_at_offset(0) }
                        .ok_or(Errno::EFAULT)
                        .and_then(|desc| {
                            let mut desc = desc.into_owned();
                            let idx = desc.entry_number;
                            self.set_thread_area(&mut desc)?;
                            if idx == u32::MAX {
                                // index -1 means the kernel should try to find and
                                // allocate an empty descriptor.
                                // return the allocated entry number
                                unsafe { user_desc.write_at_offset(0, desc) }
                                    .ok_or(Errno::EFAULT)?;
                            }
                            Ok(0)
                        })
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
                    unsafe {
                        len.write_at_offset(
                            0,
                            size_of::<
                                litebox_common_linux::RobustListHead<
                                    litebox_platform_multiplex::Platform,
                                >,
                            >(),
                        )
                    }
                    .ok_or(Errno::EFAULT)
                })
                .map(|()| 0),
            SyscallRequest::GetRandom { buf, count, flags } => {
                self.sys_getrandom(buf, count, flags)
            }
            SyscallRequest::Getpid => Ok(self.sys_getpid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getppid => Ok(self.sys_getppid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getuid => Ok(self.sys_getuid() as usize),
            SyscallRequest::Getgid => Ok(self.sys_getgid() as usize),
            SyscallRequest::Geteuid => Ok(self.sys_geteuid() as usize),
            SyscallRequest::Getegid => Ok(self.sys_getegid() as usize),
            SyscallRequest::Sysinfo { buf } => {
                let sysinfo = self.sys_sysinfo();
                unsafe { buf.write_at_offset(0, sysinfo) }
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }
            SyscallRequest::CapGet { header, data } => syscall!(sys_capget(header, data)),
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
                    mask.copy_from_slice(0, raw_bytes)
                        .map(|()| raw_bytes.len())
                        .ok_or(Errno::EFAULT)
                }
            }
            SyscallRequest::SchedYield => {
                // Do nothing until we have more scheduler integration with the
                // platform.
                Ok(0)
            }
            SyscallRequest::Futex { args } => self.sys_futex(args),
            SyscallRequest::Umask { mask } => {
                let old_mask = self.sys_umask(mask);
                Ok(old_mask.bits() as usize)
            }
            SyscallRequest::Kill { pid, sig } => self.sys_kill(pid, sig),
            SyscallRequest::Tkill { tid, sig } => self.sys_tkill(tid, sig),
            SyscallRequest::Tgkill { tgid, tid, sig } => self.sys_tgkill(tgid, tid, sig),
            SyscallRequest::Sigaltstack { ss, old_ss } => self.sys_sigaltstack(ss, old_ss, ctx),
            _ => {
                log_unsupported!("{request:?}");
                Err(Errno::ENOSYS)
            }
        }
    }
}

/// Global shim state, shared across all tasks.
struct GlobalState {
    /// The platform instance used throughout the shim.
    platform: &'static Platform,
    /// The LiteBox instance used throughout the shim.
    litebox: litebox::LiteBox<Platform>,
    /// The page manager for managing virtual memory.
    pm: litebox::mm::PageManager<Platform, { PAGE_SIZE }>,
    /// The filesystem implementation.
    fs: LinuxFS,
    /// The futex manager for handling futex operations.
    futex_manager: FutexManager<Platform>,
    /// The anonymous pipe implementation.
    pipes: Pipes<Platform>,
    /// The network subsystem.
    net: litebox::sync::Mutex<Platform, Network<Platform>>,
    /// The time when the shim was started.
    boot_time: <Platform as TimeProvider>::Instant,
    /// Optional load filter function to modify environment variables during program loading.
    load_filter: Option<LoadFilter>,
    /// Next thread ID to assign.
    // TODO: better management of thread IDs
    next_thread_id: core::sync::atomic::AtomicI32,
    /// UNIX domain socket address table
    unix_addr_table: litebox::sync::RwLock<Platform, syscalls::unix::UnixAddrTable>,
}

struct Task {
    global: Arc<GlobalState>,
    wait_state: wait::WaitState,
    thread: syscalls::process::ThreadState,
    /// Process ID
    pid: i32,
    /// Parent Process ID
    ppid: i32,
    /// Thread ID
    tid: i32,
    /// Task credentials. These are set per task but are Arc'd to save space
    /// since most tasks never change their credentials.
    credentials: Arc<syscalls::process::Credentials>,
    /// Command name (usually the executable name, excluding the path)
    comm: Cell<[u8; litebox_common_linux::TASK_COMM_LEN]>,
    /// Filesystem state. `RefCell` to support `unshare` in the future.
    fs: RefCell<Arc<syscalls::file::FsState>>,
    /// File descriptors. `RefCell` to support `unshare` in the future.
    files: RefCell<Arc<syscalls::file::FilesState>>,
    /// Signal state
    signals: syscalls::signal::SignalState,
}

impl Drop for Task {
    fn drop(&mut self) {
        self.prepare_for_exit();
    }
}

pub type LoadFilter = fn(envp: &mut alloc::vec::Vec<alloc::ffi::CString>);

#[cfg(test)]
mod test_utils {
    extern crate std;
    use super::*;

    impl GlobalState {
        /// Make a new task with default values for testing.
        pub(crate) fn new_test_task(self: Arc<Self>) -> Task {
            let pid = self
                .next_thread_id
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let files = Arc::new(syscalls::file::FilesState::new());
            files.initialize_stdio_in_shared_descriptors_table(&self);
            Task {
                wait_state: wait::WaitState::new(self.platform),
                thread: syscalls::process::ThreadState::new_process(pid),
                pid,
                ppid: 0,
                tid: pid,
                credentials: Arc::new(syscalls::process::Credentials {
                    uid: 0,
                    euid: 0,
                    gid: 0,
                    egid: 0,
                }),
                comm: Cell::new(*b"test\0\0\0\0\0\0\0\0\0\0\0\0"),
                fs: Arc::new(syscalls::file::FsState::new()).into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::new_process(),
                global: self,
            }
        }
    }

    impl Task {
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
                credentials: self.credentials.clone(),
                comm: self.comm.clone(),
                fs: self.fs.clone(),
                files: self.files.clone(),
                signals: self.signals.clone_for_new_task(),
            };
            Some(task)
        }

        /// Spawns a thread that runs with a clone of this task and a new TID.
        ///
        /// # Panics
        /// Panics if the test process is already terminating.
        pub(crate) fn spawn_clone_for_test<R>(
            &self,
            f: impl 'static + Send + FnOnce(Task) -> R,
        ) -> std::thread::JoinHandle<R>
        where
            R: 'static + Send,
        {
            let task = self.clone_for_test().unwrap();
            std::thread::spawn(move || f(task))
        }
    }
}
