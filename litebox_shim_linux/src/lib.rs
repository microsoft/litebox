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

// TODO(jayb) Replace out all uses of once_cell and such with our own implementation that uses
// platform-specific things within it.
use once_cell::race::OnceBox;

use alloc::sync::Arc;
use core::cell::{Cell, RefCell};
use litebox::{
    LiteBox,
    fd::{ErrRawIntFd, TypedFd},
    mm::{PageManager, linux::PAGE_SIZE},
    net::Network,
    pipes::Pipes,
    platform::{
        PunchthroughProvider as _, PunchthroughToken as _, RawConstPointer as _, RawMutPointer as _,
    },
    sync::futex::FutexManager,
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _},
};
use litebox_common_linux::{ContinueOperation, SyscallRequest, errno::Errno};
use litebox_platform_multiplex::Platform;

pub mod loader;
pub(crate) mod stdio;
pub mod syscalls;

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

type UserConstPointer<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
type UserMutPointer<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

static BOOT_TIME: once_cell::race::OnceBox<<Platform as litebox::platform::TimeProvider>::Instant> =
    once_cell::race::OnceBox::new();

pub struct LinuxShimEntrypoints;

impl litebox::shim::EnterShim for LinuxShimEntrypoints {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ContinueOperation = ContinueOperation;

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> Self::ContinueOperation {
        let r = with_current_task(|task| task.handle_syscall_request(ctx));
        match r {
            ContinueOperation::ResumeGuest => {}
            ContinueOperation::ExitThread(_) | ContinueOperation::ExitProcess(_) => {
                SHIM_TLS.deinit();
            }
            // TEMP: this must be done outside of with_current_task to avoid leaking a borrow.
            // Remove this once rt_sigreturn is handled natively by the shim.
            ContinueOperation::RtSigreturn(stack) => {
                let punchthrough = litebox_common_linux::PunchthroughSyscall::RtSigreturn { stack };
                let token = litebox_platform_multiplex::platform()
                    .get_punchthrough_token_for(punchthrough)
                    .expect("Failed to get punchthrough token for RT_SIGRETURN");
                token
                    .execute()
                    .map(|_| ())
                    .map_err(|e| match e {
                        litebox::platform::PunchthroughError::Failure(errno) => errno,
                        _ => unimplemented!("Unsupported punchthrough error {:?}", e),
                    })
                    .expect("rt_sigreturn failed");
                unreachable!("rt_sigreturn should not return");
            }
        }
        r
    }

    fn exception(
        &self,
        _ctx: &mut Self::ExecutionContext,
        info: &litebox::shim::ExceptionInfo,
    ) -> Self::ContinueOperation {
        panic!("Unhandled exception: {info:#x?}");
    }
}

/// Get the `Instant` representing the boot time of the platform.
///
/// # Panics
///
/// Panics if [`litebox()`] has not been invoked before this
pub(crate) fn boot_time() -> &'static <Platform as litebox::platform::TimeProvider>::Instant {
    BOOT_TIME
        .get()
        .expect("litebox() should have already been called before this point")
}

/// The shim entry point structure.
pub struct LinuxShim {
    litebox: &'static LiteBox<Platform>,
    fs: Option<LinuxFS>,
}

impl Default for LinuxShim {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxShim {
    /// Returns a new shim.
    pub fn new() -> Self {
        Self {
            litebox: crate::litebox(),
            fs: None,
        }
    }

    /// Returns the litebox object for the shim.
    pub fn litebox(&self) -> &LiteBox<Platform> {
        self.litebox
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
        default_fs(in_mem_fs, tar_ro_fs)
    }

    /// Set the load filter, which can augment envp or auxv when starting a new program.
    ///
    /// # Panics
    /// Panics if the load filter is already set.
    pub fn set_load_filter(&mut self, callback: LoadFilter) {
        set_load_filter(callback);
    }

    /// Returns the entrypoints to call to interact with the shim from guest
    /// threads.
    pub fn entrypoints(&self) -> &'static LinuxShimEntrypoints {
        &LinuxShimEntrypoints
    }

    fn into_global(self) -> Arc<GlobalState> {
        Arc::new(GlobalState {
            fs: self
                .fs
                .expect("File system must be set before creating global state"),
        })
    }

    /// Loads the program at `path` as the shim's initial task, returning the
    /// initial register state.
    ///
    /// # Panics
    /// Panics if the file system has not been set with [`set_fs`](Self::set_fs)
    /// before calling this method.
    pub fn load_program(
        self,
        task: litebox_common_linux::TaskParams,
        path: &str,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
    ) -> Result<litebox_common_linux::PtRegs, loader::ElfLoaderError> {
        let litebox = self.litebox;
        let global = self.into_global();

        let litebox_common_linux::TaskParams {
            pid,
            ppid,
            tid,
            uid,
            euid,
            gid,
            egid,
        } = task;

        let files = Arc::new(syscalls::file::FilesState::new(litebox));
        files.initialize_stdio_in_shared_descriptors_table(&global.fs);

        // TODO: ensure this gets torn down even if the thread never runs sys_exit.
        // Consider a scoped execution model, e.g.
        // ```
        // litebox_shim_linux::run_process(task, |litebox| {
        //     ...
        // })
        // ```
        SHIM_TLS.init(LinuxShimTls {
            current_task: Task {
                global,
                pid,
                ppid,
                tid,
                clear_child_tid: None.into(),
                robust_list: None.into(),
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
                process: syscalls::process::Process::new().into(),
            },
        });

        let r = with_current_task(|task| task.load_program(path, argv, envp));
        if r.is_err() {
            SHIM_TLS.deinit();
        }
        r
    }
}

/// Get the global litebox object
pub(crate) fn litebox<'a>() -> &'a LiteBox<Platform> {
    static LITEBOX: OnceBox<LiteBox<Platform>> = OnceBox::new();
    LITEBOX.get_or_init(|| {
        use litebox::platform::TimeProvider as _;
        let platform = litebox_platform_multiplex::platform();
        let _ = BOOT_TIME.get_or_init(|| alloc::boxed::Box::new(platform.now()));
        alloc::boxed::Box::new(LiteBox::new(platform))
    })
}

/// Create a default layered file system with the given in-memory and tar read-only layers.
fn default_fs(
    in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
    tar_ro_fs: litebox::fs::tar_ro::FileSystem<Platform>,
) -> LinuxFS {
    let litebox = crate::litebox();
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

/// Get the global page manager
pub fn litebox_page_manager<'a>() -> &'a PageManager<Platform, PAGE_SIZE> {
    static VMEM: OnceBox<PageManager<Platform, PAGE_SIZE>> = OnceBox::new();
    VMEM.get_or_init(|| alloc::boxed::Box::new(PageManager::new(litebox())))
}

pub(crate) fn litebox_net<'a>() -> &'a litebox::sync::Mutex<Platform, Network<Platform>> {
    static NET: OnceBox<litebox::sync::Mutex<Platform, Network<Platform>>> = OnceBox::new();
    NET.get_or_init(|| {
        let mut net = Network::new(litebox());
        net.set_platform_interaction(litebox::net::PlatformInteraction::Manual);
        alloc::boxed::Box::new(litebox().sync().new_mutex(net))
    })
}

/// Perform queued network interactions with the outside world.
///
/// This function should be invoked in a loop, based on the returned advice.
pub fn perform_network_interaction() -> litebox::net::PlatformInteractionReinvocationAdvice {
    litebox_net().lock().perform_platform_interaction()
}

pub(crate) fn litebox_pipes<'a>() -> &'a litebox::sync::RwLock<Platform, Pipes<Platform>> {
    static PIPES: OnceBox<litebox::sync::RwLock<Platform, Pipes<Platform>>> = OnceBox::new();
    PIPES.get_or_init(|| {
        let pipes = Pipes::new(litebox());
        alloc::boxed::Box::new(litebox().sync().new_rwlock(pipes))
    })
}

pub(crate) fn litebox_futex_manager<'a>() -> &'a FutexManager<Platform> {
    static FUTEX_MANAGER: OnceBox<FutexManager<Platform>> = OnceBox::new();
    FUTEX_MANAGER.get_or_init(|| {
        let futex_manager = FutexManager::new(litebox());
        alloc::boxed::Box::new(futex_manager)
    })
}

// Special override so that `GETFL` can return stdio-specific flags
pub(crate) struct StdioStatusFlags(litebox::fs::OFlags);

impl syscalls::file::FilesState {
    fn initialize_stdio_in_shared_descriptors_table(&self, fs: &LinuxFS) {
        use litebox::fs::{FileSystem as _, Mode, OFlags};
        let stdin = fs
            .open("/dev/stdin", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let stdout = fs
            .open("/dev/stdout", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let stderr = fs
            .open("/dev/stderr", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let mut dt = litebox().descriptor_table_mut();
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
                .process
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
                    && let Ok(flags) = desc.get_file_descriptor_flags(&files)
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

/// Open a file
///
/// # Safety
///
/// `pathname` must point to a valid nul-terminated C string
#[expect(
    clippy::missing_panics_doc,
    reason = "the panics here are ideally never hit, and should not be user-facing"
)]
pub unsafe extern "C" fn open(pathname: ConstPtr<i8>, flags: u32, mode: u32) -> i32 {
    let Some(path) = pathname.to_cstring() else {
        return Errno::EFAULT.as_neg();
    };
    with_current_task(|task| {
        match task.sys_open(
            path,
            litebox::fs::OFlags::from_bits(flags).unwrap(),
            litebox::fs::Mode::from_bits(mode).unwrap(),
        ) {
            Ok(fd) => fd.try_into().unwrap(),
            Err(err) => err.as_neg(),
        }
    })
}

/// Closes the file
pub extern "C" fn close(fd: i32) -> i32 {
    with_current_task(|task| task.sys_close(fd).map_or_else(Errno::as_neg, |()| 0))
}

// This places size limits on maximum read/write sizes that might occur; it exists primarily to
// prevent OOM due to the user asking for a _massive_ read or such at once. Keeping this too small
// has the downside of requiring too many syscalls, while having it be too large allows for massive
// allocations to be triggered by the userland program. For now, this is set to a
// hopefully-reasonable middle ground.
const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

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
    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::PtRegs) -> ContinueOperation {
        fn set_return(ctx: &mut litebox_common_linux::PtRegs, value: usize) {
            #[cfg(target_arch = "x86")]
            {
                ctx.eax = value;
            }
            #[cfg(target_arch = "x86_64")]
            {
                ctx.rax = value;
            }
        }

        #[cfg(target_arch = "x86")]
        let syscall_number = ctx.orig_eax;
        #[cfg(target_arch = "x86_64")]
        let syscall_number = ctx.orig_rax;
        let request = match SyscallRequest::<Platform>::try_from_raw(syscall_number, ctx) {
            Ok(request) => request,
            Err(err) => {
                set_return(ctx, (err.as_neg() as isize).reinterpret_as_unsigned());
                return ContinueOperation::ResumeGuest;
            }
        };

        let res: Result<usize, Errno> = match request {
            SyscallRequest::Exit { status } => {
                self.sys_exit(status);
                return ContinueOperation::ExitThread(status);
            }
            SyscallRequest::ExitGroup { status } => {
                self.sys_exit_group(status);
                return ContinueOperation::ExitProcess(status);
            }
            SyscallRequest::Execve {
                pathname,
                argv,
                envp,
            } => match self.sys_execve(pathname, argv, envp, ctx) {
                Ok(()) => return ContinueOperation::ResumeGuest,
                Err(err) => Err(err),
            },
            SyscallRequest::Ret(errno) => Err(errno),
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
            SyscallRequest::Close { fd } => self.sys_close(fd).map(|()| 0),
            SyscallRequest::Lseek { fd, offset, whence } => {
                use litebox::utils::TruncateExt as _;
                syscalls::file::try_into_whence(whence.truncate())
                    .map_err(|_| Errno::EINVAL)
                    .and_then(|seekwhence| self.sys_lseek(fd, offset, seekwhence))
            }
            SyscallRequest::Mkdir { pathname, mode } => {
                pathname.to_cstring().map_or(Err(Errno::EINVAL), |path| {
                    self.sys_mkdir(path, mode).map(|()| 0)
                })
            }
            SyscallRequest::RtSigprocmask {
                how,
                set,
                oldset,
                sigsetsize,
            } => {
                if sigsetsize == size_of::<litebox_common_linux::SigSet>() {
                    self.sys_rt_sigprocmask(how, set, oldset).map(|()| 0)
                } else {
                    Err(Errno::EINVAL)
                }
            }
            SyscallRequest::RtSigaction {
                signum,
                act,
                oldact,
                sigsetsize,
            } => {
                if sigsetsize == size_of::<litebox_common_linux::SigSet>() {
                    self.sys_rt_sigaction(signum, act, oldact).map(|()| 0)
                } else {
                    Err(Errno::EINVAL)
                }
            }
            SyscallRequest::RtSigreturn { stack } => return ContinueOperation::RtSigreturn(stack),
            SyscallRequest::Ioctl { fd, arg } => self.sys_ioctl(fd, arg).map(|v| v as usize),
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
                self.sys_mprotect(addr, length, prot).map(|()| 0)
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
            SyscallRequest::Munmap { addr, length } => self.sys_munmap(addr, length).map(|()| 0),
            SyscallRequest::Brk { addr } => self.sys_brk(addr),
            SyscallRequest::Readv { fd, iovec, iovcnt } => self.sys_readv(fd, iovec, iovcnt),
            SyscallRequest::Writev { fd, iovec, iovcnt } => self.sys_writev(fd, iovec, iovcnt),
            SyscallRequest::Access { pathname, mode } => {
                pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                    self.sys_access(path, mode).map(|()| 0)
                })
            }
            SyscallRequest::Madvise {
                addr,
                length,
                behavior,
            } => self.sys_madvise(addr, length, behavior).map(|()| 0),
            SyscallRequest::Dup {
                oldfd,
                newfd,
                flags,
            } => self
                .sys_dup(oldfd, newfd, flags)
                .map(|newfd| newfd as usize),
            SyscallRequest::Socket {
                domain,
                ty,
                flags,
                protocol,
            } => self
                .sys_socket(domain, ty, flags, protocol)
                .map(|fd| fd as usize),
            SyscallRequest::Connect {
                sockfd,
                sockaddr,
                addrlen,
            } => syscalls::net::read_sockaddr_from_user(sockaddr, addrlen)
                .and_then(|sockaddr| self.sys_connect(sockfd, sockaddr).map(|()| 0)),
            SyscallRequest::Accept {
                sockfd,
                addr,
                addrlen,
                flags,
            } => self
                .sys_accept(sockfd, addr, addrlen, flags)
                .map(|fd| fd as usize),
            SyscallRequest::Sendto {
                sockfd,
                buf,
                len,
                flags,
                addr,
                addrlen,
            } => addr
                .map(|addr| syscalls::net::read_sockaddr_from_user(addr, addrlen as usize))
                .transpose()
                .and_then(|sockaddr| self.sys_sendto(sockfd, buf, len, flags, sockaddr)),
            SyscallRequest::Recvfrom {
                sockfd,
                buf,
                len,
                flags,
                addr,
                addrlen,
            } => {
                let mut source_addr = None;
                self.sys_recvfrom(
                    sockfd,
                    buf,
                    len,
                    flags,
                    if addr.is_some() {
                        Some(&mut source_addr)
                    } else {
                        None
                    },
                )
                .and_then(|size| {
                    if let Some(src_addr) = source_addr
                        && let Some(sock_ptr) = addr
                    {
                        syscalls::net::write_sockaddr_to_user(src_addr, sock_ptr, addrlen)?;
                    }
                    Ok(size)
                })
            }
            SyscallRequest::Bind {
                sockfd,
                sockaddr,
                addrlen,
            } => syscalls::net::read_sockaddr_from_user(sockaddr, addrlen)
                .and_then(|sockaddr| self.sys_bind(sockfd, sockaddr).map(|()| 0)),
            SyscallRequest::Listen { sockfd, backlog } => {
                self.sys_listen(sockfd, backlog).map(|()| 0)
            }
            SyscallRequest::Setsockopt {
                sockfd,
                optname,
                optval,
                optlen,
            } => self
                .sys_setsockopt(sockfd, optname, optval, optlen)
                .map(|()| 0),
            SyscallRequest::Getsockopt {
                sockfd,
                optname,
                optval,
                optlen,
            } => self
                .sys_getsockopt(sockfd, optname, optval, optlen)
                .map(|()| 0),
            SyscallRequest::Getsockname {
                sockfd,
                addr,
                addrlen,
            } => self.sys_getsockname(sockfd).and_then(|sockaddr| {
                syscalls::net::write_sockaddr_to_user(
                    syscalls::net::SocketAddress::Inet(sockaddr),
                    addr,
                    addrlen,
                )
                .map(|()| 0)
            }),
            SyscallRequest::Uname { buf } => self.sys_uname(buf).map(|()| 0usize),
            SyscallRequest::Fcntl { fd, arg } => self.sys_fcntl(fd, arg).map(|v| v as usize),
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
            } => self.sys_epoll_ctl(epfd, op, fd, event).map(|()| 0),
            SyscallRequest::EpollCreate { flags } => {
                self.sys_epoll_create(flags).map(|fd| fd as usize)
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
            SyscallRequest::ArchPrctl { arg } => self.sys_arch_prctl(arg).map(|()| 0),
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
            SyscallRequest::Poll { fds, nfds, timeout } => self.sys_poll(fds, nfds, timeout),
            SyscallRequest::Select {
                nfds,
                readfds,
                writefds,
                exceptfds,
                timeout,
            } => self.sys_select(nfds, readfds, writefds, exceptfds, timeout),
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
            SyscallRequest::Gettimeofday { tv, tz } => self.sys_gettimeofday(tv, tz).map(|()| 0),
            SyscallRequest::ClockGettime { clockid, tp } => {
                let clock_id =
                    litebox_common_linux::ClockId::try_from(clockid).expect("invalid clockid");
                self.sys_clock_gettime(clock_id).and_then(|t| {
                    unsafe { tp.write_at_offset(0, t) }
                        .map(|()| 0)
                        .ok_or(Errno::EFAULT)
                })
            }
            SyscallRequest::ClockGetres { clockid, res } => {
                let clock_id =
                    litebox_common_linux::ClockId::try_from(clockid).expect("invalid clockid");
                self.sys_clock_getres(clock_id, res).map(|()| 0)
            }
            SyscallRequest::ClockNanosleep {
                clockid,
                flags,
                request,
                remain,
            } => {
                let clock_id =
                    litebox_common_linux::ClockId::try_from(clockid).expect("invalid clockid");
                self.sys_clock_nanosleep(clock_id, flags, request, remain)
                    .map(|()| 0)
            }
            SyscallRequest::Time { tloc } => self
                .sys_time(tloc)
                .and_then(|second| usize::try_from(second).or(Err(Errno::EOVERFLOW))),
            SyscallRequest::Openat {
                dirfd,
                pathname,
                flags,
                mode,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                self.sys_openat(dirfd, path, flags, mode)
                    .map(|fd| fd as usize)
            }),
            SyscallRequest::Ftruncate { fd, length } => self.sys_ftruncate(fd, length).map(|()| 0),
            SyscallRequest::Unlinkat {
                dirfd,
                pathname,
                flags,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                self.sys_unlinkat(dirfd, path, flags).map(|()| 0)
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
                self.sys_eventfd2(initval, flags).map(|fd| fd as usize)
            }
            SyscallRequest::Pipe2 { pipefd, flags } => {
                self.sys_pipe2(flags).and_then(|(read_fd, write_fd)| {
                    unsafe { pipefd.write_at_offset(0, read_fd).ok_or(Errno::EFAULT) }?;
                    unsafe { pipefd.write_at_offset(1, write_fd).ok_or(Errno::EFAULT) }?;
                    Ok(0)
                })
            }
            SyscallRequest::Clone { args } => self.handle_clone_request(&args, ctx),
            SyscallRequest::Clone3 { args } => {
                if let Some(clone_args) = unsafe { args.read_at_offset(0) } {
                    self.handle_clone_request(&clone_args, ctx)
                } else {
                    Err(Errno::EFAULT)
                }
            }
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
                self.sys_getrlimit(resource, rlim).map(|()| 0)
            }
            SyscallRequest::Setrlimit { resource, rlim } => {
                self.sys_setrlimit(resource, rlim).map(|()| 0)
            }
            SyscallRequest::Prlimit {
                pid,
                resource,
                new_limit,
                old_limit,
            } => self
                .sys_prlimit(pid, resource, new_limit, old_limit)
                .map(|()| 0),
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
            SyscallRequest::CapGet { header, data } => self.sys_capget(header, data).map(|()| 0),
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
            SyscallRequest::Alarm { seconds } => self.sys_alarm(seconds),
            SyscallRequest::ThreadKill { tgid, tid, sig } => {
                litebox_common_linux::Signal::try_from(sig)
                    .map_err(|_| Errno::EINVAL)
                    .and_then(|sig| self.sys_tgkill(tgid, tid, sig).map(|()| 0))
            }
            SyscallRequest::SetITimer {
                which,
                new_value,
                old_value,
            } => self.sys_setitimer(which, new_value, old_value).map(|()| 0),
            _ => {
                todo!()
            }
        };

        set_return(
            ctx,
            res.unwrap_or_else(|e| (e.as_neg() as isize).reinterpret_as_unsigned()),
        );
        ContinueOperation::ResumeGuest
    }
}

const MAX_SIGNAL_NUMBER: u64 = 64;

impl Task {
    fn handle_clone_request(
        &self,
        clone_args: &litebox_common_linux::CloneArgs,
        ctx: &litebox_common_linux::PtRegs,
    ) -> Result<usize, Errno> {
        if clone_args.cgroup != 0 {
            unimplemented!("Clone with cgroup is not supported");
        }
        if clone_args.set_tid != 0 {
            unimplemented!("Clone with set_tid is not supported");
        }
        // Note `exit_signal` is ignored because we don't support `fork` yet; we just validate it.
        if clone_args.exit_signal > MAX_SIGNAL_NUMBER {
            return Err(Errno::EINVAL);
        }
        let parent_tid = if clone_args.parent_tid == 0 {
            None
        } else {
            Some(MutPtr::from_usize(
                usize::try_from(clone_args.parent_tid).unwrap(),
            ))
        };
        let stack = if clone_args.stack == 0 {
            None
        } else {
            Some(MutPtr::from_usize(
                usize::try_from(clone_args.stack).unwrap(),
            ))
        };
        let child_tid = if clone_args.child_tid == 0 {
            None
        } else {
            Some(MutPtr::from_usize(
                usize::try_from(clone_args.child_tid).unwrap(),
            ))
        };
        let tls = if clone_args.tls != 0 {
            let addr = usize::try_from(clone_args.tls).unwrap();
            #[cfg(target_arch = "x86_64")]
            let desc = MutPtr::from_usize(addr);
            #[cfg(target_arch = "x86")]
            let desc = {
                let desc = unsafe {
                    MutPtr::<litebox_common_linux::UserDesc>::from_usize(addr).read_at_offset(0)
                }
                .ok_or(Errno::EFAULT)?
                .into_owned();
                // Note that different from `set_thread_area` syscall that returns the allocated entry number
                // when requested (i.e., `desc.entry_number` is -1), here we just read the descriptor to LiteBox and
                // assume the entry number is properly set so that we don't need to write it back. This is because
                // we set up the TLS descriptor in the new thread's context, at which point the original descriptor
                // pointer might no longer be valid. Linux does not have this problem because it sets up the TLS for
                // the child thread in the parent thread before `clone` returns.
                // In practice, glibc always sets the entry number to a valid value when calling `clone` with TLS as
                // all threads can share the same TLS entry as the main thread.
                let idx = desc.entry_number;
                debug_assert_ne!(idx, u32::MAX);
                desc
            };
            Some(desc)
        } else {
            None
        };
        usize::try_from(clone_args.stack_size)
            .map_err(|_| Errno::EINVAL)
            .and_then(|stack_size| {
                self.sys_clone(
                    clone_args.flags,
                    parent_tid,
                    stack,
                    stack_size,
                    child_tid,
                    tls,
                    ctx,
                    ctx.get_ip(),
                )
            })
    }
}

struct GlobalState {
    fs: LinuxFS,
}

struct LinuxShimTls {
    current_task: Task,
}

struct Task {
    global: Arc<GlobalState>,
    process: Arc<syscalls::process::Process>,
    /// Process ID
    pid: i32,
    /// Parent Process ID
    ppid: i32,
    /// Thread ID
    tid: i32,
    /// When a thread whose `clear_child_tid` is not `None` terminates, and it shares memory with other threads,
    /// the kernel writes 0 to the address specified by `clear_child_tid` and then executes:
    ///
    /// futex(clear_child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);
    ///
    /// This operation wakes a single thread waiting on the specified memory location via futex.
    /// Any errors from the futex wake operation are ignored.
    clear_child_tid: Cell<Option<UserMutPointer<i32>>>,
    /// The purpose of the robust futex list is to ensure that if a thread accidentally fails to unlock a futex before
    /// terminating or calling execve(2), another thread that is waiting on that futex is notified that the former owner
    /// of the futex has died. This notification consists of two pieces: the FUTEX_OWNER_DIED bit is set in the futex word,
    /// and the kernel performs a futex(2) FUTEX_WAKE operation on one of the threads waiting on the futex.
    robust_list: Cell<Option<UserConstPointer<litebox_common_linux::RobustListHead<Platform>>>>,
    /// Task credentials. These are set per task but are Arc'd to save space
    /// since most tasks never change their credentials.
    credentials: Arc<syscalls::process::Credentials>,
    /// Command name (usually the executable name, excluding the path)
    comm: Cell<[u8; litebox_common_linux::TASK_COMM_LEN]>,
    /// Filesystem state. `RefCell` to support `unshare` in the future.
    fs: RefCell<Arc<syscalls::file::FsState>>,
    /// File descriptors. `RefCell` to support `unshare` in the future.
    files: RefCell<Arc<syscalls::file::FilesState>>,
}

impl Drop for Task {
    fn drop(&mut self) {
        self.prepare_for_exit();
    }
}

litebox::shim_thread_local! {
    #[platform = Platform]
    static SHIM_TLS: LinuxShimTls;
}

fn with_current_task<R>(f: impl FnOnce(&Task) -> R) -> R {
    SHIM_TLS.with(|tls| f(&tls.current_task))
}

pub type LoadFilter =
    fn(envp: &mut alloc::vec::Vec<alloc::ffi::CString>, auxv: &mut loader::auxv::AuxVec);
static LOAD_FILTER: once_cell::race::OnceBox<LoadFilter> = once_cell::race::OnceBox::new();

/// Set the load filter, which can augment envp or auxv when starting a new program.
///
/// # Panics
/// Panics if the load filter is already set.
fn set_load_filter(callback: LoadFilter) {
    LOAD_FILTER
        .set(alloc::boxed::Box::new(callback))
        .expect("load filter already set");
}

impl Task {
    /// Loads the specified program into the process's address space and returns the
    /// register state for the initial thread.
    fn load_program(
        &self,
        path: &str,
        argv: Vec<alloc::ffi::CString>,
        mut envp: Vec<alloc::ffi::CString>,
    ) -> Result<litebox_common_linux::PtRegs, loader::ElfLoaderError> {
        let mut aux = self.init_auxv();
        if let Some(&filter) = LOAD_FILTER.get() {
            filter(&mut envp, &mut aux);
        }

        // TODO: split parsing from mapping so that we can return an error code to execve that it
        // can return to the guest.
        let load_info = loader::load_program(self, path, argv, envp, aux)?;

        let comm = path.rsplit('/').next().unwrap_or("unknown");
        self.set_task_comm(comm.as_bytes());

        #[cfg(target_arch = "x86_64")]
        let pt_regs = litebox_common_linux::PtRegs {
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
            rdi: 0,
            orig_rax: 0,
            rip: load_info.entry_point,
            cs: 0x33, // __USER_CS
            eflags: 0,
            rsp: load_info.user_stack_top,
            ss: 0x2b, // __USER_DS
        };
        #[cfg(target_arch = "x86")]
        let pt_regs = litebox_common_linux::PtRegs {
            ebx: 0,
            ecx: 0,
            edx: 0,
            esi: 0,
            edi: 0,
            ebp: 0,
            eax: 0,
            xds: 0,
            xes: 0,
            xfs: 0,
            xgs: 0,
            orig_eax: 0,
            eip: load_info.entry_point,
            xcs: 0x23, // __USER_CS
            eflags: 0,
            esp: load_info.user_stack_top,
            xss: 0x2b, // __USER_DS
        };

        Ok(pt_regs)
    }
}

#[cfg(test)]
mod test_utils {
    extern crate std;
    use super::*;
    use crate::syscalls::process::NEXT_THREAD_ID;

    impl GlobalState {
        /// Make a new task with default values for testing.
        pub(crate) fn new_test_task(self: Arc<Self>) -> Task {
            let pid = NEXT_THREAD_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let files = Arc::new(syscalls::file::FilesState::new(litebox()));
            files.initialize_stdio_in_shared_descriptors_table(&self.fs);
            Task {
                global: self,
                process: Arc::new(syscalls::process::Process::new()),
                pid,
                ppid: 0,
                tid: pid,
                clear_child_tid: Cell::new(None),
                robust_list: Cell::new(None),
                credentials: Arc::new(syscalls::process::Credentials {
                    uid: 0,
                    euid: 0,
                    gid: 0,
                    egid: 0,
                }),
                comm: Cell::new(*b"test\0\0\0\0\0\0\0\0\0\0\0\0"),
                fs: Arc::new(syscalls::file::FsState::new()).into(),
                files: files.into(),
            }
        }
    }

    impl Task {
        /// Returns a function that clones this task with a new TID for testing.
        pub(crate) fn clone_for_test(&self) -> impl 'static + Send + FnOnce() -> Self {
            let global = self.global.clone();
            let process = self.process.clone();
            let credentials = self.credentials.clone();
            let fs = self.fs.clone();
            let comm = self.comm.clone();
            let pid = self.pid;
            let tid = NEXT_THREAD_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let parent_pid = self.ppid;
            let files = self.files.clone();
            move || Task {
                global,
                process,
                pid,
                ppid: parent_pid,
                tid,
                clear_child_tid: None.into(),
                robust_list: None.into(),
                credentials,
                comm,
                fs,
                files,
            }
        }

        /// Spawns a thread that runs with a clone of this task and a new TID.
        pub(crate) fn spawn_clone_for_test<R>(
            &self,
            f: impl 'static + Send + FnOnce(Task) -> R,
        ) -> std::thread::JoinHandle<R>
        where
            R: 'static + Send,
        {
            let clone_task_fn = self.clone_for_test();
            std::thread::spawn(move || f(clone_task_fn()))
        }
    }
}
