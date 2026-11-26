// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of file related syscalls, e.g., `open`, `read`, `write`, etc.

use alloc::{ffi::CString, string::String, vec};
use litebox::{
    event::{
        Events, IOPollable,
        observer::Observer,
        wait::{WaitContext, WaitError},
    },
    fs::{
        DirectoryAnchor,
        errors::{LockError, OpenError},
    },
    process::ProcessError,
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt as _},
};
use litebox_broker_protocol::event::CreateEventRequest;
use litebox_broker_protocol::fd::{DupTarget, FdCreate, FdOperation, FdResponse};
use litebox_broker_protocol::fs::{
    DirectoryRecordBudget, FileAccessMode, FileLockOperation, FileMode as Mode, FileOpenFlags,
    FileSeekWhence as SeekWhence, FileStatus, FileStatusFlags, FileTimeUpdate, FileTimestamp,
    FileType, FileUser, SetFileTimes,
};
use litebox_broker_protocol::pipe::CreatePipeRequest;
use litebox_broker_protocol::terminal::{
    ChangeTiming, TerminalOperation, TerminalResponse, TerminalSettings,
};
use litebox_broker_protocol::{ProcessGroupId, ProcessId};
use litebox_common_linux::{
    AccessFlags, AtFlags, CloseRangeFlags, EfdFlags, EpollCreateFlags, FcntlArg,
    FileDescriptorFlags, FileStat, InodeType, IoReadVec, IoWriteVec, IoctlArg, OFlags, PAGE_SIZE,
    Statx, StatxMask, TimeParam, errno::Errno,
};
use litebox_platform::buffer::{Buffer as _, Fault, ReadBuffer, WriteBuffer};
use litebox_platform::time::{Instant as _, TimeProvider};

use super::{
    epoll::EpollFd, eventfd::EventfdFd, inet::InetSocketFd, pidfd::PidfdFd, pipe::PipeFd,
    process::RestartBlock, timerfd::TimerfdFd, unix::UnixSocketFd, vsock::VsockSocketFd,
};
use crate::guest_buffer::{GuestReadBuffer, GuestWriteBuffer};
use crate::{GlobalState, ShimPlatform, Task, UserPtr, UserPtrMut};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;

pub(crate) type FileFd<Platform> = File<Platform>;

/// A file descriptor's open file description.
pub(crate) struct File<Platform: ShimPlatform> {
    file: Arc<litebox::fs::File<Platform>>,
}

impl<Platform: ShimPlatform> From<litebox::fs::File<Platform>> for File<Platform> {
    fn from(file: litebox::fs::File<Platform>) -> Self {
        Self {
            file: Arc::new(file),
        }
    }
}

impl<Platform: ShimPlatform> IOPollable for File<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.file.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        match self.status() {
            // Linux reports regular files ready regardless of access mode or EOF.
            Ok(status) if status.file_type == FileType::RegularFile => Events::IN | Events::OUT,
            Ok(_) => self.file.check_io_events(),
            Err(_) => Events::ERR,
        }
    }
}

impl<Platform: ShimPlatform> File<Platform> {
    pub(crate) fn file(&self) -> &Arc<litebox::fs::File<Platform>> {
        &self.file
    }

    /// Reads into `buf` at `offset`, or at the file offset if `offset` is `None`.
    pub(crate) fn read(
        &self,
        buf: impl ReadBuffer,
        offset: Option<usize>,
        cx: Option<&WaitContext<'_, Platform>>,
    ) -> Result<usize, Errno> {
        Ok(self.file.read(buf, offset, cx)?)
    }

    /// Writes `buf` at `offset`, or at the file offset if `offset` is `None`.
    pub(crate) fn write(
        &self,
        buf: impl WriteBuffer,
        offset: Option<usize>,
        cx: Option<&WaitContext<'_, Platform>>,
    ) -> Result<usize, Errno> {
        Ok(self.file.write(buf, offset, cx)?)
    }

    /// Truncates or extends the file to `length` bytes, keeping the file offset.
    pub(crate) fn truncate(&self, length: usize) -> Result<(), Errno> {
        Ok(self.file.truncate(length, false)?)
    }

    pub(crate) fn status(&self) -> Result<FileStatus, Errno> {
        Ok(self.file.status()?)
    }

    /// The current name of a directory, or the name a file was opened by.
    fn path(&self) -> Result<String, Errno> {
        Ok(self.file.path()?)
    }

    /// Controls the shared terminal, waiting interruptibly for output-draining operations.
    pub(crate) fn terminal_control(
        &self,
        operation: TerminalOperation,
        cx: Option<&WaitContext<'_, Platform>>,
    ) -> Result<TerminalResponse, Errno> {
        Ok(self.file.terminal_control(operation, cx)?)
    }

    /// Returns the `F_GETFL` flags of the open file description.
    pub(crate) fn get_status_flags(&self) -> Result<OFlags, Errno> {
        linux_status_flags(self.file.get_status_flags()?)
    }

    /// Returns the access mode the open file description was opened with, or `None` if it was
    /// opened only for path-based operations (`O_PATH`).
    pub(super) fn access_mode(&self) -> Result<Option<FileAccessMode>, Errno> {
        let status = self.file.get_status_flags()?;
        Ok((!status.flags.contains(FileOpenFlags::PATH)).then_some(status.access))
    }

    /// Changes the status flags in `mask` of the open file description to their values in
    /// `flags`, ignoring flags other than `O_NONBLOCK` and `O_APPEND`.
    pub(crate) fn set_status_flags(&self, mask: OFlags, flags: OFlags) -> Result<(), Errno> {
        let (mask, flags) = status_flags_change(mask, flags);
        self.file.set_status_flags(mask, flags)?;
        Ok(())
    }
}

impl<Platform: ShimPlatform> GlobalState<Platform> {
    /// Runs `f` on the file at `fd`, without holding the descriptor table.
    pub(crate) fn with_file<R>(
        &self,
        fd: &FileFd<Platform>,
        f: impl FnOnce(&File<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        f(fd)
    }

    /// The LiteBox file behind `fd`, failing with `ENOTDIR` for other kinds of descriptor.
    pub(crate) fn file_for_dirfd(
        &self,
        fd: &AnyTypedFd<Platform>,
    ) -> Result<Arc<litebox::fs::File<Platform>>, Errno> {
        self.with_file(fd.file_only(Errno::ENOTDIR)?, |file| {
            Ok(Arc::clone(file.file()))
        })
    }
}

#[derive(Clone, Copy)]
struct AccessUserInfo {
    user: u32,
    group: u32,
}

impl From<FileUser> for AccessUserInfo {
    fn from(value: FileUser) -> Self {
        Self {
            user: u32::from(value.user),
            group: u32::from(value.group),
        }
    }
}

/// Task state shared by `CLONE_FS`.
pub(crate) struct FsState<Platform: ShimPlatform> {
    umask: core::sync::atomic::AtomicU32,
    // XXX: the context stores credentials, might need to reconsider design when implementing
    // `setuid` and similar.
    pub(crate) context: litebox::sync::RwLock<Platform, litebox::fs::Context>,
}

impl<Platform: ShimPlatform> Clone for FsState<Platform> {
    fn clone(&self) -> Self {
        Self {
            umask: self.umask.load(Ordering::Relaxed).into(),
            context: litebox::sync::RwLock::new(self.context.read().clone()),
        }
    }
}

impl<Platform: ShimPlatform> FsState<Platform> {
    /// Create filesystem context and umask state for the task.
    pub(crate) fn new(context: litebox::fs::Context) -> Self {
        Self {
            umask: u32::from((Mode::WGRP | Mode::WOTH).bits()).into(),
            context: litebox::sync::RwLock::new(context),
        }
    }

    /// The filesystem context of a task running as `credentials`.
    pub(crate) fn context_for(credentials: &super::process::Credentials) -> litebox::fs::Context {
        let user_info = FileUser {
            // XXX: Linux ids are 32-bit, but the core litebox file system uses 16-bit ones, so we
            // may need to widen `UserInfo`.
            user: u16::try_from(credentials.euid)
                .unwrap_or_else(|_| unimplemented!("{}", credentials.euid)),
            group: u16::try_from(credentials.egid)
                .unwrap_or_else(|_| unimplemented!("{}", credentials.egid)),
        };
        let mut context = litebox::fs::Context::new();
        context.set_acting_user(user_info);
        context
    }

    /// The file mode creation mask.
    pub(crate) fn umask(&self) -> Mode {
        Mode::from_u32_bits_truncate(self.umask.load(Ordering::Relaxed))
    }

    /// Sets the file mode creation mask to the permission bits of `umask`, returning the previous
    /// mask.
    pub(crate) fn set_umask(&self, umask: u32) -> Mode {
        let umask = Mode::from_u32_bits_truncate(umask) & (Mode::RWXU | Mode::RWXG | Mode::RWXO);
        Mode::from_u32_bits_truncate(self.umask.swap(umask.bits().into(), Ordering::Relaxed))
    }
}

/// Translate Linux open flags after descriptor-local `O_CLOEXEC` has been removed.
fn file_open_options(flags: OFlags) -> Result<(FileAccessMode, FileOpenFlags), OpenError> {
    const SUPPORTED_FLAGS: OFlags = OFlags::CREAT
        .union(OFlags::RDONLY)
        .union(OFlags::WRONLY)
        .union(OFlags::RDWR)
        .union(OFlags::TRUNC)
        .union(OFlags::NOCTTY)
        .union(OFlags::EXCL)
        .union(OFlags::DIRECTORY)
        .union(OFlags::NONBLOCK)
        .union(OFlags::LARGEFILE)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::APPEND)
        .union(OFlags::PATH);

    if flags.intersects(SUPPORTED_FLAGS.complement()) {
        unimplemented!("{flags:?}")
    }
    let access = match flags.bits() & 3 {
        0 => FileAccessMode::ReadOnly,
        1 => FileAccessMode::WriteOnly,
        2 => FileAccessMode::ReadWrite,
        _ => return Err(OpenError::AccessNotAllowed),
    };
    let mut output = FileOpenFlags::NONE;
    for (linux, file) in [
        (OFlags::CREAT, FileOpenFlags::CREATE),
        (OFlags::TRUNC, FileOpenFlags::TRUNCATE),
        (OFlags::NOCTTY, FileOpenFlags::NO_CONTROLLING_TERMINAL),
        (OFlags::EXCL, FileOpenFlags::EXCLUSIVE),
        (OFlags::DIRECTORY, FileOpenFlags::DIRECTORY),
        (OFlags::NONBLOCK, FileOpenFlags::NONBLOCKING),
        (OFlags::LARGEFILE, FileOpenFlags::LARGE_FILE),
        (OFlags::NOFOLLOW, FileOpenFlags::NO_FOLLOW),
        (OFlags::APPEND, FileOpenFlags::APPEND),
        (OFlags::PATH, FileOpenFlags::PATH),
    ] {
        if flags.contains(linux) {
            output = output.union(file);
        }
    }
    Ok((access, output))
}

/// Returns the `F_GETFL` flags for the access mode and status flags `status` of an open file
/// description.
pub(super) fn linux_status_flags(status: FileStatusFlags) -> Result<OFlags, Errno> {
    let mut flags = match status.access {
        FileAccessMode::ReadOnly => OFlags::RDONLY,
        FileAccessMode::WriteOnly => OFlags::WRONLY,
        FileAccessMode::ReadWrite => OFlags::RDWR,
        _ => return Err(Errno::EIO),
    };
    for (file, linux) in [
        (FileOpenFlags::NONBLOCKING, OFlags::NONBLOCK),
        (FileOpenFlags::APPEND, OFlags::APPEND),
        (FileOpenFlags::PATH, OFlags::PATH),
    ] {
        if status.flags.contains(file) {
            flags |= linux;
        }
    }
    Ok(flags)
}

/// Returns the broker mask and flags that change the status flags in `mask` of an open file
/// description to their values in `flags`, ignoring flags other than `O_NONBLOCK` and `O_APPEND`.
pub(crate) fn status_flags_change(mask: OFlags, flags: OFlags) -> (FileOpenFlags, FileOpenFlags) {
    let mut file_mask = FileOpenFlags::NONE;
    let mut file_flags = FileOpenFlags::NONE;
    for (linux, file) in [
        (OFlags::NONBLOCK, FileOpenFlags::NONBLOCKING),
        (OFlags::APPEND, FileOpenFlags::APPEND),
    ] {
        if mask.contains(linux) {
            file_mask = file_mask.union(file);
            if flags.contains(linux) {
                file_flags = file_flags.union(file);
            }
        }
    }
    (file_mask, file_flags)
}

pub(crate) use super::fd_cache::FilesState;

/// A raw fd resolved once into a typed client of a broker object.
pub(crate) enum AnyTypedFd<Platform: ShimPlatform> {
    File(Arc<FileFd<Platform>>),
    Inet(Arc<InetSocketFd<Platform>>),
    Pipe(Arc<PipeFd<Platform>>),
    Eventfd(Arc<EventfdFd<Platform>>),
    Epoll(Arc<EpollFd<Platform>>),
    Unix(Arc<UnixSocketFd<Platform>>),
    Timerfd(Arc<TimerfdFd<Platform>>),
    Vsock(Arc<VsockSocketFd<Platform>>),
    Pidfd(Arc<PidfdFd<Platform>>),
}

impl<Platform: ShimPlatform> Clone for AnyTypedFd<Platform> {
    fn clone(&self) -> Self {
        match self {
            Self::File(fd) => Self::File(fd.clone()),
            Self::Inet(fd) => Self::Inet(fd.clone()),
            Self::Pipe(fd) => Self::Pipe(fd.clone()),
            Self::Eventfd(fd) => Self::Eventfd(fd.clone()),
            Self::Epoll(fd) => Self::Epoll(fd.clone()),
            Self::Unix(fd) => Self::Unix(fd.clone()),
            Self::Timerfd(fd) => Self::Timerfd(fd.clone()),
            Self::Vsock(fd) => Self::Vsock(fd.clone()),
            Self::Pidfd(fd) => Self::Pidfd(fd.clone()),
        }
    }
}

impl<Platform: ShimPlatform> AnyTypedFd<Platform> {
    /// The subsystem backing this fd, for diagnostics.
    pub(crate) fn subsystem_name(&self) -> &'static str {
        match self {
            Self::File(_) => "file",
            Self::Inet(_) => "inet",
            Self::Pipe(_) => "pipe",
            Self::Eventfd(_) => "eventfd",
            Self::Epoll(_) => "epoll",
            Self::Unix(_) => "unix",
            Self::Timerfd(_) => "timerfd",
            Self::Vsock(_) => "vsock",
            Self::Pidfd(_) => "pidfd",
        }
    }

    /// The file fd behind this descriptor, or `None` for every other subsystem.
    pub(crate) fn as_file(&self) -> Option<&FileFd<Platform>> {
        match self {
            Self::File(fd) => Some(fd),
            _ => None,
        }
    }

    /// Like [`Self::as_file`], but fails with `otherwise` for non-file descriptors.
    pub(crate) fn file_only(&self, otherwise: Errno) -> Result<&FileFd<Platform>, Errno> {
        self.as_file().ok_or(otherwise)
    }

    /// Run the handler matching this fd's subsystem.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch<R>(
        &self,
        file: impl FnOnce(&FileFd<Platform>) -> R,
        inet: impl FnOnce(&InetSocketFd<Platform>) -> R,
        pipe: impl FnOnce(&PipeFd<Platform>) -> R,
        eventfd: impl FnOnce(&EventfdFd<Platform>) -> R,
        epoll: impl FnOnce(&EpollFd<Platform>) -> R,
        unix: impl FnOnce(&UnixSocketFd<Platform>) -> R,
        timerfd: impl FnOnce(&TimerfdFd<Platform>) -> R,
        vsock: impl FnOnce(&VsockSocketFd<Platform>) -> R,
        pidfd: impl FnOnce(&PidfdFd<Platform>) -> R,
    ) -> R {
        match self {
            Self::File(fd) => file(fd),
            Self::Inet(fd) => inet(fd),
            Self::Pipe(fd) => pipe(fd),
            Self::Eventfd(fd) => eventfd(fd),
            Self::Epoll(fd) => epoll(fd),
            Self::Unix(fd) => unix(fd),
            Self::Timerfd(fd) => timerfd(fd),
            Self::Vsock(fd) => vsock(fd),
            Self::Pidfd(fd) => pidfd(fd),
        }
    }
}

impl<Platform: ShimPlatform> core::fmt::Debug for AnyTypedFd<Platform> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("AnyTypedFd")
            .field(&self.subsystem_name())
            .finish()
    }
}

/// Path in the file system
#[derive(Debug)]
enum FsPath {
    /// Absolute path
    Absolute { path: String },
    /// Empty path at `AT_FDCWD`
    Cwd,
    /// Relative path; `fd` is a descriptor or `AT_FDCWD`
    FdRelative { fd: i32, path: String },
    /// Fd
    Fd(i32),
}

struct LookupPath<Platform: ShimPlatform> {
    dir: Option<Arc<litebox::fs::File<Platform>>>,
    path: String,
}

impl<Platform: ShimPlatform> LookupPath<Platform> {
    fn anchor(&self, task: &Task<Platform>) -> DirectoryAnchor<'_, Platform> {
        match self.dir.as_deref() {
            Some(dir) => DirectoryAnchor::Object(dir),
            None if self.path.starts_with('/') => DirectoryAnchor::None,
            None => DirectoryAnchor::Cwd {
                pending_child: task.pending_cwd_child(),
            },
        }
    }
}

/// `path` named under the directory named `dir`.
fn name_under(mut dir: String, path: &str) -> String {
    if !dir.ends_with('/') {
        dir.push('/');
    }
    dir.push_str(path);
    dir
}

/// Maximum size of a file path
pub const PATH_MAX: usize = 4096;

impl FsPath {
    /// Create a new `FsPath` from a dirfd and path.
    fn new(dirfd: i32, path: &str) -> Result<Self, Errno> {
        if path.len() > PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let fs_path = if path.starts_with('/') {
            FsPath::Absolute { path: path.into() }
        } else if dirfd >= 0 {
            if path.is_empty() {
                FsPath::Fd(dirfd)
            } else {
                FsPath::FdRelative {
                    fd: dirfd,
                    path: path.into(),
                }
            }
        } else if dirfd == litebox_common_linux::AT_FDCWD {
            if path.is_empty() {
                FsPath::Cwd
            } else {
                FsPath::FdRelative {
                    fd: dirfd,
                    path: path.into(),
                }
            }
        } else {
            // TODO: Linux rejects an empty path with ENOENT before checking dirfd, unless AT_EMPTY_PATH.
            return Err(Errno::EBADF);
        };
        match &fs_path {
            FsPath::Absolute { path } | FsPath::FdRelative { path, .. } if path.contains('\0') => {
                return Err(Errno::EINVAL);
            }
            _ => {}
        }
        Ok(fs_path)
    }
}

/// Fixed `statfs`/`fstatfs` result, since LiteBox currently does not track per-filesystem usage.
// TODO: Return actual per-filesystem values rather than this constant.
const FAKE_STATFS: litebox_common_linux::Statfs = litebox_common_linux::Statfs {
    f_type: 0x0102_1994, // TMPFS_MAGIC
    f_bsize: 4096,
    f_blocks: 1 << 20,
    f_bfree: 1 << 19,
    f_bavail: 1 << 19,
    f_files: 1 << 20,
    f_ffree: 1 << 19,
    f_fsid: [0; 2],
    f_namelen: 255,
    f_frsize: 4096,
    f_flags: 0x20, // ST_VALID
    f_spare: [0; 4],
};

impl<Platform: ShimPlatform> Task<Platform> {
    fn get_umask(&self) -> Mode {
        self.fs.borrow().umask()
    }

    fn pending_cwd_child(&self) -> Option<ProcessId> {
        self.vfork
            .borrow()
            .as_ref()
            .map(|state| state.child.identity().process_id)
    }

    /// Queries the broker for the working directory's current name.
    fn query_cwd_name(&self) -> Result<String, Errno> {
        Ok(self.global.litebox.getcwd(self.pending_cwd_child())?)
    }

    /// The file a dirfd refers to, which need not be a directory.
    fn file_for_dirfd(&self, fd: i32) -> Result<Arc<litebox::fs::File<Platform>>, Errno> {
        self.global.file_for_dirfd(&self.typed_fd(fd)?)
    }

    fn lookup_relative(&self, fd: i32, path: String) -> Result<LookupPath<Platform>, Errno> {
        let dir = (fd != litebox_common_linux::AT_FDCWD)
            .then(|| self.file_for_dirfd(fd))
            .transpose()?;
        Ok(LookupPath { dir, path })
    }

    /// Rewrites a relative lookup that lexically spells a `/proc/self/fd/` entry to its absolute
    /// name, which [`Self::proc_self_fd`] then reaches as an absolute path would.
    fn absolutize_proc_self_fd(&self, path: LookupPath<Platform>) -> LookupPath<Platform> {
        // Skip the broker round trip unless `path` itself spells `fd/`; this assumes no directory
        // named `/proc/self/fd` (or below it) exists.
        if path.path.starts_with('/') || !path.path.contains("fd/") {
            return path;
        }
        let dir = match path.dir.as_deref() {
            Some(dir) => dir.path(),
            None => self.global.litebox.getcwd(self.pending_cwd_child()),
        };
        match dir {
            Ok(dir) => {
                let name = name_under(dir, &path.path);
                if name.starts_with("/proc/self/fd/") {
                    return LookupPath {
                        dir: None,
                        path: name,
                    };
                }
                path
            }
            Err(_) => path,
        }
    }

    /// Names a path for interfaces that require an absolute name, querying the broker for the
    /// working directory's current name if `path` is relative.
    // XXX: Anchor mount and Unix socket requests on Cwd instead of forming an absolute name.
    pub(super) fn absolute_name(&self, path: &str) -> Result<String, Errno> {
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        let path = if path.starts_with('/') {
            String::from(path)
        } else {
            name_under(self.query_cwd_name()?, path)
        };
        if path.contains('\0') {
            return Err(Errno::EINVAL);
        }
        Ok(path)
    }

    /// A copy of the filesystem context, so no borrow or lock is held across broker calls.
    fn fs_context(&self) -> litebox::fs::Context {
        self.fs.borrow().context.read().clone()
    }

    /// Splits a path operand into the directory it is relative to (if any) and the path, without
    /// any I/O.
    ///
    /// Note that an empty path is not valid for this function, and will be rejected with `ENOENT`.
    fn lookup_path_at(&self, dirfd: i32, pathname: &str) -> Result<LookupPath<Platform>, Errno> {
        let fs_path = FsPath::new(dirfd, pathname)?;
        match fs_path {
            FsPath::Absolute { path } => Ok(LookupPath { dir: None, path }),
            FsPath::Cwd | FsPath::Fd(_) => Err(Errno::ENOENT),
            FsPath::FdRelative { fd, path } => self.lookup_relative(fd, path),
        }
    }

    pub(super) fn do_open(
        &self,
        path: &str,
        flags: OFlags,
        mode: Mode,
    ) -> Result<litebox::fs::File<Platform>, Errno> {
        self.do_openat(litebox_common_linux::AT_FDCWD, path, flags, mode)
    }

    fn open_from(
        &self,
        dir: DirectoryAnchor<'_, Platform>,
        path: &str,
        flags: OFlags,
        mode: Mode,
    ) -> Result<litebox::fs::File<Platform>, Errno> {
        let mode = mode & !self.get_umask();
        let context = self.fs_context();
        // The broker opens on behalf of a `vfork` child's parent, so the open must not give the
        // parent's session a controlling terminal. The child can still acquire one with
        // `TIOCSCTTY`.
        let flags = if self.vfork.borrow().is_some() {
            flags | OFlags::NOCTTY
        } else {
            flags
        };
        let (access, open_flags) =
            file_open_options(flags - OFlags::CLOEXEC).map_err(Errno::from)?;
        let file = self
            .global
            .litebox
            .open_file(&context, dir, path, access, open_flags, mode)
            .map_err(Errno::from)?;
        if flags.intersects(OFlags::WRONLY | OFlags::RDWR)
            && !flags.contains(OFlags::PATH)
            && file.status().map_err(Errno::from)?.file_type == FileType::Directory
        {
            return Err(Errno::EISDIR);
        }
        Ok(file)
    }

    fn do_openat(
        &self,
        dirfd: i32,
        pathname: &str,
        flags: OFlags,
        mode: Mode,
    ) -> Result<litebox::fs::File<Platform>, Errno> {
        let path = self.lookup_path_at(dirfd, pathname)?;
        self.open_from(path.anchor(self), &path.path, flags, mode)
    }

    /// Opens the executable without allocating a guest descriptor.
    pub(crate) fn open_program_file(&self, path: &str) -> Result<Arc<FileFd<Platform>>, Errno> {
        Ok(Arc::new(
            self.do_open(path, OFlags::RDONLY | OFlags::NOCTTY, Mode::empty())?
                .into(),
        ))
    }

    /// Handle syscall `umask`
    pub(crate) fn sys_umask(&self, new_mask: u32) -> Mode {
        self.fs.borrow().set_umask(new_mask)
    }

    /// Handle syscall `open`
    #[cfg(test)]
    pub fn sys_open(&self, path: &str, flags: OFlags, mode: Mode) -> Result<u32, Errno> {
        self.sys_openat(litebox_common_linux::AT_FDCWD, path, flags, mode)
    }

    /// Handle syscall `openat`
    pub fn sys_openat(
        &self,
        dirfd: i32,
        pathname: &str,
        flags: OFlags,
        mode: Mode,
    ) -> Result<u32, Errno> {
        let path = self.lookup_path_at(dirfd, pathname)?;
        let mut options = flags - OFlags::CLOEXEC;
        if self.pending_fd_child().is_some() {
            options |= OFlags::NOCTTY;
        }
        let (access, options) = file_open_options(options)?;
        let files = self.files.borrow().clone();
        let mutation = files.mutation();
        let response = self
            .global
            .litebox
            .open_fd(
                self.pending_fd_child(),
                &self.fs_context(),
                path.anchor(self),
                &path.path,
                access,
                options,
                mode & !self.get_umask(),
                flags.contains(OFlags::CLOEXEC),
            )
            .map_err(super::fd_cache::fd_errno)??;
        Ok(self.cache_installed(&mutation, response)?.0.number)
    }

    /// Handle path-based `symlink` and `symlinkat`.
    pub(crate) fn sys_symlinkat(
        &self,
        target: &str,
        dirfd: i32,
        linkpath: &str,
    ) -> Result<(), Errno> {
        // Report long targets as ENAMETOOLONG rather than as broker slot overflow (EIO).
        if target.len() > PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let linkpath = self.lookup_path_at(dirfd, linkpath)?;
        let context = self.fs_context();
        self.global
            .litebox
            .symlink_file(target, &context, linkpath.anchor(self), &linkpath.path)
            .map_err(Errno::from)
    }

    /// Handle path-based `chmod` and `fchmodat`.
    pub(crate) fn sys_fchmodat(&self, dirfd: i32, pathname: &str, mode: u32) -> Result<(), Errno> {
        let path = self.lookup_path_at(dirfd, pathname)?;
        let context = self.fs_context();
        self.global
            .litebox
            .chmod_file(
                &context,
                path.anchor(self),
                &path.path,
                Mode::from_u32_bits_truncate(mode),
            )
            .map_err(Errno::from)
    }

    /// Handle `utimensat`, including the NULL-path form used by `futimens`.
    pub(crate) fn sys_utimensat(
        &self,
        dirfd: i32,
        pathname: Option<UserPtr<core::ffi::c_char>>,
        times: Option<UserPtr<litebox_common_linux::Timespec>>,
        flags: AtFlags,
    ) -> Result<(), Errno> {
        let updates = match times {
            None => [FileTimeUpdate::Now; 2],
            Some(times) => {
                let times = [
                    times.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?,
                    times.read_at_offset::<Platform>(1).ok_or(Errno::EFAULT)?,
                ];
                let mut updates = [FileTimeUpdate::Omit; 2];
                for (time, update) in times.into_iter().zip(&mut updates) {
                    *update = match time.tv_nsec {
                        litebox_common_linux::UTIME_NOW => FileTimeUpdate::Now,
                        litebox_common_linux::UTIME_OMIT => FileTimeUpdate::Omit,
                        0..1_000_000_000 => FileTimeUpdate::Set(FileTimestamp {
                            seconds: time.tv_sec,
                            nanoseconds: u32::try_from(time.tv_nsec).unwrap(),
                        }),
                        _ => return Err(Errno::EINVAL),
                    };
                }
                updates
            }
        };
        self.do_utimes(dirfd, pathname, updates, flags)
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn sys_utime(
        &self,
        pathname: UserPtr<core::ffi::c_char>,
        times: Option<UserPtr<litebox_common_linux::Utimbuf>>,
    ) -> Result<(), Errno> {
        let updates = match times {
            None => [FileTimeUpdate::Now; 2],
            Some(times) => {
                let times = times.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                [times.actime, times.modtime].map(|seconds| {
                    FileTimeUpdate::Set(FileTimestamp {
                        seconds,
                        nanoseconds: 0,
                    })
                })
            }
        };
        self.do_utimes(
            litebox_common_linux::AT_FDCWD,
            Some(pathname),
            updates,
            AtFlags::empty(),
        )
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn sys_futimesat(
        &self,
        dirfd: i32,
        pathname: Option<UserPtr<core::ffi::c_char>>,
        times: Option<UserPtr<litebox_common_linux::TimeVal>>,
    ) -> Result<(), Errno> {
        let updates = match times {
            None => [FileTimeUpdate::Now; 2],
            Some(times) => {
                let times = [
                    times.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?,
                    times.read_at_offset::<Platform>(1).ok_or(Errno::EFAULT)?,
                ];
                let mut updates = [FileTimeUpdate::Omit; 2];
                for (time, update) in times.into_iter().zip(&mut updates) {
                    if !(0..1_000_000).contains(&time.tv_usec) {
                        return Err(Errno::EINVAL);
                    }
                    *update = FileTimeUpdate::Set(FileTimestamp {
                        seconds: time.tv_sec,
                        nanoseconds: u32::try_from(time.tv_usec).unwrap() * 1000,
                    });
                }
                updates
            }
        };
        self.do_utimes(dirfd, pathname, updates, AtFlags::empty())
    }

    fn do_utimes(
        &self,
        dirfd: i32,
        pathname: Option<UserPtr<core::ffi::c_char>>,
        [access, modify]: [FileTimeUpdate; 2],
        flags: AtFlags,
    ) -> Result<(), Errno> {
        // Linux skips pathname, descriptor and flag validation when both fields are omitted.
        if access == FileTimeUpdate::Omit && modify == FileTimeUpdate::Omit {
            return Ok(());
        }
        let allowed = AtFlags::AT_SYMLINK_NOFOLLOW | AtFlags::AT_EMPTY_PATH;
        if flags.intersects(allowed.complement()) {
            return Err(Errno::EINVAL);
        }
        // XXX(jayb): NOW resolves to the filesystem's clock (host, 9P server, or broker), not the
        // guest's; LiteBox assumes these agree.
        let times = SetFileTimes { access, modify };
        let path = match pathname {
            None => {
                if dirfd == litebox_common_linux::AT_FDCWD {
                    return Err(Errno::EFAULT);
                }
                if !flags.is_empty() {
                    return Err(Errno::EINVAL);
                }
                return self.set_fd_times(dirfd, &times);
            }
            Some(path) => path.to_cstring::<Platform>().ok_or(Errno::EFAULT)?,
        };
        let path = path.to_str().map_err(|_| Errno::EINVAL)?;
        let path = match FsPath::new(dirfd, path)? {
            FsPath::Absolute { path } => LookupPath { dir: None, path },
            FsPath::Cwd if flags.contains(AtFlags::AT_EMPTY_PATH) => {
                let user = self.fs_context().acting_user();
                return Ok(self.global.litebox.set_cwd_times(
                    self.pending_cwd_child(),
                    user,
                    &times,
                )?);
            }
            FsPath::Fd(fd) if flags.contains(AtFlags::AT_EMPTY_PATH) => {
                return self.set_fd_times(fd, &times);
            }
            FsPath::Cwd | FsPath::Fd(_) => return Err(Errno::ENOENT),
            FsPath::FdRelative { fd, path } => self.lookup_relative(fd, path)?,
        };
        let user = self.fs_context().acting_user();
        // The broker only sets times by handle, so path forms first open an `O_PATH` handle.
        let flags = if flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW) {
            OFlags::PATH | OFlags::NOFOLLOW
        } else {
            OFlags::PATH
        };
        let file = self.open_from(path.anchor(self), &path.path, flags, Mode::empty())?;
        Ok(file.set_times(user, &times)?)
    }

    fn set_fd_times(&self, fd: i32, times: &SetFileTimes) -> Result<(), Errno> {
        let user = self.fs_context().acting_user();
        // XXX: the NULL-path form does not reject O_PATH fds (Linux: EBADF).
        self.with_typed_fd(fd, |fd| match fd.as_file() {
            Some(fd) => self
                .global
                .with_file(fd, |file| Ok(file.file().set_times(user, times)?)),
            None => Ok(()),
        })
    }

    /// Handle path-based `chown` and `fchownat`.
    pub(crate) fn sys_fchownat(
        &self,
        dirfd: i32,
        pathname: &str,
        owner: u32,
        group: u32,
        flags: AtFlags,
    ) -> Result<(), Errno> {
        let valid_flags = AtFlags::AT_SYMLINK_NOFOLLOW | AtFlags::AT_EMPTY_PATH;
        if flags.intersects(valid_flags.complement()) {
            return Err(Errno::EINVAL);
        }
        // The broker follows symlinks and cannot chown an open descriptor yet.
        if !flags.is_empty() {
            log_unsupported!("fchownat flags: {flags:?}");
            return Err(Errno::ENOSYS);
        }
        let to_id = |id| {
            if id == u32::MAX {
                Ok(None)
            } else {
                u16::try_from(id).map(Some).map_err(|_| Errno::EINVAL)
            }
        };
        let owner = to_id(owner)?;
        let group = to_id(group)?;
        let path = self.lookup_path_at(dirfd, pathname)?;
        let context = self.fs_context();
        self.global
            .litebox
            .chown_file(&context, path.anchor(self), &path.path, owner, group)
            .map_err(Errno::from)
    }

    /// Handle syscall `ftruncate`
    pub(crate) fn sys_ftruncate(&self, fd: i32, length: usize) -> Result<(), Errno> {
        let files = self.files.borrow();
        let fd = files.typed_fd(fd)?;
        fd.dispatch(
            |fd| self.global.with_file(fd, |file| file.truncate(length)),
            |_fd| todo!("net"),
            |_fd| todo!("pipes"),
            |_fd| Err(Errno::EINVAL),
            |_fd| Err(Errno::EINVAL),
            |_fd| Err(Errno::EINVAL),
            |_fd| Err(Errno::EINVAL),
            |_fd| Err(Errno::EINVAL),
            |_fd| Err(Errno::EINVAL),
        )
    }

    /// Handle syscall `mknodat` — create a filesystem node.
    pub(crate) fn sys_mknodat(
        &self,
        dirfd: i32,
        pathname: &str,
        mode_and_type: u32,
        _dev: u32,
    ) -> Result<(), Errno> {
        const FILE_TYPE_MASK: u32 = 0o170000;

        let file_type = mode_and_type & FILE_TYPE_MASK;
        let file_type = if file_type == 0 {
            // zero translates to S_IFREG
            InodeType::File
        } else {
            InodeType::try_from(file_type).map_err(|_| Errno::EINVAL)?
        };
        match file_type {
            InodeType::File => {
                let mode = Mode::from_u32_bits_truncate(mode_and_type & !FILE_TYPE_MASK);
                drop(self.do_openat(
                    dirfd,
                    pathname,
                    OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                    mode,
                )?);
            }
            // TODO: Named pipe, socket, block and char files are not supported
            InodeType::NamedPipe
            | InodeType::Socket
            | InodeType::BlockDevice
            | InodeType::CharDevice
            | InodeType::Dir => return Err(Errno::EPERM),
            InodeType::SymLink => return Err(Errno::EINVAL),
        }
        Ok(())
    }

    /// Handle syscalls `rename`, `renameat`, and `renameat2`.
    pub(crate) fn sys_renameat2(
        &self,
        olddirfd: i32,
        oldpath: &str,
        newdirfd: i32,
        newpath: &str,
        flags: u32,
    ) -> Result<(), Errno> {
        if flags != 0 {
            // EINVAL is what Linux returns for flags the filesystem does not support, so callers
            // (e.g., `mv` with `RENAME_NOREPLACE`) can fall back to plain `rename`.
            litebox_util_log::warn!(
                "renameat2 flags {flags:#x} are not implemented yet; returning EINVAL"
            );
            return Err(Errno::EINVAL);
        }
        let oldpath = self.lookup_path_at(olddirfd, oldpath)?;
        let newpath = self.lookup_path_at(newdirfd, newpath)?;
        let context = self.fs_context();
        self.global
            .litebox
            .rename_file(
                &context,
                oldpath.anchor(self),
                &oldpath.path,
                newpath.anchor(self),
                &newpath.path,
            )
            .map_err(Errno::from)
    }

    /// Handle syscall `unlinkat`
    pub(crate) fn sys_unlinkat(
        &self,
        dirfd: i32,
        pathname: &str,
        flags: AtFlags,
    ) -> Result<(), Errno> {
        if flags.intersects(AtFlags::AT_REMOVEDIR.complement()) {
            return Err(Errno::EINVAL);
        }

        let path = self.lookup_path_at(dirfd, pathname)?;
        let context = self.fs_context();
        if flags.contains(AtFlags::AT_REMOVEDIR) {
            self.global
                .litebox
                .rmdir_file(&context, path.anchor(self), &path.path)
                .map_err(Errno::from)
        } else {
            self.global
                .litebox
                .unlink_file(&context, path.anchor(self), &path.path)
                .map_err(Errno::from)
        }
    }

    /// Handle syscall `read`
    ///
    /// `offset` is an optional offset to read from. If `None`, it will read from the current file position.
    /// If `Some`, it will read from the specified offset without changing the current file position.
    pub fn sys_read(
        &self,
        fd: i32,
        buf: impl ReadBuffer,
        offset: Option<usize>,
    ) -> Result<usize, Errno> {
        let fd = self.typed_fd(fd)?;
        self.do_read(&fd, buf, offset)
    }

    pub(crate) fn do_read(
        &self,
        fd: &AnyTypedFd<Platform>,
        buf: impl ReadBuffer,
        offset: Option<usize>,
    ) -> Result<usize, Errno> {
        // We need to do this cell dance because otherwise Rust can't recognize that the two
        // closures are mutually exclusive.
        let buf = core::cell::RefCell::new(buf);
        let result = fd.dispatch(
            |fd| {
                self.global.with_file(fd, |file| {
                    file.read(&mut *buf.borrow_mut(), offset, Some(&self.wait_cx()))
                })
            },
            |fd| {
                espipe_for_non_seekable_offset(offset)?;
                self.global.with_inet_socket(fd, |socket| {
                    let mut buf = buf.borrow_mut();
                    if buf.is_empty() {
                        return Ok(0);
                    }
                    let received = socket.receive(
                        &self.wait_cx(),
                        &mut *buf,
                        litebox_common_linux::ReceiveFlags::empty(),
                        false,
                        None,
                    )?;
                    Ok(received.min(buf.len()))
                })
            },
            |fd| {
                espipe_for_non_seekable_offset(offset)?;
                self.global.with_pipe_end(fd, |pipe| {
                    pipe.read(&self.wait_cx(), &mut *buf.borrow_mut())
                })
            },
            |fd| {
                espipe_for_non_seekable_offset(offset)?;
                self.global.with_eventfd(fd, |file| {
                    let mut buf = buf.borrow_mut();
                    if buf.len() < size_of::<u64>() {
                        return Err(Errno::EINVAL);
                    }
                    let value = file.read(&self.wait_cx())?;
                    buf.copy_from_slice_at(0, &value.to_le_bytes())
                        .map_err(|Fault| Errno::EFAULT)?;
                    Ok(size_of::<u64>())
                })
            },
            |_fd| Err(Errno::EINVAL),
            |fd| {
                espipe_for_non_seekable_offset(offset)?;
                self.global.with_unix_socket(fd, |socket| {
                    socket.recvfrom(
                        &self.wait_cx(),
                        &mut *buf.borrow_mut(),
                        litebox_common_linux::ReceiveFlags::empty(),
                        None,
                        None,
                    )
                })
            },
            |fd| {
                espipe_for_non_seekable_offset(offset)?;
                self.global.with_timerfd(fd, |file| {
                    let mut buf = buf.borrow_mut();
                    if buf.len() < size_of::<u64>() {
                        return Err(Errno::EINVAL);
                    }
                    let expirations = file.read(&self.wait_cx())?;
                    buf.copy_from_slice_at(0, &expirations.to_ne_bytes())
                        .map_err(|Fault| Errno::EFAULT)?;
                    Ok(size_of::<u64>())
                })
            },
            |fd| {
                espipe_for_non_seekable_offset(offset)?;
                self.global.with_vsock_socket(fd, |socket| {
                    let mut buf = buf.borrow_mut();
                    if buf.is_empty() {
                        return Ok(0);
                    }
                    socket.receive(
                        &self.wait_cx(),
                        &mut *buf,
                        litebox_common_linux::ReceiveFlags::empty(),
                    )
                })
            },
            |_fd| {
                espipe_for_non_seekable_offset(offset)?;
                Err(Errno::EINVAL)
            },
        );
        // For datagrams, the returned size represents the actual size of the message,
        // which may be larger than the buffer size.
        result.map(|size| size.min(buf.borrow().len()))
    }

    /// Handle syscall `write`
    ///
    /// `offset` is an optional offset to write to. If `None`, it will write to the current file position.
    /// If `Some`, it will write to the specified offset without changing the current file position.
    pub fn sys_write(
        &self,
        fd: i32,
        buf: impl WriteBuffer,
        offset: Option<usize>,
    ) -> Result<usize, Errno> {
        let fd = self.typed_fd(fd)?;
        self.do_write(&fd, buf, offset)
    }

    pub(crate) fn do_write(
        &self,
        fd: &AnyTypedFd<Platform>,
        buf: impl WriteBuffer,
        offset: Option<usize>,
    ) -> Result<usize, Errno> {
        let is_message_oriented = core::cell::Cell::new(false);
        let result = fd.dispatch(
            |fd| {
                self.global
                    .with_file(fd, |file| file.write(&buf, offset, Some(&self.wait_cx())))
            },
            |fd| {
                espipe_for_non_seekable_offset(offset)?;
                self.global.with_inet_socket(fd, |socket| {
                    is_message_oriented.set(!socket.is_stream());
                    socket.sendto(
                        &self.wait_cx(),
                        &buf,
                        litebox_common_linux::SendFlags::empty(),
                        None,
                    )
                })
            },
            |fd| {
                espipe_for_non_seekable_offset(offset)?;
                self.global
                    .with_pipe_end(fd, |pipe| pipe.write(&self.wait_cx(), &buf))
            },
            |fd| {
                espipe_for_non_seekable_offset(offset)?;
                self.global.with_eventfd(fd, |file| {
                    if buf.len() < size_of::<u64>() {
                        return Err(Errno::EINVAL);
                    }
                    let mut value = [0; size_of::<u64>()];
                    buf.copy_to_slice_at(0, &mut value)
                        .map_err(|Fault| Errno::EFAULT)?;
                    file.write(&self.wait_cx(), u64::from_le_bytes(value))
                })
            },
            |_fd| Err(Errno::EINVAL),
            |fd| {
                espipe_for_non_seekable_offset(offset)?;
                self.global.with_unix_socket(fd, |socket| {
                    is_message_oriented.set(!socket.is_stream());
                    socket.sendto(
                        self,
                        &buf,
                        litebox_common_linux::SendFlags::empty(),
                        None,
                        &[],
                    )
                })
            },
            |_fd| Err(Errno::EINVAL),
            |fd| {
                espipe_for_non_seekable_offset(offset)?;
                self.global.with_vsock_socket(fd, |socket| {
                    socket.sendto(
                        &self.wait_cx(),
                        &buf,
                        litebox_common_linux::SendFlags::empty(),
                        false,
                    )
                })
            },
            |_fd| {
                espipe_for_non_seekable_offset(offset)?;
                Err(Errno::EINVAL)
            },
        );
        self.send_sigpipe_on_epipe(
            &result,
            is_message_oriented.get(),
            litebox_common_linux::SendFlags::empty(),
        );
        result
    }

    /// Handle syscall `pread64`
    pub fn sys_pread64(&self, fd: i32, buf: impl ReadBuffer, offset: i64) -> Result<usize, Errno> {
        let pos = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.sys_read(fd, buf, Some(pos))
    }

    /// Handle syscall `pwrite64`
    pub fn sys_pwrite64(
        &self,
        fd: i32,
        buf: impl WriteBuffer,
        offset: i64,
    ) -> Result<usize, Errno> {
        let pos = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.sys_write(fd, buf, Some(pos))
    }

    fn rewind_sendfile_in_fd(
        &self,
        in_fd: &AnyTypedFd<Platform>,
        unread_n: usize,
    ) -> Result<(), Errno> {
        if unread_n == 0 {
            return Ok(());
        }

        let rewind = isize::try_from(unread_n).map_err(|_| Errno::EOVERFLOW)?;
        let fd = in_fd.file_only(Errno::EINVAL)?;
        let file = self
            .global
            .with_file(fd, |file| Ok(Arc::clone(file.file())))?;
        file.seek(-rewind, SeekWhence::RelativeToCurrentOffset)?;
        Ok(())
    }

    /// Handle syscall `sendfile`
    pub(crate) fn sys_sendfile(
        &self,
        out_fd: i32,
        in_fd: i32,
        offset_ptr: Option<UserPtrMut<i64>>,
        count: usize,
    ) -> Result<usize, Errno> {
        let typed_in_fd = self.typed_fd(in_fd)?;
        let typed_out_fd = self.typed_fd(out_fd)?;

        // TODO: Linux rejects `sendfile` with `EINVAL` when `out_fd` has `O_APPEND` set.
        let mut cur_off = offset_ptr
            .map(|p| {
                let off = p.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                if off < 0 {
                    return Err(Errno::EINVAL);
                }
                usize::try_from(off).map_err(|_| Errno::EINVAL)
            })
            .transpose()?;
        let mut kernel_buf = vec![0u8; count.min(PAGE_SIZE)];
        let mut total: usize = 0;

        while total < count {
            let to_read = (count - total).min(kernel_buf.len());

            // Non-FS sources are not seekable; Linux returns ESPIPE for any
            // non-pread-capable source when an offset is supplied, EINVAL otherwise.
            let non_fs_err = if cur_off.is_some() {
                Errno::ESPIPE
            } else {
                Errno::EINVAL
            };
            let read_result = match typed_in_fd.as_file() {
                Some(fd) => self.global.with_file(fd, |file| {
                    file.read(&mut kernel_buf[..to_read], cur_off, Some(&self.wait_cx()))
                }),
                None => Err(non_fs_err),
            };
            let read_n = match read_result {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if total == 0 => return Err(e),
                Err(_) => break,
            };

            let write_result = self.do_write(&typed_out_fd, &kernel_buf[..read_n], None);
            let write_n = match write_result {
                Ok(n) => n,
                Err(e) => {
                    if offset_ptr.is_none() {
                        self.rewind_sendfile_in_fd(&typed_in_fd, read_n)?;
                    }
                    if total == 0 {
                        return Err(e);
                    }
                    break;
                }
            };

            total += write_n;
            if let Some(ref mut off) = cur_off {
                *off = off.checked_add(write_n).ok_or(Errno::EOVERFLOW)?;
            }
            if write_n < read_n {
                if offset_ptr.is_none() {
                    self.rewind_sendfile_in_fd(&typed_in_fd, read_n - write_n)?;
                }
                break;
            }
        }

        if let (Some(p), Some(off)) = (offset_ptr, cur_off) {
            let off = i64::try_from(off).map_err(|_| Errno::EOVERFLOW)?;
            p.write_at_offset::<Platform>(0, off).ok_or(Errno::EFAULT)?;
        }

        Ok(total)
    }
}

fn espipe_for_non_seekable_offset(offset: Option<usize>) -> Result<(), Errno> {
    if offset.is_some() {
        Err(Errno::ESPIPE)
    } else {
        Ok(())
    }
}

const SEEK_SET: i16 = 0;
const SEEK_CUR: i16 = 1;
const SEEK_END: i16 = 2;

pub(crate) fn try_into_whence(value: i16) -> Result<SeekWhence, i16> {
    match value {
        SEEK_SET => Ok(SeekWhence::RelativeToBeginning),
        SEEK_CUR => Ok(SeekWhence::RelativeToCurrentOffset),
        SEEK_END => Ok(SeekWhence::RelativeToEnd),
        _ => Err(value),
    }
}

impl<Platform: ShimPlatform> Task<Platform> {
    /// Handle syscall `lseek`
    pub fn sys_lseek(&self, fd: i32, offset: isize, whence: SeekWhence) -> Result<usize, Errno> {
        let fd = self.typed_fd(fd)?;
        self.do_seek(&fd, offset, whence)
    }

    pub(crate) fn do_seek(
        &self,
        fd: &AnyTypedFd<Platform>,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, Errno> {
        let fd = fd.file_only(Errno::ESPIPE)?;
        let file = self
            .global
            .with_file(fd, |file| Ok(Arc::clone(file.file())))?;
        Ok(file.seek(offset, whence)?)
    }

    fn do_mkdir(&self, lookup: LookupPath<Platform>, mode: Mode) -> Result<(), Errno> {
        let mode = mode & !self.get_umask();
        let context = self.fs_context();
        self.global
            .litebox
            .mkdir_file(&context, lookup.anchor(self), &lookup.path, mode)
            .map_err(Errno::from)
    }

    /// Handle syscall `mkdirat`
    pub(crate) fn sys_mkdirat(&self, dirfd: i32, pathname: &str, mode: u32) -> Result<(), Errno> {
        let lookup = self.lookup_path_at(dirfd, pathname)?;
        self.do_mkdir(lookup, Mode::from_u32_bits_truncate(mode))
    }

    /// Handle syscall `mount` for a fresh tmpfs mount or a change of a mount's propagation type.
    pub(crate) fn sys_mount(
        &self,
        target: &str,
        filesystemtype: Option<&str>,
        flags: usize,
    ) -> Result<(), Errno> {
        // No set-ID exec or device nodes exist, so NOSUID/NODEV already hold; atime flags are advisory.
        const ACCEPTED_FLAGS: usize = (1 << 1) // MS_NOSUID
            | (1 << 2) // MS_NODEV
            | (1 << 10) // MS_NOATIME
            | (1 << 11) // MS_NODIRATIME
            | (1 << 15) // MS_SILENT
            | (1 << 21) // MS_RELATIME
            | (1 << 24) // MS_STRICTATIME
            | (1 << 25); // MS_LAZYTIME
        const MS_REC: usize = 1 << 14;
        const MS_SILENT: usize = 1 << 15;
        const MS_UNBINDABLE: usize = 1 << 17;
        const MS_PRIVATE: usize = 1 << 18;
        const MS_SLAVE: usize = 1 << 19;
        const MS_SHARED: usize = 1 << 20;
        // Like Linux, a propagation flag, unless `MS_REMOUNT` or `MS_BIND` is also set (both
        // unsupported, so rejected below), makes this a change of the target's propagation type,
        // which ignores the file system type.
        if flags & (MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED) != 0 {
            self.sys_stat(target)?;
            self.check_admin()?;
            return match flags & !(MS_REC | MS_SILENT) {
                // Mount views never propagate mounts to each other, so every mount is private,
                // and Linux leaves a private mount private when asked to make it a slave.
                // XXX: Linux also fails if `target` is not a mount root, which the shim can't tell.
                MS_PRIVATE | MS_SLAVE => Ok(()),
                _ => {
                    log_unsupported!("mount flags {flags:#x}");
                    Err(Errno::EINVAL)
                }
            };
        }
        if flags & !ACCEPTED_FLAGS != 0 {
            log_unsupported!("mount flags {flags:#x}");
            return Err(Errno::EINVAL);
        }
        // Like Linux, a new mount needs a file system type.
        let filesystemtype = filesystemtype.ok_or(Errno::EINVAL)?;
        if filesystemtype != "tmpfs" {
            log_unsupported!("mount filesystem {filesystemtype}");
            return Err(Errno::ENODEV);
        }
        // Mounting is name-based, so a relative target is named from the cwd handle's current path.
        let target = self.absolute_name(target)?;
        let context = self.fs_context();
        self.global
            .litebox
            .mount_in_mem(&context, &target)
            .map_err(|error| {
                use litebox_broker_protocol::fs::FileError;
                match error {
                    FileError::NotOwner => Errno::EPERM,
                    FileError::AccessNotAllowed
                    | FileError::NoWritePermissions
                    | FileError::NoSearchPermissions => Errno::EACCES,
                    FileError::NoSuchFileOrDirectory | FileError::MissingComponent => Errno::ENOENT,
                    FileError::NotDirectory | FileError::ComponentNotDirectory => Errno::ENOTDIR,
                    FileError::InvalidPathname | FileError::InvalidArgument => Errno::EINVAL,
                    FileError::TooManySymlinks => Errno::ELOOP,
                    FileError::Busy => Errno::EBUSY,
                    FileError::NoSpace => Errno::ENOSPC,
                    FileError::NotSupported => Errno::EOPNOTSUPP,
                    _ => Errno::EIO,
                }
            })
    }

    pub(crate) fn do_close(&self, raw_fd: usize) -> Result<(), Errno> {
        let number = u32::try_from(raw_fd).map_err(|_| Errno::EBADF)?;
        let files = self.files.borrow().clone();
        let mutation = files.mutation();
        let FdResponse::Changed(revision) = self.fd_request(FdOperation::Close(number))? else {
            return Err(Errno::EIO);
        };
        self.finalize_closed(mutation.remove(number, number, revision));
        Ok(())
    }

    /// Handle syscall `close`
    pub(crate) fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        let raw_fd = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        // Like Linux, an interrupted close does not restart: the descriptor is already gone.
        self.do_close(raw_fd).map_err(Errno::without_restart)
    }

    /// Handle syscall `close_range`.
    ///
    /// Like Linux, failures closing individual descriptors are not reported.
    pub(crate) fn sys_close_range(
        &self,
        first: u32,
        last: u32,
        flags: CloseRangeFlags,
    ) -> Result<(), Errno> {
        if first > last || flags.intersects(!(CloseRangeFlags::UNSHARE | CloseRangeFlags::CLOEXEC))
        {
            return Err(Errno::EINVAL);
        }
        if flags.contains(CloseRangeFlags::UNSHARE) {
            log_unsupported!("close_range with CLOSE_RANGE_UNSHARE");
            return Err(Errno::EINVAL);
        }
        let files = self.files.borrow().clone();
        let mutation = files.mutation();
        let cloexec = flags.contains(CloseRangeFlags::CLOEXEC);
        let FdResponse::Changed(revision) = self.fd_request(FdOperation::CloseRange {
            first,
            last,
            cloexec,
        })?
        else {
            return Err(Errno::EIO);
        };
        if !cloexec {
            self.finalize_closed(mutation.remove(first, last, revision));
        }
        Ok(())
    }

    /// Resolve a userland fd number into the subsystem that owns it.
    pub(crate) fn typed_fd(&self, fd: i32) -> Result<AnyTypedFd<Platform>, Errno> {
        self.files.borrow().typed_fd(fd)
    }

    pub(crate) fn with_typed_fd<R>(
        &self,
        fd: i32,
        f: impl FnOnce(&AnyTypedFd<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        f(&self.typed_fd(fd)?)
    }

    /// Handle syscall `preadv`
    pub(crate) fn sys_preadv(
        &self,
        fd: i32,
        iovec: UserPtr<IoReadVec>,
        iovcnt: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        let offset = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.readv_at(fd, iovec, iovcnt, Some(offset))
    }

    /// Handle syscall `pwritev`
    pub(crate) fn sys_pwritev(
        &self,
        fd: i32,
        iovec: UserPtr<IoWriteVec>,
        iovcnt: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        let offset = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        // TODO: Linux ignores pwritev's offset for O_APPEND files; see the O_APPEND bug documented in pwrite(2).
        self.writev_at(fd, iovec, iovcnt, Some(offset))
    }

    /// Handle syscall `readv`
    pub(crate) fn sys_readv(
        &self,
        fd: i32,
        iovec: UserPtr<IoReadVec>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        self.readv_at(fd, iovec, iovcnt, None)
    }

    /// Handle syscall `writev`
    pub(crate) fn sys_writev(
        &self,
        fd: i32,
        iovec: UserPtr<IoWriteVec>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        self.writev_at(fd, iovec, iovcnt, None)
    }

    /// Reads into the `iovcnt` iovecs at `iovec`, at `offset` if given.
    fn readv_at(
        &self,
        fd: i32,
        iovec: UserPtr<IoReadVec>,
        iovcnt: usize,
        offset: Option<usize>,
    ) -> Result<usize, Errno> {
        self.with_typed_fd(fd, |fd| {
            check_iovcnt(iovcnt)?;
            let iovs: &[IoReadVec] = &iovec
                .to_owned_slice::<Platform>(iovcnt)
                .ok_or(Errno::EFAULT)?;
            let buf = GuestReadBuffer::<Platform>::new(iovs)?;
            // Like Linux, an empty vector reads nothing without reaching the file.
            if buf.is_empty() {
                return Ok(0);
            }
            self.do_read(fd, buf, offset)
        })
    }

    /// Writes from the `iovcnt` iovecs at `iovec`, at `offset` if given.
    fn writev_at(
        &self,
        fd: i32,
        iovec: UserPtr<IoWriteVec>,
        iovcnt: usize,
        offset: Option<usize>,
    ) -> Result<usize, Errno> {
        self.with_typed_fd(fd, |fd| {
            check_iovcnt(iovcnt)?;
            let iovs: &[IoWriteVec] = &iovec
                .to_owned_slice::<Platform>(iovcnt)
                .ok_or(Errno::EFAULT)?;
            let buf = GuestWriteBuffer::<Platform>::new(iovs)?;
            // Like Linux, an empty vector writes nothing without reaching the file.
            if buf.is_empty() {
                return Ok(0);
            }
            if !matches!(fd, AnyTypedFd::Eventfd(_)) {
                return self.do_write(fd, buf, offset);
            }
            // Like Linux, an eventfd, which has no vectored write, writes each iovec separately,
            // stopping at a short write and failing only if nothing was written.
            let mut written = 0;
            for iov in iovs.iter().filter(|iov| iov.iov_len != 0) {
                let iov_offset = offset.map(|offset| offset + written);
                match self.do_write(fd, GuestWriteBuffer::<Platform>::single(iov), iov_offset) {
                    Ok(size) => {
                        written += size;
                        if size < iov.iov_len {
                            break;
                        }
                    }
                    Err(_) if written != 0 => break,
                    Err(error) => return Err(error),
                }
            }
            Ok(written)
        })
    }
}

/// Linux's `IOV_MAX` / `UIO_MAXIOV`: the kernel rejects iovec counts above this
/// with `EINVAL` for `readv`/`writev`/`preadv`/`pwritev`.
const IOV_MAX: usize = 1024;

fn check_iovcnt(iovcnt: usize) -> Result<(), Errno> {
    if iovcnt > IOV_MAX {
        Err(Errno::EINVAL)
    } else {
        Ok(())
    }
}

impl<Platform: ShimPlatform> Task<Platform> {
    fn validate_access_mode(mode: &AccessFlags) -> Result<(), Errno> {
        let valid_mode = AccessFlags::R_OK | AccessFlags::W_OK | AccessFlags::X_OK;
        if mode.intersects(valid_mode.complement()) {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    fn do_access_mode(
        mode: Mode,
        owner: AccessUserInfo,
        caller: AccessUserInfo,
        access_mode: &AccessFlags,
    ) -> Result<(), Errno> {
        if access_mode.is_empty() {
            return Ok(());
        }
        if caller.user == 0 {
            if access_mode.contains(AccessFlags::X_OK)
                && !mode.intersects(Mode::XUSR | Mode::XGRP | Mode::XOTH)
            {
                return Err(Errno::EACCES);
            }
            return Ok(());
        }
        // TODO: Linux also uses group bits when `owner.group` is in the caller's supplementary
        // group list. `AccessUserInfo` only carries the real/effective primary group today.
        let (read, write, execute) = if caller.user == owner.user {
            (Mode::RUSR, Mode::WUSR, Mode::XUSR)
        } else if caller.group == owner.group {
            (Mode::RGRP, Mode::WGRP, Mode::XGRP)
        } else {
            (Mode::ROTH, Mode::WOTH, Mode::XOTH)
        };
        if access_mode.contains(AccessFlags::R_OK) && !mode.contains(read) {
            return Err(Errno::EACCES);
        }
        if access_mode.contains(AccessFlags::W_OK) && !mode.contains(write) {
            return Err(Errno::EACCES);
        }
        if access_mode.contains(AccessFlags::X_OK) && !mode.contains(execute) {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    fn access_user(&self, flags: &AtFlags) -> AccessUserInfo {
        if flags.contains(AtFlags::AT_EACCESS) {
            AccessUserInfo {
                user: self.credentials.euid,
                group: self.credentials.egid,
            }
        } else {
            AccessUserInfo {
                user: self.credentials.uid,
                group: self.credentials.gid,
            }
        }
    }

    fn do_access(
        &self,
        dir: DirectoryAnchor<'_, Platform>,
        pathname: &str,
        mode: AccessFlags,
        caller: AccessUserInfo,
        follow_symlink: bool,
    ) -> Result<(), Errno> {
        let status = self.global.litebox.path_file_status(
            &self.fs_context(),
            dir,
            pathname,
            follow_symlink,
        )?;
        let owner = status.owner.into();
        Self::do_access_mode(status.mode, owner, caller, &mode)
    }

    /// Handle syscall `faccessat`
    pub(crate) fn sys_faccessat(
        &self,
        dirfd: i32,
        pathname: &str,
        mode: AccessFlags,
        flags: AtFlags,
    ) -> Result<(), Errno> {
        let supported_flags =
            AtFlags::AT_EACCESS | AtFlags::AT_SYMLINK_NOFOLLOW | AtFlags::AT_EMPTY_PATH;
        if flags.intersects(supported_flags.complement()) {
            return Err(Errno::EINVAL);
        }

        Self::validate_access_mode(&mode)?;
        let caller = self.access_user(&flags);
        let follow_symlink = !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW);
        let fs_path = FsPath::new(dirfd, pathname)?;
        match fs_path {
            FsPath::Absolute { path } => {
                self.do_access(DirectoryAnchor::None, &path, mode, caller, follow_symlink)
            }
            FsPath::Cwd if flags.contains(AtFlags::AT_EMPTY_PATH) => {
                let status = self.global.litebox.cwd_status(self.pending_cwd_child())?;
                Self::do_access_mode(status.mode, status.owner.into(), caller, &mode)
            }
            FsPath::Fd(fd) if flags.contains(AtFlags::AT_EMPTY_PATH) => {
                let typed_fd = self.typed_fd(fd)?;
                if let Some(file) = typed_fd.as_file() {
                    let status = self.global.with_file(file, File::status)?;
                    return Self::do_access_mode(status.mode, status.owner.into(), caller, &mode);
                }
                let stat: FileStat = self.do_stat(&typed_fd)?;
                let owner = AccessUserInfo {
                    user: stat.st_uid,
                    group: stat.st_gid,
                };
                Self::do_access_mode(
                    Mode::from_u32_bits_truncate(stat.st_mode & 0o7777),
                    owner,
                    caller,
                    &mode,
                )
            }
            FsPath::Cwd | FsPath::Fd(_) => Err(Errno::ENOENT),
            FsPath::FdRelative { fd, path } => {
                let path = self.lookup_relative(fd, path)?;
                self.do_access(path.anchor(self), &path.path, mode, caller, follow_symlink)
            }
        }
    }

    /// The open descriptor named by a `/proc/self/fd/<fd>` path, or `None` for any other path.
    ///
    /// Like Linux, a name that is not an open descriptor fails with `ENOENT`.
    // XXX(jayb): `/proc/self/fd/<fd>` should be backed by the file system rather than handled here.
    fn proc_self_fd(&self, path: &str) -> Option<Result<AnyTypedFd<Platform>, Errno>> {
        let name = path.strip_prefix("/proc/self/fd/")?;
        Some(
            name.bytes()
                .all(|byte| byte.is_ascii_digit())
                .then(|| name.parse::<i32>().ok())
                .flatten()
                .and_then(|fd| self.typed_fd(fd).ok())
                .ok_or(Errno::ENOENT),
        )
    }

    /// Read the target of a symbolic link. A relative `path` resolves from `dir`.
    fn do_readlink(&self, dir: DirectoryAnchor<'_, Platform>, path: &str) -> Result<String, Errno> {
        if let Some(fd) = self.proc_self_fd(path) {
            // Like Linux, a non-file descriptor names its kind; the inode numbers match `fstat`.
            // XXX: a removed directory fails with ENOENT; Linux names it "<path> (deleted)".
            return fd?.dispatch(
                |fd| self.global.with_file(fd, File::path),
                |_fd| Ok("socket:[0]".into()),
                |_fd| Ok("pipe:[0]".into()),
                |_fd| Ok("anon_inode:[eventfd]".into()),
                |_fd| Ok("anon_inode:[eventpoll]".into()),
                |_fd| Ok("socket:[0]".into()),
                |_fd| Ok("anon_inode:[timerfd]".into()),
                |_fd| Ok("socket:[0]".into()),
                |_fd| Ok("anon_inode:[pidfd]".into()),
            );
        }

        let context = self.fs_context();
        Ok(self.global.litebox.read_link_file(&context, dir, path)?)
    }

    /// Handle syscall `readlink`
    pub fn sys_readlink(&self, pathname: &str, buf: &mut [u8]) -> Result<usize, Errno> {
        self.sys_readlinkat(litebox_common_linux::AT_FDCWD, pathname, buf)
    }

    /// Handle syscall `readlinkat`
    pub fn sys_readlinkat(
        &self,
        dirfd: i32,
        pathname: &str,
        buf: &mut [u8],
    ) -> Result<usize, Errno> {
        let pathname = self.absolutize_proc_self_fd(self.lookup_path_at(dirfd, pathname)?);
        let path = self.do_readlink(pathname.anchor(self), &pathname.path)?;
        let bytes = path.as_bytes();
        let min_len = core::cmp::min(buf.len(), bytes.len());
        buf[..min_len].copy_from_slice(&bytes[..min_len]);
        Ok(min_len)
    }
}

impl<Platform: ShimPlatform> Task<Platform> {
    pub(crate) fn do_stat<T>(&self, fd: &AnyTypedFd<Platform>) -> Result<T, Errno>
    where
        T: TryFrom<FileStatus, Error = Errno> + From<FileStat>,
    {
        // TODO: give correct values for the synthesized branches.
        let synthetic = |mode_bits: u32, blksize: usize| FileStat {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 1,
            st_mode: mode_bits.trunc(),
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            st_size: 0,
            #[cfg(target_arch = "x86_64")]
            st_blksize: blksize,
            #[cfg(target_arch = "aarch64")]
            st_blksize: {
                // The asm-generic ABI uses signed `st_blksize`.
                let blksize: u32 = blksize.trunc();
                blksize.reinterpret_as_signed()
            },
            st_blocks: 0,
            ..Default::default()
        };
        let socket_mode = litebox_common_linux::InodeType::Socket as u32
            | u32::from((Mode::RWXU | Mode::RWXG | Mode::RWXO).bits());
        let rw_user_mode = u32::from((Mode::RUSR | Mode::WUSR).bits());
        fd.dispatch(
            |fd| T::try_from(self.global.with_file(fd, File::status)?),
            |_fd| Ok(T::from(synthetic(socket_mode, 4096))),
            |fd| {
                let mode_bits = self.global.with_pipe_end(fd, |pipe| Ok(pipe.mode_bits()))?;
                Ok(T::from(synthetic(mode_bits, 4096)))
            },
            |_fd| Ok(T::from(synthetic(rw_user_mode, 4096))),
            |_fd| Ok(T::from(synthetic(rw_user_mode, 0))),
            |_fd| Ok(T::from(synthetic(socket_mode, 4096))),
            |_fd| Ok(T::from(synthetic(rw_user_mode, 4096))),
            |_fd| Ok(T::from(synthetic(socket_mode, 4096))),
            |_fd| Ok(T::from(synthetic(rw_user_mode, 4096))),
        )
    }

    /// Get the file status of `pathname`. A relative `pathname` resolves from `dir`.
    fn do_path_stat<T>(
        &self,
        dir: DirectoryAnchor<'_, Platform>,
        pathname: &str,
        follow_symlink: bool,
    ) -> Result<T, Errno>
    where
        T: TryFrom<FileStatus, Error = Errno> + From<FileStat>,
    {
        // The shim, not the file system, serves `/proc/self/fd/<fd>`; following it reaches the open
        // descriptor itself.
        if follow_symlink && let Some(fd) = self.proc_self_fd(pathname) {
            return self.do_stat(&fd?);
        }
        let status = self.global.litebox.path_file_status(
            &self.fs_context(),
            dir,
            pathname,
            follow_symlink,
        )?;
        T::try_from(status)
    }

    /// Handle syscall `stat`
    pub fn sys_stat(&self, pathname: &str) -> Result<FileStat, Errno> {
        self.do_fstatat(litebox_common_linux::AT_FDCWD, pathname, AtFlags::empty())
    }

    /// Handle syscall `lstat`
    ///
    /// `lstat` is identical to `stat`, except that if `pathname` is a symbolic link,
    /// then it returns information about the link itself, not the file that the link refers to.
    pub fn sys_lstat(&self, pathname: &str) -> Result<FileStat, Errno> {
        self.do_fstatat(
            litebox_common_linux::AT_FDCWD,
            pathname,
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
    }

    /// Handle syscall `fstat`
    pub fn sys_fstat(&self, fd: i32) -> Result<FileStat, Errno> {
        self.with_typed_fd(fd, |fd| self.do_stat(fd))
    }

    /// Handle syscall `statfs`.
    pub(crate) fn sys_statfs(&self, pathname: &str) -> Result<litebox_common_linux::Statfs, Errno> {
        self.sys_stat(pathname)?;
        Ok(FAKE_STATFS)
    }

    /// Handle syscall `fstatfs`.
    pub(crate) fn sys_fstatfs(&self, fd: i32) -> Result<litebox_common_linux::Statfs, Errno> {
        self.sys_fstat(fd)?;
        Ok(FAKE_STATFS)
    }

    fn do_fstatat<T>(&self, dirfd: i32, pathname: &str, flags: AtFlags) -> Result<T, Errno>
    where
        T: TryFrom<FileStatus, Error = Errno> + From<FileStat>,
    {
        let follow_symlink = !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW);
        let fs_path = FsPath::new(dirfd, pathname)?;
        match fs_path {
            FsPath::Absolute { path } => {
                self.do_path_stat(DirectoryAnchor::None, &path, follow_symlink)
            }
            FsPath::Cwd if flags.contains(AtFlags::AT_EMPTY_PATH) => {
                T::try_from(self.global.litebox.cwd_status(self.pending_cwd_child())?)
            }
            FsPath::Fd(fd) if flags.contains(AtFlags::AT_EMPTY_PATH) => {
                self.with_typed_fd(fd, |fd| self.do_stat(fd))
            }
            FsPath::Cwd | FsPath::Fd(_) => Err(Errno::ENOENT),
            FsPath::FdRelative { fd, path } => {
                let path = self.absolutize_proc_self_fd(self.lookup_relative(fd, path)?);
                self.do_path_stat(path.anchor(self), &path.path, follow_symlink)
            }
        }
    }

    /// Handle syscall `newfstatat`
    pub(crate) fn sys_newfstatat(
        &self,
        dirfd: i32,
        pathname: &str,
        flags: AtFlags,
    ) -> Result<FileStat, Errno> {
        let current_support_flags = AtFlags::AT_EMPTY_PATH | AtFlags::AT_SYMLINK_NOFOLLOW;
        if flags.intersects(current_support_flags.complement()) {
            log_unsupported!("unsupported flags: {flags:?}");
            return Err(Errno::EINVAL);
        }

        self.do_fstatat(dirfd, pathname, flags)
    }

    /// Handle syscall `statx`
    pub(crate) fn sys_statx(
        &self,
        dirfd: i32,
        pathname: &str,
        flags: AtFlags,
        mask: StatxMask,
    ) -> Result<Statx, Errno> {
        if mask.contains(StatxMask::STATX__RESERVED) {
            return Err(Errno::EINVAL);
        }
        // `AT_NO_AUTOMOUNT` and the `AT_STATX_*` sync
        // hints are accepted as no-ops since LiteBox filesystems
        // do not automount or sync to a remote.
        let allowed = AtFlags::AT_EMPTY_PATH
            | AtFlags::AT_NO_AUTOMOUNT
            | AtFlags::AT_SYMLINK_NOFOLLOW
            | AtFlags::AT_STATX_FORCE_SYNC
            | AtFlags::AT_STATX_DONT_SYNC;
        if flags.intersects(allowed.complement()) {
            log_unsupported!("unsupported statx flags: {flags:?}");
            return Err(Errno::EINVAL);
        }
        if flags.contains(AtFlags::AT_STATX_FORCE_SYNC | AtFlags::AT_STATX_DONT_SYNC) {
            return Err(Errno::EINVAL);
        }

        // `mask` is informational past this point: the underlying FS doesn't
        // support field selection, so we always fill the basic stats and
        // report the actual filled set via `Statx::stx_mask`. Matches Linux's
        // documented behavior of returning more than what was asked.
        self.do_fstatat(dirfd, pathname, flags)
    }

    pub(crate) fn sys_flock(&self, fd: i32, operation: i32) -> Result<(), Errno> {
        const LOCK_SH: i32 = 1;
        const LOCK_EX: i32 = 2;
        const LOCK_NB: i32 = 4;
        const LOCK_UN: i32 = 8;
        const LOCK_MAND: i32 = 32;

        if operation & LOCK_MAND != 0 {
            log_unsupported!("flock LOCK_MAND ignored");
            return Ok(());
        }
        let lock = match operation & !LOCK_NB {
            LOCK_SH => FileLockOperation::Shared,
            LOCK_EX => FileLockOperation::Exclusive,
            LOCK_UN => FileLockOperation::Unlock,
            _ => return Err(Errno::EINVAL),
        };
        let fd = self.typed_fd(fd)?;
        let Some(file_fd) = fd.as_file() else {
            log_unsupported!("flock on a non-file descriptor ignored");
            return Ok(());
        };
        let cx = self.wait_cx();
        debug_assert!(
            cx.deadline().is_none(),
            "flock waits must not have a deadline"
        );
        loop {
            match file_fd.file.try_lock(lock) {
                Err(LockError::WouldBlock) if operation & LOCK_NB == 0 => {}
                result => return Ok(result?),
            }
            // XXX: flock waits poll every 10ms; replace with broker lock-release readiness
            // (latency, fairness).
            match cx
                .with_timeout(core::time::Duration::from_millis(10))
                .sleep()
            {
                WaitError::TimedOut => {}
                WaitError::Interrupted => return Err(Errno::ERESTARTSYS),
            }
        }
    }

    pub(crate) fn sys_fcntl(&self, fd: i32, arg: FcntlArg) -> Result<u32, Errno> {
        let number = u32::try_from(fd).map_err(|_| Errno::EBADF)?;
        match arg {
            FcntlArg::GETFD => {
                // XXX: Cache close-on-exec in the fd cache so F_GETFD needs no broker call.
                return match self.fd_request(FdOperation::GetCloexec(number))? {
                    FdResponse::Cloexec(true) => Ok(FileDescriptorFlags::FD_CLOEXEC.bits()),
                    FdResponse::Cloexec(false) => Ok(0),
                    _ => Err(Errno::EIO),
                };
            }
            FcntlArg::SETFD(flags) => {
                return self.set_cloexec(number, flags.contains(FileDescriptorFlags::FD_CLOEXEC));
            }
            FcntlArg::DUPFD { cloexec, min_fd } => {
                return self.duplicate_fd(number, DupTarget::AtLeast(min_fd), cloexec);
            }
            _ => {}
        }
        let fd = self.typed_fd(fd)?;
        match arg {
            FcntlArg::GETFL => Ok(fd
                .dispatch(
                    |fd| self.global.with_file(fd, File::get_status_flags),
                    |fd| {
                        self.global
                            .with_inet_socket(fd, super::inet::InetSocket::get_status_flags)
                    },
                    |fd| {
                        self.global
                            .with_pipe_end(fd, super::pipe::PipeEnd::get_status_flags)
                    },
                    |fd| {
                        self.global
                            .with_eventfd(fd, super::eventfd::EventFile::get_status_flags)
                    },
                    |fd| {
                        self.global
                            .with_epoll(fd, super::epoll::EpollFile::get_status_flags)
                    },
                    |fd| {
                        self.global
                            .with_unix_socket(fd, super::unix::UnixSocket::get_status_flags)
                    },
                    |fd| {
                        self.global
                            .with_timerfd(fd, super::timerfd::TimerFile::get_status_flags)
                    },
                    |fd| {
                        self.global
                            .with_vsock_socket(fd, super::vsock::VsockSocket::get_status_flags)
                    },
                    |fd| {
                        self.global
                            .with_pidfd(fd, super::pidfd::PidFile::get_status_flags)
                    },
                )?
                .bits()),
            FcntlArg::SETFL(flags) => {
                let setfl_mask = OFlags::APPEND
                    | OFlags::NONBLOCK
                    | OFlags::NDELAY
                    | OFlags::DIRECT
                    | OFlags::NOATIME;
                let flags = flags & setfl_mask;
                fd.dispatch(
                    |fd| {
                        if flags.intersects(OFlags::DIRECT | OFlags::NOATIME) {
                            log_unsupported!("unsupported flags");
                        }
                        self.global
                            .with_file(fd, |file| file.set_status_flags(setfl_mask, flags))
                    },
                    |fd| {
                        if flags.intersects(OFlags::DIRECT | OFlags::NOATIME) {
                            log_unsupported!("unsupported flags");
                        }
                        self.global.with_inet_socket(fd, |socket| {
                            socket.set_status_flags(setfl_mask, flags)
                        })
                    },
                    |fd| {
                        if flags.intersects(OFlags::DIRECT | OFlags::NOATIME) {
                            log_unsupported!("unsupported flags");
                        }
                        self.global
                            .with_pipe_end(fd, |pipe| pipe.set_status_flags(setfl_mask, flags))
                    },
                    |fd| {
                        if flags.intersects(OFlags::DIRECT | OFlags::NOATIME) {
                            log_unsupported!("unsupported flags");
                        }
                        self.global
                            .with_eventfd(fd, |file| file.set_status_flags(setfl_mask, flags))
                    },
                    |fd| {
                        if flags.intersects(OFlags::DIRECT | OFlags::NOATIME) {
                            log_unsupported!("unsupported flags");
                        }
                        self.global
                            .with_epoll(fd, |file| file.set_status_flags(setfl_mask, flags))
                    },
                    |fd| {
                        if flags.intersects(OFlags::DIRECT | OFlags::NOATIME) {
                            log_unsupported!("unsupported flags");
                        }
                        self.global.with_unix_socket(fd, |socket| {
                            socket.set_status_flags(setfl_mask, flags)
                        })
                    },
                    |fd| {
                        if flags.intersects(OFlags::DIRECT | OFlags::NOATIME) {
                            log_unsupported!("unsupported flags");
                        }
                        self.global
                            .with_timerfd(fd, |file| file.set_status_flags(setfl_mask, flags))
                    },
                    |fd| {
                        if flags.intersects(OFlags::DIRECT | OFlags::NOATIME) {
                            log_unsupported!("unsupported flags");
                        }
                        self.global.with_vsock_socket(fd, |socket| {
                            socket.set_status_flags(setfl_mask, flags)
                        })
                    },
                    |fd| {
                        if flags.intersects(OFlags::DIRECT | OFlags::NOATIME) {
                            log_unsupported!("unsupported flags");
                        }
                        self.global
                            .with_pidfd(fd, |file| file.set_status_flags(setfl_mask, flags))
                    },
                )?;
                Ok(0)
            }
            FcntlArg::GETLK(lock) => {
                fd.dispatch(
                    |_fd| {
                        let mut flock = lock.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                        let lock_type = litebox_common_linux::FlockType::try_from(flock.type_)
                            .map_err(|_| Errno::EINVAL)?;
                        if let litebox_common_linux::FlockType::Unlock = lock_type {
                            return Err(Errno::EINVAL);
                        }

                        // Note LiteBox does not support multiple processes yet, and one process
                        // can always acquire the lock it owns, so return `Unlock` unconditionally.
                        flock.type_ = litebox_common_linux::FlockType::Unlock as i16;
                        lock.write_at_offset::<Platform>(0, flock)
                            .ok_or(Errno::EFAULT)?;
                        Ok(0)
                    },
                    |_fd| todo!("net"),
                    |_fd| todo!("pipes"),
                    |_fd| Err(Errno::EBADF),
                    |_fd| Err(Errno::EBADF),
                    |_fd| Err(Errno::EBADF),
                    |_fd| Err(Errno::EBADF),
                    |_fd| Err(Errno::EBADF),
                    |_fd| Err(Errno::EBADF),
                )
            }
            FcntlArg::SETLK(lock) | FcntlArg::SETLKW(lock) => {
                fd.dispatch(
                    |_fd| {
                        let flock = lock.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                        let _ = litebox_common_linux::FlockType::try_from(flock.type_)
                            .map_err(|_| Errno::EINVAL)?;

                        // Note LiteBox does not support multiple processes yet, and one process
                        // can always acquire the lock it owns, so we don't need to maintain anything.
                        Ok(0)
                    },
                    |_fd| todo!("net"),
                    |_fd| todo!("pipes"),
                    |_fd| Err(Errno::EBADF),
                    |_fd| Err(Errno::EBADF),
                    |_fd| Err(Errno::EBADF),
                    |_fd| Err(Errno::EBADF),
                    |_fd| Err(Errno::EBADF),
                    |_fd| Err(Errno::EBADF),
                )
            }
            _ => unimplemented!(),
        }
    }

    /// Handle syscall `getcwd`
    pub fn sys_getcwd(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let cwd = self.query_cwd_name()?;
        // need to account for the null terminator
        if cwd.len() >= buf.len() {
            return Err(Errno::ERANGE);
        }

        let Ok(name) = CString::new(cwd) else {
            return Err(Errno::EINVAL);
        };
        let bytes = name.as_bytes_with_nul();
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }

    /// Handle syscall `chdir`
    pub fn sys_chdir(&self, pathname: &str) -> Result<(), Errno> {
        let path = self.lookup_path_at(litebox_common_linux::AT_FDCWD, pathname)?;
        Ok(self.global.litebox.chdir(
            &self.fs_context(),
            self.pending_cwd_child(),
            path.anchor(self),
            &path.path,
        )?)
    }

    /// Handle syscall `fchdir`
    pub(crate) fn sys_fchdir(&self, fd: i32) -> Result<(), Errno> {
        let dir = self.file_for_dirfd(fd)?;
        Ok(dir.fchdir(self.pending_cwd_child(), self.fs_context().acting_user())?)
    }
}

/// Translates a terminal ioctl into the broker operation it requests.
fn terminal_operation<Platform: ShimPlatform>(arg: &IoctlArg) -> Result<TerminalOperation, Errno> {
    Ok(match arg {
        IoctlArg::TCGETS(_) | IoctlArg::TCGETS2(_) => TerminalOperation::GetSettings,
        IoctlArg::TCSETS(ptr) | IoctlArg::TCSETSW(ptr) | IoctlArg::TCSETSF(ptr) => {
            set_settings::<Platform, _>(arg, *ptr)?
        }
        IoctlArg::TCSETS2(ptr) | IoctlArg::TCSETSW2(ptr) | IoctlArg::TCSETSF2(ptr) => {
            set_settings::<Platform, _>(arg, *ptr)?
        }
        IoctlArg::TIOCGWINSZ(_) => TerminalOperation::GetWindowSize,
        IoctlArg::TIOCSWINSZ(ptr) => {
            let size = ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
            TerminalOperation::SetWindowSize(size.into())
        }
        IoctlArg::TCFLSH(selector) => {
            if *selector > 2 {
                return Err(Errno::EINVAL);
            }
            TerminalOperation::Flush {
                input: *selector != 1,
                output: *selector != 0,
            }
        }
        IoctlArg::TCSBRK(0) => {
            log_unsupported!("terminal serial break");
            return Err(Errno::EOPNOTSUPP);
        }
        IoctlArg::TCSBRK(_) => TerminalOperation::Drain,
        IoctlArg::TIOCGPTN(_) => TerminalOperation::GetSubsidiaryIndex,
        IoctlArg::TIOCGPTLCK(_) => TerminalOperation::GetSubsidiaryLock,
        IoctlArg::TIOCSPTLCK(ptr) => {
            let lock = ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
            TerminalOperation::SetSubsidiaryLock(lock != 0)
        }
        _ => unreachable!("non-terminal ioctl"),
    })
}

/// Reads the settings a `TCSETS` or `TCSETS2` family `arg` requests through `ptr`.
fn set_settings<Platform: ShimPlatform, T>(
    arg: &IoctlArg,
    ptr: UserPtr<T>,
) -> Result<TerminalOperation, Errno>
where
    T: zerocopy::FromBytes + core::fmt::Debug,
    for<'a> TerminalSettings: TryFrom<&'a T, Error = Errno>,
{
    let termios = ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
    let settings = TerminalSettings::try_from(&termios).inspect_err(|_| {
        log_unsupported!("terminal settings {:?}", termios);
    })?;
    Ok(TerminalOperation::SetSettings {
        settings,
        timing: match arg {
            IoctlArg::TCSETSW(_) | IoctlArg::TCSETSW2(_) => ChangeTiming::AfterOutput,
            IoctlArg::TCSETSF(_) | IoctlArg::TCSETSF2(_) => ChangeTiming::AfterOutputAndFlushInput,
            _ => ChangeTiming::Now,
        },
    })
}

impl<Platform: ShimPlatform> Task<Platform> {
    /// Handle syscall `pipe2`
    pub(crate) fn sys_pipe2(&self, pipefd: UserPtrMut<u32>, flags: OFlags) -> Result<(), Errno> {
        self.do_pipe2(flags, |read_fd, write_fd| {
            pipefd
                .write_slice_at_offset::<Platform>(0, &[read_fd, write_fd])
                .ok_or(Errno::EFAULT)
        })?;
        Ok(())
    }

    /// Creates a pipe, returning `(read_fd, write_fd)` once `publish` has stored them.
    ///
    pub(crate) fn do_pipe2(
        &self,
        flags: OFlags,
        publish: impl FnOnce(u32, u32) -> Result<(), Errno>,
    ) -> Result<(u32, u32), Errno> {
        if flags.intersects(!(OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::DIRECT)) {
            return Err(Errno::EINVAL);
        }
        if flags.contains(OFlags::DIRECT) {
            todo!("O_DIRECT not supported");
        }
        let object = FdCreate::Pipe(CreatePipeRequest {
            capacity: 64 * 1024,
            atomic_write_size: 4096,
            flags: status_flags_change(OFlags::NONBLOCK, flags).1,
        });
        self.create_fd_pair(object, flags.contains(OFlags::CLOEXEC), publish)
    }

    pub fn sys_eventfd2(&self, initval: u32, flags: EfdFlags) -> Result<u32, Errno> {
        if flags
            .intersects((EfdFlags::SEMAPHORE | EfdFlags::CLOEXEC | EfdFlags::NONBLOCK).complement())
        {
            return Err(Errno::EINVAL);
        }

        let object = FdCreate::Event(CreateEventRequest {
            initial_count: u64::from(initval),
            flags: if flags.contains(EfdFlags::NONBLOCK) {
                FileOpenFlags::NONBLOCKING
            } else {
                FileOpenFlags::NONE
            },
            semaphore: flags.contains(EfdFlags::SEMAPHORE),
        });
        Ok(self
            .create_fds(object, flags.contains(EfdFlags::CLOEXEC))?
            .0
            .number)
    }

    fn terminal_ioctl(&self, file: &File<Platform>, arg: &IoctlArg) -> Result<u32, Errno> {
        // Only pseudo-terminal managers support these, and Linux fails them with `ENOTTY` on
        // other terminals.
        let manager_only = matches!(
            arg,
            IoctlArg::TIOCGPTN(_) | IoctlArg::TIOCGPTLCK(_) | IoctlArg::TIOCSPTLCK(_)
        );
        let control = |operation, cx| {
            file.terminal_control(operation, cx)
                .map_err(|error| match error {
                    Errno::EINVAL if manager_only => Errno::ENOTTY,
                    error => error,
                })
        };
        let operation = match terminal_operation::<Platform>(arg) {
            Ok(operation) => operation,
            Err(error) => {
                // Linux rejects the descriptor (`EBADF` for `O_PATH`, `ENOTTY` for a
                // non-terminal, or for a manager-only request, a non-manager) before the
                // request's argument.
                let probe = if manager_only {
                    TerminalOperation::GetSubsidiaryLock
                } else {
                    TerminalOperation::GetSettings
                };
                control(probe, None)?;
                return Err(error);
            }
        };
        let response = control(operation, Some(&self.wait_cx()))?;
        if matches!(operation, TerminalOperation::SetWindowSize(_)) {
            // Like Linux, a resize signals the terminal's process group, which may include this
            // process, before the ioctl returns.
            self.take_signals(true);
        }
        match (arg, response) {
            (IoctlArg::TCGETS(ptr), TerminalResponse::Settings(settings)) => {
                ptr.write_at_offset::<Platform>(0, settings.into())
                    .ok_or(Errno::EFAULT)?;
            }
            (IoctlArg::TCGETS2(ptr), TerminalResponse::Settings(settings)) => {
                ptr.write_at_offset::<Platform>(0, settings.into())
                    .ok_or(Errno::EFAULT)?;
            }
            (IoctlArg::TIOCGWINSZ(ptr), TerminalResponse::WindowSize(size)) => {
                ptr.write_at_offset::<Platform>(0, size.into())
                    .ok_or(Errno::EFAULT)?;
            }
            (IoctlArg::TIOCGPTN(ptr), TerminalResponse::SubsidiaryIndex(index)) => {
                ptr.write_at_offset::<Platform>(0, index)
                    .ok_or(Errno::EFAULT)?;
            }
            (IoctlArg::TIOCGPTLCK(ptr), TerminalResponse::SubsidiaryLock(locked)) => {
                ptr.write_at_offset::<Platform>(0, i32::from(locked))
                    .ok_or(Errno::EFAULT)?;
            }
            (_, TerminalResponse::Done) => {}
            _ => return Err(Errno::EIO),
        }
        Ok(0)
    }

    /// Handles a job-control ioctl, which `file` must be the controlling terminal for.
    fn job_control_ioctl(&self, file: &File<Platform>, arg: &IoctlArg) -> Result<u32, Errno> {
        // Like Linux, rejects the descriptor (`EBADF` for `O_PATH`, `ENOTTY` for a non-terminal)
        // before reporting `error`.
        let reject = |error: Errno| {
            file.terminal_control(TerminalOperation::GetSettings, None)
                .err()
                .unwrap_or(error)
        };
        let process_error = |error: ProcessError| match error {
            ProcessError::NotControllingTerminal => reject(Errno::ENOTTY),
            error => error.into(),
        };
        let litebox = &self.global.litebox;
        match arg {
            IoctlArg::TIOCGPGRP(ptr) | IoctlArg::TIOCGSID(ptr) => {
                let foreground = litebox
                    .get_foreground_group(file.file())
                    .map_err(process_error)?;
                let id = if matches!(arg, IoctlArg::TIOCGPGRP(_)) {
                    foreground.process_group.0
                } else {
                    foreground.session.0
                };
                ptr.write_at_offset::<Platform>(0, id.cast_signed())
                    .ok_or(Errno::EFAULT)?;
            }
            IoctlArg::TIOCSPGRP(ptr) => {
                let process_group = ptr
                    .read_at_offset::<Platform>(0)
                    .ok_or_else(|| reject(Errno::EFAULT))?;
                if process_group < 0 {
                    return Err(reject(Errno::EINVAL));
                }
                // The broker checks a vfork child's request against its parent's session, so
                // refuse once the child has started its own, even for a terminal it acquired.
                if self.vfork.borrow().is_some()
                    && self.process_group_membership(0)?.session
                        != self.process_group_membership(self.pid)?.session
                {
                    return Err(reject(Errno::ENOTTY));
                }
                let process_group = self
                    .translate_id_for_requests(process_group)
                    .map_err(reject)?;
                litebox
                    .set_foreground_group(
                        file.file(),
                        ProcessGroupId(process_group.cast_unsigned()),
                    )
                    .map_err(process_error)?;
            }
            // Stealing a terminal from another session is unsupported, so the argument only
            // matters when the broker denies the request anyway.
            IoctlArg::TIOCSCTTY(_) => {
                litebox
                    .set_controlling_terminal(
                        ProcessId(self.own_pid_for_requests().cast_unsigned()),
                        file.file(),
                    )
                    .map_err(process_error)?;
            }
            _ => unreachable!("non-job-control ioctl"),
        }
        Ok(0)
    }

    /// Handle syscall `ioctl`
    pub fn sys_ioctl(&self, fd: i32, arg: IoctlArg) -> Result<u32, Errno> {
        let files = self.files.borrow();
        match arg {
            IoctlArg::FIONBIO(arg) => {
                let val = arg.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                let fd = files.typed_fd(fd)?;
                let flags = if val != 0 {
                    OFlags::NONBLOCK
                } else {
                    OFlags::empty()
                };
                fd.dispatch(
                    |fd| {
                        self.global
                            .with_file(fd, |file| file.set_status_flags(OFlags::NONBLOCK, flags))
                    },
                    |fd| {
                        self.global.with_inet_socket(fd, |socket| {
                            socket.set_status_flags(OFlags::NONBLOCK, flags)
                        })
                    },
                    |fd| {
                        self.global.with_pipe_end(fd, |pipe| {
                            pipe.set_status_flags(OFlags::NONBLOCK, flags)
                        })
                    },
                    |fd| {
                        self.global
                            .with_eventfd(fd, |file| file.set_status_flags(OFlags::NONBLOCK, flags))
                    },
                    |fd| {
                        self.global
                            .with_epoll(fd, |file| file.set_status_flags(OFlags::NONBLOCK, flags))
                    },
                    |fd| {
                        self.global.with_unix_socket(fd, |socket| {
                            socket.set_status_flags(OFlags::NONBLOCK, flags)
                        })
                    },
                    |fd| {
                        self.global
                            .with_timerfd(fd, |file| file.set_status_flags(OFlags::NONBLOCK, flags))
                    },
                    |fd| {
                        self.global.with_vsock_socket(fd, |socket| {
                            socket.set_status_flags(OFlags::NONBLOCK, flags)
                        })
                    },
                    |fd| {
                        self.global
                            .with_pidfd(fd, |file| file.set_status_flags(OFlags::NONBLOCK, flags))
                    },
                )?;
                Ok(0)
            }
            IoctlArg::FIOCLEX => {
                if let Some(file) = files.typed_fd(fd)?.as_file() {
                    self.reject_path_descriptor(file)?;
                }
                self.set_cloexec(u32::try_from(fd).map_err(|_| Errno::EBADF)?, true)
            }
            IoctlArg::TCGETS(..)
            | IoctlArg::TCSETS(..)
            | IoctlArg::TCSETSW(..)
            | IoctlArg::TCSETSF(..)
            | IoctlArg::TCGETS2(..)
            | IoctlArg::TCSETS2(..)
            | IoctlArg::TCSETSW2(..)
            | IoctlArg::TCSETSF2(..)
            | IoctlArg::TCSBRK(..)
            | IoctlArg::TCFLSH(..)
            | IoctlArg::TIOCSWINSZ(..)
            | IoctlArg::TIOCGPTN(..)
            | IoctlArg::TIOCGPTLCK(..)
            | IoctlArg::TIOCSPTLCK(..)
            | IoctlArg::TIOCGWINSZ(..) => {
                let fd = files.typed_fd(fd)?;
                let fd = fd.file_only(Errno::ENOTTY)?;
                self.global
                    .with_file(fd, |file| self.terminal_ioctl(file, &arg))
            }
            IoctlArg::TIOCGPGRP(..)
            | IoctlArg::TIOCSPGRP(..)
            | IoctlArg::TIOCGSID(..)
            | IoctlArg::TIOCSCTTY(..) => {
                let fd = files.typed_fd(fd)?;
                let fd = fd.file_only(Errno::ENOTTY)?;
                self.global
                    .with_file(fd, |file| self.job_control_ioctl(file, &arg))
            }
            _ => {
                log_unsupported!("ioctl with arg {:?}", arg);
                // Like Linux, an unknown request fails with `ENOTTY` on any usable descriptor.
                let fd = files.typed_fd(fd)?;
                if let Some(fd) = fd.as_file() {
                    self.reject_path_descriptor(fd)?;
                }
                Err(Errno::ENOTTY)
            }
        }
    }

    /// Fails with `EBADF` for an `O_PATH` descriptor, on which Linux refuses every ioctl.
    fn reject_path_descriptor(&self, fd: &FileFd<Platform>) -> Result<(), Errno> {
        let flags = self.global.with_file(fd, File::get_status_flags)?;
        if flags.contains(OFlags::PATH) {
            return Err(Errno::EBADF);
        }
        Ok(())
    }

    /// Handle syscall `epoll_create` and `epoll_create1`
    pub fn sys_epoll_create(&self, flags: EpollCreateFlags) -> Result<u32, Errno> {
        if flags.intersects(EpollCreateFlags::EPOLL_CLOEXEC.complement()) {
            return Err(Errno::EINVAL);
        }

        self.create_fds(
            FdCreate::Epoll,
            flags.contains(EpollCreateFlags::EPOLL_CLOEXEC),
        )
        .map(|(fd, _, _)| fd.number)
        .map_err(|error| {
            if error == Errno::ENOBUFS {
                Errno::ENOMEM
            } else {
                error
            }
        })
    }

    /// Handle syscall `epoll_ctl`
    pub(crate) fn sys_epoll_ctl(
        &self,
        epfd: i32,
        op: litebox_common_linux::EpollOp,
        fd: i32,
        event: UserPtr<litebox_common_linux::EpollEvent>,
    ) -> Result<(), Errno> {
        let Ok(epfd) = u32::try_from(epfd) else {
            return Err(Errno::EBADF);
        };
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        if epfd == fd {
            return Err(Errno::EINVAL);
        }

        let files = self.files.borrow();

        let AnyTypedFd::Epoll(epoll) = files.typed_fd_from_raw(epfd as usize)? else {
            return Err(Errno::EBADF);
        };
        let file_descriptor = super::epoll::EpollDescriptor::try_from(&files, fd as usize)?;

        let event = if op == litebox_common_linux::EpollOp::EpollCtlDel {
            None
        } else {
            Some(event.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?)
        };
        epoll.epoll_ctl(&self.global, op, fd, &file_descriptor, event)
    }

    /// Handle syscall `epoll_pwait`
    pub fn sys_epoll_pwait(
        &self,
        epfd: i32,
        events: UserPtrMut<litebox_common_linux::EpollEvent>,
        maxevents: u32,
        timeout: i32,
        sigmask: Option<UserPtr<litebox_common_linux::signal::SigSet>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        self.set_user_signal_mask(sigmask, sigsetsize)?;
        let result = self.do_epoll_wait(epfd, events, maxevents, timeout);
        // Keep the call's mask if interrupted, so the interrupting signal is delivered under it.
        self.restore_signal_mask_unless(result == Err(Errno::EINTR));
        result
    }

    /// Waits for at most `maxevents` events on the epoll at `epfd` for `timeout` milliseconds,
    /// or until one comes if it is negative, and writes them to `events`, for `epoll_pwait`.
    fn do_epoll_wait(
        &self,
        epfd: i32,
        events: UserPtrMut<litebox_common_linux::EpollEvent>,
        maxevents: u32,
        timeout: i32,
    ) -> Result<usize, Errno> {
        let Ok(epfd) = u32::try_from(epfd) else {
            return Err(Errno::EBADF);
        };
        let maxevents = maxevents as usize;
        if maxevents == 0
            || maxevents > i32::MAX as usize / size_of::<litebox_common_linux::EpollEvent>()
        {
            return Err(Errno::EINVAL);
        }
        let timeout = if timeout >= 0 {
            #[allow(clippy::cast_sign_loss, reason = "timeout is a positive integer")]
            Some(core::time::Duration::from_millis(timeout as u64))
        } else {
            None
        };
        let AnyTypedFd::Epoll(epoll) = self.files.borrow().typed_fd_from_raw(epfd as usize)? else {
            return Err(Errno::EBADF);
        };
        let epoll_events = epoll.wait(&self.wait_cx().with_timeout(timeout), maxevents)?;
        if !epoll_events.is_empty() {
            events
                .copy_from_slice::<Platform>(0, &epoll_events)
                .ok_or(Errno::EFAULT)?;
        }
        Ok(epoll_events.len())
    }

    /// Handle syscall `poll`.
    pub(crate) fn sys_poll(
        &self,
        fds: UserPtrMut<litebox_common_linux::Pollfd>,
        nfds: usize,
        timeout: TimeParam,
    ) -> Result<usize, Errno> {
        let deadline = timeout
            .read::<Platform>()?
            .map(|timeout| self.relative_deadline(timeout));
        self.poll_until(fds, nfds, deadline)
    }

    /// Polls the `nfds` entries at `fds` until `deadline`, or until one is ready if `None`, for
    /// `poll`.
    pub(super) fn poll_until(
        &self,
        fds: UserPtrMut<litebox_common_linux::Pollfd>,
        nfds: usize,
        deadline: Option<<Platform as TimeProvider>::Instant>,
    ) -> Result<usize, Errno> {
        match self.do_poll(fds, nfds, deadline) {
            Err(Errno::ERESTARTNOHAND) => Err(self.thread.save_restart_block(RestartBlock::Poll {
                fds,
                nfds,
                deadline,
            })),
            result => result,
        }
    }

    /// Handle syscall `ppoll`.
    pub fn sys_ppoll(
        &self,
        fds: UserPtrMut<litebox_common_linux::Pollfd>,
        nfds: usize,
        timeout: TimeParam,
        sigmask: Option<UserPtr<litebox_common_linux::signal::SigSet>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        let timeout = self.read_poll_select_timeout(timeout)?;
        self.set_user_signal_mask(sigmask, sigsetsize)?;
        let result = self.do_poll(fds, nfds, timeout.deadline);
        self.finish_poll_or_select(result, &timeout)
    }

    /// Reads the timeout of `ppoll`, `select`, or `pselect` from `param`, noting when.
    fn read_poll_select_timeout(
        &self,
        param: TimeParam,
    ) -> Result<PollSelectTimeout<<Platform as TimeProvider>::Instant>, Errno> {
        let read = param
            .read::<Platform>()?
            .map(|duration| (duration, self.global.platform.now()));
        let deadline = read.map(|(duration, start)| self.relative_deadline_from(start, duration));
        Ok(PollSelectTimeout {
            param,
            read,
            deadline,
        })
    }

    /// Polls the `nfds` entries at `fds` until `deadline`, or until one is ready if `None`, and
    /// writes back their `revents`, failing with [`Errno::ERESTARTNOHAND`] if interrupted.
    fn do_poll(
        &self,
        fds: UserPtrMut<litebox_common_linux::Pollfd>,
        nfds: usize,
        deadline: Option<<Platform as TimeProvider>::Instant>,
    ) -> Result<usize, Errno> {
        // XXX: Linux rejects nfds above the soft RLIMIT_NOFILE, but that lives in the broker and
        // reading it would cost a broker call on every poll.
        if nfds > crate::syscalls::process::RLIMIT_NOFILE_MAX {
            return Err(Errno::EINVAL);
        }
        let nfds_signed = isize::try_from(nfds).map_err(|_| Errno::EINVAL)?;
        let mut set = super::epoll::PollSet::with_capacity(nfds).ok_or(Errno::ENOMEM)?;
        for i in 0..nfds_signed {
            let fd = fds.read_at_offset::<Platform>(i).ok_or(Errno::EFAULT)?;

            let events = litebox::event::Events::from_bits_truncate(
                fd.events.reinterpret_as_unsigned().into(),
            );
            set.add_fd(fd.fd, events);
        }
        let files = self.files.borrow().clone();

        let result = match set.wait(&self.wait_cx().with_deadline(deadline), &files) {
            Ok(()) => Ok(()),
            Err(WaitError::Interrupted) => Err(Errno::ERESTARTNOHAND),
            Err(WaitError::TimedOut) => {
                // A timeout occurred. Scan one last time.
                set.scan(&files);
                Ok(())
            }
        };

        // Like Linux, write just the revents back, even when interrupted.
        let fds_base_addr = fds.as_usize();
        let mut ready_count = 0;
        for (i, revents) in set.revents().enumerate() {
            // TODO: This is not great from a provenance perspective. Consider
            // adding cast+add methods to UserPtr/UserPtrMut.
            let fd_addr = fds_base_addr + i * core::mem::size_of::<litebox_common_linux::Pollfd>();
            let revents_ptr = UserPtrMut::<i16>::from_usize(
                fd_addr + core::mem::offset_of!(litebox_common_linux::Pollfd, revents),
            );
            let revents: u16 = revents.bits().trunc();
            revents_ptr
                .write_at_offset::<Platform>(0, revents.reinterpret_as_signed())
                .ok_or(Errno::EFAULT)?;
            if revents != 0 {
                ready_count += 1;
            }
        }
        result.map(|()| ready_count)
    }

    /// Ends `ppoll`, `select`, or `pselect` with `result` after waiting at most `timeout`, like
    /// Linux's `poll_select_finish`.
    fn finish_poll_or_select(
        &self,
        result: Result<usize, Errno>,
        timeout: &PollSelectTimeout<<Platform as TimeProvider>::Instant>,
    ) -> Result<usize, Errno> {
        let interrupted = result == Err(Errno::ERESTARTNOHAND);
        self.restore_signal_mask_unless(interrupted);
        let Some((duration, start)) = timeout.read.filter(|(duration, _)| !duration.is_zero())
        else {
            return result;
        };
        let elapsed = self
            .global
            .platform
            .now()
            .checked_duration_since(&start)
            .unwrap_or_default();
        let left = duration.saturating_sub(elapsed);
        match timeout.param.write::<Platform>(left) {
            Err(_) if interrupted => Err(Errno::EINTR),
            Ok(()) | Err(_) => result,
        }
    }

    pub(crate) fn do_pselect(
        &self,
        nfds: u32,
        readfds: Option<&mut bitvec::vec::BitVec>,
        writefds: Option<&mut bitvec::vec::BitVec>,
        exceptfds: Option<&mut bitvec::vec::BitVec>,
        deadline: Option<<Platform as TimeProvider>::Instant>,
    ) -> Result<usize, Errno> {
        // XXX: semantic issue likely should be fixed here to make sure EBADF is triggered early
        // enough if needed. Previously, `file_table_len` used to be
        // `self.files.borrow().file_descriptors.read().len()` before `file_descriptors` was
        // removed to clean up the table handling.
        let file_table_len = usize::MAX;
        let mut set = super::epoll::PollSet::with_capacity(nfds as usize).ok_or(Errno::ENOMEM)?;
        for i in 0..nfds {
            let mut events = litebox::event::Events::empty();
            if readfds.as_ref().is_some_and(|set| set[i as usize]) {
                events |= litebox::event::Events::IN;
            }
            if writefds.as_ref().is_some_and(|set| set[i as usize]) {
                events |= litebox::event::Events::OUT;
            }
            if exceptfds.as_ref().is_some_and(|set| set[i as usize]) {
                events |= litebox::event::Events::PRI;
            }
            if !events.is_empty() {
                if i as usize >= file_table_len {
                    return Err(Errno::EBADF);
                }
                set.add_fd(i.reinterpret_as_signed(), events);
            }
        }

        let files = self.files.borrow().clone();
        match set.wait(&self.wait_cx().with_deadline(deadline), &files) {
            Ok(()) => {}
            // Like Linux, the call is reissued unless a handler runs.
            Err(WaitError::Interrupted) => return Err(Errno::ERESTARTNOHAND),
            Err(WaitError::TimedOut) => {
                // A timeout occurred. Scan one last time.
                set.scan(&files);
            }
        }

        let mut ready_count = 0;
        let mut process_fdset =
            |fds: Option<&mut bitvec::vec::BitVec>, target_events: Events| -> Result<(), Errno> {
                if let Some(fds) = fds {
                    fds.fill(false);
                    for (i, revents) in set.revents_with_fds() {
                        if revents.contains(Events::NVAL) {
                            return Err(Errno::EBADF);
                        }
                        if revents.intersects(target_events) {
                            // no negative fds added to the set
                            fds.set(i.reinterpret_as_unsigned() as usize, true);
                            ready_count += 1;
                        }
                    }
                }
                Ok(())
            };
        process_fdset(readfds, Events::IN | Events::ALWAYS_POLLED)?;
        process_fdset(writefds, Events::OUT | Events::ALWAYS_POLLED)?;
        process_fdset(exceptfds, Events::PRI)?;
        Ok(ready_count)
    }

    /// Handle syscall `pselect`.
    pub(crate) fn sys_pselect(
        &self,
        nfds: u32,
        readfds: Option<UserPtrMut<usize>>,
        writefds: Option<UserPtrMut<usize>>,
        exceptfds: Option<UserPtrMut<usize>>,
        timeout: TimeParam,
        sigsetpack: Option<UserPtr<litebox_common_linux::SigSetPack>>,
    ) -> Result<usize, Errno> {
        // Like Linux, read where the signal mask is before the timeout, and the mask after it.
        let (sigmask, sigsetsize) = match sigsetpack {
            Some(sigsetpack) => {
                let sigsetpack = sigsetpack
                    .read_at_offset::<Platform>(0)
                    .ok_or(Errno::EFAULT)?;
                let sigmask = (!sigsetpack.sigset.is_null()).then_some(sigsetpack.sigset);
                (sigmask, sigsetpack.size)
            }
            None => (None, 0),
        };
        let timeout = self.read_poll_select_timeout(timeout)?;
        self.set_user_signal_mask(sigmask, sigsetsize)?;
        let result = self.select_fds(nfds, readfds, writefds, exceptfds, timeout.deadline);
        self.finish_poll_or_select(result, &timeout)
    }

    /// Waits until `deadline`, or until ready if `None`, for the fds in the `nfds`-bit sets at
    /// `readfds`, `writefds`, and `exceptfds`, writing back which are ready, for `select` and
    /// `pselect`.
    fn select_fds(
        &self,
        nfds: u32,
        readfds: Option<UserPtrMut<usize>>,
        writefds: Option<UserPtrMut<usize>>,
        exceptfds: Option<UserPtrMut<usize>>,
        deadline: Option<<Platform as TimeProvider>::Instant>,
    ) -> Result<usize, Errno> {
        if nfds > i32::MAX as u32 {
            return Err(Errno::EINVAL);
        }
        // Like Linux, which does not check `RLIMIT_NOFILE` here, ignore bits past every
        // descriptor that can be open.
        let nfds = nfds.min(u32::try_from(crate::syscalls::process::RLIMIT_NOFILE_MAX).unwrap());
        let len = (nfds as usize).div_ceil(core::mem::size_of::<usize>() * 8);
        let read_fd_set = |fds: Option<UserPtrMut<usize>>| {
            fds.map(|fds| {
                fds.to_owned_slice::<Platform>(len)
                    .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_vec()))
                    .ok_or(Errno::EFAULT)
            })
            .transpose()
        };
        let mut kreadfds = read_fd_set(readfds)?;
        let mut kwritefds = read_fd_set(writefds)?;
        let mut kexceptfds = read_fd_set(exceptfds)?;
        let count = self.do_pselect(
            nfds,
            kreadfds.as_mut(),
            kwritefds.as_mut(),
            kexceptfds.as_mut(),
            deadline,
        )?;
        for (fds, kfds) in [
            (readfds, kreadfds),
            (writefds, kwritefds),
            (exceptfds, kexceptfds),
        ] {
            if let (Some(fds), Some(kfds)) = (fds, kfds) {
                fds.write_slice_at_offset::<Platform>(0, kfds.as_raw_slice())
                    .ok_or(Errno::EFAULT)?;
            }
        }
        Ok(count)
    }

    // XXX: Not atomic for other threads: the broker closes the replaced handle before this
    // cache update, so a concurrent lookup can see a closed handle and fail with EBADF.
    // Resolving fds in the broker for each operation fixes this.
    fn duplicate_fd(&self, fd: u32, target: DupTarget, cloexec: bool) -> Result<u32, Errno> {
        let files = self.files.borrow().clone();
        let mutation = files.mutation();
        let response = self.fd_request(FdOperation::Duplicate {
            fd,
            target,
            cloexec,
        })?;
        Ok(self.cache_installed(&mutation, response)?.0.number)
    }

    fn set_cloexec(&self, fd: u32, cloexec: bool) -> Result<u32, Errno> {
        match self.fd_request(FdOperation::SetCloexec { fd, cloexec })? {
            FdResponse::Cloexec(_) => Ok(0),
            _ => Err(Errno::EIO),
        }
    }

    /// Handle syscall `dup/dup2/dup3`
    ///
    /// The dup() system call creates a copy of the file descriptor oldfd, using the lowest-numbered unused file descriptor for the new descriptor.
    /// The dup2() system call performs the same task as dup(), but instead of using the lowest-numbered unused file descriptor, it uses the file descriptor number specified in newfd.
    /// The dup3() system call is similar to dup2(), but it also takes an additional flags argument that can be used to set the close-on-exec flag for the new file descriptor.
    pub fn sys_dup(
        &self,
        oldfd: i32,
        newfd: Option<i32>,
        flags: Option<OFlags>,
    ) -> Result<u32, Errno> {
        if flags.is_some_and(|flags| flags.intersects(!OFlags::CLOEXEC))
            || (flags.is_some() && newfd == Some(oldfd))
        {
            return Err(Errno::EINVAL);
        }
        let oldfd = u32::try_from(oldfd).map_err(|_| Errno::EBADF)?;
        let target = match newfd {
            None => DupTarget::Lowest,
            Some(number) => DupTarget::Exact {
                number: u32::try_from(number).map_err(|_| Errno::EBADF)?,
                distinct: flags.is_some(),
            },
        };
        self.duplicate_fd(
            oldfd,
            target,
            flags.is_some_and(|flags| flags.contains(OFlags::CLOEXEC)),
        )
    }
}

const DIRENT_STRUCT_BYTES_WITHOUT_NAME: usize =
    core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name);

impl<Platform: ShimPlatform> Task<Platform> {
    /// Handle syscall `getdents64`
    pub(crate) fn sys_getdirent64(
        &self,
        fd: i32,
        dirp: UserPtrMut<u8>,
        count: usize,
    ) -> Result<usize, Errno> {
        let fd = self.typed_fd(fd)?;
        let file = self
            .global
            .with_file(fd.file_only(Errno::ENOTDIR)?, |file| {
                Ok(Arc::clone(file.file()))
            })?;
        let budget = DirectoryRecordBudget {
            capacity: u32::try_from(count).unwrap_or(u32::MAX),
            fixed: u16::try_from(DIRENT_STRUCT_BYTES_WITHOUT_NAME + 1).unwrap(),
            // The Linux ABI aligns records to 8 bytes even though our header is packed.
            alignment: 8,
        };
        // XXX: The broker advances the shared cursor before the guest copy, so probe the whole
        // buffer first; a bad `dirp` then fails with EFAULT without consuming any records.
        // Records can still be lost if another thread unmaps `dirp` after the probe.
        let probe_len = budget.capacity as usize;
        let mut offset = 0;
        while offset < probe_len {
            let chunk = (probe_len - offset).min(4096);
            dirp.copy_from_slice::<Platform>(offset, &[0; 4096][..chunk])
                .ok_or(Errno::EFAULT)?;
            offset += chunk;
        }
        let (first, entries) = file.read_directory(budget)?;
        let mut nbytes = 0;
        for (index, entry) in entries.into_iter().enumerate() {
            let len = budget
                .record_size(entry.name.len())
                .ok_or(Errno::EOVERFLOW)?;
            assert!(
                len <= count - nbytes,
                "broker returned directory records exceeding the guest budget"
            );
            let dirent64 = litebox_common_linux::LinuxDirent64 {
                ino: entry.ino_info.map_or(0, |node_info| node_info.ino),
                off: first + index as u64 + 1,
                len: u16::try_from(len).map_err(|_| Errno::EOVERFLOW)?,
                typ: litebox_common_linux::DirentType::from(entry.file_type) as u8,
                __name: [0; 0],
            };
            let hdr_ptr =
                UserPtrMut::from_usize(dirp.as_usize().checked_add(nbytes).ok_or(Errno::EFAULT)?);
            hdr_ptr
                .write_at_offset::<Platform>(0, dirent64)
                .ok_or(Errno::EFAULT)?;
            let name_offset = nbytes + DIRENT_STRUCT_BYTES_WITHOUT_NAME;
            dirp.copy_from_slice::<Platform>(name_offset, entry.name.as_bytes())
                .ok_or(Errno::EFAULT)?;
            let padding_offset = name_offset + entry.name.len();
            dirp.copy_from_slice::<Platform>(
                padding_offset,
                &[0; 8][..nbytes + len - padding_offset],
            )
            .ok_or(Errno::EFAULT)?;
            nbytes += len;
        }
        Ok(nbytes)
    }
}

/// The timeout of `ppoll`, `select`, or `pselect`, which, like Linux, they write
/// the time left back to.
struct PollSelectTimeout<Instant> {
    /// Where the timeout is.
    param: TimeParam,
    /// The timeout read from `param`, if any, and when it was read.
    read: Option<(core::time::Duration, Instant)>,
    /// When the wait ends, or `None` if it waits until an fd is ready.
    deadline: Option<Instant>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    extern crate std;

    #[test]
    fn fspath_new() {
        let fp = FsPath::new(litebox_common_linux::AT_FDCWD, "/usr/bin").unwrap();
        assert!(matches!(fp, FsPath::Absolute { path } if path == "/usr/bin"));

        let fp = FsPath::new(litebox_common_linux::AT_FDCWD, "foo/bar").unwrap();
        assert!(
            matches!(fp, FsPath::FdRelative { fd: litebox_common_linux::AT_FDCWD, path } if path == "foo/bar")
        );

        // Empty path at AT_FDCWD → Cwd variant.
        let fp = FsPath::new(litebox_common_linux::AT_FDCWD, "").unwrap();
        assert!(matches!(fp, FsPath::Cwd));

        // Positive fd + empty path → Fd variant.
        let fp = FsPath::new(5, "").unwrap();
        assert!(matches!(fp, FsPath::Fd(5)));

        // Positive fd + relative path → FdRelative variant, left for the caller to resolve.
        let fp = FsPath::new(5, "foo/bar").unwrap();
        assert!(matches!(fp, FsPath::FdRelative { fd: 5, path } if path == "foo/bar"));

        // Invalid dirfd → EBADF.
        let err = FsPath::new(-1, "file.txt").unwrap_err();
        assert_eq!(err, Errno::EBADF);

        // Path exceeding PATH_MAX → ENAMETOOLONG.
        let long_path = "a".repeat(PATH_MAX + 1);
        let err = FsPath::new(litebox_common_linux::AT_FDCWD, long_path.as_str()).unwrap_err();
        assert_eq!(err, Errno::ENAMETOOLONG);
    }

    #[test]
    fn getcwd_and_chdir() {
        use crate::syscalls::tests::{create_directory, create_file, init_platform};

        let task = init_platform();
        create_directory(&task, "/test_chdir_dir");
        create_file(&task, "/test_chdir_file", &[]);

        // The default CWD is the root.
        let mut buf = [0u8; 256];
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap(); // strip NUL
        assert_eq!(cwd, "/");

        task.sys_chdir("/test_chdir_dir").unwrap();
        let len = task.sys_getcwd(&mut buf).unwrap();
        assert_eq!(
            core::str::from_utf8(&buf[..len - 1]).unwrap(),
            "/test_chdir_dir"
        );

        // A missing target leaves the CWD alone.
        assert_eq!(
            task.sys_chdir("/does_not_exist").unwrap_err(),
            Errno::ENOENT
        );

        // An empty path is rejected.
        assert_eq!(task.sys_chdir("").unwrap_err(), Errno::ENOENT);

        // A non-directory target is rejected by the shim.
        assert_eq!(
            task.sys_chdir("/test_chdir_file").unwrap_err(),
            Errno::ENOTDIR
        );

        // The CWD is unchanged by the failed calls above.
        let len = task.sys_getcwd(&mut buf).unwrap();
        assert_eq!(
            core::str::from_utf8(&buf[..len - 1]).unwrap(),
            "/test_chdir_dir"
        );

        // getcwd with too-small buffer → ERANGE.
        let mut tiny = [0u8; 1];
        assert_eq!(task.sys_getcwd(&mut tiny).unwrap_err(), Errno::ERANGE);
    }

    #[test]
    fn chdir_normalizes_relative_paths() {
        use crate::syscalls::tests::{create_directory, init_platform};

        let task = init_platform();
        create_directory(&task, "/rel_parent");
        create_directory(&task, "/rel_parent/rel_child");

        task.sys_chdir("/rel_parent").unwrap();
        task.sys_chdir("rel_child").unwrap();
        let mut buf = [0u8; 256];
        let len = task.sys_getcwd(&mut buf).unwrap();
        assert_eq!(
            core::str::from_utf8(&buf[..len - 1]).unwrap(),
            "/rel_parent/rel_child"
        );

        task.sys_chdir("..").unwrap();
        let len = task.sys_getcwd(&mut buf).unwrap();
        assert_eq!(
            core::str::from_utf8(&buf[..len - 1]).unwrap(),
            "/rel_parent"
        );
    }

    #[test]
    fn mknodat_regular_file_does_not_consume_fd_limit() {
        use crate::syscalls::tests::init_platform;
        use litebox_common_linux::{Rlimit, RlimitResource};

        let task = init_platform();
        let old_limit = task.do_prlimit(RlimitResource::NOFILE, None).unwrap();
        task.do_prlimit(
            RlimitResource::NOFILE,
            Some(Rlimit {
                rlim_cur: 3,
                rlim_max: old_limit.rlim_max,
            }),
        )
        .unwrap();

        for index in 0..32 {
            let path = alloc::format!("/mknodat_at_fd_limit_{index}");
            assert_eq!(
                task.sys_mknodat(
                    litebox_common_linux::AT_FDCWD,
                    &path,
                    InodeType::File as u32 | u32::from((Mode::RUSR | Mode::WUSR).bits()),
                    0,
                ),
                Ok(()),
                "transient broker handles must be closed after creating {path}"
            );
            assert!(task.sys_stat(&path).is_ok());
        }
    }

    #[test]
    fn mount_tmpfs_preserves_open_files_and_rejects_unsupported_requests() {
        use crate::syscalls::tests::{create_directory, init_platform};

        const MS_REC: usize = 1 << 14;
        const MS_PRIVATE: usize = 1 << 18;
        const MS_SLAVE: usize = 1 << 19;
        const MS_SHARED: usize = 1 << 20;

        let task = init_platform();
        create_directory(&task, "/mount_tmpfs_test");
        let fd = task
            .sys_open(
                "/mount_tmpfs_test/old",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RWXU,
            )
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        let old_dev = task.sys_stat("/mount_tmpfs_test").unwrap().st_dev;
        assert_eq!(
            task.sys_mount("/missing_mount_target", Some("tmpfs"), 0),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            task.sys_mount("/mount_tmpfs_test/old", Some("tmpfs"), 0),
            Err(Errno::ENOTDIR)
        );
        assert_eq!(
            task.sys_mount("/mount_tmpfs_test", Some("proc"), 0),
            Err(Errno::ENODEV)
        );
        for flags in [1, 1 << 3, 1 << 5, 1 << 12, 1 << 13, usize::MAX] {
            assert_eq!(
                task.sys_mount("/mount_tmpfs_test", Some("tmpfs"), flags),
                Err(Errno::EINVAL)
            );
        }
        assert_eq!(
            task.sys_mount("/mount_tmpfs_test", None, 0),
            Err(Errno::EINVAL)
        );
        // Propagation changes ignore the type, and only `MS_PRIVATE` and `MS_SLAVE`, both no-ops
        // for mounts that never propagate, are supported.
        assert_eq!(
            task.sys_mount("/missing_mount_target", None, MS_PRIVATE),
            Err(Errno::ENOENT)
        );
        for flags in [MS_REC | MS_PRIVATE, MS_SLAVE] {
            task.sys_mount("/", None, flags).unwrap();
        }
        for flags in [MS_SHARED, MS_PRIVATE | MS_SLAVE, MS_PRIVATE | 1] {
            assert_eq!(
                task.sys_mount("/", Some("tmpfs"), flags),
                Err(Errno::EINVAL)
            );
        }
        task.sys_mount("/mount_tmpfs_test", Some("tmpfs"), 0)
            .unwrap();
        let status = task.sys_stat("/mount_tmpfs_test").unwrap();
        assert_ne!({ status.st_dev }, old_dev);
        assert_eq!(status.st_mode & 0o7777, 0o1777);
        assert_eq!(
            task.sys_stat("/mount_tmpfs_test/old").unwrap_err(),
            Errno::ENOENT
        );
        task.sys_fstat(fd).unwrap();
        task.sys_close(fd).unwrap();
        assert_eq!(
            task.sys_mount("/mount_tmpfs_test", Some("tmpfs"), 0),
            Err(Errno::EBUSY)
        );
        let fd = task
            .sys_open(
                "/mount_tmpfs_test/new",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RWXU,
            )
            .unwrap();
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();
        task.sys_stat("/mount_tmpfs_test/new").unwrap();
    }

    #[test]
    fn empty_pathnames_return_enoent() {
        use crate::syscalls::tests::init_platform;

        let task = init_platform();

        assert_eq!(
            task.sys_open("", OFlags::RDONLY, Mode::empty())
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            task.sys_open("", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(task.sys_stat("").unwrap_err(), Errno::ENOENT);
        assert_eq!(
            task.sys_unlinkat(litebox_common_linux::AT_FDCWD, "", AtFlags::empty())
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            task.sys_mkdirat(litebox_common_linux::AT_FDCWD, "", 0o755)
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            task.sys_mknodat(
                litebox_common_linux::AT_FDCWD,
                "",
                InodeType::File as u32 | u32::from(Mode::RWXU.bits()),
                0,
            )
            .unwrap_err(),
            Errno::ENOENT
        );
        let mut buffer = [0u8; 16];
        assert_eq!(
            task.sys_readlinkat(litebox_common_linux::AT_FDCWD, "", &mut buffer)
                .unwrap_err(),
            Errno::ENOENT
        );
    }

    /// Verify every path-taking syscall resolves relative paths after `chdir`.
    #[test]
    fn all_path_syscalls_respect_chdir() {
        use crate::syscalls::tests::{create_directory, init_platform};
        use litebox_common_linux::{AccessFlags, AtFlags};

        let task = init_platform();
        create_directory(&task, "/cwd_test");

        task.sys_chdir("/cwd_test").unwrap();

        let fd = task
            .sys_open(
                "file.txt",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();

        task.sys_stat("file.txt").unwrap();
        task.sys_lstat("file.txt").unwrap();
        task.sys_faccessat(
            litebox_common_linux::AT_FDCWD,
            "file.txt",
            AccessFlags::F_OK,
            AtFlags::empty(),
        )
        .unwrap();

        task.sys_mkdirat(litebox_common_linux::AT_FDCWD, "subdir", 0o777)
            .unwrap();

        let fd = task
            .sys_openat(
                litebox_common_linux::AT_FDCWD,
                "subdir/inner.txt",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();

        task.sys_newfstatat(
            litebox_common_linux::AT_FDCWD,
            "subdir/inner.txt",
            AtFlags::empty(),
        )
        .unwrap();

        task.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            "subdir/inner.txt",
            AtFlags::empty(),
        )
        .unwrap();
        task.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            "subdir",
            AtFlags::AT_REMOVEDIR,
        )
        .unwrap();

        assert!(task.sys_stat("/cwd_test/file.txt").is_ok());
        assert_eq!(task.sys_stat("/cwd_test/subdir"), Err(Errno::ENOENT));
    }

    #[test]
    fn fchdir_changes_to_open_directory() {
        use crate::syscalls::tests::{create_directory, create_file, init_platform};

        let task = init_platform();
        create_directory(&task, "/fchdir_parent");
        create_directory(&task, "/fchdir_parent/child");
        create_file(&task, "/fchdir_parent/file", &[]);
        task.sys_symlinkat(
            "/fchdir_parent/child",
            litebox_common_linux::AT_FDCWD,
            "/fchdir_link",
        )
        .unwrap();
        let getcwd = || {
            let mut buf = [0u8; 256];
            let len = task.sys_getcwd(&mut buf).unwrap();
            String::from(core::str::from_utf8(&buf[..len - 1]).unwrap())
        };
        let open = |path, flags| i32::try_from(task.sys_open(path, flags, Mode::empty()).unwrap());

        // The new CWD is the directory's normalized path.
        let child = open(
            "/fchdir_parent/../fchdir_parent/./child",
            OFlags::RDONLY | OFlags::DIRECTORY,
        )
        .unwrap();
        task.sys_fchdir(child).unwrap();
        assert_eq!(getcwd(), "/fchdir_parent/child");

        // Relative paths then resolve against it.
        create_file(&task, "in_child", &[]);
        assert!(task.sys_stat("/fchdir_parent/child/in_child").is_ok());

        // An `O_PATH` descriptor works too.
        let parent = open("/fchdir_parent", OFlags::PATH).unwrap();
        task.sys_fchdir(parent).unwrap();
        assert_eq!(getcwd(), "/fchdir_parent");

        // Like Linux, a directory opened through a symlink gives its physical path.
        let link = open("/fchdir_link", OFlags::RDONLY).unwrap();
        task.sys_fchdir(link).unwrap();
        assert_eq!(getcwd(), "/fchdir_parent/child");

        // Descriptors that are not directories, or not open, leave the CWD alone.
        let file = open("/fchdir_parent/file", OFlags::RDONLY).unwrap();
        assert_eq!(task.sys_fchdir(file), Err(Errno::ENOTDIR));
        let (pipe, _) = task.do_pipe2(OFlags::empty(), |_, _| Ok(())).unwrap();
        assert_eq!(
            task.sys_fchdir(i32::try_from(pipe).unwrap()),
            Err(Errno::ENOTDIR)
        );
        task.sys_close(child).unwrap();
        assert_eq!(task.sys_fchdir(child), Err(Errno::EBADF));
        assert_eq!(task.sys_fchdir(-1), Err(Errno::EBADF));
        assert_eq!(getcwd(), "/fchdir_parent/child");
    }

    /// Like Linux, `fchdir` needs search permission on the directory as of the call, so a
    /// descriptor opened before the permission was removed does not get past it.
    #[test]
    fn fchdir_checks_search_permission_after_open() {
        use crate::syscalls::tests::{create_directory, init_platform};
        use litebox_common_linux::{AT_FDCWD, AtFlags};

        const USER: u16 = 1000;
        let mut task = init_platform();
        create_directory(&task, "/fchdir_perm");
        create_directory(&task, "/fchdir_perm/child");
        task.sys_fchownat(
            AT_FDCWD,
            "/fchdir_perm",
            USER.into(),
            USER.into(),
            AtFlags::empty(),
        )
        .unwrap();
        // Test tasks run as root, which can search any directory, so act as the owner instead.
        task.credentials = Arc::new(crate::syscalls::process::Credentials {
            uid: USER.into(),
            euid: USER.into(),
            gid: USER.into(),
            egid: USER.into(),
        });
        task.fs.borrow().context.write().set_acting_user(FileUser {
            user: USER,
            group: USER,
        });
        let getcwd = |task: &crate::Task<_>| {
            let mut buf = [0u8; 256];
            let len = task.sys_getcwd(&mut buf).unwrap();
            String::from(core::str::from_utf8(&buf[..len - 1]).unwrap())
        };

        for flags in [OFlags::RDONLY | OFlags::DIRECTORY, OFlags::PATH] {
            task.sys_fchmodat(AT_FDCWD, "/fchdir_perm", 0o700).unwrap();
            let fd = i32::try_from(task.sys_open("/fchdir_perm", flags, Mode::empty()).unwrap())
                .unwrap();
            task.sys_fchmodat(AT_FDCWD, "/fchdir_perm", 0o600).unwrap();

            assert_eq!(task.sys_fchdir(fd), Err(Errno::EACCES), "{flags:?}");
            assert_eq!(getcwd(&task), "/", "{flags:?}");
            // Paths relative to the descriptor need the same permission, which the walk checks.
            assert_eq!(
                task.sys_newfstatat(fd, "child", AtFlags::empty())
                    .map(|_| ()),
                Err(Errno::EACCES),
                "{flags:?}"
            );
            task.sys_close(fd).unwrap();
        }
    }

    #[test]
    fn fchdir_lets_root_search_any_directory() {
        use crate::syscalls::tests::{create_directory, init_platform};
        use litebox_common_linux::AT_FDCWD;

        let task = init_platform();
        create_directory(&task, "/fchdir_root");
        let fd = i32::try_from(
            task.sys_open(
                "/fchdir_root",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap(),
        )
        .unwrap();
        task.sys_fchmodat(AT_FDCWD, "/fchdir_root", 0o000).unwrap();

        task.sys_fchdir(fd).unwrap();
        let mut buf = [0u8; 256];
        let len = task.sys_getcwd(&mut buf).unwrap();
        assert_eq!(
            core::str::from_utf8(&buf[..len - 1]).unwrap(),
            "/fchdir_root"
        );
    }

    /// Verify every `*at` syscall resolves relative paths against a real `dirfd`, not the CWD.
    #[test]
    fn all_at_syscalls_respect_dirfd() {
        use crate::syscalls::tests::{create_directory, create_file, init_platform};
        use litebox_common_linux::{AccessFlags, AtFlags, StatxMask};

        let task = init_platform();
        create_directory(&task, "/dirfd_test");
        create_file(&task, "/dirfd_test/file.txt", b"data");
        let dirfd = i32::try_from(
            task.sys_open(
                "/dirfd_test",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap(),
        )
        .unwrap();
        // The CWD stays at `/`, so only `dirfd` can resolve these paths.
        assert_eq!(task.sys_stat("file.txt"), Err(Errno::ENOENT));

        let fd = task
            .sys_openat(dirfd, "file.txt", OFlags::RDONLY, Mode::empty())
            .unwrap();
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();
        task.sys_faccessat(dirfd, "file.txt", AccessFlags::R_OK, AtFlags::empty())
            .unwrap();
        let stat = task
            .sys_newfstatat(dirfd, "file.txt", AtFlags::empty())
            .unwrap();
        assert_eq!({ stat.st_size }, 4);
        let statx = task
            .sys_statx(dirfd, "file.txt", AtFlags::empty(), StatxMask::STATX_SIZE)
            .unwrap();
        assert_eq!(statx.stx_size, 4);
        task.sys_fchmodat(dirfd, "file.txt", 0o600).unwrap();
        assert_eq!(
            task.sys_stat("/dirfd_test/file.txt").unwrap().st_mode & 0o777,
            0o600
        );

        task.sys_mkdirat(dirfd, "subdir", 0o777).unwrap();
        task.sys_mknodat(
            dirfd,
            "subdir/node",
            InodeType::File as u32 | u32::from((Mode::RUSR | Mode::WUSR).bits()),
            0,
        )
        .unwrap();
        // `..` resolves from the directory, not the CWD.
        task.sys_symlinkat("file.txt", dirfd, "subdir/../link")
            .unwrap();
        let mut buf = [0u8; 64];
        let len = task.sys_readlinkat(dirfd, "link", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"file.txt");
        task.sys_renameat2(dirfd, "subdir/node", dirfd, "renamed", 0)
            .unwrap();
        assert!(task.sys_stat("/dirfd_test/renamed").is_ok());

        task.sys_unlinkat(dirfd, "renamed", AtFlags::empty())
            .unwrap();
        task.sys_unlinkat(dirfd, "link", AtFlags::empty()).unwrap();
        task.sys_unlinkat(dirfd, "subdir", AtFlags::AT_REMOVEDIR)
            .unwrap();
        assert_eq!(task.sys_stat("/dirfd_test/subdir"), Err(Errno::ENOENT));

        // A relative path needs a directory; an absolute path ignores `dirfd` entirely.
        let file = i32::try_from(
            task.sys_open("/dirfd_test/file.txt", OFlags::RDONLY, Mode::empty())
                .unwrap(),
        )
        .unwrap();
        let (pipe, _) = task.do_pipe2(OFlags::empty(), |_, _| Ok(())).unwrap();
        let pipe = i32::try_from(pipe).unwrap();
        for (dirfd, errno) in [
            (file, Errno::ENOTDIR),
            (pipe, Errno::ENOTDIR),
            (1000, Errno::EBADF),
            (-1, Errno::EBADF),
        ] {
            assert_eq!(
                task.sys_openat(dirfd, "file.txt", OFlags::RDONLY, Mode::empty()),
                Err(errno)
            );
            assert_eq!(
                task.sys_newfstatat(dirfd, "file.txt", AtFlags::empty())
                    .map(|_| ()),
                Err(errno)
            );
            assert!(
                task.sys_newfstatat(dirfd, "/dirfd_test/file.txt", AtFlags::empty())
                    .is_ok()
            );
        }
    }
}
