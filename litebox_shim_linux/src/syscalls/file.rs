// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of file related syscalls, e.g., `open`, `read`, `write`, etc.

use alloc::{
    collections::BTreeMap,
    ffi::CString,
    string::{String, ToString as _},
    sync::{Arc, Weak},
    vec,
};
use litebox::{
    event::{Events, wait::WaitError},
    fd::{EntryHandle, FdEnabledSubsystem, MetadataError, TypedFd},
    fs::{AccessCredentials, Mode, OFlags, SeekWhence},
    mm::vmem::PAGE_SIZE,
    net::Network,
    path,
    pipes::Pipes,
    platform::StdioStream,
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt as _},
};
use litebox_common_linux::{
    AccessFlags, AtFlags, EfdFlags, EpollCreateFlags, FcntlArg, FileDescriptorFlags, FileStat,
    FlockOperation, InodeType, InotifyInitFlags, InotifyMask, IoReadVec, IoWriteVec, IoctlArg,
    SockFlags, SockType, Statx, StatxMask, TimeParam, errno::Errno, signal::Signal,
};
use thiserror::Error;

use crate::{GlobalState, ShimFS, ShimPlatform, Task, UserPtr, UserPtrMut, syscalls::signal};
use core::{
    ffi::CStr,
    sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering},
};

#[derive(Clone, Copy)]
struct AccessUserInfo<'a> {
    user: u32,
    group: u32,
    supplementary_groups: &'a [u32],
}

impl From<litebox::fs::UserInfo> for AccessUserInfo<'static> {
    fn from(value: litebox::fs::UserInfo) -> Self {
        Self {
            user: u32::from(value.user),
            group: u32::from(value.group),
            supplementary_groups: &[],
        }
    }
}

impl<'a> AccessUserInfo<'a> {
    fn as_fs_credentials(self) -> AccessCredentials<'a> {
        AccessCredentials::new(self.user, self.group, self.supplementary_groups)
    }
}

static NEXT_MEMFD_ID: AtomicUsize = AtomicUsize::new(0);

/// Task state shared by `CLONE_FS`.
pub(crate) struct FsState<Platform: ShimPlatform> {
    umask: core::sync::atomic::AtomicU32,
    /// The current working directory, as a real (root-inclusive, see `root`) absolute path.
    ///
    /// Must end with a '/'.
    cwd: litebox::sync::RwLock<Platform, String>,
    /// The process's root directory (`chroot(2)`): the real absolute path beneath which every
    /// guest-visible absolute path is resolved (see `Task::map_absolute_to_root`). `/` until
    /// the first `chroot`; inherited by `fork`, shared by `CLONE_FS`, kept across `execve`.
    ///
    /// Must end with a '/'.
    root: litebox::sync::RwLock<Platform, String>,
}

impl<Platform: ShimPlatform> Clone for FsState<Platform> {
    fn clone(&self) -> Self {
        Self {
            umask: self.umask.load(Ordering::Relaxed).into(),
            cwd: litebox::sync::RwLock::new(self.cwd.read().clone()),
            root: litebox::sync::RwLock::new(self.root.read().clone()),
        }
    }
}

impl<Platform: ShimPlatform> FsState<Platform> {
    pub fn new() -> Self {
        Self {
            umask: (Mode::WGRP | Mode::WOTH).bits().into(),
            cwd: litebox::sync::RwLock::new(String::from("/")),
            root: litebox::sync::RwLock::new(String::from("/")),
        }
    }

    fn umask(&self) -> Mode {
        Mode::from_bits_retain(self.umask.load(Ordering::Relaxed))
    }
}

/// Task state shared by `CLONE_FILES`.
pub(crate) struct FilesState<Platform: ShimPlatform, FS: ShimFS> {
    /// The filesystem implementation, shared across tasks that share file system.
    pub(crate) fs: alloc::sync::Arc<FS>,
    pub(crate) raw_descriptor_store:
        litebox::sync::RwLock<Platform, litebox::fd::RawDescriptorStorage>,
    pub(crate) shared_file_mappings:
        litebox::sync::Mutex<Platform, alloc::vec::Vec<super::mm::SharedFileMapping<Platform, FS>>>,
    max_fd: AtomicUsize,
}

/// A reference to an open file description carried in an `SCM_RIGHTS` message.
///
/// The sender's descriptor number and descriptor-local flags are intentionally absent.
/// The strong entry handle keeps the description alive until it is installed by the
/// receiver or discarded with the message.
pub(crate) enum TransferredFd<Platform: ShimPlatform, FS: ShimFS> {
    Fs(EntryHandle<Platform, FS>),
    Network(EntryHandle<Platform, Network<Platform>>),
    Pipe(EntryHandle<Platform, Pipes<Platform>>),
    EventFd(EntryHandle<Platform, super::eventfd::EventfdSubsystem<Platform>>),
    Epoll(EntryHandle<Platform, super::epoll::EpollSubsystem<Platform, FS>>),
    Unix(EntryHandle<Platform, super::unix::UnixSocketSubsystem<Platform, FS>>),
    Netlink(EntryHandle<Platform, super::netlink::NetlinkSubsystem<Platform>>),
}

impl<Platform: ShimPlatform, FS: ShimFS> FilesState<Platform, FS> {
    pub(crate) fn new(fs: alloc::sync::Arc<FS>) -> Self {
        Self {
            fs,
            raw_descriptor_store: litebox::sync::RwLock::new(
                litebox::fd::RawDescriptorStorage::new(),
            ),
            shared_file_mappings: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
            max_fd: AtomicUsize::new(usize::MAX),
        }
    }

    pub(crate) fn set_max_fd(&self, max_fd: usize) {
        self.max_fd.store(max_fd, Ordering::Relaxed);
    }

    /// Returns the file-descriptor table a `fork`ed child starts with: every descriptor of this
    /// table, duplicated at the same number.
    ///
    /// "Duplicated" is `dup(2)`'s sense, which is `fork(2)`'s too: the new descriptor refers to
    /// the same open file description, so the file offset and status flags stay shared with the
    /// parent, while the descriptor itself -- and, crucially, the number it is filed under -- is
    /// the child's alone. That independence is the whole point: a shell between `fork` and `exec`
    /// rearranges fds 0/1/2 for the command it is about to run, and none of that may reach back
    /// into the shell.
    ///
    /// `FD_CLOEXEC` is per descriptor rather than per description, so it is copied explicitly.
    pub(crate) fn fork_copy(&self, task: &Task<Platform, FS>) -> Result<Self, Errno> {
        fn dup_into<Platform: ShimPlatform, FS: ShimFS, S: FdEnabledSubsystem>(
            task: &Task<Platform, FS>,
            new: &FilesState<Platform, FS>,
            fd: &TypedFd<S>,
            raw_fd: usize,
            cloexec: bool,
        ) -> Result<(), Errno> {
            let mut dt = task.global.litebox.descriptor_table_mut();
            let fd: TypedFd<S> = dt.duplicate(fd).ok_or(Errno::EBADF)?;
            note_pty_slave_descriptor::<Platform, FS, _>(&dt, &fd);
            if cloexec {
                let old = dt.set_fd_metadata(&fd, FileDescriptorFlags::FD_CLOEXEC);
                assert!(old.is_none());
            }
            drop(dt);
            let inserted = new
                .raw_descriptor_store
                .write()
                .fd_into_specific_raw_integer(fd, raw_fd);
            assert!(inserted, "the new table cannot already have fd {raw_fd}");
            Ok(())
        }

        let new = Self::new(self.fs.clone());
        new.set_max_fd(self.max_fd.load(Ordering::Relaxed));
        (*new.shared_file_mappings.lock()).clone_from(&self.shared_file_mappings.lock());
        let alive_fds: alloc::vec::Vec<usize> =
            self.raw_descriptor_store.read().iter_alive().collect();
        for raw_fd in alive_fds {
            let cloexec = get_file_descriptor_flags(raw_fd, &task.global, self)
                .is_ok_and(|flags| flags.contains(FileDescriptorFlags::FD_CLOEXEC));
            // Inotify fds aren't one of `run_on_raw_fd`'s hand-enumerated subsystem parameters
            // (see that function's doc comment, and the matching pre-check in `do_read`/
            // `do_close`): resolve them directly first so a live inotify fd (e.g. dbus-daemon's
            // own `inotify_init1()` result) can be duplicated into a forked child exactly like
            // every other fd, rather than `run_on_raw_fd`'s `EBADF` fallthrough aborting the
            // *entire* fork on the first such fd it meets -- live-verified: this exact gap
            // turned `dbus-daemon`'s `fork()` for D-Bus service activation into
            // `Errno::EBADF`, breaking every activated service (`xfconfd` included) the moment
            // inotify support gave dbus-daemon a real inotify fd to carry across the fork.
            if let Ok(inotify_fd) = self
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<super::inotify::InotifySubsystem<Platform>>(raw_fd)
            {
                dup_into(task, &new, &inotify_fd, raw_fd, cloexec)?;
                continue;
            }
            let dup_result = self.run_on_raw_fd(
                raw_fd,
                |fd| dup_into(task, &new, fd, raw_fd, cloexec),
                |fd| dup_into(task, &new, fd, raw_fd, cloexec),
                |fd| dup_into(task, &new, fd, raw_fd, cloexec),
                |fd| dup_into(task, &new, fd, raw_fd, cloexec),
                |fd| dup_into(task, &new, fd, raw_fd, cloexec),
                |fd| dup_into(task, &new, fd, raw_fd, cloexec),
                |fd| dup_into(task, &new, fd, raw_fd, cloexec),
            );
            if !matches!(dup_result, Ok(Ok(()))) {
                litebox_util_log::debug!(raw_fd:% = raw_fd, result:? = dup_result; "fork_copy: fd duplication failed");
            }
            dup_result??;
        }
        Ok(new)
    }

    // Returns Ok(raw_fd) if it fits within the max limits already set up; otherwise returns the
    // Err(typed_fd)
    pub(crate) fn insert_raw_fd<Subsystem: FdEnabledSubsystem>(
        &self,
        typed_fd: TypedFd<Subsystem>,
    ) -> Result<usize, TypedFd<Subsystem>> {
        // XXX(jb): should we try to somehow enforce that it is set at the smallest
        // available/unassigned FD number?
        let mut rds = self.raw_descriptor_store.write();
        let raw_fd = rds.fd_into_raw_integer(typed_fd);
        let max_fd = self.max_fd.load(Ordering::Relaxed);
        if raw_fd > max_fd {
            let orig = rds.fd_consume_raw_integer::<Subsystem>(raw_fd).unwrap();
            return Err(alloc::sync::Arc::into_inner(orig).unwrap());
        }
        Ok(raw_fd)
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Capture an open file description for an `SCM_RIGHTS` message without
    /// allocating a descriptor in either process.
    pub(crate) fn transfer_fd(&self, raw_fd: i32) -> Result<TransferredFd<Platform, FS>, Errno> {
        let raw_fd = usize::try_from(raw_fd).map_err(|_| Errno::EBADF)?;
        let files = self.files.borrow();
        let result = files.run_on_raw_fd(
            raw_fd,
            |fd| {
                self.global
                    .litebox
                    .descriptor_table()
                    .entry_handle(fd)
                    .map(TransferredFd::Fs)
                    .ok_or(Errno::EBADF)
            },
            |fd| {
                self.global
                    .litebox
                    .descriptor_table()
                    .entry_handle(fd)
                    .map(TransferredFd::Network)
                    .ok_or(Errno::EBADF)
            },
            |fd| {
                self.global
                    .litebox
                    .descriptor_table()
                    .entry_handle(fd)
                    .map(TransferredFd::Pipe)
                    .ok_or(Errno::EBADF)
            },
            |fd| {
                self.global
                    .litebox
                    .descriptor_table()
                    .entry_handle(fd)
                    .map(TransferredFd::EventFd)
                    .ok_or(Errno::EBADF)
            },
            |fd| {
                self.global
                    .litebox
                    .descriptor_table()
                    .entry_handle(fd)
                    .map(TransferredFd::Epoll)
                    .ok_or(Errno::EBADF)
            },
            |fd| {
                self.global
                    .litebox
                    .descriptor_table()
                    .entry_handle(fd)
                    .map(TransferredFd::Unix)
                    .ok_or(Errno::EBADF)
            },
            |fd| {
                self.global
                    .litebox
                    .descriptor_table()
                    .entry_handle(fd)
                    .map(TransferredFd::Netlink)
                    .ok_or(Errno::EBADF)
            },
        );
        result.flatten()
    }

    /// Install an `SCM_RIGHTS` open file description at the receiver's lowest
    /// available descriptor number.
    pub(crate) fn install_transferred_fd(
        &self,
        transferred: TransferredFd<Platform, FS>,
        cloexec: bool,
    ) -> Result<usize, Errno> {
        fn install<Platform, FS, Subsystem>(
            task: &Task<Platform, FS>,
            handle: EntryHandle<Platform, Subsystem>,
            cloexec: bool,
        ) -> Result<usize, Errno>
        where
            Platform: ShimPlatform,
            FS: ShimFS,
            Subsystem: FdEnabledSubsystem,
        {
            let typed = {
                let mut descriptors = task.global.litebox.descriptor_table_mut();
                let typed = descriptors.insert_handle(handle);
                note_pty_slave_descriptor::<Platform, FS, _>(&descriptors, &typed);
                if cloexec {
                    let old = descriptors.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                    assert!(old.is_none());
                }
                typed
            };
            task.files.borrow().insert_raw_fd(typed).map_err(|typed| {
                let _ = task.global.litebox.descriptor_table_mut().remove(&typed);
                Errno::EMFILE
            })
        }

        match transferred {
            TransferredFd::Fs(handle) => install(self, handle, cloexec),
            TransferredFd::Network(handle) => install(self, handle, cloexec),
            TransferredFd::Pipe(handle) => install(self, handle, cloexec),
            TransferredFd::EventFd(handle) => install(self, handle, cloexec),
            TransferredFd::Epoll(handle) => install(self, handle, cloexec),
            TransferredFd::Unix(handle) => install(self, handle, cloexec),
            TransferredFd::Netlink(handle) => install(self, handle, cloexec),
        }
    }
}

const F_SEAL_SEAL: u32 = 0x0001;
const F_SEAL_SHRINK: u32 = 0x0002;
const F_SEAL_GROW: u32 = 0x0004;
const F_SEAL_WRITE: u32 = 0x0008;
const F_SEAL_FUTURE_WRITE: u32 = 0x0010;
const F_SEAL_ALL: u32 =
    F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;

/// Entry metadata identifying an unlinked file created by `memfd_create(2)` and
/// storing its inode-scoped seal set.
#[derive(Debug)]
pub(crate) struct MemfdBacking {
    seals: AtomicU32,
    shared_futex_backing: litebox::mm::vmem::SharedFutexBacking,
}

impl Clone for MemfdBacking {
    fn clone(&self) -> Self {
        Self {
            seals: AtomicU32::new(self.seals()),
            shared_futex_backing: self.shared_futex_backing,
        }
    }
}

impl MemfdBacking {
    fn new(allow_sealing: bool) -> Self {
        Self {
            seals: AtomicU32::new(if allow_sealing { 0 } else { F_SEAL_SEAL }),
            shared_futex_backing: litebox::mm::vmem::SharedFutexBacking::new(),
        }
    }

    pub(crate) fn shared_futex_backing(&self) -> litebox::mm::vmem::SharedFutexBacking {
        self.shared_futex_backing
    }

    fn seals(&self) -> u32 {
        self.seals.load(Ordering::Acquire)
    }

    fn add_seals(&self, seals: u32) -> Result<(), Errno> {
        if seals & !F_SEAL_ALL != 0 {
            return Err(Errno::EINVAL);
        }
        let mut current = self.seals();
        loop {
            if current & F_SEAL_SEAL != 0 {
                return Err(Errno::EPERM);
            }
            match self.seals.compare_exchange_weak(
                current,
                current | seals,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(updated) => current = updated,
            }
        }
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Returns the stable backing identity for a regular file. Memfds carry their identity as
    /// descriptor metadata; ordinary files converge through their filesystem device/inode pair.
    /// With `create == false`, an ordinary file that has never had a shared mapping returns `None`.
    pub(crate) fn shared_file_backing(
        &self,
        fd: &TypedFd<FS>,
        create: bool,
    ) -> Option<litebox::mm::vmem::SharedFutexBacking> {
        if let Ok(backing) = self
            .global
            .litebox
            .descriptor_table()
            .with_metadata(fd, MemfdBacking::shared_futex_backing)
        {
            return Some(backing);
        }
        let status = self.files.borrow().fs.fd_file_status(fd).ok()?;
        if status.file_type != litebox::fs::FileType::RegularFile {
            return None;
        }
        let key = (status.node_info.dev, status.node_info.ino);
        let mut backings = self.global.shared_file_backings.lock();
        if let Some(backing) = backings.get(&key) {
            return Some(*backing);
        }
        if !create {
            return None;
        }
        let backing = litebox::mm::vmem::SharedFutexBacking::new();
        backings.insert(key, backing);
        Some(backing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PtySide {
    Master,
    Slave,
}

struct PtyState<Platform: ShimPlatform> {
    unlocked: AtomicBool,
    termios: litebox::sync::Mutex<Platform, litebox_common_linux::Termios>,
    winsize: litebox::sync::Mutex<Platform, litebox_common_linux::Winsize>,
    foreground_pgid: AtomicI32,
    /// Guest descriptors currently referring to the slave end, across every process and every
    /// `dup`/`fork`/`SCM_RIGHTS` copy; see [`PtyRegistry::release_slave_descriptor`].
    slave_descriptors: AtomicUsize,
    /// Linux's `TTY_OTHER_CLOSED` as the master sees it: set when the last slave descriptor
    /// closes, cleared when a slave is (re)opened. While set, a master `read` that would
    /// otherwise block reports end-of-file, which is what a terminal emulator waits for once
    /// its shell exits -- reversibly, so the slave path stays reopenable (Unix98 semantics).
    other_closed: AtomicBool,
}

impl<Platform: ShimPlatform> PtyState<Platform> {
    fn new(foreground_pgid: i32) -> Self {
        Self {
            unlocked: AtomicBool::new(false),
            termios: litebox::sync::Mutex::new(litebox_common_linux::Termios::default_cooked()),
            winsize: litebox::sync::Mutex::new(litebox_common_linux::Winsize {
                row: 24,
                col: 80,
                xpixel: 0,
                ypixel: 0,
            }),
            foreground_pgid: AtomicI32::new(foreground_pgid),
            slave_descriptors: AtomicUsize::new(0),
            other_closed: AtomicBool::new(false),
        }
    }
}

struct PendingPtySlave<Platform: ShimPlatform, FS: ShimFS> {
    /// The registry's own reference to the slave endpoint, cloned into every `/dev/pts/<n>`
    /// open. Kept alive until the master closes (`PtyMasterLease::drop` removes this entry),
    /// so the slave can be closed and reopened any number of times meanwhile.
    handle: EntryHandle<Platform, super::unix::UnixSocketSubsystem<Platform, FS>>,
    state: Arc<PtyState<Platform>>,
}

/// Unix98 pseudoterminals allocated by `/dev/ptmx`, shared by all guest tasks.
pub(crate) struct PtyRegistry<Platform: ShimPlatform, FS: ShimFS> {
    next_number: AtomicU32,
    slaves: litebox::sync::Mutex<Platform, BTreeMap<u32, PendingPtySlave<Platform, FS>>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> PtyRegistry<Platform, FS> {
    pub(crate) fn new() -> Self {
        Self {
            next_number: AtomicU32::new(0),
            slaves: litebox::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// One descriptor to slave `number` closed. When it was the last, mark the line as hung up
    /// *reversibly* (`PtyState::other_closed`): the registry keeps its own reference to the
    /// slave endpoint until the master closes, so a later `/dev/pts/<n>` open succeeds -- the
    /// Unix98 pattern a terminal emulator relies on (the parent opens the slave to probe it,
    /// closes it, then the session-leader child reopens it as its controlling terminal). The
    /// master's readers observe the hangup through `other_closed` (see `do_read`); shutting the
    /// socket pair down here, as an earlier revision did, made every reopen `EIO` for good.
    fn release_slave_descriptor(&self, number: u32, state: &PtyState<Platform>) {
        let _ = number;
        let previous =
            state
                .slave_descriptors
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
        if previous != Ok(1) {
            return;
        }
        state.other_closed.store(true, Ordering::Release);
    }
}

/// A descriptor was just created for `fd`'s open file description; if that is a pty slave end,
/// count it (see [`PtyRegistry::release_slave_descriptor`]).
fn note_pty_slave_descriptor<Platform: ShimPlatform, FS: ShimFS, S: FdEnabledSubsystem>(
    descriptors: &litebox::fd::Descriptors<Platform>,
    fd: &TypedFd<S>,
) {
    let _ = descriptors.with_metadata(fd, |endpoint: &PtyEndpoint<Platform, FS>| {
        if endpoint.side == PtySide::Slave {
            endpoint
                .state
                .slave_descriptors
                .fetch_add(1, Ordering::AcqRel);
        }
    });
}

struct PtyMasterLease<Platform: ShimPlatform, FS: ShimFS> {
    number: u32,
    registry: Weak<PtyRegistry<Platform, FS>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> Drop for PtyMasterLease<Platform, FS> {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.slaves.lock().remove(&self.number);
        }
    }
}

/// Entry metadata that turns an AF_UNIX connected stream endpoint into one side
/// of a pseudoterminal while retaining the socket subsystem's blocking I/O and
/// poll behavior.
struct PtyEndpoint<Platform: ShimPlatform, FS: ShimFS> {
    number: u32,
    side: PtySide,
    state: Arc<PtyState<Platform>>,
    master_lease: Option<Arc<PtyMasterLease<Platform, FS>>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> Clone for PtyEndpoint<Platform, FS> {
    fn clone(&self) -> Self {
        Self {
            number: self.number,
            side: self.side,
            state: self.state.clone(),
            master_lease: self.master_lease.clone(),
        }
    }
}

/// Path in the file system
#[derive(Debug)]
enum FsPath {
    /// Absolute path
    Absolute { path: CString },
    /// Current working directory
    Cwd,
    /// Path is relative to a file descriptor
    FdRelative { fd: u32, path: CString },
    /// Fd
    Fd(u32),
}

/// Maximum size of a file path
pub const PATH_MAX: usize = 4096;

/// The absolute path a file-backed fd was opened with, attached as entry metadata (see
/// [`litebox::fd::Descriptors::set_entry_metadata`]) so `openat`/`fstatat`-family syscalls can
/// resolve a path given relative to that fd (`dirfd`-relative resolution).
///
/// Entry metadata -- unlike fd metadata -- is shared across every descriptor that refers to the
/// same open file description, so a `dup`/`dup2`/`dup3`/`fcntl(F_DUPFD)` copy of a `dirfd`
/// resolves relative paths identically to the original without any extra propagation code.
#[derive(Clone, Debug)]
struct FdPath(CString);

/// The status and access-mode flags a filesystem fd was opened with, attached as entry metadata
/// for `/proc/<pid>/fdinfo`'s `flags:` line. (`fcntl(F_GETFL)` on a plain file still answers from
/// the `Backend` layer -- see `sys_fcntl`.)
#[derive(Clone, Copy, Debug)]
pub(super) struct FdOpenFlags(pub(super) OFlags);

/// The calling task's descriptor table as `/proc/<pid>/fd` and `fdinfo` describe it (see
/// [`litebox::fs::proc::ProcFdTable`]). Weak on both ends: it is published into the `/proc`
/// backend, which outlives any one task.
struct ProcFdView<Platform: ShimPlatform, FS: ShimFS> {
    global: Weak<GlobalState<Platform, FS>>,
    files: Weak<FilesState<Platform, FS>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> litebox::fs::proc::ProcFdTable
    for ProcFdView<Platform, FS>
{
    fn fds(&self) -> alloc::vec::Vec<u32> {
        self.files
            .upgrade()
            .map_or_else(alloc::vec::Vec::new, |files| {
                files
                    .raw_descriptor_store
                    .read()
                    .iter_alive()
                    .filter_map(|fd| u32::try_from(fd).ok())
                    .collect()
            })
    }

    fn entry(&self, fd: u32) -> Option<litebox::fs::proc::ProcFdEntry> {
        let global = self.global.upgrade()?;
        let files = self.files.upgrade()?;
        describe_raw_fd(&global, &files, usize::try_from(fd).ok()?)
    }
}

/// Every live guest process as `/proc` lists it (see [`litebox::fs::proc::ProcTaskTable`]):
/// a window onto the shim-wide process table. Weak, like [`ProcFdView`]: it is published into
/// the `/proc` backend, which outlives any one task.
struct ProcTaskView<Platform: ShimPlatform, FS: ShimFS> {
    global: Weak<GlobalState<Platform, FS>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> litebox::fs::proc::ProcTaskTable
    for ProcTaskView<Platform, FS>
{
    fn pids(&self) -> alloc::vec::Vec<i32> {
        self.global
            .upgrade()
            .map_or_else(alloc::vec::Vec::new, |global| global.processes.live_pids())
    }

    fn task(&self, pid: i32) -> Option<litebox::fs::proc::ProcTaskInfo> {
        self.global.upgrade()?.processes.proc_task_info(pid)
    }
}

/// How `/proc/<pid>/fd/<raw_fd>` and `fdinfo/<raw_fd>` describe one live descriptor: the path a
/// filesystem fd was opened by (the stdio device names for the fixed stdio fds), `/dev/ptmx` or
/// `/dev/pts/<n>` for a pseudoterminal end, and the kernel's `socket:[..]`/`pipe:[..]`/
/// `anon_inode:..` spellings for the rest -- numbered by the descriptor itself, since those
/// subsystems have no inode of their own here.
fn describe_raw_fd<Platform: ShimPlatform, FS: ShimFS>(
    global: &GlobalState<Platform, FS>,
    files: &FilesState<Platform, FS>,
    raw_fd: usize,
) -> Option<litebox::fs::proc::ProcFdEntry> {
    use litebox::fs::proc::ProcFdEntry;

    let anonymous = |target: String, flags: OFlags| ProcFdEntry {
        target,
        pos: 0,
        flags: flags.bits(),
        ino: raw_fd as u64,
    };
    if files
        .raw_descriptor_store
        .read()
        .fd_from_raw_integer::<super::inotify::InotifySubsystem<Platform>>(raw_fd)
        .is_ok()
    {
        return Some(anonymous(
            String::from("anon_inode:inotify"),
            OFlags::RDONLY,
        ));
    }
    files
        .run_on_raw_fd(
            raw_fd,
            |fd| {
                // The global descriptor-table guard is scoped to these metadata
                // lookups and dropped *before* the `fs` calls below: `seek` /
                // `fd_file_status` re-enter that same non-recursive `RwLock`
                // (layered's `fd_file_status` does its own `descriptor_table()`
                // lookup), and if a writer queued in between, the nested read
                // would wait behind the writer that is itself waiting on this
                // very guard -- a same-thread self-deadlock that then wedges
                // every fd operation guest-wide (live-verified: one leaked-era
                // read guard here froze a whole desktop boot once a concurrent
                // `open` needed `descriptor_table_mut`).
                let (target, flags) = {
                    let dt = global.litebox.descriptor_table();
                    let target = dt
                        .with_metadata(fd, |FdPath(path)| path.to_string_lossy().into_owned())
                        .or_else(|_| {
                            dt.with_metadata(fd, |stream: &StdioStream| {
                                String::from(match stream {
                                    StdioStream::Stdin => "/dev/stdin",
                                    StdioStream::Stdout => "/dev/stdout",
                                    StdioStream::Stderr => "/dev/stderr",
                                })
                            })
                        })
                        .or_else(|_| {
                            dt.with_metadata(fd, |_: &MemfdBacking| {
                                String::from("/memfd: (deleted)")
                            })
                        })
                        .unwrap_or_else(|_| String::from("anon_inode:[file]"));
                    let flags = dt
                        .with_metadata(fd, |crate::StdioStatusFlags(flags)| *flags)
                        .or_else(|_| dt.with_metadata(fd, |FdOpenFlags(flags)| *flags))
                        .unwrap_or(OFlags::RDONLY);
                    (target, flags)
                };
                ProcFdEntry {
                    target,
                    pos: files
                        .fs
                        .seek(fd, 0, SeekWhence::RelativeToCurrentOffset)
                        .map_or(0, |pos| pos as u64),
                    flags: (flags & OFlags::STATUS_FLAGS_MASK).bits(),
                    ino: files
                        .fs
                        .fd_file_status(fd)
                        .map_or(0, |status| status.node_info.ino as u64),
                }
            },
            |_fd| anonymous(alloc::format!("socket:[{raw_fd}]"), OFlags::RDWR),
            |fd| {
                anonymous(
                    alloc::format!("pipe:[{raw_fd}]"),
                    global.linux_pipe_status_flags(fd).unwrap_or(OFlags::RDWR),
                )
            },
            |_fd| anonymous(String::from("anon_inode:[eventfd]"), OFlags::RDWR),
            |_fd| anonymous(String::from("anon_inode:[eventpoll]"), OFlags::RDWR),
            |fd| {
                let target = {
                    let dt = global.litebox.descriptor_table();
                    dt.with_metadata(fd, |endpoint: &PtyEndpoint<Platform, FS>| {
                        match endpoint.side {
                            PtySide::Master => String::from("/dev/ptmx"),
                            PtySide::Slave => alloc::format!("/dev/pts/{}", endpoint.number),
                        }
                    })
                    .unwrap_or_else(|_| alloc::format!("socket:[{raw_fd}]"))
                };
                anonymous(target, OFlags::RDWR)
            },
            |_fd| anonymous(alloc::format!("socket:[{raw_fd}]"), OFlags::RDWR),
        )
        .ok()
}

/// Entry metadata tagging a `/dev/input/event*` fd with its evdev minor number, attached at
/// open time (see `insert_raw_file_fd`). Entry-scoped (not fd-scoped) so `dup`ed copies share
/// it, and reachable from epoll's descriptor-table-only context where no filesystem handle is
/// in scope.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InputEventMinor {
    pub(crate) minor: usize,
    /// `O_NONBLOCK`/`O_NDELAY` at open time. A later `fcntl(F_SETFL)` is NOT reflected here
    /// (the fs-backend SETFL arm has no per-entry flag store yet); every real evdev consumer
    /// observed (Xorg's evdev driver, libevdev, links2's mice path) picks blocking-ness at
    /// `open(2)` and never toggles it.
    pub(crate) nonblock: bool,
}

/// The evdev minor for `file`, if it was tagged as a `/dev/input/event*` device at open time --
/// the descriptor-table-only lookup epoll's poll path uses (it has `GlobalState` but no
/// filesystem access).
pub(crate) fn input_event_minor_of<Platform: ShimPlatform, FS: ShimFS>(
    global: &crate::GlobalState<Platform, FS>,
    file: &TypedFd<FS>,
) -> Option<usize> {
    input_event_meta_of(global, file).map(|m| m.minor)
}

/// [`input_event_minor_of`], with the open-time `O_NONBLOCK` flag alongside.
pub(crate) fn input_event_meta_of<Platform: ShimPlatform, FS: ShimFS>(
    global: &crate::GlobalState<Platform, FS>,
    file: &TypedFd<FS>,
) -> Option<InputEventMinor> {
    global
        .litebox
        .descriptor_table()
        .with_metadata(file, |m: &InputEventMinor| *m)
        .ok()
}

impl FsPath {
    /// Create a new `FsPath` from a dirfd and path.
    ///
    /// CWD-relative paths are resolved immediately to absolute paths.
    fn new(
        dirfd: i32,
        path: impl path::Arg,
        get_cwd: impl FnOnce() -> String,
    ) -> Result<Self, Errno> {
        let path_str = path.as_rust_str()?;
        if path_str.len() > PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let fs_path = if path_str.starts_with('/') {
            let cpath = path.to_c_str()?.into_owned();
            FsPath::Absolute { path: cpath }
        } else if dirfd >= 0 {
            let dirfd = u32::try_from(dirfd).expect("dirfd >= 0");
            if path_str.is_empty() {
                FsPath::Fd(dirfd)
            } else {
                let cpath = path.to_c_str()?.into_owned();
                FsPath::FdRelative {
                    fd: dirfd,
                    path: cpath,
                }
            }
        } else if dirfd == litebox_common_linux::AT_FDCWD {
            if path_str.is_empty() {
                FsPath::Cwd
            } else {
                // Resolve CWD-relative path to absolute.
                let mut abs = get_cwd();
                abs.push_str(path_str);
                let cpath = CString::new(abs).map_err(|_| Errno::EINVAL)?;
                FsPath::Absolute { path: cpath }
            }
        } else {
            return Err(Errno::EBADF);
        };
        Ok(fs_path)
    }
}

/// The `flock(2)`-holder identity used throughout this module: the guest-visible raw fd number.
///
/// This is the one place that convention is spelled out, so `sys_flock` and the close-time lock
/// release (in `do_close_and_replace`) can never drift apart on how a holder is identified. See
/// [`litebox::fs::flock::FlockTable`]'s doc comment for what this convention does and doesn't
/// model correctly (in particular, around `dup`).
fn flock_holder_for_raw_fd(raw_fd: usize) -> u64 {
    u64::try_from(raw_fd).unwrap_or(u64::MAX)
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn credentials_snapshot(&self) -> Arc<crate::syscalls::process::Credentials> {
        self.credentials.borrow().clone()
    }

    fn access_user_from_snapshot(
        credentials: &crate::syscalls::process::Credentials,
        effective: bool,
    ) -> AccessUserInfo<'_> {
        AccessUserInfo {
            user: if effective {
                credentials.euid
            } else {
                credentials.uid
            },
            group: if effective {
                credentials.egid
            } else {
                credentials.gid
            },
            supplementary_groups: credentials.supplementary_groups(),
        }
    }

    fn get_umask(&self) -> Mode {
        self.fs.borrow().umask()
    }

    /// `/proc` describes "the task looking at it" (see `litebox::fs::proc`): ahead of any lookup
    /// under it, hand the backend this task's identity (what `self`/`thread-self` name) and
    /// descriptor table, the table every other live process is looked up through, and the
    /// network's addresses.
    fn publish_proc_view(&self, path: &str) {
        if !path.starts_with("/proc") {
            return;
        }
        let Some(proc) = self.global.proc_handle.as_ref() else {
            return;
        };
        proc.set_caller(self.tid, self.proc_task_info());
        proc.set_task_table(Arc::new(ProcTaskView {
            global: Arc::downgrade(&self.global),
        }));
        proc.set_fd_table(Arc::new(ProcFdView {
            global: Arc::downgrade(&self.global),
            files: Arc::downgrade(&self.files.borrow()),
        }));
        let net = self.global.net.lock();
        proc.set_net_addrs(net.interface_ip(), net.gateway_ip());
    }

    /// The calling process's root directory (see `FsState::root`), with its trailing '/'.
    fn fs_root(&self) -> String {
        self.fs.borrow().root.read().clone()
    }

    /// The real path a guest-visible absolute path names beneath `root`. Outside a `chroot`
    /// (`root == "/"`) the path is returned untouched. Beneath one, `.` and `..` are collapsed
    /// lexically first, so `..` can never climb above the root -- Linux stops `..` at the root
    /// during its walk; collapsing ahead of the walk is what this shim already does for
    /// cwd-relative paths -- and then the root is prefixed. A trailing '/' is kept, since a
    /// backend may answer `ENOTDIR` differently for one.
    fn map_absolute_to_root(root: &str, guest_abs: &str) -> String {
        if root == "/" {
            return String::from(guest_abs);
        }
        let mut real = String::from(root.trim_end_matches('/'));
        let mut components: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
        for component in guest_abs.split('/') {
            match component {
                "" | "." => {}
                ".." => {
                    components.pop();
                }
                component => components.push(component),
            }
        }
        for component in components {
            real.push('/');
            real.push_str(component);
        }
        if real.is_empty() || (guest_abs.ends_with('/') && !real.ends_with('/')) {
            real.push('/');
        }
        real
    }

    /// The guest-visible spelling of the real path `real` beneath `root`: `real` with the root
    /// prefix stripped, or -- for a path outside the root, which a cwd left behind by a
    /// `chroot` without a `chdir` can be -- Linux's `(unreachable)` marker ahead of the real
    /// path, exactly as its `getcwd(2)` reports one.
    fn guest_visible_path(root: &str, real: &str) -> String {
        if root == "/" {
            return String::from(real);
        }
        let root_dir = root.trim_end_matches('/');
        match real.strip_prefix(root_dir) {
            Some("") => String::from("/"),
            Some(rest) if rest.starts_with('/') => String::from(rest),
            _ => alloc::format!("(unreachable){real}"),
        }
    }

    /// [`FsPath::new`] with `chroot` applied: absolute and cwd-relative paths resolve beneath
    /// the process's root the same way [`Self::resolve_path`] resolves them; `dirfd`-relative
    /// ones start from the descriptor's own real path (see [`Self::join_dir_relative_path`]).
    fn fs_path(&self, dirfd: i32, pathname: impl path::Arg) -> Result<FsPath, Errno> {
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        if self.fs_root() == "/" {
            return FsPath::new(dirfd, pathname, get_cwd);
        }
        let path_str = pathname.as_rust_str()?;
        if path_str.len() > PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        if path_str.starts_with('/')
            || (dirfd == litebox_common_linux::AT_FDCWD && !path_str.is_empty())
        {
            return Ok(FsPath::Absolute {
                path: self.resolve_path(path_str)?,
            });
        }
        FsPath::new(dirfd, pathname, get_cwd)
    }

    /// Handle syscall `chroot`: make `pathname` -- a directory the caller may search -- the
    /// calling process's root directory (see `FsState::root`). Linux gates this on
    /// `CAP_SYS_CHROOT`; LiteBox models no capability beyond root's, so an effective uid of 0.
    /// The working directory is left where it is, as Linux leaves it: a caller that wants it
    /// inside the new root follows up with `chdir("/")`.
    pub(crate) fn sys_chroot(&self, pathname: impl path::Arg) -> Result<(), Errno> {
        use litebox::fs::FileType;
        use litebox::fs::errors::{FileStatusError, PathError};

        let credentials = self.credentials_snapshot();
        if credentials.euid != 0 {
            return Err(Errno::EPERM);
        }
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        let resolved = self.resolve_path(pathname)?;
        let abs_path = self.resolve_syscall_path_as(fs_credentials, &resolved, true)?;
        match self
            .files
            .borrow()
            .fs
            .file_status_as(fs_credentials, abs_path.as_str())
        {
            Ok(status) => {
                if status.file_type != FileType::Directory {
                    return Err(Errno::ENOTDIR);
                }
                Self::do_access_mode(&status, caller, &AccessFlags::X_OK)?;
            }
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory)) => {
                return Err(Errno::ENOENT);
            }
            Err(FileStatusError::PathError(_)) => {
                return Err(Errno::EACCES);
            }
            Err(_) => {
                return Err(Errno::ENOENT);
            }
        }
        let mut root = abs_path;
        if !root.ends_with('/') {
            root.push('/');
        }
        *self.fs.borrow().root.write() = root;
        Ok(())
    }

    /// Resolve a path against the current working directory (and, beneath a `chroot`, the
    /// process's root -- see [`Self::map_absolute_to_root`]).
    pub(crate) fn resolve_path(&self, path: impl path::Arg) -> Result<CString, Errno> {
        let path_str = path.as_rust_str().map_err(|_| Errno::EINVAL)?;
        if path_str.is_empty() {
            return Err(Errno::ENOENT);
        }
        let root = self.fs_root();
        if path_str.starts_with('/') {
            CString::new(Self::map_absolute_to_root(&root, path_str)).map_err(|_| Errno::EINVAL)
        } else {
            let cwd = self.fs.borrow().cwd.read().clone();
            let guest_cwd = Self::guest_visible_path(&root, &cwd);
            if guest_cwd.starts_with('/') {
                // Rebase on the guest-visible cwd, so that `..` is floored at the root, then map
                // the result back beneath it (a no-op outside a `chroot`).
                let mut guest = guest_cwd;
                guest.push_str(path_str);
                CString::new(Self::map_absolute_to_root(&root, &guest)).map_err(|_| Errno::EINVAL)
            } else {
                // A cwd outside the root (`chroot` without `chdir`): Linux walks relative paths
                // from the real directory, where `..` never meets the root.
                let mut real = cwd;
                real.push_str(path_str);
                CString::new(real).map_err(|_| Errno::EINVAL)
            }
        }
    }

    /// Join a directory's absolute path with a path given relative to it, matching the semantics
    /// `openat`/`fstatat`-family syscalls need for a `dirfd`-relative lookup.
    fn join_dir_relative_path(
        &self,
        dir_path: &CString,
        relative: &CString,
    ) -> Result<CString, Errno> {
        let mut joined = dir_path.to_str().map_err(|_| Errno::EINVAL)?.to_string();
        if !joined.ends_with('/') {
            joined.push('/');
        }
        joined.push_str(relative.to_str().map_err(|_| Errno::EINVAL)?);
        // Beneath a `chroot`, `..` from a descriptor inside the root is floored at the root
        // the same way an absolute path's is (Linux stops `..` at the root during its walk); a
        // descriptor outside the root -- opened before the `chroot` -- walks the real tree.
        let root = self.fs_root();
        if root != "/" {
            let guest = Self::guest_visible_path(&root, &joined);
            if guest.starts_with('/') {
                joined = Self::map_absolute_to_root(&root, &guest);
            }
        }
        CString::new(joined).map_err(|_| Errno::EINVAL)
    }

    /// Resolve `dirfd` to the absolute path it was opened with (see [`FdPath`]), for
    /// `dirfd`-relative resolution. A closed descriptor is `EBADF`; a live descriptor from a
    /// non-filesystem subsystem (socket, pipe, eventfd, and so on) is `ENOTDIR`.
    fn resolve_dirfd_path(&self, fd: u32) -> Result<CString, Errno> {
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                fd as usize,
                |fd| {
                    let status = files.fs.fd_file_status(fd).map_err(Errno::from)?;
                    if status.file_type != litebox::fs::FileType::Directory {
                        return Err(Errno::ENOTDIR);
                    }
                    self.global
                        .litebox
                        .descriptor_table()
                        .with_metadata(fd, |path: &FdPath| path.0.clone())
                        .map_err(|error| match error {
                            MetadataError::ClosedFd => Errno::EBADF,
                            MetadataError::NoSuchMetadata => Errno::ENOTDIR,
                        })
                },
                |_fd| Err(Errno::ENOTDIR),
                |_fd| Err(Errno::ENOTDIR),
                |_fd| Err(Errno::ENOTDIR),
                |_fd| Err(Errno::ENOTDIR),
                |_fd| Err(Errno::ENOTDIR),
                |_fd| Err(Errno::ENOTDIR),
            )
            .flatten()
    }

    /// The absolute path `fd` was opened with, if one was recorded (see
    /// [`FdPath`]). Best-effort by design: sockets, pipes, and fds inherited
    /// without a path resolve to `None`. Used by the ELF mapping code to name
    /// guest images for fault symbolization.
    pub(crate) fn fd_abs_path(&self, fd: i32) -> Option<CString> {
        let raw_fd = usize::try_from(fd).ok()?;
        let files = self.files.borrow();
        let raw_descriptors = files.raw_descriptor_store.read();
        let file = raw_descriptors.fd_from_raw_integer::<FS>(raw_fd).ok()?;
        self.global
            .litebox
            .descriptor_table()
            .with_metadata(&file, |path: &FdPath| path.0.clone())
            .ok()
    }

    /// Handle `fchdir(2)` using the opened directory's entry-scoped path metadata.
    pub(crate) fn sys_fchdir(&self, fd: i32) -> Result<(), Errno> {
        use litebox::path::Arg as _;

        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let raw_fd = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        let files = self.files.borrow();
        let file = {
            let descriptors = files.raw_descriptor_store.read();
            if !descriptors.is_alive(raw_fd) {
                return Err(Errno::EBADF);
            }
            descriptors
                .fd_from_raw_integer::<FS>(raw_fd)
                .map_err(|error| match error {
                    litebox::fd::ErrRawIntFd::NotFound => Errno::EBADF,
                    litebox::fd::ErrRawIntFd::InvalidSubsystem => Errno::ENOTDIR,
                })?
        };
        let status = files
            .fs
            .fd_file_status(&file)
            .map_err(|error| match error {
                litebox::fs::errors::FileStatusError::ClosedFd => Errno::EBADF,
                _ => Errno::EIO,
            })?;
        if status.file_type != litebox::fs::FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        Self::do_access_mode(&status, caller, &AccessFlags::X_OK)?;
        let path = self
            .global
            .litebox
            .descriptor_table()
            .with_metadata(&file, |path: &FdPath| path.0.clone())
            .map_err(|error| match error {
                MetadataError::ClosedFd => Errno::EBADF,
                MetadataError::NoSuchMetadata => Errno::EIO,
            })?;
        drop(files);

        let mut cwd = path.normalized().map_err(|_| Errno::EINVAL)?;
        if cwd.is_empty() {
            cwd.push('/');
        } else if !cwd.starts_with('/') {
            return Err(Errno::EIO);
        }
        if !cwd.ends_with('/') {
            cwd.push('/');
        }
        *self.fs.borrow().cwd.write() = cwd;
        Ok(())
    }

    /// Resolve a path relative to a dirfd.
    ///
    /// Note that an empty path is not valid for this function, and will be rejected with `ENOENT`.
    fn resolve_path_at(&self, dirfd: i32, pathname: impl path::Arg) -> Result<CString, Errno> {
        let fs_path = self.fs_path(dirfd, pathname)?;
        match fs_path {
            FsPath::Absolute { path } => Ok(path),
            FsPath::Cwd | FsPath::Fd(_) => Err(Errno::ENOENT),
            FsPath::FdRelative { fd, path } => {
                let dir_path = self.resolve_dirfd_path(fd)?;
                self.join_dir_relative_path(&dir_path, &path)
            }
        }
    }

    /// Resolve a cwd/`dirfd`-joined path for a path-taking syscall other than `open`: every
    /// intermediate symlink is followed (a symlinked directory such as the image's
    /// `/var/run -> ../run` is transparent, as Linux's walk makes it), the final component only
    /// when `follow_final`, and a `..` right after an intermediate link applies to the link's
    /// target rather than being collapsed lexically ahead of link expansion. Without this,
    /// `lstat`/`readlink`/`mkdir`/`unlink`/`rename`/`symlink`/`chown`/`utimensat` answered
    /// `ENOTDIR` through any symlinked directory and `stat(/tmp/bindir/../etc/hosts)`
    /// (bindir -> /bin) answered `ENOENT`, while `open` of the same names worked.
    fn resolve_syscall_path_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: &CString,
        follow_final: bool,
    ) -> Result<String, Errno> {
        self.resolve_path_symlinks_with_final_as(
            credentials,
            path.to_str().map_err(|_| Errno::EINVAL)?,
            follow_final,
        )
    }

    fn do_open_raw_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<TypedFd<FS>, litebox::fs::errors::OpenError> {
        let mode = mode & !self.get_umask();
        self.files
            .borrow()
            .fs
            .open_as(credentials, path, flags - OFlags::CLOEXEC, mode)
    }

    fn do_open_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<TypedFd<FS>, Errno> {
        self.do_open_raw_as(credentials, path, flags, mode)
            .map_err(Errno::from)
    }

    /// Linux caps a single path resolution at `MAXSYMLINKS` (40) followed links.
    const MAX_SYMLINK_HOPS: usize = 40;

    /// Resolve every symbolic link on an already-cwd-resolved absolute `path`,
    /// per `path_resolution(7)`: walk it component by component and, whenever a
    /// component is a symlink, splice in its target (an absolute target restarts
    /// from `/`, a relative one is interpreted from the directory that contains
    /// the link) and keep going -- so a symlink used as an *intermediate*
    /// directory component is followed, not only the final one.
    ///
    /// A component that does not exist stops resolution and is returned verbatim
    /// with whatever is still pending, so `O_CREAT` can still create a missing
    /// final component and a genuinely missing path yields `ENOENT` from the real
    /// operation rather than here. `ELOOP` once more than
    /// [`Self::MAX_SYMLINK_HOPS`] links are followed.
    ///
    /// `..` components stay in the pending queue until the walk reaches them, so
    /// one immediately after an intermediate symlink is applied to the followed
    /// target rather than being collapsed against the link's lexical parent.
    fn resolve_path_symlinks_with_final_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: &str,
        follow_final: bool,
    ) -> Result<String, Errno> {
        use alloc::collections::VecDeque;
        use alloc::vec::Vec;
        use litebox::fs::FileType;
        use litebox::fs::errors::{FileStatusError, PathError};

        self.publish_proc_view(path);

        let into_components = |s: &str| -> VecDeque<String> {
            s.split('/')
                .filter(|component| !component.is_empty() && *component != ".")
                .map(String::from)
                .collect()
        };
        // Beneath a `chroot`, `..` stops at the root and an absolute link target restarts from
        // it, exactly as Linux's walk does against `nd->root`. Outside one the root is `/`,
        // whose component list is empty, and both rules reduce to the plain ones.
        let root_components: Vec<String> = into_components(&self.fs_root()).into();
        let mut pending = into_components(path);
        let mut resolved: Vec<String> = Vec::new();
        let mut hops = 0usize;

        while let Some(name) = pending.pop_front() {
            if name == ".." {
                // Applied to the already-resolved prefix -- i.e. after any symlink
                // in it was followed -- which is the correct base component.
                if resolved != root_components {
                    resolved.pop();
                }
                continue;
            }
            let mut candidate = String::new();
            for component in &resolved {
                candidate.push('/');
                candidate.push_str(component);
            }
            candidate.push('/');
            candidate.push_str(&name);

            let file_type = match self
                .files
                .borrow()
                .fs
                .file_status_as(credentials, candidate.as_str())
            {
                Ok(status) => status.file_type,
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => {
                    // This component does not exist: keep it and the rest verbatim
                    // and let the real operation decide (ENOENT vs O_CREAT).
                    resolved.push(name);
                    resolved.extend(pending);
                    return Ok(Self::join_absolute(&resolved));
                }
                Err(e) => return Err(Errno::from(e)),
            };

            // A `/proc/<pid>/fd/<n>` magic link names an *open file*, not a path: following it
            // must land on that file even when its `readlink` text is `socket:[7]`,
            // `anon_inode:[eventfd]` or a since-unlinked temporary (Chromium's shared-memory
            // files). Stop here with the magic path itself; `stat`/`open` of such a path answer
            // from the descriptor (see `Task::proc_fd_magic_link`). An intermediate use
            // (`/proc/self/fd/3/child`, a directory fd) is followed by text as before.
            if file_type == FileType::SymLink
                && pending.is_empty()
                && self.proc_fd_magic_link(&candidate).is_some()
            {
                resolved.push(name);
                continue;
            }
            if file_type == FileType::SymLink && (follow_final || !pending.is_empty()) {
                hops += 1;
                if hops > Self::MAX_SYMLINK_HOPS {
                    return Err(Errno::ELOOP);
                }
                let target = self
                    .files
                    .borrow()
                    .fs
                    .readlink_as(credentials, candidate.as_str())
                    .map_err(Errno::from)?;
                if target.is_empty() {
                    return Err(Errno::ENOENT);
                }
                // An absolute target restarts resolution from the root; a relative
                // one continues from `resolved` (the link's directory, since the
                // link's own name was not pushed).
                if target.starts_with('/') {
                    resolved.clone_from(&root_components);
                }
                for component in target
                    .split('/')
                    .filter(|component| !component.is_empty() && *component != ".")
                    .rev()
                {
                    pending.push_front(String::from(component));
                }
            } else {
                resolved.push(name);
            }
        }
        Ok(Self::join_absolute(&resolved))
    }

    /// Join resolved path components into an absolute path (`/` when empty).
    fn join_absolute(components: &[String]) -> String {
        if components.is_empty() {
            return String::from("/");
        }
        let mut path = String::new();
        for component in components {
            path.push('/');
            path.push_str(component);
        }
        path
    }

    /// Apply `open(2)` default symlink-following to an already-resolved absolute
    /// path. Two flag combinations keep only the final link opaque: `O_NOFOLLOW` (the backend
    /// answers `ELOOP`) and `O_CREAT|O_EXCL` (an existing final link is `EEXIST`, never followed).
    /// Intermediate links are followed in every mode, as Linux requires.
    pub(crate) fn follow_open_path(&self, path: CString, flags: OFlags) -> Result<CString, Errno> {
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        self.follow_open_path_as(caller.as_fs_credentials(), path, flags)
    }

    fn follow_open_path_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: CString,
        flags: OFlags,
    ) -> Result<CString, Errno> {
        let follow_final =
            !flags.contains(OFlags::NOFOLLOW) && !flags.contains(OFlags::CREAT | OFlags::EXCL);
        let resolved = self.resolve_path_symlinks_with_final_as(
            credentials,
            path.to_str().map_err(|_| Errno::EINVAL)?,
            follow_final,
        )?;
        CString::new(resolved).map_err(|_| Errno::EINVAL)
    }

    fn do_openat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<TypedFd<FS>, Errno> {
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        let path = self.resolve_path_at(dirfd, pathname)?;
        let path = self.follow_open_path_as(fs_credentials, path, flags)?;
        self.do_open_as(fs_credentials, path, flags, mode)
    }

    /// Insert a freshly-opened file into the raw fd table, optionally recording the absolute
    /// path it was opened with (see [`FdPath`]) so it can later serve as a `dirfd` for
    /// `openat`/`fstatat`-family syscalls.
    fn insert_raw_file_fd(
        &self,
        file: TypedFd<FS>,
        flags: OFlags,
        path: Option<CString>,
    ) -> Result<u32, Errno> {
        if flags.contains(OFlags::CLOEXEC) {
            let None = self
                .global
                .litebox
                .descriptor_table_mut()
                .set_fd_metadata(&file, FileDescriptorFlags::FD_CLOEXEC)
            else {
                unreachable!()
            };
        }
        if let Some(path) = path {
            let old = self
                .global
                .litebox
                .descriptor_table_mut()
                .set_entry_metadata(&file, FdPath(path));
            debug_assert!(old.is_none());
        }
        let old = self
            .global
            .litebox
            .descriptor_table_mut()
            .set_entry_metadata(&file, FdOpenFlags(flags & OFlags::STATUS_FLAGS_MASK));
        debug_assert!(old.is_none());
        // Tag `/dev/input/event*` fds with their evdev minor at open time (recognized by the
        // input-core rdev major, same idea as `is_stdio`'s major check), so the read/ioctl/poll
        // paths -- epoll in particular, which has no filesystem access, only the descriptor
        // table -- can identify them by metadata lookup alone. Mirrors the `StdioStream`
        // metadata the stdio fds carry.
        {
            let files = self.files.borrow();
            if !flags.contains(OFlags::PATH)
                && let Ok(status) = files.fs.fd_file_status(&file)
                && status.file_type == litebox::fs::FileType::CharacterDevice
                && let Some(rdev) = status.node_info.rdev
                && rdev.get() >> 8 == litebox::fs::devices::INPUT_MAJOR
            {
                let old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_entry_metadata(
                        &file,
                        InputEventMinor {
                            minor: rdev.get() & 0xff,
                            nonblock: flags.intersects(OFlags::NONBLOCK | OFlags::NDELAY),
                        },
                    );
                debug_assert!(old.is_none());
            }
        }
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(file).map_err(|file| {
            if files.fs.close(&file).is_err() {
                Errno::EIO
            } else {
                Errno::EMFILE
            }
        })?;
        Ok(u32::try_from(raw_fd).unwrap())
    }

    /// Handle syscall `umask`
    pub(crate) fn sys_umask(&self, new_mask: u32) -> Mode {
        let new_mask = Mode::from_bits_truncate(new_mask) & (Mode::RWXU | Mode::RWXG | Mode::RWXO);
        let old_mask = self
            .fs
            .borrow()
            .umask
            .swap(new_mask.bits(), Ordering::Relaxed);
        Mode::from_bits_retain(old_mask)
    }

    /// Open `/dev/ptmx`, one allocated `/dev/pts/<n>` endpoint, or the calling process's
    /// `/dev/tty` alias. Returning `None` means the path is not in the pseudoterminal namespace.
    fn open_pty_path(&self, path: &CStr, flags: OFlags) -> Option<Result<u32, Errno>> {
        if flags.contains(OFlags::PATH) {
            return None;
        }
        let Ok(path) = path.to_str() else {
            return Some(Err(Errno::EINVAL));
        };
        if path == "/dev/ptmx" {
            return Some(self.open_ptmx(flags));
        }
        if path == "/dev/tty" {
            return Some(self.open_controlling_tty(flags));
        }
        let number = path
            .strip_prefix("/dev/pts/")
            .and_then(|number| number.parse::<u32>().ok())?;
        Some(self.open_pty_slave(number, flags))
    }

    fn open_ptmx(&self, flags: OFlags) -> Result<u32, Errno> {
        let mut socket_flags = SockFlags::empty();
        socket_flags.set(
            SockFlags::NONBLOCK,
            flags.intersects(OFlags::NONBLOCK | OFlags::NDELAY),
        );
        let (master, slave) =
            super::unix::UnixSocket::new_connected_pair(SockType::Stream, socket_flags, self)
                .ok_or(Errno::ENOSPC)?;
        let number = self
            .global
            .pty_registry
            .next_number
            .fetch_add(1, Ordering::Relaxed);
        let state = Arc::new(PtyState::new(self.process().process_group_id()));
        let lease = Arc::new(PtyMasterLease {
            number,
            registry: Arc::downgrade(&self.global.pty_registry),
        });

        let (master_fd, slave_handle) = {
            let mut descriptors = self.global.litebox.descriptor_table_mut();
            let master_fd =
                descriptors.insert::<super::unix::UnixSocketSubsystem<Platform, FS>>(master);
            let slave_fd =
                descriptors.insert::<super::unix::UnixSocketSubsystem<Platform, FS>>(slave);
            let old = descriptors.set_entry_metadata(
                &master_fd,
                PtyEndpoint {
                    number,
                    side: PtySide::Master,
                    state: state.clone(),
                    master_lease: Some(lease),
                },
            );
            debug_assert!(old.is_none());
            let old = descriptors.set_entry_metadata(
                &slave_fd,
                PtyEndpoint::<Platform, FS> {
                    number,
                    side: PtySide::Slave,
                    state: state.clone(),
                    master_lease: None,
                },
            );
            debug_assert!(old.is_none());
            if flags.contains(OFlags::CLOEXEC) {
                let old = descriptors.set_fd_metadata(&master_fd, FileDescriptorFlags::FD_CLOEXEC);
                debug_assert!(old.is_none());
            }
            let slave_handle = descriptors.entry_handle(&slave_fd).unwrap();
            let removed = descriptors.remove(&slave_fd);
            debug_assert!(removed.is_none());
            (master_fd, slave_handle)
        };
        let old = self.global.pty_registry.slaves.lock().insert(
            number,
            PendingPtySlave {
                handle: slave_handle,
                state,
            },
        );
        debug_assert!(old.is_none());

        let files = self.files.borrow();
        files
            .insert_raw_fd(master_fd)
            .map(u32::try_from)
            .map_err(|master_fd| {
                let _ = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .remove(&master_fd);
                Errno::EMFILE
            })
            .and_then(|raw| raw.map_err(|_| Errno::EMFILE))
    }

    fn open_controlling_tty(&self, flags: OFlags) -> Result<u32, Errno> {
        match self.process().controlling_pty() {
            Some(number) => self
                .open_pty_slave(number, flags | OFlags::NOCTTY)
                .map_err(|error| {
                    if error == Errno::ENOENT {
                        Errno::ENXIO
                    } else {
                        error
                    }
                }),
            None => self.open_host_terminal(flags),
        }
    }

    /// `/dev/tty` for a process whose controlling terminal is the host's own stdio terminal --
    /// the initial task and whatever it forked without a pseudoterminal in between: the
    /// `/dev/tty` device node, tagged like the fixed stdio fds so `TCGETS`/`TIOCGWINSZ`/... answer
    /// on it. `ENXIO` when none of the runner's stdio streams is a terminal, as on Linux for a
    /// process without a controlling terminal. `setsid()` is not tracked here: a session leader
    /// that gave the host terminal up still reaches it, where Linux would say `ENXIO`.
    fn open_host_terminal(&self, flags: OFlags) -> Result<u32, Errno> {
        let stream = [StdioStream::Stdin, StdioStream::Stdout, StdioStream::Stderr]
            .into_iter()
            .find(|stream| self.global.platform.is_a_tty(*stream))
            .ok_or(Errno::ENXIO)?;
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let path = CString::from(c"/dev/tty");
        let file = self.do_open_as(
            caller.as_fs_credentials(),
            path.clone(),
            flags,
            Mode::empty(),
        )?;
        {
            let mut status = OFlags::RDWR;
            status.set(
                OFlags::NONBLOCK,
                flags.intersects(OFlags::NONBLOCK | OFlags::NDELAY),
            );
            let mut dt = self.global.litebox.descriptor_table_mut();
            let old = dt.set_entry_metadata(&file, stream);
            debug_assert!(old.is_none());
            let old = dt.set_entry_metadata(&file, crate::StdioStatusFlags(status));
            debug_assert!(old.is_none());
        }
        self.insert_raw_file_fd(file, flags, Some(path))
    }

    fn open_pty_slave(&self, number: u32, flags: OFlags) -> Result<u32, Errno> {
        let (handle, state) = {
            let slaves = self.global.pty_registry.slaves.lock();
            let slave = slaves.get(&number).ok_or(Errno::ENOENT)?;
            (slave.handle.clone(), slave.state.clone())
        };
        if !state.unlocked.load(Ordering::Acquire) {
            return Err(Errno::EIO);
        }
        let slave_fd = {
            let mut descriptors = self.global.litebox.descriptor_table_mut();
            let slave_fd = descriptors.insert_handle(handle);
            if flags.contains(OFlags::CLOEXEC) {
                let old = descriptors.set_fd_metadata(&slave_fd, FileDescriptorFlags::FD_CLOEXEC);
                debug_assert!(old.is_none());
            }
            slave_fd
        };
        let files = self.files.borrow();
        let raw = files
            .insert_raw_fd(slave_fd)
            .map(u32::try_from)
            .map_err(|slave_fd| {
                let _ = self.global.litebox.descriptor_table_mut().remove(&slave_fd);
                Errno::EMFILE
            })
            .and_then(|raw| raw.map_err(|_| Errno::EMFILE))?;
        state.slave_descriptors.fetch_add(1, Ordering::AcqRel);
        // A (re)opened slave un-hangs the line for the master (Linux clears
        // `TTY_OTHER_CLOSED` in `pty_open`).
        state.other_closed.store(false, Ordering::Release);
        if !flags.contains(OFlags::NOCTTY) {
            // Opening a slave without O_NOCTTY acquires it only for a session leader that has no
            // controlling terminal. Failure to acquire never makes the open itself fail. Only a
            // new acquisition makes the caller's process group the terminal's foreground group;
            // reopening an existing controlling terminal must not reset a later TIOCSPGRP choice.
            if self.process().acquire_controlling_pty(self.pid, number) == Ok(true) {
                state
                    .foreground_pgid
                    .store(self.process().process_group_id(), Ordering::Release);
            }
        }
        Ok(raw)
    }

    fn pty_endpoint(
        &self,
        fd: &TypedFd<super::unix::UnixSocketSubsystem<Platform, FS>>,
    ) -> Option<PtyEndpoint<Platform, FS>> {
        self.global
            .litebox
            .descriptor_table()
            .with_metadata(fd, |endpoint: &PtyEndpoint<Platform, FS>| endpoint.clone())
            .ok()
    }

    /// Handle syscall `openat`
    pub fn sys_openat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<u32, Errno> {
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        let flags = flags.normalized_for_open();
        let path = self.resolve_path_at(dirfd, pathname)?;
        let path = self.follow_open_path_as(fs_credentials, path, flags)?;
        let result = match self.open_pty_path(&path, flags) {
            Some(result) => result,
            None => self
                .do_open_as(fs_credentials, path.clone(), flags, mode)
                .and_then(|file| self.insert_raw_file_fd(file, flags, Some(path.clone()))),
        };
        // The `req=Openat` trace line above this only shows the user pointer; the resolved
        // path with the outcome is what a syscall-level diagnosis actually needs.
        litebox_util_log::trace!(path:? = path, result:? = result; "openat");
        result
    }

    /// Handle syscall `ftruncate`
    /// Handle syscall `fadvise64` (`posix_fadvise`).
    ///
    /// Every `POSIX_FADV_*` advice is a readahead/page-cache hint, and memory-backed files have
    /// neither, so the accepted advice is a no-op; the argument checks are Linux's
    /// `ksys_fadvise64_64` ones (`EBADF`, `EINVAL` for unknown advice or a negative length,
    /// `ESPIPE` for a pipe or FIFO).
    pub(crate) fn sys_fadvise64(
        &self,
        fd: i32,
        _offset: usize,
        len: usize,
        advice: i32,
    ) -> Result<(), Errno> {
        // POSIX_FADV_NORMAL..=POSIX_FADV_NOREUSE (0..=5); aarch64 uses the generic numbering.
        if !(0..=5).contains(&advice) {
            return Err(Errno::EINVAL);
        }
        if len.reinterpret_as_signed() < 0 {
            return Err(Errno::EINVAL);
        }
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                raw_fd,
                |_fd| Ok(()),
                |_fd| Err(Errno::ESPIPE),
                |_fd| Err(Errno::ESPIPE),
                |_fd| Ok(()),
                |_fd| Ok(()),
                |_fd| Err(Errno::ESPIPE),
                |_fd| Err(Errno::ESPIPE),
            )
            .flatten()
    }

    /// Handle syscall `fallocate`.
    ///
    /// The guest filesystems here are memory-backed like `tmpfs`, and this models exactly
    /// `tmpfs`'s `fallocate`: mode `0` extends the file (zero-filled) when the range reaches past
    /// EOF and is otherwise a no-op (space is always "allocated"); `FALLOC_FL_KEEP_SIZE` alone is
    /// a no-op; `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE` zeroes the in-file part of the range;
    /// every other mode (`ZERO_RANGE`, `COLLAPSE_RANGE`, `INSERT_RANGE`, `UNSHARE_RANGE`) is
    /// `EOPNOTSUPP`, as `tmpfs` reports it. Argument checks are Linux's `vfs_fallocate` ones.
    pub(crate) fn sys_fallocate(
        &self,
        fd: i32,
        mode: i32,
        offset: usize,
        len: usize,
    ) -> Result<(), Errno> {
        const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
        const FALLOC_FL_PUNCH_HOLE: i32 = 0x02;
        const FALLOC_FL_NO_HIDE_STALE: i32 = 0x04;
        const FALLOC_FL_COLLAPSE_RANGE: i32 = 0x08;
        const FALLOC_FL_ZERO_RANGE: i32 = 0x10;
        const FALLOC_FL_INSERT_RANGE: i32 = 0x20;
        const FALLOC_FL_UNSHARE_RANGE: i32 = 0x40;
        const KNOWN: i32 = FALLOC_FL_KEEP_SIZE
            | FALLOC_FL_PUNCH_HOLE
            | FALLOC_FL_NO_HIDE_STALE
            | FALLOC_FL_COLLAPSE_RANGE
            | FALLOC_FL_ZERO_RANGE
            | FALLOC_FL_INSERT_RANGE
            | FALLOC_FL_UNSHARE_RANGE;

        let offset = usize::try_from(offset.reinterpret_as_signed()).map_err(|_| Errno::EINVAL)?;
        let len = usize::try_from(len.reinterpret_as_signed()).map_err(|_| Errno::EINVAL)?;
        if len == 0 {
            return Err(Errno::EINVAL);
        }
        let end = offset.checked_add(len).ok_or(Errno::EFBIG)?;
        if mode & !KNOWN != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        // `PUNCH_HOLE` must come with `KEEP_SIZE`, and the exclusive modes cannot be combined.
        if mode & FALLOC_FL_PUNCH_HOLE != 0 && mode & FALLOC_FL_KEEP_SIZE == 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let exclusive = mode
            & (FALLOC_FL_PUNCH_HOLE
                | FALLOC_FL_COLLAPSE_RANGE
                | FALLOC_FL_ZERO_RANGE
                | FALLOC_FL_INSERT_RANGE);
        if exclusive.count_ones() > 1 {
            return Err(Errno::EINVAL);
        }
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        // Linux: the fd must be open for writing (`EBADF`), and be a regular file (`ENODEV`)
        // or a directory (`EISDIR`); pipes and sockets are `ESPIPE`.
        let files = self.files.borrow();
        let (open_flags, status) = files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    let flags = self
                        .global
                        .litebox
                        .descriptor_table()
                        .with_metadata(fd, |FdOpenFlags(flags)| *flags)
                        .map_err(|_| Errno::EBADF)?;
                    let status = files.fs.fd_file_status(fd).map_err(Errno::from)?;
                    Ok((flags, status))
                },
                |_fd| Err(Errno::ESPIPE),
                |_fd| Err(Errno::ESPIPE),
                |_fd| Err(Errno::ENODEV),
                |_fd| Err(Errno::ENODEV),
                |_fd| Err(Errno::ESPIPE),
                |_fd| Err(Errno::ESPIPE),
            )
            .flatten()?;
        if open_flags.contains(OFlags::PATH)
            || !open_flags.intersects(OFlags::WRONLY | OFlags::RDWR)
        {
            return Err(Errno::EBADF);
        }
        match status.file_type {
            litebox::fs::FileType::RegularFile => {}
            litebox::fs::FileType::Directory => return Err(Errno::EISDIR),
            _ => return Err(Errno::ENODEV),
        }
        drop(files);
        let size = status.size;
        if mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE | FALLOC_FL_UNSHARE_RANGE) != 0
            || mode & FALLOC_FL_ZERO_RANGE != 0
        {
            // `tmpfs` (`shmem_fallocate`) only implements the plain and hole-punching modes.
            return Err(Errno::EOPNOTSUPP);
        }
        if mode & FALLOC_FL_PUNCH_HOLE != 0 {
            // Zero the part of the range that lies inside the file; the file size is untouched.
            let stop = end.min(size);
            let zeros = vec![0u8; PAGE_SIZE];
            let mut cur = offset;
            while cur < stop {
                let chunk = (stop - cur).min(zeros.len());
                let written = self.sys_write(fd, &zeros[..chunk], Some(cur))?;
                if written == 0 {
                    return Err(Errno::EIO);
                }
                cur += written;
            }
            return Ok(());
        }
        if mode & FALLOC_FL_KEEP_SIZE == 0 && end > size {
            // Plain preallocation past EOF grows the file, zero-filled -- the same path as
            // `ftruncate`, including zeroing any shared file mapping of the new tail.
            self.sys_ftruncate(fd, end)?;
        }
        Ok(())
    }

    pub(crate) fn sys_ftruncate(&self, fd: i32, length: usize) -> Result<(), Errno> {
        let length = usize::try_from(length.reinterpret_as_signed()).map_err(|_| Errno::EINVAL)?;
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    let old_size = files.fs.fd_file_status(fd).map_err(Errno::from)?.size;
                    let shared_backing = self.shared_file_backing(fd, false);
                    files.fs.truncate(fd, length, false).map_err(Errno::from)?;
                    if let Some(backing) = shared_backing
                        && old_size != length
                    {
                        self.global
                            .platform
                            .zero_shared_pages(
                                backing.identity(),
                                old_size.min(length)..old_size.max(length),
                            )
                            .map_err(|_| Errno::EIO)?;
                    }
                    Ok(())
                },
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
            )
            .flatten()
    }

    /// Handle syscall `memfd_create`.
    pub(crate) fn sys_memfd_create(&self, name: &CStr, flags: u32) -> Result<u32, Errno> {
        const MFD_CLOEXEC: u32 = 0x0001;
        const MFD_ALLOW_SEALING: u32 = 0x0002;
        const MAX_NAME_LEN: usize = 249;

        if flags & !(MFD_CLOEXEC | MFD_ALLOW_SEALING) != 0 {
            return Err(Errno::EINVAL);
        }
        if name.to_bytes().len() > MAX_NAME_LEN {
            return Err(Errno::ENAMETOOLONG);
        }

        let mut open_flags = OFlags::CREAT | OFlags::EXCL | OFlags::RDWR;
        if flags & MFD_CLOEXEC != 0 {
            open_flags |= OFlags::CLOEXEC;
        }

        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        // The generic filesystem interface has no anonymous-inode constructor. Create a private
        // regular file and unlink it before publishing its descriptor; the open file description
        // keeps the inode alive and supplies the read/write/truncate/mmap behavior memfds need.
        for _ in 0..64 {
            let id = NEXT_MEMFD_ID.fetch_add(1, Ordering::Relaxed);
            let path = alloc::format!("/tmp/.litebox-memfd-{}-{id}", self.pid);
            let file = match self.do_open_raw_as(
                fs_credentials,
                path.as_str(),
                open_flags,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(file) => file,
                Err(litebox::fs::errors::OpenError::AlreadyExists) => continue,
                Err(error) => {
                    litebox_util_log::error!(
                        pid:? = self.pid,
                        tid:? = self.tid,
                        attempt_id = id,
                        path:% = path,
                        error:? = error;
                        "memfd backing open failed"
                    );
                    return Err(Errno::from(error));
                }
            };
            let unlink_result = {
                let files = self.files.borrow();
                files.fs.unlink_as(fs_credentials, path.as_str())
            };
            if let Err(error) = unlink_result {
                let close_failed = {
                    let files = self.files.borrow();
                    files.fs.close(&file).is_err()
                };
                if close_failed {
                    return Err(Errno::EIO);
                }
                return Err(Errno::from(error));
            }
            let old = self
                .global
                .litebox
                .descriptor_table_mut()
                .set_entry_metadata(&file, MemfdBacking::new(flags & MFD_ALLOW_SEALING != 0));
            assert!(old.is_none());
            return self.insert_raw_file_fd(file, open_flags, None);
        }
        Err(Errno::EAGAIN)
    }

    /// Handle syscall `mknodat` — create a filesystem node.
    pub(crate) fn sys_mknodat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
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
                let mode = Mode::from_bits_truncate(mode_and_type & !FILE_TYPE_MASK);
                let file = self.do_openat(
                    dirfd,
                    pathname,
                    OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                    mode,
                )?;
                let files = self.files.borrow();
                let _ = files.fs.close(&file);
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

    /// Handle syscall `unlinkat`
    pub(crate) fn sys_unlinkat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
    ) -> Result<(), Errno> {
        if flags.intersects(AtFlags::AT_REMOVEDIR.complement()) {
            return Err(Errno::EINVAL);
        }

        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        let path = self.resolve_path_at(dirfd, pathname)?;
        // `unlink(2)`/`rmdir(2)` act on the final name itself, never on a link's target.
        let path = self.resolve_syscall_path_as(fs_credentials, &path, false)?;
        if flags.contains(AtFlags::AT_REMOVEDIR) {
            self.files
                .borrow()
                .fs
                .rmdir_as(fs_credentials, path.as_str())
                .map_err(Errno::from)
        } else {
            self.files
                .borrow()
                .fs
                .unlink_as(fs_credentials, path.as_str())
                .map_err(Errno::from)
        }
    }

    /// Handle syscall `renameat2` (and `renameat`/`rename`, which the dispatcher
    /// forwards here with the absent dirfds/flags defaulted to `AT_FDCWD`/0).
    ///
    /// Only the default (flags 0) and `RENAME_NOREPLACE` behaviours are
    /// implemented; `RENAME_EXCHANGE` and `RENAME_WHITEOUT` are rejected with
    /// `EINVAL`, which is what a backend that does not support them reports.
    /// Neither path's trailing component is dereferenced -- `rename(2)` acts on a
    /// symlink itself, never its target -- matching `sys_unlinkat` above.
    pub(crate) fn sys_renameat2(
        &self,
        olddirfd: i32,
        oldpath: impl path::Arg,
        newdirfd: i32,
        newpath: impl path::Arg,
        flags: u32,
    ) -> Result<(), Errno> {
        const RENAME_NOREPLACE: u32 = 1 << 0;
        const RENAME_EXCHANGE: u32 = 1 << 1;
        const RENAME_WHITEOUT: u32 = 1 << 2;

        // Reject unknown bits outright, and the two behaviours LiteBox does not
        // model.
        if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0
            || flags & (RENAME_EXCHANGE | RENAME_WHITEOUT) != 0
        {
            return Err(Errno::EINVAL);
        }
        let noreplace = flags & RENAME_NOREPLACE != 0;

        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        let oldpath = self.resolve_path_at(olddirfd, oldpath)?;
        let oldpath = self.resolve_syscall_path_as(fs_credentials, &oldpath, false)?;
        let newpath = self.resolve_path_at(newdirfd, newpath)?;
        let newpath = self.resolve_syscall_path_as(fs_credentials, &newpath, false)?;
        self.files
            .borrow()
            .fs
            .rename_as(
                fs_credentials,
                oldpath.as_str(),
                newpath.as_str(),
                noreplace,
            )
            .map_err(Errno::from)
    }

    /// Handle syscall `fchmodat`.
    ///
    /// `chmod` has no wrapper of its own here, matching this file's existing convention for the
    /// other legacy no-dirfd syscalls that have an `*at` sibling (compare `sys_mkdirat`, which
    /// likewise has no separate `sys_mkdir`): `chmod` is reached by the syscall dispatcher
    /// constructing this same [`litebox_common_linux::SyscallRequest::Fchmodat`] with `dirfd`
    /// forced to `AT_FDCWD`. The raw `fchmodat(2)` syscall (unlike `fchmodat2(2)`) takes no
    /// `flags` argument, so callers reached through it always pass `AtFlags::empty()`.
    ///
    /// A trailing symlink is followed unless `AT_SYMLINK_NOFOLLOW` (`fchmodat2(2)`) says not to,
    /// in which case naming the link itself is `EOPNOTSUPP`, as on Linux: symlinks have no mode.
    pub fn sys_fchmodat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        mode: u32,
        flags: AtFlags,
    ) -> Result<(), Errno> {
        if flags.intersects(AtFlags::AT_SYMLINK_NOFOLLOW.complement()) {
            return Err(Errno::EINVAL);
        }
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        let path = self.resolve_path_at(dirfd, pathname)?;
        let follow_final = !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW);
        let path = self.resolve_path_symlinks_with_final_as(
            fs_credentials,
            path.to_str().map_err(|_| Errno::EINVAL)?,
            follow_final,
        )?;
        let files = self.files.borrow();
        if !follow_final
            && files
                .fs
                .file_status_as(fs_credentials, path.as_str())?
                .file_type
                == litebox::fs::FileType::SymLink
        {
            return Err(Errno::EOPNOTSUPP);
        }
        files
            .fs
            .chmod_as(fs_credentials, path.as_str(), Mode::from_bits_retain(mode))
            .map_err(Errno::from)
    }

    fn chown_id(id: u32) -> Result<Option<u16>, Errno> {
        if id == u32::MAX {
            Ok(None)
        } else {
            u16::try_from(id).map(Some).map_err(|_| Errno::EINVAL)
        }
    }

    /// Handle syscall `fchownat` (and `chown`/`lchown`, which the dispatcher
    /// forwards here with `dirfd` forced to `AT_FDCWD` and `flags` set to
    /// `AT_SYMLINK_NOFOLLOW` for `lchown`).
    ///
    /// `owner`/`group` are the raw `uid_t`/`gid_t`; `(uid_t)-1` (`u32::MAX`) means
    /// "leave this id unchanged". Other ids outside LiteBox's `u16` ownership model
    /// are rejected rather than silently treated as unchanged.
    pub(crate) fn sys_fchownat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        owner: u32,
        group: u32,
        flags: AtFlags,
    ) -> Result<(), Errno> {
        if flags.intersects(AtFlags::AT_SYMLINK_NOFOLLOW.complement()) {
            return Err(Errno::EINVAL);
        }
        let owner = Self::chown_id(owner)?;
        let group = Self::chown_id(group)?;
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        let path = self.resolve_path_at(dirfd, pathname)?;
        // `chown(2)` dereferences a trailing symlink; `lchown(2)`/`AT_SYMLINK_NOFOLLOW` name
        // the link itself. Intermediate links are followed either way.
        let path = self.resolve_syscall_path_as(
            fs_credentials,
            &path,
            !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW),
        )?;
        self.files
            .borrow()
            .fs
            .chown_as(fs_credentials, path.as_str(), owner, group)
            .map_err(Errno::from)
    }

    /// Handle syscall `fchmod`
    pub fn sys_fchmod(&self, fd: i32, mode: u32) -> Result<(), Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let mode = Mode::from_bits_retain(mode);
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    files
                        .fs
                        .fd_chmod_as(caller.as_fs_credentials(), fd, mode)
                        .map_err(Errno::from)
                },
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
            )
            .flatten()
    }

    /// Handle syscall `fchown`.
    ///
    /// `owner`/`group` are the raw `uid_t`/`gid_t`; only `u32::MAX` means
    /// "unchanged". Other ids outside LiteBox's `u16` ownership model are rejected.
    pub fn sys_fchown(&self, fd: i32, owner: u32, group: u32) -> Result<(), Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let owner = Self::chown_id(owner)?;
        let group = Self::chown_id(group)?;
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    files
                        .fs
                        .fd_chown_as(caller.as_fs_credentials(), fd, owner, group)
                        .map_err(Errno::from)
                },
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
            )
            .flatten()
    }

    /// Handle syscalls `fsync`, `fdatasync`, and `syncfs`: every LiteBox filesystem is
    /// memory-resident, so there is nothing to flush and only the fd is checked -- `EBADF` when
    /// closed, `EINVAL` for the descriptor kinds Linux refuses to sync (pipes, sockets, ...).
    pub fn sys_fsync(&self, fd: i32) -> Result<(), Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        self.files
            .borrow()
            .run_on_raw_fd(
                raw_fd,
                |_fd| Ok(()),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
            )
            .flatten()
    }

    /// Resolve a single raw `timespec` from `utimensat`/`futimens` into fs-layer semantics: `None`
    /// means "leave unchanged" (`UTIME_OMIT`), `Some` carries a concrete timestamp (resolving
    /// `UTIME_NOW` against the current wall-clock time).
    fn resolve_utime(
        &self,
        ts: litebox_common_linux::Timespec,
    ) -> Result<Option<litebox::fs::Timestamp>, Errno> {
        match ts.tv_nsec {
            litebox_common_linux::UTIME_OMIT => Ok(None),
            litebox_common_linux::UTIME_NOW => Ok(Some(self.now_as_fs_timestamp())),
            nsec if nsec < 1_000_000_000 => Ok(Some(litebox::fs::Timestamp {
                sec: ts.tv_sec,
                nsec: nsec.reinterpret_as_signed(),
            })),
            _ => Err(Errno::EINVAL),
        }
    }

    /// Resolve the raw two-element `times` array from `utimensat`/`futimens` (`None` meaning a
    /// `NULL` pointer, i.e., both timestamps set to "now") into `(atime, mtime)`, per
    /// [`litebox::fs::FileSystem::utimensat`]'s `None`/`Some` semantics.
    fn resolve_utimes(
        &self,
        times: Option<[litebox_common_linux::Timespec; 2]>,
    ) -> Result<
        (
            Option<litebox::fs::Timestamp>,
            Option<litebox::fs::Timestamp>,
        ),
        Errno,
    > {
        let Some([atime, mtime]) = times else {
            let now = self.now_as_fs_timestamp();
            return Ok((Some(now), Some(now)));
        };
        Ok((self.resolve_utime(atime)?, self.resolve_utime(mtime)?))
    }

    fn now_as_fs_timestamp(&self) -> litebox::fs::Timestamp {
        let now = self.real_time_as_duration_since_epoch();
        litebox::fs::Timestamp {
            sec: now.as_secs().reinterpret_as_signed(),
            nsec: i64::from(now.subsec_nanos()),
        }
    }

    /// Handle syscall `utimensat`
    pub fn sys_utimensat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        times: Option<[litebox_common_linux::Timespec; 2]>,
        flags: AtFlags,
    ) -> Result<(), Errno> {
        if flags.intersects(AtFlags::AT_SYMLINK_NOFOLLOW.complement()) {
            return Err(Errno::EINVAL);
        }
        let (atime, mtime) = self.resolve_utimes(times)?;
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        let path = self.resolve_path_at(dirfd, pathname)?;
        let path = self.resolve_syscall_path_as(
            fs_credentials,
            &path,
            !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW),
        )?;
        self.files
            .borrow()
            .fs
            .utimensat_as(fs_credentials, path.as_str(), atime, mtime)
            .map_err(Errno::from)
    }

    /// Handle syscall `futimens`.
    ///
    /// `futimens` has no syscall of its own: glibc implements it as
    /// `utimensat(fd, NULL, times, 0)`, which LiteBox's syscall dispatcher routes here (see
    /// [`litebox_common_linux::SyscallRequest::Utimensat`]'s doc comment).
    pub fn sys_futimens(
        &self,
        fd: i32,
        times: Option<[litebox_common_linux::Timespec; 2]>,
    ) -> Result<(), Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let (atime, mtime) = self.resolve_utimes(times)?;
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    files
                        .fs
                        .fd_utimensat_as(caller.as_fs_credentials(), fd, atime, mtime)
                        .map_err(Errno::from)
                },
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
            )
            .flatten()
    }

    /// Handle syscall `flock`.
    ///
    /// See [`litebox::fs::flock::FlockTable`]'s doc comment for exactly what whole-file advisory
    /// locking means in LiteBox's single-process-but-multi-threaded model, and for the
    /// fd-number-based holder-identity simplification this relies on.
    pub fn sys_flock(&self, fd: i32, operation: FlockOperation) -> Result<(), Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let nonblock = operation.contains(FlockOperation::LOCK_NB);
        let kind = match operation - FlockOperation::LOCK_NB {
            FlockOperation::LOCK_SH => Some(litebox::fs::flock::FlockKind::Shared),
            FlockOperation::LOCK_EX => Some(litebox::fs::flock::FlockKind::Exclusive),
            FlockOperation::LOCK_UN => None,
            _ => return Err(Errno::EINVAL),
        };

        let files = self.files.borrow();
        let node = files
            .run_on_raw_fd(
                raw_fd,
                |fd| files.fs.fd_file_status(fd).map_err(Errno::from),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
            )
            .flatten()?
            .node_info;
        drop(files);

        let holder = litebox::fs::flock::FlockHolder(flock_holder_for_raw_fd(raw_fd));
        let flock_table = self.global.litebox.flock_table();
        match kind {
            None => {
                flock_table.unlock(node, holder);
                Ok(())
            }
            Some(kind) if nonblock => flock_table
                .try_lock(node, holder, kind)
                .map_err(|_| Errno::EWOULDBLOCK),
            Some(kind) => flock_table
                .lock(&self.wait_cx(), node, holder, kind)
                .map_err(|_| Errno::EINTR),
        }
    }

    /// Handle syscall `read`
    ///
    /// `offset` is an optional offset to read from. If `None`, it will read from the current file position.
    /// If `Some`, it will read from the specified offset without changing the current file position.
    pub fn sys_read(&self, fd: i32, buf: &mut [u8], offset: Option<usize>) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        self.do_read(raw_fd, buf, offset)
    }
    /// Whether a non-blocking `read()` on `fd` must return `EAGAIN` immediately instead of
    /// falling through to the (potentially real-stdin-blocking) `Backend::read` path.
    ///
    /// Only ever true for the fixed stdin fd (0): it's the only raw fd this shim attaches both
    /// `StdioStream` and `StdioStatusFlags` metadata to (see
    /// `initialize_stdio_in_shared_descriptors_table`), and it's the only one backed by a real,
    /// potentially-slow host resource that `Backend::read` has no non-blocking story for on its
    /// own -- see `litebox::platform::StdioProvider::stdin_pollable`.
    fn stdin_read_would_block(&self, fd: &TypedFd<FS>) -> bool {
        let dt = self.global.litebox.descriptor_table();
        let Ok(stream) = dt.with_metadata(fd, |s: &StdioStream| *s) else {
            return false;
        };
        if stream != StdioStream::Stdin {
            return false;
        }
        let Ok(nonblock) = dt.with_metadata(fd, |crate::StdioStatusFlags(flags)| {
            flags.contains(OFlags::NONBLOCK)
        }) else {
            return false;
        };
        if !nonblock {
            return false;
        }
        // A platform with no real stdin-readiness signal can't tell us "not ready" for real, so
        // fall back to the pre-existing (blocking) behavior rather than spuriously EAGAIN-ing.
        self.global
            .platform
            .stdin_pollable()
            .is_some_and(|pollable| !pollable.check_io_events().contains(Events::IN))
    }

    pub(crate) fn do_read(
        &self,
        fd: u32,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, Errno> {
        // A `read()` from a `NETLINK_ROUTE` socket (iproute2/busybox `ip`) drains
        // pending dump bytes; `pread` (an offset) never targets a socket. The
        // `&mut buf` is auto-reborrowed, so it stays usable on the non-netlink path.
        if offset.is_none()
            && let Some(res) = self.netlink_recv(fd, buf)
        {
            return res;
        }
        let files = self.files.borrow();
        // Inotify fds aren't one of `run_on_raw_fd`'s hand-enumerated subsystem parameters (see
        // that function's doc comment); resolve them directly first and fall through to the
        // existing dispatch below on a miss, exactly mirroring how a subsystem absent from that
        // enumeration would report `EBADF` today -- this changes no existing fd's behavior.
        if let Ok(inotify_fd) = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::inotify::InotifySubsystem<Platform>>(fd as usize)
        {
            espipe_for_non_seekable_offset(offset)?;
            let handle = self
                .global
                .litebox
                .descriptor_table()
                .entry_handle(&inotify_fd)
                .ok_or(Errno::EBADF)?;
            return handle.with_entry(|file| file.read(&self.wait_cx(), buf));
        }
        // We need to do this cell dance because otherwise Rust can't recognize that the two
        // closures are mutually exclusive.
        let buf: core::cell::RefCell<&mut [u8]> = core::cell::RefCell::new(buf);
        let n = files
            .run_on_raw_fd(
                fd as usize,
                |fd| {
                    if self.stdin_read_would_block(fd) {
                        return Err(Errno::EAGAIN);
                    }
                    if let Some(meta) = input_event_meta_of(&self.global, fd) {
                        return self.read_input_events(meta, &mut buf.borrow_mut());
                    }
                    let shared_backing = self.shared_file_backing(fd, false);
                    let read_offset = match (shared_backing, offset) {
                        (Some(_), None) => Some(
                            files
                                .fs
                                .seek(fd, 0, SeekWhence::RelativeToCurrentOffset)
                                .map_err(Errno::from)?,
                        ),
                        (_, explicit) => explicit,
                    };
                    let mut output = buf.borrow_mut();
                    let size = files
                        .fs
                        .read(fd, &mut output, offset)
                        .map_err(Errno::from)?;
                    if let (Some(backing), Some(read_offset)) = (shared_backing, read_offset) {
                        self.global
                            .platform
                            .read_shared_pages(backing.identity(), read_offset, &mut output[..size])
                            .map_err(|_| Errno::EIO)?;
                    }
                    Ok(size)
                },
                |fd| {
                    espipe_for_non_seekable_offset(offset)?;
                    self.global.receive(
                        &self.wait_cx(),
                        fd,
                        &mut buf.borrow_mut(),
                        litebox_common_linux::ReceiveFlags::empty(),
                        None,
                    )
                },
                |fd| {
                    espipe_for_non_seekable_offset(offset)?;
                    self.global
                        .read_linux_pipe(&self.wait_cx(), fd, &mut buf.borrow_mut())
                },
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    espipe_for_non_seekable_offset(offset)?;
                    handle.with_entry(|file| {
                        let buf = &mut buf.borrow_mut();
                        if buf.len() < size_of::<u64>() {
                            return Err(Errno::EINVAL);
                        }
                        let value = file.read(&self.wait_cx())?;
                        buf[..size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
                        Ok(size_of::<u64>())
                    })
                },
                |_fd| Err(Errno::EINVAL),
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    espipe_for_non_seekable_offset(offset)?;
                    // A pty master whose slave side has closed (and not been reopened since)
                    // reads end-of-file once buffered output is drained, instead of blocking
                    // forever: this is what a terminal emulator waits for after its shell exits.
                    let pty_other_closed = self.pty_endpoint(fd).is_some_and(|endpoint| {
                        endpoint.side == PtySide::Master
                            && endpoint.state.other_closed.load(Ordering::Acquire)
                    });
                    handle.with_entry(|file| {
                        if pty_other_closed {
                            return match file.recvfrom(
                                &self.wait_cx(),
                                &mut buf.borrow_mut(),
                                litebox_common_linux::ReceiveFlags::DONTWAIT,
                                None,
                            ) {
                                Err(Errno::EAGAIN) => Ok(0),
                                other => other,
                            };
                        }
                        file.recvfrom(
                            &self.wait_cx(),
                            &mut buf.borrow_mut(),
                            litebox_common_linux::ReceiveFlags::empty(),
                            None,
                        )
                    })
                },
                |fd| {
                    espipe_for_non_seekable_offset(offset)?;
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| file.handle_recv(&mut buf.borrow_mut()))
                },
            )
            .flatten()?;
        // For datagrams, the returned size represents the actual size of the message,
        // which may be larger than the buffer size.
        let capped_size = n.min(buf.borrow().len());
        Ok(capped_size)
    }

    /// Handle syscall `write`
    ///
    /// `offset` is an optional offset to write to. If `None`, it will write to the current file position.
    /// If `Some`, it will write to the specified offset without changing the current file position.
    pub fn sys_write(&self, fd: i32, buf: &[u8], offset: Option<usize>) -> Result<usize, Errno> {
        let Ok(fd_u32) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let raw_fd = fd_u32 as usize;
        // A `write()` to a `NETLINK_ROUTE` socket (as iproute2/busybox `ip` do,
        // rather than `send()`) enqueues a dump; `pwrite` (an offset) never targets
        // a socket.
        if offset.is_none()
            && let Some(res) = self.netlink_send(fd_u32, buf)
        {
            return res;
        }
        let files = self.files.borrow();
        let res = files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    let shared_backing = self.shared_file_backing(fd, false);
                    let size = files.fs.write(fd, buf, offset).map_err(Errno::from)?;
                    if let Some(backing) = shared_backing {
                        let write_offset = match offset {
                            Some(offset) => offset,
                            None => files
                                .fs
                                .seek(fd, 0, SeekWhence::RelativeToCurrentOffset)
                                .map_err(Errno::from)?
                                .checked_sub(size)
                                .ok_or(Errno::EIO)?,
                        };
                        self.global
                            .platform
                            .write_shared_pages(backing.identity(), write_offset, &buf[..size])
                            .map_err(|_| Errno::EIO)?;
                    }
                    Ok(size)
                },
                |fd| {
                    espipe_for_non_seekable_offset(offset)?;
                    self.global.sendto(
                        &self.wait_cx(),
                        fd,
                        buf,
                        litebox_common_linux::SendFlags::empty(),
                        None,
                    )
                },
                |fd| {
                    espipe_for_non_seekable_offset(offset)?;
                    self.global.write_linux_pipe(&self.wait_cx(), fd, buf)
                },
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    espipe_for_non_seekable_offset(offset)?;
                    handle.with_entry(|file| {
                        if buf.len() < size_of::<u64>() {
                            return Err(Errno::EINVAL);
                        }
                        let value: u64 = u64::from_le_bytes(
                            buf[..size_of::<u64>()]
                                .try_into()
                                .map_err(|_| Errno::EINVAL)?,
                        );
                        file.write(&self.wait_cx(), value)
                    })
                },
                |_fd| Err(Errno::EINVAL),
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    espipe_for_non_seekable_offset(offset)?;
                    let send = |payload: &[u8]| {
                        handle.with_entry(|file| {
                            file.sendto(
                                self,
                                payload,
                                litebox_common_linux::SendFlags::empty(),
                                None,
                            )
                        })
                    };
                    let Some(endpoint) = self.pty_endpoint(fd) else {
                        return send(buf);
                    };
                    if endpoint.side != PtySide::Slave {
                        return send(buf);
                    }
                    let output_flags = litebox_common_linux::OFlag::from_bits_truncate(
                        endpoint.state.termios.lock().c_oflag,
                    );
                    if !output_flags.contains(
                        litebox_common_linux::OFlag::OPOST | litebox_common_linux::OFlag::ONLCR,
                    ) {
                        return send(buf);
                    }
                    let newline_count = buf.iter().copied().filter(|byte| *byte == b'\n').count();
                    if newline_count == 0 {
                        return send(buf);
                    }
                    let output_len = buf
                        .len()
                        .checked_add(newline_count)
                        .ok_or(Errno::EOVERFLOW)?;
                    let mut output = alloc::vec::Vec::new();
                    output
                        .try_reserve_exact(output_len)
                        .map_err(|_| Errno::ENOMEM)?;
                    for &byte in buf {
                        if byte == b'\n' {
                            output.push(b'\r');
                        }
                        output.push(byte);
                    }
                    if send(&output)? != output.len() {
                        return Err(Errno::EIO);
                    }
                    Ok(buf.len())
                },
                |fd| {
                    espipe_for_non_seekable_offset(offset)?;
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    Ok(handle.with_entry(|file| file.handle_send(buf)))
                },
            )
            .flatten();
        if let Err(Errno::EPIPE) = res {
            self.send_signal(Signal::SIGPIPE, signal::siginfo_kill(Signal::SIGPIPE));
        }
        res
    }

    /// Handle syscall `pread64`
    pub fn sys_pread64(&self, fd: i32, buf: &mut [u8], offset: i64) -> Result<usize, Errno> {
        let pos = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.sys_read(fd, buf, Some(pos))
    }

    fn rewind_sendfile_in_fd(&self, in_raw_fd: usize, unread_n: usize) -> Result<(), Errno> {
        if unread_n == 0 {
            return Ok(());
        }

        let rewind = isize::try_from(unread_n).map_err(|_| Errno::EOVERFLOW)?;
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                in_raw_fd,
                |fd| {
                    files
                        .fs
                        .seek(fd, -rewind, SeekWhence::RelativeToCurrentOffset)
                        .map(|_| ())
                        .map_err(Errno::from)
                },
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
            )
            .flatten()
    }

    /// Handle syscall `sendfile`
    pub(crate) fn sys_sendfile(
        &self,
        out_fd: i32,
        in_fd: i32,
        offset_ptr: Option<UserPtrMut<i64>>,
        count: usize,
    ) -> Result<usize, Errno> {
        let Ok(in_raw_fd) = u32::try_from(in_fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        // TODO: Linux rejects `sendfile` with `EINVAL` when `out_fd` has `O_APPEND` set.
        self.check_raw_fd_exists(out_fd)?;

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
            let read_result = {
                let buf_slice = &mut kernel_buf[..to_read];
                let files = self.files.borrow();
                files
                    .run_on_raw_fd(
                        in_raw_fd,
                        |fd| {
                            let shared_backing = self.shared_file_backing(fd, false);
                            let read_offset = match (shared_backing, cur_off) {
                                (Some(_), None) => Some(
                                    files
                                        .fs
                                        .seek(fd, 0, SeekWhence::RelativeToCurrentOffset)
                                        .map_err(Errno::from)?,
                                ),
                                (_, explicit) => explicit,
                            };
                            let size =
                                files.fs.read(fd, buf_slice, cur_off).map_err(Errno::from)?;
                            if let (Some(backing), Some(read_offset)) =
                                (shared_backing, read_offset)
                            {
                                self.global
                                    .platform
                                    .read_shared_pages(
                                        backing.identity(),
                                        read_offset,
                                        &mut buf_slice[..size],
                                    )
                                    .map_err(|_| Errno::EIO)?;
                            }
                            Ok(size)
                        },
                        |_fd| Err(non_fs_err),
                        |_fd| Err(non_fs_err),
                        |_fd| Err(non_fs_err),
                        |_fd| Err(non_fs_err),
                        |_fd| Err(non_fs_err),
                        |_fd| Err(non_fs_err),
                    )
                    .flatten()
            };
            let read_n = match read_result {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if total == 0 => return Err(e),
                Err(_) => break,
            };

            let write_result = self.sys_write(out_fd, &kernel_buf[..read_n], None);
            let write_n = match write_result {
                Ok(n) => n,
                Err(e) => {
                    if offset_ptr.is_none() {
                        self.rewind_sendfile_in_fd(in_raw_fd, read_n)?;
                    }
                    if total == 0 {
                        return Err(e);
                    }
                    break;
                }
            };

            total += write_n;
            if let Some(ref mut off) = cur_off {
                *off += write_n;
            }
            if write_n < read_n {
                if offset_ptr.is_none() {
                    self.rewind_sendfile_in_fd(in_raw_fd, read_n - write_n)?;
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

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Handle syscall `lseek`
    pub fn sys_lseek(&self, fd: i32, offset: isize, whence: SeekWhence) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                raw_fd,
                |fd| files.fs.seek(fd, offset, whence).map_err(Errno::from),
                |_| Err(Errno::ESPIPE),
                |_| Err(Errno::ESPIPE),
                |_| Err(Errno::ESPIPE),
                |_| Err(Errno::ESPIPE),
                |_| Err(Errno::ESPIPE),
                |_| Err(Errno::ESPIPE),
            )
            .flatten()
    }

    fn do_mkdir(&self, pathname: impl path::Arg, mode: Mode) -> Result<(), Errno> {
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let mode = mode & !self.get_umask();
        self.files
            .borrow()
            .fs
            .mkdir_as(caller.as_fs_credentials(), pathname, mode)
            .map_err(Errno::from)
    }

    /// Handle syscall `mkdirat`
    pub(crate) fn sys_mkdirat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        mode: u32,
    ) -> Result<(), Errno> {
        let pathname = self.resolve_path_at(dirfd, pathname)?;
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let pathname =
            self.resolve_syscall_path_as(caller.as_fs_credentials(), &pathname, false)?;
        self.do_mkdir(pathname.as_str(), Mode::from_bits_retain(mode))
    }

    /// Handle syscall `symlinkat` (and `symlink`, which the dispatcher forwards
    /// here with `newdirfd` = `AT_FDCWD`).
    ///
    /// `target` is the link's contents and is stored verbatim -- it is neither
    /// resolved nor required to exist (a dangling link is valid). Only `linkpath`
    /// is resolved, against `newdirfd`.
    pub(crate) fn sys_symlinkat(
        &self,
        target: impl path::Arg,
        newdirfd: i32,
        linkpath: impl path::Arg,
    ) -> Result<(), Errno> {
        let target = target.as_rust_str().map_err(|_| Errno::EINVAL)?;
        // `symlink(2)`: an empty target is ENOENT.
        if target.is_empty() {
            return Err(Errno::ENOENT);
        }
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        let linkpath = self.resolve_path_at(newdirfd, linkpath)?;
        // The new name is never dereferenced (an existing final link is `EEXIST`), but a
        // symlinked parent directory is.
        let linkpath = self.resolve_syscall_path_as(fs_credentials, &linkpath, false)?;
        self.files
            .borrow()
            .fs
            .symlink_as(fs_credentials, target, linkpath.as_str())
            .map_err(Errno::from)
    }

    /// Handle syscalls `link` and `linkat`.
    ///
    /// DEVIATION, disclosed: the layered filesystem has no inode-sharing hard links, so this
    /// creates an exclusive *copy* of the source file at the new path. The dominant real-world
    /// caller shape -- write a finished file, `link` it into place as an atomic
    /// create-if-absent, `unlink` the original (Xorg's `/tmp/.X0-lock`, mail spools, lock
    /// files generally) -- observes identical behavior: `EEXIST` when the name is taken, the
    /// full content when it wins. What differs from real `link(2)`: post-link writes through
    /// one name are not visible through the other, and `st_nlink`/inode identity stay
    /// separate. A guest that round-trips those semantics needs real hard-link support in
    /// `litebox::fs` first.
    pub(crate) fn sys_linkat(
        &self,
        olddirfd: i32,
        oldpath: impl path::Arg,
        newdirfd: i32,
        newpath: impl path::Arg,
        flags: u32,
    ) -> Result<(), Errno> {
        const AT_SYMLINK_FOLLOW: u32 = 0x400;
        const AT_EMPTY_PATH: u32 = 0x1000;
        const COPY_BUFFER_SIZE: usize = 64 * 1024;
        const MAX_STAGE_ATTEMPTS: usize = 64;
        static NEXT_STAGE_ID: AtomicUsize = AtomicUsize::new(0);

        if flags & AT_EMPTY_PATH != 0 || flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
            return Err(Errno::EINVAL);
        }

        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        let oldpath = self.resolve_path_at(olddirfd, oldpath)?;
        let oldpath = self.resolve_path_symlinks_with_final_as(
            fs_credentials,
            oldpath.to_str().map_err(|_| Errno::EINVAL)?,
            flags & AT_SYMLINK_FOLLOW != 0,
        )?;
        let newpath = self.resolve_path_at(newdirfd, newpath)?;
        let newpath = self.resolve_path_symlinks_with_final_as(
            fs_credentials,
            newpath.to_str().map_err(|_| Errno::EINVAL)?,
            false,
        )?;
        let parent_end = newpath.rfind('/').ok_or(Errno::EINVAL)?;
        let parent = &newpath[..parent_end];
        let next_stage_path = || {
            let id = NEXT_STAGE_ID.fetch_add(1, Ordering::Relaxed);
            if parent.is_empty() {
                alloc::format!("/.litebox-linkat-{}-{id}", self.pid)
            } else {
                alloc::format!("{parent}/.litebox-linkat-{}-{id}", self.pid)
            }
        };

        let files = self.files.borrow();
        let map_status_error = |error| match error {
            litebox::fs::errors::FileStatusError::ClosedFd => Errno::EBADF,
            litebox::fs::errors::FileStatusError::PathError(error) => error.into(),
            _ => Errno::EIO,
        };
        let close = |fd: &TypedFd<FS>| files.fs.close(fd).map_err(|_| Errno::EIO);
        let cleanup = |stage: &str, failure: Errno| {
            files
                .fs
                .unlink_as(fs_credentials, stage)
                .map_err(Errno::from)?;
            Err(failure)
        };
        let publish =
            |stage: &str| match files
                .fs
                .rename_as(fs_credentials, stage, newpath.as_str(), true)
            {
                Ok(()) => Ok(()),
                Err(error) => cleanup(stage, error.into()),
            };

        let source_status = files
            .fs
            .file_status_as(fs_credentials, oldpath.as_str())
            .map_err(map_status_error)?;
        match source_status.file_type {
            litebox::fs::FileType::SymLink => {
                let target = files
                    .fs
                    .readlink_as(fs_credentials, oldpath.as_str())
                    .map_err(Errno::from)?;
                let stage = 'create: {
                    for _ in 0..MAX_STAGE_ATTEMPTS {
                        let stage = next_stage_path();
                        if stage == newpath {
                            continue;
                        }
                        match files
                            .fs
                            .symlink_as(fs_credentials, target.as_str(), stage.as_str())
                        {
                            Ok(()) => break 'create stage,
                            Err(litebox::fs::errors::SymlinkError::AlreadyExists) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                    return Err(Errno::EAGAIN);
                };
                publish(stage.as_str())
            }
            litebox::fs::FileType::RegularFile => {
                let src = files
                    .fs
                    .open_as(
                        fs_credentials,
                        oldpath.as_str(),
                        OFlags::RDONLY,
                        Mode::empty(),
                    )
                    .map_err(Errno::from)?;
                let status = match files.fs.fd_file_status(&src) {
                    Ok(status) => status,
                    Err(error) => {
                        let error = map_status_error(error);
                        close(&src)?;
                        return Err(error);
                    }
                };
                if status.file_type != litebox::fs::FileType::RegularFile {
                    close(&src)?;
                    return Err(Errno::EPERM);
                }

                let mut buffer = alloc::vec::Vec::new();
                if buffer.try_reserve_exact(COPY_BUFFER_SIZE).is_err() {
                    close(&src)?;
                    return Err(Errno::ENOMEM);
                }
                buffer.resize(COPY_BUFFER_SIZE, 0);

                let (stage, dst) = 'create: {
                    for _ in 0..MAX_STAGE_ATTEMPTS {
                        let stage = next_stage_path();
                        if stage == newpath {
                            continue;
                        }
                        match files.fs.open_as(
                            fs_credentials,
                            stage.as_str(),
                            OFlags::WRONLY | OFlags::CREAT | OFlags::EXCL,
                            Mode::RUSR | Mode::WUSR,
                        ) {
                            Ok(dst) => break 'create (stage, dst),
                            Err(litebox::fs::errors::OpenError::AlreadyExists) => {}
                            Err(error) => {
                                let error = Errno::from(error);
                                close(&src)?;
                                return Err(error);
                            }
                        }
                    }
                    close(&src)?;
                    return Err(Errno::EAGAIN);
                };

                let copy_result =
                    (|| {
                        let mut offset = 0usize;
                        loop {
                            let read = files.fs.read(&src, &mut buffer, Some(offset)).map_err(
                                |error| match error {
                                    litebox::fs::errors::ReadError::NotAFile => Errno::EISDIR,
                                    litebox::fs::errors::ReadError::ClosedFd
                                    | litebox::fs::errors::ReadError::NotForReading => Errno::EBADF,
                                    _ => Errno::EIO,
                                },
                            )?;
                            if read == 0 {
                                break;
                            }
                            if read > buffer.len() {
                                return Err(Errno::EIO);
                            }
                            let mut written = 0usize;
                            while written < read {
                                let write_offset =
                                    offset.checked_add(written).ok_or(Errno::EOVERFLOW)?;
                                let write = files
                                    .fs
                                    .write(&dst, &buffer[written..read], Some(write_offset))
                                    .map_err(|error| match error {
                                        litebox::fs::errors::WriteError::NotAFile => Errno::EISDIR,
                                        litebox::fs::errors::WriteError::ClosedFd
                                        | litebox::fs::errors::WriteError::NotForWriting => {
                                            Errno::EBADF
                                        }
                                        litebox::fs::errors::WriteError::ReadOnlyFileSystem => {
                                            Errno::EROFS
                                        }
                                        _ => Errno::EIO,
                                    })?;
                                if write == 0 || write > read - written {
                                    return Err(Errno::EIO);
                                }
                                written += write;
                            }
                            offset = offset.checked_add(read).ok_or(Errno::EOVERFLOW)?;
                        }
                        files
                            .fs
                            .fd_chown_as(
                                fs_credentials,
                                &dst,
                                Some(status.owner.user),
                                Some(status.owner.group),
                            )
                            .map_err(Errno::from)?;
                        files
                            .fs
                            .fd_chmod_as(fs_credentials, &dst, status.mode)
                            .map_err(Errno::from)?;
                        files
                            .fs
                            .fd_utimensat_as(
                                fs_credentials,
                                &dst,
                                Some(status.atime),
                                Some(status.mtime),
                            )
                            .map_err(Errno::from)
                    })();
                let src_close_result = close(&src);
                let dst_close_result = close(&dst);
                if let Err(error) = copy_result.and(src_close_result).and(dst_close_result) {
                    return cleanup(stage.as_str(), error);
                }
                publish(stage.as_str())
            }
            _ => Err(Errno::EPERM),
        }
    }

    pub(crate) fn do_close(&self, raw_fd: usize) -> Result<(), Errno> {
        // See the matching comment in `do_read`: inotify fds sit outside `do_close_and_replace`'s
        // `ConsumedFd` enumeration, so resolve them directly first. Inotify fds have no
        // replace-into-same-slot use case in this codebase (unlike `do_close_and_replace`'s
        // general `S`-typed `replace` parameter, only ever driven by `dup2`-style callers), so a
        // direct consume-and-drop is the whole close.
        {
            let files = self.files.borrow();
            let mut rds = files.raw_descriptor_store.write();
            if rds
                .fd_consume_raw_integer::<super::inotify::InotifySubsystem<Platform>>(raw_fd)
                .is_ok()
            {
                return Ok(());
            }
        }
        self.do_close_and_replace::<FS>(raw_fd, None)
    }

    /// Close the file at `raw_fd` and optionally place a new file in the same slot.
    ///
    /// This function ensure `close` and `insert` are done atomically.
    fn do_close_and_replace<S: FdEnabledSubsystem>(
        &self,
        raw_fd: usize,
        replace: Option<TypedFd<S>>,
    ) -> Result<(), Errno> {
        enum ConsumedFd<Platform: ShimPlatform, FS: ShimFS> {
            Fs(alloc::sync::Arc<TypedFd<FS>>),
            Network(alloc::sync::Arc<TypedFd<litebox::net::Network<Platform>>>),
            Pipes(alloc::sync::Arc<TypedFd<litebox::pipes::Pipes<Platform>>>),
            Eventfd(alloc::sync::Arc<TypedFd<super::eventfd::EventfdSubsystem<Platform>>>),
            Epoll(alloc::sync::Arc<TypedFd<super::epoll::EpollSubsystem<Platform, FS>>>),
            Unix(alloc::sync::Arc<TypedFd<super::unix::UnixSocketSubsystem<Platform, FS>>>),
            Netlink(alloc::sync::Arc<TypedFd<super::netlink::NetlinkSubsystem<Platform>>>),
        }

        let files = self.files.borrow();
        let mut rds = files.raw_descriptor_store.write();
        let consumed: ConsumedFd<Platform, FS> = match rds.fd_consume_raw_integer::<FS>(raw_fd) {
            Ok(fd) => ConsumedFd::Fs(fd),
            Err(litebox::fd::ErrRawIntFd::NotFound) => {
                if let Some(new_fd) = replace {
                    let success = rds.fd_into_specific_raw_integer(new_fd, raw_fd);
                    assert!(success, "raw_fd slot is empty, so insert must succeed");
                }
                return Err(Errno::EBADF);
            }
            Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => {
                if let Ok(fd) =
                    rds.fd_consume_raw_integer::<litebox::net::Network<Platform>>(raw_fd)
                {
                    ConsumedFd::Network(fd)
                } else if let Ok(fd) =
                    rds.fd_consume_raw_integer::<litebox::pipes::Pipes<Platform>>(raw_fd)
                {
                    ConsumedFd::Pipes(fd)
                } else if let Ok(fd) =
                    rds.fd_consume_raw_integer::<super::eventfd::EventfdSubsystem<Platform>>(raw_fd)
                {
                    ConsumedFd::Eventfd(fd)
                } else if let Ok(fd) =
                    rds.fd_consume_raw_integer::<super::epoll::EpollSubsystem<Platform, FS>>(raw_fd)
                {
                    ConsumedFd::Epoll(fd)
                } else if let Ok(fd) = rds
                    .fd_consume_raw_integer::<super::unix::UnixSocketSubsystem<Platform, FS>>(
                        raw_fd,
                    )
                {
                    ConsumedFd::Unix(fd)
                } else if let Ok(fd) =
                    rds.fd_consume_raw_integer::<super::netlink::NetlinkSubsystem<Platform>>(raw_fd)
                {
                    ConsumedFd::Netlink(fd)
                } else {
                    unreachable!("all subsystems covered")
                }
            }
        };

        // Insert the replacement into the now-vacated slot while still holding the lock.
        if let Some(new_fd) = replace {
            let success = rds.fd_into_specific_raw_integer(new_fd, raw_fd);
            assert!(
                success,
                "we just consumed this raw_fd, so it must be available"
            );
        }
        drop(rds);

        match consumed {
            ConsumedFd::Fs(fd) => {
                if let Ok(raw_fd) = i32::try_from(raw_fd) {
                    self.finalize_elf_patch(raw_fd);
                }
                // Release any `flock(2)` lock this fd number holds before the fd goes away, so a
                // guest that never calls `LOCK_UN` doesn't leak the lock for the rest of this
                // LiteBox instance's lifetime. See `sys_flock`'s doc comment for the fd-number-based
                // holder-identity simplification this relies on.
                if let Ok(node) = files.fs.fd_file_status(&fd) {
                    self.global.litebox.flock_table().unlock(
                        node.node_info,
                        litebox::fs::flock::FlockHolder(flock_holder_for_raw_fd(raw_fd)),
                    );
                }
                files.fs.close(&fd).map_err(Errno::from)
            }
            ConsumedFd::Network(fd) => self.global.close_socket(&self.wait_cx(), fd),
            ConsumedFd::Pipes(fd) => self.global.close_linux_pipe(&fd),
            ConsumedFd::Eventfd(fd) => {
                let entry = {
                    let mut dt = self.global.litebox.descriptor_table_mut();
                    dt.remove(&fd)
                };
                // do not hold any locks while dropping the entry
                drop(entry);
                Ok(())
            }
            ConsumedFd::Epoll(fd) => {
                let entry = {
                    let mut dt = self.global.litebox.descriptor_table_mut();
                    dt.remove(&fd)
                };
                // do not hold any locks while dropping the entry
                drop(entry);
                Ok(())
            }
            ConsumedFd::Unix(fd) => {
                let (entry, slave) = {
                    let mut dt = self.global.litebox.descriptor_table_mut();
                    let slave = dt
                        .with_metadata(&fd, |endpoint: &PtyEndpoint<Platform, FS>| {
                            (endpoint.side == PtySide::Slave)
                                .then(|| (endpoint.number, endpoint.state.clone()))
                        })
                        .ok()
                        .flatten();
                    (dt.remove(&fd), slave)
                };
                // do not hold any locks while dropping the entry
                drop(entry);
                if let Some((number, state)) = slave {
                    self.global
                        .pty_registry
                        .release_slave_descriptor(number, &state);
                }
                Ok(())
            }
            ConsumedFd::Netlink(fd) => {
                let entry = {
                    let mut dt = self.global.litebox.descriptor_table_mut();
                    dt.remove(&fd)
                };
                // do not hold any locks while dropping the entry
                drop(entry);
                Ok(())
            }
        }
    }

    /// Handle syscall `close`
    pub(crate) fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        self.do_close(raw_fd)
    }

    /// Handle syscall `preadv`
    pub(crate) fn sys_preadv(
        &self,
        fd: i32,
        iovec: UserPtr<IoReadVec>,
        iovcnt: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        let base_offset = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.check_raw_fd_exists(fd)?;
        check_iovcnt(iovcnt)?;
        let iovs: &[IoReadVec] = &iovec
            .to_owned_slice::<Platform>(iovcnt)
            .ok_or(Errno::EFAULT)?;
        let mut kernel_buffer = vec![0u8; PAGE_SIZE];
        read_from_iovec::<_, Platform>(iovs, &mut kernel_buffer, |buf, total| {
            let cur_offset = base_offset.checked_add(total).ok_or(Errno::EOVERFLOW)?;
            self.sys_read(fd, buf, Some(cur_offset))
        })
    }

    /// Handle syscall `pwritev`
    pub(crate) fn sys_pwritev(
        &self,
        fd: i32,
        iovec: UserPtr<IoWriteVec>,
        iovcnt: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        let base_offset = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.check_raw_fd_exists(fd)?;
        check_iovcnt(iovcnt)?;
        let iovs: &[IoWriteVec] = &iovec
            .to_owned_slice::<Platform>(iovcnt)
            .ok_or(Errno::EFAULT)?;
        // TODO: Linux ignores pwritev's offset for O_APPEND files; see the O_APPEND bug documented in pwrite(2).
        write_to_iovec::<_, Platform>(iovs, |buf, total| {
            let cur_offset = base_offset.checked_add(total).ok_or(Errno::EOVERFLOW)?;
            self.sys_write(fd, buf, Some(cur_offset))
        })
    }

    /// Handle syscall `preadv2`.
    ///
    /// `preadv` with an `RWF_*` flag word: an unknown flag is `EOPNOTSUPP` (Linux's
    /// `kiocb_set_rw_flags`), an offset of `-1` means "the current file offset" (`readv`
    /// semantics), and the hint flags (`HIPRI`, `DSYNC`, `SYNC`, `NOWAIT`, `DONTCACHE`) are
    /// accepted as no-ops -- memory-backed files never block or need syncing. `RWF_ATOMIC` is
    /// `EOPNOTSUPP` as on any filesystem without atomic-write support.
    pub(crate) fn sys_preadv2(
        &self,
        fd: i32,
        iovec: UserPtr<IoReadVec>,
        iovcnt: usize,
        offset: i64,
        flags: u32,
    ) -> Result<usize, Errno> {
        check_rwf_flags(flags)?;
        if offset == -1 {
            return self.sys_readv(fd, iovec, iovcnt);
        }
        self.sys_preadv(fd, iovec, iovcnt, offset)
    }

    /// Handle syscall `pwritev2`; see [`Self::sys_preadv2`] for the flag rules.
    ///
    /// `RWF_APPEND` writes at end-of-file whatever `offset` says; `RWF_NOAPPEND` (what
    /// `base::File::Write` passes so an `O_APPEND` file still honours the requested offset)
    /// is the behaviour positional writes here already have, so it needs nothing extra.
    pub(crate) fn sys_pwritev2(
        &self,
        fd: i32,
        iovec: UserPtr<IoWriteVec>,
        iovcnt: usize,
        offset: i64,
        flags: u32,
    ) -> Result<usize, Errno> {
        check_rwf_flags(flags)?;
        if flags & RWF_APPEND != 0 && flags & RWF_NOAPPEND != 0 {
            return Err(Errno::EINVAL);
        }
        if offset == -1 {
            return self.sys_writev(fd, iovec, iovcnt);
        }
        if flags & RWF_APPEND != 0 {
            let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
                return Err(Errno::EBADF);
            };
            let files = self.files.borrow();
            let size = files
                .run_on_raw_fd(
                    raw_fd,
                    |fd| {
                        files
                            .fs
                            .fd_file_status(fd)
                            .map(|s| s.size)
                            .map_err(Errno::from)
                    },
                    |_fd| Ok(0),
                    |_fd| Ok(0),
                    |_fd| Ok(0),
                    |_fd| Ok(0),
                    |_fd| Ok(0),
                    |_fd| Ok(0),
                )
                .flatten()?;
            drop(files);
            let at_end = i64::try_from(size).map_err(|_| Errno::EOVERFLOW)?;
            return self.sys_pwritev(fd, iovec, iovcnt, at_end);
        }
        self.sys_pwritev(fd, iovec, iovcnt, offset)
    }

    /// Handle syscall `readv`
    pub(crate) fn sys_readv(
        &self,
        fd: i32,
        iovec: UserPtr<IoReadVec>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        self.check_raw_fd_exists(fd)?;
        check_iovcnt(iovcnt)?;
        let iovs: &[IoReadVec] = &iovec
            .to_owned_slice::<Platform>(iovcnt)
            .ok_or(Errno::EFAULT)?;
        let mut kernel_buffer = vec![0u8; PAGE_SIZE];
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        read_from_iovec::<_, Platform>(iovs, &mut kernel_buffer, |buf, _total| {
            self.sys_read(fd, buf, None)
        })
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn check_raw_fd_exists(&self, fd: i32) -> Result<(), Errno> {
        let raw_fd = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        if self
            .files
            .borrow()
            .raw_descriptor_store
            .read()
            .is_alive(raw_fd)
        {
            Ok(())
        } else {
            Err(Errno::EBADF)
        }
    }
}

/// Linux's `IOV_MAX` / `UIO_MAXIOV`: the kernel rejects iovec counts above this
/// with `EINVAL` for `readv`/`writev`/`preadv`/`pwritev`.
const IOV_MAX: usize = 1024;
const SSIZE_MAX: usize = isize::MAX as usize;

/// `RWF_*` flags `preadv2`/`pwritev2` accept (`include/uapi/linux/fs.h`).
const RWF_HIPRI: u32 = 0x01;
const RWF_DSYNC: u32 = 0x02;
const RWF_SYNC: u32 = 0x04;
const RWF_NOWAIT: u32 = 0x08;
const RWF_APPEND: u32 = 0x10;
const RWF_NOAPPEND: u32 = 0x20;
const RWF_ATOMIC: u32 = 0x40;
const RWF_DONTCACHE: u32 = 0x80;
const RWF_SUPPORTED: u32 = RWF_HIPRI
    | RWF_DSYNC
    | RWF_SYNC
    | RWF_NOWAIT
    | RWF_APPEND
    | RWF_NOAPPEND
    | RWF_ATOMIC
    | RWF_DONTCACHE;

/// Linux's `kiocb_set_rw_flags` acceptance rules for a `preadv2`/`pwritev2` flag word.
fn check_rwf_flags(flags: u32) -> Result<(), Errno> {
    if flags & !RWF_SUPPORTED != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if flags & RWF_ATOMIC != 0 {
        // No filesystem here advertises `FMODE_CAN_ATOMIC_WRITE`.
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(())
}

fn check_iovcnt(iovcnt: usize) -> Result<(), Errno> {
    if iovcnt > IOV_MAX {
        Err(Errno::EINVAL)
    } else {
        Ok(())
    }
}

fn check_iov_lens(iov_lens: impl IntoIterator<Item = usize>) -> Result<(), Errno> {
    let mut total = 0usize;
    for iov_len in iov_lens {
        total = total.checked_add(iov_len).ok_or(Errno::EINVAL)?;
        if total > SSIZE_MAX {
            return Err(Errno::EINVAL);
        }
    }
    Ok(())
}

/// Drain reads into a sequence of user iovecs.
fn read_from_iovec<F, Platform: ShimPlatform>(
    iovs: &[IoReadVec],
    kernel_buffer: &mut [u8],
    mut read_fn: F,
) -> Result<usize, Errno>
where
    F: FnMut(&mut [u8], usize) -> Result<usize, Errno>,
{
    check_iov_lens(iovs.iter().map(|iov| iov.iov_len))?;

    let bail = |total: usize, e: Errno| if total > 0 { Ok(total) } else { Err(e) };
    let mut total_read = 0;
    'outer: for iov in iovs {
        let iov_base = iov.iov_base;
        let iov_len = iov.iov_len;
        if iov_len == 0 {
            continue;
        }
        let mut iov_filled = 0;
        while iov_filled < iov_len {
            let to_read = (iov_len - iov_filled).min(kernel_buffer.len());
            let size = match read_fn(&mut kernel_buffer[..to_read], total_read) {
                Ok(0) => break 'outer,
                Ok(s) => s,
                Err(e) => return bail(total_read, e),
            };
            if iov_base
                .copy_from_slice::<Platform>(iov_filled, &kernel_buffer[..size])
                .is_none()
            {
                return bail(total_read, Errno::EFAULT);
            }
            iov_filled += size;
            total_read += size;
            if size < to_read {
                // Short read from the source — treat as EOF for the remaining iovecs.
                break 'outer;
            }
        }
    }
    Ok(total_read)
}

/// Drain writes from a sequence of user iovecs.
///
/// `write_fn` receives the contents of each iovec along with the total number of
/// bytes already written from earlier iovecs.
pub(super) fn write_to_iovec<F, Platform: ShimPlatform>(
    iovs: &[IoWriteVec],
    mut write_fn: F,
) -> Result<usize, Errno>
where
    F: FnMut(&[u8], usize) -> Result<usize, Errno>,
{
    check_iov_lens(iovs.iter().map(|iov| iov.iov_len))?;

    // If any bytes have already been delivered from earlier iovecs, an error
    // collapses to `Ok(total)` so partial progress is reported to user space.
    let bail = |total: usize, e: Errno| if total > 0 { Ok(total) } else { Err(e) };
    let mut kernel_buffer = alloc::vec::Vec::new();
    let mut total_written = 0;
    'outer: for iov in iovs {
        let iov_base = iov.iov_base;
        let iov_len = iov.iov_len;
        if iov_len == 0 {
            continue;
        }
        if kernel_buffer.is_empty() {
            kernel_buffer.resize(PAGE_SIZE, 0);
        }
        let mut iov_written = 0;
        while iov_written < iov_len {
            let to_write = (iov_len - iov_written).min(kernel_buffer.len());
            let base_offset = isize::try_from(iov_written).unwrap();
            for (byte_offset, byte) in (0_isize..).zip(kernel_buffer[..to_write].iter_mut()) {
                let Some(value) = iov_base.read_at_offset::<Platform>(base_offset + byte_offset)
                else {
                    return bail(total_written, Errno::EFAULT);
                };
                *byte = value;
            }
            let size = match write_fn(&kernel_buffer[..to_write], total_written) {
                Ok(size) => size,
                Err(err) => return bail(total_written, err),
            };
            iov_written += size;
            total_written += size;
            if size < to_write {
                // Okay to transfer fewer bytes than requested.
                break 'outer;
            }
        }
    }
    Ok(total_written)
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Handle syscall `writev`
    pub(crate) fn sys_writev(
        &self,
        fd: i32,
        iovec: UserPtr<IoWriteVec>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        self.check_raw_fd_exists(fd)?;
        check_iovcnt(iovcnt)?;
        let iovs: &[IoWriteVec] = &iovec
            .to_owned_slice::<Platform>(iovcnt)
            .ok_or(Errno::EFAULT)?;
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        write_to_iovec::<_, Platform>(iovs, |buf, _total| self.sys_write(fd, buf, None))
    }

    fn validate_access_mode(mode: &AccessFlags) -> Result<(), Errno> {
        let valid_mode = AccessFlags::R_OK | AccessFlags::W_OK | AccessFlags::X_OK;
        if mode.intersects(valid_mode.complement()) {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    fn do_access_mode_values(
        mode: Mode,
        owner_user: u32,
        owner_group: u32,
        is_directory: bool,
        caller: AccessUserInfo<'_>,
        access_mode: &AccessFlags,
    ) -> Result<(), Errno> {
        if access_mode.is_empty() {
            return Ok(());
        }
        if caller.user == 0 {
            if access_mode.contains(AccessFlags::X_OK)
                && !is_directory
                && !mode.intersects(Mode::XUSR | Mode::XGRP | Mode::XOTH)
            {
                return Err(Errno::EACCES);
            }
            return Ok(());
        }
        let (read, write, execute) = if caller.user == owner_user {
            (Mode::RUSR, Mode::WUSR, Mode::XUSR)
        } else if caller.group == owner_group || caller.supplementary_groups.contains(&owner_group)
        {
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

    fn do_access_mode(
        status: &litebox::fs::FileStatus,
        caller: AccessUserInfo<'_>,
        access_mode: &AccessFlags,
    ) -> Result<(), Errno> {
        Self::do_access_mode_values(
            status.mode,
            u32::from(status.owner.user),
            u32::from(status.owner.group),
            status.file_type == litebox::fs::FileType::Directory,
            caller,
            access_mode,
        )
    }

    fn do_access(
        &self,
        pathname: impl path::Arg,
        mode: AccessFlags,
        caller: AccessUserInfo<'_>,
        follow_final: bool,
    ) -> Result<(), Errno> {
        // `access(2)` and ordinary `faccessat(2)` dereference a trailing symlink, so a dangling
        // link reports as absent and the target's permissions are checked. `faccessat2` with
        // `AT_SYMLINK_NOFOLLOW` instead checks the link node itself.
        let resolved = self.resolve_path_symlinks_with_final_as(
            caller.as_fs_credentials(),
            pathname.as_rust_str().map_err(|_| Errno::EINVAL)?,
            follow_final,
        )?;
        let status = self
            .files
            .borrow()
            .fs
            .file_status_as(caller.as_fs_credentials(), resolved.as_str())?;
        Self::do_access_mode(&status, caller, &mode)
    }

    /// Handle syscall `faccessat`
    pub(crate) fn sys_faccessat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        mode: AccessFlags,
        flags: AtFlags,
    ) -> Result<(), Errno> {
        let supported_flags =
            AtFlags::AT_EACCESS | AtFlags::AT_SYMLINK_NOFOLLOW | AtFlags::AT_EMPTY_PATH;
        if flags.intersects(supported_flags.complement()) {
            return Err(Errno::EINVAL);
        }

        Self::validate_access_mode(&mode)?;
        let credentials = self.credentials_snapshot();
        let caller =
            Self::access_user_from_snapshot(&credentials, flags.contains(AtFlags::AT_EACCESS));
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = self.fs_path(dirfd, pathname)?;
        let follow_final = !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW);
        match fs_path {
            FsPath::Absolute { path } => self.do_access(path, mode, caller, follow_final),
            FsPath::Cwd if flags.contains(AtFlags::AT_EMPTY_PATH) => {
                let cwd = get_cwd();
                self.do_access(cwd, mode, caller, follow_final)
            }
            FsPath::Fd(fd) if flags.contains(AtFlags::AT_EMPTY_PATH) => {
                let stat: FileStat = descriptor_stat(fd as usize, self)?;
                Self::do_access_mode_values(
                    Mode::from_bits_truncate(stat.st_mode & 0o7777),
                    stat.st_uid,
                    stat.st_gid,
                    stat.st_mode & 0o170000 == InodeType::Dir as u32,
                    caller,
                    &mode,
                )
            }
            FsPath::Cwd | FsPath::Fd(_) => Err(Errno::ENOENT),
            FsPath::FdRelative { fd, path } => {
                let dir_path = self.resolve_dirfd_path(fd)?;
                let joined = self.join_dir_relative_path(&dir_path, &path)?;
                self.do_access(joined, mode, caller, follow_final)
            }
        }
    }

    /// Read the target of a symbolic link
    ///
    /// The caller must pass an absolute path.
    fn do_readlink(&self, fullpath: &str) -> Result<String, Errno> {
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        self.do_readlink_as(caller.as_fs_credentials(), fullpath)
    }

    fn do_readlink_as(
        &self,
        credentials: AccessCredentials<'_>,
        fullpath: &str,
    ) -> Result<String, Errno> {
        // Follow every intermediate link (`/proc/self/...` included -- `self` is itself a
        // link) but never the final one, which is the object being read.
        let fullpath = self.resolve_path_symlinks_with_final_as(credentials, fullpath, false)?;
        self.publish_proc_view(&fullpath);

        // A symbolic link in the filesystem (`/proc/<pid>/fd/<n>` included): return its target
        // verbatim. `readlink(2)` is EINVAL on a non-symlink and ENOENT on a missing path,
        // which is exactly how `FileSystem::readlink` maps.
        self.files
            .borrow()
            .fs
            .readlink_as(credentials, fullpath.as_str())
            .map_err(Errno::from)
    }

    /// Handle syscall `readlink`
    pub fn sys_readlink(&self, pathname: impl path::Arg, buf: &mut [u8]) -> Result<usize, Errno> {
        self.sys_readlinkat(litebox_common_linux::AT_FDCWD, pathname, buf)
    }

    /// Handle syscall `readlinkat`
    pub fn sys_readlinkat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        buf: &mut [u8],
    ) -> Result<usize, Errno> {
        let pathname = self.resolve_path_at(dirfd, pathname)?;
        let path = self.do_readlink(pathname.to_str().map_err(|_| Errno::EINVAL)?);
        // Same rationale as `sys_openat`'s trace line: the raw request only carries a user
        // pointer, and readlink targets are load-bearing for sysfs-probing guests.
        litebox_util_log::trace!(
            pid:? = self.pid,
            tid:? = self.tid,
            path:? = pathname,
            result:? = path;
            "readlinkat"
        );
        let path = path?;
        let bytes = path.as_bytes();
        let min_len = core::cmp::min(buf.len(), bytes.len());
        buf[..min_len].copy_from_slice(&bytes[..min_len]);
        Ok(min_len)
    }
}

/// Block size used for the synthetic `statfs` figures below, as both the `i64` the ABI struct's
/// fields need and the `u64` the byte-count constants below need to divide by.
const SYNTHETIC_DISK_BLOCK_SIZE: i64 = 4096;
const SYNTHETIC_DISK_BLOCK_SIZE_U64: u64 = 4096;
/// Total synthetic "disk" space, matching the scale of `sys_sysinfo`'s synthetic RAM figures
/// (`litebox::fs::proc::SYNTHETIC_TOTAL_RAM_BYTES`) rather than anything measured -- LiteBox does
/// not model real per-mount disk usage. Kept a distinct constant since disk and RAM are unrelated
/// figures on any real system.
const SYNTHETIC_DISK_TOTAL_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Free synthetic "disk" space; half of [`SYNTHETIC_DISK_TOTAL_BYTES`], the same
/// total/free ratio `sys_sysinfo`'s synthetic RAM figures use.
const SYNTHETIC_DISK_FREE_BYTES: u64 = SYNTHETIC_DISK_TOTAL_BYTES / 2;
/// `TMPFS_MAGIC` from `<linux/magic.h>`: the closest real filesystem-type magic to LiteBox's own
/// synthetic, in-memory-backed filesystem.
const SYNTHETIC_STATFS_MAGIC: i64 = 0x0102_1994;

/// The same synthetic `statfs` figures for every path/fd -- see `sys_statfs`/`sys_fstatfs`.
fn synthetic_statfs() -> litebox_common_linux::Statfs {
    litebox_common_linux::Statfs {
        f_type: SYNTHETIC_STATFS_MAGIC,
        f_bsize: SYNTHETIC_DISK_BLOCK_SIZE,
        f_blocks: SYNTHETIC_DISK_TOTAL_BYTES / SYNTHETIC_DISK_BLOCK_SIZE_U64,
        f_bfree: SYNTHETIC_DISK_FREE_BYTES / SYNTHETIC_DISK_BLOCK_SIZE_U64,
        f_bavail: SYNTHETIC_DISK_FREE_BYTES / SYNTHETIC_DISK_BLOCK_SIZE_U64,
        f_files: 0,
        f_ffree: 0,
        f_fsid: [0, 0],
        f_namelen: 255,
        f_frsize: SYNTHETIC_DISK_BLOCK_SIZE,
        f_flags: 0,
        f_spare: [0; 4],
    }
}

/// `st_nlink`/`stx_nlink` of a `stat` result, so a link count the generic `From<FileStatus>`
/// conversion cannot know (it reports 1) can be filled in afterwards -- see
/// [`Task::proc_dir_link_count`].
trait StatLinkCount {
    fn set_link_count(&mut self, count: u64);
}

impl StatLinkCount for FileStat {
    fn set_link_count(&mut self, count: u64) {
        #[cfg(target_arch = "x86_64")]
        {
            self.st_nlink = count;
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.st_nlink = count.trunc();
        }
    }
}

impl StatLinkCount for Statx {
    fn set_link_count(&mut self, count: u64) {
        self.stx_nlink = count.trunc();
    }
}

/// Convert a [`litebox::fs::FileStatus`] into a `stat` result, filling in the link count of a
/// `/proc` directory (see [`litebox::fs::proc::Proc::dir_link_count_at`]) -- `path` is the
/// real absolute path `status` describes, when known.
fn stat_from_status<Platform: ShimPlatform, FS: ShimFS, T>(
    task: &Task<Platform, FS>,
    status: litebox::fs::FileStatus,
    path: Option<&str>,
) -> T
where
    T: From<litebox::fs::FileStatus> + StatLinkCount,
{
    let link_count = path.and_then(|path| task.proc_dir_link_count(&status, path));
    let mut stat = T::from(status);
    if let Some(link_count) = link_count {
        stat.set_link_count(link_count);
    }
    stat
}

fn descriptor_stat<Platform: ShimPlatform, FS: ShimFS, T>(
    raw_fd: usize,
    task: &Task<Platform, FS>,
) -> Result<T, Errno>
where
    T: From<litebox::fs::FileStatus> + From<FileStat> + StatLinkCount,
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
        // The x86-64 `struct stat` declares `st_blksize` as a signed word the
        // width of a pointer; the generic layout aarch64 uses declares it as a
        // plain `int`. Both are wide enough for any block size LiteBox reports.
        #[cfg(target_arch = "x86_64")]
        st_blksize: blksize,
        #[cfg(target_arch = "aarch64")]
        st_blksize: blksize.reinterpret_as_signed().trunc(),
        st_blocks: 0,
        ..Default::default()
    };
    let socket_mode = litebox_common_linux::InodeType::Socket as u32
        | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits();
    let rw_user_mode = (Mode::RUSR | Mode::WUSR).bits();
    let files = task.files.borrow();
    files
        .run_on_raw_fd(
            raw_fd,
            |fd| {
                let path = task
                    .global
                    .litebox
                    .descriptor_table()
                    .with_metadata(fd, |path: &FdPath| path.0.clone())
                    .ok();
                files
                    .fs
                    .fd_file_status(fd)
                    .map(|status| {
                        stat_from_status(task, status, path.as_ref().and_then(|p| p.to_str().ok()))
                    })
                    .map_err(Errno::from)
            },
            |_fd| Ok(T::from(synthetic(socket_mode, 4096))),
            |fd| {
                Ok(T::from(synthetic(
                    task.global.linux_pipe_mode_bits(fd)?,
                    4096,
                )))
            },
            |_fd| Ok(T::from(synthetic(rw_user_mode, 4096))),
            |_fd| Ok(T::from(synthetic(rw_user_mode, 0))),
            |_fd| Ok(T::from(synthetic(socket_mode, 4096))),
            |_fd| Ok(T::from(synthetic(socket_mode, 4096))),
        )
        .flatten()
}

pub(crate) fn get_file_descriptor_flags<Platform: ShimPlatform, FS: ShimFS>(
    raw_fd: usize,
    global: &GlobalState<Platform, FS>,
    files: &FilesState<Platform, FS>,
) -> Result<FileDescriptorFlags, Errno> {
    // Currently, only one such flag is defined: FD_CLOEXEC, the close-on-exec flag.
    // See https://www.man7.org/linux/man-pages/man2/F_GETFD.2const.html
    fn get_flags<Platform: ShimPlatform, FS: ShimFS, S: FdEnabledSubsystem>(
        global: &GlobalState<Platform, FS>,
        fd: &TypedFd<S>,
    ) -> FileDescriptorFlags {
        global
            .litebox
            .descriptor_table()
            .with_metadata(fd, |flags: &FileDescriptorFlags| *flags)
            .unwrap_or(FileDescriptorFlags::empty())
    }
    // See the matching pre-check in `fork_copy`/`do_read`/`do_close`: inotify fds sit outside
    // `run_on_raw_fd`'s hand-enumerated subsystem list, so resolve them directly first.
    if let Ok(inotify_fd) = files
        .raw_descriptor_store
        .read()
        .fd_from_raw_integer::<super::inotify::InotifySubsystem<Platform>>(raw_fd)
    {
        return Ok(get_flags(global, &inotify_fd));
    }
    files.run_on_raw_fd(
        raw_fd,
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
    )
}

fn set_file_descriptor_flags<Platform: ShimPlatform, FS: ShimFS>(
    raw_fd: usize,
    global: &GlobalState<Platform, FS>,
    files: &FilesState<Platform, FS>,
    flags: FileDescriptorFlags,
) -> Result<(), Errno> {
    fn set_flags<Platform: ShimPlatform, FS: ShimFS, S: FdEnabledSubsystem>(
        global: &GlobalState<Platform, FS>,
        fd: &TypedFd<S>,
        flags: FileDescriptorFlags,
    ) {
        let _old = global
            .litebox
            .descriptor_table_mut()
            .set_fd_metadata(fd, flags);
    }

    // See the matching pre-check in `get_file_descriptor_flags` just above.
    if let Ok(inotify_fd) = files
        .raw_descriptor_store
        .read()
        .fd_from_raw_integer::<super::inotify::InotifySubsystem<Platform>>(raw_fd)
    {
        set_flags(global, &inotify_fd, flags);
        return Ok(());
    }
    files.run_on_raw_fd(
        raw_fd,
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
    )?;
    Ok(())
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Get the file status of `pathname`.
    ///
    /// The `pathname` must be absolute.
    /// The `st_nlink` a directory of the mounted `/proc` reports: Linux's `2 + <subdirectories>`,
    /// which for `/proc/<pid>/task` counts the live threads (Chromium's
    /// `ThreadHelpers::IsSingleThreaded` reads exactly this). `None` for anything else, which
    /// keeps the generic conversion's answer. `path` is the real absolute path `status`
    /// describes; `/proc` is mounted at the real `/proc`, so beneath a `chroot` nothing matches.
    fn proc_dir_link_count(&self, status: &litebox::fs::FileStatus, path: &str) -> Option<u64> {
        if status.file_type != litebox::fs::FileType::Directory {
            return None;
        }
        let under_proc = path.strip_prefix("/proc")?;
        if !(under_proc.is_empty() || under_proc.starts_with('/')) {
            return None;
        }
        let components: alloc::vec::Vec<&str> = under_proc
            .split('/')
            .filter(|component| !component.is_empty() && *component != ".")
            .collect();
        self.global
            .proc_handle
            .as_ref()?
            .dir_link_count_at(&components)
    }

    fn do_stat<T: From<litebox::fs::FileStatus> + From<FileStat> + StatLinkCount>(
        &self,
        pathname: impl path::Arg,
        follow_symlink: bool,
    ) -> Result<T, Errno> {
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        self.do_stat_as(caller.as_fs_credentials(), pathname, follow_symlink)
    }

    /// If `path` is `/proc/self/fd/<n>`, `/proc/thread-self/fd/<n>` or `/proc/<own pid>/fd/<n>`
    /// for an open descriptor `n` of this task, that descriptor. Linux resolves such a magic
    /// link to the open file itself, whatever its `readlink` text says.
    fn proc_fd_magic_link(&self, path: &str) -> Option<i32> {
        let rest = path.strip_prefix("/proc/")?;
        let (who, rest) = rest.split_once('/')?;
        let mine =
            who == "self" || who == "thread-self" || who.parse::<i32>().ok() == Some(self.pid);
        if !mine {
            return None;
        }
        let n = rest.strip_prefix("fd/")?;
        if n.is_empty() || n.contains('/') || !n.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let fd = n.parse::<i32>().ok()?;
        self.check_raw_fd_exists(fd).ok()?;
        Some(fd)
    }

    fn do_stat_as<T: From<litebox::fs::FileStatus> + From<FileStat> + StatLinkCount>(
        &self,
        credentials: AccessCredentials<'_>,
        pathname: impl path::Arg,
        follow_symlink: bool,
    ) -> Result<T, Errno> {
        // `stat` follows a trailing symlink, `lstat` reports the link itself; both follow every
        // intermediate link, so the same component walk `open` uses runs for either -- on the
        // raw path, never a lexically normalized one: collapsing `..` ahead of link expansion
        // turned `/tmp/bindir/../etc/hosts` (bindir -> /bin) into `/tmp/etc/hosts`, and skipping
        // the walk for `lstat` made `ls -l /var/run/x` (run -> ../run) answer `ENOTDIR`.
        let path = self.resolve_path_symlinks_with_final_as(
            credentials,
            pathname.as_rust_str().map_err(|_| Errno::EINVAL)?,
            follow_symlink,
        )?;
        if follow_symlink && let Some(fd) = self.proc_fd_magic_link(&path) {
            // `stat("/proc/self/fd/N")` is `fstat(N)` on Linux (the link resolves to the open
            // file, not to its path), which is what lets a sandbox's "no open directories"
            // sweep `fstatat` every descriptor, sockets and unlinked files included.
            return descriptor_stat(fd.cast_unsigned() as usize, self);
        }
        let status = self
            .files
            .borrow()
            .fs
            .file_status_as(credentials, path.as_str())?;
        Ok(stat_from_status(self, status, Some(path.as_str())))
    }

    /// Handle syscall `stat`
    pub fn sys_stat(&self, pathname: impl path::Arg) -> Result<FileStat, Errno> {
        let pathname = self.resolve_path(pathname)?;
        self.do_stat(pathname, true)
    }

    /// Handle syscall `lstat`
    ///
    /// `lstat` is identical to `stat`, except that if `pathname` is a symbolic link,
    /// then it returns information about the link itself, not the file that the link refers to.
    /// TODO: we do not support symbolic links yet.
    pub fn sys_lstat(&self, pathname: impl path::Arg) -> Result<FileStat, Errno> {
        let pathname = self.resolve_path(pathname)?;
        self.do_stat(pathname, false)
    }

    /// Handle syscall `fstat`
    pub fn sys_fstat(&self, fd: i32) -> Result<FileStat, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        descriptor_stat(raw_fd, self)
    }

    fn do_fstatat<T>(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
    ) -> Result<T, Errno>
    where
        T: From<litebox::fs::FileStatus> + From<FileStat> + StatLinkCount,
    {
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = self.fs_path(dirfd, pathname)?;
        match fs_path {
            FsPath::Absolute { path } => self.do_stat_as(
                fs_credentials,
                path,
                !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW),
            ),
            FsPath::Cwd if flags.contains(AtFlags::AT_EMPTY_PATH) => Ok(T::from(
                self.files
                    .borrow()
                    .fs
                    .file_status_as(fs_credentials, get_cwd())?,
            )),
            FsPath::Fd(fd) if flags.contains(AtFlags::AT_EMPTY_PATH) => {
                descriptor_stat(fd as usize, self)
            }
            FsPath::Cwd | FsPath::Fd(_) => Err(Errno::ENOENT),
            FsPath::FdRelative { fd, path } => {
                let dir_path = self.resolve_dirfd_path(fd)?;
                let joined = self.join_dir_relative_path(&dir_path, &path)?;
                self.do_stat_as(
                    fs_credentials,
                    joined,
                    !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW),
                )
            }
        }
    }

    /// Handle syscall `newfstatat`
    pub(crate) fn sys_newfstatat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
    ) -> Result<FileStat, Errno> {
        // `AT_SYMLINK_NOFOLLOW` is the flag `ls` and every other directory
        // walker passes, and `do_fstatat` already acts on it -- it selects
        // whether `do_stat` resolves the final component. Rejecting it here
        // while `statx` and `faccessat` both accept it made `lstat` fail with
        // `EINVAL` on a path that `stat` handled. `AT_NO_AUTOMOUNT` is accepted
        // as the same no-op `statx` treats it as, since no LiteBox filesystem
        // automounts.
        let current_support_flags =
            AtFlags::AT_EMPTY_PATH | AtFlags::AT_SYMLINK_NOFOLLOW | AtFlags::AT_NO_AUTOMOUNT;
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
        pathname: impl path::Arg,
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

    /// Handle syscall `statfs`.
    ///
    /// LiteBox does not model per-mount free/total space, so every path (on any mount) reports
    /// the same synthetic figures -- just enough for `df`'s `statvfs` call (via
    /// `/proc/mounts`-enumerated mount points, see `litebox::fs::proc`) to succeed rather than
    /// fail outright. The path only needs to resolve to *something*; real Linux behaves the same
    /// way for any path on the same filesystem.
    pub(crate) fn sys_statfs(
        &self,
        pathname: impl path::Arg,
        buf: UserPtrMut<litebox_common_linux::Statfs>,
    ) -> Result<(), Errno> {
        let resolved = self.resolve_path(pathname)?;
        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        let abs_path = self.resolve_syscall_path_as(fs_credentials, &resolved, true)?;
        self.files
            .borrow()
            .fs
            .file_status_as(fs_credentials, abs_path.as_str())
            .map_err(Errno::from)?;
        buf.write_at_offset::<Platform>(0, synthetic_statfs())
            .ok_or(Errno::EFAULT)
    }

    /// Handle syscall `fstatfs`. See [`Self::sys_statfs`] on why every result is the same.
    pub(crate) fn sys_fstatfs(
        &self,
        fd: i32,
        buf: UserPtrMut<litebox_common_linux::Statfs>,
    ) -> Result<(), Errno> {
        self.sys_fstat(fd)?;
        buf.write_at_offset::<Platform>(0, synthetic_statfs())
            .ok_or(Errno::EFAULT)
    }

    pub(crate) fn sys_fcntl(&self, fd: i32, arg: FcntlArg) -> Result<u32, Errno> {
        let Ok(desc) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match arg {
            FcntlArg::GETFD => Ok(get_file_descriptor_flags(desc, &self.global, &files)?.bits()),
            FcntlArg::SETFD(flags) => {
                set_file_descriptor_flags(desc, &self.global, &files, flags).map(|()| 0)
            }
            FcntlArg::GETFL => {
                macro_rules! getfl_from_metadata {
                    ($fd:expr, $MetaType:path) => {
                        Ok(self
                            .global
                            .litebox
                            .descriptor_table()
                            .with_metadata($fd, |$MetaType(flags)| {
                                *flags & OFlags::STATUS_FLAGS_MASK
                            })
                            .unwrap_or(OFlags::empty()))
                    };
                }
                macro_rules! getfl_from_handle {
                    ($fd:ident) => {{
                        // TODO: Consider shared metadata table?
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle($fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file| Ok(file.get_status()))
                    }};
                }
                Ok(files
                    .run_on_raw_fd(
                        desc,
                        |fd| {
                            // Stdio fds carry `StdioStatusFlags`; every fd `sys_openat` opened
                            // carries `FdOpenFlags` (its access mode plus the status flags it was
                            // opened with, kept current by `SETFL` below). Linux answers
                            // `F_GETFL` from exactly that open-file-description state -- an
                            // `O_RDWR` file must report `O_RDWR`, which Chromium's shared-memory
                            // `CheckFDAccessMode` `CHECK`s -- so answer from the record and only
                            // fall back to "no flags" for an fd that has neither.
                            let dt = self.global.litebox.descriptor_table();
                            match dt
                                .with_metadata(fd, |crate::StdioStatusFlags(flags)| {
                                    *flags & OFlags::STATUS_FLAGS_MASK
                                })
                                .or_else(|_| {
                                    dt.with_metadata(fd, |FdOpenFlags(flags)| {
                                        *flags & OFlags::STATUS_FLAGS_MASK
                                    })
                                }) {
                                Ok(flags) => Ok(flags),
                                Err(MetadataError::ClosedFd) => Err(Errno::EBADF),
                                Err(MetadataError::NoSuchMetadata) => Ok(OFlags::empty()),
                            }
                        },
                        |fd| getfl_from_metadata!(fd, crate::syscalls::net::SocketOFlags),
                        |fd| self.global.linux_pipe_status_flags(fd),
                        |fd| getfl_from_handle!(fd),
                        |fd| getfl_from_handle!(fd),
                        |fd| getfl_from_handle!(fd),
                        |fd| getfl_from_metadata!(fd, crate::syscalls::net::SocketOFlags),
                    )
                    .flatten()?
                    .bits())
            }
            FcntlArg::SETFL(flags) => {
                let setfl_mask = OFlags::APPEND
                    | OFlags::NONBLOCK
                    | OFlags::NDELAY
                    | OFlags::DIRECT
                    | OFlags::NOATIME;
                let flags = flags & setfl_mask;
                macro_rules! toggle_flags {
                    ($fd:ident) => {{
                        // TODO: Consider shared metadata table?
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle($fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file| {
                            let diff = (file.get_status() & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            file.set_status(flags & setfl_mask, true);
                            file.set_status(flags.complement() & setfl_mask, false);
                        });
                    }};
                }
                macro_rules! setfl_in_metadata {
                    ($fd:expr, $MetaType:path, $no_metadata_msg:expr) => {
                        setfl_in_metadata!($fd, $MetaType, $no_metadata_msg, |diff: OFlags| {
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                        })
                    };
                    ($fd:expr, $MetaType:path, $no_metadata_msg:expr, $check_diff:expr) => {
                        self.global
                            .litebox
                            .descriptor_table_mut()
                            .with_metadata_mut($fd, |$MetaType(f)| {
                                let diff = (*f & setfl_mask) ^ flags;
                                $check_diff(diff);
                                f.toggle(diff);
                            })
                            .map_err(|err| match err {
                                MetadataError::ClosedFd => Errno::EBADF,
                                MetadataError::NoSuchMetadata => $no_metadata_msg,
                            })
                    };
                }
                files.run_on_raw_fd(
                    desc,
                    |fd| {
                        // Only stdio raw fds carry `StdioStatusFlags` metadata (see
                        // `initialize_stdio_in_shared_descriptors_table`); other regular files
                        // have no status-flags story at the `Backend` layer (mirroring GETFL's
                        // fallback to `OFlags::empty()` above), so `NoSuchMetadata` here is
                        // expected and silently ignored, matching this ioctl's precedent for
                        // FIONBIO and real Linux's no-op SETFL on regular files.
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        match dt.with_metadata_mut(fd, |crate::StdioStatusFlags(f)| {
                            let diff = (*f & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            f.toggle(diff);
                        }) {
                            Ok(()) => Ok(()),
                            Err(MetadataError::ClosedFd) => Err(Errno::EBADF),
                            // Not a stdio fd: keep the open-time record (`FdOpenFlags`, what
                            // `F_GETFL` and `/proc/<pid>/fdinfo` answer from) in step with the
                            // request, so a later `F_GETFL` reports the `O_NONBLOCK`/`O_APPEND`
                            // the guest just set, as Linux does. `O_APPEND` toggled here is
                            // recorded but not yet honoured by the write path (see
                            // `sys_pwritev`'s note); that is the same no-op SETFL a regular file
                            // already got, now visible instead of silently dropped.
                            Err(MetadataError::NoSuchMetadata) => {
                                match dt.with_metadata_mut(fd, |FdOpenFlags(f)| {
                                    let diff = (*f & setfl_mask) ^ flags;
                                    f.toggle(diff);
                                }) {
                                    Ok(()) | Err(MetadataError::NoSuchMetadata) => Ok(()),
                                    Err(MetadataError::ClosedFd) => Err(Errno::EBADF),
                                }
                            }
                        }
                    },
                    |fd| {
                        setfl_in_metadata!(
                            fd,
                            crate::syscalls::net::SocketOFlags,
                            unreachable!("all sockets have SocketOFlags when created")
                        )
                    },
                    |fd| {
                        self.global
                            .set_linux_pipe_status_flags(fd, flags, setfl_mask)
                    },
                    |fd| {
                        toggle_flags!(fd);
                        Ok(())
                    },
                    |_fd| todo!("epoll"),
                    |fd| {
                        toggle_flags!(fd);
                        Ok(())
                    },
                    |fd| {
                        setfl_in_metadata!(
                            fd,
                            crate::syscalls::net::SocketOFlags,
                            unreachable!("all netlink sockets have SocketOFlags when created")
                        )
                    },
                )??;
                Ok(0)
            }
            FcntlArg::GET_SEALS => files
                .run_on_raw_fd(
                    desc,
                    |fd| {
                        self.global
                            .litebox
                            .descriptor_table()
                            .with_metadata(fd, |memfd: &MemfdBacking| memfd.seals())
                            .map_err(|error| match error {
                                MetadataError::ClosedFd => Errno::EBADF,
                                MetadataError::NoSuchMetadata => Errno::EINVAL,
                            })
                    },
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                )
                .flatten(),
            FcntlArg::ADD_SEALS(seals) => files
                .run_on_raw_fd(
                    desc,
                    |fd| {
                        self.global
                            .litebox
                            .descriptor_table()
                            .with_metadata(fd, |memfd: &MemfdBacking| memfd.add_seals(seals))
                            .map_err(|error| match error {
                                MetadataError::ClosedFd => Errno::EBADF,
                                MetadataError::NoSuchMetadata => Errno::EINVAL,
                            })?
                            .map(|()| 0)
                    },
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                )
                .flatten(),
            FcntlArg::GETLK(lock) => {
                self.files
                    .borrow()
                    .run_on_raw_fd(
                        desc,
                        |_fd| {
                            let mut flock =
                                lock.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
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
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                    )
                    .flatten()
            }
            FcntlArg::SETLK(lock) | FcntlArg::SETLKW(lock) => {
                self.files
                    .borrow()
                    .run_on_raw_fd(
                        desc,
                        |_fd| {
                            let flock = lock.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                            let _ = litebox_common_linux::FlockType::try_from(flock.type_)
                                .map_err(|_| Errno::EINVAL)?;

                            // Note LiteBox does not support multiple processes yet, and one process
                            // can always acquire the lock it owns, so we don't need to maintain anything.
                            Ok(0)
                        },
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                    )
                    .flatten()
            }
            FcntlArg::DUPFD { cloexec, min_fd } => {
                let new_file = self
                    .do_dup_inner(
                        desc,
                        if cloexec {
                            OFlags::CLOEXEC
                        } else {
                            OFlags::empty()
                        },
                        DupFdRequest::LowestAtOrAbove(min_fd as usize),
                    )
                    .map_err(|e| match e {
                        DupFdError::BadFd => Errno::EBADF,
                        DupFdError::TooManyFiles => Errno::EMFILE,
                        DupFdError::TargetFdExceedsLimit => Errno::EINVAL,
                    })?;
                Ok(new_file.try_into().unwrap())
            }
            _ => unimplemented!(),
        }
    }

    /// Handle syscall `getcwd`
    pub fn sys_getcwd(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let cwd = Self::guest_visible_path(&self.fs_root(), &self.fs.borrow().cwd.read());
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
    pub fn sys_chdir(&self, pathname: impl path::Arg) -> Result<(), Errno> {
        use litebox::fs::FileType;
        use litebox::fs::errors::{FileStatusError, PathError};

        let credentials = self.credentials_snapshot();
        let caller = Self::access_user_from_snapshot(&credentials, true);
        let fs_credentials = caller.as_fs_credentials();
        // Resolve relative paths against CWD; `.`/`..` are applied by the component walk
        // below, after any intermediate link they follow has been expanded.
        let resolved = self.resolve_path(pathname)?;
        // `chdir(2)` dereferences a trailing symlink, so `cd` into a symlinked
        // directory works (and lands the cwd on the link's target).
        let abs_path = self.resolve_syscall_path_as(fs_credentials, &resolved, true)?;

        // Verify the path exists, is a directory, and is searchable by the caller.
        match self
            .files
            .borrow()
            .fs
            .file_status_as(fs_credentials, abs_path.as_str())
        {
            Ok(status) => {
                if status.file_type != FileType::Directory {
                    return Err(Errno::ENOTDIR);
                }
                Self::do_access_mode(&status, caller, &AccessFlags::X_OK)?;
            }
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory)) => {
                return Err(Errno::ENOENT);
            }
            Err(FileStatusError::PathError(_)) => {
                return Err(Errno::EACCES);
            }
            Err(_) => {
                return Err(Errno::ENOENT);
            }
        }

        // Ensure the CWD ends with '/'.
        let mut new_cwd = abs_path;
        if !new_cwd.ends_with('/') {
            new_cwd.push('/');
        }

        *self.fs.borrow().cwd.write() = new_cwd;
        Ok(())
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Handle syscall `pipe2`
    pub fn sys_pipe2(&self, flags: OFlags) -> Result<(u32, u32), Errno> {
        let pipe = self.global.create_linux_pipe(flags)?;

        let files = self.files.borrow();
        let wr_raw_fd = files.insert_raw_fd(pipe.writer).map_err(|writer| {
            self.global.close_linux_pipe(&writer).unwrap();
            Errno::EMFILE
        })?;
        let rd_raw_fd = files.insert_raw_fd(pipe.reader).map_err(|reader| {
            let writer = files
                .raw_descriptor_store
                .write()
                .fd_consume_raw_integer(wr_raw_fd)
                .unwrap();
            self.global.close_linux_pipe(&writer).unwrap();
            self.global.close_linux_pipe(&reader).unwrap();
            Errno::EMFILE
        })?;
        Ok((rd_raw_fd.try_into().unwrap(), wr_raw_fd.try_into().unwrap()))
    }

    pub fn sys_eventfd2(&self, initval: u32, flags: EfdFlags) -> Result<u32, Errno> {
        if flags
            .intersects((EfdFlags::SEMAPHORE | EfdFlags::CLOEXEC | EfdFlags::NONBLOCK).complement())
        {
            return Err(Errno::EINVAL);
        }

        let eventfd = self.global.create_linux_eventfd(initval, flags)?;
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<super::eventfd::EventfdSubsystem<Platform>>(eventfd);
        if flags.contains(EfdFlags::CLOEXEC) {
            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        drop(dt);
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
            self.global
                .litebox
                .descriptor_table_mut()
                .remove(&typed)
                .unwrap();
            Errno::EMFILE
        })?;
        Ok(raw_fd.try_into().unwrap())
    }

    /// Handle syscall `inotify_init1` (and plain `inotify_init`, dispatched with `flags` forced
    /// empty -- see `SyscallRequest::InotifyInit1`'s construction from `Sysno::inotify_init`).
    pub fn sys_inotify_init1(&self, flags: InotifyInitFlags) -> Result<u32, Errno> {
        if flags.intersects((InotifyInitFlags::NONBLOCK | InotifyInitFlags::CLOEXEC).complement()) {
            return Err(Errno::EINVAL);
        }

        let inotify = self.global.create_linux_inotify(flags);
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<super::inotify::InotifySubsystem<Platform>>(inotify);
        if flags.contains(InotifyInitFlags::CLOEXEC) {
            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        drop(dt);
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
            self.global
                .litebox
                .descriptor_table_mut()
                .remove(&typed)
                .unwrap();
            Errno::EMFILE
        })?;
        Ok(raw_fd.try_into().unwrap())
    }

    /// Handle syscall `inotify_add_watch`. `pathname` is accepted (matching this shim's
    /// no-change-notification-producer honesty note in `syscalls::inotify`'s doc comment: a
    /// watch is only ever validated as a syntactically well-formed request, never resolved
    /// against the filesystem, since it will never actually observe that path change) but is not
    /// otherwise inspected.
    pub fn sys_inotify_add_watch(
        &self,
        fd: i32,
        _pathname: alloc::ffi::CString,
        mask: InotifyMask,
    ) -> Result<i32, Errno> {
        let files = self.files.borrow();
        let inotify_fd = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::inotify::InotifySubsystem<Platform>>(
                fd.reinterpret_as_unsigned() as usize,
            )
            .map_err(|_| Errno::EBADF)?;
        let handle = self
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&inotify_fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(|file| file.add_watch(mask))
    }

    /// Handle syscall `inotify_rm_watch`.
    pub fn sys_inotify_rm_watch(&self, fd: i32, wd: i32) -> Result<(), Errno> {
        let files = self.files.borrow();
        let inotify_fd = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::inotify::InotifySubsystem<Platform>>(
                fd.reinterpret_as_unsigned() as usize,
            )
            .map_err(|_| Errno::EBADF)?;
        let handle = self
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&inotify_fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(|file| file.rm_watch(wd))
    }

    fn stdio_ioctl(&self, stream: StdioStream, arg: &IoctlArg) -> Result<u32, Errno> {
        match arg {
            IoctlArg::TCGETS(termios) => {
                let current = self.global.termios.lock().clone();
                termios
                    .write_at_offset::<Platform>(0, current)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TCSETS(termios, action) => {
                let new_termios = termios.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                let lflag = litebox_common_linux::LFlag::from_bits_truncate(new_termios.c_lflag);
                let raw = !lflag.contains(litebox_common_linux::LFlag::ICANON);
                let echo = lflag.contains(litebox_common_linux::LFlag::ECHO);
                *self.global.termios.lock() = new_termios;
                // Mirror the raw/echo-relevant bits onto the real host terminal so keystrokes
                // actually arrive byte-at-a-time once the guest disables canonical mode, honoring
                // TCSETS/TCSETSW/TCSETSF's NOW/DRAIN/FLUSH distinction -- a no-op on
                // platforms/streams without a real backing terminal.
                let platform_action = match action {
                    litebox_common_linux::TerminalSetAction::Now => {
                        litebox::platform::TerminalSetAction::Now
                    }
                    litebox_common_linux::TerminalSetAction::Drain => {
                        litebox::platform::TerminalSetAction::Drain
                    }
                    litebox_common_linux::TerminalSetAction::Flush => {
                        litebox::platform::TerminalSetAction::Flush
                    }
                };
                self.global.platform.set_terminal_raw_mode_with_action(
                    stream,
                    raw,
                    echo,
                    platform_action,
                );
                Ok(0)
            }
            IoctlArg::TIOCGPGRP(pgrp) => {
                let pgid = self.global.stdio_foreground_pgid.load(Ordering::Acquire);
                pgrp.write_at_offset::<Platform>(0, pgid)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCSPGRP(pgrp) => {
                let pgid = pgrp.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                if pgid <= 0 {
                    return Err(Errno::EINVAL);
                }
                self.global
                    .stdio_foreground_pgid
                    .store(pgid, Ordering::Release);
                Ok(0)
            }
            IoctlArg::TIOCGWINSZ(ws) => {
                // Query the real terminal size where the platform can provide it (e.g. via
                // `TIOCGWINSZ` on the real host fd, or `GetConsoleScreenBufferInfo` on Windows);
                // fall back to the traditional 80x24 default otherwise. A guest's own line
                // editor (e.g. `ash`'s `lineedit.c`) uses this to decide the column width at
                // which to wrap its own echoed-input redisplay, so returning a fake, too-narrow
                // size here (previously hardcoded to 20x20) caused spurious wraps in the echo of
                // typed input well before the real terminal would ever need to wrap.
                let (row, col) = self.global.platform.tty_window_size().unwrap_or((24, 80));
                ws.write_at_offset::<Platform>(
                    0,
                    litebox_common_linux::Winsize {
                        row,
                        col,
                        xpixel: 0,
                        ypixel: 0,
                    },
                )
                .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            // The host terminal already is this session's controlling terminal, and its window
            // is the host's to size: both are accepted as no-ops.
            IoctlArg::TIOCSCTTY(_) | IoctlArg::TIOCSWINSZ(_) => Ok(0),
            _ => Err(Errno::ENOTTY),
        }
    }

    fn pty_ioctl(
        &self,
        endpoint: &PtyEndpoint<Platform, FS>,
        arg: &IoctlArg,
    ) -> Result<u32, Errno> {
        match arg {
            IoctlArg::TCGETS(termios) => {
                let current = endpoint.state.termios.lock().clone();
                termios
                    .write_at_offset::<Platform>(0, current)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TCSETS(termios, _action) => {
                let termios = termios.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                *endpoint.state.termios.lock() = termios;
                Ok(0)
            }
            IoctlArg::TIOCSCTTY(_force) => {
                if endpoint.side != PtySide::Slave {
                    return Err(Errno::EINVAL);
                }
                self.process()
                    .acquire_controlling_pty(self.pid, endpoint.number)?;
                endpoint
                    .state
                    .foreground_pgid
                    .store(self.process().process_group_id(), Ordering::Release);
                Ok(0)
            }
            IoctlArg::TIOCGPGRP(pgrp) => {
                let pgid = endpoint.state.foreground_pgid.load(Ordering::Acquire);
                pgrp.write_at_offset::<Platform>(0, pgid)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCSPGRP(pgrp) => {
                let pgid = pgrp.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                if pgid <= 0 {
                    return Err(Errno::EINVAL);
                }
                endpoint
                    .state
                    .foreground_pgid
                    .store(pgid, Ordering::Release);
                Ok(0)
            }
            IoctlArg::TIOCGWINSZ(winsize) => {
                let current = endpoint.state.winsize.lock().clone();
                winsize
                    .write_at_offset::<Platform>(0, current)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCSWINSZ(winsize) => {
                let winsize = winsize.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                *endpoint.state.winsize.lock() = winsize;
                Ok(0)
            }
            IoctlArg::TIOCGPTN(number) if endpoint.side == PtySide::Master => {
                number
                    .write_at_offset::<Platform>(0, endpoint.number)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCSPTLCK(locked) if endpoint.side == PtySide::Master => {
                let locked = locked.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                endpoint
                    .state
                    .unlocked
                    .store(locked == 0, Ordering::Release);
                Ok(0)
            }
            _ => Err(Errno::ENOTTY),
        }
    }

    fn is_stdio(&self, fs: &FS, fd: &TypedFd<FS>) -> Result<bool, Errno> {
        match fs.fd_file_status(fd) {
            Ok(status) => {
                // See https://www.kernel.org/doc/Documentation/admin-guide/devices.txt: the
                // Unix98 pty slave majors the stdio devices report, plus `/dev/tty` itself.
                let rdev = status
                    .node_info
                    .rdev
                    .map_or(0, core::num::NonZeroUsize::get);
                let major = rdev >> 8;
                Ok(status.file_type == litebox::fs::FileType::CharacterDevice
                    && ((136..=143).contains(&major)
                        || rdev == litebox::fs::devices::TTYAUX_MAJOR << 8))
            }
            Err(litebox::fs::errors::FileStatusError::ClosedFd) => Err(Errno::EBADF),
            Err(_) => unimplemented!(),
        }
    }

    /// If `fd` names a `/dev/input/event*` device, its evdev minor number -- read from the
    /// [`InputEventMinor`] metadata attached at open time. `None` for every other fd (the
    /// read/ioctl paths then fall through to their normal handling).
    fn input_event_minor(&self, _fs: &FS, fd: &TypedFd<FS>) -> Option<usize> {
        input_event_minor_of(&self.global, fd)
    }

    /// Blocking-capable `read()` for a `/dev/input/event*` fd: waits on the device's event
    /// queue with this task's wait context (which the `Backend` trait's `read` cannot do), per
    /// evdev semantics -- whole 24-byte events only, `EINVAL` for a short buffer, `EAGAIN`
    /// only under `O_NONBLOCK`.
    fn read_input_events(&self, meta: InputEventMinor, buf: &mut [u8]) -> Result<usize, Errno> {
        let InputEventMinor { minor, nonblock } = meta;
        // `/dev/input/mice` is a plain byte stream (its handshake reads 1 byte at a time);
        // only the evdev event devices insist on whole 24-byte events.
        if minor != litebox::fs::devices::MICE_MINOR
            && buf.len() < litebox::fs::devices::INPUT_EVENT_SIZE
        {
            return Err(Errno::EINVAL);
        }
        let Some(registry) = self.global.input_registry.as_ref() else {
            return Err(Errno::ENODEV);
        };
        // `nonblock` is the open-time `O_NONBLOCK`/`O_NDELAY` (see `InputEventMinor`); honoring
        // it is load-bearing: Xorg's evdev driver opens the device `O_NDELAY` and drains it
        // with reads it expects to `EAGAIN` when empty -- a blocking read here wedged the X
        // server's whole main loop (observed live as the desktop-wide deadlock).
        registry
            .read_blocking(&self.wait_cx(), minor, buf, nonblock)
            .map_err(|e| match e {
                // A timeout maps to EAGAIN like an empty non-blocking read would -- though with
                // no timeout on this wait context it never actually fires.
                litebox::event::polling::TryOpError::TryAgain
                | litebox::event::polling::TryOpError::WaitError(
                    litebox::event::wait::WaitError::TimedOut,
                ) => Errno::EAGAIN,
                litebox::event::polling::TryOpError::WaitError(
                    litebox::event::wait::WaitError::Interrupted,
                ) => Errno::EINTR,
                litebox::event::polling::TryOpError::Other(infallible) => match infallible {},
            })
    }

    /// Whether `fd` names `/dev/fb0` -- recognized the same way [`Self::is_stdio`] recognizes a
    /// tty (by the `rdev` major number [`litebox::fs::devices`] assigns it), rather than by
    /// requiring a distinct fd-table subsystem for one device.
    pub(crate) fn is_fb0(&self, fs: &FS, fd: &TypedFd<FS>) -> Result<bool, Errno> {
        match fs.fd_file_status(fd) {
            Ok(status) => {
                let major = status.node_info.rdev.map_or(0, |v| v.get() >> 8);
                Ok(major == litebox::fs::devices::FB_MAJOR
                    && status.file_type == litebox::fs::FileType::CharacterDevice)
            }
            Err(litebox::fs::errors::FileStatusError::ClosedFd) => Err(Errno::EBADF),
            // `fd` was already resolved to an open fs-backend fd by the caller's
            // `run_on_raw_fd`, so a status lookup on it failing with anything other than
            // `ClosedFd` (`Io`, `PathError`, or any variant `#[non_exhaustive]` may add later)
            // cannot happen in practice; report "not recognized as fb0" rather than assume a
            // specific unreachable shape.
            Err(_) => Ok(false),
        }
    }

    /// Handle syscall `ioctl`
    pub fn sys_ioctl(&self, fd: i32, arg: IoctlArg) -> Result<u32, Errno> {
        let Ok(desc) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match arg {
            IoctlArg::FIONBIO(arg) => {
                let val = arg.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                self.files
                    .borrow()
                    .run_on_raw_fd(
                        desc,
                        |file_fd| {
                            // Only stdio raw fds carry `StdioStatusFlags` metadata (see
                            // `initialize_stdio_in_shared_descriptors_table`); other regular
                            // files have no non-blocking story at the `Backend` layer, so
                            // `NoSuchMetadata` there is expected and silently ignored, matching
                            // this ioctl's pre-existing (no-op) behavior for non-stdio raw fds.
                            match self
                                .global
                                .litebox
                                .descriptor_table_mut()
                                .with_metadata_mut(file_fd, |crate::StdioStatusFlags(flags)| {
                                    flags.set(OFlags::NONBLOCK, val != 0);
                                }) {
                                Ok(()) | Err(MetadataError::NoSuchMetadata) => Ok(()),
                                Err(MetadataError::ClosedFd) => Err(Errno::EBADF),
                            }
                        },
                        |socket_fd| {
                            if let Err(e) = self
                                .global
                                .litebox
                                .descriptor_table_mut()
                                .with_metadata_mut(
                                    socket_fd,
                                    |crate::syscalls::net::SocketOFlags(flags)| {
                                        flags.set(OFlags::NONBLOCK, val != 0);
                                    },
                                )
                            {
                                match e {
                                    MetadataError::ClosedFd => return Err(Errno::EBADF),
                                    MetadataError::NoSuchMetadata => unreachable!(),
                                }
                            }
                            Ok(())
                        },
                        |fd| {
                            self.global
                                .pipes
                                .update_flags(fd, litebox::pipes::Flags::NON_BLOCKING, val != 0)
                                .map_err(Errno::from)
                        },
                        |fd| {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                file.set_status(OFlags::NONBLOCK, val != 0);
                            });
                            Ok(())
                        },
                        |fd| {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                file.set_status(OFlags::NONBLOCK, val != 0);
                            });
                            Ok(())
                        },
                        |fd| {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                file.set_status(OFlags::NONBLOCK, val != 0);
                            });
                            Ok(())
                        },
                        |fd| {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .with_metadata_mut(
                                    fd,
                                    |crate::syscalls::net::SocketOFlags(flags)| {
                                        flags.set(OFlags::NONBLOCK, val != 0);
                                    },
                                )
                                .map_err(|error| match error {
                                    MetadataError::ClosedFd => Errno::EBADF,
                                    MetadataError::NoSuchMetadata => {
                                        unreachable!("all netlink sockets have SocketOFlags when created")
                                    }
                                })
                        },
                    )
                    .flatten()?;
                Ok(0)
            }
            // `FD_CLOEXEC` lives on the descriptor-table entry, not on
            // anything specific to a given fd kind, so every kind sets it the
            // same way.
            IoctlArg::FIOCLEX => files.run_on_raw_fd(
                desc,
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
            )?,
            IoctlArg::TCGETS(..)
            | IoctlArg::TCSETS(..)
            | IoctlArg::TIOCSCTTY(..)
            | IoctlArg::TIOCGPGRP(..)
            | IoctlArg::TIOCSPGRP(..)
            | IoctlArg::TIOCGPTN(..)
            | IoctlArg::TIOCSPTLCK(..)
            | IoctlArg::TIOCGWINSZ(..)
            | IoctlArg::TIOCSWINSZ(..) => files.run_on_raw_fd(
                desc,
                |fd| {
                    if self.is_stdio(&files.fs, fd)? {
                        let stream = self
                            .global
                            .litebox
                            .descriptor_table()
                            .with_metadata(fd, |stream: &StdioStream| *stream)
                            .map_err(|_| {
                                // TODO: Handle missing `StdioStream` metadata (could happen if
                                // `/dev/stdin`, `/dev/stdout`, or `/dev/stderr` was reopened).
                                // XXX(jayb): likely we might want to have some backend-specific
                                // metadata layer in our file system?
                                litebox_util_log::error!(
                                    "standard stream is missing StdioStream metadata"
                                );
                                Errno::ENOTTY
                            })?;
                        if self.global.platform.is_a_tty(stream) {
                            self.stdio_ioctl(stream, &arg)
                        } else {
                            Err(Errno::ENOTTY)
                        }
                    } else {
                        Err(Errno::ENOTTY)
                    }
                },
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
                |fd| {
                    let endpoint = self.pty_endpoint(fd).ok_or(Errno::ENOTTY)?;
                    self.pty_ioctl(&endpoint, &arg)
                },
                |_fd| Err(Errno::ENOTTY),
            )?,
            IoctlArg::FBIOGET_VSCREENINFO(..)
            | IoctlArg::FBIOPUT_VSCREENINFO(..)
            | IoctlArg::FBIOGET_FSCREENINFO(..)
            | IoctlArg::FBIOPAN_DISPLAY(..)
            | IoctlArg::FBIOBLANK => files.run_on_raw_fd(
                desc,
                |fd| -> Result<u32, Errno> {
                    if !self.is_fb0(&files.fs, fd)? {
                        return Err(Errno::ENOTTY);
                    }
                    // A framebuffer-typed fd only exists when `default_fs` mounted one (the
                    // sole source of an fb0 rdev major), so a `None` here would mean an fd
                    // recognized as fb0 by a filesystem this shim never built -- report
                    // "not a tty-like device" rather than assume that can't happen.
                    let Some(fb) = self.global.framebuffer.as_ref() else {
                        return Err(Errno::ENOTTY);
                    };
                    match &arg {
                        IoctlArg::FBIOGET_VSCREENINFO(out) => {
                            out.write_at_offset::<Platform>(0, fb.var_screeninfo())
                                .ok_or(Errno::EFAULT)?;
                            Ok(0)
                        }
                        IoctlArg::FBIOPUT_VSCREENINFO(req) => {
                            let req = req.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                            fb.put_var_screeninfo(&req);
                            Ok(0)
                        }
                        IoctlArg::FBIOGET_FSCREENINFO(out) => {
                            out.write_at_offset::<Platform>(0, fb.fix_screeninfo())
                                .ok_or(Errno::EFAULT)?;
                            Ok(0)
                        }
                        IoctlArg::FBIOPAN_DISPLAY(req) => {
                            let req = req.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                            if fb.pan_display(req.yoffset) {
                                Ok(0)
                            } else {
                                Err(Errno::EINVAL)
                            }
                        }
                        // litebox has no real display hardware to blank; treat every blank
                        // level (including an unrecognized one) as a trivially successful
                        // no-op, matching how fbdevhw.c tolerates a driver that can't blank.
                        // (`FBIOBLANK` carries no payload, so this is also the only other
                        // variant the outer match admits here.)
                        _ => Ok(0),
                    }
                },
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
            )?,
            // The `EVIOC*` family ('E' = 0x45 in the ioctl type byte) arrives undecoded as
            // `Raw` -- the variable-length getters (`EVIOCGNAME(len)` etc.) encode the caller's
            // buffer length in the command itself, so there's nothing for the static decoder in
            // `litebox_common_linux` to name per-command. Dispatched to the input registry when
            // the fd is a `/dev/input/event*` device; every other fd falls through to the
            // unsupported catch-all below.
            IoctlArg::Raw { cmd, arg: raw_arg } if (cmd >> 8) & 0xff == 0x45 => files
                .run_on_raw_fd(
                    desc,
                    |fd| -> Result<u32, Errno> {
                        let Some(minor) = self.input_event_minor(&files.fs, fd) else {
                            return Err(Errno::EINVAL);
                        };
                        let Some(registry) = self.global.input_registry.as_ref() else {
                            return Err(Errno::ENODEV);
                        };
                        // The only write-direction commands this registry accepts carry an
                        // `int`: `EVIOCGRAB`'s flag rides in the argument value itself (the
                        // kernel never dereferences it), `EVIOCSCLOCKID`'s clockid is in user
                        // memory. Read the user int only for the latter.
                        let write_arg = if cmd & 0xff == 0xa0 {
                            let ptr = litebox_common_linux::user_pointers::UserPtr::<i32>::from_usize(
                                raw_arg.as_usize(),
                            );
                            ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?
                        } else {
                            i32::try_from(raw_arg.as_usize() & 0xffff_ffff)
                                .unwrap_or(i32::MAX)
                        };
                        match registry.evdev_ioctl(minor, cmd, write_arg) {
                            litebox::fs::devices::EvdevIoctlReply::Copy { data, rc } => {
                                let dst = litebox_common_linux::user_pointers::UserPtrMut::<u8>::from_usize(
                                    raw_arg.as_usize(),
                                );
                                dst.copy_from_slice::<Platform>(0, &data)
                                    .ok_or(Errno::EFAULT)?;
                                Ok(rc)
                            }
                            litebox::fs::devices::EvdevIoctlReply::Plain { rc } => Ok(rc),
                            litebox::fs::devices::EvdevIoctlReply::NoEntry => Err(Errno::ENOENT),
                            litebox::fs::devices::EvdevIoctlReply::Invalid => Err(Errno::EINVAL),
                        }
                    },
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                    |_fd| Err(Errno::EINVAL),
                )?,
            // The VT console family ('V' = 0x56, legacy non-`_IOC`-encoded commands) also
            // arrives undecoded as `Raw`. litebox has no virtual terminals to switch between;
            // fbdev graphics clients (links2's `-g` fb driver is the archetype) nonetheless
            // require `VT_GETMODE`/`VT_SETMODE` to succeed on their controlling tty before
            // they will draw, and issue the rest fire-and-forget. Answer as a console whose
            // single VT (1) is permanently active -- kernel-shaped for a host with exactly one
            // seat and no console switching.
            IoctlArg::Raw { cmd, arg: raw_arg } if (cmd >> 8) & 0xff == 0x56 => files
                .run_on_raw_fd(
                    desc,
                    |fd| -> Result<u32, Errno> {
                        if !self.is_stdio(&files.fs, fd)? {
                            return Err(Errno::ENOTTY);
                        }
                        let write_bytes = |bytes: &[u8]| -> Result<u32, Errno> {
                            let dst =
                                litebox_common_linux::user_pointers::UserPtrMut::<u8>::from_usize(
                                    raw_arg.as_usize(),
                                );
                            dst.copy_from_slice::<Platform>(0, bytes)
                                .ok_or(Errno::EFAULT)?;
                            Ok(0)
                        };
                        match cmd {
                            // VT_GETMODE: `struct vt_mode { char mode; char waitv; short
                            // relsig; short acqsig; short frsig; }` -- VT_AUTO, no signals.
                            0x5601 => write_bytes(&[0u8; 8]),
                            // VT_GETSTATE: `struct vt_stat { u16 v_active; u16 v_signal;
                            // u16 v_state; }` -- VT 1 active, VTs 0/1 open.
                            0x5603 => write_bytes(&[1, 0, 0, 0, 3, 0]),
                            // VT_SETMODE (accepted and ignored; with no VT switching the
                            // release/acquire signals it configures can never fire), and
                            // VT_RELDISP / VT_ACTIVATE / VT_WAITACTIVE (the sole VT is
                            // always already active).
                            0x5602 | 0x5605..=0x5607 => Ok(0),
                            _ => {
                                log_unsupported!("VT ioctl {cmd:#x}");
                                Err(Errno::EINVAL)
                            }
                        }
                    },
                    |_fd| Err(Errno::ENOTTY),
                    |_fd| Err(Errno::ENOTTY),
                    |_fd| Err(Errno::ENOTTY),
                    |_fd| Err(Errno::ENOTTY),
                    |_fd| Err(Errno::ENOTTY),
                    |_fd| Err(Errno::ENOTTY),
                )?,
            // Legacy `SIOCGIF*`/`SIOCGIFCONF` socket ioctls ('S' = 0x89 in the ioctl type
            // byte). `getifaddrs(3)` reaches interfaces through rtnetlink (see
            // `crate::syscalls::netlink`) and never issues these, but tools built directly
            // against BSD-style `ifreq`/`ifconf` -- busybox `ifconfig`, `route` -- still do.
            // Answered from the same fixed two-interface table netlink synthesises: `lo`
            // (127.0.0.1/8) and `eth0` (this guest's real address, from `self.global.net`).
            IoctlArg::Raw { cmd, arg: raw_arg } if (cmd >> 8) & 0xff == 0x89 => files
                .run_on_raw_fd(
                    desc,
                    |_fd| -> Result<u32, Errno> { Err(Errno::ENOTTY) },
                    |_fd| -> Result<u32, Errno> {
                        self.sys_ioctl_siocgif(cmd, raw_arg)
                    },
                    |_fd| Err(Errno::ENOTTY),
                    |_fd| Err(Errno::ENOTTY),
                    |_fd| Err(Errno::ENOTTY),
                    |_fd| -> Result<u32, Errno> {
                        // AF_UNIX sockets answer the same fixed table: real programs only
                        // ever issue these against an AF_INET socket, but the kernel itself
                        // does not check the socket's domain for `SIOCGIF*` (it is a global
                        // ioctl number, not protocol-specific), so neither does this shim.
                        self.sys_ioctl_siocgif(cmd, raw_arg)
                    },
                    |_fd| -> Result<u32, Errno> { self.sys_ioctl_siocgif(cmd, raw_arg) },
                )?,
            _ => {
                log_unsupported!("ioctl with arg {:?}", arg);
                Err(Errno::EINVAL)
            }
        }
    }

    /// The `SIOCGIFCONF`/`SIOCGIFFLAGS`/`SIOCGIFADDR`/`SIOCGIFNETMASK`/`SIOCGIFBRDADDR`/
    /// `SIOCGIFHWADDR`/`SIOCGIFMTU`/`SIOCGIFINDEX`/`SIOCGIFTXQLEN` family, against the fixed
    /// `lo` + `eth0` interface table (see the call site's doc comment). `raw_arg` points at a
    /// `struct ifconf` for `SIOCGIFCONF`, a `struct ifreq` for everything else.
    fn sys_ioctl_siocgif(&self, cmd: u32, raw_arg: UserPtrMut<u8>) -> Result<u32, Errno> {
        use litebox_common_linux::{
            IFNAMSIZ, IfrFlags, SIOCGIFADDR, SIOCGIFBRDADDR, SIOCGIFCONF, SIOCGIFFLAGS,
            SIOCGIFHWADDR, SIOCGIFINDEX, SIOCGIFMTU, SIOCGIFNETMASK, SIOCGIFTXQLEN,
        };

        // `sockaddr_in { sa_family: u16, sin_port: u16, sin_addr: [u8;4], sin_zero: [u8;8] }`,
        // padded to `sockaddr`'s 16 bytes -- the shape every `SIOCGIF*` address getter writes
        // into `ifr_ifru.ifru_addr`.
        const AF_INET: u16 = 2;
        fn sockaddr_in(addr: [u8; 4]) -> [u8; 16] {
            let mut b = [0u8; 16];
            b[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            b[4..8].copy_from_slice(&addr);
            b
        }
        fn write_ifreq_name<P: litebox::platform::RawPointerProvider>(
            dst: UserPtrMut<u8>,
            name: &[u8],
        ) -> Option<()> {
            let mut buf = [0u8; IFNAMSIZ];
            buf[..name.len()].copy_from_slice(name);
            dst.copy_from_slice::<P>(0, &buf)
        }
        const ARPHRD_ETHER: u16 = 1;
        const ARPHRD_LOOPBACK: u16 = 772;
        const LO_ADDR: [u8; 4] = [127, 0, 0, 1];
        const LO_MASK: [u8; 4] = [255, 0, 0, 0];
        const ETH_MASK: [u8; 4] = [255, 255, 255, 0];
        const ETH_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        const MTU: i32 = 1500;
        // `struct ifreq` on musl/aarch64 is 40 bytes total, not the 32 a bare
        // `ifr_name[IFNAMSIZ] + sockaddr` sum would suggest: the `ifr_ifru`
        // union member at offset 16 is sized 24 bytes (verified live via
        // `sizeof(struct ifreq)`/`offsetof` on this target), not 16, to leave
        // room for union members not used here (e.g. `sockaddr_in6`-shaped
        // ones). `SIOCGIFCONF`'s stride through the caller-provided buffer
        // must match this exactly: a 32-byte stride left every entry past
        // the first pointing 8 bytes into the *next* real entry's payload,
        // so a caller (confirmed live: busybox `ifconfig`, whose own
        // `if_readconf` walks `ifc.ifc_req` in `sizeof(struct ifreq)`
        // strides) reading the second entry read zeroed padding instead of
        // "eth0", producing an empty-named phantom interface and a fatal
        // `SIOCGIFFLAGS` probe against it ("error fetching interface
        // information: Device not found").
        const IFREQ_SIZE: usize = IFNAMSIZ + 24;

        struct Iface {
            name: &'static [u8],
            addr: [u8; 4],
            netmask: [u8; 4],
            flags: IfrFlags,
            hw_type: u16,
            /// `ifr_ifindex`; the same numbering `crate::syscalls::netlink`'s link dump reports.
            index: i32,
            /// `ifr_qlen`; a loopback has no transmit queue.
            txqueuelen: i32,
        }
        let eth_addr = self.global.net.lock().interface_ip().octets();
        let ifaces = [
            Iface {
                name: b"lo",
                addr: LO_ADDR,
                netmask: LO_MASK,
                flags: IfrFlags::IFF_UP | IfrFlags::IFF_LOOPBACK | IfrFlags::IFF_RUNNING,
                hw_type: ARPHRD_LOOPBACK,
                index: 1,
                txqueuelen: 0,
            },
            Iface {
                name: b"eth0",
                addr: eth_addr,
                netmask: ETH_MASK,
                flags: IfrFlags::IFF_UP
                    | IfrFlags::IFF_BROADCAST
                    | IfrFlags::IFF_RUNNING
                    | IfrFlags::IFF_MULTICAST,
                hw_type: ARPHRD_ETHER,
                index: 2,
                txqueuelen: 1000,
            },
        ];

        if cmd == SIOCGIFCONF {
            // `struct ifconf { int ifc_len; union { char *ifc_buf; struct ifreq *ifc_req; }; }`.
            // LP64 pads `ifc_len` to 8 bytes before the pointer.
            let header = raw_arg
                .to_owned_slice::<Platform>(16)
                .ok_or(Errno::EFAULT)?;
            let ifc_len = i32::from_ne_bytes(
                <[u8; 4]>::try_from(&header[0..4]).unwrap_or_else(|_| unreachable!()),
            );
            let buf_addr = usize::from_ne_bytes(
                <[u8; 8]>::try_from(&header[8..16]).unwrap_or_else(|_| unreachable!()),
            );
            let dst = UserPtrMut::<u8>::from_usize(buf_addr);

            let capacity = usize::try_from(ifc_len.max(0)).unwrap_or(0) / IFREQ_SIZE;
            let n = ifaces.len().min(capacity);
            for (i, iface) in ifaces.iter().take(n).enumerate() {
                let entry = UserPtrMut::<u8>::from_usize(dst.as_usize() + i * IFREQ_SIZE);
                write_ifreq_name::<Platform>(entry, iface.name).ok_or(Errno::EFAULT)?;
                let addr_entry = UserPtrMut::<u8>::from_usize(entry.as_usize() + IFNAMSIZ);
                addr_entry
                    .copy_from_slice::<Platform>(0, &sockaddr_in(iface.addr))
                    .ok_or(Errno::EFAULT)?;
            }
            let written_len = i32::try_from(n * IFREQ_SIZE).unwrap_or(0);
            raw_arg
                .copy_from_slice::<Platform>(0, &written_len.to_ne_bytes())
                .ok_or(Errno::EFAULT)?;
            return Ok(0);
        }

        // Every other command names one interface in `ifr_name` and gets a reply written
        // into the same union slot the name doesn't occupy.
        let name_bytes = raw_arg
            .to_owned_slice::<Platform>(IFNAMSIZ)
            .ok_or(Errno::EFAULT)?;
        let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
        let name = &name_bytes[..name_len];
        let Some(iface) = ifaces.iter().find(|i| i.name == name) else {
            return Err(Errno::ENODEV);
        };
        let payload = UserPtrMut::<u8>::from_usize(raw_arg.as_usize() + IFNAMSIZ);
        match cmd {
            SIOCGIFFLAGS => {
                let mut b = [0u8; 16];
                b[0..2].copy_from_slice(&iface.flags.bits().to_ne_bytes());
                payload
                    .copy_from_slice::<Platform>(0, &b)
                    .ok_or(Errno::EFAULT)?;
            }
            SIOCGIFADDR => {
                payload
                    .copy_from_slice::<Platform>(0, &sockaddr_in(iface.addr))
                    .ok_or(Errno::EFAULT)?;
            }
            SIOCGIFNETMASK => {
                payload
                    .copy_from_slice::<Platform>(0, &sockaddr_in(iface.netmask))
                    .ok_or(Errno::EFAULT)?;
            }
            SIOCGIFBRDADDR => {
                let broadcast = [
                    iface.addr[0] | !iface.netmask[0],
                    iface.addr[1] | !iface.netmask[1],
                    iface.addr[2] | !iface.netmask[2],
                    iface.addr[3] | !iface.netmask[3],
                ];
                payload
                    .copy_from_slice::<Platform>(0, &sockaddr_in(broadcast))
                    .ok_or(Errno::EFAULT)?;
            }
            SIOCGIFHWADDR => {
                let mut b = [0u8; 16];
                b[0..2].copy_from_slice(&iface.hw_type.to_ne_bytes());
                let mac = if iface.hw_type == ARPHRD_LOOPBACK {
                    [0u8; 6]
                } else {
                    ETH_MAC
                };
                b[2..8].copy_from_slice(&mac);
                payload
                    .copy_from_slice::<Platform>(0, &b)
                    .ok_or(Errno::EFAULT)?;
            }
            SIOCGIFMTU => {
                payload
                    .copy_from_slice::<Platform>(0, &MTU.to_ne_bytes())
                    .ok_or(Errno::EFAULT)?;
            }
            SIOCGIFINDEX => {
                payload
                    .copy_from_slice::<Platform>(0, &iface.index.to_ne_bytes())
                    .ok_or(Errno::EFAULT)?;
            }
            SIOCGIFTXQLEN => {
                payload
                    .copy_from_slice::<Platform>(0, &iface.txqueuelen.to_ne_bytes())
                    .ok_or(Errno::EFAULT)?;
            }
            _ => {
                log_unsupported!("SIOCGIF ioctl {cmd:#x}");
                return Err(Errno::EINVAL);
            }
        }
        Ok(0)
    }

    /// Handle syscall `epoll_create` and `epoll_create1`
    pub fn sys_epoll_create(&self, flags: EpollCreateFlags) -> Result<u32, Errno> {
        if flags.intersects(EpollCreateFlags::EPOLL_CLOEXEC.complement()) {
            return Err(Errno::EINVAL);
        }

        let epoll_file = super::epoll::EpollFile::new();
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<super::epoll::EpollSubsystem<Platform, FS>>(epoll_file);
        if flags.contains(EpollCreateFlags::EPOLL_CLOEXEC) {
            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        drop(dt);
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
            self.global
                .litebox
                .descriptor_table_mut()
                .remove(&typed)
                .unwrap();
            Errno::EMFILE
        })?;
        Ok(raw_fd.try_into().unwrap())
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

        let epoll_fd = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::epoll::EpollSubsystem<Platform, FS>>(epfd as usize)
            .map_err(|_| Errno::EBADF)?;
        let file_descriptor =
            super::epoll::EpollDescriptor::try_from(&self.global, &files, fd as usize)?;

        let handle = self
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&epoll_fd)
            .ok_or(Errno::EBADF)?;
        if file_descriptor.is_epoll_identity(handle.identity()) {
            return Err(Errno::EINVAL);
        }
        let event = if op == litebox_common_linux::EpollOp::EpollCtlDel {
            None
        } else {
            Some(event.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?)
        };
        handle.with_entry(|entry| {
            entry.epoll_ctl(&self.global, &epoll_fd, op, fd, &file_descriptor, event)
        })
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
        // epoll_pwait(2): same temporary-mask contract as `ppoll`/`pselect`.
        let sigmask = match sigmask {
            Some(sigmask) => {
                if sigsetsize != core::mem::size_of::<litebox_common_linux::signal::SigSet>() {
                    return Err(Errno::EINVAL);
                }
                Some(sigmask.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?)
            }
            None => None,
        };
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
        let handle = {
            let files = self.files.borrow();
            {
                let raw_fd = usize::try_from(epfd).or(Err(Errno::EBADF))?;
                let Ok(fd) = files
                    .raw_descriptor_store
                    .read()
                    .fd_from_raw_integer::<crate::syscalls::epoll::EpollSubsystem<Platform, FS>>(
                    raw_fd,
                ) else {
                    return Err(Errno::EBADF);
                };
                self.global
                    .litebox
                    .descriptor_table()
                    .entry_handle(&fd)
                    .ok_or(Errno::EBADF)?
            }
        };
        let wait = || {
            handle.with_entry(|epoll_file| {
                match epoll_file.wait(
                    &self.global,
                    &self.wait_cx().with_timeout(timeout),
                    maxevents,
                ) {
                    Ok(epoll_events) => {
                        if !epoll_events.is_empty() {
                            events
                                .copy_from_slice::<Platform>(0, &epoll_events)
                                .ok_or(Errno::EFAULT)?;
                        }
                        Ok(epoll_events.len())
                    }
                    Err(WaitError::TimedOut) => Ok(0),
                    Err(WaitError::Interrupted) => Err(Errno::EINTR),
                }
            })
        };
        match sigmask {
            Some(mask) => self.with_temporary_signal_mask(mask, wait),
            None => wait(),
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
        // ppoll(2): the mask, when given, replaces the thread's blocked set for the
        // duration of the wait only (see `with_temporary_signal_mask`), exactly like
        // `pselect`; a wrong `sigsetsize` is `EINVAL`.
        let sigmask = match sigmask {
            Some(sigmask) => {
                if sigsetsize != core::mem::size_of::<litebox_common_linux::signal::SigSet>() {
                    return Err(Errno::EINVAL);
                }
                Some(sigmask.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?)
            }
            None => None,
        };
        let timeout = timeout.read::<Platform>()?;
        let nfds_signed = isize::try_from(nfds).map_err(|_| Errno::EINVAL)?;

        let mut set = super::epoll::PollSet::with_capacity(nfds);
        for i in 0..nfds_signed {
            let fd = fds.read_at_offset::<Platform>(i).ok_or(Errno::EFAULT)?;

            let events = litebox::event::Events::from_bits_truncate(
                fd.events.reinterpret_as_unsigned().into(),
            );
            set.add_fd(fd.fd, events);
        }

        let wait_result = match sigmask {
            Some(mask) => self.with_temporary_signal_mask(mask, || {
                set.wait(
                    &self.global,
                    &self.wait_cx().with_timeout(timeout),
                    &self.files.borrow(),
                )
            }),
            None => set.wait(
                &self.global,
                &self.wait_cx().with_timeout(timeout),
                &self.files.borrow(),
            ),
        };
        match wait_result {
            Ok(()) => {}
            Err(WaitError::Interrupted) => {
                // TODO: update the remaining time.
                return Err(Errno::EINTR);
            }
            Err(WaitError::TimedOut) => {
                // A timeout occurred. Scan one last time.
                set.scan(&self.global, &self.files.borrow());
            }
        }

        // Write just the revents back.
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
        Ok(ready_count)
    }

    pub(crate) fn do_pselect(
        &self,
        nfds: u32,
        readfds: Option<&mut bitvec::vec::BitVec>,
        writefds: Option<&mut bitvec::vec::BitVec>,
        exceptfds: Option<&mut bitvec::vec::BitVec>,
        timeout: Option<core::time::Duration>,
    ) -> Result<usize, Errno> {
        // XXX: semantic issue likely should be fixed here to make sure EBADF is triggered early
        // enough if needed. Previously, `file_table_len` used to be
        // `self.files.borrow().file_descriptors.read().len()` before `file_descriptors` was
        // removed to clean up the table handling.
        let file_table_len = usize::MAX;
        let mut set = super::epoll::PollSet::with_capacity(nfds as usize);
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

        match set.wait(
            &self.global,
            &self.wait_cx().with_timeout(timeout),
            &self.files.borrow(),
        ) {
            Ok(()) => {}
            Err(WaitError::Interrupted) => {
                // TODO: update the remaining time.
                return Err(Errno::EINTR);
            }
            Err(WaitError::TimedOut) => {
                // A timeout occurred. Scan one last time.
                set.scan(&self.global, &self.files.borrow());
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
        let sigmask = if let Some(sigsetpack) = sigsetpack {
            let sigsetpack = sigsetpack
                .read_at_offset::<Platform>(0)
                .ok_or(Errno::EFAULT)?;
            if sigsetpack.size != core::mem::size_of::<litebox_common_linux::signal::SigSet>() {
                return Err(Errno::EINVAL);
            }
            // A null sigset inside a non-null pack means "don't touch the mask" -- exactly how
            // the kernel reads it, and exactly what musl's plain `select` always passes
            // (`{ss: NULL, ss_len: _NSIG/8}`).
            if sigsetpack.sigset.is_null() {
                None
            } else {
                Some(
                    sigsetpack
                        .sigset
                        .read_at_offset::<Platform>(0)
                        .ok_or(Errno::EFAULT)?,
                )
            }
        } else {
            None
        };
        let timeout = timeout.read::<Platform>()?;
        if nfds >= i32::MAX as u32
            || nfds as usize
                > self
                    .process()
                    .limits
                    .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE)
        {
            return Err(Errno::EINVAL);
        }
        let len = (nfds as usize).div_ceil(core::mem::size_of::<usize>() * 8);
        let mut kreadfds = readfds
            .map(|fds| fds.to_owned_slice::<Platform>(len).ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_vec()));
        let mut kwritefds = writefds
            .map(|fds| fds.to_owned_slice::<Platform>(len).ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_vec()));
        let mut kexceptfds = exceptfds
            .map(|fds| fds.to_owned_slice::<Platform>(len).ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_vec()));

        let mut do_pselect = || {
            self.do_pselect(
                nfds,
                kreadfds.as_mut(),
                kwritefds.as_mut(),
                kexceptfds.as_mut(),
                timeout,
            )
        };
        let count = if let Some(sigmask) = sigmask {
            self.with_temporary_signal_mask(sigmask, do_pselect)
        } else {
            do_pselect()
        }?;

        if let Some(fds) = kreadfds {
            readfds
                .unwrap()
                .write_slice_at_offset::<Platform>(0, fds.as_raw_slice())
                .ok_or(Errno::EFAULT)?;
        }
        if let Some(fds) = kwritefds {
            writefds
                .unwrap()
                .write_slice_at_offset::<Platform>(0, fds.as_raw_slice())
                .ok_or(Errno::EFAULT)?;
        }
        if let Some(fds) = kexceptfds {
            exceptfds
                .unwrap()
                .write_slice_at_offset::<Platform>(0, fds.as_raw_slice())
                .ok_or(Errno::EFAULT)?;
        }

        Ok(count)
    }

    fn do_dup(&self, file: usize, flags: OFlags) -> Result<usize, DupFdError> {
        self.do_dup_inner(file, flags, DupFdRequest::LowestAvailable)
    }

    fn do_dup_inner(
        &self,
        file: usize,
        flags: OFlags,
        target: DupFdRequest,
    ) -> Result<usize, DupFdError> {
        fn dup<Platform: ShimPlatform, FS: ShimFS, S: FdEnabledSubsystem>(
            task: &Task<Platform, FS>,
            files: &FilesState<Platform, FS>,
            fd: &TypedFd<S>,
            close_on_exec: bool,
            target: DupFdRequest,
        ) -> Result<usize, DupFdError> {
            let max_fd = task
                .process()
                .limits
                .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE);
            match target {
                DupFdRequest::Exact(target) if target >= max_fd => {
                    return Err(DupFdError::TargetFdExceedsLimit);
                }
                DupFdRequest::LowestAtOrAbove(min_fd) if min_fd >= max_fd => {
                    return Err(DupFdError::TargetFdExceedsLimit);
                }
                _ => {}
            }

            let mut dt = task.global.litebox.descriptor_table_mut();
            let fd: TypedFd<_> = dt.duplicate(fd).ok_or(DupFdError::BadFd)?;
            note_pty_slave_descriptor::<Platform, FS, _>(&dt, &fd);
            if close_on_exec {
                let old = dt.set_fd_metadata(&fd, FileDescriptorFlags::FD_CLOEXEC);
                assert!(old.is_none());
            }
            drop(dt);

            let new_fd = match target {
                DupFdRequest::Exact(target) => {
                    let _ = task.do_close_and_replace(target, Some(fd));
                    target
                }
                DupFdRequest::LowestAvailable => {
                    let rds = &mut *files.raw_descriptor_store.write();
                    rds.fd_into_raw_integer(fd)
                }
                DupFdRequest::LowestAtOrAbove(min_fd) => {
                    let rds = &mut *files.raw_descriptor_store.write();
                    let mut raw_fd = min_fd;
                    for occupied_raw_fd in rds.iter_alive().skip_while(|&fd| fd < min_fd) {
                        if occupied_raw_fd != raw_fd {
                            break;
                        }
                        raw_fd += 1;
                    }
                    let success = rds.fd_into_specific_raw_integer(fd, raw_fd);
                    assert!(success);
                    raw_fd
                }
            };
            if new_fd >= max_fd {
                let _ = task.do_close(new_fd);
                return Err(DupFdError::TooManyFiles);
            }
            Ok(new_fd)
        }

        let close_on_exec = flags.contains(OFlags::CLOEXEC);
        let files = self.files.borrow();
        // See the matching pre-check in `fork_copy`: inotify fds sit outside `run_on_raw_fd`'s
        // hand-enumerated subsystem list, so `dup`/`dup2`/`dup3`/`fcntl(F_DUPFD*)` on one would
        // otherwise fail `BadFd` even though the fd is alive and valid.
        if let Ok(inotify_fd) = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::inotify::InotifySubsystem<Platform>>(file)
        {
            return dup(self, &files, &inotify_fd, close_on_exec, target);
        }
        files
            .run_on_raw_fd(
                file,
                |fd| dup(self, &files, fd, close_on_exec, target),
                |fd| dup(self, &files, fd, close_on_exec, target),
                |fd| dup(self, &files, fd, close_on_exec, target),
                |fd| dup(self, &files, fd, close_on_exec, target),
                |fd| dup(self, &files, fd, close_on_exec, target),
                |fd| dup(self, &files, fd, close_on_exec, target),
                |fd| dup(self, &files, fd, close_on_exec, target),
            )
            .map_err(|_| DupFdError::BadFd)?
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
        self.check_raw_fd_exists(oldfd)?;
        let oldfd = u32::try_from(oldfd).map_err(|_| Errno::EBADF)?;
        let oldfd_usize = usize::try_from(oldfd).or(Err(Errno::EBADF))?;
        if let Some(newfd) = newfd {
            // dup2/dup3
            let Ok(newfd) = u32::try_from(newfd) else {
                return Err(Errno::EBADF);
            };
            if oldfd == newfd {
                // Different from dup3, if oldfd is a valid file descriptor, and newfd has the same value
                // as oldfd, then dup2() does nothing.
                return if flags.is_some() {
                    // dup3
                    Err(Errno::EINVAL)
                } else {
                    // dup2
                    Ok(oldfd)
                };
            }
            let newfd_usize = usize::try_from(newfd).or(Err(Errno::EBADF))?;
            self.do_dup_inner(
                oldfd_usize,
                flags.unwrap_or(OFlags::empty()),
                DupFdRequest::Exact(newfd_usize),
            )
        } else {
            // dup
            self.do_dup(oldfd_usize, flags.unwrap_or(OFlags::empty()))
        }
        .map_err(|e| match e {
            DupFdError::BadFd | DupFdError::TargetFdExceedsLimit => Errno::EBADF,
            DupFdError::TooManyFiles => Errno::EMFILE,
        })
        .map(|new_fd| u32::try_from(new_fd).unwrap())
    }
}

#[derive(Clone, Copy)]
enum DupFdRequest {
    LowestAvailable,
    LowestAtOrAbove(usize),
    /// Duplicate to the specified fd, closing it first if it's open.
    Exact(usize),
}

#[derive(Error, Debug)]
enum DupFdError {
    #[error("Bad file descriptor")]
    BadFd,
    #[error("Too many open files")]
    TooManyFiles,
    #[error("Target fd exceeds process limit")]
    TargetFdExceedsLimit,
}

const DIRENT_STRUCT_BYTES_WITHOUT_NAME: usize =
    core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name);
const DIRENT_ALIGNMENT: usize = align_of::<u64>();

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Handle syscall `getdents64`
    pub(crate) fn sys_getdirent64(
        &self,
        fd: i32,
        dirp: UserPtrMut<u8>,
        count: usize,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files.run_on_raw_fd(
            fd,
            |file| {
                let mut entries = files.fs.read_dir(file).map_err(Errno::from)?;
                entries.sort_by(|a, b| a.name.cmp(&b.name));

                files
                    .fs
                    .with_dir_position(file, |dir_off| {
                        let mut nbytes = 0usize;
                        while let Some(entry) = entries.get(*dir_off) {
                            let record = (|| -> Result<Option<(usize, usize)>, Errno> {
                                let next_dir_off =
                                    dir_off.checked_add(1).ok_or(Errno::EOVERFLOW)?;
                                let unaligned_len = DIRENT_STRUCT_BYTES_WITHOUT_NAME
                                    .checked_add(entry.name.len())
                                    .and_then(|len| len.checked_add(1))
                                    .ok_or(Errno::EOVERFLOW)?;
                                let len = unaligned_len
                                    .checked_next_multiple_of(DIRENT_ALIGNMENT)
                                    .ok_or(Errno::EOVERFLOW)?;
                                let next_nbytes =
                                    nbytes.checked_add(len).ok_or(Errno::EOVERFLOW)?;
                                if next_nbytes > count {
                                    return if nbytes == 0 {
                                        Err(Errno::EINVAL)
                                    } else {
                                        Ok(None)
                                    };
                                }

                                let ino = entry
                                    .ino_info
                                    .as_ref()
                                    .map_or(Ok(0), |node_info| u64::try_from(node_info.ino))
                                    .map_err(|_| Errno::EOVERFLOW)?;
                                let continuation = i64::try_from(next_dir_off)
                                    .map_err(|_| Errno::EOVERFLOW)?
                                    .reinterpret_as_unsigned();
                                let record_len =
                                    u16::try_from(len).map_err(|_| Errno::EOVERFLOW)?;
                                let dirent64 = litebox_common_linux::LinuxDirent64 {
                                    ino,
                                    off: continuation,
                                    len: record_len,
                                    typ: litebox_common_linux::DirentType::from(
                                        entry.file_type.clone(),
                                    ) as u8,
                                    __name: [0; 0],
                                };

                                let header_addr =
                                    dirp.as_usize().checked_add(nbytes).ok_or(Errno::EFAULT)?;
                                let name_addr = header_addr
                                    .checked_add(DIRENT_STRUCT_BYTES_WITHOUT_NAME)
                                    .ok_or(Errno::EFAULT)?;
                                let zeros_addr = name_addr
                                    .checked_add(entry.name.len())
                                    .ok_or(Errno::EFAULT)?;
                                let header = UserPtrMut::from_usize(header_addr);
                                let name = UserPtrMut::from_usize(name_addr);
                                let zeros = UserPtrMut::from_usize(zeros_addr);
                                header
                                    .write_at_offset::<Platform>(0, dirent64)
                                    .ok_or(Errno::EFAULT)?;
                                name.write_slice_at_offset::<Platform>(0, entry.name.as_bytes())
                                    .ok_or(Errno::EFAULT)?;
                                let zero_count = len
                                    .checked_sub(
                                        DIRENT_STRUCT_BYTES_WITHOUT_NAME
                                            .checked_add(entry.name.len())
                                            .ok_or(Errno::EOVERFLOW)?,
                                    )
                                    .ok_or(Errno::EOVERFLOW)?;
                                let zero_padding = [0u8; DIRENT_ALIGNMENT];
                                let zero_padding =
                                    zero_padding.get(..zero_count).ok_or(Errno::EOVERFLOW)?;
                                zeros
                                    .write_slice_at_offset::<Platform>(0, zero_padding)
                                    .ok_or(Errno::EFAULT)?;
                                Ok(Some((next_dir_off, next_nbytes)))
                            })();

                            match record {
                                Ok(Some((next_dir_off, next_nbytes))) => {
                                    *dir_off = next_dir_off;
                                    nbytes = next_nbytes;
                                }
                                Ok(None) => break,
                                Err(_) if nbytes != 0 => break,
                                Err(error) => return Err(error),
                            }
                        }
                        Ok(nbytes)
                    })
                    .map_err(Errno::from)?
            },
            |_fd| Err(Errno::ENOTDIR),
            |_fd| Err(Errno::ENOTDIR),
            |_fd| Err(Errno::ENOTDIR),
            |_fd| Err(Errno::ENOTDIR),
            |_fd| Err(Errno::ENOTDIR),
            |_fd| Err(Errno::ENOTDIR),
        )?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use core::cell::Cell;
    use litebox::fs::Mode;
    use litebox::platform::StdioProvider as _;

    extern crate std;

    #[test]
    fn write_to_iovec_returns_partial_after_later_error() {
        let first = b"first";
        let second = b"second";
        let iovs = [
            IoWriteVec {
                iov_base: UserPtr::from_usize(first.as_ptr().expose_provenance()),
                iov_len: first.len(),
            },
            IoWriteVec {
                iov_base: UserPtr::from_usize(second.as_ptr().expose_provenance()),
                iov_len: second.len(),
            },
        ];
        let calls = Cell::new(0);

        let result =
            write_to_iovec::<_, crate::syscalls::tests::TestPlatform>(&iovs, |buf, total| {
                let call = calls.get();
                calls.set(call + 1);
                if call == 0 {
                    assert_eq!(buf, first);
                    assert_eq!(total, 0);
                    Ok(buf.len())
                } else {
                    assert_eq!(buf, second);
                    assert_eq!(total, first.len());
                    Err(Errno::EPIPE)
                }
            });

        assert_eq!(result, Ok(first.len()));
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn read_from_iovec_breaks_on_eof() {
        let mut first = [0u8; 4];
        let mut second = [0u8; 4];
        let iovs = [
            IoReadVec {
                iov_base: UserPtrMut::from_usize(first.as_mut_ptr().expose_provenance()),
                iov_len: first.len(),
            },
            IoReadVec {
                iov_base: UserPtrMut::from_usize(second.as_mut_ptr().expose_provenance()),
                iov_len: second.len(),
            },
        ];
        let mut kernel_buffer = [0u8; 8];
        let calls = Cell::new(0);

        let result = read_from_iovec::<_, crate::syscalls::tests::TestPlatform>(
            &iovs,
            &mut kernel_buffer,
            |buf, total| {
                let call = calls.get();
                calls.set(call + 1);
                if call == 0 {
                    assert_eq!(total, 0);
                    buf.fill(b'a');
                    Ok(buf.len())
                } else {
                    assert_eq!(total, 4);
                    Ok(0)
                }
            },
        );

        assert_eq!(result, Ok(4));
        assert_eq!(calls.get(), 2);
        assert_eq!(&first, b"aaaa");
        assert_eq!(&second, &[0u8; 4]);
    }

    #[test]
    fn read_from_iovec_chunks_iov_larger_than_kernel_buffer() {
        let mut dest = [0u8; 12];
        let iovs = [IoReadVec {
            iov_base: UserPtrMut::from_usize(dest.as_mut_ptr().expose_provenance()),
            iov_len: dest.len(),
        }];
        let mut kernel_buffer = [0u8; 4];
        let calls = Cell::new(0);

        let result = read_from_iovec::<_, crate::syscalls::tests::TestPlatform>(
            &iovs,
            &mut kernel_buffer,
            |buf, total| {
                assert_eq!(buf.len(), 4);
                assert_eq!(total, calls.get() * 4);
                let marker = b'a' + u8::try_from(calls.get()).unwrap();
                buf.fill(marker);
                calls.set(calls.get() + 1);
                Ok(buf.len())
            },
        );

        assert_eq!(result, Ok(12));
        assert_eq!(calls.get(), 3);
        assert_eq!(&dest, b"aaaabbbbcccc");
    }

    #[test]
    fn read_from_iovec_returns_partial_after_later_error() {
        let mut first = [0u8; 4];
        let mut second = [0u8; 4];
        let iovs = [
            IoReadVec {
                iov_base: UserPtrMut::from_usize(first.as_mut_ptr().expose_provenance()),
                iov_len: first.len(),
            },
            IoReadVec {
                iov_base: UserPtrMut::from_usize(second.as_mut_ptr().expose_provenance()),
                iov_len: second.len(),
            },
        ];
        let mut kernel_buffer = [0u8; 4];
        let calls = Cell::new(0);

        let result = read_from_iovec::<_, crate::syscalls::tests::TestPlatform>(
            &iovs,
            &mut kernel_buffer,
            |buf, total| {
                let call = calls.get();
                calls.set(call + 1);
                if call == 0 {
                    assert_eq!(total, 0);
                    buf.fill(b'x');
                    Ok(buf.len())
                } else {
                    assert_eq!(total, 4);
                    Err(Errno::EIO)
                }
            },
        );

        assert_eq!(result, Ok(4));
        assert_eq!(calls.get(), 2);
        assert_eq!(&first, b"xxxx");
    }

    #[test]
    fn fspath_new() {
        // Absolute paths should never invoke the get_cwd closure.
        let fp = FsPath::new(litebox_common_linux::AT_FDCWD, "/usr/bin", || {
            panic!("get_cwd should not be called for absolute paths")
        })
        .unwrap();
        assert!(matches!(fp, FsPath::Absolute { path } if path.to_str().unwrap() == "/usr/bin"));

        // Relative path resolves against CWD.
        let fp = FsPath::new(litebox_common_linux::AT_FDCWD, "foo/bar", || {
            String::from("/home/")
        })
        .unwrap();
        assert!(
            matches!(fp, FsPath::Absolute { path } if path.to_str().unwrap() == "/home/foo/bar")
        );

        // Empty path at AT_FDCWD → Cwd variant.
        let fp = FsPath::new(litebox_common_linux::AT_FDCWD, "", || {
            panic!("get_cwd should not be called for empty Cwd path")
        })
        .unwrap();
        assert!(matches!(fp, FsPath::Cwd));

        // Positive fd + empty path → Fd variant.
        let fp = FsPath::new(5, "", || panic!("should not be called")).unwrap();
        assert!(matches!(fp, FsPath::Fd(5)));

        // Invalid dirfd → EBADF.
        let err = FsPath::new(-1, "file.txt", || panic!("should not be called")).unwrap_err();
        assert_eq!(err, Errno::EBADF);

        // Path exceeding PATH_MAX → ENAMETOOLONG.
        let long_path = "a".repeat(PATH_MAX + 1);
        let err = FsPath::new(litebox_common_linux::AT_FDCWD, long_path.as_str(), || {
            String::from("/")
        })
        .unwrap_err();
        assert_eq!(err, Errno::ENAMETOOLONG);
    }

    #[test]
    fn getcwd_and_chdir() {
        let task = crate::syscalls::tests::init_platform(None);

        // Default CWD is root.
        let mut buf = [0u8; 256];
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap(); // strip NUL
        assert_eq!(cwd, "/");

        // chdir + getcwd round trip.
        task.sys_mkdirat(litebox_common_linux::AT_FDCWD, "/test_chdir_dir", 0o777)
            .unwrap();
        task.sys_chdir("/test_chdir_dir").unwrap();
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap();
        assert_eq!(cwd, "/test_chdir_dir/");

        // chdir to nonexistent path → ENOENT.
        assert_eq!(
            task.sys_chdir("/does_not_exist").unwrap_err(),
            Errno::ENOENT
        );

        // chdir to a regular file → ENOTDIR.
        let fd = task
            .sys_openat(
                litebox_common_linux::AT_FDCWD,
                "/test_chdir_file",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let _ = task.sys_close(i32::try_from(fd).unwrap());
        assert_eq!(
            task.sys_chdir("/test_chdir_file").unwrap_err(),
            Errno::ENOTDIR
        );

        // getcwd with too-small buffer → ERANGE.
        let mut tiny = [0u8; 1];
        assert_eq!(task.sys_getcwd(&mut tiny).unwrap_err(), Errno::ERANGE);
    }

    #[test]
    fn chdir_relative_path() {
        let task = crate::syscalls::tests::init_platform(None);

        // Create nested dirs: /rel_parent/rel_child
        task.sys_mkdirat(litebox_common_linux::AT_FDCWD, "/rel_parent", 0o777)
            .unwrap();
        task.sys_mkdirat(
            litebox_common_linux::AT_FDCWD,
            "/rel_parent/rel_child",
            0o777,
        )
        .unwrap();

        // chdir to /rel_parent first, then relative chdir into child.
        task.sys_chdir("/rel_parent").unwrap();
        task.sys_chdir("rel_child").unwrap();

        let mut buf = [0u8; 256];
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap();
        assert_eq!(cwd, "/rel_parent/rel_child/");

        // chdir("..") should normalize back to /rel_parent/.
        task.sys_chdir("..").unwrap();
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap();
        assert_eq!(cwd, "/rel_parent/");
    }

    #[test]
    fn mknodat_regular_file_does_not_consume_fd_limit() {
        use litebox_common_linux::{Rlimit, RlimitResource};

        let task = crate::syscalls::tests::init_platform(None);
        let old_limit = task.do_prlimit(RlimitResource::NOFILE, None).unwrap();
        task.do_prlimit(
            RlimitResource::NOFILE,
            Some(Rlimit {
                rlim_cur: 3,
                rlim_max: old_limit.rlim_max,
            }),
        )
        .unwrap();
        let path = "/mknodat_at_fd_limit";

        let result = task.sys_mknodat(
            litebox_common_linux::AT_FDCWD,
            path,
            InodeType::File as u32 | (Mode::RUSR | Mode::WUSR).bits(),
            0,
        );

        assert!(
            task.sys_stat(path).is_ok(),
            "mknodat created the file before returning {result:?}"
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn empty_pathnames_return_enoent() {
        let task = crate::syscalls::tests::init_platform(None);

        assert_eq!(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                "",
                OFlags::RDONLY,
                Mode::empty()
            )
            .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                "",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU
            )
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
                InodeType::File as u32 | Mode::RWXU.bits(),
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
        use litebox_common_linux::{AccessFlags, AtFlags};

        let task = crate::syscalls::tests::init_platform(None);

        // Set up: mkdir + chdir into /cwd_test/.
        task.sys_mkdirat(litebox_common_linux::AT_FDCWD, "/cwd_test", 0o777)
            .unwrap();
        task.sys_chdir("/cwd_test").unwrap();

        // ── sys_open: create a file via relative path ──
        let fd = task
            .sys_openat(
                litebox_common_linux::AT_FDCWD,
                "file.txt",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();

        // ── sys_stat: stat the relative file ──
        task.sys_stat("file.txt").unwrap();

        // ── sys_lstat: lstat the relative file ──
        task.sys_lstat("file.txt").unwrap();

        // ── sys_faccessat: check relative file is accessible ──
        task.sys_faccessat(
            litebox_common_linux::AT_FDCWD,
            "file.txt",
            AccessFlags::F_OK,
            AtFlags::empty(),
        )
        .unwrap();

        // ── create a subdirectory via relative path ──
        task.sys_mkdirat(litebox_common_linux::AT_FDCWD, "subdir", 0o777)
            .unwrap();
        task.sys_stat("/cwd_test/subdir").unwrap(); // verify via absolute

        // ── sys_openat (AT_FDCWD + relative): open inside the new subdir ──
        let fd = task
            .sys_openat(
                litebox_common_linux::AT_FDCWD,
                "subdir/inner.txt",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();

        // ── sys_newfstatat (AT_FDCWD + relative) ──
        task.sys_newfstatat(
            litebox_common_linux::AT_FDCWD,
            "subdir/inner.txt",
            AtFlags::empty(),
        )
        .unwrap();

        // ── sys_unlinkat: remove a file via relative path ──
        task.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            "subdir/inner.txt",
            AtFlags::empty(),
        )
        .unwrap();
        assert_eq!(
            task.sys_stat("/cwd_test/subdir/inner.txt").unwrap_err(),
            Errno::ENOENT
        );

        // ── sys_unlinkat (AT_REMOVEDIR): remove directory via relative path ──
        task.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            "subdir",
            AtFlags::AT_REMOVEDIR,
        )
        .unwrap();
        assert_eq!(
            task.sys_stat("/cwd_test/subdir").unwrap_err(),
            Errno::ENOENT
        );
    }

    /// Verify `openat`/`newfstatat`/`faccessat` resolve a relative path against a real `dirfd`
    /// (as opposed to `AT_FDCWD`), including across a `dup`'d copy of that `dirfd`, and reject a
    /// closed or non-directory `dirfd` the way real Linux does.
    #[test]
    fn dirfd_relative_resolution_via_real_dirfd() {
        use litebox_common_linux::{AccessFlags, AtFlags};

        let task = crate::syscalls::tests::init_platform(None);

        task.sys_mkdirat(litebox_common_linux::AT_FDCWD, "/dirfd_test", 0o777)
            .unwrap();
        let dirfd = task
            .sys_openat(
                litebox_common_linux::AT_FDCWD,
                "/dirfd_test",
                litebox::fs::OFlags::RDONLY,
                Mode::empty(),
            )
            .unwrap();
        let dirfd = i32::try_from(dirfd).unwrap();

        // openat(dirfd, "inner.txt", ...) creates the file inside the directory the dirfd
        // refers to, not relative to CWD (which is still "/").
        let file_fd = task
            .sys_openat(
                dirfd,
                "inner.txt",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(file_fd).unwrap()).unwrap();
        task.sys_stat("/dirfd_test/inner.txt")
            .expect("openat(dirfd, relative) should have created the file under /dirfd_test");

        // newfstatat(dirfd, "inner.txt", ...) resolves the same way.
        task.sys_newfstatat(dirfd, "inner.txt", AtFlags::empty())
            .unwrap();

        // faccessat(dirfd, "inner.txt", ...) resolves the same way.
        task.sys_faccessat(dirfd, "inner.txt", AccessFlags::F_OK, AtFlags::empty())
            .unwrap();

        // A dup'd dirfd resolves relative paths identically, since the recorded path lives on
        // the shared open-file-description entry, not the per-descriptor fd metadata.
        let dup_dirfd = task.sys_dup(dirfd, None, None).unwrap();
        let dup_dirfd = i32::try_from(dup_dirfd).unwrap();
        task.sys_faccessat(dup_dirfd, "inner.txt", AccessFlags::F_OK, AtFlags::empty())
            .unwrap();
        task.sys_close(dup_dirfd).unwrap();

        // A non-directory dirfd (a regular file) is rejected by the underlying filesystem's own
        // path resolution once "inner.txt" is joined under it, matching real Linux's ENOTDIR.
        let non_dir_fd = task
            .sys_openat(
                dirfd,
                "inner.txt",
                litebox::fs::OFlags::RDONLY,
                Mode::empty(),
            )
            .unwrap();
        let non_dir_fd = i32::try_from(non_dir_fd).unwrap();
        assert_eq!(
            task.sys_faccessat(non_dir_fd, "x", AccessFlags::F_OK, AtFlags::empty())
                .unwrap_err(),
            Errno::ENOTDIR
        );
        task.sys_close(non_dir_fd).unwrap();

        // An unknown/closed dirfd is rejected with EBADF, not treated as AT_FDCWD.
        task.sys_close(dirfd).unwrap();
        assert_eq!(
            task.sys_faccessat(dirfd, "inner.txt", AccessFlags::F_OK, AtFlags::empty())
                .unwrap_err(),
            Errno::EBADF
        );
    }

    /// `POLLIN`, matching real Linux's raw `poll(2)`/`ppoll(2)` event-mask bit.
    const POLLIN: i16 = 0x0001;

    /// A real-concurrency stress test for `sys_ppoll`'s lost-wakeup window: a writer thread is
    /// released (via a barrier) at the same instant the poller calls `ppoll`, hundreds of times
    /// in a row, so that across enough iterations the write lands arbitrarily close to whatever
    /// internal state transition `ppoll` goes through between its "not ready yet" check and
    /// actually blocking. A poller that checked readiness and *then* registered for
    /// notification (the classic lost-wakeup ordering bug) would eventually miss a wakeup here
    /// and report a spurious timeout instead of the byte that was actually written.
    #[test]
    fn test_ppoll_does_not_lose_a_concurrent_wakeup() {
        const ITERATIONS: usize = 300;

        let task = crate::syscalls::tests::init_platform(None);
        let (rfd_u, wfd_u) = task
            .sys_pipe2(litebox::fs::OFlags::empty())
            .expect("pipe2 failed");
        let rfd = i32::try_from(rfd_u).unwrap();
        let wfd = i32::try_from(wfd_u).unwrap();

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        for i in 0..ITERATIONS {
            let mut pollfd = litebox_common_linux::Pollfd {
                fd: rfd,
                events: POLLIN,
                revents: 0,
            };

            // Vary the writer's timing relative to the poller across iterations (immediate,
            // and after a couple of short delays) so both the poller's initial fast-path check
            // and its register-then-block path each get real exercise against a genuinely
            // concurrent write, rather than one path dominating simply because a raw pipe write
            // is fast.
            let writer_delay = core::time::Duration::from_micros(match i % 3 {
                0 => 0,
                1 => 500,
                _ => 3_000,
            });
            let writer = {
                let barrier = std::sync::Arc::clone(&barrier);
                task.spawn_clone_for_test(move |task| {
                    barrier.wait();
                    if !writer_delay.is_zero() {
                        std::thread::sleep(writer_delay);
                    }
                    task.sys_write(wfd, &[0x42], None).expect("write failed")
                })
            };

            barrier.wait();
            let ready_count = task
                .sys_ppoll(
                    UserPtrMut::from_ptr(&raw mut pollfd),
                    1,
                    TimeParam::Milliseconds(2000),
                    None,
                    0,
                )
                .unwrap_or_else(|e| panic!("iteration {i}: ppoll failed: {e:?}"));

            writer.join().expect("writer thread panicked");

            assert_eq!(
                ready_count, 1,
                "iteration {i}: ppoll should report exactly one ready fd, not time out -- a 0 \
                 here means the wakeup from the concurrent write was lost"
            );
            assert_ne!(
                pollfd.revents & POLLIN,
                0,
                "iteration {i}: the ready fd should be reported as POLLIN"
            );

            // Drain the byte so the next iteration starts from an empty pipe.
            let mut buf = [0u8; 1];
            let n = task.sys_read(rfd, &mut buf, None).expect("read failed");
            assert_eq!(n, 1);
            assert_eq!(buf, [0x42]);
        }

        let _ = task.sys_close(rfd);
        let _ = task.sys_close(wfd);
    }

    #[test]
    fn automatic_pty_acquisition_publishes_foreground_group_once() {
        let task = crate::syscalls::tests::init_platform(None);
        let original_group = task.sys_getpgid(0).unwrap();
        let allocate_pty = || {
            let master = i32::try_from(
                task.sys_openat(
                    litebox_common_linux::AT_FDCWD,
                    "/dev/ptmx",
                    OFlags::RDWR | OFlags::NOCTTY,
                    Mode::empty(),
                )
                .unwrap(),
            )
            .unwrap();
            let mut number = u32::MAX;
            task.sys_ioctl(
                master,
                IoctlArg::TIOCGPTN(UserPtrMut::from_ptr(&raw mut number)),
            )
            .unwrap();
            let unlocked = 0i32;
            task.sys_ioctl(
                master,
                IoctlArg::TIOCSPTLCK(UserPtr::from_ptr(&raw const unlocked)),
            )
            .unwrap();
            (master, number)
        };
        let (first_master, first_number) = allocate_pty();
        let (second_master, second_number) = allocate_pty();

        assert_eq!(task.sys_setsid(), Ok(task.pid));
        let session_group = task.sys_getpgid(0).unwrap();
        assert_ne!(session_group, original_group);
        let first_slave = i32::try_from(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                alloc::format!("/dev/pts/{first_number}"),
                OFlags::RDWR,
                Mode::empty(),
            )
            .unwrap(),
        )
        .unwrap();
        let foreground_group = |fd| {
            let mut group = -1;
            task.sys_ioctl(
                fd,
                IoctlArg::TIOCGPGRP(UserPtrMut::from_ptr(&raw mut group)),
            )
            .unwrap();
            group
        };
        assert_eq!(
            foreground_group(first_slave),
            session_group,
            "automatic controlling-terminal acquisition must replace the group captured at ptmx open"
        );

        let selected_group = 6767;
        task.sys_ioctl(
            first_slave,
            IoctlArg::TIOCSPGRP(UserPtr::from_ptr(&raw const selected_group)),
        )
        .unwrap();
        let reopened_first = i32::try_from(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                alloc::format!("/dev/pts/{first_number}"),
                OFlags::RDWR,
                Mode::empty(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            foreground_group(reopened_first),
            selected_group,
            "reopening an existing controlling terminal must preserve TIOCSPGRP state"
        );

        let second_slave = i32::try_from(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                alloc::format!("/dev/pts/{second_number}"),
                OFlags::RDWR,
                Mode::empty(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            foreground_group(second_slave),
            original_group,
            "failed acquisition of a different controlling terminal must not publish a new foreground group"
        );

        task.sys_close(second_slave).unwrap();
        task.sys_close(reopened_first).unwrap();
        task.sys_close(first_slave).unwrap();
        task.sys_close(second_master).unwrap();
        task.sys_close(first_master).unwrap();
    }

    #[test]
    fn unix98_pty_allocates_unlocks_and_transports_both_directions() {
        let task = crate::syscalls::tests::init_platform(None);
        assert_eq!(task.sys_setsid(), Ok(task.pid));
        assert_eq!(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                "/dev/tty",
                OFlags::RDWR,
                Mode::empty()
            ),
            Err(Errno::ENXIO),
            "setsid must leave the process without a controlling terminal"
        );
        let master = i32::try_from(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                "/dev/ptmx",
                OFlags::RDWR | OFlags::NOCTTY,
                Mode::empty(),
            )
            .unwrap(),
        )
        .unwrap();

        let mut number = u32::MAX;
        assert_eq!(
            task.sys_ioctl(
                master,
                IoctlArg::TIOCGPTN(UserPtrMut::from_ptr(&raw mut number)),
            ),
            Ok(0)
        );
        assert_eq!(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                alloc::format!("/dev/pts/{number}"),
                OFlags::RDWR | OFlags::NOCTTY,
                Mode::empty(),
            ),
            Err(Errno::EIO),
            "the slave must remain locked until TIOCSPTLCK"
        );

        let unlocked = 0i32;
        assert_eq!(
            task.sys_ioctl(
                master,
                IoctlArg::TIOCSPTLCK(UserPtr::from_ptr(&raw const unlocked)),
            ),
            Ok(0)
        );
        let slave = i32::try_from(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                alloc::format!("/dev/pts/{number}"),
                OFlags::RDWR | OFlags::NOCTTY,
                Mode::empty(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                "/dev/tty",
                OFlags::RDWR,
                Mode::empty()
            ),
            Err(Errno::ENXIO),
            "O_NOCTTY must suppress controlling-terminal acquisition"
        );

        assert_eq!(task.sys_write(master, b"input", None), Ok(5));
        let mut input = [0; 5];
        assert_eq!(task.sys_read(slave, &mut input, None), Ok(5));
        assert_eq!(&input, b"input");

        assert_eq!(task.sys_write(slave, b"output", None), Ok(6));
        let mut output = [0; 6];
        assert_eq!(task.sys_read(master, &mut output, None), Ok(6));
        assert_eq!(&output, b"output");

        let controlling = i32::try_from(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                alloc::format!("/dev/pts/{number}"),
                OFlags::RDWR,
                Mode::empty(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(task.sys_ioctl(controlling, IoctlArg::TIOCSCTTY(0)), Ok(0));
        let mut foreground_pgid = -1;
        assert_eq!(
            task.sys_ioctl(
                controlling,
                IoctlArg::TIOCGPGRP(UserPtrMut::from_ptr(&raw mut foreground_pgid)),
            ),
            Ok(0)
        );
        let process_group_id = task.sys_getpgid(0).unwrap();
        assert_eq!(
            foreground_pgid, process_group_id,
            "TIOCSCTTY must publish the caller's process-owned group as the PTY foreground group"
        );

        // Reproduce the desktop race exactly: another process mutates its own process group after
        // this PTY has published its foreground group. Neither the first process's identity nor
        // the PTY's foreground state may move, and replaying TIOCSCTTY must be idempotent.
        let unrelated = task
            .global
            .clone()
            .new_test_task(task.files.borrow().fs.clone());
        assert_eq!(unrelated.sys_setpgid(0, 7777), Ok(()));
        assert_eq!(task.sys_getpgid(0), Ok(process_group_id));
        foreground_pgid = -1;
        assert_eq!(
            task.sys_ioctl(
                controlling,
                IoctlArg::TIOCGPGRP(UserPtrMut::from_ptr(&raw mut foreground_pgid)),
            ),
            Ok(0)
        );
        assert_eq!(foreground_pgid, process_group_id);
        assert_eq!(task.sys_ioctl(controlling, IoctlArg::TIOCSCTTY(0)), Ok(0));
        foreground_pgid = -1;
        assert_eq!(
            task.sys_ioctl(
                controlling,
                IoctlArg::TIOCGPGRP(UserPtrMut::from_ptr(&raw mut foreground_pgid)),
            ),
            Ok(0)
        );
        assert_eq!(foreground_pgid, process_group_id);
        let tty = i32::try_from(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                "/dev/tty",
                OFlags::RDWR,
                Mode::empty(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(task.sys_write(tty, b"alias", None), Ok(5));
        let mut alias = [0; 5];
        assert_eq!(task.sys_read(master, &mut alias, None), Ok(5));
        assert_eq!(&alias, b"alias");

        let requested = litebox_common_linux::Winsize {
            row: 37,
            col: 111,
            xpixel: 777,
            ypixel: 333,
        };
        task.sys_ioctl(
            master,
            IoctlArg::TIOCSWINSZ(UserPtr::from_ptr(&raw const requested)),
        )
        .unwrap();
        let mut observed = litebox_common_linux::Winsize {
            row: 0,
            col: 0,
            xpixel: 0,
            ypixel: 0,
        };
        task.sys_ioctl(
            slave,
            IoctlArg::TIOCGWINSZ(UserPtrMut::from_ptr(&raw mut observed)),
        )
        .unwrap();
        assert_eq!(
            (observed.row, observed.col, observed.xpixel, observed.ypixel),
            (37, 111, 777, 333)
        );

        task.sys_close(master).unwrap();
        assert_eq!(
            task.sys_openat(
                litebox_common_linux::AT_FDCWD,
                alloc::format!("/dev/pts/{number}"),
                OFlags::RDWR,
                Mode::empty(),
            ),
            Err(Errno::ENOENT),
            "closing the master must retire the slave pathname"
        );
        task.sys_close(tty).unwrap();
        task.sys_close(controlling).unwrap();
        task.sys_close(slave).unwrap();
    }

    #[test]
    fn tiocgwinsz_never_regresses_to_the_old_hardcoded_20x20() {
        // Regression test for a genuine echo-wrapping bug: `TIOCGWINSZ` used to unconditionally
        // report a hardcoded 20x20 window, regardless of the real terminal size. Guests' own
        // line editors (e.g. `ash`'s `lineedit.c`) query this to decide the column width at
        // which to wrap their own echoed-input redisplay, so a fake 20-column width caused
        // spurious wraps in the echo of typed input well before the real terminal (which may be
        // 80, 120, or wider) would ever need to wrap.
        //
        // This calls `stdio_ioctl` directly rather than `sys_ioctl`: the latter's stdio path
        // additionally gates on `Platform::is_a_tty`, which `cargo test`'s captured stdout
        // makes false in the common case, so going through it here would just assert `ENOTTY`
        // rather than exercising the fallback logic under test.
        let task = crate::syscalls::tests::init_platform(None);

        let mut ws = litebox_common_linux::Winsize {
            row: 0xFFFF,
            col: 0xFFFF,
            xpixel: 0xFFFF,
            ypixel: 0xFFFF,
        };
        let ws_ptr = UserPtrMut::from_usize((&raw mut ws).expose_provenance());
        assert_eq!(
            task.stdio_ioctl(StdioStream::Stdout, &IoctlArg::TIOCGWINSZ(ws_ptr)),
            Ok(0)
        );
        assert_ne!(
            (ws.row, ws.col),
            (20, 20),
            "must not regress to the old hardcoded 20x20 fake window size"
        );
        // The test platform has no real terminal backing its (captured) stdout in the common
        // `cargo test` case, so this asserts the 80x24 fallback; on the rare host where stdout
        // genuinely is a tty (e.g. an interactive `cargo test -- --nocapture`), it instead
        // asserts the handler faithfully reported that real size.
        match task.global.platform.tty_window_size() {
            None => assert_eq!(
                (ws.row, ws.col),
                (24, 80),
                "must fall back to the traditional 80x24 default when the platform has no real \
                 terminal size"
            ),
            Some(real) => assert_eq!(
                (ws.row, ws.col),
                real,
                "must report the platform's real terminal size when available"
            ),
        }
    }
}
