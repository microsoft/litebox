// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of file related syscalls, e.g., `open`, `read`, `write`, etc.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    string::{String, ToString as _},
    sync::Arc,
    vec,
    vec::Vec,
};
use litebox::{
    event::{Events, IOPollable, wait::WaitError},
    fd::{ErrRawIntFd, FdEnabledSubsystem, MetadataError, TypedFd},
    fs::{Mode, OFlags, SeekWhence},
    path,
    platform::{
        Instant as _, RawConstPointer, RawMutPointer, StdioProvider as _, TimeProvider as _,
    },
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt as _},
};
use litebox_common_linux::{
    AtFlags, ClockId, EfdFlags, EpollCreateFlags, FcntlArg, FileDescriptorFlags, FileStat,
    IoReadVec, IoWriteVec, IoctlArg, ItimerSpec, STATX_BASIC_STATS, StatfsBuf, StatxBuf,
    StatxTimestamp, TMPFS_MAGIC, TimeParam, TimerfdFlags, TimerfdTimerFlags, errno::Errno,
    fd_token_protocol::PtyIoctlOp,
};
use litebox_platform_multiplex::Platform;

use crate::syscalls::signal::siginfo_kernel;
use crate::{ConstPtr, GlobalState, MutPtr, ShimFS, Task};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::{any::TypeId, fmt::Write as _};

const LITEBOX_IOCTL_KIND_TYPEID_INVARIANT: u32 = 0x4c42_4901;
const LITEBOX_IOCTL_DEBUG_BUF_LEN: usize = 4096;

impl<FS: ShimFS> Task<FS> {
    fn expected_descriptor_type(
        kind: litebox::fd::SubsystemKind,
    ) -> Option<(TypeId, &'static str)> {
        Some(match kind {
            litebox::fd::SubsystemKind::Fs => (
                TypeId::of::<<FS as FdEnabledSubsystem>::Entry>(),
                core::any::type_name::<<FS as FdEnabledSubsystem>::Entry>(),
            ),
            litebox::fd::SubsystemKind::Net => (
                TypeId::of::<<litebox::net::Network<Platform> as FdEnabledSubsystem>::Entry>(),
                core::any::type_name::<
                    <litebox::net::Network<Platform> as FdEnabledSubsystem>::Entry,
                >(),
            ),
            // Phase 3 removed the legacy `litebox::pipes::Pipes` implementation.
            // Any live descriptor table entry with this tag is therefore a hard
            // invariant violation; no concrete entry type should be registered.
            litebox::fd::SubsystemKind::Pipes => return None,
            litebox::fd::SubsystemKind::Eventfd => (
                TypeId::of::<super::eventfd::EventFile<Platform>>(),
                core::any::type_name::<super::eventfd::EventFile<Platform>>(),
            ),
            litebox::fd::SubsystemKind::Epoll => (
                TypeId::of::<super::epoll::EpollFile<FS>>(),
                core::any::type_name::<super::epoll::EpollFile<FS>>(),
            ),
            litebox::fd::SubsystemKind::Unix => (
                TypeId::of::<super::unix::UnixSocket<FS>>(),
                core::any::type_name::<super::unix::UnixSocket<FS>>(),
            ),
            litebox::fd::SubsystemKind::HostPassthroughFd => (
                TypeId::of::<super::host_passthrough_fd::HostPassthroughFdEntry>(),
                core::any::type_name::<super::host_passthrough_fd::HostPassthroughFdEntry>(),
            ),
            litebox::fd::SubsystemKind::BrokerPipe => (
                TypeId::of::<super::broker_pipe::BrokerPipeFd<Platform>>(),
                core::any::type_name::<super::broker_pipe::BrokerPipeFd<Platform>>(),
            ),
            litebox::fd::SubsystemKind::BrokerSocketPair => (
                TypeId::of::<super::broker_socketpair::BrokerSocketPairFd<Platform>>(),
                core::any::type_name::<super::broker_socketpair::BrokerSocketPairFd<Platform>>(),
            ),
            litebox::fd::SubsystemKind::BrokerSocketDgram => (
                TypeId::of::<super::broker_socket_dgram::BrokerSocketDgramFd<Platform>>(),
                core::any::type_name::<super::broker_socket_dgram::BrokerSocketDgramFd<Platform>>(),
            ),
            litebox::fd::SubsystemKind::BrokerSocketSeqPacket => (
                TypeId::of::<super::broker_socket_seqpacket::BrokerSocketSeqPacketFd<Platform>>(),
                core::any::type_name::<
                    super::broker_socket_seqpacket::BrokerSocketSeqPacketFd<Platform>,
                >(),
            ),
            litebox::fd::SubsystemKind::BrokerUnixStream => (
                TypeId::of::<super::broker_unix_stream::BrokerUnixStreamFd<Platform>>(),
                core::any::type_name::<super::broker_unix_stream::BrokerUnixStreamFd<Platform>>(),
            ),
            litebox::fd::SubsystemKind::BrokerPty => (
                TypeId::of::<super::broker_pty::BrokerPtyFd<Platform>>(),
                core::any::type_name::<super::broker_pty::BrokerPtyFd<Platform>>(),
            ),
            litebox::fd::SubsystemKind::Signalfd => (
                TypeId::of::<super::signalfd::SignalfdFile>(),
                core::any::type_name::<super::signalfd::SignalfdFile>(),
            ),
            litebox::fd::SubsystemKind::Inotify => (
                TypeId::of::<super::inotify::InotifyFile>(),
                core::any::type_name::<super::inotify::InotifyFile>(),
            ),
            litebox::fd::SubsystemKind::BrokerInetListener => (
                TypeId::of::<super::broker_inet_listener::BrokerInetListenerFd<Platform>>(),
                core::any::type_name::<super::broker_inet_listener::BrokerInetListenerFd<Platform>>(
                ),
            ),
            litebox::fd::SubsystemKind::BrokerInetDgram => (
                TypeId::of::<super::broker_inet_dgram::BrokerInetDgramFd<Platform>>(),
                core::any::type_name::<super::broker_inet_dgram::BrokerInetDgramFd<Platform>>(),
            ),
            litebox::fd::SubsystemKind::BrokerInetRaw => (
                TypeId::of::<super::broker_inet_raw::BrokerInetRawFd<Platform>>(),
                core::any::type_name::<super::broker_inet_raw::BrokerInetRawFd<Platform>>(),
            ),
            litebox::fd::SubsystemKind::BrokerTcpConn => (
                TypeId::of::<super::broker_tcp_conn::BrokerTcpConnFd<Platform>>(),
                core::any::type_name::<super::broker_tcp_conn::BrokerTcpConnFd<Platform>>(),
            ),
        })
    }

    fn debug_kind_typeid_invariant_report(&self) -> String {
        let dt = self.global.litebox.descriptor_table();
        let mut mismatches = Vec::new();
        let mut total = 0usize;
        for (fd, kind, actual) in dt.iter_with_kind() {
            total += 1;
            if kind == litebox::fd::SubsystemKind::Fs {
                continue;
            }
            match Self::expected_descriptor_type(kind) {
                Some((expected, _expected_name)) if expected == actual => {}
                Some((expected, expected_name)) => mismatches.push(alloc::format!(
                    "fd={fd} kind={kind:?} expected={expected:?} ({expected_name}) actual={actual:?}"
                )),
                None => mismatches.push(alloc::format!(
                    "fd={fd} kind={kind:?} has no registered expected TypeId; actual={actual:?}"
                )),
            }
        }
        if mismatches.is_empty() {
            alloc::format!("ok: checked {total} descriptors")
        } else {
            let mut out = alloc::format!(
                "kind/typeid mismatches ({} of {total} descriptors):",
                mismatches.len()
            );
            for mismatch in mismatches {
                let _ = write!(out, "\n{mismatch}");
            }
            out
        }
    }
}

fn host_stdio_source_for_path(path: &str) -> Option<i32> {
    match path {
        "/dev/stdin" => Some(0),
        "/dev/stdout" => Some(1),
        "/dev/stderr" => Some(2),
        _ => None,
    }
}

fn is_host_tty_path(path: &str) -> bool {
    path == "/dev/tty"
}

/// Build Linux-style NUL-separated `/proc/<pid>/cmdline` data.
pub(crate) fn proc_cmdline_from_argv(argv: &[CString], fallback_exe: &str) -> Vec<u8> {
    if argv.is_empty() {
        if fallback_exe.is_empty() {
            return vec![0];
        }
        let mut out = fallback_exe.as_bytes().to_vec();
        out.push(0);
        return out;
    }

    let mut out = Vec::new();
    for arg in argv {
        out.extend_from_slice(arg.as_bytes());
        out.push(0);
    }
    out
}

/// Check if a path matches the host's actual PTY device path (e.g., `/dev/pts/156`).
fn is_host_pty_device_path(path: &str, platform: &litebox_platform_multiplex::Platform) -> bool {
    platform
        .host_stdin_tty_device_info()
        .is_some_and(|info| path == info.path)
}

/// Synthetic device IDs for anonymous descriptor pseudo-filesystems,
/// mirroring the Linux kernel's `sockfs`, `pipefs`, and `anon_inodefs`.
const SOCKFS_DEV: u64 = 0x000c;
const PIPEFS_DEV: u64 = 0x000d;
const ANON_INODE_DEV: u64 = 0x000e;

fn timerfd_bridge_restore_spec(
    spec: ItimerSpec,
    pending_expirations: u64,
    elapsed_ns: u128,
) -> Result<ItimerSpec, Errno> {
    let mut restore_spec = spec;
    let had_value = spec.value.tv_sec != 0 || spec.value.tv_nsec != 0;
    if had_value {
        let value = core::time::Duration::try_from(spec.value)?;
        let adjusted_ns = value.as_nanos().saturating_sub(elapsed_ns);
        restore_spec.value = if adjusted_ns == 0 {
            litebox_common_linux::Timespec {
                tv_sec: 0,
                tv_nsec: 1,
            }
        } else {
            let secs = adjusted_ns / 1_000_000_000;
            let nsecs = adjusted_ns % 1_000_000_000;
            litebox_common_linux::Timespec {
                tv_sec: i64::try_from(secs).map_err(|_| Errno::EINVAL)?,
                tv_nsec: u64::try_from(nsecs).map_err(|_| Errno::EINVAL)?,
            }
        };
    } else if pending_expirations > 0 {
        restore_spec.value = litebox_common_linux::Timespec {
            tv_sec: 0,
            tv_nsec: 1,
        };
    }
    Ok(restore_spec)
}

/// Marker metadata attached to fds opened via the host PTY device path
/// (e.g., `/dev/pts/156`). Causes the shim's `descriptor_stat()` to override
/// `st_dev`, `st_ino`, and `st_rdev` with the real host PTY identity so that
/// `fstat(reopened_fd)` is consistent with `fstat(0)`.
#[derive(Clone)]
pub(crate) struct HostPtyDeviceFd;

/// Monotonically increasing counter for unique inode numbers assigned to
/// anonymous file descriptors (sockets, pipes, eventfds, epoll instances).
static ANON_INO_COUNTER: AtomicUsize = AtomicUsize::new(1);

/// Fixed inode for the `/proc/self/exe` symlink so that repeated `lstat`
/// calls return a stable identity.
static PROC_SELF_EXE_INO: AtomicUsize = AtomicUsize::new(0);

/// Stable inode number stored as entry metadata on anonymous descriptors.
/// Assigned once on first stat and reused for the lifetime of the open file
/// description (including across `dup`).
#[derive(Clone)]
struct AnonIno(u64);

/// Classification of a file descriptor for terminal ioctl routing.
enum TerminalKind {
    /// Host stdio device (major=5) — forward ioctls to host kernel.
    HostStdio,
    /// Not a terminal device.
    NotTerminal,
}

const IN_MODIFY: u32 = 0x0000_0002;
const IN_MOVED_FROM: u32 = 0x0000_0040;
const IN_MOVED_TO: u32 = 0x0000_0080;
const IN_CREATE: u32 = 0x0000_0100;
const IN_DELETE: u32 = 0x0000_0200;

static INOTIFY_COOKIE_COUNTER: AtomicUsize = AtomicUsize::new(1);

#[derive(Clone)]
struct InotifyWatch {
    path: String,
    mask: u32,
    entries: BTreeMap<String, (usize, usize, u64)>,
}

struct InotifyEventRecord {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: String,
}

pub(crate) struct InotifyInstanceState {
    eventfd: litebox::fd::EntryHandle<Platform, super::eventfd::EventfdSubsystem>,
    next_watch_descriptor: i32,
    watches: BTreeMap<i32, InotifyWatch>,
    events: Vec<InotifyEventRecord>,
}

impl InotifyInstanceState {
    fn new(eventfd: litebox::fd::EntryHandle<Platform, super::eventfd::EventfdSubsystem>) -> Self {
        Self {
            eventfd,
            next_watch_descriptor: 1,
            watches: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    fn add_watch(
        &mut self,
        path: String,
        mask: u32,
        entries: BTreeMap<String, (usize, usize, u64)>,
    ) -> Result<i32, Errno> {
        let wd = self.next_watch_descriptor;
        self.next_watch_descriptor = self
            .next_watch_descriptor
            .checked_add(1)
            .ok_or(Errno::ENOMEM)?;
        self.watches.insert(
            wd,
            InotifyWatch {
                path,
                mask,
                entries,
            },
        );
        Ok(wd)
    }

    fn remove_watch(&mut self, wd: i32) -> Result<(), Errno> {
        if wd <= 0 {
            return Err(Errno::EINVAL);
        }
        self.watches.remove(&wd).map(|_| ()).ok_or(Errno::EINVAL)
    }

    fn enqueue_matching(&mut self, dir: &str, mask: u32, cookie: u32, name: &str) -> bool {
        let mut queued = false;
        for (&wd, watch) in &self.watches {
            if watch.path == dir && (watch.mask & mask) != 0 {
                self.events.push(InotifyEventRecord {
                    wd,
                    mask,
                    cookie,
                    name: name.to_string(),
                });
                queued = true;
            }
        }
        queued
    }

    fn read_events(&mut self, buf: &mut [u8]) -> Result<usize, Errno> {
        if self.events.is_empty() {
            return Err(Errno::EAGAIN);
        }

        let mut written = 0usize;
        let mut consumed = 0usize;
        for event in &self.events {
            let name_len = event.name.len().checked_add(1).ok_or(Errno::EINVAL)?;
            let record_len = size_of::<i32>() + 3 * size_of::<u32>() + name_len;
            if written + record_len > buf.len() {
                if written == 0 {
                    return Err(Errno::EINVAL);
                }
                break;
            }

            buf[written..written + size_of::<i32>()].copy_from_slice(&event.wd.to_ne_bytes());
            written += size_of::<i32>();
            for value in [event.mask, event.cookie, u32::try_from(name_len).unwrap()] {
                buf[written..written + size_of::<u32>()].copy_from_slice(&value.to_ne_bytes());
                written += size_of::<u32>();
            }
            buf[written..written + event.name.len()].copy_from_slice(event.name.as_bytes());
            written += event.name.len();
            buf[written] = 0;
            written += 1;
            consumed += 1;
        }
        self.events.drain(..consumed);
        Ok(written)
    }
}

/// Task state shared by `CLONE_FS`.
pub(crate) struct FsState {
    umask: core::sync::atomic::AtomicU32,
    /// The current working directory
    ///
    /// Must end with a '/'.
    cwd: litebox::sync::RwLock<Platform, String>,
    /// The path of the current executable (for `/proc/self/exe`).
    pub(crate) exe_path: litebox::sync::RwLock<Platform, String>,
}

impl Clone for FsState {
    fn clone(&self) -> Self {
        Self {
            umask: self.umask.load(Ordering::Relaxed).into(),
            cwd: litebox::sync::RwLock::new(self.cwd.read().clone()),
            exe_path: litebox::sync::RwLock::new(self.exe_path.read().clone()),
        }
    }
}

impl FsState {
    pub fn new() -> Self {
        Self {
            umask: (Mode::WGRP | Mode::WOTH).bits().into(),
            cwd: litebox::sync::RwLock::new(String::from("/")),
            exe_path: litebox::sync::RwLock::new(String::new()),
        }
    }

    /// Create a new `FsState` with a custom initial working directory.
    ///
    /// The `cwd` must be an absolute path. A trailing '/' is appended if missing.
    pub fn with_cwd(mut cwd: String) -> Self {
        assert!(cwd.starts_with('/'), "initial CWD must be absolute");
        if !cwd.ends_with('/') {
            cwd.push('/');
        }
        Self {
            umask: (Mode::WGRP | Mode::WOTH).bits().into(),
            cwd: litebox::sync::RwLock::new(cwd),
            exe_path: litebox::sync::RwLock::new(String::new()),
        }
    }

    /// Reconstruct filesystem state from a fork snapshot.
    pub(crate) fn from_restore(cwd: String, exe_path: String, umask: u32) -> Self {
        Self {
            umask: core::sync::atomic::AtomicU32::new(umask),
            cwd: litebox::sync::RwLock::new(cwd),
            exe_path: litebox::sync::RwLock::new(exe_path),
        }
    }

    pub(crate) fn umask(&self) -> Mode {
        Mode::from_bits_retain(self.umask.load(Ordering::Relaxed))
    }

    /// Returns the current working directory path.
    pub(crate) fn current_working_directory(&self) -> String {
        self.cwd.read().clone()
    }
}

/// Task state shared by `CLONE_FILES`.
pub(crate) struct FilesState<FS: ShimFS> {
    /// The filesystem implementation, shared across tasks that share file system.
    pub(crate) fs: alloc::sync::Arc<FS>,
    pub(crate) raw_descriptor_store:
        litebox::sync::RwLock<Platform, litebox::fd::RawDescriptorStorage>,
    pub(crate) host_stdio_object_ids:
        litebox::sync::RwLock<Platform, [Option<litebox::fd::DescriptorObjectId>; 3]>,
    file_position_lock: alloc::sync::Arc<litebox::sync::Mutex<Platform, ()>>,
    inotify_instances: litebox::sync::Mutex<
        Platform,
        BTreeMap<usize, Arc<litebox::sync::Mutex<Platform, InotifyInstanceState>>>,
    >,
    closed_broker_pty_fds: litebox::sync::Mutex<Platform, BTreeSet<usize>>,
    max_fd: AtomicUsize,
}

impl<FS: ShimFS> FilesState<FS> {
    pub(crate) fn new(fs: alloc::sync::Arc<FS>) -> Self {
        Self {
            fs,
            raw_descriptor_store: litebox::sync::RwLock::new(
                litebox::fd::RawDescriptorStorage::new(),
            ),
            host_stdio_object_ids: litebox::sync::RwLock::new([None, None, None]),
            file_position_lock: Arc::new(litebox::sync::Mutex::new(())),
            inotify_instances: litebox::sync::Mutex::new(BTreeMap::new()),
            closed_broker_pty_fds: litebox::sync::Mutex::new(BTreeSet::new()),
            max_fd: AtomicUsize::new(usize::MAX),
        }
    }

    pub(crate) fn set_max_fd(&self, max_fd: usize) {
        self.max_fd.store(max_fd, Ordering::Relaxed);
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

    /// Clone the FD table for `fork()`.
    ///
    /// Creates an independent FD table that shares the underlying file objects
    /// (via `Arc`) with the parent. This matches POSIX fork semantics: the
    /// child gets its own FD number space but file descriptions (offsets,
    /// flags) are shared. Each raw fd is duplicated in the global descriptor
    /// table so the child's `OwnedFd` instances are independent from the
    /// parent's.
    pub fn clone_for_fork(
        &self,
        global_dt: &mut litebox::fd::Descriptors<litebox_platform_multiplex::Platform>,
    ) -> Self {
        Self {
            fs: self.fs.clone(),
            raw_descriptor_store: litebox::sync::RwLock::new(
                self.raw_descriptor_store.read().clone_for_fork(global_dt),
            ),
            host_stdio_object_ids: litebox::sync::RwLock::new(*self.host_stdio_object_ids.read()),
            file_position_lock: self.file_position_lock.clone(),
            inotify_instances: litebox::sync::Mutex::new(self.inotify_instances.lock().clone()),
            closed_broker_pty_fds: litebox::sync::Mutex::new(BTreeSet::new()),
            max_fd: AtomicUsize::new(self.max_fd.load(Ordering::Relaxed)),
        }
    }

    fn register_inotify_fd(
        &self,
        raw_fd: usize,
        state: Arc<litebox::sync::Mutex<Platform, InotifyInstanceState>>,
    ) {
        self.inotify_instances.lock().insert(raw_fd, state);
    }

    fn duplicate_inotify_fd(&self, old_fd: usize, new_fd: usize) {
        let state = self.inotify_instances.lock().get(&old_fd).cloned();
        if let Some(state) = state {
            self.inotify_instances.lock().insert(new_fd, state);
        }
    }

    fn remove_inotify_fd(
        &self,
        raw_fd: usize,
    ) -> Option<Arc<litebox::sync::Mutex<Platform, InotifyInstanceState>>> {
        self.inotify_instances.lock().remove(&raw_fd)
    }

    /// Returns true if any inotify instances are open.
    pub(crate) fn has_inotify_instances(&self) -> bool {
        !self.inotify_instances.lock().is_empty()
    }

    fn with_inotify_fd<R>(
        &self,
        raw_fd: usize,
        f: impl FnOnce(&mut InotifyInstanceState) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let state = self
            .inotify_instances
            .lock()
            .get(&raw_fd)
            .cloned()
            .ok_or(Errno::EBADF)?;
        let mut state = state.lock();
        f(&mut state)
    }
}

/// Path in the file system
#[derive(Debug)]
enum FsPath {
    /// Absolute path
    Absolute { path: CString },
    /// Current working directory
    Cwd,
    /// Path is relative to a file descriptor whose path is not known to
    /// the shim. Will be passed through to the `FileSystem` `*_at` methods.
    FdRelative { fd: u32, path: CString },
    /// Fd
    Fd(u32),
}

/// Maximum size of a file path
pub const PATH_MAX: usize = 4096;

impl FsPath {
    /// Create a new `FsPath` from a dirfd and path.
    ///
    /// CWD-relative paths are resolved immediately to absolute paths.
    /// Empty paths return `ENOENT` unless `allow_empty` is true (for
    /// syscalls that support `AT_EMPTY_PATH`).
    fn new(
        dirfd: i32,
        path: impl path::Arg,
        get_cwd: impl FnOnce() -> String,
    ) -> Result<Self, Errno> {
        Self::new_inner(dirfd, path, get_cwd, false)
    }

    /// Like [`new`](Self::new) but permits empty paths, producing
    /// `FsPath::Fd` or `FsPath::Cwd`. Callers must only use this when
    /// `AT_EMPTY_PATH` is set.
    #[cfg(test)]
    fn new_empty_ok(
        dirfd: i32,
        path: impl path::Arg,
        get_cwd: impl FnOnce() -> String,
    ) -> Result<Self, Errno> {
        Self::new_inner(dirfd, path, get_cwd, true)
    }

    fn new_inner(
        dirfd: i32,
        path: impl path::Arg,
        get_cwd: impl FnOnce() -> String,
        allow_empty: bool,
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
                if !allow_empty {
                    return Err(Errno::ENOENT);
                }
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
                if !allow_empty {
                    return Err(Errno::ENOENT);
                }
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

impl<FS: ShimFS> Task<FS> {
    fn validate_removedir_path_str(path: &str) -> Result<(), Errno> {
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        match path.rsplit('/').find(|component| !component.is_empty()) {
            Some(".") => return Err(Errno::EINVAL),
            Some("..") => return Err(Errno::ENOTEMPTY),
            _ => {}
        }
        Ok(())
    }

    fn get_umask(&self) -> Mode {
        self.fs.borrow().umask()
    }

    fn inotify_parent_and_name(path: &str) -> Option<(&str, &str)> {
        let (parent, name) = path.rsplit_once('/')?;
        if name.is_empty() {
            return None;
        }
        let parent = if parent.is_empty() { "/" } else { parent };
        Some((parent, name))
    }

    fn next_inotify_cookie() -> u32 {
        let next = INOTIFY_COOKIE_COUNTER.fetch_add(1, Ordering::Relaxed);
        u32::try_from(next).unwrap_or(u32::MAX).max(1)
    }

    fn notify_inotify_path(&self, path: &str, mask: u32, cookie: u32) {
        let Some((dir, name)) = Self::inotify_parent_and_name(path) else {
            return;
        };
        let instances = self.global.inotify_instances.lock().clone();
        for instance in instances {
            let eventfd = {
                let mut state = instance.lock();
                if state.enqueue_matching(dir, mask, cookie, name) {
                    Some(state.eventfd.clone())
                } else {
                    None
                }
            };
            if let Some(eventfd) = eventfd {
                let _ = eventfd.with_entry(|file| file.write(&self.wait_cx(), 1));
            }
        }
    }

    fn inotify_dir_snapshot(&self, path: &str) -> BTreeMap<String, (usize, usize, u64)> {
        let files = self.files.borrow();
        let Ok(dir) = ({
            let mut descriptors = self.global.litebox.descriptor_table_mut();
            files.fs.open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
                &mut *descriptors,
            )
        }) else {
            return BTreeMap::new();
        };
        let entries = {
            let mut descriptors = self.global.litebox.descriptor_table_mut();
            files
                .fs
                .read_dir(&dir, &mut *descriptors)
                .unwrap_or_default()
        };
        let mut snapshot = BTreeMap::new();
        for entry in entries {
            let child_path = if path == "/" {
                alloc::format!("/{name}", name = entry.name)
            } else {
                alloc::format!("{path}/{name}", name = entry.name)
            };
            let descriptors = self.global.litebox.descriptor_table();
            if let Ok(status) = files.fs.file_status(child_path.clone(), &*descriptors) {
                let mut hash = 0u64;
                if matches!(status.file_type, litebox::fs::FileType::RegularFile)
                    && let Ok(file) = {
                        let mut descriptors = self.global.litebox.descriptor_table_mut();
                        files.fs.open(
                            &child_path,
                            OFlags::RDONLY,
                            Mode::empty(),
                            &mut *descriptors,
                        )
                    }
                {
                    let mut buf = [0u8; 4096];
                    if let Ok(n) = {
                        let descriptors = self.global.litebox.descriptor_table();
                        files.fs.read(&file, &mut buf, Some(0), &*descriptors)
                    } {
                        for &byte in &buf[..n] {
                            hash = hash.wrapping_mul(16_777_619) ^ u64::from(byte);
                        }
                    }
                    let mut descriptors = self.global.litebox.descriptor_table_mut();
                    let _ = files.fs.close(&file, &mut *descriptors);
                }
                snapshot.insert(entry.name, (status.size, status.node_info.ino, hash));
            }
        }
        let mut descriptors = self.global.litebox.descriptor_table_mut();
        let _ = files.fs.close(&dir, &mut *descriptors);
        snapshot
    }

    fn rescan_inotify_instance(&self, instance: &mut InotifyInstanceState) {
        let watch_descriptors: Vec<i32> = instance.watches.keys().copied().collect();
        for wd in watch_descriptors {
            let Some(watch) = instance.watches.get_mut(&wd) else {
                continue;
            };
            let current = self.inotify_dir_snapshot(&watch.path);
            let removed: Vec<String> = watch
                .entries
                .keys()
                .filter(|name| !current.contains_key(*name))
                .cloned()
                .collect();
            let added: Vec<String> = current
                .keys()
                .filter(|name| !watch.entries.contains_key(*name))
                .cloned()
                .collect();
            let modified: Vec<String> = current
                .iter()
                .filter(|(name, status)| watch.entries.get(*name).is_some_and(|old| old != *status))
                .map(|(name, _)| name.clone())
                .collect();
            let mask = watch.mask;
            watch.entries = current;

            if !removed.is_empty()
                && (!added.is_empty() || !modified.is_empty())
                && (mask & (IN_MOVED_FROM | IN_MOVED_TO)) != 0
            {
                let moved_to = added.first().or_else(|| modified.first()).unwrap();
                let cookie = Self::next_inotify_cookie();
                if (mask & IN_MOVED_FROM) != 0 {
                    instance.events.push(InotifyEventRecord {
                        wd,
                        mask: IN_MOVED_FROM,
                        cookie,
                        name: removed[0].clone(),
                    });
                }
                if (mask & IN_MOVED_TO) != 0 {
                    instance.events.push(InotifyEventRecord {
                        wd,
                        mask: IN_MOVED_TO,
                        cookie,
                        name: moved_to.clone(),
                    });
                }
            } else {
                if (mask & IN_DELETE) != 0 {
                    for name in removed {
                        instance.events.push(InotifyEventRecord {
                            wd,
                            mask: IN_DELETE,
                            cookie: 0,
                            name,
                        });
                    }
                }
                if (mask & IN_CREATE) != 0 {
                    for name in added {
                        instance.events.push(InotifyEventRecord {
                            wd,
                            mask: IN_CREATE,
                            cookie: 0,
                            name,
                        });
                    }
                }
            }

            if (mask & IN_MODIFY) != 0 {
                for name in modified {
                    instance.events.push(InotifyEventRecord {
                        wd,
                        mask: IN_MODIFY,
                        cookie: 0,
                        name,
                    });
                }
            }
        }
    }

    fn broker_pty_rdev(pty_id: u32) -> usize {
        0x8800 + pty_id as usize
    }

    fn broker_pty_stat(pty_id: u32, uid: u32, gid: u32) -> FileStat {
        // S_IFCHR (0o020000) MUST be set in st_mode so glibc's
        // `is_mytty()` (called from ttyname()) recognizes the fd as a
        // character device. Without the file-type bits, ttyname falls
        // back to a /dev/pts/ getdents scan which fails (dropbear:
        // "ttyname fails for openpty device" → no PTY for SSH session).
        const S_IFCHR: u32 = 0o020000;
        let mode_bits: u32 = (Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP)
            .bits()
            .truncate();
        FileStat {
            st_dev: 5,
            st_ino: (pty_id + 3).into(),
            st_nlink: 1,
            st_mode: mode_bits | S_IFCHR,
            st_uid: uid,
            st_gid: gid,
            st_rdev: u64::try_from(Self::broker_pty_rdev(pty_id)).unwrap_or(u64::MAX),
            st_size: 0,
            st_blksize: 1024,
            st_blocks: 0,
            ..Default::default()
        }
    }

    fn pty_rdev_for_raw_fd(&self, files: &FilesState<FS>, raw_fd: usize) -> Option<usize> {
        if let Ok(fd) = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(raw_fd)
        {
            return self.global.litebox.descriptor_table().with_entry(
                &fd,
                |pty: &super::broker_pty::BrokerPtyFd<Platform>| {
                    Self::broker_pty_rdev(pty.pty_id())
                },
            );
        }
        files
            .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                crate::RawFdRef::Fs(fd) => {
                    let descriptors = self.global.litebox.descriptor_table();
                    let status = files.fs.fd_file_status(fd, &*descriptors).ok()?;
                    let rdev = status.node_info.rdev?.get();
                    ((rdev >> 8) == 136).then_some(rdev)
                }
                #[cfg(feature = "worker_local_inet")]
                crate::RawFdRef::Net(_fd) => None, // non-PTY descriptor has no PTY rdev
                crate::RawFdRef::Eventfd(_fd) => None, // non-PTY descriptor has no PTY rdev
                crate::RawFdRef::Epoll(_fd) => None,   // non-PTY descriptor has no PTY rdev
                crate::RawFdRef::Unix(_fd) => None,    // non-PTY descriptor has no PTY rdev
                crate::RawFdRef::HostPassthroughFd(_fd) => None, // non-PTY descriptor has no PTY rdev
                crate::RawFdRef::BrokerPipe(_fd) => None, // non-PTY descriptor has no PTY rdev
                crate::RawFdRef::BrokerSocketPair(_)
                | crate::RawFdRef::BrokerSocketDgram(_)
                | crate::RawFdRef::BrokerUnixStream(_)
                | crate::RawFdRef::BrokerSocketSeqPacket(_) => None, // non-PTY descriptor has no PTY rdev
                crate::RawFdRef::BrokerTcpConn(_fd) => None, // non-PTY descriptor has no PTY rdev
                crate::RawFdRef::BrokerPty(_fd) => None, // direct BrokerPty lookup is handled above
                crate::RawFdRef::Signalfd(_)
                | crate::RawFdRef::Inotify(_)
                | crate::RawFdRef::BrokerInetListener(_)
                | crate::RawFdRef::BrokerInetDgram(_) => None, // non-PTY descriptor has no PTY rdev,
                crate::RawFdRef::BrokerInetRaw(_) => None, // non-PTY descriptor has no PTY rdev,
            })
            .ok()
            .flatten()
    }

    fn _pty_target_for_guest_fd(
        &self,
        files: &FilesState<FS>,
        guest_fd: u32,
    ) -> Option<(usize, usize)> {
        let raw_fd = usize::try_from(guest_fd).ok()?;
        if !files.raw_descriptor_store.read().is_alive(raw_fd) {
            return None;
        }
        let rdev = self.pty_rdev_for_raw_fd(files, raw_fd)?;
        Some((raw_fd, rdev))
    }

    fn trace_pty_open(&self, _path: &str, _guest_fd: u32, _raw_fd: usize, _rdev: Option<usize>) {}

    fn maybe_trace_pty_dup(&self, _oldfd: u32, _newfd: u32) {}

    fn open_broker_pty_path(&self, path: &str, flags: OFlags) -> Option<Result<u32, Errno>> {
        let status = flags & OFlags::STATUS_FLAGS_MASK;
        let provider = super::broker_pty::broker_pty_provider()?;
        let (handle, pty_id, is_master, slave_anchor) = if path == "/dev/ptmx" {
            if flags.contains(OFlags::EXCL) {
                return Some(Err(Errno::EEXIST));
            }
            let pair = match provider.create_pty() {
                Ok(pair) => pair,
                Err(_) => return Some(Err(Errno::EIO)),
            };
            (
                pair.master_handle,
                pair.pty_id,
                true,
                Some(pair.slave_handle),
            )
        } else if let Some(num) = path.strip_prefix("/dev/pts/") {
            // Bare "/dev/pts/" (empty remainder) is a directory open
            // for the devpts mount itself, not a slave open — fall
            // through to the rootfs FS so applications can enumerate
            // entries via getdents. (Copilot CLI uses this as a
            // fallback after ioctl(TIOCGPTN) returns ENOTTY on
            // stdin/stdout/stderr.)
            if num.is_empty() {
                return None;
            }
            let Ok(pty_id) = num.parse::<u32>() else {
                return Some(Err(Errno::ENOENT));
            };
            if flags.contains(OFlags::EXCL) {
                return Some(Err(Errno::EEXIST));
            }
            if is_host_pty_device_path(path, self.global.platform) {
                return None;
            }
            let handle = match provider.open_pty_slave(pty_id) {
                Ok(handle) => handle,
                Err(litebox_common_linux::broker_pty_provider::BrokerOpError::UnknownHandle) => {
                    return Some(Err(Errno::ENOENT));
                }
                Err(_) => return Some(Err(Errno::EIO)),
            };
            (handle, pty_id, false, None)
        } else {
            return None;
        };

        let pty_fd = super::broker_pty::BrokerPtyFd::<Platform>::new(
            provider,
            handle,
            pty_id,
            is_master,
            slave_anchor,
            status,
        );
        // Eagerly install the broker subscription so a subsequent
        // `poll(fd, POLLIN|POLLHUP, 0)` returns current state
        // without requiring a prior read/write to trigger lazy
        // subscription (e.g., dropbear's session-end probe on the
        // master fd).
        pty_fd.ensure_subscribed_eager();
        let typed = self
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<super::broker_pty::BrokerPtySubsystem>(pty_fd);
        if flags.contains(OFlags::CLOEXEC) {
            let old = self
                .global
                .litebox
                .descriptor_table_mut()
                .set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
            debug_assert!(old.is_none());
        }
        let files = self.files.borrow();
        let raw_fd = files
            .raw_descriptor_store
            .write()
            .fd_into_raw_integer(typed);
        let guest_fd = u32::try_from(raw_fd).unwrap();
        self.trace_pty_open(path, guest_fd, raw_fd, Some(Self::broker_pty_rdev(pty_id)));
        if !is_master
            && let Some(pgid) = self
                .global
                .litebox
                .process_registry()
                .get_pgid(self.process_id)
        {
            self.global.ensure_pgrp_signal_subscription(pgid.0);
        }
        Some(Ok(guest_fd))
    }

    /// Resolve a path against the current working directory.
    fn resolve_path(&self, path: impl path::Arg) -> Result<CString, Errno> {
        let path_str = path.as_rust_str().map_err(|_| Errno::EINVAL)?;
        if path_str.starts_with('/') {
            CString::new(path_str.to_string()).map_err(|_| Errno::EINVAL)
        } else {
            let mut cwd = self.fs.borrow().cwd.read().clone();
            cwd.push_str(path_str);
            CString::new(cwd).map_err(|_| Errno::EINVAL)
        }
    }

    /// Rewrite `/proc/<N>/...` → `/proc/self/...` when N is the current
    /// process's PID. Returns `Some(rewritten)` if rewritten, `None` if
    /// the path doesn't match `/proc/<digit>/...`.
    fn rewrite_proc_pid_to_self<'a>(&self, path: &'a str) -> Option<alloc::string::String> {
        let rest = path.strip_prefix("/proc/")?;
        let slash_pos = rest.find('/').unwrap_or(rest.len());
        let pid_str = &rest[..slash_pos];
        let pid_num: i32 = pid_str.parse().ok()?;
        if pid_num == self.pid {
            let suffix = &rest[slash_pos..]; // includes leading '/' or empty
            Some(alloc::format!("/proc/self{suffix}"))
        } else {
            None
        }
    }

    /// Check if `path` is `/proc/<N>` or `/proc/<N>/...` where N is a
    /// positive integer PID. In the sandbox all guest processes are
    /// considered alive, so any positive numeric PID returns Some.
    fn proc_pid_if_known(&self, path: &str) -> Option<i32> {
        let rest = path.strip_prefix("/proc/")?;
        let slash_pos = rest.find('/').unwrap_or(rest.len());
        let pid_str = &rest[..slash_pos];
        let pid_num: i32 = pid_str.parse().ok()?;
        if pid_num > 0 { Some(pid_num) } else { None }
    }

    /// Return the subpath after `/proc/<N>`, e.g. for `/proc/42/stat`
    /// returns `"/stat"`. For `/proc/42` returns `""`.
    fn proc_pid_subpath<'a>(&self, path: &'a str) -> &'a str {
        let rest = path.strip_prefix("/proc/").unwrap_or("");
        let slash_pos = rest.find('/').unwrap_or(rest.len());
        &rest[slash_pos..]
    }

    /// Generate synthetic `/proc/<pid>/stat` content.
    /// Minimal but sufficient for sysinfo to detect process liveness.
    fn synthetic_proc_stat(&self, pid: i32) -> alloc::string::String {
        // Format: pid (comm) S ppid pgid sid ...
        // sysinfo only needs the first few fields to exist.
        let comm_bytes = self.comm.get();
        let comm = core::str::from_utf8(
            &comm_bytes[..comm_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(comm_bytes.len())],
        )
        .unwrap_or("litebox");
        alloc::format!(
            "{pid} ({comm}) S {ppid} {pgid} {sid} 0 -1 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            pid = pid,
            comm = comm,
            ppid = self.ppid,
            pgid = self.pid,
            sid = self.pid,
        )
    }

    /// Generate synthetic `/proc/<pid>/cmdline` content.
    fn synthetic_proc_cmdline(&self, pid: i32) -> alloc::vec::Vec<u8> {
        if let Some(cmdline) = self.global.proc_cmdline(pid) {
            return cmdline;
        }

        let exe = self.fs.borrow().exe_path.read().clone();
        proc_cmdline_from_argv(&[], &exe)
    }

    fn proc_comm(&self) -> alloc::string::String {
        let comm_bytes = self.comm.get();
        core::str::from_utf8(
            &comm_bytes[..comm_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(comm_bytes.len())],
        )
        .unwrap_or("litebox")
        .into()
    }

    /// Generate synthetic `/proc/<pid>/status` content.
    fn synthetic_proc_status(&self, pid: i32) -> alloc::string::String {
        let comm = self.proc_comm();
        alloc::format!(
            "Name:\t{comm}\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nUid:\t{uid}\t{euid}\t{uid}\t{euid}\nGid:\t{gid}\t{egid}\t{gid}\t{egid}\n",
            comm = comm,
            pid = pid,
            ppid = self.ppid,
            uid = self.credentials.uid,
            euid = self.credentials.euid,
            gid = self.credentials.gid,
            egid = self.credentials.egid,
        )
    }

    /// Generate synthetic `/proc/<pid>/comm` content.
    fn synthetic_proc_comm(&self) -> alloc::string::String {
        alloc::format!("{}\n", self.proc_comm())
    }

    /// Resolve an executable path to a canonical absolute path for /proc/self/exe.
    ///
    /// Linux always reports /proc/self/exe as the fully resolved path:
    /// relative paths are made absolute against CWD, `..`/`.` segments are
    /// normalized, and symlinks in every component are followed (like
    /// `realpath`).
    pub(crate) fn resolve_exe_path(&self, path: &str) -> String {
        let abs = if path.starts_with('/') {
            path.to_string()
        } else {
            let cwd = self.fs.borrow().cwd.read().clone();
            alloc::format!("{cwd}{path}")
        };
        self.canonicalize_path(&abs).unwrap_or(abs)
    }

    fn proc_self_maps_contents(&self) -> alloc::string::String {
        let ps = self.process_state.borrow();
        let mappings = ps.pm.mappings();
        let proc_map_paths = ps.proc_map_paths.lock();
        let guest_rsp = self.last_syscall.get().map(|syscall| syscall.entry_rsp);
        let stack_range = mappings
            .iter()
            .find(|(range, _)| guest_rsp.is_some_and(|rsp| range.start <= rsp && rsp < range.end))
            .or_else(|| {
                mappings
                    .iter()
                    .find(|(_, flags)| flags.contains(litebox::mm::linux::VmFlags::VM_GROWSDOWN))
            })
            .map(|(range, _)| range.clone());
        let current_brk = ps.pm.current_brk();
        let mut out = alloc::string::String::new();

        for (range, flags) in mappings {
            let mapped_path = proc_map_paths
                .iter()
                .find(|(mapped, _)| mapped.start <= range.start && range.end <= mapped.end)
                .map(|(_, path)| path.as_str());
            let _ = write!(
                out,
                "{:x}-{:x} {}{}{}{} 00000000 00:00 0",
                range.start,
                range.end,
                if flags.contains(litebox::mm::linux::VmFlags::VM_READ) {
                    'r'
                } else {
                    '-'
                },
                if flags.contains(litebox::mm::linux::VmFlags::VM_WRITE) {
                    'w'
                } else {
                    '-'
                },
                if flags.contains(litebox::mm::linux::VmFlags::VM_EXEC) {
                    'x'
                } else {
                    '-'
                },
                if flags.contains(litebox::mm::linux::VmFlags::VM_SHARED) {
                    's'
                } else {
                    'p'
                },
            );

            let label = if stack_range
                .as_ref()
                .is_some_and(|stack| stack.start == range.start && stack.end == range.end)
            {
                Some("[stack]")
            } else if current_brk != 0 && range.start <= current_brk && current_brk < range.end {
                Some("[heap]")
            } else {
                None
            };
            if let Some(label) = label {
                let _ = write!(out, "                          {label}");
            } else if let Some(path) = mapped_path {
                let _ = write!(out, "                          {path}");
            }
            out.push('\n');
        }

        out
    }

    fn open_synthetic_proc_text(
        &self,
        flags: OFlags,
        contents: alloc::string::String,
    ) -> Result<u32, Errno> {
        use litebox::fs::errors::CreateAnonymousFileError;

        if flags.intersects(OFlags::WRONLY | OFlags::RDWR) {
            return Err(Errno::EACCES);
        }
        if flags.contains(OFlags::DIRECTORY) {
            return Err(Errno::ENOTDIR);
        }

        // Create a seekable in-memory file instead of a pipe.
        // On real Linux, /proc files are seekable (lseek returns 0).
        // Using a pipe breaks programs (like the VS Code Server) that
        // call lseek() on /proc/PID/stat to check seekability.
        let files = self.files.borrow();
        let mut descriptors = self.global.litebox.descriptor_table_mut();

        let read_fd = files
            .fs
            .create_anonymous_file_from_bytes(
                "proc_synthetic",
                litebox::fs::Mode::from_bits_truncate(0o444),
                contents.as_bytes(),
                flags & OFlags::STATUS_FLAGS_MASK,
                &mut *descriptors,
            )
            .map_err(|e| match e {
                CreateAnonymousFileError::NotSupported => Errno::ENOSYS,
                CreateAnonymousFileError::Io | _ => Errno::EIO,
            })?;

        // Apply CLOEXEC if requested.
        if flags.contains(OFlags::CLOEXEC) {
            let None = descriptors.set_fd_metadata(&read_fd, FileDescriptorFlags::FD_CLOEXEC)
            else {
                unreachable!()
            };
        }
        let status = flags & OFlags::STATUS_FLAGS_MASK;
        let None = descriptors.set_entry_metadata(&read_fd, crate::StdioStatusFlags(status)) else {
            unreachable!()
        };
        drop(descriptors);

        let raw_fd = files.insert_raw_fd(read_fd).map_err(|read_fd| {
            let mut descriptors = self.global.litebox.descriptor_table_mut();
            files.fs.close(&read_fd, &mut *descriptors).ok();
            Errno::EMFILE
        })?;
        Ok(u32::try_from(raw_fd).unwrap())
    }

    /// Walk each component of an absolute path, resolving symlinks at every
    /// level (like POSIX `realpath`). Returns `Err(ELOOP)` on symlink
    /// cycles. When a symlink expands, its target components are spliced
    /// into the work queue so intermediate symlinks are also resolved.
    fn canonicalize_path(&self, path: &str) -> Result<String, Errno> {
        let mut resolved = String::from("/");
        let mut hops_remaining: usize = 40;

        // Work queue of components still to process. Symlink expansions
        // splice their target components to the front.
        let mut remaining: alloc::vec::Vec<String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect();
        let mut idx = 0;

        while idx < remaining.len() {
            let component = remaining[idx].clone();
            idx += 1;

            match component.as_str() {
                "" | "." => continue,
                ".." => {
                    if let Some(pos) = resolved[..resolved.len().saturating_sub(1)].rfind('/') {
                        resolved.truncate(pos + 1);
                    }
                    continue;
                }
                _ => {}
            }

            if !resolved.ends_with('/') {
                resolved.push('/');
            }
            resolved.push_str(&component);

            // If this prefix is a symlink, expand it: splice the target's
            // components into the front of `remaining` and restart the
            // outer loop so each new component is individually walked.
            if let Ok(target) = self.do_readlink(&resolved) {
                if hops_remaining == 0 {
                    return Err(Errno::ELOOP);
                }
                hops_remaining -= 1;

                if target.starts_with('/') {
                    resolved = String::from("/");
                } else {
                    let parent_end = resolved.rfind('/').unwrap_or(0).max(1);
                    resolved.truncate(parent_end);
                }

                let tail: alloc::vec::Vec<String> = remaining.drain(idx..).collect();
                remaining.truncate(0);
                remaining.extend(
                    target
                        .split('/')
                        .filter(|c| !c.is_empty())
                        .map(str::to_string),
                );
                remaining.extend(tail);
                idx = 0;
            }
        }

        if resolved.len() > 1 && resolved.ends_with('/') {
            resolved.pop();
        }
        Ok(resolved)
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

    /// Handle syscall `open`
    pub fn sys_open(&self, path: impl path::Arg, flags: OFlags, mode: Mode) -> Result<u32, Errno> {
        let path = self.resolve_path(path)?;

        // Rewrite /proc/<N>/... → /proc/self/... for the current PID,
        // and synthesize /proc/<N>/stat|status|cmdline for known PIDs.
        let path = if let Some(path_str) = path.to_str().ok() {
            if let Some(rewritten) = self.rewrite_proc_pid_to_self(path_str) {
                CString::new(rewritten).map_err(|_| Errno::EINVAL)?
            } else if let Some(pid) = self.proc_pid_if_known(path_str) {
                let sub = self.proc_pid_subpath(path_str);
                match sub {
                    "/stat" => {
                        return self.open_synthetic_proc_text(flags, self.synthetic_proc_stat(pid));
                    }
                    "/status" => {
                        return self
                            .open_synthetic_proc_text(flags, self.synthetic_proc_status(pid));
                    }
                    "/cmdline" => {
                        let data = self.synthetic_proc_cmdline(pid);
                        let text = alloc::string::String::from_utf8_lossy(&data).into_owned();
                        return self.open_synthetic_proc_text(flags, text);
                    }
                    "/comm" => {
                        return self.open_synthetic_proc_text(flags, self.synthetic_proc_comm());
                    }
                    "" => {
                        // open("/proc/<N>") as directory — return EISDIR
                        return Err(Errno::EISDIR);
                    }
                    _ => path, // unhandled subpath, fall through
                }
            } else {
                path
            }
        } else {
            path
        };

        // Do not fall through to the host `/proc/self/*` for identity
        // files: that reports the broker/runner process, not the guest.
        // PROC_SELF.* harness tests cover these diagnostics-facing paths.
        match path.to_str().ok() {
            Some("/proc/self/maps") => {
                return self.open_synthetic_proc_text(flags, self.proc_self_maps_contents());
            }
            Some("/proc/self/stat") => {
                return self.open_synthetic_proc_text(flags, self.synthetic_proc_stat(self.pid));
            }
            Some("/proc/self/status") => {
                return self.open_synthetic_proc_text(flags, self.synthetic_proc_status(self.pid));
            }
            Some("/proc/self/cmdline") => {
                let data = self.synthetic_proc_cmdline(self.pid);
                let text = alloc::string::String::from_utf8_lossy(&data).into_owned();
                return self.open_synthetic_proc_text(flags, text);
            }
            Some("/proc/self/comm") => {
                return self.open_synthetic_proc_text(flags, self.synthetic_proc_comm());
            }
            _ => {}
        }
        // /dev/fd/N and /proc/self/fd/N — open is equivalent to dup(N).
        // Used by bash process substitution: cat <(echo hello) passes
        // /dev/fd/63 as a filename; opening it should dup the pipe fd.
        if let Some(fd_num) = path
            .to_str()
            .ok()
            .and_then(|s| {
                s.strip_prefix("/dev/fd/")
                    .or_else(|| s.strip_prefix("/proc/self/fd/"))
            })
            .and_then(|n| n.parse::<i32>().ok())
        {
            let dup_flags = if flags.contains(OFlags::CLOEXEC) {
                Some(OFlags::CLOEXEC)
            } else {
                None
            };
            return self.sys_dup(fd_num, None, dup_flags);
        }
        let path = if path.to_str().ok() == Some("/proc/self/exe") {
            let exe = self.fs.borrow().exe_path.read().clone();
            if exe.is_empty() {
                return Err(Errno::ENOENT);
            }
            CString::new(exe).map_err(|_| Errno::EINVAL)?
        } else {
            path
        };
        if path.to_str().ok() == Some("/sys/kernel/debug/tracing/trace_marker") {
            return Err(Errno::EACCES);
        }
        let path = if path.to_str().ok() == Some("/dev/tty") {
            if let Some(pty_idx) = *self.process_state.borrow().controlling_pty.lock() {
                CString::new(alloc::format!("/dev/pts/{pty_idx}")).map_err(|_| Errno::EINVAL)?
            } else {
                path
            }
        } else {
            path
        };
        if let Ok(path_str) = path.to_str()
            && let Some(result) = self.open_broker_pty_path(path_str, flags)
        {
            return result;
        }
        let mode = mode & !self.get_umask();
        let mut descriptors = self.global.litebox.descriptor_table_mut();
        let existed_before = if flags.contains(OFlags::CREAT) {
            self.files
                .borrow()
                .fs
                .file_status(&*path, &*descriptors)
                .is_ok()
        } else {
            true
        };
        let file = self
            .files
            .borrow()
            .fs
            .open(&*path, flags - OFlags::CLOEXEC, mode, &mut *descriptors)
            .map_err(Errno::from)?;
        if flags.contains(OFlags::CREAT)
            && !existed_before
            && let Ok(path_str) = path.to_str()
        {
            self.notify_inotify_path(path_str, IN_CREATE, 0);
        }
        let status = flags & OFlags::STATUS_FLAGS_MASK;
        {
            if flags.contains(OFlags::CLOEXEC) {
                let None = descriptors.set_fd_metadata(&file, FileDescriptorFlags::FD_CLOEXEC)
                else {
                    unreachable!()
                };
            }
            // Store access mode + status flags so F_GETFL can return them.
            let None = descriptors.set_entry_metadata(&file, crate::StdioStatusFlags(status))
            else {
                unreachable!()
            };
            if let Ok(path_str) = path.to_str()
                && let Some(source_fd) = host_stdio_source_for_path(path_str)
            {
                let old =
                    descriptors.set_entry_metadata(&file, crate::HostStdioSourceFd(source_fd));
                assert!(old.is_none());
            }
            if let Ok(path_str) = path.to_str()
                && is_host_tty_path(path_str)
            {
                let old = descriptors.set_entry_metadata(&file, crate::HostTtyAlias);
                assert!(old.is_none());
            }
            // Tag fds opened via the host PTY device path (e.g., /dev/pts/156)
            // so that fstat returns the host PTY identity, not the default
            // Device::Tty identity (rdev=0x500). Skip if the fd resolved to a
            // sandbox PTY (major 136) rather than the host tty alias.
            if let Ok(path_str) = path.to_str()
                && is_host_pty_device_path(path_str, self.global.platform)
            {
                let is_sandbox_pty = self
                    .files
                    .borrow()
                    .fs
                    .fd_file_status(&file, &*descriptors)
                    .ok()
                    .and_then(|s| s.node_info.rdev)
                    .is_some_and(|rdev| (rdev.get() >> 8) >= 136);
                if !is_sandbox_pty {
                    let old = descriptors.set_entry_metadata(&file, HostPtyDeviceFd);
                    assert!(old.is_none());
                }
            }
        }
        self.files
            .borrow()
            .fs
            .set_open_status_flags(&file, status, &mut *descriptors)
            .map_err(|_| Errno::EBADF)?;
        drop(descriptors);
        #[cfg(feature = "trace_syscalls")]
        let object_id = file.object_id().as_u64();
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(file).map_err(|file| {
            let mut descriptors = self.global.litebox.descriptor_table_mut();
            files.fs.close(&file, &mut *descriptors).unwrap();
            Errno::EMFILE
        })?;
        #[cfg(feature = "trace_syscalls")]
        if raw_fd <= 20 {
            litebox::log_println!(
                self.global.platform,
                "[FD-TRACE] pid={} open raw_fd={} object_id={} path={:?} flags={:?}",
                self.pid,
                raw_fd,
                object_id,
                path,
                flags,
            );
        }
        let guest_fd = u32::try_from(raw_fd).unwrap();

        if let Ok(s) = path.to_str()
            && (s == "/dev/ptmx" || s.starts_with("/dev/pts/"))
        {
            let rdev = self.pty_rdev_for_raw_fd(&files, raw_fd);
            self.trace_pty_open(s, guest_fd, raw_fd, rdev);
            if s.starts_with("/dev/pts/")
                && let Some(pgid) = self
                    .global
                    .litebox
                    .process_registry()
                    .get_pgid(self.process_id)
            {
                self.global.ensure_pgrp_signal_subscription(pgid.0);
            }
        }

        Ok(guest_fd)
    }

    /// Handle syscall `openat`
    pub fn sys_openat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<u32, Errno> {
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        match fs_path {
            FsPath::Absolute { path } => self.sys_open(path, flags, mode),
            FsPath::Cwd => self.sys_open(get_cwd(), flags, mode),
            FsPath::Fd(_fd) => {
                log_unsupported!("openat with empty path");
                Err(Errno::EINVAL)
            }
            FsPath::FdRelative { fd, path } => {
                let Ok(raw_fd) = usize::try_from(fd) else {
                    return Err(Errno::EBADF);
                };
                let mode = mode & !self.get_umask();
                let status = flags & OFlags::STATUS_FLAGS_MASK;

                let abs_path = self.resolve_dirfd_path(fd, &path).ok();
                let files = self.files.borrow();
                let mut descriptors = self.global.litebox.descriptor_table_mut();
                let file = files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                    crate::RawFdRef::Fs(dirfd) => files
                        .fs
                        .open_at(
                            dirfd,
                            path,
                            flags - OFlags::CLOEXEC,
                            mode,
                            &mut *descriptors,
                        )
                        .map_err(Errno::from),
                    #[cfg(feature = "worker_local_inet")]
                    crate::RawFdRef::Net(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Eventfd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Epoll(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Unix(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::HostPassthroughFd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerPipe(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerSocketPair(_)
                    | crate::RawFdRef::BrokerSocketDgram(_)
                    | crate::RawFdRef::BrokerUnixStream(_)
                    | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerTcpConn(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerPty(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Signalfd(_)
                    | crate::RawFdRef::Inotify(_)
                    | crate::RawFdRef::BrokerInetListener(_)
                    | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                })?;
                let file = file?;
                {
                    if flags.contains(OFlags::CLOEXEC) {
                        let None =
                            descriptors.set_fd_metadata(&file, FileDescriptorFlags::FD_CLOEXEC)
                        else {
                            unreachable!()
                        };
                    }
                    let None =
                        descriptors.set_entry_metadata(&file, crate::StdioStatusFlags(status))
                    else {
                        unreachable!()
                    };
                    if let Some(source_fd) =
                        abs_path.as_deref().and_then(host_stdio_source_for_path)
                    {
                        let old = descriptors
                            .set_entry_metadata(&file, crate::HostStdioSourceFd(source_fd));
                        assert!(old.is_none());
                    }
                    if abs_path.as_deref().is_some_and(is_host_tty_path) {
                        let old = descriptors.set_entry_metadata(&file, crate::HostTtyAlias);
                        assert!(old.is_none());
                    }
                    if abs_path
                        .as_deref()
                        .is_some_and(|p| is_host_pty_device_path(p, self.global.platform))
                    {
                        let is_sandbox_pty = files
                            .fs
                            .fd_file_status(&file, &*descriptors)
                            .ok()
                            .and_then(|s| s.node_info.rdev)
                            .is_some_and(|rdev| (rdev.get() >> 8) >= 136);
                        if !is_sandbox_pty {
                            let old = descriptors.set_entry_metadata(&file, HostPtyDeviceFd);
                            assert!(old.is_none());
                        }
                    }
                }
                files
                    .fs
                    .set_open_status_flags(&file, status, &mut *descriptors)
                    .map_err(|_| Errno::EBADF)?;
                drop(descriptors);
                #[cfg(feature = "trace_syscalls")]
                let object_id = file.object_id().as_u64();
                let guest_raw = files.insert_raw_fd(file).map_err(|file| {
                    let mut descriptors = self.global.litebox.descriptor_table_mut();
                    files.fs.close(&file, &mut *descriptors).unwrap();
                    Errno::EMFILE
                })?;
                #[cfg(feature = "trace_syscalls")]
                if guest_raw <= 20 {
                    litebox::log_println!(
                        self.global.platform,
                        "[FD-TRACE] pid={} openat raw_fd={} object_id={} path={:?} flags={:?}",
                        self.pid,
                        guest_raw,
                        object_id,
                        abs_path.as_deref().unwrap_or("<unknown>"),
                        flags,
                    );
                }
                Ok(u32::try_from(guest_raw).unwrap())
            }
        }
    }

    /// Handle syscall `ftruncate`
    pub(crate) fn sys_ftruncate(&self, fd: i32, length: usize) -> Result<(), Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files
            .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                crate::RawFdRef::Fs(fd) => {
                    let mut descriptors = self.global.litebox.descriptor_table_mut();
                    files
                        .fs
                        .truncate(fd, length, false, &mut *descriptors)
                        .map_err(Errno::from)
                }
                #[cfg(feature = "worker_local_inet")]
                crate::RawFdRef::Net(_fd) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::Eventfd(_fd) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::Epoll(_fd) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::Unix(_fd) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::HostPassthroughFd(_fd) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::BrokerPipe(_fd) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::BrokerSocketPair(_)
                | crate::RawFdRef::BrokerSocketDgram(_)
                | crate::RawFdRef::BrokerUnixStream(_)
                | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::BrokerTcpConn(_fd) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::BrokerPty(_fd) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::Signalfd(_)
                | crate::RawFdRef::Inotify(_)
                | crate::RawFdRef::BrokerInetListener(_)
                | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
            })
            .flatten()
    }

    #[cfg(test)]
    pub(crate) fn sys_rmdir(&self, pathname: impl path::Arg) -> Result<(), Errno> {
        self.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            pathname,
            AtFlags::AT_REMOVEDIR,
        )
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
        if flags.contains(AtFlags::AT_REMOVEDIR) {
            let raw_path = pathname.as_rust_str().map_err(|_| Errno::EINVAL)?;
            Self::validate_removedir_path_str(raw_path)?;
        }

        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        match fs_path {
            FsPath::Absolute { path } => {
                if flags.contains(AtFlags::AT_REMOVEDIR) {
                    let mut descriptors = self.global.litebox.descriptor_table_mut();
                    self.files
                        .borrow()
                        .fs
                        .rmdir(path, &mut *descriptors)
                        .map_err(Errno::from)
                } else {
                    self.files
                        .borrow()
                        .fs
                        .unlink(
                            path.clone(),
                            &mut *self.global.litebox.descriptor_table_mut(),
                        )
                        .map_err(Errno::from)?;
                    if let Ok(path_str) = path.to_str() {
                        self.notify_inotify_path(path_str, IN_DELETE, 0);
                    }
                    Ok(())
                }
            }
            FsPath::Cwd | FsPath::Fd(_) => Err(Errno::EINVAL),
            FsPath::FdRelative { fd, path } => {
                let Ok(raw_fd) = usize::try_from(fd) else {
                    return Err(Errno::EBADF);
                };
                let is_rmdir = flags.contains(AtFlags::AT_REMOVEDIR);

                let files = self.files.borrow();
                files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                    crate::RawFdRef::Fs(dirfd) => {
                        if is_rmdir {
                            // rmdir doesn't have an _at variant yet; resolve manually.
                            // Verify dirfd refers to a directory.
                            let descriptors = self.global.litebox.descriptor_table();
                            let status = files
                                .fs
                                .fd_file_status(dirfd, &*descriptors)
                                .map_err(Errno::from)?;
                            if !matches!(status.file_type, litebox::fs::FileType::Directory) {
                                return Err(Errno::ENOTDIR);
                            }
                            let dir_path = {
                                let descriptors = self.global.litebox.descriptor_table();
                                files.fs.fd_path(dirfd, &*descriptors).ok_or(Errno::EBADF)?
                            };
                            let rel = path.to_str().map_err(|_| Errno::EINVAL)?;
                            let abs = if rel.starts_with('/') {
                                rel.into()
                            } else if dir_path.ends_with('/') {
                                alloc::format!("{dir_path}{rel}")
                            } else {
                                alloc::format!("{dir_path}/{rel}")
                            };
                            let mut descriptors = self.global.litebox.descriptor_table_mut();
                            files.fs.rmdir(abs, &mut *descriptors).map_err(Errno::from)
                        } else {
                            let mut descriptors = self.global.litebox.descriptor_table_mut();
                            files
                                .fs
                                .unlink_at(dirfd, path, &mut *descriptors)
                                .map_err(Errno::from)
                        }
                    }
                    #[cfg(feature = "worker_local_inet")]
                    crate::RawFdRef::Net(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Eventfd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Epoll(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Unix(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::HostPassthroughFd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerPipe(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerSocketPair(_)
                    | crate::RawFdRef::BrokerSocketDgram(_)
                    | crate::RawFdRef::BrokerUnixStream(_)
                    | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerTcpConn(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerPty(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Signalfd(_)
                    | crate::RawFdRef::Inotify(_)
                    | crate::RawFdRef::BrokerInetListener(_)
                    | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                })?
            }
        }
    }

    pub(crate) fn sys_renameat2(
        &self,
        olddirfd: i32,
        oldpath: impl path::Arg,
        newdirfd: i32,
        newpath: impl path::Arg,
        flags: u32,
    ) -> Result<(), Errno> {
        const RENAME_NOREPLACE: u32 = 1;
        const RENAME_EXCHANGE: u32 = 2;
        const RENAME_WHITEOUT: u32 = 4;
        let supported = RENAME_NOREPLACE;
        if flags & !supported != 0 {
            if flags & (RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
                return Err(Errno::EINVAL);
            }
            return Err(Errno::EINVAL);
        }
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let old = FsPath::new(olddirfd, oldpath, get_cwd)?;
        let new = FsPath::new(newdirfd, newpath, get_cwd)?;

        // Resolve both paths to absolute strings, supporting FdRelative.
        let resolve = |fspath: FsPath| -> Result<CString, Errno> {
            match fspath {
                FsPath::Absolute { path } => Ok(path),
                FsPath::Cwd => CString::new(get_cwd()).map_err(|_| Errno::EINVAL),
                FsPath::Fd(_) => Err(Errno::EINVAL),
                FsPath::FdRelative { fd, path } => {
                    let Ok(raw_fd) = usize::try_from(fd) else {
                        return Err(Errno::EBADF);
                    };

                    let files = self.files.borrow();
                    files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                        crate::RawFdRef::Fs(dirfd) => {
                            // Verify dirfd refers to a directory.
                            let descriptors = self.global.litebox.descriptor_table();
                            let status = files
                                .fs
                                .fd_file_status(dirfd, &*descriptors)
                                .map_err(Errno::from)?;
                            if !matches!(status.file_type, litebox::fs::FileType::Directory) {
                                return Err(Errno::ENOTDIR);
                            }
                            let dir_path = {
                                let descriptors = self.global.litebox.descriptor_table();
                                files.fs.fd_path(dirfd, &*descriptors).ok_or(Errno::EBADF)?
                            };
                            let rel = path.to_str().map_err(|_| Errno::EINVAL)?;
                            // Linux returns EBUSY for rename(".") or rename("").
                            if rel.is_empty() || rel == "." {
                                return Err(Errno::EBUSY);
                            }
                            let abs = if rel.starts_with('/') {
                                rel.into()
                            } else if dir_path.ends_with('/') {
                                alloc::format!("{dir_path}{rel}")
                            } else {
                                alloc::format!("{dir_path}/{rel}")
                            };
                            CString::new(abs).map_err(|_| Errno::EINVAL)
                        }
                        #[cfg(feature = "worker_local_inet")]
                        crate::RawFdRef::Net(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                        crate::RawFdRef::Eventfd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                        crate::RawFdRef::Epoll(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                        crate::RawFdRef::Unix(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                        crate::RawFdRef::HostPassthroughFd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                        crate::RawFdRef::BrokerPipe(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                        crate::RawFdRef::BrokerSocketPair(_)
                        | crate::RawFdRef::BrokerSocketDgram(_)
                        | crate::RawFdRef::BrokerUnixStream(_)
                        | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                        crate::RawFdRef::BrokerTcpConn(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                        crate::RawFdRef::BrokerPty(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                        crate::RawFdRef::Signalfd(_)
                        | crate::RawFdRef::Inotify(_)
                        | crate::RawFdRef::BrokerInetListener(_)
                        | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                        crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    })?
                }
            }
        };
        let old_path = resolve(old)?;
        let new_path = resolve(new)?;
        if flags & RENAME_NOREPLACE != 0 {
            // Check if target exists — RENAME_NOREPLACE fails with EEXIST.
            let descriptors = self.global.litebox.descriptor_table();
            if self
                .files
                .borrow()
                .fs
                .file_status(&*new_path, &*descriptors)
                .is_ok()
            {
                return Err(Errno::EEXIST);
            }
        }
        {
            let files = self.files.borrow();
            let mut descriptors = self.global.litebox.descriptor_table_mut();
            files
                .fs
                .rename(old_path.clone(), new_path.clone(), &mut *descriptors)
                .map_err(Errno::from)?;
        }
        let cookie = Self::next_inotify_cookie();
        if let Ok(old_path) = old_path.to_str() {
            self.notify_inotify_path(old_path, IN_MOVED_FROM, cookie);
        }
        if let Ok(new_path) = new_path.to_str() {
            self.notify_inotify_path(new_path, IN_MOVED_TO, cookie);
        }
        Ok(())
    }

    fn broker_pty_background_read_sigttin(
        &self,
        entry: &super::broker_pty::BrokerPtyFd<Platform>,
    ) -> Result<(), Errno> {
        if entry.is_master()
            || *self.process_state.borrow().controlling_pty.lock() != Some(entry.pty_id())
        {
            return Ok(());
        }
        let caller_pgid = i32::try_from(self.sys_getpgid(0)?).map_err(|_| Errno::EINVAL)?;
        let payload = entry.ioctl(PtyIoctlOp::Tiocgpgrp, &[])?;
        let Some(bytes) = payload.get(..4) else {
            return Err(Errno::EIO);
        };
        let foreground_pgrp = i32::from_le_bytes(bytes.try_into().map_err(|_| Errno::EIO)?);
        if foreground_pgrp == caller_pgid
            || self.is_signal_blocked_or_ignored(litebox_common_linux::signal::Signal::SIGTTIN)
        {
            return Ok(());
        }
        self.global.deliver_signal_to_process_group(
            caller_pgid,
            litebox_common_linux::signal::Signal::SIGTTIN,
        )?;
        Err(Errno::EINTR)
    }

    fn broker_pty_background_sigttou(
        &self,
        entry: &super::broker_pty::BrokerPtyFd<Platform>,
        require_tostop: bool,
    ) -> Result<(), Errno> {
        if entry.is_master()
            || *self.process_state.borrow().controlling_pty.lock() != Some(entry.pty_id())
        {
            return Ok(());
        }
        if require_tostop {
            let payload = entry.ioctl(PtyIoctlOp::Tcgets, &[])?;
            let Some(bytes) = payload.get(12..16) else {
                return Err(Errno::EIO);
            };
            let c_lflag = u32::from_le_bytes(bytes.try_into().map_err(|_| Errno::EIO)?);
            if c_lflag & litebox_common_linux::TOSTOP == 0 {
                return Ok(());
            }
        }

        let caller_pgid = i32::try_from(self.sys_getpgid(0)?).map_err(|_| Errno::EINVAL)?;
        let payload = entry.ioctl(PtyIoctlOp::Tiocgpgrp, &[])?;
        let Some(bytes) = payload.get(..4) else {
            return Err(Errno::EIO);
        };
        let foreground_pgrp = i32::from_le_bytes(bytes.try_into().map_err(|_| Errno::EIO)?);
        if foreground_pgrp == caller_pgid
            || self.is_signal_blocked_or_ignored(litebox_common_linux::signal::Signal::SIGTTOU)
        {
            return Ok(());
        }

        let pgid = litebox::process::ProcessGroupId(
            u32::try_from(caller_pgid).map_err(|_| Errno::EINVAL)?,
        );
        if self
            .global
            .litebox
            .process_registry()
            .is_process_group_orphaned(pgid)
            .ok_or(Errno::ESRCH)?
        {
            return Ok(());
        }

        self.global.deliver_signal_to_process_group(
            caller_pgid,
            litebox_common_linux::signal::Signal::SIGTTOU,
        )?;
        Err(Errno::EINTR)
    }

    /// Handle syscall `read`
    ///
    /// `offset` is an optional offset to read from. If `None`, it will read from the current file position.
    /// If `Some`, it will read from the specified offset without changing the current file position.
    pub fn sys_read(&self, fd: i32, buf: &mut [u8], offset: Option<usize>) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };

        // Netlink socket: return buffered data, 0 if empty.
        if let Some(nl) = self.netlink_sockets.borrow_mut().get_mut(&(raw_fd as u32)) {
            if !nl.has_data() {
                return Ok(0);
            }
            return Ok(nl.recv(buf));
        }

        let files = self.files.borrow();

        if let Ok(sfd) = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::signalfd::SignalfdSubsystem>(raw_fd)
        {
            let handle = self
                .global
                .litebox
                .descriptor_table()
                .entry_handle(&sfd)
                .ok_or(Errno::EBADF)?;
            if buf.len() < 128 {
                return Err(Errno::EINVAL);
            }
            loop {
                self.drain_cross_process_signals();
                if let Some(payload) = handle.with_entry(|file| file.read_siginfo())? {
                    let n = payload.len().min(buf.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    return Ok(n);
                }
                if handle.with_entry(|file| file.get_status().contains(OFlags::NONBLOCK)) {
                    return Err(Errno::EAGAIN);
                }
                core::hint::spin_loop();
            }
        }

        if let Ok(ptyfd) = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(raw_fd)
        {
            let handle = self
                .global
                .litebox
                .descriptor_table()
                .entry_handle(&ptyfd)
                .ok_or(Errno::EBADF)?;
            loop {
                match handle.with_entry(|entry| {
                    self.broker_pty_background_read_sigttin(entry)?;
                    entry.read(&self.wait_cx(), buf)
                }) {
                    Err(Errno::EINTR)
                        if !self.is_suspended() && self.pending_signals_all_ignored() =>
                    {
                        self.drain_ignored_pending();
                    }
                    result => return result,
                }
            }
        }

        // Phase F: broker-backed socketpair early-dispatch.
        // BrokerSocketPairSubsystem isn't routed through run_on_raw_fd
        // (which would require adding a 9th closure to all 43 call
        // sites). Handle it here before the generic dispatch.
        if let Ok(spfd) =
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<super::broker_socketpair::BrokerSocketPairSubsystem>(raw_fd)
        {
            let handle = self
                .global
                .litebox
                .descriptor_table()
                .entry_handle(&spfd)
                .ok_or(Errno::EBADF)?;
            loop {
                match handle.with_entry(|entry| entry.read(&self.wait_cx(), buf)) {
                    Err(Errno::EINTR)
                        if !self.is_suspended() && self.pending_signals_all_ignored() =>
                    {
                        self.drain_ignored_pending();
                    }
                    result => return result,
                }
            }
        }

        if let Ok(usfd) =
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<super::broker_unix_stream::BrokerUnixStreamSubsystem>(raw_fd)
        {
            let handle = self
                .global
                .litebox
                .descriptor_table()
                .entry_handle(&usfd)
                .ok_or(Errno::EBADF)?;
            let payload =
                handle.with_entry(|entry| entry.recv(&self.wait_cx(), buf.len() as u32))?;
            let n = payload.len().min(buf.len());
            buf[..n].copy_from_slice(&payload[..n]);
            return Ok(n);
        }

        if let Ok(inofd) = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::inotify::InotifySubsystem>(raw_fd)
        {
            let handle = self
                .global
                .litebox
                .descriptor_table()
                .entry_handle(&inofd)
                .ok_or(Errno::EBADF)?;
            return handle.with_entry(|file| file.read(buf));
        }

        if let Some(instance) = files.inotify_instances.lock().get(&raw_fd).cloned() {
            let (n, eventfd) = {
                let mut state = instance.lock();
                if state.events.is_empty() {
                    self.rescan_inotify_instance(&mut state);
                }
                let n = state.read_events(buf)?;
                (n, state.eventfd.clone())
            };
            let _ = eventfd.with_entry(|file| file.read(&self.wait_cx()));
            return Ok(n);
        }

        // We need to do this cell dance because otherwise Rust can't recognize that the two
        // closures are mutually exclusive.
        let buf: core::cell::RefCell<&mut [u8]> = core::cell::RefCell::new(buf);
        files
            .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                crate::RawFdRef::Fs(fd) => {
                    let _position_guard = if offset.is_none()
                        && matches!(
                            {
                                let descriptors = self.global.litebox.descriptor_table();
                                files.fs.fd_file_status(fd, &*descriptors)
                            },
                            Ok(status) if status.file_type == litebox::fs::FileType::RegularFile
                        ) {
                        Some(files.file_position_lock.lock())
                    } else {
                        None
                    };
                    let result = {
                        let descriptors = self.global.litebox.descriptor_table();
                        files
                            .fs
                            .read(fd, &mut buf.borrow_mut(), offset, &*descriptors)
                            .map_err(Errno::from)
                    };
                    let descriptors = self.global.litebox.descriptor_table();
                    let nonblocking = descriptors
                        .with_metadata(fd, |crate::StdioStatusFlags(flags)| {
                            flags.contains(OFlags::NONBLOCK)
                        })
                        .unwrap_or(false);
                    // If the read returned EAGAIN (no data), check whether
                    // this fd is a pollable device that wants blocking reads
                    // (e.g. PTY slave). Non-blocking pollables (PTY master)
                    // return EAGAIN immediately for epoll-driven callers.
                    if let Err(Errno::EAGAIN) = result
                        && !nonblocking
                        && let Some(pollable) = files.fs.get_io_pollable(fd, &*descriptors)
                        && pollable.should_block_read()
                    {
                        drop(descriptors);
                        loop {
                            // vfork parking needs blocked host-side loops
                            // to break out so prepare_to_run_guest() can
                            // park the thread.
                            if self.is_exiting() || self.is_suspended() {
                                return Err(Errno::EINTR);
                            }
                            let events = pollable.check_io_events();
                            if events.contains(Events::HUP) {
                                return Ok(0); // EOF — master closed
                            }
                            if events.contains(Events::IN) {
                                let descriptors = self.global.litebox.descriptor_table();
                                match files.fs.read(
                                    fd,
                                    &mut buf.borrow_mut(),
                                    offset,
                                    &*descriptors,
                                ) {
                                    Ok(n) => return Ok(n),
                                    Err(litebox::fs::errors::ReadError::WouldBlock) => {
                                        core::hint::spin_loop();
                                        continue;
                                    }
                                    Err(e) => return Err(Errno::from(e)),
                                }
                            }
                            core::hint::spin_loop();
                        }
                    }
                    result
                }
                #[cfg(feature = "worker_local_inet")]
                crate::RawFdRef::Net(fd) => self.global.receive(
                    &self.wait_cx(),
                    fd,
                    &mut buf.borrow_mut(),
                    litebox_common_linux::ReceiveFlags::empty(),
                    None,
                ),
                crate::RawFdRef::Eventfd(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        let buf = &mut buf.borrow_mut();
                        if buf.len() < size_of::<u64>() {
                            return Err(Errno::EINVAL);
                        }
                        let value = file.read(&self.wait_cx())?;
                        buf[..size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
                        Ok(size_of::<u64>())
                    })
                }
                crate::RawFdRef::Epoll(_fd) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::Unix(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        file.recvfrom(
                            &self.wait_cx(),
                            &mut buf.borrow_mut(),
                            litebox_common_linux::ReceiveFlags::empty(),
                            None,
                            &mut Vec::new(),
                            &mut Vec::new(),
                        )
                    })
                }
                crate::RawFdRef::HostPassthroughFd(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(
                        |entry: &super::host_passthrough_fd::HostPassthroughFdEntry| {
                            super::host_passthrough_fd::read_host_passthrough_fd(
                                self.global.platform,
                                entry,
                                &mut buf.borrow_mut(),
                            )
                        },
                    )
                }
                crate::RawFdRef::BrokerPipe(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    // Delayed fork can resume the parent after the child has already
                    // written and closed; preserve the first nonblocking read's EAGAIN.
                    if !buf.borrow().is_empty()
                        && self
                            .global
                            .litebox
                            .descriptor_table()
                            .with_metadata(fd, |crate::PipeNonblockEagainOnce(enabled)| *enabled)
                            .unwrap_or(false)
                    {
                        let completed_with_data = handle.with_entry(|entry| {
                            let events = entry.check_io_events();
                            events.contains(Events::IN) && events.contains(Events::HUP)
                        });
                        let _ = consume_pipe_eagain_once(self, fd);
                        if completed_with_data {
                            return Err(Errno::EAGAIN);
                        }
                    }
                    loop {
                        match handle
                            .with_entry(|entry| entry.read(&self.wait_cx(), &mut buf.borrow_mut()))
                        {
                            Err(Errno::EINTR)
                                if !self.is_suspended() && self.pending_signals_all_ignored() =>
                            {
                                self.drain_ignored_pending();
                            }
                            result => return result,
                        }
                    }
                }
                crate::RawFdRef::BrokerSocketPair(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| entry.read(&self.wait_cx(), &mut buf.borrow_mut()))
                }
                crate::RawFdRef::BrokerTcpConn(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| entry.read(&self.wait_cx(), &mut buf.borrow_mut()))
                }
                crate::RawFdRef::BrokerInetDgram(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| {
                        let (_peer, payload, _flags) =
                            entry.recvfrom(&self.wait_cx(), buf.borrow().len() as u32)?;
                        let copied = buf.borrow().len().min(payload.len());
                        buf.borrow_mut()[..copied].copy_from_slice(&payload[..copied]);
                        Ok(copied)
                    })
                }
                crate::RawFdRef::BrokerPty(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| {
                        self.broker_pty_background_read_sigttin(entry)?;
                        entry.read(&self.wait_cx(), &mut buf.borrow_mut())
                    })
                }
                crate::RawFdRef::Signalfd(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| entry.read(&mut buf.borrow_mut()))
                }
                crate::RawFdRef::Inotify(_fd) => Err(Errno::EINVAL),
                crate::RawFdRef::BrokerInetListener(_fd) => Err(Errno::EINVAL),
                crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerUnixStream(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerInetRaw(_fd) => Err(Errno::EINVAL),
            })
            .flatten()
    }

    /// Handle syscall `write`
    ///
    /// `offset` is an optional offset to write to. If `None`, it will write to the current file position.
    /// If `Some`, it will write to the specified offset without changing the current file position.
    pub fn sys_write(&self, fd: i32, buf: &[u8], offset: Option<usize>) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();

        if let Ok(ptyfd) = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(raw_fd)
        {
            let handle = self
                .global
                .litebox
                .descriptor_table()
                .entry_handle(&ptyfd)
                .ok_or(Errno::EBADF)?;
            let res = handle.with_entry(|entry| {
                if !buf.is_empty() {
                    self.broker_pty_background_sigttou(entry, true)?;
                }
                entry.write(&self.wait_cx(), buf)
            });
            if let Err(Errno::EPIPE) = res {
                self.send_signal(
                    litebox_common_linux::signal::Signal::SIGPIPE,
                    siginfo_kernel(litebox_common_linux::signal::Signal::SIGPIPE),
                );
            }
            return res;
        }

        // Phase F: broker-backed socketpair early-dispatch (mirror of sys_read).
        if let Ok(spfd) =
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<super::broker_socketpair::BrokerSocketPairSubsystem>(raw_fd)
        {
            let handle = self
                .global
                .litebox
                .descriptor_table()
                .entry_handle(&spfd)
                .ok_or(Errno::EBADF)?;
            return handle.with_entry(|entry| entry.write(&self.wait_cx(), buf));
        }

        if let Ok(usfd) =
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<super::broker_unix_stream::BrokerUnixStreamSubsystem>(raw_fd)
        {
            let handle = self
                .global
                .litebox
                .descriptor_table()
                .entry_handle(&usfd)
                .ok_or(Errno::EBADF)?;
            return handle.with_entry(|entry| entry.send(&self.wait_cx(), buf));
        }

        let res = files
            .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                crate::RawFdRef::Fs(fd) => {
                    #[cfg(feature = "trace_syscalls")]
                    if raw_fd <= 2 {
                        litebox::log_println!(
                            self.global.platform,
                            "[WRITE-FS-TRACE] pid={} fd={} len={}",
                            self.pid,
                            raw_fd,
                            buf.len(),
                        );
                    }
                    let _position_guard = if offset.is_none()
                        && matches!(
                            {
                                let descriptors = self.global.litebox.descriptor_table();
                                files.fs.fd_file_status(fd, &*descriptors)
                            },
                            Ok(status) if status.file_type == litebox::fs::FileType::RegularFile
                        ) {
                        Some(files.file_position_lock.lock())
                    } else {
                        None
                    };
                    let (result, modified_path) = {
                        let mut descriptors = self.global.litebox.descriptor_table_mut();
                        let result = files
                            .fs
                            .write(fd, buf, offset, &mut *descriptors)
                            .map_err(Errno::from);
                        let modified_path = if matches!(result, Ok(n) if n > 0) {
                            files.fs.fd_path(fd, &*descriptors)
                        } else {
                            None
                        };
                        (result, modified_path)
                    };
                    if let Some(path) = modified_path {
                        self.notify_inotify_path(&path, IN_MODIFY, 0);
                    }
                    result
                }
                #[cfg(feature = "worker_local_inet")]
                crate::RawFdRef::Net(fd) => self.global.sendto(
                    &self.wait_cx(),
                    fd,
                    buf,
                    litebox_common_linux::SendFlags::empty(),
                    None,
                ),
                crate::RawFdRef::Eventfd(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        let value: u64 = u64::from_le_bytes(
                            buf[..size_of::<u64>()]
                                .try_into()
                                .map_err(|_| Errno::EINVAL)?,
                        );
                        file.write(&self.wait_cx(), value)
                    })
                }
                crate::RawFdRef::Epoll(_fd) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::Unix(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        file.sendto(
                            self,
                            buf,
                            litebox_common_linux::SendFlags::empty(),
                            None,
                            Vec::new(),
                            Vec::new(),
                        )
                    })
                }
                crate::RawFdRef::HostPassthroughFd(fd) => {
                    #[cfg(feature = "trace_syscalls")]
                    if raw_fd <= 2 {
                        litebox::log_println!(
                            self.global.platform,
                            "[WRITE-HOSTPIPE] pid={} fd={} len={}",
                            self.pid,
                            raw_fd,
                            buf.len(),
                        );
                    }
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(
                        |entry: &super::host_passthrough_fd::HostPassthroughFdEntry| {
                            super::host_passthrough_fd::write_host_passthrough_fd(
                                self.global.platform,
                                entry,
                                buf,
                            )
                        },
                    )
                }
                crate::RawFdRef::BrokerPipe(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| entry.write(&self.wait_cx(), buf))
                }
                crate::RawFdRef::BrokerSocketPair(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| entry.write(&self.wait_cx(), buf))
                }
                crate::RawFdRef::BrokerTcpConn(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| entry.write(&self.wait_cx(), buf))
                }
                crate::RawFdRef::BrokerPty(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| {
                        if !buf.is_empty() {
                            self.broker_pty_background_sigttou(entry, true)?;
                        }
                        entry.write(&self.wait_cx(), buf)
                    })
                }
                crate::RawFdRef::Signalfd(_)
                | crate::RawFdRef::Inotify(_)
                | crate::RawFdRef::BrokerInetListener(_)
                | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerUnixStream(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
            })
            .flatten();
        if let Err(Errno::EPIPE) = res {
            self.send_signal(
                litebox_common_linux::signal::Signal::SIGPIPE,
                siginfo_kernel(litebox_common_linux::signal::Signal::SIGPIPE),
            );
        }
        res
    }

    fn copy_file_range_explicit_offset(&self, offset: MutPtr<i64>) -> Result<Option<usize>, Errno> {
        if offset.as_usize() == 0 {
            return Ok(None);
        }
        let pos = offset.read_at_offset(0).ok_or(Errno::EFAULT)?;
        Ok(Some(usize::try_from(pos).map_err(|_| Errno::EINVAL)?))
    }

    fn finish_copy_file_range_explicit_offset(
        &self,
        offset: MutPtr<i64>,
        pos: Option<usize>,
    ) -> Result<(), Errno> {
        let Some(pos) = pos else {
            return Ok(());
        };
        let pos = i64::try_from(pos).map_err(|_| Errno::EOVERFLOW)?;
        offset.write_at_offset(0, pos).ok_or(Errno::EFAULT)?;
        Ok(())
    }

    fn regular_file_open_flags(&self, typed_fd: &TypedFd<FS>) -> OFlags {
        self.global
            .litebox
            .descriptor_table()
            .with_metadata(typed_fd, |crate::StdioStatusFlags(flags)| *flags)
            .unwrap_or(OFlags::empty())
    }

    fn validate_regular_file_typed_fd(
        &self,
        files: &FilesState<FS>,
        typed_fd: &TypedFd<FS>,
        need_read: bool,
        need_write: bool,
    ) -> Result<litebox::fs::FileStatus, Errno> {
        let descriptors = self.global.litebox.descriptor_table();
        let status = files
            .fs
            .fd_file_status(typed_fd, &*descriptors)
            .map_err(Errno::from)?;
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match status.file_type {
            litebox::fs::FileType::RegularFile => {}
            litebox::fs::FileType::Directory => return Err(Errno::EISDIR),
            _ => return Err(Errno::EINVAL),
        }
        let open_flags = self.regular_file_open_flags(typed_fd);
        if open_flags.contains(OFlags::PATH) {
            return Err(Errno::EBADF);
        }
        let access = open_flags & (OFlags::WRONLY | OFlags::RDWR);
        if need_read && access == OFlags::WRONLY {
            return Err(Errno::EBADF);
        }
        if need_write && access == OFlags::empty() {
            return Err(Errno::EBADF);
        }
        Ok(status)
    }

    pub fn sys_sendfile(
        &self,
        out_fd: i32,
        in_fd: i32,
        offset: MutPtr<i64>,
        count: usize,
    ) -> Result<usize, Errno> {
        let mut explicit_pos = self.copy_file_range_explicit_offset(offset)?;
        let mut copied = 0usize;
        let mut buf = vec![0u8; count.min(super::super::MAX_KERNEL_BUF_SIZE).min(16 * 1024)];

        while copied < count {
            let chunk_len = core::cmp::min(count - copied, buf.len());
            let read = match self.sys_read(in_fd, &mut buf[..chunk_len], explicit_pos) {
                Ok(n) => n,
                Err(err) if copied == 0 => return Err(err),
                Err(_) => break,
            };
            if read == 0 {
                break;
            }
            self.park_if_deferred();

            let mut written = 0usize;
            while written < read {
                let wrote = match self.sys_write(out_fd, &buf[written..read], None) {
                    Ok(0) if copied == 0 && written == 0 => {
                        if explicit_pos.is_none() {
                            self.sys_lseek(
                                in_fd,
                                -isize::try_from(read).map_err(|_| Errno::EOVERFLOW)?,
                                SeekWhence::RelativeToCurrentOffset,
                            )?;
                        }
                        return Err(Errno::EIO);
                    }
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(err) if copied == 0 && written == 0 => {
                        if explicit_pos.is_none() {
                            self.sys_lseek(
                                in_fd,
                                -isize::try_from(read).map_err(|_| Errno::EOVERFLOW)?,
                                SeekWhence::RelativeToCurrentOffset,
                            )?;
                        }
                        return Err(err);
                    }
                    Err(_) => break,
                };
                written = written.checked_add(wrote).ok_or(Errno::EOVERFLOW)?;
                self.park_if_deferred();
            }

            if explicit_pos.is_none() && written < read {
                self.sys_lseek(
                    in_fd,
                    -isize::try_from(read - written).map_err(|_| Errno::EOVERFLOW)?,
                    SeekWhence::RelativeToCurrentOffset,
                )?;
            }
            copied = copied.checked_add(written).ok_or(Errno::EOVERFLOW)?;
            if let Some(pos) = explicit_pos.as_mut() {
                *pos = pos.checked_add(written).ok_or(Errno::EOVERFLOW)?;
            }
            if written < read {
                break;
            }
        }

        self.finish_copy_file_range_explicit_offset(offset, explicit_pos)?;
        Ok(copied)
    }

    pub fn sys_copy_file_range(
        &self,
        fd_in: i32,
        off_in: MutPtr<i64>,
        fd_out: i32,
        off_out: MutPtr<i64>,
        len: usize,
        flags: u32,
    ) -> Result<usize, Errno> {
        if flags != 0 {
            return Err(Errno::EINVAL);
        }
        let mut explicit_in_pos = self.copy_file_range_explicit_offset(off_in)?;
        let explicit_out_pos = self.copy_file_range_explicit_offset(off_out)?;
        let raw_fd_in = usize::try_from(fd_in).map_err(|_| Errno::EBADF)?;
        let raw_fd_out = usize::try_from(fd_out).map_err(|_| Errno::EBADF)?;
        let files = self.files.borrow();
        let (src_fd, dst_fd) = {
            let rds = files.raw_descriptor_store.read();
            let capture_fs_fd = |raw_fd| match rds.fd_from_raw_integer::<FS>(raw_fd) {
                Ok(fd) => Ok(fd),
                Err(ErrRawIntFd::NotFound) => Err(Errno::EBADF),
                Err(ErrRawIntFd::InvalidSubsystem) => Err(Errno::EINVAL),
            };
            (capture_fs_fd(raw_fd_in)?, capture_fs_fd(raw_fd_out)?)
        };
        let src_status = self.validate_regular_file_typed_fd(&files, &src_fd, true, false)?;
        let dst_status = self.validate_regular_file_typed_fd(&files, &dst_fd, false, true)?;
        if self
            .regular_file_open_flags(&dst_fd)
            .contains(OFlags::APPEND)
        {
            return Err(Errno::EBADF);
        }

        let use_position_lock = explicit_in_pos.is_none() || explicit_out_pos.is_none();
        let park_during_copy = !use_position_lock;
        let (copied, explicit_in_pos, out_pos) = {
            // Keep implicit-offset copies serialized against other regular-file
            // I/O on the same shared file description, but never park while
            // holding that mutex or vfork parking can deadlock on it.
            let _position_guard = use_position_lock.then(|| files.file_position_lock.lock());
            let start_in = explicit_in_pos.unwrap_or({
                let descriptors = self.global.litebox.descriptor_table();
                files
                    .fs
                    .seek(
                        &*src_fd,
                        0,
                        SeekWhence::RelativeToCurrentOffset,
                        &*descriptors,
                    )
                    .map_err(Errno::from)?
            });
            let start_out = explicit_out_pos.unwrap_or({
                let descriptors = self.global.litebox.descriptor_table();
                files
                    .fs
                    .seek(
                        &*dst_fd,
                        0,
                        SeekWhence::RelativeToCurrentOffset,
                        &*descriptors,
                    )
                    .map_err(Errno::from)?
            });
            let same_file = src_status.node_info.dev == dst_status.node_info.dev
                && src_status.node_info.ino == dst_status.node_info.ino;
            let copy_len = core::cmp::min(len, src_status.size.saturating_sub(start_in));
            start_in.checked_add(len).ok_or(Errno::EOVERFLOW)?;
            start_out.checked_add(len).ok_or(Errno::EOVERFLOW)?;
            if same_file {
                let in_end = start_in.checked_add(copy_len).ok_or(Errno::EOVERFLOW)?;
                let out_end = start_out.checked_add(copy_len).ok_or(Errno::EOVERFLOW)?;
                if start_in < out_end && start_out < in_end {
                    return Err(Errno::EINVAL);
                }
            }

            let mut copied = 0usize;
            let mut buf = [0u8; 16 * 1024];
            let mut out_pos = start_out;
            while copied < copy_len {
                let chunk_len = core::cmp::min(copy_len - copied, buf.len());
                let read = match {
                    let descriptors = self.global.litebox.descriptor_table();
                    files
                        .fs
                        .read(
                            &*src_fd,
                            &mut buf[..chunk_len],
                            explicit_in_pos,
                            &*descriptors,
                        )
                        .map_err(Errno::from)
                } {
                    Ok(n) => n,
                    Err(err) if copied == 0 => return Err(err),
                    Err(_) => break,
                };
                if read == 0 {
                    break;
                }
                if park_during_copy {
                    self.park_if_deferred();
                }

                let mut written = 0usize;
                let mut stop_after_chunk = false;
                while written < read {
                    let wrote = match {
                        let mut descriptors = self.global.litebox.descriptor_table_mut();
                        files
                            .fs
                            .write(
                                &*dst_fd,
                                &buf[written..read],
                                Some(out_pos),
                                &mut *descriptors,
                            )
                            .map_err(Errno::from)
                    } {
                        Ok(0) if copied == 0 && written == 0 => {
                            if explicit_in_pos.is_none() {
                                let descriptors = self.global.litebox.descriptor_table();
                                files
                                    .fs
                                    .seek(
                                        &*src_fd,
                                        -isize::try_from(read).map_err(|_| Errno::EOVERFLOW)?,
                                        SeekWhence::RelativeToCurrentOffset,
                                        &*descriptors,
                                    )
                                    .map_err(Errno::from)?;
                            }
                            return Err(Errno::EIO);
                        }
                        Ok(0) => {
                            stop_after_chunk = true;
                            break;
                        }
                        Ok(n) => n,
                        Err(err) if copied == 0 && written == 0 => {
                            if explicit_in_pos.is_none() {
                                let descriptors = self.global.litebox.descriptor_table();
                                files
                                    .fs
                                    .seek(
                                        &*src_fd,
                                        -isize::try_from(read).map_err(|_| Errno::EOVERFLOW)?,
                                        SeekWhence::RelativeToCurrentOffset,
                                        &*descriptors,
                                    )
                                    .map_err(Errno::from)?;
                            }
                            return Err(err);
                        }
                        Err(_) => {
                            stop_after_chunk = true;
                            break;
                        }
                    };
                    written = written.checked_add(wrote).ok_or(Errno::EOVERFLOW)?;
                    out_pos = out_pos.checked_add(wrote).ok_or(Errno::EOVERFLOW)?;
                    if explicit_out_pos.is_none() {
                        let descriptors = self.global.litebox.descriptor_table();
                        files
                            .fs
                            .seek(
                                &*dst_fd,
                                isize::try_from(out_pos).map_err(|_| Errno::EOVERFLOW)?,
                                SeekWhence::RelativeToBeginning,
                                &*descriptors,
                            )
                            .map_err(Errno::from)?;
                    }
                    if park_during_copy {
                        self.park_if_deferred();
                    }
                }

                if explicit_in_pos.is_none() && written < read {
                    let descriptors = self.global.litebox.descriptor_table();
                    files
                        .fs
                        .seek(
                            &*src_fd,
                            -isize::try_from(read - written).map_err(|_| Errno::EOVERFLOW)?,
                            SeekWhence::RelativeToCurrentOffset,
                            &*descriptors,
                        )
                        .map_err(Errno::from)?;
                }
                copied = copied.checked_add(written).ok_or(Errno::EOVERFLOW)?;
                if let Some(pos) = explicit_in_pos.as_mut() {
                    *pos = pos.checked_add(written).ok_or(Errno::EOVERFLOW)?;
                }
                if written < read || stop_after_chunk {
                    break;
                }
            }
            (copied, explicit_in_pos, out_pos)
        };

        self.park_if_deferred();
        self.finish_copy_file_range_explicit_offset(off_in, explicit_in_pos)?;
        self.finish_copy_file_range_explicit_offset(off_out, explicit_out_pos.map(|_| out_pos))?;
        Ok(copied)
    }

    /// Handle syscall `pread64`
    pub fn sys_pread64(&self, fd: i32, buf: &mut [u8], offset: i64) -> Result<usize, Errno> {
        let pos = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.sys_read(fd, buf, Some(pos))
    }

    /// Handle syscall `pwrite64`
    pub fn sys_pwrite64(&self, fd: i32, buf: &[u8], offset: i64) -> Result<usize, Errno> {
        let pos = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.sys_write(fd, buf, Some(pos))
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

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `lseek`
    pub fn sys_lseek(&self, fd: i32, offset: isize, whence: SeekWhence) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files
            .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                crate::RawFdRef::Fs(fd) => {
                    let _position_guard = if matches!(
                        {
                            let descriptors = self.global.litebox.descriptor_table();
                            files.fs.fd_file_status(fd, &*descriptors)
                        },
                        Ok(status) if status.file_type == litebox::fs::FileType::RegularFile
                    ) {
                        Some(files.file_position_lock.lock())
                    } else {
                        None
                    };
                    let descriptors = self.global.litebox.descriptor_table();
                    files
                        .fs
                        .seek(fd, offset, whence, &*descriptors)
                        .map_err(Errno::from)
                }
                #[cfg(feature = "worker_local_inet")]
                crate::RawFdRef::Net(_) => Err(Errno::ESPIPE), // real Linux: ESPIPE for non-seekable fd
                crate::RawFdRef::Eventfd(_) => Err(Errno::ESPIPE), // real Linux: ESPIPE for non-seekable fd
                crate::RawFdRef::Epoll(_) => Err(Errno::ESPIPE), // real Linux: ESPIPE for non-seekable fd
                crate::RawFdRef::Unix(_) => Err(Errno::ESPIPE), // real Linux: ESPIPE for non-seekable fd
                crate::RawFdRef::HostPassthroughFd(_) => Err(Errno::ESPIPE), // real Linux: ESPIPE for non-seekable fd
                crate::RawFdRef::BrokerPipe(_) => Err(Errno::ESPIPE), // real Linux: ESPIPE for non-seekable fd
                crate::RawFdRef::BrokerSocketPair(_)
                | crate::RawFdRef::BrokerSocketDgram(_)
                | crate::RawFdRef::BrokerUnixStream(_)
                | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ESPIPE), // real Linux: ESPIPE for non-seekable fd
                crate::RawFdRef::BrokerTcpConn(_) => Err(Errno::ESPIPE), // real Linux: ESPIPE for non-seekable fd
                crate::RawFdRef::BrokerPty(_) => Err(Errno::ESPIPE), // real Linux: ESPIPE for non-seekable fd
                crate::RawFdRef::Signalfd(_)
                | crate::RawFdRef::Inotify(_)
                | crate::RawFdRef::BrokerInetListener(_)
                | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::ESPIPE), // real Linux: ESPIPE for non-seekable fd
                crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::ESPIPE), // real Linux: ESPIPE for non-seekable fd
            })
            .flatten()
    }

    pub(crate) fn install_brokerfile_bridge_fd(
        &self,
        guest_fd: usize,
        path: &str,
        position: usize,
        status_flags_bits: u32,
    ) -> Result<(), Errno> {
        let status_flags = OFlags::from_bits_retain(status_flags_bits) & OFlags::STATUS_FLAGS_MASK;
        let files = self.files.borrow();
        let mut descriptors = self.global.litebox.descriptor_table_mut();
        let file = files
            .fs
            .open(path, status_flags, Mode::empty(), &mut *descriptors)
            .map_err(Errno::from)?;
        drop(descriptors);
        drop(files);

        self.install_brokerfile_finalize(guest_fd, file, position, status_flags)
    }

    /// Install a worker-side FS fd at `guest_fd` that wraps an
    /// existing server-side 9P fid (already installed by a broker
    /// `CloneOfd`). Used by the legacy-pipes Phase 3 D5-fs install
    /// path: parent shim issues `RegisterOfd` to mint an
    /// `OpenFileId`, ships `--broker-fd-bridge fs_fid:<id>:<flags>`,
    /// worker side allocates a fresh client-side fid number, issues
    /// `CloneOfd { open_file_id, new_fid }`, then calls this to wrap
    /// the resulting fid in a guest descriptor.
    ///
    /// The new descriptor entry is indistinguishable from one
    /// installed by [`Self::install_brokerfile_bridge_fd`]: same
    /// `RawFdRef::Fs` dispatch, same data plane (worker 9P client →
    /// broker 9P server → host file). POSIX shared-offset semantics
    /// across inheriting fds are preserved by the kernel OFD that
    /// underlies the broker's `Arc<File>` clones.
    /// Allocate a fresh client-side 9P fid via the underlying
    /// filesystem (passes through to [`super::FileSystem::allocate_fid_number`]).
    /// Returns the fid number for the caller to ship to the broker in
    /// a `CloneOfd` request. Caller must call
    /// [`Self::install_brokerfile_bridge_fd_by_fid`] (or
    /// [`super::FileSystem::free_fid_number`] on failure) so the fid
    /// is not leaked.
    pub(crate) fn fs_allocate_fid_number(&self) -> Result<u32, Errno> {
        self.files
            .borrow()
            .fs
            .allocate_fid_number()
            .map_err(Errno::from)
    }

    /// Free a client-side 9P fid via the underlying filesystem.
    pub(crate) fn fs_free_fid_number(&self, fid: u32) {
        self.files.borrow().fs.free_fid_number(fid);
    }

    /// Issue a real close/clunk for a server-visible 9P fid that failed to
    /// become a guest descriptor.
    pub(crate) fn fs_clunk_fid_number(&self, fid: u32) {
        self.files.borrow().fs.clunk_fid_number(fid);
    }

    pub(crate) fn install_brokerfile_bridge_fd_by_fid(
        &self,
        guest_fd: usize,
        remote_fid: u32,
        path: &str,
        position: usize,
        status_flags_bits: u32,
    ) -> Result<(), Errno> {
        let status_flags = OFlags::from_bits_retain(status_flags_bits) & OFlags::STATUS_FLAGS_MASK;
        let files = self.files.borrow();
        let mut descriptors = self.global.litebox.descriptor_table_mut();
        let file = files
            .fs
            .wrap_existing_fid(remote_fid, path, status_flags, &mut *descriptors)
            .map_err(Errno::from)?;
        drop(descriptors);
        drop(files);

        self.install_brokerfile_finalize(guest_fd, file, position, status_flags)
    }

    fn install_brokerfile_finalize(
        &self,
        guest_fd: usize,
        file: crate::FileFd<FS>,
        position: usize,
        status_flags: OFlags,
    ) -> Result<(), Errno> {
        let mut descriptors = self.global.litebox.descriptor_table_mut();
        {
            let None = descriptors.set_entry_metadata(&file, crate::StdioStatusFlags(status_flags))
            else {
                unreachable!()
            };
        }
        self.files
            .borrow()
            .fs
            .set_open_status_flags(&file, status_flags, &mut *descriptors)
            .map_err(|_| Errno::EBADF)?;
        if position != 0 {
            self.files
                .borrow()
                .fs
                .seek(
                    &file,
                    isize::try_from(position).map_err(|_| Errno::EINVAL)?,
                    SeekWhence::RelativeToBeginning,
                    &*descriptors,
                )
                .map_err(Errno::from)?;
        }
        drop(descriptors);

        if self
            .files
            .borrow()
            .raw_descriptor_store
            .read()
            .is_alive(guest_fd)
        {
            self.do_close(guest_fd)?;
        }

        let files = self.files.borrow();
        let mut rds = files.raw_descriptor_store.write();
        if rds.fd_into_specific_raw_integer(file, guest_fd) {
            Ok(())
        } else {
            Err(Errno::EBADF)
        }
    }

    /// Reinstall a timerfd at `guest_fd` for a non-PIE worker-exec child.
    /// Receives the snapshot taken by the parent before exec
    /// (clock, NONBLOCK flag, ItimerSpec, pending_expirations, snapshot time)
    /// and reconstructs the timerfd state by creating a fresh timerfd and
    /// re-arming it via the same `set_time` path used by
    /// `sys_timerfd_settime`. If the parent had already accumulated
    /// pending expirations that have not been read yet, we arm a tiny
    /// catch-up timer so the child's first read observes a non-zero
    /// expiration count (approximation — the real kernel timerfd
    /// preserves the exact pending count, which is not transferable
    /// without queueing it on the broker side).
    pub(crate) fn install_timerfd_bridge_fd(
        &self,
        guest_fd: usize,
        clockid: ClockId,
        nonblock: bool,
        spec: ItimerSpec,
        pending_expirations: u64,
        snapshot_now_ns: u64,
    ) -> Result<(), Errno> {
        let mut flags = TimerfdFlags::empty();
        if nonblock {
            flags |= TimerfdFlags::NONBLOCK;
        }
        // Use sys_timerfd_create to allocate a fresh guest fd, then
        // duplicate-into the requested slot. Mirrors install_*_bridge_fd
        // pattern used by other subsystems.
        let created = self.sys_timerfd_create(clockid, flags)? as usize;
        if created != guest_fd {
            let typed = {
                let files = self.files.borrow();
                files
                    .raw_descriptor_store
                    .read()
                    .fd_from_raw_integer::<super::eventfd::EventfdSubsystem>(created)
                    .map_err(|_| Errno::EBADF)?
            };
            // Close any existing descriptor at the target slot.
            if self
                .files
                .borrow()
                .raw_descriptor_store
                .read()
                .is_alive(guest_fd)
            {
                self.do_close(guest_fd)?;
            }
            // Duplicate the entry into the requested slot, then close the
            // original creation slot.
            let dup = self
                .global
                .litebox
                .descriptor_table_mut()
                .duplicate(&typed)
                .ok_or(Errno::EBADF)?;
            {
                let files = self.files.borrow();
                let mut rds = files.raw_descriptor_store.write();
                if !rds.fd_into_specific_raw_integer(dup, guest_fd) {
                    return Err(Errno::EBADF);
                }
            }
            self.do_close(created)?;
        }

        let install_now_ns = self
            .global
            .platform
            .monotonic_timestamp()
            .ok_or(Errno::EINVAL)?
            .as_nanos();
        let elapsed_ns = install_now_ns.saturating_sub(u128::from(snapshot_now_ns));

        let restore_spec = timerfd_bridge_restore_spec(spec, pending_expirations, elapsed_ns)?;

        if restore_spec.value.tv_sec != 0 || restore_spec.value.tv_nsec != 0 {
            let raw_fd_i32 = i32::try_from(guest_fd).map_err(|_| Errno::EBADF)?;
            self.sys_timerfd_settime(raw_fd_i32, TimerfdTimerFlags::empty(), restore_spec, None)?;
        }
        Ok(())
    }

    /// Handle syscall `mkdir`
    pub fn sys_mkdir(&self, pathname: impl path::Arg, mode: u32) -> Result<(), Errno> {
        let pathname = self.resolve_path(pathname)?;
        let mode = Mode::from_bits_retain(mode) & !self.get_umask();
        let descriptors = self.global.litebox.descriptor_table();
        self.files
            .borrow()
            .fs
            .mkdir(pathname, mode, &*descriptors)
            .map_err(Errno::from)
    }

    pub fn sys_mkdirat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        mode: u32,
    ) -> Result<(), Errno> {
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        let mode = Mode::from_bits_retain(mode) & !self.get_umask();
        match fs_path {
            FsPath::Absolute { path } => {
                let descriptors = self.global.litebox.descriptor_table();
                self.files
                    .borrow()
                    .fs
                    .mkdir(path, mode, &*descriptors)
                    .map_err(Errno::from)
            }
            FsPath::Cwd => {
                let descriptors = self.global.litebox.descriptor_table();
                self.files
                    .borrow()
                    .fs
                    .mkdir(get_cwd(), mode, &*descriptors)
                    .map_err(Errno::from)
            }
            FsPath::Fd(_fd) => Err(Errno::EEXIST),
            FsPath::FdRelative { fd, path } => {
                let Ok(raw_fd) = usize::try_from(fd) else {
                    return Err(Errno::EBADF);
                };
                let files = self.files.borrow();
                files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                    crate::RawFdRef::Fs(dirfd) => {
                        let descriptors = self.global.litebox.descriptor_table();
                        files
                            .fs
                            .mkdir_at(dirfd, path, mode, &*descriptors)
                            .map_err(Errno::from)
                    }
                    #[cfg(feature = "worker_local_inet")]
                    crate::RawFdRef::Net(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Eventfd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Epoll(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Unix(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::HostPassthroughFd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerPipe(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerSocketPair(_)
                    | crate::RawFdRef::BrokerSocketDgram(_)
                    | crate::RawFdRef::BrokerUnixStream(_)
                    | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerTcpConn(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerPty(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Signalfd(_)
                    | crate::RawFdRef::Inotify(_)
                    | crate::RawFdRef::BrokerInetListener(_)
                    | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                })?
            }
        }
    }

    /// Validate that an fd is open, returning `Ok(())` or `EBADF`.
    pub fn validate_fd(&self, fd: i32) -> Result<(), Errno> {
        let Ok(raw_fd) = usize::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(_) => (),
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(_) => (),
            crate::RawFdRef::Eventfd(_) => (),
            crate::RawFdRef::Epoll(_) => (),
            crate::RawFdRef::Unix(_) => (),
            crate::RawFdRef::HostPassthroughFd(_) => (),
            crate::RawFdRef::BrokerPipe(_) => (),
            crate::RawFdRef::BrokerSocketPair(_)
            | crate::RawFdRef::BrokerSocketDgram(_)
            | crate::RawFdRef::BrokerUnixStream(_)
            | crate::RawFdRef::BrokerSocketSeqPacket(_) => (),
            crate::RawFdRef::BrokerTcpConn(_) => (),
            crate::RawFdRef::BrokerPty(_) => (),
            crate::RawFdRef::Signalfd(_)
            | crate::RawFdRef::Inotify(_)
            | crate::RawFdRef::BrokerInetListener(_)
            | crate::RawFdRef::BrokerInetDgram(_) => (),
            crate::RawFdRef::BrokerInetRaw(_) => (),
        })?;
        Ok(())
    }

    /// Validate that a path resolves to an existing file (follows symlinks).
    pub fn validate_path(&self, pathname: impl path::Arg) -> Result<(), Errno> {
        let path = self.resolve_path(pathname)?;
        let descriptors = self.global.litebox.descriptor_table();
        self.files
            .borrow()
            .fs
            .file_status(path, &*descriptors)
            .map_err(Errno::from)?;
        Ok(())
    }

    /// Validate that a path entry itself exists (does not follow symlinks).
    /// A dangling symlink is considered valid.
    pub fn validate_path_nofollow(&self, pathname: impl path::Arg) -> Result<(), Errno> {
        let path = self.resolve_path(pathname)?;
        let files = self.files.borrow();
        let descriptors = self.global.litebox.descriptor_table();
        // If the path resolves via follow (normal stat), it exists.
        if files.fs.file_status(&path, &*descriptors).is_ok() {
            return Ok(());
        }
        // The follow-stat failed. Check if it's a symlink (possibly dangling).
        if files.fs.read_link(&path, &*descriptors).is_ok() {
            return Ok(());
        }
        // Neither a resolvable path nor a symlink — report the original error.
        files
            .fs
            .file_status(path, &*descriptors)
            .map_err(Errno::from)?;
        Ok(())
    }

    /// Validate a path with symlink-follow control.
    pub fn validate_path_follow(
        &self,
        pathname: impl path::Arg,
        follow: bool,
    ) -> Result<(), Errno> {
        if follow {
            self.validate_path(pathname)
        } else {
            self.validate_path_nofollow(pathname)
        }
    }

    /// Resolve an `FsPath::FdRelative` to an absolute path, validating that
    /// the dirfd refers to a directory (not a regular file).
    fn resolve_dirfd_path(&self, fd: u32, rel_path: &CString) -> Result<String, Errno> {
        let raw_fd = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        let files = self.files.borrow();
        files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(dirfd) => {
                let descriptors = self.global.litebox.descriptor_table();
                let status = files
                    .fs
                    .fd_file_status(dirfd, &*descriptors)
                    .map_err(Errno::from)?;
                if !matches!(status.file_type, litebox::fs::FileType::Directory) {
                    return Err(Errno::ENOTDIR);
                }
                let dir_path = {
                    let descriptors = self.global.litebox.descriptor_table();
                    files.fs.fd_path(dirfd, &*descriptors).ok_or(Errno::EBADF)?
                };
                let rel = rel_path.to_str().map_err(|_| Errno::EINVAL)?;
                Ok(if rel.is_empty() || rel == "." {
                    dir_path
                } else if rel.starts_with('/') {
                    rel.to_string()
                } else if dir_path.ends_with('/') {
                    alloc::format!("{dir_path}{rel}")
                } else {
                    alloc::format!("{dir_path}/{rel}")
                })
            }
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::Eventfd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::Epoll(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::Unix(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::HostPassthroughFd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerPipe(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerSocketPair(_)
            | crate::RawFdRef::BrokerSocketDgram(_)
            | crate::RawFdRef::BrokerUnixStream(_)
            | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerTcpConn(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerPty(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::Signalfd(_)
            | crate::RawFdRef::Inotify(_)
            | crate::RawFdRef::BrokerInetListener(_)
            | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
        })?
    }

    /// Handle `symlinkat` — create a symbolic link.
    pub fn sys_symlinkat(
        &self,
        target: impl path::Arg,
        newdirfd: i32,
        linkpath: impl path::Arg,
    ) -> Result<(), Errno> {
        let target_str = target.as_rust_str().map_err(|_| Errno::EINVAL)?.to_string();

        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(newdirfd, linkpath, get_cwd)?;
        match fs_path {
            FsPath::Absolute { path } => {
                let descriptors = self.global.litebox.descriptor_table();
                self.files
                    .borrow()
                    .fs
                    .symlink(target_str, path, &*descriptors)
                    .map_err(Errno::from)
            }
            FsPath::Cwd => {
                let descriptors = self.global.litebox.descriptor_table();
                self.files
                    .borrow()
                    .fs
                    .symlink(target_str, get_cwd(), &*descriptors)
                    .map_err(Errno::from)
            }
            FsPath::Fd(_) => Err(Errno::EEXIST),
            FsPath::FdRelative { fd, path } => {
                let abs = self.resolve_dirfd_path(fd, &path)?;
                let files = self.files.borrow();
                let descriptors = self.global.litebox.descriptor_table();
                files
                    .fs
                    .symlink(target_str, abs, &*descriptors)
                    .map_err(Errno::from)
            }
        }
    }

    /// Handle `linkat` — create a hard link.
    #[allow(clippy::needless_borrows_for_generic_args)]
    pub fn sys_linkat(
        &self,
        olddirfd: i32,
        oldpath: impl path::Arg,
        newdirfd: i32,
        newpath: impl path::Arg,
        _flags: AtFlags,
    ) -> Result<(), Errno> {
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let old_fs = FsPath::new(olddirfd, oldpath, &get_cwd)?;
        let new_fs = FsPath::new(newdirfd, newpath, &get_cwd)?;

        let old_abs = self.resolve_fs_path_to_string(old_fs, &get_cwd)?;
        let new_abs = self.resolve_fs_path_to_string(new_fs, &get_cwd)?;
        let descriptors = self.global.litebox.descriptor_table();
        self.files
            .borrow()
            .fs
            .link(old_abs, new_abs, &*descriptors)
            .map_err(Errno::from)
    }

    /// Helper to resolve an `FsPath` to an absolute path string.
    fn resolve_fs_path_to_string(
        &self,
        fs_path: FsPath,
        get_cwd: &impl Fn() -> String,
    ) -> Result<String, Errno> {
        match fs_path {
            FsPath::Absolute { path } => path.into_string().map_err(|_| Errno::EINVAL),
            FsPath::Cwd => Ok(get_cwd()),
            FsPath::Fd(_) => Err(Errno::EINVAL),
            FsPath::FdRelative { fd, path } => self.resolve_dirfd_path(fd, &path),
        }
    }

    pub(crate) fn do_close(&self, raw_fd: usize) -> Result<(), Errno> {
        let files = self.files.borrow();
        if let Some(state) = files.remove_inotify_fd(raw_fd) {
            self.global
                .inotify_instances
                .lock()
                .retain(|registered| !Arc::ptr_eq(registered, &state));
        }
        {
            let rds = files.raw_descriptor_store.read();
            if !rds.is_alive(raw_fd) && files.closed_broker_pty_fds.lock().remove(&raw_fd) {
                return Ok(());
            }
        }

        let mut rds = files.raw_descriptor_store.write();
        match rds.fd_consume_raw_integer(raw_fd) {
            Ok(fd) => {
                #[cfg(feature = "trace_syscalls")]
                if raw_fd <= 20 {
                    litebox::log_println!(
                        self.global.platform,
                        "[STDIO-MAP] pid={} close fd={} kind=fs object_id={}",
                        self.pid,
                        raw_fd,
                        fd.object_id().as_u64(),
                    );
                }
                drop(rds);
                let mut descriptors = self.global.litebox.descriptor_table_mut();
                return files.fs.close(&fd, &mut *descriptors).map_err(Errno::from);
            }
            Err(litebox::fd::ErrRawIntFd::NotFound) => {
                return Err(Errno::EBADF);
            }
            Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => {
                // fallthrough
            }
        }
        #[cfg(feature = "worker_local_inet")]
        if let Ok(fd) = rds.fd_consume_raw_integer(raw_fd) {
            #[cfg(feature = "trace_syscalls")]
            if raw_fd <= 20 {
                litebox::log_println!(
                    self.global.platform,
                    "[STDIO-MAP] pid={} close fd={} kind=net-socket object_id={}",
                    self.pid,
                    raw_fd,
                    fd.object_id().as_u64(),
                );
            }
            drop(rds);
            litebox::log_println!(
                self.global.platform,
                "NET CLOSE: fd={} pid={}",
                raw_fd,
                self.pid
            );
            return self.global.close_socket(&self.wait_cx(), fd);
        }
        if let Ok(fd) = rds.fd_consume_raw_integer::<super::eventfd::EventfdSubsystem>(raw_fd) {
            #[cfg(feature = "trace_syscalls")]
            if raw_fd <= 20 {
                let kind = self
                    .global
                    .litebox
                    .descriptor_table()
                    .entry_handle(&fd)
                    .map_or("eventfd-subsystem", |handle| {
                        handle.with_entry(super::eventfd::EventFile::kind_name)
                    });
                litebox::log_println!(
                    self.global.platform,
                    "[STDIO-MAP] pid={} close fd={} kind={} object_id={}",
                    self.pid,
                    raw_fd,
                    kind,
                    fd.object_id().as_u64(),
                );
            }
            drop(rds);
            let entry = {
                let mut dt = self.global.litebox.descriptor_table_mut();
                dt.remove(&fd)
            };
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) = rds.fd_consume_raw_integer::<super::inotify::InotifySubsystem>(raw_fd) {
            drop(rds);
            let entry = {
                let mut dt = self.global.litebox.descriptor_table_mut();
                dt.remove(&fd)
            };
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) = rds
            .fd_consume_raw_integer::<super::broker_inet_listener::BrokerInetListenerSubsystem>(
                raw_fd,
            )
        {
            drop(rds);
            let entry = self.global.litebox.descriptor_table_mut().remove(&fd);
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) =
            rds.fd_consume_raw_integer::<super::broker_inet_dgram::BrokerInetDgramSubsystem>(raw_fd)
        {
            drop(rds);
            let entry = self.global.litebox.descriptor_table_mut().remove(&fd);
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) =
            rds.fd_consume_raw_integer::<super::broker_inet_raw::BrokerInetRawSubsystem>(raw_fd)
        {
            drop(rds);
            let entry = self.global.litebox.descriptor_table_mut().remove(&fd);
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) = rds.fd_consume_raw_integer::<super::signalfd::SignalfdSubsystem>(raw_fd) {
            drop(rds);
            // Drop the descriptor-table entry if it's still present.
            // `fd_consume_raw_integer` may have already consumed the
            // slot; either way the close should succeed silently
            // (matches eventfd handling above, file.rs:2774-2780).
            // Previously this used `.unwrap()` which panicked the
            // shim when called with a signalfd whose slot was
            // already detached (e.g., `OwnedFd::drop` from a
            // signalfd created with `signalfd(-1, mask, SFD_CLOEXEC)`
            // and then closed when the OwnedFd is dropped). The
            // panic killed the entire worker, which under sshd-in-
            // litebox manifests as "Connection closed" mid-session.
            let entry = {
                let mut dt = self.global.litebox.descriptor_table_mut();
                dt.remove(&fd)
            };
            drop(entry);
            return Ok(());
        }

        if let Ok(fd) = rds.fd_consume_raw_integer::<super::epoll::EpollSubsystem<FS>>(raw_fd) {
            #[cfg(feature = "trace_syscalls")]
            if raw_fd <= 20 {
                litebox::log_println!(
                    self.global.platform,
                    "[STDIO-MAP] pid={} close fd={} kind=epoll object_id={}",
                    self.pid,
                    raw_fd,
                    fd.object_id().as_u64(),
                );
            }
            drop(rds);
            let _epoll_graph_guard = self.global.epoll_graph_lock.lock();
            let parent_id = self
                .global
                .litebox
                .descriptor_table()
                .entry_handle(&fd)
                .map(|handle| handle.object_id());
            let entry = {
                let mut dt = self.global.litebox.descriptor_table_mut();
                dt.remove(&fd)
            };
            if let (Some(parent_id), Some(entry)) = (parent_id, entry.as_ref()) {
                entry.detach_nested_children_by_parent_id(parent_id);
            }
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) = rds.fd_consume_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(raw_fd) {
            #[cfg(feature = "trace_syscalls")]
            if raw_fd <= 20 {
                litebox::log_println!(
                    self.global.platform,
                    "[STDIO-MAP] pid={} close fd={} kind=unix-socket",
                    self.pid,
                    raw_fd,
                );
            }
            drop(rds);
            let entry = {
                let mut dt = self.global.litebox.descriptor_table_mut();
                dt.remove(&fd)
            };
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) =
            rds.fd_consume_raw_integer::<super::host_passthrough_fd::HostPassthroughFd>(raw_fd)
        {
            drop(rds);
            // Remove the descriptor table entry.  The OS fd is only closed
            // when this was the last reference (i.e. remove() returns the
            // entry), because dup'd HostPassthroughFdEntry entries share the same
            // underlying SharedEntry and we must not invalidate the fd for
            // other aliases.
            let mut dt = self.global.litebox.descriptor_table_mut();
            let entry = dt.remove(&fd);
            drop(dt);
            if let Some(entry) = entry {
                let host_fd = entry.take_fd();
                if host_fd >= 0 {
                    self.global.platform.close_host_fd(host_fd);
                }
            }
            return Ok(());
        }
        if let Ok(fd) =
            rds.fd_consume_raw_integer::<super::broker_pipe::BrokerPipeSubsystem>(raw_fd)
        {
            drop(rds);
            let entry = self.global.litebox.descriptor_table_mut().remove(&fd);
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) = rds
            .fd_consume_raw_integer::<super::broker_socketpair::BrokerSocketPairSubsystem>(raw_fd)
        {
            drop(rds);
            let entry = self.global.litebox.descriptor_table_mut().remove(&fd);
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) = rds
            .fd_consume_raw_integer::<super::broker_socket_dgram::BrokerSocketDgramSubsystem>(
                raw_fd,
            )
        {
            drop(rds);
            let entry = self.global.litebox.descriptor_table_mut().remove(&fd);
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) = rds
            .fd_consume_raw_integer::<super::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem>(raw_fd)
        {
            drop(rds);
            let entry = self.global.litebox.descriptor_table_mut().remove(&fd);
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) = rds
            .fd_consume_raw_integer::<super::broker_unix_stream::BrokerUnixStreamSubsystem>(raw_fd)
        {
            drop(rds);
            let entry = self.global.litebox.descriptor_table_mut().remove(&fd);
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) =
            rds.fd_consume_raw_integer::<super::broker_tcp_conn::BrokerTcpConnSubsystem>(raw_fd)
        {
            drop(rds);
            let entry = self.global.litebox.descriptor_table_mut().remove(&fd);
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) = rds.fd_consume_raw_integer::<super::broker_pty::BrokerPtySubsystem>(raw_fd)
        {
            drop(rds);
            files.closed_broker_pty_fds.lock().insert(raw_fd);
            let entry = self.global.litebox.descriptor_table_mut().remove(&fd);
            drop(entry);
            return Ok(());
        }
        // The early "raw FD not found" check rejected unknown fds, so by
        // construction the fd IS in `raw_descriptor_store`. If no
        // subsystem arm above consumed it, a new `BrokerXXXSubsystem` was
        // added without a corresponding `fd_consume_raw_integer` arm
        // here. Returning EBADF would silently leak the descriptor table
        // entry and lie about the failure mode; panic loudly so the
        // missing arm is obvious in the stack trace.
        unreachable!(
            "sys_close fell through all subsystem arms for raw_fd {raw_fd}: \
             a new BrokerXXXSubsystem needs a fd_consume_raw_integer arm in this chain"
        )
    }

    /// Handle syscall `close`
    pub(crate) fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        // Finalize any in-progress ELF patching for this fd (mprotect
        // trampoline RW→RX) before closing the descriptor.
        self.finalize_elf_patch(fd);

        // Clean up netlink socket state if this fd was a netlink socket.
        if let Ok(fd_u32) = u32::try_from(fd) {
            self.netlink_sockets.borrow_mut().remove(&fd_u32);
        }

        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        self.do_close(raw_fd)
    }

    fn set_close_on_exec(&self, raw_fd: usize) -> Result<(), Errno> {
        let files = self.files.borrow();
        files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::Eventfd(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::Epoll(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::Unix(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::HostPassthroughFd(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::BrokerPipe(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::BrokerSocketPair(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::BrokerTcpConn(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::BrokerPty(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::Signalfd(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::Inotify(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::BrokerInetListener(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::BrokerInetDgram(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::BrokerSocketDgram(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::BrokerUnixStream(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::BrokerSocketSeqPacket(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
            crate::RawFdRef::BrokerInetRaw(fd) => {
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
            }
        })
    }

    pub(crate) fn sys_close_range(
        &self,
        first: u32,
        last: u32,
        flags: u32,
    ) -> Result<usize, Errno> {
        const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

        if first > last || flags & !CLOSE_RANGE_CLOEXEC != 0 {
            return Err(Errno::EINVAL);
        }

        let first = first as usize;
        let last = last as usize;
        let alive_fds: Vec<usize> = {
            let files = self.files.borrow();
            files.raw_descriptor_store.read().iter_alive().collect()
        };

        for raw_fd in alive_fds {
            if raw_fd < first || raw_fd > last {
                continue;
            }
            if flags == CLOSE_RANGE_CLOEXEC {
                let _ = self.set_close_on_exec(raw_fd);
            } else {
                if let Ok(fd) = i32::try_from(raw_fd) {
                    self.finalize_elf_patch(fd);
                }
                let _ = self.do_close(raw_fd);
            }
        }

        Ok(0)
    }

    /// Handle syscall `readv`
    pub fn sys_readv(
        &self,
        fd: i32,
        iovec: ConstPtr<IoReadVec<MutPtr<u8>>>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let iovs: &[IoReadVec<MutPtr<u8>>] = &iovec.to_owned_slice(iovcnt).ok_or(Errno::EFAULT)?;
        let files = self.files.borrow();
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        files
            .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                crate::RawFdRef::Fs(fd) => {
                    let descriptors = self.global.litebox.descriptor_table();
                    let needs_position_lock = matches!(
                        files.fs.fd_file_status(fd, &*descriptors),
                        Ok(status) if status.file_type == litebox::fs::FileType::RegularFile
                    );
                    let mut total_read = 0;
                    let kernel_buffer =
                        core::cell::RefCell::new(vec![
                            0u8;
                            iovs.iter()
                                .map(|i| i.iov_len)
                                .max()
                                .unwrap_or_default()
                                .min(super::super::MAX_KERNEL_BUF_SIZE)
                        ]);
                    for iov in iovs {
                        if iov.iov_len == 0 {
                            continue;
                        }
                        let Ok(_iov_len) = isize::try_from(iov.iov_len) else {
                            return Err(Errno::EINVAL);
                        };
                        let size = if needs_position_lock {
                            let _position_guard = files.file_position_lock.lock();
                            files
                                .fs
                                .read(fd, &mut kernel_buffer.borrow_mut(), None, &*descriptors)
                                .map_err(Errno::from)?
                        } else {
                            files
                                .fs
                                .read(fd, &mut kernel_buffer.borrow_mut(), None, &*descriptors)
                                .map_err(Errno::from)?
                        };
                        self.park_if_deferred();
                        iov.iov_base
                            .copy_from_slice(0, &kernel_buffer.borrow()[..size])
                            .ok_or(Errno::EFAULT)?;
                        total_read += size;
                        if size < iov.iov_len {
                            break;
                        }
                    }
                    Ok(total_read)
                }
                #[cfg(feature = "worker_local_inet")]
                crate::RawFdRef::Net(fd) => read_once_to_iovecs(
                    iovs,
                    || self.park_if_deferred(),
                    |buf| {
                        self.global.receive(
                            &self.wait_cx(),
                            fd,
                            buf,
                            litebox_common_linux::ReceiveFlags::empty(),
                            None,
                        )
                    },
                ),
                crate::RawFdRef::Eventfd(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        let total_len = total_readv_len(iovs)?;
                        if total_len == 0 {
                            return Ok(0);
                        }
                        if total_len < size_of::<u64>() {
                            return Err(Errno::EINVAL);
                        }
                        let bytes = file.read(&self.wait_cx())?.to_le_bytes();
                        self.park_if_deferred();
                        scatter_bytes_to_iovecs(iovs, &bytes)
                    })
                }
                crate::RawFdRef::Epoll(_fd) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::Unix(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        read_once_to_iovecs(
                            iovs,
                            || self.park_if_deferred(),
                            |buf| {
                                file.recvfrom(
                                    &self.wait_cx(),
                                    buf,
                                    litebox_common_linux::ReceiveFlags::empty(),
                                    None,
                                    &mut Vec::new(),
                                    &mut Vec::new(),
                                )
                            },
                        )
                    })
                }
                crate::RawFdRef::HostPassthroughFd(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(
                        |entry: &super::host_passthrough_fd::HostPassthroughFdEntry| {
                            read_once_to_iovecs(
                                iovs,
                                || self.park_if_deferred(),
                                |buf| {
                                    super::host_passthrough_fd::read_host_passthrough_fd(
                                        self.global.platform,
                                        entry,
                                        buf,
                                    )
                                },
                            )
                        },
                    )
                }
                crate::RawFdRef::BrokerPipe(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| {
                        read_once_to_iovecs(
                            iovs,
                            || self.park_if_deferred(),
                            |buf| entry.read(&self.wait_cx(), buf),
                        )
                    })
                }
                crate::RawFdRef::BrokerSocketPair(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| {
                        read_once_to_iovecs(
                            iovs,
                            || self.park_if_deferred(),
                            |buf| entry.read(&self.wait_cx(), buf),
                        )
                    })
                }
                crate::RawFdRef::BrokerTcpConn(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| {
                        read_once_to_iovecs(
                            iovs,
                            || self.park_if_deferred(),
                            |buf| entry.read(&self.wait_cx(), buf),
                        )
                    })
                }
                crate::RawFdRef::BrokerInetDgram(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| {
                        read_once_to_iovecs(
                            iovs,
                            || self.park_if_deferred(),
                            |buf| {
                                let (_peer, payload, _flags) =
                                    entry.recvfrom(&self.wait_cx(), buf.len() as u32)?;
                                let copied = buf.len().min(payload.len());
                                buf[..copied].copy_from_slice(&payload[..copied]);
                                Ok(copied)
                            },
                        )
                    })
                }
                crate::RawFdRef::BrokerPty(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| {
                        read_once_to_iovecs(
                            iovs,
                            || self.park_if_deferred(),
                            |buf| entry.read(&self.wait_cx(), buf),
                        )
                    })
                }
                crate::RawFdRef::Signalfd(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| {
                        read_once_to_iovecs(iovs, || self.park_if_deferred(), |buf| entry.read(buf))
                    })
                }
                crate::RawFdRef::Inotify(_fd) => Err(Errno::EINVAL),
                crate::RawFdRef::BrokerInetListener(_fd) => Err(Errno::EINVAL),
                crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerUnixStream(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerInetRaw(_fd) => Err(Errno::EINVAL),
            })
            .flatten()
    }
}

fn write_to_iovec<F>(iovs: &[IoWriteVec<ConstPtr<u8>>], mut write_fn: F) -> Result<usize, Errno>
where
    F: FnMut(&[u8]) -> Result<usize, Errno>,
{
    let mut total_written = 0;
    for iov in iovs {
        if iov.iov_len == 0 {
            continue;
        }
        let slice = iov
            .iov_base
            .to_owned_slice(iov.iov_len)
            .ok_or(Errno::EFAULT)?;
        let size = write_fn(&slice)?;
        total_written += size;
        if size < iov.iov_len {
            // Okay to transfer fewer bytes than requested
            break;
        }
    }
    Ok(total_written)
}

fn consume_pipe_eagain_once<FS: ShimFS, S: FdEnabledSubsystem>(
    task: &Task<FS>,
    fd: &TypedFd<S>,
) -> bool {
    task.global
        .litebox
        .descriptor_table_mut()
        .with_metadata_mut(fd, |crate::PipeNonblockEagainOnce(enabled)| {
            let was_enabled = *enabled;
            *enabled = false;
            was_enabled
        })
        .unwrap_or(false)
}

fn fcntl_status_flags<FS: ShimFS>(
    task: &Task<FS>,
    files: &FilesState<FS>,
    desc: usize,
) -> Result<OFlags, Errno> {
    macro_rules! getfl_from_metadata {
        ($fd:expr, $MetaType:path) => {
            Ok(task
                .global
                .litebox
                .descriptor_table()
                .with_metadata($fd, |$MetaType(flags)| *flags)
                .unwrap_or(OFlags::empty()))
        };
    }
    macro_rules! getfl_from_handle {
        ($fd:ident) => {{
            let handle = task
                .global
                .litebox
                .descriptor_table()
                .entry_handle($fd)
                .ok_or(Errno::EBADF)?;
            handle.with_entry(|file| Ok(file.get_status()))
        }};
    }
    if let Ok(fd) = files
        .raw_descriptor_store
        .read()
        .fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(desc)
    {
        let handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&fd)
            .ok_or(Errno::EBADF)?;
        return handle.with_entry(|file| Ok(file.get_status() & OFlags::STATUS_FLAGS_MASK));
    }
    files
        .run_on_raw_fd(desc, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(fd) => getfl_from_metadata!(fd, crate::StdioStatusFlags),
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(fd) => {
                getfl_from_metadata!(fd, crate::syscalls::net::SocketOFlags)
            }
            crate::RawFdRef::Eventfd(fd) => getfl_from_handle!(fd),
            crate::RawFdRef::Epoll(fd) => getfl_from_handle!(fd),
            crate::RawFdRef::Unix(fd) => getfl_from_handle!(fd),
            crate::RawFdRef::HostPassthroughFd(fd) => getfl_from_handle!(fd),
            crate::RawFdRef::BrokerPipe(fd) => getfl_from_handle!(fd),
            crate::RawFdRef::BrokerSocketPair(fd) => getfl_from_handle!(fd),
            crate::RawFdRef::BrokerTcpConn(fd) => getfl_from_handle!(fd),
            crate::RawFdRef::BrokerPty(fd) => getfl_from_handle!(fd),
            crate::RawFdRef::Signalfd(fd) => getfl_from_handle!(fd),
            crate::RawFdRef::Inotify(fd) => getfl_from_handle!(fd),
            crate::RawFdRef::BrokerInetListener(fd) => getfl_from_handle!(fd),
            crate::RawFdRef::BrokerInetDgram(fd) => getfl_from_handle!(fd),
            crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerUnixStream(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerInetRaw(fd) => getfl_from_handle!(fd),
        })
        .flatten()
        .map(|flags| flags & OFlags::STATUS_FLAGS_MASK)
}

fn validate_fcntl_lock_fd(open_flags: OFlags) -> Result<OFlags, Errno> {
    if open_flags.contains(OFlags::PATH) {
        return Err(Errno::EBADF);
    }
    Ok(open_flags & (OFlags::WRONLY | OFlags::RDWR))
}

fn emulate_fcntl_getlk(
    lock: MutPtr<litebox_common_linux::Flock>,
    park_before_guest_write: impl FnOnce(),
) -> Result<u32, Errno> {
    let mut flock = lock.read_at_offset(0).ok_or(Errno::EFAULT)?;
    let lock_type =
        litebox_common_linux::FlockType::try_from(flock.type_).map_err(|_| Errno::EINVAL)?;
    if let litebox_common_linux::FlockType::Unlock = lock_type {
        return Err(Errno::EINVAL);
    }
    flock.type_ = litebox_common_linux::FlockType::Unlock as i16;
    park_before_guest_write();
    lock.write_at_offset(0, flock).ok_or(Errno::EFAULT)?;
    Ok(0)
}

fn emulate_fcntl_setlk(
    lock: ConstPtr<litebox_common_linux::Flock>,
    open_flags: OFlags,
) -> Result<u32, Errno> {
    let flock = lock.read_at_offset(0).ok_or(Errno::EFAULT)?;
    let lock_type =
        litebox_common_linux::FlockType::try_from(flock.type_).map_err(|_| Errno::EINVAL)?;
    let access = validate_fcntl_lock_fd(open_flags)?;
    if matches!(lock_type, litebox_common_linux::FlockType::ReadLock) && access == OFlags::WRONLY {
        return Err(Errno::EBADF);
    }
    if matches!(lock_type, litebox_common_linux::FlockType::WriteLock) && access == OFlags::empty()
    {
        return Err(Errno::EBADF);
    }
    Ok(0)
}

fn total_readv_len(iovs: &[IoReadVec<MutPtr<u8>>]) -> Result<usize, Errno> {
    iovs.iter().try_fold(0usize, |total, iov| {
        let Ok(_iov_len) = isize::try_from(iov.iov_len) else {
            return Err(Errno::EINVAL);
        };
        total.checked_add(iov.iov_len).ok_or(Errno::EINVAL)
    })
}

fn total_writev_len(iovs: &[IoWriteVec<ConstPtr<u8>>]) -> Result<usize, Errno> {
    iovs.iter().try_fold(0usize, |total, iov| {
        let Ok(_iov_len) = isize::try_from(iov.iov_len) else {
            return Err(Errno::EINVAL);
        };
        total.checked_add(iov.iov_len).ok_or(Errno::EINVAL)
    })
}

fn alloc_zeroed_kernel_buf(len: usize) -> Result<alloc::vec::Vec<u8>, Errno> {
    let mut buf = alloc::vec::Vec::new();
    buf.try_reserve_exact(len).map_err(|_| Errno::ENOMEM)?;
    buf.resize(len, 0);
    Ok(buf)
}

fn scatter_bytes_to_iovecs(iovs: &[IoReadVec<MutPtr<u8>>], bytes: &[u8]) -> Result<usize, Errno> {
    let mut copied = 0;
    for iov in iovs {
        if copied == bytes.len() {
            break;
        }
        if iov.iov_len == 0 {
            continue;
        }
        let chunk_len = core::cmp::min(iov.iov_len, bytes.len() - copied);
        iov.iov_base
            .copy_from_slice(0, &bytes[copied..copied + chunk_len])
            .ok_or(Errno::EFAULT)?;
        copied += chunk_len;
    }
    Ok(copied)
}

fn read_once_to_iovecs<F, P>(
    iovs: &[IoReadVec<MutPtr<u8>>],
    park_before_guest_write: P,
    read_fn: F,
) -> Result<usize, Errno>
where
    P: FnOnce(),
    F: FnOnce(&mut [u8]) -> Result<usize, Errno>,
{
    let total_len = total_readv_len(iovs)?.min(super::super::MAX_KERNEL_BUF_SIZE);
    if total_len == 0 {
        return Ok(0);
    }
    let mut kernel_buf = alloc_zeroed_kernel_buf(total_len)?;
    let size = read_fn(&mut kernel_buf)?;
    park_before_guest_write();
    scatter_bytes_to_iovecs(iovs, &kernel_buf[..size])
}

fn gather_iovecs(iovs: &[IoWriteVec<ConstPtr<u8>>]) -> Result<alloc::vec::Vec<u8>, Errno> {
    let total_len = total_writev_len(iovs)?.min(super::super::MAX_KERNEL_BUF_SIZE);
    let mut gathered = alloc::vec::Vec::new();
    gathered
        .try_reserve_exact(total_len)
        .map_err(|_| Errno::ENOMEM)?;
    let mut remaining = total_len;
    for iov in iovs {
        if remaining == 0 {
            break;
        }
        if iov.iov_len == 0 {
            continue;
        }
        let slice = iov
            .iov_base
            .to_owned_slice(iov.iov_len)
            .ok_or(Errno::EFAULT)?;
        let chunk_len = core::cmp::min(slice.len(), remaining);
        gathered.extend_from_slice(&slice[..chunk_len]);
        remaining -= chunk_len;
    }
    Ok(gathered)
}

fn write_once_from_iovecs<F>(iovs: &[IoWriteVec<ConstPtr<u8>>], write_fn: F) -> Result<usize, Errno>
where
    F: FnOnce(&[u8]) -> Result<usize, Errno>,
{
    let gathered = gather_iovecs(iovs)?;
    if gathered.is_empty() {
        return Ok(0);
    }
    write_fn(&gathered)
}

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `writev`
    pub fn sys_writev(
        &self,
        fd: i32,
        iovec: ConstPtr<IoWriteVec<ConstPtr<u8>>>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let iovs: &[IoWriteVec<ConstPtr<u8>>] =
            &iovec.to_owned_slice(iovcnt).ok_or(Errno::EFAULT)?;
        let files = self.files.borrow();
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        let res = files
            .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                crate::RawFdRef::Fs(fd) => {
                    let mut descriptors = self.global.litebox.descriptor_table_mut();
                    let _position_guard = if matches!(
                        files.fs.fd_file_status(fd, &*descriptors),
                        Ok(status) if status.file_type == litebox::fs::FileType::RegularFile
                    ) {
                        Some(files.file_position_lock.lock())
                    } else {
                        None
                    };
                    write_to_iovec(iovs, |buf: &[u8]| {
                        files
                            .fs
                            .write(fd, buf, None, &mut *descriptors)
                            .map_err(Errno::from)
                    })
                }
                #[cfg(feature = "worker_local_inet")]
                crate::RawFdRef::Net(fd) => write_once_from_iovecs(iovs, |buf| {
                    self.global.sendto(
                        &self.wait_cx(),
                        fd,
                        buf,
                        litebox_common_linux::SendFlags::empty(),
                        None,
                    )
                }),
                crate::RawFdRef::Eventfd(fd) => {
                    let total_len = total_writev_len(iovs)?;
                    if total_len == 0 {
                        return Ok(0);
                    }
                    let Some(first_iov) = iovs.first() else {
                        return Ok(0);
                    };
                    if first_iov.iov_len != size_of::<u64>() {
                        return Err(Errno::EINVAL);
                    }
                    let bytes = first_iov
                        .iov_base
                        .to_owned_slice(size_of::<u64>())
                        .ok_or(Errno::EFAULT)?;
                    let value: u64 =
                        u64::from_le_bytes(bytes.as_ref().try_into().map_err(|_| Errno::EINVAL)?);
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| file.write(&self.wait_cx(), value))
                }
                crate::RawFdRef::Epoll(_fd) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::Unix(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        write_once_from_iovecs(iovs, |buf| {
                            file.sendto(
                                self,
                                buf,
                                litebox_common_linux::SendFlags::empty(),
                                None,
                                Vec::new(),
                                Vec::new(),
                            )
                        })
                    })
                }
                crate::RawFdRef::HostPassthroughFd(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(
                        |entry: &super::host_passthrough_fd::HostPassthroughFdEntry| {
                            write_once_from_iovecs(iovs, |buf| {
                                super::host_passthrough_fd::write_host_passthrough_fd(
                                    self.global.platform,
                                    entry,
                                    buf,
                                )
                            })
                        },
                    )
                }
                crate::RawFdRef::BrokerPipe(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| {
                        write_once_from_iovecs(iovs, |buf| entry.write(&self.wait_cx(), buf))
                    })
                }
                crate::RawFdRef::BrokerSocketPair(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| {
                        write_once_from_iovecs(iovs, |buf| entry.write(&self.wait_cx(), buf))
                    })
                }
                crate::RawFdRef::BrokerTcpConn(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| {
                        write_once_from_iovecs(iovs, |buf| entry.write(&self.wait_cx(), buf))
                    })
                }
                crate::RawFdRef::BrokerPty(fd) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| {
                        if total_writev_len(iovs)? > 0 {
                            self.broker_pty_background_sigttou(entry, true)?;
                        }
                        write_once_from_iovecs(iovs, |buf| entry.write(&self.wait_cx(), buf))
                    })
                }
                crate::RawFdRef::Signalfd(_)
                | crate::RawFdRef::Inotify(_)
                | crate::RawFdRef::BrokerInetListener(_)
                | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
                crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerUnixStream(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::EINVAL), // real Linux: EINVAL for this unsupported fd/syscall combination
            })
            .flatten();
        if let Err(Errno::EPIPE) = res {
            self.send_signal(
                litebox_common_linux::signal::Signal::SIGPIPE,
                siginfo_kernel(litebox_common_linux::signal::Signal::SIGPIPE),
            );
        }
        res
    }

    /// Handle syscall `access`
    pub fn sys_access(
        &self,
        pathname: impl path::Arg,
        mode: litebox_common_linux::AccessFlags,
    ) -> Result<(), Errno> {
        let pathname = self.resolve_path(pathname)?;
        let descriptors = self.global.litebox.descriptor_table();
        let status = self
            .files
            .borrow()
            .fs
            .file_status(&*pathname, &*descriptors)?;
        Self::check_access_mode(&status, mode)
    }

    /// Handle `faccessat` and `faccessat2` syscalls.
    pub fn sys_faccessat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        mode: litebox_common_linux::AccessFlags,
        flags: litebox_common_linux::AtFlags,
    ) -> Result<(), Errno> {
        use litebox_common_linux::AtFlags;
        let supported = AtFlags::AT_EACCESS | AtFlags::AT_SYMLINK_NOFOLLOW | AtFlags::AT_EMPTY_PATH;
        if flags.intersects(!supported) {
            return Err(Errno::EINVAL);
        }

        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let allow_empty = flags.contains(AtFlags::AT_EMPTY_PATH);
        let fs_path = FsPath::new_inner(dirfd, pathname, get_cwd, allow_empty)?;

        let follow_symlinks = !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW);

        let files = self.files.borrow();
        let descriptors = self.global.litebox.descriptor_table();
        let status = match fs_path {
            FsPath::Absolute { path } => {
                // Skip client-side symlink resolution when the FS follows
                // symlinks during walk (e.g., 9P with canonicalizing broker).
                if follow_symlinks && !files.fs.walks_follow_symlinks() {
                    let path_str = path.to_str().map_err(|_| Errno::EINVAL)?;
                    let resolved = self.canonicalize_path(path_str)?;
                    files.fs.file_status(&*resolved, &*descriptors)?
                } else {
                    files.fs.file_status(&*path, &*descriptors)?
                }
            }
            FsPath::Cwd => files.fs.file_status(&*get_cwd(), &*descriptors)?,
            FsPath::Fd(raw) => {
                // AT_EMPTY_PATH: check the fd itself. For non-FS fds
                // (network, pipes, etc.), the fd is valid so F_OK succeeds
                // and we don't model fine-grained permissions.
                let raw = usize::try_from(raw).map_err(|_| Errno::EBADF)?;
                return files.run_on_raw_fd(raw, |raw_fd_ref| match raw_fd_ref {
                    crate::RawFdRef::Fs(fd) => {
                        let descriptors = self.global.litebox.descriptor_table();
                        let s = files
                            .fs
                            .fd_file_status(fd, &*descriptors)
                            .map_err(Errno::from)?;
                        Self::check_access_mode(&s, mode)
                    }
                    #[cfg(feature = "worker_local_inet")]
                    crate::RawFdRef::Net(_) => Ok(()),
                    crate::RawFdRef::Eventfd(_) => Ok(()),
                    crate::RawFdRef::Epoll(_) => Ok(()),
                    crate::RawFdRef::Unix(_) => Ok(()),
                    crate::RawFdRef::HostPassthroughFd(_) => Ok(()),
                    crate::RawFdRef::BrokerPipe(_) => Ok(()),
                    crate::RawFdRef::BrokerSocketPair(_)
                    | crate::RawFdRef::BrokerSocketDgram(_)
                    | crate::RawFdRef::BrokerUnixStream(_)
                    | crate::RawFdRef::BrokerSocketSeqPacket(_) => Ok(()),
                    crate::RawFdRef::BrokerTcpConn(_) => Ok(()),
                    crate::RawFdRef::BrokerPty(_) => Ok(()),
                    crate::RawFdRef::Signalfd(_)
                    | crate::RawFdRef::Inotify(_)
                    | crate::RawFdRef::BrokerInetListener(_)
                    | crate::RawFdRef::BrokerInetDgram(_) => Ok(()),
                    crate::RawFdRef::BrokerInetRaw(_) => Ok(()),
                })?;
            }
            FsPath::FdRelative { fd, path } => {
                // Use stat_at which handles follow_symlinks properly.
                let raw = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
                return files.run_on_raw_fd(raw, |raw_fd_ref| match raw_fd_ref {
                    crate::RawFdRef::Fs(dirfd) => {
                        let descriptors = self.global.litebox.descriptor_table();
                        let s = files
                            .fs
                            .stat_at(dirfd, path, follow_symlinks, &*descriptors)
                            .map_err(Errno::from)?;
                        Self::check_access_mode(&s, mode)
                    }
                    #[cfg(feature = "worker_local_inet")]
                    crate::RawFdRef::Net(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Eventfd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Epoll(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Unix(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::HostPassthroughFd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerPipe(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerSocketPair(_)
                    | crate::RawFdRef::BrokerSocketDgram(_)
                    | crate::RawFdRef::BrokerUnixStream(_)
                    | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerTcpConn(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerPty(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Signalfd(_)
                    | crate::RawFdRef::Inotify(_)
                    | crate::RawFdRef::BrokerInetListener(_)
                    | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                })?;
            }
        };

        // AT_EACCESS: use effective IDs instead of real IDs.
        // We don't distinguish real vs effective, so this is a no-op.
        Self::check_access_mode(&status, mode)
    }

    /// Check file access permissions against the given mode flags.
    fn check_access_mode(
        status: &litebox::fs::FileStatus,
        mode: litebox_common_linux::AccessFlags,
    ) -> Result<(), Errno> {
        if mode == litebox_common_linux::AccessFlags::F_OK {
            return Ok(());
        }
        // TODO: the check is done using the calling process's real UID and GID.
        // Here we assume the caller owns the file.
        if mode.contains(litebox_common_linux::AccessFlags::R_OK)
            && !status.mode.contains(litebox::fs::Mode::RUSR)
        {
            return Err(Errno::EACCES);
        }
        if mode.contains(litebox_common_linux::AccessFlags::W_OK)
            && !status.mode.contains(litebox::fs::Mode::WUSR)
        {
            return Err(Errno::EACCES);
        }
        if mode.contains(litebox_common_linux::AccessFlags::X_OK)
            && !status.mode.contains(litebox::fs::Mode::XUSR)
        {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// Read the target of a symbolic link
    ///
    /// The caller must pass an absolute path.
    ///
    /// Note that this function only handles the following cases that we hardcoded:
    /// - `/proc/self/fd/<fd>`
    fn do_readlink(&self, fullpath: &str) -> Result<String, Errno> {
        // Rewrite /proc/<N>/... → /proc/self/... for own PID.
        let fullpath_owned;
        let fullpath = if let Some(rewritten) = self.rewrite_proc_pid_to_self(fullpath) {
            fullpath_owned = rewritten;
            fullpath_owned.as_str()
        } else {
            fullpath
        };

        if fullpath == "/proc/self/cwd" {
            let cwd = self.fs.borrow().cwd.read().clone();
            // Strip trailing slash (except for root "/") — Linux's
            // readlink("/proc/self/cwd") never includes one.
            let trimmed = cwd.trim_end_matches('/');
            return Ok(if trimmed.is_empty() {
                "/".into()
            } else {
                trimmed.into()
            });
        }
        if fullpath == "/proc/self/exe" {
            let exe = self.fs.borrow().exe_path.read().clone();
            if exe.is_empty() {
                return Err(Errno::ENOENT);
            }
            return Ok(exe);
        }
        // Handle both /proc/self/fd/N and /dev/fd/N (the latter is a
        // symlink to the former on real Linux).
        let fd_suffix = fullpath
            .strip_prefix("/proc/self/fd/")
            .or_else(|| fullpath.strip_prefix("/dev/fd/"));
        if let Some(stripped) = fd_suffix {
            let fd = stripped.parse::<u32>().map_err(|_| Errno::EINVAL)?;
            if let 0..=2 = fd {
                let raw_fd = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
                let files = self.files.borrow();
                let rds = files.raw_descriptor_store.read();
                // BrokerPty: synthesize /dev/pts/<pty_id> path so that
                // ttyname()/readlink() return the actual PTY slave path
                // even when stdio is wired to a broker-allocated PTY
                // slave (the dropbear SSH-session case). Mirrors the
                // non-stdio arm below; without it, the stdio path falls
                // through to a generic "/dev/std{in,out,err}" placeholder
                // and TUI apps (e.g., GitHub Copilot CLI) can't discover
                // the slave path to re-open for rendering.
                if let Ok(typed_pty) =
                    rds.fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(raw_fd)
                {
                    let pty_id = self
                        .global
                        .litebox
                        .descriptor_table()
                        .with_entry(
                            &typed_pty,
                            |pty_fd: &super::broker_pty::BrokerPtyFd<Platform>| pty_fd.pty_id(),
                        )
                        .ok_or(Errno::EBADF)?;
                    return Ok(alloc::format!("/dev/pts/{pty_id}"));
                }
                if let Ok(typed_fd) = rds.fd_from_raw_integer::<FS>(raw_fd) {
                    if let Ok(source_fd) =
                        self.global.litebox.descriptor_table().with_metadata(
                            typed_fd.as_ref(),
                            |crate::HostStdioSourceFd(source_fd)| *source_fd,
                        )
                    {
                        if (0..=2).contains(&source_fd) {
                            // Return the actual host PTY path if available,
                            // so that ttyname_r() can discover and reopen
                            // the controlling terminal by its real device path.
                            // We check host_stdin_tty_device_info() which gates
                            // on whether the host has a terminal at all, rather
                            // than checking the specific stream for this source_fd.
                            // This matches the ioctl layer's fallback behavior
                            // (host_stdio_stream_for_fd) which routes any stdio
                            // fd to whichever host stream IS a terminal.
                            if let Some(info) = self.global.platform.host_stdin_tty_device_info() {
                                return Ok(info.path);
                            }
                            // If no host PTY info is available but any host
                            // stream is a terminal, report /dev/tty.
                            let any_tty = [
                                litebox::platform::StdioStream::Stdin,
                                litebox::platform::StdioStream::Stdout,
                                litebox::platform::StdioStream::Stderr,
                            ]
                            .into_iter()
                            .any(|s| self.global.platform.is_a_tty(s));
                            if any_tty {
                                return Ok("/dev/tty".to_string());
                            }
                        }
                        return Ok(match source_fd {
                            0 => "/dev/stdin".to_string(),
                            1 => "/dev/stdout".to_string(),
                            2 => "/dev/stderr".to_string(),
                            _ => {
                                let descriptors = self.global.litebox.descriptor_table();
                                files
                                    .fs
                                    .fd_path(typed_fd.as_ref(), &*descriptors)
                                    .ok_or(Errno::ENOENT)?
                            }
                        });
                    }
                    if self
                        .global
                        .litebox
                        .descriptor_table()
                        .with_metadata(typed_fd.as_ref(), |_alias: &crate::HostTtyAlias| ())
                        .is_ok()
                    {
                        if let Some(info) = self.global.platform.host_stdin_tty_device_info() {
                            return Ok(info.path);
                        }
                        return Ok("/dev/tty".to_string());
                    }
                    // Also check for HostPtyDeviceFd (reopened via /dev/pts/N)
                    if self
                        .global
                        .litebox
                        .descriptor_table()
                        .with_metadata(typed_fd.as_ref(), |_: &HostPtyDeviceFd| ())
                        .is_ok()
                    {
                        if let Some(info) = self.global.platform.host_stdin_tty_device_info() {
                            return Ok(info.path);
                        }
                        return Ok("/dev/tty".to_string());
                    }
                }
                return Ok(match fd {
                    0 => "/dev/stdin".to_string(),
                    1 => "/dev/stdout".to_string(),
                    2 => "/dev/stderr".to_string(),
                    _ => unreachable!(),
                });
            } else {
                // Check for HostPtyDeviceFd or HostTtyAlias metadata on
                // non-stdio fds (e.g., fds reopened via /dev/pts/N or
                // /dev/tty) so readlink returns a consistent PTY path.
                let raw_fd = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
                let files = self.files.borrow();
                let rds = files.raw_descriptor_store.read();
                // BrokerPty: synthesize /dev/pts/<pty_id> path so
                // ttyname() works. Mirrors what /dev/pts/N open would
                // return; necessary for sshd/dropbear's openpty path,
                // which calls readlink(/proc/self/fd/N) then opens the
                // resulting path. (Stage B: same pattern as the
                // F_GETFD bug — see also FilesState::run_on_raw_fd.)
                if let Ok(typed_pty) =
                    rds.fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(raw_fd)
                {
                    let pty_id = self
                        .global
                        .litebox
                        .descriptor_table()
                        .with_entry(
                            &typed_pty,
                            |pty_fd: &super::broker_pty::BrokerPtyFd<Platform>| pty_fd.pty_id(),
                        )
                        .ok_or(Errno::EBADF)?;
                    return Ok(alloc::format!("/dev/pts/{pty_id}"));
                }
                if let Ok(typed_fd) = rds.fd_from_raw_integer::<FS>(raw_fd) {
                    let dt = self.global.litebox.descriptor_table();
                    if dt
                        .with_metadata(typed_fd.as_ref(), |_: &HostPtyDeviceFd| ())
                        .is_ok()
                        && let Some(info) = self.global.platform.host_stdin_tty_device_info()
                    {
                        return Ok(info.path);
                    }
                    if dt
                        .with_metadata(typed_fd.as_ref(), |_: &crate::HostTtyAlias| ())
                        .is_ok()
                    {
                        return Ok("/dev/tty".to_string());
                    }
                    return files
                        .fs
                        .fd_path(typed_fd.as_ref(), &*dt)
                        .ok_or(Errno::ENOENT);
                }
                return Err(Errno::EBADF);
            }
        }

        // Try the filesystem for symlink resolution
        let descriptors = self.global.litebox.descriptor_table();
        let result = self.files.borrow().fs.read_link(fullpath, &*descriptors);
        match result {
            Ok(target) => Ok(target),
            Err(e) => {
                use litebox::fs::errors::ReadLinkError;
                // reason: unsupported variants intentionally share this fallback path.
                #[allow(clippy::wildcard_enum_match_arm)]
                match e {
                    ReadLinkError::PathError(pe) => Err(Errno::from(pe)),
                    ReadLinkError::ClosedFd => Err(Errno::EBADF),
                    ReadLinkError::NotADirectory => Err(Errno::ENOTDIR),
                    // Not a symlink, or FS doesn't support symlinks.
                    ReadLinkError::NotASymlink | ReadLinkError::NotSupported => Err(Errno::EINVAL),
                    _ => Err(Errno::EIO),
                }
            }
        }
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
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fspath = FsPath::new_inner(dirfd, pathname, get_cwd, true)?;
        let path = match fspath {
            FsPath::Absolute { path } => {
                self.do_readlink(path.to_str().map_err(|_| Errno::EINVAL)?)
            }
            // Linux only resolves empty-path readlinkat() on an O_PATH|O_NOFOLLOW
            // symlink fd. The shim does not preserve symlink fd identity yet, so
            // valid fds fall back to ENOENT instead of resolving through the
            // original path; invalid fds still return EBADF.
            FsPath::Cwd => Err(Errno::ENOENT),
            FsPath::Fd(fd) => {
                let raw_fd = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
                let files = self.files.borrow();
                files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                    crate::RawFdRef::Fs(_) => (),
                    #[cfg(feature = "worker_local_inet")]
                    crate::RawFdRef::Net(_) => (),
                    crate::RawFdRef::Eventfd(_) => (),
                    crate::RawFdRef::Epoll(_) => (),
                    crate::RawFdRef::Unix(_) => (),
                    crate::RawFdRef::HostPassthroughFd(_) => (),
                    crate::RawFdRef::BrokerPipe(_) => (),
                    crate::RawFdRef::BrokerSocketPair(_)
                    | crate::RawFdRef::BrokerSocketDgram(_)
                    | crate::RawFdRef::BrokerUnixStream(_)
                    | crate::RawFdRef::BrokerSocketSeqPacket(_) => (),
                    crate::RawFdRef::BrokerTcpConn(_) => (),
                    crate::RawFdRef::BrokerPty(_) => (),
                    crate::RawFdRef::Signalfd(_)
                    | crate::RawFdRef::Inotify(_)
                    | crate::RawFdRef::BrokerInetListener(_)
                    | crate::RawFdRef::BrokerInetDgram(_) => (),
                    crate::RawFdRef::BrokerInetRaw(_) => (),
                })?;
                Err(Errno::ENOENT)
            }
            FsPath::FdRelative { fd, path } => {
                let Ok(raw_fd) = usize::try_from(fd) else {
                    return Err(Errno::EBADF);
                };

                let files = self.files.borrow();
                files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                    crate::RawFdRef::Fs(dirfd) => {
                        // reason: unsupported variants intentionally share this fallback path.
                        #[allow(clippy::wildcard_enum_match_arm)]
                        let descriptors = self.global.litebox.descriptor_table();
                        files
                            .fs
                            .readlink_at(dirfd, path, &*descriptors)
                            .map_err(|e| match e {
                                litebox::fs::errors::ReadLinkError::NotASymlink
                                | litebox::fs::errors::ReadLinkError::NotSupported => Errno::EINVAL,
                                litebox::fs::errors::ReadLinkError::ClosedFd => Errno::EBADF,
                                litebox::fs::errors::ReadLinkError::NotADirectory => Errno::ENOTDIR,
                                litebox::fs::errors::ReadLinkError::PathError(pe) => {
                                    Errno::from(pe)
                                }
                                _ => Errno::EIO,
                            })
                    }
                    #[cfg(feature = "worker_local_inet")]
                    crate::RawFdRef::Net(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Eventfd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Epoll(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Unix(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::HostPassthroughFd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerPipe(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerSocketPair(_)
                    | crate::RawFdRef::BrokerSocketDgram(_)
                    | crate::RawFdRef::BrokerUnixStream(_)
                    | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerTcpConn(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerPty(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Signalfd(_)
                    | crate::RawFdRef::Inotify(_)
                    | crate::RawFdRef::BrokerInetListener(_)
                    | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                })?
            }
        }?;
        let bytes = path.as_bytes();
        let min_len = core::cmp::min(buf.len(), bytes.len());
        buf[..min_len].copy_from_slice(&bytes[..min_len]);
        Ok(min_len)
    }
}

fn synthetic_symlink_stat(target_len: usize) -> FileStat {
    FileStat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 1,
        st_mode: ((litebox_common_linux::InodeType::SymLink as u32)
            | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits())
        .truncate(),
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_size: target_len,
        st_blksize: 4096,
        st_blocks: 0,
        ..Default::default()
    }
}

fn descriptor_stat<FS: ShimFS>(raw_fd: usize, task: &Task<FS>) -> Result<FileStat, Errno> {
    let uid = task.credentials.euid.truncate();
    let gid = task.credentials.egid.truncate();

    // Probe BrokerPty separately so we can release files_borrow before
    // calling fs.file_status (which re-borrows files internally).
    let pty_id_opt: Option<u32> = {
        let files_borrow = task.files.borrow();
        let pty_opt = files_borrow
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(raw_fd)
            .ok();
        pty_opt.and_then(|fd| {
            let handle = task.global.litebox.descriptor_table().entry_handle(&fd)?;
            Some(handle.with_entry(|pty| pty.pty_id()))
        })
    };
    if let Some(pty_id) = pty_id_opt {
        // Route via fs.file_status(/dev/pts/N) so the layered FS's
        // node_info rewriter gives identical st_dev/st_ino to
        // stat("/dev/pts/N"). Without this, glibc ttyname's is_mytty()
        // compares fstat(slave) vs stat("/dev/pts/N") and they mismatch
        // — dropbear then exits with "ttyname fails for openpty device".
        let authoritative = Task::<FS>::broker_pty_stat(pty_id, uid, gid);
        let path = alloc::format!("/dev/pts/{pty_id}");
        let descriptors = task.global.litebox.descriptor_table();
        let fs_status = task
            .files
            .borrow()
            .fs
            .file_status(path.as_str(), &*descriptors);
        if let Ok(status) = fs_status {
            let mut stat = FileStat::from(status);
            stat.st_mode = authoritative.st_mode;
            stat.st_uid = authoritative.st_uid;
            stat.st_gid = authoritative.st_gid;
            stat.st_rdev = authoritative.st_rdev;
            stat.st_nlink = authoritative.st_nlink;
            stat.st_size = authoritative.st_size;
            stat.st_blksize = authoritative.st_blksize;
            return Ok(stat);
        }
        return Ok(authoritative);
    }

    let mut fstat = task
        .files
        .borrow()
        .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(fd) => task
                .files
                .borrow()
                .fs
                .fd_file_status(fd, &*task.global.litebox.descriptor_table())
                .map(FileStat::from)
                .map_err(Errno::from),
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                Ok(FileStat {
                    st_dev: SOCKFS_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (litebox_common_linux::InodeType::Socket as u32
                        | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits())
                    .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
            crate::RawFdRef::Eventfd(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                Ok(FileStat {
                    st_dev: ANON_INODE_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (Mode::RUSR | Mode::WUSR).bits().truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
            crate::RawFdRef::Epoll(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                Ok(FileStat {
                    st_dev: ANON_INODE_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (Mode::RUSR | Mode::WUSR).bits().truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 0,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
            crate::RawFdRef::Unix(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                Ok(FileStat {
                    st_dev: SOCKFS_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (litebox_common_linux::InodeType::Socket as u32
                        | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits())
                    .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
            crate::RawFdRef::HostPassthroughFd(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                let dir = task
                    .global
                    .litebox
                    .descriptor_table()
                    .with_entry(
                        fd,
                        |e: &super::host_passthrough_fd::HostPassthroughFdEntry| e.direction,
                    )
                    .ok_or(Errno::EBADF)?;
                let read_write_mode = match dir {
                    super::host_passthrough_fd::HostPassthroughFdDirection::Read => Mode::RUSR,
                    super::host_passthrough_fd::HostPassthroughFdDirection::Write => Mode::WUSR,
                    super::host_passthrough_fd::HostPassthroughFdDirection::ReadWrite => {
                        Mode::from_bits_truncate(Mode::RUSR.bits() | Mode::WUSR.bits())
                    }
                };
                Ok(FileStat {
                    st_dev: PIPEFS_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (read_write_mode.bits()
                        | litebox_common_linux::InodeType::NamedPipe as u32)
                        .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
            crate::RawFdRef::BrokerPipe(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                let dir = task
                    .global
                    .litebox
                    .descriptor_table()
                    .with_entry(
                        fd,
                        |e: &super::broker_pipe::BrokerPipeFd<crate::Platform>| e.direction(),
                    )
                    .ok_or(Errno::EBADF)?;
                let read_write_mode = match dir {
                    litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Read => Mode::RUSR,
                    litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Write => Mode::WUSR,
                };
                Ok(FileStat {
                    st_dev: PIPEFS_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (read_write_mode.bits()
                        | litebox_common_linux::InodeType::NamedPipe as u32)
                        .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
            crate::RawFdRef::BrokerSocketPair(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                // Phase F: broker-backed socketpair endpoint. Reports
                // as AF_UNIX socket (S_IFSOCK) with RDWR mode. No
                // direction byte — both endpoints are bidirectional.
                let read_write_mode = Mode::RUSR | Mode::WUSR;
                Ok(FileStat {
                    st_dev: PIPEFS_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (read_write_mode.bits()
                        | litebox_common_linux::InodeType::Socket as u32)
                        .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
            crate::RawFdRef::BrokerTcpConn(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                // Stage 1 scaffold: broker-backed TCP connection.
                // Reports as a bidirectional socket with RDWR mode.
                let read_write_mode = Mode::RUSR | Mode::WUSR;
                Ok(FileStat {
                    st_dev: PIPEFS_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (read_write_mode.bits()
                        | litebox_common_linux::InodeType::Socket as u32)
                        .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
            crate::RawFdRef::BrokerPty(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                // Phase F: broker-backed socketpair endpoint. Reports
                // as AF_UNIX socket (S_IFSOCK) with RDWR mode. No
                // direction byte — both endpoints are bidirectional.
                let read_write_mode = Mode::RUSR | Mode::WUSR;
                Ok(FileStat {
                    st_dev: PIPEFS_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (read_write_mode.bits()
                        | litebox_common_linux::InodeType::Socket as u32)
                        .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
            crate::RawFdRef::Signalfd(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                let read_write_mode = Mode::RUSR | Mode::WUSR;
                Ok(FileStat {
                    st_dev: ANON_INODE_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (read_write_mode.bits()
                        | litebox_common_linux::InodeType::File as u32)
                        .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
            crate::RawFdRef::Inotify(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                let read_write_mode = Mode::RUSR;
                Ok(FileStat {
                    st_dev: ANON_INODE_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (read_write_mode.bits()
                        | litebox_common_linux::InodeType::File as u32)
                        .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
            crate::RawFdRef::BrokerInetListener(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                let read_write_mode = Mode::RUSR | Mode::WUSR;
                Ok(FileStat {
                    st_dev: ANON_INODE_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (read_write_mode.bits()
                        | litebox_common_linux::InodeType::Socket as u32)
                        .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
            crate::RawFdRef::BrokerInetDgram(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                let read_write_mode = Mode::RUSR | Mode::WUSR;
                Ok(FileStat {
                    st_dev: ANON_INODE_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (read_write_mode.bits()
                        | litebox_common_linux::InodeType::Socket as u32)
                        .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
            crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerUnixStream(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerInetRaw(fd) => {
                let ino = get_or_assign_anon_ino(task, fd);
                let read_write_mode = Mode::RUSR | Mode::WUSR;
                Ok(FileStat {
                    st_dev: ANON_INODE_DEV.truncate(),
                    st_ino: ino.truncate(),
                    st_nlink: 1,
                    st_mode: (read_write_mode.bits()
                        | litebox_common_linux::InodeType::Socket as u32)
                        .truncate(),
                    st_uid: uid,
                    st_gid: gid,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 4096,
                    st_blocks: 0,
                    ..Default::default()
                })
            }
        })
        .flatten()?;

    // Override st_dev/st_ino/st_rdev for fds that should report the host PTY
    // identity. This applies to:
    // - Inherited stdin/stdout/stderr (have HostStdioSourceFd metadata)
    // - Fds opened via the host PTY device path (have HostPtyDeviceFd metadata)
    // The device FS internally reports rdev=0x500 (major 5) which keeps
    // classify_terminal() routing to HostStdio. This override only affects
    // what the guest sees via fstat/statx.
    if let Some(info) = task.global.platform.host_stdin_tty_device_info() {
        let files = task.files.borrow();
        let should_override = files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(fd) => {
                let table = task.global.litebox.descriptor_table();
                // Check for HostPtyDeviceFd marker (reopened via /dev/pts/N)
                if table.with_metadata(fd, |_: &HostPtyDeviceFd| ()).is_ok() {
                    return true;
                }
                // Check for HostStdioSourceFd (inherited stdin/stdout/stderr).
                // Use the same any-stream-is-a-tty logic as the readlink
                // override: if the host has any terminal stream, all sandbox
                // stdio fds should report the host PTY identity.  This
                // matches the ioctl layer's fallback in
                // host_stdio_stream_for_fd which routes any stdio fd to
                // whichever host stream IS a terminal.
                if let Ok(crate::HostStdioSourceFd(source_fd)) =
                    table.with_metadata(fd, |m: &crate::HostStdioSourceFd| *m)
                    && (0..=2).contains(&source_fd)
                    && [
                        litebox::platform::StdioStream::Stdin,
                        litebox::platform::StdioStream::Stdout,
                        litebox::platform::StdioStream::Stderr,
                    ]
                    .into_iter()
                    .any(|s| task.global.platform.is_a_tty(s))
                {
                    return true;
                }
                // Check for HostTtyAlias (/dev/tty opens)
                table
                    .with_metadata(fd, |_: &crate::HostTtyAlias| ())
                    .is_ok()
            }
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(_) => false, // host-PTY stat override only applies to FS aliases
            crate::RawFdRef::Eventfd(_) => false, // host-PTY stat override only applies to FS aliases
            crate::RawFdRef::Epoll(_) => false, // host-PTY stat override only applies to FS aliases
            crate::RawFdRef::Unix(_) => false,  // host-PTY stat override only applies to FS aliases
            crate::RawFdRef::HostPassthroughFd(_) => false, // host-PTY stat override only applies to FS aliases
            crate::RawFdRef::BrokerPipe(_) => false, // host-PTY stat override only applies to FS aliases
            crate::RawFdRef::BrokerSocketPair(_)
            | crate::RawFdRef::BrokerSocketDgram(_)
            | crate::RawFdRef::BrokerUnixStream(_)
            | crate::RawFdRef::BrokerSocketSeqPacket(_) => false, // host-PTY stat override only applies to FS aliases
            crate::RawFdRef::BrokerTcpConn(_) => false, // host-PTY stat override only applies to FS aliases
            crate::RawFdRef::BrokerPty(_) => false, // broker PTYs report their own synthetic stat
            crate::RawFdRef::Signalfd(_)
            | crate::RawFdRef::Inotify(_)
            | crate::RawFdRef::BrokerInetListener(_)
            | crate::RawFdRef::BrokerInetDgram(_) => false, // host-PTY stat override only applies to FS aliases,
            crate::RawFdRef::BrokerInetRaw(_) => false, // host-PTY stat override only applies to FS aliases,
        })?;
        if should_override {
            fstat.st_dev = info.dev.truncate();
            fstat.st_ino = info.ino.truncate();
            fstat.st_rdev = info.rdev.truncate();
        }
    }

    Ok(fstat)
}

/// Return a fresh inode number for an anonymous descriptor.
fn next_anon_ino() -> u64 {
    let ino = ANON_INO_COUNTER.fetch_add(1, Ordering::Relaxed);
    assert_ne!(ino, usize::MAX, "anonymous inode counter overflow");
    ino as u64
}

/// Retrieve the cached inode for an anonymous fd, or assign a new one.
///
/// The inode is stored as [`AnonIno`] entry metadata so that repeated `fstat`
/// calls on the same fd (or a `dup`'d alias) return a stable `st_ino`.
fn get_or_assign_anon_ino<FS: ShimFS, S: litebox::fd::FdEnabledSubsystem>(
    task: &Task<FS>,
    fd: &litebox::fd::TypedFd<S>,
) -> u64 {
    // Take the write lock upfront to avoid a TOCTOU race: two threads could
    // both observe "no metadata" under a read lock and each store a different
    // inode.
    let mut dt = task.global.litebox.descriptor_table_mut();
    if let Ok(ino) = dt.with_metadata::<S, AnonIno, _>(fd, |a| a.0) {
        return ino;
    }
    let ino = next_anon_ino();
    dt.set_entry_metadata(fd, AnonIno(ino));
    ino
}

pub(crate) fn get_file_descriptor_flags<FS: ShimFS>(
    raw_fd: usize,
    global: &GlobalState<FS>,
    files: &FilesState<FS>,
) -> Result<FileDescriptorFlags, Errno> {
    // Currently, only one such flag is defined: FD_CLOEXEC, the close-on-exec flag.
    // See https://www.man7.org/linux/man-pages/man2/F_GETFD.2const.html
    fn get_flags<FS: ShimFS, S: FdEnabledSubsystem>(
        global: &GlobalState<FS>,
        fd: &TypedFd<S>,
    ) -> FileDescriptorFlags {
        global
            .litebox
            .descriptor_table()
            .with_metadata(fd, |flags: &FileDescriptorFlags| *flags)
            .unwrap_or(FileDescriptorFlags::empty())
    }

    files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
        crate::RawFdRef::Fs(fd) => get_flags(global, fd),
        #[cfg(feature = "worker_local_inet")]
        crate::RawFdRef::Net(fd) => get_flags(global, fd),
        crate::RawFdRef::Eventfd(fd) => get_flags(global, fd),
        crate::RawFdRef::Epoll(fd) => get_flags(global, fd),
        crate::RawFdRef::Unix(fd) => get_flags(global, fd),
        crate::RawFdRef::HostPassthroughFd(fd) => get_flags(global, fd),
        crate::RawFdRef::BrokerPipe(fd) => get_flags(global, fd),
        crate::RawFdRef::BrokerSocketPair(fd) => get_flags(global, fd),
        crate::RawFdRef::BrokerTcpConn(fd) => get_flags(global, fd),
        crate::RawFdRef::BrokerPty(fd) => get_flags(global, fd),
        crate::RawFdRef::Signalfd(fd) => get_flags(global, fd),
        crate::RawFdRef::Inotify(fd) => get_flags(global, fd),
        crate::RawFdRef::BrokerInetListener(fd) => get_flags(global, fd),
        crate::RawFdRef::BrokerInetDgram(fd) => get_flags(global, fd),
        crate::RawFdRef::BrokerSocketDgram(fd) => get_flags(global, fd),
        crate::RawFdRef::BrokerUnixStream(fd) => get_flags(global, fd),
        crate::RawFdRef::BrokerSocketSeqPacket(fd) => get_flags(global, fd),
        crate::RawFdRef::BrokerInetRaw(fd) => get_flags(global, fd),
    })
}

fn set_file_descriptor_flags<FS: ShimFS>(
    raw_fd: usize,
    global: &GlobalState<FS>,
    files: &FilesState<FS>,
    flags: FileDescriptorFlags,
) -> Result<(), Errno> {
    fn set_flags<FS: ShimFS, S: FdEnabledSubsystem>(
        global: &GlobalState<FS>,
        fd: &TypedFd<S>,
        flags: FileDescriptorFlags,
    ) {
        let _old = global
            .litebox
            .descriptor_table_mut()
            .set_fd_metadata(fd, flags);
    }

    files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
        crate::RawFdRef::Fs(fd) => set_flags(global, fd, flags),
        #[cfg(feature = "worker_local_inet")]
        crate::RawFdRef::Net(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::Eventfd(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::Epoll(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::Unix(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::HostPassthroughFd(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::BrokerPipe(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::BrokerSocketPair(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::BrokerTcpConn(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::BrokerPty(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::Signalfd(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::Inotify(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::BrokerInetListener(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::BrokerInetDgram(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::BrokerSocketDgram(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::BrokerUnixStream(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::BrokerSocketSeqPacket(fd) => set_flags(global, fd, flags),
        crate::RawFdRef::BrokerInetRaw(fd) => set_flags(global, fd, flags),
    })?;
    Ok(())
}

impl<FS: ShimFS> Task<FS> {
    /// Get the file status of `pathname`.
    ///
    /// The `pathname` must be absolute.
    fn do_stat(&self, pathname: impl path::Arg, follow_symlink: bool) -> Result<FileStat, Errno> {
        let normalized_path = pathname.normalized()?;
        let norm_str = normalized_path.as_str();

        // Handle /proc/<N>/... paths: rewrite own PID to /proc/self/,
        // and return synthetic entries for known PIDs.
        if let Some(_pid) = self.proc_pid_if_known(norm_str) {
            let sub = self.proc_pid_subpath(norm_str);
            if sub.is_empty() {
                // stat("/proc/<N>") — synthetic directory entry.
                return Ok(FileStat {
                    st_dev: ANON_INODE_DEV.truncate(),
                    st_ino: (next_anon_ino() as u64).truncate(),
                    st_mode: ((litebox_common_linux::InodeType::Dir as u32)
                        | (Mode::RUSR
                            | Mode::XUSR
                            | Mode::RGRP
                            | Mode::XGRP
                            | Mode::ROTH
                            | Mode::XOTH)
                            .bits())
                    .truncate(),
                    st_nlink: 1,
                    ..Default::default()
                });
            }
            match sub {
                "/stat" | "/status" | "/cmdline" | "/comm" => {
                    return Ok(FileStat {
                        st_dev: ANON_INODE_DEV.truncate(),
                        st_ino: (next_anon_ino() as u64).truncate(),
                        st_mode: ((litebox_common_linux::InodeType::File as u32)
                            | (Mode::RUSR | Mode::RGRP | Mode::ROTH).bits())
                        .truncate(),
                        st_nlink: 1,
                        st_size: 128,
                        ..Default::default()
                    });
                }
                "/exe" | "/cwd" | "/root" => {
                    return Ok(synthetic_symlink_stat(0));
                }
                _ => {
                    // For /fd and other subpaths, rewrite to /proc/self/ and fall through
                    if let Some(rewritten) = self.rewrite_proc_pid_to_self(norm_str) {
                        return self.do_stat(rewritten.as_str(), follow_symlink);
                    }
                }
            }
        } else if let Some(rewritten) = self.rewrite_proc_pid_to_self(norm_str) {
            return self.do_stat(rewritten.as_str(), follow_symlink);
        }

        if normalized_path.as_str() == "/proc/self/exe" {
            let exe = self.fs.borrow().exe_path.read().clone();
            if exe.is_empty() {
                return Err(Errno::ENOENT);
            }
            if !follow_symlink {
                let mut cached = PROC_SELF_EXE_INO.load(Ordering::Relaxed);
                if cached == 0 {
                    #[allow(clippy::cast_possible_truncation)]
                    let fresh = next_anon_ino() as usize;
                    match PROC_SELF_EXE_INO.compare_exchange(
                        0,
                        fresh,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => cached = fresh,
                        Err(winner) => cached = winner,
                    }
                }
                return Ok(FileStat {
                    st_dev: ANON_INODE_DEV.truncate(),
                    st_ino: (cached as u64).truncate(),
                    st_mode: ((litebox_common_linux::InodeType::SymLink as u32)
                        | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits())
                    .truncate(),
                    st_size: exe.len(),
                    st_blksize: 4096,
                    st_blocks: 0,
                    st_nlink: 1,
                    st_uid: self.credentials.euid.truncate(),
                    st_gid: self.credentials.egid.truncate(),
                    ..Default::default()
                });
            }
            let descriptors = self.global.litebox.descriptor_table();
            let status = self
                .files
                .borrow()
                .fs
                .file_status(exe.as_str(), &*descriptors)?;
            return Ok(FileStat::from(status));
        }
        // /dev/fd/N and /proc/self/fd/N — stat the underlying fd (like fstat).
        if let Some(fd_num) = normalized_path
            .as_str()
            .strip_prefix("/dev/fd/")
            .or_else(|| normalized_path.as_str().strip_prefix("/proc/self/fd/"))
            .and_then(|n| n.parse::<i32>().ok())
        {
            if !follow_symlink {
                // lstat: return a synthetic symlink entry.
                return Ok(synthetic_symlink_stat(0));
            }
            return self.sys_fstat(fd_num);
        }
        let fs_walks_follow_symlinks = self.files.borrow().fs.walks_follow_symlinks();
        if !follow_symlink && fs_walks_follow_symlinks {
            match self.do_readlink(normalized_path.as_str()) {
                Ok(target) => return Ok(synthetic_symlink_stat(target.len())),
                Err(Errno::EINVAL) => {}
                Err(err) => return Err(err),
            }
        }
        // Skip client-side symlink resolution when the FS backend follows
        // symlinks during walk (e.g., 9P with a canonicalizing broker).
        let is_host_pty = is_host_pty_device_path(normalized_path.as_str(), self.global.platform);
        let path = if follow_symlink && !fs_walks_follow_symlinks {
            self.canonicalize_path(normalized_path.as_str())?
        } else {
            normalized_path
        };
        let descriptors = self.global.litebox.descriptor_table();
        let status = self.files.borrow().fs.file_status(&path, &*descriptors)?;
        let mut result = FileStat::from(status);

        // Override st_dev/st_ino/st_rdev for the host PTY path so that
        // stat("/dev/pts/N") matches fstat(0) — required by glibc ttyname_r's
        // is_mytty() verification. Skip when a sandbox PTY shadows the path
        // (the stat already returned sandbox PTY identity with major 136-143).
        if is_host_pty
            && (result.st_rdev >> 8) < 136
            && let Some(info) = self.global.platform.host_stdin_tty_device_info()
        {
            result.st_dev = info.dev.truncate();
            result.st_ino = info.ino.truncate();
            result.st_rdev = info.rdev.truncate();
        }

        Ok(result)
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

    /// Handle syscall `newfstatat`
    pub fn sys_newfstatat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
    ) -> Result<FileStat, Errno> {
        let follow_symlinks = !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW);
        let allow_empty = flags.contains(AtFlags::AT_EMPTY_PATH);
        let supported_flags =
            AtFlags::AT_EMPTY_PATH | AtFlags::AT_SYMLINK_NOFOLLOW | AtFlags::AT_NO_AUTOMOUNT;
        let unsupported = flags & supported_flags.complement();
        if !unsupported.is_empty() {
            return Err(Errno::EINVAL);
        }

        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new_inner(dirfd, pathname, get_cwd, allow_empty)?;
        let files = self.files.borrow();
        let get_cwd = || self.fs.borrow().cwd.read().clone();

        #[cfg(feature = "trace_syscalls")]
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match &fs_path {
            FsPath::Absolute { path } => {
                litebox::log_println!(
                    self.global.platform,
                    "[STAT-TRACE] pid={} newfstatat path=\"{:?}\"",
                    self.pid,
                    path,
                );
            }
            FsPath::FdRelative { fd, path } => {
                litebox::log_println!(
                    self.global.platform,
                    "[STAT-TRACE] pid={} newfstatat fd={} rel_path=\"{:?}\"",
                    self.pid,
                    fd,
                    path,
                );
            }
            _ => {}
        }

        let fstat: FileStat = match fs_path {
            FsPath::Absolute { path } => self.do_stat(path, follow_symlinks)?,
            FsPath::Cwd => {
                let descriptors = self.global.litebox.descriptor_table();
                files.fs.file_status(get_cwd(), &*descriptors)?.into()
            }
            FsPath::Fd(fd) => {
                let Ok(raw_fd) = usize::try_from(fd) else {
                    return Err(Errno::EBADF);
                };
                descriptor_stat(raw_fd, self)?
            }
            FsPath::FdRelative { fd, path } => {
                let Ok(raw_fd) = usize::try_from(fd) else {
                    return Err(Errno::EBADF);
                };
                if !follow_symlinks && files.fs.walks_follow_symlinks() {
                    let mut target = [0u8; PATH_MAX];
                    let Ok(fd_i32) = i32::try_from(fd) else {
                        return Err(Errno::EBADF);
                    };
                    match self.sys_readlinkat(fd_i32, path.clone(), &mut target) {
                        Ok(len) => return Ok(synthetic_symlink_stat(len)),
                        Err(Errno::EINVAL) => {}
                        Err(err) => return Err(err),
                    }
                }

                files.run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                    crate::RawFdRef::Fs(dirfd) => {
                        let descriptors = self.global.litebox.descriptor_table();
                        files
                            .fs
                            .stat_at(dirfd, path, follow_symlinks, &*descriptors)
                            .map(FileStat::from)
                            .map_err(Errno::from)
                    }
                    #[cfg(feature = "worker_local_inet")]
                    crate::RawFdRef::Net(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Eventfd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Epoll(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Unix(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::HostPassthroughFd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerPipe(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerSocketPair(_)
                    | crate::RawFdRef::BrokerSocketDgram(_)
                    | crate::RawFdRef::BrokerUnixStream(_)
                    | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerTcpConn(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerPty(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::Signalfd(_)
                    | crate::RawFdRef::Inotify(_)
                    | crate::RawFdRef::BrokerInetListener(_)
                    | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                    crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
                })??
            }
        };
        Ok(fstat)
    }

    /// Handle `statx` — modern replacement for `stat`/`fstatat`.
    ///
    /// Delegates to the same resolution logic as `newfstatat`, then
    /// converts `FileStat` into the `statx` buffer layout.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::unnecessary_cast
    )]
    pub fn sys_statx(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
        _mask: u32,
    ) -> Result<StatxBuf, Errno> {
        // statx shares the same AT_* flags as newfstatat.
        let stat = self.sys_newfstatat(dirfd, pathname, flags)?;
        Ok(StatxBuf {
            stx_mask: STATX_BASIC_STATS,
            stx_blksize: stat.st_blksize as u32,
            stx_attributes: 0,
            stx_nlink: stat.st_nlink as u32,
            stx_uid: stat.st_uid,
            stx_gid: stat.st_gid,
            stx_mode: stat.st_mode as u16,
            __spare0: [0],
            stx_ino: stat.st_ino,
            stx_size: stat.st_size as u64,
            stx_blocks: stat.st_blocks as u64,
            stx_attributes_mask: 0,
            stx_atime: StatxTimestamp {
                tv_sec: stat.st_atime,
                tv_nsec: stat.st_atime_nsec as u32,
                __reserved: 0,
            },
            stx_btime: StatxTimestamp::default(),
            stx_ctime: StatxTimestamp {
                tv_sec: stat.st_ctime,
                tv_nsec: stat.st_ctime_nsec as u32,
                __reserved: 0,
            },
            stx_mtime: StatxTimestamp {
                tv_sec: stat.st_mtime,
                tv_nsec: stat.st_mtime_nsec as u32,
                __reserved: 0,
            },
            stx_rdev_major: (stat.st_rdev >> 8) as u32,
            stx_rdev_minor: (stat.st_rdev & 0xff) as u32,
            stx_dev_major: (stat.st_dev >> 8) as u32,
            stx_dev_minor: (stat.st_dev & 0xff) as u32,
            stx_mnt_id: 0,
            stx_dio_mem_align: 0,
            stx_dio_opt_align: 0,
            __spare3: [0; 12],
        })
    }

    /// Handle `statfs` — return synthetic tmpfs-like filesystem stats.
    pub fn sys_statfs(&self, pathname: impl path::Arg) -> Result<StatfsBuf, Errno> {
        // Verify the path exists.
        let path = self.resolve_path(pathname)?;
        let descriptors = self.global.litebox.descriptor_table();
        self.files
            .borrow()
            .fs
            .file_status(path, &*descriptors)
            .map_err(Errno::from)?;
        Ok(Self::synthetic_statfs())
    }

    /// Handle `fstatfs` — return synthetic tmpfs-like filesystem stats.
    pub fn sys_fstatfs(&self, fd: i32) -> Result<StatfsBuf, Errno> {
        let Ok(raw_fd) = usize::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        // Verify the fd is valid by attempting to stat it.
        descriptor_stat(raw_fd, self)?;
        Ok(Self::synthetic_statfs())
    }

    fn synthetic_statfs() -> StatfsBuf {
        StatfsBuf {
            f_type: TMPFS_MAGIC,
            f_bsize: 4096,
            f_blocks: 1024 * 1024,
            f_bfree: 1024 * 1024,
            f_bavail: 1024 * 1024,
            f_files: 1024 * 1024,
            f_ffree: 1024 * 1024,
            f_fsid: [0, 0],
            f_namelen: 255,
            f_frsize: 4096,
            f_flags: 0,
            __spare: [0; 4],
        }
    }

    /// Handle `fchmodat` — change file mode relative to directory fd.
    pub fn sys_fchmodat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        mode: u32,
    ) -> Result<(), Errno> {
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        let mode = litebox::fs::Mode::from_bits_truncate(mode);
        match fs_path {
            FsPath::Absolute { path } => {
                // `/proc/self/fd/N` and `/dev/fd/N` are guest-relative fd
                // references: `N` names a *guest* fd, meaningful only in the
                // guest fd namespace. Resolve to the fd's real path here (as
                // `openat`/`stat` already do) so the broker chmods the file
                // behind fd `N` — not whatever its own host fd `N` happens to
                // point at. glibc `tar` depends on this: it sets extracted-file
                // modes via `fchmodat(AT_FDCWD, "/proc/self/fd/N", mode)`, and
                // without the translation every such call mis-resolves
                // broker-side (the broker canonicalizes the literal path
                // against its own `/proc/self/fd`).
                let procfd = path.to_str().ok().and_then(|s| {
                    (s.starts_with("/proc/self/fd/") || s.starts_with("/dev/fd/"))
                        .then(|| s.to_string())
                });
                let path = match procfd {
                    Some(s) => CString::new(self.do_readlink(&s)?).map_err(|_| Errno::EINVAL)?,
                    None => path,
                };
                let mut descriptors = self.global.litebox.descriptor_table_mut();
                self.files
                    .borrow()
                    .fs
                    .chmod(path, mode, &mut *descriptors)
                    .map_err(Errno::from)
            }
            FsPath::Cwd => {
                let mut descriptors = self.global.litebox.descriptor_table_mut();
                self.files
                    .borrow()
                    .fs
                    .chmod(get_cwd(), mode, &mut *descriptors)
                    .map_err(Errno::from)
            }
            FsPath::Fd(_fd) => Err(Errno::EINVAL),
            FsPath::FdRelative { fd, path } => {
                let abs = self.resolve_dirfd_path(fd, &path)?;
                let mut descriptors = self.global.litebox.descriptor_table_mut();
                self.files
                    .borrow()
                    .fs
                    .chmod(abs, mode, &mut *descriptors)
                    .map_err(Errno::from)
            }
        }
    }

    pub(crate) fn sys_fcntl(
        &self,
        fd: i32,
        arg: FcntlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        let Ok(desc) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match arg {
            FcntlArg::GETFD => Ok(get_file_descriptor_flags(desc, &self.global, &files)?.bits()),
            FcntlArg::SETFD(flags) => {
                set_file_descriptor_flags(desc, &self.global, &files, flags).map(|()| 0)
            }
            FcntlArg::GETFL => Ok(fcntl_status_flags(self, &files, desc)?.bits()),
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
                if let Ok(fd) = files
                    .raw_descriptor_store
                    .read()
                    .fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(desc)
                {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(&fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        let diff = (file.get_status() & setfl_mask) ^ flags;
                        if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                            log_unsupported!("unsupported flags");
                        }
                        file.set_status(flags);
                    });
                    return Ok(0);
                }
                files.run_on_raw_fd(desc, |raw_fd_ref| match raw_fd_ref {
                    crate::RawFdRef::Fs(fd) => {
                        let mut descriptors = self.global.litebox.descriptor_table_mut();
                        let new_flags = descriptors
                            .with_metadata_mut(fd, |crate::StdioStatusFlags(f)| {
                                let diff = (*f & setfl_mask) ^ flags;
                                if diff
                                    .intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME)
                                {
                                    log_unsupported!("unsupported flags");
                                }
                                f.toggle(diff);
                                *f
                            })
                            .map_err(|err| match err {
                                MetadataError::ClosedFd | MetadataError::NoSuchMetadata => {
                                    Errno::EBADF
                                }
                            })?;
                        files
                            .fs
                            .set_open_status_flags(fd, new_flags, &mut *descriptors)
                            .map_err(|_| Errno::EBADF)
                    }
                    #[cfg(feature = "worker_local_inet")]
                    crate::RawFdRef::Net(fd) => {
                        setfl_in_metadata!(
                            fd,
                            crate::syscalls::net::SocketOFlags,
                            unreachable!("all sockets have SocketOFlags when created")
                        )
                    }
                    crate::RawFdRef::Eventfd(fd) => {
                        toggle_flags!(fd);
                        Ok(())
                    }
                    crate::RawFdRef::Epoll(fd) => {
                        toggle_flags!(fd);
                        Ok(())
                    }
                    crate::RawFdRef::Unix(fd) => {
                        toggle_flags!(fd);
                        Ok(())
                    }
                    crate::RawFdRef::HostPassthroughFd(fd) => {
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle(fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file: &crate::syscalls::host_passthrough_fd::HostPassthroughFdEntry| {
                            let diff = (file.get_status() & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            if diff.intersects(OFlags::NONBLOCK) {
                                self.global.platform.set_host_fd_nonblocking(
                                    file.raw_fd(),
                                    flags.intersects(OFlags::NONBLOCK),
                                )?;
                            }
                            file.set_status(flags);
                            Ok(())
                        })
                    }
                    crate::RawFdRef::BrokerPipe(fd) => {
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle(fd)
                            .ok_or(Errno::EBADF)?;
                        let arm_result = handle.with_entry(|file| {
                            let diff = (file.get_status() & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            file.set_status(flags);
                            Ok(())
                        });
                        let nonblocking = flags.intersects(OFlags::NONBLOCK);
                        let receiver = handle.with_entry(|file| {
                            file.direction()
                                == litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Read
                        });
                        let guest_created = self
                            .global
                            .litebox
                            .descriptor_table()
                            .with_metadata(fd, |crate::GuestCreatedPipe| true)
                            .unwrap_or(false);
                        // Mirror the local-pipe delayed-fork marker for broker pipes.
                        if receiver
                            && guest_created
                            && nonblocking
                            && self.recent_delayed_fork_resume.replace(false)
                        {
                            let _ = self
                                .global
                                .litebox
                                .descriptor_table_mut()
                                .set_entry_metadata(fd, crate::PipeNonblockEagainOnce(true));
                        }
                        arm_result
                    }
                    crate::RawFdRef::BrokerSocketPair(fd) => {
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle(fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file| {
                            let diff = (file.get_status() & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            file.set_status(flags);
                            Ok(())
                        })
                    }
                    crate::RawFdRef::BrokerTcpConn(fd) => {
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle(fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file| {
                            let diff = (file.get_status() & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            file.set_status(flags);
                            Ok(())
                        })
                    }
                    crate::RawFdRef::BrokerPty(fd) => {
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle(fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file| {
                            let diff = (file.get_status() & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            file.set_status(flags);
                            Ok(())
                        })
                    }
                    crate::RawFdRef::Signalfd(fd) => {
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle(fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file| {
                            let diff = (file.get_status() & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            file.set_status(flags);
                            Ok(())
                        })
                    }
                    crate::RawFdRef::Inotify(fd) => {
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle(fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file| {
                            let diff = (file.get_status() & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            file.set_status(flags);
                            Ok(())
                        })
                    }
                    crate::RawFdRef::BrokerInetListener(fd) => {
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle(fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file| {
                            let diff = (file.get_status() & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            file.set_status(flags);
                            Ok(())
                        })
                    }
                    crate::RawFdRef::BrokerInetDgram(fd) => {
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle(fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file| {
                            let diff = (file.get_status() & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            file.set_status(flags);
                            Ok(())
                        })
                    }
                    crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
                    crate::RawFdRef::BrokerUnixStream(_) => Err(Errno::EBADF),
                    crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
                    crate::RawFdRef::BrokerInetRaw(fd) => {
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle(fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file| {
                            let diff = (file.get_status() & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            file.set_status(flags);
                            Ok(())
                        })
                    }
                })??;
                Ok(0)
            }
            FcntlArg::GETLK(lock) => {
                let open_flags = fcntl_status_flags(self, &files, desc)?;
                let _ = validate_fcntl_lock_fd(open_flags)?;
                emulate_fcntl_getlk(lock, || self.park_if_deferred())
            }
            FcntlArg::SETLK(lock) | FcntlArg::SETLKW(lock) => {
                let open_flags = fcntl_status_flags(self, &files, desc)?;
                emulate_fcntl_setlk(lock, open_flags)
            }
            FcntlArg::DUPFD { cloexec, min_fd } => {
                let max_fd = self
                    .process()
                    .limits
                    .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE);
                if min_fd as usize >= max_fd {
                    return Err(Errno::EINVAL);
                }
                let new_file = self.do_dup_at_or_above(
                    desc,
                    if cloexec {
                        OFlags::CLOEXEC
                    } else {
                        OFlags::empty()
                    },
                    min_fd as usize,
                )?;
                debug_assert!(new_file >= min_fd as usize);
                Ok(new_file.try_into().unwrap())
            }
            _ => unimplemented!(),
        }
    }

    /// Handle syscall `getcwd`
    pub fn sys_getcwd(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let cwd = self.fs.borrow().cwd.read().clone();
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
        use litebox::path::Arg as _;

        // Resolve relative paths against CWD, then normalize (handle `.` / `..`).
        let resolved = self.resolve_path(pathname)?;
        let abs_path = resolved.normalized().map_err(|_| Errno::EINVAL)?;

        // Verify the path exists and is a directory.
        let descriptors = self.global.litebox.descriptor_table();
        match self
            .files
            .borrow()
            .fs
            .file_status(abs_path.as_str(), &*descriptors)
        {
            Ok(status) => {
                if status.file_type != FileType::Directory {
                    return Err(Errno::ENOTDIR);
                }
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

    /// Handle syscall `fchdir` — change working directory via an open directory fd.
    pub fn sys_fchdir(&self, fd: i32) -> Result<(), Errno> {
        use litebox::fs::FileType;

        let raw = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        let files = self.files.borrow();

        // Get the path and verify it's a directory.
        let dir_path = files.run_on_raw_fd(raw, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(typed_fd) => {
                let descriptors = self.global.litebox.descriptor_table();
                let status = files
                    .fs
                    .fd_file_status(typed_fd, &*descriptors)
                    .map_err(Errno::from)?;
                if status.file_type != FileType::Directory {
                    return Err(Errno::ENOTDIR);
                }
                files
                    .fs
                    .fd_path(typed_fd, &*descriptors)
                    .ok_or(Errno::EBADF)
            }
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::Eventfd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::Epoll(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::Unix(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::HostPassthroughFd(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerPipe(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerSocketPair(_)
            | crate::RawFdRef::BrokerSocketDgram(_)
            | crate::RawFdRef::BrokerUnixStream(_)
            | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerTcpConn(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerPty(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::Signalfd(_)
            | crate::RawFdRef::Inotify(_)
            | crate::RawFdRef::BrokerInetListener(_)
            | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
        })??;

        let mut new_cwd = dir_path;
        if !new_cwd.ends_with('/') {
            new_cwd.push('/');
        }

        drop(files);
        *self.fs.borrow().cwd.write() = new_cwd;
        Ok(())
    }
}

const DEFAULT_PIPE_BUF_SIZE: usize = 1024 * 1024;

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `pipe2`
    pub fn sys_pipe2(&self, flags: OFlags) -> Result<(u32, u32), Errno> {
        if flags.contains((OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::DIRECT).complement()) {
            return Err(Errno::EINVAL);
        }
        if flags.contains(OFlags::DIRECT) {
            todo!("O_DIRECT not supported");
        }
        let cloexec = flags.contains(OFlags::CLOEXEC);

        let provider = super::broker_pipe::broker_pipe_provider().ok_or(Errno::ENODEV)?;
        let entry_flags = flags & OFlags::STATUS_FLAGS_MASK;
        let (read_handle, write_handle) = provider
            .create_pipe(
                DEFAULT_PIPE_BUF_SIZE as u64,
                // See `man 7 pipe` for `PIPE_BUF`. On Linux, this is 4096.
                4096,
            )
            .map_err(|_| Errno::ENODEV)?;

        let writer_entry = super::broker_pipe::BrokerPipeFd::<crate::Platform>::new(
            alloc::sync::Arc::clone(&provider),
            write_handle,
            litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Write,
            entry_flags,
            0, // creation_site: sys_pipe2
        );
        let reader_entry = super::broker_pipe::BrokerPipeFd::<crate::Platform>::new(
            provider,
            read_handle,
            litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Read,
            entry_flags,
            0, // creation_site: sys_pipe2
        );
        let mut dt = self.global.litebox.descriptor_table_mut();
        let writer = dt.insert::<super::broker_pipe::BrokerPipeSubsystem>(writer_entry);
        let reader = dt.insert::<super::broker_pipe::BrokerPipeSubsystem>(reader_entry);
        {
            let initial_status = flags & OFlags::NONBLOCK;
            let _ = dt.set_entry_metadata(
                &writer,
                crate::PipeStatusFlags(initial_status | OFlags::WRONLY),
            );
            let _ = dt.set_entry_metadata(
                &reader,
                crate::PipeStatusFlags(initial_status | OFlags::RDONLY),
            );
            let _ = dt.set_entry_metadata(&writer, crate::GuestCreatedPipe);
            let _ = dt.set_entry_metadata(&reader, crate::GuestCreatedPipe);
        }
        if cloexec {
            let _ = dt.set_fd_metadata(&writer, FileDescriptorFlags::FD_CLOEXEC);
            let _ = dt.set_fd_metadata(&reader, FileDescriptorFlags::FD_CLOEXEC);
        }
        drop(dt);

        let files = self.files.borrow();
        let wr_raw_fd = files.insert_raw_fd(writer).map_err(|writer| {
            let _ = self.global.litebox.descriptor_table_mut().remove(&writer);
            Errno::EMFILE
        })?;
        let rd_raw_fd = files.insert_raw_fd(reader).map_err(|reader| {
            let _ = self.do_close(wr_raw_fd);
            let _ = self.global.litebox.descriptor_table_mut().remove(&reader);
            Errno::EMFILE
        })?;
        Ok((
            rd_raw_fd.try_into().map_err(|_| Errno::EMFILE)?,
            wr_raw_fd.try_into().map_err(|_| Errno::EMFILE)?,
        ))
    }

    pub fn sys_eventfd2(&self, initval: u32, flags: EfdFlags) -> Result<u32, Errno> {
        if flags
            .contains((EfdFlags::SEMAPHORE | EfdFlags::CLOEXEC | EfdFlags::NONBLOCK).complement())
        {
            return Err(Errno::EINVAL);
        }

        // Eager broker-backed creation: every guest-visible eventfd
        // lives in the broker from birth. This eliminates the
        // Local→BrokerBacked lazy-promotion-at-fork mechanism that
        // used to mutate the variant in `ensure_broker_backed_for_fork`.
        // Trade-off: one broker round-trip per `eventfd2()` call,
        // even in the single-worker case, in exchange for a simpler
        // fork-snapshot path and a single state-location invariant.
        //
        // If no broker provider has been registered (runner bootstrap
        // bug, or a unit-test path that didn't install one), surface
        // ENODEV — silently falling back to a local-only eventfd
        // would break the cross-worker contract (a sibling worker
        // can't reach a local-only eventfd).
        let provider = super::eventfd::broker_eventfd_provider().ok_or(Errno::ENODEV)?;
        let handle = provider
            .create_eventfd(u64::from(initval), flags.contains(EfdFlags::SEMAPHORE))
            .map_err(|_| Errno::ENODEV)?;
        let eventfd = super::eventfd::EventFile::new_broker_backed(provider, handle, flags);
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<super::eventfd::EventfdSubsystem>(eventfd);
        if flags.contains(EfdFlags::CLOEXEC) {
            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        drop(dt);
        let files = self.files.borrow();
        #[cfg(feature = "trace_syscalls")]
        let object_id = typed.object_id().as_u64();
        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
            self.global
                .litebox
                .descriptor_table_mut()
                .remove(&typed)
                .unwrap();
            Errno::EMFILE
        })?;
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[STDIO-MAP] pid={} create fd={} kind=eventfd object_id={} flags={:?}",
            self.pid,
            raw_fd,
            object_id,
            flags,
        );
        Ok(raw_fd.try_into().unwrap())
    }
    ///
    /// Creates an anonymous regular file backed by the in-memory filesystem.
    /// The returned fd behaves like a normal seekable file but has no
    /// directory entry — only the descriptor keeps it alive.
    pub fn sys_memfd_create(
        &self,
        name: alloc::ffi::CString,
        flags: litebox_common_linux::MemfdFlags,
    ) -> Result<u32, Errno> {
        use litebox::fs::errors::CreateAnonymousFileError;
        use litebox_common_linux::MemfdFlags;

        let known = MemfdFlags::CLOEXEC
            | MemfdFlags::ALLOW_SEALING
            | MemfdFlags::HUGETLB
            | MemfdFlags::NOEXEC_SEAL
            | MemfdFlags::EXEC;
        if flags.intersects(known.complement()) {
            return Err(Errno::EINVAL);
        }
        if flags.contains(MemfdFlags::HUGETLB) {
            unimplemented!(
                "litebox does not support hugetlb memfd files: no huge-page backing store"
            );
        }
        // MFD_EXEC and MFD_NOEXEC_SEAL are mutually exclusive.
        if flags.contains(MemfdFlags::EXEC) && flags.contains(MemfdFlags::NOEXEC_SEAL) {
            return Err(Errno::EINVAL);
        }

        let name_str = name.to_string_lossy();
        // Strip execute bits when MFD_NOEXEC_SEAL is set, matching Linux.
        let mode = if flags.contains(MemfdFlags::NOEXEC_SEAL) {
            litebox::fs::Mode::from_bits_truncate(0o666)
        } else {
            litebox::fs::Mode::from_bits_truncate(0o777)
        };
        let files = self.files.borrow();
        let mut descriptors = self.global.litebox.descriptor_table_mut();
        let file = files
            .fs
            .create_anonymous_file(&name_str, mode, &mut *descriptors)
            .map_err(|e| match e {
                CreateAnonymousFileError::NotSupported => {
                    todo!("ENOSYS audit: memfd_create on filesystem without anonymous-file support; reachable but not implemented")
                }
                CreateAnonymousFileError::Io | _ => Errno::EIO,
            })?;
        {
            if flags.contains(MemfdFlags::CLOEXEC) {
                let old = descriptors.set_fd_metadata(&file, FileDescriptorFlags::FD_CLOEXEC);
                assert!(old.is_none());
            }
            let status = OFlags::RDWR | OFlags::LARGEFILE;
            let old = descriptors.set_entry_metadata(&file, crate::StdioStatusFlags(status));
            assert!(old.is_none());
        }
        let raw_fd = match files.insert_raw_fd(file) {
            Ok(raw_fd) => raw_fd,
            Err(file) => {
                files.fs.close(&file, &mut *descriptors).unwrap();
                return Err(Errno::EMFILE);
            }
        };
        Ok(raw_fd.try_into().unwrap())
    }

    pub fn sys_inotify_init1(&self, flags: OFlags) -> Result<u32, Errno> {
        if flags.intersects((OFlags::CLOEXEC | OFlags::NONBLOCK).complement()) {
            return Err(Errno::EINVAL);
        }
        let Some(provider) = super::inotify::broker_inotify_provider() else {
            return Err(Errno::ENOSYS);
        };
        let handle = provider
            .inotify_init1(flags.bits() as u32)
            .map_err(super::broker_backed::broker_err_to_errno)?;
        let file = super::inotify::InotifyFile::new(provider, handle, flags);
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<super::inotify::InotifySubsystem>(file);
        if flags.contains(OFlags::CLOEXEC) {
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

    pub fn sys_inotify_add_watch(
        &self,
        fd: i32,
        pathname: impl path::Arg,
        mask: u32,
    ) -> Result<u32, Errno> {
        let raw_fd = u32::try_from(fd)
            .map_err(|_| Errno::EBADF)
            .and_then(|fd| usize::try_from(fd).map_err(|_| Errno::EBADF))?;
        let resolved = self.resolve_path(pathname)?;
        self.do_stat(resolved.clone(), true)?;
        let resolved = resolved.into_string().map_err(|_| Errno::EINVAL)?;
        let files = self.files.borrow();
        let fd = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::inotify::InotifySubsystem>(raw_fd)
            .map_err(|_| Errno::EBADF)?;
        let handle = self
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(|file| {
            file.add_watch(&resolved, mask)
                .and_then(|wd| u32::try_from(wd).map_err(|_| Errno::EINVAL))
        })
    }

    pub fn sys_inotify_rm_watch(&self, fd: i32, wd: i32) -> Result<(), Errno> {
        let raw_fd = u32::try_from(fd)
            .map_err(|_| Errno::EBADF)
            .and_then(|fd| usize::try_from(fd).map_err(|_| Errno::EBADF))?;
        let files = self.files.borrow();
        let fd = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::inotify::InotifySubsystem>(raw_fd)
            .map_err(|_| Errno::EBADF)?;
        let handle = self
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(|file| file.rm_watch(wd))
    }

    pub fn sys_timerfd_create(&self, clockid: ClockId, flags: TimerfdFlags) -> Result<u32, Errno> {
        if flags.intersects((TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK).complement()) {
            return Err(Errno::EINVAL);
        }
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match clockid {
            ClockId::RealTime
            | ClockId::RealtimeCoarse
            | ClockId::Monotonic
            | ClockId::MonotonicCoarse
            | ClockId::MonotonicRaw
            | ClockId::Boottime => {}
            _ => return Err(Errno::EINVAL),
        }

        let provider = super::eventfd::broker_timerfd_provider().ok_or(Errno::ENODEV)?;
        let handle = provider
            .create_timerfd(super::eventfd::timerfd_clockid_raw(clockid)?, flags.bits())
            .map_err(super::broker_backed::broker_err_to_errno)?;
        let timerfd = super::eventfd::EventFile::new_timer_broker_backed(provider, handle, flags);
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<super::eventfd::EventfdSubsystem>(timerfd);
        if flags.contains(TimerfdFlags::CLOEXEC) {
            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        drop(dt);
        // Eagerly subscribe to the broker timer so a blocking read() that is
        // not preceded by poll/epoll (which would subscribe via
        // register_observer) is still woken when the timer fires. Mirrors
        // install_eventfd_at_slot's pre-subscribe for inherited fds; without
        // it, sys_timerfd_create + read() hangs (TFD.basic_arm_and_read).
        self.global.litebox.descriptor_table().with_entry(
            &typed,
            |ef: &super::eventfd::EventFile<crate::Platform>| {
                ef.pre_subscribe_for_broker_blocking_read();
            },
        );
        let files = self.files.borrow();
        #[cfg(feature = "trace_syscalls")]
        let object_id = typed.object_id().as_u64();
        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
            self.global
                .litebox
                .descriptor_table_mut()
                .remove(&typed)
                .unwrap();
            Errno::EMFILE
        })?;
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[STDIO-MAP] pid={} create fd={} kind=timerfd object_id={} flags={:?}",
            self.pid,
            raw_fd,
            object_id,
            flags,
        );
        Ok(raw_fd.try_into().unwrap())
    }

    pub fn sys_timerfd_settime(
        &self,
        fd: i32,
        flags: TimerfdTimerFlags,
        new_value: ItimerSpec,
        old_value: Option<MutPtr<ItimerSpec>>,
    ) -> Result<(), Errno> {
        if flags.intersects(
            (TimerfdTimerFlags::ABSTIME | TimerfdTimerFlags::CANCEL_ON_SET).complement(),
        ) {
            return Err(Errno::EINVAL);
        }
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let handle = {
            let rds = files.raw_descriptor_store.read();
            let typed = rds
                .fd_from_raw_integer::<super::eventfd::EventfdSubsystem>(raw_fd)
                .map_err(|_| Errno::EBADF)?;
            self.global
                .litebox
                .descriptor_table()
                .entry_handle(&typed)
                .ok_or(Errno::EBADF)?
        };
        let old = handle.with_entry(|file| file.set_timer(flags, new_value))?;
        if let Some(old_value) = old_value {
            old_value.write_at_offset(0, old).ok_or(Errno::EFAULT)?;
        }
        Ok(())
    }

    pub fn sys_timerfd_gettime(&self, fd: i32) -> Result<ItimerSpec, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let handle = {
            let rds = files.raw_descriptor_store.read();
            let typed = rds
                .fd_from_raw_integer::<super::eventfd::EventfdSubsystem>(raw_fd)
                .map_err(|_| Errno::EBADF)?;
            self.global
                .litebox
                .descriptor_table()
                .entry_handle(&typed)
                .ok_or(Errno::EBADF)?
        };
        handle.with_entry(super::eventfd::EventFile::get_timer)
    }

    /// Forward a terminal ioctl to the host via the platform's semantic
    /// terminal methods.
    ///
    /// Maps the fd's device type to the corresponding host stdio stream and
    /// calls `get_terminal_attributes`, `set_terminal_attributes`,
    /// `get_window_size`, or `set_window_size` as appropriate.
    fn host_stdio_stream_for_fd(
        &self,
        fs: &FS,
        fd: &TypedFd<FS>,
    ) -> Result<litebox::platform::StdioStream, Errno> {
        use litebox::platform::StdioStream;

        let descriptors = self.global.litebox.descriptor_table();
        let status = fs
            .fd_file_status(fd, &*descriptors)
            .map_err(|_| Errno::EBADF)?;
        let preferred = match status.node_info.ino {
            9 | 12 => StdioStream::Stdin,
            10 => StdioStream::Stdout,
            _ => StdioStream::Stderr,
        };

        // Only return the stream if the host fd is actually a TTY.
        // Don't fall through to unrelated fds — that breaks ENOTTY
        // semantics (e.g., ioctl on stdout should fail if stdout is a pipe,
        // not secretly use stdin's TTY).
        if self.global.platform.is_a_tty(preferred) {
            Ok(preferred)
        } else {
            Err(Errno::ENOTTY)
        }
    }

    fn host_tty_session_id(&self) -> Result<litebox::process::SessionId, Errno> {
        self.global
            .litebox
            .process_registry()
            .get_sid(self.process_id)
            .ok_or(Errno::ESRCH)
    }

    fn set_host_tty_foreground_pgrp(&self, pgrp: i32) -> Result<(), Errno> {
        use litebox::process::ProcessGroupId;

        if pgrp <= 0 {
            return Err(Errno::EINVAL);
        }
        let pgid = ProcessGroupId(u32::try_from(pgrp).map_err(|_| Errno::EINVAL)?);
        let group_exists = self
            .global
            .litebox
            .process_registry()
            .process_group_exists_in_session(self.process_id, pgid)
            .ok_or(Errno::ESRCH)?;
        if !group_exists {
            return Err(Errno::EPERM);
        }
        *self.global.host_tty_foreground_pgrp.lock() = pgid;
        Ok(())
    }

    fn host_stdio_ioctl(
        &self,
        fs: &FS,
        fd: &TypedFd<FS>,
        arg: &IoctlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        use litebox::platform::StdioIoctlError;

        /// Map a `StdioIoctlError` to an `Errno`.
        fn ioctl_err_to_errno(e: StdioIoctlError) -> Errno {
            // reason: unsupported variants intentionally share this fallback path.
            #[allow(clippy::wildcard_enum_match_arm)]
            match e {
                StdioIoctlError::NotATerminal => Errno::ENOTTY,
                _ => Errno::EIO,
            }
        }

        let stream = self.host_stdio_stream_for_fd(fs, fd)?;

        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match arg {
            IoctlArg::TCGETS(termios_ptr) => {
                // Non-init processes may have a shadow termios from a
                // silently-accepted TCSETS. Return the shadow if present
                // so TCGETS reflects what the caller set.
                let shadow = self.global.host_tty_shadow_termios.lock().clone();
                let is_init =
                    Some(self.process_id) == self.global.litebox.process_registry().root_pid();
                let attrs = if !is_init && let Some(ref shadow_attrs) = shadow {
                    shadow_attrs.clone()
                } else {
                    self.global
                        .platform
                        .get_terminal_attributes(stream)
                        .map_err(ioctl_err_to_errno)?
                };
                termios_ptr
                    .write_at_offset(
                        0,
                        litebox_common_linux::Termios {
                            c_iflag: attrs.c_iflag,
                            c_oflag: attrs.c_oflag,
                            c_cflag: attrs.c_cflag,
                            c_lflag: attrs.c_lflag,
                            c_line: attrs.c_line,
                            c_cc: attrs.c_cc,
                        },
                    )
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TCSETS(termios_ptr) => {
                let t: litebox_common_linux::Termios =
                    termios_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let attrs = litebox::platform::TerminalAttributes {
                    c_iflag: t.c_iflag,
                    c_oflag: t.c_oflag,
                    c_cflag: t.c_cflag,
                    c_lflag: t.c_lflag,
                    c_line: t.c_line,
                    c_cc: t.c_cc,
                };
                // Store in shadow — the sandbox never modifies the host terminal.
                *self.global.host_tty_shadow_termios.lock() = Some(attrs);
                Ok(0)
            }
            IoctlArg::TCSETSW(termios_ptr) => {
                let t: litebox_common_linux::Termios =
                    termios_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let attrs = litebox::platform::TerminalAttributes {
                    c_iflag: t.c_iflag,
                    c_oflag: t.c_oflag,
                    c_cflag: t.c_cflag,
                    c_lflag: t.c_lflag,
                    c_line: t.c_line,
                    c_cc: t.c_cc,
                };
                *self.global.host_tty_shadow_termios.lock() = Some(attrs);
                Ok(0)
            }
            IoctlArg::TCSETSF(termios_ptr) => {
                let t: litebox_common_linux::Termios =
                    termios_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let attrs = litebox::platform::TerminalAttributes {
                    c_iflag: t.c_iflag,
                    c_oflag: t.c_oflag,
                    c_cflag: t.c_cflag,
                    c_lflag: t.c_lflag,
                    c_line: t.c_line,
                    c_cc: t.c_cc,
                };
                *self.global.host_tty_shadow_termios.lock() = Some(attrs);
                Ok(0)
            }
            IoctlArg::TCGETS2(termios2_ptr) => {
                let shadow = self.global.host_tty_shadow_termios.lock().clone();
                let is_init =
                    Some(self.process_id) == self.global.litebox.process_registry().root_pid();
                let attrs = if !is_init && let Some(ref shadow_attrs) = shadow {
                    shadow_attrs.clone()
                } else {
                    self.global
                        .platform
                        .get_terminal_attributes(stream)
                        .map_err(ioctl_err_to_errno)?
                };
                termios2_ptr
                    .write_at_offset(
                        0,
                        litebox_common_linux::Termios2 {
                            c_iflag: attrs.c_iflag,
                            c_oflag: attrs.c_oflag,
                            c_cflag: attrs.c_cflag,
                            c_lflag: attrs.c_lflag,
                            c_line: attrs.c_line,
                            c_cc: attrs.c_cc,
                            c_ispeed: 0,
                            c_ospeed: 0,
                        },
                    )
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TCSETS2(termios2_ptr)
            | IoctlArg::TCSETSW2(termios2_ptr)
            | IoctlArg::TCSETSF2(termios2_ptr) => {
                let t: litebox_common_linux::Termios2 =
                    termios2_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let attrs = litebox::platform::TerminalAttributes {
                    c_iflag: t.c_iflag,
                    c_oflag: t.c_oflag,
                    c_cflag: t.c_cflag,
                    c_lflag: t.c_lflag,
                    c_line: t.c_line,
                    c_cc: t.c_cc,
                };
                *self.global.host_tty_shadow_termios.lock() = Some(attrs);
                Ok(0)
            }
            IoctlArg::TIOCGWINSZ(ws_ptr) => {
                let size = self
                    .global
                    .platform
                    .get_window_size(stream)
                    .map_err(ioctl_err_to_errno)?;
                ws_ptr
                    .write_at_offset(
                        0,
                        litebox_common_linux::Winsize {
                            row: size.rows,
                            col: size.cols,
                            xpixel: size.xpixel,
                            ypixel: size.ypixel,
                        },
                    )
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCSWINSZ(ws_ptr) => {
                let ws: litebox_common_linux::Winsize =
                    ws_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let size = litebox::platform::WindowSize {
                    rows: ws.row,
                    cols: ws.col,
                    xpixel: ws.xpixel,
                    ypixel: ws.ypixel,
                };
                self.global
                    .platform
                    .set_window_size(stream, &size)
                    .map_err(ioctl_err_to_errno)?;
                Ok(0)
            }
            IoctlArg::TIOCGPGRP(pgrp) => {
                // Return the caller's own pgid rather than the shared
                // host_tty_foreground_pgrp.  After setsid() the child's
                // pgid diverges from the init-owned foreground value, and
                // /dev/tty always routes here (major 5), so returning the
                // stored global would make the child think it's in the
                // background.  Returning the caller's pgid guarantees
                // tcgetpgrp() == getpgrp() for every process.
                let caller_pgid = i32::try_from(self.sys_getpgid(0).unwrap_or(1)).unwrap_or(1);
                pgrp.write_at_offset(0, caller_pgid).ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCGSID(sid) => {
                let session_id = i32::try_from(self.host_tty_session_id()?.as_u32())
                    .map_err(|_| Errno::EINVAL)?;
                sid.write_at_offset(0, session_id).ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCSPGRP(pgrp) => {
                let foreground_pgrp = pgrp.read_at_offset(0).ok_or(Errno::EFAULT)?;
                self.set_host_tty_foreground_pgrp(foreground_pgrp)?;
                Ok(0)
            }
            // These are no-ops for stdio: TIOCSCTTY (already controlling terminal),
            // TIOCNOTTY (detach), TIOCSPTLK (unlock PTY).
            IoctlArg::TIOCSCTTY | IoctlArg::TIOCNOTTY | IoctlArg::TIOCSPTLK(_) => Ok(0),
            _ => Err(Errno::ENOTTY),
        }
    }

    fn broker_pty_ioctl_entry(
        &self,
        entry: &super::broker_pty::BrokerPtyFd<Platform>,
        arg: &IoctlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match arg {
            IoctlArg::TCGETS(termios) => {
                let payload = entry.ioctl(PtyIoctlOp::Tcgets, &[])?;
                if payload.len() != 36 {
                    return Err(Errno::EIO);
                }
                let mut c_cc = [0u8; 19];
                c_cc.copy_from_slice(&payload[17..36]);
                termios
                    .write_at_offset(
                        0,
                        litebox_common_linux::Termios {
                            c_iflag: u32::from_le_bytes(payload[0..4].try_into().unwrap()),
                            c_oflag: u32::from_le_bytes(payload[4..8].try_into().unwrap()),
                            c_cflag: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
                            c_lflag: u32::from_le_bytes(payload[12..16].try_into().unwrap()),
                            c_line: payload[16],
                            c_cc,
                        },
                    )
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TCSETS(termios_ptr)
            | IoctlArg::TCSETSW(termios_ptr)
            | IoctlArg::TCSETSF(termios_ptr) => {
                let t: litebox_common_linux::Termios =
                    termios_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let mut payload = Vec::with_capacity(36);
                payload.extend_from_slice(&t.c_iflag.to_le_bytes());
                payload.extend_from_slice(&t.c_oflag.to_le_bytes());
                payload.extend_from_slice(&t.c_cflag.to_le_bytes());
                payload.extend_from_slice(&t.c_lflag.to_le_bytes());
                payload.push(t.c_line);
                payload.extend_from_slice(&t.c_cc);
                entry.ioctl(PtyIoctlOp::Tcsets, &payload)?;
                Ok(0)
            }
            IoctlArg::TCGETS2(termios2_ptr) => {
                // Reuse the same broker Tcgets op (which returns the
                // 36-byte termios payload); fill `c_ispeed`/`c_ospeed`
                // with 0 — PTYs have no real serial line, so glibc
                // treats this as "use the CBAUD bits in c_cflag",
                // which is preserved exactly.
                let payload = entry.ioctl(PtyIoctlOp::Tcgets, &[])?;
                if payload.len() != 36 {
                    return Err(Errno::EIO);
                }
                let mut c_cc = [0u8; 19];
                c_cc.copy_from_slice(&payload[17..36]);
                termios2_ptr
                    .write_at_offset(
                        0,
                        litebox_common_linux::Termios2 {
                            c_iflag: u32::from_le_bytes(payload[0..4].try_into().unwrap()),
                            c_oflag: u32::from_le_bytes(payload[4..8].try_into().unwrap()),
                            c_cflag: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
                            c_lflag: u32::from_le_bytes(payload[12..16].try_into().unwrap()),
                            c_line: payload[16],
                            c_cc,
                            c_ispeed: 0,
                            c_ospeed: 0,
                        },
                    )
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TCSETS2(termios2_ptr)
            | IoctlArg::TCSETSW2(termios2_ptr)
            | IoctlArg::TCSETSF2(termios2_ptr) => {
                let t: litebox_common_linux::Termios2 =
                    termios2_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                // Drop c_ispeed/c_ospeed — the existing broker Tcsets
                // op takes the 36-byte termios payload; PTYs ignore
                // arbitrary baud rates anyway.
                let mut payload = Vec::with_capacity(36);
                payload.extend_from_slice(&t.c_iflag.to_le_bytes());
                payload.extend_from_slice(&t.c_oflag.to_le_bytes());
                payload.extend_from_slice(&t.c_cflag.to_le_bytes());
                payload.extend_from_slice(&t.c_lflag.to_le_bytes());
                payload.push(t.c_line);
                payload.extend_from_slice(&t.c_cc);
                entry.ioctl(PtyIoctlOp::Tcsets, &payload)?;
                Ok(0)
            }
            IoctlArg::TIOCSWINSZ(ws_ptr) => {
                let ws: litebox_common_linux::Winsize =
                    ws_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let mut payload = Vec::with_capacity(8);
                payload.extend_from_slice(&ws.row.to_le_bytes());
                payload.extend_from_slice(&ws.col.to_le_bytes());
                payload.extend_from_slice(&ws.xpixel.to_le_bytes());
                payload.extend_from_slice(&ws.ypixel.to_le_bytes());
                entry.ioctl(PtyIoctlOp::Tiocswinsz, &payload)?;
                Ok(0)
            }
            IoctlArg::TIOCSPTLK(lock_ptr) => {
                let locked: i32 = lock_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                entry.ioctl(PtyIoctlOp::Tiocsptlk, &locked.to_le_bytes())?;
                Ok(0)
            }
            IoctlArg::TIOCNOTTY => Ok(0),
            IoctlArg::TIOCSCTTY => {
                if entry.is_master() {
                    return Err(Errno::ENOTTY);
                }
                entry.ioctl(PtyIoctlOp::Tiocsctty, &[])?;
                let pgid = i32::try_from(self.sys_getpgid(0).unwrap_or(1)).unwrap_or(1);
                entry.ioctl(PtyIoctlOp::Tiocspgrp, &pgid.to_le_bytes())?;
                if let Ok(pgid_u32) = u32::try_from(pgid) {
                    self.global.ensure_pgrp_signal_subscription(pgid_u32);
                }
                *self.process_state.borrow().controlling_pty.lock() = Some(entry.pty_id());
                Ok(0)
            }
            IoctlArg::TIOCSPGRP(pgrp_ptr) => {
                self.broker_pty_background_sigttou(entry, false)?;
                let pgrp: i32 = pgrp_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
                entry.ioctl(PtyIoctlOp::Tiocspgrp, &pgrp.to_le_bytes())?;
                if let Ok(pgid) = u32::try_from(pgrp) {
                    self.global.ensure_pgrp_signal_subscription(pgid);
                }
                Ok(0)
            }
            IoctlArg::TIOCGWINSZ(ws) => {
                let payload = entry.ioctl(PtyIoctlOp::Tiocgwinsz, &[])?;
                if payload.len() != 8 {
                    return Err(Errno::EIO);
                }
                ws.write_at_offset(
                    0,
                    litebox_common_linux::Winsize {
                        row: u16::from_le_bytes(payload[0..2].try_into().unwrap()),
                        col: u16::from_le_bytes(payload[2..4].try_into().unwrap()),
                        xpixel: u16::from_le_bytes(payload[4..6].try_into().unwrap()),
                        ypixel: u16::from_le_bytes(payload[6..8].try_into().unwrap()),
                    },
                )
                .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCGPTN(ptn) => {
                // TIOCGPTN is a `/dev/ptmx`-only ioctl: native Linux
                // returns -ENOTTY when called on a PTY slave fd, and
                // many TUI apps (e.g., GitHub Copilot CLI's startup
                // probe) rely on that errno to distinguish master
                // from slave. Mirror that strictness so we don't
                // mis-classify slaves as masters.
                if !entry.is_master() {
                    return Err(Errno::ENOTTY);
                }
                ptn.write_at_offset(0, entry.pty_id())
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCGPGRP(pgrp) => {
                let payload = entry.ioctl(PtyIoctlOp::Tiocgpgrp, &[])?;
                if payload.len() != 4 {
                    return Err(Errno::EIO);
                }
                pgrp.write_at_offset(0, i32::from_le_bytes(payload[..4].try_into().unwrap()))
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TIOCGSID(sid) => {
                let payload = entry.ioctl(PtyIoctlOp::Tiocgsid, &[])?;
                if payload.len() != 4 {
                    return Err(Errno::EIO);
                }
                sid.write_at_offset(0, i32::from_le_bytes(payload[..4].try_into().unwrap()))
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            _ => Err(Errno::ENOTTY),
        }
    }

    /// Classify a file descriptor as a host stdio device, PTY device, or neither.
    fn classify_terminal(&self, fs: &FS, fd: &TypedFd<FS>) -> Result<TerminalKind, Errno> {
        let descriptors = self.global.litebox.descriptor_table();
        match fs.fd_file_status(fd, &*descriptors) {
            Ok(status) => {
                if status.file_type != litebox::fs::FileType::CharacterDevice {
                    return Ok(TerminalKind::NotTerminal);
                }
                let major = status.node_info.rdev.map_or(0, |v| v.get() >> 8);
                match major {
                    // major 5: /dev/tty, /dev/console, /dev/ptmx — host stdio
                    5 => Ok(TerminalKind::HostStdio),
                    _ => Ok(TerminalKind::NotTerminal),
                }
            }
            Err(litebox::fs::errors::FileStatusError::ClosedFd) => Err(Errno::EBADF),
            Err(_) => unimplemented!(),
        }
    }

    /// Handle syscall `ioctl`
    pub fn sys_ioctl(
        &self,
        fd: i32,
        arg: IoctlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        let Ok(desc) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };

        if let IoctlArg::Raw { cmd, arg } = &arg
            && *cmd == LITEBOX_IOCTL_KIND_TYPEID_INVARIANT
        {
            let report = self.debug_kind_typeid_invariant_report();
            let bytes = report.as_bytes();
            let len = bytes.len().min(LITEBOX_IOCTL_DEBUG_BUF_LEN - 1);
            arg.write_slice_at_offset(0, &bytes[..len])
                .ok_or(Errno::EFAULT)?;
            arg.write_at_offset(len.try_into().unwrap(), 0u8)
                .ok_or(Errno::EFAULT)?;
            return if report.starts_with("ok:") {
                Ok(0)
            } else {
                Err(Errno::EIO)
            };
        }

        let files = self.files.borrow();
        let ptyfd_opt = {
            let rds = files.raw_descriptor_store.read();
            rds.fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(desc)
                .ok()
        };

        if desc <= 2 && ptyfd_opt.is_none() {
            // reason: unsupported variants intentionally share this fallback path.
            #[allow(clippy::wildcard_enum_match_arm)]
            match &arg {
                IoctlArg::TIOCGPGRP(pgrp) => {
                    pgrp.write_at_offset(0, self.pid).ok_or(Errno::EFAULT)?;
                    return Ok(0);
                }
                IoctlArg::TIOCSPGRP(pgrp) => {
                    let pgrp: i32 = pgrp.read_at_offset(0).ok_or(Errno::EFAULT)?;
                    if pgrp <= 0 {
                        return Err(Errno::EINVAL);
                    }
                    return Ok(0);
                }
                IoctlArg::TIOCSCTTY => return Ok(0),
                _ => {}
            }
        }
        if let Some(ptyfd) = ptyfd_opt {
            // reason: unsupported variants intentionally share this fallback path.
            #[allow(clippy::wildcard_enum_match_arm)]
            match &arg {
                IoctlArg::FIONREAD(_) => return Err(Errno::ENOTTY),
                IoctlArg::FIONBIO(v) => {
                    let val = v.read_at_offset(0).ok_or(Errno::EFAULT)?;
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(&ptyfd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        let mut flags = file.get_status();
                        flags.set(OFlags::NONBLOCK, val != 0);
                        file.set_status(flags);
                    });
                    return Ok(0);
                }
                IoctlArg::FIOCLEX => {
                    self.global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(&ptyfd, FileDescriptorFlags::FD_CLOEXEC);
                    return Ok(0);
                }
                IoctlArg::FIONCLEX => {
                    self.global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(&ptyfd, FileDescriptorFlags::empty());
                    return Ok(0);
                }
                IoctlArg::TIOCGPTPEER(open_flags) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(&ptyfd)
                        .ok_or(Errno::EBADF)?;
                    let (is_master, pty_id) =
                        handle.with_entry(|file| (file.is_master(), file.pty_id()));
                    if !is_master {
                        return Err(Errno::ENOTTY);
                    }
                    drop(files);
                    let slave_path = alloc::format!("/dev/pts/{pty_id}");
                    let oflags =
                        OFlags::from_bits_truncate(u32::try_from(*open_flags).unwrap_or(0));
                    return self.sys_open(slave_path.as_str(), oflags, Mode::empty());
                }
                IoctlArg::TCGETS(..)
                | IoctlArg::TCSETS(..)
                | IoctlArg::TCSETSW(..)
                | IoctlArg::TCSETSF(..)
                | IoctlArg::TCGETS2(..)
                | IoctlArg::TCSETS2(..)
                | IoctlArg::TCSETSW2(..)
                | IoctlArg::TCSETSF2(..)
                | IoctlArg::TIOCGPTN(..)
                | IoctlArg::TIOCSPTLK(..)
                | IoctlArg::TIOCSCTTY
                | IoctlArg::TIOCNOTTY
                | IoctlArg::TIOCGSID(..)
                | IoctlArg::TIOCGPGRP(..)
                | IoctlArg::TIOCSPGRP(..)
                | IoctlArg::TIOCGWINSZ(..)
                | IoctlArg::TIOCSWINSZ(..) => {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(&ptyfd)
                        .ok_or(Errno::EBADF)?;
                    return handle.with_entry(|file| self.broker_pty_ioctl_entry(file, &arg));
                }
                _ => {}
            }
        }
        // reason: IoctlArg is non_exhaustive; unknown ioctls intentionally return ENOTTY.
        #[allow(clippy::wildcard_enum_match_arm)]
        match arg {
            IoctlArg::FIONREAD(out) => {
                // Return the number of bytes available to read.
                files
                    .run_on_raw_fd(desc, |raw_fd_ref| match raw_fd_ref {
                        crate::RawFdRef::Fs(file_fd) => {
                            let available = match self.classify_terminal(&files.fs, file_fd)? {
                                TerminalKind::HostStdio => self
                                    .global
                                    .platform
                                    .get_terminal_input_bytes(
                                        self.host_stdio_stream_for_fd(&files.fs, file_fd)?,
                                    )
                                    .map_err(|e| match e {
                                        litebox::platform::StdioIoctlError::NotATerminal => {
                                            Errno::ENOTTY
                                        }
                                        litebox::platform::StdioIoctlError::OsError(_) => {
                                            Errno::EIO
                                        }
                                        _ => Errno::EIO,
                                    })?,
                                TerminalKind::NotTerminal => {
                                    return Err(Errno::ENOTTY);
                                }
                            };
                            let available = i32::try_from(available).unwrap_or(i32::MAX);
                            out.write_at_offset(0, available).ok_or(Errno::EFAULT)?;
                            Ok(0u32)
                        }
                        #[cfg(feature = "worker_local_inet")]
                        crate::RawFdRef::Net(socket_fd) => {
                            let proxy = self.global.get_proxy(socket_fd)?;
                            let n = proxy.pending_rx_bytes();
                            let n = i32::try_from(n).unwrap_or(i32::MAX);
                            out.write_at_offset(0, n).ok_or(Errno::EFAULT)?;
                            Ok(0u32)
                        }
                        crate::RawFdRef::Eventfd(_fd) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                        crate::RawFdRef::Epoll(_fd) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                        crate::RawFdRef::Unix(_fd) => {
                            todo!("FIONREAD on Unix socket: real Linux returns queued readable byte count")
                        }
                        crate::RawFdRef::HostPassthroughFd(_fd) => {
                            todo!("FIONREAD on host passthrough fd: real Linux returns queued readable byte count")
                        }
                        crate::RawFdRef::BrokerPipe(_fd) => {
                            todo!("FIONREAD on broker pipe: real Linux returns queued readable byte count")
                        }
                        crate::RawFdRef::BrokerSocketPair(_)
                        | crate::RawFdRef::BrokerSocketDgram(_)
                        | crate::RawFdRef::BrokerUnixStream(_)
                        | crate::RawFdRef::BrokerSocketSeqPacket(_) => {
                            todo!(
                                "FIONREAD on broker socketpair: real Linux returns queued readable byte count"
                            )
                        }
                        crate::RawFdRef::BrokerTcpConn(_fd) => {
                            todo!(
                                "FIONREAD on broker TCP connection: real Linux returns queued readable byte count"
                            )
                        }
                        crate::RawFdRef::BrokerPty(_fd) => {
                            todo!("FIONREAD on broker PTY: real Linux returns queued terminal input byte count")
                        }
                        crate::RawFdRef::Signalfd(_) | crate::RawFdRef::Inotify(_) | crate::RawFdRef::BrokerInetListener(_)
                    | crate::RawFdRef::BrokerInetDgram(_)
                | crate::RawFdRef::BrokerInetRaw(_) => {
                            Err(Errno::ENOTTY)
                        },
                    })
                    .flatten()
            }
            IoctlArg::FIONBIO(arg) => {
                let val = arg.read_at_offset(0).ok_or(Errno::EFAULT)?;
                let files = self.files.borrow();
                files
                    .run_on_raw_fd(desc, |raw_fd_ref| match raw_fd_ref {
                        crate::RawFdRef::Fs(file_fd) => {
                            let mut descriptors = self.global.litebox.descriptor_table_mut();
                            let result = descriptors
                                .with_metadata_mut(file_fd, |crate::StdioStatusFlags(flags)| {
                                    flags.set(OFlags::NONBLOCK, val != 0);
                                    *flags
                                });
                            match result {
                                Ok(new_flags) => files
                                    .fs
                                    .set_open_status_flags(file_fd, new_flags, &mut *descriptors)
                                    .map_err(|_| Errno::EBADF)?,
                                Err(MetadataError::ClosedFd) => return Err(Errno::EBADF),
                                Err(MetadataError::NoSuchMetadata) => {
                                    // Non-stdio file FD; non-blocking is irrelevant for
                                    // in-memory files, so silently succeed.
                                }
                            }
                            Ok(())
                        }
                        #[cfg(feature = "worker_local_inet")]
                        crate::RawFdRef::Net(socket_fd) => {
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
                        }
                        crate::RawFdRef::Eventfd(fd) => {
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
                        }
                        crate::RawFdRef::Epoll(fd) => {
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
                        }
                        crate::RawFdRef::Unix(fd) => {
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
                        }
                        crate::RawFdRef::HostPassthroughFd(fd) => {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file: &crate::syscalls::host_passthrough_fd::HostPassthroughFdEntry| {
                                self.global
                                    .platform
                                    .set_host_fd_nonblocking(file.raw_fd(), val != 0)?;
                                let mut flags = file.get_status();
                                flags.set(OFlags::NONBLOCK, val != 0);
                                file.set_status(flags);
                                Ok::<(), Errno>(())
                            })
                        }
                        crate::RawFdRef::BrokerPipe(fd) => {
                            // BrokerPipeFd: O_NONBLOCK lives in the shim-side
                            // `status` AtomicU32; read/write paths consult
                            // `get_status().contains(NONBLOCK)` before issuing
                            // broker RPCs. No host fd to toggle.
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                let mut flags = file.get_status();
                                flags.set(OFlags::NONBLOCK, val != 0);
                                file.set_status(flags);
                            });
                            Ok(())
                        }
                        crate::RawFdRef::BrokerSocketPair(fd) => {
                            // BrokerPipeFd: O_NONBLOCK lives in the shim-side
                            // `status` AtomicU32; read/write paths consult
                            // `get_status().contains(NONBLOCK)` before issuing
                            // broker RPCs. No host fd to toggle.
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                let mut flags = file.get_status();
                                flags.set(OFlags::NONBLOCK, val != 0);
                                file.set_status(flags);
                            });
                            Ok(())
                        }
                        crate::RawFdRef::BrokerTcpConn(fd) => {
                            // BrokerTcpConnFd: O_NONBLOCK lives in the shim-side
                            // status word; read/write will consult it before
                            // issuing broker RPCs. No host fd to toggle.
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                let mut flags = file.get_status();
                                flags.set(OFlags::NONBLOCK, val != 0);
                                file.set_status(flags);
                            });
                            Ok(())
                        }
                        crate::RawFdRef::BrokerPty(fd) => {
                            // BrokerPipeFd: O_NONBLOCK lives in the shim-side
                            // `status` AtomicU32; read/write paths consult
                            // `get_status().contains(NONBLOCK)` before issuing
                            // broker RPCs. No host fd to toggle.
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                let mut flags = file.get_status();
                                flags.set(OFlags::NONBLOCK, val != 0);
                                file.set_status(flags);
                            });
                            Ok(())
                        }
                        crate::RawFdRef::Signalfd(fd) => {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                let mut flags = file.get_status();
                                flags.set(OFlags::NONBLOCK, val != 0);
                                file.set_status(flags);
                            });
                            Ok(())
                        }
                        crate::RawFdRef::Inotify(fd) => {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                let mut flags = file.get_status();
                                flags.set(OFlags::NONBLOCK, val != 0);
                                file.set_status(flags);
                            });
                            Ok(())
                        }
                        crate::RawFdRef::BrokerInetListener(fd) => {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                let mut flags = file.get_status();
                                flags.set(OFlags::NONBLOCK, val != 0);
                                file.set_status(flags);
                            });
                            Ok(())
                        }
                        crate::RawFdRef::BrokerInetDgram(fd) => {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                let mut flags = file.get_status();
                                flags.set(OFlags::NONBLOCK, val != 0);
                                file.set_status(flags);
                            });
                            Ok(())
                        }
                        crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
                        crate::RawFdRef::BrokerUnixStream(_) => Err(Errno::EBADF),
                        crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
                        crate::RawFdRef::BrokerInetRaw(fd) => {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                let mut flags = file.get_status();
                                flags.set(OFlags::NONBLOCK, val != 0);
                                file.set_status(flags);
                            });
                            Ok(())
                        }
                    })
                    .flatten()?;
                Ok(0)
            }
            IoctlArg::FIOCLEX => files.run_on_raw_fd(desc, |raw_fd_ref| match raw_fd_ref {
                crate::RawFdRef::Fs(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                #[cfg(feature = "worker_local_inet")]
                crate::RawFdRef::Net(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                crate::RawFdRef::Eventfd(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                crate::RawFdRef::Epoll(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                crate::RawFdRef::Unix(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                crate::RawFdRef::HostPassthroughFd(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                crate::RawFdRef::BrokerPipe(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                crate::RawFdRef::BrokerSocketPair(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                crate::RawFdRef::BrokerTcpConn(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                crate::RawFdRef::BrokerPty(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                crate::RawFdRef::Signalfd(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                crate::RawFdRef::Inotify(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                crate::RawFdRef::BrokerInetListener(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                crate::RawFdRef::BrokerInetDgram(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
                crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerUnixStream(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerInetRaw(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                }
            })?,
            IoctlArg::FIONCLEX => files.run_on_raw_fd(desc, |raw_fd_ref| match raw_fd_ref {
                crate::RawFdRef::Fs(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                #[cfg(feature = "worker_local_inet")]
                crate::RawFdRef::Net(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                crate::RawFdRef::Eventfd(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                crate::RawFdRef::Epoll(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                crate::RawFdRef::Unix(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                crate::RawFdRef::HostPassthroughFd(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                crate::RawFdRef::BrokerPipe(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                crate::RawFdRef::BrokerSocketPair(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                crate::RawFdRef::BrokerTcpConn(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                crate::RawFdRef::BrokerPty(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                crate::RawFdRef::Signalfd(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                crate::RawFdRef::Inotify(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                crate::RawFdRef::BrokerInetListener(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                crate::RawFdRef::BrokerInetDgram(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
                crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerUnixStream(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
                crate::RawFdRef::BrokerInetRaw(fd) => {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::empty());
                    Ok(0)
                }
            })?,
            IoctlArg::TIOCGPTPEER(open_flags) => {
                // TIOCGPTPEER: open the slave side of a PTY master, returning a new fd.
                // The argument contains O_RDWR|O_NOCTTY or similar open flags.
                let pty_idx = files.run_on_raw_fd(desc, |raw_fd_ref| match raw_fd_ref {
                    crate::RawFdRef::Fs(file_fd) => {
                        // Check the fd is a PTY master (major 136).
                        let descriptors = self.global.litebox.descriptor_table();
                        let status = files
                            .fs
                            .fd_file_status(file_fd, &*descriptors)
                            .map_err(|_| Errno::EBADF)?;
                        let rdev = status.node_info.rdev.ok_or(Errno::ENOTTY)?;
                        let major = rdev.get() >> 8;
                        if major != 136 {
                            return Err(Errno::ENOTTY);
                        }
                        Ok(rdev.get() & 0xFF)
                    }
                    #[cfg(feature = "worker_local_inet")]
                    crate::RawFdRef::Net(_) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::Eventfd(_) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::Epoll(_) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::Unix(_) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::HostPassthroughFd(_) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::BrokerPipe(_) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::BrokerSocketPair(_)
                    | crate::RawFdRef::BrokerSocketDgram(_)
                    | crate::RawFdRef::BrokerUnixStream(_)
                    | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::BrokerTcpConn(_) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::BrokerPty(_) => {
                        unreachable!(
                            "BrokerPty descriptors are handled by the direct TIOCGPTPEER branch before run_on_raw_fd"
                        )
                    }
                    crate::RawFdRef::Signalfd(_) | crate::RawFdRef::Inotify(_) | crate::RawFdRef::BrokerInetListener(_)
                    | crate::RawFdRef::BrokerInetDgram(_)
                | crate::RawFdRef::BrokerInetRaw(_) => {
                        Err(Errno::ENOTTY)
                    },
                })??;
                // Drop borrows before opening (which needs write access).
                drop(files);
                // Open the slave via the normal open path.
                let slave_path = alloc::format!("/dev/pts/{pty_idx}");
                let oflags = OFlags::from_bits_truncate(u32::try_from(open_flags).unwrap_or(0));
                self.sys_open(slave_path.as_str(), oflags, Mode::empty())
            }
            IoctlArg::TCGETS(..)
            | IoctlArg::TCSETS(..)
            | IoctlArg::TCSETSW(..)
            | IoctlArg::TCSETSF(..)
            | IoctlArg::TCGETS2(..)
            | IoctlArg::TCSETS2(..)
            | IoctlArg::TCSETSW2(..)
            | IoctlArg::TCSETSF2(..)
            | IoctlArg::TIOCGPTN(..)
            | IoctlArg::TIOCSPTLK(..)
            | IoctlArg::TIOCSCTTY
            | IoctlArg::TIOCNOTTY
            | IoctlArg::TIOCGSID(..)
            | IoctlArg::TIOCGPGRP(..)
            | IoctlArg::TIOCSPGRP(..)
            | IoctlArg::TIOCGWINSZ(..)
            | IoctlArg::TIOCSWINSZ(..) => {
                files.run_on_raw_fd(desc, |raw_fd_ref| match raw_fd_ref {
                    crate::RawFdRef::Fs(term_fd) => match self
                        .classify_terminal(&files.fs, term_fd)?
                    {
                        TerminalKind::HostStdio => self.host_stdio_ioctl(&files.fs, term_fd, &arg),
                        TerminalKind::NotTerminal => Err(Errno::ENOTTY),
                    },
                    #[cfg(feature = "worker_local_inet")]
                    crate::RawFdRef::Net(_fd) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::Eventfd(_fd) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::Epoll(_fd) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::Unix(_fd) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::HostPassthroughFd(_fd) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::BrokerPipe(_fd) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::BrokerSocketPair(_)
                    | crate::RawFdRef::BrokerSocketDgram(_)
                    | crate::RawFdRef::BrokerUnixStream(_)
                    | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::BrokerTcpConn(_fd) => Err(Errno::ENOTTY), // real Linux: ENOTTY for this ioctl on non-tty fd
                    crate::RawFdRef::BrokerPty(_fd) => {
                        unreachable!(
                            "BrokerPty descriptors are handled by the direct terminal-ioctl branch before run_on_raw_fd"
                        )
                    }
                    crate::RawFdRef::Signalfd(_) | crate::RawFdRef::Inotify(_) | crate::RawFdRef::BrokerInetListener(_)
                    | crate::RawFdRef::BrokerInetDgram(_)
                | crate::RawFdRef::BrokerInetRaw(_) => {
                        Err(Errno::ENOTTY)
                    },
                })?
            }
            // reason: IoctlArg is non_exhaustive; unknown terminal ioctls intentionally return ENOTTY.
            #[allow(clippy::wildcard_enum_match_arm)]
            _ => {
                // Return ENOTTY for unsupported ioctls rather than panicking.
                // Complex programs (e.g., bash) probe terminal capabilities and
                // handle ENOTTY gracefully.
                Err(Errno::ENOTTY)
            }
        }
    }

    /// Handle syscall `epoll_create` and `epoll_create1`
    pub fn sys_epoll_create(&self, flags: EpollCreateFlags) -> Result<u32, Errno> {
        if flags.contains(EpollCreateFlags::EPOLL_CLOEXEC.complement()) {
            return Err(Errno::EINVAL);
        }

        let epoll_file = super::epoll::EpollFile::new();
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<super::epoll::EpollSubsystem<FS>>(epoll_file);
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
        event: ConstPtr<litebox_common_linux::EpollEvent>,
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
            .fd_from_raw_integer::<super::epoll::EpollSubsystem<FS>>(epfd as usize)
            .map_err(|_| Errno::EBADF)?;
        let file_descriptor =
            super::epoll::EpollDescriptor::try_from(&self.global, &files, fd as usize)?;

        let event_ptr = event;
        let event = if op == litebox_common_linux::EpollOp::EpollCtlDel {
            None
        } else {
            Some(event_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?)
        };
        let handle = self
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&epoll_fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(|entry| {
            entry.epoll_ctl(&self.global, &*files.fs, op, fd, &file_descriptor, event)
        })
    }

    /// Handle syscall `epoll_pwait`
    pub fn sys_epoll_pwait(
        &self,
        epfd: i32,
        events: MutPtr<litebox_common_linux::EpollEvent>,
        maxevents: u32,
        timeout: TimeParam<Platform>,
        sigmask: Option<ConstPtr<litebox_common_linux::signal::SigSet>>,
        _sigsetsize: usize,
    ) -> Result<usize, Errno> {
        // Save the current signal mask and apply the caller's mask for the
        // duration of the wait.  This is the core semantics of epoll_pwait:
        // atomically { set sigmask; wait; restore sigmask }.
        //
        // The mask restore is DEFERRED via `set_restore_mask` so that
        // `process_signals()` (called by `prepare_to_run_guest`) can deliver
        // newly-unblocked signals (e.g. SIGCHLD) before re-blocking them.
        let saved_mask = if let Some(mask_ptr) = sigmask {
            let new_mask = mask_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            let old = self.signals.get_blocked();
            self.signals.set_blocked(new_mask);
            Some(old)
        } else {
            None
        };

        let Ok(epfd) = u32::try_from(epfd) else {
            if let Some(old) = saved_mask {
                self.signals.set_blocked(old);
            }
            return Err(Errno::EBADF);
        };
        let maxevents = maxevents as usize;
        if maxevents == 0
            || maxevents > i32::MAX as usize / size_of::<litebox_common_linux::EpollEvent>()
        {
            if let Some(old) = saved_mask {
                self.signals.set_blocked(old);
            }
            return Err(Errno::EINVAL);
        }
        let timeout = timeout.read()?;
        let handle = {
            let files = self.files.borrow();
            {
                let Ok(raw_fd) = usize::try_from(epfd) else {
                    if let Some(old) = saved_mask {
                        self.signals.set_blocked(old);
                    }
                    return Err(Errno::EBADF);
                };
                let Ok(fd) =
                    files
                        .raw_descriptor_store
                        .read()
                        .fd_from_raw_integer::<crate::syscalls::epoll::EpollSubsystem<FS>>(raw_fd)
                else {
                    if let Some(old) = saved_mask {
                        self.signals.set_blocked(old);
                    }
                    return Err(Errno::EBADF);
                };
                let Some(h) = self.global.litebox.descriptor_table().entry_handle(&fd) else {
                    if let Some(old) = saved_mask {
                        self.signals.set_blocked(old);
                    }
                    return Err(Errno::EBADF);
                };
                h
            }
        };
        // PE.14: loop to swallow spurious EINTR caused by signals
        // whose disposition is "ignore" (e.g., SIGCHLD with SIG_DFL).
        // Real Linux does not interrupt syscalls for these signals;
        // our shim's check_for_interrupt is over-aggressive. Retry
        // the wait until a real signal arrives, a timeout fires, or
        // events become available. Bounded by the test's deadline.
        let result = loop {
            let inner_result = handle.with_entry(|epoll_file| {
                epoll_file.wait(
                    &self.global,
                    &*self.files.borrow().fs,
                    &self.wait_cx().with_timeout(timeout),
                    maxevents,
                )
            });
            match inner_result {
                Ok(epoll_events) => {
                    #[cfg(feature = "audit_log")]
                    if !epoll_events.is_empty() && crate::audit::is_enabled() {
                        crate::audit::emit_epoll_ready_events(
                            self.pid,
                            self.tid,
                            epfd,
                            &epoll_events,
                        );
                    }
                    if !epoll_events.is_empty() {
                        if let Err(e) = events
                            .copy_from_slice(0, &epoll_events)
                            .ok_or(Errno::EFAULT)
                        {
                            break Err(e);
                        }
                    }
                    break Ok(epoll_events.len());
                }
                Err(WaitError::TimedOut) => break Ok(0),
                Err(WaitError::Interrupted) => {
                    // If only default-ignore signals are pending,
                    // this was a spurious wake — retry. If any
                    // deliverable signal is pending, propagate EINTR.
                    //
                    // Vfork/fork quiescing also interrupts epoll waiters by
                    // marking them suspended. Do not swallow that interrupt:
                    // the caller must return to the guest boundary so
                    // prepare_to_run_guest can park the sibling before the
                    // forking thread snapshots or restores shared state.
                    if !self.is_suspended() && self.pending_signals_all_ignored() {
                        // drain (clear) the ignored pending signals
                        // so we don't infinite-loop on them.
                        self.drain_ignored_pending();
                        continue;
                    }
                    break Err(Errno::EINTR);
                }
            }
        };

        // Defer mask restore to process_signals() so that signals unblocked
        // by the caller's mask (like SIGCHLD) are delivered before the
        // original mask is reinstated.
        if let Some(old) = saved_mask {
            self.signals.set_restore_mask(old);
        }

        result
    }

    /// Handle syscall `ppoll`.
    pub fn sys_ppoll(
        &self,
        fds: MutPtr<litebox_common_linux::Pollfd>,
        nfds: usize,
        timeout: TimeParam<Platform>,
        sigmask: Option<ConstPtr<litebox_common_linux::signal::SigSet>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        // Save and apply the caller's signal mask for the duration of the wait,
        // matching ppoll(2) semantics.
        let saved_mask = if let Some(mask_ptr) = sigmask {
            if sigsetsize != core::mem::size_of::<litebox_common_linux::signal::SigSet>() {
                return Err(Errno::EINVAL);
            }
            let new_mask = mask_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            let old = self.signals.get_blocked();
            self.signals.set_blocked(new_mask);
            Some(old)
        } else {
            None
        };
        let timeout = timeout.read()?;
        let timeout = match self.process().alarm_timer.lock().deadline {
            Some(alarm_deadline) => {
                let now = self.global.platform.now();
                let alarm_timeout = alarm_deadline
                    .checked_duration_since(&now)
                    .unwrap_or(core::time::Duration::ZERO);
                Some(timeout.map_or(alarm_timeout, |t| t.min(alarm_timeout)))
            }
            None => timeout,
        };
        let nfds_signed = isize::try_from(nfds).map_err(|_| {
            if let Some(old) = saved_mask {
                self.signals.set_blocked(old);
            }
            Errno::EINVAL
        })?;

        let mut set = super::epoll::PollSet::with_capacity(nfds);
        let mut eager_ready_count: usize = 0;
        for i in 0..nfds_signed {
            let mut fd = fds.read_at_offset(i).ok_or_else(|| {
                if let Some(old) = saved_mask {
                    self.signals.set_blocked(old);
                }
                Errno::EFAULT
            })?;

            // Netlink socket: always report ready (has data or EAGAIN).
            if let Ok(fd_u32) = u32::try_from(fd.fd) {
                if self.netlink_sockets.borrow().contains_key(&fd_u32) {
                    fd.revents = fd.events; // Mark as ready
                    let _ = fds.write_at_offset(i, fd);
                    eager_ready_count += 1;
                    continue;
                }
            }

            let events = litebox::event::Events::from_bits_truncate(
                fd.events.reinterpret_as_unsigned().into(),
            );
            if events.contains(litebox::event::Events::IN)
                && let Ok(raw_fd) = usize::try_from(fd.fd)
            {
                let inotify_ready = {
                    let files = self.files.borrow();
                    files
                        .with_inotify_fd(raw_fd, |state| {
                            if state.events.is_empty() {
                                self.rescan_inotify_instance(state);
                            }
                            Ok(!state.events.is_empty())
                        })
                        .unwrap_or(false)
                };
                if inotify_ready {
                    fd.revents = 1;
                    let _ = fds.write_at_offset(i, fd);
                    eager_ready_count += 1;
                    continue;
                }
            }
            set.add_fd(fd.fd, events);
        }

        // If there are fds that were not already satisfied above, do the normal poll wait.
        if !set.is_empty() {
            // PE.14: loop to swallow spurious EINTR from default-ignore
            // signals (SIGCHLD with SIG_DFL). Same pattern as
            // sys_epoll_pwait above.
            loop {
                match set.wait(
                    &self.global,
                    &self.wait_cx().with_timeout(timeout),
                    &self.files.borrow(),
                ) {
                    Ok(()) => break,
                    Err(WaitError::Interrupted) => {
                        if !self.is_suspended() && self.pending_signals_all_ignored() {
                            self.drain_ignored_pending();
                            continue;
                        }
                        // Defer mask restore for process_signals.
                        if let Some(old) = saved_mask {
                            self.signals.set_restore_mask(old);
                        }
                        // TODO: update the remaining time.
                        return Err(Errno::EINTR);
                    }
                    Err(WaitError::TimedOut) => {
                        // A timeout occurred. Scan one last time.
                        set.scan(&self.global, &self.files.borrow());
                        break;
                    }
                }
            }
        }

        // Defer mask restore for process_signals.
        if let Some(old) = saved_mask {
            self.signals.set_restore_mask(old);
        }

        // Write just the revents back for non-netlink fds.
        let fds_base_addr = fds.as_usize();
        let mut ready_count = eager_ready_count;
        for (i, revents) in set.revents().enumerate() {
            // TODO: This is not great from a provenance perspective. Consider
            // adding cast+add methods to ConstPtr/MutPtr.
            let fd_addr = fds_base_addr + i * core::mem::size_of::<litebox_common_linux::Pollfd>();
            let revents_ptr = crate::MutPtr::<i16>::from_usize(
                fd_addr + core::mem::offset_of!(litebox_common_linux::Pollfd, revents),
            );
            let revents: u16 = revents.bits().truncate();
            revents_ptr
                .write_at_offset(0, revents.reinterpret_as_signed())
                .ok_or(Errno::EFAULT)?;
            if revents != 0 {
                ready_count += 1;
            }
        }

        for i in 0..nfds_signed {
            let mut fd = fds.read_at_offset(i).ok_or(Errno::EFAULT)?;
            let events = litebox::event::Events::from_bits_truncate(
                fd.events.reinterpret_as_unsigned().into(),
            );
            if !events.contains(litebox::event::Events::IN) || fd.revents != 0 {
                continue;
            }
            let Ok(raw_fd) = usize::try_from(fd.fd) else {
                continue;
            };
            let inotify_ready = {
                let files = self.files.borrow();
                files
                    .with_inotify_fd(raw_fd, |state| {
                        if state.events.is_empty() {
                            self.rescan_inotify_instance(state);
                        }
                        Ok(!state.events.is_empty())
                    })
                    .unwrap_or(false)
            };
            if inotify_ready {
                fd.revents = 1;
                fds.write_at_offset(i, fd).ok_or(Errno::EFAULT)?;
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
        readfds: Option<MutPtr<usize>>,
        writefds: Option<MutPtr<usize>>,
        exceptfds: Option<MutPtr<usize>>,
        timeout: TimeParam<Platform>,
        sigsetpack: Option<ConstPtr<litebox_common_linux::SigSetPack>>,
    ) -> Result<usize, Errno> {
        // Save the current signal mask and apply the caller's mask for the
        // duration of the wait (same semantics as epoll_pwait / ppoll).
        //
        // pselect6 passes a pointer to {sigset_t *ss, size_t ss_len} where
        // ss is itself a pointer to the actual signal mask.
        let saved_mask = if let Some(pack_ptr) = sigsetpack {
            let pack: litebox_common_linux::SigSetPack =
                pack_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            if pack.size != core::mem::size_of::<litebox_common_linux::signal::SigSet>() {
                return Err(Errno::EINVAL);
            }
            // pack.sigset is actually a pointer to the sigset (the u64 holds
            // the guest address). Dereference it to read the actual mask.
            let sigset_ptr = crate::ConstPtr::<litebox_common_linux::signal::SigSet>::from_usize(
                pack.sigset.as_u64().truncate(),
            );
            let new_mask = sigset_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            let old = self.signals.get_blocked();
            self.signals.set_blocked(new_mask);
            Some(old)
        } else {
            None
        };

        let timeout = timeout.read()?;
        if nfds >= i32::MAX as u32
            || nfds as usize
                > self
                    .process()
                    .limits
                    .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE)
        {
            if let Some(old) = saved_mask {
                self.signals.set_blocked(old);
            }
            return Err(Errno::EINVAL);
        }
        let len = (nfds as usize).div_ceil(core::mem::size_of::<usize>() * 8);
        let mut kreadfds = readfds
            .map(|fds| fds.to_owned_slice(len).ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_vec()));
        let mut kwritefds = writefds
            .map(|fds| fds.to_owned_slice(len).ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_vec()));
        let mut kexceptfds = exceptfds
            .map(|fds| fds.to_owned_slice(len).ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_vec()));

        let count = self.do_pselect(
            nfds,
            kreadfds.as_mut(),
            kwritefds.as_mut(),
            kexceptfds.as_mut(),
            timeout,
        );

        // Defer mask restore so signals unblocked by the caller's mask are
        // delivered before the original mask is reinstated.
        if let Some(old) = saved_mask {
            self.signals.set_restore_mask(old);
        }

        let count = count?;

        if let Some(fds) = kreadfds {
            readfds
                .unwrap()
                .write_slice_at_offset(0, fds.as_raw_slice())
                .ok_or(Errno::EFAULT)?;
        }
        if let Some(fds) = kwritefds {
            writefds
                .unwrap()
                .write_slice_at_offset(0, fds.as_raw_slice())
                .ok_or(Errno::EFAULT)?;
        }
        if let Some(fds) = kexceptfds {
            exceptfds
                .unwrap()
                .write_slice_at_offset(0, fds.as_raw_slice())
                .ok_or(Errno::EFAULT)?;
        }

        Ok(count)
    }

    fn do_dup(&self, file: usize, flags: OFlags) -> Result<usize, Errno> {
        self.do_dup_inner(file, flags, None, None)
    }

    fn do_dup_at_or_above(
        &self,
        file: usize,
        flags: OFlags,
        min_fd: usize,
    ) -> Result<usize, Errno> {
        self.do_dup_inner(file, flags, None, Some(min_fd))
    }

    fn do_dup_inner(
        &self,
        file: usize,
        flags: OFlags,
        target: Option<usize>,
        min_fd: Option<usize>,
    ) -> Result<usize, Errno> {
        #[allow(clippy::too_many_arguments)]
        fn dup<FS: ShimFS, S: FdEnabledSubsystem>(
            global: &GlobalState<FS>,
            files: &FilesState<FS>,
            fd: &TypedFd<S>,
            pid: i32,
            source_raw_fd: usize,
            close_on_exec: bool,
            target: Option<usize>,
            min_fd: Option<usize>,
        ) -> Result<usize, Errno> {
            #[cfg(not(feature = "trace_syscalls"))]
            let _ = (pid, source_raw_fd);
            let mut dt = global.litebox.descriptor_table_mut();
            let fd: TypedFd<_> = dt.duplicate(fd).ok_or(Errno::EBADF)?;
            #[cfg(feature = "trace_syscalls")]
            let object_id = fd.object_id().as_u64();
            if close_on_exec {
                let old = dt.set_fd_metadata(&fd, FileDescriptorFlags::FD_CLOEXEC);
                assert!(old.is_none());
            }
            let mut rds = files.raw_descriptor_store.write();
            let new_raw_fd = if let Some(target) = target {
                if !rds.fd_into_specific_raw_integer(fd, target) {
                    return Err(Errno::EBADF);
                }
                target
            } else if let Some(min_fd) = min_fd {
                #[allow(clippy::maybe_infinite_iter)]
                let raw_fd = (min_fd..)
                    .find(|&raw_fd| !rds.is_alive(raw_fd))
                    .expect("raw fd search should always find a slot");
                let success = rds.fd_into_specific_raw_integer(fd, raw_fd);
                assert!(success);
                raw_fd
            } else {
                rds.fd_into_raw_integer(fd)
            };
            #[cfg(feature = "trace_syscalls")]
            if source_raw_fd <= 20 || new_raw_fd <= 20 {
                litebox::log_println!(
                    global.platform,
                    "[STDIO-MAP] pid={} dup source_fd={} target_fd={} object_id={} entry_type={} cloexec={}",
                    pid,
                    source_raw_fd,
                    new_raw_fd,
                    object_id,
                    core::any::type_name::<S::Entry>(),
                    close_on_exec,
                );
            }
            Ok(new_raw_fd)
        }
        let close_on_exec = flags.contains(OFlags::CLOEXEC);
        let files = self.files.borrow();
        let broker_pty_fd = {
            let rds = files.raw_descriptor_store.read();
            rds.fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(file)
        };
        if let Ok(fd) = broker_pty_fd {
            let new_fd = dup(
                &self.global,
                &files,
                &fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            )?;
            return Ok(new_fd);
        }
        let new_fd = files.run_on_raw_fd(file, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            crate::RawFdRef::Eventfd(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            crate::RawFdRef::Epoll(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            crate::RawFdRef::Unix(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            crate::RawFdRef::HostPassthroughFd(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            crate::RawFdRef::BrokerPipe(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            crate::RawFdRef::BrokerSocketPair(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            crate::RawFdRef::BrokerTcpConn(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            crate::RawFdRef::BrokerPty(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            crate::RawFdRef::Signalfd(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            crate::RawFdRef::Inotify(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            crate::RawFdRef::BrokerInetListener(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            crate::RawFdRef::BrokerInetDgram(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
            crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerUnixStream(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerInetRaw(fd) => dup(
                &self.global,
                &files,
                fd,
                self.pid,
                file,
                close_on_exec,
                target,
                min_fd,
            ),
        });
        let new_fd = match new_fd {
            Ok(Ok(fd)) => fd,
            Ok(Err(e)) | Err(e) => return Err(e),
        };
        if target.is_none() {
            let max_fd = self
                .process()
                .limits
                .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE);
            if new_fd >= max_fd {
                self.do_close(new_fd)?;
                return Err(Errno::EMFILE);
            }
        }
        files.duplicate_inotify_fd(file, new_fd);
        Ok(new_fd)
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
        let Ok(oldfd) = u32::try_from(oldfd) else {
            return Err(Errno::EBADF);
        };
        let oldfd_usize = usize::try_from(oldfd).or(Err(Errno::EBADF))?;
        if !self
            .files
            .borrow()
            .raw_descriptor_store
            .read()
            .is_alive(oldfd_usize)
        {
            return Err(Errno::EBADF);
        }
        if let Some(newfd) = newfd {
            // dup2/dup3
            let Ok(newfd) = u32::try_from(newfd) else {
                return Err(Errno::EBADF);
            };
            if oldfd == newfd {
                if flags.is_some() {
                    // dup3(fd, fd) always returns EINVAL per POSIX.
                    return Err(Errno::EINVAL);
                }
                // dup2(fd, fd): verify fd is valid, then clear CLOEXEC.
                //
                // POSIX says dup2(fd, fd) "does nothing", but libuv relies on
                // inherited stdio fds surviving exec even though the parent
                // sets CLOEXEC. Clearing CLOEXEC here matches the intent of
                // the dup2 caller (set up this fd for the child) and prevents
                // close-on-exec from closing stdio fds after exec.
                let files = self.files.borrow();
                if let Ok(fd) =
                    files
                        .raw_descriptor_store
                        .read()
                        .fd_from_raw_integer::<super::broker_pty::BrokerPtySubsystem>(oldfd_usize)
                {
                    self.global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(&fd, FileDescriptorFlags::empty());
                    return Ok(oldfd);
                }
                files
                    .run_on_raw_fd(oldfd_usize, |raw_fd_ref| match raw_fd_ref {
                        crate::RawFdRef::Fs(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        #[cfg(feature = "worker_local_inet")]
                        crate::RawFdRef::Net(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        crate::RawFdRef::Eventfd(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        crate::RawFdRef::Epoll(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        crate::RawFdRef::Unix(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        crate::RawFdRef::HostPassthroughFd(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        crate::RawFdRef::BrokerPipe(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        crate::RawFdRef::BrokerSocketPair(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        crate::RawFdRef::BrokerTcpConn(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        crate::RawFdRef::BrokerPty(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        crate::RawFdRef::Signalfd(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        crate::RawFdRef::Inotify(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        crate::RawFdRef::BrokerInetListener(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        crate::RawFdRef::BrokerInetDgram(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                        crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
                        crate::RawFdRef::BrokerUnixStream(_) => Err(Errno::EBADF),
                        crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
                        crate::RawFdRef::BrokerInetRaw(fd) => {
                            self.global
                                .litebox
                                .descriptor_table_mut()
                                .set_fd_metadata(fd, FileDescriptorFlags::empty());
                            Ok(())
                        }
                    })
                    .flatten()?;
                return Ok(oldfd);
            }
            // Close whatever is at newfd before duping into it
            let newfd_usize = usize::try_from(newfd).or(Err(Errno::EBADF))?;
            let _ = self.do_close(newfd_usize);
            self.do_dup_inner(
                oldfd_usize,
                flags.unwrap_or(OFlags::empty()),
                Some(newfd_usize),
                None,
            )?;
            self.maybe_trace_pty_dup(oldfd, newfd);
            Ok(newfd)
        } else {
            // dup
            let new_file = self.do_dup(oldfd_usize, flags.unwrap_or(OFlags::empty()))?;
            let newfd = u32::try_from(new_file).unwrap();
            self.maybe_trace_pty_dup(oldfd, newfd);
            Ok(newfd)
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Diroff(usize);

const DIRENT_STRUCT_BYTES_WITHOUT_NAME: usize =
    core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name);

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `getdents64`
    pub(crate) fn sys_getdirent64(
        &self,
        fd: i32,
        dirp: MutPtr<u8>,
        count: usize,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files.run_on_raw_fd(fd, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(file) => {
                let mut descriptors = self.global.litebox.descriptor_table_mut();
                let dir_off: Diroff = descriptors
                    .with_metadata(file, |off: &Diroff| *off)
                    .unwrap_or_default();
                let mut dir_off = dir_off.0;
                let mut nbytes = 0;

                let mut entries = files.fs.read_dir(file, &mut *descriptors)?;
                entries.sort_by(|a, b| a.name.cmp(&b.name));

                // Buffer all dirent64 entries into a kernel-side Vec<u8> before
                // writing to guest memory. This allows us to insert a single
                // park checkpoint (for deferred vfork parking) before the guest
                // write, rather than scattering them across every entry.
                let mut kernel_buf = alloc::vec::Vec::<u8>::with_capacity(count.min(4096));

                for entry in entries.iter().skip(dir_off) {
                    // include null terminator and make it aligned
                    let len = (DIRENT_STRUCT_BYTES_WITHOUT_NAME + entry.name.len() + 1)
                        .next_multiple_of(align_of::<litebox_common_linux::LinuxDirent64>());
                    if nbytes + len > count {
                        // not enough space
                        break;
                    }
                    let dirent64 = litebox_common_linux::LinuxDirent64 {
                        ino: entry.ino_info.as_ref().map_or(0, |node_info| node_info.ino) as u64,
                        off: dir_off as u64,
                        len: len.truncate(),
                        typ: litebox_common_linux::DirentType::from(entry.file_type.clone()) as u8,
                        __name: [0; 0],
                    };

                    // Append the dirent64 header as raw bytes.
                    let hdr_bytes: &[u8] = unsafe {
                        // SAFETY: LinuxDirent64 is repr(C) and all bit patterns
                        // from the initialized fields are valid. We read
                        // exactly `size_of::<LinuxDirent64>()` bytes from a
                        // properly aligned struct.
                        core::slice::from_raw_parts(
                            (&raw const dirent64).cast::<u8>(),
                            core::mem::size_of::<litebox_common_linux::LinuxDirent64>(),
                        )
                    };
                    kernel_buf.extend_from_slice(hdr_bytes);
                    // Pad to DIRENT_STRUCT_BYTES_WITHOUT_NAME (covers the
                    // __name[0] flexible array member offset).
                    let hdr_size = core::mem::size_of::<litebox_common_linux::LinuxDirent64>();
                    if hdr_size < DIRENT_STRUCT_BYTES_WITHOUT_NAME {
                        kernel_buf.extend(core::iter::repeat_n(
                            0u8,
                            DIRENT_STRUCT_BYTES_WITHOUT_NAME - hdr_size,
                        ));
                    }
                    // Append the name.
                    kernel_buf.extend_from_slice(entry.name.as_bytes());
                    // Null terminator + padding.
                    let zeros_len = len - (DIRENT_STRUCT_BYTES_WITHOUT_NAME + entry.name.len());
                    kernel_buf.extend(core::iter::repeat_n(0u8, zeros_len));

                    nbytes += len;
                    dir_off += 1;
                }

                // Park checkpoint: block for deferred vfork before guest write.
                self.park_if_deferred();

                // Single bulk write to guest memory.
                if nbytes > 0 {
                    dirp.copy_from_slice(0, &kernel_buf[..nbytes])
                        .ok_or(Errno::EFAULT)?;
                }

                let _old = descriptors.set_fd_metadata(file, Diroff(dir_off));
                Ok(nbytes)
            }
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(_fd) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::Eventfd(_fd) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::Epoll(_fd) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::Unix(_fd) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::HostPassthroughFd(_fd) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerPipe(_fd) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerSocketPair(_)
            | crate::RawFdRef::BrokerSocketDgram(_)
            | crate::RawFdRef::BrokerUnixStream(_)
            | crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerTcpConn(_fd) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerPty(_fd) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::Signalfd(_)
            | crate::RawFdRef::Inotify(_)
            | crate::RawFdRef::BrokerInetListener(_)
            | crate::RawFdRef::BrokerInetDgram(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
            crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::ENOTDIR), // real Linux: ENOTDIR for non-directory fd
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use litebox::fs::Mode;
    use litebox::process::ProcessGroupId;
    use litebox_common_linux::IoctlArg;

    extern crate std;

    fn timer_spec(value_sec: i64, value_nsec: u64) -> ItimerSpec {
        ItimerSpec {
            value: litebox_common_linux::Timespec {
                tv_sec: value_sec,
                tv_nsec: value_nsec,
            },
            interval: litebox_common_linux::Timespec {
                tv_sec: 2,
                tv_nsec: 0,
            },
        }
    }

    #[test]
    fn timerfd_bridge_restore_ages_active_value() {
        let restored = timerfd_bridge_restore_spec(timer_spec(1, 500), 0, 250).unwrap();
        assert_eq!(restored.value.tv_sec, 1);
        assert_eq!(restored.value.tv_nsec, 250);
        assert_eq!(restored.interval.tv_sec, 2);
    }

    #[test]
    fn timerfd_bridge_restore_catches_up_expired_in_transit() {
        let restored = timerfd_bridge_restore_spec(timer_spec(0, 100), 0, 100).unwrap();
        assert_eq!(restored.value.tv_sec, 0);
        assert_eq!(restored.value.tv_nsec, 1);
    }

    #[test]
    fn timerfd_bridge_restore_preserves_disarmed_without_pending() {
        let restored = timerfd_bridge_restore_spec(timer_spec(0, 0), 0, 1_000).unwrap();
        assert_eq!(restored.value.tv_sec, 0);
        assert_eq!(restored.value.tv_nsec, 0);
    }

    #[test]
    fn timerfd_bridge_restore_catches_up_pending_expiration() {
        let restored = timerfd_bridge_restore_spec(timer_spec(0, 0), 1, 0).unwrap();
        assert_eq!(restored.value.tv_sec, 0);
        assert_eq!(restored.value.tv_nsec, 1);
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

        // Empty path at AT_FDCWD → ENOENT (no AT_EMPTY_PATH).
        let err = FsPath::new(litebox_common_linux::AT_FDCWD, "", || {
            panic!("get_cwd should not be called for empty path")
        })
        .unwrap_err();
        assert_eq!(err, Errno::ENOENT);

        // Positive fd + empty path → ENOENT (no AT_EMPTY_PATH).
        let err = FsPath::new(5, "", || panic!("should not be called")).unwrap_err();
        assert_eq!(err, Errno::ENOENT);

        // Empty path at AT_FDCWD with new_empty_ok → Cwd variant.
        let fp = FsPath::new_empty_ok(litebox_common_linux::AT_FDCWD, "", || {
            panic!("get_cwd should not be called for empty Cwd path")
        })
        .unwrap();
        assert!(matches!(fp, FsPath::Cwd));

        // Positive fd + empty path with new_empty_ok → Fd variant.
        let fp = FsPath::new_empty_ok(5, "", || panic!("should not be called")).unwrap();
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

        // Positive fd + non-empty path → FdRelative variant.
        let fp = FsPath::new(3, "child/file.txt", || {
            panic!("get_cwd should not be called")
        })
        .unwrap();
        assert!(matches!(fp, FsPath::FdRelative { fd: 3, .. }));
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
        task.sys_mkdir("/test_chdir_dir", 0o777).unwrap();
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
            .sys_open(
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
        task.sys_mkdir("/rel_parent", 0o777).unwrap();
        task.sys_mkdir("/rel_parent/rel_child", 0o777).unwrap();

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
    fn fchdir_changes_cwd() {
        let task = crate::syscalls::tests::init_platform(None);

        task.sys_mkdir("/fchdir_test", 0o777).unwrap();

        // Open the directory.
        let dirfd = task
            .sys_open(
                "/fchdir_test",
                litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();

        // fchdir to it.
        task.sys_fchdir(i32::try_from(dirfd).unwrap()).unwrap();

        let mut buf = [0u8; 256];
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap();
        assert_eq!(cwd, "/fchdir_test/");

        // fchdir on a regular file fd → ENOTDIR.
        let filefd = task
            .sys_open(
                "/fchdir_test/file.txt",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        assert_eq!(
            task.sys_fchdir(i32::try_from(filefd).unwrap()).unwrap_err(),
            Errno::ENOTDIR
        );

        // fchdir on a closed fd → EBADF.
        task.sys_close(i32::try_from(dirfd).unwrap()).unwrap();
        assert_eq!(
            task.sys_fchdir(i32::try_from(dirfd).unwrap()).unwrap_err(),
            Errno::EBADF
        );

        task.sys_close(i32::try_from(filefd).unwrap()).unwrap();
    }

    #[test]
    fn host_stdio_tiocgpgrp_matches_process_group() {
        let task = crate::syscalls::tests::init_platform(None);

        let mut foreground_pgrp = -1_i32;
        task.sys_ioctl(
            0,
            IoctlArg::TIOCGPGRP(MutPtr::from_usize((&raw mut foreground_pgrp) as usize)),
        )
        .expect("TIOCGPGRP should succeed");

        let pgid = i32::try_from(task.sys_getpgid(0).expect("getpgid should succeed"))
            .expect("pgid should fit in i32");
        assert_eq!(foreground_pgrp, pgid);
    }

    #[test]
    fn host_stdio_tiocgsid_matches_session_id() {
        let task = crate::syscalls::tests::init_platform(None);

        let mut session_id = -1_i32;
        task.sys_ioctl(
            0,
            IoctlArg::TIOCGSID(MutPtr::from_usize((&raw mut session_id) as usize)),
        )
        .expect("TIOCGSID should succeed");

        let sid = i32::try_from(task.sys_getsid(0).expect("getsid should succeed"))
            .expect("sid should fit");
        assert_eq!(session_id, sid);
    }

    #[test]
    fn host_stdio_tiocspgrp_updates_shared_foreground_group() {
        let task = crate::syscalls::tests::init_platform(None);

        let child = task
            .global
            .litebox
            .process_registry()
            .create_process(Some(task.process_id), 0)
            .expect("child process should be created");
        task.global
            .litebox
            .process_registry()
            .set_pgid(task.process_id, child, ProcessGroupId::from(child))
            .expect("child should exist")
            .expect("setpgid should succeed");

        let child_pgrp = i32::try_from(child.0).expect("child pgid should fit in i32");
        task.sys_ioctl(
            0,
            IoctlArg::TIOCSPGRP(ConstPtr::from_usize((&raw const child_pgrp) as usize)),
        )
        .expect("TIOCSPGRP should succeed");

        // TIOCGPGRP always returns the caller's own pgid (not the stored
        // foreground pgrp) to avoid vfork/setsid race conditions.
        let mut foreground_pgrp = -1_i32;
        task.sys_ioctl(
            1,
            IoctlArg::TIOCGPGRP(MutPtr::from_usize((&raw mut foreground_pgrp) as usize)),
        )
        .expect("stdout TIOCGPGRP should succeed");
        let caller_pgid = i32::try_from(task.sys_getpgid(0).expect("getpgid")).unwrap();
        assert_eq!(foreground_pgrp, caller_pgid);
    }

    /// TIOCSPGRP on a PTY slave stores the foreground pgrp; TIOCGPGRP reads it
    /// back. When no pgrp has been set, TIOCGPGRP defaults to the caller's pid.
    #[test]
    fn pty_tiocspgrp_tiocgpgrp_round_trip() {
        let task = crate::syscalls::tests::init_platform(None);

        // Open a PTY master (/dev/ptmx), then the matching slave.
        let ptmx_fd = task
            .sys_open("/dev/ptmx", OFlags::RDWR, Mode::empty())
            .expect("open /dev/ptmx should succeed");
        let _ptmx_fd = i32::try_from(ptmx_fd).expect("fd should fit in i32");
        let slave_fd = task
            .sys_open("/dev/pts/0", OFlags::RDWR, Mode::empty())
            .expect("open /dev/pts/0 should succeed");
        let slave_fd_i32 = i32::try_from(slave_fd).expect("fd should fit in i32");

        // Before any TIOCSPGRP, TIOCGPGRP should default to the caller's pgid.
        let mut pgrp_out = -1_i32;
        task.sys_ioctl(
            slave_fd_i32,
            IoctlArg::TIOCGPGRP(MutPtr::from_usize((&raw mut pgrp_out) as usize)),
        )
        .expect("TIOCGPGRP on PTY slave should succeed");
        let expected_pgid =
            i32::try_from(task.sys_getpgid(0).expect("getpgid should succeed")).unwrap();
        assert_eq!(pgrp_out, expected_pgid, "default should be caller pgid");

        // Set a different foreground pgrp via TIOCSPGRP.
        let new_pgrp: i32 = 42;
        task.sys_ioctl(
            slave_fd_i32,
            IoctlArg::TIOCSPGRP(ConstPtr::from_usize((&raw const new_pgrp) as usize)),
        )
        .expect("TIOCSPGRP on PTY slave should succeed");

        // TIOCGPGRP always returns the caller's pgid (not the stored value)
        // to avoid vfork race conditions.
        let mut pgrp_out2 = -1_i32;
        task.sys_ioctl(
            slave_fd_i32,
            IoctlArg::TIOCGPGRP(MutPtr::from_usize((&raw mut pgrp_out2) as usize)),
        )
        .expect("TIOCGPGRP after TIOCSPGRP should succeed");
        assert_eq!(pgrp_out2, expected_pgid, "should still be caller pgid");
    }

    /// readlink("/proc/self/cwd") must return the CWD without a trailing slash.
    #[test]
    fn readlink_proc_self_cwd_no_trailing_slash() {
        let task = crate::syscalls::tests::init_platform(None);

        // Default CWD is "/" — readlink should return "/" (root is special).
        let mut buf = [0u8; 256];
        let len = task.sys_readlink("/proc/self/cwd", &mut buf).unwrap();
        let link = core::str::from_utf8(&buf[..len]).unwrap();
        assert_eq!(link, "/");

        // chdir to a subdirectory.
        task.sys_mkdir("/proc_cwd_test", 0o777).unwrap();
        task.sys_chdir("/proc_cwd_test").unwrap();

        let len = task.sys_readlink("/proc/self/cwd", &mut buf).unwrap();
        let link = core::str::from_utf8(&buf[..len]).unwrap();
        assert_eq!(link, "/proc_cwd_test", "must not have trailing slash");
    }

    #[test]
    fn proc_self_maps_reports_guest_stack() {
        let task = crate::syscalls::tests::init_platform(None);
        let stack_len =
            litebox::mm::linux::NonZeroPageSize::new(litebox::mm::linux::PAGE_SIZE).unwrap();
        unsafe {
            task.process_state
                .borrow()
                .pm
                .create_stack_pages(
                    None,
                    stack_len,
                    litebox::mm::linux::CreatePagesFlags::empty(),
                )
                .expect("create guest stack mapping");
        }
        let fd = task
            .sys_open("/proc/self/maps", OFlags::RDONLY, Mode::empty())
            .expect("open /proc/self/maps");

        let mut content = alloc::vec::Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = task
                .sys_read(i32::try_from(fd).unwrap(), &mut chunk, None)
                .expect("read /proc/self/maps");
            if n == 0 {
                break;
            }
            content.extend_from_slice(&chunk[..n]);
        }
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();

        let maps = alloc::string::String::from_utf8(content).expect("maps utf8");
        assert!(
            maps.contains("[stack]"),
            "maps should contain a guest stack line"
        );

        let host_exe = std::env::current_exe().expect("current_exe");
        let host_exe = host_exe.to_string_lossy();
        assert!(
            !maps.contains(host_exe.as_ref()),
            "maps must not leak host process mappings: {maps}"
        );
    }

    #[test]
    fn open_path_directory_does_not_panic() {
        let task = crate::syscalls::tests::init_platform(None);
        task.sys_mkdir("/opath_dir", 0o755).unwrap();
        let fd = task
            .sys_open(
                "/opath_dir",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .expect("O_PATH open should succeed");
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();
    }

    #[test]
    fn readlinkat_empty_path_on_non_symlink_fd_returns_enoent() {
        let task = crate::syscalls::tests::init_platform(None);
        task.sys_mkdir("/readlinkat_empty", 0o755).unwrap();
        let fd = task
            .sys_open(
                "/readlinkat_empty",
                OFlags::PATH | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .expect("O_PATH open should succeed");
        let mut buf = [0u8; 32];
        assert_eq!(
            task.sys_readlinkat(i32::try_from(fd).unwrap(), "", &mut buf)
                .unwrap_err(),
            Errno::ENOENT
        );
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();
    }

    #[test]
    fn readlinkat_empty_path_on_invalid_fd_returns_ebadf() {
        let task = crate::syscalls::tests::init_platform(None);
        let mut buf = [0u8; 32];
        assert_eq!(
            task.sys_readlinkat(123_456, "", &mut buf).unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn copy_file_range_updates_implicit_file_positions() {
        let task = crate::syscalls::tests::init_platform(None);
        let src = task
            .sys_open(
                "/copy-src",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let dst = task
            .sys_open(
                "/copy-dst",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let src = i32::try_from(src).unwrap();
        let dst = i32::try_from(dst).unwrap();

        assert_eq!(task.sys_write(src, b"hello world", None).unwrap(), 11);
        task.sys_lseek(src, 0, SeekWhence::RelativeToBeginning)
            .unwrap();

        assert_eq!(
            task.sys_copy_file_range(
                src,
                MutPtr::from_ptr(core::ptr::null_mut()),
                dst,
                MutPtr::from_ptr(core::ptr::null_mut()),
                5,
                0,
            )
            .unwrap(),
            5
        );
        assert_eq!(
            task.sys_lseek(src, 0, SeekWhence::RelativeToCurrentOffset)
                .unwrap(),
            5
        );
        assert_eq!(
            task.sys_lseek(dst, 0, SeekWhence::RelativeToCurrentOffset)
                .unwrap(),
            5
        );

        task.sys_lseek(dst, 0, SeekWhence::RelativeToBeginning)
            .unwrap();
        let mut buf = [0u8; 5];
        assert_eq!(task.sys_read(dst, &mut buf, None).unwrap(), 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn copy_file_range_explicit_offsets_leave_fd_positions_unchanged() {
        let task = crate::syscalls::tests::init_platform(None);
        let src = task
            .sys_open(
                "/copy-explicit-src",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let dst = task
            .sys_open(
                "/copy-explicit-dst",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let src = i32::try_from(src).unwrap();
        let dst = i32::try_from(dst).unwrap();

        assert_eq!(task.sys_write(src, b"abcdef", None).unwrap(), 6);
        assert_eq!(task.sys_write(dst, b"\0\0", None).unwrap(), 2);
        task.sys_lseek(dst, 0, SeekWhence::RelativeToBeginning)
            .unwrap();
        task.sys_lseek(src, 2, SeekWhence::RelativeToBeginning)
            .unwrap();
        task.sys_lseek(dst, 1, SeekWhence::RelativeToBeginning)
            .unwrap();

        let mut off_in = 1i64;
        let mut off_out = 0i64;
        assert_eq!(
            task.sys_copy_file_range(
                src,
                MutPtr::from_ptr(core::ptr::addr_of_mut!(off_in)),
                dst,
                MutPtr::from_ptr(core::ptr::addr_of_mut!(off_out)),
                3,
                0,
            )
            .unwrap(),
            3
        );
        assert_eq!(off_in, 4);
        assert_eq!(off_out, 3);
        assert_eq!(
            task.sys_lseek(src, 0, SeekWhence::RelativeToCurrentOffset)
                .unwrap(),
            2
        );
        assert_eq!(
            task.sys_lseek(dst, 0, SeekWhence::RelativeToCurrentOffset)
                .unwrap(),
            1
        );

        task.sys_lseek(dst, 0, SeekWhence::RelativeToBeginning)
            .unwrap();
        let mut buf = [0u8; 3];
        assert_eq!(task.sys_read(dst, &mut buf, None).unwrap(), 3);
        assert_eq!(&buf, b"bcd");
    }

    #[test]
    fn copy_file_range_rejects_append_destination() {
        let task = crate::syscalls::tests::init_platform(None);
        let src = task
            .sys_open(
                "/copy-append-src",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let dst = task
            .sys_open(
                "/copy-append-dst",
                OFlags::CREAT | OFlags::WRONLY | OFlags::APPEND,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let src = i32::try_from(src).unwrap();
        let dst = i32::try_from(dst).unwrap();

        assert_eq!(task.sys_write(src, b"abc", None).unwrap(), 3);
        task.sys_lseek(src, 0, SeekWhence::RelativeToBeginning)
            .unwrap();
        assert_eq!(
            task.sys_copy_file_range(
                src,
                MutPtr::from_ptr(core::ptr::null_mut()),
                dst,
                MutPtr::from_ptr(core::ptr::null_mut()),
                1,
                0,
            )
            .unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn copy_file_range_rejects_non_file_descriptors_with_einval() {
        let task = crate::syscalls::tests::init_platform(None);
        let src = task
            .sys_open(
                "/copy-nonfile-src",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let dst = task
            .sys_open(
                "/copy-nonfile-dst",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let src = i32::try_from(src).unwrap();
        let dst = i32::try_from(dst).unwrap();
        let (pipe_read, pipe_write) = task.sys_pipe2(OFlags::empty()).unwrap();
        let pipe_read = i32::try_from(pipe_read).unwrap();
        let pipe_write = i32::try_from(pipe_write).unwrap();

        assert_eq!(
            task.sys_copy_file_range(
                pipe_read,
                MutPtr::from_ptr(core::ptr::null_mut()),
                dst,
                MutPtr::from_ptr(core::ptr::null_mut()),
                1,
                0,
            )
            .unwrap_err(),
            Errno::EINVAL
        );
        assert_eq!(
            task.sys_copy_file_range(
                src,
                MutPtr::from_ptr(core::ptr::null_mut()),
                pipe_write,
                MutPtr::from_ptr(core::ptr::null_mut()),
                1,
                0,
            )
            .unwrap_err(),
            Errno::EINVAL
        );

        task.sys_close(pipe_read).unwrap();
        task.sys_close(pipe_write).unwrap();
    }

    #[test]
    fn copy_file_range_rejects_overlapping_ranges_on_same_file() {
        let task = crate::syscalls::tests::init_platform(None);
        let fd = task
            .sys_open(
                "/copy-overlap",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        let dup = i32::try_from(task.sys_dup(fd, None, None).unwrap()).unwrap();

        assert_eq!(task.sys_write(fd, b"abcdef", None).unwrap(), 6);
        let mut off_in = 0i64;
        let mut off_out = 1i64;
        assert_eq!(
            task.sys_copy_file_range(
                fd,
                MutPtr::from_ptr(core::ptr::addr_of_mut!(off_in)),
                dup,
                MutPtr::from_ptr(core::ptr::addr_of_mut!(off_out)),
                3,
                0,
            )
            .unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn copy_file_range_rejects_same_file_range_overflow() {
        let task = crate::syscalls::tests::init_platform(None);
        let fd = task
            .sys_open(
                "/copy-overflow",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        let dup = i32::try_from(task.sys_dup(fd, None, None).unwrap()).unwrap();

        let mut off_in = 0i64;
        let mut off_out = 1i64;
        assert_eq!(
            task.sys_copy_file_range(
                fd,
                MutPtr::from_ptr(core::ptr::addr_of_mut!(off_in)),
                dup,
                MutPtr::from_ptr(core::ptr::addr_of_mut!(off_out)),
                usize::MAX,
                0,
            )
            .unwrap_err(),
            Errno::EOVERFLOW
        );
    }

    #[test]
    fn copy_file_range_rejects_cross_file_range_overflow() {
        let task = crate::syscalls::tests::init_platform(None);
        let src = task
            .sys_open(
                "/copy-cross-overflow-src",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let dst = task
            .sys_open(
                "/copy-cross-overflow-dst",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let src = i32::try_from(src).unwrap();
        let dst = i32::try_from(dst).unwrap();

        assert_eq!(task.sys_write(src, b"x", None).unwrap(), 1);
        let mut off_in = 0i64;
        let mut off_out = 1i64;
        assert_eq!(
            task.sys_copy_file_range(
                src,
                MutPtr::from_ptr(core::ptr::addr_of_mut!(off_in)),
                dst,
                MutPtr::from_ptr(core::ptr::addr_of_mut!(off_out)),
                usize::MAX,
                0,
            )
            .unwrap_err(),
            Errno::EOVERFLOW
        );
    }

    #[test]
    fn copy_file_range_uses_current_position_after_clearing_append() {
        let task = crate::syscalls::tests::init_platform(None);
        let src = task
            .sys_open(
                "/copy-append-cleared-src",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let dst = task
            .sys_open(
                "/copy-append-cleared-dst",
                OFlags::CREAT | OFlags::WRONLY | OFlags::APPEND,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let src = i32::try_from(src).unwrap();
        let dst = i32::try_from(dst).unwrap();

        assert_eq!(task.sys_write(src, b"ab", None).unwrap(), 2);
        task.sys_lseek(src, 0, SeekWhence::RelativeToBeginning)
            .unwrap();
        task.sys_close(dst).unwrap();

        let dst = task
            .sys_open(
                "/copy-append-cleared-dst",
                OFlags::RDWR | OFlags::APPEND,
                Mode::empty(),
            )
            .unwrap();
        let dst = i32::try_from(dst).unwrap();
        assert_eq!(task.sys_write(dst, b"zzzz", None).unwrap(), 4);
        task.sys_fcntl(dst, FcntlArg::SETFL(OFlags::empty()))
            .unwrap();
        task.sys_lseek(dst, 1, SeekWhence::RelativeToBeginning)
            .unwrap();

        assert_eq!(
            task.sys_copy_file_range(
                src,
                MutPtr::from_ptr(core::ptr::null_mut()),
                dst,
                MutPtr::from_ptr(core::ptr::null_mut()),
                2,
                0,
            )
            .unwrap(),
            2
        );

        task.sys_lseek(dst, 0, SeekWhence::RelativeToBeginning)
            .unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(task.sys_read(dst, &mut buf, None).unwrap(), 4);
        assert_eq!(&buf, b"zabz");
    }

    #[test]
    fn copy_file_range_clamps_overlap_check_to_source_size() {
        let task = crate::syscalls::tests::init_platform(None);
        let fd = task
            .sys_open(
                "/copy-clamp-overlap",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let fd = i32::try_from(fd).unwrap();
        let dup = i32::try_from(task.sys_dup(fd, None, None).unwrap()).unwrap();

        assert_eq!(task.sys_write(fd, b"0123456789", None).unwrap(), 10);
        let mut off_in = 0i64;
        let mut off_out = 50i64;
        assert_eq!(
            task.sys_copy_file_range(
                fd,
                MutPtr::from_ptr(core::ptr::addr_of_mut!(off_in)),
                dup,
                MutPtr::from_ptr(core::ptr::addr_of_mut!(off_out)),
                100,
                0,
            )
            .unwrap(),
            10
        );
    }

    #[test]
    fn all_path_syscalls_respect_chdir() {
        use litebox_common_linux::{AccessFlags, AtFlags};

        let task = crate::syscalls::tests::init_platform(None);

        // Set up: mkdir + chdir into /cwd_test/.
        task.sys_mkdir("/cwd_test", 0o777).unwrap();
        task.sys_chdir("/cwd_test").unwrap();

        // ── sys_open: create a file via relative path ──
        let fd = task
            .sys_open(
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

        // ── sys_access: check relative file is accessible ──
        task.sys_access("file.txt", AccessFlags::F_OK).unwrap();

        // ── sys_mkdir: create a subdirectory via relative path ──
        task.sys_mkdir("subdir", 0o777).unwrap();
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

        // ── sys_rmdir: remove another directory via relative path ──
        task.sys_mkdir("subdir2", 0o777).unwrap();
        task.sys_rmdir("subdir2").unwrap();
        assert_eq!(
            task.sys_stat("/cwd_test/subdir2").unwrap_err(),
            Errno::ENOENT
        );
    }

    /// Verify `*_at` syscalls work with a real directory fd (FdRelative dispatch).
    #[test]
    fn fd_relative_syscalls() {
        use litebox_common_linux::AtFlags;

        let task = crate::syscalls::tests::init_platform(None);

        // Create /fdrel_test/ with a seed file.
        task.sys_mkdir("/fdrel_test", 0o777).unwrap();
        let seed_fd = task
            .sys_open(
                "/fdrel_test/seed.txt",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(seed_fd).unwrap()).unwrap();

        // Open the directory to get a real dirfd.
        let dirfd = task
            .sys_open(
                "/fdrel_test",
                litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
        let dirfd_i32 = i32::try_from(dirfd).unwrap();

        // ── sys_newfstatat(dirfd, "seed.txt") ──
        task.sys_newfstatat(dirfd_i32, "seed.txt", AtFlags::empty())
            .unwrap();

        // ── sys_openat(dirfd, "new.txt", O_CREAT|O_WRONLY) ──
        let new_fd = task
            .sys_openat(
                dirfd_i32,
                "new.txt",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(new_fd).unwrap()).unwrap();

        // Verify via absolute path that the file was created.
        task.sys_stat("/fdrel_test/new.txt").unwrap();

        // ── sys_unlinkat(dirfd, "new.txt") ──
        task.sys_unlinkat(dirfd_i32, "new.txt", AtFlags::empty())
            .unwrap();
        assert_eq!(
            task.sys_stat("/fdrel_test/new.txt").unwrap_err(),
            Errno::ENOENT
        );

        // ── sys_newfstatat(dirfd, "nonexistent") → ENOENT ──
        assert_eq!(
            task.sys_newfstatat(dirfd_i32, "nonexistent", AtFlags::empty())
                .unwrap_err(),
            Errno::ENOENT
        );

        // Clean up: close dirfd.
        task.sys_close(dirfd_i32).unwrap();

        // ── After closing dirfd, FdRelative should fail with EBADF ──
        assert_eq!(
            task.sys_newfstatat(dirfd_i32, "seed.txt", AtFlags::empty())
                .unwrap_err(),
            Errno::EBADF
        );
    }

    /// Non-directory fds used as dirfd must return ENOTDIR, not act on the file.
    #[test]
    fn fd_relative_rejects_non_directory_dirfd() {
        use litebox_common_linux::AtFlags;

        let task = crate::syscalls::tests::init_platform(None);

        // Create a regular file and open it.
        let filefd = task
            .sys_open(
                "/notdir_test_file",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let filefd_i32 = i32::try_from(filefd).unwrap();

        // fstatat(filefd, ".", ...) must return ENOTDIR, not stat the file.
        assert_eq!(
            task.sys_newfstatat(filefd_i32, ".", AtFlags::empty())
                .unwrap_err(),
            Errno::ENOTDIR
        );

        // openat(filefd, "child", ...) must return ENOTDIR.
        assert_eq!(
            task.sys_openat(
                filefd_i32,
                "child",
                litebox::fs::OFlags::RDONLY,
                Mode::empty(),
            )
            .unwrap_err(),
            Errno::ENOTDIR
        );

        // unlinkat(filefd, "child", 0) must return ENOTDIR.
        assert_eq!(
            task.sys_unlinkat(filefd_i32, "child", AtFlags::empty())
                .unwrap_err(),
            Errno::ENOTDIR
        );

        task.sys_close(filefd_i32).unwrap();
    }

    /// Verify `faccessat` works with AT_FDCWD, real dirfd, and invalid flags.
    #[test]
    fn faccessat_syscall() {
        use litebox_common_linux::{AccessFlags, AtFlags};

        let task = crate::syscalls::tests::init_platform(None);

        // Create /acc_test/ with a file inside.
        task.sys_mkdir("/acc_test", 0o777).unwrap();
        let fd = task
            .sys_open(
                "/acc_test/file.txt",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR | Mode::XUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();

        // ── faccessat(AT_FDCWD, absolute path, F_OK) ──
        task.sys_faccessat(
            litebox_common_linux::AT_FDCWD,
            "/acc_test/file.txt",
            AccessFlags::F_OK,
            AtFlags::empty(),
        )
        .unwrap();

        // ── faccessat(AT_FDCWD, relative path after chdir) ──
        task.sys_chdir("/acc_test").unwrap();
        task.sys_faccessat(
            litebox_common_linux::AT_FDCWD,
            "file.txt",
            AccessFlags::R_OK | AccessFlags::W_OK,
            AtFlags::empty(),
        )
        .unwrap();

        // ── faccessat with real dirfd ──
        let dirfd = task
            .sys_open(
                "/acc_test",
                litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
        let dirfd_i32 = i32::try_from(dirfd).unwrap();

        task.sys_faccessat(dirfd_i32, "file.txt", AccessFlags::F_OK, AtFlags::empty())
            .unwrap();

        task.sys_faccessat(
            dirfd_i32,
            "file.txt",
            AccessFlags::R_OK | AccessFlags::X_OK,
            AtFlags::empty(),
        )
        .unwrap();

        // ── faccessat on nonexistent file → ENOENT ──
        assert_eq!(
            task.sys_faccessat(dirfd_i32, "nope.txt", AccessFlags::F_OK, AtFlags::empty())
                .unwrap_err(),
            Errno::ENOENT
        );

        // ── faccessat with unsupported flags → EINVAL ──
        assert_eq!(
            task.sys_faccessat(
                litebox_common_linux::AT_FDCWD,
                "/acc_test/file.txt",
                AccessFlags::F_OK,
                AtFlags::AT_NO_AUTOMOUNT,
            )
            .unwrap_err(),
            Errno::EINVAL
        );

        task.sys_close(dirfd_i32).unwrap();
    }

    #[test]
    fn vectored_io_supports_hot_non_file_descriptors() {
        use litebox_common_linux::{AddressFamily, SockType};

        let task = crate::syscalls::tests::init_platform(None);

        // Pipe: writev + readv should preserve the byte stream.
        let (read_fd, write_fd) = task.sys_pipe2(OFlags::empty()).unwrap();
        let read_fd = i32::try_from(read_fd).unwrap();
        let write_fd = i32::try_from(write_fd).unwrap();
        let pipe_a = b"he";
        let pipe_b = b"llo";
        let pipe_write_iovs = [
            IoWriteVec {
                iov_base: ConstPtr::from_usize(pipe_a.as_ptr() as usize),
                iov_len: pipe_a.len(),
            },
            IoWriteVec {
                iov_base: ConstPtr::from_usize(pipe_b.as_ptr() as usize),
                iov_len: pipe_b.len(),
            },
        ];
        assert_eq!(
            task.sys_writev(
                write_fd,
                ConstPtr::from_usize(pipe_write_iovs.as_ptr() as usize),
                pipe_write_iovs.len(),
            )
            .unwrap(),
            5
        );
        let mut pipe_out_a = [0u8; 2];
        let mut pipe_out_b = [0u8; 3];
        let pipe_read_iovs = [
            IoReadVec {
                iov_base: MutPtr::from_usize(pipe_out_a.as_mut_ptr() as usize),
                iov_len: pipe_out_a.len(),
            },
            IoReadVec {
                iov_base: MutPtr::from_usize(pipe_out_b.as_mut_ptr() as usize),
                iov_len: pipe_out_b.len(),
            },
        ];
        assert_eq!(
            task.sys_readv(
                read_fd,
                ConstPtr::from_usize(pipe_read_iovs.as_ptr() as usize),
                pipe_read_iovs.len(),
            )
            .unwrap(),
            5
        );
        let mut pipe_combined = alloc::vec::Vec::new();
        pipe_combined.extend_from_slice(&pipe_out_a);
        pipe_combined.extend_from_slice(&pipe_out_b);
        assert_eq!(pipe_combined.as_slice(), b"hello");
        task.sys_close(read_fd).unwrap();
        task.sys_close(write_fd).unwrap();

        // Unix socketpair: stream and datagram paths should both handle
        // one-message scatter/gather I/O.
        for sock_type in [SockType::Stream, SockType::Datagram] {
            let mut sv = [0u32; 2];
            task.sys_socketpair(
                AddressFamily::UNIX as u32,
                sock_type as u32,
                0,
                MutPtr::from_usize(sv.as_mut_ptr() as usize),
            )
            .unwrap();
            let sock1 = i32::try_from(sv[0]).unwrap();
            let sock2 = i32::try_from(sv[1]).unwrap();

            let unix_a = b"unix";
            let unix_b = b"-iov";
            let unix_write_iovs = [
                IoWriteVec {
                    iov_base: ConstPtr::from_usize(unix_a.as_ptr() as usize),
                    iov_len: unix_a.len(),
                },
                IoWriteVec {
                    iov_base: ConstPtr::from_usize(unix_b.as_ptr() as usize),
                    iov_len: unix_b.len(),
                },
            ];
            assert_eq!(
                task.sys_writev(
                    sock1,
                    ConstPtr::from_usize(unix_write_iovs.as_ptr() as usize),
                    unix_write_iovs.len(),
                )
                .unwrap(),
                8
            );

            let mut unix_out_a = [0u8; 3];
            let mut unix_out_b = [0u8; 5];
            let unix_read_iovs = [
                IoReadVec {
                    iov_base: MutPtr::from_usize(unix_out_a.as_mut_ptr() as usize),
                    iov_len: unix_out_a.len(),
                },
                IoReadVec {
                    iov_base: MutPtr::from_usize(unix_out_b.as_mut_ptr() as usize),
                    iov_len: unix_out_b.len(),
                },
            ];
            assert_eq!(
                task.sys_readv(
                    sock2,
                    ConstPtr::from_usize(unix_read_iovs.as_ptr() as usize),
                    unix_read_iovs.len(),
                )
                .unwrap(),
                8
            );
            let mut unix_combined = alloc::vec::Vec::new();
            unix_combined.extend_from_slice(&unix_out_a);
            unix_combined.extend_from_slice(&unix_out_b);
            assert_eq!(unix_combined.as_slice(), b"unix-iov");

            task.sys_close(sock1).unwrap();
            task.sys_close(sock2).unwrap();
        }

        // eventfd: readv can split the 8-byte counter value across iovecs;
        // writev requires the first iovec to contain exactly 8 bytes.
        let eventfd = i32::try_from(task.sys_eventfd2(0, EfdFlags::empty()).unwrap()).unwrap();
        let event_value = 2u64.to_le_bytes();
        let ignored = *b"extra";
        let event_write_iovs = [
            IoWriteVec {
                iov_base: ConstPtr::from_usize(event_value.as_ptr() as usize),
                iov_len: event_value.len(),
            },
            IoWriteVec {
                iov_base: ConstPtr::from_usize(ignored.as_ptr() as usize),
                iov_len: ignored.len(),
            },
        ];
        assert_eq!(
            task.sys_writev(
                eventfd,
                ConstPtr::from_usize(event_write_iovs.as_ptr() as usize),
                event_write_iovs.len(),
            )
            .unwrap(),
            8
        );

        let mut event_out_a = [0u8; 4];
        let mut event_out_b = [0u8; 4];
        let event_read_iovs = [
            IoReadVec {
                iov_base: MutPtr::from_usize(event_out_a.as_mut_ptr() as usize),
                iov_len: event_out_a.len(),
            },
            IoReadVec {
                iov_base: MutPtr::from_usize(event_out_b.as_mut_ptr() as usize),
                iov_len: event_out_b.len(),
            },
        ];
        assert_eq!(
            task.sys_readv(
                eventfd,
                ConstPtr::from_usize(event_read_iovs.as_ptr() as usize),
                event_read_iovs.len(),
            )
            .unwrap(),
            8
        );
        let mut event_combined = alloc::vec::Vec::new();
        event_combined.extend_from_slice(&event_out_a);
        event_combined.extend_from_slice(&event_out_b);
        assert_eq!(event_combined.as_slice(), event_value.as_slice());

        let mut zero_len = [0u8; 0];
        let zero_read_iovs = [IoReadVec {
            iov_base: MutPtr::from_usize(zero_len.as_mut_ptr() as usize),
            iov_len: 0,
        }];
        assert_eq!(
            task.sys_readv(
                eventfd,
                ConstPtr::from_usize(zero_read_iovs.as_ptr() as usize),
                zero_read_iovs.len(),
            )
            .unwrap(),
            0
        );

        let split_a = 2u32.to_le_bytes();
        let split_b = 0u32.to_le_bytes();
        let bad_event_write_iovs = [
            IoWriteVec {
                iov_base: ConstPtr::from_usize(split_a.as_ptr() as usize),
                iov_len: split_a.len(),
            },
            IoWriteVec {
                iov_base: ConstPtr::from_usize(split_b.as_ptr() as usize),
                iov_len: split_b.len(),
            },
        ];
        assert_eq!(
            task.sys_writev(
                eventfd,
                ConstPtr::from_usize(bad_event_write_iovs.as_ptr() as usize),
                bad_event_write_iovs.len(),
            )
            .unwrap_err(),
            Errno::EINVAL
        );
        let zero_prefix_event_write_iovs = [
            IoWriteVec {
                iov_base: ConstPtr::from_usize(zero_len.as_ptr() as usize),
                iov_len: 0,
            },
            IoWriteVec {
                iov_base: ConstPtr::from_usize(event_value.as_ptr() as usize),
                iov_len: event_value.len(),
            },
        ];
        assert_eq!(
            task.sys_writev(
                eventfd,
                ConstPtr::from_usize(zero_prefix_event_write_iovs.as_ptr() as usize),
                zero_prefix_event_write_iovs.len(),
            )
            .unwrap_err(),
            Errno::EINVAL
        );

        let short_eventfd =
            i32::try_from(task.sys_eventfd2(1, EfdFlags::empty()).unwrap()).unwrap();
        let mut short_event_out = [0u8; 4];
        let short_event_read_iovs = [IoReadVec {
            iov_base: MutPtr::from_usize(short_event_out.as_mut_ptr() as usize),
            iov_len: short_event_out.len(),
        }];
        assert_eq!(
            task.sys_readv(
                short_eventfd,
                ConstPtr::from_usize(short_event_read_iovs.as_ptr() as usize),
                short_event_read_iovs.len(),
            )
            .unwrap_err(),
            Errno::EINVAL
        );

        task.sys_close(eventfd).unwrap();
        task.sys_close(short_eventfd).unwrap();
    }

    #[test]
    fn unix_socket_write_returns_epipe_instead_of_panicking() {
        use litebox_common_linux::{AddressFamily, SockType};

        let task = crate::syscalls::tests::init_platform(None);
        let mut sv = [0u32; 2];
        task.sys_socketpair(
            AddressFamily::UNIX as u32,
            SockType::Stream as u32,
            0,
            MutPtr::from_usize(sv.as_mut_ptr() as usize),
        )
        .unwrap();
        let sock1 = i32::try_from(sv[0]).unwrap();
        let sock2 = i32::try_from(sv[1]).unwrap();

        task.sys_close(sock2).unwrap();
        assert_eq!(task.sys_write(sock1, b"x", None).unwrap_err(), Errno::EPIPE);
        task.sys_close(sock1).unwrap();
    }

    /// rmdir(".", dirfd) must return EINVAL and rename(".", dirfd) must return EBUSY.
    #[test]
    fn dot_path_special_errors() {
        use litebox_common_linux::AtFlags;

        let task = crate::syscalls::tests::init_platform(None);

        task.sys_mkdir("/dot_test", 0o777).unwrap();
        task.sys_mkdir("/dot_test/sub", 0o777).unwrap();

        let dirfd = task
            .sys_open(
                "/dot_test/sub",
                litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
        let dirfd_i32 = i32::try_from(dirfd).unwrap();

        // unlinkat(dirfd, ".", AT_REMOVEDIR) → EINVAL (kernel behavior)
        assert_eq!(
            task.sys_unlinkat(dirfd_i32, ".", AtFlags::AT_REMOVEDIR)
                .unwrap_err(),
            Errno::EINVAL
        );
        assert_eq!(
            task.sys_unlinkat(dirfd_i32, "", AtFlags::AT_REMOVEDIR)
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(task.sys_rmdir(".").unwrap_err(), Errno::EINVAL);
        assert_eq!(task.sys_rmdir("./").unwrap_err(), Errno::EINVAL);
        assert_eq!(task.sys_rmdir("").unwrap_err(), Errno::ENOENT);
        assert_eq!(
            task.sys_rmdir("/dot_test/sub/.").unwrap_err(),
            Errno::EINVAL
        );
        assert_eq!(task.sys_rmdir("/..").unwrap_err(), Errno::ENOTEMPTY);
        assert_eq!(
            task.sys_unlinkat(
                litebox_common_linux::AT_FDCWD,
                "/dot_test/sub/.",
                AtFlags::AT_REMOVEDIR
            )
            .unwrap_err(),
            Errno::EINVAL
        );
        let parent_dirfd = task
            .sys_open(
                "/dot_test",
                litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
        let parent_dirfd_i32 = i32::try_from(parent_dirfd).unwrap();
        assert_eq!(
            task.sys_unlinkat(parent_dirfd_i32, "sub/.", AtFlags::AT_REMOVEDIR)
                .unwrap_err(),
            Errno::EINVAL
        );
        assert_eq!(
            task.sys_unlinkat(parent_dirfd_i32, "sub/..", AtFlags::AT_REMOVEDIR)
                .unwrap_err(),
            Errno::ENOTEMPTY
        );
        task.sys_chdir("/dot_test/sub").unwrap();
        assert_eq!(task.sys_rmdir("..").unwrap_err(), Errno::ENOTEMPTY);
        task.sys_chdir("/").unwrap();

        // renameat2(dirfd, ".", AT_FDCWD, "/dot_test/other") → EBUSY
        assert_eq!(
            task.sys_renameat2(
                dirfd_i32,
                ".",
                litebox_common_linux::AT_FDCWD,
                "/dot_test/other",
                0,
            )
            .unwrap_err(),
            Errno::EBUSY
        );

        // The directory must still exist after the failed operations.
        task.sys_stat("/dot_test/sub").unwrap();

        task.sys_close(dirfd_i32).unwrap();
        task.sys_close(parent_dirfd_i32).unwrap();
    }

    #[test]
    fn rmdir_syscall_handles_empty_nonempty_and_not_directory() {
        let task = crate::syscalls::tests::init_platform(None);

        task.sys_mkdir("/rmdir_test", 0o777).unwrap();
        task.sys_mkdir("/rmdir_test/empty_dir", 0o777).unwrap();
        task.sys_rmdir("/rmdir_test/empty_dir").unwrap();
        assert_eq!(
            task.sys_stat("/rmdir_test/empty_dir").unwrap_err(),
            Errno::ENOENT
        );

        task.sys_mkdir("/rmdir_test/nonempty", 0o777).unwrap();
        let fd = task
            .sys_open(
                "/rmdir_test/nonempty/file.txt",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();
        assert_eq!(
            task.sys_rmdir("/rmdir_test/nonempty").unwrap_err(),
            Errno::ENOTEMPTY
        );

        let file_fd = task
            .sys_open(
                "/rmdir_test/plain_file",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(file_fd).unwrap()).unwrap();
        assert_eq!(
            task.sys_rmdir("/rmdir_test/plain_file").unwrap_err(),
            Errno::ENOTDIR
        );
    }
}
