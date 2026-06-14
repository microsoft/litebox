// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides a Linux-compatible ABI via LiteBox.
//!
//! This shim is parametric in the choice of [LiteBox platform](../litebox/platform/index.html),
//! chosen by the [platform multiplex](../litebox_platform_multiplex/index.html).

#![no_std]
#![expect(
    clippy::unused_self,
    reason = "by convention, syscalls and related methods take &self even if unused"
)]
#![cfg_attr(feature = "trace_syscalls", allow(clippy::used_underscore_binding))]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use alloc::sync::Arc;
use core::cell::{Cell, RefCell};
use core::fmt::Write as _;
use core::sync::atomic::Ordering;
use litebox::{
    LiteBox,
    fd::TypedFd,
    mm::{PageManager, linux::PAGE_SIZE},
    platform::{RawConstPointer as _, RawMutPointer as _, TimeProvider},
    shim::ContinueOperation,
    sync::futex::FutexManager,
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt as _},
};
use litebox_common_linux::{SyscallRequest, errno::Errno};
use litebox_platform_multiplex::Platform;

/// Whether this shim build includes the worker-local smoltcp network stack.
pub const WORKER_LOCAL_INET: bool = cfg!(feature = "worker_local_inet");

#[cfg(feature = "worker_local_inet")]
struct LocalNetwork {
    inner: litebox::sync::Mutex<Platform, litebox::net::Network<Platform>>,
}

#[cfg(feature = "worker_local_inet")]
impl LocalNetwork {
    fn new(litebox: &LiteBox<Platform>) -> Self {
        let mut net = litebox::net::Network::new(litebox);
        net.set_platform_interaction(litebox::net::PlatformInteraction::Manual);
        Self {
            inner: litebox::sync::Mutex::new(net),
        }
    }

    fn lock(&self) -> litebox::sync::MutexGuard<'_, Platform, litebox::net::Network<Platform>> {
        self.inner.lock()
    }
}

/// On debug builds, logs that the user attempted to use an unsupported feature.
// DEVNOTE: this is before the `mod` declarations so that it can be used within them.
macro_rules! log_unsupported {
    ($($arg:tt)*) => {
        $crate::log_unsupported_fmt(core::format_args!($($arg)*));
    };
}

#[cfg(feature = "audit_log")]
pub mod audit;
pub(crate) mod channel;
pub mod loader;
#[cfg_attr(not(test), allow(dead_code))]
mod multihost;
pub(crate) mod stdio;
pub mod syscalls;
pub mod transport;
mod wait;

use crate::syscalls::file::get_file_descriptor_flags;

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

pub(crate) type FileFd<FS> = litebox::fd::TypedFd<FS>;

/// A trait required for file systems to be used in the shim.
pub trait ShimFS: litebox::fs::FileSystem + Send + Sync + 'static {}
impl<T: litebox::fs::FileSystem + Send + Sync + 'static> ShimFS for T {}

/// On debug builds, logs that the user attempted to use an unsupported feature.
fn log_unsupported_fmt(args: core::fmt::Arguments<'_>) {
    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;

        let msg = alloc::format!("WARNING: unsupported: {args}\n");
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = args;
    }
}

pub struct LinuxShimEntrypoints<FS: ShimFS> {
    task: Task<FS>,
    // The task should not be moved once it's bound to a platform thread so that
    // we preserve the ability to use TLS in the future.
    _not_send: core::marker::PhantomData<*const ()>,
}

impl<FS: ShimFS> LinuxShimEntrypoints<FS> {
    /// Returns the number of guest processes still running on this worker
    /// host. After the initial program exits, callers should keep the
    /// worker alive while this is > 0 (forked children outliving the
    /// initial parent).
    pub fn local_running_process_count(&self) -> usize {
        self.task.global.control_plane.local_running_process_count()
    }

    /// Returns a closure that snapshots `local_running_process_count()`
    /// when called. Allows callers to keep a count handle alive after
    /// `self` is moved (e.g. into `run_thread`).
    pub fn local_process_count_fn(&self) -> alloc::boxed::Box<dyn Fn() -> usize + Send + Sync>
    where
        FS: Send + Sync + 'static,
    {
        let global = self.task.global.clone();
        alloc::boxed::Box::new(move || global.control_plane.local_running_process_count())
    }

    /// Set the controlling PTY for the restored/exec'd task. Called by
    /// the runner during worker-exec startup if the parent process's
    /// `controlling_pty` was non-None at exec time, so that
    /// `open("/dev/tty")` in the new worker resolves correctly. Without
    /// this, the new ProcessState starts with `controlling_pty = None`
    /// and `/dev/tty` resolution fails.
    pub fn set_controlling_pty(&self, pty_id: u32) {
        *self.task.process_state.borrow().controlling_pty.lock() = Some(pty_id);
    }

    pub fn install_tcp_listen_bridge_fd(
        &self,
        guest_fd: usize,
        port: u16,
        reuse_port: bool,
    ) -> Result<(), litebox_common_linux::errno::Errno> {
        self.task
            .install_tcp_listen_bridge_fd(guest_fd, port, reuse_port)
    }

    pub fn install_signalfd_bridge_fd(
        &self,
        guest_fd: usize,
        handle_id: u64,
        mask_bits: u64,
        nonblock: bool,
    ) -> Result<(), litebox_common_linux::errno::Errno> {
        self.task
            .install_signalfd_bridge_fd(guest_fd, handle_id, mask_bits, nonblock)
    }

    pub fn install_brokerfile_bridge_fd(
        &self,
        guest_fd: usize,
        path: &str,
        position: usize,
        status_flags_bits: u32,
    ) -> Result<(), litebox_common_linux::errno::Errno> {
        self.task
            .install_brokerfile_bridge_fd(guest_fd, path, position, status_flags_bits)
    }

    /// Allocate a fresh client-side 9P fid via the underlying
    /// filesystem. See
    /// [`syscalls::file::Task::fs_allocate_fid_number`] for callers'
    /// obligation to install or free the resulting fid.
    pub fn fs_allocate_fid_number(&self) -> Result<u32, litebox_common_linux::errno::Errno> {
        self.task.fs_allocate_fid_number()
    }

    /// Free a client-side 9P fid via the underlying filesystem.
    pub fn fs_free_fid_number(&self, fid: u32) {
        self.task.fs_free_fid_number(fid);
    }

    /// Issue a real close/clunk for a server-visible 9P fid that failed to
    /// become a guest descriptor.
    pub fn fs_clunk_fid_number(&self, fid: u32) {
        self.task.fs_clunk_fid_number(fid);
    }

    /// Install a worker-side FS fd at `guest_fd` that wraps an
    /// existing server-side 9P fid. See
    /// [`syscalls::file::Task::install_brokerfile_bridge_fd_by_fid`]
    /// for the legacy-pipes Phase 3 D5-fs install path documentation.
    pub fn install_brokerfile_bridge_fd_by_fid(
        &self,
        guest_fd: usize,
        remote_fid: u32,
        path: &str,
        position: usize,
        status_flags_bits: u32,
    ) -> Result<(), litebox_common_linux::errno::Errno> {
        self.task.install_brokerfile_bridge_fd_by_fid(
            guest_fd,
            remote_fid,
            path,
            position,
            status_flags_bits,
        )
    }

    pub fn install_timerfd_bridge_fd(
        &self,
        guest_fd: usize,
        clockid: litebox_common_linux::ClockId,
        nonblock: bool,
        spec: litebox_common_linux::ItimerSpec,
        pending_expirations: u64,
        snapshot_now_ns: u64,
    ) -> Result<(), litebox_common_linux::errno::Errno> {
        self.task.install_timerfd_bridge_fd(
            guest_fd,
            clockid,
            nonblock,
            spec,
            pending_expirations,
            snapshot_now_ns,
        )
    }

    /// Install a broker-backed inotify fd at `guest_fd`, materialised
    /// from a broker handle that the parent dup'd before
    /// `exec_on_remote_host`. Mirrors `install_signalfd_bridge_fd`'s
    /// shape: shim-side `InotifyFile::new` wraps the inherited
    /// `handle_id` and registers at the matching descriptor-table
    /// slot. Called by the runner from `--inotify-bridge` specs.
    ///
    /// Returns `Err(ENODEV)` if no broker inotify provider is
    /// installed (the runner always installs one in `run()`, so this
    /// is a defensive guard rather than an expected runtime case).
    pub fn install_inotify_bridge_fd(
        &self,
        guest_fd: usize,
        handle_id: u64,
        nonblock: bool,
    ) -> Result<(), litebox_common_linux::errno::Errno> {
        let provider = syscalls::broker_inotify_provider().ok_or(Errno::ENODEV)?;
        use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
        let releaser: Arc<dyn BrokerSubscribable> = Arc::clone(&provider) as _;
        releaser.dup_handle(handle_id).map_err(|_| Errno::ENODEV)?;
        let mut flags = litebox::fs::OFlags::empty();
        if nonblock {
            flags |= litebox::fs::OFlags::NONBLOCK;
        }
        let file = syscalls::inotify::InotifyFile::new(provider, handle_id, flags);
        let typed: litebox::fd::TypedFd<syscalls::inotify::InotifySubsystem> =
            self.task.global.litebox.descriptor_table_mut().insert(file);

        let _ = self.task.do_close(guest_fd);
        let files = self.task.files.borrow();
        let mut rds = files.raw_descriptor_store.write();
        if rds.fd_into_specific_raw_integer(typed, guest_fd) {
            Ok(())
        } else {
            Err(Errno::EBADF)
        }
    }

    /// Install a fresh epoll instance at `guest_fd` and re-add every
    /// interest the parent had registered before
    /// `exec_on_remote_host`. Called by the runner from
    /// `--epoll-bridge` specs.
    ///
    /// `entries` is the snapshot of the parent's interest list as
    /// `(target_fd, events_bits, user_data)` tuples (see
    /// `EpollFile::snapshot_interests`). Each entry's `target_fd`
    /// must already be present in the worker's descriptor table —
    /// the runner orders `--epoll-bridge` install after
    /// `--broker-fd-bridge` and `--inotify-bridge` for exactly that
    /// reason.
    ///
    /// Entries whose target fd is not present or rejected by
    /// `epoll_ctl(ADD)` are skipped with a debug log marker rather
    /// than failing the whole install; matching the spirit of the
    /// pre-migration behaviour (the entry was lost when the fd
    /// became invalid).
    pub fn install_epoll_bridge_fd(
        &self,
        guest_fd: usize,
        entries: &[(u32, u32, u64)],
    ) -> Result<(), litebox_common_linux::errno::Errno> {
        let epoll_file = syscalls::epoll::EpollFile::<FS>::new();
        let typed: litebox::fd::TypedFd<syscalls::epoll::EpollSubsystem<FS>> = self
            .task
            .global
            .litebox
            .descriptor_table_mut()
            .insert(epoll_file);

        let _ = self.task.do_close(guest_fd);
        {
            let files = self.task.files.borrow();
            let mut rds = files.raw_descriptor_store.write();
            if !rds.fd_into_specific_raw_integer(typed, guest_fd) {
                return Err(Errno::EBADF);
            }
        }

        for &(target_fd, events_bits, data) in entries {
            let res = (|| -> Result<(), Errno> {
                let files = self.task.files.borrow();
                let epoll_typed = files
                    .raw_descriptor_store
                    .read()
                    .fd_from_raw_integer::<syscalls::epoll::EpollSubsystem<FS>>(guest_fd)
                    .map_err(|_| Errno::EBADF)?;
                let descriptor = syscalls::epoll::EpollDescriptor::try_from(
                    &self.task.global,
                    &files,
                    target_fd as usize,
                )?;
                let event = litebox_common_linux::EpollEvent {
                    events: events_bits,
                    data,
                };
                let handle = self
                    .task
                    .global
                    .litebox
                    .descriptor_table()
                    .entry_handle(&epoll_typed)
                    .ok_or(Errno::EBADF)?;
                handle.with_entry(|entry| {
                    entry.epoll_ctl(
                        &self.task.global,
                        &*files.fs,
                        litebox_common_linux::EpollOp::EpollCtlAdd,
                        target_fd,
                        &descriptor,
                        Some(event),
                    )
                })
            })();
            if let Err(e) = res {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "[epoll-bridge] skip ADD epfd={guest_fd} fd={target_fd} \
                     events={events_bits:#x} data={data:#x}: errno={e:?}\n"
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
        }
        Ok(())
    }

    pub fn install_broker_tcp_conn_bridge_fd(
        &self,
        guest_fd: usize,
        handle_id: u64,
    ) -> Result<(), litebox_common_linux::errno::Errno> {
        let provider =
            syscalls::broker_tcp_conn::broker_tcp_conn_provider().ok_or(Errno::ENODEV)?;
        use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
        let releaser: alloc::sync::Arc<dyn BrokerSubscribable> = Arc::clone(&provider) as _;
        let _ = releaser.dup_handle(handle_id);
        let tcp_fd = syscalls::broker_tcp_conn::BrokerTcpConnFd::<Platform>::new(
            provider,
            handle_id,
            litebox::fs::OFlags::empty(),
        );
        let typed: litebox::fd::TypedFd<syscalls::broker_tcp_conn::BrokerTcpConnSubsystem> = self
            .task
            .global
            .litebox
            .descriptor_table_mut()
            .insert(tcp_fd);

        let _ = self.task.do_close(guest_fd);
        let files = self.task.files.borrow();
        let mut rds = files.raw_descriptor_store.write();
        if rds.fd_into_specific_raw_integer(typed, guest_fd) {
            Ok(())
        } else {
            Err(Errno::EBADF)
        }
    }

    /// Install a host-passthrough fd into the restored child's descriptor table.
    ///
    /// INVARIANT: callers must pass a literal host fd whose semantics cannot be
    /// represented by a broker-held descriptor at this boundary. Today this is
    /// used for explicit Unix-socket passthroughs handed to a fork-restored
    /// worker; the parent and worker share/pass the host socket fd itself, and a
    /// future cross-binary-type fork path must replace this with a broker handle
    /// or fd-token handoff before relying on it to survive another worker hop.
    /// This replaces any existing endpoint at the given guest FD number.
    pub fn install_host_passthrough_fd(
        &self,
        guest_fd: usize,
        host_fd: i32,
        direction: syscalls::host_passthrough_fd::HostPassthroughFdDirection,
    ) {
        let entry = syscalls::host_passthrough_fd::HostPassthroughFdEntry::new(host_fd, direction);
        let mut dt = self.task.global.litebox.descriptor_table_mut();
        let typed_fd: litebox::fd::TypedFd<syscalls::host_passthrough_fd::HostPassthroughFd> =
            dt.insert(entry);
        drop(dt);

        let files = self.task.files.borrow();
        let mut rds = files.raw_descriptor_store.write();

        // Remove the existing entry at this slot, regardless of subsystem type.
        // The slot might hold a virtual Pipe (from snapshot), a StdioFd (from
        // the init process if fd_table restore is not yet implemented), or
        // nothing at all.  Close the consumed descriptor properly to avoid
        // leaking descriptor-table entries.
        if let Ok(old_fs) = rds.fd_consume_raw_integer::<FS>(guest_fd) {
            drop(rds);
            let _ = files.fs.close(&old_fs);
            rds = files.raw_descriptor_store.write();
        } else if let Ok(old_sock) =
            rds.fd_consume_raw_integer::<syscalls::unix::UnixSocketSubsystem<FS>>(guest_fd)
        {
            // Remove descriptor table entry to avoid leaking the socket.
            drop(rds);
            let _ = self
                .task
                .global
                .litebox
                .descriptor_table_mut()
                .remove(&old_sock);
            rds = files.raw_descriptor_store.write();
        } else if let Ok(old_broker_pipe) =
            rds.fd_consume_raw_integer::<syscalls::broker_pipe::BrokerPipeSubsystem>(guest_fd)
        {
            drop(rds);
            let _ = self
                .task
                .global
                .litebox
                .descriptor_table_mut()
                .remove(&old_broker_pipe);
            rds = files.raw_descriptor_store.write();
        } else if let Ok(old_host) =
            rds.fd_consume_raw_integer::<syscalls::host_passthrough_fd::HostPassthroughFd>(guest_fd)
        {
            drop(rds);
            let entry = self
                .task
                .global
                .litebox
                .descriptor_table_mut()
                .remove(&old_host);
            if let Some(entry) = entry {
                let host_fd = entry.take_fd();
                if host_fd >= 0 {
                    self.task.global.platform.close_host_fd(host_fd);
                }
            }
            rds = files.raw_descriptor_store.write();
        }

        // Install the HostPassthroughFdEntry FD at the same guest fd number.
        let ok = rds.fd_into_specific_raw_integer(typed_fd, guest_fd);
        debug_assert!(
            ok,
            "install_host_passthrough_fd: slot {guest_fd} still occupied"
        );
    }

    fn dup_broker_bridge_handle(
        releaser: alloc::sync::Arc<
            dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
        >,
        handle_id: u64,
    ) -> Result<(), ()> {
        releaser.dup_handle(handle_id).map_err(|_| ())
    }

    fn remove_typed_fd<Subsystem>(&self, typed: &litebox::fd::TypedFd<Subsystem>)
    where
        Subsystem: litebox::fd::FdEnabledSubsystem,
    {
        let _ = self
            .task
            .global
            .litebox
            .descriptor_table_mut()
            .remove(typed);
    }

    fn consume_broker_bridge_slot(&self, files: &syscalls::file::FilesState<FS>, guest_fd: usize) {
        let mut rds = files.raw_descriptor_store.write();
        #[cfg(feature = "worker_local_inet")]
        if let Ok(old_sock) =
            rds.fd_consume_raw_integer::<litebox::net::Network<Platform>>(guest_fd)
        {
            drop(rds);
            let _ = self
                .task
                .global
                .net
                .lock()
                .close(&old_sock, litebox::net::CloseBehavior::Immediate);
            return;
        }
        if let Ok(old_fs) = rds.fd_consume_raw_integer::<FS>(guest_fd) {
            drop(rds);
            let _ = files.fs.close(&old_fs);
        } else if let Ok(old_unix) =
            rds.fd_consume_raw_integer::<syscalls::unix::UnixSocketSubsystem<FS>>(guest_fd)
        {
            drop(rds);
            self.remove_typed_fd(&old_unix);
        } else if let Ok(old_eventfd) =
            rds.fd_consume_raw_integer::<syscalls::eventfd::EventfdSubsystem>(guest_fd)
        {
            drop(rds);
            self.remove_typed_fd(&old_eventfd);
        } else if let Ok(old_broker_pipe) =
            rds.fd_consume_raw_integer::<syscalls::broker_pipe::BrokerPipeSubsystem>(guest_fd)
        {
            drop(rds);
            self.remove_typed_fd(&old_broker_pipe);
        } else if let Ok(old_broker_sp) = rds
            .fd_consume_raw_integer::<syscalls::broker_socketpair::BrokerSocketPairSubsystem>(
                guest_fd,
            )
        {
            drop(rds);
            self.remove_typed_fd(&old_broker_sp);
        } else if let Ok(old_tcp) = rds
            .fd_consume_raw_integer::<syscalls::broker_tcp_conn::BrokerTcpConnSubsystem>(guest_fd)
        {
            drop(rds);
            self.remove_typed_fd(&old_tcp);
        } else if let Ok(old_listener) = rds
            .fd_consume_raw_integer::<syscalls::broker_inet_listener::BrokerInetListenerSubsystem>(
            guest_fd,
        ) {
            drop(rds);
            self.remove_typed_fd(&old_listener);
        } else if let Ok(old_dgram) = rds
            .fd_consume_raw_integer::<syscalls::broker_inet_dgram::BrokerInetDgramSubsystem>(
                guest_fd,
            )
        {
            drop(rds);
            self.remove_typed_fd(&old_dgram);
        } else if let Ok(old_host) =
            rds.fd_consume_raw_integer::<syscalls::host_passthrough_fd::HostPassthroughFd>(guest_fd)
        {
            drop(rds);
            if let Some(entry) = self
                .task
                .global
                .litebox
                .descriptor_table_mut()
                .remove(&old_host)
            {
                let host_fd = entry.take_fd();
                if host_fd >= 0 {
                    self.task.global.platform.close_host_fd(host_fd);
                }
            }
        }
    }

    fn install_typed_broker_bridge_fd_at_slot<Subsystem>(
        &self,
        typed: litebox::fd::TypedFd<Subsystem>,
        guest_fd: usize,
        files: &syscalls::file::FilesState<FS>,
        label: &str,
    ) -> Result<(), ()>
    where
        Subsystem: litebox::fd::FdEnabledSubsystem,
    {
        self.consume_broker_bridge_slot(files, guest_fd);
        let mut rds = files.raw_descriptor_store.write();
        if rds.is_alive(guest_fd) {
            drop(rds);
            self.remove_typed_fd(&typed);
            return Err(());
        }
        let ok = rds.fd_into_specific_raw_integer(typed, guest_fd);
        debug_assert!(
            ok,
            "install_broker_bridge_fd({label}): slot {guest_fd} still occupied"
        );
        if ok { Ok(()) } else { Err(()) }
    }

    /// Install a broker-backed shim fd entry at `guest_fd`, materializing
    /// it from a broker handle that the parent dup'd before spawn. Called
    /// by the runner during worker-exec startup for every `--broker-fd-bridge`
    /// spec, so the worker sees the same shared broker state as the parent
    /// across the cross-binary-type exec boundary.
    ///
    /// Returns `Err(())` if no broker provider is installed for the
    /// requested kind (the worker will then have no fd at the slot
    /// and the binary's read on it will fail with EBADF — a clean
    /// failure mode for misconfigured workers).
    ///
    /// The snapshot variant determines which broker provider to consult
    /// and how to build the per-fd shim entry. Match is exhaustive; new
    /// `BrokerHandleSnapshot` variants fail to compile here.
    ///
    /// `pipe_flags` is the open-flags bits (NONBLOCK in particular) the
    /// caller wants applied to the constructed fd. For PTYs it is
    /// ignored because the PTY provider's `reacquire` re-derives flags
    /// from its own per-handle state.
    #[deny(clippy::wildcard_enum_match_arm)]
    pub fn install_broker_bridge_fd(
        &self,
        guest_fd: usize,
        snapshot: syscalls::fork_snapshot::BrokerHandleSnapshot,
        pipe_flags: litebox::fs::OFlags,
    ) -> Result<(), ()> {
        use syscalls::fork_snapshot::BrokerHandleSnapshot;
        let files = self.task.files.borrow();
        match snapshot {
            BrokerHandleSnapshot::Eventfd { handle_id } => {
                let provider = syscalls::eventfd::broker_eventfd_provider().ok_or(())?;
                let event_file = syscalls::eventfd::EventFile::new_broker_backed(
                    provider,
                    handle_id,
                    litebox_common_linux::EfdFlags::empty(),
                );
                self.install_eventfd_at_slot(event_file, guest_fd, &files);
                Ok(())
            }
            BrokerHandleSnapshot::Pidfd { handle_id } => {
                let target_pid =
                    litebox::process::ProcessId(u32::try_from(handle_id).map_err(|_| ())?);
                let subscription =
                    syscalls::guest_pid::try_subscribe_broker_process_exit(target_pid).ok_or(())?;
                let event_file = syscalls::eventfd::EventFile::new_broker_process_pidfd(
                    target_pid,
                    subscription,
                    false,
                    None,
                );
                self.install_eventfd_at_slot(event_file, guest_fd, &files);
                Ok(())
            }
            BrokerHandleSnapshot::Pipe {
                handle_id,
                direction,
            } => {
                let provider = syscalls::broker_pipe::broker_pipe_provider().ok_or(())?;
                use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                    alloc::sync::Arc::clone(&provider) as _;
                Self::dup_broker_bridge_handle(releaser, handle_id)?;
                let bp_fd = syscalls::broker_pipe::BrokerPipeFd::<Platform>::new(
                    provider, handle_id, direction, pipe_flags,
                    1, // creation_site: install_broker_bridge_fd
                );
                let typed: litebox::fd::TypedFd<syscalls::broker_pipe::BrokerPipeSubsystem> = self
                    .task
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .insert(bp_fd);
                self.install_typed_broker_bridge_fd_at_slot(typed, guest_fd, &files, "pipe")
            }
            BrokerHandleSnapshot::UnixSocket {
                handle_id,
                endpoint,
            } => {
                let provider =
                    syscalls::broker_socketpair::broker_socketpair_provider().ok_or(())?;
                // Mirror C.5j's pipe pattern: explicit per-worker
                // dup_handle so the broker's per-connection refcount
                // tracker records our ownership and disconnect-cleanup
                // can find the entry.
                use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                    alloc::sync::Arc::clone(&provider) as _;
                Self::dup_broker_bridge_handle(releaser, handle_id)?;
                let sp_fd = syscalls::broker_socketpair::BrokerSocketPairFd::<Platform>::new(
                    provider, handle_id, endpoint, pipe_flags,
                );
                let typed: litebox::fd::TypedFd<
                    syscalls::broker_socketpair::BrokerSocketPairSubsystem,
                > = self
                    .task
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .insert(sp_fd);
                self.install_typed_broker_bridge_fd_at_slot(typed, guest_fd, &files, "unix_socket")
            }
            BrokerHandleSnapshot::SocketDgram { handle_id } => {
                let provider =
                    syscalls::broker_socket_dgram::broker_socket_dgram_provider().ok_or(())?;
                use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                    alloc::sync::Arc::clone(&provider) as _;
                Self::dup_broker_bridge_handle(releaser, handle_id)?;
                let dgram = syscalls::broker_socket_dgram::BrokerSocketDgramFd::<Platform>::new(
                    provider,
                    handle_id,
                    litebox::fs::OFlags::empty(),
                );
                let typed: litebox::fd::TypedFd<
                    syscalls::broker_socket_dgram::BrokerSocketDgramSubsystem,
                > = self
                    .task
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .insert(dgram);
                self.install_typed_broker_bridge_fd_at_slot(typed, guest_fd, &files, "socket_dgram")
            }
            BrokerHandleSnapshot::SocketSeqPacket { handle_id } => {
                let provider =
                    syscalls::broker_socket_seqpacket::broker_socket_seqpacket_provider()
                        .ok_or(())?;
                use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                    alloc::sync::Arc::clone(&provider) as _;
                Self::dup_broker_bridge_handle(releaser, handle_id)?;
                let seqpacket = syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketFd::<
                    Platform,
                >::new(
                    provider, handle_id, litebox::fs::OFlags::empty()
                );
                let typed: litebox::fd::TypedFd<
                    syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem,
                > = self
                    .task
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .insert(seqpacket);
                self.install_typed_broker_bridge_fd_at_slot(
                    typed,
                    guest_fd,
                    &files,
                    "socket_seqpacket",
                )
            }
            BrokerHandleSnapshot::TcpConn { handle_id } => {
                let provider = syscalls::broker_tcp_conn::broker_tcp_conn_provider().ok_or(())?;
                use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                    alloc::sync::Arc::clone(&provider) as _;
                Self::dup_broker_bridge_handle(releaser, handle_id)?;
                let tcp_fd = syscalls::broker_tcp_conn::BrokerTcpConnFd::<Platform>::new(
                    provider,
                    handle_id,
                    litebox::fs::OFlags::empty(),
                );
                let typed: litebox::fd::TypedFd<syscalls::broker_tcp_conn::BrokerTcpConnSubsystem> =
                    self.task
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .insert(tcp_fd);
                self.install_typed_broker_bridge_fd_at_slot(typed, guest_fd, &files, "tcp_conn")
            }
            BrokerHandleSnapshot::InetDgram { handle_id } => {
                let provider =
                    syscalls::broker_inet_dgram::broker_inet_dgram_provider().ok_or(())?;
                use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                    alloc::sync::Arc::clone(&provider) as _;
                Self::dup_broker_bridge_handle(releaser, handle_id)?;
                let dgram = syscalls::broker_inet_dgram::BrokerInetDgramFd::<Platform>::new(
                    provider,
                    handle_id,
                    litebox::fs::OFlags::empty(),
                );
                let typed: litebox::fd::TypedFd<
                    syscalls::broker_inet_dgram::BrokerInetDgramSubsystem,
                > = self
                    .task
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .insert(dgram);
                self.install_typed_broker_bridge_fd_at_slot(typed, guest_fd, &files, "inet_dgram")
            }
            BrokerHandleSnapshot::InetListener { handle_id } => {
                let provider =
                    syscalls::broker_inet_listener::broker_inet_listener_provider().ok_or(())?;
                use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                    alloc::sync::Arc::clone(&provider) as _;
                Self::dup_broker_bridge_handle(releaser, handle_id)?;
                let listener =
                    syscalls::broker_inet_listener::BrokerInetListenerFd::<Platform>::new(
                        provider,
                        handle_id,
                        0,
                        litebox::fs::OFlags::empty(),
                    );
                let typed: litebox::fd::TypedFd<
                    syscalls::broker_inet_listener::BrokerInetListenerSubsystem,
                > = self
                    .task
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .insert(listener);
                self.install_typed_broker_bridge_fd_at_slot(
                    typed,
                    guest_fd,
                    &files,
                    "inet_listener",
                )
            }
            // C.5l guardrail: Signalfd is accepted by the
            // emit-side fork-snapshot code, but the install side
            // here has no implementation. Returning `Err(())` was
            // historically a silent skip (caller logs at the
            // runner level but no early panic). Make it a hard
            // failure so a snapshot carrying this kind crashes loudly
            // instead of leaking broker refs and stalling readers.
            BrokerHandleSnapshot::Signalfd { handle_id } => todo!(
                "install_broker_bridge_fd for BrokerHandleSnapshot::Signalfd \
                 not implemented yet (guest_fd={guest_fd}, handle_id={handle_id})"
            ),
            BrokerHandleSnapshot::Pty {
                handle_id,
                role,
                pty_id,
            } => {
                let provider = syscalls::broker_pty::broker_pty_provider().ok_or(())?;
                let pty_fd = syscalls::broker_pty::BrokerPtyProviderReacquireExt::reacquire(
                    &provider, handle_id, role, pty_id,
                )
                .map_err(|_| ())?;
                self.install_broker_pty_at_slot(pty_fd, guest_fd, &files)
            }
        }
    }

    fn install_broker_pty_at_slot(
        &self,
        pty_fd: syscalls::broker_pty::BrokerPtyFd<Platform>,
        guest_fd: usize,
        files: &syscalls::file::FilesState<FS>,
    ) -> Result<(), ()> {
        let typed_fd: litebox::fd::TypedFd<syscalls::broker_pty::BrokerPtySubsystem> = self
            .task
            .global
            .litebox
            .descriptor_table_mut()
            .insert(pty_fd);

        let mut rds = files.raw_descriptor_store.write();
        let _ = rds.fd_consume_raw_integer::<FS>(guest_fd);
        let ok = rds.fd_into_specific_raw_integer(typed_fd, guest_fd);
        debug_assert!(
            ok,
            "install_broker_bridge_fd(pty): slot {guest_fd} still occupied"
        );
        if ok { Ok(()) } else { Err(()) }
    }

    fn install_eventfd_at_slot(
        &self,
        event_file: syscalls::eventfd::EventFile<Platform>,
        guest_fd: usize,
        files: &syscalls::file::FilesState<FS>,
    ) {
        let typed_fd: litebox::fd::TypedFd<syscalls::eventfd::EventfdSubsystem> = self
            .task
            .global
            .litebox
            .descriptor_table_mut()
            .insert(event_file);

        // Pre-subscribe so the child binary's blocking read() on the
        // inherited eventfd can be woken by the parent's broker write.
        // Without this, the broker subscription is only set up by
        // epoll's register_observer path, and direct read() hangs.
        self.task.global.litebox.descriptor_table().with_entry(
            &typed_fd,
            |ef: &syscalls::eventfd::EventFile<Platform>| {
                ef.pre_subscribe_for_broker_blocking_read();
            },
        );

        let mut rds = files.raw_descriptor_store.write();

        // Remove any existing entry at the slot (stdio placeholder etc.).
        let _ = rds.fd_consume_raw_integer::<FS>(guest_fd);

        let ok = rds.fd_into_specific_raw_integer(typed_fd, guest_fd);
        debug_assert!(
            ok,
            "install_broker_bridge_fd(eventfd): slot {guest_fd} still occupied"
        );
    }
}

impl<FS: ShimFS> litebox::shim::EnterShim for LinuxShimEntrypoints<FS> {
    type ExecutionContext = litebox_common_linux::ExecutionContext;

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
        // CoW fault (vfork snapshotting): check BEFORE kernel-mode page fault
        // handler, because kernel-mode (shim) code can touch guest pages that
        // we mprotected for CoW. bit 1 = write access.
        if info.exception == litebox::shim::Exception::PAGE_FAULT
            && (info.error_code & 0x2) == 0x2
            && self
                .task
                .try_handle_cow_fault(info.cr2, ctx, (info.error_code & 1) != 0)
        {
            return ContinueOperation::Resume;
        }
        if info.exception == litebox::shim::Exception::PAGE_FAULT {
            let should_try_page_manager = info.kernel_mode
                || <crate::Platform as litebox::mm::linux::VmemPageFaultHandler>::HANDLE_USER_PAGE_FAULTS;
            if should_try_page_manager {
                // SAFETY: We are servicing a live page-fault trap for the
                // current task. `cr2` and `error_code` come directly from the
                // trap context, and `pm` is this task's PageManager.
                match unsafe {
                    self.task
                        .process_state
                        .borrow()
                        .pm
                        .handle_page_fault(info.cr2, info.error_code.into())
                } {
                    Ok(()) => return ContinueOperation::Resume,
                    Err(_) if info.kernel_mode => return ContinueOperation::Terminate,
                    Err(_) => {}
                }
            }
        }
        self.enter_shim(false, ctx, |task, ctx| {
            task.handle_exception_request(info, ctx);
        })
    }

    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, |_, _| {})
    }

    fn process_id(&self) -> Option<litebox::process::ProcessId> {
        Some(self.task.process_id)
    }

    fn signal_target_scope(&self) -> Option<usize> {
        Some(Arc::as_ptr(&self.task.global).addr())
    }
}

impl<FS: ShimFS> LinuxShimEntrypoints<FS> {
    fn enter_shim(
        &self,
        is_init: bool,
        ctx: &mut litebox_common_linux::ExecutionContext,
        f: impl FnOnce(&Task<FS>, &mut litebox_common_linux::ExecutionContext),
    ) -> ContinueOperation {
        // Clear syscall context flag. handle_syscall_request sets it back
        // to true; exception/interrupt handlers leave it false so that
        // signal frame construction preserves the real guest R11.
        self.task.in_syscall.set(false);

        if !is_init {
            self.task.enter_from_guest();
        }
        f(&self.task, ctx);
        if self.task.prepare_to_run_guest(ctx) {
            ContinueOperation::Resume
        } else {
            ContinueOperation::Terminate
        }
    }
}

/// The shim entry point structure.
pub struct LinuxShimBuilder {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
    load_filter: Option<LoadFilter>,
}

impl Default for LinuxShimBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxShimBuilder {
    /// Returns a new shim builder with an **empty** process registry.
    ///
    /// The init process is not yet allocated; callers must call
    /// [`init_with_pid`](Self::init_with_pid) once they know the
    /// externally-allocated init pid (e.g. handed out by the broker).
    /// In test code, prefer [`new_for_test`](Self::new_for_test) which
    /// creates init at [`litebox::process::ProcessId::INIT`].
    pub fn new() -> Self {
        let platform = litebox_platform_multiplex::platform();
        Self {
            platform,
            litebox: LiteBox::new(platform),
            load_filter: None,
        }
    }

    /// Convenience constructor for tests: returns a builder whose init
    /// process is already allocated at [`litebox::process::ProcessId::INIT`].
    pub fn new_for_test() -> Self {
        let platform = litebox_platform_multiplex::platform();
        Self {
            platform,
            litebox: LiteBox::new_for_test(platform),
            load_filter: None,
        }
    }

    /// Allocate the init process at the given externally-allocated pid.
    ///
    /// Production runners call this after the broker has assigned a pid
    /// for the root init (see `runner_linux_userland::run`'s
    /// `RegisterProcess` reservation).
    ///
    /// # Panics
    ///
    /// Panics if init has already been allocated (e.g. the builder came
    /// from [`new_for_test`](Self::new_for_test)).
    pub fn init_with_pid(&self, pid: litebox::process::ProcessId) {
        self.litebox
            .process_registry()
            .create_process_with_id(pid, None, 0)
            .expect("init process creation must succeed");
    }

    /// Like [`init_with_pid`] but for fork-restored child workers that
    /// inherit pgid/sid from their parent's snapshot. Without this, the
    /// child registry entry would default to pgid=sid=pid, making any
    /// subsequent guest `setsid()` fail with EPERM ("already group
    /// leader"). This is required for any guest fork-then-setsid pattern,
    /// notably dropbear SSH session children.
    pub fn init_for_fork_restore(
        &self,
        pid: litebox::process::ProcessId,
        pgid: litebox::process::ProcessGroupId,
        sid: litebox::process::SessionId,
    ) {
        self.litebox
            .process_registry()
            .create_process_with_id_and_pgrp(pid, None, Some((pgid, sid)), 0)
            .expect("fork-restored process creation must succeed");
    }

    /// Returns the litebox object for the shim.
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
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
    /// Panics if the platform cannot allocate an address space for the init process.
    pub fn build<FS: ShimFS>(self) -> LinuxShim<FS> {
        use litebox::platform::AddressSpaceProvider;
        use litebox::platform::RawMutex as _;

        #[cfg(feature = "worker_local_inet")]
        let net = LocalNetwork::new(&self.litebox);

        // Allocate the init process's address space (slot 0 on userland).
        let init_as_id = self
            .platform
            .create_address_space()
            .expect("init process address space allocation must succeed");
        let as_range = self
            .platform
            .address_space_range(init_as_id)
            .expect("init address space range must be valid");

        let process_state = Arc::new(ProcessState {
            pm: PageManager::new(&self.litebox, as_range),
            address_space_id: init_as_id,
            thread_count: core::sync::atomic::AtomicI32::new(1),
            controlling_pty: litebox::sync::Mutex::new(None),
            active_vfork_layers: litebox::sync::Mutex::new(Vec::new()),
            elf_patch_cache: litebox::sync::Mutex::new(alloc::collections::BTreeMap::new()),
            shared_file_mappings: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
            main_bss_start: core::sync::atomic::AtomicUsize::new(0),
            main_bss_end: core::sync::atomic::AtomicUsize::new(0),
            proc_map_paths: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
            vfork_parking: Arc::new(VforkParking {
                park: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
                parked_count: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
                deferred_lie_count: core::sync::atomic::AtomicU32::new(0),
            }),
        });
        let control_plane = multihost::ControlPlane::new_root_local();
        let init_process_id = self
            .litebox
            .process_registry()
            .root_pid()
            .expect("init process must have been allocated before build()");
        control_plane
            .register_running_process_local(init_process_id)
            .expect("init process must be registered to the root host");
        let global = Arc::new(GlobalState {
            platform: self.platform,
            futex_manager: FutexManager::new(),
            #[cfg(feature = "worker_local_inet")]
            net,
            boot_time: self.platform.now(),
            load_filter: self.load_filter,
            next_thread_id: 2.into(), // start from 2, as 1 is used by the main thread
            litebox: self.litebox,
            unix_addr_table: litebox::sync::RwLock::new(syscalls::unix::UnixAddrTable::new()),
            cross_process_signals: litebox::sync::Mutex::new(Vec::new()),
            pgrp_signal_subscriptions: litebox::sync::Mutex::new(BTreeMap::new()),
            process_thread_handles: litebox::sync::RwLock::new(alloc::collections::BTreeMap::new()),
            host_tty_foreground_pgrp: litebox::sync::Mutex::new(
                litebox::process::ProcessGroupId::from(init_process_id),
            ),
            host_tty_shadow_termios: litebox::sync::Mutex::new(None),
            local_control_plane_pump_active: core::sync::atomic::AtomicBool::new(false),
            transport_interrupt: alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false)),
            epoll_graph_lock: litebox::sync::Mutex::new(()),
            control_plane,
            fork_child_host_pids: litebox::sync::RwLock::new(alloc::collections::BTreeMap::new()),
            remote_signalfd_targets: litebox::sync::RwLock::new(alloc::collections::BTreeMap::new()),
            proc_cmdlines: litebox::sync::RwLock::new(alloc::collections::BTreeMap::new()),
            inotify_instances: litebox::sync::Mutex::new(Vec::new()),
        });
        LinuxShim {
            global,
            process_state,
        }
    }
}

pub struct LinuxShim<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
    /// Per-process state for the initial process.
    process_state: Arc<ProcessState>,
}
impl<FS: ShimFS> Clone for LinuxShim<FS> {
    fn clone(&self) -> Self {
        Self {
            global: self.global.clone(),
            process_state: self.process_state.clone(),
        }
    }
}

impl<FS: ShimFS> LinuxShim<FS> {
    /// Loads the program at `path` as the shim's initial task, returning the
    /// initial register state.
    pub fn load_program(
        &self,
        fs: alloc::sync::Arc<FS>,
        task: litebox_common_linux::TaskParams,
        path: &str,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
        initial_cwd: Option<alloc::string::String>,
    ) -> Result<LoadedProgram<FS>, loader::elf::ElfLoaderError> {
        self.load_program_with_exec_filename(fs, task, path, path, argv, envp, initial_cwd)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn load_program_with_exec_filename(
        &self,
        fs: alloc::sync::Arc<FS>,
        task: litebox_common_linux::TaskParams,
        path: &str,
        exec_filename: &str,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
        initial_cwd: Option<alloc::string::String>,
    ) -> Result<LoadedProgram<FS>, loader::elf::ElfLoaderError> {
        let litebox_common_linux::TaskParams {
            pid,
            ppid,
            uid,
            euid,
            gid,
            egid,
        } = task;

        // A newly loaded process may already have a caller-assigned PID/TID
        // (for example, when a child resumes in its own host process), so keep
        // future clone() allocations above that main thread ID.
        self.global.reserve_thread_id(pid);

        // The init task's `ProcessId` matches its externally-visible guest
        // pid by construction (the runner allocated init in the registry
        // using `ProcessId(pid as u32)`). Phase K Step 3 retired the
        // historical `pid_to_process_id` mapping; pid and ProcessId are
        // now identical everywhere.
        let process_id = litebox::process::ProcessId(
            u32::try_from(pid).expect("init task pid must be non-negative"),
        );

        let files = syscalls::file::FilesState::new(fs);
        files.set_max_fd(syscalls::process::RLIMIT_NOFILE_CUR - 1);
        let files = Arc::new(files);
        files.initialize_stdio_in_shared_descriptors_table(&self.global);

        let entrypoints = crate::LinuxShimEntrypoints {
            _not_send: core::marker::PhantomData,
            task: Task {
                global: self.global.clone(),
                process_state: self.process_state.clone().into(),
                thread: syscalls::process::ThreadState::new_process(pid),
                wait_state: wait::WaitState::new(self.global.platform),
                process_id,
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
                fs: Arc::new(match initial_cwd {
                    Some(cwd) => syscalls::file::FsState::with_cwd(cwd),
                    None => syscalls::file::FsState::new(),
                })
                .into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::new_process(),
                fork_context: RefCell::new(None),
                last_shell_write: RefCell::new(None),
                last_syscall: Cell::new(None),
                syscall_restartable: Cell::new(false),
                in_syscall: Cell::new(false),
                deferred_vfork_park: Cell::new(false),
                delayed_fork_pending: Cell::new(false),
                recent_delayed_fork_resume: Cell::new(false),
                migrated_to_remote: Cell::new(false),
                local_task_terminated: Cell::new(false),
                netlink_sockets: RefCell::new(alloc::collections::BTreeMap::new()),
                inet6_fds: RefCell::new(alloc::collections::BTreeSet::new()),
            },
        };
        let exec_filename = alloc::ffi::CString::new(exec_filename).ok();
        let (resolved_path, argv) = entrypoints
            .task
            .resolve_shebang_program(path, argv)
            .map_err(loader::elf::ElfLoaderError::OpenError)?;
        let resolved_exe_path = entrypoints.task.resolve_exe_path(resolved_path.as_str());
        let proc_cmdline = syscalls::file::proc_cmdline_from_argv(&argv, &resolved_exe_path);
        entrypoints.task.load_program(
            loader::elf::ElfLoader::new(&entrypoints.task, resolved_path.as_str())?,
            argv,
            envp,
            exec_filename.as_ref(),
        )?;
        *entrypoints.task.fs.borrow().exe_path.write() = resolved_exe_path;
        entrypoints.task.global.set_proc_cmdline(pid, proc_cmdline);
        let process = LinuxShimProcess(entrypoints.task.process().clone());
        Ok(LoadedProgram {
            entrypoints,
            process,
        })
    }

    /// Returns the page manager for the initial (PID 1) process.
    ///
    /// This is intended for use by runners during early boot (ELF loading,
    /// page-fault handling) before multi-process support is active. Child
    /// processes will have their own `PageManager` inside their
    /// `ProcessState`; callers should not use this accessor for them.
    pub fn page_manager(&self) -> &PageManager<Platform, PAGE_SIZE> {
        &self.process_state.pm
    }

    /// Perform queued network interactions with the outside world.
    ///
    /// This function should be invoked in a loop, based on the returned advice.
    /// When called from a guest thread (e.g. via `try_accept`), this also
    /// wakes the network worker so it can handle any follow-up transmissions
    /// (ACKs, retransmissions) without waiting for its poll timeout.
    #[cfg(feature = "worker_local_inet")]
    pub fn perform_network_interaction(
        &self,
    ) -> litebox::net::PlatformInteractionReinvocationAdvice {
        let mut net = self.global.net.lock();
        let result = net.perform_platform_interaction();
        if let Some((src_port, dst_port, summary)) = net.take_rst_diagnostic() {
            let listen_ports = &summary.listen_ports[..summary.listen_count as usize];
            let msg = alloc::format!(
                "SHIM RST: src={src_port} dst={dst_port} \
                 tcp_sockets={} listen_sockets={} listen_ports={listen_ports:?}\n",
                summary.tcp_count,
                summary.listen_count
            );
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        // Wake the network worker so it can handle follow-up work
        // (e.g. transmit packets queued by this interaction, process
        // ACKs, fire retransmission timers).
        if result.call_again_immediately() {
            litebox_platform_multiplex::platform().wake_network_worker();
        }
        result
    }

    #[cfg(not(feature = "worker_local_inet"))]
    pub fn perform_network_interaction(
        &self,
    ) -> litebox::net::PlatformInteractionReinvocationAdvice {
        let _ = self;
        litebox::net::PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction {
            timeout: None,
        }
    }

    /// Returns `true` if there are TCP sockets still closing in the
    /// background (data being flushed, FIN handshake in progress).
    #[cfg(feature = "worker_local_inet")]
    pub fn has_pending_network_closes(&self) -> bool {
        self.global.net.lock().has_pending_closes()
    }

    #[cfg(not(feature = "worker_local_inet"))]
    pub fn has_pending_network_closes(&self) -> bool {
        let _ = self;
        false
    }

    /// Re-send port-listen notifications for all active listen sockets.
    ///
    /// Must be called after fork-restore: the child worker inherits listen
    /// sockets from the parent's snapshot but the parent already registered
    /// them through ITS IPC. This re-registers through the child's IPC so
    /// the broker routes inbound connections to the correct worker.
    #[cfg(feature = "worker_local_inet")]
    pub fn reannounce_listen_ports(&self) {
        self.global.net.lock().reannounce_listen_ports();
    }

    #[cfg(not(feature = "worker_local_inet"))]
    pub fn reannounce_listen_ports(&self) {
        let _ = self;
    }

    /// Establish a TCP connection to the given address.
    ///
    /// Returns a [`transport::ShimTransport`] that can be used as a
    /// byte-stream transport (e.g., for a 9P filesystem client).
    #[cfg(feature = "worker_local_inet")]
    pub fn tcp_connection(
        &self,
        addr: core::net::SocketAddr,
    ) -> Result<transport::ShimTransport, Errno> {
        transport::ShimTransport::connect(
            self.global.clone(),
            addr,
            self.global.transport_interrupt.clone(),
            self.process_state.vfork_parking.clone(),
        )
    }

    #[cfg(not(feature = "worker_local_inet"))]
    pub fn tcp_connection(
        &self,
        addr: core::net::SocketAddr,
    ) -> Result<transport::ShimTransport, Errno> {
        let _ = (self, addr);
        Err(Errno::EOPNOTSUPP)
    }

    /// Create a direct message channel for 9P (bypasses smoltcp).
    ///
    /// The actual fd must already be set on the platform via
    /// [`set_raw_message_fd`].  This method only wires up the interrupt /
    /// vfork-parking handles.
    pub fn message_channel(&self) -> transport::ShimMessageChannel {
        transport::ShimMessageChannel::new(
            self.global.transport_interrupt.clone(),
            self.process_state.vfork_parking.clone(),
        )
    }

    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.global.litebox
    }

    /// Restore a child process from a fork snapshot.
    ///
    /// Instead of loading an ELF binary, this reconstructs the child process
    /// state from the serialized snapshot captured at the fork trap. The
    /// returned [`LoadedProgram`] can be passed to `run_thread()` just like
    /// a freshly loaded program.
    ///
    /// # Errors
    ///
    /// Returns an error if restore fails (e.g., the snapshot references
    /// unsupported state).
    #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
    pub fn restore_process(
        &self,
        snapshot: syscalls::fork_snapshot::ForkSnapshot,
        fs: alloc::sync::Arc<FS>,
    ) -> Result<LoadedProgram<FS>, Errno> {
        use litebox::mm::linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize, VmFlags};
        use litebox::platform::AddressSpaceProvider;
        use litebox::platform::RawMutex as _;

        let is_delayed_fork = snapshot.is_delayed_fork;
        let syscalls::fork_snapshot::ForkSnapshot {
            identity: id,
            process_wide: pw,
            thread: th,
            signal: sig,
            fs: fs_snap,
            fd_table,
            memory: mem,
            is_delayed_fork: _,
        } = snapshot;

        // Fork-restore runs before the restored task enters the syscall loop, so
        // no syscall-level caller_pid guard is active yet. Attribute broker refs
        // materialized from the snapshot to the restored child process.
        let _caller_pid_guard = litebox_common_linux::fd_token_client::set_caller_pid_scope(
            u32::try_from(id.pid).map_err(|_| Errno::EINVAL)?,
        );

        // Reserve the child's thread ID so future clone() calls don't collide.
        self.global.reserve_thread_id(id.pid);

        // --- 1. Allocate the same VA partition slot used by the parent. ------
        // The snapshot addresses are absolute within the parent's partition.
        // Rather than rebasing all addresses, we allocate the same slot in the
        // child worker so va_rebase == 0.
        //
        // The worker's init process occupies slot 0.  If the snapshot came from
        // a different slot (e.g. slot 1), we allocate slots sequentially until
        // we get the matching one, then free the extras and init's slot.
        let init_as_id = self.process_state.address_space_id;
        let snapshot_va_start = mem.metadata.va_range.start;

        // Determine which slot the snapshot was taken from by finding the slot
        // whose range contains the snapshot's VA start.
        // Destroy init's slot first so it's available for reuse.
        self.global
            .platform
            .destroy_address_space(init_as_id)
            .map_err(|_| Errno::ENOMEM)?;

        // Allocate slots until we get one whose range matches the snapshot.
        let mut temp_slots = alloc::vec::Vec::new();
        let child_as_id = loop {
            let id = self.global.platform.create_address_space().map_err(|_| {
                // Clean up any temp slots on failure.
                for &s in &temp_slots {
                    let _ = self.global.platform.destroy_address_space(s);
                }
                Errno::ENOMEM
            })?;
            let range = self.global.platform.address_space_range(id).map_err(|_| {
                // Clean up the just-created slot and all temp slots.
                let _ = self.global.platform.destroy_address_space(id);
                for &s in &temp_slots {
                    let _ = self.global.platform.destroy_address_space(s);
                }
                Errno::ENOMEM
            })?;
            if range.start <= snapshot_va_start && snapshot_va_start < range.end {
                break id;
            }
            temp_slots.push(id);
        };
        // Free the temporary slots we allocated to skip past.
        for s in temp_slots {
            let _ = self.global.platform.destroy_address_space(s);
        }

        let as_range = self
            .global
            .platform
            .address_space_range(child_as_id)
            .map_err(|_| Errno::ENOMEM)?;

        let child_pm: PageManager<Platform, { PAGE_SIZE }> =
            PageManager::new(&self.global.litebox, as_range.clone());

        // Compute VA rebase offset (should be 0 since we matched the slot).
        let snapshot_va_start = mem.metadata.va_range.start;
        let child_va_start = as_range.start;
        let va_rebase: isize = child_va_start as isize - snapshot_va_start as isize;
        debug_assert_eq!(
            va_rebase, 0,
            "non-zero va_rebase not fully supported: signal handlers would be stale"
        );

        // --- 2. Restore memory regions. ------------------------------------
        for region in &mem.regions {
            let vm_flags = VmFlags::from_bits_truncate(region.vm_flags);
            let has_read = vm_flags.contains(VmFlags::VM_READ);
            let has_write = vm_flags.contains(VmFlags::VM_WRITE);
            let has_exec = vm_flags.contains(VmFlags::VM_EXEC);

            let rebased_addr = (region.addr as isize + va_rebase) as usize;

            // Clip regions that extend past the partition ceiling (e.g. ld.so
            // mapped at the very top with last page spilling over).
            let region_end = rebased_addr.saturating_add(region.len);
            let clipped_len = if region_end > as_range.end {
                as_range.end.saturating_sub(rebased_addr)
            } else {
                region.len
            };
            if clipped_len == 0 {
                continue;
            }

            let addr = NonZeroAddress::<PAGE_SIZE>::new(rebased_addr).ok_or(Errno::EINVAL)?;
            let len = NonZeroPageSize::<PAGE_SIZE>::new(clipped_len).ok_or(Errno::EINVAL)?;

            let mut flags = CreatePagesFlags::FIXED_ADDR;
            if region.is_shared {
                flags |= CreatePagesFlags::SHARED;
            }

            let data = if region.data.len() > clipped_len {
                &region.data[..clipped_len]
            } else {
                &region.data
            };

            // Choose the create method that matches the final permissions.
            unsafe {
                match (has_read, has_write, has_exec) {
                    (true, true, true) => {
                        child_pm.create_rwx_pages(Some(addr), len, flags, |ptr| {
                            if !data.is_empty() {
                                ptr.write_slice_at_offset(0, data)
                                    .ok_or(litebox::mm::linux::MappingError::OutOfMemory)?;
                            }
                            Ok(data.len())
                        })
                    }
                    (true | false, false, true) => {
                        child_pm.create_executable_pages(Some(addr), len, flags, |ptr| {
                            if !data.is_empty() {
                                ptr.write_slice_at_offset(0, data)
                                    .ok_or(litebox::mm::linux::MappingError::OutOfMemory)?;
                            }
                            Ok(data.len())
                        })
                    }
                    (true | false, true, false) => {
                        child_pm.create_writable_pages(Some(addr), len, flags, |ptr| {
                            if !data.is_empty() {
                                ptr.write_slice_at_offset(0, data)
                                    .ok_or(litebox::mm::linux::MappingError::OutOfMemory)?;
                            }
                            Ok(data.len())
                        })
                    }
                    (true, false, false) => {
                        child_pm.create_readable_pages(Some(addr), len, flags, |ptr| {
                            if !data.is_empty() {
                                ptr.write_slice_at_offset(0, data)
                                    .ok_or(litebox::mm::linux::MappingError::OutOfMemory)?;
                            }
                            Ok(data.len())
                        })
                    }
                    // PROT_NONE or other combinations: create writable first
                    // to copy data, then downgrade to inaccessible.
                    _ => {
                        let ptr =
                            child_pm.create_writable_pages(Some(addr), len, flags, |ptr| {
                                if !data.is_empty() {
                                    ptr.write_slice_at_offset(0, data)
                                        .ok_or(litebox::mm::linux::MappingError::OutOfMemory)?;
                                }
                                Ok(data.len())
                            })?;
                        child_pm
                            .make_pages_inaccessible(ptr, len.as_usize())
                            .map_err(|_| litebox::mm::linux::MappingError::OutOfMemory)?;
                        Ok(ptr)
                    }
                }
                .map_err(|e| {
                    litebox::log_println!(
                        self.global.platform,
                        "[FORK-RESTORE-DIAG] region addr={:#x} len={:#x} rwx={}/{}/{} err={:?}",
                        rebased_addr,
                        region.len,
                        has_read,
                        has_write,
                        has_exec,
                        e
                    );
                    Errno::ENOMEM
                })?;
            }
        }

        // --- 3. Restore brk metadata (pages already mapped above). ----------
        let pm_meta = &mem.metadata;
        if pm_meta.brk_base != 0 {
            let rb = |addr: usize| (addr as isize + va_rebase) as usize;
            child_pm.restore_brk_metadata(
                rb(pm_meta.brk_base),
                rb(pm_meta.brk),
                rb(pm_meta.brk_frontier),
            );
        }

        // --- 4. Build the child ProcessState. -------------------------------
        let rb = |addr: usize| (addr as isize + va_rebase) as usize;
        let elf_patch_cache: alloc::collections::BTreeMap<i32, syscalls::mm::ElfPatchState> =
            pm_meta
                .elf_patch_entries
                .iter()
                .map(|e| {
                    (
                        e.fd,
                        syscalls::mm::ElfPatchState {
                            _base_addr: rb(e.base_addr),
                            pre_patched: e.pre_patched,
                            trampoline_file_offset: e.trampoline_file_offset,
                            trampoline_file_size: e.trampoline_file_size,
                            _trampoline_vaddr: e.trampoline_vaddr,
                            trampoline_addr: rb(e.trampoline_addr),
                            trampoline_cursor: rb(e.trampoline_cursor),
                            trampoline_mapped: e.trampoline_mapped,
                            trampoline_mapped_len: e.trampoline_mapped_len,
                            runtime_patches_committed: e.runtime_patches_committed,
                            file_path: e.file_path.clone(),
                        },
                    )
                })
                .collect();

        let proc_map_paths: Vec<(core::ops::Range<usize>, alloc::string::String)> = pm_meta
            .proc_map_paths
            .iter()
            .map(|(range, path)| (rb(range.start)..rb(range.end), path.clone()))
            .collect();

        // --- 5. Re-patch trampoline entry points. ---------------------------
        // Each rewriter trampoline region starts with an 8-byte pointer to the
        // host's syscall_callback. The snapshot captured the parent host's
        // address; update it to the child host's address.
        let new_syscall_entry = {
            use litebox::platform::SystemInfoProvider as _;
            self.global.platform.get_syscall_entry_point()
        };
        let old_syscall_entry = pm_meta.old_syscall_entry_point;
        if new_syscall_entry != 0
            && old_syscall_entry != 0
            && new_syscall_entry != old_syscall_entry
        {
            use litebox::platform::RawMutPointer as _;

            // First patch any entries tracked in the elf_patch_cache (runtime-
            // patched libraries).
            for state in elf_patch_cache.values() {
                if !state.trampoline_mapped {
                    continue;
                }
                let tramp_addr = state.trampoline_addr;
                let tramp_page_len = state.trampoline_mapped_len;
                let tramp_ptr = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<
                    u8,
                >::from_usize(tramp_addr);
                // SAFETY: no concurrent access — child hasn't started yet.
                unsafe {
                    let _ = child_pm.make_pages_writable(tramp_ptr, tramp_page_len);
                }
                let _ = tramp_ptr.copy_from_slice(0, &new_syscall_entry.to_le_bytes());
                unsafe {
                    let _ = child_pm.make_pages_executable(tramp_ptr, tramp_page_len);
                }
            }

            // Also scan all restored RX memory regions for trampolines that
            // were created by the ELF loader (not in elf_patch_cache).
            // A trampoline region's first 8 bytes contain the host's syscall
            // entry point address.
            let old_bytes = old_syscall_entry.to_le_bytes();
            for region in &mem.regions {
                let vm_flags = VmFlags::from_bits_truncate(region.vm_flags);
                if !vm_flags.contains(VmFlags::VM_EXEC) {
                    continue;
                }
                // Check if the first 8 bytes of the region data match the old entry.
                if region.data.len() >= 8 && region.data[..8] == old_bytes {
                    let rebased_addr = (region.addr as isize + va_rebase) as usize;
                    let page_len = (region.len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                    let tramp_ptr =
                        <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>
                            ::from_usize(rebased_addr);
                    // SAFETY: no concurrent access — child hasn't started yet.
                    unsafe {
                        let _ = child_pm.make_pages_writable(tramp_ptr, page_len);
                    }
                    let _ = tramp_ptr.copy_from_slice(0, &new_syscall_entry.to_le_bytes());
                    unsafe {
                        let _ = child_pm.make_pages_executable(tramp_ptr, page_len);
                    }
                }
            }
        }

        let child_process_state = Arc::new(ProcessState {
            pm: child_pm,
            address_space_id: child_as_id,
            thread_count: core::sync::atomic::AtomicI32::new(1),
            controlling_pty: litebox::sync::Mutex::new(None),
            active_vfork_layers: litebox::sync::Mutex::new(Vec::new()),
            elf_patch_cache: litebox::sync::Mutex::new(elf_patch_cache),
            shared_file_mappings: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
            main_bss_start: core::sync::atomic::AtomicUsize::new(rb(pm_meta.main_bss_start)),
            main_bss_end: core::sync::atomic::AtomicUsize::new(rb(pm_meta.main_bss_end)),
            proc_map_paths: litebox::sync::Mutex::new(proc_map_paths),
            vfork_parking: Arc::new(VforkParking {
                park: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
                parked_count: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
                deferred_lie_count: core::sync::atomic::AtomicU32::new(0),
            }),
        });

        // --- 6. Build Process with restored rlimits. ------------------------
        let child_thread_remote = Arc::new(syscalls::process::ThreadRemote::new());
        let child_process = Arc::new(syscalls::process::Process::new_with_rlimits(
            id.pid,
            child_thread_remote.clone(),
            &pw.rlimits,
            pw.thp_disabled,
        ));

        // --- 7. Build ThreadState. ------------------------------------------
        let child_thread = syscalls::process::ThreadState::new_from_restore(
            id.pid,
            child_process.clone(),
            child_thread_remote,
            th.clear_child_tid.map(rb),
            th.robust_list.map(rb),
        );

        // --- 8. Restore signal state. ---------------------------------------
        let rebased_altstack = litebox_common_linux::signal::SigAltStack {
            sp: if sig.altstack.sp != 0 {
                rb(sig.altstack.sp)
            } else {
                0
            },
            flags: sig.altstack.flags,
            #[cfg(target_pointer_width = "64")]
            __pad: sig.altstack.__pad,
            size: sig.altstack.size,
        };
        let child_signals = syscalls::signal::SignalState::new_from_restore(
            sig.blocked,
            &sig.handlers,
            rebased_altstack,
        );

        // --- 9. Restore filesystem state. -----------------------------------
        let child_fs = {
            let mut cwd = fs_snap.cwd.clone();
            if !cwd.ends_with('/') {
                cwd.push('/');
            }
            Arc::new(syscalls::file::FsState::from_restore(
                cwd,
                fs_snap.exe_path.clone(),
                fs_snap.umask,
            ))
        };

        // --- 10. Restore FD table. -------------------------------------------
        let child_files = Arc::new(syscalls::file::FilesState::new(fs.clone()));
        child_files.set_max_fd(
            child_process
                .limits
                .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE)
                .saturating_sub(1),
        );
        child_files.initialize_stdio_in_shared_descriptors_table(&self.global);

        // Restore terminal fds beyond stdio.  Fds 0/1/2 are already
        // populated by initialize_stdio; skip them to avoid slot collisions.
        // Terminal filesystem fds (tty/pty metadata) are reconnected via
        // /dev/tty; tty-backed stdio aliases use their original /dev/std* path.
        {
            use litebox::fs::{Mode, OFlags};
            use syscalls::fork_snapshot::{BrokerHandleSnapshot, FdClass};

            for entry in &fd_table.entries {
                // Skip stdio slots (already initialized above) and non-FS fds.
                if entry.fd <= 2 || entry.class != FdClass::FilesystemFd {
                    continue;
                }
                let meta = &entry.metadata;
                if !meta.is_host_tty_alias
                    && !meta.is_host_pty_device
                    && meta.host_stdio_source_fd.is_none()
                {
                    continue;
                }

                // Choose the right device path based on the fd's origin.
                let (path, flags) = if meta.is_host_tty_alias || meta.is_host_pty_device {
                    ("/dev/tty", OFlags::RDWR)
                } else if let Some(source_fd) = meta.host_stdio_source_fd {
                    match source_fd {
                        0 => ("/dev/stdin", OFlags::RDONLY),
                        1 => ("/dev/stdout", OFlags::WRONLY),
                        _ => ("/dev/stderr", OFlags::WRONLY),
                    }
                } else {
                    continue;
                };

                let Ok(fd_handle) = child_files.fs.open(path, flags, Mode::empty()) else {
                    continue;
                };

                // Attach metadata markers matching the snapshot.
                let mut dt = self.global.litebox.descriptor_table_mut();
                let mut rds = child_files.raw_descriptor_store.write();
                let status_flags = OFlags::APPEND | flags;
                dt.set_entry_metadata(&fd_handle, StdioStatusFlags(status_flags));
                if meta.is_host_tty_alias {
                    dt.set_entry_metadata(&fd_handle, HostTtyAlias);
                }
                if meta.is_host_pty_device {
                    dt.set_entry_metadata(&fd_handle, syscalls::file::HostPtyDeviceFd);
                }
                if let Some(source_fd) = meta.host_stdio_source_fd {
                    dt.set_entry_metadata(&fd_handle, HostStdioSourceFd(source_fd));
                }
                let success = rds.fd_into_specific_raw_integer(fd_handle, entry.fd);
                debug_assert!(success, "fd slot {} already occupied", entry.fd);
                drop(rds);
                drop(dt);
            }

            // Restore broker-backed PTY fds by re-attaching to the broker handle.
            for entry in &fd_table.entries {
                if entry.class != FdClass::FilesystemFd {
                    continue;
                }
                let Some(broker_handle) = entry.metadata.broker_handle else {
                    continue;
                };
                let BrokerHandleSnapshot::Pty {
                    handle_id,
                    role,
                    pty_id,
                } = broker_handle
                else {
                    // Non-Pty broker_handle on a FilesystemFd entry:
                    // handled by other restore branches (or not
                    // installed if no provider). FdClass::FilesystemFd
                    // is the only `FdClass` arm that accepts
                    // `BrokerHandleSnapshot::Pty` per snapshot_fd_table.
                    continue;
                };
                let Some(provider) = syscalls::broker_pty::broker_pty_provider() else {
                    continue;
                };
                let Ok(pty_fd) = syscalls::broker_pty::BrokerPtyProviderReacquireExt::reacquire(
                    &provider, handle_id, role, pty_id,
                ) else {
                    continue;
                };
                let typed: litebox::fd::TypedFd<syscalls::broker_pty::BrokerPtySubsystem> =
                    self.global.litebox.descriptor_table_mut().insert(pty_fd);
                let mut rds = child_files.raw_descriptor_store.write();
                if entry.fd <= 2 {
                    let _ = rds.fd_consume_raw_integer::<FS>(entry.fd);
                }
                let success = rds.fd_into_specific_raw_integer(typed, entry.fd);
                debug_assert!(
                    success,
                    "broker pty fd slot {} occupied during restore",
                    entry.fd
                );
            }

            // Restore non-terminal FilesystemFd entries.  Reopen by path
            // if available, fall back to /dev/null.  For stdio slots (0-2),
            // consume the pre-populated entry first.
            for entry in &fd_table.entries {
                if entry.class != FdClass::FilesystemFd {
                    continue;
                }
                let meta = &entry.metadata;
                // Skip terminal fds, host stdio, and broker-backed PTYs (already handled above).
                if meta.is_host_tty_alias
                    || meta.is_host_pty_device
                    || meta.host_stdio_source_fd.is_some()
                    || matches!(meta.broker_handle, Some(BrokerHandleSnapshot::Pty { .. }))
                {
                    continue;
                }

                let path = fd_table
                    .open_file_descriptions
                    .iter()
                    .find(|ofd| ofd.object_id == entry.object_id)
                    .and_then(|ofd| ofd.reopen_path.as_deref())
                    .unwrap_or("/dev/null");
                // Use captured access mode, falling back to RDONLY.
                let access_bits = entry.status_flags & 0x3; // O_ACCMODE
                let flags = match access_bits {
                    1 => OFlags::WRONLY,
                    2 => OFlags::RDWR,
                    _ => OFlags::RDONLY,
                };
                let Ok(fd_handle) = child_files
                    .fs
                    .open(path, flags, Mode::empty())
                    .or_else(|_| {
                        // Try RDONLY if the original mode failed.
                        child_files.fs.open(path, OFlags::RDONLY, Mode::empty())
                    })
                    .or_else(|_| {
                        child_files
                            .fs
                            .open("/dev/null", OFlags::RDWR, Mode::empty())
                    })
                else {
                    continue;
                };

                // For stdio slots, consume the pre-populated entry.
                // For higher fds, the slot is empty.
                let mut rds = child_files.raw_descriptor_store.write();
                if entry.fd <= 2 {
                    let _ = rds.fd_consume_raw_integer::<FS>(entry.fd);
                }
                let success = rds.fd_into_specific_raw_integer(fd_handle, entry.fd);
                debug_assert!(success, "fd slot {} occupied during restore", entry.fd);
                drop(rds);
            }
        }

        // Recreate unconnected Unix sockets. Connected/socketpair descriptors
        // are also seeded here so any bridge fd installation below has an fd
        // table entry to replace with the cross-process host passthrough fd.
        {
            use litebox_common_linux::{SockFlags, SockType};
            use syscalls::fork_snapshot::{BrokerHandleSnapshot, FdClass};

            for entry in &fd_table.entries {
                if entry.class != FdClass::UnixSocket {
                    continue;
                }

                // Phase F: if the snapshot carries a broker UnixSocket
                // handle for this slot, install a BrokerSocketPairFd. Bump
                // the handle on this connection so its on_close release is
                // tracked locally; the parent's transit ref is drained later.
                if let Some(broker_handle) = entry.metadata.broker_handle {
                    // Exhaustive match (no wildcards: see AGENTS.md "Match
                    // exhaustiveness, no catch-alls, loud failure for logic
                    // errors"). Adding a new `BrokerHandleSnapshot` variant
                    // fails to compile here, forcing an explicit
                    // accept/reject decision for the UnixSocket restore path.
                    match broker_handle {
                        BrokerHandleSnapshot::UnixSocket {
                            handle_id,
                            endpoint,
                        } => {
                            let Some(provider) =
                                syscalls::broker_socketpair::broker_socketpair_provider()
                            else {
                                continue;
                            };
                            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                            let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                                alloc::sync::Arc::clone(&provider) as _;
                            let _ = releaser.dup_handle(handle_id);
                            let sp_fd =
                                syscalls::broker_socketpair::BrokerSocketPairFd::<Platform>::new(
                                    provider,
                                    handle_id,
                                    endpoint,
                                    litebox::fs::OFlags::empty(),
                                );
                            let typed = self
                                .global
                                .litebox
                                .descriptor_table_mut()
                                .insert::<syscalls::broker_socketpair::BrokerSocketPairSubsystem>(
                                sp_fd,
                            );
                            let mut rds = child_files.raw_descriptor_store.write();
                            if entry.fd <= 2 {
                                let _ = rds.fd_consume_raw_integer::<FS>(entry.fd);
                            }
                            let success = rds.fd_into_specific_raw_integer(typed, entry.fd);
                            debug_assert!(
                                success,
                                "broker_socketpair fd slot {} occupied during restore",
                                entry.fd
                            );
                            continue;
                        }
                        BrokerHandleSnapshot::TcpConn { handle_id } => {
                            let Some(provider) =
                                syscalls::broker_tcp_conn::broker_tcp_conn_provider()
                            else {
                                continue;
                            };
                            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                            let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                                alloc::sync::Arc::clone(&provider) as _;
                            let _ = releaser.dup_handle(handle_id);
                            let tcp_fd =
                                syscalls::broker_tcp_conn::BrokerTcpConnFd::<Platform>::new(
                                    provider,
                                    handle_id,
                                    litebox::fs::OFlags::from_bits_retain(entry.status_flags),
                                );
                            let typed = self
                                .global
                                .litebox
                                .descriptor_table_mut()
                                .insert::<syscalls::broker_tcp_conn::BrokerTcpConnSubsystem>(
                                tcp_fd,
                            );
                            let mut rds = child_files.raw_descriptor_store.write();
                            if entry.fd <= 2 {
                                let _ = rds.fd_consume_raw_integer::<FS>(entry.fd);
                            }
                            let success = rds.fd_into_specific_raw_integer(typed, entry.fd);
                            debug_assert!(
                                success,
                                "broker_tcp_conn fd slot {} occupied during restore",
                                entry.fd
                            );
                            continue;
                        }
                        // AF_UNIX SOCK_DGRAM: re-attach by broker handle.
                        // Without this arm a fork restore silently fell
                        // through to creating a fresh disconnected local
                        // stream socket, making any queued datagram
                        // unreachable from the child. The UDS_DGRAM gap
                        // was silent (no test exercised SOCK_DGRAM
                        // peer-read-after-fork until this fix).
                        BrokerHandleSnapshot::SocketDgram { handle_id } => {
                            let Some(provider) =
                                syscalls::broker_socket_dgram::broker_socket_dgram_provider()
                            else {
                                continue;
                            };
                            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                            let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                                alloc::sync::Arc::clone(&provider) as _;
                            let _ = releaser.dup_handle(handle_id);
                            let dgram_fd = syscalls::broker_socket_dgram::BrokerSocketDgramFd::<
                                Platform,
                            >::new(
                                provider,
                                handle_id,
                                litebox::fs::OFlags::from_bits_retain(entry.status_flags),
                            );
                            let typed = self
                                .global
                                .litebox
                                .descriptor_table_mut()
                                .insert::<syscalls::broker_socket_dgram::BrokerSocketDgramSubsystem>(
                                    dgram_fd,
                                );
                            let mut rds = child_files.raw_descriptor_store.write();
                            if entry.fd <= 2 {
                                let _ = rds.fd_consume_raw_integer::<FS>(entry.fd);
                            }
                            let success = rds.fd_into_specific_raw_integer(typed, entry.fd);
                            debug_assert!(
                                success,
                                "broker_socket_dgram fd slot {} occupied during restore",
                                entry.fd
                            );
                            continue;
                        }
                        // AF_UNIX SOCK_SEQPACKET: re-attach by broker
                        // handle. Without this arm `UDS_SEQPACKET.
                        // fork_restore_inherit` failed because the child
                        // got a fresh disconnected stream socket instead
                        // of a re-attached SEQPACKET endpoint.
                        BrokerHandleSnapshot::SocketSeqPacket { handle_id } => {
                            let Some(provider) =
                                syscalls::broker_socket_seqpacket::broker_socket_seqpacket_provider(
                                )
                            else {
                                continue;
                            };
                            use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                            let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                                alloc::sync::Arc::clone(&provider) as _;
                            let _ = releaser.dup_handle(handle_id);
                            let seq_fd = syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketFd::<
                                Platform,
                            >::new(
                                provider,
                                handle_id,
                                litebox::fs::OFlags::from_bits_retain(entry.status_flags),
                            );
                            let typed = self
                                .global
                                .litebox
                                .descriptor_table_mut()
                                .insert::<syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem>(
                                    seq_fd,
                                );
                            let mut rds = child_files.raw_descriptor_store.write();
                            if entry.fd <= 2 {
                                let _ = rds.fd_consume_raw_integer::<FS>(entry.fd);
                            }
                            let success = rds.fd_into_specific_raw_integer(typed, entry.fd);
                            debug_assert!(
                                success,
                                "broker_socket_seqpacket fd slot {} occupied during restore",
                                entry.fd
                            );
                            continue;
                        }
                        // Variants that cannot legitimately appear under
                        // `FdClass::UnixSocket` per the snapshot wire
                        // format invariant (snapshot_fd_table classifies
                        // these into other FdClass values). Panic loudly
                        // per AGENTS.md "loud failure for logic errors".
                        BrokerHandleSnapshot::Eventfd { .. }
                        | BrokerHandleSnapshot::Pidfd { .. }
                        | BrokerHandleSnapshot::Signalfd { .. }
                        | BrokerHandleSnapshot::Pty { .. }
                        | BrokerHandleSnapshot::Pipe { .. }
                        | BrokerHandleSnapshot::InetListener { .. }
                        | BrokerHandleSnapshot::InetDgram { .. } => unreachable!(
                            "{broker_handle:?} cannot appear in a FdClass::UnixSocket entry",
                        ),
                    }
                }

                // Non-broker-backed UnixSocket entry: fall through to a
                // fresh local stream socket. This is the legitimate
                // restore for entries with `metadata.broker_handle.is_none()`
                // (unconnected sockets recorded in the snapshot).
                if let Some(socket) =
                    syscalls::unix::UnixSocket::<FS>::new(SockType::Stream, SockFlags::empty())
                {
                    let file = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .insert::<syscalls::unix::UnixSocketSubsystem<FS>>(socket);
                    let mut rds = child_files.raw_descriptor_store.write();
                    if entry.fd <= 2 {
                        let _ = rds.fd_consume_raw_integer::<FS>(entry.fd);
                    }
                    let success = rds.fd_into_specific_raw_integer(file, entry.fd);
                    debug_assert!(success, "unix fd slot {} occupied during restore", entry.fd);
                }
            }
        }

        // Restore broker-backed inet listener fds by re-attaching to the broker handle.
        {
            use syscalls::fork_snapshot::{BrokerHandleSnapshot, FdClass};
            for entry in &fd_table.entries {
                if entry.class != FdClass::InetListener {
                    continue;
                }
                let Some(broker_handle) = entry.metadata.broker_handle else {
                    continue;
                };
                let BrokerHandleSnapshot::InetListener { handle_id } = broker_handle else {
                    continue;
                };
                let Some(provider) =
                    syscalls::broker_inet_listener::broker_inet_listener_provider()
                else {
                    continue;
                };
                use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                    alloc::sync::Arc::clone(&provider) as _;
                let _ = releaser.dup_handle(handle_id);
                let listener =
                    syscalls::broker_inet_listener::BrokerInetListenerFd::<Platform>::new(
                        provider,
                        handle_id,
                        0,
                        litebox::fs::OFlags::from_bits_retain(entry.status_flags),
                    );
                let typed = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .insert::<syscalls::broker_inet_listener::BrokerInetListenerSubsystem>(
                    listener,
                );
                let mut rds = child_files.raw_descriptor_store.write();
                if entry.fd <= 2 {
                    let _ = rds.fd_consume_raw_integer::<FS>(entry.fd);
                }
                let success = rds.fd_into_specific_raw_integer(typed, entry.fd);
                debug_assert!(
                    success,
                    "broker inet listener fd slot {} occupied during restore",
                    entry.fd
                );
            }
        }

        // Phase 2.F.3: Recreate EventFd entries that carry a broker_handle
        // reference. Re-attach to the same broker handle via the local
        // provider's `dup_handle` semantics — the parent already dup'd
        // the handle at snapshot capture, so adopting the existing ref
        // requires no additional refcount changes.
        //
        // Entries without `broker_handle` (e.g. Eventfd with no provider
        // available at snapshot time, or Timerfd) fall through to a
        // fresh local fd at the next branch.
        {
            use syscalls::fork_snapshot::{BrokerHandleSnapshot, FdClass};
            for entry in &fd_table.entries {
                if entry.class != FdClass::EventFd {
                    continue;
                }
                let Some(broker_handle) = entry.metadata.broker_handle else {
                    continue;
                };
                let event_file: Option<syscalls::eventfd::EventFile<Platform>> =
                    match broker_handle {
                        BrokerHandleSnapshot::Eventfd { handle_id } => {
                            syscalls::eventfd::broker_eventfd_provider().map(|provider| {
                                syscalls::eventfd::EventFile::new_broker_backed(
                                    provider,
                                    handle_id,
                                    litebox_common_linux::EfdFlags::empty(),
                                )
                            })
                        }
                        BrokerHandleSnapshot::Pidfd { handle_id } => {
                            u32::try_from(handle_id).ok().and_then(|pid| {
                                let target_pid = litebox::process::ProcessId(pid);
                                syscalls::guest_pid::try_subscribe_broker_process_exit(target_pid)
                                    .map(|subscription| {
                                        syscalls::eventfd::EventFile::new_broker_process_pidfd(
                                            target_pid,
                                            subscription,
                                            false,
                                            None,
                                        )
                                    })
                            })
                        }
                        // `Pipe` is handled by the FdClass::Pipe restore branch
                        // below (C.5l). It's intentionally NOT an EventFile.
                        BrokerHandleSnapshot::Pipe { .. } => None,
                        // Phase F: `UnixSocket` is handled by the
                        // FdClass::UnixSocket restore branch above.
                        BrokerHandleSnapshot::UnixSocket { .. } => None,
                        BrokerHandleSnapshot::TcpConn { .. } => None,
                        BrokerHandleSnapshot::InetListener { .. } => None,
                        BrokerHandleSnapshot::InetDgram { .. } => None,
                        BrokerHandleSnapshot::SocketDgram { .. } => None,
                        BrokerHandleSnapshot::SocketSeqPacket { .. } => None,
                        // `Signalfd` is restored by its dedicated FdClass branch below.
                        BrokerHandleSnapshot::Signalfd { handle_id } => todo!(
                            "fork-snapshot restore for BrokerHandleSnapshot::Signalfd \
                             not implemented yet (handle_id={handle_id})"
                        ),
                        // PTYs are restored by the broker-backed PTY FilesystemFd branch above.
                        BrokerHandleSnapshot::Pty { .. } => None,
                    };
                let Some(event_file) = event_file else {
                    continue;
                };
                let file = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .insert::<syscalls::eventfd::EventfdSubsystem>(event_file);
                let mut rds = child_files.raw_descriptor_store.write();
                if entry.fd <= 2 {
                    let _ = rds.fd_consume_raw_integer::<FS>(entry.fd);
                }
                let success = rds.fd_into_specific_raw_integer(file, entry.fd);
                debug_assert!(
                    success,
                    "eventfd fd slot {} occupied during restore",
                    entry.fd
                );
            }
        }

        // Restore host-fd tokens for HostPassthroughFdEntry entries.
        // INVARIANT: the aliased resource is a raw host fd that was already
        // registered with the fd-token broker during snapshot, not a broker-held
        // descriptor with durable per-fd state. The token is the explicit
        // cross-binary-type fork handoff; without it, HostPassthroughFd entries
        // must be treated as non-migratable across another worker hop.
        {
            use syscalls::fork_snapshot::FdClass;
            for entry in &fd_table.entries {
                if entry.class != FdClass::Pipe {
                    continue;
                }
                let Some(token) = entry.metadata.broker_fd_token else {
                    continue;
                };
                let Some(direction) = token.host_passthrough_fd_direction else {
                    continue;
                };
                let Some(client) = litebox_common_linux::fd_token_client::global_client() else {
                    continue;
                };
                let Ok(raw_fd) = client.materialize_raw_fd(token.token_id) else {
                    let _ = client.release(token.token_id);
                    continue;
                };
                let _ = client.release(token.token_id);
                let host_entry =
                    syscalls::host_passthrough_fd::HostPassthroughFdEntry::new(raw_fd, direction);
                let typed = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .insert::<syscalls::host_passthrough_fd::HostPassthroughFd>(host_entry);
                let mut rds = child_files.raw_descriptor_store.write();
                if entry.fd <= 2 {
                    let _ = rds.fd_consume_raw_integer::<FS>(entry.fd);
                }
                let success = rds.fd_into_specific_raw_integer(typed, entry.fd);
                debug_assert!(
                    success,
                    "host-token fd slot {} occupied during restore",
                    entry.fd
                );
            }
        }

        // Recreate broker-backed signalfd entries inherited across fork/exec.
        {
            use syscalls::fork_snapshot::{BrokerHandleSnapshot, FdClass};
            for entry in &fd_table.entries {
                if entry.class != FdClass::Signalfd {
                    continue;
                }
                let Some(broker_handle) = entry.metadata.broker_handle else {
                    continue;
                };
                let BrokerHandleSnapshot::Signalfd { handle_id } = broker_handle else {
                    continue;
                };
                let Some(provider) = syscalls::signalfd::broker_signalfd_provider() else {
                    continue;
                };
                let nonblock = litebox::fs::OFlags::from_bits_retain(entry.status_flags)
                    .contains(litebox::fs::OFlags::NONBLOCK);
                let file = syscalls::signalfd::SignalfdFile::new_broker_backed(
                    provider,
                    handle_id,
                    nonblock,
                    litebox_common_linux::signal::SigSet::from_u64(u64::MAX),
                );
                let file = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .insert::<syscalls::signalfd::SignalfdSubsystem>(file);
                let mut rds = child_files.raw_descriptor_store.write();
                if entry.fd <= 2 {
                    let _ = rds.fd_consume_raw_integer::<FS>(entry.fd);
                }
                let success = rds.fd_into_specific_raw_integer(file, entry.fd);
                debug_assert!(
                    success,
                    "signalfd fd slot {} occupied during restore",
                    entry.fd
                );
            }
        }

        // C.5l: Phase C.3 follow-up — restore BrokerPipeFd entries for
        // FdClass::Pipe slots whose snapshot carries a broker_handle.
        // Previously these fell through to the local-pipe restore branch
        // (line 1414 mapped `BrokerHandleKind::Pipe => None`), which
        // meant fork-restore created no BrokerPipeFd in the child
        // worker. The emit-side `dup_handle` in
        // `syscalls/process.rs:7283` then leaked the broker refcount,
        // and the writer-side pipe's `PipeWriteEnd::Drop` never fired
        // when the original writer process exited — readers in other
        // workers stalled forever waiting for EOF.
        //
        // Now: per FdClass::Pipe entry with broker_handle, create a
        // fresh BrokerPipeFd that adopts the parent's emit-side
        // `dup_handle` ref (no additional bump on this side).
        // BrokerPipeFd's on_close in the child worker will release on
        // drop; the broker per-connection cleanup handles SIGKILL'd
        // workers.
        {
            use syscalls::fork_snapshot::{BrokerHandleSnapshot, FdClass};
            for entry in &fd_table.entries {
                if entry.class != FdClass::Pipe {
                    continue;
                }
                let Some(broker_handle) = entry.metadata.broker_handle else {
                    continue;
                };
                let BrokerHandleSnapshot::Pipe {
                    handle_id,
                    direction,
                } = broker_handle
                else {
                    continue;
                };
                let Some(provider) = syscalls::broker_pipe::broker_pipe_provider() else {
                    continue;
                };
                // PE.13 fix (2026-05-18): bump broker rc and record
                // on this conn's tracker so the BrokerPipeFd's on_close
                // release later finds a matching tracker entry. Without
                // this, PE.9's strict ownership check fires a PROTOCOL
                // VIOLATION on the implicit release at close-time
                // (the original "adopts the parent's emit-side dup_handle
                // ref" design predated PE.9's per-conn tracking).
                //
                // The corresponding release of the parent's emit-side
                // dup happens in process.rs's commit_delayed_fork
                // success path via `fork_snapshot_broker_transit`
                // drain — see process.rs:4519. Net broker rc change
                // across the fork: +1 (our dup) -1 (parent's transit
                // release) = 0. Matches the pre-PE.9 design intent
                // while satisfying strict ownership checking.
                use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
                let releaser: alloc::sync::Arc<dyn BrokerSubscribable> =
                    alloc::sync::Arc::clone(&provider) as _;
                let _ = releaser.dup_handle(handle_id);
                let bp_fd = syscalls::broker_pipe::BrokerPipeFd::<Platform>::new(
                    provider,
                    handle_id,
                    direction,
                    litebox::fs::OFlags::empty(),
                    2, // creation_site: fork_snapshot_restore
                );
                let typed = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .insert::<syscalls::broker_pipe::BrokerPipeSubsystem>(bp_fd);
                let mut rds = child_files.raw_descriptor_store.write();
                if entry.fd <= 2 {
                    let _ = rds.fd_consume_raw_integer::<FS>(entry.fd);
                }
                let success = rds.fd_into_specific_raw_integer(typed, entry.fd);
                debug_assert!(
                    success,
                    "broker-pipe fd slot {} occupied during restore",
                    entry.fd
                );
            }
        }

        // --- 11. Build credentials. -----------------------------------------
        let child_credentials = Arc::new(syscalls::process::Credentials {
            uid: id.credentials.uid,
            euid: id.credentials.euid,
            gid: id.credentials.gid,
            egid: id.credentials.egid,
        });

        // --- 11. Build Task with execution context. ---------------------------
        let mut exec_ctx = th.execution_context;

        // Rebase all address-valued registers from the snapshot's VA partition
        // to the child's VA partition.
        if va_rebase != 0 {
            #[cfg(target_arch = "x86_64")]
            {
                let rb_reg = |v: usize| (v as isize + va_rebase) as usize;
                exec_ctx.regs.rip = rb_reg(exec_ctx.regs.rip);
                exec_ctx.regs.rsp = rb_reg(exec_ctx.regs.rsp);
                exec_ctx.regs.rbp = rb_reg(exec_ctx.regs.rbp);
                exec_ctx.regs.rcx = rb_reg(exec_ctx.regs.rcx);
                exec_ctx.regs.r11 = rb_reg(exec_ctx.regs.r11);
            }
        }

        if !is_delayed_fork {
            // True fork: fork() returns 0 in the child.
            #[cfg(target_arch = "x86_64")]
            {
                exec_ctx.rax = 0;
            }
            #[cfg(target_arch = "x86")]
            {
                exec_ctx.eax = 0;
            }
        }
        // For delayed fork the context already has rax = syscall number and
        // rip backed up to the syscall instruction, so the guest replays the
        // triggering syscall after restore.

        let mut comm = [0u8; litebox_common_linux::TASK_COMM_LEN];
        comm.copy_from_slice(&id.comm);

        let entrypoints = LinuxShimEntrypoints {
            _not_send: core::marker::PhantomData,
            task: Task {
                global: self.global.clone(),
                process_state: child_process_state.into(),
                thread: child_thread,
                wait_state: wait::WaitState::new(self.global.platform),
                process_id: litebox::process::ProcessId(
                    u32::try_from(id.pid).expect("fork-restore child pid must be non-negative"),
                ),
                pid: id.pid,
                ppid: id.ppid,
                tid: id.tid,
                credentials: child_credentials,
                comm: Cell::new(comm),
                fs: child_fs.into(),
                files: child_files.into(),
                signals: child_signals,
                fork_context: RefCell::new(None),
                last_shell_write: RefCell::new(None),
                last_syscall: Cell::new(None),
                syscall_restartable: Cell::new(false),
                in_syscall: Cell::new(false),
                deferred_vfork_park: Cell::new(false),
                delayed_fork_pending: Cell::new(false),
                recent_delayed_fork_resume: Cell::new(false),
                migrated_to_remote: Cell::new(false),
                local_task_terminated: Cell::new(false),
                netlink_sockets: RefCell::new(alloc::collections::BTreeMap::new()),
                inet6_fds: RefCell::new(alloc::collections::BTreeSet::new()),
            },
        };

        // Set the init state so the first handle_init_request restores the
        // full execution context (registers + TLS) from the snapshot.
        entrypoints
            .task
            .thread
            .init_state
            .set(syscalls::process::ThreadInitState::ForkRestore {
                exec_ctx: alloc::boxed::Box::new(exec_ctx),
                tls_base: th.tls_base.map(rb),
                set_child_tid: th.set_child_tid.map(rb),
            });

        let process = LinuxShimProcess(child_process);
        Ok(LoadedProgram {
            entrypoints,
            process,
        })
    }
}

pub struct LoadedProgram<FS: ShimFS> {
    pub entrypoints: LinuxShimEntrypoints<FS>,
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

    /// Returns whether all threads in this process have exited.
    pub fn has_exited(&self) -> bool {
        self.0.nr_threads() == 0
    }

    /// Returns the initial guest pid assigned to this process at load
    /// time. Stable for the lifetime of the process and recoverable
    /// post-exit (when the thread map is drained) — used by the
    /// runner's exit path to stamp broker-owned process-exit state.
    pub fn pid(&self) -> i32 {
        self.0.initial_pid()
    }
}

/// Create a default layered file system with the given in-memory and tar read-only layers.
pub fn default_fs(
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

// Special override so that `GETFL` can return stdio-specific flags.
pub(crate) use litebox::fs::devices::DeviceStatusFlags as StdioStatusFlags;

#[derive(Clone, Copy)]
pub(crate) struct HostStdioSourceFd(pub i32);

#[derive(Clone, Copy)]
pub(crate) struct HostTtyAlias;

/// Status flags for pipes
#[derive(Clone)]
pub(crate) struct PipeStatusFlags(pub litebox::fs::OFlags);

/// Marks a pipe created directly by the guest via pipe/pipe2.
///
/// Read site: the `BrokerPipe` `F_SETFL` arm in `syscalls/file.rs` checks this
/// marker before arming `PipeNonblockEagainOnce` after a delayed-fork resume.
/// That one-shot EAGAIN preserves native fork timing for a parent that creates a
/// pipe, forks, then sets the read end nonblocking while the child may have
/// already written and closed during delayed-fork migration. Broker pipes
/// installed from outside the guest (`install_broker_bridge_fd`, SCM_RIGHTS, or
/// D5 virtual-pipe restore) intentionally do not get that timing shim: their
/// ready/EOF state is externally owned and must be reported as-is.
#[derive(Clone, Copy)]
pub(crate) struct GuestCreatedPipe;

/// Forces one non-blocking pipe read after a delayed fork to report EAGAIN.
#[derive(Clone, Copy)]
pub(crate) struct PipeNonblockEagainOnce(pub bool);

impl<FS: ShimFS> syscalls::file::FilesState<FS> {
    fn initialize_stdio_in_shared_descriptors_table(&self, global: &GlobalState<FS>) {
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
        let stdio_object_ids = [
            Some(stdin.object_id()),
            Some(stdout.object_id()),
            Some(stderr.object_id()),
        ];
        let mut dt = global.litebox.descriptor_table_mut();
        let mut rds = self.raw_descriptor_store.write();
        for (raw_fd, fd) in [(0, stdin), (1, stdout), (2, stderr)] {
            let status_flags = OFlags::APPEND | OFlags::RDWR;
            debug_assert_eq!(OFlags::STATUS_FLAGS_MASK & status_flags, status_flags);
            let old = dt.set_entry_metadata(&fd, StdioStatusFlags(status_flags));
            assert!(old.is_none());
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let old = dt.set_entry_metadata(&fd, HostStdioSourceFd(raw_fd as i32));
            assert!(old.is_none());
            let success = rds.fd_into_specific_raw_integer(fd, raw_fd);
            assert!(success);
        }
        *self.host_stdio_object_ids.write() = stdio_object_ids;
    }
}

// Convenience type aliases
type ConstPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

impl<FS: ShimFS> Task<FS> {
    fn top_cow_layer(&self) -> Option<Arc<CowState>> {
        let ps = self.process_state.borrow();
        ps.active_vfork_layers.lock().last().cloned()
    }

    fn top_cow_layer_for_page(
        &self,
        page_addr: usize,
    ) -> Option<(
        Arc<CowState>,
        litebox::platform::page_mgmt::MemoryRegionPermissions,
    )> {
        let ps = self.process_state.borrow();
        let layers = ps.active_vfork_layers.lock();
        layers.iter().rev().find_map(|cow| {
            cow.protected_ranges
                .iter()
                .find(|&&(base, len, _)| page_addr >= base && page_addr < base + len)
                .map(|&(_, _, perms)| (cow.clone(), perms))
        })
    }

    fn snapshot_cow_page_if_needed(&self, cow: &CowState, page_addr: usize, page_present: bool) {
        let mut dirty = cow.dirty_pages.lock();
        if dirty.contains_key(&page_addr) {
            return;
        }
        let buf = if page_present {
            let mut buf = vec![0u8; PAGE_SIZE];
            unsafe {
                core::ptr::copy_nonoverlapping(page_addr as *const u8, buf.as_mut_ptr(), PAGE_SIZE);
            }
            buf
        } else {
            vec![0u8; PAGE_SIZE]
        };
        dirty.insert(page_addr, buf);
    }

    fn prepare_guest_write<T: zerocopy::FromBytes + zerocopy::IntoBytes>(
        &self,
        ptr: MutPtr<T>,
        count: usize,
    ) -> Result<(), Errno> {
        let len = core::mem::size_of::<T>()
            .checked_mul(count)
            .ok_or(Errno::ENOMEM)?;
        if len == 0 {
            return Ok(());
        }
        if self.prepare_cow_for_host_write(ptr.as_usize(), len) {
            Ok(())
        } else {
            Err(Errno::ENOMEM)
        }
    }

    fn guest_range_is_mapped(&self, addr: usize, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let Some(last_addr) = addr.checked_add(len - 1) else {
            return false;
        };
        let start = addr & !(PAGE_SIZE - 1);
        let end = (last_addr & !(PAGE_SIZE - 1)).saturating_add(PAGE_SIZE);
        let Some(start) = litebox::mm::linux::NonZeroAddress::<PAGE_SIZE>::new(start) else {
            return false;
        };
        let Some(len) =
            litebox::mm::linux::NonZeroPageSize::<PAGE_SIZE>::new(end - start.as_usize())
        else {
            return false;
        };
        self.process_state
            .borrow()
            .pm
            .get_memory_permissions(start, len)
            .is_some()
    }

    fn active_vfork_layer_count(&self) -> usize {
        let ps = self.process_state.borrow();
        ps.active_vfork_layers.lock().len()
    }

    fn reject_shared_vfork_vm_mutation(&self, what: &'static str) -> Result<(), Errno> {
        let depth = self.active_vfork_layer_count();
        if depth == 0 {
            return Ok(());
        }
        #[cfg(feature = "trace_syscalls")]
        litebox::log_println!(
            self.global.platform,
            "[TRACE-VFORK] rejecting {} during shared-vfork depth={}",
            what,
            depth,
        );
        log_unsupported!(
            "{} during shared-vfork (vm rollback not implemented yet)",
            what
        );
        Err(Errno::EINVAL)
    }

    fn lower_cow_page_permissions(
        &self,
        cow: &Arc<CowState>,
        page_addr: usize,
    ) -> Option<litebox::platform::page_mgmt::MemoryRegionPermissions> {
        use litebox::platform::page_mgmt::MemoryRegionPermissions;

        let ps = self.process_state.borrow();
        let layers = ps.active_vfork_layers.lock();
        let layer_index = layers.iter().rposition(|layer| Arc::ptr_eq(layer, cow))?;
        for lower in layers[..layer_index].iter().rev() {
            let Some(perms) = lower
                .protected_ranges
                .iter()
                .find(|&&(base, len, _)| page_addr >= base && page_addr < base + len)
                .map(|&(_, _, perms)| perms)
            else {
                continue;
            };
            let dirty = lower.dirty_pages.lock();
            return Some(if dirty.contains_key(&page_addr) {
                perms
            } else {
                perms & !MemoryRegionPermissions::WRITE
            });
        }
        None
    }

    fn restore_cow_layer_permissions(&self, cow: &Arc<CowState>) {
        for &(base, len, orig_perms) in &cow.protected_ranges {
            let mut run_start = base;
            let mut run_perms = self
                .lower_cow_page_permissions(cow, base)
                .unwrap_or(orig_perms);

            for page_addr in ((base + PAGE_SIZE)..(base + len)).step_by(PAGE_SIZE) {
                let perms = self
                    .lower_cow_page_permissions(cow, page_addr)
                    .unwrap_or(orig_perms);
                if perms == run_perms {
                    continue;
                }
                unsafe {
                    <crate::Platform as litebox::platform::PageManagementProvider<PAGE_SIZE>>::update_permissions(
                        self.global.platform,
                        run_start..page_addr,
                        run_perms,
                    )
                    .expect("CoW restore: failed to restore page permissions");
                }
                run_start = page_addr;
                run_perms = perms;
            }

            unsafe {
                <crate::Platform as litebox::platform::PageManagementProvider<PAGE_SIZE>>::update_permissions(
                    self.global.platform,
                    run_start..base + len,
                    run_perms,
                )
                .expect("CoW restore: failed to restore page permissions");
            }
        }
    }

    fn pop_cow_layer(&self, cow: &Arc<CowState>) {
        let ps = self.process_state.borrow();
        let mut layers = ps.active_vfork_layers.lock();
        let popped = layers.pop().expect("CoW stack must contain pushed layer");
        assert!(
            Arc::ptr_eq(&popped, cow),
            "CoW layers must unwind in LIFO order"
        );
    }

    fn restore_cow_layer(&self, cow: &Arc<CowState>, restore_bytes: bool) {
        if restore_bytes {
            let dirty_pages = {
                let mut dirty = cow.dirty_pages.lock();
                let dirty_pages = core::mem::take(&mut *dirty);
                // If a shim-side restore write faults on a page that we just
                // took ownership of, the fault handler still needs membership
                // in `dirty_pages` to avoid re-snapshotting it.
                *dirty = dirty_pages
                    .keys()
                    .map(|page_addr| (*page_addr, Vec::new()))
                    .collect();
                dirty_pages
            };

            for (page_addr, original_data) in &dirty_pages {
                if <crate::Platform as litebox::platform::AddressSpaceProvider>::EAGER_COW_FOR_VFORK
                {
                    let current =
                        unsafe { core::slice::from_raw_parts(*page_addr as *const u8, PAGE_SIZE) };
                    if current == original_data.as_slice() {
                        continue;
                    }
                }
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        original_data.as_ptr(),
                        *page_addr as *mut u8,
                        PAGE_SIZE,
                    );
                }
            }
        }

        self.restore_cow_layer_permissions(cow);
        self.pop_cow_layer(cow);
    }

    /// If the current task's transport told a "deferred park lie" during a 9P
    /// spin loop, this method claims that lie and blocks until the vfork window
    /// closes. Must be called before any guest memory write in `do_syscall`.
    ///
    /// The flow:
    /// 1. Try to claim one lie via CAS on `deferred_lie_count`.
    /// 2. Set per-task `deferred_vfork_park = true`.
    /// 3. Block on `park` futex until it returns to 0.
    /// 4. Decrement `parked_count` (we were counted as parked, now we leave).
    /// 5. Clear `deferred_vfork_park`.
    ///
    fn try_handle_cow_fault(
        &self,
        fault_addr: usize,
        ctx: &litebox_common_linux::PtRegs,
        page_present: bool,
    ) -> bool {
        #[cfg(not(all(feature = "trace_syscalls", target_arch = "x86_64")))]
        let _ = &ctx;
        #[cfg(all(feature = "trace_syscalls", target_arch = "x86_64"))]
        litebox::log_println!(
            self.global.platform,
            "[TRACE-COW] pid={} tid={} rip={:#x} fault_addr={:#x} page_present={} child={}",
            self.pid,
            self.tid,
            ctx.rip,
            fault_addr,
            page_present,
            self.fork_context.borrow().is_some(),
        );
        let page_addr = fault_addr & !(PAGE_SIZE - 1);
        let Some((cow, orig_perms)) = self.top_cow_layer_for_page(page_addr) else {
            return false;
        };
        let page_range = page_addr..page_addr + PAGE_SIZE;
        self.snapshot_cow_page_if_needed(cow.as_ref(), page_addr, page_present);
        unsafe { cow_update_permissions(self.global.platform, page_range, orig_perms) }
    }

    /// Uses CAS (not `fetch_sub`) to avoid underflow races with
    /// `unpark_other_threads` which uses `swap(0)` to settle all remaining
    /// unclaimed lies.
    fn park_if_deferred(&self) {
        use core::sync::atomic::Ordering;
        use litebox::platform::RawMutex as _;

        // The vfork child shares the parent's ProcessState (and therefore
        // VforkParking). It must never claim a lie or block — it's the one
        // thread allowed to run during the vfork window.
        if self.fork_context.borrow().is_some() {
            return;
        }

        let ps = self.process_state.borrow();
        let parking = &ps.vfork_parking;

        // Try to atomically claim one lie. CAS avoids underflow when
        // unpark_other_threads concurrently swaps deferred_lie_count to 0.
        loop {
            let current = parking.deferred_lie_count.load(Ordering::Acquire);
            if current == 0 {
                return; // No outstanding lies (or all settled by unpark).
            }
            if parking
                .deferred_lie_count
                .compare_exchange_weak(current, current - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break; // Successfully claimed one lie.
            }
        }

        // We own the lie. Mark ourselves as deferred-parked so that
        // prepare_for_exit can settle the parked_count if we exit early.
        self.deferred_vfork_park.set(true);

        // Block until the forking thread clears the park flag, or the
        // process is exiting (exit_group wakes vfork_park).
        loop {
            let v = parking.park.underlying_atomic().load(Ordering::Acquire);
            if v == 0 || self.is_exiting() {
                break;
            }
            let _ = parking.park.block(v);
        }

        // We're unblocked. Decrement parked_count (we were counted as parked).
        parking
            .parked_count
            .underlying_atomic()
            .fetch_sub(1, Ordering::Release);
        parking.parked_count.wake_all();

        self.deferred_vfork_park.set(false);
    }

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

    fn close_all_fds(&self) {
        let files = self.files.borrow();
        let alive_fds: Vec<usize> = files.raw_descriptor_store.read().iter_alive().collect();
        for raw_fd in alive_fds {
            let _ = self.do_close(raw_fd);
        }
        // Invariant S4: after close_all_fds, no fd-table slot should
        // remain alive. If any are left, it means do_close failed to
        // dispatch for some subsystem (i.e., a new fd kind was added
        // without wiring close support in sys_close).
        debug_assert!(
            files
                .raw_descriptor_store
                .read()
                .iter_alive()
                .next()
                .is_none(),
            "close_all_fds left alive fd-table entries — sys_close missing a subsystem arm"
        );
    }
}

/// A strongly-typed FD.
///
impl<FS: ShimFS> syscalls::file::FilesState<FS> {
    /// Exhaustive fd-kind dispatcher.
    ///
    /// Looks up `fd` in the shim's per-process descriptor store and
    /// invokes the matching closure for whichever subsystem owns the
    /// entry. Returns [`Errno::EBADF`] only when `fd` is genuinely
    /// not present in any subsystem table.
    ///
    /// **Exhaustiveness invariant**: every fd-shaped subsystem the
    /// shim supports must have a closure arm here. Adding a new
    /// subsystem (e.g., a future `PtySubsystem`, `SignalfdSubsystem`,
    /// `BrokerSocketpairSubsystem`) adds a new closure parameter,
    /// which is a compile-time forcing function for every call site
    /// to make an explicit decision about the new kind. Historically
    /// this dispatcher was 6-arm and `HostPassthroughFd` /
    /// `BrokerPipeSubsystem` were handled via per-syscall
    /// `try_host_passthrough_fd_fd` / `try_broker_pipe_fd` early-return fast
    /// paths; several syscalls forgot the broker-pipe fast path,
    /// silently returning EBADF on broker-pipe fds. The 8-arm shape
    /// makes that class of bug a compile error.
    ///
    /// **Closure receives `&Arc<TypedFd<X>>`**, not `&TypedFd<X>`, so
    /// arms that need an owned `Arc<TypedFd<X>>` (e.g., to embed in
    /// a binding type that outlives the closure) can clone it. Most
    /// call sites use it as `&TypedFd<X>` and rely on `Arc::deref`.
    /// Dispatch a raw fd integer to the subsystem that owns it.
    ///
    /// The closure receives a `RawFdRef<'_, FS>` enum and must match
    /// exhaustively — adding a new subsystem requires updating every
    /// caller, which is the property we want. (Previous positional-
    /// closure shapes silently let new subsystems be missed; that
    /// class of bug surfaced as silent `EBADF` returns for the
    /// missing subsystem — see e.g. the signalfd story captured by
    /// `PTY.dropbear_emul`.)
    ///
    /// **Variants receive `&Arc<TypedFd<X>>`**, not `&TypedFd<X>`, so
    /// arms that need an owned `Arc<TypedFd<X>>` can clone it. Most
    /// call sites use it as `&TypedFd<X>` and rely on `Arc::deref`.
    pub(crate) fn run_on_raw_fd<R>(
        &self,
        fd: usize,
        f: impl FnOnce(RawFdRef<'_, FS>) -> R,
    ) -> Result<R, Errno> {
        let rds = self.raw_descriptor_store.read();
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::Fs(&fd)));
        }
        #[cfg(feature = "worker_local_inet")]
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::Net(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::Eventfd(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::Epoll(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::Unix(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::HostPassthroughFd(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::BrokerPipe(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::BrokerSocketPair(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::BrokerSocketDgram(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::BrokerSocketSeqPacket(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::BrokerTcpConn(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::BrokerPty(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::Signalfd(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::Inotify(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::BrokerInetListener(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::BrokerInetDgram(&fd)));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(f(RawFdRef::BrokerInetRaw(&fd)));
        }
        Err(Errno::EBADF)
    }
}

/// Subsystem-tagged reference to a raw fd's owning typed fd.
///
/// Returned (via callback) by `FilesState::run_on_raw_fd`. Matching
/// on this enum is exhaustive: adding a new subsystem variant
/// produces compile errors at every call site, which is the
/// invariant the dispatcher exists to enforce.
pub(crate) enum RawFdRef<'a, FS: ShimFS> {
    Fs(&'a Arc<TypedFd<FS>>),
    #[cfg(feature = "worker_local_inet")]
    Net(&'a Arc<TypedFd<litebox::net::Network<Platform>>>),
    Eventfd(&'a Arc<TypedFd<syscalls::eventfd::EventfdSubsystem>>),
    Epoll(&'a Arc<TypedFd<syscalls::epoll::EpollSubsystem<FS>>>),
    Unix(&'a Arc<TypedFd<syscalls::unix::UnixSocketSubsystem<FS>>>),
    HostPassthroughFd(&'a Arc<TypedFd<syscalls::host_passthrough_fd::HostPassthroughFd>>),
    BrokerPipe(&'a Arc<TypedFd<syscalls::broker_pipe::BrokerPipeSubsystem>>),
    BrokerSocketPair(&'a Arc<TypedFd<syscalls::broker_socketpair::BrokerSocketPairSubsystem>>),
    BrokerSocketDgram(&'a Arc<TypedFd<syscalls::broker_socket_dgram::BrokerSocketDgramSubsystem>>),
    BrokerSocketSeqPacket(
        &'a Arc<TypedFd<syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem>>,
    ),
    BrokerTcpConn(&'a Arc<TypedFd<syscalls::broker_tcp_conn::BrokerTcpConnSubsystem>>),
    BrokerPty(&'a Arc<TypedFd<syscalls::broker_pty::BrokerPtySubsystem>>),
    Signalfd(&'a Arc<TypedFd<syscalls::signalfd::SignalfdSubsystem>>),
    Inotify(&'a Arc<TypedFd<syscalls::inotify::InotifySubsystem>>),
    BrokerInetListener(
        &'a Arc<TypedFd<syscalls::broker_inet_listener::BrokerInetListenerSubsystem>>,
    ),
    BrokerInetDgram(&'a Arc<TypedFd<syscalls::broker_inet_dgram::BrokerInetDgramSubsystem>>),
    BrokerInetRaw(&'a Arc<TypedFd<syscalls::broker_inet_raw::BrokerInetRawSubsystem>>),
}

// (Removed: pre-migration-gate scaffolding —
// `WorkerExecBridgeDecision` / `WorkerExecBridgeState` /
// `WorkerExecNoBridgeReason` / `BrokerFileBridgeState` /
// `TcpListenBridgeState` / `SignalfdBridgeState` / `TimerfdBridgeState`
// and `RawFdRef::worker_exec_bridge_decision`. These were added in
// `e3d38772` ("design: scaffold generic worker-exec fd bridge", May
// 2026) as an unused design sketch with `todo!()` arms, intended to
// become the cross-fork-path policy gate. That role is now filled by
// `litebox_shim_linux::syscalls::migration_policy::migration_policies_for`,
// which is exhaustive over `RawFdRef`, wired into all three fork-path
// entry points via `reference_gate`, and split across the three
// concrete fork-path dimensions (`worker_exec`, `delayed_fork`,
// `independent_fork`) rather than the single-dimension sketch this
// scaffold was. The scaffold had zero callers and four `todo!()`
// stubs at deletion time.)

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

impl<FS: ShimFS> Task<FS> {
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
                    self.park_if_deferred();
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
    fn task_comm_is(&self, name: &[u8]) -> bool {
        let comm = self.comm.get();
        name.len() < comm.len() && &comm[..name.len()] == name && comm[name.len()] == 0
    }

    fn task_comm_preview(&self) -> alloc::string::String {
        let comm = self.comm.get();
        let end = comm
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(comm.len());
        let mut out = alloc::string::String::new();
        for &byte in &comm[..end] {
            match byte {
                b' '..=b'~' => out.push(byte as char),
                _ => out.push('.'),
            }
        }
        out
    }

    fn address_mapping_summary(&self, addr: usize) -> alloc::string::String {
        let page_addr = addr & !(PAGE_SIZE - 1);
        let ps = self.process_state.borrow();
        let mappings = ps.pm.mappings();

        let containing = mappings
            .iter()
            .find(|(range, _)| range.start <= page_addr && page_addr < range.end);
        let prev = mappings
            .iter()
            .filter(|(range, _)| range.end <= page_addr)
            .max_by_key(|(range, _)| range.end);
        let next = mappings
            .iter()
            .filter(|(range, _)| range.start > page_addr)
            .min_by_key(|(range, _)| range.start);

        let trampoline =
            {
                let cache = ps.elf_patch_cache.lock();
                cache.iter().find_map(|(fd, state)| {
                let tramp_len = if state.pre_patched {
                    state.trampoline_file_size.next_multiple_of(PAGE_SIZE)
                } else if state.trampoline_mapped {
                    state.trampoline_cursor.max(PAGE_SIZE).next_multiple_of(PAGE_SIZE)
                } else {
                    0
                };
                if tramp_len == 0 {
                    return None;
                }
                let tramp_end = state.trampoline_addr.checked_add(tramp_len)?;
                if state.trampoline_addr <= page_addr && page_addr < tramp_end {
                    Some(alloc::format!(
                        " fd={} file={:?} tramp={:#x}..{:#x} mapped={} pre_patched={} cursor={:#x}",
                        fd,
                        state.file_path.as_deref().unwrap_or("<unknown>"),
                        state.trampoline_addr,
                        tramp_end,
                        state.trampoline_mapped,
                        state.pre_patched,
                        state.trampoline_cursor,
                    ))
                } else {
                    None
                }
            })
            };

        let bss_start = ps.main_bss_start.load(Ordering::Relaxed);
        let bss_end = ps.main_bss_end.load(Ordering::Relaxed);

        let mut out = alloc::format!(
            "addr={:#x} page={:#x} partition={:#x}..{:#x}",
            addr,
            page_addr,
            ps.pm.addr_min(),
            ps.pm.addr_max(),
        );

        if let Some((range, flags)) = containing {
            let _ = write!(
                out,
                " mapping={:#x}..{:#x} flags={:?}",
                range.start, range.end, flags,
            );
        } else {
            out.push_str(" mapping=<none>");
        }

        if let Some((range, flags)) = prev {
            let _ = write!(
                out,
                " prev={:#x}..{:#x} flags={:?}",
                range.start, range.end, flags,
            );
        }

        if let Some((range, flags)) = next {
            let _ = write!(
                out,
                " next={:#x}..{:#x} flags={:?}",
                range.start, range.end, flags,
            );
        }

        if bss_start != 0 || bss_end != 0 {
            let _ = write!(out, " main_bss={bss_start:#x}..{bss_end:#x}");
        }

        if let Some(trampoline) = trampoline {
            out.push_str(" trampoline=");
            out.push_str(&trampoline);
        }

        out
    }

    fn shell_write_contains(buf: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && buf.windows(needle.len()).any(|window| window == needle)
    }

    fn should_trace_shell_write(buf: &[u8]) -> bool {
        Self::shell_write_contains(buf, b"___BEGIN___COMMAND_")
            || Self::shell_write_contains(buf, b"COMMAND_DONE_MARKER")
            || Self::shell_write_contains(buf, b"PS1=\"\"")
            || Self::shell_write_contains(buf, b"unset HISTFILE")
            || Self::shell_write_contains(buf, b"git --no-pager")
    }

    fn shell_write_preview(buf: &[u8]) -> alloc::string::String {
        let mut out = alloc::string::String::new();
        for &byte in buf.iter().take(SHELL_WRITE_PREVIEW_LEN) {
            match byte {
                b'\n' => out.push_str("\\n"),
                b'\r' => out.push_str("\\r"),
                b'\t' => out.push_str("\\t"),
                b' '..=b'~' => out.push(byte as char),
                _ => out.push('.'),
            }
        }
        if buf.len() > SHELL_WRITE_PREVIEW_LEN {
            out.push_str("...");
        }
        out
    }

    fn shell_write_target_preview(&self, fd: i32) -> alloc::string::String {
        let Ok(raw_fd) = usize::try_from(fd) else {
            return alloc::string::String::from("<bad-fd>");
        };

        let files = self.files.borrow();
        files
            .run_on_raw_fd(raw_fd, |raw_fd_ref| match raw_fd_ref {
                crate::RawFdRef::Fs(file_fd) => {
                    let status = files.fs.fd_file_status(file_fd).ok();
                    match status
                        .and_then(|status| status.node_info.rdev.map(core::num::NonZero::get))
                    {
                        Some(rdev) => {
                            alloc::format!("raw={} fs rdev={}:{}", raw_fd, rdev >> 8, rdev & 0xff)
                        }
                        None => alloc::format!("raw={raw_fd} fs"),
                    }
                }
                #[cfg(feature = "worker_local_inet")]
                crate::RawFdRef::Net(_fd) => alloc::format!("raw={raw_fd} net"),
                crate::RawFdRef::Eventfd(_fd) => alloc::format!("raw={raw_fd} eventfd"),
                crate::RawFdRef::Epoll(_fd) => alloc::format!("raw={raw_fd} epoll"),
                crate::RawFdRef::Unix(_fd) => alloc::format!("raw={raw_fd} unix"),
                crate::RawFdRef::HostPassthroughFd(_fd) => {
                    alloc::format!("raw={raw_fd} host_passthrough_fd")
                }
                crate::RawFdRef::BrokerPipe(_fd) => alloc::format!("raw={raw_fd} broker_pipe"),
                RawFdRef::BrokerSocketPair(_fd) => {
                    alloc::format!("raw={raw_fd} broker_socketpair")
                }
                crate::RawFdRef::BrokerSocketDgram(_fd) => {
                    alloc::format!("raw={raw_fd} broker_socket_dgram")
                }
                crate::RawFdRef::BrokerSocketSeqPacket(_fd) => {
                    alloc::format!("raw={raw_fd} broker_socket_seqpacket")
                }
                crate::RawFdRef::BrokerTcpConn(_fd) => {
                    alloc::format!("raw={raw_fd} broker_tcp_conn")
                }
                crate::RawFdRef::BrokerPty(_fd) => alloc::format!("raw={raw_fd} broker_pty"),
                crate::RawFdRef::Signalfd(_fd) => alloc::format!("raw={raw_fd} signalfd"),
                crate::RawFdRef::Inotify(_fd) => alloc::format!("raw={raw_fd} inotify"),
                crate::RawFdRef::BrokerInetListener(_fd) => {
                    alloc::format!("raw={raw_fd} broker-inet-listener")
                }
                crate::RawFdRef::BrokerInetDgram(_fd) => {
                    alloc::format!("raw={raw_fd} broker-inet-dgram")
                }
                crate::RawFdRef::BrokerInetRaw(_fd) => {
                    alloc::format!("raw={raw_fd} broker-inet-raw")
                }
            })
            .unwrap_or_else(|_| alloc::format!("raw={raw_fd} invalid"))
    }

    #[allow(clippy::similar_names)] // rip/rsp are standard register names
    fn remember_traced_shell_write(
        &self,
        fd: i32,
        via: &'static str,
        total_len: usize,
        target: alloc::string::String,
        preview: alloc::string::String,
        ctx: Option<&litebox_common_linux::PtRegs>,
    ) {
        let (syscall_rip, syscall_rsp) = match ctx {
            Some(ctx) => (ctx.rip, ctx.rsp),
            None => (0, 0),
        };
        self.last_shell_write.replace(Some(RecentShellWrite {
            fd,
            via,
            total_len,
            target,
            preview,
            syscall_rip,
            syscall_rsp,
        }));
    }

    fn maybe_trace_shell_write(
        &self,
        ctx: Option<&litebox_common_linux::PtRegs>,
        fd: i32,
        via: &'static str,
        total_len: usize,
        buf: &[u8],
    ) {
        if self.task_comm_is(b"bash") || !Self::should_trace_shell_write(buf) {
            return;
        }

        let target = self.shell_write_target_preview(fd);
        let preview = Self::shell_write_preview(buf);
        self.remember_traced_shell_write(fd, via, total_len, target.clone(), preview.clone(), ctx);
    }

    fn maybe_trace_shell_writev(
        &self,
        ctx: Option<&litebox_common_linux::PtRegs>,
        fd: i32,
        iovs: &[litebox_common_linux::IoWriteVec<ConstPtr<u8>>],
    ) {
        if self.task_comm_is(b"bash") {
            return;
        }

        let mut total_len = 0usize;
        let mut sampled = alloc::vec::Vec::new();
        for iov in iovs {
            total_len = total_len.saturating_add(iov.iov_len);
            if sampled.len() >= SHELL_WRITE_SCAN_LEN {
                continue;
            }

            let to_copy = iov.iov_len.min(SHELL_WRITE_SCAN_LEN - sampled.len());
            if to_copy == 0 {
                continue;
            }
            let Some(slice) = iov.iov_base.to_owned_slice(to_copy) else {
                return;
            };
            sampled.extend_from_slice(&slice);
        }

        self.maybe_trace_shell_write(ctx, fd, "writev", total_len, &sampled);
    }

    fn record_syscall_entry(&self, ctx: &litebox_common_linux::PtRegs, syscall_number: usize) {
        self.last_syscall.set(Some(RecentSyscall {
            number: syscall_number,
            entry_rip: ctx.rip,
            entry_rsp: ctx.rsp,
            #[cfg(target_arch = "x86")]
            entry_rbp: ctx.ebp as usize,
            #[cfg(target_arch = "x86_64")]
            entry_rbp: ctx.rbp,
            arg0: ctx.syscall_arg(0),
            arg1: ctx.syscall_arg(1),
            arg2: ctx.syscall_arg(2),
        }));
    }

    #[cfg(all(feature = "trace_syscalls", target_arch = "x86_64"))]
    fn trace_stack_words(&self, rsp: usize) -> (Option<usize>, Option<usize>) {
        let stack0 = ConstPtr::<usize>::from_usize(rsp).read_at_offset(0);
        let stack1 =
            ConstPtr::<usize>::from_usize(rsp + core::mem::size_of::<usize>()).read_at_offset(0);
        (stack0, stack1)
    }

    fn log_fatal_signal_recent_activity(&self) {
        if let Some(last_syscall) = self.last_syscall.get() {
            litebox::log_println!(
                self.global.platform,
                "[FATAL-SIGNAL-LAST-SYSCALL] pid={} tid={} nr={} entry_rip={:#x} entry_rsp={:#x} arg0={:#x} arg1={:#x} arg2={:#x}",
                self.pid,
                self.tid,
                last_syscall.number,
                last_syscall.entry_rip,
                last_syscall.entry_rsp,
                last_syscall.arg0,
                last_syscall.arg1,
                last_syscall.arg2,
            );
        }

        if let Some(last_write) = self.last_shell_write.borrow().as_ref() {
            litebox::log_println!(
                self.global.platform,
                "[FATAL-SIGNAL-LAST-WRITE] pid={} tid={} fd={} target={} via={} len={} syscall_rip={:#x} syscall_rsp={:#x} preview={:?}",
                self.pid,
                self.tid,
                last_write.fd,
                last_write.target.as_str(),
                last_write.via,
                last_write.total_len,
                last_write.syscall_rip,
                last_write.syscall_rsp,
                last_write.preview.as_str(),
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn log_fatal_signal_context(
        &self,
        signal: litebox_common_linux::signal::Signal,
        ctx: &litebox_common_linux::PtRegs,
    ) {
        let last_exception = self.signals.last_exception();
        litebox::log_println!(
            self.global.platform,
            "[FATAL-SIGNAL-CONTEXT] pid={} tid={} comm={:?} signal={:?} rip={:#x} rsp={:#x} rax={:#x} orig_rax={:#x} rdi={:#x} rsi={:#x} rdx={:#x} cr2={:#x} error_code={:#x}",
            self.pid,
            self.tid,
            self.task_comm_preview(),
            signal,
            ctx.rip,
            ctx.rsp,
            ctx.rax,
            ctx.orig_rax,
            ctx.rdi,
            ctx.rsi,
            ctx.rdx,
            last_exception.cr2,
            last_exception.error_code,
        );
        litebox::log_println!(
            self.global.platform,
            "[FATAL-SIGNAL-ADDR] pid={} tid={} kind=rip summary={}",
            self.pid,
            self.tid,
            self.address_mapping_summary(ctx.rip),
        );
        if last_exception.cr2 != 0 {
            litebox::log_println!(
                self.global.platform,
                "[FATAL-SIGNAL-ADDR] pid={} tid={} kind=fault summary={}",
                self.pid,
                self.tid,
                self.address_mapping_summary(last_exception.cr2),
            );
        }
        self.log_fatal_signal_recent_activity();
    }

    #[cfg(target_arch = "x86")]
    pub(crate) fn log_fatal_signal_context(
        &self,
        signal: litebox_common_linux::signal::Signal,
        ctx: &litebox_common_linux::PtRegs,
    ) {
        let last_exception = self.signals.last_exception();
        litebox::log_println!(
            self.global.platform,
            "[FATAL-SIGNAL-CONTEXT] pid={} tid={} comm={:?} signal={:?} eip={:#x} esp={:#x} eax={:#x} orig_eax={:#x} ebx={:#x} ecx={:#x} edx={:#x} cr2={:#x} error_code={:#x}",
            self.pid,
            self.tid,
            self.task_comm_preview(),
            signal,
            ctx.eip,
            ctx.esp,
            ctx.eax,
            ctx.orig_eax,
            ctx.ebx,
            ctx.ecx,
            ctx.edx,
            last_exception.cr2,
            last_exception.error_code,
        );
        litebox::log_println!(
            self.global.platform,
            "[FATAL-SIGNAL-ADDR] pid={} tid={} kind=eip summary={}",
            self.pid,
            self.tid,
            self.address_mapping_summary(ctx.eip),
        );
        if last_exception.cr2 != 0 {
            litebox::log_println!(
                self.global.platform,
                "[FATAL-SIGNAL-ADDR] pid={} tid={} kind=fault summary={}",
                self.pid,
                self.tid,
                self.address_mapping_summary(last_exception.cr2),
            );
        }
        self.log_fatal_signal_recent_activity();
    }
}

impl<FS: ShimFS> Task<FS> {
    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::ExecutionContext) {
        // Mark that ctx.r11 holds the call-site scratch address (not the
        // real guest R11). Cleared by the exception/interrupt entry path.
        self.in_syscall.set(true);

        // Reset restart flag. Individual syscall implementations opt in to
        // restart semantics by setting this flag before returning EINTR
        // (mirroring Linux's ERESTARTSYS).
        self.syscall_restartable.set(false);

        #[cfg(feature = "trace_syscalls")]
        {
            #[cfg(target_arch = "x86_64")]
            {
                let (stack0, stack1) = self.trace_stack_words(ctx.rsp);
                litebox::log_println!(
                    self.global.platform,
                    "[TRACE] syscall: pid={} tid={} nr={} rip={:#x} rsp={:#x} stack0={:?} stack1={:?} arg0={:#x} arg1={:#x} arg2={:#x}",
                    self.pid,
                    self.tid,
                    ctx.orig_rax,
                    ctx.rip,
                    ctx.rsp,
                    stack0,
                    stack1,
                    ctx.syscall_arg(0),
                    ctx.syscall_arg(1),
                    ctx.syscall_arg(2),
                );
            }
        }

        let is_thread_exit = ctx.orig_rax == ::syscalls::Sysno::exit as usize;
        // PE.1 Step C: stamp the broker control protocol caller_pid
        // header on every broker RPC issued by this syscall, so the
        // broker's per-(pid, id) tracker correctly attributes refs to
        // the calling process.
        let _caller_pid_guard =
            litebox_common_linux::fd_token_client::set_caller_pid_scope(self.pid as u32);
        let return_value = match self.do_syscall(ctx) {
            Ok(v) => {
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[TRACE] syscall done: pid={} tid={} ret=Ok({})",
                    self.pid,
                    self.tid,
                    v,
                );
                v
            }
            Err(err) => {
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[TRACE] syscall done: pid={} tid={} ret=Err({})",
                    self.pid,
                    self.tid,
                    err.as_neg(),
                );
                (err.as_neg() as isize).reinterpret_as_unsigned()
            }
        };

        if is_thread_exit {
            self.local_task_terminated.set(true);
            return;
        }

        #[cfg(target_arch = "x86")]
        {
            ctx.eax = return_value;
        }
        #[cfg(target_arch = "x86_64")]
        {
            ctx.rax = return_value;
            #[cfg(feature = "trace_syscalls")]
            let (stack0, stack1) = self.trace_stack_words(ctx.rsp);
            #[cfg(feature = "trace_syscalls")]
            litebox::log_println!(
                self.global.platform,
                "[TRACE] syscall resume: pid={} tid={} rip={:#x} rcx={:#x} r11={:#x} rsp={:#x} stack0={:?} stack1={:?} rax={:#x}",
                self.pid,
                self.tid,
                ctx.rip,
                ctx.rcx,
                ctx.r11,
                ctx.rsp,
                stack0,
                stack1,
                ctx.rax,
            );
        }
    }

    /// Returns `true` if the given syscall is in the pre-exec allowlist and
    /// should be permitted to execute in vfork-style mode without triggering a
    /// delayed true fork.
    ///
    /// The allowlist covers the syscalls that `posix_spawn` and runtime libraries
    /// typically issue between `fork` and `execve`.  Any syscall *not* in this
    /// list indicates the child intends to run independently and must be migrated
    /// to its own worker host.
    ///
    /// Two syscalls (`fcntl` and `prctl`) require argument-level inspection
    /// because they multiplex many operations through a single syscall number.
    #[cfg(target_arch = "x86_64")]
    #[cfg(test)]
    fn is_pre_exec_syscall(ctx: &litebox_common_linux::ExecutionContext) -> bool {
        Self::is_pre_exec_syscall_impl(ctx, false)
    }

    fn is_pre_exec_syscall_for_task(&self, ctx: &litebox_common_linux::ExecutionContext) -> bool {
        use ::syscalls::Sysno;

        let socketpair_read = matches!(Sysno::new(ctx.orig_rax), Some(Sysno::read)) && {
            let files = self.files.borrow();
            let rds = files.raw_descriptor_store.read();
            rds.fd_from_raw_integer::<syscalls::unix::UnixSocketSubsystem<FS>>(ctx.rdi)
                .is_ok()
                || rds
                    .fd_from_raw_integer::<syscalls::broker_socketpair::BrokerSocketPairSubsystem>(
                        ctx.rdi,
                    )
                    .is_ok()
        };
        Self::is_pre_exec_syscall_impl(ctx, socketpair_read)
    }

    fn is_pre_exec_syscall_impl(
        ctx: &litebox_common_linux::ExecutionContext,
        unix_socket_read: bool,
    ) -> bool {
        use ::syscalls::Sysno;

        let nr = ctx.orig_rax;

        // A blocking read from an inherited Unix socket is real post-fork work,
        // not fork/exec bookkeeping.  Let delayed-fork migration run first so
        // the parent can resume and communicate with the child.
        if unix_socket_read {
            return false;
        }

        // Match on syscall number, with argument inspection for fcntl/prctl.
        match Sysno::new(nr) {
            // Number-only allowlisted syscalls.
            Some(
                // Terminal — child leaves vfork mode.
                Sysno::execve | Sysno::execveat | Sysno::exit | Sysno::exit_group
                // FD plumbing.  `read` is needed for nested $() — the
                // outer subshell reads the inner capture pipe's output
                // before writing it to its own stdout. `socket` is safe to
                // defer because later bind/connect migrates the child with
                // the new descriptor preserved.
                | Sysno::close | Sysno::close_range | Sysno::dup | Sysno::dup2 | Sysno::dup3
                | Sysno::open | Sysno::openat | Sysno::openat2 | Sysno::pipe2 | Sysno::write
                | Sysno::read | Sysno::socket
                // A nested fork or wait is real post-fork shell work.  Commit
                // delayed fork first so the parent shell can resume and service
                // command-substitution pipes while the child shell runs.
                // Directory.
                | Sysno::chdir | Sysno::fchdir
                // Process group.
                | Sysno::setpgid | Sysno::setsid
                // Signal/thread-runtime setup. Static C runtimes refresh
                // thread bookkeeping immediately after fork before user code.
                | Sysno::rt_sigaction | Sysno::rt_sigprocmask | Sysno::sigaltstack
                | Sysno::set_tid_address | Sysno::set_robust_list
                // Thread/runtime teardown before exit_group.  Rust/glibc may
                // unmap and madvise thread stacks after user code calls exit;
                // migrating at that point only stalls the vfork parent.
                | Sysno::munmap | Sysno::madvise
                // Identity.
                | Sysno::setuid | Sysno::setgid | Sysno::setgroups
                | Sysno::setreuid | Sysno::setregid
                | Sysno::setresuid | Sysno::setresgid
                // Scheduling.
                | Sysno::sched_setscheduler | Sysno::sched_setaffinity
                | Sysno::sched_setparam
                // Resource limits.
                | Sysno::setrlimit | Sysno::prlimit64
                // Relative sleeps are safe in the delayed-fork window: they do
                // not mutate the shared address space, and keeping the parent
                // parked preserves vfork-style ordering until real work starts.
                | Sysno::clock_nanosleep | Sysno::nanosleep
                // No-ops (read-only queries).
                | Sysno::getpid | Sysno::getppid | Sysno::gettid
                | Sysno::getuid | Sysno::geteuid | Sysno::getgid | Sysno::getegid
                | Sysno::getsid | Sysno::getpgid
                // Stat queries — bash calls fstat between fork and exec
                // to check terminal type and fd validity.
                | Sysno::fstat | Sysno::stat | Sysno::lstat | Sysno::newfstatat
                // Access queries — bash calls faccessat(X_OK) during PATH
                // lookup between fork and exec to check executability.
                | Sysno::access | Sysno::faccessat | Sysno::faccessat2
                // Symlink queries — bash may readlink during PATH search.
                | Sysno::readlink | Sysno::readlinkat
                // ioctl — bash calls ioctl(TIOCGPGRP) for job control
                // between fork and exec.
                | Sysno::ioctl,
            ) => true,
            // Argument-aware: fcntl — only allow fd flag / dup / status-flag operations.
            // F_DUPFD=0, F_GETFD=1, F_SETFD=2, F_GETFL=3, F_SETFL=4, F_DUPFD_CLOEXEC=1030
            Some(Sysno::fcntl) => matches!(ctx.rsi, 0 | 1 | 2 | 3 | 4 | 1030),
            // Argument-aware: prctl — only allow SET_PDEATHSIG and SET_NAME.
            // PR_SET_PDEATHSIG=1, PR_SET_NAME=15
            Some(Sysno::prctl) => matches!(ctx.rdi, 1 | 15),
            // Argument-aware: futex — only allow non-blocking WAKE-flavoured
            // operations. After fork, glibc's `__libc_fork` epilogue releases
            // its internal pthread atfork mutex via
            // `futex(FUTEX_WAKE_PRIVATE, 1)` (op=0x81). Without this allowlist
            // every static-PIE-glibc fork-child traps into
            // `commit_delayed_fork`, which (for tests that hold a CLOEXEC
            // epoll fd — e.g. the tokio runtime in the test harness) then
            // rejects and falls back to vfork shared-AS anyway. The wasted
            // snapshot_fd_table + snapshot_memory work per fork blows the
            // `PROMOTION_RACE.concurrent_fork.{eventfd,signalfd}.spg`
            // 15s send_cmd budget. Dynamic-PIE-glibc emits no futex post-fork
            // (its atfork lock release inlines as an atomic store), so this
            // gate only affects static-glibc binaries.
            //
            // Operation nibble (rsi & FUTEX_CMD_MASK = 0x7f) we accept:
            //   FUTEX_WAKE          = 1
            //   FUTEX_REQUEUE       = 3
            //   FUTEX_CMP_REQUEUE   = 4
            //   FUTEX_WAKE_OP       = 5
            //   FUTEX_UNLOCK_PI     = 7
            //   FUTEX_WAKE_BITSET   = 10
            // All are non-blocking releases that cannot stall the vfork
            // parent. Blocking ops (FUTEX_WAIT, FUTEX_WAIT_BITSET,
            // FUTEX_LOCK_PI, FUTEX_TRYLOCK_PI) deliberately remain off the
            // list — letting them run pre-exec would let a fork-child wait
            // for a wake-up the parked vfork parent cannot deliver.
            Some(Sysno::futex) => {
                let op = (ctx.rsi as u32) & 0x7f;
                matches!(op, 1 | 3 | 4 | 5 | 7 | 10)
            }
            // Any unrecognized or non-allowlisted syscall triggers a delayed fork.
            _ => false,
        }
    }

    fn do_syscall(&self, ctx: &mut litebox_common_linux::ExecutionContext) -> Result<usize, Errno> {
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

        // Delayed fork trigger: if this task is a fork child waiting to be
        // promoted to a true fork, check whether the current syscall is in
        // the pre-exec allowlist.  If not, commit the delayed fork now.
        #[cfg(target_arch = "x86_64")]
        if self.delayed_fork_pending.get() {
            let is_pre_exec = self.is_pre_exec_syscall_for_task(ctx);
            #[cfg(feature = "trace_syscalls")]
            {
                let sysname = ::syscalls::Sysno::new(ctx.orig_rax).map_or_else(
                    || alloc::format!("unknown({})", ctx.orig_rax),
                    |s| alloc::format!("{s:?}"),
                );
                let comm_bytes = self.comm.get();
                let comm_str = core::str::from_utf8(
                    &comm_bytes[..comm_bytes
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(comm_bytes.len())],
                )
                .unwrap_or("<invalid>");
                litebox::log_println!(
                    self.global.platform,
                    "[DELAYED-FORK-SYSCALL] pid={} comm={:?} ppid={}: syscall {} pre_exec={} args=({}, {}, {})",
                    self.pid,
                    comm_str,
                    self.ppid,
                    sysname,
                    is_pre_exec,
                    ctx.rdi,
                    ctx.rsi,
                    ctx.rdx,
                );
            }
            if !is_pre_exec {
                // Nested vfork: if our parent is itself a delayed-fork
                // child, do NOT migrate — the pipe bridging would corrupt
                // the parent's fd table (shared via vfork).  Instead, let
                // this child continue in the shared address space.  It
                // will exec (detaching properly) or exit.
                let parent_is_delayed = self
                    .fork_context
                    .borrow()
                    .as_ref()
                    .is_some_and(|fc| fc.parent_is_delayed_fork);
                if parent_is_delayed {
                    #[cfg(feature = "trace_syscalls")]
                    litebox::log_println!(
                        self.global.platform,
                        "[DELAYED-FORK-NESTED] pid={}: parent is delayed-fork, skipping migration",
                        self.pid,
                    );
                    self.delayed_fork_pending.set(false);
                    // Fall through to normal syscall handling.
                } else if self.commit_delayed_fork(ctx).is_ok() {
                    // Child migrated to a worker host.  Stop this local shim
                    // task without marking the current host thread as exiting:
                    // the host thread belongs to the parent runtime and must
                    // remain available after the migrated child is handed off.
                    #[cfg(feature = "trace_syscalls")]
                    litebox::log_println!(
                        self.global.platform,
                        "[DELAYED-FORK-TRIGGER] pid={}: commit SUCCESS — child migrated, terminating local task",
                        self.pid,
                    );
                    self.local_task_terminated.set(true);
                    return Ok(0);
                }
                // Delayed fork could not migrate this child (e.g. unsupported
                // fd types like sandbox PTY slaves on stdio).  Instead of
                // killing the child, let it continue as a vfork child sharing
                // the parent's address space.  The child will eventually
                // execve (which detaches from the parent and signals
                // VforkDone) or exit (which signals VforkDone via
                // prepare_for_exit).  The parent remains blocked on
                // VforkDone, which is correct vfork semantics.
                #[cfg(feature = "trace_syscalls")]
                litebox::log_println!(
                    self.global.platform,
                    "[DELAYED-FORK-TRIGGER] pid={}: commit FAILED — continuing as vfork child",
                    self.pid,
                );
                self.delayed_fork_pending.set(false);
                // Fall through to normal syscall handling.
            }
        }

        if syscall_number == ::syscalls::Sysno::close_range as usize {
            self.record_syscall_entry(ctx, syscall_number);
            #[cfg(target_arch = "x86")]
            return self.sys_close_range(ctx.ebx as u32, ctx.ecx as u32, ctx.edx as u32);
            #[cfg(target_arch = "x86_64")]
            return self.sys_close_range(
                ctx.rdi.truncate(),
                ctx.rsi.truncate(),
                ctx.rdx.truncate(),
            );
        }

        let request = match SyscallRequest::<Platform>::try_from_raw(
            syscall_number,
            ctx,
            log_unsupported_fmt,
        ) {
            Ok(req) => req,
            Err(e) => {
                return Err(e);
            }
        };

        self.record_syscall_entry(ctx, syscall_number);

        #[cfg(feature = "audit_log")]
        let (audit_seq, audit_syscall_name) = if audit::is_enabled() {
            let mut audit_event = audit::build_audit_event(&request);
            audit_event.pid = self.pid;
            audit_event.tid = self.tid;
            let comm_bytes = self.comm.get();
            let comm_len = comm_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(comm_bytes.len());
            let _ = audit_event
                .comm
                .try_push_str(core::str::from_utf8(&comm_bytes[..comm_len]).unwrap_or("?"));
            let name = audit_event.syscall_name;
            (audit::emit_entry_event(&audit_event), name)
        } else {
            (0, "")
        };

        let result = match request {
            SyscallRequest::Exit { status } => {
                self.sys_exit(status);
                Ok(0)
            }
            SyscallRequest::ExitGroup { status } => {
                self.sys_exit_group(status);
                Ok(0)
            }
            SyscallRequest::Wait4 {
                pid,
                wstatus,
                options,
                rusage,
            } => self.sys_wait4(pid, wstatus, options, rusage),
            SyscallRequest::Waitid {
                idtype,
                id,
                infop,
                options,
            } => self.sys_waitid(idtype, id, infop, options),
            SyscallRequest::PidfdOpen { pid, flags } => syscall!(sys_pidfd_open(pid, flags)),
            SyscallRequest::PidfdSendSignal {
                pidfd,
                sig,
                info,
                flags,
            } => syscall!(sys_pidfd_send_signal(pidfd, sig, info, flags)),
            SyscallRequest::Execve {
                pathname,
                argv,
                envp,
            } => self.sys_execve(pathname, argv, envp, ctx),
            SyscallRequest::Execveat {
                dirfd,
                pathname,
                argv,
                envp,
                flags,
            } => {
                const AT_EMPTY_PATH: i32 = 0x1000;
                if flags & AT_EMPTY_PATH != 0 {
                    // fexecve path: resolve the fd to a filesystem path.
                    let path = self.fd_path_for_raw(dirfd).ok_or(Errno::EBADF)?;
                    let path_cstr =
                        alloc::ffi::CString::new(path.as_bytes()).map_err(|_| Errno::EINVAL)?;
                    let path_ptr = crate::ConstPtr::<i8>::from_usize(path_cstr.as_ptr() as usize);
                    // Keep path_cstr alive across the call.
                    let result = self.sys_execve(path_ptr, argv, envp, ctx);
                    drop(path_cstr);
                    result
                } else {
                    // Non-AT_EMPTY_PATH: treat like regular execve with
                    // the pathname (dirfd-relative paths not yet supported).
                    self.sys_execve(pathname, argv, envp, ctx)
                }
            }
            SyscallRequest::Read { fd, buf, count } => {
                // Note some applications (e.g., `node`) seem to assume that getting fewer bytes than
                // requested indicates EOF.
                if count <= MAX_KERNEL_BUF_SIZE {
                    let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];

                    self.sys_read(fd, &mut kernel_buf, None).and_then(|size| {
                        self.park_if_deferred();
                        buf.copy_from_slice(0, &kernel_buf[..size])
                            .map(|()| size)
                            .ok_or(Errno::EFAULT)
                    })
                } else {
                    // Read is too large for a single kernel buffer. Try to get
                    // the current file offset so we can use pread in chunks.
                    match self.sys_lseek(fd, 0, litebox::fs::SeekWhence::RelativeToCurrentOffset) {
                        Ok(cur_loc) => {
                            // Seekable fd — use pread in chunks, then update offset.
                            self.pread_with_user_buf(
                                fd,
                                buf,
                                count,
                                i64::try_from(cur_loc).unwrap(),
                            )
                            .inspect(|read_total| {
                                self.sys_lseek(
                                    fd,
                                    (cur_loc + read_total).reinterpret_as_signed(),
                                    litebox::fs::SeekWhence::RelativeToBeginning,
                                )
                                .expect("lseek failed");
                            })
                        }
                        Err(Errno::ESPIPE) => {
                            // Non-seekable fd (pipe, socket) — read in chunks
                            // using sys_read directly.
                            let mut kernel_buf = vec![0u8; MAX_KERNEL_BUF_SIZE];
                            let mut read_total = 0;
                            while read_total < count {
                                let to_read = (count - read_total).min(kernel_buf.len());
                                match self.sys_read(fd, &mut kernel_buf[..to_read], None) {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if buf
                                            .copy_from_slice(read_total, &kernel_buf[..n])
                                            .is_none()
                                        {
                                            return Err(Errno::EFAULT);
                                        }
                                        read_total += n;
                                        if n < to_read {
                                            break; // short read
                                        }
                                    }
                                    Err(e) if read_total > 0 => {
                                        let _ = e;
                                        break; // return partial read
                                    }
                                    Err(e) => return Err(e),
                                }
                            }
                            self.park_if_deferred();
                            Ok(read_total)
                        }
                        Err(e) => Err(e),
                    }
                }
            }
            SyscallRequest::Write { fd, buf, count } => match buf.to_owned_slice(count) {
                Some(buf) => {
                    let scan_len = buf.len().min(SHELL_WRITE_SCAN_LEN);
                    self.maybe_trace_shell_write(
                        Some(ctx),
                        fd,
                        "write",
                        buf.len(),
                        &buf[..scan_len],
                    );
                    self.sys_write(fd, &buf, None)
                }
                None => Err(Errno::EFAULT),
            },
            SyscallRequest::Close { fd } => {
                syscall!(sys_close(fd))
            }
            SyscallRequest::Lseek { fd, offset, whence } => {
                use litebox::utils::TruncateExt as _;
                syscalls::file::try_into_whence(whence.truncate())
                    .map_err(|_| Errno::EINVAL)
                    .and_then(|seekwhence| self.sys_lseek(fd, offset, seekwhence))
            }
            SyscallRequest::Mkdir { pathname, mode } => pathname
                .to_cstring()
                .map_or(Err(Errno::EINVAL), |path| syscall!(sys_mkdir(path, mode))),
            SyscallRequest::Mkdirat {
                dirfd,
                pathname,
                mode,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscall!(sys_mkdirat(dirfd, path, mode))
            }),
            SyscallRequest::Chdir { pathname } => pathname
                .to_cstring()
                .map_or(Err(Errno::EINVAL), |path| syscall!(sys_chdir(path))),
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
            #[cfg(target_arch = "x86")]
            SyscallRequest::Sigreturn => self.sys_sigreturn(ctx),
            SyscallRequest::Ioctl { fd, arg } => {
                syscall!(sys_ioctl(fd, arg))
            }
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
            } => match buf.to_owned_slice(count) {
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
            SyscallRequest::Msync {
                addr,
                length,
                flags,
            } => {
                syscall!(sys_msync(addr, length, flags))
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
            SyscallRequest::Writev { fd, iovec, iovcnt } => {
                if let Some(iovs) = iovec.to_owned_slice(iovcnt) {
                    self.maybe_trace_shell_writev(Some(ctx), fd, &iovs);
                }
                self.sys_writev(fd, iovec, iovcnt)
            }
            SyscallRequest::Access { pathname, mode } => pathname
                .to_cstring()
                .map_or(Err(Errno::EFAULT), |path| syscall!(sys_access(path, mode))),
            SyscallRequest::Faccessat {
                dirfd,
                pathname,
                mode,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscall!(sys_faccessat(
                    dirfd,
                    path,
                    mode,
                    litebox_common_linux::AtFlags::empty()
                ))
            }),
            SyscallRequest::Faccessat2 {
                dirfd,
                pathname,
                mode,
                flags,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
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
            } => {
                syscall!(sys_dup(oldfd, newfd, flags))
            }
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
            } => {
                syscall!(sys_connect(sockfd, sockaddr, addrlen))
            }
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
            SyscallRequest::Bind {
                sockfd,
                sockaddr,
                addrlen,
            } => syscall!(sys_bind(sockfd, sockaddr, addrlen)),
            SyscallRequest::Listen { sockfd, backlog } => {
                syscall!(sys_listen(sockfd, backlog))
            }
            SyscallRequest::Shutdown { sockfd, how } => {
                syscall!(sys_shutdown(sockfd, how))
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
            } => self
                .sys_getsockopt(sockfd, level, optname, optval, optlen)
                .to_syscall_result(),
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
            SyscallRequest::Fcntl { fd, arg } => {
                syscall!(sys_fcntl(fd, arg))
            }
            SyscallRequest::Getcwd { buf, size: count } => {
                let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
                self.sys_getcwd(&mut kernel_buf).and_then(|size| {
                    self.park_if_deferred();
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
            } => self.sys_epoll_ctl(epfd, op, fd, event).to_syscall_result(),
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
                    self.park_if_deferred();
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
                        self.park_if_deferred();
                        buf.copy_from_slice(0, &kernel_buf[..size])
                            .map(|()| size)
                            .ok_or(Errno::EFAULT)
                    })
            }),
            SyscallRequest::Gettimeofday { tv, tz } => syscall!(sys_gettimeofday(tv, tz)),
            SyscallRequest::Getrusage { who, usage } => syscall!(sys_getrusage(who, usage)),
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
            SyscallRequest::Renameat2 {
                olddirfd,
                oldpath,
                newdirfd,
                newpath,
                flags,
            } => {
                let old = oldpath.to_cstring().ok_or(Errno::EFAULT)?;
                let new = newpath.to_cstring().ok_or(Errno::EFAULT)?;
                syscall!(sys_renameat2(olddirfd, old, newdirfd, new, flags))
            }
            SyscallRequest::Symlinkat {
                target,
                newdirfd,
                linkpath,
            } => {
                let target = target.to_cstring().ok_or(Errno::EFAULT)?;
                let linkpath = linkpath.to_cstring().ok_or(Errno::EFAULT)?;
                syscall!(sys_symlinkat(target, newdirfd, linkpath))
            }
            SyscallRequest::Linkat {
                olddirfd,
                oldpath,
                newdirfd,
                newpath,
                flags,
            } => {
                let old = oldpath.to_cstring().ok_or(Errno::EFAULT)?;
                let new = newpath.to_cstring().ok_or(Errno::EFAULT)?;
                syscall!(sys_linkat(olddirfd, old, newdirfd, new, flags))
            }
            SyscallRequest::Fchmod { fd: _, mode: _ }
            | SyscallRequest::Fchown
            | SyscallRequest::Fchownat => {
                // Silently succeed; sandbox runs as a single user.
                Ok(0)
            }
            SyscallRequest::Fsync { fd: _ }
            | SyscallRequest::Fdatasync { fd: _ }
            | SyscallRequest::Utimensat
            | SyscallRequest::Seccomp => {
                // No-op: in-memory FS doesn't need fsync/timestamps, and
                // seccomp filter installation is handled by the sandbox.
                Ok(0)
            }
            SyscallRequest::Fadvise64 { fd, .. } => {
                // No-op: file access advice is optional and safe to ignore.
                self.validate_fd(fd)?;
                Ok(0)
            }
            SyscallRequest::Sendfile {
                out_fd,
                in_fd,
                offset,
                count,
            } => self.sys_sendfile(out_fd, in_fd, offset, count),
            SyscallRequest::CopyFileRange {
                fd_in,
                off_in,
                fd_out,
                off_out,
                len,
                flags,
            } => self.sys_copy_file_range(fd_in, off_in, fd_out, off_out, len, flags),
            SyscallRequest::Flock { fd, .. } => {
                // No-op: single-process sandbox has no contention.
                self.validate_fd(fd)?;
                Ok(0)
            }
            SyscallRequest::Fallocate { fd, .. } => {
                // No-op: in-memory FS doesn't need preallocation.
                self.validate_fd(fd)?;
                Ok(0)
            }
            SyscallRequest::XattrGetPath {
                pathname,
                name,
                follow_symlinks,
            } => {
                let path = pathname.to_cstring().ok_or(Errno::EFAULT)?;
                self.validate_path_follow(path, follow_symlinks)?;
                name.to_cstring().ok_or(Errno::EFAULT)?;
                Err(Errno::ENODATA)
            }
            SyscallRequest::XattrSetPath {
                pathname,
                name,
                value,
                size,
                flags,
                follow_symlinks,
            } => {
                // XATTR_CREATE=1, XATTR_REPLACE=2; any other bits → EINVAL.
                if flags & !0x3 != 0 {
                    return Err(Errno::EINVAL);
                }
                let path = pathname.to_cstring().ok_or(Errno::EFAULT)?;
                self.validate_path_follow(path, follow_symlinks)?;
                name.to_cstring().ok_or(Errno::EFAULT)?;
                if size > 0 {
                    value.read_at_offset(0).ok_or(Errno::EFAULT)?;
                }
                Err(Errno::EOPNOTSUPP)
            }
            SyscallRequest::XattrListPath {
                pathname,
                follow_symlinks,
            } => {
                let path = pathname.to_cstring().ok_or(Errno::EFAULT)?;
                self.validate_path_follow(path, follow_symlinks)?;
                Ok(0)
            }
            SyscallRequest::XattrGetFd { fd, name } => {
                self.validate_fd(fd)?;
                name.to_cstring().ok_or(Errno::EFAULT)?;
                Err(Errno::ENODATA)
            }
            SyscallRequest::XattrSetFd {
                fd,
                name,
                value,
                size,
                flags,
            } => {
                if flags & !0x3 != 0 {
                    return Err(Errno::EINVAL);
                }
                self.validate_fd(fd)?;
                name.to_cstring().ok_or(Errno::EFAULT)?;
                if size > 0 {
                    value.read_at_offset(0).ok_or(Errno::EFAULT)?;
                }
                Err(Errno::EOPNOTSUPP)
            }
            SyscallRequest::XattrListFd { fd } => {
                self.validate_fd(fd)?;
                Ok(0)
            }
            SyscallRequest::Fchmodat {
                dirfd,
                pathname,
                mode,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscall!(sys_fchmodat(dirfd, path, mode))
            }),
            SyscallRequest::Stat { pathname, buf } => {
                pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                    self.sys_stat(path).and_then(|stat| {
                        self.park_if_deferred();
                        buf.write_at_offset(0, stat)
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                })
            }
            SyscallRequest::Lstat { pathname, buf } => {
                pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                    self.sys_lstat(path).and_then(|stat| {
                        self.park_if_deferred();
                        buf.write_at_offset(0, stat)
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                })
            }
            SyscallRequest::Fstat { fd, buf } => self.sys_fstat(fd).and_then(|stat| {
                self.park_if_deferred();
                buf.write_at_offset(0, stat)
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
                    self.park_if_deferred();
                    buf.write_at_offset(0, stat)
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
                    self.park_if_deferred();
                    buf.write_at_offset(0, stat.into())
                        .ok_or(Errno::EFAULT)
                        .map(|()| 0)
                })
            }),
            SyscallRequest::Statx {
                dirfd,
                pathname,
                flags,
                mask,
                buf,
            } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                self.sys_statx(dirfd, path, flags, mask).and_then(|statx| {
                    self.park_if_deferred();
                    buf.write_at_offset(0, statx)
                        .ok_or(Errno::EFAULT)
                        .map(|()| 0)
                })
            }),
            SyscallRequest::Statfs { pathname, buf } => {
                pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                    self.sys_statfs(path)
                        .and_then(|s| buf.write_at_offset(0, s).ok_or(Errno::EFAULT).map(|()| 0))
                })
            }
            SyscallRequest::Fstatfs { fd, buf } => self
                .sys_fstatfs(fd)
                .and_then(|s| buf.write_at_offset(0, s).ok_or(Errno::EFAULT).map(|()| 0)),
            SyscallRequest::Eventfd2 { initval, flags } => {
                syscall!(sys_eventfd2(initval, flags))
            }
            SyscallRequest::Signalfd4 {
                fd,
                mask,
                sizemask,
                flags,
            } => {
                syscall!(sys_signalfd4(fd, mask, sizemask, flags))
            }
            SyscallRequest::MemfdCreate { name, flags } => {
                name.to_cstring().map_or(Err(Errno::EFAULT), |name| {
                    syscall!(sys_memfd_create(name, flags))
                })
            }
            SyscallRequest::InotifyInit1 { flags } => syscall!(sys_inotify_init1(flags)),
            SyscallRequest::InotifyAddWatch { fd, pathname, mask } => {
                pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_inotify_add_watch(fd, path, mask))
                })
            }
            SyscallRequest::InotifyRmWatch { fd, wd } => syscall!(sys_inotify_rm_watch(fd, wd)),
            SyscallRequest::TimerfdCreate { clockid, flags } => {
                litebox_common_linux::ClockId::try_from(clockid)
                    .map_err(|_| Errno::EINVAL)
                    .and_then(|clockid| syscall!(sys_timerfd_create(clockid, flags)))
            }
            SyscallRequest::TimerfdSettime {
                fd,
                flags,
                new_value,
                old_value,
            } => new_value
                .read_at_offset(0)
                .ok_or(Errno::EFAULT)
                .and_then(|new_value| self.sys_timerfd_settime(fd, flags, new_value, old_value))
                .map(|()| 0),
            SyscallRequest::TimerfdGettime { fd, curr_value } => {
                self.sys_timerfd_gettime(fd).and_then(|curr_value_value| {
                    curr_value
                        .write_at_offset(0, curr_value_value)
                        .ok_or(Errno::EFAULT)
                        .map(|()| 0)
                })
            }
            SyscallRequest::Pipe2 { pipefd, flags } => {
                self.sys_pipe2(flags).and_then(|(read_fd, write_fd)| {
                    self.prepare_guest_write(pipefd, 2)?;
                    pipefd.write_at_offset(0, read_fd).ok_or(Errno::EFAULT)?;
                    pipefd.write_at_offset(1, write_fd).ok_or(Errno::EFAULT)?;
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
                    user_desc
                        .read_at_offset(0)
                        .ok_or(Errno::EFAULT)
                        .and_then(|mut desc| {
                            let idx = desc.entry_number;
                            self.set_thread_area(&mut desc)?;
                            if idx == u32::MAX {
                                // index -1 means the kernel should try to find and
                                // allocate an empty descriptor.
                                // return the allocated entry number
                                user_desc.write_at_offset(0, desc).ok_or(Errno::EFAULT)?;
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
                    self.prepare_guest_write(len, 1)?;
                    len.write_at_offset(0, size_of::<litebox_common_linux::RobustListHead>())
                        .ok_or(Errno::EFAULT)
                })
                .map(|()| 0),
            SyscallRequest::Rseq {
                rseq,
                rseq_len,
                flags,
                sig,
            } => syscall!(sys_rseq(rseq, rseq_len, flags, sig)),
            SyscallRequest::GetRandom { buf, count, flags } => {
                self.sys_getrandom(buf, count, flags)
            }
            SyscallRequest::Getpid => Ok(self.sys_getpid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getppid => Ok(self.sys_getppid().reinterpret_as_unsigned() as usize),
            SyscallRequest::ProcessVmReadv {
                pid,
                local_iov,
                liovcnt,
                remote_iov,
                riovcnt,
                flags,
            } => self.sys_process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags),
            SyscallRequest::Getpgid { pid } => self.sys_getpgid(pid).map(|v| v as usize),
            SyscallRequest::Setpgid { pid, pgid } => self.sys_setpgid(pid, pgid).map(|()| 0),
            SyscallRequest::Getsid { pid } => self.sys_getsid(pid).map(|v| v as usize),
            SyscallRequest::Setsid => self.sys_setsid().map(|v| v as usize),
            SyscallRequest::Getuid => Ok(self.sys_getuid() as usize),
            SyscallRequest::Getgid => Ok(self.sys_getgid() as usize),
            SyscallRequest::Geteuid => Ok(self.sys_geteuid() as usize),
            SyscallRequest::Getegid => Ok(self.sys_getegid() as usize),
            SyscallRequest::Getgroups { size, list } => self.sys_getgroups(size, list),
            SyscallRequest::Sysinfo { buf } => {
                let sysinfo = self.sys_sysinfo();
                buf.write_at_offset(0, sysinfo)
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
                // Yield the host thread so other host threads (including the
                // network worker) get a chance to run.
                // SAFETY: sched_yield is side-effect free.
                unsafe { ::syscalls::raw::syscall0(::syscalls::Sysno::sched_yield) };
                Ok(0)
            }
            SyscallRequest::SchedGetparam { pid: _, param } => {
                // Write sched_priority = 0 (SCHED_OTHER default).
                param.write_at_offset(0, 0i32).ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            SyscallRequest::SchedGetscheduler { pid: _ } => {
                // Return SCHED_OTHER (0) — the default Linux scheduler policy.
                Ok(0)
            }
            SyscallRequest::SchedSetscheduler { pid, policy, param } => {
                self.sys_sched_setscheduler(pid, policy, param)
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
            SyscallRequest::Alarm { seconds } => syscall!(sys_alarm(seconds)),
            SyscallRequest::TimerCreate {
                clockid,
                sevp,
                timerid,
            } => self.sys_timer_create(clockid, sevp, timerid),
            SyscallRequest::TimerSettime {
                timerid,
                flags,
                new_value,
                old_value,
            } => self.sys_timer_settime(timerid, flags, new_value, old_value),
            SyscallRequest::TimerGettime {
                timerid,
                curr_value,
            } => self.sys_timer_gettime(timerid, curr_value),
            SyscallRequest::TimerDelete { timerid } => self.sys_timer_delete(timerid),
            SyscallRequest::TimerGetoverrun { timerid } => self.sys_timer_getoverrun(timerid),
            SyscallRequest::RtSigsuspend { mask, sigsetsize } => {
                self.sys_rt_sigsuspend(mask, sigsetsize, ctx)
            }
            SyscallRequest::RtSigtimedwait {
                set,
                info,
                timeout,
                sigsetsize,
            } => self.sys_rt_sigtimedwait(set, info, timeout, sigsetsize),
            SyscallRequest::Sigpending { set, sigsetsize } => {
                self.sys_rt_sigpending(set, sigsetsize)
            }
            _ => {
                log_unsupported!("{request:?}");
                Err(Errno::ENOSYS)
            }
        };

        #[cfg(feature = "audit_log")]
        if audit::is_enabled() {
            let result_val = match &result {
                Ok(v) => Ok(*v),
                Err(e) => Err(e.as_neg()),
            };
            audit::emit_exit_event(
                audit_syscall_name,
                audit_seq,
                self.pid,
                self.tid,
                result_val,
            );
        }

        result
    }
}

/// Global shim state, shared across all tasks.
struct GlobalState<FS: ShimFS> {
    /// The platform instance used throughout the shim.
    platform: &'static Platform,
    /// The LiteBox instance used throughout the shim.
    litebox: litebox::LiteBox<Platform>,
    /// The futex manager for handling futex operations.
    futex_manager: FutexManager<Platform>,
    /// The optional worker-local network subsystem.
    #[cfg(feature = "worker_local_inet")]
    net: LocalNetwork,
    /// The time when the shim was started.
    boot_time: <Platform as TimeProvider>::Instant,
    /// Optional load filter function to modify environment variables during program loading.
    load_filter: Option<LoadFilter>,
    /// Next thread ID to assign.
    // TODO: better management of thread IDs
    next_thread_id: core::sync::atomic::AtomicI32,
    /// UNIX domain socket address table
    unix_addr_table: litebox::sync::RwLock<Platform, syscalls::unix::UnixAddrTable<FS>>,
    /// Local-host cross-process signal queue for delivering signals (e.g.
    /// SIGCHLD) between processes owned by this host. Entries are consumed by
    /// the target task during signal processing.
    cross_process_signals: litebox::sync::Mutex<Platform, Vec<CrossProcessSignal>>,
    /// PR-3 single-worker-pgrp scope: pgids this worker has subscribed to using
    /// its local ProcessRegistry view. Cross-worker setpgid reconciliation is PR-4.
    pgrp_signal_subscriptions: litebox::sync::Mutex<Platform, BTreeMap<u32, u64>>,
    /// Best-effort local thread handles used to interrupt a process when
    /// delivering a queued local cross-process signal.
    process_thread_handles: litebox::sync::RwLock<
        Platform,
        alloc::collections::BTreeMap<i32, alloc::sync::Arc<syscalls::process::ThreadRemote>>,
    >,
    /// Foreground process group for the shared host tty backing stdio and
    /// `/dev/tty`.
    host_tty_foreground_pgrp: litebox::sync::Mutex<Platform, litebox::process::ProcessGroupId>,
    /// Shadow terminal attributes for non-init processes. When a child calls
    /// TCSETS on host stdio, the real terminal is not changed but the shadow
    /// is updated so subsequent TCGETS returns the values the child expects.
    /// The init process bypasses this and modifies the real terminal directly.
    host_tty_shadow_termios:
        litebox::sync::Mutex<Platform, Option<litebox::platform::TerminalAttributes>>,
    /// Ensures only one task thread drains the local control-plane queue at a time.
    local_control_plane_pump_active: core::sync::atomic::AtomicBool,
    /// Flag set during vfork to break transport spin-loops and propagate EINTR.
    transport_interrupt: alloc::sync::Arc<core::sync::atomic::AtomicBool>,
    /// Serializes nested epoll graph updates so validation and insertion see
    /// one consistent graph.
    epoll_graph_lock: litebox::sync::Mutex<Platform, ()>,
    /// Root-host coordinator state for the future multi-host exec handoff path.
    control_plane: multihost::ControlPlane<Platform>,
    /// Mapping from guest ProcessId.0 → remote worker host OS PID.
    /// Used to forward signals to fork-restore and remote-exec workers.
    fork_child_host_pids: litebox::sync::RwLock<Platform, alloc::collections::BTreeMap<u32, i32>>,
    /// Signalfds inherited by a remote-exec worker, keyed by guest ProcessId.0.
    remote_signalfd_targets:
        litebox::sync::RwLock<Platform, alloc::collections::BTreeMap<u32, RemoteSignalfdTarget>>,
    /// Synthetic `/proc/<pid>/cmdline` contents for locally-known guest PIDs.
    proc_cmdlines: litebox::sync::RwLock<Platform, alloc::collections::BTreeMap<i32, Vec<u8>>>,
    /// Open inotify instances visible to all tasks on this shim host.
    inotify_instances: litebox::sync::Mutex<
        Platform,
        Vec<alloc::sync::Arc<litebox::sync::Mutex<Platform, syscalls::file::InotifyInstanceState>>>,
    >,
}

#[derive(Clone)]
struct RemoteSignalfdTarget {
    blocked_mask: u64,
    signalfds: Vec<RemoteSignalfdEntry>,
}

#[derive(Clone)]
struct RemoteSignalfdEntry {
    handle_id: u64,
    mask_bits: u64,
}

struct PgrpSignalCallback<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
}

impl<FS: ShimFS> litebox_common_linux::broker_pgrp_signal_provider::BrokerPgrpSignalCallback
    for PgrpSignalCallback<FS>
{
    fn on_signal(&self, pgid: i32, signum: i32, _siginfo: &[u8]) {
        let Ok(signal) = litebox_common_linux::signal::Signal::try_from(signum) else {
            return;
        };
        let _ = self.global.deliver_signal_to_process_group(pgid, signal);
    }
}

impl<FS: ShimFS> GlobalState<FS> {
    fn ensure_pgrp_signal_subscription(self: &Arc<Self>, pgid: u32) {
        let Some(provider) = syscalls::eventfd::broker_pgrp_signal_provider() else {
            return;
        };
        {
            let subscriptions = self.pgrp_signal_subscriptions.lock();
            if subscriptions.contains_key(&pgid) {
                return;
            }
        }
        let signal_mask = (1u32 << litebox_common_linux::signal::Signal::SIGWINCH.as_i32())
            | (1u32 << litebox_common_linux::signal::Signal::SIGINT.as_i32())
            | (1u32 << litebox_common_linux::signal::Signal::SIGQUIT.as_i32())
            | (1u32 << litebox_common_linux::signal::Signal::SIGTSTP.as_i32());
        let callback = Arc::new(PgrpSignalCallback {
            global: Arc::clone(self),
        });
        match provider.subscribe_pgrp_signal(pgid, signal_mask, callback) {
            Ok(subscription_id) => {
                self.pgrp_signal_subscriptions
                    .lock()
                    .insert(pgid, subscription_id);
            }
            Err(err) => litebox::log_println!(
                self.platform,
                "{}",
                format_args!("pgrp signal subscribe failed pgid={pgid}: {err:?}")
            ),
        }
    }

    fn cleanup_pgrp_signal_subscription_if_empty(self: &Arc<Self>, pgid: u32) {
        if !self
            .litebox
            .process_registry()
            .process_ids_in_group(litebox::process::ProcessGroupId(pgid))
            .is_empty()
        {
            return;
        }
        let Some(subscription_id) = self.pgrp_signal_subscriptions.lock().remove(&pgid) else {
            return;
        };
        if let Some(provider) = syscalls::eventfd::broker_pgrp_signal_provider() {
            provider.unsubscribe_pgrp_signal(pgid, subscription_id);
        }
    }

    fn deliver_signal_to_process_group(
        &self,
        pgrp: i32,
        signal: litebox_common_linux::signal::Signal,
    ) -> Result<(), Errno> {
        if pgrp <= 0 {
            return Ok(());
        }
        let pgid =
            litebox::process::ProcessGroupId(u32::try_from(pgrp).map_err(|_| Errno::EINVAL)?);
        let targets = self.litebox.process_registry().process_ids_in_group(pgid);
        let mut queue = self.cross_process_signals.lock();
        for target in &targets {
            queue.push(CrossProcessSignal {
                target_process_id: target.0,
                target_tid: None,
                signal,
                siginfo: syscalls::signal::siginfo_kernel(signal),
            });
        }
        drop(queue);

        let handles = self.process_thread_handles.read();
        for target in targets {
            let key = target.0.cast_signed();
            if let Some(remote) = handles.get(&key) {
                remote.interrupt();
            }
        }
        Ok(())
    }

    fn set_proc_cmdline(&self, pid: i32, cmdline: Vec<u8>) {
        self.proc_cmdlines.write().insert(pid, cmdline);
    }

    fn proc_cmdline(&self, pid: i32) -> Option<Vec<u8>> {
        self.proc_cmdlines.read().get(&pid).cloned()
    }

    fn remove_proc_cmdline(&self, pid: i32) {
        self.proc_cmdlines.write().remove(&pid);
    }

    /// Keeps the global thread allocator above a thread ID that was assigned
    /// outside `next_thread_id` (for example, when bootstrapping a process in a
    /// new host process).
    fn reserve_thread_id(&self, tid: i32) {
        let _ = self
            .next_thread_id
            .fetch_max(tid.saturating_add(1), Ordering::Relaxed);
    }
}

/// A signal that needs to be delivered to a different process.
struct CrossProcessSignal {
    /// The target process's internal ID (ProcessId).
    target_process_id: u32,
    /// Optional target thread ID for thread-directed signals (e.g. `tgkill`).
    /// When `None`, the signal is process-directed and goes to `shared_pending`.
    target_tid: Option<i32>,
    /// The signal to deliver.
    signal: litebox_common_linux::signal::Signal,
    /// The siginfo data.
    siginfo: litebox_common_linux::signal::Siginfo,
}

/// Per-process state shared by all threads in a process.
///
/// Each process has its own `ProcessState` (wrapped in `Arc` so threads of the
/// same process share it). When multi-process support is complete, forking
/// will create a new `ProcessState` with a per-process `PageManager`
/// initialized to the child's VA sub-range.
struct ProcessState {
    /// The page manager for managing this process's virtual memory.
    pm: litebox::mm::PageManager<Platform, { PAGE_SIZE }>,
    /// The address space ID for this process (VA partition on userland).
    address_space_id: <Platform as litebox::platform::AddressSpaceProvider>::AddressSpaceId,
    /// Number of active threads in this process (including the main thread).
    /// Starts at 1 and is incremented on each `clone(CLONE_THREAD)`.
    thread_count: core::sync::atomic::AtomicI32,
    /// PTY index installed as this process's controlling terminal by TIOCSCTTY.
    controlling_pty: litebox::sync::Mutex<Platform, Option<u32>>,
    /// Active shared-vfork CoW layers, with the newest layer at the end.
    /// The forking thread pushes a new layer before spawning the child and
    /// pops it after restoring state once that child execs or exits.
    active_vfork_layers: litebox::sync::Mutex<Platform, Vec<Arc<CowState>>>,
    /// Per-fd ELF patching state for the runtime syscall rewriter.
    elf_patch_cache: litebox::sync::Mutex<Platform, syscalls::mm::ElfPatchCache>,
    /// Tracks `MAP_SHARED|PROT_WRITE` file-backed mappings for writeback on
    /// `munmap`. See [`syscalls::mm::SharedFileMapping`] for details.
    shared_file_mappings: litebox::sync::Mutex<Platform, syscalls::mm::SharedFileMappings>,
    /// Page-aligned start of the main binary's `.bss` region (zero-filled
    /// portion of the writable PT_LOAD segment). Set once during ELF loading.
    main_bss_start: core::sync::atomic::AtomicUsize,
    /// Page-aligned end of the main binary's `.bss` region. Set once during
    /// ELF loading.
    main_bss_end: core::sync::atomic::AtomicUsize,
    /// Best-effort pathname annotations for guest `/proc/self/maps`.
    proc_map_paths: litebox::sync::Mutex<
        Platform,
        alloc::vec::Vec<(core::ops::Range<usize>, alloc::string::String)>,
    >,
    /// Shared vfork parking state, wrapped in `Arc` so that both the
    /// syscall-boundary parking path (`park_for_vfork_if_requested`) and the
    /// transport spin-loop parking path (`ShimTransport::park_for_vfork`) can
    /// operate on the same underlying atomics.
    vfork_parking: Arc<VforkParking>,
}

/// Shared vfork parking primitives.
///
/// This struct is `Arc`-shared between the per-process `ProcessState` and the
/// `ShimTransport` so that threads spinning inside the 9P transport can park
/// in-place during vfork without corrupting the TCP byte stream.
pub(crate) struct VforkParking {
    /// Futex for parking threads during vfork. The underlying atomic stores:
    /// 0 = normal operation, 1 = park requested by the forking thread.
    /// Other threads check this in `prepare_to_run_guest` and block until
    /// the value returns to 0.
    pub park: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    /// Counter of threads that have parked. The forking thread waits on this
    /// until the count reaches `thread_count - 1`, confirming all other
    /// threads are safely stopped before modifying page permissions.
    pub parked_count: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    /// Number of outstanding "deferred lies" — transport spin loops that have
    /// incremented `parked_count` without actually blocking. Each lie must be
    /// claimed by a task via `park_if_deferred()` before it writes to guest
    /// memory, or at the syscall boundary as a fallback.
    pub deferred_lie_count: core::sync::atomic::AtomicU32,
}

/// Which virtual subsystem the replaced fd belonged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplacedSubsystem {
    UnixSocket,
    Pty,
    Filesystem,
}

/// Describes a single fd endpoint that should be replaced with a host OS
/// pipe after the delayed-fork child has been migrated.
///
/// Used by the exec-on-remote-host path.
#[derive(Debug, Clone)]
struct FdReplacement {
    /// The guest FD number to replace.
    guest_fd: usize,
    /// The raw host OS file descriptor for the parent's end of the pipe.
    host_fd: i32,
    /// Whether this endpoint is a read or write end.
    direction: syscalls::host_passthrough_fd::HostPassthroughFdDirection,
    /// The virtual subsystem that owned the original fd.
    #[allow(dead_code)] // Useful for debug logging; may drive close logic in future.
    subsystem: ReplacedSubsystem,
}

#[derive(Debug, Clone)]
struct BrokerSocketPairParentInstall {
    guest_fd: usize,
    handle_id: u64,
    endpoint: litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint,
    dup_before_install: bool,
}

struct VforkDone {
    done: core::sync::atomic::AtomicBool,
    completion: core::sync::atomic::AtomicU8,
    /// Waker for the parent thread — calling `wake()` causes the parent's
    /// `wait_until` loop to re-evaluate the done flag.
    parent_waker: litebox::event::wait::Waker<Platform>,
    /// FD replacements the parent should apply after VforkDone is signaled.
    /// Filled by `commit_delayed_fork` (exec path), consumed by `do_fork` after resume.
    fd_replacements: litebox::sync::Mutex<Platform, Vec<FdReplacement>>,
    /// Broker socketpair endpoints that should replace parent-side UnixSocket
    /// peers after a fork-restore child migrates the other endpoint.
    broker_socketpair_parent_installs:
        litebox::sync::Mutex<Platform, Vec<BrokerSocketPairParentInstall>>,
}

impl VforkDone {
    fn new(parent_waker: litebox::event::wait::Waker<Platform>) -> Self {
        Self {
            done: core::sync::atomic::AtomicBool::new(false),
            completion: core::sync::atomic::AtomicU8::new(0),
            parent_waker,
            fd_replacements: litebox::sync::Mutex::new(Vec::new()),
            broker_socketpair_parent_installs: litebox::sync::Mutex::new(Vec::new()),
        }
    }

    fn signal_with_completion(&self, completion: u8) {
        self.completion.store(completion, Ordering::Release);
        self.done.store(true, Ordering::Release);
        self.parent_waker.wake();
    }

    /// Called when the child exits before exec/handoff.
    fn signal_exit(&self) {
        self.signal_with_completion(1);
    }

    /// Called when the child execs or is handed off to a remote worker.
    fn signal(&self) {
        self.signal_with_completion(2);
    }

    fn was_signaled_by_exit(&self) -> bool {
        self.completion.load(Ordering::Acquire) == 1
    }

    /// Returns `true` once the child has called [`signal`](Self::signal).
    fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }
}

/// Copy-on-write state for vfork memory protection.
///
/// Created by the forking thread and stored in both `ProcessState` (for
/// fault-handler access by any thread) and `ForkContext` (for the child).
///
/// All other parent threads are parked during the vfork window, so FULL CoW
/// (all writable pages) is always used regardless of thread count.
///
/// **Eager vs lazy** (platform decision): Controls how pages are snapshotted.
/// - Eager: all protected pages copied upfront, left writable.
/// - Lazy: protected pages marked read-only, snapshotted on first fault.
struct CowState {
    /// Pages that were CoW-protected (base address, length, original permissions).
    /// For lazy CoW these were made read-only; for eager CoW they were copied.
    protected_ranges: Vec<(
        usize,
        usize,
        litebox::platform::page_mgmt::MemoryRegionPermissions,
    )>,
    /// Per-page snapshots taken on first write for this layer, keyed by
    /// page-aligned address.
    dirty_pages: litebox::sync::Mutex<Platform, BTreeMap<usize, Vec<u8>>>,
}

/// Call `update_permissions` with the correct `PAGE_SIZE` const generic.
/// Returns `true` on success, `false` on failure (so the fault is not
/// considered handled and will escalate to process termination).
///
/// # Safety
///
/// The caller must ensure the memory range is valid and the permissions
/// are appropriate for the mapped pages.
unsafe fn cow_update_permissions(
    platform: &Platform,
    range: core::ops::Range<usize>,
    perms: litebox::platform::page_mgmt::MemoryRegionPermissions,
) -> bool {
    use litebox::platform::PageManagementProvider;
    unsafe {
        <Platform as PageManagementProvider<PAGE_SIZE>>::update_permissions(platform, range, perms)
    }
    .is_ok()
}

/// Context for a vfork child process.
///
/// Stored in the child's `Task` after `do_fork`. The child temporarily uses
/// the **parent's** `ProcessState` (vfork sharing). When the child calls
/// `execve()`, it creates its own `ProcessState` using the partition range
/// from `address_space_id`. When it calls `_exit()`, the partition is released.
struct ForkContext {
    /// The child's own address space ID (VA partition on userland).
    address_space_id: <Platform as litebox::platform::AddressSpaceProvider>::AddressSpaceId,
    /// Signals the parent to resume after the vfork child execs or exits.
    vfork_done: Arc<VforkDone>,
    /// The exit signal from the fork/clone args (usually SIGCHLD).
    /// Stored here so that `commit_delayed_fork` can include it in the snapshot.
    exit_signal: i32,
    /// The parent's ProcessId in the process registry.
    /// Needed by `commit_delayed_fork` for the snapshot's parent identity.
    parent_process_id: litebox::process::ProcessId,
    /// Parent controlling PTY before the vfork child borrowed ProcessState.
    parent_controlling_pty: Option<u32>,
    /// Snapshot of the parent's Unix socket FDs at fork time:
    /// (guest_fd, socket_pair_id, object_id).
    /// Used by `commit_delayed_fork` to find the parent's peer socket endpoints
    /// so both sides can be bridged with real OS pipes.
    parent_unix_socket_fds: Vec<(usize, usize, u64)>,
    /// Broker PTY raw fds that belonged to the parent at fork time. A vfork child
    /// closing one of these must not invalidate the parent's descriptor slot.
    pub(crate) parent_broker_pty_fds: Vec<usize>,
    /// True if the parent is itself a delayed-fork child (nested vfork).
    /// When true, `commit_delayed_fork` must not replace the parent's
    /// pipe fds because the parent shares the grandparent's fd table.
    parent_is_delayed_fork: bool,
    /// Phase 2.F: rollback list of broker handles dup'd during
    /// fork-snapshot capture. Each entry represents a transit ref
    /// held in the snapshot for the child to consume. On success
    /// path the child's restore-side BrokerBacked adopts that ref
    /// (entries dropped on `commit_delayed_fork` success). On
    /// failure path we drain this list and call `release` on each
    /// to undo the dup so the broker refcount returns to baseline.
    fork_snapshot_broker_transit: Vec<crate::syscalls::fork_snapshot::ForkSnapshotBrokerTransit>,
    /// Process-exit subscriptions that keep pidfd target ProcessState entries
    /// alive until a restored child can install its own inherited-pidfd wake.
    fork_snapshot_pidfd_process_transit: Vec<crate::syscalls::guest_pid::BrokerProcessExitWake>,
    /// Rollback list for host-fd tokens registered for fork-restore.
    fork_snapshot_fd_token_transit: Vec<crate::syscalls::fork_snapshot::ForkSnapshotFdTokenTransit>,
}

const SHELL_WRITE_SCAN_LEN: usize = 1024;
const SHELL_WRITE_PREVIEW_LEN: usize = 192;

#[derive(Clone)]
struct RecentShellWrite {
    fd: i32,
    via: &'static str,
    total_len: usize,
    target: alloc::string::String,
    preview: alloc::string::String,
    syscall_rip: usize,
    syscall_rsp: usize,
}

#[derive(Clone, Copy)]
struct RecentSyscall {
    number: usize,
    entry_rip: usize,
    entry_rsp: usize,
    #[allow(dead_code)]
    entry_rbp: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
}

struct Task<FS: ShimFS> {
    global: Arc<GlobalState<FS>>,
    /// Per-process state shared across threads in the same process.
    /// `RefCell` to support swapping to the child's own state on `execve`
    /// after a vfork.
    process_state: RefCell<Arc<ProcessState>>,
    wait_state: wait::WaitState,
    thread: syscalls::process::ThreadState,
    /// The process identity from the core ProcessRegistry.
    process_id: litebox::process::ProcessId,
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
    files: RefCell<Arc<syscalls::file::FilesState<FS>>>,
    /// Signal state
    signals: syscalls::signal::SignalState,
    /// Fork context for vfork children. `None` for the initial process and
    /// for threads. Set when `do_fork` creates a child process. `RefCell`
    /// because `sys_execve` consumes it via `take()` through `&self`.
    fork_context: RefCell<Option<ForkContext>>,
    /// Last traced shell write performed by this task, if any.
    last_shell_write: RefCell<Option<RecentShellWrite>>,
    /// Last syscall entry observed for this task.
    last_syscall: Cell<Option<RecentSyscall>>,
    /// Set when a blocking syscall returns `EINTR` due to a pending signal.
    /// Cleared after `process_signals` handles restart or delivers a handler.
    /// Mirrors the Linux kernel's `-ERESTARTSYS` internal error code.
    syscall_restartable: Cell<bool>,
    /// True when the current entry came through `handle_syscall_request`
    /// (ctx.r11 holds the call-site scratch address, not the real guest R11).
    /// False when the entry came from an async interrupt/exception (ctx.r11
    /// is the real architectural R11). Used by signal frame construction to
    /// decide whether to expose RFLAGS or the actual r11 in mcontext.
    in_syscall: Cell<bool>,
    /// Set by `park_if_deferred()` when this task has claimed a deferred lie
    /// from the transport and is now blocking at a park checkpoint. Cleared
    /// when the task resumes after vfork completes. `Cell` because the task
    /// owns this flag exclusively (no cross-thread sharing).
    deferred_vfork_park: Cell<bool>,
    /// When true, this task is a fork child running in vfork-style mode that
    /// should be upgraded to a true fork when it makes a non-pre-exec syscall.
    /// Set by `do_fork` for `is_shared && !is_vfork` children.  Cleared by
    /// `commit_delayed_fork` (on success) or the exit path (on failure).
    ///
    /// Distinct from `deferred_vfork_park`, which handles sibling-thread
    /// parking coordination.
    delayed_fork_pending: Cell<bool>,
    /// Set when this parent task has just resumed from a delayed fork.  Used to
    /// emulate the non-blocking empty-pipe observation that the shared-address
    /// fork path can otherwise skip while the child runs to completion.
    recent_delayed_fork_resume: Cell<bool>,
    /// Set by `commit_delayed_fork` on success.  When true, `prepare_for_exit`
    /// skips exit notification and address-space cleanup because the process
    /// was migrated to a remote worker host (the background waiter handles
    /// the real exit).
    migrated_to_remote: Cell<bool>,
    /// Set when the local shim task should stop without marking its host
    /// thread's `ThreadRemote` as exiting (for remote exec handoff paths where
    /// the host thread belongs to the parent runtime and must remain alive).
    local_task_terminated: Cell<bool>,
    /// Active netlink sockets, keyed by guest fd number.
    /// Used to intercept sendto/recvmsg/bind for AF_NETLINK fds.
    netlink_sockets:
        RefCell<alloc::collections::BTreeMap<u32, crate::syscalls::netlink::NetlinkRouteSocket>>,
    /// Raw fd numbers created via AF_INET6 that were internally mapped to AF_INET.
    /// getsockname/getpeername/accept must return sockaddr_in6 with v4-mapped addresses.
    inet6_fds: RefCell<alloc::collections::BTreeSet<u32>>,
}

impl<FS: ShimFS> Drop for Task<FS> {
    fn drop(&mut self) {
        self.prepare_for_exit();
    }
}

pub type LoadFilter = fn(envp: &mut alloc::vec::Vec<alloc::ffi::CString>);

#[cfg(test)]
mod test_utils {
    extern crate std;
    use super::*;

    impl<FS: ShimFS> LinuxShim<FS> {
        /// Create a new task with default values for testing.
        pub(crate) fn new_test_task(self, fs: alloc::sync::Arc<FS>) -> Task<FS> {
            let pid = self
                .global
                .next_thread_id
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let files = Arc::new(syscalls::file::FilesState::new(fs));
            files.initialize_stdio_in_shared_descriptors_table(&self.global);
            Task {
                wait_state: wait::WaitState::new(self.global.platform),
                thread: syscalls::process::ThreadState::new_process(pid),
                process_id: litebox::process::ProcessId::INIT,
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
                fork_context: RefCell::new(None),
                last_shell_write: RefCell::new(None),
                last_syscall: Cell::new(None),
                syscall_restartable: Cell::new(false),
                in_syscall: Cell::new(false),
                deferred_vfork_park: Cell::new(false),
                delayed_fork_pending: Cell::new(false),
                recent_delayed_fork_resume: Cell::new(false),
                migrated_to_remote: Cell::new(false),
                local_task_terminated: Cell::new(false),
                netlink_sockets: RefCell::new(alloc::collections::BTreeMap::new()),
                inet6_fds: RefCell::new(alloc::collections::BTreeSet::new()),
                process_state: self.process_state.into(),
                global: self.global,
            }
        }
    }

    impl<FS: ShimFS> Task<FS> {
        /// Returns a clone of this task with a new TID for testing.
        pub(crate) fn clone_for_test(&self) -> Option<Self> {
            let tid = self
                .global
                .next_thread_id
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let task = Task {
                wait_state: wait::WaitState::new(self.global.platform),
                global: self.global.clone(),
                process_state: self.process_state.clone(),
                thread: self.thread.new_thread(tid)?,
                process_id: self.process_id,
                pid: self.pid,
                ppid: self.ppid,
                tid,
                credentials: self.credentials.clone(),
                comm: self.comm.clone(),
                fs: self.fs.clone(),
                files: self.files.clone(),
                signals: self.signals.clone_for_new_task(),
                fork_context: RefCell::new(None),
                last_shell_write: RefCell::new(None),
                last_syscall: Cell::new(None),
                syscall_restartable: Cell::new(false),
                in_syscall: Cell::new(false),
                deferred_vfork_park: Cell::new(false),
                delayed_fork_pending: Cell::new(false),
                recent_delayed_fork_resume: Cell::new(false),
                migrated_to_remote: Cell::new(false),
                local_task_terminated: Cell::new(false),
                netlink_sockets: RefCell::new(alloc::collections::BTreeMap::new()),
                inet6_fds: RefCell::new(alloc::collections::BTreeSet::new()),
            };
            Some(task)
        }

        /// Spawns a thread that runs with a clone of this task and a new TID.
        ///
        /// # Panics
        /// Panics if the test process is already terminating.
        pub(crate) fn spawn_clone_for_test<R>(
            &self,
            f: impl 'static + Send + FnOnce(Task<FS>) -> R,
        ) -> std::thread::JoinHandle<R>
        where
            R: 'static + Send,
        {
            let task = self.clone_for_test().unwrap();
            std::thread::spawn(move || f(task))
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use litebox::fs::OFlags;
    use litebox::platform::page_mgmt::MemoryRegionPermissions;
    use litebox_common_linux::{
        FcntlArg, FileDescriptorFlags, SockFlags, SockType,
        broker_pipe_provider::{BrokerOpError, BrokerPipeEnd, BrokerPipeProvider},
        broker_socketpair_provider::{BrokerSocketPairEndpoint, BrokerSocketPairProvider},
        cwfd::broker_subscribable::{BrokerEventCallback, BrokerSubscribable},
    };

    const DUP_FAIL_HANDLE: u64 = 0xd0_fa_11;

    #[test]
    fn replaced_subsystem_has_no_pipe_kind() {
        for subsystem in [
            ReplacedSubsystem::UnixSocket,
            ReplacedSubsystem::Pty,
            ReplacedSubsystem::Filesystem,
        ] {
            let kind = match subsystem {
                ReplacedSubsystem::UnixSocket => "unix_socket",
                ReplacedSubsystem::Pty => "pty",
                ReplacedSubsystem::Filesystem => "filesystem",
            };
            assert_ne!(kind, "pipe");
        }
    }

    struct TestBrokerPipeProvider;

    impl BrokerSubscribable for TestBrokerPipeProvider {
        fn subscribe(
            &self,
            _handle: u64,
            _events_mask: u32,
            _callback: Arc<dyn BrokerEventCallback>,
        ) -> Result<u64, BrokerOpError> {
            Ok(1)
        }

        fn unsubscribe(&self, _handle: u64, _subscription_id: u64) {}

        fn release(&self, _handle: u64) {}

        fn dup_handle(&self, handle: u64) -> Result<(), BrokerOpError> {
            if handle == DUP_FAIL_HANDLE {
                Err(BrokerOpError::UnknownHandle)
            } else {
                Ok(())
            }
        }

        fn query_events(&self, _handle: u64) -> Result<u32, BrokerOpError> {
            Ok(0)
        }
    }

    impl BrokerPipeProvider for TestBrokerPipeProvider {
        fn create_pipe(
            &self,
            _capacity: u64,
            _atomic_write_size: u64,
        ) -> Result<(u64, u64), BrokerOpError> {
            Ok((10, 11))
        }

        fn read_pipe(
            &self,
            _handle: u64,
            _max_len: u64,
        ) -> Result<alloc::vec::Vec<u8>, BrokerOpError> {
            Ok(alloc::vec::Vec::new())
        }

        fn write_pipe(&self, _handle: u64, bytes: &[u8]) -> Result<usize, BrokerOpError> {
            Ok(bytes.len())
        }
    }

    struct TestBrokerSocketPairProvider;

    impl BrokerSubscribable for TestBrokerSocketPairProvider {
        fn subscribe(
            &self,
            _handle: u64,
            _events_mask: u32,
            _callback: Arc<dyn BrokerEventCallback>,
        ) -> Result<u64, BrokerOpError> {
            Ok(1)
        }

        fn unsubscribe(&self, _handle: u64, _subscription_id: u64) {}

        fn release(&self, _handle: u64) {}

        fn dup_handle(&self, _handle: u64) -> Result<(), BrokerOpError> {
            Ok(())
        }

        fn query_events(&self, _handle: u64) -> Result<u32, BrokerOpError> {
            Ok(0)
        }
    }

    impl BrokerSocketPairProvider for TestBrokerSocketPairProvider {
        fn create_socketpair(
            &self,
            _capacity: u64,
            _atomic_write_size: u64,
        ) -> Result<(u64, u64), BrokerOpError> {
            Ok((20, 21))
        }

        fn read_socketpair(
            &self,
            _handle: u64,
            _max_len: u64,
        ) -> Result<alloc::vec::Vec<u8>, BrokerOpError> {
            Ok(alloc::vec::Vec::new())
        }

        fn write_socketpair(&self, _handle: u64, bytes: &[u8]) -> Result<usize, BrokerOpError> {
            Ok(bytes.len())
        }

        fn shutdown_socketpair_write(&self, _handle: u64) -> Result<(), BrokerOpError> {
            Ok(())
        }
    }

    fn install_test_broker_providers() {
        let _ = crate::syscalls::set_broker_pipe_provider(Arc::new(TestBrokerPipeProvider));
        let _ =
            crate::syscalls::set_broker_socketpair_provider(Arc::new(TestBrokerSocketPairProvider));
    }

    fn test_entrypoints() -> LinuxShimEntrypoints<DefaultFS> {
        let task = crate::syscalls::tests::init_platform(None);
        LinuxShimEntrypoints {
            task,
            _not_send: core::marker::PhantomData,
        }
    }

    #[test]
    fn install_broker_unix_socket_replaces_restored_unix_socket_slot() {
        install_test_broker_providers();
        let entrypoints = test_entrypoints();
        let guest_fd = 91;

        let unix_socket =
            syscalls::unix::UnixSocket::<DefaultFS>::new(SockType::Stream, SockFlags::empty())
                .expect("test unix socket should be constructible");
        let typed: litebox::fd::TypedFd<syscalls::unix::UnixSocketSubsystem<DefaultFS>> =
            entrypoints
                .task
                .global
                .litebox
                .descriptor_table_mut()
                .insert(unix_socket);
        {
            let files = entrypoints.task.files.borrow();
            let mut rds = files.raw_descriptor_store.write();
            assert!(rds.fd_into_specific_raw_integer(typed, guest_fd));
        }

        assert_eq!(
            entrypoints.install_broker_bridge_fd(
                guest_fd,
                syscalls::fork_snapshot::BrokerHandleSnapshot::UnixSocket {
                    handle_id: 1234,
                    endpoint: BrokerSocketPairEndpoint::A,
                },
                OFlags::empty(),
            ),
            Ok(())
        );

        let files = entrypoints.task.files.borrow();
        let rds = files.raw_descriptor_store.read();
        assert!(
            rds.fd_from_raw_integer::<syscalls::broker_socketpair::BrokerSocketPairSubsystem>(
                guest_fd,
            )
            .is_ok(),
            "replacement slot should hold the broker-backed socketpair fd"
        );
        assert!(
            rds.fd_from_raw_integer::<syscalls::unix::UnixSocketSubsystem<DefaultFS>>(guest_fd)
                .is_err(),
            "restored in-shim unix socket should have been consumed"
        );
    }

    #[test]
    fn install_broker_pipe_dup_handle_failure_leaves_slot_empty() {
        install_test_broker_providers();
        let entrypoints = test_entrypoints();
        let guest_fd = 92;

        assert_eq!(
            entrypoints.install_broker_bridge_fd(
                guest_fd,
                syscalls::fork_snapshot::BrokerHandleSnapshot::Pipe {
                    handle_id: DUP_FAIL_HANDLE,
                    direction: BrokerPipeEnd::Read,
                },
                OFlags::empty(),
            ),
            Err(())
        );

        let files = entrypoints.task.files.borrow();
        let rds = files.raw_descriptor_store.read();
        assert!(
            !rds.is_alive(guest_fd),
            "failed install should not leave a raw fd slot behind"
        );
    }

    #[test]
    fn reserve_thread_id_advances_allocator_past_bootstrap_tid() {
        let _ = crate::syscalls::tests::init_platform(None);

        let shim = LinuxShimBuilder::new_for_test().build::<DefaultFS>();

        shim.global.reserve_thread_id(8);

        assert_eq!(
            shim.global.next_thread_id.fetch_add(1, Ordering::Relaxed),
            9
        );
    }

    #[test]
    fn top_cow_layer_for_page_finds_older_active_layer() {
        let task = crate::syscalls::tests::init_platform(None);
        let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        let lower = Arc::new(CowState {
            protected_ranges: vec![(0x4000, PAGE_SIZE, perms)],
            dirty_pages: litebox::sync::Mutex::new(BTreeMap::new()),
        });
        let upper = Arc::new(CowState {
            protected_ranges: vec![(0x8000, PAGE_SIZE, perms)],
            dirty_pages: litebox::sync::Mutex::new(BTreeMap::new()),
        });

        task.process_state
            .borrow()
            .active_vfork_layers
            .lock()
            .extend([lower.clone(), upper]);

        let (cow, found_perms) = task
            .top_cow_layer_for_page(0x4000)
            .expect("lower active CoW layer should be found");

        assert!(Arc::ptr_eq(&cow, &lower));
        assert_eq!(found_perms, perms);
    }

    fn pipe_eagain_once_enabled(task: &Task<DefaultFS>, fd: i32) -> bool {
        let files = task.files.borrow();
        let typed = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<syscalls::broker_pipe::BrokerPipeSubsystem>(
                usize::try_from(fd).expect("raw fd should be non-negative"),
            )
            .expect("raw fd should be a broker pipe");
        task.global
            .litebox
            .descriptor_table()
            .with_metadata(&typed, |PipeNonblockEagainOnce(enabled)| *enabled)
            .unwrap_or(false)
    }

    #[test]
    fn guest_created_pipe_marker_limits_delayed_fork_setfl_eagain_shim() {
        install_test_broker_providers();

        let task = crate::syscalls::tests::init_platform(None);
        let (read_fd, _write_fd) = task
            .sys_pipe2(OFlags::empty())
            .expect("pipe2 should succeed");
        let read_fd = i32::try_from(read_fd).expect("pipe fd should fit in i32");
        task.recent_delayed_fork_resume.set(true);
        task.sys_fcntl(read_fd, FcntlArg::SETFL(OFlags::NONBLOCK))
            .expect("F_SETFL on guest-created broker pipe should succeed");
        assert!(
            pipe_eagain_once_enabled(&task, read_fd),
            "guest-created read pipe should arm the delayed-fork EAGAIN shim"
        );

        let entrypoints = test_entrypoints();
        let inherited_fd = 93i32;
        entrypoints
            .install_broker_bridge_fd(
                usize::try_from(inherited_fd).expect("inherited fd should fit usize"),
                syscalls::fork_snapshot::BrokerHandleSnapshot::Pipe {
                    handle_id: 1234,
                    direction: BrokerPipeEnd::Read,
                },
                OFlags::empty(),
            )
            .expect("installing inherited broker pipe should succeed");
        entrypoints.task.recent_delayed_fork_resume.set(true);
        entrypoints
            .task
            .sys_fcntl(inherited_fd, FcntlArg::SETFL(OFlags::NONBLOCK))
            .expect("F_SETFL on inherited broker pipe should succeed");
        assert!(
            !pipe_eagain_once_enabled(&entrypoints.task, inherited_fd),
            "inherited broker pipe must report externally-owned readiness as-is"
        );
    }

    #[test]
    fn close_range_syscall_marks_pipe_fds_close_on_exec() {
        let task = crate::syscalls::tests::init_platform(None);
        let (read_fd, write_fd) = task
            .sys_pipe2(OFlags::empty())
            .expect("pipe2 should succeed");
        let read_fd = i32::try_from(read_fd).expect("pipe fd should fit in i32");
        let write_fd = i32::try_from(write_fd).expect("pipe fd should fit in i32");

        let mut ctx = litebox_common_linux::ExecutionContext::default();
        #[cfg(target_arch = "x86")]
        {
            ctx.orig_eax = ::syscalls::Sysno::close_range as usize;
            ctx.ebx = 3;
            ctx.ecx = u32::MAX as usize;
            ctx.edx = 1 << 2;
        }
        #[cfg(target_arch = "x86_64")]
        {
            ctx.orig_rax = ::syscalls::Sysno::close_range as usize;
            ctx.rdi = 3;
            ctx.rsi = u32::MAX as usize;
            ctx.rdx = 1 << 2;
        }

        assert_eq!(task.do_syscall(&mut ctx), Ok(0));
        assert_eq!(
            task.sys_fcntl(read_fd, FcntlArg::GETFD)
                .expect("fcntl F_GETFD should succeed"),
            FileDescriptorFlags::FD_CLOEXEC.bits()
        );
        assert_eq!(
            task.sys_fcntl(write_fd, FcntlArg::GETFD)
                .expect("fcntl F_GETFD should succeed"),
            FileDescriptorFlags::FD_CLOEXEC.bits()
        );
    }

    // ---- Delayed-fork allowlist tests (x86_64 only) ----

    #[cfg(target_arch = "x86_64")]
    /// Helper: build an ExecutionContext with the given syscall number and args.
    fn make_syscall_ctx(
        nr: usize,
        arg0: usize,
        arg1: usize,
    ) -> litebox_common_linux::ExecutionContext {
        let mut ctx = litebox_common_linux::ExecutionContext::default();
        ctx.orig_rax = nr;
        ctx.rdi = arg0;
        ctx.rsi = arg1;
        ctx
    }

    #[cfg(target_arch = "x86_64")]
    fn assert_allowed(nr: ::syscalls::Sysno) {
        let ctx = make_syscall_ctx(nr as usize, 0, 0);
        assert!(
            Task::<DefaultFS>::is_pre_exec_syscall(&ctx),
            "{nr:?} should be allowed"
        );
    }

    #[cfg(target_arch = "x86_64")]
    fn assert_rejected(nr: ::syscalls::Sysno) {
        let ctx = make_syscall_ctx(nr as usize, 0, 0);
        assert!(
            !Task::<DefaultFS>::is_pre_exec_syscall(&ctx),
            "{nr:?} should be rejected"
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_allows_terminal_syscalls() {
        use ::syscalls::Sysno;
        assert_allowed(Sysno::execve);
        assert_allowed(Sysno::execveat);
        assert_allowed(Sysno::exit);
        assert_allowed(Sysno::exit_group);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_allows_fd_plumbing() {
        use ::syscalls::Sysno;
        assert_allowed(Sysno::close);
        assert_allowed(Sysno::close_range);
        assert_allowed(Sysno::dup);
        assert_allowed(Sysno::dup2);
        assert_allowed(Sysno::dup3);
        assert_allowed(Sysno::open);
        assert_allowed(Sysno::openat);
        assert_allowed(Sysno::openat2);
        assert_allowed(Sysno::pipe2);
        assert_allowed(Sysno::write);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_allows_directory() {
        use ::syscalls::Sysno;
        assert_allowed(Sysno::chdir);
        assert_allowed(Sysno::fchdir);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_allows_process_group() {
        use ::syscalls::Sysno;
        assert_allowed(Sysno::setpgid);
        assert_allowed(Sysno::setsid);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_allows_signal_setup() {
        use ::syscalls::Sysno;
        assert_allowed(Sysno::rt_sigaction);
        assert_allowed(Sysno::rt_sigprocmask);
        assert_allowed(Sysno::sigaltstack);
        assert_allowed(Sysno::set_tid_address);
        assert_allowed(Sysno::set_robust_list);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_allows_identity() {
        use ::syscalls::Sysno;
        assert_allowed(Sysno::setuid);
        assert_allowed(Sysno::setgid);
        assert_allowed(Sysno::setgroups);
        assert_allowed(Sysno::setreuid);
        assert_allowed(Sysno::setregid);
        assert_allowed(Sysno::setresuid);
        assert_allowed(Sysno::setresgid);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_allows_scheduling() {
        use ::syscalls::Sysno;
        assert_allowed(Sysno::sched_setscheduler);
        assert_allowed(Sysno::sched_setaffinity);
        assert_allowed(Sysno::sched_setparam);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_allows_resource_limits() {
        use ::syscalls::Sysno;
        assert_allowed(Sysno::setrlimit);
        assert_allowed(Sysno::prlimit64);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_allows_relative_sleeps() {
        use ::syscalls::Sysno;
        assert_allowed(Sysno::clock_nanosleep);
        assert_allowed(Sysno::nanosleep);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_allows_readonly_queries() {
        use ::syscalls::Sysno;
        assert_allowed(Sysno::getpid);
        assert_allowed(Sysno::getppid);
        assert_allowed(Sysno::gettid);
        assert_allowed(Sysno::getuid);
        assert_allowed(Sysno::geteuid);
        assert_allowed(Sysno::getgid);
        assert_allowed(Sysno::getegid);
        assert_allowed(Sysno::getsid);
        assert_allowed(Sysno::getpgid);
        assert_allowed(Sysno::fstat);
        assert_allowed(Sysno::stat);
        assert_allowed(Sysno::lstat);
        assert_allowed(Sysno::newfstatat);
        assert_allowed(Sysno::access);
        assert_allowed(Sysno::faccessat);
        assert_allowed(Sysno::faccessat2);
        assert_allowed(Sysno::readlink);
        assert_allowed(Sysno::readlinkat);
        assert_allowed(Sysno::ioctl);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_rejects_non_allowlisted() {
        use ::syscalls::Sysno;
        assert_rejected(Sysno::read);
        assert_rejected(Sysno::mmap);
        assert_rejected(Sysno::brk);
        assert_rejected(Sysno::clone);
        assert_rejected(Sysno::poll);
        assert_rejected(Sysno::socket);
        assert_rejected(Sysno::connect);
        assert_rejected(Sysno::accept);
        assert_rejected(Sysno::wait4);
        assert_rejected(Sysno::kill);
        // Default arg (FUTEX_WAIT=0) — still rejected. WAKE-only ops are
        // covered by `pre_exec_syscall_futex_allows_wake_ops` below.
        assert_rejected(Sysno::futex);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_fcntl_allows_fd_ops() {
        use ::syscalls::Sysno;
        // F_DUPFD=0, F_GETFD=1, F_SETFD=2, F_GETFL=3, F_SETFL=4, F_DUPFD_CLOEXEC=1030
        for cmd in [0, 1, 2, 3, 4, 1030] {
            let ctx = make_syscall_ctx(Sysno::fcntl as usize, 3, cmd);
            assert!(
                Task::<DefaultFS>::is_pre_exec_syscall(&ctx),
                "fcntl cmd={cmd} should be allowed"
            );
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_fcntl_rejects_non_fd_ops() {
        use ::syscalls::Sysno;
        // F_GETLK=5, F_SETLK=6, F_SETOWN=8
        for cmd in [5, 6, 8] {
            let ctx = make_syscall_ctx(Sysno::fcntl as usize, 3, cmd);
            assert!(
                !Task::<DefaultFS>::is_pre_exec_syscall(&ctx),
                "fcntl cmd={cmd} should be rejected"
            );
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_prctl_allows_pdeathsig_and_name() {
        use ::syscalls::Sysno;
        // PR_SET_PDEATHSIG=1, PR_SET_NAME=15
        let ctx = make_syscall_ctx(Sysno::prctl as usize, 1, 9);
        assert!(Task::<DefaultFS>::is_pre_exec_syscall(&ctx));
        let ctx = make_syscall_ctx(Sysno::prctl as usize, 15, 0x1000);
        assert!(Task::<DefaultFS>::is_pre_exec_syscall(&ctx));
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_prctl_rejects_other_ops() {
        use ::syscalls::Sysno;
        // PR_GET_NAME=16, PR_SET_SECCOMP=22, PR_SET_NO_NEW_PRIVS=38
        for op in [16, 22, 38] {
            let ctx = make_syscall_ctx(Sysno::prctl as usize, op, 0);
            assert!(
                !Task::<DefaultFS>::is_pre_exec_syscall(&ctx),
                "prctl op={op} should be rejected"
            );
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_futex_allows_wake_ops() {
        use ::syscalls::Sysno;
        // Glibc's `__libc_fork` epilogue invokes
        // `futex(FUTEX_WAKE_PRIVATE, 1)` (op = 0x81) to release its
        // pthread atfork mutex. Without this allowlist, every
        // static-PIE-glibc fork-child trips into commit_delayed_fork
        // and pays the snapshot+reject cost on each PROMOTION_RACE
        // iteration. Cover both the bare and PRIVATE-flagged
        // variants of every WAKE-flavoured op (per FUTEX_CMD_MASK).
        for op in [1u32, 3, 4, 5, 7, 10] {
            for &priv_flag in &[0u32, 0x80] {
                let raw = (op | priv_flag) as usize;
                let ctx = make_syscall_ctx(Sysno::futex as usize, 0, raw);
                assert!(
                    Task::<DefaultFS>::is_pre_exec_syscall(&ctx),
                    "futex op=0x{raw:x} should be allowed"
                );
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pre_exec_syscall_futex_rejects_blocking_ops() {
        use ::syscalls::Sysno;
        // FUTEX_WAIT=0, FUTEX_FD=2, FUTEX_LOCK_PI=6, FUTEX_TRYLOCK_PI=8,
        // FUTEX_WAIT_BITSET=9. Blocking ops must remain off the
        // allowlist: a fork-child waiting for a wake-up the parked vfork
        // parent cannot deliver would deadlock the test process.
        for op in [0u32, 2, 6, 8, 9] {
            for &priv_flag in &[0u32, 0x80] {
                let raw = (op | priv_flag) as usize;
                let ctx = make_syscall_ctx(Sysno::futex as usize, 0, raw);
                assert!(
                    !Task::<DefaultFS>::is_pre_exec_syscall(&ctx),
                    "futex op=0x{raw:x} should be rejected"
                );
            }
        }
    }
}
