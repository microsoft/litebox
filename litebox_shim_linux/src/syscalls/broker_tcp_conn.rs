// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed TCP connection file descriptors.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use litebox::{
    event::{Events, IOPollable, observer::Observer, polling::Pollee, wait::WaitContext},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{
    broker_tcp_conn_provider::{BrokerOpError, BrokerTcpConnProvider},
    cwfd::notification_frame::{
        NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
    },
    errno::Errno,
};
use litebox_platform_multiplex::Platform;

use super::broker_backed::{BrokerBackedCommon, broker_err_to_errno};
use super::fork_snapshot::FdKind;

static BROKER_TCP_CONN_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerTcpConnProvider>> =
    once_cell::race::OnceBox::new();
static BROKER_TCP_CONN_ACCEPT_ENABLED: AtomicBool = AtomicBool::new(false);
static BROKER_INET_TCP_CONN_OUTBOUND_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_broker_tcp_conn_accept_enabled(enabled: bool) {
    BROKER_TCP_CONN_ACCEPT_ENABLED.store(enabled, Ordering::Release);
}

pub fn broker_tcp_conn_accept_enabled() -> bool {
    BROKER_TCP_CONN_ACCEPT_ENABLED.load(Ordering::Acquire)
}

pub fn set_broker_inet_tcp_conn_provider_outbound_enabled(enabled: bool) {
    BROKER_INET_TCP_CONN_OUTBOUND_ENABLED.store(enabled, Ordering::Release);
}

pub fn broker_inet_tcp_conn_provider_outbound_enabled() -> bool {
    BROKER_INET_TCP_CONN_OUTBOUND_ENABLED.load(Ordering::Acquire)
}

pub fn set_broker_tcp_conn_provider(
    provider: Arc<dyn BrokerTcpConnProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerTcpConnProvider>>> {
    BROKER_TCP_CONN_PROVIDER.set(alloc::boxed::Box::new(provider))
}

pub fn broker_tcp_conn_provider() -> Option<Arc<dyn BrokerTcpConnProvider>> {
    BROKER_TCP_CONN_PROVIDER.get().cloned()
}

pub(crate) struct BrokerTcpConnSubsystem;
impl FdEnabledSubsystem for BrokerTcpConnSubsystem {
    const KIND: litebox::fd::SubsystemKind = litebox::fd::SubsystemKind::BrokerTcpConn;

    type Entry = BrokerTcpConnFd<Platform>;
}

pub(crate) struct BrokerTcpConnFd<P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider> {
    provider: Arc<dyn BrokerTcpConnProvider>,
    common: BrokerBackedCommon<P>,
    status: AtomicU32,
    /// `shutdown(fd, SHUT_RD)` was called on this `BrokerTcpConnFd`
    /// instance. Short-circuits `read()` to EOF without an RPC.
    ///
    /// **Known divergence from Linux:** same hazard as
    /// `BrokerSocketPairFd::read_shutdown` — per-instance flag rather
    /// than broker-held state, so dup'd fds can diverge. See
    /// `files/cache-audit.md` (item C); proper fix moves the state to
    /// `TcpConnState` on the broker and queries it synchronously.
    read_shutdown: AtomicBool,
    write_shutdown: AtomicBool,
    pollee: Arc<Pollee<P>>,
}

impl<P> BrokerTcpConnFd<P>
where
    P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider,
{
    pub(crate) fn new(
        provider: Arc<dyn BrokerTcpConnProvider>,
        handle: u64,
        flags: OFlags,
    ) -> Self {
        let subscribable: Arc<
            dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
        > = Arc::clone(&provider) as _;
        let events_mask = NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT | NOTIFY_EVENT_HUP | NOTIFY_EVENT_ERR;
        let common = BrokerBackedCommon::new(subscribable, handle, events_mask);
        common.disable_release_on_drop();
        Self {
            provider,
            common,
            status: AtomicU32::new((OFlags::RDWR | (flags & OFlags::STATUS_FLAGS_MASK)).bits()),
            read_shutdown: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn handle(&self) -> u64 {
        self.common.handle()
    }

    pub(crate) fn get_status(&self) -> OFlags {
        OFlags::from_bits_truncate(self.status.load(Ordering::Relaxed)) & OFlags::STATUS_FLAGS_MASK
    }

    pub(crate) fn set_status(&self, flags: OFlags) {
        self.status.store(
            (OFlags::RDWR | (flags & OFlags::STATUS_FLAGS_MASK)).bits(),
            Ordering::Relaxed,
        );
    }

    pub(crate) fn fork_snapshot_handle(&self) -> FdKind {
        FdKind::BrokerTcpConn {
            handle_id: self.handle(),
        }
    }
}

impl BrokerTcpConnFd<Platform> {
    pub(crate) fn connect(
        &self,
        _cx: &WaitContext<'_, Platform>,
        sockaddr: &[u8],
    ) -> Result<(), Errno> {
        const CONNECT_TIMEOUT_MS: u32 = 30_000;
        self.common.ensure_subscribed(&self.pollee);
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        if nonblock {
            return match self
                .provider
                .connect(self.handle(), sockaddr, CONNECT_TIMEOUT_MS)
            {
                Ok(()) => Ok(()),
                Err(BrokerOpError::WouldBlock) => Err(Errno::EINPROGRESS),
                Err(e) => Err(broker_err_to_errno(e)),
            };
        }
        loop {
            match self
                .provider
                .connect(self.handle(), sockaddr, CONNECT_TIMEOUT_MS)
            {
                Ok(()) => return Ok(()),
                Err(BrokerOpError::WouldBlock) => core::hint::spin_loop(),
                Err(e) => return Err(broker_err_to_errno(e)),
            }
        }
    }

    pub(crate) fn getsockname(&self) -> Result<[u8; 28], Errno> {
        self.provider
            .getsockname(self.handle())
            .map_err(broker_err_to_errno)
    }

    pub(crate) fn getpeername(&self) -> Result<[u8; 28], Errno> {
        self.provider
            .getpeername(self.handle())
            .map_err(broker_err_to_errno)
    }

    pub(crate) fn setsockopt(&self, level: u32, optname: u32, optval: &[u8]) -> Result<(), Errno> {
        self.provider
            .setsockopt(self.handle(), level, optname, optval)
            .map_err(|err| match err {
                BrokerOpError::InvalidValue => Errno::EOPNOTSUPP,
                other => broker_err_to_errno(other),
            })
    }

    pub(crate) fn getsockopt(
        &self,
        level: u32,
        optname: u32,
        optlen: u32,
    ) -> Result<Vec<u8>, Errno> {
        self.provider
            .getsockopt(self.handle(), level, optname, optlen)
            .map_err(|err| match err {
                BrokerOpError::InvalidValue => Errno::EOPNOTSUPP,
                other => broker_err_to_errno(other),
            })
    }

    pub(crate) fn try_read_now(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        const READ_TCP_CONN_CHUNK: usize = 60 * 1024;
        let capped_len = core::cmp::min(buf.len(), READ_TCP_CONN_CHUNK);
        match self
            .provider
            .read_tcp_conn(self.handle(), capped_len as u64)
        {
            Ok(bytes) => {
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok(n)
            }
            Err(BrokerOpError::WouldBlock) => Err(Errno::EAGAIN),
            Err(e) => Err(broker_err_to_errno(e)),
        }
    }

    pub(crate) fn try_write_now(&self, buf: &[u8]) -> Result<usize, Errno> {
        const WRITE_TCP_CONN_CHUNK: usize = 60 * 1024;
        let chunk = &buf[..core::cmp::min(buf.len(), WRITE_TCP_CONN_CHUNK)];
        match self.provider.write_tcp_conn(self.handle(), chunk) {
            Ok(n) => Ok(n),
            Err(BrokerOpError::WouldBlock) => Err(Errno::EAGAIN),
            Err(BrokerOpError::InvalidValue) => Err(Errno::EPIPE),
            Err(e) => Err(broker_err_to_errno(e)),
        }
    }

    pub(crate) fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &mut [u8],
    ) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.read_shutdown.load(Ordering::Acquire) {
            return Ok(0);
        }
        self.common.ensure_subscribed(&self.pollee);
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::IN, || match self.try_read_now(buf) {
                Ok(n) => Ok(n),
                Err(Errno::EAGAIN) => Err(litebox::event::polling::TryOpError::TryAgain),
                Err(e) => Err(litebox::event::polling::TryOpError::Other(e)),
            })
            .map_err(|e| match e {
                litebox::event::polling::TryOpError::TryAgain => Errno::EAGAIN,
                litebox::event::polling::TryOpError::WaitError(_) => Errno::EINTR,
                litebox::event::polling::TryOpError::Other(errno) => errno,
            })
    }

    pub(crate) fn write(&self, cx: &WaitContext<'_, Platform>, buf: &[u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.write_shutdown.load(Ordering::Acquire) {
            return Err(Errno::EPIPE);
        }
        self.common.ensure_subscribed(&self.pollee);
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::OUT, || {
                match self.try_write_now(buf) {
                    Ok(n) => Ok(n),
                    Err(Errno::EAGAIN) => Err(litebox::event::polling::TryOpError::TryAgain),
                    Err(e) => Err(litebox::event::polling::TryOpError::Other(e)),
                }
            })
            .map_err(|e| match e {
                litebox::event::polling::TryOpError::TryAgain => Errno::EAGAIN,
                litebox::event::polling::TryOpError::WaitError(_) => Errno::EINTR,
                litebox::event::polling::TryOpError::Other(errno) => errno,
            })
    }

    pub(crate) fn shutdown(&self, read: bool, write: bool) -> Result<(), Errno> {
        if read {
            self.read_shutdown.store(true, Ordering::Release);
        }
        if write {
            self.write_shutdown.store(true, Ordering::Release);
        }
        self.provider
            .shutdown_tcp_conn(self.handle(), read, write)
            .map_err(broker_err_to_errno)
    }
}

impl IOPollable for BrokerTcpConnFd<Platform> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.common.ensure_subscribed(&self.pollee);
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        match self.provider.poll_tcp_conn_events(self.handle()) {
            Ok(events) => Events::from_bits_truncate(events),
            Err(_) => self.common.check_io_events(),
        }
    }
}

impl FdEnabledSubsystemEntry for BrokerTcpConnFd<Platform> {
    fn on_dup(&self) {
        self.common.note_slot_dup();
        let _ = self.provider.dup_handle(self.handle());
    }

    fn on_close(&self) {
        self.common.force_unsubscribe_if_last_slot();
        self.provider.release(self.handle());
    }
}
