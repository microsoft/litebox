// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed TCP connection file descriptors.

use alloc::sync::Arc;
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
use super::fork_snapshot::BrokerHandleKind;

static BROKER_TCP_CONN_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerTcpConnProvider>> =
    once_cell::race::OnceBox::new();
static BROKER_TCP_CONN_ACCEPT_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_broker_tcp_conn_accept_enabled(enabled: bool) {
    BROKER_TCP_CONN_ACCEPT_ENABLED.store(enabled, Ordering::Release);
}

pub fn broker_tcp_conn_accept_enabled() -> bool {
    BROKER_TCP_CONN_ACCEPT_ENABLED.load(Ordering::Acquire)
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
    type Entry = BrokerTcpConnFd<Platform>;
}

pub(crate) struct BrokerTcpConnFd<P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider> {
    provider: Arc<dyn BrokerTcpConnProvider>,
    common: BrokerBackedCommon<P>,
    status: AtomicU32,
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

    pub(crate) fn fork_snapshot_handle(&self) -> (BrokerHandleKind, u64) {
        (BrokerHandleKind::TcpConn, self.handle())
    }
}

impl BrokerTcpConnFd<Platform> {
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
        const READ_TCP_CONN_CHUNK: usize = 60 * 1024;
        let capped_len = core::cmp::min(buf.len(), READ_TCP_CONN_CHUNK);
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::IN, || {
                match self
                    .provider
                    .read_tcp_conn(self.handle(), capped_len as u64)
                {
                    Ok(bytes) => {
                        let n = bytes.len().min(buf.len());
                        buf[..n].copy_from_slice(&bytes[..n]);
                        if n == 0 {
                            self.common.set_readable(false);
                        }
                        Ok(n)
                    }
                    Err(BrokerOpError::WouldBlock) => {
                        self.common.set_readable(false);
                        Err(litebox::event::polling::TryOpError::TryAgain)
                    }
                    Err(e) => Err(litebox::event::polling::TryOpError::Other(
                        broker_err_to_errno(e),
                    )),
                }
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
        const WRITE_TCP_CONN_CHUNK: usize = 60 * 1024;
        let chunk = &buf[..core::cmp::min(buf.len(), WRITE_TCP_CONN_CHUNK)];
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::OUT, || {
                match self.provider.write_tcp_conn(self.handle(), chunk) {
                    Ok(n) => Ok(n),
                    Err(BrokerOpError::WouldBlock) => {
                        Err(litebox::event::polling::TryOpError::TryAgain)
                    }
                    Err(BrokerOpError::InvalidValue) => {
                        Err(litebox::event::polling::TryOpError::Other(Errno::EPIPE))
                    }
                    Err(e) => Err(litebox::event::polling::TryOpError::Other(
                        broker_err_to_errno(e),
                    )),
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
            self.common.set_readable(false);
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
        let _ = self.provider.dup_handle(self.handle());
    }

    fn on_close(&self) {
        self.common.force_unsubscribe();
        self.provider.release(self.handle());
    }
}
