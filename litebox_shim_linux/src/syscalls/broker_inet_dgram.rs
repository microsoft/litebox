// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed UDP datagram file descriptors.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use litebox::{
    event::{
        Events, IOPollable,
        observer::Observer,
        polling::{Pollee, TryOpError},
        wait::WaitContext,
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{
    cwfd::{
        broker_inet_dgram_provider::{BrokerInetDgramProvider, BrokerOpError},
        broker_subscribable::BrokerSubscribable,
        notification_frame::{
            NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
        },
    },
    errno::Errno,
};
use litebox_platform_multiplex::Platform;

use super::broker_backed::{BrokerBackedCommon, broker_err_to_errno};
use super::fork_snapshot::FdKind;

static BROKER_INET_DGRAM_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerInetDgramProvider>> =
    once_cell::race::OnceBox::new();
static BROKER_INET_DGRAM_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_broker_inet_dgram_enabled(enabled: bool) {
    BROKER_INET_DGRAM_ENABLED.store(enabled, Ordering::Release);
}

pub fn broker_inet_dgram_enabled() -> bool {
    BROKER_INET_DGRAM_ENABLED.load(Ordering::Acquire)
}

pub fn set_broker_inet_dgram_provider(
    provider: Arc<dyn BrokerInetDgramProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerInetDgramProvider>>> {
    BROKER_INET_DGRAM_PROVIDER.set(alloc::boxed::Box::new(provider))
}

pub fn broker_inet_dgram_provider() -> Option<Arc<dyn BrokerInetDgramProvider>> {
    BROKER_INET_DGRAM_PROVIDER.get().cloned()
}

pub(crate) struct BrokerInetDgramSubsystem;
impl FdEnabledSubsystem for BrokerInetDgramSubsystem {
    const KIND: litebox::fd::SubsystemKind = litebox::fd::SubsystemKind::BrokerInetDgram;

    type Entry = BrokerInetDgramFd<Platform>;
}

pub(crate) struct BrokerInetDgramFd<P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider>
{
    provider: Arc<dyn BrokerInetDgramProvider>,
    common: BrokerBackedCommon<P>,
    status: AtomicU32,
    read_shutdown: AtomicBool,
    write_shutdown: AtomicBool,
    pollee: Arc<Pollee<P>>,
}

impl<P> BrokerInetDgramFd<P>
where
    P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider,
{
    pub(crate) fn new(
        provider: Arc<dyn BrokerInetDgramProvider>,
        handle: u64,
        flags: OFlags,
    ) -> Self {
        let subscribable: Arc<dyn BrokerSubscribable> = Arc::clone(&provider) as _;
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
        FdKind::BrokerInetDgram {
            handle_id: self.handle(),
        }
    }
}

impl BrokerInetDgramFd<Platform> {
    pub(crate) fn bind(&self, sockaddr: &[u8]) -> Result<[u8; 28], Errno> {
        self.provider
            .bind(self.handle(), sockaddr)
            .map_err(broker_err_to_errno)
    }

    pub(crate) fn connect(&self, sockaddr: &[u8]) -> Result<(), Errno> {
        self.provider
            .connect(self.handle(), sockaddr)
            .map_err(broker_err_to_errno)
    }

    fn try_sendto_now(&self, sockaddr: &[u8], payload: &[u8]) -> Result<usize, Errno> {
        match self.provider.sendto(self.handle(), sockaddr, payload) {
            Ok(n) => Ok(n),
            Err(BrokerOpError::WouldBlock) => Err(Errno::EAGAIN),
            Err(e) => Err(broker_err_to_errno(e)),
        }
    }

    pub(crate) fn sendto(
        &self,
        cx: &WaitContext<'_, Platform>,
        sockaddr: &[u8],
        payload: &[u8],
    ) -> Result<usize, Errno> {
        if self.write_shutdown.load(Ordering::Acquire) {
            return Err(Errno::EPIPE);
        }
        self.common.ensure_subscribed(&self.pollee);
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::OUT, || {
                match self.try_sendto_now(sockaddr, payload) {
                    Ok(n) => Ok(n),
                    Err(Errno::EAGAIN) => Err(TryOpError::TryAgain),
                    Err(e) => Err(TryOpError::Other(e)),
                }
            })
            .map_err(|e| match e {
                TryOpError::TryAgain => Errno::EAGAIN,
                TryOpError::WaitError(_) => Errno::EINTR,
                TryOpError::Other(errno) => errno,
            })
    }

    fn try_recvfrom_now(
        &self,
        max_len: u32,
    ) -> Result<([u8; 28], alloc::vec::Vec<u8>, u32), Errno> {
        if self.read_shutdown.load(Ordering::Acquire) {
            return Ok(([0; 28], alloc::vec::Vec::new(), 0));
        }
        match self.provider.recvfrom(self.handle(), max_len) {
            Ok(result) => Ok(result),
            Err(BrokerOpError::WouldBlock) => Err(Errno::EAGAIN),
            Err(e) => Err(broker_err_to_errno(e)),
        }
    }

    pub(crate) fn recvfrom(
        &self,
        cx: &WaitContext<'_, Platform>,
        max_len: u32,
    ) -> Result<([u8; 28], alloc::vec::Vec<u8>, u32), Errno> {
        self.common.ensure_subscribed(&self.pollee);
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::IN, || {
                match self.try_recvfrom_now(max_len) {
                    Ok(result) => Ok(result),
                    Err(Errno::EAGAIN) => Err(TryOpError::TryAgain),
                    Err(e) => Err(TryOpError::Other(e)),
                }
            })
            .map_err(|e| match e {
                TryOpError::TryAgain => Errno::EAGAIN,
                TryOpError::WaitError(_) => Errno::EINTR,
                TryOpError::Other(errno) => errno,
            })
    }

    pub(crate) fn shutdown(&self, how: u8) -> Result<(), Errno> {
        match how {
            0 => self.read_shutdown.store(true, Ordering::Release),
            1 => self.write_shutdown.store(true, Ordering::Release),
            2 => {
                self.read_shutdown.store(true, Ordering::Release);
                self.write_shutdown.store(true, Ordering::Release);
            }
            _ => return Err(Errno::EINVAL),
        }
        self.provider
            .shutdown(self.handle(), how)
            .map_err(broker_err_to_errno)
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

    pub(crate) fn setsockopt(&self, level: i32, name: i32, value: &[u8]) -> Result<(), Errno> {
        self.provider
            .setsockopt(self.handle(), level, name, value)
            .map_err(broker_err_to_errno)
    }

    pub(crate) fn getsockopt(
        &self,
        level: i32,
        name: i32,
        max_len: u32,
    ) -> Result<alloc::vec::Vec<u8>, Errno> {
        self.provider
            .getsockopt(self.handle(), level, name, max_len)
            .map_err(broker_err_to_errno)
    }
}

impl IOPollable for BrokerInetDgramFd<Platform> {
    fn check_io_events(&self) -> Events {
        match BrokerInetDgramProvider::query_events(&*self.provider, self.handle()) {
            Ok(events) => Events::from_bits_truncate(events),
            Err(_) => self.common.check_io_events(),
        }
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.common.ensure_subscribed(&self.pollee);
        self.pollee.register_observer(observer, mask);
    }
}

impl FdEnabledSubsystemEntry for BrokerInetDgramFd<Platform> {
    fn on_dup(&self) {
        let _ = self.provider.dup_handle(self.handle());
    }

    fn on_close(&self) {
        self.common.force_unsubscribe();
        self.provider.release(self.handle());
    }
}
