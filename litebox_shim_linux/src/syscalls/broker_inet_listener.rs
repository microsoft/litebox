// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed TCP listener file support.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

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
    broker_inet_listener_provider::{BrokerInetListenerProvider, BrokerOpError},
    cwfd::{
        broker_subscribable::BrokerSubscribable,
        notification_frame::{NOTIFY_EVENT_ERR, NOTIFY_EVENT_IN},
    },
};
use litebox_platform_multiplex::Platform;

use super::broker_backed::{BrokerBackedCommon, broker_err_to_errno};

static BROKER_INET_LISTENER_PROVIDER: once_cell::race::OnceBox<
    Arc<dyn BrokerInetListenerProvider>,
> = once_cell::race::OnceBox::new();

pub fn set_broker_inet_listener_provider(
    provider: Arc<dyn BrokerInetListenerProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerInetListenerProvider>>> {
    BROKER_INET_LISTENER_PROVIDER.set(alloc::boxed::Box::new(provider))
}

pub fn broker_inet_listener_provider() -> Option<Arc<dyn BrokerInetListenerProvider>> {
    BROKER_INET_LISTENER_PROVIDER.get().cloned()
}

pub(crate) struct BrokerInetListenerSubsystem;
impl FdEnabledSubsystem for BrokerInetListenerSubsystem {
    const KIND: litebox::fd::SubsystemKind = litebox::fd::SubsystemKind::BrokerInetListener;

    type Entry = BrokerInetListenerFd<Platform>;
}
impl FdEnabledSubsystemEntry for BrokerInetListenerFd<Platform> {
    fn on_dup(&self) {
        self.common.note_slot_dup();
        let _ = self.provider.dup_handle(self.handle());
    }

    fn on_close(&self) {
        self.common.force_unsubscribe_if_last_slot();
        self.provider.release(self.handle());
    }
}

pub(crate) struct BrokerInetListenerFd<
    P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider,
> {
    provider: Arc<dyn BrokerInetListenerProvider>,
    common: BrokerBackedCommon<P>,
    status: AtomicU32,
    family: u8,
    bound_addr: litebox::sync::Mutex<P, Option<[u8; 28]>>,
    pollee: Arc<Pollee<P>>,
}

impl<P> BrokerInetListenerFd<P>
where
    P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider,
{
    pub(crate) fn new(
        provider: Arc<dyn BrokerInetListenerProvider>,
        handle: u64,
        family: u8,
        flags: OFlags,
    ) -> Self {
        let subscribable: Arc<dyn BrokerSubscribable> = Arc::clone(&provider) as _;
        let common =
            BrokerBackedCommon::new(subscribable, handle, NOTIFY_EVENT_IN | NOTIFY_EVENT_ERR);
        common.disable_release_on_drop();
        Self {
            provider,
            common,
            status: AtomicU32::new((OFlags::RDWR | (flags & OFlags::STATUS_FLAGS_MASK)).bits()),
            family,
            bound_addr: litebox::sync::Mutex::new(None),
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn handle(&self) -> u64 {
        self.common.handle()
    }

    pub(crate) fn family(&self) -> u8 {
        self.family
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

    pub(crate) fn provider(&self) -> Arc<dyn BrokerInetListenerProvider> {
        Arc::clone(&self.provider)
    }

    pub(crate) fn set_bound_addr(&self, addr: [u8; 28]) {
        *self.bound_addr.lock() = Some(addr);
    }

    pub(crate) fn bound_addr(&self) -> Option<[u8; 28]> {
        *self.bound_addr.lock()
    }
}

impl BrokerInetListenerFd<Platform> {
    pub(crate) fn setsockopt(
        &self,
        level: u32,
        optname: u32,
        optval: &[u8],
    ) -> Result<(), litebox_common_linux::errno::Errno> {
        self.provider
            .setsockopt(self.handle(), level, optname, optval)
            .map_err(broker_err_to_errno)
    }

    pub(crate) fn getsockopt(
        &self,
        level: u32,
        optname: u32,
        optlen: u32,
    ) -> Result<Vec<u8>, litebox_common_linux::errno::Errno> {
        self.provider
            .getsockopt(self.handle(), level, optname, optlen)
            .map_err(broker_err_to_errno)
    }

    pub(crate) fn getsockname(&self) -> Result<[u8; 28], litebox_common_linux::errno::Errno> {
        if let Some(addr) = self.bound_addr() {
            return Ok(addr);
        }
        let addr = self
            .provider
            .getsockname(self.handle())
            .map_err(broker_err_to_errno)?;
        self.set_bound_addr(addr);
        Ok(addr)
    }

    pub(crate) fn bind(
        &self,
        sockaddr: &[u8],
    ) -> Result<[u8; 28], litebox_common_linux::errno::Errno> {
        let actual = self
            .provider
            .bind(self.handle(), sockaddr)
            .map_err(broker_err_to_errno)?;
        self.set_bound_addr(actual);
        Ok(actual)
    }

    pub(crate) fn listen(&self, backlog: u32) -> Result<(), litebox_common_linux::errno::Errno> {
        self.common.ensure_subscribed(&self.pollee);
        self.provider
            .listen(self.handle(), backlog)
            .map_err(broker_err_to_errno)
    }

    pub(crate) fn accept(
        &self,
        cx: &WaitContext<'_, Platform>,
    ) -> Result<(u64, [u8; 28]), litebox_common_linux::errno::Errno> {
        self.common.ensure_subscribed(&self.pollee);
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::IN, || {
                match self.provider.accept(self.handle()) {
                    Ok(conn) => Ok(conn),
                    Err(BrokerOpError::WouldBlock) => Err(TryOpError::TryAgain),
                    Err(e) => Err(TryOpError::Other(broker_err_to_errno(e))),
                }
            })
            .map_err(|e| match e {
                TryOpError::TryAgain => litebox_common_linux::errno::Errno::EAGAIN,
                TryOpError::WaitError(_) => litebox_common_linux::errno::Errno::EINTR,
                TryOpError::Other(errno) => errno,
            })
    }
}

impl IOPollable for BrokerInetListenerFd<Platform> {
    fn check_io_events(&self) -> Events {
        self.common.check_io_events() & (Events::IN | Events::ERR)
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.common.ensure_subscribed(&self.pollee);
        self.pollee.register_observer(observer, mask);
    }
}
