// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed raw IPv4 socket file support.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use litebox::{
    event::{Events, IOPollable, observer::Observer, polling::Pollee},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{
    broker_inet_raw_provider::{BrokerInetRawProvider, BrokerOpError},
    cwfd::{
        broker_subscribable::BrokerSubscribable,
        notification_frame::{NOTIFY_EVENT_ERR, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT},
    },
    errno::Errno,
};
use litebox_platform_multiplex::Platform;

use super::broker_backed::{BrokerBackedCommon, broker_err_to_errno};

static BROKER_INET_RAW_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerInetRawProvider>> =
    once_cell::race::OnceBox::new();

pub fn set_broker_inet_raw_provider(
    provider: Arc<dyn BrokerInetRawProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerInetRawProvider>>> {
    BROKER_INET_RAW_PROVIDER.set(alloc::boxed::Box::new(provider))
}

pub fn broker_inet_raw_provider() -> Option<Arc<dyn BrokerInetRawProvider>> {
    BROKER_INET_RAW_PROVIDER.get().cloned()
}

pub(crate) struct BrokerInetRawSubsystem;
impl FdEnabledSubsystem for BrokerInetRawSubsystem {
    const KIND: litebox::fd::SubsystemKind = litebox::fd::SubsystemKind::BrokerInetRaw;

    type Entry = BrokerInetRawFd<Platform>;
}
impl FdEnabledSubsystemEntry for BrokerInetRawFd<Platform> {
    fn on_dup(&self) {
        self.common.note_slot_dup();
        let _ = self.provider.dup_handle(self.handle());
    }

    fn on_close(&self) {
        self.common.force_unsubscribe_if_last_slot();
        self.provider.release(self.handle());
    }
}

pub(crate) struct BrokerInetRawFd<P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider> {
    provider: Arc<dyn BrokerInetRawProvider>,
    common: BrokerBackedCommon<P>,
    status: AtomicU32,
    family: u8,
    protocol: u8,
    pollee: Arc<Pollee<P>>,
}

impl<P> BrokerInetRawFd<P>
where
    P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider,
{
    pub(crate) fn new(
        provider: Arc<dyn BrokerInetRawProvider>,
        handle: u64,
        family: u8,
        protocol: u8,
        flags: OFlags,
    ) -> Self {
        let subscribable: Arc<dyn BrokerSubscribable> = Arc::clone(&provider) as _;
        let common = BrokerBackedCommon::new(
            subscribable,
            handle,
            NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT | NOTIFY_EVENT_ERR,
        );
        common.disable_release_on_drop();
        Self {
            provider,
            common,
            status: AtomicU32::new((OFlags::RDWR | (flags & OFlags::STATUS_FLAGS_MASK)).bits()),
            family,
            protocol,
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn handle(&self) -> u64 {
        self.common.handle()
    }

    pub(crate) fn family(&self) -> u8 {
        self.family
    }

    pub(crate) fn protocol(&self) -> u8 {
        self.protocol
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
}

impl BrokerInetRawFd<Platform> {
    pub(crate) fn send_to(&self, sockaddr: &[u8], bytes: &[u8]) -> Result<usize, Errno> {
        self.common.ensure_subscribed(&self.pollee);
        self.provider
            .send_to(self.handle(), sockaddr, bytes)
            .map_err(broker_err_to_errno)
    }

    pub(crate) fn recv_from(&self, max_len: u64) -> Result<([u8; 28], alloc::vec::Vec<u8>), Errno> {
        self.common.ensure_subscribed(&self.pollee);
        self.provider
            .recv_from(self.handle(), max_len)
            .map_err(|err| match err {
                BrokerOpError::WouldBlock => Errno::EAGAIN,
                other => broker_err_to_errno(other),
            })
    }
}

impl IOPollable for BrokerInetRawFd<Platform> {
    fn check_io_events(&self) -> Events {
        self.common.check_io_events() & (Events::IN | Events::OUT | Events::ERR)
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.common.ensure_subscribed(&self.pollee);
        self.pollee.register_observer(observer, mask);
    }
}
