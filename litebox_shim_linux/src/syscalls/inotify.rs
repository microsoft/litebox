// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed inotify file support.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use litebox::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::fs::OFlags;
use litebox_common_linux::broker_inotify_provider::{BrokerInotifyProvider, BrokerOpError};
use litebox_common_linux::cwfd::notification_frame::NOTIFY_EVENT_IN;
use litebox_common_linux::errno::Errno;
use litebox_platform_multiplex::Platform;

use super::broker_backed::{BrokerBackedCommon, broker_err_to_errno};

static BROKER_INOTIFY_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerInotifyProvider>> =
    once_cell::race::OnceBox::new();

pub fn set_broker_inotify_provider(
    provider: Arc<dyn BrokerInotifyProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerInotifyProvider>>> {
    BROKER_INOTIFY_PROVIDER.set(alloc::boxed::Box::new(provider))
}

pub fn broker_inotify_provider() -> Option<Arc<dyn BrokerInotifyProvider>> {
    BROKER_INOTIFY_PROVIDER.get().cloned()
}

pub(crate) struct InotifySubsystem;
impl FdEnabledSubsystem for InotifySubsystem {
    const KIND: litebox::fd::SubsystemKind = litebox::fd::SubsystemKind::Inotify;

    type Entry = InotifyFile;
}
impl FdEnabledSubsystemEntry for InotifyFile {
    fn on_dup(&self) {
        self.common.note_slot_dup();
        let _ = self.provider.dup_handle(self.handle());
    }

    fn on_close(&self) {
        self.common.force_unsubscribe_if_last_slot();
        self.provider.release(self.handle());
    }
}

pub(crate) struct InotifyFile {
    provider: Arc<dyn BrokerInotifyProvider>,
    common: BrokerBackedCommon<Platform>,
    status: AtomicU32,
    pollee: Arc<Pollee<Platform>>,
}

impl InotifyFile {
    pub(crate) fn new(
        provider: Arc<dyn BrokerInotifyProvider>,
        handle: u64,
        flags: OFlags,
    ) -> Self {
        let subscribable: Arc<
            dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
        > = Arc::clone(&provider) as _;
        let mut status = OFlags::RDONLY;
        status.set(OFlags::NONBLOCK, flags.contains(OFlags::NONBLOCK));
        let common = BrokerBackedCommon::new(subscribable, handle, NOTIFY_EVENT_IN);
        common.disable_release_on_drop();
        Self {
            provider,
            common,
            status: AtomicU32::new(status.bits()),
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn handle(&self) -> u64 {
        self.common.handle()
    }

    pub(crate) fn get_status(&self) -> OFlags {
        OFlags::from_bits(self.status.load(Ordering::Relaxed)).unwrap() & OFlags::STATUS_FLAGS_MASK
    }

    pub(crate) fn set_status(&self, flags: OFlags) {
        let access = self.get_status() & (OFlags::RDONLY | OFlags::WRONLY | OFlags::RDWR);
        self.status.store(
            (access | (flags & OFlags::STATUS_FLAGS_MASK)).bits(),
            Ordering::Relaxed,
        );
    }

    pub(crate) fn add_watch(&self, path: &str, mask: u32) -> Result<i32, Errno> {
        self.provider
            .inotify_add_watch(self.handle(), path, mask)
            .map_err(broker_err_to_errno)
    }

    pub(crate) fn rm_watch(&self, wd: i32) -> Result<(), Errno> {
        self.provider
            .inotify_rm_watch(self.handle(), wd)
            .map_err(broker_err_to_errno)
    }

    pub(crate) fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        self.common.ensure_subscribed(&self.pollee);
        loop {
            match self.provider.inotify_read(self.handle(), buf.len() as u32) {
                Ok(Some(payload)) => {
                    let n = payload.len().min(buf.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    return Ok(n);
                }
                Ok(None) | Err(BrokerOpError::WouldBlock) => return Err(Errno::EAGAIN),
                Err(e) => return Err(broker_err_to_errno(e)),
            }
        }
    }
}

impl IOPollable for InotifyFile {
    fn check_io_events(&self) -> Events {
        self.common.check_io_events() & Events::IN
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.common.ensure_subscribed(&self.pollee);
        self.pollee.register_observer(observer, mask);
    }
}
