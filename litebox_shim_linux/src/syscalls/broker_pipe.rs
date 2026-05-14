// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed pipe file descriptors for cross-worker fork inheritance.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use litebox::{
    event::{Events, IOPollable, observer::Observer, polling::Pollee, wait::WaitContext},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{
    broker_pipe_provider::{BrokerOpError, BrokerPipeEnd, BrokerPipeProvider},
    cwfd::notification_frame::{
        NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
    },
    errno::Errno,
};
use litebox_platform_multiplex::Platform;

use super::broker_backed::{BrokerBackedCommon, broker_err_to_errno};
use super::fork_snapshot::BrokerHandleKind;

static BROKER_PIPE_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerPipeProvider>> =
    once_cell::race::OnceBox::new();

pub fn set_broker_pipe_provider(
    provider: Arc<dyn BrokerPipeProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerPipeProvider>>> {
    BROKER_PIPE_PROVIDER.set(alloc::boxed::Box::new(provider))
}

pub fn broker_pipe_provider() -> Option<Arc<dyn BrokerPipeProvider>> {
    BROKER_PIPE_PROVIDER.get().cloned()
}

pub(crate) struct BrokerPipeSubsystem;
impl FdEnabledSubsystem for BrokerPipeSubsystem {
    type Entry = BrokerPipeFd<Platform>;
}

pub(crate) struct BrokerPipeFd<P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider> {
    provider: Arc<dyn BrokerPipeProvider>,
    common: BrokerBackedCommon<P>,
    direction: BrokerPipeEnd,
    status: AtomicU32,
    pollee: Arc<Pollee<P>>,
}

impl<P> BrokerPipeFd<P>
where
    P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider,
{
    pub(crate) fn new(
        provider: Arc<dyn BrokerPipeProvider>,
        handle: u64,
        direction: BrokerPipeEnd,
        flags: OFlags,
    ) -> Self {
        let access = match direction {
            BrokerPipeEnd::Read => OFlags::RDONLY,
            BrokerPipeEnd::Write => OFlags::WRONLY,
        };
        let subscribable: Arc<
            dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
        > = Arc::clone(&provider) as _;
        let common = BrokerBackedCommon::new(
            subscribable,
            handle,
            NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP | NOTIFY_EVENT_OUT | NOTIFY_EVENT_ERR,
        );
        Self {
            provider,
            common,
            direction,
            status: AtomicU32::new((access | (flags & OFlags::STATUS_FLAGS_MASK)).bits()),
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn handle(&self) -> u64 {
        self.common.handle()
    }

    pub(crate) fn direction(&self) -> BrokerPipeEnd {
        self.direction
    }

    pub(crate) fn get_status(&self) -> OFlags {
        OFlags::from_bits_truncate(self.status.load(Ordering::Relaxed)) & OFlags::STATUS_FLAGS_MASK
    }

    pub(crate) fn set_status(&self, flags: OFlags) {
        let access = self.get_status() & (OFlags::RDONLY | OFlags::WRONLY | OFlags::RDWR);
        self.status.store(
            (access | (flags & OFlags::STATUS_FLAGS_MASK)).bits(),
            Ordering::Relaxed,
        );
    }

    pub(crate) fn fork_snapshot_handle(&self) -> (BrokerHandleKind, u64) {
        (BrokerHandleKind::Pipe, self.handle())
    }
}

impl BrokerPipeFd<Platform> {
    pub(crate) fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &mut [u8],
    ) -> Result<usize, Errno> {
        if self.direction != BrokerPipeEnd::Read {
            return Err(Errno::EBADF);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        self.common.ensure_subscribed(&self.pollee);
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::IN, || {
                match self.provider.read_pipe(self.handle(), buf.len() as u64) {
                    Ok(bytes) => {
                        let n = bytes.len().min(buf.len());
                        buf[..n].copy_from_slice(&bytes[..n]);
                        if n == 0 {
                            self.common.set_readable(false);
                        }
                        Ok(n)
                    }
                    Err(BrokerOpError::WouldBlock) => {
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
        if self.direction != BrokerPipeEnd::Write {
            return Err(Errno::EBADF);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::OUT, || {
                match self.provider.write_pipe(self.handle(), buf) {
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
}

impl IOPollable for BrokerPipeFd<Platform> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        if self.direction == BrokerPipeEnd::Read {
            self.common.ensure_subscribed(&self.pollee);
        }
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        match self.direction {
            BrokerPipeEnd::Read => {
                self.common.check_io_events() & (Events::IN | Events::HUP | Events::ERR)
            }
            BrokerPipeEnd::Write => Events::OUT,
        }
    }
}

impl FdEnabledSubsystemEntry for BrokerPipeFd<Platform> {
    fn on_dup(&self) {
        let _ = self.provider.dup_handle(self.handle());
        let _ = self.provider.incref_pipe_end(self.handle(), self.direction);
    }

    fn on_close(&self) {
        self.provider.close_pipe_end(self.handle(), self.direction);
    }
}
