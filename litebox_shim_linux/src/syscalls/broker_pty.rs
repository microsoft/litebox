// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed pseudo-terminal file descriptors.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use litebox::{
    event::{Events, IOPollable, observer::Observer, polling::Pollee, wait::WaitContext},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{
    broker_pty_provider::{BrokerOpError, BrokerPtyProvider, BrokerPtyRole},
    cwfd::notification_frame::{
        NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
    },
    errno::Errno,
    fd_token_protocol::PtyIoctlOp,
};
use litebox_platform_multiplex::Platform;

use super::broker_backed::{BrokerBackedCommon, broker_err_to_errno};
use super::fork_snapshot::FdKind;

pub use super::eventfd::{broker_pty_provider, set_broker_pty_provider};

pub(crate) struct BrokerPtySubsystem;
impl FdEnabledSubsystem for BrokerPtySubsystem {
    const KIND: litebox::fd::SubsystemKind = litebox::fd::SubsystemKind::BrokerPty;

    type Entry = BrokerPtyFd<Platform>;
}

pub(crate) struct BrokerPtyFd<P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider> {
    provider: Arc<dyn BrokerPtyProvider>,
    common: BrokerBackedCommon<P>,
    pty_id: u32,
    is_master: bool,
    /// Extra reference that keeps the slave endpoint name-openable while a
    /// master fd exists. Present only on master fds and balanced in on_close.
    slave_anchor_handle: Option<u64>,
    status: AtomicU32,
    pollee: Arc<Pollee<P>>,
    /// Stage B invariant: per-slot balance. Starts at 1 (the slot the
    /// caller of `new` is about to install into). `on_dup` increments
    /// (each new fd-table slot sharing this Arc), `on_close` decrements.
    /// Going negative indicates an over-release: more `on_close` calls
    /// than slots, which is the shape of the IO-Safety abort we hit when
    /// Stage B deleted the legacy relay. The first negative observation
    /// panics with all the context (pty_id, handle, role) that a tokio
    /// IO-Safety abort lacks.
    slot_count: AtomicI32,
}

impl<P> BrokerPtyFd<P>
where
    P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider,
{
    pub(crate) fn new(
        provider: Arc<dyn BrokerPtyProvider>,
        handle: u64,
        pty_id: u32,
        is_master: bool,
        slave_anchor_handle: Option<u64>,
        flags: OFlags,
    ) -> Self {
        let access = OFlags::RDWR;
        let subscribable: Arc<
            dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
        > = Arc::clone(&provider) as _;
        let events_mask = NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT | NOTIFY_EVENT_HUP | NOTIFY_EVENT_ERR;
        let common = BrokerBackedCommon::new(subscribable, handle, events_mask);
        common.disable_release_on_drop();
        Self {
            provider,
            common,
            pty_id,
            is_master,
            slave_anchor_handle,
            status: AtomicU32::new((access | (flags & OFlags::STATUS_FLAGS_MASK)).bits()),
            pollee: Arc::new(Pollee::new()),
            slot_count: AtomicI32::new(1),
        }
    }

    pub(crate) fn handle(&self) -> u64 {
        self.common.handle()
    }

    pub(crate) fn pty_id(&self) -> u32 {
        self.pty_id
    }

    pub(crate) fn is_master(&self) -> bool {
        self.is_master
    }

    pub(crate) fn role(&self) -> BrokerPtyRole {
        if self.is_master {
            BrokerPtyRole::Master
        } else {
            BrokerPtyRole::Slave
        }
    }

    pub(crate) fn get_status(&self) -> OFlags {
        OFlags::from_bits_truncate(self.status.load(Ordering::Relaxed)) & OFlags::STATUS_FLAGS_MASK
    }

    pub(crate) fn set_status(&self, flags: OFlags) {
        let access = OFlags::RDWR;
        self.status.store(
            (access | (flags & OFlags::STATUS_FLAGS_MASK)).bits(),
            Ordering::Relaxed,
        );
    }

    pub(crate) fn fork_snapshot_handle(&self) -> FdKind {
        FdKind::BrokerPty {
            handle_id: self.handle(),
            role: self.role(),
            pty_id: Some(self.pty_id()),
        }
    }
}

pub(crate) trait BrokerPtyProviderReacquireExt {
    fn reacquire(
        &self,
        handle_id: u64,
        role: BrokerPtyRole,
        pty_id: Option<u32>,
    ) -> Result<BrokerPtyFd<Platform>, BrokerOpError>;
}

impl BrokerPtyProviderReacquireExt for Arc<dyn BrokerPtyProvider> {
    fn reacquire(
        &self,
        handle_id: u64,
        role: BrokerPtyRole,
        pty_id: Option<u32>,
    ) -> Result<BrokerPtyFd<Platform>, BrokerOpError> {
        self.dup_handle(handle_id)?;
        let pty_id = if let Some(pty_id) = pty_id {
            pty_id
        } else {
            let pty_id_payload = match self.ioctl_pty(handle_id, PtyIoctlOp::Tiocgptn, &[]) {
                Ok(payload) => payload,
                Err(err) => {
                    self.release(handle_id);
                    return Err(err);
                }
            };
            let Some(pty_id_bytes) = pty_id_payload.get(..4) else {
                self.release(handle_id);
                return Err(BrokerOpError::InvalidValue);
            };
            u32::from_le_bytes(pty_id_bytes.try_into().map_err(|_| {
                self.release(handle_id);
                BrokerOpError::InvalidValue
            })?)
        };
        let is_master = role == BrokerPtyRole::Master;
        let slave_anchor_handle = if is_master {
            self.open_pty_slave(pty_id).ok()
        } else {
            None
        };
        Ok(BrokerPtyFd::<Platform>::new(
            Arc::clone(self),
            handle_id,
            pty_id,
            is_master,
            slave_anchor_handle,
            OFlags::empty(),
        ))
    }
}

impl BrokerPtyFd<Platform> {
    /// Eagerly install the broker subscription. Called from
    /// `open_broker_pty_path` after constructing the BrokerPtyFd so
    /// that `poll(fd, POLLIN|POLLHUP, 0)` returns current state
    /// without requiring a prior read/write to trigger lazy
    /// subscription. Especially important for the master fd:
    /// dropbear's session-end loop polls the master without first
    /// reading; without eager subscription, the broker's HUP
    /// notification (set when the slave closes) never reaches the
    /// shim's pollee.
    pub(crate) fn ensure_subscribed_eager(&self) {
        self.common.ensure_subscribed(&self.pollee);
    }

    pub(crate) fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &mut [u8],
    ) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.common.ensure_subscribed(&self.pollee);
        let capped_len = core::cmp::min(buf.len(), 60 * 1024);
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::IN, || {
                match self.provider.read_pty(self.handle(), capped_len as u32) {
                    Ok(bytes) => {
                        let n = bytes.len().min(buf.len());
                        buf[..n].copy_from_slice(&bytes[..n]);
                        if n == 0 {}
                        Ok(n)
                    }
                    Err(BrokerOpError::WouldBlock) => {
                        Err(litebox::event::polling::TryOpError::TryAgain)
                    }
                    Err(e) => Err(litebox::event::polling::TryOpError::Other(
                        Self::broker_pty_error_to_errno(e),
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
        self.common.ensure_subscribed(&self.pollee);
        let to_write = core::cmp::min(buf.len(), 60 * 1024);
        let chunk = &buf[..to_write];
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::OUT, || {
                match self.provider.write_pty(self.handle(), chunk) {
                    Ok(n) => Ok(n as usize),
                    Err(BrokerOpError::WouldBlock) => {
                        Err(litebox::event::polling::TryOpError::TryAgain)
                    }
                    Err(e) => Err(litebox::event::polling::TryOpError::Other(
                        Self::broker_pty_error_to_errno(e),
                    )),
                }
            })
            .map_err(|e| match e {
                litebox::event::polling::TryOpError::TryAgain => Errno::EAGAIN,
                litebox::event::polling::TryOpError::WaitError(_) => Errno::EINTR,
                litebox::event::polling::TryOpError::Other(errno) => errno,
            })
    }

    pub(crate) fn ioctl(&self, op: PtyIoctlOp, payload: &[u8]) -> Result<Vec<u8>, Errno> {
        self.provider
            .ioctl_pty(self.handle(), op, payload)
            .map_err(Self::broker_pty_error_to_errno)
    }

    pub(crate) fn broker_pty_error_to_errno(err: BrokerOpError) -> Errno {
        match err {
            BrokerOpError::InvalidValue => Errno::EINVAL,
            BrokerOpError::UnknownHandle => Errno::ENOTTY,
            BrokerOpError::WouldBlock => Errno::EAGAIN,
            BrokerOpError::PermissionDenied | BrokerOpError::ProtocolNotSupported => {
                broker_err_to_errno(err)
            }
            BrokerOpError::Io => broker_err_to_errno(err),
        }
    }
}

impl IOPollable for BrokerPtyFd<Platform> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.common.ensure_subscribed(&self.pollee);
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.common.check_io_events() & (Events::IN | Events::OUT | Events::HUP | Events::ERR)
    }
}

impl FdEnabledSubsystemEntry for BrokerPtyFd<Platform> {
    fn on_dup(&self) {
        self.slot_count.fetch_add(1, Ordering::SeqCst);
        let _ = self.provider.dup_handle(self.handle());
        if let Some(handle) = self.slave_anchor_handle {
            let _ = self.provider.dup_handle(handle);
        }
    }

    fn on_close(&self) {
        // Stage B invariant: catch over-release at the source rather than
        // letting the downstream broker double-free corrupt host-fd
        // accounting (which surfaces as a tokio IO-Safety abort on a
        // recycled fd with no useful backtrace).
        let prev = self.slot_count.fetch_sub(1, Ordering::SeqCst);
        assert!(
            prev > 0,
            "BrokerPtyFd over-release: on_close called with slot_count={} \
             (pty_id={}, is_master={}, handle={}, anchor={:?})",
            prev,
            self.pty_id,
            self.is_master,
            self.common.handle(),
            self.slave_anchor_handle,
        );
        // When the last shim slot is closing, force-unsubscribe BEFORE
        // the final Release so the broker-side PtyState (whose Drop
        // strictly asserts subscription list is empty) doesn't see a
        // dangling subscription. Without this, on_close's Release racing
        // BrokerBackedCommon::Drop's Unsubscribe trips PE.9 invariant.
        if prev == 1 {
            self.common.force_unsubscribe();
        }
        self.provider.release(self.handle());
        if let Some(handle) = self.slave_anchor_handle {
            self.provider.release(handle);
        }
    }
}
