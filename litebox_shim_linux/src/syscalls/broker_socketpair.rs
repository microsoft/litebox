// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed AF_UNIX SOCK_STREAM socketpair file descriptors for
//! cross-worker fork inheritance.
//!
//! Each endpoint of a socketpair is its own broker state-registry entry
//! and gets its own [`BrokerSocketPairFd`] in the shim. Unlike pipes,
//! both endpoints are bidirectional — each can both read AND write.
//! The endpoint identity (A or B) is carried in the shim purely to
//! reconstruct the correct broker handle after fork+exec snapshot
//! serialization; on the broker side, operations are routed by
//! handle alone (so reads/writes don't carry an endpoint byte on the
//! wire).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use litebox::{
    event::{Events, IOPollable, observer::Observer, polling::Pollee, wait::WaitContext},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{
    broker_socketpair_provider::{
        BrokerOpError, BrokerSocketPairEndpoint, BrokerSocketPairProvider,
    },
    cwfd::notification_frame::{
        NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
    },
    errno::Errno,
};
use litebox_platform_multiplex::Platform;

use super::broker_backed::{BrokerBackedCommon, broker_err_to_errno};
use super::fork_snapshot::BrokerHandleSnapshot;

static BROKER_SOCKETPAIR_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerSocketPairProvider>> =
    once_cell::race::OnceBox::new();

pub fn set_broker_socketpair_provider(
    provider: Arc<dyn BrokerSocketPairProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerSocketPairProvider>>> {
    BROKER_SOCKETPAIR_PROVIDER.set(alloc::boxed::Box::new(provider))
}

pub fn broker_socketpair_provider() -> Option<Arc<dyn BrokerSocketPairProvider>> {
    BROKER_SOCKETPAIR_PROVIDER.get().cloned()
}

pub(crate) struct BrokerSocketPairSubsystem;
impl FdEnabledSubsystem for BrokerSocketPairSubsystem {
    const KIND: litebox::fd::SubsystemKind = litebox::fd::SubsystemKind::BrokerSocketPair;

    type Entry = BrokerSocketPairFd<Platform>;
}

pub(crate) struct BrokerSocketPairFd<P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider>
{
    provider: Arc<dyn BrokerSocketPairProvider>,
    common: BrokerBackedCommon<P>,
    endpoint: BrokerSocketPairEndpoint,
    status: AtomicU32,
    /// `shutdown(fd, SHUT_RD)` was called on this `BrokerSocketPairFd`
    /// instance. Used to short-circuit `read()` to EOF without an RPC.
    ///
    /// **Known divergence from Linux:** in real Linux, `shutdown(2)`
    /// affects the underlying socket, so all dup'd fds observe it on
    /// subsequent ops. Here the flag lives per-`BrokerSocketPairFd`
    /// instance — if a guest dup'd this fd and the dup landed in a
    /// separate `BrokerSocketPairFd`, that dup's reads would not see
    /// the shutdown. This is the same class of hazard the Phase H fix
    /// addressed for PTY readiness: shim-side caches of broker-held
    /// state can drift. Listed in `files/cache-audit.md` (item B);
    /// proper fix is to push shutdown state into the broker
    /// `SocketPairEnd` and replace these AtomicBools with synchronous
    /// queries (parallel to `BrokerBackedCommon::check_io_events`).
    read_shutdown: AtomicBool,
    write_shutdown: AtomicBool,
    pollee: Arc<Pollee<P>>,
}

impl<P> BrokerSocketPairFd<P>
where
    P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider,
{
    /// Constructs a BrokerSocketPairFd wrapping an existing broker
    /// socketpair handle.
    ///
    /// ## STRUCTURAL INVARIANT — caller responsibility
    ///
    /// **Every `BrokerSocketPairFd::new` call MUST be paired with a
    /// prior `provider.dup_handle(handle)`** (or be the initial
    /// `create_socketpair` consumer whose refcount=1 baseline
    /// suffices). `on_close` ALWAYS fires `provider.release(handle)`;
    /// unpaired construction is a structural bug. See
    /// `broker_pipe::BrokerPipeFd::new`'s doc comment for the
    /// detailed rationale and the PE.13 historical precedent.
    pub(crate) fn new(
        provider: Arc<dyn BrokerSocketPairProvider>,
        handle: u64,
        endpoint: BrokerSocketPairEndpoint,
        flags: OFlags,
    ) -> Self {
        // Socketpair endpoints are bidirectional — open as RDWR.
        let access = OFlags::RDWR;
        let subscribable: Arc<
            dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
        > = Arc::clone(&provider) as _;
        // Both endpoints care about IN (peer wrote), OUT (peer drained,
        // we have room), HUP (peer closed), ERR (write would EPIPE).
        let events_mask = NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT | NOTIFY_EVENT_HUP | NOTIFY_EVENT_ERR;
        let common = BrokerBackedCommon::new(subscribable, handle, events_mask);
        // Per-slot refcount model (same as broker pipe): on_dup bumps
        // via dup_handle, on_close balances via release. Suppress
        // BrokerBackedCommon::Drop's own release.
        common.disable_release_on_drop();
        Self {
            provider,
            common,
            endpoint,
            status: AtomicU32::new((access | (flags & OFlags::STATUS_FLAGS_MASK)).bits()),
            read_shutdown: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn handle(&self) -> u64 {
        self.common.handle()
    }

    pub(crate) fn endpoint(&self) -> BrokerSocketPairEndpoint {
        self.endpoint
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

    pub(crate) fn fork_snapshot_handle(&self) -> BrokerHandleSnapshot {
        BrokerHandleSnapshot::UnixSocket {
            handle_id: self.handle(),
            endpoint: self.endpoint,
        }
    }
}

impl BrokerSocketPairFd<Platform> {
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
        // Wire codec response body for ReadSocketPair is
        // (len: u32, pad: u32, bytes...) — overhead 8 bytes. Cap each
        // RPC at 60 KB for a comfortable margin under BODY_MAX (64 KB),
        // matching the pipe-side READ_PIPE_CHUNK convention.
        const READ_SOCKETPAIR_CHUNK: usize = 60 * 1024;
        let capped_len = core::cmp::min(buf.len(), READ_SOCKETPAIR_CHUNK);
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::IN, || {
                match self
                    .provider
                    .read_socketpair(self.handle(), capped_len as u64)
                {
                    Ok(bytes) => {
                        let n = bytes.len().min(buf.len());
                        buf[..n].copy_from_slice(&bytes[..n]);
                        if n == 0 {}
                        Ok(n)
                    }
                    Err(BrokerOpError::WouldBlock) => {
                        // Mirror C.5k pipe fix: clear pollee readable
                        // so ppoll doesn't livelock without fresh IN.
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

    pub(crate) fn shutdown(&self, read: bool, write: bool) -> Result<(), Errno> {
        if read {
            self.read_shutdown.store(true, Ordering::Release);
        }
        if write && !self.write_shutdown.swap(true, Ordering::AcqRel) {
            self.provider
                .shutdown_socketpair_write(self.handle())
                .map_err(broker_err_to_errno)?;
        }
        Ok(())
    }

    pub(crate) fn write(&self, cx: &WaitContext<'_, Platform>, buf: &[u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.write_shutdown.load(Ordering::Acquire) {
            return Err(Errno::EPIPE);
        }
        self.common.ensure_subscribed(&self.pollee);
        // WriteSocketPair body overhead = 16 bytes (handle_id u64 +
        // len u32 + pad u32). Safe payload up to BODY_MAX - 16; 60 KB
        // chunk for parity with pipe.
        const WRITE_SOCKETPAIR_CHUNK: usize = 60 * 1024;
        let to_write = core::cmp::min(buf.len(), WRITE_SOCKETPAIR_CHUNK);
        let chunk = &buf[..to_write];
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::OUT, || {
                match self.provider.write_socketpair(self.handle(), chunk) {
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

impl IOPollable for BrokerSocketPairFd<Platform> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.common.ensure_subscribed(&self.pollee);
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        // Bidi: report whatever IN/OUT/HUP/ERR the common tracker
        // sees. Unlike pipes (Read end reports IN/HUP/ERR only;
        // Write end reports OUT only), both endpoints care about
        // all four.
        self.common.check_io_events() & (Events::IN | Events::OUT | Events::HUP | Events::ERR)
    }
}

impl FdEnabledSubsystemEntry for BrokerSocketPairFd<Platform> {
    fn on_dup(&self) {
        let _ = self.provider.dup_handle(self.handle());
    }

    fn on_close(&self) {
        self.provider.release(self.handle());
    }
}
