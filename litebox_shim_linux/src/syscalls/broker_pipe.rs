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
        // Each pipe end has its own broker state-registry handle, so
        // subscribe/unsubscribe/release/dup_handle on this handle
        // unambiguously address THIS end. No direction wrapper needed.
        let subscribable: Arc<
            dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
        > = Arc::clone(&provider) as _;
        // Event mask per end: readers care about IN/HUP/ERR; writers
        // care about OUT/ERR (a closed reader manifests as ERR/EPIPE
        // here, not HUP).
        let events_mask = match direction {
            BrokerPipeEnd::Read => NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP | NOTIFY_EVENT_ERR,
            BrokerPipeEnd::Write => NOTIFY_EVENT_OUT | NOTIFY_EVENT_ERR,
        };
        let common = BrokerBackedCommon::new(subscribable, handle, events_mask);
        // Per-slot refcount model: each fd-table slot that references
        // this BrokerPipeFd contributes one registry refcount on the
        // broker. `on_dup` bumps via `dup_handle`; `on_close` (called
        // per slot removal by `descriptor_table::remove`) balances via
        // `release`. Suppress `BrokerBackedCommon::Drop`'s own release
        // to avoid double-release — the per-slot `on_close` already
        // released for every slot that ever existed.
        common.disable_release_on_drop();
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
        // Phase C.5c: cap the requested read length to fit within
        // the wire codec's BODY_MAX. The response body is
        // `ReadPipeResponse { bytes_len: u32, bytes: [u8] }`, so
        // payload must be <= BODY_MAX - 4. Use a 60 KB chunk to
        // mirror the write path. The guest's read loop will iterate
        // for larger transfers.
        const READ_PIPE_CHUNK: usize = 60 * 1024;
        let capped_len = core::cmp::min(buf.len(), READ_PIPE_CHUNK);
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::IN, || {
                match self.provider.read_pipe(self.handle(), capped_len as u64) {
                    Ok(bytes) => {
                        let n = bytes.len().min(buf.len());
                        buf[..n].copy_from_slice(&bytes[..n]);
                        if n == 0 {
                            self.common.set_readable(false);
                        }
                        Ok(n)
                    }
                    Err(BrokerOpError::WouldBlock) => {
                        // C.5k: clear the pollee's readable flag so a
                        // subsequent ppoll without a fresh broker IN
                        // notification doesn't immediately return
                        // ready (livelock observed under eager_broker=true
                        // for PIDF.exit_self.{pie-glibc, ...} — broker
                        // pipe wakes on write, reader drains, pollee
                        // state stayed "readable" because only n==0
                        // (EOF) cleared it).
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
        if self.direction != BrokerPipeEnd::Write {
            return Err(Errno::EBADF);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        // Phase C.5b: ensure broker-side subscription exists so the
        // write pollee wakes when the reader drains the pipe (OUT)
        // or closes (ERR). Without this, writes that block on full
        // capacity never wake. Direction-aware unsubscribe (added in
        // the same change) prevents this from accidentally stripping
        // a peer worker's read subscription on Drop.
        self.common.ensure_subscribed(&self.pollee);
        // Phase C.5c: cap each RPC at WRITE_PIPE_CHUNK bytes. The wire
        // codec (`fd_token_protocol::BODY_MAX`) caps frame bodies at
        // 64 KB and writes larger than that fail with `BodyTooLarge`
        // (surfaced to the shim as `BrokerOpError::InvalidValue`,
        // which we map to EPIPE — wrong but historically observed).
        // The write_pipe request body is `handle_id (u64) + bytes`,
        // so safe payload is `BODY_MAX - 8`. We round down to 60 KB
        // for a comfortable margin and to match the MUX_MAX_PAYLOAD
        // constant used elsewhere. Returning a partial byte count to
        // the guest is normal Linux write(2) semantics for non-atomic
        // writes (any write > PIPE_BUF/4096 is non-atomic).
        const WRITE_PIPE_CHUNK: usize = 60 * 1024;
        let to_write = core::cmp::min(buf.len(), WRITE_PIPE_CHUNK);
        let chunk = &buf[..to_write];
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::OUT, || {
                match self.provider.write_pipe(self.handle(), chunk) {
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
        // Per-slot registry refcount: each new fd-table slot pointing
        // to this BrokerPipeFd contributes +1 to the broker
        // registry refcount. Balanced by `on_close` on slot removal.
        let _ = self.provider.dup_handle(self.handle());
    }

    fn on_close(&self) {
        // Per-slot release: every removal of an fd-table slot
        // referencing this BrokerPipeFd decrements the broker
        // registry refcount. When the last slot is removed, the
        // broker StateObject Drops and notifies the OTHER end's
        // subscribers (HUP → reader EOF, ERR → writer EPIPE).
        self.provider.release(self.handle());
    }
}
