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

use super::broker_backed::{BrokerBackedCommon, BrokerEdgeResetState, broker_err_to_errno};
use super::fork_snapshot::FdKind;

static BROKER_PIPE_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerPipeProvider>> =
    once_cell::race::OnceBox::new();

/// PE.14: gate for the per-slot "closed without reading" diagnostic
/// log in `BrokerPipeFd::on_close`. Default off (noisy). Set by the
/// runner from `LITEBOX_PE14_SLOT_DIAG=1`.
static SHIM_SLOT_DIAG_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub fn set_shim_slot_diag_enabled(enabled: bool) {
    SHIM_SLOT_DIAG_ENABLED.store(enabled, core::sync::atomic::Ordering::Release);
}

#[inline]
pub fn shim_slot_diag_enabled() -> bool {
    SHIM_SLOT_DIAG_ENABLED.load(core::sync::atomic::Ordering::Acquire)
}

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
    const KIND: litebox::fd::SubsystemKind = litebox::fd::SubsystemKind::BrokerPipe;

    type Entry = BrokerPipeFd<Platform>;
}

pub(crate) struct BrokerPipeFd<P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider> {
    provider: Arc<dyn BrokerPipeProvider>,
    common: BrokerBackedCommon<P>,
    direction: BrokerPipeEnd,
    status: AtomicU32,
    pollee: Arc<Pollee<P>>,
    // PE.14 invariant: count read_pipe RPCs issued through this fd
    // (for the Read direction). On on_close, if this is a Read end
    // with read_count=0 AND the broker side reported buffered data,
    // we have a "reader closed without reading" data-loss bug.
    read_count: AtomicU32,
    // PE.14 diag: creation-site tag for orphan-slot identification.
    // 0=sys_pipe2, 1=install_broker_bridge_fd,
    // 2=fork_snapshot_restore, 3=SCM_RIGHTS.
    creation_site: u8,
    edge_reset: Arc<BrokerEdgeResetState>,
}

impl<P> BrokerPipeFd<P>
where
    P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider,
{
    /// Constructs a BrokerPipeFd wrapping an existing broker pipe
    /// handle.
    ///
    /// ## STRUCTURAL INVARIANT — caller responsibility
    ///
    /// **Every `BrokerPipeFd::new` call MUST be paired with a prior
    /// `provider.dup_handle(handle)` (or its equivalent: an initial
    /// `create_pipe` that returns the handle with refcount=1, or an
    /// install_broker_bridge_fd's dup_handle).** This is because
    /// `BrokerPipeFd`'s `on_close` (called when an fd-table slot
    /// referring to it is removed) ALWAYS fires
    /// `provider.release(handle)`. If construction wasn't paired with
    /// a dup, the release leaves the broker side with negative net
    /// rc accounting (and under PE.9's strict per-conn ownership
    /// check, triggers a PROTOCOL VIOLATION that closes the broker
    /// conn).
    ///
    /// Current construction sites and their refcount pairing:
    /// - `syscalls/file.rs` `sys_pipe2`: `create_pipe` returns each end with
    ///   refcount=1; the read and write `BrokerPipeFd`s consume those baselines.
    /// - `syscalls/net.rs` NETLINK sentinel: `create_pipe` returns refcount=1;
    ///   the unused write end is released immediately and the read fd consumes
    ///   the read baseline.
    /// - `LinuxShimEntrypoints::install_broker_bridge_fd` in `lib.rs`: calls
    ///   `dup_handle` before constructing the receiving fd-table slot.
    /// - fork-snapshot restore in `lib.rs`: calls `dup_handle` before creating
    ///   the child-side restored `BrokerPipeFd`.
    /// - SCM_RIGHTS receive in `syscalls/net.rs`: calls `dup_handle` before
    ///   installing the received pipe endpoint; descriptor-table removal balances
    ///   the dup on local install failure.
    /// - D5 vpipe parent install in `syscalls/process.rs`: `create_pipe`
    ///   provides the first parent end's baseline; additional parent aliases
    ///   call `dup_handle`; failure before install releases all baselines/dups.
    ///
    /// If you add another construction site, AUDIT the caller for a successful
    /// matching `dup_handle` or one of the documented baseline-1 sources above,
    /// and verify every post-dup/pre-install error path releases or removes the
    /// partially-installed fd.
    /// Per PE.14 instrumentation: `creation_site` is a small tag
    /// (0=sys_pipe2-equivalent baseline, 1=install_broker_bridge_fd,
    /// 2=fork_snapshot_restore, 3=SCM_RIGHTS, 4=D5-vpipe parent install)
    /// recorded on this slot. When `on_close` fires with
    /// read_count==0 (orphan read-end), the tag is logged so we can
    /// identify which construction path produced the orphan slot.
    pub(crate) fn new(
        provider: Arc<dyn BrokerPipeProvider>,
        handle: u64,
        direction: BrokerPipeEnd,
        flags: OFlags,
        creation_site: u8,
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
        let edge_reset = Arc::new(BrokerEdgeResetState::new());
        let common = BrokerBackedCommon::new_edge_tracked(
            subscribable,
            handle,
            events_mask,
            Arc::clone(&edge_reset),
        );
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
            read_count: AtomicU32::new(0),
            creation_site,
            edge_reset,
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

    pub(crate) fn fork_snapshot_handle(&self) -> FdKind {
        FdKind::BrokerPipe {
            handle_id: self.handle(),
            direction: self.direction,
        }
    }

    pub(crate) fn read_edge_reset_generation(&self) -> u64 {
        self.edge_reset.read_generation()
    }

    pub(crate) fn write_edge_reset_generation(&self) -> u64 {
        self.edge_reset.write_generation()
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
        // HypB timing diag: log entry to read to detect when the
        // parent's read(ready[0]) actually fires.
        {
            use litebox::platform::DebugLogProvider as _;
            use litebox::platform::TimeProvider as _;
            let t = litebox_platform_multiplex::platform().monotonic_timestamp();
            let host_pid = unsafe { ::syscalls::raw::syscall0(::syscalls::Sysno::getpid) };
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "[HypB-read-entry] host_pid={} handle={} t_ns={}\n",
                host_pid,
                self.handle(),
                t.map(|d| d.as_nanos()).unwrap_or(0),
            ));
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
                self.read_count.fetch_add(1, Ordering::Relaxed);
                match self.provider.read_pipe(self.handle(), capped_len as u64) {
                    Ok(bytes) => {
                        let n = bytes.len().min(buf.len());
                        buf[..n].copy_from_slice(&bytes[..n]);
                        if n == 0 {}
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
                        self.edge_reset.note_write_would_block();
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
        // HypB timing diag: log close on the parent-side ready pipe
        // write end (and similar) so we can detect 2-second close
        // latencies.
        {
            use litebox::platform::DebugLogProvider as _;
            use litebox::platform::TimeProvider as _;
            let t = litebox_platform_multiplex::platform().monotonic_timestamp();
            let host_pid = unsafe { ::syscalls::raw::syscall0(::syscalls::Sysno::getpid) };
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "[HypB-close-timing] host_pid={} handle={} dir={:?} t_ns={}\n",
                host_pid,
                self.handle(),
                self.direction,
                t.map(|d| d.as_nanos()).unwrap_or(0),
            ));
        }
        // Per-slot release: every removal of an fd-table slot
        // referencing this BrokerPipeFd decrements the broker
        // registry refcount. When the last slot is removed, the
        // broker StateObject Drops and notifies the OTHER end's
        // subscribers (HUP → reader EOF, ERR → writer EPIPE).
        //
        // PE.14 invariant: per-slot "closed without reading" diag is
        // noisy (fires on legitimate inherited fds). The broker side
        // owns the authoritative data-loss check (PipeReadEnd::drop
        // now distinguishes real loss vs legitimate non-drain).
        // Keep this gated on LITEBOX_PE14_SLOT_DIAG for deep traces.
        if self.direction == BrokerPipeEnd::Read
            && self.read_count.load(Ordering::Relaxed) == 0
            && shim_slot_diag_enabled()
        {
            // SAFETY: getpid is always safe.
            let host_pid = unsafe { ::syscalls::raw::syscall0(::syscalls::Sysno::getpid) };
            litebox::log_println!(
                litebox_platform_multiplex::platform(),
                "[PE.14-diag] BrokerPipeFd READ-END CLOSED WITHOUT READING handle={} creation_site={} host_pid={host_pid}",
                self.handle(),
                self.creation_site,
            );
        }
        self.provider.release(self.handle());
    }
}
