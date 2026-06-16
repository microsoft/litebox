// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed AF_UNIX SOCK_DGRAM sockets.
//!
//! Foundation support covers bind, sendto/recvfrom with source addresses,
//! datagram truncation, connect, nonblocking waits, shutdown, and fork-restore
//! inheritance. `SCM_RIGHTS` is supported for broker-token-backed descriptors
//! (files, pipes, and broker AF_UNIX datagram sockets). `SCM_CREDENTIALS` is
//! still deferred because credential passing has authentication implications.

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
    broker_socket_dgram_provider::{BrokerOpError, BrokerSocketDgramProvider},
    cwfd::{
        broker_subscribable::BrokerSubscribable,
        fd_token_protocol::SOCKET_DGRAM_RECV_FLAG_TRUNC,
        notification_frame::{
            NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
        },
    },
    errno::Errno,
};
use litebox_platform_multiplex::Platform;

use super::{
    broker_backed::{BrokerBackedCommon, broker_err_to_errno},
    fork_snapshot::FdKind,
    unix::UnixSocketAddr,
};

static BROKER_SOCKET_DGRAM_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerSocketDgramProvider>> =
    once_cell::race::OnceBox::new();

pub fn set_broker_socket_dgram_provider(
    provider: Arc<dyn BrokerSocketDgramProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerSocketDgramProvider>>> {
    BROKER_SOCKET_DGRAM_PROVIDER.set(alloc::boxed::Box::new(provider))
}

pub fn broker_socket_dgram_provider() -> Option<Arc<dyn BrokerSocketDgramProvider>> {
    BROKER_SOCKET_DGRAM_PROVIDER.get().cloned()
}

pub(crate) struct BrokerSocketDgramSubsystem;
impl FdEnabledSubsystem for BrokerSocketDgramSubsystem {
    const KIND: litebox::fd::SubsystemKind = litebox::fd::SubsystemKind::BrokerSocketDgram;
    type Entry = BrokerSocketDgramFd<Platform>;
}

pub(crate) struct BrokerSocketDgramFd<
    P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider,
> {
    provider: Arc<dyn BrokerSocketDgramProvider>,
    common: BrokerBackedCommon<P>,
    status: AtomicU32,
    read_shutdown: AtomicBool,
    write_shutdown: AtomicBool,
    pollee: Arc<Pollee<P>>,
}

impl<P> BrokerSocketDgramFd<P>
where
    P: RawSyncPrimitivesProvider + litebox::platform::TimeProvider,
{
    pub(crate) fn new(
        provider: Arc<dyn BrokerSocketDgramProvider>,
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

    #[allow(dead_code)]
    pub(crate) fn set_status(&self, flags: OFlags) {
        self.status.store(
            (OFlags::RDWR | (flags & OFlags::STATUS_FLAGS_MASK)).bits(),
            Ordering::Relaxed,
        );
    }

    pub(crate) fn fork_snapshot_handle(&self) -> FdKind {
        FdKind::BrokerSocketDgram {
            handle_id: self.handle(),
        }
    }
}

impl BrokerSocketDgramFd<Platform> {
    pub(crate) fn bind(&self, addr: UnixSocketAddr) -> Result<UnixSocketAddr, Errno> {
        let raw = encode_unix_addr(&addr);
        self.provider
            .bind(self.handle(), &raw)
            .map_err(broker_err_to_errno)
            .and_then(|raw| decode_unix_addr(&raw))
    }

    pub(crate) fn connect(&self, addr: UnixSocketAddr) -> Result<(), Errno> {
        let raw = encode_unix_addr(&addr);
        self.provider
            .connect(self.handle(), &raw)
            .map_err(broker_err_to_errno)
    }

    pub(crate) fn sendto(
        &self,
        cx: &WaitContext<'_, Platform>,
        addr: Option<UnixSocketAddr>,
        payload: &[u8],
        tokens: &[litebox_common_linux::cwfd::fd_transfer_frame::PassedToken],
    ) -> Result<usize, Errno> {
        if self.write_shutdown.load(Ordering::Acquire) {
            return Err(Errno::EPIPE);
        }
        self.common.ensure_subscribed(&self.pollee);
        let raw = addr
            .as_ref()
            .map_or_else(alloc::vec::Vec::new, encode_unix_addr);
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::OUT, || {
                match self.provider.sendto(self.handle(), &raw, payload, tokens) {
                    Ok(n) => Ok(n),
                    Err(BrokerOpError::WouldBlock) => Err(TryOpError::TryAgain),
                    Err(e) => Err(TryOpError::Other(broker_err_to_errno(e))),
                }
            })
            .map_err(map_try_op_err)
    }

    pub(crate) fn recvfrom(
        &self,
        cx: &WaitContext<'_, Platform>,
        max_len: u32,
    ) -> Result<
        (
            UnixSocketAddr,
            alloc::vec::Vec<u8>,
            u32,
            alloc::vec::Vec<litebox_common_linux::cwfd::fd_transfer_frame::PassedToken>,
        ),
        Errno,
    > {
        if self.read_shutdown.load(Ordering::Acquire) {
            return Ok((
                UnixSocketAddr::Unnamed,
                alloc::vec::Vec::new(),
                0,
                alloc::vec::Vec::new(),
            ));
        }
        self.common.ensure_subscribed(&self.pollee);
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        self.pollee
            .wait(cx, nonblock, Events::IN, || {
                match self.provider.recvfrom(self.handle(), max_len) {
                    Ok((raw, payload, flags, tokens)) => decode_unix_addr(&raw)
                        .map(|addr| (addr, payload, flags, tokens))
                        .map_err(TryOpError::Other),
                    Err(BrokerOpError::WouldBlock) => Err(TryOpError::TryAgain),
                    Err(e) => Err(TryOpError::Other(broker_err_to_errno(e))),
                }
            })
            .map_err(map_try_op_err)
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

    pub(crate) fn getsockname(&self) -> Result<UnixSocketAddr, Errno> {
        self.provider
            .getsockname(self.handle())
            .map_err(broker_err_to_errno)
            .and_then(|raw| decode_unix_addr(&raw))
    }

    pub(crate) fn getpeername(&self) -> Result<UnixSocketAddr, Errno> {
        self.provider
            .getpeername(self.handle())
            .map_err(broker_err_to_errno)
            .and_then(|raw| decode_unix_addr(&raw))
    }
}

impl IOPollable for BrokerSocketDgramFd<Platform> {
    fn check_io_events(&self) -> Events {
        match BrokerSocketDgramProvider::query_events(&*self.provider, self.handle()) {
            Ok(events) => Events::from_bits_truncate(events),
            Err(_) => self.common.check_io_events(),
        }
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.common.ensure_subscribed(&self.pollee);
        self.pollee.register_observer(observer, mask);
    }
}

impl FdEnabledSubsystemEntry for BrokerSocketDgramFd<Platform> {
    fn on_dup(&self) {
        let _ = self.provider.dup_handle(self.handle());
    }
    fn on_close(&self) {
        self.common.force_unsubscribe();
        self.provider.release(self.handle());
    }
}

fn map_try_op_err(e: TryOpError<Errno>) -> Errno {
    match e {
        TryOpError::TryAgain => Errno::EAGAIN,
        TryOpError::WaitError(_) => Errno::EINTR,
        TryOpError::Other(errno) => errno,
    }
}

pub(crate) fn encode_unix_addr(addr: &UnixSocketAddr) -> alloc::vec::Vec<u8> {
    let (kind, bytes): (u8, &[u8]) = match addr {
        UnixSocketAddr::Unnamed => (0, &[]),
        UnixSocketAddr::Path(path) => (1, path.as_bytes()),
        UnixSocketAddr::Abstract(name) => (2, name),
    };
    let mut out = alloc::vec::Vec::with_capacity(5 + bytes.len());
    out.push(kind);
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

pub(crate) fn decode_unix_addr(raw: &[u8]) -> Result<UnixSocketAddr, Errno> {
    if raw.len() < 5 {
        return Err(Errno::EINVAL);
    }
    let kind = raw[0];
    let len = u32::from_le_bytes(raw[1..5].try_into().unwrap()) as usize;
    if raw.len() != 5 + len {
        return Err(Errno::EINVAL);
    }
    let bytes = raw[5..].to_vec();
    match kind {
        0 if bytes.is_empty() => Ok(UnixSocketAddr::Unnamed),
        1 => alloc::string::String::from_utf8(bytes)
            .map(UnixSocketAddr::Path)
            .map_err(|_| Errno::EINVAL),
        2 => Ok(UnixSocketAddr::Abstract(bytes)),
        _ => Err(Errno::EINVAL),
    }
}

pub(crate) fn recv_truncated(flags: u32) -> bool {
    (flags & SOCKET_DGRAM_RECV_FLAG_TRUNC) != 0
}
