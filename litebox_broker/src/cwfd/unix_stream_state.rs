// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted AF_UNIX SOCK_STREAM (named) state.
//!
//! This is the first-class, broker-backed implementation of *named* AF_UNIX
//! stream sockets (`bind(path)` → `listen` → `accept`, and `connect(path)`),
//! replacing the legacy shim-local `UnixSocketSubsystem` that bridged
//! cross-worker connections over a broker TCP connection with sidecar metadata
//! files on the shared filesystem.
//!
//! Structurally this mirrors [`crate::socket_seqpacket_state`] — the
//! connection-oriented named AF_UNIX shape (address registry, listen/accept
//! backlog, peer wiring, fork-restore-friendly state) — but with **stream**
//! data semantics: a contiguous byte buffer with no packet boundaries instead
//! of a packet queue. Unnamed connected pairs (`socketpair(AF_UNIX,
//! SOCK_STREAM)`) remain [`crate::socketpair_state`]; this subsystem owns the
//! *named* path/abstract listener + connected endpoints.
//!
//! `SCM_RIGHTS` over a connected stream is framed inline in the byte stream by
//! the shim (the same `FdTransferReader` mechanism the broker socketpair uses);
//! the broker carries the framed bytes opaquely.

use core::any::Any;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_frame::{
    NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
};
use litebox_common_linux::notification_ring::NotificationSender;

use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

/// Per-direction byte-buffer capacity for a connected stream. Writes beyond
/// this report `WouldBlock` (the shim surfaces `EAGAIN` / blocks).
const STREAM_BUF_CAP: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum UnixStreamAddr {
    Unnamed,
    Path(Vec<u8>),
    Abstract(Vec<u8>),
}

#[derive(Debug, thiserror::Error)]
pub enum UnixStreamError {
    #[error("invalid unix stream sockaddr")]
    InvalidSockaddr,
    #[error("unix stream socket is already bound")]
    AlreadyBound,
    #[error("unix stream address in use")]
    AddrInUse,
    #[error("unix stream peer not found")]
    NoPeer,
    #[error("unix stream socket is not connected")]
    NotConnected,
    #[error("unix stream operation would block")]
    WouldBlock,
    #[error("unix stream socket shut down")]
    Shutdown,
    #[error("unix stream socket is already connected")]
    AlreadyConnected,
    #[error("unix stream socket is not listening")]
    NotListening,
    #[error("unix stream connection refused")]
    ConnectionRefused,
}

#[derive(Debug, Default)]
struct Inner {
    bound: Option<UnixStreamAddr>,
    peer_addr: Option<UnixStreamAddr>,
    peer: Option<Weak<UnixStreamState>>,
    /// Bytes received from the peer, awaiting `recv`. Stream-ordered, no
    /// packet boundaries.
    recv_buf: VecDeque<u8>,
    /// Pending accepted server endpoints (the listen backlog).
    pending: VecDeque<Arc<UnixStreamState>>,
    listening: bool,
    backlog: usize,
    read_shutdown: bool,
    write_shutdown: bool,
}

#[derive(Debug)]
pub struct UnixStreamState {
    inner: Mutex<Inner>,
    subject: SubscriptionList,
    object_id: u64,
}

static NEXT_OBJECT_ID: AtomicU64 = AtomicU64::new(1);
static ADDR_TABLE: OnceLock<Mutex<HashMap<UnixStreamAddr, Weak<UnixStreamState>>>> =
    OnceLock::new();

fn addr_table() -> &'static Mutex<HashMap<UnixStreamAddr, Weak<UnixStreamState>>> {
    ADDR_TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn is_nameable(addr: &UnixStreamAddr) -> bool {
    matches!(addr, UnixStreamAddr::Path(_) | UnixStreamAddr::Abstract(_))
}

impl UnixStreamState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            subject: SubscriptionList::new(),
            object_id: NEXT_OBJECT_ID.fetch_add(1, Ordering::Relaxed),
        })
    }

    pub fn bind(self: &Arc<Self>, addr: UnixStreamAddr) -> Result<UnixStreamAddr, UnixStreamError> {
        if !is_nameable(&addr) {
            return Err(UnixStreamError::InvalidSockaddr);
        }
        {
            let inner = self.inner.lock().expect("UnixStreamState poisoned");
            if inner.bound.is_some() {
                return Err(UnixStreamError::AlreadyBound);
            }
        }
        let mut table = addr_table()
            .lock()
            .expect("UnixStreamState addr table poisoned");
        if table.get(&addr).and_then(Weak::upgrade).is_some() {
            return Err(UnixStreamError::AddrInUse);
        }
        table.insert(addr.clone(), Arc::downgrade(self));
        self.inner.lock().expect("UnixStreamState poisoned").bound = Some(addr.clone());
        self.notify_current();
        Ok(addr)
    }

    pub fn listen(&self, backlog: u32) -> Result<(), UnixStreamError> {
        let mut inner = self.inner.lock().expect("UnixStreamState poisoned");
        if inner.bound.is_none() || inner.peer.is_some() {
            return Err(UnixStreamError::InvalidSockaddr);
        }
        inner.listening = true;
        inner.backlog = backlog.max(1) as usize;
        drop(inner);
        self.notify_current();
        Ok(())
    }

    /// Connect this (client) socket to a bound, listening peer. On success the
    /// client is wired to a freshly created server endpoint that is queued on
    /// the listener's accept backlog.
    pub fn connect(self: &Arc<Self>, addr: UnixStreamAddr) -> Result<(), UnixStreamError> {
        if !is_nameable(&addr) {
            return Err(UnixStreamError::InvalidSockaddr);
        }
        {
            let inner = self.inner.lock().expect("UnixStreamState poisoned");
            if inner.peer.is_some() || inner.listening {
                return Err(UnixStreamError::AlreadyConnected);
            }
        }
        let listener = Self::lookup(&addr)?;
        let server = Self::new();
        let client_addr = self.getsockname();
        {
            let mut server_inner = server.inner.lock().expect("UnixStreamState poisoned");
            server_inner.bound = Some(addr.clone());
            server_inner.peer_addr = Some(client_addr);
            server_inner.peer = Some(Arc::downgrade(self));
        }
        {
            let mut client_inner = self.inner.lock().expect("UnixStreamState poisoned");
            client_inner.peer_addr = Some(addr.clone());
            client_inner.peer = Some(Arc::downgrade(&server));
        }
        {
            let mut listener_inner = listener.inner.lock().expect("UnixStreamState poisoned");
            if !listener_inner.listening {
                return Err(UnixStreamError::ConnectionRefused);
            }
            if listener_inner.pending.len() >= listener_inner.backlog {
                return Err(UnixStreamError::WouldBlock);
            }
            listener_inner.pending.push_back(server);
        }
        self.notify_current();
        listener.notify_current();
        Ok(())
    }

    pub fn accept(&self) -> Result<Arc<Self>, UnixStreamError> {
        let mut inner = self.inner.lock().expect("UnixStreamState poisoned");
        if !inner.listening {
            return Err(UnixStreamError::NotListening);
        }
        let accepted = inner
            .pending
            .pop_front()
            .ok_or(UnixStreamError::WouldBlock)?;
        drop(inner);
        self.notify_current();
        Ok(accepted)
    }

    /// Append `bytes` to the peer's receive buffer (stream semantics: writes as
    /// many bytes as fit, returns the count). Returns `WouldBlock` only when no
    /// bytes can be accepted.
    pub fn send(&self, bytes: &[u8]) -> Result<usize, UnixStreamError> {
        let peer = {
            let inner = self.inner.lock().expect("UnixStreamState poisoned");
            if inner.write_shutdown {
                return Err(UnixStreamError::Shutdown);
            }
            inner
                .peer
                .as_ref()
                .and_then(Weak::upgrade)
                .ok_or(UnixStreamError::NotConnected)?
        };
        let written = {
            let mut peer_inner = peer.inner.lock().expect("UnixStreamState peer poisoned");
            if peer_inner.read_shutdown {
                return Err(UnixStreamError::Shutdown);
            }
            let space = STREAM_BUF_CAP.saturating_sub(peer_inner.recv_buf.len());
            if space == 0 && !bytes.is_empty() {
                return Err(UnixStreamError::WouldBlock);
            }
            let n = bytes.len().min(space);
            peer_inner.recv_buf.extend(bytes[..n].iter().copied());
            n
        };
        peer.notify_current();
        Ok(written)
    }

    /// Drain up to `max_len` bytes from the receive buffer (stream semantics, no
    /// packet boundary). Returns an empty vec at EOF (peer closed), `WouldBlock`
    /// when the buffer is empty but the peer is still connected.
    pub fn recv(&self, max_len: usize) -> Result<Vec<u8>, UnixStreamError> {
        let mut inner = self.inner.lock().expect("UnixStreamState poisoned");
        if inner.read_shutdown {
            return Ok(Vec::new());
        }
        if inner.recv_buf.is_empty() {
            // EOF iff the peer has gone away after having been connected.
            if inner.peer_addr.is_some() && inner.peer.as_ref().and_then(Weak::upgrade).is_none() {
                return Ok(Vec::new());
            }
            return Err(UnixStreamError::WouldBlock);
        }
        let n = max_len.min(inner.recv_buf.len());
        let out: Vec<u8> = inner.recv_buf.drain(..n).collect();
        drop(inner);
        self.notify_current();
        Ok(out)
    }

    pub fn shutdown(&self, how: u8) -> Result<(), UnixStreamError> {
        let peer = {
            let mut inner = self.inner.lock().expect("UnixStreamState poisoned");
            match how {
                0 => inner.read_shutdown = true,
                1 => inner.write_shutdown = true,
                2 => {
                    inner.read_shutdown = true;
                    inner.write_shutdown = true;
                }
                _ => return Err(UnixStreamError::InvalidSockaddr),
            }
            inner.peer.as_ref().and_then(Weak::upgrade)
        };
        self.notify_current();
        if let Some(peer) = peer {
            peer.notify_current();
        }
        Ok(())
    }

    pub fn getsockname(&self) -> UnixStreamAddr {
        self.inner
            .lock()
            .expect("UnixStreamState poisoned")
            .bound
            .clone()
            .unwrap_or(UnixStreamAddr::Unnamed)
    }

    pub fn getpeername(&self) -> Result<UnixStreamAddr, UnixStreamError> {
        self.inner
            .lock()
            .expect("UnixStreamState poisoned")
            .peer_addr
            .clone()
            .ok_or(UnixStreamError::NotConnected)
    }

    fn lookup(addr: &UnixStreamAddr) -> Result<Arc<Self>, UnixStreamError> {
        addr_table()
            .lock()
            .expect("UnixStreamState addr table poisoned")
            .get(addr)
            .and_then(Weak::upgrade)
            .ok_or(UnixStreamError::ConnectionRefused)
    }

    fn notify_current(&self) {
        self.subject.notify(self.current_events());
    }
}

impl Drop for UnixStreamState {
    fn drop(&mut self) {
        // Wake a peer that may be blocked in `recv`/`send` so it observes the
        // disconnect (EOF on read, EPIPE on write) instead of hanging on a
        // subscription that will never fire again.
        if let Some(peer) = self
            .inner
            .lock()
            .expect("UnixStreamState poisoned")
            .peer
            .as_ref()
            .and_then(Weak::upgrade)
        {
            peer.notify_current();
        }
        if let Some(addr) = self
            .inner
            .lock()
            .expect("UnixStreamState poisoned")
            .bound
            .clone()
        {
            let mut table = addr_table()
                .lock()
                .expect("UnixStreamState addr table poisoned");
            let remove = table
                .get(&addr)
                .and_then(Weak::upgrade)
                .is_some_and(|state| state.object_id == self.object_id);
            if remove {
                table.remove(&addr);
            }
        }
    }
}

impl StateObject for UnixStreamState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::UnixSocket
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        self.subject.add(subscription_id, events_mask, sender)?;
        self.subject.notify(self.current_events());
        Ok(())
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        self.subject.remove(subscription_id)
    }

    fn current_events(&self) -> u32 {
        let inner = self.inner.lock().expect("UnixStreamState poisoned");
        let mut events = 0;
        if inner.listening {
            if !inner.pending.is_empty() || inner.read_shutdown {
                events |= NOTIFY_EVENT_IN;
            }
        } else if inner.read_shutdown
            || !inner.recv_buf.is_empty()
            || (inner.peer_addr.is_some() && inner.peer.as_ref().and_then(Weak::upgrade).is_none())
        {
            events |= NOTIFY_EVENT_IN;
        }
        if inner.write_shutdown {
            events |= NOTIFY_EVENT_HUP;
        } else if !inner.listening {
            events |= NOTIFY_EVENT_OUT;
        }
        events
    }

    fn try_flush_subscriptions(&self) {
        self.subject.try_flush();
    }
}

pub fn encode_addr(addr: &UnixStreamAddr) -> Vec<u8> {
    let (kind, bytes): (u8, &[u8]) = match addr {
        UnixStreamAddr::Unnamed => (0, &[]),
        UnixStreamAddr::Path(path) => (1, path),
        UnixStreamAddr::Abstract(name) => (2, name),
    };
    let mut out = Vec::with_capacity(5 + bytes.len());
    out.push(kind);
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

pub fn decode_addr(raw: &[u8]) -> Result<UnixStreamAddr, UnixStreamError> {
    if raw.len() < 5 {
        return Err(UnixStreamError::InvalidSockaddr);
    }
    let kind = raw[0];
    let len = u32::from_le_bytes(raw[1..5].try_into().unwrap()) as usize;
    if raw.len() != 5 + len {
        return Err(UnixStreamError::InvalidSockaddr);
    }
    let bytes = raw[5..].to_vec();
    match kind {
        0 if bytes.is_empty() => Ok(UnixStreamAddr::Unnamed),
        1 => Ok(UnixStreamAddr::Path(bytes)),
        2 => Ok(UnixStreamAddr::Abstract(bytes)),
        _ => Err(UnixStreamError::InvalidSockaddr),
    }
}
