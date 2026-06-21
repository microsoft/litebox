// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted AF_UNIX SOCK_SEQPACKET state.
//!
//! Seqpacket is connection-oriented like stream, but preserves packet
//! boundaries like datagram. This first broker-backed shape models pathname
//! Unix addresses, socketpair/connect/listen/accept, shutdown, readiness, and
//! fork-restore inheritance. `SCM_RIGHTS` is carried as broker handle tokens
//! alongside each packet. `SCM_CREDENTIALS` and abstract namespace addresses are
//! intentionally deferred.

use core::any::Any;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use litebox_common_linux::fd_token_protocol::SOCKET_SEQPACKET_RECV_FLAG_TRUNC;
use litebox_common_linux::fd_transfer_frame::{PassedToken, SubsystemTag};
use litebox_common_linux::notification_frame::{
    NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
};
use litebox_common_linux::notification_ring::NotificationSender;

use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

const RECV_QUEUE_CAP: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SocketSeqPacketAddr {
    Unnamed,
    Path(Vec<u8>),
    Abstract(Vec<u8>),
}

#[derive(Debug, thiserror::Error)]
pub enum SocketSeqPacketError {
    #[error("invalid unix seqpacket sockaddr")]
    InvalidSockaddr,
    #[error("unix seqpacket socket is already bound")]
    AlreadyBound,
    #[error("unix seqpacket address in use")]
    AddrInUse,
    #[error("unix seqpacket peer not found")]
    NoPeer,
    #[error("unix seqpacket socket is not connected")]
    NotConnected,
    #[error("unix seqpacket operation would block")]
    WouldBlock,
    #[error("unix seqpacket socket shut down")]
    Shutdown,
    #[error("unix seqpacket socket is already connected")]
    AlreadyConnected,
    #[error("unix seqpacket socket is not listening")]
    NotListening,
}

#[derive(Clone, Debug)]
struct Packet {
    payload: Vec<u8>,
    tokens: Vec<PassedToken>,
}

#[derive(Debug, Default)]
struct Inner {
    bound: Option<SocketSeqPacketAddr>,
    peer_addr: Option<SocketSeqPacketAddr>,
    peer: Option<Weak<SocketSeqPacketState>>,
    queue: VecDeque<Packet>,
    pending: VecDeque<Arc<SocketSeqPacketState>>,
    listening: bool,
    backlog: usize,
    read_shutdown: bool,
    write_shutdown: bool,
}

#[derive(Debug)]
pub struct SocketSeqPacketState {
    inner: Mutex<Inner>,
    subject: SubscriptionList,
    object_id: u64,
}

static NEXT_OBJECT_ID: AtomicU64 = AtomicU64::new(1);
static ADDR_TABLE: OnceLock<Mutex<HashMap<SocketSeqPacketAddr, Weak<SocketSeqPacketState>>>> =
    OnceLock::new();

fn addr_table() -> &'static Mutex<HashMap<SocketSeqPacketAddr, Weak<SocketSeqPacketState>>> {
    ADDR_TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

impl SocketSeqPacketState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            subject: SubscriptionList::new(),
            object_id: NEXT_OBJECT_ID.fetch_add(1, Ordering::Relaxed),
        })
    }

    pub fn new_pair() -> (Arc<Self>, Arc<Self>) {
        let a = Self::new();
        let b = Self::new();
        {
            let mut ai = a.inner.lock().expect("SocketSeqPacketState poisoned");
            ai.peer = Some(Arc::downgrade(&b));
            ai.peer_addr = Some(SocketSeqPacketAddr::Unnamed);
        }
        {
            let mut bi = b.inner.lock().expect("SocketSeqPacketState poisoned");
            bi.peer = Some(Arc::downgrade(&a));
            bi.peer_addr = Some(SocketSeqPacketAddr::Unnamed);
        }
        (a, b)
    }

    pub fn bind(
        self: &Arc<Self>,
        addr: SocketSeqPacketAddr,
    ) -> Result<SocketSeqPacketAddr, SocketSeqPacketError> {
        if !matches!(addr, SocketSeqPacketAddr::Path(_)) {
            return Err(SocketSeqPacketError::InvalidSockaddr);
        }
        {
            let inner = self.inner.lock().expect("SocketSeqPacketState poisoned");
            if inner.bound.is_some() {
                return Err(SocketSeqPacketError::AlreadyBound);
            }
        }
        let mut table = addr_table()
            .lock()
            .expect("SocketSeqPacketState addr table poisoned");
        if table.get(&addr).and_then(Weak::upgrade).is_some() {
            return Err(SocketSeqPacketError::AddrInUse);
        }
        table.insert(addr.clone(), Arc::downgrade(self));
        self.inner
            .lock()
            .expect("SocketSeqPacketState poisoned")
            .bound = Some(addr.clone());
        self.notify_current();
        Ok(addr)
    }

    pub fn listen(&self, backlog: u32) -> Result<(), SocketSeqPacketError> {
        let mut inner = self.inner.lock().expect("SocketSeqPacketState poisoned");
        if inner.bound.is_none() || inner.peer.is_some() {
            return Err(SocketSeqPacketError::InvalidSockaddr);
        }
        inner.listening = true;
        inner.backlog = backlog.max(1) as usize;
        drop(inner);
        self.notify_current();
        Ok(())
    }

    pub fn connect(
        self: &Arc<Self>,
        addr: SocketSeqPacketAddr,
    ) -> Result<(), SocketSeqPacketError> {
        if !matches!(addr, SocketSeqPacketAddr::Path(_)) {
            return Err(SocketSeqPacketError::InvalidSockaddr);
        }
        {
            let inner = self.inner.lock().expect("SocketSeqPacketState poisoned");
            if inner.peer.is_some() || inner.listening {
                return Err(SocketSeqPacketError::AlreadyConnected);
            }
        }
        let listener = Self::lookup(&addr)?;
        let server = Self::new();
        let client_addr = self.getsockname();
        {
            let mut server_inner = server.inner.lock().expect("SocketSeqPacketState poisoned");
            server_inner.bound = Some(addr.clone());
            server_inner.peer_addr = Some(client_addr);
            server_inner.peer = Some(Arc::downgrade(self));
        }
        {
            let mut client_inner = self.inner.lock().expect("SocketSeqPacketState poisoned");
            client_inner.peer_addr = Some(addr.clone());
            client_inner.peer = Some(Arc::downgrade(&server));
        }
        {
            let mut listener_inner = listener
                .inner
                .lock()
                .expect("SocketSeqPacketState poisoned");
            if !listener_inner.listening {
                return Err(SocketSeqPacketError::NotListening);
            }
            if listener_inner.pending.len() >= listener_inner.backlog {
                return Err(SocketSeqPacketError::WouldBlock);
            }
            listener_inner.pending.push_back(server);
        }
        self.notify_current();
        listener.notify_current();
        Ok(())
    }

    pub fn accept(&self) -> Result<Arc<Self>, SocketSeqPacketError> {
        let mut inner = self.inner.lock().expect("SocketSeqPacketState poisoned");
        if !inner.listening {
            return Err(SocketSeqPacketError::NotListening);
        }
        let accepted = inner
            .pending
            .pop_front()
            .ok_or(SocketSeqPacketError::WouldBlock)?;
        drop(inner);
        self.notify_current();
        Ok(accepted)
    }

    pub fn send(
        &self,
        payload: &[u8],
        tokens: &[PassedToken],
    ) -> Result<usize, SocketSeqPacketError> {
        let peer = {
            let inner = self.inner.lock().expect("SocketSeqPacketState poisoned");
            if inner.write_shutdown {
                return Err(SocketSeqPacketError::Shutdown);
            }
            inner
                .peer
                .as_ref()
                .and_then(Weak::upgrade)
                .ok_or(SocketSeqPacketError::NotConnected)?
        };
        {
            let mut peer_inner = peer
                .inner
                .lock()
                .expect("SocketSeqPacketState peer poisoned");
            if peer_inner.read_shutdown {
                return Err(SocketSeqPacketError::Shutdown);
            }
            if peer_inner.queue.len() >= RECV_QUEUE_CAP {
                return Err(SocketSeqPacketError::WouldBlock);
            }
            peer_inner.queue.push_back(Packet {
                payload: payload.to_vec(),
                tokens: tokens.to_vec(),
            });
        }
        peer.notify_current();
        Ok(payload.len())
    }

    pub fn recv(
        &self,
        max_len: usize,
    ) -> Result<(Vec<u8>, u32, Vec<PassedToken>), SocketSeqPacketError> {
        let mut inner = self.inner.lock().expect("SocketSeqPacketState poisoned");
        if inner.read_shutdown {
            return Ok((Vec::new(), 0, Vec::new()));
        }
        let Some(mut packet) = inner.queue.pop_front() else {
            if inner.peer.as_ref().and_then(Weak::upgrade).is_none() && inner.peer_addr.is_some() {
                return Ok((Vec::new(), 0, Vec::new()));
            }
            return Err(SocketSeqPacketError::WouldBlock);
        };
        let mut flags = 0;
        if packet.payload.len() > max_len {
            packet.payload.truncate(max_len);
            flags |= SOCKET_SEQPACKET_RECV_FLAG_TRUNC;
        }
        drop(inner);
        self.notify_current();
        Ok((packet.payload, flags, packet.tokens))
    }

    pub fn shutdown(&self, how: u8) -> Result<(), SocketSeqPacketError> {
        let peer = {
            let mut inner = self.inner.lock().expect("SocketSeqPacketState poisoned");
            match how {
                0 => inner.read_shutdown = true,
                1 => inner.write_shutdown = true,
                2 => {
                    inner.read_shutdown = true;
                    inner.write_shutdown = true;
                }
                _ => return Err(SocketSeqPacketError::InvalidSockaddr),
            }
            inner.peer.as_ref().and_then(Weak::upgrade)
        };
        self.notify_current();
        if let Some(peer) = peer {
            peer.notify_current();
        }
        Ok(())
    }

    pub fn getsockname(&self) -> SocketSeqPacketAddr {
        self.inner
            .lock()
            .expect("SocketSeqPacketState poisoned")
            .bound
            .clone()
            .unwrap_or(SocketSeqPacketAddr::Unnamed)
    }

    pub fn getpeername(&self) -> Result<SocketSeqPacketAddr, SocketSeqPacketError> {
        self.inner
            .lock()
            .expect("SocketSeqPacketState poisoned")
            .peer_addr
            .clone()
            .ok_or(SocketSeqPacketError::NotConnected)
    }

    fn lookup(addr: &SocketSeqPacketAddr) -> Result<Arc<Self>, SocketSeqPacketError> {
        addr_table()
            .lock()
            .expect("SocketSeqPacketState addr table poisoned")
            .get(addr)
            .and_then(Weak::upgrade)
            .ok_or(SocketSeqPacketError::NoPeer)
    }

    fn notify_current(&self) {
        self.subject.notify(self.current_events());
    }
}

impl Drop for SocketSeqPacketState {
    fn drop(&mut self) {
        if let Some(addr) = self
            .inner
            .lock()
            .expect("SocketSeqPacketState poisoned")
            .bound
            .clone()
        {
            let mut table = addr_table()
                .lock()
                .expect("SocketSeqPacketState addr table poisoned");
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

impl StateObject for SocketSeqPacketState {
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
        let inner = self.inner.lock().expect("SocketSeqPacketState poisoned");
        let mut events = 0;
        if inner.listening {
            if !inner.pending.is_empty() || inner.read_shutdown {
                events |= NOTIFY_EVENT_IN;
            }
        } else if inner.read_shutdown
            || !inner.queue.is_empty()
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

pub fn encode_addr(addr: &SocketSeqPacketAddr) -> Vec<u8> {
    let (kind, bytes): (u8, &[u8]) = match addr {
        SocketSeqPacketAddr::Unnamed => (0, &[]),
        SocketSeqPacketAddr::Path(path) => (1, path),
        SocketSeqPacketAddr::Abstract(name) => (2, name),
    };
    let mut out = Vec::with_capacity(5 + bytes.len());
    out.push(kind);
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

pub fn decode_addr(raw: &[u8]) -> Result<SocketSeqPacketAddr, SocketSeqPacketError> {
    if raw.len() < 5 {
        return Err(SocketSeqPacketError::InvalidSockaddr);
    }
    let kind = raw[0];
    let len = u32::from_le_bytes(raw[1..5].try_into().unwrap()) as usize;
    if raw.len() != 5 + len {
        return Err(SocketSeqPacketError::InvalidSockaddr);
    }
    let bytes = raw[5..].to_vec();
    match kind {
        0 if bytes.is_empty() => Ok(SocketSeqPacketAddr::Unnamed),
        1 => Ok(SocketSeqPacketAddr::Path(bytes)),
        2 => Ok(SocketSeqPacketAddr::Abstract(bytes)),
        _ => Err(SocketSeqPacketError::InvalidSockaddr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socketpair_preserves_messages_and_truncates() {
        let (a, b) = SocketSeqPacketState::new_pair();
        a.send(b"hello", &[]).unwrap();
        a.send(b"world", &[]).unwrap();
        let (payload, flags, tokens) = b.recv(3).unwrap();
        assert_eq!(payload, b"hel");
        assert_ne!(flags & SOCKET_SEQPACKET_RECV_FLAG_TRUNC, 0);
        assert!(tokens.is_empty());
        let (payload, flags, tokens) = b.recv(16).unwrap();
        assert_eq!(payload, b"world");
        assert_eq!(flags, 0);
        assert!(tokens.is_empty());
    }

    #[test]
    fn seqpacket_preserves_scm_tokens() {
        let (a, b) = SocketSeqPacketState::new_pair();
        let token = PassedToken::new(SubsystemTag::File, 0x1234).unwrap();

        a.send(b"fd", &[token]).unwrap();
        let (payload, flags, tokens) = b.recv(16).unwrap();

        assert_eq!(payload, b"fd");
        assert_eq!(flags, 0);
        assert_eq!(tokens, vec![token]);
    }
}
