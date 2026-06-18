// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted AF_UNIX SOCK_DGRAM state.
//!
//! This state intentionally models the kernel-visible datagram resource in the
//! broker instead of the worker shim so dup/fork/restore share one receive queue,
//! bind table entry, and connected-peer setting. `SCM_RIGHTS` is carried as
//! broker handle tokens alongside each datagram. `SCM_CREDENTIALS` remains
//! deferred because credential fabrication/verification has auth implications.

use core::any::Any;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use litebox_common_linux::cwfd::fd_transfer_frame::PassedToken;
use litebox_common_linux::fd_token_protocol::INET_DGRAM_RECV_FLAG_TRUNC;
use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_frame::{
    NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
};
use litebox_common_linux::notification_ring::NotificationSender;

use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

const RECV_QUEUE_CAP: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SocketDgramAddr {
    Unnamed,
    Path(Vec<u8>),
    Abstract(Vec<u8>),
}

#[derive(Debug, thiserror::Error)]
pub enum SocketDgramError {
    #[error("invalid unix datagram sockaddr")]
    InvalidSockaddr,
    #[error("unix datagram socket is already bound")]
    AlreadyBound,
    #[error("unix datagram address in use")]
    AddrInUse,
    #[error("unix datagram peer not found")]
    NoPeer,
    #[error("unix datagram socket is not connected")]
    NotConnected,
    #[error("unix datagram operation would block")]
    WouldBlock,
    #[error("unix datagram socket shut down")]
    Shutdown,
}

#[derive(Clone, Debug)]
struct Datagram {
    source: SocketDgramAddr,
    payload: Vec<u8>,
    tokens: Vec<PassedToken>,
}

#[derive(Debug, Default)]
struct Inner {
    bound: Option<SocketDgramAddr>,
    connected: Option<SocketDgramAddr>,
    queue: VecDeque<Datagram>,
    read_shutdown: bool,
    write_shutdown: bool,
}

#[derive(Debug)]
pub struct SocketDgramState {
    inner: Mutex<Inner>,
    subject: SubscriptionList,
    object_id: u64,
}

static NEXT_OBJECT_ID: AtomicU64 = AtomicU64::new(1);
static ADDR_TABLE: OnceLock<Mutex<HashMap<SocketDgramAddr, Weak<SocketDgramState>>>> =
    OnceLock::new();

fn addr_table() -> &'static Mutex<HashMap<SocketDgramAddr, Weak<SocketDgramState>>> {
    ADDR_TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

impl SocketDgramState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            subject: SubscriptionList::new(),
            object_id: NEXT_OBJECT_ID.fetch_add(1, Ordering::Relaxed),
        })
    }

    pub fn bind(
        self: &Arc<Self>,
        addr: SocketDgramAddr,
    ) -> Result<SocketDgramAddr, SocketDgramError> {
        if matches!(addr, SocketDgramAddr::Unnamed) {
            return Err(SocketDgramError::InvalidSockaddr);
        }
        {
            let inner = self.inner.lock().expect("SocketDgramState poisoned");
            if inner.bound.is_some() {
                return Err(SocketDgramError::AlreadyBound);
            }
        }
        let mut table = addr_table()
            .lock()
            .expect("SocketDgramState addr table poisoned");
        if table.get(&addr).and_then(Weak::upgrade).is_some() {
            return Err(SocketDgramError::AddrInUse);
        }
        table.insert(addr.clone(), Arc::downgrade(self));
        self.inner.lock().expect("SocketDgramState poisoned").bound = Some(addr.clone());
        self.notify_current();
        Ok(addr)
    }

    pub fn connect(&self, addr: SocketDgramAddr) -> Result<(), SocketDgramError> {
        if matches!(addr, SocketDgramAddr::Unnamed) {
            return Err(SocketDgramError::InvalidSockaddr);
        }
        Self::lookup(&addr)?;
        self.inner
            .lock()
            .expect("SocketDgramState poisoned")
            .connected = Some(addr);
        self.notify_current();
        Ok(())
    }

    pub fn sendto(
        &self,
        addr: Option<SocketDgramAddr>,
        payload: &[u8],
        tokens: &[PassedToken],
    ) -> Result<usize, SocketDgramError> {
        let (peer_addr, source) = {
            let inner = self.inner.lock().expect("SocketDgramState poisoned");
            if inner.write_shutdown {
                return Err(SocketDgramError::Shutdown);
            }
            let peer_addr = match addr {
                Some(addr) => addr,
                None => inner
                    .connected
                    .clone()
                    .ok_or(SocketDgramError::NotConnected)?,
            };
            let source = inner.bound.clone().unwrap_or(SocketDgramAddr::Unnamed);
            (peer_addr, source)
        };
        let peer = Self::lookup(&peer_addr)?;
        {
            let mut peer_inner = peer.inner.lock().expect("SocketDgramState peer poisoned");
            if peer_inner.read_shutdown {
                return Err(SocketDgramError::Shutdown);
            }
            if peer_inner.queue.len() >= RECV_QUEUE_CAP {
                return Err(SocketDgramError::WouldBlock);
            }
            peer_inner.queue.push_back(Datagram {
                source,
                payload: payload.to_vec(),
                tokens: tokens.to_vec(),
            });
        }
        peer.notify_current();
        Ok(payload.len())
    }

    pub fn recvfrom(
        &self,
        max_len: usize,
    ) -> Result<(SocketDgramAddr, Vec<u8>, u32, Vec<PassedToken>), SocketDgramError> {
        let mut inner = self.inner.lock().expect("SocketDgramState poisoned");
        if inner.read_shutdown {
            return Ok((SocketDgramAddr::Unnamed, Vec::new(), 0, Vec::new()));
        }
        let Some(mut dgram) = inner.queue.pop_front() else {
            return Err(SocketDgramError::WouldBlock);
        };
        let mut flags = 0;
        if dgram.payload.len() > max_len {
            dgram.payload.truncate(max_len);
            flags |= INET_DGRAM_RECV_FLAG_TRUNC;
        }
        drop(inner);
        self.notify_current();
        Ok((dgram.source, dgram.payload, flags, dgram.tokens))
    }

    pub fn shutdown(&self, how: u8) -> Result<(), SocketDgramError> {
        let mut inner = self.inner.lock().expect("SocketDgramState poisoned");
        match how {
            0 => inner.read_shutdown = true,
            1 => inner.write_shutdown = true,
            2 => {
                inner.read_shutdown = true;
                inner.write_shutdown = true;
            }
            _ => return Err(SocketDgramError::InvalidSockaddr),
        }
        drop(inner);
        self.notify_current();
        Ok(())
    }

    pub fn getsockname(&self) -> SocketDgramAddr {
        self.inner
            .lock()
            .expect("SocketDgramState poisoned")
            .bound
            .clone()
            .unwrap_or(SocketDgramAddr::Unnamed)
    }

    pub fn getpeername(&self) -> Result<SocketDgramAddr, SocketDgramError> {
        self.inner
            .lock()
            .expect("SocketDgramState poisoned")
            .connected
            .clone()
            .ok_or(SocketDgramError::NotConnected)
    }

    fn lookup(addr: &SocketDgramAddr) -> Result<Arc<Self>, SocketDgramError> {
        addr_table()
            .lock()
            .expect("SocketDgramState addr table poisoned")
            .get(addr)
            .and_then(Weak::upgrade)
            .ok_or(SocketDgramError::NoPeer)
    }

    fn notify_current(&self) {
        self.subject.notify(self.current_events());
    }
}

impl Drop for SocketDgramState {
    fn drop(&mut self) {
        if let Some(addr) = self
            .inner
            .lock()
            .expect("SocketDgramState poisoned")
            .bound
            .clone()
        {
            let mut table = addr_table()
                .lock()
                .expect("SocketDgramState addr table poisoned");
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

impl StateObject for SocketDgramState {
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
        let inner = self.inner.lock().expect("SocketDgramState poisoned");
        let mut events = 0;
        if inner.read_shutdown || !inner.queue.is_empty() {
            events |= NOTIFY_EVENT_IN;
        }
        if inner.write_shutdown {
            events |= NOTIFY_EVENT_HUP;
        } else {
            events |= NOTIFY_EVENT_OUT;
        }
        events
    }

    fn try_flush_subscriptions(&self) {
        self.subject.try_flush();
    }
}

pub fn encode_addr(addr: &SocketDgramAddr) -> Vec<u8> {
    let (kind, bytes): (u8, &[u8]) = match addr {
        SocketDgramAddr::Unnamed => (0, &[]),
        SocketDgramAddr::Path(path) => (1, path),
        SocketDgramAddr::Abstract(name) => (2, name),
    };
    let mut out = Vec::with_capacity(5 + bytes.len());
    out.push(kind);
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

pub fn decode_addr(raw: &[u8]) -> Result<SocketDgramAddr, SocketDgramError> {
    if raw.len() < 5 {
        return Err(SocketDgramError::InvalidSockaddr);
    }
    let kind = raw[0];
    let len = u32::from_le_bytes(raw[1..5].try_into().unwrap()) as usize;
    if raw.len() != 5 + len {
        return Err(SocketDgramError::InvalidSockaddr);
    }
    let bytes = raw[5..].to_vec();
    match kind {
        0 if bytes.is_empty() => Ok(SocketDgramAddr::Unnamed),
        1 => Ok(SocketDgramAddr::Path(bytes)),
        2 => Ok(SocketDgramAddr::Abstract(bytes)),
        _ => Err(SocketDgramError::InvalidSockaddr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_bound_send_recv_preserves_one_message_and_truncates() {
        let a = SocketDgramState::new();
        let b = SocketDgramState::new();
        a.bind(SocketDgramAddr::Abstract(b"a".to_vec())).unwrap();
        b.bind(SocketDgramAddr::Abstract(b"b".to_vec())).unwrap();
        a.sendto(
            Some(SocketDgramAddr::Abstract(b"b".to_vec())),
            b"hello",
            &[],
        )
        .unwrap();
        a.sendto(
            Some(SocketDgramAddr::Abstract(b"b".to_vec())),
            b"world",
            &[],
        )
        .unwrap();
        let (src, payload, flags, tokens) = b.recvfrom(3).unwrap();
        assert_eq!(src, SocketDgramAddr::Abstract(b"a".to_vec()));
        assert_eq!(payload, b"hel");
        assert_ne!(flags & INET_DGRAM_RECV_FLAG_TRUNC, 0);
        assert!(tokens.is_empty());
        let (_, payload, flags, tokens) = b.recvfrom(16).unwrap();
        assert_eq!(payload, b"world");
        assert_eq!(flags, 0);
        assert!(tokens.is_empty());
    }

    #[test]
    fn connected_send_uses_default_peer() {
        let a = SocketDgramState::new();
        let b = SocketDgramState::new();
        a.bind(SocketDgramAddr::Abstract(b"c".to_vec())).unwrap();
        b.bind(SocketDgramAddr::Abstract(b"d".to_vec())).unwrap();
        a.connect(SocketDgramAddr::Abstract(b"d".to_vec())).unwrap();
        a.sendto(None, b"ping", &[]).unwrap();
        let (src, payload, _, tokens) = b.recvfrom(16).unwrap();
        assert_eq!(src, SocketDgramAddr::Abstract(b"c".to_vec()));
        assert_eq!(payload, b"ping");
        assert!(tokens.is_empty());
    }

    #[test]
    fn datagram_preserves_scm_tokens() {
        let a = SocketDgramState::new();
        let b = SocketDgramState::new();
        a.bind(SocketDgramAddr::Abstract(b"scm-a".to_vec()))
            .unwrap();
        b.bind(SocketDgramAddr::Abstract(b"scm-b".to_vec()))
            .unwrap();
        let token = PassedToken::new(SubsystemTag::File, 0x1234).unwrap();

        a.sendto(
            Some(SocketDgramAddr::Abstract(b"scm-b".to_vec())),
            b"fd",
            &[token],
        )
        .unwrap();
        let (src, payload, flags, tokens) = b.recvfrom(16).unwrap();

        assert_eq!(src, SocketDgramAddr::Abstract(b"scm-a".to_vec()));
        assert_eq!(payload, b"fd");
        assert_eq!(flags, 0);
        assert_eq!(tokens, vec![token]);
    }
}
