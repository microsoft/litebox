// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted TCP listener state.

use core::any::Any;
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc as channel};
use std::thread;
use std::time::Duration;

use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_frame::{NOTIFY_EVENT_ERR, NOTIFY_EVENT_IN};
use litebox_common_linux::notification_ring::NotificationSender;

use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

const ACCEPT_QUEUE_CAP: usize = 128;
const SOCKADDR_WIRE_LEN: usize = 28;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    V4,
    V6,
}

#[derive(Debug, thiserror::Error)]
pub enum InetListenerError {
    #[error("invalid inet listener address family")]
    InvalidFamily,
    #[error("invalid inet listener sockaddr")]
    InvalidSockaddr,
    #[error("inet listener is already bound")]
    AlreadyBound,
    #[error("inet listener is not bound")]
    NotBound,
    #[error("inet listener is already listening")]
    AlreadyListening,
    #[error("inet listener accept would block")]
    WouldBlock,
    #[error("inet listener I/O error")]
    Io(#[from] std::io::Error),
}

/// Broker-owned host TCP listener plus readiness subscribers.
#[derive(Debug)]
pub struct InetListenerState {
    family: AddressFamily,
    listener: Mutex<Option<TcpListener>>,
    bound_addr: Mutex<Option<SocketAddr>>,
    subject: SubscriptionList,
    accept_chan: Mutex<Option<channel::Receiver<(TcpStream, SocketAddr)>>>,
    accept_thread: Mutex<Option<thread::JoinHandle<()>>>,
    queued_accepts: AtomicUsize,
    accept_error: AtomicBool,
    stop_accept: Arc<AtomicBool>,
}

impl InetListenerState {
    pub fn new(family: AddressFamily) -> Arc<Self> {
        Arc::new(Self {
            family,
            listener: Mutex::new(None),
            bound_addr: Mutex::new(None),
            subject: SubscriptionList::new(),
            accept_chan: Mutex::new(None),
            accept_thread: Mutex::new(None),
            queued_accepts: AtomicUsize::new(0),
            accept_error: AtomicBool::new(false),
            stop_accept: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn family(&self) -> AddressFamily {
        self.family
    }

    pub fn bound_addr(&self) -> Option<SocketAddr> {
        *self
            .bound_addr
            .lock()
            .expect("InetListenerState bound_addr poisoned")
    }

    pub fn bind(
        &self,
        sockaddr: &[u8; SOCKADDR_WIRE_LEN],
    ) -> Result<[u8; SOCKADDR_WIRE_LEN], InetListenerError> {
        let addr = decode_sockaddr(sockaddr)?;
        match (self.family, addr) {
            (AddressFamily::V4, SocketAddr::V4(_)) | (AddressFamily::V6, SocketAddr::V6(_)) => {}
            _ => return Err(InetListenerError::InvalidSockaddr),
        }
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let actual = listener.local_addr()?;
        let mut slot = self
            .listener
            .lock()
            .expect("InetListenerState listener poisoned");
        if slot.is_some() {
            return Err(InetListenerError::AlreadyBound);
        }
        *slot = Some(listener);
        *self
            .bound_addr
            .lock()
            .expect("InetListenerState bound_addr poisoned") = Some(actual);
        encode_sockaddr(actual)
    }

    pub fn listen(self: &Arc<Self>, _backlog: u32) -> Result<(), InetListenerError> {
        if self
            .accept_chan
            .lock()
            .expect("InetListenerState accept_chan poisoned")
            .is_some()
        {
            return Err(InetListenerError::AlreadyListening);
        }
        let listener = self
            .listener
            .lock()
            .expect("InetListenerState listener poisoned")
            .as_ref()
            .ok_or(InetListenerError::NotBound)?
            .try_clone()?;
        listener.set_nonblocking(true)?;
        let (tx, rx) = channel::sync_channel(ACCEPT_QUEUE_CAP);
        *self
            .accept_chan
            .lock()
            .expect("InetListenerState accept_chan poisoned") = Some(rx);
        let weak = Arc::downgrade(self);
        let stop = Arc::clone(&self.stop_accept);
        let handle = thread::Builder::new()
            .name("litebox-inet-listener-accept".into())
            .spawn(move || accept_loop(listener, tx, weak, stop))?;
        *self
            .accept_thread
            .lock()
            .expect("InetListenerState accept_thread poisoned") = Some(handle);
        Ok(())
    }

    pub fn accept(&self) -> Result<(TcpStream, SocketAddr), InetListenerError> {
        let guard = self
            .accept_chan
            .lock()
            .expect("InetListenerState accept_chan poisoned");
        let rx = guard.as_ref().ok_or(InetListenerError::NotBound)?;
        match rx.try_recv() {
            Ok(conn) => {
                self.queued_accepts.fetch_sub(1, Ordering::AcqRel);
                Ok(conn)
            }
            Err(channel::TryRecvError::Empty) => Err(InetListenerError::WouldBlock),
            Err(channel::TryRecvError::Disconnected) => Err(InetListenerError::Io(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "accept thread exited"),
            )),
        }
    }

    pub fn current_events(&self) -> u32 {
        let mut events = 0;
        if self.queued_accepts.load(Ordering::Acquire) != 0 {
            events |= NOTIFY_EVENT_IN;
        }
        if self.accept_error.load(Ordering::Acquire) {
            events |= NOTIFY_EVENT_ERR;
        }
        events
    }
}

impl Drop for InetListenerState {
    fn drop(&mut self) {
        self.stop_accept.store(true, Ordering::Release);
        let _ = self.listener.lock().map(|mut l| l.take());
        let _ = self.accept_chan.lock().map(|mut rx| rx.take());
        if let Ok(mut thread) = self.accept_thread.lock() {
            if let Some(handle) = thread.take() {
                let _ = handle.join();
            }
        }
    }
}

impl StateObject for InetListenerState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::InetListener
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
        let initial = self.current_events() & events_mask;
        if initial != 0 {
            self.subject.notify(initial);
        }
        Ok(())
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        self.subject.remove(subscription_id)
    }

    fn current_events(&self) -> u32 {
        InetListenerState::current_events(self)
    }
}

fn accept_loop(
    listener: TcpListener,
    tx: channel::SyncSender<(TcpStream, SocketAddr)>,
    state: std::sync::Weak<InetListenerState>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let mut pending = Some((stream, peer));
                while let Some(item) = pending.take() {
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                    match tx.try_send(item) {
                        Ok(()) => {
                            if let Some(state) = state.upgrade() {
                                state.queued_accepts.fetch_add(1, Ordering::AcqRel);
                                state.subject.notify(NOTIFY_EVENT_IN);
                            } else {
                                return;
                            }
                        }
                        Err(channel::TrySendError::Full(item)) => {
                            pending = Some(item);
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(channel::TrySendError::Disconnected(_)) => return,
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                if let Some(state) = state.upgrade() {
                    state.accept_error.store(true, Ordering::Release);
                    state.subject.notify(NOTIFY_EVENT_ERR);
                }
                return;
            }
        }
    }
}

pub fn family_from_u8(raw: u8) -> Result<AddressFamily, InetListenerError> {
    match raw {
        0 => Ok(AddressFamily::V4),
        1 => Ok(AddressFamily::V6),
        _ => Err(InetListenerError::InvalidFamily),
    }
}

pub fn decode_sockaddr(raw: &[u8; SOCKADDR_WIRE_LEN]) -> Result<SocketAddr, InetListenerError> {
    let family = u16::from_ne_bytes([raw[0], raw[1]]) as i32;
    match family {
        libc::AF_INET => {
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]),
                port,
            )))
        }
        libc::AF_INET6 => {
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let flowinfo = u32::from_ne_bytes(raw[4..8].try_into().expect("slice length checked"));
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&raw[8..24]);
            let scope_id =
                u32::from_ne_bytes(raw[24..28].try_into().expect("slice length checked"));
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr),
                port,
                flowinfo,
                scope_id,
            )))
        }
        _ => Err(InetListenerError::InvalidSockaddr),
    }
}

pub fn encode_sockaddr(addr: SocketAddr) -> Result<[u8; SOCKADDR_WIRE_LEN], InetListenerError> {
    let mut raw = [0u8; SOCKADDR_WIRE_LEN];
    match addr {
        SocketAddr::V4(v4) => {
            raw[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            raw[2..4].copy_from_slice(&v4.port().to_be_bytes());
            raw[4..8].copy_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            raw[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            raw[2..4].copy_from_slice(&v6.port().to_be_bytes());
            raw[4..8].copy_from_slice(&v6.flowinfo().to_ne_bytes());
            raw[8..24].copy_from_slice(&v6.ip().octets());
            raw[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
        }
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cwfd::state_registry::{BrokerStateRegistry, StateHandle, StateObjectEnum};
    use crate::cwfd::tcp_conn_state::TcpConnState;
    use litebox_common_linux::cwfd::fd_transfer_frame::SubsystemTag;
    use std::time::{Duration, Instant};

    fn bind_loopback(state: &InetListenerState) -> SocketAddr {
        let requested = encode_sockaddr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            0,
        )))
        .unwrap();
        let actual = state.bind(&requested).unwrap();
        decode_sockaddr(&actual).unwrap()
    }

    fn accept_wait(state: &InetListenerState) -> (TcpStream, SocketAddr) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match state.accept() {
                Ok(conn) => return conn,
                Err(InetListenerError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("accept failed: {err:?}"),
            }
        }
    }

    #[test]
    fn inet_listener_accept_would_block_without_pending_connections() {
        let state = InetListenerState::new(AddressFamily::V4);
        bind_loopback(&state);
        state.listen(5).unwrap();
        assert!(matches!(state.accept(), Err(InetListenerError::WouldBlock)));
        assert_eq!(state.current_events() & NOTIFY_EVENT_IN, 0);
    }

    #[test]
    fn inet_listener_accept_registers_tcp_conn_state() {
        let registry = BrokerStateRegistry::new();
        let state = InetListenerState::new(AddressFamily::V4);
        let listener_handle = registry.register(Arc::clone(&state));
        let addr = bind_loopback(&state);
        state.listen(5).unwrap();

        let client = TcpStream::connect(addr).unwrap();
        let client_addr = client.local_addr().unwrap();
        let (stream, peer) = accept_wait(&state);
        assert_eq!(peer, client_addr);

        let conn_handle = registry.register(TcpConnState::new(stream));
        let resolved = registry
            .resolve(
                StateHandle::from_id(conn_handle.id()),
                SubsystemTag::TcpSocket,
            )
            .unwrap();
        assert!(matches!(resolved.as_ref(), StateObjectEnum::TcpConn(_)));
        assert!(
            registry
                .resolve(
                    StateHandle::from_id(listener_handle.id()),
                    SubsystemTag::InetListener
                )
                .is_ok()
        );
    }

    #[test]
    fn inet_listener_multiple_connects_drain_fifo() {
        let state = InetListenerState::new(AddressFamily::V4);
        let addr = bind_loopback(&state);
        state.listen(5).unwrap();

        let clients: Vec<_> = (0..3).map(|_| TcpStream::connect(addr).unwrap()).collect();
        let expected: Vec<_> = clients.iter().map(|s| s.local_addr().unwrap()).collect();
        let actual: Vec<_> = (0..3).map(|_| accept_wait(&state).1).collect();
        assert_eq!(actual, expected);
        assert!(matches!(state.accept(), Err(InetListenerError::WouldBlock)));
    }

    #[test]
    fn inet_listener_drop_stops_accept_thread() {
        let state = InetListenerState::new(AddressFamily::V4);
        bind_loopback(&state);
        state.listen(5).unwrap();
        assert!(
            state
                .accept_thread
                .lock()
                .expect("accept_thread poisoned")
                .as_ref()
                .is_some_and(|h| !h.is_finished())
        );
        let weak = Arc::downgrade(&state);
        drop(state);
        assert!(weak.upgrade().is_none());
    }
}
