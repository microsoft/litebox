// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted UDP datagram socket state.

use core::any::Any;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc as channel};
use std::thread;
use std::time::Duration;

use litebox_common_linux::fd_token_protocol::INET_DGRAM_RECV_FLAG_TRUNC;
use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_frame::{NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT};
use litebox_common_linux::notification_ring::NotificationSender;

use crate::cwfd::inet_listener_state::{AddressFamily, decode_sockaddr, encode_sockaddr};
use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

const RECV_QUEUE_CAP: usize = 128;
const SOCKADDR_WIRE_LEN: usize = 28;
const UDP_RECV_BUF_LEN: usize = 65_536;
const BROKER_DNS_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const DNS_PORT: u16 = 53;
const DNS_FORWARD_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum InetDgramError {
    #[error("invalid inet datagram sockaddr")]
    InvalidSockaddr,
    #[error("inet datagram socket is already bound")]
    AlreadyBound,
    #[error("inet datagram socket is not bound")]
    NotBound,
    #[error("inet datagram socket is not connected")]
    NotConnected,
    #[error("inet datagram operation would block")]
    WouldBlock,
    #[error("inet datagram OS error {0}")]
    Errno(i32),
    #[error("inet datagram I/O error")]
    Io(#[from] std::io::Error),
}

/// Broker-owned host UDP socket plus readiness subscribers.
#[derive(Debug)]
pub struct InetDgramState {
    family: AddressFamily,
    socket: Mutex<Option<UdpSocket>>,
    connected_peer: Mutex<Option<SocketAddr>>,
    subject: SubscriptionList,
    recv_tx: Mutex<Option<channel::SyncSender<(Vec<u8>, SocketAddr)>>>,
    recv_chan: Mutex<Option<channel::Receiver<(Vec<u8>, SocketAddr)>>>,
    recv_thread: Mutex<Option<thread::JoinHandle<()>>>,
    queued_recvs: AtomicUsize,
    stop_recv: Arc<AtomicBool>,
}

impl InetDgramState {
    pub fn new(family: AddressFamily) -> Arc<Self> {
        Arc::new(Self {
            family,
            socket: Mutex::new(None),
            connected_peer: Mutex::new(None),
            subject: SubscriptionList::new(),
            recv_tx: Mutex::new(None),
            recv_chan: Mutex::new(None),
            recv_thread: Mutex::new(None),
            queued_recvs: AtomicUsize::new(0),
            stop_recv: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn family(&self) -> AddressFamily {
        self.family
    }

    pub fn bind(
        self: &Arc<Self>,
        sockaddr: &[u8; SOCKADDR_WIRE_LEN],
    ) -> Result<[u8; SOCKADDR_WIRE_LEN], InetDgramError> {
        let addr = self.decode_family_sockaddr(sockaddr)?;
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        let actual = socket.local_addr()?;
        self.install_socket(socket)?;
        encode_sockaddr(actual).map_err(|_| InetDgramError::InvalidSockaddr)
    }

    pub fn connect(
        self: &Arc<Self>,
        sockaddr: &[u8; SOCKADDR_WIRE_LEN],
    ) -> Result<(), InetDgramError> {
        let peer = self.decode_family_sockaddr(sockaddr)?;
        self.ensure_socket()?;
        if !is_broker_dns_service(peer) {
            let socket = self.clone_socket()?;
            socket.connect(peer)?;
        }
        *self
            .connected_peer
            .lock()
            .expect("InetDgramState connected_peer poisoned") = Some(peer);
        Ok(())
    }

    pub fn sendto(
        self: &Arc<Self>,
        sockaddr: &[u8; SOCKADDR_WIRE_LEN],
        payload: &[u8],
    ) -> Result<usize, InetDgramError> {
        self.ensure_socket()?;
        let peer = if sockaddr.iter().all(|&b| b == 0) {
            self.connected_peer
                .lock()
                .expect("InetDgramState connected_peer poisoned")
                .ok_or(InetDgramError::NotConnected)?
        } else {
            self.decode_family_sockaddr(sockaddr)?
        };
        if is_broker_dns_service(peer) {
            return self.forward_dns_query(payload, peer);
        }

        let socket = self.clone_socket()?;
        let result = if sockaddr.iter().all(|&b| b == 0) {
            socket.send(payload)
        } else {
            socket.send_to(payload, peer)
        };
        match result {
            Ok(n) => Ok(n),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                Err(InetDgramError::WouldBlock)
            }
            Err(err) => Err(io_error_to_dgram_error(err)),
        }
    }

    pub fn recvfrom(
        &self,
        max_len: usize,
    ) -> Result<([u8; SOCKADDR_WIRE_LEN], Vec<u8>, u32), InetDgramError> {
        let guard = self
            .recv_chan
            .lock()
            .expect("InetDgramState recv_chan poisoned");
        let rx = guard.as_ref().ok_or(InetDgramError::NotBound)?;
        match rx.try_recv() {
            Ok((mut payload, peer)) => {
                self.queued_recvs.fetch_sub(1, Ordering::AcqRel);
                let mut flags = 0;
                if payload.len() > max_len {
                    payload.truncate(max_len);
                    flags |= INET_DGRAM_RECV_FLAG_TRUNC;
                }
                let peer = encode_sockaddr(peer).map_err(|_| InetDgramError::InvalidSockaddr)?;
                Ok((peer, payload, flags))
            }
            Err(channel::TryRecvError::Empty) => Err(InetDgramError::WouldBlock),
            Err(channel::TryRecvError::Disconnected) => Err(InetDgramError::Io(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "recv thread exited"),
            )),
        }
    }

    pub fn shutdown(&self, how: u8) -> Result<(), InetDgramError> {
        let socket = self.clone_socket()?;
        let how = match how {
            0 => libc::SHUT_RD,
            1 => libc::SHUT_WR,
            2 => libc::SHUT_RDWR,
            _ => return Err(InetDgramError::Errno(libc::EINVAL)),
        };
        // SAFETY: `socket.as_raw_fd()` is a valid live UDP socket fd for the duration of the call;
        // `how` is one of the libc SHUT_* constants validated above.
        let rc = unsafe { libc::shutdown(socket.as_raw_fd(), how) };
        if rc == 0 {
            Ok(())
        } else {
            Err(last_errno_error())
        }
    }

    pub fn getsockname(&self) -> Result<[u8; SOCKADDR_WIRE_LEN], InetDgramError> {
        let socket = self.clone_socket()?;
        encode_sockaddr(socket.local_addr()?).map_err(|_| InetDgramError::InvalidSockaddr)
    }

    pub fn getpeername(&self) -> Result<[u8; SOCKADDR_WIRE_LEN], InetDgramError> {
        let peer = self
            .connected_peer
            .lock()
            .expect("InetDgramState connected_peer poisoned")
            .ok_or(InetDgramError::NotConnected)?;
        encode_sockaddr(peer).map_err(|_| InetDgramError::InvalidSockaddr)
    }

    pub fn setsockopt(
        self: &Arc<Self>,
        level: i32,
        name: i32,
        value: &[u8],
    ) -> Result<(), InetDgramError> {
        // Real Linux: setsockopt works on an unbound socket (kernel just sets
        // an option on the socket struct, lazy-creates if needed). Match that
        // by ensuring the host socket exists before applying the option.
        // glibc's DNS resolver calls setsockopt(SOL_IP, IP_RECVERR) immediately
        // after socket() to enable extended error reporting; without this
        // ensure_socket, the call returned NotBound→EINVAL and the resolver
        // bailed before sending any DNS query.
        self.ensure_socket()?;
        let socket = self.clone_socket()?;
        let optlen: libc::socklen_t = value
            .len()
            .try_into()
            .map_err(|_| InetDgramError::Errno(libc::EINVAL))?;
        // SAFETY: `socket.as_raw_fd()` is live, and `value.as_ptr()` is valid for `optlen` bytes.
        // The kernel copies the option value during this call and does not retain the pointer.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                name,
                value.as_ptr().cast::<libc::c_void>(),
                optlen,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(last_errno_error())
        }
    }

    pub fn getsockopt(
        &self,
        level: i32,
        name: i32,
        max_len: u32,
    ) -> Result<Vec<u8>, InetDgramError> {
        let socket = self.clone_socket()?;
        let mut value = vec![0u8; max_len as usize];
        let mut optlen: libc::socklen_t = max_len;
        // SAFETY: `socket.as_raw_fd()` is live, `value` has capacity for `optlen` bytes, and
        // `&mut optlen` is a valid out-parameter for the kernel to report bytes written.
        let rc = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                level,
                name,
                value.as_mut_ptr().cast::<libc::c_void>(),
                &mut optlen,
            )
        };
        if rc == 0 {
            let len: usize = optlen
                .try_into()
                .map_err(|_| InetDgramError::Errno(libc::EINVAL))?;
            value.truncate(len);
            Ok(value)
        } else {
            Err(last_errno_error())
        }
    }

    pub fn current_events(&self) -> u32 {
        let mut events = NOTIFY_EVENT_OUT;
        if self.queued_recvs.load(Ordering::Acquire) != 0 {
            events |= NOTIFY_EVENT_IN;
        }
        events
    }

    fn decode_family_sockaddr(
        &self,
        sockaddr: &[u8; SOCKADDR_WIRE_LEN],
    ) -> Result<SocketAddr, InetDgramError> {
        let addr = decode_sockaddr(sockaddr).map_err(|_| InetDgramError::InvalidSockaddr)?;
        match (self.family, addr) {
            (AddressFamily::V4, SocketAddr::V4(_)) | (AddressFamily::V6, SocketAddr::V6(_)) => {
                Ok(addr)
            }
            (AddressFamily::V4, SocketAddr::V6(_)) | (AddressFamily::V6, SocketAddr::V4(_)) => {
                Err(InetDgramError::Errno(libc::EAFNOSUPPORT))
            }
        }
    }

    fn ensure_socket(self: &Arc<Self>) -> Result<(), InetDgramError> {
        if self
            .socket
            .lock()
            .expect("InetDgramState socket poisoned")
            .is_some()
        {
            return Ok(());
        }
        let bind_addr = match self.family {
            AddressFamily::V4 => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            AddressFamily::V6 => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
        };
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        self.install_socket(socket)
    }

    fn install_socket(self: &Arc<Self>, socket: UdpSocket) -> Result<(), InetDgramError> {
        let reader = socket.try_clone()?;
        {
            let mut slot = self.socket.lock().expect("InetDgramState socket poisoned");
            if slot.is_some() {
                return Err(InetDgramError::AlreadyBound);
            }
            *slot = Some(socket);
        }
        let (tx, rx) = channel::sync_channel(RECV_QUEUE_CAP);
        *self
            .recv_tx
            .lock()
            .expect("InetDgramState recv_tx poisoned") = Some(tx.clone());
        *self
            .recv_chan
            .lock()
            .expect("InetDgramState recv_chan poisoned") = Some(rx);
        let weak = Arc::downgrade(self);
        let stop = Arc::clone(&self.stop_recv);
        let handle = thread::Builder::new()
            .name("litebox-inet-dgram-recv".into())
            .spawn(move || recv_loop(reader, tx, weak, stop))?;
        *self
            .recv_thread
            .lock()
            .expect("InetDgramState recv_thread poisoned") = Some(handle);
        Ok(())
    }

    fn clone_socket(&self) -> Result<UdpSocket, InetDgramError> {
        self.socket
            .lock()
            .expect("InetDgramState socket poisoned")
            .as_ref()
            .ok_or(InetDgramError::NotBound)?
            .try_clone()
            .map_err(InetDgramError::Io)
    }

    /// Preserve the legacy Litebox resolver address after smoltcp removal by
    /// forwarding guest UDP DNS packets for 10.0.0.1:53 through the host resolver.
    fn forward_dns_query(
        self: &Arc<Self>,
        payload: &[u8],
        virtual_peer: SocketAddr,
    ) -> Result<usize, InetDgramError> {
        let host_dns = SocketAddr::V4(SocketAddrV4::new(
            crate::net_proxy::host_dns::discover_host_dns(),
            DNS_PORT,
        ));
        let query = payload.to_vec();
        let state = Arc::downgrade(self);
        thread::Builder::new()
            .name("litebox-dns-forward".into())
            .spawn(move || {
                let forwarder = match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
                {
                    Ok(forwarder) => forwarder,
                    Err(err) => {
                        tracing::warn!(error = %err, "DNS forwarder UDP bind failed");
                        return;
                    }
                };
                if let Err(err) = forwarder.set_read_timeout(Some(DNS_FORWARD_TIMEOUT)) {
                    tracing::warn!(error = %err, "DNS forwarder set_read_timeout failed");
                    return;
                };
                if let Err(err) = forwarder.send_to(&query, host_dns) {
                    tracing::warn!(error = %err, %host_dns, "DNS forwarder UDP send_to failed");
                    return;
                }

                let mut response = vec![0u8; UDP_RECV_BUF_LEN];
                let (len, _) = match forwarder.recv_from(&mut response) {
                    Ok(result) => result,
                    Err(err) => {
                        tracing::warn!(error = %err, %host_dns, "DNS forwarder UDP recv_from failed");
                        return;
                    }
                };
                response.truncate(len);
                if let Some(state) = state.upgrade() {
                    if let Err(err) = state.enqueue_datagram(response, virtual_peer) {
                        tracing::warn!(error = %err, %virtual_peer, "DNS forwarder enqueue failed");
                    }
                } else {
                    tracing::warn!("DNS forwarder state dropped before response enqueue");
                }
            })?;
        Ok(payload.len())
    }

    fn enqueue_datagram(&self, payload: Vec<u8>, peer: SocketAddr) -> Result<(), InetDgramError> {
        let tx = self
            .recv_tx
            .lock()
            .expect("InetDgramState recv_tx poisoned")
            .as_ref()
            .ok_or(InetDgramError::NotBound)?
            .clone();
        match tx.try_send((payload, peer)) {
            Ok(()) => {
                self.queued_recvs.fetch_add(1, Ordering::AcqRel);
                self.subject.notify(NOTIFY_EVENT_IN);
                Ok(())
            }
            Err(channel::TrySendError::Full(_)) => Err(InetDgramError::WouldBlock),
            Err(channel::TrySendError::Disconnected(_)) => Err(InetDgramError::Io(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "recv queue disconnected"),
            )),
        }
    }
}

impl Drop for InetDgramState {
    fn drop(&mut self) {
        self.stop_recv.store(true, Ordering::Release);
        let _ = self.socket.lock().map(|mut s| s.take());
        let _ = self.recv_tx.lock().map(|mut tx| tx.take());
        let _ = self.recv_chan.lock().map(|mut rx| rx.take());
        if let Ok(mut thread) = self.recv_thread.lock() {
            if let Some(handle) = thread.take() {
                let _ = handle.join();
            }
        }
    }
}

impl StateObject for InetDgramState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::InetDgram
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
        let now = self.current_events();
        self.subject.add(subscription_id, events_mask, sender)?;
        if now & events_mask != 0 {
            self.subject.notify(now);
        }
        Ok(())
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        self.subject.remove(subscription_id)
    }

    fn current_events(&self) -> u32 {
        InetDgramState::current_events(self)
    }

    fn try_flush_subscriptions(&self) {
        self.subject.try_flush();
    }
}

pub(crate) fn is_broker_dns_service(peer: SocketAddr) -> bool {
    matches!(peer, SocketAddr::V4(addr) if *addr.ip() == BROKER_DNS_ADDR && addr.port() == DNS_PORT)
}

fn recv_loop(
    socket: UdpSocket,
    tx: channel::SyncSender<(Vec<u8>, SocketAddr)>,
    state: std::sync::Weak<InetDgramState>,
    stop: Arc<AtomicBool>,
) {
    let mut buf = vec![0u8; UDP_RECV_BUF_LEN];
    while !stop.load(Ordering::Acquire) {
        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let payload = buf[..n].to_vec();
                let mut pending = Some((payload, peer));
                while let Some(item) = pending.take() {
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                    match tx.try_send(item) {
                        Ok(()) => {
                            if let Some(state) = state.upgrade() {
                                state.queued_recvs.fetch_add(1, Ordering::AcqRel);
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
            Err(_) => return,
        }
    }
}

fn last_errno_error() -> InetDgramError {
    InetDgramError::Errno(
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    )
}

fn io_error_to_dgram_error(err: std::io::Error) -> InetDgramError {
    match err.raw_os_error() {
        Some(errno) => InetDgramError::Errno(errno),
        None => InetDgramError::Io(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use litebox_common_linux::fd_token_protocol::INET_DGRAM_RECV_FLAG_TRUNC;

    fn loopback_zero() -> [u8; SOCKADDR_WIRE_LEN] {
        encode_sockaddr(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap()
    }

    fn bound_state() -> (Arc<InetDgramState>, SocketAddr) {
        let state = InetDgramState::new(AddressFamily::V4);
        state.bind(&loopback_zero()).unwrap();
        let local = decode_sockaddr(&state.getsockname().unwrap()).unwrap();
        (state, local)
    }

    fn recv_until(
        state: &InetDgramState,
        max_len: usize,
    ) -> Result<([u8; SOCKADDR_WIRE_LEN], Vec<u8>, u32), InetDgramError> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match state.recvfrom(max_len) {
                Err(InetDgramError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                other => return other,
            }
        }
    }

    #[test]
    fn inet_dgram_create_bind_recvfrom_wouldblock() {
        let (state, _) = bound_state();

        match state.recvfrom(64) {
            Err(InetDgramError::WouldBlock) => {}
            other => panic!("expected WouldBlock, got {other:?}"),
        }
        assert_eq!(state.current_events(), NOTIFY_EVENT_OUT);
    }

    #[test]
    fn inet_dgram_bind_receives_datagram_from_loopback_peer() {
        let (state, local) = bound_state();
        let sender = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        sender.send_to(b"hello", local).unwrap();

        let (peer_raw, payload, flags) = recv_until(&state, 64).unwrap();
        let peer = decode_sockaddr(&peer_raw).unwrap();
        assert_eq!(payload, b"hello");
        assert_eq!(flags, 0);
        assert_eq!(peer, sender.local_addr().unwrap());
    }

    #[test]
    fn inet_dgram_connected_sendto_zero_sockaddr_uses_peer() {
        let (state, _) = bound_state();
        let peer = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let peer_raw = encode_sockaddr(peer.local_addr().unwrap()).unwrap();

        state.connect(&peer_raw).unwrap();
        let zero_sockaddr = [0u8; SOCKADDR_WIRE_LEN];
        assert_eq!(state.sendto(&zero_sockaddr, b"connected").unwrap(), 9);

        let mut buf = [0u8; 32];
        let (n, from) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"connected");
        assert_eq!(
            from,
            decode_sockaddr(&state.getsockname().unwrap()).unwrap()
        );
    }

    #[test]
    fn inet_dgram_recvfrom_truncates_large_datagram() {
        let (state, local) = bound_state();
        let sender = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        sender.send_to(b"abcdef", local).unwrap();

        let (_peer, payload, flags) = recv_until(&state, 3).unwrap();
        assert_eq!(payload, b"abc");
        assert_eq!(
            flags & INET_DGRAM_RECV_FLAG_TRUNC,
            INET_DGRAM_RECV_FLAG_TRUNC
        );
    }

    #[test]
    fn inet_dgram_drop_joins_recv_thread() {
        let started = Instant::now();
        {
            let (state, _) = bound_state();
            assert!(state.recv_thread.lock().unwrap().is_some());
        }
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
