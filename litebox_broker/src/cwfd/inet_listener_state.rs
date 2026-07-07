// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted TCP listener state.

use core::any::Any;
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
};
use std::os::fd::{AsRawFd, FromRawFd};
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
    pending_sockopts: Mutex<Vec<StoredSockOpt>>,
    subject: SubscriptionList,
    accept_tx: Mutex<Option<channel::SyncSender<(TcpStream, SocketAddr)>>>,
    accept_rx: Mutex<Option<channel::Receiver<(TcpStream, SocketAddr)>>>,
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
            pending_sockopts: Mutex::new(Vec::new()),
            subject: SubscriptionList::new(),
            accept_tx: Mutex::new(None),
            accept_rx: Mutex::new(None),
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

    pub fn reuse_port_enabled(&self) -> bool {
        self.pending_sockopts
            .lock()
            .expect("InetListenerState pending_sockopts poisoned")
            .iter()
            .any(|opt| {
                opt.level == libc::SOL_SOCKET
                    && opt.optname == libc::SO_REUSEPORT
                    && opt
                        .value
                        .get(..std::mem::size_of::<libc::c_int>())
                        .is_some_and(|value| {
                            let mut raw = [0u8; std::mem::size_of::<libc::c_int>()];
                            raw.copy_from_slice(value);
                            libc::c_int::from_ne_bytes(raw) != 0
                        })
            })
    }

    pub fn getsockname(&self) -> Result<[u8; SOCKADDR_WIRE_LEN], InetListenerError> {
        let addr = self.bound_addr().ok_or(InetListenerError::NotBound)?;
        encode_sockaddr(addr)
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
        let listener = bind_tcp_listener_socket(
            addr,
            &self
                .pending_sockopts
                .lock()
                .expect("InetListenerState pending_sockopts poisoned"),
        )?;
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

    /// "Virtual bind" — register a bound address without actually binding
    /// a host TCP listener. Used when the broker `net_proxy` already owns
    /// the inbound host-port socket and will deliver accepted streams via
    /// [`accept_inbound`]. Sets `bound_addr` and leaves `listener` as
    /// `None`. [`listen`] handles both real-bind and virtual-bind cases.
    pub fn virtual_bind(
        &self,
        sockaddr: &[u8; SOCKADDR_WIRE_LEN],
    ) -> Result<[u8; SOCKADDR_WIRE_LEN], InetListenerError> {
        let addr = decode_sockaddr(sockaddr)?;
        match (self.family, addr) {
            (AddressFamily::V4, SocketAddr::V4(_)) | (AddressFamily::V6, SocketAddr::V6(_)) => {}
            _ => return Err(InetListenerError::InvalidSockaddr),
        }
        let mut slot = self
            .bound_addr
            .lock()
            .expect("InetListenerState bound_addr poisoned");
        if slot.is_some() {
            return Err(InetListenerError::AlreadyBound);
        }
        *slot = Some(addr);
        encode_sockaddr(addr)
    }

    pub fn setsockopt(
        &self,
        level: u32,
        optname: u32,
        optval: &[u8],
    ) -> Result<(), InetListenerError> {
        let level = level
            .try_into()
            .map_err(|_| InetListenerError::InvalidSockaddr)?;
        let optname = optname
            .try_into()
            .map_err(|_| InetListenerError::InvalidSockaddr)?;
        ensure_supported_sockopt(level, optname)?;
        if let Some(listener) = self
            .listener
            .lock()
            .expect("InetListenerState listener poisoned")
            .as_ref()
        {
            apply_setsockopt(listener.as_raw_fd(), level, optname, optval)?;
        }
        upsert_pending_sockopt(
            &mut self
                .pending_sockopts
                .lock()
                .expect("InetListenerState pending_sockopts poisoned"),
            level,
            optname,
            optval,
        );
        Ok(())
    }

    pub fn getsockopt(
        &self,
        level: u32,
        optname: u32,
        optlen: u32,
    ) -> Result<Vec<u8>, InetListenerError> {
        let level = level
            .try_into()
            .map_err(|_| InetListenerError::InvalidSockaddr)?;
        let optname = optname
            .try_into()
            .map_err(|_| InetListenerError::InvalidSockaddr)?;
        ensure_supported_sockopt(level, optname)?;
        if let Some(listener) = self
            .listener
            .lock()
            .expect("InetListenerState listener poisoned")
            .as_ref()
        {
            return read_getsockopt(listener.as_raw_fd(), level, optname, optlen);
        }
        let pending = self
            .pending_sockopts
            .lock()
            .expect("InetListenerState pending_sockopts poisoned");
        let default = 0i32.to_ne_bytes();
        let value = pending
            .iter()
            .find(|opt| opt.level == level && opt.optname == optname)
            .map(|opt| opt.value.as_slice())
            .unwrap_or(&default);
        let len = usize::try_from(optlen).map_err(|_| InetListenerError::InvalidSockaddr)?;
        Ok(value[..value.len().min(len)].to_vec())
    }

    pub fn listen(self: &Arc<Self>, _backlog: u32) -> Result<(), InetListenerError> {
        if self
            .accept_rx
            .lock()
            .expect("InetListenerState accept_rx poisoned")
            .is_some()
        {
            return Err(InetListenerError::AlreadyListening);
        }
        // Two cases:
        //   * Real bind  → self.listener is Some(TcpListener); spawn an
        //     accept_loop thread that pulls from the host listener.
        //   * Virtual bind → self.listener is None; just wire the
        //     accept_tx/accept_rx channel pair so net_proxy can deliver
        //     streams via accept_inbound.
        let maybe_listener = {
            let guard = self
                .listener
                .lock()
                .expect("InetListenerState listener poisoned");
            if let Some(listener) = guard.as_ref() {
                listen_on_socket(listener.as_raw_fd(), _backlog)?;
                listener.set_nonblocking(true)?;
                Some(listener.try_clone()?)
            } else {
                None
            }
        };
        if maybe_listener.is_none() {
            // Verify a bound_addr exists (virtual bind path).
            if self
                .bound_addr
                .lock()
                .expect("InetListenerState bound_addr poisoned")
                .is_none()
            {
                return Err(InetListenerError::NotBound);
            }
        }
        let (tx, rx) = channel::sync_channel(ACCEPT_QUEUE_CAP);
        *self
            .accept_tx
            .lock()
            .expect("InetListenerState accept_tx poisoned") = Some(tx.clone());
        *self
            .accept_rx
            .lock()
            .expect("InetListenerState accept_rx poisoned") = Some(rx);
        if let Some(listener) = maybe_listener {
            let weak = Arc::downgrade(self);
            let stop = Arc::clone(&self.stop_accept);
            let handle = thread::Builder::new()
                .name("litebox-inet-listener-accept".into())
                .spawn(move || accept_loop(listener, tx, weak, stop))?;
            *self
                .accept_thread
                .lock()
                .expect("InetListenerState accept_thread poisoned") = Some(handle);
        }
        Ok(())
    }

    pub fn accept(&self) -> Result<(TcpStream, SocketAddr), InetListenerError> {
        let guard = self
            .accept_rx
            .lock()
            .expect("InetListenerState accept_rx poisoned");
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

    pub fn accept_inbound(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> Result<(), InetListenerError> {
        stream.set_nonblocking(true)?;
        let tx = self
            .accept_tx
            .lock()
            .expect("InetListenerState accept_tx poisoned")
            .as_ref()
            .cloned()
            .ok_or(InetListenerError::NotBound)?;
        match tx.try_send((stream, peer)) {
            Ok(()) => {
                self.queued_accepts.fetch_add(1, Ordering::AcqRel);
                self.subject.notify(NOTIFY_EVENT_IN);
                Ok(())
            }
            Err(channel::TrySendError::Full(_)) => Err(InetListenerError::WouldBlock),
            Err(channel::TrySendError::Disconnected(_)) => Err(InetListenerError::Io(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "accept queue closed"),
            )),
        }
    }

    fn drain_host_listener(&self) {
        let listener = {
            self.listener
                .lock()
                .expect("InetListenerState listener poisoned")
                .as_ref()
                .map(|listener| listener.try_clone())
                .transpose()
        };
        let Ok(Some(listener)) = listener else {
            return;
        };
        loop {
            match listener.accept() {
                Ok((stream, peer)) => {
                    let _ = stream.set_nonblocking(true);
                    let Some(tx) = self
                        .accept_tx
                        .lock()
                        .expect("InetListenerState accept_tx poisoned")
                        .as_ref()
                        .cloned()
                    else {
                        return;
                    };
                    match tx.try_send((stream, peer)) {
                        Ok(()) => {
                            self.queued_accepts.fetch_add(1, Ordering::AcqRel);
                        }
                        Err(channel::TrySendError::Full(_)) => return,
                        Err(channel::TrySendError::Disconnected(_)) => {
                            self.accept_error.store(true, Ordering::Release);
                            return;
                        }
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => return,
                Err(_) => {
                    self.accept_error.store(true, Ordering::Release);
                    return;
                }
            }
        }
    }

    pub fn current_events(&self) -> u32 {
        self.drain_host_listener();
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
        let _ = self.accept_tx.lock().map(|mut tx| tx.take());
        let _ = self.accept_rx.lock().map(|mut rx| rx.take());
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

    fn try_flush_subscriptions(&self) {
        self.subject.try_flush();
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
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                thread::sleep(Duration::from_millis(10));
            }
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

#[derive(Clone, Debug)]
struct StoredSockOpt {
    level: libc::c_int,
    optname: libc::c_int,
    value: Vec<u8>,
}

fn bind_tcp_listener_socket(
    addr: SocketAddr,
    pending_sockopts: &[StoredSockOpt],
) -> Result<TcpListener, InetListenerError> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: `socket` is called with constant domain/type/protocol arguments.
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if domain == libc::AF_INET6 {
        apply_setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &0i32.to_ne_bytes(),
        )?;
    }
    for opt in pending_sockopts {
        if let Err(err) = apply_setsockopt(fd, opt.level, opt.optname, &opt.value) {
            // SAFETY: `fd` was returned by `socket` above and is still owned here.
            let _ = unsafe { libc::close(fd) };
            return Err(err);
        }
    }
    let bind_result = match addr {
        SocketAddr::V4(v4) => {
            let sockaddr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `sockaddr` points to a properly initialized sockaddr_in.
            unsafe {
                libc::bind(
                    fd,
                    (&raw const sockaddr).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(v6) => {
            let sockaddr = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: `sockaddr` points to a properly initialized sockaddr_in6.
            unsafe {
                libc::bind(
                    fd,
                    (&raw const sockaddr).cast(),
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if bind_result != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: `fd` was returned by `socket` above and is still owned here.
        let _ = unsafe { libc::close(fd) };
        return Err(err.into());
    }
    // SAFETY: `fd` is a successfully bound TCP socket and ownership moves to TcpListener.
    Ok(unsafe { TcpListener::from_raw_fd(fd) })
}

fn listen_on_socket(fd: libc::c_int, backlog: u32) -> Result<(), InetListenerError> {
    let backlog = backlog.try_into().unwrap_or(libc::c_int::MAX);
    // SAFETY: `fd` is the live socket wrapped by TcpListener.
    let rc = unsafe { libc::listen(fd, backlog) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn ensure_supported_sockopt(
    level: libc::c_int,
    optname: libc::c_int,
) -> Result<(), InetListenerError> {
    match (level, optname) {
        (libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)
        | (libc::IPPROTO_TCP, libc::TCP_KEEPCNT)
        | (libc::IPPROTO_TCP, libc::TCP_KEEPIDLE)
        | (libc::IPPROTO_TCP, libc::TCP_KEEPINTVL)
        | (libc::IPPROTO_TCP, libc::TCP_NODELAY)
        | (libc::SOL_SOCKET, libc::SO_KEEPALIVE)
        | (libc::SOL_SOCKET, libc::SO_REUSEADDR)
        | (libc::SOL_SOCKET, libc::SO_REUSEPORT) => Ok(()),
        _ => Err(InetListenerError::InvalidSockaddr),
    }
}

fn upsert_pending_sockopt(
    pending: &mut Vec<StoredSockOpt>,
    level: libc::c_int,
    optname: libc::c_int,
    optval: &[u8],
) {
    if let Some(existing) = pending
        .iter_mut()
        .find(|opt| opt.level == level && opt.optname == optname)
    {
        existing.value.clear();
        existing.value.extend_from_slice(optval);
    } else {
        pending.push(StoredSockOpt {
            level,
            optname,
            value: optval.to_vec(),
        });
    }
}

fn apply_setsockopt(
    fd: libc::c_int,
    level: libc::c_int,
    optname: libc::c_int,
    optval: &[u8],
) -> Result<(), InetListenerError> {
    // SAFETY: `fd` is a live socket fd and `optval` is a valid readable buffer.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            optval.as_ptr().cast(),
            optval
                .len()
                .try_into()
                .map_err(|_| InetListenerError::InvalidSockaddr)?,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn read_getsockopt(
    fd: libc::c_int,
    level: libc::c_int,
    optname: libc::c_int,
    optlen: u32,
) -> Result<Vec<u8>, InetListenerError> {
    let len = usize::try_from(optlen).map_err(|_| InetListenerError::InvalidSockaddr)?;
    let mut buf = vec![0u8; len];
    let mut raw_len: libc::socklen_t = len
        .try_into()
        .map_err(|_| InetListenerError::InvalidSockaddr)?;
    // SAFETY: `fd` is a live socket; `buf` is valid for `raw_len` bytes; `raw_len` is writable.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            buf.as_mut_ptr().cast(),
            &raw mut raw_len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let raw_len = usize::try_from(raw_len).map_err(|_| InetListenerError::InvalidSockaddr)?;
    buf.truncate(raw_len.min(buf.len()));
    Ok(buf)
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
    fn inet_listener_virtual_bind_skips_host_bind_and_accepts_inbound() {
        let state = InetListenerState::new(AddressFamily::V4);
        // Virtual bind: no host port grabbed, but a bound_addr is recorded
        // so listen() can proceed with channel-only setup.
        let requested = encode_sockaddr(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            42424,
        )))
        .unwrap();
        let actual = state.virtual_bind(&requested).unwrap();
        let actual_addr = decode_sockaddr(&actual).unwrap();
        assert_eq!(actual_addr.port(), 42424);
        // Second virtual_bind on the same state should fail.
        assert!(matches!(
            state.virtual_bind(&requested),
            Err(InetListenerError::AlreadyBound)
        ));

        // listen() should set up the channels without binding any host fd.
        state.listen(5).unwrap();

        // accept_inbound delivers a stream that accept() can retrieve.
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        // Use a real TCP pair via local loopback so accept_inbound's
        // set_nonblocking call works; we synthesize a connected client.
        let host_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let host_addr = host_listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(host_addr).unwrap();
        let (server_side, _) = host_listener.accept().unwrap();
        let _ = (a, b); // unused, just demonstrating pair available
        state
            .accept_inbound(server_side, host_addr)
            .expect("accept_inbound should queue");
        let (_stream, peer) = accept_wait(&state);
        assert_eq!(peer, host_addr);
        drop(client);
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
    fn inet_listener_ipv6_loopback_accepts_ipv6_client() {
        let state = InetListenerState::new(AddressFamily::V6);
        let requested = encode_sockaddr(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        )))
        .unwrap();
        let actual = decode_sockaddr(&state.bind(&requested).unwrap()).unwrap();
        state.listen(5).unwrap();

        let client = TcpStream::connect(actual).unwrap();
        let (_, peer) = accept_wait(&state);
        assert_eq!(peer, client.local_addr().unwrap());
    }

    #[test]
    fn inet_listener_ipv6_unspecified_v6only_false_accepts_ipv4_client() {
        let state = InetListenerState::new(AddressFamily::V6);
        state
            .setsockopt(
                libc::IPPROTO_IPV6 as u32,
                libc::IPV6_V6ONLY as u32,
                &0i32.to_ne_bytes(),
            )
            .unwrap();
        let requested = encode_sockaddr(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            0,
            0,
            0,
        )))
        .unwrap();
        let actual = decode_sockaddr(&state.bind(&requested).unwrap()).unwrap();
        state.listen(5).unwrap();

        let client = TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            actual.port(),
        )))
        .unwrap();
        let (_, peer) = accept_wait(&state);
        assert_eq!(peer.port(), client.local_addr().unwrap().port());
        assert!(matches!(peer, SocketAddr::V4(_) | SocketAddr::V6(_)));
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
