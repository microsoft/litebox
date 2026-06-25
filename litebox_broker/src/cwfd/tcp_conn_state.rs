// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted connected TCP socket state.

use core::any::Any;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_frame::{
    NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
};
use litebox_common_linux::notification_ring::NotificationSender;

use crate::cwfd::inet_listener_state::{AddressFamily, encode_sockaddr, family_from_u8};
use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

const SOCKADDR_WIRE_LEN: usize = 28;
pub const NOTIFY_EVENT_RDHUP: u32 = 0x2000;
pub const NOTIFY_EVENT_NVAL: u32 = libc::POLLNVAL as u32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TcpConnError {
    #[error("tcp connection operation would block")]
    WouldBlock,
    #[error("tcp connection peer is closed")]
    PeerClosed,
    #[error("tcp connection I/O error")]
    Io,
    #[error("tcp connection OS error {0}")]
    Errno(i32),
}

/// Broker-owned host TCP connection plus readiness subscribers.
#[derive(Debug)]
pub struct TcpConnState {
    inner: Mutex<TcpConnInner>,
    subject: SubscriptionList,
    /// Set by a `read` that drains the socket to `WouldBlock`; consumed by the
    /// poll thread to re-send a still-asserted readable level exactly once after
    /// a drain (missed-wakeup recovery) instead of unconditionally every tick.
    read_drained: AtomicBool,
}

#[derive(Debug)]
enum TcpConnInner {
    /// Created by InetTcpConnCreate; not yet connected.
    /// `getsockname` returns 0.0.0.0:0; `getpeername` returns ENOTCONN.
    Unconnected {
        family: u8,
        pending_sockopts: Vec<StoredSockOpt>,
    },
    /// Mid-connect. The background thread runs connect_timeout off-thread;
    /// completion is reaped by a subsequent start_connect call.
    Connecting {
        family: u8,
        target: SocketAddr,
        pending_sockopts: Vec<StoredSockOpt>,
        thread: JoinHandle<std::io::Result<TcpStream>>,
    },
    /// Normal connected state.
    Connected(TcpConnConnected),
}

/// Today's connected TCP socket payload.
#[derive(Debug)]
struct TcpConnConnected {
    stream: Mutex<TcpStream>,
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
    read_shutdown: AtomicBool,
    write_shutdown: AtomicBool,
}

#[derive(Clone, Debug)]
struct StoredSockOpt {
    level: libc::c_int,
    optname: libc::c_int,
    value: Vec<u8>,
}

impl TcpConnState {
    pub fn new(stream: TcpStream) -> Arc<Self> {
        let (connected, poll_stream) = TcpConnConnected::new(stream);
        let state = Arc::new(Self {
            inner: Mutex::new(TcpConnInner::Connected(connected)),
            subject: SubscriptionList::new(),
            read_drained: AtomicBool::new(false),
        });
        if let Some(poll_stream) = poll_stream {
            Self::spawn_poll_thread(Arc::downgrade(&state), poll_stream);
        }
        state
    }

    pub fn new_unconnected(family: u8) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(TcpConnInner::Unconnected {
                family,
                pending_sockopts: Vec::new(),
            }),
            subject: SubscriptionList::new(),
            read_drained: AtomicBool::new(false),
        })
    }

    pub fn adopt_connected_stream(self: &Arc<Self>, stream: TcpStream) -> Result<(), TcpConnError> {
        let mut guard = self.inner.lock().expect("TcpConnState inner poisoned");
        match &*guard {
            TcpConnInner::Unconnected { .. } => {
                let (connected, poll_stream) = TcpConnConnected::new(stream);
                *guard = TcpConnInner::Connected(connected);
                drop(guard);
                if let Some(poll_stream) = poll_stream {
                    Self::spawn_poll_thread(Arc::downgrade(self), poll_stream);
                }
                self.subject.notify(NOTIFY_EVENT_OUT);
                Ok(())
            }
            TcpConnInner::Connecting { .. } | TcpConnInner::Connected(_) => {
                Err(TcpConnError::Errno(libc::EISCONN))
            }
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        match &*self.inner.lock().expect("TcpConnState inner poisoned") {
            TcpConnInner::Connected(connected) => connected.local_addr,
            TcpConnInner::Unconnected { .. } | TcpConnInner::Connecting { .. } => None,
        }
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match &*self.inner.lock().expect("TcpConnState inner poisoned") {
            TcpConnInner::Connected(connected) => connected.peer_addr,
            TcpConnInner::Unconnected { .. } | TcpConnInner::Connecting { .. } => None,
        }
    }

    pub fn start_connect(
        self: &Arc<Self>,
        target: SocketAddr,
        timeout: Duration,
    ) -> Result<(), TcpConnError> {
        if let Some(result) = self.finish_completed_connect() {
            return result;
        }

        let mut inner = self.inner.lock().expect("TcpConnState inner poisoned");
        match &*inner {
            TcpConnInner::Unconnected {
                family,
                pending_sockopts,
            } => {
                validate_target_family(*family, target)?;
                let family = *family;
                let pending_sockopts = pending_sockopts.clone();
                let weak = Arc::downgrade(self);
                let thread = std::thread::Builder::new()
                    .name("litebox-tcp-conn-connect".into())
                    .spawn(move || {
                        let result = TcpStream::connect_timeout(&target, timeout);
                        if let Some(state) = weak.upgrade() {
                            let events = match &result {
                                Ok(_) => NOTIFY_EVENT_OUT,
                                Err(_) => NOTIFY_EVENT_OUT | NOTIFY_EVENT_ERR,
                            };
                            state.subject.notify(events);
                        }
                        result
                    })
                    .map_err(|_| TcpConnError::Io)?;
                *inner = TcpConnInner::Connecting {
                    family,
                    target,
                    pending_sockopts,
                    thread,
                };
                Err(TcpConnError::WouldBlock)
            }
            TcpConnInner::Connecting { .. } => Err(TcpConnError::WouldBlock),
            TcpConnInner::Connected(_) => Ok(()),
        }
    }

    pub fn getsockname(&self) -> Result<[u8; SOCKADDR_WIRE_LEN], TcpConnError> {
        match &*self.inner.lock().expect("TcpConnState inner poisoned") {
            TcpConnInner::Unconnected { family, .. } | TcpConnInner::Connecting { family, .. } => {
                encode_unspecified_sockaddr(*family)
            }
            TcpConnInner::Connected(connected) => encode_sockaddr(
                connected
                    .local_addr
                    .ok_or(TcpConnError::Errno(libc::EINVAL))?,
            )
            .map_err(|_| TcpConnError::Errno(libc::EINVAL)),
        }
    }

    pub fn getpeername(&self) -> Result<[u8; SOCKADDR_WIRE_LEN], TcpConnError> {
        match &*self.inner.lock().expect("TcpConnState inner poisoned") {
            TcpConnInner::Unconnected { .. } | TcpConnInner::Connecting { .. } => {
                Err(TcpConnError::Errno(libc::ENOTCONN))
            }
            TcpConnInner::Connected(connected) => encode_sockaddr(
                connected
                    .peer_addr
                    .ok_or(TcpConnError::Errno(libc::ENOTCONN))?,
            )
            .map_err(|_| TcpConnError::Errno(libc::EINVAL)),
        }
    }

    pub fn read(self: &Arc<Self>, max_len: usize) -> Result<Vec<u8>, TcpConnError> {
        if max_len == 0 {
            return Ok(Vec::new());
        }
        if let Some(result) = self.finish_completed_connect() {
            result?;
        }
        let mut guard = self.inner.lock().expect("TcpConnState inner poisoned");
        let TcpConnInner::Connected(connected) = &mut *guard else {
            return match &*guard {
                TcpConnInner::Connecting { .. } => Err(TcpConnError::WouldBlock),
                TcpConnInner::Unconnected { .. } => Err(TcpConnError::Errno(libc::ENOTCONN)),
                TcpConnInner::Connected(_) => unreachable!("matched Connected in else branch"),
            };
        };
        if connected.read_shutdown.load(Ordering::Acquire) {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; max_len];
        let result = connected
            .stream
            .lock()
            .expect("TcpConnState stream poisoned")
            .read(&mut buf);
        match result {
            Ok(n) => {
                buf.truncate(n);
                drop(guard);
                self.notify_current();
                if n == 0 {
                    self.subject.notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP);
                } else {
                    // The reader consumed a unit of data. Arm a one-shot re-send
                    // so the poll thread re-notifies subsequently-arriving data
                    // even when the readable level looks unchanged — a whole-unit
                    // reader (e.g. dropbear reading one SSH packet) never hits the
                    // WouldBlock arm below, so without this the next packet that
                    // lands inside a 10ms poll window is never signalled and the
                    // subscriber blocks forever.
                    self.read_drained.store(true, Ordering::Release);
                }
                Ok(buf)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Reader drained the socket. Arm a one-shot re-send so the poll
                // thread re-notifies when data next arrives even if the level
                // mask looks unchanged (see spawn_poll_thread).
                self.read_drained.store(true, Ordering::Release);
                Err(TcpConnError::WouldBlock)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotConnected
                ) =>
            {
                self.subject
                    .notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP | NOTIFY_EVENT_ERR);
                Err(TcpConnError::PeerClosed)
            }
            Err(_) => Err(TcpConnError::Io),
        }
    }

    pub fn write(self: &Arc<Self>, bytes: &[u8]) -> Result<usize, TcpConnError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if let Some(result) = self.finish_completed_connect() {
            result?;
        }
        let mut guard = self.inner.lock().expect("TcpConnState inner poisoned");
        let TcpConnInner::Connected(connected) = &mut *guard else {
            return match &*guard {
                TcpConnInner::Connecting { .. } => Err(TcpConnError::WouldBlock),
                TcpConnInner::Unconnected { .. } => Err(TcpConnError::Errno(libc::ENOTCONN)),
                TcpConnInner::Connected(_) => unreachable!("matched Connected in else branch"),
            };
        };
        if connected.write_shutdown.load(Ordering::Acquire) {
            return Err(TcpConnError::PeerClosed);
        }
        let result = connected
            .stream
            .lock()
            .expect("TcpConnState stream poisoned")
            .write(bytes);
        match result {
            Ok(n) => {
                drop(guard);
                self.notify_current();
                Ok(n)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(TcpConnError::WouldBlock),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotConnected
                ) =>
            {
                self.subject.notify(NOTIFY_EVENT_ERR | NOTIFY_EVENT_HUP);
                Err(TcpConnError::PeerClosed)
            }
            Err(_) => Err(TcpConnError::Io),
        }
    }

    pub fn shutdown(&self, read: bool, write: bool) -> Result<(), TcpConnError> {
        let how = match (read, write) {
            (true, true) => Some(Shutdown::Both),
            (true, false) => Some(Shutdown::Read),
            (false, true) => Some(Shutdown::Write),
            (false, false) => None,
        };
        let mut guard = self.inner.lock().expect("TcpConnState inner poisoned");
        let TcpConnInner::Connected(connected) = &mut *guard else {
            return Err(TcpConnError::Errno(libc::ENOTCONN));
        };
        if read {
            connected.read_shutdown.store(true, Ordering::Release);
        }
        if write {
            connected.write_shutdown.store(true, Ordering::Release);
        }
        if let Some(how) = how {
            connected
                .stream
                .lock()
                .expect("TcpConnState stream poisoned")
                .shutdown(how)
                .map_err(|_| TcpConnError::Io)?;
        }
        drop(guard);
        self.notify_current();
        Ok(())
    }

    pub fn setsockopt(&self, level: u32, optname: u32, optval: &[u8]) -> Result<(), TcpConnError> {
        let level = level
            .try_into()
            .map_err(|_| TcpConnError::Errno(libc::EINVAL))?;
        let optname = optname
            .try_into()
            .map_err(|_| TcpConnError::Errno(libc::EINVAL))?;
        ensure_supported_sockopt(level, optname, false)?;
        let mut inner = self.inner.lock().expect("TcpConnState inner poisoned");
        match &mut *inner {
            TcpConnInner::Unconnected {
                pending_sockopts, ..
            }
            | TcpConnInner::Connecting {
                pending_sockopts, ..
            } => {
                upsert_pending_sockopt(pending_sockopts, level, optname, optval);
                Ok(())
            }
            TcpConnInner::Connected(connected) => {
                let stream = connected
                    .stream
                    .lock()
                    .expect("TcpConnState stream poisoned");
                apply_setsockopt(stream.as_raw_fd(), level, optname, optval)
            }
        }
    }

    pub fn getsockopt(
        self: &Arc<Self>,
        level: u32,
        optname: u32,
        optlen: u32,
    ) -> Result<Vec<u8>, TcpConnError> {
        let level = level
            .try_into()
            .map_err(|_| TcpConnError::Errno(libc::EINVAL))?;
        let optname = optname
            .try_into()
            .map_err(|_| TcpConnError::Errno(libc::EINVAL))?;
        ensure_supported_sockopt(level, optname, true)?;
        // If a previous non-blocking connect() returned EINPROGRESS and the
        // worker has now woken on POLLOUT (we report NOTIFY_EVENT_OUT once
        // the connect thread finishes), it will check connect status via
        // getsockopt(SOL_SOCKET, SO_ERROR). Transition the Connecting state
        // here so SO_ERROR observes the real result instead of the stale
        // "still in progress" view.
        let connect_result = self.finish_completed_connect();
        let inner = self.inner.lock().expect("TcpConnState inner poisoned");
        match &*inner {
            TcpConnInner::Unconnected {
                pending_sockopts, ..
            } => {
                // SO_ERROR after a failed connect: surface the connect errno
                // exactly once, mirroring real Linux. Other sockopts on an
                // unconnected socket still need an explicit pending value.
                if level == libc::SOL_SOCKET && optname == libc::SO_ERROR {
                    let raw = match connect_result {
                        Some(Err(TcpConnError::Errno(errno))) => errno as u32,
                        Some(Err(_)) => libc::EIO as u32,
                        Some(Ok(())) | None => 0u32,
                    };
                    return Ok(raw.to_ne_bytes().to_vec());
                }
                pending_sockopts
                    .iter()
                    .rev()
                    .find(|opt| opt.level == level && opt.optname == optname)
                    .map(|opt| opt.value.clone())
                    .ok_or(TcpConnError::Errno(libc::ENOTCONN))
            }
            TcpConnInner::Connecting { .. } => {
                // Real Linux: getsockopt(SO_ERROR) on a still-pending
                // nonblocking connect returns 0 (no error yet). Match it
                // so callers don't treat "still connecting" as failure.
                if level == libc::SOL_SOCKET && optname == libc::SO_ERROR {
                    return Ok(0u32.to_ne_bytes().to_vec());
                }
                Err(TcpConnError::WouldBlock)
            }
            TcpConnInner::Connected(connected) => {
                let stream = connected
                    .stream
                    .lock()
                    .expect("TcpConnState stream poisoned");
                read_getsockopt(stream.as_raw_fd(), level, optname, optlen)
            }
        }
    }

    pub fn current_events(&self) -> u32 {
        let inner = self.inner.lock().expect("TcpConnState inner poisoned");
        match &*inner {
            TcpConnInner::Unconnected { .. } => NOTIFY_EVENT_NVAL,
            TcpConnInner::Connecting { thread, .. } => {
                if thread.is_finished() {
                    NOTIFY_EVENT_OUT
                } else {
                    0
                }
            }
            TcpConnInner::Connected(connected) => {
                let stream = connected
                    .stream
                    .lock()
                    .expect("TcpConnState stream poisoned");
                poll_stream_events(&stream)
            }
        }
    }

    fn notify_current(&self) {
        let events = notification_events(self.current_events());
        if events != 0 {
            self.subject.notify(events);
        }
    }

    fn finish_completed_connect(self: &Arc<Self>) -> Option<Result<(), TcpConnError>> {
        let pending = {
            let mut inner = self.inner.lock().expect("TcpConnState inner poisoned");
            match &*inner {
                TcpConnInner::Connecting { thread, .. } if thread.is_finished() => {}
                TcpConnInner::Unconnected { .. }
                | TcpConnInner::Connecting { .. }
                | TcpConnInner::Connected(_) => return None,
            }
            let previous = std::mem::replace(
                &mut *inner,
                TcpConnInner::Unconnected {
                    family: 0,
                    pending_sockopts: Vec::new(),
                },
            );
            match previous {
                TcpConnInner::Connecting {
                    family,
                    target,
                    pending_sockopts,
                    thread,
                } => {
                    *inner = TcpConnInner::Unconnected {
                        family,
                        pending_sockopts: pending_sockopts.clone(),
                    };
                    (family, target, pending_sockopts, thread)
                }
                TcpConnInner::Unconnected { .. } | TcpConnInner::Connected(_) => {
                    unreachable!("non-connecting TcpConnInner after Connecting match")
                }
            }
        };

        let (family, _target, pending_sockopts, thread) = pending;
        match thread.join() {
            Ok(Ok(stream)) => {
                for opt in &pending_sockopts {
                    if let Err(err) =
                        apply_setsockopt(stream.as_raw_fd(), opt.level, opt.optname, &opt.value)
                    {
                        *self.inner.lock().expect("TcpConnState inner poisoned") =
                            TcpConnInner::Unconnected {
                                family,
                                pending_sockopts,
                            };
                        self.subject.notify(NOTIFY_EVENT_OUT | NOTIFY_EVENT_ERR);
                        return Some(Err(err));
                    }
                }
                let (connected, poll_stream) = TcpConnConnected::new(stream);
                *self.inner.lock().expect("TcpConnState inner poisoned") =
                    TcpConnInner::Connected(connected);
                if let Some(poll_stream) = poll_stream {
                    Self::spawn_poll_thread(Arc::downgrade(self), poll_stream);
                }
                self.notify_current();
                Some(Ok(()))
            }
            Ok(Err(err)) => {
                *self.inner.lock().expect("TcpConnState inner poisoned") =
                    TcpConnInner::Unconnected {
                        family,
                        pending_sockopts,
                    };
                self.subject.notify(NOTIFY_EVENT_OUT | NOTIFY_EVENT_ERR);
                Some(Err(io_error_to_tcp_error(err)))
            }
            Err(_) => {
                *self.inner.lock().expect("TcpConnState inner poisoned") =
                    TcpConnInner::Unconnected {
                        family,
                        pending_sockopts,
                    };
                self.subject.notify(NOTIFY_EVENT_OUT | NOTIFY_EVENT_ERR);
                Some(Err(TcpConnError::Io))
            }
        }
    }

    fn spawn_poll_thread(state: Weak<Self>, stream: TcpStream) {
        let _ = std::thread::Builder::new()
            .name("litebox-tcp-conn-poll".into())
            .spawn(move || {
                let mut last = 0;
                loop {
                    let Some(state) = state.upgrade() else {
                        break;
                    };
                    let events = poll_stream_events(&stream);
                    let notify = notification_events(events);
                    // Edge-correct re-notification. Data/HUP/error readiness is
                    // level-triggered, so a read that drains the socket between
                    // poll samples must not mask the next arrival when the level
                    // mask looks unchanged. The old code resent on *every* tick
                    // whenever a readable bit was set, which converts a
                    // persistently-asserted level into an unbounded edge storm
                    // and livelocks a fast (libuv-style, level-triggered) epoll
                    // subscriber. Instead, resend a still-asserted readable level
                    // only once per drain: a `read` that hit WouldBlock arms
                    // `read_drained`, which we consume here.
                    let readable =
                        notify & (NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP | NOTIFY_EVENT_ERR) != 0;
                    let drained_resend =
                        readable && state.read_drained.swap(false, Ordering::AcqRel);
                    if notify != 0 && (notify != last || drained_resend) {
                        state.subject.notify(notify);
                    }
                    last = notify;
                    drop(state);
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
    }
}

impl TcpConnConnected {
    fn new(stream: TcpStream) -> (Self, Option<TcpStream>) {
        let _ = stream.set_nonblocking(true);
        let poll_stream = stream.try_clone().ok();
        (
            Self {
                local_addr: stream.local_addr().ok(),
                peer_addr: stream.peer_addr().ok(),
                stream: Mutex::new(stream),
                read_shutdown: AtomicBool::new(false),
                write_shutdown: AtomicBool::new(false),
            },
            poll_stream,
        )
    }
}

impl Drop for TcpConnState {
    fn drop(&mut self) {
        if let Ok(inner) = self.inner.lock() {
            match &*inner {
                TcpConnInner::Connected(connected) => {
                    if let Ok(stream) = connected.stream.lock() {
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                }
                TcpConnInner::Unconnected { .. } | TcpConnInner::Connecting { .. } => {}
            }
        }
        self.subject
            .notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP | NOTIFY_EVENT_ERR);
    }
}

fn ensure_supported_sockopt(
    level: libc::c_int,
    optname: libc::c_int,
    is_get: bool,
) -> Result<(), TcpConnError> {
    match (level, optname, is_get) {
        (libc::SOL_SOCKET, libc::SO_REUSEADDR, _)
        | (libc::SOL_SOCKET, libc::SO_REUSEPORT, _)
        | (libc::SOL_SOCKET, libc::SO_KEEPALIVE, _)
        | (libc::SOL_SOCKET, libc::SO_SNDBUF, _)
        | (libc::SOL_SOCKET, libc::SO_RCVBUF, _)
        | (libc::SOL_SOCKET, libc::SO_LINGER, _)
        | (libc::SOL_SOCKET, libc::SO_RCVTIMEO, _)
        | (libc::SOL_SOCKET, libc::SO_SNDTIMEO, _)
        | (libc::SOL_SOCKET, libc::SO_ERROR, true)
        | (libc::IPPROTO_TCP, libc::TCP_KEEPCNT, _)
        | (libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, _)
        | (libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, _)
        | (libc::IPPROTO_TCP, libc::TCP_NODELAY, _)
        | (libc::IPPROTO_IP, libc::IP_TTL, _)
        | (libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, false) => Ok(()),
        (libc::SOL_SOCKET, libc::SO_ERROR, false) => Err(TcpConnError::Errno(libc::ENOPROTOOPT)),
        _ => Err(TcpConnError::Errno(libc::EOPNOTSUPP)),
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
) -> Result<(), TcpConnError> {
    if (level, optname) == (libc::IPPROTO_IPV6, libc::IPV6_V6ONLY) {
        return Ok(());
    }
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
                .map_err(|_| TcpConnError::Errno(libc::EINVAL))?,
        )
    };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

fn read_getsockopt(
    fd: libc::c_int,
    level: libc::c_int,
    optname: libc::c_int,
    optlen: u32,
) -> Result<Vec<u8>, TcpConnError> {
    let mut buf = vec![0u8; optlen as usize];
    let mut len: libc::socklen_t = optlen;
    // SAFETY: `fd` is a live socket fd; `buf` and `len` point to writable storage.
    let rc = unsafe { libc::getsockopt(fd, level, optname, buf.as_mut_ptr().cast(), &raw mut len) };
    if rc == 0 {
        buf.truncate(len as usize);
        Ok(buf)
    } else {
        Err(last_errno())
    }
}

fn last_errno() -> TcpConnError {
    let errno = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO);
    TcpConnError::Errno(errno)
}

impl StateObject for TcpConnState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::TcpSocket
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
        let now = notification_events(self.current_events());
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
        notification_events(TcpConnState::current_events(self))
    }

    fn try_flush_subscriptions(&self) {
        self.subject.try_flush();
    }
}

fn notification_events(events: u32) -> u32 {
    let mut out =
        events & (NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT | NOTIFY_EVENT_ERR | NOTIFY_EVENT_HUP);
    if events & NOTIFY_EVENT_RDHUP != 0 {
        out |= NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP;
    }
    out
}

fn validate_target_family(family: u8, target: SocketAddr) -> Result<(), TcpConnError> {
    match (family_from_u8(family), target) {
        (Ok(AddressFamily::V4), SocketAddr::V4(_)) | (Ok(AddressFamily::V6), SocketAddr::V6(_)) => {
            Ok(())
        }
        (Ok(AddressFamily::V4), SocketAddr::V6(_)) | (Ok(AddressFamily::V6), SocketAddr::V4(_)) => {
            Err(TcpConnError::Errno(libc::EAFNOSUPPORT))
        }
        (Err(_), SocketAddr::V4(_) | SocketAddr::V6(_)) => {
            Err(TcpConnError::Errno(libc::EAFNOSUPPORT))
        }
    }
}

fn encode_unspecified_sockaddr(family: u8) -> Result<[u8; SOCKADDR_WIRE_LEN], TcpConnError> {
    match family_from_u8(family) {
        Ok(AddressFamily::V4) => {
            encode_sockaddr(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
                .map_err(|_| TcpConnError::Errno(libc::EINVAL))
        }
        Ok(AddressFamily::V6) => encode_sockaddr(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            0,
            0,
            0,
        )))
        .map_err(|_| TcpConnError::Errno(libc::EINVAL)),
        Err(_) => Err(TcpConnError::Errno(libc::EAFNOSUPPORT)),
    }
}

fn io_error_to_tcp_error(err: std::io::Error) -> TcpConnError {
    match err.raw_os_error() {
        Some(errno) => TcpConnError::Errno(errno),
        None if err.kind() == std::io::ErrorKind::TimedOut => TcpConnError::Errno(libc::ETIMEDOUT),
        None => TcpConnError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cwfd::inet_listener_state::decode_sockaddr;
    use litebox_common_linux::notification_ring::NotificationReceiver;
    use litebox_common_linux::shmem_ring::ShmemRingPair;
    use std::net::TcpListener;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    fn make_notification_pair() -> (Arc<Mutex<NotificationSender>>, NotificationReceiver) {
        let (pair, tx_fd, rx_fd) = ShmemRingPair::create().expect("ring create");
        let (broker_writer, _broker_reader_unused) = pair.into_parts();
        let (_worker_writer_unused, worker_reader) =
            ShmemRingPair::open(tx_fd, rx_fd).expect("ring open");
        (
            Arc::new(Mutex::new(NotificationSender::new(broker_writer))),
            NotificationReceiver::new(worker_reader),
        )
    }

    fn wait_for_connect(
        state: &Arc<TcpConnState>,
        target: SocketAddr,
        timeout: Duration,
    ) -> Result<(), TcpConnError> {
        assert!(matches!(
            state.start_connect(target, timeout),
            Err(TcpConnError::WouldBlock)
        ));
        let deadline = Instant::now() + timeout + Duration::from_secs(2);
        loop {
            if state.current_events() & NOTIFY_EVENT_OUT != 0 {
                return state.start_connect(target, timeout);
            }
            assert!(
                Instant::now() < deadline,
                "connect did not complete before deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn read_wait(state: &Arc<TcpConnState>, max_len: usize) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match state.read(max_len) {
                Ok(bytes) => return bytes,
                Err(TcpConnError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("tcp_conn read failed: {err:?}"),
            }
        }
    }

    #[test]
    fn tcp_conn_new_unconnected_getpeername_returns_enotconn() {
        let state = TcpConnState::new_unconnected(0);
        assert_eq!(
            state.getpeername(),
            Err(TcpConnError::Errno(libc::ENOTCONN))
        );
        let local = decode_sockaddr(&state.getsockname().unwrap()).unwrap();
        assert_eq!(
            local,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        );
    }

    #[test]
    fn tcp_conn_start_connect_to_host_listener_completes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = listener.local_addr().unwrap();
        let state = TcpConnState::new_unconnected(0);

        wait_for_connect(&state, target, Duration::from_secs(2)).unwrap();
        let (server, _) = listener.accept().unwrap();
        let peer = decode_sockaddr(&state.getpeername().unwrap()).unwrap();
        assert_eq!(peer, target);
        assert_eq!(state.peer_addr(), Some(target));
        drop(server);
    }

    #[test]
    fn tcp_conn_start_connect_to_unbound_port_returns_econnrefused() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = listener.local_addr().unwrap();
        drop(listener);
        let state = TcpConnState::new_unconnected(0);

        assert_eq!(
            wait_for_connect(&state, target, Duration::from_secs(2)),
            Err(TcpConnError::Errno(libc::ECONNREFUSED))
        );
    }

    #[test]
    fn tcp_conn_start_connect_timeout_returns_etimedout() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 1));
        let state = TcpConnState::new_unconnected(0);

        assert_eq!(
            wait_for_connect(&state, target, Duration::from_millis(100)),
            Err(TcpConnError::Errno(libc::ETIMEDOUT))
        );
    }

    #[test]
    fn tcp_conn_connected_state_read_write_shutdown_still_work() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(target).unwrap();
        let (server, _) = listener.accept().unwrap();
        let state = TcpConnState::new(server);

        client.write_all(b"ping").unwrap();
        assert_eq!(read_wait(&state, 4), b"ping");

        assert_eq!(state.write(b"pong").unwrap(), 4);
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");

        state.shutdown(false, true).unwrap();
        assert_eq!(state.write(b"again"), Err(TcpConnError::PeerClosed));
    }

    /// Regression: a persistently-readable connection whose readiness level
    /// never changes must not produce an unbounded per-tick re-notification
    /// storm to a fast subscriber. That storm livelocked libuv's
    /// level-triggered epoll loop and stalled the VS Code remote exthost
    /// keepalive (server->client silence -> 25s reconnect churn).
    #[test]
    fn poll_thread_does_not_storm_persistently_readable_conn() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(target).unwrap();
        let (server, _) = listener.accept().unwrap();
        let state = TcpConnState::new(server);

        let (sender, receiver) = make_notification_pair();
        state
            .subscribe(1, NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT, sender)
            .unwrap();

        // Persistently readable; we never drain it from the broker side, so the
        // poll thread observes an unchanged IN|OUT level on every 10ms tick.
        client.write_all(b"persistently-readable").unwrap();

        // Fast consumer: drain every frame so subscription coalescing cannot
        // hide a re-send storm.
        let count = Arc::new(AtomicUsize::new(0));
        let count_thread = count.clone();
        let drainer = std::thread::spawn(move || {
            let mut receiver = receiver;
            while receiver.recv().is_ok() {
                count_thread.fetch_add(1, Ordering::Relaxed);
            }
        });

        std::thread::sleep(Duration::from_millis(150));
        let observed = count.load(Ordering::Relaxed);

        // Close the ring so the drainer's blocking recv returns and it exits.
        drop(state);
        let _ = drainer.join();

        // 150ms is ~15 poll ticks. Edge-correct delivery emits only the initial
        // readiness edges (subscribe OUT, then the first IN|OUT); the old
        // every-tick resend emitted ~15. Generous slack for the initial edges.
        assert!(
            observed <= 4,
            "broker re-notification storm: {observed} frames in 150ms for an \
             unchanged readable level (expected a few edges, not a per-tick storm)"
        );
    }

    /// The drain-aware re-send must still recover readiness after a reader
    /// drains the socket and new data later arrives — the property the old
    /// unconditional every-tick resend provided.
    #[test]
    fn poll_thread_renotifies_after_drain_then_new_data() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(target).unwrap();
        let (server, _) = listener.accept().unwrap();
        let state = TcpConnState::new(server);

        let (sender, receiver) = make_notification_pair();
        state.subscribe(1, NOTIFY_EVENT_IN, sender).unwrap();

        let count = Arc::new(AtomicUsize::new(0));
        let count_thread = count.clone();
        let drainer = std::thread::spawn(move || {
            let mut receiver = receiver;
            while receiver.recv().is_ok() {
                count_thread.fetch_add(1, Ordering::Relaxed);
            }
        });

        // First arrival, drained fully: the trailing read returns WouldBlock,
        // which arms read_drained.
        client.write_all(b"first").unwrap();
        assert_eq!(read_wait(&state, 64), b"first");
        assert_eq!(state.read(64), Err(TcpConnError::WouldBlock));
        std::thread::sleep(Duration::from_millis(60));
        let before = count.load(Ordering::Relaxed);

        // New data after the drain must produce a fresh readiness notification.
        client.write_all(b"second").unwrap();
        std::thread::sleep(Duration::from_millis(120));
        let after = count.load(Ordering::Relaxed);

        drop(state);
        let _ = drainer.join();

        assert!(
            after > before,
            "no re-notification after drain + new data (before={before}, after={after}): \
             the missed-wakeup recovery regressed"
        );
    }

    /// Regression for the whole-unit-reader hang (broke the VS Code SSH
    /// handshake): a subscriber that reads a complete unit successfully —
    /// never hitting WouldBlock — must still be re-notified when the next unit
    /// arrives. dropbear reads one SSH packet at a time; an earlier version of
    /// this fix armed the re-notify only on the WouldBlock path, so the next
    /// packet landing inside a 10ms poll window was never signalled and
    /// `pselect6` blocked forever.
    #[test]
    fn poll_thread_renotifies_after_whole_unit_read_then_next_unit() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(target).unwrap();
        let (server, _) = listener.accept().unwrap();
        let state = TcpConnState::new(server);

        let (sender, receiver) = make_notification_pair();
        state.subscribe(1, NOTIFY_EVENT_IN, sender).unwrap();

        let count = Arc::new(AtomicUsize::new(0));
        let count_thread = count.clone();
        let drainer = std::thread::spawn(move || {
            let mut receiver = receiver;
            while receiver.recv().is_ok() {
                count_thread.fetch_add(1, Ordering::Relaxed);
            }
        });

        // Let the first unit settle so the read takes it whole in one Ok(n)
        // without ever hitting WouldBlock (the dropbear single-packet pattern).
        client.write_all(b"unit-1").unwrap();
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(read_wait(&state, 6), b"unit-1");
        std::thread::sleep(Duration::from_millis(40));
        let before = count.load(Ordering::Relaxed);

        // Next unit must produce a fresh readiness notification.
        client.write_all(b"unit-2").unwrap();
        std::thread::sleep(Duration::from_millis(150));
        let after = count.load(Ordering::Relaxed);

        drop(state);
        let _ = drainer.join();

        assert!(
            after > before,
            "whole-unit reader was not re-notified for the next unit (before={before}, \
             after={after}): the SSH-handshake hang regressed"
        );
    }
}

fn poll_stream_events(stream: &TcpStream) -> u32 {
    let mut pfd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN | libc::POLLOUT | libc::POLLERR | libc::POLLHUP | libc::POLLRDHUP,
        revents: 0,
    };
    // SAFETY: `pfd` points to one initialized pollfd and the timeout is zero.
    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
    if rc <= 0 {
        return 0;
    }
    let revents = pfd.revents;
    let mut events = 0;
    if revents & libc::POLLIN != 0 {
        events |= NOTIFY_EVENT_IN;
    }
    if revents & libc::POLLOUT != 0 {
        events |= NOTIFY_EVENT_OUT;
    }
    if revents & libc::POLLERR != 0 {
        events |= NOTIFY_EVENT_ERR;
    }
    if revents & libc::POLLHUP != 0 {
        events |= NOTIFY_EVENT_HUP;
    }
    if revents & libc::POLLRDHUP != 0 {
        events |= NOTIFY_EVENT_RDHUP | NOTIFY_EVENT_IN;
    }
    events
}
