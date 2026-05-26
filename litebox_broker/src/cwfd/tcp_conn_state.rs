// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted connected TCP socket state.

use core::any::Any;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_frame::{
    NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
};
use litebox_common_linux::notification_ring::NotificationSender;

use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

pub const NOTIFY_EVENT_RDHUP: u32 = 0x2000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TcpConnError {
    #[error("tcp connection operation would block")]
    WouldBlock,
    #[error("tcp connection peer is closed")]
    PeerClosed,
    #[error("tcp connection I/O error")]
    Io,
}

/// Broker-owned host TCP stream plus readiness subscribers.
#[derive(Debug)]
pub struct TcpConnState {
    stream: Mutex<TcpStream>,
    subject: SubscriptionList,
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
    read_shutdown: AtomicBool,
    write_shutdown: AtomicBool,
}

impl TcpConnState {
    pub fn new(stream: TcpStream) -> Arc<Self> {
        let _ = stream.set_nonblocking(true);
        let poll_stream = stream.try_clone().ok();
        let state = Arc::new(Self {
            local_addr: stream.local_addr().ok(),
            peer_addr: stream.peer_addr().ok(),
            stream: Mutex::new(stream),
            subject: SubscriptionList::new(),
            read_shutdown: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
        });
        if let Some(poll_stream) = poll_stream {
            Self::spawn_poll_thread(Arc::downgrade(&state), poll_stream);
        }
        state
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    pub fn read(&self, max_len: usize) -> Result<Vec<u8>, TcpConnError> {
        if max_len == 0 {
            return Ok(Vec::new());
        }
        if self.read_shutdown.load(Ordering::Acquire) {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; max_len];
        let result = self
            .stream
            .lock()
            .expect("TcpConnState stream poisoned")
            .read(&mut buf);
        match result {
            Ok(n) => {
                buf.truncate(n);
                self.notify_current();
                if n == 0 {
                    self.subject.notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP);
                }
                Ok(buf)
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
                self.subject
                    .notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP | NOTIFY_EVENT_ERR);
                Err(TcpConnError::PeerClosed)
            }
            Err(_) => Err(TcpConnError::Io),
        }
    }

    pub fn write(&self, bytes: &[u8]) -> Result<usize, TcpConnError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.write_shutdown.load(Ordering::Acquire) {
            return Err(TcpConnError::PeerClosed);
        }
        let result = self
            .stream
            .lock()
            .expect("TcpConnState stream poisoned")
            .write(bytes);
        match result {
            Ok(n) => {
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
        if read {
            self.read_shutdown.store(true, Ordering::Release);
        }
        if write {
            self.write_shutdown.store(true, Ordering::Release);
        }
        if let Some(how) = how {
            self.stream
                .lock()
                .expect("TcpConnState stream poisoned")
                .shutdown(how)
                .map_err(|_| TcpConnError::Io)?;
        }
        self.notify_current();
        Ok(())
    }

    pub fn current_events(&self) -> u32 {
        let stream = self.stream.lock().expect("TcpConnState stream poisoned");
        poll_stream_events(&stream)
    }

    fn notify_current(&self) {
        let events = notification_events(self.current_events());
        if events != 0 {
            self.subject.notify(events);
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
                    if notify != 0 && notify != last {
                        state.subject.notify(notify);
                        last = notify;
                    } else if notify == 0 {
                        last = 0;
                    }
                    drop(state);
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
    }
}

impl Drop for TcpConnState {
    fn drop(&mut self) {
        if let Ok(stream) = self.stream.lock() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        self.subject
            .notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP | NOTIFY_EVENT_ERR);
    }
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
}

fn notification_events(events: u32) -> u32 {
    let mut out =
        events & (NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT | NOTIFY_EVENT_ERR | NOTIFY_EVENT_HUP);
    if events & NOTIFY_EVENT_RDHUP != 0 {
        out |= NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP;
    }
    out
}

fn poll_stream_events(stream: &TcpStream) -> u32 {
    let mut pfd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN | libc::POLLOUT | libc::POLLERR | libc::POLLHUP | libc::POLLRDHUP,
        revents: 0,
    };
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
