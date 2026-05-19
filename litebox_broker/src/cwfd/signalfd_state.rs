// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted signalfd state.

use core::any::Any;
use std::collections::VecDeque;
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex, Weak};
use std::thread;

use litebox_common_linux::cwfd::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::cwfd::notification_frame::NOTIFY_EVENT_IN;
use litebox_common_linux::cwfd::notification_ring::NotificationSender;

use crate::cwfd::state_registry::StateObject;
use crate::cwfd::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

const SIGINFO_SIZE: usize = 128;

/// Broker-hosted state for one Linux signalfd.
#[derive(Debug)]
pub struct SignalfdState {
    fd: RawFd,
    queue: Mutex<VecDeque<Vec<u8>>>,
    subscriptions: SubscriptionList,
}

impl SignalfdState {
    /// Creates a new nonblocking, close-on-exec kernel signalfd for `sigmask`.
    pub fn new(sigmask_lo: u64, sigmask_hi: u64) -> std::io::Result<Arc<Self>> {
        let mut mask = empty_sigset()?;
        add_mask_bits(&mut mask, sigmask_lo, 0)?;
        add_mask_bits(&mut mask, sigmask_hi, 64)?;
        // SAFETY: `mask` is initialized by sigemptyset/sigaddset and lives for this call.
        let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let state = Arc::new(Self {
            fd,
            queue: Mutex::new(VecDeque::new()),
            subscriptions: SubscriptionList::new(),
        });
        Self::spawn_watcher(&state);
        Ok(state)
    }

    /// Reads one queued `signalfd_siginfo`, or directly from the kernel fd if needed.
    pub fn read_siginfo(&self) -> std::io::Result<Option<Vec<u8>>> {
        if let Some(payload) = self
            .queue
            .lock()
            .expect("SignalfdState poisoned")
            .pop_front()
        {
            return Ok(Some(payload));
        }
        match read_one_siginfo(self.fd)? {
            Some(payload) => Ok(Some(payload)),
            None => Ok(None),
        }
    }

    fn spawn_watcher(this: &Arc<Self>) {
        let weak = Arc::downgrade(this);
        let fd = this.fd;
        thread::Builder::new()
            .name("litebox-signalfd-watcher".into())
            .spawn(move || watcher_loop(weak, fd))
            .expect("spawn signalfd watcher");
    }

    pub fn enqueue_siginfo(&self, payload: Vec<u8>) {
        self.queue
            .lock()
            .expect("SignalfdState poisoned")
            .push_back(payload.clone());
        self.subscriptions.notify_payload(NOTIFY_EVENT_IN, payload);
    }

    fn current_events(&self) -> u32 {
        if !self
            .queue
            .lock()
            .expect("SignalfdState poisoned")
            .is_empty()
        {
            NOTIFY_EVENT_IN
        } else {
            0
        }
    }
}

impl Drop for SignalfdState {
    fn drop(&mut self) {
        // SAFETY: `fd` is owned by this state and closed exactly once here.
        unsafe { libc::close(self.fd) };
    }
}

impl StateObject for SignalfdState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::Signalfd
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
        self.subscriptions
            .add(subscription_id, events_mask, sender)?;
        let initial = self.current_events() & events_mask;
        if initial != 0 {
            self.subscriptions.notify(initial);
        }
        Ok(())
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        self.subscriptions.remove(subscription_id)
    }
}

fn watcher_loop(weak: Weak<SignalfdState>, fd: RawFd) {
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` points to one valid pollfd; timeout -1 means block indefinitely.
        let rc = unsafe { libc::poll(&mut pfd, 1, -1) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        let Some(state) = weak.upgrade() else {
            return;
        };
        loop {
            match read_one_siginfo(fd) {
                Ok(Some(payload)) => state.enqueue_siginfo(payload),
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
}

fn read_one_siginfo(fd: RawFd) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = vec![0u8; SIGINFO_SIZE];
    // SAFETY: `buf` is valid for SIGINFO_SIZE bytes and `fd` is a signalfd.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        let err = std::io::Error::last_os_error();
        return if err.kind() == std::io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(err)
        };
    }
    if n == 0 {
        return Ok(None);
    }
    buf.truncate(n as usize);
    Ok(Some(buf))
}

fn empty_sigset() -> std::io::Result<libc::sigset_t> {
    // SAFETY: sigset_t may be zero-initialized before passing to sigemptyset.
    let mut mask = unsafe { core::mem::zeroed::<libc::sigset_t>() };
    // SAFETY: `mask` is a valid, writable sigset_t.
    if unsafe { libc::sigemptyset(&mut mask) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(mask)
}

fn add_mask_bits(mask: &mut libc::sigset_t, bits: u64, base: i32) -> std::io::Result<()> {
    for bit in 0..64 {
        if bits & (1u64 << bit) == 0 {
            continue;
        }
        let signo = base + bit + 1;
        // SAFETY: `mask` is valid and `signo` comes from the caller's mask bits.
        if unsafe { libc::sigaddset(mask, signo) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
