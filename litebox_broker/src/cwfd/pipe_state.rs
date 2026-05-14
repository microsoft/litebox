// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted pipe state.
//!
//! `PipeState` is the canonical readiness/refcount owner for a
//! cross-worker pipe.  The data plane is broker-mediated for Phase C:
//! workers issue read/write RPCs against the same state handle, and the
//! broker wakes read-side subscribers with `IN|HUP` when data arrives or
//! the last write end closes.

use core::any::Any;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_frame::{
    NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
};
use litebox_common_linux::notification_ring::NotificationSender;

use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

/// Which end of a pipe an operation addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeEndKind {
    Read,
    Write,
}

impl PipeEndKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            _ => None,
        }
    }
}

/// Errors returned by pipe operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PipeError {
    #[error("pipe operation would block")]
    WouldBlock,
    #[error("pipe peer is closed")]
    PeerClosed,
    #[error("invalid pipe end")]
    InvalidEnd,
}

#[derive(Debug)]
struct PipeInner {
    buf: VecDeque<u8>,
    capacity: usize,
    read_open: bool,
    write_open: bool,
}

/// Broker-hosted state for one unidirectional pipe.
#[derive(Debug)]
pub struct PipeState {
    inner: Mutex<PipeInner>,
    read_subject: SubscriptionList,
    write_subject: SubscriptionList,
    read_refcount: AtomicUsize,
    write_refcount: AtomicUsize,
    atomic_write_size: usize,
}

impl PipeState {
    pub fn new(capacity: usize, atomic_write_size: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(PipeInner {
                buf: VecDeque::with_capacity(capacity),
                capacity,
                read_open: true,
                write_open: true,
            }),
            read_subject: SubscriptionList::new(),
            write_subject: SubscriptionList::new(),
            read_refcount: AtomicUsize::new(1),
            write_refcount: AtomicUsize::new(1),
            atomic_write_size,
        })
    }

    pub fn incref_read_end(&self) {
        self.read_refcount.fetch_add(1, Ordering::AcqRel);
    }

    pub fn incref_write_end(&self) {
        self.write_refcount.fetch_add(1, Ordering::AcqRel);
    }

    pub fn decref_read_end(&self) {
        if self.read_refcount.fetch_sub(1, Ordering::AcqRel) == 1 {
            let mut inner = self.inner.lock().expect("PipeState poisoned");
            inner.read_open = false;
            drop(inner);
            self.write_subject.notify(NOTIFY_EVENT_ERR);
        }
    }

    pub fn decref_write_end(&self) {
        if self.write_refcount.fetch_sub(1, Ordering::AcqRel) == 1 {
            let mut inner = self.inner.lock().expect("PipeState poisoned");
            inner.write_open = false;
            drop(inner);
            self.read_subject.notify(NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN);
        }
    }

    pub fn read(&self, max_len: usize) -> Result<Vec<u8>, PipeError> {
        let mut inner = self.inner.lock().expect("PipeState poisoned");
        if max_len == 0 {
            return Ok(Vec::new());
        }
        if inner.buf.is_empty() {
            if !inner.write_open {
                return Ok(Vec::new());
            }
            return Err(PipeError::WouldBlock);
        }
        let n = core::cmp::min(max_len, inner.buf.len());
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(inner.buf.pop_front().expect("length checked"));
        }
        let events = current_events_unlocked(&inner);
        drop(inner);
        if events.write != 0 {
            self.write_subject.notify(events.write);
        }
        Ok(out)
    }

    pub fn write(&self, bytes: &[u8]) -> Result<usize, PipeError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut inner = self.inner.lock().expect("PipeState poisoned");
        if !inner.read_open {
            return Err(PipeError::PeerClosed);
        }
        if !inner.write_open {
            return Err(PipeError::InvalidEnd);
        }
        let vacant = inner.capacity.saturating_sub(inner.buf.len());
        if vacant == 0 || (bytes.len() <= self.atomic_write_size && vacant < bytes.len()) {
            return Err(PipeError::WouldBlock);
        }
        let n = core::cmp::min(vacant, bytes.len());
        inner.buf.extend(bytes[..n].iter().copied());
        let events = current_events_unlocked(&inner);
        drop(inner);
        if events.read != 0 {
            self.read_subject.notify(events.read);
        }
        Ok(n)
    }

    pub fn current_events(&self, end: PipeEndKind) -> u32 {
        let inner = self.inner.lock().expect("PipeState poisoned");
        let events = current_events_unlocked(&inner);
        match end {
            PipeEndKind::Read => events.read,
            PipeEndKind::Write => events.write,
        }
    }

    pub fn subscribe_end(
        &self,
        end: PipeEndKind,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        let now = self.current_events(end);
        let list = match end {
            PipeEndKind::Read => &self.read_subject,
            PipeEndKind::Write => &self.write_subject,
        };
        list.add(subscription_id, events_mask, sender)?;
        if now & events_mask != 0 {
            list.notify(now);
        }
        Ok(())
    }

    pub fn unsubscribe_end(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        if self.read_subject.remove(subscription_id).is_ok() {
            return Ok(());
        }
        self.write_subject.remove(subscription_id)
    }
}

struct ReadyEvents {
    read: u32,
    write: u32,
}

fn current_events_unlocked(inner: &PipeInner) -> ReadyEvents {
    let mut read = 0;
    let mut write = 0;
    if !inner.buf.is_empty() {
        read |= NOTIFY_EVENT_IN;
    }
    if !inner.write_open {
        read |= NOTIFY_EVENT_HUP;
    }
    if !inner.read_open {
        write |= NOTIFY_EVENT_ERR;
    } else if inner.write_open && inner.buf.len() < inner.capacity {
        write |= NOTIFY_EVENT_OUT;
    }
    ReadyEvents { read, write }
}

impl StateObject for PipeState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::Pipe
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
        self.subscribe_end(PipeEndKind::Read, subscription_id, events_mask, sender)
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        self.unsubscribe_end(subscription_id)
    }
}
