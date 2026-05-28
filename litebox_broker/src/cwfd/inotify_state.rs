// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted state for one Linux inotify instance.

use core::any::Any;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};

use litebox_common_linux::cwfd::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::cwfd::notification_frame::NOTIFY_EVENT_IN;
use litebox_common_linux::cwfd::notification_ring::NotificationSender;

use crate::cwfd::inotify_dispatcher::InotifyDispatcher;
use crate::cwfd::state_registry::StateObject;
use crate::cwfd::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

const INOTIFY_EVENT_HEADER_LEN: usize = 16;

#[derive(Clone, Debug)]
struct InotifyWatch {
    path: String,
    mask: u32,
}

#[derive(Clone, Debug)]
struct InotifyEventRecord {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: String,
}

impl InotifyEventRecord {
    fn encoded_len(&self) -> usize {
        INOTIFY_EVENT_HEADER_LEN + self.name.len() + 1
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.wd.to_ne_bytes());
        out.extend_from_slice(&self.mask.to_ne_bytes());
        out.extend_from_slice(&self.cookie.to_ne_bytes());
        let len = u32::try_from(self.name.len() + 1).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_ne_bytes());
        out.extend_from_slice(self.name.as_bytes());
        out.push(0);
    }
}

/// Broker-hosted state for one inotify file descriptor.
#[derive(Debug)]
pub struct InotifyState {
    self_ref: Weak<InotifyState>,
    watches: Mutex<BTreeMap<i32, InotifyWatch>>,
    next_watch_descriptor: Mutex<i32>,
    queue: Mutex<VecDeque<InotifyEventRecord>>,
    subscriptions: SubscriptionList,
    dispatcher: Arc<InotifyDispatcher>,
}

impl InotifyState {
    pub fn new(dispatcher: Arc<InotifyDispatcher>) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            self_ref: weak.clone(),
            watches: Mutex::new(BTreeMap::new()),
            next_watch_descriptor: Mutex::new(1),
            queue: Mutex::new(VecDeque::new()),
            subscriptions: SubscriptionList::new(),
            dispatcher,
        })
    }

    pub fn add_watch(&self, path: String, mask: u32) -> Result<i32, ()> {
        if path.is_empty() || mask == 0 {
            return Err(());
        }
        let mut next = self.next_watch_descriptor.lock().expect("InotifyState poisoned");
        let wd = *next;
        *next = next.checked_add(1).ok_or(())?;
        self.watches
            .lock()
            .expect("InotifyState poisoned")
            .insert(wd, InotifyWatch { path: path.clone(), mask });
        if let Some(state) = self.self_ref.upgrade() {
            self.dispatcher.register(path, wd, mask, &state);
        }
        Ok(wd)
    }

    pub fn remove_watch(&self, wd: i32) -> Result<(), ()> {
        if wd <= 0 {
            return Err(());
        }
        let removed = self
            .watches
            .lock()
            .expect("InotifyState poisoned")
            .remove(&wd)
            .ok_or(())?;
        self.dispatcher.unregister(&removed.path, wd);
        Ok(())
    }

    pub fn enqueue_event(&self, wd: i32, mask: u32, cookie: u32, name: String) {
        self.queue
            .lock()
            .expect("InotifyState poisoned")
            .push_back(InotifyEventRecord { wd, mask, cookie, name });
        self.subscriptions.notify(NOTIFY_EVENT_IN);
    }

    pub fn read_events(&self, max_len: usize) -> Result<Option<Vec<u8>>, ()> {
        let mut queue = self.queue.lock().expect("InotifyState poisoned");
        let Some(first) = queue.front() else {
            return Ok(None);
        };
        if first.encoded_len() > max_len {
            return Err(());
        }
        let mut out = Vec::new();
        while let Some(event) = queue.front() {
            let len = event.encoded_len();
            if out.len() + len > max_len {
                break;
            }
            let event = queue.pop_front().expect("front exists");
            event.encode_into(&mut out);
        }
        Ok(Some(out))
    }

    fn current_events(&self) -> u32 {
        if self.queue.lock().expect("InotifyState poisoned").is_empty() {
            0
        } else {
            NOTIFY_EVENT_IN
        }
    }
}

impl Drop for InotifyState {
    fn drop(&mut self) {
        let watches = std::mem::take(&mut *self.watches.lock().expect("InotifyState poisoned"));
        for (wd, watch) in watches {
            self.dispatcher.unregister(&watch.path, wd);
        }
    }
}

impl StateObject for InotifyState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::Inotify
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
        self.subscriptions.add(subscription_id, events_mask, sender)?;
        let initial = self.current_events() & events_mask;
        if initial != 0 {
            self.subscriptions.notify(initial);
        }
        Ok(())
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        self.subscriptions.remove(subscription_id)
    }

    fn current_events(&self) -> u32 {
        InotifyState::current_events(self)
    }
}
