// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted signalfd state.

use core::any::Any;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use litebox_common_linux::cwfd::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::cwfd::notification_frame::NOTIFY_EVENT_IN;
use litebox_common_linux::cwfd::notification_ring::NotificationSender;

use crate::cwfd::state_registry::StateObject;
use crate::cwfd::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

/// Broker-hosted state for one Linux signalfd.
#[derive(Debug)]
pub struct SignalfdState {
    queue: Mutex<VecDeque<Vec<u8>>>,
    subscriptions: SubscriptionList,
}

impl SignalfdState {
    /// Creates broker-hosted signalfd state for `sigmask`.
    pub fn new(sigmask_lo: u64, sigmask_hi: u64) -> std::io::Result<Arc<Self>> {
        let mut mask = empty_sigset()?;
        add_mask_bits(&mut mask, sigmask_lo, 0)?;
        add_mask_bits(&mut mask, sigmask_hi, 64)?;
        Ok(Arc::new(Self {
            queue: Mutex::new(VecDeque::new()),
            subscriptions: SubscriptionList::new(),
        }))
    }

    /// Reads one queued `signalfd_siginfo`, or `None` when no guest signal is pending.
    pub fn read_siginfo(&self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self
            .queue
            .lock()
            .expect("SignalfdState poisoned")
            .pop_front())
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

    fn current_events(&self) -> u32 {
        SignalfdState::current_events(self)
    }

    fn try_flush_subscriptions(&self) {
        self.subscriptions.try_flush();
    }
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
