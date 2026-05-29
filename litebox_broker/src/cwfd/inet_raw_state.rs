// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted raw IPv4 socket state.
//!
//! Raw sockets are deliberately sandbox-policy-gated: they can observe and
//! inject packets below the transport layer, so the broker's default policy is
//! to refuse them unless an explicit broker flag enables a narrow allowlist.
//! Phase D wires the control/state shape first and returns clean policy errors;
//! future work can replace `new_denied`/operation stubs with permitted-protocol
//! host raw socket creation without changing the shim-facing protocol.

use core::any::Any;
use std::sync::{Arc, Mutex};

use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_ring::NotificationSender;

use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InetRawError {
    #[error("raw socket operation denied by broker policy")]
    PermissionDenied,
    #[error("raw socket operation would block")]
    WouldBlock,
    #[error("raw socket invalid value")]
    InvalidValue,
}

#[derive(Debug)]
pub struct InetRawState {
    family: u8,
    protocol: u8,
    subject: SubscriptionList,
}

impl InetRawState {
    pub fn new_denied(family: u8, protocol: u8) -> Arc<Self> {
        Arc::new(Self {
            family,
            protocol,
            subject: SubscriptionList::new(),
        })
    }

    pub fn family(&self) -> u8 {
        self.family
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn send_to(&self, _sockaddr: &[u8; 28], _bytes: &[u8]) -> Result<usize, InetRawError> {
        Err(InetRawError::PermissionDenied)
    }

    pub fn recv_from(&self, _max_len: u64) -> Result<([u8; 28], Vec<u8>), InetRawError> {
        Err(InetRawError::PermissionDenied)
    }

    pub fn current_events(&self) -> u32 {
        0
    }
}

impl StateObject for InetRawState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::InetRaw
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
        InetRawState::current_events(self)
    }
}
