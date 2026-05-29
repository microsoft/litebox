// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared broker channel contracts.
//!
//! This crate defines delivery contracts for broker authority messages. The
//! current surface is intentionally limited to the paired control channel:
//! one [`BrokerRequest`] produces one [`BrokerResponse`]. Concrete IPC
//! implementations own framing, buffering, authentication, and the mechanism;
//! non-blocking IPCs can provide a blocking adapter at this boundary.
//!
//! Broker-initiated readiness, interrupt, fault, revocation, or session-failure
//! traffic must use a separately named notification channel and notification
//! message family when that lane is introduced. Such notifications must not be
//! delivered as unsolicited control-channel responses.

#![no_std]

use litebox_broker_protocol::{BrokerRequest, BrokerResponse};

/// Peer identity information supplied by the channel or host layer.
///
/// The first userland proof of concept does not authenticate Unix-socket peers,
/// but channels still return an explicit credential value so the server layer
/// can map authenticated peer identity into BrokerCore caller identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PeerCredential {
    /// Explicit deployment mode for the initial unauthenticated userland POC.
    ///
    /// Channels that are expected to authenticate peers must return an error
    /// from [`ServerControlChannel::peer_credential`] when authentication is
    /// unavailable or fails; this variant is only for deployments that
    /// deliberately choose unauthenticated operation.
    Unauthenticated,
}

/// Broker authority request received from a control channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceivedBrokerRequest {
    /// A request understood by the current protocol crate.
    Request(BrokerRequest),
    /// A request emitted by a newer peer and not understood by this process.
    Unknown,
}

impl From<BrokerRequest> for ReceivedBrokerRequest {
    fn from(request: BrokerRequest) -> Self {
        Self::Request(request)
    }
}

/// Broker authority response received from a control channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceivedBrokerResponse {
    /// A response understood by the current protocol crate.
    Response(BrokerResponse),
    /// A response emitted by a newer broker and not understood by this process.
    Unknown,
}

impl From<BrokerResponse> for ReceivedBrokerResponse {
    fn from(response: BrokerResponse) -> Self {
        Self::Response(response)
    }
}

/// Client-side control channel for broker authority calls.
pub trait ClientControlChannel {
    /// Channel-specific error type.
    type Error;

    /// Sends one broker request.
    fn send_request(&mut self, request: &BrokerRequest) -> Result<(), Self::Error>;

    /// Receives one broker response.
    ///
    /// Returns `Ok(None)` when the broker closed the channel cleanly before
    /// starting another response frame.
    fn recv_response(&mut self) -> Result<Option<ReceivedBrokerResponse>, Self::Error>;
}

/// Server-side control channel for broker authority calls.
pub trait ServerControlChannel {
    /// Channel-specific error type.
    type Error;

    /// Returns the peer credential authenticated for this channel endpoint.
    fn peer_credential(&self) -> Result<PeerCredential, Self::Error>;

    /// Receives one broker request.
    ///
    /// Returns `Ok(None)` when the peer closed the channel cleanly before
    /// starting another request frame.
    fn recv_request(&mut self) -> Result<Option<ReceivedBrokerRequest>, Self::Error>;

    /// Sends one broker response.
    fn send_response(&mut self, response: &BrokerResponse) -> Result<(), Self::Error>;
}
