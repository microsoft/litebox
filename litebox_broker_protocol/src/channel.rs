// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
    BrokerResponse,
};

/// Peer identity information supplied by the channel or host layer.
///
/// The first userland proof of concept does not authenticate Unix-socket peers,
/// but channels still return an explicit credential value so the host layer
/// can map authenticated peer identity into BrokerCore caller identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PeerCredential {
    /// The trusted host or deployment authenticated and bound the peer before
    /// constructing the channel.
    HostGuaranteed,
    /// Explicit deployment mode for the initial unauthenticated userland POC.
    ///
    /// Channels that are expected to authenticate peers must return an error
    /// from [`HostSetupChannel::peer_credential`] when authentication is
    /// unavailable or fails; this variant is only for deployments that
    /// deliberately choose unauthenticated operation.
    Unauthenticated,
}

/// Host-side receive outcome for peer-to-broker control messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostReceive<T> {
    /// The peer sent a well-formed message for the current protocol phase.
    Message(T),
    /// The peer sent a well-formed message for a different protocol phase.
    ProtocolViolation,
    /// The peer closed the channel cleanly before starting another frame.
    PeerClosed,
}

/// Local-side control channel for broker association setup and active calls.
pub trait LocalControlChannel {
    /// Channel-specific error type.
    type Error;

    /// Sends one broker handshake request.
    fn send_handshake_request(
        &mut self,
        request: &BrokerHandshakeRequest,
    ) -> Result<(), Self::Error>;

    /// Receives one broker handshake response.
    ///
    /// Returns `Ok(None)` when the broker closed the channel cleanly before
    /// starting another response frame.
    fn recv_handshake_response(&mut self) -> Result<Option<BrokerHandshakeResponse>, Self::Error>;

    /// Publishes one request and waits for its correlated response.
    ///
    /// Calls may execute concurrently, and each pending request must have a
    /// distinct identifier. If a valid active call returns a channel error, the
    /// association is considered failed: every concurrent or future call must
    /// return an error rather than remain blocked.
    fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Self::Error>;
}

/// Host-side channel for broker association setup.
pub trait HostSetupChannel {
    /// Channel-specific error type.
    type Error;

    /// Returns the peer credential authenticated for this channel endpoint.
    fn peer_credential(&self) -> Result<PeerCredential, Self::Error>;

    /// Receives one broker handshake request.
    fn recv_handshake_request(
        &mut self,
    ) -> Result<HostReceive<BrokerHandshakeRequest>, Self::Error>;

    /// Sends one broker handshake response.
    fn send_handshake_response(
        &mut self,
        response: &BrokerHandshakeResponse,
    ) -> Result<(), Self::Error>;
}

/// Local-side receive channel for broker-initiated asynchronous notifications.
///
/// A notification channel is separate from the control channel so active broker
/// requests remain strictly paired with their responses. The deployment is
/// responsible for binding this channel to the same authenticated broker
/// association as the matching control channel.
pub trait LocalNotificationChannel {
    /// Channel-specific error type.
    type Error;

    /// Receives one broker notification.
    ///
    /// Returns `Ok(None)` when the broker closed the channel cleanly before
    /// starting another notification frame.
    fn recv_notification(&mut self) -> Result<Option<BrokerNotification>, Self::Error>;
}

/// Host-side send channel for broker-initiated asynchronous notifications.
///
/// Implementations carry notification frames only; object operation responses
/// remain on the active control transport.
pub trait HostNotificationChannel {
    /// Channel-specific error type.
    type Error;

    /// Sends one broker notification.
    fn send_notification(&mut self, notification: &BrokerNotification) -> Result<(), Self::Error>;
}
