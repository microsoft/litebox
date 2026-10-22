// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runtime control-channel contracts for broker associations.
//!
//! These traits describe how an association moves protocol messages between the
//! local endpoint and the broker host. They are transport-neutral: an
//! implementation may use Unix sockets, shared rings, kernel traps, or another
//! IPC mechanism.

use litebox_broker_protocol::message::{
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

/// Local-side channel for broker association setup.
///
/// Setup ends when the deployment consumes this channel into an active
/// [`LocalCallChannel`], so handshake and active call state cannot overlap.
pub trait LocalSetupChannel {
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
}

/// Local-side channel for active broker calls.
pub trait LocalCallChannel {
    /// Channel-specific error type.
    type Error;

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
/// The notification path is logically separate from request and response
/// traffic so active broker requests remain strictly paired with their
/// responses. A deployment may carry notifications in the same authenticated
/// association as its control path.
pub trait LocalNotificationChannel {
    /// Channel-specific error type.
    type Error;

    /// Receives one broker notification.
    ///
    /// Returns `Ok(None)` when the channel closed cleanly: the broker closed it
    /// before starting another notification frame, or the local side closed
    /// the association.
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
    ///
    /// An error is terminal when this channel is part of an active
    /// association. Before returning it, the transport must terminate that
    /// association and unblock its call-lane, notification, and shutdown
    /// endpoints. This lets the association runtime preserve a clean peer
    /// close while relying on the call lanes to report transport failures.
    fn send_notification(&mut self, notification: &BrokerNotification) -> Result<(), Self::Error>;
}

/// Host-side serving end of one call lane of an active association.
///
/// A lane carries one call at a time: the broker reads a request from it and
/// answers that request on the same lane before reading the next. Calls on
/// different lanes are independent, so a broker can serve each lane on its
/// own thread. The trait is transport-neutral so a generic association
/// runtime, such as the one in `litebox_broker_userland`, can serve calls
/// without depending on a concrete transport crate.
pub trait HostCallLane {
    /// Channel-specific error type.
    type Error;

    /// Receives this lane's next broker request.
    fn recv_request(&mut self) -> Result<HostReceive<BrokerRequest>, Self::Error>;

    /// Serializes and sends the response to this lane's last request.
    fn send_response(&mut self, response: &BrokerResponse) -> Result<(), Self::Error>;
}

/// Host-side source of the call lanes of an active association.
///
/// The local peer starts using lanes as its concurrent calls grow, and this
/// source hands out each lane once the local peer starts using it, so a broker
/// serves only lanes in use. The local peer always uses the first lane, so the
/// first [`next_lane`](Self::next_lane) returns it without blocking unless the
/// association has already ended.
pub trait HostCallLaneSource {
    /// Channel-specific error type.
    type Error;

    /// Lane type handed out by this source.
    type Lane: HostCallLane<Error = Self::Error>;

    /// Blocks until the local peer starts using another lane and returns it.
    ///
    /// Once every lane is handed out, this blocks until the association ends.
    /// Returns `Ok(None)` when the local peer closed the association cleanly.
    /// An error is terminal: before returning it, the transport must terminate
    /// the association and unblock every endpoint.
    fn next_lane(&mut self) -> Result<Option<Self::Lane>, Self::Error>;
}

/// RAII-independent shutdown handle for an active broker association.
///
/// Calling [`shutdown`](Self::shutdown) ends the association's transport so
/// every endpoint blocked on it, such as a parked request read or a
/// capacity-blocked notification send, observes termination instead of
/// hanging.
pub trait HostAssociationShutdown {
    /// Channel-specific error type.
    type Error;

    /// Ends the active association transport without waiting for it to drain.
    fn shutdown(&self) -> Result<(), Self::Error>;
}
