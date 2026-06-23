// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{BrokerRequest, BrokerResponse};

/// Peer identity information supplied by the channel or host layer.
///
/// The first userland proof of concept does not authenticate Unix-socket peers,
/// but channels still return an explicit credential value so the host layer
/// can map authenticated peer identity into BrokerCore caller identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PeerCredential {
    /// Explicit deployment mode for the initial unauthenticated userland POC.
    ///
    /// Channels that are expected to authenticate peers must return an error
    /// from [`HostControlChannel::peer_credential`] when authentication is
    /// unavailable or fails; this variant is only for deployments that
    /// deliberately choose unauthenticated operation.
    Unauthenticated,
}

/// Local-side control channel for broker authority calls.
pub trait LocalControlChannel {
    /// Channel-specific error type.
    type Error;

    /// Sends one broker request.
    fn send_request(&mut self, request: &BrokerRequest) -> Result<(), Self::Error>;

    /// Receives one broker response.
    ///
    /// Returns `Ok(None)` when the broker closed the channel cleanly before
    /// starting another response frame.
    fn recv_response(&mut self) -> Result<Option<BrokerResponse>, Self::Error>;
}

/// Host-side control channel for broker authority calls.
pub trait HostControlChannel {
    /// Channel-specific error type.
    type Error;

    /// Returns the peer credential authenticated for this channel endpoint.
    fn peer_credential(&self) -> Result<PeerCredential, Self::Error>;

    /// Receives one broker request.
    ///
    /// Returns `Ok(None)` when the peer closed the channel cleanly before
    /// starting another request frame.
    fn recv_request(&mut self) -> Result<Option<BrokerRequest>, Self::Error>;

    /// Sends one broker response.
    fn send_response(&mut self, response: &BrokerResponse) -> Result<(), Self::Error>;
}
