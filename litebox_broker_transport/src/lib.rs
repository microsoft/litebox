// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared broker transport traits.
//!
//! This crate defines blocking request/response direction traits only. Concrete
//! transports own framing, buffering, and the IPC mechanism; non-blocking IPCs
//! can provide a blocking adapter at this boundary.

#![no_std]

use litebox_broker_protocol::{BrokerRequest, BrokerResponse};

/// Peer identity information supplied by the transport or host layer.
///
/// The first userland proof of concept does not authenticate Unix-socket peers,
/// but BrokerCore still accepts an explicit credential value so authenticated
/// transports can plumb identity through the same connection-creation seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PeerCredential {
    /// Explicit deployment mode for the initial unauthenticated userland POC.
    ///
    /// Transports that are expected to authenticate peers must return an error
    /// from [`ServerTransport::peer_credential`] when authentication is
    /// unavailable or fails; this variant is only for deployments that
    /// deliberately choose unauthenticated operation.
    Unauthenticated,
}

/// Request received from a transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceivedRequest {
    /// A request understood by the current protocol crate.
    Request(BrokerRequest),
    /// A request tag emitted by a newer peer and not understood by this process.
    Unknown { tag: u8 },
}

impl From<BrokerRequest> for ReceivedRequest {
    fn from(request: BrokerRequest) -> Self {
        Self::Request(request)
    }
}

/// Response received from a transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceivedResponse {
    /// A response understood by the current protocol crate.
    Response(BrokerResponse),
    /// A response tag emitted by a newer broker and not understood by this process.
    Unknown { tag: u8 },
}

impl From<BrokerResponse> for ReceivedResponse {
    fn from(response: BrokerResponse) -> Self {
        Self::Response(response)
    }
}

/// Client-side request/response transport for broker calls.
pub trait ClientTransport {
    /// Transport-specific error type.
    type Error;

    /// Sends one broker request.
    fn send_request(&mut self, request: &BrokerRequest) -> Result<(), Self::Error>;

    /// Receives one broker response.
    ///
    /// Returns `Ok(None)` when the broker closed the transport cleanly before
    /// starting another response frame.
    fn recv_response(&mut self) -> Result<Option<ReceivedResponse>, Self::Error>;
}

/// Server-side request/response transport for broker calls.
pub trait ServerTransport {
    /// Transport-specific error type.
    type Error;

    /// Returns the peer credential authenticated for this transport endpoint.
    fn peer_credential(&self) -> Result<PeerCredential, Self::Error>;

    /// Receives one broker request.
    ///
    /// Returns `Ok(None)` when the peer closed the transport cleanly before
    /// starting another request frame.
    fn recv_request(&mut self) -> Result<Option<ReceivedRequest>, Self::Error>;

    /// Sends one broker response.
    fn send_response(&mut self, response: &BrokerResponse) -> Result<(), Self::Error>;
}
