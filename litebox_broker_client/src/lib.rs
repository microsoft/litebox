// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed client adapter for broker requests.
//!
//! The client owns request/response sequencing but does not own a channel.
//! Userland, kernel, or ring-buffer deployments can provide channels by
//! implementing [`litebox_broker_protocol::ClientControlChannel`].

#![no_std]

#[cfg(any(feature = "std", test))]
extern crate std;

mod error;
mod event;
mod negotiate;
#[cfg(feature = "std")]
mod worker;

use litebox_broker_protocol::{
    BrokerRequest, BrokerResponse, ClientControlChannel, ProtocolVersion, ReceivedBrokerResponse,
};

pub use error::{ClientError, Result};
#[cfg(feature = "std")]
pub use worker::{BrokerClientWorker, BrokerClientWorkerError};

/// Protocol version this client implementation requests by default.
pub const CLIENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(0, 2);

/// Typed client for broker operations.
pub struct BrokerClient<T> {
    channel: T,
    state: ConnectionState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionState {
    AwaitingNegotiation,
    Active {
        negotiated_protocol_version: ProtocolVersion,
    },
}

impl<T> BrokerClient<T> {
    /// Creates a broker client over an already-connected control channel.
    pub const fn new(channel: T) -> Self {
        Self {
            channel,
            state: ConnectionState::AwaitingNegotiation,
        }
    }

    /// Returns the underlying control channel for deployment-specific configuration.
    pub fn control_channel_mut(&mut self) -> &mut T {
        &mut self.channel
    }
}

impl<T: ClientControlChannel> BrokerClient<T> {
    /// Returns the effective protocol version this connection negotiated.
    ///
    /// Feature gating must use this effective version because the broker may
    /// support a newer minor version than this client requested.
    pub fn negotiated_protocol_version(&self) -> Option<ProtocolVersion> {
        match self.state {
            ConnectionState::AwaitingNegotiation => None,
            ConnectionState::Active {
                negotiated_protocol_version,
            } => Some(negotiated_protocol_version),
        }
    }

    pub(crate) fn ensure_negotiated(&self) -> Result<ProtocolVersion, T::Error> {
        match self.state {
            ConnectionState::AwaitingNegotiation => Err(ClientError::NotNegotiated),
            ConnectionState::Active {
                negotiated_protocol_version,
            } => Ok(negotiated_protocol_version),
        }
    }

    pub(crate) fn request(&mut self, request: BrokerRequest) -> Result<BrokerResponse, T::Error> {
        match self.raw_request(request)? {
            BrokerResponse::Error(error) => Err(ClientError::Broker(error)),
            response => Ok(response),
        }
    }

    fn raw_request(&mut self, request: BrokerRequest) -> Result<BrokerResponse, T::Error> {
        self.channel
            .send_request(&request)
            .map_err(ClientError::Channel)?;
        match self
            .channel
            .recv_response()
            .map_err(ClientError::Channel)?
            .ok_or(ClientError::ChannelClosed)?
        {
            ReceivedBrokerResponse::Response(response) => Ok(response),
            _ => Err(ClientError::UnknownResponse),
        }
    }

    /// Sends one request on an active connection and returns the raw protocol response.
    pub fn active_raw_request(
        &mut self,
        request: BrokerRequest,
    ) -> Result<BrokerResponse, T::Error> {
        self.ensure_negotiated()?;
        self.raw_request(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use litebox_broker_protocol::{ErrorCode, ProtocolVersion};

    #[test]
    fn event_operations_require_negotiation_without_sending() {
        let channel =
            FakeControlChannel::new(Some(BrokerResponse::Error(ErrorCode::ProtocolState)));
        let mut client = BrokerClient::new(channel);

        assert!(matches!(
            client.create_event(),
            Err(ClientError::NotNegotiated)
        ));
        assert_eq!(client.channel.sent_request, None);
    }

    #[test]
    fn negotiate_version_sends_requested_version_and_activates_client() {
        let requested = ProtocolVersion::new(
            CLIENT_PROTOCOL_VERSION.major,
            CLIENT_PROTOCOL_VERSION.minor - 1,
        );
        let channel = FakeControlChannel::new(Some(BrokerResponse::Negotiated {
            broker_protocol_version: CLIENT_PROTOCOL_VERSION,
        }));
        let mut client = BrokerClient::new(channel);

        assert_eq!(client.negotiate_version(requested).unwrap(), requested);
        assert_eq!(
            client.channel.sent_request,
            Some(BrokerRequest::Negotiate {
                protocol_version: requested
            })
        );
        assert_eq!(client.negotiated_protocol_version(), Some(requested));
    }

    #[test]
    fn negotiate_version_rejects_incompatible_broker_response() {
        let requested = ProtocolVersion::new(1, 1);
        let channel = FakeControlChannel::new(Some(BrokerResponse::Negotiated {
            broker_protocol_version: ProtocolVersion::new(1, 0),
        }));
        let mut client = BrokerClient::new(channel);

        assert!(matches!(
            client.negotiate_version(requested),
            Err(ClientError::IncompatibleNegotiation {
                requested: actual_requested,
                broker_protocol_version
            }) if actual_requested == requested
                && broker_protocol_version == ProtocolVersion::new(1, 0)
        ));
        assert_eq!(client.negotiated_protocol_version(), None);
    }

    #[test]
    fn negotiate_version_reports_supported_version_and_allows_retry() {
        let too_new = ProtocolVersion::new(
            CLIENT_PROTOCOL_VERSION.major,
            CLIENT_PROTOCOL_VERSION.minor + 1,
        );
        let fallback = CLIENT_PROTOCOL_VERSION;
        let channel = FakeControlChannel::new(Some(BrokerResponse::VersionMismatch {
            broker_protocol_version: fallback,
        }));
        let mut client = BrokerClient::new(channel);

        assert!(matches!(
            client.negotiate_version(too_new),
            Err(ClientError::UnsupportedVersion {
                requested,
                broker_protocol_version
            }) if requested == too_new && broker_protocol_version == fallback
        ));
        assert_eq!(client.negotiated_protocol_version(), None);

        client.channel.response = Some(BrokerResponse::Negotiated {
            broker_protocol_version: fallback,
        });

        assert_eq!(client.negotiate_version(fallback).unwrap(), fallback);
        assert_eq!(client.negotiated_protocol_version(), Some(fallback));
    }

    struct FakeControlChannel {
        sent_request: Option<BrokerRequest>,
        response: Option<BrokerResponse>,
    }

    impl FakeControlChannel {
        const fn new(response: Option<BrokerResponse>) -> Self {
            Self {
                sent_request: None,
                response,
            }
        }
    }

    impl ClientControlChannel for FakeControlChannel {
        type Error = Infallible;

        fn send_request(
            &mut self,
            request: &BrokerRequest,
        ) -> core::result::Result<(), Self::Error> {
            self.sent_request = Some(*request);
            Ok(())
        }

        fn recv_response(
            &mut self,
        ) -> core::result::Result<Option<ReceivedBrokerResponse>, Self::Error> {
            Ok(self.response.take().map(ReceivedBrokerResponse::Response))
        }
    }
}
