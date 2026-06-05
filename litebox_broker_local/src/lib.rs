// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed control-channel client adapter for broker requests.
//!
//! The control client owns request/response sequencing but does not own a channel.
//! Userland, kernel, or ring-buffer deployments can provide channels by
//! implementing [`litebox_broker_protocol::ClientControlChannel`].

#![no_std]

#[cfg(test)]
extern crate std;

mod error;
mod event;
mod negotiate;

use litebox_broker_protocol::{
    BrokerRequest, BrokerResponse, ClientControlChannel, ProtocolVersion, ReceivedBrokerResponse,
};

pub use error::{BrokerLocalError, Result};

/// Protocol version this client implementation requests by default.
pub const CLIENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(0, 2);

/// Typed control-channel client for broker operations.
pub struct ControlClient<T> {
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

impl<T> ControlClient<T> {
    /// Creates a control client over an already-connected control channel.
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

impl<T: ClientControlChannel> ControlClient<T> {
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
            ConnectionState::AwaitingNegotiation => Err(BrokerLocalError::NotNegotiated),
            ConnectionState::Active {
                negotiated_protocol_version,
            } => Ok(negotiated_protocol_version),
        }
    }

    pub(crate) fn request(&mut self, request: BrokerRequest) -> Result<BrokerResponse, T::Error> {
        match self.raw_request(request)? {
            BrokerResponse::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => Ok(response),
        }
    }

    fn raw_request(&mut self, request: BrokerRequest) -> Result<BrokerResponse, T::Error> {
        self.channel
            .send_request(&request)
            .map_err(BrokerLocalError::Channel)?;
        match self
            .channel
            .recv_response()
            .map_err(BrokerLocalError::Channel)?
            .ok_or(BrokerLocalError::ChannelClosed)?
        {
            ReceivedBrokerResponse::Response(response) => Ok(response),
            _ => Err(BrokerLocalError::UnknownResponse),
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
        let mut client = ControlClient::new(channel);

        assert!(matches!(
            client.create_event(),
            Err(BrokerLocalError::NotNegotiated)
        ));
        assert_eq!(client.channel.sent_request, None);
    }

    #[test]
    fn event_operations_require_event_protocol_version_without_sending() {
        let channel =
            FakeControlChannel::new(Some(BrokerResponse::Error(ErrorCode::UnsupportedOperation)));
        let mut client = ControlClient::new(channel);
        client.state = ConnectionState::Active {
            negotiated_protocol_version: ProtocolVersion::new(CLIENT_PROTOCOL_VERSION.major, 1),
        };

        assert!(matches!(
            client.create_event(),
            Err(BrokerLocalError::UnsupportedNegotiatedVersion {
                required,
                negotiated_protocol_version
            }) if required == CLIENT_PROTOCOL_VERSION
                && negotiated_protocol_version == ProtocolVersion::new(CLIENT_PROTOCOL_VERSION.major, 1)
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
        let mut client = ControlClient::new(channel);

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
        let requested = CLIENT_PROTOCOL_VERSION;
        let broker_version = ProtocolVersion::new(CLIENT_PROTOCOL_VERSION.major, 1);
        let channel = FakeControlChannel::new(Some(BrokerResponse::Negotiated {
            broker_protocol_version: broker_version,
        }));
        let mut client = ControlClient::new(channel);

        assert!(matches!(
            client.negotiate_version(requested),
            Err(BrokerLocalError::IncompatibleNegotiation {
                requested: actual_requested,
                broker_protocol_version
            }) if actual_requested == requested && broker_protocol_version == broker_version
        ));
        assert_eq!(client.negotiated_protocol_version(), None);
    }

    #[test]
    fn negotiate_version_rejects_locally_unsupported_version_without_sending() {
        let too_new = ProtocolVersion::new(
            CLIENT_PROTOCOL_VERSION.major,
            CLIENT_PROTOCOL_VERSION.minor + 1,
        );
        let channel = FakeControlChannel::new(Some(BrokerResponse::VersionMismatch {
            broker_protocol_version: CLIENT_PROTOCOL_VERSION,
        }));
        let mut client = ControlClient::new(channel);

        assert!(matches!(
            client.negotiate_version(too_new),
            Err(BrokerLocalError::UnsupportedLocalVersion {
                requested,
                local_protocol_version
            }) if requested == too_new && local_protocol_version == CLIENT_PROTOCOL_VERSION
        ));
        assert_eq!(client.negotiated_protocol_version(), None);
        assert_eq!(client.channel.sent_request, None);
    }

    #[test]
    fn negotiate_version_reports_broker_supported_version_and_allows_retry() {
        let requested = CLIENT_PROTOCOL_VERSION;
        let fallback = ProtocolVersion::new(
            CLIENT_PROTOCOL_VERSION.major,
            CLIENT_PROTOCOL_VERSION.minor - 1,
        );
        let channel = FakeControlChannel::new(Some(BrokerResponse::VersionMismatch {
            broker_protocol_version: fallback,
        }));
        let mut client = ControlClient::new(channel);

        assert!(matches!(
            client.negotiate_version(requested),
            Err(BrokerLocalError::UnsupportedVersion {
                requested: actual_requested,
                broker_protocol_version
            }) if actual_requested == requested && broker_protocol_version == fallback
        ));
        assert_eq!(client.negotiated_protocol_version(), None);
        assert_eq!(
            client.channel.sent_request,
            Some(BrokerRequest::Negotiate {
                protocol_version: requested
            })
        );

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
            self.sent_request = Some(request.clone());
            Ok(())
        }

        fn recv_response(
            &mut self,
        ) -> core::result::Result<Option<ReceivedBrokerResponse>, Self::Error> {
            Ok(self.response.take().map(ReceivedBrokerResponse::Response))
        }
    }
}
