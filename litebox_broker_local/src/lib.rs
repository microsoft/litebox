// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed broker-local control adapter for broker requests.
//!
//! The local control adapter owns request/response sequencing but does not own a channel.
//! Userland, kernel, or ring-buffer deployments can provide channels by
//! implementing [`litebox_broker_protocol::LocalControlChannel`].

#![no_std]

#[cfg(test)]
extern crate std;

mod error;
mod event;

use litebox_broker_protocol::{
    BrokerRequest, BrokerResponse, LocalControlChannel, ProtocolVersion, ReceivedBrokerResponse,
};

pub use error::{BrokerLocalError, Result};

/// Protocol version this broker-local implementation requests by default.
pub const LOCAL_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(0, 2);

/// Typed broker-local control adapter for broker operations.
pub struct BrokerLocal<T> {
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

impl<T> BrokerLocal<T> {
    /// Creates a broker-local control adapter over an already-connected control channel.
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

impl<T: LocalControlChannel> BrokerLocal<T> {
    /// Negotiates the default broker-local protocol version.
    ///
    /// Returns the effective protocol version this connection will speak.
    pub fn negotiate(&mut self) -> Result<ProtocolVersion, T::Error> {
        self.negotiate_version(LOCAL_PROTOCOL_VERSION)
    }

    /// Negotiates a caller-selected protocol version.
    ///
    /// Returns the effective protocol version this connection will speak. Feature
    /// gating must use this effective version, not the broker's max-supported
    /// version returned by the wire negotiation response.
    pub fn negotiate_version(
        &mut self,
        protocol_version: ProtocolVersion,
    ) -> Result<ProtocolVersion, T::Error> {
        if self.state != ConnectionState::AwaitingNegotiation {
            return Err(BrokerLocalError::AlreadyNegotiated);
        }
        if !protocol_version.is_supported_by(LOCAL_PROTOCOL_VERSION) {
            return Err(BrokerLocalError::UnsupportedLocalVersion {
                requested: protocol_version,
                local_protocol_version: LOCAL_PROTOCOL_VERSION,
            });
        }

        let response = self.request(BrokerRequest::Negotiate { protocol_version })?;
        match response {
            BrokerResponse::Negotiated {
                broker_protocol_version,
            } => {
                if !protocol_version.is_supported_by(broker_protocol_version) {
                    return Err(BrokerLocalError::IncompatibleNegotiation {
                        requested: protocol_version,
                        broker_protocol_version,
                    });
                }
                self.state = ConnectionState::Active {
                    negotiated_protocol_version: protocol_version,
                };
                Ok(protocol_version)
            }
            BrokerResponse::VersionMismatch {
                broker_protocol_version,
            } => Err(BrokerLocalError::UnsupportedVersion {
                requested: protocol_version,
                broker_protocol_version,
            }),
            response => Err(BrokerLocalError::UnexpectedResponse(response)),
        }
    }

    /// Returns the effective protocol version this connection negotiated.
    ///
    /// Feature gating must use this effective version because the broker may
    /// support a newer minor version than this local adapter requested.
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
        let mut local = BrokerLocal::new(channel);

        assert!(matches!(
            local.create_event(),
            Err(BrokerLocalError::NotNegotiated)
        ));
        assert_eq!(local.channel.sent_request, None);
    }

    #[test]
    fn event_operations_require_event_protocol_version_without_sending() {
        let channel =
            FakeControlChannel::new(Some(BrokerResponse::Error(ErrorCode::UnsupportedOperation)));
        let mut local = BrokerLocal::new(channel);
        local.state = ConnectionState::Active {
            negotiated_protocol_version: ProtocolVersion::new(LOCAL_PROTOCOL_VERSION.major, 1),
        };

        assert!(matches!(
            local.create_event(),
            Err(BrokerLocalError::UnsupportedNegotiatedVersion {
                required,
                negotiated_protocol_version
            }) if required == LOCAL_PROTOCOL_VERSION
                && negotiated_protocol_version == ProtocolVersion::new(LOCAL_PROTOCOL_VERSION.major, 1)
        ));
        assert_eq!(local.channel.sent_request, None);
    }

    #[test]
    fn negotiate_version_sends_requested_version_and_activates_local_connection() {
        let requested = ProtocolVersion::new(
            LOCAL_PROTOCOL_VERSION.major,
            LOCAL_PROTOCOL_VERSION.minor - 1,
        );
        let channel = FakeControlChannel::new(Some(BrokerResponse::Negotiated {
            broker_protocol_version: LOCAL_PROTOCOL_VERSION,
        }));
        let mut local = BrokerLocal::new(channel);

        assert_eq!(local.negotiate_version(requested).unwrap(), requested);
        assert_eq!(
            local.channel.sent_request,
            Some(BrokerRequest::Negotiate {
                protocol_version: requested
            })
        );
        assert_eq!(local.negotiated_protocol_version(), Some(requested));
    }

    #[test]
    fn negotiate_version_rejects_incompatible_broker_response() {
        let requested = LOCAL_PROTOCOL_VERSION;
        let broker_version = ProtocolVersion::new(LOCAL_PROTOCOL_VERSION.major, 1);
        let channel = FakeControlChannel::new(Some(BrokerResponse::Negotiated {
            broker_protocol_version: broker_version,
        }));
        let mut local = BrokerLocal::new(channel);

        assert!(matches!(
            local.negotiate_version(requested),
            Err(BrokerLocalError::IncompatibleNegotiation {
                requested: actual_requested,
                broker_protocol_version
            }) if actual_requested == requested && broker_protocol_version == broker_version
        ));
        assert_eq!(local.negotiated_protocol_version(), None);
    }

    #[test]
    fn negotiate_version_rejects_locally_unsupported_version_without_sending() {
        let too_new = ProtocolVersion::new(
            LOCAL_PROTOCOL_VERSION.major,
            LOCAL_PROTOCOL_VERSION.minor + 1,
        );
        let channel = FakeControlChannel::new(Some(BrokerResponse::VersionMismatch {
            broker_protocol_version: LOCAL_PROTOCOL_VERSION,
        }));
        let mut local = BrokerLocal::new(channel);

        assert!(matches!(
            local.negotiate_version(too_new),
            Err(BrokerLocalError::UnsupportedLocalVersion {
                requested,
                local_protocol_version
            }) if requested == too_new && local_protocol_version == LOCAL_PROTOCOL_VERSION
        ));
        assert_eq!(local.negotiated_protocol_version(), None);
        assert_eq!(local.channel.sent_request, None);
    }

    #[test]
    fn negotiate_version_reports_broker_supported_version_and_allows_retry() {
        let requested = LOCAL_PROTOCOL_VERSION;
        let fallback = ProtocolVersion::new(
            LOCAL_PROTOCOL_VERSION.major,
            LOCAL_PROTOCOL_VERSION.minor - 1,
        );
        let channel = FakeControlChannel::new(Some(BrokerResponse::VersionMismatch {
            broker_protocol_version: fallback,
        }));
        let mut local = BrokerLocal::new(channel);

        assert!(matches!(
            local.negotiate_version(requested),
            Err(BrokerLocalError::UnsupportedVersion {
                requested: actual_requested,
                broker_protocol_version
            }) if actual_requested == requested && broker_protocol_version == fallback
        ));
        assert_eq!(local.negotiated_protocol_version(), None);
        assert_eq!(
            local.channel.sent_request,
            Some(BrokerRequest::Negotiate {
                protocol_version: requested
            })
        );

        local.channel.response = Some(BrokerResponse::Negotiated {
            broker_protocol_version: fallback,
        });

        assert_eq!(local.negotiate_version(fallback).unwrap(), fallback);
        assert_eq!(local.negotiated_protocol_version(), Some(fallback));
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

    impl LocalControlChannel for FakeControlChannel {
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
