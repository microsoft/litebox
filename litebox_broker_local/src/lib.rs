// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed broker-local control adapter for broker requests.
//!
//! The local control adapter owns request/response sequencing but does not own a channel.
//! Userland, kernel, or ring-buffer deployments can provide channels by
//! implementing [`litebox_broker_protocol::channel::LocalControlChannel`].

#![no_std]

#[cfg(test)]
extern crate std;

mod error;
mod event;

use litebox_broker_protocol::BROKER_PROTOCOL_VERSION;
use litebox_broker_protocol::channel::LocalControlChannel;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerRequest, BrokerResponse,
};

pub use error::{BrokerLocalError, Result};

/// Typed broker-local control adapter for broker operations.
pub struct BrokerLocal<Channel: LocalControlChannel> {
    channel: Channel,
}

impl<Channel: LocalControlChannel> BrokerLocal<Channel> {
    /// Negotiates the broker protocol over an already-connected control channel.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the negotiation request.
    pub fn negotiate(mut channel: Channel) -> Result<Self, Channel::Error> {
        let requested = BROKER_PROTOCOL_VERSION;
        let request = BrokerHandshakeRequest {
            protocol_version: requested,
        };
        channel
            .send_handshake_request(&request)
            .map_err(BrokerLocalError::Channel)?;
        match channel
            .recv_handshake_response()
            .map_err(BrokerLocalError::Channel)?
            .ok_or(BrokerLocalError::ChannelClosed)?
        {
            response @ BrokerHandshakeResponse::Negotiated {
                broker_protocol_version,
            } => {
                assert_eq!(
                    requested, broker_protocol_version,
                    "broker returned unexpected negotiation response: {response:?}"
                );
                Ok(Self { channel })
            }
            BrokerHandshakeResponse::VersionMismatch { .. } => {
                Err(BrokerLocalError::Broker(ErrorCode::UnsupportedVersion))
            }
            BrokerHandshakeResponse::Error(error) => match error {
                ErrorCode::UnsupportedVersion | ErrorCode::PolicyDenied => {
                    Err(BrokerLocalError::Broker(error))
                }
                ErrorCode::MalformedRequest
                | ErrorCode::ProtocolState
                | ErrorCode::UnsupportedOperation
                | ErrorCode::Internal => panic!("broker returned unrecoverable error: {error}"),
                _ => panic!("broker returned unexpected negotiation error: {error}"),
            },
        }
    }

    /// Sends one active broker request.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match an active request.
    pub fn request(&mut self, request: BrokerRequest) -> Result<BrokerResponse, Channel::Error> {
        self.channel
            .send_request(&request)
            .map_err(BrokerLocalError::Channel)?;
        match self
            .channel
            .recv_response()
            .map_err(BrokerLocalError::Channel)?
            .ok_or(BrokerLocalError::ChannelClosed)?
        {
            BrokerResponse::Error(error) => match error {
                ErrorCode::PolicyDenied
                | ErrorCode::UnknownObject
                | ErrorCode::InvalidRights
                | ErrorCode::ResourceExhausted
                | ErrorCode::WouldBlock => Err(BrokerLocalError::Broker(error)),
                ErrorCode::UnsupportedVersion
                | ErrorCode::MalformedRequest
                | ErrorCode::ProtocolState
                | ErrorCode::UnsupportedOperation
                | ErrorCode::Internal => panic!("broker returned unrecoverable error: {error}"),
                _ => panic!("broker returned unsupported error: {error}"),
            },
            response @ BrokerResponse::Event(_) => Ok(response),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::ProtocolVersion;
    use litebox_broker_protocol::event::{CreateEventRequest, CreateEventResponse};
    use litebox_broker_protocol::message::{EventRequest, EventResponse};

    #[test]
    fn negotiate_returns_active_local_connection() {
        let channel = FakeControlChannel::new(
            Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }),
            None,
        );
        let local = BrokerLocal::negotiate(channel).unwrap();

        assert_eq!(
            local.channel.sent_handshake_request,
            Some(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION
            })
        );
    }

    #[test]
    fn active_request_sends_event_request() {
        let handle = ObjectHandle(7);
        let request = BrokerRequest::Event(EventRequest::Create(CreateEventRequest {
            initial_count: 0,
        }));
        let response = BrokerResponse::Event(EventResponse::Create(CreateEventResponse { handle }));
        let channel = FakeControlChannel::new(None, Some(response.clone()));
        let mut local = BrokerLocal { channel };

        assert_eq!(local.request(request.clone()).unwrap(), response);
        assert_eq!(local.channel.sent_request, Some(request));
    }

    #[test]
    fn active_request_returns_recoverable_broker_error() {
        let request = BrokerRequest::Event(EventRequest::Create(CreateEventRequest {
            initial_count: 0,
        }));
        let channel =
            FakeControlChannel::new(None, Some(BrokerResponse::Error(ErrorCode::WouldBlock)));
        let mut local = BrokerLocal { channel };

        assert!(matches!(
            local.request(request),
            Err(BrokerLocalError::Broker(ErrorCode::WouldBlock))
        ));
    }

    #[test]
    #[should_panic(expected = "broker returned unrecoverable error")]
    fn active_request_panics_on_unrecoverable_broker_error() {
        let request = BrokerRequest::Event(EventRequest::Create(CreateEventRequest {
            initial_count: 0,
        }));
        let channel =
            FakeControlChannel::new(None, Some(BrokerResponse::Error(ErrorCode::Internal)));
        let mut local = BrokerLocal { channel };

        let _ = local.request(request);
    }

    #[test]
    #[should_panic(expected = "broker returned unexpected negotiation response")]
    fn negotiate_rejects_broker_different_version_response() {
        let broker_protocol_version = ProtocolVersion(BROKER_PROTOCOL_VERSION.0 + 1);
        let channel = FakeControlChannel::new(
            Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version,
            }),
            None,
        );

        let _ = BrokerLocal::negotiate(channel);
    }

    #[test]
    fn negotiate_rejects_broker_unsupported_version_response() {
        let broker_protocol_version = ProtocolVersion(BROKER_PROTOCOL_VERSION.0 + 1);
        let channel = FakeControlChannel::new(
            Some(BrokerHandshakeResponse::VersionMismatch {
                broker_protocol_version,
            }),
            None,
        );

        assert!(matches!(
            BrokerLocal::negotiate(channel),
            Err(BrokerLocalError::Broker(ErrorCode::UnsupportedVersion))
        ));
    }

    #[test]
    #[should_panic(expected = "broker returned unrecoverable error")]
    fn negotiate_panics_on_unrecoverable_broker_error() {
        let channel = FakeControlChannel::new(
            Some(BrokerHandshakeResponse::Error(ErrorCode::Internal)),
            None,
        );

        let _ = BrokerLocal::negotiate(channel);
    }

    struct FakeControlChannel {
        sent_handshake_request: Option<BrokerHandshakeRequest>,
        sent_request: Option<BrokerRequest>,
        handshake_response: Option<BrokerHandshakeResponse>,
        response: Option<BrokerResponse>,
    }

    impl FakeControlChannel {
        const fn new(
            handshake_response: Option<BrokerHandshakeResponse>,
            response: Option<BrokerResponse>,
        ) -> Self {
            Self {
                sent_handshake_request: None,
                sent_request: None,
                handshake_response,
                response,
            }
        }
    }

    impl LocalControlChannel for FakeControlChannel {
        type Error = Infallible;

        fn send_handshake_request(
            &mut self,
            request: &BrokerHandshakeRequest,
        ) -> core::result::Result<(), Self::Error> {
            self.sent_handshake_request = Some(request.clone());
            Ok(())
        }

        fn recv_handshake_response(
            &mut self,
        ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
            Ok(self.handshake_response.take())
        }

        fn send_request(
            &mut self,
            request: &BrokerRequest,
        ) -> core::result::Result<(), Self::Error> {
            self.sent_request = Some(request.clone());
            Ok(())
        }

        fn recv_response(&mut self) -> core::result::Result<Option<BrokerResponse>, Self::Error> {
            Ok(self.response.take())
        }
    }
}
