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
    BROKER_PROTOCOL_VERSION, BrokerRequest, BrokerResponse, CoreRequest, CoreResponse, ErrorCode,
    LocalControlChannel,
};

pub use error::{BrokerLocalError, Result};

/// Typed broker-local control adapter for broker operations.
pub struct BrokerLocal<Channel: LocalControlChannel> {
    channel: Channel,
}

impl<Channel: LocalControlChannel> BrokerLocal<Channel> {
    /// Returns the underlying control channel for deployment-specific configuration.
    pub fn control_channel_mut(&mut self) -> &mut Channel {
        &mut self.channel
    }

    /// Negotiates the broker protocol over an already-connected control channel.
    pub fn negotiate(mut channel: Channel) -> Result<Self, Channel::Error> {
        let requested = BROKER_PROTOCOL_VERSION;
        match raw_request(
            &mut channel,
            BrokerRequest::Negotiate {
                protocol_version: requested,
            },
        )? {
            response @ BrokerResponse::Negotiated {
                broker_protocol_version,
            } => {
                if requested != broker_protocol_version {
                    return Err(BrokerLocalError::UnexpectedResponse(response));
                }
                Ok(Self { channel })
            }
            BrokerResponse::VersionMismatch { .. } => {
                Err(BrokerLocalError::Broker(ErrorCode::UnsupportedVersion))
            }
            BrokerResponse::Error(error) => Err(BrokerLocalError::Broker(error)),
            response @ BrokerResponse::Core(_) => {
                Err(BrokerLocalError::UnexpectedResponse(response))
            }
        }
    }

    /// Sends one active BrokerCore request.
    pub fn request(&mut self, request: CoreRequest) -> Result<CoreResponse, Channel::Error> {
        match raw_request(&mut self.channel, BrokerRequest::Core(request))? {
            BrokerResponse::Core(response) => Ok(response),
            BrokerResponse::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => Err(BrokerLocalError::UnexpectedResponse(response)),
        }
    }
}

fn raw_request<Channel: LocalControlChannel>(
    channel: &mut Channel,
    request: BrokerRequest,
) -> Result<BrokerResponse, Channel::Error> {
    channel
        .send_request(&request)
        .map_err(BrokerLocalError::Channel)?;
    channel
        .recv_response()
        .map_err(BrokerLocalError::Channel)?
        .ok_or(BrokerLocalError::ChannelClosed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use litebox_broker_protocol::{
        CreateEventRequest, CreateEventResponse, EventRequest, EventResponse, ObjectHandle,
        ProtocolVersion,
    };

    #[test]
    fn negotiate_returns_active_local_connection() {
        let channel = FakeControlChannel::new(Some(BrokerResponse::Negotiated {
            broker_protocol_version: BROKER_PROTOCOL_VERSION,
        }));
        let local = BrokerLocal::negotiate(channel).unwrap();

        assert_eq!(
            local.channel.sent_request,
            Some(BrokerRequest::Negotiate {
                protocol_version: BROKER_PROTOCOL_VERSION
            })
        );
    }

    #[test]
    fn active_request_sends_core_request() {
        let handle = ObjectHandle(7);
        let request = CoreRequest::Event(EventRequest::Create(CreateEventRequest {
            initial_count: 0,
        }));
        let response = CoreResponse::Event(EventResponse::Create(CreateEventResponse { handle }));
        let channel = FakeControlChannel::new(Some(BrokerResponse::Core(response.clone())));
        let mut local = BrokerLocal { channel };

        assert_eq!(local.request(request.clone()).unwrap(), response);
        assert_eq!(
            local.channel.sent_request,
            Some(BrokerRequest::Core(request))
        );
    }

    #[test]
    fn negotiate_rejects_broker_different_version_response() {
        let broker_protocol_version = ProtocolVersion(BROKER_PROTOCOL_VERSION.0 + 1);
        let channel = FakeControlChannel::new(Some(BrokerResponse::Negotiated {
            broker_protocol_version,
        }));

        assert!(matches!(
            BrokerLocal::negotiate(channel),
            Err(BrokerLocalError::UnexpectedResponse(BrokerResponse::Negotiated {
                broker_protocol_version: broker
            })) if broker == broker_protocol_version
        ));
    }

    #[test]
    fn negotiate_rejects_broker_unsupported_version_response() {
        let broker_protocol_version = ProtocolVersion(BROKER_PROTOCOL_VERSION.0 + 1);
        let channel = FakeControlChannel::new(Some(BrokerResponse::VersionMismatch {
            broker_protocol_version,
        }));

        assert!(matches!(
            BrokerLocal::negotiate(channel),
            Err(BrokerLocalError::Broker(ErrorCode::UnsupportedVersion))
        ));
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

        fn recv_response(&mut self) -> core::result::Result<Option<BrokerResponse>, Self::Error> {
            Ok(self.response.take())
        }
    }
}
