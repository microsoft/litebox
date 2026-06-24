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
    BROKER_PROTOCOL_VERSION, BrokerRequest, BrokerResponse, CoreRequest, CoreResponse,
    LocalControlChannel,
};

pub use error::{BrokerLocalError, BrokerLocalNegotiationError, NegotiationResult, Result};

/// Typed broker-local control adapter for broker operations.
pub struct BrokerLocal<T> {
    channel: T,
}

impl<T> BrokerLocal<T> {
    /// Returns the underlying control channel for deployment-specific configuration.
    pub fn control_channel_mut(&mut self) -> &mut T {
        &mut self.channel
    }
}

impl<T: LocalControlChannel> BrokerLocal<T> {
    /// Negotiates the broker protocol over an already-connected control channel.
    pub fn negotiate(mut channel: T) -> NegotiationResult<Self, T::Error> {
        let requested = BROKER_PROTOCOL_VERSION;
        match raw_request(
            &mut channel,
            BrokerRequest::Negotiate {
                protocol_version: requested,
            },
            BrokerLocalNegotiationError::Channel,
            BrokerLocalNegotiationError::ChannelClosed,
        )? {
            BrokerResponse::Negotiated {
                broker_protocol_version,
            } => {
                if requested != broker_protocol_version {
                    return Err(BrokerLocalNegotiationError::IncompatibleNegotiation {
                        requested,
                        broker_protocol_version,
                    });
                }
                Ok(Self { channel })
            }
            BrokerResponse::VersionMismatch {
                broker_protocol_version,
            } => Err(BrokerLocalNegotiationError::UnsupportedVersion {
                requested,
                broker_protocol_version,
            }),
            BrokerResponse::Error(error) => Err(BrokerLocalNegotiationError::Broker(error)),
            response @ BrokerResponse::Core(_) => {
                Err(BrokerLocalNegotiationError::UnexpectedResponse(response))
            }
        }
    }

    /// Sends one active BrokerCore request.
    pub fn request(&mut self, request: CoreRequest) -> Result<CoreResponse, T::Error> {
        match raw_request(
            &mut self.channel,
            BrokerRequest::Core(request),
            BrokerLocalError::Channel,
            BrokerLocalError::ChannelClosed,
        )? {
            BrokerResponse::Core(response) => Ok(response),
            BrokerResponse::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => Err(BrokerLocalError::UnexpectedResponse(response)),
        }
    }
}

fn raw_request<T: LocalControlChannel, E>(
    channel: &mut T,
    request: BrokerRequest,
    channel_error: impl Fn(T::Error) -> E,
    channel_closed: E,
) -> core::result::Result<BrokerResponse, E> {
    channel.send_request(&request).map_err(&channel_error)?;
    channel
        .recv_response()
        .map_err(&channel_error)?
        .ok_or(channel_closed)
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
            Err(BrokerLocalNegotiationError::IncompatibleNegotiation {
                requested,
                broker_protocol_version: broker
            }) if requested == BROKER_PROTOCOL_VERSION && broker == broker_protocol_version
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
            Err(BrokerLocalNegotiationError::UnsupportedVersion {
                requested,
                broker_protocol_version: broker
            }) if requested == BROKER_PROTOCOL_VERSION && broker == broker_protocol_version
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
