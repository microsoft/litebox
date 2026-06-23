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
    BROKER_PROTOCOL_VERSION, BrokerRequest, BrokerResponse, LocalControlChannel,
};

pub use error::{BrokerLocalError, Result};

/// Typed broker-local control adapter for broker operations.
pub struct BrokerLocal<T> {
    channel: T,
    state: ConnectionState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionState {
    AwaitingNegotiation,
    Active,
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
    /// Sends one broker request.
    ///
    /// Negotiation is the only request allowed before the connection is active.
    pub fn request(&mut self, request: BrokerRequest) -> Result<BrokerResponse, T::Error> {
        match self.state {
            ConnectionState::AwaitingNegotiation => match request {
                BrokerRequest::Negotiate { protocol_version } => {
                    if protocol_version != BROKER_PROTOCOL_VERSION {
                        return Err(BrokerLocalError::UnsupportedLocalVersion {
                            requested: protocol_version,
                            local_protocol_version: BROKER_PROTOCOL_VERSION,
                        });
                    }

                    match self.raw_request(BrokerRequest::Negotiate { protocol_version })? {
                        BrokerResponse::Negotiated {
                            broker_protocol_version,
                        } => {
                            if protocol_version != broker_protocol_version {
                                return Err(BrokerLocalError::IncompatibleNegotiation {
                                    requested: protocol_version,
                                    broker_protocol_version,
                                });
                            }
                            self.state = ConnectionState::Active;
                            Ok(BrokerResponse::Negotiated {
                                broker_protocol_version,
                            })
                        }
                        BrokerResponse::VersionMismatch {
                            broker_protocol_version,
                        } => Err(BrokerLocalError::UnsupportedVersion {
                            requested: protocol_version,
                            broker_protocol_version,
                        }),
                        BrokerResponse::Error(error) => Err(BrokerLocalError::Broker(error)),
                        response => Err(BrokerLocalError::UnexpectedResponse(response)),
                    }
                }
                _ => Err(BrokerLocalError::NotNegotiated),
            },
            ConnectionState::Active => match request {
                BrokerRequest::Negotiate { .. } => Err(BrokerLocalError::AlreadyNegotiated),
                request => match self.raw_request(request)? {
                    BrokerResponse::Error(error) => Err(BrokerLocalError::Broker(error)),
                    response => Ok(response),
                },
            },
        }
    }

    fn raw_request(&mut self, request: BrokerRequest) -> Result<BrokerResponse, T::Error> {
        self.channel
            .send_request(&request)
            .map_err(BrokerLocalError::Channel)?;
        self.channel
            .recv_response()
            .map_err(BrokerLocalError::Channel)?
            .ok_or(BrokerLocalError::ChannelClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use litebox_broker_protocol::ProtocolVersion;

    #[test]
    fn event_operations_require_negotiation_without_sending() {
        let channel = FakeControlChannel::new(None);
        let mut local = BrokerLocal::new(channel);

        assert!(matches!(
            local.create_event(),
            Err(BrokerLocalError::NotNegotiated)
        ));
        assert_eq!(local.channel.sent_request, None);
    }

    #[test]
    fn negotiation_request_activates_local_connection() {
        let requested = BROKER_PROTOCOL_VERSION;
        let channel = FakeControlChannel::new(Some(BrokerResponse::Negotiated {
            broker_protocol_version: BROKER_PROTOCOL_VERSION,
        }));
        let mut local = BrokerLocal::new(channel);

        assert_eq!(
            local
                .request(BrokerRequest::Negotiate {
                    protocol_version: requested
                })
                .unwrap(),
            BrokerResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION
            }
        );
        assert_eq!(
            local.channel.sent_request,
            Some(BrokerRequest::Negotiate {
                protocol_version: requested
            })
        );
        assert_eq!(local.state, ConnectionState::Active);
    }

    #[test]
    fn negotiation_request_rejects_locally_unsupported_version_without_sending() {
        let too_new = ProtocolVersion(BROKER_PROTOCOL_VERSION.0 + 1);
        let channel = FakeControlChannel::new(None);
        let mut local = BrokerLocal::new(channel);

        assert!(matches!(
            local.request(BrokerRequest::Negotiate {
                protocol_version: too_new
            }),
            Err(BrokerLocalError::UnsupportedLocalVersion {
                requested,
                local_protocol_version
            }) if requested == too_new && local_protocol_version == BROKER_PROTOCOL_VERSION
        ));
        assert_eq!(local.state, ConnectionState::AwaitingNegotiation);
        assert_eq!(local.channel.sent_request, None);
    }

    #[test]
    fn negotiation_request_rejects_broker_different_version_response() {
        let broker_protocol_version = ProtocolVersion(BROKER_PROTOCOL_VERSION.0 + 1);
        let channel = FakeControlChannel::new(Some(BrokerResponse::Negotiated {
            broker_protocol_version,
        }));
        let mut local = BrokerLocal::new(channel);

        assert!(matches!(
            local.request(BrokerRequest::Negotiate {
                protocol_version: BROKER_PROTOCOL_VERSION
            }),
            Err(BrokerLocalError::IncompatibleNegotiation {
                requested,
                broker_protocol_version: broker
            }) if requested == BROKER_PROTOCOL_VERSION && broker == broker_protocol_version
        ));
        assert_eq!(local.state, ConnectionState::AwaitingNegotiation);
        assert_eq!(
            local.channel.sent_request,
            Some(BrokerRequest::Negotiate {
                protocol_version: BROKER_PROTOCOL_VERSION
            })
        );
    }

    #[test]
    fn active_connection_rejects_negotiation_without_sending() {
        let channel = FakeControlChannel::new(None);
        let mut local = BrokerLocal::new(channel);
        local.state = ConnectionState::Active;

        assert!(matches!(
            local.request(BrokerRequest::Negotiate {
                protocol_version: BROKER_PROTOCOL_VERSION
            }),
            Err(BrokerLocalError::AlreadyNegotiated)
        ));
        assert_eq!(local.channel.sent_request, None);
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
