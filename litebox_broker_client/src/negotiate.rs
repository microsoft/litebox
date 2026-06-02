// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::{
    BrokerRequest, BrokerResponse, ClientControlChannel, ProtocolVersion,
};

use crate::{BrokerClient, CLIENT_PROTOCOL_VERSION, ClientError, Result};

impl<T: ClientControlChannel> BrokerClient<T> {
    /// Negotiates the default client protocol version.
    ///
    /// Returns the effective protocol version this connection will speak.
    pub fn negotiate(&mut self) -> Result<ProtocolVersion, T::Error> {
        self.negotiate_version(CLIENT_PROTOCOL_VERSION)
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
        if self.state != crate::ConnectionState::AwaitingNegotiation {
            return Err(ClientError::AlreadyNegotiated);
        }

        let response = self.request(BrokerRequest::Negotiate { protocol_version })?;
        match response {
            BrokerResponse::Negotiated {
                broker_protocol_version,
            } => {
                if !protocol_version.is_supported_by(broker_protocol_version) {
                    return Err(ClientError::IncompatibleNegotiation {
                        requested: protocol_version,
                        broker_protocol_version,
                    });
                }
                self.state = crate::ConnectionState::Active {
                    negotiated_protocol_version: protocol_version,
                };
                Ok(protocol_version)
            }
            BrokerResponse::VersionMismatch {
                broker_protocol_version,
            } => Err(ClientError::UnsupportedVersion {
                requested: protocol_version,
                broker_protocol_version,
            }),
            response => Err(ClientError::UnexpectedResponse(response)),
        }
    }
}
