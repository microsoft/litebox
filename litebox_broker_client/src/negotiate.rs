// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::{BrokerRequest, BrokerResponse, ProtocolVersion};

use litebox_broker_transport::ClientTransport;

use crate::{BrokerClient, CLIENT_PROTOCOL_VERSION, ClientError, Result};

impl<T: ClientTransport> BrokerClient<T> {
    /// Negotiates the first POC protocol version.
    pub fn negotiate(&mut self) -> Result<ProtocolVersion, T::Error> {
        self.negotiate_version(CLIENT_PROTOCOL_VERSION)
    }

    /// Negotiates a caller-selected protocol version.
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
                self.state = crate::ConnectionState::Active;
                Ok(broker_protocol_version)
            }
            response => Err(ClientError::UnexpectedResponse(response)),
        }
    }
}
