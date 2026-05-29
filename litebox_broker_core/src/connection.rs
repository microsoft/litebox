// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::fmt;

use crate::identity::Association;
use crate::{BrokerCore, PolicyEngine, Result, SUPPORTED_PROTOCOL_VERSION};
use litebox_broker_protocol::{BrokerRequest, BrokerResponse, ErrorCode, ProtocolVersion};
use litebox_broker_transport::PeerCredential;

/// Broker-side state for one authenticated request/response connection.
pub struct BrokerConnection {
    association: Association,
    state: ConnectionState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionState {
    AwaitingNegotiation,
    Active,
}

impl BrokerConnection {
    pub(crate) const fn new(association: Association) -> Self {
        Self {
            association,
            state: ConnectionState::AwaitingNegotiation,
        }
    }

    /// Returns the transport-authenticated peer credential for this connection.
    pub const fn peer_credential(&self) -> PeerCredential {
        self.association.peer_credential()
    }
}

/// Result of dispatching one broker request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrokerDispatch {
    response: BrokerResponse,
    outcome: DispatchOutcome,
}

/// Connection outcome after sending a dispatch response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// Continue serving the connection.
    Continue,
    /// Close the connection after sending the response.
    Close(CloseReason),
}

/// Reason BrokerCore asked the server loop to close the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The peer requested an unsupported protocol version.
    UnsupportedVersion,
    /// The peer violated the request sequencing state machine.
    ProtocolViolation,
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => f.write_str("unsupported protocol version"),
            Self::ProtocolViolation => f.write_str("protocol violation"),
        }
    }
}

impl BrokerDispatch {
    const fn continue_after(response: BrokerResponse) -> Self {
        Self {
            response,
            outcome: DispatchOutcome::Continue,
        }
    }

    const fn close_after(response: BrokerResponse, reason: CloseReason) -> Self {
        Self {
            response,
            outcome: DispatchOutcome::Close(reason),
        }
    }

    /// Response to send to the peer.
    pub const fn response(&self) -> BrokerResponse {
        self.response
    }

    /// Connection outcome after sending the response.
    pub const fn outcome(&self) -> DispatchOutcome {
        self.outcome
    }

    /// Reason the deployment should close the connection after sending the response.
    pub const fn close_reason(&self) -> Option<CloseReason> {
        match self.outcome {
            DispatchOutcome::Continue => None,
            DispatchOutcome::Close(reason) => Some(reason),
        }
    }

    /// Whether the deployment should close the connection after sending the response.
    pub const fn close_after_response(&self) -> bool {
        self.close_reason().is_some()
    }
}

impl<P> BrokerCore<P> {
    /// Allocates broker state for one authenticated request/response connection.
    pub fn create_connection(
        &mut self,
        peer_credential: PeerCredential,
    ) -> Result<BrokerConnection> {
        self.create_association(peer_credential)
            .map(BrokerConnection::new)
    }

    /// Closes a broker connection and releases state owned by its association.
    pub fn close_connection(&mut self, connection: BrokerConnection) {
        self.close_association(connection.association);
    }
}

impl<P: PolicyEngine> BrokerCore<P> {
    /// Handles one request for an authenticated broker connection.
    ///
    /// Transport-specific code should receive frames, pass decoded requests here,
    /// send `BrokerDispatch::response`, and honor `BrokerDispatch::outcome`.
    pub fn handle_connection_request(
        &mut self,
        connection: &mut BrokerConnection,
        request: BrokerRequest,
    ) -> BrokerDispatch {
        if connection.state == ConnectionState::AwaitingNegotiation {
            return match request {
                BrokerRequest::Negotiate { protocol_version } => {
                    Self::handle_negotiation(connection, protocol_version)
                }
                _ => BrokerDispatch::close_after(
                    BrokerResponse::Error(ErrorCode::ProtocolState),
                    CloseReason::ProtocolViolation,
                ),
            };
        }

        match request {
            BrokerRequest::Negotiate { .. } => BrokerDispatch::close_after(
                BrokerResponse::Error(ErrorCode::ProtocolState),
                CloseReason::ProtocolViolation,
            ),
            BrokerRequest::CreateEvent => BrokerDispatch::continue_after(Self::handle_result(
                self.create_event(connection.association),
                BrokerResponse::Handle,
            )),
            BrokerRequest::WaitEvent { handle } => {
                BrokerDispatch::continue_after(Self::handle_result(
                    self.wait_event(connection.association, handle),
                    BrokerResponse::Wait,
                ))
            }
            BrokerRequest::SignalEvent { handle } => {
                BrokerDispatch::continue_after(Self::handle_result(
                    self.signal_event(connection.association, handle),
                    BrokerResponse::Readiness,
                ))
            }
            _ => BrokerDispatch::continue_after(BrokerResponse::Error(
                ErrorCode::UnsupportedOperation,
            )),
        }
    }

    /// Handles a well-formed frame with a request tag not known to this broker.
    ///
    /// Unknown future operations are regular feature-probing failures after
    /// negotiation. Before negotiation they are protocol-state violations.
    pub fn handle_unknown_connection_request(
        &mut self,
        connection: &mut BrokerConnection,
        _tag: u8,
    ) -> BrokerDispatch {
        if connection.state == ConnectionState::AwaitingNegotiation {
            BrokerDispatch::close_after(
                BrokerResponse::Error(ErrorCode::ProtocolState),
                CloseReason::ProtocolViolation,
            )
        } else {
            BrokerDispatch::continue_after(BrokerResponse::Error(ErrorCode::UnsupportedOperation))
        }
    }

    fn handle_negotiation(
        connection: &mut BrokerConnection,
        protocol_version: ProtocolVersion,
    ) -> BrokerDispatch {
        if protocol_version.is_supported_by(SUPPORTED_PROTOCOL_VERSION) {
            connection.state = ConnectionState::Active;
            BrokerDispatch::continue_after(BrokerResponse::Negotiated {
                broker_protocol_version: SUPPORTED_PROTOCOL_VERSION,
            })
        } else {
            BrokerDispatch::close_after(
                BrokerResponse::Error(ErrorCode::UnsupportedVersion),
                CloseReason::UnsupportedVersion,
            )
        }
    }

    fn handle_result<T>(
        result: Result<T>,
        into_response: impl FnOnce(T) -> BrokerResponse,
    ) -> BrokerResponse {
        match result {
            Ok(value) => into_response(value),
            Err(error) => BrokerResponse::Error(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BrokerCore, EventOnlyPolicy};
    use litebox_broker_protocol::{ReadinessState, WaitOutcome};

    #[test]
    fn dispatch_requires_negotiation_first() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut connection = core
            .create_connection(PeerCredential::Unauthenticated)
            .unwrap();

        let dispatch = core.handle_connection_request(&mut connection, BrokerRequest::CreateEvent);

        assert_eq!(
            dispatch.response(),
            BrokerResponse::Error(ErrorCode::ProtocolState)
        );
        assert!(dispatch.close_after_response());
        assert_eq!(
            dispatch.close_reason(),
            Some(CloseReason::ProtocolViolation)
        );
        assert_eq!(connection.state, ConnectionState::AwaitingNegotiation);
    }

    #[test]
    fn dispatch_closes_after_post_negotiation_negotiate() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut connection = core
            .create_connection(PeerCredential::Unauthenticated)
            .unwrap();
        negotiate(&mut core, &mut connection);

        let dispatch = core.handle_connection_request(
            &mut connection,
            BrokerRequest::Negotiate {
                protocol_version: SUPPORTED_PROTOCOL_VERSION,
            },
        );

        assert_eq!(
            dispatch.response(),
            BrokerResponse::Error(ErrorCode::ProtocolState)
        );
        assert!(dispatch.close_after_response());
        assert_eq!(
            dispatch.close_reason(),
            Some(CloseReason::ProtocolViolation)
        );
    }

    #[test]
    fn dispatch_closes_after_unsupported_version() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut connection = core
            .create_connection(PeerCredential::Unauthenticated)
            .unwrap();

        let dispatch = core.handle_connection_request(
            &mut connection,
            BrokerRequest::Negotiate {
                protocol_version: ProtocolVersion::new(SUPPORTED_PROTOCOL_VERSION.major + 1, 0),
            },
        );

        assert_eq!(
            dispatch.response(),
            BrokerResponse::Error(ErrorCode::UnsupportedVersion)
        );
        assert!(dispatch.close_after_response());
        assert_eq!(
            dispatch.close_reason(),
            Some(CloseReason::UnsupportedVersion)
        );
        assert_eq!(connection.state, ConnectionState::AwaitingNegotiation);
    }

    #[test]
    fn dispatch_accepts_supported_older_minor_version() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut connection = core
            .create_connection(PeerCredential::Unauthenticated)
            .unwrap();
        let requested = ProtocolVersion::new(
            SUPPORTED_PROTOCOL_VERSION.major,
            SUPPORTED_PROTOCOL_VERSION.minor - 1,
        );

        let dispatch = core.handle_connection_request(
            &mut connection,
            BrokerRequest::Negotiate {
                protocol_version: requested,
            },
        );

        assert_eq!(
            dispatch.response(),
            BrokerResponse::Negotiated {
                broker_protocol_version: SUPPORTED_PROTOCOL_VERSION
            }
        );
        assert!(!dispatch.close_after_response());
        assert_eq!(connection.state, ConnectionState::Active);
    }

    #[test]
    fn dispatch_rejects_newer_minor_version() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut connection = core
            .create_connection(PeerCredential::Unauthenticated)
            .unwrap();

        let dispatch = core.handle_connection_request(
            &mut connection,
            BrokerRequest::Negotiate {
                protocol_version: ProtocolVersion::new(
                    SUPPORTED_PROTOCOL_VERSION.major,
                    SUPPORTED_PROTOCOL_VERSION.minor + 1,
                ),
            },
        );

        assert_eq!(
            dispatch.response(),
            BrokerResponse::Error(ErrorCode::UnsupportedVersion)
        );
        assert!(dispatch.close_after_response());
        assert_eq!(
            dispatch.close_reason(),
            Some(CloseReason::UnsupportedVersion)
        );
        assert_eq!(connection.state, ConnectionState::AwaitingNegotiation);
    }

    #[test]
    fn dispatch_reports_unknown_requests_without_closing() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut connection = core
            .create_connection(PeerCredential::Unauthenticated)
            .unwrap();
        negotiate(&mut core, &mut connection);

        let dispatch = core.handle_unknown_connection_request(&mut connection, 0xff);

        assert_eq!(
            dispatch.response(),
            BrokerResponse::Error(ErrorCode::UnsupportedOperation)
        );
        assert_eq!(dispatch.close_reason(), None);
    }

    #[test]
    fn dispatch_closes_unknown_requests_before_negotiation() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut connection = core
            .create_connection(PeerCredential::Unauthenticated)
            .unwrap();

        let dispatch = core.handle_unknown_connection_request(&mut connection, 0xff);

        assert_eq!(
            dispatch.response(),
            BrokerResponse::Error(ErrorCode::ProtocolState)
        );
        assert_eq!(
            dispatch.close_reason(),
            Some(CloseReason::ProtocolViolation)
        );
    }

    #[test]
    fn dispatch_negotiates_then_routes_event_requests() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut connection = core
            .create_connection(PeerCredential::Unauthenticated)
            .unwrap();

        let dispatch = core.handle_connection_request(
            &mut connection,
            BrokerRequest::Negotiate {
                protocol_version: SUPPORTED_PROTOCOL_VERSION,
            },
        );
        assert_eq!(
            dispatch.response(),
            BrokerResponse::Negotiated {
                broker_protocol_version: SUPPORTED_PROTOCOL_VERSION
            }
        );
        assert!(!dispatch.close_after_response());
        assert_eq!(connection.state, ConnectionState::Active);

        let dispatch = core.handle_connection_request(&mut connection, BrokerRequest::CreateEvent);
        let handle = match dispatch.response() {
            BrokerResponse::Handle(handle) => handle,
            response => panic!("unexpected response: {response:?}"),
        };

        let dispatch =
            core.handle_connection_request(&mut connection, BrokerRequest::WaitEvent { handle });
        assert_eq!(
            dispatch.response(),
            BrokerResponse::Wait(WaitOutcome::WouldBlock(ReadinessState::new(false, 0)))
        );
        assert!(!dispatch.close_after_response());
    }

    #[test]
    fn dispatch_rejects_handle_from_another_connection() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut owner = core
            .create_connection(PeerCredential::Unauthenticated)
            .unwrap();
        let mut other = core
            .create_connection(PeerCredential::Unauthenticated)
            .unwrap();
        negotiate(&mut core, &mut owner);
        negotiate(&mut core, &mut other);

        let dispatch = core.handle_connection_request(&mut owner, BrokerRequest::CreateEvent);
        let handle = match dispatch.response() {
            BrokerResponse::Handle(handle) => handle,
            response => panic!("unexpected response: {response:?}"),
        };

        let dispatch =
            core.handle_connection_request(&mut other, BrokerRequest::WaitEvent { handle });
        assert_eq!(
            dispatch.response(),
            BrokerResponse::Error(ErrorCode::InvalidRights)
        );
        assert!(!dispatch.close_after_response());
    }

    #[test]
    fn close_connection_releases_owned_references_and_orphaned_objects() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut connection = core
            .create_connection(PeerCredential::Unauthenticated)
            .unwrap();
        negotiate(&mut core, &mut connection);

        let dispatch = core.handle_connection_request(&mut connection, BrokerRequest::CreateEvent);
        assert!(matches!(dispatch.response(), BrokerResponse::Handle(_)));
        assert_eq!(core.references.len(), 1);
        assert_eq!(core.objects.len(), 1);

        core.close_connection(connection);

        assert!(core.references.is_empty());
        assert!(core.objects.is_empty());
    }

    fn negotiate<P: PolicyEngine>(core: &mut BrokerCore<P>, connection: &mut BrokerConnection) {
        let dispatch = core.handle_connection_request(
            connection,
            BrokerRequest::Negotiate {
                protocol_version: SUPPORTED_PROTOCOL_VERSION,
            },
        );
        assert_eq!(
            dispatch.response(),
            BrokerResponse::Negotiated {
                broker_protocol_version: SUPPORTED_PROTOCOL_VERSION
            }
        );
        assert_eq!(connection.state, ConnectionState::Active);
    }
}
