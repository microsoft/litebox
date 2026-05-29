// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::fmt;

use litebox_broker_core::{
    BrokerConnection, BrokerCore, BrokerError, CallerCredential,
    ObjectGeneration as CoreObjectGeneration, ObjectHandle as CoreObjectHandle,
    ObjectId as CoreObjectId, ObjectReferenceGeneration as CoreObjectReferenceGeneration,
    ObjectReferenceId as CoreObjectReferenceId, PolicyEngine, ReadinessState as CoreReadinessState,
    WaitOutcome as CoreWaitOutcome,
};
use litebox_broker_protocol::{
    BrokerRequest, BrokerResponse, ErrorCode, ObjectGeneration as ProtocolObjectGeneration,
    ObjectHandle as ProtocolObjectHandle, ObjectId as ProtocolObjectId,
    ObjectReferenceGeneration as ProtocolObjectReferenceGeneration,
    ObjectReferenceId as ProtocolObjectReferenceId, ProtocolVersion,
    ReadinessState as ProtocolReadinessState, WaitOutcome as ProtocolWaitOutcome,
};
use litebox_broker_transport::{PeerCredential, ReceivedRequest, ServerTransport};

/// Protocol version this broker server implementation supports.
pub const SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(0, 1);

/// Serves one broker connection over the provided connected transport.
pub fn serve_connection<P, T>(
    core: &mut BrokerCore<P>,
    transport: &mut T,
) -> Result<ConnectionTermination, BrokerServeError<T::Error>>
where
    P: PolicyEngine,
    T: ServerTransport,
{
    let peer_credential = transport
        .peer_credential()
        .map_err(BrokerServeError::Transport)?;
    let caller_credential = caller_credential_from_peer(peer_credential)
        .map_err(|()| BrokerServeError::ConnectionSetup)?;
    let connection = core
        .create_connection(caller_credential)
        .map_err(|_error| BrokerServeError::ConnectionSetup)?;

    let result = serve_request_loop(core, transport, &connection);
    core.close_connection(connection);
    result
}

fn serve_request_loop<P, T>(
    core: &mut BrokerCore<P>,
    transport: &mut T,
    connection: &BrokerConnection,
) -> Result<ConnectionTermination, BrokerServeError<T::Error>>
where
    P: PolicyEngine,
    T: ServerTransport,
{
    let mut state = ConnectionState::AwaitingNegotiation;
    loop {
        let Some(received) = transport
            .recv_request()
            .map_err(BrokerServeError::Transport)?
        else {
            break;
        };

        let dispatch = handle_received_request(core, connection, &mut state, received);
        transport
            .send_response(&dispatch.response)
            .map_err(BrokerServeError::Transport)?;
        if let DispatchOutcome::Close(reason) = dispatch.outcome {
            return Ok(ConnectionTermination::BrokerClosed(reason));
        }
    }

    Ok(ConnectionTermination::PeerClosed)
}

fn caller_credential_from_peer(peer_credential: PeerCredential) -> Result<CallerCredential, ()> {
    if peer_credential == PeerCredential::Unauthenticated {
        Ok(CallerCredential::Unauthenticated)
    } else {
        Err(())
    }
}

fn handle_received_request<P: PolicyEngine>(
    core: &mut BrokerCore<P>,
    connection: &BrokerConnection,
    state: &mut ConnectionState,
    received: ReceivedRequest,
) -> BrokerDispatch {
    match received {
        ReceivedRequest::Request(request) => handle_request(core, connection, state, request),
        ReceivedRequest::Unknown { tag: _ } => handle_unknown_request(*state),
    }
}

fn handle_request<P: PolicyEngine>(
    core: &mut BrokerCore<P>,
    connection: &BrokerConnection,
    state: &mut ConnectionState,
    request: BrokerRequest,
) -> BrokerDispatch {
    if *state == ConnectionState::AwaitingNegotiation {
        return match request {
            BrokerRequest::Negotiate { protocol_version } => {
                handle_negotiation(state, protocol_version)
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
        BrokerRequest::CreateEvent => BrokerDispatch::continue_after(handle_core_result(
            core.create_event(connection),
            |handle| BrokerResponse::Handle(protocol_handle(handle)),
        )),
        BrokerRequest::WaitEvent { handle } => BrokerDispatch::continue_after(handle_core_result(
            core.wait_event(connection, core_handle(handle)),
            |outcome| BrokerResponse::Wait(protocol_wait_outcome(outcome)),
        )),
        BrokerRequest::SignalEvent { handle } => {
            BrokerDispatch::continue_after(handle_core_result(
                core.signal_event(connection, core_handle(handle)),
                |readiness| BrokerResponse::Readiness(protocol_readiness_state(readiness)),
            ))
        }
        _ => BrokerDispatch::continue_after(BrokerResponse::Error(ErrorCode::UnsupportedOperation)),
    }
}

fn handle_unknown_request(state: ConnectionState) -> BrokerDispatch {
    if state == ConnectionState::AwaitingNegotiation {
        BrokerDispatch::close_after(
            BrokerResponse::Error(ErrorCode::ProtocolState),
            CloseReason::ProtocolViolation,
        )
    } else {
        BrokerDispatch::continue_after(BrokerResponse::Error(ErrorCode::UnsupportedOperation))
    }
}

fn handle_negotiation(
    state: &mut ConnectionState,
    protocol_version: ProtocolVersion,
) -> BrokerDispatch {
    if protocol_version.is_supported_by(SUPPORTED_PROTOCOL_VERSION) {
        *state = ConnectionState::Active;
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

fn handle_core_result<T>(
    result: litebox_broker_core::Result<T>,
    into_response: impl FnOnce(T) -> BrokerResponse,
) -> BrokerResponse {
    match result {
        Ok(value) => into_response(value),
        Err(error) => BrokerResponse::Error(protocol_error(error)),
    }
}

fn protocol_error(error: BrokerError) -> ErrorCode {
    match error {
        BrokerError::PolicyDenied => ErrorCode::PolicyDenied,
        BrokerError::UnknownObject => ErrorCode::UnknownObject,
        BrokerError::StaleHandle => ErrorCode::StaleHandle,
        BrokerError::WrongObjectType => ErrorCode::WrongObjectType,
        BrokerError::InvalidRights => ErrorCode::InvalidRights,
        BrokerError::ResourceExhausted => ErrorCode::ResourceExhausted,
    }
}

fn core_handle(handle: ProtocolObjectHandle) -> CoreObjectHandle {
    CoreObjectHandle::new(
        CoreObjectId::new(handle.object_id.get()),
        CoreObjectGeneration::new(handle.object_generation.get()),
        CoreObjectReferenceId::new(handle.reference_id.get()),
        CoreObjectReferenceGeneration::new(handle.reference_generation.get()),
    )
}

fn protocol_handle(handle: CoreObjectHandle) -> ProtocolObjectHandle {
    ProtocolObjectHandle::new(
        ProtocolObjectId::new(handle.object_id.get()),
        ProtocolObjectGeneration::new(handle.object_generation.get()),
        ProtocolObjectReferenceId::new(handle.reference_id.get()),
        ProtocolObjectReferenceGeneration::new(handle.reference_generation.get()),
    )
}

fn protocol_readiness_state(readiness: CoreReadinessState) -> ProtocolReadinessState {
    ProtocolReadinessState::new(readiness.ready, readiness.generation)
}

fn protocol_wait_outcome(outcome: CoreWaitOutcome) -> ProtocolWaitOutcome {
    match outcome {
        CoreWaitOutcome::Ready(readiness) => {
            ProtocolWaitOutcome::Ready(protocol_readiness_state(readiness))
        }
        CoreWaitOutcome::WouldBlock(readiness) => {
            ProtocolWaitOutcome::WouldBlock(protocol_readiness_state(readiness))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionState {
    AwaitingNegotiation,
    Active,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BrokerDispatch {
    response: BrokerResponse,
    outcome: DispatchOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DispatchOutcome {
    Continue,
    Close(CloseReason),
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
}

/// Reason the broker server closed the connection after sending a response.
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

/// Terminal outcome for a successfully served broker connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionTermination {
    /// The peer cleanly closed the transport.
    PeerClosed,
    /// The server sent a terminal protocol response and closed the connection.
    BrokerClosed(CloseReason),
}

/// Errors returned by a broker receive/send loop.
#[derive(Debug)]
pub enum BrokerServeError<E> {
    /// The server could not allocate or map state for a new connection.
    ConnectionSetup,
    /// The concrete transport failed.
    Transport(E),
}

impl<E: fmt::Display> fmt::Display for BrokerServeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionSetup => f.write_str("broker connection setup failed"),
            Self::Transport(error) => write!(f, "broker transport failed: {error}"),
        }
    }
}

impl<E> core::error::Error for BrokerServeError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::ConnectionSetup => None,
            Self::Transport(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_core::EventOnlyPolicy;

    #[test]
    fn dispatch_requires_negotiation_first() {
        let (mut core, connection, mut state) = new_connection();

        let dispatch = handle_request(
            &mut core,
            &connection,
            &mut state,
            BrokerRequest::CreateEvent,
        );

        assert_eq!(
            dispatch.response,
            BrokerResponse::Error(ErrorCode::ProtocolState)
        );
        assert_eq!(
            dispatch.outcome,
            DispatchOutcome::Close(CloseReason::ProtocolViolation)
        );
        assert_eq!(state, ConnectionState::AwaitingNegotiation);
    }

    #[test]
    fn dispatch_closes_after_post_negotiation_negotiate() {
        let (mut core, connection, mut state) = new_connection();
        negotiate(&mut core, &connection, &mut state);

        let dispatch = handle_request(
            &mut core,
            &connection,
            &mut state,
            BrokerRequest::Negotiate {
                protocol_version: SUPPORTED_PROTOCOL_VERSION,
            },
        );

        assert_eq!(
            dispatch.response,
            BrokerResponse::Error(ErrorCode::ProtocolState)
        );
        assert_eq!(
            dispatch.outcome,
            DispatchOutcome::Close(CloseReason::ProtocolViolation)
        );
    }

    #[test]
    fn dispatch_closes_after_unsupported_version() {
        let (mut core, connection, mut state) = new_connection();

        let dispatch = handle_request(
            &mut core,
            &connection,
            &mut state,
            BrokerRequest::Negotiate {
                protocol_version: ProtocolVersion::new(SUPPORTED_PROTOCOL_VERSION.major + 1, 0),
            },
        );

        assert_eq!(
            dispatch.response,
            BrokerResponse::Error(ErrorCode::UnsupportedVersion)
        );
        assert_eq!(
            dispatch.outcome,
            DispatchOutcome::Close(CloseReason::UnsupportedVersion)
        );
        assert_eq!(state, ConnectionState::AwaitingNegotiation);
    }

    #[test]
    fn dispatch_accepts_supported_older_minor_version() {
        let (mut core, connection, mut state) = new_connection();
        let requested = ProtocolVersion::new(
            SUPPORTED_PROTOCOL_VERSION.major,
            SUPPORTED_PROTOCOL_VERSION.minor - 1,
        );

        let dispatch = handle_request(
            &mut core,
            &connection,
            &mut state,
            BrokerRequest::Negotiate {
                protocol_version: requested,
            },
        );

        assert_eq!(
            dispatch.response,
            BrokerResponse::Negotiated {
                broker_protocol_version: SUPPORTED_PROTOCOL_VERSION
            }
        );
        assert_eq!(dispatch.outcome, DispatchOutcome::Continue);
        assert_eq!(state, ConnectionState::Active);
    }

    #[test]
    fn dispatch_rejects_newer_minor_version() {
        let (mut core, connection, mut state) = new_connection();

        let dispatch = handle_request(
            &mut core,
            &connection,
            &mut state,
            BrokerRequest::Negotiate {
                protocol_version: ProtocolVersion::new(
                    SUPPORTED_PROTOCOL_VERSION.major,
                    SUPPORTED_PROTOCOL_VERSION.minor + 1,
                ),
            },
        );

        assert_eq!(
            dispatch.response,
            BrokerResponse::Error(ErrorCode::UnsupportedVersion)
        );
        assert_eq!(
            dispatch.outcome,
            DispatchOutcome::Close(CloseReason::UnsupportedVersion)
        );
        assert_eq!(state, ConnectionState::AwaitingNegotiation);
    }

    #[test]
    fn dispatch_reports_unknown_requests_without_closing() {
        let (mut core, connection, mut state) = new_connection();
        negotiate(&mut core, &connection, &mut state);

        let dispatch = handle_received_request(
            &mut core,
            &connection,
            &mut state,
            ReceivedRequest::Unknown { tag: 0xff },
        );

        assert_eq!(
            dispatch.response,
            BrokerResponse::Error(ErrorCode::UnsupportedOperation)
        );
        assert_eq!(dispatch.outcome, DispatchOutcome::Continue);
    }

    #[test]
    fn dispatch_closes_unknown_requests_before_negotiation() {
        let (mut core, connection, mut state) = new_connection();

        let dispatch = handle_received_request(
            &mut core,
            &connection,
            &mut state,
            ReceivedRequest::Unknown { tag: 0xff },
        );

        assert_eq!(
            dispatch.response,
            BrokerResponse::Error(ErrorCode::ProtocolState)
        );
        assert_eq!(
            dispatch.outcome,
            DispatchOutcome::Close(CloseReason::ProtocolViolation)
        );
    }

    #[test]
    fn dispatch_negotiates_then_routes_event_requests() {
        let (mut core, connection, mut state) = new_connection();

        let dispatch = handle_request(
            &mut core,
            &connection,
            &mut state,
            BrokerRequest::Negotiate {
                protocol_version: SUPPORTED_PROTOCOL_VERSION,
            },
        );
        assert_eq!(
            dispatch.response,
            BrokerResponse::Negotiated {
                broker_protocol_version: SUPPORTED_PROTOCOL_VERSION
            }
        );
        assert_eq!(dispatch.outcome, DispatchOutcome::Continue);
        assert_eq!(state, ConnectionState::Active);

        let dispatch = handle_request(
            &mut core,
            &connection,
            &mut state,
            BrokerRequest::CreateEvent,
        );
        let handle = match dispatch.response {
            BrokerResponse::Handle(handle) => handle,
            response => panic!("unexpected response: {response:?}"),
        };

        let dispatch = handle_request(
            &mut core,
            &connection,
            &mut state,
            BrokerRequest::WaitEvent { handle },
        );
        assert_eq!(
            dispatch.response,
            BrokerResponse::Wait(ProtocolWaitOutcome::WouldBlock(
                ProtocolReadinessState::new(false, 0)
            ))
        );
        assert_eq!(dispatch.outcome, DispatchOutcome::Continue);
    }

    #[test]
    fn dispatch_rejects_handle_from_another_connection() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let owner = core
            .create_connection(CallerCredential::Unauthenticated)
            .unwrap();
        let other = core
            .create_connection(CallerCredential::Unauthenticated)
            .unwrap();
        let mut owner_state = ConnectionState::AwaitingNegotiation;
        let mut other_state = ConnectionState::AwaitingNegotiation;
        negotiate(&mut core, &owner, &mut owner_state);
        negotiate(&mut core, &other, &mut other_state);

        let dispatch = handle_request(
            &mut core,
            &owner,
            &mut owner_state,
            BrokerRequest::CreateEvent,
        );
        let handle = match dispatch.response {
            BrokerResponse::Handle(handle) => handle,
            response => panic!("unexpected response: {response:?}"),
        };

        let dispatch = handle_request(
            &mut core,
            &other,
            &mut other_state,
            BrokerRequest::WaitEvent { handle },
        );
        assert_eq!(
            dispatch.response,
            BrokerResponse::Error(ErrorCode::InvalidRights)
        );
        assert_eq!(dispatch.outcome, DispatchOutcome::Continue);
    }

    #[test]
    fn protocol_adapters_preserve_handle_fields() {
        let protocol = ProtocolObjectHandle::new(
            ProtocolObjectId::new(10),
            ProtocolObjectGeneration::new(11),
            ProtocolObjectReferenceId::new(12),
            ProtocolObjectReferenceGeneration::new(13),
        );

        assert_eq!(protocol_handle(core_handle(protocol)), protocol);
    }

    #[test]
    fn protocol_adapters_preserve_wait_outcome() {
        let outcome = CoreWaitOutcome::Ready(CoreReadinessState::new(true, 42));

        assert_eq!(
            protocol_wait_outcome(outcome),
            ProtocolWaitOutcome::Ready(ProtocolReadinessState::new(true, 42))
        );
    }

    fn new_connection() -> (
        BrokerCore<EventOnlyPolicy>,
        BrokerConnection,
        ConnectionState,
    ) {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let connection = core
            .create_connection(CallerCredential::Unauthenticated)
            .unwrap();
        (core, connection, ConnectionState::AwaitingNegotiation)
    }

    fn negotiate<P: PolicyEngine>(
        core: &mut BrokerCore<P>,
        connection: &BrokerConnection,
        state: &mut ConnectionState,
    ) {
        let dispatch = handle_request(
            core,
            connection,
            state,
            BrokerRequest::Negotiate {
                protocol_version: SUPPORTED_PROTOCOL_VERSION,
            },
        );
        assert_eq!(
            dispatch.response,
            BrokerResponse::Negotiated {
                broker_protocol_version: SUPPORTED_PROTOCOL_VERSION
            }
        );
        assert_eq!(*state, ConnectionState::Active);
    }
}
