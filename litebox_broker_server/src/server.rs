// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::fmt;

use litebox_broker_channel::{PeerCredential, ReceivedBrokerRequest, ServerControlChannel};
use litebox_broker_core::{
    BrokerAssociation, BrokerCore, BrokerError, CallerCredential, ObjectHandle as CoreObjectHandle,
    ObjectReferenceGeneration as CoreObjectReferenceGeneration,
    ObjectReferenceId as CoreObjectReferenceId, PolicyEngine, ReadinessState as CoreReadinessState,
    WaitOutcome as CoreWaitOutcome,
};
use litebox_broker_protocol::{
    BrokerRequest, BrokerResponse, CoreRequest, CoreResponse, ErrorCode, EventRequest,
    EventResponse, ObjectHandle as ProtocolObjectHandle,
    ObjectReferenceGeneration as ProtocolObjectReferenceGeneration,
    ObjectReferenceId as ProtocolObjectReferenceId, ProtocolVersion,
    ReadinessState as ProtocolReadinessState, WaitOutcome as ProtocolWaitOutcome,
};

/// Protocol version this broker server implementation supports.
pub const SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(0, 1);

/// Serves one broker connection over the provided connected control channel.
pub fn serve_connection<P, T>(
    core: &mut BrokerCore<P>,
    channel: &mut T,
) -> Result<ConnectionTermination, BrokerServeError<T::Error>>
where
    P: PolicyEngine,
    T: ServerControlChannel,
{
    let peer_credential = channel
        .peer_credential()
        .map_err(BrokerServeError::Channel)?;
    let caller_credential = caller_credential_from_peer(peer_credential)
        .map_err(|()| BrokerServeError::AssociationSetup)?;
    let association = core
        .create_association(caller_credential)
        .map_err(|_error| BrokerServeError::AssociationSetup)?;

    let result = serve_request_loop(core, channel, &association);
    core.close_association(association);
    result
}

fn serve_request_loop<P, T>(
    core: &mut BrokerCore<P>,
    channel: &mut T,
    association: &BrokerAssociation,
) -> Result<ConnectionTermination, BrokerServeError<T::Error>>
where
    P: PolicyEngine,
    T: ServerControlChannel,
{
    let mut state = ConnectionState::AwaitingNegotiation;
    loop {
        let Some(received) = channel.recv_request().map_err(BrokerServeError::Channel)? else {
            break;
        };

        let dispatch = handle_received_request(core, association, &mut state, received);
        channel
            .send_response(&dispatch.response)
            .map_err(BrokerServeError::Channel)?;
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
    association: &BrokerAssociation,
    state: &mut ConnectionState,
    received: ReceivedBrokerRequest,
) -> BrokerDispatch {
    match received {
        ReceivedBrokerRequest::Request(request) => {
            handle_request(core, association, state, request)
        }
        _ => handle_unknown_request(*state),
    }
}

fn handle_request<P: PolicyEngine>(
    core: &mut BrokerCore<P>,
    association: &BrokerAssociation,
    state: &mut ConnectionState,
    request: BrokerRequest,
) -> BrokerDispatch {
    match *state {
        ConnectionState::AwaitingNegotiation => match request {
            BrokerRequest::Negotiate { protocol_version } => {
                handle_negotiation(state, protocol_version)
            }
            _ => BrokerDispatch::close_after(
                BrokerResponse::Error(ErrorCode::ProtocolState),
                CloseReason::ProtocolViolation,
            ),
        },
        ConnectionState::Active {
            negotiated_protocol_version,
        } => handle_active_request(core, association, negotiated_protocol_version, request),
    }
}

fn handle_active_request<P: PolicyEngine>(
    core: &mut BrokerCore<P>,
    association: &BrokerAssociation,
    _negotiated_protocol_version: ProtocolVersion,
    request: BrokerRequest,
) -> BrokerDispatch {
    match request {
        BrokerRequest::Negotiate { .. } => BrokerDispatch::close_after(
            BrokerResponse::Error(ErrorCode::ProtocolState),
            CloseReason::ProtocolViolation,
        ),
        BrokerRequest::Core(CoreRequest::Event(request)) => {
            BrokerDispatch::continue_after(handle_event_request(core, association, request))
        }
        _ => BrokerDispatch::continue_after(BrokerResponse::Error(ErrorCode::UnsupportedOperation)),
    }
}

fn handle_event_request<P: PolicyEngine>(
    core: &mut BrokerCore<P>,
    association: &BrokerAssociation,
    request: EventRequest,
) -> BrokerResponse {
    match request {
        EventRequest::Create => handle_core_result(core.create_event(association), |handle| {
            event_response(EventResponse::Created {
                handle: to_protocol_handle(handle),
            })
        }),
        EventRequest::Wait { handle } => {
            handle_wait_result(core.wait_event(association, to_core_handle(handle)))
        }
        EventRequest::Signal { handle } => handle_core_result(
            core.signal_event(association, to_core_handle(handle)),
            |readiness| {
                event_response(EventResponse::Signaled {
                    readiness: to_protocol_readiness_state(readiness),
                })
            },
        ),
        _ => BrokerResponse::Error(ErrorCode::UnsupportedOperation),
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
        *state = ConnectionState::Active {
            negotiated_protocol_version: protocol_version,
        };
        BrokerDispatch::continue_after(BrokerResponse::Negotiated {
            broker_protocol_version: SUPPORTED_PROTOCOL_VERSION,
        })
    } else {
        BrokerDispatch::continue_after(BrokerResponse::VersionMismatch {
            broker_protocol_version: SUPPORTED_PROTOCOL_VERSION,
        })
    }
}

fn handle_core_result<T>(
    result: litebox_broker_core::Result<T>,
    into_response: impl FnOnce(T) -> BrokerResponse,
) -> BrokerResponse {
    match result {
        Ok(value) => into_response(value),
        Err(error) => BrokerResponse::Error(to_protocol_error(error)),
    }
}

fn handle_wait_result(result: litebox_broker_core::Result<CoreWaitOutcome>) -> BrokerResponse {
    match result {
        Ok(outcome) => match to_protocol_wait_outcome(outcome) {
            Some(outcome) => event_response(EventResponse::Waited { outcome }),
            None => BrokerResponse::Error(ErrorCode::Internal),
        },
        Err(error) => BrokerResponse::Error(to_protocol_error(error)),
    }
}

const fn event_response(response: EventResponse) -> BrokerResponse {
    BrokerResponse::Core(CoreResponse::Event(response))
}

fn to_protocol_error(error: BrokerError) -> ErrorCode {
    match error {
        BrokerError::PolicyDenied => ErrorCode::PolicyDenied,
        BrokerError::UnknownObject => ErrorCode::UnknownObject,
        BrokerError::StaleHandle => ErrorCode::StaleHandle,
        BrokerError::WrongObjectType => ErrorCode::WrongObjectType,
        BrokerError::InvalidRights => ErrorCode::InvalidRights,
        BrokerError::ResourceExhausted => ErrorCode::ResourceExhausted,
        _ => ErrorCode::Internal,
    }
}

fn to_core_handle(handle: ProtocolObjectHandle) -> CoreObjectHandle {
    CoreObjectHandle::new(
        CoreObjectReferenceId::new(handle.reference_id.get()),
        CoreObjectReferenceGeneration::new(handle.reference_generation.get()),
    )
}

fn to_protocol_handle(handle: CoreObjectHandle) -> ProtocolObjectHandle {
    ProtocolObjectHandle::new(
        ProtocolObjectReferenceId::new(handle.reference_id.get()),
        ProtocolObjectReferenceGeneration::new(handle.reference_generation.get()),
    )
}

fn to_protocol_readiness_state(readiness: CoreReadinessState) -> ProtocolReadinessState {
    ProtocolReadinessState::new(readiness.ready, readiness.generation)
}

fn to_protocol_wait_outcome(outcome: CoreWaitOutcome) -> Option<ProtocolWaitOutcome> {
    match outcome {
        CoreWaitOutcome::Ready(readiness) => Some(ProtocolWaitOutcome::Ready(
            to_protocol_readiness_state(readiness),
        )),
        CoreWaitOutcome::WouldBlock(readiness) => Some(ProtocolWaitOutcome::WouldBlock(
            to_protocol_readiness_state(readiness),
        )),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionState {
    AwaitingNegotiation,
    Active {
        negotiated_protocol_version: ProtocolVersion,
    },
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
#[non_exhaustive]
pub enum CloseReason {
    /// The peer violated the request sequencing state machine.
    ProtocolViolation,
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolViolation => f.write_str("protocol violation"),
        }
    }
}

/// Terminal outcome for a successfully served broker connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionTermination {
    /// The peer cleanly closed the channel.
    PeerClosed,
    /// The server sent a terminal protocol response and closed the connection.
    BrokerClosed(CloseReason),
}

/// Errors returned by a broker receive/send loop.
#[derive(Debug)]
#[non_exhaustive]
pub enum BrokerServeError<E> {
    /// The server could not authenticate the peer or allocate broker association state.
    AssociationSetup,
    /// The concrete channel failed.
    Channel(E),
}

impl<E: fmt::Display> fmt::Display for BrokerServeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AssociationSetup => f.write_str("broker association setup failed"),
            Self::Channel(error) => write!(f, "broker channel failed: {error}"),
        }
    }
}

impl<E> core::error::Error for BrokerServeError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::AssociationSetup => None,
            Self::Channel(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_core::EventOnlyPolicy;

    #[test]
    fn dispatch_enforces_negotiation_state() {
        let (mut core, association, mut state) = new_association();

        let dispatch = handle_request(
            &mut core,
            &association,
            &mut state,
            event_request(EventRequest::Create),
        );
        assert_protocol_violation(dispatch);
        assert_eq!(state, ConnectionState::AwaitingNegotiation);

        let (mut core, association, mut state) = new_association();
        negotiate(&mut core, &association, &mut state);

        let dispatch = handle_request(
            &mut core,
            &association,
            &mut state,
            BrokerRequest::Negotiate {
                protocol_version: SUPPORTED_PROTOCOL_VERSION,
            },
        );
        assert_protocol_violation(dispatch);
    }

    #[test]
    fn dispatch_rejects_unsupported_protocol_version_without_activation() {
        let (mut core, association, mut state) = new_association();

        let dispatch = handle_request(
            &mut core,
            &association,
            &mut state,
            BrokerRequest::Negotiate {
                protocol_version: ProtocolVersion::new(SUPPORTED_PROTOCOL_VERSION.major + 1, 0),
            },
        );

        assert_eq!(
            dispatch.response,
            BrokerResponse::VersionMismatch {
                broker_protocol_version: SUPPORTED_PROTOCOL_VERSION
            }
        );
        assert_eq!(dispatch.outcome, DispatchOutcome::Continue);
        assert_eq!(state, ConnectionState::AwaitingNegotiation);
    }

    #[test]
    fn dispatch_handles_unknown_wire_requests_by_state() {
        let (mut core, association, mut state) = new_association();

        let dispatch = handle_received_request(
            &mut core,
            &association,
            &mut state,
            ReceivedBrokerRequest::Unknown,
        );
        assert_protocol_violation(dispatch);

        let (mut core, association, mut state) = new_association();
        negotiate(&mut core, &association, &mut state);

        let dispatch = handle_received_request(
            &mut core,
            &association,
            &mut state,
            ReceivedBrokerRequest::Unknown,
        );

        assert_eq!(
            dispatch.response,
            BrokerResponse::Error(ErrorCode::UnsupportedOperation)
        );
        assert_eq!(dispatch.outcome, DispatchOutcome::Continue);
    }

    #[test]
    fn dispatch_negotiates_then_routes_event_requests() {
        let (mut core, association, mut state) = new_association();
        negotiate(&mut core, &association, &mut state);

        let dispatch = handle_request(
            &mut core,
            &association,
            &mut state,
            event_request(EventRequest::Create),
        );
        assert_eq!(dispatch.outcome, DispatchOutcome::Continue);
        let handle = match dispatch.response {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Created { handle })) => handle,
            response => panic!("unexpected response: {response:?}"),
        };

        let dispatch = handle_request(
            &mut core,
            &association,
            &mut state,
            event_request(EventRequest::Wait { handle }),
        );
        assert_eq!(
            dispatch.response,
            event_response(EventResponse::Waited {
                outcome: ProtocolWaitOutcome::WouldBlock(ProtocolReadinessState::new(false, 0))
            })
        );
        assert_eq!(dispatch.outcome, DispatchOutcome::Continue);

        let dispatch = handle_request(
            &mut core,
            &association,
            &mut state,
            event_request(EventRequest::Signal { handle }),
        );
        assert_eq!(
            dispatch.response,
            event_response(EventResponse::Signaled {
                readiness: ProtocolReadinessState::new(true, 1)
            })
        );
        assert_eq!(dispatch.outcome, DispatchOutcome::Continue);

        let dispatch = handle_request(
            &mut core,
            &association,
            &mut state,
            event_request(EventRequest::Wait { handle }),
        );
        assert_eq!(
            dispatch.response,
            event_response(EventResponse::Waited {
                outcome: ProtocolWaitOutcome::Ready(ProtocolReadinessState::new(true, 1))
            })
        );
        assert_eq!(dispatch.outcome, DispatchOutcome::Continue);
    }

    #[test]
    fn serve_connection_negotiates_routes_event_and_returns_peer_closed() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut channel = FakeServerChannel::new(std::vec::Vec::from([
            Ok(Some(ReceivedBrokerRequest::Request(
                BrokerRequest::Negotiate {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION,
                },
            ))),
            Ok(Some(ReceivedBrokerRequest::Request(event_request(
                EventRequest::Create,
            )))),
            Ok(None),
        ]));

        assert_eq!(
            serve_connection(&mut core, &mut channel).unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.responses[0],
            BrokerResponse::Negotiated {
                broker_protocol_version: SUPPORTED_PROTOCOL_VERSION
            }
        );
        let handle = match channel.responses[1] {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Created { handle })) => handle,
            response => panic!("unexpected response: {response:?}"),
        };

        let probe = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        assert_eq!(
            core.close_object_reference(&probe, to_core_handle(handle)),
            Err(BrokerError::UnknownObject)
        );
    }

    #[test]
    fn serve_connection_closes_after_protocol_violation() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut channel = FakeServerChannel::new(std::vec::Vec::from([
            Ok(Some(ReceivedBrokerRequest::Request(event_request(
                EventRequest::Create,
            )))),
            Ok(Some(ReceivedBrokerRequest::Request(
                BrokerRequest::Negotiate {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION,
                },
            ))),
        ]));

        assert_eq!(
            serve_connection(&mut core, &mut channel).unwrap(),
            ConnectionTermination::BrokerClosed(CloseReason::ProtocolViolation)
        );
        assert_eq!(
            channel.responses,
            [BrokerResponse::Error(ErrorCode::ProtocolState)]
        );
        assert_eq!(channel.requests.len(), 1);
    }

    #[test]
    fn serve_connection_returns_channel_error_after_cleanup_path() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut channel = FakeServerChannel::new(std::vec::Vec::from([
            Ok(Some(ReceivedBrokerRequest::Request(
                BrokerRequest::Negotiate {
                    protocol_version: SUPPORTED_PROTOCOL_VERSION,
                },
            ))),
            Ok(Some(ReceivedBrokerRequest::Request(event_request(
                EventRequest::Create,
            )))),
            Err(FakeChannelError::Recv),
        ]));

        match serve_connection(&mut core, &mut channel) {
            Err(BrokerServeError::Channel(FakeChannelError::Recv)) => {}
            result => panic!("unexpected serve result: {result:?}"),
        }
        assert_eq!(channel.responses.len(), 2);
    }

    #[test]
    fn serve_connection_returns_channel_error_when_response_send_fails() {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let mut channel = FakeServerChannel::new(std::vec::Vec::from([Ok(Some(
            ReceivedBrokerRequest::Request(BrokerRequest::Negotiate {
                protocol_version: SUPPORTED_PROTOCOL_VERSION,
            }),
        ))]));
        channel.send_error = Some(FakeChannelError::Send);

        match serve_connection(&mut core, &mut channel) {
            Err(BrokerServeError::Channel(FakeChannelError::Send)) => {}
            result => panic!("unexpected serve result: {result:?}"),
        }
        assert!(channel.responses.is_empty());
    }

    fn assert_protocol_violation(dispatch: BrokerDispatch) {
        assert_eq!(
            dispatch.response,
            BrokerResponse::Error(ErrorCode::ProtocolState)
        );
        assert_eq!(
            dispatch.outcome,
            DispatchOutcome::Close(CloseReason::ProtocolViolation)
        );
    }

    fn new_association() -> (
        BrokerCore<EventOnlyPolicy>,
        BrokerAssociation,
        ConnectionState,
    ) {
        let mut core = BrokerCore::new(EventOnlyPolicy);
        let association = core
            .create_association(CallerCredential::Unauthenticated)
            .unwrap();
        (core, association, ConnectionState::AwaitingNegotiation)
    }

    fn negotiate<P: PolicyEngine>(
        core: &mut BrokerCore<P>,
        association: &BrokerAssociation,
        state: &mut ConnectionState,
    ) {
        let dispatch = handle_request(
            core,
            association,
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
        assert_eq!(
            *state,
            ConnectionState::Active {
                negotiated_protocol_version: SUPPORTED_PROTOCOL_VERSION
            }
        );
    }

    const fn event_request(request: EventRequest) -> BrokerRequest {
        BrokerRequest::Core(CoreRequest::Event(request))
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FakeChannelError {
        Recv,
        Send,
    }

    impl fmt::Display for FakeChannelError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Recv => f.write_str("fake receive error"),
                Self::Send => f.write_str("fake send error"),
            }
        }
    }

    impl core::error::Error for FakeChannelError {}

    struct FakeServerChannel {
        requests:
            std::vec::Vec<core::result::Result<Option<ReceivedBrokerRequest>, FakeChannelError>>,
        responses: std::vec::Vec<BrokerResponse>,
        send_error: Option<FakeChannelError>,
    }

    impl FakeServerChannel {
        fn new(
            requests: std::vec::Vec<
                core::result::Result<Option<ReceivedBrokerRequest>, FakeChannelError>,
            >,
        ) -> Self {
            Self {
                requests,
                responses: std::vec::Vec::new(),
                send_error: None,
            }
        }
    }

    impl ServerControlChannel for FakeServerChannel {
        type Error = FakeChannelError;

        fn peer_credential(&self) -> core::result::Result<PeerCredential, Self::Error> {
            Ok(PeerCredential::Unauthenticated)
        }

        fn recv_request(
            &mut self,
        ) -> core::result::Result<Option<ReceivedBrokerRequest>, Self::Error> {
            if self.requests.is_empty() {
                Ok(None)
            } else {
                self.requests.remove(0)
            }
        }

        fn send_response(
            &mut self,
            response: &BrokerResponse,
        ) -> core::result::Result<(), Self::Error> {
            if let Some(error) = self.send_error {
                return Err(error);
            }
            self.responses.push(*response);
            Ok(())
        }
    }
}
