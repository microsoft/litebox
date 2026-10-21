// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Generic broker association runtime.
//!
//! This module owns association setup, request dispatch, readiness
//! publication, cancellation, and teardown for one broker association.
//! It is transport-neutral: it depends only on the [`HostSetupChannel`],
//! [`HostCallLaneSource`], [`HostCallLane`], [`HostNotificationChannel`], and
//! [`HostAssociationShutdown`] contracts from
//! `litebox_broker_transport::channel`, so a deployment supplies the
//! transport-specific setup channel, activation, and shared-memory plumbing
//! and this runtime serves the association the same way regardless of
//! transport.
//!
//! Concurrency is deliberately not part of the public surface. Both
//! association entry points delegate to one internal runtime that chooses the
//! control-ring layout and serves each of its call lanes with one worker.

use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use litebox_broker_core::BrokerCore;
use litebox_broker_host::{
    BrokerHostAssociation, BrokerHostError, ConnectionTermination, handle_process_operation,
    setup_connection,
};
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_LAYOUT;
use litebox_broker_transport::channel::{
    HostAssociationShutdown, HostCallLane, HostCallLaneSource, HostNotificationChannel,
    HostReceive, HostSetupChannel,
};
use litebox_broker_transport::control_ring::{ControlRing, ControlRingLayout};
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedBufferPool, SharedMemory};

use crate::process_launcher::{PendingRunnerAssociation, UserlandProcessLauncher};
use crate::readiness::ReadinessPublisherRuntime;

pub(crate) struct AssociationOutcome {
    pub(crate) result: IoResult<()>,
    pub(crate) abnormal: bool,
}

pub(crate) fn is_peer_closed_error(error: &IoError) -> bool {
    matches!(
        error.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
    )
}

/// Serves an association for the development-only in-process runner.
///
/// `control_channel` must already be configured with whatever deadline and
/// peer authentication its transport requires; this function only negotiates
/// the broker protocol and control-ring setup over it. `create_shared_memory`
/// and `create_control_memory` (for the given control-ring layout) allocate
/// the transport's shared-memory resources, `send_shared_memory` transfers
/// them to the peer, and `activate` consumes the negotiated setup channel and
/// control ring into the transport's active call lanes, notification, and
/// shutdown endpoints.
///
/// Returns once the association ends, whether by a clean peer close or a
/// failure. Layout mismatches and broker setup failures are mapped to a
/// precise [`std::io::Error`] rather than left as an opaque boxed error.
pub fn serve_in_process_runner_association<
    Memory,
    SetupChannel,
    LaneSource,
    NotificationChannel,
    Shutdown,
>(
    broker: &BrokerCore,
    control_channel: SetupChannel,
    create_shared_memory: impl FnOnce() -> IoResult<Memory>,
    create_control_memory: impl FnOnce(ControlRingLayout) -> IoResult<Memory>,
    send_shared_memory: impl FnOnce(&mut SetupChannel, &Memory, &Memory) -> IoResult<()>,
    activate: impl FnOnce(
        SetupChannel,
        ControlRing<Memory>,
    ) -> IoResult<(LaneSource, NotificationChannel, Shutdown)>,
) -> IoResult<()>
where
    Memory: ControlRingMemory,
    SetupChannel: HostSetupChannel<Error = IoError>,
    LaneSource: HostCallLaneSource<Error = IoError> + Send,
    LaneSource::Lane: Send,
    NotificationChannel: HostNotificationChannel<Error = IoError> + Send,
    Shutdown: HostAssociationShutdown<Error = IoError> + Sync,
{
    serve_association_inner(
        broker,
        control_channel,
        create_shared_memory,
        create_control_memory,
        send_shared_memory,
        activate,
        None,
        None,
    )
    .and_then(|outcome| outcome.result)
}

/// Serves an initial or parent-started association for an out-of-process runner.
///
/// Unlike the in-process path, this reports process ownership and failure
/// details to `RunnerInstance`, which owns runner termination and cleanup.
#[allow(clippy::too_many_arguments)]
pub(crate) fn serve_out_of_process_runner_association<
    Memory,
    SetupChannel,
    LaneSource,
    NotificationChannel,
    Shutdown,
>(
    startup: PendingRunnerAssociation,
    broker: BrokerCore,
    control_channel: SetupChannel,
    create_shared_memory: impl FnOnce() -> IoResult<Memory>,
    create_control_memory: impl FnOnce(ControlRingLayout) -> IoResult<Memory>,
    send_shared_memory: impl FnOnce(&mut SetupChannel, &Memory, &Memory) -> IoResult<()>,
    activate: impl FnOnce(
        SetupChannel,
        ControlRing<Memory>,
    ) -> IoResult<(LaneSource, NotificationChannel, Shutdown)>,
    launcher: Arc<UserlandProcessLauncher>,
) -> AssociationOutcome
where
    Memory: ControlRingMemory,
    SetupChannel: HostSetupChannel<Error = IoError>,
    LaneSource: HostCallLaneSource<Error = IoError> + Send,
    LaneSource::Lane: Send,
    NotificationChannel: HostNotificationChannel<Error = IoError> + Send,
    Shutdown: HostAssociationShutdown<Error = IoError> + Sync,
{
    let outcome = serve_association_inner(
        &broker,
        control_channel,
        create_shared_memory,
        create_control_memory,
        send_shared_memory,
        activate,
        Some(launcher),
        Some(startup),
    );
    let mut outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => AssociationOutcome {
            result: Err(error),
            abnormal: false,
        },
    };
    let result_is_abnormal = outcome
        .result
        .as_ref()
        .is_err_and(|error| !is_peer_closed_error(error));
    outcome.abnormal |= result_is_abnormal;
    outcome
}

#[allow(clippy::too_many_arguments)]
fn serve_association_inner<Memory, SetupChannel, LaneSource, NotificationChannel, Shutdown>(
    broker: &BrokerCore,
    mut control_channel: SetupChannel,
    create_shared_memory: impl FnOnce() -> IoResult<Memory>,
    create_control_memory: impl FnOnce(ControlRingLayout) -> IoResult<Memory>,
    send_shared_memory: impl FnOnce(&mut SetupChannel, &Memory, &Memory) -> IoResult<()>,
    activate: impl FnOnce(
        SetupChannel,
        ControlRing<Memory>,
    ) -> IoResult<(LaneSource, NotificationChannel, Shutdown)>,
    launcher: Option<Arc<UserlandProcessLauncher>>,
    startup: Option<PendingRunnerAssociation>,
) -> IoResult<AssociationOutcome>
where
    Memory: ControlRingMemory,
    SetupChannel: HostSetupChannel<Error = IoError>,
    LaneSource: HostCallLaneSource<Error = IoError> + Send,
    LaneSource::Lane: Send,
    NotificationChannel: HostNotificationChannel<Error = IoError> + Send,
    Shutdown: HostAssociationShutdown<Error = IoError> + Sync,
{
    let (process, startup) = match startup {
        Some(startup) => {
            let (process, data) = startup.into_process_and_startup();
            (Some(process), data)
        }
        None => (None, None),
    };
    let finish_process = process.is_none();
    let shared_memory = create_shared_memory()?;
    let shared_buffers = Arc::new(
        SharedBufferPool::new(shared_memory, SHARED_BUFFER_LAYOUT)
            .map_err(|error| IoError::new(ErrorKind::InvalidData, error.to_string()))?,
    );
    let layout = ControlRingLayout::MULTI_LANE;
    let control_memory = create_control_memory(layout)?;
    let control_ring = ControlRing::new(control_memory, layout)
        .map_err(|error| IoError::other(format!("failed to create control ring: {error:?}")))?;
    let readiness = Arc::new(ReadinessPublisherRuntime::new());
    let association = match setup_connection(
        broker,
        process,
        startup,
        &mut control_channel,
        Arc::clone(&shared_buffers),
        readiness.clone(),
        |_| false,
        |channel| send_shared_memory(channel, shared_buffers.memory(), control_ring.memory()),
    )
    .map_err(map_host_error)?
    {
        Ok(association) => association,
        Err(ConnectionTermination::PeerClosed) => {
            return Err(IoError::new(
                ErrorKind::UnexpectedEof,
                "runner closed before completing broker setup",
            ));
        }
        Err(ConnectionTermination::ProtocolViolation) => {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "runner violated the broker protocol during setup",
            ));
        }
        Err(_) => {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "runner ended broker setup unexpectedly",
            ));
        }
    };
    let (lane_source, notification_channel, shutdown) =
        match activate(control_channel, control_ring) {
            Ok(active) => active,
            Err(error) => {
                if finish_process {
                    association.finish();
                }
                return Err(error);
            }
        };
    Ok(dispatch_requests(
        association,
        readiness,
        lane_source,
        notification_channel,
        shutdown,
        launcher,
        finish_process,
    ))
}

/// Maps a host setup or request failure to a precise [`std::io::Error`].
///
/// A channel failure is already an [`std::io::Error`] and is returned as-is.
/// Broker errors retain the closest matching I/O category, while a
/// shared-buffer layout mismatch is invalid transport data.
fn map_host_error(error: BrokerHostError<IoError>) -> IoError {
    let description = error.to_string();
    match error {
        BrokerHostError::Channel(error) => error,
        BrokerHostError::Broker(error) => {
            let kind = match error {
                ErrorCode::UnsupportedVersion
                | ErrorCode::MalformedRequest
                | ErrorCode::ProtocolState => ErrorKind::InvalidData,
                ErrorCode::UnsupportedOperation => ErrorKind::Unsupported,
                ErrorCode::PolicyDenied | ErrorCode::InvalidRights => ErrorKind::PermissionDenied,
                ErrorCode::UnknownObject => ErrorKind::NotFound,
                ErrorCode::WouldBlock => ErrorKind::WouldBlock,
                ErrorCode::PeerClosed => ErrorKind::BrokenPipe,
                ErrorCode::OutOfMemory => ErrorKind::OutOfMemory,
                _ => ErrorKind::Other,
            };
            IoError::new(kind, description)
        }
        BrokerHostError::SharedBufferLayoutMismatch => {
            IoError::new(ErrorKind::InvalidData, description)
        }
        BrokerHostError::AssociationFailed => {
            IoError::new(ErrorKind::ConnectionAborted, description)
        }
        _ => IoError::other(description),
    }
}

/// Records the first failure of an association and ends its transport.
///
/// Every thread serving an association reports through this, and the endpoints
/// they block on are released by ending the transport, so it is what the
/// teardown guards below reach for.
struct HostAssociationFailureCoordinator<Shutdown> {
    failed: AtomicBool,
    /// Whether an association worker panicked, requiring teardown without ID reuse.
    panicked: AtomicBool,
    abnormal: AtomicBool,
    error: Mutex<Option<IoError>>,
    shutdown: Shutdown,
}

impl<Shutdown: HostAssociationShutdown<Error = IoError>>
    HostAssociationFailureCoordinator<Shutdown>
{
    const fn new(shutdown: Shutdown) -> Self {
        Self {
            failed: AtomicBool::new(false),
            panicked: AtomicBool::new(false),
            abnormal: AtomicBool::new(false),
            error: Mutex::new(None),
            shutdown,
        }
    }

    fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn report(&self, error: IoError) {
        if !is_peer_closed_error(&error) {
            self.abnormal.store(true, Ordering::Release);
        }
        if self.failed.swap(true, Ordering::AcqRel) {
            return;
        }
        *self
            .error
            .lock()
            .expect("broker association failure mutex poisoned") = Some(error);
        let _ = self.shutdown.shutdown();
    }

    fn report_panic(&self, error: IoError) {
        self.panicked.store(true, Ordering::Release);
        self.report(error);
    }

    fn panicked(&self) -> bool {
        self.panicked.load(Ordering::Acquire)
    }

    fn abnormal(&self) -> bool {
        self.abnormal.load(Ordering::Acquire)
    }

    /// Ends the association transport without recording a failure.
    ///
    /// Teardown uses this to release blocked endpoints without turning a
    /// shutdown that reported nothing into a reported error.
    fn shutdown(&self) {
        let _ = self.shutdown.shutdown();
    }

    fn take_error(&self) -> Option<IoError> {
        self.error
            .lock()
            .expect("broker association failure mutex poisoned")
            .take()
    }
}

/// Fails the association if readiness publication unwinds.
///
/// The association thread owns association termination but does not depend on
/// the publisher, so an unwinding publisher would otherwise leave a live
/// association with no notification source. The join that turns that panic into
/// a reported failure is reached only once the association has ended, and a
/// peer that is waiting for a readiness change it will never be told about does
/// not end it. Failing the association here ends it instead.
struct PublisherPanicGuard<'association, Shutdown: HostAssociationShutdown<Error = IoError>> {
    failure_coordinator: &'association HostAssociationFailureCoordinator<Shutdown>,
}

impl<Shutdown: HostAssociationShutdown<Error = IoError>> Drop
    for PublisherPanicGuard<'_, Shutdown>
{
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.failure_coordinator
                .report_panic(IoError::other("broker readiness publisher panicked"));
        }
    }
}

/// Ends readiness publication when an association scope ends for any reason.
///
/// The publisher is a scoped thread, so the scope joins it before propagating a
/// panic out of the association, and both states it can rest in have to end for
/// that join to complete. Closing publication returns a publisher parked for
/// work, and ending the transport returns one blocked on notification capacity
/// that a local endpoint stopped draining, as well as any worker waiting for a
/// request. The failure coordinator owns the association until
/// `dispatch_requests` returns, which is after that join, so an unwind cannot
/// leave ending the transport to dropping it.
struct ReadinessPublicationGuard<'association, Shutdown: HostAssociationShutdown<Error = IoError>> {
    readiness: &'association ReadinessPublisherRuntime,
    failure_coordinator: &'association HostAssociationFailureCoordinator<Shutdown>,
}

impl<Shutdown: HostAssociationShutdown<Error = IoError>> Drop
    for ReadinessPublicationGuard<'_, Shutdown>
{
    fn drop(&mut self) {
        self.readiness.close();
        self.failure_coordinator.shutdown();
    }
}

/// Ends an association once its end is observed, including on an unwind:
/// cancels the requests still executing and applies owner-death handling, which
/// fails the children still starting.
struct AssociationEndingGuard<'association, Memory: SharedMemory> {
    association: &'association BrokerHostAssociation<Memory>,
}

impl<Memory: SharedMemory> Drop for AssociationEndingGuard<'_, Memory> {
    fn drop(&mut self) {
        self.association.request_cancellation();
        self.association.association_ending();
    }
}

/// Serves one association until it ends, then reports its first failure.
///
/// Each call lane gets its own worker once the runner first uses it, so the
/// association has as many workers as the runner has had calls in flight at
/// once. Calls on different lanes never wait for each other, and back-to-back
/// calls stay on the first lane's worker.
///
/// This thread serves the first lane: having run setup with the runner, it
/// tends to stay near the runner, whereas a new thread can land across a cache
/// boundary. An observer thread starts and joins the workers of further lanes
/// and ends the association as soon as it observes its end, so requests still
/// executing see that promptly.
///
/// `readiness` is created by the caller rather than here so readiness sources
/// can record into the same runtime this publishes from. The Linux network
/// reactor is currently its production source.
#[allow(clippy::too_many_arguments)]
fn dispatch_requests<Memory, LaneSource, NotificationChannel, Shutdown>(
    association: BrokerHostAssociation<Memory>,
    readiness: Arc<ReadinessPublisherRuntime>,
    mut lane_source: LaneSource,
    mut notification_channel: NotificationChannel,
    shutdown: Shutdown,
    launcher: Option<Arc<UserlandProcessLauncher>>,
    finish_process: bool,
) -> AssociationOutcome
where
    Memory: SharedMemory,
    LaneSource: HostCallLaneSource<Error = IoError> + Send,
    LaneSource::Lane: Send,
    NotificationChannel: HostNotificationChannel<Error = IoError> + Send,
    Shutdown: HostAssociationShutdown<Error = IoError> + Sync,
{
    let failure_coordinator = HostAssociationFailureCoordinator::new(shutdown);
    if let Err(error) = association.activate_process() {
        return AssociationOutcome {
            result: Err(IoError::other(format!(
                "failed to complete broker process startup: {error}"
            ))),
            abnormal: true,
        };
    }
    let context = AssociationContext {
        association: &association,
        failure_coordinator: &failure_coordinator,
        launcher: launcher.as_ref(),
    };

    std::thread::scope(|scope| {
        let publisher = std::thread::Builder::new()
            .name("litebox-broker-notifier".to_owned())
            .spawn_scoped(scope, || {
                let _panicking = PublisherPanicGuard {
                    failure_coordinator: &failure_coordinator,
                };
                // The association thread owns association termination. A
                // failing notification transport must fail the association
                // before returning an error, so the association thread
                // observes and reports the same failure. Reporting here would
                // instead turn a clean peer close into an error when its
                // transport teardown releases a blocked notification send.
                let _ = readiness.run(&mut notification_channel);
            });
        let publisher = match publisher {
            Ok(publisher) => Some(publisher),
            Err(error) => {
                failure_coordinator.report(error);
                None
            }
        };

        // Publication must end on every exit, including an unwind: the scope
        // joins the publisher before it propagates a panic, and a publisher
        // still parked or still blocked on transport capacity would never
        // return, hanging teardown instead.
        let publication = ReadinessPublicationGuard {
            readiness: &readiness,
            failure_coordinator: &failure_coordinator,
        };
        if let Some(first_lane) = context.next_lane(&mut lane_source) {
            let observer = std::thread::Builder::new()
                .name("litebox-broker-lanes".to_owned())
                .spawn_scoped(scope, move || context.serve_further_lanes(lane_source));
            match observer {
                Ok(observer) => {
                    context.serve(first_lane);
                    if observer.join().is_err() {
                        failure_coordinator
                            .report_panic(IoError::other("broker call-lane observer panicked"));
                    }
                }
                Err(error) => failure_coordinator.report(error),
            }
        }
        // Ends the association if no observer did; ending it again is
        // harmless.
        association.association_ending();
        // Readiness publication lives exactly as long as the association, and
        // workers can still change readiness until they are joined. Ending it
        // here rather than leaving it to the scope orders it before the join
        // that observes a panicking publisher.
        drop(publication);
        if let Some(publisher) = publisher
            && publisher.join().is_err()
        {
            failure_coordinator.report_panic(IoError::other("broker readiness publisher panicked"));
        }
    });

    let result = match failure_coordinator.take_error() {
        Some(error) => Err(error),
        None => Ok(()),
    };
    let panicked = failure_coordinator.panicked();
    let abnormal = failure_coordinator.abnormal();
    if panicked || !finish_process {
        drop(association);
    } else {
        association.finish();
    }
    AssociationOutcome { result, abnormal }
}

/// What the threads serving an association share.
struct AssociationContext<'association, Memory: SharedMemory, Shutdown> {
    association: &'association BrokerHostAssociation<Memory>,
    failure_coordinator: &'association HostAssociationFailureCoordinator<Shutdown>,
    launcher: Option<&'association Arc<UserlandProcessLauncher>>,
}

impl<Memory: SharedMemory, Shutdown> Clone for AssociationContext<'_, Memory, Shutdown> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Memory: SharedMemory, Shutdown> Copy for AssociationContext<'_, Memory, Shutdown> {}

impl<Memory, Shutdown> AssociationContext<'_, Memory, Shutdown>
where
    Memory: SharedMemory,
    Shutdown: HostAssociationShutdown<Error = IoError>,
{
    /// Returns the next lane the runner uses, or `None` once the association
    /// has ended, reporting why it ended abnormally.
    fn next_lane<LaneSource: HostCallLaneSource<Error = IoError>>(
        self,
        lane_source: &mut LaneSource,
    ) -> Option<LaneSource::Lane> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| lane_source.next_lane())) {
            Ok(Ok(lane)) => lane,
            Ok(Err(error)) => {
                self.failure_coordinator.report(error);
                None
            }
            Err(_) => {
                self.failure_coordinator
                    .report_panic(IoError::other("broker call-lane source panicked"));
                None
            }
        }
    }

    /// Starts a worker for each further lane the runner uses until the
    /// association ends, then ends the association and joins the workers.
    fn serve_further_lanes<LaneSource>(self, mut lane_source: LaneSource)
    where
        LaneSource: HostCallLaneSource<Error = IoError>,
        LaneSource::Lane: Send,
        Self: Send,
    {
        std::thread::scope(|scope| {
            // Dropped before the scope joins the workers, including on an
            // unwind, so the join never waits on a worker blocked in a request.
            let _ending = AssociationEndingGuard {
                association: self.association,
            };
            let mut workers = 0;
            while let Some(lane) = self.next_lane(&mut lane_source) {
                workers += 1;
                let started = std::thread::Builder::new()
                    .name(format!("litebox-broker-worker-{workers}"))
                    .spawn_scoped(scope, move || self.serve(lane));
                if let Err(error) = started {
                    self.failure_coordinator.report(error);
                    break;
                }
            }
        });
    }

    /// Serves one lane's requests until the association ends.
    fn serve<Lane: HostCallLane<Error = IoError>>(self, mut lane: Lane) {
        let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            while !self.failure_coordinator.failed() {
                let request = match lane.recv_request() {
                    Ok(HostReceive::Message(request)) => request,
                    Ok(HostReceive::PeerClosed) => return,
                    Ok(HostReceive::ProtocolViolation) => {
                        self.failure_coordinator.report(IoError::new(
                            ErrorKind::InvalidData,
                            "runner sent a request for the wrong protocol phase",
                        ));
                        return;
                    }
                    Err(error) => {
                        self.failure_coordinator.report(error);
                        return;
                    }
                };
                match self.association.execute_request_with(
                    request,
                    |process, operation, shared_buffers| {
                        self.launcher.and_then(|launcher| {
                            handle_process_operation(launcher, process, operation, shared_buffers)
                        })
                    },
                    |response| lane.send_response(response),
                ) {
                    Ok(()) | Err(BrokerHostError::AssociationFailed) => {}
                    Err(error) => self.failure_coordinator.report(map_host_error(error)),
                }
            }
        }));
        if served.is_err() {
            self.failure_coordinator
                .report_panic(IoError::other("broker request worker panicked"));
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::io::{Error as IoError, ErrorKind, Result as IoResult};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::mpsc::{Receiver, sync_channel};
    use std::time::{Duration, Instant};

    use litebox_broker_core::test_support::TestBrokerCoreBuilder;
    use litebox_broker_core::{ObjectRights, PolicyEngine};
    use litebox_broker_host::setup_connection;
    use litebox_broker_protocol::BROKER_PROTOCOL_VERSION;
    use litebox_broker_protocol::message::{BrokerHandshakeResponse, BrokerNotification};
    use litebox_broker_protocol::shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE};
    use litebox_broker_transport::channel::{
        HostNotificationChannel, HostSetupChannel, LocalSetupChannel,
    };
    use litebox_broker_transport::control_ring::{ControlRing, ControlRingLayout};
    use litebox_broker_transport::shared_memory::SharedBufferPool;
    use litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory;
    use litebox_broker_transport_linux_userland::unix_socket::{
        UnixControlRingHostCallLaneSource, UnixControlRingHostNotificationChannel,
        UnixControlRingHostShutdown, UnixControlRingLocalCallChannel,
        UnixControlRingLocalNotificationChannel, UnixControlRingLocalShutdown,
        UnixStreamHostSetupChannel, UnixStreamLocalSetupChannel,
    };

    use super::*;
    use crate::random;

    /// Setup deadline used only to bound test I/O; unrelated to any deadline
    /// the userland binary chooses for real runner processes.
    const TEST_SETUP_TIMEOUT: Duration = Duration::from_secs(5);

    const LAYOUT: ControlRingLayout = ControlRingLayout::MULTI_LANE;

    #[test]
    fn host_errors_preserve_io_categories() {
        for (error, expected) in [
            (ErrorCode::UnsupportedVersion, ErrorKind::InvalidData),
            (ErrorCode::MalformedRequest, ErrorKind::InvalidData),
            (ErrorCode::ProtocolState, ErrorKind::InvalidData),
            (ErrorCode::UnsupportedOperation, ErrorKind::Unsupported),
            (ErrorCode::Internal, ErrorKind::Other),
            (ErrorCode::PolicyDenied, ErrorKind::PermissionDenied),
            (ErrorCode::InvalidRights, ErrorKind::PermissionDenied),
            (ErrorCode::UnknownObject, ErrorKind::NotFound),
            (ErrorCode::ResourceExhausted, ErrorKind::Other),
            (ErrorCode::WouldBlock, ErrorKind::WouldBlock),
            (ErrorCode::PeerClosed, ErrorKind::BrokenPipe),
            (ErrorCode::OutOfMemory, ErrorKind::OutOfMemory),
        ] {
            assert_eq!(
                map_host_error(BrokerHostError::<IoError>::Broker(error)).kind(),
                expected
            );
        }

        let channel_error = map_host_error(BrokerHostError::Channel(IoError::new(
            ErrorKind::TimedOut,
            "channel timed out",
        )));
        assert_eq!(channel_error.kind(), ErrorKind::TimedOut);
        assert_eq!(channel_error.to_string(), "channel timed out");
        assert_eq!(
            map_host_error(BrokerHostError::<IoError>::SharedBufferLayoutMismatch).kind(),
            ErrorKind::InvalidData
        );
    }

    /// One live host association: the endpoints teardown acts on, and the rest
    /// held open so the association stays up for the duration of a test.
    struct LiveAssociation {
        lane_source: UnixControlRingHostCallLaneSource,
        notifications: UnixControlRingHostNotificationChannel,
        shutdown: UnixControlRingHostShutdown,
        _local: (
            UnixControlRingLocalCallChannel,
            UnixControlRingLocalNotificationChannel,
            UnixControlRingLocalShutdown,
        ),
    }

    fn live_association() -> LiveAssociation {
        let (peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut local_setup = UnixStreamLocalSetupChannel::from_connected(peer_stream);
        let mut control_channel = UnixStreamHostSetupChannel::from_accepted(host_stream);
        control_channel
            .send_handshake_response(&BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
                process_id: litebox_broker_protocol::ProcessId(1),
                initial_thread_id: litebox_broker_protocol::ThreadId(2),
                startup: None,
            })
            .unwrap();
        local_setup.recv_handshake_response().unwrap().unwrap();
        let local_memory = MemfdSharedMemory::create_control_ring(LAYOUT).unwrap();
        let host_memory = MemfdSharedMemory::control_ring_from_received_fd(
            local_memory.as_fd().try_clone_to_owned().unwrap(),
            LAYOUT,
        )
        .unwrap();
        let local_ring = ControlRing::new(local_memory, LAYOUT).unwrap();
        let host_ring = ControlRing::new(host_memory, LAYOUT).unwrap();
        let local_activation =
            std::thread::spawn(move || local_setup.into_active(local_ring, || {}).unwrap());
        let (lane_source, notifications, shutdown) =
            control_channel.into_active(host_ring).unwrap();
        LiveAssociation {
            lane_source,
            notifications,
            shutdown,
            _local: local_activation.join().unwrap(),
        }
    }

    /// Waits for a call lane beyond the always-demanded first one, as the lane
    /// observer does.
    fn wait_for_more_lanes(
        mut lane_source: UnixControlRingHostCallLaneSource,
    ) -> Receiver<IoResult<bool>> {
        let first = lane_source.next_lane().unwrap().unwrap();
        let (result_sender, result_receiver) = sync_channel(1);
        std::thread::spawn(move || {
            let _first = first;
            result_sender
                .send(lane_source.next_lane().map(|lane| lane.is_some()))
                .unwrap();
        });
        result_receiver
    }

    /// A notification channel that accepts every send and keeps nothing.
    struct DiscardingChannel;

    impl HostNotificationChannel for DiscardingChannel {
        type Error = IoError;

        fn send_notification(&mut self, _notification: &BrokerNotification) -> IoResult<()> {
            Ok(())
        }
    }

    /// Negotiates the local half of an association served by [`spawn_dispatch`].
    fn negotiate_local(
        stream: UnixStream,
    ) -> (
        litebox_broker_local::BrokerLocal<UnixControlRingLocalCallChannel>,
        UnixControlRingLocalNotificationChannel,
        UnixControlRingLocalShutdown,
    ) {
        let (local, _startup, (notifications, shutdown)) =
            litebox_broker_local::BrokerLocal::negotiate(
                UnixStreamLocalSetupChannel::from_connected(stream),
                |mut setup| {
                    let shared_memory = setup.receive_memfd(SHARED_BUFFER_POOL_SIZE, None)?;
                    let control_memory = setup.receive_control_ring(LAYOUT, None)?;
                    let control_ring =
                        ControlRing::new(control_memory, LAYOUT).map_err(|error| {
                            IoError::new(
                                ErrorKind::InvalidData,
                                format!("invalid test control ring: {error:?}"),
                            )
                        })?;
                    let (call_channel, notifications, shutdown) =
                        setup.into_active(control_ring, || {})?;
                    Ok((
                        call_channel,
                        Arc::new(shared_memory),
                        (notifications, shutdown),
                    ))
                },
            )
            .unwrap();
        (local, notifications, shutdown)
    }

    /// One association served by `dispatch_requests` exactly as production serves it.
    ///
    /// The guard tests below cover what the teardown guards do; only this covers
    /// that `dispatch_requests` installs them and starts a publisher at all.
    /// Dispatch starts only once the local half has finished negotiating, so a
    /// publisher that fails immediately cannot race activation.
    fn spawn_dispatch(
        readiness: Arc<ReadinessPublisherRuntime>,
    ) -> (
        litebox_broker_local::BrokerLocal<UnixControlRingLocalCallChannel>,
        UnixControlRingLocalNotificationChannel,
        UnixControlRingLocalShutdown,
        Receiver<IoResult<()>>,
        std::thread::JoinHandle<()>,
    ) {
        let (local_stream, host_stream) = UnixStream::pair().unwrap();
        let (outcome_sender, outcome) = sync_channel(1);
        let (start, started) = sync_channel(1);
        let host = std::thread::spawn(move || {
            let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_host_guaranteed_rights(
                ObjectRights::all(),
            ))
            .with_random_provider(Arc::new(random::UserlandRandomProvider))
            .build()
            .unwrap();
            let shared_memory = MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE).unwrap();
            let shared_buffers =
                Arc::new(SharedBufferPool::new(shared_memory, SHARED_BUFFER_LAYOUT).unwrap());
            let control_memory = MemfdSharedMemory::create_control_ring(LAYOUT).unwrap();
            let control_ring = ControlRing::new(control_memory, LAYOUT).unwrap();
            let mut control = UnixStreamHostSetupChannel::from_host_guaranteed(
                host_stream,
                Instant::now() + TEST_SETUP_TIMEOUT,
            );
            let association = setup_connection(
                &broker,
                None,
                None,
                &mut control,
                Arc::clone(&shared_buffers),
                readiness.clone(),
                |_| false,
                |channel| {
                    channel.send_memfd(shared_buffers.memory(), None)?;
                    channel.send_memfd(control_ring.memory(), None)
                },
            )
            .unwrap()
            .unwrap();
            let (lane_source, notifications, shutdown) = control.into_active(control_ring).unwrap();
            started.recv().unwrap();
            outcome_sender
                .send(
                    dispatch_requests(
                        association,
                        readiness,
                        lane_source,
                        notifications,
                        shutdown,
                        None,
                        true,
                    )
                    .result,
                )
                .unwrap();
        });
        let (local, notifications, shutdown) = negotiate_local(local_stream);
        start.send(()).unwrap();
        (local, notifications, shutdown, outcome, host)
    }

    #[test]
    fn publication_guard_ends_a_parked_publisher() {
        let association = live_association();
        let failure_coordinator = HostAssociationFailureCoordinator::new(association.shutdown);
        let readiness = Arc::new(ReadinessPublisherRuntime::new());
        let publishing = Arc::clone(&readiness);
        let (finished, finish) = sync_channel(1);
        let publisher = std::thread::spawn(move || {
            finished
                .send(publishing.run(&mut DiscardingChannel))
                .unwrap();
        });

        // The publisher parks on an empty queue, so only closing publication ends
        // it. An unwind past the explicit close leaves the guard as the only thing
        // that can, and the scope joins the publisher before it propagates the
        // panic.
        std::thread::sleep(Duration::from_millis(20));
        drop(ReadinessPublicationGuard {
            readiness: &readiness,
            failure_coordinator: &failure_coordinator,
        });

        finish
            .recv_timeout(TEST_SETUP_TIMEOUT)
            .expect("dropping the guard must end the parked publisher")
            .unwrap();
        publisher.join().unwrap();
    }

    #[test]
    fn publication_guard_ends_a_capacity_blocked_publisher() {
        use litebox_broker_protocol::ObjectHandle;
        use litebox_broker_protocol::readiness::ReadinessFlags;
        use litebox_broker_transport::control_ring::CONTROL_RING_NOTIFICATION_SLOT_COUNT;

        let association = live_association();
        let mut notifications = association.notifications;
        let failure_coordinator = HostAssociationFailureCoordinator::new(association.shutdown);
        let readiness = Arc::new(ReadinessPublisherRuntime::new());

        // The local endpoint never drains, so the ring fills and the publisher
        // ends up blocked on capacity rather than parked for work. Closing
        // publication cannot reach it there, and an unwind reaches the scope join
        // before anything else ends the transport.
        for handle in 0..CONTROL_RING_NOTIFICATION_SLOT_COUNT * 3 {
            readiness
                .publish(ObjectHandle(handle), ReadinessFlags::READ)
                .unwrap();
        }
        let publishing = Arc::clone(&readiness);
        let (finished, finish) = sync_channel(1);
        let publisher = std::thread::spawn(move || {
            finished.send(publishing.run(&mut notifications)).unwrap();
        });
        std::thread::sleep(Duration::from_millis(20));

        drop(ReadinessPublicationGuard {
            readiness: &readiness,
            failure_coordinator: &failure_coordinator,
        });

        let outcome = finish
            .recv_timeout(TEST_SETUP_TIMEOUT)
            .expect("dropping the guard must end a publisher blocked on capacity");
        publisher.join().unwrap();
        assert_eq!(
            outcome
                .expect_err("ending the transport must fail the blocked send")
                .kind(),
            ErrorKind::ConnectionAborted
        );
        assert!(
            failure_coordinator.take_error().is_none(),
            "ending the transport during teardown must not report a failure"
        );
    }

    #[test]
    fn a_panicking_publisher_ends_the_wait_for_lanes() {
        let association = live_association();
        let failure_coordinator =
            Arc::new(HostAssociationFailureCoordinator::new(association.shutdown));
        let result_receiver = wait_for_more_lanes(association.lane_source);

        // The peer sends nothing and never closes, so the wait ends only if the
        // publisher's unwind fails the association.
        let publisher_failure_coordinator = Arc::clone(&failure_coordinator);
        let publisher = std::thread::spawn(move || {
            let _panicking = PublisherPanicGuard {
                failure_coordinator: &publisher_failure_coordinator,
            };
            panic!("readiness publication panicked");
        });

        let wait_result = result_receiver
            .recv_timeout(TEST_SETUP_TIMEOUT)
            .expect("a panicking publisher must end the wait for lanes");
        assert!(matches!(wait_result, Ok(false) | Err(_)));
        assert!(publisher.join().is_err());
        assert!(failure_coordinator.panicked());
        assert!(failure_coordinator.take_error().is_some());
    }

    #[test]
    fn first_failure_is_preserved_and_ends_the_wait_for_lanes() {
        let association = live_association();
        let failure_coordinator = HostAssociationFailureCoordinator::new(association.shutdown);
        let result_receiver = wait_for_more_lanes(association.lane_source);

        failure_coordinator.report(IoError::new(ErrorKind::TimedOut, "first failure"));
        failure_coordinator.report(IoError::other("second failure"));
        let wait_result = result_receiver.recv_timeout(TEST_SETUP_TIMEOUT);

        assert!(matches!(wait_result.unwrap(), Ok(false) | Err(_)));
        let error = failure_coordinator.take_error().unwrap();
        assert!(!failure_coordinator.panicked());
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "first failure");
    }

    #[test]
    fn later_protocol_failure_upgrades_abnormal_disposition() {
        let association = live_association();
        let failure_coordinator = HostAssociationFailureCoordinator::new(association.shutdown);

        failure_coordinator.report(IoError::new(
            ErrorKind::ConnectionAborted,
            "process shutdown",
        ));
        failure_coordinator.report(IoError::new(ErrorKind::InvalidData, "protocol failure"));

        assert!(failure_coordinator.abnormal());
        assert_eq!(
            failure_coordinator.take_error().unwrap().kind(),
            ErrorKind::ConnectionAborted
        );
    }

    #[test]
    fn dispatching_requests_publishes_readiness_until_the_association_ends() {
        use litebox_broker_protocol::ObjectHandle;
        use litebox_broker_protocol::message::ReadinessNotification;
        use litebox_broker_protocol::readiness::ReadinessFlags;
        use litebox_broker_transport::channel::LocalNotificationChannel;

        const HANDLE: ObjectHandle = ObjectHandle(11);
        let expected = ReadinessFlags::READ | ReadinessFlags::WRITE;
        let readiness = Arc::new(ReadinessPublisherRuntime::new());
        let (local, mut notifications, _shutdown, outcome, host) =
            spawn_dispatch(Arc::clone(&readiness));

        readiness.publish(HANDLE, expected).unwrap();

        // The receive has no deadline of its own, so a publisher that dispatch
        // never started has to fail the test rather than hang it.
        let (notified, notifications_seen) = sync_channel(1);
        let receiver = std::thread::spawn(move || {
            let notification = notifications.recv_notification().unwrap();
            notified.send(notification).unwrap();
            notifications
        });
        let notification = notifications_seen
            .recv_timeout(TEST_SETUP_TIMEOUT)
            .expect("dispatch must publish readiness recorded in its runtime");
        assert_eq!(
            notification,
            Some(BrokerNotification::Readiness(ReadinessNotification {
                handle: HANDLE,
                readiness: expected,
            }))
        );
        let notifications = receiver.join().unwrap();

        // A publisher parked for work outlives a clean local close unless dispatch
        // ends publication, so this deadline covers that too.
        drop(local);
        drop(notifications);
        outcome
            .recv_timeout(TEST_SETUP_TIMEOUT)
            .expect("a clean local close must end dispatch")
            .unwrap();
        host.join().unwrap();
    }

    #[test]
    fn dispatching_requests_serves_more_concurrent_calls_than_lanes() {
        use litebox_broker_local::BrokerLocalError;

        let readiness = Arc::new(ReadinessPublisherRuntime::new());
        let (local, _notifications, _shutdown, outcome, host) = spawn_dispatch(readiness);

        // Callers beyond the lane count wait for a lane, and every call is
        // answered on the lane it was made on.
        std::thread::scope(|scope| {
            for _ in 0..2 * LAYOUT.lane_count() {
                scope.spawn(|| {
                    for _ in 0..50 {
                        assert!(matches!(
                            local.check_readiness(litebox_broker_protocol::ObjectHandle(u64::MAX)),
                            Err(BrokerLocalError::Broker(ErrorCode::UnknownObject))
                        ));
                    }
                });
            }
        });

        // Every started worker is waiting on its lane, and a clean local close
        // must end them all along with dispatch.
        drop(local);
        outcome
            .recv_timeout(TEST_SETUP_TIMEOUT)
            .expect("a clean local close must end dispatch")
            .unwrap();
        host.join().unwrap();
    }

    #[test]
    fn dispatching_requests_fails_when_its_readiness_publisher_panics() {
        // Publication is one-shot, so a runtime that has already run makes the
        // publisher thread panic as soon as dispatch starts it.
        let readiness = Arc::new(ReadinessPublisherRuntime::new());
        readiness.close();
        readiness.run(&mut DiscardingChannel).unwrap();

        // The local half stays connected and idle, so nothing but the panic can
        // release the association thread that owns association termination.
        let (local, _notifications, _shutdown, outcome, host) =
            spawn_dispatch(Arc::clone(&readiness));
        let error = outcome
            .recv_timeout(TEST_SETUP_TIMEOUT)
            .expect("a panicking publisher must end dispatch")
            .expect_err("a panicking publisher must fail the association");
        assert_eq!(error.to_string(), "broker readiness publisher panicked");
        drop(local);
        host.join().unwrap();
    }
}
