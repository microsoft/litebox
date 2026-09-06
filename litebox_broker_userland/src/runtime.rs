// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Generic broker association runtime.
//!
//! This module owns association setup, request dispatch, readiness
//! publication, cancellation, and teardown for one broker association.
//! It is transport-neutral: it depends only on the [`HostSetupChannel`],
//! [`HostRequestSource`], [`HostResponseSink`], [`HostNotificationChannel`],
//! and [`HostAssociationShutdown`] contracts from
//! `litebox_broker_transport::channel`, so a deployment supplies the
//! transport-specific setup channel, activation, and shared-memory plumbing
//! and this runtime serves the association the same way regardless of
//! transport.
//!
//! Concurrency and worker sizing are deliberately not part of the public
//! surface: [`serve_association`] is the only entry point, and it owns how
//! many workers dispatch requests and how deeply the request queue may buffer.

use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use litebox_broker_core::BrokerCore;
use litebox_broker_host::{
    BrokerHostAssociation, BrokerHostError, ConnectionTermination, setup_connection,
};
use litebox_broker_protocol::message::BrokerRequest;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_LAYOUT;
use litebox_broker_transport::channel::{
    HostAssociationShutdown, HostNotificationChannel, HostReceive, HostRequestSource,
    HostResponseSink, HostSetupChannel,
};
use litebox_broker_transport::control_ring::ControlRing;
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedBufferPool, SharedMemory};

use crate::readiness::ReadinessPublisherRuntime;

const REQUEST_QUEUE_CAPACITY: usize = 64;
const REQUEST_QUEUE_RETRY_DELAY: Duration = Duration::from_millis(1);
const REQUEST_QUEUE_STALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Serves one broker association from setup through teardown.
///
/// `control_channel` must already be configured with whatever deadline and
/// peer authentication its transport requires; this function only negotiates
/// the broker protocol and control-ring setup over it. `create_shared_memory`
/// and `create_control_memory` allocate the transport's shared-memory
/// resources, `send_shared_memory` transfers them to the peer, and `activate`
/// consumes the negotiated setup channel and control ring into the transport's
/// active request, response, notification, and shutdown endpoints.
///
/// Returns once the association ends, whether by a clean peer close or a
/// failure. Layout mismatches and broker setup failures are mapped to a
/// precise [`std::io::Error`] rather than left as an opaque boxed error.
pub fn serve_association<
    Memory,
    SetupChannel,
    RequestSource,
    ResponseSink,
    NotificationChannel,
    Shutdown,
>(
    broker: &BrokerCore,
    mut control_channel: SetupChannel,
    create_shared_memory: impl FnOnce() -> IoResult<Memory>,
    create_control_memory: impl FnOnce() -> IoResult<Memory>,
    send_shared_memory: impl FnOnce(&mut SetupChannel, &Memory, &Memory) -> IoResult<()>,
    activate: impl FnOnce(
        SetupChannel,
        ControlRing<Memory>,
    ) -> IoResult<(RequestSource, ResponseSink, NotificationChannel, Shutdown)>,
) -> IoResult<()>
where
    Memory: ControlRingMemory,
    SetupChannel: HostSetupChannel<Error = IoError>,
    RequestSource: HostRequestSource<Error = IoError>,
    ResponseSink: HostResponseSink<Error = IoError> + Clone + Send,
    NotificationChannel: HostNotificationChannel<Error = IoError> + Send,
    Shutdown: HostAssociationShutdown<Error = IoError> + Send + Sync,
{
    let shared_memory = create_shared_memory()?;
    let shared_buffers = SharedBufferPool::new(shared_memory, SHARED_BUFFER_LAYOUT)
        .map_err(|error| IoError::new(ErrorKind::InvalidData, error.to_string()))?;
    let control_memory = create_control_memory()?;
    let control_ring = ControlRing::new(control_memory)
        .map_err(|error| IoError::other(format!("failed to create control ring: {error:?}")))?;
    let readiness = Arc::new(ReadinessPublisherRuntime::new());
    let association = match setup_connection(
        broker,
        &mut control_channel,
        &shared_buffers,
        readiness.clone(),
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
    let (request_source, response_sink, notification_channel, shutdown) =
        activate(control_channel, control_ring)?;
    dispatch_requests(
        association,
        readiness,
        request_source,
        response_sink,
        notification_channel,
        shutdown,
    )
}

/// Maps a host setup or request failure to a precise [`std::io::Error`].
///
/// A channel failure is already an [`std::io::Error`] and is returned as-is.
/// Every other outcome, such as a shared-buffer layout mismatch or a rejected
/// broker operation, is a deployment or protocol problem rather than a channel
/// fault, so it is reported as [`ErrorKind::InvalidData`] with the broker host
/// error's message preserved.
fn map_host_error(error: BrokerHostError<IoError>) -> IoError {
    let description = error.to_string();
    match error {
        BrokerHostError::Channel(error) => error,
        _ => IoError::new(ErrorKind::InvalidData, description),
    }
}

/// Records the first failure of an association and ends its transport.
///
/// Every thread serving an association reports through this, and the endpoints
/// they block on are released by ending the transport, so it is what the
/// teardown guards below reach for.
struct HostAssociationFailureCoordinator<Shutdown> {
    failed: AtomicBool,
    error: Mutex<Option<IoError>>,
    shutdown: Shutdown,
}

impl<Shutdown: HostAssociationShutdown<Error = IoError>>
    HostAssociationFailureCoordinator<Shutdown>
{
    const fn new(shutdown: Shutdown) -> Self {
        Self {
            failed: AtomicBool::new(false),
            error: Mutex::new(None),
            shutdown,
        }
    }

    fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn report(&self, error: IoError) {
        if self.failed.swap(true, Ordering::AcqRel) {
            return;
        }
        *self
            .error
            .lock()
            .expect("broker association failure mutex poisoned") = Some(error);
        let _ = self.shutdown.shutdown();
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
/// The request reader owns association termination but does not depend on the
/// publisher, so an unwinding publisher would otherwise leave a live
/// association with no notification source. The join that turns that panic into
/// a reported failure is reached only once the reader has returned, and a peer
/// that is waiting for a readiness change it will never be told about does not
/// return it. Failing the association here ends that wait instead.
struct PublisherPanicGuard<'association, Shutdown: HostAssociationShutdown<Error = IoError>> {
    failure_coordinator: &'association HostAssociationFailureCoordinator<Shutdown>,
}

impl<Shutdown: HostAssociationShutdown<Error = IoError>> Drop
    for PublisherPanicGuard<'_, Shutdown>
{
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.failure_coordinator
                .report(IoError::other("broker readiness publisher panicked"));
        }
    }
}

/// Ends readiness publication when an association scope ends for any reason.
///
/// The publisher is a scoped thread, so the scope joins it before propagating a
/// panic out of the association, and both states it can rest in have to end for
/// that join to complete. Closing publication returns a publisher parked for
/// work, and ending the transport returns one blocked on notification capacity
/// that a local endpoint stopped draining. The failure coordinator owns the
/// association until `dispatch_requests` returns, which is after that join, so
/// an unwind cannot leave ending the transport to dropping it.
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

/// Requests cancellation before an association scope joins its workers.
struct AssociationCancellationGuard<'association, 'memory, Memory: SharedMemory> {
    association: &'association BrokerHostAssociation<'memory, Memory>,
}

impl<Memory: SharedMemory> Drop for AssociationCancellationGuard<'_, '_, Memory> {
    fn drop(&mut self) {
        self.association.request_cancellation();
    }
}

/// Serves one association until it ends, then reports its first failure.
///
/// `readiness` is created by the caller rather than here so readiness sources
/// can record into the same runtime this publishes from. The Linux network
/// reactor is currently its production source.
fn dispatch_requests<Memory, RequestSource, ResponseSink, NotificationChannel, Shutdown>(
    association: BrokerHostAssociation<'_, Memory>,
    readiness: Arc<ReadinessPublisherRuntime>,
    mut request_source: RequestSource,
    response_sink: ResponseSink,
    mut notification_channel: NotificationChannel,
    shutdown: Shutdown,
) -> IoResult<()>
where
    Memory: SharedMemory,
    RequestSource: HostRequestSource<Error = IoError>,
    ResponseSink: HostResponseSink<Error = IoError> + Clone + Send,
    NotificationChannel: HostNotificationChannel<Error = IoError> + Send,
    Shutdown: HostAssociationShutdown<Error = IoError> + Send + Sync,
{
    let association = Arc::new(association);
    let failure_coordinator = Arc::new(HostAssociationFailureCoordinator::new(shutdown));
    let (request_sender, request_receiver) = sync_channel(REQUEST_QUEUE_CAPACITY);
    let request_receiver = Arc::new(Mutex::new(request_receiver));

    std::thread::scope(|scope| {
        let publisher_readiness = Arc::clone(&readiness);
        let publisher_failure_coordinator = Arc::clone(&failure_coordinator);
        let publisher = std::thread::Builder::new()
            .name("litebox-broker-notifier".to_owned())
            .spawn_scoped(scope, move || {
                let _panicking = PublisherPanicGuard {
                    failure_coordinator: &publisher_failure_coordinator,
                };
                // The request reader owns association termination. A failing
                // notification transport fails the association, so a reader
                // still running observes and reports the same error, and a peer
                // that closed cleanly is not a failure at all. Reporting here
                // would turn a clean shutdown into a reported error. A failure
                // that first appears once the reader has returned is dropped
                // deliberately, because the association is already over.
                let _ = publisher_readiness.run(&mut notification_channel);
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
        let cancellation = AssociationCancellationGuard {
            association: &association,
        };

        let mut workers = Vec::with_capacity(crate::WORKER_COUNT);
        for worker_id in 0..crate::WORKER_COUNT {
            let association = Arc::clone(&association);
            let request_receiver = Arc::clone(&request_receiver);
            let response_sink = response_sink.clone();
            let worker_failure_coordinator = Arc::clone(&failure_coordinator);
            match std::thread::Builder::new()
                .name(format!("litebox-broker-worker-{worker_id}"))
                .spawn_scoped(scope, move || {
                    run_worker(
                        &association,
                        &request_receiver,
                        &response_sink,
                        &worker_failure_coordinator,
                    );
                }) {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    failure_coordinator.report(error);
                    break;
                }
            }
        }

        read_requests(&mut request_source, request_sender, &failure_coordinator);
        drop(cancellation);
        for worker in workers {
            if worker.join().is_err() {
                failure_coordinator.report(IoError::other("broker request worker panicked"));
            }
        }
        // Readiness publication lives exactly as long as the association. The
        // request reader returns only once the association is over, but workers
        // keep draining already-queued requests after that, so publication must
        // outlive them or a late readiness change would be discarded. Ending it
        // here rather than leaving it to the scope orders it before the join
        // that observes a panicking publisher, and dropping the guard is what
        // ends both states the publisher can rest in without depending on the
        // reader having failed the association already.
        drop(publication);
        if let Some(publisher) = publisher
            && publisher.join().is_err()
        {
            failure_coordinator.report(IoError::other("broker readiness publisher panicked"));
        }
    });

    match failure_coordinator.take_error() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn read_requests<RequestSource, Shutdown>(
    request_source: &mut RequestSource,
    request_sender: SyncSender<BrokerRequest>,
    failure_coordinator: &HostAssociationFailureCoordinator<Shutdown>,
) where
    RequestSource: HostRequestSource<Error = IoError>,
    Shutdown: HostAssociationShutdown<Error = IoError>,
{
    loop {
        if failure_coordinator.failed() {
            break;
        }
        match request_source.recv_request() {
            Ok(HostReceive::Message(request)) => {
                if !enqueue_request(
                    &request_sender,
                    request,
                    failure_coordinator,
                    REQUEST_QUEUE_STALL_TIMEOUT,
                ) {
                    break;
                }
            }
            Ok(HostReceive::ProtocolViolation) => {
                failure_coordinator.report(IoError::new(
                    ErrorKind::InvalidData,
                    "runner sent a request for the wrong protocol phase",
                ));
                break;
            }
            Ok(HostReceive::PeerClosed) => break,
            Err(error) => {
                failure_coordinator.report(error);
                break;
            }
        }
    }
}

fn enqueue_request<Shutdown>(
    request_sender: &SyncSender<BrokerRequest>,
    mut request: BrokerRequest,
    failure_coordinator: &HostAssociationFailureCoordinator<Shutdown>,
    stall_timeout: Duration,
) -> bool
where
    Shutdown: HostAssociationShutdown<Error = IoError>,
{
    let started = Instant::now();
    loop {
        match request_sender.try_send(request) {
            Ok(()) => return true,
            Err(TrySendError::Disconnected(_)) => {
                failure_coordinator.report(IoError::new(
                    ErrorKind::BrokenPipe,
                    "broker request workers stopped",
                ));
                return false;
            }
            Err(TrySendError::Full(pending)) => {
                request = pending;
                if failure_coordinator.failed() {
                    return false;
                }
                if started.elapsed() >= stall_timeout {
                    failure_coordinator.report(IoError::new(
                        ErrorKind::TimedOut,
                        "broker request queue remained full",
                    ));
                    return false;
                }
                std::thread::sleep(REQUEST_QUEUE_RETRY_DELAY);
            }
        }
    }
}

fn run_worker<Memory, ResponseSink, Shutdown>(
    association: &BrokerHostAssociation<'_, Memory>,
    request_receiver: &Mutex<Receiver<BrokerRequest>>,
    response_sink: &ResponseSink,
    failure_coordinator: &HostAssociationFailureCoordinator<Shutdown>,
) where
    Memory: SharedMemory,
    ResponseSink: HostResponseSink<Error = IoError>,
    Shutdown: HostAssociationShutdown<Error = IoError>,
{
    loop {
        let request = request_receiver
            .lock()
            .expect("broker request receiver mutex poisoned")
            .recv();
        let Ok(request) = request else {
            break;
        };
        if failure_coordinator.failed() {
            continue;
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            association.execute_request(request, |response| response_sink.send_response(response))
        })) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failure_coordinator.report(map_host_error(error)),
            Err(_) => {
                failure_coordinator.report(IoError::other("broker request worker panicked"));
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::io::{Error as IoError, ErrorKind, Result as IoResult};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
    use std::time::{Duration, Instant};

    use litebox_broker_core::socket::UnsupportedSocketProvider;
    use litebox_broker_core::stdio::{StdioProvider, StdioProviderError, UnsupportedStdioProvider};
    use litebox_broker_core::{AssociationCancellation, BrokerCore, ObjectRights, PolicyEngine};
    use litebox_broker_host::setup_connection;
    use litebox_broker_protocol::BROKER_PROTOCOL_VERSION;
    use litebox_broker_protocol::RequestId;
    use litebox_broker_protocol::message::{
        BrokerHandshakeResponse, BrokerNotification, BrokerOperation,
    };
    use litebox_broker_protocol::shared_buffer::{
        SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE, SharedBufferDescriptor,
        SharedBufferSlotIndex,
    };
    use litebox_broker_protocol::stdio::StdioOutputStream;
    use litebox_broker_transport::channel::{
        HostNotificationChannel, HostReceive, HostSetupChannel, LocalSetupChannel,
    };
    use litebox_broker_transport::control_ring::ControlRing;
    use litebox_broker_transport::shared_memory::SharedBufferPool;
    use litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory;
    use litebox_broker_transport_linux_userland::unix_socket::{
        UnixControlRingHostNotificationChannel, UnixControlRingHostRequestSource,
        UnixControlRingHostResponseSink, UnixControlRingHostShutdown,
        UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
        UnixControlRingLocalShutdown, UnixStreamHostSetupChannel, UnixStreamLocalSetupChannel,
    };

    use super::*;
    use crate::random;

    /// Setup deadline used only to bound test I/O; unrelated to any deadline
    /// the userland binary chooses for real runner processes.
    const TEST_SETUP_TIMEOUT: Duration = Duration::from_secs(5);
    const TEST_CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(10);

    /// One live host association: the endpoints teardown acts on, and the rest
    /// held open so the association stays up for the duration of a test.
    struct LiveAssociation {
        request_source: UnixControlRingHostRequestSource,
        notifications: UnixControlRingHostNotificationChannel,
        shutdown: UnixControlRingHostShutdown,
        _response_sink: UnixControlRingHostResponseSink,
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
            })
            .unwrap();
        local_setup.recv_handshake_response().unwrap().unwrap();
        let local_memory = MemfdSharedMemory::create_control_ring().unwrap();
        let host_memory = MemfdSharedMemory::control_ring_from_received_fd(
            local_memory.as_fd().try_clone_to_owned().unwrap(),
        )
        .unwrap();
        let local_ring = ControlRing::new(local_memory).unwrap();
        let host_ring = ControlRing::new(host_memory).unwrap();
        let local_activation =
            std::thread::spawn(move || local_setup.into_active(local_ring, || {}).unwrap());
        let (request_source, response_sink, notifications, shutdown) =
            control_channel.into_active(host_ring).unwrap();
        LiveAssociation {
            request_source,
            notifications,
            shutdown,
            _response_sink: response_sink,
            _local: local_activation.join().unwrap(),
        }
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
        let (local, (notifications, shutdown)) = litebox_broker_local::BrokerLocal::negotiate(
            UnixStreamLocalSetupChannel::from_connected(stream),
            |mut setup| {
                let shared_memory = setup.receive_memfd(SHARED_BUFFER_POOL_SIZE, None)?;
                let control_memory = setup.receive_control_ring(None)?;
                let control_ring = ControlRing::new(control_memory).map_err(|error| {
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
        stdio_provider: Arc<dyn StdioProvider>,
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
            let broker = BrokerCore::new(
                PolicyEngine::with_host_guaranteed_rights(ObjectRights::all()),
                Arc::new(UnsupportedSocketProvider),
                Arc::new(random::UserlandRandomProvider),
                stdio_provider,
            )
            .unwrap();
            let shared_memory = MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE).unwrap();
            let shared_buffers =
                SharedBufferPool::new(shared_memory, SHARED_BUFFER_LAYOUT).unwrap();
            let control_memory = MemfdSharedMemory::create_control_ring().unwrap();
            let control_ring = ControlRing::new(control_memory).unwrap();
            let mut control = UnixStreamHostSetupChannel::from_host_guaranteed(
                host_stream,
                Instant::now() + TEST_SETUP_TIMEOUT,
            );
            let association = setup_connection(
                &broker,
                &mut control,
                &shared_buffers,
                readiness.clone(),
                |channel| {
                    channel.send_memfd(shared_buffers.memory(), None)?;
                    channel.send_memfd(control_ring.memory(), None)
                },
            )
            .unwrap()
            .unwrap();
            let (request_source, response_sink, notifications, shutdown) =
                control.into_active(control_ring).unwrap();
            started.recv().unwrap();
            outcome_sender
                .send(dispatch_requests(
                    association,
                    readiness,
                    request_source,
                    response_sink,
                    notifications,
                    shutdown,
                ))
                .unwrap();
        });
        let (local, notifications, shutdown) = negotiate_local(local_stream);
        start.send(()).unwrap();
        (local, notifications, shutdown, outcome, host)
    }

    struct BlockingStdioProvider {
        started: SyncSender<()>,
    }

    impl BlockingStdioProvider {
        fn block_until_cancelled(
            &self,
            cancellation: &AssociationCancellation,
        ) -> Result<usize, StdioProviderError> {
            self.started.send(()).unwrap();
            while !cancellation.is_cancelled() {
                std::thread::sleep(TEST_CANCELLATION_POLL_INTERVAL);
            }
            Err(StdioProviderError::Closed)
        }
    }

    impl StdioProvider for BlockingStdioProvider {
        fn is_terminal(
            &self,
            _stream: litebox_broker_protocol::stdio::StdioStream,
        ) -> Result<bool, StdioProviderError> {
            Err(StdioProviderError::Unsupported)
        }

        fn read(
            &self,
            cancellation: &AssociationCancellation,
            _output: &mut [u8],
        ) -> Result<usize, StdioProviderError> {
            self.block_until_cancelled(cancellation)
        }

        fn write(
            &self,
            cancellation: &AssociationCancellation,
            _stream: StdioOutputStream,
            _input: &[u8],
        ) -> Result<usize, StdioProviderError> {
            self.block_until_cancelled(cancellation)
        }
    }

    struct RecordingShutdown(Arc<AtomicBool>);

    impl HostAssociationShutdown for RecordingShutdown {
        type Error = IoError;

        fn shutdown(&self) -> IoResult<()> {
            self.0.store(true, Ordering::Release);
            Ok(())
        }
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
    fn a_panicking_publisher_ends_a_blocked_request_reader() {
        let association = live_association();
        let mut request_source = association.request_source;
        let failure_coordinator =
            Arc::new(HostAssociationFailureCoordinator::new(association.shutdown));
        let (result_sender, result_receiver) = sync_channel(1);
        let reader = std::thread::spawn(move || {
            result_sender.send(request_source.recv_request()).unwrap();
        });

        // The peer sends nothing and never closes, so the reader returns only if
        // the publisher's unwind fails the association.
        let publisher_failure_coordinator = Arc::clone(&failure_coordinator);
        let publisher = std::thread::spawn(move || {
            let _panicking = PublisherPanicGuard {
                failure_coordinator: &publisher_failure_coordinator,
            };
            panic!("readiness publication panicked");
        });

        let receive_result = result_receiver
            .recv_timeout(TEST_SETUP_TIMEOUT)
            .expect("a panicking publisher must end a blocked request reader");
        assert!(matches!(
            receive_result,
            Ok(HostReceive::PeerClosed) | Err(_)
        ));
        reader.join().unwrap();
        assert!(publisher.join().is_err());
        assert!(failure_coordinator.take_error().is_some());
    }

    #[test]
    fn first_failure_is_preserved_and_unblocks_request_reading() {
        let association = live_association();
        let mut request_source = association.request_source;
        let failure_coordinator = HostAssociationFailureCoordinator::new(association.shutdown);
        let (result_sender, result_receiver) = sync_channel(1);
        let reader = std::thread::spawn(move || {
            result_sender.send(request_source.recv_request()).unwrap();
        });

        failure_coordinator.report(IoError::new(ErrorKind::TimedOut, "first failure"));
        failure_coordinator.report(IoError::other("second failure"));
        let receive_result = result_receiver.recv_timeout(TEST_SETUP_TIMEOUT);
        reader.join().unwrap();

        assert!(matches!(
            receive_result.unwrap(),
            Ok(HostReceive::PeerClosed) | Err(_)
        ));
        let error = failure_coordinator.take_error().unwrap();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "first failure");
    }

    #[test]
    fn a_stalled_request_queue_fails_after_its_deadline() {
        let request = |request_id| BrokerRequest {
            request_id: RequestId(request_id),
            operation: BrokerOperation::FillRandom(SharedBufferDescriptor {
                slot_index: SharedBufferSlotIndex(0),
                length: 1,
            }),
        };
        let shutdown_called = Arc::new(AtomicBool::new(false));
        let failure_coordinator =
            HostAssociationFailureCoordinator::new(RecordingShutdown(Arc::clone(&shutdown_called)));
        let (request_sender, _request_receiver) = sync_channel(1);
        request_sender.send(request(1)).unwrap();

        assert!(!enqueue_request(
            &request_sender,
            request(2),
            &failure_coordinator,
            Duration::ZERO,
        ));

        assert!(shutdown_called.load(Ordering::Acquire));
        assert_eq!(
            failure_coordinator.take_error().unwrap().kind(),
            ErrorKind::TimedOut
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
            spawn_dispatch(Arc::clone(&readiness), Arc::new(UnsupportedStdioProvider));

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
    fn dispatching_requests_fails_when_its_readiness_publisher_panics() {
        // Publication is one-shot, so a runtime that has already run makes the
        // publisher thread panic as soon as dispatch starts it.
        let readiness = Arc::new(ReadinessPublisherRuntime::new());
        readiness.close();
        readiness.run(&mut DiscardingChannel).unwrap();

        // The local half stays connected and idle, so nothing but the panic can
        // release the request reader that owns association termination.
        let (local, _notifications, _shutdown, outcome, host) =
            spawn_dispatch(Arc::clone(&readiness), Arc::new(UnsupportedStdioProvider));
        let error = outcome
            .recv_timeout(TEST_SETUP_TIMEOUT)
            .expect("a panicking publisher must end dispatch")
            .expect_err("a panicking publisher must fail the association");
        assert_eq!(error.to_string(), "broker readiness publisher panicked");
        drop(local);
        host.join().unwrap();
    }

    #[test]
    fn association_teardown_cancels_a_blocked_stdin_read() {
        let readiness = Arc::new(ReadinessPublisherRuntime::new());
        let (started_sender, started_receiver) = sync_channel(1);
        let provider = Arc::new(BlockingStdioProvider {
            started: started_sender,
        });
        let (local, notifications, shutdown, outcome, host) = spawn_dispatch(readiness, provider);
        let reader = std::thread::spawn(move || {
            local.read_stdio(
                SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(0),
                    length: 1,
                },
                &mut [0],
            )
        });
        started_receiver
            .recv_timeout(TEST_SETUP_TIMEOUT)
            .expect("broker stdin provider did not start reading");

        shutdown.shutdown().unwrap();
        drop(notifications);

        let dispatch_result = outcome
            .recv_timeout(TEST_SETUP_TIMEOUT)
            .expect("association teardown did not cancel the stdin read");
        assert!(dispatch_result.is_err());
        assert!(reader.join().unwrap().is_err());
        host.join().unwrap();
    }

    #[test]
    fn association_teardown_cancels_a_blocked_stdout_write() {
        let readiness = Arc::new(ReadinessPublisherRuntime::new());
        let (started_sender, started_receiver) = sync_channel(1);
        let provider = Arc::new(BlockingStdioProvider {
            started: started_sender,
        });
        let (local, notifications, shutdown, outcome, host) = spawn_dispatch(readiness, provider);
        let writer = std::thread::spawn(move || {
            local.write_stdio(
                StdioOutputStream::Stdout,
                SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(0),
                    length: 1,
                },
                b"x",
            )
        });
        started_receiver
            .recv_timeout(TEST_SETUP_TIMEOUT)
            .expect("broker stdout provider did not start writing");

        shutdown.shutdown().unwrap();
        drop(notifications);

        let dispatch_result = outcome
            .recv_timeout(TEST_SETUP_TIMEOUT)
            .expect("association teardown did not cancel the stdout write");
        assert!(dispatch_result.is_err());
        assert!(writer.join().unwrap().is_err());
        host.join().unwrap();
    }
}
