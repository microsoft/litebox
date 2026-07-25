// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::ffi::OsString;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use clap::Parser;
use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine};
use litebox_broker_host::{BrokerHostAssociation, ConnectionTermination, setup_connection};
use litebox_broker_protocol::channel::HostReceive;
use litebox_broker_protocol::message::BrokerRequest;
use litebox_broker_protocol::shared_memory::{
    SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE, SharedBufferPool, SharedMemory,
};
use litebox_broker_transport::control_ring::{CONTROL_RING_MEMORY_SIZE, ControlRing};
use litebox_broker_transport::shared_memory::MemfdSharedMemory;
use litebox_broker_transport::unix_socket::{
    UnixControlRingHostNotificationChannel, UnixControlRingHostRequestSource,
    UnixControlRingHostResponseSink, UnixControlRingHostShutdown, UnixStreamHostSetupChannel,
    validate_peer_process,
};
use litebox_broker_userland::readiness::ReadinessPublisherRuntime;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);
const REQUEST_QUEUE_CAPACITY: usize = 64;
const WORKER_COUNT: usize = 8;

#[derive(Parser, Debug)]
struct CliArgs {
    /// Local runner executable to launch.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::ExecutablePath)]
    runner: PathBuf,
    /// Arguments to pass to the local runner.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, value_hint = clap::ValueHint::CommandWithArguments)]
    runner_arguments: Vec<OsString>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = CliArgs::parse();
    let socket_dir = tempfile::Builder::new()
        .prefix("litebox-broker-userland-")
        .tempdir()?;
    let control_socket_path = socket_dir.path().join("broker.sock");
    let control_listener = UnixListener::bind(&control_socket_path)?;
    control_listener.set_nonblocking(true)?;
    let broker = BrokerCore::new(PolicyEngine::with_host_guaranteed_rights(
        ObjectRights::all(),
    ))?;

    let mut runner_command = Command::new(&args.runner);
    runner_command
        .arg("--unstable")
        .arg("--broker-control-socket")
        .arg(&control_socket_path)
        .args(&args.runner_arguments);
    let mut runner = runner_command.spawn()?;
    let runner_process_id = runner.id();

    let association_result =
        serve_runner(&broker, &control_listener, &mut runner, runner_process_id);
    if association_result.is_err() {
        let _ = runner.kill();
    }
    let runner_status = runner.wait()?;
    association_result?;
    if !runner_status.success() {
        return Err(IoError::other(format!("runner exited with {runner_status}")).into());
    }
    Ok(())
}

fn serve_runner(
    broker: &BrokerCore,
    control_listener: &UnixListener,
    runner: &mut Child,
    runner_process_id: u32,
) -> Result<(), Box<dyn Error>> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = accept_runner_stream(
        control_listener,
        runner,
        runner_process_id,
        setup_deadline,
        "control",
    )?;
    let shared_memory = MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE)?;
    let shared_buffers = SharedBufferPool::new(shared_memory, SHARED_BUFFER_LAYOUT)?;
    let control_memory = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE)?;
    let control_ring = ControlRing::new(control_memory)
        .map_err(|error| IoError::other(format!("failed to create control ring: {error:?}")))?;
    let mut control_channel =
        UnixStreamHostSetupChannel::from_host_guaranteed(control_stream, setup_deadline);
    let association =
        match setup_connection(broker, &mut control_channel, &shared_buffers, |channel| {
            channel.send_memfd(shared_buffers.memory(), Some(setup_deadline))?;
            channel.send_memfd(control_ring.memory(), Some(setup_deadline))?;
            Ok(())
        })? {
            Ok(association) => association,
            Err(ConnectionTermination::PeerClosed) => {
                return Err(IoError::new(
                    ErrorKind::UnexpectedEof,
                    "runner closed before completing broker setup",
                )
                .into());
            }
            Err(ConnectionTermination::ProtocolViolation) => {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "runner violated the broker protocol during setup",
                )
                .into());
            }
            Err(_) => {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "runner ended broker setup unexpectedly",
                )
                .into());
            }
        };
    let (request_source, response_sink, notification_channel, shutdown) =
        control_channel.into_active(control_ring)?;
    dispatch_requests(
        association,
        request_source,
        response_sink,
        notification_channel,
        shutdown,
    )?;
    Ok(())
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
struct ReadinessPublicationGuard<'association> {
    readiness: &'association ReadinessPublisherRuntime,
    failure_coordinator: &'association HostAssociationFailureCoordinator,
}

impl Drop for ReadinessPublicationGuard<'_> {
    fn drop(&mut self) {
        self.readiness.close();
        self.failure_coordinator.shutdown();
    }
}

fn dispatch_requests<Memory: SharedMemory>(
    association: BrokerHostAssociation<'_, Memory>,
    mut request_source: UnixControlRingHostRequestSource,
    response_sink: UnixControlRingHostResponseSink,
    mut notification_channel: UnixControlRingHostNotificationChannel,
    shutdown: UnixControlRingHostShutdown,
) -> IoResult<()> {
    let association = Arc::new(association);
    let failure_coordinator = Arc::new(HostAssociationFailureCoordinator::new(shutdown));
    let readiness = Arc::new(ReadinessPublisherRuntime::new());
    let (request_sender, request_receiver) = sync_channel(REQUEST_QUEUE_CAPACITY);
    let request_receiver = Arc::new(Mutex::new(request_receiver));

    std::thread::scope(|scope| {
        let publisher_readiness = Arc::clone(&readiness);
        let publisher = std::thread::Builder::new()
            .name("litebox-broker-notifier".to_owned())
            .spawn_scoped(scope, move || {
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
        // still parked or still blocked on ring capacity would never return,
        // hanging teardown instead.
        let publication = ReadinessPublicationGuard {
            readiness: &readiness,
            failure_coordinator: &failure_coordinator,
        };

        let mut workers = Vec::with_capacity(WORKER_COUNT);
        for worker_id in 0..WORKER_COUNT {
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

fn read_requests(
    request_source: &mut UnixControlRingHostRequestSource,
    request_sender: SyncSender<BrokerRequest>,
    failure_coordinator: &HostAssociationFailureCoordinator,
) {
    loop {
        if failure_coordinator.failed() {
            break;
        }
        match request_source.recv_request() {
            Ok(HostReceive::Message(request)) => {
                if request_sender.send(request).is_err() {
                    failure_coordinator.report(IoError::new(
                        ErrorKind::BrokenPipe,
                        "broker request workers stopped",
                    ));
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

fn run_worker<Memory: SharedMemory>(
    association: &BrokerHostAssociation<'_, Memory>,
    request_receiver: &Mutex<Receiver<BrokerRequest>>,
    response_sink: &UnixControlRingHostResponseSink,
    failure_coordinator: &HostAssociationFailureCoordinator,
) {
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
            Ok(Err(error)) => failure_coordinator.report(IoError::other(error)),
            Err(_) => {
                failure_coordinator.report(IoError::other("broker request worker panicked"));
            }
        }
    }
}

struct HostAssociationFailureCoordinator {
    failed: AtomicBool,
    error: Mutex<Option<IoError>>,
    shutdown: UnixControlRingHostShutdown,
}

impl HostAssociationFailureCoordinator {
    const fn new(shutdown: UnixControlRingHostShutdown) -> Self {
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
    /// Teardown uses this to release endpoints blocked on the control ring
    /// without turning a shutdown that reported nothing into a reported error.
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

fn accept_runner_stream(
    listener: &UnixListener,
    runner: &mut Child,
    runner_process_id: u32,
    deadline: Instant,
    channel_name: &'static str,
) -> IoResult<UnixStream> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(IoError::new(
                ErrorKind::TimedOut,
                format!("timed out waiting for runner {channel_name} channel"),
            ));
        }
        if let Some(status) = runner.try_wait()? {
            return Err(IoError::new(
                ErrorKind::BrokenPipe,
                format!("runner exited with {status} before connecting its {channel_name} channel"),
            ));
        }

        match listener.accept() {
            Ok((stream, _)) => {
                validate_peer_process(&stream, runner_process_id)?;
                return Ok(stream);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        std::thread::sleep(remaining.min(ACCEPT_RETRY_DELAY));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_protocol::BROKER_PROTOCOL_VERSION;
    use litebox_broker_protocol::channel::{HostSetupChannel, LocalSetupChannel};
    use litebox_broker_protocol::message::BrokerHandshakeResponse;
    use litebox_broker_transport::unix_socket::{
        UnixControlRingLocalCallChannel, UnixControlRingLocalNotificationChannel,
        UnixControlRingLocalShutdown, UnixStreamLocalSetupChannel,
    };
    use std::os::fd::AsFd;

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
        let local_memory = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
        let host_memory = MemfdSharedMemory::from_received_fd(
            local_memory.as_fd().try_clone_to_owned().unwrap(),
            CONTROL_RING_MEMORY_SIZE,
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

    #[test]
    fn dropping_the_publication_guard_ends_a_parked_publisher() {
        use litebox_broker_protocol::channel::HostNotificationChannel;
        use litebox_broker_protocol::message::BrokerNotification;

        struct DiscardingChannel;

        impl HostNotificationChannel for DiscardingChannel {
            type Error = IoError;

            fn send_notification(&mut self, _notification: &BrokerNotification) -> IoResult<()> {
                Ok(())
            }
        }

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

        // The publisher parks on an empty queue, so only closing publication
        // ends it. An unwind past the explicit close leaves the guard as the
        // only thing that can, and the scope joins the publisher before it
        // propagates the panic.
        std::thread::sleep(Duration::from_millis(20));
        drop(ReadinessPublicationGuard {
            readiness: &readiness,
            failure_coordinator: &failure_coordinator,
        });

        finish
            .recv_timeout(SETUP_TIMEOUT)
            .expect("dropping the guard must end the parked publisher")
            .unwrap();
        publisher.join().unwrap();
    }

    #[test]
    fn dropping_the_publication_guard_ends_a_publisher_blocked_on_ring_capacity() {
        use litebox_broker_protocol::ObjectHandle;
        use litebox_broker_protocol::readiness::ReadinessFlags;
        use litebox_broker_transport::control_ring::CONTROL_RING_NOTIFICATION_SLOT_COUNT;

        let association = live_association();
        let mut notifications = association.notifications;
        let failure_coordinator = HostAssociationFailureCoordinator::new(association.shutdown);
        let readiness = Arc::new(ReadinessPublisherRuntime::new());

        // The local endpoint never drains, so the ring fills and the publisher
        // ends up blocked on capacity rather than parked for work. Closing
        // publication cannot reach it there, and an unwind reaches the scope
        // join before anything else ends the transport.
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
            .recv_timeout(SETUP_TIMEOUT)
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
    fn first_failure_is_preserved_and_unblocks_request_reading() {
        let association = live_association();
        let mut request_source = association.request_source;
        let failure_coordinator = HostAssociationFailureCoordinator::new(association.shutdown);
        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            result_sender.send(request_source.recv_request()).unwrap();
        });

        failure_coordinator.report(IoError::new(ErrorKind::TimedOut, "first failure"));
        failure_coordinator.report(IoError::other("second failure"));
        let receive_result = result_receiver.recv_timeout(Duration::from_secs(1));
        reader.join().unwrap();

        assert!(matches!(
            receive_result.unwrap(),
            Ok(HostReceive::PeerClosed) | Err(_)
        ));
        let error = failure_coordinator.take_error().unwrap();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "first failure");
    }
}
