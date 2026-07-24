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
    UnixStreamHostControlChannel, UnixStreamHostControlShutdown, UnixStreamHostNotificationChannel,
    UnixStreamHostRequestSource, UnixStreamHostResponseSink, validate_peer_process,
};

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
    let notification_socket_path = socket_dir.path().join("broker-notification.sock");
    let control_listener = UnixListener::bind(&control_socket_path)?;
    let notification_listener = UnixListener::bind(&notification_socket_path)?;
    control_listener.set_nonblocking(true)?;
    notification_listener.set_nonblocking(true)?;
    let broker = BrokerCore::new(PolicyEngine::with_host_guaranteed_rights(
        ObjectRights::all(),
    ))?;

    let mut runner_command = Command::new(&args.runner);
    runner_command
        .arg("--unstable")
        .arg("--broker-control-socket")
        .arg(&control_socket_path)
        .arg("--broker-notification-socket")
        .arg(&notification_socket_path)
        .args(&args.runner_arguments);
    let mut runner = runner_command.spawn()?;
    let runner_process_id = runner.id();

    let association_result = serve_runner(
        &broker,
        &control_listener,
        &notification_listener,
        &mut runner,
        runner_process_id,
    );
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
    notification_listener: &UnixListener,
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
    let notification_stream = accept_runner_stream(
        notification_listener,
        runner,
        runner_process_id,
        setup_deadline,
        "notification",
    )?;
    let shared_memory = MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE)?;
    let shared_buffers = SharedBufferPool::new(shared_memory, SHARED_BUFFER_LAYOUT)?;
    let control_memory = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE)?;
    let control_ring = ControlRing::new(control_memory)
        .map_err(|error| IoError::other(format!("failed to create control ring: {error:?}")))?;
    let mut control_channel =
        UnixStreamHostControlChannel::from_host_guaranteed(control_stream, setup_deadline);
    let _notification_channel =
        UnixStreamHostNotificationChannel::from_accepted(notification_stream);
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
    let (request_source, response_sink, shutdown) = control_channel.into_active(control_ring)?;
    dispatch_requests(association, request_source, response_sink, shutdown)?;
    Ok(())
}

fn dispatch_requests<Memory: SharedMemory>(
    association: BrokerHostAssociation<'_, Memory>,
    mut request_source: UnixStreamHostRequestSource,
    response_sink: UnixStreamHostResponseSink,
    shutdown: UnixStreamHostControlShutdown,
) -> IoResult<()> {
    let association = Arc::new(association);
    let failure_coordinator = Arc::new(HostAssociationFailureCoordinator::new(shutdown));
    let (request_sender, request_receiver) = sync_channel(REQUEST_QUEUE_CAPACITY);
    let request_receiver = Arc::new(Mutex::new(request_receiver));

    std::thread::scope(|scope| {
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
    });

    match failure_coordinator.take_error() {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn read_requests(
    request_source: &mut UnixStreamHostRequestSource,
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
    response_sink: &UnixStreamHostResponseSink,
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
    shutdown: UnixStreamHostControlShutdown,
}

impl HostAssociationFailureCoordinator {
    const fn new(shutdown: UnixStreamHostControlShutdown) -> Self {
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
    use litebox_broker_protocol::channel::{HostSetupChannel, LocalControlChannel};
    use litebox_broker_protocol::message::BrokerHandshakeResponse;
    use litebox_broker_transport::unix_socket::UnixStreamLocalControlChannel;
    use std::os::fd::AsFd;

    #[test]
    fn first_failure_is_preserved_and_unblocks_request_reading() {
        let (peer_stream, host_stream) = UnixStream::pair().unwrap();
        let mut local_channel = UnixStreamLocalControlChannel::from_connected(peer_stream);
        let mut control_channel = UnixStreamHostControlChannel::from_accepted(host_stream);
        control_channel
            .send_handshake_response(&BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            })
            .unwrap();
        local_channel.recv_handshake_response().unwrap().unwrap();
        let local_memory = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
        let host_memory = MemfdSharedMemory::from_received_fd(
            local_memory.as_fd().try_clone_to_owned().unwrap(),
            CONTROL_RING_MEMORY_SIZE,
        )
        .unwrap();
        let local_ring = ControlRing::new(local_memory).unwrap();
        let host_ring = ControlRing::new(host_memory).unwrap();
        let local_activation = std::thread::spawn(move || {
            let cancellation = local_channel.activate(local_ring, || {}).unwrap();
            (local_channel, cancellation)
        });
        let (mut request_source, _response_sink, shutdown) =
            control_channel.into_active(host_ring).unwrap();
        let (_local_channel, _cancellation) = local_activation.join().unwrap();
        let failure_coordinator = HostAssociationFailureCoordinator::new(shutdown);
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
