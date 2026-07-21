// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::cell::Cell;
use std::error::Error;
use std::ffi::OsString;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use clap::Parser;
use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine};
use litebox_broker_host::{ConnectionTermination, serve_connection};
use litebox_broker_protocol::pipe::PIPE_TRANSFER_BUFFER_SIZE;
use litebox_broker_transport::shared_memory::MemfdSharedMemory;
use litebox_broker_transport::unix_socket::{
    UnixPeerCredentials, UnixStreamHostControlChannel, UnixStreamHostNotificationChannel,
    peer_credentials,
};

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);

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
    let (control_stream, control_credentials) = accept_runner_stream(
        control_listener,
        runner,
        runner_process_id,
        setup_deadline,
        "control",
    )?;
    let (notification_stream, notification_credentials) = accept_runner_stream(
        notification_listener,
        runner,
        runner_process_id,
        setup_deadline,
        "notification",
    )?;
    validate_channel_pair(control_credentials, notification_credentials)?;

    let shared_memory = MemfdSharedMemory::create(PIPE_TRANSFER_BUFFER_SIZE)?;
    let mut control_channel =
        UnixStreamHostControlChannel::from_host_guaranteed(control_stream, setup_deadline);
    let mut notification_channel =
        UnixStreamHostNotificationChannel::from_accepted(notification_stream);
    let setup_completed = Cell::new(false);
    let termination = serve_connection(
        broker,
        &mut control_channel,
        &mut notification_channel,
        &shared_memory,
        |channel| {
            channel.send_memfd(&shared_memory, Some(setup_deadline))?;
            setup_completed.set(true);
            Ok(())
        },
    )?;
    if termination != ConnectionTermination::PeerClosed {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "runner violated the broker protocol",
        )
        .into());
    }
    if !setup_completed.get() {
        return Err(IoError::new(
            ErrorKind::UnexpectedEof,
            "runner closed before completing broker setup",
        )
        .into());
    }
    Ok(())
}

fn accept_runner_stream(
    listener: &UnixListener,
    runner: &mut Child,
    runner_process_id: u32,
    deadline: Instant,
    channel_name: &'static str,
) -> IoResult<(UnixStream, UnixPeerCredentials)> {
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
                let credentials = peer_credentials(&stream)?;
                validate_runner_peer(credentials, runner_process_id)?;
                return Ok((stream, credentials));
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        std::thread::sleep(remaining.min(ACCEPT_RETRY_DELAY));
    }
}

fn validate_runner_peer(credentials: UnixPeerCredentials, runner_process_id: u32) -> IoResult<()> {
    if credentials.process_id() != runner_process_id {
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            "broker channel peer is not the spawned runner",
        ));
    }
    Ok(())
}

fn validate_channel_pair(
    control: UnixPeerCredentials,
    notification: UnixPeerCredentials,
) -> IoResult<()> {
    if control != notification {
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            "broker control and notification channels have different peers",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_channel_validation_rejects_unexpected_or_mismatched_peers() {
        let runner = UnixPeerCredentials::from_raw(7, 8, 9);
        assert!(validate_runner_peer(runner, 7).is_ok());
        assert_eq!(
            validate_runner_peer(runner, 6).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        assert!(validate_channel_pair(runner, runner).is_ok());
        assert_eq!(
            validate_channel_pair(runner, UnixPeerCredentials::from_raw(7, 10, 9))
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
    }
}
