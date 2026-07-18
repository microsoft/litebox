// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::ffi::OsString;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;

use clap::Parser;
use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine};
use litebox_broker_host::serve_connection;
use litebox_broker_transport::unix_socket::{
    UnixStreamHostControlChannel, UnixStreamHostNotificationChannel,
};

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
    let broker = BrokerCore::new(PolicyEngine::with_unauthenticated_rights(
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
    let _runner_waiter = std::thread::spawn(move || {
        if let Err(error) = runner.wait() {
            eprintln!("failed to wait for local runner: {error}");
        }
    });

    loop {
        let (control_stream, _) = control_listener.accept()?;
        let (notification_stream, _) = notification_listener.accept()?;
        let broker = broker.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("litebox-broker-connection".to_owned())
            .spawn(move || {
                let mut control_channel =
                    UnixStreamHostControlChannel::from_accepted(control_stream);
                let mut notification_channel =
                    UnixStreamHostNotificationChannel::from_accepted(notification_stream);
                if let Err(error) =
                    serve_connection(&broker, &mut control_channel, &mut notification_channel)
                {
                    eprintln!("failed to serve broker connection: {error}");
                }
            })
        {
            eprintln!("failed to spawn broker connection handler: {error}");
        }
    }
}
