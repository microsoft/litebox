// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::ffi::OsString;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;

use clap::Parser;
use litebox_broker_core::{BrokerCore, PolicyEngine, PrincipalRights};
use litebox_broker_host::serve_connection;
use litebox_broker_transport::unix_socket::UnixStreamHostControlChannel;

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
    let socket_path = socket_dir.path().join("broker.sock");
    let listener = UnixListener::bind(&socket_path)?;
    let broker = BrokerCore::new(PolicyEngine::with_unauthenticated_rights(
        PrincipalRights::all(),
    ))?;

    let mut runner_command = Command::new(&args.runner);
    runner_command
        .arg("--unstable")
        .arg("--broker-socket")
        .arg(&socket_path)
        .args(&args.runner_arguments);
    let mut runner = runner_command.spawn()?;
    let _runner_waiter = std::thread::spawn(move || {
        if let Err(error) = runner.wait() {
            eprintln!("failed to wait for local runner: {error}");
        }
    });

    loop {
        let (stream, _) = listener.accept()?;
        let mut channel = UnixStreamHostControlChannel::from_accepted(stream);
        serve_connection(&broker, &mut channel)?;
    }
}
