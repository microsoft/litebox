// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::thread;

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
    // SAFETY: `pre_exec` runs after fork and before exec in the runner child. The
    // closure only calls async-signal-safe Linux syscalls to make the runner exit if
    // its broker parent exits.
    unsafe {
        runner_command.pre_exec(|| {
            // SAFETY: `prctl` is called with PR_SET_PDEATHSIG and a valid signal number.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `getppid` takes no pointer arguments and has no Rust-side aliasing requirements.
            if libc::getppid() == 1 {
                // SAFETY: `_exit` terminates the child immediately if the broker died before prctl.
                libc::_exit(1);
            }
            Ok(())
        });
    }
    let mut runner = runner_command.spawn()?;
    let _runner_waiter = thread::spawn(move || {
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
