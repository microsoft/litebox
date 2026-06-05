// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use litebox_broker_core::{BrokerCore, PolicyEngine};
use litebox_broker_host::serve_connection;
use litebox_broker_transport::unix_socket::UnixStreamHostControlChannel;

const SESSION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Parser, Debug)]
struct CliArgs {
    /// Broker Unix socket path to bind.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    socket: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = CliArgs::parse();
    let listener = UnixListener::bind(args.socket)?;
    let (stream, _) = listener.accept()?;
    let mut channel = UnixStreamHostControlChannel::from_accepted(stream);
    channel.set_io_deadline(Some(Instant::now() + SESSION_TIMEOUT))?;
    let mut broker = BrokerCore::new(PolicyEngine::event_only())?;
    serve_connection(&mut broker, &mut channel)?;
    Ok(())
}
