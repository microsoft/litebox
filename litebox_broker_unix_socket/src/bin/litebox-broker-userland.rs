// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::env;
use std::io;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use litebox_broker_core::{BrokerCore, EventOnlyPolicy};
use litebox_broker_server::{BrokerServeError, serve_connection};
use litebox_broker_unix_socket::UnixStreamServerTransport;

fn main() -> io::Result<()> {
    let args = Args::parse(env::args().skip(1))?;
    let listener = UnixListener::bind(&args.socket_path)?;
    let (stream, _) = listener.accept()?;
    let mut transport = UnixStreamServerTransport::from_accepted(stream);
    let mut broker = BrokerCore::new(EventOnlyPolicy);
    serve_connection(&mut broker, &mut transport)
        .map(|_| ())
        .map_err(broker_error)
}

fn broker_error(error: BrokerServeError<io::Error>) -> io::Error {
    match error {
        BrokerServeError::ConnectionSetup => io::Error::other("broker connection setup failed"),
        BrokerServeError::Transport(error) => error,
    }
}

struct Args {
    socket_path: PathBuf,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = String>) -> io::Result<Self> {
        let mut socket_path = None;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--socket" => {
                    let path = args.next().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "--socket requires a path")
                    })?;
                    socket_path = Some(PathBuf::from(path));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unknown command-line argument",
                    ));
                }
            }
        }

        let socket_path = socket_path
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--socket is required"))?;
        Ok(Self { socket_path })
    }
}
