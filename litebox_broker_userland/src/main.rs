// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, PolicyEngine};
use litebox_broker_host::{BrokerHostError, serve_connection};
use litebox_broker_transport::unix_socket::UnixStreamServerControlChannel;

const SESSION_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> io::Result<()> {
    let args = Args::parse(env::args().skip(1))?;
    let listener = bind_listener(&args.socket_path)?;
    let _socket_cleanup = SocketPathCleanup::new(args.socket_path.clone());
    let (stream, _) = listener.accept()?;
    let mut channel = UnixStreamServerControlChannel::from_accepted(stream);
    channel.set_io_deadline(Some(Instant::now() + SESSION_TIMEOUT))?;
    let mut broker = BrokerCore::new(PolicyEngine::event_only()).map_err(io::Error::other)?;
    serve_connection(&mut broker, &mut channel)
        .map(|_| ())
        .map_err(broker_error)
}

fn bind_listener(socket_path: &Path) -> io::Result<UnixListener> {
    match UnixListener::bind(socket_path) {
        Ok(listener) => Ok(listener),
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
            remove_stale_socket(socket_path)?;
            UnixListener::bind(socket_path)
        }
        Err(error) => Err(error),
    }
}

fn remove_stale_socket(socket_path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(socket_path)?;
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "broker socket path exists and is not a socket",
        ));
    }

    match std::os::unix::net::UnixStream::connect(socket_path) {
        Ok(_stream) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "broker socket path is already accepting connections",
        )),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            fs::remove_file(socket_path)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

struct SocketPathCleanup {
    socket_path: PathBuf,
}

impl SocketPathCleanup {
    fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }
}

impl Drop for SocketPathCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
    }
}

fn broker_error(error: BrokerHostError<io::Error>) -> io::Error {
    match error {
        BrokerHostError::AssociationSetup => io::Error::other("broker association setup failed"),
        BrokerHostError::Channel(error) => error,
        error => io::Error::other(error.to_string()),
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
