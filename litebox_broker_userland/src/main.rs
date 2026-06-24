// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use litebox_broker_core::{BrokerCore, PolicyEngine, PrincipalRights};
use litebox_broker_host::serve_connection;
use litebox_broker_transport::unix_socket::UnixStreamHostControlChannel;

const SESSION_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);
const RUNNER_BINARY: &str = "litebox_runner_linux_userland";

#[derive(Parser, Debug)]
struct CliArgs {
    /// Local runner executable to launch.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::ExecutablePath)]
    runner: Option<PathBuf>,
    /// Arguments to pass to the local runner.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, value_hint = clap::ValueHint::CommandWithArguments)]
    runner_arguments: Vec<OsString>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = CliArgs::parse();
    let socket_dir = SocketDir::new()?;
    let socket_path = socket_dir.path().join("broker.sock");
    let listener = UnixListener::bind(&socket_path)?;
    listener.set_nonblocking(true)?;

    let runner = args.runner.unwrap_or(default_runner_path()?);
    let mut runner = RunnerChild::new(spawn_runner(&runner, &socket_path, &args.runner_arguments)?);
    let (stream, _) = accept_runner_connection(&listener, runner.child_mut())?;
    let runner_status = {
        let mut channel = UnixStreamHostControlChannel::from_accepted(stream);
        channel.set_io_deadline(Some(Instant::now() + SESSION_TIMEOUT))?;
        let broker = BrokerCore::new(PolicyEngine::with_unauthenticated_rights(
            PrincipalRights::all(),
        ))?;
        serve_connection(&broker, &mut channel)?;
        runner.wait()?
    };
    if !runner_status.success() {
        return Err(io::Error::other(format!("local runner exited with {runner_status}")).into());
    }
    Ok(())
}

fn spawn_runner(
    runner: &Path,
    socket_path: &Path,
    runner_arguments: &[OsString],
) -> io::Result<Child> {
    Command::new(runner)
        .arg("--unstable")
        .arg("--broker-socket")
        .arg(socket_path)
        .args(runner_arguments)
        .spawn()
}

fn accept_runner_connection(
    listener: &UnixListener,
    runner: &mut Child,
) -> io::Result<(
    std::os::unix::net::UnixStream,
    std::os::unix::net::SocketAddr,
)> {
    let deadline = Instant::now() + SESSION_TIMEOUT;
    loop {
        match listener.accept() {
            Ok(accepted) => return Ok(accepted),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if let Some(status) = runner.try_wait()? {
                    return Err(runner_exited_before_connecting(status));
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for local runner broker connection",
                    ));
                }
                thread::sleep(ACCEPT_RETRY_DELAY);
            }
            Err(error) => return Err(error),
        }
    }
}

fn runner_exited_before_connecting(status: ExitStatus) -> io::Error {
    io::Error::other(format!(
        "local runner exited before connecting to broker: {status}"
    ))
}

fn default_runner_path() -> io::Result<PathBuf> {
    let current_exe = std::env::current_exe()?;
    Ok(current_exe.with_file_name(RUNNER_BINARY))
}

struct RunnerChild {
    child: Option<Child>,
}

impl RunnerChild {
    const fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("local runner process missing")
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        let status = self.child_mut().wait();
        if status.is_ok() {
            self.child = None;
        }
        status
    }
}

impl Drop for RunnerChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            match child.try_wait() {
                Ok(Some(_status)) => {}
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(_error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }
}

struct SocketDir {
    path: PathBuf,
}

impl SocketDir {
    fn new() -> io::Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "litebox-broker-userland-{}-{now}-{attempt}",
                std::process::id()
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "failed to create unique broker socket directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SocketDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
