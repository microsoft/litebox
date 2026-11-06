// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The container's broker: `litebox-broker-userland` with the guest service as its root process,
//! its state directory, and the guest service's client.
//!
//! The broker bridges the guest's vsock sockets to sockets in the container's socket directory
//! (`--vsock-uds`), which is private to the daemon: whoever can connect there reaches the guest
//! service. Its stdout and stderr, the guest service's log among them, go to the shim's log, a
//! line at a time.
//!
//! This module is every platform's; each platform provides what the `use`s below import:
//! [`linux`] the broker, the private modes and where the sockets are; [`unix`] the private
//! directories, their locks and the bridge's socket.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(unix)]
mod unix;

use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use containerd_shim::protos::ttrpc;
use litebox_guest_service_protocol::GUEST_SERVICE_PORT;
use litebox_guest_service_protocol::guest_service_ttrpc::GuestServiceClient;

#[cfg(target_os = "linux")]
pub(crate) use self::linux::{Broker, run_private_mode};
#[cfg(target_os = "linux")]
use self::linux::{socket_dir, socket_root, temp_dir};
#[cfg(unix)]
use self::unix::{
    Lock, client, connect_bridge, create_dir, default_state_root, lock, private_root,
};
use crate::rootfs::GUEST_SERVICE_PATH;
use crate::spec::Egress;
use crate::{Result, internal};

/// How long the guest service may take to listen once the broker started.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the broker may take to end everything once told to.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest piece of a line of the broker's output that is logged at once.
const MAX_LOG_LINE: u64 = 16 * 1024;

/// The directories of a container: `<root>/<namespace>/<id>` holds the root archive; the socket
/// directory, short enough for socket paths, holds the bridge; the broker's temporary directory
/// holds its control sockets. The platform places the last two: `socket_dir`, and `temp_dir` in
/// one of the other two.
///
/// Everything the shim creates or removes here, and every socket it serves, is below one of
/// `roots`, which `create` and cleanup check with [`private_root`] first: the state root, and the
/// platform's `socket_root` unless it is below the state root.
pub struct StateDir {
    roots: Vec<PathBuf>,
    path: PathBuf,
    sockets: PathBuf,
    /// An exclusive lock on `path`: the daemon's from `create` until it drops this, after
    /// `remove`; the `delete` action leaves a locked state to its live daemon.
    lock: Option<Lock>,
}

impl StateDir {
    /// The state root is `LITEBOX_SHIM_STATE_ROOT`, or the platform's default.
    pub fn new(namespace: &str, id: &str) -> Self {
        let root = std::env::var_os("LITEBOX_SHIM_STATE_ROOT")
            .map_or_else(default_state_root, PathBuf::from);
        Self::at(root, namespace, id)
    }

    fn at(root: PathBuf, namespace: &str, id: &str) -> Self {
        let path = root.join(namespace).join(id);
        let sockets = socket_dir(&root, namespace, id);
        let socket_root = socket_root(&root);
        let mut roots = vec![root];
        if !socket_root.starts_with(&roots[0]) {
            roots.push(socket_root);
        }
        Self {
            roots,
            path,
            sockets,
            lock: None,
        }
    }

    /// Checks (and creates) [`StateDir`]'s roots with [`private_root`].
    fn private_roots(&self) -> io::Result<()> {
        self.roots.iter().try_for_each(|root| private_root(root))
    }

    /// Takes the state directory, creating it if missing, and empties both directories. Holding
    /// its lock is owning it: this fails if another daemon holds it (a container with the same ID
    /// whose cancelled `Create` still runs, and cleans up after itself).
    pub fn create(&mut self) -> Result<()> {
        let failed =
            |error: io::Error| internal(format!("cannot create the state directory: {error}"));
        self.private_roots().map_err(failed)?;
        create_dir(&self.path).map_err(failed)?;
        if !self.try_lock() {
            return Err(crate::error(
                ttrpc::Code::FAILED_PRECONDITION,
                "an earlier container with this ID is still being cleaned up; try again later",
            ));
        }
        let mut stale: Vec<PathBuf> = std::fs::read_dir(&self.path)
            .map_err(failed)?
            .filter_map(|entry| Some(entry.ok()?.path()))
            .collect();
        stale.push(self.sockets.clone());
        self.remove_paths(&stale);
        create_dir(&self.temp()).map_err(failed)?;
        create_dir(&self.sockets).map_err(failed)
    }

    /// Locks the state directory unless it is missing or locked (by its live daemon).
    pub fn try_lock(&mut self) -> bool {
        let Some(lock) = lock(&self.path) else {
            return false;
        };
        self.lock = Some(lock);
        true
    }

    /// Removes the large contents, the root archive and the broker's temporary directory, and the
    /// bridge's directory, but keeps the state directory: the mark that `poststop` is still due.
    pub fn clear(&self) {
        self.remove_paths(&[self.archive(), self.temp(), self.sockets.clone()]);
    }

    /// Removes both directories.
    pub fn remove(&self) {
        self.remove_paths(&[self.sockets.clone(), self.path.clone()]);
    }

    /// Removes the files or directories `paths`, unless a root fails [`private_root`].
    fn remove_paths(&self, paths: &[PathBuf]) {
        if let Err(error) = self.private_roots() {
            log::error!("left the state directory: {error}");
            return;
        }
        for path in paths {
            let removed = std::fs::remove_file(path).or_else(|_| std::fs::remove_dir_all(path));
            if let Err(error) = removed
                && error.kind() != io::ErrorKind::NotFound
            {
                log::warn!("cannot remove {}: {error}", path.display());
            }
        }
    }

    pub fn archive(&self) -> PathBuf {
        self.path.join("rootfs.tar")
    }

    fn temp(&self) -> PathBuf {
        temp_dir(&self.path, &self.sockets)
    }

    fn bridge(&self) -> PathBuf {
        self.sockets.join("vsock")
    }
}

/// A name for `parts` that is stable across builds, so that the `delete` action finds what the
/// daemon created: their FNV-1a hash, with a 0 byte between them.
fn stable_name(parts: &[&[u8]]) -> String {
    let hash = parts
        .join(&0)
        .iter()
        .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
        });
    format!("{hash:016x}")
}

/// The executables that run a container, the broker, the guest service and the platform's runner,
/// are next to this executable, unless `LITEBOX_BROKER`, `LITEBOX_GUEST_SERVICE` or
/// `LITEBOX_RUNNER` name them. The guest service must be static: it runs in the container's file
/// system.
pub fn guest_service() -> PathBuf {
    program("LITEBOX_GUEST_SERVICE", "litebox-guest-service")
}

fn broker_program() -> PathBuf {
    let name = format!("litebox-broker-userland{}", std::env::consts::EXE_SUFFIX);
    program("LITEBOX_BROKER", &name)
}

fn program(variable: &str, name: &str) -> PathBuf {
    std::env::var_os(variable).map_or_else(
        || {
            std::env::current_exe()
                .unwrap_or_default()
                .with_file_name(name)
        },
        PathBuf::from,
    )
}

/// Adds the broker's arguments to `command`: serving the archive of `state` and the directory
/// `binds`, allowing `egress`, and running the guest service with the runner `runner`.
fn broker_arguments(
    command: &mut Command,
    state: &StateDir,
    binds: &[(PathBuf, String)],
    egress: &Egress,
    runner: &Path,
) {
    command
        .args(["--unstable", "--allow-process-duplication", "--vsock-uds"])
        .arg(state.bridge())
        .arg("--fs-initial-files")
        .arg(state.archive());
    // TODO: fix in the broker: `LocalFs` may follow a symlink a guest renamed within a bind.
    for (source, destination) in binds {
        let mut mount = OsString::from(source);
        mount.push(format!("::{destination}"));
        command.arg("--mount").arg(mount);
    }
    for (option, destinations) in [
        ("--allow-tcp-destination", &egress.tcp),
        ("--allow-udp-destination", &egress.udp),
    ] {
        for destination in destinations {
            command.arg(option).arg(destination.to_string());
        }
    }
    command
        .arg("--runner")
        .arg(runner)
        .arg("--")
        .arg(GUEST_SERVICE_PATH);
}

/// Logs the broker's `output` (its `source`) a line at a time, until its end.
fn log_lines(source: &'static str, output: impl Read + Send + 'static) {
    std::thread::spawn(move || {
        for_each_line(BufReader::new(output), |line| {
            let text = String::from_utf8_lossy(line);
            log::info!("broker {source}: {text:?}");
        });
    });
}

/// Calls `log` with each line of `lines` until its end, without its newline, a longer line in
/// pieces of [`MAX_LOG_LINE`] bytes.
fn for_each_line(mut lines: impl BufRead, mut log: impl FnMut(&[u8])) {
    let mut line = Vec::new();
    while (&mut lines)
        .take(MAX_LOG_LINE)
        .read_until(b'\n', &mut line)
        .is_ok_and(|read| read > 0)
    {
        log(line.strip_suffix(b"\n").unwrap_or(&line));
        line.clear();
    }
}

/// Asks the bridge on `stream` for the guest service: `CONNECT <port>\n`, answered with
/// `OK <host port>\n`; the bridge closes the stream while nothing listens yet.
fn handshake(stream: &mut (impl Read + Write)) -> io::Result<()> {
    stream.write_all(format!("CONNECT {GUEST_SERVICE_PORT}\n").as_bytes())?;
    // A byte at a time: what follows the line is the guest service's.
    let mut answer = Vec::new();
    let mut byte = [0];
    while answer.last() != Some(&b'\n') {
        stream.read_exact(&mut byte)?;
        answer.push(byte[0]);
    }
    if !answer.starts_with(b"OK ") {
        return Err(io::Error::other(format!("the bridge answered {answer:?}")));
    }
    Ok(())
}

impl Broker {
    /// Connects to the guest service through the broker's bridge of `state`.
    pub fn connect(&self, state: &StateDir) -> Result<GuestServiceClient> {
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        loop {
            match connect_bridge(&state.bridge()) {
                Ok(stream) => {
                    let client = client(stream).map_err(|error| {
                        internal(format!("cannot serve the connection: {error}"))
                    })?;
                    return Ok(GuestServiceClient::new(client));
                }
                Err(_) if self.wait(Duration::ZERO) => {
                    return Err(internal(
                        "the broker exited before its guest service listened (see the shim's log)",
                    ));
                }
                Err(error) if Instant::now() > deadline => {
                    return Err(internal(format!(
                        "the guest service did not listen in time: {error}"
                    )));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_LOG_LINE, for_each_line};

    #[test]
    fn a_long_line_is_logged_in_bounded_pieces() {
        let output = [vec![b'x'; 3 << 20], b"\nend\n".to_vec()].concat();
        let mut logged = Vec::new();
        for_each_line(output.as_slice(), |piece| {
            assert!(u64::try_from(piece.len()).unwrap() <= MAX_LOG_LINE);
            logged.extend_from_slice(piece);
        });
        assert_eq!(logged, [vec![b'x'; 3 << 20], b"end".to_vec()].concat());
    }
}
