// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The container's broker: `litebox-broker-userland` below a [`guardian`](crate::guardian) (on
//! Windows, in a Job Object), with the guest service as its root process, its state directory,
//! and the guest service's client.
//!
//! The broker bridges the guest's vsock sockets to Unix sockets in the container's socket
//! directory (`--vsock-uds`), which is private to the daemon (0700; on Windows, an owner-only
//! DACL): whoever can connect there reaches the guest service. Its stdout and stderr, the guest
//! service's log among them, go to the shim's log, a line at a time.

use std::ffi::OsString;
use std::io::{self, BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::{
    io::{Read as _, Write as _},
    net::Shutdown,
    os::fd::{AsRawFd as _, IntoRawFd as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _},
    os::unix::net::UnixStream,
    os::unix::process::CommandExt as _,
    process::Stdio,
    sync::{Arc, Condvar, Mutex},
    time::Instant,
};

#[cfg(target_os = "linux")]
use containerd_shim::protos::ttrpc;
#[cfg(target_os = "linux")]
use litebox_guest_service_protocol::GUEST_SERVICE_PORT;
#[cfg(target_os = "linux")]
use litebox_guest_service_protocol::guest_service_ttrpc::GuestServiceClient;
#[cfg(target_os = "linux")]
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};

#[cfg(target_os = "linux")]
use crate::guardian::{GUARDIAN_MODE, LIFELINE_FD};
use crate::rootfs::GUEST_SERVICE_PATH;
use crate::spec::Egress;
use crate::{Result, internal};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use self::windows::Broker;
#[cfg(windows)]
use self::windows::{default_state_root, private_root};

/// How long the guest service may take to listen once the broker started.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the guardian (on Windows, the broker) may take to end everything once told to.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// The directories of a container: `<root>/<namespace>/<id>` holds the root archive and the
/// broker's temporary directory; `<root>/.vsock/<hash>`, short enough for socket paths, holds the
/// bridge.
pub struct StateDir {
    root: PathBuf,
    path: PathBuf,
    sockets: PathBuf,
}

impl StateDir {
    /// The state root is `LITEBOX_SHIM_STATE_ROOT`, or on disk for root (an archive is as large
    /// as its image), or in `XDG_RUNTIME_DIR`, or in the temporary directory (on Windows, always
    /// the temporary directory, which is the user's).
    pub fn new(namespace: &str, id: &str) -> Self {
        let root = std::env::var_os("LITEBOX_SHIM_STATE_ROOT")
            .map_or_else(default_state_root, PathBuf::from);
        // FNV-1a, stable across builds, so that the `delete` action finds it.
        let hash = namespace
            .bytes()
            .chain([0])
            .chain(id.bytes())
            .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
            });
        Self {
            path: root.join(namespace).join(id),
            sockets: root.join(".vsock").join(format!("{hash:016x}")),
            root,
        }
    }

    /// Creates both directories, empty and private.
    pub fn create(&self) -> Result<()> {
        let created = (|| {
            private_root(&self.root)?;
            self.remove();
            let mut builder = std::fs::DirBuilder::new();
            // On Windows, they inherit the state root's DACL.
            builder.recursive(true);
            #[cfg(target_os = "linux")]
            builder.mode(0o700);
            builder.create(self.temp())?;
            builder.create(&self.sockets)
        })();
        created.map_err(|error: io::Error| {
            internal(format!("cannot create the state directory: {error}"))
        })
    }

    /// Removes both directories, unless the state root fails [`private_root`].
    pub fn remove(&self) {
        if let Err(error) = private_root(&self.root) {
            log::error!("left the state directory: {error}");
            return;
        }
        for path in [&self.path, &self.sockets] {
            if let Err(error) = std::fs::remove_dir_all(path)
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
        self.path.join("tmp")
    }

    fn bridge(&self) -> PathBuf {
        self.sockets.join("vsock")
    }
}

/// The state root of a user without `LITEBOX_SHIM_STATE_ROOT`.
#[cfg(target_os = "linux")]
fn default_state_root() -> PathBuf {
    match rustix::process::geteuid() {
        user if user.is_root() => PathBuf::from("/var/lib/containerd-shim-litebox"),
        user => std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
            || {
                let name = format!("containerd-shim-litebox-{}", user.as_raw());
                std::env::temp_dir().join(name)
            },
            |runtime| PathBuf::from(runtime).join("containerd-shim-litebox"),
        ),
    }
}

/// Creates the state root `root` (0700) if it is missing; fails unless it is a directory, not a
/// symlink, of this user's, that only they can use: below it, nobody else can plant a symlink.
#[cfg(target_os = "linux")]
fn private_root(root: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)?;
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::other(format!(
            "the state root {} is not a private directory of this user's",
            root.display()
        )));
    }
    Ok(())
}

/// The executables that run a container: the broker and the guest service are next to this
/// executable, unless `LITEBOX_BROKER` or `LITEBOX_GUEST_SERVICE` name them. The guest service
/// must be static: it runs in the container's file system.
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
/// `binds`, allowing `egress`, and running the guest service in `runner`.
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

/// Logs the broker's `output` (`source`) a line at a time, until its end.
fn log_lines(source: &'static str, output: impl io::Read + Send + 'static) {
    let mut lines = BufReader::new(output);
    std::thread::spawn(move || {
        let mut line = Vec::new();
        while lines
            .read_until(b'\n', &mut line)
            .is_ok_and(|read| read > 0)
        {
            let text = String::from_utf8_lossy(line.strip_suffix(b"\n").unwrap_or(&line));
            log::info!("broker {source}: {text:?}");
            line.clear();
        }
    });
}

/// A running broker, below its guardian.
#[cfg(target_os = "linux")]
pub struct Broker {
    pid: u32,
    guardian: Pid,
    /// The daemon's end of the lifeline: its end makes the guardian kill everything below it.
    lifeline: UnixStream,
    ended: Arc<(Mutex<bool>, Condvar)>,
}

#[cfg(target_os = "linux")]
impl Broker {
    /// Spawns the broker serving the archive of `state` and the directory `binds`, allowing
    /// `egress`.
    pub fn spawn(state: &StateDir, binds: &[(PathBuf, String)], egress: &Egress) -> Result<Self> {
        let failed = |error: io::Error| internal(format!("cannot start the broker: {error}"));
        let runner = std::env::current_exe().map_err(failed)?;
        let mut command = Command::new(&runner);
        command
            .arg(GUARDIAN_MODE)
            .arg(state.temp())
            .arg(broker_program());
        broker_arguments(&mut command, state, binds, egress, &runner);
        let (lifeline, guardian_socket) = UnixStream::pair().map_err(failed)?;
        // Above `LIFELINE_FD`: `dup2` onto its own number would keep it close-on-exec.
        let guardian_end = rustix::io::fcntl_dupfd_cloexec(&guardian_socket, LIFELINE_FD + 1)
            .map_err(|error| failed(error.into()))?;
        // Only the guardian keeps its end, so that the lifeline ends if the guardian fails early.
        drop(guardian_socket);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .current_dir("/")
            // The broker and its runners share the guardian's group.
            .process_group(0);
        // SAFETY: the hook makes async-signal-safe calls only, on a descriptor it owns.
        unsafe {
            command.pre_exec(move || {
                // The guardian takes none of the daemon's other descriptors.
                libc::syscall(
                    libc::SYS_close_range,
                    3u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                );
                if libc::dup2(guardian_end.as_raw_fd(), LIFELINE_FD) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut guardian = command.spawn().map_err(failed)?;
        drop(command);
        log_lines("stdout", guardian.stdout.take().expect("piped"));
        log_lines("stderr", guardian.stderr.take().expect("piped"));
        let group = Pid::from_child(&guardian);
        let ended = Arc::new((Mutex::new(false), Condvar::new()));
        let reaper = Arc::clone(&ended);
        std::thread::spawn(move || {
            // Before the guardian is reaped, its pid names its group alone: whatever it left there
            // goes with it.
            let _ = rustix::process::waitid(
                WaitId::Pid(group),
                WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
            );
            let _ = rustix::process::kill_process_group(group, Signal::KILL);
            let status = guardian.wait();
            log::info!("the broker exited: {status:?}");
            *reaper.0.lock().expect("not poisoned") = true;
            reaper.1.notify_all();
        });
        let mut pid = [0u8; 4];
        let broker = Self {
            pid: 0,
            guardian: group,
            lifeline,
            ended,
        };
        (&broker.lifeline).read_exact(&mut pid).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                internal("the guardian could not start the broker; see the shim's log")
            } else {
                failed(error)
            }
        })?;
        Ok(Self {
            pid: u32::from_le_bytes(pid),
            ..broker
        })
    }

    /// The broker's host PID, which containerd knows as the pid of every process.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    fn wait(&self, timeout: Duration) -> bool {
        let (ended, changed) = &*self.ended;
        let ended =
            changed.wait_timeout_while(ended.lock().expect("not poisoned"), timeout, |ended| {
                !*ended
            });
        *ended.expect("not poisoned").0
    }

    /// Ends the broker and everything below it.
    pub fn stop(&self) {
        let _ = self.lifeline.shutdown(Shutdown::Both);
        if !self.wait(STOP_TIMEOUT) {
            log::error!("the broker's guardian did not exit in time; killing its group");
            let _ = rustix::process::kill_process_group(self.guardian, Signal::KILL);
            self.wait(STOP_TIMEOUT);
        }
    }

    /// Connects to the guest service through the broker's bridge of `state`: `CONNECT <port>\n`,
    /// answered with `OK <host port>\n`; the bridge closes the stream while nothing listens yet.
    pub fn connect(&self, state: &StateDir) -> Result<GuestServiceClient> {
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let attempt = || -> io::Result<UnixStream> {
            let mut stream = UnixStream::connect(state.bridge())?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
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
            stream.set_read_timeout(None)?;
            Ok(stream)
        };
        loop {
            match attempt() {
                Ok(stream) => {
                    let client = ttrpc::Client::new(stream.into_raw_fd()).map_err(|error| {
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::private_root;

    #[test]
    fn a_state_root_must_be_a_private_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        private_root(&root).unwrap();
        let mode = std::fs::metadata(&root).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        std::os::unix::fs::symlink(&root, dir.path().join("link")).unwrap();
        assert!(private_root(&dir.path().join("link")).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(private_root(&root).is_err());
    }
}
