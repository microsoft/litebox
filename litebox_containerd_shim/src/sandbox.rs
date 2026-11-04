// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The container's broker: `litebox-broker-userland` below a [`guardian`](crate::guardian), with
//! the guest service as its root process, its state directory, and the guest service's client.
//!
//! The broker bridges the guest's vsock sockets to Unix sockets in the container's socket
//! directory (`--vsock-uds`), which is private to the daemon (0700): whoever can connect there
//! reaches the guest service. Its stdout and stderr, the guest service's log among them, go to
//! the shim's log, a line at a time.

use std::ffi::OsString;
use std::io::{self, BufRead as _, BufReader, Read as _, Write as _};
use std::net::Shutdown;
use std::os::fd::{AsRawFd as _, IntoRawFd as _, OwnedFd};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use containerd_shim::protos::ttrpc;
use litebox_broker_core::socket::PublishedTcpPort;
use litebox_guest_service_protocol::GUEST_SERVICE_PORT;
use litebox_guest_service_protocol::guest_service_ttrpc::GuestServiceClient;
use rustix::fs::{FlockOperation, Mode, OFlags};
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};

use crate::guardian::{GUARDIAN_MODE, LIFELINE_FD};
use crate::rootfs::GUEST_SERVICE_PATH;
use crate::spec::Egress;
use crate::{Result, internal};

/// How long the guest service may take to listen once the broker started.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the guardian may take to end everything once the lifeline ended.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// The directories of a container: `<root>/<namespace>/<id>` holds the root archive and the
/// broker's temporary directory; `<root>/.vsock/<hash>`, short enough for socket paths, holds the
/// bridge.
pub struct StateDir {
    root: PathBuf,
    path: PathBuf,
    sockets: PathBuf,
    /// An exclusive `flock` on `path`, close-on-exec: the daemon's from `create` until it drops
    /// this, after `remove`; the `delete` action leaves a locked state to its live daemon.
    lock: Option<OwnedFd>,
}

impl StateDir {
    /// The state root is `LITEBOX_SHIM_STATE_ROOT`, or on disk for root (an archive is as large
    /// as its image), or in `XDG_RUNTIME_DIR`, or in the temporary directory.
    pub fn new(namespace: &str, id: &str) -> Self {
        let root = std::env::var_os("LITEBOX_SHIM_STATE_ROOT").map_or_else(
            || match rustix::process::geteuid() {
                user if user.is_root() => PathBuf::from("/var/lib/containerd-shim-litebox"),
                user => std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
                    || {
                        let name = format!("containerd-shim-litebox-{}", user.as_raw());
                        std::env::temp_dir().join(name)
                    },
                    |runtime| PathBuf::from(runtime).join("containerd-shim-litebox"),
                ),
            },
            PathBuf::from,
        );
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
            lock: None,
        }
    }

    /// Takes the state directory, creating it if missing, and empties both directories. Holding
    /// its lock is owning it: this fails if another daemon holds it (a container with the same ID
    /// whose cancelled `Create` still runs, and cleans up after itself).
    pub fn create(&mut self) -> Result<()> {
        let failed =
            |error: io::Error| internal(format!("cannot create the state directory: {error}"));
        private_root(&self.root).map_err(failed)?;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(&self.path).map_err(failed)?;
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
        builder.create(self.temp()).map_err(failed)?;
        builder.create(&self.sockets).map_err(failed)
    }

    /// Locks the state directory unless it is missing or locked (by its live daemon).
    pub fn try_lock(&mut self) -> bool {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let Ok(dir) = rustix::fs::open(&self.path, flags, Mode::empty()) else {
            return false;
        };
        // The directory may have been removed by its last owner since it was opened, and another
        // one created in its place: only the one at the path counts.
        let at_path = |dir: &OwnedFd| {
            let (Ok(locked), Ok(current)) = (rustix::fs::fstat(dir), std::fs::metadata(&self.path))
            else {
                return false;
            };
            locked.st_dev == current.dev() && locked.st_ino == current.ino()
        };
        if rustix::fs::flock(&dir, FlockOperation::NonBlockingLockExclusive).is_err()
            || !at_path(&dir)
        {
            return false;
        }
        self.lock = Some(dir);
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

    /// Removes the files or directories `paths`, unless the state root fails [`private_root`].
    fn remove_paths(&self, paths: &[PathBuf]) {
        if let Err(error) = private_root(&self.root) {
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
        self.path.join("tmp")
    }

    fn bridge(&self) -> PathBuf {
        self.sockets.join("vsock")
    }
}

/// Creates the state root `root` (0700) if it is missing; fails unless it is a directory, not a
/// symlink, of this user's, that only they can use: below it, nobody else can plant a symlink.
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

/// A running broker, below its guardian.
pub struct Broker {
    pid: u32,
    guardian: Pid,
    /// The daemon's end of the lifeline: its end makes the guardian kill everything below it.
    lifeline: UnixStream,
    ended: Arc<(Mutex<bool>, Condvar)>,
}

impl Broker {
    /// Spawns the broker serving the archive of `state` and the directory `binds`, allowing
    /// `egress` and publishing `published`.
    pub fn spawn(
        state: &StateDir,
        binds: &[(PathBuf, String)],
        egress: &Egress,
        published: &[PublishedTcpPort],
    ) -> Result<Self> {
        let failed = |error: io::Error| internal(format!("cannot start the broker: {error}"));
        let runner = std::env::current_exe().map_err(failed)?;
        let mut command = Command::new(&runner);
        command
            .arg(GUARDIAN_MODE)
            .arg(state.temp())
            .arg(program("LITEBOX_BROKER", "litebox-broker-userland"))
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
        for port in published {
            command.arg("--publish").arg(format!(
                "{}:{}:{}",
                port.host_address.ip(),
                port.host_address.port(),
                port.guest_port
            ));
        }
        command
            .arg("--runner")
            .arg(&runner)
            .arg("--")
            .arg(GUEST_SERVICE_PATH);
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
        for (source, output) in [
            (
                "stdout",
                guardian
                    .stdout
                    .take()
                    .map(|out| Box::new(out) as Box<dyn io::Read + Send>),
            ),
            (
                "stderr",
                guardian
                    .stderr
                    .take()
                    .map(|err| Box::new(err) as Box<dyn io::Read + Send>),
            ),
        ] {
            let mut lines = BufReader::new(output.expect("piped"));
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

#[cfg(test)]
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
