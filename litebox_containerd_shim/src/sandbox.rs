// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Access to the private socket directory grants access to the guest service on either backend.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use containerd_shim::protos::ttrpc;
#[cfg(unix)]
use containerd_shim::protos::types::mount::Mount;
use litebox_guest_service_protocol::GUEST_SERVICE_PORT;
use litebox_guest_service_protocol::guest_service_ttrpc::GuestServiceClient;

#[cfg(target_os = "linux")]
use self::linux::{
    Deprivileged, Tree, deprivileged, grant_access, mount_rootfs, socket_dir, socket_root,
    temp_dir, unmount_rootfs,
};
#[cfg(target_os = "linux")]
pub(crate) use self::linux::{remove_leftovers, run_private_mode};
#[cfg(unix)]
use self::unix::{
    Lock, client, connect_bridge, create_dir, create_traversable, default_state_root, lock,
    private_root, wait_lock,
};
#[cfg(windows)]
use self::windows::{
    Deprivileged, Lock, Tree, client, connect_bridge, create_dir, create_traversable,
    default_state_root, deprivileged, grant_access, lock, private_root, socket_dir, socket_root,
    temp_dir,
};
#[cfg(windows)]
pub(crate) use self::windows::{init_log, layer_folders, remove_leftovers, run_private_mode};
use crate::rootfs::GUEST_SERVICE_PATH;
use crate::spec::{Bind, Plan};
use crate::{Backend, Result, internal};

/// How long the guest service may take to listen once the broker's bridge takes connections.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the broker may take to end everything once told to.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the `delete` action's cleaner waits for a dead daemon's mounters: well within the 4 s
/// that the action waits for it.
#[cfg(unix)]
const LEFTOVER_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
/// The longest piece of a line of the broker's output that is logged at once.
const MAX_LOG_LINE: u64 = 16 * 1024;

/// The error of a `Create` whose container ID an earlier container's cleanup still holds.
fn cleanup_pending() -> ttrpc::Error {
    crate::error(
        ttrpc::Code::FAILED_PRECONDITION,
        "an earlier container with this ID is still being cleaned up; try again later",
    )
}

/// The directories of a container: `<root>/<namespace>/<id>` holds the root archive, or the VM's
/// payload; the socket directory, short enough for socket paths, holds the bridge (and the VM's
/// device socket); the broker's temporary directory holds its control sockets. The platform
/// places the last two: `socket_dir` and `temp_dir`.
///
/// Everything the shim creates or removes here, and every socket it serves, is below one of
/// `roots`, which `create` and cleanup check with [`private_root`] first: the state root, and the
/// platform's `socket_root` unless it is below the state root.
pub struct StateDir {
    roots: Vec<PathBuf>,
    path: PathBuf,
    sockets: PathBuf,
    /// Who does not run as the daemon's user, from `create` on.
    deprivileged: Deprivileged,
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
            deprivileged: Deprivileged::default(),
            lock: None,
        }
    }

    /// Checks (and creates) [`StateDir`]'s roots with [`private_root`].
    fn private_roots(&self) -> io::Result<()> {
        self.roots.iter().try_for_each(|root| private_root(root))
    }

    /// Takes the state directory of a `backend`'s broker, creating it if missing, and empties both
    /// directories. Holding its lock is owning it: this fails if another daemon holds it (a
    /// container with the same ID whose cancelled `Create` still runs, and cleans up after itself).
    pub fn create(&mut self, backend: Backend) -> Result<()> {
        let failed =
            |error: io::Error| internal(format!("cannot create the state directory: {error}"));
        self.deprivileged = match (backend, deprivileged()?) {
            #[cfg(target_os = "linux")]
            (Backend::Vm, Deprivileged::Runners(uid, gid)) => Deprivileged::Broker(uid, gid),
            (Backend::Userland, deprivileged) => deprivileged,
            #[cfg(target_os = "linux")]
            (Backend::Vm, deprivileged) => deprivileged,
        };
        self.private_roots().map_err(failed)?;
        // The namespace's directory and the socket root, which the broker's user traverses.
        let parents = [self.path.parent(), self.sockets.parent()];
        for parent in parents.into_iter().flatten() {
            create_traversable(parent).map_err(failed)?;
        }
        create_dir(&self.path).map_err(failed)?;
        if !self.try_lock() {
            return Err(cleanup_pending());
        }
        let mut stale: Vec<PathBuf> = std::fs::read_dir(&self.path)
            .map_err(failed)?
            .filter_map(|entry| Some(entry.ok()?.path()))
            .collect();
        stale.push(self.sockets.clone());
        self.remove_paths(&stale);
        create_dir(&self.sockets).map_err(failed)?;
        let temp = self.temp();
        if temp != self.sockets {
            create_dir(&temp).map_err(failed)?;
        }
        grant_access(self, backend).map_err(failed)
    }

    /// Locks the state directory unless it is missing or locked (by its live daemon).
    pub fn try_lock(&mut self) -> bool {
        let Some(lock) = lock(&self.path) else {
            return false;
        };
        self.lock = Some(lock);
        true
    }

    /// Removes the large contents, the root archive, the VM's payload and the broker's temporary
    /// directory, and the bridge's directory, but keeps the state directory: the mark that
    /// `poststop` is still due.
    pub fn clear(&self) {
        let (archive, payload, temp) = (self.archive(), self.payload(), self.temp());
        self.remove_paths(&[archive, payload, temp, self.sockets.clone()]);
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

    fn payload(&self) -> PathBuf {
        self.path.join("payload.tar")
    }

    fn temp(&self) -> PathBuf {
        temp_dir(&self.path, &self.sockets, self.deprivileged)
    }

    fn bridge(&self) -> PathBuf {
        self.sockets.join("vsock")
    }
}

/// containerd's root file system, mounted at `<bundle>/rootfs` as runc's shim mounts it, until
/// dropped.
///
/// An exclusive lock on the bundle directory (not on `rootfs`, which a mount replaces) keeps the
/// `delete` action from cleaning up while a mount may still be made: the daemon holds it from
/// before it mounts until it has unmounted, and its mounters inherit it, so that it outlives a
/// killed daemon until they are gone too.
#[cfg(unix)]
pub struct RootMount {
    path: PathBuf,
    lock: Lock,
}

#[cfg(unix)]
impl RootMount {
    /// Mounts `mounts`, in order, at `<bundle>/rootfs`, creating it if missing.
    pub fn new(bundle: &Path, mounts: &[Mount]) -> Result<Self> {
        let failed = |error: io::Error| {
            internal(format!(
                "cannot prepare to mount {}/rootfs: {error}",
                bundle.display()
            ))
        };
        let root = Self {
            path: bundle.join("rootfs"),
            lock: wait_lock(bundle, STOP_TIMEOUT).map_err(failed)?,
        };
        std::fs::create_dir_all(&root.path).map_err(failed)?;
        // Dropped on failure, which unmounts the mounts made.
        mount_rootfs(&root.path, mounts, &root.lock)?;
        Ok(root)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Unmounts a dead daemon's leftovers at `<bundle>/rootfs`, once its mounters are gone (or
    /// after [`LEFTOVER_LOCK_TIMEOUT`]).
    fn unmount_leftovers(bundle: &Path) -> std::result::Result<(), String> {
        let lock = wait_lock(bundle, LEFTOVER_LOCK_TIMEOUT);
        unmount_rootfs(&bundle.join("rootfs"))?;
        match lock {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(format!(
                "unmounted {}/rootfs without the bundle's lock: {error}",
                bundle.display()
            )),
            _ => Ok(()),
        }
    }
}

#[cfg(unix)]
impl Drop for RootMount {
    /// Unmounts, then releases the lock.
    fn drop(&mut self) {
        if let Err(error) = unmount_rootfs(&self.path) {
            log::error!("{error}");
        }
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
/// `LITEBOX_RUNNER` name them (the VM's: see `linux/vm.rs`). The guest service must be static: it
/// runs in the container's file system.
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

/// The paths are as the broker sees them.
fn broker_arguments(
    bridge: &Path,
    archive: &Path,
    binds: &[Bind],
    plan: &Plan,
    runner: &Path,
) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = [
        "--unstable",
        "--allow-process-duplication",
        "--root-process-as-init",
        "--vsock-uds",
    ]
    .map(OsString::from)
    .into();
    arguments.extend([bridge.into(), "--fs-initial-files".into(), archive.into()]);
    // Only read-only ones reach here (see `RootFs::bind`).
    for bind in binds {
        let mut mount = OsString::from(&bind.source);
        mount.push(format!("::{}", bind.destination));
        arguments.extend(["--mount-ro".into(), mount]);
    }
    for (option, destinations) in [
        ("--allow-tcp-destination", &plan.egress.tcp),
        ("--allow-udp-destination", &plan.egress.udp),
    ] {
        for destination in destinations {
            arguments.extend([option.into(), destination.to_string().into()]);
        }
    }
    for (option, sources) in [
        ("--allow-tcp-source", &plan.ingress.tcp),
        ("--allow-udp-source", &plan.ingress.udp),
    ] {
        for source in sources {
            arguments.extend([option.into(), source.to_string().into()]);
        }
    }
    for publish in &plan.publish {
        arguments.extend(["--publish".into(), publish.to_string().into()]);
    }
    arguments.extend([
        "--runner".into(),
        runner.into(),
        "--".into(),
        GUEST_SERVICE_PATH.into(),
    ]);
    arguments
}

/// Logs the broker's `output` (its `source`) a line at a time, until its end, and passes each line
/// to `seen`; then sends the last.
fn log_lines(
    source: &'static str,
    output: impl Read + Send + 'static,
    mut seen: impl FnMut(&str) + Send + 'static,
) -> Receiver<Vec<u8>> {
    let (last_line, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut last = Vec::new();
        for_each_line(BufReader::new(output), |line| {
            let text = String::from_utf8_lossy(line);
            log::info!("broker {source}: {text:?}");
            seen(&text);
            last.clear();
            last.extend_from_slice(line);
        });
        let _ = last_line.send(last);
    });
    receiver
}

/// Calls `log` with each line of `lines` until its end, without its newline (and a carriage
/// return before it, as a serial port's lines end), a longer line in pieces of [`MAX_LOG_LINE`]
/// bytes.
fn for_each_line(mut lines: impl BufRead, mut log: impl FnMut(&[u8])) {
    let mut line = Vec::new();
    while (&mut lines)
        .take(MAX_LOG_LINE)
        .read_until(b'\n', &mut line)
        .is_ok_and(|read| read > 0)
    {
        let text = line.strip_suffix(b"\n").unwrap_or(&line);
        log(text.strip_suffix(b"\r").unwrap_or(text));
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

/// A running broker.
pub struct Broker {
    pid: u32,
    ended: Arc<Ended>,
    /// The last line of the broker's stderr (on Linux, its guardian's), once that ends.
    stderr: Mutex<Receiver<Vec<u8>>>,
    tree: Tree,
}

/// Set by the broker's reaper.
#[derive(Default)]
struct Ended {
    ended: Mutex<bool>,
    changed: Condvar,
}

impl Ended {
    fn set(&self) {
        *self.ended.lock().expect("lock poisoned") = true;
        self.changed.notify_all();
    }

    fn wait(&self, timeout: Duration) -> bool {
        let ended = self.ended.lock().expect("lock poisoned");
        let ended = self
            .changed
            .wait_timeout_while(ended, timeout, |ended| !*ended);
        *ended.expect("lock poisoned").0
    }
}

impl Broker {
    /// The host PID of the broker, or of the VM's VMM, which containerd knows as the pid of every
    /// process.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Waits up to `timeout` for the broker to end; returns whether it did.
    pub fn wait(&self, timeout: Duration) -> bool {
        self.ended.wait(timeout)
    }

    /// Why the broker ended early. Gives its stderr a second to end after it.
    fn last_words(&self) -> String {
        let stderr = self.stderr.lock().expect("lock poisoned");
        match stderr.recv_timeout(Duration::from_secs(1)) {
            Ok(last) if !last.is_empty() => {
                crate::truncated(&String::from_utf8_lossy(&last)).to_owned()
            }
            _ => "see the shim's log".to_owned(),
        }
    }

    /// Connects to the guest service through the broker's bridge of `state`. A VM's boot, until its
    /// bridge takes connections, has no deadline: how long it takes depends on the host.
    pub fn connect(&self, state: &StateDir) -> Result<GuestServiceClient> {
        let mut deadline = None;
        loop {
            let connected = self.tree.bridge_open().then(|| {
                deadline.get_or_insert_with(|| Instant::now() + CONNECT_TIMEOUT);
                connect_bridge(&state.bridge())
            });
            match connected {
                Some(Ok(stream)) => {
                    let client = client(stream).map_err(|error| {
                        internal(format!("cannot serve the connection: {error}"))
                    })?;
                    return Ok(GuestServiceClient::new(client));
                }
                _ if self.wait(Duration::ZERO) => {
                    return Err(internal(format!(
                        "the broker exited before its guest service listened: {}",
                        self.last_words()
                    )));
                }
                Some(Err(error)) if deadline.is_some_and(|deadline| Instant::now() > deadline) => {
                    return Err(internal(format!(
                        "the guest service did not listen in time: {error}"
                    )));
                }
                _ => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_LOG_LINE, for_each_line};

    #[test]
    fn a_long_line_is_logged_in_bounded_pieces() {
        let output = [vec![b'x'; 3 << 20], b"\nend\r\n".to_vec()].concat();
        let mut logged = Vec::new();
        for_each_line(output.as_slice(), |piece| {
            assert!(u64::try_from(piece.len()).unwrap() <= MAX_LOG_LINE);
            logged.extend_from_slice(piece);
        });
        assert_eq!(logged, [vec![b'x'; 3 << 20], b"end".to_vec()].concat());
    }
}
