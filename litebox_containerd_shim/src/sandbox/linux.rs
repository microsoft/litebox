// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux: the broker, or the [`vm`], below a [`guardian`], which ends it and its runners with the
//! daemon, in the container's network namespace; LiteBox's Linux runner; and containerd's root
//! file system, [`mount`]ed.

mod guardian;
mod mount;
mod vm;

use std::ffi::{CString, OsString};
use std::fs::{File, Permissions};
use std::io::{self, Read as _};
use std::net::Shutdown;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};

use self::guardian::{GUARDIAN_MODE, LIFELINE_FD, VM_GUARDIAN_MODE};
pub(crate) use self::mount::{mount_rootfs, unmount_rootfs};
use super::{
    Backend, Broker, Ended, RootMount, STOP_TIMEOUT, StateDir, broker_arguments, broker_program,
    log_lines, program, stable_name,
};
use crate::rootfs::{Dns, DnsSource};
use crate::spec::{Bind, Network, Plan};
use crate::{Result, internal};

/// The installed name of LiteBox's Linux runner, which the broker runs once per guest process.
const RUNNER: &str = "litebox_runner_linux_userland";

/// Who runs as an unprivileged host user, `(uid, gid)`, instead of the daemon's (see the crate's
/// doc).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Deprivileged {
    /// Nobody: everything runs as the daemon's user.
    #[default]
    Nobody,
    /// The guardian, and the broker and its runners, or the VM's device daemon and VMM.
    Broker(u32, u32),
    /// Only the runners (`LITEBOX_ROOT_BROKER=1`).
    Runners(u32, u32),
}

/// Who runs as an unprivileged host user (see the crate's doc); fails if `LITEBOX_USER` or
/// `LITEBOX_ROOT_BROKER` is malformed.
pub fn deprivileged() -> Result<Deprivileged> {
    let var = |name| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned());
    // Without user namespaces, there is only the initial one.
    let uid_map = std::fs::read_to_string("/proc/self/uid_map")
        .unwrap_or_else(|_| "0 0 4294967295".to_owned());
    let root = rustix::process::geteuid().is_root();
    choose(
        root,
        &uid_map,
        var("LITEBOX_USER").as_deref(),
        var("LITEBOX_ROOT_BROKER").as_deref(),
    )
    .map_err(|message| crate::error(crate::ttrpc::Code::FAILED_PRECONDITION, message))
}

/// [`deprivileged`]'s choice for a daemon that is `root` or not, in the user namespace of
/// `uid_map`, with `LITEBOX_USER` set to `user` and `LITEBOX_ROOT_BROKER` to `root_broker`.
fn choose(
    root: bool,
    uid_map: &str,
    user: Option<&str>,
    root_broker: Option<&str>,
) -> std::result::Result<Deprivileged, String> {
    let root_broker = match root_broker {
        None | Some("0") => false,
        Some("1") => true,
        Some(value) => return Err(format!("LITEBOX_ROOT_BROKER is {value:?}, not 0 or 1")),
    };
    // Neither root's nor 4294967295, which `setresuid` takes for "unchanged".
    let id = |id: &str| id.parse().ok().filter(|id| ![0, u32::MAX].contains(id));
    let user = match user {
        Some(value) => {
            let (uid, gid) = value.split_once(':').unwrap_or((value, value));
            let malformed =
                || format!("LITEBOX_USER is {value:?}, not a numeric uid[:gid] without 0");
            Some((
                id(uid).ok_or_else(malformed)?,
                id(gid).ok_or_else(malformed)?,
            ))
        }
        // Only where its uid 0 maps to an outer 0, conservatively the host's: rootless
        // containerd's root is the host's user.
        None if uid_map
            .lines()
            .any(|line| line.split_whitespace().take(2).eq(["0", "0"])) =>
        {
            Some((2_100_000_000, 2_100_000_000))
        }
        None => None,
    };
    Ok(match user.filter(|_| root) {
        None => Deprivileged::Nobody,
        Some((uid, gid)) if root_broker => Deprivileged::Runners(uid, gid),
        Some((uid, gid)) => Deprivileged::Broker(uid, gid),
    })
}

/// Whether `namespace` is the daemon's own network namespace.
fn is_daemons(namespace: &File) -> bool {
    let id = |stat: rustix::fs::Stat| (stat.st_dev, stat.st_ino);
    let daemons = rustix::fs::stat("/proc/self/ns/net").map(id);
    rustix::fs::fstat(namespace)
        .map(id)
        .is_ok_and(|id| daemons == Ok(id))
}

/// Runs a guardian or the mount mode, and exits, if this executable's `args` ask for it.
pub fn run_private_mode(args: &[OsString]) {
    match args.get(1).and_then(|arg| arg.to_str()) {
        Some(GUARDIAN_MODE) => guardian::main(guardian::guard_broker, &args[2..]),
        Some(VM_GUARDIAN_MODE) => guardian::main(guardian::guard_vm, &args[2..]),
        Some(mount::MOUNT_MODE) => mount::main(&args[2..]),
        _ => {}
    }
}

/// The directory of every container's socket directory: `<root>/.vsock`, below the state root.
pub fn socket_root(root: &Path) -> PathBuf {
    root.join(".vsock")
}

/// The socket directory of the container `id` in `namespace`: `<root>/.vsock/<hash>`, where
/// `root` is the state root.
pub fn socket_dir(root: &Path, namespace: &str, id: &str) -> PathBuf {
    socket_root(root).join(stable_name(&[namespace.as_bytes(), id.as_bytes()]))
}

/// The broker's temporary directory, where it creates its control sockets: `tmp` in the state
/// directory `path`; with a root broker, the socket directory `sockets`, whose plain path (unlike
/// the guardian's descriptor's) its runners can follow.
pub fn temp_dir(path: &Path, sockets: &Path, deprivileged: Deprivileged) -> PathBuf {
    match deprivileged {
        Deprivileged::Runners(..) => sockets.to_owned(),
        Deprivileged::Nobody | Deprivileged::Broker(..) => path.join("tmp"),
    }
}

/// Gives who runs as an unprivileged user what they need of `state`'s directories, for `backend`.
pub fn grant_access(state: &StateDir, backend: Backend) -> io::Result<()> {
    if matches!(backend, Backend::Vm(_)) {
        // The VMM opens the payload there by path, which nobody else may replace (its `policy`
        // limits the guest); an earlier container's broker user may own the directory.
        let (group, mode) = match state.deprivileged {
            Deprivileged::Broker(_, gid) => (Some(gid), 0o710),
            Deprivileged::Nobody | Deprivileged::Runners(..) => (None, 0o700),
        };
        let daemon = rustix::process::geteuid().as_raw();
        std::os::unix::fs::lchown(&state.path, Some(daemon), group)?;
        std::fs::set_permissions(&state.path, Permissions::from_mode(mode))?;
    }
    match state.deprivileged {
        Deprivileged::Nobody => Ok(()),
        // The VMM's user uses the temporary and socket directories.
        Deprivileged::Broker(uid, gid) if matches!(backend, Backend::Vm(_)) => {
            [&state.temp(), &state.sockets]
                .into_iter()
                .try_for_each(|dir| std::os::unix::fs::lchown(dir, Some(uid), Some(gid)))
        }
        // The broker's user reads the archive there, and uses the temporary and socket directories.
        Deprivileged::Broker(uid, gid) => [&state.path, &state.temp(), &state.sockets]
            .into_iter()
            .try_for_each(|dir| std::os::unix::fs::lchown(dir, Some(uid), Some(gid))),
        // The runners' control sockets go there, but nobody else may reach the bridge.
        Deprivileged::Runners(_, gid) => {
            std::os::unix::fs::lchown(&state.sockets, None, Some(gid))?;
            std::fs::set_permissions(&state.sockets, Permissions::from_mode(0o710))
        }
    }
}

/// Lets the broker's user, if another, read `file` of `state`, whatever the daemon's umask.
fn grant_read(state: &StateDir, file: &File) -> io::Result<()> {
    if let Deprivileged::Broker(_, gid) = state.deprivileged {
        std::os::unix::fs::fchown(file, None, Some(gid))?;
        file.set_permissions(Permissions::from_mode(0o640))?;
    }
    Ok(())
}

/// Opens `path` for reading without blocking, close-on-exec as std opens every file.
fn open_nonblocking(path: &Path) -> io::Result<File> {
    File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

/// Moves the calling process into a new network namespace and brings its loopback up, as runc does.
///
/// # Safety
///
/// Async-signal-safe, for a `pre_exec` hook.
unsafe fn new_network() -> io::Result<()> {
    // SAFETY: plain system calls, on an all-zero `ifreq` (valid) and a socket this function owns.
    unsafe {
        if libc::unshare(libc::CLONE_NEWNET) < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if socket < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = OwnedFd::from_raw_fd(socket);
        let mut lo: libc::ifreq = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(c"lo".as_ptr(), lo.ifr_name.as_mut_ptr(), 2);
        if libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &raw mut lo) < 0 {
            return Err(io::Error::last_os_error());
        }
        lo.ifr_ifru.ifru_flags |= libc::c_short::try_from(libc::IFF_UP).expect("a 16-bit flag");
        if libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &raw const lo) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The broker's guardian, which ends it and everything below it.
pub struct Tree {
    guardian: Pid,
    /// The daemon's end of the lifeline: its end makes the guardian kill everything below it.
    lifeline: UnixStream,
    /// Whether connections through the bridge may start (see `vm::VSOCK_STARTED`).
    vsock_started: Arc<AtomicBool>,
}

impl Tree {
    pub(super) fn bridge_open(&self) -> bool {
        self.vsock_started.load(Ordering::Relaxed)
    }
}

/// Unmounts a dead daemon's root file system. A failure is only reported: without the bundle's
/// lock, it may follow a successful unmount.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the platforms' contract: Windows' can fail"
)]
pub fn remove_leftovers(state: &StateDir, bundle: &Path) -> std::result::Result<(), String> {
    if state.lock.is_some()
        && let Err(error) = RootMount::unmount_leftovers(bundle)
    {
        crate::report(format!("{error:?}"));
    }
    Ok(())
}

/// None: the guest keeps its image's `/etc/resolv.conf`, or a bind's (CRI binds the pod's).
impl DnsSource for Network {
    fn dns(&self) -> Result<Option<Dns>> {
        Ok(None)
    }
}

impl Broker {
    /// Fails if the broker of `backend` cannot run `plan`.
    pub fn check(backend: Backend, plan: &Plan) -> Result<()> {
        match backend {
            Backend::Userland => Ok(()),
            Backend::Vm(vmm) => vm::check(vmm, plan),
        }
    }

    /// Spawns the broker of `backend` serving `state`'s `archive` and the directory `binds`, as
    /// `plan` says; calls `exited` once it exited, after [`Broker::wait`] reports it.
    pub fn spawn(
        backend: Backend,
        state: &StateDir,
        archive: File,
        binds: &[Bind],
        plan: &Plan,
        exited: impl FnOnce() + Send + 'static,
    ) -> Result<Self> {
        let failed = |error: io::Error| internal(format!("cannot start the broker: {error}"));
        let network = &plan.network;
        let joined = match network {
            // Never blocking (on a FIFO, say): `setns` checks that it is a network namespace.
            Network::Join(path) => Some(open_nonblocking(path).map_err(|error| {
                crate::error(
                    crate::ttrpc::Code::FAILED_PRECONDITION,
                    format!(
                        "cannot open the network namespace {}: {error}",
                        path.display()
                    ),
                )
            })?),
            Network::Daemon | Network::New => None,
        };
        // Joined by path, the daemon's own is still the daemon's, whose sysctls runc refuses.
        let own = joined
            .as_ref()
            .map_or(*network == Network::New, |joined| !is_daemons(joined));
        // The child's own link to the daemon's executable, which it can follow after `setresuid`.
        let mut command = Command::new("/proc/self/exe");
        match backend {
            Backend::Userland => {
                // Runners of another user cannot follow the guardian's `/proc/<pid>/fd`: they get
                // the plain path of the (short) socket directory.
                let how = match state.deprivileged {
                    // Below it, `/litebox-broker-userland-XXXXXX/broker.sock` (43 bytes) must fit
                    // a socket's address (107 bytes); with the socket directory's 24, 40 are left.
                    Deprivileged::Runners(..) if state.sockets.as_os_str().len() > 107 - 43 => {
                        return Err(crate::error(
                            crate::ttrpc::Code::FAILED_PRECONDITION,
                            "with LITEBOX_ROOT_BROKER=1, the state root (LITEBOX_SHIM_STATE_ROOT) \
                             must be at most 40 bytes long",
                        ));
                    }
                    Deprivileged::Runners(..) => "plain",
                    Deprivileged::Nobody | Deprivileged::Broker(..) => "fd",
                };
                command
                    .arg(GUARDIAN_MODE)
                    .arg(state.temp())
                    .arg(how)
                    .arg(broker_program());
                if let Deprivileged::Runners(uid, gid) = state.deprivileged {
                    command.arg("--runner-user").arg(format!("{uid}:{gid}"));
                }
                if own {
                    // The namespace's port mappings (Docker's, CNI's) then reach the guest's
                    // servers. Only those the broker can bind: see the crate's documentation.
                    command.arg("--publish-listener-ip").arg("0.0.0.0");
                }
                // The broker opens the archive by path.
                grant_read(state, &archive).map_err(failed)?;
                let runner = program("LITEBOX_RUNNER", RUNNER);
                command.args(broker_arguments(
                    &state.bridge(),
                    &state.archive(),
                    binds,
                    plan,
                    &runner,
                ));
            }
            Backend::Vm(vmm) => {
                command.arg(VM_GUARDIAN_MODE);
                vm::guardian_arguments(vmm, &mut command, state, archive, binds, plan)?;
            }
        }
        let (lifeline, guardian_socket) = UnixStream::pair().map_err(failed)?;
        // Above `LIFELINE_FD`: `dup2` onto its own number would keep it close-on-exec.
        let guardian_end = rustix::io::fcntl_dupfd_cloexec(&guardian_socket, LIFELINE_FD + 1)
            .map_err(|error| failed(error.into()))?;
        // Only the guardian keeps its end, so that the lifeline ends if the guardian fails early.
        drop(guardian_socket);
        let (stderr, stderr_end) = io::pipe().map_err(failed)?;
        if let (Backend::Vm(_), Deprivileged::Broker(uid, gid)) = (backend, state.deprivileged) {
            vm::give_stderr(&stderr_end, uid, gid).map_err(failed)?;
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(stderr_end)
            .current_dir("/")
            // The broker's processes share the guardian's group.
            .process_group(0);
        let deprivileged = state.deprivileged;
        let new = *network == Network::New;
        let sysctl = if own { &plan.sysctl[..] } else { &[] };
        let names: Vec<&str> = sysctl.iter().map(|(path, _)| path.as_str()).collect();
        let names = if names.is_empty() {
            String::new()
        } else {
            format!(" with the sysctls {names:?}")
        };
        // Prepared here: the hook may not allocate.
        let sysctl = sysctl
            .iter()
            .map(|(path, value)| {
                let path = CString::new(format!("/proc/sys/{path}"));
                Ok((
                    path.map_err(|_| internal("a sysctl with a NUL"))?,
                    value.clone(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let groups: Vec<libc::gid_t> = match backend {
            Backend::Userland => Vec::new(),
            Backend::Vm(_) => vm::kvm_group().into_iter().collect(),
        };
        // SAFETY: the hook makes async-signal-safe calls only, on descriptors it owns.
        unsafe {
            command.pre_exec(move || {
                // Before the privilege drop: both need `CAP_SYS_ADMIN`.
                if let Some(joined) = &joined
                    && libc::setns(joined.as_raw_fd(), libc::CLONE_NEWNET) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                if new {
                    new_network()?;
                }
                // Set as root, in the namespace: `/proc/sys/net` is the opener's namespace's.
                for (path, value) in &sysctl {
                    let file = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                    let written = match file {
                        0.. => libc::write(file, value.as_ptr().cast(), value.len()),
                        _ => -1,
                    };
                    // A short write applied only part of the value, as Linux does with a list
                    // longer than a page.
                    let error = match usize::try_from(written) {
                        Ok(written) if written == value.len() => None,
                        Ok(_) => Some(io::Error::from_raw_os_error(libc::EMSGSIZE)),
                        Err(_) => Some(io::Error::last_os_error()),
                    };
                    if file >= 0 {
                        libc::close(file);
                    }
                    if let Some(error) = error {
                        return Err(error);
                    }
                }
                if let Deprivileged::Broker(uid, gid) = deprivileged
                    && (libc::setgroups(groups.len(), groups.as_ptr()) < 0
                        || libc::setresgid(gid, gid, gid) < 0
                        || libc::setresuid(uid, uid, uid) < 0
                        || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
                {
                    return Err(io::Error::last_os_error());
                }
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
        let mut guardian = command.spawn().map_err(|error| match network {
            Network::Daemon => failed(error),
            Network::Join(_) | Network::New => internal(format!(
                "cannot start the broker in the container's network namespace{names}: {error}"
            )),
        })?;
        drop(command);
        let vsock_started = Arc::new(AtomicBool::new(backend == Backend::Userland));
        let seen = Arc::clone(&vsock_started);
        let _ = log_lines(
            "stdout",
            guardian.stdout.take().expect("piped"),
            move |line| {
                if line == vm::VSOCK_STARTED {
                    seen.store(true, Ordering::Relaxed);
                }
            },
        );
        let stderr = Mutex::new(log_lines("stderr", stderr, |_| {}));
        let group = Pid::from_child(&guardian);
        let ended = Arc::new(Ended::default());
        let reaper = Arc::clone(&ended);
        std::thread::spawn(move || {
            // Before the guardian is reaped, its pid names its group alone: whatever it left there
            // goes with it.
            while matches!(
                rustix::process::waitid(
                    WaitId::Pid(group),
                    WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
                ),
                Err(rustix::io::Errno::INTR)
            ) {}
            let _ = rustix::process::kill_process_group(group, Signal::KILL);
            let status = guardian.wait();
            log::info!("the broker exited: {status:?}");
            reaper.set();
            // After `ended`, which callers wait for while they hold the shim's locks.
            exited();
        });
        let mut pid = [0u8; 4];
        let broker = Self {
            pid: 0,
            ended,
            stderr,
            tree: Tree {
                guardian: group,
                lifeline,
                vsock_started,
            },
        };
        (&broker.tree.lifeline)
            .read_exact(&mut pid)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    let why = broker.last_words();
                    internal(format!("the guardian could not start the broker: {why}"))
                } else {
                    failed(error)
                }
            })?;
        Ok(Self {
            pid: u32::from_le_bytes(pid),
            ..broker
        })
    }

    /// Ends the broker and everything below it.
    pub fn stop(&self) {
        let _ = self.tree.lifeline.shutdown(Shutdown::Both);
        if !self.wait(STOP_TIMEOUT) {
            log::error!("the broker's guardian did not exit in time; killing its group");
            let _ = rustix::process::kill_process_group(self.tree.guardian, Signal::KILL);
            self.wait(STOP_TIMEOUT);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{Deprivileged, choose};
    use crate::sandbox::StateDir;

    #[test]
    fn root_runs_the_broker_or_its_runners_as_litebox_user_or_by_default_as_the_host_s_root() {
        let (initial, rootless) = (
            "         0          0 4294967295\n",
            "0 1002 1\n1 231072 65536\n",
        );
        let default = Deprivileged::Broker(2_100_000_000, 2_100_000_000);
        assert_eq!(choose(true, initial, None, None), Ok(default));
        assert_eq!(choose(true, "1 1000 1\n0 0 1\n", None, None), Ok(default));
        assert_eq!(
            choose(true, rootless, None, Some("1")),
            Ok(Deprivileged::Nobody)
        );
        assert_eq!(
            choose(true, rootless, Some("5:6"), Some("0")),
            Ok(Deprivileged::Broker(5, 6))
        );
        assert_eq!(
            choose(true, initial, Some("5"), Some("1")),
            Ok(Deprivileged::Runners(5, 5))
        );
        assert_eq!(
            choose(false, initial, Some("5"), None),
            Ok(Deprivileged::Nobody)
        );
        for bad in ["", "0", "0:0", "5:0", "4294967295", "5:", "x", "1:2:3"] {
            assert!(choose(true, initial, Some(bad), None).is_err(), "{bad}");
        }
        for bad in ["", "true", "2"] {
            assert!(choose(true, initial, None, Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_sockets_are_below_the_state_root() {
        let state = StateDir::at(PathBuf::from("/state"), "default", "c");
        assert_eq!(state.roots, [Path::new("/state")]);
        let bridge = "/state/.vsock/633d08cc16cc911b/vsock";
        assert_eq!(state.bridge(), Path::new(bridge));
        let control = state
            .temp()
            .join("litebox-broker-userland-XXXXXX/broker.sock");
        let expected = "/state/default/c/tmp/litebox-broker-userland-XXXXXX/broker.sock";
        assert_eq!(control, Path::new(expected));
    }
}
