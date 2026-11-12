// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux: the broker below a [`guardian`], which ends it and its runners with the daemon, LiteBox's
//! Linux runner, and containerd's root file system, [`mount`]ed.

mod guardian;
mod mount;

use std::ffi::OsString;
use std::io::{self, Read as _};
use std::net::Shutdown;
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};

use self::guardian::{GUARDIAN_MODE, LIFELINE_FD};
pub(crate) use self::mount::{mount_rootfs, unmount_rootfs};
use super::{
    STOP_TIMEOUT, StateDir, broker_arguments, broker_program, log_lines, program, stable_name,
};
use crate::spec::{Bind, Egress};
use crate::{Result, internal};

/// The installed name of LiteBox's Linux runner, which the broker runs once per guest process.
const RUNNER: &str = "litebox_runner_linux_userland";

/// The user that the guardian, the broker and its runners run as, if not the daemon's (see the
/// crate's doc); fails if `LITEBOX_USER` is malformed.
pub fn broker_user() -> Result<Option<(u32, u32)>> {
    let value = std::env::var_os("LITEBOX_USER");
    let text = value
        .as_deref()
        .map(|value| value.to_str().unwrap_or_default());
    let uid_map = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
    choose_user(rustix::process::geteuid().is_root(), &uid_map, text).map_err(|()| {
        crate::error(
            crate::ttrpc::Code::FAILED_PRECONDITION,
            format!("LITEBOX_USER is {value:?}, not 0 nor a numeric uid[:gid] other than 0"),
        )
    })
}

/// [`broker_user`]'s choice for a daemon that is `root` or not, in the user namespace of `uid_map`,
/// with `LITEBOX_USER` set to `value`.
fn choose_user(
    root: bool,
    uid_map: &str,
    value: Option<&str>,
) -> std::result::Result<Option<(u32, u32)>, ()> {
    // Neither root's nor 4294967295, which `setresuid` takes for "unchanged".
    let id = |id: &str| {
        id.parse()
            .ok()
            .filter(|id| ![0, u32::MAX].contains(id))
            .ok_or(())
    };
    let user = match value {
        // The opt-out: the daemon's user, root under rootful containerd.
        Some("0") => None,
        Some(value) => {
            let (uid, gid) = value.split_once(':').unwrap_or((value, value));
            Some((id(uid)?, id(gid)?))
        }
        // Only in the initial user namespace: rootless containerd's root is the host's user.
        None if uid_map.split_whitespace().eq(["0", "0", "4294967295"]) => {
            Some((2_100_000_000, 2_100_000_000))
        }
        None => None,
    };
    Ok(user.filter(|_| root))
}

/// Runs the guardian or the mount mode, and exits, if this executable's `args` ask for it.
pub fn run_private_mode(args: &[OsString]) {
    if args.get(1).is_some_and(|arg| arg == GUARDIAN_MODE) {
        guardian::main(&args[2..]);
    }
    if args.get(1).is_some_and(|arg| arg == mount::MOUNT_MODE) {
        mount::main(&args[2..]);
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
/// directory `path`.
pub fn temp_dir(path: &Path, _sockets: &Path) -> PathBuf {
    path.join("tmp")
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
    /// `egress`; calls `exited` once it exited, after [`Broker::wait`] reports it.
    pub fn spawn(
        state: &StateDir,
        binds: &[Bind],
        egress: &Egress,
        exited: impl FnOnce() + Send + 'static,
    ) -> Result<Self> {
        let failed = |error: io::Error| internal(format!("cannot start the broker: {error}"));
        // The child's own link to the daemon's executable, which it can follow after `setresuid`.
        let mut command = Command::new("/proc/self/exe");
        command
            .arg(GUARDIAN_MODE)
            .arg(state.temp())
            .arg(broker_program());
        let runner = program("LITEBOX_RUNNER", RUNNER);
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
        let user = state.user;
        // SAFETY: the hook makes async-signal-safe calls only, on a descriptor it owns.
        unsafe {
            command.pre_exec(move || {
                if let Some((uid, gid)) = user
                    && (libc::setgroups(0, std::ptr::null()) < 0
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
            *reaper.0.lock().expect("not poisoned") = true;
            reaper.1.notify_all();
            // After `ended`, which callers wait for while they hold the shim's locks.
            exited();
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

    /// Waits up to `timeout` for the broker to end; returns whether it did.
    pub fn wait(&self, timeout: Duration) -> bool {
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
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::choose_user;
    use crate::sandbox::StateDir;

    #[test]
    fn root_runs_the_broker_as_litebox_user_or_by_default_in_the_initial_user_namespace() {
        let (initial, rootless) = (
            "         0          0 4294967295\n",
            "0 1002 1\n1 231072 65536\n",
        );
        let default = Some((2_100_000_000, 2_100_000_000));
        assert_eq!(choose_user(true, initial, None), Ok(default));
        assert_eq!(choose_user(true, rootless, None), Ok(None));
        assert_eq!(choose_user(true, rootless, Some("5:6")), Ok(Some((5, 6))));
        assert_eq!(choose_user(true, initial, Some("5")), Ok(Some((5, 5))));
        assert_eq!(choose_user(false, initial, Some("5")), Ok(None));
        assert_eq!(choose_user(true, initial, Some("0")), Ok(None));
        for bad in ["", "0:0", "5:0", "4294967295", "5:", "x", "1:2:3"] {
            assert_eq!(choose_user(true, initial, Some(bad)), Err(()), "{bad}");
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
