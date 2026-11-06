// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux: the broker below a [`guardian`], which ends it and its runners with the daemon, and
//! LiteBox's Linux runner.

mod guardian;

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
use super::{
    STOP_TIMEOUT, StateDir, broker_arguments, broker_program, log_lines, program, stable_name,
};
use crate::spec::Egress;
use crate::{Result, internal};

/// The installed name of LiteBox's Linux runner, which the broker runs once per guest process.
const RUNNER: &str = "litebox_runner_linux_userland";

/// Runs the guardian, and exits, if this executable's `args` ask for it.
pub fn run_private_mode(args: &[OsString]) {
    if args.get(1).is_some_and(|arg| arg == GUARDIAN_MODE) {
        guardian::main(&args[2..]);
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
    /// `egress`.
    pub fn spawn(state: &StateDir, binds: &[(PathBuf, String)], egress: &Egress) -> Result<Self> {
        let failed = |error: io::Error| internal(format!("cannot start the broker: {error}"));
        // The guardian is the daemon's own executable, whatever replaced its file since.
        let mut command = Command::new(format!("/proc/{}/exe", std::process::id()));
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
    pub(super) fn wait(&self, timeout: Duration) -> bool {
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

    use crate::sandbox::StateDir;

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
