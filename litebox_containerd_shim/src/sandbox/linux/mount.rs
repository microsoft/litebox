// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! containerd's root file system, mounted with the `containerd-shim` crate's helper in a private
//! mode of this executable: the helper forks, and waits for its child through the crate's reaper,
//! which the daemon does not run (it reaps each of its children itself).

use std::ffi::OsString;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use containerd_shim::protos::types::mount::Mount;
use rustix::io::Errno;
use rustix::mount::UnmountFlags;

use crate::{Result, internal};

/// The leading argument of the mount mode, which containerd never passes.
pub const MOUNT_MODE: &str = "__litebox-mount";

/// Mounts `mounts`, in order, at `target`, in a child running the mount mode, which inherits the
/// bundle's `lock` (see [`RootMount`](crate::sandbox::RootMount)).
pub fn mount_rootfs(target: &Path, mounts: &[Mount], lock: &OwnedFd) -> Result<()> {
    let failed = |error: String| {
        internal(format!(
            "cannot mount the root file system at {}: {error}",
            target.display()
        ))
    };
    let mounts: Vec<_> = mounts
        .iter()
        .map(|mount| (&mount.type_, &mount.source, &mount.options))
        .collect();
    let mounts = serde_json::to_string(&mounts).map_err(|error| failed(error.to_string()))?;
    let lock = lock.as_raw_fd();
    // The daemon's own executable, whatever replaced its file.
    let mut command = Command::new("/proc/self/exe");
    command
        .arg(MOUNT_MODE)
        .arg(lock.to_string())
        .arg(target)
        .arg(mounts)
        .stdin(Stdio::null());
    // SAFETY: `fcntl` is async-signal-safe, and the daemon's `lock` outlives the child.
    unsafe {
        command.pre_exec(move || {
            // Kept across `exec`, and by the crate's forked worker.
            if libc::fcntl(lock, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command
        .output()
        .map_err(|error| failed(error.to_string()))?;
    if !output.status.success() {
        return Err(failed(format!(
            "{:?}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Unmounts everything at and below `target`, lazily, so that open descriptors do not keep it;
/// nothing mounted there is fine. The kernel resolves `target`: mounts stack there, and each
/// unmount detaches the top one with everything below it.
pub fn unmount_rootfs(target: &Path) -> std::result::Result<(), String> {
    loop {
        match rustix::mount::unmount(target, UnmountFlags::DETACH | UnmountFlags::NOFOLLOW) {
            Ok(()) => {}
            // Not a mount point (any more), or missing; or not this user's to unmount, nor so to
            // have mounted.
            Err(Errno::INVAL | Errno::NOENT | Errno::PERM) => return Ok(()),
            Err(error) => return Err(format!("cannot unmount {}: {error}", target.display())),
        }
    }
}

/// Runs the mount mode, `<lock> <target> <mounts>` (the bundle's lock's descriptor; `[type,
/// source, options]` in JSON), and exits.
pub fn main(args: &[OsString]) -> ! {
    // The crate's reaper, for the helper's children, which are this process's only ones.
    std::thread::spawn(|| {
        loop {
            match rustix::process::wait(rustix::process::WaitOptions::empty()) {
                Ok(Some((pid, status))) => {
                    let signaled = status.terminating_signal().map(|signal| 128 + signal);
                    let code = status.exit_status().or(signaled).unwrap_or(-2);
                    let _ = containerd_shim::monitor::monitor_notify_by_pid(pid.as_raw_pid(), code);
                }
                // No child yet.
                _ => std::thread::sleep(Duration::from_millis(1)),
            }
        }
    });
    let mounted = (|| {
        let [lock, target, mounts] = args else {
            return Err("this mode is private to the shim".to_owned());
        };
        // The bundle's lock is this process's too, and its worker's (see `RootMount`).
        let lock = lock.to_str().and_then(|lock| lock.parse().ok());
        let lock = lock.ok_or("this mode is private to the shim")?;
        // SAFETY: a lock that is not open here fails the call, which owns nothing.
        let lock = unsafe { std::os::fd::BorrowedFd::borrow_raw(lock) };
        rustix::fs::flock(lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|error| format!("the bundle's lock is not this process's: {error}"))?;
        let mounts: Vec<(String, String, Vec<String>)> =
            serde_json::from_str(&mounts.to_string_lossy()).map_err(|error| error.to_string())?;
        for (kind, source, options) in &mounts {
            containerd_shim::mount::mount_rootfs(Some(kind), Some(source), options, target)
                .map_err(|error| format!("{kind} mount of {source}: {error}"))?;
        }
        Ok(())
    })();
    if let Err(error) = mounted {
        eprintln!("{error}");
        std::process::exit(1);
    }
    std::process::exit(0)
}
