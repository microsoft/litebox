// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! containerd's root file system mounts, made only in the daemon's private mount namespace, so
//! that they live and die with the daemon and never need to be unmounted.

use std::ffi::CString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use containerd_shim::protos::types::mount::Mount;
use rustix::mount::{MountFlags, MountPropagationFlags};
use rustix::thread::UnshareFlags;

use crate::error::{Error, Result};
use crate::spec::ContainerPlan;

/// Linux takes mount data of at most a page.
const MAX_MOUNT_DATA: usize = 4096;

/// Moves the daemon into a mount namespace of its own, whose mounts never reach the host's.
///
/// Must run before the process has a second thread: the mount namespace is per process only
/// then.
pub(crate) fn enter_private_namespace() -> io::Result<()> {
    if fs::read_dir("/proc/self/task")?.count() != 1 {
        return Err(io::Error::other(
            "the mount namespace must be entered single-threaded",
        ));
    }
    // SAFETY: a new mount namespace leaves the descriptor table shared.
    unsafe { rustix::thread::unshare_unsafe(UnshareFlags::NEWNS) }?;
    // Host mount changes still reach the daemon; its own never reach the host.
    rustix::mount::mount_change(
        "/",
        MountPropagationFlags::DOWNSTREAM | MountPropagationFlags::REC,
    )?;
    Ok(())
}

/// Mounts containerd's root file system mounts `rootfs` and returns the root directory of `plan`
/// in `bundle`, once it is known to be a directory.
pub(crate) fn prepare(plan: &ContainerPlan, bundle: &Path, rootfs: &[Mount]) -> Result<PathBuf> {
    // A daemon running as root is always in its private mount namespace: it does not start
    // otherwise.
    if !rootfs.is_empty() && !rustix::process::geteuid().is_root() {
        return Err(Error::precondition(
            "root file system mounts need the shim to run as root",
        ));
    }
    for mount in rootfs {
        mount_rootfs(mount, &bundle.join("rootfs"))?;
    }
    let root = bundle.join(&plan.root);
    if !root.is_dir() {
        return Err(Error::invalid("the root file system is not a directory"));
    }
    Ok(root)
}

/// Mounts one of containerd's root file system mounts onto `target`.
fn mount_rootfs(mount: &Mount, target: &Path) -> Result<()> {
    let typ = mount.type_.as_str();
    if !mount.target.is_empty() {
        return Err(Error::unimplemented(
            "root file system mounts with targets are not supported",
        ));
    }
    let mut flags = MountFlags::empty();
    let mut data = Vec::new();
    for option in &mount.options {
        match option.as_str() {
            "ro" => flags |= MountFlags::RDONLY,
            "rw" => flags -= MountFlags::RDONLY,
            "bind" => flags |= MountFlags::BIND,
            "rbind" => flags |= MountFlags::BIND | MountFlags::REC,
            "nosuid" => flags |= MountFlags::NOSUID,
            "suid" => flags -= MountFlags::NOSUID,
            "nodev" => flags |= MountFlags::NODEV,
            "dev" => flags -= MountFlags::NODEV,
            "noexec" => flags |= MountFlags::NOEXEC,
            "exec" => flags -= MountFlags::NOEXEC,
            "sync" => flags |= MountFlags::SYNCHRONOUS,
            "dirsync" => flags |= MountFlags::DIRSYNC,
            "noatime" => flags |= MountFlags::NOATIME,
            "nodiratime" => flags |= MountFlags::NODIRATIME,
            "relatime" => flags |= MountFlags::RELATIME,
            "strictatime" => flags |= MountFlags::STRICTATIME,
            other => data.push(other),
        }
    }
    let data = data.join(",");
    if data.len() >= MAX_MOUNT_DATA {
        return Err(Error::unimplemented(format!(
            "the options of the {typ} root file system mount exceed a page, which is not \
             supported"
        )));
    }
    let data = CString::new(data)
        .map_err(|_| Error::invalid("root file system mount options contain a NUL byte"))?;
    let failed = |error: rustix::io::Errno| {
        Error::io(&format!("cannot mount the {typ} root file system"), &error)
    };
    let typ = if flags.contains(MountFlags::BIND) {
        ""
    } else {
        typ
    };
    rustix::mount::mount(&mount.source, target, typ, flags, data.as_c_str()).map_err(failed)?;
    if flags.contains(MountFlags::BIND | MountFlags::RDONLY) {
        // A bind mount takes its flags only on a remount.
        rustix::mount::mount_remount(target, flags, c"").map_err(failed)?;
    }
    Ok(())
}
