// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! What Unix platforms share: private directories (0700), the `flock`s of the state and bundle
//! directories, and the bridge's Unix sockets.

use std::fs::Permissions;
use std::io;
use std::os::fd::{IntoRawFd as _, OwnedFd};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use containerd_shim::protos::ttrpc;
use rustix::fs::{FlockOperation, Mode, OFlags};

/// An exclusive `flock` on a directory, close-on-exec.
pub type Lock = OwnedFd;

/// On disk for root (an archive is as large as its image), or in `XDG_RUNTIME_DIR`, or in the
/// temporary directory.
pub fn default_state_root() -> PathBuf {
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

/// Creates the directory `path` and its missing parents, 0700.
pub fn create_dir(path: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

/// Creates the directory `path` if missing, as [`create_dir`]; if the daemon is root, lets others
/// traverse it (0711), for the broker's user.
pub fn create_traversable(path: &Path) -> io::Result<()> {
    create_dir(path)?;
    if rustix::process::geteuid().is_root() {
        std::fs::set_permissions(path, Permissions::from_mode(0o711))?;
    }
    Ok(())
}

/// Creates the root `root` (the state root, or a socket root outside it) with
/// [`create_traversable`]; fails unless it is a directory, not a symlink, of this user's, that
/// nobody else can write: below it, nobody else can plant a symlink.
pub fn private_root(root: &Path) -> io::Result<()> {
    create_dir(root)?;
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::other(format!(
            "the state root {} is not a directory that only this user can write",
            root.display()
        )));
    }
    create_traversable(root)
}

/// Locks the directory `path` unless it is missing or locked.
pub fn lock(path: &Path) -> Option<Lock> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let dir = rustix::fs::open(path, flags, Mode::empty()).ok()?;
    rustix::fs::flock(&dir, FlockOperation::NonBlockingLockExclusive).ok()?;
    // The directory may have been removed by its last owner since it was opened, and another one
    // created in its place: only the one at the path counts.
    let (locked, current) = (rustix::fs::fstat(&dir).ok()?, rustix::fs::stat(path).ok()?);
    (locked.st_dev == current.st_dev && locked.st_ino == current.st_ino).then_some(dir)
}

/// Locks the directory `path`, waiting up to `timeout` for its holders.
pub fn wait_lock(path: &Path, timeout: Duration) -> io::Result<Lock> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let dir = rustix::fs::open(path, flags, Mode::empty())?;
    let deadline = Instant::now() + timeout;
    loop {
        match rustix::fs::flock(&dir, FlockOperation::NonBlockingLockExclusive) {
            Err(rustix::io::Errno::WOULDBLOCK) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            locked => return locked.map(|()| dir).map_err(io::Error::from),
        }
    }
}

/// Connects to the broker's bridge at `path` and asks it for the guest service.
pub fn connect_bridge(path: &Path) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    super::handshake(&mut stream)?;
    stream.set_read_timeout(None)?;
    Ok(stream)
}

/// A ttrpc client on the guest service's `stream`.
pub fn client(stream: UnixStream) -> ttrpc::Result<ttrpc::Client> {
    ttrpc::Client::new(stream.into_raw_fd())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::private_root;

    #[test]
    fn a_state_root_must_be_a_directory_only_its_user_writes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        private_root(&root).unwrap();
        let mode = std::fs::metadata(&root).unwrap().permissions().mode();
        let root_mode = if rustix::process::geteuid().is_root() {
            0o711
        } else {
            0o700
        };
        assert_eq!(mode & 0o777, root_mode);
        std::os::unix::fs::symlink(&root, dir.path().join("link")).unwrap();
        assert!(private_root(&dir.path().join("link")).is_err());
        for (mode, accepted) in [(0o755, true), (0o720, false), (0o702, false)] {
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(private_root(&root).is_ok(), accepted, "{mode:o}");
        }
    }
}
