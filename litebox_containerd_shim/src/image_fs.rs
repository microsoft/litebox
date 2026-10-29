// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A file system backend that serves a host directory as a container image: [`LocalFs`] with
//! container symlink semantics.
//!
//! `LocalFs` takes an absolute symlink target for a host path: it rewrites one below its root and
//! refuses any other. In a container image such a target names a path of the container, so
//! [`ImageFs`] returns symlink targets verbatim, and the resolver restarts absolute ones at the
//! guest's root. Every other operation is `LocalFs`'s own.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use litebox_broker_core::fs::backend::{
    Backend, BackendHandles, CreationMetadata, DirHandle, FileHandle, FileTerminal, HandleRef,
    Permissioned, SeekBehavior, WalkOutcome, WalkingDirHandle,
};
use litebox_broker_core::fs::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, SymlinkError, TruncateError, UnlinkError, WalkError, WriteError,
};
use litebox_broker_core::fs::inode_allocator::InodeAllocator;
use litebox_broker_core::fs::{DirEntry, FileStatus, Mode, OFlags};
use litebox_broker_core::readiness::ReadinessSource;
use litebox_broker_userland::fs::LocalFs;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

/// A host directory served as a container image.
///
/// Like `LocalFs`, it assumes that nothing but the broker changes the directory while it is
/// served (guests cannot create symlinks or rename).
pub(crate) struct ImageFs {
    inner: LocalFs,
    /// The canonical host path of the root.
    root: PathBuf,
}

/// A directory being walked, with its host path.
pub(crate) struct WalkingDir<'a> {
    inner: WalkingDirHandle<'a>,
    path: PathBuf,
}

/// An open directory, with its host path.
#[derive(Clone)]
pub(crate) struct Dir {
    inner: DirHandle,
    path: PathBuf,
}

impl BackendHandles for ImageFs {
    type WalkingDirHandle<'a> = WalkingDir<'a>;
    /// Files are `LocalFs`'s own handles.
    type FileHandle = <LocalFs as BackendHandles>::FileHandle;
    type DirHandle = Dir;
}

impl ImageFs {
    pub(crate) fn new(root: &Path, allocator: InodeAllocator) -> io::Result<Self> {
        let root = fs::canonicalize(root)?;
        Ok(Self {
            inner: LocalFs::new(&root, allocator)?,
            root,
        })
    }

    fn walking(inner: WalkingDirHandle<'_>, path: PathBuf) -> WalkingDirHandle<'_> {
        WalkingDirHandle::from_typed::<Self>(WalkingDir { inner, path })
    }

    fn dir(inner: DirHandle, path: PathBuf) -> DirHandle {
        DirHandle::from_typed::<Self>(Dir { inner, path })
    }

    fn inner_ref(handle: HandleRef<'_>) -> HandleRef<'_> {
        match handle {
            HandleRef::Dir(dir) => HandleRef::Dir(&dir.get_typed::<Self>().inner),
            file @ HandleRef::File(_) => file,
        }
    }
}

impl Backend for ImageFs {
    fn root(&self) -> WalkingDirHandle<'_> {
        Self::walking(self.inner.root(), self.root.clone())
    }

    fn walk_directories<'a>(
        &'a self,
        from: WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<WalkOutcome<WalkingDirHandle<'a>>, WalkError> {
        let WalkingDir { inner, mut path } = from.into_typed::<Self>();
        let outcome = self.inner.walk_directories(inner, components)?;
        // `LocalFs` walks only into directories, never through host symlinks, and validates
        // each name it walks, so the path names the walked directory.
        path.extend(&components[..outcome.components.len()]);
        Ok(WalkOutcome {
            components: outcome.components,
            last: Self::walking(outcome.last, path),
            stop_reason: outcome.stop_reason,
        })
    }

    fn read_link_at(&self, dir: &WalkingDirHandle<'_>, name: &str) -> Result<String, WalkError> {
        let dir = dir.as_typed::<Self>();
        if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\0']) {
            return Err(PathError::InvalidPathname.into());
        }
        // A handle of another instance could name a directory outside this root.
        if !dir.path.starts_with(&self.root) {
            return Err(WalkError::Io);
        }
        let target = fs::read_link(dir.path.join(name)).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => PathError::NoSuchFileOrDirectory.into(),
            io::ErrorKind::InvalidInput => PathError::InvalidPathname.into(),
            _ => WalkError::Io,
        })?;
        target
            .into_os_string()
            .into_string()
            .map_err(|_| PathError::InvalidPathname.into())
    }

    fn owned_dir_at(
        &self,
        dir: WalkingDirHandle<'_>,
        flags: OFlags,
    ) -> Result<DirHandle, OpenError> {
        let WalkingDir { inner, path } = dir.into_typed::<Self>();
        Ok(Self::dir(self.inner.owned_dir_at(inner, flags)?, path))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<WalkingDirHandle<'a>> {
        let dir = dir.get_typed::<Self>();
        let inner = self.inner.walking_dir_at(&dir.inner)?;
        Some(Self::walking(inner, dir.path.clone()))
    }

    fn open_file_at(
        &self,
        dir: WalkingDirHandle<'_>,
        name: &str,
        flags: OFlags,
    ) -> Result<Permissioned<FileHandle>, OpenError> {
        self.inner
            .open_file_at(dir.into_typed::<Self>().inner, name, flags)
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        self.inner.list_dir_at(handle.into_typed::<Self>().inner)
    }

    fn lookup_at(&self, dir: &DirHandle, name: &str) -> Result<Option<DirEntry>, ReadDirError> {
        self.inner.lookup_at(&dir.get_typed::<Self>().inner, name)
    }

    fn read(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
    ) -> Result<usize, ReadError> {
        self.inner.read(h, buf, offset)
    }

    fn get_static_backing_data(&self, h: &FileHandle) -> Option<&'static [u8]> {
        self.inner.get_static_backing_data(h)
    }

    fn write(
        &self,
        h: &FileHandle,
        buf: &dyn WriteBuffer,
        offset: usize,
    ) -> Result<usize, WriteError> {
        self.inner.write(h, buf, offset)
    }

    fn truncate(&self, h: &FileHandle, length: usize) -> Result<(), TruncateError> {
        self.inner.truncate(h, length)
    }

    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior {
        self.inner.seek_behavior(h)
    }

    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        self.inner.status(Self::inner_ref(h))
    }

    fn terminal(&self, h: &FileHandle) -> Option<FileTerminal> {
        self.inner.terminal(h)
    }

    fn readiness_source(&self, h: &FileHandle) -> Option<Arc<dyn ReadinessSource>> {
        self.inner.readiness_source(h)
    }

    fn create_file_at(
        &self,
        dir: DirHandle,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        self.inner
            .create_file_at(dir.into_typed::<Self>().inner, name, metadata)
    }

    fn symlink_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _target: &str,
        _metadata: CreationMetadata,
    ) -> Result<(), SymlinkError> {
        // Path-based serving assumes guests create no host symlinks; `LocalFs` does not support
        // them either.
        Err(SymlinkError::NotSupported)
    }

    fn mkdir_at(
        &self,
        dir: DirHandle,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        let Dir { inner, path } = dir.into_typed::<Self>();
        // `LocalFs` validated `name` before creating it.
        let created = self.inner.mkdir_at(inner, name, metadata)?;
        Ok(Self::dir(created, path.join(name)))
    }

    fn unlink_at(&self, dir: DirHandle, name: &str) -> Result<(), UnlinkError> {
        self.inner.unlink_at(dir.into_typed::<Self>().inner, name)
    }

    fn rmdir_at(&self, dir: DirHandle, name: &str) -> Result<(), RmdirError> {
        self.inner.rmdir_at(dir.into_typed::<Self>().inner, name)
    }

    fn chmod(&self, h: HandleRef<'_>, mode: Mode) -> Result<(), ChmodError> {
        self.inner.chmod(Self::inner_ref(h), mode)
    }

    fn chown(
        &self,
        h: HandleRef<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        self.inner.chown(Self::inner_ref(h), user, group)
    }
}

#[cfg(test)]
mod tests {
    use litebox_broker_core::fs::composer::Composer;
    use litebox_broker_core::fs::resolver::Resolver;
    use litebox_broker_core::fs::{FileType, UserInfo};

    use super::*;

    #[test]
    fn symlinks_resolve_inside_the_served_root() {
        let host = tempfile::tempdir().unwrap();
        let outside = host.path().join("outside");
        fs::write(&outside, "host").unwrap();
        let root = host.path().join("root");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("data/sub")).unwrap();
        fs::write(root.join("bin/busybox"), "busybox").unwrap();
        let link = |target: &Path, name: &str| std::os::unix::fs::symlink(target, root.join(name));
        link(Path::new("/bin/busybox"), "bin/sh").unwrap();
        link(Path::new("busybox"), "bin/relative").unwrap();
        link(Path::new("../../../../../.."), "data/sub/up").unwrap();
        link(&outside, "bin/outside").unwrap();
        link(Path::new("/missing"), "bin/dangling").unwrap();
        // The image's root is also mounted below itself, where absolute targets still start at
        // the guest's root.
        let resolver = Resolver::<(), _>::new(
            Composer::builder()
                .try_mount("/", |allocator| ImageFs::new(&root, allocator))
                .unwrap()
                .try_mount("/mnt/image", |allocator| ImageFs::new(&root, allocator))
                .unwrap()
                .build()
                .unwrap(),
        );
        let user = UserInfo::ROOT;
        let resolve = |path| resolver.resolve_following_symlinks(user, path);
        let size = |path| {
            resolver
                .file_status(user, path, true)
                .map(|status| status.size)
        };

        assert_eq!(resolver.read_link(user, "/bin/sh").unwrap(), "/bin/busybox");
        assert_eq!(resolve("/bin/sh").unwrap(), "/bin/busybox");
        assert_eq!(resolve("/mnt/image/bin/sh").unwrap(), "/bin/busybox");
        assert_eq!(resolve("/bin/relative").unwrap(), "/bin/busybox");
        assert_eq!(
            resolve("/mnt/image/bin/relative").unwrap(),
            "/mnt/image/bin/busybox"
        );
        assert_eq!(size("/bin/sh").unwrap(), 7);
        assert_eq!(resolve("/data/sub/up").unwrap(), "/");
        assert_eq!(
            resolver.file_status(user, "/bin", false).unwrap().file_type,
            FileType::Directory
        );
        // The host file is not reachable; its path names nothing in the image.
        assert_eq!(
            resolver.read_link(user, "/bin/outside").unwrap(),
            outside.to_str().unwrap()
        );
        assert!(matches!(
            resolve("/bin/outside"),
            Err(WalkError::PathError(PathError::NoSuchFileOrDirectory))
        ));
        assert!(size("/bin/outside").is_err());
        assert!(matches!(
            resolve("/bin/dangling"),
            Err(WalkError::PathError(PathError::NoSuchFileOrDirectory))
        ));
    }
}
