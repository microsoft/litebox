// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A file system backend that serves a host directory as a container image: [`LocalFs`] with
//! container symlink semantics, bound host files, and an optional read-only view.
//!
//! `LocalFs` takes an absolute symlink target for a host path: it rewrites one below its root and
//! refuses any other. In a container image such a target names a path of the container, so
//! [`ImageFs`] returns symlink targets verbatim, and the resolver restarts absolute ones at the
//! guest's root.
//!
//! A bound host file is served live at its name in an image directory, by a `LocalFs` of its own
//! rooted at the file's host directory, from which only that file is ever reached. It replaces
//! whatever the image has at that name, if anything, and cannot be removed.
//!
//! Every other operation is `LocalFs`'s own.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use litebox_broker_core::fs::backend::{
    Backend, BackendHandles, CreationMetadata, DirHandle, FileHandle, FileTerminal, HandleRef,
    Permissioned, SeekBehavior, WalkOutcome, WalkStopReason, WalkingDirHandle,
};
use litebox_broker_core::fs::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, SymlinkError, TruncateError, UnlinkError, WalkError, WriteError,
};
use litebox_broker_core::fs::inode_allocator::InodeAllocators;
use litebox_broker_core::fs::{DirEntry, FileStatus, FileType, Mode, OFlags};
use litebox_broker_core::readiness::ReadinessSource;
use litebox_broker_userland::fs::LocalFs;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

/// A host file to bind into an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileBind {
    /// The image directory that holds the bound name, relative to the image's root.
    pub(crate) dir: PathBuf,
    pub(crate) name: String,
    /// The host file.
    pub(crate) source: PathBuf,
    pub(crate) read_only: bool,
}

/// A host directory served as a container image.
///
/// Like `LocalFs`, it assumes that nothing but the broker changes the directory while it is
/// served (guests cannot create symlinks or rename).
pub(crate) struct ImageFs {
    inner: LocalFs,
    /// The canonical host path of the root.
    root: PathBuf,
    /// Fails every change of the image with `EROFS`; bound files have their own flag.
    read_only: bool,
    files: Vec<BoundFile>,
}

/// A host file bound into the image.
struct BoundFile {
    /// The host path of the image directory that holds `name`.
    dir: PathBuf,
    name: String,
    /// Rooted at the host file's directory.
    fs: LocalFs,
    /// The host file's name in the root of `fs`.
    source: String,
    read_only: bool,
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

/// An open file: a `LocalFs` handle of the image, or of the bound file at this index.
#[derive(Clone)]
pub(crate) struct File {
    bound: Option<usize>,
    inner: FileHandle,
}

impl BackendHandles for ImageFs {
    type WalkingDirHandle<'a> = WalkingDir<'a>;
    type FileHandle = File;
    type DirHandle = Dir;
}

impl ImageFs {
    /// Serves `root`, with `files` bound into it, drawing an inode allocator for each `LocalFs`
    /// from `allocators`.
    pub(crate) fn new(
        root: &Path,
        read_only: bool,
        files: &[FileBind],
        allocators: &InodeAllocators,
    ) -> io::Result<Self> {
        let root = fs::canonicalize(root)?;
        let inner = LocalFs::new(&root, allocators.next())?;
        let files = files
            .iter()
            .map(|bind| {
                // Served by its real name, which `LocalFs` opens without following symlinks.
                let source = fs::canonicalize(&bind.source)?;
                let (Some(host_dir), Some(name)) = (
                    source.parent(),
                    source.file_name().and_then(|name| name.to_str()),
                ) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a bound file has no usable name",
                    ));
                };
                Ok(BoundFile {
                    dir: root.join(&bind.dir),
                    name: bind.name.clone(),
                    fs: LocalFs::new(host_dir, allocators.next())?,
                    source: name.to_owned(),
                    read_only: bind.read_only,
                })
            })
            .collect::<io::Result<_>>()?;
        Ok(Self {
            inner,
            root,
            read_only,
            files,
        })
    }

    fn walking(inner: WalkingDirHandle<'_>, path: PathBuf) -> WalkingDirHandle<'_> {
        WalkingDirHandle::from_typed::<Self>(WalkingDir { inner, path })
    }

    fn dir(inner: DirHandle, path: PathBuf) -> DirHandle {
        DirHandle::from_typed::<Self>(Dir { inner, path })
    }

    /// The file bound at `name` in the image directory with the host path `dir`.
    fn bound(&self, dir: &Path, name: &str) -> Option<(usize, &BoundFile)> {
        self.files
            .iter()
            .enumerate()
            .find(|(_, file)| file.name == name && file.dir == dir)
    }

    /// The entry of a bound file, unless its host file is gone.
    fn bound_entry(file: &BoundFile) -> Option<DirEntry> {
        let opened = file
            .fs
            .open_file_at(file.fs.root(), &file.source, OFlags::PATH)
            .ok()?;
        let status = file.fs.status(HandleRef::File(&opened.item)).ok()?;
        Some(DirEntry {
            name: file.name.clone(),
            file_type: status.file_type,
            ino_info: Some(status.node_info),
        })
    }

    /// The `LocalFs` that serves `file`, its handle there, and whether it is read-only.
    fn file<'h>(&self, file: &'h FileHandle) -> (&LocalFs, &'h FileHandle, bool) {
        let file = file.get_typed::<Self>();
        // A foreign index falls back to the image's `LocalFs`, which rejects foreign handles.
        match file.bound.and_then(|index| self.files.get(index)) {
            Some(bound) => (&bound.fs, &file.inner, bound.read_only),
            None => (&self.inner, &file.inner, self.read_only),
        }
    }

    /// Like [`Self::file`], for a file or directory.
    fn handle<'h>(&self, handle: HandleRef<'h>) -> (&LocalFs, HandleRef<'h>, bool) {
        match handle {
            HandleRef::Dir(dir) => (
                &self.inner,
                HandleRef::Dir(&dir.get_typed::<Self>().inner),
                self.read_only,
            ),
            HandleRef::File(file) => {
                let (fs, file, read_only) = self.file(file);
                (fs, HandleRef::File(file), read_only)
            }
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
        // A bound name is a regular file, whatever the image has there.
        let bound = components
            .iter()
            .scan(path.clone(), |dir, name| {
                let bound = self.bound(dir, name).is_some();
                dir.push(name);
                Some(bound)
            })
            .position(|bound| bound);
        let walk = &components[..bound.unwrap_or(components.len())];
        let outcome = if walk.is_empty() {
            WalkOutcome {
                components: Vec::new(),
                last: inner,
                stop_reason: WalkStopReason::CompleteDirectory,
            }
        } else {
            self.inner.walk_directories(inner, walk)?
        };
        // `LocalFs` walks only into directories, never through host symlinks, and validates
        // each name it walks, so the path names the walked directory.
        path.extend(&components[..outcome.components.len()]);
        let stop_reason = match outcome.stop_reason {
            WalkStopReason::CompleteDirectory if bound.is_some() => {
                WalkStopReason::StoppedAtNonDirectory {
                    file_type: FileType::RegularFile,
                }
            }
            reason => reason,
        };
        Ok(WalkOutcome {
            components: outcome.components,
            last: Self::walking(outcome.last, path),
            stop_reason,
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
        // A bound file is not a symlink.
        if self.bound(&dir.path, name).is_some() {
            return Err(PathError::InvalidPathname.into());
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
        let WalkingDir { inner, path } = dir.into_typed::<Self>();
        let writes = !flags.contains(OFlags::PATH)
            && flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::TRUNC);
        let (bound, opened) = match self.bound(&path, name) {
            Some((_, file)) if writes && file.read_only => {
                return Err(OpenError::ReadOnlyFileSystem);
            }
            Some((index, file)) => (
                Some(index),
                file.fs.open_file_at(file.fs.root(), &file.source, flags)?,
            ),
            None if writes && self.read_only => return Err(OpenError::ReadOnlyFileSystem),
            None => (None, self.inner.open_file_at(inner, name, flags)?),
        };
        Ok(Permissioned {
            item: FileHandle::from_typed::<Self>(File {
                bound,
                inner: opened.item,
            }),
            permissions: opened.permissions,
        })
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        let Dir { inner, path } = handle.into_typed::<Self>();
        let mut entries = self.inner.list_dir_at(inner)?;
        for file in self.files.iter().filter(|file| file.dir == path) {
            entries.retain(|entry| entry.name != file.name);
            entries.extend(Self::bound_entry(file));
        }
        Ok(entries)
    }

    fn lookup_at(&self, dir: &DirHandle, name: &str) -> Result<Option<DirEntry>, ReadDirError> {
        let dir = dir.get_typed::<Self>();
        match self.bound(&dir.path, name) {
            Some((_, file)) => Ok(Self::bound_entry(file)),
            None => self.inner.lookup_at(&dir.inner, name),
        }
    }

    fn read(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
    ) -> Result<usize, ReadError> {
        let (fs, h, _) = self.file(h);
        fs.read(h, buf, offset)
    }

    fn get_static_backing_data(&self, h: &FileHandle) -> Option<&'static [u8]> {
        let (fs, h, _) = self.file(h);
        fs.get_static_backing_data(h)
    }

    // A read-only file is never open for writing, so `LocalFs` fails its writes and truncations.
    fn write(
        &self,
        h: &FileHandle,
        buf: &dyn WriteBuffer,
        offset: usize,
    ) -> Result<usize, WriteError> {
        let (fs, h, _) = self.file(h);
        fs.write(h, buf, offset)
    }

    fn truncate(&self, h: &FileHandle, length: usize) -> Result<(), TruncateError> {
        let (fs, h, _) = self.file(h);
        fs.truncate(h, length)
    }

    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior {
        let (fs, h, _) = self.file(h);
        fs.seek_behavior(h)
    }

    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        let (fs, h, _) = self.handle(h);
        fs.status(h)
    }

    fn terminal(&self, h: &FileHandle) -> Option<FileTerminal> {
        let (fs, h, _) = self.file(h);
        fs.terminal(h)
    }

    fn readiness_source(&self, h: &FileHandle) -> Option<Arc<dyn ReadinessSource>> {
        let (fs, h, _) = self.file(h);
        fs.readiness_source(h)
    }

    fn create_file_at(
        &self,
        dir: DirHandle,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        let Dir { inner, path } = dir.into_typed::<Self>();
        if self.bound(&path, name).is_some() {
            return Err(OpenError::AlreadyExists);
        }
        if self.read_only {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        let inner = self.inner.create_file_at(inner, name, metadata)?;
        Ok(FileHandle::from_typed::<Self>(File { bound: None, inner }))
    }

    fn symlink_at(
        &self,
        dir: DirHandle,
        name: &str,
        _target: &str,
        _metadata: CreationMetadata,
    ) -> Result<(), SymlinkError> {
        // As on Linux, an existing name fails with `EEXIST` before a read-only one with `EROFS`.
        if self.bound(&dir.into_typed::<Self>().path, name).is_some() {
            return Err(SymlinkError::AlreadyExists);
        }
        if self.read_only {
            return Err(SymlinkError::ReadOnlyFileSystem);
        }
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
        // As on Linux, an existing name fails with `EEXIST` before a read-only one with `EROFS`.
        if self.bound(&path, name).is_some()
            || (self.read_only && fs::symlink_metadata(path.join(name)).is_ok())
        {
            return Err(MkdirError::AlreadyExists);
        }
        if self.read_only {
            return Err(MkdirError::ReadOnlyFileSystem);
        }
        // `LocalFs` validated `name` before creating it.
        let created = self.inner.mkdir_at(inner, name, metadata)?;
        Ok(Self::dir(created, path.join(name)))
    }

    fn unlink_at(&self, dir: DirHandle, name: &str) -> Result<(), UnlinkError> {
        let Dir { inner, path } = dir.into_typed::<Self>();
        // Linux would fail with `EBUSY`, which `UnlinkError` cannot express.
        if self.read_only || self.bound(&path, name).is_some() {
            return Err(UnlinkError::ReadOnlyFileSystem);
        }
        self.inner.unlink_at(inner, name)
    }

    fn rmdir_at(&self, dir: DirHandle, name: &str) -> Result<(), RmdirError> {
        let Dir { inner, path } = dir.into_typed::<Self>();
        if self.bound(&path, name).is_some() {
            return Err(RmdirError::NotADirectory);
        }
        if self.read_only {
            return Err(RmdirError::ReadOnlyFileSystem);
        }
        // `LocalFs` sees only the image's entries.
        let target = path.join(name);
        if self.files.iter().any(|file| file.dir == target) {
            return Err(RmdirError::NotEmpty);
        }
        self.inner.rmdir_at(inner, name)
    }

    fn chmod(&self, h: HandleRef<'_>, mode: Mode) -> Result<(), ChmodError> {
        match self.handle(h) {
            (_, _, true) => Err(ChmodError::ReadOnlyFileSystem),
            (fs, h, false) => fs.chmod(h, mode),
        }
    }

    fn chown(
        &self,
        h: HandleRef<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        match self.handle(h) {
            (_, _, true) => Err(ChownError::ReadOnlyFileSystem),
            (fs, h, false) => fs.chown(h, user, group),
        }
    }
}

#[cfg(test)]
mod tests {
    use litebox_broker_core::fs::UserInfo;
    use litebox_broker_core::fs::composer::Composer;
    use litebox_broker_core::fs::resolver::Resolver;

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
                .try_mount_nestable("/", |allocators| {
                    ImageFs::new(&root, false, &[], allocators)
                })
                .unwrap()
                .try_mount_nestable("/mnt/image", |allocators| {
                    ImageFs::new(&root, false, &[], allocators)
                })
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

    #[test]
    fn bound_files_shadow_the_image_and_read_only_views_refuse_changes() {
        let host = tempfile::tempdir().unwrap();
        let root = host.path().join("root");
        fs::create_dir_all(root.join("etc/sub")).unwrap();
        fs::write(root.join("etc/passwd"), "image").unwrap();
        std::os::unix::fs::symlink("/run/resolv.conf", root.join("etc/resolv.conf")).unwrap();
        let hosts = host.path().join("hosts");
        fs::write(&hosts, "hosts").unwrap();
        // Bound by its real name through a host symlink.
        fs::write(host.path().join("resolv"), "resolv").unwrap();
        let resolv = host.path().join("resolv-link");
        std::os::unix::fs::symlink("resolv", &resolv).unwrap();
        let bind = |name: &str, source: &Path, read_only| FileBind {
            dir: "etc".into(),
            name: name.into(),
            source: source.to_owned(),
            read_only,
        };
        // The image has no `hosts`, and a symlink at `resolv.conf`.
        let files = [
            bind("hosts", &hosts, false),
            bind("resolv.conf", &resolv, true),
        ];
        // A writable image with an otherwise empty directory that holds a bound file.
        let writable = host.path().join("writable");
        fs::create_dir_all(writable.join("etc")).unwrap();
        let resolver = Resolver::<(), _>::new(
            Composer::builder()
                .try_mount_nestable("/", |allocators| {
                    ImageFs::new(&root, true, &files, allocators)
                })
                .unwrap()
                .try_mount_nestable("/rw", |allocators| {
                    ImageFs::new(&writable, false, &files[..1], allocators)
                })
                .unwrap()
                .build()
                .unwrap(),
        );
        let user = UserInfo::ROOT;
        let open = |path, flags| resolver.open(user, path, flags, Mode::from_bits_truncate(0o644));
        let read = |path| {
            let mut entry = open(path, OFlags::RDONLY).unwrap();
            let mut buffer = [0; 16];
            let read = resolver.read(&mut entry, &mut buffer, None).unwrap();
            String::from_utf8(buffer[..read].to_vec()).unwrap()
        };

        assert_eq!(read("/etc/hosts"), "hosts");
        assert_eq!(read("/etc/resolv.conf"), "resolv");
        assert_eq!(read("/etc/passwd"), "image");
        let status = resolver
            .file_status(user, "/etc/resolv.conf", false)
            .unwrap();
        assert_eq!(status.file_type, FileType::RegularFile);
        assert!(matches!(
            resolver.read_link(user, "/etc/resolv.conf"),
            Err(WalkError::PathError(PathError::InvalidPathname))
        ));
        let directory = open("/etc", OFlags::RDONLY | OFlags::DIRECTORY).unwrap();
        let mut names: Vec<_> = resolver
            .read_dir(&directory)
            .unwrap()
            .into_iter()
            .map(|entry| (entry.name, entry.file_type, entry.ino_info.is_some()))
            .collect();
        names.sort_by(|a, b| a.0.cmp(&b.0));
        let file = |name: &str| (name.to_owned(), FileType::RegularFile, true);
        let dir = |name: &str, known| (name.to_owned(), FileType::Directory, known);
        assert_eq!(
            names,
            [
                dir(".", false),
                dir("..", false),
                file("hosts"),
                file("passwd"),
                file("resolv.conf"),
                dir("sub", true),
            ]
        );
        assert!(matches!(
            open("/etc/hosts/x", OFlags::RDONLY),
            Err(OpenError::PathError(PathError::ComponentNotADirectory))
        ));

        // The read-write bound file writes through to the host, but stays bound.
        let mut entry = open("/etc/hosts", OFlags::WRONLY | OFlags::TRUNC).unwrap();
        resolver.write(&mut entry, b"guest", None).unwrap();
        assert_eq!(fs::read_to_string(&hosts).unwrap(), "guest");
        resolver
            .chmod(user, "/etc/hosts", Mode::from_bits_truncate(0o600))
            .unwrap();
        assert!(matches!(
            resolver.unlink(user, "/etc/hosts"),
            Err(UnlinkError::ReadOnlyFileSystem)
        ));
        assert!(matches!(
            resolver.rmdir(user, "/etc/hosts"),
            Err(RmdirError::NotADirectory)
        ));
        assert!(matches!(
            resolver.mkdir(user, "/etc/hosts", Mode::RWXU),
            Err(MkdirError::AlreadyExists)
        ));
        assert!(matches!(
            open("/etc/hosts", OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY),
            Err(OpenError::AlreadyExists)
        ));
        assert!(matches!(
            resolver.symlink(user, "/x", "/etc/hosts"),
            Err(SymlinkError::AlreadyExists)
        ));
        // A directory that holds a bound file is not empty, even without an image entry.
        assert!(matches!(
            resolver.rmdir(user, "/rw/etc"),
            Err(RmdirError::NotEmpty)
        ));
        assert_eq!(read("/rw/etc/hosts"), "guest");
        assert!(matches!(
            resolver.symlink(user, "/x", "/rw/etc/link"),
            Err(SymlinkError::NotSupported)
        ));

        // The read-only bound file and the read-only image refuse every change.
        let read_only = |result: Result<_, OpenError>| {
            assert!(matches!(result, Err(OpenError::ReadOnlyFileSystem)));
        };
        read_only(open("/etc/resolv.conf", OFlags::RDWR));
        read_only(open("/etc/passwd", OFlags::WRONLY));
        read_only(open("/etc/passwd", OFlags::RDONLY | OFlags::TRUNC));
        read_only(open("/etc/new", OFlags::CREAT | OFlags::WRONLY));
        assert!(matches!(
            resolver.symlink(user, "/x", "/etc/new"),
            Err(SymlinkError::ReadOnlyFileSystem)
        ));
        assert!(matches!(
            resolver.mkdir(user, "/etc/new", Mode::RWXU),
            Err(MkdirError::ReadOnlyFileSystem)
        ));
        assert!(matches!(
            resolver.mkdir(user, "/etc/sub", Mode::RWXU),
            Err(MkdirError::AlreadyExists)
        ));
        assert!(matches!(
            resolver.rmdir(user, "/etc/sub"),
            Err(RmdirError::ReadOnlyFileSystem)
        ));
        assert!(matches!(
            resolver.unlink(user, "/etc/passwd"),
            Err(UnlinkError::ReadOnlyFileSystem)
        ));
        for path in ["/etc/passwd", "/etc/sub", "/etc/resolv.conf"] {
            assert!(matches!(
                resolver.chmod(user, path, Mode::RWXU),
                Err(ChmodError::ReadOnlyFileSystem)
            ));
            assert!(matches!(
                resolver.chown(user, path, Some(0), None),
                Err(ChownError::ReadOnlyFileSystem)
            ));
        }
        assert_eq!(
            fs::read_to_string(root.join("etc/passwd")).unwrap(),
            "image"
        );
        assert_eq!(read("/etc/resolv.conf"), "resolv");
    }
}
