// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A network file system, using the FUSE protocol
//!
//! This module provides a [`Fuse`] [`Backend`](super::backend::Backend) that accesses files on a
//! FUSE server, such as `virtiofsd` behind a virtio-fs device. Unlike 9P's fids, FUSE addresses
//! files by node ids the server hands out on lookup, each to be forgotten once unused, and files
//! (and directories) are opened as separate handles, each to be released.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::NonZeroU64;

use thiserror::Error;

use super::OFlags;
use super::backend::{
    DirHandle, FileHandle, HandleRef, PermissionCheck, Permissioned, SeekBehavior, WalkOutcome,
    WalkStopReason, WalkedComponent, WalkingDirHandle,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, TruncateError, UnlinkError, WalkError, WriteError,
};
use litebox_platform::sync;

mod abi;
mod client;
#[cfg(all(test, target_os = "linux"))]
mod tests;

pub mod transport;

/// A [`Backend`](super::backend::Backend) backed by a FUSE server.
///
/// All file operations are translated into FUSE requests sent to the server, which is
/// authoritative for permissions, as whatever identity it checks them against: requests carry
/// uid and gid 0, except that creating a file or directory carries its requested owner (see
/// [`CreationMetadata`](super::backend::CreationMetadata)). As every walked component is
/// [`PermissionCheck::ByBackend`], the resolver checks none itself, so this backend does not
/// isolate the resolver's users from one another: any of them may do whatever the server allows
/// a request from uid 0. (Linux's virtio-fs client checks permissions itself, against the
/// caller's identity, with `default_permissions`; servers such as `virtiofsd` rely on that.)
///
/// # Type Parameters
///
/// - `Platform`: The platform provider that supplies synchronization primitives.
/// - `T`: The transport to the server.
pub struct Fuse<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> {
    client: Arc<client::Client<Platform, T>>,
    /// The root directory, which needs no lookup, and is never forgotten.
    root: Arc<Node<Platform, T>>,
    /// Device id reported in every [`NodeInfo`](super::NodeInfo) from this backend; inode numbers
    /// come from the server's attributes instead.
    device_id: u64,
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> Fuse<Platform, T> {
    /// Construct a new `Fuse` backend, negotiating the protocol with the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails, or the server's protocol version is unsupported.
    pub fn new(
        transport: T,
        inode_allocator: super::inode_allocator::InodeAllocator,
    ) -> Result<Self, Error> {
        let client = Arc::new(client::Client::new(transport)?);
        Ok(Self {
            root: Arc::new(Node {
                id: abi::ROOT_ID,
                lookups: 0,
                client: Arc::clone(&client),
            }),
            client,
            device_id: inode_allocator.device_id(),
        })
    }

    /// Tie a node the server just counted a lookup of to this backend's client, so that it is
    /// forgotten once the last handle referring to it goes away.
    fn own(&self, entry: &abi::EntryOut) -> Arc<Node<Platform, T>> {
        Arc::new(Node {
            id: entry.nodeid,
            lookups: 1,
            client: Arc::clone(&self.client),
        })
    }

    /// Open `node`, with Linux `open(2)` `flags`, so that it is released once the last handle
    /// referring to it goes away.
    fn open(
        &self,
        node: &Arc<Node<Platform, T>>,
        flags: u32,
        dir: bool,
    ) -> Result<Arc<Open<Platform, T>>, Error> {
        let fh = self.client.open(node.id, flags, dir)?;
        Ok(Arc::new(Open {
            node: Arc::clone(node),
            fh,
            flags,
            dir,
        }))
    }

    fn file_status(&self, attr: &abi::Attr) -> Result<super::FileStatus, Error> {
        Ok(super::FileStatus {
            file_type: mode_to_file_type(attr.mode),
            mode: super::Mode::from_u32_bits_truncate(attr.mode),
            size: attr.size,
            owner: super::UserInfo {
                user: u16::try_from(attr.uid).map_err(|_| Error::InvalidResponse)?,
                group: u16::try_from(attr.gid).map_err(|_| Error::InvalidResponse)?,
            },
            node_info: super::NodeInfo {
                dev: self.device_id,
                ino: attr.ino,
                rdev: NonZeroU64::new(attr.rdev.into()),
            },
            blksize: attr.blksize.into(),
        })
    }
}

/// A node whose lookups are forgotten when the last handle referring to it goes away.
///
/// [`Backend`](super::backend::Backend) has no close hook, so the `FUSE_FORGET` has to ride on
/// `Drop`. Handles hold this behind an [`Arc`], so incidental handle clones do not forget; only
/// the last reference does.
struct Node<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> {
    id: u64,
    /// How many lookups of the node the server counted for this reference; zero for the root.
    lookups: u64,
    client: Arc<client::Client<Platform, T>>,
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> Drop
    for Node<Platform, T>
{
    fn drop(&mut self) {
        if self.lookups > 0 {
            self.client.forget(self.id, self.lookups);
        }
    }
}

/// An open file or directory, released when the last handle referring to it goes away.
struct Open<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> {
    /// Kept until after the release, which addresses the node.
    node: Arc<Node<Platform, T>>,
    fh: u64,
    /// The flags it was opened with, which the release repeats.
    flags: u32,
    dir: bool,
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> Drop
    for Open<Platform, T>
{
    fn drop(&mut self) {
        self.node
            .client
            .release(self.node.id, self.fh, self.flags, self.dir);
    }
}

/// Walking directory handle
pub struct FuseWalkingDirHandle<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport>
{
    /// The directory itself.
    dir: Arc<Node<Platform, T>>,
    /// Where the walk stopped at a non-directory: its name in `dir`, and its node, which saves
    /// `open_file_at` a lookup of its own.
    stopped_at: Option<(String, Arc<Node<Platform, T>>)>,
}

/// Directory handle
pub struct FuseDirHandle<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> {
    node: Arc<Node<Platform, T>>,
    /// `None` for an `O_PATH` handle, which is not opened server-side.
    open: Option<Arc<Open<Platform, T>>>,
}
impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> Clone
    for FuseDirHandle<Platform, T>
{
    fn clone(&self) -> Self {
        Self {
            node: Arc::clone(&self.node),
            open: self.open.clone(),
        }
    }
}

/// File handle
pub struct FuseFileHandle<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> {
    node: Arc<Node<Platform, T>>,
    /// `None` for an `O_PATH` handle, which is not opened server-side.
    open: Option<Arc<Open<Platform, T>>>,
}
impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> Clone
    for FuseFileHandle<Platform, T>
{
    fn clone(&self) -> Self {
        Self {
            node: Arc::clone(&self.node),
            open: self.open.clone(),
        }
    }
}

impl<Platform, T> super::backend::BackendHandles for Fuse<Platform, T>
where
    Platform: sync::RawSyncPrimitivesProvider + 'static,
    T: transport::Transport + Send + 'static,
{
    type WalkingDirHandle<'a> = FuseWalkingDirHandle<Platform, T>;
    type FileHandle = FuseFileHandle<Platform, T>;
    type DirHandle = FuseDirHandle<Platform, T>;
}

impl<Platform, T> Fuse<Platform, T>
where
    Platform: sync::RawSyncPrimitivesProvider + 'static,
    T: transport::Transport + Send + 'static,
{
    /// The node and open file handle (if any) `h` refers to.
    fn handle_parts(h: HandleRef<'_>) -> (&Arc<Node<Platform, T>>, Option<u64>) {
        let (node, open) = match h {
            HandleRef::File(h) => {
                let h = h.get_typed::<Self>();
                (&h.node, &h.open)
            }
            HandleRef::Dir(h) => {
                let h = h.get_typed::<Self>();
                (&h.node, &h.open)
            }
        };
        (node, open.as_ref().map(|open| open.fh))
    }

    fn setattr(&self, h: HandleRef<'_>, mut attr: client::SetAttr) -> Result<(), Error> {
        let (node, fh) = Self::handle_parts(h);
        if let Some(fh) = fh {
            attr.valid |= abi::fattr::FH;
            attr.fh = fh;
        }
        self.client.setattr(node.id, attr)?;
        Ok(())
    }
}

impl<Platform, T> super::backend::Backend for Fuse<Platform, T>
where
    Platform: sync::RawSyncPrimitivesProvider + 'static,
    T: transport::Transport + Send + 'static,
{
    fn root(&self) -> WalkingDirHandle<'_> {
        WalkingDirHandle::from_typed::<Self>(FuseWalkingDirHandle {
            dir: Arc::clone(&self.root),
            stopped_at: None,
        })
    }

    fn walk_directories<'a>(
        &'a self,
        from: WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<WalkOutcome<WalkingDirHandle<'a>>, WalkError> {
        assert_ne!(components, [] as [&str; 0]);
        // A walk that stopped at a non-directory is a handle on its parent directory.
        let mut dir = from.into_typed::<Self>().dir;
        for (walked, &name) in components.iter().enumerate() {
            // FUSE looks up a component at a time.
            let entry = self.client.lookup(dir.id, name)?;
            let node = self.own(&entry);
            if !entry.attr.is_dir() {
                return Ok(WalkOutcome {
                    components: backend_checked_components(walked),
                    last: WalkingDirHandle::from_typed::<Self>(FuseWalkingDirHandle {
                        dir,
                        stopped_at: Some((String::from(name), node)),
                    }),
                    stop_reason: WalkStopReason::StoppedAtNonDirectory,
                });
            }
            dir = node;
        }
        Ok(WalkOutcome {
            components: backend_checked_components(components.len()),
            last: WalkingDirHandle::from_typed::<Self>(FuseWalkingDirHandle {
                dir,
                stopped_at: None,
            }),
            stop_reason: WalkStopReason::CompleteDirectory,
        })
    }

    fn owned_dir_at(
        &self,
        dir: WalkingDirHandle<'_>,
        flags: OFlags,
    ) -> Result<DirHandle, OpenError> {
        assert_supported_oflags(flags);
        let node = dir.into_typed::<Self>().dir;
        let open = if flags.contains(OFlags::PATH) {
            // An `O_PATH` handle is never opened server-side.
            None
        } else {
            // As for 9P, directories are opened for reading only, whatever was asked for.
            Some(self.open(&node, OFlags::DIRECTORY.bits(), true)?)
        };
        Ok(DirHandle::from_typed::<Self>(FuseDirHandle { node, open }))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<WalkingDirHandle<'a>> {
        // Walking only looks nodes up, so sharing the directory's node is fine.
        Some(WalkingDirHandle::from_typed::<Self>(FuseWalkingDirHandle {
            dir: Arc::clone(&dir.get_typed::<Self>().node),
            stopped_at: None,
        }))
    }

    fn open_file_at(
        &self,
        dir: WalkingDirHandle<'_>,
        name: &str,
        flags: OFlags,
    ) -> Result<Permissioned<FileHandle>, OpenError> {
        assert_supported_oflags(flags);
        // TODO: we do not support non-blocking, so ignore that flag instead of returning an error.
        let flags = flags - OFlags::NONBLOCK;
        if flags.contains(OFlags::DIRECTORY) {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }

        let dir = dir.into_typed::<Self>();
        let node = match dir.stopped_at {
            // The walk already looked this very file up.
            Some((walked, node)) if walked == name => node,
            _ => self.own(&self.client.lookup(dir.dir.id, name)?),
        };

        let open = if flags.contains(OFlags::PATH) {
            // An `O_PATH` handle addresses the file without opening it server-side.
            None
        } else {
            // The file exists (it is what stopped the walk), so the creation flags say nothing
            // about how to open it; the resolver enforces `O_CREAT | O_EXCL` itself.
            let truncate = flags.contains(OFlags::TRUNC);
            let mut open_flags = flags - OFlags::CREAT - OFlags::EXCL;
            if !self.client.atomic_o_trunc() {
                open_flags -= OFlags::TRUNC;
            }
            let open = self.open(&node, oflags_to_open(open_flags), false)?;
            if truncate && !self.client.atomic_o_trunc() {
                self.client.setattr(
                    node.id,
                    client::SetAttr {
                        valid: abi::fattr::SIZE | abi::fattr::FH,
                        fh: open.fh,
                        size: 0,
                        ..Default::default()
                    },
                )?;
            }
            Some(open)
        };
        Ok(Permissioned {
            item: FileHandle::from_typed::<Self>(FuseFileHandle { node, open }),
            permissions: PermissionCheck::ByBackend,
        })
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<super::DirEntry>, ReadDirError> {
        let handle = handle.into_typed::<Self>();
        // Reading needs an open directory; an `O_PATH` handle gets one for the occasion.
        let open = match handle.open {
            Some(open) => open,
            None => self.open(&handle.node, OFlags::DIRECTORY.bits(), true)?,
        };
        let entries = self.client.readdir_all(open.node.id, open.fh)?;
        Ok(entries
            .into_iter()
            // The resolver synthesizes `.` and `..` itself.
            .filter(|entry| !matches!(&*entry.name, b"." | b".."))
            .map(|entry| super::DirEntry {
                name: String::from_utf8_lossy(&entry.name).into_owned(),
                file_type: if entry.typ == abi::DT_DIR {
                    super::FileType::Directory
                } else {
                    super::FileType::RegularFile
                },
                ino_info: Some(super::NodeInfo {
                    dev: self.device_id,
                    ino: entry.ino,
                    rdev: None,
                }),
            })
            .collect())
    }

    /// A single `FUSE_LOOKUP`, rather than reading the whole directory.
    fn lookup_at(
        &self,
        dir: &DirHandle,
        name: &str,
    ) -> Result<Option<super::DirEntry>, ReadDirError> {
        // `list_dir_at` reports neither `.` nor `..`, and no name with a `/` or NUL can exist.
        if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\0']) {
            return Ok(None);
        }
        let entry = match self.client.lookup(dir.get_typed::<Self>().node.id, name) {
            Ok(entry) => entry,
            Err(Error::Remote(ENOENT)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        // Only the attributes are needed: forget the node right away.
        drop(self.own(&entry));
        Ok(Some(super::DirEntry {
            name: String::from(name),
            file_type: mode_to_file_type(entry.attr.mode),
            ino_info: Some(super::NodeInfo {
                dev: self.device_id,
                ino: entry.attr.ino,
                rdev: None,
            }),
        }))
    }

    /// As many `FUSE_READ`s as it takes to fill `buf`, short of the end of the file: each
    /// request to the broker costs more than a request to the server.
    fn read(&self, h: &FileHandle, buf: &mut [u8], offset: usize) -> Result<usize, ReadError> {
        let h = h.get_typed::<Self>();
        let open = h.open.as_ref().ok_or(ReadError::NotForReading)?;
        transfer(buf.len(), self.client.max_read(), |done| {
            let offset = offset_after(offset, done).ok_or(ReadError::Io)?;
            Ok(self
                .client
                .read(h.node.id, open.fh, offset, &mut buf[done..])?)
        })
    }

    /// As many `FUSE_WRITE`s as it takes to write all of `buf`, short of the server writing less.
    fn write(&self, h: &FileHandle, buf: &[u8], offset: usize) -> Result<usize, WriteError> {
        let h = h.get_typed::<Self>();
        let open = h.open.as_ref().ok_or(WriteError::NotForWriting)?;
        transfer(buf.len(), self.client.max_write(), |done| {
            let offset = offset_after(offset, done).ok_or(WriteError::Io)?;
            Ok(self
                .client
                .write(h.node.id, open.fh, offset, &buf[done..])?)
        })
    }

    fn truncate(&self, h: &FileHandle, length: usize) -> Result<(), TruncateError> {
        let size = u64::try_from(length).map_err(|_| TruncateError::Io)?;
        Ok(self.setattr(
            HandleRef::File(h),
            client::SetAttr {
                valid: abi::fattr::SIZE,
                size,
                ..Default::default()
            },
        )?)
    }

    fn seek_behavior(&self, _h: &FileHandle) -> SeekBehavior {
        // FUSE reads and writes carry their offsets; the resolver owns positions.
        SeekBehavior::PositionBased
    }

    fn status(&self, h: HandleRef<'_>) -> Result<super::FileStatus, FileStatusError> {
        let (node, fh) = Self::handle_parts(h);
        let attr = self.client.getattr(node.id, fh)?;
        Ok(self.file_status(&attr)?)
    }

    fn create_file_at(
        &self,
        dir: DirHandle,
        name: &str,
        metadata: super::backend::CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        let dir = dir.into_typed::<Self>();
        // NOTE: as with 9P, the server needs an access mode at creation time. The resolver still
        // enforces the caller's read/write intent via its own `read_allowed`/`write_allowed`.
        let flags = (OFlags::RDWR | OFlags::CREAT | OFlags::EXCL).bits();
        let (entry, fh) = self.client.create(
            dir.node.id,
            name,
            flags,
            abi::S_IFREG | u32::from(metadata.mode.bits()),
            credentials(metadata.owner),
        )?;
        let node = self.own(&entry);
        let open = Arc::new(Open {
            node: Arc::clone(&node),
            fh,
            flags,
            dir: false,
        });
        Ok(FileHandle::from_typed::<Self>(FuseFileHandle {
            node,
            open: Some(open),
        }))
    }

    fn mkdir_at(
        &self,
        dir: DirHandle,
        name: &str,
        metadata: super::backend::CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        let dir = dir.into_typed::<Self>();
        let entry = self.client.mkdir(
            dir.node.id,
            name,
            u32::from(metadata.mode.bits()),
            credentials(metadata.owner),
        )?;
        Ok(DirHandle::from_typed::<Self>(FuseDirHandle {
            node: self.own(&entry),
            open: None,
        }))
    }

    fn unlink_at(&self, dir: DirHandle, name: &str) -> Result<(), UnlinkError> {
        let dir = dir.into_typed::<Self>();
        Ok(self.client.remove(dir.node.id, name, false)?)
    }

    fn rmdir_at(&self, dir: DirHandle, name: &str) -> Result<(), RmdirError> {
        let dir = dir.into_typed::<Self>();
        Ok(self.client.remove(dir.node.id, name, true)?)
    }

    fn chmod(&self, h: HandleRef<'_>, mode: super::Mode) -> Result<(), ChmodError> {
        Ok(self.setattr(
            h,
            client::SetAttr {
                valid: abi::fattr::MODE,
                mode: mode.bits().into(),
                ..Default::default()
            },
        )?)
    }

    fn chown(
        &self,
        h: HandleRef<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        // Only the fields actually supplied are marked valid, so the rest are left alone.
        let mut attr = client::SetAttr::default();
        if let Some(user) = user {
            attr.valid |= abi::fattr::UID;
            attr.uid = user.into();
        }
        if let Some(group) = group {
            attr.valid |= abi::fattr::GID;
            attr.gid = group.into();
        }
        Ok(self.setattr(h, attr)?)
    }
}

/// Transfers `len` bytes by `step`s, each given how many bytes are done and transferring at most
/// `max` bytes, until all are done or a step transfers less (e.g., at the end of the file).
///
/// Bytes already transferred are reported rather than a later step's error, as `read(2)` and
/// `write(2)` do.
fn transfer<E>(
    len: usize,
    max: usize,
    mut step: impl FnMut(usize) -> Result<usize, E>,
) -> Result<usize, E> {
    let mut done = 0;
    while done < len {
        let asked = (len - done).min(max);
        match step(done) {
            Ok(n) => {
                done += n;
                if n < asked {
                    break;
                }
            }
            Err(_) if done > 0 => break,
            Err(error) => return Err(error),
        }
    }
    Ok(done)
}

/// The file offset `done` bytes past `offset`.
fn offset_after(offset: usize, done: usize) -> Option<u64> {
    u64::try_from(offset.checked_add(done)?).ok()
}

/// The FUSE server is authoritative for permissions, so every component the backend reports is
/// left for it to check.
fn backend_checked_components(count: usize) -> Vec<WalkedComponent> {
    alloc::vec![
        WalkedComponent {
            permissions: PermissionCheck::ByBackend
        };
        count
    ]
}

/// The credentials to create a file owned by `owner` with.
fn credentials(owner: super::UserInfo) -> abi::Credentials {
    abi::Credentials {
        uid: owner.user.into(),
        gid: owner.group.into(),
    }
}

/// Flags this backend knows how to honor when opening files/directories.
const SUPPORTED_OFLAGS: OFlags = OFlags::CREAT
    .union(OFlags::RDONLY)
    .union(OFlags::WRONLY)
    .union(OFlags::RDWR)
    .union(OFlags::TRUNC)
    .union(OFlags::NOCTTY)
    .union(OFlags::EXCL)
    .union(OFlags::DIRECTORY)
    .union(OFlags::NONBLOCK)
    .union(OFlags::LARGEFILE)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::APPEND)
    .union(OFlags::PATH);

fn assert_supported_oflags(flags: OFlags) {
    if flags.intersects(SUPPORTED_OFLAGS.complement()) {
        unimplemented!("{flags:?}")
    }
}

/// The `open(2)` flags a `FUSE_OPEN` carries, which the server passes to the host's `open(2)`.
///
/// The bits are the guest's Linux [`OFlags`], forwarded untranslated (as is `O_DIRECTORY` with
/// `FUSE_OPENDIR`), so the server must use the same encoding: a precondition of this backend,
/// not a protocol guarantee. `O_DIRECT`, `O_LARGEFILE`, and `O_DIRECTORY` have different values
/// on x86-64 and AArch64, so in practice the server must run on a host of the guest's
/// architecture, as with a virtio-fs device under KVM.
fn oflags_to_open(flags: OFlags) -> u32 {
    // `O_CREAT`, `O_EXCL`, and `O_NOCTTY` are never sent, as with Linux's own client. `O_APPEND`
    // is not sent either: the resolver writes appends at the end of the file itself, and
    // `F_SETFL` can change the flag after the server has opened the file. `O_NOFOLLOW` and
    // `O_DIRECTORY` concern the lookup, which is done.
    const PASSED: OFlags = OFlags::RDONLY
        .union(OFlags::WRONLY)
        .union(OFlags::RDWR)
        .union(OFlags::TRUNC)
        .union(OFlags::LARGEFILE)
        .union(OFlags::SYNC)
        .union(OFlags::DSYNC)
        .union(OFlags::DIRECT)
        .union(OFlags::NOATIME);
    (flags & PASSED).bits()
}

/// The [`FileType`](super::FileType) of a file of `mode` (with its `S_IFMT` bits).
fn mode_to_file_type(mode: u32) -> super::FileType {
    // As for 9P, everything but a directory is reported as a regular file.
    if mode & abi::S_IFMT == abi::S_IFDIR {
        super::FileType::Directory
    } else {
        super::FileType::RegularFile
    }
}

// Common POSIX error codes used when converting remote errors to specific FS error types.
const EPERM: u32 = 1;
const ENOENT: u32 = 2;
const EACCES: u32 = 13;
const EEXIST: u32 = 17;
const ENOTDIR: u32 = 20;
const EISDIR: u32 = 21;
const ENAMETOOLONG: u32 = 36;
const ENOTEMPTY: u32 = 39;

/// Error type for FUSE operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io,

    #[error("Invalid response from server")]
    InvalidResponse,

    #[error("Invalid pathname")]
    InvalidPathname,

    /// Error reported by the FUSE server, carrying the raw errno
    #[error("Remote error (errno={0})")]
    Remote(u32),
}

impl From<Error> for OpenError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => OpenError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => OpenError::PathError(PathError::NoSuchFileOrDirectory),
                EEXIST => OpenError::AlreadyExists,
                EPERM | EACCES => OpenError::AccessNotAllowed,
                ENOTDIR => OpenError::PathError(PathError::ComponentNotADirectory),
                ENAMETOOLONG => OpenError::PathError(PathError::InvalidPathname),
                _ => OpenError::Io,
            },
            Error::Io | Error::InvalidResponse => OpenError::Io,
        }
    }
}

impl From<Error> for ReadError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT | EISDIR => ReadError::NotAFile,
                EPERM | EACCES => ReadError::NotForReading,
                _ => ReadError::Io,
            },
            Error::Io | Error::InvalidResponse | Error::InvalidPathname => ReadError::Io,
        }
    }
}

impl From<Error> for WriteError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT | EISDIR => WriteError::NotAFile,
                EPERM | EACCES => WriteError::NotForWriting,
                _ => WriteError::Io,
            },
            Error::Io | Error::InvalidResponse | Error::InvalidPathname => WriteError::Io,
        }
    }
}

impl From<Error> for MkdirError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => MkdirError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => MkdirError::PathError(PathError::NoSuchFileOrDirectory),
                EEXIST => MkdirError::AlreadyExists,
                EPERM | EACCES => MkdirError::NoWritePerms,
                ENOTDIR => MkdirError::PathError(PathError::ComponentNotADirectory),
                ENAMETOOLONG => MkdirError::PathError(PathError::InvalidPathname),
                _ => MkdirError::Io,
            },
            Error::Io | Error::InvalidResponse => MkdirError::Io,
        }
    }
}

impl From<Error> for ReadDirError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT | ENOTDIR => ReadDirError::NotADirectory,
                _ => ReadDirError::Io,
            },
            Error::Io | Error::InvalidResponse | Error::InvalidPathname => ReadDirError::Io,
        }
    }
}

impl From<Error> for UnlinkError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => UnlinkError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => UnlinkError::PathError(PathError::NoSuchFileOrDirectory),
                EISDIR => UnlinkError::IsADirectory,
                EPERM | EACCES => UnlinkError::NoWritePerms,
                ENOTDIR => UnlinkError::PathError(PathError::ComponentNotADirectory),
                ENAMETOOLONG => UnlinkError::PathError(PathError::InvalidPathname),
                _ => UnlinkError::Io,
            },
            Error::Io | Error::InvalidResponse => UnlinkError::Io,
        }
    }
}

impl From<Error> for RmdirError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => RmdirError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => RmdirError::PathError(PathError::NoSuchFileOrDirectory),
                ENOTDIR => RmdirError::NotADirectory,
                EPERM | EACCES => RmdirError::NoWritePerms,
                ENAMETOOLONG => RmdirError::PathError(PathError::InvalidPathname),
                ENOTEMPTY => RmdirError::NotEmpty,
                _ => RmdirError::Io,
            },
            Error::Io | Error::InvalidResponse => RmdirError::Io,
        }
    }
}

impl From<Error> for FileStatusError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => FileStatusError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => FileStatusError::PathError(PathError::NoSuchFileOrDirectory),
                ENAMETOOLONG => FileStatusError::PathError(PathError::InvalidPathname),
                ENOTDIR => FileStatusError::PathError(PathError::ComponentNotADirectory),
                EPERM | EACCES => FileStatusError::PathError(PathError::NoSearchPerms),
                _ => FileStatusError::Io,
            },
            Error::Io | Error::InvalidResponse => FileStatusError::Io,
        }
    }
}

impl From<Error> for TruncateError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT => TruncateError::ClosedFd,
                EISDIR => TruncateError::IsDirectory,
                EPERM | EACCES => TruncateError::NotForWriting,
                _ => TruncateError::Io,
            },
            Error::Io | Error::InvalidResponse | Error::InvalidPathname => TruncateError::Io,
        }
    }
}

impl From<Error> for ChmodError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => ChmodError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => ChmodError::PathError(PathError::NoSuchFileOrDirectory),
                ENOTDIR => ChmodError::PathError(PathError::ComponentNotADirectory),
                EPERM | EACCES => ChmodError::NotTheOwner,
                _ => ChmodError::Io,
            },
            Error::Io | Error::InvalidResponse => ChmodError::Io,
        }
    }
}

impl From<Error> for ChownError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => ChownError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => ChownError::PathError(PathError::NoSuchFileOrDirectory),
                ENOTDIR => ChownError::PathError(PathError::ComponentNotADirectory),
                EPERM | EACCES => ChownError::NotTheOwner,
                _ => ChownError::Io,
            },
            Error::Io | Error::InvalidResponse => ChownError::Io,
        }
    }
}

impl From<Error> for WalkError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => WalkError::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => WalkError::PathError(PathError::NoSuchFileOrDirectory),
                ENAMETOOLONG => WalkError::PathError(PathError::InvalidPathname),
                ENOTDIR => WalkError::PathError(PathError::ComponentNotADirectory),
                EPERM | EACCES => WalkError::PathError(PathError::NoSearchPerms),
                _ => WalkError::Io,
            },
            Error::Io | Error::InvalidResponse => WalkError::Io,
        }
    }
}
