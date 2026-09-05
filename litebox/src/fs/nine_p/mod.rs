// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A network file system, using the 9P2000.L protocol
//!
//! This module provides a [`NineP`] [`Backend`](super::backend::Backend) that accesses files over
//! a 9P2000.L network connection. The 9P protocol is a simple, message-based protocol originally
//! designed for Plan 9 from Bell Labs. 9P2000.L is a Linux-specific variant that provides better
//! compatibility with POSIX semantics.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;

use crate::fs::OFlags;
use crate::fs::backend::{
    DirHandle, FileHandle, HandleRef, PermissionCheck, Permissioned, SeekBehavior, WalkOutcome,
    WalkStopReason, WalkedComponent, WalkingDirHandle,
};
use crate::fs::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WalkError, WriteError,
};
use crate::fs::nine_p::fcall::Rlerror;
use litebox_platform::sync;

mod client;
mod fcall;

pub mod transport;

#[cfg(test)]
mod tests;

/// A [`Backend`](super::backend::Backend) backed by a 9P2000.L server.
///
/// This filesystem implementation communicates with a 9P server to provide access to remote files.
/// All file operations are translated into 9P protocol messages that are sent to the server.
///
/// # Type Parameters
///
/// - `Platform`: The platform provider that supplies synchronization primitives.
/// - `T`: The transport type that implements both `Read` and `Write` traits.
pub struct NineP<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write> {
    /// 9P client for protocol operations
    client: Arc<client::Client<Platform, T>>,
    /// The fid attached to the root of the remote filesystem.
    ///
    /// Handed out (shared) by [`Backend::root`](super::backend::Backend::root), so it must never
    /// be `Tlopen`ed or `Tlcreate`d; see the `is_backend_root` flag on the walking dir handle.
    root: Arc<OwnedFid<Platform, T>>,
    /// Device id reported in every [`NodeInfo`](super::NodeInfo) from this backend; inode numbers
    /// come from the server's qids instead.
    device_id: usize,
    /// Whether `unlinkat` is supported by the server
    unlinkat_supported: AtomicBool,
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write>
    NineP<Platform, T>
{
    /// Construct a new `NineP` backend, negotiating the protocol version and attaching to `path`.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport for 9P communication
    /// * `msize` - Maximum message size to negotiate
    /// * `username` - Username for authentication
    /// * `path` - Attach path (typically the root directory path)
    /// * `inode_allocator` - Supplies the device id reported for this backend's files
    ///
    /// # Errors
    ///
    /// Returns an error if version negotiation or attach fails.
    pub fn new(
        transport: T,
        msize: u32,
        username: &str,
        path: &str,
        inode_allocator: super::inode_allocator::InodeAllocator,
    ) -> Result<Self, Error> {
        let client = Arc::new(client::Client::new(transport, msize)?);
        let (_qid, fid) = client.attach(username, path)?;
        Ok(Self {
            root: Arc::new(OwnedFid {
                fid,
                client: Arc::clone(&client),
            }),
            client,
            device_id: inode_allocator.device_id(),
            unlinkat_supported: AtomicBool::new(true),
        })
    }

    /// Tie a freshly obtained `fid` to this backend's client, so that it is clunked once the last
    /// handle referring to it goes away.
    fn own(&self, fid: client::Fid<Platform>) -> Arc<OwnedFid<Platform, T>> {
        Arc::new(OwnedFid {
            fid,
            client: Arc::clone(&self.client),
        })
    }

    /// Remove `name` from `dir`, via `Tunlinkat` where the server supports it.
    fn remove_at(
        &self,
        dir: &NinePDirHandle<Platform, T>,
        name: &str,
        is_file: bool,
    ) -> Result<(), Error> {
        const AT_REMOVEDIR: u32 = 0x200;

        if self.unlinkat_supported.load(Ordering::SeqCst) {
            let result =
                self.client
                    .unlinkat(&dir.fid.fid, name, if is_file { 0 } else { AT_REMOVEDIR });
            if let Err(Error::Remote(ENOSYS | EOPNOTSUPP)) = &result {
                self.unlinkat_supported.store(false, Ordering::SeqCst);
                // fall back to `remove`
            } else {
                return result;
            }
        }

        // `Tremove` removes whatever a fid names (and clunks it), so it needs a fid of its own.
        let fid = self
            .client
            .walk(&dir.fid.fid, &[name])?
            .into_complete_fid()?;
        self.client.remove(fid)
    }
}

/// A fid whose server-side state is released when the last handle referring to it goes away.
///
/// [`Backend`](super::backend::Backend) has no close hook, so the `Tclunk` has to ride on `Drop`.
/// Handles hold this behind an [`Arc`], so incidental handle clones (the resolver passing a clone
/// into a single call) do not clunk; only the last reference does.
struct OwnedFid<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write> {
    fid: client::Fid<Platform>,
    client: Arc<client::Client<Platform, T>>,
}
impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write> Drop
    for OwnedFid<Platform, T>
{
    fn drop(&mut self) {
        // `clunk` takes the (refcounted) fid by value; the local id is recycled once this
        // `OwnedFid`'s own reference goes away, immediately after this call.
        self.client.clunk(self.fid.clone());
    }
}

/// Walking directory handle
pub struct NinePWalkingDirHandle<
    Platform: sync::RawSyncPrimitivesProvider,
    T: transport::Read + transport::Write,
> {
    inner: NinePWalkingDirHandleInner<Platform, T>,
}

enum NinePWalkingDirHandleInner<
    Platform: sync::RawSyncPrimitivesProvider,
    T: transport::Read + transport::Write,
> {
    /// A fid on the directory itself.
    Dir {
        fid: Arc<OwnedFid<Platform, T>>,
        /// Whether `fid` is the backend's own attach fid, handed out by
        /// [`Backend::root`](super::backend::Backend::root).
        ///
        /// Such a fid is shared with the backend itself, so any operation that mutates it
        /// server-side (`Tlopen`, `Tlcreate`) must be performed on a private clone instead.
        is_backend_root: bool,
    },
    /// The walk stopped because `name` is not a directory.
    ///
    /// No fid on the parent directory is held: 9P walks into files just fine, so the walk already
    /// ended up with a fid on `name` itself, which is the only thing the resolver asks for here
    /// (see [`Backend::open_file_at`](super::backend::Backend::open_file_at)).
    ///
    /// `child` is `None` when the path continued *through* the non-directory, as a short walk
    /// establishes no fid; the resolver turns that into `ComponentNotADirectory` without ever
    /// using this handle.
    // XXX: anything this handle is asked for other than `name` itself (a different child via
    // `open_file_at`, or the directory via `into_dir`) needs a walk to the parent first; both paths
    // are `unimplemented!()` today.
    StoppedAtNonDir {
        name: String,
        child: Option<Arc<OwnedFid<Platform, T>>>,
    },
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write>
    From<NinePWalkingDirHandleInner<Platform, T>> for NinePWalkingDirHandle<Platform, T>
{
    fn from(inner: NinePWalkingDirHandleInner<Platform, T>) -> Self {
        Self { inner }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write>
    NinePWalkingDirHandle<Platform, T>
{
    /// The fid of the directory this handle names, and whether it is the backend's shared root.
    fn into_dir(self) -> (Arc<OwnedFid<Platform, T>>, bool) {
        match self.inner {
            NinePWalkingDirHandleInner::Dir {
                fid,
                is_backend_root,
            } => (fid, is_backend_root),
            // XXX: reaching the parent directory of a walk that stopped at a non-directory would
            // need a second walk (from the fid the walk started at, back down the prefix); nothing
            // currently needs it, as the resolver only ever opens the child.
            NinePWalkingDirHandleInner::StoppedAtNonDir { .. } => {
                unimplemented!()
            }
        }
    }
}

/// Directory handle
pub struct NinePDirHandle<
    Platform: sync::RawSyncPrimitivesProvider,
    T: transport::Read + transport::Write,
> {
    fid: Arc<OwnedFid<Platform, T>>,
}
impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write> Clone
    for NinePDirHandle<Platform, T>
{
    fn clone(&self) -> Self {
        Self {
            fid: Arc::clone(&self.fid),
        }
    }
}

/// File handle
pub struct NinePFileHandle<
    Platform: sync::RawSyncPrimitivesProvider,
    T: transport::Read + transport::Write,
> {
    fid: Arc<OwnedFid<Platform, T>>,
}
impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write> Clone
    for NinePFileHandle<Platform, T>
{
    fn clone(&self) -> Self {
        Self {
            fid: Arc::clone(&self.fid),
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write>
    super::backend::private::Sealed for NineP<Platform, T>
{
}

impl<Platform, T> super::backend::BackendHandles for NineP<Platform, T>
where
    Platform: sync::RawSyncPrimitivesProvider + 'static,
    T: transport::Read + transport::Write + Send + 'static,
{
    type WalkingDirHandle<'a> = NinePWalkingDirHandle<Platform, T>;
    type FileHandle = NinePFileHandle<Platform, T>;
    type DirHandle = NinePDirHandle<Platform, T>;
}

impl<Platform, T> super::backend::Backend for NineP<Platform, T>
where
    Platform: sync::RawSyncPrimitivesProvider + 'static,
    T: transport::Read + transport::Write + Send + 'static,
{
    fn root(&self) -> WalkingDirHandle<'_> {
        WalkingDirHandle::from_typed::<Self>(
            NinePWalkingDirHandleInner::Dir {
                fid: Arc::clone(&self.root),
                is_backend_root: true,
            }
            .into(),
        )
    }

    fn walk_directories<'a>(
        &'a self,
        from: WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<WalkOutcome<WalkingDirHandle<'a>>, WalkError> {
        assert!(!components.is_empty());
        let (from, _) = from.into_typed::<Self>().into_dir();
        // 9P walks happily into files, so the qids have to be inspected to find where this walk
        // must stop for the resolver's purposes.
        let result = self.client.walk(&from.fid, components)?;
        let first_non_dir = result
            .wqids
            .iter()
            .position(|qid| !qid.typ.contains(fcall::QidType::DIR));

        let Some(stopped_at) = first_non_dir else {
            let Some(fid) = result.fid else {
                // A short walk whose walked components are all directories means the next
                // component simply does not exist.
                return Err(WalkError::PathError(PathError::NoSuchFileOrDirectory));
            };
            debug_assert_eq!(result.wqids.len(), components.len());
            return Ok(WalkOutcome {
                components: backend_checked_components(components.len()),
                last: WalkingDirHandle::from_typed::<Self>(
                    NinePWalkingDirHandleInner::Dir {
                        fid: self.own(fid),
                        is_backend_root: false,
                    }
                    .into(),
                ),
                stop_reason: WalkStopReason::CompleteDirectory,
            });
        };

        let child = result.fid.map(|fid| {
            // A completed walk lands on the last component, so its fid names the non-directory the
            // walk stopped at. Anything else would mean the server walked *through* a
            // non-directory, which 9P2000.L does not permit.
            assert_eq!(
                stopped_at + 1,
                components.len(),
                "server completed a walk through a non-directory"
            );
            // Holding on to the fid saves `open_file_at` a walk of its own.
            self.own(fid)
        });
        Ok(WalkOutcome {
            components: backend_checked_components(stopped_at),
            last: WalkingDirHandle::from_typed::<Self>(
                NinePWalkingDirHandleInner::StoppedAtNonDir {
                    name: String::from(components[stopped_at]),
                    child,
                }
                .into(),
            ),
            stop_reason: WalkStopReason::StoppedAtNonDirectory,
        })
    }

    fn owned_dir_at(
        &self,
        dir: WalkingDirHandle<'_>,
        flags: OFlags,
    ) -> Result<DirHandle, OpenError> {
        assert_supported_oflags(flags);
        if flags.intersects(OFlags::WRONLY | OFlags::RDWR) {
            // TODO(jayb): POSIX requires `EISDIR` when write access is requested on a directory,
            // but `OpenError` has no such variant yet.
            unimplemented!()
        }
        let (fid, is_backend_root) = dir.into_typed::<Self>().into_dir();
        if flags.contains(OFlags::PATH) {
            // An `O_PATH` handle is never opened server-side, so the walked fid can be handed over
            // as-is, even when it is the shared root fid.
            return Ok(DirHandle::from_typed::<Self>(NinePDirHandle { fid }));
        }
        // `Tlopen` mutates the fid server-side, so it must never be issued on the shared root fid.
        let fid = if is_backend_root {
            self.own(self.client.clone_fid(&fid.fid)?)
        } else {
            fid
        };
        self.client.open(&fid.fid, fcall::LOpenFlags::O_DIRECTORY)?;
        Ok(DirHandle::from_typed::<Self>(NinePDirHandle { fid }))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<WalkingDirHandle<'a>> {
        // The walking handle can end up being opened (via `owned_dir_at`), which must not affect
        // the directory handle it came from, so this hands out a private clone of the fid.
        let fid = self
            .client
            .clone_fid(&dir.get_typed::<Self>().fid.fid)
            .ok()?;
        Some(WalkingDirHandle::from_typed::<Self>(
            NinePWalkingDirHandleInner::Dir {
                fid: self.own(fid),
                is_backend_root: false,
            }
            .into(),
        ))
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

        let fid = match dir.into_typed::<Self>().inner {
            // The walk already ended up holding a fid on this very file.
            NinePWalkingDirHandleInner::StoppedAtNonDir {
                name: walked,
                child: Some(child),
            } if walked == name => child,
            NinePWalkingDirHandleInner::StoppedAtNonDir { .. } => unimplemented!("{name}"),
            NinePWalkingDirHandleInner::Dir { fid, .. } => {
                self.own(self.client.walk(&fid.fid, &[name])?.into_complete_fid()?)
            }
        };

        if !flags.contains(OFlags::PATH) {
            // An `O_PATH` handle addresses the file without opening it server-side.
            //
            // The file exists (it is what stopped the walk), so the creation flags say nothing
            // about how to open it; the resolver enforces `O_CREAT | O_EXCL` itself.
            self.client.open(
                &fid.fid,
                oflags_to_lopen(flags - OFlags::CREAT - OFlags::EXCL),
            )?;
        }
        Ok(Permissioned {
            item: FileHandle::from_typed::<Self>(NinePFileHandle { fid }),
            permissions: PermissionCheck::ByBackend,
        })
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<super::DirEntry>, ReadDirError> {
        let handle = handle.into_typed::<Self>();
        let entries = self.client.readdir_all(&handle.fid.fid)?;
        Ok(entries
            .into_iter()
            .filter(|entry| {
                // The resolver synthesizes `.` and `..` itself.
                //
                // XXX(jayb): would it be better to allow `list_dir_at` to handle `.` and `..` and
                // have the resolver handle only cases where it is not handled by the backend?
                !matches!(&*entry.name, b"." | b"..")
            })
            .map(|entry| {
                Ok(super::DirEntry {
                    name: String::from_utf8_lossy(&entry.name).into_owned(),
                    file_type: qid_type_to_file_type(entry.qid.typ),
                    ino_info: Some(super::NodeInfo {
                        dev: self.device_id,
                        ino: usize::try_from(entry.qid.path).map_err(|_| Error::InvalidResponse)?,
                        rdev: None,
                    }),
                })
            })
            .collect::<Result<_, Error>>()?)
    }

    fn read(
        &self,
        _device_io: &dyn super::backend::DeviceIo,
        h: &FileHandle,
        buf: &mut [u8],
        offset: usize,
    ) -> Result<usize, ReadError> {
        let offset = u64::try_from(offset).map_err(|_| ReadError::Io)?;
        Ok(self
            .client
            .read(&h.get_typed::<Self>().fid.fid, offset, buf)?)
    }

    fn write(
        &self,
        _device_io: &dyn super::backend::DeviceIo,
        h: &FileHandle,
        buf: &[u8],
        offset: usize,
    ) -> Result<usize, WriteError> {
        let offset = u64::try_from(offset).map_err(|_| WriteError::Io)?;
        Ok(self
            .client
            .write(&h.get_typed::<Self>().fid.fid, offset, buf)?)
    }

    fn truncate(&self, h: &FileHandle, length: usize) -> Result<(), TruncateError> {
        let stat = fcall::SetAttr {
            size: u64::try_from(length).map_err(|_| TruncateError::Io)?,
            ..Default::default()
        };
        self.client.setattr(
            &h.get_typed::<Self>().fid.fid,
            fcall::SetattrMask::SIZE,
            stat,
        )?;
        Ok(())
    }

    fn seek_behavior(&self, _h: &FileHandle) -> SeekBehavior {
        // 9P has no server-side file position; the resolver owns positions and passes offsets in.
        SeekBehavior::PositionBased
    }

    fn status(&self, h: HandleRef<'_>) -> Result<super::FileStatus, FileStatusError> {
        let fid = match h {
            HandleRef::File(h) => &h.get_typed::<Self>().fid,
            HandleRef::Dir(h) => &h.get_typed::<Self>().fid,
        };
        let attr = self.client.getattr(&fid.fid, fcall::GetattrMask::ALL)?;
        Ok(rgetattr_to_file_status(&attr, self.device_id)?)
    }

    fn create_file_at(
        &self,
        dir: DirHandle,
        name: &str,
        metadata: super::backend::CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        // `Tlcreate` turns the directory fid into the new file's fid server-side, so it must be
        // handed a private clone rather than the caller's directory handle.
        let fid = self.client.clone_fid(&dir.get_typed::<Self>().fid.fid)?;
        // NOTE: 9P needs to commit to an access mode at creation time. The resolver still enforces
        // the caller's read/write intent via its own `read_allowed`/`write_allowed`.
        //
        // XXX: `Tlcreate` only carries a gid; the owning uid is whichever user the connection
        // attached as, so `metadata.owner.user` cannot be honored here.
        let (_, fid) = self.client.create(
            fid,
            name,
            fcall::LOpenFlags::O_RDWR,
            metadata.mode.bits(),
            u32::from(metadata.owner.group),
        )?;
        Ok(FileHandle::from_typed::<Self>(NinePFileHandle {
            fid: self.own(fid),
        }))
    }

    fn mkdir_at(
        &self,
        dir: DirHandle,
        name: &str,
        metadata: super::backend::CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        let dir = dir.into_typed::<Self>();
        // XXX: as in `create_file_at`, `Tmkdir` cannot set the owning uid.
        self.client.mkdir(
            &dir.fid.fid,
            name,
            metadata.mode.bits(),
            u32::from(metadata.owner.group),
        )?;
        // `Tmkdir` only reports the new directory's qid, so a walk is needed to address it.
        //
        // TODO(jayb): the resolver discards this handle, so the walk is pure overhead, and worse, a
        // walk that fails (connection loss, or a concurrent removal) reports a `Tmkdir` that
        // already succeeded as a failure. I should decide if having `mkdir_at` return a dir is the
        // right move, or I want to remove that behavior.
        let fid = self
            .client
            .walk(&dir.fid.fid, &[name])?
            .into_complete_fid()?;
        Ok(DirHandle::from_typed::<Self>(NinePDirHandle {
            fid: self.own(fid),
        }))
    }

    fn unlink_at(&self, dir: DirHandle, name: &str) -> Result<(), UnlinkError> {
        Ok(self.remove_at(&dir.into_typed::<Self>(), name, true)?)
    }

    fn rmdir_at(&self, dir: DirHandle, name: &str) -> Result<(), RmdirError> {
        Ok(self.remove_at(&dir.into_typed::<Self>(), name, false)?)
    }

    fn chmod(&self, h: HandleRef<'_>, mode: super::Mode) -> Result<(), ChmodError> {
        let fid = match h {
            HandleRef::File(h) => &h.get_typed::<Self>().fid,
            HandleRef::Dir(h) => &h.get_typed::<Self>().fid,
        };
        let stat = fcall::SetAttr {
            mode: mode.bits(),
            ..Default::default()
        };
        Ok(self
            .client
            .setattr(&fid.fid, fcall::SetattrMask::MODE, stat)?)
    }

    fn chown(
        &self,
        h: HandleRef<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let fid = match h {
            HandleRef::File(h) => &h.get_typed::<Self>().fid,
            HandleRef::Dir(h) => &h.get_typed::<Self>().fid,
        };
        // Only the fields actually supplied are marked valid, so the rest are left alone.
        let mut valid = fcall::SetattrMask::empty();
        let uid = match user {
            Some(u) => {
                valid |= fcall::SetattrMask::UID;
                u32::from(u)
            }
            None => 0,
        };
        let gid = match group {
            Some(g) => {
                valid |= fcall::SetattrMask::GID;
                u32::from(g)
            }
            None => 0,
        };
        let stat = fcall::SetAttr {
            uid,
            gid,
            ..Default::default()
        };
        Ok(self.client.setattr(&fid.fid, valid, stat)?)
    }
}

/// The 9P server is authoritative for permissions, so every component the backend reports is left
/// for it to check.
fn backend_checked_components(count: usize) -> Vec<WalkedComponent> {
    alloc::vec![
        WalkedComponent {
            permissions: PermissionCheck::ByBackend
        };
        count
    ]
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

/// Convert [`OFlags`] to 9P `LOpenFlags`
fn oflags_to_lopen(flags: OFlags) -> fcall::LOpenFlags {
    let mut lflags = fcall::LOpenFlags::empty();

    // Access mode (RDONLY is 0, so we only check for WRONLY and RDWR)
    if flags.contains(OFlags::RDWR) {
        lflags |= fcall::LOpenFlags::O_RDWR;
    } else if flags.contains(OFlags::WRONLY) {
        lflags |= fcall::LOpenFlags::O_WRONLY;
    }
    // RDONLY is implicit if neither WRONLY nor RDWR

    if flags.contains(OFlags::CREAT) {
        lflags |= fcall::LOpenFlags::O_CREAT;
    }
    if flags.contains(OFlags::EXCL) {
        lflags |= fcall::LOpenFlags::O_EXCL;
    }
    if flags.contains(OFlags::TRUNC) {
        lflags |= fcall::LOpenFlags::O_TRUNC;
    }
    if flags.contains(OFlags::APPEND) {
        lflags |= fcall::LOpenFlags::O_APPEND;
    }
    if flags.contains(OFlags::DIRECTORY) {
        lflags |= fcall::LOpenFlags::O_DIRECTORY;
    }
    if flags.contains(OFlags::NOFOLLOW) {
        lflags |= fcall::LOpenFlags::O_NOFOLLOW;
    }
    if flags.contains(OFlags::NONBLOCK) {
        lflags |= fcall::LOpenFlags::O_NONBLOCK;
    }
    if flags.contains(OFlags::SYNC) {
        lflags |= fcall::LOpenFlags::O_SYNC;
    }
    if flags.contains(OFlags::DSYNC) {
        lflags |= fcall::LOpenFlags::O_DSYNC;
    }
    if flags.contains(OFlags::DIRECT) {
        lflags |= fcall::LOpenFlags::O_DIRECT;
    }
    if flags.contains(OFlags::NOATIME) {
        lflags |= fcall::LOpenFlags::O_NOATIME;
    }

    lflags
}

/// Convert a Qid type to our FileType
fn qid_type_to_file_type(qid_type: fcall::QidType) -> super::FileType {
    if qid_type.contains(fcall::QidType::DIR) {
        super::FileType::Directory
    } else {
        super::FileType::RegularFile
    }
}

/// Convert getattr response to FileStatus
///
/// Inode numbers come from the server's qids; `device_id` is the device the caller reports this
/// filesystem as.
fn rgetattr_to_file_status(
    attr: &fcall::Rgetattr,
    device_id: usize,
) -> Result<super::FileStatus, Error> {
    let file_type = qid_type_to_file_type(attr.qid.typ);

    if attr.valid.contains(fcall::GetattrMask::BASIC) {
        Ok(super::FileStatus {
            file_type,
            mode: super::Mode::from_bits_truncate(attr.stat.mode),
            size: usize::try_from(attr.stat.size).map_err(|_| Error::InvalidResponse)?,
            owner: super::UserInfo {
                user: u16::try_from(attr.stat.uid).map_err(|_| Error::InvalidResponse)?,
                group: u16::try_from(attr.stat.gid).map_err(|_| Error::InvalidResponse)?,
            },
            node_info: super::NodeInfo {
                dev: device_id,
                ino: usize::try_from(attr.qid.path).map_err(|_| Error::InvalidResponse)?,
                rdev: NonZeroUsize::new(
                    usize::try_from(attr.stat.rdev).map_err(|_| Error::InvalidResponse)?,
                ),
            },
            blksize: usize::try_from(attr.stat.blksize).map_err(|_| Error::InvalidResponse)?,
        })
    } else {
        Ok(super::FileStatus {
            file_type,
            mode: if attr.valid.contains(fcall::GetattrMask::MODE) {
                super::Mode::from_bits_truncate(attr.stat.mode)
            } else {
                super::Mode::empty()
            },
            size: if attr.valid.contains(fcall::GetattrMask::SIZE) {
                usize::try_from(attr.stat.size).map_err(|_| Error::InvalidResponse)?
            } else {
                0
            },
            owner: super::UserInfo {
                user: if attr.valid.contains(fcall::GetattrMask::UID) {
                    u16::try_from(attr.stat.uid).map_err(|_| Error::InvalidResponse)?
                } else {
                    0
                },
                group: if attr.valid.contains(fcall::GetattrMask::GID) {
                    u16::try_from(attr.stat.gid).map_err(|_| Error::InvalidResponse)?
                } else {
                    0
                },
            },
            node_info: super::NodeInfo {
                dev: device_id,
                ino: usize::try_from(attr.qid.path).map_err(|_| Error::InvalidResponse)?,
                rdev: if attr.valid.contains(fcall::GetattrMask::RDEV) {
                    NonZeroUsize::new(
                        usize::try_from(attr.stat.rdev).map_err(|_| Error::InvalidResponse)?,
                    )
                } else {
                    None
                },
            },
            blksize: if attr.valid.contains(fcall::GetattrMask::BLOCKS) {
                usize::try_from(attr.stat.blksize).map_err(|_| Error::InvalidResponse)?
            } else {
                0
            },
        })
    }
}

// Common POSIX error codes used when converting remote errors to specific FS error types.
const EPERM: u32 = 1;
const ENOENT: u32 = 2;
const EACCES: u32 = 13;
const EEXIST: u32 = 17;
const ENOTDIR: u32 = 20;
const EISDIR: u32 = 21;
const EINVAL: u32 = 22;
const ESPIPE: u32 = 29;
const ENAMETOOLONG: u32 = 36;
const ENOSYS: u32 = 38;
const ENOTEMPTY: u32 = 39;
const EOPNOTSUPP: u32 = 95;

/// Error type for 9P operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io,

    #[error("Invalid response from server")]
    InvalidResponse,

    #[error("Invalid pathname")]
    InvalidPathname,

    /// Error reported by the 9P server, carrying the raw errno
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
                EPERM | EACCES => FileStatusError::PathError(PathError::NoSearchPerms {
                    #[cfg(debug_assertions)]
                    dir: String::new(),
                    #[cfg(debug_assertions)]
                    perms: super::Mode::empty(),
                }),
                _ => FileStatusError::Io,
            },
            Error::Io | Error::InvalidResponse => FileStatusError::Io,
        }
    }
}

impl From<Error> for SeekError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(e) => match e {
                ENOENT => SeekError::ClosedFd,
                EINVAL => SeekError::InvalidOffset,
                ESPIPE => SeekError::NonSeekable,
                _ => SeekError::Io,
            },
            _ => SeekError::Io,
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
                EPERM | EACCES => WalkError::PathError(PathError::NoSearchPerms {
                    #[cfg(debug_assertions)]
                    dir: String::new(),
                    #[cfg(debug_assertions)]
                    perms: super::Mode::empty(),
                }),
                _ => WalkError::Io,
            },
            Error::Io | Error::InvalidResponse => WalkError::Io,
        }
    }
}

impl From<Rlerror> for Error {
    fn from(err: Rlerror) -> Self {
        Error::Remote(err.ecode)
    }
}
