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
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;

use self::fcall::Rlerror;
use super::OFlags;
use super::backend::{
    DirHandle, DirPathResult, FileHandle, HandleRef, PermissionCheck, PermissionInfo, Resolution,
    ResolvedDir, ResolvedFile, ResolvedTarget, SeekBehavior,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RenameError, ResolutionError, RmdirError, SeekError, SymlinkError, TruncateError,
    UnlinkError, WalkError, WriteError, walk_error_or,
};
use litebox_platform::buffer::{Fault, ReadBuffer, WriteBuffer};
use litebox_platform::sync;

use crate::BrokerError;

mod client;
mod fcall;
mod id_pool;
#[cfg(all(test, target_os = "linux"))]
mod tests;

pub mod transport;

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
    /// be `Tlopen`ed or `Tlcreate`d.
    root: Arc<OwnedFid<Platform, T>>,
    /// Qid path of [`Self::root`].
    root_qid_path: u64,
    /// Qid path of `..` walked from [`Self::root`], if the server reported one; looked up on
    /// first use by [`Self::walk_parent`].
    root_parent_qid_path: spin::Once<Option<u64>>,
    /// Device id reported in every [`NodeInfo`](super::NodeInfo) from this backend; inode numbers
    /// come from the server's qids instead.
    device_id: u64,
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
        let (qid, fid) = client.attach(username, path)?;
        Ok(Self {
            root: Arc::new(OwnedFid {
                fid,
                client: Arc::clone(&client),
            }),
            root_qid_path: qid.path,
            root_parent_qid_path: spin::Once::new(),
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

    /// Walks `..` from the directory `dir` (whose qid path is `qid_path`), or returns `None` at
    /// the export root.
    ///
    /// A matching qid path alone does not identify the root, since an export spanning several
    /// host filesystems can repeat inode numbers; the root's `..` must match too. Some servers
    /// (e.g., diod) walk `..` from the export root out of the export, so any doubt resolves to
    /// the root.
    fn walk_parent(
        &self,
        dir: &client::Fid<Platform>,
        qid_path: u64,
    ) -> Result<Option<WalkedDir<Platform, T>>, WalkError> {
        if qid_path != self.root_qid_path {
            return Ok(Some(self.walk_dot_dot(dir)?));
        }
        // Only a server's answer is cached; transport failures are reported and retried later.
        let root_parent = *self.root_parent_qid_path.try_call_once(|| {
            server_refusal_as_none(self.walk_dot_dot(&self.root.fid))
                .map(|walked| walked.map(|(qid_path, _)| qid_path))
        })?;
        Ok(
            match (root_parent, server_refusal_as_none(self.walk_dot_dot(dir))?) {
                (Some(root_parent), Some((parent, fid))) if parent != root_parent => {
                    Some((parent, fid))
                }
                _ => None,
            },
        )
    }

    /// The attributes of the directory `dir` holds, failing with `NoSuchFileOrDirectory` once its
    /// fid names another object. Servers such as diod track fids by path, so a renamed or
    /// replaced held directory cannot be followed; failing keeps operations from acting on
    /// whatever now has its old name.
    fn verified_held_dir_attr(
        &self,
        dir: &NinePDirHandle<Platform, T>,
        mask: fcall::GetattrMask,
    ) -> Result<fcall::Rgetattr, WalkError> {
        let attr = self.client.getattr(&dir.fid.fid, mask)?;
        if attr.qid.path != dir.qid_path {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }
        Ok(attr)
    }

    /// [`Backend::dir_path`](super::backend::Backend::dir_path) of `dir`, whose attributes
    /// [`Self::verified_held_dir_attr`] returned as `attr`.
    fn path_of_held_dir(
        &self,
        dir: &NinePDirHandle<Platform, T>,
        attr: &fcall::Rgetattr,
    ) -> Result<Option<Vec<String>>, WalkError> {
        if is_unlinked(attr) {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }
        if attr.qid.path == self.root_qid_path
            && self.walk_parent(&dir.fid.fid, attr.qid.path)?.is_none()
        {
            return Ok(Some(Vec::new()));
        }
        // 9P2000.L cannot request the current name of a fid, and enumerating ancestors would
        // require extra permissions.
        Ok(None)
    }

    /// A walking handle sharing the fid `dir` holds.
    fn walking_handle(dir: &NinePDirHandle<Platform, T>) -> NinePWalkingDirHandle<Platform, T> {
        NinePWalkingDirHandle {
            fid: Arc::clone(&dir.fid),
            qid_path: dir.qid_path,
        }
    }

    /// Walks `..` from `dir`, returning the qid path and fid it reached.
    fn walk_dot_dot(&self, dir: &client::Fid<Platform>) -> Result<WalkedDir<Platform, T>, Error> {
        self.walk_one(dir, "..")
    }

    /// Walks the single component `name` from `dir`, returning the qid path and fid it reached.
    fn walk_one(
        &self,
        dir: &client::Fid<Platform>,
        name: &str,
    ) -> Result<WalkedDir<Platform, T>, Error> {
        self.walk_complete(dir, &[name])
    }

    /// Walks all of `names` from `dir`, returning the qid path and fid it reached.
    fn walk_complete(
        &self,
        dir: &client::Fid<Platform>,
        names: &[&str],
    ) -> Result<WalkedDir<Platform, T>, Error> {
        let walk = self.client.walk(dir, names)?;
        let qid_path = walk.wqids.last().map(|qid| qid.path);
        let fid = self.own(walk.into_complete_fid()?);
        Ok((qid_path.ok_or(Error::InvalidResponse)?, fid))
    }

    /// Remove `name` from `dir`, via `Tunlinkat` where the server supports it.
    fn remove_at(
        &self,
        dir: &NinePWalkingDirHandle<Platform, T>,
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

/// A directory reached by a walk: its qid path and fid.
type WalkedDir<Platform, T> = (u64, Arc<OwnedFid<Platform, T>>);

/// Walking directory handle
pub struct NinePWalkingDirHandle<
    Platform: sync::RawSyncPrimitivesProvider,
    T: transport::Read + transport::Write,
> {
    fid: Arc<OwnedFid<Platform, T>>,
    /// Qid path the server reported for `fid` when it was reached, so opening the directory
    /// needs no further round trip to learn its identity.
    qid_path: u64,
}

/// Directory handle
pub struct NinePDirHandle<
    Platform: sync::RawSyncPrimitivesProvider,
    T: transport::Read + transport::Write,
> {
    fid: Arc<OwnedFid<Platform, T>>,
    /// Qid path of the directory `fid` named when this handle was created (see
    /// [`NineP::verified_held_dir_attr`]).
    qid_path: u64,
    /// Opened clone used for `Treaddir`; `fid` stays unopened because Twalk requires that.
    reader: Option<Arc<OwnedFid<Platform, T>>>,
}
impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Read + transport::Write> Clone
    for NinePDirHandle<Platform, T>
{
    fn clone(&self) -> Self {
        Self {
            fid: Arc::clone(&self.fid),
            qid_path: self.qid_path,
            reader: self.reader.clone(),
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

impl<Platform, T> super::backend::BackendHandles for NineP<Platform, T>
where
    Platform: sync::RawSyncPrimitivesProvider + 'static,
    T: transport::Read + transport::Write + Send + 'static,
{
    type ResolvedDir<'a> = NinePWalkingDirHandle<Platform, T>;
    type ResolvedFile<'a> = NinePFileHandle<Platform, T>;
    type FileHandle = NinePFileHandle<Platform, T>;
    type DirHandle = NinePDirHandle<Platform, T>;
}

impl<Platform, T> super::backend::Backend for NineP<Platform, T>
where
    Platform: sync::RawSyncPrimitivesProvider + 'static,
    T: transport::Read + transport::Write + Send + 'static,
{
    fn root(&self) -> Result<ResolvedDir<'_>, WalkError> {
        Ok(ResolvedDir::from_typed::<Self>(
            NinePWalkingDirHandle {
                fid: Arc::clone(&self.root),
                qid_path: self.root_qid_path,
            },
            PermissionCheck::ByBackend,
        ))
    }

    fn resolve<'a>(
        &'a self,
        from: ResolvedDir<'a>,
        components: &[&str],
        _authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        let mut current = from.into_typed::<Self>();
        let mut index = 0;
        for chunk in components.chunks(fcall::MAXWELEM) {
            let result = match self.client.walk(&current.fid.fid, chunk) {
                Ok(result) => result,
                Err(Error::Remote(ENOENT)) if index + 1 == components.len() => {
                    return Ok(Resolution::MissingFinal {
                        parent: ResolvedDir::from_typed::<Self>(
                            current,
                            PermissionCheck::ByBackend,
                        ),
                    });
                }
                Err(error) => {
                    return Err(ResolutionError {
                        component: None,
                        error: error.into(),
                    });
                }
            };
            let fid = result.fid.map(|fid| self.own(fid));
            if let Some(non_dir) = result
                .wqids
                .iter()
                .position(|qid| !qid.typ.contains(fcall::QidType::DIR))
            {
                if index + non_dir + 1 != components.len() {
                    return Err(ResolutionError {
                        component: Some(index + non_dir + 1),
                        error: PathError::ComponentNotADirectory.into(),
                    });
                }
                let fid = fid.ok_or(ResolutionError {
                    component: None,
                    error: WalkError::Io,
                })?;
                return Ok(Resolution::Found(ResolvedTarget::File(
                    ResolvedFile::from_typed::<Self>(
                        NinePFileHandle { fid },
                        PermissionCheck::ByBackend,
                        qid_type_to_file_type(result.wqids[non_dir].typ),
                    ),
                )));
            }
            if let Some(fid) = fid {
                // A complete walk reports one qid per component, the last being where it ended.
                let qid = result.wqids.last().ok_or(ResolutionError {
                    component: None,
                    error: WalkError::Io,
                })?;
                current = NinePWalkingDirHandle {
                    fid,
                    qid_path: qid.path,
                };
                index += chunk.len();
                continue;
            }
            let walked = result.wqids.len();
            if index + walked + 1 != components.len() {
                return Err(ResolutionError {
                    component: Some(index + walked),
                    error: PathError::NoSuchFileOrDirectory.into(),
                });
            }
            // Short walks establish no fid. Recover the parent before reporting a creatable name.
            if walked != 0 {
                let (qid_path, fid) = self
                    .walk_complete(&current.fid.fid, &chunk[..walked])
                    .map_err(|error| ResolutionError {
                        component: None,
                        error: error.into(),
                    })?;
                current = NinePWalkingDirHandle { fid, qid_path };
            }
            return Ok(Resolution::MissingFinal {
                parent: ResolvedDir::from_typed::<Self>(current, PermissionCheck::ByBackend),
            });
        }
        Ok(Resolution::Found(ResolvedTarget::Dir(
            ResolvedDir::from_typed::<Self>(current, PermissionCheck::ByBackend),
        )))
    }

    fn read_link_at(&self, dir: &ResolvedDir<'_>, name: &str) -> Result<String, WalkError> {
        let dir = dir.get_typed::<Self>();
        let fid = self.own(
            self.client
                .walk(&dir.fid.fid, &[name])?
                .into_complete_fid()?,
        );
        let target = self.client.readlink(&fid.fid)?;
        // Targets are passed through unchanged: an absolute target resolves from the guest's root,
        // `/`, not from where this export is mounted.
        String::from_utf8(target).map_err(|_| PathError::InvalidPathname.into())
    }

    fn open_dir(&self, dir: ResolvedDir<'_>, flags: OFlags) -> Result<DirHandle, OpenError> {
        assert_supported_oflags(flags);
        let NinePWalkingDirHandle { fid, qid_path } = dir.into_typed::<Self>();
        let reader = if flags.contains(OFlags::PATH) {
            None
        } else {
            let reader = self.own(self.client.clone_fid(&fid.fid)?);
            self.client
                .open(&reader.fid, fcall::LOpenFlags::O_DIRECTORY)?;
            Some(reader)
        };
        Ok(DirHandle::from_typed::<Self>(NinePDirHandle {
            fid,
            qid_path,
            reader,
        }))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Result<ResolvedDir<'a>, WalkError> {
        let dir = dir.get_typed::<Self>();
        self.verified_held_dir_attr(dir, fcall::GetattrMask::NLINK)?;
        Ok(ResolvedDir::from_typed::<Self>(
            Self::walking_handle(dir),
            PermissionCheck::ByBackend,
        ))
    }

    fn walking_dir_with_path<'a>(
        &'a self,
        dir: &DirHandle,
    ) -> Result<(ResolvedDir<'a>, DirPathResult), WalkError> {
        // One identity check serves both results.
        let dir = dir.get_typed::<Self>();
        let attr = self.verified_held_dir_attr(dir, fcall::GetattrMask::NLINK)?;
        Ok((
            ResolvedDir::from_typed::<Self>(Self::walking_handle(dir), PermissionCheck::ByBackend),
            self.path_of_held_dir(dir, &attr),
        ))
    }

    fn dir_path(&self, dir: &DirHandle) -> Result<Option<Vec<String>>, WalkError> {
        let dir = dir.get_typed::<Self>();
        let attr = self.verified_held_dir_attr(dir, fcall::GetattrMask::NLINK)?;
        self.path_of_held_dir(dir, &attr)
    }

    fn parent_dir(&self, dir: &DirHandle) -> Result<Option<DirHandle>, WalkError> {
        let dir = dir.get_typed::<Self>();
        self.verified_held_dir_attr(dir, fcall::GetattrMask::NLINK)?;
        Ok(self
            .walk_parent(&dir.fid.fid, dir.qid_path)?
            .map(|(qid_path, fid)| {
                DirHandle::from_typed::<Self>(NinePDirHandle {
                    fid,
                    qid_path,
                    reader: None,
                })
            }))
    }

    fn check_search_permission(&self, dir: &ResolvedDir<'_>) -> Result<(), WalkError> {
        let fid = self
            .client
            .walk(&dir.get_typed::<Self>().fid.fid, &["."])?
            .into_complete_fid()?;
        drop(self.own(fid));
        Ok(())
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        assert_supported_oflags(flags);
        // TODO: we do not support non-blocking, so ignore that flag instead of returning an error.
        let flags = flags - OFlags::NONBLOCK;
        if flags.contains(OFlags::DIRECTORY) {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }

        let NinePFileHandle { fid } = file.into_typed::<Self>();

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
        Ok(FileHandle::from_typed::<Self>(NinePFileHandle { fid }))
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<super::DirEntry>, ReadDirError> {
        let handle = handle.into_typed::<Self>();
        let entries = self
            .client
            .readdir_all(&handle.reader.as_ref().unwrap_or(&handle.fid).fid)?;
        // Servers may list a removed directory as empty (glibc's readdir hides the ENOENT that
        // Linux reports), and only an empty directory can be removed, so check its link count.
        if entries
            .iter()
            .all(|entry| matches!(&*entry.name, b"." | b".."))
        {
            let attr = self
                .client
                .getattr(&handle.fid.fid, fcall::GetattrMask::NLINK)?;
            if is_unlinked(&attr) {
                return Err(ReadDirError::Removed);
            }
        }
        Ok(entries
            .into_iter()
            .filter(|entry| {
                // The resolver synthesizes `.` and `..` itself.
                //
                // XXX(jayb): would it be better to allow `list_dir_at` to handle `.` and `..` and
                // have the resolver handle only cases where it is not handled by the backend?
                !matches!(&*entry.name, b"." | b"..")
            })
            .map(|entry| super::DirEntry {
                name: String::from_utf8_lossy(&entry.name).into_owned(),
                file_type: qid_type_to_file_type(entry.qid.typ),
                ino_info: Some(super::NodeInfo {
                    dev: self.device_id,
                    ino: entry.qid.path,
                    rdev: None,
                }),
            })
            .collect())
    }

    fn read(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
    ) -> Result<usize, ReadError> {
        let offset = u64::try_from(offset).map_err(|_| ReadError::Io)?;
        Ok(self
            .client
            .read(&h.get_typed::<Self>().fid.fid, offset, buf)?)
    }

    fn write(
        &self,
        h: &FileHandle,
        buf: &dyn WriteBuffer,
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
        let attr = match h {
            HandleRef::File(h) => self
                .client
                .getattr(&h.get_typed::<Self>().fid.fid, fcall::GetattrMask::ALL)?,
            HandleRef::Dir(h) => self
                .verified_held_dir_attr(h.get_typed::<Self>(), fcall::GetattrMask::ALL)
                .map_err(walk_error_or(FileStatusError::Io))?,
        };
        Ok(rgetattr_to_file_status(&attr, self.device_id)?)
    }

    fn resolved_status(
        &self,
        target: &ResolvedTarget<'_>,
    ) -> Result<super::FileStatus, FileStatusError> {
        let fid = match target {
            ResolvedTarget::File(h) => &h.get_typed::<Self>().fid,
            ResolvedTarget::Dir(h) => &h.get_typed::<Self>().fid,
        };
        let attr = self.client.getattr(&fid.fid, fcall::GetattrMask::ALL)?;
        Ok(rgetattr_to_file_status(&attr, self.device_id)?)
    }

    fn create_file_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        metadata: super::backend::CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        // `Tlcreate` turns the directory fid into the new file's fid server-side, so it must be
        // handed a private clone rather than the caller's directory handle.
        let dir = dir.into_typed::<Self>();
        let fid = self.client.clone_fid(&dir.fid.fid)?;
        // NOTE: 9P needs to commit to an access mode at creation time. The resolver still enforces
        // the caller's read/write intent via its own `read_allowed`/`write_allowed`.
        //
        // XXX: `Tlcreate` only carries a gid; the owning uid is whichever user the connection
        // attached as, so `metadata.owner.user` cannot be honored here.
        let (_, fid) = self.client.create(
            fid,
            name,
            fcall::LOpenFlags::O_RDWR,
            metadata.mode.bits().into(),
            u32::from(metadata.owner.group),
        )?;
        Ok(FileHandle::from_typed::<Self>(NinePFileHandle {
            fid: self.own(fid),
        }))
    }

    fn symlink_at(
        &self,
        _dir: ResolvedDir<'_>,
        _name: &str,
        _target: &str,
        _metadata: super::backend::CreationMetadata,
    ) -> Result<(), SymlinkError> {
        // The 9P server follows symlinks itself, so on a writable export a guest-created link
        // (e.g., to `/` or `../..`) could make later lookups escape the share onto the host.
        // Supporting this requires the server to confine path resolution to the export.
        unimplemented!()
    }

    fn mkdir_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        metadata: super::backend::CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        let dir = dir.into_typed::<Self>();
        // XXX: as in `create_file_at`, `Tmkdir` cannot set the owning uid.
        self.client.mkdir(
            &dir.fid.fid,
            name,
            metadata.mode.bits().into(),
            u32::from(metadata.owner.group),
        )?;
        // `Tmkdir` only reports the new directory's qid, so a walk is needed to address it.
        //
        // TODO(jayb): the resolver discards this handle, so the walk is pure overhead, and worse, a
        // walk that fails (connection loss, or a concurrent removal) reports a `Tmkdir` that
        // already succeeded as a failure. I should decide if having `mkdir_at` return a dir is the
        // right move, or I want to remove that behavior.
        let (qid_path, fid) = self.walk_one(&dir.fid.fid, name)?;
        Ok(DirHandle::from_typed::<Self>(NinePDirHandle {
            fid,
            qid_path,
            reader: None,
        }))
    }

    fn unlink_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), UnlinkError> {
        Ok(self.remove_at(&dir.into_typed::<Self>(), name, true)?)
    }

    fn rmdir_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), RmdirError> {
        Ok(self.remove_at(&dir.into_typed::<Self>(), name, false)?)
    }

    fn rename_at(
        &self,
        old_dir: DirHandle,
        old_name: &str,
        new_dir: DirHandle,
        new_name: &str,
    ) -> Result<(), RenameError> {
        if [old_name, new_name].iter().any(|name| {
            name.is_empty() || matches!(*name, "." | "..") || name.contains(['/', '\0'])
        }) {
            return Err(PathError::InvalidPathname.into());
        }
        let old_dir = old_dir.into_typed::<Self>();
        let new_dir = new_dir.into_typed::<Self>();
        // Walk without opening, so a final symlink itself is renamed.
        let source = self.own(
            self.client
                .walk(&old_dir.fid.fid, &[old_name])?
                .into_complete_fid()?,
        );
        Ok(self
            .client
            .rename(&source.fid, &new_dir.fid.fid, new_name)?)
    }

    fn set_times(
        &self,
        target: ResolvedTarget<'_>,
        times: &super::SetFileTimes,
    ) -> Result<(), super::errors::SetTimesError> {
        use super::FileTimeUpdate;
        let fid = match target {
            ResolvedTarget::File(h) => h.into_typed::<Self>().fid,
            ResolvedTarget::Dir(h) => h.into_typed::<Self>().fid,
        };
        let mut valid = fcall::SetattrMask::empty();
        let mut stat = fcall::SetAttr::default();
        for (update, value, mask, set_mask) in [
            (
                times.access,
                &mut stat.atime,
                fcall::SetattrMask::ATIME,
                fcall::SetattrMask::ATIME_SET,
            ),
            (
                times.modify,
                &mut stat.mtime,
                fcall::SetattrMask::MTIME,
                fcall::SetattrMask::MTIME_SET,
            ),
        ] {
            match update {
                FileTimeUpdate::Omit => {}
                // Server NOW: same clock the server uses for this file's other timestamps.
                FileTimeUpdate::Now => valid |= mask,
                FileTimeUpdate::Set(time) => {
                    valid |= mask | set_mask;
                    value.sec = time.seconds.cast_unsigned();
                    value.nsec = u64::from(time.nanoseconds);
                }
            }
        }
        if valid.is_empty() {
            return Ok(());
        }
        self.client
            .setattr(&fid.fid, valid, stat)
            .map_err(Into::into)
    }

    fn chmod(&self, h: ResolvedTarget<'_>, mode: super::Mode) -> Result<(), ChmodError> {
        let fid = match h {
            ResolvedTarget::File(h) => h.into_typed::<Self>().fid,
            ResolvedTarget::Dir(h) => h.into_typed::<Self>().fid,
        };
        let stat = fcall::SetAttr {
            mode: mode.bits().into(),
            ..Default::default()
        };
        Ok(self
            .client
            .setattr(&fid.fid, fcall::SetattrMask::MODE, stat)?)
    }

    fn chown(
        &self,
        h: ResolvedTarget<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let fid = match h {
            ResolvedTarget::File(h) => h.into_typed::<Self>().fid,
            ResolvedTarget::Dir(h) => h.into_typed::<Self>().fid,
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
    // `O_APPEND` is not sent: the resolver writes appends at the end of the file itself, and
    // `F_SETFL` can change the flag after the server has opened the file.
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
    } else if qid_type.contains(fcall::QidType::SYMLINK) {
        super::FileType::SymbolicLink
    } else {
        super::FileType::RegularFile
    }
}

/// A server's user or group id as the guest's: one beyond `u16` (e.g., the host's, which QEMU's
/// `security_model=none` passes through) is the overflow id, as for the userland broker's host
/// files.
fn guest_id(id: u32) -> u16 {
    u16::try_from(id).unwrap_or(super::tar_ro::OVERFLOW_ID)
}

/// Convert getattr response to FileStatus
///
/// Inode numbers come from the server's qids; `device_id` is the device the caller reports this
/// filesystem as.
fn rgetattr_to_file_status(
    attr: &fcall::Rgetattr,
    device_id: u64,
) -> Result<super::FileStatus, Error> {
    let file_type = qid_type_to_file_type(attr.qid.typ);
    let times = if attr
        .valid
        .contains(fcall::GetattrMask::ATIME | fcall::GetattrMask::MTIME | fcall::GetattrMask::CTIME)
    {
        let convert = |time: fcall::Time| -> Result<super::FileTimestamp, Error> {
            if time.nsec >= 1_000_000_000 {
                return Err(Error::InvalidResponse);
            }
            Ok(super::FileTimestamp {
                seconds: i64::from_ne_bytes(time.sec.to_ne_bytes()),
                nanoseconds: u32::try_from(time.nsec).map_err(|_| Error::InvalidResponse)?,
            })
        };
        Some(super::FileTimestamps {
            accessed: convert(attr.stat.atime)?,
            modified: convert(attr.stat.mtime)?,
            changed: convert(attr.stat.ctime)?,
        })
    } else {
        None
    };

    if attr.valid.contains(fcall::GetattrMask::BASIC) {
        Ok(super::FileStatus {
            file_type,
            mode: super::Mode::from_u32_bits_truncate(attr.stat.mode),
            size: attr.stat.size,
            owner: super::UserInfo {
                user: guest_id(attr.stat.uid),
                group: guest_id(attr.stat.gid),
            },
            node_info: super::NodeInfo {
                dev: device_id,
                ino: attr.qid.path,
                rdev: NonZeroU64::new(attr.stat.rdev),
            },
            times,
            blksize: attr.stat.blksize,
        })
    } else {
        Ok(super::FileStatus {
            file_type,
            mode: if attr.valid.contains(fcall::GetattrMask::MODE) {
                super::Mode::from_u32_bits_truncate(attr.stat.mode)
            } else {
                super::Mode::empty()
            },
            size: if attr.valid.contains(fcall::GetattrMask::SIZE) {
                attr.stat.size
            } else {
                0
            },
            owner: super::UserInfo {
                user: if attr.valid.contains(fcall::GetattrMask::UID) {
                    guest_id(attr.stat.uid)
                } else {
                    0
                },
                group: if attr.valid.contains(fcall::GetattrMask::GID) {
                    guest_id(attr.stat.gid)
                } else {
                    0
                },
            },
            node_info: super::NodeInfo {
                dev: device_id,
                ino: attr.qid.path,
                rdev: if attr.valid.contains(fcall::GetattrMask::RDEV) {
                    NonZeroU64::new(attr.stat.rdev)
                } else {
                    None
                },
            },
            times,
            blksize: if attr.valid.contains(fcall::GetattrMask::BLOCKS) {
                attr.stat.blksize
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
const EBUSY: u32 = 16;
const EEXIST: u32 = 17;
const EXDEV: u32 = 18;
const ENOTDIR: u32 = 20;
const EISDIR: u32 = 21;
const EINVAL: u32 = 22;
const ESPIPE: u32 = 29;
const EROFS: u32 = 30;
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

    /// The broker failed the operation itself, such as when copying to or from
    /// the caller's buffer faulted or it ran out of memory
    #[error(transparent)]
    Broker(#[from] BrokerError),
}

impl From<Fault> for Error {
    fn from(fault: Fault) -> Self {
        Self::Broker(fault.into())
    }
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
            Error::Io | Error::InvalidResponse | Error::Broker(_) => OpenError::Io,
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
            Error::Broker(error) => ReadError::Broker(error),
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
            Error::Broker(error) => WriteError::Broker(error),
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
            Error::Io | Error::InvalidResponse | Error::Broker(_) => MkdirError::Io,
        }
    }
}

impl From<Error> for ReadDirError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                // Reading an open directory fails with ENOENT once it has been removed.
                ENOENT => ReadDirError::Removed,
                ENOTDIR => ReadDirError::NotADirectory,
                _ => ReadDirError::Io,
            },
            Error::Io | Error::InvalidResponse | Error::InvalidPathname | Error::Broker(_) => {
                ReadDirError::Io
            }
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
            Error::Io | Error::InvalidResponse | Error::Broker(_) => UnlinkError::Io,
        }
    }
}

impl From<Error> for RenameError {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidPathname => Self::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOENT => Self::PathError(PathError::NoSuchFileOrDirectory),
                EPERM | EACCES => Self::NoWritePerms,
                EBUSY => Self::Busy,
                // Unsupported atomic rename is EXDEV, never copy/delete.
                EXDEV | ENOSYS | EOPNOTSUPP => Self::CrossDevice,
                EINVAL => Self::InvalidArgument,
                EISDIR => Self::IsADirectory,
                ENOTDIR => Self::NotADirectory,
                ENOTEMPTY | EEXIST => Self::NotEmpty,
                EROFS => Self::ReadOnlyFileSystem,
                ENAMETOOLONG => Self::PathError(PathError::InvalidPathname),
                _ => Self::Io,
            },
            Error::Io | Error::InvalidResponse | Error::Broker(_) => Self::Io,
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
            Error::Io | Error::InvalidResponse | Error::Broker(_) => RmdirError::Io,
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
            Error::Io | Error::InvalidResponse | Error::Broker(_) => FileStatusError::Io,
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
            Error::Io | Error::InvalidResponse | Error::InvalidPathname | Error::Broker(_) => {
                TruncateError::Io
            }
        }
    }
}

impl From<Error> for super::errors::SetTimesError {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidPathname => Self::PathError(PathError::InvalidPathname),
            Error::Remote(code) => match code {
                EPERM => Self::NotTheOwner,
                EACCES => Self::AccessNotAllowed,
                EROFS => Self::ReadOnlyFileSystem,
                ENOSYS | EOPNOTSUPP => Self::NotSupported,
                ENOENT => Self::PathError(PathError::NoSuchFileOrDirectory),
                ENOTDIR => Self::PathError(PathError::ComponentNotADirectory),
                ENAMETOOLONG => Self::PathError(PathError::InvalidPathname),
                _ => Self::Io,
            },
            Error::Io | Error::InvalidResponse | Error::Broker(_) => Self::Io,
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
            Error::Io | Error::InvalidResponse | Error::Broker(_) => ChmodError::Io,
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
            Error::Io | Error::InvalidResponse | Error::Broker(_) => ChownError::Io,
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
            Error::Io | Error::InvalidResponse | Error::Broker(_) => WalkError::Io,
        }
    }
}

impl From<Rlerror> for Error {
    fn from(err: Rlerror) -> Self {
        Error::Remote(err.ecode)
    }
}

/// Maps an error the server reported to `None`, keeping transport failures as errors.
fn server_refusal_as_none<V>(result: Result<V, Error>) -> Result<Option<V>, WalkError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Error::Remote(_)) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Whether `attr` describes a removed object; servers that omit the link count never report one.
fn is_unlinked(attr: &fcall::Rgetattr) -> bool {
    attr.valid.contains(fcall::GetattrMask::NLINK) && attr.stat.nlink == 0
}
