// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A read-only view of another filesystem backend.
//!
//! Reads, metadata, permissions, and node identities are preserved. Mutations through this view
//! are refused; other users of the underlying storage can still change it. Reads and read-only
//! opens retain any backend-specific side effects, such as access-time updates or device I/O.
//!
//! As on a Linux read-only mount, removals and renames report a read-only error before looking up
//! the name, and creations report an existing name first. Unlike Linux, the resolver may report
//! permission denial before a read-only error for metadata changes, and writable opens are refused
//! even for device nodes.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use super::backend::{
    Backend, CreationMetadata, DirHandle, FileHandle, FileTerminal, HandleRef, PermissionCheck,
    PermissionInfo, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget, SeekBehavior,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MapSharedError, MkdirError, OpenError, ReadDirError,
    ReadError, RenameError, ResolutionError, RmdirError, SetTimesError, SymlinkError,
    TruncateError, UnlinkError, WalkError, WriteError,
};
use super::shared_storage::SharedFile;
use super::{DirEntry, FileStatus, FileType, Mode, OFlags, UserInfo};
use crate::readiness::ReadinessSource;

/// A [`Backend`] that refuses changes to an inner backend.
pub struct ReadOnly<B: Backend> {
    inner: B,
}

impl<B: Backend> ReadOnly<B> {
    /// Wrap `inner` in a read-only view without modifying its contents or permissions.
    #[must_use]
    pub fn new(inner: B) -> Self {
        Self { inner }
    }
}

fn mark_read_only(permissions: &mut PermissionCheck) {
    match permissions {
        PermissionCheck::ByResolver(permissions) => permissions.on_read_only_fs = true,
        PermissionCheck::ByBackend => {
            // ByBackend backends are covered by the open-flag and mutation checks below.
        }
    }
}

// Strip APPEND so an Overlay inner backend doesn't copy up on a read-only open.
fn read_only_flags(flags: OFlags) -> Result<OFlags, OpenError> {
    if flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::TRUNC) {
        return Err(OpenError::ReadOnlyFileSystem);
    }
    Ok(flags - OFlags::APPEND)
}

impl<B: Backend> Backend for ReadOnly<B> {
    fn root(&self) -> Result<ResolvedDir<'_>, WalkError> {
        let mut dir = self.inner.root()?;
        mark_read_only(&mut dir.permissions);
        Ok(dir)
    }

    fn resolve<'a>(
        &'a self,
        from: ResolvedDir<'a>,
        components: &[&str],
        authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        let mut resolution = self.inner.resolve(from, components, authorize_dir_lookup)?;
        match &mut resolution {
            Resolution::Found(ResolvedTarget::Dir(dir))
            | Resolution::MissingFinal { parent: dir } => mark_read_only(&mut dir.permissions),
            Resolution::Found(ResolvedTarget::File(file)) => {
                mark_read_only(&mut file.permissions);
            }
        }
        Ok(resolution)
    }

    fn read_link_at(&self, dir: &ResolvedDir<'_>, name: &str) -> Result<String, WalkError> {
        self.inner.read_link_at(dir, name)
    }

    fn open_dir(&self, dir: ResolvedDir<'_>, flags: OFlags) -> Result<DirHandle, OpenError> {
        self.inner.open_dir(dir, read_only_flags(flags)?)
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<ResolvedDir<'a>> {
        let mut dir = self.inner.walking_dir_at(dir)?;
        mark_read_only(&mut dir.permissions);
        Some(dir)
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        if matches!(file.file_type, FileType::CharacterDevice)
            && flags.intersects(OFlags::WRONLY | OFlags::RDWR)
        {
            unimplemented!("writable device open on a read-only filesystem");
        }
        self.inner.open_file(file, read_only_flags(flags)?)
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        self.inner.list_dir_at(handle)
    }

    fn lookup_at(&self, dir: &DirHandle, name: &str) -> Result<Option<DirEntry>, ReadDirError> {
        self.inner.lookup_at(dir, name)
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

    fn map_shared(&self, h: &FileHandle) -> Result<Arc<SharedFile>, MapSharedError> {
        self.inner.map_shared(h)
    }

    fn write(
        &self,
        _h: &FileHandle,
        _buf: &dyn WriteBuffer,
        _offset: usize,
    ) -> Result<usize, WriteError> {
        Err(WriteError::NotForWriting)
    }

    fn truncate(&self, _h: &FileHandle, _length: usize) -> Result<(), TruncateError> {
        Err(TruncateError::NotForWriting)
    }

    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior {
        self.inner.seek_behavior(h)
    }

    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        self.inner.status(h)
    }

    fn resolved_status(&self, target: &ResolvedTarget<'_>) -> Result<FileStatus, FileStatusError> {
        self.inner.resolved_status(target)
    }

    fn terminal(&self, h: &FileHandle) -> Option<FileTerminal> {
        self.inner.terminal(h)
    }

    fn readiness_source(&self, h: &FileHandle) -> Option<Arc<dyn ReadinessSource>> {
        self.inner.readiness_source(h)
    }

    fn create_file_at(
        &self,
        _parent: ResolvedDir<'_>,
        _name: &str,
        _metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        Err(OpenError::ReadOnlyFileSystem)
    }

    fn symlink_at(
        &self,
        _dir: ResolvedDir<'_>,
        _name: &str,
        _target: &str,
        _metadata: CreationMetadata,
    ) -> Result<(), SymlinkError> {
        Err(SymlinkError::ReadOnlyFileSystem)
    }

    fn mkdir_at(
        &self,
        _parent: ResolvedDir<'_>,
        _name: &str,
        _metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn unlink_at(&self, _parent: ResolvedDir<'_>, _name: &str) -> Result<(), UnlinkError> {
        Err(UnlinkError::ReadOnlyFileSystem)
    }

    fn rmdir_at(&self, _parent: ResolvedDir<'_>, _name: &str) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn rename_at(
        &self,
        _old_dir: DirHandle,
        _old_name: &str,
        _new_dir: DirHandle,
        _new_name: &str,
    ) -> Result<(), RenameError> {
        Err(RenameError::ReadOnlyFileSystem)
    }

    fn set_times(
        &self,
        _target: ResolvedTarget<'_>,
        _times: &super::SetFileTimes,
    ) -> Result<(), SetTimesError> {
        Err(SetTimesError::ReadOnlyFileSystem)
    }

    fn chmod(&self, _h: ResolvedTarget<'_>, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chmod_handle(
        &self,
        _h: HandleRef<'_>,
        _user: UserInfo,
        _mode: Mode,
    ) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chown(
        &self,
        _h: ResolvedTarget<'_>,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        Err(ChownError::ReadOnlyFileSystem)
    }
}
