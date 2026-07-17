// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Support for composing [`Backend`]s by mounting them.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::backend::{
    Backend, BackendHandles, DirHandle, FileHandle, PermissionCheck, Permissioned, SeekBehavior,
    WalkOutcome, WalkStopReason, WalkedComponent, WalkingDirHandle,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::inode_allocator::InodeAllocator;
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, UserInfo};
use crate::path::Arg;
use thiserror::Error;

// XXX(jayb): consider removing this via a runtime reserved device ID?
const VIRTUAL_DIR_DEVICE_ID: u64 = 0x436f_6d70;

/// A [`Backend`] composed from mounted [`Backend`]s at various paths.
pub struct Composer {
    mounts: Vec<Mount>,
    // TODO(jayb): We have these to account for `/mnt` in something like mounting `/mnt/foo`; I am
    // not certain this is the best design (maybe we should have something _explicitly_ make
    // `/mnt`), but for now, this is the design I've chosen.
    virtual_dirs: Vec<VirtualDir>,
}

/// A [`Composer`] builder.
pub struct ComposerBuilder {
    mounts: Vec<(Option<String>, Box<dyn Backend>)>,
    next_backend_device_id: u64,
}

/// A mounted backend.
struct Mount {
    path: Vec<String>,
    backend: Box<dyn Backend>,
}

/// Synthetic directory needed to connect mount points.
#[derive(Clone)]
struct VirtualDir {
    path: Vec<String>,
    node_info: NodeInfo,
}

/// Composer construction errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    #[error("composer must have at least one mount")]
    NoMounts,
    #[error("mount paths must be absolute normalized paths")]
    InvalidMountPath,
    #[error("two backends were mounted at the same path")]
    DuplicateMountPath,
}

impl Composer {
    /// Start building an empty composer.
    #[must_use]
    pub fn builder() -> ComposerBuilder {
        ComposerBuilder {
            mounts: vec![],
            next_backend_device_id: 1,
        }
    }
}

impl ComposerBuilder {
    /// Add a backend mounted at `path`.
    #[must_use]
    pub fn mount<B: Backend>(
        mut self,
        path: impl Arg,
        backend: impl FnOnce(InodeAllocator) -> B,
    ) -> Self {
        let backend_device_id = self.next_backend_device_id;
        // TODO(jayb): Decide whether we need a fallible version of closure-based mount.
        let backend = backend(InodeAllocator::for_device(backend_device_id));
        self.mounts
            .push((path.as_rust_str().map(Into::into).ok(), Box::new(backend)));
        self.next_backend_device_id = backend_device_id + 1;
        self
    }

    /// Validate mount paths and finalize the composer.
    pub fn build(self) -> Result<Composer, BuildError> {
        if self.mounts.is_empty() {
            return Err(BuildError::NoMounts);
        }

        let mut mounts = vec![];
        let mut paths = vec![];
        for (raw, backend) in self.mounts {
            let raw = raw.ok_or(BuildError::InvalidMountPath)?;
            if !raw.starts_with('/') {
                return Err(BuildError::InvalidMountPath);
            }
            let path: Vec<String> = raw
                .split('/')
                .skip(1)
                .filter(|component| !component.is_empty())
                .map(ToString::to_string)
                .collect();
            if path
                .iter()
                .any(|component| component == "." || component == "..")
            {
                return Err(BuildError::InvalidMountPath);
            }
            if raw != format!("/{}", path.join("/")) {
                // Just confirming that it is absolute + canonical
                return Err(BuildError::InvalidMountPath);
            }
            paths.push(path.clone());
            mounts.push(Mount { path, backend });
        }

        let sorted_paths = {
            let mut p = paths.clone();
            p.sort();
            p
        };
        if sorted_paths.array_windows().any(|[a, b]| a == b) {
            return Err(BuildError::DuplicateMountPath);
        }

        // TODO(jayb): Decide whether mounting a deep path should implicitly synthesize
        // missing ancestor directories like `/mnt` and `/mnt/foo`.
        let virtual_dir_allocator = InodeAllocator::for_device(VIRTUAL_DIR_DEVICE_ID);
        let mut virtual_dirs = vec![];
        for mount_path in paths {
            for len in 0..mount_path.len() {
                let path = mount_path[..len].to_vec();
                if MountRelation::of(&mounts, &path) == MountRelation::Exact
                    || virtual_dirs.iter().any(|dir: &VirtualDir| dir.path == path)
                {
                    continue;
                }
                virtual_dirs.push(VirtualDir {
                    path,
                    node_info: virtual_dir_allocator.next(),
                });
            }
        }

        // TODO(jayb): Validate mounted backend device IDs once backends expose that cheaply.
        Ok(Composer {
            mounts,
            virtual_dirs,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountRelation {
    Exact,
    AncestorOfMount,
    Unrelated,
}

impl MountRelation {
    fn of(mounts: &[Mount], path: &[String]) -> Self {
        for mount in mounts {
            if mount.path == path {
                return MountRelation::Exact;
            }
            if path.len() < mount.path.len() && mount.path.starts_with(path) {
                return MountRelation::AncestorOfMount;
            }
        }
        MountRelation::Unrelated
    }
}

fn append_components(mut path: Vec<String>, components: &[&str]) -> Vec<String> {
    path.extend(components.iter().map(|component| (*component).to_string()));
    path
}

impl Composer {
    fn mount_relation(&self, path: &[String]) -> MountRelation {
        MountRelation::of(&self.mounts, path)
    }

    /// This function exists primarily to simplify + mark implementations of mutating operations
    /// where the mutation semantics of exact mount points have not been fully figured out. This is
    /// equivalnet to `Ok(path + [name])`, but errors out if anything is either a mount point or an
    /// ancestor of a mount point.
    fn checked_child_path<E>(
        &self,
        path: Vec<String>,
        name: &str,
        error: E,
    ) -> Result<Vec<String>, E> {
        let path = append_components(path, &[name]);
        if self.mount_relation(&path) != MountRelation::Unrelated {
            // TODO(jayb): Define mutation semantics for exact mount points.
            return Err(error);
        }
        Ok(path)
    }

    /// Returns child names from mount paths only; mounted backend contents are not inspected.
    fn immediate_mount_children(&self, path: &[String]) -> Vec<String> {
        let mut children = vec![];
        for mount in &self.mounts {
            if path.len() < mount.path.len() && mount.path.starts_with(path) {
                let child = mount.path[path.len()].clone();
                if !children.contains(&child) {
                    children.push(child);
                }
            }
        }
        children
    }

    fn list_mount_children(&self, path: &[String]) -> Vec<DirEntry> {
        self.immediate_mount_children(path)
            .into_iter()
            .map(|name| DirEntry {
                name,
                file_type: FileType::Directory,
                // TODO(jayb): set up proper inode info for these
                ino_info: None,
            })
            .collect()
    }

    fn merge_mount_children(&self, mut entries: Vec<DirEntry>, path: &[String]) -> Vec<DirEntry> {
        for child in self.list_mount_children(path) {
            entries.retain(|entry| entry.name != child.name);
            entries.push(child);
        }
        entries
    }

    fn exact_mount_root(&self, path: &[String]) -> Option<(usize, WalkingDirHandle<'_>)> {
        self.mounts
            .iter()
            .enumerate()
            .find(|(_, mount)| mount.path == path)
            .map(|(index, mount)| (index, mount.backend.root()))
    }

    fn root_handle(&self) -> ComposerWalkingDirHandle<'_> {
        if let Some((mount_index, handle)) = self.exact_mount_root(&[]) {
            ComposerWalkingDirHandleInner::Mounted {
                path: vec![],
                mount_index,
                handle,
            }
            .into()
        } else {
            ComposerWalkingDirHandleInner::Virtual { path: vec![] }.into()
        }
    }

    fn virtual_dir_status(&self, path: &[String]) -> FileStatus {
        let node_info = self
            .virtual_dirs
            .iter()
            .find(|dir| dir.path == path)
            .map(|dir| dir.node_info.clone())
            .expect("virtual directory is precomputed");
        FileStatus {
            file_type: FileType::Directory,
            // rwxr-xr-x for virtual dirs
            mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
            size: super::DEFAULT_DIRECTORY_SIZE,
            owner: UserInfo::ROOT,
            node_info,
            blksize: super::DEFAULT_DIRECTORY_SIZE,
        }
    }

    /// Returns how many components can be walked before reaching another mount boundary.
    fn mounted_walk_prefix_len(&self, path: &[String], components: &[&str]) -> usize {
        let mut next_path = path.to_vec();
        for (idx, component) in components.iter().enumerate() {
            next_path = append_components(next_path, &[*component]);
            if self.mount_relation(&next_path) != MountRelation::Unrelated {
                return idx;
            }
        }
        components.len()
    }
}

/// Borrowed directory handle in a composed filesystem namespace.
pub struct ComposerWalkingDirHandle<'a> {
    inner: ComposerWalkingDirHandleInner<'a>,
}

enum ComposerWalkingDirHandleInner<'a> {
    Virtual {
        path: Vec<String>,
    },
    Mounted {
        path: Vec<String>,
        mount_index: usize,
        handle: WalkingDirHandle<'a>,
    },
}

impl<'a> From<ComposerWalkingDirHandleInner<'a>> for ComposerWalkingDirHandle<'a> {
    fn from(inner: ComposerWalkingDirHandleInner<'a>) -> Self {
        Self { inner }
    }
}

/// File handle in a composed filesystem namespace.
pub struct ComposerFileHandle {
    mount_index: usize,
    handle: FileHandle,
}

/// Owned directory handle in a composed filesystem namespace.
pub struct ComposerDirHandle {
    inner: ComposerDirHandleInner,
}

enum ComposerDirHandleInner {
    Virtual {
        path: Vec<String>,
    },
    Mounted {
        path: Vec<String>,
        mount_index: usize,
        handle: DirHandle,
    },
}

impl From<ComposerDirHandleInner> for ComposerDirHandle {
    fn from(inner: ComposerDirHandleInner) -> Self {
        Self { inner }
    }
}

impl Clone for ComposerFileHandle {
    fn clone(&self) -> Self {
        Self {
            mount_index: self.mount_index,
            handle: self.handle.clone(),
        }
    }
}

impl Clone for ComposerDirHandle {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Clone for ComposerDirHandleInner {
    fn clone(&self) -> Self {
        match self {
            Self::Virtual { path } => Self::Virtual { path: path.clone() },
            Self::Mounted {
                path,
                mount_index,
                handle,
            } => Self::Mounted {
                path: path.clone(),
                mount_index: *mount_index,
                handle: handle.clone(),
            },
        }
    }
}

impl super::backend::private::Sealed for Composer {}

impl BackendHandles for Composer {
    type WalkingDirHandle<'a> = ComposerWalkingDirHandle<'a>;
    type FileHandle = ComposerFileHandle;
    type DirHandle = ComposerDirHandle;
}

impl Backend for Composer {
    fn root(&self) -> WalkingDirHandle<'_> {
        WalkingDirHandle::from_typed::<Self>(self.root_handle())
    }

    fn walk_directories<'a>(
        &'a self,
        from: WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<WalkOutcome<WalkingDirHandle<'a>>, WalkError> {
        const BY_BACKEND: WalkedComponent = WalkedComponent {
            permissions: PermissionCheck::ByBackend,
        };
        let mut current = from.into_typed::<Self>();
        let mut walked_components = Vec::with_capacity(components.len());
        let mut index = 0;
        while index < components.len() {
            let component = components[index];
            match current.inner {
                ComposerWalkingDirHandleInner::Virtual { path } => {
                    let path = append_components(path, &[component]);
                    if let Some((mount_index, handle)) = self.exact_mount_root(&path) {
                        walked_components.push(BY_BACKEND);
                        current = ComposerWalkingDirHandleInner::Mounted {
                            path,
                            mount_index,
                            handle,
                        }
                        .into();
                    } else if self.mount_relation(&path) == MountRelation::AncestorOfMount {
                        walked_components.push(BY_BACKEND);
                        current = ComposerWalkingDirHandleInner::Virtual { path }.into();
                    } else {
                        return Err(WalkError::PathError(PathError::NoSuchFileOrDirectory));
                    }
                    index += 1;
                }
                ComposerWalkingDirHandleInner::Mounted {
                    path,
                    mount_index,
                    handle,
                } => {
                    let child_path = append_components(path.clone(), &[component]);
                    if let Some((child_mount_index, child_handle)) =
                        self.exact_mount_root(&child_path)
                    {
                        walked_components.push(BY_BACKEND);
                        current = ComposerWalkingDirHandleInner::Mounted {
                            path: child_path,
                            mount_index: child_mount_index,
                            handle: child_handle,
                        }
                        .into();
                        index += 1;
                    } else if self.mount_relation(&child_path) == MountRelation::AncestorOfMount {
                        match self.mounts[mount_index]
                            .backend
                            .walk_directories(handle, &[component])
                        {
                            Ok(outcome) => {
                                let walked_len = outcome.components.len();
                                assert!(walked_len <= 1);
                                assert!(
                                    outcome.stop_reason != WalkStopReason::CompleteDirectory
                                        || walked_len == 1
                                );
                                walked_components.extend(outcome.components);
                                let last = ComposerWalkingDirHandleInner::Mounted {
                                    path: append_components(
                                        path,
                                        &components[index..index + walked_len],
                                    ),
                                    mount_index,
                                    handle: outcome.last,
                                }
                                .into();
                                match outcome.stop_reason {
                                    WalkStopReason::CompleteDirectory => {
                                        index += walked_len;
                                        current = last;
                                    }
                                    WalkStopReason::StoppedAtNonDirectory
                                    | WalkStopReason::Continue => {
                                        return Ok(WalkOutcome {
                                            components: walked_components,
                                            last: WalkingDirHandle::from_typed::<Self>(last),
                                            stop_reason: outcome.stop_reason,
                                        });
                                    }
                                }
                            }
                            Err(WalkError::PathError(PathError::NoSuchFileOrDirectory)) => {
                                walked_components.push(BY_BACKEND);
                                current =
                                    ComposerWalkingDirHandleInner::Virtual { path: child_path }
                                        .into();
                                index += 1;
                            }
                            Err(error) => return Err(error),
                        }
                    } else {
                        // TODO(jayb): Decide whether future backends need absolute-ish namespace
                        // views instead of this mount-root-relative suffix view. POSIX `..` across
                        // mount roots is also deferred; the resolver normalizes it before walking.
                        let prefix_len = self.mounted_walk_prefix_len(&path, &components[index..]);
                        assert!(prefix_len > 0);
                        let outcome = self.mounts[mount_index]
                            .backend
                            .walk_directories(handle, &components[index..index + prefix_len])?;
                        let walked_len = outcome.components.len();
                        assert!(
                            outcome.stop_reason != WalkStopReason::CompleteDirectory
                                || walked_len == prefix_len
                        );
                        walked_components.extend(outcome.components);
                        let last = ComposerWalkingDirHandleInner::Mounted {
                            path: append_components(path, &components[index..index + walked_len]),
                            mount_index,
                            handle: outcome.last,
                        }
                        .into();
                        match outcome.stop_reason {
                            WalkStopReason::CompleteDirectory => {
                                index += walked_len;
                                current = last;
                            }
                            WalkStopReason::StoppedAtNonDirectory | WalkStopReason::Continue => {
                                return Ok(WalkOutcome {
                                    components: walked_components,
                                    last: WalkingDirHandle::from_typed::<Self>(last),
                                    stop_reason: outcome.stop_reason,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(WalkOutcome {
            components: walked_components,
            last: WalkingDirHandle::from_typed::<Self>(current),
            stop_reason: WalkStopReason::CompleteDirectory,
        })
    }

    fn owned_dir_at(
        &self,
        dir: WalkingDirHandle<'_>,
        flags: OFlags,
    ) -> Result<DirHandle, OpenError> {
        let dir = dir.into_typed::<Self>();
        let inner = match dir.inner {
            ComposerWalkingDirHandleInner::Virtual { path } => {
                ComposerDirHandleInner::Virtual { path }
            }
            ComposerWalkingDirHandleInner::Mounted {
                path,
                mount_index,
                handle,
            } => ComposerDirHandleInner::Mounted {
                path,
                mount_index,
                handle: self.mounts[mount_index]
                    .backend
                    .owned_dir_at(handle, flags)?,
            },
        };
        Ok(DirHandle::from_typed::<Self>(ComposerDirHandle { inner }))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<WalkingDirHandle<'a>> {
        let dir = dir.get_typed::<Self>();
        match &dir.inner {
            ComposerDirHandleInner::Virtual { path } => Some(WalkingDirHandle::from_typed::<Self>(
                ComposerWalkingDirHandleInner::Virtual { path: path.clone() }.into(),
            )),
            ComposerDirHandleInner::Mounted {
                path,
                mount_index,
                handle,
            } => self.mounts[*mount_index]
                .backend
                .walking_dir_at(handle)
                .map(|handle| {
                    WalkingDirHandle::from_typed::<Self>(
                        ComposerWalkingDirHandleInner::Mounted {
                            path: path.clone(),
                            mount_index: *mount_index,
                            handle,
                        }
                        .into(),
                    )
                }),
        }
    }

    fn open_file_at(
        &self,
        dir: WalkingDirHandle<'_>,
        name: &str,
        flags: OFlags,
    ) -> Result<Permissioned<FileHandle>, OpenError> {
        let dir = dir.into_typed::<Self>();
        match dir.inner {
            ComposerWalkingDirHandleInner::Virtual { .. } => {
                Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
            }
            ComposerWalkingDirHandleInner::Mounted {
                path,
                mount_index,
                handle,
            } => {
                self.checked_child_path(
                    path,
                    name,
                    OpenError::PathError(PathError::NoSuchFileOrDirectory),
                )?;
                self.mounts[mount_index]
                    .backend
                    .open_file_at(handle, name, flags)
                    .map(|file| Permissioned {
                        item: FileHandle::from_typed::<Self>(ComposerFileHandle {
                            mount_index,
                            handle: file.item,
                        }),
                        permissions: file.permissions,
                    })
            }
        }
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        let handle = handle.into_typed::<Self>();
        match handle.inner {
            ComposerDirHandleInner::Virtual { path } => Ok(self.list_mount_children(&path)),
            ComposerDirHandleInner::Mounted {
                path,
                mount_index,
                handle,
            } => {
                let entries = self.mounts[mount_index].backend.list_dir_at(handle)?;
                Ok(self.merge_mount_children(entries, &path))
            }
        }
    }

    fn read(&self, h: &FileHandle, buf: &mut [u8], offset: usize) -> Result<usize, ReadError> {
        let h = h.get_typed::<Self>();
        self.mounts[h.mount_index]
            .backend
            .read(&h.handle, buf, offset)
    }

    fn get_static_backing_data(&self, h: &FileHandle) -> Option<&'static [u8]> {
        let h = h.get_typed::<Self>();
        self.mounts[h.mount_index]
            .backend
            .get_static_backing_data(&h.handle)
    }

    fn write(&self, h: &FileHandle, buf: &[u8], offset: usize) -> Result<usize, WriteError> {
        let h = h.get_typed::<Self>();
        self.mounts[h.mount_index]
            .backend
            .write(&h.handle, buf, offset)
    }

    fn truncate(&self, h: &FileHandle, length: usize) -> Result<(), TruncateError> {
        let h = h.get_typed::<Self>();
        self.mounts[h.mount_index]
            .backend
            .truncate(&h.handle, length)
    }

    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior {
        let h = h.get_typed::<Self>();
        self.mounts[h.mount_index].backend.seek_behavior(&h.handle)
    }

    fn file_status(&self, h: &FileHandle) -> Result<FileStatus, FileStatusError> {
        let h = h.get_typed::<Self>();
        self.mounts[h.mount_index].backend.file_status(&h.handle)
    }

    fn dir_status(&self, h: &DirHandle) -> Result<FileStatus, FileStatusError> {
        let h = h.get_typed::<Self>();
        match &h.inner {
            ComposerDirHandleInner::Virtual { path } => Ok(self.virtual_dir_status(path)),
            ComposerDirHandleInner::Mounted {
                mount_index,
                handle,
                ..
            } => self.mounts[*mount_index].backend.dir_status(handle),
        }
    }

    fn create_file_at(
        &self,
        dir: DirHandle,
        name: &str,
        mode: Mode,
    ) -> Result<FileHandle, OpenError> {
        let dir = dir.into_typed::<Self>();
        match dir.inner {
            ComposerDirHandleInner::Virtual { .. } => Err(OpenError::ReadOnlyFileSystem),
            ComposerDirHandleInner::Mounted {
                path,
                mount_index,
                handle,
            } => {
                self.checked_child_path(path, name, OpenError::ReadOnlyFileSystem)?;
                self.mounts[mount_index]
                    .backend
                    .create_file_at(handle, name, mode)
                    .map(|handle| {
                        FileHandle::from_typed::<Self>(ComposerFileHandle {
                            mount_index,
                            handle,
                        })
                    })
            }
        }
    }

    fn mkdir_at(&self, dir: DirHandle, name: &str, mode: Mode) -> Result<DirHandle, MkdirError> {
        let dir = dir.into_typed::<Self>();
        match dir.inner {
            ComposerDirHandleInner::Virtual { .. } => Err(MkdirError::ReadOnlyFileSystem),
            ComposerDirHandleInner::Mounted {
                path,
                mount_index,
                handle,
            } => {
                let path = self.checked_child_path(path, name, MkdirError::ReadOnlyFileSystem)?;
                self.mounts[mount_index]
                    .backend
                    .mkdir_at(handle, name, mode)
                    .map(|handle| {
                        DirHandle::from_typed::<Self>(
                            ComposerDirHandleInner::Mounted {
                                path,
                                mount_index,
                                handle,
                            }
                            .into(),
                        )
                    })
            }
        }
    }

    fn unlink_at(&self, dir: DirHandle, name: &str) -> Result<(), UnlinkError> {
        let dir = dir.into_typed::<Self>();
        match dir.inner {
            ComposerDirHandleInner::Virtual { .. } => Err(UnlinkError::ReadOnlyFileSystem),
            ComposerDirHandleInner::Mounted {
                path,
                mount_index,
                handle,
            } => {
                self.checked_child_path(path, name, UnlinkError::ReadOnlyFileSystem)?;
                self.mounts[mount_index].backend.unlink_at(handle, name)
            }
        }
    }

    fn rmdir_at(&self, dir: DirHandle, name: &str) -> Result<(), RmdirError> {
        let dir = dir.into_typed::<Self>();
        match dir.inner {
            ComposerDirHandleInner::Virtual { .. } => Err(RmdirError::ReadOnlyFileSystem),
            ComposerDirHandleInner::Mounted {
                path,
                mount_index,
                handle,
            } => {
                self.checked_child_path(path, name, RmdirError::ReadOnlyFileSystem)?;
                self.mounts[mount_index].backend.rmdir_at(handle, name)
            }
        }
    }

    fn chmod_at(&self, dir: DirHandle, name: &str, mode: Mode) -> Result<(), ChmodError> {
        let dir = dir.into_typed::<Self>();
        match dir.inner {
            ComposerDirHandleInner::Virtual { .. } => Err(ChmodError::ReadOnlyFileSystem),
            ComposerDirHandleInner::Mounted {
                path,
                mount_index,
                handle,
            } => {
                self.checked_child_path(path, name, ChmodError::ReadOnlyFileSystem)?;
                self.mounts[mount_index]
                    .backend
                    .chmod_at(handle, name, mode)
            }
        }
    }

    fn chown_at(
        &self,
        dir: DirHandle,
        name: &str,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let dir = dir.into_typed::<Self>();
        match dir.inner {
            ComposerDirHandleInner::Virtual { .. } => Err(ChownError::ReadOnlyFileSystem),
            ComposerDirHandleInner::Mounted {
                path,
                mount_index,
                handle,
            } => {
                self.checked_child_path(path, name, ChownError::ReadOnlyFileSystem)?;
                self.mounts[mount_index]
                    .backend
                    .chown_at(handle, name, user, group)
            }
        }
    }
}
