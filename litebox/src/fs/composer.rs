// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Support for composing [`Backend`]s by mounting them.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::backend::{
    Backend, BackendHandles, CreationMetadata, DirHandle, FileHandle, HandleRef, PermissionCheck,
    PermissionInfo, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget, SeekBehavior,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, ResolutionError, RmdirError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::inode_allocator::{InodeAllocator, InodeAllocators};
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
    allocators: InodeAllocators,
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
            allocators: InodeAllocators::starting_at(1),
        }
    }
}

impl ComposerBuilder {
    /// Add a backend mounted at `path`.
    #[must_use]
    pub fn mount<B: Backend>(
        self,
        path: impl Arg,
        backend: impl FnOnce(InodeAllocator) -> B,
    ) -> Self {
        self.mount_nestable(path, |allocators| backend(allocators.next()))
    }

    /// Add a backend mounted at `path`, which may draw an allocator per backend it is made of.
    #[must_use]
    pub fn mount_nestable<B: Backend>(
        mut self,
        path: impl Arg,
        backend: impl FnOnce(&InodeAllocators) -> B,
    ) -> Self {
        // TODO(jayb): Decide whether we need a fallible version of closure-based mount.
        let backend = backend(&self.allocators);
        self.mounts
            .push((path.as_rust_str().map(Into::into).ok(), Box::new(backend)));
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
        let mut relation = MountRelation::Unrelated;
        for mount in mounts {
            if mount.path == path {
                return MountRelation::Exact;
            }
            if path.len() < mount.path.len() && mount.path.starts_with(path) {
                relation = MountRelation::AncestorOfMount;
            }
        }
        relation
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

    fn exact_mount_root(
        &self,
        path: &[String],
    ) -> Result<Option<(usize, ResolvedDir<'_>)>, WalkError> {
        self.mounts
            .iter()
            .enumerate()
            .find(|(_, mount)| mount.path == path)
            .map(|(index, mount)| mount.backend.root().map(|root| (index, root)))
            .transpose()
    }

    fn resolved_dir<'a>(&self, dir: ComposerWalkingDirHandle<'a>) -> ResolvedDir<'a> {
        let permissions = match &dir.inner {
            ComposerWalkingDirHandleInner::Virtual { path } => {
                let status = self.virtual_dir_status(path);
                PermissionCheck::ByResolver(PermissionInfo {
                    mode: status.mode,
                    owner: status.owner,
                })
            }
            ComposerWalkingDirHandleInner::Mounted { target, .. } => match target {
                ResolvedTarget::Dir(handle) => handle.permissions.clone(),
                ResolvedTarget::File(_) => unreachable!(),
            },
        };
        ResolvedDir::from_typed::<Self>(dir, permissions)
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
        target: ResolvedTarget<'a>,
    },
}

impl<'a> From<ComposerWalkingDirHandleInner<'a>> for ComposerWalkingDirHandle<'a> {
    fn from(inner: ComposerWalkingDirHandleInner<'a>) -> Self {
        Self { inner }
    }
}

pub struct ComposerResolvedFile<'a> {
    mount_index: usize,
    target: ResolvedTarget<'a>,
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
    type ResolvedDir<'a> = ComposerWalkingDirHandle<'a>;
    type ResolvedFile<'a> = ComposerResolvedFile<'a>;
    type FileHandle = ComposerFileHandle;
    type DirHandle = ComposerDirHandle;
}

impl Backend for Composer {
    fn root(&self) -> Result<ResolvedDir<'_>, WalkError> {
        let inner = match self.exact_mount_root(&[])? {
            Some((mount_index, handle)) => ComposerWalkingDirHandleInner::Mounted {
                path: vec![],
                mount_index,
                target: ResolvedTarget::Dir(handle),
            },
            None => ComposerWalkingDirHandleInner::Virtual { path: vec![] },
        };
        Ok(self.resolved_dir(inner.into()))
    }

    fn resolve<'a>(
        &'a self,
        from: ResolvedDir<'a>,
        components: &[&str],
        authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        let mut current = from;
        let mut index = 0;
        while index < components.len() {
            let fail = |error| ResolutionError {
                component: Some(index),
                error,
            };
            let shift = |mut error: ResolutionError| {
                error.component = error.component.map(|component| component + index);
                error
            };
            let component = components[index];
            let permissions = current.permissions.clone();
            match current.into_typed::<Self>().inner {
                ComposerWalkingDirHandleInner::Virtual { path } => {
                    if let PermissionCheck::ByResolver(permissions) = permissions {
                        authorize_dir_lookup(&permissions).map_err(fail)?;
                    }
                    let child_path = append_components(path.clone(), &[component]);
                    let inner = if let Some((mount_index, handle)) =
                        self.exact_mount_root(&child_path).map_err(fail)?
                    {
                        ComposerWalkingDirHandleInner::Mounted {
                            path: child_path,
                            mount_index,
                            target: ResolvedTarget::Dir(handle),
                        }
                    } else if self.mount_relation(&child_path) == MountRelation::AncestorOfMount {
                        ComposerWalkingDirHandleInner::Virtual { path: child_path }
                    } else if index + 1 == components.len() {
                        return Ok(Resolution::MissingFinal {
                            parent: self.resolved_dir(
                                ComposerWalkingDirHandleInner::Virtual { path }.into(),
                            ),
                        });
                    } else {
                        return Err(fail(PathError::NoSuchFileOrDirectory.into()));
                    };
                    current = self.resolved_dir(inner.into());
                    index += 1;
                }
                ComposerWalkingDirHandleInner::Mounted {
                    path,
                    mount_index,
                    target,
                } => {
                    let ResolvedTarget::Dir(handle) = target else {
                        unreachable!()
                    };
                    let child_path = append_components(path.clone(), &[component]);
                    let relation = self.mount_relation(&child_path);
                    let backend = &self.mounts[mount_index].backend;
                    if relation == MountRelation::Exact {
                        // TODO(DO NOT COMMIT): Overlay's ByResolver policy can hide a nested server's
                        // search denial at this crossing. Either always probe the underlying child
                        // lookup (conservative, but adds I/O and may require directory read access),
                        // or add precise search-only enforcement for resolved directories (needs
                        // backend interface and 9P support investigation).
                        match &handle.permissions {
                            PermissionCheck::ByResolver(permissions) => {
                                authorize_dir_lookup(permissions).map_err(fail)?;
                            }
                            // A server-authorized parent must still be searched before crossing a mount.
                            PermissionCheck::ByBackend => {
                                let _ = backend
                                    .resolve(handle, &[component], authorize_dir_lookup)
                                    .map_err(shift)?;
                            }
                        }
                        let (mount_index, handle) =
                            self.exact_mount_root(&child_path).map_err(fail)?.unwrap();
                        current = self.resolved_dir(
                            ComposerWalkingDirHandleInner::Mounted {
                                path: child_path,
                                mount_index,
                                target: ResolvedTarget::Dir(handle),
                            }
                            .into(),
                        );
                        index += 1;
                        continue;
                    }
                    let prefix_len = if relation == MountRelation::AncestorOfMount {
                        1
                    } else {
                        self.mounted_walk_prefix_len(&path, &components[index..])
                    };
                    let end = index + prefix_len;
                    match backend
                        .resolve(handle, &components[index..end], authorize_dir_lookup)
                        .map_err(shift)?
                    {
                        Resolution::Found(ResolvedTarget::Dir(handle)) => {
                            current = self.resolved_dir(
                                ComposerWalkingDirHandleInner::Mounted {
                                    path: append_components(path, &components[index..end]),
                                    mount_index,
                                    target: ResolvedTarget::Dir(handle),
                                }
                                .into(),
                            );
                        }
                        Resolution::Found(ResolvedTarget::File(handle)) => {
                            if end != components.len() {
                                return Err(ResolutionError {
                                    component: Some(end),
                                    error: PathError::ComponentNotADirectory.into(),
                                });
                            }
                            let permissions = handle.permissions.clone();
                            return Ok(Resolution::Found(ResolvedTarget::File(
                                ResolvedFile::from_typed::<Self>(
                                    ComposerResolvedFile {
                                        mount_index,
                                        target: ResolvedTarget::File(handle),
                                    },
                                    permissions,
                                ),
                            )));
                        }
                        Resolution::MissingFinal { .. }
                            if relation == MountRelation::AncestorOfMount =>
                        {
                            current = self.resolved_dir(
                                ComposerWalkingDirHandleInner::Virtual { path: child_path }.into(),
                            );
                        }
                        Resolution::MissingFinal { parent } if end == components.len() => {
                            return Ok(Resolution::MissingFinal {
                                parent: self.resolved_dir(
                                    ComposerWalkingDirHandleInner::Mounted {
                                        path: append_components(path, &components[index..end - 1]),
                                        mount_index,
                                        target: ResolvedTarget::Dir(parent),
                                    }
                                    .into(),
                                ),
                            });
                        }
                        Resolution::MissingFinal { .. } => {
                            return Err(ResolutionError {
                                component: Some(end - 1),
                                error: PathError::NoSuchFileOrDirectory.into(),
                            });
                        }
                    }
                    index = end;
                }
            }
        }
        Ok(Resolution::Found(ResolvedTarget::Dir(current)))
    }

    fn open_dir(&self, dir: ResolvedDir<'_>, flags: OFlags) -> Result<DirHandle, OpenError> {
        let dir = dir.into_typed::<Self>();
        let inner = match dir.inner {
            ComposerWalkingDirHandleInner::Virtual { path } => {
                ComposerDirHandleInner::Virtual { path }
            }
            ComposerWalkingDirHandleInner::Mounted {
                path,
                mount_index,
                target,
            } => {
                let ResolvedTarget::Dir(handle) = target else {
                    unreachable!()
                };
                ComposerDirHandleInner::Mounted {
                    path,
                    mount_index,
                    handle: self.mounts[mount_index].backend.open_dir(handle, flags)?,
                }
            }
        };
        Ok(DirHandle::from_typed::<Self>(ComposerDirHandle { inner }))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<ResolvedDir<'a>> {
        let dir = dir.get_typed::<Self>();
        match &dir.inner {
            ComposerDirHandleInner::Virtual { path } => Some(self.resolved_dir(
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
                    self.resolved_dir(
                        ComposerWalkingDirHandleInner::Mounted {
                            path: path.clone(),
                            mount_index: *mount_index,
                            target: ResolvedTarget::Dir(handle),
                        }
                        .into(),
                    )
                }),
        }
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        let ComposerResolvedFile {
            mount_index,
            target,
        } = file.into_typed::<Self>();
        let ResolvedTarget::File(handle) = target else {
            unreachable!()
        };
        let handle = self.mounts[mount_index].backend.open_file(handle, flags)?;
        Ok(FileHandle::from_typed::<Self>(ComposerFileHandle {
            mount_index,
            handle,
        }))
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

    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        match h {
            HandleRef::File(h) => {
                let h = h.get_typed::<Self>();
                self.mounts[h.mount_index]
                    .backend
                    .status(HandleRef::File(&h.handle))
            }
            HandleRef::Dir(h) => match &h.get_typed::<Self>().inner {
                ComposerDirHandleInner::Virtual { path } => Ok(self.virtual_dir_status(path)),
                ComposerDirHandleInner::Mounted {
                    mount_index,
                    handle,
                    ..
                } => self.mounts[*mount_index]
                    .backend
                    .status(HandleRef::Dir(handle)),
            },
        }
    }

    fn resolved_status(&self, target: &ResolvedTarget<'_>) -> Result<FileStatus, FileStatusError> {
        match target {
            ResolvedTarget::File(h) => {
                let h = h.get_typed::<Self>();
                self.mounts[h.mount_index]
                    .backend
                    .resolved_status(&h.target)
            }
            ResolvedTarget::Dir(h) => match &h.get_typed::<Self>().inner {
                ComposerWalkingDirHandleInner::Virtual { path } => {
                    Ok(self.virtual_dir_status(path))
                }
                ComposerWalkingDirHandleInner::Mounted {
                    mount_index,
                    target,
                    ..
                } => self.mounts[*mount_index].backend.resolved_status(target),
            },
        }
    }

    fn create_file_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        let dir = dir.into_typed::<Self>();
        match dir.inner {
            ComposerWalkingDirHandleInner::Virtual { .. } => Err(OpenError::ReadOnlyFileSystem),
            ComposerWalkingDirHandleInner::Mounted {
                path,
                mount_index,
                target,
            } => {
                let ResolvedTarget::Dir(handle) = target else {
                    unreachable!()
                };
                self.checked_child_path(path, name, OpenError::ReadOnlyFileSystem)?;
                self.mounts[mount_index]
                    .backend
                    .create_file_at(handle, name, metadata)
                    .map(|handle| {
                        FileHandle::from_typed::<Self>(ComposerFileHandle {
                            mount_index,
                            handle,
                        })
                    })
            }
        }
    }

    fn mkdir_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        let dir = dir.into_typed::<Self>();
        match dir.inner {
            ComposerWalkingDirHandleInner::Virtual { .. } => Err(MkdirError::ReadOnlyFileSystem),
            ComposerWalkingDirHandleInner::Mounted {
                path,
                mount_index,
                target,
            } => {
                let ResolvedTarget::Dir(handle) = target else {
                    unreachable!()
                };
                let path = self.checked_child_path(path, name, MkdirError::ReadOnlyFileSystem)?;
                self.mounts[mount_index]
                    .backend
                    .mkdir_at(handle, name, metadata)
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

    fn unlink_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), UnlinkError> {
        let dir = dir.into_typed::<Self>();
        match dir.inner {
            ComposerWalkingDirHandleInner::Virtual { .. } => Err(UnlinkError::ReadOnlyFileSystem),
            ComposerWalkingDirHandleInner::Mounted {
                path,
                mount_index,
                target,
            } => {
                let ResolvedTarget::Dir(handle) = target else {
                    unreachable!()
                };
                self.checked_child_path(path, name, UnlinkError::ReadOnlyFileSystem)?;
                self.mounts[mount_index].backend.unlink_at(handle, name)
            }
        }
    }

    fn rmdir_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), RmdirError> {
        let dir = dir.into_typed::<Self>();
        match dir.inner {
            ComposerWalkingDirHandleInner::Virtual { .. } => Err(RmdirError::ReadOnlyFileSystem),
            ComposerWalkingDirHandleInner::Mounted {
                path,
                mount_index,
                target,
            } => {
                let ResolvedTarget::Dir(handle) = target else {
                    unreachable!()
                };
                self.checked_child_path(path, name, RmdirError::ReadOnlyFileSystem)?;
                self.mounts[mount_index].backend.rmdir_at(handle, name)
            }
        }
    }

    fn chmod(&self, h: ResolvedTarget<'_>, mode: Mode) -> Result<(), ChmodError> {
        match h {
            ResolvedTarget::File(h) => {
                let h = h.into_typed::<Self>();
                self.mounts[h.mount_index].backend.chmod(h.target, mode)
            }
            ResolvedTarget::Dir(h) => match h.into_typed::<Self>().inner {
                ComposerWalkingDirHandleInner::Virtual { .. } => {
                    Err(ChmodError::ReadOnlyFileSystem)
                }
                ComposerWalkingDirHandleInner::Mounted {
                    mount_index,
                    target,
                    ..
                } => self.mounts[mount_index].backend.chmod(target, mode),
            },
        }
    }

    fn chown(
        &self,
        h: ResolvedTarget<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        match h {
            ResolvedTarget::File(h) => {
                let h = h.into_typed::<Self>();
                self.mounts[h.mount_index]
                    .backend
                    .chown(h.target, user, group)
            }
            ResolvedTarget::Dir(h) => match h.into_typed::<Self>().inner {
                ComposerWalkingDirHandleInner::Virtual { .. } => {
                    Err(ChownError::ReadOnlyFileSystem)
                }
                ComposerWalkingDirHandleInner::Mounted {
                    mount_index,
                    target,
                    ..
                } => self.mounts[mount_index].backend.chown(target, user, group),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::in_mem::{InMem, InitialNode};
    use crate::platform::mock::MockPlatform;

    #[test]
    fn child_mount_before_parent_does_not_truncate_shadowed_file() {
        let file = || InitialNode::File {
            mode: Mode::RWXU,
            owner: UserInfo::ROOT,
            data: b"preserve".as_slice().into(),
        };
        let composer = Composer::builder()
            .mount("/", |_| {
                InMem::<MockPlatform>::new_initialized([
                    (
                        "/a",
                        InitialNode::Directory {
                            mode: Mode::RWXU,
                            owner: UserInfo::ROOT,
                        },
                    ),
                    ("/a/file", file()),
                ])
            })
            .mount("/a/b", InMem::<MockPlatform>::new)
            .mount("/a", |_| {
                InMem::<MockPlatform>::new_initialized([("/file", file())])
            })
            .build()
            .unwrap();

        let Resolution::Found(ResolvedTarget::File(target)) = composer
            .resolve(composer.root().unwrap(), &["a", "file"], &|_| Ok(()))
            .unwrap()
        else {
            panic!("expected mounted file");
        };
        composer
            .open_file(target, OFlags::WRONLY | OFlags::TRUNC)
            .unwrap();

        for (index, components, expected) in [(0, &["a", "file"][..], 8), (2, &["file"][..], 0)] {
            let backend = &composer.mounts[index].backend;
            let Resolution::Found(target) = backend
                .resolve(backend.root().unwrap(), components, &|_| Ok(()))
                .unwrap()
            else {
                panic!("expected existing file");
            };
            assert_eq!(backend.resolved_status(&target).unwrap().size, expected);
        }
    }
}
