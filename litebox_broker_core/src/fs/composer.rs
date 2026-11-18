// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Support for composing [`Backend`]s by mounting them.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::marker::PhantomData;

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform::sync::{RawSyncPrimitivesProvider, RwLock};

use super::backend::{
    Backend, BackendHandles, CreationMetadata, DirHandle, FileHandle, HandleRef, PermissionCheck,
    PermissionInfo, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget, SeekBehavior,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MapSharedError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RenameError, ResolutionError, RmdirError, SymlinkError, TruncateError,
    UnlinkError, WalkError, WriteError,
};
use super::inode_allocator::{InodeAllocator, InodeAllocators};
use super::shared_storage::SharedFile;
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, UserInfo};
use crate::readiness::ReadinessSource;
use thiserror::Error;

/// A [`Backend`] composed from mounted [`Backend`]s at various paths.
pub struct Composer<Platform: RawSyncPrimitivesProvider> {
    state: RwLock<Platform, MountState>,
}

struct MountState {
    // Append-only: borrowed backend handles point into these boxes.
    #[expect(
        clippy::vec_box,
        reason = "published mounts need stable addresses for borrowed handles"
    )]
    mounts: Vec<Box<Mount>>,
    limit: usize,
    allocators: InodeAllocators,
    virtual_dir_allocator: InodeAllocator,
    // TODO(jayb): We have these to account for `/mnt` in something like mounting `/mnt/foo`; I am
    // not certain this is the best design (maybe we should have something _explicitly_ make
    // `/mnt`), but for now, this is the design I've chosen.
    virtual_dirs: Vec<VirtualDir>,
}

/// A [`Composer`] builder.
// XXX(jayb): Possibly replaceable by `Composer::new(root)` + runtime `mount`, once that supports
// nestable/fallible constructors and startup mounts don't count against the runtime cap.
pub struct ComposerBuilder<Platform: RawSyncPrimitivesProvider> {
    mounts: Vec<(String, Box<dyn Backend>)>,
    allocators: InodeAllocators,
    _sync: PhantomData<fn() -> Platform>,
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

/// Runtime mount errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum MountError {
    #[error("mount paths must be absolute normalized paths")]
    InvalidMountPath,
    #[error("a backend is already mounted at this path")]
    Busy,
    #[error("runtime mount capacity is exhausted")]
    NoSpace,
}

// XXX(jayb): Arbitrary cap; Linux allows ~100k. Revisit once unmount exists.
const RUNTIME_MOUNT_CAPACITY: usize = 16;

fn parse_mount_path(raw: &str) -> Result<Vec<String>, MountError> {
    if !raw.starts_with('/') || raw.contains('\0') {
        return Err(MountError::InvalidMountPath);
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
        || raw != format!("/{}", path.join("/"))
    {
        return Err(MountError::InvalidMountPath);
    }
    Ok(path)
}

impl<Platform: RawSyncPrimitivesProvider> Composer<Platform> {
    /// Append a mounted backend without invalidating existing handles.
    ///
    /// Missing ancestor directories are synthesized; callers that require an existing target
    /// directory must validate it before calling this method.
    ///
    /// # Deadlocks
    ///
    /// `make` runs while the namespace state is exclusively locked; it must not access this
    /// `Composer`.
    pub fn mount<B: Backend>(
        &self,
        path: &str,
        make: impl FnOnce(InodeAllocator) -> B,
    ) -> Result<(), MountError> {
        let path = parse_mount_path(path)?;
        let mut state = self.state.write();
        // XXX(jayb): No mount stacking or unmount; Linux would stack here instead of EBUSY.
        if MountRelation::of(state.mounts.iter().map(Box::as_ref), &path) == MountRelation::Exact {
            return Err(MountError::Busy);
        }
        if state.mounts.len() >= state.limit {
            return Err(MountError::NoSpace);
        }
        let backend = Box::new(make(state.allocators.next()));
        let MountState {
            mounts,
            virtual_dirs,
            virtual_dir_allocator,
            ..
        } = &mut *state;
        for len in 0..path.len() {
            let ancestor = &path[..len];
            if virtual_dirs.iter().any(|dir| dir.path == ancestor) {
                continue;
            }
            virtual_dirs.push(VirtualDir {
                path: ancestor.to_vec(),
                node_info: virtual_dir_allocator.next(),
            });
        }
        // Publish fallback metadata first: a host ancestor can disappear after validation.
        // XXX(jayb): Mounts are keyed by path, not dentry; renaming an ancestor doesn't move the
        // mount as on Linux.
        mounts.push(Box::new(Mount { path, backend }));
        Ok(())
    }

    /// Start building an empty composer.
    #[must_use]
    pub fn builder() -> ComposerBuilder<Platform> {
        ComposerBuilder {
            mounts: vec![],
            // XXX(jayb): Each builder numbers devices from 1, so nesting composers (unsupported
            // for now) would collide device IDs unless the outer `InodeAllocators` is threaded in.
            allocators: InodeAllocators::new(),
            _sync: PhantomData,
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider> ComposerBuilder<Platform> {
    /// Add a backend mounted at `path`.
    #[must_use]
    pub fn mount<B: Backend>(self, path: &str, backend: impl FnOnce(InodeAllocator) -> B) -> Self {
        self.try_mount(path, |allocator| Ok::<_, Infallible>(backend(allocator)))
            .unwrap_or_else(|never| match never {})
    }

    /// Add a backend mounted at `path`, propagating errors from its constructor.
    ///
    /// The backend is only mounted when construction succeeds.
    pub fn try_mount<B: Backend, E>(
        self,
        path: &str,
        backend: impl FnOnce(InodeAllocator) -> Result<B, E>,
    ) -> Result<Self, E> {
        self.try_mount_nestable(path, |allocators| backend(allocators.next()))
    }

    /// Add a backend mounted at `path`, which may draw an allocator per backend it is made of.
    #[must_use]
    pub fn mount_nestable<B: Backend>(
        self,
        path: &str,
        backend: impl FnOnce(&InodeAllocators) -> B,
    ) -> Self {
        self.try_mount_nestable(path, |allocators| Ok::<_, Infallible>(backend(allocators)))
            .unwrap_or_else(|never| match never {})
    }

    /// Add a backend mounted at `path` using a fallible constructor which may draw an allocator
    /// per backend it is made of.
    ///
    /// The backend is only mounted when construction succeeds.
    pub fn try_mount_nestable<B: Backend, E>(
        mut self,
        path: &str,
        backend: impl FnOnce(&InodeAllocators) -> Result<B, E>,
    ) -> Result<Self, E> {
        let backend = backend(&self.allocators)?;
        self.mounts.push((path.into(), Box::new(backend)));
        Ok(self)
    }

    /// Validate mount paths and finalize the composer.
    pub fn build(self) -> Result<Composer<Platform>, BuildError> {
        if self.mounts.is_empty() {
            return Err(BuildError::NoMounts);
        }

        let mut mounts = vec![];
        let mut paths = vec![];
        for (raw, backend) in self.mounts {
            let path = parse_mount_path(&raw).map_err(|_| BuildError::InvalidMountPath)?;
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
        let virtual_dir_allocator = self.allocators.next();
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

        let mount_limit = mounts.len() + RUNTIME_MOUNT_CAPACITY;
        let mut published = Vec::with_capacity(mount_limit);
        published.extend(mounts.into_iter().map(Box::new));

        // TODO(jayb): Validate mounted backend device IDs once backends expose that cheaply.
        Ok(Composer {
            state: RwLock::new(MountState {
                mounts: published,
                limit: mount_limit,
                allocators: self.allocators,
                virtual_dir_allocator,
                virtual_dirs,
            }),
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
    fn of<'a>(mounts: impl IntoIterator<Item = &'a Mount>, path: &[String]) -> Self {
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

impl<Platform: RawSyncPrimitivesProvider> Composer<Platform> {
    fn mount_at(&self, index: usize) -> Option<&Mount> {
        let mount = core::ptr::from_ref(self.state.read().mounts.get(index)?.as_ref());
        // SAFETY: Writers only push new boxed mounts; published mounts remain immutable.
        // Their boxes keep their addresses stable, and the pointees cannot be freed while
        // `self` is borrowed. The read lock synchronizes publication and is released before
        // calling into a backend.
        Some(unsafe { &*mount })
    }

    fn initialized_mounts(&self) -> impl Iterator<Item = (usize, &Mount)> {
        (0..).map_while(move |index| self.mount_at(index).map(|mount| (index, mount)))
    }

    fn initialized_mount(&self, index: usize) -> &Mount {
        self.mount_at(index)
            .expect("handle refers to an initialized mount")
    }

    fn backend(&self, index: usize) -> &dyn Backend {
        self.initialized_mount(index).backend.as_ref()
    }

    /// Namespace location of a directory inside `mount`, used to find mount crossings below it.
    ///
    /// `recorded` is the location seen when the handle was created. It is only trusted when no
    /// mount is nested below `mount` or when the backend cannot name the directory, since a
    /// rename or a later runtime mount can make it stale.
    fn current_route(
        &self,
        mount: &Mount,
        recorded: Vec<String>,
        dir: &DirHandle,
    ) -> Result<Vec<String>, WalkError> {
        if !self.initialized_mounts().any(|(_, other)| {
            other.path.len() > mount.path.len() && other.path.starts_with(&mount.path)
        }) {
            return Ok(recorded);
        }
        let mut route = mount.path.clone();
        match mount.backend.dir_path(dir) {
            Ok(Some(path)) => route.extend(path),
            Ok(None) => return Ok(recorded),
            // An unlinked directory still supports `..`; an empty component cannot match any
            // mount path.
            Err(WalkError::PathError(PathError::NoSuchFileOrDirectory)) => {
                route.push(String::new());
            }
            Err(error) => return Err(error),
        }
        Ok(route)
    }

    fn mount_relation(&self, path: &[String]) -> MountRelation {
        MountRelation::of(self.initialized_mounts().map(|(_, mount)| mount), path)
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
        for (_, mount) in self.initialized_mounts() {
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
        self.initialized_mounts()
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
                    on_read_only_fs: true,
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
            .state
            .read()
            .virtual_dirs
            .iter()
            .find(|dir| dir.path == path)
            .map(|dir| dir.node_info)
            .expect("virtual directory is precomputed");
        FileStatus {
            file_type: FileType::Directory,
            // rwxr-xr-x for virtual dirs
            mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
            size: super::DEFAULT_DIRECTORY_SIZE,
            owner: UserInfo::ROOT,
            node_info,
            times: None,
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

/// Resolved, unopened file in a composed filesystem namespace.
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

impl<Platform: RawSyncPrimitivesProvider> BackendHandles for Composer<Platform> {
    type ResolvedDir<'a> = ComposerWalkingDirHandle<'a>;
    type ResolvedFile<'a> = ComposerResolvedFile<'a>;
    type FileHandle = ComposerFileHandle;
    type DirHandle = ComposerDirHandle;
}

impl<Platform: RawSyncPrimitivesProvider> Backend for Composer<Platform> {
    fn check_search(&self, dir: &ResolvedDir<'_>) -> Result<(), WalkError> {
        match &dir.get_typed::<Self>().inner {
            ComposerWalkingDirHandleInner::Mounted {
                mount_index,
                target: ResolvedTarget::Dir(dir),
                ..
            } => self.backend(*mount_index).check_search(dir),
            ComposerWalkingDirHandleInner::Virtual { .. } => Ok(()),
            ComposerWalkingDirHandleInner::Mounted { .. } => {
                Err(PathError::ComponentNotADirectory.into())
            }
        }
    }

    fn dir_path(&self, dir: &DirHandle) -> Result<Option<Vec<String>>, WalkError> {
        match &dir.get_typed::<Self>().inner {
            ComposerDirHandleInner::Virtual { path } => Ok(Some(path.clone())),
            ComposerDirHandleInner::Mounted {
                mount_index,
                handle,
                ..
            } => {
                let mount = self.initialized_mount(*mount_index);
                let Some(suffix) = mount.backend.dir_path(handle)? else {
                    return Ok(None);
                };
                let mut path = mount.path.clone();
                path.extend(suffix);
                // An external rename can move the backing directory under a nested mount.
                if self.initialized_mounts().any(|(_, other)| {
                    other.path.len() > mount.path.len() && path.starts_with(&other.path)
                }) {
                    return Err(PathError::NoSuchFileOrDirectory.into());
                }
                Ok(Some(path))
            }
        }
    }

    fn parent_dir(&self, dir: &DirHandle) -> Result<Option<DirHandle>, WalkError> {
        let mount_path = match &dir.get_typed::<Self>().inner {
            ComposerDirHandleInner::Virtual { path } => path,
            ComposerDirHandleInner::Mounted {
                path,
                mount_index,
                handle,
            } => {
                let mount = self.initialized_mount(*mount_index);
                if let Some(parent) = mount.backend.parent_dir(handle)? {
                    let mut recorded = path.clone();
                    if recorded.len() > mount.path.len() {
                        recorded.pop();
                    }
                    let route = self.current_route(mount, recorded, &parent)?;
                    return Ok(Some(DirHandle::from_typed::<Self>(ComposerDirHandle {
                        inner: ComposerDirHandleInner::Mounted {
                            path: route,
                            mount_index: *mount_index,
                            handle: parent,
                        },
                    })));
                }
                &mount.path
            }
        };
        let Some((_, parent)) = mount_path.split_last() else {
            return Ok(None);
        };
        let parts: Vec<_> = parent.iter().map(String::as_str).collect();
        let Resolution::Found(ResolvedTarget::Dir(parent)) = self
            .resolve(self.root()?, &parts, &|_| Ok(()))
            .map_err(|e| e.error)?
        else {
            return Err(PathError::NoSuchFileOrDirectory.into());
        };
        self.open_dir(parent, OFlags::PATH)
            .map(Some)
            .map_err(|_| WalkError::Io)
    }

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
                    let backend = self.backend(mount_index);
                    if relation == MountRelation::Exact {
                        // XXX: an overlay can hide a nested server's search denial at a mount
                        // crossing; precise enforcement needs a backend/9P API change.
                        match &handle.permissions {
                            PermissionCheck::ByResolver(permissions) => {
                                authorize_dir_lookup(permissions).map_err(fail)?;
                                drop(handle);
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
                        // TODO(jayb): Decide whether future backends need absolute-ish namespace
                        // views instead of this mount-root-relative suffix view. The resolver handles
                        // `..`, including across mount roots, before walking.
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
                        Resolution::Found(ResolvedTarget::File(file))
                            if relation == MountRelation::AncestorOfMount
                                && file.file_type != FileType::SymbolicLink =>
                        {
                            // TODO(jayb): files shadowed by a deeper mount return indexed ENOENT
                            // (never MissingFinal) so open/create can't touch them; symlinks still
                            // pass through.
                            return Err(fail(PathError::NoSuchFileOrDirectory.into()));
                        }
                        Resolution::Found(ResolvedTarget::File(handle)) => {
                            if end != components.len() {
                                return Err(ResolutionError {
                                    component: Some(end),
                                    error: PathError::ComponentNotADirectory.into(),
                                });
                            }
                            let permissions = handle.permissions.clone();
                            let file_type = handle.file_type;
                            return Ok(Resolution::Found(ResolvedTarget::File(
                                ResolvedFile::from_typed::<Self>(
                                    ComposerResolvedFile {
                                        mount_index,
                                        target: ResolvedTarget::File(handle),
                                    },
                                    permissions,
                                    file_type,
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
                    handle: self.backend(mount_index).open_dir(handle, flags)?,
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
            } => {
                let mount = self.initialized_mount(*mount_index);
                let path = self.current_route(mount, path.clone(), handle).ok()?;
                mount.backend.walking_dir_at(handle).map(|handle| {
                    self.resolved_dir(
                        ComposerWalkingDirHandleInner::Mounted {
                            path,
                            mount_index: *mount_index,
                            target: ResolvedTarget::Dir(handle),
                        }
                        .into(),
                    )
                })
            }
        }
    }

    fn read_link_at(&self, dir: &ResolvedDir<'_>, name: &str) -> Result<String, WalkError> {
        match &dir.get_typed::<Self>().inner {
            ComposerWalkingDirHandleInner::Virtual { .. } => {
                Err(PathError::NoSuchFileOrDirectory.into())
            }
            ComposerWalkingDirHandleInner::Mounted {
                mount_index,
                target,
                ..
            } => {
                let ResolvedTarget::Dir(handle) = target else {
                    unreachable!()
                };
                self.backend(*mount_index).read_link_at(handle, name)
            }
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
        let handle = self.backend(mount_index).open_file(handle, flags)?;
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
                let mount = self.initialized_mount(mount_index);
                let path = self
                    .current_route(mount, path, &handle)
                    .map_err(|_| ReadDirError::Io)?;
                let entries = mount.backend.list_dir_at(handle)?;
                Ok(self.merge_mount_children(entries, &path))
            }
        }
    }

    fn read(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
    ) -> Result<usize, ReadError> {
        let h = h.get_typed::<Self>();
        self.backend(h.mount_index).read(&h.handle, buf, offset)
    }

    fn get_static_backing_data(&self, h: &FileHandle) -> Option<&'static [u8]> {
        let h = h.get_typed::<Self>();
        self.backend(h.mount_index)
            .get_static_backing_data(&h.handle)
    }

    fn map_shared(&self, h: &FileHandle) -> Result<Arc<SharedFile>, MapSharedError> {
        let h = h.get_typed::<Self>();
        self.backend(h.mount_index).map_shared(&h.handle)
    }

    fn write(
        &self,
        h: &FileHandle,
        buf: &dyn WriteBuffer,
        offset: usize,
    ) -> Result<usize, WriteError> {
        let h = h.get_typed::<Self>();
        self.backend(h.mount_index).write(&h.handle, buf, offset)
    }

    fn truncate(&self, h: &FileHandle, length: usize) -> Result<(), TruncateError> {
        let h = h.get_typed::<Self>();
        self.backend(h.mount_index).truncate(&h.handle, length)
    }

    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior {
        let h = h.get_typed::<Self>();
        self.backend(h.mount_index).seek_behavior(&h.handle)
    }

    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        match h {
            HandleRef::File(h) => {
                let h = h.get_typed::<Self>();
                self.backend(h.mount_index)
                    .status(HandleRef::File(&h.handle))
            }
            HandleRef::Dir(h) => match &h.get_typed::<Self>().inner {
                ComposerDirHandleInner::Virtual { path } => Ok(self.virtual_dir_status(path)),
                ComposerDirHandleInner::Mounted {
                    mount_index,
                    handle,
                    ..
                } => self.backend(*mount_index).status(HandleRef::Dir(handle)),
            },
        }
    }

    fn terminal(&self, h: &FileHandle) -> Option<super::backend::FileTerminal> {
        let h = h.get_typed::<Self>();
        self.backend(h.mount_index).terminal(&h.handle)
    }

    fn readiness_source(&self, h: &FileHandle) -> Option<Arc<dyn ReadinessSource>> {
        let h = h.get_typed::<Self>();
        self.backend(h.mount_index).readiness_source(&h.handle)
    }

    fn resolved_status(&self, target: &ResolvedTarget<'_>) -> Result<FileStatus, FileStatusError> {
        match target {
            ResolvedTarget::File(h) => {
                let h = h.get_typed::<Self>();
                self.backend(h.mount_index).resolved_status(&h.target)
            }
            ResolvedTarget::Dir(h) => match &h.get_typed::<Self>().inner {
                ComposerWalkingDirHandleInner::Virtual { path } => {
                    Ok(self.virtual_dir_status(path))
                }
                ComposerWalkingDirHandleInner::Mounted {
                    mount_index,
                    target,
                    ..
                } => self.backend(*mount_index).resolved_status(target),
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
                self.backend(mount_index)
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

    fn symlink_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        target: &str,
        metadata: CreationMetadata,
    ) -> Result<(), SymlinkError> {
        let dir = dir.into_typed::<Self>();
        match dir.inner {
            ComposerWalkingDirHandleInner::Virtual { .. } => Err(SymlinkError::ReadOnlyFileSystem),
            ComposerWalkingDirHandleInner::Mounted {
                path,
                mount_index,
                target: parent,
            } => {
                let ResolvedTarget::Dir(handle) = parent else {
                    unreachable!()
                };
                self.checked_child_path(path, name, SymlinkError::ReadOnlyFileSystem)?;
                self.backend(mount_index)
                    .symlink_at(handle, name, target, metadata)
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
                self.backend(mount_index)
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
                self.backend(mount_index).unlink_at(handle, name)
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
                self.backend(mount_index).rmdir_at(handle, name)
            }
        }
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
        let old_dir = old_dir.into_typed::<Self>().inner;
        let new_dir = new_dir.into_typed::<Self>().inner;
        for (dir, name) in [(&old_dir, old_name), (&new_dir, new_name)] {
            let path = match dir {
                ComposerDirHandleInner::Virtual { path }
                | ComposerDirHandleInner::Mounted { path, .. } => path,
            };
            self.checked_child_path(path.clone(), name, RenameError::Busy)?;
        }
        match (old_dir, new_dir) {
            (
                ComposerDirHandleInner::Mounted {
                    mount_index: old_mount,
                    handle: old_handle,
                    ..
                },
                ComposerDirHandleInner::Mounted {
                    mount_index: new_mount,
                    handle: new_handle,
                    ..
                },
            ) if old_mount == new_mount => self
                .backend(old_mount)
                .rename_at(old_handle, old_name, new_handle, new_name),
            (ComposerDirHandleInner::Virtual { .. }, ComposerDirHandleInner::Virtual { .. }) => {
                Err(RenameError::ReadOnlyFileSystem)
            }
            // Different mounts are EXDEV even if they share a backend device.
            _ => Err(RenameError::CrossDevice),
        }
    }

    fn set_times(
        &self,
        target: ResolvedTarget<'_>,
        times: &super::SetFileTimes,
    ) -> Result<(), super::errors::SetTimesError> {
        match target {
            ResolvedTarget::File(h) => {
                let h = h.into_typed::<Self>();
                self.backend(h.mount_index).set_times(h.target, times)
            }
            ResolvedTarget::Dir(h) => match h.into_typed::<Self>().inner {
                ComposerWalkingDirHandleInner::Virtual { .. } => {
                    Err(super::errors::SetTimesError::ReadOnlyFileSystem)
                }
                ComposerWalkingDirHandleInner::Mounted {
                    mount_index,
                    target,
                    ..
                } => self.backend(mount_index).set_times(target, times),
            },
        }
    }

    fn chmod(&self, h: ResolvedTarget<'_>, mode: Mode) -> Result<(), ChmodError> {
        match h {
            ResolvedTarget::File(h) => {
                let h = h.into_typed::<Self>();
                self.backend(h.mount_index).chmod(h.target, mode)
            }
            ResolvedTarget::Dir(h) => match h.into_typed::<Self>().inner {
                ComposerWalkingDirHandleInner::Virtual { .. } => {
                    Err(ChmodError::ReadOnlyFileSystem)
                }
                ComposerWalkingDirHandleInner::Mounted {
                    mount_index,
                    target,
                    ..
                } => self.backend(mount_index).chmod(target, mode),
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
                self.backend(h.mount_index).chown(h.target, user, group)
            }
            ResolvedTarget::Dir(h) => match h.into_typed::<Self>().inner {
                ComposerWalkingDirHandleInner::Virtual { .. } => {
                    Err(ChownError::ReadOnlyFileSystem)
                }
                ComposerWalkingDirHandleInner::Mounted {
                    mount_index,
                    target,
                    ..
                } => self.backend(mount_index).chown(target, user, group),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::in_mem::{InMem, InitialNode};
    use crate::test_platform::TestPlatform;

    #[test]
    fn runtime_mount_shadows_files_without_invalidating_handles() {
        let file = |data: &'static [u8]| InitialNode::File {
            mode: Mode::RWXU,
            owner: UserInfo::ROOT,
            data: data.into(),
        };
        let composer = Composer::<TestPlatform>::builder()
            .mount("/", |allocator| {
                InMem::<TestPlatform>::new_initialized(
                    [
                        (
                            "/mnt",
                            InitialNode::Directory {
                                mode: Mode::RWXU,
                                owner: UserInfo::ROOT,
                            },
                        ),
                        ("/mnt/file", file(b"old")),
                    ],
                    allocator,
                )
            })
            .build()
            .unwrap();
        let open_file = || {
            let Resolution::Found(ResolvedTarget::File(file)) = composer
                .resolve(composer.root().unwrap(), &["mnt", "file"], &|_| Ok(()))
                .unwrap()
            else {
                panic!("expected mounted file");
            };
            composer.open_file(file, OFlags::RDONLY).unwrap()
        };
        let old_file = open_file();
        let Resolution::Found(ResolvedTarget::Dir(dir)) = composer
            .resolve(composer.root().unwrap(), &["mnt"], &|_| Ok(()))
            .unwrap()
        else {
            panic!("expected original directory");
        };
        let old_dir = composer.open_dir(dir, OFlags::RDONLY).unwrap();
        let Resolution::Found(ResolvedTarget::File(unopened)) = composer
            .resolve(composer.root().unwrap(), &["mnt", "file"], &|_| Ok(()))
            .unwrap()
        else {
            panic!("expected original file");
        };

        composer
            .mount("/mnt", |allocator| {
                InMem::<TestPlatform>::new_initialized([("/file", file(b"new"))], allocator)
            })
            .unwrap();
        let new_file = open_file();
        let late_open = composer.open_file(unopened, OFlags::RDONLY).unwrap();
        let Resolution::Found(ResolvedTarget::File(from_old_dir)) = composer
            .resolve(
                composer.walking_dir_at(&old_dir).unwrap(),
                &["file"],
                &|_| Ok(()),
            )
            .unwrap()
        else {
            panic!("expected original directory's file");
        };
        let from_old_dir = composer.open_file(from_old_dir, OFlags::RDONLY).unwrap();
        for (handle, expected) in [
            (&old_file, b"old"),
            (&late_open, b"old"),
            (&from_old_dir, b"old"),
            (&new_file, b"new"),
        ] {
            let mut data = [0; 3];
            assert_eq!(composer.read(handle, &mut data, 0).unwrap(), 3);
            assert_eq!(&data, expected);
        }
        assert_ne!(
            composer
                .status(HandleRef::File(&old_file))
                .unwrap()
                .node_info
                .dev,
            composer
                .status(HandleRef::File(&new_file))
                .unwrap()
                .node_info
                .dev,
        );
    }

    #[test]
    fn runtime_mount_rejects_duplicates_and_exhaustion_before_construction() {
        let composer = Composer::<TestPlatform>::builder()
            .mount("/", InMem::<TestPlatform>::new)
            .build()
            .unwrap();
        assert_eq!(
            composer.mount::<InMem<TestPlatform>>("/", |_| panic!("duplicate constructor")),
            Err(MountError::Busy),
        );
        for index in 0..RUNTIME_MOUNT_CAPACITY {
            composer
                .mount(&format!("/runtime/{index}"), InMem::<TestPlatform>::new)
                .unwrap();
        }
        assert_eq!(
            composer
                .mount::<InMem<TestPlatform>>("/runtime/0", |_| panic!("duplicate constructor")),
            Err(MountError::Busy),
        );
        assert_eq!(
            composer.mount::<InMem<TestPlatform>>("/overflow", |_| panic!("exhausted constructor")),
            Err(MountError::NoSpace),
        );
        assert!(matches!(
            composer
                .resolve(composer.root().unwrap(), &["overflow"], &|_| Ok(()))
                .unwrap(),
            Resolution::MissingFinal { .. },
        ));
        assert_eq!(
            composer.initialized_mounts().count(),
            1 + RUNTIME_MOUNT_CAPACITY
        );
    }

    #[test]
    fn builder_and_runtime_mount_paths_share_validation() {
        let composer = Composer::<TestPlatform>::builder()
            .mount("/", InMem::<TestPlatform>::new)
            .build()
            .unwrap();
        for path in ["", "relative", "//a", "/a/", "/a/./b", "/a/../b", "/a\0b"] {
            assert_eq!(
                Composer::<TestPlatform>::builder()
                    .mount(path, InMem::<TestPlatform>::new)
                    .build()
                    .err(),
                Some(BuildError::InvalidMountPath),
            );
            assert_eq!(
                composer.mount::<InMem<TestPlatform>>(path, |_| panic!("invalid constructor")),
                Err(MountError::InvalidMountPath),
            );
        }
    }

    #[test]
    fn runtime_mount_retains_virtual_metadata_when_host_ancestor_disappears() {
        let composer = Composer::<TestPlatform>::builder()
            .mount("/", |allocator| {
                InMem::<TestPlatform>::new_initialized(
                    [(
                        "/host",
                        InitialNode::Directory {
                            mode: Mode::RWXU,
                            owner: UserInfo::ROOT,
                        },
                    )],
                    allocator,
                )
            })
            .build()
            .unwrap();
        composer
            .mount("/host/child", InMem::<TestPlatform>::new)
            .unwrap();
        let host = composer.backend(0);
        host.rmdir_at(host.root().unwrap(), "host").unwrap();

        let virtual_status = || {
            let Resolution::Found(target) = composer
                .resolve(composer.root().unwrap(), &["host"], &|_| Ok(()))
                .unwrap()
            else {
                panic!("expected synthesized ancestor");
            };
            composer.resolved_status(&target).unwrap()
        };
        let status = virtual_status();
        assert_eq!(status.file_type, FileType::Directory);
        composer
            .mount("/host/sibling", InMem::<TestPlatform>::new)
            .unwrap();
        assert_eq!(virtual_status().node_info, status.node_info);
        let Resolution::Found(ResolvedTarget::Dir(dir)) = composer
            .resolve(composer.root().unwrap(), &["host"], &|_| Ok(()))
            .unwrap()
        else {
            panic!("expected synthesized ancestor");
        };
        let entries = composer
            .list_dir_at(composer.open_dir(dir, OFlags::RDONLY).unwrap())
            .unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["child", "sibling"],
        );
        assert!(matches!(
            composer.resolve(composer.root().unwrap(), &["host", "child"], &|_| Ok(())),
            Ok(Resolution::Found(ResolvedTarget::Dir(_))),
        ));
    }

    #[test]
    fn runtime_mounts_publish_while_borrowed_backends_are_in_use() {
        let composer = Composer::<TestPlatform>::builder()
            .mount("/", InMem::<TestPlatform>::new)
            .build()
            .unwrap();
        let original = composer.backend(0);
        let start = std::sync::Barrier::new(RUNTIME_MOUNT_CAPACITY + 1);
        std::thread::scope(|scope| {
            for index in 0..RUNTIME_MOUNT_CAPACITY {
                let composer = &composer;
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    composer
                        .mount(&format!("/runtime/{index}"), InMem::<TestPlatform>::new)
                        .unwrap();
                });
            }
            start.wait();
            for _ in 0..128 {
                original.root().unwrap();
                for (_, mount) in composer.initialized_mounts() {
                    mount.backend.root().unwrap();
                }
            }
        });
        assert_eq!(
            composer.initialized_mounts().count(),
            RUNTIME_MOUNT_CAPACITY + 1
        );
        for index in 0..RUNTIME_MOUNT_CAPACITY {
            assert!(matches!(
                composer.resolve(
                    composer.root().unwrap(),
                    &["runtime", &index.to_string()],
                    &|_| Ok(())
                ),
                Ok(Resolution::Found(ResolvedTarget::Dir(_))),
            ));
        }
    }

    #[test]
    fn concurrent_mounts_of_the_same_path_construct_one_backend() {
        use core::sync::atomic::{AtomicUsize, Ordering};

        let composer = Composer::<TestPlatform>::builder()
            .mount("/", InMem::<TestPlatform>::new)
            .build()
            .unwrap();
        let constructed = AtomicUsize::new(0);
        let start = std::sync::Barrier::new(RUNTIME_MOUNT_CAPACITY);
        let results = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..RUNTIME_MOUNT_CAPACITY)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        composer.mount("/runtime", |allocator| {
                            constructed.fetch_add(1, Ordering::Relaxed);
                            InMem::<TestPlatform>::new(allocator)
                        })
                    })
                })
                .collect();
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(constructed.load(Ordering::Relaxed), 1);
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(
            results
                .into_iter()
                .all(|result| matches!(result, Ok(()) | Err(MountError::Busy)))
        );
    }

    #[test]
    fn child_mount_before_parent_does_not_truncate_shadowed_file() {
        let file = || InitialNode::File {
            mode: Mode::RWXU,
            owner: UserInfo::ROOT,
            data: b"preserve".as_slice().into(),
        };
        let composer = Composer::<TestPlatform>::builder()
            .mount("/", |allocator| {
                InMem::<TestPlatform>::new_initialized(
                    [
                        (
                            "/a",
                            InitialNode::Directory {
                                mode: Mode::RWXU,
                                owner: UserInfo::ROOT,
                            },
                        ),
                        ("/a/file", file()),
                    ],
                    allocator,
                )
            })
            .mount("/a/b", InMem::<TestPlatform>::new)
            .mount("/a", |allocator| {
                InMem::<TestPlatform>::new_initialized([("/file", file())], allocator)
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
            let backend = composer.backend(index);
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
