// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A writable upper backend layered over one or more immutable lower backends.
//!
//! All backends are logically exclusively owned by the overlay while it exists: lower backends must
//! not change, and the upper backend must only be mutated through the overlay. The entire
//! `.litebox-overlay-*` namespace is permanently reserved; an upper backend must be fresh or have
//! been initialized by this overlay format.
//!
//! The immutability described above (i.e., logical exclusivity) is a correctness requirement, not a
//! safety requirement. If a lower is changed (say, externally), operations may observe stale
//! entries or fail, but the overlay treats stale/mismatched objects as ordinary errors. Such
//! changes do not compromise memory safety or the structural integrity of its internal state.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use hashbrown::HashMap;

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform::sync::{Mutex, MutexGuard, RawSyncPrimitivesProvider};

use super::backend::{
    Backend, BackendHandles, CreationMetadata, DirHandle, FileHandle, HandleRef, PermissionCheck,
    PermissionInfo, Resolution, ResolvedDir as ScopedDir, ResolvedFile, ResolvedTarget,
    SeekBehavior,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RenameError, ResolutionError, RmdirError, SymlinkError, TruncateError, UnlinkError,
    WalkError, WriteError,
};
use super::inode_allocator::InodeAllocator;
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, UserInfo};
use crate::readiness::ReadinessSource;

/// The reserved namespace prefix; no overlay-visible name may start with it.
const MARKER_PREFIX: &str = ".litebox-overlay-";
/// Prefix of a per-hidden-name whiteout marker; the suffix is the hidden name itself.
const WHITEOUT_PREFIX: &str = ".litebox-overlay-whiteout-";
/// Name of the per-directory marker that hides all lower entries of that directory.
const OPAQUE_MARKER: &str = ".litebox-overlay-opaque";

/// A layered backend with a writable upper backend and one or more immutable lower backends.
pub struct Overlay<Platform: RawSyncPrimitivesProvider> {
    upper: Box<dyn Backend>,
    // Lower backends are ordered from highest to lowest precedence.
    lowers: Vec<Box<dyn Backend>>,
    alloc: InodeAllocator,
    /// Keeps resolution, authorization, and any subsequent copy-up or mutation atomic.
    namespace: Mutex<Platform, Namespace>,
    state: Mutex<Platform, State>,
}

/// A held namespace lock, marking mutability of the upper backend.
type NamespaceGuard<'a, Platform> = MutexGuard<'a, Platform, Namespace>;
struct Namespace;

struct State {
    /// Overlay-visible identity assigned to each per-layer node.
    ids: HashMap<LayerNode, NodeInfo>,
    /// Files that have been copied up, by overlay identity, and their handle in the upper backend.
    /// A handle opened against a lower backend stays valid, but every operation looks here first.
    copied_up: HashMap<NodeInfo, FileHandle>,
}

/// A node as identified by the layer that owns it; `Lower` carries the lower backend's index.
#[derive(Clone, PartialEq, Eq, Hash)]
enum LayerNode {
    Upper(NodeInfo),
    Lower(usize, NodeInfo),
}

// Holds no nested-layer scopes: re-entering a layer during lazy lookup would deadlock.
pub struct OverlayWalkingDir<'a, Platform: RawSyncPrimitivesProvider> {
    path: Vec<String>,
    resolved: ResolvedDir,
    locked: NamespaceGuard<'a, Platform>,
}

pub struct OverlayResolvedFile<'a, Platform: RawSyncPrimitivesProvider> {
    parent: Vec<String>,
    name: String,
    layer: Option<usize>,
    target: ResolvedTarget<'a>,
    locked: NamespaceGuard<'a, Platform>,
}

#[derive(Clone)]
pub struct OverlayDir {
    // XXX(jayb): directory handles are path-based and go stale on directory rename.
    path: Vec<String>,
}

/// An owned handle to a file opened through the overlay.
#[derive(Clone)]
pub struct OverlayFile {
    /// The layer this file was _opened_ against; a later copy-up can move it, which is what
    /// [`State::copied_up`] records.
    layer: OverlayFileLayer,
}

/// The layer backing an open overlay file.
#[derive(Clone)]
enum OverlayFileLayer {
    Upper(FileHandle),
    Lower {
        layer: usize,
        handle: FileHandle,
        /// The overlay identity of the file, under which a later copy-up records its upper handle.
        node: NodeInfo,
    },
}

/// A logical directory, resolved to the per-layer directories that make it up.
///
/// Its entries are looked up by name on demand (see [`Overlay::entry`]), so resolving a path never
/// reads whole lower directories.
struct ResolvedDir {
    upper: Option<DirHandle>,
    /// Per lower backend, in precedence order, its directory at this path if any.
    lowers: Vec<Option<DirHandle>>,
}

/// An overlay-visible directory entry, plus which layers contribute to it.
struct ResolvedEntry {
    /// The entry as reported by the layer that owns it.
    entry: DirEntry,
    upper: bool,
    /// The highest-precedence lower backend with an entry of this name, if any.
    lower: Option<usize>,
    /// Per lower backend, whether it has a *directory* of this name that merges into this entry.
    lower_directories: Vec<bool>,
}

/// One name's entries in the layers of a directory: its upper entry, and its lower entries (by
/// lower backend, in precedence order) that the upper directory does not hide.
type LayerEntries = (Option<DirEntry>, Vec<(usize, DirEntry)>);

impl<Platform: RawSyncPrimitivesProvider> Overlay<Platform> {
    /// Construct an overlay over a single `lower`, using `allocator` for overlay-visible inodes.
    pub fn new(upper: impl Backend, lower: impl Backend, allocator: InodeAllocator) -> Self {
        Self::with_boxed_lowers(upper, vec![Box::new(lower)], allocator)
    }

    /// Construct an overlay with lower backends ordered from highest to lowest precedence.
    ///
    /// # Panics
    ///
    /// Panics if `lowers` is empty.
    pub fn with_boxed_lowers(
        upper: impl Backend,
        lowers: Vec<Box<dyn Backend>>,
        allocator: InodeAllocator,
    ) -> Self {
        assert!(
            !lowers.is_empty(),
            "an overlay requires at least one lower backend"
        );
        Self {
            upper: Box::new(upper),
            lowers,
            alloc: allocator,
            namespace: Mutex::new(Namespace),
            state: Mutex::new(State {
                ids: HashMap::new(),
                copied_up: HashMap::new(),
            }),
        }
    }

    fn resolve_root(&self) -> Result<ResolvedDir, OpenError> {
        let upper = self
            .upper
            .open_dir(self.upper.root().map_err(walk_to_open_error)?, OFlags::PATH)?;
        let lowers = self
            .lowers
            .iter()
            .map(|lower| {
                lower
                    .open_dir(lower.root().map_err(walk_to_open_error)?, OFlags::PATH)
                    .map(Some)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ResolvedDir {
            upper: Some(upper),
            lowers,
        })
    }

    /// Resolve a child without inspecting the child's entries.
    fn resolve_child_dir(
        &self,
        parent: &ResolvedDir,
        dir_name: &str,
        entry: &ResolvedEntry,
    ) -> Result<ResolvedDir, OpenError> {
        fn walk_into_dir(
            backend: &dyn Backend,
            parent: &DirHandle,
            dir_name: &str,
        ) -> Result<DirHandle, OpenError> {
            let walking = backend.walking_dir_at(parent).ok_or(OpenError::Io)?;
            match backend
                .resolve(walking, &[dir_name], &|_| Ok(()))
                .map_err(|error| walk_to_open_error(error.error))?
            {
                Resolution::Found(ResolvedTarget::Dir(dir)) => backend.open_dir(dir, OFlags::PATH),
                Resolution::Found(ResolvedTarget::File(_)) => {
                    Err(PathError::ComponentNotADirectory.into())
                }
                Resolution::MissingFinal { .. } => Err(PathError::NoSuchFileOrDirectory.into()),
            }
        }

        if entry.entry.file_type != FileType::Directory {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }

        let upper = match (&parent.upper, entry.upper) {
            (Some(parent), true) => Some(walk_into_dir(self.upper.as_ref(), parent, dir_name)?),
            _ => None,
        };

        let mut lowers = Vec::with_capacity(self.lowers.len());
        for ((layer, lower), parent) in self.lowers.iter().enumerate().zip(&parent.lowers) {
            let child = match parent {
                Some(parent) if entry.lower_directories[layer] => {
                    Some(walk_into_dir(lower.as_ref(), parent, dir_name)?)
                }
                _ => None,
            };
            lowers.push(child);
        }
        Ok(ResolvedDir { upper, lowers })
    }

    /// Resolve a logical `path` (relative to the overlay root) to its per-layer directories.
    fn resolve_dir(&self, path: &[String]) -> Result<ResolvedDir, OpenError> {
        let mut current = self.resolve_root()?;
        for name in path {
            let entry = self
                .entry(&current, name)?
                .ok_or(OpenError::PathError(PathError::MissingComponent))?;
            current = self.resolve_child_dir(&current, name, &entry)?;
        }
        Ok(current)
    }

    fn scoped_dir<'a>(
        &'a self,
        path: Vec<String>,
        resolved: ResolvedDir,
        locked: NamespaceGuard<'a, Platform>,
    ) -> Result<ScopedDir<'a>, OpenError> {
        let (_, backend, handle) = self.owning_dir(&resolved).ok_or(OpenError::Io)?;
        let status = backend
            .resolved_status(&ResolvedTarget::Dir(
                backend.walking_dir_at(handle).ok_or(OpenError::Io)?,
            ))
            .map_err(file_status_to_open_error)?;
        Ok(ScopedDir::from_typed::<Self>(
            OverlayWalkingDir {
                path,
                resolved,
                locked,
            },
            PermissionCheck::ByResolver(PermissionInfo {
                mode: status.mode,
                owner: status.owner,
                on_read_only_fs: false,
            }),
        ))
    }

    /// Copy the lower file `lower` up into the upper backend as `name` within `upper_dir`.
    ///
    /// The namespace lock is held for the whole copy, so a partially written (or failed and
    /// unlinked) upper file is never observable.
    // XXX(jayb): holding the namespace lock across a whole-file byte copy blocks every other
    // namespace operation for as long as the copy takes. Ideally, we would avoid this by doing an
    // atomic link/rename, would need to update `Backend` for that.
    fn copy_up_file(
        &self,
        _guard: &NamespaceGuard<'_, Platform>,
        upper_dir: &DirHandle,
        name: &str,
        lower: (usize, &FileHandle),
        status: &FileStatus,
        truncate: bool,
    ) -> Result<FileHandle, OpenError> {
        let (layer, lower) = lower;
        let upper = self.upper.create_file_at(
            self.upper.walking_dir_at(upper_dir).ok_or(OpenError::Io)?,
            name,
            CreationMetadata {
                mode: status.mode,
                owner: status.owner,
            },
        )?;
        let copied = if truncate {
            Ok(())
        } else {
            self.copy_bytes(layer, lower, &upper)
        };

        if let Err(error) = copied {
            // Ancestor directories materialised for this copy-up deliberately stay behind.
            let _rollback_result = self
                .upper
                .walking_dir_at(upper_dir)
                .ok_or(UnlinkError::Io)
                .and_then(|dir| self.upper.unlink_at(dir, name));
            return Err(error);
        }
        // The copied-up file keeps the identity it had in the lower backend, so existing
        // lower-backed handles keep reporting the same inode.
        if let Ok(upper_status) = self.upper.status(HandleRef::File(&upper)) {
            self.bind_copy_up(
                layer,
                status.node_info,
                upper_status.node_info,
                Some(&upper),
            );
        }
        Ok(upper)
    }

    fn copy_bytes(
        &self,
        layer: usize,
        lower: &FileHandle,
        upper: &FileHandle,
    ) -> Result<(), OpenError> {
        let mut offset = 0;
        let mut buf = [0u8; 4096];
        loop {
            let count = self.lowers[layer]
                .read(lower, &mut buf, offset)
                .map_err(|_| OpenError::Io)?;
            if count == 0 {
                return Ok(());
            }
            let mut written = 0;
            while written < count {
                let progress = self
                    .upper
                    .write(upper, &&buf[written..count], offset + written)
                    .map_err(|_| OpenError::Io)?;
                if progress == 0 {
                    return Err(OpenError::Io);
                }
                written += progress;
            }
            offset += count;
        }
    }

    /// Materialise the authorized target and retain the namespace lock through its mutation.
    fn with_upper<R>(
        &self,
        h: ResolvedTarget<'_>,
        f: impl FnOnce(ResolvedTarget<'_>) -> R,
    ) -> Result<R, OpenError> {
        match h {
            ResolvedTarget::Dir(dir) => {
                let OverlayWalkingDir {
                    path,
                    resolved,
                    locked,
                } = dir.into_typed::<Self>();
                let upper = match resolved.upper {
                    Some(upper) => upper,
                    None => self.ensure_upper_dir(&locked, &path)?,
                };
                let target = self.upper.walking_dir_at(&upper).ok_or(OpenError::Io)?;
                Ok(f(ResolvedTarget::Dir(target)))
            }
            ResolvedTarget::File(file) => {
                let OverlayResolvedFile {
                    parent,
                    name,
                    layer,
                    target,
                    locked,
                } = file.into_typed::<Self>();
                let Some(layer) = layer else {
                    return Ok(f(target));
                };
                let status = self.lowers[layer]
                    .resolved_status(&target)
                    .map_err(file_status_to_open_error)?;
                if status.file_type != FileType::RegularFile {
                    return Err(OpenError::ReadOnlyFileSystem);
                }
                let ResolvedTarget::File(file) = target else {
                    unreachable!()
                };
                // Release any nested overlay scope before resolving ancestor directories there.
                let lower = self.lowers[layer].open_file(file, OFlags::RDONLY)?;
                let upper_dir = self.ensure_upper_dir(&locked, &parent)?;
                self.copy_up_file(&locked, &upper_dir, &name, (layer, &lower), &status, false)?;
                let parent = self.upper.walking_dir_at(&upper_dir).ok_or(OpenError::Io)?;
                match self
                    .upper
                    .resolve(parent, &[&name], &|_| Ok(()))
                    .map_err(|error| walk_to_open_error(error.error))?
                {
                    Resolution::Found(target @ ResolvedTarget::File(_)) => Ok(f(target)),
                    _ => Err(OpenError::Io),
                }
            }
        }
    }

    fn marker_present(&self, dir: &DirHandle, marker: &str) -> Result<bool, ReadDirError> {
        Ok(lookup_layer_entry(self.upper.as_ref(), dir, marker)?.is_some())
    }

    /// Create `marker` in the upper directory `dir`, if not already there.
    fn create_marker(
        &self,
        _locked: &NamespaceGuard<'_, Platform>,
        dir: &DirHandle,
        marker: &str,
    ) -> Result<(), OpenError> {
        if self
            .marker_present(dir, marker)
            .map_err(|_| OpenError::Io)?
        {
            return Ok(());
        }
        // Markers are overlay-internal bookkeeping, never visible to callers, so they are owned by
        // root rather than by whoever happened to trigger the write.
        self.upper.create_file_at(
            self.upper.walking_dir_at(dir).ok_or(OpenError::Io)?,
            marker,
            CreationMetadata {
                mode: Mode::empty(),
                owner: UserInfo::ROOT,
            },
        )?;
        Ok(())
    }

    fn remove_marker(
        &self,
        _locked: &NamespaceGuard<'_, Platform>,
        dir: &DirHandle,
        marker: &str,
    ) -> Result<(), UnlinkError> {
        if self
            .marker_present(dir, marker)
            .map_err(|_| UnlinkError::Io)?
        {
            self.upper.unlink_at(
                self.upper.walking_dir_at(dir).ok_or(UnlinkError::Io)?,
                marker,
            )?;
        }
        Ok(())
    }

    /// Remove every overlay marker held directly by the upper directory `dir`, so that a
    /// caller-visibly empty directory is also empty to the upper backend.
    fn clear_markers(
        &self,
        _locked: &NamespaceGuard<'_, Platform>,
        dir: &DirHandle,
    ) -> Result<Vec<String>, UnlinkError> {
        let entries = list_layer_dir(self.upper.as_ref(), dir).map_err(|_| UnlinkError::Io)?;
        let mut removed = Vec::new();
        for entry in entries.iter().filter(|entry| !valid(&entry.name)) {
            self.upper.unlink_at(
                self.upper.walking_dir_at(dir).ok_or(UnlinkError::Io)?,
                &entry.name,
            )?;
            removed.push(entry.name.clone());
        }
        Ok(removed)
    }

    /// Materialise `path` in the upper backend, creating any missing directory along the way.
    ///
    /// Only mutating operations call this: reads never write to the upper backend.
    fn ensure_upper_dir(
        &self,
        locked: &NamespaceGuard<'_, Platform>,
        path: &[String],
    ) -> Result<DirHandle, OpenError> {
        let mut upper = self
            .upper
            .open_dir(self.upper.root().map_err(walk_to_open_error)?, OFlags::PATH)?;
        for index in 0..path.len() {
            // Re-resolve after each materialisation, since it changed the upper namespace.
            let resolved = self.resolve_dir(&path[..=index])?;
            upper = match resolved.upper {
                Some(handle) => handle,
                None => self.materialize_dir(locked, &upper, &resolved, &path[index])?,
            };
        }
        Ok(upper)
    }

    /// Create the upper counterpart of the lower-only directory `resolved`, named `name` in
    /// `parent`.
    fn materialize_dir(
        &self,
        _locked: &NamespaceGuard<'_, Platform>,
        parent: &DirHandle,
        resolved: &ResolvedDir,
        name: &str,
    ) -> Result<DirHandle, OpenError> {
        let (layer, backend, handle) = self.owning_dir(resolved).ok_or(OpenError::Io)?;
        let status = backend
            .status(HandleRef::Dir(handle))
            .map_err(file_status_to_open_error)?;
        let child = self
            .upper
            .mkdir_at(
                self.upper.walking_dir_at(parent).ok_or(OpenError::Io)?,
                name,
                CreationMetadata {
                    mode: status.mode,
                    owner: status.owner,
                },
            )
            .map_err(|error| match error {
                MkdirError::PathError(error) => OpenError::PathError(error),
                MkdirError::AlreadyExists => OpenError::AlreadyExists,
                MkdirError::ReadOnlyFileSystem => OpenError::ReadOnlyFileSystem,
                MkdirError::NoWritePerms => OpenError::NoWritePerms,
                MkdirError::Io => OpenError::Io,
            })?;
        // A materialised directory stands in for the lower one, so it keeps its identity.
        if let (Some(layer), Ok(upper)) = (layer, self.upper.status(HandleRef::Dir(&child))) {
            self.bind_copy_up(layer, status.node_info, upper.node_info, None);
        }
        Ok(child)
    }

    /// The layer that owns a resolved directory, and its handle within that layer: the upper
    /// directory when there is one, the highest-precedence lower directory otherwise.
    fn owning_dir<'a, 'd>(
        &'a self,
        dir: &'d ResolvedDir,
    ) -> Option<(Option<usize>, &'a dyn Backend, &'d DirHandle)> {
        match &dir.upper {
            Some(handle) => Some((None, self.upper.as_ref(), handle)),
            None => dir.lowers.iter().zip(&self.lowers).enumerate().find_map(
                |(layer, (handle, lower))| {
                    handle
                        .as_ref()
                        .map(|handle| (Some(layer), lower.as_ref(), handle))
                },
            ),
        }
    }

    /// Run `f` against the layer that currently backs an open `file`: the one it was opened
    /// against, or the upper backend if it has been copied up since.
    fn with_file<R>(
        &self,
        file: &OverlayFile,
        f: impl FnOnce(Option<usize>, &dyn Backend, &FileHandle) -> R,
    ) -> R {
        if let Some(upper) = self.migrated(file) {
            return f(None, self.upper.as_ref(), &upper);
        }
        match &file.layer {
            OverlayFileLayer::Upper(handle) => f(None, self.upper.as_ref(), handle),
            OverlayFileLayer::Lower { layer, handle, .. } => {
                f(Some(*layer), self.lowers[*layer].as_ref(), handle)
            }
        }
    }

    /// The overlay-visible identity of `node` as owned by `layer`, allocated on first sight.
    fn map_node(
        &self,
        ids: &mut HashMap<LayerNode, NodeInfo>,
        layer: Option<usize>,
        node: NodeInfo,
    ) -> NodeInfo {
        let rdev = node.rdev;
        *ids.entry(layer_node(layer, node))
            .or_insert_with(|| NodeInfo {
                rdev,
                ..self.alloc.next()
            })
    }

    /// `status` as reported by `layer`, with its node identity replaced by the overlay's own.
    fn map_status(&self, mut status: FileStatus, layer: Option<usize>) -> FileStatus {
        status.node_info = self.map_node(&mut self.state.lock().ids, layer, status.node_info);
        status
    }

    /// Give the freshly created `upper` node the overlay identity of the `lower` node it copies,
    /// which is what makes copy-up invisible: the object keeps its inode.
    ///
    /// `upper_file` is the new upper handle, which lets lower-backed handles follow the contents;
    /// directories are addressed by path, so they have nothing to follow.
    fn bind_copy_up(
        &self,
        layer: usize,
        lower: NodeInfo,
        upper: NodeInfo,
        upper_file: Option<&FileHandle>,
    ) {
        let mut state = self.state.lock();
        let id = self.map_node(&mut state.ids, Some(layer), lower);
        state.ids.insert(layer_node(None, upper), id);
        if let Some(file) = upper_file {
            state.copied_up.insert(id, file.clone());
        }
    }

    /// The upper handle for `file`, if it has been copied up since it was opened.
    fn migrated(&self, file: &OverlayFile) -> Option<FileHandle> {
        let OverlayFileLayer::Lower { node, .. } = &file.layer else {
            return None;
        };
        self.state.lock().copied_up.get(node).cloned()
    }

    /// The overlay-visible entry `name` of `dir`, if any, merged across the layers that hold it.
    fn entry(&self, dir: &ResolvedDir, name: &str) -> Result<Option<ResolvedEntry>, OpenError> {
        if !valid(name) {
            return Ok(None);
        }

        let mut upper = None;
        let mut lowers = Vec::new();
        if let Some(handle) = &dir.upper {
            // Read the upper entry and the markers hiding its lower counterparts together.
            let whiteout = whiteout(name);
            let mut hidden = false;
            for entry in list_layer_dir(self.upper.as_ref(), handle).map_err(|_| OpenError::Io)? {
                if entry.name == name {
                    upper = Some(entry);
                } else if entry.name == whiteout || entry.name == OPAQUE_MARKER {
                    // Markers held by the upper directory say what it hides from the lowers.
                    hidden = true;
                }
            }
            if hidden {
                return Ok(self.merge_entry(upper, lowers));
            }
        }
        // Lower backends are immutable, so they can be looked up by name.
        for (layer, (backend, handle)) in self.lowers.iter().zip(&dir.lowers).enumerate() {
            if let Some(handle) = handle
                && let Some(entry) =
                    lookup_layer_entry(backend.as_ref(), handle, name).map_err(|_| OpenError::Io)?
            {
                lowers.push((layer, entry));
            }
        }
        Ok(self.merge_entry(upper, lowers))
    }

    /// Every overlay-visible entry of `dir`, sorted by name.
    fn entries(&self, dir: &ResolvedDir) -> Result<Vec<DirEntry>, OpenError> {
        fn list(backend: &dyn Backend, dir: &DirHandle) -> Result<Vec<DirEntry>, OpenError> {
            list_layer_dir(backend, dir).map_err(|_| OpenError::Io)
        }

        let mut names: BTreeMap<String, LayerEntries> = BTreeMap::new();
        // Markers held by the upper directory say what it hides from the lowers.
        let mut markers = BTreeSet::new();
        if let Some(handle) = &dir.upper {
            for entry in list(self.upper.as_ref(), handle)? {
                if valid(&entry.name) {
                    let name = entry.name.clone();
                    names.entry(name).or_default().0 = Some(entry);
                } else {
                    markers.insert(entry.name);
                }
            }
        }
        if !markers.contains(OPAQUE_MARKER) {
            for (layer, (backend, handle)) in self.lowers.iter().zip(&dir.lowers).enumerate() {
                let Some(handle) = handle else {
                    continue;
                };
                for entry in list(backend.as_ref(), handle)? {
                    if valid(&entry.name) && !markers.contains(&whiteout(&entry.name)) {
                        names
                            .entry(entry.name.clone())
                            .or_default()
                            .1
                            .push((layer, entry));
                    }
                }
            }
        }
        Ok(names
            .into_values()
            .filter_map(|(upper, lowers)| self.merge_entry(upper, lowers))
            .map(|merged| merged.entry)
            .collect())
    }

    /// Merge the entries of one name in one logical directory: `upper` from its upper directory,
    /// and `lowers` (in precedence order) from the lower directories it does not hide.
    fn merge_entry(
        &self,
        upper: Option<DirEntry>,
        lowers: Vec<(usize, DirEntry)>,
    ) -> Option<ResolvedEntry> {
        let mut merged: Option<ResolvedEntry> = None;
        // Whether lower entries can no longer be merged in: the entry is not a directory in every
        // layer that contributed to it.
        let mut blocked = false;
        if let Some(mut entry) = upper {
            blocked = entry.file_type != FileType::Directory;
            entry.ino_info = entry
                .ino_info
                .take()
                .map(|node| self.map_node(&mut self.state.lock().ids, None, node));
            merged = Some(ResolvedEntry {
                entry,
                upper: true,
                lower: None,
                lower_directories: vec![false; self.lowers.len()],
            });
        }

        for (layer, mut lower_entry) in lowers {
            let directory = lower_entry.file_type == FileType::Directory;
            let lower_node = lower_entry.ino_info.take();
            let entry = merged.get_or_insert_with(|| ResolvedEntry {
                entry: lower_entry,
                upper: false,
                lower: Some(layer),
                lower_directories: vec![false; self.lowers.len()],
            });
            entry.lower.get_or_insert(layer);
            if !entry.upper && entry.lower == Some(layer) {
                // This layer owns the entry, so its node is the one callers see.
                entry.entry.ino_info = lower_node
                    .map(|node| self.map_node(&mut self.state.lock().ids, Some(layer), node));
            }
            if blocked {
                continue;
            }
            if directory {
                entry.lower_directories[layer] = true;
                // Several layers describe one logical directory; the one already resolved above
                // owns the identity, and this layer's node adopts it.
                if let (Some(node), Some(id)) = (lower_node, entry.entry.ino_info) {
                    self.state
                        .lock()
                        .ids
                        .entry(layer_node(Some(layer), node))
                        .or_insert(id);
                }
            } else {
                blocked = true;
            }
        }
        merged
    }
}

/// The node `node` as owned by `layer`, which is `None` for the upper backend and `Some(index)`
/// for a lower one.
fn layer_node(layer: Option<usize>, node: NodeInfo) -> LayerNode {
    match layer {
        None => LayerNode::Upper(node),
        Some(layer) => LayerNode::Lower(layer, node),
    }
}

/// Whether `name` may be visible through the overlay.
fn valid(name: &str) -> bool {
    !name.starts_with(MARKER_PREFIX)
}

/// The whiteout marker name that hides `name` in a directory.
fn whiteout(name: &str) -> String {
    let mut out = String::from(WHITEOUT_PREFIX);
    out.push_str(name);
    out
}

fn lookup_layer_entry(
    backend: &dyn Backend,
    dir: &DirHandle,
    name: &str,
) -> Result<Option<DirEntry>, ReadDirError> {
    // The default lookup scans a directory, so it needs the same private read-open as readdir.
    let dir = backend.walking_dir_at(dir).ok_or(ReadDirError::Io)?;
    let dir = backend
        .open_dir(dir, OFlags::RDONLY)
        .map_err(|_| ReadDirError::Io)?;
    backend.lookup_at(&dir, name)
}

fn list_layer_dir(backend: &dyn Backend, dir: &DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
    // Traversal retains O_PATH handles. A server may require a private, read-opened fid for
    // readdir; never open the retained handle itself or bypass the server's checks.
    let dir = backend.walking_dir_at(dir).ok_or(ReadDirError::Io)?;
    let dir = backend
        .open_dir(dir, OFlags::RDONLY)
        .map_err(|_| ReadDirError::Io)?;
    backend.list_dir_at(dir)
}

fn unlink_to_open_error(error: UnlinkError) -> OpenError {
    match error {
        UnlinkError::PathError(error) => OpenError::PathError(error),
        UnlinkError::ReadOnlyFileSystem => OpenError::ReadOnlyFileSystem,
        UnlinkError::NoWritePerms => OpenError::NoWritePerms,
        _ => OpenError::Io,
    }
}

fn walk_to_open_error(error: WalkError) -> OpenError {
    match error {
        WalkError::PathError(error) => OpenError::PathError(error),
        WalkError::Io => OpenError::Io,
    }
}

fn open_to_walk_error(error: OpenError) -> WalkError {
    match error {
        OpenError::PathError(error) => WalkError::PathError(error),
        _ => WalkError::Io,
    }
}

fn file_status_to_open_error(error: FileStatusError) -> OpenError {
    match error {
        FileStatusError::PathError(error) => OpenError::PathError(error),
        _ => OpenError::Io,
    }
}

impl<Platform: RawSyncPrimitivesProvider> BackendHandles for Overlay<Platform> {
    type ResolvedDir<'a> = OverlayWalkingDir<'a, Platform>;
    type ResolvedFile<'a> = OverlayResolvedFile<'a, Platform>;
    type FileHandle = OverlayFile;
    type DirHandle = OverlayDir;
}

impl<Platform: RawSyncPrimitivesProvider> Backend for Overlay<Platform> {
    fn root(&self) -> Result<ScopedDir<'_>, WalkError> {
        let locked = self.namespace.lock();
        let resolved = self.resolve_root().map_err(open_to_walk_error)?;
        self.scoped_dir(Vec::new(), resolved, locked)
            .map_err(open_to_walk_error)
    }

    fn resolve<'a>(
        &'a self,
        from: ScopedDir<'a>,
        components: &[&str],
        authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        let mut current = from;
        for (index, name) in components.iter().enumerate() {
            let fail = |error| ResolutionError {
                component: Some(index),
                error,
            };
            let PermissionCheck::ByResolver(permissions) = &current.permissions else {
                unreachable!()
            };
            authorize_dir_lookup(permissions).map_err(fail)?;
            if !valid(name) {
                return Err(fail(PathError::InvalidPathname.into()));
            }
            let OverlayWalkingDir {
                mut path,
                resolved,
                locked,
            } = current.into_typed::<Self>();
            let Some(entry) = self
                .entry(&resolved, name)
                .map_err(open_to_walk_error)
                .map_err(fail)?
            else {
                if index + 1 == components.len() {
                    let parent = self
                        .scoped_dir(path, resolved, locked)
                        .map_err(open_to_walk_error)
                        .map_err(fail)?;
                    return Ok(Resolution::MissingFinal { parent });
                }
                return Err(fail(PathError::NoSuchFileOrDirectory.into()));
            };
            if entry.entry.file_type == FileType::Directory {
                let child = self
                    .resolve_child_dir(&resolved, name, &entry)
                    .map_err(open_to_walk_error)
                    .map_err(fail)?;
                path.push(String::from(*name));
                current = self
                    .scoped_dir(path, child, locked)
                    .map_err(open_to_walk_error)
                    .map_err(fail)?;
                continue;
            }
            if index + 1 != components.len() {
                return Err(ResolutionError {
                    component: Some(index + 1),
                    error: PathError::ComponentNotADirectory.into(),
                });
            }
            let file_type = entry.entry.file_type;
            let (layer, backend, parent) = if entry.upper {
                (None, self.upper.as_ref(), resolved.upper.as_ref())
            } else {
                let layer = entry.lower.ok_or_else(|| fail(WalkError::Io))?;
                (
                    Some(layer),
                    self.lowers[layer].as_ref(),
                    resolved.lowers[layer].as_ref(),
                )
            };
            let parent = parent
                .and_then(|dir| backend.walking_dir_at(dir))
                .ok_or_else(|| fail(WalkError::Io))?;
            let Resolution::Found(target @ ResolvedTarget::File(_)) = backend
                .resolve(parent, &[name], &|_| Ok(()))
                .map_err(|mut error| {
                    error.component = error.component.map(|component| component + index);
                    error
                })?
            else {
                return Err(fail(WalkError::Io));
            };
            let status = backend
                .resolved_status(&target)
                .map_err(file_status_to_open_error)
                .map_err(open_to_walk_error)
                .map_err(fail)?;
            let permissions = PermissionCheck::ByResolver(PermissionInfo {
                mode: status.mode,
                owner: status.owner,
                on_read_only_fs: false,
            });
            return Ok(Resolution::Found(ResolvedTarget::File(
                ResolvedFile::from_typed::<Self>(
                    OverlayResolvedFile {
                        parent: path,
                        name: String::from(*name),
                        layer,
                        target,
                        locked,
                    },
                    permissions,
                    file_type,
                ),
            )));
        }
        Ok(Resolution::Found(ResolvedTarget::Dir(current)))
    }

    fn read_link_at(&self, dir: &ScopedDir<'_>, name: &str) -> Result<String, WalkError> {
        let OverlayWalkingDir { resolved, .. } = dir.get_typed::<Self>();
        let entry = self
            .entry(resolved, name)
            .map_err(open_to_walk_error)?
            .ok_or(PathError::NoSuchFileOrDirectory)?;
        let layer = if entry.upper {
            None
        } else {
            Some(entry.lower.ok_or(WalkError::Io)?)
        };
        let backend = layer.map_or(self.upper.as_ref(), |layer| self.lowers[layer].as_ref());
        let parent = match layer {
            None => resolved.upper.as_ref(),
            Some(layer) => resolved.lowers[layer].as_ref(),
        };
        let parent = parent
            .and_then(|dir| backend.walking_dir_at(dir))
            .ok_or(WalkError::Io)?;
        backend.read_link_at(&parent, name)
    }

    fn open_dir(&self, dir: ScopedDir<'_>, flags: OFlags) -> Result<DirHandle, OpenError> {
        let OverlayWalkingDir {
            path,
            resolved,
            locked: _locked,
        } = dir.into_typed::<Self>();
        let (_, backend, handle) = self.owning_dir(&resolved).ok_or(OpenError::Io)?;
        backend.open_dir(backend.walking_dir_at(handle).ok_or(OpenError::Io)?, flags)?;
        Ok(DirHandle::from_typed::<Self>(OverlayDir { path }))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<ScopedDir<'a>> {
        let locked = self.namespace.lock();
        let path = dir.get_typed::<Self>().path.clone();
        let resolved = self.resolve_dir(&path).ok()?;
        self.scoped_dir(path, resolved, locked).ok()
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        if flags.contains(OFlags::DIRECTORY) {
            return Err(PathError::ComponentNotADirectory.into());
        }
        let OverlayResolvedFile {
            parent,
            name,
            layer,
            target,
            locked,
        } = file.into_typed::<Self>();
        let layer = if let Some(layer) = layer {
            let status = self.lowers[layer]
                .resolved_status(&target)
                .map_err(file_status_to_open_error)?;
            let ResolvedTarget::File(file) = target else {
                unreachable!()
            };
            let writing = !flags.contains(OFlags::PATH)
                && flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::APPEND | OFlags::TRUNC);
            let lower_flags = if writing {
                OFlags::RDONLY
            } else {
                flags - OFlags::CREAT
            };
            let file = self.lowers[layer].open_file(file, lower_flags)?;
            if writing {
                if status.file_type != FileType::RegularFile {
                    return Err(OpenError::ReadOnlyFileSystem);
                }
                let upper_dir = self.ensure_upper_dir(&locked, &parent)?;
                let upper = self.copy_up_file(
                    &locked,
                    &upper_dir,
                    &name,
                    (layer, &file),
                    &status,
                    flags.contains(OFlags::TRUNC),
                )?;
                OverlayFileLayer::Upper(upper)
            } else {
                let node = self.map_node(&mut self.state.lock().ids, Some(layer), status.node_info);
                OverlayFileLayer::Lower {
                    layer,
                    handle: file,
                    node,
                }
            }
        } else {
            let ResolvedTarget::File(file) = target else {
                unreachable!()
            };
            OverlayFileLayer::Upper(self.upper.open_file(file, flags)?)
        };
        Ok(FileHandle::from_typed::<Self>(OverlayFile { layer }))
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        let path = handle.into_typed::<Self>().path;
        let _locked = self.namespace.lock();
        let resolved = self.resolve_dir(&path).map_err(|_| ReadDirError::Io)?;
        self.entries(&resolved).map_err(|_| ReadDirError::Io)
    }

    fn read(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
    ) -> Result<usize, ReadError> {
        self.with_file(h.get_typed::<Self>(), |_, backend, handle| {
            backend.read(handle, buf, offset)
        })
    }

    fn get_static_backing_data(&self, h: &FileHandle) -> Option<&'static [u8]> {
        self.with_file(h.get_typed::<Self>(), |_, backend, handle| {
            backend.get_static_backing_data(handle)
        })
    }

    fn write(
        &self,
        h: &FileHandle,
        buf: &dyn WriteBuffer,
        offset: usize,
    ) -> Result<usize, WriteError> {
        let file = h.get_typed::<Self>();
        if let Some(upper) = self.migrated(file) {
            return self.upper.write(&upper, buf, offset);
        }
        match &file.layer {
            OverlayFileLayer::Upper(handle) => self.upper.write(handle, buf, offset),
            // A writable open copies up first, so a lower-backed handle is read-only.
            OverlayFileLayer::Lower { .. } => Err(WriteError::NotForWriting),
        }
    }

    fn truncate(&self, h: &FileHandle, length: usize) -> Result<(), TruncateError> {
        let file = h.get_typed::<Self>();
        if let Some(upper) = self.migrated(file) {
            return self.upper.truncate(&upper, length);
        }
        match &file.layer {
            OverlayFileLayer::Upper(handle) => self.upper.truncate(handle, length),
            OverlayFileLayer::Lower { .. } => Err(TruncateError::NotForWriting),
        }
    }

    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior {
        self.with_file(h.get_typed::<Self>(), |_, backend, handle| {
            backend.seek_behavior(handle)
        })
    }

    fn terminal(&self, h: &FileHandle) -> Option<super::backend::FileTerminal> {
        self.with_file(h.get_typed::<Self>(), |_, backend, handle| {
            backend.terminal(handle)
        })
    }

    fn readiness_source(&self, h: &FileHandle) -> Option<Arc<dyn ReadinessSource>> {
        self.with_file(h.get_typed::<Self>(), |_, backend, handle| {
            backend.readiness_source(handle)
        })
    }

    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        match h {
            HandleRef::File(handle) => {
                self.with_file(handle.get_typed::<Self>(), |layer, backend, handle| {
                    let status = backend.status(HandleRef::File(handle))?;
                    Ok(self.map_status(status, layer))
                })
            }
            HandleRef::Dir(handle) => {
                let path = &handle.get_typed::<Self>().path;
                let _locked = self.namespace.lock();
                let resolved = self.resolve_dir(path).map_err(|_| FileStatusError::Io)?;
                let (layer, backend, handle) =
                    self.owning_dir(&resolved).ok_or(FileStatusError::Io)?;
                let status = backend.status(HandleRef::Dir(handle))?;
                Ok(self.map_status(status, layer))
            }
        }
    }

    fn resolved_status(&self, target: &ResolvedTarget<'_>) -> Result<FileStatus, FileStatusError> {
        match target {
            ResolvedTarget::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                let (layer, backend, handle) =
                    self.owning_dir(&dir.resolved).ok_or(FileStatusError::Io)?;
                let status = backend.resolved_status(&ResolvedTarget::Dir(
                    backend.walking_dir_at(handle).ok_or(FileStatusError::Io)?,
                ))?;
                Ok(self.map_status(status, layer))
            }
            ResolvedTarget::File(file) => {
                let file = file.get_typed::<Self>();
                let backend = file
                    .layer
                    .map_or(self.upper.as_ref(), |layer| self.lowers[layer].as_ref());
                Ok(self.map_status(backend.resolved_status(&file.target)?, file.layer))
            }
        }
    }

    fn create_file_at(
        &self,
        dir: ScopedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        if !valid(name) {
            return Err(PathError::InvalidPathname.into());
        }
        let OverlayWalkingDir {
            path,
            resolved,
            locked,
        } = dir.into_typed::<Self>();
        if self.entry(&resolved, name)?.is_some() {
            return Err(OpenError::AlreadyExists);
        }
        let upper = self.ensure_upper_dir(&locked, &path)?;
        let file = self.upper.create_file_at(
            self.upper.walking_dir_at(&upper).ok_or(OpenError::Io)?,
            name,
            metadata,
        )?;
        if let Err(error) = self.remove_marker(&locked, &upper, &whiteout(name)) {
            let _rollback_result = self
                .upper
                .walking_dir_at(&upper)
                .ok_or(UnlinkError::Io)
                .and_then(|dir| self.upper.unlink_at(dir, name));
            return Err(unlink_to_open_error(error));
        }
        Ok(FileHandle::from_typed::<Self>(OverlayFile {
            layer: OverlayFileLayer::Upper(file),
        }))
    }

    fn symlink_at(
        &self,
        dir: ScopedDir<'_>,
        name: &str,
        target: &str,
        metadata: CreationMetadata,
    ) -> Result<(), SymlinkError> {
        fn open_to_symlink_error(error: OpenError) -> SymlinkError {
            match error {
                OpenError::PathError(error) => SymlinkError::PathError(error),
                OpenError::AlreadyExists => SymlinkError::AlreadyExists,
                OpenError::ReadOnlyFileSystem => SymlinkError::ReadOnlyFileSystem,
                OpenError::NoWritePerms => SymlinkError::NoWritePerms,
                _ => SymlinkError::Io,
            }
        }
        if !valid(name) {
            return Err(PathError::InvalidPathname.into());
        }
        let OverlayWalkingDir {
            path,
            resolved,
            locked,
        } = dir.into_typed::<Self>();
        if self
            .entry(&resolved, name)
            .map_err(open_to_symlink_error)?
            .is_some()
        {
            return Err(SymlinkError::AlreadyExists);
        }
        let upper = self
            .ensure_upper_dir(&locked, &path)
            .map_err(open_to_symlink_error)?;
        self.upper.symlink_at(
            self.upper.walking_dir_at(&upper).ok_or(SymlinkError::Io)?,
            name,
            target,
            metadata,
        )?;
        // Like a regular file, a replacement link clears its whiteout but
        // needs no opaque marker: only directories can merge with lower entries.
        if let Err(error) = self.remove_marker(&locked, &upper, &whiteout(name)) {
            let _rollback_result = self
                .upper
                .walking_dir_at(&upper)
                .ok_or(UnlinkError::Io)
                .and_then(|dir| self.upper.unlink_at(dir, name));
            return Err(open_to_symlink_error(unlink_to_open_error(error)));
        }
        Ok(())
    }

    fn mkdir_at(
        &self,
        dir: ScopedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        fn open_to_mkdir_error(error: OpenError) -> MkdirError {
            match error {
                OpenError::PathError(error) => MkdirError::PathError(error),
                OpenError::AlreadyExists => MkdirError::AlreadyExists,
                OpenError::ReadOnlyFileSystem => MkdirError::ReadOnlyFileSystem,
                OpenError::NoWritePerms => MkdirError::NoWritePerms,
                _ => MkdirError::Io,
            }
        }
        if !valid(name) {
            return Err(PathError::InvalidPathname.into());
        }
        let OverlayWalkingDir {
            mut path,
            resolved,
            locked,
        } = dir.into_typed::<Self>();
        if self
            .entry(&resolved, name)
            .map_err(open_to_mkdir_error)?
            .is_some()
        {
            return Err(MkdirError::AlreadyExists);
        }
        let upper = self
            .ensure_upper_dir(&locked, &path)
            .map_err(open_to_mkdir_error)?;
        let whiteout = whiteout(name);
        let recreated = self
            .marker_present(&upper, &whiteout)
            .map_err(|_| MkdirError::Io)?;
        let child = self.upper.mkdir_at(
            self.upper.walking_dir_at(&upper).ok_or(MkdirError::Io)?,
            name,
            metadata,
        )?;

        // A directory recreated over a whiteout must not re-merge with the lower directory it
        // replaces, so it starts out opaque.
        let cleared = if recreated {
            self.create_marker(&locked, &child, OPAQUE_MARKER)
                .and_then(|()| {
                    self.remove_marker(&locked, &upper, &whiteout)
                        .map_err(unlink_to_open_error)
                })
                .map_err(open_to_mkdir_error)
        } else {
            Ok(())
        };
        if let Err(error) = cleared {
            let _rollback_marker = self.clear_markers(&locked, &child);
            let _rollback_dir = self
                .upper
                .walking_dir_at(&upper)
                .ok_or(RmdirError::Io)
                .and_then(|dir| self.upper.rmdir_at(dir, name));
            return Err(error);
        }

        path.push(String::from(name));
        Ok(DirHandle::from_typed::<Self>(OverlayDir { path }))
    }

    fn unlink_at(&self, dir: ScopedDir<'_>, name: &str) -> Result<(), UnlinkError> {
        fn open_to_unlink_error(error: OpenError) -> UnlinkError {
            match error {
                OpenError::PathError(error) => UnlinkError::PathError(error),
                OpenError::ReadOnlyFileSystem => UnlinkError::ReadOnlyFileSystem,
                OpenError::NoWritePerms => UnlinkError::NoWritePerms,
                _ => UnlinkError::Io,
            }
        }
        if !valid(name) {
            return Err(PathError::InvalidPathname.into());
        }
        let OverlayWalkingDir {
            path,
            resolved,
            locked,
        } = dir.into_typed::<Self>();
        let entry = self
            .entry(&resolved, name)
            .map_err(open_to_unlink_error)?
            .ok_or(PathError::NoSuchFileOrDirectory)?;
        if entry.entry.file_type == FileType::Directory {
            return Err(UnlinkError::IsADirectory);
        }
        // The whiteout goes in before the upper entry comes out, so a failure part-way through can
        // never reveal the lower entry.
        let upper = match entry.lower {
            Some(_) => {
                let upper = self
                    .ensure_upper_dir(&locked, &path)
                    .map_err(open_to_unlink_error)?;
                self.create_marker(&locked, &upper, &whiteout(name))
                    .map_err(open_to_unlink_error)?;
                upper
            }
            None => resolved.upper.ok_or(UnlinkError::Io)?,
        };
        if entry.upper {
            self.upper.unlink_at(
                self.upper.walking_dir_at(&upper).ok_or(UnlinkError::Io)?,
                name,
            )?;
        }
        Ok(())
    }

    fn rmdir_at(&self, dir: ScopedDir<'_>, name: &str) -> Result<(), RmdirError> {
        fn open_to_rmdir_error(error: OpenError) -> RmdirError {
            match error {
                OpenError::PathError(error) => RmdirError::PathError(error),
                OpenError::ReadOnlyFileSystem => RmdirError::ReadOnlyFileSystem,
                OpenError::NoWritePerms => RmdirError::NoWritePerms,
                _ => RmdirError::Io,
            }
        }
        if !valid(name) {
            return Err(PathError::InvalidPathname.into());
        }
        let OverlayWalkingDir {
            path,
            resolved,
            locked,
        } = dir.into_typed::<Self>();
        let entry = self
            .entry(&resolved, name)
            .map_err(open_to_rmdir_error)?
            .ok_or(PathError::NoSuchFileOrDirectory)?;
        if entry.entry.file_type != FileType::Directory {
            return Err(RmdirError::NotADirectory);
        }
        let child = self
            .resolve_child_dir(&resolved, name, &entry)
            .map_err(open_to_rmdir_error)?;
        if !self
            .entries(&child)
            .map_err(open_to_rmdir_error)?
            .is_empty()
        {
            return Err(RmdirError::NotEmpty);
        }

        // As in `unlink_at`, hide the lower directory before removing the upper one.
        let upper = match entry.lower {
            Some(_) => {
                let upper = self
                    .ensure_upper_dir(&locked, &path)
                    .map_err(open_to_rmdir_error)?;
                self.create_marker(&locked, &upper, &whiteout(name))
                    .map_err(open_to_rmdir_error)?;
                upper
            }
            None => resolved.upper.ok_or(RmdirError::Io)?,
        };
        if let Some(child) = &child.upper {
            let cleared = self
                .clear_markers(&locked, child)
                .map_err(unlink_to_open_error)
                .map_err(open_to_rmdir_error)?;
            if let Err(error) = self.upper.rmdir_at(
                self.upper.walking_dir_at(&upper).ok_or(RmdirError::Io)?,
                name,
            ) {
                for marker in cleared {
                    let _rollback_marker = self.create_marker(&locked, child, &marker);
                }
                return Err(error);
            }
        }
        Ok(())
    }

    fn rename_at(
        &self,
        old_dir: DirHandle,
        old_name: &str,
        new_dir: DirHandle,
        new_name: &str,
    ) -> Result<(), RenameError> {
        fn open_to_rename_error(error: OpenError) -> RenameError {
            match error {
                OpenError::PathError(error) => RenameError::PathError(error),
                OpenError::ReadOnlyFileSystem => RenameError::ReadOnlyFileSystem,
                OpenError::NoWritePerms | OpenError::AccessNotAllowed => RenameError::NoWritePerms,
                _ => RenameError::Io,
            }
        }
        if [old_name, new_name].iter().any(|name| {
            !valid(name)
                || name.is_empty()
                || matches!(*name, "." | "..")
                || name.contains(['/', '\0'])
        }) {
            return Err(PathError::InvalidPathname.into());
        }
        let old_path = old_dir.into_typed::<Self>().path;
        let new_path = new_dir.into_typed::<Self>().path;
        let locked = self.namespace.lock();
        let old_dir = self.resolve_dir(&old_path).map_err(open_to_rename_error)?;
        let source = self
            .entry(&old_dir, old_name)
            .map_err(open_to_rename_error)?
            .ok_or(PathError::NoSuchFileOrDirectory)?;
        let directory = source.entry.file_type == FileType::Directory;
        if old_path == new_path && old_name == new_name {
            return Ok(());
        }
        let mut source_path = old_path.clone();
        source_path.push(String::from(old_name));
        if directory && new_path.starts_with(&source_path) {
            return Err(RenameError::InvalidArgument);
        }
        let mut destination_path = new_path.clone();
        destination_path.push(String::from(new_name));
        if old_path.starts_with(&destination_path) {
            return Err(RenameError::NotEmpty);
        }
        let new_dir = self.resolve_dir(&new_path).map_err(open_to_rename_error)?;
        let destination = self
            .entry(&new_dir, new_name)
            .map_err(open_to_rename_error)?;
        if let Some(destination) = &destination {
            match (
                directory,
                destination.entry.file_type == FileType::Directory,
            ) {
                (true, false) => return Err(RenameError::NotADirectory),
                (false, true) => return Err(RenameError::IsADirectory),
                (true, true) => {
                    let child = self
                        .resolve_child_dir(&new_dir, new_name, destination)
                        .map_err(open_to_rename_error)?;
                    if !self
                        .entries(&child)
                        .map_err(open_to_rename_error)?
                        .is_empty()
                    {
                        return Err(RenameError::NotEmpty);
                    }
                    // XXX(jayb): a logically empty destination can still hold hidden markers;
                    // handle this by clearing them (with rollback) as Linux overlayfs does.
                    if let Some(upper) = &child.upper
                        && self
                            .upper
                            .list_dir_at(upper.clone())
                            .map_err(|_| RenameError::Io)?
                            .iter()
                            .any(|entry| !valid(&entry.name))
                    {
                        unimplemented!("rename over a directory with hidden overlay markers");
                    }
                }
                (false, false) => {}
            }
        }
        // Never emulate rename with copy/delete: lower-backed sources and directories with lower
        // contributions at either endpoint cannot be moved atomically.
        if !source.upper
            || (directory
                && (source.lower.is_some()
                    || destination
                        .as_ref()
                        .is_some_and(|entry| entry.lower.is_some())))
        {
            unimplemented!("rename of lower-backed overlay entries");
        }
        let old_upper = old_dir.upper.ok_or(RenameError::Io)?;
        let new_upper = self
            .ensure_upper_dir(&locked, &new_path)
            .map_err(open_to_rename_error)?;
        if source.lower.is_some() {
            // XXX(jayb): hide the old lower entry before moving its upper replacement; not atomic,
            // so fix as part of broader atomicity fixups. Failure leaves the source visible
            // because an upper entry takes precedence over whiteouts. Keep any destination
            // whiteout so moving away cannot reveal its lower.
            self.create_marker(&locked, &old_upper, &whiteout(old_name))
                .map_err(open_to_rename_error)?;
        }
        self.upper
            .rename_at(old_upper, old_name, new_upper, new_name)
    }

    fn chmod(&self, h: ResolvedTarget<'_>, mode: Mode) -> Result<(), ChmodError> {
        if let ResolvedTarget::File(file) = &h
            && file.file_type == FileType::SymbolicLink
        {
            return Err(ChmodError::IsSymlink);
        }
        self.with_upper(h, |target| self.upper.chmod(target, mode))
            .map_err(|error| match error {
                OpenError::PathError(error) => ChmodError::PathError(error),
                OpenError::ReadOnlyFileSystem => ChmodError::ReadOnlyFileSystem,
                _ => ChmodError::Io,
            })?
    }

    fn chown(
        &self,
        h: ResolvedTarget<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        if let ResolvedTarget::File(file) = &h
            && file.file_type == FileType::SymbolicLink
        {
            return Err(ChownError::IsSymlink);
        }
        self.with_upper(h, |target| self.upper.chown(target, user, group))
            .map_err(|error| match error {
                OpenError::PathError(error) => ChownError::PathError(error),
                OpenError::ReadOnlyFileSystem => ChownError::ReadOnlyFileSystem,
                _ => ChownError::Io,
            })?
    }
}
