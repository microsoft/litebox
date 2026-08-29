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
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use hashbrown::{HashMap, HashSet};

use crate::LiteBox;
use crate::sync::{Mutex, MutexGuard, RawSyncPrimitivesProvider};

use super::backend::{
    Backend, BackendHandles, CreationMetadata, DirHandle, FileHandle, Handle, HandleRef,
    PermissionCheck, PermissionInfo, Permissioned, SeekBehavior, WalkOutcome, WalkStopReason,
    WalkedComponent, WalkingDirHandle,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::inode_allocator::InodeAllocator;
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, UserInfo};

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
    /// Makes a resolve-then-mutate sequence atomic against other overlay mutations. It is
    /// deliberately *not* taken by read paths.
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

pub struct OverlayWalkingDir {
    path: Vec<String>,
}

#[derive(Clone)]
pub struct OverlayDir {
    path: Vec<String>,
}

/// An owned handle to a file opened through the overlay.
#[derive(Clone)]
pub struct OverlayFile {
    /// The layer this file was _opened_ against; a later copy-up can move it, which is what
    /// [`State::copied_up`] records.
    layer: OverlayFileLayer,
    // TODO(jayb): the parent path plus name is how object-addressed operations (`chmod`/`chown`)
    // find the file again in order to copy it up. This must be revisited when rename lands, since a
    // rename invalidates the recorded location.
    parent: Vec<String>,
    name: String,
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
struct ResolvedDir {
    upper: Option<DirHandle>,
    /// Per lower backend, in precedence order, its directory at this path if any.
    lowers: Vec<Option<DirHandle>>,
    entries: HashMap<String, ResolvedEntry>,
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

impl<Platform: RawSyncPrimitivesProvider> Overlay<Platform> {
    /// Construct an overlay over a single `lower`, using `allocator` for overlay-visible inodes.
    pub fn new(
        litebox: &LiteBox<Platform>,
        upper: impl Backend,
        lower: impl Backend,
        allocator: InodeAllocator,
    ) -> Self {
        Self::with_boxed_lowers(litebox, upper, vec![Box::new(lower)], allocator)
    }

    /// Construct an overlay with lower backends ordered from highest to lowest precedence.
    ///
    /// # Panics
    ///
    /// Panics if `lowers` is empty.
    pub fn with_boxed_lowers(
        _litebox: &LiteBox<Platform>,
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
        let upper = self.upper.owned_dir_at(self.upper.root(), OFlags::PATH)?;
        let lowers = self
            .lowers
            .iter()
            .map(|lower| lower.owned_dir_at(lower.root(), OFlags::PATH).map(Some))
            .collect::<Result<Vec<_>, _>>()?;
        self.merge(Some(upper), lowers)
    }

    /// Resolve the directory `dir_name` within the already-resolved `parent`, along with the
    /// [`WalkedComponent`] reported by the layer that owns it.
    fn resolve_child_dir(
        &self,
        parent: &ResolvedDir,
        dir_name: &str,
    ) -> Result<(ResolvedDir, WalkedComponent), OpenError> {
        fn walk_into_dir(
            backend: &dyn Backend,
            parent: &DirHandle,
            dir_name: &str,
        ) -> Result<(DirHandle, WalkedComponent), OpenError> {
            let walking = backend.walking_dir_at(parent).ok_or(OpenError::Io)?;
            let outcome = backend
                .walk_directories(walking, &[dir_name])
                .map_err(|error| match error {
                    WalkError::PathError(error) => OpenError::PathError(error),
                    WalkError::Io => OpenError::Io,
                })?;
            let [component] = &outcome.components[..] else {
                return Err(PathError::ComponentNotADirectory.into());
            };
            if outcome.stop_reason != WalkStopReason::CompleteDirectory {
                return Err(PathError::ComponentNotADirectory.into());
            }
            let component = component.clone();
            let owned = backend.owned_dir_at(outcome.last, OFlags::PATH)?;
            Ok((owned, component))
        }

        let entry = parent
            .entries
            .get(dir_name)
            .ok_or(OpenError::PathError(PathError::MissingComponent))?;
        if entry.entry.file_type != FileType::Directory {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }

        let mut owner_component = None;
        let upper = match (&parent.upper, entry.upper) {
            (Some(parent), true) => {
                let (handle, component) = walk_into_dir(self.upper.as_ref(), parent, dir_name)?;
                // The upper backend owns any name it has.
                owner_component = Some(component);
                Some(handle)
            }
            _ => None,
        };

        let mut lowers = Vec::with_capacity(self.lowers.len());
        for ((layer, lower), parent) in self.lowers.iter().enumerate().zip(&parent.lowers) {
            let child = match parent {
                Some(parent) if entry.lower_directories[layer] => {
                    let (handle, component) = walk_into_dir(lower.as_ref(), parent, dir_name)?;
                    // Otherwise the highest-precedence lower with this name owns it.
                    owner_component.get_or_insert(component);
                    Some(handle)
                }
                _ => None,
            };
            lowers.push(child);
        }
        let component =
            owner_component.expect("a merged directory is owned by upper or by a lower directory");

        Ok((self.merge(upper, lowers)?, component))
    }

    /// Resolve a logical `path` (relative to the overlay root) to its per-layer directories.
    fn resolve_dir(&self, path: &[String]) -> Result<ResolvedDir, OpenError> {
        let mut current = self.resolve_root()?;
        for name in path {
            current = self.resolve_child_dir(&current, name)?.0;
        }
        Ok(current)
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
            upper_dir.clone(),
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
            let _rollback_result = self.upper.unlink_at(upper_dir.clone(), name);
            return Err(error);
        }
        // The copied-up file keeps the identity it had in the lower backend, so existing
        // lower-backed handles keep reporting the same inode.
        if let Ok(upper_status) = self.upper.status(HandleRef::File(&upper)) {
            self.bind_copy_up(
                layer,
                status.node_info.clone(),
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
                    .write(upper, &buf[written..count], offset + written)
                    .map_err(|_| OpenError::Io)?;
                if progress == 0 {
                    return Err(OpenError::Io);
                }
                written += progress;
            }
            offset += count;
        }
    }

    /// Materialise whatever `h` refers to in the upper backend, and return a handle to it.
    fn ensure_upper(
        &self,
        locked: NamespaceGuard<'_, Platform>,
        h: HandleRef<'_>,
    ) -> Result<Handle, OpenError> {
        let file = match h {
            HandleRef::Dir(dir) => {
                let path = &dir.get_typed::<Self>().path;
                return Ok(Handle::Dir(self.ensure_upper_dir(&locked, path)?));
            }
            HandleRef::File(file) => file.get_typed::<Self>(),
        };
        let (layer, lower) = match &file.layer {
            OverlayFileLayer::Upper(handle) => return Ok(Handle::File(handle.clone())),
            OverlayFileLayer::Lower { layer, handle, .. } => (*layer, handle),
        };
        if let Some(upper) = self.migrated(file) {
            return Ok(Handle::File(upper));
        }

        let status = self.lowers[layer]
            .status(HandleRef::File(lower))
            .map_err(file_status_to_open_error)?;
        if status.file_type != FileType::RegularFile {
            // Only regular files can be copied up.
            return Err(OpenError::ReadOnlyFileSystem);
        }
        let upper_dir = self.ensure_upper_dir(&locked, &file.parent)?;
        let upper = self.copy_up_file(
            &locked,
            &upper_dir,
            &file.name,
            (layer, lower),
            &status,
            false,
        )?;
        Ok(Handle::File(upper))
    }

    fn marker_present(&self, dir: &DirHandle, marker: &str) -> Result<bool, ReadDirError> {
        Ok(self
            .upper
            .list_dir_at(dir.clone())?
            .iter()
            .any(|entry| entry.name == marker))
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
            dir.clone(),
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
            self.upper.unlink_at(dir.clone(), marker)?;
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
        let entries = self
            .upper
            .list_dir_at(dir.clone())
            .map_err(|_| UnlinkError::Io)?;
        let mut removed = Vec::new();
        for entry in entries.iter().filter(|entry| !valid(&entry.name)) {
            self.upper.unlink_at(dir.clone(), &entry.name)?;
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
        let mut upper = self.upper.owned_dir_at(self.upper.root(), OFlags::PATH)?;
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
                parent.clone(),
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
                _ => OpenError::Io,
            })?;
        // A materialised directory stands in for the lower one, so it keeps its identity.
        if let (Some(layer), Ok(upper)) = (layer, self.upper.status(HandleRef::Dir(&child))) {
            self.bind_copy_up(layer, status.node_info, upper.node_info, None);
        }
        Ok(child)
    }

    /// The layer that owns a resolved directory, and its handle within that layer: the upper
    /// directory when there is one, the highest-precedence lower directory otherwise.
    fn owning_dir<'a>(
        &'a self,
        dir: &'a ResolvedDir,
    ) -> Option<(Option<usize>, &'a dyn Backend, &'a DirHandle)> {
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
        ids.entry(layer_node(layer, node))
            .or_insert_with(|| NodeInfo {
                rdev,
                ..self.alloc.next()
            })
            .clone()
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
        state.ids.insert(layer_node(None, upper), id.clone());
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

    /// Merge the per-layer directories of one logical directory into its overlay-visible entries.
    fn merge(
        &self,
        upper: Option<DirHandle>,
        lowers: Vec<Option<DirHandle>>,
    ) -> Result<ResolvedDir, OpenError> {
        let upper_entries = match &upper {
            Some(handle) => self
                .upper
                .list_dir_at(handle.clone())
                .map_err(|_| OpenError::Io)?,
            None => Vec::new(),
        };
        // Markers held by this upper directory, which say what it hides from the lowers.
        let markers: HashSet<String> = upper_entries
            .iter()
            .filter(|entry| !valid(&entry.name))
            .map(|entry| entry.name.clone())
            .collect();
        let opaque = markers.contains(OPAQUE_MARKER);

        let mut entries = HashMap::new();
        // Names at which lower entries can no longer be merged in: an entry exists there that is
        // not a directory in every layer that contributed to it.
        let mut blocked = HashSet::new();

        for mut entry in upper_entries.into_iter().filter(|entry| valid(&entry.name)) {
            if entry.file_type != FileType::Directory {
                blocked.insert(entry.name.clone());
            }
            entry.ino_info = entry
                .ino_info
                .take()
                .map(|node| self.map_node(&mut self.state.lock().ids, None, node));
            entries.insert(
                entry.name.clone(),
                ResolvedEntry {
                    entry,
                    upper: true,
                    lower: None,
                    lower_directories: vec![false; self.lowers.len()],
                },
            );
        }

        if !opaque {
            for (layer, handle) in lowers.iter().enumerate() {
                let Some(handle) = handle else {
                    continue;
                };
                let layer_entries = self.lowers[layer]
                    .list_dir_at(handle.clone())
                    .map_err(|_| OpenError::Io)?;
                for mut lower_entry in layer_entries {
                    let name = lower_entry.name.clone();
                    if !valid(&name) || markers.contains(&whiteout(&name)) {
                        continue;
                    }
                    let directory = lower_entry.file_type == FileType::Directory;
                    let lower_node = lower_entry.ino_info.take();
                    let entry = entries
                        .entry(name.clone())
                        .or_insert_with(|| ResolvedEntry {
                            entry: lower_entry,
                            upper: false,
                            lower: Some(layer),
                            lower_directories: vec![false; self.lowers.len()],
                        });
                    entry.lower.get_or_insert(layer);
                    if !entry.upper && entry.lower == Some(layer) {
                        // This layer owns the entry, so its node is the one callers see.
                        entry.entry.ino_info = lower_node.clone().map(|node| {
                            self.map_node(&mut self.state.lock().ids, Some(layer), node)
                        });
                    }
                    if blocked.contains(&name) {
                        continue;
                    }
                    if directory {
                        entry.lower_directories[layer] = true;
                        // Several layers describe one logical directory; the one already resolved
                        // above owns the identity, and this layer's node adopts it.
                        if let (Some(node), Some(id)) = (lower_node, entry.entry.ino_info.clone()) {
                            self.state
                                .lock()
                                .ids
                                .entry(layer_node(Some(layer), node))
                                .or_insert(id);
                        }
                    } else {
                        blocked.insert(name);
                    }
                }
            }
        }

        Ok(ResolvedDir {
            upper,
            lowers,
            entries,
        })
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

fn unlink_to_open_error(error: UnlinkError) -> OpenError {
    match error {
        UnlinkError::PathError(error) => OpenError::PathError(error),
        UnlinkError::ReadOnlyFileSystem => OpenError::ReadOnlyFileSystem,
        UnlinkError::NoWritePerms => OpenError::NoWritePerms,
        _ => OpenError::Io,
    }
}

fn file_status_to_open_error(error: FileStatusError) -> OpenError {
    match error {
        FileStatusError::PathError(error) => OpenError::PathError(error),
        _ => OpenError::Io,
    }
}

impl<Platform: RawSyncPrimitivesProvider> super::backend::private::Sealed for Overlay<Platform> {}

impl<Platform: RawSyncPrimitivesProvider> BackendHandles for Overlay<Platform> {
    type WalkingDirHandle<'a> = OverlayWalkingDir;
    type FileHandle = OverlayFile;
    type DirHandle = OverlayDir;
}

impl<Platform: RawSyncPrimitivesProvider> Backend for Overlay<Platform> {
    fn root(&self) -> WalkingDirHandle<'_> {
        WalkingDirHandle::from_typed::<Self>(OverlayWalkingDir { path: Vec::new() })
    }

    fn walk_directories<'a>(
        &'a self,
        from: WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<WalkOutcome<WalkingDirHandle<'a>>, WalkError> {
        fn open_to_walk_error(error: OpenError) -> WalkError {
            match error {
                OpenError::PathError(error) => WalkError::PathError(error),
                _ => WalkError::Io,
            }
        }
        let mut path = from.into_typed::<Self>().path;
        let mut walked = Vec::with_capacity(components.len());
        let mut current = self.resolve_dir(&path).map_err(open_to_walk_error)?;
        for name in components {
            if !valid(name) {
                return Err(PathError::InvalidPathname.into());
            }
            let entry = current
                .entries
                .get(*name)
                .ok_or(PathError::NoSuchFileOrDirectory)?;
            if entry.entry.file_type != FileType::Directory {
                return Ok(WalkOutcome {
                    components: walked,
                    last: WalkingDirHandle::from_typed::<Self>(OverlayWalkingDir { path }),
                    stop_reason: WalkStopReason::StoppedAtNonDirectory,
                });
            }
            let (child, component) = self
                .resolve_child_dir(&current, name)
                .map_err(open_to_walk_error)?;
            current = child;
            path.push(String::from(*name));
            walked.push(component);
        }
        Ok(WalkOutcome {
            components: walked,
            last: WalkingDirHandle::from_typed::<Self>(OverlayWalkingDir { path }),
            stop_reason: WalkStopReason::CompleteDirectory,
        })
    }

    fn owned_dir_at(
        &self,
        dir: WalkingDirHandle<'_>,
        flags: OFlags,
    ) -> Result<DirHandle, OpenError> {
        let path = dir.into_typed::<Self>().path;
        let resolved = self.resolve_dir(&path)?;
        let (_, backend, handle) = self.owning_dir(&resolved).ok_or(OpenError::Io)?;
        let walking = backend.walking_dir_at(handle).ok_or(OpenError::Io)?;
        backend.owned_dir_at(walking, flags)?;
        Ok(DirHandle::from_typed::<Self>(OverlayDir { path }))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<WalkingDirHandle<'a>> {
        Some(WalkingDirHandle::from_typed::<Self>(OverlayWalkingDir {
            path: dir.get_typed::<Self>().path.clone(),
        }))
    }

    fn open_file_at(
        &self,
        dir: WalkingDirHandle<'_>,
        name: &str,
        flags: OFlags,
    ) -> Result<Permissioned<FileHandle>, OpenError> {
        if !valid(name) {
            return Err(PathError::InvalidPathname.into());
        }
        if flags.contains(OFlags::DIRECTORY) {
            return Err(PathError::ComponentNotADirectory.into());
        }
        let path = dir.into_typed::<Self>().path;
        let guard = self.namespace.lock();
        let resolved = self.resolve_dir(&path)?;
        let entry = resolved
            .entries
            .get(name)
            .ok_or(OpenError::PathError(PathError::NoSuchFileOrDirectory))?;
        // The resolver only reaches `create_file_at` once a walk reported the name as missing, so
        // an existing entry means an exclusive create must fail here.
        if flags.contains(OFlags::CREAT | OFlags::EXCL) {
            return Err(OpenError::AlreadyExists);
        }

        let (layer, permissions) = if entry.upper {
            let upper = resolved.upper.as_ref().ok_or(OpenError::Io)?;
            let walking = self.upper.walking_dir_at(upper).ok_or(OpenError::Io)?;
            let file = self.upper.open_file_at(walking, name, flags)?;
            (OverlayFileLayer::Upper(file.item), file.permissions)
        } else {
            let layer = entry.lower.ok_or(OpenError::Io)?;
            let lower_dir = resolved.lowers[layer].as_ref().ok_or(OpenError::Io)?;
            let walking = self.lowers[layer]
                .walking_dir_at(lower_dir)
                .ok_or(OpenError::Io)?;
            // An open that may modify the file has to copy it up first; the lower backends are
            // immutable, so such an open is read-only down there.
            //
            // XXX(jayb): the resolver authorizes an open only after this returns, so a
            // writable open can copy up before a later permission denial. A preflight
            // authorization hook in `Backend` would make copy-up properly two-phase.
            let writing =
                flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::APPEND | OFlags::TRUNC);
            let lower_flags = if writing {
                OFlags::RDONLY
            } else {
                flags.difference(OFlags::CREAT)
            };
            let file = self.lowers[layer].open_file_at(walking, name, lower_flags)?;
            // The file's own identity, which is also the key a later copy-up records itself under.
            let status = self.lowers[layer]
                .status(HandleRef::File(&file.item))
                .map_err(file_status_to_open_error)?;
            if writing {
                if entry.entry.file_type != FileType::RegularFile {
                    // Only regular files can be copied up, and the lowers do not accept writes.
                    return Err(OpenError::ReadOnlyFileSystem);
                }
                let upper_dir = self.ensure_upper_dir(&guard, &path)?;
                let upper = self.copy_up_file(
                    &guard,
                    &upper_dir,
                    name,
                    (layer, &file.item),
                    &status,
                    flags.contains(OFlags::TRUNC),
                )?;
                // The lower open was substituted with a read-only one, so its `PermissionCheck`
                // says nothing about the caller's write access; check the file's own mode instead.
                let permissions = PermissionCheck::ByResolver(PermissionInfo {
                    mode: status.mode,
                    owner: status.owner,
                });
                (OverlayFileLayer::Upper(upper), permissions)
            } else {
                let node = self.map_node(&mut self.state.lock().ids, Some(layer), status.node_info);
                (
                    OverlayFileLayer::Lower {
                        layer,
                        handle: file.item,
                        node,
                    },
                    file.permissions,
                )
            }
        };

        Ok(Permissioned {
            item: FileHandle::from_typed::<Self>(OverlayFile {
                layer,
                parent: path,
                name: String::from(name),
            }),
            permissions,
        })
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        let path = handle.into_typed::<Self>().path;
        let resolved = self.resolve_dir(&path).map_err(|_| ReadDirError::Io)?;
        let mut entries: Vec<DirEntry> = resolved
            .entries
            .into_values()
            .map(|entry| entry.entry)
            .collect();
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }

    fn read(&self, h: &FileHandle, buf: &mut [u8], offset: usize) -> Result<usize, ReadError> {
        self.with_file(h.get_typed::<Self>(), |_, backend, handle| {
            backend.read(handle, buf, offset)
        })
    }

    fn get_static_backing_data(&self, h: &FileHandle) -> Option<&'static [u8]> {
        self.with_file(h.get_typed::<Self>(), |_, backend, handle| {
            backend.get_static_backing_data(handle)
        })
    }

    fn write(&self, h: &FileHandle, buf: &[u8], offset: usize) -> Result<usize, WriteError> {
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
                let resolved = self.resolve_dir(path).map_err(|_| FileStatusError::Io)?;
                let (layer, backend, handle) =
                    self.owning_dir(&resolved).ok_or(FileStatusError::Io)?;
                let status = backend.status(HandleRef::Dir(handle))?;
                Ok(self.map_status(status, layer))
            }
        }
    }

    fn create_file_at(
        &self,
        dir: DirHandle,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        if !valid(name) {
            return Err(PathError::InvalidPathname.into());
        }
        let path = dir.into_typed::<Self>().path;
        let locked = self.namespace.lock();
        if self.resolve_dir(&path)?.entries.contains_key(name) {
            return Err(OpenError::AlreadyExists);
        }
        let upper = self.ensure_upper_dir(&locked, &path)?;
        let file = self.upper.create_file_at(upper.clone(), name, metadata)?;
        if let Err(error) = self.remove_marker(&locked, &upper, &whiteout(name)) {
            let _rollback_result = self.upper.unlink_at(upper, name);
            return Err(unlink_to_open_error(error));
        }
        Ok(FileHandle::from_typed::<Self>(OverlayFile {
            layer: OverlayFileLayer::Upper(file),
            parent: path,
            name: String::from(name),
        }))
    }

    fn mkdir_at(
        &self,
        dir: DirHandle,
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
        let mut path = dir.into_typed::<Self>().path;
        let locked = self.namespace.lock();
        let resolved = self.resolve_dir(&path).map_err(open_to_mkdir_error)?;
        if resolved.entries.contains_key(name) {
            return Err(MkdirError::AlreadyExists);
        }
        let upper = self
            .ensure_upper_dir(&locked, &path)
            .map_err(open_to_mkdir_error)?;
        let whiteout = whiteout(name);
        let recreated = self
            .marker_present(&upper, &whiteout)
            .map_err(|_| MkdirError::Io)?;
        let child = self.upper.mkdir_at(upper.clone(), name, metadata)?;

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
            let _rollback_dir = self.upper.rmdir_at(upper, name);
            return Err(error);
        }

        path.push(String::from(name));
        Ok(DirHandle::from_typed::<Self>(OverlayDir { path }))
    }

    fn unlink_at(&self, dir: DirHandle, name: &str) -> Result<(), UnlinkError> {
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
        let path = dir.into_typed::<Self>().path;
        let locked = self.namespace.lock();
        let resolved = self.resolve_dir(&path).map_err(open_to_unlink_error)?;
        let entry = resolved
            .entries
            .get(name)
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
            self.upper.unlink_at(upper, name)?;
        }
        Ok(())
    }

    fn rmdir_at(&self, dir: DirHandle, name: &str) -> Result<(), RmdirError> {
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
        let path = dir.into_typed::<Self>().path;
        let locked = self.namespace.lock();
        let resolved = self.resolve_dir(&path).map_err(open_to_rmdir_error)?;
        let entry = resolved
            .entries
            .get(name)
            .ok_or(PathError::NoSuchFileOrDirectory)?;
        if entry.entry.file_type != FileType::Directory {
            return Err(RmdirError::NotADirectory);
        }
        let (child, _) = self
            .resolve_child_dir(&resolved, name)
            .map_err(open_to_rmdir_error)?;
        if !child.entries.is_empty() {
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
            if let Err(error) = self.upper.rmdir_at(upper, name) {
                for marker in cleared {
                    let _rollback_marker = self.create_marker(&locked, child, &marker);
                }
                return Err(error);
            }
        }
        Ok(())
    }

    fn chmod(&self, h: HandleRef<'_>, mode: Mode) -> Result<(), ChmodError> {
        let locked = self.namespace.lock();
        let handle = self.ensure_upper(locked, h).map_err(|error| match error {
            OpenError::PathError(error) => ChmodError::PathError(error),
            OpenError::ReadOnlyFileSystem => ChmodError::ReadOnlyFileSystem,
            _ => ChmodError::Io,
        })?;
        self.upper.chmod(handle.as_ref(), mode)
    }

    fn chown(
        &self,
        h: HandleRef<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let locked = self.namespace.lock();
        let handle = self.ensure_upper(locked, h).map_err(|error| match error {
            OpenError::PathError(error) => ChownError::PathError(error),
            OpenError::ReadOnlyFileSystem => ChownError::ReadOnlyFileSystem,
            _ => ChownError::Io,
        })?;
        self.upper.chown(handle.as_ref(), user, group)
    }
}
