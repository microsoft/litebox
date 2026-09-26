// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An layered file system, layering on [`FileSystem`](super::FileSystem) on top of another.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use hashbrown::{HashMap, HashSet};

use crate::LiteBox;
use crate::fd::TypedFd;
use crate::path::Arg;
use crate::sync;

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, ReadlinkError, RenameError, RmdirError, SeekError, SymlinkError,
    TruncateError, UnlinkError, UtimeError, WriteError,
};
use super::private;
use super::{
    AccessCredentials, DacAccessKind, DirEntry, FileStatus, FileSystem as _, FileType, Mode,
    NodeInfo, OFlags, SeekWhence, Timestamp, UserInfo, dac_allows_as,
    sticky_directory_allows_removal,
};

/// Just a random constant that is distinct from other file systems. In this case, it is
/// `b'Lyrs'.hex()`.
const DEVICE_ID: usize = 0x4c797273;

/// Possible semantics for layering file systems together
#[non_exhaustive]
pub enum LayeringSemantics {
    /// Lower layer is read-only.
    ///
    /// Any writes to the lower layer have copy-on-write semantics, copying it over to the upper
    /// layer, before performing the write.
    LowerLayerReadOnly,
    /// Lower layer's files are writable.
    ///
    /// No new files can be made at the lower layer, but any existing files in the lower layer can
    /// still be written to. If an upper level file exists with the same name as a lower layer file,
    /// then it is shadowed, and only the upper layer file would be visible.
    LowerLayerWritableFiles,
}

/// A backing implementation of [`FileSystem`](super::FileSystem) that layers a file system on top
/// of another.
///
/// This particular implementation itself doesn't carry or store any of the files, but delegates to
/// each of the layers. Specifically, this implementation will look for and work with files in
/// the upper layer, unless they don't exist, in which case the lower layer is looked at.
///
/// The current design of layering supports treating the lower layer as read-only, or as a
/// transparent write-through. In read-only lower layer, if a file is opened in writable mode that
/// doesn't exist in the upper layer, but _does_ exist in the lower layer, this will have
/// copy-on-write semantics.
///
/// Future versions of the layering might support other configurable options for the layering.
pub struct FileSystem<
    Platform: sync::RawSyncPrimitivesProvider,
    Upper: super::FileSystem + 'static,
    Lower: super::FileSystem + 'static,
> {
    litebox: LiteBox<Platform>,
    upper: Upper,
    lower: Lower,
    // Serializes merged-namespace publication. Backend locks protect each layer independently,
    // but operations such as upper unlink plus lower tombstoning are one logical transaction.
    namespace: sync::Mutex<Platform, ()>,
    namespace_sequence: AtomicUsize,
    // TODO: Possibly support a single-threaded variant that doesn't have the cost of requiring a
    // sync-primitives platform, as well as cost of mutexes and such?
    root: sync::RwLock<Platform, RootDir>,
    layering_semantics: LayeringSemantics,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
    current_user: UserInfo,
    node_info_lookup: sync::RwLock<Platform, HashMap<LayerNodeInfo, usize>>,
}

impl<Platform: sync::RawSyncPrimitivesProvider, Upper: super::FileSystem, Lower: super::FileSystem>
    FileSystem<Platform, Upper, Lower>
{
    /// Construct a new `FileSystem` instance
    #[must_use]
    pub fn new(
        litebox: &LiteBox<Platform>,
        upper: Upper,
        lower: Lower,
        layering_semantics: LayeringSemantics,
    ) -> Self {
        Self::new_with_user(
            litebox,
            upper,
            lower,
            layering_semantics,
            UserInfo {
                user: 1000,
                group: 1000,
            },
        )
    }

    /// Construct a new `FileSystem` instance for `current_user`.
    #[must_use]
    pub fn new_with_user(
        litebox: &LiteBox<Platform>,
        upper: Upper,
        lower: Lower,
        layering_semantics: LayeringSemantics,
        current_user: UserInfo,
    ) -> Self {
        let root = sync::RwLock::new(RootDir::new());
        let namespace = sync::Mutex::new(());
        let node_info_lookup = sync::RwLock::new(HashMap::new());
        Self {
            litebox: litebox.clone(),
            upper,
            lower,
            namespace,
            namespace_sequence: AtomicUsize::new(0),
            root,
            current_working_dir: "/".into(),
            current_user,
            layering_semantics,
            node_info_lookup,
        }
    }

    /// Check whether the lower level has `path`, using one immutable credential snapshot.
    fn ensure_lower_contains_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: &str,
    ) -> Result<FileType, FileStatusError> {
        self.lower
            .file_status_as(credentials, path)
            .map(|stat| stat.file_type)
    }

    fn parent_path(path: &str) -> Option<&str> {
        let (parent, _) = path.rsplit_once('/')?;
        Some(if parent.is_empty() { "/" } else { parent })
    }

    /// Authorize mutation against the merged parent before any physical upper scaffolding is made.
    fn authorize_mutating_parent(
        &self,
        credentials: AccessCredentials<'_>,
        path: &str,
    ) -> Result<FileStatus, ParentAuthorizationError> {
        let parent = Self::parent_path(path).ok_or(ParentAuthorizationError::InvalidRoot)?;
        let status = self
            .file_status_as(credentials, parent)
            .map_err(ParentAuthorizationError::Status)?;
        if status.file_type != FileType::Directory {
            return Err(ParentAuthorizationError::NotADirectory);
        }
        if !dac_allows_as(
            credentials,
            status.owner,
            status.mode,
            DacAccessKind::DirectorySearch,
        ) || !dac_allows_as(credentials, status.owner, status.mode, DacAccessKind::Write)
        {
            return Err(ParentAuthorizationError::Denied);
        }
        Ok(status)
    }

    fn authorize_inode_owner(credentials: AccessCredentials<'_>, status: &FileStatus) -> bool {
        credentials.user() == 0 || credentials.owns(status.owner)
    }

    fn authorize_chown(
        credentials: AccessCredentials<'_>,
        status: &FileStatus,
        user: Option<u16>,
        group: Option<u16>,
    ) -> bool {
        if credentials.user() == 0 {
            return true;
        }
        credentials.owns(status.owner)
            && user.is_none_or(|user| user == status.owner.user)
            && group.is_none_or(|group| credentials.in_group(group))
    }

    fn publish_upper_nondirectory(&self, path: &str) {
        self.root.write().publish_upper_nondirectory(path);
    }

    #[allow(
        clippy::unused_self,
        reason = "instance method for API symmetry with lower_entry"
    )]
    fn upper_entry(
        &self,
        fd: TypedFd<Upper>,
        directory: Option<DirectoryBinding>,
    ) -> Entry<Platform, Upper, Lower> {
        Arc::new(OpenDescription {
            state: sync::Mutex::new(Some(OpenState {
                backing: EntryX::Upper { fd },
                position: 0,
                directory: directory.map(|binding| DirectoryState::Upper {
                    binding,
                    lower: None,
                }),
            })),
        })
    }

    #[allow(
        clippy::unused_self,
        reason = "instance method for API symmetry with upper_entry"
    )]
    fn lower_entry(
        &self,
        fd: TypedFd<Lower>,
        directory: Option<DirectoryBinding>,
    ) -> Entry<Platform, Upper, Lower> {
        Arc::new(OpenDescription {
            state: sync::Mutex::new(Some(OpenState {
                backing: EntryX::Lower { fd },
                position: 0,
                directory: directory.map(|binding| DirectoryState::Lower {
                    binding,
                    upper: None,
                }),
            })),
        })
    }

    fn path_suppresses_lower(&self, path: &str) -> bool {
        self.root.read().suppresses_lower(path)
    }

    fn path_is_copy_up_staging(&self, path: &str) -> bool {
        self.root.read().is_copy_up_staging(path)
    }

    fn unregister_copy_up_staging(&self, path: &str) {
        self.root.write().copy_up_staging.remove(path);
    }

    fn cleanup_regular_copy_up_staging(&self, path: &str) {
        match self.upper.remove_file_for_copy_up(&private::COPY_UP, path) {
            Ok(())
            | Err(UnlinkError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => self.unregister_copy_up_staging(path),
            Err(error) => {
                litebox_util_log::error!(path:% = path, error:? = error; "copy-up staging cleanup failed");
            }
        }
    }

    fn cleanup_symlink_copy_up_staging(&self, path: &str) {
        match self.upper.unlink_as(AccessCredentials::root(), path) {
            Ok(())
            | Err(UnlinkError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => self.unregister_copy_up_staging(path),
            Err(error) => {
                litebox_util_log::error!(path:% = path, error:? = error; "symlink staging cleanup failed");
            }
        }
    }

    fn upper_directory_binding_under_namespace(
        &self,
        _namespace_guard: &sync::MutexGuard<'_, Platform, ()>,
        path: &str,
        fd: &TypedFd<Upper>,
    ) -> Result<Option<DirectoryBinding>, OpenError> {
        let held = self.upper.fd_file_status(fd).map_err(|error| match error {
            FileStatusError::PathError(error) => OpenError::PathError(error),
            FileStatusError::Io | FileStatusError::ClosedFd => OpenError::Io,
        })?;
        if held.file_type != FileType::Directory {
            return Ok(None);
        }
        let current = match self.upper.file_status_as(AccessCredentials::root(), path) {
            Ok(status) => status,
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => return Ok(Some(DirectoryBinding::Detached)),
            Err(FileStatusError::PathError(error)) => return Err(error.into()),
            Err(FileStatusError::Io | FileStatusError::ClosedFd) => return Err(OpenError::Io),
        };
        if current.file_type != FileType::Directory || current.node_info != held.node_info {
            return Ok(Some(DirectoryBinding::Detached));
        }
        let generation = self.root.write().directory_generation(path);
        Ok(Some(DirectoryBinding::Current {
            path: path.into(),
            generation,
            backing: LayerNodeInfo::Upper(held.node_info),
        }))
    }

    fn lower_directory_binding_under_namespace(
        &self,
        _namespace_guard: &sync::MutexGuard<'_, Platform, ()>,
        path: &str,
        fd: &TypedFd<Lower>,
    ) -> Result<Option<DirectoryBinding>, OpenError> {
        let held = self.lower.fd_file_status(fd).map_err(|error| match error {
            FileStatusError::PathError(error) => OpenError::PathError(error),
            FileStatusError::Io | FileStatusError::ClosedFd => OpenError::Io,
        })?;
        if held.file_type != FileType::Directory {
            return Ok(None);
        }
        let current = match self.lower.file_status_as(AccessCredentials::root(), path) {
            Ok(status) => status,
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => return Ok(Some(DirectoryBinding::Detached)),
            Err(FileStatusError::PathError(error)) => return Err(error.into()),
            Err(FileStatusError::Io | FileStatusError::ClosedFd) => return Err(OpenError::Io),
        };
        if current.file_type != FileType::Directory || current.node_info != held.node_info {
            return Ok(Some(DirectoryBinding::Detached));
        }
        let generation = self.root.write().directory_generation(path);
        Ok(Some(DirectoryBinding::Current {
            path: path.into(),
            generation,
            backing: LayerNodeInfo::Lower(held.node_info),
        }))
    }

    fn upper_path_status_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: &str,
    ) -> Result<Option<FileStatus>, DirectoryInspectionError> {
        match self.upper.file_status_as(credentials, path) {
            Ok(status) => Ok(Some(status)),
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => Ok(None),
            Err(error) => Err(DirectoryInspectionError::from_file_status(error)),
        }
    }

    fn upper_path_status(
        &self,
        path: &str,
    ) -> Result<Option<FileStatus>, DirectoryInspectionError> {
        self.upper_path_status_as(AccessCredentials::root(), path)
    }

    fn lower_path_status_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: &str,
    ) -> Result<Option<FileStatus>, DirectoryInspectionError> {
        match self.lower.file_status_as(credentials, path) {
            Ok(status) => Ok(Some(status)),
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => Ok(None),
            Err(error) => Err(DirectoryInspectionError::from_file_status(error)),
        }
    }

    fn lower_path_status(
        &self,
        path: &str,
    ) -> Result<Option<FileStatus>, DirectoryInspectionError> {
        self.lower_path_status_as(AccessCredentials::root(), path)
    }

    fn read_upper_directory_at_path(
        &self,
        path: &str,
    ) -> Result<Vec<DirEntry>, DirectoryInspectionError> {
        let fd = self
            .upper
            .open_as(
                AccessCredentials::root(),
                path,
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .map_err(DirectoryInspectionError::from_open)?;
        let result = self
            .upper
            .read_dir(&fd)
            .map_err(DirectoryInspectionError::from_read_dir);
        let _ = self.upper.close(&fd);
        result
    }

    fn read_lower_directory_at_path(
        &self,
        path: &str,
    ) -> Result<Vec<DirEntry>, DirectoryInspectionError> {
        let fd = self
            .lower
            .open_as(
                AccessCredentials::root(),
                path,
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .map_err(DirectoryInspectionError::from_open)?;
        let result = self
            .lower
            .read_dir(&fd)
            .map_err(DirectoryInspectionError::from_read_dir);
        let _ = self.lower.close(&fd);
        result
    }

    fn open_optional_upper_directory_under_namespace(
        &self,
        _namespace_guard: &sync::MutexGuard<'_, Platform, ()>,
        path: &str,
    ) -> Result<Option<TypedFd<Upper>>, ReadDirError> {
        let Some(path_status) = self
            .upper_path_status(path)
            .map_err(DirectoryInspectionError::into_read_dir)?
        else {
            return Ok(None);
        };
        if path_status.file_type != FileType::Directory {
            return Ok(None);
        }
        let fd = match self.upper.open_as(
            AccessCredentials::root(),
            path,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(OpenError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => return Ok(None),
            Err(error) => return Err(DirectoryInspectionError::from_open(error).into_read_dir()),
        };
        let held_status = match self.upper.fd_file_status(&fd) {
            Ok(status) => status,
            Err(error) => {
                let _ = self.upper.close(&fd);
                return Err(DirectoryInspectionError::from_file_status(error).into_read_dir());
            }
        };
        if held_status.file_type != FileType::Directory
            || held_status.node_info != path_status.node_info
        {
            let _ = self.upper.close(&fd);
            return Err(ReadDirError::Io);
        }
        Ok(Some(fd))
    }

    fn open_optional_lower_directory_under_namespace(
        &self,
        _namespace_guard: &sync::MutexGuard<'_, Platform, ()>,
        path: &str,
    ) -> Result<Option<TypedFd<Lower>>, ReadDirError> {
        let Some(path_status) = self
            .lower_path_status(path)
            .map_err(DirectoryInspectionError::into_read_dir)?
        else {
            return Ok(None);
        };
        if path_status.file_type != FileType::Directory {
            return Ok(None);
        }
        let fd = match self.lower.open_as(
            AccessCredentials::root(),
            path,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(OpenError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => return Ok(None),
            Err(error) => return Err(DirectoryInspectionError::from_open(error).into_read_dir()),
        };
        let held_status = match self.lower.fd_file_status(&fd) {
            Ok(status) => status,
            Err(error) => {
                let _ = self.lower.close(&fd);
                return Err(DirectoryInspectionError::from_file_status(error).into_read_dir());
            }
        };
        if held_status.file_type != FileType::Directory
            || held_status.node_info != path_status.node_info
        {
            let _ = self.lower.close(&fd);
            return Err(ReadDirError::Io);
        }
        Ok(Some(fd))
    }

    fn directory_binding_is_current_under_namespace(
        &self,
        _namespace_guard: &sync::MutexGuard<'_, Platform, ()>,
        binding: &DirectoryBinding,
    ) -> Result<bool, ReadDirError> {
        let DirectoryBinding::Current {
            path,
            generation,
            backing,
        } = binding
        else {
            return Ok(false);
        };
        {
            let root = self.root.read();
            if !root.directory_generation_matches(path, *generation)
                || matches!(backing, LayerNodeInfo::Lower(_)) && root.suppresses_lower(path)
            {
                return Ok(false);
            }
        }
        let status = match backing {
            LayerNodeInfo::Upper(expected) => match self
                .upper
                .file_status_as(AccessCredentials::root(), path.as_str())
            {
                Ok(status) => Some((status, expected)),
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => None,
                Err(_) => return Err(ReadDirError::Io),
            },
            LayerNodeInfo::Lower(expected) => match self
                .lower
                .file_status_as(AccessCredentials::root(), path.as_str())
            {
                Ok(status) => Some((status, expected)),
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => None,
                Err(_) => return Err(ReadDirError::Io),
            },
        };
        Ok(status.is_some_and(|(status, expected)| {
            status.file_type == FileType::Directory && status.node_info == *expected
        }))
    }

    fn child_path(path: &str, name: &str) -> String {
        let mut child = String::from(path);
        if child != "/" {
            child.push('/');
        }
        child.push_str(name);
        child
    }

    fn normalize_and_merge_directory_entries(
        upper_entries: &mut Vec<DirEntry>,
        lower_entries: &mut Vec<DirEntry>,
    ) {
        // Each backend synthesizes its own `.`/`..` pair, so a naive merge would either drop
        // them (if both layers' copies were simply treated as ordinary, dedup-by-name entries
        // and one layer happened to lose the dedup) or duplicate them (one pair per layer).
        // Pull out exactly one canonical `.` and one `..`, preferring the upper layer's copy
        // when both layers provide one, before deduplicating the rest by name.
        let mut dot_entries = Vec::with_capacity(2);
        for name in [".", ".."] {
            if let Some(pos) = upper_entries.iter().position(|entry| entry.name == name) {
                dot_entries.push(upper_entries.remove(pos));
            } else if let Some(pos) = lower_entries.iter().position(|entry| entry.name == name) {
                dot_entries.push(lower_entries.remove(pos));
            }
        }

        let is_real_name = |entry: &DirEntry| entry.name != "." && entry.name != "..";
        upper_entries.retain(is_real_name);
        lower_entries.retain(is_real_name);
        let upper_names: HashSet<String> = upper_entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        lower_entries.retain(|entry| !upper_names.contains(&entry.name));

        // Restore the canonical dot entries at the front, matching a real directory listing's
        // conventional `.`, `..`, ... order.
        for entry in dot_entries.into_iter().rev() {
            upper_entries.insert(0, entry);
        }
    }

    fn filter_merged_directory_entries_under_namespace(
        &self,
        _namespace_guard: &sync::MutexGuard<'_, Platform, ()>,
        path: &str,
        upper_entries: &mut Vec<DirEntry>,
        lower_entries: &mut Vec<DirEntry>,
    ) {
        let root = self.root.read();
        upper_entries
            .retain(|entry| !root.is_copy_up_staging(&Self::child_path(path, entry.name.as_str())));
        if root.suppresses_lower(path) {
            lower_entries.clear();
            return;
        }
        lower_entries.retain(|entry| {
            let child = Self::child_path(path, entry.name.as_str());
            !root.is_copy_up_staging(&child) && !root.suppresses_lower(&child)
        });
        drop(root);
        Self::normalize_and_merge_directory_entries(upper_entries, lower_entries);
    }

    fn directory_has_visible_children_under_namespace(
        &self,
        namespace_guard: &sync::MutexGuard<'_, Platform, ()>,
        path: &str,
    ) -> Result<bool, DirectoryInspectionError> {
        let upper_status = self.upper_path_status(path)?;
        let upper_is_directory = match upper_status {
            Some(status) if status.file_type == FileType::Directory => true,
            Some(_) => return Err(DirectoryInspectionError::NotADirectory),
            None => false,
        };
        let lower_suppressed = self.root.read().suppresses_lower(path);
        let lower_status = if lower_suppressed {
            None
        } else {
            self.lower_path_status(path)?
        };
        let lower_is_directory = match lower_status {
            Some(status) if status.file_type == FileType::Directory => true,
            Some(_) if upper_is_directory => false,
            Some(_) => return Err(DirectoryInspectionError::NotADirectory),
            None => false,
        };
        if !upper_is_directory && !lower_is_directory {
            return Err(DirectoryInspectionError::PathError(
                PathError::NoSuchFileOrDirectory,
            ));
        }

        let mut upper_entries = if upper_is_directory {
            self.read_upper_directory_at_path(path)?
        } else {
            Vec::new()
        };
        let mut lower_entries = if lower_is_directory {
            match self.read_lower_directory_at_path(path) {
                Err(DirectoryInspectionError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) if upper_is_directory => Vec::new(),
                result => result?,
            }
        } else {
            Vec::new()
        };
        self.filter_merged_directory_entries_under_namespace(
            namespace_guard,
            path,
            &mut upper_entries,
            &mut lower_entries,
        );
        Ok(upper_entries
            .iter()
            .chain(lower_entries.iter())
            .any(|entry| entry.name != "." && entry.name != ".."))
    }

    fn with_layered_node_info(&self, mut status: FileStatus, upper: bool) -> FileStatus {
        status.node_info = self.get_layered_nodeinfo(status.node_info, upper);
        status
    }

    /// (private-only) Create all parent/ancestor directories for a `path`, making sure that each of
    /// these exist in the lower layer. It does _not_ set up `path` itself on the upper layer
    /// though; this is left to the callee to handle.
    ///
    /// NOTE: This is _not_ equivalent to running `mkdir -p {path}` or `mkdir {path}` or anything
    /// like that.
    fn mkdir_migrating_ancestor_dirs(&self, path: &str) -> Result<(), MkdirError> {
        let path = self.absolute_path(path)?;
        for dir in path.increasing_ancestors().map_err(PathError::from)? {
            if dir == path {
                return Ok(());
            }

            let status = match self.file_status_as(AccessCredentials::root(), dir) {
                Ok(status) => status,
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => return Err(PathError::MissingComponent.into()),
                Err(FileStatusError::PathError(error)) => return Err(error.into()),
                Err(FileStatusError::Io) => return Err(MkdirError::Io),
                Err(FileStatusError::ClosedFd) => unreachable!(),
            };
            if status.file_type != FileType::Directory {
                return Err(PathError::ComponentNotADirectory.into());
            }

            match self.upper.file_status_as(AccessCredentials::root(), dir) {
                Ok(upper_status) if upper_status.file_type == FileType::Directory => {}
                Ok(_) => return Err(PathError::ComponentNotADirectory.into()),
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => match self.upper.mkdir_for_copy_up(
                    &private::COPY_UP,
                    dir,
                    status.mode,
                    status.owner,
                ) {
                    Ok(()) => {}
                    Err(MkdirError::AlreadyExists) => {
                        match self.upper.file_status_as(AccessCredentials::root(), dir) {
                            Ok(upper_status) if upper_status.file_type == FileType::Directory => {}
                            Ok(_) => return Err(PathError::ComponentNotADirectory.into()),
                            Err(FileStatusError::PathError(error)) => return Err(error.into()),
                            Err(FileStatusError::Io) => return Err(MkdirError::Io),
                            Err(FileStatusError::ClosedFd) => unreachable!(),
                        }
                    }
                    Err(error) => return Err(error),
                },
                Err(FileStatusError::PathError(error)) => return Err(error.into()),
                Err(FileStatusError::Io) => return Err(MkdirError::Io),
                Err(FileStatusError::ClosedFd) => unreachable!(),
            }
        }
        unreachable!("increasing_ancestors always reaches the leaf")
    }

    fn mkdir_migrating_ancestor_dirs_for_rename(&self, path: &str) -> Result<(), RenameError> {
        self.mkdir_migrating_ancestor_dirs(path)
            .map_err(|error| match error {
                MkdirError::NoWritePerms => RenameError::NoWritePerms,
                MkdirError::ReadOnlyFileSystem => RenameError::ReadOnlyFileSystem,
                MkdirError::Io => RenameError::Io,
                MkdirError::AlreadyExists => RenameError::AlreadyExists,
                MkdirError::PathError(error) => RenameError::PathError(error),
            })
    }

    /// Copy a lower regular-file object into upper and atomically bind every compatible open
    /// description to the prepared upper inode. If the initiating object is no longer the object
    /// named by `path`, the new upper inode is detached before the binding swap so the current
    /// pathname is never resurrected or replaced.
    fn migrate_file_up(
        &self,
        path: &str,
        copy_data: bool,
        initiating_fd: Option<&FileFd<Platform, Upper, Lower>>,
    ) -> Result<(), MigrationError> {
        let namespace_guard = self.namespace.lock();
        self.migrate_file_up_under_namespace(&namespace_guard, path, copy_data, initiating_fd)
    }

    fn migrate_file_up_under_namespace(
        &self,
        _namespace_guard: &sync::MutexGuard<'_, Platform, ()>,
        path: &str,
        copy_data: bool,
        initiating_fd: Option<&FileFd<Platform, Upper, Lower>>,
    ) -> Result<(), MigrationError> {
        let initiating = match initiating_fd {
            Some(fd) => Some(
                self.litebox
                    .descriptor_table()
                    .with_entry(fd, |descriptor| {
                        (Arc::clone(&descriptor.entry.entry), descriptor.entry.flags)
                    })
                    .ok_or(MigrationError::Io)?,
            ),
            None => None,
        };

        let mut owned_source_fd = None;
        let lower_status = if let Some((entry, _)) = initiating.as_ref() {
            let state = entry.state.lock();
            match state.as_ref().map(|state| &state.backing) {
                Some(EntryX::Upper { .. }) => return Ok(()),
                Some(EntryX::Lower { fd }) => {
                    self.lower.fd_file_status(fd).map_err(|error| match error {
                        FileStatusError::PathError(error) => MigrationError::PathError(error),
                        FileStatusError::Io | FileStatusError::ClosedFd => MigrationError::Io,
                    })?
                }
                None => return Err(MigrationError::Io),
            }
        } else {
            match self.upper.file_status_as(AccessCredentials::root(), path) {
                Ok(_) => return Ok(()),
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => {}
                Err(FileStatusError::PathError(error)) => return Err(error.into()),
                Err(FileStatusError::Io | FileStatusError::ClosedFd) => {
                    return Err(MigrationError::Io);
                }
            }
            if self.path_suppresses_lower(path) {
                return Err(PathError::NoSuchFileOrDirectory.into());
            }
            let fd = self
                .lower
                .open_as(
                    AccessCredentials::root(),
                    path,
                    OFlags::RDONLY,
                    Mode::empty(),
                )
                .map_err(|error| match error {
                    OpenError::AccessNotAllowed | OpenError::OperationNotPermitted => {
                        MigrationError::NoReadPerms
                    }
                    OpenError::PathError(error) => MigrationError::PathError(error),
                    OpenError::TooManySymbolicLinks => MigrationError::NotAFile,
                    OpenError::Io
                    | OpenError::NoWritePerms
                    | OpenError::ReadOnlyFileSystem
                    | OpenError::AlreadyExists
                    | OpenError::TruncateError(_)
                    | OpenError::UnsupportedFlags => MigrationError::Io,
                })?;
            let status = self
                .lower
                .fd_file_status(&fd)
                .map_err(|error| match error {
                    FileStatusError::PathError(error) => MigrationError::PathError(error),
                    FileStatusError::Io | FileStatusError::ClosedFd => MigrationError::Io,
                })?;
            owned_source_fd = Some(fd);
            status
        };
        if lower_status.file_type != FileType::RegularFile {
            if let Some(fd) = owned_source_fd {
                let _ = self.lower.close(&fd);
            }
            return Err(MigrationError::NotAFile);
        }

        let upper_absent = match self.upper.file_status_as(AccessCredentials::root(), path) {
            Ok(_) => false,
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => true,
            Err(FileStatusError::PathError(error)) => {
                if let Some(fd) = owned_source_fd {
                    let _ = self.lower.close(&fd);
                }
                return Err(error.into());
            }
            Err(FileStatusError::Io | FileStatusError::ClosedFd) => {
                if let Some(fd) = owned_source_fd {
                    let _ = self.lower.close(&fd);
                }
                return Err(MigrationError::Io);
            }
        };
        let current_lower_is_source = upper_absent
            && !self.path_suppresses_lower(path)
            && self
                .lower
                .file_status_as(AccessCredentials::root(), path)
                .is_ok_and(|status| status.node_info == lower_status.node_info);
        let publish_named = current_lower_is_source;
        if initiating.is_none() && !publish_named {
            if let Some(fd) = owned_source_fd {
                let _ = self.lower.close(&fd);
            }
            return Err(PathError::NoSuchFileOrDirectory.into());
        }

        // The initiating description is first and remains the source object. Every other open
        // description of that same lower inode is rebound too, including aliases whose old pathname
        // has since been unlinked or replaced.
        let mut candidates: Vec<(Entry<Platform, Upper, Lower>, OFlags)> = Vec::new();
        if let Some((entry, flags)) = initiating.as_ref() {
            candidates.push((Arc::clone(entry), *flags));
        }
        let descriptor_snapshot: Vec<_> = self
            .litebox
            .descriptor_table()
            .iter::<Self>()
            .map(|(_, descriptor)| {
                (
                    descriptor.entry.path.clone(),
                    Arc::clone(&descriptor.entry.entry),
                    descriptor.entry.flags,
                )
            })
            .collect();
        for (descriptor_path, entry, flags) in descriptor_snapshot {
            if (publish_named && descriptor_path != path)
                || candidates
                    .iter()
                    .any(|(candidate, _)| Arc::ptr_eq(candidate, &entry))
            {
                continue;
            }
            let same_lower_object = {
                let state = entry.state.lock();
                match state.as_ref().map(|state| &state.backing) {
                    Some(EntryX::Lower { fd }) => self
                        .lower
                        .fd_file_status(fd)
                        .is_ok_and(|status| status.node_info == lower_status.node_info),
                    Some(EntryX::Upper { .. }) | None => false,
                }
            };
            if same_lower_object {
                candidates.push((entry, flags));
            }
        }

        if publish_named {
            self.mkdir_migrating_ancestor_dirs(path)
                .map_err(|error| match error {
                    MkdirError::NoWritePerms | MkdirError::ReadOnlyFileSystem => {
                        MigrationError::UpperCannotHoldFile
                    }
                    MkdirError::PathError(error) => MigrationError::PathError(error),
                    MkdirError::Io | MkdirError::AlreadyExists => MigrationError::Io,
                })?;
        }
        let named_parent_leaf = if publish_named {
            Some(path.rsplit_once('/').ok_or(MigrationError::Io)?)
        } else {
            None
        };
        let staging = loop {
            let sequence = self.namespace_sequence.fetch_add(1, SeqCst);
            let candidate = if let Some((parent, leaf)) = named_parent_leaf {
                if parent.is_empty() {
                    alloc::format!("/.{leaf}.litebox-copy-up-{sequence}")
                } else {
                    alloc::format!("{parent}/.{leaf}.litebox-copy-up-{sequence}")
                }
            } else {
                alloc::format!("/.litebox-detached-copy-up-{sequence}")
            };
            if !self.root.write().copy_up_staging.insert(candidate.clone()) {
                continue;
            }
            match self
                .upper
                .file_status_as(AccessCredentials::root(), candidate.as_str())
            {
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => break candidate,
                Ok(_) => {
                    self.unregister_copy_up_staging(&candidate);
                }
                Err(FileStatusError::PathError(error)) => {
                    self.unregister_copy_up_staging(&candidate);
                    if let Some(fd) = owned_source_fd.as_ref() {
                        let _ = self.lower.close(fd);
                    }
                    return Err(error.into());
                }
                Err(FileStatusError::Io | FileStatusError::ClosedFd) => {
                    self.unregister_copy_up_staging(&candidate);
                    if let Some(fd) = owned_source_fd.as_ref() {
                        let _ = self.lower.close(fd);
                    }
                    return Err(MigrationError::Io);
                }
            }
        };

        // Holding these guards freezes source reads, close, and concurrent operations on every open
        // description until all replacement handles are prepared and publication commits.
        let mut guards: Vec<_> = candidates
            .iter()
            .map(|(entry, _)| entry.state.lock())
            .collect();
        if initiating.is_some()
            && !matches!(
                guards
                    .first()
                    .and_then(|guard| guard.as_ref())
                    .map(|state| &state.backing),
                Some(EntryX::Lower { .. })
            )
        {
            self.unregister_copy_up_staging(&staging);
            if let Some(fd) = owned_source_fd {
                let _ = self.lower.close(&fd);
            }
            return Err(MigrationError::Io);
        }

        let staging_fd = match self.upper.create_file_for_copy_up(
            &private::COPY_UP,
            staging.as_str(),
            lower_status.mode,
            lower_status.owner,
        ) {
            Ok(fd) => fd,
            Err(error) => {
                litebox_util_log::error!(
                    path:% = path,
                    staging:% = staging,
                    error:? = error;
                    "copy-up staging creation failed"
                );
                drop(guards);
                self.unregister_copy_up_staging(&staging);
                if let Some(fd) = owned_source_fd {
                    let _ = self.lower.close(&fd);
                }
                return Err(match error {
                    OpenError::AccessNotAllowed
                    | OpenError::OperationNotPermitted
                    | OpenError::NoWritePerms
                    | OpenError::ReadOnlyFileSystem => MigrationError::UpperCannotHoldFile,
                    OpenError::PathError(error) => MigrationError::PathError(error),
                    OpenError::Io
                    | OpenError::AlreadyExists
                    | OpenError::TooManySymbolicLinks
                    | OpenError::TruncateError(_)
                    | OpenError::UnsupportedFlags => MigrationError::Io,
                });
            }
        };

        let mut replacements: Vec<(usize, TypedFd<Upper>)> = Vec::new();
        let mut preparation_stage = "copy-data";
        let preparation = (|| -> Result<NodeInfo, MigrationError> {
            if copy_data {
                let mut buffer = [0u8; 16 * 1024];
                let mut copied = 0usize;
                loop {
                    preparation_stage = "source-read";
                    let read = if let Some(fd) = owned_source_fd.as_ref() {
                        self.lower
                            .read_file_for_copy_up(&private::COPY_UP, fd, &mut buffer, copied)
                    } else {
                        match guards
                            .first()
                            .and_then(|guard| guard.as_ref())
                            .map(|state| &state.backing)
                        {
                            Some(EntryX::Lower { fd }) => self.lower.read_file_for_copy_up(
                                &private::COPY_UP,
                                fd,
                                &mut buffer,
                                copied,
                            ),
                            Some(EntryX::Upper { .. }) | None => return Err(MigrationError::Io),
                        }
                    }
                    .map_err(|error| match error {
                        ReadError::NotAFile => MigrationError::NotAFile,
                        ReadError::ClosedFd | ReadError::NotForReading | ReadError::Io => {
                            MigrationError::Io
                        }
                    })?;
                    if read > buffer.len() {
                        return Err(MigrationError::Io);
                    }
                    if read == 0 {
                        break;
                    }
                    let mut written = 0usize;
                    while written < read {
                        preparation_stage = "staging-write";
                        let offset = copied.checked_add(written).ok_or(MigrationError::Io)?;
                        let count = self
                            .upper
                            .write(&staging_fd, &buffer[written..read], Some(offset))
                            .map_err(|error| match error {
                                WriteError::ReadOnlyFileSystem => {
                                    MigrationError::UpperCannotHoldFile
                                }
                                WriteError::ClosedFd
                                | WriteError::NotAFile
                                | WriteError::NotForWriting
                                | WriteError::Io => MigrationError::Io,
                            })?;
                        if count == 0 || count > read - written {
                            return Err(MigrationError::Io);
                        }
                        written = written.checked_add(count).ok_or(MigrationError::Io)?;
                    }
                    copied = copied.checked_add(read).ok_or(MigrationError::Io)?;
                }
            }

            preparation_stage = "preserve-times";
            self.upper
                .set_times_for_copy_up(
                    &private::COPY_UP,
                    &staging_fd,
                    lower_status.atime,
                    lower_status.mtime,
                    lower_status.ctime,
                )
                .map_err(|error| match error {
                    UtimeError::NoWritePerms | UtimeError::ReadOnlyFileSystem => {
                        MigrationError::UpperCannotHoldFile
                    }
                    UtimeError::PathError(error) => MigrationError::PathError(error),
                    UtimeError::Io | UtimeError::ClosedFd | UtimeError::PathOnlyFd => {
                        MigrationError::Io
                    }
                })?;
            preparation_stage = "staging-status";
            let upper_node = self
                .upper
                .fd_file_status(&staging_fd)
                .map_err(|_| MigrationError::Io)?
                .node_info;
            for (index, (_, original_flags)) in candidates.iter().enumerate() {
                let Some(state) = guards[index].as_ref() else {
                    continue;
                };
                if !matches!(state.backing, EntryX::Lower { .. }) {
                    continue;
                }
                let mut flags = *original_flags;
                flags.remove(OFlags::CREAT | OFlags::EXCL | OFlags::TRUNC);
                let seek_position = if state.position > 0 && !flags.contains(OFlags::PATH) {
                    Some(isize::try_from(state.position).map_err(|_| MigrationError::Io)?)
                } else {
                    None
                };
                preparation_stage = "replacement-open";
                let replacement = self
                    .upper
                    .open_as(
                        AccessCredentials::root(),
                        staging.as_str(),
                        flags,
                        Mode::empty(),
                    )
                    .map_err(|error| match error {
                        OpenError::AccessNotAllowed
                        | OpenError::OperationNotPermitted
                        | OpenError::NoWritePerms
                        | OpenError::ReadOnlyFileSystem => MigrationError::UpperCannotHoldFile,
                        OpenError::PathError(error) => MigrationError::PathError(error),
                        OpenError::Io
                        | OpenError::AlreadyExists
                        | OpenError::TooManySymbolicLinks
                        | OpenError::TruncateError(_)
                        | OpenError::UnsupportedFlags => MigrationError::Io,
                    })?;
                preparation_stage = "replacement-seek";
                if let Some(position) = seek_position
                    && self
                        .upper
                        .seek(&replacement, position, SeekWhence::RelativeToBeginning)
                        .is_err()
                {
                    let _ = self.upper.close(&replacement);
                    return Err(MigrationError::Io);
                }
                replacements.push((index, replacement));
            }
            Ok(upper_node)
        })();

        let upper_node = match preparation {
            Ok(node) => node,
            Err(error) => {
                litebox_util_log::error!(
                    path:% = path,
                    staging:% = staging,
                    stage:% = preparation_stage,
                    error:? = error;
                    "copy-up preparation failed"
                );
                for (_, fd) in replacements {
                    let _ = self.upper.close(&fd);
                }
                let _ = self.upper.close(&staging_fd);
                self.cleanup_regular_copy_up_staging(&staging);
                drop(guards);
                if let Some(fd) = owned_source_fd {
                    let _ = self.lower.close(&fd);
                }
                return Err(error);
            }
        };
        let _ = self.upper.close(&staging_fd);

        let lower_node_key = LayerNodeInfo::Lower(lower_status.node_info.clone());
        let upper_node_key = LayerNodeInfo::Upper(upper_node);
        let layered_id = self.node_info_lookup.read().get(&lower_node_key).copied();
        if let Some(layered_id) = layered_id
            && self
                .node_info_lookup
                .read()
                .get(&upper_node_key)
                .is_some_and(|existing| *existing != layered_id)
        {
            for (_, fd) in replacements {
                let _ = self.upper.close(&fd);
            }
            let _ = self
                .upper
                .remove_file_for_copy_up(&private::COPY_UP, staging.as_str());
            self.unregister_copy_up_staging(&staging);
            drop(guards);
            if let Some(fd) = owned_source_fd {
                let _ = self.lower.close(&fd);
            }
            return Err(MigrationError::Io);
        }
        let previous_mapping = layered_id.map(|layered_id| {
            (
                layered_id,
                self.node_info_lookup
                    .write()
                    .insert(upper_node_key.clone(), layered_id),
            )
        });

        let publication = if publish_named {
            self.upper
                .publish_file_for_copy_up(&private::COPY_UP, staging.as_str(), path)
                .map_err(|error| match error {
                    RenameError::NoWritePerms | RenameError::ReadOnlyFileSystem => {
                        MigrationError::UpperCannotHoldFile
                    }
                    RenameError::PathError(error) => MigrationError::PathError(error),
                    RenameError::Io
                    | RenameError::OperationNotPermitted
                    | RenameError::NotEmpty
                    | RenameError::IsADirectory
                    | RenameError::NotADirectory
                    | RenameError::AlreadyExists
                    | RenameError::CrossDevice
                    | RenameError::InvalidArgument => MigrationError::Io,
                })
        } else {
            self.upper
                .remove_file_for_copy_up(&private::COPY_UP, staging.as_str())
                .map_err(|error| match error {
                    UnlinkError::NoWritePerms | UnlinkError::ReadOnlyFileSystem => {
                        MigrationError::UpperCannotHoldFile
                    }
                    UnlinkError::PathError(error) => MigrationError::PathError(error),
                    UnlinkError::IsADirectory
                    | UnlinkError::OperationNotPermitted
                    | UnlinkError::Io => MigrationError::Io,
                })
        };
        if let Err(error) = publication {
            litebox_util_log::error!(
                path:% = path,
                staging:% = staging,
                publish_named = publish_named,
                error:? = error;
                "copy-up publication failed"
            );
            if let Some((_, previous)) = previous_mapping {
                let mut lookup = self.node_info_lookup.write();
                if let Some(previous) = previous {
                    lookup.insert(upper_node_key.clone(), previous);
                } else {
                    lookup.remove(&upper_node_key);
                }
            }
            for (_, fd) in replacements {
                let _ = self.upper.close(&fd);
            }
            let _ = self
                .upper
                .remove_file_for_copy_up(&private::COPY_UP, staging.as_str());
            self.unregister_copy_up_staging(&staging);
            drop(guards);
            if let Some(fd) = owned_source_fd {
                let _ = self.lower.close(&fd);
            }
            return Err(error);
        }
        self.unregister_copy_up_staging(&staging);
        if publish_named {
            self.publish_upper_nondirectory(path);
        }

        // Publication and anonymous detachment are complete; only infallible backing swaps remain.
        let mut retired_lower = Vec::new();
        for (index, replacement) in replacements {
            if let Some(state) = guards[index].as_mut() {
                let previous =
                    core::mem::replace(&mut state.backing, EntryX::Upper { fd: replacement });
                match previous {
                    EntryX::Lower { fd } => retired_lower.push(fd),
                    EntryX::Upper { fd } => {
                        // Namespace serialization makes this unreachable, but retain ownership if a
                        // backend violated the contract rather than leaking it.
                        let _ = self.upper.close(&fd);
                    }
                }
            }
        }
        drop(guards);
        for fd in retired_lower {
            let _ = self.lower.close(&fd);
        }
        if let Some(fd) = owned_source_fd {
            let _ = self.lower.close(&fd);
        }
        Ok(())
    }

    fn finish_upper_open(
        &self,
        namespace_guard: &sync::MutexGuard<'_, Platform, ()>,
        path: String,
        flags: OFlags,
        upper_fd: TypedFd<Upper>,
    ) -> Result<FileFd<Platform, Upper, Lower>, OpenError> {
        let directory = match self.upper_directory_binding_under_namespace(
            namespace_guard,
            path.as_str(),
            &upper_fd,
        ) {
            Ok(directory) => directory,
            Err(error) => {
                let _ = self.upper.close(&upper_fd);
                return Err(error);
            }
        };
        let entry = self.upper_entry(upper_fd, directory);
        Ok(self
            .litebox
            .descriptor_table_mut()
            .insert(Descriptor { path, flags, entry }))
    }

    fn finish_lower_open(
        &self,
        credentials: AccessCredentials<'_>,
        path: String,
        original_flags: OFlags,
        mode: Mode,
        lower_fd: TypedFd<Lower>,
    ) -> Result<FileFd<Platform, Upper, Lower>, OpenError> {
        // A lower open may have started before a concurrent copy-up published its
        // upper replacement. Join the namespace serialization point before exposing
        // the descriptor, then recheck upper and the tombstone while migration is
        // unable to pass its descriptor snapshot. This guarantees that every lower
        // descriptor either predates the snapshot or observes the published upper.
        let namespace_guard = self.namespace.lock();
        let exclusive_create = original_flags.contains(OFlags::CREAT | OFlags::EXCL);
        if exclusive_create {
            match self
                .upper
                .file_status_as(AccessCredentials::root(), path.as_str())
            {
                Ok(_) => {
                    let _ = self.lower.close(&lower_fd);
                    return Err(OpenError::AlreadyExists);
                }
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => {}
                Err(FileStatusError::PathError(error)) => {
                    let _ = self.lower.close(&lower_fd);
                    return Err(error.into());
                }
                Err(FileStatusError::Io | FileStatusError::ClosedFd) => {
                    let _ = self.lower.close(&lower_fd);
                    return Err(OpenError::Io);
                }
            }
        } else {
            let recheck_flags = original_flags - OFlags::CREAT;
            match self
                .upper
                .open_as(credentials, path.as_str(), recheck_flags, Mode::empty())
            {
                Ok(upper_fd) => {
                    let _ = self.lower.close(&lower_fd);
                    return self.finish_upper_open(
                        &namespace_guard,
                        path,
                        original_flags,
                        upper_fd,
                    );
                }
                Err(OpenError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => {}
                Err(error) => {
                    let _ = self.lower.close(&lower_fd);
                    return Err(error);
                }
            }
        }
        if self.path_suppresses_lower(&path) {
            let _ = self.lower.close(&lower_fd);
            if original_flags.contains(OFlags::CREAT) {
                let upper_fd =
                    match self
                        .upper
                        .open_as(credentials, path.as_str(), original_flags, mode)
                    {
                        Ok(fd) => fd,
                        Err(OpenError::PathError(PathError::MissingComponent)) => {
                            self.authorize_mutating_parent(credentials, &path)
                                .map_err(ParentAuthorizationError::into_open)?;
                            self.mkdir_migrating_ancestor_dirs(&path).map_err(
                                |error| match error {
                                    MkdirError::NoWritePerms => OpenError::NoWritePerms,
                                    MkdirError::ReadOnlyFileSystem => OpenError::ReadOnlyFileSystem,
                                    MkdirError::Io => OpenError::Io,
                                    MkdirError::PathError(error) => OpenError::PathError(error),
                                    MkdirError::AlreadyExists => OpenError::AlreadyExists,
                                },
                            )?;
                            self.upper
                                .open_as(credentials, path.as_str(), original_flags, mode)?
                        }
                        Err(error) => return Err(error),
                    };
                self.publish_upper_nondirectory(&path);
                return self.finish_upper_open(&namespace_guard, path, original_flags, upper_fd);
            }
            return Err(PathError::NoSuchFileOrDirectory.into());
        }
        if exclusive_create {
            let _ = self.lower.close(&lower_fd);
            return Err(OpenError::AlreadyExists);
        }

        // Every independent open owns a distinct lower open description. Sharing a
        // cached backend fd here aliases its access mode and seek position across
        // unrelated callers, corrupting concurrent ELF/library reads. Raw dup still
        // shares this descriptor-table entry, as required.
        let directory = match self.lower_directory_binding_under_namespace(
            &namespace_guard,
            path.as_str(),
            &lower_fd,
        ) {
            Ok(directory) => directory,
            Err(error) => {
                let _ = self.lower.close(&lower_fd);
                return Err(error);
            }
        };
        let entry = self.lower_entry(lower_fd, directory);
        Ok(self.litebox.descriptor_table_mut().insert(Descriptor {
            path,
            flags: original_flags,
            entry,
        }))
    }

    fn observe_open_error(stage: &'static str, path: &str, error: &OpenError) {
        if matches!(error, OpenError::PathError(PathError::InvalidPathname)) {
            litebox_util_log::error!(
                stage:% = stage,
                path:% = path,
                error:? = error,
                upper:% = core::any::type_name::<Upper>(),
                lower:% = core::any::type_name::<Lower>();
                "layered filesystem open failed"
            );
        }
    }

    // Gives the absolute path for `path`, resolving any `.` or `..`s, and making sure to account
    // for any relative paths from current working directory.
    //
    // Note: does NOT account for symlinks.
    fn absolute_path(&self, path: impl crate::path::Arg) -> Result<String, PathError> {
        assert!(self.current_working_dir.ends_with('/'));
        let path = path.as_rust_str()?;
        if path.starts_with('/') {
            // Absolute path
            Ok(path.normalized()?)
        } else {
            // Relative path
            Ok((self.current_working_dir.clone() + path.as_rust_str()?).normalized()?)
        }
    }

    // Converts a `NodeInfo` from any of the layers into a layered `NodeInfo`
    fn get_layered_nodeinfo(&self, node_info: NodeInfo, upper: bool) -> NodeInfo {
        let mut node_info_lookup = self.node_info_lookup.write();
        let rdev = node_info.rdev;
        let key = if upper {
            LayerNodeInfo::Upper(node_info)
        } else {
            LayerNodeInfo::Lower(node_info)
        };
        // ino starts at 1 (zero represents deleted file)
        let new_id = node_info_lookup.len() + 1;
        let ino = *node_info_lookup.entry(key).or_insert(new_id);
        NodeInfo {
            dev: DEVICE_ID,
            ino,
            rdev,
        }
    }
}

/// Possible errors when migrating a file up from lower to upper layer
#[derive(thiserror::Error, Debug)]
pub enum MigrationError {
    #[error("does not point to a file")]
    NotAFile,
    #[error("no read access permissions")]
    NoReadPerms,
    #[error("the upper layer cannot hold migrated files (e.g. it is a virtual filesystem)")]
    UpperCannotHoldFile,
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

enum ParentAuthorizationError {
    Denied,
    InvalidRoot,
    NotADirectory,
    Status(FileStatusError),
}

impl ParentAuthorizationError {
    fn into_open(self) -> OpenError {
        match self {
            Self::Denied => OpenError::NoWritePerms,
            Self::InvalidRoot => OpenError::AlreadyExists,
            Self::NotADirectory => PathError::ComponentNotADirectory.into(),
            Self::Status(FileStatusError::PathError(error)) => error.into(),
            Self::Status(FileStatusError::Io | FileStatusError::ClosedFd) => OpenError::Io,
        }
    }

    fn into_mkdir(self) -> MkdirError {
        match self {
            Self::Denied => MkdirError::NoWritePerms,
            Self::InvalidRoot => MkdirError::AlreadyExists,
            Self::NotADirectory => PathError::ComponentNotADirectory.into(),
            Self::Status(FileStatusError::PathError(error)) => error.into(),
            Self::Status(FileStatusError::Io | FileStatusError::ClosedFd) => MkdirError::Io,
        }
    }

    fn into_symlink(self) -> SymlinkError {
        match self {
            Self::Denied => SymlinkError::NoWritePerms,
            Self::InvalidRoot => SymlinkError::AlreadyExists,
            Self::NotADirectory => PathError::ComponentNotADirectory.into(),
            Self::Status(FileStatusError::PathError(error)) => error.into(),
            Self::Status(FileStatusError::Io | FileStatusError::ClosedFd) => SymlinkError::Io,
        }
    }

    fn into_unlink(self) -> UnlinkError {
        match self {
            Self::Denied => UnlinkError::NoWritePerms,
            Self::InvalidRoot => UnlinkError::IsADirectory,
            Self::NotADirectory => PathError::ComponentNotADirectory.into(),
            Self::Status(FileStatusError::PathError(error)) => error.into(),
            Self::Status(FileStatusError::Io | FileStatusError::ClosedFd) => UnlinkError::Io,
        }
    }

    fn into_rename(self) -> RenameError {
        match self {
            Self::Denied => RenameError::NoWritePerms,
            Self::InvalidRoot => RenameError::InvalidArgument,
            Self::NotADirectory => RenameError::NotADirectory,
            Self::Status(FileStatusError::PathError(error)) => error.into(),
            Self::Status(FileStatusError::Io | FileStatusError::ClosedFd) => RenameError::Io,
        }
    }

    fn into_rmdir(self) -> RmdirError {
        match self {
            Self::Denied => RmdirError::NoWritePerms,
            Self::InvalidRoot => RmdirError::Busy,
            Self::NotADirectory => RmdirError::NotADirectory,
            Self::Status(FileStatusError::PathError(error)) => error.into(),
            Self::Status(FileStatusError::Io | FileStatusError::ClosedFd) => RmdirError::Io,
        }
    }
}

enum DirectoryInspectionError {
    AccessNotAllowed,
    OperationNotPermitted,
    NoWritePerms,
    ReadOnlyFileSystem,
    NotADirectory,
    Io,
    PathError(PathError),
}

impl DirectoryInspectionError {
    fn from_file_status(error: FileStatusError) -> Self {
        match error {
            FileStatusError::PathError(error) => Self::PathError(error),
            FileStatusError::Io | FileStatusError::ClosedFd => Self::Io,
        }
    }

    fn from_open(error: OpenError) -> Self {
        match error {
            OpenError::AccessNotAllowed => Self::AccessNotAllowed,
            OpenError::OperationNotPermitted => Self::OperationNotPermitted,
            OpenError::NoWritePerms => Self::NoWritePerms,
            OpenError::ReadOnlyFileSystem => Self::ReadOnlyFileSystem,
            OpenError::PathError(PathError::ComponentNotADirectory) => Self::NotADirectory,
            OpenError::PathError(error) => Self::PathError(error),
            OpenError::Io
            | OpenError::AlreadyExists
            | OpenError::TooManySymbolicLinks
            | OpenError::TruncateError(_)
            | OpenError::UnsupportedFlags => Self::Io,
        }
    }

    fn from_read_dir(error: ReadDirError) -> Self {
        match error {
            ReadDirError::NotADirectory => Self::NotADirectory,
            ReadDirError::ClosedFd | ReadDirError::PathOnlyFd | ReadDirError::Io => Self::Io,
        }
    }

    fn into_read_dir(self) -> ReadDirError {
        match self {
            Self::NotADirectory => ReadDirError::NotADirectory,
            Self::AccessNotAllowed
            | Self::OperationNotPermitted
            | Self::NoWritePerms
            | Self::ReadOnlyFileSystem
            | Self::Io
            | Self::PathError(_) => ReadDirError::Io,
        }
    }

    fn into_rename(self) -> RenameError {
        match self {
            Self::AccessNotAllowed | Self::OperationNotPermitted | Self::NoWritePerms => {
                RenameError::NoWritePerms
            }
            Self::ReadOnlyFileSystem => RenameError::ReadOnlyFileSystem,
            Self::NotADirectory => RenameError::NotADirectory,
            Self::Io => RenameError::Io,
            Self::PathError(error) => RenameError::PathError(error),
        }
    }

    fn into_rmdir(self) -> RmdirError {
        match self {
            Self::AccessNotAllowed | Self::OperationNotPermitted | Self::NoWritePerms => {
                RmdirError::NoWritePerms
            }
            Self::ReadOnlyFileSystem => RmdirError::ReadOnlyFileSystem,
            Self::NotADirectory => RmdirError::NotADirectory,
            Self::Io => RmdirError::Io,
            Self::PathError(error) => RmdirError::PathError(error),
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider, Upper: super::FileSystem, Lower: super::FileSystem>
    super::private::Sealed for FileSystem<Platform, Upper, Lower>
{
    fn read_file_for_copy_up(
        &self,
        _token: &super::private::CopyUpToken,
        fd: &FileFd<Platform, Upper, Lower>,
        buf: &mut [u8],
        offset: usize,
    ) -> Result<usize, ReadError> {
        let entry = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| Arc::clone(&descriptor.entry.entry))
            .ok_or(ReadError::ClosedFd)?;
        let state = entry.state.lock();
        match state.as_ref().map(|state| &state.backing) {
            Some(EntryX::Upper { fd }) => {
                self.upper
                    .read_file_for_copy_up(&private::COPY_UP, fd, buf, offset)
            }
            Some(EntryX::Lower { fd }) => {
                self.lower
                    .read_file_for_copy_up(&private::COPY_UP, fd, buf, offset)
            }
            None => Err(ReadError::ClosedFd),
        }
    }
}

impl<
    Platform: sync::RawSyncPrimitivesProvider,
    Upper: super::FileSystem + 'static,
    Lower: super::FileSystem + 'static,
> super::FileSystem for FileSystem<Platform, Upper, Lower>
{
    fn open(
        &self,
        path: impl crate::path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<FileFd<Platform, Upper, Lower>, OpenError> {
        self.open_as(self.current_user.into(), path, flags, mode)
    }

    fn open_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl crate::path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<FileFd<Platform, Upper, Lower>, OpenError> {
        let flags = flags.normalized_for_open();
        let currently_supported_oflags: OFlags = OFlags::CREAT
            | OFlags::RDONLY
            | OFlags::WRONLY
            | OFlags::RDWR
            | OFlags::EXCL
            | OFlags::TRUNC
            | OFlags::NOCTTY
            | OFlags::DIRECTORY
            | OFlags::NONBLOCK
            | OFlags::LARGEFILE
            | OFlags::NOATIME
            | OFlags::NOFOLLOW
            | OFlags::APPEND
            | OFlags::PATH;
        if flags.intersects(currently_supported_oflags.complement()) {
            return Err(OpenError::UnsupportedFlags);
        }
        let path = match self.absolute_path(path) {
            Ok(path) => path,
            Err(path_error) => {
                let error = OpenError::PathError(path_error);
                Self::observe_open_error("normalize", "<unavailable>", &error);
                return Err(error);
            }
        };
        if self.path_is_copy_up_staging(&path) {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }
        if flags.contains(OFlags::NOATIME)
            && let Ok(status) = self.file_status_as(credentials, path.as_str())
            && credentials.user() != 0
            && !credentials.owns(status.owner)
        {
            return Err(OpenError::OperationNotPermitted);
        }
        // A create spans merged lookup, optional parent copy-up, upper publication, and
        // tombstone cleanup. Serialize publication, but never call `open` while retaining this
        // non-reentrant namespace mutex: mutable lower filesystems such as `/proc` can make an
        // existing path appear between the unlocked preflight and the locked recheck.
        let create_guard = if flags.contains(OFlags::CREAT) {
            if !flags.contains(OFlags::EXCL) {
                match self.open_as(credentials, path.as_str(), flags - OFlags::CREAT, mode) {
                    Ok(fd) => return Ok(fd),
                    Err(OpenError::PathError(
                        PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                    )) => {}
                    Err(error) => return Err(error),
                }
            }

            loop {
                let guard = self.namespace.lock();
                match self.file_status_as(credentials, path.as_str()) {
                    Ok(_) if flags.contains(OFlags::EXCL) => {
                        return Err(OpenError::AlreadyExists);
                    }
                    Ok(_) => {
                        drop(guard);
                        match self.open_as(credentials, path.as_str(), flags - OFlags::CREAT, mode)
                        {
                            Ok(fd) => return Ok(fd),
                            Err(OpenError::PathError(
                                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                            )) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    Err(FileStatusError::PathError(
                        PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                    )) => break Some(guard),
                    Err(FileStatusError::PathError(error)) => return Err(error.into()),
                    Err(FileStatusError::Io) => return Err(OpenError::Io),
                    Err(FileStatusError::ClosedFd) => unreachable!(),
                }
            }
        } else {
            None
        };

        // Always consult upper before a cached lower entry. An open lower descriptor is an
        // object-lifetime optimization, not namespace authority, and must never mask a newer
        // upper replacement.
        match self.upper.open_as(credentials, path.as_str(), flags, mode) {
            Ok(fd) => {
                let ordinary_guard = if create_guard.is_none() {
                    Some(self.namespace.lock())
                } else {
                    None
                };
                let namespace_guard = create_guard
                    .as_ref()
                    .or(ordinary_guard.as_ref())
                    .expect("every upper open completion holds the namespace");
                if self.path_is_copy_up_staging(&path) {
                    let _ = self.upper.close(&fd);
                    return Err(PathError::NoSuchFileOrDirectory.into());
                }
                if flags.contains(OFlags::CREAT) {
                    self.publish_upper_nondirectory(&path);
                }
                return self.finish_upper_open(namespace_guard, path, flags, fd);
            }
            Err(error) => match &error {
                OpenError::AccessNotAllowed
                | OpenError::OperationNotPermitted
                | OpenError::Io
                | OpenError::NoWritePerms
                | OpenError::ReadOnlyFileSystem
                | OpenError::AlreadyExists
                | OpenError::TooManySymbolicLinks
                | OpenError::TruncateError(
                    TruncateError::IsDirectory
                    | TruncateError::NotForWriting
                    | TruncateError::PathOnlyFd
                    | TruncateError::IsTerminalDevice
                    | TruncateError::ReadOnlyFileSystem
                    | TruncateError::ClosedFd
                    | TruncateError::Io,
                )
                | OpenError::UnsupportedFlags
                | OpenError::PathError(
                    PathError::ComponentNotADirectory
                    | PathError::InvalidPathname
                    | PathError::NoSearchPerms { .. },
                ) => {
                    Self::observe_open_error("upper", &path, &error);
                    return Err(error);
                }
                OpenError::PathError(PathError::MissingComponent)
                    if flags.contains(OFlags::CREAT) =>
                {
                    let dirname = path.rsplit_once('/').unwrap().0;
                    if let Ok(FileType::Directory) =
                        self.ensure_lower_contains_as(credentials, dirname)
                    {
                        self.authorize_mutating_parent(credentials, &path)
                            .map_err(ParentAuthorizationError::into_open)?;
                        match self.mkdir_migrating_ancestor_dirs(&path) {
                            Ok(()) => {}
                            Err(MkdirError::NoWritePerms) => return Err(OpenError::NoWritePerms),
                            Err(MkdirError::ReadOnlyFileSystem) => {
                                return Err(OpenError::ReadOnlyFileSystem);
                            }
                            Err(MkdirError::Io) => return Err(OpenError::Io),
                            Err(MkdirError::PathError(path_error)) => return Err(path_error.into()),
                            Err(MkdirError::AlreadyExists) => unreachable!(
                                "mkdir_migrating_ancestor_dirs handles existing ancestors"
                            ),
                        }
                        let fd = self
                            .upper
                            .open_as(credentials, path.as_str(), flags, mode)?;
                        self.publish_upper_nondirectory(&path);
                        return self.finish_upper_open(
                            create_guard
                                .as_ref()
                                .expect("O_CREAT holds the namespace through publication"),
                            path,
                            flags,
                            fd,
                        );
                    }
                }
                OpenError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                ) => {}
            },
        }

        // `finish_lower_open` owns the lower-publication serialization point. An `O_CREAT`
        // preflight guard that reached an upper miss must be released before that helper can
        // acquire the same non-reentrant mutex; its locked upper recheck closes the race.
        drop(create_guard);

        // Only after an upper miss may lower participate. A directory tombstone suppresses its
        // entire lower subtree, not merely the exact name.
        if self.path_suppresses_lower(&path) {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }
        // We must check the lower level, creating an independent open description if present.
        let original_flags = flags;
        let mut flags = flags;
        // Prevent creation or truncation of files at lower level
        flags.remove(OFlags::CREAT);
        flags.remove(OFlags::TRUNC);
        match self.layering_semantics {
            LayeringSemantics::LowerLayerReadOnly => {
                // Switch the lower level to read-only; the other calls will take care of
                // copying into the upper level if/when necessary.
                flags.remove(OFlags::RDWR);
                flags.remove(OFlags::WRONLY);
                flags.insert(OFlags::RDONLY);
            }
            LayeringSemantics::LowerLayerWritableFiles => {
                // Do nothing more to the flags, because we might be writing things to lower level.
                // We just make sure that there is no creation happening, that's all :)
                assert!(!flags.contains(OFlags::CREAT));
                assert!(!flags.contains(OFlags::TRUNC));
            }
        }
        // Any errors from lower level now _must_ propagate up, so we can just invoke
        // the lower level and set up the relevant descriptor upon success.
        let lower_fd = match self.layering_semantics {
            LayeringSemantics::LowerLayerReadOnly => {
                // Authorize the guest's requested access against the lower inode, but acquire the
                // physical source handle with the private root capability. A write-only owner must
                // not need read permission merely because copy-up will later read this handle.
                let status = self
                    .lower
                    .file_status_as(credentials, path.as_str())
                    .map_err(|error| match error {
                        FileStatusError::PathError(error) => OpenError::PathError(error),
                        FileStatusError::Io | FileStatusError::ClosedFd => OpenError::Io,
                    })?;
                if original_flags.contains(OFlags::DIRECTORY)
                    && status.file_type != FileType::Directory
                {
                    return Err(PathError::ComponentNotADirectory.into());
                }
                let exclusive_existing = original_flags.contains(OFlags::CREAT | OFlags::EXCL);
                if !exclusive_existing && !original_flags.contains(OFlags::PATH) {
                    let access_mode = original_flags & (OFlags::WRONLY | OFlags::RDWR);
                    let read_requested =
                        access_mode == OFlags::RDONLY || access_mode == OFlags::RDWR;
                    let write_requested =
                        access_mode == OFlags::WRONLY || access_mode == OFlags::RDWR;
                    if read_requested
                        && !dac_allows_as(
                            credentials,
                            status.owner,
                            status.mode,
                            DacAccessKind::Read,
                        )
                        || write_requested
                            && !dac_allows_as(
                                credentials,
                                status.owner,
                                status.mode,
                                DacAccessKind::Write,
                            )
                    {
                        return Err(OpenError::AccessNotAllowed);
                    }
                }
                self.lower
                    .open_as(AccessCredentials::root(), path.as_str(), flags, mode)
            }
            LayeringSemantics::LowerLayerWritableFiles => {
                self.lower.open_as(credentials, path.as_str(), flags, mode)
            }
        };
        let lower_fd = match lower_fd {
            Ok(fd) => fd,
            Err(error) => {
                Self::observe_open_error("lower", &path, &error);
                return Err(error);
            }
        };
        let fd = self.finish_lower_open(credentials, path, original_flags, mode, lower_fd)?;
        if original_flags.contains(OFlags::TRUNC) {
            // The only scenario where we need to manually trigger truncation is when a file does
            // not exist at the upper level but exists at the lower level; in that case, our
            // `truncate` functionality (at the layered FS itself) should correctly migrate things
            // over and handle them.
            match self.truncate(&fd, 0, true) {
                Ok(()) | Err(TruncateError::IsTerminalDevice) => {
                    // The terminal device is the one case we need to (due to Linux compatibility)
                    // explicitly ignore the truncation ability, and instead silently continue as if
                    // no error was thrown during truncation.
                }
                Err(e) => {
                    self.close(&fd).unwrap();
                    return Err(e.into());
                }
            }
        }
        Ok(fd)
    }

    fn close(&self, fd: &FileFd<Platform, Upper, Lower>) -> Result<(), CloseError> {
        let Some(removed_entry) = self.litebox.descriptor_table_mut().remove(fd) else {
            // Another raw descriptor still references this open description, or it was already
            // closed. In either case this slot owns no backend close.
            return Ok(());
        };
        let entry = removed_entry.entry.entry;
        let state = {
            let mut state = entry.state.lock();
            state.take()
        };
        let Some(OpenState {
            backing,
            directory,
            position: _,
        }) = state
        else {
            return Ok(());
        };
        let backing_result = match backing {
            EntryX::Upper { fd } => self.upper.close(&fd),
            EntryX::Lower { fd } => self.lower.close(&fd),
        };
        let companion_result = match directory {
            Some(DirectoryState::Upper {
                lower: Some(fd), ..
            }) => self.lower.close(&fd),
            Some(DirectoryState::Lower {
                upper: Some(fd), ..
            }) => self.upper.close(&fd),
            Some(
                DirectoryState::Upper { lower: None, .. }
                | DirectoryState::Lower { upper: None, .. },
            )
            | None => Ok(()),
        };
        backing_result.and(companion_result)
    }

    fn read(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let entry = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| {
                let access_mode = descriptor.entry.flags & (OFlags::WRONLY | OFlags::RDWR);
                if descriptor.entry.flags.contains(OFlags::PATH)
                    || (access_mode != OFlags::RDONLY && access_mode != OFlags::RDWR)
                {
                    Err(ReadError::NotForReading)
                } else {
                    Ok(Arc::clone(&descriptor.entry.entry))
                }
            })
            .ok_or(ReadError::ClosedFd)
            .flatten()?;
        let mut guard = entry.state.lock();
        let state = guard.as_mut().ok_or(ReadError::ClosedFd)?;
        let num_bytes = match &state.backing {
            EntryX::Upper { fd } => self.upper.read(fd, buf, offset)?,
            EntryX::Lower { fd } => self.lower.read(fd, buf, offset)?,
        };
        if num_bytes > buf.len() {
            return Err(ReadError::Io);
        }
        if offset.is_none() {
            state.position = state.position.checked_add(num_bytes).ok_or(ReadError::Io)?;
        }
        Ok(num_bytes)
    }

    fn write(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let (entry, path, flags) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| {
                let access_mode = descriptor.entry.flags & (OFlags::WRONLY | OFlags::RDWR);
                if descriptor.entry.flags.contains(OFlags::PATH)
                    || (access_mode != OFlags::WRONLY && access_mode != OFlags::RDWR)
                {
                    Err(WriteError::NotForWriting)
                } else {
                    Ok((
                        Arc::clone(&descriptor.entry.entry),
                        descriptor.entry.path.clone(),
                        descriptor.entry.flags,
                    ))
                }
            })
            .ok_or(WriteError::ClosedFd)
            .flatten()?;

        let mut state_guard = entry.state.lock();
        let state = state_guard.as_mut().ok_or(WriteError::ClosedFd)?;
        let write_result = match &state.backing {
            EntryX::Upper { fd } => Some(self.upper.write(fd, buf, offset)),
            EntryX::Lower { fd }
                if matches!(
                    self.layering_semantics,
                    LayeringSemantics::LowerLayerWritableFiles
                ) =>
            {
                match self.lower.write(fd, buf, offset) {
                    Err(WriteError::ReadOnlyFileSystem) => None,
                    result => Some(result),
                }
            }
            EntryX::Lower { .. } => None,
        };
        if let Some(result) = write_result {
            let written = result?;
            if written > buf.len() {
                return Err(WriteError::Io);
            }
            if offset.is_none() {
                let fallback = state.position.checked_add(written).ok_or(WriteError::Io)?;
                state.position = if flags.contains(OFlags::APPEND) {
                    match &state.backing {
                        EntryX::Upper { fd } => self
                            .upper
                            .seek(fd, 0, SeekWhence::RelativeToCurrentOffset)
                            .unwrap_or(fallback),
                        EntryX::Lower { fd } => self
                            .lower
                            .seek(fd, 0, SeekWhence::RelativeToCurrentOffset)
                            .unwrap_or(fallback),
                    }
                } else {
                    fallback
                };
            }
            return Ok(written);
        }
        drop(state_guard);

        match self.migrate_file_up(&path, true, Some(fd)) {
            Ok(()) => self.write(fd, buf, offset),
            Err(MigrationError::NotAFile) => Err(WriteError::NotAFile),
            Err(MigrationError::UpperCannotHoldFile) => Err(WriteError::ReadOnlyFileSystem),
            Err(
                MigrationError::NoReadPerms | MigrationError::Io | MigrationError::PathError(_),
            ) => Err(WriteError::Io),
        }
    }

    fn seek(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        let entry = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| {
                if descriptor.entry.flags.contains(OFlags::PATH) {
                    Err(SeekError::NotAFile)
                } else {
                    Ok(Arc::clone(&descriptor.entry.entry))
                }
            })
            .ok_or(SeekError::ClosedFd)
            .flatten()?;
        let mut guard = entry.state.lock();
        let state = guard.as_mut().ok_or(SeekError::ClosedFd)?;
        if state.directory.is_some() {
            let base = match whence {
                SeekWhence::RelativeToBeginning => 0,
                SeekWhence::RelativeToCurrentOffset => state.position,
                SeekWhence::RelativeToEnd => return Err(SeekError::InvalidOffset),
            };
            let position = base
                .checked_add_signed(offset)
                .ok_or(SeekError::InvalidOffset)?;
            if isize::try_from(position).is_err() {
                return Err(SeekError::InvalidOffset);
            }
            state.position = position;
            return Ok(position);
        }
        let position = match &state.backing {
            EntryX::Upper { fd } => self.upper.seek(fd, offset, whence)?,
            EntryX::Lower { fd } => self.lower.seek(fd, offset, whence)?,
        };
        if isize::try_from(position).is_err() {
            return Err(SeekError::InvalidOffset);
        }
        state.position = position;
        Ok(position)
    }

    fn truncate(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        let (flags, entry, path) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| {
                (
                    descriptor.entry.flags,
                    Arc::clone(&descriptor.entry.entry),
                    descriptor.entry.path.clone(),
                )
            })
            .ok_or(TruncateError::ClosedFd)?;
        if flags.contains(OFlags::PATH) {
            return Err(TruncateError::PathOnlyFd);
        }
        let access_mode = flags & (OFlags::WRONLY | OFlags::RDWR);
        if access_mode != OFlags::WRONLY && access_mode != OFlags::RDWR {
            return Err(TruncateError::NotForWriting);
        }

        let mut state_guard = entry.state.lock();
        let state = state_guard.as_mut().ok_or(TruncateError::ClosedFd)?;
        let direct_result = match &state.backing {
            EntryX::Upper { fd } => Some(self.upper.truncate(fd, length, reset_offset)),
            EntryX::Lower { fd }
                if matches!(
                    self.layering_semantics,
                    LayeringSemantics::LowerLayerWritableFiles
                ) =>
            {
                match self.lower.truncate(fd, length, reset_offset) {
                    Err(TruncateError::ReadOnlyFileSystem) => None,
                    result => Some(result),
                }
            }
            EntryX::Lower { fd } => match self.lower.fd_file_status(fd) {
                Ok(status) if status.file_type == FileType::Directory => {
                    return Err(TruncateError::IsDirectory);
                }
                Ok(status) if status.file_type == FileType::CharacterDevice => {
                    Some(self.lower.truncate(fd, length, reset_offset))
                }
                Ok(_) => None,
                Err(FileStatusError::ClosedFd) => return Err(TruncateError::ClosedFd),
                Err(FileStatusError::Io | FileStatusError::PathError(_)) => {
                    return Err(TruncateError::Io);
                }
            },
        };
        if let Some(result) = direct_result {
            result?;
            if reset_offset {
                state.position = 0;
            }
            return Ok(());
        }
        drop(state_guard);

        match self.migrate_file_up(&path, length != 0, Some(fd)) {
            Ok(()) => self.truncate(fd, length, reset_offset),
            Err(MigrationError::UpperCannotHoldFile) => Err(TruncateError::ReadOnlyFileSystem),
            Err(MigrationError::NotAFile) => Err(TruncateError::IsDirectory),
            Err(
                MigrationError::NoReadPerms | MigrationError::Io | MigrationError::PathError(_),
            ) => Err(TruncateError::Io),
        }
    }

    fn chmod(&self, path: impl crate::path::Arg, mode: Mode) -> Result<(), ChmodError> {
        self.chmod_as(self.current_user.into(), path, mode)
    }

    fn chmod_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl crate::path::Arg,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        let path = self.absolute_path(path)?;
        match self.upper.chmod_as(credentials, path.as_str(), mode) {
            Ok(()) => return Ok(()),
            Err(e) => match e {
                ChmodError::NotTheOwner
                | ChmodError::Io
                | ChmodError::ReadOnlyFileSystem
                | ChmodError::PathError(
                    PathError::ComponentNotADirectory
                    | PathError::InvalidPathname
                    | PathError::NoSearchPerms { .. },
                ) => {
                    return Err(e);
                }
                ChmodError::ClosedFd | ChmodError::PathOnlyFd => {
                    // `chmod` is path-based and never resolves through an fd, so `self.upper.chmod`
                    // (also path-based) cannot produce these fd-specific errors.
                    unreachable!()
                }
                ChmodError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                ) => {
                    // fallthrough
                }
            },
        }
        if self.path_suppresses_lower(&path) {
            return Err(ChmodError::PathError(PathError::NoSuchFileOrDirectory));
        }
        let lower_status = match self.lower.file_status_as(credentials, path.as_str()) {
            Ok(status) => status,
            Err(FileStatusError::Io) => return Err(ChmodError::Io),
            Err(FileStatusError::PathError(error)) => return Err(ChmodError::PathError(error)),
            Err(FileStatusError::ClosedFd) => unreachable!(),
        };
        if !Self::authorize_inode_owner(credentials, &lower_status) {
            return Err(ChmodError::NotTheOwner);
        }
        match self.migrate_file_up(&path, true, None) {
            Ok(()) => {}
            Err(MigrationError::UpperCannotHoldFile) => return Err(ChmodError::ReadOnlyFileSystem),
            Err(MigrationError::PathError(error)) => return Err(ChmodError::PathError(error)),
            Err(MigrationError::NoReadPerms | MigrationError::NotAFile | MigrationError::Io) => {
                return Err(ChmodError::Io);
            }
        }
        self.upper.chmod_as(credentials, path.as_str(), mode)
    }

    fn fd_chmod(&self, fd: &FileFd<Platform, Upper, Lower>, mode: Mode) -> Result<(), ChmodError> {
        self.fd_chmod_as(self.current_user.into(), fd, mode)
    }

    fn fd_chmod_as(
        &self,
        credentials: AccessCredentials<'_>,
        fd: &FileFd<Platform, Upper, Lower>,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        let (entry, path) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| {
                if descriptor.entry.flags.contains(OFlags::PATH) {
                    Err(ChmodError::PathOnlyFd)
                } else {
                    Ok((
                        Arc::clone(&descriptor.entry.entry),
                        descriptor.entry.path.clone(),
                    ))
                }
            })
            .ok_or(ChmodError::ClosedFd)
            .flatten()?;
        let state = entry.state.lock();
        match state.as_ref().map(|state| &state.backing) {
            Some(EntryX::Upper { fd }) => self.upper.fd_chmod_as(credentials, fd, mode),
            Some(EntryX::Lower { fd: lower_fd }) => {
                let status = self
                    .lower
                    .fd_file_status(lower_fd)
                    .map_err(|error| match error {
                        FileStatusError::ClosedFd => ChmodError::ClosedFd,
                        FileStatusError::PathError(error) => ChmodError::PathError(error),
                        FileStatusError::Io => ChmodError::Io,
                    })?;
                if !Self::authorize_inode_owner(credentials, &status) {
                    return Err(ChmodError::NotTheOwner);
                }
                drop(state);
                self.migrate_file_up(&path, true, Some(fd))
                    .map_err(|error| match error {
                        MigrationError::UpperCannotHoldFile => ChmodError::ReadOnlyFileSystem,
                        MigrationError::PathError(error) => ChmodError::PathError(error),
                        MigrationError::NoReadPerms
                        | MigrationError::NotAFile
                        | MigrationError::Io => ChmodError::Io,
                    })?;
                self.fd_chmod_as(credentials, fd, mode)
            }
            None => Err(ChmodError::ClosedFd),
        }
    }

    fn chown(
        &self,
        path: impl crate::path::Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        self.chown_as(self.current_user.into(), path, user, group)
    }

    fn chown_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl crate::path::Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = self.absolute_path(path)?;
        match self.upper.chown_as(credentials, path.as_str(), user, group) {
            Ok(()) => return Ok(()),
            Err(e) => match e {
                ChownError::NotTheOwner
                | ChownError::Io
                | ChownError::ReadOnlyFileSystem
                // `ClosedFd`/`PathOnlyFd` are only produced by `fd_chown`, never by this
                // path-based `chown`, but the match must be exhaustive over the enum.
                | ChownError::ClosedFd
                | ChownError::PathOnlyFd
                | ChownError::PathError(
                    PathError::ComponentNotADirectory
                    | PathError::InvalidPathname
                    | PathError::NoSearchPerms { .. },
                ) => {
                    return Err(e);
                }
                ChownError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                ) => {
                    // fallthrough
                }
            },
        }
        if self.path_suppresses_lower(&path) {
            return Err(ChownError::PathError(PathError::NoSuchFileOrDirectory));
        }
        let lower_status = match self.lower.file_status_as(credentials, path.as_str()) {
            Ok(status) => status,
            Err(FileStatusError::Io) => return Err(ChownError::Io),
            Err(FileStatusError::PathError(error)) => return Err(ChownError::PathError(error)),
            Err(FileStatusError::ClosedFd) => unreachable!(),
        };
        if !Self::authorize_chown(credentials, &lower_status, user, group) {
            return Err(ChownError::NotTheOwner);
        }
        match self.migrate_file_up(&path, true, None) {
            Ok(()) => {}
            Err(MigrationError::UpperCannotHoldFile) => return Err(ChownError::ReadOnlyFileSystem),
            Err(MigrationError::PathError(error)) => return Err(ChownError::PathError(error)),
            Err(MigrationError::NoReadPerms | MigrationError::NotAFile | MigrationError::Io) => {
                return Err(ChownError::Io);
            }
        }
        self.upper.chown_as(credentials, path.as_str(), user, group)
    }

    fn fd_chown(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        self.fd_chown_as(self.current_user.into(), fd, user, group)
    }

    fn fd_chown_as(
        &self,
        credentials: AccessCredentials<'_>,
        fd: &FileFd<Platform, Upper, Lower>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let (entry, path) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| {
                if descriptor.entry.flags.contains(OFlags::PATH) {
                    Err(ChownError::PathOnlyFd)
                } else {
                    Ok((
                        Arc::clone(&descriptor.entry.entry),
                        descriptor.entry.path.clone(),
                    ))
                }
            })
            .ok_or(ChownError::ClosedFd)
            .flatten()?;
        let state = entry.state.lock();
        match state.as_ref().map(|state| &state.backing) {
            Some(EntryX::Upper { fd }) => self.upper.fd_chown_as(credentials, fd, user, group),
            Some(EntryX::Lower { fd: lower_fd }) => {
                let status = self
                    .lower
                    .fd_file_status(lower_fd)
                    .map_err(|error| match error {
                        FileStatusError::ClosedFd => ChownError::ClosedFd,
                        FileStatusError::PathError(error) => ChownError::PathError(error),
                        FileStatusError::Io => ChownError::Io,
                    })?;
                if !Self::authorize_chown(credentials, &status, user, group) {
                    return Err(ChownError::NotTheOwner);
                }
                drop(state);
                self.migrate_file_up(&path, true, Some(fd))
                    .map_err(|error| match error {
                        MigrationError::UpperCannotHoldFile => ChownError::ReadOnlyFileSystem,
                        MigrationError::PathError(error) => ChownError::PathError(error),
                        MigrationError::NoReadPerms
                        | MigrationError::NotAFile
                        | MigrationError::Io => ChownError::Io,
                    })?;
                self.fd_chown_as(credentials, fd, user, group)
            }
            None => Err(ChownError::ClosedFd),
        }
    }

    fn utimensat(
        &self,
        path: impl crate::path::Arg,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        self.utimensat_as(self.current_user.into(), path, atime, mtime)
    }

    fn utimensat_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl crate::path::Arg,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        let path = self.absolute_path(path)?;
        match self
            .upper
            .utimensat_as(credentials, path.as_str(), atime, mtime)
        {
            Ok(()) => return Ok(()),
            Err(e) => match e {
                UtimeError::NoWritePerms
                | UtimeError::Io
                | UtimeError::ReadOnlyFileSystem
                | UtimeError::PathError(
                    PathError::ComponentNotADirectory
                    | PathError::InvalidPathname
                    | PathError::NoSearchPerms { .. },
                ) => {
                    return Err(e);
                }
                UtimeError::ClosedFd | UtimeError::PathOnlyFd => {
                    // `utimensat` is path-based and never resolves through an fd, so
                    // `self.upper.utimensat` (also path-based) cannot produce these fd-specific
                    // errors.
                    unreachable!()
                }
                UtimeError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                ) => {
                    // fallthrough
                }
            },
        }
        if self.path_suppresses_lower(&path) {
            return Err(UtimeError::PathError(PathError::NoSuchFileOrDirectory));
        }
        let lower_status = match self.lower.file_status_as(credentials, path.as_str()) {
            Ok(status) => status,
            Err(FileStatusError::Io) => return Err(UtimeError::Io),
            Err(FileStatusError::PathError(error)) => return Err(UtimeError::PathError(error)),
            Err(FileStatusError::ClosedFd) => unreachable!(),
        };
        if !Self::authorize_inode_owner(credentials, &lower_status) {
            return Err(UtimeError::NoWritePerms);
        }
        match self.migrate_file_up(&path, true, None) {
            Ok(()) => {}
            Err(MigrationError::UpperCannotHoldFile) => return Err(UtimeError::ReadOnlyFileSystem),
            Err(MigrationError::PathError(error)) => return Err(UtimeError::PathError(error)),
            Err(MigrationError::NoReadPerms | MigrationError::NotAFile | MigrationError::Io) => {
                return Err(UtimeError::Io);
            }
        }
        self.upper
            .utimensat_as(credentials, path.as_str(), atime, mtime)
    }

    fn fd_utimensat(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        self.fd_utimensat_as(self.current_user.into(), fd, atime, mtime)
    }

    fn fd_utimensat_as(
        &self,
        credentials: AccessCredentials<'_>,
        fd: &FileFd<Platform, Upper, Lower>,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        let (entry, path) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| {
                if descriptor.entry.flags.contains(OFlags::PATH) {
                    Err(UtimeError::PathOnlyFd)
                } else {
                    Ok((
                        Arc::clone(&descriptor.entry.entry),
                        descriptor.entry.path.clone(),
                    ))
                }
            })
            .ok_or(UtimeError::ClosedFd)
            .flatten()?;
        let state = entry.state.lock();
        match state.as_ref().map(|state| &state.backing) {
            Some(EntryX::Upper { fd }) => self.upper.fd_utimensat_as(credentials, fd, atime, mtime),
            Some(EntryX::Lower { fd: lower_fd }) => {
                let status = self
                    .lower
                    .fd_file_status(lower_fd)
                    .map_err(|error| match error {
                        FileStatusError::ClosedFd => UtimeError::ClosedFd,
                        FileStatusError::PathError(error) => UtimeError::PathError(error),
                        FileStatusError::Io => UtimeError::Io,
                    })?;
                if !Self::authorize_inode_owner(credentials, &status) {
                    return Err(UtimeError::NoWritePerms);
                }
                drop(state);
                self.migrate_file_up(&path, true, Some(fd))
                    .map_err(|error| match error {
                        MigrationError::UpperCannotHoldFile => UtimeError::ReadOnlyFileSystem,
                        MigrationError::PathError(error) => UtimeError::PathError(error),
                        MigrationError::NoReadPerms
                        | MigrationError::NotAFile
                        | MigrationError::Io => UtimeError::Io,
                    })?;
                self.fd_utimensat_as(credentials, fd, atime, mtime)
            }
            None => Err(UtimeError::ClosedFd),
        }
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), UnlinkError> {
        self.unlink_as(self.current_user.into(), path)
    }

    fn unlink_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl crate::path::Arg,
    ) -> Result<(), UnlinkError> {
        let path = self.absolute_path(path)?;
        let _namespace_guard = self.namespace.lock();

        let upper_status = match self.upper.file_status_as(credentials, path.as_str()) {
            Ok(status) => Some(status),
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => None,
            Err(FileStatusError::PathError(error)) => return Err(error.into()),
            Err(FileStatusError::Io) => return Err(UnlinkError::Io),
            Err(FileStatusError::ClosedFd) => unreachable!(),
        };
        let lower_status = if self.path_suppresses_lower(&path) {
            None
        } else {
            match self.lower.file_status_as(credentials, path.as_str()) {
                Ok(status) => Some(status),
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => None,
                Err(FileStatusError::PathError(error)) => return Err(error.into()),
                Err(FileStatusError::Io) => return Err(UnlinkError::Io),
                Err(FileStatusError::ClosedFd) => unreachable!(),
            }
        };

        let victim_status = upper_status
            .as_ref()
            .or(lower_status.as_ref())
            .ok_or(UnlinkError::PathError(PathError::NoSuchFileOrDirectory))?;
        if victim_status.file_type == FileType::Directory {
            return Err(UnlinkError::IsADirectory);
        }
        let parent_status = self
            .authorize_mutating_parent(credentials, &path)
            .map_err(ParentAuthorizationError::into_unlink)?;
        if !sticky_directory_allows_removal(
            credentials,
            parent_status.owner,
            parent_status.mode,
            victim_status.owner,
        ) {
            return Err(UnlinkError::OperationNotPermitted);
        }

        if upper_status.is_some() {
            // Install the whiteout before removing upper so a lower node can never briefly
            // resurface. Upper-first lookup keeps it invisible while upper still exists. If the
            // backend removal fails, restore the exact cache/tombstone state we replaced.
            let previous_root_state = lower_status
                .as_ref()
                .map(|_| self.root.write().publish_tombstone(&path));
            match self
                .upper
                .unlink_as(AccessCredentials::root(), path.as_str())
            {
                Ok(()) => {
                    self.root
                        .write()
                        .publish_removed_path(&path, lower_status.is_some());
                    Ok(())
                }
                Err(error) => {
                    if let Some(previous_root_state) = previous_root_state {
                        self.root.write().restore_path(&path, previous_root_state);
                    }
                    Err(error)
                }
            }
        } else {
            if self.path_suppresses_lower(&path) {
                return Err(PathError::NoSuchFileOrDirectory.into());
            }
            match lower_status {
                Some(FileStatus {
                    file_type: FileType::Directory,
                    ..
                }) => Err(UnlinkError::IsADirectory),
                Some(_) => {
                    self.root.write().publish_removed_path(&path, true);
                    Ok(())
                }
                None => Err(PathError::NoSuchFileOrDirectory.into()),
            }
        }
    }

    fn rename(
        &self,
        oldpath: impl crate::path::Arg,
        newpath: impl crate::path::Arg,
        noreplace: bool,
    ) -> Result<(), RenameError> {
        self.rename_as(self.current_user.into(), oldpath, newpath, noreplace)
    }

    fn rename_as(
        &self,
        credentials: AccessCredentials<'_>,
        oldpath: impl crate::path::Arg,
        newpath: impl crate::path::Arg,
        noreplace: bool,
    ) -> Result<(), RenameError> {
        let old = self.absolute_path(oldpath)?;
        let new = self.absolute_path(newpath)?;
        let namespace_guard = self.namespace.lock();

        let source_status = match self.file_status_as(credentials, old.as_str()) {
            Ok(status) => status,
            Err(FileStatusError::PathError(error)) => return Err(error.into()),
            Err(FileStatusError::Io) => return Err(RenameError::Io),
            Err(FileStatusError::ClosedFd) => unreachable!(),
        };
        if old == new {
            return Ok(());
        }

        let destination_status = match self.file_status_as(credentials, new.as_str()) {
            Ok(status) => Some(status),
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => None,
            Err(FileStatusError::PathError(error)) => return Err(error.into()),
            Err(FileStatusError::Io) => return Err(RenameError::Io),
            Err(FileStatusError::ClosedFd) => unreachable!(),
        };
        let source_parent = self
            .authorize_mutating_parent(credentials, &old)
            .map_err(ParentAuthorizationError::into_rename)?;
        let destination_parent = self
            .authorize_mutating_parent(credentials, &new)
            .map_err(ParentAuthorizationError::into_rename)?;
        if !sticky_directory_allows_removal(
            credentials,
            source_parent.owner,
            source_parent.mode,
            source_status.owner,
        ) {
            return Err(RenameError::OperationNotPermitted);
        }
        if let Some(destination_status) = destination_status.as_ref()
            && !sticky_directory_allows_removal(
                credentials,
                destination_parent.owner,
                destination_parent.mode,
                destination_status.owner,
            )
        {
            return Err(RenameError::OperationNotPermitted);
        }

        if noreplace && destination_status.is_some() {
            return Err(RenameError::AlreadyExists);
        }
        if let Some(destination_status) = destination_status.as_ref() {
            let source_is_directory = source_status.file_type == FileType::Directory;
            let destination_is_directory = destination_status.file_type == FileType::Directory;
            match (source_is_directory, destination_is_directory) {
                (true, true) => {
                    if self
                        .directory_has_visible_children_under_namespace(&namespace_guard, &new)
                        .map_err(DirectoryInspectionError::into_rename)?
                    {
                        return Err(RenameError::NotEmpty);
                    }
                }
                (true, false) => return Err(RenameError::NotADirectory),
                (false, true) => return Err(RenameError::IsADirectory),
                (false, false) => {}
            }
        }

        let upper_source = match self
            .upper
            .file_status_as(AccessCredentials::root(), old.as_str())
        {
            Ok(status) => Some(status),
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => None,
            Err(FileStatusError::PathError(error)) => return Err(error.into()),
            Err(FileStatusError::Io) => return Err(RenameError::Io),
            Err(FileStatusError::ClosedFd) => unreachable!(),
        };
        let lower_source = match self
            .lower
            .file_status_as(AccessCredentials::root(), old.as_str())
        {
            Ok(status) => Some(status),
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => None,
            Err(FileStatusError::PathError(error)) => return Err(error.into()),
            Err(FileStatusError::Io) => return Err(RenameError::Io),
            Err(FileStatusError::ClosedFd) => unreachable!(),
        };

        if upper_source.is_some() {
            let lower_source_exists = lower_source.is_some();
            if source_status.file_type == FileType::Directory {
                let (source_effectively_opaque, destination_already_suppressed) = {
                    let root = self.root.read();
                    (root.suppresses_lower(&old), root.suppresses_lower(&new))
                };
                if !source_effectively_opaque
                    && lower_source
                        .as_ref()
                        .is_some_and(|status| status.file_type == FileType::Directory)
                {
                    return Err(RenameError::CrossDevice);
                }
                let lower_destination = self
                    .lower_path_status(&new)
                    .map_err(DirectoryInspectionError::into_rename)?;
                let destination_opaque = source_effectively_opaque
                    || destination_already_suppressed
                    || lower_destination.is_some();
                self.mkdir_migrating_ancestor_dirs_for_rename(&new)?;
                let (previous_source_state, previous_destination_state) = {
                    let mut root = self.root.write();
                    let source = lower_source_exists.then(|| root.publish_tombstone(&old));
                    let destination = destination_opaque.then(|| root.publish_opaque(&new));
                    (source, destination)
                };
                match self.upper.rename_as(
                    AccessCredentials::root(),
                    old.as_str(),
                    new.as_str(),
                    noreplace,
                ) {
                    Ok(()) => {
                        self.root.write().publish_renamed_directory(
                            &old,
                            &new,
                            lower_source_exists,
                            destination_opaque,
                        );
                        Ok(())
                    }
                    Err(error) => {
                        let mut root = self.root.write();
                        if let Some(previous_source_state) = previous_source_state {
                            root.restore_path(&old, previous_source_state);
                        }
                        if let Some(previous_destination_state) = previous_destination_state {
                            root.restore_path(&new, previous_destination_state);
                        }
                        Err(error)
                    }
                }
            } else {
                self.mkdir_migrating_ancestor_dirs_for_rename(&new)?;
                // Whiteout the lower source before upper removes its namesake, preventing even a brief
                // resurfacing window. Restore the exact previous cache state if the atomic backend
                // rename fails.
                let previous_root_state = lower_source
                    .as_ref()
                    .map(|_| self.root.write().publish_tombstone(&old));
                match self.upper.rename_as(
                    AccessCredentials::root(),
                    old.as_str(),
                    new.as_str(),
                    noreplace,
                ) {
                    Ok(()) => {
                        self.root.write().publish_renamed_nondirectory(
                            &old,
                            &new,
                            lower_source_exists,
                        );
                        Ok(())
                    }
                    Err(error) => {
                        if let Some(previous_root_state) = previous_root_state {
                            self.root.write().restore_path(&old, previous_root_state);
                        }
                        Err(error)
                    }
                }
            }
        } else {
            let lower_source =
                lower_source.ok_or(RenameError::PathError(PathError::NoSuchFileOrDirectory))?;
            if !matches!(
                lower_source.file_type,
                FileType::RegularFile | FileType::SymLink
            ) {
                return Err(RenameError::CrossDevice);
            }
            self.mkdir_migrating_ancestor_dirs_for_rename(&new)?;

            if lower_source.file_type == FileType::RegularFile {
                self.migrate_file_up_under_namespace(&namespace_guard, old.as_str(), true, None)
                    .map_err(|error| match error {
                        MigrationError::UpperCannotHoldFile => RenameError::ReadOnlyFileSystem,
                        MigrationError::PathError(error) => RenameError::PathError(error),
                        MigrationError::NoReadPerms
                        | MigrationError::NotAFile
                        | MigrationError::Io => RenameError::Io,
                    })?;

                // Copy-up retained the source inode mapping and rebound every open description.
                // Whiteout lower before the physical upper rename, rolling it back if publication
                // fails so no denied rename changes the merged namespace.
                let previous_source_state = self.root.write().publish_tombstone(&old);
                return match self.upper.rename_as(
                    AccessCredentials::root(),
                    old.as_str(),
                    new.as_str(),
                    noreplace,
                ) {
                    Ok(()) => {
                        self.root
                            .write()
                            .publish_renamed_nondirectory(&old, &new, true);
                        Ok(())
                    }
                    Err(error) => {
                        self.root.write().restore_path(&old, previous_source_state);
                        Err(error)
                    }
                };
            }

            let sequence = self.namespace_sequence.fetch_add(1, SeqCst);
            let (parent, leaf) = new.rsplit_once('/').unwrap();
            let staging = if parent.is_empty() {
                alloc::format!("/.{leaf}.litebox-rename-{sequence}")
            } else {
                alloc::format!("{parent}/.{leaf}.litebox-rename-{sequence}")
            };
            if !self.root.write().copy_up_staging.insert(staging.clone()) {
                return Err(RenameError::Io);
            }

            let target = self
                .lower
                .readlink_as(AccessCredentials::root(), old.as_str())
                .map_err(|error| match error {
                    ReadlinkError::PathError(error) => RenameError::PathError(error),
                    ReadlinkError::Io | ReadlinkError::NotASymlink => RenameError::Io,
                });
            let prepare = target.and_then(|target| {
                self.upper
                    .symlink_as(AccessCredentials::root(), target.as_str(), staging.as_str())
                    .map_err(|error| match error {
                        SymlinkError::NoWritePerms => RenameError::NoWritePerms,
                        SymlinkError::ReadOnlyFileSystem => RenameError::ReadOnlyFileSystem,
                        SymlinkError::AlreadyExists => RenameError::AlreadyExists,
                        SymlinkError::Io => RenameError::Io,
                        SymlinkError::PathError(error) => RenameError::PathError(error),
                    })?;
                self.upper
                    .chown_as(
                        AccessCredentials::root(),
                        staging.as_str(),
                        Some(lower_source.owner.user),
                        Some(lower_source.owner.group),
                    )
                    .map_err(|error| match error {
                        ChownError::ReadOnlyFileSystem => RenameError::ReadOnlyFileSystem,
                        ChownError::PathError(error) => RenameError::PathError(error),
                        ChownError::NotTheOwner
                        | ChownError::ClosedFd
                        | ChownError::PathOnlyFd
                        | ChownError::Io => RenameError::Io,
                    })?;
                self.upper
                    .utimensat_as(
                        AccessCredentials::root(),
                        staging.as_str(),
                        Some(lower_source.atime),
                        Some(lower_source.mtime),
                    )
                    .map_err(|error| match error {
                        UtimeError::ReadOnlyFileSystem => RenameError::ReadOnlyFileSystem,
                        UtimeError::PathError(error) => RenameError::PathError(error),
                        UtimeError::NoWritePerms
                        | UtimeError::ClosedFd
                        | UtimeError::PathOnlyFd
                        | UtimeError::Io => RenameError::Io,
                    })
            });
            if let Err(error) = prepare {
                self.cleanup_symlink_copy_up_staging(&staging);
                return Err(error);
            }

            if let Err(error) = self.upper.rename_as(
                AccessCredentials::root(),
                staging.as_str(),
                new.as_str(),
                noreplace,
            ) {
                self.cleanup_symlink_copy_up_staging(&staging);
                return Err(error);
            }
            self.unregister_copy_up_staging(&staging);
            self.root
                .write()
                .publish_renamed_nondirectory(&old, &new, true);
            Ok(())
        }
    }

    fn mkdir(&self, path: impl crate::path::Arg, mode: Mode) -> Result<(), MkdirError> {
        self.mkdir_as(self.current_user.into(), path, mode)
    }

    fn mkdir_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl crate::path::Arg,
        mode: Mode,
    ) -> Result<(), MkdirError> {
        let path = self.absolute_path(path)?;
        let _namespace_guard = self.namespace.lock();
        let new_directory_opaque = self.root.read().suppresses_lower(&path);
        let ensure_absent = || -> Result<(), MkdirError> {
            match self.file_status_as(credentials, path.as_str()) {
                Ok(_) => Err(MkdirError::AlreadyExists),
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => Ok(()),
                Err(FileStatusError::PathError(error)) => Err(MkdirError::PathError(error)),
                Err(FileStatusError::Io) => Err(MkdirError::Io),
                Err(FileStatusError::ClosedFd) => unreachable!(),
            }
        };

        // Every failure-prone merged-namespace check happens before publication. In
        // particular, never create in upper and only then discover a lower collision.
        ensure_absent()?;
        self.authorize_mutating_parent(credentials, &path)
            .map_err(ParentAuthorizationError::into_mkdir)?;
        let result = match self.upper.mkdir_as(credentials, path.as_str(), mode) {
            Ok(()) => Ok(()),
            Err(MkdirError::PathError(PathError::MissingComponent)) => {
                self.mkdir_migrating_ancestor_dirs(&path)?;
                // Ancestor migration is allowed to expose a concurrent destination; recheck
                // before the only operation that publishes the leaf.
                ensure_absent()?;
                self.upper.mkdir_as(credentials, path.as_str(), mode)
            }
            Err(error) => Err(error),
        };
        if result.is_ok() {
            self.root
                .write()
                .publish_new_directory(&path, new_directory_opaque);
        }
        result
    }

    fn symlink(&self, target: &str, linkpath: impl crate::path::Arg) -> Result<(), SymlinkError> {
        self.symlink_as(self.current_user.into(), target, linkpath)
    }

    fn symlink_as(
        &self,
        credentials: AccessCredentials<'_>,
        target: &str,
        linkpath: impl crate::path::Arg,
    ) -> Result<(), SymlinkError> {
        let path = self.absolute_path(linkpath)?;
        let _namespace_guard = self.namespace.lock();
        let ensure_absent = || -> Result<(), SymlinkError> {
            match self.file_status_as(credentials, path.as_str()) {
                Ok(_) => Err(SymlinkError::AlreadyExists),
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => Ok(()),
                Err(FileStatusError::PathError(error)) => Err(SymlinkError::PathError(error)),
                Err(FileStatusError::Io) => Err(SymlinkError::Io),
                Err(FileStatusError::ClosedFd) => unreachable!(),
            }
        };

        // `EEXIST` must be observationally side-effect-free across the merged namespace.
        // The old implementation published the upper link first, then returned EEXIST after
        // discovering the lower node -- exactly what corrupted `/bin/sleep` during APK's
        // BusyBox trigger.
        ensure_absent()?;
        self.authorize_mutating_parent(credentials, &path)
            .map_err(ParentAuthorizationError::into_symlink)?;
        let result = match self.upper.symlink_as(credentials, target, path.as_str()) {
            Ok(()) => Ok(()),
            Err(SymlinkError::PathError(PathError::MissingComponent)) => {
                self.mkdir_migrating_ancestor_dirs(&path)
                    .map_err(|error| match error {
                        MkdirError::NoWritePerms => SymlinkError::NoWritePerms,
                        MkdirError::ReadOnlyFileSystem => SymlinkError::ReadOnlyFileSystem,
                        MkdirError::Io => SymlinkError::Io,
                        MkdirError::AlreadyExists => SymlinkError::AlreadyExists,
                        MkdirError::PathError(error) => SymlinkError::PathError(error),
                    })?;
                ensure_absent()?;
                self.upper.symlink_as(credentials, target, path.as_str())
            }
            Err(error) => Err(error),
        };
        if result.is_ok() {
            self.publish_upper_nondirectory(&path);
        }
        result
    }

    fn readlink(&self, path: impl crate::path::Arg) -> Result<String, ReadlinkError> {
        self.readlink_as(self.current_user.into(), path)
    }

    fn readlink_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl crate::path::Arg,
    ) -> Result<String, ReadlinkError> {
        // A fresh upper node always wins. A tombstone suppresses only lower fallback;
        // it must not hide an upper node and must not allow a deleted lower link to resurface.
        let path = self.absolute_path(path)?;
        if self.path_is_copy_up_staging(&path) {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }
        let upper_result = self.upper.readlink_as(credentials, path.as_str());
        if self.path_is_copy_up_staging(&path) {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }
        match upper_result {
            Err(ReadlinkError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => {
                if self.path_suppresses_lower(&path) {
                    Err(PathError::NoSuchFileOrDirectory.into())
                } else {
                    self.lower.readlink_as(credentials, path.as_str())
                }
            }
            other => other,
        }
    }

    fn rmdir(&self, path: impl crate::path::Arg) -> Result<(), RmdirError> {
        self.rmdir_as(self.current_user.into(), path)
    }

    fn rmdir_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl crate::path::Arg,
    ) -> Result<(), RmdirError> {
        let path = self.absolute_path(path)?;
        let namespace_guard = self.namespace.lock();

        if path == "/" {
            return Err(RmdirError::Busy);
        }
        let status = match self.file_status_as(credentials, path.as_str()) {
            Ok(status) => status,
            Err(FileStatusError::PathError(error)) => return Err(error.into()),
            Err(FileStatusError::Io) => return Err(RmdirError::Io),
            Err(FileStatusError::ClosedFd) => unreachable!(),
        };
        if status.file_type != FileType::Directory {
            return Err(RmdirError::NotADirectory);
        }
        let parent_status = self
            .authorize_mutating_parent(credentials, &path)
            .map_err(ParentAuthorizationError::into_rmdir)?;
        if !sticky_directory_allows_removal(
            credentials,
            parent_status.owner,
            parent_status.mode,
            status.owner,
        ) {
            return Err(RmdirError::OperationNotPermitted);
        }
        if self
            .directory_has_visible_children_under_namespace(&namespace_guard, &path)
            .map_err(DirectoryInspectionError::into_rmdir)?
        {
            return Err(RmdirError::NotEmpty);
        }

        let upper_exists = match self
            .upper
            .file_status_as(AccessCredentials::root(), path.as_str())
        {
            Ok(_) => true,
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => false,
            Err(FileStatusError::PathError(error)) => return Err(error.into()),
            Err(FileStatusError::Io) => return Err(RmdirError::Io),
            Err(FileStatusError::ClosedFd) => unreachable!(),
        };
        let lower_exists = match self
            .lower
            .file_status_as(AccessCredentials::root(), path.as_str())
        {
            Ok(_) => true,
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => false,
            Err(FileStatusError::PathError(error)) => return Err(error.into()),
            Err(FileStatusError::Io) => return Err(RmdirError::Io),
            Err(FileStatusError::ClosedFd) => unreachable!(),
        };

        if !upper_exists {
            debug_assert!(lower_exists);
            self.root.write().publish_removed_path(&path, true);
            return Ok(());
        }

        // Stage the lower whiteout before removing upper so a lower directory (and its subtree)
        // never resurfaces between the two halves of the merged operation.
        let previous_root_state = lower_exists.then(|| self.root.write().publish_tombstone(&path));
        match self
            .upper
            .rmdir_as(AccessCredentials::root(), path.as_str())
        {
            Ok(()) => {
                self.root.write().publish_removed_path(&path, lower_exists);
                Ok(())
            }
            Err(error) => {
                if let Some(previous_root_state) = previous_root_state {
                    self.root.write().restore_path(&path, previous_root_state);
                }
                Err(error)
            }
        }
    }

    fn read_dir(&self, fd: &FileFd<Platform, Upper, Lower>) -> Result<Vec<DirEntry>, ReadDirError> {
        let (entry, path_only) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| {
                (
                    Arc::clone(&descriptor.entry.entry),
                    descriptor.entry.flags.contains(OFlags::PATH),
                )
            })
            .ok_or(ReadDirError::ClosedFd)?;
        if path_only {
            return Err(ReadDirError::PathOnlyFd);
        }

        // Keep one namespace/staging epoch across mandatory enumeration, companion acquisition,
        // companion enumeration, and whiteout/opacity filtering. The OFD guard protects held
        // backend handles, but is deliberately dropped before an opposite-layer `open`: backend
        // opens publish into the global descriptor table and must never run under an OFD lock.
        let namespace_guard = self.namespace.lock();
        let (
            mandatory_is_upper,
            mut upper_entries,
            mut lower_entries,
            binding,
            companion_is_attached,
        ) = {
            let state = entry.state.lock();
            let state = state.as_ref().ok_or(ReadDirError::ClosedFd)?;
            match (&state.backing, state.directory.as_ref()) {
                (EntryX::Upper { fd }, Some(DirectoryState::Upper { binding, lower })) => (
                    true,
                    self.upper.read_dir(fd)?,
                    match lower {
                        Some(fd) => self.lower.read_dir(fd)?,
                        None => Vec::new(),
                    },
                    binding.clone(),
                    lower.is_some(),
                ),
                (EntryX::Lower { fd }, Some(DirectoryState::Lower { binding, upper })) => (
                    false,
                    match upper {
                        Some(fd) => self.upper.read_dir(fd)?,
                        None => Vec::new(),
                    },
                    self.lower.read_dir(fd)?,
                    binding.clone(),
                    upper.is_some(),
                ),
                (EntryX::Upper { .. } | EntryX::Lower { .. }, None) => {
                    return Err(ReadDirError::NotADirectory);
                }
                _ => return Err(ReadDirError::Io),
            }
        };

        let binding_is_current =
            self.directory_binding_is_current_under_namespace(&namespace_guard, &binding)?;
        let current_path = match (&binding, binding_is_current) {
            (DirectoryBinding::Current { path, .. }, true) => Some(path.as_str()),
            (DirectoryBinding::Current { .. } | DirectoryBinding::Detached, false) => None,
            (DirectoryBinding::Detached, true) => return Err(ReadDirError::Io),
        };

        if !companion_is_attached && let Some(path) = current_path {
            if mandatory_is_upper {
                if !self.root.read().suppresses_lower(path)
                    && let Some(optional_fd) =
                        self.open_optional_lower_directory_under_namespace(&namespace_guard, path)?
                {
                    let mut optional_fd = Some(optional_fd);
                    let read_result = {
                        let mut state = entry.state.lock();
                        match state.as_mut() {
                            Some(OpenState {
                                backing: EntryX::Upper { .. },
                                directory:
                                    Some(DirectoryState::Upper {
                                        binding: installed_binding,
                                        lower,
                                    }),
                                position: _,
                            }) if *installed_binding == binding => {
                                if lower.is_none() {
                                    *lower = optional_fd.take();
                                }
                                match lower.as_ref() {
                                    Some(fd) => self.lower.read_dir(fd),
                                    None => Err(ReadDirError::ClosedFd),
                                }
                            }
                            Some(_) => Err(ReadDirError::Io),
                            None => Err(ReadDirError::ClosedFd),
                        }
                    };
                    if let Some(optional_fd) = optional_fd
                        && self.lower.close(&optional_fd).is_err()
                    {
                        return Err(ReadDirError::Io);
                    }
                    lower_entries = read_result?;
                }
            } else if let Some(optional_fd) =
                self.open_optional_upper_directory_under_namespace(&namespace_guard, path)?
            {
                let mut optional_fd = Some(optional_fd);
                let read_result = {
                    let mut state = entry.state.lock();
                    match state.as_mut() {
                        Some(OpenState {
                            backing: EntryX::Lower { .. },
                            directory:
                                Some(DirectoryState::Lower {
                                    binding: installed_binding,
                                    upper,
                                }),
                            position: _,
                        }) if *installed_binding == binding => {
                            if upper.is_none() {
                                *upper = optional_fd.take();
                            }
                            match upper.as_ref() {
                                Some(fd) => self.upper.read_dir(fd),
                                None => Err(ReadDirError::ClosedFd),
                            }
                        }
                        Some(_) => Err(ReadDirError::Io),
                        None => Err(ReadDirError::ClosedFd),
                    }
                };
                if let Some(optional_fd) = optional_fd
                    && self.upper.close(&optional_fd).is_err()
                {
                    return Err(ReadDirError::Io);
                }
                upper_entries = read_result?;
            }
        }

        if let Some(path) = current_path {
            self.filter_merged_directory_entries_under_namespace(
                &namespace_guard,
                path,
                &mut upper_entries,
                &mut lower_entries,
            );
        } else {
            // A detached OFD may retain both handles from its old merged generation. Never reopen
            // by its stale descriptor path, but keep upper-first merging and normalize backend dot
            // entries on those held objects.
            Self::normalize_and_merge_directory_entries(&mut upper_entries, &mut lower_entries);
        }
        drop(namespace_guard);

        for entry in &mut upper_entries {
            if let Some(node_info) = entry.ino_info.take() {
                entry.ino_info = Some(self.get_layered_nodeinfo(node_info, true));
            }
        }
        for entry in &mut lower_entries {
            if let Some(node_info) = entry.ino_info.take() {
                entry.ino_info = Some(self.get_layered_nodeinfo(node_info, false));
            }
        }
        upper_entries.append(&mut lower_entries);
        Ok(upper_entries)
    }

    fn with_dir_position<T>(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        f: impl FnOnce(&mut usize) -> T,
    ) -> Result<T, ReadDirError> {
        let (entry, path_only) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| {
                (
                    Arc::clone(&descriptor.entry.entry),
                    descriptor.entry.flags.contains(OFlags::PATH),
                )
            })
            .ok_or(ReadDirError::ClosedFd)?;
        if path_only {
            return Err(ReadDirError::PathOnlyFd);
        }
        let mut state = entry.state.lock();
        let state = state.as_mut().ok_or(ReadDirError::ClosedFd)?;
        if state.directory.is_none() {
            return Err(ReadDirError::NotADirectory);
        }
        Ok(f(&mut state.position))
    }

    fn file_status(&self, path: impl crate::path::Arg) -> Result<FileStatus, FileStatusError> {
        self.file_status_as(self.current_user.into(), path)
    }

    fn file_status_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl crate::path::Arg,
    ) -> Result<FileStatus, FileStatusError> {
        let path = self.absolute_path(path)?;
        if self.path_is_copy_up_staging(&path) {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }

        // A fresh upper node is authoritative even if an older lower descriptor remains
        // open under this pathname. Descriptor lifetime must not control namespace visibility.
        match self.upper.file_status_as(credentials, path.as_str()) {
            Ok(status) => {
                if self.path_is_copy_up_staging(&path) {
                    return Err(PathError::NoSuchFileOrDirectory.into());
                }
                return Ok(self.with_layered_node_info(status, true));
            }
            Err(FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            )) => {}
            Err(error) => return Err(error),
        }

        if self.path_suppresses_lower(&path) {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }

        self.lower
            .file_status_as(credentials, path.as_str())
            .map(|status| self.with_layered_node_info(status, false))
    }

    fn fd_file_status(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
    ) -> Result<FileStatus, FileStatusError> {
        let entry = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| Arc::clone(&descriptor.entry.entry))
            .ok_or(FileStatusError::ClosedFd)?;
        let state = entry.state.lock();
        let (status, upper) = match state.as_ref().map(|state| &state.backing) {
            Some(EntryX::Upper { fd }) => (self.upper.fd_file_status(fd)?, true),
            Some(EntryX::Lower { fd }) => (self.lower.fd_file_status(fd)?, false),
            None => return Err(FileStatusError::ClosedFd),
        };
        let FileStatus {
            file_type,
            mode,
            size,
            owner,
            node_info,
            blksize,
            atime,
            mtime,
            ctime,
        } = status;
        // Note: we grab the info and then immediately spit back the same, essentially to ask the
        // compiler to remind us we need to update this when we support inodes and such.
        Ok(FileStatus {
            file_type,
            mode,
            size,
            owner,
            node_info: self.get_layered_nodeinfo(node_info, upper),
            blksize,
            atime,
            mtime,
            ctime,
        })
    }

    fn get_static_backing_data(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
    ) -> Option<&'static [u8]> {
        let entry = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| {
                let access_mode = descriptor.entry.flags & (OFlags::WRONLY | OFlags::RDWR);
                if descriptor.entry.flags.contains(OFlags::PATH)
                    || (access_mode != OFlags::RDONLY && access_mode != OFlags::RDWR)
                {
                    None
                } else {
                    Some(Arc::clone(&descriptor.entry.entry))
                }
            })??;
        let state = entry.state.lock();
        match state.as_ref().map(|state| &state.backing) {
            Some(EntryX::Upper { fd }) => self.upper.get_static_backing_data(fd),
            Some(EntryX::Lower { fd }) => self.lower.get_static_backing_data(fd),
            None => None,
        }
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
enum LayerNodeInfo {
    Upper(NodeInfo),
    Lower(NodeInfo),
}

#[derive(Clone, PartialEq, Eq)]
enum DirectoryBinding {
    Current {
        path: String,
        generation: usize,
        backing: LayerNodeInfo,
    },
    Detached,
}

enum DirectoryState<Upper: super::FileSystem + 'static, Lower: super::FileSystem + 'static> {
    Upper {
        binding: DirectoryBinding,
        lower: Option<TypedFd<Lower>>,
    },
    Lower {
        binding: DirectoryBinding,
        upper: Option<TypedFd<Upper>>,
    },
}

struct Descriptor<
    Platform: sync::RawSyncPrimitivesProvider,
    Upper: super::FileSystem + 'static,
    Lower: super::FileSystem + 'static,
> {
    path: String,
    flags: OFlags,
    entry: Entry<Platform, Upper, Lower>,
}

struct RootDir {
    // Whiteouts are namespace state. Open descriptions are owned only by descriptors and never
    // cached by pathname: independent opens must never share backend offsets or access modes.
    tombstones: HashSet<String>,
    opaque_directories: HashSet<String>,
    // Copy-up staging nodes physically exist in upper while a transaction prepares independent
    // replacement descriptions, but they are never part of the merged guest-visible namespace.
    copy_up_staging: HashSet<String>,
    directory_generations: HashMap<String, usize>,
    next_directory_generation: usize,
}

struct RootPathState {
    tombstoned: bool,
    opaque: bool,
}

impl RootDir {
    fn new() -> Self {
        Self {
            tombstones: HashSet::new(),
            opaque_directories: HashSet::new(),
            copy_up_staging: HashSet::new(),
            directory_generations: HashMap::new(),
            next_directory_generation: 1,
        }
    }

    fn path_or_descendant(candidate: &str, ancestor: &str) -> bool {
        candidate == ancestor
            || ancestor == "/" && candidate.starts_with('/')
            || candidate
                .strip_prefix(ancestor)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }

    fn clear_namespace_subtree(&mut self, path: &str) {
        self.tombstones
            .retain(|candidate| !Self::path_or_descendant(candidate, path));
        self.opaque_directories
            .retain(|candidate| !Self::path_or_descendant(candidate, path));
        self.directory_generations
            .retain(|candidate, _| !Self::path_or_descendant(candidate, path));
    }

    fn rebase_path(path: &str, old: &str, new: &str) -> String {
        if path == old {
            return new.into();
        }
        let mut rebased = String::from(new);
        rebased.push_str(&path[old.len()..]);
        rebased
    }

    fn publish_upper_nondirectory(&mut self, path: &str) {
        self.clear_namespace_subtree(path);
    }

    fn publish_new_directory(&mut self, path: &str, opaque: bool) {
        self.clear_namespace_subtree(path);
        if opaque {
            self.opaque_directories.insert(path.into());
        }
    }

    fn publish_removed_path(&mut self, path: &str, hides_lower: bool) {
        self.clear_namespace_subtree(path);
        if hides_lower {
            self.tombstones.insert(path.into());
        }
    }

    fn publish_renamed_nondirectory(&mut self, old: &str, new: &str, source_hides_lower: bool) {
        self.clear_namespace_subtree(new);
        self.clear_namespace_subtree(old);
        if source_hides_lower {
            self.tombstones.insert(old.into());
        }
    }

    fn publish_renamed_directory(
        &mut self,
        old: &str,
        new: &str,
        source_hides_lower: bool,
        destination_opaque: bool,
    ) {
        let moved_tombstones: Vec<String> = self
            .tombstones
            .iter()
            .filter(|candidate| Self::path_or_descendant(candidate, old))
            .map(|candidate| Self::rebase_path(candidate, old, new))
            .collect();
        let moved_opaque_directories: Vec<String> = self
            .opaque_directories
            .iter()
            .filter(|candidate| Self::path_or_descendant(candidate, old))
            .map(|candidate| Self::rebase_path(candidate, old, new))
            .collect();
        self.clear_namespace_subtree(new);
        self.clear_namespace_subtree(old);
        self.tombstones.extend(moved_tombstones);
        self.opaque_directories.extend(moved_opaque_directories);
        self.tombstones.remove(new);
        if destination_opaque {
            self.opaque_directories.insert(new.into());
        }
        if source_hides_lower {
            self.tombstones.insert(old.into());
        }
    }

    fn directory_generation(&mut self, path: &str) -> usize {
        if let Some(generation) = self.directory_generations.get(path) {
            return *generation;
        }
        let generation = self.next_directory_generation;
        self.next_directory_generation = self
            .next_directory_generation
            .checked_add(1)
            .expect("directory generation space exhausted");
        self.directory_generations.insert(path.into(), generation);
        generation
    }

    fn directory_generation_matches(&self, path: &str, generation: usize) -> bool {
        self.directory_generations.get(path) == Some(&generation)
    }

    fn is_copy_up_staging(&self, path: &str) -> bool {
        self.copy_up_staging.contains(path)
    }

    fn path_state(&self, path: &str) -> RootPathState {
        RootPathState {
            tombstoned: self.tombstones.contains(path),
            opaque: self.opaque_directories.contains(path),
        }
    }

    fn publish_tombstone(&mut self, path: &str) -> RootPathState {
        let state = self.path_state(path);
        self.tombstones.insert(path.into());
        state
    }

    fn publish_opaque(&mut self, path: &str) -> RootPathState {
        let state = self.path_state(path);
        self.opaque_directories.insert(path.into());
        state
    }

    fn restore_path(&mut self, path: &str, state: RootPathState) {
        if state.tombstoned {
            self.tombstones.insert(path.into());
        } else {
            self.tombstones.remove(path);
        }
        if state.opaque {
            self.opaque_directories.insert(path.into());
        } else {
            self.opaque_directories.remove(path);
        }
    }

    fn suppresses_lower(&self, path: &str) -> bool {
        let mut candidate = path;
        loop {
            if self.tombstones.contains(candidate) || self.opaque_directories.contains(candidate) {
                return true;
            }
            if candidate == "/" {
                return false;
            }
            candidate = candidate.rsplit_once('/').map_or("/", |(parent, _)| {
                if parent.is_empty() { "/" } else { parent }
            });
        }
    }
}

struct OpenDescription<
    Platform: sync::RawSyncPrimitivesProvider,
    Upper: super::FileSystem + 'static,
    Lower: super::FileSystem + 'static,
> {
    // Backing and logical offset form one open-file-description state. Raw dup shares this lock;
    // unrelated opens get distinct state. Migration can therefore freeze both, prepare a replacement,
    // and swap them atomically with respect to read/write/seek/close.
    state: sync::Mutex<Platform, Option<OpenState<Upper, Lower>>>,
}

struct OpenState<Upper: super::FileSystem + 'static, Lower: super::FileSystem + 'static> {
    backing: EntryX<Upper, Lower>,
    position: usize,
    directory: Option<DirectoryState<Upper, Lower>>,
}

type Entry<Platform, Upper, Lower> = Arc<OpenDescription<Platform, Upper, Lower>>;

enum EntryX<Upper: super::FileSystem + 'static, Lower: super::FileSystem + 'static> {
    Upper { fd: TypedFd<Upper> },
    Lower { fd: TypedFd<Lower> },
}

impl<Upper: super::FileSystem + 'static, Lower: super::FileSystem + 'static> core::fmt::Debug
    for EntryX<Upper, Lower>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Upper { fd: _ } => f.debug_struct("Upper").finish_non_exhaustive(),
            Self::Lower { fd: _ } => f.debug_struct("Lower").finish_non_exhaustive(),
        }
    }
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { sync::RawSyncPrimitivesProvider }, Upper: { super::FileSystem + 'static }, Lower: { super::FileSystem + 'static };
    FileSystem<Platform, Upper, Lower>;
    @Platform: { sync::RawSyncPrimitivesProvider }, Upper: { super::FileSystem + 'static }, Lower: { super::FileSystem + 'static };
    Descriptor<Platform, Upper, Lower>;
    -> FileFd<Platform, Upper, Lower>;
}
