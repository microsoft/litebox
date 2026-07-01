// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An layered file system, layering on [`FileSystem`](super::FileSystem) on top of another.

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use hashbrown::{HashMap, HashSet};

#[cfg(feature = "trace_fs")]
use crate::log_println;

use crate::LiteBox;
use crate::fd::{Descriptors, InternalFd, MetadataError, TypedFd};
use crate::path::Arg;
use crate::sync;

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RenameError, RmdirError, SeekError, SymlinkError, TruncateError,
    UnlinkError, WriteError,
};
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, SeekWhence};

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
    /// New files created with `O_CREAT` are placed directly on the lower layer so they persist
    /// on the backing store (e.g., the host filesystem via 9P). Existing lower-layer files can
    /// be written to directly. If an upper level file exists with the same name as a lower layer
    /// file, then it is shadowed, and only the upper layer file would be visible.
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
    Upper: super::FileSystem<DescriptorPlatform = Platform> + 'static,
    Lower: super::FileSystem<DescriptorPlatform = Platform> + 'static,
> {
    litebox: LiteBox<Platform>,
    upper: Upper,
    lower: Lower,
    // TODO: Possibly support a single-threaded variant that doesn't have the cost of requiring a
    // sync-primitives platform, as well as cost of mutexes and such?
    //
    // INVARIANT: never hold this lock (read OR write) across any call into
    // `self.lower` (9P filesystem).  The RwLock is writer-preferring: a
    // queued writer blocks all new readers.  If a thread holds this lock
    // while a 9P round-trip blocks, concurrent open()/close()/fstat()
    // callers deadlock behind the queued writer.  Pattern: take lock →
    // extract/clone what you need → drop lock → call 9P → re-lock if
    // mutation is required.
    root: sync::RwLock<Platform, RootDir<Upper, Lower>>,
    layering_semantics: LayeringSemantics,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
    node_info_lookup: sync::RwLock<Platform, HashMap<NodeInfo, usize>>,
}

#[cfg(test)]
impl<
    Platform: sync::RawSyncPrimitivesProvider,
    Upper: super::FileSystem<DescriptorPlatform = Platform> + 'static,
    Lower: super::FileSystem<DescriptorPlatform = Platform> + 'static,
> FileSystem<Platform, Upper, Lower>
{
    super::impl_test_descriptor_compat!();
}

impl<
    Platform: sync::RawSyncPrimitivesProvider,
    Upper: super::FileSystem<DescriptorPlatform = Platform>,
    Lower: super::FileSystem<DescriptorPlatform = Platform>,
> FileSystem<Platform, Upper, Lower>
{
    /// Construct a new `FileSystem` instance
    #[must_use]
    pub fn new(
        litebox: &LiteBox<Platform>,
        upper: Upper,
        lower: Lower,
        layering_semantics: LayeringSemantics,
    ) -> Self {
        let root = sync::RwLock::new(RootDir::new());
        let node_info_lookup = sync::RwLock::new(HashMap::new());
        Self {
            litebox: litebox.clone(),
            upper,
            lower,
            root,
            current_working_dir: "/".into(),
            layering_semantics,
            node_info_lookup,
        }
    }

    /// (private-only) check if the lower level has the path; if there is an I/O or path failure,
    /// propagate the relevant error.
    fn ensure_lower_contains(&self, path: &str) -> Result<FileType, FileStatusError> {
        self.lower.file_status(path).map(|stat| stat.file_type)
    }

    /// Whether this path is hidden because it or one of its ancestors is tombstoned.
    fn is_hidden_by_tombstone(&self, path: &str) -> Result<bool, PathError> {
        let root = self.root.read();
        Ok(path.increasing_ancestors()?.any(|ancestor| {
            root.entries
                .get(ancestor)
                .is_some_and(|e| matches!(e.as_ref(), EntryX::Tombstone))
        }))
    }

    /// Whether one of this path's strict ancestors is tombstoned.
    fn has_tombstoned_ancestor(&self, path: &str) -> Result<bool, PathError> {
        let root = self.root.read();
        Ok(path.increasing_ancestors()?.any(|ancestor| {
            ancestor != path
                && root
                    .entries
                    .get(ancestor)
                    .is_some_and(|e| matches!(e.as_ref(), EntryX::Tombstone))
        }))
    }

    /// Invalidate `root.entries` cache for a path and all its descendants.
    /// Required after rename to prevent stale cached fds and tombstones
    /// from shadowing the post-rename namespace.
    fn invalidate_cache_tree(root: &mut RootDir<Upper, Lower>, path: &str) {
        root.entries.remove(path);
        root.lower_access_modes.remove(path);
        let prefix = alloc::format!("{path}/");
        let descendants: Vec<String> = root
            .entries
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        for k in descendants {
            root.entries.remove(&k);
            root.lower_access_modes.remove(&k);
        }
    }

    /// Returns whether a lower-layer fd is safe to share across multiple layered opens.
    ///
    /// Regular files and directories can reuse a shared lower fd because layered descriptors track
    /// their own offsets. Character devices often have per-open state or side effects, so each
    /// layered open must keep its own lower fd.
    fn lower_fd_is_shareable(
        &self,
        fd: &TypedFd<Lower>,
        descriptors: &Descriptors<Platform>,
    ) -> Result<bool, FileStatusError> {
        Ok(!matches!(
            self.lower.fd_file_status(fd, descriptors)?.file_type,
            FileType::CharacterDevice
        ))
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
            if self.is_hidden_by_tombstone(dir)? {
                return Err(PathError::NoSuchFileOrDirectory)?;
            }
            // Check if the ancestor already exists on the upper layer.
            // This handles dirs created on upper in a prior layered mkdir
            // (e.g., a parent that only exists in the in-mem FS because the
            // lower layer couldn't create it).
            match self.upper.file_status(dir) {
                Ok(FileStatus {
                    file_type: FileType::Directory,
                    ..
                }) => continue,
                Ok(_) => return Err(MkdirError::PathError(PathError::ComponentNotADirectory)),
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => {
                    // Not on upper; check lower and migrate if found.
                }
                Err(FileStatusError::PathError(e @ PathError::NoSearchPerms { .. })) => {
                    return Err(e)?;
                }
                Err(FileStatusError::PathError(PathError::ComponentNotADirectory)) => {
                    return Err(MkdirError::PathError(PathError::ComponentNotADirectory));
                }
                Err(FileStatusError::PathError(PathError::InvalidPathname)) => {
                    unreachable!("we just confirmed valid path")
                }
                Err(_) => return Err(MkdirError::Io),
            }
            match self.ensure_lower_contains(dir) {
                Ok(FileType::Directory) => {
                    // The dir exists on lower; mirror it on upper.
                    match self
                        .upper
                        .mkdir(dir, self.lower.file_status(dir).unwrap().mode)
                    {
                        Ok(()) | Err(MkdirError::AlreadyExists) => {}
                        Err(e) => match e {
                            MkdirError::ReadOnlyFileSystem
                            | MkdirError::Io
                            | MkdirError::NoWritePerms
                            | MkdirError::PathError(
                                PathError::ComponentNotADirectory
                                | PathError::InvalidPathname
                                | PathError::NoSearchPerms { .. },
                            ) => {
                                return Err(e);
                            }
                            MkdirError::PathError(
                                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                            ) => {
                                unreachable!()
                            }
                            _ => return Err(MkdirError::Io),
                        },
                    }
                }
                Ok(FileType::RegularFile | FileType::CharacterDevice | FileType::Symlink)
                | Err(
                    FileStatusError::PathError(PathError::MissingComponent)
                    | FileStatusError::ClosedFd
                    | FileStatusError::NotADirectory,
                ) => unreachable!(),
                Err(FileStatusError::PathError(PathError::ComponentNotADirectory)) => {
                    unimplemented!()
                }
                Err(FileStatusError::PathError(PathError::InvalidPathname)) => {
                    unreachable!("we just confirmed valid path")
                }
                Err(FileStatusError::PathError(e @ PathError::NoSearchPerms { .. })) => {
                    return Err(e)?;
                }
                Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory)) => {
                    assert_ne!(dir, path);
                    return Err(PathError::MissingComponent)?;
                }
                Err(FileStatusError::Io | FileStatusError::SymlinkLoop) => {
                    return Err(MkdirError::Io);
                }
            }
        }
        // The loop above should return at one of its return points
        unreachable!()
    }

    /// (private-only) Migrate a file from lower to upper layer
    ///
    /// It performs a check to make sure that the lower level has the file, and if the lower-level
    /// does not, then it will error out with the relevant `PathError` that can be propagated as
    /// necessary.
    ///
    /// Note: this focuses only on files.
    ///
    /// If `copy_data` is `true`, it copies over the lower data to the upper one, otherwise, it
    /// makes the upper file empty (similar to a truncate). Generally speaking, you want to use
    /// `true` for `copy_data`.
    fn migrate_file_up(
        &self,
        path: &str,
        copy_data: bool,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), MigrationError> {
        match self.layering_semantics {
            LayeringSemantics::LowerLayerReadOnly => {
                // fallthrough
            }
            LayeringSemantics::LowerLayerWritableFiles => {
                // If this is ever hit, then that specific layered function calling this
                // `migrate_file_up` function needs to be looked at to make sure that it is
                // implemented correctly and update its semantics if necessary. The
                // `migrate_file_up` functionality was implemented when there was only one set of
                // semantics for layered file systems (namely `LowerLayerReadOnly`), thus the file
                // system may not correctly account for other situations just yet (specifically,
                // some situations might attempt to migrate files when they shouldn't). This
                // particular panic is simply to catch such cases.
                unreachable!()
            }
        }

        // We first open the file up at the lower level for reading
        let lower_fd = match self
            .lower
            .open(path, OFlags::RDONLY, Mode::empty(), descriptors)
        {
            Ok(fd) => fd,
            Err(e) => match e {
                OpenError::AccessNotAllowed => return Err(MigrationError::NoReadPerms),
                OpenError::Io | OpenError::Interrupted => return Err(MigrationError::Io),
                OpenError::NoWritePerms
                | OpenError::ReadOnlyFileSystem
                | OpenError::AlreadyExists
                | OpenError::ClosedFd
                | OpenError::NotADirectory
                | OpenError::TruncateError(_) => unreachable!(),
                OpenError::PathError(path_error) => return Err(path_error)?,
            },
        };
        // We begin to read the lower file before opening the upper file, just in case the lower
        // file is not really a file (in which case, we don't want to tell the upper layer anything,
        // but error out sooner.
        //
        // Other than that, this is a simple loop that just copies over in chunks by a simple
        // read-write loop.
        let mut upper_fd = None;
        let mut temp_buf = [0u8; 4096];
        loop {
            match self.lower.read(&lower_fd, &mut temp_buf, None, descriptors) {
                Ok(size) => {
                    if upper_fd.is_none() {
                        // We are here the first time around, and did not error out, yay! We can
                        // actually open up the file.
                        //
                        // First, we make sure we've set up the ancestor directories.
                        match self.mkdir_migrating_ancestor_dirs(path) {
                            Ok(()) => {}
                            Err(_) => return Err(MigrationError::Io),
                        }
                        // Now we can actually open the file.
                        upper_fd = Some(
                            self.upper
                                .open(
                                    path,
                                    OFlags::CREAT | OFlags::WRONLY,
                                    self.lower
                                        .fd_file_status(&lower_fd, descriptors)
                                        .unwrap()
                                        .mode,
                                    descriptors,
                                )
                                .unwrap(),
                        );
                    }
                    let upper_fd = upper_fd.as_ref().unwrap();
                    if size > 0 && copy_data {
                        self.upper.write(upper_fd, &temp_buf[..size], None, descriptors).expect(
                            "writing to upper layer must succeed, or layered file migration is in serious trouble",
                        );
                    } else {
                        // EOF
                        break;
                    }
                }
                Err(e) => match e {
                    ReadError::NotAFile => {
                        // We can only have this happen the first time around
                        assert!(upper_fd.is_none());
                        // In which case we quit early
                        return Err(MigrationError::NotAFile);
                    }
                    ReadError::ClosedFd | ReadError::NotForReading => unreachable!(),
                    ReadError::Io | ReadError::WouldBlock | ReadError::Interrupted => {
                        return Err(MigrationError::Io);
                    }
                },
            }
        }
        // After migrating the data, we also use these FDs to migrate the node-info over, so that
        // any caller that tries to get the inode before/after the migration sees the same inode.
        if let Some(&layered_id) = self.node_info_lookup.read().get(
            &self
                .lower
                .fd_file_status(&lower_fd, descriptors)
                .unwrap()
                .node_info,
        ) {
            let old = self.node_info_lookup.write().insert(
                self.upper
                    .fd_file_status(upper_fd.as_ref().unwrap(), descriptors)
                    .unwrap()
                    .node_info,
                layered_id,
            );
            assert!(old.is_none());
        }
        // Now that we've migrated the data (and node-info) over, we can close out both of the file
        // descriptors.
        self.upper.close(&upper_fd.unwrap(), descriptors).unwrap();
        self.lower.close(&lower_fd, descriptors).unwrap();

        // Now we need to migrate all the descriptor entries over.
        //
        // Perf: this does a full scan over all open descriptors: if a process has a HUGE number of
        // open descriptors, this could be slow.
        let RootDir {
            entries: root_entries,
            lower_access_modes: root_access_modes,
        } = &mut *self.root.write();
        // First we figure out which entries need to be moved up. These entries are arc-cloned into
        // a `Vec` so that we can release the lock the file descriptor table when setting things up
        // within the upper layer.
        let to_migrate: alloc::vec::Vec<(InternalFd, usize, OFlags, Entry<Upper, Lower>)> =
            descriptors
                .iter::<Self>()
                .filter_map(|(internal_fd, e)| {
                    if e.entry.path != path {
                        // Skip any that do not match the path
                        return None;
                    }
                    match &*e.entry.entry {
                        EntryX::Upper { fd: _ } => {
                            // Need to do nothing, jump to next
                            None
                        }
                        EntryX::Lower { fd: _ } => {
                            // We need to change this up to an upper-level entry.
                            Some((
                                internal_fd,
                                e.entry.position.load(SeqCst),
                                e.entry.flags,
                                Arc::clone(&e.entry.entry),
                            ))
                        }
                        EntryX::Tombstone => unreachable!(),
                    }
                })
                .collect();
        // Now we can actually perform the migration, since we've unlocked the lock on the
        // file-descriptor table, which allows us to actually access things within the upper/lower
        // levels without trouble.
        for (internal_fd, position, flags, entry) in to_migrate {
            // First, we set up the upper entry we'll be swapping/placing in.
            let upper_fd = self
                .upper
                .open(path, flags, Mode::empty(), descriptors)
                .unwrap();
            if position > 0 {
                self.upper
                    .seek(
                        &upper_fd,
                        isize::try_from(position).unwrap(),
                        SeekWhence::RelativeToBeginning,
                        descriptors,
                    )
                    .unwrap();
            }
            let upper_entry = Arc::new(EntryX::Upper { fd: upper_fd });
            // Then we check up on replacing entries
            match Arc::strong_count(&entry) {
                0..=2 => {
                    // We are holding one, and also there must be an entry in `root` and the file
                    // descriptor table.
                    unreachable!()
                }
                3 => {
                    // Perfect amount to trigger a `close` on the lower level, and remove
                    // the underlying root entry, since further syncing is no longer
                    // necessary.
                    let old_entry = descriptors
                        .with_entry_mut_via_internal_fd::<Self, _, _>(internal_fd, |entry| {
                            core::mem::replace(&mut entry.entry.entry, upper_entry)
                        })
                        .expect("nothing should have changed the existing entry");
                    assert!(Arc::ptr_eq(&old_entry, &entry));
                    drop(entry);
                    let root_entry = root_entries.remove(path).unwrap();
                    root_access_modes.remove(path);
                    assert!(Arc::ptr_eq(&old_entry, &root_entry));
                    drop(root_entry);
                    let entry = Arc::into_inner(old_entry).unwrap();
                    match entry {
                        EntryX::Upper { .. } | EntryX::Tombstone => unreachable!(),
                        EntryX::Lower { fd } => {
                            self.lower.close(&fd, descriptors).unwrap();
                        }
                    }
                }
                _ => {
                    // Other FDs are open with the same file too. We'll handle the open one
                    // here locally, and a future FD will take care of the relevant closing.
                    let old_entry = descriptors
                        .with_entry_mut_via_internal_fd::<Self, _, _>(internal_fd, |entry| {
                            core::mem::replace(&mut entry.entry.entry, upper_entry)
                        })
                        .expect("nothing should have changed the existing entry");
                    assert!(Arc::ptr_eq(&old_entry, &entry));
                }
            }
        }

        Ok(())
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

    /// Get the stored path from any fd's Descriptor.
    fn descriptor_path(
        dirfd: &FileFd<Platform, Upper, Lower>,
        descriptors: &Descriptors<Platform>,
    ) -> Option<String> {
        let entry = descriptors.get_entry(dirfd)?;
        Some(entry.entry.path.clone())
    }

    /// Get the stored path from a directory fd's Descriptor.
    fn dir_fd_path(
        &self,
        dirfd: &FileFd<Platform, Upper, Lower>,
        descriptors: &Descriptors<Platform>,
    ) -> Result<String, super::DirFdError> {
        // Clone the path and underlying entry in a single borrow scope so the
        // descriptor_table borrow is released before we query the backend.
        let (path, entry) = {
            let desc = descriptors
                .get_entry(dirfd)
                .ok_or(super::DirFdError::ClosedFd)?;
            (desc.entry.path.clone(), Arc::clone(&desc.entry.entry))
        };
        // Check the actual file type from the underlying backend rather than
        // relying on OFlags::DIRECTORY, which the caller may not have set.
        let file_type = match entry.as_ref() {
            EntryX::Upper { fd } => self.upper.fd_file_status(fd, descriptors),
            EntryX::Lower { fd } => self.lower.fd_file_status(fd, descriptors),
            EntryX::Tombstone => return Err(super::DirFdError::ClosedFd),
        }
        .map_err(|e| match e {
            FileStatusError::ClosedFd => super::DirFdError::ClosedFd,
            _ => super::DirFdError::Io,
        })?
        .file_type;
        if matches!(file_type, super::FileType::Directory) {
            Ok(path)
        } else {
            Err(super::DirFdError::NotADirectory)
        }
    }

    /// Resolve a relative path against a base directory path.
    fn resolve_relative(base: &str, rel: &str) -> Result<String, PathError> {
        if rel.is_empty() || rel == "." {
            return Ok(base.into());
        }
        if rel.starts_with('/') {
            return Ok(rel.normalized()?);
        }
        let combined = if base.ends_with('/') {
            alloc::format!("{base}{rel}")
        } else {
            alloc::format!("{base}/{rel}")
        };
        Ok(combined.normalized()?)
    }

    fn file_status_with_descriptors(
        &self,
        path: impl crate::path::Arg,
        descriptors: &Descriptors<Platform>,
    ) -> Result<FileStatus, FileStatusError> {
        let path = self.absolute_path(path)?;
        if self.is_hidden_by_tombstone(&path)? {
            return Err(PathError::NoSuchFileOrDirectory)?;
        }
        if let Some(entry) = self.root.read().entries.get(&path).cloned() {
            let FileStatus {
                file_type,
                mode,
                size,
                owner,
                node_info,
                blksize,
            } = match entry.as_ref() {
                EntryX::Upper { fd } => self.upper.fd_file_status(fd, descriptors)?,
                EntryX::Lower { fd } => self.lower.fd_file_status(fd, descriptors)?,
                EntryX::Tombstone => {
                    return Err(PathError::NoSuchFileOrDirectory)?;
                }
            };
            return Ok(FileStatus {
                file_type,
                mode,
                size,
                owner,
                node_info: self.get_layered_nodeinfo(node_info),
                blksize,
            });
        }
        match self.upper.file_status(&*path) {
            Ok(FileStatus {
                file_type,
                mode,
                size,
                owner,
                node_info,
                blksize,
            }) => {
                return Ok(FileStatus {
                    file_type,
                    mode,
                    size,
                    owner,
                    node_info: self.get_layered_nodeinfo(node_info),
                    blksize,
                });
            }
            Err(e) => match e {
                FileStatusError::PathError(
                    PathError::ComponentNotADirectory
                    | PathError::InvalidPathname
                    | PathError::NoSearchPerms { .. },
                ) => {
                    return Err(e);
                }
                FileStatusError::Io | FileStatusError::SymlinkLoop => return Err(e),
                FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                ) => {}
                FileStatusError::ClosedFd | FileStatusError::NotADirectory => unreachable!(),
            },
        }
        let FileStatus {
            file_type,
            mode,
            size,
            owner,
            node_info,
            blksize,
        } = self.lower.file_status(path)?;
        Ok(FileStatus {
            file_type,
            mode,
            size,
            owner,
            node_info: self.get_layered_nodeinfo(node_info),
            blksize,
        })
    }

    /// Resolve symlinks in every component of `path` (like `realpath`).
    ///
    /// Walks each component, checking for symlinks at each prefix. When a
    /// symlink is found, its target's components are spliced into the work
    /// queue so nested symlinks within the target are also resolved.
    /// Returns `SymlinkLoop` if more than `max_hops` symlinks are followed.
    fn resolve_follow_symlinks(
        &self,
        path: String,
        max_hops: usize,
    ) -> Result<String, super::FileStatusError> {
        let mut resolved = alloc::string::String::from("/");
        let mut hops_remaining = max_hops;

        let mut remaining: alloc::vec::Vec<alloc::string::String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(alloc::string::String::from)
            .collect();
        let mut idx = 0;

        while idx < remaining.len() {
            let component = remaining[idx].clone();
            idx += 1;

            match component.as_str() {
                "" | "." => continue,
                ".." => {
                    if let Some(pos) = resolved[..resolved.len().saturating_sub(1)].rfind('/') {
                        resolved.truncate(pos + 1);
                    }
                    continue;
                }
                _ => {}
            }

            if !resolved.ends_with('/') {
                resolved.push('/');
            }
            resolved.push_str(&component);

            if let Ok(t) = <Self as super::FileSystem>::read_link(self, &*resolved) {
                if hops_remaining == 0 {
                    return Err(super::FileStatusError::SymlinkLoop);
                }
                hops_remaining -= 1;

                if t.starts_with('/') {
                    resolved = alloc::string::String::from("/");
                } else {
                    let parent_end = resolved.rfind('/').unwrap_or(0).max(1);
                    resolved.truncate(parent_end);
                }

                let tail: alloc::vec::Vec<alloc::string::String> = remaining.drain(idx..).collect();
                remaining.truncate(0);
                remaining.extend(
                    t.split('/')
                        .filter(|c| !c.is_empty())
                        .map(alloc::string::String::from),
                );
                remaining.extend(tail);
                idx = 0;
            }
        }

        if resolved.len() > 1 && resolved.ends_with('/') {
            resolved.pop();
        }
        Ok(resolved)
    }

    // Converts a `NodeInfo` from any of the layers into a layered `NodeInfo`
    fn get_layered_nodeinfo(&self, node_info: NodeInfo) -> NodeInfo {
        let mut node_info_lookup = self.node_info_lookup.write();
        let rdev = node_info.rdev;
        // ino starts at 1 (zero represents deleted file)
        let new_id = node_info_lookup.len() + 1;
        let ino = *node_info_lookup.entry(node_info).or_insert(new_id);
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
    #[error("I/O error")]
    Io,
    #[error(transparent)]
    PathError(#[from] PathError),
}

impl<
    Platform: sync::RawSyncPrimitivesProvider,
    Upper: super::FileSystem<DescriptorPlatform = Platform>,
    Lower: super::FileSystem<DescriptorPlatform = Platform>,
> super::private::Sealed for FileSystem<Platform, Upper, Lower>
{
}

impl<
    Platform: sync::RawSyncPrimitivesProvider,
    Upper: super::FileSystem<DescriptorPlatform = Platform> + 'static,
    Lower: super::FileSystem<DescriptorPlatform = Platform> + 'static,
> super::FileSystem for FileSystem<Platform, Upper, Lower>
{
    type DescriptorPlatform = Platform;

    fn walks_follow_symlinks(&self) -> bool {
        // Returns true if either layer follows symlinks during walks.
        // The upper layer (in_mem/tar) has no symlinks, so it returns
        // false (the default). The lower layer (9P) follows symlinks
        // via server-side canonicalization. Using OR is correct because
        // the upper layer never has symlinks that would need client-side
        // resolution, and the lower layer resolves them server-side.
        self.upper.walks_follow_symlinks() || self.lower.walks_follow_symlinks()
    }

    fn create_anonymous_file(
        &self,
        name: &str,
        mode: super::Mode,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<FileFd<Platform, Upper, Lower>, super::errors::CreateAnonymousFileError> {
        let upper_fd = self.upper.create_anonymous_file(name, mode, descriptors)?;
        Ok(descriptors.insert(Descriptor {
            path: super::memfd_display_path(name),
            flags: OFlags::RDWR | OFlags::LARGEFILE,
            entry: Arc::new(EntryX::Upper { fd: upper_fd }),
            position: 0.into(),
        }))
    }

    fn allocate_fid_number(&self) -> Result<u32, OpenError> {
        self.lower.allocate_fid_number()
    }

    fn free_fid_number(&self, fid: u32) {
        self.lower.free_fid_number(fid);
    }

    fn clunk_fid_number(&self, fid: u32) {
        self.lower.clunk_fid_number(fid);
    }

    fn wrap_existing_fid(
        &self,
        remote_fid: u32,
        path: &str,
        status_flags: OFlags,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<FileFd<Platform, Upper, Lower>, OpenError> {
        let lower_fd = self
            .lower
            .wrap_existing_fid(remote_fid, path, status_flags, descriptors)?;
        let descriptor_path = if path.is_empty() {
            alloc::format!("<wrapped-fid:{remote_fid}>")
        } else {
            String::from(path)
        };
        let descriptor_flags = if status_flags.is_empty() {
            OFlags::RDWR | OFlags::LARGEFILE
        } else {
            status_flags
        };
        Ok(descriptors.insert(Descriptor {
            path: descriptor_path,
            flags: descriptor_flags,
            entry: Arc::new(EntryX::Lower { fd: lower_fd }),
            position: 0.into(),
        }))
    }

    fn descriptor_backend_fid(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        descriptors: &Descriptors<Platform>,
    ) -> Option<u32> {
        descriptors
            .with_entry(fd, |descriptor| match descriptor.entry.entry.as_ref() {
                EntryX::Upper { fd } => self.upper.descriptor_backend_fid(fd, descriptors),
                EntryX::Lower { fd } => self.lower.descriptor_backend_fid(fd, descriptors),
                EntryX::Tombstone => unreachable!(),
            })
            .flatten()
    }

    fn open(
        &self,
        path: impl crate::path::Arg,
        mut flags: OFlags,
        mode: Mode,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<FileFd<Platform, Upper, Lower>, OpenError> {
        flags.remove(OFlags::PATH);
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
            | OFlags::NOFOLLOW
            | OFlags::APPEND
            | OFlags::PATH;
        let unsupported = flags & currently_supported_oflags.complement();
        if !unsupported.is_empty() {
            // Strip unsupported flags rather than panicking — Node.js/V8 may
            // pass platform-specific flags that are harmless to ignore.
            flags &= currently_supported_oflags;
        }
        let path = self.absolute_path(path)?;
        if self.has_tombstoned_ancestor(&path)? {
            return Err(PathError::NoSuchFileOrDirectory)?;
        }
        if flags.contains(OFlags::CREAT) {
            if flags.contains(OFlags::EXCL) {
                // O_EXCL with O_CREAT: fail if file already exists anywhere (upper or lower layer)
                if self
                    .file_status_with_descriptors(path.as_str(), descriptors)
                    .is_ok()
                {
                    return Err(OpenError::AlreadyExists);
                }
            } else {
                // We must first attempt to open the file _without_ creating it, and only if that
                // fails, do we fall-through and end up creating it.
                if let Ok(fd) = <Self as super::FileSystem>::open(
                    self,
                    path.as_str(),
                    flags - OFlags::CREAT,
                    mode,
                    descriptors,
                ) {
                    return Ok(fd);
                }
            }
        }
        let mut tombstone_removal = false;
        // If we already have an entry saying it is a tombstone, then we need to quit out early;
        // otherwise, we'll check the levels.
        // Snapshot the cached entry AND its lower access mode together under a
        // single read lock, then release before running the body. Two reasons:
        //  - The read must NOT be held across `lower_fd_is_shareable` (a 9P
        //    fstat): the writer-preferring RwLock deadlocks at high thread
        //    count when a writer queues while readers are parked in the fstat.
        //  - Reading `entry` and `lower_access_modes` under the *same* guard
        //    keeps the (entry, access-mode) pair consistent. Reading the access
        //    mode separately (a second `self.root.read()` later) races a
        //    concurrent reopen and can pair a fresh access mode with a stale
        //    entry, yielding a wrong compatibility decision — a stale fid gets
        //    reused for an incompatible mode and the open hangs (observed as a
        //    `vscode::bootstrap` regression).
        // The cloned `entry` Arc keeps the lower fd alive across the body.
        let cache_hit = {
            let root = self.root.read();
            root.entries.get(&path).cloned().map(|entry| {
                let access = root.lower_access_modes.get(&path).copied().unwrap_or(0);
                (entry, access)
            })
        };
        if let Some((entry, cached_access)) = cache_hit {
            #[cfg(feature = "trace_fs")]
            if matches!(
                self.layering_semantics,
                LayeringSemantics::LowerLayerWritableFiles
            ) {
                log_println!(
                    self.litebox.x.platform,
                    "[LAYERED-TRACE] cache hit path={:?} entry={:?} flags={:?}",
                    path,
                    entry,
                    flags,
                );
            }
            match entry.as_ref() {
                EntryX::Tombstone => {
                    // The file has been cleared out; it used to exist on the lower level, but we
                    // explicitly have placed a tombstone in its place.
                    if flags.contains(OFlags::CREAT) {
                        // Fallthrough, since we will create it at the upper level now. We should
                        // remove the tombstone though.
                        tombstone_removal = true;
                    } else {
                        return Err(PathError::NoSuchFileOrDirectory)?;
                    }
                }
                EntryX::Upper { .. } => unreachable!(),
                EntryX::Lower { fd } => {
                    // As an optimization, since a lower-level file entry is always opened with the
                    // same flags, and since it indicates that there is no such file at the upper
                    // level, we can just return that directly (with the "real" flags being wrapped
                    // up in the layered descriptor).
                    match self.lower_fd_is_shareable(fd, descriptors) {
                        Ok(true) => {
                            // Check that the cached fid's access mode is
                            // compatible with the requested mode.  A fid
                            // opened WRONLY cannot serve reads (9P Tread
                            // would fail), and a RDONLY fid cannot serve
                            // writes.  On mismatch, fall through to open a
                            // new fid with the correct mode.
                            let requested_access = flags.bits() & 0x3; // O_ACCMODE
                            // `cached_access` was snapshotted with `entry`
                            // above, under one read lock, to keep the pair
                            // consistent and avoid holding the lock across the
                            // 9P fstat in `lower_fd_is_shareable`.
                            let needs_read = requested_access == 0 || requested_access == 2; // RDONLY or RDWR
                            let needs_write = requested_access == 1 || requested_access == 2; // WRONLY or RDWR
                            let cached_can_read = cached_access == 0 || cached_access == 2; // RDONLY or RDWR
                            let cached_can_write = cached_access == 1 || cached_access == 2; // WRONLY or RDWR
                            let compatible = (!needs_read || cached_can_read)
                                && (!needs_write || cached_can_write);
                            if compatible {
                                return Ok(descriptors.insert(Descriptor {
                                    path,
                                    flags,
                                    entry,
                                    position: 0.into(),
                                }));
                            }
                            // Incompatible access mode — fall through to
                            // open a new fid on the lower layer.
                        }
                        Ok(false) => {}
                        Err(_) => return Err(OpenError::Io),
                    }
                }
            }
        }
        if tombstone_removal {
            if let Some(entry) = self.root.write().entries.remove(&path) {
                let EntryX::Tombstone = *entry else {
                    unreachable!()
                };
            } else {
                // Another thread which also was attempting to create the same file (on top of a
                // tombstoned file) won on the race to lock `self.root`, and thus it has already
                // removed it for us. We don't need to remove it, and can proceed as normal.
            }
        }
        // When LowerLayerWritableFiles and O_CREAT for a new file, try the
        // lower layer first so the file persists on the host filesystem.
        // Fall back to upper if lower can't create (e.g., parent dir only
        // exists on upper).  Skip if we just removed a tombstone — the file
        // still exists on lower and reopening it would resurrect a hidden entry.
        // Also skip if the file already exists visibly — the non-O_CREAT open
        // above (line 629) failed for a non-missing reason (e.g., not writable,
        // wrong type), and creating on lower would shadow the upper entry.
        if flags.contains(OFlags::CREAT)
            && !tombstone_removal
            && matches!(
                self.layering_semantics,
                LayeringSemantics::LowerLayerWritableFiles
            )
            && self
                .file_status_with_descriptors(path.as_str(), descriptors)
                .is_err()
        {
            // Validate path through upper first. Only soft not-found errors
            // (the path or an ancestor simply doesn't exist on upper) allow
            // creation on lower. All other errors — ancestor is a non-dir,
            // no search perms, I/O failures — must propagate.
            match self.upper.file_status(path.as_str()) {
                Ok(_)
                | Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => {}
                Err(FileStatusError::PathError(p)) => return Err(OpenError::PathError(p)),
                Err(_) => return Err(OpenError::Io),
            }
            match self.lower.open(path.as_str(), flags, mode, descriptors) {
                Ok(lower_fd) => {
                    // Mirror the shared-cache logic used by the normal lower
                    // open path so that subsequent opens of the same
                    // shareable file reuse this entry instead of creating a
                    // conflicting standalone Arc.
                    let Ok(shareable) = self.lower_fd_is_shareable(&lower_fd, descriptors) else {
                        let _ = self.lower.close(&lower_fd, descriptors);
                        return Err(OpenError::Io);
                    };
                    let entry = if shareable {
                        // Check if another thread already inserted an entry
                        // for this path.  We must NOT call lower_fd_is_shareable()
                        // (9P fstat) while holding the write lock — the writer-
                        // preferring RwLock would deadlock concurrent readers.
                        let existing_arc = {
                            let root = self.root.write();
                            match root.entries.get(&path) {
                                Some(existing) => match existing.as_ref() {
                                    EntryX::Lower { .. } => Some(Arc::clone(existing)),
                                    EntryX::Upper { .. } | EntryX::Tombstone => {
                                        drop(root);
                                        let _ = self.lower.close(&lower_fd, descriptors);
                                        return Err(PathError::NoSuchFileOrDirectory.into());
                                    }
                                },
                                None => None,
                            }
                            // write lock released here
                        };
                        if let Some(existing_arc) = existing_arc {
                            // Call lower_fd_is_shareable OUTSIDE the lock.
                            let existing_shareable = match &*existing_arc {
                                EntryX::Lower { fd } => self.lower_fd_is_shareable(fd, descriptors),
                                _ => unreachable!(),
                            };
                            let Ok(existing_shareable) = existing_shareable else {
                                let _ = self.lower.close(&lower_fd, descriptors);
                                return Err(OpenError::Io);
                            };
                            if existing_shareable {
                                let _ = self.lower.close(&lower_fd, descriptors);
                                existing_arc
                            } else {
                                let _ = self.lower.close(&lower_fd, descriptors);
                                return Err(PathError::NoSuchFileOrDirectory.into());
                            }
                        } else {
                            // No existing entry — insert under the write lock.
                            let mut root = self.root.write();
                            // Re-check: another thread may have inserted while
                            // we briefly released the lock above.
                            if let Some(existing) = root.entries.get(&path) {
                                let shared = Arc::clone(existing);
                                drop(root);
                                let _ = self.lower.close(&lower_fd, descriptors);
                                shared
                            } else {
                                let entry = Arc::new(EntryX::Lower { fd: lower_fd });
                                root.entries.insert(path.clone(), Arc::clone(&entry));
                                root.lower_access_modes
                                    .insert(path.clone(), flags.bits() & 0x3);
                                entry
                            }
                        }
                    } else {
                        Arc::new(EntryX::Lower { fd: lower_fd })
                    };
                    return Ok(descriptors.insert(Descriptor {
                        path,
                        flags,
                        entry,
                        position: 0.into(),
                    }));
                }
                Err(
                    OpenError::PathError(
                        PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                    )
                    | OpenError::ReadOnlyFileSystem
                    | OpenError::Io,
                ) => {
                    // Parent dir doesn't exist on lower, lower is read-only
                    // for this path, or transport error — fall through to
                    // upper-layer creation.
                }
                Err(e) => return Err(e),
            }
        }
        // Otherwise, we first check the upper level, creating an entry if needed
        match self.upper.open(&*path, flags, mode, descriptors) {
            Ok(fd) => {
                let entry = Arc::new(EntryX::Upper { fd });
                return Ok(descriptors.insert(Descriptor {
                    path,
                    flags,
                    entry,
                    position: 0.into(),
                }));
            }
            Err(e) => {
                #[cfg(feature = "trace_fs")]
                if matches!(
                    self.layering_semantics,
                    LayeringSemantics::LowerLayerWritableFiles
                ) {
                    log_println!(
                        self.litebox.x.platform,
                        "[LAYERED-TRACE] upper.open FAILED path={:?} flags={:?} err={:?}",
                        path,
                        flags,
                        e,
                    );
                }
                match &e {
                    OpenError::AccessNotAllowed
                    | OpenError::Io
                    | OpenError::Interrupted
                    | OpenError::NoWritePerms
                    | OpenError::ReadOnlyFileSystem
                    | OpenError::AlreadyExists
                    | OpenError::ClosedFd
                    | OpenError::NotADirectory
                    | OpenError::TruncateError(
                        TruncateError::IsDirectory
                        | TruncateError::NotForWriting
                        | TruncateError::IsTerminalDevice
                        | TruncateError::ClosedFd
                        | TruncateError::Io,
                    )
                    | OpenError::PathError(
                        PathError::ComponentNotADirectory
                        | PathError::InvalidPathname
                        | PathError::NoSearchPerms { .. },
                    ) => {
                        // None of these can be handled by lower level, just quit out early
                        return Err(e);
                    }
                    OpenError::PathError(PathError::MissingComponent)
                        if flags.contains(OFlags::CREAT) =>
                    {
                        // We must check if the lower layer contains all the directories; if it does, we
                        // can create the same directories and then re-trigger the open.
                        let dirname = path.rsplit_once('/').unwrap().0;
                        if let Ok(FileType::Directory) = self.ensure_lower_contains(dirname) {
                            // We must migrate the directories above, and then re-trigger the open
                            match self.mkdir_migrating_ancestor_dirs(&path) {
                                Ok(()) => {
                                    return <Self as super::FileSystem>::open(
                                        self,
                                        path,
                                        flags,
                                        mode,
                                        descriptors,
                                    );
                                }
                                Err(MkdirError::NoWritePerms) => {
                                    return Err(OpenError::NoWritePerms);
                                }
                                Err(MkdirError::ReadOnlyFileSystem) => {
                                    return Err(OpenError::ReadOnlyFileSystem);
                                }
                                Err(MkdirError::PathError(e)) => {
                                    return Err(OpenError::PathError(e));
                                }
                                Err(_) => return Err(OpenError::Io),
                            }
                        }
                        // Otherwise, handle-able by a lower level, fallthrough
                    }
                    OpenError::PathError(
                        PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                    ) => {
                        // Handle-able by a lower level, fallthrough
                    }
                }
            }
        }
        // We must check the lower level, creating an entry if needed
        let original_flags = flags;
        match self.layering_semantics {
            LayeringSemantics::LowerLayerReadOnly => {
                // Prevent creation or truncation of files at lower level
                flags.remove(OFlags::CREAT);
                flags.remove(OFlags::TRUNC);
                // Switch the lower level to read-only; the other calls will take care of
                // copying into the upper level if/when necessary.
                flags.remove(OFlags::RDWR);
                flags.remove(OFlags::WRONLY);
                flags.insert(OFlags::RDONLY);
            }
            LayeringSemantics::LowerLayerWritableFiles => {
                // Preserve O_CREAT so the lower layer can create new files.
                // O_TRUNC is also preserved — the lower layer handles it directly.
            }
        }
        // Any errors from lower level now _must_ propagate up, so we can just invoke
        // the lower level and set up the relevant descriptor upon success.
        #[cfg(feature = "trace_fs")]
        if matches!(
            self.layering_semantics,
            LayeringSemantics::LowerLayerWritableFiles
        ) {
            log_println!(
                self.litebox.x.platform,
                "[LAYERED-TRACE] trying lower.open path={:?} flags={:?}",
                path,
                flags,
            );
        }
        let lower_fd = match self.lower.open(path.as_str(), flags, mode, descriptors) {
            Ok(fd) => fd,
            Err(e) => {
                #[cfg(feature = "trace_fs")]
                if matches!(
                    self.layering_semantics,
                    LayeringSemantics::LowerLayerWritableFiles
                ) {
                    log_println!(
                        self.litebox.x.platform,
                        "[LAYERED-TRACE] lower.open FAILED path={:?} flags={:?} err={:?}",
                        path,
                        flags,
                        e,
                    );
                }
                return Err(e);
            }
        };
        let Ok(shareable) = self.lower_fd_is_shareable(&lower_fd, descriptors) else {
            let _ = self.lower.close(&lower_fd, descriptors);
            return Err(OpenError::Io);
        };
        let entry = if shareable {
            // Insert into root entries, handling the race where another thread may have
            // already inserted an entry for the same path between our earlier read-lock
            // check and this write-lock acquisition.
            //
            // IMPORTANT: we must NOT call lower_fd_is_shareable() (which does
            // a 9P fstat) while holding the write lock.  The writer-preferring
            // RwLock would block all concurrent readers/writers, causing deadlock.
            // Instead we: take write lock → clone Arc → drop lock → call 9P → re-lock.
            let existing_info = {
                let root = self.root.write();
                match root.entries.get(&path) {
                    Some(existing) => match existing.as_ref() {
                        EntryX::Lower { .. } => {
                            let arc = Arc::clone(existing);
                            let cached_access =
                                root.lower_access_modes.get(&path).copied().unwrap_or(0);
                            Some((arc, cached_access))
                        }
                        EntryX::Upper { .. } | EntryX::Tombstone => {
                            // Tombstone or Upper inserted concurrently — shouldn't happen in
                            // normal operation, but close the FD we opened and bail out.
                            drop(root);
                            let _ = self.lower.close(&lower_fd, descriptors);
                            return Err(PathError::NoSuchFileOrDirectory.into());
                        }
                    },
                    None => None,
                }
                // write lock released here
            };
            if let Some((existing_arc, cached_access)) = existing_info {
                // Call lower_fd_is_shareable OUTSIDE the lock (9P fstat).
                let existing_shareable = match &*existing_arc {
                    EntryX::Lower { fd } => self.lower_fd_is_shareable(fd, descriptors),
                    _ => unreachable!(),
                };
                let Ok(existing_shareable) = existing_shareable else {
                    let _ = self.lower.close(&lower_fd, descriptors);
                    return Err(OpenError::Io);
                };
                if existing_shareable {
                    // Check if the existing entry's access mode is
                    // compatible with the requested mode before reusing.
                    let requested_access = flags.bits() & 0x3;
                    let needs_read = requested_access == 0 || requested_access == 2;
                    let needs_write = requested_access == 1 || requested_access == 2;
                    let cached_can_read = cached_access == 0 || cached_access == 2;
                    let cached_can_write = cached_access == 1 || cached_access == 2;
                    let compatible =
                        (!needs_read || cached_can_read) && (!needs_write || cached_can_write);
                    if compatible {
                        // Reuse the existing entry.
                        let _ = self.lower.close(&lower_fd, descriptors);
                        existing_arc
                    } else {
                        // Incompatible mode — replace the cache entry
                        // with the new fid that has the correct mode.
                        let mut root = self.root.write();
                        let entry = Arc::new(EntryX::Lower { fd: lower_fd });
                        root.entries.insert(path.clone(), Arc::clone(&entry));
                        root.lower_access_modes
                            .insert(path.clone(), requested_access);
                        entry
                    }
                } else {
                    let _ = self.lower.close(&lower_fd, descriptors);
                    return Err(PathError::NoSuchFileOrDirectory.into());
                }
            } else {
                // No existing entry — insert under write lock.
                let mut root = self.root.write();
                // Re-check for race: another thread may have inserted.
                if let Some(existing) = root.entries.get(&path) {
                    let shared = Arc::clone(existing);
                    drop(root);
                    let _ = self.lower.close(&lower_fd, descriptors);
                    shared
                } else {
                    let entry = Arc::new(EntryX::Lower { fd: lower_fd });
                    root.entries.insert(path.clone(), Arc::clone(&entry));
                    root.lower_access_modes
                        .insert(path.clone(), flags.bits() & 0x3);
                    entry
                }
            }
        } else {
            Arc::new(EntryX::Lower { fd: lower_fd })
        };
        let fd = descriptors.insert(Descriptor {
            path,
            flags: original_flags,
            entry,
            position: 0.into(),
        });
        if original_flags.contains(OFlags::TRUNC) {
            // The only scenario where we need to manually trigger truncation is when a file does
            // not exist at the upper level but exists at the lower level; in that case, our
            // `truncate` functionality (at the layered FS itself) should correctly migrate things
            // over and handle them.
            match <Self as super::FileSystem>::truncate(self, &fd, 0, true, descriptors) {
                Ok(()) | Err(TruncateError::IsTerminalDevice) => {
                    // The terminal device is the one case we need to (due to Linux compatibility)
                    // explicitly ignore the truncation ability, and instead silently continue as if
                    // no error was thrown during truncation.
                }
                Err(e) => {
                    <Self as super::FileSystem>::close(self, &fd, descriptors).unwrap();
                    return Err(e.into());
                }
            }
        }
        Ok(fd)
    }

    fn close(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), CloseError> {
        let Some(removed_entry) = descriptors.remove(fd) else {
            // Was duplicated, don't need to do anything.
            return Ok(());
        };
        let Descriptor {
            path,
            entry,
            flags: _,
            position: _,
        } = removed_entry.entry;
        // We can first sanity check that we don't have a tombstone: none of the other operations
        // should ever cause the entry _at_ an fd to become a tombstone, even if the entry at the
        // path becomes a tombstone due to a file removal.
        match entry.as_ref() {
            EntryX::Upper { .. } | EntryX::Lower { .. } => {}
            EntryX::Tombstone => unreachable!(),
        }
        // Crucially, we need to grab an exclusive lock to the root, so that the counts cannot
        // change while we are reasoning about them.
        //
        // IMPORTANT: we must NOT hold this lock across blocking I/O
        // (e.g., `self.lower.close()`).  The RwLock is writer-preferring,
        // so a queued writer blocks all new readers.  If a reader is
        // blocked on 9P while a close() writer queues, concurrent
        // open() readers deadlock behind the writer.  We extract the
        // fd to close under the lock, then release the lock before
        // calling `self.lower.close()`.
        let deferred_close = {
            let RootDir {
                entries: root_entries,
                lower_access_modes: root_access_modes,
            } = &mut *self.root.write();
            // Our approach to this changes depending on whether this is an upper level FD or a
            // lower FD.
            match *entry {
                EntryX::Tombstone => {
                    // A tombstone should never have even become an FD (if a file was opened, and then
                    // was subsequently deleted, then the FD itself would not yet be a tombstone, but
                    // would be pointing to the original value).
                    unreachable!()
                }
                EntryX::Upper { .. } => {
                    // Upper-level FDs do not have any entry in the root, nor do they share anything via
                    // `Arc`s. Thus, we can deal with them individually.
                    assert_eq!(Arc::strong_count(&entry), 1);
                    // Specifically, we can just immediately close them out, consuming the entry itself.
                    let EntryX::Upper { fd } = Arc::into_inner(entry).unwrap() else {
                        unreachable!()
                    };
                    // Upper close doesn't go through 9P, safe to do here.
                    return self.upper.close(&fd, descriptors);
                }
                EntryX::Lower { .. } => {
                    // Lower-level descriptors without a root entry are either standalone
                    // (e.g., character devices) or had their cache evicted (e.g., by rename).
                    // Close the fd if we are the sole remaining holder; otherwise another
                    // descriptor will handle it.
                    if !root_entries.contains_key(&path) {
                        match Arc::into_inner(entry) {
                            Some(EntryX::Lower { fd }) => Some(fd),
                            Some(_) => unreachable!(),
                            None => None,
                        }
                    } else {
                        // Shared lower-level FDs have a corresponding entry in the root. Thus, we might
                        // need to possibly clean things up from the root.
                        //
                        // First, we can attempt a fast-path clean-up by quickly check if there are other
                        // FDs referring to the same file
                        if Arc::strong_count(&entry) > 2 {
                            // There are _definitely_ other FDs pointing at this file, leave it alone
                            None
                        } else {
                            // Otherwise, either we have ourselves and the root pointing at it OR the root has
                            // been tombstoned out after the FDs have been opened at it.
                            match **root_entries.get(&path).unwrap() {
                                EntryX::Upper { .. } => unreachable!(),
                                EntryX::Lower { .. } => {
                                    // We are going to have to deal with it at the entry too, fallthrough
                                    // Pull out the root entry. If it is a different Arc (e.g., the
                                    // cache was evicted by rename and a new open re-populated it),
                                    // put it back and treat this fd as evicted.
                                    let root_entry = root_entries.remove(&path).unwrap();
                                    root_access_modes.remove(&path);
                                    if !Arc::ptr_eq(&entry, &root_entry) {
                                        root_entries.insert(path, root_entry);
                                        match Arc::into_inner(entry) {
                                            Some(EntryX::Lower { fd }) => Some(fd),
                                            Some(_) => unreachable!(),
                                            None => None,
                                        }
                                    } else {
                                        assert!(matches!(*root_entry, EntryX::Lower { .. }));
                                        drop(root_entry);
                                        // We are now assured that we can close out the underlying file; we are the only
                                        // holder of the entry, and then close it out.
                                        let EntryX::Lower { fd, .. } =
                                            Arc::into_inner(entry).unwrap()
                                        else {
                                            unreachable!()
                                        };
                                        Some(fd)
                                    }
                                }
                                EntryX::Tombstone => {
                                    // A tombstone here means that the root doesn't contain the entry. There may
                                    // possibly be other FDs opened for the same file before it was tombstoned
                                    // out, so we'll close it out if we are the sole remaining holder;
                                    // otherwise, it will be someone else's job to do so.
                                    match Arc::into_inner(entry) {
                                        Some(EntryX::Upper { .. } | EntryX::Tombstone) => {
                                            unreachable!()
                                        }
                                        Some(EntryX::Lower { fd }) => Some(fd),
                                        None => None,
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }; // write lock released here

        // Perform the lower-level close OUTSIDE the RootDir lock.
        // This prevents deadlock when close()'s 9P round-trip blocks
        // while other threads need the RootDir lock for open().
        match deferred_close {
            Some(fd) => self.lower.close(&fd, descriptors),
            None => Ok(()),
        }
    }

    fn read(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        buf: &mut [u8],
        offset: Option<usize>,
        descriptors: &Descriptors<Platform>,
    ) -> Result<usize, ReadError> {
        // Since a write to a lower-level file upgrades the underlying entry out completely to an
        // upper-level file, we don't actually need to worry about a desync; a write to lower-level
        // file will successfully be seen as just being an upper level file. Thus, it is sufficient
        // just to delegate this operation based whether the entry points to upper or lower layers.
        let entry = descriptors
            .with_entry(fd, |descriptor| {
                if !descriptor.entry.flags.contains(OFlags::RDONLY)
                    && !descriptor.entry.flags.contains(OFlags::RDWR)
                {
                    Err(ReadError::NotForReading)
                } else {
                    Ok(Arc::clone(&descriptor.entry.entry))
                }
            })
            .ok_or(ReadError::ClosedFd)
            .flatten()?;
        // Perform the actual operation
        let num_bytes = match entry.as_ref() {
            EntryX::Upper { fd: upper_fd } => {
                self.upper.read(upper_fd, buf, offset, descriptors)?
            }
            EntryX::Lower { fd: lower_fd } => {
                // Lower-layer file descriptors are shared across all opens of the same
                // path (see the `EntryX::Lower` fast-path in `open`). We must always
                // provide an explicit offset to the lower layer so concurrent readers
                // don't corrupt each other's positions.
                let lower_offset = offset.unwrap_or_else(|| {
                    descriptors
                        .get_entry(fd)
                        .map_or(0, |e| e.entry.position.load(SeqCst))
                });
                self.lower
                    .read(lower_fd, buf, Some(lower_offset), descriptors)?
            }
            EntryX::Tombstone => unreachable!(),
        };
        if offset.is_none() {
            descriptors
                .get_entry(fd)
                .ok_or(ReadError::ClosedFd)?
                .entry
                .position
                .fetch_add(num_bytes, SeqCst);
        }
        Ok(num_bytes)
    }

    fn write(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        buf: &[u8],
        offset: Option<usize>,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<usize, WriteError> {
        // Writing needs to be careful of how it is performing the write. Any upper-level file can
        // instantly be written to; but a lower-level file must become a upper-level file, before
        // actually being written to.
        let (entry, path) = descriptors
            .with_entry(fd, |descriptor| {
                if !descriptor.entry.flags.contains(OFlags::WRONLY)
                    && !descriptor.entry.flags.contains(OFlags::RDWR)
                {
                    Err(WriteError::NotForWriting)
                } else {
                    Ok((
                        Arc::clone(&descriptor.entry.entry),
                        descriptor.entry.path.clone(),
                    ))
                }
            })
            .ok_or(WriteError::ClosedFd)
            .flatten()?;
        match entry.as_ref() {
            EntryX::Upper { fd: upper_fd } => {
                let num_bytes = self.upper.write(upper_fd, buf, offset, descriptors)?;
                descriptors
                    .get_entry(fd)
                    .unwrap()
                    .entry
                    .position
                    .fetch_add(num_bytes, SeqCst);
                return Ok(num_bytes);
            }
            EntryX::Lower { fd: lower_fd } => {
                match self.layering_semantics {
                    LayeringSemantics::LowerLayerReadOnly => {
                        // fallthrough
                    }
                    LayeringSemantics::LowerLayerWritableFiles => {
                        // Allow direct write to lower layer
                        let num_bytes = self.lower.write(lower_fd, buf, offset, descriptors)?;
                        if let Some(e) = descriptors.get_entry(fd) {
                            e.entry.position.fetch_add(num_bytes, SeqCst);
                        }
                        return Ok(num_bytes);
                    }
                }
            }
            EntryX::Tombstone => unreachable!(),
        }
        // Change it to an upper-level file, also altering the file descriptor.
        drop(entry);
        match self.migrate_file_up(&path, true, descriptors) {
            Ok(()) => {}
            Err(MigrationError::NoReadPerms) => unimplemented!(),
            Err(MigrationError::NotAFile) => return Err(WriteError::NotAFile),
            Err(MigrationError::Io) => return Err(WriteError::Io),
            Err(MigrationError::PathError(_e)) => unreachable!(),
        }
        // As a sanity check, in debug mode, confirm that it is now an upper file
        debug_assert!(matches!(
            *descriptors.get_entry(fd).unwrap().entry.entry,
            EntryX::Upper { .. }
        ));
        // Since it has been migrated, we can just re-trigger, causing it to apply to the
        // upper layer
        <Self as super::FileSystem>::write(self, fd, buf, offset, descriptors)
    }

    fn seek(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        offset: isize,
        whence: SeekWhence,
        descriptors: &Descriptors<Platform>,
    ) -> Result<usize, SeekError> {
        let entry = descriptors
            .with_entry(fd, |descriptor| Arc::clone(&descriptor.entry.entry))
            .ok_or(SeekError::ClosedFd)?;
        // Perform the seek, and update the position info
        let position = match entry.as_ref() {
            EntryX::Upper { fd: upper_fd } => {
                self.upper.seek(upper_fd, offset, whence, descriptors)?
            }
            EntryX::Lower { fd: lower_fd } => {
                // For lower-layer files the underlying fd is shared across all opens
                // of the same path. Translate SEEK_CUR into SEEK_SET using our own
                // tracked position so concurrent seekers don't interfere.
                match whence {
                    SeekWhence::RelativeToCurrentOffset => {
                        let cur = descriptors
                            .get_entry(fd)
                            .map_or(0, |e| e.entry.position.load(SeqCst));
                        let effective_offset = isize::try_from(cur)
                            .ok()
                            .and_then(|c| c.checked_add(offset));
                        match effective_offset {
                            Some(o) => self.lower.seek(
                                lower_fd,
                                o,
                                SeekWhence::RelativeToBeginning,
                                descriptors,
                            )?,
                            None => return Err(SeekError::InvalidOffset),
                        }
                    }
                    _ => self.lower.seek(lower_fd, offset, whence, descriptors)?,
                }
            }
            EntryX::Tombstone => unreachable!(),
        };
        if let Some(e) = descriptors.get_entry(fd) {
            e.entry.position.store(position, SeqCst);
        }
        Ok(position)
    }

    fn truncate(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        length: usize,
        reset_offset: bool,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), TruncateError> {
        let (flags, entry) = descriptors
            .with_entry(fd, |descriptor| {
                (descriptor.entry.flags, Arc::clone(&descriptor.entry.entry))
            })
            .ok_or(TruncateError::ClosedFd)?;
        let layered_fd = fd;
        match entry.as_ref() {
            EntryX::Upper { fd } => self.upper.truncate(fd, length, reset_offset, descriptors),
            EntryX::Lower { fd } => {
                match self.layering_semantics {
                    LayeringSemantics::LowerLayerWritableFiles => {
                        self.lower.truncate(fd, length, reset_offset, descriptors)
                    }
                    LayeringSemantics::LowerLayerReadOnly => {
                        if flags.contains(OFlags::WRONLY) || flags.contains(OFlags::RDWR) {
                            // We might need to migrate the file up
                            match self.lower.truncate(fd, length, reset_offset, descriptors) {
                                Ok(()) | Err(TruncateError::ClosedFd) => unreachable!(),
                                Err(TruncateError::IsDirectory) => Err(TruncateError::IsDirectory),
                                Err(TruncateError::IsTerminalDevice) => {
                                    Err(TruncateError::IsTerminalDevice)
                                }
                                Err(TruncateError::NotForWriting) => {
                                    // We must actually migrate this file up, and keep it truncated.
                                    //
                                    // We must first drop the cloned entry to make sure that the ref
                                    // counting works out correctly during migration.
                                    drop(entry);
                                    let path = descriptors
                                        .with_entry(layered_fd, |descriptor| {
                                            descriptor.entry.path.clone()
                                        })
                                        .ok_or(TruncateError::ClosedFd)?;
                                    match self.migrate_file_up(&path, false, descriptors) {
                                        Ok(()) => Ok(()),
                                        Err(MigrationError::Io | _) => Err(TruncateError::Io),
                                    }
                                }
                                Err(TruncateError::Io) => Err(TruncateError::Io),
                            }
                        } else {
                            // The lower level truncate will correctly identify dir/file and handle
                            // the difference in erroring.
                            self.lower.truncate(fd, length, reset_offset, descriptors)
                        }
                    }
                }
            }
            EntryX::Tombstone => unreachable!(),
        }
    }

    fn chmod(&self, path: impl crate::path::Arg, mode: Mode) -> Result<(), ChmodError> {
        let path = self.absolute_path(path)?;
        match self.upper.chmod(path.as_str(), mode) {
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
                ChmodError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                ) => {
                    // fallthrough to lower
                }
            },
        }
        // A tombstoned path is visibly absent in the layered namespace even
        // though the hidden lower entry still physically exists.
        if self
            .root
            .read()
            .entries
            .get(&*path)
            .is_some_and(|e| matches!(e.as_ref(), EntryX::Tombstone))
        {
            return Err(ChmodError::PathError(PathError::NoSuchFileOrDirectory));
        }
        match self.ensure_lower_contains(&path) {
            Ok(_) => {}
            Err(FileStatusError::Io | FileStatusError::SymlinkLoop) => return Err(ChmodError::Io),
            Err(FileStatusError::PathError(e)) => return Err(ChmodError::PathError(e)),
            Err(FileStatusError::ClosedFd | FileStatusError::NotADirectory) => unreachable!(),
        }
        if matches!(
            self.layering_semantics,
            LayeringSemantics::LowerLayerWritableFiles
        ) {
            return self.lower.chmod(path.as_str(), mode);
        }
        let mut descriptors = self.litebox.descriptor_table_mut();
        match self.migrate_file_up(&path, true, &mut *descriptors) {
            Ok(()) => {}
            Err(MigrationError::NoReadPerms) => unimplemented!(),
            Err(MigrationError::NotAFile) => unimplemented!(),
            Err(MigrationError::Io) => return Err(ChmodError::Io),
            Err(MigrationError::PathError(_e)) => unreachable!(),
        }
        // Since it has been migrated, we can just re-trigger, causing it to apply to the
        // upper layer
        drop(descriptors);
        self.chmod(path, mode)
    }

    fn chown(
        &self,
        path: impl crate::path::Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = self.absolute_path(path)?;
        match self.upper.chown(path.as_str(), user, group) {
            Ok(()) => return Ok(()),
            Err(e) => match e {
                ChownError::NotTheOwner
                | ChownError::Io
                | ChownError::ReadOnlyFileSystem
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
                    // fallthrough to lower
                }
            },
        }
        // A tombstoned path is visibly absent in the layered namespace even
        // though the hidden lower entry still physically exists.
        if self
            .root
            .read()
            .entries
            .get(&*path)
            .is_some_and(|e| matches!(e.as_ref(), EntryX::Tombstone))
        {
            return Err(ChownError::PathError(PathError::NoSuchFileOrDirectory));
        }
        match self.ensure_lower_contains(&path) {
            Ok(_) => {}
            Err(FileStatusError::Io | FileStatusError::SymlinkLoop) => return Err(ChownError::Io),
            Err(FileStatusError::PathError(e)) => return Err(ChownError::PathError(e)),
            Err(FileStatusError::ClosedFd | FileStatusError::NotADirectory) => unreachable!(),
        }
        if matches!(
            self.layering_semantics,
            LayeringSemantics::LowerLayerWritableFiles
        ) {
            return self.lower.chown(path.as_str(), user, group);
        }
        let mut descriptors = self.litebox.descriptor_table_mut();
        match self.migrate_file_up(&path, true, &mut *descriptors) {
            Ok(()) => {}
            Err(MigrationError::NoReadPerms) => unimplemented!(),
            Err(MigrationError::NotAFile) => unimplemented!(),
            Err(MigrationError::Io) => return Err(ChownError::Io),
            Err(MigrationError::PathError(_e)) => unreachable!(),
        }
        // Since it has been migrated, we can just re-trigger, causing it to apply to the
        // upper layer
        drop(descriptors);
        self.chown(path, user, group)
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), UnlinkError> {
        let path = self.absolute_path(path)?;
        match self.upper.unlink(path.as_str()) {
            Ok(()) => {
                // If the lower level contains the file, then we need to place a tombstone in its
                // path, to prevent the lower level from showing up above.
                if self.ensure_lower_contains(&path).is_ok() {
                    // fallthrough to place the tombstone
                } else {
                    // Lower level doesn't contain it, we are done (with success, since we actually
                    // removed the file).
                    return Ok(());
                }
            }
            Err(e) => match e {
                UnlinkError::NoWritePerms
                | UnlinkError::Io
                | UnlinkError::IsADirectory
                | UnlinkError::ReadOnlyFileSystem
                | UnlinkError::ClosedFd
                | UnlinkError::NotADirectory
                | UnlinkError::PathError(
                    PathError::ComponentNotADirectory
                    | PathError::InvalidPathname
                    | PathError::NoSearchPerms { .. },
                ) => {
                    return Err(e);
                }
                UnlinkError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                ) => {
                    // We must now check if the lower level contains the file; if it does not, we
                    // must exit with failure. Otherwise, we fallthrough to place the tombstone.
                    match self.ensure_lower_contains(&path).map_err(|e| match e {
                        FileStatusError::Io | FileStatusError::SymlinkLoop => UnlinkError::Io,
                        FileStatusError::PathError(p) => UnlinkError::PathError(p),
                        FileStatusError::ClosedFd | FileStatusError::NotADirectory => {
                            unreachable!()
                        }
                    })? {
                        FileType::RegularFile | FileType::Symlink => {
                            // fallthrough
                        }
                        FileType::Directory => {
                            return Err(UnlinkError::IsADirectory);
                        }
                        FileType::CharacterDevice => unimplemented!(),
                    }
                }
            },
        }
        if let LayeringSemantics::LowerLayerReadOnly = self.layering_semantics {
            // Read-only lower: tombstone hides the file without modifying
            // the lower layer.
            self.root
                .write()
                .entries
                .insert(path, Arc::new(EntryX::Tombstone));
        } else {
            // Writable lower: actually remove from the lower layer so that
            // a subsequent rmdir on the parent directory succeeds.
            if let Err(e) = self.lower.unlink(path.as_str()) {
                match e {
                    UnlinkError::PathError(
                        PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                    ) => {
                        // File only existed on upper — already removed above.
                    }
                    _ => return Err(e),
                }
            }
        }
        Ok(())
    }

    fn rename(
        &self,
        old_path: impl crate::path::Arg,
        new_path: impl crate::path::Arg,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), RenameError> {
        let old = self.absolute_path(old_path)?;
        let new = self.absolute_path(new_path)?;

        if old == new {
            return Ok(());
        }

        // Block rename if the source is tombstoned (deleted from view).
        // Also check if the destination is tombstoned — a tombstoned path
        // is visibly absent in the layered namespace even though the lower
        // entry still physically exists. This affects cross-layer EXDEV
        // decisions: a tombstoned lower destination is not a live cross-
        // layer target.
        let new_is_tombstoned;
        {
            let root = self.root.read();
            if let Some(entry) = root.entries.get(&old)
                && matches!(entry.as_ref(), EntryX::Tombstone)
            {
                return Err(RenameError::PathError(PathError::NoSuchFileOrDirectory));
            }
            new_is_tombstoned = root
                .entries
                .get(&new)
                .is_some_and(|e| matches!(e.as_ref(), EntryX::Tombstone));
        }

        // When LowerLayerWritableFiles, try the lower layer first so renames
        // of host-persisted files stay on the lower layer.
        if matches!(
            self.layering_semantics,
            LayeringSemantics::LowerLayerWritableFiles
        ) {
            // Check upper status for both paths, propagating hard ancestor
            // errors (ComponentNotADirectory, NoSearchPerms, etc.) that
            // visible lookup would also reject.
            let old_on_upper = match self.upper.file_status(&*old) {
                Ok(_) => true,
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => false,
                Err(FileStatusError::PathError(p)) => return Err(RenameError::PathError(p)),
                Err(_) => return Err(RenameError::Io),
            };
            let new_on_upper = match self.upper.file_status(&*new) {
                Ok(_) => true,
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => false,
                Err(FileStatusError::PathError(p)) => return Err(RenameError::PathError(p)),
                Err(_) => return Err(RenameError::Io),
            };

            if !old_on_upper {
                // Source is not on upper — must be on lower.
                // Verify source exists on lower, propagating hard errors.
                match self.lower.file_status(&*old) {
                    Ok(_) => {}
                    Err(FileStatusError::PathError(
                        PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                    )) => {
                        // Source not on lower either — upper.rename will
                        // produce the appropriate ENOENT.
                        return self.upper.rename(old.as_str(), new.as_str(), descriptors);
                    }
                    Err(FileStatusError::PathError(p)) => return Err(RenameError::PathError(p)),
                    Err(_) => return Err(RenameError::Io),
                }

                if new_on_upper {
                    // Cross-layer rename: source on lower, destination on
                    // upper. Return EXDEV so callers fall back to
                    // copy + delete (which every POSIX program already
                    // handles for cross-mount renames).
                    //
                    // Why not attempt the rename directly?
                    //
                    // The lower backend (in-mem or 9P) can destroy a hidden
                    // lower destination as part of rename, and there is no
                    // way to atomically clean up the upper shadow in the
                    // same operation. Any multi-step approach (park upper
                    // dest, lower rename, cleanup parked entry) has failure
                    // modes where rollback cannot fully restore hidden
                    // state. See docs/litebox/design/layered-rename-codex.md
                    // for a detailed analysis.
                    //
                    // TODO: Implement OverrideEntry::RedirectLower in the
                    // layered namespace so cross-layer rename can be
                    // expressed as a metadata transaction without immediate
                    // lower mutation. Until then, EXDEV is the safe choice.
                    return Err(RenameError::CrossDevice);
                }

                // No upper shadow on destination — pure lower rename.
                // If the destination is tombstoned, the lower backend still
                // has the hidden entry. Park it at a temp path so
                // lower.rename doesn't validate type/emptiness against an
                // invisible entry. If the rename fails, restore the hidden
                // entry from temp so no hidden state is lost.
                let tombstone_saved = if new_is_tombstoned && self.lower.file_status(&*new).is_ok()
                {
                    static TOMB_COUNTER: AtomicUsize = AtomicUsize::new(0);
                    let parent_dir = {
                        let p = new.rsplit_once('/').map_or("/", |(p, _)| p);
                        if p.is_empty() { "/" } else { p }
                    };
                    let tmp = loop {
                        let n = TOMB_COUNTER.fetch_add(1, SeqCst);
                        let c = alloc::format!("{parent_dir}/.litebox_ts_{n:x}");
                        if self.lower.file_status(&c).is_err() {
                            break c;
                        }
                    };
                    self.lower
                        .rename(new.as_str(), &tmp, descriptors)
                        .ok()
                        .map(|()| tmp)
                } else {
                    None
                };

                match self.lower.rename(old.as_str(), new.as_str(), descriptors) {
                    Ok(()) => {
                        // Clean up the saved hidden entry (best-effort).
                        if let Some(ref ts) = tombstone_saved
                            && self.lower.unlink(ts.as_str()).is_err()
                        {
                            let _ = self.lower.rmdir(ts.as_str());
                        }
                        let mut root = self.root.write();
                        Self::invalidate_cache_tree(&mut root, &old);
                        Self::invalidate_cache_tree(&mut root, &new);
                        return Ok(());
                    }
                    Err(e) => {
                        // Restore the hidden lower entry on failure.
                        if let Some(ref ts) = tombstone_saved {
                            let _ = self.lower.rename(ts.as_str(), new.as_str(), descriptors);
                        }
                        return Err(e);
                    }
                }
            }
            // old_on_upper: visible source is on upper.
            // Check if destination exists only on lower — that's also
            // cross-layer and needs EXDEV for the same reasons. But skip
            // the check if the destination is tombstoned (visibly absent).
            if !new_on_upper && !new_is_tombstoned {
                let new_on_lower = match self.lower.file_status(&*new) {
                    Ok(_) => true,
                    Err(FileStatusError::PathError(
                        PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                    )) => false,
                    Err(FileStatusError::PathError(p)) => return Err(RenameError::PathError(p)),
                    Err(_) => return Err(RenameError::Io),
                };
                if new_on_lower {
                    // Cross-layer rename: source on upper, destination on
                    // lower. The upper rename can't see or validate the
                    // visible lower destination (type compatibility,
                    // emptiness), and would leave stale lower cache entries.
                    // Same rationale as the lower→upper EXDEV above.
                    return Err(RenameError::CrossDevice);
                }
            }
            // Both on upper (or new doesn't exist anywhere) — safe to
            // delegate to upper.rename().
        }

        self.upper.rename(old.as_str(), new.as_str(), descriptors)?;
        // Clear any tombstone or stale cache at the destination so the
        // renamed entry is visible through layered lookup.
        let mut root = self.root.write();
        Self::invalidate_cache_tree(&mut root, &old);
        Self::invalidate_cache_tree(&mut root, &new);
        Ok(())
    }

    fn mkdir(&self, path: impl crate::path::Arg, mode: Mode) -> Result<(), MkdirError> {
        let path = self.absolute_path(path)?;
        if self.has_tombstoned_ancestor(&path)? {
            return Err(PathError::NoSuchFileOrDirectory)?;
        }
        // When LowerLayerWritableFiles, try lower layer first so directories
        // persist on the host. Fall back to upper if lower can't create.
        // But first, check upper for conflicts: if the path already exists,
        // reject with AlreadyExists; if an ancestor is invalid (non-dir,
        // no search perms), propagate that error instead of creating on lower.
        if matches!(
            self.layering_semantics,
            LayeringSemantics::LowerLayerWritableFiles
        ) {
            match self.upper.file_status(path.as_str()) {
                Ok(_) => return Err(MkdirError::AlreadyExists),
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => {}
                Err(FileStatusError::PathError(p)) => return Err(MkdirError::PathError(p)),
                Err(_) => return Err(MkdirError::Io),
            }
            match self.lower.mkdir(path.as_str(), mode) {
                Ok(()) => return Ok(()),
                Err(
                    MkdirError::PathError(
                        PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                    )
                    | MkdirError::ReadOnlyFileSystem
                    | MkdirError::Io,
                ) => {
                    // Parent doesn't exist on lower, or lower had a
                    // transport error — fall through to upper.
                }
                Err(e) => return Err(e),
            }
        }
        match self.upper.mkdir(path.as_str(), mode) {
            Ok(()) => {
                // If we could successfully make the directory, we know that things are "sane" at
                // the upper level, but we must also check the lower level to make sure that this
                // directory didn't already exist.
                if self.ensure_lower_contains(&path).is_ok() {
                    return Err(MkdirError::AlreadyExists);
                }
                return Ok(());
            }
            Err(e) => match e {
                MkdirError::NoWritePerms
                | MkdirError::AlreadyExists
                | MkdirError::ReadOnlyFileSystem
                | MkdirError::PathError(
                    PathError::ComponentNotADirectory
                    | PathError::InvalidPathname
                    | PathError::NoSearchPerms { .. },
                ) => {
                    return Err(e);
                }
                MkdirError::PathError(PathError::NoSuchFileOrDirectory) => {
                    unreachable!()
                }
                MkdirError::PathError(PathError::MissingComponent) | MkdirError::Io => {
                    // MissingComponent: ancestor only exists on lower,
                    // needs migration. Io: nested layered FS couldn't
                    // resolve the path. Both cases fall through to
                    // ancestor migration.
                }
            },
        }
        // We know that at least one of the components is missing. We should check each of the
        // components individually, making directories for any components that already exist at the
        // lower layer, and erroring out if no lower layer component exists of that form.
        self.mkdir_migrating_ancestor_dirs(&path)?;
        // And then now we can make the upper directory.
        self.upper.mkdir(path, mode)
    }

    fn symlink(
        &self,
        target: impl crate::path::Arg,
        linkpath: impl crate::path::Arg,
    ) -> Result<(), SymlinkError> {
        let target = target
            .as_rust_str()
            .map_err(|e| SymlinkError::PathError(e.into()))?;
        let path = self.absolute_path(linkpath)?;
        if self.has_tombstoned_ancestor(&path)? {
            return Err(PathError::NoSuchFileOrDirectory)?;
        }

        if matches!(
            self.layering_semantics,
            LayeringSemantics::LowerLayerWritableFiles
        ) {
            match self.upper.file_status(path.as_str()) {
                Ok(_) => return Err(SymlinkError::AlreadyExists),
                Err(FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )) => {}
                Err(FileStatusError::PathError(p)) => return Err(SymlinkError::PathError(p)),
                Err(_) => return Err(SymlinkError::Io),
            }
            match self.lower.symlink(target, path.as_str()) {
                Ok(()) => {
                    let mut root = self.root.write();
                    Self::invalidate_cache_tree(&mut root, &path);
                    return Ok(());
                }
                Err(
                    SymlinkError::PathError(
                        PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                    )
                    | SymlinkError::ReadOnlyFileSystem
                    | SymlinkError::NotSupported
                    | SymlinkError::Io,
                ) => {}
                Err(e) => return Err(e),
            }
        }

        match self.upper.symlink(target, path.as_str()) {
            Ok(()) => {
                let mut root = self.root.write();
                Self::invalidate_cache_tree(&mut root, &path);
                return Ok(());
            }
            Err(e) => match e {
                SymlinkError::NoWritePerms
                | SymlinkError::AlreadyExists
                | SymlinkError::ReadOnlyFileSystem
                | SymlinkError::NotSupported
                | SymlinkError::PathError(
                    PathError::ComponentNotADirectory
                    | PathError::InvalidPathname
                    | PathError::NoSearchPerms { .. },
                ) => return Err(e),
                SymlinkError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                )
                | SymlinkError::Io => {}
            },
        }

        self.mkdir_migrating_ancestor_dirs(&path)
            .map_err(|e| match e {
                MkdirError::AlreadyExists => SymlinkError::AlreadyExists,
                MkdirError::ReadOnlyFileSystem => SymlinkError::ReadOnlyFileSystem,
                MkdirError::NoWritePerms => SymlinkError::NoWritePerms,
                MkdirError::Io => SymlinkError::Io,
                MkdirError::PathError(p) => SymlinkError::PathError(p),
            })?;
        let result = self.upper.symlink(target, path.as_str());
        if result.is_ok() {
            let mut root = self.root.write();
            Self::invalidate_cache_tree(&mut root, &path);
        }
        result
    }

    fn rmdir(&self, path: impl crate::path::Arg) -> Result<(), RmdirError> {
        let path = self.absolute_path(path)?;

        // Prevent removing root explicitly (even if upper is empty).
        if path == "/" {
            return Err(RmdirError::Busy);
        }

        let mut descriptors = self.litebox.descriptor_table_mut();
        let dir_fd = match <Self as super::FileSystem>::open(
            self,
            path.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
            &mut *descriptors,
        ) {
            Ok(fd) => fd,
            Err(e) => match e {
                OpenError::PathError(PathError::ComponentNotADirectory) => {
                    return Err(RmdirError::NotADirectory);
                }
                OpenError::PathError(pe) => return Err(pe.into()),
                OpenError::AccessNotAllowed => todo!(),
                OpenError::Io => return Err(RmdirError::Io),
                OpenError::ReadOnlyFileSystem => {
                    return Err(RmdirError::ReadOnlyFileSystem);
                }
                OpenError::NoWritePerms
                | OpenError::AlreadyExists
                | OpenError::ClosedFd
                | OpenError::NotADirectory
                | OpenError::Interrupted
                | OpenError::TruncateError(_) => {
                    unreachable!()
                }
            },
        };
        let entries = match <Self as super::FileSystem>::read_dir(self, &dir_fd, &mut *descriptors)
        {
            Ok(entries) => entries,
            Err(ReadDirError::ClosedFd | ReadDirError::NotADirectory) => unreachable!(),
            Err(ReadDirError::Io) => return Err(RmdirError::Io),
        };
        <Self as super::FileSystem>::close(self, &dir_fd, &mut *descriptors)
            .map_err(|_| RmdirError::Io)?;
        // "." and ".." are always present; anything more => not empty.
        if entries.len() > 2 {
            return Err(RmdirError::NotEmpty);
        }

        // blindly rmdir at upper layer, suppressing non-existence errors.
        if let Err(e) = self.upper.rmdir(path.as_str()) {
            match e {
                RmdirError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                ) => {
                    // fallthrough
                }
                RmdirError::NotEmpty
                | RmdirError::NotADirectory
                | RmdirError::ReadOnlyFileSystem
                | RmdirError::PathError(
                    PathError::ComponentNotADirectory | PathError::InvalidPathname,
                ) => unreachable!(),
                RmdirError::Busy
                | RmdirError::NoWritePerms
                | RmdirError::Io
                | RmdirError::PathError(PathError::NoSearchPerms { .. }) => return Err(e),
            }
        }

        if let LayeringSemantics::LowerLayerReadOnly = self.layering_semantics {
            self.root
                .write()
                .entries
                .insert(path, Arc::new(EntryX::Tombstone));
        } else {
            // If lower layer is writable, we can just rmdir there too, suppressing non-existence errors.
            if let Err(e) = self.lower.rmdir(path.as_str()) {
                match e {
                    RmdirError::PathError(
                        PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                    ) => {
                        // Dir doesn't exist on lower — fine, it only existed on upper.
                    }
                    // The lower rmdir can legitimately fail: the directory
                    // may not be empty on lower (lower-only children), or
                    // the lower path may not be a directory.
                    _ => return Err(e),
                }
            }
        }
        Ok(())
    }

    fn read_dir(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<Vec<DirEntry>, ReadDirError> {
        let (entry, path) = descriptors
            .with_entry(fd, |descriptor| {
                (
                    Arc::clone(&descriptor.entry.entry),
                    descriptor.entry.path.clone(),
                )
            })
            .ok_or(ReadDirError::ClosedFd)?;

        let mut entries = match entry.as_ref() {
            EntryX::Upper { fd } => {
                // Get entries from upper layer
                let mut upper_entries = self.upper.read_dir(fd, descriptors)?;

                // Try to get entries from lower layer for the same path
                if let Ok(lower_fd) =
                    self.lower
                        .open(path.as_str(), OFlags::RDONLY, Mode::empty(), descriptors)
                {
                    if let Ok(lower_entries) = self.lower.read_dir(&lower_fd, descriptors) {
                        // Merge entries, avoiding duplicates (upper layer takes precedence)
                        let upper_names: HashSet<String> =
                            upper_entries.iter().map(|e| e.name.clone()).collect();

                        let root = self.root.read();
                        for lower_entry in lower_entries {
                            if upper_names.contains(&lower_entry.name) {
                                continue;
                            }
                            // Skip tombstoned entries — they are visibly deleted.
                            let child_path = if path == "/" {
                                alloc::format!("/{}", lower_entry.name)
                            } else {
                                alloc::format!("{}/{}", path, lower_entry.name)
                            };
                            if root
                                .entries
                                .get(&child_path)
                                .is_some_and(|e| matches!(e.as_ref(), EntryX::Tombstone))
                            {
                                continue;
                            }
                            upper_entries.push(lower_entry);
                        }
                    }
                    let _ = self.lower.close(&lower_fd, descriptors);
                }

                upper_entries
            }
            EntryX::Lower { fd } => {
                // Lower-only directory: still need to filter tombstoned children.
                let mut lower_entries = self.lower.read_dir(fd, descriptors)?;
                let root = self.root.read();
                lower_entries.retain(|e| {
                    let child_path = if path == "/" {
                        alloc::format!("/{}", e.name)
                    } else {
                        alloc::format!("{}/{}", path, e.name)
                    };
                    !root
                        .entries
                        .get(&child_path)
                        .is_some_and(|e| matches!(e.as_ref(), EntryX::Tombstone))
                });
                lower_entries
            }
            EntryX::Tombstone => unreachable!(),
        };

        for e in &mut entries {
            if let Some(ni) = e.ino_info.take() {
                e.ino_info = Some(self.get_layered_nodeinfo(ni));
            }
        }
        Ok(entries)
    }

    fn file_status(&self, path: impl crate::path::Arg) -> Result<FileStatus, FileStatusError> {
        let descriptors = self.litebox.descriptor_table();
        self.file_status_with_descriptors(path, &*descriptors)
    }

    fn fd_file_status(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        descriptors: &Descriptors<Platform>,
    ) -> Result<FileStatus, FileStatusError> {
        let entry = descriptors
            .with_entry(fd, |descriptor| Arc::clone(&descriptor.entry.entry))
            .ok_or(FileStatusError::ClosedFd)?;
        let FileStatus {
            file_type,
            mode,
            size,
            owner,
            node_info,
            blksize,
        } = match entry.as_ref() {
            EntryX::Upper { fd } => self.upper.fd_file_status(fd, descriptors)?,
            EntryX::Lower { fd } => self.lower.fd_file_status(fd, descriptors)?,
            EntryX::Tombstone => unreachable!(),
        };
        // Note: we grab the info and then immediately spit back the same, essentially to ask the
        // compiler to remind us we need to update this when we support inodes and such.
        Ok(FileStatus {
            file_type,
            mode,
            size,
            owner,
            node_info: self.get_layered_nodeinfo(node_info),
            blksize,
        })
    }

    fn get_static_backing_data(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        descriptors: &Descriptors<Platform>,
    ) -> Option<&'static [u8]> {
        let entry = descriptors.with_entry(fd, |descriptor| Arc::clone(&descriptor.entry.entry))?;
        match entry.as_ref() {
            EntryX::Upper { fd } => self.upper.get_static_backing_data(fd, descriptors),
            EntryX::Lower { fd } => self.lower.get_static_backing_data(fd, descriptors),
            EntryX::Tombstone => unreachable!(),
        }
    }

    fn is_writable(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        descriptors: &Descriptors<Platform>,
    ) -> bool {
        descriptors
            .with_entry(fd, |descriptor| {
                descriptor
                    .entry
                    .flags
                    .intersects(OFlags::WRONLY | OFlags::RDWR)
            })
            .unwrap_or(false)
    }

    fn set_open_status_flags(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        flags: OFlags,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), MetadataError> {
        let entry = descriptors
            .with_entry(fd, |descriptor| Arc::clone(&descriptor.entry.entry))
            .ok_or(MetadataError::ClosedFd)?;
        match entry.as_ref() {
            EntryX::Upper { fd } => self.upper.set_open_status_flags(fd, flags, descriptors),
            EntryX::Lower { fd } => self.lower.set_open_status_flags(fd, flags, descriptors),
            EntryX::Tombstone => unreachable!(),
        }
    }

    fn get_io_pollable(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        descriptors: &Descriptors<Platform>,
    ) -> Option<alloc::boxed::Box<dyn crate::event::IOPollable>> {
        let entry = descriptors.with_entry(fd, |descriptor| Arc::clone(&descriptor.entry.entry))?;
        match entry.as_ref() {
            EntryX::Upper { fd } => self.upper.get_io_pollable(fd, descriptors),
            EntryX::Lower { fd } => self.lower.get_io_pollable(fd, descriptors),
            EntryX::Tombstone => None,
        }
    }

    fn read_link(
        &self,
        path: impl crate::path::Arg,
    ) -> Result<alloc::string::String, super::errors::ReadLinkError> {
        let path = self
            .absolute_path(path)
            .map_err(|_| super::errors::ReadLinkError::Io)?;
        if self
            .is_hidden_by_tombstone(&path)
            .map_err(super::errors::ReadLinkError::PathError)?
        {
            return Err(super::errors::ReadLinkError::PathError(
                super::errors::PathError::NoSuchFileOrDirectory,
            ));
        }

        match self.upper.file_status(&*path) {
            Ok(_) => {
                return match self.upper.read_link(&*path) {
                    Ok(target) => Ok(target),
                    Err(super::errors::ReadLinkError::NotSupported) => {
                        Err(super::errors::ReadLinkError::NotASymlink)
                    }
                    Err(e) => Err(e),
                };
            }
            Err(super::errors::FileStatusError::PathError(
                super::errors::PathError::NoSuchFileOrDirectory
                | super::errors::PathError::MissingComponent,
            )) => {
                // fall through to lower
            }
            Err(super::errors::FileStatusError::PathError(e)) => {
                return Err(super::errors::ReadLinkError::PathError(e));
            }
            Err(
                super::errors::FileStatusError::Io | super::errors::FileStatusError::SymlinkLoop,
            ) => {
                return Err(super::errors::ReadLinkError::Io);
            }
            Err(
                super::errors::FileStatusError::ClosedFd
                | super::errors::FileStatusError::NotADirectory,
            ) => {
                unreachable!()
            }
        }

        self.lower.read_link(path)
    }

    fn open_at(
        &self,
        dirfd: &FileFd<Platform, Upper, Lower>,
        rel_path: impl crate::path::Arg,
        flags: super::OFlags,
        mode: super::Mode,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<FileFd<Platform, Upper, Lower>, OpenError> {
        let dir = self.dir_fd_path(dirfd, descriptors).map_err(|e| match e {
            super::DirFdError::ClosedFd => OpenError::ClosedFd,
            super::DirFdError::NotADirectory => OpenError::NotADirectory,
            super::DirFdError::Io => OpenError::Io,
        })?;
        let rel = rel_path
            .as_rust_str()
            .map_err(|e| OpenError::PathError(e.into()))?;
        let abs = Self::resolve_relative(&dir, rel).map_err(OpenError::PathError)?;
        <Self as super::FileSystem>::open(self, abs, flags, mode, descriptors)
    }

    fn stat_at(
        &self,
        dirfd: &FileFd<Platform, Upper, Lower>,
        rel_path: impl crate::path::Arg,
        follow_symlinks: bool,
        descriptors: &Descriptors<Platform>,
    ) -> Result<super::FileStatus, super::FileStatusError> {
        let dir = self.dir_fd_path(dirfd, descriptors).map_err(|e| match e {
            super::DirFdError::ClosedFd => super::FileStatusError::ClosedFd,
            super::DirFdError::NotADirectory => super::FileStatusError::NotADirectory,
            super::DirFdError::Io => super::FileStatusError::Io,
        })?;
        let rel = rel_path
            .as_rust_str()
            .map_err(|e| super::FileStatusError::PathError(e.into()))?;
        let abs = Self::resolve_relative(&dir, rel).map_err(super::FileStatusError::PathError)?;
        // When following symlinks, resolve the full chain (up to 40 hops).
        // Relative targets are resolved against the symlink's parent
        // directory, not the process CWD.
        let resolved = if follow_symlinks {
            self.resolve_follow_symlinks(abs, 40)?
        } else {
            abs
        };
        self.file_status_with_descriptors(resolved, descriptors)
    }

    fn unlink_at(
        &self,
        dirfd: &FileFd<Platform, Upper, Lower>,
        rel_path: impl crate::path::Arg,
        descriptors: &Descriptors<Platform>,
    ) -> Result<(), UnlinkError> {
        let dir = self.dir_fd_path(dirfd, descriptors).map_err(|e| match e {
            super::DirFdError::ClosedFd => UnlinkError::ClosedFd,
            super::DirFdError::NotADirectory => UnlinkError::NotADirectory,
            super::DirFdError::Io => UnlinkError::Io,
        })?;
        let rel = rel_path
            .as_rust_str()
            .map_err(|e| UnlinkError::PathError(e.into()))?;
        let abs = Self::resolve_relative(&dir, rel).map_err(UnlinkError::PathError)?;
        self.unlink(abs)
    }

    fn readlink_at(
        &self,
        dirfd: &FileFd<Platform, Upper, Lower>,
        rel_path: impl crate::path::Arg,
        descriptors: &Descriptors<Platform>,
    ) -> Result<alloc::string::String, super::errors::ReadLinkError> {
        let dir = self.dir_fd_path(dirfd, descriptors).map_err(|e| match e {
            super::DirFdError::ClosedFd => super::errors::ReadLinkError::ClosedFd,
            super::DirFdError::NotADirectory => super::errors::ReadLinkError::NotADirectory,
            super::DirFdError::Io => super::errors::ReadLinkError::Io,
        })?;
        let rel = rel_path
            .as_rust_str()
            .map_err(|e| super::errors::ReadLinkError::PathError(e.into()))?;
        let abs =
            Self::resolve_relative(&dir, rel).map_err(super::errors::ReadLinkError::PathError)?;
        self.read_link(abs)
    }

    fn rename_at(
        &self,
        old_dirfd: &FileFd<Platform, Upper, Lower>,
        old_rel: impl crate::path::Arg,
        new_dirfd: &FileFd<Platform, Upper, Lower>,
        new_rel: impl crate::path::Arg,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), RenameError> {
        let old_dir = self
            .dir_fd_path(old_dirfd, descriptors)
            .map_err(|e| match e {
                super::DirFdError::ClosedFd => RenameError::ClosedFd,
                super::DirFdError::NotADirectory => RenameError::NotADirectory,
                super::DirFdError::Io => RenameError::Io,
            })?;
        let old_r = old_rel
            .as_rust_str()
            .map_err(|e| RenameError::PathError(e.into()))?;
        let old_abs = Self::resolve_relative(&old_dir, old_r).map_err(RenameError::PathError)?;
        let new_dir = self
            .dir_fd_path(new_dirfd, descriptors)
            .map_err(|e| match e {
                super::DirFdError::ClosedFd => RenameError::ClosedFd,
                super::DirFdError::NotADirectory => RenameError::NotADirectory,
                super::DirFdError::Io => RenameError::Io,
            })?;
        let new_r = new_rel
            .as_rust_str()
            .map_err(|e| RenameError::PathError(e.into()))?;
        let new_abs = Self::resolve_relative(&new_dir, new_r).map_err(RenameError::PathError)?;
        <Self as super::FileSystem>::rename(self, old_abs, new_abs, descriptors)
    }

    fn fd_path(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        descriptors: &Descriptors<Platform>,
    ) -> Option<alloc::string::String> {
        Self::descriptor_path(fd, descriptors)
    }

    fn mkdir_at(
        &self,
        dirfd: &FileFd<Platform, Upper, Lower>,
        rel_path: impl crate::path::Arg,
        mode: super::Mode,
        descriptors: &Descriptors<Platform>,
    ) -> Result<(), MkdirError> {
        let dir = self.dir_fd_path(dirfd, descriptors).map_err(|e| match e {
            super::DirFdError::NotADirectory => {
                MkdirError::PathError(PathError::ComponentNotADirectory)
            }
            super::DirFdError::ClosedFd | super::DirFdError::Io => MkdirError::Io,
        })?;
        let rel = rel_path
            .as_rust_str()
            .map_err(|e| MkdirError::PathError(e.into()))?;
        let abs = Self::resolve_relative(&dir, rel).map_err(MkdirError::PathError)?;
        self.mkdir(abs, mode)
    }
}

struct Descriptor<Upper: super::FileSystem + 'static, Lower: super::FileSystem + 'static> {
    path: String,
    flags: OFlags,
    entry: Entry<Upper, Lower>,
    position: AtomicUsize,
}

struct RootDir<Upper: super::FileSystem + 'static, Lower: super::FileSystem + 'static> {
    // keys are normalized paths; directories do not have the final `/` (thus the root would be at
    // the empty-string key "")
    //
    // Invariant: this only stores shareable lower+tombstone entries, no upper entries will show up
    // here.
    entries: HashMap<String, Entry<Upper, Lower>>,
    /// O_ACCMODE bits (0=RDONLY, 1=WRONLY, 2=RDWR) for cached lower entries,
    /// keyed by path. Used to detect incompatible cache hits (e.g., a WRONLY
    /// fid reused by an RDONLY open would cause 9P Tread to fail with EIO).
    lower_access_modes: HashMap<String, u32>,
}

impl<Upper: super::FileSystem, Lower: super::FileSystem> RootDir<Upper, Lower> {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            lower_access_modes: HashMap::new(),
        }
    }
}

type Entry<Upper, Lower> = Arc<EntryX<Upper, Lower>>;

enum EntryX<Upper: super::FileSystem + 'static, Lower: super::FileSystem + 'static> {
    // This file should be considered a purely upper-level file, independent of whether lower level file exists or not.
    Upper { fd: TypedFd<Upper> },
    // This file is a lower-level file and does NOT exist in the upper level file.
    Lower { fd: TypedFd<Lower> },
    // This file exists in the lower level, but as far as the layered architecture is concerned,
    // this is marked as deleted. RIP (x_x)
    Tombstone,
}

impl<Upper: super::FileSystem + 'static, Lower: super::FileSystem + 'static> core::fmt::Debug
    for EntryX<Upper, Lower>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Upper { fd: _ } => f.debug_struct("Upper").finish_non_exhaustive(),
            Self::Lower { fd: _ } => f.debug_struct("Lower").finish_non_exhaustive(),
            Self::Tombstone => write!(f, "Tombstone"),
        }
    }
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { sync::RawSyncPrimitivesProvider }, Upper: { super::FileSystem<DescriptorPlatform = Platform> + 'static }, Lower: { super::FileSystem<DescriptorPlatform = Platform> + 'static };
    FileSystem<Platform, Upper, Lower>;
    @Upper: { super::FileSystem + 'static }, Lower: { super::FileSystem + 'static };
    Descriptor<Upper, Lower>;
    crate::fd::SubsystemKind::Fs;
    -> FileFd<Platform, Upper, Lower>;
}
