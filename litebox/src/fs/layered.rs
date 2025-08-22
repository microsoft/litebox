//! An layered file system, layering on [`FileSystem`](super::FileSystem) on top of another.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use hashbrown::{HashMap, HashSet};

use crate::LiteBox;
use crate::fd::{InternalFd, TypedFd};
use crate::path::Arg;
use crate::sync;

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RmdirError, SeekError, UnlinkError, WriteError,
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
    /// No new files can be made at the lower layer, but any existing files in the lower layer can
    /// still be written to. If an upper level file exists with the same name as a lower layer file,
    /// then it is shadowed, and only the upper layer file would be visible.
    LowerLayerWritableFiles,
}

/// A backing implementation of [`FileSystem`](super::FileSystem) that layers a file system on top
/// of another.
///
/// This particular implementation itself doesn't carry or store any of the files, but delegates to
/// each of the the layers. Specifically, this implementation will look for and work with files in
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
    // TODO: Possibly support a single-threaded variant that doesn't have the cost of requiring a
    // sync-primitives platform, as well as cost of mutexes and such?
    root: sync::RwLock<Platform, RootDir<Upper, Lower>>,
    layering_semantics: LayeringSemantics,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
    node_info_lookup: sync::RwLock<Platform, HashMap<NodeInfo, usize>>,
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
        let sync = litebox.sync();
        let root = sync.new_rwlock(RootDir::new());
        let node_info_lookup = sync.new_rwlock(HashMap::new());
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

    /// (private-only) check if the lower level has the path; if there is a path failure, just fail
    /// out with the relevant path error.
    fn ensure_lower_contains(&self, path: &str) -> Result<FileType, PathError> {
        match self.lower.file_status(path) {
            Ok(stat) => Ok(stat.file_type),
            Err(FileStatusError::PathError(e)) => Err(e),
        }
    }

    /// (private-only) Migrate a file from lower to upper layer
    ///
    /// It performs a check to make sure that the lower level has the file, and if the lower-level
    /// does not, then it will error out with the relevant `PathError` that can be propagated as
    /// necessary.
    ///
    /// Note: this focuses only on files.
    #[allow(clippy::too_many_lines)]
    fn migrate_file_up(&self, path: &str) -> Result<(), MigrationError> {
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
        let lower_fd = match self.lower.open(path, OFlags::RDONLY, Mode::empty()) {
            Ok(fd) => fd,
            Err(e) => match e {
                OpenError::AccessNotAllowed => return Err(MigrationError::NoReadPerms),
                OpenError::NoWritePerms | OpenError::ReadOnlyFileSystem => unreachable!(),
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
            match self.lower.read(&lower_fd, &mut temp_buf, None) {
                Ok(size) => {
                    if upper_fd.is_none() {
                        // We are here the first time around, and did not error out, yay! We can
                        // actually open up the file.
                        //
                        // TODO: We might need to make all the parent directories?
                        upper_fd = Some(
                            self.upper
                                .open(
                                    path,
                                    OFlags::CREAT | OFlags::WRONLY,
                                    self.lower.fd_file_status(&lower_fd).unwrap().mode,
                                )
                                .unwrap(),
                        );
                    }
                    let upper_fd = upper_fd.as_ref().unwrap();
                    if size > 0 {
                        self.upper.write(upper_fd, &temp_buf[..size], None).expect(
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
                    ReadError::NotForReading => unreachable!(),
                },
            }
        }
        // After migrating the data, we also use these FDs to migrate the node-info over, so that
        // any caller that tries to get the inode before/after the migration sees the same inode.
        if let Some(&layered_id) = self
            .node_info_lookup
            .read()
            .get(&self.lower.fd_file_status(&lower_fd).unwrap().node_info)
        {
            let old = self.node_info_lookup.write().insert(
                self.upper
                    .fd_file_status(upper_fd.as_ref().unwrap())
                    .unwrap()
                    .node_info,
                layered_id,
            );
            assert!(old.is_none());
        }
        // Now that we've migrated the data (and node-info) over, we can close out both of the file
        // descriptors.
        self.upper.close(upper_fd.unwrap()).unwrap();
        self.lower.close(lower_fd).unwrap();

        // Now we need to migrate all the descriptor entries over.
        //
        // Perf: this does a full scan over all open descriptors: if a process has a HUGE number of
        // open descriptors, this could be slow.
        let RootDir {
            entries: root_entries,
        } = &mut *self.root.write();
        // First we figure out which entries need to be moved up. These entries are arc-cloned into
        // a `Vec` so that we can release the lock the file descriptor table when setting things up
        // within the upper layer.
        let to_migrate: alloc::vec::Vec<(InternalFd, usize, OFlags, Entry<Upper, Lower>)> = self
            .litebox
            .descriptor_table()
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
            let upper_fd = self.upper.open(path, flags, Mode::empty()).unwrap();
            if position > 0 {
                self.upper
                    .seek(
                        &upper_fd,
                        isize::try_from(position).unwrap(),
                        SeekWhence::RelativeToBeginning,
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
                    let old_entry = self
                        .litebox
                        .descriptor_table()
                        .with_entry_mut_via_internal_fd::<Self, _, _>(internal_fd, |entry| {
                            core::mem::replace(&mut entry.entry.entry, upper_entry)
                        })
                        .expect("nothing should have changed the existing entry");
                    assert!(Arc::ptr_eq(&old_entry, &entry));
                    drop(entry);
                    let root_entry = root_entries.remove(path).unwrap();
                    assert!(Arc::ptr_eq(&old_entry, &root_entry));
                    drop(root_entry);
                    let entry = Arc::into_inner(old_entry).unwrap();
                    match entry {
                        EntryX::Upper { .. } | EntryX::Tombstone => unreachable!(),
                        EntryX::Lower { fd } => {
                            self.lower.close(fd).unwrap();
                        }
                    }
                }
                _ => {
                    // Other FDs are open with the same file too. We'll handle the open one
                    // here locally, and a future FD will take care of the relevant closing.
                    let old_entry = self
                        .litebox
                        .descriptor_table()
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
    #[error(transparent)]
    PathError(#[from] PathError),
}

impl<Platform: sync::RawSyncPrimitivesProvider, Upper: super::FileSystem, Lower: super::FileSystem>
    super::private::Sealed for FileSystem<Platform, Upper, Lower>
{
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
        let currently_supported_oflags: OFlags = OFlags::CREAT
            | OFlags::RDONLY
            | OFlags::WRONLY
            | OFlags::RDWR
            | OFlags::NOCTTY
            | OFlags::DIRECTORY
            | OFlags::NONBLOCK;
        if flags.intersects(currently_supported_oflags.complement()) {
            unimplemented!()
        }
        let path = self.absolute_path(path)?;
        if flags.contains(OFlags::CREAT) {
            // We must first attempt to open the file _without_ creating it, and only if that fails,
            // do we fall-through and end up creating it (which will happen on the upper layer).
            if let Ok(fd) = self.open(path.as_str(), flags - OFlags::CREAT, mode) {
                return Ok(fd);
            }
        }
        let mut tombstone_removal = false;
        // If we already have an entry saying it is a tombstone, then we need to quit out early;
        // otherwise, we'll check the levels.
        if let Some(entry) = self.root.read().entries.get(&path) {
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
                EntryX::Lower { .. } => {
                    // As an optimization, since a lower-level file entry is always opened with the
                    // same flags, and since it indicates that there is no such file at the upper
                    // level, we can just return that directly (with the "real" flags being wrapped
                    // up in the layered descriptor).
                    return Ok(self.litebox.descriptor_table_mut().insert(Descriptor {
                        path,
                        flags,
                        entry: Arc::clone(entry),
                        position: 0.into(),
                    }));
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
        // Otherwise, we first check the upper level, creating an entry if needed
        match self.upper.open(&*path, flags, mode) {
            Ok(fd) => {
                let entry = Arc::new(EntryX::Upper { fd });
                return Ok(self.litebox.descriptor_table_mut().insert(Descriptor {
                    path,
                    flags,
                    entry,
                    position: 0.into(),
                }));
            }
            Err(e) => match &e {
                OpenError::AccessNotAllowed
                | OpenError::NoWritePerms
                | OpenError::ReadOnlyFileSystem
                | OpenError::PathError(
                    PathError::ComponentNotADirectory
                    | PathError::InvalidPathname
                    | PathError::NoSearchPerms { .. },
                ) => {
                    // None of these can be handled by lower level, just quit out early
                    return Err(e);
                }
                OpenError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                ) => {
                    // Handle-able by a lower level, fallthrough
                }
            },
        }
        // We must check the lower level, creating an entry if needed
        let original_flags = flags;
        let mut flags = flags;
        // Prevent creation of files at lower level
        flags.remove(OFlags::CREAT);
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
            }
        }
        // Any errors from lower level now _must_ propagate up, so we can just invoke
        // the lower level and set up the relevant descriptor upon success.
        let entry = Arc::new(EntryX::Lower {
            fd: self.lower.open(path.as_str(), flags, mode)?,
        });
        let old = self
            .root
            .write()
            .entries
            .insert(path.clone(), Arc::clone(&entry));
        assert!(old.is_none());
        Ok(self.litebox.descriptor_table_mut().insert(Descriptor {
            path,
            flags: original_flags,
            entry,
            position: 0.into(),
        }))
    }

    fn close(&self, fd: FileFd<Platform, Upper, Lower>) -> Result<(), CloseError> {
        let Some(removed_entry) = self.litebox.descriptor_table_mut().remove(fd) else {
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
        let RootDir {
            entries: root_entries,
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
                self.upper.close(fd)
            }
            EntryX::Lower { .. } => {
                // Lower level FDs almost always have a corresponding entry in the root. Thus, we
                // might need to possibly clean things up from the root.
                //
                // First, we can attempt a fast-path clean-up by quickly check if there are other
                // FDs referring to the same file
                if Arc::strong_count(&entry) > 2 {
                    // There are _definitely_ other FDs pointing at this file, leave it alone
                    return Ok(());
                }
                // Otherwise, either we have ourselves and the root pointing at it OR the root has
                // been tombstoned out after the FDs have been opened at it.
                match **root_entries.get(&path).unwrap() {
                    EntryX::Upper { .. } => unreachable!(),
                    EntryX::Lower { .. } => {
                        // We are going to have to deal with it at the entry too, fallthrough
                    }
                    EntryX::Tombstone => {
                        // A tombstone here means that the root doesn't contain the entry. There may
                        // possibly be other FDs opened for the same file before it was tombstoned
                        // out, so we'll close it out if we are the sole remaining holder;
                        // otherwise, it will be someone else's job to do so.
                        match Arc::into_inner(entry) {
                            Some(EntryX::Upper { .. } | EntryX::Tombstone) => unreachable!(),
                            Some(EntryX::Lower { fd }) => {
                                // We are the sole remaining holder of the FD. Let us clean things
                                // up at the lower level.
                                return self.lower.close(fd);
                            }
                            None => {
                                // Someone else's job. We can quit successfully.
                                return Ok(());
                            }
                        }
                    }
                }
                // Pull out the root entry, and perform a quick sanity check, and drop it out
                // entirely, which should lead us to become the sole owner.
                let root_entry = root_entries.remove(&path).unwrap();
                assert!(Arc::ptr_eq(&entry, &root_entry));
                assert!(matches!(*root_entry, EntryX::Lower { .. }));
                drop(root_entry);
                // We are now assured that we can close out the underlying file; we are the only
                // holder of the entry, and thus can change it from an Arc to the underlying value
                // itself, and then close it out.
                let EntryX::Lower { fd, .. } = Arc::into_inner(entry).unwrap() else {
                    unreachable!()
                };
                self.lower.close(fd)
            }
        }
    }

    fn read(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        // Since a write to a lower-level file upgrades the underlying entry out completely to an
        // upper-level file, we don't actually need to worry about a desync; a write to lower-level
        // file will successfully be seen as just being an upper level file. Thus, it is sufficient
        // just to delegate this operation based whether the entry points to upper or lower layers.
        let entry = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| {
                if !descriptor.entry.flags.contains(OFlags::RDONLY)
                    && !descriptor.entry.flags.contains(OFlags::RDWR)
                {
                    Err(ReadError::NotForReading)
                } else {
                    Ok(Arc::clone(&descriptor.entry.entry))
                }
            })?;
        // Perform the actual operation
        let num_bytes = match entry.as_ref() {
            EntryX::Upper { fd } => self.upper.read(fd, buf, offset)?,
            EntryX::Lower { fd } => self.lower.read(fd, buf, offset)?,
            EntryX::Tombstone => unreachable!(),
        };
        self.litebox
            .descriptor_table()
            .get_entry(fd)
            .entry
            .position
            .fetch_add(num_bytes, SeqCst);
        Ok(num_bytes)
    }

    fn write(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        // Writing needs to be careful of how it is performing the write. Any upper-level file can
        // instantly be written to; but a lower-level file must become a upper-level file, before
        // actually being written to.
        let (entry, path) = self
            .litebox
            .descriptor_table()
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
            })?;
        match entry.as_ref() {
            EntryX::Upper { fd: upper_fd } => {
                let num_bytes = self.upper.write(upper_fd, buf, offset)?;
                self.litebox
                    .descriptor_table()
                    .get_entry(fd)
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
                        let num_bytes = self.lower.write(lower_fd, buf, offset)?;
                        self.litebox
                            .descriptor_table()
                            .get_entry(fd)
                            .entry
                            .position
                            .fetch_add(num_bytes, SeqCst);
                        return Ok(num_bytes);
                    }
                }
            }
            EntryX::Tombstone => unreachable!(),
        }
        // Change it to an upper-level file, also altering the file descriptor.
        match self.migrate_file_up(&path) {
            Ok(()) => {}
            Err(MigrationError::NoReadPerms) => unimplemented!(),
            Err(MigrationError::NotAFile) => return Err(WriteError::NotAFile),
            Err(MigrationError::PathError(_e)) => unreachable!(),
        }
        // As a sanity check, in debug mode, confirm that it is now an upper file
        debug_assert!(matches!(
            *self.litebox.descriptor_table().get_entry(fd).entry.entry,
            EntryX::Upper { .. }
        ));
        // Since it has been migrated, we can just re-trigger, causing it to apply to the
        // upper layer
        self.write(fd, buf, offset)
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
            .with_entry(fd, |descriptor| Arc::clone(&descriptor.entry.entry));
        // Perform the seek, and update the position info
        let position = match entry.as_ref() {
            EntryX::Upper { fd } => self.upper.seek(fd, offset, whence)?,
            EntryX::Lower { fd } => self.lower.seek(fd, offset, whence)?,
            EntryX::Tombstone => unreachable!(),
        };
        self.litebox
            .descriptor_table()
            .get_entry(fd)
            .entry
            .position
            .store(position, SeqCst);
        Ok(position)
    }

    fn chmod(&self, path: impl crate::path::Arg, mode: Mode) -> Result<(), ChmodError> {
        let path = self.absolute_path(path)?;
        match self.upper.chmod(path.as_str(), mode) {
            Ok(()) => return Ok(()),
            Err(e) => match e {
                ChmodError::NotTheOwner
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
                    // fallthrough
                }
            },
        }
        self.ensure_lower_contains(&path)?;
        match self.migrate_file_up(&path) {
            Ok(()) => {}
            Err(MigrationError::NoReadPerms) => unimplemented!(),
            Err(MigrationError::NotAFile) => unimplemented!(),
            Err(MigrationError::PathError(_e)) => unreachable!(),
        }
        // Since it has been migrated, we can just re-trigger, causing it to apply to the
        // upper layer
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
                    // fallthrough
                }
            },
        }
        self.ensure_lower_contains(&path)?;
        match self.migrate_file_up(&path) {
            Ok(()) => {}
            Err(MigrationError::NoReadPerms) => unimplemented!(),
            Err(MigrationError::NotAFile) => unimplemented!(),
            Err(MigrationError::PathError(_e)) => unreachable!(),
        }
        // Since it has been migrated, we can just re-trigger, causing it to apply to the
        // upper layer
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
                | UnlinkError::IsADirectory
                | UnlinkError::ReadOnlyFileSystem
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
                    match self.ensure_lower_contains(&path)? {
                        FileType::RegularFile => {
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
        // We can now place a tombstone over the lower level file, marking it as deleted, without
        // actually changing the lower level.
        self.root
            .write()
            .entries
            .insert(path, Arc::new(EntryX::Tombstone));
        Ok(())
    }

    fn mkdir(&self, path: impl crate::path::Arg, mode: Mode) -> Result<(), MkdirError> {
        let path = self.absolute_path(path)?;
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
                MkdirError::PathError(PathError::MissingComponent) => {
                    // fallthrough
                }
            },
        }
        // We know that at least one of the components is missing. We should check each of the
        // components individually, making directories for any components that already exist at the
        // lower layer, and erroring out if no lower layer component exists of that form.
        for dir in path.increasing_ancestors().map_err(PathError::from)? {
            match self.ensure_lower_contains(dir) {
                Ok(FileType::Directory) => {
                    // The dir does in fact exist; we just need to confirm that the upper layer also
                    // has it.
                    match self
                        .upper
                        .mkdir(dir, self.lower.file_status(dir).unwrap().mode)
                    {
                        Ok(()) => {
                            // fallthrough to next increasing ancestor
                        }
                        Err(e) => match e {
                            MkdirError::AlreadyExists => {
                                // perfectly fine, just fallthrough to next place in the loop
                            }
                            MkdirError::ReadOnlyFileSystem
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
                        },
                    }
                }
                Ok(FileType::RegularFile | FileType::CharacterDevice)
                | Err(PathError::MissingComponent) => unreachable!(),
                Err(PathError::ComponentNotADirectory) => unimplemented!(),
                Err(PathError::InvalidPathname) => unreachable!("we just confirmed valid path"),
                Err(e @ PathError::NoSearchPerms { .. }) => {
                    return Err(e)?;
                }
                Err(PathError::NoSuchFileOrDirectory) => {
                    // This is possibly the missing component; if it is same as the path itself,
                    // then it just needs its mkdir at the upper level; otherwise it is a true
                    // missing component.
                    if dir != path {
                        return Err(PathError::MissingComponent)?;
                    }
                    return self.upper.mkdir(&*path, mode);
                }
            }
        }
        // The last round of the loop should guarantee upper-directory creation if needed, so it
        // should be impossible for us to actually reach here.
        unreachable!()
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn rmdir(&self, path: impl crate::path::Arg) -> Result<(), RmdirError> {
        // Roughly identical to `unlink` except we need to worry about directories, thus need to
        // check for whether there are any sub-entries in the directories. This does require us to
        // do at least a "number of entries" check on both upper and lower level at all times.
        // However, in terms of functionality, we will be placing tombstone entries.
        todo!()
    }

    fn read_dir(&self, fd: &FileFd<Platform, Upper, Lower>) -> Result<Vec<DirEntry>, ReadDirError> {
        let (entry, path) = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| {
                (
                    Arc::clone(&descriptor.entry.entry),
                    descriptor.entry.path.clone(),
                )
            });

        let mut entries = match entry.as_ref() {
            EntryX::Upper { fd } => {
                // Get entries from upper layer
                let mut upper_entries = self.upper.read_dir(fd)?;

                // Try to get entries from lower layer for the same path
                if let Ok(lower_fd) = self
                    .lower
                    .open(path.as_str(), OFlags::RDONLY, Mode::empty())
                {
                    if let Ok(lower_entries) = self.lower.read_dir(&lower_fd) {
                        // Merge entries, avoiding duplicates (upper layer takes precedence)
                        let upper_names: HashSet<String> =
                            upper_entries.iter().map(|e| e.name.clone()).collect();

                        for lower_entry in lower_entries {
                            if !upper_names.contains(&lower_entry.name) {
                                upper_entries.push(lower_entry);
                            }
                        }
                    }
                    let _ = self.lower.close(lower_fd);
                }

                upper_entries
            }
            EntryX::Lower { fd } => {
                // This is the easy case, nothing to deal with upper entries.
                self.lower.read_dir(fd)?
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
        // Note: we grab the info from the relevant level and then immediately spit back the same,
        // essentially to ask the compiler to remind us we need to update this when we support
        // inodes and such.
        let path = self.absolute_path(path)?;
        if let Some(entry) = self.root.read().entries.get(&path) {
            let FileStatus {
                file_type,
                mode,
                size,
                owner,
                node_info,
                blksize,
            } = match entry.as_ref() {
                EntryX::Upper { fd } => self.upper.fd_file_status(fd)?,
                EntryX::Lower { fd } => self.lower.fd_file_status(fd)?,
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
        // The file is not open, we must look at the levels themselves.
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
                    // None of these can be handled by lower level, just quit out early
                    return Err(e);
                }
                FileStatusError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                ) => {
                    // Handle-able by a lower level, fallthrough
                }
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

    fn fd_file_status(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
    ) -> Result<FileStatus, FileStatusError> {
        let entry = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| Arc::clone(&descriptor.entry.entry));
        let FileStatus {
            file_type,
            mode,
            size,
            owner,
            node_info,
            blksize,
        } = match entry.as_ref() {
            EntryX::Upper { fd } => self.upper.fd_file_status(fd)?,
            EntryX::Lower { fd } => self.lower.fd_file_status(fd)?,
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

    fn with_metadata<T: core::any::Any, R>(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        f: impl FnOnce(&T) -> R,
    ) -> Result<R, super::errors::MetadataError> {
        let entry = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| Arc::clone(&descriptor.entry.entry));
        match entry.as_ref() {
            EntryX::Upper { fd } => self.upper.with_metadata(fd, f),
            EntryX::Lower { fd } => self.lower.with_metadata(fd, f),
            EntryX::Tombstone => unreachable!(),
        }
    }

    fn with_metadata_mut<T: core::any::Any, R>(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        f: impl FnOnce(&mut T) -> R,
    ) -> Result<R, super::errors::MetadataError> {
        let entry = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| Arc::clone(&descriptor.entry.entry));
        match entry.as_ref() {
            EntryX::Upper { fd } => self.upper.with_metadata_mut(fd, f),
            EntryX::Lower { fd } => self.lower.with_metadata_mut(fd, f),
            EntryX::Tombstone => unreachable!(),
        }
    }

    fn set_file_metadata<T: core::any::Any>(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        metadata: T,
    ) -> Result<Option<T>, super::errors::SetMetadataError<T>> {
        let entry = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| Arc::clone(&descriptor.entry.entry));
        match entry.as_ref() {
            EntryX::Upper { fd } => self.upper.set_file_metadata(fd, metadata),
            EntryX::Lower { fd } => self.lower.set_file_metadata(fd, metadata),
            EntryX::Tombstone => unreachable!(),
        }
    }

    fn set_fd_metadata<T: core::any::Any>(
        &self,
        fd: &FileFd<Platform, Upper, Lower>,
        metadata: T,
    ) -> Result<Option<T>, super::errors::SetMetadataError<T>> {
        let entry = self
            .litebox
            .descriptor_table()
            .with_entry(fd, |descriptor| Arc::clone(&descriptor.entry.entry));
        match entry.as_ref() {
            EntryX::Upper { fd } => self.upper.set_fd_metadata(fd, metadata),
            EntryX::Lower { fd } => self.lower.set_fd_metadata(fd, metadata),
            EntryX::Tombstone => unreachable!(),
        }
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
    // Invariant: this only stores lower+tombstone entries, no upper entries will show up here.
    entries: HashMap<String, Entry<Upper, Lower>>,
}

impl<Upper: super::FileSystem, Lower: super::FileSystem> RootDir<Upper, Lower> {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
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

crate::fd::enable_fds_for_subsystem! {
    @Platform: { sync::RawSyncPrimitivesProvider }, Upper: { super::FileSystem + 'static }, Lower: { super::FileSystem + 'static };
    FileSystem<Platform, Upper, Lower>;
    @Upper: { super::FileSystem + 'static }, Lower: { super::FileSystem + 'static };
    Descriptor<Upper, Lower>;
    -> FileFd<Platform, Upper, Lower>;
}
