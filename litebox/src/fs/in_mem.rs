//! An in-memory file system, not backed by any physical device.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::LiteBox;
use crate::path::Arg;
use crate::sync;

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MetadataError, MkdirError, OpenError,
    PathError, ReadDirError, ReadError, RmdirError, SeekError, SetMetadataError, UnlinkError,
    WriteError,
};
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, SeekWhence, UserInfo};
use crate::utilities::anymap::AnyMap;

/// Just a random constant that is distinct from other file systems. In this case, it is
/// `b'IMem'.hex()`.
const DEVICE_ID: usize = 0x494d656d;

/// Block size for file system I/O operations
// TODO(jayb): Determine appropriate block size
const BLOCK_SIZE: usize = 0;

/// A backing implementation for [`FileSystem`](super::FileSystem) storing all files in-memory.
///
/// # Warning
///
/// This has no physical backing store, thus any files in memory are erased as soon as this object
/// is dropped.
pub struct FileSystem<Platform: sync::RawSyncPrimitivesProvider> {
    litebox: LiteBox<Platform>,
    // TODO: Possibly support a single-threaded variant that doesn't have the cost of requiring a
    // sync-primitives platform, as well as cost of mutexes and such?
    root: sync::RwLock<Platform, RootDir<Platform>>,
    current_user: UserInfo,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
    // a source of freshness for providing unique IDs
    unique_id_freshness: core::sync::atomic::AtomicUsize,
}

impl<Platform: sync::RawSyncPrimitivesProvider> FileSystem<Platform> {
    /// Construct a new `FileSystem` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialiation step,
    /// and the created `FileSystem` handle is expected to be shared across all usage over the
    /// system.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        let litebox = litebox.clone();
        let sync = litebox.sync();
        let root = sync.new_rwlock(RootDir::new(sync));
        Self {
            litebox,
            root,
            current_user: UserInfo {
                user: 1000,
                group: 1000,
            },
            current_working_dir: "/".into(),
            unique_id_freshness: 1.into(), // the root dir gets unique ID of 0
        }
    }

    /// Execute `f` with superuser/root privileges.
    ///
    /// This function primarily exists to initialize files. Most regular interaction with the file
    /// system should be done without this function.
    pub fn with_root_privileges<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Self),
    {
        let original_user = core::mem::replace(&mut self.current_user, UserInfo::ROOT);
        f(self);
        let root_again = core::mem::replace(&mut self.current_user, original_user);
        if root_again.user != UserInfo::ROOT.user || root_again.group != UserInfo::ROOT.group {
            unreachable!()
        }
    }

    /// Execute `f` as a specific user (for testing purposes).
    #[cfg(test)]
    pub fn with_user<F>(&mut self, user: u16, group: u16, f: F)
    where
        F: FnOnce(&mut Self),
    {
        let test_user = UserInfo { user, group };
        let original_user = core::mem::replace(&mut self.current_user, test_user);
        f(self);
        let test_user_again = core::mem::replace(&mut self.current_user, original_user);
        if test_user_again.user != test_user.user || test_user_again.group != test_user.group {
            unreachable!()
        }
    }

    /// (Private) Provide a fresh unique ID
    fn fresh_id(&self) -> usize {
        let res = self
            .unique_id_freshness
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        assert_ne!(
            res,
            usize::MAX,
            "we never expect to hit this, but if we do, someone has made way too many files in this session"
        );
        res
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::private::Sealed for FileSystem<Platform> {}

impl<Platform: sync::RawSyncPrimitivesProvider> FileSystem<Platform> {
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
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::FileSystem for FileSystem<Platform> {
    fn open(
        &self,
        path: impl crate::path::Arg,
        mut flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        use super::OFlags;
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
        let entry = if flags.contains(OFlags::CREAT) {
            let mut root = self.root.write();
            let (parent, entry) = root.parent_and_entry(&path, self.current_user)?;
            if let Some(entry) = entry {
                entry
            } else {
                let Some((_, parent)) = parent else {
                    // Only `/` does not have a parent; any other scenario (e.g., missing ancestor)
                    // is handled already by a `PathError`. If `/` was passed, then it would have
                    // gotten `Some(entry)` out already. Thus, this is unreachable.
                    unreachable!()
                };
                let mut parent = parent.write();
                if !self.current_user.can_write(&parent.perms) {
                    return Err(OpenError::NoWritePerms);
                }
                // When both O_CREAT and O_DIRECTORY are specified in flags and the
                // file specified by pathname does not exist, open() will create a
                // regular file (i.e., O_DIRECTORY is ignored).
                flags.remove(OFlags::DIRECTORY);
                let old = parent.children.insert(
                    path.components().unwrap().last().unwrap().into(),
                    FileType::RegularFile,
                );
                assert!(old.is_none());
                let entry = Entry::File(Arc::new(self.litebox.sync().new_rwlock(FileX {
                    perms: Permissions {
                        mode,
                        userinfo: self.current_user,
                    },
                    data: Vec::new(),
                    metadata: AnyMap::new(),
                    unique_id: self.fresh_id(),
                })));
                let old = root.entries.insert(path, entry.clone());
                assert!(old.is_none());
                entry
            }
        } else {
            let root = self.root.read();
            let (_, entry) = root.parent_and_entry(&path, self.current_user)?;
            let Some(entry) = entry else {
                return Err(PathError::NoSuchFileOrDirectory)?;
            };
            entry
        };
        let read_allowed = if flags.contains(OFlags::RDONLY) || flags.contains(OFlags::RDWR) {
            if !self.current_user.can_read(&entry.perms()) {
                return Err(OpenError::AccessNotAllowed);
            }
            true
        } else {
            false
        };
        let write_allowed = if flags.contains(OFlags::WRONLY) || flags.contains(OFlags::RDWR) {
            if !self.current_user.can_write(&entry.perms()) {
                return Err(OpenError::AccessNotAllowed);
            }
            true
        } else {
            false
        };
        match entry {
            Entry::File(file) => {
                if flags.contains(OFlags::DIRECTORY) {
                    return Err(OpenError::PathError(PathError::ComponentNotADirectory));
                }
                Ok(self
                    .litebox
                    .descriptor_table_mut()
                    .insert(Descriptor::File {
                        file: file.clone(),
                        read_allowed,
                        write_allowed,
                        position: 0,
                        metadata: AnyMap::new(),
                    }))
            }
            Entry::Dir(dir) => Ok(self.litebox.descriptor_table_mut().insert(Descriptor::Dir {
                dir: dir.clone(),
                metadata: AnyMap::new(),
            })),
        }
    }

    fn close(&self, fd: FileFd<Platform>) -> Result<(), CloseError> {
        self.litebox.descriptor_table_mut().remove(fd);
        Ok(())
    }

    fn read(
        &self,
        fd: &FileFd<Platform>,
        buf: &mut [u8],
        mut offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File {
            file,
            read_allowed,
            write_allowed: _,
            position,
            metadata: _,
        } = &mut descriptor_table.get_entry_mut(fd).entry
        else {
            return Err(ReadError::NotAFile);
        };
        if !*read_allowed {
            return Err(ReadError::NotForReading);
        }
        let position = offset.as_mut().unwrap_or(position);
        let file = file.read();
        let start = (*position).min(file.data.len());
        let end = position
            .checked_add(buf.len())
            .unwrap()
            .min(file.data.len());
        debug_assert!(start <= end);
        let retlen = end - start;
        buf[..retlen].copy_from_slice(&file.data[start..end]);
        *position = end;
        Ok(retlen)
    }

    fn write(
        &self,
        fd: &FileFd<Platform>,
        buf: &[u8],
        mut offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File {
            file,
            read_allowed: _,
            write_allowed,
            position,
            metadata: _,
        } = &mut descriptor_table.get_entry_mut(fd).entry
        else {
            return Err(WriteError::NotAFile);
        };
        if !*write_allowed {
            return Err(WriteError::NotForWriting);
        }
        let position = offset.as_mut().unwrap_or(position);
        let mut file = file.write();
        let start = if *position < file.data.len() {
            let start = *position;
            let end = position
                .checked_add(buf.len())
                .unwrap()
                .min(file.data.len());
            debug_assert!(start <= end);
            let first_half_len = end - start;
            file.data[start..end].copy_from_slice(&buf[..first_half_len]);
            first_half_len
        } else {
            0
        };
        file.data.extend(&buf[start..]);
        *position = file.data.len();
        Ok(buf.len())
    }

    fn seek(
        &self,
        fd: &FileFd<Platform>,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File {
            file,
            read_allowed: _,
            write_allowed: _,
            position,
            metadata: _,
        } = &mut descriptor_table.get_entry_mut(fd).entry
        else {
            return Err(SeekError::NotAFile);
        };
        let file_len = file.read().data.len();
        let base = match whence {
            SeekWhence::RelativeToBeginning => 0,
            SeekWhence::RelativeToCurrentOffset => *position,
            SeekWhence::RelativeToEnd => file_len,
        };
        let new_posn = base
            .checked_add_signed(offset)
            .ok_or(SeekError::InvalidOffset)?;
        if new_posn > file_len {
            Err(SeekError::InvalidOffset)
        } else {
            *position = new_posn;
            Ok(new_posn)
        }
    }

    fn chmod(&self, path: impl crate::path::Arg, mode: super::Mode) -> Result<(), ChmodError> {
        let path = self.absolute_path(path)?;
        let root = self.root.read();
        let (_, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        match entry {
            Entry::File(file) => {
                let perms = &mut file.write().perms;
                if !(self.current_user.user == 0 || self.current_user.user == perms.userinfo.user) {
                    return Err(ChmodError::NotTheOwner);
                }
                perms.mode = mode;
                Ok(())
            }
            Entry::Dir(dir) => {
                let perms = &mut dir.write().perms;
                if !(self.current_user.user == 0 || self.current_user.user == perms.userinfo.user) {
                    return Err(ChmodError::NotTheOwner);
                }
                perms.mode = mode;
                Ok(())
            }
        }
    }

    fn chown(
        &self,
        path: impl crate::path::Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = self.absolute_path(path)?;
        let root = self.root.read();
        let (_, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        match entry {
            Entry::File(file) => {
                let perms = &mut file.write().perms;
                if !(self.current_user.user == 0 || self.current_user.user == perms.userinfo.user) {
                    return Err(ChownError::NotTheOwner);
                }
                if let Some(new_user) = user {
                    perms.userinfo.user = new_user;
                }
                if let Some(new_group) = group {
                    perms.userinfo.group = new_group;
                }
                Ok(())
            }
            Entry::Dir(dir) => {
                let perms = &mut dir.write().perms;
                if !(self.current_user.user == 0 || self.current_user.user == perms.userinfo.user) {
                    return Err(ChownError::NotTheOwner);
                }
                if let Some(new_user) = user {
                    perms.userinfo.user = new_user;
                }
                if let Some(new_group) = group {
                    perms.userinfo.group = new_group;
                }
                Ok(())
            }
        }
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), UnlinkError> {
        let path = self.absolute_path(path)?;
        let mut root = self.root.write();
        let (parent, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some((_, parent)) = parent else {
            // Attempted to remove `/`
            return Err(UnlinkError::IsADirectory);
        };
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        if let Entry::Dir(_) = entry {
            return Err(UnlinkError::IsADirectory);
        }
        let mut parent = parent.write();
        if !self.current_user.can_write(&parent.perms) {
            return Err(UnlinkError::NoWritePerms);
        }
        let removed = parent
            .children
            .remove(path.components().unwrap().last().unwrap());
        // Just a sanity check
        assert!(matches!(removed, Some(FileType::RegularFile)));
        let removed = root.entries.remove(&path).unwrap();
        // Just a sanity check
        assert!(matches!(removed, Entry::File(File { .. })));
        Ok(())
    }

    fn mkdir(&self, path: impl crate::path::Arg, mode: super::Mode) -> Result<(), MkdirError> {
        let path = self.absolute_path(path)?;
        let mut root = self.root.write();
        let (parent, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some((_parent_path, parent)) = parent else {
            // Attempted to make `/`
            return Err(MkdirError::AlreadyExists);
        };
        let None = entry else {
            return Err(MkdirError::AlreadyExists);
        };
        let mut parent = parent.write();
        if !self.current_user.can_write(&parent.perms) {
            return Err(MkdirError::NoWritePerms);
        }
        let old = parent.children.insert(
            path.components().unwrap().last().unwrap().into(),
            FileType::Directory,
        );
        assert!(old.is_none());
        let old = root.entries.insert(
            path,
            Entry::Dir(Arc::new(self.litebox.sync().new_rwlock(DirX {
                perms: Permissions {
                    mode,
                    userinfo: self.current_user,
                },
                children: HashMap::default(),
                metadata: AnyMap::new(),
                unique_id: self.fresh_id(),
            }))),
        );
        assert!(old.is_none());
        Ok(())
    }

    fn rmdir(&self, path: impl crate::path::Arg) -> Result<(), RmdirError> {
        let path = self.absolute_path(path)?;
        let mut root = self.root.write();
        let (parent, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some((_, parent)) = parent else {
            // Attempted to remove `/`
            return Err(RmdirError::Busy);
        };
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        let Entry::Dir(dir) = entry else {
            return Err(RmdirError::NotADirectory);
        };
        if !dir.read().children.is_empty() {
            return Err(RmdirError::NotEmpty);
        }
        let mut parent = parent.write();
        if !self.current_user.can_write(&parent.perms) {
            return Err(RmdirError::NoWritePerms);
        }
        let removed = parent
            .children
            .remove(path.components().unwrap().last().unwrap());
        // Just a sanity check
        assert!(matches!(removed, Some(FileType::Directory)));
        let removed = root.entries.remove(&path).unwrap();
        // Just a sanity check
        assert!(matches!(removed, Entry::Dir(_)));
        Ok(())
    }

    fn read_dir(&self, fd: &FileFd<Platform>) -> Result<Vec<DirEntry>, ReadDirError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::Dir { dir, metadata: _ } = &descriptor_table.get_entry(fd).entry else {
            return Err(ReadDirError::NotADirectory);
        };

        // find the directory path in the root entries by pointer-equality of the Arc
        let mut parent_path = {
            let root = self.root.read();
            root.entries
                .iter()
                .find_map(|(path, entry)| match entry {
                    Entry::Dir(d) if alloc::sync::Arc::ptr_eq(d, dir) => Some(path.clone()),
                    _ => None,
                })
                .unwrap_or(String::new())
        };

        // helper to get NodeInfo by an entries-key (entries keys have no trailing '/')
        let get_node_info = |key: &str| -> Option<NodeInfo> {
            self.root.read().entries.get(key).map(|entry| {
                let ino = match entry {
                    Entry::File(file) => file.read().unique_id,
                    Entry::Dir(dir) => dir.read().unique_id,
                };
                NodeInfo {
                    dev: DEVICE_ID,
                    ino,
                    rdev: None,
                }
            })
        };

        let mut entries: Vec<DirEntry> = Vec::new();

        // Add "."
        entries.push(DirEntry {
            name: ".".into(),
            file_type: FileType::Directory,
            ino_info: Some(NodeInfo {
                dev: DEVICE_ID,
                ino: dir.read().unique_id,
                rdev: None,
            }),
        });

        // Add ".."
        entries.push(DirEntry {
            name: "..".into(),
            file_type: FileType::Directory,
            ino_info: get_node_info(&parent_path),
        });

        // Append a trailing '/' to `parent_path`.
        // An empty string (`""`) represents the root.
        parent_path.push('/');

        // Add normal children
        entries.extend(dir.read().children.iter().map(|(name, file_type)| {
            let mut full_path = parent_path.clone();
            full_path.push_str(name);
            DirEntry {
                name: name.into(),
                file_type: file_type.clone(),
                ino_info: get_node_info(&full_path),
            }
        }));
        Ok(entries)
    }

    fn file_status(&self, path: impl crate::path::Arg) -> Result<FileStatus, FileStatusError> {
        let path = self.absolute_path(path)?;
        let root = self.root.read();
        let (_, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        let (file_type, perms, size, unique_id) = match entry {
            Entry::File(file) => {
                let file = file.read();
                (
                    super::FileType::RegularFile,
                    file.perms.clone(),
                    file.data.len(),
                    file.unique_id,
                )
            }
            Entry::Dir(dir) => {
                let dir = dir.read();
                (
                    super::FileType::Directory,
                    dir.perms.clone(),
                    super::DEFAULT_DIRECTORY_SIZE,
                    dir.unique_id,
                )
            }
        };
        Ok(FileStatus {
            file_type,
            mode: perms.mode,
            size,
            owner: perms.userinfo,
            node_info: NodeInfo {
                dev: DEVICE_ID,
                ino: unique_id,
                rdev: None,
            },
            blksize: BLOCK_SIZE,
        })
    }

    fn fd_file_status(&self, fd: &FileFd<Platform>) -> Result<FileStatus, FileStatusError> {
        let (file_type, perms, size, unique_id) =
            match &self.litebox.descriptor_table().get_entry(fd).entry {
                Descriptor::File { file, .. } => {
                    let file = file.read();
                    (
                        super::FileType::RegularFile,
                        file.perms.clone(),
                        file.data.len(),
                        file.unique_id,
                    )
                }
                Descriptor::Dir { dir, .. } => {
                    let dir = dir.read();
                    (
                        super::FileType::Directory,
                        dir.perms.clone(),
                        super::DEFAULT_DIRECTORY_SIZE,
                        dir.unique_id,
                    )
                }
            };
        Ok(FileStatus {
            file_type,
            mode: perms.mode,
            size,
            owner: perms.userinfo,
            node_info: NodeInfo {
                dev: DEVICE_ID,
                ino: unique_id,
                rdev: None,
            },
            blksize: BLOCK_SIZE,
        })
    }

    fn with_metadata<T: core::any::Any, R>(
        &self,
        fd: &FileFd<Platform>,
        f: impl FnOnce(&T) -> R,
    ) -> Result<R, MetadataError> {
        match &self.litebox.descriptor_table().get_entry(fd).entry {
            Descriptor::File { file, metadata, .. } => match metadata.get::<T>() {
                Some(m) => Ok(f(m)),
                None => file
                    .read()
                    .metadata
                    .get::<T>()
                    .map(f)
                    .ok_or(MetadataError::NoSuchMetadata),
            },
            Descriptor::Dir { dir, metadata } => match metadata.get::<T>() {
                Some(m) => Ok(f(m)),
                None => dir
                    .read()
                    .metadata
                    .get::<T>()
                    .map(f)
                    .ok_or(MetadataError::NoSuchMetadata),
            },
        }
    }

    fn with_metadata_mut<T: core::any::Any, R>(
        &self,
        fd: &FileFd<Platform>,
        f: impl FnOnce(&mut T) -> R,
    ) -> Result<R, MetadataError> {
        match &mut self.litebox.descriptor_table().get_entry_mut(fd).entry {
            Descriptor::File { file, metadata, .. } => match metadata.get_mut::<T>() {
                Some(m) => Ok(f(m)),
                None => file
                    .write()
                    .metadata
                    .get_mut::<T>()
                    .map(f)
                    .ok_or(MetadataError::NoSuchMetadata),
            },
            Descriptor::Dir { dir, metadata } => match metadata.get_mut::<T>() {
                Some(m) => Ok(f(m)),
                None => dir
                    .write()
                    .metadata
                    .get_mut::<T>()
                    .map(f)
                    .ok_or(MetadataError::NoSuchMetadata),
            },
        }
    }

    fn set_file_metadata<T: core::any::Any>(
        &self,
        fd: &FileFd<Platform>,
        m: T,
    ) -> Result<Option<T>, SetMetadataError<T>> {
        match &self.litebox.descriptor_table().get_entry(fd).entry {
            Descriptor::File { file, .. } => Ok(file.write().metadata.insert(m)),
            Descriptor::Dir { dir, .. } => Ok(dir.write().metadata.insert(m)),
        }
    }

    fn set_fd_metadata<T: core::any::Any>(
        &self,
        fd: &FileFd<Platform>,
        m: T,
    ) -> Result<Option<T>, SetMetadataError<T>> {
        match &mut self.litebox.descriptor_table().get_entry_mut(fd).entry {
            Descriptor::File { metadata, .. } | Descriptor::Dir { metadata, .. } => {
                Ok(metadata.insert(m))
            }
        }
    }
}

struct RootDir<Platform: sync::RawSyncPrimitivesProvider> {
    // keys are normalized paths; directories do not have the final `/` (thus the root would be at
    // the empty-string key "")
    entries: HashMap<String, Entry<Platform>>,
}

// Parent, if it exists, is the path as well as the directory
//
// The entry, if it exists, is just the entry itself
type ParentAndEntry<'a, D, E> = Result<(Option<(&'a str, D)>, Option<E>), PathError>;

impl<Platform: sync::RawSyncPrimitivesProvider> RootDir<Platform> {
    fn new(sync: &sync::Synchronization<Platform>) -> Self {
        Self {
            entries: [(
                String::new(),
                Entry::Dir(Arc::new(sync.new_rwlock(DirX {
                    perms: Permissions {
                        mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                        userinfo: UserInfo { user: 0, group: 0 },
                    },
                    children: HashMap::default(),
                    metadata: AnyMap::new(),
                    unique_id: 0,
                }))),
            )]
            .into_iter()
            .collect(),
        }
    }

    fn parent_and_entry(
        &self,
        path: &str,
        current_user: UserInfo,
    ) -> ParentAndEntry<'_, Dir<Platform>, Entry<Platform>> {
        let mut real_components_seen = false;
        let mut collected = String::new();
        let mut parent_dir = None;
        for p in path.normalized_components()? {
            if p.is_empty() || p == ".." {
                // After normalization, these can only be at the start of the path, so can all be
                // ignored. We do an `assert` here mostly as a sanity check.
                assert!(!real_components_seen);
                continue;
            }
            // We have seen real components, should no longer see any empty or `/`s.
            real_components_seen = true;
            match self
                .entries
                .get_key_value(&collected)
                .ok_or(PathError::MissingComponent)?
            {
                (_, Entry::File(_)) => return Err(PathError::ComponentNotADirectory),
                (parent_path, Entry::Dir(dir)) => {
                    if !current_user.can_execute(&dir.read().perms) {
                        return Err(PathError::NoSearchPerms {
                            #[cfg(debug_assertions)]
                            dir: parent_path.clone(),
                            #[cfg(debug_assertions)]
                            perms: dir.read().perms.mode,
                        });
                    }
                    parent_dir = Some((parent_path.as_str(), dir.clone()));
                }
            }
            collected += "/";
            collected += p;
        }
        Ok((parent_dir, self.entries.get(&collected).cloned()))
    }
}

enum Entry<Platform: sync::RawSyncPrimitivesProvider> {
    File(File<Platform>),
    Dir(Dir<Platform>),
}

impl<Platform: sync::RawSyncPrimitivesProvider> Entry<Platform> {
    fn perms(&self) -> Permissions {
        match self {
            Self::File(file) => file.read().perms.clone(),
            Self::Dir(dir) => dir.read().perms.clone(),
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> Clone for Entry<Platform> {
    fn clone(&self) -> Self {
        match self {
            Self::File(file) => Self::File(file.clone()),
            Self::Dir(dir) => Self::Dir(dir.clone()),
        }
    }
}

type Dir<Platform> = Arc<sync::RwLock<Platform, DirX>>;

pub(crate) struct DirX {
    perms: Permissions,
    children: HashMap<String, FileType>,
    metadata: AnyMap,
    unique_id: usize,
}

type File<Platform> = Arc<sync::RwLock<Platform, FileX>>;

pub(crate) struct FileX {
    perms: Permissions,
    data: Vec<u8>,
    metadata: AnyMap,
    unique_id: usize,
}

#[derive(Clone, Debug)]
struct Permissions {
    mode: Mode,
    userinfo: UserInfo,
}

impl UserInfo {
    fn can_read(self, perms: &Permissions) -> bool {
        perms.can_read_by(self)
    }
    fn can_write(self, perms: &Permissions) -> bool {
        perms.can_write_by(self)
    }
    fn can_execute(self, perms: &Permissions) -> bool {
        perms.can_execute_by(self)
    }
}

impl Permissions {
    fn can_read_by(&self, current: UserInfo) -> bool {
        if self.userinfo.user == current.user {
            self.mode.contains(Mode::RUSR)
        } else if self.userinfo.group == current.group {
            self.mode.contains(Mode::RGRP)
        } else {
            self.mode.contains(Mode::ROTH)
        }
    }
    fn can_write_by(&self, current: UserInfo) -> bool {
        if self.userinfo.user == current.user {
            self.mode.contains(Mode::WUSR)
        } else if self.userinfo.group == current.group {
            self.mode.contains(Mode::WGRP)
        } else {
            self.mode.contains(Mode::WOTH)
        }
    }
    fn can_execute_by(&self, current: UserInfo) -> bool {
        if self.userinfo.user == current.user {
            self.mode.contains(Mode::XUSR)
        } else if self.userinfo.group == current.group {
            self.mode.contains(Mode::XGRP)
        } else {
            self.mode.contains(Mode::XOTH)
        }
    }
}

pub(crate) enum Descriptor<Platform: sync::RawSyncPrimitivesProvider> {
    File {
        file: File<Platform>,
        read_allowed: bool,
        write_allowed: bool,
        position: usize,
        metadata: AnyMap,
    },
    Dir {
        dir: Dir<Platform>,
        metadata: AnyMap,
    },
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider };
    FileSystem<Platform>;
    @ Platform: { sync::RawSyncPrimitivesProvider };
    Descriptor<Platform>;
    -> FileFd<Platform>;
}
