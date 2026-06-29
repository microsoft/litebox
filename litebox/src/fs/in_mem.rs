// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An in-memory file system, not backed by any physical device.

use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::LiteBox;
use crate::fd::Descriptors;
use crate::path::Arg;
use crate::sync;

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RenameError, RmdirError, SeekError, TruncateError, UnlinkError,
    WriteError,
};
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, SeekWhence, UserInfo};

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
        let root = sync::RwLock::new(RootDir::new());
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

    /// Initialize a primarily read-heavy file with static data.
    ///
    /// While this function could technically work with write-heavy files, it has performance
    /// benefits _particularly_ for files that are read-only, compared to doing open+write
    /// operations.
    ///
    /// The file is initialized with clone-on-write semantics for the data, meaning that the first
    /// time a write occurs on the file, it suffers the penalty of the entire data being cloned into
    /// memory, which is why this is intended primarily for read-only files (such as executables).
    ///
    /// # Panics
    ///
    /// Panics if used on
    /// - a closed FD
    /// - a non-file FD
    /// - a file that already contains data
    pub fn initialize_primarily_read_heavy_file(
        &mut self,
        fd: &FileFd<Platform>,
        data: alloc::borrow::Cow<'static, [u8]>,
    ) {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File {
            file,
            read_allowed: _,
            write_allowed: _,
            position: _,
            append_mode: _,
            ..
        } = &mut descriptor_table.get_entry_mut(fd).unwrap().entry
        else {
            panic!("must only be used on files, not directories")
        };
        let mut file = file.write();
        assert!(
            file.data.is_empty(),
            "must only be used on empty files during initialization"
        );
        file.data = data;
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

    /// Get the stored path from any fd's Descriptor.
    fn descriptor_path(
        dirfd: &FileFd<Platform>,
        descriptors: &Descriptors<Platform>,
    ) -> Option<String> {
        let entry = descriptors.get_entry(dirfd)?;
        let path = match &entry.entry {
            Descriptor::File { path, .. } | Descriptor::Dir { path, .. } => path,
        };
        Some(path.clone())
    }

    /// Get the stored path from a directory fd's Descriptor.
    ///
    /// Returns `ClosedFd` if the fd is not in the table, or `NotADirectory`
    /// if the fd refers to a regular file.
    fn dir_fd_path(&self, dirfd: &FileFd<Platform>) -> Result<String, super::DirFdError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(dirfd)
            .ok_or(super::DirFdError::ClosedFd)?;
        match &entry.entry {
            Descriptor::Dir { path, .. } => Ok(path.clone()),
            Descriptor::File { .. } => Err(super::DirFdError::NotADirectory),
        }
    }

    /// Resolve a relative path against a base directory path.
    fn resolve_relative(base: &str, rel: &str) -> Result<String, PathError> {
        if rel.is_empty() || rel == "." {
            return Ok(base.to_string());
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
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::FileSystem for FileSystem<Platform> {
    type DescriptorPlatform = Platform;

    fn open(
        &self,
        path: impl crate::path::Arg,
        mut flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        use super::OFlags;
        flags.remove(OFlags::PATH);
        let currently_supported_oflags: OFlags = OFlags::CREAT
            | OFlags::RDONLY
            | OFlags::WRONLY
            | OFlags::RDWR
            | OFlags::TRUNC
            | OFlags::NOCTTY
            | OFlags::EXCL
            | OFlags::DIRECTORY
            | OFlags::NONBLOCK
            | OFlags::LARGEFILE
            | OFlags::NOFOLLOW
            | OFlags::APPEND
            | OFlags::PATH;
        if flags.intersects(currently_supported_oflags.complement()) {
            unimplemented!("{flags:?}")
        }
        let path = self.absolute_path(path)?;
        let entry = if flags.contains(OFlags::CREAT) {
            let mut root = self.root.write();
            let (parent, entry) = root.parent_and_entry(&path, self.current_user)?;
            if let Some(entry) = entry {
                if flags.contains(OFlags::EXCL) {
                    return Err(OpenError::AlreadyExists);
                }
                (entry, false)
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
                let entry = Entry::File(Arc::new(sync::RwLock::new(FileX {
                    perms: Permissions {
                        mode,
                        userinfo: self.current_user,
                    },
                    data: Vec::new().into(),
                    unique_id: self.fresh_id(),
                })));
                let old = root.entries.insert(path.clone(), entry.clone());
                assert!(old.is_none());
                (entry, true)
            }
        } else {
            let root = self.root.read();
            let (_, entry) = root.parent_and_entry(&path, self.current_user)?;
            let Some(entry) = entry else {
                return Err(PathError::NoSuchFileOrDirectory)?;
            };
            (entry, false)
        };
        let (entry, just_created) = entry;
        // On Linux, the creator of a file always gets the requested access mode
        // regardless of the file's permission bits. Permission bits only restrict
        // future opens.
        let read_allowed = if flags.contains(OFlags::RDONLY) || flags.contains(OFlags::RDWR) {
            if !just_created && !self.current_user.can_read(&entry.perms()) {
                return Err(OpenError::AccessNotAllowed);
            }
            true
        } else {
            false
        };
        let write_allowed = if flags.contains(OFlags::WRONLY) || flags.contains(OFlags::RDWR) {
            if !just_created && !self.current_user.can_write(&entry.perms()) {
                return Err(OpenError::AccessNotAllowed);
            }
            true
        } else {
            false
        };
        let append_mode = flags.contains(OFlags::APPEND);
        let fd = match entry {
            Entry::File(file) => {
                if flags.contains(OFlags::DIRECTORY) {
                    return Err(OpenError::PathError(PathError::ComponentNotADirectory));
                }
                self.litebox
                    .descriptor_table_mut()
                    .insert(Descriptor::File {
                        file: file.clone(),
                        read_allowed,
                        write_allowed,
                        position: 0,
                        append_mode,
                        path: path.clone(),
                    })
            }
            Entry::Dir(dir) => self.litebox.descriptor_table_mut().insert(Descriptor::Dir {
                dir: dir.clone(),
                path: path.clone(),
            }),
            Entry::Symlink(_) => {
                // Symlinks must be resolved by the caller before opening.
                return Err(OpenError::PathError(PathError::ComponentNotADirectory));
            }
        };
        if flags.contains(OFlags::TRUNC) {
            match self.truncate(&fd, 0, true) {
                Ok(()) => {}
                Err(e) => {
                    self.close(&fd).unwrap();
                    return Err(e.into());
                }
            }
        }
        Ok(fd)
    }

    fn create_anonymous_file(
        &self,
        name: &str,
        mode: super::Mode,
    ) -> Result<FileFd<Platform>, super::errors::CreateAnonymousFileError> {
        let path = super::memfd_display_path(name);
        let file = Arc::new(sync::RwLock::new(FileX {
            perms: Permissions {
                mode,
                userinfo: self.current_user,
            },
            data: Vec::new().into(),
            unique_id: self.fresh_id(),
        }));
        Ok(self
            .litebox
            .descriptor_table_mut()
            .insert(Descriptor::File {
                file,
                read_allowed: true,
                write_allowed: true,
                position: 0,
                append_mode: false,
                path,
            }))
    }

    fn close(&self, fd: &FileFd<Platform>) -> Result<(), CloseError> {
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
            append_mode: _,
            ..
        } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(ReadError::ClosedFd)?
            .entry
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
            append_mode,
            ..
        } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(WriteError::ClosedFd)?
            .entry
        else {
            return Err(WriteError::NotAFile);
        };
        if !*write_allowed {
            return Err(WriteError::NotForWriting);
        }
        // For append mode, we always write at the end of the file.
        // Note: pwrite (offset != None) ignores append mode per POSIX.
        let mut file = file.write();
        let write_position = if *append_mode && offset.is_none() {
            file.data.len()
        } else {
            *offset.as_mut().unwrap_or(position)
        };
        let end_position = write_position.checked_add(buf.len()).unwrap();
        let start = if write_position < file.data.len() {
            let start = write_position;
            let end = end_position.min(file.data.len());
            debug_assert!(start <= end);
            let first_half_len = end - start;
            file.data.to_mut()[start..end].copy_from_slice(&buf[..first_half_len]);
            first_half_len
        } else {
            if write_position > file.data.len() {
                // Need to pad with 0s because position was past the end of the file
                file.data.to_mut().resize(write_position, 0);
            }
            0
        };
        file.data.to_mut().extend(&buf[start..]);
        // Update the file position for positional writes (not pwrite)
        if offset.is_none() {
            *position = end_position;
        }
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
            append_mode: _,
            ..
        } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(SeekError::ClosedFd)?
            .entry
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

    fn truncate(
        &self,
        fd: &FileFd<Platform>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File {
            file,
            read_allowed: _,
            write_allowed,
            position,
            append_mode: _,
            ..
        } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(TruncateError::ClosedFd)?
            .entry
        else {
            return Err(TruncateError::IsDirectory);
        };
        if !*write_allowed {
            return Err(TruncateError::NotForWriting);
        }
        let mut file_data = file.write();
        match length.cmp(&file_data.data.len()) {
            core::cmp::Ordering::Less => match &mut file_data.data {
                alloc::borrow::Cow::Borrowed(d) => {
                    *d = &d[..length];
                }
                alloc::borrow::Cow::Owned(d) => d.truncate(length),
            },
            core::cmp::Ordering::Equal => (),
            core::cmp::Ordering::Greater => file_data.data.to_mut().resize(length, 0),
        }
        if reset_offset {
            *position = 0;
        }
        Ok(())
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
            Entry::Symlink(_) => {
                // Symlinks must be resolved by the caller before chmod.
                Err(PathError::NoSuchFileOrDirectory)?
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
            Entry::Symlink(_) => {
                // Symlinks must be resolved by the caller before chown.
                Err(PathError::NoSuchFileOrDirectory)?
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
        assert!(matches!(
            removed,
            Some(FileType::RegularFile | FileType::Symlink)
        ));
        let removed = root.entries.remove(&path).unwrap();
        assert!(matches!(removed, Entry::File(_) | Entry::Symlink(_)));
        Ok(())
    }

    fn rename(
        &self,
        old_path: impl crate::path::Arg,
        new_path: impl crate::path::Arg,
    ) -> Result<(), RenameError> {
        let old_path = self.absolute_path(old_path)?;
        let new_path = self.absolute_path(new_path)?;

        if old_path == new_path {
            return Ok(());
        }

        let mut root = self.root.write();

        // Validate old path exists
        let (old_parent, old_entry) = root.parent_and_entry(&old_path, self.current_user)?;
        let Some((_, old_parent_dir)) = old_parent else {
            // Cannot rename /
            return Err(RenameError::NoWritePerms);
        };
        let Some(old_entry) = old_entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        let old_is_dir = matches!(old_entry, Entry::Dir(_));

        // Check write permission on old parent
        if !self.current_user.can_write(&old_parent_dir.read().perms) {
            return Err(RenameError::NoWritePerms);
        }

        // Validate new path parent exists
        let (new_parent, new_entry) = root.parent_and_entry(&new_path, self.current_user)?;
        let Some((_, new_parent_dir)) = new_parent else {
            return Err(RenameError::NoWritePerms);
        };

        // Check write permission on new parent
        if !self.current_user.can_write(&new_parent_dir.read().perms) {
            return Err(RenameError::NoWritePerms);
        }

        // If new path exists, validate compatibility
        if let Some(new_entry) = &new_entry {
            let new_is_dir = matches!(new_entry, Entry::Dir(_));
            if old_is_dir && !new_is_dir {
                return Err(RenameError::NotADirectory);
            }
            if !old_is_dir && new_is_dir {
                return Err(RenameError::IsADirectory);
            }
            if let Entry::Dir(d) = new_entry
                && !d.read().children.is_empty()
            {
                return Err(RenameError::NotEmpty);
            }
        }

        // Perform the rename: remove from old location, insert at new
        let old_name = old_path.components().unwrap().last().unwrap().to_string();
        let new_name = new_path.components().unwrap().last().unwrap().to_string();
        let file_type = old_parent_dir.write().children.remove(&old_name).unwrap();

        // Remove old entry from new parent's children if replacing
        if new_entry.is_some() {
            new_parent_dir.write().children.remove(&new_name);
            root.entries.remove(&new_path);
        }

        // Insert into new parent
        new_parent_dir.write().children.insert(new_name, file_type);

        // Move entry in the entries map
        let entry = root.entries.remove(&old_path).unwrap();
        root.entries.insert(new_path.clone(), entry);

        // If renaming a directory, update all descendant paths
        if old_is_dir {
            let mut prefix = old_path.clone();
            prefix.push('/');
            let to_move: Vec<(String, Entry<Platform>)> = root
                .entries
                .keys()
                .filter(|k| k.starts_with(prefix.as_str()))
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .map(|k| {
                    let entry = root.entries.remove(&k).unwrap();
                    let mut new_key = new_path.clone();
                    new_key.push_str(&k[old_path.len()..]);
                    (new_key, entry)
                })
                .collect();
            for (new_key, entry) in to_move {
                root.entries.insert(new_key, entry);
            }
        }

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
            Entry::Dir(Arc::new(sync::RwLock::new(DirX {
                perms: Permissions {
                    mode,
                    userinfo: self.current_user,
                },
                children: HashMap::default(),
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

    fn symlink(
        &self,
        target: impl crate::path::Arg,
        linkpath: impl crate::path::Arg,
    ) -> Result<(), super::errors::SymlinkError> {
        let target_str = target
            .as_rust_str()
            .map_err(|_| super::errors::SymlinkError::Io)?
            .to_string();
        let path = self
            .absolute_path(linkpath)
            .map_err(super::errors::SymlinkError::PathError)?;
        let mut root = self.root.write();
        let (parent, existing) = root.parent_and_entry(&path, self.current_user)?;
        if existing.is_some() {
            return Err(super::errors::SymlinkError::AlreadyExists);
        }
        let Some((_, parent)) = parent else {
            return Err(super::errors::SymlinkError::Io);
        };
        let mut parent = parent.write();
        if !self.current_user.can_write(&parent.perms) {
            return Err(super::errors::SymlinkError::NoWritePerms);
        }
        let old = parent.children.insert(
            path.components().unwrap().last().unwrap().into(),
            FileType::Symlink,
        );
        assert!(old.is_none());
        let entry = Entry::Symlink(SymlinkEntry {
            perms: Permissions {
                mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                userinfo: self.current_user,
            },
            target: target_str,
            unique_id: self.fresh_id(),
        });
        let old = root.entries.insert(path, entry);
        assert!(old.is_none());
        Ok(())
    }

    fn read_link(
        &self,
        path: impl crate::path::Arg,
    ) -> Result<alloc::string::String, super::errors::ReadLinkError> {
        let path = self
            .absolute_path(path)
            .map_err(super::errors::ReadLinkError::PathError)?;
        let root = self.root.read();
        let (_, entry) = root
            .parent_and_entry(&path, self.current_user)
            .map_err(super::errors::ReadLinkError::PathError)?;
        match entry {
            Some(Entry::Symlink(link)) => Ok(link.target.clone()),
            Some(_) => Err(super::errors::ReadLinkError::NotASymlink),
            None => Err(super::errors::ReadLinkError::PathError(
                super::errors::PathError::NoSuchFileOrDirectory,
            )),
        }
    }

    fn link(
        &self,
        oldpath: impl crate::path::Arg,
        newpath: impl crate::path::Arg,
    ) -> Result<(), super::errors::LinkError> {
        let old = self
            .absolute_path(oldpath)
            .map_err(super::errors::LinkError::PathError)?;
        let new = self
            .absolute_path(newpath)
            .map_err(super::errors::LinkError::PathError)?;
        let mut root = self.root.write();
        let (_, old_entry) = root.parent_and_entry(&old, self.current_user)?;
        let Some(old_entry) = old_entry else {
            return Err(super::errors::PathError::NoSuchFileOrDirectory)?;
        };
        let old_entry = old_entry.clone();
        if matches!(old_entry, Entry::Dir(_)) {
            return Err(super::errors::LinkError::IsDirectory);
        }
        let (new_parent, existing) = root.parent_and_entry(&new, self.current_user)?;
        if existing.is_some() {
            return Err(super::errors::LinkError::AlreadyExists);
        }
        let Some((_, new_parent)) = new_parent else {
            return Err(super::errors::LinkError::Io);
        };
        let mut parent = new_parent.write();
        if !self.current_user.can_write(&parent.perms) {
            return Err(super::errors::LinkError::NoWritePerms);
        }
        let file_type = match &old_entry {
            Entry::File(_) => FileType::RegularFile,
            Entry::Symlink(_) => FileType::Symlink,
            Entry::Dir(_) => unreachable!(),
        };
        let old = parent
            .children
            .insert(new.components().unwrap().last().unwrap().into(), file_type);
        assert!(old.is_none());
        let old = root.entries.insert(new, old_entry);
        assert!(old.is_none());
        Ok(())
    }

    fn read_dir(&self, fd: &FileFd<Platform>) -> Result<Vec<DirEntry>, ReadDirError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::Dir { dir, .. } = &descriptor_table
            .get_entry(fd)
            .ok_or(ReadDirError::ClosedFd)?
            .entry
        else {
            return Err(ReadDirError::NotADirectory);
        };

        // find the directory path in the root entries by pointer-equality of the Arc
        let mut parent_path = {
            let root = self.root.read();
            root.entries
                .iter()
                .find_map(|(path, entry)| match entry {
                    Entry::Dir(d) if alloc::sync::Arc::ptr_eq(d, dir) => Some(path.clone()),
                    Entry::Dir(_) | Entry::File(_) | Entry::Symlink(_) => None,
                })
                .unwrap_or(String::new())
        };

        // helper to get NodeInfo by an entries-key (entries keys have no trailing '/')
        let get_node_info = |key: &str| -> Option<NodeInfo> {
            self.root.read().entries.get(key).map(|entry| {
                let ino = match entry {
                    Entry::File(file) => file.read().unique_id,
                    Entry::Dir(dir) => dir.read().unique_id,
                    Entry::Symlink(link) => link.unique_id,
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
            Entry::Symlink(link) => (
                super::FileType::Symlink,
                link.perms.clone(),
                link.target.len(),
                link.unique_id,
            ),
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
        let (file_type, perms, size, unique_id) = match &self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(FileStatusError::ClosedFd)?
            .entry
        {
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

    fn get_static_backing_data(&self, fd: &FileFd<Platform>) -> Option<&'static [u8]> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.get_entry(fd)?;
        match &entry.entry {
            Descriptor::File { file, .. } => {
                let file = file.read();
                match &file.data {
                    alloc::borrow::Cow::Borrowed(slice) => Some(*slice),
                    alloc::borrow::Cow::Owned(_) => None,
                }
            }
            Descriptor::Dir { .. } => None,
        }
    }

    fn is_writable(&self, fd: &FileFd<Platform>) -> bool {
        let descriptor_table = self.litebox.descriptor_table();
        let Some(entry) = descriptor_table.get_entry(fd) else {
            return false;
        };
        matches!(
            &entry.entry,
            Descriptor::File {
                write_allowed: true,
                ..
            }
        )
    }

    fn open_at(
        &self,
        dirfd: &FileFd<Platform>,
        rel_path: impl crate::path::Arg,
        flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        let dir = self.dir_fd_path(dirfd).map_err(|e| match e {
            super::DirFdError::ClosedFd => OpenError::ClosedFd,
            super::DirFdError::NotADirectory => OpenError::NotADirectory,
            super::DirFdError::Io => OpenError::Io,
        })?;
        let rel = rel_path
            .as_rust_str()
            .map_err(|e| OpenError::PathError(e.into()))?;
        let abs = Self::resolve_relative(&dir, rel).map_err(OpenError::PathError)?;
        self.open(abs, flags, mode)
    }

    fn stat_at(
        &self,
        dirfd: &FileFd<Platform>,
        rel_path: impl crate::path::Arg,
        follow_symlinks: bool,
    ) -> Result<super::FileStatus, super::FileStatusError> {
        let dir = self.dir_fd_path(dirfd).map_err(|e| match e {
            super::DirFdError::ClosedFd => super::FileStatusError::ClosedFd,
            super::DirFdError::NotADirectory => super::FileStatusError::NotADirectory,
            super::DirFdError::Io => super::FileStatusError::Io,
        })?;
        let rel = rel_path
            .as_rust_str()
            .map_err(|e| super::FileStatusError::PathError(e.into()))?;
        let mut abs =
            Self::resolve_relative(&dir, rel).map_err(super::FileStatusError::PathError)?;
        if follow_symlinks {
            let mut hops = 40usize;
            loop {
                let status = self.file_status(&*abs)?;
                if status.file_type != FileType::Symlink {
                    return Ok(status);
                }
                if hops == 0 {
                    return Err(super::FileStatusError::SymlinkLoop);
                }
                hops -= 1;
                let target = self
                    .read_link(&*abs)
                    .map_err(|_| super::FileStatusError::Io)?;
                if target.starts_with('/') {
                    abs = target;
                } else {
                    let parent_end = abs.rfind('/').unwrap_or(0).max(1);
                    abs.truncate(parent_end);
                    if !abs.ends_with('/') {
                        abs.push('/');
                    }
                    abs.push_str(&target);
                }
            }
        }
        self.file_status(abs)
    }

    fn unlink_at(
        &self,
        dirfd: &FileFd<Platform>,
        rel_path: impl crate::path::Arg,
    ) -> Result<(), UnlinkError> {
        let dir = self.dir_fd_path(dirfd).map_err(|e| match e {
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
        dirfd: &FileFd<Platform>,
        rel_path: impl crate::path::Arg,
    ) -> Result<alloc::string::String, super::errors::ReadLinkError> {
        let dir = self.dir_fd_path(dirfd).map_err(|e| match e {
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
        old_dirfd: &FileFd<Platform>,
        old_rel: impl crate::path::Arg,
        new_dirfd: &FileFd<Platform>,
        new_rel: impl crate::path::Arg,
    ) -> Result<(), RenameError> {
        let old_dir = self.dir_fd_path(old_dirfd).map_err(|e| match e {
            super::DirFdError::ClosedFd => RenameError::ClosedFd,
            super::DirFdError::NotADirectory => RenameError::NotADirectory,
            super::DirFdError::Io => RenameError::Io,
        })?;
        let old_r = old_rel
            .as_rust_str()
            .map_err(|e| RenameError::PathError(e.into()))?;
        let old_abs = Self::resolve_relative(&old_dir, old_r).map_err(RenameError::PathError)?;
        let new_dir = self.dir_fd_path(new_dirfd).map_err(|e| match e {
            super::DirFdError::ClosedFd => RenameError::ClosedFd,
            super::DirFdError::NotADirectory => RenameError::NotADirectory,
            super::DirFdError::Io => RenameError::Io,
        })?;
        let new_r = new_rel
            .as_rust_str()
            .map_err(|e| RenameError::PathError(e.into()))?;
        let new_abs = Self::resolve_relative(&new_dir, new_r).map_err(RenameError::PathError)?;
        self.rename(old_abs, new_abs)
    }

    fn fd_path(
        &self,
        fd: &FileFd<Platform>,
        descriptors: &Descriptors<Platform>,
    ) -> Option<alloc::string::String> {
        Self::descriptor_path(fd, descriptors)
    }

    fn mkdir_at(
        &self,
        dirfd: &FileFd<Platform>,
        rel_path: impl crate::path::Arg,
        mode: super::Mode,
    ) -> Result<(), MkdirError> {
        let dir = self.dir_fd_path(dirfd).map_err(|e| match e {
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
    fn new() -> Self {
        // The root directory is owned by the default non-root user so that
        // the guest process can create top-level directories. The runner
        // uses `with_root_privileges` for any setup that needs elevated
        // access. This mirrors a single-user sandbox where the guest owns
        // the entire filesystem tree.
        Self {
            entries: [(
                String::new(),
                Entry::Dir(Arc::new(sync::RwLock::new(DirX {
                    perms: Permissions {
                        mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                        userinfo: UserInfo {
                            user: 1000,
                            group: 1000,
                        },
                    },
                    children: HashMap::default(),
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
                (_, Entry::File(_) | Entry::Symlink(_)) => {
                    return Err(PathError::ComponentNotADirectory);
                }
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
    Symlink(SymlinkEntry),
}

impl<Platform: sync::RawSyncPrimitivesProvider> Entry<Platform> {
    fn perms(&self) -> Permissions {
        match self {
            Self::File(file) => file.read().perms.clone(),
            Self::Dir(dir) => dir.read().perms.clone(),
            Self::Symlink(link) => link.perms.clone(),
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> Clone for Entry<Platform> {
    fn clone(&self) -> Self {
        match self {
            Self::File(file) => Self::File(file.clone()),
            Self::Dir(dir) => Self::Dir(dir.clone()),
            Self::Symlink(link) => Self::Symlink(link.clone()),
        }
    }
}

type Dir<Platform> = Arc<sync::RwLock<Platform, DirX>>;

pub(crate) struct DirX {
    perms: Permissions,
    children: HashMap<String, FileType>,
    unique_id: usize,
}

type File<Platform> = Arc<sync::RwLock<Platform, FileX>>;

pub(crate) struct FileX {
    perms: Permissions,
    data: alloc::borrow::Cow<'static, [u8]>,
    unique_id: usize,
}

#[derive(Clone)]
struct SymlinkEntry {
    perms: Permissions,
    target: String,
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
        // CAP_DAC_OVERRIDE: root bypasses all file permission checks.
        if current.user == 0 {
            return true;
        }
        if self.userinfo.user == current.user {
            self.mode.contains(Mode::RUSR)
        } else if self.userinfo.group == current.group {
            self.mode.contains(Mode::RGRP)
        } else {
            self.mode.contains(Mode::ROTH)
        }
    }
    fn can_write_by(&self, current: UserInfo) -> bool {
        if current.user == 0 {
            return true;
        }
        if self.userinfo.user == current.user {
            self.mode.contains(Mode::WUSR)
        } else if self.userinfo.group == current.group {
            self.mode.contains(Mode::WGRP)
        } else {
            self.mode.contains(Mode::WOTH)
        }
    }
    fn can_execute_by(&self, current: UserInfo) -> bool {
        // CAP_DAC_OVERRIDE bypasses execute checks on directories but not
        // regular files (where at least one execute bit must be set).
        // For simplicity we grant full bypass — files in the sandbox are
        // typically marked executable when they need to be.
        if current.user == 0 {
            return true;
        }
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
        append_mode: bool,
        path: String,
    },
    Dir {
        dir: Dir<Platform>,
        path: String,
    },
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider };
    FileSystem<Platform>;
    @ Platform: { sync::RawSyncPrimitivesProvider };
    Descriptor<Platform>;
    crate::fd::SubsystemKind::Fs;
    -> FileFd<Platform>;
}
