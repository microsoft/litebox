//! An in-memory file system, not backed by any physical device.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::fd::FileFd;
use crate::path::Arg;
use crate::sync;

use super::errors::{
    ChmodError, CloseError, FileStatusError, MkdirError, OpenError, PathError, ReadError,
    RmdirError, SeekError, UnlinkError, WriteError,
};
use super::{FileStatus, Mode, SeekWhence};

/// A backing implementation for [`FileSystem`](super::FileSystem) storing all files in-memory.
///
/// # Warning
///
/// This has no physical backing store, thus any files in memory are erased as soon as this object
/// is dropped.
pub struct FileSystem<'platform, Platform: sync::RawSyncPrimitivesProvider> {
    // TODO: Possibly support a single-threaded variant that doesn't have the cost of requiring a
    // sync-primitives platform, as well as cost of mutexes and such?
    sync: sync::Synchronization<'platform, Platform>,
    root: sync::RwLock<'platform, Platform, RootDir<'platform, Platform>>,
    current_user: UserInfo,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
    descriptors: sync::RwLock<'platform, Platform, Descriptors<'platform, Platform>>,
}

impl<'platform, Platform: sync::RawSyncPrimitivesProvider> FileSystem<'platform, Platform> {
    /// Construct a new `FileSystem` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialiation step,
    /// and the created `FileSystem` handle is expected to be shared across all usage over the
    /// system.
    #[must_use]
    pub fn new(platform: &'platform Platform) -> Self {
        let sync = sync::Synchronization::new(platform);
        let root = sync.new_rwlock(RootDir::new(&sync));
        let descriptors = sync.new_rwlock(Descriptors::new());
        Self {
            sync,
            root,
            current_user: UserInfo {
                user: 1000,
                group: 1000,
            },
            current_working_dir: "/".into(),
            descriptors,
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
        const ROOT: UserInfo = UserInfo { user: 0, group: 0 };
        let original_user = core::mem::replace(&mut self.current_user, ROOT);
        f(self);
        let root_again = core::mem::replace(&mut self.current_user, original_user);
        if root_again.user != ROOT.user || root_again.group != ROOT.group {
            unreachable!()
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::private::Sealed
    for FileSystem<'_, Platform>
{
}

impl<Platform: sync::RawSyncPrimitivesProvider> FileSystem<'_, Platform> {
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

impl<Platform: sync::RawSyncPrimitivesProvider> super::FileSystem for FileSystem<'_, Platform> {
    fn open(
        &self,
        path: impl crate::path::Arg,
        flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<FileFd, OpenError> {
        use super::OFlags;
        let currently_supported_oflags: OFlags =
            OFlags::CREAT | OFlags::RDONLY | OFlags::WRONLY | OFlags::RDWR;
        if flags.contains(currently_supported_oflags.complement()) {
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
                };
                parent.children_count = parent.children_count.checked_add(1).unwrap();
                let entry = Entry::File(Arc::new(self.sync.new_rwlock(FileX {
                    perms: Permissions {
                        mode,
                        userinfo: self.current_user,
                    },
                    data: Vec::new(),
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
            Entry::File(file) => Ok(self.descriptors.write().insert(Descriptor::File {
                file: file.clone(),
                read_allowed,
                write_allowed,
                position: 0,
            })),
            Entry::Dir(dir) => Ok(self
                .descriptors
                .write()
                .insert(Descriptor::Dir { dir: dir.clone() })),
        }
    }

    fn close(&self, fd: FileFd) -> Result<(), CloseError> {
        self.descriptors.write().remove(fd);
        Ok(())
    }

    fn read(
        &self,
        fd: &FileFd,
        buf: &mut [u8],
        mut offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let mut descriptors = self.descriptors.write();
        let Descriptor::File {
            file,
            read_allowed,
            write_allowed: _,
            position,
        } = descriptors.get_mut(fd)
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
        fd: &FileFd,
        buf: &[u8],
        mut offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let mut descriptors = self.descriptors.write();
        let Descriptor::File {
            file,
            read_allowed: _,
            write_allowed,
            position,
        } = descriptors.get_mut(fd)
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

    fn seek(&self, fd: &FileFd, offset: isize, whence: SeekWhence) -> Result<usize, SeekError> {
        let mut descriptors = self.descriptors.write();
        let Descriptor::File {
            file,
            read_allowed: _,
            write_allowed,
            position,
        } = descriptors.get_mut(fd)
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
        let mut root = self.root.write();
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
        };
        let mut parent = parent.write();
        if !self.current_user.can_write(&parent.perms) {
            return Err(UnlinkError::NoWritePerms);
        }
        parent.children_count = parent.children_count.checked_sub(1).unwrap();
        let removed = root.entries.remove(&path).unwrap();
        // Just a sanity check
        assert!(matches!(removed, Entry::File(File { .. })));
        Ok(())
    }

    fn mkdir(&self, path: impl crate::path::Arg, mode: super::Mode) -> Result<(), MkdirError> {
        let path = self.absolute_path(path)?;
        let mut root = self.root.write();
        let (parent, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some((parent_path, parent)) = parent else {
            // Attempted to make `/`
            return Err(MkdirError::AlreadyExists);
        };
        let None = entry else {
            return Err(MkdirError::AlreadyExists);
        };
        let mut parent = parent.write();
        if !self.current_user.can_write(&parent.perms) {
            return Err(MkdirError::NoWritePerms);
        };
        parent.children_count = parent.children_count.checked_add(1).unwrap();
        let old = root.entries.insert(
            path,
            Entry::Dir(Arc::new(self.sync.new_rwlock(DirX {
                perms: Permissions {
                    mode,
                    userinfo: self.current_user,
                },
                children_count: 0,
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
        if dir.read().children_count > 0 {
            return Err(RmdirError::NotEmpty);
        }
        let mut parent = parent.write();
        if !self.current_user.can_write(&parent.perms) {
            return Err(RmdirError::NoWritePerms);
        }
        parent.children_count = parent.children_count.checked_sub(1).unwrap();
        let removed = root.entries.remove(&path).unwrap();
        // Just a sanity check
        assert!(matches!(removed, Entry::Dir(_)));
        Ok(())
    }

    fn file_status(&self, path: impl crate::path::Arg) -> Result<FileStatus, FileStatusError> {
        let path = self.absolute_path(path)?;
        let root = self.root.read();
        let (_, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        let (file_type, perms, size) = match entry {
            Entry::File(file) => {
                let file = file.read();
                (
                    super::FileType::RegularFile,
                    file.perms.clone(),
                    file.data.len(),
                )
            }
            Entry::Dir(dir) => (
                super::FileType::Directory,
                dir.read().perms.clone(),
                super::DEFAULT_DIRECTORY_SIZE,
            ),
        };
        Ok(FileStatus {
            file_type,
            mode: perms.mode,
            size,
        })
    }

    fn fd_file_status(&self, fd: &FileFd) -> Result<FileStatus, FileStatusError> {
        let (file_type, perms, size) = match self.descriptors.read().get(fd) {
            Descriptor::File { file, .. } => {
                let file = file.read();
                (
                    super::FileType::RegularFile,
                    file.perms.clone(),
                    file.data.len(),
                )
            }
            Descriptor::Dir { dir } => (
                super::FileType::Directory,
                dir.read().perms.clone(),
                super::DEFAULT_DIRECTORY_SIZE,
            ),
        };
        Ok(FileStatus {
            file_type,
            mode: perms.mode,
            size,
        })
    }
}

struct RootDir<'platform, Platform: sync::RawSyncPrimitivesProvider> {
    // keys are normalized paths; directories do not have the final `/` (thus the root would be at
    // the empty-string key "")
    entries: HashMap<String, Entry<'platform, Platform>>,
}

// Parent, if it exists, is the path as well as the directory
//
// The entry, if it exists, is just the entry itself
type ParentAndEntry<'a, D, E> = Result<(Option<(&'a str, D)>, Option<E>), PathError>;

impl<'platform, Platform: sync::RawSyncPrimitivesProvider> RootDir<'platform, Platform> {
    fn new(sync: &sync::Synchronization<'platform, Platform>) -> Self {
        Self {
            entries: [(
                String::new(),
                Entry::Dir(Arc::new(sync.new_rwlock(DirX {
                    perms: Permissions {
                        mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                        userinfo: UserInfo { user: 0, group: 0 },
                    },
                    children_count: 0,
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
    ) -> ParentAndEntry<Dir<'platform, Platform>, Entry<'platform, Platform>> {
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

enum Entry<'platform, Platform: sync::RawSyncPrimitivesProvider> {
    File(File<'platform, Platform>),
    Dir(Dir<'platform, Platform>),
}

impl<Platform: sync::RawSyncPrimitivesProvider> Entry<'_, Platform> {
    fn perms(&self) -> Permissions {
        match self {
            Self::File(file) => file.read().perms.clone(),
            Self::Dir(dir) => dir.read().perms.clone(),
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> Clone for Entry<'_, Platform> {
    fn clone(&self) -> Self {
        match self {
            Self::File(file) => Self::File(file.clone()),
            Self::Dir(dir) => Self::Dir(dir.clone()),
        }
    }
}

type Dir<'platform, Platform> = Arc<sync::RwLock<'platform, Platform, DirX>>;

struct DirX {
    perms: Permissions,
    children_count: u32,
}

type File<'platform, Platform> = Arc<sync::RwLock<'platform, Platform, FileX>>;

struct FileX {
    perms: Permissions,
    data: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Permissions {
    mode: Mode,
    userinfo: UserInfo,
}

#[derive(Clone, Copy, Debug)]
struct UserInfo {
    user: u16,
    group: u16,
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

type Descriptors<'platform, Platform> = super::shared::Descriptors<Descriptor<'platform, Platform>>;

enum Descriptor<'platform, Platform: sync::RawSyncPrimitivesProvider> {
    File {
        file: File<'platform, Platform>,
        read_allowed: bool,
        write_allowed: bool,
        position: usize,
    },
    Dir {
        dir: Dir<'platform, Platform>,
    },
}
