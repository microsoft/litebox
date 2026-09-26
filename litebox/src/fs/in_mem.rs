// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An in-memory file system, not backed by any physical device.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::LiteBox;
use crate::path::Arg;
use crate::sync;

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, ReadlinkError, RenameError, RmdirError, SeekError, SymlinkError,
    TruncateError, UnlinkError, UtimeError, WriteError,
};
use super::{
    AccessCredentials, DacAccessKind, DirEntry, FileStatus, FileType, Mode, NodeInfo, SeekWhence,
    Timestamp, UserInfo,
};

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

    /// Set the identity every subsequent operation runs as (and thus records as the owner of
    /// anything it creates). The single-user default is 1000/1000; a runner presenting the
    /// guest as root (`--guest-root`) must set 0/0 here too, or everything the guest creates
    /// is owned by a uid it doesn't have -- observed live as Xorg refusing to bind
    /// `/tmp/.X11-unix/X0` (its socket dir "owned" by 1000 while X ran as 0) and dbus
    /// rejecting `XDG_RUNTIME_DIR` for the same mismatch.
    pub fn set_current_user(&mut self, user: u16, group: u16) {
        self.current_user = UserInfo { user, group };
    }

    /// Return the identity used for permission and ownership checks.
    pub fn current_user(&self) -> UserInfo {
        self.current_user
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
            path_only: _,
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

impl<Platform: sync::RawSyncPrimitivesProvider> super::private::Sealed for FileSystem<Platform> {
    fn mkdir_for_copy_up(
        &self,
        _token: &super::private::CopyUpToken,
        path: &str,
        mode: Mode,
        owner: UserInfo,
    ) -> Result<(), MkdirError> {
        let path = self.absolute_path(path)?;
        self.mkdir_inner(path, mode, owner, false, AccessCredentials::root())
    }

    fn create_file_for_copy_up(
        &self,
        _token: &super::private::CopyUpToken,
        path: &str,
        mode: Mode,
        owner: UserInfo,
    ) -> Result<FileFd<Platform>, OpenError> {
        let path = self.absolute_path(path)?;
        self.create_file_for_copy_up_inner(path, mode, owner)
    }

    fn publish_file_for_copy_up(
        &self,
        _token: &super::private::CopyUpToken,
        staging_path: &str,
        destination_path: &str,
    ) -> Result<(), RenameError> {
        let staging_path = self.absolute_path(staging_path)?;
        let destination_path = self.absolute_path(destination_path)?;
        if staging_path == destination_path {
            return Err(RenameError::InvalidArgument);
        }

        let mut root = self.root.write();
        let (staging_parent, staging_entry) =
            root.parent_and_entry_as(&staging_path, AccessCredentials::root())?;
        let staging_parent = staging_parent.map(|(_, directory)| directory);
        let Some(Entry::File(_)) = staging_entry else {
            return Err(PathError::NoSuchFileOrDirectory.into());
        };
        let Some(staging_parent) = staging_parent else {
            return Err(RenameError::InvalidArgument);
        };

        let (destination_parent, destination_entry) =
            root.parent_and_entry_as(&destination_path, AccessCredentials::root())?;
        let destination_parent = destination_parent.map(|(_, directory)| directory);
        if destination_entry.is_some() {
            return Err(RenameError::AlreadyExists);
        }
        let Some(destination_parent) = destination_parent else {
            return Err(RenameError::InvalidArgument);
        };
        if !Arc::ptr_eq(&staging_parent, &destination_parent) {
            return Err(RenameError::InvalidArgument);
        }

        let staging_name: String = staging_path
            .components()
            .map_err(PathError::from)?
            .last()
            .ok_or(RenameError::InvalidArgument)?
            .into();
        let destination_name: String = destination_path
            .components()
            .map_err(PathError::from)?
            .last()
            .ok_or(RenameError::InvalidArgument)?
            .into();
        let mut parent = staging_parent.write();
        if parent.children.get(&staging_name) != Some(&FileType::RegularFile)
            || parent.children.contains_key(&destination_name)
        {
            return Err(RenameError::Io);
        }
        let Some(staging_entry) = root.entries.remove(&staging_path) else {
            return Err(RenameError::Io);
        };
        parent.children.remove(&staging_name);
        parent
            .children
            .insert(destination_name, FileType::RegularFile);
        root.entries.insert(destination_path, staging_entry);
        Ok(())
    }

    fn remove_file_for_copy_up(
        &self,
        _token: &super::private::CopyUpToken,
        staging_path: &str,
    ) -> Result<(), UnlinkError> {
        let staging_path = self.absolute_path(staging_path)?;
        let mut root = self.root.write();
        let (parent, entry) = root.parent_and_entry_as(&staging_path, AccessCredentials::root())?;
        let parent = parent.map(|(_, directory)| directory);
        let Some(Entry::File(_)) = entry else {
            return match entry {
                Some(Entry::Dir(_)) => Err(UnlinkError::IsADirectory),
                Some(Entry::SymLink(_)) => Err(UnlinkError::Io),
                Some(Entry::File(_)) => unreachable!(),
                None => Err(PathError::NoSuchFileOrDirectory.into()),
            };
        };
        let Some(parent) = parent else {
            return Err(UnlinkError::IsADirectory);
        };
        let Some(staging_name) = staging_path.components().map_err(PathError::from)?.last() else {
            return Err(UnlinkError::IsADirectory);
        };
        let mut parent = parent.write();
        if parent.children.get(staging_name) != Some(&FileType::RegularFile)
            || !matches!(root.entries.get(&staging_path), Some(Entry::File(_)))
        {
            return Err(UnlinkError::Io);
        }
        parent.children.remove(staging_name);
        root.entries.remove(&staging_path);
        Ok(())
    }

    fn read_file_for_copy_up(
        &self,
        _token: &super::private::CopyUpToken,
        fd: &FileFd<Platform>,
        buf: &mut [u8],
        offset: usize,
    ) -> Result<usize, ReadError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.get_entry(fd).ok_or(ReadError::ClosedFd)?;
        let Descriptor::File { file, .. } = &entry.entry else {
            return Err(ReadError::NotAFile);
        };
        let file = file.read();
        let start = offset.min(file.data.len());
        let end = offset
            .checked_add(buf.len())
            .ok_or(ReadError::Io)?
            .min(file.data.len());
        let size = end.checked_sub(start).ok_or(ReadError::Io)?;
        buf[..size].copy_from_slice(&file.data[start..end]);
        Ok(size)
    }

    fn set_times_for_copy_up(
        &self,
        _token: &super::private::CopyUpToken,
        fd: &FileFd<Platform>,
        atime: Timestamp,
        mtime: Timestamp,
        ctime: Timestamp,
    ) -> Result<(), UtimeError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.get_entry(fd).ok_or(UtimeError::ClosedFd)?;
        let Descriptor::File { file, .. } = &entry.entry else {
            return Err(UtimeError::Io);
        };
        let mut file = file.write();
        file.atime = atime;
        file.mtime = mtime;
        file.ctime = ctime;
        Ok(())
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> FileSystem<Platform> {
    fn update_owner(
        credentials: AccessCredentials<'_>,
        perms: &mut Permissions,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        if credentials.user() != 0
            && (!credentials.owns(perms.userinfo)
                || user.is_some_and(|user| user != perms.userinfo.user)
                || group.is_some_and(|group| !credentials.in_group(group)))
        {
            return Err(ChownError::NotTheOwner);
        }
        let changed = user.is_some_and(|user| user != perms.userinfo.user)
            || group.is_some_and(|group| group != perms.userinfo.group);
        if let Some(user) = user {
            perms.userinfo.user = user;
        }
        if let Some(group) = group {
            perms.userinfo.group = group;
        }
        if changed {
            perms.mode.remove(Mode::SUID | Mode::SGID);
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

    fn mkdir_inner(
        &self,
        path: String,
        mode: Mode,
        owner: UserInfo,
        require_parent_write: bool,
        credentials: AccessCredentials<'_>,
    ) -> Result<(), MkdirError> {
        let mut root = self.root.write();
        let (parent, entry) = root.parent_and_entry_as(&path, credentials)?;
        let Some((_parent_path, parent)) = parent else {
            return Err(MkdirError::AlreadyExists);
        };
        let None = entry else {
            return Err(MkdirError::AlreadyExists);
        };
        let mut parent = parent.write();
        if require_parent_write
            && !super::dac_allows_as(
                credentials,
                parent.perms.userinfo,
                parent.perms.mode,
                DacAccessKind::Write,
            )
        {
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
                    userinfo: owner,
                },
                children: HashMap::default(),
                unique_id: self.fresh_id(),
                atime: Timestamp::default(),
                mtime: Timestamp::default(),
                ctime: Timestamp::default(),
            }))),
        );
        assert!(old.is_none());
        Ok(())
    }

    fn create_file_for_copy_up_inner(
        &self,
        path: String,
        mode: Mode,
        owner: UserInfo,
    ) -> Result<FileFd<Platform>, OpenError> {
        let mut root = self.root.write();
        let (parent, entry) = root.parent_and_entry_as(&path, AccessCredentials::root())?;
        let Some((_, parent)) = parent else {
            return Err(OpenError::AlreadyExists);
        };
        if entry.is_some() {
            return Err(OpenError::AlreadyExists);
        }
        let mut parent = parent.write();
        let old = parent.children.insert(
            path.components().unwrap().last().unwrap().into(),
            FileType::RegularFile,
        );
        assert!(old.is_none());
        let file = Arc::new(sync::RwLock::new(FileX {
            perms: Permissions {
                mode,
                userinfo: owner,
            },
            data: Vec::new().into(),
            unique_id: self.fresh_id(),
            atime: Timestamp::default(),
            mtime: Timestamp::default(),
            ctime: Timestamp::default(),
        }));
        let old = root.entries.insert(path, Entry::File(file.clone()));
        assert!(old.is_none());
        drop(parent);
        drop(root);
        Ok(self
            .litebox
            .descriptor_table_mut()
            .insert(Descriptor::File {
                file,
                read_allowed: false,
                write_allowed: true,
                position: 0,
                append_mode: false,
                path_only: false,
            }))
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::FileSystem for FileSystem<Platform> {
    fn open(
        &self,
        path: impl crate::path::Arg,
        flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        self.open_as(self.current_user.into(), path, flags, mode)
    }

    fn open_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl crate::path::Arg,
        mut flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        use super::OFlags;
        flags = flags.normalized_for_open();
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
            | OFlags::NOATIME
            | OFlags::NOFOLLOW
            | OFlags::APPEND
            | OFlags::PATH;
        if flags.intersects(currently_supported_oflags.complement()) {
            return Err(OpenError::UnsupportedFlags);
        }
        let path = self.absolute_path(path)?;
        let (entry, created) = if flags.contains(OFlags::CREAT) {
            let mut root = self.root.write();
            let (parent, entry) = root.parent_and_entry_as(&path, credentials)?;
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
                if !super::dac_allows_as(
                    credentials,
                    parent.perms.userinfo,
                    parent.perms.mode,
                    DacAccessKind::Write,
                ) {
                    return Err(OpenError::NoWritePerms);
                }
                // When both O_CREAT and O_DIRECTORY are specified in flags and the
                // file specified by pathname does not exist, open() will create a
                // regular file (i.e., O_DIRECTORY is ignored).
                flags.remove(OFlags::DIRECTORY);
                let owner = credentials
                    .as_user_info()
                    .ok_or(OpenError::OperationNotPermitted)?;
                let old = parent.children.insert(
                    path.components().unwrap().last().unwrap().into(),
                    FileType::RegularFile,
                );
                assert!(old.is_none());
                let entry = Entry::File(Arc::new(sync::RwLock::new(FileX {
                    perms: Permissions {
                        mode,
                        userinfo: owner,
                    },
                    data: Vec::new().into(),
                    unique_id: self.fresh_id(),
                    atime: Timestamp::default(),
                    mtime: Timestamp::default(),
                    ctime: Timestamp::default(),
                })));
                let old = root.entries.insert(path, entry.clone());
                assert!(old.is_none());
                (entry, true)
            }
        } else {
            let root = self.root.read();
            let (_, entry) = root.parent_and_entry_as(&path, credentials)?;
            let Some(entry) = entry else {
                return Err(PathError::NoSuchFileOrDirectory)?;
            };
            (entry, false)
        };
        if flags.contains(OFlags::NOATIME) {
            let owner = entry.perms().userinfo;
            if credentials.user() != 0 && !credentials.owns(owner) {
                return Err(OpenError::OperationNotPermitted);
            }
        }
        let path_only = flags.contains(OFlags::PATH);
        let access_mode = flags & (OFlags::WRONLY | OFlags::RDWR);
        let read_allowed =
            if !path_only && (access_mode == OFlags::RDONLY || access_mode == OFlags::RDWR) {
                if !created {
                    let permissions = entry.perms();
                    if !super::dac_allows_as(
                        credentials,
                        permissions.userinfo,
                        permissions.mode,
                        DacAccessKind::Read,
                    ) {
                        return Err(OpenError::AccessNotAllowed);
                    }
                }
                true
            } else {
                false
            };
        let write_allowed =
            if !path_only && (access_mode == OFlags::WRONLY || access_mode == OFlags::RDWR) {
                if !created {
                    let permissions = entry.perms();
                    if !super::dac_allows_as(
                        credentials,
                        permissions.userinfo,
                        permissions.mode,
                        DacAccessKind::Write,
                    ) {
                        return Err(OpenError::AccessNotAllowed);
                    }
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
                        path_only,
                    })
            }
            Entry::Dir(dir) => self.litebox.descriptor_table_mut().insert(Descriptor::Dir {
                dir: dir.clone(),
                position: Arc::new(sync::Mutex::new(0)),
                path_only,
            }),
            Entry::SymLink(link) if path_only => {
                if flags.contains(OFlags::DIRECTORY) {
                    return Err(OpenError::PathError(PathError::ComponentNotADirectory));
                }
                self.litebox
                    .descriptor_table_mut()
                    .insert(Descriptor::SymLink { link: link.clone() })
            }
            Entry::SymLink(_) => {
                // The shim resolves symlink following before it ever calls
                // `open`, so a symlink reaching here without O_PATH means
                // O_NOFOLLOW was set on the final component.
                return Err(OpenError::TooManySymbolicLinks);
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
        let descriptor = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(ReadError::ClosedFd)?
            .entry;
        if match descriptor {
            Descriptor::File { path_only, .. } | Descriptor::Dir { path_only, .. } => *path_only,
            Descriptor::SymLink { .. } => true,
        } {
            return Err(ReadError::NotForReading);
        }
        let Descriptor::File {
            file,
            read_allowed,
            write_allowed: _,
            position,
            append_mode: _,
            path_only: _,
        } = descriptor
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
        let descriptor = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(WriteError::ClosedFd)?
            .entry;
        if match descriptor {
            Descriptor::File { path_only, .. } | Descriptor::Dir { path_only, .. } => *path_only,
            Descriptor::SymLink { .. } => true,
        } {
            return Err(WriteError::NotForWriting);
        }
        let Descriptor::File {
            file,
            read_allowed: _,
            write_allowed,
            position,
            append_mode,
            path_only: _,
        } = descriptor
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
        let descriptor = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(SeekError::ClosedFd)?
            .entry;
        match descriptor {
            Descriptor::File {
                file,
                position,
                path_only,
                ..
            } => {
                if *path_only {
                    return Err(SeekError::NotAFile);
                }
                let file_len = file.read().data.len();
                let base = match whence {
                    SeekWhence::RelativeToBeginning => 0,
                    SeekWhence::RelativeToCurrentOffset => *position,
                    SeekWhence::RelativeToEnd => file_len,
                };
                let new_position = base
                    .checked_add_signed(offset)
                    .ok_or(SeekError::InvalidOffset)?;
                if isize::try_from(new_position).is_err() {
                    return Err(SeekError::InvalidOffset);
                }
                *position = new_position;
                Ok(new_position)
            }
            Descriptor::Dir {
                position,
                path_only,
                ..
            } => {
                if *path_only {
                    return Err(SeekError::NotAFile);
                }
                let mut position = position.lock();
                let base = match whence {
                    SeekWhence::RelativeToBeginning => 0,
                    SeekWhence::RelativeToCurrentOffset => *position,
                    SeekWhence::RelativeToEnd => return Err(SeekError::InvalidOffset),
                };
                let new_position = base
                    .checked_add_signed(offset)
                    .ok_or(SeekError::InvalidOffset)?;
                if isize::try_from(new_position).is_err() {
                    return Err(SeekError::InvalidOffset);
                }
                *position = new_position;
                Ok(new_position)
            }
            Descriptor::SymLink { .. } => Err(SeekError::NotAFile),
        }
    }

    fn truncate(
        &self,
        fd: &FileFd<Platform>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        let descriptor_table = self.litebox.descriptor_table();
        let descriptor = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(TruncateError::ClosedFd)?
            .entry;
        if match descriptor {
            Descriptor::File { path_only, .. } | Descriptor::Dir { path_only, .. } => *path_only,
            Descriptor::SymLink { .. } => true,
        } {
            return Err(TruncateError::PathOnlyFd);
        }
        let Descriptor::File {
            file,
            read_allowed: _,
            write_allowed,
            position,
            append_mode: _,
            path_only: _,
        } = descriptor
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
        self.chmod_as(self.current_user.into(), path, mode)
    }

    fn chmod_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl crate::path::Arg,
        mode: super::Mode,
    ) -> Result<(), ChmodError> {
        let path = self.absolute_path(path)?;
        let root = self.root.read();
        let (_, entry) = root.parent_and_entry_as(&path, credentials)?;
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        match entry {
            Entry::File(file) => {
                let perms = &mut file.write().perms;
                if !(credentials.user() == 0 || credentials.owns(perms.userinfo)) {
                    return Err(ChmodError::NotTheOwner);
                }
                perms.mode = mode;
                Ok(())
            }
            Entry::Dir(dir) => {
                let perms = &mut dir.write().perms;
                if !(credentials.user() == 0 || credentials.owns(perms.userinfo)) {
                    return Err(ChmodError::NotTheOwner);
                }
                perms.mode = mode;
                Ok(())
            }
            // Reached only via `AT_SYMLINK_NOFOLLOW` (a following caller resolves
            // the link first); a symlink's own mode is inert on Linux but the
            // ownership check still applies.
            Entry::SymLink(link) => {
                let perms = &mut link.write().perms;
                if !(credentials.user() == 0 || credentials.owns(perms.userinfo)) {
                    return Err(ChmodError::NotTheOwner);
                }
                perms.mode = mode;
                Ok(())
            }
        }
    }

    fn fd_chmod(&self, fd: &FileFd<Platform>, mode: super::Mode) -> Result<(), ChmodError> {
        self.fd_chmod_as(self.current_user.into(), fd, mode)
    }

    fn fd_chmod_as(
        &self,
        credentials: AccessCredentials<'_>,
        fd: &FileFd<Platform>,
        mode: super::Mode,
    ) -> Result<(), ChmodError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.get_entry(fd).ok_or(ChmodError::ClosedFd)?;
        match &entry.entry {
            Descriptor::File {
                path_only: true, ..
            }
            | Descriptor::Dir {
                path_only: true, ..
            }
            | Descriptor::SymLink { .. } => Err(ChmodError::PathOnlyFd),
            Descriptor::File { file, .. } => {
                let perms = &mut file.write().perms;
                if !(credentials.user() == 0 || credentials.owns(perms.userinfo)) {
                    return Err(ChmodError::NotTheOwner);
                }
                perms.mode = mode;
                Ok(())
            }
            Descriptor::Dir { dir, .. } => {
                let perms = &mut dir.write().perms;
                if !(credentials.user() == 0 || credentials.owns(perms.userinfo)) {
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
        let root = self.root.read();
        let (_, entry) = root.parent_and_entry_as(&path, credentials)?;
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        match entry {
            Entry::File(file) => {
                let perms = &mut file.write().perms;
                Self::update_owner(credentials, perms, user, group)
            }
            Entry::Dir(dir) => {
                let perms = &mut dir.write().perms;
                Self::update_owner(credentials, perms, user, group)
            }
            // `lchown` on the link itself (following callers resolve first).
            Entry::SymLink(link) => {
                let perms = &mut link.write().perms;
                Self::update_owner(credentials, perms, user, group)
            }
        }
    }

    fn fd_chown(
        &self,
        fd: &FileFd<Platform>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        self.fd_chown_as(self.current_user.into(), fd, user, group)
    }

    fn fd_chown_as(
        &self,
        credentials: AccessCredentials<'_>,
        fd: &FileFd<Platform>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.get_entry(fd).ok_or(ChownError::ClosedFd)?;
        match &entry.entry {
            Descriptor::File {
                path_only: true, ..
            }
            | Descriptor::Dir {
                path_only: true, ..
            }
            | Descriptor::SymLink { .. } => Err(ChownError::PathOnlyFd),
            Descriptor::File { file, .. } => {
                let perms = &mut file.write().perms;
                Self::update_owner(credentials, perms, user, group)
            }
            Descriptor::Dir { dir, .. } => {
                let perms = &mut dir.write().perms;
                Self::update_owner(credentials, perms, user, group)
            }
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
        let root = self.root.read();
        let (_, entry) = root.parent_and_entry_as(&path, credentials)?;
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        let permissions = entry.perms();
        if !(credentials.user() == 0 || credentials.owns(permissions.userinfo)) {
            return Err(UtimeError::NoWritePerms);
        }
        match entry {
            Entry::File(file) => {
                let mut file = file.write();
                if let Some(atime) = atime {
                    file.atime = atime;
                }
                if let Some(mtime) = mtime {
                    file.mtime = mtime;
                }
                if let Some(changed) = mtime.or(atime) {
                    file.ctime = changed;
                }
            }
            Entry::Dir(dir) => {
                let mut dir = dir.write();
                if let Some(atime) = atime {
                    dir.atime = atime;
                }
                if let Some(mtime) = mtime {
                    dir.mtime = mtime;
                }
                if let Some(changed) = mtime.or(atime) {
                    dir.ctime = changed;
                }
            }
            Entry::SymLink(link) => {
                let mut link = link.write();
                if let Some(atime) = atime {
                    link.atime = atime;
                }
                if let Some(mtime) = mtime {
                    link.mtime = mtime;
                }
                if let Some(changed) = mtime.or(atime) {
                    link.ctime = changed;
                }
            }
        }
        Ok(())
    }

    fn fd_utimensat(
        &self,
        fd: &FileFd<Platform>,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        self.fd_utimensat_as(self.current_user.into(), fd, atime, mtime)
    }

    fn fd_utimensat_as(
        &self,
        credentials: AccessCredentials<'_>,
        fd: &FileFd<Platform>,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.get_entry(fd).ok_or(UtimeError::ClosedFd)?;
        match &entry.entry {
            Descriptor::File {
                path_only: true, ..
            }
            | Descriptor::Dir {
                path_only: true, ..
            }
            | Descriptor::SymLink { .. } => return Err(UtimeError::PathOnlyFd),
            Descriptor::File { file, .. } => {
                let mut file = file.write();
                if !(credentials.user() == 0 || credentials.owns(file.perms.userinfo)) {
                    return Err(UtimeError::NoWritePerms);
                }
                if let Some(atime) = atime {
                    file.atime = atime;
                }
                if let Some(mtime) = mtime {
                    file.mtime = mtime;
                }
                if let Some(changed) = mtime.or(atime) {
                    file.ctime = changed;
                }
            }
            Descriptor::Dir { dir, .. } => {
                let mut dir = dir.write();
                if !(credentials.user() == 0 || credentials.owns(dir.perms.userinfo)) {
                    return Err(UtimeError::NoWritePerms);
                }
                if let Some(atime) = atime {
                    dir.atime = atime;
                }
                if let Some(mtime) = mtime {
                    dir.mtime = mtime;
                }
                if let Some(changed) = mtime.or(atime) {
                    dir.ctime = changed;
                }
            }
        }
        Ok(())
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
        let mut root = self.root.write();
        let (parent, entry) = root.parent_and_entry_as(&path, credentials)?;
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
        let victim_owner = entry.perms().userinfo;
        let mut parent = parent.write();
        if !super::dac_allows_as(
            credentials,
            parent.perms.userinfo,
            parent.perms.mode,
            DacAccessKind::Write,
        ) {
            return Err(UnlinkError::NoWritePerms);
        }
        if !super::sticky_directory_allows_removal(
            credentials,
            parent.perms.userinfo,
            parent.perms.mode,
            victim_owner,
        ) {
            return Err(UnlinkError::OperationNotPermitted);
        }
        let removed = parent
            .children
            .remove(path.components().unwrap().last().unwrap());
        // Just a sanity check. `unlink` removes a regular file or a symlink (the
        // link itself, never its target); directories were rejected above.
        assert!(matches!(
            removed,
            Some(FileType::RegularFile | FileType::SymLink)
        ));
        let removed = root.entries.remove(&path).unwrap();
        // Just a sanity check
        assert!(matches!(removed, Entry::File(_) | Entry::SymLink(_)));
        Ok(())
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

        // Renaming a path to itself is a no-op success, provided the path exists.
        if old == new {
            let root = self.root.read();
            let (_, entry) = root.parent_and_entry_as(&old, credentials)?;
            return if entry.is_some() {
                Ok(())
            } else {
                Err(PathError::NoSuchFileOrDirectory)?
            };
        }

        // A directory can never be moved inside its own subtree (`/a` -> `/a/b`).
        let mut old_prefix = old.clone();
        old_prefix.push('/');
        if new.starts_with(&old_prefix) {
            return Err(RenameError::InvalidArgument);
        }

        let mut root = self.root.write();

        // Resolve source and destination. `parent_and_entry` hands back the parent
        // path as a `&str` borrowed from `root`; project it away (keeping the parent
        // `Arc`) so the later `root.entries` mutation is permitted.
        let (old_parent, old_entry) = root.parent_and_entry_as(&old, credentials)?;
        let old_parent = old_parent.map(|(_, dir)| dir);
        let Some(old_val) = old_entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        let Some(old_parent) = old_parent else {
            // `old` is the root directory itself.
            return Err(RenameError::InvalidArgument);
        };

        let (new_parent, new_entry) = root.parent_and_entry_as(&new, credentials)?;
        let new_parent = new_parent.map(|(_, dir)| dir);
        let Some(new_parent) = new_parent else {
            // `new` is the root directory itself.
            return Err(RenameError::InvalidArgument);
        };

        // Write permission is required on both the source and destination directories.
        let old_parent_permissions = old_parent.read().perms.clone();
        if !super::dac_allows_as(
            credentials,
            old_parent_permissions.userinfo,
            old_parent_permissions.mode,
            DacAccessKind::Write,
        ) {
            return Err(RenameError::NoWritePerms);
        }
        let new_parent_permissions = new_parent.read().perms.clone();
        if !super::dac_allows_as(
            credentials,
            new_parent_permissions.userinfo,
            new_parent_permissions.mode,
            DacAccessKind::Write,
        ) {
            return Err(RenameError::NoWritePerms);
        }

        if !super::sticky_directory_allows_removal(
            credentials,
            old_parent_permissions.userinfo,
            old_parent_permissions.mode,
            old_val.perms().userinfo,
        ) {
            return Err(RenameError::OperationNotPermitted);
        }
        if let Some(new_entry) = &new_entry
            && !super::sticky_directory_allows_removal(
                credentials,
                new_parent_permissions.userinfo,
                new_parent_permissions.mode,
                new_entry.perms().userinfo,
            )
        {
            return Err(RenameError::OperationNotPermitted);
        }

        let old_is_dir = matches!(&old_val, Entry::Dir(_));

        // Validate an existing destination against `rename(2)`'s type/emptiness rules.
        if let Some(new_val) = &new_entry {
            if noreplace {
                return Err(RenameError::AlreadyExists);
            }
            match (old_is_dir, new_val) {
                (true, Entry::Dir(new_dir)) => {
                    if !new_dir.read().children.is_empty() {
                        return Err(RenameError::NotEmpty);
                    }
                }
                // A directory cannot replace an existing non-directory.
                (true, Entry::File(_) | Entry::SymLink(_)) => {
                    return Err(RenameError::NotADirectory);
                }
                // A non-directory cannot replace an existing directory.
                (false, Entry::Dir(_)) => {
                    return Err(RenameError::IsADirectory);
                }
                (false, Entry::File(_) | Entry::SymLink(_)) => {
                    // Non-directory replacing a non-directory: allowed.
                }
            }
        }

        let old_name: String = old.components().unwrap().last().unwrap().into();
        let new_name: String = new.components().unwrap().last().unwrap().into();
        let old_ft = match &old_val {
            Entry::File(_) => FileType::RegularFile,
            Entry::Dir(_) => FileType::Directory,
            Entry::SymLink(_) => FileType::SymLink,
        };

        // Detach the source name from its parent directory.
        old_parent.write().children.remove(&old_name);

        // Drop a validated existing destination (an in-place replace): unlink its
        // name from the destination directory and its node from `entries`. The
        // destination is a non-directory or an empty directory, so it owns no
        // descendant keys.
        if new_entry.is_some() {
            new_parent.write().children.remove(&new_name);
            root.entries.remove(&new);
        }

        // Attach the source name -- carrying the source's own type -- under the
        // destination directory.
        new_parent.write().children.insert(new_name, old_ft);

        // Re-key the moved node, and for a directory every descendant (whose
        // `entries` keys embed the old absolute path), from the `old` prefix to the
        // `new` prefix.
        let moved_keys: Vec<String> = root
            .entries
            .keys()
            .filter(|k| **k == old || k.starts_with(&old_prefix))
            .cloned()
            .collect();
        for k in moved_keys {
            let entry = root.entries.remove(&k).unwrap();
            let new_key = if k == old {
                new.clone()
            } else {
                let mut nk = new.clone();
                nk.push_str(&k[old.len()..]);
                nk
            };
            root.entries.insert(new_key, entry);
        }
        Ok(())
    }

    fn mkdir(&self, path: impl crate::path::Arg, mode: super::Mode) -> Result<(), MkdirError> {
        self.mkdir_as(self.current_user.into(), path, mode)
    }

    fn mkdir_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl crate::path::Arg,
        mode: super::Mode,
    ) -> Result<(), MkdirError> {
        let path = self.absolute_path(path)?;
        let owner = credentials.as_user_info().ok_or(MkdirError::NoWritePerms)?;
        self.mkdir_inner(path, mode, owner, true, credentials)
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
        let mut root = self.root.write();
        let (parent, entry) = root.parent_and_entry_as(&path, credentials)?;
        let Some((_parent_path, parent)) = parent else {
            // A link at `/` -- the root already exists.
            return Err(SymlinkError::AlreadyExists);
        };
        let None = entry else {
            return Err(SymlinkError::AlreadyExists);
        };
        let mut parent = parent.write();
        if !super::dac_allows_as(
            credentials,
            parent.perms.userinfo,
            parent.perms.mode,
            DacAccessKind::Write,
        ) {
            return Err(SymlinkError::NoWritePerms);
        }
        let owner = credentials
            .as_user_info()
            .ok_or(SymlinkError::NoWritePerms)?;
        let old = parent.children.insert(
            path.components().unwrap().last().unwrap().into(),
            FileType::SymLink,
        );
        assert!(old.is_none());
        let old = root.entries.insert(
            path,
            Entry::SymLink(Arc::new(sync::RwLock::new(SymLinkX {
                target: target.into(),
                // A symlink's own mode is a fixed `lrwxrwxrwx` on Linux; access
                // checks apply to the resolved target, never to the link node.
                perms: Permissions {
                    mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                    userinfo: owner,
                },
                unique_id: self.fresh_id(),
                atime: Timestamp::default(),
                mtime: Timestamp::default(),
                ctime: Timestamp::default(),
            }))),
        );
        assert!(old.is_none());
        Ok(())
    }

    fn readlink(&self, path: impl crate::path::Arg) -> Result<String, ReadlinkError> {
        self.readlink_as(self.current_user.into(), path)
    }

    fn readlink_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl crate::path::Arg,
    ) -> Result<String, ReadlinkError> {
        let path = self.absolute_path(path)?;
        let root = self.root.read();
        let (_, entry) = root.parent_and_entry_as(&path, credentials)?;
        match entry {
            Some(Entry::SymLink(link)) => Ok(link.read().target.clone()),
            Some(_) => Err(ReadlinkError::NotASymlink),
            None => Err(PathError::NoSuchFileOrDirectory)?,
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
        let mut root = self.root.write();
        let (parent, entry) = root.parent_and_entry_as(&path, credentials)?;
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
        let victim_owner = dir.read().perms.userinfo;
        let mut parent = parent.write();
        if !super::dac_allows_as(
            credentials,
            parent.perms.userinfo,
            parent.perms.mode,
            DacAccessKind::Write,
        ) {
            return Err(RmdirError::NoWritePerms);
        }
        if !super::sticky_directory_allows_removal(
            credentials,
            parent.perms.userinfo,
            parent.perms.mode,
            victim_owner,
        ) {
            return Err(RmdirError::OperationNotPermitted);
        }
        if !dir.read().children.is_empty() {
            return Err(RmdirError::NotEmpty);
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
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(ReadDirError::ClosedFd)?;
        if match &entry.entry {
            Descriptor::File { path_only, .. } | Descriptor::Dir { path_only, .. } => *path_only,
            Descriptor::SymLink { .. } => true,
        } {
            return Err(ReadDirError::PathOnlyFd);
        }
        let Descriptor::Dir { dir, .. } = &entry.entry else {
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
                    Entry::SymLink(link) => link.read().unique_id,
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

    fn with_dir_position<T>(
        &self,
        fd: &FileFd<Platform>,
        f: impl FnOnce(&mut usize) -> T,
    ) -> Result<T, ReadDirError> {
        let position = {
            let descriptor_table = self.litebox.descriptor_table();
            let entry = descriptor_table
                .get_entry(fd)
                .ok_or(ReadDirError::ClosedFd)?;
            if match &entry.entry {
                Descriptor::File { path_only, .. } | Descriptor::Dir { path_only, .. } => {
                    *path_only
                }
                Descriptor::SymLink { .. } => true,
            } {
                return Err(ReadDirError::PathOnlyFd);
            }
            let Descriptor::Dir { position, .. } = &entry.entry else {
                return Err(ReadDirError::NotADirectory);
            };
            Arc::clone(position)
        };
        let mut position = position.lock();
        Ok(f(&mut position))
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
        let root = self.root.read();
        let (_, entry) = root.parent_and_entry_as(&path, credentials)?;
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        let (file_type, perms, size, unique_id, atime, mtime, ctime) = match entry {
            Entry::File(file) => {
                let file = file.read();
                (
                    super::FileType::RegularFile,
                    file.perms.clone(),
                    file.data.len(),
                    file.unique_id,
                    file.atime,
                    file.mtime,
                    file.ctime,
                )
            }
            Entry::Dir(dir) => {
                let dir = dir.read();
                (
                    super::FileType::Directory,
                    dir.perms.clone(),
                    super::DEFAULT_DIRECTORY_SIZE,
                    dir.unique_id,
                    dir.atime,
                    dir.mtime,
                    dir.ctime,
                )
            }
            Entry::SymLink(link) => {
                let link = link.read();
                (
                    // `file_status` is `lstat` semantics: report the link itself.
                    // Its size is the byte length of the target string.
                    super::FileType::SymLink,
                    link.perms.clone(),
                    link.target.len(),
                    link.unique_id,
                    link.atime,
                    link.mtime,
                    link.ctime,
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
            atime,
            mtime,
            ctime,
        })
    }

    fn fd_file_status(&self, fd: &FileFd<Platform>) -> Result<FileStatus, FileStatusError> {
        let (file_type, perms, size, unique_id, atime, mtime, ctime) = match &self
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
                    file.atime,
                    file.mtime,
                    file.ctime,
                )
            }
            Descriptor::SymLink { link } => {
                let link = link.read();
                (
                    super::FileType::SymLink,
                    link.perms.clone(),
                    link.target.len(),
                    link.unique_id,
                    link.atime,
                    link.mtime,
                    link.ctime,
                )
            }
            Descriptor::Dir { dir, .. } => {
                let dir = dir.read();
                (
                    super::FileType::Directory,
                    dir.perms.clone(),
                    super::DEFAULT_DIRECTORY_SIZE,
                    dir.unique_id,
                    dir.atime,
                    dir.mtime,
                    dir.ctime,
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
            atime,
            mtime,
            ctime,
        })
    }

    fn get_static_backing_data(&self, fd: &FileFd<Platform>) -> Option<&'static [u8]> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.get_entry(fd)?;
        match &entry.entry {
            Descriptor::File {
                file,
                read_allowed: true,
                path_only: false,
                ..
            } => {
                let file = file.read();
                match &file.data {
                    alloc::borrow::Cow::Borrowed(slice) => Some(*slice),
                    alloc::borrow::Cow::Owned(_) => None,
                }
            }
            Descriptor::File { .. } | Descriptor::Dir { .. } | Descriptor::SymLink { .. } => None,
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
    fn new() -> Self {
        Self {
            entries: [(
                String::new(),
                Entry::Dir(Arc::new(sync::RwLock::new(DirX {
                    perms: Permissions {
                        mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                        userinfo: UserInfo { user: 0, group: 0 },
                    },
                    children: HashMap::default(),
                    unique_id: 0,
                    atime: Timestamp::default(),
                    mtime: Timestamp::default(),
                    ctime: Timestamp::default(),
                }))),
            )]
            .into_iter()
            .collect(),
        }
    }

    fn parent_and_entry_as(
        &self,
        path: &str,
        credentials: AccessCredentials<'_>,
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
                // A regular file or a symlink used as an intermediate directory
                // component is not traversable. Following an intermediate symlink
                // is deferred (a leaf symlink is followed above this layer, in the
                // shim); a non-final symlink surfaces as ENOTDIR, matching how a
                // regular file in that position does.
                (_, Entry::File(_) | Entry::SymLink(_)) => {
                    return Err(PathError::ComponentNotADirectory);
                }
                (parent_path, Entry::Dir(dir)) => {
                    let permissions = dir.read().perms.clone();
                    if !super::dac_allows_as(
                        credentials,
                        permissions.userinfo,
                        permissions.mode,
                        DacAccessKind::DirectorySearch,
                    ) {
                        return Err(PathError::NoSearchPerms {
                            #[cfg(debug_assertions)]
                            dir: parent_path.clone(),
                            #[cfg(debug_assertions)]
                            perms: permissions.mode,
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
    SymLink(SymLink<Platform>),
}

impl<Platform: sync::RawSyncPrimitivesProvider> Entry<Platform> {
    fn perms(&self) -> Permissions {
        match self {
            Self::File(file) => file.read().perms.clone(),
            Self::Dir(dir) => dir.read().perms.clone(),
            Self::SymLink(link) => link.read().perms.clone(),
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> Clone for Entry<Platform> {
    fn clone(&self) -> Self {
        match self {
            Self::File(file) => Self::File(file.clone()),
            Self::Dir(dir) => Self::Dir(dir.clone()),
            Self::SymLink(link) => Self::SymLink(link.clone()),
        }
    }
}

type Dir<Platform> = Arc<sync::RwLock<Platform, DirX>>;

type SymLink<Platform> = Arc<sync::RwLock<Platform, SymLinkX>>;

/// A symbolic link node. `target` is the uninterpreted link contents; resolution
/// happens above this layer (see the shim's path-following).
pub(crate) struct SymLinkX {
    target: String,
    perms: Permissions,
    unique_id: usize,
    atime: Timestamp,
    mtime: Timestamp,
    ctime: Timestamp,
}

pub(crate) struct DirX {
    perms: Permissions,
    children: HashMap<String, FileType>,
    unique_id: usize,
    atime: Timestamp,
    mtime: Timestamp,
    ctime: Timestamp,
}

type File<Platform> = Arc<sync::RwLock<Platform, FileX>>;

pub(crate) struct FileX {
    perms: Permissions,
    data: alloc::borrow::Cow<'static, [u8]>,
    unique_id: usize,
    atime: Timestamp,
    mtime: Timestamp,
    ctime: Timestamp,
}

#[derive(Clone, Debug)]
struct Permissions {
    mode: Mode,
    userinfo: UserInfo,
}

pub(crate) enum Descriptor<Platform: sync::RawSyncPrimitivesProvider> {
    File {
        file: File<Platform>,
        read_allowed: bool,
        write_allowed: bool,
        position: usize,
        append_mode: bool,
        path_only: bool,
    },
    Dir {
        dir: Dir<Platform>,
        position: Arc<sync::Mutex<Platform, usize>>,
        path_only: bool,
    },
    SymLink {
        link: SymLink<Platform>,
    },
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider };
    FileSystem<Platform>;
    @ Platform: { sync::RawSyncPrimitivesProvider };
    Descriptor<Platform>;
    -> FileFd<Platform>;
}
