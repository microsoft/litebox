//! A read-only tar-backed file system.
//!
//! ```txt
//!                  __
//!                 / /
//!                / /
//!               / /
//!     ================
//!     |       / /    |
//!     |______/_/_____|
//!     \              /
//!      |            |
//!      |            |
//!      \            /
//!       |          |
//!       |  O  O  O |
//!        \O O O O /
//!        | O O O O|
//!        |________|
//!
//! Taro Milk Tea, Tapioca Bubbles, 50% Sugar, No Ice.
//! ```

use alloc::borrow::ToOwned as _;
use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::{
    LiteBox,
    fs::{DirEntry, FileType},
    path::Arg as _,
    sync,
};

use super::{
    Mode, NodeInfo, OFlags, SeekWhence, UserInfo,
    errors::{
        ChmodError, ChownError, CloseError, MkdirError, OpenError, PathError, ReadDirError,
        ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
    },
};

/// Just a random constant that is distinct from other file systems. In this case, it is
/// `b'Taro'.hex()`.
const DEVICE_ID: usize = 0x5461726f;

/// TODO(jayb): Replace this proper auto-incrementing inode number storage (although that will
/// require migrating to the hashmap based tar entry storage). This is ok for now, until something
/// is actually checking for real inode numbers.
const TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER: usize = 0xFACE;

/// Block size for file system I/O operations
// TODO(jayb): Determine appropriate block size
const BLOCK_SIZE: usize = 0;

enum TarData {
    Owned(tar_no_std::TarArchive),
    Borrowed(tar_no_std::TarArchiveRef<'static>),
}

impl TarData {
    fn entries(&self) -> tar_no_std::ArchiveEntryIterator<'_> {
        match self {
            TarData::Owned(ar) => ar.entries(),
            TarData::Borrowed(ar_ref) => ar_ref.entries(),
        }
    }
}

/// A backing implementation for [`FileSystem`](super::FileSystem), storing all files in-memory, via
/// a read-only `.tar` file.
pub struct FileSystem<Platform: sync::RawSyncPrimitivesProvider> {
    litebox: LiteBox<Platform>,
    tar_data: TarData,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
}

/// An empty tar file to support an empty file system.
pub const EMPTY_TAR_FILE: &[u8] = &[0u8; 10240];

impl<Platform: sync::RawSyncPrimitivesProvider> FileSystem<Platform> {
    /// Construct a new `FileSystem` instance from provided `tar_data`.
    ///
    /// Note: this function accepts `tar_data` as a `Cow<'static, [u8]>`. When a borrowed slice is
    /// provided the filesystem will use a `TarArchiveRef` without taking ownership; when an owned
    /// buffer is provided it will be consumed to construct a `TarArchive`. Using `Cow` avoids an
    /// unnecessary copy while allowing either borrowed or owned input.
    ///
    /// Use [`EMPTY_TAR_FILE`] if you need an empty file system.
    ///
    /// # Panics
    ///
    /// Panics if the provided `tar_data` is found to be an invalid `.tar` file.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>, tar_data: alloc::borrow::Cow<'static, [u8]>) -> Self {
        Self {
            litebox: litebox.clone(),
            tar_data: match tar_data {
                alloc::borrow::Cow::Borrowed(slice) => TarData::Borrowed(
                    tar_no_std::TarArchiveRef::new(slice).expect("invalid tar data"),
                ),
                alloc::borrow::Cow::Owned(vec) => TarData::Owned(
                    tar_no_std::TarArchive::new(vec.into_boxed_slice()).expect("invalid tar data"),
                ),
            },
            current_working_dir: "/".into(),
        }
    }

    /// Gives the absolute path for `path`, resolving any `.` or `..`s, and making sure to account
    /// for any relative paths from current working directory.
    ///
    /// Note: does NOT account for symlinks.
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

impl<Platform: sync::RawSyncPrimitivesProvider> super::private::Sealed for FileSystem<Platform> {}

fn contains_dir(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    assert!(!needle.ends_with('/'));
    haystack.starts_with(needle) && haystack.as_bytes().get(needle.len()) == Some(&b'/')
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::FileSystem for FileSystem<Platform> {
    fn open(
        &self,
        path: impl crate::path::Arg,
        flags: OFlags,
        _mode: Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        use super::OFlags;
        let currently_supported_oflags: OFlags = OFlags::RDONLY
            | OFlags::WRONLY
            | OFlags::RDWR
            | OFlags::CREAT
            | OFlags::EXCL
            | OFlags::TRUNC
            | OFlags::NOCTTY
            | OFlags::DIRECTORY
            | OFlags::NONBLOCK
            | OFlags::LARGEFILE
            | OFlags::NOFOLLOW;
        if flags.intersects(currently_supported_oflags.complement()) {
            unimplemented!("{flags:?}")
        }
        if flags.contains(OFlags::CREAT) {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        let path = self.absolute_path(path)?;
        if path.is_empty() {
            // We are at the root directory, we should just return early.
            return Ok(self
                .litebox
                .descriptor_table_mut()
                .insert(Descriptor::Dir { path: path.clone() }));
        }
        assert!(path.starts_with('/'));
        let path = &path[1..];
        let Some((idx, entry)) =
            // TODO: this might be slow for large tar files, due to a linear scan. If better perf is
            // needed, we can add a hashmap layer after doing one scan (in `new()`) that allows a
            // direct hashmap lookup of relevant information and data.
            self.tar_data.entries().enumerate().find(|(_, entry)| {
                match entry.filename().as_str() {
                    Ok(p) => p == path || contains_dir(p, path),
                    Err(_) => false,
                }
            })
        else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        if flags.contains(OFlags::RDWR) || flags.contains(OFlags::WRONLY) {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        assert!(flags.contains(OFlags::RDONLY));
        let fd = if entry.filename().as_str().unwrap() == path {
            // it is a file
            if flags.contains(OFlags::DIRECTORY) {
                return Err(OpenError::PathError(PathError::ComponentNotADirectory));
            }
            self.litebox
                .descriptor_table_mut()
                .insert(Descriptor::File { idx, position: 0 })
        } else {
            // it is a dir
            self.litebox.descriptor_table_mut().insert(Descriptor::Dir {
                path: path.to_owned(),
            })
        };
        if flags.contains(OFlags::TRUNC) {
            match self.truncate(&fd, 0, true) {
                Ok(()) => {}
                Err(e) => {
                    self.close(fd).unwrap();
                    return Err(e.into());
                }
            }
        }
        Ok(fd)
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
        let Descriptor::File { idx, position } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(ReadError::ClosedFd)?
            .entry
        else {
            return Err(ReadError::NotAFile);
        };
        let position = offset.as_mut().unwrap_or(position);
        let file = self.tar_data.entries().nth(*idx).unwrap().data();
        let start = (*position).min(file.len());
        let end = position.checked_add(buf.len()).unwrap().min(file.len());
        debug_assert!(start <= end);
        let retlen = end - start;
        buf[..retlen].copy_from_slice(&file[start..end]);
        *position = end;
        Ok(retlen)
    }

    fn write(
        &self,
        fd: &FileFd<Platform>,
        _buf: &[u8],
        _offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        match self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(WriteError::ClosedFd)?
            .entry
        {
            Descriptor::File { .. } => Err(WriteError::NotForWriting),
            Descriptor::Dir { .. } => Err(WriteError::NotAFile),
        }
    }

    fn seek(
        &self,
        fd: &FileFd<Platform>,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File { idx, position } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(SeekError::ClosedFd)?
            .entry
        else {
            return Err(SeekError::NotAFile);
        };
        let file_len = self.tar_data.entries().nth(*idx).unwrap().data().len();
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
        _length: usize,
        _reset_offset: bool,
    ) -> Result<(), TruncateError> {
        match self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(TruncateError::ClosedFd)?
            .entry
        {
            Descriptor::File { .. } => Err(TruncateError::NotForWriting),
            Descriptor::Dir { .. } => Err(TruncateError::IsDirectory),
        }
    }

    fn chmod(&self, path: impl crate::path::Arg, _mode: Mode) -> Result<(), ChmodError> {
        let path = self.absolute_path(path)?;
        assert!(path.starts_with('/'));
        let path = &path[1..];
        if self
            .tar_data
            .entries()
            .any(|entry| match entry.filename().as_str() {
                Ok(p) => p == path || contains_dir(p, path),
                Err(_) => false,
            })
        {
            Err(ChmodError::ReadOnlyFileSystem)
        } else {
            Err(PathError::NoSuchFileOrDirectory)?
        }
    }

    fn chown(
        &self,
        path: impl crate::path::Arg,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = self.absolute_path(path)?;
        assert!(path.starts_with('/'));
        let path = &path[1..];
        if self
            .tar_data
            .entries()
            .any(|entry| match entry.filename().as_str() {
                Ok(p) => p == path || contains_dir(p, path),
                Err(_) => false,
            })
        {
            Err(ChownError::ReadOnlyFileSystem)
        } else {
            Err(PathError::NoSuchFileOrDirectory)?
        }
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), UnlinkError> {
        let path = self.absolute_path(path)?;
        assert!(path.starts_with('/'));
        let path = &path[1..];
        let entry = self
            .tar_data
            .entries()
            .find(|entry| match entry.filename().as_str() {
                Ok(p) => p == path || contains_dir(p, path),
                Err(_) => false,
            });
        match entry {
            None => Err(PathError::NoSuchFileOrDirectory)?,
            Some(p) if p.filename().as_str().unwrap() != path => Err(UnlinkError::IsADirectory),
            Some(_) => Err(UnlinkError::ReadOnlyFileSystem),
        }
    }

    fn mkdir(&self, _path: impl crate::path::Arg, _mode: Mode) -> Result<(), MkdirError> {
        // TODO: Do we need to do the type of checks that are happening in the other functions, or
        // should the other functions be simplified to this?
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn rmdir(&self, _path: impl crate::path::Arg) -> Result<(), RmdirError> {
        // TODO: Do we need to do the type of checks that are happening in the other functions, or
        // should the other functions be simplified to this?
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn read_dir(&self, fd: &FileFd<Platform>) -> Result<Vec<DirEntry>, ReadDirError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::Dir { path } = &descriptor_table
            .get_entry(fd)
            .ok_or(ReadDirError::ClosedFd)?
            .entry
        else {
            return Err(ReadDirError::NotADirectory);
        };
        // Store into a hashmap to collapse together the entries we end up with for multiple files
        // within a sub-dir.
        let entries: HashMap<String, (FileType, usize)> = self
            .tar_data
            .entries()
            .enumerate()
            .map(|(idx, entry)| (idx, entry.filename()))
            .filter_map(|(idx, p)| {
                let p = p.as_str().ok()?;
                contains_dir(p, path).then(|| {
                    // Drop the directory path from `p`
                    let suffix = p.trim_start_matches(path).trim_start_matches('/');
                    // Then drop everything after the first `/`; if there is any then it was a dir,
                    // otherwise it was a file.
                    match suffix.split_once('/') {
                        Some((dir, _)) => (
                            String::from(dir),
                            (FileType::Directory, TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER),
                        ),
                        None => (String::from(suffix), (FileType::RegularFile, idx + 1)), // ino starts at 1 (zero represents deleted file)
                    }
                })
            })
            .collect();

        // Add "." and ".." entries first.
        // In this read-only tar FS we don't maintain distinct inode numbers per-dir,
        // so use the same directory inode constant for directories (including root).
        let mut out: Vec<DirEntry> = Vec::new();

        out.push(DirEntry {
            name: ".".into(),
            file_type: FileType::Directory,
            ino_info: Some(NodeInfo {
                dev: DEVICE_ID,
                ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                rdev: None,
            }),
        });

        out.push(DirEntry {
            name: "..".into(),
            file_type: FileType::Directory,
            ino_info: Some(NodeInfo {
                dev: DEVICE_ID,
                ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                rdev: None,
            }),
        });

        out.extend(
            entries
                .into_iter()
                .map(|(name, (file_type, ino))| DirEntry {
                    name,
                    file_type,
                    ino_info: Some(NodeInfo {
                        dev: DEVICE_ID,
                        ino,
                        rdev: None,
                    }),
                }),
        );
        Ok(out)
    }

    fn file_status(
        &self,
        path: impl crate::path::Arg,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        let path = self.absolute_path(path)?;
        let path = if path.is_empty() {
            ""
        } else {
            assert!(path.starts_with('/'));
            &path[1..]
        };
        let entry = self.tar_data.entries().enumerate().find(|(_, entry)| {
            match entry.filename().as_str() {
                Ok(p) => p == path || contains_dir(p, path),
                Err(_) => false,
            }
        });
        match entry {
            None => Err(PathError::NoSuchFileOrDirectory)?,
            Some((_, p)) if p.filename().as_str().unwrap() != path => Ok(super::FileStatus {
                file_type: super::FileType::Directory,
                mode: DEFAULT_DIR_MODE,
                size: super::DEFAULT_DIRECTORY_SIZE,
                owner: owner_from_posix_header(p.posix_header()),
                node_info: NodeInfo {
                    dev: DEVICE_ID,
                    ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                    rdev: None,
                },
                blksize: BLOCK_SIZE,
            }),
            Some((idx, p)) => Ok(super::FileStatus {
                file_type: super::FileType::RegularFile,
                mode: mode_of_modeflags(p.posix_header().mode.to_flags().unwrap()),
                size: p.size(),
                owner: owner_from_posix_header(p.posix_header()),
                node_info: NodeInfo {
                    dev: DEVICE_ID,
                    // ino starts at 1 (zero represents deleted file)
                    ino: idx + 1,
                    rdev: None,
                },
                blksize: BLOCK_SIZE,
            }),
        }
    }

    fn fd_file_status(
        &self,
        fd: &FileFd<Platform>,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        match &self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(super::errors::FileStatusError::ClosedFd)?
            .entry
        {
            Descriptor::File { idx, .. } => {
                let entry = self.tar_data.entries().nth(*idx).unwrap();
                Ok(super::FileStatus {
                    file_type: super::FileType::RegularFile,
                    mode: mode_of_modeflags(entry.posix_header().mode.to_flags().unwrap()),
                    size: entry.size(),
                    owner: owner_from_posix_header(entry.posix_header()),
                    node_info: NodeInfo {
                        dev: DEVICE_ID,
                        // ino starts at 1 (zero represents deleted file)
                        ino: *idx + 1,
                        rdev: None,
                    },
                    blksize: BLOCK_SIZE,
                })
            }
            Descriptor::Dir { .. } => Ok(super::FileStatus {
                file_type: super::FileType::Directory,
                mode: DEFAULT_DIR_MODE,
                size: super::DEFAULT_DIRECTORY_SIZE,
                owner: DEFAULT_DIRECTORY_OWNER,
                node_info: NodeInfo {
                    dev: DEVICE_ID,
                    ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                    rdev: None,
                },
                blksize: BLOCK_SIZE,
            }),
        }
    }
}

const DEFAULT_DIR_MODE: Mode =
    Mode::from_bits(Mode::RWXU.bits() | Mode::RWXG.bits() | Mode::RWXO.bits()).unwrap();

const DEFAULT_DIRECTORY_OWNER: UserInfo = UserInfo {
    user: 1000,
    group: 1000,
};

fn mode_of_modeflags(perms: tar_no_std::ModeFlags) -> Mode {
    use tar_no_std::ModeFlags;
    let mut mode = Mode::empty();
    mode.set(Mode::RUSR, perms.contains(ModeFlags::OwnerRead));
    mode.set(Mode::WUSR, perms.contains(ModeFlags::OwnerWrite));
    mode.set(Mode::XUSR, perms.contains(ModeFlags::OwnerExec));
    mode.set(Mode::RGRP, perms.contains(ModeFlags::GroupRead));
    mode.set(Mode::WGRP, perms.contains(ModeFlags::GroupWrite));
    mode.set(Mode::XGRP, perms.contains(ModeFlags::GroupExec));
    mode.set(Mode::ROTH, perms.contains(ModeFlags::OthersRead));
    mode.set(Mode::WOTH, perms.contains(ModeFlags::OthersWrite));
    mode.set(Mode::XOTH, perms.contains(ModeFlags::OthersExec));
    mode
}

fn owner_from_posix_header(posix_header: &tar_no_std::PosixHeader) -> UserInfo {
    UserInfo {
        user: posix_header.uid.as_number().unwrap(),
        group: posix_header.gid.as_number().unwrap(),
    }
}

enum Descriptor {
    File { idx: usize, position: usize },
    Dir { path: String },
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider };
    FileSystem<Platform>;
    Descriptor;
    -> FileFd<Platform>;
}
