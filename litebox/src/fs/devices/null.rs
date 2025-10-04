//! /dev/null device provider

use alloc::string::String;

use crate::{
    LiteBox,
    fs::{
        FileStatus, FileType, Mode, NodeInfo, OFlags, SeekWhence, UserInfo,
        errors::{
            ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
            ReadDirError, ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
        },
    },
    path::Arg,
};

/// Block size for null device
const NULL_BLKSIZE: usize = 0x1000;

/// Node info for /dev/null (Gotten from a Linux system via `stat /dev/null`)
const NULL_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 4,
    // major=1, minor=3
    rdev: core::num::NonZeroUsize::new(0x103),
};

/// Entry type for dev/null descriptors: zero-sized marker
pub struct NullDevice;

/// A tiny file system that only provides `/dev/null`.
pub struct FileSystem<Platform: crate::sync::RawSyncPrimitivesProvider + 'static> {
    litebox: LiteBox<Platform>,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
}

impl<Platform: crate::sync::RawSyncPrimitivesProvider> FileSystem<Platform> {
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            litebox: litebox.clone(),
            current_working_dir: "/".into(),
        }
    }

    fn absolute_path(&self, path: impl Arg) -> Result<String, PathError> {
        assert!(self.current_working_dir.ends_with('/'));
        let path = path.as_rust_str()?;
        if path.starts_with('/') {
            Ok(path.normalized()?)
        } else {
            Ok((self.current_working_dir.clone() + path.as_rust_str()?).normalized()?)
        }
    }
}

impl<Platform: crate::sync::RawSyncPrimitivesProvider> super::super::private::Sealed
    for FileSystem<Platform>
{
}

impl<Platform: crate::sync::RawSyncPrimitivesProvider> super::super::FileSystem
    for FileSystem<Platform>
{
    fn open(
        &self,
        path: impl Arg,
        flags: OFlags,
        _mode: Mode,
    ) -> Result<crate::fd::TypedFd<Self>, OpenError> {
        let open_directory = flags.contains(OFlags::DIRECTORY);
        let path = self.absolute_path(path)?;
        if path != "/dev/null" {
            return Err(OpenError::PathError(PathError::NoSuchFileOrDirectory));
        }
        if open_directory {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }
        let fd = self.litebox.descriptor_table_mut().insert(NullDevice);
        Ok(fd)
    }

    fn close(&self, fd: crate::fd::TypedFd<Self>) -> Result<(), CloseError> {
        self.litebox.descriptor_table_mut().remove(fd);
        Ok(())
    }

    fn read(
        &self,
        _fd: &crate::fd::TypedFd<Self>,
        _buf: &mut [u8],
        _offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        // /dev/null read returns EOF
        Ok(0)
    }

    fn write(
        &self,
        _fd: &crate::fd::TypedFd<Self>,
        buf: &[u8],
        _offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        // /dev/null discards data: report as if written fully
        Ok(buf.len())
    }

    fn seek(
        &self,
        _fd: &crate::fd::TypedFd<Self>,
        _offset: isize,
        _whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        // Linux allows lseek on /dev/null and returns position 0 (or sets to length 0).
        Ok(0)
    }

    fn truncate(
        &self,
        _fd: &crate::fd::TypedFd<Self>,
        _length: usize,
        _reset_offset: bool,
    ) -> Result<(), TruncateError> {
        // /dev/null is not truncatable in any meaningful way; treat as terminal-like error.
        Err(TruncateError::IsTerminalDevice)
    }

    #[allow(unused_variables)]
    fn chmod(&self, path: impl Arg, mode: Mode) -> Result<(), ChmodError> {
        unimplemented!()
    }
    #[allow(unused_variables)]
    fn chown(
        &self,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        unimplemented!()
    }
    #[allow(unused_variables)]
    fn unlink(&self, path: impl Arg) -> Result<(), UnlinkError> {
        unimplemented!()
    }
    #[allow(unused_variables)]
    fn mkdir(&self, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
        unimplemented!()
    }
    #[allow(unused_variables)]
    fn rmdir(&self, path: impl Arg) -> Result<(), RmdirError> {
        unimplemented!()
    }

    fn read_dir(
        &self,
        _fd: &crate::fd::TypedFd<Self>,
    ) -> Result<alloc::vec::Vec<crate::fs::DirEntry>, ReadDirError> {
        Err(ReadDirError::NotADirectory)
    }

    fn file_status(&self, path: impl Arg) -> Result<FileStatus, FileStatusError> {
        let path = self.absolute_path(path)?;
        if path == "/dev/null" {
            Ok(FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: NULL_NODE_INFO,
                blksize: NULL_BLKSIZE,
            })
        } else {
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory))
        }
    }

    fn fd_file_status(
        &self,
        _fd: &crate::fd::TypedFd<Self>,
    ) -> Result<FileStatus, FileStatusError> {
        Ok(FileStatus {
            file_type: FileType::CharacterDevice,
            mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
            size: 0,
            owner: UserInfo::ROOT,
            node_info: NULL_NODE_INFO,
            blksize: NULL_BLKSIZE,
        })
    }
}

// Expose typed-fd support for this subsystem
crate::fd::enable_fds_for_subsystem! {
    @ Platform: { crate::sync::RawSyncPrimitivesProvider };
    FileSystem<Platform>;
    NullDevice;
    -> FileFd<Platform>;
}
