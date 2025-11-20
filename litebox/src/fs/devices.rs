//! Device provider for LiteBox including:
//! 1. Standard input/output devices.
//! 2. /dev/null device.

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
    platform::{StdioOutStream, StdioReadError, StdioWriteError},
};

/// Block size for stdio devices
const STDIO_BLOCK_SIZE: usize = 1024;
/// Block size for null device
const NULL_BLOCK_SIZE: usize = 0x1000;
/// Block size for /dev/urandom
const URANDOM_BLOCK_SIZE: usize = 0x1000;

/// Constant node information for all 3 stdio devices:
/// ```console
/// $ stat -L --format 'name=%-11n dev=%d ino=%i rdev=%r' /dev/stdin /dev/stdout /dev/stderr
/// name=/dev/stdin  dev=64 ino=9 rdev=34822
/// name=/dev/stdout dev=64 ino=9 rdev=34822
/// name=/dev/stderr dev=64 ino=9 rdev=34822
/// ```
const STDIO_NODE_INFO: NodeInfo = NodeInfo {
    dev: 64,
    ino: 9,
    rdev: core::num::NonZeroUsize::new(34822),
};
/// Node info for /dev/null
const NULL_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 4,
    // major=1, minor=3
    rdev: core::num::NonZeroUsize::new(0x103),
};
/// Node info for /dev/urandom
const URANDOM_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 8,
    // major=1, minor=9
    rdev: core::num::NonZeroUsize::new(0x109),
};
#[derive(Debug, Clone, Copy)]
enum Device {
    Stdin,
    Stdout,
    Stderr,
    Null,
    URandom,
}

/// A backing implementation for [`FileSystem`](super::FileSystem).
///
/// This provider provides only `/dev/stdin`, `/dev/stdout`, and `/dev/stderr`.
pub struct FileSystem<
    Platform: crate::sync::RawSyncPrimitivesProvider + crate::platform::StdioProvider + 'static,
> {
    litebox: LiteBox<Platform>,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
}

impl<Platform: crate::platform::StdioProvider + crate::sync::RawSyncPrimitivesProvider>
    FileSystem<Platform>
{
    /// Construct a new `FileSystem` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialiation step,
    /// and the created `FileSystem` handle is expected to be shared across all usage over the
    /// system.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            litebox: litebox.clone(),
            current_working_dir: "/".into(),
        }
    }
}

impl<Platform: crate::sync::RawSyncPrimitivesProvider + crate::platform::StdioProvider>
    super::private::Sealed for FileSystem<Platform>
{
}

impl<Platform: crate::sync::RawSyncPrimitivesProvider + crate::platform::StdioProvider>
    FileSystem<Platform>
{
    // Gives the absolute path for `path`, resolving any `.` or `..`s, and making sure to account
    // for any relative paths from current working directory.
    //
    // Note: does NOT account for symlinks.
    fn absolute_path(&self, path: impl Arg) -> Result<String, PathError> {
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

    fn device_file_status(device: Device) -> FileStatus {
        match device {
            Device::Stdin | Device::Stdout | Device::Stderr => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: STDIO_NODE_INFO,
                blksize: STDIO_BLOCK_SIZE,
            },
            Device::Null => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: NULL_NODE_INFO,
                blksize: NULL_BLOCK_SIZE,
            },
            Device::URandom => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: URANDOM_NODE_INFO,
                blksize: URANDOM_BLOCK_SIZE,
            },
        }
    }
}

impl<
    Platform: crate::sync::RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + crate::platform::CrngProvider,
> super::FileSystem for FileSystem<Platform>
{
    fn open(
        &self,
        path: impl Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        let open_directory = flags.contains(OFlags::DIRECTORY);
        let flags = flags - OFlags::DIRECTORY;
        let nonblocking = flags.contains(OFlags::NONBLOCK);
        let flags = flags - OFlags::NONBLOCK;
        // ignore NOCTTY and NOFOLLOW
        let flags = flags - OFlags::NOCTTY - OFlags::NOFOLLOW;
        let truncate = flags.contains(OFlags::TRUNC);
        let flags = flags - OFlags::TRUNC;
        let path = self.absolute_path(path)?;
        let device = match path.as_str() {
            "/dev/stdin" => {
                if flags == OFlags::RDONLY && mode.is_empty() {
                    Device::Stdin
                } else {
                    unimplemented!()
                }
            }
            "/dev/stdout" => {
                if flags == OFlags::WRONLY && mode.is_empty() {
                    Device::Stdout
                } else {
                    unimplemented!()
                }
            }
            "/dev/stderr" => {
                if flags == OFlags::WRONLY && mode.is_empty() {
                    Device::Stderr
                } else {
                    unimplemented!()
                }
            }
            "/dev/null" => Device::Null,
            "/dev/urandom" => Device::URandom,
            _ => return Err(OpenError::PathError(PathError::NoSuchFileOrDirectory)),
        };
        if open_directory {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }
        if nonblocking
            && matches!(
                device,
                Device::Stdin | Device::Stderr | Device::Stdout | Device::URandom
            )
        {
            unimplemented!("Non-blocking I/O is not supported for {:?}", device);
        }
        let fd = self.litebox.descriptor_table_mut().insert(device);
        if truncate {
            // Note: matching Linux behavior, this does not actually perform any truncation, and
            // instead, it is silently ignored if you attempt to truncate upon opening stdio.
            assert!(matches!(
                self.truncate(&fd, 0, true),
                Err(TruncateError::IsTerminalDevice)
            ));
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
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        match &self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(ReadError::ClosedFd)?
            .entry
        {
            Device::Stdin => {}
            Device::Stdout | Device::Stderr => {
                return Err(ReadError::NotForReading);
            }
            Device::Null => {
                // /dev/null read returns EOF
                return Ok(0);
            }
            Device::URandom => {
                self.litebox.x.platform.fill_bytes_crng(buf);
                return Ok(buf.len());
            }
        }
        if offset.is_some() {
            unimplemented!()
        }
        self.litebox
            .x
            .platform
            .read_from_stdin(buf)
            .map_err(|e| match e {
                StdioReadError::Closed => unimplemented!(),
            })
    }

    fn write(
        &self,
        fd: &FileFd<Platform>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let stream = match &self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(WriteError::ClosedFd)?
            .entry
        {
            Device::Stdin => return Err(WriteError::NotForWriting),
            Device::Stdout => StdioOutStream::Stdout,
            Device::Stderr => StdioOutStream::Stderr,
            Device::Null | Device::URandom => {
                // /dev/null discards data: report as if written fully
                //
                // Writing to /dev/random or /dev/urandom will update the entropy
                // pool with the data written, but this will not result in a higher
                // entropy count. This means that it will impact the contents read
                // from both files, but it will not make reads from /dev/random
                // faster. For simplicity, we just discard the data written to
                // /dev/urandom here.
                return Ok(buf.len());
            }
        };
        if offset.is_some() {
            unimplemented!()
        }
        self.litebox
            .x
            .platform
            .write_to(stream, buf)
            .map_err(|e| match e {
                StdioWriteError::Closed => unimplemented!(),
            })
    }

    fn seek(
        &self,
        fd: &FileFd<Platform>,
        _offset: isize,
        _whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        match &self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(SeekError::ClosedFd)?
            .entry
        {
            Device::Stdin | Device::Stdout | Device::Stderr => Err(SeekError::NonSeekable),
            Device::Null | Device::URandom => {
                // Linux allows lseek on /dev/null and returns position 0 (or sets to length 0).
                Ok(0)
            }
        }
    }

    fn truncate(
        &self,
        _fd: &FileFd<Platform>,
        _length: usize,
        _reset_offset: bool,
    ) -> Result<(), TruncateError> {
        Err(TruncateError::IsTerminalDevice)
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn chmod(&self, path: impl Arg, mode: Mode) -> Result<(), ChmodError> {
        unimplemented!()
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn chown(
        &self,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        unimplemented!()
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn unlink(&self, path: impl Arg) -> Result<(), UnlinkError> {
        unimplemented!()
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn mkdir(&self, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
        unimplemented!()
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn rmdir(&self, path: impl Arg) -> Result<(), RmdirError> {
        unimplemented!()
    }

    fn read_dir(
        &self,
        _fd: &FileFd<Platform>,
    ) -> Result<alloc::vec::Vec<crate::fs::DirEntry>, ReadDirError> {
        Err(ReadDirError::NotADirectory)
    }

    fn file_status(&self, path: impl Arg) -> Result<FileStatus, FileStatusError> {
        let path = self.absolute_path(path)?;
        let device = match path.as_str() {
            "/dev/stdin" => Device::Stdin,
            "/dev/stdout" => Device::Stdout,
            "/dev/stderr" => Device::Stderr,
            "/dev/null" => Device::Null,
            "/dev/urandom" => Device::URandom,
            _ => return Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory)),
        };
        Ok(Self::device_file_status(device))
    }

    fn fd_file_status(&self, fd: &FileFd<Platform>) -> Result<FileStatus, FileStatusError> {
        let device = self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(FileStatusError::ClosedFd)?
            .entry;
        Ok(Self::device_file_status(device))
    }
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { crate::sync::RawSyncPrimitivesProvider + crate::platform::StdioProvider };
    FileSystem<Platform>;
    Device;
    -> FileFd<Platform>;
}
