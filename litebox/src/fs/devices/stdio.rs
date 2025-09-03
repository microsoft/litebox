//! Standard input/output devices.

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
    platform::{StdioOutStream, StdioReadError, StdioStream, StdioWriteError},
};

/// Block size for stdio devices
const STDIO_BLOCK_SIZE: usize = 1024;

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

/// A backing implementation for [`FileSystem`](super::super::FileSystem).
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
    super::super::private::Sealed for FileSystem<Platform>
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
}

impl<Platform: crate::sync::RawSyncPrimitivesProvider + crate::platform::StdioProvider>
    super::super::FileSystem for FileSystem<Platform>
{
    fn open(
        &self,
        path: impl Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        let open_directory = flags.contains(OFlags::DIRECTORY);
        let nonblocking = flags.contains(OFlags::NONBLOCK);
        let flags = flags - OFlags::DIRECTORY - OFlags::NONBLOCK - OFlags::NOCTTY; // ignore NOCTTY
        let path = self.absolute_path(path)?;
        let stream = match path.as_str() {
            "/dev/stdin" => {
                if flags == OFlags::RDONLY && mode.is_empty() {
                    StdioStream::Stdin
                } else {
                    unimplemented!()
                }
            }
            "/dev/stdout" => {
                if flags == OFlags::WRONLY && mode.is_empty() {
                    StdioStream::Stdout
                } else {
                    unimplemented!()
                }
            }
            "/dev/stderr" => {
                if flags == OFlags::WRONLY && mode.is_empty() {
                    StdioStream::Stderr
                } else {
                    unimplemented!()
                }
            }
            _ => return Err(OpenError::PathError(PathError::NoSuchFileOrDirectory)),
        };
        if open_directory {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }
        if nonblocking {
            unimplemented!("Non-blocking I/O is not supported for stdio streams");
        }
        Ok(self.litebox.descriptor_table_mut().insert(stream))
    }

    fn close(&self, fd: FileFd<Platform>) -> Result<(), CloseError> {
        self.litebox.descriptor_table_mut().remove(fd);
        Ok(())
    }

    fn read(
        &self,
        fd: &FileFd<Platform>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        if self.litebox.descriptor_table().get_entry(fd).entry != StdioStream::Stdin {
            return Err(ReadError::NotForReading);
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
        let stream = match &self.litebox.descriptor_table().get_entry(fd).entry {
            StdioStream::Stdin => return Err(WriteError::NotForWriting),
            StdioStream::Stdout => StdioOutStream::Stdout,
            StdioStream::Stderr => StdioOutStream::Stderr,
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

    #[expect(unused_variables, reason = "unimplemented")]
    fn seek(
        &self,
        fd: &FileFd<Platform>,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        unimplemented!()
    }

    fn truncate(&self, fd: &FileFd<Platform>) -> Result<(), TruncateError> {
        match self.litebox.descriptor_table().get_entry(fd).entry {
            StdioStream::Stdin => Err(TruncateError::NotForWriting),
            StdioStream::Stdout | StdioStream::Stderr => Ok(()),
        }
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
        if matches!(path.as_str(), "/dev/stdin" | "/dev/stdout" | "/dev/stderr") {
            Ok(FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: STDIO_NODE_INFO,
                blksize: STDIO_BLOCK_SIZE,
            })
        } else {
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory))
        }
    }

    fn fd_file_status(&self, _fd: &FileFd<Platform>) -> Result<FileStatus, FileStatusError> {
        Ok(FileStatus {
            file_type: FileType::CharacterDevice,
            mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
            size: 0,
            owner: UserInfo::ROOT,
            node_info: STDIO_NODE_INFO,
            blksize: STDIO_BLOCK_SIZE,
        })
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn with_metadata<T: core::any::Any, R>(
        &self,
        fd: &FileFd<Platform>,
        f: impl FnOnce(&T) -> R,
    ) -> Result<R, crate::fs::errors::MetadataError> {
        unimplemented!()
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn with_metadata_mut<T: core::any::Any, R>(
        &self,
        fd: &FileFd<Platform>,
        f: impl FnOnce(&mut T) -> R,
    ) -> Result<R, crate::fs::errors::MetadataError> {
        unimplemented!()
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn set_file_metadata<T: core::any::Any>(
        &self,
        fd: &FileFd<Platform>,
        metadata: T,
    ) -> Result<Option<T>, crate::fs::errors::SetMetadataError<T>> {
        unimplemented!()
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn set_fd_metadata<T: core::any::Any>(
        &self,
        fd: &FileFd<Platform>,
        metadata: T,
    ) -> Result<Option<T>, crate::fs::errors::SetMetadataError<T>> {
        unimplemented!()
    }
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { crate::sync::RawSyncPrimitivesProvider + crate::platform::StdioProvider };
    FileSystem<Platform>;
    StdioStream;
    -> FileFd<Platform>;
}
