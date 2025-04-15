//! Standard input/output devices.

use alloc::string::String;

use crate::{
    fd::{FileFd, OwnedFd},
    fs::{
        FileStatus, FileType, Mode, OFlags, SeekWhence,
        errors::{
            ChmodError, CloseError, FileStatusError, MkdirError, OpenError, PathError, ReadError,
            RmdirError, SeekError, UnlinkError, WriteError,
        },
    },
    path::Arg,
    platform::{StdioOutStream, StdioReadError, StdioWriteError},
};

/// A backing implementation for [`FileSystem`](super::super::FileSystem).
///
/// This provider provides only `/dev/stdin`, `/dev/stdout`, and `/dev/stderr`.
pub struct FileSystem<'platform, Platform: crate::platform::StdioProvider> {
    platform: &'platform Platform,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
}

impl<'platform, Platform: crate::platform::StdioProvider> FileSystem<'platform, Platform> {
    /// Construct a new `FileSystem` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialiation step,
    /// and the created `FileSystem` handle is expected to be shared across all usage over the
    /// system.
    #[must_use]
    pub fn new(platform: &'platform Platform) -> Self {
        Self {
            platform,
            current_working_dir: "/".into(),
        }
    }
}

impl<Platform: crate::platform::StdioProvider> super::super::private::Sealed
    for FileSystem<'_, Platform>
{
}

impl<Platform: crate::platform::StdioProvider> FileSystem<'_, Platform> {
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

impl<Platform: crate::platform::StdioProvider> super::super::FileSystem
    for FileSystem<'_, Platform>
{
    // NOTE: The counters inside this are purely internal to this module, so we are just using the
    // regular convention of 0,1,2 for stdin,stdout,stderr. This does NOT need to account for
    // anything externally, so as long as we are internally consistent, we are good.
    fn open(&self, path: impl Arg, flags: OFlags, mode: Mode) -> Result<FileFd, OpenError> {
        let path = self.absolute_path(path)?;
        match path.as_str() {
            "/dev/stdin" => {
                if flags == OFlags::RDONLY && mode.is_empty() {
                    Ok(FileFd { x: OwnedFd::new(0) })
                } else {
                    unimplemented!()
                }
            }
            "/dev/stdout" => {
                if flags == OFlags::WRONLY && mode.is_empty() {
                    Ok(FileFd { x: OwnedFd::new(1) })
                } else {
                    unimplemented!()
                }
            }
            "/dev/stderr" => {
                if flags == OFlags::WRONLY && mode.is_empty() {
                    Ok(FileFd { x: OwnedFd::new(2) })
                } else {
                    unimplemented!()
                }
            }
            _ => Err(OpenError::PathError(PathError::NoSuchFileOrDirectory)),
        }
    }

    fn close(&self, mut fd: FileFd) -> Result<(), CloseError> {
        fd.x.mark_as_closed();
        Ok(())
    }

    fn read(&self, fd: &FileFd, buf: &mut [u8], offset: Option<usize>) -> Result<usize, ReadError> {
        if fd.x.as_usize() != 0 {
            return Err(ReadError::NotForReading);
        }
        if offset.is_some() {
            unimplemented!()
        }
        self.platform.read_from_stdin(buf).map_err(|e| match e {
            StdioReadError::Closed => unimplemented!(),
        })
    }

    fn write(&self, fd: &FileFd, buf: &[u8], offset: Option<usize>) -> Result<usize, WriteError> {
        let stream = match fd.x.as_usize() {
            1 => StdioOutStream::Stdout,
            2 => StdioOutStream::Stderr,
            _ => return Err(WriteError::NotForWriting),
        };
        if offset.is_some() {
            unimplemented!()
        }
        self.platform.write_to(stream, buf).map_err(|e| match e {
            StdioWriteError::Closed => unimplemented!(),
        })
    }

    fn seek(&self, fd: &FileFd, offset: isize, whence: SeekWhence) -> Result<usize, SeekError> {
        unimplemented!()
    }

    fn chmod(&self, path: impl Arg, mode: Mode) -> Result<(), ChmodError> {
        unimplemented!()
    }

    fn unlink(&self, path: impl Arg) -> Result<(), UnlinkError> {
        unimplemented!()
    }

    fn mkdir(&self, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
        unimplemented!()
    }

    fn rmdir(&self, path: impl Arg) -> Result<(), RmdirError> {
        unimplemented!()
    }

    fn file_status(&self, path: impl Arg) -> Result<FileStatus, FileStatusError> {
        let path = self.absolute_path(path)?;
        if matches!(path.as_str(), "/dev/stdin" | "/dev/stdout" | "/dev/stderr") {
            Ok(FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
                size: 0,
            })
        } else {
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory))
        }
    }

    fn fd_file_status(&self, fd: &FileFd) -> Result<FileStatus, FileStatusError> {
        unimplemented!()
    }

    fn with_metadata<T: core::any::Any, R>(
        &self,
        fd: &FileFd,
        f: impl FnOnce(&T) -> R,
    ) -> Result<R, crate::fs::errors::MetadataError> {
        unimplemented!()
    }

    fn with_metadata_mut<T: core::any::Any, R>(
        &self,
        fd: &FileFd,
        f: impl FnOnce(&mut T) -> R,
    ) -> Result<R, crate::fs::errors::MetadataError> {
        unimplemented!()
    }

    fn set_file_metadata<T: core::any::Any>(
        &self,
        fd: &FileFd,
        metadata: T,
    ) -> Result<Option<T>, crate::fs::errors::SetMetadataError<T>> {
        unimplemented!()
    }

    fn set_fd_metadata<T: core::any::Any>(
        &self,
        fd: &FileFd,
        metadata: T,
    ) -> Result<Option<T>, crate::fs::errors::SetMetadataError<T>> {
        unimplemented!()
    }
}
