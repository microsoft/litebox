//! A network file system, using the 9p protocol

use crate::platform;

/// A backing implementation for [`FileSystem`](super::FileSystem) using a 9p-based network file
/// system.
// TODO(jayb): Reduce the requirements necessary on `Platform` to the most precise one possible.
pub struct FileSystem<Platform: platform::Provider + 'static> {
    platform: &'static Platform,
}

impl<Platform: platform::Provider + 'static> FileSystem<Platform> {
    /// Construct a new `FileSystem` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialiation step,
    /// and the created `FileSystem` handle is expected to be shared across all usage over the
    /// system.
    #[must_use]
    pub fn new(platform: &'static Platform) -> Self {
        Self { platform }
    }
}

impl<Platform: platform::Provider> super::private::Sealed for FileSystem<Platform> {}

impl<Platform: platform::Provider> super::FileSystem for FileSystem<Platform> {
    fn open(
        &self,
        path: impl crate::path::Arg,
        flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<crate::fd::FileFd, super::errors::OpenError> {
        todo!()
    }

    fn close(&self, fd: crate::fd::FileFd) -> Result<(), super::errors::CloseError> {
        todo!()
    }

    fn read(
        &self,
        fd: &crate::fd::FileFd,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, super::errors::ReadError> {
        todo!()
    }

    fn write(
        &self,
        fd: &crate::fd::FileFd,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, super::errors::WriteError> {
        todo!()
    }

    fn seek(
        &self,
        fd: &crate::fd::FileFd,
        offset: isize,
        whence: super::SeekWhence,
    ) -> Result<usize, super::errors::SeekError> {
        todo!()
    }

    fn chmod(
        &self,
        path: impl crate::path::Arg,
        mode: super::Mode,
    ) -> Result<(), super::errors::ChmodError> {
        todo!()
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), super::errors::UnlinkError> {
        todo!()
    }

    fn mkdir(
        &self,
        path: impl crate::path::Arg,
        mode: super::Mode,
    ) -> Result<(), super::errors::MkdirError> {
        todo!()
    }

    fn rmdir(&self, path: impl crate::path::Arg) -> Result<(), super::errors::RmdirError> {
        todo!()
    }

    fn file_status(
        &self,
        path: impl crate::path::Arg,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        todo!()
    }

    fn fd_file_status(
        &self,
        fd: &crate::fd::FileFd,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        todo!()
    }

    fn with_metadata<T: core::any::Any, R>(
        &self,
        fd: &crate::fd::FileFd,
        f: impl FnOnce(&T) -> R,
    ) -> Result<R, super::errors::MetadataError> {
        todo!()
    }

    fn with_metadata_mut<T: core::any::Any, R>(
        &self,
        fd: &crate::fd::FileFd,
        f: impl FnOnce(&mut T) -> R,
    ) -> Result<R, super::errors::MetadataError> {
        todo!()
    }

    fn set_file_metadata<T: core::any::Any>(
        &self,
        fd: &crate::fd::FileFd,
        metadata: T,
    ) -> Result<Option<T>, super::errors::SetMetadataError<T>> {
        todo!()
    }

    fn set_fd_metadata<T: core::any::Any>(
        &self,
        fd: &crate::fd::FileFd,
        metadata: T,
    ) -> Result<Option<T>, super::errors::SetMetadataError<T>> {
        todo!()
    }
}
