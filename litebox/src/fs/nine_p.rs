//! A network file system, using the 9p protocol

use crate::{LiteBox, platform};

/// A backing implementation for [`FileSystem`](super::FileSystem) using a 9p-based network file
/// system.
// TODO(jayb): Reduce the requirements necessary on `Platform` to the most precise one possible.
pub struct FileSystem<Platform: platform::Provider + Sync + 'static> {
    #[expect(dead_code, reason = "placeholder, currently nine_p is unimplemented")]
    litebox: LiteBox<Platform>,
}

impl<Platform: platform::Provider + Sync + 'static> FileSystem<Platform> {
    /// Construct a new `FileSystem` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialiation step,
    /// and the created `FileSystem` handle is expected to be shared across all usage over the
    /// system.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            litebox: litebox.clone(),
        }
    }
}

impl<Platform: platform::Provider + Sync> super::private::Sealed for FileSystem<Platform> {}

#[expect(unused_variables, reason = "unimplemented")]
impl<Platform: platform::Provider + Sync> super::FileSystem for FileSystem<Platform> {
    fn open(
        &self,
        path: impl crate::path::Arg,
        flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<FileFd<Platform>, super::errors::OpenError> {
        todo!()
    }

    fn close(&self, fd: &FileFd<Platform>) -> Result<(), super::errors::CloseError> {
        todo!()
    }

    fn read(
        &self,
        fd: &FileFd<Platform>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, super::errors::ReadError> {
        todo!()
    }

    fn write(
        &self,
        fd: &FileFd<Platform>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, super::errors::WriteError> {
        todo!()
    }

    fn seek(
        &self,
        fd: &FileFd<Platform>,
        offset: isize,
        whence: super::SeekWhence,
    ) -> Result<usize, super::errors::SeekError> {
        todo!()
    }

    fn truncate(
        &self,
        fd: &FileFd<Platform>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), super::errors::TruncateError> {
        todo!()
    }

    fn chmod(
        &self,
        path: impl crate::path::Arg,
        mode: super::Mode,
    ) -> Result<(), super::errors::ChmodError> {
        todo!()
    }

    fn chown(
        &self,
        path: impl crate::path::Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), super::errors::ChownError> {
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

    fn read_dir(
        &self,
        fd: &FileFd<Platform>,
    ) -> Result<alloc::vec::Vec<crate::fs::DirEntry>, super::errors::ReadDirError> {
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
        fd: &FileFd<Platform>,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        todo!()
    }
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { platform::Provider + Sync + 'static };
    FileSystem<Platform>;
    ();
    -> FileFd<Platform>;
}
