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
use tar_no_std::TarArchive;

use crate::{path::Arg as _, sync};

use super::{
    Mode, OFlags,
    errors::{
        ChmodError, CloseError, MkdirError, OpenError, PathError, ReadError, RmdirError,
        UnlinkError, WriteError,
    },
};

/// A backing implementation for [`FileSystem`](super::FileSystem), storing all files in-memory, via
/// a read-only `.tar` file.
pub struct FileSystem<'platform, Platform: sync::RawSyncPrimitivesProvider> {
    // TODO: Possibly support a single-threaded variant that doesn't have the cost of requiring a
    // sync-primitives platform, as well as cost of mutexes and such?
    sync: sync::Synchronization<'platform, Platform>,
    tar_data: TarArchive,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
    descriptors: sync::RwLock<'platform, Platform, Descriptors>,
}

impl<'platform, Platform: sync::RawSyncPrimitivesProvider> FileSystem<'platform, Platform> {
    /// Construct a new `FileSystem` instance from provided `tar_data`.
    ///
    /// Note: this function takes `tar_data` as a `Vec` rather than a `&[u8]` to eliminate a memcpy
    /// and ensure that full ownership is taken; if the fact that it is a `Vec` is sub-optimal due
    /// to an _external_ forced-memcpy for any particular use case, then this could be updated to a
    /// more flexible type, at the cost of adding an additional lifetime throughout this file
    /// system.
    ///
    /// # Panics
    ///
    /// Panics if the provided `tar_data` is found to be an invalid `.tar` file.
    #[must_use]
    pub fn new(platform: &'platform Platform, tar_data: Vec<u8>) -> Self {
        let sync = sync::Synchronization::new(platform);
        let descriptors = sync.new_rwlock(Descriptors::new());
        Self {
            sync,
            tar_data: TarArchive::new(tar_data.into_boxed_slice()).unwrap(),
            current_working_dir: "/".into(),
            descriptors,
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

impl<Platform: sync::RawSyncPrimitivesProvider> super::private::Sealed
    for FileSystem<'_, Platform>
{
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::FileSystem for FileSystem<'_, Platform> {
    fn open(
        &self,
        path: impl crate::path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<crate::fd::FileFd, OpenError> {
        use super::OFlags;
        let currently_supported_oflags: OFlags = OFlags::RDONLY | OFlags::WRONLY | OFlags::RDWR;
        if flags.contains(currently_supported_oflags.complement()) {
            unimplemented!()
        }
        let path = self.absolute_path(path)?;
        assert!(path.starts_with('/'));
        let path = &path[1..];
        let Some((idx, entry)) =
            // TODO: this might be slow for large tar files, due to a linear scan. If better perf is
            // needed, we can add a hashmap layer after doing one scan (in `new()`) that allows a
            // direct hashmap lookup of relevant information and data.
            self.tar_data.entries().enumerate().find(|(_, entry)| {
                match entry.filename().as_str() {
                    Ok(p) => p.starts_with(path),
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
        if entry.filename().as_str().unwrap() == path {
            // it is a file
            Ok(self
                .descriptors
                .write()
                .insert(Descriptor::File { idx, position: 0 }))
        } else {
            // it is a dir
            Ok(self.descriptors.write().insert(Descriptor::Dir {
                path: path.to_owned(),
            }))
        }
    }

    fn close(&self, fd: crate::fd::FileFd) -> Result<(), CloseError> {
        self.descriptors.write().remove(fd);
        Ok(())
    }

    fn read(&self, fd: &crate::fd::FileFd, buf: &mut [u8]) -> Result<usize, ReadError> {
        let mut descriptors = self.descriptors.write();
        let Descriptor::File { idx, position } = descriptors.get_mut(fd) else {
            return Err(ReadError::NotAFile);
        };
        let file = self.tar_data.entries().nth(*idx).unwrap().data();
        let start = (*position).min(file.len());
        let end = position.checked_add(buf.len()).unwrap().min(file.len());
        debug_assert!(start <= end);
        let retlen = end - start;
        buf[..retlen].copy_from_slice(&file[start..end]);
        *position = end;
        Ok(retlen)
    }

    fn write(&self, fd: &crate::fd::FileFd, buf: &[u8]) -> Result<usize, WriteError> {
        match self.descriptors.read().get(fd) {
            Descriptor::File { .. } => Err(WriteError::NotForWriting),
            Descriptor::Dir { .. } => Err(WriteError::NotAFile),
        }
    }

    fn chmod(&self, path: impl crate::path::Arg, mode: Mode) -> Result<(), ChmodError> {
        let path = self.absolute_path(path)?;
        assert!(path.starts_with('/'));
        let path = &path[1..];
        if self
            .tar_data
            .entries()
            .any(|entry| match entry.filename().as_str() {
                Ok(p) => p.starts_with(path),
                Err(_) => false,
            })
        {
            Err(ChmodError::ReadOnlyFileSystem)
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
                Ok(p) => p.starts_with(path),
                Err(_) => false,
            });
        match entry {
            None => Err(PathError::NoSuchFileOrDirectory)?,
            Some(p) if p.filename().as_str().unwrap() != path => Err(UnlinkError::IsADirectory),
            Some(p) => Err(UnlinkError::ReadOnlyFileSystem),
        }
    }

    fn mkdir(&self, path: impl crate::path::Arg, mode: Mode) -> Result<(), MkdirError> {
        // TODO: Do we need to do the type of checks that are happening in the other functions, or
        // should the other functions be simplified to this?
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn rmdir(&self, path: impl crate::path::Arg) -> Result<(), RmdirError> {
        // TODO: Do we need to do the type of checks that are happening in the other functions, or
        // should the other functions be simplified to this?
        Err(RmdirError::ReadOnlyFileSystem)
    }
}

type Descriptors = super::shared::Descriptors<Descriptor>;

enum Descriptor {
    File { idx: usize, position: usize },
    Dir { path: String },
}
