//! An layered file system, layering on [`FileSystem`](super::FileSystem) on top of another.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::fd::FileFd;
use crate::path::Arg;
use crate::sync;

use super::Mode;
use super::errors::{
    ChmodError, CloseError, MkdirError, OpenError, PathError, ReadError, RmdirError, UnlinkError,
    WriteError,
};

/// A backing implementation of [`FileSystem`](super::FileSystem) that layers a file system on top
/// of another.
///
/// This particular implementation itself doesn't carry or store any of the files, but delegates to
/// each of the the layers. Specifically, this implementation will look for and work with files in
/// the upper layer, unless they don't exist, in which case the lower layer is looked at.
///
/// The current design of layering treats the lower layer as read-only, and thus if a file is opened
/// in writable mode that doesn't exist in the upper layer, but _does_ exist in the lower layer,
/// this will have copy-on-write semantics. Future versions of the layering might support other
/// configurable options for the layering.
pub struct FileSystem<
    'platform,
    Platform: sync::RawSyncPrimitivesProvider,
    Upper: super::FileSystem,
    Lower: super::FileSystem,
> {
    // TODO: Possibly support a single-threaded variant that doesn't have the cost of requiring a
    // sync-primitives platform, as well as cost of mutexes and such?
    sync: sync::Synchronization<'platform, Platform>,
    upper: Upper,
    lower: Lower,
    descriptors: sync::RwLock<'platform, Platform, Descriptors>,
}

impl<
    'platform,
    Platform: sync::RawSyncPrimitivesProvider,
    Upper: super::FileSystem,
    Lower: super::FileSystem,
> FileSystem<'platform, Platform, Upper, Lower>
{
    /// Construct a new `FileSystem` instance
    #[must_use]
    pub fn new(platform: &'platform Platform, upper: Upper, lower: Lower) -> Self {
        let sync = sync::Synchronization::new(platform);
        let descriptors = sync.new_rwlock(Descriptors::new());
        Self {
            sync,
            upper,
            lower,
            descriptors,
        }
    }

    /// (private-only) check if the lower level has the path; if there is a path failure, just fail
    /// out with the relevant path error.
    #[must_use]
    fn ensure_lower_contains(&self, path: &str) -> Result<(), PathError> {
        // TODO: We current do this with `open`. We might want to switch to `stat` or similar.
        match self
            .lower
            .open(path, super::OFlags::RDONLY, super::Mode::empty())
        {
            Ok(fd) => {
                self.lower.close(fd);
                Ok(())
            }
            Err(e) => match e {
                OpenError::AccessNotAllowed => Ok(()),
                OpenError::NoWritePerms | OpenError::ReadOnlyFileSystem => unreachable!(),
                OpenError::PathError(path_error) => Err(path_error),
            },
        }
    }

    /// (private-only) Migrate a file from lower to upper layer
    ///
    /// It performs a check to make sure that the lower level has the file, and if the lower-level
    /// does not, then it will error out with the relevant `PathError` that can be propagated as
    /// necessary.
    ///
    /// Note: this focuses only on files.
    #[must_use]
    fn migrate_file_up(&self, path: &str) -> Result<(), PathError> {
        self.ensure_lower_contains(path)?;
        // TODO:
        // - Make all parent directories in upper layer (if needed)
        // - Actually move the file over (making sure to also migrate the perms over)
        // - (MAYBE?) Update all the existing descriptors over (how do we check for this?)
        todo!()
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider, Upper: super::FileSystem, Lower: super::FileSystem>
    super::private::Sealed for FileSystem<'_, Platform, Upper, Lower>
{
}

impl<Platform: sync::RawSyncPrimitivesProvider, Upper: super::FileSystem, Lower: super::FileSystem>
    super::FileSystem for FileSystem<'_, Platform, Upper, Lower>
{
    fn open(
        &self,
        path: impl crate::path::Arg,
        flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<crate::fd::FileFd, OpenError> {
        use super::OFlags;
        let currently_supported_oflags: OFlags =
            OFlags::CREAT | OFlags::RDONLY | OFlags::WRONLY | OFlags::RDWR;
        if flags.contains(currently_supported_oflags.complement()) {
            unimplemented!()
        }
        let Ok(path) = path.as_rust_str() else {
            return Err(PathError::InvalidPathname)?;
        };
        match self.upper.open(path, flags, mode) {
            Ok(fd) => Ok(self.descriptors.write().insert(Descriptor::Upper { fd })),
            Err(e) => match &e {
                OpenError::AccessNotAllowed
                | OpenError::NoWritePerms
                | OpenError::ReadOnlyFileSystem
                | OpenError::PathError(
                    PathError::ComponentNotADirectory
                    | PathError::InvalidPathname
                    | PathError::MissingComponent
                    | PathError::NoSearchPerms { .. },
                ) => {
                    // None of these can be handled by lower level, just quit out early
                    Err(e)
                }
                OpenError::PathError(PathError::NoSuchFileOrDirectory) => {
                    // Handle-able by lower level, let us invoke the lower level, although we are
                    // likely going to have to mess with permissions a little bit.
                    let original_flags = flags;
                    let mut flags = flags;
                    // Prevent creation of files at lower level
                    flags.remove(OFlags::CREAT);
                    // Switch the lower level to read-only; the other calls will take care of
                    // copying into the upper level if/when necessary.
                    flags.remove(OFlags::RDWR);
                    flags.remove(OFlags::WRONLY);
                    flags.insert(OFlags::RDONLY);
                    // TODO: We need to track whether what the permissions on the file from the
                    // lower layer themselves are, otherwise we might end up allowing write (via
                    // CoW) on a read-only file.
                    //
                    // Any errors from lower level now _must_ propagate up, so we can just invoke
                    // the lower level and set up the relevant descriptor upon success.
                    Ok(self.descriptors.write().insert(Descriptor::Lower {
                        fd: self.lower.open(path, flags, mode)?,
                        original_flags,
                        file_path: path.to_string(),
                    }))
                }
            },
        }
    }

    fn close(&self, fd: crate::fd::FileFd) -> Result<(), CloseError> {
        match self.descriptors.write().remove(fd) {
            Descriptor::Upper { fd } => self.upper.close(fd),
            Descriptor::Lower { fd, .. } => self.lower.close(fd),
        }
    }

    fn read(&self, fd: &crate::fd::FileFd, buf: &mut [u8]) -> Result<usize, ReadError> {
        // TODO: We need to confirm that nothing in the upper layer _also_ opened the file and wrote
        // something for a lower-level-opened file
        match self.descriptors.read().get(fd) {
            Descriptor::Upper { fd } => self.upper.read(fd, buf),
            Descriptor::Lower { fd, .. } => self.lower.read(fd, buf),
        }
    }

    fn write(&self, fd: &crate::fd::FileFd, buf: &[u8]) -> Result<usize, WriteError> {
        let (file_path, original_flags) = match self.descriptors.read().get(fd) {
            Descriptor::Upper { fd } => {
                return self.upper.write(fd, buf);
            }
            Descriptor::Lower {
                fd,
                original_flags,
                file_path,
            } => {
                if original_flags.contains(super::OFlags::WRONLY)
                    || original_flags.contains(super::OFlags::RDWR)
                {
                    // Fallthrough
                    (file_path.clone(), *original_flags)
                } else {
                    return Err(WriteError::NotForWriting);
                }
            }
        };
        // We have a lower-layer file open with copy-on-write semantics here. We will migrate it
        // over to the upper layer.
        //
        // TODO: What if there are other FDs open to the same file? How do we ensure
        // they are not looking at a stale copy of the file?

        // First we migrate the file data itself up
        self.migrate_file_up(&file_path);

        // Then we switch the descriptor over, making it into an upper-layer descriptor
        let mut descriptors = self.descriptors.write();
        let desc = descriptors.get_mut(fd);
        match core::mem::replace(
            desc,
            Descriptor::Upper {
                fd: self
                    .upper
                    .open(file_path, original_flags, Mode::empty())
                    .unwrap(),
            },
        ) {
            Descriptor::Lower {
                fd: lower_fd,
                original_flags: _,
                file_path: _,
            } => self.lower.close(lower_fd).unwrap(),
            Descriptor::Upper { .. } => unreachable!(),
        };

        // Finally, we can perform the write that we were supposed to do, essentially by just
        // recursing into ourselves, since things have migrated over at this point.
        self.write(fd, buf)
    }

    fn chmod(&self, path: impl crate::path::Arg, mode: super::Mode) -> Result<(), ChmodError> {
        let Ok(path) = path.as_rust_str() else {
            return Err(PathError::InvalidPathname)?;
        };
        match self.upper.chmod(path, mode) {
            Ok(()) => return Ok(()),
            Err(e) => match e {
                ChmodError::NotTheOwner
                | ChmodError::ReadOnlyFileSystem
                | ChmodError::PathError(
                    PathError::ComponentNotADirectory
                    | PathError::InvalidPathname
                    | PathError::MissingComponent
                    | PathError::NoSearchPerms { .. },
                ) => {
                    return Err(e);
                }
                ChmodError::PathError(PathError::NoSuchFileOrDirectory) => {
                    // fallthrough
                }
            },
        };
        self.migrate_file_up(path);
        self.chmod(path, mode)
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), UnlinkError> {
        let Ok(path) = path.as_rust_str() else {
            return Err(PathError::InvalidPathname)?;
        };
        match self.upper.unlink(path) {
            Ok(()) => return Ok(()),
            Err(e) => match e {
                UnlinkError::NoWritePerms
                | UnlinkError::IsADirectory
                | UnlinkError::ReadOnlyFileSystem
                | UnlinkError::PathError(
                    PathError::ComponentNotADirectory
                    | PathError::InvalidPathname
                    | PathError::MissingComponent
                    | PathError::NoSearchPerms { .. },
                ) => {
                    return Err(e);
                }
                UnlinkError::PathError(PathError::NoSuchFileOrDirectory) => {
                    // fallthrough
                }
            },
        }
        self.ensure_lower_contains(path)?;
        // TODO: We need to place tombstones since this file exists at lower layer, and thus must be
        // correctly accounted for above.
        todo!()
    }

    fn mkdir(&self, path: impl crate::path::Arg, mode: super::Mode) -> Result<(), MkdirError> {
        let Ok(path) = path.as_rust_str() else {
            return Err(PathError::InvalidPathname)?;
        };
        match self.upper.mkdir(path, mode) {
            Ok(()) => return Ok(()),
            Err(e) => match e {
                MkdirError::NoWritePerms
                | MkdirError::AlreadyExists
                | MkdirError::ReadOnlyFileSystem
                | MkdirError::PathError(
                    PathError::ComponentNotADirectory
                    | PathError::InvalidPathname
                    | PathError::NoSearchPerms { .. },
                ) => {
                    return Err(e);
                }
                MkdirError::PathError(PathError::NoSuchFileOrDirectory) => {
                    unreachable!()
                }
                MkdirError::PathError(PathError::MissingComponent) => {
                    // fallthrough
                }
            },
        }
        // We know that at least one of the components is missing. We should check each of the
        // components individually, making directories for any components that already exist at the
        // lower layer, and erroring out if no lower layer component exists of that form.
        let path = path.normalized().map_err(PathError::from)?;
        for dir in path.increasing_ancestors().map_err(PathError::from)? {
            match self.ensure_lower_contains(dir) {
                Ok(()) => {
                    // The dir does in fact exist; we just need to confirm that the upper layer also
                    // has it.
                    // TODO: Get the mode using `stat` or whatever
                    match self.upper.mkdir(dir, mode) {
                        Ok(()) => {
                            // fallthrough
                        }
                        Err(e) => match e {
                            MkdirError::AlreadyExists => {
                                // perfectly fine, just fallthrough to next place in the loop
                            }
                            MkdirError::ReadOnlyFileSystem
                            | MkdirError::NoWritePerms
                            | MkdirError::PathError(
                                PathError::ComponentNotADirectory
                                | PathError::InvalidPathname
                                | PathError::NoSearchPerms { .. },
                            ) => {
                                return Err(e);
                            }
                            MkdirError::PathError(
                                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
                            ) => {
                                unreachable!()
                            }
                        },
                    }
                }
                Err(PathError::ComponentNotADirectory) => unimplemented!(),
                Err(PathError::InvalidPathname) => unreachable!("we just confirmed valid path"),
                Err(PathError::MissingComponent) => unreachable!(),
                Err(e @ PathError::NoSearchPerms { .. }) => {
                    return Err(e)?;
                }
                Err(PathError::NoSuchFileOrDirectory) => {
                    // This is possibly the missing component; if it is same as the path itself,
                    // then it just needs its mkdir at the upper level; otherwise it is a true
                    // missing component.
                    if dir == path {
                        return self.upper.mkdir(&*path, mode);
                    } else {
                        return Err(PathError::MissingComponent)?;
                    }
                }
            }
        }
        unreachable!()
    }

    fn rmdir(&self, path: impl crate::path::Arg) -> Result<(), RmdirError> {
        // TODO: We need to place tombstones in the upper layer if a lower-layer directory is
        // deleted
        //
        // TODO: We also need to confirm that there is no possible lower-level file possible
        // at that directory, oof.
        todo!()
    }
}

type Descriptors = super::shared::Descriptors<Descriptor>;

enum Descriptor {
    Upper {
        fd: FileFd,
    },
    Lower {
        fd: FileFd,
        original_flags: super::OFlags,
        file_path: String,
    },
}
