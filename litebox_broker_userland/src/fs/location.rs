// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A name usable with std filesystem operations for the lifetime of the retained handle.
#[derive(Clone, Debug)]
pub(super) struct Location {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    pub(super) pin: Arc<File>,
    // Windows has no std dirfd-relative operations. Instead, exclude rename/deletion
    // of every directory in the path (including ancestors of the configured root).
    #[cfg(windows)]
    locks: Arc<Vec<Arc<File>>>,
    #[cfg(windows)]
    locked_dir: bool,
    #[cfg(all(unix, not(target_os = "linux")))]
    directory: Arc<CheckedDir>,
}

// Other Unix hosts retain a directory fd as an identity witness, not a path locator. They
// reject stale names.
#[cfg(all(unix, not(target_os = "linux")))]
#[derive(Debug)]
struct CheckedDir {
    path: PathBuf,
    file: File,
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(super) fn namespace_guard(root: &Path) -> io::Result<Vec<File>> {
    // Independent open descriptions release their advisory locks on drop. A shared lock
    // on each ancestor and an exclusive one at the export root serialize overlapping
    // exports (including independently created instances), but not unrelated mounts.
    // All callers acquire in the same root-to-leaf order.
    let mut ancestors: Vec<_> = root.ancestors().collect();
    ancestors.reverse();
    ancestors
        .into_iter()
        .map(|path| {
            let file = open_directory(path)?;
            if path == root {
                file.lock()?;
            } else {
                file.lock_shared()?;
            }
            Ok(file)
        })
        .collect()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn open_directory(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Darwin O_EVTONLY: pin identity without requesting directory read permission.
        const O_EVTONLY: i32 = 0x8000;
        options.custom_flags(O_EVTONLY);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_dir() {
        return Err(io::ErrorKind::NotADirectory.into());
    }
    Ok(file)
}

/// The type of a directory entry, without following a final symlink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EntryKind {
    Directory,
    RegularFile,
    Symlink,
    Other,
}

/// A directory entry as `lstat` describes it.
#[derive(Clone, Copy, Debug)]
pub(super) struct Entry {
    pub(super) kind: EntryKind,
    /// The Windows readonly attribute.
    #[cfg(windows)]
    pub(super) readonly: bool,
}

/// Fails unless `name` names an entry of a directory rather than escaping or aliasing it; every
/// host operation on an entry checks this before using `name`.
fn check_name(name: &str) -> io::Result<()> {
    super::validate_name(name).map_err(|_| super::invalid_path())
}

impl Location {
    /// The host names of `root` and of this location, failing with `NotFound` once this
    /// location is no longer inside `root`.
    pub(super) fn checked_names_under(&self, root: &Self) -> io::Result<(PathBuf, PathBuf)> {
        let root_name = root.host_path()?;
        let name = self.host_path()?;
        if !name.starts_with(&root_name) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "directory was moved outside the LocalFs root",
            ));
        }
        Ok((root_name, name))
    }

    /// Fails unless the caller may search this directory.
    pub(super) fn check_search(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags, openat};
            openat(
                &*self.pin,
                ".",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        fs::metadata(self.join(".")).map(drop)
    }

    /// Fails with `NotFound` once the pinned directory has been removed.
    #[cfg(target_os = "linux")]
    pub(super) fn ensure_linked(&self) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        if self.pin.metadata()?.nlink() == 0 {
            return Err(io::ErrorKind::NotFound.into());
        }
        Ok(())
    }

    /// The directory's current host name, or `NotFound` once it has been removed.
    pub(super) fn linked_path(&self) -> io::Result<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            // Ask the kernel without reopening any ancestor. Its procfs suffix " (deleted)" can
            // also be part of a legitimate name.
            let name = self.host_path()?;
            self.ensure_linked()?;
            Ok(name)
        }
        // Other hosts name directories by path. Windows holds the directory and its ancestors
        // without FILE_SHARE_DELETE; other Unix hosts reject a stale name for every operation
        // with `NotFound`, so a moved directory is unreachable and reported like a removed one.
        #[cfg(not(target_os = "linux"))]
        {
            self.host_path()
        }
    }
}

// Hosts without dirfd-relative std operations reach entries by path.
#[cfg(not(target_os = "linux"))]
impl Location {
    fn entry_path(&self, name: &str) -> io::Result<PathBuf> {
        check_name(name)?;
        Ok(self.path.join(name))
    }

    pub(super) fn entry_at(&self, name: &str) -> io::Result<Entry> {
        let metadata = fs::symlink_metadata(self.entry_path(name)?)?;
        let kind = if metadata.file_type().is_symlink() {
            EntryKind::Symlink
        } else if metadata.is_dir() {
            EntryKind::Directory
        } else if metadata.is_file() {
            EntryKind::RegularFile
        } else {
            EntryKind::Other
        };
        Ok(Entry {
            kind,
            #[cfg(windows)]
            readonly: metadata.permissions().readonly(),
        })
    }

    pub(super) fn read_link_at(&self, name: &str) -> io::Result<PathBuf> {
        fs::read_link(self.entry_path(name)?)
    }

    /// Creates the regular file `name`, failing if it exists. Windows ignores `mode`; the caller
    /// applies it afterwards.
    pub(super) fn create_file_at(&self, name: &str, mode: super::Mode) -> io::Result<File> {
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, super::host_mode(mode));
        #[cfg(windows)]
        let _ = mode;
        options.open(self.entry_path(name)?)
    }

    /// Creates the directory `name`. Windows ignores `mode`; the caller applies it afterwards.
    pub(super) fn create_dir_at(&self, name: &str, mode: super::Mode) -> io::Result<()> {
        let path = self.entry_path(name)?;
        #[cfg(unix)]
        {
            let mut builder = fs::DirBuilder::new();
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, super::host_mode(mode));
            builder.create(path)
        }
        #[cfg(windows)]
        {
            let _ = mode;
            fs::create_dir(path)
        }
    }

    pub(super) fn remove_file_at(&self, name: &str) -> io::Result<()> {
        fs::remove_file(self.entry_path(name)?)
    }

    pub(super) fn remove_dir_at(&self, name: &str) -> io::Result<()> {
        fs::remove_dir(self.entry_path(name)?)
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
impl Location {
    pub(super) fn pin_dir(path: &Path) -> io::Result<Self> {
        let file = open_directory(path)?;
        Ok(Self {
            path: path.into(),
            directory: Arc::new(CheckedDir {
                path: path.into(),
                file,
            }),
        })
    }

    pub(super) fn pin_child(&self, name: &str) -> io::Result<Self> {
        check_name(name)?;
        let path = self.path.join(name);
        if fs::symlink_metadata(&path)?.is_dir() {
            // Pin the host's spelling of the name: case- or normalization-insensitive volumes
            // accept other spellings, which the canonical-name check would treat as a move.
            let canonical = fs::canonicalize(&path)?;
            if canonical.parent() != Some(self.path.as_path()) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "directory was moved or replaced",
                ));
            }
            Self::pin_dir(&canonical)
        } else {
            Ok(Self {
                path,
                directory: self.directory.clone(),
            })
        }
    }

    pub(super) fn metadata(&self) -> io::Result<fs::Metadata> {
        self.check_directory()?;
        fs::symlink_metadata(&self.path)
    }

    /// Fails with `NotFound` unless the recorded name still names the pinned directory.
    fn check_directory(&self) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let stale = || io::Error::new(io::ErrorKind::NotFound, "directory was moved or replaced");
        // A symlink to the moved original must not authorize its new location outside the root.
        if fs::canonicalize(&self.directory.path)? != self.directory.path {
            return Err(stale());
        }
        let named = fs::symlink_metadata(&self.directory.path)?;
        let pinned = self.directory.file.metadata()?;
        if (pinned.dev(), pinned.ino()) != (named.dev(), named.ino()) {
            return Err(stale());
        }
        Ok(())
    }

    fn host_path(&self) -> io::Result<PathBuf> {
        self.check_directory()?;
        Ok(self.path.clone())
    }

    pub(super) fn parent_under(&self, root: &Self) -> io::Result<Option<Self>> {
        self.check_directory()?;
        // Require search permission on the starting directory before granting its parent.
        self.check_search()?;
        if self.path == root.path {
            return Ok(None);
        }
        let parent = self
            .path
            .parent()
            .filter(|p| p.starts_with(root))
            .ok_or_else(super::invalid_path)?;
        Self::pin_dir(parent).map(Some)
    }
}

impl AsRef<Path> for Location {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl std::ops::Deref for Location {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

#[cfg(target_os = "linux")]
impl Location {
    pub(super) fn opened(file: Arc<File>) -> Self {
        use std::os::fd::AsRawFd;
        // Only the kernel-supplied magic link for *our own live descriptor* is followed.
        // Never canonicalize and reopen its target. If procfs is unavailable, fail closed.
        Self {
            path: format!("/proc/self/fd/{}", file.as_raw_fd()).into(),
            pin: file,
        }
    }

    /// Pins `name` relative to `dir` with `O_PATH`, adding `flags`.
    fn pin_at(
        dir: impl std::os::fd::AsFd,
        name: impl rustix::path::Arg,
        flags: rustix::fs::OFlags,
    ) -> io::Result<Self> {
        use rustix::fs::{Mode, OFlags, openat};
        Ok(Self::opened(Arc::new(File::from(openat(
            dir,
            name,
            OFlags::PATH | OFlags::CLOEXEC | flags,
            Mode::empty(),
        )?))))
    }

    pub(super) fn pin_dir(path: &Path) -> io::Result<Self> {
        use rustix::fs::{CWD, OFlags};
        Self::pin_at(CWD, path, OFlags::DIRECTORY | OFlags::NOFOLLOW)
    }

    pub(super) fn pin_child(&self, name: &str) -> io::Result<Self> {
        check_name(name)?;
        Self::pin_at(&*self.pin, name, rustix::fs::OFlags::NOFOLLOW)
    }

    pub(super) fn metadata(&self) -> io::Result<fs::Metadata> {
        self.pin.metadata()
    }

    /// The kernel's name for the pinned file, for containment checks. Unlike
    /// [`Self::linked_path`], an unlinked directory keeps a ` (deleted)` suffix.
    fn host_path(&self) -> io::Result<PathBuf> {
        fs::read_link(&self.path)
    }

    /// Pin the actual parent without looking up the child from it. The canonical names are
    /// only containment checks, never locators used for a subsequent open. A directory moved
    /// outside the root fails with `NotFound` (see [`Self::checked_names_under`]).
    pub(super) fn parent_under(&self, root: &Self) -> io::Result<Option<Self>> {
        use std::os::unix::fs::MetadataExt;
        let (root_name, name) = self.checked_names_under(root)?;
        if name == root_name {
            let a = self.metadata()?;
            let b = root.metadata()?;
            if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
                return Err(super::invalid_path());
            }
            self.check_search()?;
            return Ok(None);
        }
        let parent = Self::pin_at(&*self.pin, "..", rustix::fs::OFlags::DIRECTORY)?;
        // A root moved since `root_name` was read fails this check closed.
        if !parent.host_path()?.starts_with(&root_name) {
            return Err(super::invalid_path());
        }
        Ok(Some(parent))
    }

    // Entry operations go through the pin rather than its procfs name, sparing the kernel the
    // magic-link walk and the caller a path allocation.

    pub(super) fn entry_at(&self, name: &str) -> io::Result<Entry> {
        use rustix::fs::{AtFlags, FileType, statat};
        check_name(name)?;
        let stat = statat(&*self.pin, name, AtFlags::SYMLINK_NOFOLLOW)?;
        let kind = match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => EntryKind::Directory,
            FileType::RegularFile => EntryKind::RegularFile,
            FileType::Symlink => EntryKind::Symlink,
            _ => EntryKind::Other,
        };
        Ok(Entry { kind })
    }

    pub(super) fn read_link_at(&self, name: &str) -> io::Result<PathBuf> {
        use std::os::unix::ffi::OsStringExt;
        check_name(name)?;
        let target = rustix::fs::readlinkat(&*self.pin, name, Vec::new())?;
        Ok(std::ffi::OsString::from_vec(target.into_bytes()).into())
    }

    /// Creates the regular file `name`, failing if it exists.
    pub(super) fn create_file_at(&self, name: &str, mode: super::Mode) -> io::Result<File> {
        use rustix::fs::{Mode, OFlags, openat};
        check_name(name)?;
        Ok(File::from(openat(
            &*self.pin,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(super::host_mode(mode)),
        )?))
    }

    pub(super) fn create_dir_at(&self, name: &str, mode: super::Mode) -> io::Result<()> {
        use rustix::fs::{Mode, mkdirat};
        check_name(name)?;
        Ok(mkdirat(
            &*self.pin,
            name,
            Mode::from_raw_mode(super::host_mode(mode)),
        )?)
    }

    pub(super) fn remove_file_at(&self, name: &str) -> io::Result<()> {
        use rustix::fs::{AtFlags, unlinkat};
        check_name(name)?;
        Ok(unlinkat(&*self.pin, name, AtFlags::empty())?)
    }

    pub(super) fn remove_dir_at(&self, name: &str) -> io::Result<()> {
        use rustix::fs::{AtFlags, unlinkat};
        check_name(name)?;
        Ok(unlinkat(&*self.pin, name, AtFlags::REMOVEDIR)?)
    }
}

#[cfg(all(test, unix, not(target_os = "linux")))]
#[test]
fn directory_identity_witness_rejects_replaced_ancestor() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    fs::create_dir_all(root.join("ancestor/sub")).unwrap();
    let pinned = Location::pin_dir(&root)
        .unwrap()
        .pin_child("ancestor")
        .unwrap()
        .pin_child("sub")
        .unwrap();
    assert!(pinned.metadata().is_ok());
    fs::rename(root.join("ancestor"), root.join("renamed")).unwrap();
    fs::create_dir_all(root.join("ancestor/sub")).unwrap();
    assert!(pinned.host_path().is_err());
}

#[cfg(all(test, windows, target_arch = "x86_64"))]
#[test]
fn directory_pins_preclude_ancestor_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("ancestor");
    let renamed = temp.path().join("renamed");
    fs::create_dir_all(original.join("sub")).unwrap();
    let sub = Location::pin_dir(&fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .pin_child("ancestor")
        .unwrap()
        .pin_child("sub")
        .unwrap();
    assert!(fs::rename(&original, &renamed).is_err());
    drop(sub);
    fs::rename(original, renamed).unwrap();
}

#[cfg(windows)]
impl Location {
    fn lock_dir(path: &Path) -> io::Result<Arc<File>> {
        use super::win_flags::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
        };
        use std::os::windows::fs::OpenOptionsExt as _;
        let (pin, metadata) = super::open_no_reparse(
            fs::OpenOptions::new()
                // A metadata-only open does not participate in the I/O manager's sharing check.
                .access_mode(FILE_TRAVERSE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE),
            FILE_FLAG_BACKUP_SEMANTICS,
            path,
        )?;
        if !metadata.is_dir() {
            return Err(super::invalid_path());
        }
        Ok(Arc::new(pin))
    }

    pub(super) fn pin_dir(path: &Path) -> io::Result<Self> {
        let mut ancestors: Vec<_> = path.ancestors().collect();
        ancestors.reverse();
        let locks = ancestors
            .into_iter()
            .map(Self::lock_dir)
            .collect::<io::Result<_>>()?;
        Ok(Self {
            path: path.into(),
            locks: Arc::new(locks),
            locked_dir: true,
        })
    }

    pub(super) fn pin_child(&self, name: &str) -> io::Result<Self> {
        check_name(name)?;
        let path = self.path.join(name);
        let locked_dir = fs::symlink_metadata(&path)?.is_dir();
        let locks = if locked_dir {
            let mut locks = self.locks.as_ref().clone();
            locks.push(Self::lock_dir(&path)?);
            Arc::new(locks)
        } else {
            self.locks.clone()
        };
        Ok(Self {
            path,
            locks,
            locked_dir,
        })
    }

    pub(super) fn metadata(&self) -> io::Result<fs::Metadata> {
        let metadata = fs::symlink_metadata(&self.path)?;
        if metadata.is_dir() != self.locked_dir {
            return Err(super::invalid_path());
        }
        Ok(metadata)
    }

    fn host_path(&self) -> io::Result<PathBuf> {
        self.metadata()?;
        Ok(self.path.clone())
    }

    pub(super) fn parent_under(&self, root: &Self) -> io::Result<Option<Self>> {
        // Require search permission on the starting directory before granting its parent.
        self.check_search()?;
        if self.path == root.path {
            return Ok(None);
        }
        if self.locked_dir
            && let Some(parent) = self.path.parent().filter(|p| p.starts_with(root))
        {
            let mut locks = self.locks.as_ref().clone();
            locks.pop();
            return Ok(Some(Self {
                path: parent.into(),
                locks: Arc::new(locks),
                locked_dir: true,
            }));
        }
        Err(super::invalid_path())
    }
}
