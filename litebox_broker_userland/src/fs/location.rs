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
// reject stale names. Serialize the checks and operations with guest renames/removals across
// *all* LocalFs instances, even when two exports overlap. External host namespace changes
// must not race operations on these hosts, as for the original path-based backend.
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

impl Location {
    /// The directory's current host name, or `NotFound` once it has been removed.
    pub(super) fn directory_name(&self) -> io::Result<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            // Ask the kernel without reopening any ancestor. Its procfs suffix " (deleted)" can
            // also be part of a legitimate name.
            let name = self.host_name()?;
            if self.pin.metadata()?.nlink() == 0 {
                return Err(io::ErrorKind::NotFound.into());
            }
            Ok(name)
        }
        // Other hosts name directories by path. Windows holds the directory and its ancestors
        // without FILE_SHARE_DELETE; other Unix hosts reject a stale name for every operation,
        // so a moved directory has no name.
        #[cfg(not(target_os = "linux"))]
        {
            self.host_name()
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
impl Location {
    pub(super) fn root(path: &Path) -> io::Result<Self> {
        let file = open_directory(path)?;
        Ok(Self {
            path: path.into(),
            directory: Arc::new(CheckedDir {
                path: path.into(),
                file,
            }),
        })
    }

    pub(super) fn child(&self, name: &str) -> io::Result<Self> {
        super::validate_name(name).map_err(|_| super::invalid_path())?;
        let path = self.path.join(name);
        if fs::symlink_metadata(&path)?.is_dir() {
            Self::root(&path)
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

    fn check_directory(&self) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        // A symlink to the moved original must not authorize its new location outside the root.
        if fs::canonicalize(&self.directory.path)? != self.directory.path {
            return Err(super::invalid_path());
        }
        let named = fs::symlink_metadata(&self.directory.path)?;
        let pinned = self.directory.file.metadata()?;
        if (pinned.dev(), pinned.ino()) != (named.dev(), named.ino()) {
            return Err(super::invalid_path());
        }
        Ok(())
    }

    pub(super) fn host_name(&self) -> io::Result<PathBuf> {
        self.check_directory()?;
        Ok(self.path.clone())
    }

    pub(super) fn parent_under(&self, root: &Self) -> io::Result<Option<Self>> {
        self.check_directory()?;
        // Require search permission on the starting directory before granting its parent.
        fs::metadata(self.path.join("."))?;
        if self.path == root.path {
            return Ok(None);
        }
        let parent = self
            .path
            .parent()
            .filter(|p| p.starts_with(root))
            .ok_or_else(super::invalid_path)?;
        Self::root(parent).map(Some)
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

    pub(super) fn root(path: &Path) -> io::Result<Self> {
        use rustix::fs::{Mode, OFlags, open};
        Ok(Self::opened(Arc::new(File::from(open(
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?))))
    }

    pub(super) fn child(&self, name: &str) -> io::Result<Self> {
        use rustix::fs::{Mode, OFlags, openat};
        super::validate_name(name).map_err(|_| super::invalid_path())?;
        Ok(Self::opened(Arc::new(File::from(openat(
            &*self.pin,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?))))
    }

    pub(super) fn metadata(&self) -> io::Result<fs::Metadata> {
        self.pin.metadata()
    }

    /// The kernel's name for the pinned file, for containment checks. Unlike
    /// [`Self::directory_name`], an unlinked directory keeps a ` (deleted)` suffix.
    pub(super) fn host_name(&self) -> io::Result<PathBuf> {
        fs::read_link(&self.path)
    }

    /// Pin the actual parent without looking up the child from it. The canonical names are
    /// only containment checks, never locators used for a subsequent open.
    pub(super) fn parent_under(&self, root: &Self) -> io::Result<Option<Self>> {
        use rustix::fs::{Mode, OFlags, openat};
        use std::os::unix::fs::MetadataExt;
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let root_name = root.host_name()?;
        let name = self.host_name()?;
        if !name.starts_with(&root_name) {
            return Err(super::invalid_path());
        }
        if name == root_name {
            let a = self.metadata()?;
            let b = root.metadata()?;
            if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
                return Err(super::invalid_path());
            }
            let _search = openat(&*self.pin, ".", flags, Mode::empty())?;
            return Ok(None);
        }
        let parent = Self::opened(Arc::new(File::from(openat(
            &*self.pin,
            "..",
            flags,
            Mode::empty(),
        )?)));
        // A root moved since `root_name` was read fails this check closed.
        if !parent.host_name()?.starts_with(&root_name) {
            return Err(super::invalid_path());
        }
        Ok(Some(parent))
    }
}

#[cfg(all(test, unix, not(target_os = "linux")))]
#[test]
fn directory_identity_witness_rejects_replaced_ancestor() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    fs::create_dir_all(root.join("ancestor/sub")).unwrap();
    let pinned = Location::root(&root)
        .unwrap()
        .child("ancestor")
        .unwrap()
        .child("sub")
        .unwrap();
    assert!(pinned.metadata().is_ok());
    fs::rename(root.join("ancestor"), root.join("renamed")).unwrap();
    fs::create_dir_all(root.join("ancestor/sub")).unwrap();
    assert!(pinned.host_name().is_err());
}

#[cfg(all(test, windows, target_arch = "x86_64"))]
#[test]
fn directory_pins_preclude_ancestor_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("ancestor");
    let renamed = temp.path().join("renamed");
    fs::create_dir_all(original.join("sub")).unwrap();
    let sub = Location::root(&fs::canonicalize(temp.path()).unwrap())
        .unwrap()
        .child("ancestor")
        .unwrap()
        .child("sub")
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

    pub(super) fn root(path: &Path) -> io::Result<Self> {
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

    pub(super) fn child(&self, name: &str) -> io::Result<Self> {
        super::validate_name(name).map_err(|_| super::invalid_path())?;
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

    pub(super) fn host_name(&self) -> io::Result<PathBuf> {
        self.metadata()?;
        Ok(self.path.clone())
    }

    pub(super) fn parent_under(&self, root: &Self) -> io::Result<Option<Self>> {
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
