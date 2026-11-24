// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Live host filesystem access rooted at a canonical host directory.
//!
//! Guest-supplied components are validated and walked one at a time. Linux pins the root and
//! each resolved object with a non-following descriptor. Regular files, directories, and symlinks are exposed live and host
//! access checks use the broker process's own credentials. Walks stop at host symlinks so the
//! resolver follows their targets inside the guest namespace; an absolute target below the root is
//! reported as an equivalent relative target so it stays correct wherever the backend is mounted,
//! and any other absolute target is rejected.
//!
//! External host namespace changes may occur between broker operations, but must not race
//! an operation's checks and subsequent filesystem access. Windows pins directory path
//! components against deletion and rename, but still relies on this assumption for
//! final-component checks. Non-Linux Unix hosts retain directory descriptors to detect
//! changed path identities and serialize pathname operations against guest namespace changes.
//! On Windows, std's native deletion can remain pending while an ordinary file handle is open, so the
//! same name may not be reusable until retained handles close. Rename uses the host's atomic
//! rename operation; in particular, replacing an empty directory may fail on Windows even though
//! the backend's type checks pass.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

mod io_errors;
mod location;
// Win32 ABI values used with std OpenOptionsExt, also on targets without windows-sys.
#[cfg(windows)]
mod win_flags {
    pub(super) const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    pub(super) const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    pub(super) const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    pub(super) const FILE_SHARE_READ: u32 = 1;
    pub(super) const FILE_SHARE_WRITE: u32 = 2;
    pub(super) const FILE_TRAVERSE: u32 = 0x20;
    pub(super) const FILE_READ_ATTRIBUTES: u32 = 0x80;
    pub(super) const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
}
#[cfg(all(test, target_os = "linux"))]
mod tests;
use location::Location;

macro_rules! guard_path_operations {
    ($this:expr, $failure:expr) => {
        #[cfg(all(unix, not(target_os = "linux")))]
        let _namespace = match location::namespace_guard($this.root.as_ref()) {
            Ok(namespace) => namespace,
            Err(error) => {
                litebox_util_log::debug!(error:? = error; "LocalFs namespace guard failed");
                return $failure;
            }
        };
    };
}
// On Linux and x86-64 Windows hosts, file reads and writes transfer directly between the host file
// and a buffer that is one contiguous part of raw bytes, such as a run of a runner's shared memory.
// Other buffers, and all buffers on other hosts, are staged through a bounce buffer.
#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(all(windows, target_arch = "x86_64"))]
pub(crate) mod windows;

/// Reads from `file` at `offset` into `buf` with one positioned read.
pub(crate) fn read_slice_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    check_offset(offset)?;
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_read(file, buf, offset)
    }
}

/// Writes `buf` to `file` at `offset` with one positioned write.
pub(crate) fn write_slice_at(file: &File, buf: &[u8], offset: u64) -> std::io::Result<usize> {
    check_offset(offset)?;
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::write_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_write(file, buf, offset)
    }
}

fn check_offset(offset: u64) -> std::io::Result<()> {
    i64::try_from(offset)
        .map(drop)
        .map_err(|_| std::io::ErrorKind::InvalidInput.into())
}

#[cfg(unix)]
use io_errors::chown_error;
use io_errors::{
    chmod_error, invalid_path, mkdir_error, open_error, rename_error, rmdir_error,
    stale_handle_error, unlink_error, unsupported_object, walk_error,
};

use litebox_broker_core::fs::backend::{
    Backend, BackendHandles, Caller, CreationMetadata, DirHandle, FileHandle, HandleRef,
    PermissionCheck, PermissionInfo, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget,
    SeekBehavior,
};
use litebox_broker_core::fs::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RenameError, ResolutionError, RmdirError, SetTimesError, SymlinkError,
    TruncateError, UnlinkError, WalkError, WriteError,
};
use litebox_broker_core::fs::inode_allocator::InodeAllocator;
use litebox_broker_core::fs::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, UserInfo};
use litebox_broker_core::transfer::bounce_buffer;
use litebox_broker_protocol::fs::{FileTimestamp, FileTimestamps, SetFileTimes};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

/// A live host filesystem rooted at a canonical directory path.
pub struct LocalFs {
    root: Location,
    instance_tag: BackendInstanceTag,
    allocator: InodeAllocator,
    identities: Mutex<HashMap<HostIdentity, NodeInfo>>,
}

/// Directory handle owned by [`LocalFs`].
#[derive(Clone)]
pub struct LocalDir {
    instance_tag: BackendInstanceTag,
    location: Location,
}

/// Regular-file or (`O_PATH`) symlink handle owned by [`LocalFs`].
#[derive(Clone)]
pub struct LocalFile {
    instance_tag: BackendInstanceTag,
    location: Location,
    /// Currently always [`FileType::RegularFile`] or (for `O_PATH` opens) [`FileType::SymbolicLink`].
    file_type: FileType,
    file: Option<Arc<File>>,
    readable: bool,
    writable: bool,
}

impl LocalFile {
    fn is_symlink(&self) -> bool {
        assert!(
            matches!(
                self.file_type,
                FileType::RegularFile | FileType::SymbolicLink
            ),
            "unexpected LocalFile type {:?}",
            self.file_type
        );
        self.file_type == FileType::SymbolicLink
    }
}

/// Identifies the [`LocalFs`] instance that created a handle.
///
/// Erased backend handles are only checked by backend type, and these handles carry host locations
/// (pinned descriptors on Linux, host paths elsewhere), so a handle passed to a different `LocalFs`
/// instance must be rejected rather than used outside that instance's root.
#[derive(Clone)]
struct BackendInstanceTag(Arc<()>);

impl BackendInstanceTag {
    fn new() -> Self {
        Self(Arc::new(()))
    }

    fn same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct HostIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(windows)]
    canonical_path: PathBuf,
}

struct Located {
    location: Location,
    file_type: FileType,
}

impl BackendHandles for LocalFs {
    type ResolvedDir<'a> = LocalDir;
    type ResolvedFile<'a> = LocalFile;
    type FileHandle = LocalFile;
    type DirHandle = LocalDir;
}

#[cfg(windows)]
fn is_reserved_device_stem(stem: &str) -> bool {
    if ["CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"]
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return true;
    }

    let upper = stem.to_ascii_uppercase();
    ["COM", "LPT"].iter().any(|prefix| {
        upper.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

fn validate_name(name: &str) -> Result<(), PathError> {
    let invalid = name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\0']);
    // Win32 path parsing gives these names namespace or device meaning, so they cannot name an
    // ordinary entry inside the root.
    #[cfg(windows)]
    let invalid = invalid
        || name.ends_with([' ', '.'])
        || name.chars().any(|ch| {
            ch <= '\u{1f}' || matches!(ch, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
        })
        || is_reserved_device_stem(name.split('.').next().unwrap_or(name));
    if invalid {
        return Err(PathError::InvalidPathname);
    }
    Ok(())
}

/// The components of the host name `name` below `root`; a name outside it was moved out.
fn components_under(root: &Path, name: &Path) -> Result<Vec<String>, WalkError> {
    name.strip_prefix(root)
        .map_err(|_| PathError::NoSuchFileOrDirectory)?
        .iter()
        .map(|part| part.to_str().map(String::from).ok_or(WalkError::Io))
        .collect()
}

fn check_flags(flags: OFlags) -> Result<(), OpenError> {
    const ALLOWED: OFlags = OFlags::CREAT
        .union(OFlags::WRONLY)
        .union(OFlags::RDWR)
        .union(OFlags::TRUNC)
        .union(OFlags::NOCTTY)
        .union(OFlags::EXCL)
        .union(OFlags::DIRECTORY)
        .union(OFlags::NONBLOCK)
        .union(OFlags::LARGEFILE)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::APPEND)
        .union(OFlags::PATH)
        .union(OFlags::CLOEXEC);
    if flags.intersects(!ALLOWED) || flags.contains(OFlags::WRONLY | OFlags::RDWR) {
        litebox_util_log::debug!(
            flags:? = flags;
            "rejecting open flags with EACCES where Linux would return EINVAL"
        );
        return Err(OpenError::AccessNotAllowed);
    }
    Ok(())
}

#[cfg(unix)]
fn host_mode(mode: Mode) -> u32 {
    u32::from((mode & !(Mode::SUID | Mode::SGID)).bits())
}

/// The broker's host umask still filters creation modes, unlike later `chmod`s.
#[cfg(unix)]
fn log_umask_filtered_mode(name: &str, metadata: &fs::Metadata, mode: Mode) {
    use std::os::unix::fs::MetadataExt as _;
    let requested = host_mode(mode);
    if metadata.mode() & 0o7777 != requested {
        litebox_util_log::debug!(
            name = name, requested = requested, actual = metadata.mode() & 0o7777;
            "host umask changed the created mode"
        );
    }
}

fn identity(metadata: &fs::Metadata, canonical_path: &Path) -> HostIdentity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let _ = canonical_path;
        HostIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
    #[cfg(windows)]
    {
        // XXX(jayb): `std` does not expose Windows file IDs on stable Rust. Canonical paths
        // preserve stable identity for ordinary names, but distinct hard links receive distinct
        // guest inode IDs, and an open old object plus a replacement at the same path can share
        // one guest inode ID.
        // XXX: Windows identity is path-keyed, so a rename changes the inode ID seen through the
        // new name; retained handles still use the old path.
        let _ = metadata;
        HostIdentity {
            canonical_path: canonical_path.to_owned(),
        }
    }
}

/// Type of a host object described by metadata that did not follow a final symlink.
fn host_file_type(metadata: &fs::Metadata) -> std::io::Result<FileType> {
    if metadata.file_type().is_symlink() {
        Ok(FileType::SymbolicLink)
    } else if metadata.is_file() {
        Ok(FileType::RegularFile)
    } else if metadata.is_dir() {
        Ok(FileType::Directory)
    } else {
        Err(unsupported_object())
    }
}

#[cfg(windows)]
fn timestamp_from_system_time(time: std::time::SystemTime) -> std::io::Result<FileTimestamp> {
    let (seconds, nanoseconds) = match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => (i128::from(duration.as_secs()), duration.subsec_nanos()),
        Err(error) => {
            let duration = error.duration();
            let nanos = duration.subsec_nanos();
            (
                -i128::from(duration.as_secs()) - i128::from(nanos != 0),
                if nanos == 0 { 0 } else { 1_000_000_000 - nanos },
            )
        }
    };
    Ok(FileTimestamp {
        seconds: i64::try_from(seconds).map_err(|_| std::io::ErrorKind::InvalidData)?,
        nanoseconds,
    })
}

fn timestamps_from_metadata(metadata: &fs::Metadata) -> std::io::Result<FileTimestamps> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok(FileTimestamps {
            accessed: FileTimestamp {
                seconds: metadata.atime(),
                nanoseconds: u32::try_from(metadata.atime_nsec())
                    .map_err(|_| std::io::ErrorKind::InvalidData)?,
            },
            modified: FileTimestamp {
                seconds: metadata.mtime(),
                nanoseconds: u32::try_from(metadata.mtime_nsec())
                    .map_err(|_| std::io::ErrorKind::InvalidData)?,
            },
            changed: FileTimestamp {
                seconds: metadata.ctime(),
                nanoseconds: u32::try_from(metadata.ctime_nsec())
                    .map_err(|_| std::io::ErrorKind::InvalidData)?,
            },
        })
    }
    #[cfg(windows)]
    {
        let modified = timestamp_from_system_time(metadata.modified()?)?;
        Ok(FileTimestamps {
            accessed: timestamp_from_system_time(metadata.accessed()?)?,
            modified,
            // XXX: std exposes no Windows change time; approximate with mtime.
            changed: modified,
        })
    }
}

fn status_from_metadata(
    metadata: &fs::Metadata,
    node_info: NodeInfo,
) -> std::io::Result<FileStatus> {
    let file_type = host_file_type(metadata)?;
    let (mode, owner, blksize) = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let owner = UserInfo {
                user: u16::try_from(metadata.uid()).unwrap_or(65534),
                group: u16::try_from(metadata.gid()).unwrap_or(65534),
            };
            (
                Mode::from_u32_bits_truncate(metadata.mode()),
                owner,
                metadata.blksize(),
            )
        }
        #[cfg(windows)]
        {
            let mut mode = Mode::RUSR
                | Mode::RGRP
                | Mode::ROTH
                // Windows has no execute permission bit, so report every object as executable and
                // leave rejecting non-executable formats to the loader.
                | Mode::XUSR
                | Mode::XGRP
                | Mode::XOTH;
            if !metadata.permissions().readonly() {
                mode |= Mode::WUSR | Mode::WGRP | Mode::WOTH;
            }
            litebox_util_log::debug!(
                "reporting Windows file as executable because Windows has no execute permission bit"
            );
            // Windows reports no block size; 4096 matches common NTFS clusters and keeps guests
            // that size buffers by `st_blksize` from seeing zero.
            litebox_util_log::debug!(
                "reporting a 4096-byte block size because Windows reports none"
            );
            (mode, UserInfo::ROOT, 4096)
        }
    };
    Ok(FileStatus {
        file_type,
        mode,
        size: metadata.len(),
        owner,
        node_info,
        blksize,
        times: Some(timestamps_from_metadata(metadata)?),
    })
}

#[cfg(windows)]
fn readonly_for_mode(mode: Mode) -> bool {
    !mode.intersects(Mode::WUSR | Mode::WGRP | Mode::WOTH)
}

/// Opens the final component of `path` without following reparse points and rejects it if
/// it is one. This does not validate any parent components.
#[cfg(windows)]
fn open_no_reparse(
    options: &mut OpenOptions,
    flags: u32,
    path: &Path,
) -> std::io::Result<(File, fs::Metadata)> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    let file = options
        .custom_flags(flags | win_flags::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & win_flags::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid_path());
    }
    Ok((file, metadata))
}

fn set_permissions_path(path: &Path, mode: Mode) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use win_flags::{FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES};
        let (file, _) = open_no_reparse(
            OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES),
            FILE_FLAG_BACKUP_SEMANTICS,
            path,
        )?;
        set_permissions_file(&file, mode)
    }
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(path)?.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, host_mode(mode));
        fs::set_permissions(path, permissions)
    }
}

/// Opens the regular file at `path` for I/O. Callers have checked its type. Hosts other than
/// Linux open it by path: other Unix hosts rely on the namespace guard to keep it in place, while
/// Windows checks the type again and refuses reparse points.
fn open_for_io(path: &Location, readable: bool, writable: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(readable).write(writable);
    #[cfg(windows)]
    {
        let (file, metadata) = open_no_reparse(&mut options, 0, path.as_ref())?;
        if !metadata.is_file() {
            return Err(invalid_path());
        }
        Ok(file)
    }
    #[cfg(not(windows))]
    options.open(path)
}

#[cfg(windows)]
fn set_permissions_file(file: &File, mode: Mode) -> std::io::Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(readonly_for_mode(mode));
    file.set_permissions(permissions)
}

impl LocalFs {
    /// Canonicalize an existing host directory as the filesystem root.
    ///
    /// External host namespace changes must not race individual filesystem operations.
    pub fn new(root: impl AsRef<Path>, allocator: InodeAllocator) -> std::io::Result<Self> {
        let root = fs::canonicalize(root)?;
        #[cfg(all(unix, not(target_os = "linux")))]
        let _namespace = location::namespace_guard(&root)?;
        let root = Location::pin_dir(&root)?;
        if !root.metadata()?.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "LocalFs root is not a directory",
            ));
        }
        Ok(Self {
            root,
            instance_tag: BackendInstanceTag::new(),
            allocator,
            identities: Mutex::new(HashMap::new()),
        })
    }

    /// [`Self::check_dir`], with its failures mapped to path errors (else `io`).
    fn check_usable_dir<E: From<PathError> + core::fmt::Debug>(
        &self,
        dir: &LocalDir,
        io: E,
    ) -> Result<(), E> {
        self.check_dir(dir)
            .map_err(|error| stale_handle_error(&error, io))
    }

    /// Checks a directory reached within the current operation. On Linux, such a directory was
    /// pinned from the root, or from a held directory that `walking_dir_at` or
    /// `walking_dir_with_path` checked, through non-following lookups of validated names, so it is
    /// inside the root by construction. Other hosts name directories by path and check them every
    /// time.
    fn check_walked_dir<E: From<PathError> + core::fmt::Debug>(
        &self,
        dir: &LocalDir,
        io: E,
    ) -> Result<(), E> {
        #[cfg(target_os = "linux")]
        return if self.valid_dir(dir) { Ok(()) } else { Err(io) };
        #[cfg(not(target_os = "linux"))]
        self.check_usable_dir(dir, io)
    }

    /// Fails unless `dir` belongs to this instance and is still inside the root. A directory
    /// moved outside the root, or (on non-Linux Unix hosts) moved or replaced at all, fails with
    /// `NotFound`. On Linux, a removed directory passes; see [`Location::linked_path`].
    fn check_dir(&self, dir: &LocalDir) -> std::io::Result<()> {
        if !self.valid_dir(dir) {
            return Err(invalid_path());
        }
        // Every absolute lookup starts from a clone of the root, which is trivially inside itself;
        // skip the two procfs readlinks.
        #[cfg(target_os = "linux")]
        if Arc::ptr_eq(&dir.location.pin, &self.root.pin) {
            return Ok(());
        }
        dir.location.checked_names_under(&self.root).map(drop)
    }

    fn valid_dir(&self, dir: &LocalDir) -> bool {
        self.instance_tag.same_instance(&dir.instance_tag)
    }

    fn valid_file(&self, file: &LocalFile) -> bool {
        self.instance_tag.same_instance(&file.instance_tag)
    }

    /// Fails unless `file` belongs to this instance and still names an object of its resolved
    /// type. A Linux location pins its inode, whose type cannot change.
    fn check_resolved_file(&self, file: &LocalFile) -> std::io::Result<()> {
        let stale = || std::io::Error::other("file is from another instance or was replaced");
        if !self.valid_file(file) {
            return Err(stale());
        }
        #[cfg(not(target_os = "linux"))]
        if !host_file_type(&file.location.metadata()?).is_ok_and(|ty| ty == file.file_type) {
            return Err(stale());
        }
        Ok(())
    }

    fn root_dir(&self) -> LocalDir {
        LocalDir {
            instance_tag: self.instance_tag.clone(),
            location: self.root.clone(),
        }
    }

    fn locate(parent: &LocalDir, name: &str) -> std::io::Result<Located> {
        // `pin_child` validates `name`.
        let location = parent.location.pin_child(name)?;
        let file_type = host_file_type(&location.metadata()?)?;
        Ok(Located {
            location,
            file_type,
        })
    }

    fn node(&self, metadata: &fs::Metadata, path: &Path) -> NodeInfo {
        let identity = identity(metadata, path);
        let mut identities = self
            .identities
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *identities
            .entry(identity)
            .or_insert_with(|| self.allocator.next())
    }

    fn status_location_of_type(
        &self,
        location: &Location,
        expected: FileType,
    ) -> std::io::Result<FileStatus> {
        let metadata = location.metadata()?;
        let actual = host_file_type(&metadata)?;
        // Check before `node` so a replaced object is not assigned a guest inode ID.
        if actual != expected {
            return Err(unsupported_object());
        }
        status_from_metadata(&metadata, self.node(&metadata, location.as_ref()))
    }

    fn status_file(&self, file: &File, identity_path: &Path) -> std::io::Result<FileStatus> {
        let metadata = file.metadata()?;
        status_from_metadata(&metadata, self.node(&metadata, identity_path))
    }
}

impl Backend for LocalFs {
    fn root(&self, _caller: Caller<'_>) -> Result<ResolvedDir<'_>, WalkError> {
        Ok(ResolvedDir::from_typed::<Self>(
            self.root_dir(),
            PermissionCheck::ByBackend,
        ))
    }

    fn resolve<'a>(
        &'a self,
        _caller: Caller<'_>,
        from: ResolvedDir<'a>,
        components: &[&str],
        _authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        guard_path_operations!(
            self,
            Err(ResolutionError {
                component: None,
                error: WalkError::Io
            })
        );
        let mut dir = from.into_typed::<Self>();
        self.check_walked_dir(&dir, WalkError::Io)
            .map_err(|error| ResolutionError {
                component: None,
                error,
            })?;
        for (index, &name) in components.iter().enumerate() {
            // An intermediate component must be a directory, which the open itself can check.
            #[cfg(target_os = "linux")]
            if index + 1 != components.len() {
                match dir.location.pin_child_dir(name) {
                    Ok(location) => {
                        dir = LocalDir {
                            instance_tag: self.instance_tag.clone(),
                            location,
                        };
                        continue;
                    }
                    // Anything else is classified below, which reports the precise error.
                    Err(error)
                        if error.raw_os_error().is_some_and(|errno| {
                            errno == rustix::io::Errno::NOTDIR.raw_os_error()
                                || errno == rustix::io::Errno::LOOP.raw_os_error()
                        }) => {}
                    Err(error) => {
                        return Err(ResolutionError {
                            component: Some(index),
                            error: walk_error(error),
                        });
                    }
                }
            }
            let Located {
                location,
                file_type,
            } = match Self::locate(&dir, name) {
                Ok(located) => located,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && index + 1 == components.len() =>
                {
                    return Ok(Resolution::MissingFinal {
                        parent: ResolvedDir::from_typed::<Self>(dir, PermissionCheck::ByBackend),
                    });
                }
                Err(error) => {
                    return Err(ResolutionError {
                        component: Some(index),
                        error: walk_error(error),
                    });
                }
            };
            if file_type == FileType::Directory {
                dir = LocalDir {
                    instance_tag: self.instance_tag.clone(),
                    location,
                };
            } else if index + 1 != components.len() {
                return Err(ResolutionError {
                    component: Some(index + 1),
                    error: PathError::ComponentNotADirectory.into(),
                });
            } else {
                return Ok(Resolution::Found(ResolvedTarget::File(
                    ResolvedFile::from_typed::<Self>(
                        LocalFile {
                            instance_tag: self.instance_tag.clone(),
                            location,
                            file_type,
                            file: None,
                            readable: false,
                            writable: false,
                        },
                        PermissionCheck::ByBackend,
                        file_type,
                    ),
                )));
            }
        }
        Ok(Resolution::Found(ResolvedTarget::Dir(
            ResolvedDir::from_typed::<Self>(dir, PermissionCheck::ByBackend),
        )))
    }

    fn read_link_at(
        &self,
        _caller: Caller<'_>,
        dir: &ResolvedDir<'_>,
        name: &str,
    ) -> Result<String, WalkError> {
        guard_path_operations!(self, Err(WalkError::Io));
        validate_name(name)?;
        let dir = dir.get_typed::<Self>();
        self.check_walked_dir(dir, WalkError::Io)?;
        let target = dir.location.read_link_at(name).map_err(walk_error)?;
        // The guest root is wherever this backend is mounted, so an absolute target below the host
        // root becomes the equivalent path relative to the link's directory. Any other rooted
        // target (including Windows drive- or root-relative forms) names a host location outside
        // the root and is rejected.
        if matches!(
            target.components().next(),
            Some(std::path::Component::Prefix(_) | std::path::Component::RootDir)
        ) {
            let (root, dir_name) = dir
                .location
                .checked_names_under(&self.root)
                .map_err(walk_error)?;
            let inside = target.strip_prefix(&root);
            // The root is canonical, but targets may spell it differently (Windows verbatim or 8.3
            // short prefixes, case, host symlinks in ancestors). Canonicalize the parent only, so
            // the final component stays a name the resolver will itself follow.
            let canonical_target =
                target
                    .parent()
                    .zip(target.file_name())
                    .and_then(|(parent, name)| {
                        fs::canonicalize(parent)
                            .ok()
                            .map(|parent| parent.join(name))
                    });
            let inside = inside.or_else(|error| {
                canonical_target
                    .as_deref()
                    .map_or(Err(error), |target| target.strip_prefix(&root))
            });
            let (Ok(inside), Ok(depth)) = (inside, dir_name.strip_prefix(&root)) else {
                litebox_util_log::debug!(
                    target:? = target;
                    "rejecting host symlink with an absolute target outside the root"
                );
                return Err(PathError::InvalidPathname.into());
            };
            if inside
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            {
                return Err(PathError::InvalidPathname.into());
            }
            let parts = depth
                .components()
                .map(|_| Some(".."))
                .chain(inside.components().map(|part| part.as_os_str().to_str()))
                .collect::<Option<Vec<_>>>()
                .ok_or(PathError::InvalidPathname)?;
            return Ok(if parts.is_empty() {
                String::from(".")
            } else {
                parts.join("/")
            });
        }
        let target = target.to_str().ok_or(PathError::InvalidPathname)?;
        #[cfg(windows)]
        return Ok(target.replace('\\', "/"));
        #[cfg(not(windows))]
        Ok(target.into())
    }

    fn open_dir(&self, dir: ResolvedDir<'_>, flags: OFlags) -> Result<DirHandle, OpenError> {
        guard_path_operations!(self, Err(OpenError::Io));
        check_flags(flags)?;
        let dir = dir.into_typed::<Self>();
        self.check_walked_dir(&dir, OpenError::Io)?;
        if flags.contains(OFlags::CREAT | OFlags::EXCL) {
            return Err(OpenError::AlreadyExists);
        }
        if flags.contains(OFlags::TRUNC) && !flags.contains(OFlags::PATH) {
            return Err(OpenError::AccessNotAllowed);
        }
        if !flags.contains(OFlags::PATH) {
            if flags.intersects(OFlags::WRONLY | OFlags::RDWR) {
                // Linux would return EISDIR, but `OpenError` cannot express it; the in-memory
                // backend likewise accepts writable directory opens.
                litebox_util_log::debug!(
                    path:? = dir.location, flags:? = flags;
                    "accepting writable directory open without host permission check"
                );
            } else {
                // std has no portable open-directory-for-reading call, so a listing probes the
                // host's read permission.
                let _ = fs::read_dir(&dir.location).map_err(open_error)?;
            }
        }
        Ok(DirHandle::from_typed::<Self>(dir))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Result<ResolvedDir<'a>, WalkError> {
        let dir = dir.get_typed::<Self>();
        // On Linux, operations trust directories walked from the result (see
        // `check_walked_dir`), so check containment once here. Other hosts check every
        // directory they use.
        #[cfg(target_os = "linux")]
        self.check_usable_dir(dir, WalkError::Io)?;
        #[cfg(not(target_os = "linux"))]
        if !self.valid_dir(dir) {
            return Err(WalkError::Io);
        }
        Ok(ResolvedDir::from_typed::<Self>(
            dir.clone(),
            PermissionCheck::ByBackend,
        ))
    }

    #[cfg(target_os = "linux")]
    fn walking_dir_with_path<'a>(
        &'a self,
        dir: &DirHandle,
    ) -> Result<
        (
            ResolvedDir<'a>,
            litebox_broker_core::fs::backend::DirPathResult,
        ),
        WalkError,
    > {
        let dir = dir.get_typed::<Self>();
        if !self.valid_dir(dir) {
            return Err(WalkError::Io);
        }
        let path = if Arc::ptr_eq(&dir.location.pin, &self.root.pin) {
            // The root is trivially inside itself (see `check_dir`).
            self.root
                .ensure_linked()
                .map_err(walk_error)
                .map(|()| Some(Vec::new()))
        } else {
            // One pair of procfs readlinks serves both the containment check of
            // `walking_dir_at` and the name of `dir_path`.
            let (root, name) = dir
                .location
                .checked_names_under(&self.root)
                .map_err(|error| stale_handle_error(&error, WalkError::Io))?;
            self.root
                .ensure_linked()
                .and_then(|()| dir.location.ensure_linked())
                .map_err(walk_error)
                .and_then(|()| components_under(&root, &name))
                .map(Some)
        };
        Ok((
            ResolvedDir::from_typed::<Self>(dir.clone(), PermissionCheck::ByBackend),
            path,
        ))
    }

    fn dir_path(
        &self,
        _caller: Caller<'_>,
        dir: &DirHandle,
    ) -> Result<Option<Vec<String>>, WalkError> {
        guard_path_operations!(self, Err(WalkError::Io));
        let dir = dir.get_typed::<Self>();
        if !self.valid_dir(dir) {
            return Err(WalkError::Io);
        }
        let root = self.root.linked_path().map_err(walk_error)?;
        let name = dir.location.linked_path().map_err(walk_error)?;
        components_under(&root, &name).map(Some)
    }

    fn parent_dir(
        &self,
        _caller: Caller<'_>,
        dir: &DirHandle,
    ) -> Result<Option<DirHandle>, WalkError> {
        guard_path_operations!(self, Err(WalkError::Io));
        let dir = dir.get_typed::<Self>();
        // On Linux, `parent_under` checks containment itself; checking here too would repeat its
        // procfs readlinks.
        #[cfg(target_os = "linux")]
        if !self.valid_dir(dir) {
            return Err(WalkError::Io);
        }
        #[cfg(not(target_os = "linux"))]
        self.check_usable_dir(dir, WalkError::Io)?;
        let parent = dir.location.parent_under(&self.root).map_err(walk_error)?;
        Ok(parent.map(|location| {
            DirHandle::from_typed::<Self>(LocalDir {
                instance_tag: self.instance_tag.clone(),
                location,
            })
        }))
    }

    fn check_search_permission(&self, dir: &ResolvedDir<'_>) -> Result<(), WalkError> {
        guard_path_operations!(self, Err(WalkError::Io));
        let dir = dir.get_typed::<Self>();
        self.check_walked_dir(dir, WalkError::Io)?;
        dir.location.check_search().map_err(walk_error)
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        guard_path_operations!(self, Err(OpenError::Io));
        check_flags(flags)?;
        let file = file.into_typed::<Self>();
        self.check_resolved_file(&file).map_err(open_error)?;
        let LocalFile {
            location,
            file_type,
            ..
        } = file;
        if flags.contains(OFlags::CREAT | OFlags::EXCL) {
            return Err(OpenError::AlreadyExists);
        }
        let symlink = file_type == FileType::SymbolicLink;
        if symlink
            && !flags.contains(OFlags::DIRECTORY)
            && !flags.contains(OFlags::PATH | OFlags::NOFOLLOW)
        {
            // The resolver follows links itself, so only a non-following `O_PATH` open names one.
            return Err(PathError::TooManySymlinks.into());
        }
        if !(file_type == FileType::RegularFile || symlink) || flags.contains(OFlags::DIRECTORY) {
            if file_type == FileType::Directory {
                litebox_util_log::debug!(
                    path:? = location;
                    "rejecting directory file open as ComponentNotADirectory where Linux would return EISDIR"
                );
            }
            return Err(PathError::ComponentNotADirectory.into());
        }
        let path_only = flags.contains(OFlags::PATH);
        let readable = !path_only && !flags.contains(OFlags::WRONLY);
        let writable = !path_only && flags.intersects(OFlags::WRONLY | OFlags::RDWR);
        let file = if path_only {
            if flags.contains(OFlags::TRUNC) {
                litebox_util_log::debug!(
                    path:? = location;
                    "ignoring O_TRUNC on O_PATH file open"
                );
            }
            None
        } else {
            let opened = open_for_io(&location, readable, writable).map_err(open_error)?;
            if flags.contains(OFlags::TRUNC) {
                if writable {
                    opened.set_len(0).map_err(open_error)?;
                } else {
                    // Linux truncates on O_RDONLY | O_TRUNC when the caller may write, so use a
                    // temporary write handle to get the host's write-permission check.
                    open_for_io(&location, false, true)
                        .and_then(|file| file.set_len(0))
                        .map_err(open_error)?;
                }
            }
            Some(Arc::new(opened))
        };
        // On Linux the opened file names itself, so its O_PATH pin can go.
        #[cfg(target_os = "linux")]
        let location = file
            .as_ref()
            .map_or(location, |file| Location::opened(Arc::clone(file)));
        Ok(FileHandle::from_typed::<Self>(LocalFile {
            instance_tag: self.instance_tag.clone(),
            location,
            file_type,
            file,
            readable,
            writable,
        }))
    }

    fn list_dir_at(
        &self,
        _caller: Caller<'_>,
        handle: DirHandle,
    ) -> Result<Vec<DirEntry>, ReadDirError> {
        guard_path_operations!(self, Err(ReadDirError::Io));
        let dir = handle.into_typed::<Self>();
        // Like Linux, listing a removed directory fails with ENOENT.
        let removed = |error: std::io::Error| match error.kind() {
            std::io::ErrorKind::NotFound => ReadDirError::Removed,
            _ => ReadDirError::Io,
        };
        self.check_dir(&dir).map_err(removed)?;
        let entries = fs::read_dir(&dir.location).map_err(removed)?;
        let mut result = Vec::new();
        for entry in entries {
            let entry = entry.map_err(removed)?;
            let name = entry.file_name();
            let Some(text) = name.to_str() else {
                continue;
            };
            if validate_name(text).is_err() {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            // `DirEntry::metadata` does not follow symlinks.
            let Ok(file_type) = host_file_type(&metadata) else {
                continue;
            };
            result.push(DirEntry {
                name: text.to_owned(),
                file_type,
                ino_info: Some(self.node(&metadata, &entry.path())),
            });
        }
        // std's listing (glibc's readdir) reports a removed directory as empty instead of failing,
        // and only an empty directory can be removed.
        if result.is_empty() {
            dir.location.linked_path().map_err(removed)?;
        }
        Ok(result)
    }

    fn read(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
    ) -> Result<usize, ReadError> {
        let h = h.get_typed::<Self>();
        if !self.valid_file(h) {
            return Err(ReadError::Io);
        }
        let file = h
            .file
            .as_ref()
            .filter(|_| h.readable)
            .ok_or(ReadError::NotForReading)?;
        let offset = u64::try_from(offset).map_err(|_| ReadError::Io)?;
        #[cfg(target_os = "linux")]
        if let Some(result) = linux::read_at(file, buf, 0, offset) {
            return result.map_err(|_| ReadError::Io);
        }
        #[cfg(all(windows, target_arch = "x86_64"))]
        if let Some(result) = windows::read_at(file, buf, 0, offset) {
            return result.map_err(|_| ReadError::Io);
        }
        let mut staged = bounce_buffer(buf.len())?;
        let read = read_slice_at(file, &mut staged, offset).map_err(|_| ReadError::Io)?;
        buf.copy_from_slice_at(0, &staged[..read])?;
        Ok(read)
    }

    fn write(
        &self,
        h: &FileHandle,
        buf: &dyn WriteBuffer,
        offset: usize,
    ) -> Result<usize, WriteError> {
        let h = h.get_typed::<Self>();
        if !self.valid_file(h) {
            return Err(WriteError::Io);
        }
        let file = h
            .file
            .as_ref()
            .filter(|_| h.writable)
            .ok_or(WriteError::NotForWriting)?;
        let offset = u64::try_from(offset).map_err(|_| WriteError::Io)?;
        #[cfg(target_os = "linux")]
        if let Some(result) = linux::write_at(file, buf, 0, offset) {
            return result.map_err(|_| WriteError::Io);
        }
        #[cfg(all(windows, target_arch = "x86_64"))]
        if let Some(result) = windows::write_at(file, buf, 0, offset) {
            return result.map_err(|_| WriteError::Io);
        }
        let mut staged = bounce_buffer(buf.len())?;
        buf.copy_to_slice_at(0, &mut staged)?;
        write_slice_at(file, &staged, offset).map_err(|_| WriteError::Io)
    }

    fn truncate(&self, h: &FileHandle, length: usize) -> Result<(), TruncateError> {
        let h = h.get_typed::<Self>();
        if !self.valid_file(h) {
            return Err(TruncateError::Io);
        }
        let file = h
            .file
            .as_ref()
            .filter(|_| h.writable)
            .ok_or(TruncateError::NotForWriting)?;
        file.set_len(u64::try_from(length).map_err(|_| TruncateError::Io)?)
            .map_err(|_| TruncateError::Io)
    }

    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior {
        if self.valid_file(h.get_typed::<Self>()) {
            SeekBehavior::PositionBased
        } else {
            litebox_util_log::debug!("reporting a foreign LocalFs file handle as non-seekable");
            SeekBehavior::NonSeekable
        }
    }

    fn status(&self, _caller: Caller<'_>, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        guard_path_operations!(self, Err(FileStatusError::Io));
        match h {
            HandleRef::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                self.check_usable_dir(dir, FileStatusError::Io)?;
                self.status_location_of_type(&dir.location, FileType::Directory)
                    .map_err(|_| FileStatusError::Io)
            }
            HandleRef::File(file) => {
                let file = file.get_typed::<Self>();
                if !self.valid_file(file) {
                    return Err(FileStatusError::Io);
                }
                if let Some(open) = &file.file {
                    self.status_file(open, file.location.as_ref())
                        .map_err(|_| FileStatusError::Io)
                } else {
                    self.status_location_of_type(&file.location, file.file_type)
                        .map_err(|_| FileStatusError::Io)
                }
            }
        }
    }

    fn resolved_status(
        &self,
        _caller: Caller<'_>,
        target: &ResolvedTarget<'_>,
    ) -> Result<FileStatus, FileStatusError> {
        guard_path_operations!(self, Err(FileStatusError::Io));
        let (location, file_type) = match target {
            ResolvedTarget::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                self.check_walked_dir(dir, FileStatusError::Io)?;
                (&dir.location, FileType::Directory)
            }
            ResolvedTarget::File(file) => {
                let file = file.get_typed::<Self>();
                if !self.valid_file(file) {
                    return Err(FileStatusError::Io);
                }
                (&file.location, file.file_type)
            }
        };
        self.status_location_of_type(location, file_type)
            .map_err(|_| FileStatusError::Io)
    }

    fn create_file_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        guard_path_operations!(self, Err(OpenError::Io));
        validate_name(name)?;
        let dir = dir.into_typed::<Self>();
        self.check_walked_dir(&dir, OpenError::Io)?;
        let opened = dir
            .location
            .create_file_at(name, metadata.mode)
            .map_err(open_error)?;
        #[cfg(unix)]
        if let Ok(host) = opened.metadata() {
            log_umask_filtered_mode(name, &host, metadata.mode);
        }
        #[cfg(windows)]
        if let Err(error) = set_permissions_file(&opened, metadata.mode) {
            drop(opened);
            if let Err(cleanup) = dir.location.remove_file_at(name) {
                litebox_util_log::warn!(
                    name = name, error:? = cleanup;
                    "failed to remove file after its creation failed"
                );
            }
            return Err(open_error(error));
        }
        let opened = Arc::new(opened);
        #[cfg(target_os = "linux")]
        let location = Location::opened(opened.clone());
        #[cfg(not(target_os = "linux"))]
        let location = dir.location.pin_child(name).map_err(open_error)?;
        Ok(FileHandle::from_typed::<Self>(LocalFile {
            instance_tag: self.instance_tag.clone(),
            location,
            file_type: FileType::RegularFile,
            file: Some(opened),
            readable: true,
            writable: true,
        }))
    }

    fn symlink_at(
        &self,
        _dir: ResolvedDir<'_>,
        _name: &str,
        _target: &str,
        _metadata: CreationMetadata,
    ) -> Result<(), SymlinkError> {
        // Guest-created host symlinks would let the guest race path checks against later opens
        // to escape the root. Validating the target alone cannot make the path-based non-Linux
        // variants safe; supporting this requires confining host access atomically on every host.
        unimplemented!()
    }

    fn mkdir_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        guard_path_operations!(self, Err(MkdirError::Io));
        validate_name(name)?;
        let dir = dir.into_typed::<Self>();
        self.check_walked_dir(&dir, MkdirError::Io)?;
        dir.location
            .create_dir_at(name, metadata.mode)
            .map_err(mkdir_error)?;
        #[cfg(windows)]
        if let Err(error) = set_permissions_path(&dir.location.as_ref().join(name), metadata.mode) {
            if let Err(cleanup) = dir.location.remove_dir_at(name) {
                litebox_util_log::warn!(
                    name = name, error:? = cleanup;
                    "failed to remove directory after its creation failed"
                );
            }
            return Err(mkdir_error(error));
        }
        let location = dir.location.pin_child(name).map_err(mkdir_error)?;
        let host = location.metadata().map_err(mkdir_error)?;
        if !host.is_dir() {
            return Err(MkdirError::Io);
        }
        #[cfg(unix)]
        log_umask_filtered_mode(name, &host, metadata.mode);
        Ok(DirHandle::from_typed::<Self>(LocalDir {
            instance_tag: self.instance_tag.clone(),
            location,
        }))
    }

    fn unlink_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), UnlinkError> {
        guard_path_operations!(self, Err(UnlinkError::Io));
        validate_name(name)?;
        let dir = dir.into_typed::<Self>();
        self.check_walked_dir(&dir, UnlinkError::Io)?;
        let entry = dir.location.entry_at(name).map_err(unlink_error)?;
        match entry.kind {
            Some(FileType::Directory) => return Err(UnlinkError::IsADirectory),
            Some(FileType::RegularFile | FileType::SymbolicLink) => {}
            _ => return Err(UnlinkError::Io),
        }
        #[cfg(windows)]
        let is_symlink = entry.kind == Some(FileType::SymbolicLink);
        #[cfg(windows)]
        if !is_symlink && entry.readonly {
            // Rust's Windows remove_file implementation can override the readonly attribute.
            // Preserve host-native readonly protection; callers can clear it with chmod first.
            return Err(UnlinkError::NoWritePerms);
        }
        match dir.location.remove_file_at(name) {
            Ok(()) => Ok(()),
            #[cfg(windows)]
            Err(error) if is_symlink => dir.location.remove_dir_at(name).map_err(|fallback| {
                litebox_util_log::debug!(
                    name = name, error:? = error, fallback:? = fallback;
                    "symlink removal failed as file and directory; reporting the file error"
                );
                unlink_error(error)
            }),
            Err(error) => Err(unlink_error(error)),
        }
    }

    fn rmdir_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), RmdirError> {
        guard_path_operations!(self, Err(RmdirError::Io));
        validate_name(name)?;
        let dir = dir.into_typed::<Self>();
        self.check_walked_dir(&dir, RmdirError::Io)?;
        if dir.location.entry_at(name).map_err(rmdir_error)?.kind != Some(FileType::Directory) {
            return Err(RmdirError::NotADirectory);
        }
        dir.location.remove_dir_at(name).map_err(rmdir_error)
    }

    fn rename_at(
        &self,
        old_dir: DirHandle,
        old_name: &str,
        new_dir: DirHandle,
        new_name: &str,
    ) -> Result<(), RenameError> {
        guard_path_operations!(self, Err(RenameError::Io));
        validate_name(old_name)?;
        validate_name(new_name)?;
        let old_dir = old_dir.into_typed::<Self>();
        let new_dir = new_dir.into_typed::<Self>();
        self.check_usable_dir(&old_dir, RenameError::Io)?;
        self.check_usable_dir(&new_dir, RenameError::Io)?;
        // Each pinned directory has its own procfs name, so path comparisons cannot detect a
        // move into the source's own subtree. The kernel checks that (EINVAL) before the
        // destination's type, as Linux guests expect.
        #[cfg(target_os = "linux")]
        {
            rustix::fs::renameat(
                &*old_dir.location.pin,
                old_name,
                &*new_dir.location.pin,
                new_name,
            )
            .map_err(|error| rename_error(error.into()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let old_path = old_dir.location.as_ref().join(old_name);
            let new_path = new_dir.location.as_ref().join(new_name);
            let source = fs::symlink_metadata(&old_path).map_err(rename_error)?;
            let source_is_dir = source.is_dir() && !source.file_type().is_symlink();
            if old_path == new_path {
                return Ok(());
            }
            if source_is_dir && new_path.starts_with(&old_path) {
                return Err(RenameError::InvalidArgument);
            }

            match fs::symlink_metadata(&new_path) {
                Ok(destination) => {
                    let destination_is_dir =
                        destination.is_dir() && !destination.file_type().is_symlink();
                    if !source_is_dir && destination_is_dir {
                        return Err(RenameError::IsADirectory);
                    }
                    if source_is_dir && !destination_is_dir {
                        return Err(RenameError::NotADirectory);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(rename_error(error)),
            }
            fs::rename(old_path, new_path).map_err(rename_error)
        }
    }

    fn set_times(
        &self,
        target: ResolvedTarget<'_>,
        times: &SetFileTimes,
    ) -> Result<(), SetTimesError> {
        guard_path_operations!(self, Err(SetTimesError::Io));
        let path = match &target {
            ResolvedTarget::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                self.check_walked_dir(dir, SetTimesError::Io)?;
                &dir.location
            }
            ResolvedTarget::File(file) => {
                let file = file.get_typed::<Self>();
                self.check_resolved_file(file)
                    .map_err(|error| stale_handle_error(&error, SetTimesError::Io))?;
                &file.location
            }
        };
        #[cfg(target_os = "linux")]
        {
            linux::set_times(path, times)
        }
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            windows::set_times(path.as_ref(), times)
        }
        #[cfg(not(any(target_os = "linux", all(windows, target_arch = "x86_64"))))]
        {
            let _ = (path, times);
            Err(SetTimesError::NotSupported)
        }
    }

    fn chmod(&self, h: ResolvedTarget<'_>, mode: Mode) -> Result<(), ChmodError> {
        guard_path_operations!(self, Err(ChmodError::Io));
        #[cfg(windows)]
        litebox_util_log::debug!(
            mode:? = mode;
            "Windows chmod keeps only whether any write bit is set (the readonly attribute)"
        );
        let result = match h {
            ResolvedTarget::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                self.check_walked_dir(dir, ChmodError::Io)?;
                if !dir
                    .location
                    .metadata()
                    .is_ok_and(|metadata| metadata.is_dir())
                {
                    return Err(ChmodError::Io);
                }
                set_permissions_path(dir.location.as_ref(), mode)
            }
            ResolvedTarget::File(file) => {
                let file = file.get_typed::<Self>();
                if !self.valid_file(file) {
                    return Err(ChmodError::Io);
                }
                if file.is_symlink() {
                    return Err(ChmodError::IsSymlink);
                }
                if !file
                    .location
                    .metadata()
                    .is_ok_and(|metadata| metadata.is_file())
                {
                    return Err(ChmodError::Io);
                }
                set_permissions_path(file.location.as_ref(), mode)
            }
        };
        result.map_err(chmod_error)
    }

    fn chown(
        &self,
        h: ResolvedTarget<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        guard_path_operations!(self, Err(ChownError::Io));
        let (path, file_type) = match &h {
            ResolvedTarget::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                self.check_walked_dir(dir, ChownError::Io)?;
                (&dir.location, FileType::Directory)
            }
            ResolvedTarget::File(file) => {
                let file = file.get_typed::<Self>();
                if !self.valid_file(file) {
                    return Err(ChownError::Io);
                }
                if file.is_symlink() {
                    return Err(ChownError::IsSymlink);
                }
                (&file.location, FileType::RegularFile)
            }
        };
        let metadata = path.metadata().map_err(|_| ChownError::Io)?;
        if file_type == FileType::Directory && !metadata.is_dir()
            || file_type == FileType::RegularFile && !metadata.is_file()
        {
            return Err(ChownError::Io);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if user.is_some_and(|user| u32::from(user) != metadata.uid())
                || group.is_some_and(|group| u32::from(group) != metadata.gid())
            {
                if u16::try_from(metadata.uid()).is_err() || u16::try_from(metadata.gid()).is_err()
                {
                    litebox_util_log::debug!(
                        uid = metadata.uid(), gid = metadata.gid();
                        "rejecting chown of a host owner that stat reports as 65534"
                    );
                }
                return Err(ChownError::NotTheOwner);
            }
            let user = user.map(u32::from);
            let group = group.map(u32::from);
            // The ids are unchanged, but the host call still applies its own permission check.
            std::os::unix::fs::chown(path, user, group).map_err(chown_error)
        }
        #[cfg(windows)]
        {
            litebox_util_log::debug!(
                user:? = user, group:? = group;
                "emulating Windows chown against the reported root owner"
            );
            if user.is_some_and(|user| user != UserInfo::ROOT.user)
                || group.is_some_and(|group| group != UserInfo::ROOT.group)
            {
                Err(ChownError::NotTheOwner)
            } else {
                Ok(())
            }
        }
    }
}
