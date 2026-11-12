// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Live host filesystem access rooted at a canonical host directory.
//!
//! This backend assumes the host namespace is trusted not to race its checks. Guest-supplied path
//! components are validated, every resolved object is canonicalized, and the result must remain
//! below the configured root. Regular files, directories, and symlinks are exposed live and host
//! access checks use the broker process's own credentials. Walks stop at host symlinks so the
//! resolver follows their targets inside the guest namespace; an absolute target below the root is
//! reported as an equivalent relative target so it stays correct wherever the backend is mounted.
//! An indirect absolute target, such as a tool alternative, is also accepted if its fully resolved
//! host target is below the root; any other absolute target is rejected.
//!
//! The root is intentionally path-based rather than pinned by a directory handle. A concurrent
//! host rename, replacement, or symlink swap can therefore invalidate a check or redirect a later
//! operation. Walks, directory listings, and `O_PATH` directory handles are pathname locators:
//! deleting and recreating their path retargets them. Open (non-`O_PATH`) directories hold a host
//! descriptor, so their status, mode changes, and reopens keep acting on the original object; on
//! Linux, `O_PATH` files do too for their status and reopens. This tradeoff keeps the implementation portable and mostly
//! platform-neutral; it is suitable only when host namespace administration is trusted. On
//! Windows, std's native deletion can remain pending while an ordinary file handle is open, so the
//! same name may not be reusable until retained handles close. Rename uses the host's atomic
//! rename operation; in particular, replacing an empty directory may fail on Windows even though
//! the backend's type checks pass.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

mod io_errors;
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
    chmod_error, invalid_path, mkdir_error, open_error, rename_error, rmdir_error, unlink_error,
    unsupported_object, walk_error,
};

use litebox_broker_core::fs::backend::{
    Backend, BackendHandles, CreationMetadata, DirHandle, FileHandle, HandleRef, PermissionCheck,
    PermissionInfo, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget, SeekBehavior,
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
    root: PathBuf,
    instance_tag: BackendInstanceTag,
    allocator: InodeAllocator,
    identities: Mutex<HashMap<HostIdentity, NodeInfo>>,
}

/// Directory handle owned by [`LocalFs`].
#[derive(Clone)]
pub struct LocalDir {
    instance_tag: BackendInstanceTag,
    canonical_path: PathBuf,
    /// Native descriptor retained by an open directory, not by walking handles.
    file: Option<Arc<File>>,
}

/// Regular-file or (`O_PATH`) symlink handle owned by [`LocalFs`].
#[derive(Clone)]
pub struct LocalFile {
    instance_tag: BackendInstanceTag,
    canonical_path: PathBuf,
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
/// Erased backend handles are only checked by backend type, and these handles carry absolute host
/// paths, so a handle passed to a different `LocalFs` instance must be rejected rather than used
/// outside that instance's root.
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
    canonical_path: PathBuf,
    file_type: FileType,
}

impl BackendHandles for LocalFs {
    // XXX(jayb): LocalFs handles are path-based and can go stale on host rename.
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
fn log_umask_filtered_mode(path: &Path, metadata: std::io::Result<fs::Metadata>, mode: Mode) {
    use std::os::unix::fs::MetadataExt as _;
    let requested = host_mode(mode);
    if let Ok(metadata) = metadata
        && metadata.mode() & 0o7777 != requested
    {
        litebox_util_log::debug!(
            path:? = path, requested = requested, actual = metadata.mode() & 0o7777;
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

/// `permissions` with the host equivalent of `mode`.
fn with_mode(mut permissions: fs::Permissions, mode: Mode) -> fs::Permissions {
    #[cfg(unix)]
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, host_mode(mode));
    #[cfg(windows)]
    permissions.set_readonly(readonly_for_mode(mode));
    permissions
}

fn set_permissions_path(path: &Path, mode: Mode) -> std::io::Result<()> {
    fs::set_permissions(path, with_mode(fs::metadata(path)?.permissions(), mode))
}

fn set_permissions_file(file: &File, mode: Mode) -> std::io::Result<()> {
    file.set_permissions(with_mode(file.metadata()?.permissions(), mode))
}

fn open_directory(path: &Path) -> std::io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS);
    }
    options.open(path)
}

impl LocalFs {
    /// Canonicalize an existing host directory as the filesystem root.
    ///
    /// Host namespace administration must be trusted not to race later checks and operations.
    pub fn new(root: impl AsRef<Path>, allocator: InodeAllocator) -> std::io::Result<Self> {
        let root = fs::canonicalize(root)?;
        if !fs::metadata(&root)?.is_dir() {
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

    fn valid_dir(&self, dir: &LocalDir) -> bool {
        self.instance_tag.same_instance(&dir.instance_tag)
    }

    fn valid_file(&self, file: &LocalFile) -> bool {
        self.instance_tag.same_instance(&file.instance_tag)
    }

    fn root_dir(&self) -> LocalDir {
        LocalDir {
            instance_tag: self.instance_tag.clone(),
            canonical_path: self.root.clone(),
            file: None,
        }
    }

    fn locate(parent: &LocalDir, name: &str) -> std::io::Result<Located> {
        validate_name(name).map_err(|_| invalid_path())?;
        let canonical_path = parent.canonical_path.join(name);
        let file_type = host_file_type(&fs::symlink_metadata(&canonical_path)?)?;
        Ok(Located {
            canonical_path,
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

    fn status_path_of_type(&self, path: &Path, expected: FileType) -> std::io::Result<FileStatus> {
        let metadata = fs::symlink_metadata(path)?;
        let actual = host_file_type(&metadata)?;
        // Check before `node` so a replaced object is not assigned a guest inode ID.
        if actual != expected {
            return Err(unsupported_object());
        }
        status_from_metadata(&metadata, self.node(&metadata, path))
    }

    fn status_file(&self, file: &File, identity_path: &Path) -> std::io::Result<FileStatus> {
        let metadata = file.metadata()?;
        status_from_metadata(&metadata, self.node(&metadata, identity_path))
    }
}

impl Backend for LocalFs {
    fn root_with_context(
        &self,
        _context: &litebox_broker_core::fs::backend::LookupContext,
    ) -> Result<ResolvedDir<'_>, WalkError> {
        Ok(ResolvedDir::from_typed::<Self>(
            self.root_dir(),
            PermissionCheck::ByBackend,
        ))
    }

    fn resolve_with_context<'a>(
        &'a self,
        _context: &litebox_broker_core::fs::backend::LookupContext,
        from: ResolvedDir<'a>,
        components: &[&str],
        _authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        let mut dir = from.into_typed::<Self>();
        if !self.valid_dir(&dir) {
            return Err(ResolutionError {
                component: None,
                error: WalkError::Io,
            });
        }
        for (index, &name) in components.iter().enumerate() {
            let Located {
                canonical_path,
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
                    canonical_path,
                    file: None,
                };
                // XXX: search on a dir followed by `..` goes unchecked (e.g. `blocked/../target`).
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
                            canonical_path,
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

    fn read_link_at_with_context(
        &self,
        _context: &litebox_broker_core::fs::backend::LookupContext,
        dir: &ResolvedDir<'_>,
        name: &str,
    ) -> Result<String, WalkError> {
        validate_name(name)?;
        let dir = dir.get_typed::<Self>();
        if !self.valid_dir(dir) {
            return Err(WalkError::Io);
        }
        let target = fs::read_link(dir.canonical_path.join(name)).map_err(walk_error)?;
        // The guest root is wherever this backend is mounted, so an absolute target below the host
        // root becomes the equivalent path relative to the link's directory. Indirect targets
        // must resolve back inside this root, never into another host directory.
        if matches!(
            target.components().next(),
            Some(std::path::Component::Prefix(_) | std::path::Component::RootDir)
        ) {
            let inside = target.strip_prefix(&self.root);
            // The root is canonical, but targets may spell it differently (Windows verbatim or 8.3
            // short prefixes, case, host symlinks in ancestors). Canonicalize the parent first, so
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
                    .map_or(Err(error), |target| target.strip_prefix(&self.root))
            });
            // A final component that is itself a host link may still lead back inside the root.
            // Any failure to place the target there is the same rejection, so the guest cannot
            // probe host paths outside the root.
            let resolved_target = if inside.is_err() {
                fs::canonicalize(&target).ok()
            } else {
                None
            };
            let inside = inside.or_else(|error| {
                resolved_target
                    .as_deref()
                    .map_or(Err(error), |target| target.strip_prefix(&self.root))
            });
            let (Ok(inside), Ok(depth)) = (inside, dir.canonical_path.strip_prefix(&self.root))
            else {
                litebox_util_log::debug!(
                    target:? = target;
                    "rejecting host symlink with an absolute target outside the root"
                );
                return Err(PathError::InvalidPathname.into());
            };
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
        check_flags(flags)?;
        let mut dir = dir.into_typed::<Self>();
        if !self.valid_dir(&dir) {
            return Err(OpenError::Io);
        }
        if !fs::metadata(&dir.canonical_path).is_ok_and(|metadata| metadata.is_dir()) {
            litebox_util_log::debug!(
                path:? = dir.canonical_path;
                "directory vanished or was replaced before open; reporting Io"
            );
            return Err(OpenError::Io);
        }
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
                    path:? = dir.canonical_path, flags:? = flags;
                    "accepting writable directory open, which the host opens for reading"
                );
            }
            // Opening the directory for reading checks the host's read permission, as listing
            // it would.
            dir.file = Some(Arc::new(
                open_directory(&dir.canonical_path).map_err(open_error)?,
            ));
        }
        Ok(DirHandle::from_typed::<Self>(dir))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<ResolvedDir<'a>> {
        let dir = dir.get_typed::<Self>();
        if !self.valid_dir(dir) {
            return None;
        }
        if !fs::metadata(&dir.canonical_path).is_ok_and(|metadata| metadata.is_dir()) {
            litebox_util_log::debug!(
                path:? = dir.canonical_path;
                "directory handle no longer names a host directory"
            );
            return None;
        }
        Some(ResolvedDir::from_typed::<Self>(
            dir.clone(),
            PermissionCheck::ByBackend,
        ))
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        check_flags(flags)?;
        let file = file.into_typed::<Self>();
        if !self.valid_file(&file) {
            return Err(OpenError::Io);
        }
        let LocalFile {
            canonical_path,
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
                    path:? = canonical_path;
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
                    path:? = canonical_path;
                    "ignoring O_TRUNC on O_PATH file open"
                );
            }
            #[cfg(target_os = "linux")]
            {
                let descriptor = rustix::fs::open(
                    &canonical_path,
                    rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|error| open_error(error.into()))?;
                Some(Arc::new(File::from(descriptor)))
            }
            #[cfg(not(target_os = "linux"))]
            {
                None
            }
        } else {
            let opened = OpenOptions::new()
                .read(readable)
                .write(writable)
                .open(&canonical_path)
                .map_err(open_error)?;
            if flags.contains(OFlags::TRUNC) {
                if writable {
                    opened.set_len(0).map_err(open_error)?;
                } else {
                    // Linux truncates on O_RDONLY | O_TRUNC when the caller may write, so use a
                    // temporary write handle to get the host's write-permission check.
                    OpenOptions::new()
                        .write(true)
                        .open(&canonical_path)
                        .and_then(|file| file.set_len(0))
                        .map_err(open_error)?;
                }
            }
            Some(Arc::new(opened))
        };
        Ok(FileHandle::from_typed::<Self>(LocalFile {
            instance_tag: self.instance_tag.clone(),
            canonical_path,
            file_type,
            file,
            readable,
            writable,
        }))
    }

    fn reopen_file(&self, handle: &FileHandle, flags: OFlags) -> Result<FileHandle, OpenError> {
        check_flags(flags)?;
        let source = handle.get_typed::<Self>();
        if !self.valid_file(source) {
            return Err(OpenError::Io);
        }
        let path_only = flags.contains(OFlags::PATH);
        let readable = !path_only && !flags.contains(OFlags::WRONLY);
        let writable = !path_only && flags.intersects(OFlags::WRONLY | OFlags::RDWR);
        let descriptor = source.file.as_ref().ok_or(OpenError::NoSuchDevice)?;
        let file = if path_only {
            Arc::clone(descriptor)
        } else {
            if source.is_symlink() {
                return Err(PathError::TooManySymlinks.into());
            }
            #[cfg(target_os = "linux")]
            {
                use std::os::fd::AsRawFd;
                let truncate = flags.contains(OFlags::TRUNC);
                Arc::new(
                    OpenOptions::new()
                        .read(readable)
                        .write(writable || truncate)
                        .truncate(truncate)
                        .open(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
                        .map_err(open_error)?,
                )
            }
            #[cfg(not(target_os = "linux"))]
            {
                if (readable && !source.readable) || (writable && !source.writable) {
                    return Err(OpenError::NoSuchDevice);
                }
                if flags.contains(OFlags::TRUNC) {
                    descriptor.set_len(0).map_err(open_error)?;
                }
                Arc::clone(descriptor)
            }
        };
        Ok(FileHandle::from_typed::<Self>(LocalFile {
            file: Some(file),
            readable,
            writable,
            ..source.clone()
        }))
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        let dir = handle.into_typed::<Self>();
        if !self.valid_dir(&dir) {
            return Err(ReadDirError::Io);
        }
        let entries = fs::read_dir(&dir.canonical_path).map_err(|_| ReadDirError::Io)?;
        let mut result = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| ReadDirError::Io)?;
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

    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        match h {
            HandleRef::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                if !self.valid_dir(dir) {
                    return Err(FileStatusError::Io);
                }
                if let Some(file) = &dir.file {
                    return self
                        .status_file(file, &dir.canonical_path)
                        .map_err(|_| FileStatusError::Io);
                }
                self.status_path_of_type(&dir.canonical_path, FileType::Directory)
                    .map_err(|_| FileStatusError::Io)
            }
            HandleRef::File(file) => {
                let file = file.get_typed::<Self>();
                if !self.valid_file(file) {
                    return Err(FileStatusError::Io);
                }
                if let Some(open) = &file.file {
                    self.status_file(open, &file.canonical_path)
                        .map_err(|_| FileStatusError::Io)
                } else {
                    self.status_path_of_type(&file.canonical_path, file.file_type)
                        .map_err(|_| FileStatusError::Io)
                }
            }
        }
    }

    fn resolved_status(&self, target: &ResolvedTarget<'_>) -> Result<FileStatus, FileStatusError> {
        let (path, file_type) = match target {
            ResolvedTarget::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                if !self.valid_dir(dir) {
                    return Err(FileStatusError::Io);
                }
                (&dir.canonical_path, FileType::Directory)
            }
            ResolvedTarget::File(file) => {
                let file = file.get_typed::<Self>();
                if !self.valid_file(file) {
                    return Err(FileStatusError::Io);
                }
                (&file.canonical_path, file.file_type)
            }
        };
        self.status_path_of_type(path, file_type)
            .map_err(|_| FileStatusError::Io)
    }

    fn create_file_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        validate_name(name)?;
        let dir = dir.into_typed::<Self>();
        if !self.valid_dir(&dir) {
            return Err(OpenError::Io);
        }
        let canonical_path = dir.canonical_path.join(name);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, host_mode(metadata.mode));
        let opened = options.open(&canonical_path).map_err(open_error)?;
        #[cfg(unix)]
        log_umask_filtered_mode(&canonical_path, opened.metadata(), metadata.mode);
        #[cfg(windows)]
        if let Err(error) = set_permissions_file(&opened, metadata.mode) {
            drop(opened);
            if let Err(cleanup) = fs::remove_file(&canonical_path) {
                litebox_util_log::warn!(
                    path:? = canonical_path, error:? = cleanup;
                    "failed to remove file after its creation failed"
                );
            }
            return Err(open_error(error));
        }
        Ok(FileHandle::from_typed::<Self>(LocalFile {
            instance_tag: self.instance_tag.clone(),
            canonical_path,
            file_type: FileType::RegularFile,
            file: Some(Arc::new(opened)),
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
        // to escape the root. Validating the target alone cannot make this path-based backend
        // safe; supporting this requires confining host access atomically.
        unimplemented!()
    }

    fn mkdir_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        validate_name(name)?;
        let dir = dir.into_typed::<Self>();
        if !self.valid_dir(&dir) {
            return Err(MkdirError::Io);
        }
        let canonical_path = dir.canonical_path.join(name);
        let builder = {
            #[cfg(unix)]
            {
                let mut builder = fs::DirBuilder::new();
                std::os::unix::fs::DirBuilderExt::mode(&mut builder, host_mode(metadata.mode));
                builder
            }
            #[cfg(windows)]
            {
                fs::DirBuilder::new()
            }
        };
        builder.create(&canonical_path).map_err(mkdir_error)?;
        #[cfg(unix)]
        log_umask_filtered_mode(
            &canonical_path,
            fs::metadata(&canonical_path),
            metadata.mode,
        );
        #[cfg(windows)]
        if let Err(error) = set_permissions_path(&canonical_path, metadata.mode) {
            if let Err(cleanup) = fs::remove_dir(&canonical_path) {
                litebox_util_log::warn!(
                    path:? = canonical_path, error:? = cleanup;
                    "failed to remove directory after its creation failed"
                );
            }
            return Err(mkdir_error(error));
        }
        Ok(DirHandle::from_typed::<Self>(LocalDir {
            instance_tag: self.instance_tag.clone(),
            canonical_path,
            file: None,
        }))
    }

    fn unlink_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), UnlinkError> {
        validate_name(name)?;
        let dir = dir.into_typed::<Self>();
        if !self.valid_dir(&dir) {
            return Err(UnlinkError::Io);
        }
        let path = dir.canonical_path.join(name);
        let metadata = fs::symlink_metadata(&path).map_err(unlink_error)?;
        let is_symlink = metadata.file_type().is_symlink();
        if metadata.is_dir() && !is_symlink {
            return Err(UnlinkError::IsADirectory);
        }
        if !metadata.is_file() && !is_symlink {
            return Err(UnlinkError::Io);
        }
        #[cfg(windows)]
        if !is_symlink && metadata.permissions().readonly() {
            // Rust's Windows remove_file implementation can override the readonly attribute.
            // Preserve host-native readonly protection; callers can clear it with chmod first.
            return Err(UnlinkError::NoWritePerms);
        }
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            #[cfg(windows)]
            Err(error) if is_symlink => fs::remove_dir(&path).map_err(|fallback| {
                litebox_util_log::debug!(
                    path:? = path, error:? = error, fallback:? = fallback;
                    "symlink removal failed as file and directory; reporting the file error"
                );
                unlink_error(error)
            }),
            Err(error) => Err(unlink_error(error)),
        }
    }

    fn rmdir_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), RmdirError> {
        validate_name(name)?;
        let dir = dir.into_typed::<Self>();
        if !self.valid_dir(&dir) {
            return Err(RmdirError::Io);
        }
        let path = dir.canonical_path.join(name);
        let metadata = fs::symlink_metadata(&path).map_err(rmdir_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RmdirError::NotADirectory);
        }
        fs::remove_dir(path).map_err(rmdir_error)
    }

    fn rename_at(
        &self,
        old_dir: DirHandle,
        old_name: &str,
        new_dir: DirHandle,
        new_name: &str,
    ) -> Result<(), RenameError> {
        validate_name(old_name)?;
        validate_name(new_name)?;
        let old_dir = old_dir.into_typed::<Self>();
        let new_dir = new_dir.into_typed::<Self>();
        if !self.valid_dir(&old_dir) || !self.valid_dir(&new_dir) {
            return Err(RenameError::Io);
        }
        let old_path = old_dir.canonical_path.join(old_name);
        let new_path = new_dir.canonical_path.join(new_name);
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

    fn set_times(
        &self,
        target: ResolvedTarget<'_>,
        times: &SetFileTimes,
    ) -> Result<(), SetTimesError> {
        let path = match &target {
            ResolvedTarget::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                if !self.valid_dir(dir) {
                    return Err(SetTimesError::Io);
                }
                &dir.canonical_path
            }
            ResolvedTarget::File(file) => {
                let file = file.get_typed::<Self>();
                if !self.valid_file(file) {
                    return Err(SetTimesError::Io);
                }
                &file.canonical_path
            }
        };
        #[cfg(target_os = "linux")]
        {
            linux::set_times(path, times)
        }
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            windows::set_times(path, times)
        }
        #[cfg(not(any(target_os = "linux", all(windows, target_arch = "x86_64"))))]
        {
            let _ = (path, times);
            Err(SetTimesError::NotSupported)
        }
    }

    fn chmod_handle(&self, h: HandleRef<'_>, mode: Mode) -> Result<(), ChmodError> {
        let file = match h {
            HandleRef::File(h) => {
                let h = h.get_typed::<Self>();
                if !self.valid_file(h) {
                    return Err(ChmodError::Io);
                }
                h.file.as_ref()
            }
            HandleRef::Dir(h) => {
                let h = h.get_typed::<Self>();
                if !self.valid_dir(h) {
                    return Err(ChmodError::Io);
                }
                h.file.as_ref()
            }
        }
        .ok_or(ChmodError::BadDescriptor)?;
        set_permissions_file(file, mode).map_err(chmod_error)
    }

    fn chmod(&self, h: ResolvedTarget<'_>, mode: Mode) -> Result<(), ChmodError> {
        #[cfg(windows)]
        litebox_util_log::debug!(
            mode:? = mode;
            "Windows chmod keeps only whether any write bit is set (the readonly attribute)"
        );
        let result = match h {
            ResolvedTarget::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                if !self.valid_dir(dir)
                    || !fs::metadata(&dir.canonical_path).is_ok_and(|metadata| metadata.is_dir())
                {
                    return Err(ChmodError::Io);
                }
                set_permissions_path(&dir.canonical_path, mode)
            }
            ResolvedTarget::File(file) => {
                let file = file.get_typed::<Self>();
                if !self.valid_file(file) {
                    return Err(ChmodError::Io);
                }
                if file.is_symlink() {
                    return Err(ChmodError::IsSymlink);
                }
                if !fs::metadata(&file.canonical_path).is_ok_and(|metadata| metadata.is_file()) {
                    return Err(ChmodError::Io);
                }
                set_permissions_path(&file.canonical_path, mode)
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
        let (path, file_type) = match &h {
            ResolvedTarget::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                if !self.valid_dir(dir) {
                    return Err(ChownError::Io);
                }
                (&dir.canonical_path, FileType::Directory)
            }
            ResolvedTarget::File(file) => {
                let file = file.get_typed::<Self>();
                if !self.valid_file(file) {
                    return Err(ChownError::Io);
                }
                if file.is_symlink() {
                    return Err(ChownError::IsSymlink);
                }
                (&file.canonical_path, FileType::RegularFile)
            }
        };
        let metadata = fs::metadata(path).map_err(|_| ChownError::Io)?;
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
