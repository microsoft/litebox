// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Live host filesystem access rooted at a canonical host directory.
//!
//! This backend assumes the host namespace is trusted not to race its checks. Guest-supplied path
//! components are validated, every resolved object is canonicalized, and the result must remain
//! below the configured root. Existing host symlinks are followed only when their canonical target
//! remains below that root. Regular files and directories are exposed live and host access checks
//! use the broker process's own credentials.
//!
//! The root is intentionally path-based rather than pinned by a directory handle. A concurrent
//! host rename, replacement, or symlink swap can therefore invalidate a check or redirect a later
//! operation. Directory and `O_PATH` handles are pathname locators: deleting and recreating their
//! path retargets them. This tradeoff keeps the implementation portable and mostly
//! platform-neutral; it is suitable only when host namespace administration is trusted. On
//! Windows, std's native deletion can remain pending while an ordinary file handle is open, so the
//! same name may not be reusable until retained handles close.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

mod io_errors;

#[cfg(unix)]
use io_errors::chown_error;
use io_errors::{
    chmod_error, invalid_path, mkdir_error, open_error, rmdir_error, unlink_error,
    unsupported_object, walk_error,
};

use litebox_broker_core::fs::backend::{
    Backend, BackendHandles, CreationMetadata, DirHandle, FileHandle, HandleRef, PermissionCheck,
    Permissioned, SeekBehavior, WalkOutcome, WalkStopReason, WalkedComponent, WalkingDirHandle,
};
use litebox_broker_core::fs::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, TruncateError, UnlinkError, WalkError, WriteError,
};
use litebox_broker_core::fs::inode_allocator::InodeAllocator;
use litebox_broker_core::fs::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, UserInfo};

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
    requested_name_was_symlink: bool,
}

/// Regular-file handle owned by [`LocalFs`].
#[derive(Clone)]
pub struct LocalFile {
    instance_tag: BackendInstanceTag,
    canonical_path: PathBuf,
    file: Option<Arc<File>>,
    readable: bool,
    writable: bool,
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
    requested_name_was_symlink: bool,
}

impl BackendHandles for LocalFs {
    type WalkingDirHandle<'a> = LocalDir;
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
        let _ = metadata;
        HostIdentity {
            canonical_path: canonical_path.to_owned(),
        }
    }
}

fn status_from_metadata(
    metadata: &fs::Metadata,
    node_info: NodeInfo,
) -> std::io::Result<FileStatus> {
    let file_type = if metadata.is_file() {
        FileType::RegularFile
    } else if metadata.is_dir() {
        FileType::Directory
    } else {
        return Err(unsupported_object());
    };
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
    })
}

#[cfg(windows)]
fn readonly_for_mode(mode: Mode) -> bool {
    !mode.intersects(Mode::WUSR | Mode::WGRP | Mode::WOTH)
}

fn set_permissions_path(path: &Path, mode: Mode) -> std::io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    #[cfg(unix)]
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, host_mode(mode));
    #[cfg(windows)]
    permissions.set_readonly(readonly_for_mode(mode));
    fs::set_permissions(path, permissions)
}

fn set_permissions_file(file: &File, mode: Mode) -> std::io::Result<()> {
    let mut permissions = file.metadata()?.permissions();
    #[cfg(unix)]
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, host_mode(mode));
    #[cfg(windows)]
    permissions.set_readonly(readonly_for_mode(mode));
    file.set_permissions(permissions)
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
            requested_name_was_symlink: false,
        }
    }

    fn ensure_beneath_root(&self, path: PathBuf) -> std::io::Result<PathBuf> {
        let relative = path.strip_prefix(&self.root).map_err(|_| invalid_path())?;
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(invalid_path());
            };
            validate_name(name.to_str().ok_or_else(invalid_path)?).map_err(|_| invalid_path())?;
        }
        Ok(path)
    }

    fn locate(&self, parent: &LocalDir, name: &str) -> std::io::Result<Located> {
        validate_name(name).map_err(|_| invalid_path())?;
        let candidate = parent.canonical_path.join(name);
        let requested_name_was_symlink = fs::symlink_metadata(&candidate)?.file_type().is_symlink();
        // Resolve once through the guest-visible spelling so the host performs native search
        // permission checks for every symlink target component (including `dir/..`). The trusted
        // host assumption lets the subsequent canonicalization reuse that result safely.
        let metadata = fs::metadata(&candidate)?;
        let canonical_path = self.ensure_beneath_root(fs::canonicalize(candidate)?)?;
        let file_type = if metadata.is_file() {
            FileType::RegularFile
        } else if metadata.is_dir() {
            FileType::Directory
        } else {
            return Err(unsupported_object());
        };
        Ok(Located {
            canonical_path,
            file_type,
            requested_name_was_symlink,
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
        let metadata = fs::metadata(path)?;
        let actual = if metadata.is_file() {
            FileType::RegularFile
        } else if metadata.is_dir() {
            FileType::Directory
        } else {
            return Err(unsupported_object());
        };
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
    fn root(&self) -> WalkingDirHandle<'_> {
        WalkingDirHandle::from_typed::<Self>(self.root_dir())
    }

    fn walk_directories<'a>(
        &'a self,
        from: WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<WalkOutcome<WalkingDirHandle<'a>>, WalkError> {
        let mut dir = from.into_typed::<Self>();
        if !self.valid_dir(&dir) {
            return Err(WalkError::Io);
        }
        let mut walked = Vec::with_capacity(components.len());
        for &name in components {
            let Located {
                canonical_path,
                file_type,
                requested_name_was_symlink,
            } = self.locate(&dir, name).map_err(walk_error)?;
            if file_type == FileType::Directory {
                dir = LocalDir {
                    instance_tag: self.instance_tag.clone(),
                    canonical_path,
                    requested_name_was_symlink,
                };
                walked.push(WalkedComponent {
                    permissions: PermissionCheck::ByBackend,
                });
            } else {
                return Ok(WalkOutcome {
                    components: walked,
                    last: WalkingDirHandle::from_typed::<Self>(dir),
                    stop_reason: WalkStopReason::StoppedAtNonDirectory,
                });
            }
        }
        Ok(WalkOutcome {
            components: walked,
            last: WalkingDirHandle::from_typed::<Self>(dir),
            stop_reason: WalkStopReason::CompleteDirectory,
        })
    }

    fn owned_dir_at(
        &self,
        dir: WalkingDirHandle<'_>,
        flags: OFlags,
    ) -> Result<DirHandle, OpenError> {
        check_flags(flags)?;
        let dir = dir.into_typed::<Self>();
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
        if dir.requested_name_was_symlink && flags.contains(OFlags::NOFOLLOW) {
            // This flag persists on opened handles, so reopening one with `O_NOFOLLOW` and no
            // further components is rejected too.
            litebox_util_log::debug!(
                path:? = dir.canonical_path;
                "rejecting O_NOFOLLOW directory symlink as InvalidPathname where Linux would return ELOOP"
            );
            return Err(PathError::InvalidPathname.into());
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
                    "accepting writable directory open without host permission check"
                );
            } else {
                // std has no portable open-directory-for-reading call, so a listing probes the
                // host's read permission.
                let _ = fs::read_dir(&dir.canonical_path).map_err(open_error)?;
            }
        }
        Ok(DirHandle::from_typed::<Self>(dir))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<WalkingDirHandle<'a>> {
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
        Some(WalkingDirHandle::from_typed::<Self>(dir.clone()))
    }

    fn open_file_at(
        &self,
        dir: WalkingDirHandle<'_>,
        name: &str,
        flags: OFlags,
    ) -> Result<Permissioned<FileHandle>, OpenError> {
        check_flags(flags)?;
        let dir = dir.into_typed::<Self>();
        if !self.valid_dir(&dir) {
            return Err(OpenError::Io);
        }
        let Located {
            canonical_path,
            file_type,
            requested_name_was_symlink,
        } = self.locate(&dir, name).map_err(open_error)?;
        if requested_name_was_symlink && flags.contains(OFlags::NOFOLLOW) {
            litebox_util_log::debug!(
                path:? = canonical_path;
                "rejecting O_NOFOLLOW file symlink as InvalidPathname where Linux would return ELOOP"
            );
            return Err(PathError::InvalidPathname.into());
        }
        if flags.contains(OFlags::CREAT | OFlags::EXCL) {
            return Err(OpenError::AlreadyExists);
        }
        if file_type != FileType::RegularFile || flags.contains(OFlags::DIRECTORY) {
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
            None
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
        Ok(Permissioned {
            item: FileHandle::from_typed::<Self>(LocalFile {
                instance_tag: self.instance_tag.clone(),
                canonical_path,
                file,
                readable,
                writable,
            }),
            permissions: PermissionCheck::ByBackend,
        })
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
            // `DirEntry::metadata` does not follow symlinks. Symlinks stay unlisted even when
            // lookups would follow them inside the root.
            if metadata.file_type().is_symlink() {
                continue;
            }
            let file_type = if metadata.is_file() {
                FileType::RegularFile
            } else if metadata.is_dir() {
                FileType::Directory
            } else {
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

    fn read(&self, h: &FileHandle, buf: &mut [u8], offset: usize) -> Result<usize, ReadError> {
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
        let result = {
            #[cfg(unix)]
            {
                std::os::unix::fs::FileExt::read_at(&**file, buf, offset)
            }
            #[cfg(windows)]
            {
                std::os::windows::fs::FileExt::seek_read(&**file, buf, offset)
            }
        };
        result.map_err(|_| ReadError::Io)
    }

    fn write(&self, h: &FileHandle, buf: &[u8], offset: usize) -> Result<usize, WriteError> {
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
        let result = {
            #[cfg(unix)]
            {
                std::os::unix::fs::FileExt::write_at(&**file, buf, offset)
            }
            #[cfg(windows)]
            {
                std::os::windows::fs::FileExt::seek_write(&**file, buf, offset)
            }
        };
        result.map_err(|_| WriteError::Io)
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
                    self.status_path_of_type(&file.canonical_path, FileType::RegularFile)
                        .map_err(|_| FileStatusError::Io)
                }
            }
        }
    }

    fn create_file_at(
        &self,
        dir: DirHandle,
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
            file: Some(Arc::new(opened)),
            readable: true,
            writable: true,
        }))
    }

    fn mkdir_at(
        &self,
        dir: DirHandle,
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
            requested_name_was_symlink: false,
        }))
    }

    fn unlink_at(&self, dir: DirHandle, name: &str) -> Result<(), UnlinkError> {
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

    fn rmdir_at(&self, dir: DirHandle, name: &str) -> Result<(), RmdirError> {
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

    fn chmod(&self, h: HandleRef<'_>, mode: Mode) -> Result<(), ChmodError> {
        #[cfg(windows)]
        litebox_util_log::debug!(
            mode:? = mode;
            "Windows chmod keeps only whether any write bit is set (the readonly attribute)"
        );
        let result = match h {
            HandleRef::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                if !self.valid_dir(dir)
                    || !fs::metadata(&dir.canonical_path).is_ok_and(|metadata| metadata.is_dir())
                {
                    return Err(ChmodError::Io);
                }
                set_permissions_path(&dir.canonical_path, mode)
            }
            HandleRef::File(file) => {
                let file = file.get_typed::<Self>();
                if !self.valid_file(file) {
                    return Err(ChmodError::Io);
                }
                if let Some(open) = &file.file {
                    set_permissions_file(open, mode)
                } else {
                    if !fs::metadata(&file.canonical_path).is_ok_and(|metadata| metadata.is_file())
                    {
                        return Err(ChmodError::Io);
                    }
                    set_permissions_path(&file.canonical_path, mode)
                }
            }
        };
        result.map_err(chmod_error)
    }

    fn chown(
        &self,
        h: HandleRef<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        #[derive(Clone, Copy)]
        enum Target<'a> {
            Directory(&'a Path),
            PathFile(&'a Path),
            OpenFile(&'a File),
        }

        let target = match h {
            HandleRef::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                if !self.valid_dir(dir) {
                    return Err(ChownError::Io);
                }
                Target::Directory(&dir.canonical_path)
            }
            HandleRef::File(file) => {
                let file = file.get_typed::<Self>();
                if !self.valid_file(file) {
                    return Err(ChownError::Io);
                }
                file.file
                    .as_deref()
                    .map_or(Target::PathFile(&file.canonical_path), Target::OpenFile)
            }
        };
        let metadata = match target {
            Target::Directory(path) | Target::PathFile(path) => fs::metadata(path),
            Target::OpenFile(file) => file.metadata(),
        }
        .map_err(|_| ChownError::Io)?;
        if matches!(target, Target::Directory(_)) && !metadata.is_dir()
            || matches!(target, Target::PathFile(_)) && !metadata.is_file()
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
            let result = match target {
                Target::Directory(path) | Target::PathFile(path) => {
                    std::os::unix::fs::chown(path, user, group)
                }
                Target::OpenFile(file) => std::os::unix::fs::fchown(file, user, group),
            };
            result.map_err(chown_error)
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
