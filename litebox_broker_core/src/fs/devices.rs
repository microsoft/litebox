// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-y devices [`super::backend::Backend`].
//!
//! Provides `{stdin,stdout,tty,null,urandom,...}` entries, intended to be mounted at `/dev`, and
//! pseudo-terminals: opening `ptmx` creates a pair and opens its manager, and `pts/<index>` names
//! each pair's subsidiary. The constructor's caller can add symbolic links, such as a guest's
//! conventional links into another mount.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use super::backend::{
    Backend, BackendHandles, CreationMetadata, DirHandle, FileHandle, FileTerminal, HandleRef,
    PermissionCheck, PermissionInfo, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget,
    SeekBehavior,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RenameError, ResolutionError, RmdirError, SymlinkError, TruncateError, UnlinkError,
    WalkError, WriteError,
};
use super::inode_allocator::InodeAllocator;
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, UserInfo};
use crate::pseudo_terminal::{ManagerFile, PseudoTerminal, PseudoTerminals, SubsidiaryFile};
use crate::random::RandomProvider;
use crate::readiness::{ReadinessRegistration, ReadinessSource};
use crate::stdio::{StdioOutputStream, StdioProvider, StdioProviderError, StdioStream};
use crate::terminal::TerminalEndpoint;
use crate::transfer::bounce_buffer;

/// Block size for stdio devices and /dev/tty
const STDIO_BLOCK_SIZE: u64 = 1024;
/// Block size for null device
const NULL_BLOCK_SIZE: u64 = 0x1000;
/// Block size for /dev/urandom
const URANDOM_BLOCK_SIZE: u64 = 0x1000;

/// Device number for all 3 stdio devices.
const STDIO_RDEV: Option<core::num::NonZeroU64> = core::num::NonZeroU64::new(34822);
/// Device number for /dev/tty (major=5, minor=0).
const TTY_RDEV: Option<core::num::NonZeroU64> = core::num::NonZeroU64::new(0x500);
/// Device number for /dev/null (major=1, minor=3).
const NULL_RDEV: Option<core::num::NonZeroU64> = core::num::NonZeroU64::new(0x103);
/// Device number for /dev/urandom (major=1, minor=9).
const URANDOM_RDEV: Option<core::num::NonZeroU64> = core::num::NonZeroU64::new(0x109);
/// Device number for /dev/ptmx (major=5, minor=2).
const PTMX_RDEV: Option<core::num::NonZeroU64> = core::num::NonZeroU64::new(0x502);

/// Name of the directory of pseudo-terminal subsidiaries.
const PTS_DIR_NAME: &str = "pts";
/// Major device number of pseudo-terminal subsidiaries, whose minors are their indices.
const PTS_MAJOR: u64 = 136;

/// The device number of the subsidiary with index `index`, encoded as `makedev` does.
fn pts_rdev(index: u32) -> core::num::NonZeroU64 {
    let minor = u64::from(index);
    core::num::NonZeroU64::new((minor & 0xff) | (PTS_MAJOR << 8) | ((minor & !0xff) << 12))
        .expect("the major number is nonzero")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Device {
    Stdin,
    Stdout,
    Stderr,
    Tty,
    Null,
    URandom,
    /// Creates a pseudo-terminal pair when opened, other than by path.
    Ptmx,
}

impl Device {
    const ALL: &'static [(&'static str, Device)] = &[
        ("stdin", Device::Stdin),
        ("stdout", Device::Stdout),
        ("stderr", Device::Stderr),
        ("tty", Device::Tty),
        ("null", Device::Null),
        ("urandom", Device::URandom),
        ("ptmx", Device::Ptmx),
    ];

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().find(|(n, _)| *n == name).map(|(_, d)| *d)
    }

    fn stdio_stream(self) -> Option<StdioStream> {
        match self {
            Device::Stdin => Some(StdioStream::Stdin),
            Device::Stdout => Some(StdioStream::Stdout),
            Device::Stderr => Some(StdioStream::Stderr),
            Device::Tty | Device::Null | Device::URandom | Device::Ptmx => None,
        }
    }

    fn file_status(self, devices: &Devices) -> FileStatus {
        match self {
            Device::Stdin | Device::Stdout | Device::Stderr => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
                size: 0,
                owner: UserInfo::ROOT,
                times: None,
                node_info: devices.stdio_inode,
                blksize: STDIO_BLOCK_SIZE,
            },
            Device::Tty => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                times: None,
                node_info: devices.tty_inode,
                blksize: STDIO_BLOCK_SIZE,
            },
            Device::Null => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                times: None,
                node_info: devices.null_inode,
                blksize: NULL_BLOCK_SIZE,
            },
            Device::URandom => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                times: None,
                node_info: devices.urandom_inode,
                blksize: URANDOM_BLOCK_SIZE,
            },
            Device::Ptmx => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                times: None,
                node_info: devices.ptmx_inode,
                blksize: STDIO_BLOCK_SIZE,
            },
        }
    }
}

/// A [`super::backend::Backend`] that supports Unix-y devices.
pub struct Devices {
    /// Stable inode info for this backend's root directory.
    root_inode: NodeInfo,
    /// Stable inode info for the `pts` directory.
    pts_inode: NodeInfo,
    /// Stable inode info shared by `stdin`, `stdout`, and `stderr`.
    stdio_inode: NodeInfo,
    /// Stable inode info for `tty`.
    tty_inode: NodeInfo,
    /// Stable inode info for `null`.
    null_inode: NodeInfo,
    /// Stable inode info for `urandom`.
    urandom_inode: NodeInfo,
    /// Stable inode info for `ptmx`.
    ptmx_inode: NodeInfo,
    /// Symbolic links in the root directory, which the constructor's caller chose.
    links: Vec<DeviceLink>,
    /// Inode number of the subsidiary with index zero; later indices follow it.
    first_pts_ino: u64,
    /// Host standard streams behind `stdin`, `stdout`, and `stderr`.
    stdio: Arc<dyn StdioProvider>,
    /// Randomness behind `urandom`.
    random: Arc<dyn RandomProvider>,
    /// Pseudo-terminal pairs that `ptmx` created.
    pseudo_terminals: PseudoTerminals,
    /// Allocated the directories' and devices' inodes. It must allocate no more,
    /// since subsidiaries' inode numbers start at `first_pts_ino`.
    _alloc: InodeAllocator,
}

/// A symbolic link in the root directory.
struct DeviceLink {
    name: String,
    target: String,
    node_info: NodeInfo,
}

impl Devices {
    /// Construct a new `Devices` backend over the given providers.
    #[must_use]
    pub fn new(
        allocator: InodeAllocator,
        stdio: Arc<dyn StdioProvider>,
        random: Arc<dyn RandomProvider>,
    ) -> Self {
        Self::with_links(allocator, stdio, random, Vec::new())
    }

    /// Construct a new `Devices` backend over the given providers, whose root directory also has
    /// each `(name, target)` of `links` as a symbolic link named `name` to `target`.
    ///
    /// # Panics
    ///
    /// Panics if a name is empty, contains `/`, or names another entry.
    #[must_use]
    pub fn with_links(
        allocator: InodeAllocator,
        stdio: Arc<dyn StdioProvider>,
        random: Arc<dyn RandomProvider>,
        links: Vec<(String, String)>,
    ) -> Self {
        let root_inode = allocator.next();
        let pts_inode = allocator.next();
        let stdio_inode = NodeInfo {
            rdev: STDIO_RDEV,
            ..allocator.next()
        };
        let tty_inode = NodeInfo {
            rdev: TTY_RDEV,
            ..allocator.next()
        };
        let null_inode = NodeInfo {
            rdev: NULL_RDEV,
            ..allocator.next()
        };
        let urandom_inode = NodeInfo {
            rdev: URANDOM_RDEV,
            ..allocator.next()
        };
        let ptmx_inode = NodeInfo {
            rdev: PTMX_RDEV,
            ..allocator.next()
        };
        let mut device_links: Vec<DeviceLink> = Vec::new();
        for (name, target) in links {
            assert!(
                !name.is_empty()
                    && !name.contains('/')
                    && name != PTS_DIR_NAME
                    && Device::from_name(&name).is_none()
                    && device_links.iter().all(|link| link.name != name),
                "invalid device link name {name:?}"
            );
            device_links.push(DeviceLink {
                name,
                target,
                node_info: allocator.next(),
            });
        }
        let first_pts_ino = allocator.next().ino;
        Self {
            root_inode,
            pts_inode,
            stdio_inode,
            tty_inode,
            null_inode,
            urandom_inode,
            ptmx_inode,
            links: device_links,
            first_pts_ino,
            stdio,
            random,
            pseudo_terminals: PseudoTerminals::new(),
            _alloc: allocator,
        }
    }

    /// The pair whose subsidiary `name` names, while its manager is open.
    fn pseudo_terminal(&self, name: &str) -> Option<Arc<PseudoTerminal>> {
        self.pseudo_terminals.get(super::canonical_decimal(name)?)
    }

    fn subsidiary_status(&self, index: u32) -> FileStatus {
        FileStatus {
            file_type: FileType::CharacterDevice,
            mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
            size: 0,
            owner: UserInfo::ROOT,
            times: None,
            node_info: NodeInfo {
                dev: self.pts_inode.dev,
                ino: self.first_pts_ino + u64::from(index),
                rdev: Some(pts_rdev(index)),
            },
            blksize: STDIO_BLOCK_SIZE,
        }
    }

    fn link(&self, name: &str) -> Option<usize> {
        self.links.iter().position(|link| link.name == name)
    }

    fn link_status(&self, index: usize) -> FileStatus {
        let link = &self.links[index];
        FileStatus {
            file_type: FileType::SymbolicLink,
            mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
            size: link.target.len() as u64,
            owner: UserInfo::ROOT,
            times: None,
            node_info: link.node_info,
            blksize: 0,
        }
    }

    /// Terminal endpoint behind `device`, through which its I/O goes.
    fn endpoint(&self, device: Device) -> Option<Arc<dyn TerminalEndpoint>> {
        if !self.stdio.is_terminal(device.stdio_stream()?) {
            return None;
        }
        self.stdio.terminal()
    }
}

/// Readiness of one standard stream, for files open on its device.
struct StdioReadiness {
    stdio: Arc<dyn StdioProvider>,
    stream: StdioStream,
}

impl ReadinessSource for StdioReadiness {
    fn readiness(&self) -> ReadinessFlags {
        self.stdio.readiness(self.stream)
    }

    fn watch(&self, registration: &ReadinessRegistration) -> crate::Result<()> {
        self.stdio.watch(self.stream, registration)
    }
}

/// Resolved device, without opening it or creating a pseudo-terminal pair.
pub struct DeviceResolvedFile(DeviceResolvedTarget);

enum DeviceResolvedTarget {
    Device(Device),
    Link(usize),
    Subsidiary {
        index: u32,
        pair: Arc<PseudoTerminal>,
    },
}

/// Owned file handle; identifies which device backs this fd.
#[derive(Clone)]
pub struct DeviceFileHandle(DeviceFile);

#[derive(Clone)]
enum DeviceFile {
    Device(Device),
    /// The link with this index, opened path-only without following it.
    Link(usize),
    /// The manager of a pair that opening `ptmx` created.
    Manager(Arc<ManagerFile>),
    /// The subsidiary named by `index`, open unless `file` is `None`, for a
    /// path-only handle.
    Subsidiary {
        index: u32,
        file: Option<Arc<SubsidiaryFile>>,
    },
}

impl DeviceFile {
    fn terminal(&self) -> Option<Arc<dyn TerminalEndpoint>> {
        match self {
            DeviceFile::Device(_) | DeviceFile::Link(_) => None,
            DeviceFile::Manager(file) => Some(file.endpoint().clone()),
            DeviceFile::Subsidiary { file, .. } => file
                .as_ref()
                .map(|file| file.endpoint().clone() as Arc<dyn TerminalEndpoint>),
        }
    }
}

/// Directory handle
// For devices, since no borrows are needed, we reuse this type for both the walking handles as
// well as the dir handles.
#[derive(Debug, Clone, Copy)]
pub enum DeviceDirHandle {
    /// The backend's root.
    Root,
    /// The directory of pseudo-terminal subsidiaries.
    Pts,
}

impl BackendHandles for Devices {
    type ResolvedDir<'a> = DeviceDirHandle;
    type ResolvedFile<'a> = DeviceResolvedFile;
    type FileHandle = DeviceFileHandle;
    type DirHandle = DeviceDirHandle;
}

impl Backend for Devices {
    fn terminal(&self, h: &FileHandle) -> Option<FileTerminal> {
        match &h.get_typed::<Self>().0 {
            DeviceFile::Device(Device::Tty) => Some(FileTerminal::OpenersControlling),
            DeviceFile::Device(device) => self.endpoint(*device).map(FileTerminal::Fixed),
            file => file.terminal().map(FileTerminal::Fixed),
        }
    }

    fn root_with_context(
        &self,
        _context: &super::backend::LookupContext,
    ) -> Result<ResolvedDir<'_>, WalkError> {
        Ok(ResolvedDir::from_typed::<Self>(
            DeviceDirHandle::Root,
            PermissionCheck::ByBackend,
        ))
    }

    fn resolve_with_context<'a>(
        &'a self,
        _context: &super::backend::LookupContext,
        from: ResolvedDir<'a>,
        components: &[&str],
        _authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        if components.is_empty() {
            return Ok(Resolution::Found(ResolvedTarget::Dir(from)));
        }
        let mut dir = from.into_typed::<Self>();
        for (index, &component) in components.iter().enumerate() {
            let target = match dir {
                DeviceDirHandle::Root if component == PTS_DIR_NAME => {
                    dir = DeviceDirHandle::Pts;
                    continue;
                }
                DeviceDirHandle::Root => Device::from_name(component)
                    .map(DeviceResolvedTarget::Device)
                    .or_else(|| self.link(component).map(DeviceResolvedTarget::Link)),
                DeviceDirHandle::Pts => {
                    self.pseudo_terminal(component)
                        .map(|pair| DeviceResolvedTarget::Subsidiary {
                            index: super::canonical_decimal(component).unwrap(),
                            pair,
                        })
                }
            };
            match target {
                Some(target) if index + 1 == components.len() => {
                    let file_type = match target {
                        DeviceResolvedTarget::Link(_) => FileType::SymbolicLink,
                        _ => FileType::CharacterDevice,
                    };
                    return Ok(Resolution::Found(ResolvedTarget::File(
                        ResolvedFile::from_typed::<Self>(
                            DeviceResolvedFile(target),
                            PermissionCheck::ByBackend,
                            file_type,
                        ),
                    )));
                }
                Some(_) => {
                    return Err(ResolutionError {
                        component: Some(index + 1),
                        error: PathError::ComponentNotADirectory.into(),
                    });
                }
                None if index + 1 == components.len() => {
                    return Ok(Resolution::MissingFinal {
                        parent: ResolvedDir::from_typed::<Self>(dir, PermissionCheck::ByBackend),
                    });
                }
                None => {
                    return Err(ResolutionError {
                        component: Some(index),
                        error: PathError::NoSuchFileOrDirectory.into(),
                    });
                }
            }
        }
        Ok(Resolution::Found(ResolvedTarget::Dir(
            ResolvedDir::from_typed::<Self>(dir, PermissionCheck::ByBackend),
        )))
    }

    fn read_link_at_with_context(
        &self,
        _context: &super::backend::LookupContext,
        dir: &ResolvedDir<'_>,
        name: &str,
    ) -> Result<String, WalkError> {
        match dir.get_typed::<Self>() {
            DeviceDirHandle::Root => self
                .link(name)
                .map(|index| self.links[index].target.clone())
                .ok_or_else(|| PathError::InvalidPathname.into()),
            DeviceDirHandle::Pts => Err(PathError::InvalidPathname.into()),
        }
    }

    fn open_dir(&self, dir: ResolvedDir<'_>, _flags: OFlags) -> Result<DirHandle, OpenError> {
        Ok(DirHandle::from_typed::<Self>(dir.into_typed::<Self>()))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<ResolvedDir<'a>> {
        Some(ResolvedDir::from_typed::<Self>(
            *dir.get_typed::<Self>(),
            PermissionCheck::ByBackend,
        ))
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        let DeviceResolvedFile(target) = file.into_typed::<Self>();
        if flags.contains(OFlags::DIRECTORY) {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }
        let path_only = flags.contains(OFlags::PATH);
        let file = match target {
            // The resolver follows links before opening, unless asked to open the link itself.
            DeviceResolvedTarget::Link(_) if !flags.contains(OFlags::PATH | OFlags::NOFOLLOW) => {
                return Err(PathError::TooManySymlinks.into());
            }
            DeviceResolvedTarget::Link(index) => DeviceFile::Link(index),
            DeviceResolvedTarget::Device(Device::Ptmx) if !path_only => {
                DeviceFile::Manager(Arc::new(self.pseudo_terminals.open_manager()?))
            }
            DeviceResolvedTarget::Device(device) => DeviceFile::Device(device),
            DeviceResolvedTarget::Subsidiary { index, pair } => {
                let file = if path_only {
                    None
                } else {
                    Some(Arc::new(pair.open_subsidiary()?))
                };
                DeviceFile::Subsidiary { index, file }
            }
        };
        let item = FileHandle::from_typed::<Self>(DeviceFileHandle(file));

        if flags.contains(OFlags::TRUNC) {
            // Note: matching Linux behavior, this does not actually perform any truncation, and
            // instead, it is silently ignored if you attempt to truncate upon opening a device.
            debug_assert!(matches!(
                self.truncate(&item, 0),
                Err(TruncateError::IsTerminalDevice)
            ));
        }

        Ok(item)
    }

    fn reopen_file(&self, file: &FileHandle, flags: OFlags) -> Result<FileHandle, OpenError> {
        let path_only = flags.contains(OFlags::PATH);
        // Per-open terminal state starts afresh, as when opening the device by name.
        let file = match &file.get_typed::<Self>().0 {
            DeviceFile::Link(_) if !path_only => {
                return Err(PathError::TooManySymlinks.into());
            }
            DeviceFile::Device(Device::Ptmx) | DeviceFile::Manager(_) if path_only => {
                DeviceFile::Device(Device::Ptmx)
            }
            DeviceFile::Device(Device::Ptmx) | DeviceFile::Manager(_) => {
                DeviceFile::Manager(Arc::new(self.pseudo_terminals.open_manager()?))
            }
            &DeviceFile::Subsidiary { index, .. } if path_only => {
                DeviceFile::Subsidiary { index, file: None }
            }
            &DeviceFile::Subsidiary { index, ref file } => {
                let pair = match file {
                    Some(file) => Arc::clone(file.endpoint()),
                    None => self
                        .pseudo_terminals
                        .get(index)
                        .ok_or(PathError::NoSuchFileOrDirectory)?,
                };
                DeviceFile::Subsidiary {
                    index,
                    file: Some(Arc::new(pair.open_subsidiary()?)),
                }
            }
            file @ (DeviceFile::Device(_) | DeviceFile::Link(_)) => file.clone(),
        };
        Ok(FileHandle::from_typed::<Self>(DeviceFileHandle(file)))
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        Ok(match handle.into_typed::<Self>() {
            DeviceDirHandle::Root => Device::ALL
                .iter()
                .map(|(n, d)| DirEntry {
                    name: String::from(*n),
                    file_type: FileType::CharacterDevice,
                    ino_info: Some(d.file_status(self).node_info),
                })
                .chain([DirEntry {
                    name: String::from(PTS_DIR_NAME),
                    file_type: FileType::Directory,
                    ino_info: Some(self.pts_inode),
                }])
                .chain(self.links.iter().map(|link| DirEntry {
                    name: link.name.clone(),
                    file_type: FileType::SymbolicLink,
                    ino_info: Some(link.node_info),
                }))
                .collect(),
            DeviceDirHandle::Pts => self
                .pseudo_terminals
                .indices()
                .into_iter()
                .map(|index| DirEntry {
                    name: index.to_string(),
                    file_type: FileType::CharacterDevice,
                    ino_info: Some(self.subsidiary_status(index).node_info),
                })
                .collect(),
        })
    }

    fn read(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        _offset: usize,
    ) -> Result<usize, ReadError> {
        let device = match &h.get_typed::<Self>().0 {
            DeviceFile::Device(device) => *device,
            DeviceFile::Link(_) => return Err(ReadError::NotForReading),
            file => return file.terminal().ok_or(ReadError::Io)?.read(buf),
        };
        match device {
            // Opening `ptmx` yields a manager, so only `O_PATH` handles, which the resolver bars
            // from I/O, hold `Ptmx`. The resolver routes I/O through a `tty` handle to the
            // opener's controlling terminal.
            Device::Ptmx | Device::Tty => Err(ReadError::Io),
            Device::Stdout | Device::Stderr => Err(ReadError::NotForReading),
            Device::Null => Ok(0),
            Device::Stdin if buf.is_empty() => Ok(0),
            Device::Stdin => match self.endpoint(device) {
                Some(terminal) => terminal.read(buf),
                None => self.stdio.read(buf).map_err(|error| match error {
                    StdioProviderError::WouldBlock => ReadError::WouldBlock,
                    StdioProviderError::Broker(error) => ReadError::Broker(error),
                    _ => ReadError::Io,
                }),
            },
            Device::URandom => {
                let mut bytes = bounce_buffer(buf.len())?;
                self.random.fill(&mut bytes).map_err(|_| ReadError::Io)?;
                buf.copy_from_slice_at(0, &bytes)?;
                Ok(bytes.len())
            }
        }
    }

    fn write(
        &self,
        h: &FileHandle,
        buf: &dyn WriteBuffer,
        _offset: usize,
    ) -> Result<usize, WriteError> {
        let device = match &h.get_typed::<Self>().0 {
            DeviceFile::Device(device) => *device,
            DeviceFile::Link(_) => return Err(WriteError::NotForWriting),
            file => return file.terminal().ok_or(WriteError::Io)?.write(buf),
        };
        match device {
            // See `read`.
            Device::Ptmx | Device::Tty => return Err(WriteError::Io),
            Device::Stdin => return Err(WriteError::NotForWriting),
            Device::Null | Device::URandom => return Ok(buf.len()),
            Device::Stdout | Device::Stderr if buf.is_empty() => return Ok(0),
            Device::Stdout | Device::Stderr => {}
        }
        if let Some(terminal) = self.endpoint(device) {
            return terminal.write(buf);
        }
        let stream = match device {
            Device::Stdout => StdioOutputStream::Stdout,
            Device::Stderr => StdioOutputStream::Stderr,
            _ => return Err(WriteError::Io),
        };
        self.stdio.write(stream, buf).map_err(|error| match error {
            StdioProviderError::WouldBlock => WriteError::WouldBlock,
            StdioProviderError::Broker(error) => WriteError::Broker(error),
            _ => WriteError::Io,
        })
    }

    fn truncate(&self, _h: &FileHandle, _len: usize) -> Result<(), TruncateError> {
        Err(TruncateError::IsTerminalDevice)
    }

    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior {
        match h.get_typed::<Self>().0 {
            DeviceFile::Device(Device::Null | Device::URandom) => SeekBehavior::ZeroPosition,
            DeviceFile::Device(
                Device::Stdin | Device::Stdout | Device::Stderr | Device::Tty | Device::Ptmx,
            )
            | DeviceFile::Link(_)
            | DeviceFile::Manager(_)
            | DeviceFile::Subsidiary { .. } => SeekBehavior::NonSeekable,
        }
    }

    fn readiness_source(&self, h: &FileHandle) -> Option<Arc<dyn ReadinessSource>> {
        let device = match &h.get_typed::<Self>().0 {
            DeviceFile::Device(device) => *device,
            DeviceFile::Link(_) => return None,
            file => {
                return file
                    .terminal()
                    .map(|terminal| terminal as Arc<dyn ReadinessSource>);
            }
        };
        if let Some(terminal) = self.endpoint(device) {
            return Some(terminal);
        }
        let stream = device.stdio_stream()?;
        Some(Arc::new(StdioReadiness {
            stdio: Arc::clone(&self.stdio),
            stream,
        }))
    }

    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        match h {
            HandleRef::File(h) => Ok(match &h.get_typed::<Self>().0 {
                DeviceFile::Device(device) => device.file_status(self),
                DeviceFile::Link(index) => self.link_status(*index),
                DeviceFile::Manager(_) => Device::Ptmx.file_status(self),
                DeviceFile::Subsidiary { index, .. } => self.subsidiary_status(*index),
            }),
            HandleRef::Dir(h) => Ok(FileStatus {
                file_type: FileType::Directory,
                mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                size: super::DEFAULT_DIRECTORY_SIZE,
                owner: UserInfo::ROOT,
                times: None,
                node_info: match h.get_typed::<Self>() {
                    DeviceDirHandle::Root => self.root_inode,
                    DeviceDirHandle::Pts => self.pts_inode,
                },
                blksize: super::DEFAULT_DIRECTORY_SIZE,
            }),
        }
    }

    fn resolved_status(&self, target: &ResolvedTarget<'_>) -> Result<FileStatus, FileStatusError> {
        match target {
            ResolvedTarget::File(h) => Ok(match &h.get_typed::<Self>().0 {
                DeviceResolvedTarget::Device(device) => device.file_status(self),
                DeviceResolvedTarget::Link(index) => self.link_status(*index),
                DeviceResolvedTarget::Subsidiary { index, .. } => self.subsidiary_status(*index),
            }),
            ResolvedTarget::Dir(h) => self.status(HandleRef::Dir(&DirHandle::from_typed::<Self>(
                *h.get_typed::<Self>(),
            ))),
        }
    }

    fn create_file_at(
        &self,
        _dir: ResolvedDir<'_>,
        _name: &str,
        _metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        Err(OpenError::ReadOnlyFileSystem)
    }

    fn symlink_at(
        &self,
        _dir: ResolvedDir<'_>,
        _name: &str,
        _target: &str,
        _metadata: CreationMetadata,
    ) -> Result<(), SymlinkError> {
        Err(SymlinkError::ReadOnlyFileSystem)
    }

    fn mkdir_at(
        &self,
        _dir: ResolvedDir<'_>,
        _name: &str,
        _metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn unlink_at(&self, _dir: ResolvedDir<'_>, _name: &str) -> Result<(), UnlinkError> {
        Err(UnlinkError::ReadOnlyFileSystem)
    }

    fn rename_at(
        &self,
        _old_dir: DirHandle,
        _old_name: &str,
        _new_dir: DirHandle,
        _new_name: &str,
    ) -> Result<(), RenameError> {
        Err(RenameError::ReadOnlyFileSystem)
    }

    fn rmdir_at(&self, _dir: ResolvedDir<'_>, _name: &str) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn set_times(
        &self,
        _target: ResolvedTarget<'_>,
        _times: &super::SetFileTimes,
    ) -> Result<(), super::errors::SetTimesError> {
        Ok(())
    }

    fn chmod(&self, _h: ResolvedTarget<'_>, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chown(
        &self,
        _h: ResolvedTarget<'_>,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        Err(ChownError::ReadOnlyFileSystem)
    }
}
