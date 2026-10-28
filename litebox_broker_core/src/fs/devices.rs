// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-y devices [`super::backend::Backend`].
//!
//! Provides `{stdin,stdout,tty,null,urandom,...}` entries, intended to be mounted at `/dev`, and
//! pseudo-terminals: opening `ptmx` creates a pair and opens its manager, and `pts/<index>` names
//! each pair's subsidiary.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use super::backend::{
    Backend, BackendHandles, CreationMetadata, DirHandle, FileHandle, FileTerminal, HandleRef,
    PermissionCheck, Permissioned, SeekBehavior, WalkOutcome, WalkStopReason, WalkedComponent,
    WalkingDirHandle,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, SymlinkError, TruncateError, UnlinkError, WalkError, WriteError,
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

/// Constant node information for all 3 stdio devices:
/// ```console
/// $ stat -L --format 'name=%-11n dev=%d ino=%i rdev=%r' /dev/stdin /dev/stdout /dev/stderr
/// name=/dev/stdin  dev=64 ino=9 rdev=34822
/// name=/dev/stdout dev=64 ino=9 rdev=34822
/// name=/dev/stderr dev=64 ino=9 rdev=34822
/// ```
// XXX(jayb): Should we be pulling the device names and such from the inode allocator?
const STDIO_NODE_INFO: NodeInfo = NodeInfo {
    dev: 64,
    ino: 9,
    rdev: core::num::NonZeroU64::new(34822),
};
/// Node info for /dev/tty
const TTY_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 12,
    // major=5, minor=0
    rdev: core::num::NonZeroU64::new(0x500),
};
/// Node info for /dev/null
const NULL_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 4,
    // major=1, minor=3
    rdev: core::num::NonZeroU64::new(0x103),
};
/// Node info for /dev/urandom
const URANDOM_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 8,
    // major=1, minor=9
    rdev: core::num::NonZeroU64::new(0x109),
};
/// Node info for /dev/ptmx
const PTMX_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 89,
    // major=5, minor=2
    rdev: core::num::NonZeroU64::new(0x502),
};

/// Name of the directory of pseudo-terminal subsidiaries.
const PTS_DIR_NAME: &str = "pts";
/// Major device number of pseudo-terminal subsidiaries, whose minors are their indices.
const PTS_MAJOR: u64 = 136;
/// Inode number of the subsidiary with index zero; later indices follow it.
const FIRST_PTS_INODE: u64 = 3;

/// The device number of the subsidiary with index `index`, encoded as `makedev` does.
fn pts_rdev(index: u32) -> core::num::NonZeroU64 {
    let minor = u64::from(index);
    core::num::NonZeroU64::new((minor & 0xff) | (PTS_MAJOR << 8) | ((minor & !0xff) << 12))
        .expect("the major number is nonzero")
}

/// The index that `name` spells in canonical decimal, if any.
fn pts_index(name: &str) -> Option<u32> {
    if !name.bytes().all(|byte| byte.is_ascii_digit()) || (name.len() > 1 && name.starts_with('0'))
    {
        return None;
    }
    name.parse().ok()
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

    fn file_status(self) -> FileStatus {
        match self {
            Device::Stdin | Device::Stdout | Device::Stderr => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: STDIO_NODE_INFO,
                blksize: STDIO_BLOCK_SIZE,
            },
            Device::Tty => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: TTY_NODE_INFO,
                blksize: STDIO_BLOCK_SIZE,
            },
            Device::Null => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: NULL_NODE_INFO,
                blksize: NULL_BLOCK_SIZE,
            },
            Device::URandom => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: URANDOM_NODE_INFO,
                blksize: URANDOM_BLOCK_SIZE,
            },
            Device::Ptmx => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: PTMX_NODE_INFO,
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
    /// Host standard streams behind `stdin`, `stdout`, and `stderr`.
    stdio: Arc<dyn StdioProvider>,
    /// Randomness behind `urandom`.
    random: Arc<dyn RandomProvider>,
    /// Pseudo-terminal pairs that `ptmx` created.
    pseudo_terminals: PseudoTerminals,
    /// Allocated the directories' inodes. It must allocate no more, since
    /// subsidiaries' inode numbers start at [`FIRST_PTS_INODE`].
    _alloc: InodeAllocator,
}

impl Devices {
    /// Construct a new `Devices` backend over the given providers.
    #[must_use]
    pub fn new(
        allocator: InodeAllocator,
        stdio: Arc<dyn StdioProvider>,
        random: Arc<dyn RandomProvider>,
    ) -> Self {
        let root_inode = allocator.next();
        let pts_inode = allocator.next();
        debug_assert_eq!(pts_inode.ino + 1, FIRST_PTS_INODE);
        Self {
            root_inode,
            pts_inode,
            stdio,
            random,
            pseudo_terminals: PseudoTerminals::new(),
            _alloc: allocator,
        }
    }

    /// The pair whose subsidiary `name` names, while its manager is open.
    fn pseudo_terminal(&self, name: &str) -> Option<Arc<PseudoTerminal>> {
        self.pseudo_terminals.get(pts_index(name)?)
    }

    fn subsidiary_status(&self, index: u32) -> FileStatus {
        FileStatus {
            file_type: FileType::CharacterDevice,
            mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
            size: 0,
            owner: UserInfo::ROOT,
            node_info: NodeInfo {
                dev: self.pts_inode.dev,
                ino: FIRST_PTS_INODE + u64::from(index),
                rdev: Some(pts_rdev(index)),
            },
            blksize: STDIO_BLOCK_SIZE,
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

/// Owned file handle; identifies which device backs this fd.
#[derive(Clone)]
pub struct DeviceFileHandle(DeviceFile);

#[derive(Clone)]
enum DeviceFile {
    Device(Device),
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
            DeviceFile::Device(_) => None,
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
    type WalkingDirHandle<'a> = DeviceDirHandle;
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

    fn root(&self) -> WalkingDirHandle<'_> {
        WalkingDirHandle::from_typed::<Self>(DeviceDirHandle::Root)
    }

    fn walk_directories<'a>(
        &'a self,
        from: WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<WalkOutcome<WalkingDirHandle<'a>>, WalkError> {
        let mut dir = from.into_typed::<Self>();
        let mut walked = vec![];
        for &component in components {
            let exists = match dir {
                DeviceDirHandle::Root if component == PTS_DIR_NAME => {
                    walked.push(WalkedComponent {
                        permissions: PermissionCheck::ByBackend,
                    });
                    dir = DeviceDirHandle::Pts;
                    continue;
                }
                DeviceDirHandle::Root => Device::from_name(component).is_some(),
                DeviceDirHandle::Pts => self.pseudo_terminal(component).is_some(),
            };
            if !exists {
                return Err(WalkError::PathError(PathError::NoSuchFileOrDirectory));
            }
            // Device files are final path targets, so directory walking must stop before them.
            return Ok(WalkOutcome {
                components: walked,
                last: WalkingDirHandle::from_typed::<Self>(dir),
                stop_reason: WalkStopReason::StoppedAtNonDirectory {
                    file_type: FileType::CharacterDevice,
                },
            });
        }
        Ok(WalkOutcome {
            components: walked,
            last: WalkingDirHandle::from_typed::<Self>(dir),
            stop_reason: WalkStopReason::CompleteDirectory,
        })
    }

    fn read_link_at(&self, _dir: &WalkingDirHandle<'_>, _name: &str) -> Result<String, WalkError> {
        Err(PathError::InvalidPathname.into())
    }

    fn owned_dir_at(
        &self,
        dir: WalkingDirHandle<'_>,
        _flags: OFlags,
    ) -> Result<DirHandle, OpenError> {
        Ok(DirHandle::from_typed::<Self>(dir.into_typed::<Self>()))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<WalkingDirHandle<'a>> {
        Some(WalkingDirHandle::from_typed::<Self>(
            *dir.get_typed::<Self>(),
        ))
    }

    fn open_file_at(
        &self,
        dir: WalkingDirHandle<'_>,
        name: &str,
        flags: OFlags,
    ) -> Result<Permissioned<FileHandle>, OpenError> {
        let not_found = || OpenError::PathError(PathError::NoSuchFileOrDirectory);
        let path_only = flags.contains(OFlags::PATH);
        let file = match dir.into_typed::<Self>() {
            DeviceDirHandle::Root => {
                let device = Device::from_name(name).ok_or_else(not_found)?;
                if flags.contains(OFlags::DIRECTORY) {
                    return Err(OpenError::PathError(PathError::ComponentNotADirectory));
                }
                if device == Device::Ptmx && !path_only {
                    DeviceFile::Manager(Arc::new(self.pseudo_terminals.open_manager()?))
                } else {
                    DeviceFile::Device(device)
                }
            }
            DeviceDirHandle::Pts => {
                let index = pts_index(name).ok_or_else(not_found)?;
                let pair = self.pseudo_terminals.get(index).ok_or_else(not_found)?;
                if flags.contains(OFlags::DIRECTORY) {
                    return Err(OpenError::PathError(PathError::ComponentNotADirectory));
                }
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

        Ok(Permissioned {
            item,
            permissions: PermissionCheck::ByBackend,
        })
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        Ok(match handle.into_typed::<Self>() {
            DeviceDirHandle::Root => Device::ALL
                .iter()
                .map(|(n, d)| DirEntry {
                    name: String::from(*n),
                    file_type: FileType::CharacterDevice,
                    ino_info: Some(d.file_status().node_info),
                })
                .chain([DirEntry {
                    name: String::from(PTS_DIR_NAME),
                    file_type: FileType::Directory,
                    ino_info: Some(self.pts_inode),
                }])
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
            | DeviceFile::Manager(_)
            | DeviceFile::Subsidiary { .. } => SeekBehavior::NonSeekable,
        }
    }

    fn readiness_source(&self, h: &FileHandle) -> Option<Arc<dyn ReadinessSource>> {
        let device = match &h.get_typed::<Self>().0 {
            DeviceFile::Device(device) => *device,
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
                DeviceFile::Device(device) => device.file_status(),
                DeviceFile::Manager(_) => Device::Ptmx.file_status(),
                DeviceFile::Subsidiary { index, .. } => self.subsidiary_status(*index),
            }),
            HandleRef::Dir(h) => Ok(FileStatus {
                file_type: FileType::Directory,
                mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                size: super::DEFAULT_DIRECTORY_SIZE,
                owner: UserInfo::ROOT,
                node_info: match h.get_typed::<Self>() {
                    DeviceDirHandle::Root => self.root_inode,
                    DeviceDirHandle::Pts => self.pts_inode,
                },
                blksize: super::DEFAULT_DIRECTORY_SIZE,
            }),
        }
    }

    fn create_file_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        Err(OpenError::ReadOnlyFileSystem)
    }

    fn symlink_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _target: &str,
        _metadata: CreationMetadata,
    ) -> Result<(), SymlinkError> {
        Err(SymlinkError::ReadOnlyFileSystem)
    }

    fn mkdir_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn unlink_at(&self, _dir: DirHandle, _name: &str) -> Result<(), UnlinkError> {
        Err(UnlinkError::ReadOnlyFileSystem)
    }

    fn rmdir_at(&self, _dir: DirHandle, _name: &str) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn chmod(&self, _h: HandleRef<'_>, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chown(
        &self,
        _h: HandleRef<'_>,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        Err(ChownError::ReadOnlyFileSystem)
    }
}
