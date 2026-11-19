// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-y devices [`super::backend::Backend`].
//!
//! Provides `{stdin,stdout,tty,null,urandom,...}` entries, intended to be mounted at `/dev`, and
//! pseudo-terminals: opening `ptmx` creates a pair and opens its manager, and `pts/<index>` names
//! each pair's subsidiary.
//!
//! By default the backend enforces its own (lack of) permissions, as legacy resolvers expect. A
//! backend configured with [`Devices::with_security`] instead reports the descriptors of its
//! objects for a resolver that authorizes subjects to check: those of its directories and fixed
//! devices come from trusted configuration and never change, while each subsidiary belongs to the
//! subject that opened `ptmx` and keeps the descriptor its owner sets.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox_broker_protocol::authority::Principal;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use super::backend::{
    AuthorizeRemoval, AuthorizeRename, AuthorizeUse, Backend, BackendHandles, ContentChange,
    CreationMetadata, DirHandle, FileHandle, FileTerminal, HandleRef, OpenChecks, Opener,
    PermissionCheck, PermissionInfo, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget,
    SeekBehavior, mode_descriptor, status_mode,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RenameError, ResolutionError, RmdirError, SetSecurityError, SetTimesError,
    SymlinkError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::inode_allocator::InodeAllocator;
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, SetFileTimes};
use crate::descriptor::{FileKind, SecurityDescriptor};
use crate::pseudo_terminal::{
    ManagerFile, PseudoTerminal, PseudoTerminals, SubsidiaryFile, SubsidiaryMetadata,
};
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

    fn node_info(self, devices: &Devices) -> NodeInfo {
        match self {
            Device::Stdin | Device::Stdout | Device::Stderr => devices.stdio_inode,
            Device::Tty => devices.tty_inode,
            Device::Null => devices.null_inode,
            Device::URandom => devices.urandom_inode,
            Device::Ptmx => devices.ptmx_inode,
        }
    }

    /// The device's descriptor, which never changes.
    fn descriptor(self, devices: &Devices) -> &SecurityDescriptor {
        match self {
            Device::Stdin | Device::Stdout | Device::Stderr => &devices.security.consoles,
            Device::Tty | Device::Null | Device::URandom | Device::Ptmx => &devices.security.shared,
        }
    }

    fn file_status(self, devices: &Devices) -> FileStatus {
        let blksize = match self {
            Device::Stdin | Device::Stdout | Device::Stderr | Device::Tty | Device::Ptmx => {
                STDIO_BLOCK_SIZE
            }
            Device::Null => NULL_BLOCK_SIZE,
            Device::URandom => URANDOM_BLOCK_SIZE,
        };
        device_status(self.descriptor(devices), self.node_info(devices), blksize)
    }
}

/// The status of a character device with `descriptor`.
fn device_status(descriptor: &SecurityDescriptor, node_info: NodeInfo, blksize: u64) -> FileStatus {
    FileStatus {
        file_type: FileType::CharacterDevice,
        mode: status_mode(descriptor),
        size: 0,
        owner: descriptor.owner(),
        group: descriptor.group(),
        times: None,
        node_info,
        blksize,
    }
}

/// Who may use the objects of a [`Devices`] backend that a resolver authorizing subjects serves
/// (see [`Devices::with_security`]), from trusted configuration.
#[derive(Clone, Debug)]
pub struct DeviceSecurity {
    /// Of the root and `pts` directories.
    directories: SecurityDescriptor,
    /// Of `stdin`, `stdout` and `stderr`.
    consoles: SecurityDescriptor,
    /// Of `tty`, `null`, `urandom` and `ptmx`.
    shared: SecurityDescriptor,
    /// Group of new subsidiaries, or `None` for the opener's.
    terminal_group: Option<Principal>,
    /// Access mode of new subsidiaries.
    terminal_mode: Mode,
}

impl DeviceSecurity {
    /// Access mode of new subsidiaries unless configured otherwise.
    const TERMINAL_MODE: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::WGRP);

    /// The usual POSIX configuration: `system_owner` and `system_group` own the directories
    /// (mode 0755) and the devices anyone may use (`tty`, `null`, `urandom` and `ptmx`, mode
    /// 0666), `console_owner` and `console_group` the standard streams (mode 0620), like a
    /// session's terminal, and new subsidiaries have mode 0620 and the opener's group.
    #[must_use]
    pub fn posix(
        system_owner: Principal,
        system_group: Principal,
        console_owner: Principal,
        console_group: Principal,
    ) -> Self {
        let everyone = Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH;
        Self {
            directories: mode_descriptor(
                FileType::Directory,
                Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                system_owner,
                system_group,
            ),
            consoles: mode_descriptor(
                FileType::CharacterDevice,
                Self::TERMINAL_MODE,
                console_owner,
                console_group,
            ),
            shared: mode_descriptor(
                FileType::CharacterDevice,
                everyone,
                system_owner,
                system_group,
            ),
            terminal_group: None,
            terminal_mode: Self::TERMINAL_MODE,
        }
    }

    /// A configuration protecting the directories with `directories`, the standard streams with
    /// `consoles`, and the other fixed devices with `shared`, whose new subsidiaries have mode
    /// 0620 and the opener's group; `None` unless `directories` describes a directory and the
    /// others files.
    #[must_use]
    pub fn new(
        directories: SecurityDescriptor,
        consoles: SecurityDescriptor,
        shared: SecurityDescriptor,
    ) -> Option<Self> {
        (directories.kind() == FileKind::Directory
            && consoles.kind() == FileKind::File
            && shared.kind() == FileKind::File)
            .then_some(Self {
                directories,
                consoles,
                shared,
                terminal_group: None,
                terminal_mode: Self::TERMINAL_MODE,
            })
    }

    /// New subsidiaries have the access bits of `mode` and belong to `group`, or to the opener's
    /// group for `None`, like the `gid` and `mode` options of Linux's devpts.
    #[must_use]
    pub fn with_terminals(self, group: Option<Principal>, mode: Mode) -> Self {
        Self {
            terminal_group: group,
            terminal_mode: mode & (Mode::RWXU | Mode::RWXG | Mode::RWXO),
            ..self
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
    /// Inode number of the subsidiary with index zero; later indices follow it.
    first_pts_ino: u64,
    /// Host standard streams behind `stdin`, `stdout`, and `stderr`.
    stdio: Arc<dyn StdioProvider>,
    /// Randomness behind `urandom`.
    random: Arc<dyn RandomProvider>,
    /// Pseudo-terminal pairs that `ptmx` created.
    pseudo_terminals: PseudoTerminals,
    /// Descriptors of the directories and fixed devices, and how new subsidiaries are protected.
    security: DeviceSecurity,
    /// Whether resolvers check `security` (see [`Self::with_security`]), rather than the
    /// backend enforcing its own permissions.
    secured: bool,
    /// Allocated the directories' and devices' inodes. It must allocate no more,
    /// since subsidiaries' inode numbers start at `first_pts_ino`.
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
        let first_pts_ino = allocator.next().ino;
        Self {
            root_inode,
            pts_inode,
            stdio_inode,
            tty_inode,
            null_inode,
            urandom_inode,
            ptmx_inode,
            first_pts_ino,
            stdio,
            random,
            pseudo_terminals: PseudoTerminals::new(),
            // What legacy resolvers have always seen.
            security: DeviceSecurity::posix(
                Principal::posix_user(0),
                Principal::posix_group(0),
                Principal::posix_user(0),
                Principal::posix_group(0),
            ),
            secured: false,
            _alloc: allocator,
        }
    }

    /// This backend, but reporting the descriptors of its objects, from `security`, for a resolver
    /// that authorizes subjects (see [`super::resolver::Resolver::with_credentials`]) to check, rather than
    /// enforcing its own permissions. Legacy resolvers cannot open its files.
    ///
    /// The directories and fixed devices keep their descriptors. Opening `ptmx` creates a
    /// subsidiary owned by the opening subject's owner (see [`OpenChecks::opener`]), with the
    /// group and access that `security` configures; the subsidiary's owner may then change its
    /// descriptor as [`crate::descriptor::mutation::MutationContext::set_security`] allows, until
    /// its manager closes.
    #[must_use]
    pub fn with_security(self, security: DeviceSecurity) -> Self {
        Self {
            security: DeviceSecurity {
                directories: security.directories.from_trusted_configuration(),
                consoles: security.consoles.from_trusted_configuration(),
                shared: security.shared.from_trusted_configuration(),
                ..security
            },
            secured: true,
            ..self
        }
    }

    /// The pair whose subsidiary `name` names, while its manager is open.
    fn pseudo_terminal(&self, name: &str) -> Option<Arc<PseudoTerminal>> {
        self.pseudo_terminals.get(pts_index(name)?)
    }

    /// The descriptor of a new subsidiary opened by `opener`.
    fn subsidiary_descriptor(&self, opener: Opener) -> SecurityDescriptor {
        mode_descriptor(
            FileType::CharacterDevice,
            self.security.terminal_mode,
            opener.owner,
            self.security.terminal_group.unwrap_or(opener.group),
        )
        .from_trusted_configuration()
    }

    fn subsidiary_node_info(&self, index: u32) -> NodeInfo {
        NodeInfo {
            dev: self.pts_inode.dev,
            ino: self.first_pts_ino + u64::from(index),
            rdev: Some(pts_rdev(index)),
        }
    }

    fn subsidiary_status(&self, index: u32, descriptor: &SecurityDescriptor) -> FileStatus {
        device_status(
            descriptor,
            self.subsidiary_node_info(index),
            STDIO_BLOCK_SIZE,
        )
    }

    /// How resolvers check access to the directories.
    fn dir_permissions(&self) -> PermissionCheck {
        if self.secured {
            // No entry of either directory changes but by opening `ptmx` or closing a manager.
            PermissionCheck::ByResolver(PermissionInfo::new(
                self.security.directories.clone(),
                true,
            ))
        } else {
            PermissionCheck::ByBackend
        }
    }

    /// How resolvers check access to a device with `descriptor`.
    fn file_permissions(&self, descriptor: &SecurityDescriptor) -> PermissionCheck {
        if self.secured {
            PermissionCheck::ByResolver(PermissionInfo::new(descriptor.clone(), false))
        } else {
            PermissionCheck::ByBackend
        }
    }

    /// Opens `file` like [`Backend::open_file`], or for a subject, admitted by `checks`, like
    /// [`Backend::open_file_checked`].
    fn open(
        &self,
        file: ResolvedFile<'_>,
        flags: OFlags,
        checks: Option<&OpenChecks<'_>>,
    ) -> Result<FileHandle, OpenError> {
        let DeviceResolvedFile(target) = file.into_typed::<Self>();
        if flags.contains(OFlags::DIRECTORY) {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }
        let admit = |descriptor: &SecurityDescriptor| match checks {
            Some(checks) => (checks.admit)(descriptor),
            None => Ok(()),
        };
        let path_only = flags.contains(OFlags::PATH);
        let file = match target {
            DeviceResolvedTarget::Device(Device::Ptmx) if !path_only => {
                admit(Device::Ptmx.descriptor(self))?;
                let opener = match checks {
                    Some(checks) => checks.opener,
                    // What legacy resolvers have always seen.
                    None => Opener {
                        owner: Principal::posix_user(0),
                        group: Principal::posix_group(0),
                    },
                };
                DeviceFile::Manager(Arc::new(
                    self.pseudo_terminals
                        .open_manager(self.subsidiary_descriptor(opener))?,
                ))
            }
            DeviceResolvedTarget::Device(device) => {
                // Fixed devices' descriptors never change.
                admit(device.descriptor(self))?;
                DeviceFile::Device(device)
            }
            DeviceResolvedTarget::Subsidiary { index, pair } => {
                let file = if path_only {
                    admit(&pair.descriptor())?;
                    None
                } else {
                    Some(Arc::new(pair.open_subsidiary_checked(&admit)?))
                };
                DeviceFile::Subsidiary {
                    index,
                    file,
                    metadata: pair.metadata(),
                }
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

    /// The current descriptor of a resolved device or directory.
    fn resolved_descriptor(&self, target: &ResolvedTarget<'_>) -> SecurityDescriptor {
        match target {
            ResolvedTarget::File(file) => match &file.get_typed::<Self>().0 {
                DeviceResolvedTarget::Device(device) => device.descriptor(self).clone(),
                DeviceResolvedTarget::Subsidiary { pair, .. } => pair.descriptor(),
            },
            ResolvedTarget::Dir(_) => self.security.directories.clone(),
        }
    }

    /// The descriptor of an open device that is not a subsidiary, which never changes.
    fn fixed_descriptor(&self, file: &DeviceFile) -> Option<&SecurityDescriptor> {
        match file {
            DeviceFile::Device(device) => Some(device.descriptor(self)),
            // A manager is what opening `ptmx` yields.
            DeviceFile::Manager(_) => Some(Device::Ptmx.descriptor(self)),
            DeviceFile::Subsidiary { .. } => None,
        }
    }

    /// Whether `authorize` allows the current descriptor of the open device `file`. A
    /// subsidiary's descriptor may change right after, so I/O must check it under its lock.
    fn authorize_file(&self, file: &DeviceFile, authorize: AuthorizeUse<'_>) -> bool {
        if !self.secured {
            return false;
        }
        if let DeviceFile::Subsidiary { metadata, .. } = file {
            return authorize(&metadata.descriptor());
        }
        self.fixed_descriptor(file).is_some_and(authorize)
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
    /// The manager of a pair that opening `ptmx` created.
    Manager(Arc<ManagerFile>),
    /// The subsidiary named by `index`, open unless `file` is `None`, for a
    /// path-only handle.
    Subsidiary {
        index: u32,
        file: Option<Arc<SubsidiaryFile>>,
        metadata: Arc<SubsidiaryMetadata>,
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

    fn root(&self) -> Result<ResolvedDir<'_>, WalkError> {
        Ok(ResolvedDir::from_typed::<Self>(
            DeviceDirHandle::Root,
            self.dir_permissions(),
        ))
    }

    fn resolve<'a>(
        &'a self,
        from: ResolvedDir<'a>,
        components: &[&str],
        authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        if components.is_empty() {
            return Ok(Resolution::Found(ResolvedTarget::Dir(from)));
        }
        let mut dir = from.into_typed::<Self>();
        for (index, &component) in components.iter().enumerate() {
            if let PermissionCheck::ByResolver(permissions) = self.dir_permissions() {
                authorize_dir_lookup(&permissions).map_err(|error| ResolutionError {
                    component: Some(index),
                    error,
                })?;
            }
            let target = match dir {
                DeviceDirHandle::Root if component == PTS_DIR_NAME => {
                    dir = DeviceDirHandle::Pts;
                    continue;
                }
                DeviceDirHandle::Root => {
                    Device::from_name(component).map(DeviceResolvedTarget::Device)
                }
                DeviceDirHandle::Pts => {
                    self.pseudo_terminal(component)
                        .map(|pair| DeviceResolvedTarget::Subsidiary {
                            index: pts_index(component).unwrap(),
                            pair,
                        })
                }
            };
            match target {
                Some(target) if index + 1 == components.len() => {
                    let permissions = match &target {
                        DeviceResolvedTarget::Device(device) => {
                            self.file_permissions(device.descriptor(self))
                        }
                        DeviceResolvedTarget::Subsidiary { pair, .. } => {
                            self.file_permissions(&pair.descriptor())
                        }
                    };
                    return Ok(Resolution::Found(ResolvedTarget::File(
                        ResolvedFile::from_typed::<Self>(
                            DeviceResolvedFile(target),
                            permissions,
                            FileType::CharacterDevice,
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
                        parent: ResolvedDir::from_typed::<Self>(dir, self.dir_permissions()),
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
            ResolvedDir::from_typed::<Self>(dir, self.dir_permissions()),
        )))
    }

    fn read_link_at(&self, _dir: &ResolvedDir<'_>, _name: &str) -> Result<String, WalkError> {
        Err(PathError::InvalidPathname.into())
    }

    fn open_dir(&self, dir: ResolvedDir<'_>, _flags: OFlags) -> Result<DirHandle, OpenError> {
        Ok(DirHandle::from_typed::<Self>(dir.into_typed::<Self>()))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<ResolvedDir<'a>> {
        Some(ResolvedDir::from_typed::<Self>(
            *dir.get_typed::<Self>(),
            self.dir_permissions(),
        ))
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        if self.secured {
            // Only subjects, whose opens are checked, may use the configured descriptors.
            return Err(OpenError::Io);
        }
        self.open(file, flags, None)
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        Ok(match handle.into_typed::<Self>() {
            DeviceDirHandle::Root => Device::ALL
                .iter()
                .map(|(n, d)| DirEntry {
                    name: String::from(*n),
                    file_type: FileType::CharacterDevice,
                    ino_info: Some(d.node_info(self)),
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
                    ino_info: Some(self.subsidiary_node_info(index)),
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
                DeviceFile::Device(device) => device.file_status(self),
                DeviceFile::Manager(_) => Device::Ptmx.file_status(self),
                DeviceFile::Subsidiary {
                    index, metadata, ..
                } => self.subsidiary_status(*index, &metadata.descriptor()),
            }),
            HandleRef::Dir(h) => Ok(FileStatus {
                file_type: FileType::Directory,
                mode: status_mode(&self.security.directories),
                size: super::DEFAULT_DIRECTORY_SIZE,
                owner: self.security.directories.owner(),
                group: self.security.directories.group(),
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
                DeviceResolvedTarget::Subsidiary { index, pair } => {
                    self.subsidiary_status(*index, &pair.descriptor())
                }
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

    // The checked operations serve only a backend configured with `with_security`; the others
    // report `PermissionCheck::ByBackend`, which resolvers that authorize subjects refuse.

    fn create_file_checked(
        &self,
        _parent: ResolvedDir<'_>,
        _name: &str,
        _authorize: &dyn Fn(&SecurityDescriptor) -> Result<SecurityDescriptor, OpenError>,
    ) -> Result<FileHandle, OpenError> {
        Err(OpenError::ReadOnlyFileSystem)
    }

    fn symlink_checked(
        &self,
        _dir: ResolvedDir<'_>,
        _name: &str,
        _target: &str,
        _authorize: &dyn Fn(&SecurityDescriptor) -> Result<SecurityDescriptor, SymlinkError>,
    ) -> Result<(), SymlinkError> {
        Err(SymlinkError::ReadOnlyFileSystem)
    }

    fn mkdir_checked(
        &self,
        _parent: ResolvedDir<'_>,
        _name: &str,
        _authorize: &dyn Fn(&SecurityDescriptor) -> Result<SecurityDescriptor, MkdirError>,
    ) -> Result<DirHandle, MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn unlink_checked(
        &self,
        _parent: ResolvedDir<'_>,
        _name: &str,
        _authorize: AuthorizeRemoval<'_, UnlinkError>,
    ) -> Result<(), UnlinkError> {
        Err(UnlinkError::ReadOnlyFileSystem)
    }

    fn rmdir_checked(
        &self,
        _parent: ResolvedDir<'_>,
        _name: &str,
        _authorize: AuthorizeRemoval<'_, RmdirError>,
    ) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn rename_checked(
        &self,
        _old_dir: DirHandle,
        _old_name: &str,
        _new_dir: DirHandle,
        _new_name: &str,
        _authorize: AuthorizeRename<'_>,
    ) -> Result<(), RenameError> {
        Err(RenameError::ReadOnlyFileSystem)
    }

    fn set_times_checked(
        &self,
        target: ResolvedTarget<'_>,
        _times: &SetFileTimes,
        authorize: &dyn Fn(&SecurityDescriptor) -> Result<(), SetTimesError>,
    ) -> Result<(), SetTimesError> {
        if !self.secured {
            return Err(SetTimesError::Io);
        }
        // Devices keep no times, so once authorized, the change is done.
        authorize(&self.resolved_descriptor(&target))?;
        match target {
            ResolvedTarget::File(_) => Ok(()),
            ResolvedTarget::Dir(_) => Err(SetTimesError::ReadOnlyFileSystem),
        }
    }

    fn update_security(
        &self,
        target: ResolvedTarget<'_>,
        update: &dyn Fn(&SecurityDescriptor) -> Result<SecurityDescriptor, SetSecurityError>,
    ) -> Result<(), SetSecurityError> {
        if !self.secured {
            return Err(SetSecurityError::Io);
        }
        if let ResolvedTarget::File(file) = &target
            && let DeviceResolvedTarget::Subsidiary { pair, .. } = &file.get_typed::<Self>().0
        {
            // Under the lock that opens of the subsidiary take, until its name goes.
            return pair.update_descriptor(
                update,
                SetSecurityError::PathError(PathError::NoSuchFileOrDirectory),
            );
        }
        // Configuration fixes the other descriptors, but only those who may change them learn so.
        update(&self.resolved_descriptor(&target))?;
        Err(SetSecurityError::ReadOnlyFileSystem)
    }

    fn open_file_checked(
        &self,
        file: ResolvedFile<'_>,
        flags: OFlags,
        checks: &OpenChecks<'_>,
    ) -> Result<FileHandle, OpenError> {
        if !self.secured {
            return Err(OpenError::Io);
        }
        self.open(file, flags, Some(checks))
    }

    fn write_checked(
        &self,
        h: &FileHandle,
        buf: &dyn WriteBuffer,
        offset: usize,
        authorize: AuthorizeUse<'_>,
        _content_change: ContentChange<'_>,
    ) -> Result<usize, WriteError> {
        // Writing to a device changes no file's contents, so its descriptor stays.
        let file = &h.get_typed::<Self>().0;
        if !self.secured {
            return Err(WriteError::Io);
        }
        if let DeviceFile::Subsidiary { file, .. } = file {
            return file
                .as_ref()
                .ok_or(WriteError::Io)?
                .endpoint()
                .subsidiary_write_checked(buf, authorize);
        }
        if !self.authorize_file(file, authorize) {
            return Err(WriteError::NotForWriting);
        }
        self.write(h, buf, offset)
    }

    fn truncate_checked(
        &self,
        h: &FileHandle,
        length: usize,
        authorize: AuthorizeUse<'_>,
        _content_change: ContentChange<'_>,
    ) -> Result<(), TruncateError> {
        // Devices are never truncated, so a racing descriptor change makes no difference.
        if !self.authorize_file(&h.get_typed::<Self>().0, authorize) {
            return Err(TruncateError::NotForWriting);
        }
        self.truncate(h, length)
    }

    fn read_checked(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
        authorize: AuthorizeUse<'_>,
    ) -> Result<usize, ReadError> {
        let file = &h.get_typed::<Self>().0;
        if !self.secured {
            return Err(ReadError::Io);
        }
        if let DeviceFile::Subsidiary { file, .. } = file {
            return file
                .as_ref()
                .ok_or(ReadError::Io)?
                .endpoint()
                .subsidiary_read_checked(buf, authorize);
        }
        if !self.authorize_file(file, authorize) {
            return Err(ReadError::NotForReading);
        }
        self.read(h, buf, offset)
    }

    fn open_dir_checked(
        &self,
        dir: ResolvedDir<'_>,
        flags: OFlags,
        admit: &dyn Fn(&SecurityDescriptor) -> Result<(), OpenError>,
    ) -> Result<DirHandle, OpenError> {
        if !self.secured {
            return Err(OpenError::Io);
        }
        // The directories' descriptor never changes.
        admit(&self.security.directories)?;
        self.open_dir(dir, flags)
    }

    fn set_handle_times_checked(
        &self,
        h: HandleRef<'_>,
        _times: &SetFileTimes,
        authorize: &dyn Fn(&SecurityDescriptor) -> Result<(), SetTimesError>,
    ) -> Result<(), SetTimesError> {
        if !self.secured {
            return Err(SetTimesError::Io);
        }
        match h {
            // Devices keep no times, so once authorized, the change is done.
            HandleRef::File(h) => match &h.get_typed::<Self>().0 {
                DeviceFile::Subsidiary { metadata, .. } => authorize(&metadata.descriptor()),
                file => authorize(self.fixed_descriptor(file).ok_or(SetTimesError::Io)?),
            },
            // As their permissions say, the directories are on a read-only file system.
            HandleRef::Dir(_) => Err(SetTimesError::ReadOnlyFileSystem),
        }
    }

    fn list_dir_checked(
        &self,
        handle: DirHandle,
        authorize: AuthorizeUse<'_>,
    ) -> Result<Vec<DirEntry>, ReadDirError> {
        if !self.secured {
            return Err(ReadDirError::Io);
        }
        // The directories' descriptor never changes.
        if !authorize(&self.security.directories) {
            return Err(ReadDirError::NotOpenForReading);
        }
        self.list_dir_at(handle)
    }

    fn authorize_handle(&self, h: HandleRef<'_>, authorize: AuthorizeUse<'_>) -> bool {
        match h {
            HandleRef::File(h) => self.authorize_file(&h.get_typed::<Self>().0, authorize),
            HandleRef::Dir(_) => self.secured && authorize(&self.security.directories),
        }
    }
}
