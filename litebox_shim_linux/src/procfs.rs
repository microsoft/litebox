// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-side Linux procfs provider, enabled with the `procfs` feature.
//!
//! Inject a shared [`ProcState`] into [`ProcFs`] and mount it through the filesystem composer.
//! Enable automatic registration
//! with [`ProcFs::with_process_lifecycle`], or retain a [`ProcessRegistration`] per live process.
//! This subset exposes `self`, the accessing process's directory, a read-only object-backed
//! `exe` link, a path-based `cwd` link, and generated `limits` and `status` files, each after
//! trusted publication, and an `fd` directory whose entries the broker hands back to the
//! accessing process's shim. It never exposes host procfs or other processes.

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use litebox_broker_core::{
    BrokerProcess,
    fs::{
        DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, UserInfo,
        backend::{
            Backend, BackendHandles, CreationMetadata, DirHandle, FileCaller, FileHandle,
            FilePublisher, FileTarget, HandleRef, LinkTarget, LookupContext, PermissionCheck,
            PermissionInfo, PublishedObject, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget,
            SeekBehavior,
        },
        errors::{
            ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError,
            ReadDirError, ReadError, RenameError, ResolutionError, RmdirError, SymlinkError,
            TruncateError, UnlinkError, WalkError, WriteError,
        },
        inode_allocator::InodeAllocator,
    },
};
use litebox_platform::{
    buffer::{ReadBuffer, WriteBuffer},
    sync::{Mutex, RawSyncPrimitivesProvider},
};

#[cfg(test)]
mod tests;

/// The `(name, target)` symbolic links Linux conventionally has in `/dev` into procfs, for a
/// devices backend mounted at `/dev` beside this one mounted at `/proc`.
#[must_use]
pub fn dev_links() -> Vec<(String, String)> {
    alloc::vec![(String::from("fd"), String::from("/proc/self/fd"))]
}

/// Read-only filesystem view of an injected process-state controller.
///
/// Clones share the controller and preserve the namespace's inode identities.
pub struct ProcFs<Platform: RawSyncPrimitivesProvider> {
    state: ProcState<Platform>,
    root: NodeInfo,
    self_link: NodeInfo,
    lifecycle_owner: Option<UserInfo>,
}

/// Shared, bounded controller for procfs registration and process-state publication.
///
/// Clones share registrations. A registration's lifetime is independent of the controller
/// handle used to create it. The controller does not retain its filesystem view.
pub struct ProcState<Platform: RawSyncPrimitivesProvider> {
    registry: Arc<Registry<Platform>>,
}

struct Registry<Platform: RawSyncPrimitivesProvider> {
    processes: Mutex<Platform, Vec<RegisteredProcess>>,
    allocator: InodeAllocator,
    limit: usize,
}

struct RegisteredProcess {
    process: Arc<Process>,
    state: PublishedState,
}

/// Process state published by the process's runner, and inherited by its children.
#[derive(Clone, Default)]
struct PublishedState {
    executable: Option<FileTarget>,
    /// The absolute working directory, as of when the runner published it.
    cwd: Option<String>,
    /// The text of `limits`, which the runner formats and republishes whenever a limit changes.
    limits: Option<Arc<[u8]>>,
    status: PublishedStatus,
}

/// The fields of `status` that the runner formats and republishes whenever they change.
#[derive(Clone, Default)]
struct PublishedStatus {
    /// The escaped value of `Name`.
    name: Option<Arc<[u8]>>,
    /// The value of `Umask`.
    umask: Option<Arc<[u8]>>,
    /// The IDs of the `Uid`, `Gid`, and `Groups` lines, as [`crate::StatusCredentials`] encodes
    /// them.
    credentials: Option<Arc<[u8]>>,
}

/// The most bytes a process may publish as its `limits` text; Linux's is under 1.5 KiB.
const MAX_LIMITS_TEXT: usize = 4096;
/// The most bytes a process may publish as an escaped `status` name, of at most 15 bytes.
const MAX_STATUS_NAME: usize = 64;
/// The most bytes a process may publish as its `status` umask.
const MAX_STATUS_UMASK: usize = 8;

/// Owns the live registration of a process in one procfs namespace.
///
/// Drop this on process exit, not on exec. Dropping removes the process from future lookups;
/// retained handles keep its inode identity but cannot enumerate or traverse its dead directory.
/// A later process with the same numeric PID never inherits the old directory.
pub struct ProcessRegistration<Platform: RawSyncPrimitivesProvider> {
    registry: Arc<Registry<Platform>>,
    process: Arc<Process>,
}

/// Failure to register process state. Registrations are never silently replaced or evicted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistrationError {
    /// This process key already has a live registration.
    #[error("process identity is already registered")]
    AlreadyRegistered,
    /// The namespace's configured live-process limit has been reached.
    #[error("procfs process registration limit reached")]
    Capacity,
}

struct Process {
    caller: FileCaller,
    /// The broker's process, for generic state such as its parent and threads.
    broker: Weak<BrokerProcess>,
    /// Effective UID/GID packed together so metadata cannot observe half an owner update.
    owner: AtomicU32,
    node: NodeInfo,
    executable_node: NodeInfo,
    cwd_node: NodeInfo,
    limits_node: NodeInfo,
    status_node: NodeInfo,
    fd_node: NodeInfo,
    live: AtomicBool,
}

impl Process {
    fn owner(&self) -> UserInfo {
        let [user_low, user_high, group_low, group_high] =
            self.owner.load(Ordering::Relaxed).to_le_bytes();
        UserInfo {
            user: u16::from_le_bytes([user_low, user_high]),
            group: u16::from_le_bytes([group_low, group_high]),
        }
    }

    fn set_owner(&self, owner: UserInfo) {
        self.owner
            .store(Self::packed_owner(owner), Ordering::Relaxed);
    }

    /// `owner` packed as [`Self::owner`] unpacks it.
    fn packed_owner(owner: UserInfo) -> u32 {
        u32::from(owner.user) | (u32::from(owner.group) << 16)
    }
}

/// A directory bound either to the namespace or to a particular process incarnation.
#[derive(Clone)]
pub struct ProcDirectory {
    caller: Option<FileCaller>,
    user: UserInfo,
    target: DirectoryTarget,
}

#[derive(Clone)]
enum DirectoryTarget {
    Root,
    Process(Arc<Process>),
    /// The process's descriptors, which its runner, not procfs, knows.
    Descriptors(Arc<Process>),
}

impl DirectoryTarget {
    fn process(&self) -> Option<&Arc<Process>> {
        match self {
            Self::Root => None,
            Self::Process(process) | Self::Descriptors(process) => Some(process),
        }
    }
}

/// The descriptor number `name` spells as Linux accepts it: decimal digits, without a sign or
/// leading zeros, of a value a descriptor can have.
fn descriptor_number(name: &str) -> Option<u32> {
    litebox_broker_core::fs::canonical_decimal(name).filter(|&number| i32::try_from(number).is_ok())
}

#[derive(Clone, Copy)]
enum ProcEntry {
    SelfLink,
    Cwd,
    Executable,
    Limits,
    Status,
}

impl ProcEntry {
    fn in_directory(directory: &DirectoryTarget) -> &'static [(&'static str, Self)] {
        match directory {
            DirectoryTarget::Root => &[("self", Self::SelfLink)],
            DirectoryTarget::Descriptors(_) => &[],
            DirectoryTarget::Process(_) => &[
                ("cwd", Self::Cwd),
                ("exe", Self::Executable),
                ("limits", Self::Limits),
                ("status", Self::Status),
            ],
        }
    }

    fn from_name(directory: &DirectoryTarget, name: &str) -> Option<Self> {
        Self::in_directory(directory)
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, entry)| *entry)
    }
}

/// An opened `O_PATH | O_NOFOLLOW` reference to a procfs link.
#[derive(Clone)]
pub enum ProcLink {
    /// Namespace-relative link interpreted using the accessing caller.
    SelfLink,
    /// Process-incarnation-bound working-directory link.
    Cwd(ProcProcessLink),
    /// Process-incarnation-bound executable link.
    Executable(ProcProcessLink),
}

/// Retained identity of a process-bound link inode, without retaining the state it names.
#[derive(Clone)]
pub struct ProcProcessLink {
    process: Arc<Process>,
}

/// A procfs non-directory: a link, or a file generated from published process state.
pub enum ProcFile<Platform: RawSyncPrimitivesProvider> {
    Link(ProcLink),
    Generated(ProcGeneratedFile<Platform>),
}

impl<Platform: RawSyncPrimitivesProvider> Clone for ProcFile<Platform> {
    fn clone(&self) -> Self {
        match self {
            Self::Link(link) => Self::Link(link.clone()),
            Self::Generated(file) => Self::Generated(ProcGeneratedFile {
                process: Arc::clone(&file.process),
                kind: file.kind,
                snapshot: Arc::clone(&file.snapshot),
            }),
        }
    }
}

/// A process-incarnation-bound generated file, with the snapshot its open description reads.
///
/// Contiguous reads share a snapshot, including repeated EOF reads. A read at another offset
/// regenerates it, so rewinding or repositioning refreshes the text. Clones share this state.
pub struct ProcGeneratedFile<Platform: RawSyncPrimitivesProvider> {
    process: Arc<Process>,
    kind: GeneratedKind,
    snapshot: Arc<Mutex<Platform, Option<GeneratedSnapshot>>>,
}

struct GeneratedSnapshot {
    text: Arc<[u8]>,
    next_offset: usize,
}

#[derive(Clone, Copy)]
enum GeneratedKind {
    Limits,
    Status,
}

impl<Platform: RawSyncPrimitivesProvider> Clone for ProcFs<Platform> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            root: self.root,
            self_link: self.self_link,
            lifecycle_owner: self.lifecycle_owner,
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider> Clone for ProcState<Platform> {
    fn clone(&self) -> Self {
        Self {
            registry: Arc::clone(&self.registry),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider> ProcState<Platform> {
    /// Construct a controller allowing at most `max_processes` live registrations.
    ///
    /// The allocator supplies both namespace and process inodes. Zero capacity still
    /// permits constructing a filesystem view but rejects every process registration.
    #[must_use]
    pub fn new(allocator: InodeAllocator, max_processes: usize) -> Self {
        Self {
            registry: Arc::new(Registry {
                processes: Mutex::new(Vec::new()),
                allocator,
                limit: max_processes,
            }),
        }
    }

    /// Register a broker-authenticated process and its initial Linux filesystem owner.
    ///
    /// This is a trusted broker-side state-source API, not a guest request. The caller must
    /// arrange for the returned guard to be dropped on exit, including runner failure.
    /// Trusted credential publication subsequently updates ownership to the effective UID/GID.
    pub fn register_process(
        &self,
        process: &Arc<BrokerProcess>,
        owner: UserInfo,
    ) -> Result<ProcessRegistration<Platform>, RegistrationError> {
        self.register_broker_process(process, owner)
    }

    /// Publish this process's executable as a retained readable regular file, as the guest's
    /// executable publication does, atomically replacing the image capability.
    #[cfg(test)]
    fn set_executable(
        &self,
        process: &BrokerProcess,
        handle: litebox_broker_protocol::ObjectHandle,
    ) -> litebox_broker_core::Result<litebox_broker_core::fs::FileResult<()>> {
        let target = match litebox_broker_core::fs::retain_file(process, handle)? {
            Ok(target) => target,
            Err(error) => return Ok(Err(error)),
        };
        let caller = FileCaller::for_process(process);
        Ok(self.publish_executable(caller, target))
    }

    fn publish_executable(
        &self,
        caller: FileCaller,
        target: FileTarget,
    ) -> litebox_broker_core::fs::FileResult<()> {
        let old = self.update(caller, |state| state.executable.replace(target))?;
        drop(old);
        Ok(())
    }

    fn publish_cwd(
        &self,
        caller: FileCaller,
        path: String,
    ) -> litebox_broker_core::fs::FileResult<()> {
        self.update(caller, |state| state.cwd = Some(path))
    }

    /// Applies `update` to the published state of the live process `caller`, returning its result
    /// so that the caller can drop replaced state outside the registry lock.
    fn update<R>(
        &self,
        caller: FileCaller,
        update: impl FnOnce(&mut PublishedState) -> R,
    ) -> litebox_broker_core::fs::FileResult<R> {
        let mut processes = self.registry.processes.lock();
        let entry = processes
            .iter_mut()
            .find(|entry| entry.process.caller == caller)
            .ok_or(litebox_broker_protocol::fs::FileError::NoSuchFileOrDirectory)?;
        Ok(update(&mut entry.state))
    }

    /// Returns `select` of the published state of `process`, or fails once it has exited.
    fn published<R>(
        &self,
        process: &Process,
        select: impl FnOnce(&PublishedState) -> R,
    ) -> Result<R, PathError> {
        self.registry
            .processes
            .lock()
            .iter()
            .find(|entry| entry.process.caller == process.caller)
            .map(|entry| select(&entry.state))
            .ok_or(PathError::NoSuchFileOrDirectory)
    }

    fn executable(&self, process: &Process) -> Result<Option<FileTarget>, PathError> {
        self.published(process, |state| state.executable.clone())
    }

    fn cwd(&self, process: &Process) -> Result<Option<String>, PathError> {
        self.published(process, |state| state.cwd.clone())
    }

    fn limits(&self, process: &Process) -> Result<Option<Arc<[u8]>>, PathError> {
        self.published(process, |state| state.limits.clone())
    }

    fn status(&self, process: &Process) -> Result<PublishedStatus, PathError> {
        self.published(process, |state| state.status.clone())
    }

    /// Generates the text of `kind` for `process`, failing once it exits.
    // XXX: Linux fails reads of an exited process's files with `ESRCH`.
    fn generate(&self, process: &Process, kind: GeneratedKind) -> Result<Arc<[u8]>, ReadError> {
        match kind {
            GeneratedKind::Limits => self
                .limits(process)
                .map_err(|_| ReadError::Io)?
                .ok_or(ReadError::Io),
            GeneratedKind::Status => self.status_text(process),
        }
    }

    /// Formats `status`: the fields the runner published, in Linux's order around those the
    /// broker knows. Fields without a source, such as `State` and memory usage, are omitted.
    fn status_text(&self, process: &Process) -> Result<Arc<[u8]>, ReadError> {
        let status = self.status(process).map_err(|_| ReadError::Io)?;
        let (Some(name), Some(umask), Some(credentials)) =
            (status.name, status.umask, status.credentials)
        else {
            return Err(ReadError::Io);
        };
        let broker = process.broker.upgrade().ok_or(ReadError::Io)?;
        let pid = process.caller.process_id;
        let parent = broker
            .process_info(pid)
            .map_err(|_| ReadError::Io)?
            .parent
            .map_or(0, |parent| parent.0);
        let threads = broker.thread_count();
        let mut text = Vec::new();
        text.extend_from_slice(b"Name:\t");
        text.extend_from_slice(&name);
        text.extend_from_slice(b"\nUmask:\t");
        text.extend_from_slice(&umask);
        // LiteBox does not support tracing, so no process traces another.
        text.extend_from_slice(
            alloc::format!(
                "\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{parent}\nTracerPid:\t0\n",
                pid = pid.0
            )
            .as_bytes(),
        );
        // The credentials never change, so the saved and filesystem IDs are the effective ones,
        // and the groups are those `getgroups` reports.
        let crate::StatusCredentials {
            uid,
            euid,
            gid,
            egid,
        } = crate::StatusCredentials::decode(&credentials).ok_or(ReadError::Io)?;
        text.extend_from_slice(
            alloc::format!(
                "Uid:\t{uid}\t{euid}\t{euid}\t{euid}\nGid:\t{gid}\t{egid}\t{egid}\t{egid}\n\
                 Groups:\t{gid} \nThreads:\t{threads}\n"
            )
            .as_bytes(),
        );
        Ok(text.into())
    }

    fn register_broker_process(
        &self,
        broker: &Arc<BrokerProcess>,
        owner: UserInfo,
    ) -> Result<ProcessRegistration<Platform>, RegistrationError> {
        let caller = FileCaller::for_process(broker);
        self.register_identity(caller, Arc::downgrade(broker), owner)
    }

    /// Registers `caller` with no broker process, whose broker-sourced fields are unavailable.
    #[cfg(test)]
    fn register(
        &self,
        caller: FileCaller,
        owner: UserInfo,
    ) -> Result<ProcessRegistration<Platform>, RegistrationError> {
        self.register_identity(caller, Weak::new(), owner)
    }

    fn register_identity(
        &self,
        caller: FileCaller,
        broker: Weak<BrokerProcess>,
        owner: UserInfo,
    ) -> Result<ProcessRegistration<Platform>, RegistrationError> {
        let mut processes = self.registry.processes.lock();
        // Only the key is unique: processes in different PID namespaces may share an ID.
        if processes
            .iter()
            .any(|entry| entry.process.caller.process_key == caller.process_key)
        {
            return Err(RegistrationError::AlreadyRegistered);
        }
        if processes.len() >= self.registry.limit {
            return Err(RegistrationError::Capacity);
        }
        let process = Arc::new(Process {
            caller,
            broker,
            owner: AtomicU32::new(Process::packed_owner(owner)),
            node: self.registry.allocator.next(),
            executable_node: self.registry.allocator.next(),
            cwd_node: self.registry.allocator.next(),
            limits_node: self.registry.allocator.next(),
            status_node: self.registry.allocator.next(),
            fd_node: self.registry.allocator.next(),
            live: AtomicBool::new(true),
        });
        processes.push(RegisteredProcess {
            process: Arc::clone(&process),
            state: PublishedState::default(),
        });
        Ok(ProcessRegistration {
            registry: Arc::clone(&self.registry),
            process,
        })
    }

    fn process(&self, caller: Option<FileCaller>) -> Result<Arc<Process>, PathError> {
        let caller = caller.ok_or(PathError::NoSearchPerms)?;
        self.registry
            .processes
            .lock()
            .iter()
            .find(|entry| entry.process.caller == caller)
            .map(|entry| Arc::clone(&entry.process))
            .ok_or(PathError::NoSuchFileOrDirectory)
    }

    fn process_created(
        &self,
        broker: &Arc<BrokerProcess>,
        parent: Option<FileCaller>,
        root_owner: UserInfo,
    ) -> litebox_broker_core::Result<Box<dyn Send + Sync>> {
        use litebox_broker_core::BrokerError;

        let caller = FileCaller::for_process(broker);
        let (owner, inherited) = match parent {
            Some(parent) => {
                let process = self
                    .process(Some(parent))
                    .map_err(|_| BrokerError::PeerClosed)?;
                let inherited = self
                    .published(&process, PublishedState::clone)
                    .map_err(|_| BrokerError::PeerClosed)?;
                (process.owner(), inherited)
            }
            None => (root_owner, PublishedState::default()),
        };
        let registration =
            self.register_broker_process(broker, owner)
                .map_err(|error| match error {
                    RegistrationError::Capacity => BrokerError::ResourceExhausted,
                    RegistrationError::AlreadyRegistered => BrokerError::Internal,
                })?;
        self.update(caller, |state| *state = inherited)
            .map_err(|_| BrokerError::PeerClosed)?;
        Ok(Box::new(registration))
    }
}

impl<Platform: RawSyncPrimitivesProvider> ProcFs<Platform> {
    /// Construct a namespace over `state`, allocating its root and `self` link inodes.
    ///
    /// Retain a controller clone for trusted registration and publication. Clone the
    /// filesystem view, rather than constructing it again, to preserve namespace identity.
    #[must_use]
    pub fn new(state: ProcState<Platform>) -> Self {
        let root = state.registry.allocator.next();
        let self_link = state.registry.allocator.next();
        Self {
            state,
            root,
            self_link,
            lifecycle_owner: None,
        }
    }

    /// Register processes automatically when the composed filesystem receives broker lifecycle
    /// events. Root processes start with `owner`; children inherit their creator's registered
    /// owner, and its published state. Configure this before mounting/cloning the provider.
    #[must_use]
    pub fn with_process_lifecycle(mut self, owner: UserInfo) -> Self {
        self.lifecycle_owner = Some(owner);
        self
    }

    /// The node `entry` names in `directory`, or `None` while its process has not published it.
    fn entry_node(
        &self,
        entry: ProcEntry,
        directory: &DirectoryTarget,
    ) -> Result<Option<ProcFile<Platform>>, PathError> {
        let link = |process: &Arc<Process>| ProcProcessLink {
            process: Arc::clone(process),
        };
        let generated = |process: &Arc<Process>, kind| {
            ProcFile::Generated(ProcGeneratedFile {
                process: Arc::clone(process),
                kind,
                snapshot: Arc::new(Mutex::new(None)),
            })
        };
        Ok(match (entry, directory) {
            (ProcEntry::SelfLink, DirectoryTarget::Root) => {
                Some(ProcFile::Link(ProcLink::SelfLink))
            }
            (ProcEntry::Cwd, DirectoryTarget::Process(process)) => self
                .state
                .cwd(process)?
                .map(|_| ProcFile::Link(ProcLink::Cwd(link(process)))),
            (ProcEntry::Executable, DirectoryTarget::Process(process)) => self
                .state
                .executable(process)?
                .map(|_| ProcFile::Link(ProcLink::Executable(link(process)))),
            (ProcEntry::Limits, DirectoryTarget::Process(process)) => self
                .state
                .limits(process)?
                .map(|_| generated(process, GeneratedKind::Limits)),
            (ProcEntry::Status, DirectoryTarget::Process(process)) => {
                let status = self.state.status(process)?;
                (status.name.is_some() && status.umask.is_some() && status.credentials.is_some())
                    .then(|| generated(process, GeneratedKind::Status))
            }
            _ => return Err(PathError::InvalidPathname),
        })
    }

    /// Whether `directory`'s opener may use it whatever its mode: as on Linux, root may, and so
    /// may a process using its own descriptor directory.
    fn directory_access_is_unconditional(directory: &ProcDirectory) -> bool {
        directory.user.user == UserInfo::ROOT.user
            || matches!(
                &directory.target,
                DirectoryTarget::Descriptors(process) if directory.caller == Some(process.caller)
            )
    }

    /// Whether `directory`'s opener has the owner, group, or other permission in `needed` that
    /// applies to it, or [unconditional access](Self::directory_access_is_unconditional).
    fn directory_permits(&self, directory: &ProcDirectory, needed: [Mode; 3]) -> bool {
        if Self::directory_access_is_unconditional(directory) {
            return true;
        }
        let status = self.directory_status(directory);
        PermissionInfo {
            mode: status.mode,
            owner: status.owner,
            on_read_only_fs: false,
        }
        .permits(directory.user, needed)
    }

    fn directory_status(&self, directory: &ProcDirectory) -> FileStatus {
        let readable_by_all =
            Mode::RUSR | Mode::XUSR | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH;
        let (node_info, owner, mode) = match &directory.target {
            DirectoryTarget::Root => (self.root, UserInfo::ROOT, readable_by_all),
            DirectoryTarget::Process(process) => (process.node, process.owner(), readable_by_all),
            DirectoryTarget::Descriptors(process) => {
                (process.fd_node, process.owner(), Mode::RUSR | Mode::XUSR)
            }
        };
        FileStatus {
            file_type: FileType::Directory,
            mode,
            size: 0,
            owner,
            times: None,
            node_info,
            blksize: 0,
        }
    }

    fn file_status(&self, file: &ProcFile<Platform>) -> FileStatus {
        match file {
            ProcFile::Link(link) => self.link_status(link),
            // Like Linux, generated files report no size, since it is known only once generated.
            ProcFile::Generated(file) => FileStatus {
                file_type: FileType::RegularFile,
                mode: Mode::RUSR | Mode::RGRP | Mode::ROTH,
                size: 0,
                owner: file.process.owner(),
                times: None,
                node_info: match file.kind {
                    GeneratedKind::Limits => file.process.limits_node,
                    GeneratedKind::Status => file.process.status_node,
                },
                blksize: 0,
            },
        }
    }

    /// Generated files refuse writes through their mode, reporting `EACCES` as on Linux.
    fn file_permissions(&self, file: &ProcFile<Platform>) -> PermissionCheck {
        let status = self.file_status(file);
        PermissionCheck::ByResolver(PermissionInfo {
            mode: status.mode,
            owner: status.owner,
            on_read_only_fs: matches!(file, ProcFile::Link(_)),
        })
    }

    fn link_status(&self, link: &ProcLink) -> FileStatus {
        let (owner, node_info) = match link {
            ProcLink::SelfLink => (UserInfo::ROOT, self.self_link),
            ProcLink::Cwd(link) => (link.process.owner(), link.process.cwd_node),
            ProcLink::Executable(link) => (link.process.owner(), link.process.executable_node),
        };
        FileStatus {
            file_type: FileType::SymbolicLink,
            mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
            size: 0,
            owner,
            times: None,
            node_info,
            blksize: 0,
        }
    }

    fn resolved_directory<'a>(&self, directory: ProcDirectory) -> ResolvedDir<'a> {
        // Procfs orders entry-mutation errors itself instead of treating it as an ordinary
        // read-only mount. Search and open permissions are enforced below.
        ResolvedDir::from_typed::<Self>(directory, PermissionCheck::ByBackend)
    }

    fn name_exists(&self, dir: ResolvedDir<'_>, name: &str) -> Result<bool, PathError> {
        let directory = dir.get_typed::<Self>();
        check_live(directory)?;
        if !self.directory_permits(directory, [Mode::XUSR, Mode::XGRP, Mode::XOTH]) {
            return Err(PathError::NoSearchPerms);
        }
        Ok(match &directory.target {
            DirectoryTarget::Root => {
                name == "self"
                    || self
                        .state
                        .process(directory.caller)
                        .is_ok_and(|process| name == process.caller.process_id.0.to_string())
            }
            DirectoryTarget::Process(_) if name == "fd" => true,
            DirectoryTarget::Process(_) => match ProcEntry::from_name(&directory.target, name) {
                Some(entry) => self.entry_node(entry, &directory.target)?.is_some(),
                None => false,
            },
            DirectoryTarget::Descriptors(_) => match descriptor_number(name) {
                Some(number) => return Err(PathError::CallerObject(number)),
                None => false,
            },
        })
    }

    fn open_node(&self, file: ProcFile<Platform>, flags: OFlags) -> Result<FileHandle, OpenError> {
        if flags.contains(OFlags::DIRECTORY) {
            return Err(PathError::ComponentNotADirectory.into());
        }
        let file = match file {
            ProcFile::Link(_) if !flags.contains(OFlags::PATH | OFlags::NOFOLLOW) => {
                return Err(PathError::TooManySymlinks.into());
            }
            ProcFile::Generated(_)
                if !flags.contains(OFlags::PATH)
                    && flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::TRUNC) =>
            {
                return Err(OpenError::AccessNotAllowed);
            }
            // An independent open, unlike a cloned handle, owns fresh snapshot state.
            ProcFile::Generated(file) => ProcFile::Generated(ProcGeneratedFile {
                process: file.process,
                kind: file.kind,
                snapshot: Arc::new(Mutex::new(None)),
            }),
            link @ ProcFile::Link(_) => link,
        };
        Ok(FileHandle::from_typed::<Self>(file))
    }
}

/// The owner that published credentials give their effective IDs, if they are valid.
fn credentials_owner(data: &[u8]) -> Option<UserInfo> {
    let credentials = crate::StatusCredentials::decode(data)?;
    Some(UserInfo {
        user: u16::try_from(credentials.euid).ok()?,
        group: u16::try_from(credentials.egid).ok()?,
    })
}

fn check_live(directory: &ProcDirectory) -> Result<(), PathError> {
    if let Some(process) = directory.target.process()
        && !process.live.load(Ordering::Acquire)
    {
        return Err(PathError::NoSuchFileOrDirectory);
    }
    Ok(())
}

impl<Platform: RawSyncPrimitivesProvider> Drop for ProcessRegistration<Platform> {
    fn drop(&mut self) {
        let mut processes = self.registry.processes.lock();
        self.process.live.store(false, Ordering::Release);
        let removed = processes
            .iter()
            .position(|entry| Arc::ptr_eq(&entry.process, &self.process))
            .map(|index| processes.swap_remove(index));
        drop(processes);
        drop(removed);
    }
}

impl<Platform: RawSyncPrimitivesProvider> FilePublisher for ProcState<Platform> {
    fn publish_data(
        &self,
        caller: FileCaller,
        key: u64,
        data: &[u8],
    ) -> litebox_broker_core::fs::FileResult<()> {
        use litebox_broker_protocol::fs::FileError;

        type Valid = fn(&[u8]) -> bool;
        type Field = fn(&mut PublishedState) -> &mut Option<Arc<[u8]>>;
        let (max, valid, field): (usize, Valid, Field) = match key {
            crate::LIMITS_DATA_PUBLICATION_KEY => {
                (MAX_LIMITS_TEXT, |_| true, |state| &mut state.limits)
            }
            crate::STATUS_NAME_DATA_PUBLICATION_KEY => (
                MAX_STATUS_NAME,
                |name| !name.contains(&b'\n'),
                |state| &mut state.status.name,
            ),
            crate::STATUS_UMASK_DATA_PUBLICATION_KEY => (
                MAX_STATUS_UMASK,
                |umask| {
                    !umask.is_empty() && umask.iter().all(|digit| (b'0'..=b'7').contains(digit))
                },
                |state| &mut state.status.umask,
            ),
            crate::STATUS_CREDENTIALS_DATA_PUBLICATION_KEY => (
                16,
                |data| credentials_owner(data).is_some(),
                |state| &mut state.status.credentials,
            ),
            _ => return Err(FileError::NotSupported),
        };
        if data.len() > max || !valid(data) {
            return Err(FileError::InvalidArgument);
        }
        let owner = if key == crate::STATUS_CREDENTIALS_DATA_PUBLICATION_KEY {
            Some(credentials_owner(data).ok_or(FileError::InvalidArgument)?)
        } else {
            None
        };
        let process = owner
            .map(|_| self.process(Some(caller)))
            .transpose()
            .map_err(|_| FileError::NoSuchFileOrDirectory)?;
        let data: Arc<[u8]> = data.into();
        let old = self.update(caller, |state| {
            if let (Some(process), Some(owner)) = (process, owner) {
                process.set_owner(owner);
            }
            field(state).replace(data)
        })?;
        drop(old);
        Ok(())
    }

    fn publish_file(
        &self,
        caller: FileCaller,
        key: u64,
        object: PublishedObject,
    ) -> litebox_broker_core::fs::FileResult<()> {
        use litebox_broker_protocol::fs::FileError;

        match (key, object) {
            (crate::EXECUTABLE_FILE_PUBLICATION_KEY, PublishedObject::File(target)) => {
                self.publish_executable(caller, target)
            }
            (crate::EXECUTABLE_FILE_PUBLICATION_KEY, PublishedObject::Directory { .. }) => {
                Err(FileError::IsDirectory)
            }
            (crate::CWD_FILE_PUBLICATION_KEY, PublishedObject::Directory { path }) => {
                self.publish_cwd(caller, path)
            }
            (crate::CWD_FILE_PUBLICATION_KEY, PublishedObject::File(_)) => {
                Err(FileError::NotDirectory)
            }
            _ => Err(FileError::NotSupported),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider> BackendHandles for ProcFs<Platform> {
    type ResolvedDir<'a> = ProcDirectory;
    type ResolvedFile<'a> = ProcFile<Platform>;
    type DirHandle = ProcDirectory;
    type FileHandle = ProcFile<Platform>;
}

impl<Platform: RawSyncPrimitivesProvider> Backend for ProcFs<Platform> {
    fn process_created(
        &self,
        process: &Arc<BrokerProcess>,
        parent: Option<FileCaller>,
    ) -> litebox_broker_core::Result<Box<dyn Send + Sync>> {
        let Some(root_owner) = self.lifecycle_owner else {
            return Ok(Box::new(()));
        };
        self.state.process_created(process, parent, root_owner)
    }

    fn root_with_context(&self, context: &LookupContext) -> Result<ResolvedDir<'_>, WalkError> {
        Ok(self.resolved_directory(ProcDirectory {
            caller: context.caller,
            user: context.user,
            target: DirectoryTarget::Root,
        }))
    }

    fn resolve_with_context<'a>(
        &'a self,
        context: &LookupContext,
        from: ResolvedDir<'a>,
        components: &[&str],
        authorize: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        let mut current = from;
        for (index, name) in components.iter().enumerate() {
            let fail = |error| ResolutionError {
                component: Some(index),
                error,
            };
            let mut directory = current.into_typed::<Self>();
            directory.user = context.user;
            check_live(&directory).map_err(|error| fail(error.into()))?;
            if !Self::directory_access_is_unconditional(&directory) {
                let status = self.directory_status(&directory);
                authorize(&PermissionInfo {
                    mode: status.mode,
                    owner: status.owner,
                    on_read_only_fs: false,
                })
                .map_err(fail)?;
            }
            let node = match ProcEntry::from_name(&directory.target, name) {
                Some(entry) => self
                    .entry_node(entry, &directory.target)
                    .map_err(|error| fail(error.into()))?,
                None => None,
            };
            if let Some(node) = node {
                if index + 1 != components.len() {
                    return Err(ResolutionError {
                        component: Some(index + 1),
                        error: PathError::ComponentNotADirectory.into(),
                    });
                }
                let permissions = self.file_permissions(&node);
                let file_type = self.file_status(&node).file_type;
                return Ok(Resolution::Found(ResolvedTarget::File(
                    ResolvedFile::from_typed::<Self>(node, permissions, file_type),
                )));
            }
            if let DirectoryTarget::Descriptors(_) = &directory.target {
                // The caller resolves its own descriptors; one cannot yet lead elsewhere.
                return Err(fail(match descriptor_number(name) {
                    Some(number) if index + 1 == components.len() => {
                        PathError::CallerObject(number).into()
                    }
                    Some(_) => PathError::ComponentNotADirectory.into(),
                    None if index + 1 == components.len() => {
                        return Ok(Resolution::MissingFinal {
                            parent: self.resolved_directory(directory),
                        });
                    }
                    None => PathError::NoSuchFileOrDirectory.into(),
                }));
            }
            if let DirectoryTarget::Process(process) = &directory.target
                && *name == "fd"
            {
                current = self.resolved_directory(ProcDirectory {
                    caller: directory.caller,
                    user: context.user,
                    target: DirectoryTarget::Descriptors(Arc::clone(process)),
                });
                continue;
            }
            if let DirectoryTarget::Root = directory.target {
                let process = self
                    .state
                    .process(context.caller)
                    .map_err(|error| fail(error.into()))?;
                if *name == process.caller.process_id.0.to_string() {
                    current = self.resolved_directory(ProcDirectory {
                        caller: context.caller,
                        user: context.user,
                        target: DirectoryTarget::Process(process),
                    });
                    continue;
                }
            }
            if index + 1 == components.len() {
                return Ok(Resolution::MissingFinal {
                    parent: self.resolved_directory(directory),
                });
            }
            return Err(fail(PathError::NoSuchFileOrDirectory.into()));
        }
        Ok(Resolution::Found(ResolvedTarget::Dir(current)))
    }

    fn read_link_at_with_context(
        &self,
        context: &LookupContext,
        dir: &ResolvedDir<'_>,
        name: &str,
    ) -> Result<String, WalkError> {
        match self.follow_link_at(context, dir, name)? {
            LinkTarget::Path(path) => Ok(path),
            LinkTarget::File(target) => {
                let mut path = target.display_path();
                if target.is_unlinked() {
                    path.push_str(" (deleted)");
                }
                Ok(path)
            }
        }
    }

    fn follow_link_at(
        &self,
        context: &LookupContext,
        dir: &ResolvedDir<'_>,
        name: &str,
    ) -> Result<LinkTarget, WalkError> {
        let directory = dir.get_typed::<Self>();
        check_live(directory)?;
        let entry =
            ProcEntry::from_name(&directory.target, name).ok_or(PathError::InvalidPathname)?;
        match (entry, &directory.target) {
            (ProcEntry::SelfLink, DirectoryTarget::Root) => Ok(LinkTarget::Path(
                self.state
                    .process(context.caller)?
                    .caller
                    .process_id
                    .0
                    .to_string(),
            )),
            // XXX: Linux follows `cwd` to the directory object itself; this re-walks the path
            // published at the last `chdir`, so it goes stale if that directory is renamed.
            (ProcEntry::Cwd, DirectoryTarget::Process(process)) => self
                .state
                .cwd(process)?
                .map(LinkTarget::Path)
                .ok_or_else(|| PathError::NoSuchFileOrDirectory.into()),
            (ProcEntry::Executable, DirectoryTarget::Process(process)) => self
                .state
                .executable(process)?
                .map(LinkTarget::File)
                .ok_or_else(|| PathError::NoSuchFileOrDirectory.into()),
            // A generated file is not a link, which `readlink` reports as `EINVAL`.
            _ => Err(PathError::InvalidPathname.into()),
        }
    }

    fn open_dir(&self, dir: ResolvedDir<'_>, flags: OFlags) -> Result<DirHandle, OpenError> {
        // Like Linux, which refuses to write any directory.
        if !flags.contains(OFlags::PATH)
            && flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::CREAT | OFlags::TRUNC)
        {
            return Err(TruncateError::IsDirectory.into());
        }
        let directory = dir.into_typed::<Self>();
        check_live(&directory)?;
        if !flags.contains(OFlags::PATH)
            && !self.directory_permits(&directory, [Mode::RUSR, Mode::RGRP, Mode::ROTH])
        {
            return Err(OpenError::AccessNotAllowed);
        }
        Ok(DirHandle::from_typed::<Self>(directory))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<ResolvedDir<'a>> {
        Some(self.resolved_directory(dir.get_typed::<Self>().clone()))
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        self.open_node(file.into_typed::<Self>(), flags)
    }

    fn reopen_file(&self, file: &FileHandle, flags: OFlags) -> Result<FileHandle, OpenError> {
        self.open_node(file.get_typed::<Self>().clone(), flags)
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        let directory = handle.into_typed::<Self>();
        check_live(&directory)?;
        let (process, descriptors) = match &directory.target {
            DirectoryTarget::Root => (Some(self.state.process(directory.caller)?), None),
            DirectoryTarget::Process(process) => (None, Some(process.fd_node)),
            DirectoryTarget::Descriptors(_) => return Err(PathError::CallerObjects.into()),
        };
        let mut entries = Vec::new();
        if let Some(node) = descriptors {
            entries.push(DirEntry {
                name: String::from("fd"),
                file_type: FileType::Directory,
                ino_info: Some(node),
            });
        }
        for &(name, entry) in ProcEntry::in_directory(&directory.target) {
            if let Some(node) = self.entry_node(entry, &directory.target)? {
                let status = self.file_status(&node);
                entries.push(DirEntry {
                    name: String::from(name),
                    file_type: status.file_type,
                    ino_info: Some(status.node_info),
                });
            }
        }
        if let Some(process) = process {
            entries.push(DirEntry {
                name: process.caller.process_id.0.to_string(),
                file_type: FileType::Directory,
                ino_info: Some(process.node),
            });
        }
        Ok(entries)
    }

    fn read(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
    ) -> Result<usize, ReadError> {
        let ProcFile::Generated(file) = h.get_typed::<Self>() else {
            return Err(ReadError::NotForReading);
        };
        if buf.is_empty() {
            return Ok(0);
        }
        let mut snapshot = file.snapshot.lock();
        if snapshot.as_ref().is_none_or(|s| s.next_offset != offset) {
            // Generation takes broker process locks; never hold the snapshot lock across it.
            drop(snapshot);
            let text = self.state.generate(&file.process, file.kind)?;
            snapshot = file.snapshot.lock();
            *snapshot = Some(GeneratedSnapshot {
                text,
                next_offset: offset,
            });
        }
        let snapshot = snapshot.as_mut().unwrap();
        let start = offset.min(snapshot.text.len());
        let end = offset.saturating_add(buf.len()).min(snapshot.text.len());
        buf.copy_from_slice_at(0, &snapshot.text[start..end])?;
        let count = end - start;
        snapshot.next_offset = offset.saturating_add(count);
        Ok(count)
    }

    fn write(
        &self,
        _h: &FileHandle,
        _buf: &dyn WriteBuffer,
        _offset: usize,
    ) -> Result<usize, WriteError> {
        Err(WriteError::NotForWriting)
    }

    fn truncate(&self, _h: &FileHandle, _length: usize) -> Result<(), TruncateError> {
        Err(TruncateError::NotOpenForWriting)
    }

    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior {
        match h.get_typed::<Self>() {
            ProcFile::Link(_) => SeekBehavior::NonSeekable,
            ProcFile::Generated(_) => SeekBehavior::UnsizedPosition,
        }
    }

    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        Ok(match h {
            HandleRef::Dir(dir) => self.directory_status(dir.get_typed::<Self>()),
            HandleRef::File(file) => self.file_status(file.get_typed::<Self>()),
        })
    }

    fn resolved_status(&self, target: &ResolvedTarget<'_>) -> Result<FileStatus, FileStatusError> {
        Ok(match target {
            ResolvedTarget::Dir(dir) => self.directory_status(dir.get_typed::<Self>()),
            ResolvedTarget::File(file) => self.file_status(file.get_typed::<Self>()),
        })
    }

    fn create_file_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        _metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        Err(if self.name_exists(dir, name)? {
            OpenError::AlreadyExists
        } else {
            PathError::NoSuchFileOrDirectory.into()
        })
    }
    fn symlink_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        _target: &str,
        _metadata: CreationMetadata,
    ) -> Result<(), SymlinkError> {
        Err(if self.name_exists(dir, name)? {
            SymlinkError::AlreadyExists
        } else {
            PathError::NoSuchFileOrDirectory.into()
        })
    }
    fn mkdir_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        _metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        Err(if self.name_exists(dir, name)? {
            MkdirError::AlreadyExists
        } else {
            PathError::NoSuchFileOrDirectory.into()
        })
    }
    fn unlink_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), UnlinkError> {
        // XXX: Linux fails root, which passes the write check, with EPERM; backends are not told
        // the acting user here.
        Err(if self.name_exists(dir, name)? {
            UnlinkError::NoWritePerms
        } else {
            PathError::NoSuchFileOrDirectory.into()
        })
    }
    fn rmdir_at(&self, _dir: ResolvedDir<'_>, _name: &str) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
    }
    fn rename_at(
        &self,
        _old: DirHandle,
        _old_name: &str,
        _new: DirHandle,
        _new_name: &str,
    ) -> Result<(), RenameError> {
        Err(RenameError::ReadOnlyFileSystem)
    }
    fn set_times(
        &self,
        _target: ResolvedTarget<'_>,
        _times: &litebox_broker_core::fs::SetFileTimes,
    ) -> Result<(), litebox_broker_core::fs::errors::SetTimesError> {
        Err(litebox_broker_core::fs::errors::SetTimesError::ReadOnlyFileSystem)
    }

    fn chmod(&self, _h: ResolvedTarget<'_>, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::NotTheOwner)
    }
    fn chmod_handle(&self, _h: HandleRef<'_>, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::NotTheOwner)
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
