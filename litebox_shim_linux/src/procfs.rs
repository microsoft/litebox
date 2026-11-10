// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-side Linux procfs provider, enabled with the `procfs` feature.
//!
//! Inject a shared [`ProcState`] into [`ProcFs`] and mount it through the filesystem composer.
//! Enable automatic registration
//! with [`ProcFs::with_process_lifecycle`], or retain a [`ProcessRegistration`] per live process.
//! This subset exposes `self`, the accessing process's directory, a read-only object-backed
//! `exe` link, a path-based `cwd` link, and generated `limits` and `status` files, each after
//! trusted publication. It never exposes host procfs or other processes.

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, Ordering};

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
    /// The `Uid`, `Gid`, and `Groups` lines.
    credentials: Option<Arc<[u8]>>,
}

/// The most bytes a process may publish as its `limits` text; Linux's is under 1.5 KiB.
const MAX_LIMITS_TEXT: usize = 4096;
/// The most bytes a process may publish as an escaped `status` name, of at most 15 bytes.
const MAX_STATUS_NAME: usize = 64;
/// The most bytes a process may publish as its `status` umask.
const MAX_STATUS_UMASK: usize = 8;
/// The most bytes a process may publish as its `status` credential lines.
const MAX_STATUS_CREDENTIALS: usize = 1024;

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
    /// Either this process key or its visible PID already has a live registration.
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
    owner: UserInfo,
    node: NodeInfo,
    executable_node: NodeInfo,
    cwd_node: NodeInfo,
    limits_node: NodeInfo,
    status_node: NodeInfo,
    live: AtomicBool,
}

/// A directory bound either to the namespace or to a particular process incarnation.
#[derive(Clone)]
pub struct ProcDirectory {
    caller: Option<FileCaller>,
    target: DirectoryTarget,
}

#[derive(Clone)]
enum DirectoryTarget {
    Root,
    Process(Arc<Process>),
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
    /// A link.
    Link(ProcLink),
    /// A generated file.
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
/// Reads see one snapshot of the generated text, taken by the first read and again by each read
/// that starts at offset zero, so reads at increasing offsets never splice two snapshots, and
/// rewinding refreshes the text.
pub struct ProcGeneratedFile<Platform: RawSyncPrimitivesProvider> {
    process: Arc<Process>,
    kind: GeneratedKind,
    snapshot: Arc<Mutex<Platform, Option<Arc<[u8]>>>>,
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
    pub fn register_process(
        &self,
        process: &Arc<BrokerProcess>,
        owner: UserInfo,
    ) -> Result<ProcessRegistration<Platform>, RegistrationError> {
        self.register_broker_process(process, owner)
    }

    /// Publish this process's executable as a retained readable regular file.
    ///
    /// This trusted broker-side state-source API atomically replaces the image capability.
    /// Following `exe` never reopens its display path. Runner-to-broker publication is a
    /// separate transport concern; this method must receive an authenticated association.
    pub fn set_executable(
        &self,
        process: &BrokerProcess,
        handle: litebox_broker_protocol::ObjectHandle,
    ) -> litebox_broker_core::Result<litebox_broker_core::fs::FileResult<()>> {
        let target = match litebox_broker_core::fs::retain_file(process, handle)? {
            Ok(target) => target,
            Err(error) => return Ok(Err(error)),
        };
        let caller = FileCaller {
            process_key: process.key(),
            process_id: process.id(),
        };
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
        text.extend_from_slice(&credentials);
        text.extend_from_slice(alloc::format!("Threads:\t{threads}\n").as_bytes());
        Ok(text.into())
    }

    fn register_broker_process(
        &self,
        broker: &Arc<BrokerProcess>,
        owner: UserInfo,
    ) -> Result<ProcessRegistration<Platform>, RegistrationError> {
        let caller = FileCaller {
            process_key: broker.key(),
            process_id: broker.id(),
        };
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
        if processes.iter().any(|entry| {
            entry.process.caller.process_key == caller.process_key
                || entry.process.caller.process_id == caller.process_id
        }) {
            return Err(RegistrationError::AlreadyRegistered);
        }
        if processes.len() >= self.registry.limit {
            return Err(RegistrationError::Capacity);
        }
        let process = Arc::new(Process {
            caller,
            broker,
            owner,
            node: self.registry.allocator.next(),
            executable_node: self.registry.allocator.next(),
            cwd_node: self.registry.allocator.next(),
            limits_node: self.registry.allocator.next(),
            status_node: self.registry.allocator.next(),
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

        let caller = FileCaller {
            process_key: broker.key(),
            process_id: broker.id(),
        };
        let (owner, inherited) = match parent {
            Some(parent) => {
                let process = self
                    .process(Some(parent))
                    .map_err(|_| BrokerError::PeerClosed)?;
                let inherited = self
                    .published(&process, PublishedState::clone)
                    .map_err(|_| BrokerError::PeerClosed)?;
                (process.owner, inherited)
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
    /// events. Root processes start with `owner`; children inherit their creator's published
    /// owner. Configure this before mounting/cloning the provider.
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

    fn directory_status(&self, directory: &ProcDirectory) -> FileStatus {
        let (node_info, owner) = match &directory.target {
            DirectoryTarget::Root => (self.root, UserInfo::ROOT),
            DirectoryTarget::Process(process) => (process.node, process.owner),
        };
        FileStatus {
            file_type: FileType::Directory,
            mode: Mode::RUSR | Mode::XUSR | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
            size: 0,
            owner,
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
                owner: file.process.owner,
                node_info: match file.kind {
                    GeneratedKind::Limits => file.process.limits_node,
                    GeneratedKind::Status => file.process.status_node,
                },
                blksize: 0,
            },
        }
    }

    /// Permission checks for `file`: links, like directories, are on a read-only filesystem,
    /// while a generated file's mode alone refuses writes, so that opening one for writing fails
    /// with `EACCES` as on Linux.
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
            ProcLink::Cwd(link) => (link.process.owner, link.process.cwd_node),
            ProcLink::Executable(link) => (link.process.owner, link.process.executable_node),
        };
        FileStatus {
            file_type: FileType::SymbolicLink,
            mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
            size: 0,
            owner,
            node_info,
            blksize: 0,
        }
    }

    fn resolved_directory<'a>(&self, directory: ProcDirectory) -> ResolvedDir<'a> {
        let status = self.directory_status(&directory);
        ResolvedDir::from_typed::<Self>(directory, permissions(status))
    }
}

fn permissions(status: FileStatus) -> PermissionCheck {
    PermissionCheck::ByResolver(PermissionInfo {
        mode: status.mode,
        owner: status.owner,
        on_read_only_fs: true,
    })
}

fn check_live(directory: &ProcDirectory) -> Result<(), PathError> {
    if let DirectoryTarget::Process(process) = &directory.target
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

        let (max, valid): (usize, fn(&[u8]) -> bool) = match key {
            crate::LIMITS_DATA_PUBLICATION_KEY => (MAX_LIMITS_TEXT, |_| true),
            crate::STATUS_NAME_DATA_PUBLICATION_KEY => {
                (MAX_STATUS_NAME, |name| !name.contains(&b'\n'))
            }
            crate::STATUS_UMASK_DATA_PUBLICATION_KEY => (MAX_STATUS_UMASK, |umask| {
                !umask.is_empty() && umask.iter().all(|digit| (b'0'..=b'7').contains(digit))
            }),
            crate::STATUS_CREDENTIALS_DATA_PUBLICATION_KEY => {
                (MAX_STATUS_CREDENTIALS, |lines| lines.ends_with(b"\n"))
            }
            _ => return Err(FileError::NotSupported),
        };
        if data.len() > max || !valid(data) {
            return Err(FileError::InvalidArgument);
        }
        let data: Arc<[u8]> = data.into();
        let old = self.update(caller, |state| {
            let field = match key {
                crate::LIMITS_DATA_PUBLICATION_KEY => &mut state.limits,
                crate::STATUS_NAME_DATA_PUBLICATION_KEY => &mut state.status.name,
                crate::STATUS_UMASK_DATA_PUBLICATION_KEY => &mut state.status.umask,
                _ => &mut state.status.credentials,
            };
            field.replace(data)
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

    fn root(&self) -> Result<ResolvedDir<'_>, WalkError> {
        Ok(self.resolved_directory(ProcDirectory {
            caller: None,
            target: DirectoryTarget::Root,
        }))
    }

    fn root_with_context(&self, context: &LookupContext) -> Result<ResolvedDir<'_>, WalkError> {
        Ok(self.resolved_directory(ProcDirectory {
            caller: context.caller,
            target: DirectoryTarget::Root,
        }))
    }

    fn resolve<'a>(
        &'a self,
        from: ResolvedDir<'a>,
        components: &[&str],
        authorize: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        self.resolve_with_context(
            &LookupContext {
                caller: None,
                user: UserInfo::ROOT,
            },
            from,
            components,
            authorize,
        )
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
            if let PermissionCheck::ByResolver(info) = &current.permissions {
                authorize(info).map_err(fail)?;
            }
            let directory = current.into_typed::<Self>();
            check_live(&directory).map_err(|error| fail(error.into()))?;
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
            if let DirectoryTarget::Root = directory.target {
                let process = self
                    .state
                    .process(context.caller)
                    .map_err(|error| fail(error.into()))?;
                if *name == process.caller.process_id.0.to_string() {
                    current = self.resolved_directory(ProcDirectory {
                        caller: context.caller,
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

    fn read_link_at(&self, _dir: &ResolvedDir<'_>, _name: &str) -> Result<String, WalkError> {
        Err(PathError::NoSearchPerms.into())
    }

    fn read_link_at_with_context(
        &self,
        context: &LookupContext,
        dir: &ResolvedDir<'_>,
        name: &str,
    ) -> Result<String, WalkError> {
        match self.follow_link_at(context, dir, name)? {
            LinkTarget::Path(path) => Ok(path),
            LinkTarget::File(target) => Ok(String::from(target.display_path())),
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
        if !flags.contains(OFlags::PATH)
            && flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::CREAT | OFlags::TRUNC)
        {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        let directory = dir.into_typed::<Self>();
        check_live(&directory)?;
        Ok(DirHandle::from_typed::<Self>(directory))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<ResolvedDir<'a>> {
        Some(self.resolved_directory(dir.get_typed::<Self>().clone()))
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        if flags.contains(OFlags::DIRECTORY) {
            return Err(PathError::ComponentNotADirectory.into());
        }
        let file = match file.into_typed::<Self>() {
            ProcFile::Link(_) if !flags.contains(OFlags::PATH | OFlags::NOFOLLOW) => {
                return Err(PathError::TooManySymlinks.into());
            }
            ProcFile::Generated(_)
                if flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::TRUNC) =>
            {
                return Err(OpenError::AccessNotAllowed);
            }
            // Each open description reads its own snapshots.
            ProcFile::Generated(file) => ProcFile::Generated(ProcGeneratedFile {
                process: file.process,
                kind: file.kind,
                snapshot: Arc::new(Mutex::new(None)),
            }),
            link @ ProcFile::Link(_) => link,
        };
        Ok(FileHandle::from_typed::<Self>(file))
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        let directory = handle.into_typed::<Self>();
        check_live(&directory)?;
        let process = match &directory.target {
            DirectoryTarget::Root => Some(self.state.process(directory.caller)?),
            DirectoryTarget::Process(_) => None,
        };
        let mut entries = Vec::new();
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
        let text = {
            // Generating takes broker process locks, so it must not hold the snapshot's lock.
            let current = file.snapshot.lock().clone();
            match current {
                Some(text) if offset != 0 => text,
                _ => {
                    let text = self.state.generate(&file.process, file.kind)?;
                    *file.snapshot.lock() = Some(Arc::clone(&text));
                    text
                }
            }
        };
        let start = offset.min(text.len());
        let end = offset.saturating_add(buf.len()).min(text.len());
        buf.copy_from_slice_at(0, &text[start..end])?;
        Ok(end - start)
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
            ProcFile::Generated(_) => SeekBehavior::PositionBased,
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
    fn chmod(&self, _h: ResolvedTarget<'_>, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }
    fn chmod_handle(
        &self,
        _h: HandleRef<'_>,
        _user: UserInfo,
        _mode: Mode,
    ) -> Result<(), ChmodError> {
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
