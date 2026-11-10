// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-side Linux procfs provider, enabled with the `procfs` feature.
//!
//! Inject a shared [`ProcState`] into [`ProcFs`] and mount it through the filesystem composer.
//! Enable automatic registration
//! with [`ProcFs::with_process_lifecycle`], or retain a [`ProcessRegistration`] per live process.
//! This subset exposes `self`, the accessing process's directory, and a read-only object-backed
//! `exe` link after trusted publication. It never exposes host procfs or other processes.

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
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
            PermissionInfo, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget, SeekBehavior,
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

/// Shared, bounded controller for procfs registration and executable publication.
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
    executable: Option<FileTarget>,
}

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
    owner: UserInfo,
    node: NodeInfo,
    executable_node: NodeInfo,
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
    Executable,
}

impl ProcEntry {
    fn in_directory(directory: &DirectoryTarget) -> &'static [(&'static str, Self)] {
        match directory {
            DirectoryTarget::Root => &[("self", Self::SelfLink)],
            DirectoryTarget::Process(_) => &[("exe", Self::Executable)],
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
    /// Process-incarnation-bound executable link.
    Executable(ProcExecutableLink),
}

/// Retained identity of an executable-link inode, without retaining its old image.
#[derive(Clone)]
pub struct ProcExecutableLink {
    process: Arc<Process>,
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
        process: &BrokerProcess,
        owner: UserInfo,
    ) -> Result<ProcessRegistration<Platform>, RegistrationError> {
        self.register(
            FileCaller {
                process_key: process.key(),
                process_id: process.id(),
            },
            owner,
        )
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
        let mut processes = self.registry.processes.lock();
        let entry = processes
            .iter_mut()
            .find(|entry| entry.process.caller == caller)
            .ok_or(litebox_broker_protocol::fs::FileError::NoSuchFileOrDirectory)?;
        let old = entry.executable.replace(target);
        drop(processes);
        drop(old);
        Ok(())
    }

    fn executable(&self, process: &Process) -> Result<Option<FileTarget>, PathError> {
        self.registry
            .processes
            .lock()
            .iter()
            .find(|entry| entry.process.caller == process.caller)
            .map(|entry| entry.executable.clone())
            .ok_or(PathError::NoSuchFileOrDirectory)
    }

    fn register(
        &self,
        caller: FileCaller,
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
            owner,
            node: self.registry.allocator.next(),
            executable_node: self.registry.allocator.next(),
            live: AtomicBool::new(true),
        });
        processes.push(RegisteredProcess {
            process: Arc::clone(&process),
            executable: None,
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
        caller: FileCaller,
        parent: Option<FileCaller>,
        root_owner: UserInfo,
    ) -> litebox_broker_core::Result<Box<dyn Send + Sync>> {
        use litebox_broker_core::BrokerError;

        let (owner, executable) = match parent {
            Some(parent) => {
                let process = self
                    .process(Some(parent))
                    .map_err(|_| BrokerError::PeerClosed)?;
                let executable = self
                    .executable(&process)
                    .map_err(|_| BrokerError::PeerClosed)?;
                (process.owner, executable)
            }
            None => (root_owner, None),
        };
        let registration = self.register(caller, owner).map_err(|error| match error {
            RegistrationError::Capacity => BrokerError::ResourceExhausted,
            RegistrationError::AlreadyRegistered => BrokerError::Internal,
        })?;
        if let Some(executable) = executable {
            self.publish_executable(caller, executable)
                .map_err(|_| BrokerError::PeerClosed)?;
        }
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

    fn entry_link(
        &self,
        entry: ProcEntry,
        directory: &DirectoryTarget,
    ) -> Result<Option<ProcLink>, PathError> {
        match (entry, directory) {
            (ProcEntry::SelfLink, DirectoryTarget::Root) => Ok(Some(ProcLink::SelfLink)),
            (ProcEntry::Executable, DirectoryTarget::Process(process)) => {
                Ok(self.state.executable(process)?.map(|_| {
                    ProcLink::Executable(ProcExecutableLink {
                        process: Arc::clone(process),
                    })
                }))
            }
            _ => Err(PathError::InvalidPathname),
        }
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

    fn link_status(&self, link: &ProcLink) -> FileStatus {
        let (owner, node_info) = match link {
            ProcLink::SelfLink => (UserInfo::ROOT, self.self_link),
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
    fn publish_file(
        &self,
        caller: FileCaller,
        key: u64,
        target: FileTarget,
    ) -> litebox_broker_core::fs::FileResult<()> {
        if key != crate::EXECUTABLE_FILE_PUBLICATION_KEY {
            return Err(litebox_broker_protocol::fs::FileError::NotSupported);
        }
        self.publish_executable(caller, target)
    }
}

impl<Platform: RawSyncPrimitivesProvider> BackendHandles for ProcFs<Platform> {
    type ResolvedDir<'a> = ProcDirectory;
    type ResolvedFile<'a> = ProcLink;
    type DirHandle = ProcDirectory;
    type FileHandle = ProcLink;
}

impl<Platform: RawSyncPrimitivesProvider> Backend for ProcFs<Platform> {
    fn process_created(
        &self,
        caller: FileCaller,
        parent: Option<FileCaller>,
    ) -> litebox_broker_core::Result<Box<dyn Send + Sync>> {
        let Some(root_owner) = self.lifecycle_owner else {
            return Ok(Box::new(()));
        };
        self.state.process_created(caller, parent, root_owner)
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
            let link = match ProcEntry::from_name(&directory.target, name) {
                Some(entry) => self
                    .entry_link(entry, &directory.target)
                    .map_err(|error| fail(error.into()))?,
                None => None,
            };
            if let Some(link) = link {
                if index + 1 != components.len() {
                    return Err(ResolutionError {
                        component: Some(index + 1),
                        error: PathError::ComponentNotADirectory.into(),
                    });
                }
                let status = self.link_status(&link);
                return Ok(Resolution::Found(ResolvedTarget::File(
                    ResolvedFile::from_typed::<Self>(link, permissions(status), status.file_type),
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
            (ProcEntry::Executable, DirectoryTarget::Process(process)) => self
                .state
                .executable(process)?
                .map(LinkTarget::File)
                .ok_or_else(|| PathError::NoSuchFileOrDirectory.into()),
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
        if !flags.contains(OFlags::PATH | OFlags::NOFOLLOW) {
            return Err(PathError::TooManySymlinks.into());
        }
        Ok(FileHandle::from_typed::<Self>(file.into_typed::<Self>()))
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
            if let Some(link) = self.entry_link(entry, &directory.target)? {
                let status = self.link_status(&link);
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
        _h: &FileHandle,
        _buf: &mut dyn ReadBuffer,
        _offset: usize,
    ) -> Result<usize, ReadError> {
        Err(ReadError::NotForReading)
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

    fn seek_behavior(&self, _h: &FileHandle) -> SeekBehavior {
        SeekBehavior::NonSeekable
    }

    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        Ok(match h {
            HandleRef::Dir(dir) => self.directory_status(dir.get_typed::<Self>()),
            HandleRef::File(file) => self.link_status(file.get_typed::<Self>()),
        })
    }

    fn resolved_status(&self, target: &ResolvedTarget<'_>) -> Result<FileStatus, FileStatusError> {
        Ok(match target {
            ResolvedTarget::Dir(dir) => self.directory_status(dir.get_typed::<Self>()),
            ResolvedTarget::File(file) => self.link_status(file.get_typed::<Self>()),
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
