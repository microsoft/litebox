// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-side Linux procfs provider, enabled with the `procfs` feature.
//!
//! Mount [`ProcFs`] through the broker's filesystem composer. Trusted startup/state-publication
//! code must retain one [`ProcessRegistration`] per live Linux process. This initial subset
//! exposes only `self` and the accessing process's directory; it does not expose host procfs,
//! other processes, generated files, or object-backed magic links.

use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, Ordering};

use litebox_broker_core::{
    BrokerProcess,
    fs::{
        DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, UserInfo,
        backend::{
            Backend, BackendHandles, CreationMetadata, DirHandle, FileCaller, FileHandle,
            HandleRef, LookupContext, PermissionCheck, PermissionInfo, Resolution, ResolvedDir,
            ResolvedFile, ResolvedTarget, SeekBehavior,
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

/// Read-only procfs namespace with bounded, explicitly registered process state.
///
/// Clones share both the namespace and registrations. A registration's lifetime is independent
/// of the provider handle used to create it.
pub struct ProcFs<Platform: RawSyncPrimitivesProvider> {
    registry: Arc<Registry<Platform>>,
}

struct Registry<Platform: RawSyncPrimitivesProvider> {
    processes: Mutex<Platform, Vec<Arc<Process>>>,
    allocator: InodeAllocator,
    limit: usize,
    root: NodeInfo,
    self_link: NodeInfo,
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

/// An opened `O_PATH | O_NOFOLLOW` reference to the `self` link.
#[derive(Clone)]
pub struct ProcSelfLink;

impl<Platform: RawSyncPrimitivesProvider> Clone for ProcFs<Platform> {
    fn clone(&self) -> Self {
        Self {
            registry: Arc::clone(&self.registry),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider> ProcFs<Platform> {
    /// Construct a namespace allowing at most `max_processes` live registrations.
    ///
    /// Zero permits the root directory but rejects every process registration.
    #[must_use]
    pub fn new(allocator: InodeAllocator, max_processes: usize) -> Self {
        let root = allocator.next();
        let self_link = allocator.next();
        Self {
            registry: Arc::new(Registry {
                processes: Mutex::new(Vec::new()),
                allocator,
                limit: max_processes,
                root,
                self_link,
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

    fn register(
        &self,
        caller: FileCaller,
        owner: UserInfo,
    ) -> Result<ProcessRegistration<Platform>, RegistrationError> {
        let mut processes = self.registry.processes.lock();
        if processes.iter().any(|process| {
            process.caller.process_key == caller.process_key
                || process.caller.process_id == caller.process_id
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
            live: AtomicBool::new(true),
        });
        processes.push(Arc::clone(&process));
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
            .find(|process| process.caller == caller)
            .cloned()
            .ok_or(PathError::NoSuchFileOrDirectory)
    }

    fn directory_status(&self, directory: &ProcDirectory) -> FileStatus {
        let (node_info, owner) = match &directory.target {
            DirectoryTarget::Root => (self.registry.root, UserInfo::ROOT),
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

    fn link_status(&self, _link: &ProcSelfLink) -> FileStatus {
        FileStatus {
            file_type: FileType::SymbolicLink,
            mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
            size: 0,
            owner: UserInfo::ROOT,
            node_info: self.registry.self_link,
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
        processes.retain(|process| !Arc::ptr_eq(process, &self.process));
    }
}

impl<Platform: RawSyncPrimitivesProvider> BackendHandles for ProcFs<Platform> {
    type ResolvedDir<'a> = ProcDirectory;
    type ResolvedFile<'a> = ProcSelfLink;
    type DirHandle = ProcDirectory;
    type FileHandle = ProcSelfLink;
}

impl<Platform: RawSyncPrimitivesProvider> Backend for ProcFs<Platform> {
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
            if let DirectoryTarget::Root = directory.target {
                if *name == "self" {
                    if index + 1 != components.len() {
                        return Err(ResolutionError {
                            component: Some(index + 1),
                            error: PathError::ComponentNotADirectory.into(),
                        });
                    }
                    let link = ProcSelfLink;
                    let status = self.link_status(&link);
                    return Ok(Resolution::Found(ResolvedTarget::File(
                        ResolvedFile::from_typed::<Self>(
                            link,
                            permissions(status),
                            FileType::SymbolicLink,
                        ),
                    )));
                }
                let process = self
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
        if !matches!(dir.get_typed::<Self>().target, DirectoryTarget::Root) || name != "self" {
            return Err(PathError::InvalidPathname.into());
        }
        Ok(self
            .process(context.caller)?
            .caller
            .process_id
            .0
            .to_string())
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
        match directory.target {
            DirectoryTarget::Process(_) => Ok(Vec::new()),
            DirectoryTarget::Root => {
                let process = self.process(directory.caller)?;
                Ok(vec![
                    DirEntry {
                        name: String::from("self"),
                        file_type: FileType::SymbolicLink,
                        ino_info: Some(self.registry.self_link),
                    },
                    DirEntry {
                        name: process.caller.process_id.0.to_string(),
                        file_type: FileType::Directory,
                        ino_info: Some(process.node),
                    },
                ])
            }
        }
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
