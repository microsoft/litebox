// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Read-only process directories and the caller-relative `self` symlink.

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use hashbrown::HashMap;
use litebox_broker_protocol::ProcessId;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use spin::Mutex;

use super::backend::{
    Backend, BackendHandles, Caller, CreationMetadata, DirHandle, FileHandle, HandleRef,
    PermissionCheck, PermissionInfo, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget,
    SeekBehavior,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RenameError, ResolutionError, RmdirError, SetTimesError, SymlinkError,
    TruncateError, UnlinkError, WalkError, WriteError,
};
use super::inode_allocator::InodeAllocator;
use super::{
    DEFAULT_DIRECTORY_SIZE, DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, SetFileTimes,
    UserInfo,
};
use crate::{BrokerProcess, ProcessKey};

/// The broker's procfs, intended to be mounted at `/proc` for Linux guests.
// XXX: Linux uses the mounter's PID namespace, not the caller's; bind mounts to one to match.
pub struct ProcFs {
    root: NodeInfo,
    self_link: NodeInfo,
    allocator: InodeAllocator,
    // Per mount: a process can appear in several procfs mounts.
    pid_inodes: Mutex<HashMap<ProcessKey, (Weak<BrokerProcess>, NodeInfo)>>,
}

/// Identity of a procfs directory, including the process's lifetime rather than just its PID.
#[derive(Clone)]
pub enum Directory {
    /// The mount root.
    Root,
    /// A process directory. The handle does not keep the process alive.
    Process(Weak<BrokerProcess>),
}

impl Directory {
    fn live_process(process: &Weak<BrokerProcess>) -> Result<Arc<BrokerProcess>, PathError> {
        process
            .upgrade()
            .filter(|p| !p.is_released())
            .ok_or(PathError::NoSuchFileOrDirectory)
    }

    fn visible_pid(
        process: &Weak<BrokerProcess>,
        caller: Caller<'_>,
    ) -> Result<ProcessId, PathError> {
        Self::live_process(process)?
            .process_id_in_namespace(requester(caller)?.pid_namespace())
            .ok_or(PathError::NoSuchFileOrDirectory)
    }
}

fn requester(caller: Caller<'_>) -> Result<&BrokerProcess, PathError> {
    // XXX: In-runner vfork children still make broker requests as their parent until exec.
    caller.process().ok_or(PathError::NoSuchFileOrDirectory)
}

fn parse_pid(name: &str) -> Option<ProcessId> {
    if !name.starts_with(|c| matches!(c, '1'..='9')) {
        return None;
    }
    name.parse().ok().map(ProcessId)
}

fn permissions(mode: Mode) -> PermissionCheck {
    PermissionCheck::ByResolver(PermissionInfo {
        mode,
        owner: UserInfo::ROOT,
        on_read_only_fs: true,
    })
}

const DIR_MODE: Mode = Mode::RUSR
    .union(Mode::XUSR)
    .union(Mode::RGRP)
    .union(Mode::XGRP)
    .union(Mode::ROTH)
    .union(Mode::XOTH);
const LINK_MODE: Mode = Mode::RWXU.union(Mode::RWXG).union(Mode::RWXO);

impl ProcFs {
    /// Constructs an empty procfs view. Processes are discovered from each request's caller.
    #[must_use]
    pub fn new(allocator: InodeAllocator) -> Self {
        Self {
            root: allocator.next(),
            self_link: allocator.next(),
            allocator,
            pid_inodes: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn caller_relative_name(name: &str) -> bool {
        matches!(name, "self" | "thread-self") || parse_pid(name).is_some()
    }

    fn resolved_dir<'a>(dir: Directory) -> ResolvedDir<'a> {
        ResolvedDir::from_typed::<Self>(dir, permissions(DIR_MODE))
    }

    fn pid_inode(&self, process: &Arc<BrokerProcess>) -> NodeInfo {
        let mut inodes = self.pid_inodes.lock();
        let key = process.key();
        if let Some((_, inode)) = inodes.get(&key) {
            return *inode;
        }
        // Don't upgrade the weak refs: dropping the last strong ref would run process cleanup.
        inodes.retain(|_, (process, _)| process.strong_count() != 0);
        let inode = self.allocator.next();
        inodes.insert(key, (Arc::downgrade(process), inode));
        inode
    }

    fn directory_status(&self, dir: &Directory) -> Result<FileStatus, FileStatusError> {
        let node_info = match dir {
            Directory::Root => self.root,
            Directory::Process(process) => {
                let process = Directory::live_process(process)?;
                self.pid_inode(&process)
            }
        };
        Ok(FileStatus {
            file_type: FileType::Directory,
            mode: DIR_MODE,
            size: DEFAULT_DIRECTORY_SIZE,
            owner: UserInfo::ROOT,
            node_info,
            times: None,
            blksize: DEFAULT_DIRECTORY_SIZE,
        })
    }

    fn symlink_status(&self, caller: Caller<'_>) -> Result<FileStatus, FileStatusError> {
        Ok(FileStatus {
            file_type: FileType::SymbolicLink,
            mode: LINK_MODE,
            size: requester(caller)?.id().0.to_string().len() as u64,
            owner: UserInfo::ROOT,
            node_info: self.self_link,
            times: None,
            blksize: DEFAULT_DIRECTORY_SIZE,
        })
    }
}

impl BackendHandles for ProcFs {
    type ResolvedDir<'a> = Directory;
    type ResolvedFile<'a> = ();
    type DirHandle = Directory;
    type FileHandle = ();
}

impl Backend for ProcFs {
    fn root(&self, _caller: Caller<'_>) -> Result<ResolvedDir<'_>, WalkError> {
        Ok(Self::resolved_dir(Directory::Root))
    }

    fn resolve<'a>(
        &'a self,
        caller: Caller<'_>,
        from: ResolvedDir<'a>,
        components: &[&str],
        authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        let mut current = from;
        for (index, &name) in components.iter().enumerate() {
            let fail = |error| ResolutionError {
                component: Some(index),
                error,
            };
            let PermissionCheck::ByResolver(info) = &current.permissions else {
                unreachable!()
            };
            authorize_dir_lookup(info).map_err(fail)?;
            match current.get_typed::<Self>() {
                Directory::Root => {
                    if let Some(process) = caller.process() {
                        if name == "self" {
                            if index + 1 < components.len() {
                                return Err(ResolutionError {
                                    component: Some(index + 1),
                                    error: PathError::ComponentNotADirectory.into(),
                                });
                            }
                            return Ok(Resolution::Found(ResolvedTarget::File(
                                ResolvedFile::from_typed::<Self>(
                                    (),
                                    permissions(LINK_MODE),
                                    FileType::SymbolicLink,
                                ),
                            )));
                        }
                        if let Some(target) = parse_pid(name)
                            .and_then(|pid| process.pid_namespace().registered_process(pid).ok())
                        {
                            current =
                                Self::resolved_dir(Directory::Process(Arc::downgrade(&target)));
                            continue;
                        }
                    }
                }
                Directory::Process(target) => {
                    Directory::visible_pid(target, caller).map_err(|error| fail(error.into()))?;
                    // XXX: Add fd/ and other process entries when the broker can supply their data.
                }
            }
            return if index + 1 == components.len() {
                Ok(Resolution::MissingFinal { parent: current })
            } else {
                Err(fail(PathError::NoSuchFileOrDirectory.into()))
            };
        }
        Ok(Resolution::Found(ResolvedTarget::Dir(current)))
    }

    fn read_link_at(
        &self,
        caller: Caller<'_>,
        dir: &ResolvedDir<'_>,
        name: &str,
    ) -> Result<String, WalkError> {
        if matches!(dir.get_typed::<Self>(), Directory::Root) && name == "self" {
            return Ok(requester(caller)?.id().0.to_string());
        }
        Err(PathError::NoSuchFileOrDirectory.into())
    }

    fn open_dir(&self, dir: ResolvedDir<'_>, flags: OFlags) -> Result<DirHandle, OpenError> {
        if flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::CREAT | OFlags::TRUNC) {
            return Err(OpenError::IsDirectory);
        }
        Ok(DirHandle::from_typed::<Self>(dir.into_typed::<Self>()))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Result<ResolvedDir<'a>, WalkError> {
        let dir = dir.get_typed::<Self>();
        if let Directory::Process(process) = dir {
            Directory::live_process(process)?;
        }
        Ok(Self::resolved_dir(dir.clone()))
    }

    fn dir_path(
        &self,
        caller: Caller<'_>,
        dir: &DirHandle,
    ) -> Result<Option<Vec<String>>, WalkError> {
        Ok(match dir.get_typed::<Self>() {
            Directory::Root => Some(Vec::new()),
            Directory::Process(p) if caller.process().is_some() => {
                Some(vec![Directory::visible_pid(p, caller)?.0.to_string()])
            }
            // A contextless walking snapshot cannot name a PID directory.
            Directory::Process(_) => None,
        })
    }

    fn parent_dir(
        &self,
        caller: Caller<'_>,
        dir: &DirHandle,
    ) -> Result<Option<DirHandle>, WalkError> {
        match dir.get_typed::<Self>() {
            Directory::Root => Ok(None),
            Directory::Process(p) => {
                Directory::visible_pid(p, caller)?;
                Ok(Some(DirHandle::from_typed::<Self>(Directory::Root)))
            }
        }
    }

    fn check_search_permission(&self, _dir: &ResolvedDir<'_>) -> Result<(), WalkError> {
        Ok(())
    }

    fn open_file(&self, _file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        assert!(flags.contains(OFlags::PATH | OFlags::NOFOLLOW));
        Ok(FileHandle::from_typed::<Self>(()))
    }

    fn list_dir_at(
        &self,
        caller: Caller<'_>,
        handle: DirHandle,
    ) -> Result<Vec<DirEntry>, ReadDirError> {
        if let Directory::Process(p) = handle.get_typed::<Self>() {
            Directory::visible_pid(p, caller).map_err(|_| ReadDirError::Removed)?;
            return Ok(Vec::new());
        }
        let Some(process) = caller.process() else {
            return Ok(Vec::new());
        };
        let namespace = process.pid_namespace();
        let mut entries = vec![DirEntry {
            name: String::from("self"),
            file_type: FileType::SymbolicLink,
            ino_info: Some(self.self_link),
        }];
        entries.extend(namespace.registered_processes().into_iter().map(|process| {
            DirEntry {
                name: process
                    .process_id_in_namespace(namespace)
                    .expect("registered in namespace")
                    .0
                    .to_string(),
                file_type: FileType::Directory,
                ino_info: Some(self.pid_inode(&process)),
            }
        }));
        Ok(entries)
    }

    fn status(&self, caller: Caller<'_>, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        match h {
            HandleRef::Dir(dir) => self.directory_status(dir.get_typed::<Self>()),
            HandleRef::File(_) => self.symlink_status(caller),
        }
    }

    fn resolved_status(
        &self,
        caller: Caller<'_>,
        target: &ResolvedTarget<'_>,
    ) -> Result<FileStatus, FileStatusError> {
        match target {
            ResolvedTarget::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                if let Directory::Process(p) = dir {
                    Directory::visible_pid(p, caller)?;
                }
                self.directory_status(dir)
            }
            ResolvedTarget::File(_) => self.symlink_status(caller),
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
        Err(TruncateError::NotForWriting)
    }

    fn seek_behavior(&self, _h: &FileHandle) -> SeekBehavior {
        SeekBehavior::NonSeekable
    }

    fn create_file_at(
        &self,
        _parent: ResolvedDir<'_>,
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
        _parent: ResolvedDir<'_>,
        _name: &str,
        _metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn unlink_at(&self, _parent: ResolvedDir<'_>, _name: &str) -> Result<(), UnlinkError> {
        Err(UnlinkError::ReadOnlyFileSystem)
    }

    fn rmdir_at(&self, _parent: ResolvedDir<'_>, _name: &str) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
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

    fn set_times(
        &self,
        _h: ResolvedTarget<'_>,
        _times: &SetFileTimes,
    ) -> Result<(), SetTimesError> {
        Err(SetTimesError::ReadOnlyFileSystem)
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
