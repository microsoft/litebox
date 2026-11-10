// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use alloc::sync::Arc;

use litebox_broker_protocol::fs::{
    FileAccessMode, FileError, FileMode, FileOpenFlags, FileStatus, FileUser,
};
use litebox_broker_protocol::{ObjectHandle, ThreadId};

use super::{
    MountPath, NewMount, bind, change_directory, change_root, mount, set_read_only, unmount,
};
use crate::fs::in_mem::InMem;
use crate::fs::inode_allocator::InodeAllocator;
use crate::fs::mount::MountInfo;
use crate::fs::resolver::Resolver;
use crate::fs::service::{PathStart, path_status_at};
use crate::fs::{FileResult, WorkingDirectory, working_directory};
use crate::object::ObjectRights;
use crate::readiness::ReadinessSink;
use crate::readiness::tests::TestReadinessSink;
use crate::test_platform::TestPlatform;
use crate::test_support::TestBrokerBuilder;
use crate::{BrokerProcess, CallerCredential, PolicyEngine};

const ROOT: FileUser = FileUser::ROOT;
const USER: FileUser = FileUser {
    user: 1000,
    group: 1000,
};
const DIR_MODE: FileMode = FileMode::RWXU
    .union(FileMode::RGRP)
    .union(FileMode::XGRP)
    .union(FileMode::ROTH)
    .union(FileMode::XOTH);

/// A process whose file system has the directories `/mnt`, `/dir`, `/dir/sub` and `/other`, and
/// the files `/dir/file` and `/target`.
pub(super) struct Fixture {
    pub(super) process: Arc<BrokerProcess>,
    pub(super) thread: ThreadId,
    readiness: Arc<dyn ReadinessSink>,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let fs = Resolver::<TestPlatform>::new(InMem::<TestPlatform>::new(
            InodeAllocator::for_device(1),
        ));
        for dir in ["/mnt", "/dir", "/dir/sub", "/other"] {
            fs.mkdir(ROOT, dir, DIR_MODE).unwrap();
        }
        let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_file_service(Arc::new(fs))
        .build()
        .unwrap();
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let fixture = Self {
            thread: process.initial_thread_id(),
            process,
            readiness: Arc::new(TestReadinessSink::default()),
        };
        fixture.write("/dir/file", b"file");
        fixture.write("/target", b"target");
        fixture
    }

    pub(super) fn open(
        &self,
        path: &str,
        access: FileAccessMode,
        flags: FileOpenFlags,
    ) -> FileResult<ObjectHandle> {
        crate::fs::open(
            &self.process,
            path,
            ROOT,
            access,
            flags,
            DIR_MODE,
            &self.readiness,
        )
        .unwrap()
    }

    /// Opens the directory at `path` for path-based operations.
    pub(super) fn open_dir(&self, path: &str) -> ObjectHandle {
        self.open(
            path,
            FileAccessMode::ReadOnly,
            FileOpenFlags::DIRECTORY | FileOpenFlags::PATH,
        )
        .unwrap()
    }

    /// Create or replace the file at `path` with `data`.
    pub(super) fn write(&self, path: &str, data: &[u8]) {
        let file = self
            .open(
                path,
                FileAccessMode::WriteOnly,
                FileOpenFlags::CREATE | FileOpenFlags::TRUNCATE,
            )
            .unwrap();
        assert_eq!(
            crate::fs::write(&self.process, file, &data, None),
            Ok(Ok(data.len()))
        );
        self.process.close_object_reference(file).unwrap();
    }

    pub(super) fn read(&self, path: &str) -> FileResult<String> {
        let file = self.open(path, FileAccessMode::ReadOnly, FileOpenFlags::NONE)?;
        let mut data = [0; 64];
        let read = crate::fs::read(&self.process, file, &mut data, Some(0))
            .unwrap()
            .unwrap();
        self.process.close_object_reference(file).unwrap();
        Ok(String::from(core::str::from_utf8(&data[..read]).unwrap()))
    }

    /// The status of what `path` names from the thread's context.
    pub(super) fn status(&self, path: &str) -> FileResult<FileStatus> {
        let start = PathStart {
            thread: Some(self.thread),
            base: None,
        };
        path_status_at(&self.process, start, path, ROOT, true).unwrap()
    }

    pub(super) fn dev(&self, path: &str) -> u64 {
        self.status(path).unwrap().node_info.dev
    }

    pub(super) fn mkdir(&self, path: &str) -> FileResult<()> {
        crate::fs::mkdir(&self.process, path, ROOT, DIR_MODE).unwrap()
    }

    pub(super) fn tmpfs(&self, path: &str) -> FileResult<()> {
        self.tmpfs_with(path, false)
    }

    fn tmpfs_with(&self, path: &str, read_only: bool) -> FileResult<()> {
        let source = NewMount::Tmpfs {
            mode: DIR_MODE,
            owner: ROOT,
        };
        let info = MountInfo {
            fs_type: String::from("tmpfs"),
            ..MountInfo::default()
        };
        mount(
            &self.process,
            self.thread,
            ROOT,
            MountPath::path(path),
            source,
            info,
            read_only,
        )
        .unwrap()
    }

    pub(super) fn bind(&self, source: &str, target: &str, recursive: bool) -> FileResult<()> {
        bind(
            &self.process,
            self.thread,
            ROOT,
            MountPath::path(source),
            MountPath::path(target),
            recursive,
        )
        .unwrap()
    }

    pub(super) fn unmount(&self, target: MountPath<'_>, detach: bool) -> FileResult<()> {
        unmount(&self.process, self.thread, ROOT, target, detach).unwrap()
    }

    fn set_read_only(&self, path: &str, read_only: bool) -> FileResult<()> {
        set_read_only(
            &self.process,
            self.thread,
            ROOT,
            MountPath::path(path),
            read_only,
        )
        .unwrap()
    }

    pub(super) fn chdir(&self, user: FileUser, target: MountPath<'_>) -> FileResult<()> {
        change_directory(&self.process, self.thread, user, target).unwrap()
    }
}

#[test]
fn mounts_show_until_unmounted() {
    let fixture = Fixture::new();
    fixture.tmpfs("/mnt").unwrap();
    fixture.mkdir("/mnt/new").unwrap();
    assert_ne!(fixture.dev("/mnt/new"), fixture.dev("/"));
    assert_eq!(fixture.dev("/mnt/new/.."), fixture.dev("/mnt"));

    fixture.unmount(MountPath::path("/mnt"), false).unwrap();
    assert_eq!(
        fixture.status("/mnt/new"),
        Err(FileError::NoSuchFileOrDirectory)
    );
    assert_eq!(fixture.dev("/mnt"), fixture.dev("/"));
    // Now `/mnt` is no mount's root, and `/` is the namespace's root mount.
    for path in ["/mnt", "/"] {
        assert_eq!(
            fixture.unmount(MountPath::path(path), true),
            Err(FileError::InvalidArgument)
        );
    }
    assert_eq!(fixture.tmpfs("/target"), Err(FileError::NotDirectory));
    assert_eq!(
        fixture.tmpfs("/missing"),
        Err(FileError::NoSuchFileOrDirectory)
    );
}

#[test]
fn unmounting_a_busy_mount_needs_detaching() {
    let fixture = Fixture::new();
    fixture.tmpfs("/mnt").unwrap();
    fixture.mkdir("/mnt/sub").unwrap();
    let file = fixture
        .open(
            "/mnt/file",
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
        )
        .unwrap();
    assert_eq!(
        fixture.unmount(MountPath::path("/mnt"), false),
        Err(FileError::Busy)
    );
    fixture.process.close_object_reference(file).unwrap();
    // So does a mount attached in it.
    fixture.tmpfs("/mnt/sub").unwrap();
    assert_eq!(
        fixture.unmount(MountPath::path("/mnt"), false),
        Err(FileError::Busy)
    );

    // Detached, a mount and the files open on it keep working, out of the namespace's sight.
    let file = fixture
        .open("/mnt/file", FileAccessMode::ReadWrite, FileOpenFlags::NONE)
        .unwrap();
    fixture.unmount(MountPath::path("/mnt"), true).unwrap();
    assert_eq!(
        fixture.status("/mnt/file"),
        Err(FileError::NoSuchFileOrDirectory)
    );
    assert_eq!(
        crate::fs::write(&fixture.process, file, &b"detached", Some(0)),
        Ok(Ok(8))
    );
    let mut data = [0; 8];
    assert_eq!(
        crate::fs::read(&fixture.process, file, &mut data, Some(0)),
        Ok(Ok(8))
    );
    assert_eq!(&data, b"detached");
}

#[test]
fn unmounting_names_the_top_of_the_stack_on_the_node() {
    let fixture = Fixture::new();
    fixture.tmpfs("/mnt").unwrap();
    let lower = fixture.open_dir("/mnt");
    fixture.tmpfs("/mnt").unwrap();
    fixture.mkdir("/mnt/top").unwrap();
    // The handle names the lower mount's root, and so the mount stacked there.
    fixture.unmount(MountPath::handle(lower), false).unwrap();
    assert_eq!(
        fixture.status("/mnt/top"),
        Err(FileError::NoSuchFileOrDirectory)
    );
    assert_ne!(fixture.dev("/mnt"), fixture.dev("/"));
}

#[test]
fn binds_show_a_node_elsewhere() {
    let fixture = Fixture::new();
    fixture.bind("/dir", "/other", false).unwrap();
    assert_eq!(
        fixture.status("/other/file").unwrap().node_info,
        fixture.status("/dir/file").unwrap().node_info
    );
    fixture.bind("/dir/file", "/target", false).unwrap();
    assert_eq!(fixture.read("/target"), Ok(String::from("file")));
    for (source, target) in [("/dir", "/target"), ("/dir/file", "/mnt")] {
        assert_eq!(
            fixture.bind(source, target, false),
            Err(FileError::NotDirectory)
        );
    }

    // Only a recursive bind copies the mounts below its source.
    fixture.tmpfs("/dir/sub").unwrap();
    fixture.write("/dir/sub/inner", b"inner");
    fixture.bind("/dir", "/mnt", false).unwrap();
    assert_eq!(
        fixture.status("/mnt/sub/inner"),
        Err(FileError::NoSuchFileOrDirectory)
    );
    fixture.unmount(MountPath::path("/mnt"), false).unwrap();
    fixture.bind("/dir", "/mnt", true).unwrap();
    assert_eq!(fixture.read("/mnt/sub/inner"), Ok(String::from("inner")));
    // The copy is a mount of its own: unmounting it leaves the original.
    fixture.unmount(MountPath::path("/mnt/sub"), false).unwrap();
    assert_eq!(fixture.read("/dir/sub/inner"), Ok(String::from("inner")));
}

#[test]
fn mounts_outside_the_namespace_cannot_change_its_tree() {
    let fixture = Fixture::new();
    fixture.tmpfs("/mnt").unwrap();
    let detached = MountPath::handle(fixture.open_dir("/mnt"));
    fixture.unmount(MountPath::path("/mnt"), true).unwrap();
    assert_eq!(
        bind(
            &fixture.process,
            fixture.thread,
            ROOT,
            detached,
            MountPath::path("/other"),
            false
        ),
        Ok(Err(FileError::InvalidArgument))
    );
    assert_eq!(
        fixture.unmount(detached, true),
        Err(FileError::InvalidArgument)
    );
    // A working directory may be anywhere, though.
    fixture.chdir(ROOT, detached).unwrap();
    assert_eq!(
        working_directory(&fixture.process, Some(fixture.thread)),
        Ok(WorkingDirectory::Unreachable(String::from("/")))
    );
}

#[test]
fn read_only_mounts_refuse_writes() {
    let fixture = Fixture::new();
    fixture.bind("/dir", "/other", false).unwrap();
    fixture.set_read_only("/other", true).unwrap();
    assert_eq!(fixture.mkdir("/other/new"), Err(FileError::ReadOnlyFs));
    assert_eq!(
        fixture.open(
            "/other/file",
            FileAccessMode::WriteOnly,
            FileOpenFlags::NONE
        ),
        Err(FileError::ReadOnlyFs)
    );
    assert_eq!(
        crate::fs::unlink(&fixture.process, "/other/file", ROOT),
        Ok(Err(FileError::ReadOnlyFs))
    );
    assert_eq!(fixture.read("/other/file"), Ok(String::from("file")));
    // Only through that mount.
    fixture.mkdir("/dir/new").unwrap();
    assert_eq!(
        fixture.set_read_only("/other/new", true),
        Err(FileError::InvalidArgument)
    );

    fixture.set_read_only("/other", false).unwrap();
    let writer = fixture
        .open(
            "/other/file",
            FileAccessMode::WriteOnly,
            FileOpenFlags::NONE,
        )
        .unwrap();
    assert_eq!(fixture.set_read_only("/other", true), Err(FileError::Busy));
    fixture.process.close_object_reference(writer).unwrap();
    fixture.set_read_only("/other", true).unwrap();
    fixture.tmpfs_with("/mnt", true).unwrap();
    assert_eq!(fixture.mkdir("/mnt/new"), Err(FileError::ReadOnlyFs));
}

#[test]
fn mount_points_cannot_be_removed_or_renamed_through_any_alias() {
    let fixture = Fixture::new();
    fixture.tmpfs("/dir/sub").unwrap();
    // The bind shows the mount point `/dir/sub` as `/other/sub` too, without the mount.
    fixture.bind("/dir", "/other", false).unwrap();
    for (from, to) in [
        ("/dir/sub", "/moved"),
        ("/dir", "/moved"),
        ("/other", "/mnt/moved"),
    ] {
        assert_eq!(
            crate::fs::rename(&fixture.process, from, to, ROOT),
            Ok(Err(FileError::Busy)),
            "{from}"
        );
    }
    assert_eq!(
        crate::fs::rmdir(&fixture.process, "/other/sub", ROOT),
        Ok(Err(FileError::Busy))
    );
    fixture.bind("/dir/file", "/target", false).unwrap();
    assert_eq!(
        crate::fs::unlink(&fixture.process, "/target", ROOT),
        Ok(Err(FileError::Busy))
    );
    assert_eq!(
        crate::fs::rename(&fixture.process, "/dir/sub/x", "/dir/x", ROOT),
        Ok(Err(FileError::CrossDevice))
    );

    fixture.unmount(MountPath::path("/target"), false).unwrap();
    fixture.unmount(MountPath::path("/dir/sub"), false).unwrap();
    crate::fs::rmdir(&fixture.process, "/other/sub", ROOT)
        .unwrap()
        .unwrap();
    crate::fs::unlink(&fixture.process, "/target", ROOT)
        .unwrap()
        .unwrap();
}

#[test]
fn changing_directories_changes_where_paths_start() {
    let fixture = Fixture::new();
    fixture.chdir(ROOT, MountPath::path("/dir")).unwrap();
    assert_eq!(fixture.status("file").unwrap().size, 4);
    // The process's default context is its initial thread's.
    assert_eq!(
        working_directory(&fixture.process, None),
        Ok(WorkingDirectory::Reachable(String::from("/dir")))
    );
    assert_eq!(
        fixture.chdir(ROOT, MountPath::path("file")),
        Err(FileError::NotDirectory)
    );
    crate::fs::chmod(&fixture.process, "/dir/sub", ROOT, FileMode::RWXU)
        .unwrap()
        .unwrap();
    assert_eq!(
        fixture.chdir(USER, MountPath::path("sub")),
        Err(FileError::NoSearchPermissions)
    );

    change_root(
        &fixture.process,
        fixture.thread,
        ROOT,
        MountPath::path("/dir"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(fixture.status("/file").unwrap().size, 4);
    assert_eq!(fixture.status("/../file").unwrap().size, 4);
    assert_eq!(
        working_directory(&fixture.process, Some(fixture.thread)),
        Ok(WorkingDirectory::Reachable(String::from("/")))
    );
}
