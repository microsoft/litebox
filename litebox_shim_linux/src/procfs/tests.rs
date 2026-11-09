// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(target_os = "linux")]
extern crate std;

use super::*;
use crate::syscalls::tests::TestPlatform;
use alloc::format;
use litebox_broker_core::{
    CallerCredential, ObjectRights, PolicyEngine, ProcessKey,
    fs::{self, composer::Composer, in_mem::InMem, resolver::Resolver},
    readiness::ReadinessSink,
    test_support::TestBrokerBuilder,
};
use litebox_broker_protocol::{
    ObjectHandle, ProcessId,
    fs::{FileAccessMode, FileError, FileOpenFlags},
    readiness::ReadinessFlags,
};
use litebox_common_linux::errno::Errno;

const USER: UserInfo = UserInfo {
    user: 1000,
    group: 1000,
};

struct NoReadiness;

impl ReadinessSink for NoReadiness {
    fn max_tracked_objects(&self) -> usize {
        0
    }
    fn publish(
        &self,
        _handle: ObjectHandle,
        _flags: ReadinessFlags,
    ) -> litebox_broker_core::Result<()> {
        panic!("procfs must not publish readiness")
    }
    fn republish(
        &self,
        _handle: ObjectHandle,
        _flags: ReadinessFlags,
    ) -> litebox_broker_core::Result<()> {
        panic!("procfs must not republish readiness")
    }
    fn retire(&self, _handle: ObjectHandle) {
        panic!("procfs has no readiness registrations")
    }
}

struct Fixture {
    first: Arc<BrokerProcess>,
    second: Arc<BrokerProcess>,
    procfs: ProcFs<TestPlatform>,
    registrations: Vec<ProcessRegistration<TestPlatform>>,
    sink: Arc<dyn ReadinessSink>,
}

impl Fixture {
    fn new() -> Self {
        let mut provider = None;
        let backend = Composer::builder()
            .mount("/", InMem::<TestPlatform>::new)
            .mount("/proc", |allocator| {
                let procfs = ProcFs::new(allocator, 2);
                provider = Some(procfs.clone());
                procfs
            })
            .build()
            .unwrap();
        let fs = Resolver::<TestPlatform, _>::new(backend);
        fs.symlink(UserInfo::ROOT, "/proc/self", "/who").unwrap();
        let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_file_service(Arc::new(fs))
        .build()
        .unwrap();
        let first = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let second = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let procfs = provider.unwrap();
        let registrations = vec![
            procfs.register_process(&first, USER).unwrap(),
            procfs.register_process(&second, USER).unwrap(),
        ];
        Self {
            first,
            second,
            procfs,
            registrations,
            sink: Arc::new(NoReadiness),
        }
    }

    fn open(&self, process: &BrokerProcess, path: &str, flags: FileOpenFlags) -> ObjectHandle {
        fs::open(
            process,
            path,
            USER,
            FileAccessMode::ReadOnly,
            flags,
            Mode::empty(),
            &self.sink,
        )
        .unwrap()
        .unwrap()
    }
}

#[test]
fn self_is_a_real_link_into_a_caller_bound_directory() {
    let fixture = Fixture::new();
    for process in [&fixture.first, &fixture.second] {
        let pid = process.id().0.to_string();
        assert_eq!(
            fs::read_link(process, "/proc/self", USER).unwrap().unwrap(),
            pid
        );
        assert_eq!(
            fs::resolve_path(process, "/who", USER).unwrap().unwrap(),
            format!("/proc/{pid}")
        );
        let link = fs::path_status(process, "/proc/self", USER, false)
            .unwrap()
            .unwrap();
        assert_eq!(link.file_type, FileType::SymbolicLink);
        assert_eq!(link.size, 0);
        assert_eq!(link.owner, UserInfo::ROOT);
        let directory = fs::path_status(process, "/proc/self", USER, true)
            .unwrap()
            .unwrap();
        assert_eq!(directory.file_type, FileType::Directory);
        assert_eq!(directory.owner, USER);
        assert_ne!(link.node_info, directory.node_info);
        let handle = fixture.open(process, "/who", FileOpenFlags::NONE);
        assert_eq!(
            fs::handle_status(process, handle)
                .unwrap()
                .unwrap()
                .node_info,
            directory.node_info
        );
        let children = fs::read_directory(process, handle, 0).unwrap().unwrap();
        assert_eq!(
            children
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec![".", ".."],
        );
        let link_handle = fixture.open(
            process,
            "/proc/self",
            FileOpenFlags::PATH | FileOpenFlags::NO_FOLLOW,
        );
        assert_eq!(
            fs::handle_status(process, link_handle).unwrap().unwrap(),
            link
        );
        let root = fixture.open(process, "/proc", FileOpenFlags::NONE);
        let entries = fs::read_directory(process, root, 0).unwrap().unwrap();
        assert_eq!(entries.len(), 4);
        assert!(
            entries
                .iter()
                .any(|entry| entry.name == "self" && entry.file_type == FileType::SymbolicLink)
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.name == pid && entry.ino_info == Some(directory.node_info))
        );
    }
    let other_path = format!("/proc/{}", fixture.second.id().0);
    assert_eq!(
        fs::path_status(&fixture.first, &other_path, USER, true),
        Ok(Err(FileError::NoSuchFileOrDirectory)),
    );
    assert_eq!(
        fs::read_link(&fixture.first, "/proc/thread-self", USER),
        Ok(Err(FileError::NoSuchFileOrDirectory)),
    );
}

#[test]
fn mutation_and_unsupported_link_open_are_explicit_errors() {
    let fixture = Fixture::new();
    let process = &fixture.first;
    assert_eq!(
        fs::mkdir(process, "/proc/new", USER, Mode::RWXU),
        Ok(Err(FileError::ReadOnlyFs))
    );
    assert_eq!(
        fs::unlink(process, "/proc/self", USER),
        Ok(Err(FileError::ReadOnlyFs))
    );
    assert_eq!(
        fs::chmod(process, "/proc/self", USER, Mode::RWXU),
        Ok(Err(FileError::ReadOnlyFs))
    );
    assert_eq!(
        fs::symlink(process, "/elsewhere", "/proc/link", USER),
        Ok(Err(FileError::ReadOnlyFs))
    );
    assert_eq!(
        fs::open(
            process,
            "/proc/self",
            USER,
            FileAccessMode::ReadOnly,
            FileOpenFlags::NO_FOLLOW,
            Mode::empty(),
            &fixture.sink
        ),
        Ok(Err(FileError::TooManySymlinks)),
    );
    assert_eq!(
        fs::open(
            process,
            "/proc/self",
            USER,
            FileAccessMode::WriteOnly,
            FileOpenFlags::NONE,
            Mode::empty(),
            &fixture.sink
        ),
        Ok(Err(FileError::ReadOnlyFs)),
    );
}

#[test]
fn registration_exit_invalidates_lookup_and_directory_reads() {
    let mut fixture = Fixture::new();
    let handle = fixture.open(&fixture.first, "/proc/self", FileOpenFlags::NONE);
    let identity = fs::handle_status(&fixture.first, handle)
        .unwrap()
        .unwrap()
        .node_info;
    assert!(matches!(
        fixture.procfs.register_process(&fixture.first, USER),
        Err(RegistrationError::AlreadyRegistered)
    ));
    fixture.registrations.remove(0);
    assert_eq!(
        fs::read_link(&fixture.first, "/proc/self", USER),
        Ok(Err(FileError::NoSuchFileOrDirectory))
    );
    let error = fs::read_directory(&fixture.first, handle, 0)
        .unwrap()
        .unwrap_err();
    assert_eq!(error, FileError::NoSuchFileOrDirectory);
    let client_error: litebox::fs::errors::ReadDirError = error.into();
    assert_eq!(Errno::from(client_error), Errno::ENOENT);
    assert_eq!(
        fs::handle_status(&fixture.first, handle)
            .unwrap()
            .unwrap()
            .node_info,
        identity
    );
    assert_eq!(
        fs::read_link(&fixture.second, "/proc/self", USER)
            .unwrap()
            .unwrap(),
        fixture.second.id().0.to_string()
    );
}

fn caller(key: u64) -> FileCaller {
    FileCaller {
        process_key: ProcessKey::for_test(key),
        process_id: ProcessId(42),
    }
}

fn context(caller: FileCaller) -> LookupContext {
    LookupContext {
        caller: Some(caller),
        user: USER,
    }
}

fn process_directory(provider: &ProcFs<TestPlatform>, caller: FileCaller) -> DirHandle {
    let ctx = context(caller);
    let resolution = provider
        .resolve_with_context(
            &ctx,
            provider.root_with_context(&ctx).unwrap(),
            &["42"],
            &|_| Ok(()),
        )
        .unwrap();
    let Resolution::Found(ResolvedTarget::Dir(dir)) = resolution else {
        panic!("expected process directory")
    };
    provider.open_dir(dir, OFlags::RDONLY).unwrap()
}

#[test]
fn pid_reuse_never_retargets_held_directories_and_capacity_is_reclaimed() {
    let provider = ProcFs::<TestPlatform>::new(InodeAllocator::standalone(), 1);
    let first = provider.register(caller(1), USER).unwrap();
    assert!(matches!(
        provider.register(caller(2), USER),
        Err(RegistrationError::AlreadyRegistered)
    ));
    let other = FileCaller {
        process_id: ProcessId(43),
        ..caller(2)
    };
    assert!(matches!(
        provider.register(other, USER),
        Err(RegistrationError::Capacity)
    ));
    let old = process_directory(&provider, caller(1));
    let old_identity = provider.status(HandleRef::Dir(&old)).unwrap().node_info;
    drop(first);
    let _second = provider.register(caller(2), USER).unwrap();
    let new = process_directory(&provider, caller(2));
    assert_ne!(
        old_identity,
        provider.status(HandleRef::Dir(&new)).unwrap().node_info
    );
    assert_eq!(
        old_identity,
        provider.status(HandleRef::Dir(&old)).unwrap().node_info
    );
    assert!(matches!(
        provider.list_dir_at(old.clone()),
        Err(ReadDirError::PathError(PathError::NoSuchFileOrDirectory))
    ));
    assert_eq!(provider.list_dir_at(new).unwrap(), Vec::new());
    let ctx = context(caller(2));
    let error = provider
        .resolve_with_context(
            &ctx,
            provider.walking_dir_at(&old).unwrap(),
            &["child"],
            &|_| Ok(()),
        )
        .err()
        .unwrap();
    assert!(matches!(
        error.error,
        WalkError::PathError(PathError::NoSuchFileOrDirectory)
    ));
}

#[test]
fn missing_process_context_is_not_replaced_with_a_global_caller() {
    let provider = ProcFs::<TestPlatform>::new(InodeAllocator::standalone(), 1);
    let _registered = provider.register(caller(1), USER).unwrap();
    let fs = Resolver::<TestPlatform, _>::new(provider);
    assert!(matches!(
        fs.read_link(USER, "/self"),
        Err(WalkError::PathError(PathError::NoSearchPerms))
    ));
    let disabled = ProcFs::<TestPlatform>::new(InodeAllocator::standalone(), 0);
    assert!(matches!(
        disabled.register(caller(2), USER),
        Err(RegistrationError::Capacity)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn self_metadata_shape_matches_native_linux() {
    use std::os::unix::fs::MetadataExt as _;

    let fixture = Fixture::new();
    let native_link = std::fs::symlink_metadata("/proc/self").unwrap();
    let native_target = std::fs::metadata("/proc/self").unwrap();
    let link = fs::path_status(&fixture.first, "/proc/self", USER, false)
        .unwrap()
        .unwrap();
    let target = fs::path_status(&fixture.first, "/proc/self", USER, true)
        .unwrap()
        .unwrap();
    assert!(native_link.file_type().is_symlink());
    assert_eq!(link.file_type, FileType::SymbolicLink);
    assert_eq!(link.size, native_link.len());
    assert_eq!(u32::from(link.mode.bits()), native_link.mode() & 0o777);
    assert!(native_target.is_dir());
    assert_eq!(target.file_type, FileType::Directory);
    assert_eq!(target.size, native_target.len());
    assert_eq!(u32::from(target.mode.bits()), native_target.mode() & 0o777);
}
