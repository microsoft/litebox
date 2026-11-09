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
    broker: litebox_broker_core::test_support::TestBroker,
    first: Arc<BrokerProcess>,
    second: Arc<BrokerProcess>,
    procfs: ProcFs<TestPlatform>,
    registrations: Vec<ProcessRegistration<TestPlatform>>,
    sink: Arc<dyn ReadinessSink>,
}

impl Fixture {
    fn new() -> Self {
        Self::configured(false, 2)
    }

    fn configured(automatic: bool, limit: usize) -> Self {
        let mut provider = None;
        let backend = Composer::builder()
            .mount("/", InMem::<TestPlatform>::new)
            .mount("/proc", |allocator| {
                let procfs = ProcFs::new(allocator, limit);
                let procfs = if automatic {
                    procfs.with_process_lifecycle(USER)
                } else {
                    procfs
                };
                provider = Some(procfs.clone());
                procfs
            })
            .build()
            .unwrap();
        let procfs = provider.unwrap();
        let fs =
            Resolver::<TestPlatform, _>::new(backend).with_file_publisher(Arc::new(procfs.clone()));
        fs.mkdir(UserInfo::ROOT, "/images", Mode::SUPPORTED)
            .unwrap();
        fs.symlink(UserInfo::ROOT, "/proc/self", "/who").unwrap();
        let broker = TestBrokerBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .with_file_service(Arc::new(fs))
        .build()
        .unwrap();
        let first = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let second = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let registrations = if automatic {
            Vec::new()
        } else {
            vec![
                procfs.register_process(&first, USER).unwrap(),
                procfs.register_process(&second, USER).unwrap(),
            ]
        };
        Self {
            broker,
            first,
            second,
            procfs,
            registrations,
            sink: Arc::new(NoReadiness),
        }
    }

    fn image(&self, process: &BrokerProcess, path: &str, data: &[u8]) -> ObjectHandle {
        let file = fs::open(
            process,
            path,
            USER,
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
            Mode::RWXU,
            &self.sink,
        )
        .unwrap()
        .unwrap();
        fs::write(process, file, &data, None).unwrap().unwrap();
        file
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
fn automatic_registration_follows_child_start_failure_exit_and_cleanup() {
    use litebox_broker_core::BrokerError;
    use litebox_broker_protocol::process::{CpuTime, ProcessExitStatus};

    let fixture = Fixture::configured(true, 4);
    fixture.first.complete_start().unwrap();
    assert_eq!(fixture.procfs.registry.processes.lock().len(), 2);
    let identity = fixture.first.allocate_child_process().unwrap();
    let child = fixture
        .first
        .take_child_process(identity.process_id)
        .unwrap();
    assert_eq!(fixture.procfs.registry.processes.lock().len(), 3);
    assert_eq!(
        fs::read_link(&child, "/proc/self", USER).unwrap().unwrap(),
        child.id().0.to_string()
    );
    child.complete_start().unwrap();
    child
        .complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
        .unwrap();
    assert_eq!(fixture.procfs.registry.processes.lock().len(), 2);
    let failed = fixture
        .broker
        .create_process(CallerCredential::Unauthenticated)
        .unwrap();
    assert_eq!(fixture.procfs.registry.processes.lock().len(), 3);
    assert_eq!(
        failed.fail_start(BrokerError::PeerClosed, false, true),
        Err(BrokerError::PeerClosed)
    );
    assert_eq!(fixture.procfs.registry.processes.lock().len(), 2);
    failed.cleanup(true);
    fixture.second.cleanup(true);
    assert_eq!(fixture.procfs.registry.processes.lock().len(), 1);
    fixture
        .first
        .complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
        .unwrap();
    assert_eq!(fixture.procfs.registry.processes.lock().len(), 0);
}

#[test]
fn automatic_registration_failure_rolls_back_process_startup() {
    use litebox_broker_core::BrokerError;
    let fixture = Fixture::configured(true, 2);
    assert!(matches!(
        fixture
            .broker
            .create_process(CallerCredential::Unauthenticated),
        Err(BrokerError::ResourceExhausted)
    ));
    assert_eq!(fixture.procfs.registry.processes.lock().len(), 2);
    assert_eq!(
        fixture
            .first
            .fail_start(BrokerError::PeerClosed, false, true),
        Err(BrokerError::PeerClosed)
    );
    let replacement = fixture
        .broker
        .create_process(CallerCredential::Unauthenticated)
        .unwrap();
    assert_eq!(fixture.procfs.registry.processes.lock().len(), 2);
    assert_eq!(
        fs::read_link(&replacement, "/proc/self", USER)
            .unwrap()
            .unwrap(),
        replacement.id().0.to_string()
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

#[test]
fn executable_links_retain_objects_after_rename_unlink_and_source_close() {
    use litebox_broker_protocol::fs::FileSeekWhence;

    let fixture = Fixture::new();
    let process = &fixture.first;
    let source = fixture.image(process, "/images/original", b"original");
    let identity = fs::handle_status(process, source)
        .unwrap()
        .unwrap()
        .node_info;
    fs::seek(process, source, 2, FileSeekWhence::RelativeToBeginning)
        .unwrap()
        .unwrap();
    fixture
        .procfs
        .set_executable(process, source)
        .unwrap()
        .unwrap();
    fs::rename(process, "/images/original", "/images/renamed", USER)
        .unwrap()
        .unwrap();
    let replacement = fixture.image(process, "/images/original", b"replaced");
    assert_ne!(
        fs::handle_status(process, replacement)
            .unwrap()
            .unwrap()
            .node_info,
        identity
    );
    fs::unlink(process, "/images/renamed", USER)
        .unwrap()
        .unwrap();
    assert_eq!(
        fs::read_link(process, "/proc/self/exe", USER)
            .unwrap()
            .unwrap(),
        "/images/original"
    );
    assert_eq!(
        fs::path_status(process, "/proc/self/exe", USER, true)
            .unwrap()
            .unwrap()
            .node_info,
        identity
    );
    let first = fixture.open(process, "/proc/self/exe", FileOpenFlags::NONE);
    let second = fixture.open(process, "/proc/self/exe", FileOpenFlags::NONE);
    let mut buffer = [0; 3];
    assert_eq!(
        fs::read(process, first, &mut buffer, None)
            .unwrap()
            .unwrap(),
        3
    );
    assert_eq!(&buffer, b"ori");
    assert_eq!(
        fs::read(process, second, &mut buffer, None)
            .unwrap()
            .unwrap(),
        3
    );
    assert_eq!(&buffer, b"ori");
    assert_eq!(
        fs::read(process, source, &mut buffer, None)
            .unwrap()
            .unwrap(),
        3
    );
    assert_eq!(&buffer, b"igi");
    process.close_object_reference(source).unwrap();
    process.close_object_reference(replacement).unwrap();
    let retained = fixture.open(process, "/proc/self/exe", FileOpenFlags::NONE);
    let mut whole = [0; 8];
    assert_eq!(
        fs::read(process, retained, &mut whole, None)
            .unwrap()
            .unwrap(),
        8
    );
    assert_eq!(&whole, b"original");
    assert_eq!(
        fs::handle_status(process, retained)
            .unwrap()
            .unwrap()
            .node_info,
        identity
    );
    let symlink = fixture.open(
        process,
        "/proc/self/exe",
        FileOpenFlags::PATH | FileOpenFlags::NO_FOLLOW,
    );
    assert_eq!(
        fs::handle_status(process, symlink)
            .unwrap()
            .unwrap()
            .file_type,
        FileType::SymbolicLink
    );
    assert_eq!(
        fs::chmod_handle(process, retained, USER, Mode::RWXU),
        Ok(Err(FileError::ReadOnlyFs))
    );
    assert_eq!(
        fs::open(
            process,
            "/proc/self/exe",
            USER,
            FileAccessMode::WriteOnly,
            FileOpenFlags::NONE,
            Mode::empty(),
            &fixture.sink
        ),
        Ok(Err(FileError::ReadOnlyFs))
    );
    for path in [
        "/proc/self/exe/child",
        "/proc/self/exe/",
        "/proc/self/exe/..",
    ] {
        assert_eq!(
            fs::path_status(process, path, USER, true),
            Ok(Err(FileError::ComponentNotDirectory))
        );
    }
    assert_eq!(
        fs::resolve_path(process, "/proc/self/exe", USER),
        Ok(Err(FileError::InvalidPathname))
    );
}

#[test]
fn executable_publication_is_authenticated_read_only_and_rechecks_permissions() {
    use litebox_broker_core::BrokerError;

    let fixture = Fixture::new();
    let source = fixture.image(&fixture.first, "/images/source", b"data");
    assert_eq!(
        fixture.procfs.set_executable(&fixture.second, source),
        Err(BrokerError::UnknownObject)
    );
    let write_only = fixture
        .first
        .duplicate_object_reference_to(source, &fixture.second, ObjectRights::WRITE)
        .unwrap();
    assert_eq!(
        fixture.procfs.set_executable(&fixture.second, write_only),
        Err(BrokerError::InvalidRights)
    );
    let directory = fixture.open(&fixture.first, "/images", FileOpenFlags::NONE);
    assert_eq!(
        fixture.procfs.set_executable(&fixture.first, directory),
        Ok(Err(FileError::NoSuchDevice))
    );
    let path_only = fixture.open(&fixture.first, "/images/source", FileOpenFlags::PATH);
    assert_eq!(
        fixture.procfs.set_executable(&fixture.first, path_only),
        Ok(Err(FileError::AccessNotAllowed))
    );
    fixture
        .procfs
        .set_executable(&fixture.first, source)
        .unwrap()
        .unwrap();
    fs::chmod_handle(&fixture.first, source, USER, Mode::empty())
        .unwrap()
        .unwrap();
    assert_eq!(
        fs::open(
            &fixture.first,
            "/proc/self/exe",
            USER,
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
            Mode::empty(),
            &fixture.sink
        ),
        Ok(Err(FileError::AccessNotAllowed))
    );
    let metadata = fixture.open(&fixture.first, "/proc/self/exe", FileOpenFlags::PATH);
    assert_eq!(
        fs::handle_status(&fixture.first, metadata)
            .unwrap()
            .unwrap()
            .file_type,
        FileType::RegularFile
    );
    assert_eq!(
        fs::path_status(&fixture.second, "/proc/self/exe", USER, true),
        Ok(Err(FileError::NoSuchFileOrDirectory))
    );
}

#[test]
fn fork_inherits_the_image_but_image_replacement_does_not_retarget_open_files() {
    let fixture = Fixture::configured(true, 4);
    fixture.first.complete_start().unwrap();
    let source = fixture.image(&fixture.first, "/images/first", b"first");
    fixture
        .procfs
        .set_executable(&fixture.first, source)
        .unwrap()
        .unwrap();
    let old = fixture.open(&fixture.first, "/proc/self/exe", FileOpenFlags::NONE);
    let old_identity = fs::handle_status(&fixture.first, old)
        .unwrap()
        .unwrap()
        .node_info;
    let child_identity = fixture.first.allocate_child_process().unwrap();
    let child = fixture
        .first
        .take_child_process(child_identity.process_id)
        .unwrap();
    let replacement = fixture.image(&fixture.first, "/images/second", b"second");
    fixture
        .procfs
        .set_executable(&fixture.first, replacement)
        .unwrap()
        .unwrap();
    assert_ne!(
        fs::path_status(&fixture.first, "/proc/self/exe", USER, true)
            .unwrap()
            .unwrap()
            .node_info,
        old_identity
    );
    assert_eq!(
        fs::path_status(&child, "/proc/self/exe", USER, true)
            .unwrap()
            .unwrap()
            .node_info,
        old_identity
    );
    assert_eq!(
        fs::handle_status(&fixture.first, old)
            .unwrap()
            .unwrap()
            .node_info,
        old_identity
    );
    assert_eq!(fixture.procfs.registry.processes.lock().len(), 3);
}

#[test]
fn composed_lifecycle_registration_rolls_back_earlier_providers() {
    let mut providers = Vec::new();
    let backend = Composer::builder()
        .mount("/", InMem::<TestPlatform>::new)
        .mount("/first", |allocator| {
            let provider = ProcFs::<TestPlatform>::new(allocator, 2).with_process_lifecycle(USER);
            providers.push(provider.clone());
            provider
        })
        .mount("/second", |allocator| {
            let provider = ProcFs::<TestPlatform>::new(allocator, 1).with_process_lifecycle(USER);
            providers.push(provider.clone());
            provider
        })
        .build()
        .unwrap();
    let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
    .with_file_service(Arc::new(Resolver::<TestPlatform, _>::new(backend)))
    .build()
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated)
        .unwrap();
    assert!(matches!(
        broker.create_process(CallerCredential::Unauthenticated),
        Err(litebox_broker_core::BrokerError::ResourceExhausted)
    ));
    for provider in &providers {
        assert_eq!(provider.registry.processes.lock().len(), 1);
    }
    drop(process);
    for provider in &providers {
        assert_eq!(provider.registry.processes.lock().len(), 0);
    }
}

#[test]
fn publication_authenticates_the_source_and_rejects_unknown_keys_without_replacement() {
    let fixture = Fixture::new();
    let source = fixture.image(&fixture.first, "/images/source", b"data");
    let key = crate::EXECUTABLE_FILE_PUBLICATION_KEY;
    assert_eq!(fs::publish_file(&fixture.first, source, key), Ok(Ok(())));
    let identity = fs::handle_status(&fixture.first, source)
        .unwrap()
        .unwrap()
        .node_info;
    let replacement = fixture.image(&fixture.first, "/images/other", b"other");
    assert_eq!(
        fs::publish_file(&fixture.first, replacement, u64::MAX),
        Ok(Err(FileError::NotSupported))
    );
    assert_eq!(
        fs::path_status(&fixture.first, "/proc/self/exe", USER, true)
            .unwrap()
            .unwrap()
            .node_info,
        identity
    );
    assert_eq!(
        fs::publish_file(&fixture.second, source, key),
        Err(litebox_broker_core::BrokerError::UnknownObject)
    );
    let write_only = fixture
        .first
        .duplicate_object_reference_to(source, &fixture.second, ObjectRights::WRITE)
        .unwrap();
    assert_eq!(
        fs::publish_file(&fixture.second, write_only, key),
        Err(litebox_broker_core::BrokerError::InvalidRights)
    );
}

#[test]
fn ordinary_and_object_links_share_one_traversal_budget() {
    let fixture = Fixture::new();
    let source = fixture.image(&fixture.first, "/images/source", b"data");
    fixture
        .procfs
        .set_executable(&fixture.first, source)
        .unwrap()
        .unwrap();
    for index in (0..38).rev() {
        let target = if index == 37 {
            "/proc/self/exe".to_string()
        } else {
            format!("/images/link-{}", index + 1)
        };
        fs::symlink(
            &fixture.first,
            &target,
            &format!("/images/link-{index}"),
            USER,
        )
        .unwrap()
        .unwrap();
    }
    let opened = fixture.open(&fixture.first, "/images/link-0", FileOpenFlags::NONE);
    assert_eq!(
        fs::handle_status(&fixture.first, opened)
            .unwrap()
            .unwrap()
            .node_info,
        fs::handle_status(&fixture.first, source)
            .unwrap()
            .unwrap()
            .node_info
    );
    fs::symlink(
        &fixture.first,
        "/images/link-0",
        "/images/over-budget",
        USER,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        fs::path_status(&fixture.first, "/images/over-budget", USER, true),
        Ok(Err(FileError::TooManySymlinks))
    );
}

#[test]
fn retained_images_do_not_form_a_namespace_reference_cycle() {
    let fixture = Fixture::new();
    let source = fixture.image(&fixture.first, "/images/source", b"data");
    fixture
        .procfs
        .set_executable(&fixture.first, source)
        .unwrap()
        .unwrap();
    let registry = Arc::downgrade(&fixture.procfs.registry);
    drop(fixture);
    assert!(registry.upgrade().is_none());
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
