// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(target_os = "linux")]
extern crate std;

use super::*;
use crate::syscalls::tests::TestPlatform;
use alloc::{format, vec};
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
    state: ProcState<TestPlatform>,
    registrations: Vec<ProcessRegistration<TestPlatform>>,
    sink: Arc<dyn ReadinessSink>,
}

impl Fixture {
    fn new() -> Self {
        Self::configured(false, 2)
    }

    fn configured(automatic: bool, limit: usize) -> Self {
        let mut controller = None;
        let backend = Composer::builder()
            .mount("/", InMem::<TestPlatform>::new)
            .mount("/proc", |allocator| {
                let state = ProcState::new(allocator, limit);
                let procfs = ProcFs::new(state.clone());
                let procfs = if automatic {
                    procfs.with_process_lifecycle(USER)
                } else {
                    procfs
                };
                controller = Some(state);
                procfs
            })
            .build()
            .unwrap();
        let state = controller.unwrap();
        let fs =
            Resolver::<TestPlatform, _>::new(backend).with_file_publisher(Arc::new(state.clone()));
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
                state.register_process(&first, USER).unwrap(),
                state.register_process(&second, USER).unwrap(),
            ]
        };
        Self {
            broker,
            first,
            second,
            state,
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
        let children = fs::read_directory(process, handle, Some(0))
            .unwrap()
            .unwrap()
            .0;
        let names: Vec<_> = children.iter().map(|entry| entry.name.as_str()).collect();
        for name in [".", "..", "fd"] {
            assert!(names.contains(&name), "{names:?}");
        }
        // Nothing is published yet.
        for name in ["exe", "cwd", "limits", "status"] {
            assert!(!names.contains(&name), "{names:?}");
        }
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
        let entries = fs::read_directory(process, root, Some(0))
            .unwrap()
            .unwrap()
            .0;
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
}

#[test]
fn automatic_registration_follows_child_start_failure_exit_and_cleanup() {
    use litebox_broker_core::BrokerError;
    use litebox_broker_protocol::process::{CpuTime, ProcessExitStatus};

    let fixture = Fixture::configured(true, 4);
    fixture.first.complete_start().unwrap();
    assert_eq!(fixture.state.registry.processes.lock().len(), 2);
    let identity = fixture.first.allocate_child_process().unwrap();
    let child = fixture
        .first
        .take_child_process(identity.process_id)
        .unwrap();
    assert_eq!(fixture.state.registry.processes.lock().len(), 3);
    assert_eq!(
        fs::read_link(&child, "/proc/self", USER).unwrap().unwrap(),
        child.id().0.to_string()
    );
    child.complete_start().unwrap();
    child
        .complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
        .unwrap();
    assert_eq!(fixture.state.registry.processes.lock().len(), 2);
    let failed = fixture
        .broker
        .create_process(CallerCredential::Unauthenticated)
        .unwrap();
    assert_eq!(fixture.state.registry.processes.lock().len(), 3);
    assert_eq!(
        failed.fail_start(BrokerError::PeerClosed, false, true),
        Err(BrokerError::PeerClosed)
    );
    assert_eq!(fixture.state.registry.processes.lock().len(), 2);
    failed.cleanup(true);
    fixture.second.cleanup(true);
    assert_eq!(fixture.state.registry.processes.lock().len(), 1);
    fixture
        .first
        .complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
        .unwrap();
    assert_eq!(fixture.state.registry.processes.lock().len(), 0);
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
    assert_eq!(fixture.state.registry.processes.lock().len(), 2);
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
    assert_eq!(fixture.state.registry.processes.lock().len(), 2);
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
    // Procfs orders lookup and permission errors itself; it is not an EROFS mount.
    for user in [USER, UserInfo::ROOT] {
        for parent in ["/proc", "/proc/self"] {
            let missing = format!("{parent}/new");
            let existing = format!("{parent}/self");
            let existing = if parent == "/proc/self" {
                format!("{parent}/fd")
            } else {
                existing
            };
            assert_eq!(
                fs::mkdir(process, &missing, user, Mode::RWXU),
                Ok(Err(FileError::NoSuchFileOrDirectory))
            );
            assert_eq!(
                fs::symlink(process, "/elsewhere", &missing, user),
                Ok(Err(FileError::NoSuchFileOrDirectory))
            );
            assert_eq!(
                fs::mkdir(process, &existing, user, Mode::RWXU),
                Ok(Err(FileError::AlreadyExists))
            );
            assert_eq!(
                fs::symlink(process, "/elsewhere", &existing, user),
                Ok(Err(FileError::AlreadyExists))
            );
            assert_eq!(
                fs::unlink(process, &missing, user),
                Ok(Err(FileError::NoSuchFileOrDirectory))
            );
        }
        assert_eq!(
            fs::chmod(process, "/proc/self", user, Mode::RWXU),
            Ok(Err(FileError::NotOwner))
        );
    }
    // Linux: unprivileged `unlink("/proc/self")` fails the directory write check with EACCES.
    assert_eq!(
        fs::unlink(process, "/proc/self", USER),
        Ok(Err(FileError::NoWritePermissions))
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
        Ok(Err(FileError::IsDirectory)),
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
        fixture.state.register_process(&fixture.first, USER),
        Err(RegistrationError::AlreadyRegistered)
    ));
    fixture.registrations.remove(0);
    assert_eq!(
        fs::read_link(&fixture.first, "/proc/self", USER),
        Ok(Err(FileError::NoSuchFileOrDirectory))
    );
    let error = fs::read_directory(&fixture.first, handle, Some(0))
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

/// Credentials whose real IDs are `real` and whose effective IDs are `effective`.
fn credentials(real: u32, effective: u32) -> crate::StatusCredentials {
    crate::StatusCredentials {
        uid: real,
        euid: effective,
        gid: real,
        egid: effective,
    }
}

/// Checks that a process directory lists its `fd` directory but no published entry.
fn assert_lists_nothing_published(provider: &ProcFs<TestPlatform>, directory: DirHandle) {
    let names: Vec<_> = provider
        .list_dir_at(directory)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert!(names.iter().any(|name| name == "fd"), "{names:?}");
    for published in ["exe", "cwd", "limits", "status"] {
        assert!(!names.iter().any(|name| name == published), "{names:?}");
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
fn injected_controller_and_filesystem_clones_share_state_without_owning_each_other() {
    let controller = ProcState::<TestPlatform>::new(InodeAllocator::standalone(), 1);
    let registry = Arc::downgrade(&controller.registry);
    let view = ProcFs::new(controller.clone());
    let cloned = view.clone();
    let root_status = |provider: &ProcFs<TestPlatform>| {
        provider
            .resolved_status(&ResolvedTarget::Dir(provider.root().unwrap()))
            .unwrap()
    };
    assert_eq!(root_status(&view).node_info, root_status(&cloned).node_info);
    let registration = controller.register(caller(1), USER).unwrap();
    let directory = process_directory(&view, caller(1));
    let identity = view.status(HandleRef::Dir(&directory)).unwrap().node_info;
    drop(controller);
    assert_lists_nothing_published(&cloned, directory.clone());
    drop(registration);
    assert_eq!(
        cloned.status(HandleRef::Dir(&directory)).unwrap().node_info,
        identity
    );
    assert!(matches!(
        cloned.list_dir_at(directory),
        Err(ReadDirError::PathError(PathError::NoSuchFileOrDirectory))
    ));
    drop(view);
    assert!(registry.upgrade().is_some());
    drop(cloned);
    assert!(registry.upgrade().is_none());
}

#[test]
fn pid_reuse_never_retargets_held_directories_and_capacity_is_reclaimed() {
    let state = ProcState::new(InodeAllocator::standalone(), 1);
    let provider = ProcFs::<TestPlatform>::new(state.clone());
    let first = state.register(caller(1), USER).unwrap();
    assert!(matches!(
        state.register(caller(2), USER),
        Err(RegistrationError::AlreadyRegistered)
    ));
    let other = FileCaller {
        process_id: ProcessId(43),
        ..caller(2)
    };
    assert!(matches!(
        state.register(other, USER),
        Err(RegistrationError::Capacity)
    ));
    let old = process_directory(&provider, caller(1));
    let old_identity = provider.status(HandleRef::Dir(&old)).unwrap().node_info;
    drop(first);
    let _second = state.register(caller(2), USER).unwrap();
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
    assert_lists_nothing_published(&provider, new);
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
    let state = ProcState::new(InodeAllocator::standalone(), 1);
    let provider = ProcFs::<TestPlatform>::new(state.clone());
    let _registered = state.register(caller(1), USER).unwrap();
    let fs = Resolver::<TestPlatform, _>::new(provider);
    assert!(matches!(
        fs.read_link(USER, "/self"),
        Err(WalkError::PathError(PathError::NoSearchPerms))
    ));
    let disabled = ProcState::<TestPlatform>::new(InodeAllocator::standalone(), 0);
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
        .state
        .set_executable(process, source)
        .unwrap()
        .unwrap();
    fs::rename(process, "/images/original", "/images/renamed", USER)
        .unwrap()
        .unwrap();
    assert_eq!(
        fs::read_link(process, "/proc/self/exe", USER)
            .unwrap()
            .unwrap(),
        "/images/renamed"
    );
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
        "/images/renamed (deleted)"
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
        fs::open(
            process,
            "/proc/self/exe",
            USER,
            FileAccessMode::WriteOnly,
            FileOpenFlags::NONE,
            Mode::empty(),
            &fixture.sink
        ),
        Ok(Err(FileError::InUse))
    );
    // Reopening the retained image is subject to the same write refusal.
    for (access, flags) in [
        (FileAccessMode::WriteOnly, FileOpenFlags::NONE),
        (FileAccessMode::ReadOnly, FileOpenFlags::TRUNCATE),
    ] {
        assert_eq!(
            fs::reopen(process, retained, USER, access, flags, &fixture.sink),
            Ok(Err(FileError::InUse))
        );
    }
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
    // Linux: `chdir("/proc/self/exe")` fails with ENOTDIR.
    assert_eq!(
        fs::resolve_path(process, "/proc/self/exe", USER),
        Ok(Err(FileError::ComponentNotDirectory))
    );
}

#[test]
fn executable_publication_is_authenticated_read_only_and_rechecks_permissions() {
    use litebox_broker_core::BrokerError;

    let fixture = Fixture::new();
    let source = fixture.image(&fixture.first, "/images/source", b"data");
    assert_eq!(
        fixture.state.set_executable(&fixture.second, source),
        Err(BrokerError::UnknownObject)
    );
    let write_only = fixture
        .first
        .duplicate_object_reference_to(source, &fixture.second, ObjectRights::WRITE)
        .unwrap();
    assert_eq!(
        fixture.state.set_executable(&fixture.second, write_only),
        Err(BrokerError::InvalidRights)
    );
    let directory = fixture.open(&fixture.first, "/images", FileOpenFlags::NONE);
    assert_eq!(
        fixture.state.set_executable(&fixture.first, directory),
        Ok(Err(FileError::NoSuchDevice))
    );
    let path_only = fixture.open(&fixture.first, "/images/source", FileOpenFlags::PATH);
    assert_eq!(
        fixture.state.set_executable(&fixture.first, path_only),
        Ok(Err(FileError::AccessNotAllowed))
    );
    fixture
        .state
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
        .state
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
        .state
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
    assert_eq!(fixture.state.registry.processes.lock().len(), 3);
}

#[test]
fn cwd_is_a_published_path_link_that_children_inherit() {
    let fixture = Fixture::configured(true, 4);
    fixture.first.complete_start().unwrap();
    let process = &fixture.first;
    let key = crate::CWD_FILE_PUBLICATION_KEY;
    let read_cwd = |process: &BrokerProcess| fs::read_link(process, "/proc/self/cwd", USER);
    assert_eq!(read_cwd(process), Ok(Err(FileError::NoSuchFileOrDirectory)));

    // A path-only directory publishes its path, which the link names and paths continue through.
    fs::mkdir(process, "/images/work", USER, Mode::RWXU)
        .unwrap()
        .unwrap();
    fixture.image(process, "/images/work/file", b"data");
    let work = fixture.open(
        process,
        "/images/work",
        FileOpenFlags::PATH | FileOpenFlags::DIRECTORY,
    );
    assert_eq!(fs::publish_file(process, work, key), Ok(Ok(())));
    assert_eq!(read_cwd(process), Ok(Ok("/images/work".into())));
    let status = |path: &str, follow| {
        fs::path_status(process, path, USER, follow)
            .unwrap()
            .unwrap()
    };
    assert_eq!(
        status("/proc/self/cwd", true).node_info,
        status("/images/work", true).node_info
    );
    assert_eq!(
        status("/proc/self/cwd", false).file_type,
        FileType::SymbolicLink
    );
    assert_eq!(
        status("/proc/self/cwd/file", true).node_info,
        status("/images/work/file", true).node_info
    );

    // Objects of the wrong kind for a key are rejected without replacing the published state.
    let file = fixture.image(process, "/images/file", b"data");
    assert_eq!(
        fs::publish_file(process, file, key),
        Ok(Err(FileError::NotDirectory))
    );
    assert_eq!(
        fs::publish_file(process, work, crate::EXECUTABLE_FILE_PUBLICATION_KEY),
        Ok(Err(FileError::IsDirectory))
    );
    assert_eq!(read_cwd(process), Ok(Ok("/images/work".into())));

    // A child starts with its parent's working directory, which later changes do not affect.
    let identity = process.allocate_child_process().unwrap();
    let child = process.take_child_process(identity.process_id).unwrap();
    let images = fixture.open(
        process,
        "/images",
        FileOpenFlags::PATH | FileOpenFlags::DIRECTORY,
    );
    assert_eq!(fs::publish_file(process, images, key), Ok(Ok(())));
    assert_eq!(read_cwd(process), Ok(Ok("/images".into())));
    assert_eq!(read_cwd(&child), Ok(Ok("/images/work".into())));
    assert_eq!(
        read_cwd(&fixture.second),
        Ok(Err(FileError::NoSuchFileOrDirectory))
    );
}

#[test]
fn limits_is_a_generated_file_read_from_per_open_snapshots() {
    use litebox_broker_protocol::fs::FileSeekWhence as Whence;

    let fixture = Fixture::configured(true, 4);
    fixture.first.complete_start().unwrap();
    let process = &fixture.first;
    let key = crate::LIMITS_DATA_PUBLICATION_KEY;
    let status = |path: &str| fs::path_status(process, path, USER, true);
    assert_eq!(
        status("/proc/self/limits"),
        Ok(Err(FileError::NoSuchFileOrDirectory))
    );
    assert_eq!(fs::publish_data(process, key, b"first"), Ok(Ok(())));

    let limits = status("/proc/self/limits").unwrap().unwrap();
    assert_eq!(limits.file_type, FileType::RegularFile);
    assert_eq!(limits.mode, Mode::RUSR | Mode::RGRP | Mode::ROTH);
    assert_eq!(limits.size, 0);
    let listing = fixture.open(process, "/proc/self", FileOpenFlags::NONE);
    assert!(
        fs::read_directory(process, listing, Some(0))
            .unwrap()
            .unwrap()
            .0
            .iter()
            .any(|entry| entry.name == "limits"
                && entry.file_type == FileType::RegularFile
                && entry.ino_info == Some(limits.node_info))
    );
    assert_eq!(
        fs::read_link(process, "/proc/self/limits", USER),
        Ok(Err(FileError::InvalidPathname))
    );
    for access in [FileAccessMode::WriteOnly, FileAccessMode::ReadWrite] {
        assert_eq!(
            fs::open(
                process,
                "/proc/self/limits",
                USER,
                access,
                FileOpenFlags::NONE,
                Mode::empty(),
                &fixture.sink,
            ),
            Ok(Err(FileError::AccessNotAllowed))
        );
    }

    // Contiguous reads retain a snapshot, even at EOF; any repositioning refreshes it.
    let file = fixture.open(process, "/proc/self/limits", FileOpenFlags::NONE);
    let mut buffer = [0; 3];
    let mut read = |offset| {
        let count = fs::read(process, file, &mut buffer, offset)
            .unwrap()
            .unwrap();
        String::from_utf8(buffer[..count].to_vec()).unwrap()
    };
    assert_eq!(read(None), "fir");
    assert_eq!(fs::publish_data(process, key, b"second"), Ok(Ok(())));
    assert_eq!(read(None), "st");
    assert_eq!(read(None), "");
    assert_eq!(read(Some(1)), "eco");
    assert_eq!(read(Some(4)), "nd");
    assert_eq!(read(Some(6)), "");
    assert_eq!(read(Some(0)), "sec");
    assert_eq!(read(Some(3)), "ond");
    fs::seek(
        process,
        file,
        0,
        litebox_broker_protocol::fs::FileSeekWhence::RelativeToBeginning,
    )
    .unwrap()
    .unwrap();
    assert_eq!(read(None), "sec");
    // Like a Linux seq_file, the text has no size to bound seeks or to seek from the end.
    let seek = |offset, whence| fs::seek(process, file, offset, whence).unwrap();
    assert_eq!(seek(0, Whence::RelativeToCurrentOffset), Ok(3));
    assert_eq!(seek(1, Whence::RelativeToCurrentOffset), Ok(4));
    assert_eq!(read(None), "nd");
    assert_eq!(
        seek(0, Whence::RelativeToEnd),
        Err(FileError::InvalidOffset)
    );
    assert_eq!(seek(100, Whence::RelativeToBeginning), Ok(100));
    assert_eq!(read(None), "");

    // A child starts with its parent's text; unknown keys and oversized text change nothing.
    let identity = process.allocate_child_process().unwrap();
    let child = process.take_child_process(identity.process_id).unwrap();
    assert_eq!(
        fs::publish_data(process, u64::MAX, b"other"),
        Ok(Err(FileError::NotSupported))
    );
    assert_eq!(
        fs::publish_data(process, key, &[b'x'; MAX_LIMITS_TEXT + 1]),
        Ok(Err(FileError::InvalidArgument))
    );
    let parent_file = fixture.open(process, "/proc/self/limits", FileOpenFlags::NONE);
    let mut buffer = [0; 16];
    let count = fs::read(process, parent_file, &mut buffer, None)
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..count], b"second");
    assert_eq!(fs::publish_data(process, key, b"third"), Ok(Ok(())));
    let child_file = fixture.open(&child, "/proc/self/limits", FileOpenFlags::NONE);
    let count = fs::read(&child, child_file, &mut buffer, None)
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..count], b"second");
}

#[test]
fn generated_snapshot_state_is_shared_by_clones_but_not_reopens() {
    let state = ProcState::<TestPlatform>::new(InodeAllocator::standalone(), 1);
    let provider = ProcFs::new(state.clone());
    let caller = caller(1);
    let _registration = state.register(caller, USER).unwrap();
    let key = crate::LIMITS_DATA_PUBLICATION_KEY;
    state.publish_data(caller, key, b"first").unwrap();
    let context = context(caller);
    let Resolution::Found(ResolvedTarget::File(file)) = provider
        .resolve_with_context(
            &context,
            provider.root_with_context(&context).unwrap(),
            &["42", "limits"],
            &|_| Ok(()),
        )
        .unwrap()
    else {
        panic!("expected generated file")
    };
    let file = provider.open_file(file, OFlags::RDONLY).unwrap();
    let cloned = file.clone();
    let read = |file: &FileHandle, offset| {
        let mut bytes = [0; 3];
        let count = provider.read(file, &mut bytes, offset).unwrap();
        bytes[..count].to_vec()
    };
    assert_eq!(read(&file, 0), b"fir");
    state.publish_data(caller, key, b"second").unwrap();
    assert_eq!(provider.read(&file, &mut [], 1).unwrap(), 0);
    assert_eq!(read(&cloned, 3), b"st");
    assert_eq!(read(&file, 5), b"");
    assert_eq!(read(&cloned, 5), b"");

    let reopened = provider.reopen_file(&file, OFlags::RDONLY).unwrap();
    assert_eq!(read(&reopened, 3), b"ond");
    assert_eq!(read(&file, 1), b"eco");
    state.publish_data(caller, key, b"third").unwrap();
    assert_eq!(read(&cloned, 4), b"nd");
    assert_eq!(read(&file, 6), b"");
    assert_eq!(read(&file, usize::MAX), b"");
    assert_eq!(read(&file, usize::MAX), b"");
    assert_eq!(read(&cloned, 1), b"hir");
    assert_eq!(read(&reopened, 6), b"");

    assert!(matches!(
        provider.reopen_file(&file, OFlags::WRONLY),
        Err(OpenError::AccessNotAllowed)
    ));
    assert!(matches!(
        provider.reopen_file(&file, OFlags::DIRECTORY),
        Err(OpenError::PathError(PathError::ComponentNotADirectory))
    ));
    assert!(provider.reopen_file(&file, OFlags::PATH).is_ok());
}

#[test]
fn descriptor_directory_owner_and_permissions_follow_published_credentials() {
    let fixture = Fixture::configured(true, 4);
    fixture.first.complete_start().unwrap();
    let process = &fixture.first;
    let other = UserInfo {
        user: 2000,
        group: 2000,
    };
    let open = |user, flags| {
        fs::open(
            process,
            "/proc/self/fd",
            user,
            FileAccessMode::ReadOnly,
            flags,
            Mode::empty(),
            &fixture.sink,
        )
    };
    // Linux (`proc_fd_permission`): a process may use its own descriptor directory whatever
    // its owner and mode.
    for user in [USER, other, UserInfo::ROOT] {
        assert!(open(user, FileOpenFlags::NONE).unwrap().is_ok());
        assert_eq!(
            fs::path_status(process, "/proc/self/fd/3", user, true),
            Ok(Err(FileError::CallerObject(3)))
        );
    }
    assert_eq!(
        fs::publish_data(
            process,
            crate::STATUS_CREDENTIALS_DATA_PUBLICATION_KEY,
            &credentials(1000, 2000).encode(),
        ),
        Ok(Ok(()))
    );
    let status = fs::path_status(process, "/proc/self/fd", other, true)
        .unwrap()
        .unwrap();
    assert_eq!(status.owner, other);
    assert_eq!(status.mode, Mode::RUSR | Mode::XUSR);
    assert_eq!(
        fs::publish_data(
            process,
            crate::STATUS_CREDENTIALS_DATA_PUBLICATION_KEY,
            &credentials(1000, 70000).encode(),
        ),
        Ok(Err(FileError::InvalidArgument))
    );
    assert_eq!(
        fs::path_status(process, "/proc/self/fd", other, true)
            .unwrap()
            .unwrap()
            .owner,
        other
    );
}

#[test]
fn status_merges_published_fields_with_broker_process_state() {
    let fixture = Fixture::configured(true, 4);
    fixture.first.complete_start().unwrap();
    let process = &fixture.first;
    let publish = |process: &BrokerProcess, key, data: &[u8]| fs::publish_data(process, key, data);
    let exists = |process: &BrokerProcess| {
        fs::path_status(process, "/proc/self/status", USER, true).map(|status| status.is_ok())
    };
    let published = credentials(1000, 1000).encode();
    assert_eq!(
        publish(process, crate::STATUS_NAME_DATA_PUBLICATION_KEY, b"first"),
        Ok(Ok(()))
    );
    assert_eq!(
        publish(process, crate::STATUS_UMASK_DATA_PUBLICATION_KEY, b"0022"),
        Ok(Ok(()))
    );
    assert_eq!(exists(process), Ok(false));
    assert_eq!(
        publish(
            process,
            crate::STATUS_CREDENTIALS_DATA_PUBLICATION_KEY,
            &published
        ),
        Ok(Ok(()))
    );
    assert_eq!(exists(process), Ok(true));

    let read = |process: &BrokerProcess| {
        let file = fixture.open(process, "/proc/self/status", FileOpenFlags::NONE);
        let mut buffer = [0; 512];
        let count = fs::read(process, file, &mut buffer, None).unwrap().unwrap();
        String::from_utf8(buffer[..count].to_vec()).unwrap()
    };
    let pid = process.id().0;
    // The fields each have Linux's value, in Linux's order, among any others.
    let check = |text: String, name: &str, pid: u32, parent: u32, threads: usize| {
        let pid = pid.to_string();
        let parent = parent.to_string();
        let threads = threads.to_string();
        let expected = [
            ("Name", name),
            ("Umask", "0022"),
            ("Tgid", &pid),
            ("Pid", &pid),
            ("PPid", &parent),
            ("TracerPid", "0"),
            ("Uid", "1000\t1000\t1000\t1000"),
            ("Gid", "1000\t1000\t1000\t1000"),
            ("Groups", "1000 "),
            ("Threads", &threads),
        ];
        let lines: Vec<_> = text
            .lines()
            .map(|line| line.split_once(":\t").unwrap())
            .collect();
        let mut positions = expected.iter().map(|(key, value)| {
            let position = lines.iter().position(|(line_key, _)| line_key == key);
            assert_eq!(
                position.map(|position| lines[position].1),
                Some(*value),
                "{key}"
            );
            position
        });
        let mut previous = positions.next().unwrap();
        for position in positions {
            assert!(position > previous, "{text}");
            previous = position;
        }
    };
    check(read(process), "first", pid, 0, 1);
    process.create_thread().unwrap();
    check(read(process), "first", pid, 0, 2);

    // A child inherits the published fields; its parent and threads are its own.
    let identity = process.allocate_child_process().unwrap();
    let child = process.take_child_process(identity.process_id).unwrap();
    assert_eq!(
        publish(&child, crate::STATUS_NAME_DATA_PUBLICATION_KEY, b"child\\n"),
        Ok(Ok(()))
    );
    check(read(&child), "child\\n", child.id().0, pid, 1);

    // Malformed fields are rejected without replacing the published ones.
    for (key, data) in [
        (crate::STATUS_NAME_DATA_PUBLICATION_KEY, &b"two\nlines"[..]),
        (crate::STATUS_UMASK_DATA_PUBLICATION_KEY, b"0x12"),
        (crate::STATUS_UMASK_DATA_PUBLICATION_KEY, b""),
        (
            crate::STATUS_CREDENTIALS_DATA_PUBLICATION_KEY,
            &published[..12],
        ),
        (
            crate::STATUS_CREDENTIALS_DATA_PUBLICATION_KEY,
            &credentials(1000, 70000).encode(),
        ),
    ] {
        assert_eq!(
            publish(process, key, data),
            Ok(Err(FileError::InvalidArgument))
        );
    }
    check(read(process), "first", pid, 0, 2);
}

#[test]
fn descriptor_paths_and_listings_are_handed_back_to_the_caller() {
    let fixture = Fixture::configured(true, 4);
    fixture.first.complete_start().unwrap();
    let process = &fixture.first;
    let pid = process.id().0;
    let fd = fs::path_status(process, "/proc/self/fd", USER, true)
        .unwrap()
        .unwrap();
    assert_eq!(fd.file_type, FileType::Directory);
    assert_eq!(fd.mode, Mode::RUSR | Mode::XUSR);
    assert_eq!(fd.owner, USER);
    let listing = fixture.open(process, "/proc/self", FileOpenFlags::NONE);
    assert!(
        fs::read_directory(process, listing, Some(0))
            .unwrap()
            .unwrap()
            .0
            .iter()
            .any(|entry| entry.name == "fd"
                && entry.file_type == FileType::Directory
                && entry.ino_info == Some(fd.node_info))
    );

    for path in [
        "/proc/self/fd/3".to_string(),
        format!("/proc/{pid}/fd/3"),
        "/proc/self/fd/../fd/3".to_string(),
    ] {
        for follow in [true, false] {
            assert_eq!(
                fs::path_status(process, &path, USER, follow),
                Ok(Err(FileError::CallerObject(3))),
                "{path}"
            );
        }
        assert_eq!(
            fs::read_link(process, &path, USER),
            Ok(Err(FileError::CallerObject(3)))
        );
        assert_eq!(
            fs::open(
                process,
                &path,
                USER,
                FileAccessMode::ReadOnly,
                FileOpenFlags::NONE,
                Mode::empty(),
                &fixture.sink,
            ),
            Ok(Err(FileError::CallerObject(3)))
        );
    }
    assert_eq!(
        fs::path_status(process, "/proc/self/fd/0", USER, true),
        Ok(Err(FileError::CallerObject(0)))
    );
    // An ordinary link to a descriptor is itself, until followed.
    fs::symlink(process, "/proc/self/fd/3", "/images/via-link", USER)
        .unwrap()
        .unwrap();
    assert_eq!(
        fs::path_status(process, "/images/via-link", USER, true),
        Ok(Err(FileError::CallerObject(3)))
    );
    assert_eq!(
        fs::read_link(process, "/images/via-link", USER),
        Ok(Ok("/proc/self/fd/3".into()))
    );
    for name in ["03", "+3", "-1", "x", "2147483648"] {
        assert_eq!(
            fs::path_status(process, &format!("/proc/self/fd/{name}"), USER, true),
            Ok(Err(FileError::NoSuchFileOrDirectory)),
            "{name}"
        );
    }
    // Walking through a descriptor, including to change an entry below it, must never silently
    // name the descriptor itself.
    for path in [
        "/proc/self/fd/3/file",
        "/images/via-link/file",
        "/proc/self/fd/3/..",
    ] {
        let status = fs::path_status(process, path, USER, true).unwrap();
        assert!(
            !matches!(status, Err(FileError::CallerObject(_))),
            "{path}: {status:?}"
        );
    }
    for path in ["/proc/self/fd/3/new", "/images/via-link/new"] {
        for result in [
            fs::mkdir(process, path, USER, Mode::RWXU),
            fs::unlink(process, path, USER),
            fs::rmdir(process, path, USER),
            fs::symlink(process, "target", path, USER),
            fs::rename(process, "/images/source", path, USER),
            fs::rename(process, path, "/images/renamed", USER),
        ] {
            assert!(
                !matches!(result, Ok(Err(FileError::CallerObject(_)))),
                "{path}: {result:?}"
            );
        }
    }

    let descriptors = fixture.open(process, "/proc/self/fd", FileOpenFlags::NONE);
    assert_eq!(
        fs::read_directory(process, descriptors, Some(0)),
        Ok(Err(FileError::CallerObjects))
    );
}

#[test]
fn composed_lifecycle_registration_rolls_back_earlier_providers() {
    let mut providers = Vec::new();
    let backend = Composer::builder()
        .mount("/", InMem::<TestPlatform>::new)
        .mount("/first", |allocator| {
            let state = ProcState::<TestPlatform>::new(allocator, 2);
            let provider = ProcFs::new(state.clone()).with_process_lifecycle(USER);
            providers.push(state);
            provider
        })
        .mount("/second", |allocator| {
            let state = ProcState::<TestPlatform>::new(allocator, 1);
            let provider = ProcFs::new(state.clone()).with_process_lifecycle(USER);
            providers.push(state);
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
fn named_entries_agree_across_lookup_listing_readlink_and_path_only_open() {
    let fixture = Fixture::new();
    let process = &fixture.first;
    let check = |path: &str, expected: &[&str]| {
        let directory = fixture.open(process, path, FileOpenFlags::NONE);
        let entries: Vec<_> = fs::read_directory(process, directory, Some(0))
            .unwrap()
            .unwrap()
            .0
            .iter()
            .filter(|entry| {
                entry.file_type == FileType::SymbolicLink
                    && ["self", "exe", "cwd"].contains(&entry.name.as_str())
            })
            .cloned()
            .collect();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            expected
        );
        for entry in entries {
            let path = format!("{path}/{}", entry.name);
            let status = fs::path_status(process, &path, USER, false)
                .unwrap()
                .unwrap();
            assert_eq!(entry.file_type, status.file_type);
            assert_eq!(entry.ino_info, Some(status.node_info));
            let opened = fixture.open(
                process,
                &path,
                FileOpenFlags::PATH | FileOpenFlags::NO_FOLLOW,
            );
            let opened_status = fs::handle_status(process, opened).unwrap().unwrap();
            assert_eq!(opened_status.file_type, status.file_type);
            assert_eq!(opened_status.node_info, status.node_info);
            let target = match entry.name.as_str() {
                "self" => process.id().0.to_string(),
                "exe" => "/images/source".to_string(),
                "cwd" => "/images".to_string(),
                _ => unreachable!(),
            };
            assert_eq!(
                fs::read_link(process, &path, USER).unwrap().unwrap(),
                target
            );
        }
    };
    check("/proc", &["self"]);
    check("/proc/self", &[]);
    let source = fixture.image(process, "/images/source", b"data");
    fixture
        .state
        .set_executable(process, source)
        .unwrap()
        .unwrap();
    check("/proc", &["self"]);
    check("/proc/self", &["exe"]);
    let images = fixture.open(
        process,
        "/images",
        FileOpenFlags::PATH | FileOpenFlags::DIRECTORY,
    );
    assert_eq!(
        fs::publish_file(process, images, crate::CWD_FILE_PUBLICATION_KEY),
        Ok(Ok(()))
    );
    check("/proc/self", &["cwd", "exe"]);
    for path in ["/proc/exe", "/proc/cwd", "/proc/self/self"] {
        assert_eq!(
            fs::path_status(process, path, USER, false),
            Ok(Err(FileError::NoSuchFileOrDirectory))
        );
    }
}

#[test]
fn ordinary_and_object_links_share_one_traversal_budget() {
    let fixture = Fixture::new();
    let source = fixture.image(&fixture.first, "/images/source", b"data");
    fixture
        .state
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
        .state
        .set_executable(&fixture.first, source)
        .unwrap()
        .unwrap();
    let registry = Arc::downgrade(&fixture.state.registry);
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
