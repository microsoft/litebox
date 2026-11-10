// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Caller-aware provider traversal through an actual broker process association.

use alloc::{format, string::String, sync::Arc, vec::Vec};

use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use super::{InMem, InodeAllocator, ROOT, Resolver, TestPlatform};
use crate::{
    BrokerProcess, CallerCredential, PolicyEngine,
    fs::{
        self, DirEntry, FileStatus, Mode, OFlags, UserInfo,
        backend::{
            Backend, CreationMetadata, DirHandle, FileCaller, FileHandle, HandleRef, LookupContext,
            PermissionInfo, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget, SeekBehavior,
        },
        composer::Composer,
        errors::{
            ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError,
            ReadDirError, ReadError, RenameError, ResolutionError, RmdirError, SymlinkError,
            TruncateError, UnlinkError, WalkError, WriteError,
        },
    },
    object::ObjectRights,
    test_support::TestBrokerBuilder,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Root,
    Resolve,
    ReadLink,
}

type Observations = Arc<spin::Mutex<Vec<(Stage, LookupContext)>>>;

struct CallerBackend {
    inner: InMem<TestPlatform>,
    observations: Observations,
}

impl CallerBackend {
    fn new(allocator: InodeAllocator, observations: Observations) -> Self {
        let inner = InMem::new(allocator);
        inner
            .symlink_at(
                inner.root().unwrap(),
                "self",
                "unused",
                CreationMetadata {
                    mode: Mode::SUPPORTED,
                    owner: ROOT,
                },
            )
            .unwrap();
        Self {
            inner,
            observations,
        }
    }

    fn observe(&self, stage: Stage, context: &LookupContext) -> Result<FileCaller, WalkError> {
        let caller = context.caller.ok_or(PathError::NoSearchPerms)?;
        self.observations.lock().push((stage, *context));
        Ok(caller)
    }
}

macro_rules! forward {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
        $(fn $name(&self, $($arg: $ty),*) -> $ret {
            self.inner.$name($($arg),*)
        })*
    };
}

impl Backend for CallerBackend {
    fn root(&self) -> Result<ResolvedDir<'_>, WalkError> {
        Err(PathError::NoSearchPerms.into())
    }

    fn root_with_context(&self, context: &LookupContext) -> Result<ResolvedDir<'_>, WalkError> {
        self.observe(Stage::Root, context)?;
        self.inner.root()
    }

    fn resolve<'a>(
        &'a self,
        _from: ResolvedDir<'a>,
        _components: &[&str],
        _authorize: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        Err(ResolutionError {
            component: None,
            error: PathError::NoSearchPerms.into(),
        })
    }

    fn resolve_with_context<'a>(
        &'a self,
        context: &LookupContext,
        from: ResolvedDir<'a>,
        components: &[&str],
        authorize: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        self.observe(Stage::Resolve, context)
            .map_err(|error| ResolutionError {
                component: None,
                error,
            })?;
        self.inner.resolve(from, components, authorize)
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
        let caller = self.observe(Stage::ReadLink, context)?;
        if name == "self" {
            Ok(format!("/objects/{}", caller.process_id.0))
        } else {
            self.inner.read_link_at(dir, name)
        }
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<ResolvedDir<'a>> {
        self.inner.walking_dir_at(dir)
    }

    forward! {
        open_dir(dir: ResolvedDir<'_>, flags: OFlags) -> Result<DirHandle, OpenError>;
        open_file(file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError>;
        list_dir_at(dir: DirHandle) -> Result<Vec<DirEntry>, ReadDirError>;
        read(h: &FileHandle, buf: &mut dyn ReadBuffer, offset: usize) -> Result<usize, ReadError>;
        write(h: &FileHandle, buf: &dyn WriteBuffer, offset: usize) -> Result<usize, WriteError>;
        truncate(h: &FileHandle, length: usize) -> Result<(), TruncateError>;
        seek_behavior(h: &FileHandle) -> SeekBehavior;
        status(h: HandleRef<'_>) -> Result<FileStatus, FileStatusError>;
        resolved_status(h: &ResolvedTarget<'_>) -> Result<FileStatus, FileStatusError>;
        create_file_at(dir: ResolvedDir<'_>, name: &str, metadata: CreationMetadata) -> Result<FileHandle, OpenError>;
        symlink_at(dir: ResolvedDir<'_>, name: &str, target: &str, metadata: CreationMetadata) -> Result<(), SymlinkError>;
        mkdir_at(dir: ResolvedDir<'_>, name: &str, metadata: CreationMetadata) -> Result<DirHandle, MkdirError>;
        unlink_at(dir: ResolvedDir<'_>, name: &str) -> Result<(), UnlinkError>;
        rmdir_at(dir: ResolvedDir<'_>, name: &str) -> Result<(), RmdirError>;
        rename_at(old: DirHandle, old_name: &str, new: DirHandle, new_name: &str) -> Result<(), RenameError>;
        chmod(h: ResolvedTarget<'_>, mode: Mode) -> Result<(), ChmodError>;
        chown(h: ResolvedTarget<'_>, user: Option<u16>, group: Option<u16>) -> Result<(), ChownError>;
    }
}

fn filesystem(observations: Observations) -> Resolver<TestPlatform, Composer> {
    Resolver::new(
        Composer::builder()
            .mount("/", InMem::<TestPlatform>::new)
            .mount_nestable("/views", |allocators| {
                Composer::builder()
                    .mount("/provider", |_| {
                        CallerBackend::new(allocators.next(), observations)
                    })
                    .build()
                    .unwrap()
            })
            .build()
            .unwrap(),
    )
}

fn broker_processes(
    fs: Resolver<TestPlatform, Composer>,
) -> (Arc<BrokerProcess>, Arc<BrokerProcess>) {
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
    (first, second)
}

#[test]
fn caller_context_crosses_mounts_and_binds_open_targets() {
    let observations = Observations::default();
    let fs = filesystem(observations.clone());
    fs.mkdir(ROOT, "/objects", Mode::RWXU).unwrap();
    fs.symlink(ROOT, "/views/provider/self", "/alias").unwrap();
    let (first, second) = broker_processes(fs);
    for process in [&first, &second] {
        fs::open_without_reference(
            process,
            &format!("/objects/{}", process.id().0),
            ROOT,
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
            Mode::RWXU,
        )
        .unwrap()
        .unwrap();
    }
    for process in [&first, &second] {
        let expected = format!("/objects/{}", process.id().0);
        assert_eq!(
            fs::read_link(process, "/views/provider/self", ROOT)
                .unwrap()
                .unwrap(),
            expected
        );
        assert_eq!(
            fs::resolve_path(process, "/alias", ROOT).unwrap().unwrap(),
            expected
        );
        let (_, opened) = fs::open_without_reference(
            process,
            "/alias",
            ROOT,
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
            Mode::empty(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            opened.node_info,
            fs::path_status(process, &expected, ROOT, true)
                .unwrap()
                .unwrap()
                .node_info
        );
    }
    let (file, first_status) = fs::open_without_reference(
        &first,
        "/alias",
        ROOT,
        FileAccessMode::ReadOnly,
        FileOpenFlags::NONE,
        Mode::empty(),
    )
    .unwrap()
    .unwrap();
    let (_, second_status) = fs::open_without_reference(
        &second,
        "/alias",
        ROOT,
        FileAccessMode::ReadOnly,
        FileOpenFlags::NONE,
        Mode::empty(),
    )
    .unwrap()
    .unwrap();
    assert_ne!(first_status.node_info, second_status.node_info);
    assert_eq!(
        first.fs.handle_status(&file).unwrap().unwrap().node_info,
        first_status.node_info
    );
    assert_eq!(
        second.fs.handle_status(&file).unwrap().unwrap().node_info,
        first_status.node_info
    );
    let observations = observations.lock();
    for process in [&first, &second] {
        for stage in [Stage::Root, Stage::Resolve, Stage::ReadLink] {
            assert!(
                observations.iter().any(|(seen_stage, context)| {
                    *seen_stage == stage
                        && context.caller == Some(FileCaller::for_process(process))
                        && context.user == ROOT
                }),
                "missing {stage:?} for {:?}",
                process.id()
            );
        }
    }
}

#[test]
fn caller_context_is_not_ambient_between_concurrent_requests() {
    let (first, second) = broker_processes(filesystem(Observations::default()));
    // Both threads start their requests together, so that they overlap.
    let start = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        for process in [&first, &second] {
            let start = &start;
            scope.spawn(move || {
                let expected = format!("/objects/{}", process.id().0);
                let user = UserInfo {
                    user: 1000,
                    group: 1000,
                };
                start.wait();
                for _ in 0..500 {
                    assert_eq!(
                        fs::read_link(process, "/views/provider/self", user)
                            .unwrap()
                            .unwrap(),
                        expected,
                    );
                }
            });
        }
    });
}

#[test]
fn caller_dependent_provider_rejects_anonymous_resolver_access() {
    let fs = filesystem(Observations::default());
    assert!(matches!(
        fs.read_link(ROOT, "/views/provider/self"),
        Err(WalkError::PathError(PathError::NoSearchPerms)),
    ));
}

#[test]
fn path_mutations_keep_caller_and_acting_credentials() {
    let observations = Observations::default();
    let fs = filesystem(observations.clone());
    fs.mkdir(ROOT, "/objects", Mode::RWXU | Mode::ROTH | Mode::XOTH)
        .unwrap();
    let (process, _) = broker_processes(fs);
    fs::mkdir(
        &process,
        &format!("/objects/{}", process.id().0),
        ROOT,
        Mode::SUPPORTED,
    )
    .unwrap()
    .unwrap();
    observations.lock().clear();
    let user = UserInfo {
        user: 1000,
        group: 1000,
    };
    let directory = "/views/provider/self/work";
    fs::mkdir(&process, directory, user, Mode::RWXU)
        .unwrap()
        .unwrap();
    fs::chmod(&process, directory, user, Mode::RWXU)
        .unwrap()
        .unwrap();
    fs::chown(&process, directory, user, Some(user.user), Some(user.group))
        .unwrap()
        .unwrap();
    fs::symlink(&process, "missing", &format!("{directory}/link"), user)
        .unwrap()
        .unwrap();
    fs::rename(
        &process,
        &format!("{directory}/link"),
        &format!("{directory}/renamed"),
        user,
    )
    .unwrap()
    .unwrap();
    fs::unlink(&process, &format!("{directory}/renamed"), user)
        .unwrap()
        .unwrap();
    fs::rename(
        &process,
        &format!("{directory}/"),
        "/views/provider/self/moved/",
        user,
    )
    .unwrap()
    .unwrap();
    fs::rmdir(&process, "/views/provider/self/moved", user)
        .unwrap()
        .unwrap();
    let observations = observations.lock();
    assert!(!observations.is_empty());
    assert!(observations.iter().all(|(_, context)| {
        context.caller == Some(FileCaller::for_process(&process)) && context.user == user
    }));
}

#[test]
fn data_publication_is_authorized_by_policy() {
    let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all().difference(ObjectRights::WAIT),
    ))
    .with_file_service(Arc::new(filesystem(Observations::default())))
    .build()
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated)
        .unwrap();
    assert_eq!(
        fs::publish_data(&process, 1, b"data"),
        Err(crate::BrokerError::PolicyDenied)
    );
}

#[test]
fn read_only_views_pass_caller_context_through() {
    let observations = Observations::default();
    let fs = Resolver::new(
        Composer::builder()
            .mount("/", InMem::<TestPlatform>::new)
            .mount("/provider", |allocator| {
                crate::fs::read_only::ReadOnly::new(CallerBackend::new(
                    allocator,
                    observations.clone(),
                ))
            })
            .build()
            .unwrap(),
    );
    let (first, _) = broker_processes(fs);
    assert_eq!(
        fs::read_link(&first, "/provider/self", ROOT)
            .unwrap()
            .unwrap(),
        format!("/objects/{}", first.id().0)
    );
    let stages: Vec<_> = observations
        .lock()
        .iter()
        .map(|(stage, context)| {
            assert_eq!(context.caller, Some(FileCaller::for_process(&first)));
            *stage
        })
        .collect();
    assert!(stages.contains(&Stage::ReadLink), "{stages:?}");
}
