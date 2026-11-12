// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(any(target_os = "linux", target_os = "macos", windows))]

use std::fs;
#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, PermissionsExt, symlink},
};
#[cfg(windows)]
use std::os::windows::fs::{symlink_dir, symlink_file};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(unix)]
use litebox_broker_core::fs::SeekWhence;
use litebox_broker_core::fs::backend::{
    Backend, HandleRef, Resolution, ResolvedFile, ResolvedTarget,
};
use litebox_broker_core::fs::composer::Composer;
use litebox_broker_core::fs::errors::{
    ChmodError, ChownError, MkdirError, OpenError, PathError, RenameError, ResolutionError,
    RmdirError, SetTimesError, SymlinkError, UnlinkError, WalkError,
};
#[cfg(unix)]
use litebox_broker_core::fs::errors::{TruncateError, WriteError};
use litebox_broker_core::fs::inode_allocator::InodeAllocators;
use litebox_broker_core::fs::read_only::ReadOnly;
use litebox_broker_core::fs::resolver::Resolver;
use litebox_broker_core::fs::{FileType, Mode, OFlags, UserInfo};
use litebox_broker_protocol::fs::{FileTimeUpdate, FileTimestamp, FileTimestamps, SetFileTimes};
use litebox_broker_protocol::shared_buffer::{
    SharedBufferLayout, SharedBufferSequence, SharedBufferSlotIndex,
};
use litebox_broker_transport::shared_memory::{
    HeapSharedMemory, SharedBufferPool, SharedMemory, SharedMemoryError,
};
use litebox_broker_userland::fs::LocalFs;
use litebox_platform::buffer::{RawBytes, ReadBuffer, WriteBuffer};

const USER: UserInfo = UserInfo {
    user: 123,
    group: 456,
};

fn backend(root: &Path) -> LocalFs {
    LocalFs::new(root, InodeAllocators::new().next()).unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn reopen_uses_the_retained_inode_and_checks_new_access() {
    let temp = tempfile::tempdir_in(".").unwrap();
    let path = temp.path().join("original");
    fs::write(&path, b"old").unwrap();
    let local = backend(temp.path());
    let source = local
        .open_file(resolved_file(&local, "original"), OFlags::RDONLY)
        .unwrap();
    fs::rename(&path, temp.path().join("moved")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    fs::remove_file(temp.path().join("moved")).unwrap();
    let reopened = local.reopen_file(&source, OFlags::RDWR).unwrap();
    assert_eq!(local.write(&reopened, b"new", 0).unwrap(), 3);
    let mut buffer = [0; 3];
    assert_eq!(local.read(&source, &mut buffer, 0).unwrap(), 3);
    assert_eq!(&buffer, b"new");
    assert_eq!(fs::read(&path).unwrap(), b"replacement");
    assert_eq!(
        local.status(HandleRef::File(&source)).unwrap().node_info,
        local.status(HandleRef::File(&reopened)).unwrap().node_info
    );
    let truncated = local
        .reopen_file(&source, OFlags::RDONLY | OFlags::TRUNC)
        .unwrap();
    assert_eq!(local.status(HandleRef::File(&truncated)).unwrap().size, 0);

    let path_only = local
        .open_file(resolved_file(&local, "original"), OFlags::PATH)
        .unwrap();
    fs::remove_file(&path).unwrap();
    let reopened = local.reopen_file(&path_only, OFlags::RDONLY).unwrap();
    let mut buffer = [0; 11];
    assert_eq!(local.read(&reopened, &mut buffer, 0).unwrap(), 11);
    assert_eq!(&buffer, b"replacement");
}

#[cfg(unix)]
#[test]
fn descriptor_chmod_survives_rename_and_unlink() {
    let temp = tempfile::tempdir_in(".").unwrap();
    fs::write(temp.path().join("original"), b"data").unwrap();
    let resolver = Resolver::<(), _>::new(backend(temp.path()));
    let open = resolver
        .open(USER, "/original", OFlags::RDONLY, Mode::empty())
        .unwrap();
    let path_only = resolver
        .open(USER, "/original", OFlags::PATH, Mode::empty())
        .unwrap();
    assert!(matches!(
        resolver.chmod_handle(&path_only, USER, Mode::RUSR),
        Err(ChmodError::BadDescriptor)
    ));
    fs::rename(temp.path().join("original"), temp.path().join("renamed")).unwrap();
    fs::write(temp.path().join("original"), b"replacement").unwrap();
    fs::set_permissions(
        temp.path().join("original"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    resolver
        .chmod_handle(&open, USER, Mode::RUSR | Mode::XUSR)
        .unwrap();
    assert_eq!(
        fs::metadata(temp.path().join("renamed")).unwrap().mode() & 0o777,
        0o500
    );
    assert_eq!(
        fs::metadata(temp.path().join("original")).unwrap().mode() & 0o777,
        0o600
    );
    fs::remove_file(temp.path().join("renamed")).unwrap();
    resolver.chmod_handle(&open, USER, Mode::WUSR).unwrap();
    assert_eq!(resolver.handle_status(&open).unwrap().mode, Mode::WUSR);
}

#[cfg(unix)]
#[test]
fn descriptor_chmod_directory_and_read_only_mount() {
    let temp = tempfile::tempdir_in(".").unwrap();
    fs::create_dir(temp.path().join("directory")).unwrap();
    let resolver = Resolver::<(), _>::new(backend(temp.path()));
    let open = resolver
        .open(USER, "/directory", OFlags::RDONLY, Mode::empty())
        .unwrap();
    fs::rename(temp.path().join("directory"), temp.path().join("renamed")).unwrap();
    fs::remove_dir(temp.path().join("renamed")).unwrap();
    resolver
        .chmod_handle(&open, USER, Mode::RUSR | Mode::XUSR)
        .unwrap();
    assert_eq!(
        resolver.handle_status(&open).unwrap().mode,
        Mode::RUSR | Mode::XUSR
    );

    fs::write(temp.path().join("file"), b"data").unwrap();
    let read_only = Resolver::<(), _>::new(ReadOnly::new(
        LocalFs::new(temp.path(), InodeAllocator::standalone()).unwrap(),
    ));
    let open = read_only
        .open(USER, "/file", OFlags::RDONLY, Mode::empty())
        .unwrap();
    assert!(matches!(
        read_only.chmod_handle(&open, USER, Mode::WUSR),
        Err(ChmodError::ReadOnlyFileSystem)
    ));
}

fn resolved_file<'a>(local: &'a LocalFs, name: &str) -> ResolvedFile<'a> {
    match local
        .resolve(local.root().unwrap(), &[name], &|_| {
            panic!("LocalFs must enforce host permissions itself")
        })
        .unwrap()
    {
        Resolution::Found(ResolvedTarget::File(file)) => file,
        _ => panic!("expected a resolved file"),
    }
}

fn host_timestamps(metadata: &fs::Metadata) -> FileTimestamps {
    #[cfg(unix)]
    {
        FileTimestamps {
            accessed: FileTimestamp {
                seconds: metadata.atime(),
                nanoseconds: metadata.atime_nsec().try_into().unwrap(),
            },
            modified: FileTimestamp {
                seconds: metadata.mtime(),
                nanoseconds: metadata.mtime_nsec().try_into().unwrap(),
            },
            changed: FileTimestamp {
                seconds: metadata.ctime(),
                nanoseconds: metadata.ctime_nsec().try_into().unwrap(),
            },
        }
    }
    #[cfg(windows)]
    {
        let timestamp = |time: std::time::SystemTime| {
            let nanos = match time.duration_since(std::time::UNIX_EPOCH) {
                Ok(duration) => i128::try_from(duration.as_nanos()).unwrap(),
                Err(error) => -i128::try_from(error.duration().as_nanos()).unwrap(),
            };
            FileTimestamp {
                seconds: nanos.div_euclid(1_000_000_000).try_into().unwrap(),
                nanoseconds: nanos.rem_euclid(1_000_000_000).try_into().unwrap(),
            }
        };
        let modified = timestamp(metadata.modified().unwrap());
        FileTimestamps {
            accessed: timestamp(metadata.accessed().unwrap()),
            modified,
            changed: modified,
        }
    }
}

#[test]
fn timestamp_readback_uses_signed_live_host_metadata() {
    use std::time::{Duration, UNIX_EPOCH};

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("file");
    fs::write(&path, b"content").unwrap();
    let local = backend(temp.path());
    let file = local
        .open_file(resolved_file(&local, "file"), OFlags::RDWR)
        .unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(
            fs::FileTimes::new()
                .set_accessed(UNIX_EPOCH - Duration::new(1, 123_456_700))
                .set_modified(UNIX_EPOCH - Duration::new(0, 765_432_100)),
        )
        .unwrap();
    let host = host_timestamps(&fs::metadata(&path).unwrap());
    assert_eq!(host.accessed.seconds, -2);
    assert_eq!(host.accessed.nanoseconds, 876_543_300);
    assert_eq!(host.modified.seconds, -1);
    assert_eq!(host.modified.nanoseconds, 234_567_900);
    assert_eq!(
        local.status(HandleRef::File(&file)).unwrap().times,
        Some(host)
    );
    assert_eq!(
        local
            .resolved_status(&ResolvedTarget::File(resolved_file(&local, "file")))
            .unwrap()
            .times,
        Some(host)
    );
    let root = local.open_dir(local.root().unwrap(), OFlags::PATH).unwrap();
    assert_eq!(
        local.status(HandleRef::Dir(&root)).unwrap().times,
        Some(host_timestamps(&fs::metadata(temp.path()).unwrap()))
    );
}

#[cfg(any(target_os = "linux", windows))]
#[test]
fn explicit_signed_timestamp_updates_round_trip_for_files_and_directories() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("file"), b"content").unwrap();
    let local = backend(temp.path());
    let access = FileTimestamp {
        seconds: -1_234_567,
        nanoseconds: 123_456_700,
    };
    let modify = FileTimestamp {
        seconds: -1,
        nanoseconds: 987_654_300,
    };
    let updates = SetFileTimes {
        access: FileTimeUpdate::Set(access),
        modify: FileTimeUpdate::Set(modify),
    };
    for directory in [false, true] {
        let target = || {
            if directory {
                ResolvedTarget::Dir(local.root().unwrap())
            } else {
                ResolvedTarget::File(resolved_file(&local, "file"))
            }
        };
        local.set_times(target(), &updates).unwrap();
        let status = local.resolved_status(&target()).unwrap().times.unwrap();
        assert_eq!(status.accessed, access);
        assert_eq!(status.modified, modify);
        let host_path = if directory {
            temp.path().to_owned()
        } else {
            temp.path().join("file")
        };
        assert_eq!(status, host_timestamps(&fs::metadata(host_path).unwrap()));
    }
}

#[cfg(windows)]
#[test]
fn unrepresentable_windows_timestamps_fail_without_updating_the_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("file");
    fs::write(&path, b"content").unwrap();
    let local = backend(temp.path());
    let target = || ResolvedTarget::File(resolved_file(&local, "file"));
    let before = host_timestamps(&fs::metadata(&path).unwrap());
    for seconds in [i64::MIN, i64::MAX] {
        let out_of_range = FileTimestamp {
            seconds,
            nanoseconds: 0,
        };
        assert!(matches!(
            local.set_times(
                target(),
                &SetFileTimes {
                    access: FileTimeUpdate::Omit,
                    modify: FileTimeUpdate::Set(out_of_range),
                }
            ),
            Err(SetTimesError::Io)
        ));
        assert_eq!(host_timestamps(&fs::metadata(&path).unwrap()), before);
    }
}

#[cfg(any(target_os = "linux", windows))]
#[test]
fn now_uses_host_clock_and_omit_preserves_the_other_timestamp() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("file");
    fs::write(&path, b"content").unwrap();
    let local = backend(temp.path());
    let target = || ResolvedTarget::File(resolved_file(&local, "file"));
    let explicit = FileTimestamp {
        seconds: -2,
        nanoseconds: 123_456_700,
    };
    local
        .set_times(
            target(),
            &SetFileTimes {
                access: FileTimeUpdate::Set(explicit),
                modify: FileTimeUpdate::Set(explicit),
            },
        )
        .unwrap();

    let mut previous = local.resolved_status(&target()).unwrap().times.unwrap();
    for access in [false, true] {
        let before = std::time::SystemTime::now();
        local
            .set_times(
                target(),
                &SetFileTimes {
                    access: if access {
                        FileTimeUpdate::Now
                    } else {
                        FileTimeUpdate::Omit
                    },
                    modify: if access {
                        FileTimeUpdate::Omit
                    } else {
                        FileTimeUpdate::Now
                    },
                },
            )
            .unwrap();
        let after = std::time::SystemTime::now();
        let metadata = fs::metadata(&path).unwrap();
        let current = local.resolved_status(&target()).unwrap().times.unwrap();
        assert_eq!(current, host_timestamps(&metadata));
        let host_now = if access {
            assert_eq!(current.modified, previous.modified);
            metadata.accessed().unwrap()
        } else {
            assert_eq!(current.accessed, previous.accessed);
            metadata.modified().unwrap()
        };
        // Native filesystem timestamps can lag the wall clock by one kernel clock tick.
        assert!(host_now >= before - std::time::Duration::from_secs(1));
        assert!(host_now <= after);
        previous = current;
    }
    local
        .set_times(
            target(),
            &SetFileTimes {
                access: FileTimeUpdate::Omit,
                modify: FileTimeUpdate::Omit,
            },
        )
        .unwrap();
    let omitted = local.resolved_status(&target()).unwrap().times.unwrap();
    assert_eq!(omitted.accessed, previous.accessed);
    assert_eq!(omitted.modified, previous.modified);
    #[cfg(target_os = "linux")]
    assert_eq!(omitted.changed, previous.changed);
}

#[cfg(any(target_os = "linux", windows))]
#[test]
fn timestamp_updates_do_not_follow_final_symlinks_outside_the_root() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    let outside = temp.path().join("outside");
    fs::write(&outside, b"untouched").unwrap();
    #[cfg(unix)]
    {
        symlink(&outside, root.join("escape")).unwrap();
        symlink("missing", root.join("dangling")).unwrap();
    }
    #[cfg(windows)]
    if symlink_file(&outside, root.join("escape")).is_err()
        || symlink_file("missing", root.join("dangling")).is_err()
    {
        return;
    }
    let local = backend(&root);
    let untouched = host_timestamps(&fs::metadata(&outside).unwrap());
    let explicit = FileTimestamp {
        seconds: -1,
        nanoseconds: 123_456_700,
    };
    for name in ["escape", "dangling"] {
        local
            .set_times(
                ResolvedTarget::File(resolved_file(&local, name)),
                &SetFileTimes {
                    access: FileTimeUpdate::Set(explicit),
                    modify: FileTimeUpdate::Set(explicit),
                },
            )
            .unwrap();
        let status = local
            .resolved_status(&ResolvedTarget::File(resolved_file(&local, name)))
            .unwrap();
        assert_eq!(status.file_type, FileType::SymbolicLink);
        let times = status.times.unwrap();
        assert_eq!(times.accessed, explicit);
        assert_eq!(times.modified, explicit);
        assert_eq!(
            times,
            host_timestamps(&fs::symlink_metadata(root.join(name)).unwrap())
        );
        assert_eq!(host_timestamps(&fs::metadata(&outside).unwrap()), untouched);
    }
}

#[cfg(unix)]
#[test]
fn canonical_root_live_io_and_open_file_handles() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("file"), b"initial").unwrap();
    symlink(root.join("file"), root.join("absolute")).unwrap();
    symlink(&root, temp.path().join("root_link")).unwrap();
    let local = backend(&temp.path().join("root_link"));
    assert_eq!(
        local
            .read_link_at(&local.root().unwrap(), "absolute")
            .unwrap(),
        "file"
    );
    let read_only = local
        .open_file(resolved_file(&local, "file"), OFlags::RDONLY)
        .unwrap();
    let mut buf = [0; 7];
    assert_eq!(local.read(&read_only, &mut buf, 0).unwrap(), 7);
    assert_eq!(&buf, b"initial");
    assert!(matches!(
        local.write(&read_only, b"x", 0),
        Err(WriteError::NotForWriting)
    ));
    assert!(matches!(
        local.truncate(&read_only, 0),
        Err(TruncateError::NotForWriting)
    ));

    let dir = local.root().unwrap();
    let file = local
        .open_file(resolved_file(&local, "file"), OFlags::RDWR)
        .unwrap();
    fs::rename(root.join("file"), root.join("moved_file")).unwrap();
    fs::write(root.join("file"), b"decoy").unwrap();
    local.write(&file, b"live", 0).unwrap();
    assert_eq!(fs::read(root.join("moved_file")).unwrap(), b"liveial");
    assert_eq!(fs::read(root.join("file")).unwrap(), b"decoy");
    local.unlink_at(dir, "file").unwrap();
    assert_eq!(local.read(&file, &mut buf, 0).unwrap(), 7);
    local.truncate(&file, 3).unwrap();
    assert_eq!(local.status(HandleRef::File(&file)).unwrap().size, 3);
    local
        .chmod(
            ResolvedTarget::File(resolved_file(&local, "moved_file")),
            Mode::RUSR,
        )
        .unwrap();
    assert_eq!(
        local.status(HandleRef::File(&file)).unwrap().mode,
        Mode::RUSR
    );
}

/// Shared memory that counts the copies made through it and exposes its raw
/// bytes only if `raw`.
struct CountingMemory {
    bytes: HeapSharedMemory,
    raw: bool,
    copies: AtomicUsize,
}

impl SharedMemory for CountingMemory {
    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        self.copies.fetch_add(1, Ordering::Relaxed);
        self.bytes.read(offset, destination)
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        self.copies.fetch_add(1, Ordering::Relaxed);
        self.bytes.write(offset, source)
    }

    fn raw_bytes(&self) -> Option<RawBytes<'_>> {
        self.bytes.raw_bytes().filter(|_| self.raw)
    }
}

#[test]
fn shared_buffer_io_is_direct_when_the_buffer_is_contiguous_raw_bytes() {
    // In-order slots form one contiguous part; out-of-order slots form several.
    let allocators = InodeAllocators::new();
    for (raw, slots) in [(true, [1, 2, 3]), (true, [2, 0, 3]), (false, [1, 2, 3])] {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("file"), b"0123456789").unwrap();
        let local = LocalFs::new(temp.path(), allocators.next()).unwrap();
        let file = local
            .open_file(resolved_file(&local, "file"), OFlags::RDWR)
            .unwrap();
        let memory = Arc::new(CountingMemory {
            bytes: HeapSharedMemory::new(16),
            raw,
            copies: AtomicUsize::new(0),
        });
        let layout = SharedBufferLayout::new(4, 4).unwrap();
        let pool = SharedBufferPool::new(Arc::clone(&memory), layout).unwrap();
        let mut buffer = pool
            .buffer(
                SharedBufferSequence::new(&slots.map(SharedBufferSlotIndex), 11).unwrap(),
                11,
            )
            .unwrap();
        buffer.copy_from_slice_at(0, b"abcdefghijk").unwrap();
        let direct = raw
            && slots == [1, 2, 3]
            && cfg!(any(
                target_os = "linux",
                all(windows, target_arch = "x86_64")
            ));
        memory.copies.store(0, Ordering::Relaxed);

        assert_eq!(local.write(&file, &buffer, 3).unwrap(), 11);
        let copies = memory.copies.swap(0, Ordering::Relaxed);
        assert_eq!(copies == 0, direct, "write, raw: {raw}, slots: {slots:?}");
        assert_eq!(
            fs::read(temp.path().join("file")).unwrap(),
            b"012abcdefghijk"
        );
        // A read past the end is short and leaves the rest of the buffer alone.
        assert_eq!(local.read(&file, &mut buffer, 5).unwrap(), 9);
        let copies = memory.copies.load(Ordering::Relaxed);
        assert_eq!(copies == 0, direct, "read, raw: {raw}, slots: {slots:?}");
        let mut contents = [0; 11];
        buffer.copy_to_slice_at(0, &mut contents).unwrap();
        assert_eq!(&contents, b"cdefghijkjk");
        // A read that starts past the end reads nothing.
        assert_eq!(local.read(&file, &mut buffer, 20).unwrap(), 0);
    }
}

#[cfg(unix)]
#[test]
fn native_identity_and_listing_agree_even_for_hard_links() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("one"), b"content").unwrap();
    fs::hard_link(temp.path().join("one"), temp.path().join("two")).unwrap();
    let local = backend(temp.path());
    let one = local
        .open_file(resolved_file(&local, "one"), OFlags::PATH)
        .unwrap();
    let two = local
        .open_file(resolved_file(&local, "two"), OFlags::PATH)
        .unwrap();
    let expected = local.status(HandleRef::File(&one)).unwrap().node_info;
    assert_eq!(
        expected,
        local.status(HandleRef::File(&two)).unwrap().node_info
    );
    let bad_name = std::ffi::OsStr::from_bytes(b"bad\xffname");
    fs::write(temp.path().join(bad_name), b"hidden").unwrap();
    let entries = local
        .list_dir_at(
            local
                .open_dir(local.root().unwrap(), OFlags::RDONLY)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(entries.len(), 2, "non-UTF-8 entries must be hidden");
    assert_eq!(
        entries.iter().find(|e| e.name == "one").unwrap().ino_info,
        Some(expected)
    );
    assert_eq!(
        entries.iter().find(|e| e.name == "two").unwrap().ino_info,
        Some(expected)
    );
}

#[test]
fn invalid_components_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let local = backend(temp.path());
    let portable = ["", ".", "..", "a/b", "/absolute", "nul\0byte"];
    // Win32 path parsing gives these namespace or device meaning.
    let win32_special = [
        "a\\b",
        "stream:name",
        "CON",
        "con.txt",
        "COM0",
        "com1.log",
        "LPT9.log",
        "trailing.",
        "trailing ",
        "question?",
    ];
    let rejected = portable
        .iter()
        .chain(win32_special.iter().filter(|_| cfg!(windows)));
    for &bad in rejected {
        assert!(
            matches!(
                local.resolve(local.root().unwrap(), &[bad], &|_| unreachable!()),
                Err(ResolutionError {
                    component: Some(0),
                    error: WalkError::PathError(PathError::InvalidPathname),
                })
            ),
            "{bad:?}"
        );
        assert!(
            local.unlink_at(local.root().unwrap(), bad).is_err(),
            "{bad:?}"
        );
        assert!(
            local.rmdir_at(local.root().unwrap(), bad).is_err(),
            "{bad:?}"
        );
    }

    // Win32-reserved spellings are ordinary names on Unix hosts.
    #[cfg(unix)]
    {
        for name in win32_special {
            fs::write(temp.path().join(name), b"visible").unwrap();
        }
        let entries = local
            .list_dir_at(
                local
                    .open_dir(local.root().unwrap(), OFlags::RDONLY)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(entries.len(), win32_special.len());
        for name in win32_special {
            assert!(entries.iter().any(|e| e.name == name), "{name:?}");
            assert!(
                local
                    .open_file(resolved_file(&local, name), OFlags::RDONLY)
                    .is_ok(),
                "{name:?}"
            );
        }
    }
}

#[test]
fn resolution_is_unopened_and_reports_component_failures() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("dir")).unwrap();
    fs::write(temp.path().join("file"), b"intact").unwrap();
    let local = backend(temp.path());
    assert!(matches!(
        local.resolve(local.root().unwrap(), &[], &|_| unreachable!()),
        Ok(Resolution::Found(ResolvedTarget::Dir(_)))
    ));
    let target = ResolvedTarget::File(resolved_file(&local, "file"));
    assert_eq!(local.resolved_status(&target).unwrap().size, 6);
    assert_eq!(
        local.resolved_status(&target).unwrap().file_type,
        FileType::RegularFile
    );
    #[cfg(unix)]
    {
        fs::set_permissions(temp.path().join("file"), fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(local.resolved_status(&target).unwrap().mode, Mode::empty());
        local.chmod(target, Mode::RUSR | Mode::WUSR).unwrap();
    }
    assert_eq!(fs::read(temp.path().join("file")).unwrap(), b"intact");
    for (components, component, non_directory) in [
        (["absent", "child"], 0, false),
        (["file", "child"], 1, true),
    ] {
        let error = local
            .resolve(local.root().unwrap(), &components, &|_| unreachable!())
            .err()
            .expect("an intermediate component must fail");
        assert_eq!(error.component, Some(component));
        assert!(matches!(
            (error.error, non_directory),
            (
                WalkError::PathError(PathError::NoSuchFileOrDirectory),
                false
            ) | (
                WalkError::PathError(PathError::ComponentNotADirectory),
                true
            )
        ));
    }
    let Resolution::MissingFinal { parent } = local
        .resolve(
            local.root().unwrap(),
            &["dir", "missing"],
            &|_| unreachable!(),
        )
        .unwrap()
    else {
        panic!("only the final component is missing");
    };
    let parent = local.open_dir(parent, OFlags::RDONLY).unwrap();
    assert_eq!(local.list_dir_at(parent).unwrap().len(), 0);
    assert!(!temp.path().join("dir/missing").exists());
}

#[test]
fn exclusive_open_never_truncates_existing_file() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("file"), b"intact").unwrap();
    let local = backend(temp.path());
    assert!(matches!(
        local.open_file(
            resolved_file(&local, "file"),
            OFlags::CREAT | OFlags::EXCL | OFlags::TRUNC | OFlags::RDWR,
        ),
        Err(OpenError::AlreadyExists)
    ));
    assert_eq!(fs::read(temp.path().join("file")).unwrap(), b"intact");
}

#[test]
fn path_handles_report_live_files() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("file"), b"content").unwrap();
    let local = backend(temp.path());
    let file = local
        .open_file(resolved_file(&local, "file"), OFlags::PATH)
        .unwrap();
    assert_eq!(local.status(HandleRef::File(&file)).unwrap().size, 7);
    fs::write(temp.path().join("file"), b"longer content").unwrap();
    assert_eq!(local.status(HandleRef::File(&file)).unwrap().size, 14);
}

/// Every host entry below `root`, with its permissions and any file contents.
fn host_tree(root: &Path) -> Vec<(PathBuf, fs::Permissions, Option<Vec<u8>>)> {
    let mut tree = Vec::new();
    let mut pending = vec![root.to_owned()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            let contents = if metadata.is_dir() {
                pending.push(path.clone());
                None
            } else {
                Some(fs::read(&path).unwrap())
            };
            tree.push((path, metadata.permissions(), contents));
        }
    }
    tree.sort_by(|a, b| a.0.cmp(&b.0));
    tree
}

#[test]
fn read_only_backend_reads_live_and_refuses_every_host_mutation() {
    macro_rules! assert_err {
        ($result:expr, $error:pat) => {
            assert!(matches!($result, Err($error)), "{}", stringify!($result))
        };
    }
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("file"), b"content").unwrap();
    fs::create_dir(temp.path().join("dir")).unwrap();
    fs::write(temp.path().join("dir/inner"), b"inner").unwrap();
    fs::create_dir(temp.path().join("empty")).unwrap();
    let before = host_tree(temp.path());
    let resolver: Resolver<(), _> = Resolver::new(
        Composer::builder()
            .try_mount("/ro", |ids| {
                LocalFs::new(temp.path(), ids).map(ReadOnly::new)
            })
            .unwrap()
            .build()
            .unwrap(),
    );
    let open = |path, flags| resolver.open(USER, path, flags, Mode::RWXU);

    for (path, flags) in [
        ("/ro/file", OFlags::WRONLY),
        ("/ro/file", OFlags::RDWR),
        ("/ro/file", OFlags::RDONLY | OFlags::TRUNC),
        ("/ro/dir", OFlags::RDWR),
        ("/ro/dir", OFlags::RDONLY | OFlags::TRUNC),
        ("/ro/new", OFlags::RDONLY | OFlags::CREAT),
    ] {
        assert!(
            matches!(open(path, flags), Err(OpenError::ReadOnlyFileSystem)),
            "{path} {flags:?}"
        );
    }
    assert_err!(
        open("/ro/file", OFlags::RDWR | OFlags::CREAT | OFlags::EXCL),
        OpenError::AlreadyExists
    );
    assert_err!(
        resolver.mkdir(USER, "/ro/new", Mode::RWXU),
        MkdirError::ReadOnlyFileSystem
    );
    assert_err!(
        resolver.mkdir(USER, "/ro/dir", Mode::RWXU),
        MkdirError::AlreadyExists
    );
    assert_err!(
        resolver.symlink(USER, "file", "/ro/new"),
        SymlinkError::ReadOnlyFileSystem
    );
    assert_err!(
        resolver.symlink(USER, "file", "/ro/file"),
        SymlinkError::AlreadyExists
    );
    // Like Linux, the read-only check precedes the final-name lookup.
    for (file, dir) in [("/ro/file", "/ro/empty"), ("/ro/missing", "/ro/missing")] {
        assert_err!(resolver.unlink(USER, file), UnlinkError::ReadOnlyFileSystem);
        assert_err!(resolver.rmdir(USER, dir), RmdirError::ReadOnlyFileSystem);
        assert_err!(
            resolver.rename(USER, file, "/ro/moved"),
            RenameError::ReadOnlyFileSystem
        );
    }
    assert_err!(
        resolver.chmod(USER, "/ro/file", Mode::RUSR),
        ChmodError::ReadOnlyFileSystem
    );
    assert_err!(
        resolver.chown(USER, "/ro/file", None, None),
        ChownError::ReadOnlyFileSystem
    );
    let explicit = FileTimeUpdate::Set(FileTimestamp {
        seconds: 1,
        nanoseconds: 0,
    });
    assert_err!(
        resolver.set_times(
            USER,
            &open("/ro/file", OFlags::PATH).unwrap(),
            &SetFileTimes {
                access: explicit,
                modify: explicit,
            },
        ),
        SetTimesError::ReadOnlyFileSystem
    );

    let mut opened = open("/ro/file", OFlags::RDONLY | OFlags::CREAT).unwrap();
    let mut buf = [0; 7];
    assert_eq!(resolver.read(&mut opened, &mut buf, Some(0)).unwrap(), 7);
    assert_eq!(&buf, b"content");
    assert_eq!(host_tree(temp.path()), before);

    fs::write(temp.path().join("file"), b"changed").unwrap();
    assert_eq!(resolver.read(&mut opened, &mut buf, Some(0)).unwrap(), 7);
    assert_eq!(&buf, b"changed");
}

#[cfg(unix)]
#[test]
fn direct_backend_mutations_and_flags() {
    let temp = tempfile::tempdir().unwrap();
    let local = backend(temp.path());
    fs::write(temp.path().join("new"), b"").unwrap();
    let file = local
        .open_file(resolved_file(&local, "new"), OFlags::RDWR)
        .unwrap();
    local.write(&file, b"x", 4096).unwrap();
    let mut hole = [1; 4];
    assert_eq!(local.read(&file, &mut hole, 64).unwrap(), 4);
    assert_eq!(hole, [0; 4]);
    assert_eq!(local.status(HandleRef::File(&file)).unwrap().size, 4097);
    local.truncate(&file, 8192).unwrap();
    assert_eq!(local.status(HandleRef::File(&file)).unwrap().size, 8192);
    local.truncate(&file, 4097).unwrap();
    assert!(
        local
            .open_file(
                resolved_file(&local, "new"),
                OFlags::WRONLY | OFlags::DIRECTORY | OFlags::TRUNC
            )
            .is_err()
    );
    assert_eq!(fs::metadata(temp.path().join("new")).unwrap().len(), 4097);
    fs::create_dir(temp.path().join("dir")).unwrap();
    let Resolution::Found(ResolvedTarget::Dir(dir)) = local
        .resolve(local.root().unwrap(), &["dir"], &|_| unreachable!())
        .unwrap()
    else {
        panic!("expected directory");
    };
    let dir = local.open_dir(dir, OFlags::PATH).unwrap();
    assert!(local.status(HandleRef::Dir(&dir)).is_ok());
    assert!(local.walking_dir_at(&dir).is_some());
    local.unlink_at(local.root().unwrap(), "new").unwrap();
    local.rmdir_at(local.root().unwrap(), "dir").unwrap();
    assert!(!temp.path().join("new").exists());
    assert!(!temp.path().join("dir").exists());
}

#[test]
fn competing_creators_never_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let local: Resolver<(), _> = Resolver::new(backend(temp.path()));
    let (left, right) = std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            local.open(
                USER,
                "/only_one",
                OFlags::CREAT | OFlags::EXCL | OFlags::RDWR,
                Mode::RWXU,
            )
        });
        let right = scope.spawn(|| {
            local.open(
                USER,
                "/only_one",
                OFlags::CREAT | OFlags::EXCL | OFlags::RDWR,
                Mode::RWXU,
            )
        });
        (left.join().unwrap(), right.join().unwrap())
    });
    assert_ne!(left.is_ok(), right.is_ok());
    assert!(matches!(
        left.err().or(right.err()),
        Some(OpenError::AlreadyExists)
    ));
}

#[cfg(unix)]
#[test]
fn read_only_truncate_requires_host_write_permission() {
    let temp = tempfile::tempdir().unwrap();
    if fs::metadata(temp.path()).unwrap().uid() == 0 {
        return;
    }
    let path = temp.path().join("file");
    fs::write(&path, b"intact").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    let local = backend(temp.path());
    assert!(
        local
            .open_file(
                resolved_file(&local, "file"),
                OFlags::RDONLY | OFlags::TRUNC
            )
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), b"intact");
}

#[cfg(unix)]
#[test]
fn dangling_symlink_cannot_be_replaced_by_creation() {
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside");
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    symlink(&outside, root.join("dangling")).unwrap();
    let local: Resolver<(), _> = Resolver::new(backend(&root));
    assert!(
        local
            .open(
                USER,
                "/dangling",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RUSR
            )
            .is_err()
    );
    assert!(
        fs::symlink_metadata(root.join("dangling"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!outside.exists());
}

#[cfg(unix)]
#[test]
fn host_symlinks_stay_bounded_and_special_files_are_not_opened() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("target"), b"inside").unwrap();
    let outside = temp.path().join("outside");
    fs::write(&outside, b"outside").unwrap();
    symlink("../target", root.join("sub/relative")).unwrap();
    symlink("sub", root.join("dir_link")).unwrap();
    symlink(root.join("target"), root.join("absolute")).unwrap();
    symlink(&outside, root.join("escape")).unwrap();
    symlink("../../outside", root.join("sub/climb")).unwrap();
    symlink("cycle_b", root.join("cycle_a")).unwrap();
    symlink("cycle_a", root.join("cycle_b")).unwrap();
    symlink("target", root.join("chain_a")).unwrap();
    symlink("chain_a", root.join("chain_b")).unwrap();
    let alternative = temp.path().join("alternative");
    symlink(root.join("target"), &alternative).unwrap();
    symlink(&alternative, root.join("tool")).unwrap();
    let outside_alternative = temp.path().join("outside_alternative");
    symlink(&outside, &outside_alternative).unwrap();
    symlink(&outside_alternative, root.join("tool_escape")).unwrap();
    let socket = std::os::unix::net::UnixListener::bind(root.join("socket")).unwrap();
    let local: Resolver<(), _> = Resolver::new(backend(&root));
    let listed = local
        .read_dir(
            &local
                .open(USER, "/", OFlags::RDONLY, Mode::empty())
                .unwrap(),
        )
        .unwrap();
    assert!(!listed.iter().any(|entry| entry.name == "socket"));
    for name in ["escape", "absolute", "dir_link"] {
        assert!(
            listed
                .iter()
                .any(|entry| entry.name == name && entry.file_type == FileType::SymbolicLink),
            "{name}"
        );
    }
    assert_eq!(local.read_link(USER, "/absolute").unwrap(), "target");
    assert_eq!(local.read_link(USER, "/tool").unwrap(), "target");
    assert_eq!(local.read_link(USER, "/sub/relative").unwrap(), "../target");
    assert_eq!(
        local
            .file_status(USER, "/absolute", false)
            .unwrap()
            .file_type,
        FileType::SymbolicLink
    );
    for name in [
        "/absolute",
        "/chain_b",
        "/sub/relative",
        "/dir_link/relative",
        "/tool",
    ] {
        let mut file = local
            .open(USER, name, OFlags::RDONLY, Mode::empty())
            .unwrap();
        let mut buf = [0; 6];
        assert_eq!(
            local.read(&mut file, &mut buf, Some(0)).unwrap(),
            6,
            "{name}"
        );
        assert_eq!(&buf, b"inside");
    }
    for name in [
        "/escape",
        "/sub/climb",
        "/cycle_a",
        "/socket",
        "/tool_escape",
    ] {
        assert!(
            local
                .open(USER, name, OFlags::RDONLY, Mode::empty())
                .is_err(),
            "{name}"
        );
    }
    for (name, flags) in [
        ("/absolute", OFlags::RDONLY | OFlags::NOFOLLOW),
        (
            "/dir_link",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        ),
    ] {
        assert!(
            local.open(USER, name, flags, Mode::empty()).is_err(),
            "{name}"
        );
    }
    assert!(local.unlink(USER, "/socket").is_err());
    assert!(root.join("socket").exists());
    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    drop(socket);
}

/// Following a host link out of the root fails the same way whether or not its target exists,
/// so the guest learns nothing about host paths outside the root.
#[cfg(unix)]
#[test]
fn host_symlinks_out_of_the_root_reveal_nothing_about_their_targets() {
    use litebox_broker_core::fs::errors::FileStatusError;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("present"), b"outside").unwrap();
    symlink(outside.join("present"), root.join("present")).unwrap();
    symlink(outside.join("missing"), root.join("missing")).unwrap();
    symlink(outside.join("present/below"), root.join("not_directory")).unwrap();
    let local: Resolver<(), _> = Resolver::new(backend(&root));
    for name in ["/present", "/missing", "/not_directory"] {
        assert!(
            matches!(
                local.file_status(USER, name, true),
                Err(FileStatusError::PathError(PathError::InvalidPathname))
            ),
            "{name}"
        );
    }
}

#[cfg(unix)]
#[test]
fn unreadable_directory_is_not_an_empty_listing() {
    // Root may legitimately bypass DAC, so this requires an unprivileged host test run.
    let temp = tempfile::tempdir().unwrap();
    if fs::metadata(temp.path()).unwrap().uid() == 0 {
        return;
    }
    fs::write(temp.path().join("entry"), b"data").unwrap();
    let local = backend(temp.path());
    let dir = local.open_dir(local.root().unwrap(), OFlags::PATH).unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o000)).unwrap();
    assert!(local.list_dir_at(dir).is_err());
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
#[test]
fn final_symlink_removal_does_not_follow_the_link() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("directory")).unwrap();
    symlink("directory", temp.path().join("dir_link")).unwrap();
    symlink("missing", temp.path().join("file_link")).unwrap();
    let local = backend(temp.path());

    assert!(local.rmdir_at(local.root().unwrap(), "dir_link").is_err());
    assert!(temp.path().join("directory").is_dir());
    assert!(
        fs::symlink_metadata(temp.path().join("dir_link"))
            .unwrap()
            .file_type()
            .is_symlink()
    );

    local.unlink_at(local.root().unwrap(), "file_link").unwrap();
    assert!(fs::symlink_metadata(temp.path().join("file_link")).is_err());
}

#[cfg(unix)]
#[test]
fn resolver_and_composer_use_host_permissions_and_live_positions() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("file"), b"abc").unwrap();
    let composer = Composer::builder()
        .try_mount("/host", |ids| LocalFs::new(temp.path(), ids))
        .unwrap()
        .build()
        .unwrap();
    let resolver: Resolver<(), _> = Resolver::new(composer);
    let mut file = resolver
        .open(USER, "/host/file", OFlags::RDWR, Mode::empty())
        .unwrap();
    assert!(resolver.get_static_backing_data(&file).is_none());
    let mut buf = [0; 3];
    assert_eq!(resolver.read(&mut file, &mut buf, None).unwrap(), 3);
    assert_eq!(&buf, b"abc");
    resolver
        .seek(&mut file, 0, SeekWhence::RelativeToBeginning)
        .unwrap();
    resolver.write(&mut file, b"Z", None).unwrap();
    resolver.write(&mut file, b"!", Some(2)).unwrap();
    assert_eq!(fs::read(temp.path().join("file")).unwrap(), b"Zb!");
    let mut appended = resolver
        .open(
            USER,
            "/host/file",
            OFlags::WRONLY | OFlags::APPEND,
            Mode::empty(),
        )
        .unwrap();
    resolver.write(&mut appended, b"+", None).unwrap();
    assert_eq!(fs::read(temp.path().join("file")).unwrap(), b"Zb!+");
    let status = resolver.file_status(USER, "/host/file", true).unwrap();
    assert_eq!(status.size, 4);
    resolver.truncate(&mut file, 2, false).unwrap();
    assert_eq!(fs::read(temp.path().join("file")).unwrap(), b"Zb");
    resolver.mkdir(USER, "/host/folder", Mode::RWXU).unwrap();
    resolver.rmdir(USER, "/host/folder").unwrap();
    // Existing resolver behavior creates a regular file on CREAT|DIRECTORY.
    let created = resolver
        .open(
            USER,
            "/host/creat_dir",
            OFlags::CREAT | OFlags::DIRECTORY | OFlags::RDWR,
            Mode::RUSR | Mode::SUID | Mode::SGID,
        )
        .unwrap();
    assert_eq!(
        resolver.handle_status(&created).unwrap().file_type,
        litebox_broker_core::fs::FileType::RegularFile
    );
    assert_eq!(
        resolver.handle_status(&created).unwrap().mode & (Mode::SUID | Mode::SGID),
        Mode::empty()
    );
    resolver.unlink(USER, "/host/creat_dir").unwrap();
    resolver.unlink(USER, "/host/file").unwrap();
}

#[cfg(unix)]
#[test]
fn foreign_handles_are_not_usable_and_host_modes_are_live() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    fs::write(a.path().join("f"), b"one").unwrap();
    let allocators = InodeAllocators::new();
    let first = LocalFs::new(a.path(), allocators.next()).unwrap();
    let second = LocalFs::new(b.path(), allocators.next()).unwrap();
    assert!(
        second
            .resolve(first.root().unwrap(), &["f"], &|_| unreachable!())
            .is_err()
    );
    let foreign = first.open_dir(first.root().unwrap(), OFlags::PATH).unwrap();
    assert!(second.list_dir_at(foreign.clone()).is_err());
    assert!(second.walking_dir_at(&foreign).is_none());
    assert!(second.unlink_at(first.root().unwrap(), "f").is_err());
    assert_eq!(fs::read(a.path().join("f")).unwrap(), b"one");
    let file = first
        .open_file(resolved_file(&first, "f"), OFlags::RDONLY)
        .unwrap();
    assert!(second.status(HandleRef::File(&file)).is_err());
    assert!(
        second
            .open_file(resolved_file(&first, "f"), OFlags::PATH)
            .is_err()
    );
    assert!(
        second
            .resolved_status(&ResolvedTarget::File(resolved_file(&first, "f")))
            .is_err()
    );
    assert!(
        second
            .chmod(
                ResolvedTarget::File(resolved_file(&first, "f")),
                Mode::empty()
            )
            .is_err()
    );
    assert!(
        second
            .chown(ResolvedTarget::File(resolved_file(&first, "f")), None, None)
            .is_err()
    );
    let times = SetFileTimes {
        access: FileTimeUpdate::Omit,
        modify: FileTimeUpdate::Omit,
    };
    for foreign in [
        ResolvedTarget::Dir(first.root().unwrap()),
        ResolvedTarget::File(resolved_file(&first, "f")),
    ] {
        assert!(matches!(
            second.set_times(foreign, &times),
            Err(SetTimesError::Io)
        ));
    }
    fs::set_permissions(a.path().join("f"), fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        first.status(HandleRef::File(&file)).unwrap().mode.bits() & 0o777,
        0o600
    );
    first
        .chmod(
            ResolvedTarget::File(resolved_file(&first, "f")),
            Mode::RUSR | Mode::SUID | Mode::SGID,
        )
        .unwrap();
    assert_eq!(
        first.status(HandleRef::File(&file)).unwrap().mode & (Mode::SUID | Mode::SGID),
        Mode::empty()
    );
    assert_eq!(
        fs::metadata(a.path().join("f"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o400
    );
    let host_metadata = fs::metadata(a.path().join("f")).unwrap();
    if let (Ok(uid), Ok(gid)) = (
        u16::try_from(host_metadata.uid()),
        u16::try_from(host_metadata.gid()),
    ) {
        first
            .chown(
                ResolvedTarget::File(resolved_file(&first, "f")),
                Some(uid),
                Some(gid),
            )
            .unwrap();
        assert!(matches!(
            first.chown(
                ResolvedTarget::File(resolved_file(&first, "f")),
                Some(uid.wrapping_add(1)),
                None
            ),
            Err(ChownError::NotTheOwner)
        ));
    }
}

#[cfg(windows)]
#[test]
fn live_io_creation_listing_and_removal() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("existing"), b"abc").unwrap();
    let local: Resolver<(), _> = Resolver::new(backend(temp.path()));

    let mut file = local
        .open(USER, "/existing", OFlags::RDWR, Mode::empty())
        .unwrap();
    let mut data = [0; 3];
    assert_eq!(local.read(&mut file, &mut data, Some(0)).unwrap(), 3);
    assert_eq!(&data, b"abc");
    assert_eq!(local.write(&mut file, b"Z", Some(1)).unwrap(), 1);
    assert_eq!(fs::read(temp.path().join("existing")).unwrap(), b"aZc");

    local.mkdir(USER, "/directory", Mode::RWXU).unwrap();
    let created = local
        .open(
            USER,
            "/created",
            OFlags::CREAT | OFlags::EXCL | OFlags::RDWR,
            Mode::RUSR | Mode::WUSR,
        )
        .unwrap();
    assert_eq!(local.handle_status(&created).unwrap().size, 0);
    let root = local
        .open(USER, "/", OFlags::RDONLY, Mode::empty())
        .unwrap();
    let entries = local.read_dir(&root).unwrap();
    assert!(entries.iter().any(|entry| entry.name == "existing"));
    assert!(entries.iter().any(|entry| entry.name == "created"));
    assert!(entries.iter().any(|entry| entry.name == "directory"));

    local.chmod(USER, "/created", Mode::RUSR).unwrap();
    assert!(
        fs::metadata(temp.path().join("created"))
            .unwrap()
            .permissions()
            .readonly()
    );
    assert!(local.unlink(USER, "/created").is_err());
    local
        .chmod(USER, "/created", Mode::RUSR | Mode::WUSR)
        .unwrap();
    // std's Windows deletion can remain pending while an existing handle is open.
    drop(created);
    local.unlink(USER, "/created").unwrap();
    let replacement = local
        .open(
            USER,
            "/created",
            OFlags::CREAT | OFlags::EXCL | OFlags::RDWR,
            Mode::RUSR | Mode::WUSR,
        )
        .unwrap();
    drop(replacement);
    local.unlink(USER, "/created").unwrap();
    local.rmdir(USER, "/directory").unwrap();
    local.unlink(USER, "/existing").unwrap();
    assert!(!temp.path().join("created").exists());
    assert!(!temp.path().join("directory").exists());
    assert!(!temp.path().join("existing").exists());
}

#[cfg(windows)]
#[test]
fn symlinks_are_bounded_when_windows_allows_test_symlink_creation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("target"), b"inside").unwrap();
    fs::write(temp.path().join("outside"), b"outside").unwrap();

    if symlink_file("target", root.join("inside_link")).is_err()
        || symlink_file(root.join("target"), root.join("absolute_link")).is_err()
        || symlink_file("..\\outside", root.join("escape_link")).is_err()
        || symlink_dir(".", root.join("dir_link")).is_err()
    {
        return;
    }

    let local: Resolver<(), _> = Resolver::new(backend(&root));
    for name in ["/inside_link", "/absolute_link"] {
        let mut inside = local
            .open(USER, name, OFlags::RDONLY, Mode::empty())
            .unwrap();
        let mut data = [0; 6];
        assert_eq!(local.read(&mut inside, &mut data, Some(0)).unwrap(), 6);
        assert_eq!(&data, b"inside");
    }
    assert_eq!(local.read_link(USER, "/absolute_link").unwrap(), "target");
    assert!(
        local
            .open(USER, "/escape_link", OFlags::RDONLY, Mode::empty())
            .is_err()
    );
    assert!(
        local
            .open(
                USER,
                "/inside_link",
                OFlags::RDONLY | OFlags::NOFOLLOW,
                Mode::empty()
            )
            .is_err()
    );

    assert!(matches!(
        local.rmdir(USER, "/dir_link"),
        Err(RmdirError::NotADirectory)
    ));
    local.unlink(USER, "/inside_link").unwrap();
    assert!(fs::symlink_metadata(root.join("inside_link")).is_err());
    assert_eq!(fs::read(root.join("target")).unwrap(), b"inside");
}
