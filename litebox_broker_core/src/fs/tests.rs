// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Filesystem semantics for the broker-core resolver and its backends.
//!
//! These tests drive the resolver and the backends directly. There is deliberately no broker
//! process, transport, or guest descriptor table involved: the semantics under test are owned by
//! broker core.

use alloc::borrow::Cow;

use super::in_mem::InMem;
use super::inode_allocator::{InodeAllocator, InodeAllocators};
use super::overlay::Overlay;
use super::resolver::{Resolver, ResolverEntry};
use super::tar_ro::TarRo;
use super::{FileType, Mode, OFlags, SeekWhence, UserInfo};
use crate::test_platform::TestPlatform;

const TEST_TAR_FILE: &[u8] = include_bytes!("./test.tar");
const USER: UserInfo = UserInfo {
    user: 1000,
    group: 1000,
};
const ROOT: UserInfo = UserInfo::ROOT;

impl<Platform: litebox_platform::sync::RawSyncPrimitivesProvider> Resolver<Platform> {
    /// Sets times by path the way the shim does: open the target `O_PATH`, then set by handle.
    pub(crate) fn set_times_at(
        &self,
        user: UserInfo,
        path: &str,
        follow_symlinks: bool,
        times: &super::SetFileTimes,
    ) -> Result<(), super::errors::SetTimesError> {
        let flags = if follow_symlinks {
            OFlags::PATH
        } else {
            OFlags::PATH | OFlags::NOFOLLOW
        };
        let entry = self
            .open(user, path, flags, Mode::empty())
            .expect("open the target");
        self.set_times(user, &entry, times)
    }
}

fn in_mem_fs() -> Resolver<TestPlatform> {
    Resolver::new(InMem::<TestPlatform>::new(InodeAllocators::new().next()))
}

fn tar_ro_fs(tar_data: Cow<'static, [u8]>) -> Resolver<TestPlatform> {
    Resolver::new(TarRo::new(tar_data, InodeAllocators::new().next()))
}

/// The path that `path` opens as, and up to 1 KiB of its content.
fn read_path(
    fs: &Resolver<TestPlatform>,
    path: &str,
) -> (alloc::string::String, alloc::vec::Vec<u8>) {
    let mut fd = fs
        .open(USER, path, OFlags::RDONLY, Mode::empty())
        .unwrap_or_else(|error| panic!("open {path:?} failed: {error:?}"));
    let mut buffer = alloc::vec![0; 1024];
    let len = fs.read(&mut fd, &mut buffer, None).unwrap();
    buffer.truncate(len);
    (fd.path().into(), buffer)
}

/// One entry of an archive built by [`build_tar`].
struct ArchiveEntry<'a> {
    entry_type: tar_core::EntryType,
    path: &'a str,
    /// The link target for symlinks and hard links.
    link: &'a str,
    mode: u32,
    owner: u64,
    data: &'a [u8],
}

impl<'a> ArchiveEntry<'a> {
    fn dir(path: &'a str, mode: u32, owner: u64) -> Self {
        Self {
            entry_type: tar_core::EntryType::Directory,
            path,
            link: "",
            mode,
            owner,
            data: &[],
        }
    }

    fn file(path: &'a str, mode: u32, data: &'a [u8]) -> Self {
        Self {
            entry_type: tar_core::EntryType::Regular,
            path,
            link: "",
            mode,
            owner: u64::from(USER.user),
            data,
        }
    }

    fn symlink(path: &'a str, target: &'a str) -> Self {
        Self {
            entry_type: tar_core::EntryType::Symlink,
            path,
            link: target,
            mode: 0o777,
            owner: u64::from(USER.user),
            data: &[],
        }
    }

    fn hard_link(path: &'a str, target: &'a str) -> Self {
        Self {
            entry_type: tar_core::EntryType::Link,
            ..Self::symlink(path, target)
        }
    }
}

/// An archive of `entries`, with long names and link targets in `extension_mode` records.
fn build_tar(
    extension_mode: tar_core::builder::ExtensionMode,
    entries: &[ArchiveEntry<'_>],
) -> Cow<'static, [u8]> {
    use tar_core::builder::{EntryBuilder, HeaderBuilder};
    let mut archive = alloc::vec::Vec::new();
    for entry in entries {
        let mut builder = EntryBuilder::with_mode(HeaderBuilder::new_ustar(), extension_mode);
        builder
            .path(entry.path)
            .entry_type(entry.entry_type)
            .mode(entry.mode)
            .unwrap()
            .uid(entry.owner)
            .unwrap()
            .gid(entry.owner)
            .unwrap()
            .size(entry.data.len() as u64)
            .unwrap();
        if !entry.link.is_empty() {
            builder.link_name(entry.link);
        }
        archive.extend(builder.finish_bytes());
        archive.extend_from_slice(entry.data);
        archive.resize(archive.len().next_multiple_of(512), 0);
    }
    archive.resize(archive.len() + 1024, 0);
    archive.into()
}

/// An overlay of `upper` over a tar-backed lower layer.
fn overlay_fs(
    upper: impl FnOnce(InodeAllocator) -> InMem<TestPlatform>,
    tar_data: Cow<'static, [u8]>,
) -> Resolver<TestPlatform> {
    let allocators = InodeAllocators::new();
    Resolver::new(Overlay::<TestPlatform>::new(
        upper(allocators.next()),
        TarRo::new(tar_data, allocators.next()),
        allocators.next(),
    ))
}

mod timestamps {
    use super::*;
    use crate::fs::backend::{Backend, Resolution};
    use crate::fs::errors::SetTimesError;
    use crate::fs::in_mem::InitialNode;
    use crate::fs::{FileTimeUpdate, FileTimestamp, FileTimestamps, SetFileTimes};

    const BEFORE_EPOCH: FileTimestamp = FileTimestamp {
        seconds: -123,
        nanoseconds: 987_654_321,
    };
    const LATER: FileTimestamp = FileTimestamp {
        seconds: 456,
        nanoseconds: 123_456_789,
    };
    const UNSET: FileTimestamp = FileTimestamp {
        seconds: 0,
        nanoseconds: 0,
    };

    fn update(access: FileTimeUpdate, modify: FileTimeUpdate) -> SetFileTimes {
        SetFileTimes { access, modify }
    }

    #[test]
    fn set_times_permission_matrix() {
        let backend = InMem::<TestPlatform>::new_initialized(
            [
                (
                    "/owned",
                    InitialNode::File {
                        mode: Mode::empty(),
                        owner: USER,
                        data: Cow::Borrowed(b""),
                    },
                ),
                (
                    "/writable",
                    InitialNode::File {
                        mode: Mode::WOTH,
                        owner: ROOT,
                        data: Cow::Borrowed(b""),
                    },
                ),
                (
                    "/private",
                    InitialNode::File {
                        mode: Mode::empty(),
                        owner: ROOT,
                        data: Cow::Borrowed(b""),
                    },
                ),
            ],
            InodeAllocators::new().next(),
        );
        let fs = Resolver::<TestPlatform>::new(backend);
        let explicit = update(FileTimeUpdate::Set(BEFORE_EPOCH), FileTimeUpdate::Omit);
        let both_now = update(FileTimeUpdate::Now, FileTimeUpdate::Now);
        fs.set_times_at(USER, "/owned", true, &explicit).unwrap();
        fs.set_times_at(ROOT, "/owned", true, &explicit).unwrap();
        fs.set_times_at(USER, "/writable", true, &both_now).unwrap();
        // In-mem has no clock, so an authorized NOW leaves times unset.
        assert_eq!(fs.file_status(ROOT, "/writable", true).unwrap().times, None);
        assert!(matches!(
            fs.set_times_at(USER, "/private", true, &both_now),
            Err(SetTimesError::AccessNotAllowed)
        ));
        for path in ["/writable", "/private"] {
            for times in [explicit, update(FileTimeUpdate::Now, FileTimeUpdate::Omit)] {
                assert!(matches!(
                    fs.set_times_at(USER, path, true, &times),
                    Err(SetTimesError::NotTheOwner)
                ));
            }
        }
        fs.set_times_at(
            USER,
            "/private",
            true,
            &update(FileTimeUpdate::Omit, FileTimeUpdate::Omit),
        )
        .unwrap();
        assert_eq!(fs.file_status(ROOT, "/private", true).unwrap().times, None);
    }

    #[test]
    fn set_times_signed_omit_nofollow_and_directory() {
        let fs = in_mem_fs();
        fs.mkdir(ROOT, "/dir", Mode::RWXU).unwrap();
        let entry = fs
            .open(
                ROOT,
                "/dir/file",
                OFlags::CREAT | OFlags::RDONLY,
                Mode::RUSR,
            )
            .unwrap();
        fs.symlink(ROOT, "file", "/dir/link").unwrap();
        let explicit = update(FileTimeUpdate::Set(BEFORE_EPOCH), FileTimeUpdate::Now);
        fs.set_times_at(ROOT, "/dir/link", false, &explicit)
            .unwrap();
        assert_eq!(
            fs.file_status(ROOT, "/dir/link", false).unwrap().times,
            Some(FileTimestamps {
                accessed: BEFORE_EPOCH,
                modified: UNSET,
                changed: UNSET
            })
        );
        assert_eq!(fs.handle_status(&entry).unwrap().times, None);
        fs.set_times_at(ROOT, "/dir/link", true, &explicit).unwrap();
        fs.set_times(
            ROOT,
            &entry,
            &update(FileTimeUpdate::Omit, FileTimeUpdate::Set(LATER)),
        )
        .unwrap();
        let expected = Some(FileTimestamps {
            accessed: BEFORE_EPOCH,
            modified: LATER,
            changed: UNSET,
        });
        assert_eq!(fs.handle_status(&entry).unwrap().times, expected);
        fs.set_times_at(
            ROOT,
            "/dir/file",
            true,
            &update(FileTimeUpdate::Omit, FileTimeUpdate::Omit),
        )
        .unwrap();
        assert_eq!(fs.handle_status(&entry).unwrap().times, expected);
        let path_only = fs
            .open(ROOT, "/dir/file", OFlags::PATH, Mode::empty())
            .unwrap();
        fs.set_times(ROOT, &path_only, &explicit).unwrap();
        assert_eq!(
            fs.handle_status(&path_only)
                .unwrap()
                .times
                .unwrap()
                .accessed,
            BEFORE_EPOCH
        );
        fs.set_times_at(ROOT, "/dir", false, &explicit).unwrap();
        assert_eq!(
            fs.file_status(ROOT, "/dir", true)
                .unwrap()
                .times
                .unwrap()
                .accessed,
            BEFORE_EPOCH
        );
    }

    #[test]
    fn set_times_readonly_precedes_ownership_and_both_omit_is_noop() {
        let fs = tar_ro_fs(TEST_TAR_FILE.into());
        let explicit = update(FileTimeUpdate::Set(BEFORE_EPOCH), FileTimeUpdate::Omit);
        for user in [
            ROOT,
            UserInfo {
                user: u16::MAX,
                group: u16::MAX,
            },
        ] {
            assert!(matches!(
                fs.set_times_at(user, "/foo", true, &explicit),
                Err(SetTimesError::ReadOnlyFileSystem)
            ));
        }
        let old = fs.file_status(ROOT, "/foo", true).unwrap().times;
        fs.set_times_at(
            USER,
            "/foo",
            true,
            &update(FileTimeUpdate::Omit, FileTimeUpdate::Omit),
        )
        .unwrap();
        assert_eq!(fs.file_status(ROOT, "/foo", true).unwrap().times, old);
        assert!(old.is_some());
        assert!(fs.file_status(ROOT, "/", true).unwrap().times.is_none());
    }

    #[test]
    fn set_times_rejects_renamed_unlinked_and_replaced_paths() {
        let fs = in_mem_fs();
        let entry = fs
            .open(ROOT, "/file", OFlags::CREAT | OFlags::RDONLY, Mode::RUSR)
            .unwrap();
        let times = update(
            FileTimeUpdate::Set(BEFORE_EPOCH),
            FileTimeUpdate::Set(BEFORE_EPOCH),
        );
        fs.set_times(ROOT, &entry, &times).unwrap();
        fs.rename(ROOT, "/file", "/moved").unwrap();
        assert!(matches!(
            fs.set_times(ROOT, &entry, &times),
            Err(SetTimesError::Io)
        ));
        let replacement = fs
            .open(ROOT, "/file", OFlags::CREAT | OFlags::RDONLY, Mode::RUSR)
            .unwrap();
        assert!(matches!(
            fs.set_times(ROOT, &entry, &times),
            Err(SetTimesError::Io)
        ));
        assert_eq!(fs.handle_status(&replacement).unwrap().times, None);
        fs.unlink(ROOT, "/file").unwrap();
        assert!(matches!(
            fs.set_times(ROOT, &replacement, &times),
            Err(SetTimesError::Io)
        ));
    }

    #[test]
    fn overlay_set_times_on_tar_directory_without_recorded_times() {
        let fs = overlay_fs(
            InMem::<TestPlatform>::new,
            build_tar(
                tar_core::builder::ExtensionMode::Gnu,
                &[ArchiveEntry::file("bar/file", 0o644, b"")],
            ),
        );
        assert_eq!(fs.file_status(ROOT, "/bar", true).unwrap().times, None);
        fs.set_times_at(
            ROOT,
            "/bar",
            true,
            &update(FileTimeUpdate::Omit, FileTimeUpdate::Set(LATER)),
        )
        .unwrap();
        assert_eq!(
            fs.file_status(ROOT, "/bar", true).unwrap().times,
            Some(FileTimestamps {
                accessed: UNSET,
                modified: LATER,
                changed: UNSET,
            })
        );
    }

    #[test]
    fn overlay_set_times_preserves_omitted_lower_values_during_copyup() {
        let allocators = InodeAllocators::new();
        let lower = InMem::<TestPlatform>::new_initialized(
            [(
                "/file",
                InitialNode::File {
                    mode: Mode::RWXU,
                    owner: ROOT,
                    data: Cow::Borrowed(b"lower"),
                },
            )],
            allocators.next(),
        );
        let Resolution::Found(target) = lower
            .resolve(lower.root().unwrap(), &["file"], &|_| Ok(()))
            .unwrap()
        else {
            panic!("missing lower file")
        };
        lower
            .set_times(
                target,
                &update(
                    FileTimeUpdate::Set(BEFORE_EPOCH),
                    FileTimeUpdate::Set(BEFORE_EPOCH),
                ),
            )
            .unwrap();
        let fs = Resolver::<TestPlatform>::new(Overlay::<TestPlatform>::new(
            InMem::<TestPlatform>::new(allocators.next()),
            lower,
            allocators.next(),
        ));
        let entry = fs
            .open(ROOT, "/file", OFlags::RDONLY, Mode::empty())
            .unwrap();
        fs.set_times(
            ROOT,
            &entry,
            &update(FileTimeUpdate::Omit, FileTimeUpdate::Set(LATER)),
        )
        .unwrap();
        let expected = Some(FileTimestamps {
            accessed: BEFORE_EPOCH,
            modified: LATER,
            changed: UNSET,
        });
        assert_eq!(fs.file_status(ROOT, "/file", true).unwrap().times, expected);
        assert_eq!(fs.handle_status(&entry).unwrap().times, expected);
        fs.set_times(
            ROOT,
            &entry,
            &update(FileTimeUpdate::Omit, FileTimeUpdate::Set(BEFORE_EPOCH)),
        )
        .unwrap();
        assert_eq!(
            fs.handle_status(&entry).unwrap().times.unwrap().modified,
            BEFORE_EPOCH
        );
    }
}

mod in_mem {
    use super::{
        FileType, InMem, InodeAllocators, Mode, OFlags, ROOT, Resolver, ResolverEntry, SeekWhence,
        TestPlatform, USER, UserInfo, in_mem_fs,
    };
    use crate::fs::errors::{
        ChownError, MkdirError, OpenError, PathError, ReadDirError, ReadError, RenameError,
        RmdirError, SymlinkError, UnlinkError,
    };
    use alloc::vec;
    use alloc::vec::Vec;

    type InMemFs = Resolver<TestPlatform>;
    type InMemEntry = ResolverEntry;

    /// Create `/tmp` as root, so that the unprivileged user can create entries in it.
    fn world_writable_tmp(fs: &InMemFs) {
        fs.mkdir(ROOT, "/tmp", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to create /tmp");
    }

    /// Make the root directory world-writable, so tests can create entries directly in it.
    fn world_writable_root(fs: &InMemFs) {
        fs.chmod(ROOT, "/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to chmod /");
    }

    #[test]
    fn root_file_creation_and_deletion() {
        let fs = in_mem_fs();

        // Test file creation
        let path = "/testfile";
        let fd = fs
            .open(ROOT, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        drop(fd);

        // Test file deletion
        fs.unlink(ROOT, path).expect("Failed to unlink file");
        assert!(
            fs.open(ROOT, path, OFlags::RDONLY, Mode::RWXU).is_err(),
            "File should not exist"
        );
    }

    #[test]
    fn root_file_read_write() {
        let fs = in_mem_fs();

        // Create and write to a file
        let path = "/testfile";
        let mut fd = fs
            .open(ROOT, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        let data = b"Hello, world!";
        fs.write(&mut fd, data, None)
            .expect("Failed to write to file");
        // Like `pwrite`, writing nothing past the end leaves the size alone.
        assert_eq!(fs.write(&mut fd, b"", Some(20)).unwrap(), 0);
        assert_eq!(fs.handle_status(&fd).unwrap().size, 13);
        drop(fd);

        // Read from the file
        let mut fd = fs
            .open(ROOT, path, OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut buffer = vec![0; data.len()];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(bytes_read, data.len());
        assert_eq!(&buffer, data);
    }

    #[test]
    fn write_only_open_does_not_require_read_permission() {
        let fs = in_mem_fs();
        world_writable_tmp(&fs);

        let path = "/tmp/write_only";
        let mut fd = fs
            .open(USER, path, OFlags::CREAT | OFlags::WRONLY, Mode::WUSR)
            .expect("Failed to create write-only file");
        fs.write(&mut fd, b"x", None).expect("Failed to write file");

        let mut buffer = [0];
        assert!(matches!(
            fs.read(&mut fd, &mut buffer, None),
            Err(ReadError::NotForReading)
        ));
        drop(fd);

        assert!(matches!(
            fs.open(USER, path, OFlags::RDONLY, Mode::empty()),
            Err(OpenError::AccessNotAllowed)
        ));
    }

    #[test]
    fn newly_created_file_does_not_require_its_own_permissions() {
        let fs = in_mem_fs();
        world_writable_tmp(&fs);

        let path = "/tmp/zero_mode";
        let mut fd = fs
            .open(USER, path, OFlags::CREAT | OFlags::WRONLY, Mode::empty())
            .expect("Failed to create zero-mode file");
        fs.write(&mut fd, b"x", None).expect("Failed to write file");
        drop(fd);

        let status = fs
            .file_status(USER, path, true)
            .expect("Failed to stat file");
        assert_eq!(status.mode, Mode::empty());
        assert!(matches!(
            fs.open(USER, path, OFlags::WRONLY, Mode::empty()),
            Err(OpenError::AccessNotAllowed)
        ));
    }

    #[test]
    fn denied_open_does_not_truncate_the_file() {
        let fs = in_mem_fs();
        world_writable_tmp(&fs);
        let path = "/tmp/private";
        let mut fd = fs
            .open(
                USER,
                path,
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        fs.write(&mut fd, b"keep this data", None).unwrap();
        drop(fd);
        fs.chmod(USER, path, Mode::RUSR).unwrap();

        for flags in [
            OFlags::WRONLY | OFlags::TRUNC,
            OFlags::RDONLY | OFlags::TRUNC,
        ] {
            assert!(matches!(
                fs.open(USER, path, flags, Mode::empty()),
                Err(OpenError::AccessNotAllowed)
            ));
            assert_eq!(fs.file_status(USER, path, true).unwrap().size, 14);
        }
        let mut fd = fs.open(USER, path, OFlags::RDONLY, Mode::empty()).unwrap();
        let mut data = [0; 14];
        assert_eq!(fs.read(&mut fd, &mut data, None).unwrap(), data.len());
        assert_eq!(&data, b"keep this data");
    }

    #[test]
    fn root_directory_creation_and_removal() {
        let fs = in_mem_fs();

        // Test directory creation
        let path = "/testdir";
        fs.mkdir(ROOT, path, Mode::RWXU)
            .expect("Failed to create directory");

        // Test directory removal
        fs.rmdir(ROOT, path).expect("Failed to remove directory");
        assert!(
            fs.open(ROOT, path, OFlags::RDONLY, Mode::RWXU).is_err(),
            "Directory should not exist"
        );
    }

    #[test]
    fn file_creation_and_deletion() {
        let fs = in_mem_fs();
        world_writable_tmp(&fs);

        // Test file creation
        let path = "/tmp/testfile";
        let fd = fs
            .open(USER, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        drop(fd);

        // Test file deletion
        fs.unlink(USER, path).expect("Failed to unlink file");
        assert!(
            fs.open(USER, path, OFlags::RDONLY, Mode::RWXU).is_err(),
            "File should not exist"
        );
    }

    #[test]
    fn file_read_write() {
        let fs = in_mem_fs();
        world_writable_tmp(&fs);

        // Create and write to a file
        let path = "/tmp/testfile";
        let mut fd = fs
            .open(USER, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        let data = b"Hello, world!";
        fs.write(&mut fd, data, None)
            .expect("Failed to write to file");
        fs.write(&mut fd, &&data[2..], Some(2))
            .expect("Failed to write to file with offset");
        drop(fd);

        // Read from the file
        let mut fd = fs
            .open(USER, path, OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut buffer = vec![0; data.len()];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        let mut rest = &mut buffer[2..];
        let bytes_read2 = fs
            .read(&mut fd, &mut rest, Some(2))
            .expect("Failed to read from file with offset");
        assert_eq!(bytes_read, data.len());
        assert_eq!(bytes_read2, data.len() - 2);
        assert_eq!(&buffer, data);
    }

    #[test]
    fn directory_creation_and_removal() {
        let fs = in_mem_fs();
        world_writable_tmp(&fs);

        // Test directory creation
        let path = "/tmp/testdir";
        fs.mkdir(USER, path, Mode::RWXU)
            .expect("Failed to create directory");

        // Test directory removal
        fs.rmdir(USER, path).expect("Failed to remove directory");
        assert!(
            fs.open(USER, path, OFlags::RDONLY, Mode::RWXU).is_err(),
            "Directory should not exist"
        );
    }

    #[test]
    fn read_dir_empty() {
        let fs = in_mem_fs();

        let fd = fs
            .open(ROOT, "/", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open root directory");
        let entries = fs
            .read_dir(&fd)
            .expect("Failed to read directory")
            .iter()
            .map(|e| e.name.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            entries,
            vec![".", ".."],
            "Root directory should contain . and .."
        );
    }

    #[test]
    fn read_dir_with_files_and_dirs() {
        let fs = in_mem_fs();

        // Create a directory structure
        fs.mkdir(ROOT, "/testdir", Mode::RWXU)
            .expect("Failed to create directory");
        let fd1 = fs
            .open(
                ROOT,
                "/testfile1",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create file1");
        drop(fd1);
        let fd2 = fs
            .open(
                ROOT,
                "/testfile2",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create file2");
        drop(fd2);

        // Read root directory
        let fd = fs
            .open(ROOT, "/", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open root directory");
        let entries = fs.read_dir(&fd).expect("Failed to read directory");
        drop(fd);

        // Should have 5 entries: ., .., testdir, testfile1, testfile2
        assert_eq!(entries.len(), 5);

        let mut names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec![".", "..", "testdir", "testfile1", "testfile2"]);

        // Check file types
        for entry in &entries {
            match entry.name.as_str() {
                "testdir" | "." | ".." => {
                    assert_eq!(entry.file_type, FileType::Directory);
                }
                "testfile1" | "testfile2" => {
                    assert_eq!(entry.file_type, FileType::RegularFile);
                }
                _ => panic!("Unexpected entry: {}", entry.name),
            }
            if entry.name != "." && entry.name != ".." {
                assert!(entry.ino_info.is_some(), "Inode info should be present");
            } else {
                // TODO(jayb): Re-enable this assertion once the resolver fills in
                // inode information for the synthesized `.` and `..` entries.
            }
        }

        // Read the subdirectory (should be empty)
        let fd = fs
            .open(ROOT, "/testdir", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open subdirectory");
        let entries = fs
            .read_dir(&fd)
            .expect("Failed to read subdirectory")
            .iter()
            .map(|e| e.name.clone())
            .collect::<Vec<_>>();
        assert!(entries.len() == 2, "Subdirectory should contain . and ..");
    }

    #[test]
    fn read_dir_file_not_directory() {
        let fs = in_mem_fs();

        // Create a file
        let fd = fs
            .open(
                ROOT,
                "/testfile",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create file");
        drop(fd);

        // Try to read_dir on the file (should fail)
        let fd = fs
            .open(ROOT, "/testfile", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file");
        assert!(matches!(fs.read_dir(&fd), Err(ReadDirError::NotADirectory)));
    }

    #[test]
    fn parent_dir_write_permissions_are_enforced() {
        let fs = in_mem_fs();

        // A root-owned 0755 directory, holding a file and a directory to try to remove.
        fs.mkdir(
            ROOT,
            "/rootdir",
            Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
        )
        .expect("Failed to create directory");
        let fd = fs
            .open(
                ROOT,
                "/rootdir/file",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create file");
        drop(fd);
        fs.mkdir(ROOT, "/rootdir/sub", Mode::RWXU)
            .expect("Failed to create subdirectory");
        fs.mkdir(ROOT, "/rootdir/sub/inner", Mode::RWXU)
            .expect("Failed to create unsearchable entry");
        fs.symlink(ROOT, "missing", "/rootdir/dangling")
            .expect("Failed to create dangling symlink");

        // A world-writable directory, for the positive case.
        fs.mkdir(ROOT, "/opendir", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to create directory");

        assert!(matches!(
            fs.open(
                USER,
                "/rootdir/new",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU
            ),
            Err(OpenError::NoWritePerms)
        ));
        assert!(matches!(
            fs.mkdir(USER, "/rootdir/newdir", Mode::RWXU),
            Err(MkdirError::NoWritePerms)
        ));
        assert!(matches!(
            fs.symlink(USER, "target", "/rootdir/newlink"),
            Err(SymlinkError::NoWritePerms)
        ));
        for path in ["/rootdir/sub", "/rootdir/file", "/rootdir/dangling"] {
            assert!(matches!(
                fs.mkdir(USER, path, Mode::RWXU),
                Err(MkdirError::AlreadyExists)
            ));
            assert!(matches!(
                fs.symlink(USER, "target", path),
                Err(SymlinkError::AlreadyExists)
            ));
        }
        assert!(matches!(
            fs.mkdir(USER, "/rootdir/sub/inner", Mode::RWXU),
            Err(MkdirError::PathError(PathError::NoSearchPerms))
        ));
        assert!(matches!(
            fs.symlink(USER, "target", "/rootdir/sub/inner"),
            Err(SymlinkError::PathError(PathError::NoSearchPerms))
        ));
        assert!(matches!(
            fs.unlink(USER, "/rootdir/file"),
            Err(UnlinkError::NoWritePerms)
        ));
        assert!(matches!(
            fs.rmdir(USER, "/rootdir/sub"),
            Err(RmdirError::NoWritePerms)
        ));
        assert!(matches!(
            fs.unlink(USER, "/rootdir/sub"),
            Err(UnlinkError::NoWritePerms)
        ));
        assert!(matches!(
            fs.rmdir(USER, "/rootdir/file"),
            Err(RmdirError::NoWritePerms)
        ));
        assert!(matches!(
            fs.unlink(USER, "/rootdir/missing"),
            Err(UnlinkError::PathError(PathError::NoSuchFileOrDirectory))
        ));
        assert!(matches!(
            fs.rmdir(USER, "/rootdir/missing"),
            Err(RmdirError::PathError(PathError::NoSuchFileOrDirectory))
        ));
        for (old, new) in [
            ("/rootdir/missing", "/opendir/x"),
            ("/opendir/missing", "/rootdir/x"),
        ] {
            assert!(matches!(
                fs.rename(USER, old, new),
                Err(RenameError::PathError(PathError::NoSuchFileOrDirectory))
            ));
        }
        assert!(matches!(
            fs.rename(USER, "/rootdir/file", "/opendir/x"),
            Err(RenameError::NoWritePerms)
        ));
        let fd = fs
            .open(
                USER,
                "/opendir/file",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create file");
        drop(fd);
        assert!(matches!(
            fs.rename(USER, "/opendir/file", "/rootdir/x"),
            Err(RenameError::NoWritePerms)
        ));
        assert!(matches!(
            fs.rename(USER, "/rootdir/file/", "/opendir/x"),
            Err(RenameError::PathError(PathError::ComponentNotADirectory))
        ));

        // The same operations succeed in a directory the user may write.
        let fd = fs
            .open(
                USER,
                "/opendir/new",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create file");
        drop(fd);
        fs.mkdir(USER, "/opendir/newdir", Mode::RWXU)
            .expect("Failed to create directory");
        fs.symlink(USER, "target", "/opendir/newlink")
            .expect("Failed to create symlink");
        fs.unlink(USER, "/opendir/new")
            .expect("Failed to unlink file");
        fs.rmdir(USER, "/opendir/newdir")
            .expect("Failed to remove directory");
    }

    #[test]
    fn chown_test() {
        let fs = in_mem_fs();

        // Create a test file as root
        let path = "/testfile";
        let fd = fs
            .open(ROOT, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        drop(fd);

        // First chown to 1000:1000 as root (should succeed)
        fs.chown(ROOT, path, Some(1000), Some(1000))
            .expect("Failed to chown as root");

        // The owner may chown (should succeed)
        fs.chown(USER, path, Some(123), Some(456))
            .expect("Failed to chown as owner");

        // A different user may not chown (should fail)
        let other = UserInfo {
            user: 500,
            group: 500,
        };
        match fs.chown(other, path, Some(789), Some(101)) {
            Err(ChownError::NotTheOwner) => {
                // Expected behavior
            }
            Ok(()) => panic!("Non-owner should not be able to chown"),
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        // Test chown on non-existent file (should fail)
        match fs.chown(USER, "/nonexistent", Some(123), Some(456)) {
            Err(ChownError::PathError(PathError::NoSuchFileOrDirectory)) => {
                // Expected behavior
            }
            Ok(()) => panic!("Should not be able to chown non-existent file"),
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        // Test partial chown (change only user, leave group unchanged)
        fs.chown(ROOT, path, Some(999), None)
            .expect("Failed to chown user only");

        // Test partial chown (change only group, leave user unchanged)
        fs.chown(ROOT, path, None, Some(888))
            .expect("Failed to chown group only");
    }

    #[test]
    fn o_directory_flag_tests() {
        let fs = in_mem_fs();
        world_writable_root(&fs);

        // Create test directory and file
        fs.mkdir(USER, "/testdir", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to create directory");

        let fd = fs
            .open(
                USER,
                "/testfile",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create file");
        drop(fd);

        // Test O_DIRECTORY on a directory (should succeed)
        let fd = fs
            .open(
                USER,
                "/testdir",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .expect("Failed to open directory with O_DIRECTORY");
        drop(fd);

        // Test O_DIRECTORY on a regular file (should fail)
        assert!(matches!(
            fs.open(
                USER,
                "/testfile",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(OpenError::PathError(PathError::ComponentNotADirectory))
        ));

        // Test O_DIRECTORY on non-existent path (should fail)
        assert!(matches!(
            fs.open(
                USER,
                "/nonexistent",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
        ));

        // Test O_DIRECTORY with O_CREAT on non-existent path
        // According to the implementation, O_DIRECTORY should be ignored when O_CREAT is specified
        let fd = fs
            .open(
                USER,
                "/newfile",
                OFlags::CREAT | OFlags::WRONLY | OFlags::DIRECTORY,
                Mode::RWXU,
            )
            .expect("Failed to create file with O_CREAT | O_DIRECTORY");
        drop(fd);

        // Verify it created a regular file, not a directory
        let stat = fs
            .file_status(USER, "/newfile", true)
            .expect("Failed to get file status");
        assert_eq!(stat.file_type, FileType::RegularFile);

        // TODO(jayb): Restore coverage of `O_RDWR | O_DIRECTORY` once `OpenError` can report
        // `EISDIR`; see the matching TODO in `InMem::open_dir`. The legacy in-memory file
        // system used to accept such an open, which Linux rejects.
    }

    #[test]
    fn o_excl_flag_tests() {
        let fs = in_mem_fs();
        world_writable_root(&fs);

        // Test O_CREAT | O_EXCL on non-existent file (should succeed)
        let mut fd = fs
            .open(
                USER,
                "/newfile",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create new file with O_CREAT | O_EXCL");

        // Write some data to verify file was created
        fs.write(&mut fd, b"test data", None)
            .expect("Failed to write to new file");
        drop(fd);

        // Test O_CREAT | O_EXCL on existing file (should fail)
        assert!(matches!(
            fs.open(
                USER,
                "/newfile",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            ),
            Err(OpenError::AlreadyExists)
        ));

        // Test O_CREAT | O_EXCL | O_TRUNC on existing file (should fail)
        assert!(matches!(
            fs.open(
                USER,
                "/newfile",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY | OFlags::TRUNC,
                Mode::RWXU,
            ),
            Err(OpenError::AlreadyExists)
        ));

        // Test O_EXCL without O_CREAT (should be ignored and succeed)
        let mut fd = fs
            .open(
                USER,
                "/newfile",
                OFlags::EXCL | OFlags::RDONLY,
                Mode::empty(),
            )
            .expect("Failed to open existing file with O_EXCL (without O_CREAT)");

        // Verify we can read the data
        let mut buffer = vec![0; 9];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test data");
        drop(fd);

        // Test O_CREAT without O_EXCL on existing file (should succeed)
        let fd = fs
            .open(USER, "/newfile", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to open existing file with O_CREAT (without O_EXCL)");
        drop(fd);

        // Test O_CREAT | O_EXCL on directory (should fail)
        fs.mkdir(USER, "/testdir", Mode::RWXU)
            .expect("Failed to create directory");
        assert!(matches!(
            fs.open(
                USER,
                "/testdir",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            ),
            Err(OpenError::AlreadyExists)
        ));
    }

    #[test]
    fn open_with_trunc() {
        let fs = in_mem_fs();
        world_writable_root(&fs);

        // Create a file and write some initial content
        let path = "/testfile";
        let mut fd = fs
            .open(USER, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        let initial_data = b"Hello, world! This is initial content.";
        fs.write(&mut fd, initial_data, None)
            .expect("Failed to write initial content");
        drop(fd);

        // Verify initial content was written
        let mut fd = fs
            .open(USER, path, OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file for reading");
        let mut buffer = vec![0; initial_data.len()];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read initial content");
        assert_eq!(bytes_read, initial_data.len());
        assert_eq!(&buffer, initial_data);
        drop(fd);

        // Test O_TRUNC with O_WRONLY - should truncate file
        let mut fd = fs
            .open(USER, path, OFlags::WRONLY | OFlags::TRUNC, Mode::empty())
            .expect("Failed to open file with O_TRUNC | O_WRONLY");

        // Write new content to the truncated file
        let new_data = b"New content";
        fs.write(&mut fd, new_data, None)
            .expect("Failed to write new content");
        drop(fd);

        // Verify the file was truncated and contains only new content
        let mut fd = fs
            .open(USER, path, OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file for verification");
        let mut buffer = vec![0; initial_data.len()];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read after truncation");
        assert_eq!(bytes_read, new_data.len());
        assert_eq!(&buffer[..bytes_read], new_data);
        drop(fd);

        // Test O_TRUNC with O_RDWR - should also truncate
        let mut fd = fs
            .open(USER, path, OFlags::WRONLY, Mode::empty())
            .expect("Failed to open file for writing");
        fs.write(&mut fd, b"More content to truncate", None)
            .expect("Failed to write more content");
        drop(fd);

        let mut fd = fs
            .open(USER, path, OFlags::RDWR | OFlags::TRUNC, Mode::empty())
            .expect("Failed to open file with O_TRUNC | O_RDWR");

        // File should be empty after truncation
        let mut buffer = vec![0; 100];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from truncated file");
        assert_eq!(bytes_read, 0);

        // Write and read back to verify it works
        let test_data = b"After RDWR truncation";
        fs.write(&mut fd, test_data, None)
            .expect("Failed to write after RDWR truncation");

        fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
            .expect("Failed to seek to beginning");
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read after write");
        assert_eq!(bytes_read, test_data.len());
        assert_eq!(&buffer[..bytes_read], test_data);
    }

    #[test]
    fn write_position_after_seek() {
        let fs = in_mem_fs();
        // Allow regular user to create in root for this focused test
        world_writable_root(&fs);

        let mut fd = fs
            .open(
                USER,
                "/posfile",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RWXU | Mode::RWXG | Mode::RWXO,
            )
            .expect("open failed");

        // 1. First positional write; position should advance by 6.
        fs.write(&mut fd, b"abcdef", None)
            .expect("first write failed");

        // 2. Rewind to beginning.
        fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
            .expect("seek failed");

        // 3. Another positional write should write from start
        fs.write(&mut fd, b"X", None).expect("overwrite failed");

        // The file offset should now be at 1.
        assert_eq!(
            fs.seek(&mut fd, 0, SeekWhence::RelativeToCurrentOffset)
                .expect("seek failed"),
            1
        );

        // Read back whole file to verify content and length.
        fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
            .expect("seek failed");
        let mut buf = [0u8; 16];
        let n = fs.read(&mut fd, &mut buf, None).expect("read failed");
        assert_eq!(n, 6, "file length should be 6 after writes");
        assert_eq!(&buf[..n], b"Xbcdef", "file content mismatch");

        // Extra: another append to verify continued correct advancement.
        fs.write(&mut fd, b"12", None)
            .expect("second append failed");
        fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
            .expect("seek 2 failed");
        let mut buf2 = [0u8; 16];
        let n2 = fs.read(&mut fd, &mut buf2, None).expect("read 2 failed");
        assert_eq!(n2, 8);
        assert_eq!(&buf2[..n2], b"Xbcdef12");
    }

    /// Create `path` holding `data`, as the unprivileged user.
    fn create_with_content(fs: &InMemFs, path: &str, data: &[u8]) {
        let mut fd = fs
            .open(USER, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        fs.write(&mut fd, &data, None)
            .expect("Failed to write initial content");
    }

    /// Read the whole of `fd` from its current position.
    fn read_all(fs: &InMemFs, fd: &mut InMemEntry) -> Vec<u8> {
        let mut buffer = vec![0; 64];
        let bytes_read = fs
            .read(fd, &mut buffer, None)
            .expect("Failed to read from file");
        buffer.truncate(bytes_read);
        buffer
    }

    #[test]
    fn o_append_flag_basic() {
        let fs = in_mem_fs();
        world_writable_root(&fs);

        // Create a file and write some initial content
        let path = "/testfile";
        create_with_content(&fs, path, b"Hello");

        // Re-open with O_APPEND and write more data
        let mut fd = fs
            .open(USER, path, OFlags::WRONLY | OFlags::APPEND, Mode::empty())
            .expect("Failed to open file with O_APPEND");
        fs.write(&mut fd, b" World", None)
            .expect("Failed to append data");
        drop(fd);

        // Verify the file contains both pieces of data concatenated
        let mut fd = fs
            .open(USER, path, OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file for reading");
        assert_eq!(read_all(&fs, &mut fd), b"Hello World");
    }

    #[test]
    fn o_append_flag_seek_ignored_for_write() {
        let fs = in_mem_fs();
        world_writable_root(&fs);

        // Create a file and write some initial content
        let path = "/testfile";
        create_with_content(&fs, path, b"ABCDEF");

        // Re-open with O_APPEND
        let mut fd = fs
            .open(USER, path, OFlags::WRONLY | OFlags::APPEND, Mode::empty())
            .expect("Failed to open file with O_APPEND");

        // Seek to beginning - this should succeed but writes should still append
        fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
            .expect("Failed to seek to beginning");

        // Write some data - it should go to the end despite the seek
        fs.write(&mut fd, b"123", None)
            .expect("Failed to write after seek");
        drop(fd);

        // Verify the file content: original data followed by appended data
        let mut fd = fs
            .open(USER, path, OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file for reading");
        assert_eq!(read_all(&fs, &mut fd), b"ABCDEF123");
    }

    #[test]
    fn o_append_flag_with_rdwr() {
        let fs = in_mem_fs();
        world_writable_root(&fs);

        // Create a file with initial content
        let path = "/testfile";
        create_with_content(&fs, path, b"Hello");

        // Re-open with O_RDWR | O_APPEND
        let mut fd = fs
            .open(USER, path, OFlags::RDWR | OFlags::APPEND, Mode::empty())
            .expect("Failed to open file with O_RDWR | O_APPEND");

        // Read should work normally from the beginning
        assert_eq!(read_all(&fs, &mut fd), b"Hello");

        // Seek to beginning - write should still append despite position being at 0
        fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
            .expect("Seek failed");

        // Write should append to end, ignoring the current position
        fs.write(&mut fd, b" World", None)
            .expect("Failed to write with append");

        // Seek to beginning and read the whole file
        fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
            .expect("Seek failed");
        assert_eq!(read_all(&fs, &mut fd), b"Hello World");
    }

    #[test]
    fn o_append_pwrite_ignores_append_mode() {
        let fs = in_mem_fs();
        world_writable_root(&fs);

        // Create a file with initial content
        let path = "/testfile";
        create_with_content(&fs, path, b"ABCDEF");

        // Re-open with O_APPEND
        let mut fd = fs
            .open(USER, path, OFlags::WRONLY | OFlags::APPEND, Mode::empty())
            .expect("Failed to open file with O_APPEND");

        // pwrite (write with explicit offset) should ignore O_APPEND per POSIX
        fs.write(&mut fd, b"XX", Some(2)).expect("Failed to pwrite");
        drop(fd);

        // Verify the file content: XX should be at position 2, not appended
        let mut fd = fs
            .open(USER, path, OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file for reading");
        assert_eq!(read_all(&fs, &mut fd), b"ABXXEF");
    }

    #[test]
    fn o_append_with_trunc() {
        let fs = in_mem_fs();
        world_writable_root(&fs);

        // Create a file with initial content
        let path = "/testfile";
        create_with_content(&fs, path, b"Original content");

        // Re-open with O_TRUNC | O_APPEND
        let mut fd = fs
            .open(
                USER,
                path,
                OFlags::WRONLY | OFlags::TRUNC | OFlags::APPEND,
                Mode::empty(),
            )
            .expect("Failed to open file with O_TRUNC | O_APPEND");

        // File should be truncated, then write should append (to empty file)
        fs.write(&mut fd, b"New", None)
            .expect("Failed to write after truncation");
        fs.write(&mut fd, b"Content", None)
            .expect("Failed to write second chunk");
        drop(fd);

        // Verify the file content
        let mut fd = fs
            .open(USER, path, OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file for reading");
        assert_eq!(read_all(&fs, &mut fd), b"NewContent");
    }

    #[test]
    fn open_returns_symlink_resolved_path() {
        use crate::fs::in_mem::InitialNode;
        use alloc::string::String;

        const ALL_PERMS: Mode = Mode::RWXU.union(Mode::RWXG).union(Mode::RWXO);
        let directory = || InitialNode::Directory {
            mode: ALL_PERMS,
            owner: ROOT,
        };
        let symlink = |target: &str| InitialNode::Symlink {
            mode: ALL_PERMS,
            owner: ROOT,
            target: target.into(),
        };
        let fs: InMemFs = Resolver::new(InMem::<TestPlatform>::new_initialized(
            [
                ("/", directory()),
                ("/dir", directory()),
                (
                    "/dir/file",
                    InitialNode::File {
                        mode: ALL_PERMS,
                        owner: ROOT,
                        data: (&[][..]).into(),
                    },
                ),
                ("/dir/file-link", symlink("file")),
                ("/dir-link", symlink("/dir")),
                ("/dangling", symlink("dir/created")),
                (
                    "/blocked",
                    InitialNode::Directory {
                        mode: Mode::empty(),
                        owner: ROOT,
                    },
                ),
                ("/dotlink", symlink("blocked/../dir/file")),
                ("/dir/a", directory()),
                ("/dir/a/b", directory()),
                ("/dir/a/b/c", directory()),
                ("/deep-link", symlink("dir/a/b/c")),
            ],
            InodeAllocators::new().next(),
        ));
        let path = |path: &str, flags: OFlags| -> String {
            let entry = fs
                .open(USER, path, flags, Mode::RWXU)
                .unwrap_or_else(|error| panic!("open {path:?} failed: {error:?}"));
            String::from(entry.path())
        };

        assert_eq!(path("/", OFlags::RDONLY), "/");
        assert_eq!(path("/dir-link", OFlags::RDONLY), "/dir");
        assert_eq!(path("/dir-link/file-link", OFlags::RDONLY), "/dir/file");
        assert_eq!(path("/dir/../dir-link/./file", OFlags::RDONLY), "/dir/file");
        assert_eq!(
            path("/deep-link/../../../file", OFlags::RDONLY),
            "/dir/file"
        );
        for path in ["/dotlink", "/blocked/../dir/file", "/blocked/./../dir/file"] {
            assert!(matches!(
                fs.open(USER, path, OFlags::PATH, Mode::empty()),
                Err(OpenError::PathError(PathError::NoSearchPerms))
            ));
        }
        assert_eq!(
            path("/dir-link/file-link", OFlags::PATH | OFlags::NOFOLLOW),
            "/dir/file-link"
        );
        assert_eq!(
            path("/dangling", OFlags::CREAT | OFlags::WRONLY),
            "/dir/created"
        );
    }
}

mod tar_ro {
    use super::{
        ArchiveEntry, FileType, InodeAllocators, Mode, OFlags, ROOT, Resolver, TEST_TAR_FILE,
        TarRo, TestPlatform, USER, build_tar, read_path, tar_ro_fs,
    };
    use crate::fs::FileStatus;
    use crate::fs::errors::{
        FileStatusError, MkdirError, OpenError, PathError, ReadDirError, RenameError, RmdirError,
        SymlinkError, UnlinkError, WalkError,
    };
    use alloc::vec;
    use alloc::vec::Vec;
    use tar_core::builder::ExtensionMode;

    #[test]
    fn file_read() {
        let fs = tar_ro_fs(TEST_TAR_FILE.into());
        let mut fd = fs
            .open(USER, "foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"testfoo\n");
        drop(fd);

        let mut fd = fs
            .open(USER, "bar/baz", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test bar baz\n");
    }

    #[test]
    fn dir_and_nonexist_checks() {
        let fs = tar_ro_fs(TEST_TAR_FILE.into());
        assert!(matches!(
            fs.open(USER, "bar/ba", OFlags::RDONLY, Mode::empty()),
            Err(OpenError::PathError(PathError::NoSuchFileOrDirectory)),
        ));
        fs.open(USER, "bar", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open dir");
    }

    #[test]
    fn o_directory_flag_tests() {
        let fs = tar_ro_fs(TEST_TAR_FILE.into());

        // Test O_DIRECTORY on a directory (should succeed)
        fs.open(
            USER,
            "bar",
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .expect("Failed to open directory with O_DIRECTORY");

        // Test O_DIRECTORY on a regular file (should fail)
        assert!(matches!(
            fs.open(
                USER,
                "foo",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(OpenError::PathError(PathError::ComponentNotADirectory))
        ));

        // Test O_DIRECTORY on non-existent path (should fail)
        assert!(matches!(
            fs.open(
                USER,
                "nonexistent",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
        ));

        // Test O_DIRECTORY on nested file (should fail)
        assert!(matches!(
            fs.open(
                USER,
                "bar/baz",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(OpenError::PathError(PathError::ComponentNotADirectory))
        ));
    }

    #[test]
    fn read_only_errors_precede_file_permission_denials() {
        use crate::fs::UserInfo;
        use crate::fs::backend::Backend;
        use crate::fs::composer::Composer;
        use crate::fs::inode_allocator::InodeAllocators;
        use crate::fs::resolver::Resolver;
        use crate::fs::tar_ro::TarRo;
        use crate::test_platform::TestPlatform;

        fn check(backend: impl Backend, path: &str, user: UserInfo) {
            let fs = Resolver::<TestPlatform>::new(backend);
            for flags in [OFlags::WRONLY, OFlags::RDWR, OFlags::RDONLY | OFlags::TRUNC] {
                assert!(matches!(
                    fs.open(user, path, flags, Mode::empty()),
                    Err(OpenError::ReadOnlyFileSystem)
                ));
            }
            assert!(matches!(
                fs.open(
                    user,
                    path,
                    OFlags::WRONLY | OFlags::DIRECTORY,
                    Mode::empty()
                ),
                Err(OpenError::PathError(PathError::ComponentNotADirectory))
            ));
            assert!(matches!(
                fs.open(
                    user,
                    path,
                    OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                    Mode::empty()
                ),
                Err(OpenError::AlreadyExists)
            ));
            drop(fs.open(user, path, OFlags::RDONLY, Mode::empty()).unwrap());
            drop(
                fs.open(
                    user,
                    path,
                    OFlags::PATH | OFlags::WRONLY | OFlags::TRUNC,
                    Mode::empty(),
                )
                .unwrap(),
            );
            assert_eq!(fs.file_status(user, path, true).unwrap().size, 8);
        }
        let user = UserInfo {
            user: 4242,
            group: 4242,
        };
        let tar = |allocator| TarRo::new(TEST_TAR_FILE.into(), allocator);
        check(tar(InodeAllocators::new().next()), "/foo", user);
        check(
            Composer::builder().mount("/tar", tar).build().unwrap(),
            "/tar/foo",
            user,
        );
    }

    #[test]
    fn write_or_truncate_open_of_directory_fails() {
        let fs = tar_ro_fs(TEST_TAR_FILE.into());

        for flags in [OFlags::WRONLY, OFlags::RDWR, OFlags::TRUNC] {
            assert!(matches!(
                fs.open(USER, "bar", flags, Mode::empty()),
                Err(OpenError::ReadOnlyFileSystem)
            ));
        }
    }

    #[test]
    fn read_dir_subdirectory() {
        let fs = tar_ro_fs(TEST_TAR_FILE.into());

        // Read root directory
        let fd = fs
            .open(USER, "/", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open root directory");
        let entries = fs.read_dir(&fd).expect("Failed to read root directory");
        drop(fd);

        // Should have 4 entries: ., .., bar, foo
        assert_eq!(entries.len(), 4);

        let mut names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec![".", "..", "bar", "foo"]);

        // Check file types
        for entry in &entries {
            match entry.name.as_str() {
                "foo" => {
                    assert_eq!(entry.file_type, FileType::RegularFile);
                }
                "bar" | "." | ".." => assert_eq!(entry.file_type, FileType::Directory),
                _ => panic!("Unexpected entry: {}", entry.name),
            }
            if entry.name != "." && entry.name != ".." {
                assert!(entry.ino_info.is_some(), "Inode info should be present");
            } else {
                // TODO(jayb): Re-enable this assertion once Composer handles `.` and `..` inode
                // information better.
            }
        }

        // Read `bar` directory
        let fd = fs
            .open(USER, "bar", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open bar directory");
        let entries = fs.read_dir(&fd).expect("Failed to read bar directory");

        // Should have 3 entries: ., .., baz (file)
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].name, "baz");
        assert_eq!(entries[2].file_type, FileType::RegularFile);
    }

    #[test]
    fn read_dir_file_not_directory() {
        let fs = tar_ro_fs(TEST_TAR_FILE.into());

        let fd = fs
            .open(USER, "foo", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open foo file");
        assert!(matches!(fs.read_dir(&fd), Err(ReadDirError::NotADirectory)));
    }

    #[test]
    fn symlinks_are_followed_by_the_resolver() {
        let fs = tar_ro_fs(build_tar(
            ExtensionMode::Gnu,
            &[
                ArchiveEntry::file("usr/bin/busybox", 0o755, b"busybox"),
                ArchiveEntry::file("usr/lib/libc.so", 0o644, b"libc"),
                ArchiveEntry::symlink("lib", "usr/lib"),
                ArchiveEntry::dir("bin", 0o755, u64::from(USER.user)),
                ArchiveEntry::symlink("bin/sh", "/usr/bin/busybox"),
                ArchiveEntry::symlink("bin/ash", "sh"),
                ArchiveEntry::symlink("bin/up", "../lib/../../../usr/lib/libc.so"),
                ArchiveEntry::symlink("dangling", "/nowhere"),
                ArchiveEntry::symlink("loop1", "loop2"),
                ArchiveEntry::symlink("loop2", "/loop1"),
            ],
        ));

        assert_eq!(
            read_path(&fs, "/bin/ash"),
            ("/usr/bin/busybox".into(), b"busybox".to_vec())
        );
        assert_eq!(
            read_path(&fs, "/lib/libc.so"),
            ("/usr/lib/libc.so".into(), b"libc".to_vec())
        );
        assert_eq!(
            read_path(&fs, "/bin/up"),
            ("/usr/lib/libc.so".into(), b"libc".to_vec())
        );
        assert_eq!(fs.read_link(USER, "/bin/sh").unwrap(), "/usr/bin/busybox");
        assert_eq!(fs.read_link(USER, "/lib").unwrap(), "usr/lib");
        assert_eq!(fs.read_link(USER, "/lib/../../bin/ash").unwrap(), "sh");
        for path in ["/usr/bin/busybox", "/usr", "/lib/"] {
            assert!(matches!(
                fs.read_link(USER, path),
                Err(WalkError::PathError(PathError::InvalidPathname))
            ));
        }

        let link = fs.file_status(USER, "/bin/sh", false).unwrap();
        assert_eq!(link.file_type, FileType::SymbolicLink);
        assert_eq!(link.size, "/usr/bin/busybox".len() as u64);
        assert_eq!(link.mode, Mode::from_bits(0o777).unwrap());
        let target = fs.file_status(USER, "/bin/sh", true).unwrap();
        assert_eq!(target.file_type, FileType::RegularFile);
        assert_eq!(target.mode, Mode::from_bits(0o755).unwrap());
        assert_eq!(
            fs.file_status(USER, "/lib", true).unwrap().file_type,
            FileType::Directory
        );

        let fd = fs
            .open(
                USER,
                "/bin/sh",
                OFlags::PATH | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .unwrap();
        assert_eq!(fd.path(), "/bin/sh");
        assert_eq!(fs.handle_status(&fd).unwrap(), link);
        drop(fd);
        assert!(matches!(
            fs.open(
                USER,
                "/bin/sh",
                OFlags::RDONLY | OFlags::NOFOLLOW,
                Mode::empty()
            ),
            Err(OpenError::PathError(PathError::TooManySymlinks))
        ));
        assert!(matches!(
            fs.open(USER, "/dangling", OFlags::RDONLY, Mode::empty()),
            Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
        ));
        assert!(matches!(
            fs.open(
                USER,
                "/dangling",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU
            ),
            Err(OpenError::ReadOnlyFileSystem)
        ));
        assert!(matches!(
            fs.open(USER, "/loop1", OFlags::RDONLY, Mode::empty()),
            Err(OpenError::PathError(PathError::TooManySymlinks))
        ));

        let fd = fs.open(USER, "/", OFlags::RDONLY, Mode::empty()).unwrap();
        let entries = fs.read_dir(&fd).unwrap();
        let lib = entries.iter().find(|entry| entry.name == "lib").unwrap();
        assert_eq!(lib.file_type, FileType::SymbolicLink);
    }

    #[test]
    fn hard_links_resolve_to_their_target() {
        let fs = tar_ro_fs(build_tar(
            ExtensionMode::Gnu,
            &[
                ArchiveEntry::file("a/data", 0o640, b"shared"),
                ArchiveEntry::hard_link("b/alias", "./a/data"),
                ArchiveEntry::symlink("link", "a/data"),
                ArchiveEntry::hard_link("link-alias", "link"),
                ArchiveEntry::hard_link("missing", "nowhere"),
                ArchiveEntry::hard_link("dir-alias", "a"),
                ArchiveEntry::file("after", 0o644, b"after"),
            ],
        ));
        for (path, alias) in [("/a/data", "/b/alias"), ("/link", "/link-alias")] {
            let status = fs.file_status(USER, path, false).unwrap();
            let alias = fs.file_status(USER, alias, false).unwrap();
            assert_eq!(
                FileStatus {
                    node_info: status.node_info,
                    ..alias
                },
                status
            );
        }
        assert_eq!(
            fs.file_status(USER, "/b/alias", false).unwrap().mode,
            Mode::from_bits(0o640).unwrap()
        );
        assert_eq!(read_path(&fs, "/b/alias").1, b"shared");
        assert_eq!(fs.read_link(USER, "/link-alias").unwrap(), "a/data");
        assert_eq!(read_path(&fs, "/link-alias").1, b"shared");

        for path in ["/missing", "/dir-alias"] {
            assert!(matches!(
                fs.file_status(USER, path, false),
                Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory))
            ));
        }
        assert_eq!(read_path(&fs, "/after").1, b"after");
    }

    #[test]
    fn directory_entries_set_mode_and_owner() {
        let root = u64::from(ROOT.user);
        let fs = tar_ro_fs(build_tar(
            ExtensionMode::Gnu,
            &[
                ArchiveEntry::dir("./", 0o755, root),
                ArchiveEntry::file("./after/file", 0o644, b""),
                ArchiveEntry::dir("./after/", 0o750, root),
                ArchiveEntry::dir("/before", 0o700, 1234),
                ArchiveEntry::file("/before/file", 0o644, b""),
                ArchiveEntry::dir("overflow", 0o555, 70000),
                ArchiveEntry::file("implicit/file", 0o644, b""),
            ],
        ));
        let status = |path| {
            let status = fs.file_status(ROOT, path, true).unwrap();
            assert_eq!(status.file_type, FileType::Directory);
            (status.mode.bits(), status.owner.user, status.owner.group)
        };
        assert_eq!(status("/"), (0o755, 0, 0));
        assert_eq!(status("/after"), (0o750, 0, 0));
        assert_eq!(status("/before"), (0o700, 1234, 1234));
        assert_eq!(status("/overflow"), (0o555, 65534, 65534));
        assert_eq!(status("/implicit"), (0o777, USER.user, USER.group));

        assert!(matches!(
            fs.open(USER, "/after/file", OFlags::RDONLY, Mode::empty()),
            Err(OpenError::PathError(PathError::NoSearchPerms))
        ));
    }

    #[test]
    fn long_paths_and_link_targets_round_trip() {
        let directory = "d".repeat(150);
        let long_path = alloc::format!("{directory}/{}", "f".repeat(150));
        let long_target = alloc::format!("/{long_path}");
        let allocators = InodeAllocators::new();
        for extension_mode in [ExtensionMode::Gnu, ExtensionMode::Pax] {
            let fs = Resolver::<TestPlatform>::new(TarRo::new(
                build_tar(
                    extension_mode,
                    &[
                        ArchiveEntry::file(&long_path, 0o644, b"long"),
                        ArchiveEntry::symlink("link", &long_target),
                        ArchiveEntry::hard_link(&alloc::format!("{directory}/alias"), &long_path),
                        ArchiveEntry::file("after", 0o644, b"after"),
                    ],
                ),
                allocators.next(),
            ));
            assert_eq!(read_path(&fs, &long_path).1, b"long");
            assert_eq!(fs.read_link(USER, "/link").unwrap(), long_target);
            assert_eq!(
                read_path(&fs, "/link"),
                (long_target.clone(), b"long".to_vec())
            );
            assert_eq!(
                read_path(&fs, &alloc::format!("/{directory}/alias")).1,
                b"long"
            );
            assert_eq!(read_path(&fs, "/after").1, b"after");
        }
    }

    #[test]
    fn read_only_errors_precede_directory_write_denials() {
        let root = u64::from(ROOT.user);
        let fs = tar_ro_fs(build_tar(
            ExtensionMode::Gnu,
            &[
                ArchiveEntry::dir("ro", 0o755, root),
                ArchiveEntry::file("ro/file", 0o644, b""),
                ArchiveEntry::dir("ro/sub", 0o755, root),
                ArchiveEntry::dir("open", 0o777, root),
                ArchiveEntry::file("open/file", 0o644, b""),
                ArchiveEntry::dir("open/sub", 0o755, root),
            ],
        ));
        // The errors must not depend on whether the acting user could write the directory.
        for dir in ["/ro", "/open"] {
            let path = |name| alloc::format!("{dir}/{name}");
            assert!(matches!(
                fs.open(
                    USER,
                    &path("new"),
                    OFlags::CREAT | OFlags::WRONLY,
                    Mode::RWXU
                ),
                Err(OpenError::ReadOnlyFileSystem)
            ));
            assert!(matches!(
                fs.mkdir(USER, &path("new"), Mode::RWXU),
                Err(MkdirError::ReadOnlyFileSystem)
            ));
            assert!(matches!(
                fs.symlink(USER, "target", &path("new")),
                Err(SymlinkError::ReadOnlyFileSystem)
            ));
            // Creations report an existing name first.
            assert!(matches!(
                fs.mkdir(USER, &path("file"), Mode::RWXU),
                Err(MkdirError::AlreadyExists)
            ));
            assert!(matches!(
                fs.symlink(USER, "target", &path("sub")),
                Err(SymlinkError::AlreadyExists)
            ));
            // Removals and renames report the read-only filesystem before looking up the name.
            for name in ["file", "sub", "sub/", "missing"] {
                assert!(matches!(
                    fs.unlink(USER, &path(name)),
                    Err(UnlinkError::ReadOnlyFileSystem)
                ));
            }
            for name in ["file", "sub", "missing"] {
                assert!(matches!(
                    fs.rmdir(USER, &path(name)),
                    Err(RmdirError::ReadOnlyFileSystem)
                ));
                assert!(matches!(
                    fs.rename(USER, &path(name), &path("new")),
                    Err(RenameError::ReadOnlyFileSystem)
                ));
            }
        }
    }

    #[test]
    fn read_only_renames_across_mounts_are_cross_device() {
        use super::InMem;
        use crate::fs::composer::Composer;
        use crate::fs::read_only::ReadOnly;

        let fs = Resolver::<TestPlatform>::new(
            Composer::builder()
                .mount("/", |allocator| {
                    let archive = build_tar(
                        ExtensionMode::Gnu,
                        &[
                            ArchiveEntry::dir("ro", 0o755, u64::from(ROOT.user)),
                            ArchiveEntry::file("ro/file", 0o644, b"data"),
                        ],
                    );
                    TarRo::new(archive, allocator)
                })
                .mount("/tmp", InMem::<TestPlatform>::new)
                .mount("/mnt", |allocator| {
                    ReadOnly::new(InMem::<TestPlatform>::new(allocator))
                })
                .build()
                .unwrap(),
        );
        fs.chmod(ROOT, "/tmp", Mode::from_bits(0o777).unwrap())
            .unwrap();
        fs.mkdir(ROOT, "/tmp/dir", Mode::RWXU).unwrap();
        for user in [ROOT, USER] {
            for (old, new) in [
                ("/ro/file", "/tmp/new"),
                ("/tmp/dir", "/ro/new"),
                ("/ro/missing", "/tmp/new"),
                ("/tmp/missing", "/new"),
                ("/ro/file", "/mnt/new"),
            ] {
                assert!(
                    matches!(fs.rename(user, old, new), Err(RenameError::CrossDevice)),
                    "{old} -> {new} as {}",
                    user.user
                );
            }
            for (old, new) in [
                ("/ro/file", "/new"),
                ("/ro/missing", "/new"),
                ("/mnt/missing", "/mnt/new"),
            ] {
                assert!(
                    matches!(
                        fs.rename(user, old, new),
                        Err(RenameError::ReadOnlyFileSystem)
                    ),
                    "{old} -> {new} as {}",
                    user.user
                );
            }
        }
        assert_eq!(fs.file_status(ROOT, "/ro/file", true).unwrap().size, 4);
        assert!(fs.file_status(ROOT, "/tmp/dir", true).is_ok());
        for path in ["/new", "/ro/new", "/tmp/new", "/mnt/new"] {
            assert!(
                matches!(
                    fs.file_status(ROOT, path, true),
                    Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory))
                ),
                "{path}"
            );
        }
    }

    #[test]
    fn metadata_and_special_entries_do_not_stop_indexing() {
        use tar_core::builder::{EntryBuilder, HeaderBuilder};
        use tar_core::{EntryType, SparseEntry};

        let mut sparse = EntryBuilder::with_mode(HeaderBuilder::new_gnu(), ExtensionMode::Gnu);
        sparse
            .path("sparse")
            .mode(0o644)
            .unwrap()
            .size(512)
            .unwrap()
            .sparse(
                &[SparseEntry {
                    offset: 4096,
                    length: 512,
                }],
                8192,
            );
        let mut archive = sparse.finish_bytes();
        archive.extend_from_slice(&[1; 512]);
        archive.extend_from_slice(&build_tar(
            ExtensionMode::Gnu,
            &[
                ArchiveEntry {
                    entry_type: EntryType::XGlobalHeader,
                    ..ArchiveEntry::file("pax_global_header", 0o644, b"17 comment=hello\n")
                },
                ArchiveEntry {
                    entry_type: EntryType::Fifo,
                    ..ArchiveEntry::file("fifo", 0o644, b"")
                },
                ArchiveEntry::file("after", 0o644, b"after"),
            ],
        ));
        let fs = tar_ro_fs(archive.into());
        assert!(matches!(
            fs.file_status(USER, "/pax_global_header", false),
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory))
        ));
        assert_eq!(read_path(&fs, "/after").1, b"after");
    }

    #[test]
    #[should_panic(expected = "tar entry \"file\" is too large")]
    fn pax_size_overflowing_padding_panics() {
        use tar_core::builder::{EntryBuilder, HeaderBuilder};

        let mut entry = EntryBuilder::with_mode(HeaderBuilder::new_ustar(), ExtensionMode::Pax);
        entry
            .path("file")
            .mode(0o644)
            .unwrap()
            .size(u64::MAX)
            .unwrap();
        let mut archive = entry.finish_bytes();
        archive.resize(archive.len() + 1024, 0);
        drop(tar_ro_fs(archive.into()));
    }

    /// An archive of the file `file`, holding `data`, with the extra PAX records `records`.
    fn pax_archive(records: &[(&str, &str)]) -> alloc::borrow::Cow<'static, [u8]> {
        use tar_core::builder::{EntryBuilder, HeaderBuilder};

        let mut entry = EntryBuilder::with_mode(HeaderBuilder::new_ustar(), ExtensionMode::Pax);
        entry.path("file").mode(0o644).unwrap().size(4).unwrap();
        for (key, value) in records {
            entry.add_pax(key, value);
        }
        let mut archive = entry.finish_bytes();
        archive.extend_from_slice(b"data");
        archive.resize(archive.len().next_multiple_of(512) + 1024, 0);
        archive.into()
    }

    #[test]
    fn pre_epoch_pax_timestamps_are_accepted() {
        // Python's `tarfile`, for one, writes these for files from before 1970.
        let fs = tar_ro_fs(pax_archive(&[("mtime", "-1.5")]));
        assert_eq!(read_path(&fs, "/file").1, b"data");
    }

    #[test]
    #[should_panic(expected = "invalid PAX size value")]
    fn pre_epoch_pax_timestamps_keep_other_pax_values_strict() {
        drop(tar_ro_fs(pax_archive(&[
            ("mtime", "-1"),
            ("size", "4 bytes"),
        ])));
    }
}

mod overlay {
    use super::{
        FileType, InodeAllocator, Mode, OFlags, Overlay, Resolver, SeekWhence, TEST_TAR_FILE,
        TestPlatform, USER, UserInfo,
    };
    use crate::fs::errors::{FileStatusError, OpenError, PathError, RmdirError};
    use crate::fs::in_mem::{InMem, InitialNode};
    use alloc::vec;
    use alloc::vec::Vec;
    extern crate std;

    /// The user these tests act as, and so the owner of anything they are set up as having created.
    const ACTING_USER: UserInfo = USER;
    const ALL_PERMS: Mode = Mode::RWXU.union(Mode::RWXG).union(Mode::RWXO);

    /// An upper backend whose root is writable by the acting user, holding `entries`.
    ///
    /// The overlay directs every mutation to the upper backend, so its root has to allow writes for
    /// anything to be created.
    fn upper(
        entries: impl IntoIterator<Item = (&'static str, InitialNode)>,
    ) -> impl FnOnce(InodeAllocator) -> InMem<TestPlatform> {
        |allocator| {
            InMem::new_initialized(
                [(
                    "/",
                    InitialNode::Directory {
                        mode: ALL_PERMS,
                        owner: UserInfo::ROOT,
                    },
                )]
                .into_iter()
                .chain(entries),
                allocator,
            )
        }
    }

    fn overlay_fs(
        upper: impl FnOnce(InodeAllocator) -> InMem<TestPlatform>,
    ) -> Resolver<TestPlatform> {
        super::overlay_fs(upper, TEST_TAR_FILE.into())
    }

    #[test]
    fn file_read_from_lower() {
        let fs = overlay_fs(upper([]));
        let mut fd = fs
            .open(USER, "foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"testfoo\n");
        let stat = fs.handle_status(&fd).expect("Failed to handle stat");
        assert_eq!(stat.file_type, FileType::RegularFile);
        assert_eq!(stat.mode, Mode::from_bits(0o644).unwrap());
        drop(fd);

        let stat = fs
            .file_status(USER, "bar", true)
            .expect("Failed to file stat");
        assert_eq!(stat.file_type, FileType::Directory);
        assert_eq!(stat.mode, Mode::from_bits(0o755).unwrap());

        let mut fd = fs
            .open(USER, "bar/baz", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test bar baz\n");
        let stat = fs.handle_status(&fd).expect("Failed to handle stat");
        assert_eq!(stat.file_type, FileType::RegularFile);
        assert_eq!(stat.mode, Mode::from_bits(0o644).unwrap());
    }

    #[test]
    fn dir_and_nonexist_checks() {
        let fs = overlay_fs(upper([]));
        assert!(matches!(
            fs.open(USER, "bar/ba", OFlags::RDONLY, Mode::empty()),
            Err(OpenError::PathError(PathError::NoSuchFileOrDirectory)),
        ));
        fs.open(USER, "bar", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open dir");
    }

    /// A lower directory kept as an anchor, as a working directory is, sees the entries made in it
    /// after it is copied up.
    #[test]
    fn anchored_directory_sees_entries_after_copy_up() {
        use crate::fs::backend::{Resolution, ResolvedTarget};
        use crate::fs::mount::Location;
        use crate::fs::resolver::resolve_from;
        use alloc::sync::Arc;

        let fs = overlay_fs(upper([]));
        let root = fs.namespace().root();
        let bar = resolve_from(USER, &root, &root, "/bar", true, |location, resolution| {
            let Resolution::Found(ResolvedTarget::Dir(dir)) = resolution else {
                panic!("/bar is not a directory");
            };
            let dir = location
                .mount
                .backend()
                .open_dir(dir, OFlags::PATH)
                .unwrap();
            Location::anchored(Arc::clone(&location.mount), location.path.clone(), dir)
        })
        .unwrap();

        drop(
            fs.open(USER, "/bar/new", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .unwrap(),
        );
        for name in ["new", "baz"] {
            assert!(
                resolve_from(USER, &root, &bar, name, true, |_, resolution| {
                    matches!(resolution, Resolution::Found(ResolvedTarget::File(_)))
                })
                .unwrap(),
                "{name}"
            );
        }
    }

    /// Check that for the same file, even though it started as a lower file, writing to it copies
    /// it up and redirects handles already open on it, so every descriptor sees the update.
    #[test]
    fn file_read_write_copy_up() {
        let fs = overlay_fs(upper([]));
        let mut fd1 = fs
            .open(USER, "foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut fd2 = fs
            .open(USER, "foo", OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to open file");

        let mut buffer = vec![0; 1024];

        let bytes_read = fs
            .read(&mut fd1, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"testfoo\n");

        fs.write(&mut fd2, b"share", None)
            .expect("Failed to write to file");

        fs.seek(&mut fd1, 0, SeekWhence::RelativeToBeginning)
            .expect("Failed to seek to start");
        let bytes_read = fs
            .read(&mut fd1, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"shareoo\n");
    }

    /// Similar to [`file_read_write_copy_up`] but also confirm that file positions have been
    /// maintained.
    #[test]
    fn file_read_write_copy_up_keeps_position() {
        let fs = overlay_fs(upper([]));
        let mut fd1 = fs
            .open(USER, "foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut fd2 = fs
            .open(USER, "foo", OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to open file");

        let mut buffer = vec![0; 4];

        let bytes_read = fs
            .read(&mut fd1, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test");

        fs.write(&mut fd2, b"share", None)
            .expect("Failed to write to file");

        let bytes_read = fs
            .read(&mut fd1, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"eoo\n");
    }

    #[test]
    fn file_deletion() {
        let fs = overlay_fs(upper([]));
        let mut fd = fs
            .open(USER, "foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");

        let mut buffer = vec![0; 4];

        // The file exists, and is readable
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test");

        // Then we delete it
        fs.unlink(USER, "foo").unwrap();

        // This should not really impact the readability; file is fine.
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"foo\n");

        // But if we close and attempt to re-open, it should not exist
        drop(fd);
        assert!(matches!(
            fs.open(USER, "foo", OFlags::RDONLY, Mode::empty()),
            Err(OpenError::PathError(PathError::NoSuchFileOrDirectory)),
        ));
    }

    #[test]
    fn o_directory_flag_tests() {
        let fs = overlay_fs(upper([
            (
                "/upperdir",
                InitialNode::Directory {
                    mode: ALL_PERMS,
                    owner: ACTING_USER,
                },
            ),
            (
                "/upperfile",
                InitialNode::File {
                    mode: Mode::RWXU,
                    owner: ACTING_USER,
                    data: alloc::borrow::Cow::Borrowed(b""),
                },
            ),
        ]));

        // Test O_DIRECTORY on directory from lower layer (tar)
        fs.open(
            USER,
            "bar",
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .expect("Failed to open lower layer directory with O_DIRECTORY");

        // Test O_DIRECTORY on directory from upper layer (in_mem)
        fs.open(
            USER,
            "/upperdir",
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .expect("Failed to open upper layer directory with O_DIRECTORY");

        // Test O_DIRECTORY on file from lower layer (should fail)
        assert!(matches!(
            fs.open(
                USER,
                "foo",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(OpenError::PathError(PathError::ComponentNotADirectory))
        ));

        // Test O_DIRECTORY on file from upper layer (should fail)
        assert!(matches!(
            fs.open(
                USER,
                "/upperfile",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(OpenError::PathError(PathError::ComponentNotADirectory))
        ));

        // Test O_DIRECTORY on nested file from lower layer (should fail)
        assert!(matches!(
            fs.open(
                USER,
                "bar/baz",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(OpenError::PathError(PathError::ComponentNotADirectory))
        ));

        // Test O_DIRECTORY on non-existent path (should fail)
        assert!(matches!(
            fs.open(
                USER,
                "nonexistent",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
        ));
    }

    #[test]
    // Regression test for #250: a file that already exists in the lower layer should not be
    // shadowed by an attempt to create a file.
    fn file_create_exist_in_lower() {
        let fs = overlay_fs(upper([]));
        let mut fd = fs
            .open(USER, "foo", OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
            .expect("Failed to open file");
        let mut buffer = vec![0; 4];

        // The file exists, and is readable
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test");
    }

    #[test]
    fn read_dir_from_lower_layer() {
        let fs = overlay_fs(upper([]));

        // Read bar subdirectory
        let fd = fs
            .open(USER, "bar", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open bar directory");
        let entries = fs.read_dir(&fd).expect("Failed to read bar directory");

        // Should have 3 entries: ., .., baz (file)
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].name, "baz");
        assert_eq!(entries[2].file_type, FileType::RegularFile);
        assert!(
            entries[2].ino_info.is_some(),
            "Inode info should be present"
        );
    }

    #[test]
    fn read_dir_from_upper_layer() {
        let fs = overlay_fs(upper([
            (
                "/upperdir",
                InitialNode::Directory {
                    mode: ALL_PERMS,
                    owner: ACTING_USER,
                },
            ),
            (
                "/upperfile",
                InitialNode::File {
                    mode: Mode::RWXU,
                    owner: ACTING_USER,
                    data: alloc::borrow::Cow::Borrowed(b""),
                },
            ),
        ]));

        // Read root directory (should contain entries from both layers)
        let fd = fs
            .open(USER, "/", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open root directory");
        let entries = fs.read_dir(&fd).expect("Failed to read root directory");
        drop(fd);

        // Should have 6 entries: ., .., bar, foo (from lower), upperdir, upperfile (from upper)
        assert_eq!(entries.len(), 6);

        let mut names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![".", "..", "bar", "foo", "upperdir", "upperfile"]
        );

        // Check file types
        for entry in &entries {
            match entry.name.as_str() {
                "foo" | "upperfile" => {
                    assert_eq!(entry.file_type, FileType::RegularFile);
                }
                "bar" | "upperdir" | "." | ".." => {
                    assert_eq!(entry.file_type, FileType::Directory);
                }
                _ => panic!("Unexpected entry: {}", entry.name),
            }
            if entry.name != "." && entry.name != ".." {
                assert!(entry.ino_info.is_some(), "Inode info should be present");
            } else {
                // TODO(jayb): Re-enable this assertion once the resolver fills in
                // inode information for the synthesized `.` and `..` entries.
            }
        }

        // Read upperdir directory (should be from upper layer)
        let fd = fs
            .open(USER, "/upperdir", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open upperdir");
        let entries = fs.read_dir(&fd).expect("Failed to read upperdir");

        // only . and ..
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn o_excl_tests() {
        let fs = overlay_fs(upper([]));

        // Test O_CREAT | O_EXCL on file that exists in lower layer (should fail)
        // "foo" exists in the tar file
        assert!(matches!(
            fs.open(
                USER,
                "foo",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            ),
            Err(OpenError::AlreadyExists)
        ));

        // Test O_CREAT | O_EXCL on file that doesn't exist anywhere (should succeed)
        let mut fd = fs
            .open(
                USER,
                "/newfile",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create new file with O_CREAT | O_EXCL");

        fs.write(&mut fd, b"overlay test", None)
            .expect("Failed to write to new file");
        drop(fd);

        // Test O_CREAT | O_EXCL on file that now exists in upper layer (should fail)
        assert!(matches!(
            fs.open(
                USER,
                "/newfile",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            ),
            Err(OpenError::AlreadyExists)
        ));

        // Test O_CREAT | O_EXCL on directory that exists in lower layer (should fail)
        // "bar" is a directory in the tar file
        assert!(matches!(
            fs.open(
                USER,
                "bar",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            ),
            Err(OpenError::AlreadyExists)
        ));

        // Test O_CREAT | O_EXCL on file that was deleted (tombstoned) should succeed
        // First delete a file from lower layer
        fs.unlink(USER, "foo")
            .expect("Failed to unlink lower layer file");

        // Now try to create it with O_EXCL (should succeed since it's tombstoned)
        let mut fd = fs
            .open(
                USER,
                "foo",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create file over tombstone with O_CREAT | O_EXCL");

        fs.write(&mut fd, b"new foo content", None)
            .expect("Failed to write to recreated file");
        drop(fd);

        // Verify the new content
        let mut fd = fs
            .open(USER, "foo", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open recreated file");
        let mut buffer = vec![0; 15];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from recreated file");
        assert_eq!(&buffer[..bytes_read], b"new foo content");
        drop(fd);

        // Test O_CREAT | O_EXCL behavior with existing upper layer file
        // Create a file in upper layer first
        let mut fd = fs
            .open(
                USER,
                "/upper_only_file",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create upper layer file");
        fs.write(&mut fd, b"upper content", None)
            .expect("Failed to write to upper layer file");
        drop(fd);

        // Now try O_CREAT | O_EXCL on the same file (should fail)
        assert!(matches!(
            fs.open(
                USER,
                "/upper_only_file",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            ),
            Err(OpenError::AlreadyExists)
        ));
    }

    #[test]
    fn dir_creation_inside_lower_existing_dir() {
        let fs = overlay_fs(upper([]));

        // Create the directory /bar/test (where /bar already exists inside the tar file)
        fs.mkdir(USER, "/bar/test", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to create /bar/test directory");

        // Verify the directory was created
        let stat = fs
            .file_status(USER, "/bar/test", true)
            .expect("Failed to get status of /bar/test");
        assert_eq!(stat.file_type, FileType::Directory);

        // Verify we can open the directory
        let fd = fs
            .open(USER, "/bar/test", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open /bar/test directory");
        let entries = fs
            .read_dir(&fd)
            .expect("Failed to read /bar/test directory");

        // Should contain only . and .. entries
        assert_eq!(entries.len(), 2);
        let mut names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec![".", ".."]);
    }

    #[test]
    fn file_creation_materializes_ancestor_dirs() {
        let fs = overlay_fs(upper([]));

        // Open bar/test for writing (where bar exists in lower layer but test doesn't exist)
        // This should create ancestor directories and allow file creation
        let mut fd = fs
            .open(USER, "bar/test", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to open bar/test for writing");

        // Write data to the file
        let data = b"Hello from nested file!";
        fs.write(&mut fd, data, None)
            .expect("Failed to write to bar/test");
        drop(fd);

        // Read the file back
        let mut fd = fs
            .open(USER, "bar/test", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open bar/test for reading");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from bar/test");
        assert_eq!(&buffer[..bytes_read], data);
        drop(fd);

        // Verify the file exists and has correct type
        let stat = fs
            .file_status(USER, "bar/test", true)
            .expect("Failed to get status of bar/test");
        assert_eq!(stat.file_type, FileType::RegularFile);
    }

    #[test]
    fn file_modification_materializes_ancestor_dirs() {
        let fs = overlay_fs(upper([]));

        // Open bar/baz for writing (both bar and baz exist in lower layer)
        // This copies up the ancestor directories and allows the file to be modified
        let mut fd = fs
            .open(USER, "bar/baz", OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to open bar/baz for writing");

        // Write new data to the file (overwriting existing content)
        let data = b"Modified content!";
        fs.write(&mut fd, data, None)
            .expect("Failed to write to bar/baz");
        drop(fd);

        // Read the file back to verify it was modified
        let mut fd = fs
            .open(USER, "bar/baz", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open bar/baz for reading");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read from bar/baz");

        assert_eq!(&buffer[..bytes_read], data);
        drop(fd);

        // Verify the file still exists and has correct type
        let stat = fs
            .file_status(USER, "bar/baz", true)
            .expect("Failed to get status of bar/baz");
        assert_eq!(stat.file_type, FileType::RegularFile);
    }

    #[test]
    fn open_with_trunc() {
        let fs = overlay_fs(upper([]));

        // Open with O_TRUNC should copy the file up into the upper backend, empty
        let mut fd = fs
            .open(USER, "foo", OFlags::RDWR | OFlags::TRUNC, Mode::empty())
            .expect("Failed to open file with O_TRUNC");

        // File should be truncated (empty)
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read file");
        assert_eq!(bytes_read, 0);

        // Write new content
        fs.write(&mut fd, b"new content", None)
            .expect("Failed to write to file");
        drop(fd);

        // Verify the content persists
        let mut fd = fs
            .open(USER, "foo", OFlags::RDONLY, Mode::empty())
            .expect("Failed to reopen file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read file");
        assert_eq!(&buffer[..bytes_read], b"new content");
    }

    #[test]
    fn rmdir_upper_only_directory() {
        let fs = overlay_fs(upper([]));

        // Create an empty directory only in upper layer
        fs.mkdir(USER, "/upper_empty", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("mkdir upper_empty failed");

        // Remove it
        fs.rmdir(USER, "/upper_empty")
            .expect("rmdir upper_empty should succeed");

        // Verify it no longer exists
        assert!(matches!(
            fs.file_status(USER, "/upper_empty", true),
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory))
        ));

        // Second removal should yield NoSuchFileOrDirectory (path error)
        assert!(matches!(
            fs.rmdir(USER, "/upper_empty"),
            Err(RmdirError::PathError(PathError::NoSuchFileOrDirectory))
        ));
    }

    #[test]
    fn rmdir_upper_directory_not_empty_then_empty() {
        let fs = overlay_fs(upper([]));

        fs.mkdir(USER, "/upper_dir", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("mkdir upper_dir failed");

        // Create a file inside making directory non-empty
        let fd = fs
            .open(
                USER,
                "/upper_dir/file",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU | Mode::RWXG,
            )
            .expect("create file in upper_dir failed");
        drop(fd);

        // Attempt to remove while non-empty
        assert!(matches!(
            fs.rmdir(USER, "/upper_dir"),
            Err(RmdirError::NotEmpty)
        ));

        // Remove inner file
        fs.unlink(USER, "/upper_dir/file")
            .expect("unlink inner failed");

        // Now should succeed
        fs.rmdir(USER, "/upper_dir")
            .expect("rmdir upper_dir should succeed");

        // Confirm gone
        assert!(matches!(
            fs.file_status(USER, "/upper_dir", true),
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory))
        ));
    }

    #[test]
    fn rmdir_lower_directory_non_empty() {
        let fs = overlay_fs(upper([]));

        // "bar" exists in lower layer and contains "baz" (non-empty)
        assert!(matches!(fs.rmdir(USER, "bar"), Err(RmdirError::NotEmpty)));
    }

    #[test]
    fn rmdir_not_a_directory() {
        let fs = overlay_fs(upper([]));

        // Create a regular file (upper only)
        let fd = fs
            .open(
                USER,
                "/regular_file",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU | Mode::RWXG,
            )
            .expect("create file failed");
        drop(fd);

        // rmdir should fail with NotADirectory
        assert!(matches!(
            fs.rmdir(USER, "/regular_file"),
            Err(RmdirError::NotADirectory)
        ));
    }

    #[test]
    fn nested_overlay_resolution_and_mutation_do_not_deadlock() {
        use crate::fs::composer::Composer;
        use crate::fs::inode_allocator::InodeAllocators;
        use crate::fs::tar_ro::{EMPTY_TAR_FILE, TarRo};
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let allocators = InodeAllocators::new();
            let lower = Overlay::<TestPlatform>::new(
                upper([])(allocators.next()),
                TarRo::new(TEST_TAR_FILE.into(), allocators.next()),
                allocators.next(),
            );
            let nested_upper = Overlay::<TestPlatform>::new(
                InMem::<TestPlatform>::new_initialized(
                    [
                        (
                            "/",
                            InitialNode::Directory {
                                mode: ALL_PERMS,
                                owner: UserInfo::ROOT,
                            },
                        ),
                        (
                            "/link",
                            InitialNode::Symlink {
                                mode: ALL_PERMS,
                                owner: USER,
                                target: "/bar/baz".into(),
                            },
                        ),
                    ],
                    allocators.next(),
                ),
                TarRo::new(EMPTY_TAR_FILE.into(), allocators.next()),
                allocators.next(),
            );
            let fs = Resolver::<TestPlatform>::new(
                Composer::builder()
                    .mount("/", |allocator| {
                        Overlay::<TestPlatform>::new(nested_upper, lower, allocator)
                    })
                    .build()
                    .unwrap(),
            );
            assert_eq!(fs.file_status(USER, "/bar/baz", true).unwrap().size, 13);
            assert_eq!(
                fs.file_status(USER, "/bar", true).unwrap().file_type,
                FileType::Directory
            );
            drop(
                fs.open(USER, "/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
                    .unwrap(),
            );
            assert_eq!(fs.read_link(USER, "/link").unwrap(), "/bar/baz");
            drop(
                fs.open(USER, "/link", OFlags::RDONLY, Mode::empty())
                    .unwrap(),
            );
            fs.chmod(USER, "/bar/baz", Mode::RUSR | Mode::WUSR).unwrap();
            drop(
                fs.open(
                    USER,
                    "/bar/baz",
                    OFlags::WRONLY | OFlags::TRUNC,
                    Mode::empty(),
                )
                .unwrap(),
            );
            drop(
                fs.open(
                    USER,
                    "/bar/new",
                    OFlags::CREAT | OFlags::WRONLY,
                    Mode::RUSR | Mode::WUSR,
                )
                .unwrap(),
            );
            fs.unlink(USER, "/bar/new").unwrap();
            fs.mkdir(USER, "/bar/sub", ALL_PERMS).unwrap();
            fs.rmdir(USER, "/bar/sub").unwrap();
            tx.send(()).unwrap();
        });
        rx.recv_timeout(Duration::from_secs(5))
            .expect("nested overlay operation failed or deadlocked");
    }

    #[test]
    fn lower_symlinks_read_unlink_and_write_through() {
        use super::{ArchiveEntry, build_tar, read_path};

        let fs = super::overlay_fs(
            upper([]),
            build_tar(
                tar_core::builder::ExtensionMode::Gnu,
                &[
                    ArchiveEntry::file("etc/real", 0o644, b"lower"),
                    ArchiveEntry::symlink("etc/link", "real"),
                    ArchiveEntry::symlink("etc/gone", "/etc/real"),
                ],
            ),
        );
        assert_eq!(fs.read_link(USER, "/etc/link").unwrap(), "real");

        fs.unlink(USER, "/etc/gone").unwrap();
        assert!(matches!(
            fs.file_status(USER, "/etc/gone", false),
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory))
        ));

        let mut fd = fs
            .open(
                USER,
                "/etc/link",
                OFlags::WRONLY | OFlags::TRUNC,
                Mode::empty(),
            )
            .unwrap();
        fs.write(&mut fd, b"upper", None).unwrap();
        drop(fd);
        assert_eq!(
            fs.file_status(USER, "/etc/link", false).unwrap().file_type,
            FileType::SymbolicLink
        );
        assert_eq!(fs.read_link(USER, "/etc/link").unwrap(), "real");
        assert_eq!(read_path(&fs, "/etc/real").1, b"upper");
    }

    #[test]
    fn lower_hard_link_names_stay_consistent() {
        use super::{ArchiveEntry, build_tar, read_path};

        let fs = super::overlay_fs(
            upper([]),
            build_tar(
                tar_core::builder::ExtensionMode::Gnu,
                &[
                    ArchiveEntry::file("a", 0o666, b"old"),
                    ArchiveEntry::hard_link("b", "a"),
                ],
            ),
        );
        // Copy-up is per name: each name must still report what it holds, and names that share
        // an inode must hold the same.
        let check = || {
            let [a, b] = ["/a", "/b"].map(|path| {
                let status = fs.file_status(USER, path, false).unwrap();
                let (_, data) = read_path(&fs, path);
                assert_eq!(status.size, u64::try_from(data.len()).unwrap(), "{path}");
                (status, data)
            });
            if a.0.node_info == b.0.node_info {
                assert_eq!(a, b);
            }
            a.1
        };

        let mut fd = fs.open(USER, "/a", OFlags::RDWR, Mode::empty()).unwrap();
        fs.write(&mut fd, b"new-long", None).unwrap();
        drop(fd);
        assert_eq!(check(), b"new-long");
        drop(fs.open(USER, "/b", OFlags::WRONLY, Mode::empty()).unwrap());
        assert_eq!(check(), b"new-long");
        fs.chmod(USER, "/a", Mode::RUSR).unwrap();
        check();
    }

    #[test]
    fn copy_up_does_not_deadlock() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let fs = overlay_fs(upper([]));

        fs.file_status(USER, "foo", true)
            .expect("Failed to stat foo");

        // Writing to the lower-layer file triggers copy-up. Run it on a worker thread.
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut fd = fs
                .open(USER, "foo", OFlags::WRONLY, Mode::RWXU)
                .expect("Failed to open file for writing");
            fs.write(&mut fd, b"x", None)
                .expect("Failed to write to file");
            drop(fd);
            let _ = tx.send(());
        });

        rx.recv_timeout(Duration::from_secs(2))
            .expect("copy-up deadlocked");
    }
}

mod devices {
    use super::{FileType, Mode, OFlags, Resolver, TestPlatform, USER};
    use crate::fs::composer::Composer;
    use crate::fs::devices::Devices;
    use crate::fs::errors::{OpenError, PathError};
    use crate::random::TestRandomProvider;
    use crate::stdio::{StdioOutputStream, StdioProvider, StdioStream};
    use crate::test_support::TestStdioProvider;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use litebox_broker_protocol::terminal::{TerminalOperation, TerminalResponse};

    fn devices_fs(provider: Arc<TestStdioProvider>) -> Resolver<TestPlatform> {
        Resolver::new(
            Composer::builder()
                .mount("/dev", |allocator| {
                    Devices::new(allocator, provider, Arc::new(TestRandomProvider))
                })
                .build()
                .unwrap(),
        )
    }

    /// Device I/O and terminal queries reach the providers the backend was built with.
    #[test]
    fn devices_use_their_providers() {
        let provider = Arc::new(TestStdioProvider::default());
        let fs = devices_fs(provider.clone());

        let mut stdout = fs
            .open(USER, "/dev/stdout", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stdout");
        assert!(matches!(fs.write(&mut stdout, b"", None), Ok(0)));
        assert!(matches!(fs.write(&mut stdout, b"out", None), Ok(3)));
        let mut stderr = fs
            .open(USER, "/dev/stderr", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stderr");
        assert!(matches!(fs.write(&mut stderr, b"err", None), Ok(3)));
        assert_eq!(
            provider.writes(),
            vec![
                (StdioOutputStream::Stdout, b"out".to_vec()),
                (StdioOutputStream::Stderr, b"err".to_vec()),
            ]
        );

        provider.push_input(b"in");
        let mut stdin = fs
            .open(USER, "/dev/stdin", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open /dev/stdin");
        let mut buffer = [0; 4];
        assert!(matches!(fs.read(&mut stdin, &mut buffer, None), Ok(2)));
        assert_eq!(&buffer[..2], b"in");

        let mut urandom = fs
            .open(USER, "/dev/urandom", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open /dev/urandom");
        assert!(matches!(fs.read(&mut urandom, &mut buffer, None), Ok(4)));
        assert_eq!(buffer, [0x5a; 4]);

        for file in [&stdin, &stdout, &stderr, &urandom] {
            assert!(fs.terminal(file).is_none());
        }
    }

    /// `/dev/tty`, bound to the provider's terminal as the opener's controlling
    /// terminal, and the standard streams referring to that terminal share its
    /// endpoint's I/O; other streams go to the host streams.
    #[test]
    fn terminal_devices_use_the_terminal_endpoint() {
        let provider = Arc::new(
            TestStdioProvider::default()
                .with_terminal(StdioStream::Stdin)
                .with_terminal(StdioStream::Stdout),
        );
        let fs = devices_fs(provider.clone());

        let mut tty = fs
            .open_with_controlling_terminal(USER, "/dev/tty", OFlags::RDWR, Mode::empty(), &|| {
                provider.terminal()
            })
            .expect("Failed to open /dev/tty");
        let mut stdin = fs
            .open(USER, "/dev/stdin", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open /dev/stdin");
        let mut stdout = fs
            .open(USER, "/dev/stdout", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stdout");
        let mut stderr = fs
            .open(USER, "/dev/stderr", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stderr");
        for file in [&tty, &stdin, &stdout] {
            assert!(fs.terminal(file).is_some());
        }
        assert!(fs.terminal(&stderr).is_none());
        let stdout_path = fs
            .open(USER, "/dev/stdout", OFlags::PATH, Mode::empty())
            .expect("Failed to open /dev/stdout with O_PATH");
        assert!(fs.terminal(&stdout_path).is_none());

        assert!(matches!(fs.write(&mut tty, b"tty", None), Ok(3)));
        assert!(matches!(fs.write(&mut stdout, b"out", None), Ok(3)));
        assert!(matches!(fs.write(&mut stderr, b"err", None), Ok(3)));
        assert_eq!(
            provider.terminal_writes(),
            vec![b"tty".to_vec(), b"out".to_vec()]
        );
        assert_eq!(
            provider.writes(),
            vec![(StdioOutputStream::Stderr, b"err".to_vec())]
        );

        provider.push_terminal_input(b"line");
        let mut buffer = [0; 2];
        assert!(matches!(fs.read(&mut stdin, &mut buffer, None), Ok(2)));
        assert_eq!(&buffer, b"li");
        assert!(matches!(fs.read(&mut tty, &mut buffer, None), Ok(2)));
        assert_eq!(&buffer, b"ne");
    }

    /// `/dev/tty` reaches the opener's controlling terminal when no standard
    /// stream refers to it.
    #[test]
    fn tty_without_terminal_streams() {
        let provider = Arc::new(TestStdioProvider::default().with_controlling_terminal());
        let fs = devices_fs(provider.clone());

        let mut tty = fs
            .open_with_controlling_terminal(
                USER,
                "/dev/tty",
                OFlags::WRONLY,
                Mode::empty(),
                &|| provider.terminal(),
            )
            .expect("Failed to open /dev/tty");
        assert!(fs.terminal(&tty).is_some());
        assert!(matches!(fs.write(&mut tty, b"tty", None), Ok(3)));
        let stdout = fs
            .open(USER, "/dev/stdout", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stdout");
        assert!(fs.terminal(&stdout).is_none());
        assert_eq!(provider.terminal_writes(), vec![b"tty".to_vec()]);
    }

    /// Without a controlling terminal, `/dev/tty` exists but cannot be opened
    /// for I/O, even if the provider has a terminal.
    #[test]
    fn tty_without_terminal() {
        let fs = devices_fs(Arc::new(
            TestStdioProvider::default().with_controlling_terminal(),
        ));

        assert!(matches!(
            fs.open(USER, "/dev/tty", OFlags::RDWR, Mode::empty()),
            Err(OpenError::NoSuchDevice)
        ));
        let tty = fs
            .open(USER, "/dev/tty", OFlags::PATH, Mode::empty())
            .expect("Failed to open /dev/tty with O_PATH");
        assert!(fs.terminal(&tty).is_none());

        let status = fs
            .file_status(USER, "/dev/tty", true)
            .expect("Failed to stat /dev/tty");
        assert_eq!(status.file_type, FileType::CharacterDevice);
        assert_eq!(
            status.node_info.rdev.map(core::num::NonZeroU64::get),
            Some(0x500)
        );

        let dev = fs
            .open(
                USER,
                "/dev",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .expect("Failed to open /dev");
        let entries = fs.read_dir(&dev).expect("Failed to read /dev");
        let names: Vec<_> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert!(names.contains(&"tty"));
    }

    #[test]
    fn non_dev_path_fails() {
        let fs = devices_fs(Arc::new(TestStdioProvider::default()));

        // Attempt to open a non-/dev/* path
        assert!(matches!(
            fs.open(USER, "foo", OFlags::RDONLY, Mode::empty()),
            Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
        ));
    }

    fn names(fs: &Resolver<TestPlatform>, path: &str) -> Vec<String> {
        let dir = fs
            .open(
                USER,
                path,
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .expect("Failed to open directory");
        let entries = fs.read_dir(&dir).expect("Failed to read directory");
        entries.into_iter().map(|entry| entry.name).collect()
    }

    /// Opening `/dev/ptmx` creates a pair whose subsidiary `/dev/pts/<index>`
    /// opens once unlocked, and the two ends exchange bytes.
    #[test]
    fn ptmx_opens_pseudo_terminal_pairs() {
        let fs = devices_fs(Arc::new(TestStdioProvider::default()));
        let mut manager = fs
            .open(USER, "/dev/ptmx", OFlags::RDWR, Mode::empty())
            .expect("Failed to open /dev/ptmx");
        let endpoint = fs.terminal(&manager).expect("ptmx opens a terminal");
        assert_eq!(
            endpoint.control(TerminalOperation::GetSubsidiaryIndex),
            Ok(Ok(TerminalResponse::SubsidiaryIndex(0)))
        );
        assert!(fs.readiness_source(&manager).is_some());
        let status = fs.handle_status(&manager).unwrap();
        assert_eq!(
            status.node_info.rdev.map(core::num::NonZeroU64::get),
            Some(0x502)
        );

        assert!(matches!(
            fs.open(USER, "/dev/pts/0", OFlags::RDWR, Mode::empty()),
            Err(OpenError::Io)
        ));
        assert_eq!(
            endpoint.control(TerminalOperation::SetSubsidiaryLock(false)),
            Ok(Ok(TerminalResponse::Done))
        );
        let mut subsidiary = fs
            .open(USER, "/dev/pts/0", OFlags::RDWR, Mode::empty())
            .expect("Failed to open /dev/pts/0");
        assert!(fs.terminal(&subsidiary).is_some());
        assert!(fs.readiness_source(&subsidiary).is_some());

        let mut buffer = [0; 16];
        assert!(matches!(fs.write(&mut manager, b"in\n", None), Ok(3)));
        assert!(matches!(fs.read(&mut subsidiary, &mut buffer, None), Ok(3)));
        assert_eq!(&buffer[..3], b"in\n");
        // Echo reaches the manager ahead of the subsidiary's output.
        assert!(matches!(fs.write(&mut subsidiary, b"out", None), Ok(3)));
        assert!(matches!(fs.read(&mut manager, &mut buffer, None), Ok(7)));
        assert_eq!(&buffer[..7], b"in\r\nout");
    }

    /// `/dev/pts` lists and names the subsidiaries of open managers, with
    /// Linux's device numbers, without `stat` or `O_PATH` creating pairs.
    #[test]
    fn pts_names_open_pairs() {
        let fs = devices_fs(Arc::new(TestStdioProvider::default()));
        let ptmx_path = fs
            .open(USER, "/dev/ptmx", OFlags::PATH, Mode::empty())
            .expect("Failed to open /dev/ptmx with O_PATH");
        assert!(fs.terminal(&ptmx_path).is_none());
        let ptmx = fs.file_status(USER, "/dev/ptmx", true).unwrap();
        assert_eq!(ptmx.file_type, FileType::CharacterDevice);
        assert_eq!(names(&fs, "/dev/pts"), [".", ".."]);
        let pts = fs.file_status(USER, "/dev/pts", true).unwrap();
        assert_eq!(pts.file_type, FileType::Directory);
        let dev = names(&fs, "/dev");
        assert!(dev.iter().any(|name| name == "ptmx"));
        assert!(dev.iter().any(|name| name == "pts"));

        let first = fs
            .open(USER, "/dev/ptmx", OFlags::RDWR, Mode::empty())
            .unwrap();
        let second = fs
            .open(USER, "/dev/ptmx", OFlags::RDWR, Mode::empty())
            .unwrap();
        assert_eq!(names(&fs, "/dev/pts"), [".", "..", "0", "1"]);
        let status = fs.file_status(USER, "/dev/pts/1", true).unwrap();
        assert_eq!(status.file_type, FileType::CharacterDevice);
        assert_eq!(status.mode, Mode::RUSR | Mode::WUSR | Mode::WGRP);
        assert_eq!(status.node_info.dev, pts.node_info.dev);
        let first_status = fs.file_status(USER, "/dev/pts/0", true).unwrap();
        assert_ne!(status.node_info.ino, first_status.node_info.ino);
        assert_eq!(
            status.node_info.rdev.map(core::num::NonZeroU64::get),
            Some((136 << 8) | 1)
        );
        // A path-only subsidiary describes itself without opening it.
        let path = fs
            .open(USER, "/dev/pts/1", OFlags::PATH, Mode::empty())
            .unwrap();
        assert!(fs.terminal(&path).is_none());
        assert_eq!(fs.handle_status(&path).unwrap().node_info, status.node_info);

        for missing in ["/dev/pts/2", "/dev/pts/01", "/dev/pts/+1", "/dev/pts/x"] {
            assert!(
                matches!(
                    fs.open(USER, missing, OFlags::PATH, Mode::empty()),
                    Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
                ),
                "{missing}"
            );
        }
        for not_directory in ["/dev/pts/0/", "/dev/pts/0/x", "/dev/ptmx/x"] {
            assert!(
                matches!(
                    fs.open(USER, not_directory, OFlags::PATH, Mode::empty()),
                    Err(OpenError::PathError(PathError::ComponentNotADirectory))
                ),
                "{not_directory}"
            );
        }
        assert!(matches!(
            fs.open(USER, "/dev/pts/0", OFlags::DIRECTORY, Mode::empty()),
            Err(OpenError::PathError(PathError::ComponentNotADirectory))
        ));

        // A subsidiary's name goes away with its manager.
        drop(first);
        assert_eq!(names(&fs, "/dev/pts"), [".", "..", "1"]);
        assert!(matches!(
            fs.open(USER, "/dev/pts/0", OFlags::PATH, Mode::empty()),
            Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
        ));
        drop(second);
    }

    /// `/dev/ptmx` fails to open once every index is in use.
    #[test]
    fn ptmx_runs_out_of_space() {
        let fs = devices_fs(Arc::new(TestStdioProvider::default()));
        let mut managers: Vec<_> =
            core::iter::from_fn(|| fs.open(USER, "/dev/ptmx", OFlags::RDWR, Mode::empty()).ok())
                .collect();
        assert_eq!(managers.len(), 64);
        assert!(matches!(
            fs.open(USER, "/dev/ptmx", OFlags::RDWR, Mode::empty()),
            Err(OpenError::NoSpace)
        ));
        managers.pop();
        fs.open(USER, "/dev/ptmx", OFlags::RDWR, Mode::empty())
            .expect("A closed pair frees its index");
    }
}

mod composed {
    use super::{InMem, Mode, OFlags, Resolver, TestPlatform, USER, UserInfo};
    use crate::fs::composer::Composer;
    use crate::fs::devices::Devices;
    use crate::fs::errors::{MkdirError, SymlinkError};
    use crate::fs::in_mem::InitialNode;
    use crate::fs::inode_allocator::InodeAllocators;
    use crate::random::TestRandomProvider;
    use crate::stdio::StdioOutputStream;
    use crate::test_support::TestStdioProvider;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    fn composed_fs(provider: Arc<TestStdioProvider>) -> Resolver<TestPlatform> {
        Resolver::new(
            Composer::builder()
                .mount("/", |allocator| {
                    InMem::<TestPlatform>::new_initialized(
                        [(
                            "/",
                            InitialNode::Directory {
                                mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                                owner: UserInfo::ROOT,
                            },
                        )],
                        allocator,
                    )
                })
                .mount("/dev", |allocator| {
                    Devices::new(allocator, provider, Arc::new(TestRandomProvider))
                })
                .build()
                .unwrap(),
        )
    }

    #[test]
    fn stdio_reaches_mounted_devices() {
        let provider = Arc::new(TestStdioProvider::default());
        let fs = composed_fs(provider.clone());

        let mut fd_stdout = fs
            .open(USER, "/dev/stdout", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stdout");
        assert!(matches!(fs.write(&mut fd_stdout, b"composed", None), Ok(8)));
        assert_eq!(
            provider.writes(),
            vec![(StdioOutputStream::Stdout, b"composed".to_vec())]
        );

        provider.push_input(b"input");
        let mut fd_stdin = fs
            .open(USER, "/dev/stdin", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open /dev/stdin");
        let mut buffer = vec![0; 1024];
        assert!(matches!(fs.read(&mut fd_stdin, &mut buffer, None), Ok(5)));
        assert_eq!(&buffer[..5], b"input");
    }

    #[test]
    fn existing_name_returns_already_exists() {
        let fs = composed_fs(Arc::new(TestStdioProvider::default()));

        for path in ["/dev", "/dev/null"] {
            assert!(matches!(
                fs.mkdir(USER, path, Mode::RWXU),
                Err(MkdirError::AlreadyExists)
            ));
            assert!(matches!(
                fs.symlink(USER, "target", path),
                Err(SymlinkError::AlreadyExists)
            ));
        }
        assert!(matches!(
            fs.mkdir(USER, "/dev/new", Mode::RWXU),
            Err(MkdirError::ReadOnlyFileSystem)
        ));
        assert!(matches!(
            fs.symlink(USER, "target", "/dev/new"),
            Err(SymlinkError::ReadOnlyFileSystem)
        ));
    }

    /// Composers built from shared allocators give each node its own identity,
    /// including their virtual directories and device nodes.
    #[test]
    fn composers_sharing_allocators_never_share_a_node_identity() {
        let allocators = Arc::new(InodeAllocators::new());
        let mut nodes = Vec::new();
        for _ in 0..2 {
            let fs = Resolver::<TestPlatform>::new(
                Composer::builder_with(Arc::clone(&allocators))
                    .mount("/mnt/data", InMem::<TestPlatform>::new)
                    .mount("/dev", |allocator| {
                        Devices::new(
                            allocator,
                            Arc::new(TestStdioProvider::default()),
                            Arc::new(TestRandomProvider),
                        )
                    })
                    .build()
                    .unwrap(),
            );
            for path in [
                "/",
                "/mnt",
                "/mnt/data",
                "/dev",
                "/dev/stdin",
                "/dev/tty",
                "/dev/null",
                "/dev/urandom",
                "/dev/ptmx",
                "/dev/pts",
            ] {
                let node = fs.file_status(USER, path, true).unwrap().node_info;
                nodes.push((node.dev, node.ino));
            }
        }
        let count = nodes.len();
        nodes.sort_unstable();
        nodes.dedup();
        assert_eq!(nodes.len(), count);
    }

    #[test]
    fn write_to_non_dev() {
        let fs = composed_fs(Arc::new(TestStdioProvider::default()));

        // Test file creation
        let path = "/testfile";
        let fd = fs
            .open(USER, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        drop(fd);

        // Test file deletion
        fs.unlink(USER, path).expect("Failed to unlink file");
        assert!(
            fs.open(USER, path, OFlags::RDONLY, Mode::RWXU).is_err(),
            "File should not exist"
        );
    }
}

mod shared_mapping {
    use super::{InMem, InodeAllocators, Mode, OFlags, ROOT, Resolver, TestPlatform, USER};
    use crate::fs::errors::{MapSharedError, OpenError, StorageError, TruncateError, WriteError};
    use crate::fs::in_mem::InitialNode;
    use crate::fs::shared_storage::test_memory::VecMemoryProvider;
    use crate::fs::shared_storage::{
        DEFAULT_MAX_SHARED_FILES, SharedFileLimit, SharedFileMemory, SharedMapping,
    };
    use crate::test_support::FaultingBuffer;
    use alloc::borrow::Cow;
    use alloc::sync::Arc;
    use alloc::vec;

    fn shared_in_mem_with_limit(
        limit: &Arc<SharedFileLimit>,
    ) -> (InMem<TestPlatform>, Arc<VecMemoryProvider>) {
        let provider = Arc::new(VecMemoryProvider::new(false));
        let fs = InMem::<TestPlatform>::new(InodeAllocators::new().next())
            .with_shared_memory(provider.clone(), Arc::clone(limit));
        (fs, provider)
    }

    fn shared_in_mem() -> (InMem<TestPlatform>, Arc<VecMemoryProvider>) {
        shared_in_mem_with_limit(&Arc::new(SharedFileLimit::new(DEFAULT_MAX_SHARED_FILES)))
    }

    #[test]
    fn mapped_file_contents_stay_coherent_with_file_io() {
        let (fs, provider) = shared_in_mem();
        let fs = Resolver::<TestPlatform>::new(fs);
        let mut fd = fs
            .open(ROOT, "/file", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
            .unwrap();
        fs.write(&mut fd, b"hello", None).unwrap();

        let SharedMapping {
            file: mapping,
            writable,
        } = fs.map_shared(&fd).unwrap();
        assert!(writable);
        let memory = provider.last();
        assert_eq!(memory.contents(), b"hello");

        fs.write(&mut fd, b"!!", Some(6)).unwrap();
        assert_eq!(memory.contents(), b"hello\0!!");
        assert_eq!(fs.handle_status(&fd).unwrap().size, 8);

        memory.write_at(0, &b"J".as_slice()).unwrap();
        let mut read = vec![0; 8];
        assert_eq!(fs.read(&mut fd, &mut read, Some(0)).unwrap(), 8);
        assert_eq!(&read, b"Jello\0!!");

        memory.set_len(10).unwrap();
        assert_eq!(fs.handle_status(&fd).unwrap().size, 10);
        fs.truncate(&mut fd, 2, false).unwrap();
        assert_eq!(memory.contents(), b"Je");
        assert_eq!(fs.handle_status(&fd).unwrap().size, 2);

        let mut append = fs
            .open(
                ROOT,
                "/file",
                OFlags::WRONLY | OFlags::APPEND,
                Mode::empty(),
            )
            .unwrap();
        // The memory grows behind the backend's back, and appending still lands at its end.
        memory.set_len(3).unwrap();
        assert_eq!(fs.write(&mut append, b"!!", None).unwrap(), 2);
        assert_eq!(memory.contents(), b"Je\0!!");

        let fd = fs
            .open(ROOT, "/file", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let SharedMapping {
            file: again,
            writable,
        } = fs.map_shared(&fd).unwrap();
        assert!(!writable);
        assert!(Arc::ptr_eq(&again, &mapping));

        let fd = fs
            .open(ROOT, "/file", OFlags::RDWR | OFlags::TRUNC, Mode::empty())
            .unwrap();
        assert_eq!(memory.contents(), b"");
        assert_eq!(fs.handle_status(&fd).unwrap().size, 0);
        assert!(Arc::ptr_eq(&fs.map_shared(&fd).unwrap().file, &mapping));
    }

    #[test]
    fn mapping_requires_a_readable_file() {
        let fs = Resolver::<TestPlatform>::new(shared_in_mem().0);
        drop(
            fs.open(ROOT, "/file", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .unwrap(),
        );
        let write_only = fs
            .open(ROOT, "/file", OFlags::WRONLY, Mode::empty())
            .unwrap();
        assert!(matches!(
            fs.map_shared(&write_only),
            Err(MapSharedError::NotForReading)
        ));
        let dir = fs.open(ROOT, "/", OFlags::RDONLY, Mode::empty()).unwrap();
        assert!(matches!(
            fs.map_shared(&dir),
            Err(MapSharedError::IsDirectory)
        ));
        let path_only = fs.open(ROOT, "/file", OFlags::PATH, Mode::empty()).unwrap();
        assert!(matches!(
            fs.map_shared(&path_only),
            Err(MapSharedError::PathOnly)
        ));
        let path_only_dir = fs.open(ROOT, "/", OFlags::PATH, Mode::empty()).unwrap();
        assert!(matches!(
            fs.map_shared(&path_only_dir),
            Err(MapSharedError::PathOnly)
        ));
    }

    #[test]
    fn files_in_shared_memory_are_limited_until_they_go_away() {
        let limit = Arc::new(SharedFileLimit::new(2));
        let fs = Resolver::<TestPlatform>::new(shared_in_mem_with_limit(&limit).0);
        let open = |path| {
            fs.open(ROOT, path, OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
                .unwrap()
        };
        let (first, second, third) = (open("/first"), open("/second"), open("/third"));
        let mapping = fs.map_shared(&first).unwrap().file;
        fs.map_shared(&second).unwrap();
        assert_eq!(limit.live(), 2);
        assert!(matches!(
            fs.map_shared(&third),
            Err(MapSharedError::NoMemory)
        ));
        fs.map_shared(&first).unwrap();
        assert_eq!(limit.live(), 2);

        fs.unlink(ROOT, "/first").unwrap();
        assert!(matches!(
            fs.map_shared(&third),
            Err(MapSharedError::NoMemory)
        ));
        drop(first);
        assert_eq!(limit.live(), 2);
        drop(mapping);
        assert_eq!(limit.live(), 1);
        fs.map_shared(&third).unwrap();
        assert_eq!(limit.live(), 2);
    }

    #[test]
    fn failed_storage_creation_releases_its_slot_and_preserves_contents() {
        use crate::fs::shared_storage::SharedFileMemoryProvider;

        struct FailingProvider;

        impl SharedFileMemoryProvider for FailingProvider {
            fn create(&self) -> Result<SharedFileMemory, StorageError> {
                Err(StorageError::NoSpace)
            }
        }

        // Memory that cannot be created, and memory too small to take the contents.
        let providers: [Arc<dyn SharedFileMemoryProvider>; 2] = [
            Arc::new(FailingProvider),
            Arc::new(VecMemoryProvider::new(false).with_capacity(4)),
        ];
        let allocators = InodeAllocators::new();
        for provider in providers {
            let limit = Arc::new(SharedFileLimit::new(1));
            let backend = InMem::<TestPlatform>::new(allocators.next())
                .with_shared_memory(provider, Arc::clone(&limit));
            let fs = Resolver::<TestPlatform>::new(backend);
            let mut fd = fs
                .open(ROOT, "/file", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
                .unwrap();
            fs.write(&mut fd, b"hello", None).unwrap();
            for _ in 0..2 {
                assert!(matches!(fs.map_shared(&fd), Err(MapSharedError::NoMemory)));
                assert_eq!(limit.live(), 0);
            }
            let mut read = vec![0; 5];
            assert_eq!(fs.read(&mut fd, &mut read, Some(0)).unwrap(), 5);
            assert_eq!(read, b"hello");
        }
    }

    #[test]
    fn overlay_shares_copied_up_files() {
        let provider = Arc::new(VecMemoryProvider::new(false));
        let upper = |allocator| {
            InMem::<TestPlatform>::new_initialized(
                [(
                    "/",
                    InitialNode::Directory {
                        mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                        owner: ROOT,
                    },
                )],
                allocator,
            )
            .with_shared_memory(
                provider.clone(),
                Arc::new(SharedFileLimit::new(DEFAULT_MAX_SHARED_FILES)),
            )
        };
        let fs = super::overlay_fs(upper, Cow::Borrowed(super::TEST_TAR_FILE));
        let mut lower = fs
            .open(ROOT, "/foo", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let upper = fs.open(USER, "/foo", OFlags::RDWR, Mode::empty()).unwrap();
        let mapping = fs.map_shared(&upper).unwrap().file;
        let bytes = provider.last().contents();
        assert_eq!(bytes.len(), 8);

        // The handle opened before the copy-up follows the upper copy, and so does its mapping.
        let mut read = vec![0; 8];
        assert_eq!(fs.read(&mut lower, &mut read, Some(0)).unwrap(), 8);
        assert_eq!(read, bytes);
        let SharedMapping {
            file: followed,
            writable,
        } = fs.map_shared(&lower).unwrap();
        assert!(!writable);
        assert!(Arc::ptr_eq(&followed, &mapping));

        let mut reopened = fs
            .open(ROOT, "/foo", OFlags::RDONLY, Mode::empty())
            .unwrap();
        assert_eq!(fs.read(&mut reopened, &mut read, Some(0)).unwrap(), 8);
        assert_eq!(read, bytes);
        assert!(Arc::ptr_eq(
            &fs.map_shared(&reopened).unwrap().file,
            &mapping
        ));
    }

    #[test]
    fn composer_shares_files_through_the_mount_holding_them() {
        use crate::fs::composer::Composer;

        let provider = Arc::new(VecMemoryProvider::new(false));
        let fs = Resolver::<TestPlatform>::new(
            Composer::builder()
                .mount("/", InMem::<TestPlatform>::new)
                .mount("/shared", |allocator| {
                    InMem::<TestPlatform>::new(allocator).with_shared_memory(
                        provider.clone(),
                        Arc::new(SharedFileLimit::new(DEFAULT_MAX_SHARED_FILES)),
                    )
                })
                .build()
                .unwrap(),
        );
        // Only the mount at `/shared` can share files, so this maps only if the composer asks
        // the mount holding the file.
        let mut fd = fs
            .open(
                ROOT,
                "/shared/file",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RWXU,
            )
            .unwrap();
        fs.write(&mut fd, b"hello", None).unwrap();
        fs.map_shared(&fd).unwrap();
        assert_eq!(provider.last().contents(), b"hello");
    }

    /// Through the broker's own stack, a composer over an overlay over shared in-memory files,
    /// failed writes and truncations of a mapped file report what the storage did.
    #[test]
    fn deployment_stack_reports_mapped_file_errors() {
        use crate::fs::composer::Composer;
        use crate::fs::overlay::Overlay;
        use crate::fs::tar_ro::TarRo;

        let provider = Arc::new(VecMemoryProvider::new(true).with_capacity(12));
        let fs = Resolver::<TestPlatform>::new(
            Composer::builder()
                .mount_nestable("/", |allocators| {
                    let upper = InMem::<TestPlatform>::new_initialized(
                        [(
                            "/",
                            InitialNode::Directory {
                                mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                                owner: ROOT,
                            },
                        )],
                        allocators.next(),
                    )
                    .with_shared_memory(
                        provider.clone(),
                        Arc::new(SharedFileLimit::new(DEFAULT_MAX_SHARED_FILES)),
                    );
                    Overlay::<TestPlatform>::new(
                        upper,
                        TarRo::new(Cow::Borrowed(super::TEST_TAR_FILE), allocators.next()),
                        allocators.next(),
                    )
                })
                .build()
                .unwrap(),
        );
        let mut fd = fs.open(USER, "/foo", OFlags::RDWR, Mode::empty()).unwrap();
        fs.map_shared(&fd).unwrap();
        let memory = provider.last();
        assert_eq!(memory.contents(), b"testfoo\n");

        // A fault before anything is written fails and keeps the size, and one after the first
        // chunk reports a short write, as `pwrite` does.
        assert!(matches!(
            fs.write(&mut fd, &FaultingBuffer::new(4, 0), Some(10)),
            Err(WriteError::Broker(_))
        ));
        assert_eq!(fs.handle_status(&fd).unwrap().size, 8);
        assert_eq!(
            fs.write(&mut fd, &FaultingBuffer::new(4, 3), Some(8))
                .unwrap(),
            2
        );
        assert_eq!(memory.contents(), b"testfoo\n\0\0");

        // Running out of space partway reports the bytes that fit, and growing at the end of
        // the space fails.
        assert_eq!(fs.write(&mut fd, b"abcd", Some(10)).unwrap(), 2);
        assert!(matches!(
            fs.write(&mut fd, b"!", Some(12)),
            Err(WriteError::NoSpace)
        ));
        assert!(matches!(
            fs.truncate(&mut fd, 13, false),
            Err(TruncateError::NoSpace)
        ));

        // The storage refuses to shrink, as Windows does while the file is mapped.
        assert!(matches!(
            fs.truncate(&mut fd, 1, false),
            Err(TruncateError::Busy)
        ));
        assert!(matches!(
            fs.open(USER, "/foo", OFlags::RDWR | OFlags::TRUNC, Mode::empty()),
            Err(OpenError::TruncateError(TruncateError::Busy))
        ));
        assert_eq!(memory.contents(), b"testfoo\n\0\0ab");
        assert_eq!(fs.handle_status(&fd).unwrap().size, 12);
    }
}

mod mounts {
    use super::{InMem, Mode, OFlags, ROOT, Resolver, TestPlatform, USER};
    use crate::fs::backend::{Backend, Resolution, ResolvedTarget};
    use crate::fs::errors::{FileStatusError, OpenError, PathError, WalkError};
    use crate::fs::inode_allocator::InodeAllocators;
    use crate::fs::mount::{Location, Mount, MountInfo, MountRoot};
    use crate::fs::resolver::resolve_from;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    const DIR_MODE: Mode = Mode::RWXU
        .union(Mode::RGRP)
        .union(Mode::XGRP)
        .union(Mode::ROTH)
        .union(Mode::XOTH);
    const FILE_MODE: Mode = Mode::RUSR
        .union(Mode::WUSR)
        .union(Mode::RGRP)
        .union(Mode::ROTH);

    /// An in-memory backend whose nodes have device `device`, which tells which mount a node is
    /// on.
    fn in_mem(device: u64) -> InMem<TestPlatform> {
        // Allocators hand out devices from 1.
        let allocators = InodeAllocators::new();
        for _ in 1..device {
            let _ = allocators.next();
        }
        InMem::new(allocators.next())
    }

    /// A resolver whose root mount is an in-memory backend of device 1, with `dirs` made in it.
    fn fs(dirs: &[(&str, Mode)]) -> Resolver<TestPlatform> {
        let fs = Resolver::new(in_mem(1));
        for &(dir, mode) in dirs {
            fs.mkdir(ROOT, dir, mode).unwrap();
        }
        fs
    }

    fn device(fs: &Resolver<TestPlatform>, path: &str) -> u64 {
        fs.file_status(USER, path, true).unwrap().node_info.dev
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|&name| String::from(name)).collect()
    }

    /// The directory at `path`, anchored on an open handle on it, as a working directory is.
    fn locate(root: &Location, path: &str) -> Location {
        resolve_from(ROOT, root, root, path, true, |location, resolution| {
            let Resolution::Found(ResolvedTarget::Dir(dir)) = resolution else {
                panic!("{path} is not a directory");
            };
            let dir = location
                .mount
                .backend()
                .open_dir(dir, OFlags::PATH)
                .unwrap();
            Location::anchored(Arc::clone(&location.mount), location.path.clone(), dir)
        })
        .unwrap()
    }

    /// Attach a mount of `root` in `backend` at `path`, which it shows at `backend_root`.
    fn attach(
        fs: &Resolver<TestPlatform>,
        path: &str,
        backend: Arc<dyn Backend>,
        root: MountRoot,
        backend_root: &[&str],
    ) -> Arc<Mount> {
        let namespace = fs.namespace();
        let target = namespace.root();
        let (parent, point) = resolve_from(ROOT, &target, &target, path, true, |location, _| {
            (Arc::clone(&location.mount), location.path.clone())
        })
        .unwrap();
        let mount = namespace.new_mount(backend, root, names(backend_root), MountInfo::default());
        namespace
            .attach(&parent, point, Arc::clone(&mount))
            .unwrap();
        mount
    }

    /// Mount all of `backend` at `path`.
    fn mount(fs: &Resolver<TestPlatform>, path: &str, backend: impl Backend) -> Arc<Mount> {
        attach(fs, path, Arc::new(backend), MountRoot::Backend, &[])
    }

    /// Where `path` leads for the user, from `base` and never above `root`: a mount and a path in
    /// it.
    fn walk(
        root: &Location,
        base: &Location,
        path: &str,
    ) -> Result<(Arc<Mount>, Vec<String>), WalkError> {
        resolve_from(USER, root, base, path, true, |location, _| {
            (Arc::clone(&location.mount), location.path.clone())
        })
    }

    #[test]
    fn walks_cross_a_mount_and_dot_dot_climbs_back_out() {
        let fs = fs(&[("/mnt", DIR_MODE), ("/dir", DIR_MODE)]);
        mount(&fs, "/mnt", in_mem(2));
        fs.mkdir(ROOT, "/mnt/inner", DIR_MODE).unwrap();

        assert_eq!(device(&fs, "/mnt"), 2);
        assert_eq!(device(&fs, "/mnt/inner"), 2);
        assert_eq!(device(&fs, "/mnt/inner/../.."), 1);
        assert_eq!(
            fs.resolve_following_symlinks(USER, "/mnt/inner/../../dir")
                .unwrap(),
            "/dir"
        );
        assert_eq!(
            fs.resolve_following_symlinks(USER, "/mnt/inner").unwrap(),
            "/mnt/inner"
        );
    }

    #[test]
    fn mounts_on_an_occupied_point_stack_in_a_chain() {
        let fs = fs(&[("/mnt", DIR_MODE)]);
        mount(&fs, "/mnt", in_mem(2));
        // `/mnt` now leads to the root of the mount on it, where this one goes.
        mount(&fs, "/mnt", in_mem(3));
        // Attaching at the bottom of the stack goes on top of it too.
        let namespace = fs.namespace();
        let top = namespace.new_mount(
            Arc::new(in_mem(4)),
            MountRoot::Backend,
            Vec::new(),
            MountInfo::default(),
        );
        namespace
            .attach(&namespace.root().mount, names(&["mnt"]), top)
            .unwrap();
        fs.mkdir(ROOT, "/mnt/top", DIR_MODE).unwrap();

        assert_eq!(device(&fs, "/mnt/top"), 4);
        assert_eq!(device(&fs, "/mnt/top/../.."), 1);
        assert_eq!(
            fs.resolve_following_symlinks(USER, "/mnt/top/..").unwrap(),
            "/mnt"
        );
    }

    #[test]
    fn dot_dot_stops_at_the_root() {
        let fs = fs(&[
            ("/dir", DIR_MODE),
            ("/dir/sub", DIR_MODE),
            ("/mnt", DIR_MODE),
        ]);
        let mnt = mount(&fs, "/mnt", in_mem(2));
        fs.mkdir(ROOT, "/mnt/inner", DIR_MODE).unwrap();
        let namespace_root = fs.namespace().root();

        let root = locate(&namespace_root, "/dir");
        let (mount, path) = walk(&root, &root, "/../../sub").unwrap();
        assert!(Arc::ptr_eq(&mount, &root.mount));
        assert_eq!(path, names(&["dir", "sub"]));

        let root = locate(&namespace_root, "/mnt");
        let (mount, path) = walk(&root, &root, "../..").unwrap();
        assert!(Arc::ptr_eq(&mount, &mnt));
        assert_eq!(path, names(&[]));

        // A detached mount is a tree of its own, whose root `..` stays at.
        let inner = locate(&namespace_root, "/mnt/inner");
        fs.namespace().detach(&mnt).unwrap();
        assert_eq!(device(&fs, "/mnt"), 1);
        let (mount, path) = walk(&namespace_root, &inner, "../../..").unwrap();
        assert!(Arc::ptr_eq(&mount, &mnt));
        assert_eq!(path, names(&[]));
    }

    #[test]
    fn dot_dot_at_the_root_follows_a_mount_on_the_root() {
        let fs = fs(&[]);
        mount(&fs, "/", in_mem(2));

        // Like Linux, a walk doesn't follow the mounts on where it starts, but `..` follows those
        // where it ends.
        assert_eq!(device(&fs, "/"), 1);
        assert_eq!(device(&fs, "/.."), 2);
        assert_eq!(device(&fs, "/../.."), 2);
    }

    #[test]
    fn symlinks_resolve_from_the_root_or_their_directory() {
        let fs = fs(&[
            ("/dir", DIR_MODE),
            ("/dir/sub", DIR_MODE),
            ("/mnt", DIR_MODE),
        ]);
        mount(&fs, "/mnt", in_mem(2));
        fs.symlink(ROOT, "/dir", "/mnt/absolute").unwrap();
        fs.symlink(ROOT, "../dir", "/mnt/relative").unwrap();
        fs.symlink(ROOT, "/sub", "/dir/link").unwrap();

        for path in ["/mnt/absolute/sub", "/mnt/relative/sub"] {
            assert_eq!(
                fs.resolve_following_symlinks(USER, path).unwrap(),
                "/dir/sub"
            );
        }
        // An absolute target restarts at the walk's root, not the namespace's.
        let root = locate(&fs.namespace().root(), "/dir");
        let (_, path) = walk(&root, &root, "link").unwrap();
        assert_eq!(path, names(&["dir", "sub"]));
    }

    #[test]
    fn relative_paths_resolve_from_an_anchored_base() {
        let fs = fs(&[("/a", Mode::RWXU), ("/a/b", DIR_MODE), ("/a/b/c", DIR_MODE)]);
        let root = fs.namespace().root();
        let base = locate(&root, "/a/b");

        // Lookups from the base don't check its ancestors, which the user can't search, but
        // looking a name up above it does.
        assert!(matches!(
            walk(&root, &root, "/a/b/c"),
            Err(WalkError::PathError(PathError::NoSearchPerms))
        ));
        assert_eq!(walk(&root, &base, "c").unwrap().1, names(&["a", "b", "c"]));
        assert!(matches!(
            walk(&root, &base, "../b/c"),
            Err(WalkError::PathError(PathError::NoSearchPerms))
        ));

        // Forward lookups go through the anchor after its directory is renamed; the base keeps its
        // old path.
        fs.rename(ROOT, "/a/b", "/a/moved").unwrap();
        assert_eq!(
            walk(&root, &base, "c/.").unwrap().1,
            names(&["a", "b", "c"])
        );
    }

    #[test]
    fn binds_show_their_source_without_search_checks_above_it() {
        let fs = fs(&[
            ("/private", Mode::RWXU),
            ("/private/shared", DIR_MODE),
            ("/mnt", DIR_MODE),
        ]);
        for path in ["/private/shared/file", "/private/secret", "/file"] {
            let mut file = fs
                .open(ROOT, path, OFlags::CREAT | OFlags::WRONLY, FILE_MODE)
                .unwrap();
            fs.write(&mut file, &path.as_bytes(), None).unwrap();
        }
        let root = fs.namespace().root();
        let backend = Arc::clone(root.mount.backend());

        let shared = locate(&root, "/private/shared");
        let dir_root = MountRoot::Dir(shared.anchor.unwrap());
        attach(
            &fs,
            "/mnt",
            Arc::clone(&backend),
            dir_root,
            &["private", "shared"],
        );
        assert!(matches!(
            fs.file_status(USER, "/private/shared/file", true),
            Err(FileStatusError::PathError(PathError::NoSearchPerms))
        ));
        assert_eq!(
            fs.resolve_following_symlinks(USER, "/mnt/file").unwrap(),
            "/mnt/file"
        );

        let private = locate(&root, "/private");
        let file_root =
            MountRoot::file(&*backend, private.anchor.unwrap(), String::from("secret")).unwrap();
        attach(&fs, "/file", backend, file_root, &["private", "secret"]);
        let mut file = fs
            .open(USER, "/file", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let mut contents = vec![0; 32];
        let read = fs.read(&mut file, &mut contents, None).unwrap();
        assert_eq!(&contents[..read], b"/private/secret");

        // The bind shows the node it was made of, never another node, or a symbolic link, that
        // later takes its name.
        fs.unlink(ROOT, "/private/secret").unwrap();
        fs.symlink(ROOT, "/private/shared/file", "/private/secret")
            .unwrap();
        for follow_symlinks in [true, false] {
            assert!(matches!(
                fs.file_status(USER, "/file", follow_symlinks),
                Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory))
            ));
        }
        fs.unlink(ROOT, "/private/secret").unwrap();
        drop(
            fs.open(
                ROOT,
                "/private/secret",
                OFlags::CREAT | OFlags::WRONLY,
                FILE_MODE,
            )
            .unwrap(),
        );
        assert!(matches!(
            fs.open(USER, "/file", OFlags::RDONLY, Mode::empty()),
            Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
        ));
    }
}
