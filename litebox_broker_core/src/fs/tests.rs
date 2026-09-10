// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Filesystem semantics for the broker-core resolver and its backends.
//!
//! These tests drive the resolver and the backends directly, through the [`Fs`] facade from
//! [`super::test_support`]. There is deliberately no broker session, transport, or guest
//! descriptor table involved: the semantics under test are owned by broker core.

use alloc::borrow::Cow;
use litebox_broker_protocol::fs::{
    FileMode as Mode, FileSeekWhence as SeekWhence, FileType, FileUser as UserInfo,
};

use super::OFlags;
use super::in_mem::InMem;
use super::inode_allocator::InodeAllocator;
use super::overlay::Overlay;
use super::tar_ro::TarRo;
use super::test_support::{Fs, ROOT, RecordingStdio, USER, UnservicedStdio};
use crate::test_platform::TestPlatform;

const TEST_TAR_FILE: &[u8] = include_bytes!("./test.tar");

fn in_mem_fs() -> Fs<InMem<TestPlatform>> {
    Fs::new(InMem::<TestPlatform>::new(InodeAllocator::standalone()))
}

fn tar_ro_fs(tar_data: Cow<'static, [u8]>) -> Fs<TarRo> {
    Fs::new(TarRo::new(tar_data, InodeAllocator::standalone()))
}

/// An overlay of `upper` over a tar-backed lower layer.
fn overlay_fs(
    upper: InMem<TestPlatform>,
    tar_data: Cow<'static, [u8]>,
) -> Fs<Overlay<TestPlatform>> {
    Fs::new(Overlay::<TestPlatform>::new(
        upper,
        TarRo::new(tar_data, InodeAllocator::standalone()),
        InodeAllocator::standalone(),
    ))
}

mod in_mem {
    use super::{
        FileType, Fs, InMem, Mode, OFlags, ROOT, SeekWhence, TestPlatform, USER, UserInfo,
        in_mem_fs,
    };
    use crate::fs::errors::{
        ChownError, MkdirError, OpenError, PathError, ReadDirError, ReadError, RmdirError,
        UnlinkError,
    };
    use crate::fs::test_support::Entry;
    use alloc::vec;
    use alloc::vec::Vec;

    type InMemFs = Fs<InMem<TestPlatform>>;
    type InMemEntry = Entry<InMem<TestPlatform>>;

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

        let status = fs.file_status(USER, path).expect("Failed to stat file");
        assert_eq!(status.mode, Mode::empty());
        assert!(matches!(
            fs.open(USER, path, OFlags::WRONLY, Mode::empty()),
            Err(OpenError::AccessNotAllowed)
        ));
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
        fs.write(&mut fd, &data[2..], Some(2))
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
        let bytes_read2 = fs
            .read(&mut fd, &mut buffer[2..], Some(2))
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
                assert!(entry.node_info.is_some(), "Inode info should be present");
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
            fs.unlink(USER, "/rootdir/file"),
            Err(UnlinkError::NoWritePerms)
        ));
        assert!(matches!(
            fs.rmdir(USER, "/rootdir/sub"),
            Err(RmdirError::NoWritePerms)
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
            .file_status(USER, "/newfile")
            .expect("Failed to get file status");
        assert_eq!(stat.file_type, FileType::RegularFile);

        // TODO(jayb): Restore coverage of `O_RDWR | O_DIRECTORY` once `OpenError` can report
        // `EISDIR`; see the matching TODO in `InMem::owned_dir_at`. The legacy in-memory file
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
    fn truncate_resets_or_keeps_position() {
        let fs = in_mem_fs();
        world_writable_root(&fs);

        let mut fd = fs
            .open(USER, "/truncfile", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
            .expect("Failed to create file");
        fs.write(&mut fd, b"0123456789", None)
            .expect("Failed to write file");

        // Truncating without resetting keeps the position, so a read sees nothing.
        fs.truncate(&mut fd, 4, false).expect("Failed to truncate");
        let mut buffer = vec![0; 10];
        assert_eq!(
            fs.read(&mut fd, &mut buffer, None)
                .expect("Failed to read file"),
            0
        );

        // Truncating with a reset rewinds to the start of the (now shorter) file.
        fs.truncate(&mut fd, 4, true).expect("Failed to truncate");
        let bytes_read = fs
            .read(&mut fd, &mut buffer, None)
            .expect("Failed to read file");
        assert_eq!(&buffer[..bytes_read], b"0123");
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
        fs.write(&mut fd, data, None)
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
}

mod tar_ro {
    use super::{FileType, Mode, OFlags, TEST_TAR_FILE, USER, tar_ro_fs};
    use crate::fs::errors::{OpenError, PathError, ReadDirError};
    use alloc::vec;
    use alloc::vec::Vec;

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
                assert!(entry.node_info.is_some(), "Inode info should be present");
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
}

mod overlay {
    use super::{
        FileType, Fs, Mode, OFlags, Overlay, SeekWhence, TEST_TAR_FILE, TestPlatform, USER,
        UserInfo,
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
    ) -> InMem<TestPlatform> {
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
        )
    }

    fn overlay_fs(upper: InMem<TestPlatform>) -> Fs<Overlay<TestPlatform>> {
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

        let stat = fs.file_status(USER, "bar").expect("Failed to file stat");
        assert_eq!(stat.file_type, FileType::Directory);
        assert_eq!(stat.mode, Mode::from_bits(0o777).unwrap());

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
            entries[2].node_info.is_some(),
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
                assert!(entry.node_info.is_some(), "Inode info should be present");
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
            .file_status(USER, "/bar/test")
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
            .file_status(USER, "bar/test")
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
            .file_status(USER, "bar/baz")
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
            fs.file_status(USER, "/upper_empty"),
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
            fs.file_status(USER, "/upper_dir"),
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
    fn copy_up_does_not_deadlock() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let fs = overlay_fs(upper([]));

        fs.file_status(USER, "foo").expect("Failed to stat foo");

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
    use super::{Fs, Mode, OFlags, RecordingStdio, USER, UnservicedStdio};
    use crate::fs::composer::Composer;
    use crate::fs::devices::Devices;
    use crate::fs::errors::{OpenError, PathError, ReadError, WriteError};
    use alloc::vec;
    use litebox_broker_protocol::stdio::StdioOutputStream;

    fn devices_fs() -> Fs<Composer> {
        Fs::new(
            Composer::builder()
                .mount("/dev", Devices::new)
                .build()
                .unwrap(),
        )
    }

    /// Stdio devices hold no data of their own: every non-empty transfer needs the session's
    /// device I/O, and fails when the session cannot service it.
    #[test]
    fn stdio_requires_broker() {
        let fs = devices_fs();
        let stdio = UnservicedStdio;

        let mut fd_stdout = fs
            .open(USER, "/dev/stdout", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stdout");
        assert!(matches!(
            fs.write_with(&stdio, &mut fd_stdout, b"", None),
            Ok(0)
        ));
        assert!(matches!(
            fs.write_with(&stdio, &mut fd_stdout, b"Hello, stdout!", None),
            Err(WriteError::Io)
        ));
        drop(fd_stdout);

        let mut fd_stderr = fs
            .open(USER, "/dev/stderr", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stderr");
        assert!(matches!(
            fs.write_with(&stdio, &mut fd_stderr, b"", None),
            Ok(0)
        ));
        assert!(matches!(
            fs.write_with(&stdio, &mut fd_stderr, b"Hello, stderr!", None),
            Err(WriteError::Io)
        ));
        drop(fd_stderr);

        let mut fd_stdin = fs
            .open(USER, "/dev/stdin", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open /dev/stdin");
        assert!(matches!(
            fs.read_with(&stdio, &mut fd_stdin, &mut [], None),
            Ok(0)
        ));
        let mut buffer = vec![0; 13];
        assert!(matches!(
            fs.read_with(&stdio, &mut fd_stdin, &mut buffer, None),
            Err(ReadError::Io)
        ));
    }

    /// Each stdio device routes to its own stream on the session's device I/O.
    #[test]
    fn stdio_routes_to_the_session_streams() {
        let fs = devices_fs();
        let stdio = RecordingStdio::new(b"host input");

        let mut fd_stdout = fs
            .open(USER, "/dev/stdout", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stdout");
        assert_eq!(
            fs.write_with(&stdio, &mut fd_stdout, b"out", None)
                .expect("Failed to write /dev/stdout"),
            3
        );

        let mut fd_stderr = fs
            .open(USER, "/dev/stderr", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stderr");
        assert_eq!(
            fs.write_with(&stdio, &mut fd_stderr, b"err", None)
                .expect("Failed to write /dev/stderr"),
            3
        );

        assert_eq!(
            stdio.writes(),
            vec![
                (StdioOutputStream::Stdout, b"out".to_vec()),
                (StdioOutputStream::Stderr, b"err".to_vec()),
            ]
        );

        let mut fd_stdin = fs
            .open(USER, "/dev/stdin", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open /dev/stdin");
        let mut buffer = vec![0; 16];
        let read = fs
            .read_with(&stdio, &mut fd_stdin, &mut buffer, None)
            .expect("Failed to read /dev/stdin");
        assert_eq!(&buffer[..read], b"host input");

        // Reading a write-only device and writing a read-only device are rejected.
        assert!(matches!(
            fs.read_with(&stdio, &mut fd_stdout, &mut buffer, None),
            Err(ReadError::NotForReading)
        ));
        assert!(matches!(
            fs.write_with(&stdio, &mut fd_stdin, b"x", None),
            Err(WriteError::NotForWriting)
        ));
    }

    #[test]
    fn non_dev_path_fails() {
        let fs = devices_fs();

        // Attempt to open a non-/dev/* path
        assert!(matches!(
            fs.open(USER, "foo", OFlags::RDONLY, Mode::empty()),
            Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
        ));
    }
}

mod composed {
    use super::{Fs, InMem, Mode, OFlags, TestPlatform, USER, UnservicedStdio, UserInfo};
    use crate::fs::composer::Composer;
    use crate::fs::devices::Devices;
    use crate::fs::errors::{ReadError, WriteError};
    use crate::fs::in_mem::InitialNode;
    use alloc::vec;

    fn composed_fs() -> Fs<Composer> {
        Fs::new(
            Composer::builder()
                .mount("/", |_| {
                    InMem::<TestPlatform>::new_initialized([(
                        "/",
                        InitialNode::Directory {
                            mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                            owner: UserInfo::ROOT,
                        },
                    )])
                })
                .mount("/dev", Devices::new)
                .build()
                .unwrap(),
        )
    }

    #[test]
    fn stdio_requires_broker() {
        let fs = composed_fs();
        let stdio = UnservicedStdio;

        let mut fd_stdout = fs
            .open(USER, "/dev/stdout", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stdout");
        assert!(matches!(
            fs.write_with(&stdio, &mut fd_stdout, b"", None),
            Ok(0)
        ));
        assert!(matches!(
            fs.write_with(&stdio, &mut fd_stdout, b"Hello, composed stdout!", None),
            Err(WriteError::Io)
        ));
        drop(fd_stdout);

        let mut fd_stderr = fs
            .open(USER, "/dev/stderr", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stderr");
        assert!(matches!(
            fs.write_with(&stdio, &mut fd_stderr, b"", None),
            Ok(0)
        ));
        assert!(matches!(
            fs.write_with(&stdio, &mut fd_stderr, b"Hello, composed stderr!", None),
            Err(WriteError::Io)
        ));
        drop(fd_stderr);

        let mut fd_stdin = fs
            .open(USER, "/dev/stdin", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open /dev/stdin");
        assert!(matches!(
            fs.read_with(&stdio, &mut fd_stdin, &mut [], None),
            Ok(0)
        ));
        let mut buffer = vec![0; 1024];
        assert!(matches!(
            fs.read_with(&stdio, &mut fd_stdin, &mut buffer, None),
            Err(ReadError::Io)
        ));
    }

    #[test]
    fn write_to_non_dev() {
        let fs = composed_fs();

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
