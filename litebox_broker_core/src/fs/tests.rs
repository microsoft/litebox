// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Engine semantics exercised without LiteBox's context or descriptor table.

use alloc::borrow::Cow;

use super::UserInfo;
use super::backend::Backend;
use super::in_mem::InMem;
use super::inode_allocator::InodeAllocator;
use super::overlay::Overlay;
use super::resolver::Resolver;
use super::tar_ro::TarRo;
use crate::test_platform::TestPlatform;

const USER: UserInfo = UserInfo {
    user: 1000,
    group: 1000,
};

fn tar_ro_fs(tar_data: Cow<'static, [u8]>) -> Resolver<TestPlatform, TarRo> {
    Resolver::new(TarRo::new(tar_data, InodeAllocator::standalone()))
}

type InMemFs = Resolver<TestPlatform, InMem<TestPlatform>>;

fn in_mem_fs() -> InMemFs {
    Resolver::new(InMem::new(InodeAllocator::standalone()))
}

/// Run `f` with the acting user set to root.
fn with_root_privileges<Platform, B: Backend>(
    fs: &Resolver<Platform, B>,
    f: impl FnOnce(&Resolver<Platform, B>, UserInfo),
) {
    f(fs, UserInfo::ROOT);
}

/// Run `f` with the acting user set to `user`/`group`, so that tests can exercise operations
/// whose outcome depends on the acting user.
fn with_user<Platform, B: Backend>(
    fs: &Resolver<Platform, B>,
    user: u16,
    group: u16,
    f: impl FnOnce(&Resolver<Platform, B>, UserInfo),
) {
    f(fs, UserInfo { user, group });
}

type OverlayFs = Resolver<TestPlatform, Overlay<TestPlatform>>;

/// An overlay of `upper` over a tar-backed lower layer.
fn overlay_fs(upper: InMem<TestPlatform>, tar_data: Cow<'static, [u8]>) -> OverlayFs {
    Resolver::new(Overlay::new(
        upper,
        TarRo::new(tar_data, InodeAllocator::standalone()),
        InodeAllocator::standalone(),
    ))
}

mod in_mem {
    use super::USER;
    use crate::fs::backend::NoDeviceIo;
    use crate::fs::{Mode, OFlags};
    use alloc::vec;
    use alloc::vec::Vec;
    extern crate std;

    use super::{with_root_privileges, with_user};

    #[test]
    fn root_file_creation_and_deletion() {
        with_root_privileges(&super::in_mem_fs(), |fs, user| {
            // Test file creation
            let path = "/testfile";
            let fd = fs
                .open(user, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .expect("Failed to create file");

            drop(fd);

            // Test file deletion
            fs.unlink(user, path).expect("Failed to unlink file");
            assert!(
                fs.open(user, path, OFlags::RDONLY, Mode::RWXU).is_err(),
                "File should not exist"
            );
        });
    }

    #[test]
    fn root_file_read_write() {
        with_root_privileges(&super::in_mem_fs(), |fs, user| {
            // Create and write to a file
            let path = "/testfile";
            let mut fd = fs
                .open(user, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .expect("Failed to create file");
            let data = b"Hello, world!";
            fs.write(&NoDeviceIo, &mut fd, data, None)
                .expect("Failed to write to file");
            drop(fd);

            // Read from the file
            let mut fd = fs
                .open(user, path, OFlags::RDONLY, Mode::RWXU)
                .expect("Failed to open file");
            let mut buffer = vec![0; data.len()];
            let bytes_read = fs
                .read(&NoDeviceIo, &mut fd, &mut buffer, None)
                .expect("Failed to read from file");
            assert_eq!(bytes_read, data.len());
            assert_eq!(&buffer, data);
            drop(fd);
        });
    }

    #[test]
    fn write_only_open_does_not_require_read_permission() {
        let user = USER;

        let fs = super::in_mem_fs();
        with_root_privileges(&fs, |fs, user| {
            fs.mkdir(user, "/tmp", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to create /tmp");
        });

        let path = "/tmp/write_only";
        let mut fd = fs
            .open(user, path, OFlags::CREAT | OFlags::WRONLY, Mode::WUSR)
            .expect("Failed to create write-only file");
        fs.write(&NoDeviceIo, &mut fd, b"x", None)
            .expect("Failed to write file");

        let mut buffer = [0];
        assert!(matches!(
            fs.read(&NoDeviceIo, &mut fd, &mut buffer, None),
            Err(crate::fs::errors::ReadError::NotForReading)
        ));
        drop(fd);

        assert!(matches!(
            fs.open(user, path, OFlags::RDONLY, Mode::empty()),
            Err(crate::fs::errors::OpenError::AccessNotAllowed)
        ));
    }

    #[test]
    fn newly_created_file_does_not_require_its_own_permissions() {
        let user = USER;

        let fs = super::in_mem_fs();
        with_root_privileges(&fs, |fs, user| {
            fs.mkdir(user, "/tmp", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to create /tmp");
        });

        let path = "/tmp/zero_mode";
        let mut fd = fs
            .open(user, path, OFlags::CREAT | OFlags::WRONLY, Mode::empty())
            .expect("Failed to create zero-mode file");
        fs.write(&NoDeviceIo, &mut fd, b"x", None)
            .expect("Failed to write file");
        drop(fd);

        let status = fs.file_status(user, path).expect("Failed to stat file");
        assert_eq!(status.mode, Mode::empty());
        assert!(matches!(
            fs.open(user, path, OFlags::WRONLY, Mode::empty()),
            Err(crate::fs::errors::OpenError::AccessNotAllowed)
        ));
    }

    #[test]
    fn root_directory_creation_and_removal() {
        with_root_privileges(&super::in_mem_fs(), |fs, user| {
            // Test directory creation
            let path = "/testdir";
            fs.mkdir(user, path, Mode::RWXU)
                .expect("Failed to create directory");

            // Test directory removal
            fs.rmdir(user, path).expect("Failed to remove directory");
            assert!(
                fs.open(user, path, OFlags::RDONLY, Mode::RWXU).is_err(),
                "Directory should not exist"
            );
        });
    }

    #[test]
    fn file_creation_and_deletion() {
        let user = USER;

        let fs = super::in_mem_fs();
        with_root_privileges(&fs, |fs, user| {
            // Make `/tmp` and set up with reasonable privs so normal users can do things in there.
            fs.mkdir(user, "/tmp", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to create /tmp");
        });

        // Test file creation
        let path = "/tmp/testfile";
        let fd = fs
            .open(user, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");

        drop(fd);

        // Test file deletion
        fs.unlink(user, path).expect("Failed to unlink file");
        assert!(
            fs.open(user, path, OFlags::RDONLY, Mode::RWXU).is_err(),
            "File should not exist"
        );
    }

    #[test]
    fn file_read_write() {
        let user = USER;

        let fs = super::in_mem_fs();
        with_root_privileges(&fs, |fs, user| {
            // Make `/tmp` and set up with reasonable privs so normal users can do things in there.
            fs.mkdir(user, "/tmp", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to create /tmp");
        });

        // Create and write to a file
        let path = "/tmp/testfile";
        let mut fd = fs
            .open(user, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        let data = b"Hello, world!";
        fs.write(&NoDeviceIo, &mut fd, data, None)
            .expect("Failed to write to file");
        fs.write(&NoDeviceIo, &mut fd, &data[2..], Some(2))
            .expect("Failed to write to file with offset");
        drop(fd);

        // Read from the file
        let mut fd = fs
            .open(user, path, OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut buffer = vec![0; data.len()];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        let bytes_read2 = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer[2..], Some(2))
            .expect("Failed to read from file with offset");
        assert_eq!(bytes_read, data.len());
        assert_eq!(bytes_read2, data.len() - 2);
        assert_eq!(&buffer, data);
        drop(fd);
    }

    #[test]
    fn directory_creation_and_removal() {
        let user = USER;

        let fs = super::in_mem_fs();
        with_root_privileges(&fs, |fs, user| {
            // Make `/tmp` and set up with reasonable privs so normal users can do things in there.
            fs.mkdir(user, "/tmp", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to create /tmp");
        });

        // Test directory creation
        let path = "/tmp/testdir";
        fs.mkdir(user, path, Mode::RWXU)
            .expect("Failed to create directory");

        // Test directory removal
        fs.rmdir(user, path).expect("Failed to remove directory");
        assert!(
            fs.open(user, path, OFlags::RDONLY, Mode::RWXU).is_err(),
            "Directory should not exist"
        );
    }

    #[test]
    fn read_dir_empty() {
        with_root_privileges(&super::in_mem_fs(), |fs, user| {
            let fd = fs
                .open(user, "/", OFlags::RDONLY, Mode::empty())
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
            drop(fd);
        });
    }

    #[test]
    fn read_dir_with_files_and_dirs() {
        with_root_privileges(&super::in_mem_fs(), |fs, user| {
            // Create a directory structure
            fs.mkdir(user, "/testdir", Mode::RWXU)
                .expect("Failed to create directory");
            let fd1 = fs
                .open(
                    user,
                    "/testfile1",
                    OFlags::CREAT | OFlags::WRONLY,
                    Mode::RWXU,
                )
                .expect("Failed to create file1");
            drop(fd1);
            let fd2 = fs
                .open(
                    user,
                    "/testfile2",
                    OFlags::CREAT | OFlags::WRONLY,
                    Mode::RWXU,
                )
                .expect("Failed to create file2");
            drop(fd2);

            // Read root directory
            let fd = fs
                .open(user, "/", OFlags::RDONLY, Mode::empty())
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
                        assert_eq!(entry.file_type, crate::fs::FileType::Directory);
                    }
                    "testfile1" | "testfile2" => {
                        assert_eq!(entry.file_type, crate::fs::FileType::RegularFile);
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
                .open(user, "/testdir", OFlags::RDONLY, Mode::empty())
                .expect("Failed to open subdirectory");
            let entries = fs
                .read_dir(&fd)
                .expect("Failed to read subdirectory")
                .iter()
                .map(|e| e.name.clone())
                .collect::<Vec<_>>();
            assert!(entries.len() == 2, "Subdirectory should contain . and ..");
            drop(fd);
        });
    }

    #[test]
    fn read_dir_file_not_directory() {
        with_root_privileges(&super::in_mem_fs(), |fs, user| {
            // Create a file
            let fd = fs
                .open(
                    user,
                    "/testfile",
                    OFlags::CREAT | OFlags::WRONLY,
                    Mode::RWXU,
                )
                .expect("Failed to create file");
            drop(fd);

            // Try to read_dir on the file (should fail)
            let fd = fs
                .open(user, "/testfile", OFlags::RDONLY, Mode::empty())
                .expect("Failed to open file");
            let result = fs.read_dir(&fd);
            drop(fd);

            assert!(matches!(
                result,
                Err(crate::fs::errors::ReadDirError::NotADirectory)
            ));
        });
    }

    #[test]
    fn parent_dir_write_permissions_are_enforced() {
        let fs = super::in_mem_fs();

        with_root_privileges(&fs, |fs, user| {
            // A root-owned 0755 directory, holding a file and a directory to try to remove.
            fs.mkdir(
                user,
                "/rootdir",
                Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
            )
            .expect("Failed to create directory");
            let fd = fs
                .open(
                    user,
                    "/rootdir/file",
                    OFlags::CREAT | OFlags::WRONLY,
                    Mode::RWXU,
                )
                .expect("Failed to create file");
            drop(fd);
            fs.mkdir(user, "/rootdir/sub", Mode::RWXU)
                .expect("Failed to create subdirectory");

            // A world-writable directory, for the positive case.
            fs.mkdir(user, "/opendir", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to create directory");
        });

        with_user(&fs, 1000, 1000, |fs, user| {
            assert!(matches!(
                fs.open(
                    user,
                    "/rootdir/new",
                    OFlags::CREAT | OFlags::WRONLY,
                    Mode::RWXU
                ),
                Err(crate::fs::errors::OpenError::NoWritePerms)
            ));
            assert!(matches!(
                fs.mkdir(user, "/rootdir/newdir", Mode::RWXU),
                Err(crate::fs::errors::MkdirError::NoWritePerms)
            ));
            assert!(matches!(
                fs.unlink(user, "/rootdir/file"),
                Err(crate::fs::errors::UnlinkError::NoWritePerms)
            ));
            assert!(matches!(
                fs.rmdir(user, "/rootdir/sub"),
                Err(crate::fs::errors::RmdirError::NoWritePerms)
            ));

            // The same operations succeed in a directory the user may write.
            let fd = fs
                .open(
                    user,
                    "/opendir/new",
                    OFlags::CREAT | OFlags::WRONLY,
                    Mode::RWXU,
                )
                .expect("Failed to create file");
            drop(fd);
            fs.mkdir(user, "/opendir/newdir", Mode::RWXU)
                .expect("Failed to create directory");
            fs.unlink(user, "/opendir/new")
                .expect("Failed to unlink file");
            fs.rmdir(user, "/opendir/newdir")
                .expect("Failed to remove directory");
        });
    }

    #[test]
    fn chown_test() {
        let user = USER;

        let fs = super::in_mem_fs();

        // Create a test file as root
        with_root_privileges(&fs, |fs, user| {
            let path = "/testfile";
            let fd = fs
                .open(user, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .expect("Failed to create file");
            drop(fd);

            // First chown to 1000:1000 as root (should succeed)
            fs.chown(user, path, Some(1000), Some(1000))
                .expect("Failed to chown as root");
        });

        // Switch to user 1000 and test that owner can chown (should succeed)
        let path = "/testfile";
        with_user(&fs, 1000, 1000, |fs, user| {
            fs.chown(user, path, Some(123), Some(456))
                .expect("Failed to chown as owner");
        });

        // Switch to a different user and test that non-owner cannot chown (should fail)
        with_user(&fs, 500, 500, |fs, user| {
            match fs.chown(user, path, Some(789), Some(101)) {
                Err(crate::fs::errors::ChownError::NotTheOwner) => {
                    // Expected behavior
                }
                Ok(()) => panic!("Non-owner should not be able to chown"),
                Err(e) => panic!("Unexpected error: {e:?}"),
            }
        });

        // Test chown on non-existent file (should fail)
        match fs.chown(user, "/nonexistent", Some(123), Some(456)) {
            Err(crate::fs::errors::ChownError::PathError(
                crate::fs::errors::PathError::NoSuchFileOrDirectory,
            )) => {
                // Expected behavior
            }
            Ok(()) => panic!("Should not be able to chown non-existent file"),
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        // Test partial chown (change only user, leave group unchanged)
        with_root_privileges(&fs, |fs, user| {
            fs.chown(user, path, Some(999), None)
                .expect("Failed to chown user only");
        });

        // Test partial chown (change only group, leave user unchanged)
        with_root_privileges(&fs, |fs, user| {
            fs.chown(user, path, None, Some(888))
                .expect("Failed to chown group only");
        });
    }

    #[test]
    fn o_directory_flag_tests() {
        let user = USER;

        let fs = super::in_mem_fs();

        with_root_privileges(&fs, |fs, user| {
            fs.chmod(user, "/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });
        // Create test directory and file
        fs.mkdir(user, "/testdir", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to create directory");

        let fd = fs
            .open(
                user,
                "/testfile",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create file");
        drop(fd);

        // Test O_DIRECTORY on a directory (should succeed)
        let fd = fs
            .open(
                user,
                "/testdir",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .expect("Failed to open directory with O_DIRECTORY");
        drop(fd);

        // Test O_DIRECTORY on a regular file (should fail)
        assert!(matches!(
            fs.open(
                user,
                "/testfile",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::ComponentNotADirectory
            ))
        ));

        // Test O_DIRECTORY on non-existent path (should fail)
        assert!(matches!(
            fs.open(
                user,
                "/nonexistent",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::NoSuchFileOrDirectory
            ))
        ));

        // Test O_DIRECTORY with O_CREAT on non-existent path
        // According to the implementation, O_DIRECTORY should be ignored when O_CREAT is specified
        let fd = fs
            .open(
                user,
                "/newfile",
                OFlags::CREAT | OFlags::WRONLY | OFlags::DIRECTORY,
                Mode::RWXU,
            )
            .expect("Failed to create file with O_CREAT | O_DIRECTORY");
        drop(fd);

        // Verify it created a regular file, not a directory
        let stat = fs
            .file_status(user, "/newfile")
            .expect("Failed to get file status");
        assert_eq!(stat.file_type, crate::fs::FileType::RegularFile);

        // TODO(jayb): Restore coverage of `O_RDWR | O_DIRECTORY` once `OpenError` can report
        // `EISDIR`; see the matching TODO in `InMem::owned_dir_at`. The legacy in-memory file
        // system used to accept such an open, which Linux rejects.
    }

    #[test]
    fn o_excl_flag_tests() {
        let user = USER;

        let fs = super::in_mem_fs();

        with_root_privileges(&fs, |fs, user| {
            fs.chmod(user, "/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });

        // Test O_CREAT | O_EXCL on non-existent file (should succeed)
        let mut fd = fs
            .open(
                user,
                "/newfile",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create new file with O_CREAT | O_EXCL");

        // Write some data to verify file was created
        fs.write(&NoDeviceIo, &mut fd, b"test data", None)
            .expect("Failed to write to new file");
        drop(fd);

        // Test O_CREAT | O_EXCL on existing file (should fail)
        assert!(matches!(
            fs.open(
                user,
                "/newfile",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            ),
            Err(crate::fs::errors::OpenError::AlreadyExists)
        ));

        // Test O_EXCL without O_CREAT (should be ignored and succeed)
        let mut fd = fs
            .open(
                user,
                "/newfile",
                OFlags::EXCL | OFlags::RDONLY,
                Mode::empty(),
            )
            .expect("Failed to open existing file with O_EXCL (without O_CREAT)");

        // Verify we can read the data
        let mut buffer = vec![0; 9];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test data");
        drop(fd);

        // Test O_CREAT without O_EXCL on existing file (should succeed)
        let fd = fs
            .open(user, "/newfile", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to open existing file with O_CREAT (without O_EXCL)");
        drop(fd);

        // Test O_CREAT | O_EXCL on directory (should fail)
        fs.mkdir(user, "/testdir", Mode::RWXU)
            .expect("Failed to create directory");
        assert!(matches!(
            fs.open(
                user,
                "/testdir",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            ),
            Err(crate::fs::errors::OpenError::AlreadyExists)
        ));
    }

    #[test]
    fn open_with_trunc() {
        let user = USER;

        let fs = super::in_mem_fs();

        with_root_privileges(&fs, |fs, user| {
            fs.chmod(user, "/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });

        // Create a file and write some initial content
        let path = "/testfile";
        let mut fd = fs
            .open(user, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        let initial_data = b"Hello, world! This is initial content.";
        fs.write(&NoDeviceIo, &mut fd, initial_data, None)
            .expect("Failed to write initial content");
        drop(fd);

        // Verify initial content was written
        let mut fd = fs
            .open(user, path, OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file for reading");
        let mut buffer = vec![0; initial_data.len()];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read initial content");
        assert_eq!(bytes_read, initial_data.len());
        assert_eq!(&buffer, initial_data);
        drop(fd);

        // Test O_TRUNC with O_WRONLY - should truncate file
        let mut fd = fs
            .open(user, path, OFlags::WRONLY | OFlags::TRUNC, Mode::empty())
            .expect("Failed to open file with O_TRUNC | O_WRONLY");

        // Write new content to the truncated file
        let new_data = b"New content";
        fs.write(&NoDeviceIo, &mut fd, new_data, None)
            .expect("Failed to write new content");
        drop(fd);

        // Verify the file was truncated and contains only new content
        let mut fd = fs
            .open(user, path, OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file for verification");
        let mut buffer = vec![0; initial_data.len()];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read after truncation");
        assert_eq!(bytes_read, new_data.len());
        assert_eq!(&buffer[..bytes_read], new_data);
        drop(fd);

        // Test O_TRUNC with O_RDWR - should also truncate
        fs.write(
            &NoDeviceIo,
            &mut fs.open(user, path, OFlags::WRONLY, Mode::empty()).unwrap(),
            b"More content to truncate",
            None,
        )
        .unwrap();
        let mut fd = fs
            .open(user, path, OFlags::RDWR | OFlags::TRUNC, Mode::empty())
            .expect("Failed to open file with O_TRUNC | O_RDWR");

        // File should be empty after truncation
        let mut buffer = vec![0; 100];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from truncated file");
        assert_eq!(bytes_read, 0);

        // Write and read back to verify it works
        let test_data = b"After RDWR truncation";
        fs.write(&NoDeviceIo, &mut fd, test_data, None)
            .expect("Failed to write after RDWR truncation");

        fs.seek(&mut fd, 0, crate::fs::SeekWhence::RelativeToBeginning)
            .expect("Failed to seek to beginning");
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read after write");
        assert_eq!(bytes_read, test_data.len());
        assert_eq!(&buffer[..bytes_read], test_data);
        drop(fd);
    }

    #[test]
    fn write_position_after_seek() {
        use crate::fs::SeekWhence;

        let user = USER;

        let fs = super::in_mem_fs();
        with_root_privileges(&fs, |fs, user| {
            // Allow regular user to create in root for this focused test
            fs.chmod(user, "/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("chmod / failed");
        });

        let mut fd = fs
            .open(
                user,
                "/posfile",
                OFlags::CREAT | OFlags::RDWR,
                Mode::RWXU | Mode::RWXG | Mode::RWXO,
            )
            .expect("open failed");

        // 1. First positional write; position should advance by 6.
        fs.write(&NoDeviceIo, &mut fd, b"abcdef", None)
            .expect("first write failed");

        // 2. Rewind to beginning.
        fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
            .expect("seek failed");

        // 3. Another positional write should write from start
        fs.write(&NoDeviceIo, &mut fd, b"X", None)
            .expect("overwrite failed");

        // The file offset should now be at 2.
        assert_eq!(
            fs.seek(&mut fd, 0, SeekWhence::RelativeToCurrentOffset)
                .expect("seek failed"),
            1
        );

        // Read back whole file to verify content and length.
        fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
            .expect("seek failed");
        let mut buf = [0u8; 16];
        let n = fs
            .read(&NoDeviceIo, &mut fd, &mut buf, None)
            .expect("read failed");
        assert_eq!(n, 6, "file length should be 6 after writes");
        assert_eq!(&buf[..n], b"Xbcdef", "file content mismatch");

        // Extra: another append to verify continued correct advancement.
        fs.write(&NoDeviceIo, &mut fd, b"12", None)
            .expect("second append failed");
        fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
            .expect("seek 2 failed");
        let mut buf2 = [0u8; 16];
        let n2 = fs
            .read(&NoDeviceIo, &mut fd, &mut buf2, None)
            .expect("read 2 failed");
        assert_eq!(n2, 8);
        assert_eq!(&buf2[..n2], b"Xbcdef12");

        drop(fd);
    }

    #[test]
    fn o_append_flag_basic() {
        let user = USER;

        let fs = super::in_mem_fs();

        with_root_privileges(&fs, |fs, user| {
            fs.chmod(user, "/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });

        // Create a file and write some initial content
        let path = "/testfile";
        let mut fd = fs
            .open(user, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        let initial_data = b"Hello";
        fs.write(&NoDeviceIo, &mut fd, initial_data, None)
            .expect("Failed to write initial content");
        drop(fd);

        // Re-open with O_APPEND and write more data
        let mut fd = fs
            .open(user, path, OFlags::WRONLY | OFlags::APPEND, Mode::empty())
            .expect("Failed to open file with O_APPEND");
        let append_data = b" World";
        fs.write(&NoDeviceIo, &mut fd, append_data, None)
            .expect("Failed to append data");
        drop(fd);

        // Verify the file contains both pieces of data concatenated
        let mut fd = fs
            .open(user, path, OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file for reading");
        let mut buffer = vec![0; 11];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(bytes_read, 11);
        assert_eq!(&buffer[..bytes_read], b"Hello World");
        drop(fd);
    }

    #[test]
    fn o_append_flag_seek_ignored_for_write() {
        use crate::fs::SeekWhence;

        let user = USER;

        let fs = super::in_mem_fs();

        with_root_privileges(&fs, |fs, user| {
            fs.chmod(user, "/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });

        // Create a file and write some initial content
        let path = "/testfile";
        let mut fd = fs
            .open(user, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        fs.write(&NoDeviceIo, &mut fd, b"ABCDEF", None)
            .expect("Failed to write initial content");
        drop(fd);

        // Re-open with O_APPEND
        let mut fd = fs
            .open(user, path, OFlags::WRONLY | OFlags::APPEND, Mode::empty())
            .expect("Failed to open file with O_APPEND");

        // Seek to beginning - this should succeed but writes should still append
        fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
            .expect("Failed to seek to beginning");

        // Write some data - it should go to the end despite the seek
        fs.write(&NoDeviceIo, &mut fd, b"123", None)
            .expect("Failed to write after seek");
        drop(fd);

        // Verify the file content: original data followed by appended data
        let mut fd = fs
            .open(user, path, OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file for reading");
        let mut buffer = vec![0; 20];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(bytes_read, 9);
        assert_eq!(&buffer[..bytes_read], b"ABCDEF123");
        drop(fd);
    }

    #[test]
    fn o_append_flag_with_rdwr() {
        use crate::fs::SeekWhence;

        let user = USER;

        let fs = super::in_mem_fs();

        with_root_privileges(&fs, |fs, user| {
            fs.chmod(user, "/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });

        // Create a file with initial content
        let path = "/testfile";
        let mut fd = fs
            .open(user, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        fs.write(&NoDeviceIo, &mut fd, b"Hello", None)
            .expect("Failed to write initial content");
        drop(fd);

        // Re-open with O_RDWR | O_APPEND
        let mut fd = fs
            .open(user, path, OFlags::RDWR | OFlags::APPEND, Mode::empty())
            .expect("Failed to open file with O_RDWR | O_APPEND");

        // Read should work normally from the beginning
        let mut buffer = vec![0; 10];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(bytes_read, 5);
        assert_eq!(&buffer[..bytes_read], b"Hello");

        // Seek to beginning - write should still append despite position being at 0
        fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
            .expect("Seek failed");

        // Write should append to end, ignoring the current position
        fs.write(&NoDeviceIo, &mut fd, b" World", None)
            .expect("Failed to write with append");

        // Seek to beginning and read the whole file
        fs.seek(&mut fd, 0, SeekWhence::RelativeToBeginning)
            .expect("Seek failed");
        let mut buffer = vec![0; 20];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(bytes_read, 11);
        assert_eq!(&buffer[..bytes_read], b"Hello World");
        drop(fd);
    }

    #[test]
    fn o_append_pwrite_ignores_append_mode() {
        let user = USER;

        let fs = super::in_mem_fs();

        with_root_privileges(&fs, |fs, user| {
            fs.chmod(user, "/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });

        // Create a file with initial content
        let path = "/testfile";
        let mut fd = fs
            .open(user, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        fs.write(&NoDeviceIo, &mut fd, b"ABCDEF", None)
            .expect("Failed to write initial content");
        drop(fd);

        // Re-open with O_APPEND
        let mut fd = fs
            .open(user, path, OFlags::WRONLY | OFlags::APPEND, Mode::empty())
            .expect("Failed to open file with O_APPEND");

        // pwrite (write with explicit offset) should ignore O_APPEND per POSIX
        fs.write(&NoDeviceIo, &mut fd, b"XX", Some(2))
            .expect("Failed to pwrite");
        drop(fd);

        // Verify the file content: XX should be at position 2, not appended
        let mut fd = fs
            .open(user, path, OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file for reading");
        let mut buffer = vec![0; 10];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(bytes_read, 6);
        assert_eq!(&buffer[..bytes_read], b"ABXXEF");
        drop(fd);
    }

    #[test]
    fn o_append_with_trunc() {
        let user = USER;

        let fs = super::in_mem_fs();

        with_root_privileges(&fs, |fs, user| {
            fs.chmod(user, "/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });

        // Create a file with initial content
        let path = "/testfile";
        let mut fd = fs
            .open(user, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        fs.write(&NoDeviceIo, &mut fd, b"Original content", None)
            .expect("Failed to write initial content");
        drop(fd);

        // Re-open with O_TRUNC | O_APPEND
        let mut fd = fs
            .open(
                user,
                path,
                OFlags::WRONLY | OFlags::TRUNC | OFlags::APPEND,
                Mode::empty(),
            )
            .expect("Failed to open file with O_TRUNC | O_APPEND");

        // File should be truncated, then write should append (to empty file)
        fs.write(&NoDeviceIo, &mut fd, b"New", None)
            .expect("Failed to write after truncation");
        fs.write(&NoDeviceIo, &mut fd, b"Content", None)
            .expect("Failed to write second chunk");
        drop(fd);

        // Verify the file content
        let mut fd = fs
            .open(user, path, OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file for reading");
        let mut buffer = vec![0; 20];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(bytes_read, 10);
        assert_eq!(&buffer[..bytes_read], b"NewContent");
        drop(fd);
    }
}

mod tar_ro {
    use super::USER;
    use crate::fs::backend::NoDeviceIo;
    use crate::fs::{Mode, OFlags};
    use alloc::vec;
    use alloc::vec::Vec;
    extern crate std;

    const TEST_TAR_FILE: &[u8] = include_bytes!("./test.tar");

    #[test]
    fn file_read() {
        let user = USER;

        let fs = super::tar_ro_fs(TEST_TAR_FILE.into());
        let mut fd = fs
            .open(user, "foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"testfoo\n");
        drop(fd);
        let mut fd = fs
            .open(user, "bar/baz", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test bar baz\n");
        drop(fd);
    }

    #[test]
    fn dir_and_nonexist_checks() {
        let user = USER;

        let fs = super::tar_ro_fs(TEST_TAR_FILE.into());
        assert!(matches!(
            fs.open(user, "bar/ba", OFlags::RDONLY, Mode::empty()),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::NoSuchFileOrDirectory
            )),
        ));
        let fd = fs
            .open(user, "bar", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open dir");
        drop(fd);
    }

    #[test]
    fn o_directory_flag_tests() {
        let user = USER;

        let fs = super::tar_ro_fs(TEST_TAR_FILE.into());

        // Test O_DIRECTORY on a directory (should succeed)
        let fd = fs
            .open(
                user,
                "bar",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .expect("Failed to open directory with O_DIRECTORY");
        drop(fd);

        // Test O_DIRECTORY on a regular file (should fail)
        assert!(matches!(
            fs.open(
                user,
                "foo",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::ComponentNotADirectory
            ))
        ));

        // Test O_DIRECTORY on non-existent path (should fail)
        assert!(matches!(
            fs.open(
                user,
                "nonexistent",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::NoSuchFileOrDirectory
            ))
        ));

        // Test O_DIRECTORY on nested file (should fail)
        assert!(matches!(
            fs.open(
                user,
                "bar/baz",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::ComponentNotADirectory
            ))
        ));
    }

    #[test]
    fn write_or_truncate_open_of_directory_fails() {
        let user = USER;

        let fs = super::tar_ro_fs(TEST_TAR_FILE.into());

        for flags in [OFlags::WRONLY, OFlags::RDWR, OFlags::TRUNC] {
            assert!(matches!(
                fs.open(user, "bar", flags, Mode::empty()),
                Err(crate::fs::errors::OpenError::ReadOnlyFileSystem)
            ));
        }
    }

    #[test]
    fn read_dir_subdirectory() {
        let user = USER;

        let fs = super::tar_ro_fs(TEST_TAR_FILE.into());

        // Read root directory
        let fd = fs
            .open(user, "/", OFlags::RDONLY, Mode::empty())
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
                    assert_eq!(entry.file_type, crate::fs::FileType::RegularFile);
                }
                "bar" | "." | ".." => assert_eq!(entry.file_type, crate::fs::FileType::Directory),
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
            .open(user, "bar", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open bar directory");
        let entries = fs.read_dir(&fd).expect("Failed to read bar directory");
        drop(fd);

        // Should have 3 entry: ., .., baz (file)
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].name, "baz");
        assert_eq!(entries[2].file_type, crate::fs::FileType::RegularFile);
    }

    #[test]
    fn read_dir_file_not_directory() {
        let user = USER;

        let fs = super::tar_ro_fs(TEST_TAR_FILE.into());

        let fd = fs
            .open(user, "foo", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open foo file");
        let result = fs.read_dir(&fd);
        drop(fd);

        assert!(matches!(
            result,
            Err(crate::fs::errors::ReadDirError::NotADirectory)
        ));
    }
}

mod overlay {
    use super::USER;
    use crate::fs::backend::NoDeviceIo;
    use crate::fs::in_mem::{InMem, InitialNode};
    use crate::fs::{FileType, Mode, OFlags, UserInfo};
    use crate::test_platform::TestPlatform;
    use alloc::vec;
    use alloc::vec::Vec;
    extern crate std;

    const TEST_TAR_FILE: &[u8] = include_bytes!("./test.tar");

    /// The user these tests act as, and so the owner of anything they are set up as having created.
    const ACTING_USER: UserInfo = UserInfo {
        user: 1000,
        group: 1000,
    };
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

    fn overlay_fs(upper: InMem<TestPlatform>) -> super::OverlayFs {
        super::overlay_fs(upper, TEST_TAR_FILE.into())
    }

    #[test]
    fn file_read_from_lower() {
        let user = USER;

        let fs = overlay_fs(upper([]));
        let mut fd = fs
            .open(user, "foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"testfoo\n");
        let stat = fs.handle_status(&fd).expect("Failed to fd file stat");
        assert_eq!(stat.file_type, FileType::RegularFile);
        assert_eq!(stat.mode, Mode::from_bits(0o644).unwrap());
        drop(fd);

        let stat = fs.file_status(user, "bar").expect("Failed to file stat");
        assert_eq!(stat.file_type, FileType::Directory);
        assert_eq!(stat.mode, Mode::from_bits(0o777).unwrap());

        let mut fd = fs
            .open(user, "bar/baz", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test bar baz\n");
        let stat = fs.handle_status(&fd).expect("Failed to fd file stat");
        assert_eq!(stat.file_type, FileType::RegularFile);
        assert_eq!(stat.mode, Mode::from_bits(0o644).unwrap());
        drop(fd);
    }

    #[test]
    fn dir_and_nonexist_checks() {
        let user = USER;

        let fs = overlay_fs(upper([]));
        assert!(matches!(
            fs.open(user, "bar/ba", OFlags::RDONLY, Mode::empty()),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::NoSuchFileOrDirectory
            )),
        ));
        let fd = fs
            .open(user, "bar", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open dir");
        drop(fd);
    }

    /// Check that for the same file, even though it started as a lower file, writing to it copies
    /// it up and redirects handles already open on it, so every descriptor sees the update.
    #[test]
    fn file_read_write_copy_up() {
        let user = USER;

        let fs = overlay_fs(upper([]));
        let mut fd1 = fs
            .open(user, "foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut fd2 = fs
            .open(user, "foo", OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to open file");

        let mut buffer = vec![0; 1024];

        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd1, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"testfoo\n");

        fs.write(&NoDeviceIo, &mut fd2, b"share", None)
            .expect("Failed to write to file");

        fs.seek(&mut fd1, 0, crate::fs::SeekWhence::RelativeToBeginning)
            .expect("Failed to seek to start");
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd1, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"shareoo\n");

        drop(fd1);
        drop(fd2);
    }

    /// Similar to [`file_read_write_copy_up`] but also confirm that file positions have been
    /// maintained.
    #[test]
    fn file_read_write_copy_up_keeps_position() {
        let user = USER;

        let fs = overlay_fs(upper([]));
        let mut fd1 = fs
            .open(user, "foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut fd2 = fs
            .open(user, "foo", OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to open file");

        let mut buffer = vec![0; 4];

        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd1, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test");

        fs.write(&NoDeviceIo, &mut fd2, b"share", None)
            .expect("Failed to write to file");

        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd1, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"eoo\n");

        drop(fd1);
        drop(fd2);
    }

    #[test]
    fn file_deletion() {
        let user = USER;

        let fs = overlay_fs(upper([]));
        let mut fd = fs
            .open(user, "foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");

        let mut buffer = vec![0; 4];

        // The file exists, and is readable
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test");

        // Then we delete it
        fs.unlink(user, "foo").unwrap();

        // This should not really impact the readability; file is fine.
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"foo\n");

        // But if we close and attempt to re-open, it should not exist
        drop(fd);
        assert!(matches!(
            fs.open(user, "foo", OFlags::RDONLY, Mode::empty()),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::NoSuchFileOrDirectory
            )),
        ));
    }

    #[test]
    fn o_directory_flag_tests() {
        let user = USER;

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
        let fd = fs
            .open(
                user,
                "bar",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .expect("Failed to open lower layer directory with O_DIRECTORY");
        drop(fd);

        // Test O_DIRECTORY on directory from upper layer (in_mem)
        let fd = fs
            .open(
                user,
                "/upperdir",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .expect("Failed to open upper layer directory with O_DIRECTORY");
        drop(fd);

        // Test O_DIRECTORY on file from lower layer (should fail)
        assert!(matches!(
            fs.open(
                user,
                "foo",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::ComponentNotADirectory
            ))
        ));

        // Test O_DIRECTORY on file from upper layer (should fail)
        assert!(matches!(
            fs.open(
                user,
                "/upperfile",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::ComponentNotADirectory
            ))
        ));

        // Test O_DIRECTORY on nested file from lower layer (should fail)
        assert!(matches!(
            fs.open(
                user,
                "bar/baz",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::ComponentNotADirectory
            ))
        ));

        // Test O_DIRECTORY on non-existent path (should fail)
        assert!(matches!(
            fs.open(
                user,
                "nonexistent",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty()
            ),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::NoSuchFileOrDirectory
            ))
        ));
    }

    #[test]
    // Regression test for #250: a file that already exists in the lower layer should not be
    // shadowed by an attempt to create a file.
    fn file_create_exist_in_lower() {
        let user = USER;

        let fs = overlay_fs(upper([]));
        let mut fd = fs
            .open(user, "foo", OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
            .expect("Failed to open file");
        let mut buffer = vec![0; 4];

        // The file exists, and is readable
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test");
    }

    #[test]
    fn read_dir_from_lower_layer() {
        let user = USER;

        let fs = overlay_fs(upper([]));

        // Read bar subdirectory
        let fd = fs
            .open(user, "bar", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open bar directory");
        let entries = fs.read_dir(&fd).expect("Failed to read bar directory");
        drop(fd);

        // Should have 3 entries: ., .., baz (file)
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].name, "baz");
        assert_eq!(entries[2].file_type, crate::fs::FileType::RegularFile);
        assert!(
            entries[2].ino_info.is_some(),
            "Inode info should be present"
        );
    }

    #[test]
    fn read_dir_from_upper_layer() {
        let user = USER;

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
            .open(user, "/", OFlags::RDONLY, Mode::empty())
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
                    assert_eq!(entry.file_type, crate::fs::FileType::RegularFile);
                }
                "bar" | "upperdir" | "." | ".." => {
                    assert_eq!(entry.file_type, crate::fs::FileType::Directory);
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
            .open(user, "/upperdir", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open upperdir");
        let entries = fs.read_dir(&fd).expect("Failed to read upperdir");
        drop(fd);

        // only . and ..
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn o_excl_tests() {
        let user = USER;

        let fs = overlay_fs(upper([]));

        // Test O_CREAT | O_EXCL on file that exists in lower layer (should fail)
        // "foo" exists in the tar file
        assert!(matches!(
            fs.open(
                user,
                "foo",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            ),
            Err(crate::fs::errors::OpenError::AlreadyExists)
        ));

        // Test O_CREAT | O_EXCL on file that doesn't exist anywhere (should succeed)
        let mut fd = fs
            .open(
                user,
                "/newfile",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create new file with O_CREAT | O_EXCL");

        fs.write(&NoDeviceIo, &mut fd, b"overlay test", None)
            .expect("Failed to write to new file");
        drop(fd);

        // Test O_CREAT | O_EXCL on file that now exists in upper layer (should fail)
        assert!(matches!(
            fs.open(
                user,
                "/newfile",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            ),
            Err(crate::fs::errors::OpenError::AlreadyExists)
        ));

        // Test O_CREAT | O_EXCL on directory that exists in lower layer (should fail)
        // "bar" is a directory in the tar file
        assert!(matches!(
            fs.open(
                user,
                "bar",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            ),
            Err(crate::fs::errors::OpenError::AlreadyExists)
        ));

        // Test O_CREAT | O_EXCL on file that was deleted (tombstoned) should succeed
        // First delete a file from lower layer
        fs.unlink(user, "foo")
            .expect("Failed to unlink lower layer file");

        // Now try to create it with O_EXCL (should succeed since it's tombstoned)
        let mut fd = fs
            .open(
                user,
                "foo",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create file over tombstone with O_CREAT | O_EXCL");

        fs.write(&NoDeviceIo, &mut fd, b"new foo content", None)
            .expect("Failed to write to recreated file");
        drop(fd);

        // Verify the new content
        let mut fd = fs
            .open(user, "foo", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open recreated file");
        let mut buffer = vec![0; 15];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from recreated file");
        assert_eq!(&buffer[..bytes_read], b"new foo content");
        drop(fd);

        // Test O_CREAT | O_EXCL behavior with existing upper layer file
        // Create a file in upper layer first
        let mut fd = fs
            .open(
                user,
                "/upper_only_file",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU,
            )
            .expect("Failed to create upper layer file");
        fs.write(&NoDeviceIo, &mut fd, b"upper content", None)
            .expect("Failed to write to upper layer file");
        drop(fd);

        // Now try O_CREAT | O_EXCL on the same file (should fail)
        assert!(matches!(
            fs.open(
                user,
                "/upper_only_file",
                OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                Mode::RWXU,
            ),
            Err(crate::fs::errors::OpenError::AlreadyExists)
        ));
    }

    #[test]
    fn dir_creation_inside_lower_existing_dir() {
        let user = USER;

        let fs = overlay_fs(upper([]));

        // Create the directory /bar/test (where /bar already exists inside the tar file)
        fs.mkdir(user, "/bar/test", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to create /bar/test directory");

        // Verify the directory was created
        let stat = fs
            .file_status(user, "/bar/test")
            .expect("Failed to get status of /bar/test");
        assert_eq!(stat.file_type, FileType::Directory);

        // Verify we can open the directory
        let fd = fs
            .open(user, "/bar/test", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open /bar/test directory");
        let entries = fs
            .read_dir(&fd)
            .expect("Failed to read /bar/test directory");
        drop(fd);

        // Should contain only . and .. entries
        assert_eq!(entries.len(), 2);
        let mut names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec![".", ".."]);
    }

    #[test]
    fn file_creation_materializes_ancestor_dirs() {
        let user = USER;

        let fs = overlay_fs(upper([]));

        // Open bar/test for writing (where bar exists in lower layer but test doesn't exist)
        // This should create ancestor directories and allow file creation
        let mut fd = fs
            .open(user, "bar/test", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to open bar/test for writing");

        // Write data to the file
        let data = b"Hello from nested file!";
        fs.write(&NoDeviceIo, &mut fd, data, None)
            .expect("Failed to write to bar/test");
        drop(fd);

        // Read the file back
        let mut fd = fs
            .open(user, "bar/test", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open bar/test for reading");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from bar/test");
        assert_eq!(&buffer[..bytes_read], data);
        drop(fd);

        // Verify the file exists and has correct type
        let stat = fs
            .file_status(user, "bar/test")
            .expect("Failed to get status of bar/test");
        assert_eq!(stat.file_type, FileType::RegularFile);
    }

    #[test]
    fn file_modification_materializes_ancestor_dirs() {
        let user = USER;

        let fs = overlay_fs(upper([]));

        // Open bar/baz for writing (both bar and baz exist in lower layer)
        // This copies up the ancestor directories and allows the file to be modified
        let mut fd = fs
            .open(user, "bar/baz", OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to open bar/baz for writing");

        // Write new data to the file (overwriting existing content)
        let data = b"Modified content!";
        fs.write(&NoDeviceIo, &mut fd, data, None)
            .expect("Failed to write to bar/baz");
        drop(fd);

        // Read the file back to verify it was modified
        let mut fd = fs
            .open(user, "bar/baz", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open bar/baz for reading");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read from bar/baz");

        assert_eq!(&buffer[..bytes_read], data);
        drop(fd);

        // Verify the file still exists and has correct type
        let stat = fs
            .file_status(user, "bar/baz")
            .expect("Failed to get status of bar/baz");
        assert_eq!(stat.file_type, FileType::RegularFile);
    }

    #[test]
    fn open_with_trunc() {
        let user = USER;

        let fs = overlay_fs(upper([]));

        // Open with O_TRUNC should copy the file up into the upper backend, empty
        let mut fd = fs
            .open(user, "foo", OFlags::RDWR | OFlags::TRUNC, Mode::empty())
            .expect("Failed to open file with O_TRUNC");

        // File should be truncated (empty)
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read file");
        assert_eq!(bytes_read, 0);

        // Write new content
        fs.write(&NoDeviceIo, &mut fd, b"new content", None)
            .expect("Failed to write to file");
        drop(fd);

        // Verify the content persists
        let mut fd = fs
            .open(user, "foo", OFlags::RDONLY, Mode::empty())
            .expect("Failed to reopen file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&NoDeviceIo, &mut fd, &mut buffer, None)
            .expect("Failed to read file");
        assert_eq!(&buffer[..bytes_read], b"new content");
        drop(fd);
    }

    #[test]
    fn rmdir_upper_only_directory() {
        use crate::fs::errors::{PathError, RmdirError};

        let user = USER;

        let fs = overlay_fs(upper([]));

        // Create an empty directory only in upper layer
        fs.mkdir(user, "/upper_empty", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("mkdir upper_empty failed");

        // Remove it
        fs.rmdir(user, "/upper_empty")
            .expect("rmdir upper_empty should succeed");

        // Verify it no longer exists
        assert!(matches!(
            fs.file_status(user, "/upper_empty"),
            Err(crate::fs::errors::FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory
            ))
        ));

        // Second removal should yield NoSuchFileOrDirectory (path error)
        assert!(matches!(
            fs.rmdir(user, "/upper_empty"),
            Err(RmdirError::PathError(PathError::NoSuchFileOrDirectory))
        ));
    }

    #[test]
    fn rmdir_upper_directory_not_empty_then_empty() {
        use crate::fs::errors::{PathError, RmdirError};

        let user = USER;

        let fs = overlay_fs(upper([]));

        fs.mkdir(user, "/upper_dir", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("mkdir upper_dir failed");

        // Create a file inside making directory non-empty
        let fd = fs
            .open(
                user,
                "/upper_dir/file",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU | Mode::RWXG,
            )
            .expect("create file in upper_dir failed");
        drop(fd);

        // Attempt to remove while non-empty
        assert!(matches!(
            fs.rmdir(user, "/upper_dir"),
            Err(RmdirError::NotEmpty)
        ));

        // Remove inner file
        fs.unlink(user, "/upper_dir/file")
            .expect("unlink inner failed");

        // Now should succeed
        fs.rmdir(user, "/upper_dir")
            .expect("rmdir upper_dir should succeed");

        // Confirm gone
        assert!(matches!(
            fs.file_status(user, "/upper_dir"),
            Err(crate::fs::errors::FileStatusError::PathError(
                PathError::NoSuchFileOrDirectory
            ))
        ));
    }

    #[test]
    fn rmdir_lower_directory_non_empty() {
        use crate::fs::errors::RmdirError;

        let user = USER;

        let fs = overlay_fs(upper([]));

        // "bar" exists in lower layer and contains "baz" (non-empty)
        assert!(matches!(fs.rmdir(user, "bar"), Err(RmdirError::NotEmpty)));
    }

    #[test]
    fn rmdir_not_a_directory() {
        use crate::fs::errors::RmdirError;

        let user = USER;

        let fs = overlay_fs(upper([]));

        // Create a regular file (upper only)
        let fd = fs
            .open(
                user,
                "/regular_file",
                OFlags::CREAT | OFlags::WRONLY,
                Mode::RWXU | Mode::RWXG,
            )
            .expect("create file failed");
        drop(fd);

        // rmdir should fail with NotADirectory
        assert!(matches!(
            fs.rmdir(user, "/regular_file"),
            Err(RmdirError::NotADirectory)
        ));
    }

    #[test]
    fn copy_up_does_not_deadlock() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let user = USER;

        let fs = overlay_fs(upper([]));

        fs.file_status(user, "foo").expect("Failed to stat foo");

        // Writing to the lower-layer file triggers copy-up. Run it on a worker thread.
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut fd = fs
                .open(user, "foo", OFlags::WRONLY, Mode::RWXU)
                .expect("Failed to open file for writing");
            fs.write(&NoDeviceIo, &mut fd, b"x", None)
                .expect("Failed to write to file");
            drop(fd);
            let _ = tx.send(());
        });

        rx.recv_timeout(Duration::from_secs(2))
            .expect("copy-up deadlocked");
    }
}
