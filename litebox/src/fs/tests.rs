mod in_mem {
    use crate::LiteBox;
    use crate::fs::in_mem;
    use crate::fs::{FileSystem as _, Mode, OFlags};
    use crate::platform::mock::MockPlatform;
    use alloc::vec;
    use alloc::vec::Vec;
    extern crate std;

    #[test]
    fn root_file_creation_and_deletion() {
        let litebox = LiteBox::new(MockPlatform::new());

        in_mem::FileSystem::new(&litebox).with_root_privileges(|fs| {
            // Test file creation
            let path = "/testfile";
            let fd = fs
                .open(path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .expect("Failed to create file");

            fs.close(fd).expect("Failed to close file");

            // Test file deletion
            fs.unlink(path).expect("Failed to unlink file");
            assert!(
                fs.open(path, OFlags::RDONLY, Mode::RWXU).is_err(),
                "File should not exist"
            );
        });
    }

    #[test]
    fn root_file_read_write() {
        let litebox = LiteBox::new(MockPlatform::new());

        in_mem::FileSystem::new(&litebox).with_root_privileges(|fs| {
            // Create and write to a file
            let path = "/testfile";
            let fd = fs
                .open(path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .expect("Failed to create file");
            let data = b"Hello, world!";
            fs.write(&fd, data, None).expect("Failed to write to file");
            fs.close(fd).expect("Failed to close file");

            // Read from the file
            let fd = fs
                .open(path, OFlags::RDONLY, Mode::RWXU)
                .expect("Failed to open file");
            let mut buffer = vec![0; data.len()];
            let bytes_read = fs
                .read(&fd, &mut buffer, None)
                .expect("Failed to read from file");
            assert_eq!(bytes_read, data.len());
            assert_eq!(&buffer, data);
            fs.close(fd).expect("Failed to close file");
        });
    }

    #[test]
    fn root_directory_creation_and_removal() {
        let litebox = LiteBox::new(MockPlatform::new());

        in_mem::FileSystem::new(&litebox).with_root_privileges(|fs| {
            // Test directory creation
            let path = "/testdir";
            fs.mkdir(path, Mode::RWXU)
                .expect("Failed to create directory");

            // Test directory removal
            fs.rmdir(path).expect("Failed to remove directory");
            assert!(
                fs.open(path, OFlags::RDONLY, Mode::RWXU).is_err(),
                "Directory should not exist"
            );
        });
    }

    #[test]
    fn file_creation_and_deletion() {
        let litebox = LiteBox::new(MockPlatform::new());
        let mut fs = in_mem::FileSystem::new(&litebox);
        fs.with_root_privileges(|fs| {
            // Make `/tmp` and set up with reasonable privs so normal users can do things in there.
            fs.mkdir("/tmp", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to create /tmp");
        });

        // Test file creation
        let path = "/tmp/testfile";
        let fd = fs
            .open(path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");

        fs.close(fd).expect("Failed to close file");

        // Test file deletion
        fs.unlink(path).expect("Failed to unlink file");
        assert!(
            fs.open(path, OFlags::RDONLY, Mode::RWXU).is_err(),
            "File should not exist"
        );
    }

    #[test]
    fn file_read_write() {
        let litebox = LiteBox::new(MockPlatform::new());
        let mut fs = in_mem::FileSystem::new(&litebox);
        fs.with_root_privileges(|fs| {
            // Make `/tmp` and set up with reasonable privs so normal users can do things in there.
            fs.mkdir("/tmp", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to create /tmp");
        });

        // Create and write to a file
        let path = "/tmp/testfile";
        let fd = fs
            .open(path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        let data = b"Hello, world!";
        fs.write(&fd, data, None).expect("Failed to write to file");
        fs.write(&fd, &data[2..], Some(2))
            .expect("Failed to write to file with offset");
        fs.close(fd).expect("Failed to close file");

        // Read from the file
        let fd = fs
            .open(path, OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut buffer = vec![0; data.len()];
        let bytes_read = fs
            .read(&fd, &mut buffer, None)
            .expect("Failed to read from file");
        let bytes_read2 = fs
            .read(&fd, &mut buffer[2..], Some(2))
            .expect("Failed to read from file with offset");
        assert_eq!(bytes_read, data.len());
        assert_eq!(bytes_read2, data.len() - 2);
        assert_eq!(&buffer, data);
        fs.close(fd).expect("Failed to close file");
    }

    #[test]
    fn directory_creation_and_removal() {
        let litebox = LiteBox::new(MockPlatform::new());
        let mut fs = in_mem::FileSystem::new(&litebox);
        fs.with_root_privileges(|fs| {
            // Make `/tmp` and set up with reasonable privs so normal users can do things in there.
            fs.mkdir("/tmp", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to create /tmp");
        });

        // Test directory creation
        let path = "/tmp/testdir";
        fs.mkdir(path, Mode::RWXU)
            .expect("Failed to create directory");

        // Test directory removal
        fs.rmdir(path).expect("Failed to remove directory");
        assert!(
            fs.open(path, OFlags::RDONLY, Mode::RWXU).is_err(),
            "Directory should not exist"
        );
    }

    #[test]
    fn read_dir_empty() {
        let litebox = LiteBox::new(MockPlatform::new());

        in_mem::FileSystem::new(&litebox).with_root_privileges(|fs| {
            let fd = fs
                .open("/", OFlags::RDONLY, Mode::empty())
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
            fs.close(fd).expect("Failed to close directory");
        });
    }

    #[test]
    fn read_dir_with_files_and_dirs() {
        let litebox = LiteBox::new(MockPlatform::new());

        in_mem::FileSystem::new(&litebox).with_root_privileges(|fs| {
            // Create a directory structure
            fs.mkdir("/testdir", Mode::RWXU)
                .expect("Failed to create directory");
            let fd1 = fs
                .open("/testfile1", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .expect("Failed to create file1");
            fs.close(fd1).expect("Failed to close file1");
            let fd2 = fs
                .open("/testfile2", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .expect("Failed to create file2");
            fs.close(fd2).expect("Failed to close file2");

            // Read root directory
            let fd = fs
                .open("/", OFlags::RDONLY, Mode::empty())
                .expect("Failed to open root directory");
            let entries = fs.read_dir(&fd).expect("Failed to read directory");
            fs.close(fd).expect("Failed to close directory");

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
                assert!(entry.ino_info.is_some(), "Inode info should be present");
            }

            // Read the subdirectory (should be empty)
            let fd = fs
                .open("/testdir", OFlags::RDONLY, Mode::empty())
                .expect("Failed to open subdirectory");
            let entries = fs
                .read_dir(&fd)
                .expect("Failed to read subdirectory")
                .iter()
                .map(|e| e.name.clone())
                .collect::<Vec<_>>();
            assert!(entries.len() == 2, "Subdirectory should contain . and ..");
            fs.close(fd).expect("Failed to close subdirectory");
        });
    }

    #[test]
    fn read_dir_file_not_directory() {
        let litebox = LiteBox::new(MockPlatform::new());

        in_mem::FileSystem::new(&litebox).with_root_privileges(|fs| {
            // Create a file
            let fd = fs
                .open("/testfile", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .expect("Failed to create file");
            fs.close(fd).expect("Failed to close file");

            // Try to read_dir on the file (should fail)
            let fd = fs
                .open("/testfile", OFlags::RDONLY, Mode::empty())
                .expect("Failed to open file");
            let result = fs.read_dir(&fd);
            fs.close(fd).expect("Failed to close file");

            assert!(matches!(
                result,
                Err(crate::fs::errors::ReadDirError::NotADirectory)
            ));
        });
    }

    #[test]
    fn chown_test() {
        let litebox = LiteBox::new(MockPlatform::new());
        let mut fs = in_mem::FileSystem::new(&litebox);

        // Create a test file as root
        fs.with_root_privileges(|fs| {
            let path = "/testfile";
            let fd = fs
                .open(path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .expect("Failed to create file");
            fs.close(fd).expect("Failed to close file");

            // First chown to 1000:1000 as root (should succeed)
            fs.chown(path, Some(1000), Some(1000))
                .expect("Failed to chown as root");
        });

        // Switch to user 1000 and test that owner can chown (should succeed)
        let path = "/testfile";
        fs.with_user(1000, 1000, |fs| {
            fs.chown(path, Some(123), Some(456))
                .expect("Failed to chown as owner");
        });

        // Switch to a different user and test that non-owner cannot chown (should fail)
        fs.with_user(500, 500, |fs| {
            match fs.chown(path, Some(789), Some(101)) {
                Err(crate::fs::errors::ChownError::NotTheOwner) => {
                    // Expected behavior
                }
                Ok(()) => panic!("Non-owner should not be able to chown"),
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        });

        // Test chown on non-existent file (should fail)
        match fs.chown("/nonexistent", Some(123), Some(456)) {
            Err(crate::fs::errors::ChownError::PathError(
                crate::fs::errors::PathError::NoSuchFileOrDirectory,
            )) => {
                // Expected behavior
            }
            Ok(()) => panic!("Should not be able to chown non-existent file"),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }

        // Test partial chown (change only user, leave group unchanged)
        fs.with_root_privileges(|fs| {
            fs.chown(path, Some(999), None)
                .expect("Failed to chown user only");
        });

        // Test partial chown (change only group, leave user unchanged)
        fs.with_root_privileges(|fs| {
            fs.chown(path, None, Some(888))
                .expect("Failed to chown group only");
        });
    }

    #[test]
    fn o_directory_flag_tests() {
        let litebox = LiteBox::new(MockPlatform::new());
        let mut fs = in_mem::FileSystem::new(&litebox);

        fs.with_root_privileges(|fs| {
            fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });
        // Create test directory and file
        fs.mkdir("/testdir", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to create directory");

        let fd = fs
            .open("/testfile", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        fs.close(fd).expect("Failed to close file");

        // Test O_DIRECTORY on a directory (should succeed)
        let fd = fs
            .open(
                "/testdir",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .expect("Failed to open directory with O_DIRECTORY");
        fs.close(fd).expect("Failed to close directory");

        // Test O_DIRECTORY on a regular file (should fail)
        assert!(matches!(
            fs.open(
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
                "/newfile",
                OFlags::CREAT | OFlags::WRONLY | OFlags::DIRECTORY,
                Mode::RWXU,
            )
            .expect("Failed to create file with O_CREAT | O_DIRECTORY");
        fs.close(fd).expect("Failed to close file");

        // Verify it created a regular file, not a directory
        let stat = fs
            .file_status("/newfile")
            .expect("Failed to get file status");
        assert_eq!(stat.file_type, crate::fs::FileType::RegularFile);

        // Test O_DIRECTORY with various access modes
        let fd = fs
            .open("/testdir", OFlags::RDWR | OFlags::DIRECTORY, Mode::empty())
            .expect("Failed to open directory with O_RDWR | O_DIRECTORY");
        fs.close(fd).expect("Failed to close directory");
    }
}

mod tar_ro {
    use crate::LiteBox;
    use crate::fs::tar_ro;
    use crate::fs::{FileSystem as _, Mode, OFlags};
    use crate::platform::mock::MockPlatform;
    use alloc::vec;
    use alloc::vec::Vec;
    extern crate std;

    const TEST_TAR_FILE: &[u8] = include_bytes!("./test.tar");

    #[test]
    fn file_read() {
        let litebox = LiteBox::new(MockPlatform::new());
        let fs = tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into());
        let fd = fs
            .open("foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"testfoo\n");
        fs.close(fd).expect("Failed to close file");
        let fd = fs
            .open("bar/baz", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test bar baz\n");
        fs.close(fd).expect("Failed to close file");
    }

    #[test]
    fn dir_and_nonexist_checks() {
        let litebox = LiteBox::new(MockPlatform::new());
        let fs = tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into());
        assert!(matches!(
            fs.open("bar/ba", OFlags::RDONLY, Mode::empty()),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::NoSuchFileOrDirectory
            )),
        ));
        let fd = fs
            .open("bar", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open dir");
        fs.close(fd).expect("Failed to close dir");
    }

    #[test]
    fn o_directory_flag_tests() {
        let litebox = LiteBox::new(MockPlatform::new());
        let fs = tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into());

        // Test O_DIRECTORY on a directory (should succeed)
        let fd = fs
            .open("bar", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
            .expect("Failed to open directory with O_DIRECTORY");
        fs.close(fd).expect("Failed to close directory");

        // Test O_DIRECTORY on a regular file (should fail)
        assert!(matches!(
            fs.open("foo", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::ComponentNotADirectory
            ))
        ));

        // Test O_DIRECTORY on non-existent path (should fail)
        assert!(matches!(
            fs.open(
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
            fs.open("bar/baz", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::ComponentNotADirectory
            ))
        ));
    }

    #[test]
    fn read_dir_subdirectory() {
        let litebox = LiteBox::new(MockPlatform::new());
        let fs = tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into());

        // Read root directory
        let fd = fs
            .open("/", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open root directory");
        let entries = fs.read_dir(&fd).expect("Failed to read root directory");
        fs.close(fd).expect("Failed to close root directory");

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
            assert!(entry.ino_info.is_some(), "Inode info should be present");
        }

        // Read `bar` directory
        let fd = fs
            .open("bar", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open bar directory");
        let entries = fs.read_dir(&fd).expect("Failed to read bar directory");
        fs.close(fd).expect("Failed to close bar directory");

        // Should have 3 entry: ., .., baz (file)
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].name, "baz");
        assert_eq!(entries[2].file_type, crate::fs::FileType::RegularFile);
    }

    #[test]
    fn read_dir_file_not_directory() {
        let litebox = LiteBox::new(MockPlatform::new());
        let fs = tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into());

        let fd = fs
            .open("foo", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open foo file");
        let result = fs.read_dir(&fd);
        fs.close(fd).expect("Failed to close foo file");

        assert!(matches!(
            result,
            Err(crate::fs::errors::ReadDirError::NotADirectory)
        ));
    }
}

mod layered {
    use crate::LiteBox;
    use crate::fs::{FileSystem as _, FileType, Mode, OFlags};
    use crate::fs::{in_mem, layered, tar_ro};
    use crate::platform::mock::MockPlatform;
    use alloc::vec;
    use alloc::vec::Vec;
    extern crate std;

    const TEST_TAR_FILE: &[u8] = include_bytes!("./test.tar");

    #[test]
    fn file_read_from_lower() {
        let litebox = LiteBox::new(MockPlatform::new());
        let fs = layered::FileSystem::new(
            &litebox,
            in_mem::FileSystem::new(&litebox),
            tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into()),
            layered::LayeringSemantics::LowerLayerReadOnly,
        );
        let fd = fs
            .open("foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"testfoo\n");
        let stat = fs.fd_file_status(&fd).expect("Failed to fd file stat");
        assert_eq!(stat.file_type, FileType::RegularFile);
        assert_eq!(stat.mode, Mode::from_bits(0o644).unwrap());
        fs.close(fd).expect("Failed to close file");

        let stat = fs.file_status("bar").expect("Failed to file stat");
        assert_eq!(stat.file_type, FileType::Directory);
        assert_eq!(stat.mode, Mode::from_bits(0o777).unwrap());

        let fd = fs
            .open("bar/baz", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open file");
        let mut buffer = vec![0; 1024];
        let bytes_read = fs
            .read(&fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test bar baz\n");
        let stat = fs.fd_file_status(&fd).expect("Failed to fd file stat");
        assert_eq!(stat.file_type, FileType::RegularFile);
        assert_eq!(stat.mode, Mode::from_bits(0o644).unwrap());
        fs.close(fd).expect("Failed to close file");
    }

    #[test]
    fn dir_and_nonexist_checks() {
        let litebox = LiteBox::new(MockPlatform::new());
        let fs = layered::FileSystem::new(
            &litebox,
            in_mem::FileSystem::new(&litebox),
            tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into()),
            layered::LayeringSemantics::LowerLayerReadOnly,
        );
        assert!(matches!(
            fs.open("bar/ba", OFlags::RDONLY, Mode::empty()),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::NoSuchFileOrDirectory
            )),
        ));
        let fd = fs
            .open("bar", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open dir");
        fs.close(fd).expect("Failed to close dir");
    }

    /// Check that for the same file, even though it started as a lower-level file, writing to it
    /// successfully migrated it to an upper-level file, and converted the internal descriptors
    /// over, such that the expected semantics of being able to see the updated file are held.
    #[test]
    fn file_read_write_sync_up() {
        let litebox = LiteBox::new(MockPlatform::new());

        let mut in_mem_fs = in_mem::FileSystem::new(&litebox);
        in_mem_fs.with_root_privileges(|fs| {
            // Change the permissions for `/` to allow file creation
            //
            // TODO: We might need to force-allow file creation in cases where the lower level
            // already has the file in the correct mode. This would likely require `stat` as well as
            // some internal-only force-creation API.
            fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });

        let fs = layered::FileSystem::new(
            &litebox,
            in_mem_fs,
            tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into()),
            layered::LayeringSemantics::LowerLayerReadOnly,
        );
        let fd1 = fs
            .open("foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let fd2 = fs
            .open("foo", OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to open file");

        let mut buffer = vec![0; 1024];

        let bytes_read = fs
            .read(&fd1, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"testfoo\n");

        fs.write(&fd2, b"share", None)
            .expect("Failed to write to file");

        fs.seek(&fd1, 0, crate::fs::SeekWhence::RelativeToBeginning)
            .expect("Failed to seek to start");
        let bytes_read = fs
            .read(&fd1, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"shareoo\n");

        fs.close(fd1).expect("Failed to close file");
        fs.close(fd2).expect("Failed to close file");
    }

    /// Similar to [`file_read_write_sync_up`] but also confirm that file positions have been
    /// maintained.
    #[test]
    fn file_read_write_seek_sync() {
        let litebox = LiteBox::new(MockPlatform::new());

        let mut in_mem_fs = in_mem::FileSystem::new(&litebox);
        in_mem_fs.with_root_privileges(|fs| {
            // Change the permissions for `/` to allow file creation
            //
            // TODO: We might need to force-allow file creation in cases where the lower level
            // already has the file in the correct mode. This would likely require `stat` as well as
            // some internal-only force-creation API.
            fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });

        let fs = layered::FileSystem::new(
            &litebox,
            in_mem_fs,
            tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into()),
            layered::LayeringSemantics::LowerLayerReadOnly,
        );
        let fd1 = fs
            .open("foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");
        let fd2 = fs
            .open("foo", OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to open file");

        let mut buffer = vec![0; 4];

        let bytes_read = fs
            .read(&fd1, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test");

        fs.write(&fd2, b"share", None)
            .expect("Failed to write to file");

        let bytes_read = fs
            .read(&fd1, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"eoo\n");

        fs.close(fd1).expect("Failed to close file");
        fs.close(fd2).expect("Failed to close file");
    }

    #[test]
    fn file_deletion() {
        let litebox = LiteBox::new(MockPlatform::new());

        let fs = layered::FileSystem::new(
            &litebox,
            in_mem::FileSystem::new(&litebox),
            tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into()),
            layered::LayeringSemantics::LowerLayerReadOnly,
        );
        let fd = fs
            .open("foo", OFlags::RDONLY, Mode::RWXU)
            .expect("Failed to open file");

        let mut buffer = vec![0; 4];

        // The file exists, and is readable
        let bytes_read = fs
            .read(&fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test");

        // Then we delete it
        fs.unlink("foo").unwrap();

        // This should not really impact the readability; file is fine.
        let bytes_read = fs
            .read(&fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"foo\n");

        // But if we close and attempt to re-open, it should not exist
        fs.close(fd).expect("Failed to close file");
        assert!(matches!(
            fs.open("foo", OFlags::RDONLY, Mode::empty()),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::NoSuchFileOrDirectory
            )),
        ));
    }

    #[test]
    fn o_directory_flag_tests() {
        let litebox = LiteBox::new(MockPlatform::new());
        let mut in_mem_fs = in_mem::FileSystem::new(&litebox);

        in_mem_fs.with_root_privileges(|fs| {
            fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });
        // Create a test directory in the upper layer
        in_mem_fs
            .mkdir("/upperdir", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to create directory");

        // Create a test file in the upper layer
        let fd = in_mem_fs
            .open("/upperfile", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");
        in_mem_fs.close(fd).expect("Failed to close file");

        let fs = layered::FileSystem::new(
            &litebox,
            in_mem_fs,
            tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into()),
            layered::LayeringSemantics::LowerLayerReadOnly,
        );

        // Test O_DIRECTORY on directory from lower layer (tar)
        let fd = fs
            .open("bar", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
            .expect("Failed to open lower layer directory with O_DIRECTORY");
        fs.close(fd).expect("Failed to close directory");

        // Test O_DIRECTORY on directory from upper layer (in_mem)
        let fd = fs
            .open(
                "/upperdir",
                OFlags::RDONLY | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .expect("Failed to open upper layer directory with O_DIRECTORY");
        fs.close(fd).expect("Failed to close directory");

        // Test O_DIRECTORY on file from lower layer (should fail)
        assert!(matches!(
            fs.open("foo", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::ComponentNotADirectory
            ))
        ));

        // Test O_DIRECTORY on file from upper layer (should fail)
        assert!(matches!(
            fs.open(
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
            fs.open("bar/baz", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()),
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::ComponentNotADirectory
            ))
        ));

        // Test O_DIRECTORY on non-existent path (should fail)
        assert!(matches!(
            fs.open(
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
        let litebox = LiteBox::new(MockPlatform::new());

        let mut in_mem_fs = in_mem::FileSystem::new(&litebox);
        in_mem_fs.with_root_privileges(|fs| {
            fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });
        let fs = layered::FileSystem::new(
            &litebox,
            in_mem_fs,
            tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into()),
            layered::LayeringSemantics::LowerLayerReadOnly,
        );
        let fd = fs
            .open("foo", OFlags::RDWR | OFlags::CREAT, Mode::RWXU)
            .expect("Failed to open file");
        let mut buffer = vec![0; 4];

        // The file exists, and is readable
        let bytes_read = fs
            .read(&fd, &mut buffer, None)
            .expect("Failed to read from file");
        assert_eq!(&buffer[..bytes_read], b"test");
    }

    #[test]
    fn read_dir_from_lower_layer() {
        let litebox = LiteBox::new(MockPlatform::new());
        let fs = layered::FileSystem::new(
            &litebox,
            in_mem::FileSystem::new(&litebox),
            tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into()),
            layered::LayeringSemantics::LowerLayerReadOnly,
        );

        // Read bar subdirectory
        let fd = fs
            .open("bar", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open bar directory");
        let entries = fs.read_dir(&fd).expect("Failed to read bar directory");
        fs.close(fd).expect("Failed to close bar directory");

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
        let litebox = LiteBox::new(MockPlatform::new());

        let mut in_mem_fs = in_mem::FileSystem::new(&litebox);
        in_mem_fs.with_root_privileges(|fs| {
            // Set up root directory permissions to allow access
            fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");

            // Create some files in the upper layer
            fs.mkdir("/upperdir", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to create upperdir");
            let fd = fs
                .open("/upperfile", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .expect("Failed to create upperfile");
            fs.close(fd).expect("Failed to close upperfile");
        });

        let fs = layered::FileSystem::new(
            &litebox,
            in_mem_fs,
            tar_ro::FileSystem::new(&litebox, TEST_TAR_FILE.into()),
            layered::LayeringSemantics::LowerLayerReadOnly,
        );

        // Read root directory (should contain entries from both layers)
        let fd = fs
            .open("/", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open root directory");
        let entries = fs.read_dir(&fd).expect("Failed to read root directory");
        fs.close(fd).expect("Failed to close root directory");

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
            assert!(entry.ino_info.is_some(), "Inode info should be present");
        }

        // Read upperdir directory (should be from upper layer)
        let fd = fs
            .open("/upperdir", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open upperdir");
        let entries = fs.read_dir(&fd).expect("Failed to read upperdir");
        fs.close(fd).expect("Failed to close upperdir");

        // only . and ..
        assert!(entries.len() == 2);
    }
}

mod stdio {
    use crate::LiteBox;
    use crate::fs::{FileSystem as _, Mode, OFlags};
    use crate::platform::mock::MockPlatform;
    use alloc::vec;
    extern crate std;

    #[test]
    fn stdio_open_read_write() {
        let platform = MockPlatform::new();
        let litebox = LiteBox::new(platform);
        let fs = crate::fs::devices::stdio::FileSystem::new(&litebox);

        // Test opening and writing to /dev/stdout
        let fd_stdout = fs
            .open("/dev/stdout", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stdout");
        let data = b"Hello, stdout!";
        fs.write(&fd_stdout, data, None)
            .expect("Failed to write to /dev/stdout");
        fs.close(fd_stdout).expect("Failed to close /dev/stdout");
        assert_eq!(platform.stdout_queue.read().unwrap().len(), 1);
        assert_eq!(platform.stdout_queue.read().unwrap()[0], data);

        // Test opening and writing to /dev/stderr
        let fd_stderr = fs
            .open("/dev/stderr", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stderr");
        let data = b"Hello, stderr!";
        fs.write(&fd_stderr, data, None)
            .expect("Failed to write to /dev/stderr");
        fs.close(fd_stderr).expect("Failed to close /dev/stderr");
        assert_eq!(platform.stderr_queue.read().unwrap().len(), 1);
        assert_eq!(platform.stderr_queue.read().unwrap()[0], data);

        // Test opening and reading from /dev/stdin
        platform
            .stdin_queue
            .write()
            .unwrap()
            .push_back(b"Hello, stdin!".to_vec());
        let fd_stdin = fs
            .open("/dev/stdin", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open /dev/stdin");
        let mut buffer = vec![0; 13];
        let bytes_read = fs
            .read(&fd_stdin, &mut buffer, None)
            .expect("Failed to read from /dev/stdin");
        assert_eq!(bytes_read, 13);
        assert_eq!(&buffer, b"Hello, stdin!");
        fs.close(fd_stdin).expect("Failed to close /dev/stdin");
    }

    #[test]
    fn non_dev_path_fails() {
        let litebox = LiteBox::new(MockPlatform::new());
        let fs = crate::fs::devices::stdio::FileSystem::new(&litebox);

        // Attempt to open a non-/dev/* path
        let result = fs.open("foo", OFlags::RDONLY, Mode::empty());
        assert!(matches!(
            result,
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::NoSuchFileOrDirectory
            ))
        ));
    }
}

mod layered_stdio {
    use crate::LiteBox;
    use crate::fs::layered::LayeringSemantics;
    use crate::fs::{FileSystem as _, Mode, OFlags};
    use crate::fs::{devices, in_mem, layered};
    use crate::platform::mock::MockPlatform;
    use alloc::vec;
    extern crate std;

    #[test]
    fn layered_stdio_open_read_write() {
        let platform = MockPlatform::new();
        let litebox = LiteBox::new(platform);
        let layered_fs = layered::FileSystem::new(
            &litebox,
            in_mem::FileSystem::new(&litebox),
            devices::stdio::FileSystem::new(&litebox),
            LayeringSemantics::LowerLayerWritableFiles,
        );

        // Test opening and writing to /dev/stdout
        let fd_stdout = layered_fs
            .open("/dev/stdout", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stdout");
        let data = b"Hello, layered stdout!";
        layered_fs
            .write(&fd_stdout, data, None)
            .expect("Failed to write to /dev/stdout");
        layered_fs
            .close(fd_stdout)
            .expect("Failed to close /dev/stdout");
        assert_eq!(platform.stdout_queue.read().unwrap().len(), 1);
        assert_eq!(platform.stdout_queue.read().unwrap()[0], data);

        // Test opening and writing to /dev/stderr
        let fd_stderr = layered_fs
            .open("/dev/stderr", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stderr");
        let data = b"Hello, layered stderr!";
        layered_fs
            .write(&fd_stderr, data, None)
            .expect("Failed to write to /dev/stderr");
        layered_fs
            .close(fd_stderr)
            .expect("Failed to close /dev/stderr");
        assert_eq!(platform.stderr_queue.read().unwrap().len(), 1);
        assert_eq!(platform.stderr_queue.read().unwrap()[0], data);

        // Test opening and reading from /dev/stdin
        platform
            .stdin_queue
            .write()
            .unwrap()
            .push_back(b"Hello, layered stdin!".to_vec());
        let fd_stdin = layered_fs
            .open("/dev/stdin", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open /dev/stdin");
        let mut buffer = vec![0; 1024];
        let bytes_read = layered_fs
            .read(&fd_stdin, &mut buffer, None)
            .expect("Failed to read from /dev/stdin");
        assert_eq!(&buffer[..bytes_read], b"Hello, layered stdin!");
        layered_fs
            .close(fd_stdin)
            .expect("Failed to close /dev/stdin");
    }

    #[test]
    fn layered_write_to_non_dev() {
        let litebox = LiteBox::new(MockPlatform::new());
        let in_mem = {
            let mut in_mem = in_mem::FileSystem::new(&litebox);
            in_mem.with_root_privileges(|fs| {
                fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO).unwrap();
            });
            in_mem
        };
        let fs = layered::FileSystem::new(
            &litebox,
            in_mem,
            devices::stdio::FileSystem::new(&litebox),
            LayeringSemantics::LowerLayerWritableFiles,
        );

        // Test file creation
        let path = "/testfile";
        let fd = fs
            .open(path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");

        fs.close(fd).expect("Failed to close file");

        // Test file deletion
        fs.unlink(path).expect("Failed to unlink file");
        assert!(
            fs.open(path, OFlags::RDONLY, Mode::RWXU).is_err(),
            "File should not exist"
        );
    }
}
