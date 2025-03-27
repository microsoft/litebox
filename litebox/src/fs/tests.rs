mod in_mem {
    use crate::fs::in_mem;
    use crate::fs::{FileSystem as _, Mode, OFlags};
    use crate::platform::mock::MockPlatform;
    use alloc::vec;
    extern crate std;

    #[test]
    fn root_file_creation_and_deletion() {
        let platform = MockPlatform::new();

        in_mem::FileSystem::new(&platform).with_root_privileges(|fs| {
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
        let platform = MockPlatform::new();

        in_mem::FileSystem::new(&platform).with_root_privileges(|fs| {
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
        let platform = MockPlatform::new();

        in_mem::FileSystem::new(&platform).with_root_privileges(|fs| {
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
        let platform = MockPlatform::new();
        let mut fs = in_mem::FileSystem::new(&platform);
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
        let platform = MockPlatform::new();
        let mut fs = in_mem::FileSystem::new(&platform);
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
        let platform = MockPlatform::new();
        let mut fs = in_mem::FileSystem::new(&platform);
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
}

mod tar_ro {
    use crate::fs::tar_ro;
    use crate::fs::{FileSystem as _, Mode, OFlags};
    use crate::platform::mock::MockPlatform;
    use alloc::vec;
    extern crate std;

    const TEST_TAR_FILE: &[u8] = include_bytes!("./test.tar");

    #[test]
    fn file_read() {
        let platform = MockPlatform::new();
        let mut fs = tar_ro::FileSystem::new(&platform, TEST_TAR_FILE.into());
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
        let platform = MockPlatform::new();
        let mut fs = tar_ro::FileSystem::new(&platform, TEST_TAR_FILE.into());
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
}

mod layered {
    use crate::fs::{FileSystem as _, FileType, Mode, OFlags};
    use crate::fs::{in_mem, layered, tar_ro};
    use crate::platform::mock::MockPlatform;
    use alloc::vec;
    extern crate std;

    const TEST_TAR_FILE: &[u8] = include_bytes!("./test.tar");

    #[test]
    fn file_read_from_lower() {
        let platform = MockPlatform::new();
        let mut fs = layered::FileSystem::new(
            &platform,
            in_mem::FileSystem::new(&platform),
            tar_ro::FileSystem::new(&platform, TEST_TAR_FILE.into()),
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
        let platform = MockPlatform::new();
        let mut fs = layered::FileSystem::new(
            &platform,
            in_mem::FileSystem::new(&platform),
            tar_ro::FileSystem::new(&platform, TEST_TAR_FILE.into()),
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
        let platform = MockPlatform::new();

        let mut in_mem_fs = in_mem::FileSystem::new(&platform);
        in_mem_fs.with_root_privileges(|fs| {
            // Change the permissions for `/` to allow file creation
            //
            // TODO: We might need to force-allow file creation in cases where the lower level
            // already has the file in the correct mode. This would likely require `stat` as well as
            // some internal-only force-creation API.
            fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });

        let mut fs = layered::FileSystem::new(
            &platform,
            in_mem_fs,
            tar_ro::FileSystem::new(&platform, TEST_TAR_FILE.into()),
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
        let platform = MockPlatform::new();

        let mut in_mem_fs = in_mem::FileSystem::new(&platform);
        in_mem_fs.with_root_privileges(|fs| {
            // Change the permissions for `/` to allow file creation
            //
            // TODO: We might need to force-allow file creation in cases where the lower level
            // already has the file in the correct mode. This would likely require `stat` as well as
            // some internal-only force-creation API.
            fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
                .expect("Failed to chmod /");
        });

        let mut fs = layered::FileSystem::new(
            &platform,
            in_mem_fs,
            tar_ro::FileSystem::new(&platform, TEST_TAR_FILE.into()),
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
        let platform = MockPlatform::new();

        let mut fs = layered::FileSystem::new(
            &platform,
            in_mem::FileSystem::new(&platform),
            tar_ro::FileSystem::new(&platform, TEST_TAR_FILE.into()),
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
}
