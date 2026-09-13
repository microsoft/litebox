// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Smoke coverage for the compatibility facade. Backend semantics live in broker-core tests.

use crate::LiteBox;
use crate::fs::errors::{OpenError, ReadError, WriteError};
use crate::fs::in_mem::{InMem, InitialNode};
use crate::fs::resolver::{Context, Resolver};
use crate::fs::{FileType, Mode, OFlags, SeekWhence, UserInfo};
use crate::platform::mock::MockPlatform;

fn facade_fs(litebox: &LiteBox<MockPlatform>) -> Resolver<MockPlatform, InMem<MockPlatform>> {
    Resolver::new(
        litebox,
        InMem::new_initialized([
            (
                "/",
                InitialNode::Directory {
                    mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                    owner: UserInfo::ROOT,
                },
            ),
            (
                "/seed",
                InitialNode::File {
                    mode: Mode::RUSR | Mode::RGRP | Mode::ROTH,
                    owner: UserInfo {
                        user: 123,
                        group: 456,
                    },
                    data: b"seed data".as_slice().into(),
                },
            ),
        ]),
    )
}

#[test]
fn context_resolves_relative_paths_and_forwards_credentials() {
    let litebox = LiteBox::new(MockPlatform::new());
    let fs = facade_fs(&litebox);
    let mut ctx = Context::new();
    fs.mkdir(&ctx, "/work", Mode::RWXU | Mode::XOTH).unwrap();
    ctx.set_cwd(ctx.resolve("/work").unwrap());

    let fd = fs
        .open(&ctx, "./file", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
        .unwrap();
    fs.write(&fd, b"data", None).unwrap();
    fs.close(&fd).unwrap();

    let status = fs.file_status(&ctx, "../work/file").unwrap();
    assert_eq!(status.file_type, FileType::RegularFile);
    assert_eq!(status.mode, Mode::RWXU);
    assert_eq!(status.owner.user, ctx.acting_user().user);
    assert_eq!(status.owner.group, ctx.acting_user().group);
    assert_eq!(status.size, 4);

    fs.chmod(&ctx, "file", Mode::WUSR).unwrap();
    assert!(matches!(
        fs.open(&ctx, "file", OFlags::RDONLY, Mode::empty()),
        Err(OpenError::AccessNotAllowed)
    ));
    ctx.set_acting_user(UserInfo::ROOT);
    fs.chown(&ctx, "file", Some(321), Some(654)).unwrap();
    let status = fs.file_status(&ctx, "/work/file").unwrap();
    assert_eq!(status.owner.user, 321);
    assert_eq!(status.owner.group, 654);
    assert_eq!(status.mode, Mode::WUSR);
}

#[test]
fn descriptors_share_position_and_report_closed_fd_errors() {
    let litebox = LiteBox::new(MockPlatform::new());
    let fs = facade_fs(&litebox);
    let ctx = Context::new();
    let fd = fs
        .open(&ctx, "/file", OFlags::CREAT | OFlags::RDWR, Mode::RWXU)
        .unwrap();
    fs.write(&fd, b"abcdef", None).unwrap();
    fs.seek(&fd, 0, SeekWhence::RelativeToBeginning).unwrap();
    let duplicate = litebox.descriptor_table_mut().duplicate(&fd).unwrap();

    let mut buffer = [0; 3];
    assert_eq!(fs.read(&fd, &mut buffer, None).unwrap(), 3);
    assert_eq!(&buffer, b"abc");
    assert_eq!(fs.read(&duplicate, &mut buffer, None).unwrap(), 3);
    assert_eq!(&buffer, b"def");
    fs.close(&fd).unwrap();
    assert!(matches!(
        fs.read(&fd, &mut buffer, None),
        Err(ReadError::ClosedFd)
    ));
    assert!(matches!(
        fs.write(&fd, b"x", None),
        Err(WriteError::ClosedFd)
    ));
    fs.truncate(&duplicate, 2, true).unwrap();
    assert_eq!(fs.fd_file_status(&duplicate).unwrap().size, 2);
    assert_eq!(fs.read(&duplicate, &mut buffer, None).unwrap(), 2);
    assert_eq!(&buffer[..2], b"ab");
    fs.close(&duplicate).unwrap();
}

#[test]
fn initial_nodes_and_directory_entries_preserve_guest_values() {
    let litebox = LiteBox::new(MockPlatform::new());
    let fs = facade_fs(&litebox);
    let ctx = Context::new();
    let fd = fs
        .open(&ctx, "/seed", OFlags::RDONLY, Mode::empty())
        .unwrap();
    assert_eq!(
        fs.get_static_backing_data(&fd),
        Some(b"seed data".as_slice())
    );
    let status = fs.fd_file_status(&fd).unwrap();
    assert_eq!(status.file_type, FileType::RegularFile);
    assert_eq!(status.mode, Mode::RUSR | Mode::RGRP | Mode::ROTH);
    assert_eq!(status.owner.user, 123);
    assert_eq!(status.owner.group, 456);
    assert_eq!(status.size, 9);
    fs.close(&fd).unwrap();

    let directory = fs
        .open(&ctx, "/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .unwrap();
    let entries = fs.read_dir(&directory).unwrap();
    let entry = entries.iter().find(|entry| entry.name == "seed").unwrap();
    assert_eq!(entry.file_type, FileType::RegularFile);
    assert_eq!(entry.ino_info, Some(status.node_info));
    fs.close(&directory).unwrap();
}

mod stdio {
    use crate::LiteBox;
    use crate::fs::devices::Devices;
    use crate::fs::errors::{ReadError, WriteError};
    use crate::fs::resolver::Resolver;
    use crate::fs::{Mode, OFlags};
    use crate::platform::mock::MockPlatform;
    use alloc::vec;
    extern crate std;

    #[test]
    fn stdio_requires_broker() {
        let ctx = crate::fs::resolver::Context::new();
        let platform = MockPlatform::new();
        let litebox = LiteBox::new(platform);
        let fs = Resolver::new(
            &litebox,
            crate::fs::composer::Composer::builder()
                .mount("/dev", Devices::new)
                .build()
                .unwrap(),
        );

        let fd_stdout = fs
            .open(&ctx, "/dev/stdout", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stdout");
        assert!(matches!(fs.write(&fd_stdout, b"", None), Ok(0)));
        assert!(matches!(
            fs.write(&fd_stdout, b"Hello, stdout!", None),
            Err(WriteError::Io)
        ));
        fs.close(&fd_stdout).expect("Failed to close /dev/stdout");

        let fd_stderr = fs
            .open(&ctx, "/dev/stderr", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stderr");
        assert!(matches!(fs.write(&fd_stderr, b"", None), Ok(0)));
        assert!(matches!(
            fs.write(&fd_stderr, b"Hello, stderr!", None),
            Err(WriteError::Io)
        ));
        fs.close(&fd_stderr).expect("Failed to close /dev/stderr");

        let fd_stdin = fs
            .open(&ctx, "/dev/stdin", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open /dev/stdin");
        assert!(matches!(fs.read(&fd_stdin, &mut [], None), Ok(0)));
        let mut buffer = vec![0; 13];
        assert!(matches!(
            fs.read(&fd_stdin, &mut buffer, None),
            Err(ReadError::Io)
        ));
        fs.close(&fd_stdin).expect("Failed to close /dev/stdin");
    }

    #[test]
    fn non_dev_path_fails() {
        let ctx = crate::fs::resolver::Context::new();
        let litebox = LiteBox::new(MockPlatform::new());
        let fs = Resolver::new(
            &litebox,
            crate::fs::composer::Composer::builder()
                .mount("/dev", Devices::new)
                .build()
                .unwrap(),
        );

        // Attempt to open a non-/dev/* path
        let result = fs.open(&ctx, "foo", OFlags::RDONLY, Mode::empty());
        assert!(matches!(
            result,
            Err(crate::fs::errors::OpenError::PathError(
                crate::fs::errors::PathError::NoSuchFileOrDirectory
            ))
        ));
    }
}

mod composed_stdio {
    use crate::LiteBox;
    use crate::fs::composer::Composer;
    use crate::fs::devices::Devices;
    use crate::fs::errors::{ReadError, WriteError};
    use crate::fs::in_mem::{InMem, InitialNode};
    use crate::fs::resolver::Resolver;
    use crate::fs::{Mode, OFlags, UserInfo};
    use crate::platform::mock::MockPlatform;
    use alloc::vec;
    extern crate std;

    type ComposedFs = Resolver<MockPlatform, Composer>;

    fn composed_fs(litebox: &LiteBox<MockPlatform>) -> ComposedFs {
        Resolver::new(
            litebox,
            Composer::builder()
                .mount("/", |_| {
                    InMem::<MockPlatform>::new_initialized([(
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
        let ctx = crate::fs::resolver::Context::new();
        let platform = MockPlatform::new();
        let litebox = LiteBox::new(platform);
        let fs = composed_fs(&litebox);

        let fd_stdout = fs
            .open(&ctx, "/dev/stdout", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stdout");
        assert!(matches!(fs.write(&fd_stdout, b"", None), Ok(0)));
        assert!(matches!(
            fs.write(&fd_stdout, b"Hello, composed stdout!", None),
            Err(WriteError::Io)
        ));
        fs.close(&fd_stdout).expect("Failed to close /dev/stdout");

        let fd_stderr = fs
            .open(&ctx, "/dev/stderr", OFlags::WRONLY, Mode::empty())
            .expect("Failed to open /dev/stderr");
        assert!(matches!(fs.write(&fd_stderr, b"", None), Ok(0)));
        assert!(matches!(
            fs.write(&fd_stderr, b"Hello, composed stderr!", None),
            Err(WriteError::Io)
        ));
        fs.close(&fd_stderr).expect("Failed to close /dev/stderr");

        let fd_stdin = fs
            .open(&ctx, "/dev/stdin", OFlags::RDONLY, Mode::empty())
            .expect("Failed to open /dev/stdin");
        assert!(matches!(fs.read(&fd_stdin, &mut [], None), Ok(0)));
        let mut buffer = vec![0; 1024];
        assert!(matches!(
            fs.read(&fd_stdin, &mut buffer, None),
            Err(ReadError::Io)
        ));
        fs.close(&fd_stdin).expect("Failed to close /dev/stdin");
    }

    #[test]
    fn write_to_non_dev() {
        let ctx = crate::fs::resolver::Context::new();
        let litebox = LiteBox::new(MockPlatform::new());
        let fs = composed_fs(&litebox);

        // Test file creation
        let path = "/testfile";
        let fd = fs
            .open(&ctx, path, OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
            .expect("Failed to create file");

        fs.close(&fd).expect("Failed to close file");

        // Test file deletion
        fs.unlink(&ctx, path).expect("Failed to unlink file");
        assert!(
            fs.open(&ctx, path, OFlags::RDONLY, Mode::RWXU).is_err(),
            "File should not exist"
        );
    }
}
