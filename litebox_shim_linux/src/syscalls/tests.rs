use litebox::{fs::OFlags, platform::trivial_providers::ImpossiblePunchthroughProvider};
use litebox_common_linux::{EfdFlags, FcntlArg, FileDescriptorFlags};
use litebox_platform_multiplex::{Platform, set_platform};

use super::file::{sys_eventfd2, sys_fcntl, sys_pipe2};

pub(crate) fn init_platform() {
    set_platform(Platform::new(None, ImpossiblePunchthroughProvider {}));

    let platform = litebox_platform_multiplex::platform();
    let litebox = litebox::LiteBox::new(platform);

    let in_mem_fs = litebox::fs::in_mem::FileSystem::new(&litebox);
    let dev_stdio = litebox::fs::devices::stdio::FileSystem::new(&litebox);
    let tar_ro_fs =
        litebox::fs::tar_ro::FileSystem::new(&litebox, litebox::fs::tar_ro::empty_tar_file());
    crate::set_fs(litebox::fs::layered::FileSystem::new(
        &litebox,
        in_mem_fs,
        litebox::fs::layered::FileSystem::new(
            &litebox,
            dev_stdio,
            tar_ro_fs,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    ));
}

#[test]
fn test_fcntl() {
    init_platform();

    let check = |fd: i32, flags1: OFlags, flags2: OFlags| {
        assert_eq!(
            sys_fcntl(fd, FcntlArg::GETFD).unwrap(),
            FileDescriptorFlags::FD_CLOEXEC.bits()
        );

        assert_eq!(sys_fcntl(fd, FcntlArg::GETFL).unwrap(), flags1.bits());

        sys_fcntl(fd, FcntlArg::SETFD(FileDescriptorFlags::empty())).unwrap();
        assert_eq!(sys_fcntl(fd, FcntlArg::GETFD).unwrap(), 0);

        sys_fcntl(fd, FcntlArg::SETFL(OFlags::empty())).unwrap();
        assert_eq!(sys_fcntl(fd, FcntlArg::GETFL).unwrap(), flags2.bits());
    };

    // Test pipe
    let (read_fd, write_fd) =
        sys_pipe2(OFlags::CLOEXEC | OFlags::NONBLOCK).expect("Failed to create pipe");
    let read_fd = i32::try_from(read_fd).unwrap();
    check(read_fd, OFlags::RDONLY | OFlags::NONBLOCK, OFlags::RDONLY);
    let write_fd = i32::try_from(write_fd).unwrap();
    check(write_fd, OFlags::WRONLY | OFlags::NONBLOCK, OFlags::WRONLY);

    // Test eventfd
    let eventfd = sys_eventfd2(
        0,
        EfdFlags::CLOEXEC | EfdFlags::SEMAPHORE | EfdFlags::NONBLOCK,
    )
    .expect("Failed to create eventfd");
    let eventfd = i32::try_from(eventfd).unwrap();
    check(eventfd, OFlags::RDWR | OFlags::NONBLOCK, OFlags::RDWR);
}
