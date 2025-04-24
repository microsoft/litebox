use litebox::{fs::OFlags, platform::trivial_providers::ImpossiblePunchthroughProvider};
use litebox_common_linux::{FcntlArg, FileDescriptorFlags};
use litebox_platform_multiplex::{Platform, set_platform};

use super::file::{sys_fcntl, sys_pipe2};

fn init_platform() {
    set_platform(Platform::new(None, ImpossiblePunchthroughProvider {}));
}

#[test]
fn test_fcntl() {
    init_platform();

    let (read_fd, write_fd) =
        sys_pipe2(OFlags::CLOEXEC | OFlags::NONBLOCK).expect("Failed to create pipe");
    let read_fd = i32::try_from(read_fd).unwrap();
    let write_fd = i32::try_from(write_fd).unwrap();
    assert_eq!(
        sys_fcntl(read_fd, FcntlArg::GETFD).unwrap(),
        FileDescriptorFlags::FD_CLOEXEC.bits()
    );

    assert_eq!(
        sys_fcntl(read_fd, FcntlArg::GETFL).unwrap(),
        (OFlags::NONBLOCK | OFlags::RDONLY).bits()
    );
    assert_eq!(
        sys_fcntl(write_fd, FcntlArg::GETFL).unwrap(),
        (OFlags::NONBLOCK | OFlags::WRONLY).bits()
    );

    sys_fcntl(read_fd, FcntlArg::SETFD(FileDescriptorFlags::empty())).unwrap();
    assert_eq!(sys_fcntl(read_fd, FcntlArg::GETFD).unwrap(), 0);

    sys_fcntl(write_fd, FcntlArg::SETFL(OFlags::empty())).unwrap();
    assert_eq!(
        sys_fcntl(write_fd, FcntlArg::GETFL).unwrap(),
        (OFlags::WRONLY).bits()
    );
}
