use litebox::fs::{Mode, OFlags};
use litebox_common_linux::{EfdFlags, FcntlArg, FileDescriptorFlags, errno::Errno};
use litebox_platform_multiplex::{Platform, set_platform};

use super::file::{sys_dup, sys_eventfd2, sys_fcntl, sys_open, sys_pipe2};

extern crate std;

// Ensure we only init the platform once
static INIT_FUNC: spin::Once = spin::Once::new();

pub(crate) fn init_platform(tun_device_name: Option<&str>) {
    INIT_FUNC.call_once(|| {
        set_platform(Platform::new(tun_device_name));

        let litebox = crate::litebox();
        let in_mem_fs = litebox::fs::in_mem::FileSystem::new(litebox);
        let dev_stdio = litebox::fs::devices::stdio::FileSystem::new(litebox);
        let tar_ro_fs =
            litebox::fs::tar_ro::FileSystem::new(litebox, litebox::fs::tar_ro::empty_tar_file());
        crate::set_fs(litebox::fs::layered::FileSystem::new(
            litebox,
            in_mem_fs,
            litebox::fs::layered::FileSystem::new(
                litebox,
                dev_stdio,
                tar_ro_fs,
                litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
            ),
            litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
        ));
    });
}

pub(crate) fn compile(input: &str, output: &str, is_static: bool, nolibc: bool) {
    // Compile the hello.c file to an executable
    let mut args = alloc::vec!["-o", output, input];
    if is_static {
        args.push("-static");
    }
    if nolibc {
        args.push("-nostdlib");
    }
    args.push(match std::env::consts::ARCH {
        "x86_64" => "-m64",
        "x86" => "-m32",
        _ => unimplemented!(),
    });
    let output = std::process::Command::new("gcc")
        .args(args)
        .output()
        .expect("Failed to compile hello.c");
    assert!(
        output.status.success(),
        "failed to compile {input:} {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );
}

#[test]
fn test_fcntl() {
    init_platform(None);

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

#[test]
fn test_dup() {
    init_platform(None);

    let fd = sys_open("/dev/stdin", OFlags::RDONLY, Mode::empty()).unwrap();
    let fd = i32::try_from(fd).unwrap();
    // test dup
    let fd2 = sys_dup(fd, None, None).unwrap();
    let fd2 = i32::try_from(fd2).unwrap();
    assert_eq!(fd + 1, fd2);

    // test dup2
    let fd3 = sys_dup(fd2, Some(fd2 + 10), None).unwrap();
    let fd3 = i32::try_from(fd3).unwrap();
    assert_eq!(fd2 + 10, fd3);

    // test dup3
    assert_eq!(
        sys_dup(fd3, Some(fd3), Some(OFlags::CLOEXEC)),
        Err(Errno::EINVAL)
    );
    let fd4 = sys_dup(fd2, Some(fd2 + 10), Some(OFlags::CLOEXEC)).unwrap();
    let fd4 = i32::try_from(fd4).unwrap();
    assert_eq!(fd2 + 10, fd4);
}
