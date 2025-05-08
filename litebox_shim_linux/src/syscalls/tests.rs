use litebox::fs::OFlags;
use litebox_common_linux::{EfdFlags, FcntlArg, FileDescriptorFlags};
use litebox_platform_multiplex::{Platform, set_platform};

use super::file::{sys_eventfd2, sys_fcntl, sys_pipe2};

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
