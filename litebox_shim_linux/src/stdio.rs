// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Standard input/output streams.

#[cfg(test)]
mod tests {
    use core::ffi::CStr;

    use litebox::fs::{Mode, OFlags};
    use litebox_common_linux::{FcntlArg, FileDescriptorFlags, IoctlArg, Termios, errno::Errno};

    use crate::{
        UserPtrMut,
        syscalls::tests::{init_platform, init_platform_with_broker},
    };

    fn termios() -> Termios {
        Termios {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: 0,
            c_line: 0,
            c_cc: [0; 19],
        }
    }

    #[test]
    fn test_stdio() {
        let task = init_platform();

        // Check that the stdio streams are in the file table
        let stdin_stat = task.sys_fstat(0).unwrap();
        let stdout_stat = task.sys_fstat(1).unwrap();
        let stderr_stat = task.sys_fstat(2).unwrap();

        // Check that the stdio stat are consistent
        let stdin = task
            .sys_open("/dev/stdin", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let stdout = task
            .sys_open("/dev/stdout", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let stderr = task
            .sys_open("/dev/stderr", OFlags::WRONLY, Mode::empty())
            .unwrap();
        assert_eq!(
            stdin_stat,
            task.sys_fstat(i32::try_from(stdin).unwrap()).unwrap()
        );
        assert_eq!(
            stdout_stat,
            task.sys_fstat(i32::try_from(stdout).unwrap()).unwrap()
        );
        assert_eq!(
            stderr_stat,
            task.sys_fstat(i32::try_from(stderr).unwrap()).unwrap()
        );

        // test sys_stat is working with symbolic links
        assert_eq!(task.sys_stat("/proc/self/fd/0").unwrap(), stdin_stat);
        assert_eq!(task.sys_stat("/proc/self/fd/1").unwrap(), stdout_stat);
        assert_eq!(task.sys_stat("/proc/self/fd/2").unwrap(), stderr_stat);

        let mut buf: [u8; 128] = [0; 128];
        let size = task.sys_readlink("/proc/self/fd/0", &mut buf).unwrap();
        assert_eq!("/dev/stdin", core::str::from_utf8(&buf[..size]).unwrap());
        let size = task.sys_readlink("/proc/self/fd/1", &mut buf).unwrap();
        assert_eq!("/dev/stdout", core::str::from_utf8(&buf[..size]).unwrap());
        let size = task.sys_readlink("/proc/self/fd/2", &mut buf).unwrap();
        assert_eq!("/dev/stderr", core::str::from_utf8(&buf[..size]).unwrap());
    }

    #[test]
    fn test_stdio_flags_with_dup() {
        let task = init_platform();

        let stdin = 0;
        let flags = task.sys_fcntl(stdin, FcntlArg::GETFL).unwrap();

        let stdin2 = i32::try_from(task.sys_dup(stdin, None, None).unwrap()).unwrap();
        assert_eq!(flags, task.sys_fcntl(stdin2, FcntlArg::GETFL).unwrap());

        let mut stdio_path: [u8; 32] = [0; 32];
        task.sys_readlink("/proc/self/fd/0", &mut stdio_path)
            .expect("Failed to read link");
        let path =
            CStr::from_bytes_until_nul(stdio_path.as_slice()).expect("Failed to convert to CStr");
        let stdin3 = i32::try_from(
            task.sys_open(path.to_str().unwrap(), OFlags::RDONLY, Mode::empty())
                .expect("Failed to open stdin"),
        )
        .expect("Failed to convert to i32");
        let stdin3_flags = task.sys_fcntl(stdin3, FcntlArg::GETFL).unwrap();

        // duplicated fd shares the same status flags while the newly-opened file does not
        // (even though they point to the same file)
        let new_flags = flags | OFlags::NONBLOCK.bits();
        task.sys_fcntl(
            stdin2,
            FcntlArg::SETFL(OFlags::from_bits(new_flags).unwrap()),
        )
        .expect("Failed to set flags");
        assert_eq!(new_flags, task.sys_fcntl(stdin2, FcntlArg::GETFL).unwrap());
        assert_eq!(new_flags, task.sys_fcntl(stdin, FcntlArg::GETFL).unwrap());
        // not affected by the `SETFL` above
        assert_eq!(
            stdin3_flags,
            task.sys_fcntl(stdin3, FcntlArg::GETFL).unwrap()
        );

        // duplicated fd does not share the same close-on-exec flag
        task.sys_fcntl(stdin, FcntlArg::SETFD(FileDescriptorFlags::FD_CLOEXEC))
            .expect("Failed to set close-on-exec flag");
        assert_eq!(
            FileDescriptorFlags::FD_CLOEXEC.bits(),
            task.sys_fcntl(stdin, FcntlArg::GETFD).unwrap()
        );
        assert_eq!(
            FileDescriptorFlags::empty().bits(),
            task.sys_fcntl(stdin2, FcntlArg::GETFD).unwrap()
        );
        assert_eq!(
            FileDescriptorFlags::empty().bits(),
            task.sys_fcntl(stdin3, FcntlArg::GETFD).unwrap()
        );
    }

    #[test]
    fn test_stdio_terminal_query_requires_broker() {
        let task = init_platform();
        let mut termios = termios();

        assert_eq!(
            task.sys_ioctl(1, IoctlArg::TCGETS(UserPtrMut::from_ptr(&raw mut termios)),),
            Err(Errno::EIO)
        );
    }

    #[test]
    fn test_stdio_terminal_query_uses_broker() {
        let task = init_platform_with_broker();
        let mut termios = termios();

        assert_eq!(
            task.sys_ioctl(1, IoctlArg::TCGETS(UserPtrMut::from_ptr(&raw mut termios)),),
            Ok(0)
        );
        assert_eq!(
            task.sys_ioctl(0, IoctlArg::TCGETS(UserPtrMut::from_ptr(&raw mut termios)),),
            Err(Errno::ENOTTY)
        );
    }
}
