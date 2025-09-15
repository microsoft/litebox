//! Standard input/output streams.

#[cfg(test)]
mod tests {
    use core::ffi::CStr;

    use litebox::fs::{Mode, OFlags};
    use litebox_common_linux::{FcntlArg, FileDescriptorFlags};

    use crate::syscalls::{
        file::{sys_dup, sys_fcntl, sys_fstat, sys_readlink, sys_stat},
        tests::init_platform,
    };

    #[test]
    fn test_stdio() {
        crate::syscalls::tests::init_platform(None);

        // Check that the stdio streams are in the file table
        let stdin_stat = sys_fstat(0).unwrap();
        let stdout_stat = sys_fstat(1).unwrap();
        let stderr_stat = sys_fstat(2).unwrap();

        // Check that the stdio stat are consistent
        let stdin =
            crate::syscalls::file::sys_open("/dev/stdin", OFlags::RDONLY, Mode::empty()).unwrap();
        let stdout =
            crate::syscalls::file::sys_open("/dev/stdout", OFlags::WRONLY, Mode::empty()).unwrap();
        let stderr =
            crate::syscalls::file::sys_open("/dev/stderr", OFlags::WRONLY, Mode::empty()).unwrap();
        assert_eq!(
            stdin_stat,
            sys_fstat(i32::try_from(stdin).unwrap()).unwrap()
        );
        assert_eq!(
            stdout_stat,
            sys_fstat(i32::try_from(stdout).unwrap()).unwrap()
        );
        assert_eq!(
            stderr_stat,
            sys_fstat(i32::try_from(stderr).unwrap()).unwrap()
        );

        // test sys_stat is working with symbolic links
        assert_eq!(sys_stat("/proc/self/fd/0").unwrap(), stdin_stat);
        assert_eq!(sys_stat("/proc/self/fd/1").unwrap(), stdout_stat);
        assert_eq!(sys_stat("/proc/self/fd/2").unwrap(), stderr_stat);

        let mut buf: [u8; 128] = [0; 128];
        let size = sys_readlink("/proc/self/fd/0", &mut buf).unwrap();
        assert_eq!("/dev/stdin", core::str::from_utf8(&buf[..size]).unwrap());
        let size = sys_readlink("/proc/self/fd/1", &mut buf).unwrap();
        assert_eq!("/dev/stdout", core::str::from_utf8(&buf[..size]).unwrap());
        let size = sys_readlink("/proc/self/fd/2", &mut buf).unwrap();
        assert_eq!("/dev/stderr", core::str::from_utf8(&buf[..size]).unwrap());
    }

    #[test]
    fn test_stdio_flags_with_dup() {
        init_platform(None);

        let stdin = 0;
        let flags = sys_fcntl(stdin, FcntlArg::GETFL).unwrap();

        let stdin2 = i32::try_from(sys_dup(stdin, None, None).unwrap()).unwrap();
        assert_eq!(flags, sys_fcntl(stdin2, FcntlArg::GETFL).unwrap());

        let mut stdio_path: [u8; 32] = [0; 32];
        sys_readlink("/proc/self/fd/0", &mut stdio_path).expect("Failed to read link");
        let path =
            CStr::from_bytes_until_nul(stdio_path.as_slice()).expect("Failed to convert to CStr");
        let stdin3 = i32::try_from(
            crate::syscalls::file::sys_open(path.to_str().unwrap(), OFlags::RDONLY, Mode::empty())
                .expect("Failed to open stdin"),
        )
        .expect("Failed to convert to i32");
        let stdin3_flags = sys_fcntl(stdin3, FcntlArg::GETFL).unwrap();

        // duplicated fd shares the same status flags while the newly-opened file does not
        // (even though they point to the same file)
        let new_flags = flags | OFlags::NONBLOCK.bits();
        sys_fcntl(
            stdin2,
            FcntlArg::SETFL(OFlags::from_bits(new_flags).unwrap()),
        )
        .expect("Failed to set flags");
        assert_eq!(new_flags, sys_fcntl(stdin2, FcntlArg::GETFL).unwrap());
        assert_eq!(new_flags, sys_fcntl(stdin, FcntlArg::GETFL).unwrap());
        // not affected by the `SETFL` above
        assert_eq!(stdin3_flags, sys_fcntl(stdin3, FcntlArg::GETFL).unwrap());

        // duplicated fd does not share the same close-on-exec flag
        sys_fcntl(stdin, FcntlArg::SETFD(FileDescriptorFlags::FD_CLOEXEC))
            .expect("Failed to set close-on-exec flag");
        assert_eq!(
            FileDescriptorFlags::FD_CLOEXEC.bits(),
            sys_fcntl(stdin, FcntlArg::GETFD).unwrap()
        );
        assert_eq!(
            FileDescriptorFlags::empty().bits(),
            sys_fcntl(stdin2, FcntlArg::GETFD).unwrap()
        );
        assert_eq!(
            FileDescriptorFlags::empty().bits(),
            sys_fcntl(stdin3, FcntlArg::GETFD).unwrap()
        );
    }
}
