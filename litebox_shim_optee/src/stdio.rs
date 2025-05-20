//! Standard input/output streams.

use litebox::fs::{FileSystem as _, OFlags};
use litebox_common_linux::errno::Errno;

use crate::litebox_fs;

pub(crate) struct StdioFileInner {
    file: Option<litebox::fd::FileFd>,
    status: core::sync::atomic::AtomicU32,
}

impl StdioFileInner {
    pub(crate) fn file(&self) -> &litebox::fd::FileFd {
        self.file.as_ref().expect("File descriptor is not set")
    }

    crate::syscalls::common_functions_for_file_status!();
}

impl Drop for StdioFileInner {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            // Close the file descriptor
            let _ = litebox_fs().close(file);
        }
    }
}

pub(crate) struct StdioFile {
    pub(crate) typ: litebox::platform::StdioStream,
    pub(crate) close_on_exec: core::sync::atomic::AtomicBool,
    pub(crate) inner: alloc::sync::Arc<StdioFileInner>,
}

impl StdioFile {
    pub(crate) fn new(
        typ: litebox::platform::StdioStream,
        file: litebox::fd::FileFd,
        flags: OFlags,
    ) -> Self {
        let flags = flags | OFlags::RDWR | OFlags::APPEND;
        Self {
            typ,
            close_on_exec: core::sync::atomic::AtomicBool::new(flags.contains(OFlags::CLOEXEC)),
            inner: alloc::sync::Arc::new(StdioFileInner {
                file: Some(file),
                status: core::sync::atomic::AtomicU32::new(flags.bits()),
            }),
        }
    }

    pub(crate) fn dup(&self, close_on_exec: bool) -> Self {
        Self {
            typ: self.typ,
            close_on_exec: core::sync::atomic::AtomicBool::new(close_on_exec),
            inner: self.inner.clone(),
        }
    }

    pub(crate) fn read(&self, buf: &mut [u8], offset: Option<usize>) -> Result<usize, Errno> {
        if self.inner.get_status().contains(OFlags::NONBLOCK) {
            todo!("non-blocking read");
        }
        litebox_fs()
            .read(self.inner.file.as_ref().unwrap(), buf, offset)
            .map_err(Errno::from)
    }

    pub(crate) fn write(&self, buf: &[u8], offset: Option<usize>) -> Result<usize, Errno> {
        if self.inner.get_status().contains(OFlags::NONBLOCK) {
            todo!("non-blocking write");
        }
        litebox_fs()
            .write(self.inner.file.as_ref().unwrap(), buf, offset)
            .map_err(Errno::from)
    }
}

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
