//! Standard input/output streams.

use litebox::fs::{FileSystem as _, OFlags};
use litebox_common_linux::errno::Errno;

use crate::litebox_fs;

pub(crate) struct StdioFile {
    pub(crate) typ: litebox::platform::StdioStream,
    pub(crate) file: litebox::fd::FileFd,
    pub(crate) status: core::sync::atomic::AtomicU32,
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
            file,
            status: core::sync::atomic::AtomicU32::new(flags.bits()),
        }
    }

    pub(crate) fn read(&self, buf: &mut [u8], offset: Option<usize>) -> Result<usize, Errno> {
        if self.get_status().contains(OFlags::NONBLOCK) {
            todo!("non-blocking read");
        }
        litebox_fs()
            .read(&self.file, buf, offset)
            .map_err(Errno::from)
    }

    pub(crate) fn write(&self, buf: &[u8], offset: Option<usize>) -> Result<usize, Errno> {
        if self.get_status().contains(OFlags::NONBLOCK) {
            todo!("non-blocking write");
        }
        litebox_fs()
            .write(&self.file, buf, offset)
            .map_err(Errno::from)
    }

    crate::syscalls::common_functions_for_file_status!();
}

#[cfg(test)]
mod tests {
    use litebox::fs::{Mode, OFlags};

    use crate::syscalls::file::{sys_fstat, sys_readlink, sys_stat};

    #[test]
    fn test_stdio() {
        crate::syscalls::tests::init_platform();

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
}
