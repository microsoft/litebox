use litebox::fs::{FileSystem as _, OFlags};
use litebox_common_linux::errno::Errno;

use crate::litebox_fs;

pub(crate) struct StdioFile {
    pub(crate) file: litebox::fd::FileFd,
    pub(crate) status: core::sync::atomic::AtomicU32,
    pub(crate) close_on_exec: core::sync::atomic::AtomicBool,
}

impl StdioFile {
    pub(crate) fn new(file: litebox::fd::FileFd, flags: OFlags) -> Self {
        Self {
            file,
            status: core::sync::atomic::AtomicU32::new(flags.bits()),
            close_on_exec: core::sync::atomic::AtomicBool::new(flags.contains(OFlags::CLOEXEC)),
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
