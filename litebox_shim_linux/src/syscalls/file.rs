//! File related syscalls implementation including:
//! * `open`
//! * `close`
//! * `read`

use litebox::{
    fs::{FileSystem as _, Mode, OFlags},
    path,
};
use litebox_common_linux::errno::Errno;

use crate::{Descriptor, file_descriptors, litebox_fs};

/// Open a file
pub(crate) fn sys_open(path: impl path::Arg, flags: OFlags, mode: Mode) -> Result<i32, Errno> {
    litebox_fs()
        .open(path, flags, mode)
        .map(|file| {
            file_descriptors()
                .write()
                .insert(Descriptor::File(file))
                .try_into()
                .unwrap()
        })
        .map_err(Errno::from)
}

/// Read from a file
///
/// `offset` is an optional offset to read from. If `None`, it will read from the current file position.
/// If `Some`, it will read from the specified offset without changing the current file position.
pub(crate) fn sys_read(fd: i32, buf: &mut [u8], offset: Option<usize>) -> Result<usize, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };
    match file_descriptors().read().get_file_fd(fd) {
        Some(file) => litebox_fs().read(file, buf, offset).map_err(Errno::from),
        None => Err(Errno::EBADF),
    }
}
