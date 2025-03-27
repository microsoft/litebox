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

/// Special value `libc::AT_FDCWD` used to indicate openat should use
/// the current working directory.
pub(crate) const AT_FDCWD: i32 = -100;
pub(crate) fn sys_openat(
    dirfd: i32,
    pathname: impl path::Arg,
    flags: OFlags,
    mode: Mode,
) -> Result<i32, Errno> {
    if dirfd == AT_FDCWD {
        return sys_open(pathname, flags, mode);
    }
    todo!("openat");
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

pub(crate) fn sys_pread64(fd: i32, buf: &mut [u8], offset: usize) -> Result<usize, Errno> {
    if offset > isize::MAX as usize {
        return Err(Errno::EINVAL);
    }
    sys_read(fd, buf, Some(offset))
}

/// Close a file
pub(crate) fn sys_close(fd: i32) -> Result<(), Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };
    match file_descriptors().write().remove(fd) {
        Some(Descriptor::File(file_fd)) => litebox_fs().close(file_fd).map_err(Errno::from),
        Some(Descriptor::Socket(socket_fd)) => todo!(),
        None => Err(Errno::EBADF),
    }
}
