//! Read syscall implementation

use litebox::fs::{FileSystem, errors::ReadError};

use crate::{file_descriptors, litebox_fs};

/// Read from a file
///
/// `offset` is an optional offset to read from. If `None`, it will read from the current file position.
/// If `Some`, it will read from the specified offset without changing the current file position.
pub(crate) fn sys_read(fd: i32, buf: &mut [u8], offset: Option<usize>) -> Result<usize, ReadError> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(ReadError::NotAFile);
    };
    match file_descriptors().read().get_file_fd(fd) {
        Some(file) => litebox_fs().read(file, buf, offset),
        None => Err(ReadError::NotAFile),
    }
}
