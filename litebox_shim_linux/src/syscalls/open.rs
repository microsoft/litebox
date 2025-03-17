//! `Open` syscall implementation.

use litebox::{
    fs::{FileSystem as _, Mode, OFlags, errors::OpenError},
    path,
};

use crate::{Descriptor, file_descriptors, litebox_fs};

/// Open a file
pub(crate) fn sys_open(path: impl path::Arg, flags: OFlags, mode: Mode) -> Result<i32, OpenError> {
    litebox_fs().open(path, flags, mode).map(|file| {
        file_descriptors()
            .write()
            .insert(Descriptor::File(file))
            .try_into()
            .unwrap()
    })
}
