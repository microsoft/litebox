// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host files: those the spec names (the image, bind sources), the guest service, and the archive.

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::path::Path;

/// Never waits for a FIFO's writer.
#[cfg(unix)]
pub(super) fn open(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

/// Opens directories too, and never lets a pipe server impersonate the shim.
#[cfg(windows)]
pub(super) fn open(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, SECURITY_IDENTIFICATION,
    };
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(path)
}

#[cfg(unix)]
pub(super) fn metadata(path: &Path) -> io::Result<Metadata> {
    std::fs::metadata(path)
}

/// Through [`open`], which a pipe server cannot use to impersonate the shim.
#[cfg(windows)]
pub(super) fn metadata(path: &Path) -> io::Result<Metadata> {
    open(path)?.metadata()
}

#[cfg(unix)]
pub(super) fn mode(metadata: &Metadata) -> u32 {
    std::os::unix::fs::MetadataExt::mode(metadata)
}

/// Host files on Windows have no execute bit to preserve.
#[cfg(windows)]
pub(super) fn mode(metadata: &Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o555
    } else {
        0o755
    }
}

pub(super) fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    return std::os::unix::fs::FileExt::read_at(file, buffer, offset);
    #[cfg(windows)]
    return std::os::windows::fs::FileExt::seek_read(file, buffer, offset);
}

/// Creates `path` to write and read, never through a symlink: the broker's user may own its
/// directory. On Unix it is the daemon's alone, whatever the umask, until granted.
pub(super) fn create(path: &Path) -> io::Result<File> {
    let mut options = File::options();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}
