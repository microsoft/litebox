//! Implementation of file related syscalls, e.g., `open`, `read`, `write`, etc.

use alloc::ffi::CString;
use litebox::{
    fs::{FileSystem as _, Mode, OFlags},
    path,
    platform::{RawConstPointer, RawMutPointer},
};
use litebox_common_linux::{
    AtFlags, FcntlArg, FileDescriptorFlags, FileStat, IoReadVec, IoWriteVec, errno::Errno,
};

use crate::{ConstPtr, Descriptor, MutPtr, file_descriptors, litebox_fs};

/// Path in the file system
enum FsPath<P: path::Arg> {
    /// Absolute path
    Absolute { path: P },
    /// Path is relative to `cwd`
    CwdRelative { path: P },
    /// Current working directory
    Cwd,
    /// Path is relative to a file descriptor
    FdRelative { fd: u32, path: P },
    /// Fd
    Fd(u32),
}

/// Maximum size of a file path
pub const PATH_MAX: usize = 4096;
/// Special value `libc::AT_FDCWD` used to indicate openat should use
/// the current working directory.
pub const AT_FDCWD: i32 = -100;

impl<P: path::Arg> FsPath<P> {
    fn new(dirfd: i32, path: P) -> Result<Self, Errno> {
        let path_str = path.as_rust_str()?;
        if path_str.len() > PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let fs_path = if path_str.starts_with('/') {
            FsPath::Absolute { path }
        } else if dirfd >= 0 {
            let dirfd = u32::try_from(dirfd).expect("dirfd >= 0");
            if path_str.is_empty() {
                FsPath::Fd(dirfd)
            } else {
                FsPath::FdRelative { fd: dirfd, path }
            }
        } else if dirfd == AT_FDCWD {
            if path_str.is_empty() {
                FsPath::Cwd
            } else {
                FsPath::CwdRelative { path }
            }
        } else {
            return Err(Errno::EBADF);
        };
        Ok(fs_path)
    }
}

/// Handle syscall `open`
pub fn sys_open(path: impl path::Arg, flags: OFlags, mode: Mode) -> Result<u32, Errno> {
    litebox_fs()
        .open(path, flags, mode)
        .map(|file| {
            if flags.contains(OFlags::CLOEXEC)
                && litebox_fs()
                    .set_fd_metadata(&file, FileDescriptorFlags::FD_CLOEXEC)
                    .is_err()
            {
                unreachable!()
            }
            file_descriptors().write().insert(Descriptor::File(file))
        })
        .map_err(Errno::from)
}

/// Handle syscall `openat`
pub fn sys_openat(
    dirfd: i32,
    pathname: impl path::Arg,
    flags: OFlags,
    mode: Mode,
) -> Result<u32, Errno> {
    let fs_path = FsPath::new(dirfd, pathname)?;
    match fs_path {
        FsPath::Absolute { path } | FsPath::CwdRelative { path } => sys_open(path, flags, mode),
        FsPath::Cwd => sys_open("", flags, mode),
        FsPath::Fd(fd) => todo!(),
        FsPath::FdRelative { fd, path } => todo!(),
    }
}

/// Handle syscall `read`
///
/// `offset` is an optional offset to read from. If `None`, it will read from the current file position.
/// If `Some`, it will read from the specified offset without changing the current file position.
pub fn sys_read(fd: i32, buf: &mut [u8], offset: Option<usize>) -> Result<usize, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };
    match file_descriptors().read().get_fd(fd) {
        Some(desc) => match desc {
            Descriptor::File(file) => litebox_fs().read(file, buf, offset).map_err(Errno::from),
            Descriptor::Socket(socket) => todo!(),
        },
        None => Err(Errno::EBADF),
    }
}

/// Handle syscall `write`
///
/// `offset` is an optional offset to write to. If `None`, it will write to the current file position.
/// If `Some`, it will write to the specified offset without changing the current file position.
pub fn sys_write(fd: i32, buf: &[u8], offset: Option<usize>) -> Result<usize, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };
    match file_descriptors().read().get_fd(fd) {
        Some(desc) => match desc {
            Descriptor::File(file) => litebox_fs().write(file, buf, offset).map_err(Errno::from),
            Descriptor::Socket(socket) => todo!(),
        },
        None => Err(Errno::EBADF),
    }
}

/// Handle syscall `pread64`
pub fn sys_pread64(fd: i32, buf: &mut [u8], offset: usize) -> Result<usize, Errno> {
    if offset > isize::MAX as usize {
        return Err(Errno::EINVAL);
    }
    sys_read(fd, buf, Some(offset))
}

/// Handle syscall `pwrite64`
pub fn sys_pwrite64(fd: i32, buf: &[u8], offset: usize) -> Result<usize, Errno> {
    if offset > isize::MAX as usize {
        return Err(Errno::EINVAL);
    }
    sys_write(fd, buf, Some(offset))
}

/// Handle syscall `close`
pub fn sys_close(fd: i32) -> Result<(), Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };
    match file_descriptors().write().remove(fd) {
        Some(Descriptor::File(file)) => litebox_fs().close(file).map_err(Errno::from),
        Some(Descriptor::Socket(socket)) => todo!(),
        None => Err(Errno::EBADF),
    }
}

/// Handle syscall `readv`
pub fn sys_readv(
    fd: i32,
    iovec: ConstPtr<IoReadVec<MutPtr<u8>>>,
    iovcnt: usize,
) -> Result<usize, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };
    let iovs: &[IoReadVec<MutPtr<u8>>] =
        unsafe { &iovec.to_cow_slice(iovcnt).ok_or(Errno::EFAULT)? };
    let locked_file_descriptors = file_descriptors().read();
    let desc = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
    let mut total_read = 0;
    for iov in iovs {
        if iov.iov_len == 0 {
            continue;
        }
        let Ok(iov_len) = isize::try_from(iov.iov_len) else {
            return Err(Errno::EINVAL);
        };
        // TODO: use kernel buffer to avoid page faults
        let size = iov
            .iov_base
            .mutate_subslice_with(..iov_len, |user_buf| {
                // TODO: The data transfers performed by readv() and writev() are atomic: the data
                // written by writev() is written as a single block that is not intermingled with
                // output from writes in other processes
                match desc {
                    Descriptor::File(file) => {
                        litebox_fs().read(file, user_buf, None).map_err(Errno::from)
                    }
                    Descriptor::Socket(socket) => todo!(),
                }
            })
            .ok_or(Errno::EFAULT)??;

        total_read += size;
        if size < iov.iov_len {
            // Okay to transfer fewer bytes than requested
            break;
        }
    }
    Ok(total_read)
}

/// Handle syscall `writev`
pub fn sys_writev(
    fd: i32,
    iovec: ConstPtr<IoWriteVec<ConstPtr<u8>>>,
    iovcnt: usize,
) -> Result<usize, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };
    let iovs: &[IoWriteVec<ConstPtr<u8>>] =
        unsafe { &iovec.to_cow_slice(iovcnt).ok_or(Errno::EFAULT)? };
    let locked_file_descriptors = file_descriptors().read();
    let desc = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
    let mut total_written = 0;
    for iov in iovs {
        if iov.iov_len == 0 {
            continue;
        }
        let slice = unsafe { iov.iov_base.to_cow_slice(iov.iov_len) }.ok_or(Errno::EFAULT)?;
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        let size = match desc {
            Descriptor::File(file) => litebox_fs()
                .write(file, &slice, None)
                .map_err(Errno::from)?,
            Descriptor::Socket(socket) => todo!(),
        };

        total_written += size;
        if size < iov.iov_len {
            // Okay to transfer fewer bytes than requested
            break;
        }
    }
    Ok(total_written)
}

/// Handle syscall `access`
pub fn sys_access(
    pathname: impl path::Arg,
    mode: litebox_common_linux::AccessFlags,
) -> Result<(), Errno> {
    let status = litebox_fs().file_status(pathname)?;
    if mode == litebox_common_linux::AccessFlags::F_OK {
        return Ok(());
    }
    // TODO: the check is done using the calling process's real UID and GID.
    // Here we assume the caller owns the file.
    if mode.contains(litebox_common_linux::AccessFlags::R_OK)
        && !status.mode.contains(litebox::fs::Mode::RUSR)
    {
        return Err(Errno::EACCES);
    }
    if mode.contains(litebox_common_linux::AccessFlags::W_OK)
        && !status.mode.contains(litebox::fs::Mode::WUSR)
    {
        return Err(Errno::EACCES);
    }
    if mode.contains(litebox_common_linux::AccessFlags::X_OK)
        && !status.mode.contains(litebox::fs::Mode::XUSR)
    {
        return Err(Errno::EACCES);
    }
    Ok(())
}

/// Handle syscall `readlink`
pub fn sys_readlink(pathname: impl path::Arg, buf: &mut [u8]) -> Result<usize, Errno> {
    // TODO: support symbolic links
    Err(Errno::ENOSYS)
}

/// Handle syscall `readlinkat`
pub fn sys_readlinkat(
    dirfd: i32,
    pathname: impl path::Arg,
    buf: &mut [u8],
) -> Result<usize, Errno> {
    // TODO: support symbolic links
    Err(Errno::ENOSYS)
}

/// Handle syscall `fstat`
pub fn sys_fstat(fd: i32) -> Result<FileStat, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };
    let stat = match file_descriptors().read().get_fd(fd) {
        Some(desc) => match desc {
            Descriptor::File(file) => FileStat::from(litebox_fs().fd_file_status(file)?),
            Descriptor::Socket(socket) => todo!(),
        },
        None => return Err(Errno::EBADF),
    };
    Ok(stat)
}

/// Handle syscall `newfstatat`
pub fn sys_newfstatat(
    dirfd: i32,
    pathname: impl path::Arg,
    flags: AtFlags,
) -> Result<FileStat, Errno> {
    let current_support_flags = AtFlags::AT_EMPTY_PATH;
    if flags.contains(current_support_flags.complement()) {
        todo!("unsupported flags");
    }

    let fs_path = FsPath::new(dirfd, pathname)?;
    let status = match fs_path {
        FsPath::Absolute { path } | FsPath::CwdRelative { path } => {
            litebox_fs().file_status(path)?
        }
        FsPath::Cwd => litebox_fs().file_status("")?,
        FsPath::Fd(fd) => file_descriptors()
            .read()
            .get_file_fd(fd)
            .ok_or(Errno::EBADF)
            .and_then(|file| Ok(litebox_fs().fd_file_status(file)?))?,
        FsPath::FdRelative { fd, path } => todo!(),
    };
    Ok(FileStat::from(status))
}

pub fn sys_fcntl(fd: i32, arg: FcntlArg) -> Result<u32, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };

    let locked_file_descriptors = file_descriptors().read();
    let desc = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
    match arg {
        FcntlArg::GETFD => {
            let flags: FileDescriptorFlags =
                match file_descriptors().read().get_fd(fd).ok_or(Errno::EBADF)? {
                    Descriptor::File(file) => litebox_fs()
                        .with_metadata(file, |flags: &FileDescriptorFlags| *flags)
                        .unwrap_or(FileDescriptorFlags::empty()),
                    Descriptor::Socket(socket) => todo!(),
                };
            Ok(flags.bits())
        }
        FcntlArg::SETFD(flags) => {
            match file_descriptors().read().get_fd(fd).ok_or(Errno::EBADF)? {
                Descriptor::File(file) => {
                    if litebox_fs().set_fd_metadata(file, flags).is_err() {
                        unreachable!()
                    }
                }
                Descriptor::Socket(socket) => todo!(),
            }
            Ok(0)
        }
        FcntlArg::GETFL => todo!(),
        _ => unimplemented!(),
    }
}

/// Handle syscall `getcwd`
pub fn sys_getcwd(buf: &mut [u8]) -> Result<usize, Errno> {
    // TODO: use a fixed path for now
    let cwd = "/";
    // need to account for the null terminator
    if cwd.len() >= buf.len() {
        return Err(Errno::ERANGE);
    }

    let Ok(name) = CString::new(cwd) else {
        return Err(Errno::EINVAL);
    };
    let bytes = name.as_bytes_with_nul();
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}
