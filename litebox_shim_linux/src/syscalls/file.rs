//! Implementation of file related syscalls, e.g., `open`, `read`, `write`, etc.

use alloc::{
    ffi::CString,
    string::{String, ToString as _},
    vec,
};
use litebox::{
    fs::{FileSystem as _, Mode, OFlags},
    path,
    platform::{RawConstPointer, RawMutPointer},
    utils::TruncateExt as _,
};
use litebox_common_linux::{
    AtFlags, EfdFlags, EpollCreateFlags, FcntlArg, FileDescriptorFlags, FileStat, IoReadVec,
    IoWriteVec, IoctlArg, errno::Errno,
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
    // TODO: check file stat instead of hardcoding the path to distinguish between stdio
    // and other files once #68 is completed.
    let stdio_typ = match path.normalized()?.as_str() {
        "/dev/stdin" => Some(litebox::platform::StdioStream::Stdin),
        "/dev/stdout" => Some(litebox::platform::StdioStream::Stdout),
        "/dev/stderr" => Some(litebox::platform::StdioStream::Stderr),
        _ => None,
    };
    litebox_fs()
        .open(path, flags - OFlags::CLOEXEC, mode)
        .map(|file| {
            let file = if let Some(typ) = stdio_typ {
                Descriptor::Stdio(crate::stdio::StdioFile::new(typ, file, flags))
            } else {
                if flags.contains(OFlags::CLOEXEC)
                    && litebox_fs()
                        .set_fd_metadata(&file, FileDescriptorFlags::FD_CLOEXEC)
                        .is_err()
                {
                    unreachable!()
                }
                Descriptor::File(file)
            };
            file_descriptors().write().insert(file)
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
    let file_table = file_descriptors().read();
    let desc = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
    match desc {
        Descriptor::File(file) => litebox_fs().read(file, buf, offset).map_err(Errno::from),
        Descriptor::Stdio(file) => file.read(buf, offset),
        Descriptor::Socket(socket) => {
            let socket = socket.clone();
            drop(file_table);
            socket.receive(buf, litebox::net::ReceiveFlags::empty())
        }
        Descriptor::PipeReader { consumer, .. } => {
            let consumer = consumer.clone();
            drop(file_table);
            consumer.read(buf)
        }
        Descriptor::PipeWriter { .. } | Descriptor::Epoll { .. } => Err(Errno::EINVAL),
        Descriptor::Eventfd { file, .. } => {
            let file = file.clone();
            drop(file_table);
            if buf.len() < size_of::<u64>() {
                return Err(Errno::EINVAL);
            }
            let value = file.read()?;
            buf[..size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
            Ok(size_of::<u64>())
        }
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
    let file_table = file_descriptors().read();
    let desc = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
    match desc {
        Descriptor::File(file) => litebox_fs().write(file, buf, offset).map_err(Errno::from),
        Descriptor::Stdio(file) => file.write(buf, offset),
        Descriptor::Socket(socket) => {
            let socket = socket.clone();
            drop(file_table);
            socket.sendto(buf, litebox::net::SendFlags::empty(), None)
        }
        Descriptor::PipeReader { .. } | Descriptor::Epoll { .. } => Err(Errno::EINVAL),
        Descriptor::PipeWriter { producer, .. } => {
            let producer = producer.clone();
            drop(file_table);
            producer.write(buf)
        }
        Descriptor::Eventfd { file, .. } => {
            let file = file.clone();
            drop(file_table);
            let value: u64 = u64::from_le_bytes(
                buf[..size_of::<u64>()]
                    .try_into()
                    .map_err(|_| Errno::EINVAL)?,
            );
            file.write(value)
        }
    }
}

/// Handle syscall `pread64`
pub fn sys_pread64(fd: i32, buf: &mut [u8], offset: i64) -> Result<usize, Errno> {
    let pos = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
    sys_read(fd, buf, Some(pos))
}

/// Handle syscall `pwrite64`
pub fn sys_pwrite64(fd: i32, buf: &[u8], offset: usize) -> Result<usize, Errno> {
    if offset > isize::MAX as usize {
        return Err(Errno::EINVAL);
    }
    sys_write(fd, buf, Some(offset))
}

fn do_close(desc: Descriptor) -> Result<(), Errno> {
    match desc {
        Descriptor::File(file) => litebox_fs().close(file).map_err(Errno::from),
        Descriptor::Stdio(crate::stdio::StdioFile { inner, .. }) => {
            // The actual close happens when the file is dropped
            Ok(())
        }
        Descriptor::Socket(socket) => Ok(()), // The actual close happens when the socket is dropped
        Descriptor::PipeReader { .. }
        | Descriptor::PipeWriter { .. }
        | Descriptor::Eventfd { .. }
        | Descriptor::Epoll { .. } => Ok(()),
    }
}

/// Handle syscall `close`
pub fn sys_close(fd: i32) -> Result<(), Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };
    match file_descriptors().write().remove(fd) {
        Some(desc) => do_close(desc),
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
    let mut kernel_buffer = vec![
        0u8;
        iovs.iter()
            .map(|i| i.iov_len)
            .max()
            .unwrap_or_default()
            .min(super::super::MAX_KERNEL_BUF_SIZE)
    ];
    for iov in iovs {
        if iov.iov_len == 0 {
            continue;
        }
        let Ok(iov_len) = isize::try_from(iov.iov_len) else {
            return Err(Errno::EINVAL);
        };
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        let size = match desc {
            Descriptor::File(file) => litebox_fs()
                .read(file, &mut kernel_buffer, None)
                .map_err(Errno::from)?,
            Descriptor::Stdio(file) => file.read(&mut kernel_buffer, None)?,
            Descriptor::Socket(socket) => todo!(),
            Descriptor::PipeReader { consumer, .. } => todo!(),
            Descriptor::PipeWriter { .. } | Descriptor::Epoll { .. } => return Err(Errno::EINVAL),
            Descriptor::Eventfd { file, .. } => todo!(),
        };
        iov.iov_base
            .copy_from_slice(0, &kernel_buffer[..size])
            .ok_or(Errno::EFAULT)?;
        total_read += size;
        if size < iov.iov_len {
            // Okay to transfer fewer bytes than requested
            break;
        }
    }
    Ok(total_read)
}

fn write_to_iovec<F>(iovs: &[IoWriteVec<ConstPtr<u8>>], write_fn: F) -> Result<usize, Errno>
where
    F: Fn(&[u8]) -> Result<usize, Errno>,
{
    let mut total_written = 0;
    for iov in iovs {
        if iov.iov_len == 0 {
            continue;
        }
        let slice = unsafe { iov.iov_base.to_cow_slice(iov.iov_len) }.ok_or(Errno::EFAULT)?;
        let size = write_fn(&slice)?;
        total_written += size;
        if size < iov.iov_len {
            // Okay to transfer fewer bytes than requested
            break;
        }
    }
    Ok(total_written)
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
    match desc {
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        Descriptor::File(file) => write_to_iovec(iovs, |buf: &[u8]| {
            litebox_fs().write(file, buf, None).map_err(Errno::from)
        }),
        Descriptor::Stdio(file) => write_to_iovec(iovs, |buf: &[u8]| file.write(buf, None)),
        Descriptor::Socket(socket) => {
            let socket = socket.clone();
            drop(locked_file_descriptors);
            write_to_iovec(iovs, |buf: &[u8]| {
                socket.sendto(buf, litebox::net::SendFlags::empty(), None)
            })
        }
        Descriptor::PipeReader { .. } | Descriptor::Epoll { .. } => Err(Errno::EINVAL),
        Descriptor::PipeWriter { producer, .. } => todo!(),
        Descriptor::Eventfd { file, .. } => todo!(),
        _ => todo!(),
    }
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

const PROC_SELF_FD_PREFIX: &str = "/proc/self/fd/";
/// Read the target of a symbolic link
///
/// Note that this function only handles the following cases that we hardcoded:
/// - `/proc/self/fd/<fd>`
fn do_readlink(fullpath: &str) -> Result<String, Errno> {
    // It assumes that the path is absolute. Will fix once #71 is done.
    if let Some(stripped) = fullpath.strip_prefix(PROC_SELF_FD_PREFIX) {
        let fd = stripped.parse::<u32>().map_err(|_| Errno::EINVAL)?;
        let locked_file_descriptors = file_descriptors().read();
        let desc = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
        if let Descriptor::Stdio(crate::stdio::StdioFile { typ, .. }) = desc {
            return match typ {
                litebox::platform::StdioStream::Stdin => Ok("/dev/stdin".to_string()),
                litebox::platform::StdioStream::Stdout => Ok("/dev/stdout".to_string()),
                litebox::platform::StdioStream::Stderr => Ok("/dev/stderr".to_string()),
            };
        }
    }

    // TODO: we do not support symbolic links other than stdio yet.
    Err(Errno::ENOENT)
}

/// Handle syscall `readlink`
pub fn sys_readlink(pathname: impl path::Arg, buf: &mut [u8]) -> Result<usize, Errno> {
    sys_readlinkat(AT_FDCWD, pathname, buf)
}

/// Handle syscall `readlinkat`
pub fn sys_readlinkat(
    dirfd: i32,
    pathname: impl path::Arg,
    buf: &mut [u8],
) -> Result<usize, Errno> {
    let fspath = FsPath::new(dirfd, pathname)?;
    let path = match fspath {
        FsPath::Absolute { path } => do_readlink(path.normalized()?.as_str()),
        _ => todo!(),
    }?;
    let bytes = path.as_bytes();
    let min_len = core::cmp::min(buf.len(), bytes.len());
    buf[..min_len].copy_from_slice(&bytes[..min_len]);
    Ok(min_len)
}

impl Descriptor {
    fn stat(&self) -> Result<FileStat, Errno> {
        let fstat = match self {
            Descriptor::File(file) => FileStat::from(litebox_fs().fd_file_status(file)?),
            Descriptor::Stdio(crate::stdio::StdioFile { inner, .. }) => {
                FileStat::from(litebox_fs().fd_file_status(inner.file())?)
            }
            Descriptor::Socket(socket) => todo!(),
            Descriptor::PipeReader { .. } => FileStat {
                // TODO: give correct values
                st_dev: 0,
                st_ino: 0,
                st_nlink: 1,
                st_mode: (Mode::RUSR.bits() | litebox_common_linux::InodeType::NamedPipe as u32)
                    .truncate(),
                st_uid: 0,
                st_gid: 0,
                st_rdev: 0,
                st_size: 0,
                st_blksize: 4096,
                st_blocks: 0,
                ..Default::default()
            },
            Descriptor::PipeWriter { .. } => FileStat {
                // TODO: give correct values
                st_dev: 0,
                st_ino: 0,
                st_nlink: 1,
                st_mode: (Mode::WUSR.bits() | litebox_common_linux::InodeType::NamedPipe as u32)
                    .truncate(),
                st_uid: 0,
                st_gid: 0,
                st_rdev: 0,
                st_size: 0,
                st_blksize: 4096,
                st_blocks: 0,
                ..Default::default()
            },
            Descriptor::Eventfd { .. } => FileStat {
                // TODO: give correct values
                st_dev: 0,
                st_ino: 0,
                st_nlink: 1,
                st_mode: (Mode::RUSR | Mode::WUSR).bits().truncate(),
                st_uid: 0,
                st_gid: 0,
                st_rdev: 0,
                st_size: 0,
                st_blksize: 4096,
                st_blocks: 0,
                ..Default::default()
            },
            Descriptor::Epoll { .. } => FileStat {
                // TODO: give correct values
                st_dev: 0,
                st_ino: 0,
                st_nlink: 1,
                st_mode: (Mode::RUSR | Mode::WUSR).bits().truncate(),
                st_uid: 0,
                st_gid: 0,
                st_rdev: 0,
                st_size: 0,
                st_blksize: 0,
                st_blocks: 0,
                ..Default::default()
            },
        };
        Ok(fstat)
    }
}

fn do_stat(pathname: impl path::Arg, follow_symlink: bool) -> Result<FileStat, Errno> {
    let normalized_path = pathname.normalized()?;
    let path = if follow_symlink {
        // TODO: `do_readlink` assumes the path is absolute
        do_readlink(normalized_path.as_str()).unwrap_or(normalized_path)
    } else {
        normalized_path
    };
    let stdio_typ = match path.as_str() {
        "/dev/stdin" => Some(litebox::platform::StdioStream::Stdin),
        "/dev/stdout" => Some(litebox::platform::StdioStream::Stdout),
        "/dev/stderr" => Some(litebox::platform::StdioStream::Stderr),
        _ => None,
    };
    let status = litebox_fs().file_status(path)?;
    Ok(FileStat::from(status))
}

/// Handle syscall `stat`
pub fn sys_stat(pathname: impl path::Arg) -> Result<FileStat, Errno> {
    do_stat(pathname, true)
}

/// Handle syscall `lstat`
///
/// `lstat` is identical to `stat`, except that if `pathname` is a symbolic link,
/// then it returns information about the link itself, not the file that the link refers to.
/// TODO: we do not support symbolic links yet.
pub fn sys_lstat(pathname: impl path::Arg) -> Result<FileStat, Errno> {
    do_stat(pathname, false)
}

/// Handle syscall `fstat`
pub fn sys_fstat(fd: i32) -> Result<FileStat, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };
    file_descriptors()
        .read()
        .get_fd(fd)
        .ok_or(Errno::EBADF)?
        .stat()
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
    let fstat: FileStat = match fs_path {
        FsPath::Absolute { path } | FsPath::CwdRelative { path } => {
            do_stat(path, !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW))?
        }
        FsPath::Cwd => litebox_fs().file_status("")?.into(),
        FsPath::Fd(fd) => file_descriptors()
            .read()
            .get_fd(fd)
            .ok_or(Errno::EBADF)
            .and_then(Descriptor::stat)?,
        FsPath::FdRelative { fd, path } => todo!(),
    };
    Ok(fstat)
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
                    Descriptor::PipeReader { close_on_exec, .. }
                    | Descriptor::PipeWriter { close_on_exec, .. }
                    | Descriptor::Eventfd { close_on_exec, .. }
                    | Descriptor::Epoll { close_on_exec, .. }
                    | Descriptor::Stdio(crate::stdio::StdioFile { close_on_exec, .. }) => {
                        if close_on_exec.load(core::sync::atomic::Ordering::Relaxed) {
                            FileDescriptorFlags::FD_CLOEXEC
                        } else {
                            FileDescriptorFlags::empty()
                        }
                    }
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
                Descriptor::PipeReader { close_on_exec, .. }
                | Descriptor::PipeWriter { close_on_exec, .. }
                | Descriptor::Eventfd { close_on_exec, .. }
                | Descriptor::Epoll { close_on_exec, .. }
                | Descriptor::Stdio(crate::stdio::StdioFile { close_on_exec, .. }) => {
                    close_on_exec.store(
                        flags.contains(FileDescriptorFlags::FD_CLOEXEC),
                        core::sync::atomic::Ordering::Relaxed,
                    );
                }
            }
            Ok(0)
        }
        FcntlArg::GETFL => match desc {
            Descriptor::File(file) => todo!(),
            Descriptor::Socket(socket) => todo!(),
            Descriptor::PipeReader { consumer, .. } => Ok(consumer.get_status().bits()),
            Descriptor::PipeWriter { producer, .. } => Ok(producer.get_status().bits()),
            Descriptor::Eventfd { file, .. } => Ok(file.get_status().bits()),
            Descriptor::Epoll { file, .. } => Ok(file.get_status().bits()),
            Descriptor::Stdio(file) => Ok(file.inner.get_status().bits()),
        },
        FcntlArg::SETFL(flags) => {
            let setfl_mask = OFlags::APPEND
                | OFlags::NONBLOCK
                | OFlags::NDELAY
                | OFlags::DIRECT
                | OFlags::NOATIME;
            macro_rules! toggle_flags {
                ($t:ident) => {
                    let diff = $t.get_status() ^ flags;
                    if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                        todo!("unsupported flags");
                    }
                    $t.set_status(flags & setfl_mask, true);
                    $t.set_status(flags.complement() & setfl_mask, false);
                };
            }
            match desc {
                Descriptor::File(file) => todo!(),
                Descriptor::Stdio(file) => {
                    let f = &file.inner;
                    toggle_flags!(f);
                }
                Descriptor::Socket(socket) => todo!(),
                Descriptor::PipeReader { consumer, .. } => {
                    toggle_flags!(consumer);
                }
                Descriptor::PipeWriter { producer, .. } => {
                    toggle_flags!(producer);
                }
                Descriptor::Eventfd { file, .. } => {
                    toggle_flags!(file);
                }
                Descriptor::Epoll { file, .. } => todo!(),
            }
            Ok(0)
        }
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

const DEFAULT_PIPE_BUF_SIZE: usize = 1024 * 1024;
/// Handle syscall `pipe2`
pub fn sys_pipe2(flags: OFlags) -> Result<(u32, u32), Errno> {
    if flags.contains((OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::DIRECT).complement()) {
        return Err(Errno::EINVAL);
    }

    if flags.contains(litebox::fs::OFlags::DIRECT) {
        todo!("O_DIRECT not supported");
    }

    let (writer, reader) =
        crate::channel::Channel::new(DEFAULT_PIPE_BUF_SIZE, flags, crate::litebox()).split();
    let close_on_exec = flags.contains(OFlags::CLOEXEC);
    let read_fd = file_descriptors().write().insert(Descriptor::PipeReader {
        consumer: reader,
        close_on_exec: core::sync::atomic::AtomicBool::new(close_on_exec),
    });
    let write_fd = file_descriptors().write().insert(Descriptor::PipeWriter {
        producer: writer,
        close_on_exec: core::sync::atomic::AtomicBool::new(close_on_exec),
    });
    Ok((read_fd, write_fd))
}

pub fn sys_eventfd2(initval: u32, flags: EfdFlags) -> Result<u32, Errno> {
    if flags.contains((EfdFlags::SEMAPHORE | EfdFlags::CLOEXEC | EfdFlags::NONBLOCK).complement()) {
        return Err(Errno::EINVAL);
    }

    let eventfd = super::eventfd::EventFile::new(u64::from(initval), flags, crate::litebox());
    let fd = file_descriptors().write().insert(Descriptor::Eventfd {
        file: alloc::sync::Arc::new(eventfd),
        close_on_exec: core::sync::atomic::AtomicBool::new(flags.contains(EfdFlags::CLOEXEC)),
    });
    Ok(fd)
}

fn stdio_ioctl(
    file: &crate::stdio::StdioFile,
    arg: IoctlArg<litebox_platform_multiplex::Platform>,
) -> Result<u32, Errno> {
    match arg {
        IoctlArg::TCGETS(termios) => {
            unsafe {
                termios.write_at_offset(
                    0,
                    litebox_common_linux::Termios {
                        c_iflag: 0,
                        c_oflag: 0,
                        c_cflag: 0,
                        c_lflag: 0,
                        c_line: 0,
                        c_cc: [0; 19],
                    },
                )
            }
            .ok_or(Errno::EFAULT)?;
            Ok(0)
        }
        IoctlArg::TCSETS(_) => Ok(0), // TODO: implement
        IoctlArg::TIOCGWINSZ(ws) => unsafe {
            ws.write_at_offset(
                0,
                litebox_common_linux::Winsize {
                    row: 20,
                    col: 20,
                    xpixel: 0,
                    ypixel: 0,
                },
            )
            .ok_or(Errno::EFAULT)?;
            Ok(0)
        },
        IoctlArg::TIOCGPTN(_) => Err(Errno::ENOTTY),
        _ => todo!(),
    }
}

/// Handle syscall `ioctl`
pub fn sys_ioctl(
    fd: i32,
    arg: IoctlArg<litebox_platform_multiplex::Platform>,
) -> Result<u32, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };

    let locked_file_descriptors = file_descriptors().read();
    let desc = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
    if let IoctlArg::FIONBIO(arg) = arg {
        let val = unsafe { arg.read_at_offset(0) }
            .ok_or(Errno::EFAULT)?
            .into_owned();
        match desc {
            Descriptor::File(file) => todo!(),
            Descriptor::Stdio(file) => {
                file.inner.set_status(OFlags::NONBLOCK, val != 0);
            }
            Descriptor::Socket(socket) => todo!(),
            Descriptor::PipeReader { consumer, .. } => {
                consumer.set_status(OFlags::NONBLOCK, val != 0);
            }
            Descriptor::PipeWriter { producer, .. } => {
                producer.set_status(OFlags::NONBLOCK, val != 0);
            }
            Descriptor::Eventfd { file, .. } => file.set_status(OFlags::NONBLOCK, val != 0),
            Descriptor::Epoll { file, .. } => {
                file.set_status(OFlags::NONBLOCK, val != 0);
            }
        }
        return Ok(0);
    }

    match desc {
        Descriptor::Stdio(file) => stdio_ioctl(file, arg),
        Descriptor::File(file) => todo!(),
        Descriptor::Socket(socket) => todo!(),
        Descriptor::PipeReader {
            consumer,
            close_on_exec,
        } => todo!(),
        Descriptor::PipeWriter {
            producer,
            close_on_exec,
        } => todo!(),
        Descriptor::Eventfd {
            file,
            close_on_exec,
        } => todo!(),
        Descriptor::Epoll {
            file,
            close_on_exec,
        } => todo!(),
    }
}

/// Handle syscall `epoll_create` and `epoll_create1`
pub fn sys_epoll_create(flags: EpollCreateFlags) -> Result<u32, Errno> {
    if flags.contains(EpollCreateFlags::EPOLL_CLOEXEC.complement()) {
        return Err(Errno::EINVAL);
    }

    let epoll_file = super::epoll::EpollFile::new(crate::litebox());
    let fd = file_descriptors().write().insert(Descriptor::Epoll {
        file: alloc::sync::Arc::new(epoll_file),
        close_on_exec: core::sync::atomic::AtomicBool::new(
            flags.contains(EpollCreateFlags::EPOLL_CLOEXEC),
        ),
    });
    Ok(fd)
}

/// Handle syscall `epoll_ctl`
pub fn sys_epoll_ctl(
    epfd: i32,
    op: litebox_common_linux::EpollOp,
    fd: i32,
    event: ConstPtr<litebox_common_linux::EpollEvent>,
) -> Result<(), Errno> {
    let Ok(epfd) = u32::try_from(epfd) else {
        return Err(Errno::EBADF);
    };
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };
    if epfd == fd {
        return Err(Errno::EINVAL);
    }

    let locked_file_descriptors = file_descriptors().read();
    let epoll_entry = locked_file_descriptors.get_fd(epfd).ok_or(Errno::EBADF)?;
    let Descriptor::Epoll { file: epoll, .. } = epoll_entry else {
        return Err(Errno::EBADF);
    };

    let file = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
    let event = if op == litebox_common_linux::EpollOp::EpollCtlDel {
        None
    } else {
        Some(
            unsafe { event.read_at_offset(0) }
                .ok_or(Errno::EFAULT)?
                .into_owned(),
        )
    };
    epoll.epoll_ctl(op, fd, file, event)
}

/// Handle syscall `epoll_pwait`
pub fn sys_epoll_pwait(
    epfd: i32,
    events: MutPtr<litebox_common_linux::EpollEvent>,
    maxevents: u32,
    timeout: i32,
    sigmask: Option<ConstPtr<litebox_common_linux::SigSet>>,
    _sigsetsize: usize,
) -> Result<usize, Errno> {
    if sigmask.is_some() {
        todo!("sigmask not supported");
    }
    let Ok(epfd) = u32::try_from(epfd) else {
        return Err(Errno::EBADF);
    };
    let maxevents = maxevents as usize;
    if maxevents == 0
        || maxevents > i32::MAX as usize / size_of::<litebox_common_linux::EpollEvent>()
    {
        return Err(Errno::EINVAL);
    }
    let timeout = if timeout >= 0 {
        #[allow(clippy::cast_sign_loss, reason = "timeout is a positive integer")]
        Some(core::time::Duration::from_millis(timeout as u64))
    } else {
        None
    };
    let epoll_file = {
        let locked_file_descriptors = file_descriptors().read();
        match locked_file_descriptors.get_fd(epfd).ok_or(Errno::EBADF)? {
            Descriptor::Epoll { file, .. } => file.clone(),
            _ => return Err(Errno::EBADF),
        }
    };
    let epoll_events = epoll_file.wait(maxevents, timeout)?;
    if !epoll_events.is_empty() {
        events
            .copy_from_slice(0, &epoll_events)
            .ok_or(Errno::EFAULT)?;
    }
    Ok(epoll_events.len())
}

fn do_dup(file: &Descriptor, flags: OFlags) -> Descriptor {
    match file {
        Descriptor::Stdio(file) => Descriptor::Stdio(file.dup(flags.contains(OFlags::CLOEXEC))),
        _ => todo!(),
    }
}

/// Handle syscall `dup/dup2/dup3`
///
/// The dup() system call creates a copy of the file descriptor oldfd, using the lowest-numbered unused file descriptor for the new descriptor.
/// The dup2() system call performs the same task as dup(), but instead of using the lowest-numbered unused file descriptor, it uses the file descriptor number specified in newfd.
/// The dup3() system call is similar to dup2(), but it also takes an additional flags argument that can be used to set the close-on-exec flag for the new file descriptor.
pub fn sys_dup(oldfd: i32, newfd: Option<i32>, flags: Option<OFlags>) -> Result<u32, Errno> {
    let Ok(oldfd) = u32::try_from(oldfd) else {
        return Err(Errno::EBADF);
    };
    let new_file = file_descriptors()
        .read()
        .get_fd(oldfd)
        .ok_or(Errno::EBADF)
        .map(|desc| do_dup(desc, flags.unwrap_or(OFlags::empty())))?;
    if let Some(newfd) = newfd {
        // dup2/dup3
        let Ok(newfd) = u32::try_from(newfd) else {
            return Err(Errno::EBADF);
        };
        if oldfd == newfd {
            // Different from dup3, if oldfd is a valid file descriptor, and newfd has the same value
            // as oldfd, then dup2() does nothing.
            return if flags.is_some() {
                // dup3
                Err(Errno::EINVAL)
            } else {
                // dup2
                Ok(oldfd)
            };
        }

        if let Some(old_file) = file_descriptors()
            .write()
            .insert_at(new_file, newfd as usize)
        {
            do_close(old_file)?;
        }
        Ok(newfd)
    } else {
        // dup
        Ok(file_descriptors().write().insert(new_file))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Diroff(usize);

const DIRENT_STRUCT_BYTES_WITHOUT_NAME: usize =
    core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name);

/// Handle syscall `getdents64`
pub(crate) fn sys_getdirent64(fd: i32, dirp: MutPtr<u8>, count: usize) -> Result<usize, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };
    let locked_file_descriptors = file_descriptors().read();
    let Descriptor::File(file) = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)? else {
        return Err(Errno::EBADF);
    };
    let dir_off: Diroff = litebox_fs()
        .with_metadata(file, |off: &Diroff| *off)
        .unwrap_or_default();
    let mut dir_off = dir_off.0;
    let mut nbytes = 0;
    let off = 0;

    let mut entries = litebox_fs().read_dir(file)?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    for entry in entries.iter().skip(dir_off) {
        // include null terminator and make it aligned
        let len = (DIRENT_STRUCT_BYTES_WITHOUT_NAME + entry.name.len() + 1)
            .next_multiple_of(align_of::<litebox_common_linux::LinuxDirent64>());
        if nbytes + len > count {
            // not enough space
            break;
        }
        let dirent64 = litebox_common_linux::LinuxDirent64 {
            ino: entry.ino_info.as_ref().map_or(0, |node_info| node_info.ino) as u64,
            off: dir_off as u64,
            len: len.truncate(),
            typ: litebox_common_linux::DirentType::from(entry.file_type.clone()) as u8,
            __name: [0; 0],
        };
        let hdr_ptr = crate::MutPtr::from_usize(dirp.as_usize() + nbytes);
        unsafe { hdr_ptr.write_at_offset(0, dirent64) }.ok_or(Errno::EFAULT)?;
        let name_ptr =
            crate::MutPtr::from_usize(hdr_ptr.as_usize() + DIRENT_STRUCT_BYTES_WITHOUT_NAME);
        unsafe { name_ptr.write_slice_at_offset(0, entry.name.as_bytes()) }.ok_or(Errno::EFAULT)?;
        // set the null terminator and padding
        let zeros_len = len - (DIRENT_STRUCT_BYTES_WITHOUT_NAME + entry.name.len());
        unsafe {
            name_ptr.write_slice_at_offset(
                isize::try_from(entry.name.len()).unwrap(),
                &vec![0; zeros_len],
            )
        }
        .ok_or(Errno::EFAULT)?;
        nbytes += len;
        dir_off += 1;
    }
    let _ = litebox_fs()
        .set_fd_metadata(file, Diroff(dir_off))
        .expect("failed to set dir offset");
    Ok(nbytes)
}
