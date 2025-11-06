//! Implementation of file related syscalls, e.g., `open`, `read`, `write`, etc.

use alloc::{
    ffi::CString,
    string::{String, ToString as _},
    vec,
};
use litebox::{
    event::Events,
    fd::{FdEnabledSubsystem, MetadataError, TypedFd},
    fs::{FileSystem as _, Mode, OFlags, SeekWhence},
    path,
    platform::{RawConstPointer, RawMutPointer},
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt as _},
};
use litebox_common_linux::{
    AtFlags, EfdFlags, EpollCreateFlags, FcntlArg, FileDescriptorFlags, FileStat, IoReadVec,
    IoWriteVec, IoctlArg, errno::Errno,
};
use litebox_platform_multiplex::Platform;

use crate::{ConstPtr, Descriptor, Descriptors, MutPtr, Task, litebox, litebox_pipes};
use core::sync::atomic::Ordering;

/// Task state shared by `CLONE_FS`.
pub(crate) struct FsState {
    umask: core::sync::atomic::AtomicU32,
}

impl Clone for FsState {
    fn clone(&self) -> Self {
        Self {
            umask: self.umask.load(Ordering::Relaxed).into(),
        }
    }
}

impl FsState {
    pub fn new() -> Self {
        Self {
            umask: (Mode::WGRP | Mode::WOTH).bits().into(),
        }
    }

    fn umask(&self) -> Mode {
        Mode::from_bits_retain(self.umask.load(Ordering::Relaxed))
    }
}

/// Task state shared by `CLONE_FILES`.
pub(crate) struct FilesState {
    pub file_descriptors: litebox::sync::RwLock<Platform, Descriptors>,
    pub raw_descriptor_store: litebox::sync::RwLock<Platform, litebox::fd::RawDescriptorStorage>,
}

impl FilesState {
    pub fn new(litebox: &litebox::LiteBox<Platform>) -> Self {
        Self {
            file_descriptors: litebox.sync().new_rwlock(Descriptors::new()),
            raw_descriptor_store: litebox
                .sync()
                .new_rwlock(litebox::fd::RawDescriptorStorage::new()),
        }
    }
}

/// Path in the file system
enum FsPath<P: path::Arg> {
    /// Absolute path
    Absolute { path: P },
    /// Path is relative to `cwd`
    CwdRelative { path: P },
    /// Current working directory
    Cwd,
    /// Path is relative to a file descriptor
    #[expect(dead_code, reason = "currently unused, might want to use later")]
    FdRelative { fd: u32, path: P },
    /// Fd
    Fd(u32),
}

/// Maximum size of a file path
pub const PATH_MAX: usize = 4096;

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
        } else if dirfd == litebox_common_linux::AT_FDCWD {
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

impl Task {
    fn get_umask(&self) -> Mode {
        self.fs.borrow().umask()
    }

    /// Handle syscall `umask`
    pub(crate) fn sys_umask(&self, new_mask: u32) -> Mode {
        let new_mask = Mode::from_bits_truncate(new_mask) & (Mode::RWXU | Mode::RWXG | Mode::RWXO);
        let old_mask = self
            .fs
            .borrow()
            .umask
            .swap(new_mask.bits(), Ordering::Relaxed);
        Mode::from_bits_retain(old_mask)
    }

    /// Handle syscall `open`
    pub fn sys_open(&self, path: impl path::Arg, flags: OFlags, mode: Mode) -> Result<u32, Errno> {
        let mode = mode & !self.get_umask();
        let file = self.global.fs.open(path, flags - OFlags::CLOEXEC, mode)?;
        if flags.contains(OFlags::CLOEXEC) {
            let None = litebox()
                .descriptor_table_mut()
                .set_fd_metadata(&file, FileDescriptorFlags::FD_CLOEXEC)
            else {
                unreachable!()
            };
        }
        let files = self.files.borrow();
        let raw_fd = files.raw_descriptor_store.write().fd_into_raw_integer(file);
        files
            .file_descriptors
            .write()
            .insert(self, Descriptor::LiteBoxRawFd(raw_fd))
            .map_err(|desc| self.do_close(desc).err().unwrap_or(Errno::EMFILE))
    }

    /// Handle syscall `openat`
    pub fn sys_openat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<u32, Errno> {
        let fs_path = FsPath::new(dirfd, pathname)?;
        match fs_path {
            FsPath::Absolute { path } | FsPath::CwdRelative { path } => {
                self.sys_open(path, flags, mode)
            }
            FsPath::Cwd => self.sys_open("", flags, mode),
            FsPath::Fd(_fd) => todo!(),
            FsPath::FdRelative { fd: _, path: _ } => todo!(),
        }
    }

    /// Handle syscall `ftruncate`
    pub(crate) fn sys_ftruncate(&self, fd: i32, length: usize) -> Result<(), Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        let desc = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
        match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => self.files.borrow().run_on_raw_fd(
                *raw_fd,
                |fd| {
                    self.global
                        .fs
                        .truncate(fd, length, false)
                        .map_err(Errno::from)
                },
                |_fd| todo!("net"),
                |_fd| todo!("pipes"),
            ),
            _ => Err(Errno::EINVAL),
        }
        .flatten()
    }

    /// Handle syscall `unlinkat`
    pub(crate) fn sys_unlinkat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
    ) -> Result<(), Errno> {
        if flags.intersects(AtFlags::AT_REMOVEDIR.complement()) {
            return Err(Errno::EINVAL);
        }

        let fs_path = FsPath::new(dirfd, pathname)?;
        match fs_path {
            FsPath::Absolute { path } | FsPath::CwdRelative { path } => {
                if flags.contains(AtFlags::AT_REMOVEDIR) {
                    self.global.fs.rmdir(path).map_err(Errno::from)
                } else {
                    self.global.fs.unlink(path).map_err(Errno::from)
                }
            }
            FsPath::Cwd => Err(Errno::EINVAL),
            FsPath::Fd(_) | FsPath::FdRelative { .. } => unimplemented!(),
        }
    }

    /// Handle syscall `read`
    ///
    /// `offset` is an optional offset to read from. If `None`, it will read from the current file position.
    /// If `Some`, it will read from the specified offset without changing the current file position.
    pub fn sys_read(&self, fd: i32, buf: &mut [u8], offset: Option<usize>) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        let desc = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
        match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                let raw_fd = *raw_fd;
                drop(file_table);
                // We need to do this cell dance because otherwise Rust can't recognize that the two
                // closures are mutually exclusive.
                let buf: core::cell::RefCell<&mut [u8]> = core::cell::RefCell::new(buf);
                files
                    .run_on_raw_fd(
                        raw_fd,
                        |fd| {
                            self.global
                                .fs
                                .read(fd, &mut buf.borrow_mut(), offset)
                                .map_err(Errno::from)
                        },
                        |fd| {
                            super::net::receive(
                                fd,
                                &mut buf.borrow_mut(),
                                litebox_common_linux::ReceiveFlags::empty(),
                                None,
                            )
                        },
                        |fd| {
                            litebox_pipes()
                                .read()
                                .read(fd, &mut buf.borrow_mut())
                                .map_err(Errno::from)
                        },
                    )
                    .flatten()
            }
            Descriptor::Epoll { .. } => Err(Errno::EINVAL),
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
    pub fn sys_write(&self, fd: i32, buf: &[u8], offset: Option<usize>) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        let desc = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
        match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                let raw_fd = *raw_fd;
                drop(file_table);
                files
                    .run_on_raw_fd(
                        raw_fd,
                        |fd| self.global.fs.write(fd, buf, offset).map_err(Errno::from),
                        |fd| {
                            super::net::sendto(
                                fd,
                                buf,
                                litebox_common_linux::SendFlags::empty(),
                                None,
                            )
                        },
                        |fd| litebox_pipes().read().write(fd, buf).map_err(Errno::from),
                    )
                    .flatten()
            }
            Descriptor::Epoll { .. } => Err(Errno::EINVAL),
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
    pub fn sys_pread64(&self, fd: i32, buf: &mut [u8], offset: i64) -> Result<usize, Errno> {
        let pos = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.sys_read(fd, buf, Some(pos))
    }

    /// Handle syscall `pwrite64`
    pub fn sys_pwrite64(&self, fd: i32, buf: &[u8], offset: i64) -> Result<usize, Errno> {
        let pos = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.sys_write(fd, buf, Some(pos))
    }
}

const SEEK_SET: i16 = 0;
const SEEK_CUR: i16 = 1;
const SEEK_END: i16 = 2;

pub(crate) fn try_into_whence(value: i16) -> Result<SeekWhence, i16> {
    match value {
        SEEK_SET => Ok(SeekWhence::RelativeToBeginning),
        SEEK_CUR => Ok(SeekWhence::RelativeToCurrentOffset),
        SEEK_END => Ok(SeekWhence::RelativeToEnd),
        _ => Err(value),
    }
}

impl Task {
    /// Handle syscall `lseek`
    pub fn sys_lseek(&self, fd: i32, offset: isize, whence: SeekWhence) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        let desc = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
        match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => files
                .run_on_raw_fd(
                    *raw_fd,
                    |fd| self.global.fs.seek(fd, offset, whence).map_err(Errno::from),
                    |_| Err(Errno::ESPIPE),
                    |_| Err(Errno::ESPIPE),
                )
                .flatten(),
            Descriptor::Epoll { .. } | Descriptor::Eventfd { .. } => Err(Errno::ESPIPE),
        }
    }

    /// Handle syscall `mkdir`
    pub fn sys_mkdir(&self, pathname: impl path::Arg, mode: u32) -> Result<(), Errno> {
        let mode = Mode::from_bits_retain(mode) & !self.get_umask();
        self.global.fs.mkdir(pathname, mode).map_err(Errno::from)
    }

    pub(crate) fn do_close(&self, desc: Descriptor) -> Result<(), Errno> {
        let files = self.files.borrow();
        match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                let mut rds = files.raw_descriptor_store.write();
                match rds.fd_consume_raw_integer(raw_fd) {
                    Ok(fd) => {
                        drop(rds);
                        self.global.fs.close(&fd).map_err(Errno::from)
                    }
                    Err(litebox::fd::ErrRawIntFd::NotFound) => Err(Errno::EBADF),
                    Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => {
                        match rds
                        .fd_consume_raw_integer::<litebox::net::Network<litebox_platform_multiplex::Platform>>(raw_fd)
                    {
                        Ok(fd) => {
                            drop(rds);
                            crate::litebox_net().lock().close(&fd).map_err(Errno::from)
                        },
                        Err(litebox::fd::ErrRawIntFd::NotFound) => Err(Errno::EBADF),
                        Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => {
                            match rds.fd_consume_raw_integer::<litebox::pipes::Pipes<litebox_platform_multiplex::Platform>>(raw_fd) {
                                Ok(fd) => {
                                    drop(rds);
                                    litebox_pipes().read().close(&fd).map_err(Errno::from)
                                }
                                Err(litebox::fd::ErrRawIntFd::NotFound) => Err(Errno::EBADF),
                                Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => {
                                    // We currently only have fs, net and pipes FDs at the moment,
                                    // if/when we add more, we need to expand this out too.
                                    unreachable!()
                                }
                            }
                        }
                    }
                    }
                }
            }
            Descriptor::Eventfd { .. } | Descriptor::Epoll { .. } => Ok(()),
        }
    }

    /// Handle syscall `close`
    pub fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        match files.file_descriptors.write().remove(fd) {
            Some(desc) => self.do_close(desc),
            None => Err(Errno::EBADF),
        }
    }

    /// Handle syscall `readv`
    pub fn sys_readv(
        &self,
        fd: i32,
        iovec: ConstPtr<IoReadVec<MutPtr<u8>>>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let iovs: &[IoReadVec<MutPtr<u8>>] =
            unsafe { &iovec.to_cow_slice(iovcnt).ok_or(Errno::EFAULT)? };
        let files = self.files.borrow();
        let locked_file_descriptors = files.file_descriptors.read();
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
            let Ok(_iov_len) = isize::try_from(iov.iov_len) else {
                return Err(Errno::EINVAL);
            };
            // TODO: The data transfers performed by readv() and writev() are atomic: the data
            // written by writev() is written as a single block that is not intermingled with
            // output from writes in other processes
            let size = match desc {
                Descriptor::LiteBoxRawFd(raw_fd) => files
                    .run_on_raw_fd(
                        *raw_fd,
                        |fd| {
                            self.global
                                .fs
                                .read(fd, &mut kernel_buffer, None)
                                .map_err(Errno::from)
                        },
                        |_fd| todo!("net"),
                        |_fd| todo!("pipes"),
                    )
                    .flatten()?,
                Descriptor::Epoll { .. } => return Err(Errno::EINVAL),
                Descriptor::Eventfd { .. } => todo!(),
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

impl Task {
    /// Handle syscall `writev`
    pub fn sys_writev(
        &self,
        fd: i32,
        iovec: ConstPtr<IoWriteVec<ConstPtr<u8>>>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let iovs: &[IoWriteVec<ConstPtr<u8>>] =
            unsafe { &iovec.to_cow_slice(iovcnt).ok_or(Errno::EFAULT)? };
        let files = self.files.borrow();
        let locked_file_descriptors = files.file_descriptors.read();
        let desc = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => files
                .run_on_raw_fd(
                    *raw_fd,
                    |fd| {
                        write_to_iovec(iovs, |buf: &[u8]| {
                            self.global.fs.write(fd, buf, None).map_err(Errno::from)
                        })
                    },
                    |fd| {
                        write_to_iovec(iovs, |buf: &[u8]| {
                            super::net::sendto(
                                fd,
                                buf,
                                litebox_common_linux::SendFlags::empty(),
                                None,
                            )
                        })
                    },
                    |_fd| todo!("pipes"),
                )
                .flatten(),
            Descriptor::Epoll { .. } => Err(Errno::EINVAL),
            Descriptor::Eventfd { .. } => todo!(),
        }
    }

    /// Handle syscall `access`
    pub fn sys_access(
        &self,
        pathname: impl path::Arg,
        mode: litebox_common_linux::AccessFlags,
    ) -> Result<(), Errno> {
        let status = self.global.fs.file_status(pathname)?;
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

    /// Read the target of a symbolic link
    ///
    /// Note that this function only handles the following cases that we hardcoded:
    /// - `/proc/self/fd/<fd>`
    fn do_readlink(&self, fullpath: &str) -> Result<String, Errno> {
        // It assumes that the path is absolute. Will fix once #71 is done.
        if let Some(stripped) = fullpath.strip_prefix("/proc/self/fd/") {
            let fd = stripped.parse::<u32>().map_err(|_| Errno::EINVAL)?;
            match fd {
                0 => return Ok("/dev/stdin".to_string()),
                1 => return Ok("/dev/stdout".to_string()),
                2 => return Ok("/dev/stderr".to_string()),
                _ => unimplemented!(),
            }
        }

        // TODO: we do not support symbolic links other than stdio yet.
        Err(Errno::ENOENT)
    }

    /// Handle syscall `readlink`
    pub fn sys_readlink(&self, pathname: impl path::Arg, buf: &mut [u8]) -> Result<usize, Errno> {
        self.sys_readlinkat(litebox_common_linux::AT_FDCWD, pathname, buf)
    }

    /// Handle syscall `readlinkat`
    pub fn sys_readlinkat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        buf: &mut [u8],
    ) -> Result<usize, Errno> {
        let fspath = FsPath::new(dirfd, pathname)?;
        let path = match fspath {
            FsPath::Absolute { path } => self.do_readlink(path.normalized()?.as_str()),
            // Note we don't support changing cwd yet; cwd is always `/`.
            FsPath::Cwd => self.do_readlink("/"),
            FsPath::CwdRelative { path } => {
                let normalized_path = path.normalized()?;
                let full_path = alloc::format!("/{}", normalized_path.as_str());
                self.do_readlink(&full_path)
            }
            FsPath::Fd(_) | FsPath::FdRelative { .. } => unimplemented!(),
        }?;
        let bytes = path.as_bytes();
        let min_len = core::cmp::min(buf.len(), bytes.len());
        buf[..min_len].copy_from_slice(&bytes[..min_len]);
        Ok(min_len)
    }
}

impl Descriptor {
    fn stat(&self, task: &Task) -> Result<FileStat, Errno> {
        let fstat = match self {
            Descriptor::LiteBoxRawFd(raw_fd) => task
                .files
                .borrow()
                .run_on_raw_fd(
                    *raw_fd,
                    |fd| {
                        task.global
                            .fs
                            .fd_file_status(fd)
                            .map(FileStat::from)
                            .map_err(Errno::from)
                    },
                    |_fd| todo!("net"),
                    |fd| {
                        let half_pipe_type = litebox_pipes().read().half_pipe_type(fd)?;
                        let read_write_mode = match half_pipe_type {
                            litebox::pipes::HalfPipeType::SenderHalf => Mode::WUSR,
                            litebox::pipes::HalfPipeType::ReceiverHalf => Mode::RUSR,
                        };
                        Ok(FileStat {
                            // TODO: give correct values
                            st_dev: 0,
                            st_ino: 0,
                            st_nlink: 1,
                            st_mode: (read_write_mode.bits()
                                | litebox_common_linux::InodeType::NamedPipe as u32)
                                .truncate(),
                            st_uid: 0,
                            st_gid: 0,
                            st_rdev: 0,
                            st_size: 0,
                            st_blksize: 4096,
                            st_blocks: 0,
                            ..Default::default()
                        })
                    },
                )
                .flatten()?,
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

    pub(crate) fn get_file_descriptor_flags(
        &self,
        files: &FilesState,
    ) -> Result<FileDescriptorFlags, Errno> {
        // Currently, only one such flag is defined: FD_CLOEXEC, the close-on-exec flag.
        // See https://www.man7.org/linux/man-pages/man2/F_GETFD.2const.html
        fn get_flags<S: FdEnabledSubsystem>(fd: &TypedFd<S>) -> FileDescriptorFlags {
            litebox()
                .descriptor_table()
                .with_metadata(fd, |flags: &FileDescriptorFlags| *flags)
                .unwrap_or(FileDescriptorFlags::empty())
        }
        match self {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                files.run_on_raw_fd(*raw_fd, get_flags, get_flags, get_flags)
            }
            Descriptor::Eventfd { close_on_exec, .. } | Descriptor::Epoll { close_on_exec, .. } => {
                Ok(
                    if close_on_exec.load(core::sync::atomic::Ordering::Relaxed) {
                        FileDescriptorFlags::FD_CLOEXEC
                    } else {
                        FileDescriptorFlags::empty()
                    },
                )
            }
        }
    }
}

impl Task {
    fn do_stat(&self, pathname: impl path::Arg, follow_symlink: bool) -> Result<FileStat, Errno> {
        let normalized_path = pathname.normalized()?;
        let path = if follow_symlink {
            // TODO: `do_readlink` assumes the path is absolute
            self.do_readlink(normalized_path.as_str())
                .unwrap_or(normalized_path)
        } else {
            normalized_path
        };
        let status = self.global.fs.file_status(path)?;
        Ok(FileStat::from(status))
    }

    /// Handle syscall `stat`
    pub fn sys_stat(&self, pathname: impl path::Arg) -> Result<FileStat, Errno> {
        self.do_stat(pathname, true)
    }

    /// Handle syscall `lstat`
    ///
    /// `lstat` is identical to `stat`, except that if `pathname` is a symbolic link,
    /// then it returns information about the link itself, not the file that the link refers to.
    /// TODO: we do not support symbolic links yet.
    pub fn sys_lstat(&self, pathname: impl path::Arg) -> Result<FileStat, Errno> {
        self.do_stat(pathname, false)
    }

    /// Handle syscall `fstat`
    pub fn sys_fstat(&self, fd: i32) -> Result<FileStat, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files
            .file_descriptors
            .read()
            .get_fd(fd)
            .ok_or(Errno::EBADF)?
            .stat(self)
    }

    /// Handle syscall `newfstatat`
    pub fn sys_newfstatat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
    ) -> Result<FileStat, Errno> {
        let current_support_flags = AtFlags::AT_EMPTY_PATH;
        if flags.contains(current_support_flags.complement()) {
            todo!("unsupported flags");
        }

        let files = self.files.borrow();
        let fs_path = FsPath::new(dirfd, pathname)?;
        let fstat: FileStat = match fs_path {
            FsPath::Absolute { path } | FsPath::CwdRelative { path } => {
                self.do_stat(path, !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW))?
            }
            FsPath::Cwd => self.global.fs.file_status("")?.into(),
            FsPath::Fd(fd) => files
                .file_descriptors
                .read()
                .get_fd(fd)
                .ok_or(Errno::EBADF)?
                .stat(self)?,
            FsPath::FdRelative { .. } => todo!(),
        };
        Ok(fstat)
    }

    pub(crate) fn sys_fcntl(
        &self,
        fd: i32,
        arg: FcntlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        let locked_file_descriptors = files.file_descriptors.read();
        let desc = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
        match arg {
            FcntlArg::GETFD => Ok(locked_file_descriptors
                .get_fd(fd)
                .ok_or(Errno::EBADF)?
                .get_file_descriptor_flags(&files)?
                .bits()),
            FcntlArg::SETFD(flags) => {
                match locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)? {
                    Descriptor::LiteBoxRawFd(raw_fd) => files.run_on_raw_fd(
                        *raw_fd,
                        |fd| {
                            let _old = litebox().descriptor_table_mut().set_fd_metadata(fd, flags);
                        },
                        |fd| {
                            let _old = litebox().descriptor_table_mut().set_fd_metadata(fd, flags);
                        },
                        |fd| {
                            let _old = litebox().descriptor_table_mut().set_fd_metadata(fd, flags);
                        },
                    )?,
                    Descriptor::Eventfd { close_on_exec, .. }
                    | Descriptor::Epoll { close_on_exec, .. } => {
                        close_on_exec.store(
                            flags.contains(FileDescriptorFlags::FD_CLOEXEC),
                            core::sync::atomic::Ordering::Relaxed,
                        );
                    }
                }
                Ok(0)
            }
            FcntlArg::GETFL => match desc {
                Descriptor::LiteBoxRawFd(raw_fd) => Ok(files
                    .run_on_raw_fd(
                        *raw_fd,
                        |fd| {
                            Ok(litebox()
                                .descriptor_table()
                                .with_metadata(fd, |crate::StdioStatusFlags(flags)| {
                                    *flags & OFlags::STATUS_FLAGS_MASK
                                })
                                .unwrap_or(OFlags::empty()))
                        },
                        |fd| {
                            Ok(litebox()
                                .descriptor_table()
                                .with_metadata(fd, |crate::syscalls::net::SocketOFlags(flags)| {
                                    *flags & OFlags::STATUS_FLAGS_MASK
                                })
                                .unwrap_or(OFlags::empty()))
                        },
                        |fd| {
                            let pipes = litebox_pipes().read();
                            let flags = OFlags::from(pipes.get_flags(fd).map_err(Errno::from)?);
                            let dirn = match pipes.half_pipe_type(fd)? {
                                litebox::pipes::HalfPipeType::SenderHalf => OFlags::WRONLY,
                                litebox::pipes::HalfPipeType::ReceiverHalf => OFlags::RDONLY,
                            };
                            Ok(dirn | flags)
                        },
                    )
                    .flatten()?
                    .bits()),
                Descriptor::Eventfd { file, .. } => Ok(file.get_status().bits()),
                Descriptor::Epoll { file, .. } => Ok(file.get_status().bits()),
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
                    Descriptor::LiteBoxRawFd(raw_fd) => files.run_on_raw_fd(
                        *raw_fd,
                        |fd| {
                            litebox()
                                .descriptor_table_mut()
                                .with_metadata_mut(fd, |crate::StdioStatusFlags(f)| {
                                    let diff = *f ^ flags;
                                    if diff.intersects(
                                        OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME,
                                    ) {
                                        todo!("unsupported flags");
                                    }
                                    f.toggle(diff);
                                })
                                .map_err(|err| match err {
                                    MetadataError::ClosedFd => Errno::EBADF,
                                    MetadataError::NoSuchMetadata => {
                                        unimplemented!("SETFL on non-stdio")
                                    }
                                })
                        },
                        |fd| {
                            litebox()
                                .descriptor_table_mut()
                                .with_metadata_mut(fd, |crate::syscalls::net::SocketOFlags(f)| {
                                    let diff = *f ^ flags;
                                    if diff.intersects(
                                        OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME,
                                    ) {
                                        todo!("unsupported flags");
                                    }
                                    f.toggle(diff);
                                })
                                .map_err(|err| match err {
                                    MetadataError::ClosedFd => Errno::EBADF,
                                    MetadataError::NoSuchMetadata => {
                                        unreachable!("all sockets have SocketOFlags when created")
                                    }
                                })
                        },
                        |fd| {
                            if flags.intersects(OFlags::NONBLOCK.complement()) {
                                todo!("unsupported flags for pipes")
                            }
                            litebox_pipes()
                                .read()
                                .update_flags(
                                    fd,
                                    litebox::pipes::Flags::NON_BLOCKING,
                                    flags.intersects(OFlags::NONBLOCK),
                                )
                                .map_err(Errno::from)
                        },
                    )??,
                    Descriptor::Eventfd { file, .. } => {
                        toggle_flags!(file);
                    }
                    Descriptor::Epoll { .. } => todo!(),
                }
                Ok(0)
            }
            FcntlArg::GETLK(lock) => {
                let Descriptor::LiteBoxRawFd(raw_fd) = desc else {
                    return Err(Errno::EBADF);
                };
                self.files
                    .borrow()
                    .run_on_raw_fd(
                        *raw_fd,
                        |_fd| {
                            let mut flock = unsafe { lock.read_at_offset(0) }
                                .ok_or(Errno::EFAULT)?
                                .into_owned();
                            let lock_type = litebox_common_linux::FlockType::try_from(flock.type_)
                                .map_err(|_| Errno::EINVAL)?;
                            if let litebox_common_linux::FlockType::Unlock = lock_type {
                                return Err(Errno::EINVAL);
                            }

                            // Note LiteBox does not support multiple processes yet, and one process
                            // can always acquire the lock it owns, so return `Unlock` unconditionally.
                            flock.type_ = litebox_common_linux::FlockType::Unlock as i16;
                            unsafe { lock.write_at_offset(0, flock) }.ok_or(Errno::EFAULT)?;
                            Ok(0)
                        },
                        |_fd| todo!("net"),
                        |_fd| todo!("pipes"),
                    )
                    .flatten()
            }
            FcntlArg::SETLK(lock) | FcntlArg::SETLKW(lock) => {
                let Descriptor::LiteBoxRawFd(raw_fd) = desc else {
                    return Err(Errno::EBADF);
                };
                self.files
                    .borrow()
                    .run_on_raw_fd(
                        *raw_fd,
                        |_fd| {
                            let flock = unsafe { lock.read_at_offset(0) }.ok_or(Errno::EFAULT)?;
                            let _ = litebox_common_linux::FlockType::try_from(flock.type_)
                                .map_err(|_| Errno::EINVAL)?;

                            // Note LiteBox does not support multiple processes yet, and one process
                            // can always acquire the lock it owns, so we don't need to maintain anything.
                            Ok(0)
                        },
                        |_fd| todo!("net"),
                        |_fd| todo!("pipes"),
                    )
                    .flatten()
            }
            _ => unimplemented!(),
        }
    }

    /// Handle syscall `getcwd`
    pub fn sys_getcwd(&self, buf: &mut [u8]) -> Result<usize, Errno> {
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
}

const DEFAULT_PIPE_BUF_SIZE: usize = 1024 * 1024;

impl Task {
    /// Handle syscall `pipe2`
    pub fn sys_pipe2(&self, flags: OFlags) -> Result<(u32, u32), Errno> {
        let (pipe_flags, cloexec) = {
            use litebox::pipes::Flags;
            let mut f = Flags::empty();
            if flags.contains((OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::DIRECT).complement()) {
                return Err(Errno::EINVAL);
            }
            f.set(Flags::NON_BLOCKING, flags.contains(OFlags::NONBLOCK));
            if flags.contains(OFlags::DIRECT) {
                todo!("O_DIRECT not supported");
            }
            (f, flags.contains(OFlags::CLOEXEC))
        };

        let (writer, reader) = crate::litebox_pipes().read().create_pipe(
            DEFAULT_PIPE_BUF_SIZE,
            pipe_flags,
            // See `man 7 pipe` for `PIPE_BUF`. On Linux, this is 4096.
            core::num::NonZero::new(4096),
        );

        if cloexec {
            let mut dt = litebox().descriptor_table_mut();
            let None = dt.set_fd_metadata(&writer, FileDescriptorFlags::FD_CLOEXEC) else {
                unreachable!()
            };
            let None = dt.set_fd_metadata(&reader, FileDescriptorFlags::FD_CLOEXEC) else {
                unreachable!()
            };
        }

        let files = self.files.borrow();
        let mut rds = files.raw_descriptor_store.write();
        let wr_raw_fd = rds.fd_into_raw_integer(writer);
        let rd_raw_fd = rds.fd_into_raw_integer(reader);
        let mut fds = files.file_descriptors.write();
        let w = fds
            .insert(self, Descriptor::LiteBoxRawFd(wr_raw_fd))
            .map_err(|desc| self.do_close(desc).err().unwrap_or(Errno::EMFILE))?;
        let r = fds
            .insert(self, Descriptor::LiteBoxRawFd(rd_raw_fd))
            .map_err(|desc| self.do_close(desc).err().unwrap_or(Errno::EMFILE))?;
        Ok((r, w))
    }

    pub fn sys_eventfd2(&self, initval: u32, flags: EfdFlags) -> Result<u32, Errno> {
        if flags
            .contains((EfdFlags::SEMAPHORE | EfdFlags::CLOEXEC | EfdFlags::NONBLOCK).complement())
        {
            return Err(Errno::EINVAL);
        }

        let eventfd = super::eventfd::EventFile::new(u64::from(initval), flags, litebox());
        let files = self.files.borrow();
        files
            .file_descriptors
            .write()
            .insert(
                self,
                Descriptor::Eventfd {
                    file: alloc::sync::Arc::new(eventfd),
                    close_on_exec: core::sync::atomic::AtomicBool::new(
                        flags.contains(EfdFlags::CLOEXEC),
                    ),
                },
            )
            .map_err(|desc| self.do_close(desc).err().unwrap_or(Errno::EMFILE))
    }

    fn stdio_ioctl(
        &self,
        arg: &IoctlArg<litebox_platform_multiplex::Platform>,
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
        &self,
        fd: i32,
        arg: IoctlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        let locked_file_descriptors = files.file_descriptors.read();
        let desc = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
        if let IoctlArg::FIONBIO(arg) = arg {
            let val = unsafe { arg.read_at_offset(0) }
                .ok_or(Errno::EFAULT)?
                .into_owned();
            match desc {
                Descriptor::LiteBoxRawFd(raw_fd) => {
                    self.files.borrow().run_on_raw_fd(
                        *raw_fd,
                        |_file_fd| {
                            // TODO: stdio NONBLOCK?
                            #[cfg(debug_assertions)]
                            litebox::log_println!(
                                litebox_platform_multiplex::platform(),
                                "Attempted to set non-blocking on raw fd; currently unimplemented"
                            );
                            Ok(())
                        },
                        |socket_fd| {
                            if let Err(e) = litebox().descriptor_table_mut().with_metadata_mut(
                                socket_fd,
                                |crate::syscalls::net::SocketOFlags(flags)| {
                                    flags.set(OFlags::NONBLOCK, val != 0);
                                },
                            ) {
                                match e {
                                    MetadataError::ClosedFd => return Err(Errno::EBADF),
                                    MetadataError::NoSuchMetadata => unreachable!(),
                                }
                            }
                            Ok(())
                        },
                        |fd| {
                            litebox_pipes()
                                .read()
                                .update_flags(fd, litebox::pipes::Flags::NON_BLOCKING, val != 0)
                                .map_err(Errno::from)
                        },
                    )
                    .flatten()?;
                }
                Descriptor::Eventfd { file, .. } => file.set_status(OFlags::NONBLOCK, val != 0),
                Descriptor::Epoll { file, .. } => {
                    file.set_status(OFlags::NONBLOCK, val != 0);
                }
            }
            return Ok(0);
        }

        match desc {
            Descriptor::LiteBoxRawFd(raw_fd) => files.run_on_raw_fd(
                *raw_fd,
                |fd| {
                    litebox()
                    .descriptor_table()
                    .with_metadata(fd, |crate::StdioStatusFlags(_)| self.stdio_ioctl(&arg))
                    .unwrap_or_else(|err| {
                        match err {
                            MetadataError::NoSuchMetadata => {},
                            MetadataError::ClosedFd => {
                                todo!()
                            }
                        }
                        match arg {
                            IoctlArg::TCGETS(..) => Err(Errno::ENOTTY),
                            IoctlArg::FIOCLEX => {
                                files.run_on_raw_fd(
                                    *raw_fd,
                                    |fd| {
                                        let _old = litebox()
                                            .descriptor_table_mut()
                                            .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                                    },
                                    |_fd| todo!("net"),
                                    |_fd| todo!("pipes"),
                                )?;
                                Ok(0)
                            }
                            IoctlArg::TIOCGWINSZ(_) | IoctlArg::TCSETS(_) => {
                                #[cfg(debug_assertions)]
                                litebox::log_println!(
                                    litebox_platform_multiplex::platform(),
                                    "Got {:?} for non-stdio file; this is likely temporary during the migration away from stdio and should get cleaned up at some point",
                                    arg
                                );
                                Err(Errno::EPERM)
                            }
                            _ => {
                                #[cfg(debug_assertions)]
                                litebox::log_println!(
                                    litebox_platform_multiplex::platform(),
                                    "\n\n\n{:?}\n\n\n",
                                    arg
                                );
                                todo!()
                            }
                        }
                    })
                },
                |_fd| todo!("net"),
                |_fd| todo!("pipes"),
            )?,
            Descriptor::Eventfd {
                file: _,
                close_on_exec: _,
            } => todo!(),
            Descriptor::Epoll {
                file: _,
                close_on_exec: _,
            } => todo!(),
        }
    }

    /// Handle syscall `epoll_create` and `epoll_create1`
    pub fn sys_epoll_create(&self, flags: EpollCreateFlags) -> Result<u32, Errno> {
        if flags.contains(EpollCreateFlags::EPOLL_CLOEXEC.complement()) {
            return Err(Errno::EINVAL);
        }

        let epoll_file = super::epoll::EpollFile::new(litebox());
        let files = self.files.borrow();
        files
            .file_descriptors
            .write()
            .insert(
                self,
                Descriptor::Epoll {
                    file: alloc::sync::Arc::new(epoll_file),
                    close_on_exec: core::sync::atomic::AtomicBool::new(
                        flags.contains(EpollCreateFlags::EPOLL_CLOEXEC),
                    ),
                },
            )
            .map_err(|desc| self.do_close(desc).err().unwrap_or(Errno::EMFILE))
    }

    /// Handle syscall `epoll_ctl`
    pub(crate) fn sys_epoll_ctl(
        &self,
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

        let files = self.files.borrow();
        let locked_file_descriptors = files.file_descriptors.read();
        let epoll_entry = locked_file_descriptors.get_fd(epfd).ok_or(Errno::EBADF)?;
        let Descriptor::Epoll { file: epoll, .. } = epoll_entry else {
            return Err(Errno::EBADF);
        };

        let file = locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?;
        let file_descriptor = super::epoll::EpollDescriptor::try_from(&files, file)?;
        let event = if op == litebox_common_linux::EpollOp::EpollCtlDel {
            None
        } else {
            Some(
                unsafe { event.read_at_offset(0) }
                    .ok_or(Errno::EFAULT)?
                    .into_owned(),
            )
        };
        epoll.epoll_ctl(op, fd, &file_descriptor, event)
    }

    /// Handle syscall `epoll_pwait`
    pub fn sys_epoll_pwait(
        &self,
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
            let files = self.files.borrow();
            let locked_file_descriptors = files.file_descriptors.read();
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

    /// Handle syscall `ppoll`.
    pub fn sys_ppoll(
        &self,
        fds: MutPtr<litebox_common_linux::Pollfd>,
        nfds: usize,
        timeout: Option<ConstPtr<litebox_common_linux::Timespec>>,
        sigmask: Option<ConstPtr<litebox_common_linux::SigSet>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if sigmask.is_some() {
            unimplemented!("no sigmask support yet");
        }
        if sigsetsize != core::mem::size_of::<litebox_common_linux::SigSet>() {
            // Expected via ppoll(2) manpage
            unimplemented!()
        }
        let timeout = timeout
            .map(super::process::get_timeout)
            .transpose()?
            .map(Into::into);

        self.do_ppoll(fds, nfds, timeout)
    }

    /// Handle syscall `poll`.
    pub fn sys_poll(
        &self,
        fds: MutPtr<litebox_common_linux::Pollfd>,
        nfds: usize,
        timeout: i32,
    ) -> Result<usize, Errno> {
        let timeout = if timeout >= 0 {
            #[allow(clippy::cast_sign_loss, reason = "timeout is a positive integer")]
            Some(core::time::Duration::from_millis(timeout as u64))
        } else {
            None
        };
        self.do_ppoll(fds, nfds, timeout)
    }

    fn do_ppoll(
        &self,
        fds: MutPtr<litebox_common_linux::Pollfd>,
        nfds: usize,
        timeout: Option<core::time::Duration>,
    ) -> Result<usize, Errno> {
        let nfds_signed = isize::try_from(nfds).map_err(|_| Errno::EINVAL)?;

        let mut set = super::epoll::PollSet::with_capacity(nfds);
        for i in 0..nfds_signed {
            let fd = unsafe { fds.read_at_offset(i) }
                .ok_or(Errno::EFAULT)?
                .into_owned();

            let events = litebox::event::Events::from_bits_truncate(
                fd.events.reinterpret_as_unsigned().into(),
            );
            set.add_fd(fd.fd, events);
        }

        set.wait_or_timeout(&self.files.borrow(), timeout);

        // Write just the revents back.
        let fds_base_addr = fds.as_usize();
        let mut ready_count = 0;
        for (i, revents) in set.revents().enumerate() {
            // TODO: This is not great from a provenance perspective. Consider
            // adding cast+add methods to ConstPtr/MutPtr.
            let fd_addr = fds_base_addr + i * core::mem::size_of::<litebox_common_linux::Pollfd>();
            let revents_ptr = crate::MutPtr::<i16>::from_usize(
                fd_addr + core::mem::offset_of!(litebox_common_linux::Pollfd, revents),
            );
            let revents: u16 = revents.bits().truncate();
            unsafe {
                revents_ptr
                    .write_at_offset(0, revents.reinterpret_as_signed())
                    .ok_or(Errno::EFAULT)
            }?;
            if revents != 0 {
                ready_count += 1;
            }
        }
        Ok(ready_count)
    }

    pub(crate) fn do_pselect(
        &self,
        nfds: u32,
        readfds: Option<&mut bitvec::vec::BitVec>,
        writefds: Option<&mut bitvec::vec::BitVec>,
        exceptfds: Option<&mut bitvec::vec::BitVec>,
        timeout: Option<core::time::Duration>,
    ) -> Result<usize, Errno> {
        let file_table_len = self.files.borrow().file_descriptors.read().len();
        let mut set = super::epoll::PollSet::with_capacity(nfds as usize);
        for i in 0..nfds {
            let mut events = litebox::event::Events::empty();
            if readfds.as_ref().is_some_and(|set| set[i as usize]) {
                events |= litebox::event::Events::IN;
            }
            if writefds.as_ref().is_some_and(|set| set[i as usize]) {
                events |= litebox::event::Events::OUT;
            }
            if exceptfds.as_ref().is_some_and(|set| set[i as usize]) {
                events |= litebox::event::Events::PRI;
            }
            if !events.is_empty() {
                if i as usize >= file_table_len {
                    return Err(Errno::EBADF);
                }
                set.add_fd(i.reinterpret_as_signed(), events);
            }
        }

        set.wait_or_timeout(&self.files.borrow(), timeout);

        let mut ready_count = 0;
        let mut process_fdset =
            |fds: Option<&mut bitvec::vec::BitVec>, target_events: Events| -> Result<(), Errno> {
                if let Some(fds) = fds {
                    fds.fill(false);
                    for (i, revents) in set.revents_with_fds() {
                        if revents.contains(Events::NVAL) {
                            return Err(Errno::EBADF);
                        }
                        if revents.intersects(target_events) {
                            // no negative fds added to the set
                            fds.set(i.reinterpret_as_unsigned() as usize, true);
                            ready_count += 1;
                        }
                    }
                }
                Ok(())
            };
        process_fdset(readfds, Events::IN | Events::ALWAYS_POLLED)?;
        process_fdset(writefds, Events::OUT | Events::ALWAYS_POLLED)?;
        process_fdset(exceptfds, Events::PRI)?;
        Ok(ready_count)
    }

    fn select_common(
        &self,
        nfds: u32,
        readfds: Option<MutPtr<usize>>,
        writefds: Option<MutPtr<usize>>,
        exceptfds: Option<MutPtr<usize>>,
        timeout: Option<core::time::Duration>,
    ) -> Result<usize, Errno> {
        if nfds >= i32::MAX as u32
            || nfds as usize
                > self
                    .process
                    .limits
                    .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE)
        {
            return Err(Errno::EINVAL);
        }
        let len = (nfds as usize).div_ceil(core::mem::size_of::<usize>() * 8);
        let mut kreadfds = readfds
            .map(|fds| unsafe { fds.to_cow_slice(len) }.ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_owned()));
        let mut kwritefds = writefds
            .map(|fds| unsafe { fds.to_cow_slice(len) }.ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_owned()));
        let mut kexceptfds = exceptfds
            .map(|fds| unsafe { fds.to_cow_slice(len) }.ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_owned()));

        let count = self.do_pselect(
            nfds,
            kreadfds.as_mut(),
            kwritefds.as_mut(),
            kexceptfds.as_mut(),
            timeout,
        )?;

        if let Some(fds) = kreadfds {
            unsafe {
                readfds
                    .unwrap()
                    .write_slice_at_offset(0, fds.as_raw_slice())
            }
            .ok_or(Errno::EFAULT)?;
        }
        if let Some(fds) = kwritefds {
            unsafe {
                writefds
                    .unwrap()
                    .write_slice_at_offset(0, fds.as_raw_slice())
            }
            .ok_or(Errno::EFAULT)?;
        }
        if let Some(fds) = kexceptfds {
            unsafe {
                exceptfds
                    .unwrap()
                    .write_slice_at_offset(0, fds.as_raw_slice())
            }
            .ok_or(Errno::EFAULT)?;
        }

        Ok(count)
    }

    /// Handle syscall `select`.
    pub(crate) fn sys_select(
        &self,
        nfds: u32,
        readfds: Option<MutPtr<usize>>,
        writefds: Option<MutPtr<usize>>,
        exceptfds: Option<MutPtr<usize>>,
        timeout: Option<MutPtr<litebox_common_linux::TimeVal>>,
    ) -> Result<usize, Errno> {
        let timeout = timeout
            .map(|tv_ptr| {
                let tv = unsafe { tv_ptr.read_at_offset(0) }
                    .ok_or(Errno::EFAULT)?
                    .into_owned();
                core::time::Duration::try_from(tv).map_err(|_| Errno::EINVAL)
            })
            .transpose()?;

        self.select_common(nfds, readfds, writefds, exceptfds, timeout)
    }

    /// Handle syscall `pselect`.
    pub(crate) fn sys_pselect(
        &self,
        nfds: u32,
        readfds: Option<MutPtr<usize>>,
        writefds: Option<MutPtr<usize>>,
        exceptfds: Option<MutPtr<usize>>,
        timeout: Option<ConstPtr<litebox_common_linux::Timespec>>,
        sigsetpack: Option<ConstPtr<litebox_common_linux::SigSetPack>>,
    ) -> Result<usize, Errno> {
        if sigsetpack.is_some() {
            unimplemented!("no sigsetpack support yet");
        }
        let timeout = timeout
            .map(super::process::get_timeout)
            .transpose()?
            .map(Into::into);

        self.select_common(nfds, readfds, writefds, exceptfds, timeout)
    }

    fn do_dup(&self, file: &Descriptor, flags: OFlags) -> Result<Descriptor, Errno> {
        let close_on_exec = flags.contains(OFlags::CLOEXEC);
        let files = self.files.borrow();
        match file {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                fn dup<S: FdEnabledSubsystem>(
                    files: &FilesState,
                    fd: &TypedFd<S>,
                    close_on_exec: bool,
                ) -> Result<Descriptor, Errno> {
                    let mut dt = litebox().descriptor_table_mut();
                    let fd = dt.duplicate(fd).ok_or(Errno::EBADF)?;
                    if close_on_exec {
                        let old = dt.set_fd_metadata(&fd, FileDescriptorFlags::FD_CLOEXEC);
                        assert!(old.is_none());
                    }
                    Ok(Descriptor::LiteBoxRawFd(
                        files.raw_descriptor_store.write().fd_into_raw_integer(fd),
                    ))
                }
                files.run_on_raw_fd(
                    *raw_fd,
                    |fd| dup(&files, fd, close_on_exec),
                    |fd| dup(&files, fd, close_on_exec),
                    |fd| dup(&files, fd, close_on_exec),
                )?
            }
            Descriptor::Eventfd { file, .. } => Ok(Descriptor::Eventfd {
                file: file.clone(),
                close_on_exec: core::sync::atomic::AtomicBool::new(close_on_exec),
            }),
            Descriptor::Epoll { file, .. } => Ok(Descriptor::Epoll {
                file: file.clone(),
                close_on_exec: core::sync::atomic::AtomicBool::new(close_on_exec),
            }),
        }
    }

    /// Handle syscall `dup/dup2/dup3`
    ///
    /// The dup() system call creates a copy of the file descriptor oldfd, using the lowest-numbered unused file descriptor for the new descriptor.
    /// The dup2() system call performs the same task as dup(), but instead of using the lowest-numbered unused file descriptor, it uses the file descriptor number specified in newfd.
    /// The dup3() system call is similar to dup2(), but it also takes an additional flags argument that can be used to set the close-on-exec flag for the new file descriptor.
    pub fn sys_dup(
        &self,
        oldfd: i32,
        newfd: Option<i32>,
        flags: Option<OFlags>,
    ) -> Result<u32, Errno> {
        let Ok(oldfd) = u32::try_from(oldfd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let new_file = files
            .file_descriptors
            .read()
            .get_fd(oldfd)
            .ok_or(Errno::EBADF)
            .map(|desc| self.do_dup(desc, flags.unwrap_or(OFlags::empty())))??;
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
            if newfd as usize
                > self
                    .process
                    .limits
                    .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE)
            {
                return Err(Errno::EBADF);
            }

            if let Some(old_file) = files
                .file_descriptors
                .write()
                .insert_at(new_file, newfd as usize)
            {
                self.do_close(old_file)?;
            }
            Ok(newfd)
        } else {
            // dup
            files
                .file_descriptors
                .write()
                .insert(self, new_file)
                .map_err(|desc| self.do_close(desc).err().unwrap_or(Errno::EMFILE))
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Diroff(usize);

const DIRENT_STRUCT_BYTES_WITHOUT_NAME: usize =
    core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name);

impl Task {
    /// Handle syscall `getdents64`
    pub(crate) fn sys_getdirent64(
        &self,
        fd: i32,
        dirp: MutPtr<u8>,
        count: usize,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let locked_file_descriptors = files.file_descriptors.read();
        let Descriptor::LiteBoxRawFd(raw_fd) =
            locked_file_descriptors.get_fd(fd).ok_or(Errno::EBADF)?
        else {
            return Err(Errno::EBADF);
        };
        files.run_on_raw_fd(
            *raw_fd,
            |file| {
                let dir_off: Diroff = litebox()
                    .descriptor_table()
                    .with_metadata(file, |off: &Diroff| *off)
                    .unwrap_or_default();
                let mut dir_off = dir_off.0;
                let mut nbytes = 0;

                let mut entries = self.global.fs.read_dir(file)?;
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
                    let name_ptr = crate::MutPtr::from_usize(
                        hdr_ptr.as_usize() + DIRENT_STRUCT_BYTES_WITHOUT_NAME,
                    );
                    unsafe { name_ptr.write_slice_at_offset(0, entry.name.as_bytes()) }
                        .ok_or(Errno::EFAULT)?;
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
                let _old = litebox()
                    .descriptor_table_mut()
                    .set_fd_metadata(file, Diroff(dir_off));
                Ok(nbytes)
            },
            |_fd| todo!("net"),
            |_fd| todo!("pipes"),
        )?
    }
}
