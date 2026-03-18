// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of file related syscalls, e.g., `open`, `read`, `write`, etc.

use alloc::{
    ffi::CString,
    string::{String, ToString as _},
    vec,
};
use litebox::{
    event::{Events, wait::WaitError},
    fd::{FdEnabledSubsystem, MetadataError, TypedFd},
    fs::{Mode, OFlags, SeekWhence},
    path,
    platform::{RawConstPointer, RawMutPointer},
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt as _},
};
use litebox_common_linux::{
    AtFlags, EfdFlags, EpollCreateFlags, FcntlArg, FileDescriptorFlags, FileStat, IoReadVec,
    IoWriteVec, IoctlArg, TimeParam, errno::Errno,
};
use litebox_platform_multiplex::Platform;

use crate::{ConstPtr, GlobalState, MutPtr, ShimFS, Task};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Task state shared by `CLONE_FS`.
pub(crate) struct FsState {
    umask: core::sync::atomic::AtomicU32,
    /// The current working directory
    ///
    /// Must end with a '/'.
    cwd: litebox::sync::RwLock<Platform, String>,
}

impl Clone for FsState {
    fn clone(&self) -> Self {
        Self {
            umask: self.umask.load(Ordering::Relaxed).into(),
            cwd: litebox::sync::RwLock::new(self.cwd.read().clone()),
        }
    }
}

impl FsState {
    pub fn new() -> Self {
        Self {
            umask: (Mode::WGRP | Mode::WOTH).bits().into(),
            cwd: litebox::sync::RwLock::new(String::from("/")),
        }
    }

    fn umask(&self) -> Mode {
        Mode::from_bits_retain(self.umask.load(Ordering::Relaxed))
    }
}

/// Task state shared by `CLONE_FILES`.
pub(crate) struct FilesState<FS: ShimFS> {
    /// The filesystem implementation, shared across tasks that share file system.
    pub(crate) fs: alloc::sync::Arc<FS>,
    pub(crate) raw_descriptor_store:
        litebox::sync::RwLock<Platform, litebox::fd::RawDescriptorStorage>,
    max_fd: AtomicUsize,
}

impl<FS: ShimFS> FilesState<FS> {
    pub(crate) fn new(fs: alloc::sync::Arc<FS>) -> Self {
        Self {
            fs,
            raw_descriptor_store: litebox::sync::RwLock::new(
                litebox::fd::RawDescriptorStorage::new(),
            ),
            max_fd: AtomicUsize::new(usize::MAX),
        }
    }

    pub(crate) fn set_max_fd(&self, max_fd: usize) {
        self.max_fd.store(max_fd, Ordering::Relaxed);
    }

    // Returns Ok(raw_fd) if it fits within the max limits already set up; otherwise returns the
    // Err(typed_fd)
    pub(crate) fn insert_raw_fd<Subsystem: FdEnabledSubsystem>(
        &self,
        typed_fd: TypedFd<Subsystem>,
    ) -> Result<usize, TypedFd<Subsystem>> {
        // XXX(jb): should we try to somehow enforce that it is set at the smallest
        // available/unassigned FD number?
        let mut rds = self.raw_descriptor_store.write();
        let raw_fd = rds.fd_into_raw_integer(typed_fd);
        let max_fd = self.max_fd.load(Ordering::Relaxed);
        if raw_fd > max_fd {
            let orig = rds.fd_consume_raw_integer::<Subsystem>(raw_fd).unwrap();
            return Err(alloc::sync::Arc::into_inner(orig).unwrap());
        }
        Ok(raw_fd)
    }
}

/// Path in the file system
#[derive(Debug)]
enum FsPath {
    /// Absolute path
    Absolute { path: CString },
    /// Current working directory
    Cwd,
    /// Path is relative to a file descriptor
    #[expect(dead_code, reason = "currently unused, might want to use later")]
    FdRelative { fd: u32, path: CString },
    /// Fd
    Fd(u32),
}

/// Maximum size of a file path
pub const PATH_MAX: usize = 4096;

impl FsPath {
    /// Create a new `FsPath` from a dirfd and path.
    ///
    /// CWD-relative paths are resolved immediately to absolute paths.
    fn new(
        dirfd: i32,
        path: impl path::Arg,
        get_cwd: impl FnOnce() -> String,
    ) -> Result<Self, Errno> {
        let path_str = path.as_rust_str()?;
        if path_str.len() > PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let fs_path = if path_str.starts_with('/') {
            let cpath = path.to_c_str()?.into_owned();
            FsPath::Absolute { path: cpath }
        } else if dirfd >= 0 {
            let dirfd = u32::try_from(dirfd).expect("dirfd >= 0");
            if path_str.is_empty() {
                FsPath::Fd(dirfd)
            } else {
                let cpath = path.to_c_str()?.into_owned();
                FsPath::FdRelative {
                    fd: dirfd,
                    path: cpath,
                }
            }
        } else if dirfd == litebox_common_linux::AT_FDCWD {
            if path_str.is_empty() {
                FsPath::Cwd
            } else {
                // Resolve CWD-relative path to absolute.
                let mut abs = get_cwd();
                abs.push_str(path_str);
                let cpath = CString::new(abs).map_err(|_| Errno::EINVAL)?;
                FsPath::Absolute { path: cpath }
            }
        } else {
            return Err(Errno::EBADF);
        };
        Ok(fs_path)
    }
}

impl<FS: ShimFS> Task<FS> {
    fn get_umask(&self) -> Mode {
        self.fs.borrow().umask()
    }

    /// Resolve a path against the current working directory.
    fn resolve_path(&self, path: impl path::Arg) -> Result<CString, Errno> {
        let path_str = path.as_rust_str().map_err(|_| Errno::EINVAL)?;
        if path_str.starts_with('/') {
            CString::new(path_str.to_string()).map_err(|_| Errno::EINVAL)
        } else {
            let mut cwd = self.fs.borrow().cwd.read().clone();
            cwd.push_str(path_str);
            CString::new(cwd).map_err(|_| Errno::EINVAL)
        }
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
        let path = self.resolve_path(path)?;
        let mode = mode & !self.get_umask();
        let file = self
            .files
            .borrow()
            .fs
            .open(path, flags - OFlags::CLOEXEC, mode)?;
        if flags.contains(OFlags::CLOEXEC) {
            let None = self
                .global
                .litebox
                .descriptor_table_mut()
                .set_fd_metadata(&file, FileDescriptorFlags::FD_CLOEXEC)
            else {
                unreachable!()
            };
        }
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(file).map_err(|file| {
            files.fs.close(&file).unwrap();
            Errno::EMFILE
        })?;
        Ok(u32::try_from(raw_fd).unwrap())
    }

    /// Handle syscall `openat`
    pub fn sys_openat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<u32, Errno> {
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        match fs_path {
            FsPath::Absolute { path } => self.sys_open(path, flags, mode),
            FsPath::Cwd => self.sys_open(get_cwd(), flags, mode),
            FsPath::Fd(_fd) => {
                log_unsupported!("openat with FsPath::Fd");
                Err(Errno::EINVAL)
            }
            FsPath::FdRelative { fd: _, path: _ } => {
                log_unsupported!("openat with FsPath::FdRelative");
                Err(Errno::EINVAL)
            }
        }
    }

    /// Handle syscall `ftruncate`
    pub(crate) fn sys_ftruncate(&self, fd: i32, length: usize) -> Result<(), Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                raw_fd,
                |fd| files.fs.truncate(fd, length, false).map_err(Errno::from),
                |_fd| todo!("net"),
                |_fd| todo!("pipes"),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
            )
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

        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        match fs_path {
            FsPath::Absolute { path } => {
                if flags.contains(AtFlags::AT_REMOVEDIR) {
                    self.files.borrow().fs.rmdir(path).map_err(Errno::from)
                } else {
                    self.files.borrow().fs.unlink(path).map_err(Errno::from)
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
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        // We need to do this cell dance because otherwise Rust can't recognize that the two
        // closures are mutually exclusive.
        let buf: core::cell::RefCell<&mut [u8]> = core::cell::RefCell::new(buf);
        files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    files
                        .fs
                        .read(fd, &mut buf.borrow_mut(), offset)
                        .map_err(Errno::from)
                },
                |fd| {
                    self.global.receive(
                        &self.wait_cx(),
                        fd,
                        &mut buf.borrow_mut(),
                        litebox_common_linux::ReceiveFlags::empty(),
                        None,
                    )
                },
                |fd| {
                    self.global
                        .pipes
                        .read(&self.wait_cx(), fd, &mut buf.borrow_mut())
                        .map_err(Errno::from)
                },
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        let buf = &mut buf.borrow_mut();
                        if buf.len() < size_of::<u64>() {
                            return Err(Errno::EINVAL);
                        }
                        let value = file.read(&self.wait_cx())?;
                        buf[..size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
                        Ok(size_of::<u64>())
                    })
                },
                |_fd| Err(Errno::EINVAL),
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        file.recvfrom(
                            &self.wait_cx(),
                            &mut buf.borrow_mut(),
                            litebox_common_linux::ReceiveFlags::empty(),
                            None,
                        )
                    })
                },
            )
            .flatten()
    }

    /// Handle syscall `write`
    ///
    /// `offset` is an optional offset to write to. If `None`, it will write to the current file position.
    /// If `Some`, it will write to the specified offset without changing the current file position.
    pub fn sys_write(&self, fd: i32, buf: &[u8], offset: Option<usize>) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        let res = files
            .run_on_raw_fd(
                raw_fd,
                |fd| files.fs.write(fd, buf, offset).map_err(Errno::from),
                |fd| {
                    self.global.sendto(
                        &self.wait_cx(),
                        fd,
                        buf,
                        litebox_common_linux::SendFlags::empty(),
                        None,
                    )
                },
                |fd| {
                    self.global
                        .pipes
                        .write(&self.wait_cx(), fd, buf)
                        .map_err(Errno::from)
                },
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        if buf.len() < size_of::<u64>() {
                            return Err(Errno::EINVAL);
                        }
                        let value: u64 = u64::from_le_bytes(
                            buf[..size_of::<u64>()]
                                .try_into()
                                .map_err(|_| Errno::EINVAL)?,
                        );
                        file.write(&self.wait_cx(), value)
                    })
                },
                |_fd| Err(Errno::EINVAL),
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|file| {
                        file.sendto(self, buf, litebox_common_linux::SendFlags::empty(), None)
                    })
                },
            )
            .flatten();
        if let Err(Errno::EPIPE) = res {
            unimplemented!("send SIGPIPE to the current task");
        }
        res
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

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `lseek`
    pub fn sys_lseek(&self, fd: i32, offset: isize, whence: SeekWhence) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                raw_fd,
                |fd| files.fs.seek(fd, offset, whence).map_err(Errno::from),
                |_| Err(Errno::ESPIPE),
                |_| Err(Errno::ESPIPE),
                |_| Err(Errno::ESPIPE),
                |_| Err(Errno::ESPIPE),
                |_| Err(Errno::ESPIPE),
            )
            .flatten()
    }

    /// Handle syscall `mkdir`
    pub fn sys_mkdir(&self, pathname: impl path::Arg, mode: u32) -> Result<(), Errno> {
        let pathname = self.resolve_path(pathname)?;
        let mode = Mode::from_bits_retain(mode) & !self.get_umask();
        self.files
            .borrow()
            .fs
            .mkdir(pathname, mode)
            .map_err(Errno::from)
    }

    pub(crate) fn do_close(&self, raw_fd: usize) -> Result<(), Errno> {
        let files = self.files.borrow();
        let mut rds = files.raw_descriptor_store.write();
        match rds.fd_consume_raw_integer(raw_fd) {
            Ok(fd) => {
                drop(rds);
                return files.fs.close(&fd).map_err(Errno::from);
            }
            Err(litebox::fd::ErrRawIntFd::NotFound) => {
                return Err(Errno::EBADF);
            }
            Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => {
                // fallthrough
            }
        }
        if let Ok(fd) = rds.fd_consume_raw_integer(raw_fd) {
            drop(rds);
            return self.global.close_socket(&self.wait_cx(), fd);
        }
        if let Ok(fd) = rds.fd_consume_raw_integer(raw_fd) {
            drop(rds);
            return self.global.pipes.close(&fd).map_err(Errno::from);
        }
        if let Ok(fd) = rds.fd_consume_raw_integer::<super::eventfd::EventfdSubsystem>(raw_fd) {
            drop(rds);
            let entry = {
                let mut dt = self.global.litebox.descriptor_table_mut();
                dt.remove(&fd)
            };
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) = rds.fd_consume_raw_integer::<super::epoll::EpollSubsystem<FS>>(raw_fd) {
            drop(rds);
            let entry = {
                let mut dt = self.global.litebox.descriptor_table_mut();
                dt.remove(&fd)
            };
            drop(entry);
            return Ok(());
        }
        if let Ok(fd) = rds.fd_consume_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(raw_fd) {
            drop(rds);
            let entry = {
                let mut dt = self.global.litebox.descriptor_table_mut();
                dt.remove(&fd)
            };
            drop(entry);
            return Ok(());
        }
        // All the above cases should cover all the known subsystems, and we've already
        // early-handled the "raw FD not found" case.
        unreachable!()
    }

    /// Handle syscall `close`
    pub(crate) fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        self.do_close(raw_fd)
    }

    /// Handle syscall `readv`
    pub fn sys_readv(
        &self,
        fd: i32,
        iovec: ConstPtr<IoReadVec<MutPtr<u8>>>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let iovs: &[IoReadVec<MutPtr<u8>>] = &iovec.to_owned_slice(iovcnt).ok_or(Errno::EFAULT)?;
        let files = self.files.borrow();
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
            let size = files
                .run_on_raw_fd(
                    raw_fd,
                    |fd| {
                        files
                            .fs
                            .read(fd, &mut kernel_buffer, None)
                            .map_err(Errno::from)
                    },
                    |_fd| todo!("net"),
                    |_fd| todo!("pipes"),
                    |_fd| todo!("eventfd"),
                    |_fd| Err(Errno::EINVAL),
                    |_fd| todo!("unix"),
                )
                .flatten()?;
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
        let slice = iov
            .iov_base
            .to_owned_slice(iov.iov_len)
            .ok_or(Errno::EFAULT)?;
        let size = write_fn(&slice)?;
        total_written += size;
        if size < iov.iov_len {
            // Okay to transfer fewer bytes than requested
            break;
        }
    }
    Ok(total_written)
}

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `writev`
    pub fn sys_writev(
        &self,
        fd: i32,
        iovec: ConstPtr<IoWriteVec<ConstPtr<u8>>>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let iovs: &[IoWriteVec<ConstPtr<u8>>] =
            &iovec.to_owned_slice(iovcnt).ok_or(Errno::EFAULT)?;
        let files = self.files.borrow();
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        let res = files
            .run_on_raw_fd(
                raw_fd,
                |fd| {
                    write_to_iovec(iovs, |buf: &[u8]| {
                        files.fs.write(fd, buf, None).map_err(Errno::from)
                    })
                },
                |fd| {
                    write_to_iovec(iovs, |buf| {
                        self.global.sendto(
                            &self.wait_cx(),
                            fd,
                            buf,
                            litebox_common_linux::SendFlags::empty(),
                            None,
                        )
                    })
                },
                |_fd| todo!("pipes"),
                |_fd| todo!("eventfd"),
                |_fd| Err(Errno::EINVAL),
                |_fd| todo!("unix"),
            )
            .flatten();
        if let Err(Errno::EPIPE) = res {
            unimplemented!("send SIGPIPE to the current task");
        }
        res
    }

    /// Handle syscall `access`
    pub fn sys_access(
        &self,
        pathname: impl path::Arg,
        mode: litebox_common_linux::AccessFlags,
    ) -> Result<(), Errno> {
        let pathname = self.resolve_path(pathname)?;
        let status = self.files.borrow().fs.file_status(pathname)?;
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
    /// The caller must pass an absolute path.
    ///
    /// Note that this function only handles the following cases that we hardcoded:
    /// - `/proc/self/fd/<fd>`
    fn do_readlink(&self, fullpath: &str) -> Result<String, Errno> {
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
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fspath = FsPath::new(dirfd, pathname, get_cwd)?;
        let path = match fspath {
            FsPath::Absolute { path } => {
                self.do_readlink(path.to_str().map_err(|_| Errno::EINVAL)?)
            }
            FsPath::Cwd => {
                let cwd = self.fs.borrow().cwd.read().clone();
                self.do_readlink(&cwd)
            }
            FsPath::Fd(_) | FsPath::FdRelative { .. } => unimplemented!(),
        }?;
        let bytes = path.as_bytes();
        let min_len = core::cmp::min(buf.len(), bytes.len());
        buf[..min_len].copy_from_slice(&bytes[..min_len]);
        Ok(min_len)
    }
}

fn descriptor_stat<FS: ShimFS>(raw_fd: usize, task: &Task<FS>) -> Result<FileStat, Errno> {
    let fstat = task
        .files
        .borrow()
        .run_on_raw_fd(
            raw_fd,
            |fd| {
                task.files
                    .borrow()
                    .fs
                    .fd_file_status(fd)
                    .map(FileStat::from)
                    .map_err(Errno::from)
            },
            |_fd| {
                Ok(FileStat {
                    // TODO: give correct values
                    st_dev: 0,
                    st_ino: 0,
                    st_nlink: 1,
                    st_mode: (litebox_common_linux::InodeType::Socket as u32
                        | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits())
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
            |fd| {
                let half_pipe_type = task.global.pipes.half_pipe_type(fd)?;
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
            |_fd| {
                Ok(FileStat {
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
                })
            },
            |_fd| {
                Ok(FileStat {
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
                })
            },
            |_fd| {
                Ok(FileStat {
                    // TODO: give correct values
                    st_dev: 0,
                    st_ino: 0,
                    st_nlink: 1,
                    st_mode: (litebox_common_linux::InodeType::Socket as u32
                        | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits())
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
        .flatten()?;
    Ok(fstat)
}

pub(crate) fn get_file_descriptor_flags<FS: ShimFS>(
    raw_fd: usize,
    global: &GlobalState<FS>,
    files: &FilesState<FS>,
) -> Result<FileDescriptorFlags, Errno> {
    // Currently, only one such flag is defined: FD_CLOEXEC, the close-on-exec flag.
    // See https://www.man7.org/linux/man-pages/man2/F_GETFD.2const.html
    fn get_flags<FS: ShimFS, S: FdEnabledSubsystem>(
        global: &GlobalState<FS>,
        fd: &TypedFd<S>,
    ) -> FileDescriptorFlags {
        global
            .litebox
            .descriptor_table()
            .with_metadata(fd, |flags: &FileDescriptorFlags| *flags)
            .unwrap_or(FileDescriptorFlags::empty())
    }
    files.run_on_raw_fd(
        raw_fd,
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
        |fd| get_flags(global, fd),
    )
}

fn set_file_descriptor_flags<FS: ShimFS>(
    raw_fd: usize,
    global: &GlobalState<FS>,
    files: &FilesState<FS>,
    flags: FileDescriptorFlags,
) -> Result<(), Errno> {
    fn set_flags<FS: ShimFS, S: FdEnabledSubsystem>(
        global: &GlobalState<FS>,
        fd: &TypedFd<S>,
        flags: FileDescriptorFlags,
    ) {
        let _old = global
            .litebox
            .descriptor_table_mut()
            .set_fd_metadata(fd, flags);
    }

    files.run_on_raw_fd(
        raw_fd,
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
        |fd| set_flags(global, fd, flags),
    )?;
    Ok(())
}

impl<FS: ShimFS> Task<FS> {
    /// Get the file status of `pathname`.
    ///
    /// The `pathname` must be absolute.
    fn do_stat(&self, pathname: impl path::Arg, follow_symlink: bool) -> Result<FileStat, Errno> {
        let normalized_path = pathname.normalized()?;
        let path = if follow_symlink {
            self.do_readlink(normalized_path.as_str())
                .unwrap_or(normalized_path)
        } else {
            normalized_path
        };
        let status = self.files.borrow().fs.file_status(path)?;
        Ok(FileStat::from(status))
    }

    /// Handle syscall `stat`
    pub fn sys_stat(&self, pathname: impl path::Arg) -> Result<FileStat, Errno> {
        let pathname = self.resolve_path(pathname)?;
        self.do_stat(pathname, true)
    }

    /// Handle syscall `lstat`
    ///
    /// `lstat` is identical to `stat`, except that if `pathname` is a symbolic link,
    /// then it returns information about the link itself, not the file that the link refers to.
    /// TODO: we do not support symbolic links yet.
    pub fn sys_lstat(&self, pathname: impl path::Arg) -> Result<FileStat, Errno> {
        let pathname = self.resolve_path(pathname)?;
        self.do_stat(pathname, false)
    }

    /// Handle syscall `fstat`
    pub fn sys_fstat(&self, fd: i32) -> Result<FileStat, Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        descriptor_stat(raw_fd, self)
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
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        let fstat: FileStat = match fs_path {
            FsPath::Absolute { path } => {
                self.do_stat(path, !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW))?
            }
            FsPath::Cwd => files.fs.file_status(get_cwd())?.into(),
            FsPath::Fd(fd) => {
                let Ok(raw_fd) = usize::try_from(fd) else {
                    return Err(Errno::EBADF);
                };
                descriptor_stat(raw_fd, self)?
            }
            FsPath::FdRelative { .. } => todo!(),
        };
        Ok(fstat)
    }

    pub(crate) fn sys_fcntl(
        &self,
        fd: i32,
        arg: FcntlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        let Ok(desc) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match arg {
            FcntlArg::GETFD => Ok(get_file_descriptor_flags(desc, &self.global, &files)?.bits()),
            FcntlArg::SETFD(flags) => {
                set_file_descriptor_flags(desc, &self.global, &files, flags).map(|()| 0)
            }
            FcntlArg::GETFL => {
                macro_rules! getfl_from_metadata {
                    ($fd:expr, $MetaType:path) => {
                        Ok(self
                            .global
                            .litebox
                            .descriptor_table()
                            .with_metadata($fd, |$MetaType(flags)| {
                                *flags & OFlags::STATUS_FLAGS_MASK
                            })
                            .unwrap_or(OFlags::empty()))
                    };
                }
                macro_rules! getfl_from_handle {
                    ($fd:ident) => {{
                        // TODO: Consider shared metadata table?
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle($fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file| Ok(file.get_status()))
                    }};
                }
                Ok(files
                    .run_on_raw_fd(
                        desc,
                        |fd| getfl_from_metadata!(fd, crate::StdioStatusFlags),
                        |fd| getfl_from_metadata!(fd, crate::syscalls::net::SocketOFlags),
                        |fd| getfl_from_metadata!(fd, crate::PipeStatusFlags),
                        |fd| getfl_from_handle!(fd),
                        |fd| getfl_from_handle!(fd),
                        |fd| getfl_from_handle!(fd),
                    )
                    .flatten()?
                    .bits())
            }
            FcntlArg::SETFL(flags) => {
                let setfl_mask = OFlags::APPEND
                    | OFlags::NONBLOCK
                    | OFlags::NDELAY
                    | OFlags::DIRECT
                    | OFlags::NOATIME;
                let flags = flags & setfl_mask;
                macro_rules! toggle_flags {
                    ($fd:ident) => {{
                        // TODO: Consider shared metadata table?
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle($fd)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|file| {
                            let diff = (file.get_status() & setfl_mask) ^ flags;
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                            file.set_status(flags & setfl_mask, true);
                            file.set_status(flags.complement() & setfl_mask, false);
                        });
                    }};
                }
                macro_rules! setfl_in_metadata {
                    ($fd:expr, $MetaType:path, $no_metadata_msg:expr) => {
                        setfl_in_metadata!($fd, $MetaType, $no_metadata_msg, |diff: OFlags| {
                            if diff.intersects(OFlags::APPEND | OFlags::DIRECT | OFlags::NOATIME) {
                                log_unsupported!("unsupported flags");
                            }
                        })
                    };
                    ($fd:expr, $MetaType:path, $no_metadata_msg:expr, $check_diff:expr) => {
                        self.global
                            .litebox
                            .descriptor_table_mut()
                            .with_metadata_mut($fd, |$MetaType(f)| {
                                let diff = (*f & setfl_mask) ^ flags;
                                $check_diff(diff);
                                f.toggle(diff);
                            })
                            .map_err(|err| match err {
                                MetadataError::ClosedFd => Errno::EBADF,
                                MetadataError::NoSuchMetadata => $no_metadata_msg,
                            })
                    };
                }
                files.run_on_raw_fd(
                    desc,
                    |fd| {
                        setfl_in_metadata!(
                            fd,
                            crate::StdioStatusFlags,
                            unimplemented!("SETFL on non-stdio")
                        )
                    },
                    |fd| {
                        setfl_in_metadata!(
                            fd,
                            crate::syscalls::net::SocketOFlags,
                            unreachable!("all sockets have SocketOFlags when created")
                        )
                    },
                    |fd| {
                        // Update the actual pipe non-blocking behavior
                        self.global
                            .pipes
                            .update_flags(
                                fd,
                                litebox::pipes::Flags::NON_BLOCKING,
                                flags.intersects(OFlags::NONBLOCK),
                            )
                            .map_err(Errno::from)?;
                        // Record all status flags in metadata for F_GETFL
                        setfl_in_metadata!(
                            fd,
                            crate::PipeStatusFlags,
                            unreachable!("all pipes have PipeStatusFlags when created"),
                            |_| {}
                        )
                    },
                    |fd| {
                        toggle_flags!(fd);
                        Ok(())
                    },
                    |_fd| todo!("epoll"),
                    |fd| {
                        toggle_flags!(fd);
                        Ok(())
                    },
                )??;
                Ok(0)
            }
            FcntlArg::GETLK(lock) => {
                self.files
                    .borrow()
                    .run_on_raw_fd(
                        desc,
                        |_fd| {
                            let mut flock = lock.read_at_offset(0).ok_or(Errno::EFAULT)?;
                            let lock_type = litebox_common_linux::FlockType::try_from(flock.type_)
                                .map_err(|_| Errno::EINVAL)?;
                            if let litebox_common_linux::FlockType::Unlock = lock_type {
                                return Err(Errno::EINVAL);
                            }

                            // Note LiteBox does not support multiple processes yet, and one process
                            // can always acquire the lock it owns, so return `Unlock` unconditionally.
                            flock.type_ = litebox_common_linux::FlockType::Unlock as i16;
                            lock.write_at_offset(0, flock).ok_or(Errno::EFAULT)?;
                            Ok(0)
                        },
                        |_fd| todo!("net"),
                        |_fd| todo!("pipes"),
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                    )
                    .flatten()
            }
            FcntlArg::SETLK(lock) | FcntlArg::SETLKW(lock) => {
                self.files
                    .borrow()
                    .run_on_raw_fd(
                        desc,
                        |_fd| {
                            let flock = lock.read_at_offset(0).ok_or(Errno::EFAULT)?;
                            let _ = litebox_common_linux::FlockType::try_from(flock.type_)
                                .map_err(|_| Errno::EINVAL)?;

                            // Note LiteBox does not support multiple processes yet, and one process
                            // can always acquire the lock it owns, so we don't need to maintain anything.
                            Ok(0)
                        },
                        |_fd| todo!("net"),
                        |_fd| todo!("pipes"),
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                        |_fd| Err(Errno::EBADF),
                    )
                    .flatten()
            }
            FcntlArg::DUPFD { cloexec, min_fd } => {
                let new_file = self.do_dup(
                    desc,
                    if cloexec {
                        OFlags::CLOEXEC
                    } else {
                        OFlags::empty()
                    },
                )?;
                let max_fd = self
                    .process()
                    .limits
                    .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE);
                if min_fd as usize >= max_fd {
                    return Err(Errno::EINVAL);
                }
                if new_file < min_fd as usize || new_file > max_fd {
                    self.do_close(new_file)?;
                    return Err(Errno::EMFILE);
                }
                Ok(new_file.try_into().unwrap())
            }
            _ => unimplemented!(),
        }
    }

    /// Handle syscall `getcwd`
    pub fn sys_getcwd(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let cwd = self.fs.borrow().cwd.read().clone();
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

    /// Handle syscall `chdir`
    pub fn sys_chdir(&self, pathname: impl path::Arg) -> Result<(), Errno> {
        use litebox::fs::FileType;
        use litebox::fs::errors::{FileStatusError, PathError};
        use litebox::path::Arg as _;

        // Resolve relative paths against CWD, then normalize (handle `.` / `..`).
        let resolved = self.resolve_path(pathname)?;
        let abs_path = resolved.normalized().map_err(|_| Errno::EINVAL)?;

        // Verify the path exists and is a directory.
        match self.files.borrow().fs.file_status(abs_path.as_str()) {
            Ok(status) => {
                if status.file_type != FileType::Directory {
                    return Err(Errno::ENOTDIR);
                }
            }
            Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory)) => {
                return Err(Errno::ENOENT);
            }
            Err(FileStatusError::PathError(_)) => {
                return Err(Errno::EACCES);
            }
            Err(_) => {
                return Err(Errno::ENOENT);
            }
        }

        // Ensure the CWD ends with '/'.
        let mut new_cwd = abs_path;
        if !new_cwd.ends_with('/') {
            new_cwd.push('/');
        }

        *self.fs.borrow().cwd.write() = new_cwd;
        Ok(())
    }
}

const DEFAULT_PIPE_BUF_SIZE: usize = 1024 * 1024;

impl<FS: ShimFS> Task<FS> {
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

        let (writer, reader) = self.global.pipes.create_pipe(
            DEFAULT_PIPE_BUF_SIZE,
            pipe_flags,
            // See `man 7 pipe` for `PIPE_BUF`. On Linux, this is 4096.
            core::num::NonZero::new(4096),
        );

        {
            let initial_status = OFlags::from(pipe_flags);
            let mut dt = self.global.litebox.descriptor_table_mut();
            let old = dt.set_entry_metadata(
                &writer,
                crate::PipeStatusFlags(initial_status | OFlags::WRONLY),
            );
            assert!(old.is_none());
            let old = dt.set_entry_metadata(
                &reader,
                crate::PipeStatusFlags(initial_status | OFlags::RDONLY),
            );
            assert!(old.is_none());
        }

        if cloexec {
            let mut dt = self.global.litebox.descriptor_table_mut();
            let None = dt.set_fd_metadata(&writer, FileDescriptorFlags::FD_CLOEXEC) else {
                unreachable!()
            };
            let None = dt.set_fd_metadata(&reader, FileDescriptorFlags::FD_CLOEXEC) else {
                unreachable!()
            };
        }

        let files = self.files.borrow();
        let wr_raw_fd = files.insert_raw_fd(writer).map_err(|writer| {
            self.global.pipes.close(&writer).unwrap();
            Errno::EMFILE
        })?;
        let rd_raw_fd = files.insert_raw_fd(reader).map_err(|reader| {
            let writer = files
                .raw_descriptor_store
                .write()
                .fd_consume_raw_integer(wr_raw_fd)
                .unwrap();
            self.global.pipes.close(&writer).unwrap();
            self.global.pipes.close(&reader).unwrap();
            Errno::EMFILE
        })?;
        Ok((rd_raw_fd.try_into().unwrap(), wr_raw_fd.try_into().unwrap()))
    }

    pub fn sys_eventfd2(&self, initval: u32, flags: EfdFlags) -> Result<u32, Errno> {
        if flags
            .contains((EfdFlags::SEMAPHORE | EfdFlags::CLOEXEC | EfdFlags::NONBLOCK).complement())
        {
            return Err(Errno::EINVAL);
        }

        let eventfd = super::eventfd::EventFile::new(u64::from(initval), flags);
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<super::eventfd::EventfdSubsystem>(eventfd);
        if flags.contains(EfdFlags::CLOEXEC) {
            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        drop(dt);
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
            self.global
                .litebox
                .descriptor_table_mut()
                .remove(&typed)
                .unwrap();
            Errno::EMFILE
        })?;
        Ok(raw_fd.try_into().unwrap())
    }

    fn stdio_ioctl(
        &self,
        arg: &IoctlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        match arg {
            IoctlArg::TCGETS(termios) => {
                termios
                    .write_at_offset(
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
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            IoctlArg::TCSETS(_) => Ok(0), // TODO: implement
            IoctlArg::TIOCGWINSZ(ws) => {
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
            }
            IoctlArg::TIOCGPTN(_) => Err(Errno::ENOTTY),
            _ => todo!(),
        }
    }

    fn is_stdio(&self, fs: &FS, fd: &TypedFd<FS>) -> Result<bool, Errno> {
        match fs.fd_file_status(fd) {
            Ok(status) => {
                // See https://www.kernel.org/doc/Documentation/admin-guide/devices.txt
                let major = status.node_info.rdev.map_or(0, |v| v.get() >> 8);
                Ok((136..=143).contains(&major)
                    && status.file_type == litebox::fs::FileType::CharacterDevice)
            }
            Err(litebox::fs::errors::FileStatusError::ClosedFd) => Err(Errno::EBADF),
            Err(_) => unimplemented!(),
        }
    }

    /// Handle syscall `ioctl`
    pub fn sys_ioctl(
        &self,
        fd: i32,
        arg: IoctlArg<litebox_platform_multiplex::Platform>,
    ) -> Result<u32, Errno> {
        let Ok(desc) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match arg {
            IoctlArg::FIONBIO(arg) => {
                let val = arg.read_at_offset(0).ok_or(Errno::EFAULT)?;
                self.files
                    .borrow()
                    .run_on_raw_fd(
                        desc,
                        |_file_fd| {
                            // TODO: stdio NONBLOCK?
                            #[cfg(debug_assertions)]
                            litebox::log_println!(
                                self.global.platform,
                                "Attempted to set non-blocking on raw fd; currently unimplemented"
                            );
                            Ok(())
                        },
                        |socket_fd| {
                            if let Err(e) = self
                                .global
                                .litebox
                                .descriptor_table_mut()
                                .with_metadata_mut(
                                    socket_fd,
                                    |crate::syscalls::net::SocketOFlags(flags)| {
                                        flags.set(OFlags::NONBLOCK, val != 0);
                                    },
                                )
                            {
                                match e {
                                    MetadataError::ClosedFd => return Err(Errno::EBADF),
                                    MetadataError::NoSuchMetadata => unreachable!(),
                                }
                            }
                            Ok(())
                        },
                        |fd| {
                            self.global
                                .pipes
                                .update_flags(fd, litebox::pipes::Flags::NON_BLOCKING, val != 0)
                                .map_err(Errno::from)
                        },
                        |fd| {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                file.set_status(OFlags::NONBLOCK, val != 0);
                            });
                            Ok(())
                        },
                        |fd| {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                file.set_status(OFlags::NONBLOCK, val != 0);
                            });
                            Ok(())
                        },
                        |fd| {
                            let handle = self
                                .global
                                .litebox
                                .descriptor_table()
                                .entry_handle(fd)
                                .ok_or(Errno::EBADF)?;
                            handle.with_entry(|file| {
                                file.set_status(OFlags::NONBLOCK, val != 0);
                            });
                            Ok(())
                        },
                    )
                    .flatten()?;
                Ok(0)
            }
            IoctlArg::FIOCLEX => files.run_on_raw_fd(
                desc,
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |_fd| todo!("net"),
                |_fd| todo!("pipes"),
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
                |fd| {
                    let _old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(fd, FileDescriptorFlags::FD_CLOEXEC);
                    Ok(0)
                },
            )?,
            IoctlArg::TCGETS(..)
            | IoctlArg::TCSETS(..)
            | IoctlArg::TIOCGPTN(..)
            | IoctlArg::TIOCGWINSZ(..) => files.run_on_raw_fd(
                desc,
                |fd| {
                    if self.is_stdio(&files.fs, fd)? {
                        self.stdio_ioctl(&arg)
                    } else {
                        Err(Errno::ENOTTY)
                    }
                },
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
                |_fd| Err(Errno::ENOTTY),
            )?,
            _ => {
                #[cfg(debug_assertions)]
                litebox::log_println!(self.global.platform, "\n\n\n{:?}\n\n\n", arg);
                todo!()
            }
        }
    }

    /// Handle syscall `epoll_create` and `epoll_create1`
    pub fn sys_epoll_create(&self, flags: EpollCreateFlags) -> Result<u32, Errno> {
        if flags.contains(EpollCreateFlags::EPOLL_CLOEXEC.complement()) {
            return Err(Errno::EINVAL);
        }

        let epoll_file = super::epoll::EpollFile::new();
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<super::epoll::EpollSubsystem<FS>>(epoll_file);
        if flags.contains(EpollCreateFlags::EPOLL_CLOEXEC) {
            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        drop(dt);
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
            self.global
                .litebox
                .descriptor_table_mut()
                .remove(&typed)
                .unwrap();
            Errno::EMFILE
        })?;
        Ok(raw_fd.try_into().unwrap())
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

        let epoll_fd = files
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<super::epoll::EpollSubsystem<FS>>(epfd as usize)
            .map_err(|_| Errno::EBADF)?;
        let file_descriptor = super::epoll::EpollDescriptor::try_from(&files, fd as usize)?;

        let event = if op == litebox_common_linux::EpollOp::EpollCtlDel {
            None
        } else {
            Some(event.read_at_offset(0).ok_or(Errno::EFAULT)?)
        };
        let handle = self
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&epoll_fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(|entry| entry.epoll_ctl(&self.global, op, fd, &file_descriptor, event))
    }

    /// Handle syscall `epoll_pwait`
    pub fn sys_epoll_pwait(
        &self,
        epfd: i32,
        events: MutPtr<litebox_common_linux::EpollEvent>,
        maxevents: u32,
        timeout: i32,
        sigmask: Option<ConstPtr<litebox_common_linux::signal::SigSet>>,
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
        let handle = {
            let files = self.files.borrow();
            {
                let raw_fd = usize::try_from(epfd).or(Err(Errno::EBADF))?;
                let Ok(fd) =
                    files
                        .raw_descriptor_store
                        .read()
                        .fd_from_raw_integer::<crate::syscalls::epoll::EpollSubsystem<FS>>(raw_fd)
                else {
                    return Err(Errno::EBADF);
                };
                self.global
                    .litebox
                    .descriptor_table()
                    .entry_handle(&fd)
                    .ok_or(Errno::EBADF)?
            }
        };
        handle.with_entry(|epoll_file| {
            match epoll_file.wait(
                &self.global,
                &self.wait_cx().with_timeout(timeout),
                maxevents,
            ) {
                Ok(epoll_events) => {
                    if !epoll_events.is_empty() {
                        events
                            .copy_from_slice(0, &epoll_events)
                            .ok_or(Errno::EFAULT)?;
                    }
                    Ok(epoll_events.len())
                }
                Err(WaitError::TimedOut) => Ok(0),
                Err(WaitError::Interrupted) => Err(Errno::EINTR),
            }
        })
    }

    /// Handle syscall `ppoll`.
    pub fn sys_ppoll(
        &self,
        fds: MutPtr<litebox_common_linux::Pollfd>,
        nfds: usize,
        timeout: TimeParam<Platform>,
        sigmask: Option<ConstPtr<litebox_common_linux::signal::SigSet>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if sigmask.is_some() {
            if sigsetsize != core::mem::size_of::<litebox_common_linux::signal::SigSet>() {
                // Expected via ppoll(2) manpage
                unimplemented!()
            }
            unimplemented!("no sigmask support yet");
        }
        let timeout = timeout.read()?;
        let nfds_signed = isize::try_from(nfds).map_err(|_| Errno::EINVAL)?;

        let mut set = super::epoll::PollSet::with_capacity(nfds);
        for i in 0..nfds_signed {
            let fd = fds.read_at_offset(i).ok_or(Errno::EFAULT)?;

            let events = litebox::event::Events::from_bits_truncate(
                fd.events.reinterpret_as_unsigned().into(),
            );
            set.add_fd(fd.fd, events);
        }

        match set.wait(
            &self.global,
            &self.wait_cx().with_timeout(timeout),
            &self.files.borrow(),
        ) {
            Ok(()) => {}
            Err(WaitError::Interrupted) => {
                // TODO: update the remaining time.
                return Err(Errno::EINTR);
            }
            Err(WaitError::TimedOut) => {
                // A timeout occurred. Scan one last time.
                set.scan(&self.global, &self.files.borrow());
            }
        }

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
            revents_ptr
                .write_at_offset(0, revents.reinterpret_as_signed())
                .ok_or(Errno::EFAULT)?;
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
        // XXX: semantic issue likely should be fixed here to make sure EBADF is triggered early
        // enough if needed. Previously, `file_table_len` used to be
        // `self.files.borrow().file_descriptors.read().len()` before `file_descriptors` was
        // removed to clean up the table handling.
        let file_table_len = usize::MAX;
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

        match set.wait(
            &self.global,
            &self.wait_cx().with_timeout(timeout),
            &self.files.borrow(),
        ) {
            Ok(()) => {}
            Err(WaitError::Interrupted) => {
                // TODO: update the remaining time.
                return Err(Errno::EINTR);
            }
            Err(WaitError::TimedOut) => {
                // A timeout occurred. Scan one last time.
                set.scan(&self.global, &self.files.borrow());
            }
        }

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

    /// Handle syscall `pselect`.
    pub(crate) fn sys_pselect(
        &self,
        nfds: u32,
        readfds: Option<MutPtr<usize>>,
        writefds: Option<MutPtr<usize>>,
        exceptfds: Option<MutPtr<usize>>,
        timeout: TimeParam<Platform>,
        sigsetpack: Option<ConstPtr<litebox_common_linux::SigSetPack>>,
    ) -> Result<usize, Errno> {
        if sigsetpack.is_some() {
            unimplemented!("no sigsetpack support yet");
        }
        let timeout = timeout.read()?;
        if nfds >= i32::MAX as u32
            || nfds as usize
                > self
                    .process()
                    .limits
                    .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE)
        {
            return Err(Errno::EINVAL);
        }
        let len = (nfds as usize).div_ceil(core::mem::size_of::<usize>() * 8);
        let mut kreadfds = readfds
            .map(|fds| fds.to_owned_slice(len).ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_vec()));
        let mut kwritefds = writefds
            .map(|fds| fds.to_owned_slice(len).ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_vec()));
        let mut kexceptfds = exceptfds
            .map(|fds| fds.to_owned_slice(len).ok_or(Errno::EFAULT))
            .transpose()?
            .map(|fds| bitvec::vec::BitVec::from_vec(fds.into_vec()));

        let count = self.do_pselect(
            nfds,
            kreadfds.as_mut(),
            kwritefds.as_mut(),
            kexceptfds.as_mut(),
            timeout,
        )?;

        if let Some(fds) = kreadfds {
            readfds
                .unwrap()
                .write_slice_at_offset(0, fds.as_raw_slice())
                .ok_or(Errno::EFAULT)?;
        }
        if let Some(fds) = kwritefds {
            writefds
                .unwrap()
                .write_slice_at_offset(0, fds.as_raw_slice())
                .ok_or(Errno::EFAULT)?;
        }
        if let Some(fds) = kexceptfds {
            exceptfds
                .unwrap()
                .write_slice_at_offset(0, fds.as_raw_slice())
                .ok_or(Errno::EFAULT)?;
        }

        Ok(count)
    }

    fn do_dup(&self, file: usize, flags: OFlags) -> Result<usize, Errno> {
        self.do_dup_inner(file, flags, None)
    }

    fn do_dup_inner(
        &self,
        file: usize,
        flags: OFlags,
        target: Option<usize>,
    ) -> Result<usize, Errno> {
        fn dup<FS: ShimFS, S: FdEnabledSubsystem>(
            global: &GlobalState<FS>,
            files: &FilesState<FS>,
            fd: &TypedFd<S>,
            close_on_exec: bool,
            target: Option<usize>,
        ) -> Result<usize, Errno> {
            let mut dt = global.litebox.descriptor_table_mut();
            let fd: TypedFd<_> = dt.duplicate(fd).ok_or(Errno::EBADF)?;
            if close_on_exec {
                let old = dt.set_fd_metadata(&fd, FileDescriptorFlags::FD_CLOEXEC);
                assert!(old.is_none());
            }
            let mut rds = files.raw_descriptor_store.write();
            if let Some(target) = target {
                if !rds.fd_into_specific_raw_integer(fd, target) {
                    return Err(Errno::EBADF);
                }
                Ok(target)
            } else {
                Ok(rds.fd_into_raw_integer(fd))
            }
        }
        let close_on_exec = flags.contains(OFlags::CLOEXEC);
        let files = self.files.borrow();
        let new_fd = files.run_on_raw_fd(
            file,
            |fd| dup(&self.global, &files, fd, close_on_exec, target),
            |fd| dup(&self.global, &files, fd, close_on_exec, target),
            |fd| dup(&self.global, &files, fd, close_on_exec, target),
            |fd| dup(&self.global, &files, fd, close_on_exec, target),
            |fd| dup(&self.global, &files, fd, close_on_exec, target),
            |fd| dup(&self.global, &files, fd, close_on_exec, target),
        )??;
        if target.is_none() {
            let max_fd = self
                .process()
                .limits
                .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE);
            if new_fd >= max_fd {
                self.do_close(new_fd)?;
                return Err(Errno::EMFILE);
            }
        }
        Ok(new_fd)
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
        let oldfd_usize = usize::try_from(oldfd).or(Err(Errno::EBADF))?;
        if !self
            .files
            .borrow()
            .raw_descriptor_store
            .read()
            .is_alive(oldfd_usize)
        {
            return Err(Errno::EBADF);
        }
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
            // Close whatever is at newfd before duping into it
            let newfd_usize = usize::try_from(newfd).or(Err(Errno::EBADF))?;
            let _ = self.do_close(newfd_usize);
            self.do_dup_inner(
                oldfd_usize,
                flags.unwrap_or(OFlags::empty()),
                Some(newfd_usize),
            )?;
            Ok(newfd)
        } else {
            // dup
            let new_file = self.do_dup(oldfd_usize, flags.unwrap_or(OFlags::empty()))?;
            Ok(u32::try_from(new_file).unwrap())
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Diroff(usize);

const DIRENT_STRUCT_BYTES_WITHOUT_NAME: usize =
    core::mem::offset_of!(litebox_common_linux::LinuxDirent64, __name);

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `getdents64`
    pub(crate) fn sys_getdirent64(
        &self,
        fd: i32,
        dirp: MutPtr<u8>,
        count: usize,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        let files = self.files.borrow();
        files.run_on_raw_fd(
            fd,
            |file| {
                let dir_off: Diroff = self
                    .global
                    .litebox
                    .descriptor_table()
                    .with_metadata(file, |off: &Diroff| *off)
                    .unwrap_or_default();
                let mut dir_off = dir_off.0;
                let mut nbytes = 0;

                let mut entries = files.fs.read_dir(file)?;
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
                    hdr_ptr.write_at_offset(0, dirent64).ok_or(Errno::EFAULT)?;
                    let name_ptr = crate::MutPtr::from_usize(
                        hdr_ptr.as_usize() + DIRENT_STRUCT_BYTES_WITHOUT_NAME,
                    );
                    name_ptr
                        .write_slice_at_offset(0, entry.name.as_bytes())
                        .ok_or(Errno::EFAULT)?;
                    // set the null terminator and padding
                    let zeros_len = len - (DIRENT_STRUCT_BYTES_WITHOUT_NAME + entry.name.len());
                    name_ptr
                        .write_slice_at_offset(
                            isize::try_from(entry.name.len()).unwrap(),
                            &vec![0; zeros_len],
                        )
                        .ok_or(Errno::EFAULT)?;
                    nbytes += len;
                    dir_off += 1;
                }
                let _old = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(file, Diroff(dir_off));
                Ok(nbytes)
            },
            |_fd| todo!("net"),
            |_fd| todo!("pipes"),
            |_fd| Err(Errno::EBADF),
            |_fd| Err(Errno::EBADF),
            |_fd| Err(Errno::EBADF),
        )?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use litebox::fs::Mode;

    extern crate std;

    #[test]
    fn fspath_new() {
        // Absolute paths should never invoke the get_cwd closure.
        let fp = FsPath::new(litebox_common_linux::AT_FDCWD, "/usr/bin", || {
            panic!("get_cwd should not be called for absolute paths")
        })
        .unwrap();
        assert!(matches!(fp, FsPath::Absolute { path } if path.to_str().unwrap() == "/usr/bin"));

        // Relative path resolves against CWD.
        let fp = FsPath::new(litebox_common_linux::AT_FDCWD, "foo/bar", || {
            String::from("/home/")
        })
        .unwrap();
        assert!(
            matches!(fp, FsPath::Absolute { path } if path.to_str().unwrap() == "/home/foo/bar")
        );

        // Empty path at AT_FDCWD → Cwd variant.
        let fp = FsPath::new(litebox_common_linux::AT_FDCWD, "", || {
            panic!("get_cwd should not be called for empty Cwd path")
        })
        .unwrap();
        assert!(matches!(fp, FsPath::Cwd));

        // Positive fd + empty path → Fd variant.
        let fp = FsPath::new(5, "", || panic!("should not be called")).unwrap();
        assert!(matches!(fp, FsPath::Fd(5)));

        // Invalid dirfd → EBADF.
        let err = FsPath::new(-1, "file.txt", || panic!("should not be called")).unwrap_err();
        assert_eq!(err, Errno::EBADF);

        // Path exceeding PATH_MAX → ENAMETOOLONG.
        let long_path = "a".repeat(PATH_MAX + 1);
        let err = FsPath::new(litebox_common_linux::AT_FDCWD, long_path.as_str(), || {
            String::from("/")
        })
        .unwrap_err();
        assert_eq!(err, Errno::ENAMETOOLONG);
    }

    #[test]
    fn getcwd_and_chdir() {
        let task = crate::syscalls::tests::init_platform(None);

        // Default CWD is root.
        let mut buf = [0u8; 256];
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap(); // strip NUL
        assert_eq!(cwd, "/");

        // chdir + getcwd round trip.
        task.sys_mkdir("/test_chdir_dir", 0o777).unwrap();
        task.sys_chdir("/test_chdir_dir").unwrap();
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap();
        assert_eq!(cwd, "/test_chdir_dir/");

        // chdir to nonexistent path → ENOENT.
        assert_eq!(
            task.sys_chdir("/does_not_exist").unwrap_err(),
            Errno::ENOENT
        );

        // chdir to a regular file → ENOTDIR.
        let fd = task
            .sys_open(
                "/test_chdir_file",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        let _ = task.sys_close(i32::try_from(fd).unwrap());
        assert_eq!(
            task.sys_chdir("/test_chdir_file").unwrap_err(),
            Errno::ENOTDIR
        );

        // getcwd with too-small buffer → ERANGE.
        let mut tiny = [0u8; 1];
        assert_eq!(task.sys_getcwd(&mut tiny).unwrap_err(), Errno::ERANGE);
    }

    #[test]
    fn chdir_relative_path() {
        let task = crate::syscalls::tests::init_platform(None);

        // Create nested dirs: /rel_parent/rel_child
        task.sys_mkdir("/rel_parent", 0o777).unwrap();
        task.sys_mkdir("/rel_parent/rel_child", 0o777).unwrap();

        // chdir to /rel_parent first, then relative chdir into child.
        task.sys_chdir("/rel_parent").unwrap();
        task.sys_chdir("rel_child").unwrap();

        let mut buf = [0u8; 256];
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap();
        assert_eq!(cwd, "/rel_parent/rel_child/");

        // chdir("..") should normalize back to /rel_parent/.
        task.sys_chdir("..").unwrap();
        let len = task.sys_getcwd(&mut buf).unwrap();
        let cwd = core::str::from_utf8(&buf[..len - 1]).unwrap();
        assert_eq!(cwd, "/rel_parent/");
    }

    /// Verify every path-taking syscall resolves relative paths after `chdir`.
    #[test]
    fn all_path_syscalls_respect_chdir() {
        use litebox_common_linux::{AccessFlags, AtFlags};

        let task = crate::syscalls::tests::init_platform(None);

        // Set up: mkdir + chdir into /cwd_test/.
        task.sys_mkdir("/cwd_test", 0o777).unwrap();
        task.sys_chdir("/cwd_test").unwrap();

        // ── sys_open: create a file via relative path ──
        let fd = task
            .sys_open(
                "file.txt",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();

        // ── sys_stat: stat the relative file ──
        task.sys_stat("file.txt").unwrap();

        // ── sys_lstat: lstat the relative file ──
        task.sys_lstat("file.txt").unwrap();

        // ── sys_access: check relative file is accessible ──
        task.sys_access("file.txt", AccessFlags::F_OK).unwrap();

        // ── sys_mkdir: create a subdirectory via relative path ──
        task.sys_mkdir("subdir", 0o777).unwrap();
        task.sys_stat("/cwd_test/subdir").unwrap(); // verify via absolute

        // ── sys_openat (AT_FDCWD + relative): open inside the new subdir ──
        let fd = task
            .sys_openat(
                litebox_common_linux::AT_FDCWD,
                "subdir/inner.txt",
                litebox::fs::OFlags::CREAT | litebox::fs::OFlags::WRONLY,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();

        // ── sys_newfstatat (AT_FDCWD + relative) ──
        task.sys_newfstatat(
            litebox_common_linux::AT_FDCWD,
            "subdir/inner.txt",
            AtFlags::empty(),
        )
        .unwrap();

        // ── sys_unlinkat: remove a file via relative path ──
        task.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            "subdir/inner.txt",
            AtFlags::empty(),
        )
        .unwrap();
        assert_eq!(
            task.sys_stat("/cwd_test/subdir/inner.txt").unwrap_err(),
            Errno::ENOENT
        );

        // ── sys_unlinkat (AT_REMOVEDIR): remove directory via relative path ──
        task.sys_unlinkat(
            litebox_common_linux::AT_FDCWD,
            "subdir",
            AtFlags::AT_REMOVEDIR,
        )
        .unwrap();
        assert_eq!(
            task.sys_stat("/cwd_test/subdir").unwrap_err(),
            Errno::ENOENT
        );
    }
}
