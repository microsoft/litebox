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
    mm::linux::PAGE_SIZE,
    path,
    platform::{RawConstPointer, RawMutPointer},
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _, TruncateExt as _},
};
use litebox_common_linux::{
    AccessFlags, AtFlags, EfdFlags, EpollCreateFlags, FcntlArg, FileDescriptorFlags, FileStat,
    InodeType, IoReadVec, IoWriteVec, IoctlArg, Statx, StatxMask, TimeParam, errno::Errno,
    signal::Signal,
};
use litebox_platform_multiplex::Platform;
use thiserror::Error;

use crate::{ConstPtr, GlobalState, MutPtr, ShimFS, Task, syscalls::signal};
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy)]
struct AccessUserInfo {
    user: u32,
    group: u32,
}

impl From<litebox::fs::UserInfo> for AccessUserInfo {
    fn from(value: litebox::fs::UserInfo) -> Self {
        Self {
            user: u32::from(value.user),
            group: u32::from(value.group),
        }
    }
}

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
    pub(crate) fn resolve_path(&self, path: impl path::Arg) -> Result<CString, Errno> {
        let path_str = path.as_rust_str().map_err(|_| Errno::EINVAL)?;
        if path_str.is_empty() {
            return Err(Errno::ENOENT);
        }
        if path_str.starts_with('/') {
            CString::new(path_str.to_string()).map_err(|_| Errno::EINVAL)
        } else {
            let mut cwd = self.fs.borrow().cwd.read().clone();
            cwd.push_str(path_str);
            CString::new(cwd).map_err(|_| Errno::EINVAL)
        }
    }

    /// Resolve a path relative to a dirfd.
    ///
    /// Note that an empty path is not valid for this function, and will be rejected with `ENOENT`.
    fn resolve_path_at(&self, dirfd: i32, pathname: impl path::Arg) -> Result<CString, Errno> {
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        match fs_path {
            FsPath::Absolute { path } => Ok(path),
            FsPath::Cwd | FsPath::Fd(_) => Err(Errno::ENOENT),
            FsPath::FdRelative { fd: _, path: _ } => {
                log_unsupported!("path resolution with FsPath::FdRelative");
                Err(Errno::EINVAL)
            }
        }
    }

    pub(crate) fn do_open(
        &self,
        path: impl path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<TypedFd<FS>, Errno> {
        let mode = mode & !self.get_umask();
        self.files
            .borrow()
            .fs
            .open(path, flags - OFlags::CLOEXEC, mode)
            .map_err(Errno::from)
    }

    fn do_openat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<TypedFd<FS>, Errno> {
        let path = self.resolve_path_at(dirfd, pathname)?;
        self.do_open(path, flags, mode)
    }

    fn insert_raw_file_fd(&self, file: TypedFd<FS>, flags: OFlags) -> Result<u32, Errno> {
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
        let file = self.do_open(path, flags, mode)?;
        self.insert_raw_file_fd(file, flags)
    }

    /// Handle syscall `openat`
    pub fn sys_openat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<u32, Errno> {
        let file = self.do_openat(dirfd, pathname, flags, mode)?;
        self.insert_raw_file_fd(file, flags)
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

    /// Handle syscall `mknodat` — create a filesystem node.
    pub(crate) fn sys_mknodat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        mode_and_type: u32,
        _dev: u32,
    ) -> Result<(), Errno> {
        const FILE_TYPE_MASK: u32 = 0o170000;

        let file_type = mode_and_type & FILE_TYPE_MASK;
        let file_type = if file_type == 0 {
            // zero translates to S_IFREG
            InodeType::File
        } else {
            InodeType::try_from(file_type).map_err(|_| Errno::EINVAL)?
        };
        match file_type {
            InodeType::File => {
                let mode = Mode::from_bits_truncate(mode_and_type & !FILE_TYPE_MASK);
                let file = self.do_openat(
                    dirfd,
                    pathname,
                    OFlags::CREAT | OFlags::EXCL | OFlags::WRONLY,
                    mode,
                )?;
                let files = self.files.borrow();
                let _ = files.fs.close(&file);
            }
            // TODO: Named pipe, socket, block and char files are not supported
            InodeType::NamedPipe
            | InodeType::Socket
            | InodeType::BlockDevice
            | InodeType::CharDevice
            | InodeType::Dir => return Err(Errno::EPERM),
            InodeType::SymLink => return Err(Errno::EINVAL),
        }
        Ok(())
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

        let path = self.resolve_path_at(dirfd, pathname)?;
        if flags.contains(AtFlags::AT_REMOVEDIR) {
            self.files.borrow().fs.rmdir(path).map_err(Errno::from)
        } else {
            self.files.borrow().fs.unlink(path).map_err(Errno::from)
        }
    }

    /// Handle syscall `read`
    ///
    /// `offset` is an optional offset to read from. If `None`, it will read from the current file position.
    /// If `Some`, it will read from the specified offset without changing the current file position.
    pub fn sys_read(&self, fd: i32, buf: &mut [u8], offset: Option<usize>) -> Result<usize, Errno> {
        let Ok(raw_fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        self.do_read(raw_fd, buf, offset)
    }
    pub(crate) fn do_read(
        &self,
        fd: u32,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, Errno> {
        let files = self.files.borrow();
        // We need to do this cell dance because otherwise Rust can't recognize that the two
        // closures are mutually exclusive.
        let buf: core::cell::RefCell<&mut [u8]> = core::cell::RefCell::new(buf);
        let n = files
            .run_on_raw_fd(
                fd as usize,
                |fd| {
                    files
                        .fs
                        .read(fd, &mut buf.borrow_mut(), offset)
                        .map_err(Errno::from)
                },
                |fd| {
                    espipe_for_non_seekable_offset(offset)?;
                    self.global.receive(
                        &self.wait_cx(),
                        fd,
                        &mut buf.borrow_mut(),
                        litebox_common_linux::ReceiveFlags::empty(),
                        None,
                    )
                },
                |fd| {
                    espipe_for_non_seekable_offset(offset)?;
                    self.global
                        .read_linux_pipe(&self.wait_cx(), fd, &mut buf.borrow_mut())
                },
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    espipe_for_non_seekable_offset(offset)?;
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
                    espipe_for_non_seekable_offset(offset)?;
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
            .flatten()?;
        // For datagrams, the returned size represents the actual size of the message,
        // which may be larger than the buffer size.
        let capped_size = n.min(buf.borrow().len());
        Ok(capped_size)
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
                    espipe_for_non_seekable_offset(offset)?;
                    self.global.sendto(
                        &self.wait_cx(),
                        fd,
                        buf,
                        litebox_common_linux::SendFlags::empty(),
                        None,
                    )
                },
                |fd| {
                    espipe_for_non_seekable_offset(offset)?;
                    self.global.write_linux_pipe(&self.wait_cx(), fd, buf)
                },
                |fd| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(fd)
                        .ok_or(Errno::EBADF)?;
                    espipe_for_non_seekable_offset(offset)?;
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
                    espipe_for_non_seekable_offset(offset)?;
                    handle.with_entry(|file| {
                        file.sendto(self, buf, litebox_common_linux::SendFlags::empty(), None)
                    })
                },
            )
            .flatten();
        if let Err(Errno::EPIPE) = res {
            self.send_signal(Signal::SIGPIPE, signal::siginfo_kill(Signal::SIGPIPE));
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

    fn rewind_sendfile_in_fd(&self, in_raw_fd: usize, unread_n: usize) -> Result<(), Errno> {
        if unread_n == 0 {
            return Ok(());
        }

        let rewind = isize::try_from(unread_n).map_err(|_| Errno::EOVERFLOW)?;
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                in_raw_fd,
                |fd| {
                    files
                        .fs
                        .seek(fd, -rewind, SeekWhence::RelativeToCurrentOffset)
                        .map(|_| ())
                        .map_err(Errno::from)
                },
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
                |_fd| Err(Errno::EINVAL),
            )
            .flatten()
    }

    /// Handle syscall `sendfile`
    pub(crate) fn sys_sendfile(
        &self,
        out_fd: i32,
        in_fd: i32,
        offset_ptr: Option<MutPtr<i64>>,
        count: usize,
    ) -> Result<usize, Errno> {
        let Ok(in_raw_fd) = u32::try_from(in_fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        // TODO: Linux rejects `sendfile` with `EINVAL` when `out_fd` has `O_APPEND` set.
        self.check_raw_fd_exists(out_fd)?;

        let mut cur_off = offset_ptr
            .map(|p| {
                let off = p.read_at_offset(0).ok_or(Errno::EFAULT)?;
                if off < 0 {
                    return Err(Errno::EINVAL);
                }
                usize::try_from(off).map_err(|_| Errno::EINVAL)
            })
            .transpose()?;

        let mut kernel_buf = vec![0u8; count.min(PAGE_SIZE)];
        let mut total: usize = 0;

        while total < count {
            let to_read = (count - total).min(kernel_buf.len());

            // Non-FS sources are not seekable; Linux returns ESPIPE for any
            // non-pread-capable source when an offset is supplied, EINVAL otherwise.
            let non_fs_err = if cur_off.is_some() {
                Errno::ESPIPE
            } else {
                Errno::EINVAL
            };
            let read_result = {
                let buf_slice = &mut kernel_buf[..to_read];
                let files = self.files.borrow();
                files
                    .run_on_raw_fd(
                        in_raw_fd,
                        |fd| files.fs.read(fd, buf_slice, cur_off).map_err(Errno::from),
                        |_fd| Err(non_fs_err),
                        |_fd| Err(non_fs_err),
                        |_fd| Err(non_fs_err),
                        |_fd| Err(non_fs_err),
                        |_fd| Err(non_fs_err),
                    )
                    .flatten()
            };
            let read_n = match read_result {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if total == 0 => return Err(e),
                Err(_) => break,
            };

            let write_result = self.sys_write(out_fd, &kernel_buf[..read_n], None);
            let write_n = match write_result {
                Ok(n) => n,
                Err(e) => {
                    if offset_ptr.is_none() {
                        self.rewind_sendfile_in_fd(in_raw_fd, read_n)?;
                    }
                    if total == 0 {
                        return Err(e);
                    }
                    break;
                }
            };

            total += write_n;
            if let Some(ref mut off) = cur_off {
                *off += write_n;
            }
            if write_n < read_n {
                if offset_ptr.is_none() {
                    self.rewind_sendfile_in_fd(in_raw_fd, read_n - write_n)?;
                }
                break;
            }
        }

        if let (Some(p), Some(off)) = (offset_ptr, cur_off) {
            let off = i64::try_from(off).map_err(|_| Errno::EOVERFLOW)?;
            p.write_at_offset(0, off).ok_or(Errno::EFAULT)?;
        }

        Ok(total)
    }
}

fn espipe_for_non_seekable_offset(offset: Option<usize>) -> Result<(), Errno> {
    if offset.is_some() {
        Err(Errno::ESPIPE)
    } else {
        Ok(())
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
                |fd| match files.fs.seek(fd, offset, whence) {
                    Ok(pos) => Ok(pos),
                    Err(litebox::fs::errors::SeekError::NotAFile) => {
                        let base: usize = match whence {
                            SeekWhence::RelativeToBeginning => 0,
                            SeekWhence::RelativeToCurrentOffset => self
                                .global
                                .litebox
                                .descriptor_table()
                                .with_metadata(fd, |off: &Diroff| off.0)
                                .unwrap_or(0),
                            SeekWhence::RelativeToEnd => {
                                return Err(Errno::EINVAL);
                            }
                        };
                        let new_pos = base.checked_add_signed(offset).ok_or(Errno::EINVAL)?;
                        self.global
                            .litebox
                            .descriptor_table_mut()
                            .set_fd_metadata(fd, Diroff(new_pos));
                        Ok(new_pos)
                    }
                    Err(e) => Err(Errno::from(e)),
                },
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
        self.do_close_and_replace::<FS>(raw_fd, None)
    }

    /// Close the file at `raw_fd` and optionally place a new file in the same slot.
    ///
    /// This function ensure `close` and `insert` are done atomically.
    fn do_close_and_replace<S: FdEnabledSubsystem>(
        &self,
        raw_fd: usize,
        replace: Option<TypedFd<S>>,
    ) -> Result<(), Errno> {
        enum ConsumedFd<FS: ShimFS> {
            Fs(alloc::sync::Arc<TypedFd<FS>>),
            Network(alloc::sync::Arc<TypedFd<litebox::net::Network<Platform>>>),
            Pipes(alloc::sync::Arc<TypedFd<litebox::pipes::Pipes<Platform>>>),
            Eventfd(alloc::sync::Arc<TypedFd<super::eventfd::EventfdSubsystem>>),
            Epoll(alloc::sync::Arc<TypedFd<super::epoll::EpollSubsystem<FS>>>),
            Unix(alloc::sync::Arc<TypedFd<super::unix::UnixSocketSubsystem<FS>>>),
        }

        let files = self.files.borrow();
        let mut rds = files.raw_descriptor_store.write();
        let consumed: ConsumedFd<FS> = match rds.fd_consume_raw_integer::<FS>(raw_fd) {
            Ok(fd) => ConsumedFd::Fs(fd),
            Err(litebox::fd::ErrRawIntFd::NotFound) => {
                if let Some(new_fd) = replace {
                    let success = rds.fd_into_specific_raw_integer(new_fd, raw_fd);
                    assert!(success, "raw_fd slot is empty, so insert must succeed");
                }
                return Err(Errno::EBADF);
            }
            Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => {
                if let Ok(fd) =
                    rds.fd_consume_raw_integer::<litebox::net::Network<Platform>>(raw_fd)
                {
                    ConsumedFd::Network(fd)
                } else if let Ok(fd) =
                    rds.fd_consume_raw_integer::<litebox::pipes::Pipes<Platform>>(raw_fd)
                {
                    ConsumedFd::Pipes(fd)
                } else if let Ok(fd) =
                    rds.fd_consume_raw_integer::<super::eventfd::EventfdSubsystem>(raw_fd)
                {
                    ConsumedFd::Eventfd(fd)
                } else if let Ok(fd) =
                    rds.fd_consume_raw_integer::<super::epoll::EpollSubsystem<FS>>(raw_fd)
                {
                    ConsumedFd::Epoll(fd)
                } else if let Ok(fd) =
                    rds.fd_consume_raw_integer::<super::unix::UnixSocketSubsystem<FS>>(raw_fd)
                {
                    ConsumedFd::Unix(fd)
                } else {
                    unreachable!("all subsystems covered")
                }
            }
        };

        // Insert the replacement into the now-vacated slot while still holding the lock.
        if let Some(new_fd) = replace {
            let success = rds.fd_into_specific_raw_integer(new_fd, raw_fd);
            assert!(
                success,
                "we just consumed this raw_fd, so it must be available"
            );
        }
        drop(rds);

        match consumed {
            ConsumedFd::Fs(fd) => {
                if let Ok(raw_fd) = i32::try_from(raw_fd) {
                    self.finalize_elf_patch(raw_fd);
                }
                files.fs.close(&fd).map_err(Errno::from)
            }
            ConsumedFd::Network(fd) => self.global.close_socket(&self.wait_cx(), fd),
            ConsumedFd::Pipes(fd) => self.global.close_linux_pipe(&fd),
            ConsumedFd::Eventfd(fd) => {
                let entry = {
                    let mut dt = self.global.litebox.descriptor_table_mut();
                    dt.remove(&fd)
                };
                // do not hold any locks while dropping the entry
                drop(entry);
                Ok(())
            }
            ConsumedFd::Epoll(fd) => {
                let entry = {
                    let mut dt = self.global.litebox.descriptor_table_mut();
                    dt.remove(&fd)
                };
                // do not hold any locks while dropping the entry
                drop(entry);
                Ok(())
            }
            ConsumedFd::Unix(fd) => {
                let entry = {
                    let mut dt = self.global.litebox.descriptor_table_mut();
                    dt.remove(&fd)
                };
                // do not hold any locks while dropping the entry
                drop(entry);
                Ok(())
            }
        }
    }

    /// Handle syscall `close`
    pub(crate) fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        let Ok(raw_fd) = u32::try_from(fd).and_then(usize::try_from) else {
            return Err(Errno::EBADF);
        };
        self.do_close(raw_fd)
    }

    /// Handle syscall `preadv`
    pub(crate) fn sys_preadv(
        &self,
        fd: i32,
        iovec: ConstPtr<IoReadVec<MutPtr<u8>>>,
        iovcnt: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        let base_offset = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.check_raw_fd_exists(fd)?;
        check_iovcnt(iovcnt)?;
        let iovs: &[IoReadVec<MutPtr<u8>>] = &iovec.to_owned_slice(iovcnt).ok_or(Errno::EFAULT)?;
        let mut kernel_buffer = vec![0u8; PAGE_SIZE];
        read_from_iovec(iovs, &mut kernel_buffer, |buf, total| {
            let cur_offset = base_offset.checked_add(total).ok_or(Errno::EOVERFLOW)?;
            self.sys_read(fd, buf, Some(cur_offset))
        })
    }

    /// Handle syscall `pwritev`
    pub(crate) fn sys_pwritev(
        &self,
        fd: i32,
        iovec: ConstPtr<IoWriteVec<ConstPtr<u8>>>,
        iovcnt: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        let base_offset = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        self.check_raw_fd_exists(fd)?;
        check_iovcnt(iovcnt)?;
        let iovs: &[IoWriteVec<ConstPtr<u8>>] =
            &iovec.to_owned_slice(iovcnt).ok_or(Errno::EFAULT)?;
        // TODO: Linux ignores pwritev's offset for O_APPEND files; see the O_APPEND bug documented in pwrite(2).
        write_to_iovec(iovs, |buf, total| {
            let cur_offset = base_offset.checked_add(total).ok_or(Errno::EOVERFLOW)?;
            self.sys_write(fd, buf, Some(cur_offset))
        })
    }

    /// Handle syscall `readv`
    pub(crate) fn sys_readv(
        &self,
        fd: i32,
        iovec: ConstPtr<IoReadVec<MutPtr<u8>>>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        self.check_raw_fd_exists(fd)?;
        check_iovcnt(iovcnt)?;
        let iovs: &[IoReadVec<MutPtr<u8>>] = &iovec.to_owned_slice(iovcnt).ok_or(Errno::EFAULT)?;
        let mut kernel_buffer = vec![0u8; PAGE_SIZE];
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        read_from_iovec(iovs, &mut kernel_buffer, |buf, _total| {
            self.sys_read(fd, buf, None)
        })
    }
}

impl<FS: ShimFS> Task<FS> {
    fn check_raw_fd_exists(&self, fd: i32) -> Result<(), Errno> {
        let raw_fd = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        if self
            .files
            .borrow()
            .raw_descriptor_store
            .read()
            .is_alive(raw_fd)
        {
            Ok(())
        } else {
            Err(Errno::EBADF)
        }
    }
}

/// Linux's `IOV_MAX` / `UIO_MAXIOV`: the kernel rejects iovec counts above this
/// with `EINVAL` for `readv`/`writev`/`preadv`/`pwritev`.
const IOV_MAX: usize = 1024;
const SSIZE_MAX: usize = isize::MAX as usize;

fn check_iovcnt(iovcnt: usize) -> Result<(), Errno> {
    if iovcnt > IOV_MAX {
        Err(Errno::EINVAL)
    } else {
        Ok(())
    }
}

fn check_iov_lens(iov_lens: impl IntoIterator<Item = usize>) -> Result<(), Errno> {
    let mut total = 0usize;
    for iov_len in iov_lens {
        total = total.checked_add(iov_len).ok_or(Errno::EINVAL)?;
        if total > SSIZE_MAX {
            return Err(Errno::EINVAL);
        }
    }
    Ok(())
}

/// Drain reads into a sequence of user iovecs.
fn read_from_iovec<P, F>(
    iovs: &[IoReadVec<P>],
    kernel_buffer: &mut [u8],
    mut read_fn: F,
) -> Result<usize, Errno>
where
    P: RawMutPointer<u8>,
    F: FnMut(&mut [u8], usize) -> Result<usize, Errno>,
{
    check_iov_lens(iovs.iter().map(|iov| iov.iov_len))?;

    let bail = |total: usize, e: Errno| if total > 0 { Ok(total) } else { Err(e) };
    let mut total_read = 0;
    'outer: for iov in iovs {
        let iov_base = iov.iov_base;
        let iov_len = iov.iov_len;
        if iov_len == 0 {
            continue;
        }
        let mut iov_filled = 0;
        while iov_filled < iov_len {
            let to_read = (iov_len - iov_filled).min(kernel_buffer.len());
            let size = match read_fn(&mut kernel_buffer[..to_read], total_read) {
                Ok(0) => break 'outer,
                Ok(s) => s,
                Err(e) => return bail(total_read, e),
            };
            if iov_base
                .copy_from_slice(iov_filled, &kernel_buffer[..size])
                .is_none()
            {
                return bail(total_read, Errno::EFAULT);
            }
            iov_filled += size;
            total_read += size;
            if size < to_read {
                // Short read from the source — treat as EOF for the remaining iovecs.
                break 'outer;
            }
        }
    }
    Ok(total_read)
}

/// Drain writes from a sequence of user iovecs.
///
/// `write_fn` receives the contents of each iovec along with the total number of
/// bytes already written from earlier iovecs.
pub(super) fn write_to_iovec<P, F>(iovs: &[IoWriteVec<P>], mut write_fn: F) -> Result<usize, Errno>
where
    P: RawConstPointer<u8>,
    F: FnMut(&[u8], usize) -> Result<usize, Errno>,
{
    check_iov_lens(iovs.iter().map(|iov| iov.iov_len))?;

    // If any bytes have already been delivered from earlier iovecs, an error
    // collapses to `Ok(total)` so partial progress is reported to user space.
    let bail = |total: usize, e: Errno| if total > 0 { Ok(total) } else { Err(e) };
    let mut kernel_buffer = alloc::vec::Vec::new();
    let mut total_written = 0;
    'outer: for iov in iovs {
        let iov_base = iov.iov_base;
        let iov_len = iov.iov_len;
        if iov_len == 0 {
            continue;
        }
        if kernel_buffer.is_empty() {
            kernel_buffer.resize(PAGE_SIZE, 0);
        }
        let mut iov_written = 0;
        while iov_written < iov_len {
            let to_write = (iov_len - iov_written).min(kernel_buffer.len());
            let base_offset = isize::try_from(iov_written).unwrap();
            for (byte_offset, byte) in (0_isize..).zip(kernel_buffer[..to_write].iter_mut()) {
                let Some(value) = iov_base.read_at_offset(base_offset + byte_offset) else {
                    return bail(total_written, Errno::EFAULT);
                };
                *byte = value;
            }
            let size = match write_fn(&kernel_buffer[..to_write], total_written) {
                Ok(size) => size,
                Err(err) => return bail(total_written, err),
            };
            iov_written += size;
            total_written += size;
            if size < to_write {
                // Okay to transfer fewer bytes than requested.
                break 'outer;
            }
        }
    }
    Ok(total_written)
}

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `writev`
    pub(crate) fn sys_writev(
        &self,
        fd: i32,
        iovec: ConstPtr<IoWriteVec<ConstPtr<u8>>>,
        iovcnt: usize,
    ) -> Result<usize, Errno> {
        self.check_raw_fd_exists(fd)?;
        check_iovcnt(iovcnt)?;
        let iovs: &[IoWriteVec<ConstPtr<u8>>] =
            &iovec.to_owned_slice(iovcnt).ok_or(Errno::EFAULT)?;
        // TODO: The data transfers performed by readv() and writev() are atomic: the data
        // written by writev() is written as a single block that is not intermingled with
        // output from writes in other processes
        write_to_iovec(iovs, |buf, _total| self.sys_write(fd, buf, None))
    }

    fn validate_access_mode(mode: &AccessFlags) -> Result<(), Errno> {
        let valid_mode = AccessFlags::R_OK | AccessFlags::W_OK | AccessFlags::X_OK;
        if mode.intersects(valid_mode.complement()) {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    fn do_access_mode(
        mode: Mode,
        owner: AccessUserInfo,
        caller: AccessUserInfo,
        access_mode: &AccessFlags,
    ) -> Result<(), Errno> {
        if access_mode.is_empty() {
            return Ok(());
        }
        if caller.user == 0 {
            if access_mode.contains(AccessFlags::X_OK)
                && !mode.intersects(Mode::XUSR | Mode::XGRP | Mode::XOTH)
            {
                return Err(Errno::EACCES);
            }
            return Ok(());
        }
        // TODO: Linux also uses group bits when `owner.group` is in the caller's supplementary
        // group list. `AccessUserInfo` only carries the real/effective primary group today.
        let (read, write, execute) = if caller.user == owner.user {
            (Mode::RUSR, Mode::WUSR, Mode::XUSR)
        } else if caller.group == owner.group {
            (Mode::RGRP, Mode::WGRP, Mode::XGRP)
        } else {
            (Mode::ROTH, Mode::WOTH, Mode::XOTH)
        };
        if access_mode.contains(AccessFlags::R_OK) && !mode.contains(read) {
            return Err(Errno::EACCES);
        }
        if access_mode.contains(AccessFlags::W_OK) && !mode.contains(write) {
            return Err(Errno::EACCES);
        }
        if access_mode.contains(AccessFlags::X_OK) && !mode.contains(execute) {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    fn access_user(&self, flags: &AtFlags) -> AccessUserInfo {
        if flags.contains(AtFlags::AT_EACCESS) {
            AccessUserInfo {
                user: self.credentials.euid,
                group: self.credentials.egid,
            }
        } else {
            AccessUserInfo {
                user: self.credentials.uid,
                group: self.credentials.gid,
            }
        }
    }

    fn do_access(
        &self,
        pathname: impl path::Arg,
        mode: AccessFlags,
        caller: AccessUserInfo,
    ) -> Result<(), Errno> {
        let status = self.files.borrow().fs.file_status(pathname)?;
        let owner = status.owner.into();
        Self::do_access_mode(status.mode, owner, caller, &mode)
    }

    /// Handle syscall `faccessat`
    pub(crate) fn sys_faccessat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        mode: AccessFlags,
        flags: AtFlags,
    ) -> Result<(), Errno> {
        let supported_flags =
            AtFlags::AT_EACCESS | AtFlags::AT_SYMLINK_NOFOLLOW | AtFlags::AT_EMPTY_PATH;
        // TODO: `AT_SYMLINK_NOFOLLOW` is accepted for Linux compatibility, but LiteBox file
        // status lookups do not currently follow symlinks in any backend.
        if flags.intersects(supported_flags.complement()) {
            return Err(Errno::EINVAL);
        }

        Self::validate_access_mode(&mode)?;
        let caller = self.access_user(&flags);
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        match fs_path {
            FsPath::Absolute { path } => self.do_access(path, mode, caller),
            FsPath::Cwd if flags.contains(AtFlags::AT_EMPTY_PATH) => {
                let cwd = get_cwd();
                self.do_access(cwd, mode, caller)
            }
            FsPath::Fd(fd) if flags.contains(AtFlags::AT_EMPTY_PATH) => {
                let stat: FileStat = descriptor_stat(fd as usize, self)?;
                let owner = AccessUserInfo {
                    user: stat.st_uid,
                    group: stat.st_gid,
                };
                Self::do_access_mode(
                    Mode::from_bits_truncate(stat.st_mode & 0o7777),
                    owner,
                    caller,
                    &mode,
                )
            }
            FsPath::Cwd | FsPath::Fd(_) => Err(Errno::ENOENT),
            FsPath::FdRelative { .. } => {
                log_unsupported!("fd-relative faccessat is not supported yet");
                Err(Errno::EINVAL)
            }
        }
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
        let pathname = self.resolve_path_at(dirfd, pathname)?;
        let path = self.do_readlink(pathname.to_str().map_err(|_| Errno::EINVAL)?)?;
        let bytes = path.as_bytes();
        let min_len = core::cmp::min(buf.len(), bytes.len());
        buf[..min_len].copy_from_slice(&bytes[..min_len]);
        Ok(min_len)
    }
}

fn descriptor_stat<FS: ShimFS, T>(raw_fd: usize, task: &Task<FS>) -> Result<T, Errno>
where
    T: From<litebox::fs::FileStatus> + From<FileStat>,
{
    // TODO: give correct values for the synthesized branches.
    let synthetic = |mode_bits: u32, blksize: usize| FileStat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 1,
        st_mode: mode_bits.trunc(),
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: blksize,
        st_blocks: 0,
        ..Default::default()
    };
    let socket_mode = litebox_common_linux::InodeType::Socket as u32
        | (Mode::RWXU | Mode::RWXG | Mode::RWXO).bits();
    let rw_user_mode = (Mode::RUSR | Mode::WUSR).bits();
    let files = task.files.borrow();
    files
        .run_on_raw_fd(
            raw_fd,
            |fd| {
                files
                    .fs
                    .fd_file_status(fd)
                    .map(T::from)
                    .map_err(Errno::from)
            },
            |_fd| Ok(T::from(synthetic(socket_mode, 4096))),
            |fd| {
                Ok(T::from(synthetic(
                    task.global.linux_pipe_mode_bits(fd)?,
                    4096,
                )))
            },
            |_fd| Ok(T::from(synthetic(rw_user_mode, 4096))),
            |_fd| Ok(T::from(synthetic(rw_user_mode, 0))),
            |_fd| Ok(T::from(synthetic(socket_mode, 4096))),
        )
        .flatten()
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
    fn do_stat<T: From<litebox::fs::FileStatus>>(
        &self,
        pathname: impl path::Arg,
        follow_symlink: bool,
    ) -> Result<T, Errno> {
        let normalized_path = pathname.normalized()?;
        let path = if follow_symlink {
            self.do_readlink(normalized_path.as_str())
                .unwrap_or(normalized_path)
        } else {
            normalized_path
        };
        let status = self.files.borrow().fs.file_status(path)?;
        Ok(T::from(status))
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

    fn do_fstatat<T>(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
    ) -> Result<T, Errno>
    where
        T: From<litebox::fs::FileStatus> + From<FileStat>,
    {
        let get_cwd = || self.fs.borrow().cwd.read().clone();
        let fs_path = FsPath::new(dirfd, pathname, get_cwd)?;
        match fs_path {
            FsPath::Absolute { path } => {
                self.do_stat(path, !flags.contains(AtFlags::AT_SYMLINK_NOFOLLOW))
            }
            FsPath::Cwd if flags.contains(AtFlags::AT_EMPTY_PATH) => {
                Ok(T::from(self.files.borrow().fs.file_status(get_cwd())?))
            }
            FsPath::Fd(fd) if flags.contains(AtFlags::AT_EMPTY_PATH) => {
                descriptor_stat(fd as usize, self)
            }
            FsPath::Cwd | FsPath::Fd(_) => Err(Errno::ENOENT),
            FsPath::FdRelative { .. } => {
                log_unsupported!("relative fstatat with AT_EMPTY_PATH unset is not supported yet");
                Err(Errno::EINVAL)
            }
        }
    }

    /// Handle syscall `newfstatat`
    pub(crate) fn sys_newfstatat(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
    ) -> Result<FileStat, Errno> {
        let current_support_flags = AtFlags::AT_EMPTY_PATH;
        if flags.intersects(current_support_flags.complement()) {
            log_unsupported!("unsupported flags: {flags:?}");
            return Err(Errno::EINVAL);
        }

        self.do_fstatat(dirfd, pathname, flags)
    }

    /// Handle syscall `statx`
    pub(crate) fn sys_statx(
        &self,
        dirfd: i32,
        pathname: impl path::Arg,
        flags: AtFlags,
        mask: StatxMask,
    ) -> Result<Statx, Errno> {
        if mask.contains(StatxMask::STATX__RESERVED) {
            return Err(Errno::EINVAL);
        }
        // `AT_NO_AUTOMOUNT` and the `AT_STATX_*` sync
        // hints are accepted as no-ops since LiteBox filesystems
        // do not automount or sync to a remote.
        let allowed = AtFlags::AT_EMPTY_PATH
            | AtFlags::AT_NO_AUTOMOUNT
            | AtFlags::AT_SYMLINK_NOFOLLOW
            | AtFlags::AT_STATX_FORCE_SYNC
            | AtFlags::AT_STATX_DONT_SYNC;
        if flags.intersects(allowed.complement()) {
            log_unsupported!("unsupported statx flags: {flags:?}");
            return Err(Errno::EINVAL);
        }
        if flags.contains(AtFlags::AT_STATX_FORCE_SYNC | AtFlags::AT_STATX_DONT_SYNC) {
            return Err(Errno::EINVAL);
        }

        // `mask` is informational past this point: the underlying FS doesn't
        // support field selection, so we always fill the basic stats and
        // report the actual filled set via `Statx::stx_mask`. Matches Linux's
        // documented behavior of returning more than what was asked.
        self.do_fstatat(dirfd, pathname, flags)
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
                        |fd| self.global.linux_pipe_status_flags(fd),
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
                        self.global
                            .set_linux_pipe_status_flags(fd, flags, setfl_mask)
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
                let new_file = self
                    .do_dup_inner(
                        desc,
                        if cloexec {
                            OFlags::CLOEXEC
                        } else {
                            OFlags::empty()
                        },
                        DupFdRequest::LowestAtOrAbove(min_fd as usize),
                    )
                    .map_err(|e| match e {
                        DupFdError::BadFd => Errno::EBADF,
                        DupFdError::TooManyFiles => Errno::EMFILE,
                        DupFdError::TargetFdExceedsLimit => Errno::EINVAL,
                    })?;
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

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `pipe2`
    pub fn sys_pipe2(&self, flags: OFlags) -> Result<(u32, u32), Errno> {
        let pipe = self.global.create_linux_pipe(flags)?;

        let files = self.files.borrow();
        let wr_raw_fd = files.insert_raw_fd(pipe.writer).map_err(|writer| {
            self.global.close_linux_pipe(&writer).unwrap();
            Errno::EMFILE
        })?;
        let rd_raw_fd = files.insert_raw_fd(pipe.reader).map_err(|reader| {
            let writer = files
                .raw_descriptor_store
                .write()
                .fd_consume_raw_integer(wr_raw_fd)
                .unwrap();
            self.global.close_linux_pipe(&writer).unwrap();
            self.global.close_linux_pipe(&reader).unwrap();
            Errno::EMFILE
        })?;
        Ok((rd_raw_fd.try_into().unwrap(), wr_raw_fd.try_into().unwrap()))
    }

    pub fn sys_eventfd2(&self, initval: u32, flags: EfdFlags) -> Result<u32, Errno> {
        if flags
            .intersects((EfdFlags::SEMAPHORE | EfdFlags::CLOEXEC | EfdFlags::NONBLOCK).complement())
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
                            litebox_util_log::debug!("set non-blocking on raw fd unimplemented");
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
                log_unsupported!("ioctl with arg {:?}", arg);
                Err(Errno::EINVAL)
            }
        }
    }

    /// Handle syscall `epoll_create` and `epoll_create1`
    pub fn sys_epoll_create(&self, flags: EpollCreateFlags) -> Result<u32, Errno> {
        if flags.intersects(EpollCreateFlags::EPOLL_CLOEXEC.complement()) {
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
            let revents: u16 = revents.bits().trunc();
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

    fn do_dup(&self, file: usize, flags: OFlags) -> Result<usize, DupFdError> {
        self.do_dup_inner(file, flags, DupFdRequest::LowestAvailable)
    }

    fn do_dup_inner(
        &self,
        file: usize,
        flags: OFlags,
        target: DupFdRequest,
    ) -> Result<usize, DupFdError> {
        fn dup<FS: ShimFS, S: FdEnabledSubsystem>(
            task: &Task<FS>,
            files: &FilesState<FS>,
            fd: &TypedFd<S>,
            close_on_exec: bool,
            target: DupFdRequest,
        ) -> Result<usize, DupFdError> {
            let max_fd = task
                .process()
                .limits
                .get_rlimit_cur(litebox_common_linux::RlimitResource::NOFILE);
            match target {
                DupFdRequest::Exact(target) if target >= max_fd => {
                    return Err(DupFdError::TargetFdExceedsLimit);
                }
                DupFdRequest::LowestAtOrAbove(min_fd) if min_fd >= max_fd => {
                    return Err(DupFdError::TargetFdExceedsLimit);
                }
                _ => {}
            }

            let mut dt = task.global.litebox.descriptor_table_mut();
            let fd: TypedFd<_> = dt.duplicate(fd).ok_or(DupFdError::BadFd)?;
            if close_on_exec {
                let old = dt.set_fd_metadata(&fd, FileDescriptorFlags::FD_CLOEXEC);
                assert!(old.is_none());
            }
            drop(dt);

            let new_fd = match target {
                DupFdRequest::Exact(target) => {
                    let _ = task.do_close_and_replace(target, Some(fd));
                    target
                }
                DupFdRequest::LowestAvailable => {
                    let rds = &mut *files.raw_descriptor_store.write();
                    rds.fd_into_raw_integer(fd)
                }
                DupFdRequest::LowestAtOrAbove(min_fd) => {
                    let rds = &mut *files.raw_descriptor_store.write();
                    let mut raw_fd = min_fd;
                    for occupied_raw_fd in rds.iter_alive().skip_while(|&fd| fd < min_fd) {
                        if occupied_raw_fd != raw_fd {
                            break;
                        }
                        raw_fd += 1;
                    }
                    let success = rds.fd_into_specific_raw_integer(fd, raw_fd);
                    assert!(success);
                    raw_fd
                }
            };
            if new_fd >= max_fd {
                let _ = task.do_close(new_fd);
                return Err(DupFdError::TooManyFiles);
            }
            Ok(new_fd)
        }

        let close_on_exec = flags.contains(OFlags::CLOEXEC);
        let files = self.files.borrow();
        files
            .run_on_raw_fd(
                file,
                |fd| dup(self, &files, fd, close_on_exec, target),
                |fd| dup(self, &files, fd, close_on_exec, target),
                |fd| dup(self, &files, fd, close_on_exec, target),
                |fd| dup(self, &files, fd, close_on_exec, target),
                |fd| dup(self, &files, fd, close_on_exec, target),
                |fd| dup(self, &files, fd, close_on_exec, target),
            )
            .map_err(|_| DupFdError::BadFd)?
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
        self.check_raw_fd_exists(oldfd)?;
        let oldfd = u32::try_from(oldfd).map_err(|_| Errno::EBADF)?;
        let oldfd_usize = usize::try_from(oldfd).or(Err(Errno::EBADF))?;
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
            let newfd_usize = usize::try_from(newfd).or(Err(Errno::EBADF))?;
            self.do_dup_inner(
                oldfd_usize,
                flags.unwrap_or(OFlags::empty()),
                DupFdRequest::Exact(newfd_usize),
            )
        } else {
            // dup
            self.do_dup(oldfd_usize, flags.unwrap_or(OFlags::empty()))
        }
        .map_err(|e| match e {
            DupFdError::BadFd | DupFdError::TargetFdExceedsLimit => Errno::EBADF,
            DupFdError::TooManyFiles => Errno::EMFILE,
        })
        .map(|new_fd| u32::try_from(new_fd).unwrap())
    }
}

#[derive(Clone, Copy)]
enum DupFdRequest {
    LowestAvailable,
    LowestAtOrAbove(usize),
    /// Duplicate to the specified fd, closing it first if it's open.
    Exact(usize),
}

#[derive(Error, Debug)]
enum DupFdError {
    #[error("Bad file descriptor")]
    BadFd,
    #[error("Too many open files")]
    TooManyFiles,
    #[error("Target fd exceeds process limit")]
    TargetFdExceedsLimit,
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
                        if nbytes == 0 {
                            // not enough space for even a single entry
                            return Err(Errno::EINVAL);
                        }
                        break;
                    }
                    let dirent64 = litebox_common_linux::LinuxDirent64 {
                        ino: entry.ino_info.as_ref().map_or(0, |node_info| node_info.ino) as u64,
                        off: dir_off as u64,
                        len: len.trunc(),
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
            |_fd| Err(Errno::ENOTDIR),
            |_fd| Err(Errno::ENOTDIR),
            |_fd| Err(Errno::ENOTDIR),
            |_fd| Err(Errno::ENOTDIR),
            |_fd| Err(Errno::ENOTDIR),
        )?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use core::cell::Cell;
    use litebox::fs::Mode;

    extern crate std;

    #[test]
    fn write_to_iovec_returns_partial_after_later_error() {
        let first = b"first";
        let second = b"second";
        let iovs = [
            IoWriteVec {
                iov_base: ConstPtr::from_usize(first.as_ptr().expose_provenance()),
                iov_len: first.len(),
            },
            IoWriteVec {
                iov_base: ConstPtr::from_usize(second.as_ptr().expose_provenance()),
                iov_len: second.len(),
            },
        ];
        let calls = Cell::new(0);

        let result = write_to_iovec(&iovs, |buf, total| {
            let call = calls.get();
            calls.set(call + 1);
            if call == 0 {
                assert_eq!(buf, first);
                assert_eq!(total, 0);
                Ok(buf.len())
            } else {
                assert_eq!(buf, second);
                assert_eq!(total, first.len());
                Err(Errno::EPIPE)
            }
        });

        assert_eq!(result, Ok(first.len()));
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn read_from_iovec_breaks_on_eof() {
        let mut first = [0u8; 4];
        let mut second = [0u8; 4];
        let iovs = [
            IoReadVec {
                iov_base: MutPtr::from_usize(first.as_mut_ptr().expose_provenance()),
                iov_len: first.len(),
            },
            IoReadVec {
                iov_base: MutPtr::from_usize(second.as_mut_ptr().expose_provenance()),
                iov_len: second.len(),
            },
        ];
        let mut kernel_buffer = [0u8; 8];
        let calls = Cell::new(0);

        let result = read_from_iovec(&iovs, &mut kernel_buffer, |buf, total| {
            let call = calls.get();
            calls.set(call + 1);
            if call == 0 {
                assert_eq!(total, 0);
                buf.fill(b'a');
                Ok(buf.len())
            } else {
                assert_eq!(total, 4);
                Ok(0)
            }
        });

        assert_eq!(result, Ok(4));
        assert_eq!(calls.get(), 2);
        assert_eq!(&first, b"aaaa");
        assert_eq!(&second, &[0u8; 4]);
    }

    #[test]
    fn read_from_iovec_chunks_iov_larger_than_kernel_buffer() {
        let mut dest = [0u8; 12];
        let iovs = [IoReadVec {
            iov_base: MutPtr::from_usize(dest.as_mut_ptr().expose_provenance()),
            iov_len: dest.len(),
        }];
        let mut kernel_buffer = [0u8; 4];
        let calls = Cell::new(0);

        let result = read_from_iovec(&iovs, &mut kernel_buffer, |buf, total| {
            assert_eq!(buf.len(), 4);
            assert_eq!(total, calls.get() * 4);
            let marker = b'a' + u8::try_from(calls.get()).unwrap();
            buf.fill(marker);
            calls.set(calls.get() + 1);
            Ok(buf.len())
        });

        assert_eq!(result, Ok(12));
        assert_eq!(calls.get(), 3);
        assert_eq!(&dest, b"aaaabbbbcccc");
    }

    #[test]
    fn read_from_iovec_returns_partial_after_later_error() {
        let mut first = [0u8; 4];
        let mut second = [0u8; 4];
        let iovs = [
            IoReadVec {
                iov_base: MutPtr::from_usize(first.as_mut_ptr().expose_provenance()),
                iov_len: first.len(),
            },
            IoReadVec {
                iov_base: MutPtr::from_usize(second.as_mut_ptr().expose_provenance()),
                iov_len: second.len(),
            },
        ];
        let mut kernel_buffer = [0u8; 4];
        let calls = Cell::new(0);

        let result = read_from_iovec(&iovs, &mut kernel_buffer, |buf, total| {
            let call = calls.get();
            calls.set(call + 1);
            if call == 0 {
                assert_eq!(total, 0);
                buf.fill(b'x');
                Ok(buf.len())
            } else {
                assert_eq!(total, 4);
                Err(Errno::EIO)
            }
        });

        assert_eq!(result, Ok(4));
        assert_eq!(calls.get(), 2);
        assert_eq!(&first, b"xxxx");
    }

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

    #[test]
    fn mknodat_regular_file_does_not_consume_fd_limit() {
        use litebox_common_linux::{Rlimit, RlimitResource};

        let task = crate::syscalls::tests::init_platform(None);
        let old_limit = task.do_prlimit(RlimitResource::NOFILE, None).unwrap();
        task.do_prlimit(
            RlimitResource::NOFILE,
            Some(Rlimit {
                rlim_cur: 3,
                rlim_max: old_limit.rlim_max,
            }),
        )
        .unwrap();
        let path = "/mknodat_at_fd_limit";

        let result = task.sys_mknodat(
            litebox_common_linux::AT_FDCWD,
            path,
            InodeType::File as u32 | (Mode::RUSR | Mode::WUSR).bits(),
            0,
        );

        assert!(
            task.sys_stat(path).is_ok(),
            "mknodat created the file before returning {result:?}"
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn empty_pathnames_return_enoent() {
        let task = crate::syscalls::tests::init_platform(None);

        assert_eq!(
            task.sys_open("", OFlags::RDONLY, Mode::empty())
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            task.sys_open("", OFlags::CREAT | OFlags::WRONLY, Mode::RWXU)
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(task.sys_stat("").unwrap_err(), Errno::ENOENT);
        assert_eq!(
            task.sys_unlinkat(litebox_common_linux::AT_FDCWD, "", AtFlags::empty())
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(task.sys_mkdir("", 0o755).unwrap_err(), Errno::ENOENT);
        assert_eq!(
            task.sys_mknodat(
                litebox_common_linux::AT_FDCWD,
                "",
                InodeType::File as u32 | Mode::RWXU.bits(),
                0,
            )
            .unwrap_err(),
            Errno::ENOENT
        );
        let mut buffer = [0u8; 16];
        assert_eq!(
            task.sys_readlinkat(litebox_common_linux::AT_FDCWD, "", &mut buffer)
                .unwrap_err(),
            Errno::ENOENT
        );
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

        // ── sys_faccessat: check relative file is accessible ──
        task.sys_faccessat(
            litebox_common_linux::AT_FDCWD,
            "file.txt",
            AccessFlags::F_OK,
            AtFlags::empty(),
        )
        .unwrap();

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
