// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest descriptor namespace and LiteBox file operations.

use crate::{ShimPlatform, Task};
use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use litebox::{
    LiteBox,
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, RawDescriptorStorage, TypedFd},
    fs::errors::{
        FileStatusError, OpenError, PathError, ReadError, StatusFlagsError, TruncateError,
        WriteError,
    },
    sync::RwLock,
};
use litebox_broker_protocol::fs::{
    FileAccessMode, FileMode, FileOpenFlags, FileSeekWhence, FileType, FileUser,
};
use litebox_common_macos::{
    FileDescriptorFlags, OpenFlags, PAGE_SIZE, PATH_MAX, Stat64,
    errno::Errno,
    user_pointers::{UserPtr, UserPtrMut},
};

const MAX_FDS: usize = 1024;

pub(crate) struct FileSubsystem<P: ShimPlatform>(core::marker::PhantomData<P>);
impl<P: ShimPlatform> FdEnabledSubsystem for FileSubsystem<P> {
    type Entry = File<P>;
}

impl<P: ShimPlatform> FdEnabledSubsystemEntry for File<P> {}

pub(crate) type FileFd<P> = TypedFd<FileSubsystem<P>>;

/// A file descriptor's open file description.
pub(crate) struct File<P: ShimPlatform> {
    /// The LiteBox file this open file description refers to.
    description: Arc<litebox::fs::File<P>>,
    /// The absolute path it was opened by, for `F_GETPATH`. Inherited
    /// descriptors (such as stdio) have none.
    path: Option<Arc<str>>,
    /// XNU file status flags LiteBox files have no behavior for
    /// ([`XNU_ONLY_STATUS_FLAGS`]): recorded for `F_GETFL` only.
    xnu_status: Arc<AtomicU32>,
}

impl<P: ShimPlatform> From<litebox::fs::File<P>> for File<P> {
    fn from(file: litebox::fs::File<P>) -> Self {
        Self {
            description: Arc::new(file),
            path: None,
            xnu_status: Arc::new(AtomicU32::new(0)),
        }
    }
}

/// Darwin `fcntl.h` file status flags (`O_*` / `F*`).
const O_NONBLOCK: u32 = 0x4;
const O_APPEND: u32 = 0x8;
const O_ASYNC: u32 = 0x40;
const O_FSYNC: u32 = 0x80;
const O_DSYNC: u32 = 0x40_0000;
const FNOCACHE: u32 = 0x4_0000;
/// `FCNTLFLAGS`: what `F_SETFL` can change.
const FCNTL_FLAGS: u32 = O_APPEND | O_ASYNC | O_FSYNC | O_DSYNC | O_NONBLOCK;
/// Status flags XNU records that have no LiteBox behavior: no SIGIO, every
/// write is as durable as the broker makes it, and there is no unified
/// buffer cache to bypass.
const XNU_ONLY_STATUS_FLAGS: u32 = O_ASYNC | O_FSYNC | O_DSYNC | FNOCACHE;

/// `path` relative to the root, which is every guest's working directory,
/// with `.` and `..` components resolved lexically.
fn absolute_path(path: &str) -> String {
    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component => components.push(component),
        }
    }
    let mut absolute = String::from("/");
    absolute.push_str(&components.join("/"));
    absolute
}

pub(crate) struct FilesState<P: ShimPlatform> {
    litebox: Arc<LiteBox<P>>,
    raw: RwLock<P, RawDescriptorStorage>,
}

impl<P: ShimPlatform> FilesState<P> {
    pub(crate) fn new(litebox: Arc<LiteBox<P>>) -> Self {
        Self {
            litebox,
            raw: RwLock::new(RawDescriptorStorage::new()),
        }
    }

    pub(crate) fn insert_file(&self, file: litebox::fs::File<P>) -> Result<u32, Errno> {
        let fd = self
            .litebox
            .descriptor_table_mut()
            .insert::<FileSubsystem<P>>(file);
        self.insert_fd(fd)
    }

    fn insert_fd(&self, fd: FileFd<P>) -> Result<u32, Errno> {
        let mut raw = self.raw.write();
        if raw.iter_alive().count() >= MAX_FDS {
            drop(raw);
            self.remove(&fd);
            return Err(Errno::EMFILE);
        }
        Ok(u32::try_from(raw.fd_into_raw_integer(fd)).expect("fd bounded by MAX_FDS"))
    }

    pub(crate) fn typed_fd(&self, fd: i32) -> Result<Arc<FileFd<P>>, Errno> {
        self.raw
            .read()
            .fd_from_raw_integer::<FileSubsystem<P>>(usize::try_from(fd).map_err(|_| Errno::EBADF)?)
            .map_err(|_| Errno::EBADF)
    }

    /// The path `fd` was opened by, if any.
    pub(crate) fn path(&self, fd: &FileFd<P>) -> Result<Option<Arc<str>>, Errno> {
        self.litebox
            .descriptor_table()
            .with_entry(fd, |file| file.path.clone())
            .ok_or(Errno::EBADF)
    }

    /// The XNU-only status flags of `fd`'s open file description.
    fn xnu_status(&self, fd: &FileFd<P>) -> Result<Arc<AtomicU32>, Errno> {
        self.litebox
            .descriptor_table()
            .with_entry(fd, |file| Arc::clone(&file.xnu_status))
            .ok_or(Errno::EBADF)
    }

    /// Returns the file at `fd`, without holding the descriptor table.
    pub(crate) fn file(&self, fd: &FileFd<P>) -> Result<Arc<litebox::fs::File<P>>, Errno> {
        self.litebox
            .descriptor_table()
            .with_entry(fd, |file| Arc::clone(&file.description))
            .ok_or(Errno::EBADF)
    }

    fn consume(&self, fd: usize) -> Result<Arc<FileFd<P>>, Errno> {
        self.raw
            .write()
            .fd_consume_raw_integer::<FileSubsystem<P>>(fd)
            .map_err(|_| Errno::EBADF)
    }

    /// Removes `fd` from the descriptor table, dropping its file once no duplicate refers to it.
    fn remove(&self, fd: &FileFd<P>) {
        let entry = self.litebox.descriptor_table_mut().remove(fd);
        // Drop the file without holding the descriptor table.
        drop(entry);
    }

    pub(crate) fn close(&self, fd: i32) -> Result<(), Errno> {
        let fd = self.consume(usize::try_from(fd).map_err(|_| Errno::EBADF)?)?;
        self.remove(&fd);
        Ok(())
    }

    /// XNU's `dup2`: `old` must be open, `new` must be below the descriptor
    /// limit, `old == new` is a no-op, and an open `new` is closed first.
    pub(crate) fn dup2(&self, old: i32, new: i32) -> Result<u32, Errno> {
        let old_fd = self.typed_fd(old)?;
        let new_raw = usize::try_from(new)
            .ok()
            .filter(|new| *new < MAX_FDS)
            .ok_or(Errno::EBADF)?;
        if old == new {
            return Ok(new.cast_unsigned());
        }
        let duplicate = self
            .litebox
            .descriptor_table_mut()
            .duplicate(&old_fd)
            .ok_or(Errno::EBADF)?;
        let replaced = {
            let mut raw = self.raw.write();
            // Make the (possibly sparse) target storable before vacating it.
            if raw.try_reserve_slots(new_raw + 1).is_err() {
                drop(raw);
                self.remove(&duplicate);
                return Err(Errno::ENOMEM);
            }
            let replaced = raw.fd_consume_raw_integer::<FileSubsystem<P>>(new_raw).ok();
            let stored = raw.fd_into_specific_raw_integer(duplicate, new_raw);
            assert!(stored, "dup2 target was just vacated");
            replaced
        };
        if let Some(replaced) = replaced {
            self.remove(&replaced);
        }
        Ok(new.cast_unsigned())
    }

    pub(crate) fn dup(&self, fd: i32) -> Result<u32, Errno> {
        let fd = self.typed_fd(fd)?;
        let duplicate = self
            .litebox
            .descriptor_table_mut()
            .duplicate(&fd)
            .ok_or(Errno::EBADF)?;
        self.insert_fd(duplicate)
    }

    /// `F_DUPFD`: duplicate `fd` onto the lowest free descriptor at or above
    /// `minimum`, which must be below the descriptor limit (`fdalloc`).
    pub(crate) fn dup_from(&self, fd: i32, minimum: i32) -> Result<u32, Errno> {
        let fd = self.typed_fd(fd)?;
        let minimum = usize::try_from(minimum)
            .ok()
            .filter(|minimum| *minimum < MAX_FDS)
            .ok_or(Errno::EINVAL)?;
        let duplicate = self
            .litebox
            .descriptor_table_mut()
            .duplicate(&fd)
            .ok_or(Errno::EBADF)?;
        let mut raw = self.raw.write();
        let free = (minimum..MAX_FDS).find(|candidate| !raw.is_alive(*candidate));
        let Some(free) = free.filter(|free| raw.try_reserve_slots(free + 1).is_ok()) else {
            drop(raw);
            self.remove(&duplicate);
            return Err(if free.is_some() {
                Errno::ENOMEM
            } else {
                Errno::EMFILE
            });
        };
        let stored = raw.fd_into_specific_raw_integer(duplicate, free);
        assert!(stored, "descriptor {free} was free");
        Ok(u32::try_from(free).expect("fd bounded by MAX_FDS"))
    }
}

impl<P: ShimPlatform> Drop for FilesState<P> {
    fn drop(&mut self) {
        let alive: Vec<_> = self.raw.read().iter_alive().collect();
        for raw in alive {
            if let Ok(fd) = self.consume(raw) {
                self.remove(&fd);
            }
        }
    }
}

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_open(
        &self,
        path: &str,
        flags: OpenFlags,
        mode: FileMode,
    ) -> Result<u32, Errno> {
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        if path.len() >= PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        self.open_path(path, flags, mode)
    }

    /// `open` of a nonempty `path` whose guest-supplied part was checked
    /// against PATH_MAX: `openat` prefixes its directory's path, which namei
    /// does not count.
    fn open_path(&self, path: &str, flags: OpenFlags, mode: FileMode) -> Result<u32, Errno> {
        if path.as_bytes().contains(&0) {
            return Err(Errno::EINVAL);
        }
        if flags.bits() & !OpenFlags::all().bits() != 0 {
            return Err(Errno::EINVAL);
        }
        if flags.contains(OpenFlags::NOFOLLOW_ANY)
            && path
                .split('/')
                .filter(|component| !component.is_empty())
                .count()
                > 1
        {
            return Err(Errno::ENOTSUP);
        }
        let access = match flags.bits() & 3 {
            0 => FileAccessMode::ReadOnly,
            1 => FileAccessMode::WriteOnly,
            2 => FileAccessMode::ReadWrite,
            _ => return Err(Errno::EINVAL),
        };
        let mut open_flags = FileOpenFlags::NONE;
        for (guest, broker) in [
            (OpenFlags::CREAT, FileOpenFlags::CREATE),
            (OpenFlags::TRUNC, FileOpenFlags::TRUNCATE),
            (OpenFlags::EXCL, FileOpenFlags::EXCLUSIVE),
            (OpenFlags::APPEND, FileOpenFlags::APPEND),
            (OpenFlags::NONBLOCK, FileOpenFlags::NONBLOCKING),
            (OpenFlags::NOFOLLOW, FileOpenFlags::NO_FOLLOW),
            // With at most one component, checking the final component also
            // implements NOFOLLOW_ANY.
            (OpenFlags::NOFOLLOW_ANY, FileOpenFlags::NO_FOLLOW),
            (OpenFlags::NOCTTY, FileOpenFlags::NO_CONTROLLING_TERMINAL),
            (OpenFlags::DIRECTORY, FileOpenFlags::DIRECTORY),
        ] {
            if flags.contains(guest) {
                open_flags = open_flags.union(broker);
            }
        }
        let context = Self::fs_context(self.params.euid, self.params.egid)?;
        self.check_dot_dot_components(&context, path)?;
        if path.ends_with('/') {
            // namei: a trailing slash names a directory, so it can neither
            // create a file (lookup_validate_creation_path) nor open one.
            if flags.contains(OpenFlags::CREAT) {
                self.global
                    .litebox
                    .path_file_status(&context, path)
                    .map_err(file_status_error)?;
            }
            open_flags = open_flags.union(FileOpenFlags::DIRECTORY);
        }
        // Until chdir/umask are supported, use cwd "/" and the Linux shim's default umask.
        let mode = mode & !(FileMode::WGRP | FileMode::WOTH);
        // Keep the free slot exclusive until open succeeds and the FD is published.
        // TODO: reserve a slot without holding the FD-table lock across broker IPC.
        let mut raw = self.files.raw.write();
        if raw.iter_alive().count() >= MAX_FDS {
            return Err(Errno::EMFILE);
        }
        let file = self
            .global
            .litebox
            .open_file(&context, path, access, open_flags, mode)
            .map_err(open_error)?;
        let mut descriptors = self.global.litebox.descriptor_table_mut();
        let fd = descriptors.insert::<FileSubsystem<P>>(File {
            description: Arc::new(file),
            path: Some(Arc::from(absolute_path(path))),
            xnu_status: Arc::new(AtomicU32::new(0)),
        });
        if flags.contains(OpenFlags::CLOEXEC) {
            // TODO: honor FD_CLOEXEC when macOS exec is implemented.
            let old = descriptors.set_fd_metadata(&fd, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        drop(descriptors);
        Ok(u32::try_from(raw.fd_into_raw_integer(fd)).expect("fd bounded by MAX_FDS"))
    }

    /// namei resolves `..` against the directory it reached, so a `..`
    /// after a missing component or a non-directory fails (ENOENT, ENOTDIR)
    /// instead of being removed lexically. LiteBox filesystems have no
    /// symbolic links, so the lexical prefix is the directory reached.
    fn check_dot_dot_components(
        &self,
        context: &litebox::fs::Context,
        path: &str,
    ) -> Result<(), Errno> {
        let mut prefix = String::new();
        for component in path.split('/') {
            if component == ".." && !prefix.is_empty() {
                let status = self
                    .global
                    .litebox
                    .path_file_status(context, &prefix)
                    .map_err(file_status_error)?;
                if status.file_type != FileType::Directory {
                    return Err(Errno::ENOTDIR);
                }
            }
            if !prefix.is_empty() || path.starts_with('/') {
                prefix.push('/');
            }
            prefix.push_str(component);
        }
        Ok(())
    }

    pub(crate) fn read_path(path: UserPtr<core::ffi::c_char>) -> Result<String, Errno> {
        let mut bytes = Vec::new();
        while bytes.len() < PATH_MAX {
            let address = path
                .as_usize()
                .checked_add(bytes.len())
                .ok_or(Errno::EFAULT)?;
            let length = (PAGE_SIZE - address % PAGE_SIZE).min(PATH_MAX - bytes.len());
            let chunk = UserPtr::<u8>::from_usize(address)
                .to_owned_slice::<P>(length)
                .ok_or(Errno::EFAULT)?;
            if let Some(end) = chunk.iter().position(|&byte| byte == 0) {
                bytes.extend_from_slice(&chunk[..end]);
                return String::from_utf8(bytes).map_err(|_| Errno::EINVAL);
            }
            bytes.extend_from_slice(&chunk);
        }
        Err(Errno::ENAMETOOLONG)
    }

    /// Read at an explicit offset without changing the shared offset, or use
    /// and advance the shared offset when `offset` is `None`.
    pub(crate) fn do_read(
        &self,
        fd: &FileFd<P>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, Errno> {
        let size = self
            .files
            .file(fd)?
            .read(buf, offset, Some(&self.wait_cx()))
            .map_err(read_error)?;
        if size > buf.len() {
            return Err(Errno::EIO);
        }
        Ok(size)
    }

    pub(crate) fn do_write(&self, fd: &FileFd<P>, buf: &[u8]) -> Result<usize, Errno> {
        let size = self
            .files
            .file(fd)?
            .write(buf, None, Some(&self.wait_cx()))
            .map_err(write_error)?;
        if size > buf.len() {
            return Err(Errno::EIO);
        }
        Ok(size)
    }

    pub(crate) fn sys_close(&self, fd: i32) -> Result<(), Errno> {
        self.files.close(fd)
    }
    pub(crate) fn sys_dup(&self, fd: i32) -> Result<u32, Errno> {
        self.files.dup(fd)
    }
    pub(crate) fn sys_dup2(&self, old: i32, new: i32) -> Result<u32, Errno> {
        self.files.dup2(old, new)
    }

    /// The filesystem context of guest path lookups, acting as `user`/`group`.
    pub(crate) fn fs_context(user: u32, group: u32) -> Result<litebox::fs::Context, Errno> {
        let mut context = litebox::fs::Context::new();
        context.set_acting_user(FileUser {
            user: u16::try_from(user).map_err(|_| Errno::EINVAL)?,
            group: u16::try_from(group).map_err(|_| Errno::EINVAL)?,
        });
        Ok(context)
    }

    /// `stat64` and `lstat64`. LiteBox filesystems have no symbolic links,
    /// so both describe the named file.
    pub(crate) fn sys_stat64(&self, path: &str, buffer: UserPtrMut<Stat64>) -> Result<(), Errno> {
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        let context = Self::fs_context(self.params.euid, self.params.egid)?;
        let status = self
            .global
            .litebox
            .path_file_status(&context, path)
            .map_err(file_status_error)?;
        buffer
            .write_at_offset::<P>(0, Stat64::try_from(&status)?)
            .ok_or(Errno::EFAULT)
    }

    pub(crate) fn sys_fstat64(&self, fd: i32, buffer: UserPtrMut<Stat64>) -> Result<(), Errno> {
        let fd = self.files.typed_fd(fd)?;
        let status = self.files.file(&fd)?.status().map_err(file_status_error)?;
        buffer
            .write_at_offset::<P>(0, Stat64::try_from(&status)?)
            .ok_or(Errno::EFAULT)
    }

    /// XNU's `fcntl` for the commands LiteBox files support. Unsupported
    /// commands fail with EINVAL (logged once) — notably code-signature
    /// registration (`F_ADDFILESIGS*`): guest files carry no kernel-validated
    /// signature.
    pub(crate) fn sys_fcntl(&self, fd: i32, command: i32, argument: usize) -> Result<usize, Errno> {
        const F_DUPFD: i32 = 0;
        const F_GETFD: i32 = 1;
        const F_SETFD: i32 = 2;
        const F_GETFL: i32 = 3;
        const F_SETFL: i32 = 4;
        const F_NOCACHE: i32 = 48;
        const F_GETPATH: i32 = 50;
        const F_DUPFD_CLOEXEC: i32 = 67;
        const F_CHECK_LV: i32 = 98;
        const F_GETPATH_NOFIRMLINK: i32 = 102;
        let typed = self.files.typed_fd(fd)?;
        // `int` arguments.
        let int_argument = litebox::utils::TruncateExt::<u32>::trunc(argument);
        match command {
            F_DUPFD | F_DUPFD_CLOEXEC => {
                let duplicate = self.files.dup_from(fd, int_argument.cast_signed())?;
                if command == F_DUPFD_CLOEXEC {
                    let duplicate_fd = self.files.typed_fd(duplicate.cast_signed())?;
                    self.global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(&duplicate_fd, FileDescriptorFlags::FD_CLOEXEC);
                }
                Ok(duplicate as usize)
            }
            F_GETFD => {
                let flags = self
                    .global
                    .litebox
                    .descriptor_table()
                    .with_metadata(&typed, |flags: &FileDescriptorFlags| *flags)
                    .unwrap_or_default();
                Ok(flags.bits() as usize)
            }
            F_SETFD => {
                let flags = FileDescriptorFlags::from_bits_truncate(int_argument);
                self.global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(&typed, flags);
                Ok(0)
            }
            F_GETFL => {
                let status = self
                    .files
                    .file(&typed)?
                    .get_status_flags()
                    .map_err(status_flags_error)?;
                let mut flags = match status.access {
                    FileAccessMode::ReadOnly => 0,
                    FileAccessMode::WriteOnly => 1,
                    FileAccessMode::ReadWrite => 2,
                    _ => return Err(Errno::EIO),
                };
                if status.flags.contains(FileOpenFlags::NONBLOCKING) {
                    flags |= O_NONBLOCK;
                }
                if status.flags.contains(FileOpenFlags::APPEND) {
                    flags |= O_APPEND;
                }
                flags |= self.files.xnu_status(&typed)?.load(Ordering::Relaxed);
                Ok(flags as usize)
            }
            F_SETFL => {
                let requested = int_argument & FCNTL_FLAGS;
                let mut broker = FileOpenFlags::NONE;
                if requested & O_NONBLOCK != 0 {
                    broker = broker.union(FileOpenFlags::NONBLOCKING);
                }
                if requested & O_APPEND != 0 {
                    broker = broker.union(FileOpenFlags::APPEND);
                }
                self.files
                    .file(&typed)?
                    .set_status_flags(FileOpenFlags::STATUS, broker)
                    .map_err(status_flags_error)?;
                let xnu_only = XNU_ONLY_STATUS_FLAGS & FCNTL_FLAGS;
                let xnu_status = self.files.xnu_status(&typed)?;
                xnu_status.update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                    (old & !xnu_only) | (requested & xnu_only)
                });
                Ok(0)
            }
            F_NOCACHE => {
                // Only recorded: LiteBox files have no buffer cache to bypass.
                let xnu_status = self.files.xnu_status(&typed)?;
                if argument != 0 {
                    xnu_status.fetch_or(FNOCACHE, Ordering::Relaxed);
                } else {
                    xnu_status.fetch_and(!FNOCACHE, Ordering::Relaxed);
                }
                Ok(0)
            }
            F_CHECK_LV => {
                // `fchecklv_t`: copied in, then judged by the MAC policies.
                // The guest is unsigned and does not opt into library
                // validation, so AMFI's check allows every file.
                UserPtr::<u8>::from_usize(argument)
                    .to_owned_slice::<P>(24)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            F_GETPATH | F_GETPATH_NOFIRMLINK => {
                // Only vnodes have a path.
                let path = self.files.path(&typed)?.ok_or(Errno::EBADF)?;
                // The caller's buffer holds MAXPATHLEN bytes; vn_getpath_ext
                // fails with ENOSPC rather than copy out more
                // (bsd/vfs/vfs_cache.c build_path_with_parent).
                if path.len() >= PATH_MAX {
                    return Err(Errno::ENOSPC);
                }
                let mut bytes = Vec::with_capacity(path.len() + 1);
                bytes.extend_from_slice(path.as_bytes());
                bytes.push(0);
                UserPtrMut::<u8>::from_usize(argument)
                    .copy_from_slice::<P>(0, &bytes)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            _ => {
                self.log_unsupported_once(
                    "fcntl command",
                    format_args!("fd {fd}, command {command}"),
                );
                Err(Errno::EINVAL)
            }
        }
    }

    /// `openat`. Every guest's working directory is `/`, so `AT_FDCWD` and
    /// absolute paths open like `open`; other relative paths resolve against
    /// the directory's open path (LiteBox filesystems have no symbolic links
    /// or renames that could make it stale).
    pub(crate) fn sys_openat(
        &self,
        dirfd: i32,
        path: &str,
        flags: OpenFlags,
        mode: FileMode,
    ) -> Result<u32, Errno> {
        /// `AT_FDCWD`.
        const AT_FDCWD: i32 = -2;
        if dirfd == AT_FDCWD || path.starts_with('/') {
            return self.sys_open(path, flags, mode);
        }
        // nameiat: the descriptor must be an open directory.
        let fd = self.files.typed_fd(dirfd)?;
        let status = self.files.file(&fd)?.status().map_err(file_status_error)?;
        if status.file_type != litebox_broker_protocol::fs::FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        let Some(directory) = self.files.path(&fd)? else {
            // An inherited directory descriptor with no known path.
            self.log_unsupported_once(
                "openat relative to an inherited directory",
                format_args!(""),
            );
            return Err(Errno::ENOTSUP);
        };
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        if path.len() >= PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        // Not normalized: `open_path` needs the trailing slash and the `..`
        // components to resolve them like namei. Only the guest's `path`
        // counts against PATH_MAX: nameiat starts from the directory's vnode
        // (vfs_lookup.c). The directory's path names an existing directory,
        // and the broker bounds the joined path it accepts.
        let mut joined = String::from(&*directory);
        joined.push('/');
        joined.push_str(path);
        self.open_path(&joined, flags, mode)
    }

    /// `ioctl`. Descriptor-level requests (`FIOCLEX`, `FIONCLEX`) and the
    /// status-flag requests (`FIONBIO`, `FIOASYNC`) are handled like
    /// `sys_generic.c`; `vn_ioctl` accepts the latter and `FIONREAD` on
    /// regular files and directories. Every other request, and every request
    /// to a character device (the non-tty stdio streams), fails with ENOTTY.
    pub(crate) fn sys_ioctl(&self, fd: i32, command: u32, data: usize) -> Result<(), Errno> {
        // sys/ioccom.h and sys/filio.h.
        const IOCPARM_MAX: u32 = 8192;
        const IOC_IN: u32 = 0x8000_0000;
        const FIOCLEX: u32 = 0x2000_6601;
        const FIONCLEX: u32 = 0x2000_6602;
        const FIONREAD: u32 = 0x4004_667f;
        const FIONBIO: u32 = 0x8004_667e;
        const FIOASYNC: u32 = 0x8004_667d;
        let size = (command >> 16) & 0x1fff;
        if size > IOCPARM_MAX {
            return Err(Errno::ENOTTY);
        }
        let input = if command & IOC_IN != 0 && size != 0 {
            UserPtr::<u8>::from_usize(data)
                .to_owned_slice::<P>(size as usize)
                .ok_or(Errno::EFAULT)?
        } else {
            alloc::boxed::Box::default()
        };
        let typed = self.files.typed_fd(fd)?;
        match command {
            FIOCLEX | FIONCLEX => {
                let flags = if command == FIOCLEX {
                    FileDescriptorFlags::FD_CLOEXEC
                } else {
                    FileDescriptorFlags::empty()
                };
                self.global
                    .litebox
                    .descriptor_table_mut()
                    .set_fd_metadata(&typed, flags);
                Ok(())
            }
            FIONBIO | FIOASYNC | FIONREAD => {
                let file = self.files.file(&typed)?;
                let status = file.status().map_err(file_status_error)?;
                if !matches!(
                    status.file_type,
                    FileType::RegularFile | FileType::Directory
                ) {
                    return Err(Errno::ENOTTY);
                }
                match command {
                    FIONBIO | FIOASYNC => {
                        let enable = input.iter().any(|byte| *byte != 0);
                        if command == FIONBIO {
                            let flags = if enable {
                                FileOpenFlags::NONBLOCKING
                            } else {
                                FileOpenFlags::NONE
                            };
                            file.set_status_flags(FileOpenFlags::NONBLOCKING, flags)
                                .map_err(status_flags_error)?;
                        } else {
                            let xnu_status = self.files.xnu_status(&typed)?;
                            if enable {
                                xnu_status.fetch_or(O_ASYNC, Ordering::Relaxed);
                            } else {
                                xnu_status.fetch_and(!O_ASYNC, Ordering::Relaxed);
                            }
                        }
                        Ok(())
                    }
                    _ => {
                        // Bytes from the shared offset to the end, within [0, INT_MAX].
                        let offset = if status.file_type == FileType::Directory {
                            0
                        } else {
                            file.seek(0, FileSeekWhence::RelativeToCurrentOffset)
                                .map_err(|_| Errno::EIO)?
                        };
                        let remaining = status
                            .size
                            .saturating_sub(offset as u64)
                            .min(i32::MAX as u64);
                        let remaining = i32::try_from(remaining).expect("clamped to INT_MAX");
                        UserPtrMut::<i32>::from_usize(data)
                            .write_at_offset::<P>(0, remaining)
                            .ok_or(Errno::EFAULT)
                    }
                }
            }
            _ => Err(Errno::ENOTTY),
        }
    }

    /// XNU's `fsctl` on a LiteBox file, found by lookup (no descriptor, no
    /// read permission). Devices are not filesystem objects (ENOTTY);
    /// generic and filesystem-specific commands are unsupported: guest files
    /// are not host volumes, and their `VNOP_IOCTL` is `err_ioctl` (ENOTSUP).
    /// Never forwarded to the host.
    pub(crate) fn sys_fsctl(&self, path: &str, command: u32, data: usize) -> Result<(), Errno> {
        // IOCPARM_LEN / IOCPARM_MAX / IOC_IN from sys/ioccom.h.
        const IOCPARM_MAX: usize = 8192;
        const IOC_IN: u32 = 0x8000_0000;
        const FSIOC_FD_ONLY_OPEN_ONCE: u32 = 0x4004_4a16;
        if command == FSIOC_FD_ONLY_OPEN_ONCE {
            return Err(Errno::EINVAL);
        }
        // namei (LOOKUP): the path must name an existing file.
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        let context = Self::fs_context(self.params.euid, self.params.egid)?;
        self.check_dot_dot_components(&context, path)?;
        let status = self
            .global
            .litebox
            .path_file_status(&context, path)
            .map_err(file_status_error)?;
        if path.ends_with('/') && status.file_type != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        if status.file_type == FileType::CharacterDevice {
            return Err(Errno::ENOTTY);
        }
        let size = ((command >> 16) & 0x1fff) as usize;
        if size > IOCPARM_MAX {
            return Err(Errno::EINVAL);
        }
        if command & IOC_IN != 0 && size != 0 {
            litebox_common_macos::user_pointers::UserPtr::<u8>::from_usize(data)
                .to_owned_slice::<P>(size)
                .ok_or(Errno::EFAULT)?;
        }
        litebox_util_log::debug!(path:%, command:? = format_args!("{command:#x}"); "unsupported fsctl");
        Err(Errno::ENOTSUP)
    }
}

fn open_error(error: OpenError) -> Errno {
    match error {
        OpenError::AccessNotAllowed | OpenError::NoWritePerms => Errno::EACCES,
        OpenError::ReadOnlyFileSystem => Errno::EROFS,
        OpenError::AlreadyExists => Errno::EEXIST,
        OpenError::PathError(error) => path_error(error),
        OpenError::TruncateError(error) => match error {
            TruncateError::ClosedFd => Errno::EBADF,
            TruncateError::IsDirectory => Errno::EISDIR,
            TruncateError::NotForWriting => Errno::EACCES,
            TruncateError::NotOpenForWriting | TruncateError::IsTerminalDevice => Errno::EINVAL,
            TruncateError::Io => Errno::EIO,
        },
        _ => Errno::EIO,
    }
}

fn path_error(error: PathError) -> Errno {
    match error {
        PathError::NoSuchFileOrDirectory | PathError::MissingComponent => Errno::ENOENT,
        PathError::NoSearchPerms => Errno::EACCES,
        PathError::InvalidPathname => Errno::EINVAL,
        PathError::ComponentNotADirectory => Errno::ENOTDIR,
    }
}

pub(crate) fn file_status_error(error: FileStatusError) -> Errno {
    match error {
        FileStatusError::ClosedFd => Errno::EBADF,
        FileStatusError::PathError(error) => path_error(error),
        _ => Errno::EIO,
    }
}

fn status_flags_error(error: StatusFlagsError) -> Errno {
    match error {
        StatusFlagsError::ClosedFd | StatusFlagsError::PathOnly => Errno::EBADF,
        _ => Errno::EIO,
    }
}

fn read_error(error: ReadError) -> Errno {
    match error {
        ReadError::ClosedFd | ReadError::NotForReading => Errno::EBADF,
        ReadError::NotAFile => Errno::EISDIR,
        ReadError::WouldBlock => Errno::EAGAIN,
        ReadError::WaitError(_) => Errno::EINTR,
        _ => Errno::EIO,
    }
}

fn write_error(error: WriteError) -> Errno {
    match error {
        WriteError::ClosedFd | WriteError::NotForWriting => Errno::EBADF,
        WriteError::NotAFile => Errno::EISDIR,
        WriteError::WouldBlock => Errno::EAGAIN,
        WriteError::WaitError(_) => Errno::EINTR,
        _ => Errno::EIO,
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    extern crate std;
    use super::*;
    use crate::{MAX_KERNEL_BUF_SIZE, MacosShimBuilder, Process};
    use alloc::vec;
    use core::sync::atomic::AtomicI32;
    use litebox::mm::page::{NonZeroAddress, NonZeroPageSize};
    use litebox::platform::{
        PageManagementProvider as _, RawConstPointer as _, RawMutPointer as _,
    };
    use litebox_broker_core::{
        ObjectRights, PolicyEngine,
        fs::{
            composer::Composer,
            devices::Devices,
            in_mem::{InMem, InitialNode},
            resolver::Resolver,
        },
        test_support::{FailingRandomProvider, TestBrokerCoreBuilder, TestStdioProvider},
    };
    use litebox_broker_host::test_support::InProcessBrokerSetup;
    use litebox_broker_local::BrokerLocal;
    use litebox_broker_protocol::fs::{
        FileAccessMode, FileMode, FileOpenFlags, FileSeekWhence, FileUser,
    };
    use litebox_common_linux::{PtRegs, vmem::CreatePagesFlags};
    use litebox_common_macos::{MmapFlags, PAGE_SIZE, TaskParams, VmProtection, syscall::nr};
    use litebox_platform_macos_userland::MacosUserland as Platform;

    const O_SHLOCK: i32 = 0x10;
    const O_EXLOCK: i32 = 0x20;

    /// A shim whose LiteBox has `nodes` in memory and the stdio devices at `/dev`.
    fn builder_with_files(nodes: Vec<(&'static str, InitialNode)>) -> MacosShimBuilder<Platform> {
        let platform = Platform::new();
        let fs = InMem::<Platform>::new_initialized(nodes);
        let fs = Composer::builder()
            .mount("/", |_| fs)
            .mount("/dev", |allocator| {
                Devices::new(
                    allocator,
                    Arc::new(TestStdioProvider::default()),
                    Arc::new(FailingRandomProvider),
                )
            })
            .build()
            .unwrap();
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_file_service(Arc::new(Resolver::<Platform, _>::new(fs)))
        .build()
        .unwrap();
        let setup = InProcessBrokerSetup::new(broker);
        let readiness = setup.readiness_sink();
        let (local, _startup, ()) = BrokerLocal::negotiate(setup, |setup| {
            let memory = setup.shared_memory();
            Ok((setup.activate(), memory, ()))
        })
        .unwrap();
        let litebox = LiteBox::new_with_broker_local(platform, local);
        readiness.attach(litebox.broker_notification_dispatcher());
        MacosShimBuilder::new_with_litebox(platform, litebox)
    }

    fn task_with(builder: MacosShimBuilder<Platform>, params: TaskParams) -> Task<Platform> {
        let shim = builder.build();
        let thread = crate::ThreadState::new(1u64 << 32, shim.global.platform);
        Task {
            global: shim.global,
            files: shim.files,
            params,
            process: Process(Arc::new(AtomicI32::new(-1))),
            thread,
        }
    }

    #[test]
    fn inherited_descriptions_use_the_syscall_dispatcher() {
        let mode = FileMode::RWXU | FileMode::RWXG | FileMode::RWXO;
        let mut builder = builder_with_files(vec![
            (
                "/",
                InitialNode::Directory {
                    mode,
                    owner: FileUser::ROOT,
                },
            ),
            (
                "/data",
                InitialNode::File {
                    mode,
                    owner: FileUser::ROOT,
                    data: (&b"abcdef"[..]).into(),
                },
            ),
        ]);
        let context = litebox::fs::Context::new();
        let rw = builder
            .litebox()
            .open_file(
                &context,
                "/data",
                FileAccessMode::ReadWrite,
                FileOpenFlags::NONE,
                FileMode::empty(),
            )
            .unwrap();
        let ro = builder
            .litebox()
            .open_file(
                &context,
                "/data",
                FileAccessMode::ReadOnly,
                FileOpenFlags::NONE,
                FileMode::empty(),
            )
            .unwrap();
        assert_eq!(builder.inherit_file(rw), Ok(0));
        assert_eq!(builder.inherit_file(ro), Ok(1));
        let task = task_with(builder, TaskParams::default());
        // SAFETY: a fresh, non-fixed mapping owned by this task.
        let buf = unsafe {
            task.global.mm.create_writable_pages(
                NonZeroAddress::new(Platform::TASK_ADDR_MIN),
                NonZeroPageSize::new(MAX_KERNEL_BUF_SIZE).unwrap(),
                CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                |_| Ok(0),
            )
        }
        .unwrap();
        let invoke = |number, fd, count| {
            let mut ctx = PtRegs::default();
            ctx.regs[16] = number;
            ctx.regs[0] = fd;
            ctx.regs[1] = buf.as_usize();
            ctx.regs[2] = count;
            task.do_syscall(&ctx)
        };
        let max_count = core::ffi::c_int::MAX.cast_unsigned() as usize;
        let source = task.files.typed_fd(0).unwrap();
        let untouched = [0xa5; 16];
        buf.copy_from_slice(0, &untouched).unwrap();
        // The FD and 64 KiB buffer are valid: rejection must precede clamping
        // and must neither transfer data nor advance the shared file offset.
        for number in [nr::READ, nr::READ_NOCANCEL, nr::WRITE, nr::WRITE_NOCANCEL] {
            for count in [max_count + 1, usize::MAX] {
                assert_eq!(invoke(number, 0, count), Err(Errno::EINVAL));
                let file = task.files.file(&source).unwrap();
                assert_eq!(
                    file.seek(0, FileSeekWhence::RelativeToCurrentOffset)
                        .unwrap(),
                    0
                );
                assert_eq!(file.status().unwrap().size, 6);
                assert_eq!(&*buf.to_owned_slice(untouched.len()).unwrap(), &untouched);
            }
        }
        assert_eq!(invoke(nr::READ, 0, 2), Ok(2));
        assert_eq!(&*buf.to_owned_slice(2).unwrap(), b"ab");
        assert_eq!(invoke(nr::DUP, 0, 0), Ok(2));
        assert_eq!(invoke(nr::CLOSE, 0, 0), Ok(0));
        assert_eq!(invoke(nr::READ, 0, 2), Err(Errno::EBADF));
        assert_eq!(task.do_read(&source, &mut [0; 2], None), Err(Errno::EBADF));
        assert_eq!(task.files.file(&source).err(), Some(Errno::EBADF));
        assert_eq!(invoke(nr::READ, 2, 2), Ok(2));
        assert_eq!(&*buf.to_owned_slice(2).unwrap(), b"cd");
        buf.copy_from_slice(0, b"XY").unwrap();
        assert_eq!(invoke(nr::WRITE, 2, 2), Ok(2));
        assert_eq!(invoke(nr::READ, 2, 2), Ok(0));
        assert_eq!(invoke(nr::WRITE, 1, 2), Err(Errno::EBADF));
        assert_eq!(invoke(nr::READ, 1, 6), Ok(6));
        assert_eq!(&*buf.to_owned_slice(6).unwrap(), b"abcdXY");
        // INT_MAX itself is permitted; at EOF it returns zero bytes.
        assert_eq!(invoke(nr::READ, 1, max_count), Ok(0));
        // dup2 replaces an open target, shares the open file description,
        // and validates both descriptors like XNU.
        assert_eq!(task.sys_dup2(1, 1), Ok(1));
        assert_eq!(task.sys_dup2(1, 2), Ok(2));
        assert_eq!(invoke(nr::READ, 2, 1), Ok(0), "shares fd 1's offset");
        assert_eq!(
            invoke(nr::WRITE, 2, 1),
            Err(Errno::EBADF),
            "fd 2 is now read-only"
        );
        assert_eq!(task.sys_dup2(9, 3), Err(Errno::EBADF));
        assert_eq!(task.sys_dup2(1, -1), Err(Errno::EBADF));
        assert_eq!(task.sys_dup2(1, i32::MAX), Err(Errno::EBADF));
        assert_eq!(task.sys_dup2(1, 7), Ok(7));
        assert_eq!(invoke(nr::CLOSE, 7, 0), Ok(0));
        // Sparse targets up to the descriptor limit are valid with a small table.
        let mut ctx = PtRegs::default();
        ctx.regs[16] = nr::DUP2;
        ctx.regs[0] = 1;
        ctx.regs[1] = MAX_FDS - 1;
        assert_eq!(task.do_syscall(&ctx), Ok(MAX_FDS - 1));
        assert_eq!(invoke(nr::READ, MAX_FDS - 1, 1), Ok(0), "shares fd 1");
        assert_eq!(task.sys_dup2(2, 300), Ok(300));
        assert_eq!(
            task.sys_dup2(1, 300),
            Ok(300),
            "replaces an open sparse target"
        );
        assert_eq!(task.sys_dup2(1, 1024), Err(Errno::EBADF));
        assert_eq!(invoke(nr::DUP, 1, 0), Ok(0), "lowest free descriptor");
        for fd in [0, 300, MAX_FDS - 1] {
            assert_eq!(invoke(nr::CLOSE, fd, 0), Ok(0));
        }
        // fsctl resolves the path and never reaches a host volume.
        assert_eq!(task.sys_fsctl("/data", 0x4008_4a6a, 0), Err(Errno::ENOTSUP));
        assert_eq!(
            task.sys_fsctl("/missing", 0x4008_4a6a, 0),
            Err(Errno::ENOENT)
        );
        assert_eq!(task.sys_fsctl("/data", 0x8008_4a6a, 0), Err(Errno::EFAULT));
        assert_eq!(task.sys_fsctl("/data", 0x4004_4a16, 0), Err(Errno::EINVAL));
        assert_eq!(invoke(nr::CLOSE, 2, 0), Ok(0));
        assert_eq!(invoke(nr::CLOSE, 2, 0), Err(Errno::EBADF));

        let open = |number, path, flags: OpenFlags, mode| {
            let mut ctx = PtRegs::default();
            ctx.regs[16] = number;
            ctx.regs[0] = path;
            ctx.regs[1] = flags.bits().cast_unsigned() as usize;
            ctx.regs[2] = mode;
            task.do_syscall(&ctx)
        };
        // The terminator is the last mapped byte: open must not read the next page.
        let path_offset = MAX_KERNEL_BUF_SIZE - b"/new\0".len();
        buf.copy_from_slice(path_offset, b"/new\0").unwrap();
        let path = buf.as_usize() + path_offset;
        let flags = OpenFlags::RDWR | OpenFlags::CREAT | OpenFlags::EXCL | OpenFlags::CLOEXEC;
        let created = open(nr::OPEN, path, flags, 0o666).unwrap();
        let descriptor_flags = |fd| {
            let fd = task.files.typed_fd(i32::try_from(fd).unwrap()).unwrap();
            task.global
                .litebox
                .descriptor_table()
                .with_metadata(&fd, |flags: &FileDescriptorFlags| *flags)
        };
        let duplicate = invoke(nr::DUP, created, 0).unwrap();
        assert!(matches!(
            descriptor_flags(duplicate),
            Err(litebox::fd::MetadataError::NoSuchMetadata)
        ));
        assert_eq!(
            descriptor_flags(created).unwrap(),
            FileDescriptorFlags::FD_CLOEXEC
        );
        assert_eq!(invoke(nr::CLOSE, duplicate, 0), Ok(0));
        let status = task
            .files
            .file(
                &task
                    .files
                    .typed_fd(i32::try_from(created).unwrap())
                    .unwrap(),
            )
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(status.mode, FileMode::from_u32_bits_truncate(0o644));
        assert_eq!(
            status.owner,
            FileUser {
                user: 1000,
                group: 1000
            }
        );
        assert_eq!(
            open(nr::OPEN_NOCANCEL, path, flags, 0o666),
            Err(Errno::EEXIST)
        );
        buf.copy_from_slice(0, b"new").unwrap();
        assert_eq!(invoke(nr::WRITE, created, 3), Ok(3));
        assert_eq!(invoke(nr::CLOSE, created, 0), Ok(0));
        let reopened = open(nr::OPEN_NOCANCEL, path, OpenFlags::RDONLY, 0).unwrap();
        assert!(matches!(
            descriptor_flags(reopened),
            Err(litebox::fd::MetadataError::NoSuchMetadata)
        ));
        assert_eq!(invoke(nr::READ, reopened, 3), Ok(3));
        assert_eq!(&*buf.to_owned_slice(3).unwrap(), b"new");
        assert_eq!(invoke(nr::CLOSE_NOCANCEL, reopened, 0), Ok(0));
        for unsupported in [O_SHLOCK, O_EXLOCK] {
            assert_eq!(
                open(nr::OPEN, path, OpenFlags::from_bits_retain(unsupported), 0,),
                Err(Errno::EINVAL)
            );
        }
        assert_eq!(open(nr::OPEN, 0, OpenFlags::RDONLY, 0), Err(Errno::EFAULT));
        buf.copy_from_slice(0, &[b'x'; PATH_MAX]).unwrap();
        assert_eq!(
            open(nr::OPEN, buf.as_usize(), OpenFlags::RDONLY, 0),
            Err(Errno::ENAMETOOLONG)
        );
        buf.copy_from_slice(0, b"\0").unwrap();
        assert_eq!(
            open(nr::OPEN, buf.as_usize(), OpenFlags::RDONLY, 0),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            task.sys_open("/data/", OpenFlags::RDONLY, FileMode::empty()),
            Err(Errno::ENOTDIR)
        );
        let relative = task
            .sys_open("data", OpenFlags::RDONLY, FileMode::empty())
            .unwrap();
        task.sys_close(i32::try_from(relative).unwrap()).unwrap();
        let no_follow = task
            .sys_open(
                "/data",
                OpenFlags::RDONLY | OpenFlags::NOFOLLOW_ANY,
                FileMode::empty(),
            )
            .unwrap();
        task.sys_close(i32::try_from(no_follow).unwrap()).unwrap();
        assert_eq!(
            task.sys_open(
                "/directory/data",
                OpenFlags::RDONLY | OpenFlags::NOFOLLOW_ANY,
                FileMode::empty(),
            ),
            Err(Errno::ENOTSUP)
        );

        let directory = task
            .sys_open("/", OpenFlags::RDONLY, FileMode::empty())
            .unwrap();
        assert_eq!(
            task.sys_mmap(
                0,
                PAGE_SIZE,
                VmProtection::READ,
                MmapFlags::PRIVATE,
                i32::try_from(directory).unwrap(),
                0,
            ),
            Err(Errno::EINVAL)
        );
        task.sys_close(i32::try_from(directory).unwrap()).unwrap();

        // Publishing a duplicate is atomic with the descriptor limit check.
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let files = &task.files;
                scope.spawn(move || {
                    for _ in 0..100 {
                        let duplicate = i32::try_from(files.dup(1).unwrap()).unwrap();
                        files.close(duplicate).unwrap();
                    }
                });
            }
        });
        for expected in (0..MAX_FDS).filter(|&fd| fd != 1) {
            assert_eq!(task.sys_dup(1), Ok(u32::try_from(expected).unwrap()));
        }
        assert_eq!(task.sys_dup(1), Err(Errno::EMFILE));
        // fsctl looks the path up without needing a descriptor.
        assert_eq!(task.sys_fsctl("/data", 0x4008_4a6a, 0), Err(Errno::ENOTSUP));
        buf.copy_from_slice(0, b"/data\0").unwrap();
        assert_eq!(
            open(
                nr::OPEN,
                buf.as_usize(),
                OpenFlags::WRONLY | OpenFlags::TRUNC,
                0
            ),
            Err(Errno::EMFILE),
        );
        let mut contents = [0; 6];
        assert_eq!(
            task.files
                .file(&task.files.typed_fd(1).unwrap())
                .unwrap()
                .read(&mut contents, Some(0), None)
                .unwrap(),
            6
        );
        assert_eq!(&contents, b"abcdXY");
        buf.copy_from_slice(0, b"/not-created\0").unwrap();
        assert_eq!(
            open(
                nr::OPEN_NOCANCEL,
                buf.as_usize(),
                OpenFlags::WRONLY | OpenFlags::CREAT,
                0o600
            ),
            Err(Errno::EMFILE),
        );
        task.sys_close(12).unwrap();
        assert_eq!(
            open(nr::OPEN, buf.as_usize(), OpenFlags::RDONLY, 0),
            Err(Errno::ENOENT),
        );
        assert_eq!(task.sys_dup(1), Ok(12));
    }

    /// F_GETPATH never copies out more than MAXPATHLEN bytes, even for a file
    /// opened relative to a directory whose canonical path is longer.
    #[test]
    fn getpath_fails_with_enospc_beyond_maxpathlen() {
        const AT_FDCWD: usize = (-2isize).cast_unsigned();
        let mode = FileMode::from_u32_bits_truncate(0o755);
        let component = "c".repeat(200);
        let mut nodes = vec![(
            "/",
            InitialNode::Directory {
                mode,
                owner: FileUser::ROOT,
            },
        )];
        let mut path = String::new();
        for _ in 0..6 {
            path.push('/');
            path.push_str(&component);
            nodes.push((
                String::leak(path.clone()),
                InitialNode::Directory {
                    mode,
                    owner: FileUser::ROOT,
                },
            ));
        }
        let task = task_with(builder_with_files(nodes), TaskParams::default());
        let call = |number: usize, args: &[usize]| {
            let mut ctx = PtRegs::default();
            ctx.regs[16] = number;
            ctx.regs[..args.len()].copy_from_slice(args);
            task.do_syscall(&ctx)
        };
        let openat = |dirfd: usize, path: &str| {
            let path = alloc::ffi::CString::new(path).unwrap();
            call(nr::OPENAT, &[dirfd, path.as_ptr() as usize, 0, 0]).unwrap()
        };
        let half = alloc::format!("/{component}").repeat(3);
        assert_eq!(half.len(), 603);
        let outer = openat(AT_FDCWD, &half);
        let inner = openat(outer, &half[1..]);
        assert_eq!(path.len(), 1206);
        for command in [50, 102] {
            // A MAXPATHLEN buffer followed by sentinel bytes.
            let mut buffer = [0xa5u8; PATH_MAX + 256];
            let pointer = buffer.as_mut_ptr() as usize;
            assert_eq!(
                call(nr::FCNTL, &[inner, command, pointer]),
                Err(Errno::ENOSPC)
            );
            assert!(buffer.iter().all(|byte| *byte == 0xa5), "{command}");
            // A path that fits, with its NUL, is copied out.
            assert_eq!(call(nr::FCNTL, &[outer, command, pointer]), Ok(0));
            assert_eq!(&buffer[..half.len()], half.as_bytes());
            assert_eq!(buffer[half.len()], 0);
            assert!(buffer[half.len() + 1..].iter().all(|byte| *byte == 0xa5));
        }
    }

    /// stat64/fstat64, openat, fcntl, ioctl, fsctl and access against a small
    /// guest filesystem, through the dispatcher.
    #[test]
    fn file_syscalls_follow_xnu() {
        use litebox_common_macos::Stat64;
        const AT_FDCWD: usize = (-2isize).cast_unsigned();
        const FIOCLEX: usize = 0x2000_6601;
        const FIONREAD: usize = 0x4004_667f;
        const FIONBIO: usize = 0x8004_667e;
        const FIOASYNC: usize = 0x8004_667d;
        let user = FileUser {
            user: 1000,
            group: 1000,
        };
        let other = FileUser {
            user: 2000,
            group: 2000,
        };
        let mode = FileMode::from_u32_bits_truncate;
        let builder = builder_with_files(vec![
            (
                "/",
                InitialNode::Directory {
                    mode: mode(0o777),
                    owner: FileUser::ROOT,
                },
            ),
            (
                "/dir",
                InitialNode::Directory {
                    mode: mode(0o755),
                    owner: user,
                },
            ),
            (
                "/dir/data",
                InitialNode::File {
                    mode: mode(0o640),
                    owner: user,
                    data: (&b"0123456789"[..]).into(),
                },
            ),
            (
                "/dir/sub",
                InitialNode::Directory {
                    mode: mode(0o777),
                    owner: user,
                },
            ),
            (
                "/script",
                InitialNode::File {
                    mode: mode(0o751),
                    owner: other,
                    data: (&b"#!"[..]).into(),
                },
            ),
            (
                "/group-only",
                InitialNode::File {
                    mode: mode(0o040),
                    owner: FileUser {
                        user: 2000,
                        group: 1000,
                    },
                    data: (&b""[..]).into(),
                },
            ),
            (
                "/secret",
                InitialNode::File {
                    mode: mode(0o000),
                    owner: FileUser::ROOT,
                    data: (&b"x"[..]).into(),
                },
            ),
            (
                "/locked",
                InitialNode::Directory {
                    mode: mode(0o000),
                    owner: FileUser::ROOT,
                },
            ),
        ]);
        let task = task_with(builder, TaskParams::default());
        let call = |number: usize, args: &[usize]| {
            let mut ctx = PtRegs::default();
            ctx.regs[16] = number;
            ctx.regs[..args.len()].copy_from_slice(args);
            task.do_syscall(&ctx)
        };
        let ptr = |s: &core::ffi::CStr| s.as_ptr() as usize;
        let openat = |dirfd: usize, path: &core::ffi::CStr, flags: OpenFlags| {
            call(
                nr::OPENAT,
                &[
                    dirfd,
                    ptr(path),
                    flags.bits().cast_unsigned() as usize,
                    0o644,
                ],
            )
        };
        let close = |fd: usize| assert_eq!(call(nr::CLOSE, &[fd]), Ok(0));
        let mut path_buffer = [0u8; PATH_MAX];
        let get_path = |fd: usize, buffer: &mut [u8]| {
            call(nr::FCNTL, &[fd, 50, buffer.as_mut_ptr() as usize])?;
            let end = buffer.iter().position(|byte| *byte == 0).unwrap();
            Ok::<_, Errno>(String::from_utf8(buffer[..end].to_vec()).unwrap())
        };

        // stat64 / fstat64: the Darwin layout and mode bits.
        let mut stat = Stat64::default();
        let stat_ptr = core::ptr::from_mut(&mut stat) as usize;
        assert_eq!(call(nr::STAT64, &[ptr(c"/dir/data"), stat_ptr]), Ok(0));
        assert_eq!((stat.mode, stat.size, stat.nlink), (0o100_640, 10, 1));
        assert_eq!((stat.uid, stat.gid, stat.blocks), (1000, 1000, 1));
        assert_ne!(stat.ino, 0);
        let data_ino = stat.ino;
        assert_eq!(call(nr::LSTAT64, &[ptr(c"/dir"), stat_ptr]), Ok(0));
        assert_eq!(stat.mode, 0o040_755);
        assert_eq!(
            call(nr::STAT64, &[ptr(c"/missing"), stat_ptr]),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            call(nr::STAT64, &[ptr(c"/dir/data"), 0x10]),
            Err(Errno::EFAULT)
        );

        // openat: AT_FDCWD, a directory descriptor, trailing slashes, `..`.
        let dir = openat(AT_FDCWD, c"/dir", OpenFlags::RDONLY).unwrap();
        let data = openat(dir, c"data", OpenFlags::RDWR).unwrap();
        assert_eq!(get_path(data, &mut path_buffer).as_deref(), Ok("/dir/data"));
        assert_eq!(call(nr::FSTAT64, &[data, stat_ptr]), Ok(0));
        assert_eq!((stat.ino, stat.size), (data_ino, 10));
        assert_eq!(call(nr::FSTAT64, &[data, 0x10]), Err(Errno::EFAULT));
        assert_eq!(call(nr::FSTAT64, &[999, stat_ptr]), Err(Errno::EBADF));
        assert_eq!(call(nr::FSTAT64, &[dir, stat_ptr]), Ok(0));
        assert_eq!(stat.mode, 0o040_755);
        assert_eq!(
            openat(dir, c"data/", OpenFlags::RDONLY),
            Err(Errno::ENOTDIR)
        );
        assert_eq!(
            openat(dir, c"data/..", OpenFlags::RDONLY),
            Err(Errno::ENOTDIR)
        );
        assert_eq!(
            openat(AT_FDCWD, c"/dir/data/../sub", OpenFlags::RDONLY),
            Err(Errno::ENOTDIR)
        );
        assert_eq!(
            openat(dir, c"missing/../data", OpenFlags::RDONLY),
            Err(Errno::ENOENT)
        );
        let sub = openat(dir, c"sub/", OpenFlags::RDONLY).unwrap();
        assert_eq!(get_path(sub, &mut path_buffer).as_deref(), Ok("/dir/sub"));
        close(sub);
        let parent = openat(dir, c"sub/../data", OpenFlags::RDONLY).unwrap();
        assert_eq!(
            get_path(parent, &mut path_buffer).as_deref(),
            Ok("/dir/data")
        );
        close(parent);
        // A trailing slash can never create a file.
        let create = OpenFlags::RDWR | OpenFlags::CREAT;
        assert_eq!(openat(dir, c"new/", create), Err(Errno::ENOENT));
        assert_eq!(openat(dir, c"data/", create), Err(Errno::ENOTDIR));
        assert_eq!(
            call(nr::STAT64, &[ptr(c"/dir/new"), stat_ptr]),
            Err(Errno::ENOENT)
        );
        let created = openat(dir, c"new", create).unwrap();
        assert_eq!(
            get_path(created, &mut path_buffer).as_deref(),
            Ok("/dir/new")
        );
        close(created);
        // PATH_MAX bounds the guest's pathname, not the directory prefix.
        let mut long = "./".repeat(508);
        long.push_str("data");
        assert_eq!(long.len(), PATH_MAX - 4);
        let long = alloc::ffi::CString::new(long).unwrap();
        let long_data = openat(dir, &long, OpenFlags::RDONLY).unwrap();
        assert_eq!(
            get_path(long_data, &mut path_buffer).as_deref(),
            Ok("/dir/data")
        );
        close(long_data);
        let mut too_long = "./".repeat(510);
        too_long.push_str("data");
        let too_long = alloc::ffi::CString::new(too_long).unwrap();
        assert_eq!(
            openat(dir, &too_long, OpenFlags::RDONLY),
            Err(Errno::ENAMETOOLONG)
        );
        assert_eq!(openat(data, c"x", OpenFlags::RDONLY), Err(Errno::ENOTDIR));
        assert_eq!(openat(999, c"x", OpenFlags::RDONLY), Err(Errno::EBADF));
        assert_eq!(openat(dir, c"", OpenFlags::RDONLY), Err(Errno::ENOENT));

        // fcntl: descriptor and status flags, duplication, signatures.
        assert_eq!(call(nr::FCNTL, &[data, 50, 0x10]), Err(Errno::EFAULT));
        assert_eq!(call(nr::FCNTL, &[data, 1, 0]), Ok(0));
        assert_eq!(call(nr::FCNTL, &[data, 2, 1]), Ok(0));
        assert_eq!(call(nr::FCNTL_NOCANCEL, &[data, 1, 0]), Ok(1));
        assert_eq!(call(nr::FCNTL, &[data, 2, 0]), Ok(0));
        assert_eq!(call(nr::FCNTL, &[data, 3, 0]), Ok(2), "O_RDWR");
        assert_eq!(call(nr::FCNTL, &[dir, 3, 0]), Ok(0), "O_RDONLY");
        // O_NONBLOCK | O_APPEND | O_ASYNC; O_CREAT is not a status flag.
        assert_eq!(call(nr::FCNTL, &[data, 4, 0x4 | 0x8 | 0x40 | 0x200]), Ok(0));
        assert_eq!(call(nr::FCNTL, &[data, 3, 0]), Ok(2 | 0x4 | 0x8 | 0x40));
        let file = task
            .files
            .file(&task.files.typed_fd(i32::try_from(data).unwrap()).unwrap())
            .unwrap();
        let status = file.get_status_flags().unwrap();
        assert!(
            status
                .flags
                .contains(FileOpenFlags::NONBLOCKING | FileOpenFlags::APPEND)
        );
        // F_NOCACHE is recorded like XNU's FNOCACHE.
        assert_eq!(call(nr::FCNTL, &[data, 48, 1]), Ok(0));
        assert_eq!(
            call(nr::FCNTL, &[data, 3, 0]),
            Ok(2 | 0x4 | 0x8 | 0x40 | 0x4_0000)
        );
        assert_eq!(call(nr::FCNTL, &[data, 48, 0]), Ok(0));
        assert_eq!(call(nr::FCNTL, &[data, 4, 0]), Ok(0));
        assert_eq!(call(nr::FCNTL, &[data, 3, 0]), Ok(2));
        // F_DUPFD / F_DUPFD_CLOEXEC: lowest free descriptor at or above the minimum.
        let duplicate = call(nr::FCNTL, &[data, 0, 10]).unwrap();
        assert_eq!(duplicate, 10);
        assert_eq!(call(nr::FCNTL, &[duplicate, 1, 0]), Ok(0));
        assert_eq!(call(nr::FCNTL, &[data, 67, 10]), Ok(11));
        assert_eq!(call(nr::FCNTL, &[11, 1, 0]), Ok(1));
        assert_eq!(get_path(11, &mut path_buffer).as_deref(), Ok("/dir/data"));
        assert_eq!(call(nr::FCNTL, &[data, 0, MAX_FDS - 1]), Ok(MAX_FDS - 1));
        assert_eq!(call(nr::FCNTL, &[data, 0, MAX_FDS - 1]), Err(Errno::EMFILE));
        assert_eq!(call(nr::FCNTL, &[data, 0, MAX_FDS]), Err(Errno::EINVAL));
        assert_eq!(call(nr::FCNTL, &[data, 0, usize::MAX]), Err(Errno::EINVAL));
        for fd in [10, 11, MAX_FDS - 1] {
            close(fd);
        }
        // F_CHECK_LV: library validation allows the unsigned guest.
        let check_lv = [0u64; 3];
        assert_eq!(
            call(nr::FCNTL, &[data, 98, check_lv.as_ptr() as usize]),
            Ok(0)
        );
        assert_eq!(call(nr::FCNTL, &[data, 98, 0x10]), Err(Errno::EFAULT));
        // F_ADDFILESIGS_RETURN: guest files carry no kernel-validated signature.
        assert_eq!(
            call(nr::FCNTL, &[data, 97, check_lv.as_ptr() as usize]),
            Err(Errno::EINVAL)
        );
        assert_eq!(call(nr::FCNTL, &[999, 1, 0]), Err(Errno::EBADF));

        // ioctl: descriptor requests, vn_ioctl's FIONREAD/FIONBIO/FIOASYNC.
        let mut count = -1i32;
        let count_ptr = core::ptr::from_mut(&mut count) as usize;
        assert_eq!(call(nr::IOCTL, &[data, FIONREAD, count_ptr]), Ok(0));
        assert_eq!(count, 10);
        assert_eq!(
            call(nr::READ, &[data, path_buffer.as_mut_ptr() as usize, 4]),
            Ok(4)
        );
        assert_eq!(call(nr::IOCTL, &[data, FIONREAD, count_ptr]), Ok(0));
        assert_eq!(count, 6);
        // Another open truncates the file below the shared offset: vn_ioctl
        // reports 0 bytes and the offset stays put.
        let truncating = openat(dir, c"data", OpenFlags::WRONLY | OpenFlags::TRUNC).unwrap();
        assert_eq!(call(nr::IOCTL, &[data, FIONREAD, count_ptr]), Ok(0));
        assert_eq!(count, 0);
        assert_eq!(
            call(nr::WRITE, &[truncating, b"abcdefgh".as_ptr() as usize, 8]),
            Ok(8)
        );
        close(truncating);
        assert_eq!(call(nr::IOCTL, &[data, FIONREAD, count_ptr]), Ok(0));
        assert_eq!(count, 4);
        assert_eq!(
            call(nr::READ, &[data, path_buffer.as_mut_ptr() as usize, 8]),
            Ok(4)
        );
        assert_eq!(&path_buffer[..4], b"efgh");
        assert_eq!(call(nr::IOCTL, &[dir, FIONREAD, count_ptr]), Ok(0));
        assert_eq!(call(nr::IOCTL, &[data, FIONREAD, 0x10]), Err(Errno::EFAULT));
        let on = 1i32;
        let off = 0i32;
        assert_eq!(
            call(
                nr::IOCTL,
                &[data, FIONBIO, core::ptr::from_ref(&on) as usize]
            ),
            Ok(0)
        );
        assert_eq!(
            call(
                nr::IOCTL,
                &[dir, FIOASYNC, core::ptr::from_ref(&on) as usize]
            ),
            Ok(0)
        );
        assert_eq!(call(nr::FCNTL, &[data, 3, 0]), Ok(2 | 0x4));
        assert_eq!(call(nr::FCNTL, &[dir, 3, 0]), Ok(0x40));
        assert_eq!(
            call(
                nr::IOCTL,
                &[data, FIONBIO, core::ptr::from_ref(&off) as usize]
            ),
            Ok(0)
        );
        assert_eq!(call(nr::FCNTL, &[data, 3, 0]), Ok(2));
        assert_eq!(call(nr::IOCTL, &[data, FIONBIO, 0x10]), Err(Errno::EFAULT));
        assert_eq!(call(nr::IOCTL, &[data, FIOCLEX, 0]), Ok(0));
        assert_eq!(call(nr::FCNTL, &[data, 1, 0]), Ok(1));
        // Terminal requests on a regular file; any FIO request on a device.
        assert_eq!(
            call(nr::IOCTL, &[data, 0x4008_7468, count_ptr]),
            Err(Errno::ENOTTY)
        );
        let null = openat(AT_FDCWD, c"/dev/null", OpenFlags::RDWR).unwrap();
        assert_eq!(call(nr::FSTAT64, &[null, stat_ptr]), Ok(0));
        assert_eq!(stat.mode & 0o170_000, 0o020_000);
        assert_eq!(
            call(nr::IOCTL, &[null, FIONREAD, count_ptr]),
            Err(Errno::ENOTTY)
        );
        assert_eq!(call(nr::IOCTL, &[999, FIOCLEX, 0]), Err(Errno::EBADF));
        close(null);

        // fsctl: lookup only, no read permission, devices are not volumes.
        assert_eq!(
            task.sys_fsctl("/secret", 0x4008_4a6a, 0),
            Err(Errno::ENOTSUP)
        );
        assert_eq!(
            task.sys_fsctl("/dev/null", 0x4008_4a6a, 0),
            Err(Errno::ENOTTY)
        );
        assert_eq!(
            task.sys_fsctl("/dir/data/", 0x4008_4a6a, 0),
            Err(Errno::ENOTDIR)
        );
        assert_eq!(
            task.sys_fsctl("/dir/data/..", 0x4008_4a6a, 0),
            Err(Errno::ENOTDIR)
        );

        // access with the real credentials (uid/gid 1000).
        let access = |path: &core::ffi::CStr, mode: usize| call(nr::ACCESS, &[ptr(path), mode]);
        assert_eq!(access(c"/dir/data", 0), Ok(0));
        assert_eq!(access(c"/dir/data", 4 | 2), Ok(0));
        assert_eq!(access(c"/dir/data", 1), Err(Errno::EACCES));
        assert_eq!(access(c"/group-only", 4), Ok(0));
        assert_eq!(access(c"/group-only", 2), Err(Errno::EACCES));
        assert_eq!(access(c"/script", 1), Ok(0));
        assert_eq!(access(c"/script", 4), Err(Errno::EACCES));
        assert_eq!(access(c"/dir", 1), Ok(0));
        assert_eq!(access(c"/locked", 1), Err(Errno::EACCES));
        assert_eq!(access(c"/missing", 0), Err(Errno::ENOENT));
        // Bits beyond R/W/X and the extended rights are ignored, as access1 does.
        assert_eq!(access(c"/dir/data", 0x10 | 4), Ok(0));
        assert_eq!(access(c"/dir/data", 1 << 9), Err(Errno::ENOTSUP));

        close(data);
        close(dir);

        // Root: everything except executing a regular file with no x bit.
        let root = Task {
            global: Arc::clone(&task.global),
            files: Arc::clone(&task.files),
            params: TaskParams {
                uid: 0,
                euid: 0,
                gid: 0,
                egid: 0,
                ..TaskParams::default()
            },
            process: Process(Arc::new(AtomicI32::new(-1))),
            thread: crate::ThreadState::new(2u64 << 32, task.global.platform),
        };
        let root_access = |path: &str, mode: i32| root.sys_access(path, mode);
        assert_eq!(root_access("/locked", 4 | 2 | 1), Ok(()));
        assert_eq!(root_access("/secret", 4 | 2), Ok(()));
        assert_eq!(root_access("/secret", 1), Err(Errno::EPERM));
        assert_eq!(root_access("/secret", 4 | 1), Err(Errno::EPERM));
        assert_eq!(root_access("/group-only", 1), Err(Errno::EPERM));
        assert_eq!(root_access("/script", 1), Ok(()));
    }
}
