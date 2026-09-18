// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest descriptor namespace and LiteBox file operations.

use crate::{ShimPlatform, Task};
use alloc::{string::String, sync::Arc, vec::Vec};
use litebox::{
    LiteBox,
    fd::RawDescriptorStorage,
    fs::{
        BrokerFile, FileFd,
        errors::{FileStatusError, OpenError, PathError, ReadError, TruncateError, WriteError},
    },
    sync::RwLock,
};
use litebox_broker_protocol::fs::{FileAccessMode, FileMode, FileOpenFlags, FileUser};
use litebox_common_macos::{
    FileDescriptorFlags, OpenFlags, PAGE_SIZE, PATH_MAX, errno::Errno, user_pointers::UserPtr,
};

const MAX_FDS: usize = 1024;

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

    pub(crate) fn insert_file(&self, fd: FileFd) -> Result<u32, Errno> {
        let mut raw = self.raw.write();
        if raw.iter_alive().count() >= MAX_FDS {
            drop(raw);
            if let Err(error) = self.litebox.close_file(&fd) {
                litebox_util_log::warn!(error:? = error; "failed to close unpublished descriptor");
            }
            return Err(Errno::EMFILE);
        }
        Ok(u32::try_from(raw.fd_into_raw_integer(fd)).expect("fd bounded by MAX_FDS"))
    }

    pub(crate) fn typed_fd(&self, fd: i32) -> Result<Arc<FileFd>, Errno> {
        self.raw
            .read()
            .fd_from_raw_integer::<BrokerFile>(usize::try_from(fd).map_err(|_| Errno::EBADF)?)
            .map_err(|_| Errno::EBADF)
    }

    fn consume(&self, fd: usize) -> Result<Arc<FileFd>, Errno> {
        self.raw
            .write()
            .fd_consume_raw_integer::<BrokerFile>(fd)
            .map_err(|_| Errno::EBADF)
    }

    pub(crate) fn close(&self, fd: i32) -> Result<(), Errno> {
        let fd = self.consume(usize::try_from(fd).map_err(|_| Errno::EBADF)?)?;
        self.litebox.close_file(&fd).map_err(|_| Errno::EIO)
    }

    pub(crate) fn dup(&self, fd: i32) -> Result<u32, Errno> {
        let fd = self.typed_fd(fd)?;
        let duplicate = self
            .litebox
            .descriptor_table_mut()
            .duplicate(&fd)
            .ok_or(Errno::EBADF)?;
        self.insert_file(duplicate)
    }
}

impl<P: ShimPlatform> Drop for FilesState<P> {
    fn drop(&mut self) {
        let alive: Vec<_> = self.raw.read().iter_alive().collect();
        for raw in alive {
            if let Ok(fd) = self.consume(raw)
                && let Err(error) = self.litebox.close_file(&fd)
            {
                litebox_util_log::warn!(error:? = error; "failed to close guest descriptor");
            }
        }
    }
}

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn sys_open(
        &self,
        path: impl litebox::path::Arg,
        flags: OpenFlags,
        mode: FileMode,
    ) -> Result<u32, Errno> {
        let path = path.as_rust_str().map_err(|_| Errno::EINVAL)?;
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        if path.len() >= PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        if path.as_bytes().contains(&0) {
            return Err(Errno::EINVAL);
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
            (OpenFlags::NOCTTY, FileOpenFlags::NO_CONTROLLING_TERMINAL),
            (OpenFlags::DIRECTORY, FileOpenFlags::DIRECTORY),
        ] {
            if flags.contains(guest) {
                open_flags = open_flags.union(broker);
            }
        }
        let mut context = litebox::fs::Context::new();
        context.set_acting_user(FileUser {
            user: u16::try_from(self.params.euid).map_err(|_| Errno::EINVAL)?,
            group: u16::try_from(self.params.egid).map_err(|_| Errno::EINVAL)?,
        });
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
        if flags.contains(OpenFlags::CLOEXEC) {
            // TODO: honor FD_CLOEXEC when macOS exec is implemented.
            let old = self
                .global
                .litebox
                .descriptor_table_mut()
                .set_fd_metadata(&file, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        Ok(u32::try_from(raw.fd_into_raw_integer(file)).expect("fd bounded by MAX_FDS"))
    }

    pub(crate) fn read_path(&self, path: UserPtr<core::ffi::c_char>) -> Result<String, Errno> {
        let mut bytes = Vec::new();
        while bytes.len() < PATH_MAX {
            let address = path
                .as_usize()
                .checked_add(bytes.len())
                .ok_or(Errno::EFAULT)?;
            let length = (PAGE_SIZE - address % PAGE_SIZE).min(PATH_MAX - bytes.len());
            self.check_user_buffer(
                address,
                length,
                litebox::platform::page_mgmt::MemoryRegionPermissions::READ,
            )?;
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
        fd: &FileFd,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, Errno> {
        let size = self
            .global
            .litebox
            .read_file(fd, buf, offset)
            .map_err(read_error)?;
        if size > buf.len() {
            return Err(Errno::EIO);
        }
        Ok(size)
    }

    pub(crate) fn do_write(&self, fd: &FileFd, buf: &[u8]) -> Result<usize, Errno> {
        let size = self
            .global
            .litebox
            .write_file(fd, buf, None)
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
            TruncateError::IsTerminalDevice => Errno::EINVAL,
            TruncateError::Io => Errno::EIO,
        },
        _ => Errno::EIO,
    }
}

fn path_error(error: PathError) -> Errno {
    match error {
        PathError::NoSuchFileOrDirectory | PathError::MissingComponent => Errno::ENOENT,
        PathError::NoSearchPerms { .. } => Errno::EACCES,
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

fn read_error(error: ReadError) -> Errno {
    match error {
        ReadError::ClosedFd | ReadError::NotForReading => Errno::EBADF,
        ReadError::NotAFile => Errno::EISDIR,
        _ => Errno::EIO,
    }
}

fn write_error(error: WriteError) -> Errno {
    match error {
        WriteError::ClosedFd | WriteError::NotForWriting => Errno::EBADF,
        WriteError::NotAFile => Errno::EISDIR,
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
    use litebox::mm::linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize};
    use litebox::platform::page_mgmt::MemoryRegionPermissions as Permissions;
    use litebox::platform::{
        PageManagementProvider as _, RawConstPointer as _, RawMutPointer as _,
    };
    use litebox_broker_core::{
        ObjectRights, PolicyEngine,
        fs::{
            in_mem::{InMem, InitialNode},
            resolver::Resolver,
        },
        test_support::TestBrokerCoreBuilder,
    };
    use litebox_broker_host::test_support::InProcessBrokerSetup;
    use litebox_broker_local::BrokerLocal;
    use litebox_broker_protocol::fs::{
        FileAccessMode, FileMode, FileOpenFlags, FileSeekWhence, FileUser,
    };
    use litebox_common_macos::{
        MmapFlags, PAGE_SIZE, PtRegs, TaskParams, VmProtection, syscall::nr,
    };
    use litebox_platform_macos_userland::MacosUserland as Platform;

    #[test]
    fn inherited_litebox_files_use_the_syscall_dispatcher() {
        let platform = Platform::new();
        let mode = FileMode::RWXU | FileMode::RWXG | FileMode::RWXO;
        let fs = InMem::<Platform>::new_initialized(vec![
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
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_file_service(Arc::new(Resolver::<Platform, _>::new(fs)))
        .build()
        .unwrap();
        let setup = InProcessBrokerSetup::new(broker);
        let readiness = setup.readiness_sink();
        let (local, ()) = BrokerLocal::negotiate(setup, |setup| {
            let memory = setup.shared_memory();
            Ok((setup.activate(), memory, ()))
        })
        .unwrap();
        let litebox = LiteBox::new_with_broker_local(platform, local);
        readiness.attach(litebox.broker_notification_dispatcher());
        let mut builder = MacosShimBuilder::new_with_litebox(platform, litebox);
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
        let shim = builder.build();
        let task = Task {
            global: shim.global,
            files: shim.files,
            params: TaskParams::default(),
            process: Process(Arc::new(AtomicI32::new(-1))),
        };
        // SAFETY: a fresh, non-fixed mapping owned by this task.
        let buf = unsafe {
            task.global.pm.create_writable_pages(
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
                assert_eq!(
                    task.global
                        .litebox
                        .seek_file(&source, 0, FileSeekWhence::RelativeToCurrentOffset)
                        .unwrap(),
                    0
                );
                assert_eq!(task.global.litebox.file_status(&source).unwrap().size, 6);
                assert_eq!(&*buf.to_owned_slice(untouched.len()).unwrap(), &untouched);
            }
        }
        assert_eq!(invoke(nr::READ, 0, 2), Ok(2));
        assert_eq!(&*buf.to_owned_slice(2).unwrap(), b"ab");
        assert_eq!(invoke(nr::DUP, 0, 0), Ok(2));
        assert_eq!(invoke(nr::CLOSE, 0, 0), Ok(0));
        assert_eq!(invoke(nr::READ, 0, 2), Err(Errno::EBADF));
        assert_eq!(task.do_read(&source, &mut [0; 2], None), Err(Errno::EBADF));
        assert_eq!(
            task.global
                .litebox
                .file_status(&source)
                .map_err(file_status_error)
                .unwrap_err(),
            Errno::EBADF
        );
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
        assert_eq!(invoke(nr::CLOSE, 2, 0), Ok(0));
        assert_eq!(invoke(nr::CLOSE, 2, 0), Err(Errno::EBADF));

        // Invalid output buffers must not advance a file's offset.
        let fresh = task
            .sys_open("/data", OpenFlags::RDONLY, FileMode::empty())
            .unwrap() as usize;
        // SAFETY: the test owns this idle mapping.
        unsafe {
            task.global
                .pm
                .change_page_permissions(buf, PAGE_SIZE, Permissions::READ)
                .unwrap();
        }
        assert_eq!(invoke(nr::READ, fresh, 2), Err(Errno::EFAULT));
        // SAFETY: the test owns this idle mapping.
        unsafe {
            task.global
                .pm
                .change_page_permissions(buf, PAGE_SIZE, Permissions::READ | Permissions::WRITE)
                .unwrap();
        }
        assert_eq!(invoke(nr::READ, fresh, 2), Ok(2));
        assert_eq!(&*buf.to_owned_slice(2).unwrap(), b"ab");

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
            .global
            .litebox
            .file_status(
                &task
                    .files
                    .typed_fd(i32::try_from(created).unwrap())
                    .unwrap(),
            )
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
        for expected in 2..MAX_FDS {
            assert_eq!(task.sys_dup(1), Ok(u32::try_from(expected).unwrap()));
        }
        assert_eq!(task.sys_dup(1), Err(Errno::EMFILE));
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
            task.global
                .litebox
                .read_file(&task.files.typed_fd(1).unwrap(), &mut contents, Some(0),)
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
}
