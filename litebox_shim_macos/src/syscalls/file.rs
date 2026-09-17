// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest descriptor namespace and LiteBox file operations.

use crate::{ShimPlatform, Task};
use alloc::{sync::Arc, vec::Vec};
use litebox::{
    LiteBox,
    fd::RawDescriptorStorage,
    fs::{
        BrokerFile, FileFd,
        errors::{ReadError, WriteError},
    },
    sync::RwLock,
};
use litebox_common_macos::errno::Errno;

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
    pub(crate) fn do_read(&self, fd: &FileFd, buf: &mut [u8]) -> Result<usize, Errno> {
        let size = self
            .global
            .litebox
            .read_file(fd, buf, None)
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
    use crate::{MacosShimBuilder, Process};
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
    use litebox_broker_protocol::fs::{FileAccessMode, FileMode, FileOpenFlags, FileUser};
    use litebox_common_macos::{PAGE_SIZE, PtRegs, TaskParams, syscall::nr};
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
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
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
        assert_eq!(invoke(nr::READ, 0, 2), Ok(2));
        assert_eq!(&*buf.to_owned_slice(2).unwrap(), b"ab");
        assert_eq!(invoke(nr::DUP, 0, 0), Ok(2));
        let source = task.files.typed_fd(0).unwrap();
        assert_eq!(invoke(nr::CLOSE, 0, 0), Ok(0));
        assert_eq!(invoke(nr::READ, 0, 2), Err(Errno::EBADF));
        assert_eq!(task.do_read(&source, &mut [0; 2]), Err(Errno::EBADF));
        assert_eq!(invoke(nr::READ, 2, 2), Ok(2));
        assert_eq!(&*buf.to_owned_slice(2).unwrap(), b"cd");
        buf.copy_from_slice(0, b"XY").unwrap();
        assert_eq!(invoke(nr::WRITE, 2, 2), Ok(2));
        assert_eq!(invoke(nr::READ, 2, 2), Ok(0));
        assert_eq!(invoke(nr::WRITE, 1, 2), Err(Errno::EBADF));
        assert_eq!(invoke(nr::READ, 1, 6), Ok(6));
        assert_eq!(&*buf.to_owned_slice(6).unwrap(), b"abcdXY");
        assert_eq!(invoke(nr::CLOSE, 2, 0), Ok(0));
        assert_eq!(invoke(nr::CLOSE, 2, 0), Err(Errno::EBADF));

        // Invalid output buffers must not advance a file's offset.
        let fd = task
            .global
            .litebox
            .open_file(
                &context,
                "/data",
                FileAccessMode::ReadOnly,
                FileOpenFlags::NONE,
                FileMode::empty(),
            )
            .unwrap();
        let fresh = task.files.insert_file(fd).unwrap() as usize;
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
        task.sys_close(12).unwrap();
        assert_eq!(task.sys_dup(1), Ok(12));
    }
}
