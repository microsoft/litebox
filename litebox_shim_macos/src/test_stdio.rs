// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test-only local stdio and its descriptor namespace.
//!
//! LiteBox manages typed descriptor identity and lifetime. The adapter supplies
//! I/O for the test streams. No broker connection is used by this module.

use crate::{ShimPlatform, Task, ToSyscallResult as _};
use alloc::{sync::Arc, vec, vec::Vec};
use litebox::platform::page_mgmt::MemoryRegionPermissions as Permissions;
use litebox::{
    LiteBox,
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, RawDescriptorStorage, TypedFd},
    stdio::{StdioOutputStream, StdioStream},
    sync::RwLock,
};
use litebox_common_macos::{SyscallRequest, errno::Errno};

/// Runner-provided test I/O. Buffers are shim-owned slices.
pub trait Stdio: Send + Sync {
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno>;
    fn write(&self, stream: StdioOutputStream, buf: &[u8]) -> Result<usize, Errno>;
}

struct LocalStdio;
struct StdioEntry {
    stream: StdioStream,
}
impl FdEnabledSubsystem for LocalStdio {
    type Entry = StdioEntry;
}
impl FdEnabledSubsystemEntry for StdioEntry {}

const MAX_FDS: usize = 1024;
const MAX_IO_SIZE: usize = 64 * 1024;

pub(crate) struct TestStdio<P: ShimPlatform> {
    litebox: Arc<LiteBox<P>>,
    adapter: Option<Arc<dyn Stdio>>,
    raw_descriptor_store: RwLock<P, RawDescriptorStorage>,
}

impl<P: ShimPlatform> TestStdio<P> {
    pub(crate) fn new(litebox: Arc<LiteBox<P>>, adapter: Option<Arc<dyn Stdio>>) -> Self {
        let mut raw = RawDescriptorStorage::new();
        if adapter.is_some() {
            let mut descriptors = litebox.descriptor_table_mut();
            for stream in [StdioStream::Stdin, StdioStream::Stdout, StdioStream::Stderr] {
                let fd = descriptors.insert::<LocalStdio>(StdioEntry { stream });
                raw.fd_into_raw_integer(fd);
            }
        }
        Self {
            litebox,
            adapter,
            raw_descriptor_store: RwLock::new(raw),
        }
    }

    /// Dispatch only the descriptor syscalls supplied by this test adapter.
    pub(crate) fn dispatch(
        &self,
        task: &Task<P>,
        request: SyscallRequest,
    ) -> Option<Result<usize, Errno>> {
        Some(match request {
            SyscallRequest::Read { fd, buf, count } => (|| {
                self.read_stream(fd)?;
                let length = io_length(count)?;
                task.check_user_buffer(buf.as_usize(), length, Permissions::WRITE)?;
                let mut bytes = vec![0; length];
                let size = self.do_read(&mut bytes)?;
                if size != 0 {
                    buf.copy_from_slice::<P>(0, &bytes[..size])
                        .ok_or(Errno::EFAULT)?;
                }
                Ok(size)
            })(),
            SyscallRequest::Write { fd, buf, count } => (|| {
                let stream = self.write_stream(fd)?;
                let length = io_length(count)?;
                task.check_user_buffer(buf.as_usize(), length, Permissions::READ)?;
                if length == 0 {
                    return self.do_write(stream, &[]);
                }
                let bytes = buf.to_owned_slice::<P>(length).ok_or(Errno::EFAULT)?;
                self.do_write(stream, &bytes)
            })(),
            SyscallRequest::Close { fd } => self.close(fd).to_syscall_result(),
            SyscallRequest::Dup { fd } => self.dup(fd).to_syscall_result(),
            _ => return None,
        })
    }

    fn typed_fd(&self, raw: i32) -> Result<Arc<TypedFd<LocalStdio>>, Errno> {
        self.raw_descriptor_store
            .read()
            .fd_from_raw_integer::<LocalStdio>(usize::try_from(raw).map_err(|_| Errno::EBADF)?)
            .map_err(|_| Errno::EBADF)
    }

    fn stream(&self, raw: i32) -> Result<StdioStream, Errno> {
        let fd = self.typed_fd(raw)?;
        self.litebox
            .descriptor_table()
            .with_entry(&fd, |entry| entry.stream)
            .ok_or(Errno::EBADF)
    }

    fn read_stream(&self, raw: i32) -> Result<(), Errno> {
        match self.stream(raw)? {
            StdioStream::Stdin => Ok(()),
            _ => Err(Errno::EBADF),
        }
    }

    fn write_stream(&self, raw: i32) -> Result<StdioOutputStream, Errno> {
        match self.stream(raw)? {
            StdioStream::Stdout => Ok(StdioOutputStream::Stdout),
            StdioStream::Stderr => Ok(StdioOutputStream::Stderr),
            StdioStream::Stdin => Err(Errno::EBADF),
        }
    }

    #[cfg(all(test, target_os = "macos"))]
    fn read(&self, fd: i32, buf: &mut [u8]) -> Result<usize, Errno> {
        self.read_stream(fd)?;
        self.do_read(buf)
    }

    fn do_read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        let size = self.adapter.as_ref().ok_or(Errno::EBADF)?.read(buf)?;
        if size > buf.len() {
            return Err(Errno::EIO);
        }
        Ok(size)
    }

    #[cfg(all(test, target_os = "macos"))]
    fn write(&self, fd: i32, buf: &[u8]) -> Result<usize, Errno> {
        let stream = self.write_stream(fd)?;
        self.do_write(stream, buf)
    }

    fn do_write(&self, stream: StdioOutputStream, buf: &[u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        let size = self
            .adapter
            .as_ref()
            .ok_or(Errno::EBADF)?
            .write(stream, buf)?;
        if size > buf.len() {
            return Err(Errno::EIO);
        }
        Ok(size)
    }

    fn close(&self, raw: i32) -> Result<(), Errno> {
        let fd = self
            .raw_descriptor_store
            .write()
            .fd_consume_raw_integer::<LocalStdio>(usize::try_from(raw).map_err(|_| Errno::EBADF)?)
            .map_err(|_| Errno::EBADF)?;
        // The raw-store lock is released before taking the descriptor-table lock.
        self.litebox.descriptor_table_mut().remove(&fd);
        Ok(())
    }

    fn dup(&self, raw: i32) -> Result<u32, Errno> {
        let fd = self.typed_fd(raw)?;
        let duplicate = self
            .litebox
            .descriptor_table_mut()
            .duplicate(&fd)
            .ok_or(Errno::EBADF)?;
        let mut store = self.raw_descriptor_store.write();
        // Limit checking and publication are atomic. Retire unpublished
        // duplicates outside the raw-store lock when the namespace is full.
        if store.iter_alive().count() >= MAX_FDS {
            drop(store);
            self.litebox.descriptor_table_mut().remove(&duplicate);
            return Err(Errno::EMFILE);
        }
        Ok(u32::try_from(store.fd_into_raw_integer(duplicate))
            .expect("raw descriptor is bounded by MAX_FDS"))
    }
}

impl<P: ShimPlatform> Drop for TestStdio<P> {
    fn drop(&mut self) {
        let alive: Vec<_> = self.raw_descriptor_store.read().iter_alive().collect();
        for raw in alive {
            let fd = self
                .raw_descriptor_store
                .write()
                .fd_consume_raw_integer::<LocalStdio>(raw)
                .expect("live descriptor has the stdio subsystem type");
            self.litebox.descriptor_table_mut().remove(&fd);
        }
    }
}

fn io_length(count: usize) -> Result<usize, Errno> {
    if count > isize::MAX.cast_unsigned() {
        return Err(Errno::EINVAL);
    }
    Ok(count.min(MAX_IO_SIZE))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    extern crate std;

    use super::*;
    use crate::{MacosShimBuilder, Process};
    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use litebox::mm::linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize};
    use litebox::platform::{PageManagementProvider as _, RawConstPointer as _};
    use litebox_common_macos::{
        PAGE_SIZE, PtRegs, TaskParams, syscall::nr, user_pointers::UserPtr,
    };
    use litebox_platform_macos_userland::MacosUserland as Platform;
    use std::sync::Mutex;

    #[derive(Default)]
    struct TestIo {
        reads: AtomicUsize,
        writes: Mutex<Vec<(StdioOutputStream, Vec<u8>)>>,
    }
    impl Stdio for TestIo {
        fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.reads.fetch_add(1, Ordering::Relaxed);
            buf[0] = b'x';
            Ok(1)
        }
        fn write(&self, stream: StdioOutputStream, buf: &[u8]) -> Result<usize, Errno> {
            self.writes.lock().unwrap().push((stream, buf.to_vec()));
            Ok(buf.len())
        }
    }

    fn stdio() -> TestStdio<Platform> {
        TestStdio::new(
            Arc::new(LiteBox::new(Platform::new())),
            Some(Arc::new(TestIo::default())),
        )
    }

    #[test]
    fn typed_descriptors_duplicate_reuse_and_retirement() {
        let litebox = Arc::new(LiteBox::new(Platform::new()));
        let io = Arc::new(TestIo::default());
        // Occupy an internal slot so the guest fd namespace differs from it.
        let unrelated = litebox
            .descriptor_table_mut()
            .insert::<LocalStdio>(StdioEntry {
                stream: StdioStream::Stderr,
            });
        let stdio = TestStdio::new(Arc::clone(&litebox), Some(io.clone()));
        let stdout = stdio.typed_fd(1).unwrap();
        let duplicate = i32::try_from(stdio.dup(1).unwrap()).unwrap();
        assert_eq!(duplicate, 3);
        assert_eq!(stdio.close(1), Ok(()));
        assert!(
            litebox
                .descriptor_table()
                .with_entry(&stdout, |_| ())
                .is_none()
        );
        assert_eq!(stdio.close(1), Err(Errno::EBADF));
        assert_eq!(stdio.dup(duplicate), Ok(1));
        assert_eq!(stdio.write(duplicate, b"dup"), Ok(3));
        // Stream direction belongs to the typed entry, not the raw fd number.
        stdio.close(0).unwrap();
        assert_eq!(stdio.dup(duplicate), Ok(0));
        assert_eq!(stdio.write(0, b"reused"), Ok(6));
        assert_eq!(stdio.read(0, &mut [0]), Err(Errno::EBADF));
        assert_eq!(stdio.write(-1, b""), Err(Errno::EBADF));
        assert_eq!(
            io.writes.lock().unwrap().as_slice(),
            &[
                (StdioOutputStream::Stdout, b"dup".to_vec()),
                (StdioOutputStream::Stdout, b"reused".to_vec()),
            ]
        );
        let retained = stdio.typed_fd(duplicate).unwrap();
        drop(stdio);
        assert!(
            litebox
                .descriptor_table()
                .with_entry(&retained, |_| ())
                .is_none()
        );
        assert!(
            litebox
                .descriptor_table()
                .with_entry(&unrelated, |_| ())
                .is_some()
        );
        litebox.descriptor_table_mut().remove(&unrelated);
    }

    #[test]
    fn descriptor_limit_is_bounded_and_slots_are_reused() {
        let stdio = stdio();
        for raw in 3..1024 {
            assert_eq!(stdio.dup(1), Ok(raw));
        }
        assert_eq!(stdio.dup(1), Err(Errno::EMFILE));
        stdio.close(12).unwrap();
        assert_eq!(stdio.dup(1), Ok(12));
        assert_eq!(stdio.dup(1), Err(Errno::EMFILE));
    }

    #[test]
    fn concurrent_dup_and_close_share_the_raw_namespace() {
        let stdio = stdio();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let stdio = &stdio;
                scope.spawn(move || {
                    for _ in 0..100 {
                        let fd = i32::try_from(stdio.dup(1).unwrap()).unwrap();
                        assert!(fd >= 3);
                        assert_eq!(stdio.write(fd, &[]), Ok(0));
                        stdio.close(fd).unwrap();
                    }
                });
            }
        });
        assert_eq!(stdio.dup(1), Ok(3));
    }

    #[test]
    fn user_buffers_are_validated_and_copied() {
        let io = Arc::new(TestIo::default());
        let shim = MacosShimBuilder::new(Platform::new())
            .with_stdio(io.clone())
            .build();
        let task = Task {
            global: shim.0,
            params: TaskParams::default(),
            process: Process(Arc::new(AtomicI32::new(-1))),
        };
        // SAFETY: a fresh, non-fixed mapping with no existing users.
        let ptr = unsafe {
            task.global.pm.create_writable_pages(
                NonZeroAddress::new(Platform::TASK_ADDR_MIN),
                NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
                CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                |_| Ok(0),
            )
        }
        .unwrap();
        let base = ptr.as_usize();
        // SAFETY: these idle pages are exclusively owned by this test.
        unsafe {
            task.global
                .pm
                .change_page_permissions(ptr, PAGE_SIZE, Permissions::READ)
                .unwrap();
        }
        let mut ctx = PtRegs::default();
        ctx.regs[16] = nr::READ;
        ctx.regs[0] = 0;
        ctx.regs[1] = base;
        ctx.regs[2] = 1;
        assert_eq!(task.do_syscall(&ctx), Err(Errno::EFAULT));
        assert_eq!(
            io.reads.load(Ordering::Relaxed),
            0,
            "invalid buffers must not consume input"
        );
        ctx.regs[1] = base + PAGE_SIZE;
        assert_eq!(task.do_syscall(&ctx), Ok(1));
        assert_eq!(io.reads.load(Ordering::Relaxed), 1);
        assert_eq!(
            UserPtr::<u8>::from_usize(base + PAGE_SIZE).read_at_offset::<Platform>(0),
            Some(b'x')
        );
        ctx.regs[16] = nr::WRITE;
        ctx.regs[0] = 1;
        assert_eq!(task.do_syscall(&ctx), Ok(1));
        assert_eq!(
            io.writes.lock().unwrap().as_slice(),
            &[(StdioOutputStream::Stdout, b"x".to_vec())]
        );
        ctx.regs[1] = usize::MAX;
        ctx.regs[2] = 2;
        assert_eq!(task.do_syscall(&ctx), Err(Errno::EFAULT));
        let host = [b'a'; 8];
        ctx.regs[1] = host.as_ptr() as usize;
        ctx.regs[2] = host.len();
        assert_eq!(task.do_syscall(&ctx), Err(Errno::EFAULT));
        assert_eq!(
            io.writes.lock().unwrap().len(),
            1,
            "rejected writes must not reach the adapter"
        );
    }
}
