//! A shim that provides a Linux-compatible ABI via LiteBox.
//!
//! This shim is parametric in the choice of [LiteBox platform](../litebox/platform/index.html),
//! chosen by the [platform multiplex](../litebox_platform_multiplex/index.html).

#![no_std]
// NOTE(jayb): Allowing this only until the API design is fleshed out, once that is complete, this
// suppressed warning should be removed.
#![allow(dead_code, unused)]
#![warn(unused_imports)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

// TODO(jayb) Replace out all uses of once_cell and such with our own implementation that uses
// platform-specific things within it.
use once_cell::race::OnceBox;

use litebox::{
    LiteBox,
    fs::FileSystem,
    mm::{PageManager, linux::PAGE_SIZE},
    platform::{RawConstPointer as _, RawMutPointer as _},
    sync::RwLock,
};
use litebox_common_linux::{SyscallRequest, errno::Errno};
use litebox_platform_multiplex::Platform;

pub(crate) mod channel;
pub mod loader;
pub(crate) mod stdio;
pub mod syscalls;

type LinuxFS = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::devices::stdio::FileSystem<Platform>,
        litebox::fs::tar_ro::FileSystem<Platform>,
    >,
>;

/// Get the global litebox object
pub fn litebox<'a>() -> &'a LiteBox<Platform> {
    static LITEBOX: OnceBox<LiteBox<Platform>> = OnceBox::new();
    LITEBOX.get_or_init(|| {
        alloc::boxed::Box::new(LiteBox::new(litebox_platform_multiplex::platform()))
    })
}

static FS: OnceBox<LinuxFS> = OnceBox::new();
/// Set the global file system
///
/// NOTE: This function signature might change as better parametricity is added to file systems.
/// Related: <https://github.com/MSRSSP/litebox/issues/24>
///
/// # Panics
///
/// Panics if this is called more than once or [`litebox_fs`] is called before this
pub fn set_fs(fs: LinuxFS) {
    FS.set(alloc::boxed::Box::new(fs))
        .map_err(|_| {})
        .expect("fs is already set");
}

/// Get the global file system
///
/// # Panics
///
/// Panics if this is called before [`set_fs`] has been called
pub fn litebox_fs<'a>() -> &'a impl litebox::fs::FileSystem {
    FS.get().expect("fs has not yet been set")
}

pub(crate) fn litebox_page_manager<'a>() -> &'a PageManager<Platform, PAGE_SIZE> {
    static VMEM: OnceBox<PageManager<Platform, PAGE_SIZE>> = OnceBox::new();
    VMEM.get_or_init(|| alloc::boxed::Box::new(PageManager::new(litebox())))
}

// Convenience type aliases
type ConstPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

struct Descriptors {
    descriptors: Vec<Option<Descriptor>>,
}

impl Descriptors {
    fn new() -> Self {
        Self {
            descriptors: vec![
                Some(Descriptor::Stdio(stdio::StdioFile::new(
                    litebox::platform::StdioStream::Stdin,
                    litebox_fs()
                        .open(
                            "/dev/stdin",
                            litebox::fs::OFlags::RDONLY,
                            litebox::fs::Mode::empty(),
                        )
                        .unwrap(),
                    litebox::fs::OFlags::APPEND | litebox::fs::OFlags::RDWR,
                ))),
                Some(Descriptor::Stdio(stdio::StdioFile::new(
                    litebox::platform::StdioStream::Stdout,
                    litebox_fs()
                        .open(
                            "/dev/stdout",
                            litebox::fs::OFlags::WRONLY,
                            litebox::fs::Mode::empty(),
                        )
                        .unwrap(),
                    litebox::fs::OFlags::APPEND | litebox::fs::OFlags::RDWR,
                ))),
                Some(Descriptor::Stdio(stdio::StdioFile::new(
                    litebox::platform::StdioStream::Stderr,
                    litebox_fs()
                        .open(
                            "/dev/stderr",
                            litebox::fs::OFlags::WRONLY,
                            litebox::fs::Mode::empty(),
                        )
                        .unwrap(),
                    litebox::fs::OFlags::APPEND | litebox::fs::OFlags::RDWR,
                ))),
            ],
        }
    }
    fn insert(&mut self, descriptor: Descriptor) -> u32 {
        let idx = self
            .descriptors
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.descriptors.push(None);
                self.descriptors.len() - 1
            });
        let old = self.descriptors[idx].replace(descriptor);
        assert!(old.is_none());
        if idx >= (2 << 30) {
            panic!("Too many FDs");
        } else {
            u32::try_from(idx).unwrap()
        }
    }
    fn remove(&mut self, fd: u32) -> Option<Descriptor> {
        let fd = fd as usize;
        self.descriptors.get_mut(fd)?.take()
    }
    fn remove_file(&mut self, fd: u32) -> Option<litebox::fd::FileFd> {
        let fd = fd as usize;
        if let Some(Descriptor::File(file_fd)) = self
            .descriptors
            .get_mut(fd)?
            .take_if(|v| matches!(v, Descriptor::File(_)))
        {
            Some(file_fd)
        } else {
            None
        }
    }
    fn remove_socket(&mut self, fd: u32) -> Option<litebox::fd::SocketFd> {
        let fd = fd as usize;
        if let Some(Descriptor::Socket(socket_fd)) = self
            .descriptors
            .get_mut(fd)?
            .take_if(|v| matches!(v, Descriptor::Socket(_)))
        {
            Some(socket_fd)
        } else {
            None
        }
    }
    fn get_fd(&self, fd: u32) -> Option<&Descriptor> {
        self.descriptors.get(fd as usize)?.as_ref()
    }
    fn get_file_fd(&self, fd: u32) -> Option<&litebox::fd::FileFd> {
        if let Descriptor::File(file_fd) = self.descriptors.get(fd as usize)?.as_ref()? {
            Some(file_fd)
        } else {
            None
        }
    }
    fn get_socket_fd(&self, fd: u32) -> Option<&litebox::fd::SocketFd> {
        if let Descriptor::Socket(socket_fd) = self.descriptors.get(fd as usize)?.as_ref()? {
            Some(socket_fd)
        } else {
            None
        }
    }
}

enum Descriptor {
    File(litebox::fd::FileFd),
    Socket(litebox::fd::SocketFd),
    PipeReader {
        consumer: alloc::sync::Arc<crate::channel::Consumer<u8>>,
        close_on_exec: core::sync::atomic::AtomicBool,
    },
    PipeWriter {
        producer: alloc::sync::Arc<crate::channel::Producer<u8>>,
        close_on_exec: core::sync::atomic::AtomicBool,
    },
    Eventfd {
        file: alloc::sync::Arc<syscalls::eventfd::EventFile<Platform>>,
        close_on_exec: core::sync::atomic::AtomicBool,
    },
    // TODO: we may not need this once #31 and #68 are done.
    Stdio(stdio::StdioFile),
}

pub(crate) fn file_descriptors<'a>() -> &'a RwLock<Platform, Descriptors> {
    static FILE_DESCRIPTORS: once_cell::race::OnceBox<RwLock<Platform, Descriptors>> =
        once_cell::race::OnceBox::new();
    FILE_DESCRIPTORS
        .get_or_init(|| alloc::boxed::Box::new(litebox().sync().new_rwlock(Descriptors::new())))
}

/// Open a file
///
/// # Safety
///
/// `pathname` must point to a valid nul-terminated C string
#[expect(
    clippy::missing_panics_doc,
    reason = "the panics here are ideally never hit, and should not be user-facing"
)]
pub unsafe extern "C" fn open(pathname: ConstPtr<i8>, flags: u32, mode: u32) -> i32 {
    let Some(path) = pathname.to_cstring() else {
        return Errno::EFAULT.as_neg();
    };
    match syscalls::file::sys_open(
        path,
        litebox::fs::OFlags::from_bits(flags).unwrap(),
        litebox::fs::Mode::from_bits(mode).unwrap(),
    ) {
        Ok(fd) => fd.try_into().unwrap(),
        Err(err) => err.as_neg(),
    }
}

/// Closes the file
pub extern "C" fn close(fd: i32) -> i32 {
    syscalls::file::sys_close(fd).map_or_else(Errno::as_neg, |()| 0)
}

// This places size limits on maximum read/write sizes that might occur; it exists primarily to
// prevent OOM due to the user asking for a _massive_ read or such at once. Keeping this too small
// has the downside of requiring too many syscalls, while having it be too large allows for massive
// allocations to be triggered by the userland program. For now, this is set to a
// hopefully-reasonable middle ground.
const MAX_KERNEL_BUF_SIZE: usize = 64 * 1024;

/// Entry point for the syscall handler
#[allow(clippy::too_many_lines)]
pub fn syscall_entry(request: SyscallRequest<Platform>) -> isize {
    let res: Result<usize, Errno> = match request {
        SyscallRequest::Read { fd, buf, count } => {
            let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
            syscalls::file::sys_read(fd, &mut kernel_buf, None).and_then(|size| {
                buf.copy_from_slice(0, &kernel_buf[..size])
                    .map(|()| size)
                    .ok_or(Errno::EFAULT)
            })
        }
        SyscallRequest::Write { fd, buf, count } => match unsafe { buf.to_cow_slice(count) } {
            Some(buf) => syscalls::file::sys_write(fd, &buf, None),
            None => Err(Errno::EFAULT),
        },
        SyscallRequest::Close { fd } => syscalls::file::sys_close(fd).map(|()| 0),
        SyscallRequest::Ioctl { fd, arg } => syscalls::file::sys_ioctl(fd, arg).map(|v| v as usize),
        SyscallRequest::Pread64 {
            fd,
            buf,
            count,
            offset,
        } => {
            let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
            syscalls::file::sys_pread64(fd, &mut kernel_buf, offset).and_then(|size| {
                buf.copy_from_slice(0, &kernel_buf[..size])
                    .map(|()| size)
                    .ok_or(Errno::EFAULT)
            })
        }
        SyscallRequest::Pwrite64 {
            fd,
            buf,
            count,
            offset,
        } => match unsafe { buf.to_cow_slice(count) } {
            Some(buf) => syscalls::file::sys_pwrite64(fd, &buf, offset),
            None => Err(Errno::EFAULT),
        },
        SyscallRequest::Mmap {
            addr,
            length,
            prot,
            flags,
            fd,
            offset,
        } => {
            syscalls::mm::sys_mmap(addr, length, prot, flags, fd, offset).map(|ptr| ptr.as_usize())
        }
        SyscallRequest::Mprotect { addr, length, prot } => {
            syscalls::mm::sys_mprotect(addr, length, prot).map(|()| 0)
        }
        SyscallRequest::Munmap { addr, length } => {
            syscalls::mm::sys_munmap(addr, length).map(|()| 0)
        }
        SyscallRequest::Readv { fd, iovec, iovcnt } => syscalls::file::sys_readv(fd, iovec, iovcnt),
        SyscallRequest::Writev { fd, iovec, iovcnt } => {
            syscalls::file::sys_writev(fd, iovec, iovcnt)
        }
        SyscallRequest::Access { pathname, mode } => {
            pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscalls::file::sys_access(path, mode).map(|()| 0)
            })
        }
        SyscallRequest::Fcntl { fd, arg } => syscalls::file::sys_fcntl(fd, arg).map(|v| v as usize),
        SyscallRequest::Getcwd { buf, size: count } => {
            let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
            syscalls::file::sys_getcwd(&mut kernel_buf).and_then(|size| {
                buf.copy_from_slice(0, &kernel_buf[..size])
                    .map(|()| size)
                    .ok_or(Errno::EFAULT)
            })
        }
        SyscallRequest::Readlink {
            pathname,
            buf,
            bufsiz,
        } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
            let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
            syscalls::file::sys_readlink(path, &mut kernel_buf).and_then(|size| {
                buf.copy_from_slice(0, &kernel_buf[..size])
                    .map(|()| size)
                    .ok_or(Errno::EFAULT)
            })
        }),
        SyscallRequest::Readlinkat {
            dirfd,
            pathname,
            buf,
            bufsiz,
        } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
            let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
            syscalls::file::sys_readlinkat(dirfd, path, &mut kernel_buf).and_then(|size| {
                buf.copy_from_slice(0, &kernel_buf[..size])
                    .map(|()| size)
                    .ok_or(Errno::EFAULT)
            })
        }),
        SyscallRequest::Openat {
            dirfd,
            pathname,
            flags,
            mode,
        } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
            syscalls::file::sys_openat(dirfd, path, flags, mode).map(|fd| fd as usize)
        }),
        SyscallRequest::Stat { pathname, buf } => {
            pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscalls::file::sys_stat(path).and_then(|stat| {
                    unsafe { buf.write_at_offset(0, stat) }
                        .ok_or(Errno::EFAULT)
                        .map(|()| 0)
                })
            })
        }
        SyscallRequest::Lstat { pathname, buf } => {
            pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscalls::file::sys_lstat(path).and_then(|stat| {
                    unsafe { buf.write_at_offset(0, stat) }
                        .ok_or(Errno::EFAULT)
                        .map(|()| 0)
                })
            })
        }
        SyscallRequest::Fstat { fd, buf } => syscalls::file::sys_fstat(fd).and_then(|stat| {
            unsafe { buf.write_at_offset(0, stat) }
                .ok_or(Errno::EFAULT)
                .map(|()| 0)
        }),
        SyscallRequest::Newfstatat {
            dirfd,
            pathname,
            buf,
            flags,
        } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
            syscalls::file::sys_newfstatat(dirfd, path, flags).and_then(|stat| {
                unsafe { buf.write_at_offset(0, stat) }
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            })
        }),
        SyscallRequest::Eventfd2 { initval, flags } => {
            syscalls::file::sys_eventfd2(initval, flags).map(|fd| fd as usize)
        }
        SyscallRequest::Pipe2 { pipefd, flags } => {
            syscalls::file::sys_pipe2(flags).and_then(|(read_fd, write_fd)| {
                unsafe { pipefd.write_at_offset(0, read_fd).ok_or(Errno::EFAULT) }?;
                unsafe { pipefd.write_at_offset(1, write_fd).ok_or(Errno::EFAULT) }?;
                Ok(0)
            })
        }
        _ => {
            todo!()
        }
    };

    res.map_or_else(
        |e| {
            let e: i32 = e.as_neg();
            let Ok(e) = isize::try_from(e) else {
                // On both 32-bit and 64-bit, this should never be triggered
                unreachable!()
            };
            e
        },
        |val: usize| {
            let Ok(v) = isize::try_from(val) else {
                // Note in case where val is an address (e.g., returned from `mmap`), we currently
                // assume user space address does not exceed isize::MAX. On 64-bit, the max user
                // address is 0x7FFF_FFFF_F000, which is below this; for 32-bit, this may not hold,
                // and we might need to de-restrict this if ever seen in practice. For now, we are
                // keeping the stricter version.
                unreachable!("invalid user pointer");
            };
            v
        },
    )
}
