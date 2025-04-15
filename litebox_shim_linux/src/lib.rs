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
    mm::{PageManager, linux::PAGE_SIZE},
    platform::{RawConstPointer as _, RawMutPointer as _},
    sync::RwLock,
};
use litebox_common_linux::{SyscallRequest, errno::Errno};
use litebox_platform_multiplex::Platform;

pub mod loader;
pub mod syscalls;

static FS: OnceBox<litebox::fs::in_mem::FileSystem<Platform>> = OnceBox::new();
/// Set the global file system
///
/// # Panics
///
/// Panics if this is called more than once or `litebox_fs` is called before this
#[cfg(feature = "unstable-testing")]
pub fn set_fs(fs: litebox::fs::in_mem::FileSystem<'static, Platform>) {
    FS.set(alloc::boxed::Box::new(fs))
        .map_err(|_| {})
        .expect("fs is already set");
}

/// Get the global file system
pub fn litebox_fs<'a>() -> &'a impl litebox::fs::FileSystem {
    FS.get_or_init(|| {
        alloc::boxed::Box::new(litebox::fs::in_mem::FileSystem::new(
            litebox_platform_multiplex::platform(),
        ))
    })
}

pub(crate) fn litebox_sync<'a>() -> &'a litebox::sync::Synchronization<'static, Platform> {
    static SYNC: OnceBox<litebox::sync::Synchronization<Platform>> = OnceBox::new();
    SYNC.get_or_init(|| {
        alloc::boxed::Box::new(litebox::sync::Synchronization::new(
            litebox_platform_multiplex::platform(),
        ))
    })
}

pub(crate) fn litebox_page_manager<'a>() -> &'a PageManager<'static, Platform, PAGE_SIZE> {
    static VMEM: OnceBox<PageManager<'static, Platform, PAGE_SIZE>> = OnceBox::new();
    VMEM.get_or_init(|| {
        let vmm = PageManager::new(litebox_platform_multiplex::platform());
        alloc::boxed::Box::new(vmm)
    })
}

// Convenience type aliases
type ConstPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer<T>;
type MutPtr<T> = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<T>;

struct Descriptors {
    descriptors: Vec<Option<Descriptor>>,
}

impl Descriptors {
    fn new() -> Self {
        // TODO: Add stdin/stdout/stderr
        Self {
            descriptors: vec![],
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
}

pub(crate) fn file_descriptors<'a>() -> &'a RwLock<'static, Platform, Descriptors> {
    static FILE_DESCRIPTORS: once_cell::race::OnceBox<RwLock<'_, Platform, Descriptors>> =
        once_cell::race::OnceBox::new();
    FILE_DESCRIPTORS
        .get_or_init(|| alloc::boxed::Box::new(litebox_sync().new_rwlock(Descriptors::new())))
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

/// Entry point for the syscall handler
#[allow(clippy::too_many_lines)]
pub fn syscall_entry(request: SyscallRequest<Platform>) -> i64 {
    let res: Result<usize, Errno> = match request {
        SyscallRequest::Read { fd, buf, count } => {
            isize::try_from(count)
                .map_err(|_| Errno::EINVAL)
                .and_then(|count| {
                    buf.mutate_subslice_with(..count, |user_buf| {
                        // TODO: use kernel buffer to avoid page faults
                        syscalls::file::sys_read(fd, user_buf, None)
                    })
                    .unwrap_or(Err(Errno::EFAULT))
                })
        }
        SyscallRequest::Write { fd, buf, count } => match unsafe { buf.to_cow_slice(count) } {
            Some(buf) => syscalls::file::sys_write(fd, &buf, None),
            None => Err(Errno::EFAULT),
        },
        SyscallRequest::Close { fd } => syscalls::file::sys_close(fd).map(|()| 0),
        SyscallRequest::Pread64 {
            fd,
            buf,
            count,
            offset,
        } => {
            isize::try_from(count)
                .map_err(|_| Errno::EINVAL)
                .and_then(|count| {
                    buf.mutate_subslice_with(..count, |user_buf| {
                        // TODO: use kernel buffer to avoid page faults
                        syscalls::file::sys_pread64(fd, user_buf, offset)
                    })
                    .unwrap_or(Err(Errno::EFAULT))
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
        SyscallRequest::Getcwd { buf, size } => {
            isize::try_from(size)
                .map_err(|_| Errno::EINVAL)
                .and_then(|size| {
                    buf.mutate_subslice_with(..size, |user_buf| {
                        // TODO: use kernel buffer to avoid page faults
                        syscalls::file::sys_getcwd(user_buf)
                    })
                    .unwrap_or(Err(Errno::EFAULT))
                })
        }
        SyscallRequest::Readlink {
            pathname,
            buf,
            bufsiz,
        } => {
            pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                let Ok(size) = isize::try_from(bufsiz) else {
                    return Err(Errno::EINVAL);
                };
                buf.mutate_subslice_with(..size, |user_buf| {
                    // TODO: use kernel buffer to avoid page faults
                    syscalls::file::sys_readlink(path, user_buf)
                })
                .unwrap_or(Err(Errno::EFAULT))
            })
        }
        SyscallRequest::Readlinkat {
            dirfd,
            pathname,
            buf,
            bufsiz,
        } => {
            pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                let Ok(size) = isize::try_from(bufsiz) else {
                    return Err(Errno::EINVAL);
                };
                buf.mutate_subslice_with(..size, |user_buf| {
                    // TODO: use kernel buffer to avoid page faults
                    syscalls::file::sys_readlinkat(dirfd, path, user_buf)
                })
                .unwrap_or(Err(Errno::EFAULT))
            })
        }
        SyscallRequest::Openat {
            dirfd,
            pathname,
            flags,
            mode,
        } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
            syscalls::file::sys_openat(dirfd, path, flags, mode).map(|fd| fd as usize)
        }),
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
        _ => {
            todo!()
        }
    };

    res.map_or_else(
        |e| i64::from(e.as_neg()),
        |val| {
            let Ok(v) = i64::try_from(val) else {
                // Note in case where val is an address (e.g., returned from `mmap`), it assumes
                // user space address does not exceed i64::MAX (0x7FFF_FFFF_FFFF_FFFF).
                // For Linux the max user address is 0x7FFF_FFFF_F000.
                unreachable!("invalid user pointer");
            };
            v
        },
    )
}
