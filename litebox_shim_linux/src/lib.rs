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
        if fd >= (2 << 30) {
            return None;
        }
        let fd = fd as usize;
        self.descriptors.get_mut(fd)?.take()
    }
    fn remove_file(&mut self, fd: u32) -> Option<litebox::fd::FileFd> {
        if fd >= (2 << 30) {
            return None;
        }
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
        if fd >= (2 << 30) {
            return None;
        }
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
    fn get_file_fd(&self, fd: u32) -> Option<&litebox::fd::FileFd> {
        if fd >= (2 << 30) {
            return None;
        }
        match self.descriptors.get(fd as usize)?.as_ref()? {
            Descriptor::File(file_fd) => Some(file_fd),
            Descriptor::Socket(_) => None,
        }
    }
    fn get_file_fd_mut(&mut self, fd: u32) -> Option<&mut litebox::fd::FileFd> {
        if fd >= (2 << 30) {
            return None;
        }
        match self.descriptors.get_mut(fd as usize)?.as_mut()? {
            Descriptor::File(file_fd) => Some(file_fd),
            Descriptor::Socket(_) => None,
        }
    }
    fn get_socket_fd(&self, fd: u32) -> Option<&litebox::fd::SocketFd> {
        if fd >= (2 << 30) {
            return None;
        }
        match self.descriptors.get(fd as usize)?.as_ref()? {
            Descriptor::File(_) => None,
            Descriptor::Socket(socket_fd) => Some(socket_fd),
        }
    }
    fn get_socket_fd_mut(&mut self, fd: u32) -> Option<&mut litebox::fd::SocketFd> {
        if fd >= (2 << 30) {
            return None;
        }
        match self.descriptors.get_mut(fd as usize)?.as_mut()? {
            Descriptor::File(_) => None,
            Descriptor::Socket(socket_fd) => Some(socket_fd),
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
        Ok(fd) => fd,
        Err(err) => err.as_neg(),
    }
}

/// Closes the file
pub extern "C" fn close(fd: i32) -> i32 {
    syscalls::file::sys_close(fd).map_or_else(Errno::as_neg, |()| 0)
}

/// Entry point for the syscall handler
pub fn syscall_entry(request: SyscallRequest<Platform>) -> i64 {
    match request {
        SyscallRequest::Read { fd, buf, count } => {
            let Ok(count) = isize::try_from(count) else {
                return i64::from(Errno::EINVAL.as_neg());
            };
            buf.mutate_subslice_with(..count, |user_buf| {
                // TODO: use kernel buffer to avoid page faults
                syscalls::file::sys_read(fd, user_buf, None).map_or_else(
                    |e| i64::from(e.as_neg()),
                    #[allow(clippy::cast_possible_wrap)]
                    |size| size as i64,
                )
            })
            .unwrap_or(i64::from(Errno::EFAULT.as_neg()))
        }
        SyscallRequest::Close { fd } => {
            i64::from(syscalls::file::sys_close(fd).map_or_else(Errno::as_neg, |()| 0))
        }
        SyscallRequest::Pread64 {
            fd,
            buf,
            count,
            offset,
        } => {
            let Ok(count) = isize::try_from(count) else {
                return i64::from(Errno::EINVAL.as_neg());
            };
            buf.mutate_subslice_with(..count, |user_buf| {
                // TODO: use kernel buffer to avoid page faults
                syscalls::file::sys_pread64(fd, user_buf, offset).map_or_else(
                    |e| i64::from(e.as_neg()),
                    #[allow(clippy::cast_possible_wrap)]
                    |size| size as i64,
                )
            })
            .unwrap_or(i64::from(Errno::EFAULT.as_neg()))
        }
        SyscallRequest::Mmap {
            addr,
            length,
            prot,
            flags,
            fd,
            offset,
        } => {
            syscalls::mm::sys_mmap(addr, length, prot, flags, fd, offset).map_or_else(
                |e| i64::from(e.as_neg()),
                |ptr| {
                    let Ok(addr) = i64::try_from(ptr.as_usize()) else {
                        // Note it assumes user space address does not exceed i64::MAX (0x7FFF_FFFF_FFFF_FFFF).
                        // For Linux the max user address is 0x7FFF_FFFF_F000.
                        unreachable!("invalid user pointer");
                    };
                    addr
                },
            )
        }
        SyscallRequest::Openat {
            dirfd,
            pathname,
            flags,
            mode,
        } => {
            let Some(path) = pathname.to_cstring() else {
                return i64::from(Errno::EFAULT.as_neg());
            };
            i64::from(
                syscalls::file::sys_openat(dirfd, path, flags, mode).unwrap_or_else(Errno::as_neg),
            )
        }
        _ => {
            todo!()
        }
    }
}
