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

use litebox::{fs::FileSystem as _, platform::RawConstPointer as _, sync::RwLock};
use litebox_common_linux::errno::Errno;
use litebox_platform_multiplex::Platform;

pub(crate) fn litebox_fs<'a>() -> &'a impl litebox::fs::FileSystem {
    static FS: OnceBox<litebox::fs::in_mem::FileSystem<Platform>> = OnceBox::new();
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
    match litebox_fs().open(
        path,
        litebox::fs::OFlags::from_bits(flags).unwrap(),
        litebox::fs::Mode::from_bits(mode).unwrap(),
    ) {
        Ok(fd) => file_descriptors()
            .write()
            .insert(Descriptor::File(fd))
            .try_into()
            .unwrap(),
        Err(err) => Errno::from(err).as_neg(),
    }
}

/// Closes the file
pub extern "C" fn close(fd: i32) -> i32 {
    let Ok(fd) = u32::try_from(fd) else {
        return Errno::EBADF.as_neg();
    };
    match file_descriptors().write().remove(fd) {
        Some(Descriptor::File(file_fd)) => match litebox_fs().close(file_fd) {
            Ok(()) => 0,
            Err(err) => Errno::from(err).as_neg(),
        },
        Some(Descriptor::Socket(socket_fd)) => todo!(),
        None => Errno::EBADF.as_neg(),
    }
}
