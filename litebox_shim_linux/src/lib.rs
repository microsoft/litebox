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
    sync::{RwLock, futex::FutexManager},
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _},
};
use litebox_common_linux::{SyscallRequest, errno::Errno};
use litebox_platform_multiplex::Platform;
use syscalls::net::sys_setsockopt;

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

type FileFd = litebox::fd::TypedFd<LinuxFS>;

static BOOT_TIME: once_cell::race::OnceBox<<Platform as litebox::platform::TimeProvider>::Instant> =
    once_cell::race::OnceBox::new();

/// Get the `Instant` representing the boot time of the platform.
///
/// # Panics
///
/// Panics if [`litebox()`] has not been invoked before this
pub(crate) fn boot_time() -> &'static <Platform as litebox::platform::TimeProvider>::Instant {
    BOOT_TIME
        .get()
        .expect("litebox() should have already been called before this point")
}

/// Get the global litebox object
pub fn litebox<'a>() -> &'a LiteBox<Platform> {
    static LITEBOX: OnceBox<LiteBox<Platform>> = OnceBox::new();
    LITEBOX.get_or_init(|| {
        use litebox::platform::TimeProvider as _;
        let platform = litebox_platform_multiplex::platform();
        let _ = BOOT_TIME.get_or_init(|| alloc::boxed::Box::new(platform.now()));
        alloc::boxed::Box::new(LiteBox::new(platform))
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
pub fn litebox_fs<'a>() -> &'a LinuxFS {
    FS.get().expect("fs has not yet been set")
}

/// Get the global page manager
pub fn litebox_page_manager<'a>() -> &'a PageManager<Platform, PAGE_SIZE> {
    static VMEM: OnceBox<PageManager<Platform, PAGE_SIZE>> = OnceBox::new();
    VMEM.get_or_init(|| alloc::boxed::Box::new(PageManager::new(litebox())))
}

pub(crate) fn litebox_net<'a>()
-> &'a litebox::sync::Mutex<Platform, litebox::net::Network<Platform>> {
    static NET: OnceBox<litebox::sync::Mutex<Platform, litebox::net::Network<Platform>>> =
        OnceBox::new();
    NET.get_or_init(|| {
        let net = litebox::net::Network::new(litebox());
        alloc::boxed::Box::new(litebox().sync().new_mutex(net))
    })
}

pub(crate) fn litebox_futex_manager<'a>() -> &'a FutexManager<Platform> {
    static FUTEX_MANAGER: OnceBox<FutexManager<Platform>> = OnceBox::new();
    FUTEX_MANAGER.get_or_init(|| {
        let futex_manager = FutexManager::new(litebox());
        alloc::boxed::Box::new(futex_manager)
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
    fn insert_at(&mut self, descriptor: Descriptor, idx: usize) -> Option<Descriptor> {
        if idx >= self.descriptors.len() {
            self.descriptors.resize_with(idx + 1, Default::default);
        }
        self.descriptors
            .get_mut(idx)
            .and_then(|v| v.replace(descriptor))
    }
    fn remove(&mut self, fd: u32) -> Option<Descriptor> {
        let fd = fd as usize;
        self.descriptors.get_mut(fd)?.take()
    }
    fn remove_file(&mut self, fd: u32) -> Option<FileFd> {
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
    fn remove_socket(&mut self, fd: u32) -> Option<alloc::sync::Arc<crate::syscalls::net::Socket>> {
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
    fn get_file_fd(&self, fd: u32) -> Option<&FileFd> {
        if let Descriptor::File(file_fd) = self.descriptors.get(fd as usize)?.as_ref()? {
            Some(file_fd)
        } else {
            None
        }
    }
    fn get_socket_fd(&self, fd: u32) -> Option<&crate::syscalls::net::Socket> {
        if let Descriptor::Socket(socket_fd) = self.descriptors.get(fd as usize)?.as_ref()? {
            Some(socket_fd)
        } else {
            None
        }
    }
    fn close_on_exec(&mut self) {
        self.descriptors.iter_mut().for_each(|slot| {
            if let Some(desc) = slot.take() {
                if desc
                    .get_file_descriptor_flags()
                    .contains(litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC)
                {
                    syscalls::file::do_close(desc);
                } else {
                    *slot = Some(desc);
                }
            }
        });
    }
}

enum Descriptor {
    File(FileFd),
    // Note we are using `Arc` here so that we can hold a reference to the socket
    // without holding a lock on the file descriptor (see `sys_accept` for an example).
    // TODO: this could be addressed by #120.
    Socket(alloc::sync::Arc<crate::syscalls::net::Socket>),
    PipeReader {
        consumer: alloc::sync::Arc<litebox::pipes::ReadEnd<Platform, u8>>,
        close_on_exec: core::sync::atomic::AtomicBool,
    },
    PipeWriter {
        producer: alloc::sync::Arc<litebox::pipes::WriteEnd<Platform, u8>>,
        close_on_exec: core::sync::atomic::AtomicBool,
    },
    Eventfd {
        file: alloc::sync::Arc<syscalls::eventfd::EventFile<Platform>>,
        close_on_exec: core::sync::atomic::AtomicBool,
    },
    // TODO: we may not need this once #31 and #68 are done.
    Stdio(stdio::StdioFile),
    Epoll {
        file: alloc::sync::Arc<syscalls::epoll::EpollFile>,
        close_on_exec: core::sync::atomic::AtomicBool,
    },
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
const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

/// A wrapper function around `sys_pread64` that copies data in chunks to avoid OOMing.
fn pread_with_user_buf(
    fd: i32,
    buf: MutPtr<u8>,
    count: usize,
    offset: i64,
) -> Result<usize, Errno> {
    let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
    let mut read_total = 0;
    while read_total < count {
        let to_read = (count - read_total).min(kernel_buf.len());
        match syscalls::file::sys_pread64(
            fd,
            &mut kernel_buf[..to_read],
            offset + (read_total.reinterpret_as_signed() as i64),
        ) {
            Ok(0) => break, // EOF
            Ok(size) => {
                buf.copy_from_slice(read_total, &kernel_buf[..size])
                    .ok_or(Errno::EFAULT)?;
                read_total += size;
            }
            Err(e) => return Err(e),
        }
    }
    assert!(read_total <= count);
    Ok(read_total)
}

/// Handle Linux syscalls and dispatch them to LiteBox implementations.
///
/// # Panics
///
/// Unsupported syscalls or arguments would trigger a panic for development purposes.
#[allow(clippy::too_many_lines)]
pub fn handle_syscall_request(request: SyscallRequest<Platform>) -> usize {
    let res: Result<usize, Errno> = match request {
        SyscallRequest::Ret(errno) => Err(errno),
        SyscallRequest::Exit { status } => syscalls::process::sys_exit(status),
        SyscallRequest::ExitGroup { status } => syscalls::process::sys_exit_group(status),
        SyscallRequest::Read { fd, buf, count } => {
            // Note some applications (e.g., `node`) seem to assume that getting fewer bytes than
            // requested indicates EOF.
            if count <= MAX_KERNEL_BUF_SIZE {
                let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
                syscalls::file::sys_read(fd, &mut kernel_buf, None).and_then(|size| {
                    buf.copy_from_slice(0, &kernel_buf[..size])
                        .map(|()| size)
                        .ok_or(Errno::EFAULT)
                })
            } else {
                // If the read size is too large, we need to do some extra work to avoid OOMing.
                // We read data in chunks and update the file offset ourselves only if the read succeeds.
                syscalls::file::sys_lseek(fd, 0, litebox::fs::SeekWhence::RelativeToCurrentOffset)
                    .inspect_err(|e| {
                        match *e {
                            Errno::EBADF => (), // safe errors to return
                            Errno::ESPIPE => {
                                unimplemented!("read on non-seekable fds with large buffers");
                            }
                            Errno::EINVAL => {
                                unreachable!("seekable file should not return EINVAL when getting current offset");
                            }
                            _ => {
                                unimplemented!("unexpected error from lseek: {}", e);
                            }
                        }
                    })
                    .and_then(|cur_loc| {
                        pread_with_user_buf(fd, buf, count, i64::try_from(cur_loc).unwrap())
                            .inspect(|read_total| {
                                // Update the file offset to reflect the read we just did.
                                syscalls::file::sys_lseek(
                                    fd,
                                    (cur_loc + read_total).reinterpret_as_signed(),
                                    litebox::fs::SeekWhence::RelativeToBeginning,
                                )
                                // Given that previous lseek and pread succeeded, this lseek should also succeed.
                                .expect("lseek failed");
                            })
                    })
            }
        }
        SyscallRequest::Write { fd, buf, count } => match unsafe { buf.to_cow_slice(count) } {
            Some(buf) => syscalls::file::sys_write(fd, &buf, None),
            None => Err(Errno::EFAULT),
        },
        SyscallRequest::Close { fd } => syscalls::file::sys_close(fd).map(|()| 0),
        SyscallRequest::Lseek { fd, offset, whence } => {
            let seekwhence = match whence {
                0 => litebox::fs::SeekWhence::RelativeToBeginning,
                1 => litebox::fs::SeekWhence::RelativeToCurrentOffset,
                2 => litebox::fs::SeekWhence::RelativeToEnd,
                _ => todo!("unsupported whence"),
            };
            syscalls::file::sys_lseek(fd, offset, seekwhence)
        }
        SyscallRequest::Mkdir { pathname, mode } => {
            pathname.to_cstring().map_or(Err(Errno::EINVAL), |path| {
                syscalls::file::sys_mkdir(path, mode).map(|()| 0)
            })
        }
        SyscallRequest::RtSigprocmask {
            how,
            set,
            oldset,
            sigsetsize,
        } => {
            if sigsetsize == size_of::<litebox_common_linux::SigSet>() {
                syscalls::process::sys_rt_sigprocmask(how, set, oldset).map(|()| 0)
            } else {
                Err(Errno::EINVAL)
            }
        }
        SyscallRequest::RtSigaction {
            signum,
            act,
            oldact,
            sigsetsize,
        } => {
            if sigsetsize == size_of::<litebox_common_linux::SigSet>() {
                syscalls::process::sys_rt_sigaction(signum, act, oldact).map(|()| 0)
            } else {
                Err(Errno::EINVAL)
            }
        }
        SyscallRequest::RtSigreturn { stack } => syscalls::process::sys_rt_sigreturn(stack),
        SyscallRequest::Ioctl { fd, arg } => syscalls::file::sys_ioctl(fd, arg).map(|v| v as usize),
        SyscallRequest::Pread64 {
            fd,
            buf,
            count,
            offset,
        } => pread_with_user_buf(fd, buf, count, offset),
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
        SyscallRequest::Mremap {
            old_addr,
            old_size,
            new_size,
            flags,
            new_addr,
        } => syscalls::mm::sys_mremap(old_addr, old_size, new_size, flags, new_addr)
            .map(|ptr| ptr.as_usize()),
        SyscallRequest::Munmap { addr, length } => {
            syscalls::mm::sys_munmap(addr, length).map(|()| 0)
        }
        SyscallRequest::Brk { addr } => syscalls::mm::sys_brk(addr),
        SyscallRequest::Readv { fd, iovec, iovcnt } => syscalls::file::sys_readv(fd, iovec, iovcnt),
        SyscallRequest::Writev { fd, iovec, iovcnt } => {
            syscalls::file::sys_writev(fd, iovec, iovcnt)
        }
        SyscallRequest::Access { pathname, mode } => {
            pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
                syscalls::file::sys_access(path, mode).map(|()| 0)
            })
        }
        SyscallRequest::Madvise {
            addr,
            length,
            behavior,
        } => syscalls::mm::sys_madvise(addr, length, behavior).map(|()| 0),
        SyscallRequest::Dup {
            oldfd,
            newfd,
            flags,
        } => syscalls::file::sys_dup(oldfd, newfd, flags).map(|newfd| newfd as usize),
        SyscallRequest::Socket {
            domain,
            ty,
            flags,
            protocol,
        } => syscalls::net::sys_socket(domain, ty, flags, protocol).map(|fd| fd as usize),
        SyscallRequest::Connect {
            sockfd,
            sockaddr,
            addrlen,
        } => syscalls::net::sys_connect(sockfd, sockaddr, addrlen).map(|()| 0),
        SyscallRequest::Accept {
            sockfd,
            addr,
            addrlen,
            flags,
        } => syscalls::net::sys_accept(sockfd, addr, addrlen, flags).map(|fd| fd as usize),
        SyscallRequest::Sendto {
            sockfd,
            buf,
            len,
            flags,
            addr,
            addrlen,
        } => syscalls::net::sys_sendto(sockfd, buf, len, flags, addr, addrlen),
        SyscallRequest::Recvfrom {
            sockfd,
            buf,
            len,
            flags,
            addr,
            addrlen,
        } => syscalls::net::sys_recvfrom(sockfd, buf, len, flags, addr, addrlen),
        SyscallRequest::Bind {
            sockfd,
            sockaddr,
            addrlen,
        } => syscalls::net::sys_bind(sockfd, sockaddr, addrlen).map(|()| 0),
        SyscallRequest::Listen { sockfd, backlog } => {
            syscalls::net::sys_listen(sockfd, backlog).map(|()| 0)
        }
        SyscallRequest::Setsockopt {
            sockfd,
            optname,
            optval,
            optlen,
        } => sys_setsockopt(sockfd, optname, optval, optlen).map(|()| 0),
        SyscallRequest::Uname { buf } => syscalls::misc::sys_uname(buf).map(|()| 0usize),
        SyscallRequest::Fcntl { fd, arg } => syscalls::file::sys_fcntl(fd, arg).map(|v| v as usize),
        SyscallRequest::Getcwd { buf, size: count } => {
            let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
            syscalls::file::sys_getcwd(&mut kernel_buf).and_then(|size| {
                buf.copy_from_slice(0, &kernel_buf[..size])
                    .map(|()| size)
                    .ok_or(Errno::EFAULT)
            })
        }
        SyscallRequest::EpollCtl {
            epfd,
            op,
            fd,
            event,
        } => syscalls::file::sys_epoll_ctl(epfd, op, fd, event).map(|()| 0),
        SyscallRequest::EpollCreate { flags } => {
            syscalls::file::sys_epoll_create(flags).map(|fd| fd as usize)
        }
        SyscallRequest::EpollPwait {
            epfd,
            events,
            maxevents,
            timeout,
            sigmask,
            sigsetsize,
        } => syscalls::file::sys_epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize),
        SyscallRequest::Prctl { args } => syscalls::process::sys_prctl(args),
        SyscallRequest::ArchPrctl { arg } => syscalls::process::sys_arch_prctl(arg).map(|()| 0),
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
        SyscallRequest::Gettimeofday { tv, tz } => {
            syscalls::process::sys_gettimeofday(tv, tz).map(|()| 0)
        }
        SyscallRequest::ClockGettime { clockid, tp } => {
            let clock_id =
                litebox_common_linux::ClockId::try_from(clockid).expect("invalid clockid");
            syscalls::process::sys_clock_gettime(clock_id).and_then(|t| {
                unsafe { tp.write_at_offset(0, t) }
                    .map(|()| 0)
                    .ok_or(Errno::EFAULT)
            })
        }
        SyscallRequest::ClockGetres { clockid, res } => {
            let clock_id =
                litebox_common_linux::ClockId::try_from(clockid).expect("invalid clockid");
            syscalls::process::sys_clock_getres(clock_id, res);
            Ok(0)
        }
        SyscallRequest::ClockNanosleep {
            clockid,
            flags,
            request,
            remain,
        } => {
            let clock_id =
                litebox_common_linux::ClockId::try_from(clockid).expect("invalid clockid");
            syscalls::process::sys_clock_nanosleep(clock_id, flags, request, remain).map(|()| 0)
        }
        SyscallRequest::Time { tloc } => syscalls::process::sys_time(tloc)
            .and_then(|second| usize::try_from(second).or(Err(Errno::EOVERFLOW))),
        SyscallRequest::Openat {
            dirfd,
            pathname,
            flags,
            mode,
        } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
            syscalls::file::sys_openat(dirfd, path, flags, mode).map(|fd| fd as usize)
        }),
        SyscallRequest::Ftruncate { fd, length } => {
            syscalls::file::sys_ftruncate(fd, length).map(|()| 0)
        }
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
        #[cfg(target_arch = "x86_64")]
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
        #[cfg(target_arch = "x86")]
        SyscallRequest::Fstatat64 {
            dirfd,
            pathname,
            buf,
            flags,
        } => pathname.to_cstring().map_or(Err(Errno::EFAULT), |path| {
            syscalls::file::sys_newfstatat(dirfd, path, flags).and_then(|stat| {
                unsafe { buf.write_at_offset(0, stat.into()) }
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
        SyscallRequest::Clone { args, ctx } => handle_clone_request(&args, ctx),
        SyscallRequest::Clone3 { args, ctx } => {
            if let Some(clone_args) = unsafe { args.read_at_offset(0) } {
                handle_clone_request(&clone_args, ctx)
            } else {
                Err(Errno::EFAULT)
            }
        }
        SyscallRequest::SetThreadArea { user_desc } => {
            syscalls::process::set_thread_area(user_desc).map(|()| 0)
        }
        SyscallRequest::SetTidAddress { tidptr } => {
            Ok(syscalls::process::sys_set_tid_address(tidptr).reinterpret_as_unsigned() as usize)
        }
        SyscallRequest::Gettid => {
            Ok(syscalls::process::sys_gettid().reinterpret_as_unsigned() as usize)
        }
        SyscallRequest::Getrlimit { resource, rlim } => {
            syscalls::process::sys_getrlimit(resource, rlim).map(|()| 0)
        }
        SyscallRequest::Setrlimit { resource, rlim } => {
            syscalls::process::sys_setrlimit(resource, rlim).map(|()| 0)
        }
        SyscallRequest::Prlimit {
            pid,
            resource,
            new_limit,
            old_limit,
        } => syscalls::process::sys_prlimit(pid, resource, new_limit, old_limit).map(|()| 0),
        SyscallRequest::SetRobustList { head } => {
            syscalls::process::sys_set_robust_list(head);
            Ok(0)
        }
        SyscallRequest::GetRobustList { pid, head, len } => {
            syscalls::process::sys_get_robust_list(pid, head)
                .and_then(|()| {
                    unsafe {
                        len.write_at_offset(
                            0,
                            size_of::<
                                litebox_common_linux::RobustListHead<
                                    litebox_platform_multiplex::Platform,
                                >,
                            >(),
                        )
                    }
                    .ok_or(Errno::EFAULT)
                })
                .map(|()| 0)
        }
        SyscallRequest::GetRandom { buf, count, flags } => {
            syscalls::misc::sys_getrandom(buf, count, flags)
        }
        SyscallRequest::Getpid => {
            Ok(syscalls::process::sys_getpid().reinterpret_as_unsigned() as usize)
        }
        SyscallRequest::Getppid => {
            Ok(syscalls::process::sys_getppid().reinterpret_as_unsigned() as usize)
        }
        SyscallRequest::Getuid => Ok(syscalls::process::sys_getuid()),
        SyscallRequest::Getgid => Ok(syscalls::process::sys_getgid()),
        SyscallRequest::Geteuid => Ok(syscalls::process::sys_geteuid()),
        SyscallRequest::Getegid => Ok(syscalls::process::sys_getegid()),
        SyscallRequest::Sysinfo { buf } => {
            let sysinfo = syscalls::misc::sys_sysinfo();
            unsafe { buf.write_at_offset(0, sysinfo) }
                .ok_or(Errno::EFAULT)
                .map(|()| 0)
        }
        SyscallRequest::CapGet { header, data } => {
            syscalls::misc::sys_capget(header, data).map(|()| 0)
        }
        SyscallRequest::GetDirent64 { fd, dirp, count } => {
            syscalls::file::sys_getdirent64(fd, dirp, count)
        }
        SyscallRequest::SchedGetAffinity { pid, len, mask } => {
            const BITS_PER_BYTE: usize = 8;
            let cpuset = syscalls::process::sys_sched_getaffinity(pid);
            if len * BITS_PER_BYTE < cpuset.len() || len & (core::mem::size_of::<usize>() - 1) != 0
            {
                Err(Errno::EINVAL)
            } else {
                let raw_bytes = cpuset.as_bytes();
                unsafe { mask.copy_from_slice(0, raw_bytes) }
                    .map(|()| raw_bytes.len())
                    .ok_or(Errno::EFAULT)
            }
        }
        SyscallRequest::Futex { args } => syscalls::process::sys_futex(args),
        SyscallRequest::Execve {
            pathname,
            argv,
            envp,
        } => syscalls::process::sys_execve(pathname, argv, envp).map(|()| unreachable!()),
        SyscallRequest::Umask { mask } => {
            let old_mask = syscalls::file::sys_umask(mask);
            Ok(old_mask.bits() as usize)
        }
        SyscallRequest::Alarm { seconds } => syscalls::process::sys_alarm(seconds),
        SyscallRequest::ThreadKill { tgid, tid, sig } => {
            litebox_common_linux::Signal::try_from(sig)
                .map_err(|_| Errno::EINVAL)
                .and_then(|sig| syscalls::process::sys_tgkill(tgid, tid, sig).map(|()| 0))
        }
        _ => {
            todo!()
        }
    };

    res.unwrap_or_else(|e| {
        let e: i32 = e.as_neg();
        let Ok(e) = isize::try_from(e) else {
            // On both 32-bit and 64-bit, this should never be triggered
            unreachable!()
        };
        e.reinterpret_as_unsigned()
    })
}

fn handle_clone_request(
    clone_args: &litebox_common_linux::CloneArgs,
    ctx: &litebox_common_linux::PtRegs,
) -> Result<usize, Errno> {
    if clone_args.cgroup != 0 {
        unimplemented!("Clone with cgroup is not supported");
    }
    if clone_args.set_tid != 0 {
        unimplemented!("Clone with set_tid is not supported");
    }
    if clone_args.exit_signal != 0 {
        unimplemented!("Clone with exit_signal is not supported");
    }
    let parent_tid = if clone_args.parent_tid == 0 {
        None
    } else {
        Some(MutPtr::from_usize(
            usize::try_from(clone_args.parent_tid).unwrap(),
        ))
    };
    let stack = if clone_args.stack == 0 {
        None
    } else {
        Some(MutPtr::from_usize(
            usize::try_from(clone_args.stack).unwrap(),
        ))
    };
    let child_tid = if clone_args.child_tid == 0 {
        None
    } else {
        Some(MutPtr::from_usize(
            usize::try_from(clone_args.child_tid).unwrap(),
        ))
    };
    let tls = if clone_args.tls != 0 {
        Some(MutPtr::from_usize(usize::try_from(clone_args.tls).unwrap()))
    } else {
        None
    };
    usize::try_from(clone_args.stack_size)
        .map_err(|_| Errno::EINVAL)
        .and_then(|stack_size| {
            syscalls::process::sys_clone(
                clone_args.flags,
                parent_tid,
                stack,
                stack_size,
                child_tid,
                tls,
                ctx,
                ctx.get_ip(),
            )
        })
}
