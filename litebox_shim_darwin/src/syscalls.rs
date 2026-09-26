// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The Darwin system calls this shim implements.
//!
//! On x86-64 a Darwin system call puts `class << 24 | number` in `rax` and its
//! arguments in `rdi`, `rsi`, `rdx`, `r10`, `r8` and `r9`. Only the BSD class
//! (2) is served. A call returns its result in `rax` with the carry flag clear,
//! or fails with the carry flag set and the `errno` in `rax`; there are no
//! negative return values as on Linux.
//!
//! Implemented, by BSD number: `exit` (1), `read` (3), `write` (4), `open` (5),
//! `close` (6), `getpid` (20), `getuid` (24), `geteuid` (25), `getppid` (39),
//! `getegid` (43), `getgid` (47), `munmap` (73), `mprotect` (74), `mmap` (197),
//! `lseek` (199), `issetugid` (327), the `_nocancel` variants of `read`,
//! `write`, `open` and `close` (396-399), and `getentropy` (500). Everything
//! else fails with `ENOSYS`.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use litebox::fd::TypedFd;
use litebox::fs::{Mode, OFlags, SeekWhence};
use litebox::mm::vmem::{CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, StdioOutStream};
use litebox::shim::ContinueOperation;
use litebox::utils::{ReinterpretSignedExt as _, TruncateExt as _};
use litebox_common_linux::PtRegs;

use crate::errno::Errno;
use crate::{ConstPtr, MutPtr, PAGE_SIZE, ShimFS, ShimPlatform, Task};

/// `rax` carries the call class in bits 24 and up.
const CLASS_SHIFT: usize = 24;
const CLASS_UNIX: usize = 2;
/// The carry flag in `rflags`.
const CARRY: usize = 1;

const SYS_EXIT: usize = 1;
const SYS_READ: usize = 3;
const SYS_WRITE: usize = 4;
const SYS_OPEN: usize = 5;
const SYS_CLOSE: usize = 6;
const SYS_GETPID: usize = 20;
const SYS_GETUID: usize = 24;
const SYS_GETEUID: usize = 25;
const SYS_GETPPID: usize = 39;
const SYS_GETEGID: usize = 43;
const SYS_GETGID: usize = 47;
const SYS_MUNMAP: usize = 73;
const SYS_MPROTECT: usize = 74;
const SYS_MMAP: usize = 197;
const SYS_LSEEK: usize = 199;
const SYS_ISSETUGID: usize = 327;
const SYS_READ_NOCANCEL: usize = 396;
const SYS_WRITE_NOCANCEL: usize = 397;
const SYS_OPEN_NOCANCEL: usize = 398;
const SYS_CLOSE_NOCANCEL: usize = 399;
const SYS_GETENTROPY: usize = 500;

/// The process identity the guest sees. It is the only process there is, and
/// its credentials are those of the first account macOS creates (uid 501 in
/// group `staff`, 20).
const GUEST_PID: usize = 1;
const GUEST_UID: usize = 501;
const GUEST_GID: usize = 20;

/// Longest path `open` accepts, including the NUL (`PATH_MAX`).
const PATH_MAX: usize = 1024;
/// Bytes moved by one `read` or `write`; larger requests complete partially,
/// which both calls allow.
const MAX_IO: usize = 1 << 20;
/// Descriptors a process may hold (`OPEN_MAX`).
const OPEN_MAX: i32 = 256;
/// `getentropy` refuses more than this many bytes.
const GETENTROPY_MAX: usize = 256;

// `open` flags.
const O_ACCMODE: u32 = 0x3;
const O_WRONLY: u32 = 0x1;
const O_RDWR: u32 = 0x2;
const O_NONBLOCK: u32 = 0x4;
const O_APPEND: u32 = 0x8;
const O_NOFOLLOW: u32 = 0x100;
const O_CREAT: u32 = 0x200;
const O_TRUNC: u32 = 0x400;
const O_EXCL: u32 = 0x800;
const O_DIRECTORY: u32 = 0x10_0000;
const O_CLOEXEC: u32 = 0x100_0000;

// `mmap` protections and flags.
const PROT_READ: u32 = 0x1;
const PROT_WRITE: u32 = 0x2;
const PROT_EXEC: u32 = 0x4;
const MAP_SHARED: u32 = 0x1;
const MAP_PRIVATE: u32 = 0x2;
const MAP_FIXED: u32 = 0x10;
const MAP_ANON: u32 = 0x1000;

/// One open descriptor.
pub(crate) enum Descriptor<FS: ShimFS> {
    Stdin,
    Stdout,
    Stderr,
    File(TypedFd<FS>),
}

/// The process's descriptor table.
pub(crate) struct FileTable<FS: ShimFS> {
    entries: BTreeMap<i32, Descriptor<FS>>,
}

impl<FS: ShimFS> FileTable<FS> {
    /// A table holding only the standard streams.
    pub(crate) fn new() -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(0, Descriptor::Stdin);
        entries.insert(1, Descriptor::Stdout);
        entries.insert(2, Descriptor::Stderr);
        Self { entries }
    }

    /// Store `descriptor` under the lowest free number, as `open` must.
    fn insert(&mut self, descriptor: Descriptor<FS>) -> Result<i32, Descriptor<FS>> {
        let Some(fd) = (0..OPEN_MAX).find(|fd| !self.entries.contains_key(fd)) else {
            return Err(descriptor);
        };
        self.entries.insert(fd, descriptor);
        Ok(fd)
    }
}

fn succeed(ctx: &mut PtRegs, value: usize) {
    ctx.rax = value;
    ctx.eflags &= !CARRY;
}

fn fail(ctx: &mut PtRegs, errno: Errno) {
    ctx.rax = usize::from(errno.0);
    ctx.eflags |= CARRY;
}

/// An `int` argument, which is the low 32 bits of its register.
fn int(register: usize) -> i32 {
    let low: u32 = register.trunc();
    low.reinterpret_as_signed()
}

/// A 32-bit flags argument.
fn flags(register: usize) -> u32 {
    register.trunc()
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn handle_syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        let raw = ctx.orig_rax;
        let (class, number) = (raw >> CLASS_SHIFT, raw & ((1 << CLASS_SHIFT) - 1));
        let args = [ctx.rdi, ctx.rsi, ctx.rdx, ctx.r10, ctx.r8, ctx.r9];
        if class != CLASS_UNIX {
            litebox_util_log::warn!(class, number; "unsupported Darwin system call class");
            fail(ctx, Errno::ENOSYS);
            return ContinueOperation::Resume;
        }
        let result = match number {
            SYS_EXIT => return self.exit(int(args[0])),
            SYS_READ | SYS_READ_NOCANCEL => self.sys_read(int(args[0]), args[1], args[2]),
            SYS_WRITE | SYS_WRITE_NOCANCEL => self.sys_write(int(args[0]), args[1], args[2]),
            SYS_OPEN | SYS_OPEN_NOCANCEL => self.sys_open(args[0], flags(args[1]), flags(args[2])),
            SYS_CLOSE | SYS_CLOSE_NOCANCEL => self.sys_close(int(args[0])),
            SYS_GETPID => Ok(GUEST_PID),
            SYS_GETUID | SYS_GETEUID => Ok(GUEST_UID),
            SYS_GETGID | SYS_GETEGID => Ok(GUEST_GID),
            // No parent process, and never set-id.
            SYS_GETPPID | SYS_ISSETUGID => Ok(0),
            SYS_MMAP => self.sys_mmap(
                args[0],
                args[1],
                flags(args[2]),
                flags(args[3]),
                int(args[4]),
                args[5],
            ),
            SYS_MUNMAP => self.sys_munmap(args[0], args[1]),
            SYS_MPROTECT => self.sys_mprotect(args[0], args[1], flags(args[2])),
            SYS_LSEEK => {
                self.sys_lseek(int(args[0]), args[1].reinterpret_as_signed(), int(args[2]))
            }
            SYS_GETENTROPY => self.sys_getentropy(args[0], args[1]),
            _ => {
                litebox_util_log::warn!(number; "unimplemented Darwin system call");
                Err(Errno::ENOSYS)
            }
        };
        match result {
            Ok(value) => succeed(ctx, value),
            Err(errno) => fail(ctx, errno),
        }
        ContinueOperation::Resume
    }

    fn sys_read(&self, fd: i32, buf: usize, count: usize) -> Result<usize, Errno> {
        let mut data = vec![0u8; count.min(MAX_IO)];
        let read = {
            let files = self.files.lock();
            match files.entries.get(&fd).ok_or(Errno::EBADF)? {
                Descriptor::Stdin => self
                    .global
                    .platform
                    .read_from_stdin(&mut data)
                    .map_err(|_| Errno::EIO)?,
                Descriptor::Stdout | Descriptor::Stderr => return Err(Errno::EBADF),
                Descriptor::File(file) => self.fs.read(file, &mut data, None)?,
            }
        };
        if read > 0 {
            MutPtr::<Platform, u8>::from_usize(buf)
                .copy_from_slice(0, &data[..read])
                .ok_or(Errno::EFAULT)?;
        }
        Ok(read)
    }

    fn sys_write(&self, fd: i32, buf: usize, count: usize) -> Result<usize, Errno> {
        let count = count.min(MAX_IO);
        let data = if count == 0 {
            alloc::boxed::Box::default()
        } else {
            ConstPtr::<Platform, u8>::from_usize(buf)
                .to_owned_slice(count)
                .ok_or(Errno::EFAULT)?
        };
        let files = self.files.lock();
        match files.entries.get(&fd).ok_or(Errno::EBADF)? {
            Descriptor::Stdin => Err(Errno::EBADF),
            Descriptor::Stdout => self.write_stdio(StdioOutStream::Stdout, &data),
            Descriptor::Stderr => self.write_stdio(StdioOutStream::Stderr, &data),
            Descriptor::File(file) => Ok(self.fs.write(file, &data, None)?),
        }
    }

    fn write_stdio(&self, stream: StdioOutStream, data: &[u8]) -> Result<usize, Errno> {
        self.global
            .platform
            .write_to(stream, data)
            .map_err(|_| Errno::EIO)
    }

    fn sys_open(&self, path: usize, open_flags: u32, mode: u32) -> Result<usize, Errno> {
        let path = read_path::<Platform>(path)?;
        let mut oflags = match open_flags & O_ACCMODE {
            O_WRONLY => OFlags::WRONLY,
            O_RDWR => OFlags::RDWR,
            0 => OFlags::RDONLY,
            _ => return Err(Errno::EINVAL),
        };
        for (darwin, flag) in [
            (O_NONBLOCK, OFlags::NONBLOCK),
            (O_APPEND, OFlags::APPEND),
            (O_NOFOLLOW, OFlags::NOFOLLOW),
            (O_CREAT, OFlags::CREAT),
            (O_TRUNC, OFlags::TRUNC),
            (O_EXCL, OFlags::EXCL),
            (O_DIRECTORY, OFlags::DIRECTORY),
            (O_CLOEXEC, OFlags::CLOEXEC),
        ] {
            if open_flags & darwin != 0 {
                oflags |= flag;
            }
        }
        let mode = Mode::from_bits_truncate(mode & 0o7777);
        let file = self.fs.open(path.as_str(), oflags, mode)?;
        let fd = self
            .files
            .lock()
            .insert(Descriptor::File(file))
            .map_err(|descriptor| {
                if let Descriptor::File(file) = descriptor {
                    let _ = self.fs.close(&file);
                }
                Errno::EMFILE
            })?;
        usize::try_from(fd).map_err(|_| Errno::EMFILE)
    }

    fn sys_close(&self, fd: i32) -> Result<usize, Errno> {
        let descriptor = self.files.lock().entries.remove(&fd).ok_or(Errno::EBADF)?;
        if let Descriptor::File(file) = descriptor {
            self.fs.close(&file)?;
        }
        Ok(0)
    }

    fn sys_lseek(&self, fd: i32, offset: isize, whence: i32) -> Result<usize, Errno> {
        let whence = match whence {
            0 => SeekWhence::RelativeToBeginning,
            1 => SeekWhence::RelativeToCurrentOffset,
            2 => SeekWhence::RelativeToEnd,
            _ => return Err(Errno::EINVAL),
        };
        let files = self.files.lock();
        match files.entries.get(&fd).ok_or(Errno::EBADF)? {
            Descriptor::File(file) => Ok(self.fs.seek(file, offset, whence)?),
            Descriptor::Stdin | Descriptor::Stdout | Descriptor::Stderr => Err(Errno::ESPIPE),
        }
    }

    fn sys_getentropy(&self, buf: usize, len: usize) -> Result<usize, Errno> {
        if len > GETENTROPY_MAX {
            return Err(Errno::EIO);
        }
        let mut bytes = [0u8; GETENTROPY_MAX];
        self.global.platform.fill_bytes_crng(&mut bytes[..len]);
        MutPtr::<Platform, u8>::from_usize(buf)
            .copy_from_slice(0, &bytes[..len])
            .ok_or(Errno::EFAULT)?;
        Ok(0)
    }

    fn sys_mmap(
        &self,
        address: usize,
        len: usize,
        prot: u32,
        map_flags: u32,
        fd: i32,
        offset: usize,
    ) -> Result<usize, Errno> {
        let length = len
            .checked_next_multiple_of(PAGE_SIZE)
            .and_then(NonZeroPageSize::new)
            .ok_or(Errno::EINVAL)?;
        if map_flags & (MAP_SHARED | MAP_PRIVATE) == 0 || !offset.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        let fixed = map_flags & MAP_FIXED != 0;
        if fixed && !address.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        // An anonymous mapping ignores `fd` (macOS reuses it as a VM tag). A file
        // mapping is filled with a private copy of the file's bytes; a shared one
        // would need the file's pages themselves.
        let file_bytes = if map_flags & MAP_ANON != 0 {
            None
        } else if map_flags & MAP_SHARED != 0 {
            return Err(Errno::ENOTSUP);
        } else {
            Some(self.read_for_mapping(fd, offset, length.as_usize())?)
        };
        let hint = NonZeroAddress::new(address).filter(|_| address.is_multiple_of(PAGE_SIZE));
        let placement = if fixed {
            CreatePagesFlags::FIXED_ADDR
        } else {
            CreatePagesFlags::empty()
        };
        // SAFETY: a `MAP_FIXED` request replaces whatever the guest had mapped
        // there, which is the call's contract; otherwise nothing is replaced.
        let mapped = unsafe {
            self.global
                .page_manager
                .create_writable_pages(hint, length, placement, |ptr| {
                    if let Some(bytes) = &file_bytes {
                        ptr.copy_from_slice(0, bytes)
                            .ok_or(MappingError::OutOfMemory)?;
                    }
                    Ok(0)
                })
        }
        .map_err(|_| Errno::ENOMEM)?
        .as_usize();
        if prot != PROT_READ | PROT_WRITE {
            self.set_protection(mapped, length.as_usize(), prot)?;
        }
        Ok(mapped)
    }

    /// Up to `len` bytes of the file behind `fd` from `offset`, zero-padded.
    fn read_for_mapping(&self, fd: i32, offset: usize, len: usize) -> Result<vec::Vec<u8>, Errno> {
        let files = self.files.lock();
        let Descriptor::File(file) = files.entries.get(&fd).ok_or(Errno::EBADF)? else {
            return Err(Errno::ENOTSUP);
        };
        let mut bytes = vec![0u8; len];
        let mut done = 0;
        while done < len {
            let read = self
                .fs
                .read(file, &mut bytes[done..], Some(offset + done))?;
            if read == 0 {
                break;
            }
            done += read;
        }
        Ok(bytes)
    }

    fn sys_munmap(&self, address: usize, len: usize) -> Result<usize, Errno> {
        let len = len
            .checked_next_multiple_of(PAGE_SIZE)
            .filter(|len| *len != 0)
            .ok_or(Errno::EINVAL)?;
        if !address.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        // SAFETY: the guest is giving up the range; nothing in the shim uses it.
        unsafe {
            self.global
                .page_manager
                .remove_pages(MutPtr::<Platform, u8>::from_usize(address), len)
        }
        .map_err(|_| Errno::EINVAL)?;
        Ok(0)
    }

    fn sys_mprotect(&self, address: usize, len: usize, prot: u32) -> Result<usize, Errno> {
        let len = len
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::EINVAL)?;
        if !address.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        if len != 0 {
            self.set_protection(address, len, prot)?;
        }
        Ok(0)
    }

    fn set_protection(&self, address: usize, len: usize, prot: u32) -> Result<(), Errno> {
        let page_manager = &self.global.page_manager;
        let ptr = MutPtr::<Platform, u8>::from_usize(address);
        // SAFETY: the guest owns the range and asked for the new protection.
        unsafe {
            match (
                prot & PROT_READ != 0,
                prot & PROT_WRITE != 0,
                prot & PROT_EXEC != 0,
            ) {
                (_, true, true) => page_manager.make_pages_rwx(ptr, len),
                (_, false, true) => page_manager.make_pages_executable(ptr, len),
                (_, true, false) => page_manager.make_pages_writable(ptr, len),
                (true, false, false) => page_manager.make_pages_readable(ptr, len),
                (false, false, false) => page_manager.make_pages_inaccessible(ptr, len),
            }
        }
        .map_err(|_| Errno::ENOMEM)
    }
}

/// Read a NUL-terminated path from guest memory.
fn read_path<Platform: ShimPlatform>(address: usize) -> Result<String, Errno> {
    let mut bytes = vec::Vec::new();
    loop {
        if bytes.len() == PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let offset = isize::try_from(bytes.len()).map_err(|_| Errno::EFAULT)?;
        let byte = ConstPtr::<Platform, u8>::from_usize(address)
            .read_at_offset(offset)
            .ok_or(Errno::EFAULT)?;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    String::from_utf8(bytes).map_err(|_| Errno::EINVAL)
}
