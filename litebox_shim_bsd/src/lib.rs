// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides a BSD/macOS-compatible ABI via LiteBox.
//!
//! This shim is designed for running static x86_64 Mach-O binaries on Linux.

#![no_std]

extern crate alloc;

use alloc::ffi::CString;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;
use litebox::LiteBox;
use litebox::mm::PageManager;
use litebox::mm::linux::PAGE_SIZE;
use litebox::platform::{
    RawConstPointer as _, RawMutPointer as _, StdioOutStream, StdioProvider as _, SystemTime as _,
    TimeProvider as _,
};
use litebox::shim::ContinueOperation;
use litebox_common_bsd::loader::{MachoParseError, MachoParsedFile};
use litebox_common_bsd::syscall_nr;
use litebox_common_linux::PtRegs;
use litebox_platform_multiplex::Platform;
use thiserror::Error;

pub mod loader;

#[cfg(target_arch = "x86_64")]
const LINUX_SYS_EXIT_GROUP: usize = 231;
#[cfg(target_arch = "x86_64")]
const LINUX_SYS_MMAP: usize = 9;
#[cfg(target_arch = "x86_64")]
const LINUX_SYS_MPROTECT: usize = 10;
#[cfg(target_arch = "x86_64")]
const LINUX_SYS_MUNMAP: usize = 11;
#[cfg(target_arch = "x86_64")]
const SYSCALL_ARG_MAGIC: usize = usize::from_le_bytes(*b"LITE BOX");
#[cfg(target_arch = "x86_64")]
const MMAP_FLAG_MAGIC: i32 = 1 << 31;

const MACOS_EIO: isize = 5;
const MACOS_EBADF: isize = 9;
const MACOS_ENOMEM: isize = 12;
const MACOS_EFAULT: isize = 14;
const MACOS_EINVAL: isize = 22;
const MACOS_ENOTTY: isize = 25;
const MACOS_ENOTSUP: isize = 45;
const MACOS_ENOENT: isize = 2;
const MACOS_ENOSYS: isize = 78;

const MACOS_F_GETFD: i32 = 1;
const MACOS_F_SETFD: i32 = 2;
const MACOS_F_GETFL: i32 = 3;
const MACOS_O_RDONLY: isize = 0;
const MACOS_O_WRONLY: isize = 1;

const MACOS_CLOCK_REALTIME: i32 = 0;
const MACOS_CLOCK_MONOTONIC: i32 = 6;

const MACOS_PROT_READ: i32 = 0x1;
const MACOS_PROT_WRITE: i32 = 0x2;
const MACOS_PROT_EXEC: i32 = 0x4;
const MACOS_MAP_SHARED: i32 = 0x0001;
const MACOS_MAP_PRIVATE: i32 = 0x0002;
const MACOS_MAP_FIXED: i32 = 0x0010;
const MACOS_MAP_ANON: i32 = 0x1000;

const LINUX_PROT_READ: i32 = 0x1;
const LINUX_PROT_WRITE: i32 = 0x2;
const LINUX_PROT_EXEC: i32 = 0x4;
const LINUX_MAP_SHARED: i32 = 0x01;
const LINUX_MAP_PRIVATE: i32 = 0x02;
const LINUX_MAP_FIXED: i32 = 0x10;
const LINUX_MAP_ANONYMOUS: i32 = 0x20;

/// Shim entry points for one guest task
pub struct BsdShimEntrypoints {
    task: Task,
    /// The task should not be moved once it's bound to a platform thread
    _not_send: core::marker::PhantomData<*const ()>,
}

impl litebox::shim::EnterShim for BsdShimEntrypoints {
    type ExecutionContext = PtRegs;

    fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
        if self
            .task
            .global
            .seccomp_enabled
            .compare_exchange(
                false,
                true,
                core::sync::atomic::Ordering::SeqCst,
                core::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
        {
            litebox_platform_multiplex::platform().enable_seccomp_based_syscall_interception();
        }

        // Set instruction pointer and stack pointer from loaded values
        ctx.rip = self.task.entry_point;
        ctx.rsp = self.task.stack_top;
        if let Some(main_entry) = self.task.dynamic_main_entry {
            ctx.rdi = main_entry;
            ctx.rsi = self.task.stack_top;
        }
        // Linux x86_64 user-mode selectors/flags.
        ctx.cs = 0x33;
        ctx.ss = 0x2b;
        ctx.eflags = 0x202;
        ContinueOperation::Resume
    }

    fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.task.handle_syscall(ctx)
    }

    fn exception(
        &self,
        _ctx: &mut PtRegs,
        info: &litebox::shim::ExceptionInfo,
    ) -> ContinueOperation {
        if info.kernel_mode && info.exception == litebox::shim::Exception::PAGE_FAULT {
            if unsafe {
                self.task
                    .global
                    .pm
                    .handle_page_fault(info.cr2, info.error_code.into())
            }
            .is_ok()
            {
                return ContinueOperation::Resume;
            }
        }
        ContinueOperation::Terminate
    }

    fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        ContinueOperation::Resume
    }
}

struct GlobalState {
    pm: PageManager<Platform, PAGE_SIZE>,
    seccomp_enabled: core::sync::atomic::AtomicBool,
    #[expect(dead_code, reason = "keeping for future use")]
    litebox: LiteBox<Platform>,
}

struct Task {
    global: Arc<GlobalState>,
    entry_point: usize,
    stack_top: usize,
    dynamic_main_entry: Option<usize>,
}

impl Task {
    fn handle_syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        // On x86_64 interception paths, syscall number is preserved in orig_rax.
        let nr = ctx.orig_rax as u64;

        match nr {
            syscall_nr::SYS_READ | syscall_nr::SYS_READ_NOCANCEL => {
                let fd = ctx.rdi as i32;
                let ptr = ctx.rsi;
                let count = ctx.rdx;
                ctx.rax = self.do_read(fd, ptr, count) as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_WRITE => {
                let fd = ctx.rdi as i32;
                let ptr = ctx.rsi;
                let count = ctx.rdx;
                let result = self.do_write(fd, ptr, count);
                ctx.rax = result as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_OPEN | syscall_nr::SYS_OPEN_NOCANCEL => {
                let path = ctx.rdi;
                let flags = ctx.rsi as i32;
                let mode = ctx.rdx as u32;
                ctx.rax = self.do_open(path, flags, mode) as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_CLOSE | syscall_nr::SYS_CLOSE_NOCANCEL => {
                let fd = ctx.rdi as i32;
                ctx.rax = self.do_close(fd) as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_FCNTL | syscall_nr::SYS_FCNTL_NOCANCEL => {
                let fd = ctx.rdi as i32;
                let cmd = ctx.rsi as i32;
                let arg = ctx.rdx;
                ctx.rax = self.do_fcntl(fd, cmd, arg) as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_IOCTL => {
                let fd = ctx.rdi as i32;
                let request = ctx.rsi;
                let arg = ctx.rdx;
                ctx.rax = self.do_ioctl(fd, request, arg) as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_GETPID => {
                ctx.rax = 1;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_ISSETUGID => {
                ctx.rax = 0;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_GETTIMEOFDAY => {
                let tv_ptr = ctx.rdi;
                ctx.rax = self.do_gettimeofday(tv_ptr) as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_CLOCK_GETTIME => {
                let clock_id = ctx.rdi as i32;
                let ts_ptr = ctx.rsi;
                ctx.rax = self.do_clock_gettime(clock_id, ts_ptr) as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_MMAP => {
                let addr = ctx.rdi;
                let len = ctx.rsi;
                let prot = ctx.rdx as i32;
                let flags = ctx.r10 as i32;
                let fd = ctx.r8 as i32;
                let pos = ctx.r9 as i64;
                ctx.rax = self.do_mmap(addr, len, prot, flags, fd, pos) as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_MPROTECT => {
                let addr = ctx.rdi;
                let len = ctx.rsi;
                let prot = ctx.rdx as i32;
                ctx.rax = self.do_mprotect(addr, len, prot) as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_MUNMAP => {
                let addr = ctx.rdi;
                let len = ctx.rsi;
                ctx.rax = self.do_munmap(addr, len) as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_CSOPS => {
                self.log_unsupported_syscall(nr, "csops is currently unsupported");
                ctx.rax = (-MACOS_ENOTSUP) as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_PREAD => {
                let fd = ctx.rdi as i32;
                let ptr = ctx.rsi;
                let count = ctx.rdx;
                let offset = ctx.r10 as i64;
                ctx.rax = self.do_pread(fd, ptr, count, offset) as usize;
                ContinueOperation::Resume
            }
            syscall_nr::SYS_EXIT => {
                #[cfg(target_arch = "x86_64")]
                {
                    // SAFETY: This intentionally terminates the current process using the host Linux
                    // syscall ABI. We provide the seccomp magic in the second argument so the
                    // platform filter allows this syscall.
                    unsafe {
                        terminate_process(ctx.rdi);
                    }
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    ContinueOperation::Terminate
                }
            }
            _ => {
                self.log_unknown_syscall(ctx, nr);
                ctx.rax = (-MACOS_ENOSYS) as usize;
                ContinueOperation::Resume
            }
        }
    }

    fn log_unknown_syscall(&self, ctx: &PtRegs, nr: u64) {
        let msg = format!(
            "litebox_shim_bsd: unimplemented macOS syscall 0x{nr:x} (rdi=0x{:x}, rsi=0x{:x}, rdx=0x{:x}, r10=0x{:x}, r8=0x{:x}, r9=0x{:x}, rip=0x{:x})\n",
            ctx.rdi, ctx.rsi, ctx.rdx, ctx.r10, ctx.r8, ctx.r9, ctx.rip
        );
        let _ =
            litebox_platform_multiplex::platform().write_to(StdioOutStream::Stderr, msg.as_bytes());
    }

    fn log_unsupported_syscall(&self, nr: u64, reason: &str) {
        let msg = format!("litebox_shim_bsd: syscall 0x{nr:x} unsupported: {reason}\n");
        let _ =
            litebox_platform_multiplex::platform().write_to(StdioOutStream::Stderr, msg.as_bytes());
    }

    fn do_read(&self, fd: i32, ptr: usize, count: usize) -> isize {
        if fd != 0 {
            return -MACOS_EBADF;
        }

        let mut host_buf = alloc::vec![0u8; count];
        let bytes_read = match litebox_platform_multiplex::platform().read_from_stdin(&mut host_buf)
        {
            Ok(n) => n,
            Err(litebox::platform::StdioReadError::Closed) => 0,
            Err(_) => return -MACOS_EIO,
        };

        self.write_guest_bytes(ptr, &host_buf[..bytes_read])
            .map(|_| bytes_read as isize)
            .unwrap_or(-MACOS_EFAULT)
    }

    fn do_write(&self, fd: i32, ptr: usize, count: usize) -> isize {
        // Only handle stdout (1) and stderr (2) for now
        if fd != 1 && fd != 2 {
            return -MACOS_EBADF;
        }

        let Ok(buf) = self.read_guest_bytes(ptr, count) else {
            return -MACOS_EFAULT;
        };

        // Write to platform stdout/stderr
        let platform = litebox_platform_multiplex::platform();
        let stream = if fd == 1 {
            StdioOutStream::Stdout
        } else {
            StdioOutStream::Stderr
        };

        match platform.write_to(stream, &buf) {
            Ok(n) => n as isize,
            Err(_) => -MACOS_EIO,
        }
    }

    fn do_open(&self, path_ptr: usize, _flags: i32, _mode: u32) -> isize {
        let path_ptr = <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<
            core::ffi::c_char,
        >::from_usize(path_ptr);
        let Some(path) = path_ptr.to_cstring() else {
            return -MACOS_EFAULT;
        };
        let Ok(path) = path.into_string() else {
            return -MACOS_EINVAL;
        };

        self.log_unsupported_syscall(
            syscall_nr::SYS_OPEN,
            &format!("open('{path}') is not implemented yet"),
        );
        -MACOS_ENOENT
    }

    fn do_close(&self, fd: i32) -> isize {
        if (0..=2).contains(&fd) {
            0
        } else {
            -MACOS_EBADF
        }
    }

    fn do_pread(&self, fd: i32, ptr: usize, count: usize, offset: i64) -> isize {
        if offset < 0 {
            return -MACOS_EINVAL;
        }
        if fd == 0 {
            return self.do_read(fd, ptr, count);
        }
        -MACOS_EBADF
    }

    fn do_fcntl(&self, fd: i32, cmd: i32, _arg: usize) -> isize {
        if !(0..=2).contains(&fd) {
            return -MACOS_EBADF;
        }
        match cmd {
            MACOS_F_GETFD | MACOS_F_SETFD => 0,
            MACOS_F_GETFL => {
                if fd == 0 {
                    MACOS_O_RDONLY
                } else {
                    MACOS_O_WRONLY
                }
            }
            _ => -MACOS_ENOTSUP,
        }
    }

    fn do_ioctl(&self, fd: i32, _request: usize, _arg: usize) -> isize {
        if !(0..=2).contains(&fd) {
            return -MACOS_EBADF;
        }
        -MACOS_ENOTTY
    }

    fn do_gettimeofday(&self, tv_ptr: usize) -> isize {
        if tv_ptr == 0 {
            return 0;
        }
        let now = realtime_duration_since_epoch();
        let secs = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        let usecs = now.subsec_micros() as i32;

        if self.write_i64(tv_ptr, secs).is_none()
            || self.write_i32(tv_ptr + 8, usecs).is_none()
            || self.write_i32(tv_ptr + 12, 0).is_none()
        {
            return -MACOS_EFAULT;
        }
        0
    }

    fn do_clock_gettime(&self, clock_id: i32, ts_ptr: usize) -> isize {
        if ts_ptr == 0 {
            return -MACOS_EFAULT;
        }

        let now = match clock_id {
            MACOS_CLOCK_REALTIME => realtime_duration_since_epoch(),
            MACOS_CLOCK_MONOTONIC => realtime_duration_since_epoch(),
            _ => return -MACOS_EINVAL,
        };

        let secs = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        let nanos = i64::from(now.subsec_nanos() as i32);
        if self.write_i64(ts_ptr, secs).is_none() || self.write_i64(ts_ptr + 8, nanos).is_none() {
            return -MACOS_EFAULT;
        }
        0
    }

    fn do_mmap(&self, addr: usize, len: usize, prot: i32, flags: i32, fd: i32, pos: i64) -> isize {
        if len == 0 {
            return -MACOS_EINVAL;
        }
        let Ok(linux_prot) = map_macos_prot_to_linux(prot) else {
            return -MACOS_EINVAL;
        };
        let Ok(mut linux_flags) = map_macos_mmap_flags_to_linux(flags) else {
            return -MACOS_EINVAL;
        };
        linux_flags |= MMAP_FLAG_MAGIC;

        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: This enters the host Linux syscall ABI and returns the kernel result as-is.
            let ret = unsafe {
                linux_syscall6(
                    LINUX_SYS_MMAP,
                    addr,
                    len,
                    linux_prot as usize,
                    linux_flags as usize,
                    fd as usize,
                    pos as usize,
                )
            };
            return map_linux_ret_to_macos_errno(ret);
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (addr, len, prot, flags, fd, pos);
            -MACOS_ENOSYS
        }
    }

    fn do_mprotect(&self, addr: usize, len: usize, prot: i32) -> isize {
        let Ok(linux_prot) = map_macos_prot_to_linux(prot) else {
            return -MACOS_EINVAL;
        };
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: This enters the host Linux syscall ABI and returns the kernel result as-is.
            let ret = unsafe {
                linux_syscall4(
                    LINUX_SYS_MPROTECT,
                    addr,
                    len,
                    linux_prot as usize,
                    SYSCALL_ARG_MAGIC,
                )
            };
            return map_linux_ret_to_macos_errno(ret);
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (addr, len, prot);
            -MACOS_ENOSYS
        }
    }

    fn do_munmap(&self, addr: usize, len: usize) -> isize {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: This enters the host Linux syscall ABI and returns the kernel result as-is.
            let ret = unsafe { linux_syscall3(LINUX_SYS_MUNMAP, addr, len, SYSCALL_ARG_MAGIC) };
            return map_linux_ret_to_macos_errno(ret);
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (addr, len);
            -MACOS_ENOSYS
        }
    }

    fn read_guest_bytes(&self, ptr: usize, count: usize) -> Result<Vec<u8>, ()> {
        let guest_ptr =
            <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<u8>::from_usize(
                ptr,
            );
        let mut out = alloc::vec![0u8; count];
        for (offset, dst) in out.iter_mut().enumerate() {
            *dst = guest_ptr.read_at_offset(offset as isize).ok_or(())?;
        }
        Ok(out)
    }

    fn write_guest_bytes(&self, ptr: usize, bytes: &[u8]) -> Result<(), ()> {
        let guest_ptr =
            <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>::from_usize(
                ptr,
            );
        for (offset, byte) in bytes.iter().copied().enumerate() {
            guest_ptr.write_at_offset(offset as isize, byte).ok_or(())?;
        }
        Ok(())
    }

    fn write_i32(&self, ptr: usize, value: i32) -> Option<()> {
        self.write_guest_bytes(ptr, &value.to_le_bytes()).ok()
    }

    fn write_i64(&self, ptr: usize, value: i64) -> Option<()> {
        self.write_guest_bytes(ptr, &value.to_le_bytes()).ok()
    }
}

fn realtime_duration_since_epoch() -> Duration {
    litebox_platform_multiplex::platform()
        .current_time()
        .duration_since(&<Platform as litebox::platform::TimeProvider>::SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

fn map_macos_prot_to_linux(prot: i32) -> Result<i32, ()> {
    let mut out = 0;
    let known = MACOS_PROT_READ | MACOS_PROT_WRITE | MACOS_PROT_EXEC;
    if prot & !known != 0 {
        return Err(());
    }
    if prot & MACOS_PROT_READ != 0 {
        out |= LINUX_PROT_READ;
    }
    if prot & MACOS_PROT_WRITE != 0 {
        out |= LINUX_PROT_WRITE;
    }
    if prot & MACOS_PROT_EXEC != 0 {
        out |= LINUX_PROT_EXEC;
    }
    Ok(out)
}

fn map_macos_mmap_flags_to_linux(flags: i32) -> Result<i32, ()> {
    let mut out = 0;
    let known = MACOS_MAP_SHARED | MACOS_MAP_PRIVATE | MACOS_MAP_FIXED | MACOS_MAP_ANON;
    if flags & !known != 0 {
        return Err(());
    }
    if flags & MACOS_MAP_SHARED != 0 {
        out |= LINUX_MAP_SHARED;
    }
    if flags & MACOS_MAP_PRIVATE != 0 {
        out |= LINUX_MAP_PRIVATE;
    }
    if flags & MACOS_MAP_FIXED != 0 {
        out |= LINUX_MAP_FIXED;
    }
    if flags & MACOS_MAP_ANON != 0 {
        out |= LINUX_MAP_ANONYMOUS;
    }
    Ok(out)
}

fn map_linux_ret_to_macos_errno(ret: isize) -> isize {
    if ret >= 0 {
        return ret;
    }
    let errno = -ret;
    if (1..=4095).contains(&errno) {
        match errno {
            9 => -MACOS_EBADF,
            12 => -MACOS_ENOMEM,
            14 => -MACOS_EFAULT,
            22 => -MACOS_EINVAL,
            _ => -errno,
        }
    } else {
        -MACOS_EINVAL
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn linux_syscall3(nr: usize, a0: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    // SAFETY: We call into Linux syscall ABI with provided register values.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
unsafe fn linux_syscall4(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    // SAFETY: We call into Linux syscall ABI with provided register values.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
unsafe fn linux_syscall6(
    nr: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> isize {
    let ret: isize;
    // SAFETY: We call into Linux syscall ABI with provided register values.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            in("r9") a5,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
unsafe fn terminate_process(status: usize) -> ! {
    // SAFETY: We invoke the Linux `exit_group` syscall directly and never return.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") LINUX_SYS_EXIT_GROUP,
            in("rdi") status,
            in("rsi") SYSCALL_ARG_MAGIC,
            options(noreturn)
        );
    }
}

/// The built shim, ready to load programs.
pub struct BsdShim(Arc<GlobalState>);

impl Clone for BsdShim {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// A loaded program ready to run.
pub struct LoadedProgram {
    /// The entry points for the shim.
    pub entrypoints: BsdShimEntrypoints,
}

/// Errors that can occur when loading a program.
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("Failed to parse Mach-O: {0}")]
    Parse(#[from] MachoParseError),
    #[error("Failed to load program: {0}")]
    Load(#[source] litebox::mm::linux::MappingError),
    #[error("Failed to create stack")]
    StackCreation,
    #[error("Dynamic runtime linker '{0}' was not provided")]
    MissingRuntimeLinker(String),
    #[error("Failed to parse dynamic runtime linker: {0}")]
    RuntimeLinkerParse(#[source] MachoParseError),
}

/// Runtime file resolver used to provide dyld and dylibs for dynamic Mach-O execution.
pub trait RuntimeFileResolver {
    /// Read a file by guest path.
    fn read_file(&self, path: &str) -> Option<&[u8]>;
}

struct EmptyRuntimeFileResolver;

impl RuntimeFileResolver for EmptyRuntimeFileResolver {
    fn read_file(&self, _path: &str) -> Option<&[u8]> {
        None
    }
}

impl BsdShim {
    /// Load a program from binary data.
    pub fn load_program(
        &self,
        binary_data: &[u8],
        argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<LoadedProgram, LoadError> {
        let resolver = EmptyRuntimeFileResolver;
        self.load_program_with_runtime_files(binary_data, argv, envp, &resolver)
    }

    /// Load a program from binary data, optionally resolving runtime files for dynamic images.
    pub fn load_program_with_runtime_files(
        &self,
        binary_data: &[u8],
        argv: Vec<CString>,
        envp: Vec<CString>,
        runtime_files: &dyn RuntimeFileResolver,
    ) -> Result<LoadedProgram, LoadError> {
        // Parse the Mach-O file
        let parsed = MachoParsedFile::parse(binary_data)?;

        // Create a mapper that uses PageManager
        let mut mapper = loader::PageManagerMapper::new(&self.0.pm);

        // Create a simple reader for the binary data
        let mut reader = loader::SliceReader::new(binary_data);

        // Load the binary
        let mapping_info = parsed.load(&mut reader, &mut mapper).map_err(|e| match e {
            litebox_common_bsd::loader::MachoLoadError::Map(e) => LoadError::Load(e),
            litebox_common_bsd::loader::MachoLoadError::Io(_) => LoadError::StackCreation,
            litebox_common_bsd::loader::MachoLoadError::InvalidSegment => LoadError::StackCreation,
        })?;

        for dylib in parsed.required_dylibs() {
            if runtime_files.read_file(dylib).is_none() {
                let msg = format!(
                    "litebox_shim_bsd: runtime bundle missing dylib '{}'\n",
                    dylib
                );
                let _ = litebox_platform_multiplex::platform()
                    .write_to(StdioOutStream::Stderr, msg.as_bytes());
            }
        }

        let mut dynamic_main_entry = None;
        let mut entry_point = mapping_info.entry_point;
        if let Some(runtime_linker_path) = parsed.runtime_linker_path() {
            if let Some(linker_data) = runtime_files.read_file(runtime_linker_path) {
                let linker_parsed =
                    MachoParsedFile::parse(linker_data).map_err(LoadError::RuntimeLinkerParse)?;
                let mut linker_reader = loader::SliceReader::new(linker_data);
                let linker_slide = 0x1_0000_0000usize;
                let linker_mapping = linker_parsed
                    .load_with_slide(&mut linker_reader, &mut mapper, linker_slide)
                    .map_err(|e| match e {
                        litebox_common_bsd::loader::MachoLoadError::Map(e) => LoadError::Load(e),
                        litebox_common_bsd::loader::MachoLoadError::Io(_) => {
                            LoadError::StackCreation
                        }
                        litebox_common_bsd::loader::MachoLoadError::InvalidSegment => {
                            LoadError::StackCreation
                        }
                    })?;
                dynamic_main_entry = Some(mapping_info.entry_point);
                entry_point = linker_mapping.entry_point;
            } else if !parsed.required_dylibs().is_empty() {
                let msg = format!(
                    "litebox_shim_bsd: runtime linker '{}' not provided; continuing with main entry\n",
                    runtime_linker_path
                );
                let _ = litebox_platform_multiplex::platform()
                    .write_to(StdioOutStream::Stderr, msg.as_bytes());
            }
        }

        // Create a stack
        let stack_size = 8 * 1024 * 1024; // 8 MB
        let stack_top = loader::create_stack(&self.0.pm, stack_size, &argv, &envp)
            .ok_or(LoadError::StackCreation)?;

        let task = Task {
            global: self.0.clone(),
            entry_point,
            stack_top,
            dynamic_main_entry,
        };

        let entrypoints = BsdShimEntrypoints {
            task,
            _not_send: core::marker::PhantomData,
        };

        Ok(LoadedProgram { entrypoints })
    }

    /// Get the global page manager.
    pub fn page_manager(&self) -> &PageManager<Platform, PAGE_SIZE> {
        &self.0.pm
    }
}

/// Builder for creating a [`BsdShim`].
pub struct BsdShimBuilder {
    litebox: LiteBox<Platform>,
}

impl Default for BsdShimBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BsdShimBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        let platform = litebox_platform_multiplex::platform();
        Self {
            litebox: LiteBox::new(platform),
        }
    }

    /// Build the shim.
    #[must_use]
    pub fn build(self) -> BsdShim {
        let global = Arc::new(GlobalState {
            pm: PageManager::new(&self.litebox),
            seccomp_enabled: core::sync::atomic::AtomicBool::new(false),
            litebox: self.litebox,
        });
        BsdShim(global)
    }
}
