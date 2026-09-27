// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Opt-in native synchronization bridge for the pthread lifecycle experiment.
//! Guest and host still share libpthread globals, so they must use the same
//! kernel wait queues and native thread identities. This is not runtime isolation.

use anyhow::{Result, bail};
use litebox_common_macos::errno::Errno;
use litebox_shim_macos::{PthreadRuntime, PthreadSync};

/// libpthread's `pthread_s` TSD offset and `_PTHREAD_TSD_SLOT_MACH_THREAD_SELF`
/// byte offset in the macOS 26 layout.
const TSD_OFFSET: usize = 0xe0;
const MACH_THREAD_SELF_OFFSET: usize = 3 * size_of::<usize>();
// PTHREAD_SIZE passed to bsdthread_register by the supported macOS libpthread:
// its pthread/TSD structure fits in one 16 KiB allocation span. The pthread_t
// may start partway through a page, so the shim rounds both ends of the pin.
const PTHREAD_SIZE: usize = 16 * 1024;

/// Returns the host libpthread runtime after checking its layout on this thread.
pub(crate) fn runtime() -> Result<PthreadRuntime> {
    // SAFETY: dlsym only looks up a symbol.
    let thread_start = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"_pthread_start".as_ptr()) };
    if thread_start.is_null() {
        bail!("libpthread thread entrypoint unavailable");
    }
    let tsd: usize;
    // SAFETY: TPIDRRO_EL0 is readable at EL0 and holds this thread's TSD base.
    unsafe { core::arch::asm!("mrs {}, tpidrro_el0", out(reg) tsd, options(nomem, nostack)) };
    // SAFETY: these query the live calling thread.
    let (this, expected_port) = unsafe {
        let this = libc::pthread_self();
        (this as usize, libc::pthread_mach_thread_np(this) as usize)
    };
    if tsd != this + TSD_OFFSET {
        bail!("unsupported libpthread TSD layout");
    }
    // SAFETY: the slot lies in this live thread's TSD.
    let port = unsafe { *((tsd + MACH_THREAD_SELF_OFFSET) as *const usize) };
    if port != expected_port {
        bail!("unsupported libpthread Mach thread slot");
    }
    Ok(PthreadRuntime {
        thread_start: thread_start as usize,
        // This address is entered as guest code, never invoked on the host stack.
        process_exit: libc::exit as *const () as usize,
        tsd_offset: TSD_OFFSET,
        mach_thread_self_offset: MACH_THREAD_SELF_OFFSET,
        pthread_size: PTHREAD_SIZE,
        synchronize,
        current_thread_identity: || {
            let mut id = 0;
            // SAFETY: queries this live host thread.
            unsafe {
                libc::pthread_threadid_np(libc::pthread_self(), &raw mut id);
                (id, libc::pthread_mach_thread_np(libc::pthread_self()))
            }
        },
    })
}

unsafe extern "C" {
    fn __ulock_wait(
        operation: u32,
        address: *mut core::ffi::c_void,
        value: u64,
        timeout: u32,
    ) -> i32;
    fn __ulock_wake(operation: u32, address: *mut core::ffi::c_void, value: u64) -> i32;
    fn __ulock_wait2(
        operation: u32,
        address: *mut core::ffi::c_void,
        value: u64,
        timeout: u64,
        value2: u64,
    ) -> i32;
    fn __psynch_mutexwait(
        mutex: *mut core::ffi::c_void,
        mgen: u32,
        ugen: u32,
        tid: u64,
        flags: u32,
    ) -> u32;
    fn __psynch_mutexdrop(
        mutex: *mut core::ffi::c_void,
        mgen: u32,
        ugen: u32,
        tid: u64,
        flags: u32,
    ) -> u32;
}

pub(crate) fn synchronize(operation: PthreadSync) -> Result<usize, Errno> {
    const ULF_NO_ERRNO: u32 = 0x0100_0000;
    // SAFETY: XNU validates the addresses, and this runs on the clean host
    // stack with IN_GUEST cleared. No guest Rust references are constructed.
    unsafe {
        match operation {
            PthreadSync::UlockWait {
                operation,
                address,
                value,
                timeout,
            } => {
                let result = __ulock_wait(operation, address as *mut _, value, timeout);
                if result == -1 && operation & ULF_NO_ERRNO == 0 {
                    Err(last_error())
                } else {
                    Ok((result as isize).cast_unsigned())
                }
            }
            PthreadSync::UlockWait2 {
                operation,
                address,
                value,
                timeout,
                value2,
            } => {
                let result = __ulock_wait2(operation, address as *mut _, value, timeout, value2);
                if result == -1 && operation & ULF_NO_ERRNO == 0 {
                    Err(last_error())
                } else {
                    Ok((result as isize).cast_unsigned())
                }
            }
            PthreadSync::UlockWake {
                operation,
                address,
                value,
            } => {
                let result = __ulock_wake(operation, address as *mut _, value);
                if result == -1 && operation & ULF_NO_ERRNO == 0 {
                    Err(last_error())
                } else {
                    Ok((result as isize).cast_unsigned())
                }
            }
            PthreadSync::MutexWait {
                mutex,
                mgen,
                ugen,
                tid,
                flags,
            } => {
                let result = __psynch_mutexwait(mutex as *mut _, mgen, ugen, tid, flags);
                if result == u32::MAX {
                    Err(last_error())
                } else {
                    Ok(result as usize)
                }
            }
            PthreadSync::MutexDrop {
                mutex,
                mgen,
                ugen,
                tid,
                flags,
            } => {
                let result = __psynch_mutexdrop(mutex as *mut _, mgen, ugen, tid, flags);
                if result == u32::MAX {
                    Err(last_error())
                } else {
                    Ok(result as usize)
                }
            }
        }
    }
}

fn last_error() -> Errno {
    // SAFETY: host errno is live for this executing host thread.
    match unsafe { *libc::__error() } {
        libc::EFAULT => Errno::EFAULT,
        libc::EINVAL => Errno::EINVAL,
        libc::EINTR => Errno::EINTR,
        libc::ETIMEDOUT => Errno::ETIMEDOUT,
        libc::ENOENT => Errno::ENOENT,
        libc::ENOMEM => Errno::ENOMEM,
        libc::EBUSY => Errno::EBUSY,
        libc::EAGAIN => Errno::EAGAIN,
        libc::EPERM => Errno::EPERM,
        libc::ESRCH => Errno::ESRCH,
        libc::ENOTSUP => Errno::ENOTSUP,
        libc::EOWNERDEAD => Errno::EOWNERDEAD,
        _ => Errno::EIO,
    }
}
