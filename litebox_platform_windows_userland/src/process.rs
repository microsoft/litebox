// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Experimental native Windows process operations.

use core::cell::Cell;
use core::convert::Infallible;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::null_mut;
use std::io::{Error, Result};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

use litebox::platform::{
    ForkError, ForkResult as ProviderForkResult, ProcessHandle, ProcessProvider,
};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{GetProcessId, ResumeThread, TerminateProcess};

/// A handle to a process created by [`ProcessProvider::fork_process`].
pub struct ClonedProcess {
    process: OwnedHandle,
    thread: OwnedHandle,
}

impl AsRawHandle for ClonedProcess {
    fn as_raw_handle(&self) -> RawHandle {
        self.process.as_raw_handle()
    }
}

impl<const ALIGN: usize> ProcessProvider for crate::WindowsUserland<ALIGN> {
    type ProcessHandle = ClonedProcess;
    type ProcessError = Error;

    unsafe fn fork_process()
    -> core::result::Result<ProviderForkResult<ClonedProcess>, ForkError<Error>> {
        // SAFETY: The caller guarantees quiescence and a clone-safe child bootstrap.
        match unsafe { fork_process() } {
            Ok(ForkResult::Parent { process, thread }) => {
                Ok(ProviderForkResult::Parent(ClonedProcess {
                    process,
                    thread,
                }))
            }
            Ok(ForkResult::Child) => Ok(ProviderForkResult::Child),
            Err(error)
                if matches!(
                    error.raw_os_error().map(i32::cast_unsigned),
                    Some(0xC000_0002 | 0xC000_00BB)
                ) =>
            {
                // STATUS_NOT_IMPLEMENTED and STATUS_NOT_SUPPORTED create no child.
                Err(ForkError::Unsupported)
            }
            Err(error) => Err(ForkError::Failed(error)),
        }
    }

    unsafe fn prepare_fork_child() -> Result<()> {
        // SAFETY: The caller is the sole cloned thread and never returns to the copied stack.
        unsafe { crate::reset_current_thread_after_process_clone() };
        Ok(())
    }
}

/// Terminates a process created by [`ProcessProvider::fork_process`] with `status`, without
/// running the C runtime or DLL teardown of state copied from its multithreaded parent.
///
/// # Safety
///
/// The caller must be a cloned child whose copied runtime must not be torn down.
pub unsafe fn exit_fork_child(status: i32) -> ! {
    // SAFETY: Terminating the current process through its pseudo-handle does not return.
    unsafe {
        TerminateProcess(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            status.cast_unsigned(),
        );
    }
    unreachable!("TerminateProcess on the current process returned")
}

thread_local! {
    static GUEST_STACK_BASE: Cell<usize> = const { Cell::new(0) };
}

pub(crate) fn record_guest_stack_base() {
    if GUEST_STACK_BASE.get() == 0 {
        let marker = 0u8;
        GUEST_STACK_BASE.set(core::ptr::from_ref(&marker).addr());
    }
}

/// Runs `f` at the stack depth where this thread first entered the guest, abandoning the
/// copied runtime frames so successive native fork generations do not deepen the stack.
/// If the thread has not entered the guest, runs `f` in place.
///
/// # Safety
///
/// The caller must be the sole thread of a newly cloned process. Nothing may subsequently use
/// the abandoned frames or any frame below the recorded guest-entry depth. The closure must own
/// everything it needs, since the abandoned stack memory will be reused.
pub unsafe fn rewind_stack_and_run<F: FnOnce() -> Infallible + 'static>(f: F) -> ! {
    let base = GUEST_STACK_BASE.get();
    if base == 0 {
        match f() {}
    }
    let f = Box::into_raw(Box::new(f)).cast::<()>();
    // SAFETY: The recorded address is within this thread's stack and the caller abandons the
    // frames below it. Align RSP and reserve the Windows x64 ABI's 32-byte shadow space before
    // calling the non-returning entry point with the owned closure in RCX.
    unsafe {
        core::arch::asm!(
            "mov rsp, {base}",
            "and rsp, -16",
            "sub rsp, 32",
            "call {entry}",
            "ud2",
            base = in(reg) base,
            entry = sym rewound_stack_entry::<F>,
            in("rcx") f,
            options(noreturn),
        )
    }
}

unsafe extern "C" fn rewound_stack_entry<F: FnOnce() -> Infallible>(f: *mut ()) -> ! {
    // SAFETY: `rewind_stack_and_run` passes the pointer returned by `Box::<F>::into_raw`.
    let f = unsafe { *Box::from_raw(f.cast::<F>()) };
    match f() {}
}

impl ProcessHandle for ClonedProcess {
    type Error = Error;

    fn process_id(&self) -> Result<u32> {
        // SAFETY: The handle is owned and refers to the cloned process.
        let process_id = unsafe { GetProcessId(self.process.as_raw_handle()) };
        if process_id == 0 {
            Err(Error::last_os_error())
        } else {
            Ok(process_id)
        }
    }

    fn resume(&self) -> Result<()> {
        // SAFETY: The handle owns the suspended initial thread of the clone.
        if unsafe { ResumeThread(self.thread.as_raw_handle()) } == u32::MAX {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn terminate(&self) -> Result<()> {
        // SAFETY: The handle is owned and refers to the cloned process.
        if unsafe { TerminateProcess(self.process.as_raw_handle(), 1) } == 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

const STATUS_SUCCESS: i32 = 0;
const STATUS_PROCESS_CLONED: i32 = 0x0000_0129;
const RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;

/// Result returned by [`fork_process`].
pub enum ForkResult {
    /// The original process receives handles for its suspended child.
    Parent {
        /// Cloned process.
        process: OwnedHandle,
        /// Cloned process's only thread.
        thread: OwnedHandle,
    },
    /// The cloned process resumes on the calling thread.
    Child,
}

#[repr(C)]
struct RtlUserProcessInformation {
    length: u32,
    process: HANDLE,
    thread: HANDLE,
    client_id: [usize; 2],
    image_information: [u64; 8],
}

const _: () = assert!(size_of::<RtlUserProcessInformation>() == 0x68);

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlCloneUserProcess(
        process_flags: u32,
        process_security_descriptor: *const c_void,
        thread_security_descriptor: *const c_void,
        debug_port: HANDLE,
        process_information: *mut RtlUserProcessInformation,
    ) -> i32;
}

/// Clones the calling process with copy-on-write memory, one suspended thread, and no inherited
/// handles.
///
/// The caller must ensure every other thread is quiescent and that the child immediately enters
/// a clone-safe bootstrap path. This uses an undocumented NT interface and can fail on Windows
/// versions whose behavior is incompatible with LiteBox.
///
/// The runtime synchronizes its loader, heap, and thread-pool state around the clone.
///
/// # Safety
///
/// The child inherits user-mode synchronization and runtime state without the threads that may
/// own it. Calling arbitrary code in the child before rebuilding that state can deadlock.
pub unsafe fn fork_process() -> Result<ForkResult> {
    let mut information = RtlUserProcessInformation {
        length: 0,
        process: null_mut(),
        thread: null_mut(),
        client_id: [0; 2],
        image_information: [0; 8],
    };
    // SAFETY: `information` has the x64 RTL_USER_PROCESS_INFORMATION layout and is writable.
    // Optional inputs are null. The runtime synchronizes its internal locks before cloning
    // and repairs them in the child; the caller guarantees a clone-safe bootstrap.
    let status = unsafe {
        RtlCloneUserProcess(
            RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            null_mut(),
            &raw mut information,
        )
    };
    match status {
        STATUS_SUCCESS => {
            if information.process.is_null() || information.thread.is_null() {
                return Err(Error::other("RtlCloneUserProcess returned null handles"));
            }
            // SAFETY: Successful process creation returned owned handles to the parent.
            let process = unsafe { OwnedHandle::from_raw_handle(information.process) };
            // SAFETY: Successful process creation returned owned handles to the parent.
            let thread = unsafe { OwnedHandle::from_raw_handle(information.thread) };
            Ok(ForkResult::Parent { process, thread })
        }
        STATUS_PROCESS_CLONED => Ok(ForkResult::Child),
        status => Err(Error::from_raw_os_error(status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

    fn in_forked_child(run: fn() -> !) {
        // SAFETY: RtlCloneUserProcess synchronizes native runtime state; the child only runs
        // the supplied bootstrap and exits without returning to the copied test harness.
        let clone = unsafe { fork_process() }.expect("failed to clone test process");
        match clone {
            ForkResult::Child => run(),
            ForkResult::Parent { process, thread } => {
                // SAFETY: The handles belong to this suspended child.
                assert_ne!(unsafe { ResumeThread(thread.as_raw_handle()) }, u32::MAX);
                // SAFETY: The owned process handle remains valid throughout the wait.
                let wait = unsafe { WaitForSingleObject(process.as_raw_handle(), 10_000) };
                if wait != WAIT_OBJECT_0 {
                    // SAFETY: The handle refers to the child created by this test.
                    unsafe { TerminateProcess(process.as_raw_handle(), 1) };
                    panic!("rewinding child did not exit: wait status {wait:#x}");
                }
                let mut status = 0;
                // SAFETY: The child handle is valid and `status` is writable.
                assert_ne!(
                    unsafe { GetExitCodeProcess(process.as_raw_handle(), &raw mut status) },
                    0
                );
                assert_eq!(status, 0, "rewinding child failed with status {status:#x}");
            }
        }
    }

    #[inline(never)]
    fn deeper(depth: usize, run: &mut dyn FnMut()) {
        let frame = core::hint::black_box([0u8; 1024]);
        if depth == 0 {
            run();
        } else {
            deeper(depth - 1, run);
        }
        core::hint::black_box(frame);
    }

    fn stack_address() -> usize {
        let marker = 0u8;
        core::hint::black_box(core::ptr::from_ref(&marker).addr())
    }

    #[test]
    fn clones_rewind_to_the_same_depth_in_every_generation() {
        in_forked_child(|| {
            record_guest_stack_base();
            let base = GUEST_STACK_BASE.get();
            let payload = String::from("owned bootstrap state");
            deeper(64, &mut || {
                let payload = payload.clone();
                // SAFETY: This is the clone's only thread, and all reused stack frames are
                // abandoned. The continuation owns its bootstrap state and never returns.
                unsafe {
                    rewind_stack_and_run(move || {
                        if !(base - 4096..base).contains(&stack_address()) {
                            exit_fork_child(1);
                        }
                        deeper(8, &mut || {
                            record_guest_stack_base();
                            deeper(64, &mut || {
                                let payload = payload.clone();
                                rewind_stack_and_run(move || {
                                    let rewound = (base - 4096..base).contains(&stack_address());
                                    let owned = payload == "owned bootstrap state";
                                    exit_fork_child(if rewound && owned { 0 } else { 2 })
                                })
                            });
                        });
                        unreachable!()
                    })
                }
            });
            unreachable!()
        });
    }

    #[test]
    fn rewind_without_guest_entry_runs_in_place() {
        in_forked_child(|| {
            // SAFETY: This is the clone's only thread and the continuation exits immediately.
            unsafe { rewind_stack_and_run(|| exit_fork_child(0)) }
        });
    }
}
