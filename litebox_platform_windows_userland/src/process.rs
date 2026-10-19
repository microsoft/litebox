// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Experimental native Windows process operations.

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
