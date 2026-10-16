// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Experimental native Windows process cloning.

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

/// Owned native child resources used by [`ProcessProvider`].
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

    unsafe fn prepare_forked_process() -> Result<()> {
        // SAFETY: The caller is the sole cloned thread and never returns to the copied stack.
        unsafe { crate::reset_current_thread_after_process_clone() };
        Ok(())
    }
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
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT: u32 = 0x0000_0100;
const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;

/// Result of cloning the calling process.
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
struct PsCreateInfo {
    size: usize,
    state: u32,
    padding: u32,
    data: [u8; 72],
}

const _: () = assert!(size_of::<PsCreateInfo>() == 0x58);

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateUserProcess(
        process_handle: *mut HANDLE,
        thread_handle: *mut HANDLE,
        process_desired_access: u32,
        thread_desired_access: u32,
        process_object_attributes: *const c_void,
        thread_object_attributes: *const c_void,
        process_flags: u32,
        thread_flags: u32,
        process_parameters: *const c_void,
        create_info: *mut PsCreateInfo,
        attribute_list: *const c_void,
    ) -> i32;
}

/// Clones the calling process with one suspended thread and no inherited handles.
///
/// The caller must ensure every other thread is quiescent and that the child immediately enters
/// a clone-safe bootstrap path. This uses an undocumented NT interface and can fail on Windows
/// versions whose behavior is incompatible with LiteBox.
///
/// # Safety
///
/// The child inherits user-mode synchronization and runtime state without the threads that may
/// own it. Calling arbitrary code in the child before rebuilding that state can deadlock.
pub unsafe fn fork_process() -> Result<ForkResult> {
    let mut process = null_mut();
    let mut thread = null_mut();
    let mut create_info = PsCreateInfo {
        size: size_of::<PsCreateInfo>(),
        state: 0,
        padding: 0,
        data: [0; 72],
    };
    // SAFETY: All output pointers refer to initialized writable storage, optional inputs are null,
    // and `create_info` has the x64 layout and size required by NtCreateUserProcess.
    let status = unsafe {
        NtCreateUserProcess(
            &raw mut process,
            &raw mut thread,
            MAXIMUM_ALLOWED,
            MAXIMUM_ALLOWED,
            null_mut(),
            null_mut(),
            PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT,
            THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
            null_mut(),
            &raw mut create_info,
            null_mut(),
        )
    };
    match status {
        STATUS_SUCCESS => {
            if process.is_null() || thread.is_null() {
                return Err(Error::other("NtCreateUserProcess returned null handles"));
            }
            // SAFETY: Successful process creation returned owned handles to the parent.
            let process = unsafe { OwnedHandle::from_raw_handle(process) };
            // SAFETY: Successful process creation returned owned handles to the parent.
            let thread = unsafe { OwnedHandle::from_raw_handle(thread) };
            Ok(ForkResult::Parent { process, thread })
        }
        STATUS_PROCESS_CLONED => Ok(ForkResult::Child),
        status => Err(Error::from_raw_os_error(status)),
    }
}
