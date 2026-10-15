// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicU32, Ordering};

use litebox_platform_windows_userland::process_clone::{ProcessClone, clone_current_process};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, INFINITE, ResumeThread, WaitForSingleObject,
};

static COW_MARKER: AtomicU32 = AtomicU32::new(1);

fn main() -> std::io::Result<()> {
    // SAFETY: This single-purpose probe has no application-created sibling threads at the clone
    // point, and the child immediately performs the bounded checks below before exiting.
    match unsafe { clone_current_process()? } {
        ProcessClone::Parent { process, thread } => {
            COW_MARKER.store(3, Ordering::SeqCst);
            // SAFETY: `thread` is the suspended initial thread returned by process creation.
            if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: `process` remains valid for the duration of the wait.
            if unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) } == u32::MAX {
                return Err(std::io::Error::last_os_error());
            }
            let mut exit_code = 0;
            // SAFETY: `process` is signaled and `exit_code` is writable.
            if unsafe { GetExitCodeProcess(process.as_raw_handle(), &raw mut exit_code) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            if exit_code != 42 || COW_MARKER.load(Ordering::SeqCst) != 3 {
                return Err(std::io::Error::other(format!(
                    "clone probe failed: child={exit_code}, parent_marker={}",
                    COW_MARKER.load(Ordering::SeqCst)
                )));
            }
            println!("native process clone probe passed");
            Ok(())
        }
        ProcessClone::Child => {
            let allocation = vec![0x5au8; 4096];
            let thread_marker = std::thread::spawn(|| 7u32).join().unwrap_or_default();
            let passed = COW_MARKER.load(Ordering::SeqCst) == 1
                && allocation.iter().all(|byte| *byte == 0x5a)
                && thread_marker == 7;
            std::process::exit(if passed { 42 } else { 1 });
        }
    }
}
