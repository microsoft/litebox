// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};

use litebox_platform_linux_userland::process_clone::{ProcessClone, clone_current_process};

static COW_MARKER: AtomicU32 = AtomicU32::new(1);

fn main() -> std::io::Result<()> {
    let mut pipe = [-1; 2];
    // SAFETY: `pipe` is writable storage for two new descriptors.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two new descriptors owned by this process.
    let read_pipe = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    // SAFETY: pipe2 returned two new descriptors owned by this process.
    let write_pipe = unsafe { OwnedFd::from_raw_fd(pipe[1]) };

    // SAFETY: This single-purpose probe has no application-created sibling threads at the clone
    // point, and the child immediately performs the bounded checks below before exiting.
    match unsafe { clone_current_process()? } {
        ProcessClone::Parent {
            process_id,
            process,
        } => {
            COW_MARKER.store(3, Ordering::SeqCst);
            drop(write_pipe);
            let mut result = 0u8;
            // SAFETY: `read_pipe` is valid and `result` is writable for one byte.
            if unsafe {
                libc::read(
                    read_pipe.as_raw_fd(),
                    (&raw mut result).cast(),
                    core::mem::size_of_val(&result),
                )
            } != 1
            {
                return Err(std::io::Error::last_os_error());
            }
            let mut ready = libc::pollfd {
                fd: process.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `ready` is a valid writable poll entry and the pidfd stays open.
            if unsafe { libc::poll(&raw mut ready, 1, 5_000) } != 1 {
                return Err(std::io::Error::last_os_error());
            }
            if process_id == 0 || result != 42 || COW_MARKER.load(Ordering::SeqCst) != 3 {
                return Err(std::io::Error::other(format!(
                    "clone probe failed: pid={process_id}, child={result}, parent_marker={}",
                    COW_MARKER.load(Ordering::SeqCst)
                )));
            }
            println!("native process clone probe passed");
            Ok(())
        }
        ProcessClone::Child => {
            drop(read_pipe);
            let allocation = vec![0x5au8; 4096];
            let thread_marker = std::thread::spawn(|| 7u32).join().unwrap_or_default();
            let passed = COW_MARKER.load(Ordering::SeqCst) == 1
                && allocation.iter().all(|byte| *byte == 0x5a)
                && thread_marker == 7;
            let result = if passed { 42u8 } else { 1u8 };
            // SAFETY: `write_pipe` is valid and `result` is readable for one byte.
            let _ = unsafe {
                libc::write(
                    write_pipe.as_raw_fd(),
                    (&raw const result).cast(),
                    core::mem::size_of_val(&result),
                )
            };
            // SAFETY: The cloned process must not run copied runtime destructors.
            unsafe { libc::_exit(i32::from(!passed)) }
        }
    }
}
