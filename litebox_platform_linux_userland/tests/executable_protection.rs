// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

use core::sync::atomic::{AtomicBool, Ordering};
use litebox::platform::PageManagementProvider;
use litebox::platform::page_mgmt::{
    AllocationDirection, AllocationOptions, FixedAddressBehavior, MemoryRegionPermissions as Perm,
    PageReservation as _,
};
use litebox_platform_linux_userland::LinuxUserland;

/// Calls the C-ABI function at `entry` and returns its 32-bit result.
///
/// # Safety
///
/// `entry` must be executable code implementing `extern "C" fn() -> u32`.
unsafe fn call(entry: usize) -> u32 {
    let result: u32;
    // SAFETY: Forwarded caller contract; `clobber_abi("C")` covers the callee's clobbers,
    // including the link register written by `blr`.
    unsafe {
        core::arch::asm!(
            "blr {entry}",
            entry = in(reg) entry,
            lateout("x0") result,
            clobber_abi("C"),
        );
    }
    result
}

#[test]
fn cache_synchronization_preserves_live_execution() {
    const PAGE: usize = 4096;
    // A large range lengthens each cache synchronization, widening the window in which
    // revoking EXEC would fault the executor.
    const LEN: usize = 256 * PAGE;

    let platform = LinuxUserland::new();
    // SAFETY: this test owns the new mapping and does not replace existing pages.
    let reservation = unsafe {
        <LinuxUserland as PageManagementProvider<PAGE>>::reserve_and_commit_pages(
            platform,
            core::iter::empty,
            0..LEN,
            Perm::READ | Perm::WRITE,
            AllocationOptions::empty(),
            FixedAddressBehavior::Hint(AllocationDirection::TopDown),
        )
    }
    .unwrap();
    let range = reservation.range();
    let release = litebox::utils::defer(|| {
        // SAFETY: the executor has joined before this guard releases the owned mapping.
        unsafe {
            <LinuxUserland as PageManagementProvider<PAGE>>::release_pages(platform, range.clone())
        }
        .unwrap();
    });
    let entry = range.start + 128;
    // MOV w0, #42; RET. The executor has no TLS, syscall, or guest-stack dependencies.
    let instructions = [0x5280_0540u32, 0xd65f_03c0];
    // SAFETY: the newly owned mapping is writable and the destination is aligned.
    unsafe {
        core::ptr::copy_nonoverlapping(
            instructions.as_ptr(),
            entry as *mut u32,
            instructions.len(),
        );
        <LinuxUserland as PageManagementProvider<PAGE>>::protect_pages(
            platform,
            || core::iter::once(&reservation),
            range.start..range.start + PAGE,
            Perm::EXEC,
        )
        .unwrap();
        <LinuxUserland as PageManagementProvider<PAGE>>::protect_pages(
            platform,
            || core::iter::once(&reservation),
            range.start + PAGE..range.end,
            Perm::empty(),
        )
        .unwrap();
    }

    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let stop = &stop;
        let executor = scope.spawn(move || {
            // SAFETY: the mapping contains the function above and remains executable
            // and allocated until this thread joins. Permission changes retain EXEC.
            assert_eq!(unsafe { call(entry) }, 42);
            ready_tx.send(()).unwrap();
            while !stop.load(Ordering::Acquire) {
                // SAFETY: As above.
                assert_eq!(unsafe { call(entry) }, 42);
            }
        });
        let stop_executor = litebox::utils::defer(|| stop.store(true, Ordering::Release));
        ready_rx.recv().unwrap();

        let protect = |permissions| {
            // SAFETY: the reservation covers the range and only this thread changes permissions.
            unsafe {
                <LinuxUserland as PageManagementProvider<PAGE>>::protect_pages(
                    platform,
                    || core::iter::once(&reservation),
                    range.clone(),
                    permissions,
                )
            }
            .unwrap();
        };
        // Make live code and NX pages executable together, then toggle READ on live code.
        // Revoking EXEC at any point faults the executor and crashes this test.
        protect(Perm::EXEC);
        for _ in 0..16 {
            protect(Perm::READ | Perm::EXEC);
            protect(Perm::EXEC);
        }
        drop(stop_executor);
        executor.join().unwrap();
    });
    drop(release);
}
