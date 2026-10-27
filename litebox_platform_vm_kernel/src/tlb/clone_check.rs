// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Self-check (debug builds, as [`VmKernel::start_cpus`] starts the CPUs) of
//! the shootdown of [`VmKernel::clone_address_space`]: CPU 1 writes
//! increasing values to a page of the source while the boot CPU clones it,
//! and the clone's page must keep its value as CPU 1 writes on, which CPU 1
//! would change through a translation the shootdown left writable. CPU 1
//! writes in kernel mode, through a user pointer, in a run's `init`
//! ([`run_thread_ref`]): with `CR0.WP`, a write through the leaf the clone
//! made read-only faults, and the platform's page-fault handler copies the
//! page, as for a thread's access.
//!
//! The boot CPU owns both address spaces. It frees the child, which only it
//! uses, once done with it, and the source only once CPU 1, which uses the
//! source only after it claimed the check, reported, back in the kernel's
//! address space, or once it withdrew the check unclaimed.
//!
//! The waits for CPU 1 time out, as the host may not run it in time (e.g.,
//! when overloaded), which says nothing of the kernel: a timeout only warns
//! (e.g., that the check was skipped or is inconclusive). If CPU 1 has yet
//! to report, the source, which it may still use, is kept for good (see
//! [`finish`]).

use super::SHOOTDOWNS;
use crate::{
    AddressSpaceId, UserConstPtr, UserMutPtr, UserThreadState, VmKernel, cpu, run_thread_ref,
};
use alloc::{format, string::String, sync::Arc};
use core::cell::Cell;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64};
use core::time::Duration;
use litebox::mm::page::PageRange;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo};
use litebox_common_linux::{PAGE_SIZE, PtRegs, vmem::VmFlags, vmem::VmemPageFaultHandler as _};
use litebox_platform::time::{Instant as _, TimeProvider as _};
use x86_64::structures::idt::PageFaultErrorCode;

/// The index of the CPU that writes.
pub(crate) const WRITER: usize = 1;
/// The page it writes, read-write in the source, and private: a clone keeps
/// shared memory's leaves writable.
const PAGE: usize = crate::USER_ADDR_MIN;
/// How many values the boot CPU waits for CPU 1 to write before the clone,
/// and between its reads of the clone's page.
const WRITES: u64 = 1 << 10;
/// How long each wait may take: several times what the whole check takes on
/// an overloaded host (up to about 0.15 s), and short, as a CPU 1 that the
/// host runs too little delays the boot by up to four waits.
const TIMEOUT: Duration = Duration::from_millis(500);

// `Check::phase`: CPU 1 claims a pending check (running), then reports
// whether its writes all succeeded; the boot CPU may cancel a pending one.
const PENDING: u8 = 0;
const RUNNING: u8 = 1;
const DONE: u8 = 2;
const FAILED: u8 = 3;
const CANCELLED: u8 = 4;

/// What CPU 1 needs of the check, which owns nothing of the source.
pub(super) struct Check {
    source: AddressSpaceId,
    phase: AtomicU8,
    /// The value CPU 1 wrote last.
    progress: AtomicU64,
    stop: AtomicBool,
}

/// Before CPU 1 starts, once a CPU is to: the check, with its source
/// registered and the page populated, for [`finish`] to unregister; none if a
/// task's address space is current, which the check would leave.
pub(crate) fn prepare(platform: &VmKernel) {
    if platform.current_address_space() != AddressSpaceId::KERNEL {
        return;
    }
    let source = platform.create_address_space();
    let table = Arc::clone(&platform.page_table_manager.task_page_tables.read()[&source]);
    let page = PageRange::new(PAGE, PAGE + PAGE_SIZE).expect("an aligned page");
    // Safety: a user page, which the new table does not map yet.
    unsafe { table.map_pages(page, VmFlags::VM_READ | VmFlags::VM_WRITE, true) }
        .expect("a frame for the page");
    SHOOTDOWNS.clone_check.call_once(|| Check {
        source,
        phase: AtomicU8::new(PENDING),
        progress: AtomicU64::new(0),
        stop: AtomicBool::new(false),
    });
}

/// CPU 1's part, once online, before its entry: unless withdrawn, or given
/// up on (see [`finish`]), writes the source's page until stopped, then
/// reports.
///
/// # Panics
///
/// If a write failed, once reported, even if [`finish`] no longer waits for
/// the report.
pub(crate) fn write(platform: &'static VmKernel) {
    let Some(check) = SHOOTDOWNS.clone_check.get() else {
        return;
    };
    // Before the source is used: a withdrawn check's is freed.
    if check
        .phase
        .compare_exchange(PENDING, RUNNING, Acquire, Relaxed)
        .is_err()
    {
        return;
    }
    // Safety: in the kernel's address space, with no reference to user memory.
    if unsafe { platform.switch_address_space(check.source) }.is_err() {
        // Unregistered: the boot CPU gave up waiting for this one.
        return;
    }
    let writer = Writer {
        platform,
        check,
        failed: Cell::new(false),
    };
    let mut state = UserThreadState::default();
    // `init` ends the run, which never enters user mode.
    // Safety: the platform is set up, and this CPU is in no other run.
    let _ = unsafe { run_thread_ref(&writer, &mut PtRegs::default(), &mut state) };
    drop(state);
    // Safety: no reference to the source's memory outlives the run.
    unsafe { platform.page_table_manager.load_base() };
    let phase = if writer.failed.get() { FAILED } else { DONE };
    // Once this CPU left the source: the boot CPU may then free it.
    check.phase.store(phase, Release);
    // As in `finish`, which may have given up waiting for the report.
    assert_ne!(phase, FAILED, "clone check: a write of CPU 1 failed");
}

/// CPU 1's thread, which never enters user mode.
struct Writer {
    platform: &'static VmKernel,
    check: &'static Check,
    failed: Cell<bool>,
}

impl EnterShim for Writer {
    type ExecutionContext = PtRegs;

    /// Writes increasing values, each published once written, until stopped
    /// or a write fails, taking interrupts (so flush requests) between
    /// writes. Neither switches tables nor schedules.
    fn init(&self, _: &mut PtRegs) -> ContinueOperation {
        let page = UserMutPtr::<u64>::from_usize(PAGE);
        let mut value = 0;
        while !self.check.stop.load(Acquire) {
            value += 1;
            if page.write_at_offset(0, value).is_none() {
                self.failed.set(true);
                break;
            }
            self.check.progress.store(value, Release);
            cpu::relax();
        }
        ContinueOperation::Terminate
    }

    fn syscall(&self, _: &mut PtRegs) -> ContinueOperation {
        ContinueOperation::Terminate
    }

    /// Only a write's fault on the page, present (copy-on-write once
    /// cloned), which the platform's handler resolves; others fail the write.
    fn exception(&self, _: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
        let error = PageFaultErrorCode::PROTECTION_VIOLATION | PageFaultErrorCode::CAUSED_BY_WRITE;
        let flags = VmFlags::VM_READ | VmFlags::VM_WRITE;
        let expected = info.kernel_mode
            && info.exception == Exception::PAGE_FAULT
            && info.cr2 == PAGE
            && u64::from(info.error_code) == error.bits();
        // Safety: this CPU's page-fault handler, for a write that the page's
        // mapping (`flags`) allows. Serialized with the page's other faults,
        // changes and copies: only this CPU faults on the source, and its one
        // clone copied the page's leaf, making it copy-on-write, before this
        // write could fault on it.
        if expected && unsafe { self.platform.handle_page_fault(PAGE, flags, error.bits()) }.is_ok()
        {
            ContinueOperation::Resume
        } else {
            ContinueOperation::Terminate
        }
    }

    fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
        ContinueOperation::Terminate
    }
}

/// After the other CPUs started, if [`prepare`]d: the check, unless CPU 1 is
/// not online, then the address spaces unregistered. A wait for CPU 1 that
/// times out only warns; if it is for CPU 1 to stop, the source, which CPU 1
/// may still use, is kept for good, though unregistered.
///
/// # Panics
///
/// If the check fails: the clone's page changed, or a write (if reported in
/// time), a read, or the clone failed; once the address spaces are
/// unregistered.
pub(crate) fn finish(platform: &VmKernel) {
    let Some(check) = SHOOTDOWNS.clone_check.get() else {
        return;
    };
    let source = check.source;
    let phase = || check.phase.load(Acquire);
    let online = cpu::online_mask() & (1 << WRITER) != 0;
    // Online, CPU 1 claims it at once; else withdrawn, unless claimed since.
    let claimed = (online && wait(platform, || phase() != PENDING))
        || check
            .phase
            .compare_exchange(PENDING, CANCELLED, Relaxed, Relaxed)
            .is_err();
    let mut child = None;
    let seen = claimed.then(|| observe(platform, check, &mut child));
    check.stop.store(true, Release);
    // Never freed while CPU 1 may still use the source.
    if claimed && !wait(platform, || matches!(phase(), DONE | FAILED)) {
        litebox_util_log::warn!(
            timeout:? = TIMEOUT;
            "clone check: CPU 1 did not stop in time; keeping the source address space for good"
        );
        // Kept, also so that no other address space takes its ID: CPU 1's
        // late switch then fails (see `write`).
        core::mem::forget(Arc::clone(
            &platform.page_table_manager.task_page_tables.read()[&source],
        ));
    }
    // Unregistered even if kept: leak checks count the registered ones (see
    // `VmKernel::address_space_count`).
    for id in child.into_iter().chain([source]) {
        // Safety: no CPU uses them, or the source is never destroyed (above):
        // CPU 1 left the source before it reported, or never used it, and
        // this CPU left the child (see `observe`).
        unsafe { platform.unregister_address_space(id) }.expect("registered");
    }
    let Some(seen) = seen else {
        if online {
            litebox_util_log::warn!(
                timeout:? = TIMEOUT;
                "clone check skipped: CPU 1 did not claim it in time"
            );
        } else {
            litebox_util_log::info!("clone check skipped: CPU 1 is not online");
        }
        return;
    };
    assert_ne!(phase(), FAILED, "clone check: a write of CPU 1 failed");
    match seen.unwrap_or_else(|why| panic!("clone check: {why}")) {
        Seen::Kept { value, last } => {
            litebox_util_log::info!(value:% = value, writes:% = last; "clone check passed");
        }
        Seen::Inconclusive(why) => {
            litebox_util_log::warn!(why:% = why, timeout:? = TIMEOUT; "clone check inconclusive");
        }
    }
}

/// What [`observe`] saw, but for a failure.
enum Seen {
    /// The clone's page kept `value` as CPU 1 wrote on, to `last`.
    Kept { value: u64, last: u64 },
    /// CPU 1 wrote too few values in time to tell: how many.
    Inconclusive(String),
}

/// Clones the source into `child` once CPU 1 wrote a while, then reads the
/// clone's page twice, the second time once CPU 1 wrote many values more.
/// Returns in the kernel's address space.
fn observe(
    platform: &VmKernel,
    check: &Check,
    child: &mut Option<AddressSpaceId>,
) -> Result<Seen, String> {
    let progress = || check.progress.load(Acquire);
    if !wait(platform, || progress() >= WRITES) {
        return Ok(Seen::Inconclusive(format!(
            "CPU 1 wrote {} values before the clone, not {WRITES}",
            progress()
        )));
    }
    let clone = platform
        .clone_address_space(check.source)
        .map_err(|e| format!("cloning failed: {e:?}"))?;
    *child = Some(clone);
    // Safety: in the kernel's address space, with no reference to user memory.
    unsafe { platform.switch_address_space(clone) }.expect("registered");
    let page = UserConstPtr::<u64>::from_usize(PAGE);
    let before = page.read_at_offset(0);
    let first = progress();
    // Many: CPU 1 may have written `first + 1` before the first read.
    let wrote = wait(platform, || progress() >= first + WRITES);
    let after = page.read_at_offset(0);
    let last = progress();
    // Safety: no reference to the clone's memory outlives the reads.
    unsafe { platform.page_table_manager.load_base() };
    match before {
        Some(value) if after == before && wrote => Ok(Seen::Kept { value, last }),
        Some(_) if after == before => Ok(Seen::Inconclusive(format!(
            "CPU 1 wrote {first} to {last} after the clone, not {WRITES} values"
        ))),
        _ => Err(format!(
            "the clone's page read {before:?}, then {after:?}, as CPU 1 wrote {first} to {last}"
        )),
    }
}

/// Spins until `done`, taking interrupts, for at most [`TIMEOUT`]: whether
/// done.
fn wait(platform: &VmKernel, done: impl Fn() -> bool) -> bool {
    let deadline = platform
        .now()
        .checked_add(TIMEOUT)
        .expect("the clock is far from overflowing");
    while !done() {
        if platform.now() >= deadline {
            return done();
        }
        cpu::relax();
    }
    true
}
