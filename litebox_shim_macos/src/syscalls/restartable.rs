// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Restartable ranges (`osfmk/kern/restartable.c`): a task registers code
//! ranges once, while it has one thread, and
//! `task_restartable_ranges_synchronize` makes every other thread whose PC
//! is strictly inside a range resume at that range's recovery address
//! before it runs more guest code (`AST_RESET_PCS`).
//!
//! The synchronizer marks every sibling, interrupts those running guest
//! code, and waits until each of them has left the guest (its IPI
//! acknowledgement) or terminated. A marked thread resets its PC when it
//! next returns to the guest, so one blocked in a syscall needs no wait.

use super::mig::RestartableRange;
use crate::{ShimPlatform, Task};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use litebox::event::wait::Waker;
use litebox_common_macos::KernReturn;

/// A task's restartable ranges and its synchronize call in flight.
pub(crate) struct RestartableRanges<P: ShimPlatform> {
    /// Sorted and non-overlapping; set once, while the task has one thread.
    ranges: Option<Vec<RestartableRange>>,
    /// The thread in `task_restartable_ranges_synchronize`
    /// (`task_rr_in_flight`), woken by each acknowledgement.
    synchronizer: Option<Waker<P>>,
}

impl<P: ShimPlatform> Default for RestartableRanges<P> {
    fn default() -> Self {
        Self {
            ranges: None,
            synchronizer: None,
        }
    }
}

impl<P: ShimPlatform> RestartableRanges<P> {
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn synchronizer_is_waiting(&self) -> bool {
        self.synchronizer.is_some()
    }
}

/// `_ranges_lookup`: the recovery address for a PC strictly inside a range.
fn recovery_address(ranges: &[RestartableRange], pc: u64) -> Option<u64> {
    let index = ranges.partition_point(|range| range.location < pc);
    let range = ranges.get(index.checked_sub(1)?)?;
    (pc < range.location + u64::from(range.length))
        .then(|| range.location + u64::from(range.recovery_offset))
}

impl<P: ShimPlatform> Task<P> {
    /// `task_restartable_ranges_register` with validated, sorted `ranges`.
    pub(crate) fn register_restartable_ranges(&self, ranges: Vec<RestartableRange>) -> KernReturn {
        // Only this thread can create another, so the count cannot change
        // before the ranges are set.
        if self.process.0.threads.lock().len() > 1 {
            return KernReturn::NOT_SUPPORTED;
        }
        let mut state = self.global.restartable_ranges.lock();
        if state.ranges.is_some() {
            // Release kernels allow one registration per task.
            return KernReturn::NOT_SUPPORTED;
        }
        state.ranges = Some(ranges);
        self.global
            .restartable_ranges_registered
            .store(true, Ordering::Relaxed);
        KernReturn::SUCCESS
    }

    /// `task_restartable_ranges_synchronize`.
    pub(crate) fn synchronize_restartable_ranges(&self) -> KernReturn {
        {
            let mut state = self.global.restartable_ranges.lock();
            if state.ranges.is_none() {
                return KernReturn::SUCCESS;
            }
            if state.synchronizer.is_some() {
                return KernReturn::ALREADY_WAITING;
            }
            state.synchronizer = Some(self.wait_cx().waker().clone());
        }
        let mut waited = Vec::new();
        for thread in self.sibling_threads() {
            thread.reset_pcs.store(true, Ordering::SeqCst);
            // Set before the interrupt's fence, so the thread sees it at the
            // shim entry the interrupt causes.
            thread.reset_pcs_ack.store(true, Ordering::SeqCst);
            let in_guest = thread
                .interrupt
                .lock()
                .as_ref()
                .is_some_and(litebox::event::wait::ThreadHandle::interrupt_guest);
            if in_guest {
                waited.push(thread);
            } else {
                thread.reset_pcs_ack.store(false, Ordering::Relaxed);
            }
        }
        // Process exit is the only interruption: the wait does not consume
        // a pending safe abort, which the thread's next abort-safe wait or
        // return to the guest still sees.
        let exiting = ExitOnly(self);
        let result = self
            .thread
            .wait_state
            .context()
            .with_check_for_interrupt(&exiting)
            .wait_until(|| {
                waited
                    .iter()
                    .all(|thread| !thread.reset_pcs_ack.load(Ordering::Acquire))
            });
        self.global.restartable_ranges.lock().synchronizer = None;
        match result {
            Ok(()) => KernReturn::SUCCESS,
            // The process is exiting; this thread never returns to the guest.
            Err(_) => KernReturn::ABORTED,
        }
    }

    /// The thread left the guest, or terminated: acknowledge a pending
    /// synchronize interrupt (`thread_reset_pcs_ack_IPI`).
    pub(crate) fn acknowledge_reset_pcs(&self) {
        if !self
            .global
            .restartable_ranges_registered
            .load(Ordering::Relaxed)
        {
            return;
        }
        // The thread's RUNNING_IN_HOST store is ordered before this read,
        // which pairs with the synchronizer's fence in `interrupt_guest`:
        // either it sees the request or the synchronizer sees the thread out
        // of the guest and does not wait.
        core::sync::atomic::fence(Ordering::SeqCst);
        let guest = &self.thread.guest;
        if guest.reset_pcs_ack.load(Ordering::Relaxed)
            && guest.reset_pcs_ack.swap(false, Ordering::AcqRel)
            && let Some(synchronizer) = &self.global.restartable_ranges.lock().synchronizer
        {
            synchronizer.wake();
        }
    }

    /// `thread_reset_pcs_ast`: before returning to the guest, a thread a
    /// synchronize marked resumes at the recovery address of the range its
    /// PC is in. Runs after `prepare_to_run_guest`'s fence.
    pub(crate) fn reset_pcs(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let guest = &self.thread.guest;
        if !guest.reset_pcs.load(Ordering::Relaxed)
            || !guest.reset_pcs.swap(false, Ordering::Acquire)
        {
            return;
        }
        let state = self.global.restartable_ranges.lock();
        if let Some(recovery) = state
            .ranges
            .as_deref()
            .and_then(|ranges| recovery_address(ranges, ctx.pc as u64))
        {
            ctx.pc = usize::try_from(recovery).expect("AArch64 addresses fit in usize");
        }
    }
}

/// Interrupts a wait only for a host signal or process exit.
struct ExitOnly<'a, P: ShimPlatform>(&'a Task<P>);

impl<P: ShimPlatform> litebox::event::wait::CheckForInterrupt for ExitOnly<'_, P> {
    fn check_for_interrupt(&self) -> bool {
        self.0.take_host_signal() || self.0.process.exit_status().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::{RestartableRange, recovery_address};

    #[test]
    fn recovery_addresses_cover_pcs_strictly_inside_a_range() {
        let range = |location, length, recovery_offset| RestartableRange {
            location,
            length,
            recovery_offset,
            flags: 0,
        };
        let ranges = [range(0x1000, 0x20, 0x18), range(0x2000, 0x10, 0)];
        let lookups: alloc::vec::Vec<_> = [
            0xfff, 0x1000, 0x1004, 0x101c, 0x1020, 0x1ffc, 0x2000, 0x2008, 0x2010, 0x3000,
        ]
        .iter()
        .map(|&pc| recovery_address(&ranges, pc))
        .collect();
        assert_eq!(
            lookups,
            [
                None,
                None,
                Some(0x1018),
                Some(0x1018),
                None,
                None,
                None,
                Some(0x2000),
                None,
                None
            ]
        );
    }
}
