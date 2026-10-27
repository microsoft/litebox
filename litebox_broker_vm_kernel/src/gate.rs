// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Debug builds: holds broker threads in the midst of their work, for tests.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::time::Duration;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::kthread::{self, WaitQueue};
use litebox_platform_vm_kernel::{Instant, VmKernel};

/// Where a [`Gate`] holds a broker thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Point {
    /// A read of a share file, once done, holding its description's lock.
    Read = 1,
    /// A handshake, before it is made.
    Handshake = 2,
    /// A process clone's adoption, before it is made.
    Adopt = 3,
    /// A share's request, once transmitted, before its response is looked for.
    Transmitted = 4,
}

/// Once armed at a [`Point`], holds the next broker thread that reaches it
/// until released, a millisecond's sleep at a time, so that the CPUs look
/// again that often; it may then move to another CPU ([`kthread::migrate`]).
pub struct Gate {
    platform: &'static VmKernel,
    /// The [`Point`] armed, if any (zero for none).
    armed: AtomicU8,
    /// A thread is held.
    held: AtomicBool,
    /// Ends the hold.
    released: AtomicBool,
    /// The released thread moves to another CPU.
    migrate: AtomicBool,
    queue: WaitQueue,
}

impl Gate {
    pub const fn new(platform: &'static VmKernel) -> Self {
        Self {
            platform,
            armed: AtomicU8::new(0),
            held: AtomicBool::new(false),
            released: AtomicBool::new(false),
            migrate: AtomicBool::new(false),
            queue: WaitQueue::new(),
        }
    }

    /// Holds the next thread that reaches `point`.
    pub fn arm(&self, point: Point) {
        self.released.store(false, Ordering::SeqCst);
        self.armed.store(point as u8, Ordering::SeqCst);
    }

    /// Whether a thread is held.
    pub fn holds(&self) -> bool {
        self.held.load(Ordering::SeqCst)
    }

    /// Ends the hold, if any, and disarms the gate.
    pub fn release(&self) {
        self.armed.store(0, Ordering::SeqCst);
        self.released.store(true, Ordering::SeqCst);
        self.queue.wake(usize::MAX);
    }

    /// Has the next released thread move to another CPU.
    pub fn migrate(&self) {
        self.migrate.store(true, Ordering::SeqCst);
    }

    /// For a broker thread at `point`: holds it if armed there.
    pub fn hold_at(&self, point: Point) {
        const POLL: Duration = Duration::from_millis(1);
        // A load first: no write to the shared line on every pass.
        if self.armed.load(Ordering::Relaxed) != point as u8
            || !kthread::in_kthread()
            || self
                .armed
                .compare_exchange(point as u8, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            return;
        }
        self.held.store(true, Ordering::SeqCst);
        loop {
            let prepared = self.queue.prepare();
            if self.released.load(Ordering::SeqCst) {
                break;
            }
            let deadline: Option<Instant> = self.platform.now().checked_add(POLL);
            prepared.sleep(deadline);
        }
        self.held.store(false, Ordering::SeqCst);
        if self.migrate.swap(false, Ordering::SeqCst) {
            kthread::migrate();
        }
    }
}
