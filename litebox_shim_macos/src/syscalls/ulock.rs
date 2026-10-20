// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `ulock_wait`, `ulock_wait2` and `ulock_wake`, after XNU's
//! `bsd/kern/sys_ulock.c`.
//!
//! Each waited-on lock word has a record (`ull_t`) keyed by its address, or
//! for the shared operations by its memory object and offset, which within
//! one guest is also its address but a separate key space. An unfair lock's
//! record tracks its owner, the thread whose port name the lock word holds.

use crate::{
    ShimPlatform, Task, ThreadId,
    wait::{WaitQueue, WaitResult},
};
use alloc::collections::BTreeMap;
use litebox::utils::TruncateExt as _;
use litebox_common_macos::{errno::Errno, mach::MACH_PORT_DEAD, user_pointers::UserPtr};

/// Operation codes (`UL_*`).
mod op {
    pub const COMPARE_AND_WAIT: u32 = 1;
    pub const UNFAIR_LOCK: u32 = 2;
    pub const COMPARE_AND_WAIT_SHARED: u32 = 3;
    pub const COMPARE_AND_WAIT64: u32 = 5;
    pub const COMPARE_AND_WAIT64_SHARED: u32 = 6;
    pub const OPCODE_MASK: u32 = 0xff;
    pub const FLAGS_MASK: u32 = !OPCODE_MASK;
}

/// Flags (`ULF_*`).
mod flag {
    pub const WAKE_ALL: u32 = 0x0000_0100;
    pub const WAKE_THREAD: u32 = 0x0000_0200;
    pub const WAKE_ALLOW_NON_OWNER: u32 = 0x0000_0400;
    pub const WAIT_WORKQ_DATA_CONTENTION: u32 = 0x0001_0000;
    pub const WAIT_CANCEL_POINT: u32 = 0x0002_0000;
    pub const WAIT_ADAPTIVE_SPIN: u32 = 0x0004_0000;
    pub const NO_ERRNO: u32 = 0x0100_0000;
    pub const DEADLINE: u32 = 0x0200_0000;
    pub const WAIT_MASK: u32 =
        NO_ERRNO | DEADLINE | WAIT_WORKQ_DATA_CONTENTION | WAIT_CANCEL_POINT | WAIT_ADAPTIVE_SPIN;
    pub const WAKE_MASK: u32 = NO_ERRNO | WAKE_ALL | WAKE_THREAD | WAKE_ALLOW_NON_OWNER;
}

/// `ulk_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum UlockKey {
    /// `ULK_UADDR`: an address in this task.
    Address(usize),
    /// `ULK_XPROC`: a memory object and offset; this guest maps no object
    /// twice, so its address names it.
    Object(usize),
}

/// `ull_t`.
struct Ull<P: ShimPlatform> {
    opcode: u32,
    /// Threads in `sys_ulock_wait` for this key, including woken threads
    /// that have not returned yet.
    waiters: u32,
    /// The unfair lock's owner as the last waiter saw it.
    owner: Option<ThreadId>,
    queue: WaitQueue<P>,
}

/// Every lock word with threads in `ulock_wait`.
pub(crate) struct UlockTable<P: ShimPlatform> {
    locks: BTreeMap<UlockKey, Ull<P>>,
}

impl<P: ShimPlatform> Default for UlockTable<P> {
    fn default() -> Self {
        Self {
            locks: BTreeMap::new(),
        }
    }
}

impl<P: ShimPlatform> UlockTable<P> {
    /// Threads in `ulock_wait` on the private lock word at `address`.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn waiters(&self, address: usize) -> u32 {
        self.locks
            .get(&UlockKey::Address(address))
            .map_or(0, |ull| ull.waiters)
    }

    /// `ulock_wait_cleanup`: the waiter leaves; returns the waiters left.
    fn leave(&mut self, key: UlockKey) -> u32 {
        let ull = self.locks.get_mut(&key).expect("a waiter holds the record");
        ull.waiters -= 1;
        let left = ull.waiters;
        if left == 0 {
            self.locks.remove(&key);
        }
        left
    }
}

/// The value `ulock_wait` returns: remaining waiters, or an error. With
/// `ULF_NO_ERRNO` an error is returned as its negation without errno; like
/// every `int` syscall result, it is sign-extended into x0.
fn ulock_result(flags: u32, result: Result<u32, Errno>) -> Result<usize, Errno> {
    match result {
        Ok(value) => Ok(value as usize),
        Err(error) if flags & flag::NO_ERRNO != 0 => Ok((-(error as isize)).cast_unsigned()),
        Err(error) => Err(error),
    }
}

impl<P: ShimPlatform> Task<P> {
    /// `ulock_owner_value_to_port_name` and `port_name_to_thread` with
    /// `PORT_INTRANS_THREAD_IN_CURRENT_TASK | ..._NOT_CURRENT_THREAD`.
    fn port_name_to_other_thread(&self, name: u32) -> Option<ThreadId> {
        self.global
            .ipc
            .lock()
            .thread_for_name(name)
            .filter(|thread| *thread != self.thread.guest.id)
    }

    /// `ulock_resolve_owner`: the thread an unfair lock's value names.
    fn ulock_resolve_owner(&self, value: u32) -> Result<ThreadId, Errno> {
        let name = value | 0x3;
        self.port_name_to_other_thread(name)
            .ok_or(if name == MACH_PORT_DEAD {
                Errno::ESRCH
            } else {
                Errno::EOWNERDEAD
            })
    }

    /// `uaddr_findobj`: whether a mapping backs `address`.
    fn ulock_object(&self, address: usize) -> Option<UlockKey> {
        let mapped = !self
            .global
            .mm
            .overlapping(address..address.saturating_add(1))
            .is_empty();
        mapped.then_some(UlockKey::Object(address))
    }

    /// `sys_ulock_wait2`; `timeout` is in nanoseconds, or a
    /// `mach_absolute_time` deadline with `ULF_DEADLINE`; 0 waits forever.
    pub(crate) fn sys_ulock_wait(
        &self,
        operation: u32,
        address: usize,
        value: u64,
        timeout: u64,
    ) -> Result<usize, Errno> {
        let flags = operation & op::FLAGS_MASK;
        ulock_result(flags, self.ulock_wait(operation, address, value, timeout))
    }

    fn ulock_wait(
        &self,
        operation: u32,
        address: usize,
        value: u64,
        timeout: u64,
    ) -> Result<u32, Errno> {
        let opcode = operation & op::OPCODE_MASK;
        let flags = operation & op::FLAGS_MASK;
        // ULF_WAIT_CANCEL_POINT tests for cancellation, which is not emulated.
        if flags & flag::WAIT_MASK != flags {
            return Err(Errno::EINVAL);
        }
        let (set_owner, shared, size) = match opcode {
            op::UNFAIR_LOCK => (true, false, 4),
            op::COMPARE_AND_WAIT => (false, false, 4),
            op::COMPARE_AND_WAIT64 => (false, false, 8),
            op::COMPARE_AND_WAIT_SHARED => (false, true, 4),
            op::COMPARE_AND_WAIT64_SHARED => (false, true, 8),
            _ => return Err(Errno::EINVAL),
        };
        if address == 0 || !address.is_multiple_of(size) {
            return Err(Errno::EINVAL);
        }
        let key = if shared {
            self.ulock_object(address).ok_or(Errno::EINVAL)?
        } else {
            UlockKey::Address(address)
        };
        let mut owner = None;
        if flags & flag::WAIT_ADAPTIVE_SPIN != 0 && set_owner {
            // A changed lock returns at once. Spinning while the owner runs
            // is an optimization the host scheduler cannot inform.
            let current = UserPtr::<u32>::from_usize(address)
                .read_at_offset::<P>(0)
                .ok_or(Errno::EFAULT)?;
            if u64::from(current) != value {
                return Ok(0);
            }
            owner = self.ulock_resolve_owner(current).ok();
        }
        let mut table = self.global.ulocks.lock();
        let ull = table.locks.entry(key).or_insert_with(|| Ull {
            opcode: 0,
            waiters: 0,
            owner: None,
            queue: WaitQueue::default(),
        });
        ull.waiters += 1;
        let checked = (|| {
            if ull.opcode == 0 {
                ull.opcode = opcode;
            } else if ull.opcode != opcode {
                return Err(Errno::EDOM);
            }
            let current = if size == 4 {
                UserPtr::<u32>::from_usize(address)
                    .read_at_offset::<P>(0)
                    .map(u64::from)
            } else {
                UserPtr::<u64>::from_usize(address).read_at_offset::<P>(0)
            }
            .ok_or(Errno::EFAULT)?;
            if current != value {
                return Ok(false);
            }
            if set_owner {
                if owner.is_none() {
                    match self.ulock_resolve_owner(value.trunc()) {
                        Ok(thread) => owner = Some(thread),
                        Err(Errno::EOWNERDEAD) => return Err(Errno::EOWNERDEAD),
                        // MACH_PORT_DEAD: wait without an owner.
                        Err(_) => {}
                    }
                }
                ull.owner = owner;
            }
            Ok(true)
        })();
        match checked {
            Ok(true) => {}
            Ok(false) => {
                table.leave(key);
                return Ok(0);
            }
            Err(error) => {
                table.leave(key);
                return Err(error);
            }
        }
        let waiter = self.new_waiter();
        ull.queue.push(alloc::sync::Arc::clone(&waiter));
        drop(table);
        let timeout = match timeout {
            0 => None,
            deadline if flags & flag::DEADLINE != 0 => Some(self.mach_deadline_timeout(deadline)),
            nanoseconds => Some(core::time::Duration::from_nanos(nanoseconds)),
        };
        let mut result = self.wait_for_wakeup(&waiter, timeout);
        let mut table = self.global.ulocks.lock();
        if result != WaitResult::Awakened {
            let ull = table
                .locks
                .get_mut(&key)
                .expect("a waiter holds the record");
            if !ull.queue.withdraw(&waiter) {
                result = WaitResult::Awakened;
            }
        }
        let left = table.leave(key);
        match result {
            WaitResult::Awakened => Ok(left),
            WaitResult::TimedOut => Err(Errno::ETIMEDOUT),
            WaitResult::Interrupted => Err(Errno::EINTR),
        }
    }

    /// `sys_ulock_wake`.
    pub(crate) fn sys_ulock_wake(
        &self,
        operation: u32,
        address: usize,
        wake_value: u64,
    ) -> Result<usize, Errno> {
        let flags = operation & op::FLAGS_MASK;
        ulock_result(
            flags,
            self.ulock_wake(operation, address, wake_value).map(|()| 0),
        )
    }

    fn ulock_wake(&self, operation: u32, address: usize, wake_value: u64) -> Result<(), Errno> {
        let opcode = operation & op::OPCODE_MASK;
        let flags = operation & op::FLAGS_MASK;
        let (set_owner, shared) = match opcode {
            op::UNFAIR_LOCK => (true, false),
            op::COMPARE_AND_WAIT | op::COMPARE_AND_WAIT64 => (false, false),
            op::COMPARE_AND_WAIT_SHARED | op::COMPARE_AND_WAIT64_SHARED => (false, true),
            _ => return Err(Errno::EINVAL),
        };
        if flags & flag::WAKE_MASK != flags {
            return Err(Errno::EINVAL);
        }
        if flags & flag::WAKE_THREAD != 0 && (flags & flag::WAKE_ALL != 0 || set_owner) {
            return Err(Errno::EINVAL);
        }
        let allow_non_owner = flags & flag::WAKE_ALLOW_NON_OWNER != 0;
        if allow_non_owner && !set_owner {
            return Err(Errno::EINVAL);
        }
        if address == 0 {
            return Err(Errno::EINVAL);
        }
        let key = if shared {
            self.ulock_object(address).ok_or(Errno::EINVAL)?
        } else {
            UlockKey::Address(address)
        };
        let wake_thread = if flags & flag::WAKE_THREAD != 0 {
            Some(
                self.port_name_to_other_thread(wake_value.trunc())
                    .ok_or(Errno::ESRCH)?,
            )
        } else {
            None
        };
        self.ulock_wake_key(key, opcode, flags, wake_thread, allow_non_owner)
    }

    fn ulock_wake_key(
        &self,
        key: UlockKey,
        opcode: u32,
        flags: u32,
        wake_thread: Option<ThreadId>,
        allow_non_owner: bool,
    ) -> Result<(), Errno> {
        let set_owner = opcode == op::UNFAIR_LOCK;
        let mut table = self.global.ulocks.lock();
        let ull = table.locks.get_mut(&key).ok_or(Errno::ENOENT)?;
        if ull.opcode != opcode {
            return Err(Errno::EDOM);
        }
        if set_owner && ull.owner != Some(self.thread.guest.id) && !allow_non_owner {
            // The owner the kernel knows will redrive the wakeup.
            return Ok(());
        }
        if let Some(thread) = wake_thread {
            if !ull.queue.wake_thread(thread) {
                return Err(Errno::EALREADY);
            }
        } else if flags & flag::WAKE_ALL != 0 {
            ull.queue.wake_all();
            if set_owner {
                ull.owner = None;
            }
        } else if set_owner {
            ull.owner = ull.queue.wake_one();
        } else {
            ull.queue.wake_one();
        }
        Ok(())
    }

    /// `ulock_wake(UL_UNFAIR_LOCK | ULF_WAKE_ALL | ULF_WAKE_ALLOW_NON_OWNER)`
    /// on behalf of a terminated thread (`uthread_joiner_wake`).
    pub(crate) fn ulock_wake_all_unfair(&self, address: usize) {
        if address == 0 {
            return;
        }
        let _ = self.ulock_wake_key(
            UlockKey::Address(address),
            op::UNFAIR_LOCK,
            flag::WAKE_ALL | flag::WAKE_ALLOW_NON_OWNER,
            None,
            true,
        );
    }
}
