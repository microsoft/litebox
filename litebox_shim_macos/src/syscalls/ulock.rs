// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `ulock_wait`, `ulock_wait2` and `ulock_wake`, after XNU's
//! `bsd/kern/sys_ulock.c`.
//!
//! Each waited-on lock word has a record (`ull_t`) keyed by its address
//! (`ULK_UADDR`). An unfair lock's record tracks its owner, the thread whose
//! port name the lock word holds.

use crate::{
    ShimPlatform, Task, ThreadId,
    wait::{WaitQueue, WaitResult},
};
use alloc::collections::BTreeMap;
use litebox::utils::TruncateExt as _;
use litebox_common_macos::{
    errno::Errno,
    mach::MACH_PORT_DEAD,
    syscall::{UlockFlags, UlockOpcode},
    user_pointers::UserPtr,
};

/// `ull_t`.
struct Ull<P: ShimPlatform> {
    /// Set by the first waiter.
    opcode: Option<UlockOpcode>,
    /// Threads in `sys_ulock_wait` on this lock word, including woken threads
    /// that have not returned yet.
    waiters: u32,
    /// The unfair lock's owner as the last waiter saw it.
    owner: Option<ThreadId>,
    queue: WaitQueue<P>,
}

/// Every lock word with threads in `ulock_wait`, by address.
pub(crate) struct UlockTable<P: ShimPlatform> {
    locks: BTreeMap<usize, Ull<P>>,
}

impl<P: ShimPlatform> Default for UlockTable<P> {
    fn default() -> Self {
        Self {
            locks: BTreeMap::new(),
        }
    }
}

impl<P: ShimPlatform> UlockTable<P> {
    /// Threads in `ulock_wait` on the lock word at `address`.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn waiters(&self, address: usize) -> u32 {
        self.locks.get(&address).map_or(0, |ull| ull.waiters)
    }

    /// `ulock_wait_cleanup`: the waiter leaves; returns the waiters left.
    fn leave(&mut self, address: usize) -> u32 {
        let ull = self
            .locks
            .get_mut(&address)
            .expect("a waiter holds the record");
        ull.waiters -= 1;
        let left = ull.waiters;
        if left == 0 {
            self.locks.remove(&address);
        }
        left
    }
}

/// The value `ulock_wait` returns: remaining waiters, or an error. With
/// `ULF_NO_ERRNO` an error is returned as its negation without errno; like
/// every `int` syscall result, it is sign-extended into x0.
fn ulock_result(flags: UlockFlags, result: Result<u32, Errno>) -> Result<usize, Errno> {
    match result {
        Ok(value) => Ok(value as usize),
        Err(error) if flags.contains(UlockFlags::NO_ERRNO) => {
            Ok((-(error as isize)).cast_unsigned())
        }
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

    /// `UL_COMPARE_AND_WAIT_SHARED` and `UL_COMPARE_AND_WAIT64_SHARED`, which
    /// only `os_sync_wait_on_address` and `os_sync_wake_by_address` with
    /// `OS_SYNC_*_SHARED` use, are refused.
    fn refuse_shared_ulock(&self, opcode: UlockOpcode) -> Errno {
        // TODO: shared ulocks (os_sync_*_SHARED): key by the mapped object and
        // offset (`ULK_XPROC`), so waiters stay with a mapping that is
        // replaced or removed and never meet the one that replaces it.
        self.log_unsupported_once("shared ulock", 0, format_args!("{opcode:?}"));
        Errno::ENOTSUP
    }

    /// `sys_ulock_wait2`; `timeout` is in nanoseconds, or a
    /// `mach_absolute_time` deadline with `ULF_DEADLINE`; 0 waits forever.
    pub(crate) fn sys_ulock_wait(
        &self,
        opcode: UlockOpcode,
        flags: UlockFlags,
        address: usize,
        value: u64,
        timeout: u64,
    ) -> Result<usize, Errno> {
        ulock_result(
            flags,
            self.ulock_wait(opcode, flags, address, value, timeout),
        )
    }

    fn ulock_wait(
        &self,
        opcode: UlockOpcode,
        flags: UlockFlags,
        address: usize,
        value: u64,
        timeout: u64,
    ) -> Result<u32, Errno> {
        if !UlockFlags::WAIT_MASK.contains(flags) {
            return Err(Errno::EINVAL);
        }
        let (set_owner, size) = match opcode {
            UlockOpcode::UnfairLock => (true, 4),
            UlockOpcode::CompareAndWait => (false, 4),
            UlockOpcode::CompareAndWait64 => (false, 8),
            UlockOpcode::CompareAndWaitShared | UlockOpcode::CompareAndWait64Shared => {
                return Err(self.refuse_shared_ulock(opcode));
            }
            UlockOpcode::Unknown(_) => return Err(Errno::EINVAL),
        };
        if address == 0 || !address.is_multiple_of(size) {
            return Err(Errno::EINVAL);
        }
        let mut owner = None;
        if flags.contains(UlockFlags::WAIT_ADAPTIVE_SPIN) && set_owner {
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
        let ull = table.locks.entry(address).or_insert_with(|| Ull {
            opcode: None,
            waiters: 0,
            owner: None,
            queue: WaitQueue::default(),
        });
        ull.waiters += 1;
        let checked = (|| {
            if *ull.opcode.get_or_insert(opcode) != opcode {
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
            // `out_locked` -> `ulock_wait_cleanup`: the waiters left.
            Ok(false) => return Ok(table.leave(address)),
            Err(error) => {
                table.leave(address);
                return Err(error);
            }
        }
        let waiter = self.new_waiter();
        ull.queue.push(alloc::sync::Arc::clone(&waiter));
        drop(table);
        let timeout = match timeout {
            0 => None,
            deadline if flags.contains(UlockFlags::DEADLINE) => {
                Some(self.mach_deadline_timeout(deadline))
            }
            nanoseconds => Some(core::time::Duration::from_nanos(nanoseconds)),
        };
        let mut result = self.wait_for_wakeup(&waiter, timeout);
        let mut table = self.global.ulocks.lock();
        if result != WaitResult::Awakened {
            let ull = table
                .locks
                .get_mut(&address)
                .expect("a waiter holds the record");
            if !ull.queue.withdraw(&waiter) {
                result = WaitResult::Awakened;
            }
        }
        let left = table.leave(address);
        match result {
            WaitResult::Awakened => Ok(left),
            WaitResult::TimedOut => Err(Errno::ETIMEDOUT),
            WaitResult::Interrupted => Err(Errno::EINTR),
        }
    }

    /// `sys_ulock_wake`.
    pub(crate) fn sys_ulock_wake(
        &self,
        opcode: UlockOpcode,
        flags: UlockFlags,
        address: usize,
        wake_value: u64,
    ) -> Result<usize, Errno> {
        ulock_result(
            flags,
            self.ulock_wake(opcode, flags, address, wake_value)
                .map(|()| 0),
        )
    }

    fn ulock_wake(
        &self,
        opcode: UlockOpcode,
        flags: UlockFlags,
        address: usize,
        wake_value: u64,
    ) -> Result<(), Errno> {
        let set_owner = match opcode {
            UlockOpcode::UnfairLock => true,
            UlockOpcode::CompareAndWait | UlockOpcode::CompareAndWait64 => false,
            UlockOpcode::CompareAndWaitShared | UlockOpcode::CompareAndWait64Shared => {
                return Err(self.refuse_shared_ulock(opcode));
            }
            UlockOpcode::Unknown(_) => return Err(Errno::EINVAL),
        };
        if !UlockFlags::WAKE_MASK.contains(flags) {
            return Err(Errno::EINVAL);
        }
        if flags.contains(UlockFlags::WAKE_THREAD)
            && (flags.contains(UlockFlags::WAKE_ALL) || set_owner)
        {
            return Err(Errno::EINVAL);
        }
        let allow_non_owner = flags.contains(UlockFlags::WAKE_ALLOW_NON_OWNER);
        if allow_non_owner && !set_owner {
            return Err(Errno::EINVAL);
        }
        if address == 0 {
            return Err(Errno::EINVAL);
        }
        let wake_thread = if flags.contains(UlockFlags::WAKE_THREAD) {
            Some(
                self.port_name_to_other_thread(wake_value.trunc())
                    .ok_or(Errno::ESRCH)?,
            )
        } else {
            None
        };
        self.ulock_wake_address(address, opcode, flags, wake_thread, allow_non_owner)
    }

    fn ulock_wake_address(
        &self,
        address: usize,
        opcode: UlockOpcode,
        flags: UlockFlags,
        wake_thread: Option<ThreadId>,
        allow_non_owner: bool,
    ) -> Result<(), Errno> {
        let set_owner = opcode == UlockOpcode::UnfairLock;
        let mut table = self.global.ulocks.lock();
        let ull = table.locks.get_mut(&address).ok_or(Errno::ENOENT)?;
        if ull.opcode != Some(opcode) {
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
        } else if flags.contains(UlockFlags::WAKE_ALL) {
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
        let _ = self.ulock_wake_address(
            address,
            UlockOpcode::UnfairLock,
            UlockFlags::WAKE_ALL | UlockFlags::WAKE_ALLOW_NON_OWNER,
            None,
            true,
        );
    }
}
