// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of the `futex` syscall.

use core::num::NonZeroU32;

use litebox::event::wait::WaitContext;
use litebox::sync::futex::shared::{SharedFutexError, SharedFutexWaiter};
use litebox_broker_protocol::shared_futex::{SharedFutexKey, SharedMemoryId};
use litebox_common_linux::errno::Errno;
use litebox_common_linux::{ClockId, FutexArgs, FutexFlags};

use litebox_platform::time::TimeProvider;

use crate::syscalls::process::RestartBlock;
use crate::{ShimPlatform, Task, UserPtrMut};

impl<Platform: ShimPlatform> Task<Platform> {
    /// Handle syscall `futex`
    pub(crate) fn sys_futex(&self, arg: FutexArgs) -> Result<usize, Errno> {
        let res = match arg {
            FutexArgs::Wake { addr, flags, count } => self.futex_wake(addr, flags, count, None)?,
            FutexArgs::WakeBitset {
                addr,
                flags,
                count,
                bitmask,
            } => {
                // Like Linux, an empty mask fails even when there is nothing to wake.
                let bitmask = NonZeroU32::new(bitmask).ok_or(Errno::EINVAL)?;
                self.futex_wake(addr, flags, count, Some(bitmask))?
            }
            FutexArgs::Wait {
                addr,
                flags,
                val,
                timeout,
            } => {
                // Like Linux, a relative timeout ends at a deadline, which a resumed wait keeps.
                let deadline = timeout
                    .read::<Platform>()?
                    .map(|timeout| self.relative_deadline(timeout));
                self.futex_wait_for(addr, flags, val, None, deadline)?;
                0
            }
            FutexArgs::WaitBitset {
                addr,
                flags,
                val,
                timeout,
                bitmask,
            } => {
                let deadline = timeout
                    .read::<Platform>()?
                    .map(|timeout| {
                        let clock_id = if flags.contains(FutexFlags::CLOCK_REALTIME) {
                            ClockId::RealTime
                        } else {
                            ClockId::Monotonic
                        };
                        self.duration_since_epoch_to_deadline(clock_id, timeout)
                    })
                    .transpose()?;
                // Like Linux, an empty mask fails rather than waiting for a wake that never comes.
                let bitmask = NonZeroU32::new(bitmask).ok_or(Errno::EINVAL)?;
                self.futex_wait_for(addr, flags, val, Some(bitmask), deadline)?;
                0
            }
            _ => unimplemented!("Unsupported futex operation"),
        };
        Ok(res)
    }

    /// Returns a new name for the memory of a shared anonymous mapping, or `None` without a
    /// broker, as then no other process can share the memory either.
    pub(super) fn issue_shared_memory_id(&self) -> Result<Option<SharedMemoryId>, Errno> {
        match self.global.litebox.issue_shared_memory_id() {
            Ok(id) => Ok(Some(id)),
            Err(SharedFutexError::Unavailable) => Ok(None),
            Err(_) => Err(Errno::ENOMEM),
        }
    }

    /// Returns the key of the futex word at `addr` if a futex operation with `flags` on it spans
    /// the processes that share the word's memory.
    ///
    /// Otherwise the operation goes to the process's private [`FutexManager`], keyed by address,
    /// even without [`FutexFlags::PRIVATE`]. This differs from Linux, which keys a non-private
    /// futex in private memory apart from a private futex on the same word, so that neither kind
    /// of wake reaches the other kind of waiter. Only a program that mixes the two kinds on one
    /// word can tell: LiteBox wakes where Linux would leave the waiter sleeping.
    ///
    /// [`FutexManager`]: litebox::sync::futex::FutexManager
    fn shared_futex_key_for(
        &self,
        addr: UserPtrMut<u32>,
        flags: FutexFlags,
    ) -> Result<Option<SharedFutexKey>, Errno> {
        if !addr.as_usize().is_multiple_of(align_of::<u32>()) {
            return Err(Errno::EINVAL);
        }
        if flags.contains(FutexFlags::PRIVATE) {
            Ok(None)
        } else {
            self.global
                .mm
                .shared_futex_key(addr.as_usize(), || self.issue_shared_memory_id())
        }
    }

    /// Wakes up to `count` waiters on the futex word at `addr` whose masks intersect `bitset`, or
    /// all masks if it is `None`, among the shared or private futexes `flags` selects.
    fn futex_wake(
        &self,
        addr: UserPtrMut<u32>,
        flags: FutexFlags,
        count: u32,
        bitset: Option<NonZeroU32>,
    ) -> Result<usize, Errno> {
        // Linux takes the count as an `int` and counts a waiter before comparing, so a count that
        // is zero or negative as an `int` still wakes one waiter.
        let count = NonZeroU32::new(count)
            .filter(|count| i32::try_from(count.get()).is_ok())
            .unwrap_or(NonZeroU32::MIN);
        Ok(if let Some(key) = self.shared_futex_key_for(addr, flags)? {
            self.global.litebox.wake_shared_futex(key, count, bitset)? as usize
        } else {
            self.global
                .futex_manager
                .wake(addr.to_platform_ptr::<Platform>(), count, bitset)? as usize
        })
    }

    /// Waits on the futex word at `addr` with the shared or private futexes `flags` selects.
    fn futex_wait(
        &self,
        cx: &WaitContext<'_, Platform>,
        addr: UserPtrMut<u32>,
        flags: FutexFlags,
        val: u32,
        bitset: Option<NonZeroU32>,
    ) -> Result<(), Errno> {
        let addr_ptr = addr.to_platform_ptr::<Platform>();
        if let Some(key) = self.shared_futex_key_for(addr, flags)? {
            self.get_or_create_shared_futex_waiter()?
                .wait(cx, key, addr_ptr, val, bitset)?;
        } else {
            self.global.futex_manager.wait(cx, addr_ptr, val, bitset)?;
        }
        Ok(())
    }

    /// Waits like [`Self::futex_wait`] until `deadline`, or until woken if `None`.
    fn futex_wait_for(
        &self,
        addr: UserPtrMut<u32>,
        flags: FutexFlags,
        val: u32,
        bitset: Option<NonZeroU32>,
        deadline: Option<<Platform as TimeProvider>::Instant>,
    ) -> Result<(), Errno> {
        match deadline {
            None => self.futex_wait(&self.wait_cx(), addr, flags, val, bitset),
            Some(deadline) => self.futex_wait_until(addr, flags, val, bitset, deadline),
        }
    }

    /// Waits like [`Self::futex_wait`] until `deadline`, for a wait with a timeout.
    ///
    /// Like Linux, an interrupted wait resumes through `restart_syscall` until `deadline` unless
    /// a handler runs, rather than being reissued with its whole timeout, so a handler interrupts
    /// it even with `SA_RESTART`.
    pub(super) fn futex_wait_until(
        &self,
        addr: UserPtrMut<u32>,
        flags: FutexFlags,
        val: u32,
        bitset: Option<NonZeroU32>,
        deadline: <Platform as TimeProvider>::Instant,
    ) -> Result<(), Errno> {
        match self.futex_wait(
            &self.wait_cx().with_deadline(deadline),
            addr,
            flags,
            val,
            bitset,
        ) {
            Err(Errno::ERESTARTSYS) => Err(self.thread.save_restart_block(RestartBlock::Futex {
                addr,
                flags,
                val,
                bitset,
                deadline,
            })),
            result => result,
        }
    }

    /// Returns this thread's waiter for futexes in shared memory, creating it in the broker on
    /// first use.
    fn get_or_create_shared_futex_waiter(&self) -> Result<&SharedFutexWaiter<Platform>, Errno> {
        if let Some(waiter) = self.shared_futex_waiter.get() {
            return Ok(waiter);
        }
        let waiter = SharedFutexWaiter::new(&self.global.litebox).map_err(Errno::from)?;
        Ok(self.shared_futex_waiter.get_or_init(|| waiter))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::time::Duration;

    use litebox_broker_protocol::shared_futex::SharedFutexKey;
    use litebox_common_linux::errno::Errno;
    use litebox_common_linux::{FutexArgs, FutexFlags, MapFlags, PAGE_SIZE, ProtFlags, TimeParam};

    use crate::syscalls::tests::{TestPlatform, init_platform};
    use crate::{Task, UserPtrMut};

    fn map(task: &Task<TestPlatform>, pages: usize, flags: MapFlags) -> UserPtrMut<u8> {
        task.sys_mmap(
            0,
            pages * PAGE_SIZE,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            flags | MapFlags::MAP_ANONYMOUS,
            -1,
            0,
        )
        .unwrap()
    }

    fn key(task: &Task<TestPlatform>, address: usize) -> Option<SharedFutexKey> {
        task.global
            .mm
            .shared_futex_key(address, || task.issue_shared_memory_id())
            .unwrap()
    }

    fn word(address: usize) -> UserPtrMut<u32> {
        UserPtrMut::from_usize(address)
    }

    fn wait(
        task: &Task<TestPlatform>,
        address: usize,
        val: u32,
        flags: FutexFlags,
        timeout_ms: Option<i32>,
    ) -> Result<usize, Errno> {
        task.sys_futex(FutexArgs::Wait {
            addr: word(address),
            flags,
            val,
            timeout: timeout_ms.map_or(TimeParam::None, TimeParam::Milliseconds),
        })
    }

    /// How long a spawned waiter waits before giving up, so that a failed test does not hang.
    const WAITER_TIMEOUT_MS: i32 = 10_000;

    /// Spawns a thread of `task`'s process that waits on the word at `address` with `flags`
    /// until it is woken, and gives it time to arm its waiter.
    fn spawn_waiter(
        task: &Task<TestPlatform>,
        address: usize,
        flags: FutexFlags,
    ) -> std::thread::JoinHandle<Result<usize, Errno>> {
        let waiter = task.spawn_clone_for_test(move |task| {
            wait(&task, address, 0, flags, Some(WAITER_TIMEOUT_MS))
        });
        // The waiter cannot report when it sleeps, so wakes that must not reach it are checked
        // after giving it time to; `wake_until_woken` then tolerates a slower waiter.
        std::thread::sleep(Duration::from_millis(100));
        waiter
    }

    /// Calls `wake` until it wakes a waiter, as a spawned waiter may not have armed yet, and
    /// returns how many it woke.
    fn wake_until_woken(wake: impl Fn() -> Result<usize, Errno>) -> usize {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let woken = wake().unwrap();
            if woken != 0 || std::time::Instant::now() > deadline {
                return woken;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn shared_futex_keys_name_memory_and_offset_of_whole_words() {
        let task = init_platform();
        let mapping = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let private = map(&task, 1, MapFlags::MAP_PRIVATE).as_usize();
        assert!(key(&task, private).is_none());
        assert!(key(&task, private + 4).is_none());
        let start = key(&task, mapping).unwrap();
        assert_eq!(start.offset, 0);
        assert_eq!(
            key(&task, mapping + 8),
            Some(SharedFutexKey {
                memory: start.memory,
                offset: 8
            })
        );
        // A word must lie entirely within the mapping.
        assert!(
            key(&task, mapping + PAGE_SIZE - 4).is_some()
                && key(&task, mapping + PAGE_SIZE - 2).is_none()
        );
    }

    #[test]
    fn each_shared_mapping_names_its_own_memory() {
        let task = init_platform();
        let first = map(&task, 2, MapFlags::MAP_SHARED).as_usize();
        // A second mapping right after the first stays distinct memory, even though neither is
        // named until its first futex use.
        let second = task
            .sys_mmap(
                first + PAGE_SIZE,
                PAGE_SIZE,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            )
            .unwrap()
            .as_usize();
        assert_eq!(second, first + PAGE_SIZE);
        let (first_key, second_key) = (key(&task, first).unwrap(), key(&task, second).unwrap());
        assert_ne!(first_key.memory, second_key.memory);
        // Even when adjacent, distinct mappings stay distinct memory, each from offset zero.
        assert_eq!((first_key.offset, second_key.offset), (0, 0));

        // Replacing a mapping replaces its memory, with new shared memory or none.
        let remap = |flags: MapFlags| {
            task.sys_mmap(
                first,
                PAGE_SIZE,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                flags | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            )
            .unwrap()
        };
        assert_eq!(remap(MapFlags::MAP_SHARED).as_usize(), first);
        assert_ne!(key(&task, first).unwrap().memory, first_key.memory);
        assert_eq!(remap(MapFlags::MAP_PRIVATE).as_usize(), first);
        assert!(key(&task, first).is_none());
    }

    #[test]
    fn memory_split_while_it_is_named_still_gets_a_shared_key() {
        let task = init_platform();
        let mapping = map(&task, 2, MapFlags::MAP_SHARED);
        // Another thread splits the mapping while this one asks the broker for its name. The
        // word must still get a shared key, the one every later futex call on it uses, rather
        // than a private one that their wakes would never reach.
        let racing = task
            .global
            .mm
            .shared_futex_key(mapping.as_usize(), || {
                let second = UserPtrMut::from_usize(mapping.as_usize() + PAGE_SIZE);
                task.sys_mprotect(second, PAGE_SIZE, ProtFlags::PROT_READ)
                    .unwrap();
                task.issue_shared_memory_id()
            })
            .unwrap();
        assert!(racing.is_some());
        assert_eq!(racing, key(&task, mapping.as_usize()));
    }

    #[test]
    fn pieces_of_a_mapping_split_before_first_use_share_one_name() {
        let task = init_platform();
        let start = map(&task, 4, MapFlags::MAP_SHARED).as_usize();
        // Mapping issues no name, so split the mapping before any futex names it: changing the
        // protection of the second page leaves adjacent pieces, and unmapping the third leaves a
        // hole between them.
        task.sys_mprotect(
            UserPtrMut::from_usize(start + PAGE_SIZE),
            PAGE_SIZE,
            ProtFlags::PROT_READ,
        )
        .unwrap();
        task.sys_munmap(UserPtrMut::from_usize(start + 2 * PAGE_SIZE), PAGE_SIZE)
            .unwrap();
        // Naming one piece names the whole mapping, with offsets from its start, as Linux keys
        // the words of one shared mapping by their offset in its memory.
        let last = key(&task, start + 3 * PAGE_SIZE + 4).unwrap();
        assert_eq!(last.offset, 3 * PAGE_SIZE as u64 + 4);
        for offset in [4, PAGE_SIZE + 4] {
            assert_eq!(
                key(&task, start + offset),
                Some(SharedFutexKey {
                    memory: last.memory,
                    offset: offset as u64
                })
            );
        }
    }

    #[test]
    fn native_fork_child_keeps_inherited_ids_and_gets_new_ones() {
        use crate::syscalls::tests::test_platform;
        use litebox::platform::ThreadProvider;

        let platform = test_platform();
        TestPlatform::run_test_thread(|| {
            let (litebox, process_id) = crate::syscalls::test_broker::litebox(platform);
            let builder = crate::LinuxShimBuilder::new_with_litebox(platform, litebox, process_id);
            let memory = std::sync::Arc::clone(&builder.memory_manager);
            let parent = builder.build();
            let task = parent.0.clone().new_test_task();
            let inherited = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
            let parent_memory = key(&task, inherited).unwrap().memory;
            drop(task);
            drop(parent);

            // A native fork child is another broker process holding the parent's memory manager.
            let (litebox, process_id) = crate::syscalls::test_broker::litebox(platform);
            // SAFETY: The old task and shim are gone, no locks are held, and this test transfers
            // the manager to a single fresh shim using the same live platform.
            let child = unsafe {
                crate::LinuxShimBuilder::new_for_native_fork(platform, litebox, process_id, memory)
            }
            .build();
            let task = child.0.clone().new_test_task();
            // The inherited mapping keeps naming the memory the parent shares, and the broker
            // accepts its signed ID from the child, while memory the child creates gets an ID of
            // its own.
            assert_eq!(key(&task, inherited).unwrap().memory, parent_memory);
            assert_eq!(
                task.sys_futex(FutexArgs::Wake {
                    addr: word(inherited),
                    flags: FutexFlags::empty(),
                    count: 1,
                }),
                Ok(0)
            );
            let created = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
            assert_ne!(key(&task, created).unwrap().memory, parent_memory);
        });
    }

    #[test]
    fn splitting_a_mapping_keeps_its_futex_keys() {
        let task = init_platform();
        let mapping = map(&task, 3, MapFlags::MAP_SHARED);
        let start = mapping.as_usize();
        let memory = key(&task, start).unwrap().memory;
        let tail = SharedFutexKey {
            memory,
            offset: 2 * PAGE_SIZE as u64 + 4,
        };

        // Changing the protection of the middle page splits the mapping, and changing it back
        // joins it again.
        let middle = UserPtrMut::from_usize(start + PAGE_SIZE);
        task.sys_mprotect(middle, PAGE_SIZE, ProtFlags::PROT_READ)
            .unwrap();
        assert_eq!(key(&task, start + 2 * PAGE_SIZE + 4), Some(tail));
        task.sys_mprotect(
            middle,
            PAGE_SIZE,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        )
        .unwrap();
        assert_eq!(key(&task, start + 2 * PAGE_SIZE + 4), Some(tail));
        // Once its pieces match again, the named mapping is one area again.
        let areas: alloc::vec::Vec<_> = task
            .global
            .mm
            .mappings()
            .into_iter()
            .filter(|(range, _)| range.start < start + 3 * PAGE_SIZE && start < range.end)
            .map(|(range, _)| range)
            .collect();
        assert_eq!(areas, alloc::vec![start..start + 3 * PAGE_SIZE]);

        task.sys_munmap(middle, PAGE_SIZE).unwrap();
        assert!(key(&task, start + PAGE_SIZE).is_none());
        assert_eq!(key(&task, start + 2 * PAGE_SIZE + 4), Some(tail));
        task.sys_munmap(mapping, 3 * PAGE_SIZE).unwrap();
        assert!(key(&task, start + 2 * PAGE_SIZE).is_none());
    }

    #[test]
    fn broker_failure_wakes_shared_futex_waiter_with_eio() {
        let task = init_platform();
        let mapping = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let waiter = spawn_waiter(&task, mapping, FutexFlags::empty());
        task.global.litebox.broker_failure_dispatcher()();
        assert_eq!(waiter.join().unwrap(), Err(Errno::EIO));
    }

    #[test]
    fn wake_with_non_positive_signed_count_wakes_one_waiter() {
        // Linux takes the count as an `int` and counts a waiter before comparing with it, so a
        // count that is zero, or past `i32::MAX` and so negative, wakes one waiter even when more
        // match.
        const COUNTS: [u32; 3] = [0, 0x8000_0000, u32::MAX];
        let task = init_platform();
        let shared = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let private = map(&task, 1, MapFlags::MAP_PRIVATE).as_usize();
        for address in [shared, private] {
            for bitmask in [None, Some(u32::MAX)] {
                let waiters = COUNTS.map(|_| spawn_waiter(&task, address, FutexFlags::empty()));
                for count in COUNTS {
                    let woken = wake_until_woken(|| {
                        let addr = word(address);
                        let flags = FutexFlags::empty();
                        task.sys_futex(match bitmask {
                            None => FutexArgs::Wake { addr, flags, count },
                            Some(bitmask) => FutexArgs::WakeBitset {
                                addr,
                                flags,
                                count,
                                bitmask,
                            },
                        })
                    });
                    assert_eq!(woken, 1, "{address:#x} {bitmask:?} {count:#x}");
                }
                for waiter in waiters {
                    assert_eq!(waiter.join().unwrap(), Ok(0));
                }
            }
        }
    }

    #[test]
    fn shared_futex_ping_pong_loses_no_wakes() {
        const ROUNDS: u32 = 500;
        let task = init_platform();
        let turn = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        // Each side waits for its turn, then hands the turn over, so a lost wake times out.
        let take_turns = move |task: &Task<TestPlatform>, me: u32| -> Result<(), Errno> {
            for _ in 0..ROUNDS {
                loop {
                    let current = word(turn).read_at_offset::<TestPlatform>(0).unwrap();
                    if current == me {
                        break;
                    }
                    match wait(
                        task,
                        turn,
                        current,
                        FutexFlags::empty(),
                        Some(WAITER_TIMEOUT_MS),
                    ) {
                        Ok(_) | Err(Errno::EAGAIN) => {}
                        Err(error) => return Err(error),
                    }
                }
                word(turn)
                    .write_at_offset::<TestPlatform>(0, 1 - me)
                    .unwrap();
                task.sys_futex(FutexArgs::Wake {
                    addr: word(turn),
                    flags: FutexFlags::empty(),
                    count: 1,
                })?;
            }
            Ok(())
        };
        let other = task.spawn_clone_for_test(move |task| take_turns(&task, 1));
        assert_eq!(take_turns(&task, 0), Ok(()));
        assert_eq!(other.join().unwrap(), Ok(()));
    }

    /// Waits that time out race wakes on a word in a mapping with `map_flags`, with `flags`.
    fn futex_wakes_racing_timeouts_are_each_reported_once(map_flags: MapFlags, flags: FutexFlags) {
        use core::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        const WAITS: usize = 300;
        let task = init_platform();
        let address = map(&task, 1, map_flags).as_usize();
        let done = Arc::new(AtomicBool::new(false));
        let waiter = {
            let done = Arc::clone(&done);
            task.spawn_clone_for_test(move |task| {
                let mut woken = 0;
                for _ in 0..WAITS {
                    match wait(&task, address, 0, flags, Some(1)) {
                        Ok(_) => woken += 1,
                        Err(Errno::ETIMEDOUT) => {}
                        Err(error) => panic!("unexpected wait failure: {error:?}"),
                    }
                }
                done.store(true, Ordering::Release);
                woken
            })
        };
        let mut woken = 0;
        while !done.load(Ordering::Acquire) {
            woken += task
                .sys_futex(FutexArgs::Wake {
                    addr: word(address),
                    flags,
                    count: 1,
                })
                .unwrap();
            // Waking a little less often than waits time out makes wakes land as waits time out.
            std::thread::sleep(Duration::from_micros(1500));
        }
        // A wake that selects a timing-out waiter must make that wait succeed, and a wait only
        // succeeds if a wake selected it.
        assert_eq!(waiter.join().unwrap(), woken);
    }

    #[test]
    fn shared_futex_wakes_racing_timeouts_are_each_reported_once() {
        futex_wakes_racing_timeouts_are_each_reported_once(
            MapFlags::MAP_SHARED,
            FutexFlags::empty(),
        );
    }

    #[test]
    fn private_futex_wakes_racing_timeouts_are_each_reported_once() {
        futex_wakes_racing_timeouts_are_each_reported_once(
            MapFlags::MAP_PRIVATE,
            FutexFlags::PRIVATE,
        );
    }

    /// Like Linux, a futex wait with a timeout that a signal interrupts resumes through
    /// `restart_syscall`, which waits again, checking the word, and then leaves nothing to resume,
    /// while a wait without a timeout is reissued (see the `wait_restart.c` runner test). SIGCHLD
    /// is pending before each wait, which lasts an hour or has no timeout, so every interruption
    /// is certain.
    #[test]
    fn test_interrupted_futex_wait_with_timeout_resumes_through_restart_syscall() {
        use litebox::platform::ThreadProvider as _;

        let task = init_platform();
        TestPlatform::run_test_thread(|| {
            let address = map(&task, 1, MapFlags::MAP_PRIVATE).as_usize();
            let discard_sigchld = || crate::syscalls::tests::discard_pending_signals(&task);

            crate::syscalls::tests::queue_ignored_sigchld(&task);
            assert_eq!(
                wait(&task, address, 0, FutexFlags::PRIVATE, None),
                Err(Errno::ERESTARTSYS)
            );
            discard_sigchld();
            assert_eq!(task.sys_restart_syscall(), Err(Errno::EINTR));

            crate::syscalls::tests::queue_ignored_sigchld(&task);
            assert_eq!(
                wait(&task, address, 0, FutexFlags::PRIVATE, Some(3_600_000)),
                Err(Errno::ERESTART_RESTARTBLOCK)
            );
            discard_sigchld();
            // Interrupted again, the resumed wait saves itself again.
            crate::syscalls::tests::queue_ignored_sigchld(&task);
            assert_eq!(
                task.sys_restart_syscall(),
                Err(Errno::ERESTART_RESTARTBLOCK)
            );
            discard_sigchld();

            // Once the word changes, the resumed wait ends, leaving nothing to resume.
            word(address).write_at_offset::<TestPlatform>(0, 1).unwrap();
            assert_eq!(task.sys_restart_syscall(), Err(Errno::EAGAIN));
            assert_eq!(task.sys_restart_syscall(), Err(Errno::EINTR));
        });
    }
}
