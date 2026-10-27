// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of the `futex` syscall.

use core::num::NonZeroU32;

use litebox::event::wait::WaitContext;
use litebox::sync::futex::shared::{SharedFutexError, SharedFutexWaiter};
use litebox_broker_protocol::shared_futex::{SharedFutexKey, SharedMemoryId};
use litebox_common_linux::errno::Errno;
use litebox_common_linux::vmem::MappingError;
use litebox_common_linux::{ClockId, FutexArgs, FutexFlags};

use crate::wait::wait_errno;
use crate::{ShimPlatform, Task, UserPtrMut};

impl<Platform: ShimPlatform> Task<Platform> {
    /// Handle syscall `futex`
    pub(crate) fn sys_futex(&self, arg: FutexArgs) -> Result<usize, Errno> {
        let res = match arg {
            FutexArgs::Wake { addr, flags, count } => self.futex_wake(addr, &flags, count, None)?,
            FutexArgs::WakeBitset {
                addr,
                flags,
                count,
                bitmask,
            } => {
                // Like Linux, an empty mask fails even when there is nothing to wake.
                let bitmask = NonZeroU32::new(bitmask).ok_or(Errno::EINVAL)?;
                self.futex_wake(addr, &flags, count, Some(bitmask))?
            }
            FutexArgs::Wait {
                addr,
                flags,
                val,
                timeout,
            } => {
                let timeout = timeout.read::<Platform>()?;
                self.futex_wait(
                    &self.wait_cx().with_timeout(timeout),
                    addr,
                    &flags,
                    val,
                    None,
                )
                .map_err(|error| wait_errno(timeout, error))?;
                0
            }
            FutexArgs::WaitBitset {
                addr,
                flags,
                val,
                timeout,
                bitmask,
            } => {
                let timeout = timeout.read::<Platform>()?;
                let deadline = if let Some(timeout) = timeout {
                    let clock_id = if flags.contains(FutexFlags::CLOCK_REALTIME) {
                        ClockId::RealTime
                    } else {
                        ClockId::Monotonic
                    };
                    self.duration_since_epoch_to_deadline(clock_id, timeout)?
                } else {
                    None
                };
                // Like Linux, an empty mask fails rather than waiting for a wake that never comes.
                let bitmask = NonZeroU32::new(bitmask).ok_or(Errno::EINVAL)?;
                self.futex_wait(
                    &self.wait_cx().with_deadline(deadline),
                    addr,
                    &flags,
                    val,
                    Some(bitmask),
                )
                .map_err(|error| wait_errno(timeout, error))?;
                0
            }
            _ => unimplemented!("Unsupported futex operation"),
        };
        Ok(res)
    }

    /// Returns a new name for the memory of a shared anonymous mapping, or `None` without a
    /// broker, as then no other process can share the memory either.
    ///
    /// Fails with [`MappingError::OutOfMemory`] if the broker cannot provide a name, as `mmap`
    /// reports any failure to back a mapping with `ENOMEM`.
    pub(super) fn allocate_shared_memory_id(&self) -> Result<Option<SharedMemoryId>, MappingError> {
        match self.global.shared_memory_ids.allocate(&self.global.litebox) {
            Ok(id) => Ok(Some(id)),
            Err(SharedFutexError::Unavailable) => Ok(None),
            Err(_) => Err(MappingError::OutOfMemory),
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
    /// Like Linux, fails with `EINVAL` if the word is misaligned, and then with `EFAULT` if it is
    /// in shared memory that is inaccessible.
    ///
    /// [`FutexManager`]: litebox::sync::futex::FutexManager
    fn shared_futex_key_for(
        &self,
        addr: UserPtrMut<u32>,
        flags: &FutexFlags,
    ) -> Result<Option<SharedFutexKey>, Errno> {
        if !addr.as_usize().is_multiple_of(align_of::<u32>()) {
            return Err(Errno::EINVAL);
        }
        if flags.contains(FutexFlags::PRIVATE) {
            Ok(None)
        } else {
            self.global.mm.shared_futex_key(addr.as_usize())
        }
    }

    /// Wakes up to `count` waiters on the futex word at `addr` whose masks intersect `bitset`, or
    /// all masks if it is `None`, among the shared or private futexes `flags` selects.
    fn futex_wake(
        &self,
        addr: UserPtrMut<u32>,
        flags: &FutexFlags,
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
        flags: &FutexFlags,
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
        task.global.mm.shared_futex_key(address).unwrap()
    }

    fn word(address: usize) -> UserPtrMut<u32> {
        UserPtrMut::from_usize(address)
    }

    /// The count that wakes all waiters, the largest that Linux's signed count allows.
    const WAKE_ALL: u32 = i32::MAX as u32;

    fn wake(task: &Task<TestPlatform>, address: usize, flags: FutexFlags) -> usize {
        task.sys_futex(FutexArgs::Wake {
            addr: word(address),
            flags,
            count: WAKE_ALL,
        })
        .unwrap()
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
    fn shared_mapping_futexes_are_keyed_apart_from_private_ones() {
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

        // Linux keys a private futex by address space and a shared one in shared memory by its
        // backing object, so neither kind of wake reaches the other kind of waiter.
        let waiter = spawn_waiter(&task, mapping + 8, FutexFlags::empty());
        assert_eq!(wake(&task, mapping + 8, FutexFlags::PRIVATE), 0);
        assert_eq!(wake(&task, mapping + 12, FutexFlags::empty()), 0);
        assert_eq!(
            wake_until_woken(|| Ok(wake(&task, mapping + 8, FutexFlags::empty()))),
            1
        );
        assert_eq!(waiter.join().unwrap(), Ok(0));

        let waiter = spawn_waiter(&task, mapping + 8, FutexFlags::PRIVATE);
        assert_eq!(wake(&task, mapping + 8, FutexFlags::empty()), 0);
        assert_eq!(
            wake_until_woken(|| Ok(wake(&task, mapping + 8, FutexFlags::PRIVATE))),
            1
        );
        assert_eq!(waiter.join().unwrap(), Ok(0));
    }

    #[test]
    fn each_shared_mapping_names_distinct_memory() {
        let task = init_platform();
        let first = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let second = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let (first, second) = (key(&task, first).unwrap(), key(&task, second).unwrap());
        assert_ne!(first.memory, second.memory);
        // Even when adjacent, distinct mappings stay distinct memory, each from offset zero.
        assert_eq!((first.offset, second.offset), (0, 0));
    }

    #[test]
    fn shared_futex_wait_checks_value_and_times_out() {
        let task = init_platform();
        let mapping = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        word(mapping).write_at_offset::<TestPlatform>(0, 1).unwrap();
        assert_eq!(
            wait(&task, mapping, 0, FutexFlags::empty(), None),
            Err(Errno::EAGAIN)
        );
        assert_eq!(
            wait(&task, mapping, 1, FutexFlags::empty(), Some(50)),
            Err(Errno::ETIMEDOUT)
        );
        // The timed-out waiter left the queue, and the thread's waiter can be reused.
        assert_eq!(wake(&task, mapping, FutexFlags::empty()), 0);
        assert_eq!(
            wait(&task, mapping, 1, FutexFlags::empty(), Some(10)),
            Err(Errno::ETIMEDOUT)
        );
    }

    #[test]
    fn bitset_ops_reject_empty_masks_and_wake_select_intersecting_ones() {
        let task = init_platform();
        let shared = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let private = map(&task, 1, MapFlags::MAP_PRIVATE).as_usize();
        let wake_bitset = |address: usize, bitmask: u32| {
            task.sys_futex(FutexArgs::WakeBitset {
                addr: word(address),
                flags: FutexFlags::empty(),
                count: WAKE_ALL,
                bitmask,
            })
        };
        for address in [shared, private] {
            assert_eq!(wake_bitset(address, 0), Err(Errno::EINVAL));
            assert_eq!(
                task.sys_futex(FutexArgs::WaitBitset {
                    addr: word(address),
                    flags: FutexFlags::empty(),
                    val: 0,
                    timeout: TimeParam::None,
                    bitmask: 0,
                }),
                Err(Errno::EINVAL)
            );
            let waiter = task.spawn_clone_for_test(move |task| {
                task.sys_futex(FutexArgs::WaitBitset {
                    addr: word(address),
                    flags: FutexFlags::empty(),
                    val: 0,
                    timeout: TimeParam::None,
                    bitmask: 0b01,
                })
            });
            std::thread::sleep(Duration::from_millis(100));
            assert_eq!(wake_bitset(address, 0b10), Ok(0));
            assert_eq!(wake_until_woken(|| wake_bitset(address, 0b11)), 1);
            assert_eq!(waiter.join().unwrap(), Ok(0));
        }
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

        task.sys_munmap(middle, PAGE_SIZE).unwrap();
        assert!(key(&task, start + PAGE_SIZE).is_none());
        assert_eq!(key(&task, start + 2 * PAGE_SIZE + 4), Some(tail));
        task.sys_munmap(mapping, 3 * PAGE_SIZE).unwrap();
        assert!(key(&task, start + 2 * PAGE_SIZE).is_none());
    }

    #[test]
    fn replacing_a_mapping_replaces_its_memory() {
        let task = init_platform();
        let start = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let memory = key(&task, start).unwrap().memory;
        let remap = |flags: MapFlags| {
            task.sys_mmap(
                start,
                PAGE_SIZE,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                flags | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            )
            .unwrap()
        };
        assert_eq!(remap(MapFlags::MAP_SHARED).as_usize(), start);
        assert_ne!(key(&task, start).unwrap().memory, memory);
        assert_eq!(remap(MapFlags::MAP_PRIVATE).as_usize(), start);
        assert!(key(&task, start).is_none());
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
    fn misaligned_shared_futex_fails_with_einval() {
        let task = init_platform();
        let mapping = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        // The word lies within the mapping, so only its alignment is wrong.
        let misaligned = mapping + 2;
        assert!(key(&task, misaligned).is_some());
        for count in [0, 1] {
            assert_eq!(
                task.sys_futex(FutexArgs::Wake {
                    addr: word(misaligned),
                    flags: FutexFlags::empty(),
                    count,
                }),
                Err(Errno::EINVAL)
            );
        }
        assert_eq!(
            wait(&task, misaligned, 0, FutexFlags::empty(), Some(10)),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn wake_with_zero_count_wakes_one_waiter() {
        let task = init_platform();
        let shared = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let private = map(&task, 1, MapFlags::MAP_PRIVATE).as_usize();
        // Linux's futex_wake counts a waiter before comparing with the count, so zero wakes one.
        for address in [shared, private] {
            let waiter = spawn_waiter(&task, address, FutexFlags::empty());
            let woken = wake_until_woken(|| {
                task.sys_futex(FutexArgs::Wake {
                    addr: word(address),
                    flags: FutexFlags::empty(),
                    count: 0,
                })
            });
            assert_eq!(woken, 1);
            assert_eq!(waiter.join().unwrap(), Ok(0));
        }
    }

    /// Wakes the word at `address` with `count`, with `FUTEX_WAKE_BITSET` and `bitmask` if it is
    /// `Some`.
    fn wake_with(
        task: &Task<TestPlatform>,
        address: usize,
        flags: FutexFlags,
        count: u32,
        bitmask: Option<u32>,
    ) -> Result<usize, Errno> {
        let addr = word(address);
        task.sys_futex(match bitmask {
            None => FutexArgs::Wake { addr, flags, count },
            Some(bitmask) => FutexArgs::WakeBitset {
                addr,
                flags,
                count,
                bitmask,
            },
        })
    }

    #[test]
    fn wake_with_negative_signed_count_wakes_one_waiter() {
        let task = init_platform();
        let shared = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let private = map(&task, 1, MapFlags::MAP_PRIVATE).as_usize();
        // Linux takes the count as an `int`, so a count past `i32::MAX` is negative, and like
        // zero wakes one waiter even when more match.
        for address in [shared, private] {
            for bitmask in [None, Some(u32::MAX)] {
                let waiters = [
                    spawn_waiter(&task, address, FutexFlags::empty()),
                    spawn_waiter(&task, address, FutexFlags::empty()),
                ];
                for count in [0x8000_0000, u32::MAX] {
                    let woken = wake_until_woken(|| {
                        wake_with(&task, address, FutexFlags::empty(), count, bitmask)
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
    fn futex_in_inaccessible_shared_memory_faults() {
        let task = init_platform();
        let shared = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let private = map(&task, 1, MapFlags::MAP_PRIVATE).as_usize();
        let protect = |address: usize, prot: ProtFlags| {
            task.sys_mprotect(UserPtrMut::from_usize(address), PAGE_SIZE, prot)
                .unwrap();
        };
        let waiter = spawn_waiter(&task, shared, FutexFlags::empty());
        protect(shared, ProtFlags::PROT_NONE);
        protect(private, ProtFlags::PROT_NONE);
        // The shared memory keeps its identity, but like Linux, a shared wake checks access
        // before looking at the waiters. Private wakes never look at the mapping.
        for count in [0, 1] {
            for bitmask in [None, Some(u32::MAX)] {
                let wake = |address, flags| wake_with(&task, address, flags, count, bitmask);
                assert_eq!(wake(shared, FutexFlags::empty()), Err(Errno::EFAULT));
                assert_eq!(wake(shared, FutexFlags::PRIVATE), Ok(0));
                assert_eq!(wake(private, FutexFlags::PRIVATE), Ok(0));
                // Alignment is checked first.
                assert_eq!(wake(shared + 2, FutexFlags::empty()), Err(Errno::EINVAL));
            }
        }
        assert_eq!(
            wait(&task, shared, 0, FutexFlags::empty(), Some(10)),
            Err(Errno::EFAULT)
        );

        // The faulting wakes left the waiter queued.
        protect(shared, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE);
        assert_eq!(
            wake_until_woken(|| wake_with(&task, shared, FutexFlags::empty(), 1, None)),
            1
        );
        assert_eq!(waiter.join().unwrap(), Ok(0));
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
}
