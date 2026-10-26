// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Futexes in shared anonymous memory, which span the processes that share it.
//!
//! Each guest `MAP_SHARED | MAP_ANONYMOUS` mapping names its memory with a fresh
//! [`SharedMemoryId`], which the memory manager records with the mapping, so a native fork child
//! that inherits the mapping inherits the name too. A futex operation without
//! `FUTEX_PRIVATE_FLAG` on such a mapping goes through the broker, keyed by the name and the
//! futex word's offset in the memory, as Linux keys shared futexes by their backing object.
//! Every other futex stays in the process's private futex manager.

use litebox::sync::futex::shared::SharedFutexError;
use litebox_broker_protocol::shared_futex::SharedMemoryId;
use litebox_common_linux::vmem::MappingError;

use crate::{ShimPlatform, Task};

impl<Platform: ShimPlatform> Task<Platform> {
    /// Returns a new name for the memory of a shared anonymous mapping, or `None` without a
    /// broker, as then no other process can share the memory either.
    ///
    /// Fails with [`MappingError::OutOfMemory`], as `mmap` reports any failure to back a mapping
    /// with `ENOMEM`, if the broker fails.
    pub(super) fn new_shared_memory_id(&self) -> Result<Option<SharedMemoryId>, MappingError> {
        match self.global.shared_memory_ids.allocate(&self.global.litebox) {
            Ok(id) => Ok(Some(id)),
            Err(SharedFutexError::Unavailable) => Ok(None),
            Err(_) => Err(MappingError::OutOfMemory),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::time::Duration;

    use litebox_broker_protocol::shared_futex::SharedFutexKey;
    use litebox_common_linux::errno::Errno;
    use litebox_common_linux::{
        FutexArgs, FutexFlags, MRemapFlags, MadviseBehavior, MapFlags, PAGE_SIZE, ProtFlags,
        TimeParam,
    };

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
        task.global.mm.shared_futex_key(address)
    }

    fn word(address: usize) -> UserPtrMut<u32> {
        UserPtrMut::from_usize(address)
    }

    fn wake(task: &Task<TestPlatform>, address: usize, flags: FutexFlags) -> usize {
        task.sys_futex(FutexArgs::Wake {
            addr: word(address),
            flags,
            count: u32::MAX,
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

    /// Spawns a thread of `task`'s process that waits on the word at `address` with `flags`
    /// until it is woken, and gives it time to arm its waiter.
    fn spawn_waiter(
        task: &Task<TestPlatform>,
        address: usize,
        flags: FutexFlags,
    ) -> std::thread::JoinHandle<Result<usize, Errno>> {
        let waiter = task.spawn_clone_for_test(move |task| wait(&task, address, 0, flags, None));
        // The waiter cannot report when it sleeps, so give it time to.
        std::thread::sleep(Duration::from_millis(100));
        waiter
    }

    #[test]
    fn shared_futex_in_shared_mapping_goes_through_broker() {
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
        assert_eq!(wake(&task, mapping + 8, FutexFlags::empty()), 1);
        assert_eq!(waiter.join().unwrap(), Ok(0));

        // A private waiter is woken only by a private wake.
        let waiter = spawn_waiter(&task, mapping + 8, FutexFlags::PRIVATE);
        assert_eq!(wake(&task, mapping + 8, FutexFlags::empty()), 0);
        assert_eq!(wake(&task, mapping + 8, FutexFlags::PRIVATE), 1);
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
    fn plain_wake_matches_any_wait_bitset() {
        let task = init_platform();
        let mapping = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let waiter = task.spawn_clone_for_test(move |task| {
            task.sys_futex(FutexArgs::WaitBitset {
                addr: word(mapping),
                flags: FutexFlags::empty(),
                val: 0,
                timeout: TimeParam::None,
                bitmask: 0b10,
            })
        });
        std::thread::sleep(Duration::from_millis(100));
        // A plain wake matches every mask.
        assert_eq!(wake(&task, mapping, FutexFlags::empty()), 1);
        assert_eq!(waiter.join().unwrap(), Ok(0));
    }

    #[test]
    fn bitset_wakes_select_intersecting_masks_and_reject_empty_ones() {
        let task = init_platform();
        let shared = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let private = map(&task, 1, MapFlags::MAP_PRIVATE).as_usize();
        let wake_bitset = |address: usize, bitmask: u32| {
            task.sys_futex(FutexArgs::WakeBitset {
                addr: word(address),
                flags: FutexFlags::empty(),
                count: u32::MAX,
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
            assert_eq!(wake_bitset(address, 0b11), Ok(1));
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
    fn shared_memory_survives_madvise() {
        let task = init_platform();
        let mapping = map(&task, 2, MapFlags::MAP_SHARED);
        mapping.write_at_offset::<TestPlatform>(0, 42).unwrap();
        task.sys_madvise(mapping, PAGE_SIZE, MadviseBehavior::DontNeed)
            .unwrap();
        // Like Linux shared memory, the contents remain for every process sharing them.
        assert_eq!(mapping.read_at_offset::<TestPlatform>(0), Some(42));
        task.sys_munmap(mapping, 2 * PAGE_SIZE).unwrap();
    }

    #[test]
    fn shared_memory_can_shrink_but_unlike_linux_cannot_grow() {
        let task = init_platform();
        let mapping = map(&task, 2, MapFlags::MAP_SHARED);
        let start = mapping.as_usize();
        let start_key = key(&task, start);
        // Known limitation: Linux grows shared anonymous mappings (mremap(2)), but LiteBox
        // refuses.
        for flags in [MRemapFlags::empty(), MRemapFlags::MREMAP_MAYMOVE] {
            assert_eq!(
                task.sys_mremap(mapping, 2 * PAGE_SIZE, 4 * PAGE_SIZE, flags, 0)
                    .err(),
                Some(Errno::ENOMEM)
            );
        }
        let shrunk = task
            .sys_mremap(mapping, 2 * PAGE_SIZE, PAGE_SIZE, MRemapFlags::empty(), 0)
            .unwrap();
        assert_eq!(shrunk.as_usize(), start);
        assert_eq!(key(&task, start), start_key);
        assert!(key(&task, start + PAGE_SIZE).is_none());
        task.sys_munmap(mapping, PAGE_SIZE).unwrap();
    }

    #[test]
    fn broker_failure_wakes_shared_futex_waiter_with_error() {
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
        assert_eq!(
            task.sys_futex(FutexArgs::Wake {
                addr: word(misaligned),
                flags: FutexFlags::empty(),
                count: 1,
            }),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            wait(&task, misaligned, 0, FutexFlags::empty(), Some(10)),
            Err(Errno::EINVAL)
        );
    }
}
