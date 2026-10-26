// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared anonymous memory, whose futexes span the processes that share it.
//!
//! Each guest `MAP_SHARED | MAP_ANONYMOUS` mapping gets broker [`SharedMemory`], which a native
//! fork child inherits along with the mapping's [shared pages](
//! litebox::platform::page_mgmt::AllocationOptions::SHARED). A futex
//! operation without `FUTEX_PRIVATE_FLAG` on such a mapping goes through the broker, keyed by the
//! memory and the futex word's offset in it, as Linux keys shared futexes by their backing
//! object. Every other futex stays in the process's private futex manager.
//!
//! Guest calls that change mappings update the recorded regions while holding the
//! [`SharedMappings`] lock, and anonymous mappings hold it across the change itself. Because file
//! mappings and `execve` change the memory manager outside the lock, a futex lookup also checks
//! that the memory manager still maps the word as shared anonymous memory.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Range;

use litebox::shared_memory::{SharedMemory, SharedMemoryError};
use litebox_broker_protocol::ObjectHandle;
use litebox_common_linux::errno::Errno;
use litebox_common_linux::mm::RangePiece;
use litebox_common_linux::program_startup::ForkSharedMemory;

use crate::{ShimPlatform, Task};

/// The shared memory each guest shared anonymous mapping, or what remains of it, refers to.
pub(crate) struct SharedMappings<Platform: ShimPlatform> {
    /// Mapped ranges by start address, which never overlap.
    regions: BTreeMap<usize, SharedRegion<Platform>>,
}

/// Memory references removed from [`SharedMappings`], which must be released only after its lock
/// is, since releasing one calls the broker.
#[must_use]
pub(super) struct ForgottenMemory<Platform: ShimPlatform>(Vec<Arc<SharedMemory<Platform>>>);

impl<Platform: ShimPlatform> Default for ForgottenMemory<Platform> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<Platform: ShimPlatform> ForgottenMemory<Platform> {
    fn append(&mut self, mut other: Self) {
        self.0.append(&mut other.0);
    }
}

struct SharedRegion<Platform: ShimPlatform> {
    end: usize,
    memory: Arc<SharedMemory<Platform>>,
    /// Offset in `memory` of the region's start.
    offset: u64,
}

impl<Platform: ShimPlatform> SharedMappings<Platform> {
    pub(crate) const fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
        }
    }

    /// Forgets the parts of regions within `range`, as when they are unmapped or replaced.
    pub(super) fn forget(&mut self, range: Range<usize>) -> ForgottenMemory<Platform> {
        let mut forgotten = Vec::new();
        if range.is_empty() {
            return ForgottenMemory(forgotten);
        }
        let overlapping: Vec<usize> = self
            .regions
            .range(..range.end)
            .rev()
            .take_while(|(_, region)| region.end > range.start)
            .map(|(&start, _)| start)
            .collect();
        for start in overlapping {
            let region = self.regions.remove(&start).unwrap();
            if start < range.start {
                self.regions.insert(
                    start,
                    SharedRegion {
                        end: range.start,
                        memory: Arc::clone(&region.memory),
                        offset: region.offset,
                    },
                );
            }
            if region.end > range.end {
                self.regions.insert(
                    range.end,
                    SharedRegion {
                        end: region.end,
                        memory: Arc::clone(&region.memory),
                        offset: region.offset + (range.end - start) as u64,
                    },
                );
            }
            forgotten.push(region.memory);
        }
        ForgottenMemory(forgotten)
    }

    /// Forgets every region, as `execve` replaces every mapping.
    pub(super) fn forget_all(&mut self) -> ForgottenMemory<Platform> {
        ForgottenMemory(
            core::mem::take(&mut self.regions)
                .into_values()
                .map(|region| region.memory)
                .collect(),
        )
    }

    fn insert(
        &mut self,
        range: Range<usize>,
        memory: Arc<SharedMemory<Platform>>,
        offset: u64,
    ) -> ForgottenMemory<Platform> {
        let forgotten = self.forget(range.clone());
        self.regions.insert(
            range.start,
            SharedRegion {
                end: range.end,
                memory,
                offset,
            },
        );
        forgotten
    }

    /// Returns the memory holding the futex word at `address`, and the word's offset in it.
    fn lookup(&self, address: usize) -> Option<(Arc<SharedMemory<Platform>>, u64)> {
        let (&start, region) = self.regions.range(..=address).next_back()?;
        let end = address.checked_add(size_of::<u32>())?;
        (end <= region.end).then(|| {
            (
                Arc::clone(&region.memory),
                region.offset + (address - start) as u64,
            )
        })
    }

    /// Records the shared memory a native fork child inherited, as described by `records`,
    /// adopting each handle once however many records share it.
    pub(crate) fn adopt_inherited(
        &mut self,
        litebox: &litebox::LiteBox<Platform>,
        records: &[ForkSharedMemory],
    ) -> Result<(), litebox::process::ProcessError> {
        let mut adopted: BTreeMap<ObjectHandle, Arc<SharedMemory<Platform>>> = BTreeMap::new();
        for record in records {
            let memory = if let Some(memory) = adopted.get(&record.handle) {
                Arc::clone(memory)
            } else {
                let memory = Arc::new(litebox.adopt_inherited_shared_memory(record.handle)?);
                adopted.insert(record.handle, Arc::clone(&memory));
                memory
            };
            // Records never overlap, so nothing is forgotten.
            let _ = self.insert(record.range.clone(), memory, record.offset);
        }
        Ok(())
    }
}

/// Shared memory a native fork child inherits.
pub(super) struct InheritedSharedMappings<Platform: ShimPlatform> {
    /// Each memory once, however many regions refer to it.
    pub(super) memories: Vec<Arc<SharedMemory<Platform>>>,
    /// Each region's range, offset in its memory, and index of its memory in `memories`.
    regions: Vec<(Range<usize>, u64, usize)>,
}

impl<Platform: ShimPlatform> InheritedSharedMappings<Platform> {
    /// Returns the startup records of the regions, given the child's handle to each memory in
    /// the order of `memories`, or placeholder handles if `handles` is empty.
    pub(super) fn records(&self, handles: &[ObjectHandle]) -> Vec<ForkSharedMemory> {
        self.regions
            .iter()
            .map(|(range, offset, index)| ForkSharedMemory {
                range: range.clone(),
                offset: *offset,
                handle: handles.get(*index).copied().unwrap_or_default(),
            })
            .collect()
    }
}

impl<Platform: ShimPlatform> Task<Platform> {
    /// Creates the broker shared memory for a new shared anonymous mapping of `len` bytes, before
    /// the mapping and its [`SharedMappings`] lock, since creating it calls the broker.
    ///
    /// Returns `None` without a broker, as then no other process can share the memory either.
    /// Fails with `ENOMEM`, as `mmap` reports any failure to back a mapping, if the broker fails.
    pub(super) fn create_shared_memory_for_mapping(
        &self,
        len: usize,
    ) -> Result<Option<Arc<SharedMemory<Platform>>>, Errno> {
        match SharedMemory::new(&self.global.litebox, len as u64) {
            Ok(memory) => Ok(Some(Arc::new(memory))),
            Err(SharedMemoryError::Unavailable) => Ok(None),
            Err(_) => Err(Errno::ENOMEM),
        }
    }

    /// Records a guest mapping of `range` that just replaced whatever was mapped there, backed by
    /// `memory` if it is shared anonymous memory.
    pub(super) fn record_new_mapping(
        &self,
        mappings: &mut SharedMappings<Platform>,
        range: Range<usize>,
        memory: Option<Arc<SharedMemory<Platform>>>,
    ) -> ForgottenMemory<Platform> {
        let mut forgotten = mappings.forget(range.clone());
        if let Some(memory) = memory {
            if self.global.mm.range_is_shared_anonymous(range.clone()) {
                let replaced = mappings.insert(range, memory, 0);
                debug_assert!(replaced.0.is_empty());
            } else {
                forgotten.0.push(memory);
            }
        }
        forgotten
    }

    /// Forgets the shared memory of the parts of `range` that are no longer shared anonymous
    /// mappings, keeping the rest.
    pub(super) fn forget_unshared_mappings(
        &self,
        mappings: &mut SharedMappings<Platform>,
        range: Range<usize>,
    ) -> ForgottenMemory<Platform> {
        let mut forgotten = ForgottenMemory::default();
        for (piece, kind) in self.global.mm.range_pieces(range) {
            if kind
                != (RangePiece::Mapped {
                    shared_anonymous: true,
                })
            {
                forgotten.append(mappings.forget(piece));
            }
        }
        forgotten
    }

    /// Returns the broker shared memory holding the futex word at `address`, and the word's
    /// offset in it, if the word is in a shared anonymous mapping.
    ///
    /// Takes the [`SharedMappings`] lock, so its caller must not hold it.
    pub(super) fn shared_futex_key(
        &self,
        address: usize,
    ) -> Option<(Arc<SharedMemory<Platform>>, u64)> {
        let mappings = self.global.shared_mappings.lock();
        let found = mappings.lookup(address)?;
        self.global
            .mm
            .range_is_shared_anonymous(address..address + size_of::<u32>())
            .then_some(found)
    }

    /// Returns the shared memory a native fork child inherits.
    pub(super) fn shared_mappings_for_fork(&self) -> InheritedSharedMappings<Platform> {
        let mappings = self.global.shared_mappings.lock();
        let mut memories: Vec<Arc<SharedMemory<Platform>>> = Vec::new();
        let mut indices: BTreeMap<*const SharedMemory<Platform>, usize> = BTreeMap::new();
        let mut regions = Vec::new();
        for (&start, region) in &mappings.regions {
            // Regions split from one mapping share their memory, which the child inherits once.
            let index = *indices
                .entry(Arc::as_ptr(&region.memory))
                .or_insert_with(|| {
                    memories.push(Arc::clone(&region.memory));
                    memories.len() - 1
                });
            regions.push((start..region.end, region.offset, index));
        }
        InheritedSharedMappings { memories, regions }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::time::Duration;

    use litebox_common_linux::errno::Errno;
    use litebox_common_linux::{
        FutexArgs, FutexFlags, MRemapFlags, MadviseBehavior, MapFlags, PAGE_SIZE, ProtFlags,
        TimeParam,
    };

    use alloc::sync::Arc;

    use litebox_common_linux::program_startup::ForkSharedMemory;

    use super::SharedMappings;
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
        assert!(task.shared_futex_key(private).is_none());
        assert!(task.shared_futex_key(private + 4).is_none());
        let (memory, offset) = task.shared_futex_key(mapping + 8).unwrap();
        assert_eq!(offset, 8);
        // A word must lie entirely within the mapping.
        assert!(
            task.shared_futex_key(mapping + PAGE_SIZE - 4).is_some()
                && task.shared_futex_key(mapping + PAGE_SIZE - 2).is_none()
        );
        drop(memory);

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
    fn unmapping_splits_shared_memory_and_keeps_offsets() {
        let task = init_platform();
        let mapping = map(&task, 3, MapFlags::MAP_SHARED);
        let start = mapping.as_usize();
        let (memory, _) = task.shared_futex_key(start).unwrap();
        task.sys_munmap(UserPtrMut::from_usize(start + PAGE_SIZE), PAGE_SIZE)
            .unwrap();
        assert!(task.shared_futex_key(start + PAGE_SIZE).is_none());
        let (tail_memory, offset) = task.shared_futex_key(start + 2 * PAGE_SIZE + 4).unwrap();
        assert!(alloc::sync::Arc::ptr_eq(&memory, &tail_memory));
        assert_eq!(offset, 2 * PAGE_SIZE as u64 + 4);

        task.sys_munmap(mapping, PAGE_SIZE).unwrap();
        let replaced = task
            .sys_mmap(
                start,
                PAGE_SIZE,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                -1,
                0,
            )
            .unwrap();
        assert_eq!(replaced.as_usize(), start);
        assert!(task.shared_futex_key(start).is_none());

        task.sys_munmap(mapping, 3 * PAGE_SIZE).unwrap();
        assert!(task.shared_futex_key(start + 2 * PAGE_SIZE).is_none());
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
        // Known limitation: Linux grows shared anonymous mappings (mremap(2)), but LiteBox cannot
        // grow their broker shared memory, so it refuses.
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
        assert!(task.shared_futex_key(start).is_some());
        assert!(task.shared_futex_key(start + PAGE_SIZE).is_none());
        task.sys_munmap(mapping, PAGE_SIZE).unwrap();
    }

    #[test]
    fn exec_forgets_shared_memory() {
        let task = init_platform();
        let start = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let forgotten = task.global.shared_mappings.lock().forget_all();
        assert_eq!(forgotten.0.len(), 1);
        drop(forgotten);
        assert!(task.shared_futex_key(start).is_none());
    }

    #[test]
    fn shared_anonymous_range_spans_split_areas_but_not_gaps() {
        let task = init_platform();
        let mapping = map(&task, 3, MapFlags::MAP_SHARED);
        let start = mapping.as_usize();
        let mm = &task.global.mm;
        // Changing the protection of part of the mapping splits its area.
        task.sys_mprotect(
            UserPtrMut::from_usize(start + PAGE_SIZE),
            PAGE_SIZE,
            ProtFlags::PROT_READ,
        )
        .unwrap();
        assert!(mm.range_is_shared_anonymous(start..start + 3 * PAGE_SIZE));
        assert!(!mm.has_unforkable_shared_mappings());
        task.sys_munmap(UserPtrMut::from_usize(start + PAGE_SIZE), PAGE_SIZE)
            .unwrap();
        assert!(!mm.range_is_shared_anonymous(start..start + 3 * PAGE_SIZE));
        assert!(mm.range_is_shared_anonymous(start + 2 * PAGE_SIZE..start + 3 * PAGE_SIZE));
        let private = map(&task, 1, MapFlags::MAP_PRIVATE).as_usize();
        assert!(!mm.range_is_shared_anonymous(private..private + PAGE_SIZE));
        task.sys_munmap(mapping, 3 * PAGE_SIZE).unwrap();
    }

    #[test]
    fn unmap_progress_preserves_shared_records_for_remaining_pages() {
        let task = init_platform();
        let first = map(&task, 2, MapFlags::MAP_SHARED).as_usize();
        let second = map(&task, 2, MapFlags::MAP_SHARED).as_usize();
        let (lower, upper) = (first.min(second), first.max(second));
        task.sys_munmap(UserPtrMut::from_usize(lower), upper - lower + PAGE_SIZE)
            .unwrap();
        assert!(task.shared_futex_key(upper).is_none());
        assert!(task.shared_futex_key(lower).is_none());
        assert!(task.shared_futex_key(upper + PAGE_SIZE).is_some());
        let mappings = task.global.shared_mappings.lock();
        assert!(mappings.lookup(lower).is_none());
        assert!(mappings.lookup(upper + PAGE_SIZE).is_some());
        drop(mappings);
        task.sys_munmap(UserPtrMut::from_usize(upper), 2 * PAGE_SIZE)
            .unwrap();
    }

    #[test]
    fn inherited_memory_is_adopted_once_for_every_region() {
        let task = init_platform();
        let litebox = &task.global.litebox;
        // Adopting makes no broker request, so any handle stands in for an inherited one.
        let handle = litebox_broker_protocol::ObjectHandle(u64::MAX);
        let records = [
            ForkSharedMemory {
                range: 0x10_0000..0x10_1000,
                offset: 0,
                handle,
            },
            ForkSharedMemory {
                range: 0x10_2000..0x10_3000,
                offset: 2 * PAGE_SIZE as u64,
                handle,
            },
        ];
        let mut mappings = SharedMappings::new();
        mappings.adopt_inherited(litebox, &records).unwrap();
        let (first, first_offset) = mappings.lookup(0x10_0008).unwrap();
        let (second, second_offset) = mappings.lookup(0x10_2008).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!((first_offset, second_offset), (8, 2 * PAGE_SIZE as u64 + 8));
        assert!(mappings.lookup(0x10_1000).is_none());
        drop((first, second));
        let forgotten = mappings.forget_all();
        assert_eq!(forgotten.0.len(), 2);
        assert!(Arc::ptr_eq(&forgotten.0[0], &forgotten.0[1]));
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
    fn forgetting_unshared_mappings_keeps_shared_ones() {
        let task = init_platform();
        let shared = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        let range = shared - PAGE_SIZE..shared + 2 * PAGE_SIZE;
        let forgotten =
            task.forget_unshared_mappings(&mut task.global.shared_mappings.lock(), range.clone());
        drop(forgotten);
        assert!(task.shared_futex_key(shared).is_some());

        task.sys_munmap(UserPtrMut::from_usize(shared), PAGE_SIZE)
            .unwrap();
        // Unmapping already forgot the memory; forgetting again finds nothing.
        let forgotten =
            task.forget_unshared_mappings(&mut task.global.shared_mappings.lock(), range);
        assert!(forgotten.0.is_empty());
    }

    #[test]
    fn misaligned_shared_futex_fails_with_einval() {
        let task = init_platform();
        let mapping = map(&task, 1, MapFlags::MAP_SHARED).as_usize();
        // The word lies within the mapping, so only its alignment is wrong.
        let misaligned = mapping + 2;
        assert!(task.shared_futex_key(misaligned).is_some());
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
