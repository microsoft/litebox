// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::super::{ElfPatchKey, MRemapFlags, PAGE_SIZE};
use super::*;
use crate::syscalls::tests::{TestPlatform, create_file, init_platform};
use litebox_broker_protocol::fs::FileMode;
use litebox_common_linux::OFlags;

// Keep the general fixtures guest-page-sized, including their file offsets.
fn image() -> Vec<u8> {
    image_with_gap(PAGE_SIZE)
}

// Two LOADs with a gap of the requested granule, without sections. Only tests
// requiring a real host-page hole use HOST_PAGE_SIZE; the site count stays fixed.
fn image_with_gap(granule: usize) -> Vec<u8> {
    let mut bytes = alloc::vec![0; 4 * granule];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (offset, value) in [(16, 3u16), (18, 183), (52, 64), (54, 56), (56, 2)] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    for (i, offset, size) in [(0, 0, 2 * granule), (1, 3 * granule, granule)] {
        let at = 64 + i * 56;
        bytes[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&5u32.to_le_bytes());
        for (field, value) in [
            (8, offset),
            (16, offset),
            (32, size),
            (40, size),
            (48, granule),
        ] {
            bytes[at + field..at + field + 8].copy_from_slice(&(value as u64).to_le_bytes());
        }
    }
    for at in (PAGE_SIZE..2 * PAGE_SIZE).step_by(4) {
        bytes[at..at + 4].copy_from_slice(&0xd4000001u32.to_le_bytes());
    }
    bytes[3 * granule..3 * granule + 4].copy_from_slice(&0xd4000001u32.to_le_bytes());
    bytes
}

fn open(task: &Task<TestPlatform>, path: &str) -> i32 {
    i32::try_from(
        task.sys_open(path, OFlags::RDONLY, FileMode::empty())
            .unwrap(),
    )
    .unwrap()
}

fn open_image(task: &Task<TestPlatform>, path: &str, bytes: &[u8]) -> (i32, ElfPatchKey) {
    create_file(task, path, bytes);
    let fd = open(task, path);
    (fd, super::super::tests::elf_patch_key(task, fd))
}

fn map_file(task: &Task<TestPlatform>, fd: i32, len: usize, prot: ProtFlags) -> UserPtrMut<u8> {
    task.sys_mmap(0, len, prot, MapFlags::MAP_PRIVATE, fd, 0)
        .unwrap()
}

fn read_bytes(address: usize, len: usize) -> Vec<u8> {
    UserPtrMut::<u8>::from_usize(address)
        .to_owned_slice::<TestPlatform>(len)
        .unwrap()
        .into_vec()
}

#[test]
fn biased_load_overflow_does_not_poison_unrelated_exec_mappings() {
    let task = init_platform();
    let mut malformed = sparse_image();
    // The second LOAD fits in u64 at bias zero, but not at the mapped bias.
    malformed[136..144].copy_from_slice(&(usize::MAX - 2 * PAGE_SIZE + 1).to_le_bytes());
    create_file(&task, "/overflow-load", &malformed);
    let fd = open(&task, "/overflow-load");
    let bad = task
        .sys_mmap(
            0,
            PAGE_SIZE,
            ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE,
            fd,
            0,
        )
        .unwrap();
    let key = super::super::tests::elf_patch_key(&task, fd);
    create_file(&task, "/valid-after-overflow", &sparse_image());
    let valid_fd = open(&task, "/valid-after-overflow");
    let valid = task
        .sys_mmap(
            0,
            4 * PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC,
            MapFlags::MAP_PRIVATE,
            valid_fd,
            0,
        )
        .unwrap();
    task.sys_mprotect(valid, PAGE_SIZE, ProtFlags::PROT_READ)
        .unwrap();
    task.sys_mprotect(valid, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = &cache.get(&key).unwrap().islands;
        assert_eq!(state.mappings[0].bias, None);
        assert!(state.future_loads().unwrap().is_empty());
    }
    task.sys_munmap(valid, 4 * PAGE_SIZE).unwrap();
    task.sys_munmap(bad, PAGE_SIZE).unwrap();
}

#[test]
fn huge_sparse_gap_walk_is_bounded_by_whole_pair_reach() {
    let far = 1usize << 47;
    let allowed = far + 1..=far + 3 * HOST_PAGE_SIZE;
    let mut attempts = 0;
    let pages: Vec<_> = island_pages(HOST_PAGE_SIZE..1usize << 48, &allowed)
        .inspect(|_| attempts += 1)
        .collect();
    assert_eq!(attempts, 3);
    assert_eq!(
        pages,
        [
            far + HOST_PAGE_SIZE,
            far + 2 * HOST_PAGE_SIZE,
            far + 3 * HOST_PAGE_SIZE
        ]
    );
    assert_eq!(
        island_pages(far..far + HOST_PAGE_SIZE - 1, &(far..=far)).count(),
        0
    );
    assert_eq!(
        island_pages(0..usize::MAX, &(usize::MAX..=usize::MAX)).count(),
        0
    );
}

#[test]
fn close_then_exec_growth_multiple_bases_and_partial_unmap() {
    let task = init_platform();
    create_file(&task, "/island-lifecycle", &image());
    let fd = open(&task, "/island-lifecycle");
    let key = super::super::tests::elf_patch_key(&task, fd);
    let first = task
        .sys_mmap(
            0,
            4 * PAGE_SIZE,
            ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE,
            fd,
            0,
        )
        .unwrap();
    let second = task
        .sys_mmap(
            0,
            PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC,
            MapFlags::MAP_PRIVATE,
            fd,
            3 * PAGE_SIZE,
        )
        .unwrap();
    task.sys_close(fd).unwrap();
    task.sys_mprotect(
        UserPtrMut::from_usize(first.as_usize() + PAGE_SIZE),
        PAGE_SIZE,
        ProtFlags::PROT_READ_EXEC,
    )
    .unwrap();
    let pairs = {
        let cache = task.global.elf_patch_cache.lock();
        let state = cache.get(&key).unwrap();
        assert!(
            state.islands.pairs.len() > 6,
            "runtime sites exceed one island"
        );
        assert_ne!(
            state.islands.mappings[0].bias,
            state.islands.mappings[1].bias
        );
        state.islands.owned_ranges().collect::<Vec<_>>()
    };
    // A one-page ELF hole may now contain an island. Loader PROT_NONE cannot
    // revoke any published transport page, including far chunks.
    for range in &pairs {
        task.sys_mprotect(
            UserPtrMut::from_usize(range.start),
            range.len(),
            ProtFlags::PROT_NONE,
        )
        .unwrap();
        assert!(
            task.global
                .mm
                .mappings()
                .iter()
                .any(|(r, flags)| r.contains(&range.start) && flags.contains(VmFlags::VM_EXEC))
        );
        assert_eq!(
            task.sys_munmap(UserPtrMut::from_usize(range.start), range.len()),
            Err(Errno::EBUSY)
        );
    }
    assert!(matches!(
        task.sys_mremap(
            first,
            4 * PAGE_SIZE,
            5 * PAGE_SIZE,
            MRemapFlags::MREMAP_MAYMOVE,
            0
        ),
        Err(Errno::EINVAL)
    ));
    // Remove just the first page; the right fragment keeps offset PAGE_SIZE.
    task.sys_munmap(first, PAGE_SIZE).unwrap();
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = cache.get(&key).unwrap();
        let m = state
            .islands
            .mapping(first.as_usize() + PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        assert_eq!(m.offset, PAGE_SIZE);
        assert_eq!(m.range.start, first.as_usize() + PAGE_SIZE);
    }
    // Raw fd reuse must not consume the old retained descriptor identity.
    create_file(&task, "/island-lifecycle-other", &image());
    let reused = open(&task, "/island-lifecycle-other");
    assert_eq!(reused, fd, "exercise actual raw-fd reuse");
    let reused_key = super::super::tests::elf_patch_key(&task, reused);
    assert_ne!(key, reused_key);
    let other_mapping = task
        .sys_mmap(
            0,
            PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC,
            MapFlags::MAP_PRIVATE,
            reused,
            3 * PAGE_SIZE,
        )
        .unwrap();
    task.sys_close(reused).unwrap();
    {
        let cache = task.global.elf_patch_cache.lock();
        assert!(cache.contains_key(&key));
        assert!(!cache.get(&reused_key).unwrap().islands.pairs.is_empty());
    }
    task.sys_munmap(other_mapping, PAGE_SIZE).unwrap();
    task.sys_munmap(
        UserPtrMut::from_usize(first.as_usize() + PAGE_SIZE),
        3 * PAGE_SIZE,
    )
    .unwrap();
    assert!(task.global.elf_patch_cache.lock().contains_key(&key));
    task.sys_munmap(second, PAGE_SIZE).unwrap();
    assert!(!task.global.elf_patch_cache.lock().contains_key(&key));
    for range in pairs {
        assert!(
            !task
                .global
                .mm
                .mappings()
                .iter()
                .any(|(r, _)| overlaps(r, &range))
        );
    }
}

#[test]
fn failed_writable_mprotect_rescans_sites_without_retiring_pairs() {
    let task = init_platform();
    create_file(&task, "/island-mprotect", &image());
    create_file(&task, "/island-readonly", &alloc::vec![0; PAGE_SIZE]);
    let fd = open(&task, "/island-mprotect");
    let readonly_fd = open(&task, "/island-readonly");
    let key = super::super::tests::elf_patch_key(&task, fd);
    let reserved = task
        .sys_mmap(
            0,
            3 * PAGE_SIZE,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            -1,
            0,
        )
        .unwrap();
    let code = task
        .sys_mmap(
            reserved.as_usize() + PAGE_SIZE,
            PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            fd,
            3 * PAGE_SIZE,
        )
        .unwrap();
    for offset in [0, 2 * PAGE_SIZE] {
        task.sys_mmap(
            reserved.as_usize() + offset,
            PAGE_SIZE,
            ProtFlags::PROT_READ,
            MapFlags::MAP_SHARED | MapFlags::MAP_FIXED,
            readonly_fd,
            0,
        )
        .unwrap();
    }
    task.sys_close(fd).unwrap();
    task.sys_close(readonly_fd).unwrap();
    let original = code.to_owned_slice::<TestPlatform>(PAGE_SIZE).unwrap();
    assert_eq!(
        u32::from_le_bytes(original[..4].try_into().unwrap()) & 0xfc000000,
        0x14000000
    );
    let pairs = {
        let cache = task.global.elf_patch_cache.lock();
        let state = cache.get(&key).unwrap();
        assert!(state.patched_ranges.contains(&(code.as_usize(), PAGE_SIZE)));
        state
            .islands
            .pairs
            .iter()
            .map(|p| (p.near.clone(), p.far.clone(), p.sites.clone()))
            .collect::<Vec<_>>()
    };
    let transport = pairs
        .iter()
        .flat_map(|(near, far, _)| [near, far])
        .map(|range| {
            let bytes = UserPtrMut::<u8>::from_usize(range.start)
                .to_owned_slice::<TestPlatform>(range.len())
                .unwrap();
            (range.clone(), bytes)
        })
        .collect::<Vec<_>>();

    // Invalid arguments and W^X refusal are side-effect-free preflight checks.
    let before = task.global.mm.mappings();
    assert_eq!(
        task.sys_mprotect(code, PAGE_SIZE - 1, ProtFlags::PROT_READ_WRITE),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        task.sys_mprotect(code, PAGE_SIZE, ProtFlags::PROT_READ_WRITE_EXEC),
        Err(Errno::EACCES)
    );
    assert_eq!(task.global.mm.mappings(), before);
    assert!(
        task.global.elf_patch_cache.lock()[&key]
            .patched_ranges
            .contains(&(code.as_usize(), PAGE_SIZE))
    );
    // The first shared page rejects +W before any permissions change. The
    // conservative invalidation must still allow an unchanged page's next +X.
    assert_eq!(
        task.sys_mprotect(reserved, 3 * PAGE_SIZE, ProtFlags::PROT_READ_WRITE),
        Err(Errno::EACCES)
    );
    assert_eq!(task.global.mm.mappings(), before);
    task.sys_mprotect(code, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    assert_eq!(
        code.to_owned_slice::<TestPlatform>(PAGE_SIZE)
            .unwrap()
            .as_ref(),
        original.as_ref()
    );

    // Starting at the RX ELF page changes it to RW before the trailing shared
    // page rejects +W. Replacing B with SVC must invalidate the exact-range hit.
    assert_eq!(
        task.sys_mprotect(code, 2 * PAGE_SIZE, ProtFlags::PROT_READ_WRITE),
        Err(Errno::EACCES)
    );
    assert!(task.global.mm.mappings().iter().any(|(range, flags)| {
        range.contains(&code.as_usize())
            && flags.contains(VmFlags::VM_READ | VmFlags::VM_WRITE)
            && !flags.contains(VmFlags::VM_EXEC)
    }));
    code.copy_from_slice::<TestPlatform>(0, &0xd4000001u32.to_le_bytes())
        .unwrap();
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = cache.get(&key).unwrap();
        assert!(!state.patched_ranges.contains(&(code.as_usize(), PAGE_SIZE)));
        assert_eq!(state.islands.pairs.len(), pairs.len());
    }
    task.sys_mprotect(code, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    let rewritten = code.to_owned_slice::<TestPlatform>(4).unwrap();
    assert_eq!(
        u32::from_le_bytes(rewritten.as_ref().try_into().unwrap()) & 0xfc000000,
        0x14000000,
        "the replacement SVC must not be left executable"
    );
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = cache.get(&key).unwrap();
        assert!(state.patched_ranges.contains(&(code.as_usize(), PAGE_SIZE)));
        assert!(state.islands.pairs.len() > pairs.len());
        for (pair, (near, far, sites)) in state.islands.pairs.iter().zip(&pairs) {
            assert_eq!((&pair.near, &pair.far, &pair.sites), (near, far, sites));
        }
    }
    for (range, bytes) in transport {
        assert_eq!(
            UserPtrMut::<u8>::from_usize(range.start)
                .to_owned_slice::<TestPlatform>(range.len())
                .unwrap()
                .as_ref(),
            bytes.as_ref(),
            "old referenced pairs must stay mapped and immutable"
        );
    }
    task.sys_munmap(reserved, 3 * PAGE_SIZE).unwrap();
}

#[test]
fn mapping_fragments_keep_offsets_and_pair_references() {
    let mut state = RuntimeIslands::default();
    state.mappings.push(FileMapping {
        range: 0x1000..0x5000,
        offset: 0x9000,
        bias: Some(0),
        loader_managed: false,
    });
    state.pairs.push(PublishedPair {
        near: 0x6000..0x7000,
        far: 0x1_0000_0000..0x1_0000_5000,
        sites: alloc::vec![0x1004, 0x4004],
        previous: None,
        serialized: None,
        prefix_bias: None,
    });
    assert!(!state.permits_removal(&(0x6000..0x7000)));
    assert!(state.remove(&(0x2000..0x3000)).is_empty());
    assert_eq!(state.mappings[1].offset, 0xb000);
    assert!(state.remove(&(0x1000..0x2000)).is_empty());
    assert_eq!(state.pairs[0].sites, [0x4004]);
    assert_eq!(state.remove(&(0x4000..0x5000)).len(), 2);
    assert!(state.pairs.is_empty());
}

#[test]
fn overlapping_load_coverage_keeps_every_future_segment_out_of_gaps() {
    let state = RuntimeIslands {
        loads: alloc::vec![
            Load {
                file: 0..PAGE_SIZE,
                address: 0..4 * HOST_PAGE_SIZE
            },
            Load {
                file: PAGE_SIZE..3 * PAGE_SIZE,
                address: HOST_PAGE_SIZE..2 * HOST_PAGE_SIZE
            },
            Load {
                file: 3 * PAGE_SIZE..4 * PAGE_SIZE,
                address: 5 * HOST_PAGE_SIZE..6 * HOST_PAGE_SIZE
            },
            Load {
                file: 4 * PAGE_SIZE..5 * PAGE_SIZE,
                address: 7 * HOST_PAGE_SIZE..8 * HOST_PAGE_SIZE
            },
        ],
        ..Default::default()
    };
    let bias = 0x10000000;
    let coverage = state.load_coverage(bias).unwrap();
    assert_eq!(
        subtract_ranges(bias..bias + 8 * HOST_PAGE_SIZE, &coverage),
        alloc::vec![
            bias + 4 * HOST_PAGE_SIZE..bias + 5 * HOST_PAGE_SIZE,
            bias + 6 * HOST_PAGE_SIZE..bias + 7 * HOST_PAGE_SIZE,
        ]
    );
}

#[test]
fn unpublished_owned_gap_rollback_preserves_mapping_and_bytes() {
    let task = init_platform();
    let page = task
        .do_mmap_anonymous(
            None,
            HOST_PAGE_SIZE,
            ProtFlags::PROT_READ_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();
    let original = alloc::vec![0x5a; HOST_PAGE_SIZE];
    page.copy_from_slice::<TestPlatform>(0, &original).unwrap();
    let mut state = RuntimeIslands::default();
    let base = page.as_usize() - HOST_PAGE_SIZE;
    state.loads = alloc::vec![
        Load {
            file: 0..HOST_PAGE_SIZE,
            address: 0..HOST_PAGE_SIZE
        },
        Load {
            file: 2 * HOST_PAGE_SIZE..3 * HOST_PAGE_SIZE,
            address: 2 * HOST_PAGE_SIZE..3 * HOST_PAGE_SIZE
        },
    ];
    state.mappings.push(FileMapping {
        range: page.as_usize()..page.as_usize() + HOST_PAGE_SIZE,
        offset: HOST_PAGE_SIZE,
        bias: Some(base),
        loader_managed: false,
    });
    let staged = task
        .allocate_island(
            &state,
            base,
            IslandPlacement {
                preferred: base,
                allowed: base..=base + 3 * HOST_PAGE_SIZE,
            },
            &[],
            &[],
            None,
        )
        .unwrap();
    assert_eq!(staged.range.start, page.as_usize());
    assert!(staged.previous.is_some());
    page.copy_from_slice::<TestPlatform>(0, &[1, 2, 3, 4])
        .unwrap();
    task.rollback_island_mapping(staged).unwrap();
    assert_eq!(
        &*page.to_owned_slice::<TestPlatform>(HOST_PAGE_SIZE).unwrap(),
        original.as_slice()
    );
    task.sys_munmap(page, HOST_PAGE_SIZE).unwrap();
}

#[test]
fn early_unused_island_rollback_failure_is_fatal_before_source_restore() {
    extern crate std;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let task = init_platform();
    let source = task.allocate_chunk(2 * HOST_PAGE_SIZE, &[], None).unwrap();
    let native = 0xd4000001u32.to_le_bytes();
    source.copy_from_slice::<TestPlatform>(0, &native).unwrap();
    let address = source.as_usize() + HOST_PAGE_SIZE;
    let staged = || StagedMapping {
        range: address..address + HOST_PAGE_SIZE,
        previous: Some(DisplacedMapping {
            bytes: alloc::vec![0x5a; HOST_PAGE_SIZE],
            protections: alloc::vec![ProtFlags::PROT_READ; HOST_PAGE_SIZE / PAGE_SIZE],
            guest_owned: true,
        }),
        prefix_bias: None,
    };
    // Synthetic VM fault: revoke an unpublished reservation before cleanup.
    // Its backup extent stays consistent; the real protection seam now fails.
    task.sys_munmap_raw(UserPtrMut::from_usize(address), HOST_PAGE_SIZE)
        .unwrap();
    assert_eq!(task.rollback_island_mapping(staged()), Err(Errno::ENOMEM));
    let mut restoration_reached = false;
    let result = catch_unwind(AssertUnwindSafe(|| {
        task.rollback_island_mapping_or_fatal(staged());
        restoration_reached = true;
        task.sys_mprotect_raw(source, HOST_PAGE_SIZE, ProtFlags::PROT_READ)
            .unwrap();
    }));
    let panic = result.expect_err("indeterminate rollback must not return to retry logic");
    assert_eq!(
        panic.downcast_ref::<&str>().copied(),
        Some("failed to roll back unpublished island mapping")
    );
    assert!(!restoration_reached);
    assert!(task.global.mm.mappings().iter().any(|(range, flags)| {
        range.contains(&source.as_usize())
            && flags.contains(VmFlags::VM_READ | VmFlags::VM_WRITE)
            && !flags.contains(VmFlags::VM_EXEC)
    }));
    assert_eq!(&*source.to_owned_slice::<TestPlatform>(4).unwrap(), &native);
    task.sys_munmap_raw(source, HOST_PAGE_SIZE).unwrap();
}

#[test]
fn blocked_near_allocation_publishes_brk_without_transport() {
    for immediate in [false, true] {
        blocked_near_allocation(false, immediate);
    }
}

#[test]
fn serialized_relocation_exhaustion_rolls_back_partial_batch() {
    blocked_near_allocation(true, false);
}

fn blocked_near_allocation(serialized: bool, immediate: bool) {
    let task = init_platform();
    let path = if serialized {
        "/serialized-island-exhaustion"
    } else if immediate {
        "/island-exhaustion-mmap"
    } else {
        "/island-exhaustion-mprotect"
    };
    let bytes = if serialized {
        litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
            &image(),
            None,
            crate::aarch64_rewrite_options(),
        )
        .unwrap()
    } else {
        let mut bytes = image();
        bytes[3 * PAGE_SIZE + 4..3 * PAGE_SIZE + 8].copy_from_slice(&0xd53bd040u32.to_le_bytes()); // MRS x0, TPIDR_EL0
        bytes
    };
    create_file(&task, path, &bytes);
    let fd = open(&task, path);
    let length = 256 * 1024 * 1024;
    let reserved = task
        .sys_mmap(
            0,
            length,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            -1,
            0,
        )
        .unwrap();
    let address = reserved.as_usize() + length / 2;
    if serialized {
        // Only one near page is free for a multi-pair batch: the second pair
        // fails after the first was staged/published, without publishing sources.
        let free = align_down(address - 4 * HOST_PAGE_SIZE, HOST_PAGE_SIZE);
        task.sys_munmap(UserPtrMut::from_usize(free), HOST_PAGE_SIZE)
            .unwrap();
    }
    // Unrelated anonymous reservations are not evidence of gap ownership.
    let mapped = task
        .sys_mmap(
            address,
            PAGE_SIZE,
            ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            fd,
            if serialized { PAGE_SIZE } else { 3 * PAGE_SIZE },
        )
        .unwrap();
    let key = super::super::tests::elf_patch_key(&task, fd);
    let before = task.global.mm.mappings();
    if !serialized {
        if immediate {
            assert_eq!(
                task.sys_mmap(
                    address,
                    PAGE_SIZE,
                    ProtFlags::PROT_READ_EXEC,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                    fd,
                    3 * PAGE_SIZE,
                )
                .unwrap()
                .as_usize(),
                mapped.as_usize()
            );
        } else {
            task.sys_mprotect(mapped, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
                .unwrap();
        }
        let mut expected = before;
        for (range, flags) in &mut expected {
            if range.contains(&address) {
                *flags = (*flags & !VmFlags::VM_ACCESS_FLAGS) | VmFlags::VM_READ | VmFlags::VM_EXEC;
            }
        }
        assert_eq!(task.global.mm.mappings(), expected);
        let code = read_bytes(address, PAGE_SIZE);
        for word in code[..8].as_chunks::<4>().0 {
            assert_eq!(u32::from_le_bytes(*word) & 0xffe0001f, 0xd4200000);
        }
        assert_eq!(&code[8..], &bytes[3 * PAGE_SIZE + 8..4 * PAGE_SIZE]);
        {
            let cache = task.global.elf_patch_cache.lock();
            let state = &cache[&key];
            assert!(!state.trampoline_invalidated);
            assert!(state.islands.pairs.is_empty());
            assert!(state.patched_ranges.contains(&(address, PAGE_SIZE)));
        }
        // A cached BRK remains a successful mapping even if placement later opens.
        task.sys_munmap(
            UserPtrMut::from_usize(address - 512 * HOST_PAGE_SIZE),
            256 * HOST_PAGE_SIZE,
        )
        .unwrap();
        task.sys_mprotect(mapped, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
            .unwrap();
        assert_eq!(read_bytes(address, PAGE_SIZE), code);
        assert!(
            task.global.elf_patch_cache.lock()[&key]
                .islands
                .pairs
                .is_empty()
        );
        task.sys_munmap(reserved, length).unwrap();
        task.sys_close(fd).unwrap();
        return;
    }
    assert_eq!(
        task.sys_mprotect(mapped, PAGE_SIZE, ProtFlags::PROT_READ_EXEC),
        Err(Errno::ENOMEM)
    );
    assert_eq!(task.global.mm.mappings(), before);
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = cache.get(&key).unwrap();
        assert!(!state.trampoline_invalidated);
        assert!(state.islands.pairs.is_empty());
    }
    assert!(
        task.global
            .mm
            .mappings()
            .iter()
            .filter(|(r, _)| r.contains(&address))
            .all(|(_, flags)| !flags.contains(VmFlags::VM_EXEC))
    );
    assert_eq!(
        task.sys_mprotect(mapped, PAGE_SIZE, ProtFlags::PROT_READ_EXEC),
        Err(Errno::ENOMEM)
    );
    // Fix resource exhaustion and retry the same retained state.
    task.sys_munmap(
        UserPtrMut::from_usize(address - 512 * HOST_PAGE_SIZE),
        256 * HOST_PAGE_SIZE,
    )
    .unwrap();
    task.sys_mprotect(mapped, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    assert!(
        !task.global.elf_patch_cache.lock()[&key]
            .islands
            .pairs
            .is_empty()
    );
    task.sys_munmap(reserved, length).unwrap();
    task.sys_close(fd).unwrap();
}

#[test]
fn bad_fd_fixed_replacement_preserves_original_executable_mapping() {
    let task = init_platform();
    create_file(&task, "/island-failed-fixed", &sparse_image());
    let fd = open(&task, "/island-failed-fixed");
    let mapping = map_file(&task, fd, 4 * PAGE_SIZE, ProtFlags::PROT_READ_EXEC);
    let key = super::super::tests::elf_patch_key(&task, fd);
    let code = mapping.as_usize() + PAGE_SIZE;
    let pair_count = task
        .global
        .elf_patch_cache
        .lock()
        .get(&key)
        .unwrap()
        .islands
        .pairs
        .len();
    // Bad fd is a preflight error: neither permissions nor references change.
    // The runner counterpart executes the original mapping afterward.
    assert!(matches!(
        task.sys_mmap(
            code,
            PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            -1,
            0
        ),
        Err(Errno::EBADF)
    ));
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = cache.get(&key).unwrap();
        assert_eq!(state.islands.pairs.len(), pair_count);
        assert!(!state.trampoline_invalidated);
    }
    assert!(
        task.global
            .mm
            .mappings()
            .iter()
            .filter(|(r, _)| r.contains(&code))
            .all(|(_, flags)| flags.contains(VmFlags::VM_EXEC))
    );
    assert_eq!(
        task.sys_mprotect(
            UserPtrMut::from_usize(code),
            PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC
        ),
        Ok(())
    );
    task.sys_munmap(mapping, 4 * PAGE_SIZE).unwrap();
    task.sys_close(fd).unwrap();
}

// A real VM pack with tracked ELF ownership, not numerical LOAD-span evidence.
// The released prefix supplies deterministic free pages even on 16KiB hosts.
fn packed_dso(task: &Task<TestPlatform>, name: &str, bytes: &[u8]) -> (usize, usize, i32) {
    let main_path = alloc::format!("/{name}-main");
    create_file(task, &main_path, &gapless_image());
    let main = open(task, &main_path);
    task.begin_main_elf_load(super::super::tests::elf_patch_key(task, main).0);
    task.sys_close(main).unwrap();
    let size = 512 * 1024 * 1024 + HOST_PAGE_SIZE;
    let pack = task
        .do_mmap_anonymous(
            None,
            size,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();
    let base = align_up(pack.as_usize() + 256 * 1024 * 1024, HOST_PAGE_SIZE);
    task.sys_munmap(pack, base - pack.as_usize()).unwrap();
    let floor = base - 256 * 1024 * 1024;
    task.global.mm.set_initial_brk(floor);
    task.set_main_elf_heap_floor(floor);
    let path = alloc::format!("/{name}-dso");
    create_file(task, &path, bytes);
    let fd = open(task, &path);
    task.sys_mmap(
        base,
        3 * HOST_PAGE_SIZE,
        ProtFlags::PROT_READ,
        MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
        fd,
        0,
    )
    .unwrap();
    (base, pack.as_usize() + size - base, fd)
}

fn packed_image(dense: bool) -> Vec<u8> {
    let mut bytes = gapless_image();
    bytes.resize(3 * HOST_PAGE_SIZE, 0);
    bytes[PAGE_SIZE..].fill(0);
    let len = bytes.len() as u64;
    for field in [32, 40] {
        bytes[64 + field..72 + field].copy_from_slice(&len.to_le_bytes());
    }
    let end = if dense {
        2 * HOST_PAGE_SIZE
    } else {
        HOST_PAGE_SIZE + 4
    };
    for at in (HOST_PAGE_SIZE..end).step_by(4).chain([2 * HOST_PAGE_SIZE]) {
        bytes[at..at + 4].copy_from_slice(&0xd4000001u32.to_le_bytes());
    }
    bytes
}

#[test]
fn top_down_library_pack_heap_corridor_extends_owned_dso_prefix() {
    let task = init_platform();
    let (base, size, fd) = packed_dso(&task, "pack-runtime", &packed_image(true));
    let key = super::super::tests::elf_patch_key(&task, fd);
    task.sys_close(fd).unwrap();
    let first = UserPtrMut::from_usize(base + HOST_PAGE_SIZE);
    task.sys_mprotect(first, HOST_PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    let (frontier, immutable) = {
        let cache = task.global.elf_patch_cache.lock();
        let pairs = &cache[&key].islands.pairs;
        assert!(
            pairs.len() > 1,
            "multiple staged pages must extend one frontier"
        );
        for (i, pair) in pairs.iter().enumerate() {
            assert_eq!(pair.prefix_bias, Some(base));
            assert_eq!(
                pair.near,
                base - (i + 1) * HOST_PAGE_SIZE..base - i * HOST_PAGE_SIZE
            );
            assert!(!overlaps(&pair.far, &(base - 256 * 1024 * 1024..base)));
        }
        let frontier = pairs.last().unwrap().near.start;
        (
            frontier,
            UserPtrMut::<u8>::from_usize(frontier)
                .to_owned_slice::<TestPlatform>(HOST_PAGE_SIZE)
                .unwrap()
                .into_vec(),
        )
    };
    let second = UserPtrMut::from_usize(base + 2 * HOST_PAGE_SIZE);
    task.sys_mprotect(second, HOST_PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    let boundary = frontier - HOST_PAGE_SIZE;
    {
        let cache = task.global.elf_patch_cache.lock();
        let pair = cache[&key].islands.pairs.last().unwrap();
        assert_eq!(pair.near, boundary..frontier);
        assert_eq!(pair.prefix_bias, Some(base));
        assert!(!overlaps(&pair.far, &(base - 256 * 1024 * 1024..base)));
    }
    assert_eq!(
        &*UserPtrMut::<u8>::from_usize(frontier)
            .to_owned_slice::<TestPlatform>(HOST_PAGE_SIZE)
            .unwrap(),
        immutable.as_slice()
    );
    assert_eq!(task.sys_brk(UserPtrMut::from_usize(boundary)), Ok(boundary));
    assert_eq!(
        task.sys_brk(UserPtrMut::from_usize(boundary + HOST_PAGE_SIZE)),
        Ok(boundary)
    );
    let corridor = task
        .global
        .elf_heap_placement
        .lock()
        .corridor(task.global.mm.mappings().into_iter().map(|(r, _)| r.start))
        .unwrap();
    assert_eq!(
        corridor.end, boundary,
        "heap VMAs cannot hide the prefix barrier"
    );
    task.sys_munmap(second, HOST_PAGE_SIZE).unwrap();
    assert_eq!(task.sys_brk(UserPtrMut::from_usize(frontier)), Ok(frontier));
    // Last-site retirement reclaims only its prefix, not the adjacent live batch.
    assert_eq!(
        &*UserPtrMut::<u8>::from_usize(frontier)
            .to_owned_slice::<TestPlatform>(HOST_PAGE_SIZE)
            .unwrap(),
        immutable.as_slice()
    );
    task.sys_munmap(first, HOST_PAGE_SIZE).unwrap();
    assert_eq!(task.sys_brk(UserPtrMut::from_usize(base)), Ok(base));
    assert_eq!(
        task.sys_brk(UserPtrMut::from_usize(base + HOST_PAGE_SIZE)),
        Ok(base)
    );
    task.sys_munmap(UserPtrMut::from_usize(base), size).unwrap();
    assert!(!task.global.elf_patch_cache.lock().contains_key(&key));
    task.sys_brk(UserPtrMut::from_usize(base - 256 * 1024 * 1024))
        .unwrap();
}

#[test]
fn heap_boundary_rejects_unproven_main_heap_reach_future_load_and_collision() {
    use litebox::platform::page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions};
    use litebox::platform::{PageManagementProvider, RawConstPointer as _, RawMutPointer as _};

    let task = init_platform();
    let (base, size, fd) = packed_dso(&task, "pack-negative", &packed_image(false));
    let key = super::super::tests::elf_patch_key(&task, fd);
    let candidate = base - HOST_PAGE_SIZE;
    let cache = task.global.elf_patch_cache.lock();
    let state = &cache[&key].islands;
    let mut heap = task.global.elf_heap_placement.lock();
    let corridor = heap.island_corridor(&key, [base].into_iter()).unwrap();
    let attempt =
        |state: &RuntimeIslands, heap: &HeapCorridor, allowed, future: &[Range<usize>]| {
            task.allocate_island(
                state,
                base,
                IslandPlacement {
                    preferred: base,
                    allowed,
                },
                &[],
                future,
                Some(heap),
            )
        };
    let before = task.global.mm.mappings();
    let staged = attempt(state, &corridor, candidate..=candidate, &[]).unwrap();
    assert_eq!(staged.range, candidate..base);
    assert_eq!(staged.prefix_bias, Some(base));
    task.rollback_island_mapping(staged).unwrap();
    assert_eq!(task.global.mm.mappings(), before);
    // Explicit main identity, missing main identity, unknown mapping bias, and
    // another instance/file cannot confer boundary ownership.
    let main_identity = heap.main.clone();
    for main in [Some(key.clone()), None] {
        heap.main = main;
        let rejected = heap.island_corridor(&key, [base].into_iter()).unwrap();
        assert!(matches!(
            attempt(state, &rejected, candidate..=candidate, &[]),
            Err(Errno::ENOMEM)
        ));
    }
    for bias in [None, Some(base + HOST_PAGE_SIZE)] {
        let foreign = RuntimeIslands {
            loads: state.loads.clone(),
            mappings: alloc::vec![FileMapping {
                range: base..base + 3 * HOST_PAGE_SIZE,
                offset: 0,
                bias,
                loader_managed: false,
            }],
            ..Default::default()
        };
        assert!(matches!(
            attempt(&foreign, &corridor, candidate..=candidate, &[]),
            Err(Errno::ENOMEM)
        ));
    }
    let foreign = RuntimeIslands {
        loads: state.loads.clone(),
        ..Default::default()
    };
    assert!(matches!(
        attempt(&foreign, &corridor, candidate..=candidate, &[]),
        Err(Errno::ENOMEM)
    ));
    for brk in [base, candidate + 1] {
        let full = HeapCorridor {
            range: corridor.range.clone(),
            heap_end: align_up(brk, HOST_PAGE_SIZE),
            dso: true,
        };
        assert!(matches!(
            attempt(state, &full, candidate..=candidate, &[]),
            Err(Errno::ENOMEM)
        ));
    }
    for allowed in [candidate + 4..=candidate + 4, base..=candidate] {
        assert!(matches!(
            attempt(state, &corridor, allowed, &[]),
            Err(Errno::ENOMEM)
        ));
    }
    assert!(matches!(
        attempt(
            state,
            &corridor,
            candidate..=candidate,
            core::slice::from_ref(&(candidate..base))
        ),
        Err(Errno::ENOMEM)
    ));
    // An untracked host mapping exercises NOREPLACE, not just the PM snapshot.
    let platform = crate::syscalls::tests::test_platform();
    let collision = <TestPlatform as PageManagementProvider<PAGE_SIZE>>::allocate_pages(
        platform,
        candidate..candidate + HOST_PAGE_SIZE,
        MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
        false,
        false,
        FixedAddressBehavior::NoReplace,
    )
    .unwrap();
    assert_eq!(collision.as_usize(), candidate);
    assert_eq!(collision.write_at_offset(0, 0x5a), Some(()));
    assert!(matches!(
        attempt(state, &corridor, candidate..=candidate, &[]),
        Err(Errno::ENOMEM)
    ));
    assert_eq!(read_bytes(candidate, 1), [0x5a]);
    // SAFETY: this test owns the idle exact, non-replacing host allocation.
    unsafe {
        <TestPlatform as PageManagementProvider<PAGE_SIZE>>::deallocate_pages(
            platform,
            candidate..candidate + HOST_PAGE_SIZE,
        )
        .unwrap();
    }
    assert_eq!(task.global.mm.mappings(), before);
    heap.main = main_identity;
    drop(heap);
    drop(cache);
    // A partial final host page of a real mapped heap is not spare island space.
    assert_eq!(
        task.sys_brk(UserPtrMut::from_usize(candidate + 1)),
        Ok(candidate + 1)
    );
    let heap_byte = UserPtrMut::<u8>::from_usize(candidate);
    heap_byte
        .copy_from_slice::<TestPlatform>(0, &[0x5a])
        .unwrap();
    {
        let cache = task.global.elf_patch_cache.lock();
        let corridor = task
            .global
            .elf_heap_placement
            .lock()
            .island_corridor(
                &key,
                task.global.mm.mappings().into_iter().map(|(r, _)| r.start),
            )
            .unwrap();
        assert!(matches!(
            attempt(&cache[&key].islands, &corridor, candidate..=candidate, &[]),
            Err(Errno::ENOMEM)
        ));
    }
    assert_eq!(
        &*heap_byte.to_owned_slice::<TestPlatform>(1).unwrap(),
        &[0x5a]
    );
    task.sys_brk(UserPtrMut::from_usize(base - 256 * 1024 * 1024))
        .unwrap();
    task.sys_munmap(UserPtrMut::from_usize(base), size).unwrap();
    task.sys_close(fd).unwrap();
}

#[test]
fn serialized_pack_relocates_whole_pair_to_owned_boundary() {
    let task = init_platform();
    let bytes = litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
        &packed_image(false),
        None,
        crate::aarch64_rewrite_options(),
    )
    .unwrap();
    let (base, size, fd) = packed_dso(&task, "pack-aot", &bytes);
    let key = super::super::tests::elf_patch_key(&task, fd);
    task.sys_mprotect(
        UserPtrMut::from_usize(base + HOST_PAGE_SIZE),
        HOST_PAGE_SIZE,
        ProtFlags::PROT_READ_EXEC,
    )
    .unwrap();
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = &cache[&key].islands;
        let published = &state.pairs[0];
        assert_eq!(published.near, base - HOST_PAGE_SIZE..base);
        assert_eq!(published.prefix_bias, Some(base));
        let image = &state.serialized.as_ref().unwrap().pairs[published.serialized.unwrap().1];
        let pair = IslandPair::from_images(
            base as u64 + image.island_vaddr(),
            image.island().to_vec(),
            image.chunk().to_vec(),
            crate::aarch64_rewrite_options().target_host(),
        )
        .unwrap();
        assert!(
            pair.placement_range()
                .unwrap()
                .contains(&(published.near.start as u64))
        );
        assert!(
            pair.relocated(
                published.near.start as u64,
                crate::aarch64_rewrite_options().target_host()
            )
            .is_ok()
        );
    }
    task.sys_munmap(UserPtrMut::from_usize(base), size).unwrap();
    task.sys_close(fd).unwrap();
}

#[cfg(feature = "aarch64_virtualize_x18")]
fn image_with_distant_load(distant: usize) -> Vec<u8> {
    let mut bytes = packed_image(false);
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
    for field in [32, 40] {
        bytes[64 + field..72 + field].copy_from_slice(&(2 * HOST_PAGE_SIZE as u64).to_le_bytes());
    }
    for (field, value) in [
        (0, 1),
        (4, 5),
        (8, 2 * HOST_PAGE_SIZE),
        (16, distant),
        (32, HOST_PAGE_SIZE),
        (40, HOST_PAGE_SIZE),
        (48, HOST_PAGE_SIZE),
    ] {
        let width = if field < 8 { 4 } else { 8 };
        bytes[120 + field..120 + field + width]
            .copy_from_slice(&(value as u64).to_le_bytes()[..width]);
    }
    bytes[2 * HOST_PAGE_SIZE..].fill(0);
    bytes
}

#[cfg(feature = "aarch64_virtualize_x18")]
#[test]
fn conditional_runtime_placement_skips_primary_only_gap_pages() {
    for (name, raw, displacement) in [
        ("cbz", 0xb47f_fff2u32, (1 << 20) - 4),
        ("tbnz", 0xb7fb_fff2u32, (1 << 15) - 4),
    ] {
        for mixed in [false, true] {
            let task = init_platform();
            let distant = (1 << 27) + 2 * HOST_PAGE_SIZE;
            let mut bytes = image_with_distant_load(distant);
            if mixed {
                // Initial placement follows SVC's wider interval; the conditional
                // then needs retry expansion and gets a nonzero primary slot.
                bytes[2 * HOST_PAGE_SIZE + 28..2 * HOST_PAGE_SIZE + 32]
                    .copy_from_slice(&0xd400_0001u32.to_le_bytes());
            }
            bytes[2 * HOST_PAGE_SIZE + 32..2 * HOST_PAGE_SIZE + 36]
                .copy_from_slice(&raw.to_le_bytes());
            let (base, size, fd) = packed_dso(&task, &alloc::format!("{name}-{mixed}"), &bytes);
            // A real free ELF gap: the first two pages fit the primary but not the
            // auxiliary exit. Do not reserve/map the enormous gap as a file image.
            task.sys_munmap(
                UserPtrMut::from_usize(base + 2 * HOST_PAGE_SIZE),
                distant - 2 * HOST_PAGE_SIZE,
            )
            .unwrap();
            let code = task
                .sys_mmap(
                    base + distant,
                    HOST_PAGE_SIZE,
                    ProtFlags::PROT_READ,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                    fd,
                    2 * HOST_PAGE_SIZE,
                )
                .unwrap();
            let pc = code.as_usize() + 32;
            let expected = align_up(
                base + 2 * HOST_PAGE_SIZE + displacement - 52,
                HOST_PAGE_SIZE,
            );
            assert!(expected >= base + 4 * HOST_PAGE_SIZE);
            task.sys_mprotect(code, HOST_PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
                .unwrap();
            let key = super::super::tests::elf_patch_key(&task, fd);
            let branch = UserPtrMut::<u32>::from_usize(pc)
                .read_at_offset::<TestPlatform>(0)
                .unwrap();
            assert_eq!(
                branch & 0xfc00_0000,
                0x1400_0000,
                "{name} must not become BRK"
            );
            let (near, far, island_bytes, chunk_bytes) = {
                let cache = task.global.elf_patch_cache.lock();
                let state = &cache[&key];
                assert!(
                    state
                        .patched_ranges
                        .contains(&(code.as_usize(), HOST_PAGE_SIZE))
                );
                assert_eq!(state.islands.pairs.len(), 1);
                let pair = &state.islands.pairs[0];
                assert_eq!(pair.near.start, expected);
                let near = UserPtrMut::<u8>::from_usize(pair.near.start)
                    .to_owned_slice::<TestPlatform>(island::ISLAND_BYTES)
                    .unwrap()
                    .into_vec();
                let slot = usize::from(mixed);
                let primary = island::decode_island_slot(&near, expected as u64, slot).unwrap();
                let auxiliary =
                    island::decode_island_slot(&near, expected as u64, slot + 1).unwrap();
                let entry_displacement = ((branch & 0x03ff_ffff) << 6).cast_signed() >> 4;
                assert_eq!(
                    pc as i128 + i128::from(entry_displacement),
                    (expected + island::ISLAND_HEADER_BYTES + slot * island::ISLAND_SLOT_BYTES)
                        as i128
                );
                assert_eq!(primary.site, pc as u64);
                assert_eq!(primary.resume, pc as u64 + 4);
                assert!(!primary.auxiliary);
                assert!(auxiliary.auxiliary);
                assert_eq!(auxiliary.resume, (pc + displacement) as u64);
                let chunk = UserPtrMut::<u8>::from_usize(pair.far.start)
                    .to_owned_slice::<TestPlatform>(pair.far.len())
                    .unwrap()
                    .into_vec();
                let host = crate::aarch64_rewrite_options().target_host();
                let mut gate =
                    island::decode_island_gate(&chunk, island::CHUNK_GATES_OFFSET, host).unwrap();
                if mixed {
                    gate =
                        island::decode_island_gate(&chunk, gate.offset + gate.size, host).unwrap();
                }
                assert_eq!(gate.original, Some(raw));
                let validated = IslandPair::from_images(
                    expected as u64,
                    near.clone(),
                    chunk[..gate.offset + gate.size].to_vec(),
                    host,
                )
                .unwrap();
                assert_eq!(validated.slots_used(), slot + 2);
                assert!(
                    validated
                        .placement_range()
                        .unwrap()
                        .contains(&(expected as u64))
                );
                (pair.near.clone(), pair.far.clone(), near, chunk)
            };
            for prot in [
                ProtFlags::PROT_READ_EXEC,
                ProtFlags::PROT_READ,
                ProtFlags::PROT_READ_EXEC,
            ] {
                task.sys_mprotect(code, HOST_PAGE_SIZE, prot).unwrap();
            }
            assert_eq!(
                UserPtrMut::<u32>::from_usize(pc)
                    .read_at_offset::<TestPlatform>(0)
                    .unwrap(),
                branch
            );
            assert_eq!(
                task.global.elf_patch_cache.lock()[&key].islands.pairs.len(),
                1
            );
            // Publish another batch while the old pair still has free slots. Its
            // immutable image must survive both cache hits and this later growth.
            task.sys_mprotect(
                UserPtrMut::from_usize(base + HOST_PAGE_SIZE),
                HOST_PAGE_SIZE,
                ProtFlags::PROT_READ_EXEC,
            )
            .unwrap();
            assert_eq!(
                task.global.elf_patch_cache.lock()[&key].islands.pairs.len(),
                2
            );
            for (range, saved) in [(near, island_bytes), (far, chunk_bytes)] {
                assert_eq!(
                    &*UserPtrMut::<u8>::from_usize(range.start)
                        .to_owned_slice::<TestPlatform>(saved.len())
                        .unwrap(),
                    saved.as_slice()
                );
            }
            task.sys_munmap(UserPtrMut::from_usize(base), size).unwrap();
            task.sys_close(fd).unwrap();
        }
    }
}

#[cfg(feature = "aarch64_virtualize_x18")]
#[test]
fn boundary_inbound_reach_traps_unreachable_conditional_exit() {
    for mixed in [false, true] {
        let task = init_platform();
        let distant = (1 << 27) - HOST_PAGE_SIZE;
        // One near LOAD attests ownership, one distant LOAD contains CBZ x18 whose
        // primary entry fits at/near the boundary but whose taken exit is out of reach.
        let mut bytes = image_with_distant_load(distant);
        let conditional_offset = if mixed { 28 } else { 32 };
        let at = 2 * HOST_PAGE_SIZE + conditional_offset;
        bytes[at..at + 4].copy_from_slice(&0xb47ffff2u32.to_le_bytes()); // CBZ x18, PC + 1MiB - 4
        if mixed {
            // This later site can use the heap prefix even though CBZ cannot.
            bytes[2 * HOST_PAGE_SIZE + 32..2 * HOST_PAGE_SIZE + 36]
                .copy_from_slice(&0xd4000001u32.to_le_bytes());
        }
        let (base, size, fd) = packed_dso(&task, &alloc::format!("pack-aux-exit-{mixed}"), &bytes);
        // The first mapping covers only its LOAD, not the distant LOAD's file page.
        task.sys_mmap(
            base + 2 * HOST_PAGE_SIZE,
            HOST_PAGE_SIZE,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
            -1,
            0,
        )
        .unwrap();
        let key = super::super::tests::elf_patch_key(&task, fd);
        let code = task
            .sys_mmap(
                base + distant,
                HOST_PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                fd,
                2 * HOST_PAGE_SIZE,
            )
            .unwrap();
        // The numerical gap remains reserved. Only the owned heap prefix is free;
        // that page fails CBZ's auxiliary reach, so CBZ truly has no placement.
        let candidate = base - HOST_PAGE_SIZE;
        let pc = code.as_usize() + conditional_offset;
        assert!(
            (pc - (1 << 27) - island::ISLAND_HEADER_BYTES
                ..=pc + (1 << 27) - island::ISLAND_HEADER_BYTES - 16)
                .contains(&candidate)
        );
        let before = task.global.mm.mappings();
        for _ in 0..2 {
            task.sys_mprotect(code, HOST_PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
                .unwrap();
            let cache = task.global.elf_patch_cache.lock();
            let state = &cache[&key];
            assert_eq!(state.islands.pairs.len(), usize::from(mixed));
            assert!(
                state
                    .patched_ranges
                    .contains(&(code.as_usize(), HOST_PAGE_SIZE))
            );
            assert!(!state.trampoline_invalidated);
            let words = read_bytes(code.as_usize(), HOST_PAGE_SIZE);
            assert_eq!(
                u32::from_le_bytes(
                    words[conditional_offset..conditional_offset + 4]
                        .try_into()
                        .unwrap()
                ) & 0xffe0001f,
                0xd4200000
            );
            assert_eq!(&words[..conditional_offset], &bytes[2 * HOST_PAGE_SIZE..at]);
            assert_eq!(&words[36..], &bytes[2 * HOST_PAGE_SIZE + 36..]);
            if mixed {
                let pair = &state.islands.pairs[0];
                assert_eq!(pair.near.start, candidate);
                assert_eq!(pair.sites, [pc + 4]);
                let branch = u32::from_le_bytes(words[32..36].try_into().unwrap());
                assert_eq!(branch & 0xfc000000, 0x14000000);
                let displacement = ((branch & 0x03ff_ffff) << 6).cast_signed() >> 4;
                assert_eq!(
                    (pc + 4) as i128 + i128::from(displacement),
                    (candidate + island::ISLAND_HEADER_BYTES) as i128
                );
                let near = read_bytes(candidate, island::ISLAND_BYTES);
                let slot = island::decode_island_slot(&near, candidate as u64, 0).unwrap();
                assert_eq!(slot.site, (pc + 4) as u64);
                assert_eq!(slot.resume, (pc + 8) as u64);
                assert!(!slot.auxiliary);
                for range in [&pair.near, &pair.far] {
                    assert!(
                        task.global
                            .mm
                            .mappings()
                            .iter()
                            .any(|(r, f)| r.start <= range.start
                                && range.end <= r.end
                                && f.intersection(VmFlags::VM_ACCESS_FLAGS)
                                    == VmFlags::VM_READ | VmFlags::VM_EXEC)
                    );
                }
            }
        }
        assert!(
            task.global
                .mm
                .mappings()
                .iter()
                .any(|(r, f)| r.contains(&pc)
                    && f.intersection(VmFlags::VM_ACCESS_FLAGS)
                        == VmFlags::VM_READ | VmFlags::VM_EXEC)
        );
        if !mixed {
            let mut expected = before;
            for (range, flags) in &mut expected {
                if range.contains(&pc) {
                    *flags =
                        (*flags & !VmFlags::VM_ACCESS_FLAGS) | VmFlags::VM_READ | VmFlags::VM_EXEC;
                }
            }
            assert_eq!(task.global.mm.mappings(), expected);
        }
        task.sys_munmap(UserPtrMut::from_usize(base), size).unwrap();
        assert!(
            !task
                .global
                .mm
                .mappings()
                .iter()
                .any(|(r, _)| r.contains(&candidate))
        );
        task.sys_close(fd).unwrap();
    }
}

#[test]
fn growing_main_heap_is_not_its_own_placement_barrier() {
    let heap = super::super::ElfHeapPlacement {
        main: None,
        floor: Some(0x1000),
        current_brk: Some(0x4000),
    };
    assert_eq!(
        heap.corridor([0x1000, 0x8000].into_iter()),
        Some(0x1000..0x8000)
    );
    assert_eq!(
        heap.corridor([0x1000].into_iter()),
        Some(0x1000..usize::MAX)
    );
}

#[test]
fn whole_span_fixed_replacements_preserve_every_replacement_page() {
    let task = init_platform();
    let image = image_with_gap(HOST_PAGE_SIZE);
    let span_len = image.len();
    create_file(&task, "/island-whole-span", &image);
    let fd = open(&task, "/island-whole-span");
    create_file(
        &task,
        "/island-replacement-data",
        &alloc::vec![0x5a; span_len],
    );
    let data_fd = open(&task, "/island-replacement-data");
    for replacement_fd in [-1, data_fd] {
        let mapping = map_file(&task, fd, span_len, ProtFlags::PROT_READ_EXEC);
        let key = super::super::tests::elf_patch_key(&task, fd);
        let released = {
            let cache = task.global.elf_patch_cache.lock();
            let islands = &cache.get(&key).unwrap().islands;
            assert!(
                islands
                    .pairs
                    .iter()
                    .any(|p| p.near.start == mapping.as_usize() + 2 * HOST_PAGE_SIZE),
                "fixture must place transport in the replaced ELF gap"
            );
            let span = mapping.as_usize()..mapping.as_usize() + span_len;
            assert!(islands.pairs.iter().any(|p| !overlaps(&p.far, &span)));
            islands.owned_ranges().collect::<Vec<_>>()
        };
        let anonymous = if replacement_fd == -1 {
            MapFlags::MAP_ANONYMOUS
        } else {
            MapFlags::empty()
        };
        let replacement = task
            .sys_mmap(
                mapping.as_usize(),
                span_len,
                ProtFlags::PROT_READ_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED | anonymous,
                replacement_fd,
                0,
            )
            .unwrap();
        assert_eq!(replacement.as_usize(), mapping.as_usize());
        for page in 0..span_len / PAGE_SIZE {
            let address = replacement.as_usize() + page * PAGE_SIZE;
            assert!(
                task.global
                    .mm
                    .mappings()
                    .iter()
                    .any(|(r, flags)| r.start <= address
                        && address + PAGE_SIZE <= r.end
                        && flags.contains(VmFlags::VM_READ | VmFlags::VM_WRITE))
            );
            let ptr = UserPtrMut::<u8>::from_usize(address);
            assert_eq!(
                ptr.to_owned_slice::<TestPlatform>(PAGE_SIZE)
                    .unwrap()
                    .as_ref(),
                alloc::vec![if replacement_fd == -1 { 0 } else { 0x5a }; PAGE_SIZE].as_slice()
            );
            let bytes = alloc::vec![u8::try_from(page + 1).unwrap(); PAGE_SIZE];
            ptr.copy_from_slice::<TestPlatform>(0, &bytes).unwrap();
            assert_eq!(
                ptr.to_owned_slice::<TestPlatform>(PAGE_SIZE)
                    .unwrap()
                    .as_ref(),
                bytes.as_slice()
            );
        }
        assert!(!task.global.elf_patch_cache.lock().contains_key(&key));
        for range in released {
            for part in subtract_ranges(
                range,
                core::slice::from_ref(&(mapping.as_usize()..mapping.as_usize() + span_len)),
            ) {
                assert!(
                    !task
                        .global
                        .mm
                        .mappings()
                        .iter()
                        .any(|(r, _)| overlaps(r, &part))
                );
            }
        }
        task.sys_munmap(replacement, span_len).unwrap();
    }
    task.sys_close(fd).unwrap();
    task.sys_close(data_fd).unwrap();
}

#[test]
fn partial_overlap_fixed_failure_preserves_original_executable_mapping() {
    let task = init_platform();
    create_file(&task, "/island-partial-fixed", &sparse_image());
    let fd = open(&task, "/island-partial-fixed");
    // Keep the page above the site occupied while publishing so it cannot
    // become transport. Then remove it to reproduce Vmem's partial overlap.
    let mapping = task
        .sys_mmap(
            0,
            2 * PAGE_SIZE,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            -1,
            0,
        )
        .unwrap();
    task.sys_mmap(
        mapping.as_usize(),
        PAGE_SIZE,
        ProtFlags::PROT_READ_EXEC,
        MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
        fd,
        3 * PAGE_SIZE,
    )
    .unwrap();
    task.sys_munmap(
        UserPtrMut::from_usize(mapping.as_usize() + PAGE_SIZE),
        PAGE_SIZE,
    )
    .unwrap();
    let key = super::super::tests::elf_patch_key(&task, fd);
    let code = mapping.to_owned_slice::<TestPlatform>(PAGE_SIZE).unwrap();
    let before = task.global.mm.mappings();
    let pairs = task
        .global
        .elf_patch_cache
        .lock()
        .get(&key)
        .unwrap()
        .islands
        .pairs
        .len();
    for replacement_fd in [-1, fd] {
        let anonymous = if replacement_fd == -1 {
            MapFlags::MAP_ANONYMOUS
        } else {
            MapFlags::empty()
        };
        assert!(matches!(
            task.sys_mmap(
                mapping.as_usize(),
                2 * PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED | anonymous,
                replacement_fd,
                0
            ),
            Err(Errno::ENOMEM)
        ));
        assert_eq!(task.global.mm.mappings(), before);
        assert_eq!(
            mapping
                .to_owned_slice::<TestPlatform>(PAGE_SIZE)
                .unwrap()
                .as_ref(),
            code.as_ref()
        );
        {
            let cache = task.global.elf_patch_cache.lock();
            let state = cache.get(&key).unwrap();
            assert!(!state.trampoline_invalidated);
            assert_eq!(state.islands.pairs.len(), pairs);
        }
        task.sys_mprotect(mapping, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
            .unwrap();
    }
    task.sys_munmap(mapping, PAGE_SIZE).unwrap();
    task.sys_close(fd).unwrap();
}

#[test]
fn non_load_file_offset_maps_without_bias_or_gap_ownership() {
    let task = init_platform();
    let mut bytes = sparse_image();
    bytes[2 * PAGE_SIZE..3 * PAGE_SIZE].fill(0x5a);
    create_file(&task, "/island-non-load", &bytes);
    let fd = open(&task, "/island-non-load");
    let mapping = task
        .sys_mmap(
            0,
            PAGE_SIZE,
            ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE,
            fd,
            2 * PAGE_SIZE,
        )
        .unwrap();
    let key = super::super::tests::elf_patch_key(&task, fd);
    assert_eq!(
        mapping
            .to_owned_slice::<TestPlatform>(PAGE_SIZE)
            .unwrap()
            .as_ref(),
        &bytes[2 * PAGE_SIZE..3 * PAGE_SIZE]
    );
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = &cache.get(&key).unwrap().islands;
        let record = state.mapping(mapping.as_usize(), PAGE_SIZE).unwrap();
        assert_eq!(record.offset, 2 * PAGE_SIZE);
        assert_eq!(record.bias, None);
        assert!(state.future_loads().unwrap().is_empty());
        assert!(state.pairs.is_empty());
    }
    task.sys_close(fd).unwrap();
    task.sys_munmap(mapping, PAGE_SIZE).unwrap();
}

fn sparse_image() -> Vec<u8> {
    let mut bytes = image();
    for at in (PAGE_SIZE..2 * PAGE_SIZE).step_by(4) {
        bytes[at..at + 4].copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    bytes[PAGE_SIZE..PAGE_SIZE + 4].copy_from_slice(&0xd4000001u32.to_le_bytes());
    bytes
}

fn aot_image() -> Vec<u8> {
    litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
        &sparse_image(),
        None,
        crate::aarch64_rewrite_options(),
    )
    .unwrap()
}

// Parse the emitted payload rather than assuming that a guest-page hole can
// hold an island. These small serialized fixtures deliberately use one pair.
fn serialized_island_extent(bytes: &[u8], granule: usize) -> Range<usize> {
    let payload = litebox_syscall_rewriter::aarch64::elf_islands::ElfIslands::parse(bytes)
        .unwrap()
        .unwrap();
    assert_eq!(payload.granule, granule as u64);
    assert_eq!(payload.pairs.len(), 1);
    let start = usize::try_from(payload.pairs[0].island_vaddr()).unwrap();
    assert_eq!(start % granule, 0);
    start..start + granule
}

#[test]
fn serialized_pairs_reuse_per_bias_after_close_and_retire_on_last_reference() {
    let task = init_platform();
    let (fd, key) = open_image(&task, "/aot-lifecycle", &aot_image());
    let mut bases = Vec::new();
    for _ in 0..2 {
        bases.push(map_file(&task, fd, 4 * PAGE_SIZE, ProtFlags::PROT_READ));
    }
    task.sys_close(fd).unwrap();
    for base in &bases {
        // Last RX LOAD is enabled first; source records and fd identity survive close.
        task.sys_mprotect(
            UserPtrMut::from_usize(base.as_usize() + 3 * PAGE_SIZE),
            PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC,
        )
        .unwrap();
        task.sys_mprotect(
            UserPtrMut::from_usize(base.as_usize() + PAGE_SIZE),
            PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC,
        )
        .unwrap();
        task.sys_mprotect(
            UserPtrMut::from_usize(base.as_usize() + 2 * PAGE_SIZE),
            PAGE_SIZE,
            ProtFlags::PROT_NONE,
        )
        .unwrap();
    }
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = &cache[&key];
        assert_eq!(state.islands.pairs.len(), 2);
        assert!(
            state
                .islands
                .pairs
                .iter()
                .all(|p| p.serialized.is_some() && p.sites.len() == 2)
        );
    }
    task.sys_munmap(
        UserPtrMut::from_usize(bases[0].as_usize() + PAGE_SIZE),
        PAGE_SIZE,
    )
    .unwrap();
    assert_eq!(
        task.global.elf_patch_cache.lock()[&key].islands.pairs[0]
            .sites
            .len(),
        1
    );
    task.sys_munmap(bases[0], 4 * PAGE_SIZE).unwrap();
    assert_eq!(
        task.global.elf_patch_cache.lock()[&key].islands.pairs.len(),
        1
    );
    task.sys_munmap(bases[1], 4 * PAGE_SIZE).unwrap();
    assert!(
        task.global
            .elf_patch_cache
            .lock()
            .get(&key)
            .is_none_or(|s| s.islands.pairs.is_empty())
    );
}

#[test]
fn serialized_collision_relocates_and_reuses_pair_for_delayed_mapping_after_close() {
    let task = init_platform();
    let bytes = aot_image();
    let island = serialized_island_extent(&bytes, HOST_PAGE_SIZE);
    let (fd, key) = open_image(&task, "/aot-collision", &bytes);
    let before = task.global.mm.mappings();
    // Reserve room for both LOADs AND the actual island, plus alignment slack.
    // On 16KiB hosts the island is above the image, not in its 4KiB file hole.
    let reserved_len = (4 * PAGE_SIZE).max(island.end) + HOST_PAGE_SIZE;
    let base = task
        .sys_mmap(
            0,
            reserved_len,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
            -1,
            0,
        )
        .unwrap();
    let bias = align_up(base.as_usize(), HOST_PAGE_SIZE);
    let near = task
        .sys_mmap(
            bias + island.start,
            island.len(),
            ProtFlags::PROT_READ_WRITE,
            MapFlags::MAP_FIXED | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
            -1,
            0,
        )
        .unwrap();
    let sentinel = alloc::vec![0x5a; island.len()];
    near.copy_from_slice::<TestPlatform>(0, &sentinel).unwrap();
    let code = UserPtrMut::from_usize(bias + 3 * PAGE_SIZE);
    task.sys_mmap(
        code.as_usize(),
        PAGE_SIZE,
        ProtFlags::PROT_READ,
        MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE,
        fd,
        3 * PAGE_SIZE,
    )
    .unwrap();
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = &cache[&key].islands;
        let mapping = state.mapping(code.as_usize(), PAGE_SIZE).unwrap();
        assert_eq!((mapping.offset, mapping.bias), (3 * PAGE_SIZE, Some(bias)));
        assert!(state.loader_reservations.is_empty() && state.mmap_reservations.is_empty());
        assert!(
            state.future_loads().unwrap().iter().all(|load| {
                !overlaps(load, &(near.as_usize()..near.as_usize() + island.len()))
            })
        );
    }
    task.sys_mprotect(code, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    let (actual, far) = {
        let cache = task.global.elf_patch_cache.lock();
        let pairs = &cache[&key].islands.pairs;
        assert_eq!(pairs.len(), 1);
        assert_ne!(pairs[0].near.start, near.as_usize());
        (pairs[0].near.clone(), pairs[0].far.clone())
    };
    let transport = read_bytes(actual.start, actual.len());
    let first = task
        .sys_mmap(
            bias + PAGE_SIZE,
            PAGE_SIZE,
            ProtFlags::PROT_READ,
            MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE,
            fd,
            PAGE_SIZE,
        )
        .unwrap();
    task.sys_close(fd).unwrap();
    task.sys_mprotect(first, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    // A delayed source mapping redirects to the SAME immutable pair, after close.
    task.sys_munmap(code, PAGE_SIZE).unwrap();
    task.sys_mprotect(first, PAGE_SIZE, ProtFlags::PROT_READ_WRITE)
        .unwrap();
    task.sys_mprotect(first, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    {
        let cache = task.global.elf_patch_cache.lock();
        let pairs = &cache[&key].islands.pairs;
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            (pairs[0].near.clone(), pairs[0].far.clone()),
            (actual.clone(), far)
        );
        assert_eq!(pairs[0].sites, [first.as_usize()]);
    }
    assert_eq!(read_bytes(actual.start, actual.len()), transport);
    assert_eq!(
        &*near.to_owned_slice::<TestPlatform>(island.len()).unwrap(),
        sentinel.as_slice()
    );
    task.sys_munmap(first, PAGE_SIZE).unwrap();
    assert!(!task.global.elf_patch_cache.lock().contains_key(&key));
    task.sys_munmap(base, reserved_len).unwrap();
    assert_eq!(task.global.mm.mappings(), before);
}

#[test]
fn serialized_modified_code_reenable_still_uses_runtime_scanner() {
    let task = init_platform();
    let (fd, key) = open_image(&task, "/aot-rescan", &aot_image());
    let base = map_file(&task, fd, 4 * PAGE_SIZE, ProtFlags::PROT_READ);
    let code = UserPtrMut::<u8>::from_usize(base.as_usize() + PAGE_SIZE);
    assert_eq!(
        task.sys_madvise(code, 1, litebox_common_linux::MadviseBehavior::DontNeed),
        Err(Errno::EBUSY)
    );
    task.sys_mprotect(code, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    let before = task.global.elf_patch_cache.lock()[&key].islands.pairs[0]
        .near
        .clone();
    let slot_before = read_bytes(before.start, PAGE_SIZE);
    task.sys_mprotect(code, PAGE_SIZE, ProtFlags::PROT_READ_WRITE)
        .unwrap();
    code.copy_from_slice::<TestPlatform>(4, &0xd4000001u32.to_le_bytes())
        .unwrap();
    task.sys_mprotect(code, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    let word = code.to_owned_slice::<TestPlatform>(8).unwrap();
    assert_ne!(&word[4..8], &0xd4000001u32.to_le_bytes());
    assert_eq!(
        task.global.elf_patch_cache.lock()[&key].islands.pairs.len(),
        2
    );
    assert_eq!(read_bytes(before.start, PAGE_SIZE), slot_before);
    task.sys_munmap(base, 4 * PAGE_SIZE).unwrap();
    task.sys_close(fd).unwrap();
}

#[test]
fn serialized_remap_reinstalls_retired_pair_and_reuses_surviving_reference() {
    let task = init_platform();
    let (fd, key) = open_image(&task, "/aot-remap", &aot_image());
    let base = map_file(&task, fd, 4 * PAGE_SIZE, ProtFlags::PROT_READ);
    let first = UserPtrMut::from_usize(base.as_usize() + PAGE_SIZE);
    let second = UserPtrMut::from_usize(base.as_usize() + 3 * PAGE_SIZE);
    task.sys_mprotect(first, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    task.sys_mprotect(second, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    let near = task.global.elf_patch_cache.lock()[&key].islands.pairs[0]
        .near
        .clone();
    task.sys_munmap(first, PAGE_SIZE).unwrap();
    task.sys_munmap(second, PAGE_SIZE).unwrap();
    assert!(
        task.global.elf_patch_cache.lock()[&key]
            .islands
            .pairs
            .is_empty()
    );
    task.sys_mmap(
        first.as_usize(),
        PAGE_SIZE,
        ProtFlags::PROT_READ_EXEC,
        MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE,
        fd,
        PAGE_SIZE,
    )
    .unwrap();
    {
        let cache = task.global.elf_patch_cache.lock();
        let pairs = &cache[&key].islands.pairs;
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].near, near);
        assert_eq!(pairs[0].sites, [first.as_usize()]);
    }
    task.sys_mmap(
        second.as_usize(),
        PAGE_SIZE,
        ProtFlags::PROT_READ_EXEC,
        MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE,
        fd,
        3 * PAGE_SIZE,
    )
    .unwrap();
    let far = task.global.elf_patch_cache.lock()[&key].islands.pairs[0]
        .far
        .clone();
    // Replacing one source LOAD must not retire the second LOAD's pair or
    // unmap any bytes just installed by MAP_FIXED.
    task.sys_mmap(
        first.as_usize(),
        PAGE_SIZE,
        ProtFlags::PROT_READ_EXEC,
        MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE,
        fd,
        PAGE_SIZE,
    )
    .unwrap();
    {
        let cache = task.global.elf_patch_cache.lock();
        let pairs = &cache[&key].islands.pairs;
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].far, far);
        assert_eq!(pairs[0].sites.len(), 2);
    }
    task.sys_munmap(base, 4 * PAGE_SIZE).unwrap();
    task.sys_close(fd).unwrap();
}

fn gapless_image() -> Vec<u8> {
    let mut bytes = image();
    bytes.truncate(2 * PAGE_SIZE);
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    // One syscall, one island above the image, no internal LOAD holes.
    bytes[PAGE_SIZE + 4..].fill(0);
    bytes
}

#[test]
fn mmap_envelope_reservations_survive_close_split_and_multiple_biases() {
    let task = init_platform();
    let bytes = litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
        &gapless_image(),
        None,
        crate::aarch64_rewrite_options(),
    )
    .unwrap();
    let island = serialized_island_extent(&bytes, HOST_PAGE_SIZE);
    assert!(island.start >= 2 * PAGE_SIZE);
    create_file(&task, "/mmap-envelope", &bytes);
    let fd = open(&task, "/mmap-envelope");
    let key = super::super::tests::elf_patch_key(&task, fd);
    let before = task.global.mm.mappings();
    let mut instances = Vec::new();
    for _ in 0..2 {
        let address = task
            .sys_mmap(
                0,
                2 * PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd,
                0,
            )
            .unwrap();
        instances.push(address);
        let cache = task.global.elf_patch_cache.lock();
        let state = cache.get(&key).unwrap();
        let bias = state
            .islands
            .mapping(address.as_usize(), 2 * PAGE_SIZE)
            .unwrap()
            .bias
            .unwrap();
        assert_eq!(bias, address.as_usize());
        let extras = state
            .islands
            .mmap_reservations
            .iter()
            .filter(|(b, _)| *b == bias)
            .cloned()
            .collect::<Vec<_>>();
        let extra = bias + island.start..bias + island.end;
        assert_eq!(extras, [(bias, extra.clone())]);
        let mappings = task.global.mm.mappings();
        assert!(mappings.iter().any(|(r, f)| r.contains(&bias)
            && f.contains(VmFlags::VM_READ)
            && !f.contains(VmFlags::VM_EXEC)));
        assert!(mappings.iter().any(|(r, f)| r.start <= extra.start
            && extra.end <= r.end
            && !f.intersects(VmFlags::VM_ACCESS_FLAGS)));
    }
    for instance in &instances {
        let extra = UserPtrMut::from_usize(instance.as_usize() + island.start);
        assert_eq!(
            task.sys_madvise(extra, 1, litebox_common_linux::MadviseBehavior::DontNeed),
            Err(Errno::EBUSY)
        );
        task.sys_mprotect(extra, island.len(), ProtFlags::PROT_READ_EXEC)
            .unwrap();
        assert!(task.global.mm.mappings().iter().any(|(r, f)| {
            r.contains(&extra.as_usize()) && !f.intersects(VmFlags::VM_ACCESS_FLAGS)
        }));
        assert!(matches!(
            task.sys_mremap(
                extra,
                island.len(),
                island.len() + PAGE_SIZE,
                MRemapFlags::MREMAP_MAYMOVE,
                0
            ),
            Err(Errno::EINVAL)
        ));
    }
    task.sys_close(fd).unwrap();
    task.sys_munmap(instances[0], PAGE_SIZE).unwrap();
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = cache.get(&key).unwrap();
        assert_eq!(state.islands.mmap_reservations.len(), 2);
        assert_eq!(
            state
                .islands
                .mapping(instances[0].as_usize() + PAGE_SIZE, PAGE_SIZE)
                .unwrap()
                .offset,
            PAGE_SIZE
        );
    }
    // Publishing one instance consumes only its own provenance, after fdclose.
    task.sys_mprotect(instances[1], 2 * PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    assert_eq!(
        task.global
            .elf_patch_cache
            .lock()
            .get(&key)
            .unwrap()
            .islands
            .mmap_reservations
            .len(),
        1
    );
    // The envelope trims slack between the guest LOAD and a host-aligned island.
    // Fill that hole explicitly: Vmem rejects partially owned FIXED spans.
    let file_end = instances[0].as_usize() + 2 * PAGE_SIZE;
    let extra_start = instances[0].as_usize() + island.start;
    if file_end < extra_start {
        task.sys_mmap(
            file_end,
            extra_start - file_end,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
        .unwrap();
    }
    // Replace both the surviving guest LOAD page and the entire extra host page.
    // Reservation cleanup must not release any of the NEW mapping.
    let replacement = instances[0].as_usize() + PAGE_SIZE;
    let replacement_len = island.end - PAGE_SIZE;
    task.sys_mmap(
        replacement,
        replacement_len,
        ProtFlags::PROT_READ_WRITE,
        MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
        -1,
        0,
    )
    .unwrap();
    assert!(
        task.global
            .mm
            .mappings()
            .iter()
            .any(|(r, f)| r.start <= replacement
                && r.end >= replacement + replacement_len
                && f.contains(VmFlags::VM_WRITE))
    );
    task.sys_munmap(UserPtrMut::from_usize(replacement), replacement_len)
        .unwrap();
    task.sys_munmap(instances[1], 2 * PAGE_SIZE).unwrap();
    assert!(!task.global.elf_patch_cache.lock().contains_key(&key));
    assert_eq!(task.global.mm.mappings(), before);
}

#[test]
fn mmap_envelope_failed_publication_rolls_back_requested_and_extra_pages() {
    let task = init_platform();
    let bytes = litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
        &gapless_image(),
        None,
        crate::aarch64_rewrite_options(),
    )
    .unwrap();
    create_file(&task, "/mmap-envelope-fail", &bytes);
    let fd = open(&task, "/mmap-envelope-fail");
    let key = super::super::tests::elf_patch_key(&task, fd);
    task.init_elf_patch_state(&key, 0, 0);
    // Inject a deterministic prepublication failure after reserving the envelope.
    task.global
        .elf_patch_cache
        .lock()
        .get_mut(&key)
        .unwrap()
        .trampoline_invalidated = true;
    let before = task.global.mm.mappings();
    assert!(
        task.sys_mmap(
            0,
            2 * PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC,
            MapFlags::MAP_PRIVATE,
            fd,
            0
        )
        .is_err()
    );
    assert_eq!(task.global.mm.mappings(), before);
    assert!(!task.global.elf_patch_cache.lock().contains_key(&key));
    task.sys_close(fd).unwrap();
}

#[test]
fn shared_offset_bias_requires_whole_span_geometry_or_known_instance() {
    let mut state = RuntimeIslands {
        loads: alloc::vec![
            Load {
                file: 0..PAGE_SIZE,
                address: 0..PAGE_SIZE
            },
            Load {
                file: 0..PAGE_SIZE,
                address: PAGE_SIZE..3 * PAGE_SIZE
            }
        ],
        whole_span: Some(WholeSpan {
            address: 0..3 * PAGE_SIZE,
            offset: 0,
            align: PAGE_SIZE,
        }),
        ..Default::default()
    };
    state.record_mapping(0x100000, PAGE_SIZE, 0, None).unwrap();
    assert_eq!(state.mappings[0].bias, None);
    state
        .record_mapping(0x200000, 3 * PAGE_SIZE, 0, None)
        .unwrap();
    assert_eq!(state.mappings[1].bias, Some(0x200000));
    state.record_mapping(0x201000, PAGE_SIZE, 0, None).unwrap();
    assert_eq!(state.mappings[2].bias, Some(0x200000));
    state
        .record_mapping(0x300000, 3 * PAGE_SIZE, 0, None)
        .unwrap();
    assert_eq!(state.mappings[3].bias, Some(0x300000));
}

#[test]
fn unrewritten_elf_incidental_litebox_tail_loads_and_rewrites() {
    let task = init_platform();
    let mut bytes = gapless_image();
    bytes.extend_from_slice(b"arbitrary trailing LITEBOX text!!");
    create_file(&task, "/incidental-litebox", &bytes);
    let fd = open(&task, "/incidental-litebox");
    let address = task
        .sys_mmap(
            0,
            2 * PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC,
            MapFlags::MAP_PRIVATE,
            fd,
            0,
        )
        .unwrap();
    let word = UserPtrMut::<u32>::from_usize(address.as_usize() + PAGE_SIZE)
        .read_at_offset::<TestPlatform>(0)
        .unwrap();
    assert_eq!(word & 0xfc000000, 0x14000000);
    task.sys_close(fd).unwrap();
    task.sys_munmap(address, 2 * PAGE_SIZE).unwrap();
}

fn nonzero_load_image() -> Vec<u8> {
    let mut elf = gapless_image();
    elf[PAGE_SIZE..PAGE_SIZE + 4].fill(0);
    elf[0x110..0x114].copy_from_slice(&0xd4000001u32.to_le_bytes());
    elf[80..88].copy_from_slice(&0x10000u64.to_le_bytes());
    elf[112..120].copy_from_slice(&0x10000u64.to_le_bytes());
    elf
}

#[test]
fn serialized_envelope_geometry_for_4k_and_16k_hosts() {
    use litebox_syscall_rewriter::{RewriteOptions, TargetHost};

    // Pure file geometry: exercise both emitters without changing the platform
    // or executing foreign-host instructions. The over-aligned LOAD stays at
    // 0x10000; its nearest island moves from below it to above it on macOS.
    for (host, granule, expected) in [
        (TargetHost::Linux, 4096, [0x2000..0x3000, 0xf000..0x10000]),
        (TargetHost::MacOs, 16384, [0x4000..0x8000, 0x14000..0x18000]),
    ] {
        for (elf, extent) in [gapless_image(), nonzero_load_image()]
            .into_iter()
            .zip(expected)
        {
            let bytes = litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
                &elf,
                None,
                RewriteOptions::new(host, host == TargetHost::MacOs),
            )
            .unwrap();
            assert_eq!(serialized_island_extent(&bytes, granule), extent);
        }
    }
}

#[test]
fn mmap_envelope_nonzero_load_keeps_file_start_offset_and_aligned_bias() {
    let task = init_platform();
    let elf = nonzero_load_image();
    let bytes = litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
        &elf,
        None,
        crate::aarch64_rewrite_options(),
    )
    .unwrap();
    let island = serialized_island_extent(&bytes, HOST_PAGE_SIZE);
    assert!(!overlaps(&island, &(0x10000..0x10000 + 2 * PAGE_SIZE)));
    create_file(&task, "/mmap-envelope-nonzero", &bytes);
    let fd = open(&task, "/mmap-envelope-nonzero");
    let key = super::super::tests::elf_patch_key(&task, fd);
    let before = task.global.mm.mappings();
    let address = task
        .sys_mmap(
            0,
            2 * PAGE_SIZE,
            ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE,
            fd,
            0,
        )
        .unwrap();
    assert_eq!(
        &*address.to_owned_slice::<TestPlatform>(64).unwrap(),
        &elf[..64]
    );
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = cache.get(&key).unwrap();
        let mapping = state
            .islands
            .mapping(address.as_usize(), 2 * PAGE_SIZE)
            .unwrap();
        let bias = mapping.bias.unwrap();
        assert_eq!(bias % 0x10000, 0);
        assert_eq!(address.as_usize(), bias + 0x10000);
        assert_eq!(mapping.offset, 0);
        assert_eq!(
            state.islands.mmap_reservations,
            [(bias, bias + island.start..bias + island.end)]
        );
    }
    task.sys_close(fd).unwrap();
    task.sys_munmap(address, 2 * PAGE_SIZE).unwrap();
    assert!(!task.global.elf_patch_cache.lock().contains_key(&key));
    assert_eq!(task.global.mm.mappings(), before);
}

#[test]
fn serialized_large_alignment_probe_fixed_mapping() {
    let task = init_platform();
    let mut original = gapless_image();
    original[112..120].copy_from_slice(&0x10000u64.to_le_bytes());
    let bytes = litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
        &original,
        None,
        crate::aarch64_rewrite_options(),
    )
    .unwrap();
    create_file(&task, "/aligned-aot", &bytes);
    let fd = open(&task, "/aligned-aot");
    let before = task.global.mm.mappings();
    // ld.so _dl_map_segment (fixture PCs 0x78c8, 0x7904): reserve
    // max(maplength, p_align) + p_align, then MAP_FIXED at the aligned start.
    let probe = task
        .sys_mmap(
            0,
            0x20000,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            -1,
            0,
        )
        .unwrap();
    let base = align_up(probe.as_usize(), 0x10000);
    let mapped = task.sys_mmap(
        base,
        2 * PAGE_SIZE,
        ProtFlags::PROT_READ_EXEC,
        MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
        fd,
        0,
    );
    assert_eq!(
        mapped.as_ref().map(UserPtrMut::as_usize),
        Ok(base),
        "AOT fixed mapping inside alignment probe {:#x}..{:#x}",
        probe.as_usize(),
        probe.as_usize() + 0x20000
    );
    if probe.as_usize() < base {
        task.sys_munmap(probe, base - probe.as_usize()).unwrap();
    }
    task.sys_munmap(
        UserPtrMut::from_usize(base + 2 * PAGE_SIZE),
        probe.as_usize() + 0x20000 - base - 2 * PAGE_SIZE,
    )
    .unwrap();
    task.sys_close(fd).unwrap();
    task.sys_munmap(UserPtrMut::from_usize(base), 2 * PAGE_SIZE)
        .unwrap();
    assert_eq!(task.global.mm.mappings(), before);
}

#[test]
#[cfg(feature = "aarch64_virtualize_x18")]
fn unsupported_sites_do_not_allocate_or_abort_supported_sites() {
    for supported in [false, true] {
        let task = init_platform();
        let mut bytes = image();
        let at = 3 * PAGE_SIZE;
        bytes[at..at + 4].copy_from_slice(&0x58000012u32.to_le_bytes()); // unsupported LDR literal x18
        if supported {
            bytes[at + 4..at + 8].copy_from_slice(&0xd4000001u32.to_le_bytes());
        }
        let path = if supported {
            "/mixed-unsupported"
        } else {
            "/only-unsupported"
        };
        create_file(&task, path, &bytes);
        let fd = open(&task, path);
        let length = 256 * 1024 * 1024;
        let reserved = task
            .sys_mmap(
                0,
                length,
                ProtFlags::PROT_NONE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
                -1,
                0,
            )
            .unwrap();
        let address = reserved.as_usize() + length / 2;
        if supported {
            // Exactly one usable near page: allocating for the unsupported site fails.
            task.sys_munmap(
                UserPtrMut::from_usize(address - 4 * HOST_PAGE_SIZE),
                HOST_PAGE_SIZE,
            )
            .unwrap();
        }
        let mapped = task
            .sys_mmap(
                address,
                PAGE_SIZE,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                fd,
                at,
            )
            .unwrap();
        let key = super::super::tests::elf_patch_key(&task, fd);
        task.sys_mprotect(mapped, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
            .unwrap();
        let code = mapped.to_owned_slice::<TestPlatform>(8).unwrap();
        assert_eq!(
            u32::from_le_bytes(code[..4].try_into().unwrap()) & 0xffe0001f,
            0xd4200000
        );
        if supported {
            assert_eq!(
                u32::from_le_bytes(code[4..8].try_into().unwrap()) & 0xfc000000,
                0x14000000
            );
        }
        assert_eq!(
            task.global.elf_patch_cache.lock()[&key].islands.pairs.len(),
            usize::from(supported)
        );
        task.sys_close(fd).unwrap();
        task.sys_mprotect(mapped, PAGE_SIZE, ProtFlags::PROT_READ_WRITE)
            .unwrap();
        assert_eq!(
            task.sys_madvise(mapped, 1, litebox_common_linux::MadviseBehavior::DontNeed),
            Err(Errno::EBUSY)
        ); // includes the no-pair, unsupported-only case
        task.sys_mprotect(mapped, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
            .unwrap();
        assert_eq!(&*mapped.to_owned_slice::<TestPlatform>(8).unwrap(), &*code);
        task.sys_munmap(reserved, length).unwrap();
    }
}

#[test]
fn source_publication_error_remains_invalidated() {
    let task = init_platform();
    let bytes = retirement_image();
    create_file(&task, "/source-publication-failure", &bytes);
    let fd = open(&task, "/source-publication-failure");
    let mapped = task
        .sys_mmap(
            0,
            bytes.len(),
            ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE,
            fd,
            0,
        )
        .unwrap();
    let code = UserPtrMut::from_usize(mapped.as_usize() + PAGE_SIZE);
    let gap = UserPtrMut::<u8>::from_usize(mapped.as_usize() + 2 * HOST_PAGE_SIZE);
    let key = super::super::tests::elf_patch_key(&task, fd);
    {
        let mut cache = task.global.elf_patch_cache.lock();
        let state = cache.get_mut(&key).unwrap();
        let loads = state.islands.future_loads().unwrap();
        // Existing fallible protection seam, after source stores: an unmapped
        // restore range must not turn a potentially partial publication retryable.
        assert!(
            task.patch_exec_with_islands(
                state,
                mapped,
                bytes.len(),
                &[(0, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)],
                &loads,
                None
            )
            .is_err()
        );
        assert!(state.trampoline_invalidated);
        assert_eq!(state.islands.pairs.len(), 1);
        assert_eq!(state.islands.pairs[0].near.start, gap.as_usize());
        assert_eq!(state.islands.pairs[0].sites, [code.as_usize()]);
    }
    assert_eq!(
        task.sys_mprotect(code, PAGE_SIZE, ProtFlags::PROT_READ_EXEC),
        Err(Errno::ENOMEM)
    );
    assert!(
        task.global
            .mm
            .mappings()
            .iter()
            .filter(|(r, _)| r.contains(&code.as_usize()))
            .all(|(_, flags)| !flags.contains(VmFlags::VM_EXEC))
    );
    task.sys_munmap(code, PAGE_SIZE).unwrap();
    assert_eq!(
        &*gap.to_owned_slice::<TestPlatform>(HOST_PAGE_SIZE).unwrap(),
        &bytes[2 * HOST_PAGE_SIZE..3 * HOST_PAGE_SIZE]
    );
    for offset in (0..HOST_PAGE_SIZE).step_by(PAGE_SIZE) {
        let flags = task
            .global
            .mm
            .mappings()
            .into_iter()
            .find(|(r, _)| r.contains(&(gap.as_usize() + offset)))
            .unwrap()
            .1;
        assert_eq!(flags & VmFlags::VM_ACCESS_FLAGS, VmFlags::VM_READ);
    }
    task.sys_close(fd).unwrap();
    task.sys_munmap(mapped, bytes.len()).unwrap();
    assert!(!task.global.elf_patch_cache.lock().contains_key(&key));
}

#[test]
fn runtime_brk_fallback_preserves_new_serialized_pairs() {
    let task = init_platform();
    let mut bytes = image();
    bytes[PAGE_SIZE..2 * PAGE_SIZE].fill(0);
    let bytes = litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
        &bytes,
        None,
        crate::aarch64_rewrite_options(),
    )
    .unwrap();
    create_file(&task, "/serialized-runtime-brk", &bytes);
    let fd = open(&task, "/serialized-runtime-brk");
    let length = 256 * 1024 * 1024;
    let reserved = task
        .sys_mmap(
            0,
            length,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            -1,
            0,
        )
        .unwrap();
    let address = reserved.as_usize() + length / 2;
    task.sys_munmap(
        UserPtrMut::from_usize(address - 4 * HOST_PAGE_SIZE),
        HOST_PAGE_SIZE,
    )
    .unwrap();
    let mapped = task
        .sys_mmap(
            address,
            PAGE_SIZE,
            ProtFlags::PROT_READ_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            fd,
            3 * PAGE_SIZE,
        )
        .unwrap();
    // The serialized branch still needs relocation; a new syscall also needs
    // a runtime pair, for which the constrained reservation has no room.
    mapped
        .copy_from_slice::<TestPlatform>(4, &0xd4000001u32.to_le_bytes())
        .unwrap();
    let key = super::super::tests::elf_patch_key(&task, fd);
    task.sys_mprotect(mapped, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    let code = read_bytes(address, PAGE_SIZE);
    let branch = u32::from_le_bytes(code[..4].try_into().unwrap());
    assert_eq!(branch & 0xfc000000, 0x14000000);
    assert_eq!(
        u32::from_le_bytes(code[4..8].try_into().unwrap()) & 0xffe0001f,
        0xd4200000
    );
    assert_eq!(&code[8..], &bytes[3 * PAGE_SIZE + 8..4 * PAGE_SIZE]);
    assert!(
        task.global
            .mm
            .mappings()
            .iter()
            .any(|(r, flags)| r.contains(&address)
                && flags.intersection(VmFlags::VM_ACCESS_FLAGS)
                    == VmFlags::VM_READ | VmFlags::VM_EXEC)
    );
    let (near, far, sites) = {
        let cache = task.global.elf_patch_cache.lock();
        let state = &cache[&key];
        assert!(!state.trampoline_invalidated);
        assert_eq!(state.islands.pairs.len(), 1);
        assert!(state.patched_ranges.contains(&(address, PAGE_SIZE)));
        let pair = &state.islands.pairs[0];
        assert!(pair.serialized.is_some());
        assert_eq!(pair.sites, [address]);
        let displacement = ((branch & 0x03ff_ffff) << 6).cast_signed() >> 4;
        assert_eq!(
            address as i128 + i128::from(displacement),
            (pair.near.start + island::ISLAND_HEADER_BYTES) as i128
        );
        (pair.near.clone(), pair.far.clone(), pair.sites.clone())
    };
    let transport: Vec<_> = [&near, &far]
        .into_iter()
        .map(|r| {
            UserPtrMut::<u8>::from_usize(r.start)
                .to_owned_slice::<TestPlatform>(r.len())
                .unwrap()
        })
        .collect();
    task.sys_munmap(
        UserPtrMut::from_usize(address - 8 * HOST_PAGE_SIZE),
        HOST_PAGE_SIZE,
    )
    .unwrap();
    task.sys_mprotect(mapped, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = &cache[&key];
        assert_eq!(state.islands.pairs.len(), 1);
        let pair = &state.islands.pairs[0];
        assert_eq!((&pair.near, &pair.far, &pair.sites), (&near, &far, &sites));
    }
    for (r, bytes) in [&near, &far].into_iter().zip(transport) {
        assert_eq!(
            UserPtrMut::<u8>::from_usize(r.start)
                .to_owned_slice::<TestPlatform>(r.len())
                .unwrap(),
            bytes
        );
    }
    assert_eq!(read_bytes(address, PAGE_SIZE), code);
    // Only an explicit writable edit supplies a fresh runtime instruction to scan.
    task.sys_mprotect(mapped, PAGE_SIZE, ProtFlags::PROT_READ_WRITE)
        .unwrap();
    mapped
        .copy_from_slice::<TestPlatform>(4, &0xd4000001u32.to_le_bytes())
        .unwrap();
    task.sys_mprotect(mapped, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    assert_eq!(
        task.global.elf_patch_cache.lock()[&key].islands.pairs.len(),
        2
    );
    let edited = read_bytes(address, 8);
    assert_eq!(&edited[..4], &code[..4]);
    assert_eq!(
        u32::from_le_bytes(edited[4..8].try_into().unwrap()) & 0xfc000000,
        0x14000000
    );
    task.sys_munmap(reserved, length).unwrap();
    task.sys_close(fd).unwrap();
}

fn aliased_load_image() -> Vec<u8> {
    let mut bytes = image_with_gap(HOST_PAGE_SIZE);
    bytes[68..72].copy_from_slice(&4u32.to_le_bytes()); // first LOAD is read-only
    for (at, value) in [
        (96, 0x200usize),
        (104, 0x200),
        (128, 0x200),
        (136, HOST_PAGE_SIZE + 0x200),
        (152, 4),
        (160, 4),
        (168, PAGE_SIZE),
    ] {
        bytes[at..at + 8].copy_from_slice(&(value as u64).to_le_bytes());
    }
    bytes[0x200..0x204].copy_from_slice(&0xd400_0001u32.to_le_bytes());
    bytes
}

#[test]
fn explicit_load_bias_is_per_mapping_not_per_fd() {
    let task = init_platform();
    create_file(&task, "/aliased-loads", &aliased_load_image());
    let fd = open(&task, "/aliased-loads");
    let key = super::super::tests::elf_patch_key(&task, fd);
    let envelope = task
        .sys_mmap(
            0,
            6 * HOST_PAGE_SIZE,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            -1,
            0,
        )
        .unwrap();
    let base = envelope.as_usize();
    let map = |address, bias| {
        task.mmap_with_source(
            address,
            PAGE_SIZE,
            ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            fd,
            super::super::FileMappingSource {
                offset: 0,
                load_bias: Some(bias),
            },
        )
    };
    map(base, base).unwrap();
    map(base + HOST_PAGE_SIZE, base).unwrap();
    // A second instance of the same descriptor keeps its own immutable bias.
    let second = base + 2 * HOST_PAGE_SIZE;
    map(second, second).unwrap();
    map(second + HOST_PAGE_SIZE, second).unwrap();
    let ambiguous = base + 4 * HOST_PAGE_SIZE;
    task.sys_mmap(
        ambiguous,
        PAGE_SIZE,
        ProtFlags::PROT_READ,
        MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
        fd,
        0,
    )
    .unwrap();
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = &cache[&key].islands;
        for (address, bias) in [
            (base, base),
            (base + HOST_PAGE_SIZE, base),
            (second, second),
            (second + HOST_PAGE_SIZE, second),
        ] {
            let m = state.mapping(address, PAGE_SIZE).unwrap();
            assert_eq!(m.bias, Some(bias));
            assert!(m.loader_managed);
        }
        assert_eq!(state.mapping(ambiguous, PAGE_SIZE).unwrap().bias, None);
    }
    // Invalid source provenance is rejected before replacing the old mapping.
    let before = task.global.mm.mappings();
    assert_eq!(map(base, base + HOST_PAGE_SIZE).err(), Some(Errno::ENOEXEC));
    assert_eq!(task.global.mm.mappings(), before);
    assert_eq!(
        task.sys_mremap(
            envelope,
            PAGE_SIZE,
            PAGE_SIZE,
            MRemapFlags::MREMAP_MAYMOVE,
            0
        )
        .err(),
        Some(Errno::EINVAL)
    );
    assert_eq!(task.global.mm.mappings(), before);
    // A valid hint must also disappear after failed executable publication.
    let metadata = task
        .global
        .elf_patch_cache
        .lock()
        .get_mut(&key)
        .unwrap()
        .code_metadata
        .take();
    let failed = base + 5 * HOST_PAGE_SIZE;
    assert!(
        task.mmap_with_source(
            failed,
            PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            fd,
            super::super::FileMappingSource {
                offset: 0,
                load_bias: Some(ambiguous)
            },
        )
        .is_err()
    );
    {
        let mut cache = task.global.elf_patch_cache.lock();
        let state = cache.get_mut(&key).unwrap();
        assert!(state.islands.mapping(failed, PAGE_SIZE).is_none());
        state.code_metadata = metadata;
    }
    task.sys_mmap(
        failed,
        PAGE_SIZE,
        ProtFlags::PROT_READ,
        MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
        fd,
        0,
    )
    .unwrap();
    assert_eq!(
        task.global.elf_patch_cache.lock()[&key]
            .islands
            .mapping(failed, PAGE_SIZE)
            .unwrap()
            .bias,
        None
    );
    task.sys_close(fd).unwrap();
    for address in [base + HOST_PAGE_SIZE, second + HOST_PAGE_SIZE] {
        task.sys_mprotect(
            UserPtrMut::from_usize(address),
            PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC,
        )
        .unwrap();
    }
    // Deferred publication keeps the original immutable identities after close.
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = &cache[&key].islands;
        assert_eq!(state.pairs.len(), 2);
        assert_eq!(
            state
                .mapping(base + HOST_PAGE_SIZE, PAGE_SIZE)
                .unwrap()
                .bias,
            Some(base)
        );
        assert_eq!(
            state
                .mapping(second + HOST_PAGE_SIZE, PAGE_SIZE)
                .unwrap()
                .bias,
            Some(second)
        );
    }
    assert!(
        task.sys_mprotect(
            UserPtrMut::from_usize(ambiguous),
            PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC
        )
        .is_err()
    );
    task.sys_munmap(envelope, 6 * HOST_PAGE_SIZE).unwrap();
    assert!(task.global.elf_patch_cache.lock().get(&key).is_none());
}

#[test]
fn explicit_load_bias_validation_and_retirement() {
    let mut state = RuntimeIslands {
        loads: alloc::vec![
            Load {
                file: 0..PAGE_SIZE,
                address: 0..PAGE_SIZE
            },
            Load {
                file: 0..PAGE_SIZE,
                address: HOST_PAGE_SIZE..HOST_PAGE_SIZE + PAGE_SIZE
            },
        ],
        load_alignment: Some(HOST_PAGE_SIZE),
        ..Default::default()
    };
    let base = 0x100_0000;
    state
        .record_mapping(base, PAGE_SIZE, 0, Some(base))
        .unwrap();
    // This ambiguous guest map has the loader's bias as one candidate. It must
    // not inherit it, even though it uses the very same descriptor and bytes.
    state
        .record_mapping(base + HOST_PAGE_SIZE, PAGE_SIZE, 0, None)
        .unwrap();
    assert_eq!(state.mappings[1].bias, None);
    for (start, len, offset, bias) in [
        (base, PAGE_SIZE, 0, base + HOST_PAGE_SIZE),
        (base, PAGE_SIZE, PAGE_SIZE, base),
        (base, 2 * PAGE_SIZE, 0, base),
        (base + 1, PAGE_SIZE, 0, base + 1),
        (base, 0, 0, base),
    ] {
        assert!(
            state
                .record_mapping(start, len, offset, Some(bias))
                .is_err()
        );
        assert_eq!(state.mappings.len(), 2);
    }
    state.remove(&(base + HOST_PAGE_SIZE..base + 2 * HOST_PAGE_SIZE));
    // Both base and base + HOST_PAGE_SIZE are candidates. This explicitly
    // chosen second instance must not be mistaken for the first instance's RX.
    state
        .record_mapping(
            base + HOST_PAGE_SIZE,
            PAGE_SIZE,
            0,
            Some(base + HOST_PAGE_SIZE),
        )
        .unwrap();
    assert_eq!(state.mappings[1].bias, Some(base + HOST_PAGE_SIZE));
    state.remove(&(base..base + 2 * HOST_PAGE_SIZE));
    state.record_mapping(base, PAGE_SIZE, 0, None).unwrap();
    assert_eq!(state.mappings[0].bias, None);
    assert!(state.future_loads().unwrap().is_empty());
    // Guest-page-aligned explicit loads need not have host-page-aligned bias.
    state.load_alignment = Some(PAGE_SIZE);
    state
        .validate_load_mapping(base + PAGE_SIZE, PAGE_SIZE, 0, base + PAGE_SIZE)
        .unwrap();
    state.load_alignment = Some(16 * PAGE_SIZE);
    assert_eq!(
        state.validate_load_mapping(base + PAGE_SIZE, PAGE_SIZE, 0, base + PAGE_SIZE),
        Err(Errno::ENOEXEC)
    );
    // Overflow in any other biased LOAD invalidates explicit provenance too.
    state.loads[1].address = usize::MAX - HOST_PAGE_SIZE + 1..usize::MAX;
    assert_eq!(
        state.record_mapping(base, PAGE_SIZE, 0, Some(base)),
        Err(Errno::EOVERFLOW)
    );
    assert_eq!(state.mappings.len(), 1);
}

fn retirement_image() -> Vec<u8> {
    let mut bytes = image_with_gap(HOST_PAGE_SIZE);
    bytes[PAGE_SIZE + 4..2 * HOST_PAGE_SIZE].fill(0);
    bytes[3 * HOST_PAGE_SIZE..].fill(0);
    bytes[2 * HOST_PAGE_SIZE..3 * HOST_PAGE_SIZE].fill(0x5a);
    bytes
}

#[test]
fn retired_pair_restores_surviving_file_gap() {
    let task = init_platform();
    let bytes = retirement_image();
    let (fd, key) = open_image(&task, "/retired-gap", &bytes);
    let base = map_file(&task, fd, bytes.len(), ProtFlags::PROT_READ);
    let code = UserPtrMut::from_usize(base.as_usize() + PAGE_SIZE);
    let gap = UserPtrMut::<u8>::from_usize(base.as_usize() + 2 * HOST_PAGE_SIZE);
    task.sys_mprotect(code, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
        .unwrap();
    let far = {
        let cache = task.global.elf_patch_cache.lock();
        let pair = &cache[&key].islands.pairs[0];
        assert_eq!(pair.near.start, gap.as_usize());
        pair.far.clone()
    };
    {
        let mut cache = task.global.elf_patch_cache.lock();
        let state = cache.get_mut(&key).unwrap();
        let loads = state.islands.future_loads().unwrap();
        // A later scan snapshots the existing near page as RX, but must not
        // overwrite its deferred read-only guest intent during publication.
        task.patch_exec_with_islands(
            state,
            base,
            bytes.len(),
            &[(base.as_usize(), bytes.len(), ProtFlags::PROT_READ)],
            &loads,
            None,
        )
        .unwrap();
    }
    task.sys_close(fd).unwrap();
    task.sys_munmap(code, PAGE_SIZE).unwrap();
    assert!(
        task.global
            .mm
            .mappings()
            .iter()
            .any(|(r, f)| r.contains(&gap.as_usize())
                && *f & VmFlags::VM_ACCESS_FLAGS == VmFlags::VM_READ)
    );
    assert_eq!(
        &*gap.to_owned_slice::<TestPlatform>(HOST_PAGE_SIZE).unwrap(),
        &bytes[2 * HOST_PAGE_SIZE..3 * HOST_PAGE_SIZE]
    );
    assert!(
        !task
            .global
            .mm
            .mappings()
            .iter()
            .any(|(r, _)| overlaps(r, &far))
    );
    // The borrow retained file-backed identity, not merely the access flags.
    assert_eq!(
        task.sys_madvise(gap, 1, litebox_common_linux::MadviseBehavior::DontNeed),
        Err(Errno::EINVAL)
    );
    task.sys_munmap(base, bytes.len()).unwrap();
    assert!(!task.global.elf_patch_cache.lock().contains_key(&key));
}

#[test]
fn anonymous_mremap_ignores_overflowing_nonfixed_destination() {
    let task = init_platform();
    let base = task
        .sys_mmap(
            0,
            2 * HOST_PAGE_SIZE,
            ProtFlags::PROT_READ_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            -1,
            0,
        )
        .unwrap();
    assert_eq!(
        task.sys_mremap(
            base,
            2 * HOST_PAGE_SIZE,
            HOST_PAGE_SIZE,
            MRemapFlags::empty(),
            usize::MAX
        )
        .unwrap()
        .as_usize(),
        base.as_usize()
    );
    assert!(matches!(
        task.sys_mremap(
            base,
            HOST_PAGE_SIZE,
            HOST_PAGE_SIZE,
            MRemapFlags::MREMAP_MAYMOVE | MRemapFlags::MREMAP_FIXED,
            usize::MAX
        ),
        Err(Errno::EINVAL)
    ));
    task.sys_munmap(base, HOST_PAGE_SIZE).unwrap();
}

#[test]
fn dontneed_allows_ordinary_elf_data_but_not_rewritten_sources() {
    use litebox_common_linux::MadviseBehavior::DontNeed;
    let task = init_platform();
    let mut bytes = image_with_gap(HOST_PAGE_SIZE);
    bytes[124..128].copy_from_slice(&6u32.to_le_bytes()); // second LOAD is data
    create_file(&task, "/advice-data", &bytes);
    let fd = open(&task, "/advice-data");
    let base = task
        .sys_mmap(
            0,
            bytes.len(),
            ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE,
            fd,
            0,
        )
        .unwrap();
    let code = UserPtrMut::from_usize(base.as_usize() + PAGE_SIZE);
    let data = UserPtrMut::from_usize(base.as_usize() + 3 * HOST_PAGE_SIZE);
    assert_eq!(task.sys_madvise(code, 1, DontNeed), Err(Errno::EINVAL)); // never-executable
    // Whole ld.so RX spans must not permanently classify their data as source.
    task.sys_mprotect(base, bytes.len(), ProtFlags::PROT_READ_EXEC)
        .unwrap();
    task.sys_mprotect(data, HOST_PAGE_SIZE, ProtFlags::PROT_READ)
        .unwrap();
    let key = super::super::tests::elf_patch_key(&task, fd);
    task.sys_close(fd).unwrap();
    let transport: Vec<_> = task.global.elf_patch_cache.lock()[&key]
        .islands
        .owned_ranges()
        .collect();
    for range in transport {
        assert_eq!(
            task.sys_madvise(UserPtrMut::from_usize(range.end - PAGE_SIZE), 1, DontNeed),
            Err(Errno::EBUSY)
        );
    }
    // File reset is unsupported by the underlying VM, not blocked by islands.
    assert_eq!(task.sys_madvise(data, 1, DontNeed), Err(Errno::EINVAL));
    assert_eq!(
        &*data.to_owned_slice::<TestPlatform>(PAGE_SIZE).unwrap(),
        &bytes[3 * HOST_PAGE_SIZE..3 * HOST_PAGE_SIZE + PAGE_SIZE]
    );
    assert_eq!(task.sys_madvise(code, 0, DontNeed), Ok(()));
    assert_eq!(task.sys_madvise(code, 1, DontNeed), Err(Errno::EBUSY));
    task.sys_mprotect(code, PAGE_SIZE, ProtFlags::PROT_READ_WRITE)
        .unwrap();
    assert_eq!(
        task.sys_madvise(code, PAGE_SIZE, DontNeed),
        Err(Errno::EBUSY)
    );
    task.sys_munmap(base, bytes.len()).unwrap();
}

#[test]
fn retired_loader_reservation_restores_hidden_bytes_and_guest_page_intent() {
    check_retired_loader_reservation(true);
}

#[test]
fn retired_loader_reservation_survives_close_after_source_unmap() {
    check_retired_loader_reservation(false);
}

fn check_retired_loader_reservation(close_before_retirement: bool) {
    use litebox_common_linux::MadviseBehavior::DontNeed;
    let task = init_platform();
    let bytes = litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
        &retirement_image(),
        None,
        crate::aarch64_rewrite_options(),
    )
    .unwrap();
    let payload = litebox_syscall_rewriter::aarch64::elf_islands::ElfIslands::parse(&bytes)
        .unwrap()
        .unwrap();
    let extent = serialized_island_extent(&bytes, HOST_PAGE_SIZE);
    let path = if close_before_retirement {
        "/loader-retirement"
    } else {
        "/loader-retirement-close-after"
    };
    let (fd, key) = open_image(&task, path, &bytes);
    let before = task.global.mm.mappings();
    let base = task.allocate_chunk(4 * HOST_PAGE_SIZE, &[], None).unwrap();
    let near = UserPtrMut::<u8>::from_usize(base.as_usize() + extent.start);
    let saved = alloc::vec![0x5a; HOST_PAGE_SIZE];
    near.copy_from_slice::<TestPlatform>(0, &saved).unwrap();
    task.sys_mprotect(base, 4 * HOST_PAGE_SIZE, ProtFlags::PROT_NONE)
        .unwrap();
    task.prepare_serialized_islands(&key, &payload, base.as_usize(), true)
        .unwrap();
    assert_eq!(task.sys_madvise(near, 1, DontNeed), Err(Errno::EBUSY));
    let code = task
        .sys_mmap(
            base.as_usize() + PAGE_SIZE,
            PAGE_SIZE,
            ProtFlags::PROT_READ_EXEC,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            fd,
            PAGE_SIZE,
        )
        .unwrap();
    assert_eq!(
        task.global.elf_patch_cache.lock()[&key].islands.pairs[0]
            .near
            .start,
        near.as_usize()
    );
    if close_before_retirement {
        task.sys_close(fd).unwrap();
    }
    // A failed earlier shared VMA must not update a later shadow permission.
    let path = if close_before_retirement {
        "/loader-readonly"
    } else {
        "/loader-readonly-close-after"
    };
    create_file(&task, path, &alloc::vec![0; PAGE_SIZE]);
    let readonly = open(&task, path);
    task.sys_mmap(
        base.as_usize(),
        PAGE_SIZE,
        ProtFlags::PROT_READ,
        MapFlags::MAP_SHARED | MapFlags::MAP_FIXED,
        readonly,
        0,
    )
    .unwrap();
    task.sys_close(readonly).unwrap();
    assert_eq!(
        task.sys_mprotect(base, extent.end, ProtFlags::PROT_READ_WRITE),
        Err(Errno::EACCES)
    );
    assert!(
        task.global.elf_patch_cache.lock()[&key].islands.pairs[0]
            .previous
            .as_ref()
            .unwrap()
            .protections
            .iter()
            .all(|p| *p == ProtFlags::PROT_NONE)
    );
    // On a 16KiB host, this changes only one guest page of the shadow view.
    task.sys_mprotect(near, PAGE_SIZE, ProtFlags::PROT_READ_WRITE)
        .unwrap();
    task.sys_munmap(code, PAGE_SIZE).unwrap();
    for offset in (0..HOST_PAGE_SIZE).step_by(PAGE_SIZE) {
        let flags = task
            .global
            .mm
            .mappings()
            .into_iter()
            .find(|(r, _)| r.contains(&(near.as_usize() + offset)))
            .unwrap()
            .1;
        assert_eq!(
            flags & VmFlags::VM_ACCESS_FLAGS,
            if offset == 0 {
                VmFlags::VM_READ | VmFlags::VM_WRITE
            } else {
                VmFlags::empty()
            }
        );
    }
    {
        let cache = task.global.elf_patch_cache.lock();
        let state = &cache[&key];
        assert!(state.file_mappings.is_empty());
        assert!(state.islands.pairs.is_empty());
        assert!(!state.islands.loader_reservations.is_empty());
    }
    assert_eq!(task.sys_madvise(near, 1, DontNeed), Err(Errno::EBUSY));
    if !close_before_retirement {
        task.sys_close(fd).unwrap();
    }
    assert!(task.global.elf_patch_cache.lock().contains_key(&key));
    assert_eq!(task.sys_madvise(near, 1, DontNeed), Err(Errno::EBUSY));
    task.sys_mprotect(near, HOST_PAGE_SIZE, ProtFlags::PROT_READ)
        .unwrap();
    assert_eq!(
        &*near.to_owned_slice::<TestPlatform>(HOST_PAGE_SIZE).unwrap(),
        &saved
    );
    task.sys_munmap(base, 4 * HOST_PAGE_SIZE).unwrap();
    assert!(!task.global.elf_patch_cache.lock().contains_key(&key));
    assert_eq!(task.global.mm.mappings(), before);
}

#[test]
fn retired_gap_excludes_partial_unmap_and_new_fixed_bytes() {
    for fixed in [false, true] {
        let task = init_platform();
        let bytes = retirement_image();
        let path = if fixed {
            "/fixed-retired-gap"
        } else {
            "/unmapped-retired-gap"
        };
        create_file(&task, path, &bytes);
        let fd = open(&task, path);
        let base = map_file(&task, fd, bytes.len(), ProtFlags::PROT_READ);
        let code = UserPtrMut::from_usize(base.as_usize() + PAGE_SIZE);
        let gap = base.as_usize() + 2 * HOST_PAGE_SIZE;
        task.sys_mprotect(code, PAGE_SIZE, ProtFlags::PROT_READ_EXEC)
            .unwrap();
        let removed_len = 2 * HOST_PAGE_SIZE;
        if fixed {
            let replacement = task
                .sys_mmap(
                    code.as_usize(),
                    removed_len,
                    ProtFlags::PROT_READ_WRITE,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                    -1,
                    0,
                )
                .unwrap();
            assert!(
                replacement
                    .to_owned_slice::<TestPlatform>(removed_len)
                    .unwrap()
                    .iter()
                    .all(|b| *b == 0)
            );
        } else {
            task.sys_munmap(code, removed_len).unwrap();
            assert!(
                !task
                    .global
                    .mm
                    .mappings()
                    .iter()
                    .any(|(r, _)| overlaps(r, &(code.as_usize()..gap + PAGE_SIZE)))
            );
        }
        if HOST_PAGE_SIZE > PAGE_SIZE {
            let tail = UserPtrMut::<u8>::from_usize(gap + PAGE_SIZE);
            assert!(
                tail.to_owned_slice::<TestPlatform>(HOST_PAGE_SIZE - PAGE_SIZE)
                    .unwrap()
                    .iter()
                    .all(|b| *b == 0x5a)
            );
        }
        task.sys_close(fd).unwrap();
        task.sys_munmap(base, bytes.len()).unwrap();
    }
}

#[test]
fn retired_mapping_restore_failure_is_fatal() {
    extern crate std;
    let task = init_platform();
    let ptr = task.allocate_chunk(HOST_PAGE_SIZE, &[], None).unwrap();
    let previous = task
        .displace_island_mapping(
            ptr.as_usize(),
            VmFlags::VM_READ | VmFlags::VM_WRITE | VmFlags::VM_MAY_ACCESS_FLAGS,
            true,
        )
        .unwrap();
    task.sys_munmap_raw(ptr, HOST_PAGE_SIZE).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        task.retire_island_mapping(
            StagedMapping {
                range: ptr.as_usize()..ptr.as_usize() + HOST_PAGE_SIZE,
                previous: Some(previous),
                prefix_bias: None,
            },
            &(0..0),
        );
    }));
    let panic = result.expect_err("indeterminate retirement must not return");
    assert_eq!(
        panic.downcast_ref::<&str>().copied(),
        Some("failed to restore retired island mapping")
    );
}
