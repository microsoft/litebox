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

fn gapless_image() -> Vec<u8> {
    let mut bytes = image();
    bytes.truncate(2 * PAGE_SIZE);
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    // One syscall, one island above the image, no internal LOAD holes.
    bytes[PAGE_SIZE + 4..].fill(0);
    bytes
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

fn retirement_image() -> Vec<u8> {
    let mut bytes = image_with_gap(HOST_PAGE_SIZE);
    bytes[PAGE_SIZE + 4..2 * HOST_PAGE_SIZE].fill(0);
    bytes[3 * HOST_PAGE_SIZE..].fill(0);
    bytes[2 * HOST_PAGE_SIZE..3 * HOST_PAGE_SIZE].fill(0x5a);
    bytes
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
    let (fd, key) = open_image(&task, "/loader-retirement", &bytes);
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
    task.sys_close(fd).unwrap();
    // A failed earlier shared VMA must not update a later shadow permission.
    let path = "/loader-readonly";
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
        assert_ne!(state.islands.loader_reservations, []);
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
