// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use super::*;
use crate::shared_cache::{
    SHARED_CACHE_MIN_ADDRESS, SharedCacheBacking, SharedCacheCodeRegion, SharedCacheInstallError,
    SharedCacheLayout, SharedCachePage, SharedCachePager, SharedCachePiece,
};
use litebox::mm::page::{NonZeroAddress, NonZeroPageSize};
use litebox::platform::{
    RawConstPointer as _,
    page_mgmt::{AllocationOptions, MemoryRegionPermissions as Permissions},
};
use litebox_common_linux::vmem::{CreatePagesFlags, VmFlags};
use litebox_common_macos::VmProtection;
use litebox_platform_macos_userland::MacosUserland as Platform;

mod mach;

pub(crate) fn task(shim: MacosShim<Platform>) -> Task<Platform> {
    let thread = ThreadState::new(1u64 << 32, shim.global.platform);
    Task {
        global: shim.global,
        files: shim.files,
        params: TaskParams::default(),
        process: Process(Arc::new(AtomicI32::new(-1))),
        thread,
    }
}

#[test]
fn syscall_return_registers_and_carry() {
    let task = task(MacosShimBuilder::new(Platform::new()).build());
    let mut ctx = PtRegs::default();
    ctx.regs[1] = 0x1234;
    ctx.regs[16] = 999;
    ctx.pstate = 0x9000_0000;
    task.handle_syscall_request(&mut ctx);
    assert_eq!(ctx.regs[0], 78);
    assert_eq!(ctx.pstate, 0xb000_0000);
    assert_eq!(ctx.regs[1], 0x1234);

    // By default a guest is an ordinary process (PID 2) whose parent is
    // launchd (PID 1), never launchd itself.
    ctx.regs[16] = litebox_common_macos::syscall::nr::GETPID;
    task.handle_syscall_request(&mut ctx);
    assert_eq!(ctx.regs[0], 2);
    assert_eq!(ctx.pstate, 0x9000_0000);
    assert_eq!(ctx.regs[1], 0x1234);
    ctx.regs[16] = litebox_common_macos::syscall::nr::GETPPID;
    task.handle_syscall_request(&mut ctx);
    assert_eq!(ctx.regs[0], 1);
}

#[test]
fn unknown_syscall_reports_use_bounded_state() {
    let mut reported = ReportedSyscalls::default();
    // Each BSD number and Mach trap is reported once.
    assert!(reported.first_report(999));
    assert!(!reported.first_report(999));
    assert!(!reported.first_report(0xffff_ffff_0000_03e7));
    assert!(reported.first_report(0u32.wrapping_sub(48) as usize));
    assert!(!reported.first_report((-48isize).cast_unsigned()));
    assert!(reported.first_report(48), "BSD 48 is not Mach trap 48");
    // Every other selector shares one report, however many the guest tries.
    assert!(reported.first_report(1024));
    for selector in 1025..100_000u32 {
        assert!(!reported.first_report(selector as usize));
        assert!(!reported.first_report(0u32.wrapping_sub(selector) as usize));
    }
    assert_eq!(size_of::<ReportedSyscalls>(), (1024 + 128) / 8 + 8);

    // Through the dispatcher: distinct unknown selectors keep failing
    // with ENOSYS without retaining per-selector state.
    let task = task(MacosShimBuilder::new(Platform::new()).build());
    for selector in [5000usize, 5001, 0x7fff_ffff] {
        let mut ctx = PtRegs::default();
        ctx.regs[16] = selector;
        task.handle_syscall_request(&mut ctx);
        assert_eq!(ctx.regs[0], 78);
    }
    assert!(task.global.reported_syscalls.lock().other);
}

#[test]
fn platform_syscall_sets_and_gets_tsd_base_like_xnu() {
    use litebox::platform::{ArchSpecificProvider as _, ArchSpecificRegister};
    use litebox_common_macos::syscall::PLATFORM_SYSCALL_SELECTOR;

    let task = task(MacosShimBuilder::new(Platform::new()).build());
    let platform = task.global.platform;
    let original = platform
        .get_arch_specific_register(&ArchSpecificRegister::TpidrroEl0)
        .unwrap();
    let _restore = litebox::utils::defer(|| {
        platform
            .set_arch_specific_register(&ArchSpecificRegister::TpidrroEl0, original)
            .unwrap();
    });
    let tsd_base = Platform::TASK_ADDR_MIN + 0x1230;
    let mut ctx = PtRegs::default();
    // Upper x16 and x3 bits are ignored, as XNU reads them as 32-bit values.
    ctx.regs[16] = 0xdead_0000_0000_0000 | PLATFORM_SYSCALL_SELECTOR as usize;
    ctx.regs[0] = tsd_base;
    ctx.regs[3] = 0xffff_ffff_0000_0002;
    ctx.pstate = 0x2000_0000; // carry set
    task.handle_syscall_request(&mut ctx);
    assert_eq!(ctx.regs[0], tsd_base, "set leaves x0 unchanged");
    assert_eq!(ctx.pstate, 0x2000_0000, "no BSD carry semantics");
    assert_eq!(
        platform
            .get_arch_specific_register(&ArchSpecificRegister::TpidrroEl0)
            .unwrap(),
        tsd_base
    );

    ctx.regs[0] = 0;
    ctx.regs[3] = 3;
    ctx.pstate = 0;
    task.handle_syscall_request(&mut ctx);
    assert_eq!(ctx.regs[0], tsd_base);
    assert_eq!(ctx.pstate, 0);

    // Unknown and removed cache-flush codes have no effect.
    for code in [0, 1, 4] {
        ctx.regs[0] = 0x55;
        ctx.regs[3] = code;
        task.handle_syscall_request(&mut ctx);
        assert_eq!(ctx.regs[0], 0x55);
        assert_eq!(ctx.pstate, 0);
    }

    // machine_thread_set_tsd_base clears addresses beyond the task's map.
    ctx.regs[0] = Platform::TASK_ADDR_MAX + 1;
    ctx.regs[3] = 2;
    task.handle_syscall_request(&mut ctx);
    assert_eq!(ctx.regs[0], Platform::TASK_ADDR_MAX + 1);
    assert_eq!(
        platform
            .get_arch_specific_register(&ArchSpecificRegister::TpidrroEl0)
            .unwrap(),
        0
    );
    assert_eq!(task.process.exit_status(), None);
}

pub(crate) fn loaded_program(task: Task<Platform>) -> LoadedProgram<Platform> {
    let process = task.process.clone();
    LoadedProgram {
        entrypoints: MacosShimEntrypoints {
            task,
            _not_send: core::marker::PhantomData,
        },
        process,
        initial_ctx: PtRegs::default(),
    }
}

const SVC: u32 = 0xd400_1001;
const NOP: u32 = 0xd503_201f;
const RET: u32 = 0xd65f_03c0;

fn words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn read_guest(address: usize, length: usize) -> Option<Vec<u8>> {
    litebox_common_macos::user_pointers::UserPtr::<u8>::from_usize(address)
        .to_owned_slice::<Platform>(length)
        .map(<[u8]>::into_vec)
}

pub(crate) fn guest_flags(task: &Task<Platform>, address: usize) -> VmFlags {
    task.global
        .mm
        .mappings()
        .into_iter()
        .find_map(|(range, flags)| range.contains(&address).then_some(flags))
        .unwrap()
}

#[test]
fn shared_cache_installation_rewrites_maps_and_registers_pieces() {
    let program = loaded_program(task(MacosShimBuilder::new(Platform::new()).build()));
    // Above the host's malloc reservation that covers [64, 448) GiB.
    let range = 0x70_0000_0000..0x70_0000_0000 + 6 * PAGE_SIZE;
    assert_eq!(
        program.reserve_shared_cache(PAGE_SIZE..2 * PAGE_SIZE),
        Err(SharedCacheInstallError::InvalidCacheRange)
    );
    program.reserve_shared_cache(range.clone()).unwrap();
    assert_eq!(
        program.reserve_shared_cache(range.clone()),
        Err(SharedCacheInstallError::AlreadyInstalled)
    );
    let base = range.start;
    let page = |index: usize| base + index * PAGE_SIZE..base + (index + 1) * PAGE_SIZE;
    let pieces = test_cache_pieces(base);
    let instructions = 0..PAGE_SIZE;
    let code_regions = [SharedCacheCodeRegion {
        piece: 0,
        instruction_ranges: core::slice::from_ref(&instructions),
    }];
    // The nearest island candidate (inside the read-only Paged piece) is
    // used; the other (inside the Reserved piece) is not.
    let islands = [page(2), page(5)];
    let pager = test_cache_pager(base);
    let layout = |pieces, code_regions, gate_islands| SharedCacheLayout {
        range: range.clone(),
        pieces,
        code_regions,
        gate_islands,
        pager: Some(pager.clone()),
    };
    let copied_island = [page(3)];
    let code_island = [page(0)];
    let rejected = [
        // Executable code without a code region would run unrewritten.
        layout(&pieces, &[], &islands),
        // Islands may not replace copied bytes or code.
        layout(&pieces, &code_regions, &copied_island),
        layout(&pieces, &code_regions, &code_island),
        // Pieces must tile the reservation.
        layout(&pieces[..3], &code_regions, &islands),
    ];
    for (layout, expected) in rejected.iter().zip([
        SharedCacheInstallError::InvalidRegion,
        SharedCacheInstallError::InvalidGateIsland,
        SharedCacheInstallError::InvalidGateIsland,
        SharedCacheInstallError::InvalidCacheRange,
    ]) {
        assert_eq!(program.install_shared_cache(layout), Err(expected));
    }
    // Only rewritten file views may execute: Paged and copied pieces never
    // may, and a view must name a page-aligned cache address.
    let code_bytes = words(&[NOP, RET]);
    for backing in [
        SharedCacheBacking::Paged,
        SharedCacheBacking::Copy(&code_bytes),
        SharedCacheBacking::FileView(0x1_8000_0004),
    ] {
        let executable = [SharedCachePiece {
            range: range.clone(),
            backing,
            protection: RX,
            max_protection: RX,
        }];
        assert_eq!(
            program.install_shared_cache(&SharedCacheLayout {
                range: range.clone(),
                pieces: &executable,
                code_regions: &code_regions,
                gate_islands: &[],
                pager: Some(pager.clone()),
            }),
            Err(SharedCacheInstallError::InvalidCacheRange)
        );
    }

    program
        .install_shared_cache(&layout(&pieces, &code_regions, &islands))
        .unwrap();
    assert_eq!(
        program.entrypoints.task.executable_ranges(&range),
        [page(0), page(2)]
    );
    let task = &program.entrypoints.task;
    assert_eq!(task.global.shared_cache_base.load(Ordering::Acquire), base);
    assert!(guest_flags(task, base).contains(VmFlags::VM_EXEC));
    assert!(guest_flags(task, page(2).start).contains(VmFlags::VM_EXEC));
    assert_eq!(read_guest(page(1).start, 1), None, "not supplied yet");
    for protection in [RX, VmProtection::READ | VmProtection::WRITE] {
        assert_eq!(
            task.sys_mprotect(page(1).start, PAGE_SIZE, protection),
            Err(litebox_common_macos::errno::Errno::EACCES),
        );
    }
    assert!(task.page_in_shared_cache(page(1).start + 8));
    assert_eq!(read_guest(page(1).start, 2).unwrap(), [0x5a, 0x5a]);
    assert!(!guest_flags(task, page(1).start).contains(VmFlags::VM_EXEC));
    assert!(!guest_flags(task, page(1).start).contains(VmFlags::VM_WRITE));
    assert_eq!(
        read_guest(page(3).start, 9).unwrap(),
        [0x11; 8].iter().copied().chain([0]).collect::<Vec<_>>()
    );
    assert_eq!(
        read_guest(page(5).start, 1),
        None,
        "unused islands stay reserved"
    );

    // Protections follow each piece's maximum, like XNU map entries.
    let rw = VmProtection::READ | VmProtection::WRITE;
    assert_eq!(
        task.sys_mprotect(page(1).start, PAGE_SIZE, VmProtection::READ),
        Ok(())
    );
    for (page, protection) in [(page(0), rw), (page(2), rw)] {
        assert_eq!(
            task.sys_mprotect(page.start, PAGE_SIZE, protection),
            Err(litebox_common_macos::errno::Errno::EACCES),
            "{page:#x?} {protection:?}"
        );
    }
    assert_eq!(task.sys_mprotect(page(3).start, PAGE_SIZE, rw), Ok(()));
    assert!(guest_flags(task, page(3).start).contains(VmFlags::VM_WRITE));
    // A page awaiting the pager has its map entry's protections: changes
    // are recorded without mapping it (dyld makes whole DATA_CONST mappings
    // writable this way), and never allow execution.
    assert_eq!(
        task.sys_mprotect(page(4).start, PAGE_SIZE, RX),
        Err(litebox_common_macos::errno::Errno::EACCES)
    );
    assert_eq!(task.sys_mprotect(page(4).start, PAGE_SIZE, rw), Ok(()));
    assert_eq!(read_guest(page(4).start, 1), None, "not supplied yet");
    assert!(
        task.global
            .shared_cache
            .lock()
            .as_ref()
            .unwrap()
            .mapping_at(page(4).start)
            .is_some_and(|mapping| mapping.paged)
    );

    assert!(!task.page_in_shared_cache(page(5).start));
    assert!(!task.page_in_shared_cache(page(3).start));
    assert!(!task.page_in_shared_cache(page(1).start));
    assert!(task.page_in_shared_cache(page(4).start + 8));
    assert_eq!(read_guest(page(4).start, 2).unwrap(), [0x77, 0x77]);
    assert!(guest_flags(task, page(4).start).contains(VmFlags::VM_WRITE));
    assert!(!task.page_in_shared_cache(page(4).start), "supplied once");
    assert_eq!(
        program.install_shared_cache(&layout(&pieces, &code_regions, &islands)),
        Err(SharedCacheInstallError::AlreadyInstalled)
    );
}

const RX: VmProtection = VmProtection::READ.union(VmProtection::EXECUTE);
const RW: VmProtection = VmProtection::READ.union(VmProtection::WRITE);

fn install_test_cache(base: usize) -> LoadedProgram<Platform> {
    install_test_cache_for(task(MacosShimBuilder::new(Platform::new()).build()), base)
}

fn test_cache_pieces(base: usize) -> [SharedCachePiece<'static>; 5] {
    let page = |index: usize| base + index * PAGE_SIZE..base + (index + 1) * PAGE_SIZE;
    [
        SharedCachePiece {
            range: page(0),
            backing: SharedCacheBacking::FileView(cache_code_page().0),
            protection: RX,
            max_protection: RX,
        },
        SharedCachePiece {
            range: base + PAGE_SIZE..base + 3 * PAGE_SIZE,
            backing: SharedCacheBacking::Paged,
            protection: VmProtection::READ,
            max_protection: VmProtection::READ,
        },
        SharedCachePiece {
            range: page(3),
            backing: SharedCacheBacking::Copy(&[0x11; 8]),
            protection: VmProtection::READ,
            max_protection: RW,
        },
        SharedCachePiece {
            range: page(4),
            backing: SharedCacheBacking::Paged,
            protection: VmProtection::READ,
            max_protection: RW,
        },
        SharedCachePiece {
            range: page(5),
            backing: SharedCacheBacking::Reserved,
            protection: VmProtection::empty(),
            max_protection: VmProtection::empty(),
        },
    ]
}

fn test_cache_pager(base: usize) -> SharedCachePager {
    Arc::new(move |address| {
        let (fill, max_protection) = match (address - base) / PAGE_SIZE {
            1 | 2 => (0x5a, VmProtection::READ),
            4 => (0x77, RW),
            _ => return None,
        };
        Some(SharedCachePage {
            bytes: vec![fill; PAGE_SIZE],
            max_protection,
        })
    })
}

/// Install [`test_cache_pieces`] for `task`, with page 2 as the used gate island.
pub(crate) fn install_test_cache_for(task: Task<Platform>, base: usize) -> LoadedProgram<Platform> {
    let program = loaded_program(task);
    let range = base..base + 6 * PAGE_SIZE;
    program.reserve_shared_cache(range.clone()).unwrap();
    let page = |index: usize| base + index * PAGE_SIZE..base + (index + 1) * PAGE_SIZE;
    let pieces = test_cache_pieces(base);
    let instructions = 0..PAGE_SIZE;
    let code_regions = [SharedCacheCodeRegion {
        piece: 0,
        instruction_ranges: core::slice::from_ref(&instructions),
    }];
    let islands = [page(2)];
    program
        .install_shared_cache(&SharedCacheLayout {
            range,
            pieces: &pieces,
            code_regions: &code_regions,
            gate_islands: &islands,
            pager: Some(test_cache_pager(base)),
        })
        .unwrap();
    program
}

fn is_site(word: u32) -> bool {
    use litebox_trampoline::aarch64::{SVC_OPCODE_BITS, SVC_OPCODE_MASK};
    word & SVC_OPCODE_MASK == SVC_OPCODE_BITS || word & 0xffff_ffe0 == 0xd53b_d060
}

/// The unslid address and bytes of a libsystem_kernel `__text` page with
/// rewrite sites, none at offset 0.
fn cache_code_page() -> (u64, Vec<u8>) {
    use litebox_common_macos::shared_cache::HostSharedCache as _;
    let cache = Platform::new().host_shared_cache().unwrap().cache;
    let index = cache
        .image_index_by_path("/usr/lib/system/libsystem_kernel.dylib")
        .unwrap();
    let image = cache.parse_image(cache.images()[index].address).unwrap();
    let text = image
        .segment("__TEXT")
        .and_then(|segment| {
            segment
                .sections
                .iter()
                .find(|section| section.name == "__text")
        })
        .unwrap()
        .address_range
        .clone();
    let page_size = PAGE_SIZE as u64;
    (text.start.next_multiple_of(page_size)..text.end)
        .step_by(PAGE_SIZE)
        .take_while(|page| page + page_size <= text.end)
        .map(|page| (page, cache.read_at_address(page, PAGE_SIZE).unwrap()))
        .find(|(_, bytes)| {
            let words = bytes.as_chunks::<4>().0;
            !is_site(u32::from_le_bytes(words[0]))
                && words.iter().any(|word| is_site(u32::from_le_bytes(*word)))
        })
        .unwrap()
}

#[test]
fn shared_cache_file_views_are_private_views_of_the_cache_files() {
    use litebox_common_macos::{errno::Errno, shared_cache::HostSharedCache as _};

    let host = Platform::new().host_shared_cache().unwrap();
    let header = host.cache.files()[0].mappings()[0].address;
    let header_bytes = host.cache.read_at_address(header, PAGE_SIZE).unwrap();
    let (code_page, file_code) = cache_code_page();
    let base = 0x7a_0000_0000;
    let program = loaded_program(task(MacosShimBuilder::new(Platform::new()).build()));
    let range = base..base + 4 * PAGE_SIZE;
    program.reserve_shared_cache(range.clone()).unwrap();
    let page = |index: usize| base + index * PAGE_SIZE..base + (index + 1) * PAGE_SIZE;
    let view = |index, address, protection, max_protection| SharedCachePiece {
        range: page(index),
        backing: SharedCacheBacking::FileView(address),
        protection,
        max_protection,
    };
    let pieces = [
        view(0, header, VmProtection::READ, VmProtection::READ),
        view(1, header, VmProtection::READ, RW),
        view(2, code_page, RX, RX),
        SharedCachePiece {
            range: page(3),
            backing: SharedCacheBacking::Reserved,
            protection: VmProtection::empty(),
            max_protection: VmProtection::empty(),
        },
    ];
    // Code after the first word, so the rewritten batch starts inside the
    // view.
    let instructions = 4..PAGE_SIZE;
    program
        .install_shared_cache(&SharedCacheLayout {
            range: range.clone(),
            pieces: &pieces,
            code_regions: &[SharedCacheCodeRegion {
                piece: 2,
                instruction_ranges: core::slice::from_ref(&instructions),
            }],
            gate_islands: &[page(3)],
            pager: None,
        })
        .unwrap();
    let task = &program.entrypoints.task;
    let code_and_island = page(2).start..page(3).end;
    assert_eq!(
        task.executable_ranges(&range),
        core::slice::from_ref(&code_and_island)
    );
    for index in [0, 1] {
        assert_eq!(
            read_guest(page(index).start, PAGE_SIZE).unwrap(),
            header_bytes
        );
        assert!(!guest_flags(task, page(index).start).contains(VmFlags::VM_WRITE));
    }
    for (page, protection) in [(page(0), RW), (page(0), RX), (page(1), RX), (page(2), RW)] {
        assert_eq!(
            task.sys_mprotect(page.start, PAGE_SIZE, protection),
            Err(Errno::EACCES),
            "{page:#x?} {protection:?}"
        );
    }
    assert_eq!(task.sys_mprotect(page(1).start, PAGE_SIZE, RW), Ok(()));
    let marker = [0xa5u8; 16];
    assert!(
        litebox_common_macos::user_pointers::UserPtrMut::<u8>::from_usize(page(1).start)
            .copy_from_slice::<Platform>(0, &marker)
            .is_some()
    );
    assert_eq!(read_guest(page(1).start, 16).unwrap(), marker);
    assert_eq!(read_guest(page(0).start, PAGE_SIZE).unwrap(), header_bytes);
    let code = read_guest(page(2).start, PAGE_SIZE).unwrap();
    for (index, (word, original)) in code
        .as_chunks::<4>()
        .0
        .iter()
        .zip(file_code.as_chunks::<4>().0)
        .enumerate()
    {
        if is_site(u32::from_le_bytes(*original)) {
            let address = (page(2).start + 4 * index) as u64;
            let target = litebox_trampoline::aarch64::decode_branch_target(
                u32::from_le_bytes(*word),
                address,
            )
            .expect("site must branch to its gate");
            assert!(page(3).contains(&usize::try_from(target).unwrap()));
        } else {
            assert_eq!(word, original, "word {index}");
        }
    }
    assert_eq!(
        task.sys_mprotect(page(2).start, PAGE_SIZE, VmProtection::READ),
        Ok(())
    );
    assert_eq!(task.sys_mprotect(page(2).start, PAGE_SIZE, RX), Ok(()));
    assert!(guest_flags(task, page(2).start).contains(VmFlags::VM_EXEC));
    assert_eq!(read_guest(page(2).start, PAGE_SIZE).unwrap(), code);
}

#[test]
fn shared_cache_code_views_keep_their_protection_and_islands_split_views() {
    use litebox_common_macos::shared_cache::HostSharedCache as _;

    let host = Platform::new().host_shared_cache().unwrap();
    let header = host.cache.files()[0].mappings()[0].address;
    let (code_page, _) = cache_code_page();
    let base = 0x7d_0000_0000;
    let program = loaded_program(task(MacosShimBuilder::new(Platform::new()).build()));
    let range = base..base + 4 * PAGE_SIZE;
    program.reserve_shared_cache(range.clone()).unwrap();
    let page = |index: usize| base + index * PAGE_SIZE..base + (index + 1) * PAGE_SIZE;
    let pieces = [
        SharedCachePiece {
            range: page(0),
            backing: SharedCacheBacking::FileView(code_page),
            protection: VmProtection::READ,
            max_protection: RX,
        },
        SharedCachePiece {
            range: page(1).start..page(3).end,
            backing: SharedCacheBacking::FileView(header),
            protection: VmProtection::READ,
            max_protection: VmProtection::READ,
        },
    ];
    let instructions = 0..PAGE_SIZE;
    program
        .install_shared_cache(&SharedCacheLayout {
            range: range.clone(),
            pieces: &pieces,
            code_regions: &[SharedCacheCodeRegion {
                piece: 0,
                instruction_ranges: core::slice::from_ref(&instructions),
            }],
            gate_islands: &[page(2)],
            pager: None,
        })
        .unwrap();
    let task = &program.entrypoints.task;
    assert!(!guest_flags(task, page(0).start).contains(VmFlags::VM_EXEC));
    assert_eq!(task.executable_ranges(&range), [page(2)]);
    assert_eq!(task.sys_mprotect(page(0).start, PAGE_SIZE, RX), Ok(()));
    assert_eq!(task.executable_ranges(&range), [page(0), page(2)]);
    let records = task
        .global
        .shared_cache
        .lock()
        .as_ref()
        .unwrap()
        .mappings
        .iter()
        .map(|mapping| {
            (
                mapping.range.clone(),
                mapping.protection,
                mapping.max_protection,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        records,
        [
            (page(0), RX, RX),
            (page(1), VmProtection::READ, VmProtection::READ),
            (page(2), RX, RX),
            (page(3), VmProtection::READ, VmProtection::READ),
        ]
    );
}

#[test]
fn failed_shared_cache_views_fail_installation() {
    use litebox_common_macos::shared_cache::HostSharedCache as _;

    let host = Platform::new().host_shared_cache().unwrap();
    let outside = host.cache.header().shared_region_start - PAGE_SIZE as u64;
    let base = 0x7b_0000_0000;
    let program = loaded_program(task(MacosShimBuilder::new(Platform::new()).build()));
    let range = base..base + PAGE_SIZE;
    program.reserve_shared_cache(range.clone()).unwrap();
    assert_eq!(
        program.install_shared_cache(&SharedCacheLayout {
            range: range.clone(),
            pieces: &[SharedCachePiece {
                range,
                backing: SharedCacheBacking::FileView(outside),
                protection: VmProtection::READ,
                max_protection: VmProtection::READ,
            }],
            code_regions: &[],
            gate_islands: &[],
            pager: None,
        }),
        Err(SharedCacheInstallError::Map)
    );
    assert_eq!(read_guest(base, 1), None);

    let base = 0x7c_0000_0000;
    let program = loaded_program(task(MacosShimBuilder::new(Platform::new()).build()));
    let range = base..base + (160 << 20);
    program.reserve_shared_cache(range.clone()).unwrap();
    let instructions = 0..PAGE_SIZE;
    let far_island = range.end - PAGE_SIZE..range.end;
    assert_eq!(
        program.install_shared_cache(&SharedCacheLayout {
            range: range.clone(),
            pieces: &[
                SharedCachePiece {
                    range: base..base + PAGE_SIZE,
                    backing: SharedCacheBacking::FileView(cache_code_page().0),
                    protection: RX,
                    max_protection: RX,
                },
                SharedCachePiece {
                    range: base + PAGE_SIZE..range.end,
                    backing: SharedCacheBacking::Reserved,
                    protection: VmProtection::empty(),
                    max_protection: VmProtection::empty(),
                },
            ],
            code_regions: &[SharedCacheCodeRegion {
                piece: 0,
                instruction_ranges: core::slice::from_ref(&instructions),
            }],
            gate_islands: core::slice::from_ref(&far_island),
            pager: None,
        }),
        Err(SharedCacheInstallError::UnreachableGates)
    );
    assert_eq!(
        program.entrypoints.task.executable_ranges(&range),
        Vec::<core::ops::Range<usize>>::new()
    );
}

#[test]
fn shared_cache_page_in_uses_the_recorded_protection() {
    let base = 0x74_0000_0000;
    let program = install_test_cache(base);
    let task = &program.entrypoints.task;
    let page = base + 4 * PAGE_SIZE..base + 5 * PAGE_SIZE;
    // A whole-range vm_protect over mixed pieces: the copied page changes
    // now, the unsupplied page when it is supplied.
    assert_eq!(
        task.sys_mach_vm_protect(
            litebox_common_macos::syscall::MachPortName(
                u32::try_from(task.sys_task_self()).unwrap()
            ),
            base + 3 * PAGE_SIZE,
            2 * PAGE_SIZE,
            false,
            litebox_common_macos::syscall::MachVmProtection::new(RW, true),
        ),
        KernReturn::SUCCESS
    );
    assert!(guest_flags(task, base + 3 * PAGE_SIZE).contains(VmFlags::VM_WRITE));
    assert_eq!(read_guest(page.start, 1), None);
    assert_eq!(
        task.sys_mprotect(page.start, PAGE_SIZE, VmProtection::empty()),
        Ok(())
    );
    assert!(!task.page_in_shared_cache(page.start));
    assert_eq!(read_guest(page.start, 1), None);
    assert_eq!(
        task.sys_mprotect(page.start, PAGE_SIZE, VmProtection::READ),
        Ok(())
    );
    assert!(task.page_in_shared_cache(page.start));
    assert_eq!(read_guest(page.start, 1).unwrap(), [0x77]);
    assert!(!guest_flags(task, page.start).contains(VmFlags::VM_WRITE));
}

#[test]
fn shared_cache_pages_with_an_invalid_maximum_are_refused() {
    let base = 0x78_0000_0000;
    let program = loaded_program(task(MacosShimBuilder::new(Platform::new()).build()));
    let range = base..base + 2 * PAGE_SIZE;
    program.reserve_shared_cache(range.clone()).unwrap();
    let pieces = [SharedCachePiece {
        range: range.clone(),
        backing: SharedCacheBacking::Paged,
        protection: VmProtection::READ,
        max_protection: VmProtection::READ,
    }];
    program
        .install_shared_cache(&SharedCacheLayout {
            range,
            pieces: &pieces,
            code_regions: &[],
            gate_islands: &[],
            pager: Some(Arc::new(move |address| {
                Some(SharedCachePage {
                    bytes: vec![0x5a; PAGE_SIZE],
                    max_protection: if address == base {
                        RX
                    } else {
                        VmProtection::empty()
                    },
                })
            })),
        })
        .unwrap();
    let task = &program.entrypoints.task;
    for page in [base, base + PAGE_SIZE] {
        assert!(!task.page_in_shared_cache(page));
        assert!(
            task.global
                .shared_cache
                .lock()
                .as_ref()
                .unwrap()
                .mapping_at(page)
                .is_some_and(|mapping| mapping.paged)
        );
        assert_eq!(read_guest(page, 1), None);
    }
}

#[test]
fn mprotect_across_the_shared_cache_boundary_splits_at_the_instance() {
    use litebox_common_macos::errno::Errno;

    let base = 0x73_0000_0000;
    let program = loaded_program(task(MacosShimBuilder::new(Platform::new()).build()));
    let task = &program.entrypoints.task;
    let range = base..base + 2 * PAGE_SIZE;
    program.reserve_shared_cache(range.clone()).unwrap();
    let data = [0x22u8; 4];
    let pieces = [
        SharedCachePiece {
            range: base..base + PAGE_SIZE,
            backing: SharedCacheBacking::Copy(&data),
            protection: VmProtection::READ,
            max_protection: RW,
        },
        SharedCachePiece {
            range: base + PAGE_SIZE..range.end,
            backing: SharedCacheBacking::Copy(&data),
            protection: VmProtection::READ,
            max_protection: VmProtection::READ,
        },
    ];
    program
        .install_shared_cache(&SharedCacheLayout {
            range: range.clone(),
            pieces: &pieces,
            code_regions: &[],
            gate_islands: &[],
            pager: None,
        })
        .unwrap();
    let below = base - PAGE_SIZE;
    assert_eq!(
        task.map_anonymous(
            below,
            PAGE_SIZE,
            crate::syscalls::mm::AnonymousPlacement::Fixed { replace: false },
            VmProtection::READ,
            VmProtection::all(),
        )
        .unwrap(),
        below
    );
    assert_eq!(task.sys_mprotect(below, 2 * PAGE_SIZE, RW), Ok(()));
    assert!(guest_flags(task, below).contains(VmFlags::VM_WRITE));
    assert!(guest_flags(task, base).contains(VmFlags::VM_WRITE));
    let cache_protection = |address: usize| {
        task.global
            .shared_cache
            .lock()
            .as_ref()
            .unwrap()
            .mappings
            .iter()
            .find(|mapping| mapping.range.contains(&address))
            .unwrap()
            .protection
    };
    assert_eq!(cache_protection(base), RW);
    assert_eq!(
        task.sys_mprotect(
            below,
            3 * PAGE_SIZE,
            VmProtection::READ.union(VmProtection::WRITE)
        ),
        Err(Errno::EACCES)
    );
    assert_eq!(
        task.sys_mprotect(below, 3 * PAGE_SIZE, VmProtection::READ),
        Ok(())
    );
    assert!(!guest_flags(task, below).contains(VmFlags::VM_WRITE));
    assert_eq!(cache_protection(base), VmProtection::READ);
    assert_eq!(
        task.sys_mprotect(base + PAGE_SIZE, 2 * PAGE_SIZE, VmProtection::READ),
        Err(Errno::ENOMEM)
    );
    assert_eq!(task.sys_mprotect(below, PAGE_SIZE, RW), Ok(()));
    assert_eq!(
        task.sys_mprotect(below, 4 * PAGE_SIZE, VmProtection::READ),
        Err(Errno::ENOMEM)
    );
    assert!(guest_flags(task, below).contains(VmFlags::VM_WRITE));
    assert_eq!(cache_protection(base), VmProtection::READ);
    assert_eq!(
        task.sys_mprotect(below, 2 * PAGE_SIZE, RX),
        Err(Errno::EACCES)
    );
    assert!(!guest_flags(task, below).contains(VmFlags::VM_EXEC));
    task.sys_munmap(below, PAGE_SIZE).unwrap();
}

/// Gate bytes one site needs, measured with an empty island.
fn gate_bytes_per_site(
    task: &Task<Platform>,
    address: usize,
    island: &core::ops::Range<usize>,
) -> usize {
    let mut code = words(&[SVC]);
    let mut gates = vec![Vec::new()];
    rewrite_code(
        task,
        &mut code,
        address,
        core::slice::from_ref(&(0..4)),
        core::slice::from_ref(island),
        &mut gates,
    )
    .unwrap();
    gates[0].len()
}

fn rewrite_code(
    task: &Task<Platform>,
    code: &mut [u8],
    address: usize,
    instruction_ranges: &[core::ops::Range<usize>],
    islands: &[core::ops::Range<usize>],
    gates: &mut [Vec<u8>],
) -> Result<(), SharedCacheInstallError> {
    let patches = task.rewrite_shared_cache_code(
        |bytes| code.get(bytes).map(<[u8]>::to_vec),
        code.len(),
        address,
        instruction_ranges,
        islands,
        gates,
    )?;
    for (offset, word) in patches {
        code[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }
    Ok(())
}

/// The index of the island each word of `code` at `address` branches into;
/// panics if a word does not branch into one.
fn sites_branch_into(
    code: &[u8],
    address: usize,
    islands: &[core::ops::Range<usize>],
) -> Vec<usize> {
    use litebox_trampoline::aarch64::decode_branch_target;
    code.as_chunks::<4>()
        .0
        .iter()
        .enumerate()
        .map(|(index, word)| {
            let target =
                decode_branch_target(u32::from_le_bytes(*word), (address + 4 * index) as u64)
                    .expect("every site branches to its gate");
            islands
                .iter()
                .position(|island| island.contains(&usize::try_from(target).unwrap()))
                .expect("gates lie in an island")
        })
        .collect()
}

#[test]
fn shared_cache_rewrite_refuses_svc_with_another_immediate() {
    let task = task(MacosShimBuilder::new(Platform::new()).build());
    let address = SHARED_CACHE_MIN_ADDRESS + (8 << 20);
    let island = address - PAGE_SIZE..address;
    // `svc #0x81`
    let mut code = words(&[0xd400_1021]);
    let original = code.clone();
    let whole = 0..code.len();
    let mut gates = vec![Vec::new()];
    assert!(matches!(
        rewrite_code(
            &task,
            &mut code,
            address,
            core::slice::from_ref(&whole),
            core::slice::from_ref(&island),
            &mut gates,
        ),
        Err(SharedCacheInstallError::Rewrite)
    ));
    assert_eq!(code, original);
    assert_eq!(gates, [Vec::<u8>::new()]);
}

#[test]
fn shared_cache_rewrite_splits_batches_across_island_pages() {
    let task = task(MacosShimBuilder::new(Platform::new()).build());
    let address = SHARED_CACHE_MIN_ADDRESS + (8 << 20);
    let islands: Vec<_> = (1..=4)
        .map(|index| address - index * PAGE_SIZE..address - (index - 1) * PAGE_SIZE)
        .collect();
    let per_site = gate_bytes_per_site(&task, address, &islands[0]);
    // More sites than one island page holds, all in one 64 KiB batch span.
    let sites = (PAGE_SIZE / per_site * 3 / 2).min(PAGE_SIZE / 4);
    assert!(
        sites * per_site > PAGE_SIZE,
        "the test needs a batch to split"
    );
    let mut code = words(&vec![SVC; sites]);
    let whole = 0..code.len();
    let mut gates = vec![Vec::new(); islands.len()];
    rewrite_code(
        &task,
        &mut code,
        address,
        core::slice::from_ref(&whole),
        &islands,
        &mut gates,
    )
    .unwrap();
    let used = sites_branch_into(&code, address, &islands);
    let mut distinct = used.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert!(distinct.len() >= 2, "a split batch uses several islands");
    for (island, gates) in islands.iter().zip(&gates) {
        assert!(gates.len() <= island.len());
    }
}

#[test]
fn shared_cache_rewrite_skips_full_islands() {
    let task = task(MacosShimBuilder::new(Platform::new()).build());
    let address = SHARED_CACHE_MIN_ADDRESS + (8 << 20);
    let near = address - PAGE_SIZE..address;
    let far = address - 3 * PAGE_SIZE..address - 2 * PAGE_SIZE;
    let islands = [near, far];
    let mut code = words(&[SVC, NOP, SVC]);
    let whole = 0..code.len();
    let mut gates = vec![vec![0; PAGE_SIZE], Vec::new()];
    rewrite_code(
        &task,
        &mut code,
        address,
        core::slice::from_ref(&whole),
        &islands,
        &mut gates,
    )
    .unwrap();
    assert_eq!(gates[0].len(), PAGE_SIZE, "the full island is untouched");
    assert_ne!(gates[1], Vec::<u8>::new());
    assert_eq!(code[4..8], NOP.to_le_bytes());
    for site in [0, 8] {
        assert_eq!(
            sites_branch_into(&code[site..site + 4], address + site, &islands),
            [1]
        );
    }
}

#[test]
fn sysctl_mirrors_only_allowlisted_host_nodes_read_only() {
    use litebox_common_macos::{errno::Errno, user_pointers::UserPtr};

    use litebox_common_macos::user_pointers::UserPtrMut;

    let shim = MacosShimBuilder::new(Platform::new())
        .host_sysctls(vec![
            HostSysctl {
                name: "hw.target",
                mib: vec![6, 26],
                value: Ok(b"J274AP\0".to_vec()),
            },
            HostSysctl {
                name: "security.mac.img4.ignition_blob",
                mib: vec![103, 101, 118, 100],
                value: Err(Errno::EPERM),
            },
        ])
        .unwrap()
        .build();
    let task = task(shim);
    let sysctl = |mib: &[i32], old: &mut [u8], old_length: Option<&mut usize>, new: &[u8]| {
        task.sys_sysctl(
            UserPtr::from_ptr(mib.as_ptr()),
            u32::try_from(mib.len()).unwrap(),
            UserPtrMut::from_usize(if old.is_empty() {
                0
            } else {
                old.as_mut_ptr() as usize
            }),
            UserPtrMut::from_usize(
                old_length.map_or(0, |length| core::ptr::from_mut(length) as usize),
            ),
            UserPtr::from_usize(if new.is_empty() {
                0
            } else {
                new.as_ptr() as usize
            }),
            new.len(),
        )
    };
    let name_to_oid = [0, 3];
    // Lookups: allowlisted names resolve to the host's MIB; others do not exist.
    let mut oid = [0u8; 48];
    let mut length = oid.len();
    assert_eq!(
        sysctl(&name_to_oid, &mut oid, Some(&mut length), b"hw.target"),
        Ok(0)
    );
    assert_eq!(length, 8);
    assert_eq!(oid[..8], [6, 0, 0, 0, 26, 0, 0, 0]);
    for (name, expected) in [
        (&b"kern.bootargs"[..], Errno::ENOENT),
        (b"", Errno::ENOENT),
        (&[b'a'; 1024], Errno::ENAMETOOLONG),
    ] {
        assert_eq!(sysctl(&name_to_oid, &mut [], None, name), Err(expected));
    }
    // Reads: size query, exact copy, short buffers, mirrored errors, no writes.
    let mut length = 0;
    assert_eq!(sysctl(&[6, 26], &mut [], Some(&mut length), b""), Ok(0));
    assert_eq!(length, 7);
    let mut value = [0u8; 7];
    assert_eq!(sysctl(&[6, 26], &mut value, Some(&mut length), b""), Ok(0));
    assert_eq!(&value, b"J274AP\0");
    // sysctl_old_user fails a short transfer before copying and without
    // advancing the output cursor, so nothing is written and 0 is reported.
    let mut short = [0xa5u8; 3];
    let mut length = short.len();
    assert_eq!(
        sysctl(&[6, 26], &mut short, Some(&mut length), b""),
        Err(Errno::ENOMEM)
    );
    assert_eq!((short, length), ([0xa5; 3], 0));
    let mut oid = [0xa5u8; 4];
    let mut length = oid.len();
    assert_eq!(
        sysctl(&name_to_oid, &mut oid, Some(&mut length), b"hw.target"),
        Err(Errno::ENOMEM)
    );
    assert_eq!((oid, length), ([0xa5; 4], 0));
    // A short buffer is never touched, so even an unmapped one is ENOMEM.
    let target_mib = [6, 26];
    let mut length = 3usize;
    assert_eq!(
        task.sys_sysctl(
            UserPtr::from_ptr(target_mib.as_ptr()),
            2,
            UserPtrMut::from_usize(0x10),
            UserPtrMut::from_usize(core::ptr::from_mut(&mut length) as usize),
            UserPtr::from_usize(0),
            0,
        ),
        Err(Errno::ENOMEM)
    );
    assert_eq!(length, 0);
    assert_eq!(
        sysctl(&[103, 101, 118, 100], &mut [], None, b""),
        Err(Errno::EPERM)
    );
    assert_eq!(sysctl(&[6, 26], &mut [], None, b"x"), Err(Errno::EPERM));
    // A new value is only a write when its length is nonzero.
    let mut value = [0u8; 7];
    let mut length = value.len();
    assert_eq!(
        task.sys_sysctl(
            UserPtr::from_ptr(target_mib.as_ptr()),
            2,
            UserPtrMut::from_usize(value.as_mut_ptr() as usize),
            UserPtrMut::from_usize(core::ptr::from_mut(&mut length) as usize),
            UserPtr::from_usize(0x10),
            0,
        ),
        Ok(0)
    );
    assert_eq!((&value, length), (b"J274AP\0", 7));
    assert_eq!(sysctl(&[1, 65], &mut [], None, b""), Err(Errno::ENOENT));
    assert_eq!(sysctl(&[1], &mut [], None, b""), Err(Errno::EINVAL));
    // Only allowlisted names can be mirrored.
    assert!(
        MacosShimBuilder::new(Platform::new())
            .host_sysctls(vec![HostSysctl {
                name: "kern.bootargs",
                mib: vec![1, 65],
                value: Ok(Vec::new()),
            }])
            .is_err()
    );
}

#[test]
fn shared_region_check_handles_sentinel_and_copyout_fault() {
    use litebox_common_macos::{errno::Errno, user_pointers::UserPtrMut};

    let task = task(MacosShimBuilder::new(Platform::new()).build());
    assert_eq!(
        task.sys_shared_region_check_np(UserPtrMut::from_usize(usize::MAX)),
        Err(Errno::EINVAL),
        "no shared region"
    );
    task.global
        .shared_cache_base
        .store(0x1800_0000, Ordering::Release);
    assert_eq!(
        task.sys_shared_region_check_np(UserPtrMut::from_usize(usize::MAX)),
        Ok(())
    );
    assert_eq!(
        task.sys_shared_region_check_np(UserPtrMut::from_usize(0x1234)),
        Err(Errno::EFAULT)
    );
}

#[test]
fn shared_region_map_and_slide_never_maps_another_cache() {
    use litebox_common_macos::{errno::Errno, syscall::nr};

    let call = |task: &Task<Platform>, args: &[usize]| {
        let mut ctx = PtRegs::default();
        ctx.regs[16] = nr::SHARED_REGION_MAP_AND_SLIDE_2_NP;
        ctx.regs[..args.len()].copy_from_slice(args);
        task.handle_syscall_request(&mut ctx);
        (ctx.regs[0], ctx.pstate & (1 << 29) != 0)
    };
    // shared_file_np { sf_fd, sf_mappings_count, sf_slide }
    let files = [3u32, 1, 0];
    let files = files.as_ptr() as usize;
    // One shared_file_mapping_slide_np.
    let mappings = [0u64; 6];
    let mappings = mappings.as_ptr() as usize;
    let task = task(MacosShimBuilder::new(Platform::new()).build());
    // Empty requests succeed; oversized counts and unreadable file arrays
    // fail before the region is examined.
    assert_eq!(call(&task, &[0, 0, 1, 0]), (0, false));
    assert_eq!(call(&task, &[1, files, 0, 0]), (0, false));
    assert_eq!(call(&task, &[257, files, 1, 0]), (Errno::EIO.raw(), true));
    assert_eq!(call(&task, &[1, files, 2049, 0]), (Errno::EIO.raw(), true));
    assert_eq!(call(&task, &[1, 0x10, 1, 0]), (Errno::EFAULT.raw(), true));
    // With an instance, the region is already mapped: KERN_FAILURE, which
    // _shared_region_map_and_slide converts to EINVAL.
    let program = install_test_cache(0x75_0000_0000);
    assert_eq!(
        call(&program.entrypoints.task, &[1, files, 1, mappings]),
        (Errno::EINVAL.raw(), true)
    );
    // The mappings array is copied in before the region is examined.
    assert_eq!(
        call(&program.entrypoints.task, &[1, files, 1, 0]),
        (Errno::EFAULT.raw(), true)
    );
}

#[test]
fn teardown_continues_after_unmap_failure_during_unwind() {
    use litebox::platform::page_mgmt::FixedAddressBehavior;
    let platform = Platform::new();
    let task = task(MacosShimBuilder::new(platform).build());
    // SAFETY: non-fixed allocation into a fresh, idle guest address space.
    let ptr = unsafe {
        task.global.mm.create_writable_pages(
            NonZeroAddress::new(Platform::TASK_ADDR_MIN),
            NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    }
    .unwrap();
    let base = ptr.as_usize();
    // SAFETY: the test owns these idle pages. Split the VMAs, then deliberately
    // remove the first page behind PageManager to inject a teardown failure.
    unsafe {
        task.global
            .mm
            .change_page_permissions(ptr, PAGE_SIZE, Permissions::READ)
            .unwrap();
        platform.release_pages(base..base + PAGE_SIZE).unwrap();
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _task = task;
        panic!("original panic");
    }));
    assert!(result.is_err());
    // Cleanup continues with the second VMA after the first unmap fails.
    let second_page = base + PAGE_SIZE..base + 2 * PAGE_SIZE;
    let probe = unsafe {
        platform
            .reserve_and_commit_pages(
                core::iter::empty,
                second_page.clone(),
                Permissions::READ,
                AllocationOptions::POPULATE,
                FixedAddressBehavior::NoReplace,
            )
            .unwrap()
    };
    let probe: core::ops::Range<usize> = probe.into();
    assert_eq!(probe.start, second_page.start);
    // SAFETY: the probe has no users and is owned by this test.
    unsafe {
        platform.release_pages(second_page).unwrap();
    }
}
