// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use super::*;
use crate::shared_cache::{
    SHARED_CACHE_MIN_ADDRESS, SharedCacheBacking, SharedCacheCodeRegion, SharedCacheInstallError,
    SharedCacheLayout, SharedCachePage, SharedCachePager, SharedCachePiece,
};
use litebox::mm::page::{NonZeroAddress, NonZeroPageSize};
use litebox::platform::{RawConstPointer as _, page_mgmt::MemoryRegionPermissions as Permissions};
use litebox_common_linux::vmem::{CreatePagesFlags, VmFlags};
use litebox_common_macos::VmProtection;
use litebox_platform_macos_userland::MacosUserland as Platform;

mod mach;

fn task(shim: MacosShim<Platform>) -> Task<Platform> {
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

    ctx.regs[16] = litebox_common_macos::syscall::nr::GETPID;
    task.handle_syscall_request(&mut ctx);
    assert_eq!(ctx.regs[0], 1);
    assert_eq!(ctx.pstate, 0x9000_0000);
    assert_eq!(ctx.regs[1], 0x1234);
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

fn loaded_program(task: Task<Platform>) -> LoadedProgram<Platform> {
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
const MRS_TPIDRRO_X3: u32 = 0xd53b_d063;
const NOP: u32 = 0xd503_201f;
const RET: u32 = 0xd65f_03c0;

fn words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// Native-page-aligned immutable host bytes, as a cache file mapping provides.
fn leaked_source(pages: usize, fill: u8) -> &'static [u8] {
    let bytes: &'static mut [u8] = Vec::leak(vec![fill; (pages + 1) * PAGE_SIZE]);
    let offset = bytes.as_ptr().align_offset(PAGE_SIZE);
    &bytes[offset..offset + pages * PAGE_SIZE]
}

fn read_guest(address: usize, length: usize) -> Option<Vec<u8>> {
    litebox_common_macos::user_pointers::UserPtr::<u8>::from_usize(address)
        .to_owned_slice::<Platform>(length)
        .map(<[u8]>::into_vec)
}

fn guest_flags(task: &Task<Platform>, address: usize) -> VmFlags {
    task.global
        .mm
        .mappings()
        .into_iter()
        .find_map(|(range, flags)| range.contains(&address).then_some(flags))
        .unwrap()
}

#[test]
fn shared_cache_installation_rewrites_maps_and_registers_pieces() {
    use litebox_trampoline::aarch64::decode_branch_target;
    const RX: VmProtection = VmProtection::READ.union(VmProtection::EXECUTE);

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
    let source = leaked_source(2, 0x5a);
    let code = words(&[NOP, SVC, MRS_TPIDRRO_X3, RET]);
    let data = [0x11u8; 8];
    let pieces = [
        SharedCachePiece {
            range: page(0),
            backing: SharedCacheBacking::Copy(&code),
            protection: RX,
            max_protection: RX,
        },
        SharedCachePiece {
            range: base + PAGE_SIZE..base + 3 * PAGE_SIZE,
            backing: SharedCacheBacking::Source(source),
            protection: VmProtection::READ,
            max_protection: VmProtection::READ,
        },
        SharedCachePiece {
            range: page(3),
            backing: SharedCacheBacking::Copy(&data),
            protection: VmProtection::READ,
            max_protection: VmProtection::READ | VmProtection::WRITE,
        },
        SharedCachePiece {
            range: page(4),
            backing: SharedCacheBacking::Paged,
            protection: VmProtection::empty(),
            max_protection: VmProtection::empty(),
        },
        SharedCachePiece {
            range: page(5),
            backing: SharedCacheBacking::Reserved,
            protection: VmProtection::empty(),
            max_protection: VmProtection::empty(),
        },
    ];
    let instructions = 0..code.len();
    let code_regions = [SharedCacheCodeRegion {
        piece: 0,
        instruction_ranges: core::slice::from_ref(&instructions),
    }];
    // The nearest island candidate (inside the Source piece) is used; the
    // other (inside the Reserved piece) is not.
    let islands = [page(2), page(5)];
    let paged_address = page(4).start;
    let pager: SharedCachePager = Arc::new(move |address| {
        (address == paged_address).then(|| SharedCachePage {
            bytes: vec![0x77; PAGE_SIZE],
            protection: VmProtection::READ,
            max_protection: VmProtection::READ | VmProtection::WRITE,
        })
    });
    let layout = |pieces, code_regions, gate_islands| SharedCacheLayout {
        range: range.clone(),
        pieces,
        code_regions,
        gate_islands,
        attribution: None,
        pager: Some(pager.clone()),
    };
    let copied_island = [page(3)];
    let rejected = [
        // Executable code without a code region would run unrewritten.
        layout(&pieces, &[], &islands),
        // Islands may not replace copied bytes.
        layout(&pieces, &code_regions, &copied_island),
        // Pieces must tile the reservation.
        layout(&pieces[..3], &code_regions, &islands),
    ];
    for (layout, expected) in rejected.iter().zip([
        SharedCacheInstallError::InvalidRegion,
        SharedCacheInstallError::InvalidGateIsland,
        SharedCacheInstallError::InvalidCacheRange,
    ]) {
        assert_eq!(program.install_shared_cache(layout), Err(expected));
    }
    let executable_source = [SharedCachePiece {
        range: range.clone(),
        backing: SharedCacheBacking::Source(leaked_source(6, 0)),
        protection: VmProtection::READ,
        max_protection: RX,
    }];
    assert_eq!(
        program.install_shared_cache(&layout(&executable_source, &[], &[])),
        Err(SharedCacheInstallError::InvalidCacheRange)
    );

    program
        .install_shared_cache(&layout(&pieces, &code_regions, &islands))
        .unwrap();
    // Only the rewritten code page and the used gate island are executable.
    assert_eq!(
        program.entrypoints.task.executable_ranges(&range),
        [page(0), page(2)]
    );
    let task = &program.entrypoints.task;
    assert_eq!(task.global.shared_cache_base.load(Ordering::Acquire), base);
    let code = read_guest(base, code.len()).unwrap();
    let word =
        |index: usize| u32::from_le_bytes(code[4 * index..4 * index + 4].try_into().unwrap());
    assert_eq!((word(0), word(3)), (NOP, RET));
    for index in [1, 2] {
        let target = decode_branch_target(word(index), (base + 4 * index) as u64)
            .expect("site must branch to its gate");
        assert!(page(2).contains(&usize::try_from(target).unwrap()));
    }
    assert!(guest_flags(task, base).contains(VmFlags::VM_EXEC));
    assert!(guest_flags(task, page(2).start).contains(VmFlags::VM_EXEC));
    assert_eq!(read_guest(page(1).start, 2).unwrap(), [0x5a, 0x5a]);
    assert!(!guest_flags(task, page(1).start).contains(VmFlags::VM_EXEC));
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
    for (page, protection) in [(page(1), RX), (page(1), rw), (page(0), rw), (page(2), rw)] {
        assert_eq!(
            task.sys_mprotect(page.start, PAGE_SIZE, protection),
            Err(litebox_common_macos::errno::Errno::EACCES),
            "{page:#x?} {protection:?}"
        );
    }
    assert_eq!(task.sys_mprotect(page(3).start, PAGE_SIZE, rw), Ok(()));
    assert!(guest_flags(task, page(3).start).contains(VmFlags::VM_WRITE));
    assert_eq!(
        task.sys_mprotect(page(4).start, PAGE_SIZE, VmProtection::READ),
        Err(litebox_common_macos::errno::Errno::EACCES),
        "pages await the pager"
    );

    // Demand paging: only paged pieces are supplied, then follow their maximum.
    assert!(!task.page_in_shared_cache(page(5).start));
    assert!(!task.page_in_shared_cache(page(1).start));
    assert!(task.page_in_shared_cache(page(4).start + 8));
    assert_eq!(read_guest(page(4).start, 2).unwrap(), [0x77, 0x77]);
    assert!(!guest_flags(task, page(4).start).contains(VmFlags::VM_WRITE));
    assert!(!task.page_in_shared_cache(page(4).start), "supplied once");
    assert_eq!(task.sys_mprotect(page(4).start, PAGE_SIZE, rw), Ok(()));
    assert_eq!(
        program.install_shared_cache(&layout(&pieces, &code_regions, &islands)),
        Err(SharedCacheInstallError::AlreadyInstalled)
    );
}

#[test]
fn shared_cache_rewrite_fails_closed_without_reachable_island() {
    let task = task(MacosShimBuilder::new(Platform::new()).build());
    let original = words(&[NOP, SVC, MRS_TPIDRRO_X3, RET]);
    let mut code = original.clone();
    let address = SHARED_CACHE_MIN_ADDRESS;
    let far = address + (256 << 20)..address + (256 << 20) + PAGE_SIZE;
    let mut gates = vec![Vec::new()];
    assert_eq!(
        task.rewrite_shared_cache_code(
            &mut code,
            address,
            core::slice::from_ref(&(0..16)),
            &[far],
            &mut gates
        ),
        Err(SharedCacheInstallError::UnreachableGates)
    );
    assert_eq!(code, original);
    assert!(gates[0].is_empty());
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
    // Reads: size query, exact copy, truncation, mirrored errors, no writes.
    let mut length = 0;
    assert_eq!(sysctl(&[6, 26], &mut [], Some(&mut length), b""), Ok(0));
    assert_eq!(length, 7);
    let mut value = [0u8; 7];
    assert_eq!(sysctl(&[6, 26], &mut value, Some(&mut length), b""), Ok(0));
    assert_eq!(&value, b"J274AP\0");
    let mut short = [0u8; 3];
    let mut length = short.len();
    assert_eq!(
        sysctl(&[6, 26], &mut short, Some(&mut length), b""),
        Err(Errno::ENOMEM)
    );
    assert_eq!((&short, length), (b"J27", 3));
    assert_eq!(
        sysctl(&[103, 101, 118, 100], &mut [], None, b""),
        Err(Errno::EPERM)
    );
    assert_eq!(sysctl(&[6, 26], &mut [], None, b"x"), Err(Errno::EPERM));
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
        "no shared region before installation"
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
                false,
                true,
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
