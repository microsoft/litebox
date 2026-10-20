// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use super::*;
use litebox::mm::page::{NonZeroAddress, NonZeroPageSize};
use litebox::platform::{RawConstPointer as _, page_mgmt::MemoryRegionPermissions as Permissions};
use litebox_common_linux::vmem::{CreatePagesFlags, VmFlags};
use litebox_platform_macos_userland::MacosUserland as Platform;

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

#[test]
fn shared_cache_installation_validates_layout() {
    const RX: VmProtection = VmProtection::READ.union(VmProtection::EXECUTE);
    let program = loaded_program(task(MacosShimBuilder::new(Platform::new()).build()));
    let base = 0x10_0000_0000;
    let mappings = [
        SharedCacheMapping {
            range: base..base + PAGE_SIZE,
            protection: VmProtection::READ,
        },
        SharedCacheMapping {
            range: base + PAGE_SIZE..base + 3 * PAGE_SIZE,
            protection: RX,
        },
    ];
    let island = |start: usize| SharedCacheGateIsland {
        range: start..start + PAGE_SIZE,
        writable_alias: start,
    };
    let code = |start: usize| SharedCacheCodeRegion {
        range: start..start + PAGE_SIZE,
        writable_alias: start,
        instruction_ranges: &[],
    };
    let layout = |code_regions, gate_islands| SharedCacheLayout {
        range: base..base + 4 * PAGE_SIZE,
        mappings: &mappings,
        code_regions,
        gate_islands,
    };
    let read_only_island = [island(base)];
    let outside_island = [island(base + 4 * PAGE_SIZE)];
    let overlapping_islands = [island(base + PAGE_SIZE), island(base + PAGE_SIZE)];
    let unmapped_island = [island(base + 3 * PAGE_SIZE)];
    for islands in [
        &read_only_island[..],
        &outside_island,
        &overlapping_islands,
        &unmapped_island,
    ] {
        assert_eq!(
            program.install_shared_cache(&layout(&[], islands)),
            Err(SharedCacheInstallError::InvalidGateIsland)
        );
    }
    let valid_island = [island(base + 2 * PAGE_SIZE)];
    let read_only_code = [code(base)];
    let island_code = [code(base + 2 * PAGE_SIZE)];
    for regions in [&read_only_code[..], &island_code] {
        assert_eq!(
            program.install_shared_cache(&layout(regions, &valid_island)),
            Err(SharedCacheInstallError::InvalidRegion)
        );
    }
    let unaligned = SharedCacheLayout {
        range: base + 1..base + 4 * PAGE_SIZE,
        ..layout(&[], &valid_island)
    };
    assert_eq!(
        program.install_shared_cache(&unaligned),
        Err(SharedCacheInstallError::InvalidCacheRange)
    );
    // Without code to rewrite, a valid layout only registers the instance.
    assert_eq!(
        program.install_shared_cache(&layout(&[], &valid_island)),
        Ok(())
    );
    assert_eq!(
        program
            .entrypoints
            .task
            .global
            .shared_cache_base
            .load(Ordering::Acquire),
        base
    );
    assert_eq!(
        program.install_shared_cache(&layout(&[], &valid_island)),
        Err(SharedCacheInstallError::AlreadyInstalled)
    );
}

/// Rewrite one SVC and one TPIDRRO read with the given islands. Returns the
/// region result, the code page, and the island cursors.
fn rewrite_with_islands(
    task: &Task<Platform>,
    islands: impl FnOnce(usize) -> Vec<SharedCacheGateIsland>,
) -> (
    Result<(), SharedCacheInstallError>,
    Vec<u8>,
    Vec<SharedCacheGateIsland>,
    Vec<usize>,
) {
    const CODE: [u32; 4] = [0xd503_201f, 0xd400_1001, 0xd53b_d063, 0xd65f_03c0];
    // SAFETY: allocate fresh pages owned exclusively by this idle test task.
    let base = unsafe {
        task.global.mm.create_writable_pages(
            NonZeroAddress::new(Platform::TASK_ADDR_MIN),
            NonZeroPageSize::new(3 * PAGE_SIZE).unwrap(),
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    }
    .unwrap()
    .as_usize();
    let code: Vec<u8> = CODE.iter().flat_map(|word| word.to_le_bytes()).collect();
    litebox_common_macos::user_pointers::UserPtrMut::<u8>::from_usize(base)
        .copy_from_slice::<Platform>(0, &code)
        .unwrap();
    let instructions = 0..code.len();
    let instruction_ranges = core::slice::from_ref(&instructions);
    let region = SharedCacheCodeRegion {
        range: base..base + PAGE_SIZE,
        writable_alias: base,
        instruction_ranges,
    };
    let islands = islands(base);
    let mut cursors = vec![0; islands.len()];
    let result = task.rewrite_shared_cache_region(&region, &islands, &mut cursors);
    let code = litebox_common_macos::user_pointers::UserPtr::<u8>::from_usize(base)
        .to_owned_slice::<Platform>(code.len())
        .unwrap()
        .into_vec();
    (result, code, islands, cursors)
}

#[test]
fn shared_cache_rewrite_uses_nearest_reachable_island() {
    use litebox_trampoline::aarch64::decode_branch_target;

    let task = task(MacosShimBuilder::new(Platform::new()).build());
    // The first island is out of `B` range. Its writable alias is a real page,
    // so a wrong choice would be observable rather than fault.
    let (result, code, islands, cursors) = rewrite_with_islands(&task, |base| {
        vec![
            SharedCacheGateIsland {
                range: base + (256 << 20)..base + (256 << 20) + PAGE_SIZE,
                writable_alias: base + PAGE_SIZE,
            },
            SharedCacheGateIsland {
                range: base + 2 * PAGE_SIZE..base + 3 * PAGE_SIZE,
                writable_alias: base + 2 * PAGE_SIZE,
            },
        ]
    });
    assert_eq!(result, Ok(()));
    assert_eq!(cursors[0], 0);
    assert_ne!(cursors[1], 0);
    let word =
        |index: usize| u32::from_le_bytes(code[4 * index..4 * index + 4].try_into().unwrap());
    assert_eq!(word(0), 0xd503_201f);
    assert_eq!(word(3), 0xd65f_03c0);
    let base = islands[1].range.start - 2 * PAGE_SIZE;
    for index in [1, 2] {
        let target = decode_branch_target(word(index), (base + 4 * index) as u64)
            .expect("site must branch to its gate");
        assert!(islands[1].range.contains(&usize::try_from(target).unwrap()));
    }
}

#[test]
fn shared_cache_rewrite_fails_closed_without_reachable_island() {
    let task = task(MacosShimBuilder::new(Platform::new()).build());
    let (result, code, _, cursors) = rewrite_with_islands(&task, |base| {
        vec![SharedCacheGateIsland {
            range: base + (256 << 20)..base + (256 << 20) + PAGE_SIZE,
            writable_alias: base + PAGE_SIZE,
        }]
    });
    assert_eq!(result, Err(SharedCacheInstallError::UnreachableGates));
    assert_eq!(cursors, [0]);
    assert_eq!(
        code,
        [0xd503_201fu32, 0xd400_1001, 0xd53b_d063, 0xd65f_03c0]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>()
    );
}

#[test]
fn dyld_data_remains_writable_during_bootstrap() {
    use litebox_common_macos::VmProtection;

    let task = task(MacosShimBuilder::new(Platform::new()).build());
    // SAFETY: allocate one fresh page owned exclusively by this test task.
    let page = unsafe {
        task.global.mm.create_writable_pages(
            NonZeroAddress::new(Platform::TASK_ADDR_MIN),
            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    }
    .unwrap();
    let base = page.as_usize();
    *task.global.privately_mapped_dyld_range.lock() = Some(base..base + PAGE_SIZE);
    task.sys_mprotect(base, PAGE_SIZE, VmProtection::READ)
        .unwrap();
    let flags = task
        .global
        .mm
        .mappings()
        .into_iter()
        .find_map(|(range, flags)| range.contains(&base).then_some(flags))
        .unwrap();
    assert!(flags.contains(VmFlags::VM_WRITE));
}

#[test]
fn mach_vm_map_honors_current_protection() {
    use litebox_common_macos::{
        KernReturn, VmProtection,
        syscall::{MachVmAddressMask, MachVmFlags, MachVmProtection, synthetic_port},
        user_pointers::UserPtrMut,
    };

    let task = task(MacosShimBuilder::new(Platform::new()).build());
    // SAFETY: allocate fresh address-output storage in this idle guest task.
    let slot = unsafe {
        task.global.mm.create_writable_pages(
            NonZeroAddress::new(Platform::TASK_ADDR_MIN),
            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    }
    .unwrap();
    let address = UserPtrMut::from_usize(slot.as_usize());
    address
        .write_at_offset::<Platform>(0, Platform::TASK_ADDR_MIN + 1)
        .unwrap();

    assert_eq!(
        task.sys_mach_vm_map_compat(
            synthetic_port::TASK_SELF,
            address,
            PAGE_SIZE,
            MachVmAddressMask(PAGE_SIZE - 1),
            MachVmFlags::ANYWHERE,
            MachVmProtection::new(VmProtection::READ, false),
        ),
        usize::from(KernReturn::INVALID_ARGUMENT)
    );
    assert_eq!(
        address.read_at_offset::<Platform>(0),
        Some(Platform::TASK_ADDR_MIN + 1)
    );

    assert_eq!(
        task.sys_mach_vm_map_compat(
            synthetic_port::TASK_SELF,
            address,
            PAGE_SIZE,
            MachVmAddressMask(0),
            MachVmFlags::ANYWHERE,
            MachVmProtection::new(VmProtection::READ, false),
        ),
        usize::from(KernReturn::SUCCESS)
    );
    let mapped = address.read_at_offset::<Platform>(0).unwrap();
    let flags = task
        .global
        .mm
        .mappings()
        .into_iter()
        .find_map(|(range, flags)| range.contains(&mapped).then_some(flags))
        .unwrap();
    assert!(flags.contains(VmFlags::VM_READ));
    assert!(!flags.contains(VmFlags::VM_WRITE));

    assert_eq!(
        task.sys_mach_vm_protect_compat(
            synthetic_port::TASK_SELF,
            mapped + 1,
            1,
            false,
            MachVmProtection::new(VmProtection::READ | VmProtection::WRITE, true),
        ),
        usize::from(KernReturn::SUCCESS)
    );
    let flags = task
        .global
        .mm
        .mappings()
        .into_iter()
        .find_map(|(range, flags)| range.contains(&mapped).then_some(flags))
        .unwrap();
    assert!(flags.contains(VmFlags::VM_WRITE));
    assert_eq!(
        task.sys_mach_vm_deallocate_compat(synthetic_port::TASK_SELF, mapped + 1, 1),
        usize::from(KernReturn::SUCCESS)
    );
    assert!(
        task.global
            .mm
            .mappings()
            .into_iter()
            .all(|(range, _)| !range.contains(&mapped))
    );

    address
        .write_at_offset::<Platform>(0, Platform::TASK_ADDR_MIN + 1)
        .unwrap();
    assert_eq!(
        task.sys_mach_vm_map_compat(
            synthetic_port::TASK_SELF,
            address,
            0,
            MachVmAddressMask(0),
            MachVmFlags::ANYWHERE,
            MachVmProtection::new(VmProtection::READ | VmProtection::WRITE, false),
        ),
        usize::from(KernReturn::INVALID_ARGUMENT)
    );
    assert_eq!(
        address.read_at_offset::<Platform>(0),
        Some(Platform::TASK_ADDR_MIN + 1)
    );
    assert_eq!(
        task.sys_mach_vm_allocate_compat(
            synthetic_port::TASK_SELF,
            address,
            0,
            MachVmFlags::ANYWHERE,
        ),
        usize::from(KernReturn::SUCCESS)
    );
    assert_eq!(address.read_at_offset::<Platform>(0), Some(0));
}

#[test]
fn sysctl_fallback_requires_name_to_oid_mib_and_bounds_name() {
    use litebox_common_macos::{errno::Errno, user_pointers::UserPtr};

    let wrong_mib = [0, 2];
    assert_eq!(
        Task::<Platform>::sys_sysctl_compat(
            UserPtr::from_ptr(wrong_mib.as_ptr()),
            2,
            UserPtr::from_usize(1),
            b"kern.bootargs".len(),
        ),
        Err(Errno::ENOSYS)
    );
    let name_to_oid = [0, 3];
    assert_eq!(
        Task::<Platform>::sys_sysctl_compat(
            UserPtr::from_ptr(name_to_oid.as_ptr()),
            2,
            UserPtr::from_usize(1),
            usize::MAX,
        ),
        Err(Errno::ENOSYS)
    );
}

#[test]
fn shared_region_check_handles_sentinel_and_copyout_fault() {
    use litebox_common_macos::{errno::Errno, user_pointers::UserPtrMut};

    let task = task(MacosShimBuilder::new(Platform::new()).build());
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
