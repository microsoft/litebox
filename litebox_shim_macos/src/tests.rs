// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use super::*;
use litebox::mm::vmem::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize, VmFlags};
use litebox::platform::{RawConstPointer as _, page_mgmt::MemoryRegionPermissions as Permissions};
use litebox_platform_macos_userland::MacosUserland as Platform;

fn task(shim: MacosShim<Platform>) -> Task<Platform> {
    Task {
        global: shim.global,
        files: shim.files,
        params: TaskParams::default(),
        process: Process(Arc::new(AtomicI32::new(-1))),
        thread: ThreadState { id: 1u64 << 32 },
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
fn shared_cache_installation_validates_state_and_trampoline() {
    let task = task(MacosShimBuilder::new(Platform::new()).build());
    let process = task.process.clone();
    let program = LoadedProgram {
        entrypoints: MacosShimEntrypoints {
            task,
            _not_send: core::marker::PhantomData,
        },
        process,
        initial_ctx: PtRegs::default(),
    };
    let mappings = [SharedCacheMapping {
        range: PAGE_SIZE..3 * PAGE_SIZE,
        protection: VmProtection::READ,
    }];
    let cache = SharedCacheLayout {
        range: PAGE_SIZE..3 * PAGE_SIZE,
        mappings: &mappings,
        executable_regions: &[],
        trampoline: SharedCacheTrampoline {
            range: 2 * PAGE_SIZE..4 * PAGE_SIZE,
            writable_alias: PAGE_SIZE,
        },
    };
    assert_eq!(
        program.install_shared_cache(&cache),
        Err(SharedCacheInstallError::InvalidCacheRange)
    );

    program
        .entrypoints
        .task
        .global
        .shared_cache_base
        .store(PAGE_SIZE, Ordering::Release);
    assert_eq!(
        program.install_shared_cache(&cache),
        Err(SharedCacheInstallError::AlreadyInstalled)
    );
}

#[test]
fn dyld_data_remains_writable_during_bootstrap() {
    use litebox_common_macos::VmProtection;

    let task = task(MacosShimBuilder::new(Platform::new()).build());
    // SAFETY: allocate one fresh page owned exclusively by this test task.
    let page = unsafe {
        task.global.pm.create_writable_pages(
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
        .pm
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
        task.global.pm.create_writable_pages(
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
        .pm
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
        .pm
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
            .pm
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
        task.global.pm.create_writable_pages(
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
            .pm
            .change_page_permissions(ptr, PAGE_SIZE, Permissions::READ)
            .unwrap();
        platform.deallocate_pages(base..base + PAGE_SIZE).unwrap();
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _task = task;
        panic!("original panic");
    }));
    assert!(result.is_err());
    // Cleanup continues with the second VMA after the first unmap fails.
    let second_page = base + PAGE_SIZE..base + 2 * PAGE_SIZE;
    let probe = platform
        .allocate_pages(
            second_page.clone(),
            Permissions::READ,
            false,
            true,
            FixedAddressBehavior::NoReplace,
        )
        .unwrap();
    assert_eq!(probe.as_usize(), second_page.start);
    // SAFETY: the probe has no users and is owned by this test.
    unsafe {
        platform.deallocate_pages(second_page).unwrap();
    }
}
