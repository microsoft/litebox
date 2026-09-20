// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use super::*;
use litebox::mm::linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize, VmFlags};
use litebox::platform::RawConstPointer as _;
use litebox_platform_macos_userland::MacosUserland as Platform;

fn task(shim: MacosShim<Platform>) -> Task<Platform> {
    Task {
        global: shim.global,
        files: shim.files,
        params: TaskParams::default(),
        process: Process(Arc::new(AtomicI32::new(-1))),
        thread: ThreadState {
            blocked_signals: core::sync::atomic::AtomicU32::new(0),
            id: 1u64 << 32,
        },
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
fn standalone_dyld_bootstrap_data_remains_writable() {
    use litebox::platform::page_mgmt::MemoryRegionPermissions;
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
    *task.global.standalone_dyld_range.lock() = Some(base..base + PAGE_SIZE);
    task.sys_mprotect(base, PAGE_SIZE, VmProtection::READ)
        .unwrap();
    assert!(
        task.check_user_buffer(base + 32, 1, MemoryRegionPermissions::WRITE)
            .is_ok(),
        "dyld bootstrap data must remain writable"
    );
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
fn bootstrap_compatibility_outputs_are_initialized() {
    use litebox_common_macos::{
        errno::Errno,
        user_pointers::{UserPtr, UserPtrMut},
    };

    let task = task(MacosShimBuilder::new(Platform::new()).build());
    // SAFETY: allocate one private page in this idle guest task.
    let page = unsafe {
        task.global.pm.create_writable_pages(
            NonZeroAddress::new(Platform::TASK_ADDR_MIN),
            NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    }
    .unwrap()
    .as_usize();

    let path = UserPtrMut::<u8>::from_usize(page);
    path.copy_from_slice::<Platform>(0, b"AMFI\0").unwrap();
    UserPtrMut::<u64>::from_usize(page + 16)
        .write_at_offset::<Platform>(0, 0)
        .unwrap();
    UserPtrMut::<usize>::from_usize(page + 24)
        .write_at_offset::<Platform>(0, page + 32)
        .unwrap();
    UserPtrMut::<u64>::from_usize(page + 32)
        .write_at_offset::<Platform>(0, 0xaaaa_aaaa_aaaa_aaaa)
        .unwrap();
    assert_eq!(
        task.sys_mac_policy(
            UserPtr::from_usize(page),
            0x5a,
            UserPtrMut::from_usize(page + 16),
        ),
        Ok(0)
    );
    assert_eq!(
        UserPtr::<u64>::from_usize(page + 32).read_at_offset::<Platform>(0),
        Some(0x3f)
    );
    assert_eq!(
        task.sys_mac_policy(
            UserPtr::from_usize(page),
            0x66,
            UserPtrMut::from_usize(page + 16),
        ),
        Err(Errno::ENOSYS)
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

    let oldset = UserPtrMut::<u32>::from_usize(page + 40);
    oldset.write_at_offset::<Platform>(0, 0xa5a5_a5a5).unwrap();
    assert_eq!(
        task.sys_sigprocmask(1, UserPtr::from_usize(0x1234), oldset,),
        Err(Errno::EFAULT)
    );
    assert_eq!(oldset.read_at_offset::<Platform>(0), Some(0xa5a5_a5a5));

    *task.global.shared_cache_range.lock() = Some(0x1800_0000..0x1801_0000);
    task.global.shared_cache_mappings.lock().extend([
        (
            0x1800_0000..0x1800_4000,
            VmProtection::READ | VmProtection::EXECUTE,
        ),
        (0x1800_8000..0x1801_0000, VmProtection::READ),
    ]);
    assert!(
        task.check_user_buffer(0x1800_1000, 4, Permissions::READ)
            .is_ok()
    );
    assert!(
        task.check_user_buffer(0x1800_1000, 4, Permissions::EXEC)
            .is_ok()
    );
    assert_eq!(
        task.check_user_buffer(0x1800_1000, 4, Permissions::WRITE),
        Err(Errno::EFAULT)
    );
    assert_eq!(
        task.check_user_buffer(0x1800_8000, 4, Permissions::EXEC),
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
