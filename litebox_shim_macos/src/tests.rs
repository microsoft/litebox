// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use super::*;
use litebox::mm::page::{NonZeroAddress, NonZeroPageSize};
use litebox::platform::{
    RawConstPointer as _,
    page_mgmt::{AllocationOptions, MemoryRegionPermissions as Permissions},
};
use litebox_common_linux::vmem::CreatePagesFlags;
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

fn read_guest(address: usize, length: usize) -> Option<Vec<u8>> {
    litebox_common_macos::user_pointers::UserPtr::<u8>::from_usize(address)
        .to_owned_slice::<Platform>(length)
        .map(<[u8]>::into_vec)
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
