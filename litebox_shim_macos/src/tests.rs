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
fn unsupported_syscall_reports_use_bounded_state() {
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

    // Through the dispatcher: distinct unsupported selectors keep failing
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

fn read_guest(address: usize, length: usize) -> Option<Vec<u8>> {
    litebox_common_macos::user_pointers::UserPtr::<u8>::from_usize(address)
        .to_owned_slice::<Platform>(length)
        .map(<[u8]>::into_vec)
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
