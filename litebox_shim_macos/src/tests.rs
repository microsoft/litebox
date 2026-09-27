// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use super::*;
use litebox::platform::{RawConstPointer as _, page_mgmt::MemoryRegionPermissions as Permissions};
use litebox_common_linux::vmem::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize, VmFlags};
use litebox_platform_macos_userland::MacosUserland as Platform;

fn task(shim: MacosShim<Platform>) -> Task<Platform> {
    let thread = ThreadState::new(1u64 << 32, shim.global.platform);
    Task {
        global: shim.global,
        files: shim.files,
        params: TaskParams::default(),
        process: Process::new(),
        thread,
    }
}

#[test]
fn last_pthread_keeps_a_live_task_for_libc_exit() {
    use alloc::collections::BTreeSet;
    use litebox_common_macos::{MmapFlags, user_pointers::UserPtrMut};

    let first = task(
        MacosShimBuilder::new(Platform::new())
            .with_pthread_runtime(PthreadRuntime {
                thread_start: 0x1000,
                process_exit: 0x2000,
                tsd_offset: 0,
                mach_thread_self_offset: 0,
                pthread_size: PAGE_SIZE,
                current_thread_identity: || (1, 1),
                synchronize: |_| Ok(0),
            })
            .build(),
    );
    let process = first.process.clone();
    process.thread_started();
    let last = Task {
        global: first.global.clone(),
        files: first.files.clone(),
        params: first.params,
        process: process.clone(),
        thread: ThreadState::new(first.thread.id + 1, first.global.platform),
    };
    let global = first.global.clone();
    let base = first
        .sys_mmap(
            0,
            4 * PAGE_SIZE,
            VmProtection::READ | VmProtection::WRITE,
            MmapFlags::ANONYMOUS | MmapFlags::PRIVATE,
            -1,
            0,
        )
        .unwrap();
    let page = |index| UserPtrMut::<usize>::from_usize(base + index * PAGE_SIZE);
    // Aligned and unaligned pthread footprints share a page in one merged VM
    // span. Round their bounds without absorbing the rest of that span.
    last.retain_pthread_mapping(base + PAGE_SIZE).unwrap();
    first.retain_pthread_mapping(base + PAGE_SIZE + 16).unwrap();
    first.sys_munmap(base + 3 * PAGE_SIZE, PAGE_SIZE).unwrap();
    assert_eq!(page(3).read_at_offset::<Platform>(0), None);
    let tsd = page(1);
    tsd.write_at_offset::<Platform>(0, 0xfeed).unwrap();
    assert_eq!(
        first.sys_mach_vm_deallocate_compat(
            litebox_common_macos::syscall::synthetic_port::TASK_SELF,
            base,
            4 * PAGE_SIZE,
        ),
        usize::from(KernReturn::SUCCESS)
    );
    // Repeated unmaps must not create stale duplicate cleanup requests.
    first.sys_munmap(base, 4 * PAGE_SIZE).unwrap();
    assert_eq!(
        global.pthread_mappings.lock().pending_pages,
        BTreeSet::from([base + PAGE_SIZE, base + 2 * PAGE_SIZE])
    );
    let replace = |index| {
        let address = base + index * PAGE_SIZE;
        assert_eq!(
            last.sys_mmap(
                address,
                PAGE_SIZE,
                VmProtection::READ | VmProtection::WRITE,
                MmapFlags::ANONYMOUS | MmapFlags::PRIVATE | MmapFlags::FIXED,
                -1,
                0
            ),
            Ok(address)
        );
        page(index)
            .write_at_offset::<Platform>(0, 0xcafe + index)
            .unwrap();
    };
    for index in [0, 3] {
        assert_eq!(page(index).read_at_offset::<Platform>(0), None);
        replace(index);
    }
    assert_eq!(
        first.sys_munmap(base + PAGE_SIZE + 1, PAGE_SIZE),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        first.sys_mmap(
            base + PAGE_SIZE,
            PAGE_SIZE,
            VmProtection::READ | VmProtection::WRITE,
            MmapFlags::ANONYMOUS | MmapFlags::PRIVATE | MmapFlags::FIXED,
            -1,
            0,
        ),
        Err(Errno::ENOMEM)
    );
    let mut ctx = PtRegs {
        pc: 0x3000,
        sp: base + PAGE_SIZE,
        ..PtRegs::default()
    };
    ctx.regs[16] = litebox_common_macos::syscall::nr::BSDTHREAD_TERMINATE;
    first.handle_syscall_request(&mut ctx);
    assert!(first.thread.exited.load(Ordering::Acquire));
    assert!(!first.thread.counted.get());
    // The first host Task has not been dropped yet. It must not prevent the
    // last guest from detecting process completion at bsdthread_terminate.
    last.handle_syscall_request(&mut ctx);
    assert_eq!(
        (ctx.pc, ctx.sp, ctx.regs[0], ctx.regs[30]),
        (0x2000, base + PAGE_SIZE, 0, 0)
    );
    assert_eq!(last.continuation(&ctx), ContinueOperation::Resume);
    drop(first);
    // Release the first pin independently, then reuse its page while the other
    // pin still exists. Dropping the last pin must not destroy this mapping.
    assert_eq!(page(2).read_at_offset::<Platform>(0), None);
    replace(2);
    assert_eq!(process.0.live_threads.load(Ordering::Acquire), 1);
    assert_eq!(process.exit_status(), None);
    assert_eq!(tsd.read_at_offset::<Platform>(0), Some(0xfeed));
    tsd.write_at_offset::<Platform>(0, 0xbeef).unwrap();
    // Only libc's subsequent exit syscall should publish successful completion.
    last.sys_exit(7);
    drop(last);
    assert_eq!(process.0.live_threads.load(Ordering::Acquire), 0);
    assert_eq!(process.exit_status(), Some(7));
    assert_eq!(tsd.read_at_offset::<Platform>(0), None);
    assert_eq!(
        global.pthread_mappings.lock().pending_pages,
        BTreeSet::new()
    );
    for index in [0, 2, 3] {
        assert_eq!(
            page(index).read_at_offset::<Platform>(0),
            Some(0xcafe + index)
        );
    }
}

#[test]
fn pthread_terminate_requires_the_runtime_opt_in() {
    let task = task(MacosShimBuilder::new(Platform::new()).build());
    let mut ctx = PtRegs {
        pc: 0x1000,
        sp: 0x2000,
        ..PtRegs::default()
    };
    ctx.regs[16] = litebox_common_macos::syscall::nr::BSDTHREAD_TERMINATE;
    task.handle_syscall_request(&mut ctx);
    assert_eq!(ctx.regs[0], Errno::ENOSYS.raw());
    assert_ne!(ctx.pstate & (1 << 29), 0);
    assert_eq!(ctx.pc, 0x1000);
    assert_eq!(task.continuation(&ctx), ContinueOperation::Resume);
    assert_eq!(task.process.exit_status(), None);
    assert!(task.thread.counted.get());
}

#[test]
fn broker_wait_observes_process_exit() {
    let task = task(MacosShimBuilder::new(Platform::new()).build());
    assert!(!litebox::event::wait::CheckForInterrupt::check_for_interrupt(&task));
    assert!(task.process.exit(5));
    assert!(matches!(
        task.wait_cx()
            .with_timeout(core::time::Duration::from_secs(1))
            .sleep(),
        litebox::event::wait::WaitError::Interrupted
    ));
}

#[test]
fn process_exit_retries_an_interrupt_delivered_before_a_host_wait() {
    use litebox_platform::sync::{RawMutex as _, UnblockedOrTimedOut};
    use std::time::{Duration, Instant};

    struct Probe<F> {
        entrypoints: MacosShimEntrypoints<Platform>,
        body: F,
    }
    impl<F: Fn(&MacosShimEntrypoints<Platform>)> EnterShim for Probe<F> {
        type ExecutionContext = PtRegs;
        fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
            assert_eq!(self.entrypoints.init(ctx), ContinueOperation::Resume);
            (self.body)(&self.entrypoints);
            self.entrypoints.task.continuation(ctx)
        }
        fn syscall(&self, _: &mut PtRegs) -> ContinueOperation {
            unreachable!()
        }
        fn exception(&self, _: &mut PtRegs, _: &ExceptionInfo) -> ContinueOperation {
            unreachable!()
        }
        fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
            unreachable!()
        }
    }

    litebox_platform_macos_userland::set_guest_abi(
        litebox_platform_macos_userland::GuestAbi::Linux,
    );
    let waiter = task(MacosShimBuilder::new(Platform::new()).build());
    let process = waiter.process.clone();
    let global = waiter.global.clone();
    process.thread_started();
    let exiting = Task {
        global: waiter.global.clone(),
        files: waiter.files.clone(),
        params: waiter.params,
        process: process.clone(),
        thread: ThreadState::new(waiter.thread.id + 1, waiter.global.platform),
    };
    let (ready, receiver) = std::sync::mpsc::channel();
    let exiter = std::thread::spawn(move || {
        let probe = Probe {
            entrypoints: MacosShimEntrypoints {
                task: exiting,
                _not_send: core::marker::PhantomData,
            },
            body: |entry: &MacosShimEntrypoints<Platform>| {
                receiver.recv_timeout(Duration::from_secs(3)).unwrap();
                entry.task.sys_exit(5);
            },
        };
        // SAFETY: init exits the process; no guest instructions execute.
        unsafe { litebox_platform_macos_userland::run_thread(probe, &mut PtRegs::default()) };
    });
    let outcome = core::cell::Cell::new(None);
    let probe = Probe {
        entrypoints: MacosShimEntrypoints {
            task: waiter,
            _not_send: core::marker::PhantomData,
        },
        body: |entry: &MacosShimEntrypoints<Platform>| {
            // Queue the first exit interrupt so we can deliberately consume it
            // before entering the host wait, rather than relying on scheduling.
            let signals = (1 << (libc::SIGUSR1 - 1)) | (1 << (libc::SIGUSR2 - 1));
            let mut previous = 0;
            // SAFETY: both masks are live; this changes only the current thread.
            assert_eq!(
                unsafe {
                    libc::pthread_sigmask(libc::SIG_BLOCK, &raw const signals, &raw mut previous)
                },
                0
            );
            let _restore = litebox::utils::defer(|| {
                // SAFETY: previous is this thread's saved signal mask.
                assert_eq!(
                    unsafe {
                        libc::pthread_sigmask(
                            libc::SIG_SETMASK,
                            &raw const previous,
                            core::ptr::null_mut(),
                        )
                    },
                    0
                );
            });
            ready.send(()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let mut pending = 0;
                // SAFETY: pending is writable output storage for this thread.
                assert_eq!(unsafe { libc::sigpending(&raw mut pending) }, 0);
                if pending & signals != 0 {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "first exit interrupt was not sent"
                );
                std::thread::yield_now();
            }
            // SAFETY: restoring the mask delivers the queued signal in host code.
            assert_eq!(
                unsafe {
                    libc::pthread_sigmask(
                        libc::SIG_SETMASK,
                        &raw const previous,
                        core::ptr::null_mut(),
                    )
                },
                0
            );
            std::thread::sleep(Duration::from_millis(25));
            // No waker or pre-wait exit check: only a subsequent interrupt can
            // release this wait before its test-only safety timeout.
            let wait = litebox_platform_macos_userland::RawMutex::INIT;
            outcome.set(Some(
                wait.block_or_timeout(0, Duration::from_secs(1)).unwrap(),
            ));
            // A losing exit caller must not wait for the coordinator waiting on it.
            entry.task.sys_exit(9);
        },
    };
    // SAFETY: init waits on the host stack, then observes process exit and terminates.
    unsafe { litebox_platform_macos_userland::run_thread(probe, &mut PtRegs::default()) };
    exiter.join().unwrap();
    assert_eq!(outcome.get(), Some(UnblockedOrTimedOut::Unblocked));
    assert_eq!(process.exit_status(), Some(5));
    assert!(global.threads.lock().is_empty());
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
        platform.release_pages(second_page).unwrap();
    }
}
