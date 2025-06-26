//! Process/thread related syscalls.

use alloc::boxed::Box;
use litebox::platform::{ExitProvider as _, RawMutPointer, ThreadProvider};
use litebox::platform::{
    PunchthroughProvider as _, PunchthroughToken as _, ThreadLocalStorageProvider as _,
};
use litebox::utils::TruncateExt;
use litebox_common_linux::CloneFlags;
use litebox_common_linux::{ArchPrctlArg, errno::Errno};

use crate::MutPtr;

pub(crate) fn sys_arch_prctl(
    arg: ArchPrctlArg<litebox_platform_multiplex::Platform>,
) -> Result<(), Errno> {
    match arg {
        #[cfg(target_arch = "x86_64")]
        ArchPrctlArg::SetFs(addr) => {
            let punchthrough = litebox_common_linux::PunchthroughSyscall::SetFsBase { addr };
            let token = litebox_platform_multiplex::platform()
                .get_punchthrough_token_for(punchthrough)
                .expect("Failed to get punchthrough token for SET_FS");
            token.execute().map(|_| ()).map_err(|e| match e {
                litebox::platform::PunchthroughError::Failure(errno) => errno,
                _ => unimplemented!("Unsupported punchthrough error {:?}", e),
            })
        }
        #[cfg(target_arch = "x86_64")]
        ArchPrctlArg::GetFs(addr) => {
            let punchthrough = litebox_common_linux::PunchthroughSyscall::GetFsBase { addr };
            let token = litebox_platform_multiplex::platform()
                .get_punchthrough_token_for(punchthrough)
                .expect("Failed to get punchthrough token for GET_FS");
            token.execute().map(|_| ()).map_err(|e| match e {
                litebox::platform::PunchthroughError::Failure(errno) => errno,
                _ => unimplemented!("Unsupported punchthrough error {:?}", e),
            })
        }
        ArchPrctlArg::CETStatus | ArchPrctlArg::CETDisable | ArchPrctlArg::CETLock => {
            Err(Errno::EINVAL)
        }
        _ => unimplemented!(),
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn set_thread_area(
    user_desc: crate::MutPtr<litebox_common_linux::UserDesc>,
) -> Result<(), Errno> {
    Err(Errno::ENOSYS) // x86_64 does not support set_thread_area
}

#[cfg(target_arch = "x86")]
pub(crate) fn set_thread_area(
    user_desc: crate::MutPtr<litebox_common_linux::UserDesc>,
) -> Result<(), Errno> {
    use litebox::platform::{PunchthroughProvider as _, PunchthroughToken as _};
    let punchthrough = litebox_common_linux::PunchthroughSyscall::SetThreadArea { user_desc };
    let token = litebox_platform_multiplex::platform()
        .get_punchthrough_token_for(punchthrough)
        .expect("Failed to get punchthrough token for SET_THREAD_AREA");
    token.execute().map(|_| ()).map_err(|e| match e {
        litebox::platform::PunchthroughError::Failure(errno) => errno,
        _ => unimplemented!("Unsupported punchthrough error {:?}", e),
    })
}

pub(crate) fn sys_rt_sigprocmask(
    how: litebox_common_linux::SigmaskHow,
    set: Option<crate::ConstPtr<litebox_common_linux::SigSet>>,
    oldset: Option<crate::MutPtr<litebox_common_linux::SigSet>>,
) -> Result<(), Errno> {
    let punchthrough =
        litebox_common_linux::PunchthroughSyscall::RtSigprocmask { how, set, oldset };
    let token = litebox_platform_multiplex::platform()
        .get_punchthrough_token_for(punchthrough)
        .expect("Failed to get punchthrough token for RT_SIGPROCMASK");
    token.execute().map(|_| ()).map_err(|e| match e {
        litebox::platform::PunchthroughError::Failure(errno) => errno,
        _ => unimplemented!("Unsupported punchthrough error {:?}", e),
    })
}

pub(crate) fn sys_rt_sigaction(
    signum: litebox_common_linux::Signal,
    act: Option<crate::ConstPtr<litebox_common_linux::SigAction>>,
    oldact: Option<crate::MutPtr<litebox_common_linux::SigAction>>,
) -> Result<(), Errno> {
    let punchthrough = litebox_common_linux::PunchthroughSyscall::RtSigaction {
        signum,
        act,
        oldact,
    };
    let token = litebox_platform_multiplex::platform()
        .get_punchthrough_token_for(punchthrough)
        .expect("Failed to get punchthrough token for RT_SIGACTION");
    token.execute().map(|_| ()).map_err(|e| match e {
        litebox::platform::PunchthroughError::Failure(errno) => errno,
        _ => unimplemented!("Unsupported punchthrough error {:?}", e),
    })
}

fn futex_wake(addr: MutPtr<i32>) {
    let punchthrough = litebox_common_linux::PunchthroughSyscall::WakeByAddress { addr };
    let token = litebox_platform_multiplex::platform()
        .get_punchthrough_token_for(punchthrough)
        .expect("Failed to get punchthrough token for FUTEX_WAKE");
    token.execute().unwrap_or_else(|e| match e {
        litebox::platform::PunchthroughError::Failure(errno) => {
            panic!("FUTEX_WAKE failed with error: {:?}", errno)
        }
        _ => unimplemented!("Unsupported punchthrough error {:?}", e),
    });
}

pub(crate) fn sys_exit(status: i32) -> ! {
    let mut tls = litebox_platform_multiplex::platform().release_thread_local_storage();
    if let Some(clear_child_tid) = tls.current_task.clear_child_tid.take() {
        // Clear the child TID if requested
        // TODO: if we are the last thread, we don't need to clear it
        let _ = unsafe { clear_child_tid.write_at_offset(0, 0) };
        futex_wake(clear_child_tid);
    }

    litebox_platform_multiplex::platform().terminate_thread(status)
}

pub(crate) fn sys_exit_group(status: i32) -> ! {
    litebox_platform_multiplex::platform().exit(status)
}

fn new_thread_callback(
    args: litebox_common_linux::NewThreadArgs<litebox_platform_multiplex::Platform>,
) {
    let litebox_common_linux::NewThreadArgs {
        mut task,
        tls,
        set_child_tid,
        callback: _,
    } = args;
    let child_tid = task.tid;

    // Set the TLS for the platform itself
    let litebox_tls = litebox_common_linux::ThreadLocalStorage::new(task);
    litebox_platform_multiplex::platform().set_thread_local_storage(litebox_tls);

    // Set the TLS for the guest program
    if let Some(tls) = tls {
        // Set the TLS base pointer for the new thread
        #[cfg(target_arch = "x86")]
        set_thread_area(tls);

        #[cfg(target_arch = "x86_64")]
        {
            use litebox::platform::RawConstPointer as _;
            sys_arch_prctl(ArchPrctlArg::SetFs(tls.as_usize()));
        }
    }

    if let Some(set_child_tid) = set_child_tid {
        // Set the child TID if requested
        let _ = unsafe { set_child_tid.write_at_offset(0, child_tid) };
    }
}

/// Creates a new thread or process.
///
/// Note we currently only support creating threads with the VM, FS, and FILES flags set.
#[expect(clippy::too_many_arguments)]
pub(crate) fn sys_clone(
    flags: litebox_common_linux::CloneFlags,
    parent_tid: Option<crate::MutPtr<u32>>,
    stack: Option<crate::MutPtr<u8>>,
    stack_size: usize,
    child_tid: Option<crate::MutPtr<i32>>,
    tls: Option<crate::MutPtr<litebox_common_linux::ThreadLocalDescriptor>>,
    ctx: &litebox_common_linux::PtRegs,
    main: usize,
) -> Result<usize, Errno> {
    if !flags.contains(CloneFlags::VM) {
        unimplemented!("Clone without VM flag is not supported");
    }
    if !flags.contains(CloneFlags::FS) {
        unimplemented!("Clone without FS flag is not supported");
    }
    if !flags.contains(CloneFlags::FILES) {
        unimplemented!("Clone without FILES flag is not supported");
    }
    if !flags.contains(CloneFlags::SYSVSEM) {
        unimplemented!("Clone without SYSVSEM flag is not supported");
    }
    let unsupported_clone_flags = CloneFlags::PIDFD
        | CloneFlags::PTRACE
        | CloneFlags::VFORK
        | CloneFlags::PARENT
        | CloneFlags::NEWNS
        | CloneFlags::UNTRACED
        | CloneFlags::NEWCGROUP
        | CloneFlags::NEWUTS
        | CloneFlags::NEWIPC
        | CloneFlags::NEWUSER
        | CloneFlags::NEWPID
        | CloneFlags::NEWNET
        | CloneFlags::IO
        | CloneFlags::CLEAR_SIGHAND
        | CloneFlags::INTO_CGROUP
        | CloneFlags::NEWTIME;
    if flags.intersects(unsupported_clone_flags) {
        unimplemented!("Clone with unsupported flags: {:?}", flags);
    }

    let platform = litebox_platform_multiplex::platform();
    let child_tid = unsafe {
        platform.spawn_thread(
            ctx,
            stack.expect("Stack pointer is required for thread creation"),
            stack_size,
            main,
            Box::new(litebox_common_linux::NewThreadArgs {
                tls,
                set_child_tid: if flags.contains(CloneFlags::CHILD_SETTID) {
                    child_tid
                } else {
                    None
                },
                task: Box::new(litebox_common_linux::Task {
                    tid: 0, // The actual TID will be set by the platform
                    clear_child_tid: if flags.contains(CloneFlags::CHILD_CLEARTID) {
                        child_tid
                    } else {
                        None
                    },
                }),
                callback: new_thread_callback,
            }),
        )
    }?;
    if flags.contains(CloneFlags::PARENT_SETTID) {
        if let Some(parent_tid_ptr) = parent_tid {
            let _ = unsafe { parent_tid_ptr.write_at_offset(0, child_tid.truncate()) };
        }
    }
    Ok(child_tid)
}

/// Handle syscall `set_tid_address`.
pub(crate) fn sys_set_tid_address(tidptr: crate::MutPtr<i32>) -> i32 {
    unsafe {
        litebox_platform_multiplex::platform().with_thread_local_storage_mut(|tls| {
            tls.current_task.clear_child_tid = Some(tidptr);
            tls.current_task.tid
        })
    }
}

/// Handle syscall `gettid`.
pub(crate) fn sys_gettid() -> i32 {
    unsafe {
        litebox_platform_multiplex::platform()
            .with_thread_local_storage_mut(|tls| tls.current_task.tid)
    }
}

#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;

    use litebox::{mm::linux::PAGE_SIZE, platform::RawConstPointer as _};
    use litebox_common_linux::{CloneFlags, MapFlags, ProtFlags};

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_arch_prctl() {
        use super::sys_arch_prctl;
        use crate::{MutPtr, syscalls::tests::init_platform};
        use core::mem::MaybeUninit;
        use litebox_common_linux::ArchPrctlArg;

        init_platform(None);

        // Save old FS base
        let mut old_fs_base = MaybeUninit::<usize>::uninit();
        let ptr = MutPtr {
            inner: old_fs_base.as_mut_ptr(),
        };
        sys_arch_prctl(ArchPrctlArg::GetFs(ptr)).expect("Failed to get FS base");
        let old_fs_base = unsafe { old_fs_base.assume_init() };

        // Set new FS base
        let mut new_fs_base: [u8; 16] = [0; 16];
        let ptr = crate::MutPtr {
            inner: new_fs_base.as_mut_ptr(),
        };
        sys_arch_prctl(ArchPrctlArg::SetFs(ptr.as_usize())).expect("Failed to set FS base");

        // Verify new FS base
        let mut current_fs_base = MaybeUninit::<usize>::uninit();
        let ptr = MutPtr {
            inner: current_fs_base.as_mut_ptr(),
        };
        sys_arch_prctl(ArchPrctlArg::GetFs(ptr)).expect("Failed to get FS base");
        let current_fs_base = unsafe { current_fs_base.assume_init() };
        assert_eq!(current_fs_base, new_fs_base.as_ptr() as usize);

        // Restore old FS base
        let ptr: crate::MutPtr<u8> = crate::MutPtr::from_usize(old_fs_base);
        sys_arch_prctl(ArchPrctlArg::SetFs(ptr.as_usize())).expect("Failed to restore FS base");
    }

    static mut TLS: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
    static mut CHILD_TID: i32 = 0;

    #[test]
    #[expect(clippy::too_many_lines)]
    fn test_thread_spawn() {
        crate::syscalls::tests::init_platform(None);

        let stack_size = 8 * 1024 * 1024; // 8 MiB
        let stack = crate::syscalls::mm::sys_mmap(
            0,
            stack_size,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
            -1,
            0,
        )
        .expect("Failed to allocate stack");

        let mut parent_tid = MaybeUninit::<u32>::uninit();
        let parent_tid_ptr = crate::MutPtr {
            inner: parent_tid.as_mut_ptr(),
        };

        #[allow(static_mut_refs)]
        let child_tid_ptr = crate::MutPtr {
            inner: &raw mut CHILD_TID,
        };

        let flags = CloneFlags::THREAD
            | CloneFlags::VM
            | CloneFlags::FS
            | CloneFlags::FILES
            | CloneFlags::SIGHAND
            | CloneFlags::PARENT_SETTID
            | CloneFlags::CHILD_SETTID
            | CloneFlags::CHILD_CLEARTID
            | CloneFlags::SYSVSEM;

        // Call sys_clone
        #[cfg(target_arch = "x86_64")]
        let pt_regs = litebox_common_linux::PtRegs {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            orig_rax: syscalls::Sysno::clone3 as usize,
            rip: 0,
            cs: 0x33, // __USER_CS
            eflags: 0,
            rsp: 0,
            ss: 0x2b, // __USER_DS
        };
        #[cfg(target_arch = "x86")]
        let pt_regs = litebox_common_linux::PtRegs {
            ebx: 0,
            ecx: 0,
            edx: 0,
            esi: 0,
            edi: 0,
            ebp: 0,
            eax: 0,
            xds: 0,
            xes: 0,
            xfs: 0,
            xgs: 0,
            orig_eax: syscalls::Sysno::clone3 as usize,
            eip: 0,
            xcs: 0x23, // __USER_CS
            eflags: 0,
            esp: 0,
            xss: 0x2b, // __USER_DS
        };
        crate::syscalls::tests::log_println!("stack allocated at: {:#x}", stack.as_usize());
        let main: fn() = || {
            let tid = super::sys_gettid();
            crate::syscalls::tests::log_println!("Child started {tid}");

            #[cfg(target_arch = "x86_64")]
            {
                let mut current_fs_base = MaybeUninit::<usize>::uninit();
                super::sys_arch_prctl(litebox_common_linux::ArchPrctlArg::GetFs(crate::MutPtr {
                    inner: current_fs_base.as_mut_ptr(),
                }))
                .expect("Failed to get FS base");
                #[allow(static_mut_refs)]
                let addr = unsafe { TLS.as_ptr() } as usize;
                assert_eq!(
                    addr,
                    unsafe { current_fs_base.assume_init() },
                    "FS base should match TLS pointer"
                );
            }

            assert!(unsafe { CHILD_TID } > 0, "Child TID should be set");
            assert_eq!(
                unsafe { CHILD_TID },
                tid,
                "Child TID should match sys_gettid result"
            );
            crate::syscalls::tests::log_println!("Child TID: {}", unsafe { CHILD_TID });
            super::sys_exit(0);
        };

        #[cfg(target_arch = "x86")]
        let mut user_desc = {
            let mut flags = litebox_common_linux::UserDescFlags(0);
            flags.set_seg_32bit(true);
            flags.set_useable(true);
            litebox_common_linux::UserDesc {
                entry_number: u32::MAX,
                #[allow(static_mut_refs)]
                base_addr: unsafe { TLS.as_mut_ptr() } as u32,
                limit: u32::try_from(core::mem::size_of::<
                    litebox_common_linux::ThreadLocalStorage<litebox_platform_multiplex::Platform>,
                >())
                .unwrap()
                    - 1,
                flags,
            }
        };

        let result = super::sys_clone(
            flags,
            Some(parent_tid_ptr),
            Some(stack),
            stack_size,
            Some(child_tid_ptr),
            Some(crate::MutPtr {
                #[cfg(target_arch = "x86_64")]
                #[allow(static_mut_refs)]
                inner: unsafe { TLS.as_mut_ptr() },
                #[cfg(target_arch = "x86")]
                inner: &mut user_desc,
            }),
            &pt_regs,
            main as usize,
        )
        .expect("sys_clone failed");
        crate::syscalls::tests::log_println!("sys_clone returned: {}", result);
        assert!(result > 0, "sys_clone should return a positive PID");
        assert_eq!(
            unsafe { parent_tid.assume_init() } as usize,
            result,
            "Parent TID mismatch"
        );
    }
}
