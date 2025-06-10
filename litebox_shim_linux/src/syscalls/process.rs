//! Process/thread related syscalls.

use litebox_common_linux::{ArchPrctlArg, errno::Errno};

pub(crate) fn sys_arch_prctl(
    arg: ArchPrctlArg<litebox_platform_multiplex::Platform>,
) -> Result<(), Errno> {
    match arg {
        #[cfg(target_arch = "x86_64")]
        ArchPrctlArg::SetFs(addr) => {
            use litebox::platform::{PunchthroughProvider as _, PunchthroughToken as _};
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
            use litebox::platform::{PunchthroughProvider as _, PunchthroughToken as _};
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

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_arch_prctl() {
        use super::sys_arch_prctl;
        use crate::{ConstPtr, MutPtr, syscalls::tests::init_platform};
        use core::mem::MaybeUninit;
        use litebox_common_linux::ArchPrctlArg;

        init_platform(None);

        // Save old FS base
        let mut old_fs_base = MaybeUninit::<usize>::uninit();
        let ptr: MutPtr<usize> = unsafe { core::mem::transmute(old_fs_base.as_mut_ptr()) };
        sys_arch_prctl(ArchPrctlArg::GetFs(ptr)).expect("Failed to get FS base");
        let old_fs_base = unsafe { old_fs_base.assume_init() };

        // Set new FS base
        let new_fs_base: [u8; 16] = [0; 16];
        let ptr: ConstPtr<u8> = unsafe { core::mem::transmute(new_fs_base.as_ptr()) };
        sys_arch_prctl(ArchPrctlArg::SetFs(ptr)).expect("Failed to set FS base");

        // Verify new FS base
        let mut current_fs_base = MaybeUninit::<usize>::uninit();
        let ptr: MutPtr<usize> = unsafe { core::mem::transmute(current_fs_base.as_mut_ptr()) };
        sys_arch_prctl(ArchPrctlArg::GetFs(ptr)).expect("Failed to get FS base");
        let current_fs_base = unsafe { current_fs_base.assume_init() };
        assert_eq!(current_fs_base, new_fs_base.as_ptr() as usize);

        // Restore old FS base
        let ptr: ConstPtr<u8> = unsafe { core::mem::transmute(old_fs_base) };
        sys_arch_prctl(ArchPrctlArg::SetFs(ptr)).expect("Failed to restore FS base");
    }
}
