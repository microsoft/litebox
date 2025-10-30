//! VSM OP-TEE SMC functions

use crate::{
    debug_serial_println, host::per_cpu_variables::with_per_cpu_variables_mut, mshv::HV_VTL_SECURE,
};
use litebox_common_linux::errno::Errno;
use x86_64::PhysAddr;

/// OP-TEE SMC call arguments. OP-TEE assumes that the underlying architecture is Arm with TrustZone.
/// This is why it uses Secure Monitor Call (SMC) calling convention (SMCCC).
/// We translate SMCCC into VTL switch convention.
#[repr(align(4096))]
#[derive(Clone, Copy)]
#[repr(C)]
struct OpteeSmcArgs {
    args: [usize; Self::NUM_OPTEE_SMC_ARGS],
}

impl OpteeSmcArgs {
    const NUM_OPTEE_SMC_ARGS: usize = 9;
}

pub(crate) fn optee_smc_dispatch(optee_smc_args_pfn: u64) -> i64 {
    if let Ok(optee_smc_args_page_addr) = PhysAddr::try_new(optee_smc_args_pfn << 12)
        && let Some(mut _optee_smc_args) = unsafe {
            crate::platform_low().copy_from_vtl0_phys::<OpteeSmcArgs>(optee_smc_args_page_addr)
        }
    {
        // Since we do not know whether an OP-TEE TA uses extended states, we conservatively
        // save and restore extended states before and after running any OP-TEE TA.
        with_per_cpu_variables_mut(|per_cpu_variables| {
            per_cpu_variables.save_extended_states(HV_VTL_SECURE);
        });
        // TODO: Implement OP-TEE SMC for TA command invocation here.
        debug_serial_println!("VSM function call for OP-TEE message");
        with_per_cpu_variables_mut(|per_cpu_variables| {
            per_cpu_variables.restore_extended_states(HV_VTL_SECURE);
        });
        0
    } else {
        Errno::EINVAL.as_neg().into()
    }
}
