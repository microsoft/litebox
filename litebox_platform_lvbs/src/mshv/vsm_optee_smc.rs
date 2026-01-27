// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VSM OP-TEE SMC functions

use crate::{debug_serial_println, host::per_cpu_variables::with_per_cpu_variables_mut};
use litebox_common_linux::errno::Errno;
use litebox_common_optee::OpteeSmcArgs;
use x86_64::PhysAddr;

pub(crate) fn optee_smc_dispatch(optee_smc_args_pfn: u64) -> i64 {
    if let Ok(optee_smc_args_page_addr) = PhysAddr::try_new(optee_smc_args_pfn << 12)
        && let Some(mut _optee_smc_args) = unsafe {
            crate::platform_low().copy_from_vtl0_phys::<OpteeSmcArgs>(optee_smc_args_page_addr)
        }
    {
        // Since we do not know whether an OP-TEE TA uses extended states, we conservatively
        // save and restore extended states before and after running any OP-TEE TA.
        with_per_cpu_variables_mut(|per_cpu_variables| {
            per_cpu_variables.save_vtl1_extended_states();
        });
        // TODO: Implement OP-TEE SMC for TA command invocation here.
        debug_serial_println!("VSM function call for OP-TEE message");
        with_per_cpu_variables_mut(|per_cpu_variables| {
            per_cpu_variables.restore_vtl1_extended_states();
        });
        0
    } else {
        Errno::EINVAL.as_neg().into()
    }
}
