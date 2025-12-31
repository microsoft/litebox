// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::Task;
use litebox_platform_multiplex::{Platform, set_platform};

// Ensure we only init the platform once
static INIT_FUNC: spin::Once = spin::Once::new();

#[must_use]
#[cfg_attr(
    not(target_os = "linux"),
    expect(unused_variables, reason = "ignored parameter on non-linux platforms")
)]
pub(crate) fn init_platform() -> crate::Task {
    INIT_FUNC.call_once(|| {
        #[cfg(target_os = "linux")]
        let platform = Platform::new(None);

        #[cfg(not(target_os = "linux"))]
        let platform = Platform::new();

        set_platform(platform);
    });

    let mut shim_builder = crate::OpteeShimBuilder::new();
    let litebox = shim_builder.litebox();
    shim_builder.build().0.new_test_task()
}

#[test]
fn test_sys_log() {
    let task = init_platform();
    let result = task.sys_log(b"Hello! This is litebox_shim_optee.");
    assert!(result.is_ok());
}

#[test]
fn test_cryp_random_number_generate() {
    let task = init_platform();
    let mut buf = [0u8; 16];
    let result = task.sys_cryp_random_number_generate(&mut buf);
    assert!(result.is_ok() && buf != [0u8; 16]);
}
