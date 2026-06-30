// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

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

    let shim_builder = crate::OpteeShimBuilder::new();
    let _litebox = shim_builder.litebox();
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

#[test]
fn test_sys_get_time_system_is_monotonic() {
    use litebox::platform::RawConstPointer as _;
    use litebox_common_optee::{TeeTime, TeeTimeCategory};

    let task = init_platform();

    let mut first = TeeTime::default();
    let first_ptr = crate::UserMutPtr::<TeeTime>::from_usize(&raw mut first as usize);
    task.sys_get_time(TeeTimeCategory::System, first_ptr)
        .expect("system time should be supported");

    let mut second = TeeTime::default();
    let second_ptr = crate::UserMutPtr::<TeeTime>::from_usize(&raw mut second as usize);
    task.sys_get_time(TeeTimeCategory::System, second_ptr)
        .expect("system time should be supported");

    // `millis` is the sub-second remainder, so always in `0..1000`.
    assert!(first.millis < 1000 && second.millis < 1000);

    let first_ms = u64::from(first.seconds) * 1000 + u64::from(first.millis);
    let second_ms = u64::from(second.seconds) * 1000 + u64::from(second.millis);
    assert!(second_ms >= first_ms, "system time went backwards");
}
