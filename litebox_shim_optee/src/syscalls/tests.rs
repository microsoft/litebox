// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_platform_linux_userland::LinuxUserland as Platform;

/// A shim builder bound to the test platform and a single session registry shared by
/// every shim built here, per [`crate::OpteeShimBuilder::new`]'s invariant.
#[must_use]
pub(crate) fn shim_builder() -> crate::OpteeShimBuilder<Platform> {
    static PLATFORM: spin::Once<&'static Platform> = spin::Once::new();
    static SESSION_MANAGER: once_cell::race::OnceBox<crate::session::SessionManager<Platform>> =
        once_cell::race::OnceBox::new();

    let platform = *PLATFORM.call_once(|| Platform::new(None));
    let session_manager = SESSION_MANAGER
        .get_or_init(|| alloc::boxed::Box::new(crate::session::SessionManager::new()));

    crate::OpteeShimBuilder::new(platform, session_manager)
}

pub(crate) fn init_platform() -> crate::Task<Platform> {
    let shim_builder = shim_builder();
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
    let first_ptr = crate::UserMutPtr::<Platform, TeeTime>::from_usize(&raw mut first as usize);
    task.sys_get_time(TeeTimeCategory::System, first_ptr)
        .expect("system time should be supported");

    let mut second = TeeTime::default();
    let second_ptr = crate::UserMutPtr::<Platform, TeeTime>::from_usize(&raw mut second as usize);
    task.sys_get_time(TeeTimeCategory::System, second_ptr)
        .expect("system time should be supported");

    // `millis` is the sub-second remainder, so always in `0..1000`.
    assert!(first.millis < 1000 && second.millis < 1000);

    let first_ms = u64::from(first.seconds) * 1000 + u64::from(first.millis);
    let second_ms = u64::from(second.seconds) * 1000 + u64::from(second.millis);
    assert!(second_ms >= first_ms, "system time went backwards");
}

#[test]
fn test_sys_map_zi_uses_bottom_up_placement() {
    use litebox::mm::linux::PAGE_SIZE;
    use litebox_common_optee::LdelfMapFlags;

    let task = init_platform();
    let (header, header_cleanup) = task
        .sys_map_zi(0, PAGE_SIZE, 0, 0, LdelfMapFlags::empty())
        .expect("header mapping should succeed");
    let (image, image_cleanup) = task
        .sys_map_zi(
            0,
            PAGE_SIZE,
            PAGE_SIZE,
            2 * PAGE_SIZE,
            LdelfMapFlags::empty(),
        )
        .expect("padded image mapping should succeed");

    assert!(header < image, "OP-TEE-chosen mappings must grow upward");
    image_cleanup.run(&task);
    header_cleanup.run(&task);
}
