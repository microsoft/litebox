// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_platform_linux_userland::LinuxUserland as Platform;

#[must_use]
pub(crate) fn shim_builder() -> crate::OpteeShimBuilder<Platform> {
    static PLATFORM: spin::Once<&'static Platform> = spin::Once::new();
    static SESSION_MANAGER: once_cell::race::OnceBox<crate::session::SessionManager<Platform>> =
        once_cell::race::OnceBox::new();

    let platform = *PLATFORM.call_once(|| {
        let platform = Platform::new();
        // `compute_with_derived_key` (used by IDKS) needs the boot ID.
        platform.initialize_boot_specific_kdf_support();
        platform
    });
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
fn test_cryp_random_number_generate_requires_broker() {
    let task = init_platform();
    let mut buf = [0u8; 16];
    assert_eq!(
        task.sys_cryp_random_number_generate(&mut []),
        Ok(()),
        "zero-length random generation must not require a broker"
    );
    assert_eq!(
        task.sys_cryp_random_number_generate(&mut buf),
        Err(litebox_common_optee::TeeResult::CommunicationError)
    );
    assert_eq!(buf, [0; 16]);
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
    use litebox_common_optee::LdelfMapFlags;
    use litebox_common_optee::PAGE_SIZE;

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

#[test]
fn test_sys_check_access_rights_checks_permissions_and_ownership() {
    use litebox::platform::RawConstPointer as _;
    use litebox_common_linux::mm::MmapPlacement;
    use litebox_common_linux::{MapFlags, ProtFlags};
    use litebox_common_optee::{PAGE_SIZE, TeeMemoryAccessRights as Rights, TeeResult};

    let task = init_platform();
    let map = |prot, flags| {
        task.global
            .mm
            .do_mmap(
                None,
                PAGE_SIZE,
                prot,
                flags | MapFlags::MAP_ANONYMOUS,
                MmapPlacement {
                    direction: litebox::platform::page_mgmt::AllocationDirection::BottomUp,
                    allowed_range: None,
                },
                |_| Ok(0),
            )
            .unwrap()
            .as_usize()
    };
    let check = |rights, address| {
        task.sys_check_access_rights(
            rights,
            crate::UserConstPtr::<Platform, u8>::from_usize(address),
            PAGE_SIZE,
        )
    };
    let read_write = Rights::TEE_MEMORY_ACCESS_READ | Rights::TEE_MEMORY_ACCESS_WRITE;

    let private = map(ProtFlags::PROT_READ, MapFlags::MAP_PRIVATE);
    assert_eq!(check(Rights::TEE_MEMORY_ACCESS_READ, private), Ok(()));
    assert_eq!(check(read_write, private), Err(TeeResult::AccessDenied));
    assert_eq!(
        check(read_write | Rights::TEE_MEMORY_ACCESS_ANY_OWNER, private),
        Err(TeeResult::AccessDenied)
    );

    // Shared memory may be owned by others, so it passes only with `ANY_OWNER`.
    let shared = map(ProtFlags::PROT_READ_WRITE, MapFlags::MAP_SHARED);
    assert_eq!(check(read_write, shared), Err(TeeResult::AccessDenied));
    assert_eq!(
        check(read_write | Rights::TEE_MEMORY_ACCESS_ANY_OWNER, shared),
        Ok(())
    );
}
