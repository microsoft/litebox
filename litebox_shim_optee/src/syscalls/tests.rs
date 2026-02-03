// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::platform::CrngProvider;
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

        // Initialize the unique platform key with a random boot nonce
        let mut boot_nonce = [0u8; litebox_platform_linux_userland::UPK_LEN];
        platform.fill_bytes_crng(&mut boot_nonce);
        litebox_platform_linux_userland::set_unique_platform_key(&boot_nonce);

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
fn test_derive_ta_svn_key_stack_success() {
    use litebox_common_optee::{TeeParamType, UteeParams, UteeParamsTypes};

    let task = init_platform();

    let key_size: u32 = 32;
    let svn_key_stack_size: u32 = 10;
    let extra_data = [0u8; 64];
    let mut key_stack = [0u8; 256];

    let mut params = UteeParams {
        types: UteeParamsTypes::new()
            .with_type_0(TeeParamType::ValueInput as u8)
            .with_type_1(TeeParamType::MemrefInput as u8)
            .with_type_2(TeeParamType::MemrefOutput as u8)
            .with_type_3(TeeParamType::None as u8),
        vals: [0u64; 8],
    };

    // params[0]: key_size and svn_key_stack_size
    params.vals[0] = u64::from(key_size);
    params.vals[1] = u64::from(svn_key_stack_size);

    // params[1]: extra_data buffer and size
    params.vals[2] = extra_data.as_ptr() as u64;
    params.vals[3] = extra_data.len() as u64;

    // params[2]: key_stack buffer and size
    params.vals[4] = key_stack.as_mut_ptr() as u64;
    params.vals[5] = key_stack.len() as u64;

    let result = task.handle_system_pta_command(
        crate::syscalls::pta::PtaSystemCommandId::DeriveTaSvnKeyStack as u32,
        &params,
    );

    assert!(result.is_ok());
    // With SVN=0, only key[0] should be populated (first 32 bytes)
    assert_ne!(&key_stack[..32], &[0u8; 32]);
}

#[test]
fn test_derive_ta_svn_key_stack_bad_key_size() {
    use litebox_common_optee::{TeeParamType, TeeResult, UteeParams, UteeParamsTypes};

    let task = init_platform();

    let extra_data = [0u8; 64];
    let mut key_stack = [0u8; 256];

    let mut params = UteeParams {
        types: UteeParamsTypes::new()
            .with_type_0(TeeParamType::ValueInput as u8)
            .with_type_1(TeeParamType::MemrefInput as u8)
            .with_type_2(TeeParamType::MemrefOutput as u8)
            .with_type_3(TeeParamType::None as u8),
        vals: [0u64; 8],
    };

    // key_size too small (< 16)
    params.vals[0] = 8;
    params.vals[1] = 10;
    params.vals[2] = extra_data.as_ptr() as u64;
    params.vals[3] = extra_data.len() as u64;
    params.vals[4] = key_stack.as_mut_ptr() as u64;
    params.vals[5] = key_stack.len() as u64;

    let result = task.handle_system_pta_command(
        crate::syscalls::pta::PtaSystemCommandId::DeriveTaSvnKeyStack as u32,
        &params,
    );

    assert!(matches!(result, Err(TeeResult::BadParameters)));

    // key_size too large (> 32)
    params.vals[0] = 64;
    let result = task.handle_system_pta_command(
        crate::syscalls::pta::PtaSystemCommandId::DeriveTaSvnKeyStack as u32,
        &params,
    );

    assert!(matches!(result, Err(TeeResult::BadParameters)));
}

#[test]
fn test_derive_ta_svn_key_stack_bad_param_types() {
    use litebox_common_optee::{TeeParamType, TeeResult, UteeParams, UteeParamsTypes};

    let task = init_platform();

    let extra_data = [0u8; 64];
    let mut key_stack = [0u8; 256];

    // Wrong type for params[0] - should be ValueInput
    let mut params = UteeParams {
        types: UteeParamsTypes::new()
            .with_type_0(TeeParamType::MemrefInput as u8) // Wrong!
            .with_type_1(TeeParamType::MemrefInput as u8)
            .with_type_2(TeeParamType::MemrefOutput as u8)
            .with_type_3(TeeParamType::None as u8),
        vals: [0u64; 8],
    };

    params.vals[0] = 32;
    params.vals[1] = 10;
    params.vals[2] = extra_data.as_ptr() as u64;
    params.vals[3] = extra_data.len() as u64;
    params.vals[4] = key_stack.as_mut_ptr() as u64;
    params.vals[5] = key_stack.len() as u64;

    let result = task.handle_system_pta_command(
        crate::syscalls::pta::PtaSystemCommandId::DeriveTaSvnKeyStack as u32,
        &params,
    );

    assert!(matches!(result, Err(TeeResult::BadParameters)));
}

#[test]
fn test_derive_ta_svn_key_stack_zero_stack_size() {
    use litebox_common_optee::{TeeParamType, TeeResult, UteeParams, UteeParamsTypes};

    let task = init_platform();

    let extra_data = [0u8; 64];
    let mut key_stack = [0u8; 256];

    let mut params = UteeParams {
        types: UteeParamsTypes::new()
            .with_type_0(TeeParamType::ValueInput as u8)
            .with_type_1(TeeParamType::MemrefInput as u8)
            .with_type_2(TeeParamType::MemrefOutput as u8)
            .with_type_3(TeeParamType::None as u8),
        vals: [0u64; 8],
    };

    params.vals[0] = 32;
    params.vals[1] = 0; // Zero stack size - invalid
    params.vals[2] = extra_data.as_ptr() as u64;
    params.vals[3] = extra_data.len() as u64;
    params.vals[4] = key_stack.as_mut_ptr() as u64;
    params.vals[5] = key_stack.len() as u64;

    let result = task.handle_system_pta_command(
        crate::syscalls::pta::PtaSystemCommandId::DeriveTaSvnKeyStack as u32,
        &params,
    );

    assert!(matches!(result, Err(TeeResult::BadParameters)));
}
