#[cfg(target_arch = "x86_64")]
use super::cryp::sys_cryp_random_number_generate;

use super::tee::sys_log;
use litebox_platform_multiplex::{Platform, set_platform};

// Ensure we only init the platform once
static INIT_FUNC: spin::Once = spin::Once::new();

pub(crate) fn init_platform() {
    INIT_FUNC.call_once(|| {
        set_platform(Platform::new(None));
        let _ = crate::litebox();
    });
}

#[test]
fn test_sys_log() {
    init_platform();
    let result = sys_log(b"Hello! This is litebox_shim_optee.");
    assert!(result.is_ok());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_cryp_random_number_generate() {
    init_platform();
    let mut buf = [0u8; 16];
    let result = sys_cryp_random_number_generate(&mut buf);
    assert!(result.is_ok() && buf != [0u8; 16]);
}
