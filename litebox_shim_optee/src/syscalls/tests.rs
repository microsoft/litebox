use super::{cryp::sys_cryp_random_number_generate, tee::sys_log};
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

#[test]
fn test_cryp_random_number_generate() {
    init_platform();
    let mut buf = [0u8; 16];
    let result = sys_cryp_random_number_generate(&mut buf);
    assert!(result.is_ok() && buf != [0u8; 16]);
}

const HELLO_TA_ELF: &[u8] = include_bytes!("hello-ta.elf");

#[test]
fn test_loader() {
    init_platform();

    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "TA ELF size: {}",
        HELLO_TA_ELF.len()
    );

    let loaded_elf = crate::loader::load_elf_buffer(&HELLO_TA_ELF).expect("Failed to load TA ELF");

    litebox::log_println!(
        litebox_platform_multiplex::platform(),
        "TA ELF entry point: {:#x}, user stack top: {:#x}",
        loaded_elf.entry_point,
        loaded_elf.user_stack_top,
    );
}
