use litebox_platform_multiplex::{Platform, set_platform};

fn init_platform() {
    let platform = Platform::new(None);
    set_platform(platform);
    platform.register_syscall_handler(litebox_shim_optee::handle_syscall_request);
}

#[test]
fn test_load_ta() {
    init_platform();

    let executable_path = "tests/hello-ta.elf";
    let executable_data = std::fs::read(executable_path).unwrap();
    let _loaded_program =
        litebox_shim_optee::loader::load_elf_buffer(executable_data.as_slice()).unwrap();
}
