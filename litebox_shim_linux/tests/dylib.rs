mod common;

#[test]
fn test_load_exec_dynamic() {
    let dir_path = std::env::var("OUT_DIR").unwrap();
    let path = std::path::Path::new(dir_path.as_str()).join("hello_dylib");
    common::compile(&path, false);

    let executable_path = "/hello_dylib";
    let executable_data = std::fs::read(path).unwrap();
    let ld_data = std::fs::read("/lib64/ld-linux-x86-64.so.2").unwrap();
    let libc_data = std::fs::read("/lib/x86_64-linux-gnu/libc.so.6").unwrap();

    common::init_platform();

    common::install_file(executable_data, executable_path);
    common::install_file(ld_data, "/lib64/ld-linux-x86-64.so.2");
    common::install_file(libc_data, "/lib/x86_64-linux-gnu/libc.so.6");

    common::test_load_exec_common(executable_path);
}
