use core::str::FromStr as _;

extern crate std;

mod common;

#[test]
fn test_load_exec_dynamic() {
    common::init_platform();

    // no std::env::var("OUT_DIR").unwrap()??
    let path = std::path::Path::new("../target/debug").join("hello_dylib");
    common::compile(&path, false);

    let executable_path = "/hello_dylib";
    common::install_file(&path, executable_path);
    common::install_file(
        &std::path::PathBuf::from_str("/lib64/ld-linux-x86-64.so.2").unwrap(),
        "/lib64/ld-linux-x86-64.so.2",
    );

    common::test_load_exec_common(executable_path);
}
