extern crate std;

mod common;

#[test]
fn test_load_exec_static() {
    common::init_platform();

    // no std::env::var("OUT_DIR").unwrap()??
    let path = std::path::Path::new("../target/debug").join("hello_exec");
    common::compile(&path, true);

    let executable_path = "/hello_exec";
    common::install_file(&path, executable_path);

    common::test_load_exec_common(executable_path);
}
