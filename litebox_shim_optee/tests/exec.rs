mod common;

#[test]
fn test_load_exec_static() {
    let dir_path = std::env::var("OUT_DIR").unwrap();
    let path = std::path::Path::new(dir_path.as_str()).join("hello_exec");
    common::compile(&path, true);

    let executable_path = "/hello_exec";
    let executable_data = std::fs::read(path).unwrap();

    common::init_platform();

    common::install_file(executable_data, executable_path);

    common::test_load_exec_common(executable_path);
}
