mod common;

#[test]
fn test_load_exec_dynamic() {
    let dir_path = std::env::var("OUT_DIR").unwrap();
    let path = std::path::Path::new(dir_path.as_str()).join("hello_dylib");
    common::compile("./tests/hello.c", path.to_str().unwrap(), false, false);

    let executable_path = "/hello_dylib";
    let executable_data = std::fs::read(path).unwrap();

    #[cfg(target_arch = "x86_64")]
    let files_to_install = [
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/libc.so.6",
    ];

    #[cfg(target_arch = "x86")]
    let files_to_install = ["/lib/ld-linux.so.2", "/lib32/libc.so.6"];

    common::init_platform(
        &[],
        &["lib64", "lib32", "lib", "lib/x86_64-linux-gnu"],
        &files_to_install,
        None,
        true,
    );
    common::install_file(executable_data, executable_path);
    common::test_load_exec_common(executable_path);
}
