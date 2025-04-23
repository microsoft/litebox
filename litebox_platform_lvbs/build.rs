use std::env;
use std::path::PathBuf;

fn generate_bindings(header: &str, module_name: &str) {
    let bindings = bindgen::Builder::default()
        .header(header)
        .clang_arg("--target=x86_64-unknown-none")
        .use_core()
        .ctypes_prefix("core::ffi")
        .wrap_unsafe_ops(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_file = PathBuf::from(env::var("OUT_DIR").unwrap()).join(format!("{}.rs", module_name));
    bindings
        .write_to_file(out_file)
        .expect("Couldn't write bindings!");
}

fn main() {
    generate_bindings("src/host/mshv/mshv_wrapper.h", "mshv_bindings");
    generate_bindings("src/host/mshv/msr_wrapper.h", "msr_bindings");
}
