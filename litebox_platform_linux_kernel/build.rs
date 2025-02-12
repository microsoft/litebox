#[cfg(feature = "platform_snp")]
fn build_binding_from_sandbox_driver() {
    let bindings = bindgen::Builder::default()
        .clang_arg("--target=x86_64-unknown-none")
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_type("SnpVmplRequestArgs")
        .allowlist_type("vsbox_task")
        .allowlist_var("SNP_VMPL_.+")
        .use_core()
        .formatter(bindgen::Formatter::Rustfmt)
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    #[cfg(feature = "platform_snp")]
    build_binding_from_sandbox_driver();
}
