const SRC_PATH: &str = "../litebox_rtld_audit/rtld_audit.c";

fn main() {
    // Compile the C code into a dynamic library
    let dir_path = std::env::var("OUT_DIR").unwrap();
    let output_path = std::path::Path::new(dir_path.as_str()).join("litebox_rtld_audit.so");

    let mut cc_args = vec![
        "-Wall",
        "-Werror",
        "-fPIC",
        "-shared",
        "-nostdlib",
        "-o",
        output_path.to_str().unwrap(),
        SRC_PATH,
    ];
    // Add -DDEBUG if in debug mode
    if std::env::var("PROFILE").unwrap_or_default() == "debug" {
        cc_args.push("-DDEBUG");
    }
    let output = std::process::Command::new("cc")
        .args(cc_args)
        .output()
        .expect("Failed to compile rtld_audit.c");

    assert!(
        output.status.success(),
        "failed to compile rtld_audit.c {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );

    println!("cargo:rerun-if-changed={SRC_PATH}");
    println!("cargo:rerun-if-changed=build.rs");
}
