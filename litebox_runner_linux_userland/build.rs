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

    // Use the target architecture provided by Cargo.
    // Prefer CARGO_CFG_TARGET_ARCH (gives "x86_64", "x86", "arm", etc.)
    // Fall back to parsing TARGET triple if necessary.
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH")
        .or_else(|_| std::env::var("TARGET"))
        .unwrap();

    let arch_flag = if target_arch.starts_with("x86_64") {
        "-m64"
    } else if target_arch.starts_with("x86")
        || target_arch.starts_with("i686")
        || target_arch.starts_with("i386")
    {
        // Don't build it as we do not support x86 yet
        // "-m32"
        return;
    } else {
        panic!("build.rs: unsupported target arch '{target_arch}'");
    };
    cc_args.push(arch_flag);

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
