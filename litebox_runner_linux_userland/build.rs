use std::path::PathBuf;

const RTLD_AUDIT_DIR: &str = "../litebox_rtld_audit";

fn main() {
    let mut make_cmd = std::process::Command::new("make");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    make_cmd
        .current_dir(RTLD_AUDIT_DIR)
        .env("OUT_DIR", &out_dir)
        .env("ARCH", std::env::var("CARGO_CFG_TARGET_ARCH").unwrap());
    if std::env::var("PROFILE").unwrap_or_default() == "debug" {
        make_cmd.env("DEBUG", "1");
    }
    let output = make_cmd
        .output()
        .expect("Failed to execute make for rtld_audit");
    assert!(
        output.status.success(),
        "failed to build rtld_audit.so via make:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        out_dir.join("litebox_rtld_audit.so").exists(),
        "Build failed to create necessary file"
    );

    println!("cargo:rerun-if-changed={RTLD_AUDIT_DIR}/rtld_audit.c");
    println!("cargo:rerun-if-changed={RTLD_AUDIT_DIR}/Makefile");
    println!("cargo:rerun-if-changed=build.rs");
}
