// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::path::PathBuf;

const RTLD_AUDIT_DIR: &str = "../litebox_rtld_audit";

fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    if target_arch != "x86_64" {
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let mut make_cmd = std::process::Command::new("make");
    make_cmd
        .current_dir(RTLD_AUDIT_DIR)
        .env("OUT_DIR", &out_dir)
        .env("ARCH", &target_arch);
    // Always build without DEBUG for the packager -- packaged binaries are
    // release artifacts.
    make_cmd.env_remove("DEBUG");
    // Force rebuild in case a stale artifact exists from a different config.
    let _ = std::fs::remove_file(out_dir.join("litebox_rtld_audit.so"));

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
        "Build failed to create litebox_rtld_audit.so"
    );

    println!("cargo:rerun-if-changed={RTLD_AUDIT_DIR}/rtld_audit.c");
    println!("cargo:rerun-if-changed={RTLD_AUDIT_DIR}/Makefile");
    println!("cargo:rerun-if-changed=build.rs");
}
