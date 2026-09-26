// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

fn main() {
    println!("cargo::rerun-if-changed=x86_64_kvm.ld");
    println!("cargo::rerun-if-changed=x86_64_kvm.json");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        let script = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("x86_64_kvm.ld");
        println!(
            "cargo::rustc-link-arg-bin=litebox_runner_optee_on_kvm=--script={}",
            script.display()
        );
    }
}
