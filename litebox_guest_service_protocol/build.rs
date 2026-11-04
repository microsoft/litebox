// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Generates the messages and the sync ttrpc client and server of `guest_service.proto`.

fn main() {
    let out_dir =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let crate_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    println!("cargo:rerun-if-changed=guest_service.proto");
    ttrpc_codegen::Codegen::new()
        .out_dir(&out_dir)
        .input(crate_dir.join("guest_service.proto"))
        .include(&crate_dir)
        .rust_protobuf()
        .rust_protobuf_customize(ttrpc_codegen::ProtobufCustomize::default().gen_mod_rs(false))
        .customize(ttrpc_codegen::Customize {
            async_all: false,
            ..Default::default()
        })
        .run()
        .expect("cannot generate the protocol's Rust modules");
    // `include!` takes no inner attributes or inner doc comments.
    for module in ["guest_service.rs", "guest_service_ttrpc.rs"] {
        let path = out_dir.join(module);
        let code = std::fs::read_to_string(&path).expect("cannot read a generated module");
        let kept: Vec<&str> = code
            .lines()
            .filter(|line| !line.starts_with("#!") && !line.starts_with("//!"))
            .collect();
        std::fs::write(&path, kept.join("\n")).expect("cannot write a generated module");
    }
}
